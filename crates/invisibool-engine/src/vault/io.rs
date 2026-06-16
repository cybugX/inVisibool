//! Filesystem operations the vault module uses, behind a swappable
//! trait so tests can inject failures at every step of the atomic
//! write dance.
//!
//! The production [`StdVaultIo`] performs the standard write-temp +
//! fsync + rename + fsync-parent sequence. Each step's error is
//! captured at the precise step it occurred via [`AtomicWriteError`]
//! so the caller can tell "rename failed" apart from "tmp file
//! couldn't be created", and so the orphan-scan path can clean up a
//! leftover temp file after a mid-write failure.
//!
//! Tests use [`InjectableVaultIo`] (cfg(test) only) to force a
//! failure at a specific step. The vault module's crash-safety
//! invariants ("old vault intact after rename failure", "tmp file
//! present for orphan scan after write failure") are pinned by
//! exercising that injection against a real on-disk fixture.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

/// What the atomic write was doing when it failed.
///
/// Returned by [`VaultIo::write_atomic`] so the caller's typed error
/// distinguishes the steps without parsing string messages. Tests
/// pin specific variants to prove the steps fail in the right
/// places.
#[derive(Debug)]
pub enum AtomicWriteError {
    /// Could not create the sibling temp file (parent dir missing,
    /// permission denied, etc.).
    AtTmpCreate(io::Error),
    /// The body write to the temp file failed (disk full,
    /// I/O error).
    AtBodyWrite(io::Error),
    /// `fsync` on the temp file failed.
    AtBodyFsync(io::Error),
    /// `rename` from temp file to target path failed. The temp file
    /// is left on disk for the orphan-scan path to clean up. The
    /// original target (if any) is untouched.
    AtRename(io::Error),
    /// `fsync` on the parent directory failed (the rename succeeded
    /// but its durability is not guaranteed). On Windows this step is
    /// a no-op and this variant cannot fire there.
    AtParentFsync(io::Error),
}

impl std::fmt::Display for AtomicWriteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AtTmpCreate(e) => write!(f, "could not create vault temp file: {e}"),
            Self::AtBodyWrite(e) => write!(f, "could not write vault body: {e}"),
            Self::AtBodyFsync(e) => write!(f, "could not fsync vault temp file: {e}"),
            Self::AtRename(e) => write!(f, "could not atomically rename vault file: {e}"),
            Self::AtParentFsync(e) => write!(f, "could not fsync vault parent directory: {e}"),
        }
    }
}

impl std::error::Error for AtomicWriteError {}

/// Filesystem operations the vault module needs. Real impl is
/// [`StdVaultIo`]; tests use [`InjectableVaultIo`] (under `cfg(test)`)
/// to force specific failure points.
pub trait VaultIo: Send + Sync {
    /// Atomically write `bytes` to `path` with file mode `mode` (Unix
    /// permission bits; ignored on Windows where the parent dir's DACL
    /// controls access). Implementation contract:
    ///
    /// 1. Create a sibling temp file `path.tmp.<pid>` with the given
    ///    mode and `O_CREAT | O_WRONLY | O_TRUNC | O_EXCL` semantics
    ///    (so it never overwrites an existing temp file).
    /// 2. Write `bytes` into it.
    /// 3. `fsync` the temp file.
    /// 4. `rename` it over `path` (atomic on every supported platform).
    /// 5. `fsync` the parent directory (POSIX requirement for the
    ///    rename to be durable; no-op on Windows).
    ///
    /// On error, the precise step is reported via [`AtomicWriteError`]
    /// and the temp file (if it was created) is left on disk for the
    /// orphan-scan path. The target `path` is untouched if any step
    /// before the rename failed.
    fn write_atomic(&self, path: &Path, bytes: &[u8], mode: u32) -> Result<(), AtomicWriteError>;

    /// Read the file at `path`. Returns `Ok(None)` if the file does
    /// not exist (used by the open-or-empty path), `Err` on any
    /// other I/O failure.
    fn read_if_exists(&self, path: &Path) -> io::Result<Option<Vec<u8>>>;

    /// List sibling files of `vault_path` that match the orphan-tmp
    /// pattern `<basename>.tmp.*`. Used at vault open to clean up
    /// any tmp files left behind by a previous crashed write.
    fn list_orphan_tmps(&self, vault_path: &Path) -> io::Result<Vec<PathBuf>>;

    /// Best-effort delete. Silently ignores any error (the caller is
    /// the orphan-scan cleanup; an inability to delete an orphan
    /// should not abort the parent operation).
    fn remove_quiet(&self, path: &Path);
}

/// Production [`VaultIo`] backed by `std::fs`.
pub struct StdVaultIo;

impl StdVaultIo {
    /// Build the sibling tmp path for `vault_path`: the basename with
    /// `.tmp.<pid>` appended, in the same parent directory. PID
    /// disambiguates so two concurrent processes don't collide on the
    /// tmp file (though concurrent writes to the same vault are a
    /// documented anti-pattern at M1).
    fn tmp_path(vault_path: &Path) -> PathBuf {
        let parent = vault_path.parent().unwrap_or_else(|| Path::new("."));
        let file_name = vault_path
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "vault".to_string());
        parent.join(format!("{file_name}.tmp.{}", std::process::id()))
    }
}

impl Default for StdVaultIo {
    fn default() -> Self {
        Self
    }
}

impl VaultIo for StdVaultIo {
    fn write_atomic(&self, path: &Path, bytes: &[u8], mode: u32) -> Result<(), AtomicWriteError> {
        let tmp_path = Self::tmp_path(path);
        let parent = path.parent().unwrap_or_else(|| Path::new("."));

        // Ensure parent dir exists with restrictive mode (0o700 on Unix).
        if !parent.exists() {
            std::fs::create_dir_all(parent).map_err(AtomicWriteError::AtTmpCreate)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let perms = std::fs::Permissions::from_mode(0o700);
                let _ = std::fs::set_permissions(parent, perms);
            }
        }

        // 1. Create the temp file with restrictive mode at create time.
        let mut tmp_file = open_tmp(&tmp_path, mode).map_err(AtomicWriteError::AtTmpCreate)?;

        // 2. Write body.
        if let Err(e) = tmp_file.write_all(bytes) {
            return Err(AtomicWriteError::AtBodyWrite(e));
        }

        // 3. fsync the temp file.
        if let Err(e) = tmp_file.sync_all() {
            return Err(AtomicWriteError::AtBodyFsync(e));
        }
        // Close the file (drop) before rename - some platforms
        // (Windows historically) disallow rename of an open handle.
        drop(tmp_file);

        // 4. Atomic rename.
        if let Err(e) = std::fs::rename(&tmp_path, path) {
            return Err(AtomicWriteError::AtRename(e));
        }

        // 5. fsync the parent directory for rename durability (Unix only).
        #[cfg(unix)]
        {
            match File::open(parent) {
                Ok(dir) => {
                    if let Err(e) = dir.sync_all() {
                        return Err(AtomicWriteError::AtParentFsync(e));
                    }
                }
                Err(e) => return Err(AtomicWriteError::AtParentFsync(e)),
            }
        }

        Ok(())
    }

    fn read_if_exists(&self, path: &Path) -> io::Result<Option<Vec<u8>>> {
        match File::open(path) {
            Ok(mut f) => {
                let mut buf = Vec::new();
                f.read_to_end(&mut buf)?;
                Ok(Some(buf))
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn list_orphan_tmps(&self, vault_path: &Path) -> io::Result<Vec<PathBuf>> {
        let parent = vault_path.parent().unwrap_or_else(|| Path::new("."));
        let file_name = match vault_path.file_name() {
            Some(s) => s.to_string_lossy().into_owned(),
            None => return Ok(Vec::new()),
        };
        let prefix = format!("{file_name}.tmp.");

        let mut orphans = Vec::new();
        let entries = match std::fs::read_dir(parent) {
            Ok(e) => e,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e),
        };
        for entry in entries {
            let entry = entry?;
            let name = entry.file_name();
            if name.to_string_lossy().starts_with(&prefix) {
                orphans.push(entry.path());
            }
        }
        Ok(orphans)
    }

    fn remove_quiet(&self, path: &Path) {
        let _ = std::fs::remove_file(path);
    }
}

/// Open a temp file with `O_CREAT | O_WRONLY | O_TRUNC | O_EXCL` (so
/// it never silently overwrites an existing file with the same name)
/// and the given Unix mode at create time (so no other process ever
/// sees the file with looser permissions). On Windows mode is
/// ignored; ACLs are inherited from the parent dir.
fn open_tmp(path: &Path, mode: u32) -> io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(mode);
    }
    #[cfg(not(unix))]
    {
        let _ = mode;
    }
    opts.open(path)
}

// ---------- test-only failure injection ----------

#[cfg(test)]
pub(crate) use injectable::{AtomicWriteFailAt, InjectableVaultIo};

#[cfg(test)]
mod injectable {
    use super::*;
    use std::sync::Mutex;

    /// Where to force a failure in `write_atomic`. Variant names
    /// mirror `AtomicWriteError`'s variants so the test setup and
    /// the expected error read in parallel; the `At` prefix is the
    /// shared convention rather than a clippy-style violation.
    #[allow(clippy::enum_variant_names)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum AtomicWriteFailAt {
        AtTmpCreate,
        AtBodyWrite,
        AtBodyFsync,
        AtRename,
        AtParentFsync,
    }

    /// Test [`VaultIo`] that wraps `StdVaultIo` and forces a failure
    /// at a configured step of the atomic-write dance. Other
    /// operations delegate to the wrapped real backend.
    pub(crate) struct InjectableVaultIo {
        inner: StdVaultIo,
        fail_at: Mutex<Option<AtomicWriteFailAt>>,
    }

    impl InjectableVaultIo {
        pub(crate) fn new() -> Self {
            Self {
                inner: StdVaultIo,
                fail_at: Mutex::new(None),
            }
        }

        pub(crate) fn fail_next_write_at(&self, step: AtomicWriteFailAt) {
            *self.fail_at.lock().unwrap() = Some(step);
        }
    }

    impl VaultIo for InjectableVaultIo {
        fn write_atomic(
            &self,
            path: &Path,
            bytes: &[u8],
            mode: u32,
        ) -> Result<(), AtomicWriteError> {
            let fault = self.fail_at.lock().unwrap().take();

            // Honor the fault if it is for an early step. For later
            // steps we have to do real work up to that point so the
            // post-failure on-disk state is what the production code
            // would produce.
            if fault == Some(AtomicWriteFailAt::AtTmpCreate) {
                return Err(AtomicWriteError::AtTmpCreate(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "injected create failure",
                )));
            }

            let tmp_path = StdVaultIo::tmp_path(path);
            let parent = path.parent().unwrap_or_else(|| Path::new("."));
            if !parent.exists() {
                std::fs::create_dir_all(parent).map_err(AtomicWriteError::AtTmpCreate)?;
            }

            let mut tmp_file = open_tmp(&tmp_path, mode).map_err(AtomicWriteError::AtTmpCreate)?;

            if fault == Some(AtomicWriteFailAt::AtBodyWrite) {
                // Leave the tmp file empty for the orphan-scan path.
                drop(tmp_file);
                return Err(AtomicWriteError::AtBodyWrite(io::Error::other(
                    "injected write failure",
                )));
            }

            if let Err(e) = tmp_file.write_all(bytes) {
                return Err(AtomicWriteError::AtBodyWrite(e));
            }

            if fault == Some(AtomicWriteFailAt::AtBodyFsync) {
                drop(tmp_file);
                return Err(AtomicWriteError::AtBodyFsync(io::Error::other(
                    "injected fsync failure",
                )));
            }

            if let Err(e) = tmp_file.sync_all() {
                return Err(AtomicWriteError::AtBodyFsync(e));
            }
            drop(tmp_file);

            if fault == Some(AtomicWriteFailAt::AtRename) {
                // The tmp file is on disk; the rename does NOT happen.
                // The original vault path is untouched.
                return Err(AtomicWriteError::AtRename(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "injected rename failure",
                )));
            }

            if let Err(e) = std::fs::rename(&tmp_path, path) {
                return Err(AtomicWriteError::AtRename(e));
            }

            #[cfg(unix)]
            {
                if fault == Some(AtomicWriteFailAt::AtParentFsync) {
                    return Err(AtomicWriteError::AtParentFsync(io::Error::other(
                        "injected parent fsync failure",
                    )));
                }
                match File::open(parent) {
                    Ok(dir) => {
                        if let Err(e) = dir.sync_all() {
                            return Err(AtomicWriteError::AtParentFsync(e));
                        }
                    }
                    Err(e) => return Err(AtomicWriteError::AtParentFsync(e)),
                }
            }

            Ok(())
        }

        fn read_if_exists(&self, path: &Path) -> io::Result<Option<Vec<u8>>> {
            self.inner.read_if_exists(path)
        }

        fn list_orphan_tmps(&self, vault_path: &Path) -> io::Result<Vec<PathBuf>> {
            self.inner.list_orphan_tmps(vault_path)
        }

        fn remove_quiet(&self, path: &Path) {
            self.inner.remove_quiet(path);
        }
    }
}
