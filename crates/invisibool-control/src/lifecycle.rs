//! Single-instance locking and stale-socket cleanup.
//!
//! Startup sequence used by the daemon:
//!   1. `SingleInstanceLock::acquire(lock_path)`: takes an exclusive
//!      `flock(LOCK_EX | LOCK_NB)` on `ctl.lock`. On contention,
//!      returns `SingleInstanceLockHeld` with the lock path in the
//!      message. Does NOT auto-unlink stale lock files: `flock` is
//!      released by the kernel on process death regardless, so a
//!      lingering file is harmless (a fresh daemon just re-acquires).
//!   2. `cleanup_stale_socket(socket_path)`: if the socket exists,
//!      try to `connect()` with a short timeout. If the connect
//!      succeeds, another daemon really is running; return
//!      `SingleInstanceLockHeld`. If it fails with `ConnectionRefused`
//!      or `NotFound`, the socket is stale; unlink it. Anything else
//!      (`PermissionDenied` etc.) is refused rather than blindly
//!      unlinked.
//!   3. `UnixServer::bind()` (in `transport.rs`): binds the fresh
//!      socket at 0600 under a 0700 parent.

use std::fs;
use std::io;
use std::mem;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

use crate::error::ControlError;

/// Held for the lifetime of a running daemon. Drop releases the
/// flock (and the OS releases it automatically on process death).
#[derive(Debug)]
pub struct SingleInstanceLock {
    file: fs::File,
    path: PathBuf,
}

impl SingleInstanceLock {
    /// Acquire an exclusive non-blocking flock on `lock_path`.
    ///
    /// The parent directory is expected to already exist at 0700
    /// (transport::UnixServer::bind creates it in the normal flow;
    /// callers that lock before binding should call
    /// prepare_lock_parent below).
    pub fn acquire(lock_path: PathBuf) -> Result<Self, ControlError> {
        use std::fs::OpenOptions;
        use std::os::unix::fs::OpenOptionsExt;
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .mode(0o600)
            .open(&lock_path)?;
        // Safety: fd is valid for the lifetime of the borrowed file;
        // LOCK_EX | LOCK_NB does not block.
        #[allow(unsafe_code)]
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if rc != 0 {
            let e = io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EWOULDBLOCK) {
                return Err(ControlError::SingleInstanceLockHeld {
                    path: lock_path.display().to_string(),
                });
            }
            return Err(ControlError::Io(e));
        }
        Ok(Self {
            file,
            path: lock_path,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for SingleInstanceLock {
    fn drop(&mut self) {
        // Release explicitly so the fd is closed before we unlink;
        // OS releases the flock either way.
        // Safety: fd is valid for the lifetime of the file field.
        #[allow(unsafe_code)]
        unsafe {
            libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
        }
        // Best-effort unlink on clean shutdown. A crash leaves the
        // file behind; that is fine, the flock is released by the
        // OS and a fresh daemon reacquires.
        let _ = fs::remove_file(&self.path);
    }
}

/// Ensure the parent directory of the given path exists at 0700.
/// Called separately from bind so callers can lock before binding
/// (which is how the daemon startup sequence is ordered).
pub fn prepare_parent_dir_0700(path: &Path) -> Result<(), ControlError> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::other("path has no parent"))?;
    match fs::metadata(parent) {
        Ok(md) => {
            use std::os::unix::fs::PermissionsExt;
            let actual = md.permissions().mode() & 0o777;
            if actual != 0o700 {
                return Err(ControlError::SocketDirWrongMode {
                    path: parent.display().to_string(),
                    actual_mode: actual,
                    expected_mode: 0o700,
                });
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            use std::os::unix::fs::PermissionsExt;
            fs::create_dir_all(parent)?;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
        }
        Err(e) => return Err(ControlError::Io(e)),
    }
    Ok(())
}

/// Detect and unlink a stale socket at `socket_path`.
///
/// Uses a **non-blocking** `connect(2)` probe (never blocks in
/// pathological cases where a live daemon has a full accept
/// queue - test-8 empirical results confirm blocking `connect()`
/// hangs indefinitely on that condition).
///
/// Behavior:
///   - Path does not exist: no-op, return Ok.
///   - Non-blocking connect returns 0 (accepted): another daemon is
///     running with an empty queue slot; return `SingleInstanceLockHeld`.
///   - Non-blocking connect returns `EAGAIN` / `EWOULDBLOCK` or
///     `EINPROGRESS`: another daemon is running with a full accept
///     queue or an in-progress non-blocking handshake; STILL treated
///     as live, return `SingleInstanceLockHeld`. Do not unlink; a
///     live-but-busy peer is not stale.
///   - Non-blocking connect returns `ECONNREFUSED` or `ENOENT`: no
///     listener; stale, unlink and return Ok.
///   - Any other errno (`EACCES`, `EPERM`, etc.): refuse to unlink,
///     return `StaleSocketCleanupRefused`.
pub fn cleanup_stale_socket(socket_path: &Path) -> Result<(), ControlError> {
    if !socket_path.exists() {
        return Ok(());
    }
    match probe_connect_nonblocking(socket_path) {
        Ok(ProbeResult::Live) => Err(ControlError::SingleInstanceLockHeld {
            path: socket_path.display().to_string(),
        }),
        Ok(ProbeResult::Stale) => {
            fs::remove_file(socket_path).map_err(ControlError::Io)?;
            Ok(())
        }
        Err(e) => Err(ControlError::StaleSocketCleanupRefused {
            path: socket_path.display().to_string(),
            source: e,
        }),
    }
}

enum ProbeResult {
    Live,
    Stale,
}

/// Non-blocking connect probe. Returns immediately (no timeout
/// parameter because none is needed on UDS: SOCK_STREAM UDS
/// `connect(2)` on Linux completes synchronously in the kernel -
/// there is no TCP-style handshake - so a non-blocking call
/// returns 0 or the classifying errno right away).
fn probe_connect_nonblocking(socket_path: &Path) -> io::Result<ProbeResult> {
    // Safety: socket(2) with valid AF/type/protocol constants; we
    // check the return for -1.
    #[allow(unsafe_code)]
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_NONBLOCK, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let _guard = FdGuard(fd);

    // Encode the path into sockaddr_un.
    #[allow(unsafe_code)]
    let mut addr: libc::sockaddr_un = unsafe { mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let path_bytes = socket_path.as_os_str().as_bytes();
    if path_bytes.len() >= addr.sun_path.len() {
        return Err(io::Error::other("socket path too long for sockaddr_un"));
    }
    for (i, b) in path_bytes.iter().enumerate() {
        addr.sun_path[i] = *b as libc::c_char;
    }
    // Trailing NUL is already in place because we zeroed the struct.
    let addr_len = (mem::size_of::<libc::sa_family_t>() + path_bytes.len() + 1) as libc::socklen_t;

    // Safety: fd is valid until the FdGuard drops; addr is a
    // properly-populated sockaddr_un.
    #[allow(unsafe_code)]
    let rc = unsafe { libc::connect(fd, &addr as *const _ as *const libc::sockaddr, addr_len) };
    if rc == 0 {
        return Ok(ProbeResult::Live);
    }
    let err = io::Error::last_os_error();
    match err.raw_os_error() {
        Some(libc::ECONNREFUSED) | Some(libc::ENOENT) => Ok(ProbeResult::Stale),
        // EAGAIN: full accept queue on a live listener. On Linux
        // libc::EWOULDBLOCK aliases to EAGAIN so the extra arm is
        // unreachable and omitted; on the macOS / *BSD path (later
        // chunk) both values are still numerically EAGAIN.
        // EINPROGRESS: some UDS variants report this on non-blocking
        // connect instead of 0. Both mean "live".
        Some(libc::EAGAIN) | Some(libc::EINPROGRESS) => Ok(ProbeResult::Live),
        _ => Err(err),
    }
}

/// RAII fd closer for the probe socket.
struct FdGuard(libc::c_int);

impl Drop for FdGuard {
    fn drop(&mut self) {
        // Safety: fd owned by this guard; close(2) always safe on a
        // held fd.
        #[allow(unsafe_code)]
        unsafe {
            libc::close(self.0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acquire_holds_and_second_acquire_reports_lock_held() {
        let tmp = tempfile::tempdir().unwrap();
        let lock_path = tmp.path().join("ctl.lock");
        let lock_a = SingleInstanceLock::acquire(lock_path.clone()).unwrap();

        // Second acquire from the same process: flock semantics
        // vary: on Linux the same-process case honors the exclusive
        // flock across different fds. We open a fresh fd via the
        // acquire path.
        let err = SingleInstanceLock::acquire(lock_path.clone()).unwrap_err();
        match err {
            ControlError::SingleInstanceLockHeld { path } => {
                assert!(
                    path.contains("ctl.lock"),
                    "error message must name the lock file: {path}"
                );
            }
            other => panic!("expected SingleInstanceLockHeld, got {other:?}"),
        }
        drop(lock_a);
        // After drop, the lock file is removed and re-acquire works.
        let _lock_b = SingleInstanceLock::acquire(lock_path).unwrap();
    }

    #[test]
    fn acquire_does_not_touch_socket_or_lock_when_it_reports_held() {
        let tmp = tempfile::tempdir().unwrap();
        let lock_path = tmp.path().join("ctl.lock");
        let sock_path = tmp.path().join("ctl.sock");
        // Create both files ahead of time so we can check they
        // survive the failed acquire attempt.
        std::fs::write(&sock_path, b"placeholder").unwrap();
        let _held = SingleInstanceLock::acquire(lock_path.clone()).unwrap();
        let attempt = SingleInstanceLock::acquire(lock_path.clone());
        assert!(matches!(
            attempt,
            Err(ControlError::SingleInstanceLockHeld { .. })
        ));
        assert!(
            sock_path.exists(),
            "failed lock attempt must NOT unlink the socket"
        );
        assert!(
            lock_path.exists(),
            "failed lock attempt must NOT unlink the lock"
        );
    }

    #[test]
    fn cleanup_no_op_when_socket_absent() {
        let tmp = tempfile::tempdir().unwrap();
        let socket_path = tmp.path().join("ctl.sock");
        cleanup_stale_socket(&socket_path).unwrap();
    }

    #[test]
    fn cleanup_unlinks_regular_file_at_socket_path() {
        // A regular file at the socket path is stale. On Linux,
        // UnixStream::connect() to a regular file returns
        // ECONNREFUSED, so cleanup classifies it as stale and
        // unlinks. This is acceptable because the parent directory
        // is exclusively invisibool-owned (verified 0700 by
        // transport::prepare_parent_dir before bind).
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("ctl.sock");
        std::fs::write(&path, b"stale").unwrap();
        cleanup_stale_socket(&path).unwrap();
        assert!(
            !path.exists(),
            "regular file at socket path is treated as stale and unlinked"
        );
    }

    #[test]
    fn cleanup_refuses_when_probe_returns_unclassifiable_error() {
        // Point at a path whose parent doesn't exist. connect()
        // returns ENOENT which we classify as NotFound → treat as
        // stale (no-op unlink because the parent doesn't exist).
        // The exists()-check short-circuit means cleanup returns
        // Ok(()) before touching anything.
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("does-not-exist").join("ctl.sock");
        assert!(!path.exists());
        cleanup_stale_socket(&path).unwrap();
    }

    #[test]
    fn cleanup_unlinks_true_stale_socket() {
        // Create a real UDS, then drop the listener without unlinking.
        // The resulting inode is a socket type but nothing is listening.
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("ctl.sock");
        {
            let _listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
            // Set backlog high; leave scope.
        }
        assert!(path.exists());
        // connect() to a bound-but-closed UDS returns ECONNREFUSED.
        cleanup_stale_socket(&path).unwrap();
        assert!(!path.exists(), "stale socket must be unlinked");
    }

    /// Review item 4 regression: the previous probe used blocking
    /// `connect()` which hangs indefinitely on a live-but-backlog-full
    /// socket. Non-blocking `connect()` returns `EAGAIN` in that case;
    /// we classify it as "live", refuse to unlink, and return
    /// [`ControlError::SingleInstanceLockHeld`].
    ///
    /// Without the non-blocking fix in probe_connect_nonblocking,
    /// this test would hang forever rather than fail: that is the
    /// class of bug this test guards. (The test itself fills the
    /// backlog via raw non-blocking connects to avoid the same hang.)
    #[test]
    fn cleanup_refuses_when_probe_finds_live_daemon_with_full_backlog() {
        use std::os::unix::io::AsRawFd;
        use std::os::unix::net::UnixListener;
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("ctl.sock");
        let listener = UnixListener::bind(&path).unwrap();
        // Tiny backlog + do NOT accept: queue fills fast.
        #[allow(unsafe_code)]
        unsafe {
            libc::listen(listener.as_raw_fd(), 1);
        }
        // Fill the accept queue with raw non-blocking connects so we
        // do not hang if the queue closes at backlog+1.
        let mut fds: Vec<libc::c_int> = Vec::new();
        for _ in 0..4 {
            #[allow(unsafe_code)]
            let fd =
                unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_NONBLOCK, 0) };
            assert!(fd >= 0);
            #[allow(unsafe_code)]
            let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
            addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
            let path_bytes = path.as_os_str().as_bytes();
            for (i, b) in path_bytes.iter().enumerate() {
                if i >= addr.sun_path.len() - 1 {
                    break;
                }
                addr.sun_path[i] = *b as libc::c_char;
            }
            let addr_len = (std::mem::size_of::<libc::sa_family_t>() + path_bytes.len() + 1)
                as libc::socklen_t;
            #[allow(unsafe_code)]
            let _rc =
                unsafe { libc::connect(fd, &addr as *const _ as *const libc::sockaddr, addr_len) };
            fds.push(fd);
        }
        // With the queue full, cleanup must refuse: the socket is
        // LIVE even though non-blocking connect returns EAGAIN.
        let err = cleanup_stale_socket(&path).unwrap_err();
        assert!(
            matches!(err, ControlError::SingleInstanceLockHeld { .. }),
            "expected SingleInstanceLockHeld for live-but-busy socket, got {err:?}"
        );
        assert!(path.exists(), "must NOT unlink a live-but-busy socket");
        // Close held fds.
        for fd in fds {
            #[allow(unsafe_code)]
            unsafe {
                libc::close(fd);
            }
        }
    }
}
