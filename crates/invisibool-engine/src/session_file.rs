//! `--session` file format: an AEAD-encrypted `{fake -> real}` map
//! written to disk between a `scrub --session PATH` and a
//! `restore --session PATH`.
//!
//! ## Chunk-21 scope
//!
//! This module is the on-disk artifact for the terminal-mode session
//! store. The design is an AEAD-encrypted file under a private app
//! dir, keyed from the vault/keychain, with a mandatory short TTL
//! and auto-expiry, wiped on restore or on expiry. Chunk 21 delivers
//! the AEAD file itself and the merge / expiry / wipe semantics. The
//! `session ls|clear` subcommand and the daemon-side `watch` idle
//! lock live in later milestones (M4a full CLI; M1 chunks 22-27 for
//! the daemon path).
//!
//! ## Cryptographic design
//!
//! Reuses every primitive from the vault's chunk-18 AEAD path
//! (XChaCha20-Poly1305, HKDF-SHA-256, `write_atomic`), with **three
//! deliberately-distinct** identifiers so a session file and a vault
//! file cannot be confused under a shared vault key:
//!
//! 1. **MAGIC:** `b"INVISIBOOL_SESSN"` (vault uses `b"INVISIBOOL_VAULT"`).
//!    In the AAD, so tampering fails the AEAD tag check; also
//!    checked before AEAD so wrong-file-kind returns a typed
//!    `NotASessionFile` rather than a raw AEAD failure.
//! 2. **VERSION:** starts at `0x01`, independent of the vault
//!    format's version byte.
//! 3. **HKDF `info` label:** `b"invisibool-session-aead-v1"` (vault
//!    uses `b"invisibool-vault-aead-v1"`). Same vault key sources
//!    both, but the derived subkeys are independent per HKDF's
//!    domain-separation guarantee.
//!
//! ## On-disk layout (identical shape to the vault, distinct bytes)
//!
//! ```text
//! 0..16   magic    = b"INVISIBOOL_SESSN"       (distinct from vault)
//! 16      version  = 0x01
//! 17..20  reserved = [0x00, 0x00, 0x00]
//! 20..44  nonce    = 24 random bytes (XChaCha20-Poly1305)
//! 44..N   ciphertext_and_tag                    (Poly1305 tag = last 16 bytes)
//! ```
//!
//! First 20 bytes are the AAD. Tampering with any of them fails
//! Poly1305; the version-in-AAD guarantee inherits from the vault
//! design (see `vault/mod.rs` for the reasoning).
//!
//! ## Plaintext schema
//!
//! The plaintext (the bytes that get AEAD-encrypted) is the
//! `serde_json`-encoded form of [`SessionContents`]:
//! `{schema_version, created_at, expires_at, entries: [{fake, real}, ...]}`.
//! `created_at` and `expires_at` are Unix epoch seconds; the CLI
//! layer passes `SystemTime::UNIX_EPOCH.elapsed()` from production
//! callers and known constants from tests.
//!
//! ## Expiry semantics
//!
//! - Fresh scrub with `--session PATH` where PATH does not exist:
//!   `created_at = now_epoch`, `expires_at = now_epoch + SESSION_TTL_SECS`.
//! - Repeat scrub against an existing (non-expired) file: the
//!   CLI-layer merge preserves the ORIGINAL `expires_at`. A fresh
//!   TTL per scrub would let repeated scrubbing keep a session
//!   alive forever, defeating the spec's mandatory short TTL.
//! - Load with `expires_at <= now_epoch`: fail closed with
//!   `SessionFileError::Expired { expired_at }`. Never silently reset.
//! - Wipe on successful restore: unlink, not shred. Modern
//!   filesystems' journaling / SSD wear-levelling make overwrite-based
//!   shredding largely ineffective; the real confidentiality mitigation
//!   is AEAD ciphertext + keychain custody. Documented in
//!   `docs/THREAT_MODEL.md` row 15.
//!
//! ## Zeroize coverage
//!
//! Four wipeable surfaces mirror the vault's five:
//! - vault key bytes (passed in by `Vault`): wrapped by the caller;
//!   this module never stores the key past a single crypto call.
//! - derived AEAD key: `Zeroizing<[u8; 32]>`, dropped at end of the
//!   encrypt or decrypt helper.
//! - decrypted plaintext bytes: `Zeroizing<Vec<u8>>`, dropped after
//!   the serde_json parse into `SessionContents`.
//! - `SessionContents.entries[i].real`: plain `String` during the
//!   deserialize window - same class of residual as the vault's
//!   documented in `docs/THREAT_MODEL.md` row 14; the sibling
//!   row-15 addition names it explicitly and defers the closure
//!   to M4a alongside the vault-side siblings.

use std::path::Path;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::vault::{AtomicWriteError, VaultIo};

// ---------- file-format constants ----------

/// Magic bytes identifying an Invisibool session file. 16 ASCII bytes,
/// deliberately DISTINCT from the vault's `INVISIBOOL_VAULT` so a
/// wrong-file-kind operation fails with a clean typed error rather
/// than a subtle AEAD or JSON-schema failure. In AAD; tampering causes
/// a decryption failure.
pub(crate) const SESSION_MAGIC: &[u8; 16] = b"INVISIBOOL_SESSN";

/// File-format version. Independent of the vault's version byte.
/// In AAD.
pub(crate) const SESSION_VERSION: u8 = 1;

/// Reserved bytes for future format flags. In AAD.
pub(crate) const SESSION_RESERVED: [u8; 3] = [0, 0, 0];

/// Length of the AAD passed to the AEAD: magic + version + reserved.
const AAD_LEN: usize = 20;

/// XChaCha20-Poly1305 nonce length (192 bits = 24 bytes).
const NONCE_LEN: usize = 24;

/// Poly1305 tag length, appended to the ciphertext by the AEAD.
const TAG_LEN: usize = 16;

/// AEAD-key length: 32 bytes (256 bits).
const AEAD_KEY_LEN: usize = 32;

/// HKDF `info` string for deriving the session file's AEAD subkey
/// from the vault key. Deliberately DISTINCT from the vault's
/// `invisibool-vault-aead-v1` so the two derived keys are
/// independent under HKDF's domain-separation guarantee.
const SESSION_HKDF_INFO_AEAD: &[u8] = b"invisibool-session-aead-v1";

/// Default session TTL: 30 minutes, mandatory-short per the
/// session-file design. Chunk 21 ships this as a fixed constant;
/// configurability lands with the full CLI in M4a.
pub const SESSION_TTL_SECS: u64 = 30 * 60;

/// Unix file mode for the session file at create time. Owner
/// read/write only, matching the vault's `0o600` discipline.
pub const SESSION_FILE_MODE: u32 = 0o600;

/// The plaintext-schema version written for new session files at
/// chunk 21. Independent from the file-format version above.
const CURRENT_SESSION_SCHEMA_VERSION: u32 = 1;

// ---------- plaintext schema ----------

/// Plaintext of a session file. After AEAD decrypt, `serde_json`
/// parses the ciphertext into this. Consumed by the CLI's
/// `restore --session PATH` handler to seed a `SessionMap` before
/// the engine's restore pass.
#[derive(Debug, Serialize, Deserialize)]
pub struct SessionContents {
    /// Plaintext-schema version. Independent from the file-format
    /// version.
    pub schema_version: u32,
    /// Unix epoch seconds of the file's first-write time. Never
    /// changes across merges (see `expires_at`).
    pub created_at: u64,
    /// Unix epoch seconds after which the session file is refused at
    /// load time. Load-bearing invariant: a repeat-scrub merge does
    /// NOT push this forward - if `created_at + SESSION_TTL_SECS`
    /// once, it stays there. Otherwise repeated scrubs could keep a
    /// session alive indefinitely, violating the spec's mandatory
    /// short TTL.
    pub expires_at: u64,
    /// The `{fake -> real}` pairs stored during scrubs. Ordering is
    /// not semantic; equality of entries is by the pair.
    pub entries: Vec<SessionPair>,
}

/// One `{fake -> real}` pair.
///
/// `fake` is opaque (safe to log if the user wanted to). `real` is
/// the registered plaintext - as sensitive as any vault entry's
/// value, and covered by the same THREAT_MODEL row 15 residuals.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct SessionPair {
    pub fake: String,
    pub real: String,
}

impl SessionContents {
    /// Build a fresh, empty session-contents at time `now_epoch`.
    /// `expires_at` is `now_epoch + SESSION_TTL_SECS`.
    pub fn new_at(now_epoch: u64) -> Self {
        Self {
            schema_version: CURRENT_SESSION_SCHEMA_VERSION,
            created_at: now_epoch,
            expires_at: now_epoch.saturating_add(SESSION_TTL_SECS),
            entries: Vec::new(),
        }
    }
}

// ---------- error type ----------

/// Reasons a session-file operation can fail.
#[derive(Debug)]
pub enum SessionFileError {
    /// I/O on the session file failed (open, read, remove).
    Io(std::io::Error),
    /// Atomic write of a new session file failed.
    AtomicWrite(AtomicWriteError),
    /// The file's first 16 bytes are not the session MAGIC. A common
    /// cause is pointing `--session` at a vault file or an unrelated
    /// file. Fails typed rather than surfacing as a raw AEAD failure.
    NotASessionFile,
    /// The file's version byte is not one this reader understands.
    UnsupportedVersion(u8),
    /// The file is shorter than the minimum session file size
    /// (20-byte header + 24-byte nonce + 16-byte tag).
    TruncatedFile,
    /// AEAD authentication failed: ciphertext tampered, AAD does not
    /// match, nonce does not match what was used to encrypt, or the
    /// AEAD key is wrong (different vault, different keychain slot).
    AeadDecrypt,
    /// Plaintext parsed to a `SessionContents` with `expires_at <=
    /// now_epoch`. Load-bearing failure mode: refuse rather than
    /// silently reset the file.
    Expired { expired_at: u64 },
    /// The plaintext was AEAD-valid but serde_json could not parse
    /// it. Indicates a session file written by a version with a
    /// different plaintext schema.
    Serde(serde_json::Error),
}

impl std::fmt::Display for SessionFileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "session file I/O: {e}"),
            Self::AtomicWrite(e) => write!(f, "session file write: {e}"),
            Self::NotASessionFile => write!(
                f,
                "the path does not point at an Invisibool session file \
                 (magic bytes do not match); if you meant to use a fresh path, \
                 remove or choose a different filename"
            ),
            Self::UnsupportedVersion(v) => write!(
                f,
                "session file format version {v} is not supported by this reader"
            ),
            Self::TruncatedFile => {
                write!(f, "session file is truncated below the minimum size")
            }
            Self::AeadDecrypt => write!(
                f,
                "session file decryption failed (wrong key, tampered ciphertext, \
                 or the file was written under a different vault)"
            ),
            Self::Expired { expired_at } => write!(
                f,
                "session file expired at Unix epoch {expired_at}; \
                 please pick a fresh path or delete this file - \
                 a fresh scrub cannot silently reset the TTL"
            ),
            Self::Serde(e) => write!(f, "session file plaintext could not be parsed: {e}"),
        }
    }
}

impl std::error::Error for SessionFileError {}

impl From<std::io::Error> for SessionFileError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<AtomicWriteError> for SessionFileError {
    fn from(e: AtomicWriteError) -> Self {
        Self::AtomicWrite(e)
    }
}

impl From<serde_json::Error> for SessionFileError {
    fn from(e: serde_json::Error) -> Self {
        Self::Serde(e)
    }
}

// ---------- AEAD helpers ----------

fn os_random_nonce() -> [u8; NONCE_LEN] {
    let mut buf = [0u8; NONCE_LEN];
    // Inherits the vault-side `os_random` PANIC CONTRACT: a CSPRNG
    // failure is unrecoverable (a non-random nonce would leak the
    // XChaCha20-Poly1305 authentication key and the plaintext).
    getrandom::fill(&mut buf).expect(
        "OS CSPRNG must be available; \
         refusing to continue with a non-random session file nonce",
    );
    buf
}

fn derive_session_aead_key(vault_key: &[u8]) -> Zeroizing<[u8; AEAD_KEY_LEN]> {
    let hk = Hkdf::<Sha256>::new(None, vault_key);
    let mut out = [0u8; AEAD_KEY_LEN];
    hk.expand(SESSION_HKDF_INFO_AEAD, &mut out)
        .expect("HKDF-SHA-256 expand to AEAD_KEY_LEN bytes always succeeds");
    Zeroizing::new(out)
}

fn build_session_aad() -> [u8; AAD_LEN] {
    let mut aad = [0u8; AAD_LEN];
    aad[..16].copy_from_slice(SESSION_MAGIC);
    aad[16] = SESSION_VERSION;
    aad[17..20].copy_from_slice(&SESSION_RESERVED);
    aad
}

/// AEAD-encrypt `plaintext` under a key derived from `vault_key`
/// via the session-specific HKDF label. Returns the on-disk bytes
/// (`aad || nonce || ciphertext+tag`).
pub(crate) fn encrypt_session_bytes(
    vault_key: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, SessionFileError> {
    let aead_key = derive_session_aead_key(vault_key);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(aead_key.as_ref()));

    let nonce_bytes = os_random_nonce();
    let aad = build_session_aad();

    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce_bytes),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| SessionFileError::AeadDecrypt)?;

    let mut file_bytes = Vec::with_capacity(AAD_LEN + NONCE_LEN + ciphertext.len());
    file_bytes.extend_from_slice(&aad);
    file_bytes.extend_from_slice(&nonce_bytes);
    file_bytes.extend_from_slice(&ciphertext);
    Ok(file_bytes)
}

/// Reverse of [`encrypt_session_bytes`]. Validates header bytes
/// BEFORE running AEAD so wrong-magic returns a typed
/// [`SessionFileError::NotASessionFile`] instead of surfacing as a
/// raw crypto failure. Also enforces `expires_at > now_epoch`.
///
/// Returns the parsed [`SessionContents`] on success; the plaintext
/// intermediate is `Zeroizing<Vec<u8>>` for its lifetime inside
/// this function.
pub(crate) fn decrypt_session_bytes(
    vault_key: &[u8],
    file_bytes: &[u8],
    now_epoch: u64,
) -> Result<SessionContents, SessionFileError> {
    if file_bytes.len() < AAD_LEN + NONCE_LEN + TAG_LEN {
        return Err(SessionFileError::TruncatedFile);
    }
    if file_bytes[..16] != SESSION_MAGIC[..] {
        return Err(SessionFileError::NotASessionFile);
    }
    if file_bytes[16] != SESSION_VERSION {
        return Err(SessionFileError::UnsupportedVersion(file_bytes[16]));
    }
    // Reserved bytes are AAD-authenticated; mismatched values fail as
    // AeadDecrypt rather than a separate typed error.

    let aad = &file_bytes[..AAD_LEN];
    let nonce_slice = &file_bytes[AAD_LEN..AAD_LEN + NONCE_LEN];
    let nonce: &[u8; NONCE_LEN] =
        <&[u8; NONCE_LEN]>::try_from(nonce_slice).expect("slice length checked above");
    let ciphertext = &file_bytes[AAD_LEN + NONCE_LEN..];

    let aead_key = derive_session_aead_key(vault_key);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(aead_key.as_ref()));

    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| SessionFileError::AeadDecrypt)?;

    let plaintext = Zeroizing::new(plaintext);
    let contents: SessionContents = serde_json::from_slice(&plaintext)?;

    if contents.expires_at <= now_epoch {
        return Err(SessionFileError::Expired {
            expired_at: contents.expires_at,
        });
    }
    Ok(contents)
}

// ---------- public save / load helpers ----------

/// Load a session file from `path`, decrypting under `vault_key` and
/// checking `expires_at > now_epoch`. Returns `Ok(None)` if the file
/// does not exist (the caller decides whether that is an error - for
/// `scrub --session` it means "fresh session"; for `restore --session`
/// it means "fail closed").
pub fn load_session_file(
    io: &dyn VaultIo,
    path: &Path,
    vault_key: &[u8],
    now_epoch: u64,
) -> Result<Option<SessionContents>, SessionFileError> {
    let bytes = io.read_if_exists(path)?;
    match bytes {
        None => Ok(None),
        Some(bytes) => Ok(Some(decrypt_session_bytes(vault_key, &bytes, now_epoch)?)),
    }
}

/// Serialize `contents`, AEAD-encrypt under a subkey derived from
/// `vault_key`, and atomically write to `path` with mode
/// [`SESSION_FILE_MODE`].
///
/// The serde_json plaintext is wrapped in `Zeroizing<Vec<u8>>` for
/// its (short) in-scope lifetime so it wipes on drop after
/// encryption. The engine-internal `SessionContents.entries[i].real`
/// residual is documented in THREAT_MODEL row 15.
pub fn save_session_file(
    io: &dyn VaultIo,
    path: &Path,
    vault_key: &[u8],
    contents: &SessionContents,
) -> Result<(), SessionFileError> {
    let plaintext = Zeroizing::new(serde_json::to_vec(contents)?);
    let file_bytes = encrypt_session_bytes(vault_key, &plaintext)?;
    io.write_atomic(path, &file_bytes, SESSION_FILE_MODE)?;
    Ok(())
}

/// Best-effort unlink of the session file. Called by
/// `restore --session PATH` after a successful restore: the design
/// requires `restore --session` to consume the file and wipe it.
///
/// UNLINK, NOT SHRED. Modern filesystems' journaling + SSD
/// wear-levelling make overwrite-based shredding largely ineffective;
/// the real confidentiality mitigation is AEAD ciphertext + keychain
/// custody. THREAT_MODEL row 15 documents the surviving-blocks
/// residual honestly.
pub fn wipe_session_file(path: &Path) -> std::io::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

// ---------- tests ----------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::StdVaultIo;
    use std::path::PathBuf;

    /// Small temp dir with cleanup on drop. Local mirror of the
    /// pattern the vault tests use; keeps this module hermetic.
    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new(tag: &str) -> Self {
            use std::sync::atomic::{AtomicU64, Ordering};
            static N: AtomicU64 = AtomicU64::new(0);
            let n = N.fetch_add(1, Ordering::Relaxed);
            let pid = std::process::id();
            let path = std::env::temp_dir().join(format!("invisibool-session-{tag}-{pid}-{n}"));
            std::fs::create_dir_all(&path).expect("create temp dir");
            Self { path }
        }
        fn file(&self, name: &str) -> PathBuf {
            self.path.join(name)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    fn key() -> Vec<u8> {
        vec![0xA5u8; 32]
    }

    fn contents_with(now_epoch: u64, entries: Vec<(&str, &str)>) -> SessionContents {
        let mut c = SessionContents::new_at(now_epoch);
        for (fake, real) in entries {
            c.entries.push(SessionPair {
                fake: fake.to_string(),
                real: real.to_string(),
            });
        }
        c
    }

    // ----- format constants pinned -----

    #[test]
    fn format_constants_pinned() {
        assert_eq!(SESSION_MAGIC, b"INVISIBOOL_SESSN");
        assert_eq!(SESSION_MAGIC.len(), 16);
        assert_eq!(SESSION_VERSION, 1);
        assert_eq!(SESSION_RESERVED, [0u8; 3]);
        assert_eq!(AAD_LEN, 20);
        assert_eq!(NONCE_LEN, 24);
        assert_eq!(TAG_LEN, 16);
        assert_eq!(AEAD_KEY_LEN, 32);
        assert_eq!(SESSION_TTL_SECS, 30 * 60);
        assert_eq!(SESSION_FILE_MODE, 0o600);
        assert_eq!(SESSION_HKDF_INFO_AEAD, b"invisibool-session-aead-v1");
    }

    #[test]
    fn session_magic_differs_from_vault_magic() {
        // Guards against a mid-review rename that would collapse the
        // two file kinds under a shared vault key. Distinct MAGIC is
        // the type-tag that lets wrong-file-kind fail as
        // NotASessionFile rather than as a raw AEAD or JSON error.
        assert_ne!(SESSION_MAGIC.as_slice(), b"INVISIBOOL_VAULT" as &[u8]);
    }

    // ----- round trip -----

    #[test]
    fn session_file_round_trips_through_aead() {
        let dir = TempDir::new("round-trip");
        let path = dir.file("s.bin");
        let io = StdVaultIo;
        let k = key();

        let now = 1_000_000_u64;
        let original = contents_with(
            now,
            vec![
                ("fake@example.com", "alice@example.com"),
                ("555-0100", "617-555-9922"),
            ],
        );
        save_session_file(&io, &path, &k, &original).expect("save");

        let loaded = load_session_file(&io, &path, &k, now + 1)
            .expect("load")
            .expect("Some(contents) - file was written");
        assert_eq!(loaded.schema_version, original.schema_version);
        assert_eq!(loaded.created_at, original.created_at);
        assert_eq!(loaded.expires_at, original.expires_at);
        assert_eq!(loaded.entries, original.entries);
    }

    // ----- typed errors -----

    #[test]
    fn wrong_magic_returns_typed_not_a_session_file_not_crypto() {
        let dir = TempDir::new("wrong-magic");
        let path = dir.file("v.bin");
        // Write bytes that look like a vault file: right length band,
        // wrong first 16 bytes (INVISIBOOL_VAULT not INVISIBOOL_SESSN).
        let mut bytes = vec![0u8; 100];
        bytes[..16].copy_from_slice(b"INVISIBOOL_VAULT");
        std::fs::write(&path, &bytes).expect("write");

        let err = load_session_file(&StdVaultIo, &path, &key(), 1_000_000)
            .expect_err("wrong magic must fail");
        assert!(
            matches!(err, SessionFileError::NotASessionFile),
            "wrong-magic must surface as NotASessionFile (typed), not as AeadDecrypt \
             (crypto) or Serde (schema). Got: {err:?}"
        );
    }

    #[test]
    fn truncated_file_returns_typed_truncated() {
        let dir = TempDir::new("truncated");
        let path = dir.file("s.bin");
        std::fs::write(&path, b"short").expect("write");
        let err = load_session_file(&StdVaultIo, &path, &key(), 1_000_000).expect_err("must fail");
        assert!(matches!(err, SessionFileError::TruncatedFile), "{err:?}");
    }

    #[test]
    fn expired_file_returns_typed_expired() {
        let dir = TempDir::new("expired");
        let path = dir.file("s.bin");
        let io = StdVaultIo;
        let k = key();
        let contents = contents_with(1_000_000, vec![("f", "r")]);
        // expires_at = 1_000_000 + 30*60 = 1_001_800
        save_session_file(&io, &path, &k, &contents).expect("save");

        // Load AT expiry (equals expires_at) - must refuse.
        let err = load_session_file(&io, &path, &k, contents.expires_at)
            .expect_err("expired must refuse");
        assert!(
            matches!(err, SessionFileError::Expired { expired_at } if expired_at == contents.expires_at),
            "{err:?}"
        );

        // Load PAST expiry - must also refuse.
        let err2 = load_session_file(&io, &path, &k, contents.expires_at + 1)
            .expect_err("past-expiry must refuse");
        assert!(matches!(err2, SessionFileError::Expired { .. }), "{err2:?}");
    }

    #[test]
    fn wrong_key_returns_typed_aead_decrypt() {
        let dir = TempDir::new("wrong-key");
        let path = dir.file("s.bin");
        let io = StdVaultIo;
        let contents = contents_with(1_000_000, vec![("f", "r")]);
        save_session_file(&io, &path, &key(), &contents).expect("save");

        // Different key: same length, different bytes.
        let other_key = vec![0x5Au8; 32];
        let err =
            load_session_file(&io, &path, &other_key, 1_000_001).expect_err("wrong key must fail");
        assert!(matches!(err, SessionFileError::AeadDecrypt), "{err:?}");
    }

    #[test]
    fn missing_file_returns_ok_none() {
        let dir = TempDir::new("missing");
        let path = dir.file("does-not-exist.bin");
        let got = load_session_file(&StdVaultIo, &path, &key(), 1_000_000).expect("no error");
        assert!(got.is_none());
    }

    // ----- wipe -----

    #[test]
    fn wipe_removes_the_file() {
        let dir = TempDir::new("wipe");
        let path = dir.file("s.bin");
        std::fs::write(&path, b"some bytes").expect("write");
        assert!(path.exists());
        wipe_session_file(&path).expect("wipe");
        assert!(!path.exists());
    }

    #[test]
    fn wipe_missing_file_is_ok() {
        let dir = TempDir::new("wipe-missing");
        let path = dir.file("never-existed.bin");
        wipe_session_file(&path).expect("no error on missing");
    }

    // ----- file mode -----

    #[test]
    #[cfg(unix)]
    fn saved_session_file_has_mode_0o600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new("mode");
        let path = dir.file("s.bin");
        let contents = contents_with(1_000_000, vec![("f", "r")]);
        save_session_file(&StdVaultIo, &path, &key(), &contents).expect("save");
        let mode = std::fs::metadata(&path).expect("stat").permissions().mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "session file must be mode 0o600, got {:o}",
            mode & 0o777
        );
    }

    // ----- new_at expiry math -----

    #[test]
    fn new_at_sets_expires_at_created_plus_ttl() {
        let c = SessionContents::new_at(1_000_000);
        assert_eq!(c.created_at, 1_000_000);
        assert_eq!(c.expires_at, 1_000_000 + SESSION_TTL_SECS);
        assert!(c.entries.is_empty());
        assert_eq!(c.schema_version, CURRENT_SESSION_SCHEMA_VERSION);
    }
}
