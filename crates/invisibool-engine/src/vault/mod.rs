//! The encrypted-at-rest vault: holds registered values, AEAD-wrapped
//! under a key fetched from the keychain.
//!
//! ## What this module is
//!
//! At rest, the vault is one file on disk: a fixed 20-byte header
//! (magic + version + reserved), a 24-byte XChaCha20-Poly1305 nonce,
//! and the AEAD ciphertext of the JSON-serialized registered values.
//! In memory while the engine is running, the vault is a list of
//! [`format::VaultEntry`] structs ready to be turned into the
//! engine's [`crate::tokenizer::fpe::RegisteredValue`] set.
//!
//! ## Cryptographic design (load-bearing; do not change without a
//! security review)
//!
//! - **AEAD: XChaCha20-Poly1305.** 192-bit nonce; random per-encrypt
//!   from the OS CSPRNG. Collision probability at q writes is q^2 /
//!   2^192 (a 192-bit birthday bound), which is below any meaningful
//!   threshold for any realistic vault write count. No persistent
//!   nonce counter is required, eliminating that whole failure mode.
//! - **AEAD key derivation.** HKDF-SHA-256 with `salt = empty`,
//!   `ikm = vault_key` (fetched from the keychain), `info =
//!   "invisibool-vault-aead-v1"`. The versioned info string lets a
//!   future M4a rotate the derivation independently of the vault key.
//!   The same `vault_key` is the HKDF `ikm` for the FF1 subkey
//!   (separate info string, so the derived keys are independent).
//! - **AAD = first 20 bytes of the file** (magic + version +
//!   reserved). Tampering with any of those bytes makes Poly1305
//!   verification fail. Version-in-AAD specifically defeats downgrade
//!   attacks: a v2 reader cannot accept a v1 file even under the same
//!   vault key.
//! - **Atomic write.** Write to a sibling tmp file with `0o600` at
//!   create time, fsync, rename over the target, fsync the parent
//!   directory. At any crash point the on-disk state is either the
//!   old vault intact or the new vault durable, never a half-written
//!   file. The orphan-scan path at open cleans up any leftover tmp
//!   file from a previous crashed write.
//! - **No hand-rolled crypto.** Every primitive is from RustCrypto
//!   (`chacha20poly1305`, `hkdf`, `sha2`). The vault module only
//!   composes them.
//!
//! ## Crash safety + the OS CSPRNG
//!
//! Every random byte (vault key generation, nonce generation) flows
//! through [`os_random`], which calls `getrandom::fill` and PANICS on
//! failure. The PANIC CONTRACT documented on that helper is
//! load-bearing: a non-random nonce makes XChaCha20-Poly1305 unsafe;
//! a non-random vault key makes every future encrypt brute-forceable.
//! Returning an error here would let a caller paper over the failure
//! with a degraded fallback, so the helper has no `Result` by design.
//!
//! ## Zeroize coverage
//!
//! Five wipeable surfaces:
//! - vault key from keychain: `SecretBox<[u8; 32]>` from
//!   `keychain::fetch_or_create`, dropped after AEAD key derivation
//! - derived AEAD key: `Zeroizing<[u8; 32]>`, dropped at end of
//!   encrypt or decrypt
//! - decrypted plaintext bytes: `Zeroizing<Vec<u8>>`, dropped after
//!   serde_json parsing into VaultContents
//! - the ciphertext + nonce buffer assembled for write: dropped at
//!   end of save (no Zeroize needed; ciphertext is not secret)
//! - each registered value string in VaultEntry: plain `String`
//!   during the (short) deserialize window; moved into the engine's
//!   own `Zeroizing<String>` when `into_registered` runs. The
//!   serde_json intermediate allocation is a documented residual in
//!   the threat model.

mod format;
pub mod io;
mod path;

use std::path::{Path, PathBuf};

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use secrecy::{ExposeSecret, SecretBox};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::keychain::{self, KeychainBackend, KeychainError, KeychainSlot, KEY_LEN};
use crate::tokenizer::fpe::{
    FpeRegistration, KeyProvider, RegisteredValue, SessionFakeKind, SessionRegistration, TWEAK_LEN,
};

pub use format::{VaultContents, VaultEntry, VaultEntryKind};
pub use io::{AtomicWriteError, StdVaultIo, VaultIo};
pub use path::default_vault_path;

#[cfg(test)]
pub(crate) use io::{AtomicWriteFailAt, InjectableVaultIo};

use format::{
    resolve_alphabet, AAD_LEN, AEAD_KEY_LEN, HKDF_INFO_AEAD, MAGIC, NONCE_LEN, RESERVED, TAG_LEN,
    VERSION,
};

/// Unix file mode for the vault file at create time. Owner read/write
/// only; no other user on a shared system can read the ciphertext
/// (which is already AEAD-encrypted but defense-in-depth on the
/// filesystem boundary too).
pub const VAULT_FILE_MODE: u32 = 0o600;

// ---------- the os_random PANIC CONTRACT ----------

/// Fill `buf` with bytes from the OS CSPRNG.
///
/// **PANIC CONTRACT.** `getrandom` failure is unrecoverable and MUST
/// terminate the process. A non-random nonce would be catastrophic
/// (XChaCha20-Poly1305 nonce reuse leaks the authentication key plus
/// the plaintext); a non-random vault key would be even worse. The
/// helper has NO `Result` by design - returning one would let a
/// caller paper over the failure with a degraded fallback.
///
/// `expect` is the panic mechanism, which terminates the process with
/// the workspace's default `panic=unwind` behaviour. **Callers MUST
/// NOT wrap vault writes in `std::panic::catch_unwind`** - the only
/// safe response to a CSPRNG failure is process exit. If a future
/// contributor adds catch_unwind around a vault path, this contract
/// is defeated.
fn os_random(buf: &mut [u8]) {
    getrandom::fill(buf).expect(
        "OS CSPRNG must be available; \
         refusing to continue with non-random key/nonce material",
    );
}

/// Generate a fresh 16-byte FF1 tweak using the OS CSPRNG.
///
/// Inherits [`os_random`]'s **PANIC CONTRACT**: a CSPRNG failure
/// terminates the process. A non-random tweak weakens FF1 (the same
/// (key, tweak) pair encrypts the same plaintext to the same
/// ciphertext, so a repeated or predictable tweak across registered
/// values lets an observer correlate same-value-registered-twice and
/// reduces FF1's domain-separation guarantee). Treating CSPRNG
/// failure as recoverable would let a caller silently proceed with
/// zeros or low-entropy bytes; this helper has NO `Result` by design,
/// matching the discipline used for vault key/nonce generation.
///
/// Lives in this module (rather than in `tokenizer::fpe`) because it
/// reuses [`os_random`]'s already-audited panic path. If a future
/// `crypto_random` module ever consolidates all CSPRNG entry points,
/// both this and [`os_random`] move there together.
pub fn random_ff1_tweak() -> [u8; 16] {
    let mut buf = [0u8; 16];
    os_random(&mut buf);
    buf
}

// ---------- error type ----------

/// Reasons a vault operation can fail.
#[derive(Debug)]
pub enum VaultError {
    /// I/O on the vault file (open, read, list, remove) failed.
    Io(std::io::Error),
    /// Atomic write of a new vault file failed at a specific step.
    /// The original vault file (if any) is untouched.
    AtomicWrite(AtomicWriteError),
    /// The keychain backend returned an error (locked keychain, IPC
    /// failure). The vault is never decrypted under a key the
    /// keychain didn't successfully return.
    Keychain(KeychainError),
    /// The file's first 16 bytes are not the magic. Refuse to treat
    /// it as a vault.
    BadMagic,
    /// The file's version byte is not one this reader understands.
    /// Includes a downgrade-attack failure: a v2 reader rejects a v1
    /// file via this variant or via the AEAD verification (depending
    /// on whether the reader supports v1 at all).
    UnsupportedVersion(u8),
    /// The file is shorter than the minimum vault file size (20-byte
    /// header + 24-byte nonce + 16-byte tag = 60 bytes). Reject
    /// before attempting AEAD decryption.
    TruncatedFile,
    /// AEAD authentication failed: ciphertext was tampered with, the
    /// AAD doesn't match, the nonce doesn't match what was used to
    /// encrypt, or the AEAD key is wrong. The vault contents are not
    /// recoverable from this file with the current key.
    AeadDecrypt,
    /// The plaintext was AEAD-valid but serde_json could not parse
    /// it. Indicates a vault written by a version with a different
    /// plaintext schema; not recoverable here.
    Serde(serde_json::Error),
    /// A `VaultEntryKind::Fpe` entry referenced an alphabet name the
    /// reader doesn't know about.
    UnknownAlphabet(String),
}

impl std::fmt::Display for VaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "vault I/O: {e}"),
            Self::AtomicWrite(e) => write!(f, "vault write: {e}"),
            Self::Keychain(e) => write!(f, "vault keychain: {e}"),
            Self::BadMagic => write!(f, "vault file does not have the expected magic bytes"),
            Self::UnsupportedVersion(v) => {
                write!(
                    f,
                    "vault file format version {v} is not supported by this reader"
                )
            }
            Self::TruncatedFile => write!(f, "vault file is truncated below the minimum size"),
            Self::AeadDecrypt => write!(
                f,
                "vault decryption failed (wrong key, tampered ciphertext, \
                 tampered header, or mismatched version)"
            ),
            Self::Serde(e) => write!(f, "vault plaintext could not be parsed: {e}"),
            Self::UnknownAlphabet(name) => write!(
                f,
                "vault entry references unknown alphabet '{name}'; \
                 this vault was written by a version that knows alphabets this reader does not"
            ),
        }
    }
}

impl std::error::Error for VaultError {}

impl From<std::io::Error> for VaultError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<AtomicWriteError> for VaultError {
    fn from(e: AtomicWriteError) -> Self {
        Self::AtomicWrite(e)
    }
}

impl From<KeychainError> for VaultError {
    fn from(e: KeychainError) -> Self {
        Self::Keychain(e)
    }
}

impl From<serde_json::Error> for VaultError {
    fn from(e: serde_json::Error) -> Self {
        Self::Serde(e)
    }
}

// ---------- list-time metadata projection ----------
//
// `EntryMetadata` + `EntryKindSummary` are the display-safe
// projections of a `VaultEntry` exposed to the CLI's `list`
// subcommand. They have NO `value` field (by type, not by
// discipline), so a caller cannot accidentally print plaintext when
// rendering list output. The FF1 `tweak` bytes are dropped at the
// projection step too: they are random per-entry noise of no display
// value (the user never needs to see them; FF1's correctness does
// not depend on the tweak being remembered by the user), and
// omitting them keeps `list` output narrow and copy-pasteable.

/// One entry as the `list` subcommand sees it. Has no field that
/// holds the registered plaintext.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryMetadata {
    pub label: String,
    pub kind: EntryKindSummary,
}

/// Display-safe summary of [`VaultEntryKind`]. The `Fpe` variant
/// keeps the alphabet name and prefix so `list` can show how an
/// entry fakes (e.g. "FPE base62 prefix=''"), but drops the random
/// 16-byte tweak. The `SessionMapped` variant keeps only the kind
/// discriminator (Card / Pii / Formatless).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryKindSummary {
    Fpe { alphabet: String, prefix: String },
    SessionMapped { kind: SessionFakeKind },
}

impl EntryKindSummary {
    fn from_entry_kind(k: &VaultEntryKind) -> Self {
        match k {
            VaultEntryKind::Fpe {
                alphabet, prefix, ..
            } => Self::Fpe {
                alphabet: alphabet.clone(),
                prefix: prefix.clone(),
            },
            VaultEntryKind::SessionMapped { kind } => Self::SessionMapped { kind: *kind },
        }
    }
}

// ---------- the Vault type ----------

/// In-memory vault: the entries plus the secret material needed to
/// re-encrypt on save.
///
/// `Vault::open` is the one entry point: it acquires the vault key
/// via `keychain::fetch_or_create` (generating one on first run),
/// reads the file if it exists (decrypting + deserializing), and
/// returns a `Vault` ready for `register`/`forget`/`save`.
pub struct Vault {
    /// Vault key (the HKDF ikm). Held as `SecretBox` so it never
    /// debug-prints and wipes on drop.
    vault_key: SecretBox<[u8; KEY_LEN]>,
    /// In-memory entries. Mutated by `register`/`forget`; persisted
    /// by `save`.
    contents: VaultContents,
}

impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Manual Debug so the key bytes never accidentally print and
        // so the entries' values are summarized rather than dumped.
        f.debug_struct("Vault")
            .field("vault_key", &"<redacted>")
            .field("entry_count", &self.contents.entries.len())
            .field("schema_version", &self.contents.schema_version)
            .finish()
    }
}

impl Vault {
    /// Open or initialize the vault at `path`.
    ///
    /// On first run (file does not exist): fetch-or-create a vault key
    /// via `keychain::fetch_or_create` and return an empty vault.
    /// The empty vault is NOT persisted to disk yet; the next `save`
    /// writes the first file.
    ///
    /// On subsequent runs: fetch the vault key from the keychain,
    /// read the file, verify the magic + version, AEAD-decrypt with
    /// the derived key + AAD, deserialize, return the populated
    /// vault.
    ///
    /// Before reading, the orphan-scan path cleans up any sibling
    /// `<basename>.tmp.*` files left behind by a previous crashed
    /// write.
    pub fn open<B>(io: &dyn VaultIo, path: &Path, keychain: &B) -> Result<Self, VaultError>
    where
        B: KeychainBackend + ?Sized,
    {
        // Clean up any orphaned tmp files from a previous crashed
        // write. Quiet failures: the vault open itself does not
        // depend on this succeeding.
        if let Ok(orphans) = io.list_orphan_tmps(path) {
            for orphan in orphans {
                io.remove_quiet(&orphan);
            }
        }

        // Fetch-or-create the vault key. The closure is invoked at
        // most once, only when the keychain slot is empty.
        let vault_key = keychain::fetch_or_create(keychain, &KeychainSlot::VaultKey, || {
            let mut bytes = [0u8; KEY_LEN];
            os_random(&mut bytes);
            SecretBox::new(Box::new(bytes))
        })?;

        // Read the file (if present).
        let file_bytes = io.read_if_exists(path)?;

        let contents = match file_bytes {
            None => VaultContents::default(),
            Some(bytes) => decrypt_vault(&vault_key, &bytes)?,
        };

        Ok(Self {
            vault_key,
            contents,
        })
    }

    /// Add an entry. Replaces any existing entry with the same label
    /// (consistent with the future `register` CLI command's
    /// "register --update" semantics; M4a will harden the behaviour).
    pub fn register(&mut self, entry: VaultEntry) {
        self.contents.entries.retain(|e| e.label != entry.label);
        self.contents.entries.push(entry);
    }

    /// Remove the entry with `label`. Returns true if an entry was
    /// removed, false if no entry matched.
    pub fn forget(&mut self, label: &str) -> bool {
        let before = self.contents.entries.len();
        self.contents.entries.retain(|e| e.label != label);
        before != self.contents.entries.len()
    }

    /// Iterate over the entries' labels (metadata-only). The CLI's
    /// `list` command formats this output. Values are deliberately
    /// not exposed here so a caller cannot accidentally print
    /// plaintext.
    pub fn labels(&self) -> impl Iterator<Item = &str> {
        self.contents.entries.iter().map(|e| e.label.as_str())
    }

    /// Display-safe metadata for every entry, suitable for `list`
    /// output. Returns owned [`EntryMetadata`] values (no `value`
    /// field, no FF1 tweak bytes) so a caller printing the result
    /// has no path to plaintext.
    pub fn list_metadata(&self) -> Vec<EntryMetadata> {
        self.contents
            .entries
            .iter()
            .map(|e| EntryMetadata {
                label: e.label.clone(),
                kind: EntryKindSummary::from_entry_kind(&e.entry_kind),
            })
            .collect()
    }

    /// Number of entries in the vault.
    pub fn len(&self) -> usize {
        self.contents.entries.len()
    }

    /// True iff the vault has no entries.
    pub fn is_empty(&self) -> bool {
        self.contents.entries.is_empty()
    }

    /// Serialize, AEAD-encrypt, atomically write to `path`. The
    /// existing vault file (if any) is replaced atomically; on any
    /// failure before the rename step the existing file is
    /// untouched.
    pub fn save(&self, io: &dyn VaultIo, path: &Path) -> Result<(), VaultError> {
        let plaintext = Zeroizing::new(serde_json::to_vec(&self.contents)?);
        let file_bytes = encrypt_vault(&self.vault_key, &plaintext)?;
        io.write_atomic(path, &file_bytes, VAULT_FILE_MODE)?;
        Ok(())
    }

    /// Build an [`crate::Engine`] from this vault's entries.
    ///
    /// Each [`VaultEntry`] is converted to a
    /// [`RegisteredValue`] (either `Fpe` or `SessionMapped`), wrapped
    /// in `Zeroizing` at the boundary so the engine's own
    /// secret-bytes lifecycle takes over from here on.
    pub fn build_engine(&self) -> Result<crate::Engine, VaultError> {
        let registered = self.registered_values()?;
        let provider = VaultKeyProvider::from(&self.vault_key);
        // The MAC key for idempotence is HKDF-derived from the vault
        // key under a separate info label. Compute it once here so
        // the engine receives stable bytes.
        let mac_key = derive_mac_key(&self.vault_key);
        crate::Engine::new(&provider, registered, Vec::new(), mac_key.to_vec())
            .map_err(|_| VaultError::Io(std::io::Error::other("engine build failed")))
    }

    /// Convert this vault's entries into engine-shaped
    /// `RegisteredValue` instances. Exposed so the M1 CLI can wire
    /// them up directly when building an engine if it needs to
    /// inject additional registrations (e.g. from a `--session`
    /// file).
    pub fn registered_values(&self) -> Result<Vec<RegisteredValue>, VaultError> {
        self.contents
            .entries
            .iter()
            .map(entry_to_registered)
            .collect()
    }

    /// Load and AEAD-decrypt a `--session` file at `path` under this
    /// vault's key. Returns `Ok(None)` if the file does not exist (a
    /// signal, not an error - the CLI decides whether "not present"
    /// is fatal per the operation). See
    /// `crate::session_file::load_session_file` for the format and
    /// error surface.
    ///
    /// The vault key stays inside this `Vault` - only a copy of its
    /// bytes is passed to the session helper, wrapped in `Zeroizing`
    /// so it wipes when the copy leaves scope.
    pub fn load_session_file(
        &self,
        io: &dyn VaultIo,
        path: &Path,
        now_epoch: u64,
    ) -> Result<Option<crate::session_file::SessionContents>, crate::session_file::SessionFileError>
    {
        let key = Zeroizing::new(self.vault_key.expose_secret().to_vec());
        crate::session_file::load_session_file(io, path, &key, now_epoch)
    }

    /// Serialize `contents`, AEAD-encrypt under a subkey derived
    /// from this vault's key, and atomically write to `path` with
    /// mode `SESSION_FILE_MODE`.
    pub fn save_session_file(
        &self,
        io: &dyn VaultIo,
        path: &Path,
        contents: &crate::session_file::SessionContents,
    ) -> Result<(), crate::session_file::SessionFileError> {
        let key = Zeroizing::new(self.vault_key.expose_secret().to_vec());
        crate::session_file::save_session_file(io, path, &key, contents)
    }
}

// ---------- helpers: AEAD encrypt / decrypt ----------

fn derive_aead_key(vault_key: &SecretBox<[u8; KEY_LEN]>) -> Zeroizing<[u8; AEAD_KEY_LEN]> {
    let hk = Hkdf::<Sha256>::new(None, vault_key.expose_secret());
    let mut out = [0u8; AEAD_KEY_LEN];
    hk.expand(HKDF_INFO_AEAD, &mut out)
        .expect("HKDF-SHA-256 expand to AEAD_KEY_LEN bytes always succeeds");
    Zeroizing::new(out)
}

/// Derive the MAC key the engine's idempotence layer uses. Different
/// HKDF info string from the AEAD key, so the two derived keys are
/// independent given the same vault key.
fn derive_mac_key(vault_key: &SecretBox<[u8; KEY_LEN]>) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(None, vault_key.expose_secret());
    let mut out = [0u8; 32];
    hk.expand(b"invisibool-mac-key-v1", &mut out)
        .expect("HKDF-SHA-256 expand to 32 bytes always succeeds");
    Zeroizing::new(out)
}

fn encrypt_vault(
    vault_key: &SecretBox<[u8; KEY_LEN]>,
    plaintext: &[u8],
) -> Result<Vec<u8>, VaultError> {
    let aead_key = derive_aead_key(vault_key);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(aead_key.as_ref()));

    let mut nonce_bytes = [0u8; NONCE_LEN];
    os_random(&mut nonce_bytes);

    // Build the AAD inline; it equals the first 20 bytes of the file
    // we are about to produce.
    let mut aad = [0u8; AAD_LEN];
    aad[..16].copy_from_slice(MAGIC);
    aad[16] = VERSION;
    aad[17..20].copy_from_slice(&RESERVED);

    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce_bytes),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| {
            VaultError::Io(std::io::Error::other(
                "AEAD encrypt failed (should not happen for valid inputs)",
            ))
        })?;

    // Assemble the on-disk bytes: aad || nonce || ciphertext+tag.
    let mut file_bytes = Vec::with_capacity(AAD_LEN + NONCE_LEN + ciphertext.len());
    file_bytes.extend_from_slice(&aad);
    file_bytes.extend_from_slice(&nonce_bytes);
    file_bytes.extend_from_slice(&ciphertext);
    Ok(file_bytes)
}

fn decrypt_vault(
    vault_key: &SecretBox<[u8; KEY_LEN]>,
    file_bytes: &[u8],
) -> Result<VaultContents, VaultError> {
    // Minimum file size: AAD + nonce + tag (an empty plaintext yields
    // just the tag).
    if file_bytes.len() < AAD_LEN + NONCE_LEN + TAG_LEN {
        return Err(VaultError::TruncatedFile);
    }
    if file_bytes[..16] != MAGIC[..] {
        return Err(VaultError::BadMagic);
    }
    if file_bytes[16] != VERSION {
        return Err(VaultError::UnsupportedVersion(file_bytes[16]));
    }
    // Reserved bytes are authenticated by AAD; mismatched bytes
    // surface as AEAD failure, not a separate error.

    let aad = &file_bytes[..AAD_LEN];
    let nonce: &[u8; NONCE_LEN] =
        <&[u8; NONCE_LEN]>::try_from(&file_bytes[AAD_LEN..AAD_LEN + NONCE_LEN])
            .expect("slice length checked above");
    let ciphertext = &file_bytes[AAD_LEN + NONCE_LEN..];

    let aead_key = derive_aead_key(vault_key);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(aead_key.as_ref()));

    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| VaultError::AeadDecrypt)?;

    let plaintext = Zeroizing::new(plaintext);
    let contents: VaultContents = serde_json::from_slice(&plaintext)?;
    Ok(contents)
}

// ---------- helpers: convert vault entry to engine registered value ----------

fn entry_to_registered(entry: &VaultEntry) -> Result<RegisteredValue, VaultError> {
    match &entry.entry_kind {
        VaultEntryKind::Fpe {
            tweak,
            prefix,
            alphabet,
        } => {
            let alphabet = resolve_alphabet(alphabet)
                .ok_or_else(|| VaultError::UnknownAlphabet(alphabet.clone()))?;
            let mut tweak_bytes = [0u8; TWEAK_LEN];
            tweak_bytes.copy_from_slice(tweak);
            Ok(RegisteredValue::Fpe(FpeRegistration {
                label: entry.label.clone(),
                value: Zeroizing::new(entry.value.clone()),
                tweak: tweak_bytes,
                alphabet,
                prefix: prefix.clone(),
            }))
        }
        VaultEntryKind::SessionMapped { kind } => {
            Ok(RegisteredValue::SessionMapped(SessionRegistration {
                label: entry.label.clone(),
                value: Zeroizing::new(entry.value.clone()),
                kind: *kind,
            }))
        }
    }
}

// ---------- KeyProvider bridge ----------

/// Bridges the vault's `SecretBox<[u8; 32]>` to the engine's
/// `KeyProvider` trait. Holds a `Zeroizing<Vec<u8>>` copy of the
/// vault key bytes that wipes on drop, separate from the
/// `SecretBox<[u8; 32]>` inside the Vault itself.
struct VaultKeyProvider {
    key: Zeroizing<Vec<u8>>,
}

impl VaultKeyProvider {
    fn from(secret: &SecretBox<[u8; KEY_LEN]>) -> Self {
        Self {
            key: Zeroizing::new(secret.expose_secret().to_vec()),
        }
    }
}

impl KeyProvider for VaultKeyProvider {
    fn vault_key(&self) -> &[u8] {
        &self.key
    }
}

/// Convenience for callers that have a vault path and want to also
/// know what the orphan-scan saw. Used by the M1 CLI to surface the
/// "we cleaned up a crashed write" diagnostic.
pub fn list_orphan_tmps(io: &dyn VaultIo, vault_path: &Path) -> std::io::Result<Vec<PathBuf>> {
    io.list_orphan_tmps(vault_path)
}

// ---------- tests ----------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keychain::InMemoryKeychain;
    use crate::tokenizer::fpe::{PiiKind, SessionFakeKind};
    use std::fs;

    // ----- helpers -----

    /// Per-test temp directory inside the workspace's target/ so cargo
    /// cleans it on `cargo clean`. We do not use `std::env::temp_dir`
    /// because that lands outside the cargo target tree.
    fn fresh_tmp_dir(test_name: &str) -> PathBuf {
        let mut dir = std::env::current_dir().expect("cwd");
        // Walk up to repo root (where Cargo.lock lives).
        while !dir.join("Cargo.lock").exists() {
            if !dir.pop() {
                break;
            }
        }
        let dir = dir
            .join("target")
            .join("vault-test")
            .join(format!("{test_name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create test dir");
        dir
    }

    fn sample_ff1_entry() -> VaultEntry {
        VaultEntry {
            label: "ff1".to_string(),
            value: "sk-test-EXAMPLEa1b2c3d4e5f6g7".to_string(),
            entry_kind: VaultEntryKind::Fpe {
                tweak: [0xAB; 16],
                prefix: "sk-test-".to_string(),
                alphabet: "BASE62".to_string(),
            },
        }
    }

    fn sample_pii_entry() -> VaultEntry {
        VaultEntry {
            label: "pii".to_string(),
            value: "alice@example.com".to_string(),
            entry_kind: VaultEntryKind::SessionMapped {
                kind: SessionFakeKind::Pii(PiiKind::Email),
            },
        }
    }

    fn sample_card_entry() -> VaultEntry {
        VaultEntry {
            label: "card".to_string(),
            value: "4111 1111 1111 1111".to_string(),
            entry_kind: VaultEntryKind::SessionMapped {
                kind: SessionFakeKind::Card,
            },
        }
    }

    fn sample_formatless_entry() -> VaultEntry {
        VaultEntry {
            label: "pin".to_string(),
            value: "this-is-a-long-formatless-passphrase".to_string(),
            entry_kind: VaultEntryKind::SessionMapped {
                kind: SessionFakeKind::Formatless,
            },
        }
    }

    // ----- 1. Empty vault open + first save + reopen. -----

    #[test]
    fn empty_vault_round_trips_through_open_save_reopen() {
        let dir = fresh_tmp_dir("empty_round_trip");
        let path = dir.join("vault.bin");
        let io = StdVaultIo;
        let keychain = InMemoryKeychain::new();

        let v = Vault::open(&io, &path, &keychain).unwrap();
        assert_eq!(v.len(), 0);
        v.save(&io, &path).unwrap();

        let v2 = Vault::open(&io, &path, &keychain).unwrap();
        assert_eq!(v2.len(), 0);
    }

    // ----- 2. Single FF1 entry round-trips. -----

    #[test]
    fn single_ff1_entry_round_trips() {
        let dir = fresh_tmp_dir("single_ff1");
        let path = dir.join("vault.bin");
        let io = StdVaultIo;
        let keychain = InMemoryKeychain::new();

        let mut v = Vault::open(&io, &path, &keychain).unwrap();
        v.register(sample_ff1_entry());
        v.save(&io, &path).unwrap();

        let v2 = Vault::open(&io, &path, &keychain).unwrap();
        assert_eq!(v2.len(), 1);
        let labels: Vec<&str> = v2.labels().collect();
        assert_eq!(labels, vec!["ff1"]);
    }

    // ----- 3. Each SessionFakeKind variant round-trips. -----

    #[test]
    fn every_session_fake_kind_variant_round_trips() {
        let dir = fresh_tmp_dir("every_kind");
        let path = dir.join("vault.bin");
        let io = StdVaultIo;
        let keychain = InMemoryKeychain::new();

        let mut v = Vault::open(&io, &path, &keychain).unwrap();
        v.register(sample_ff1_entry());
        v.register(sample_pii_entry());
        v.register(sample_card_entry());
        v.register(sample_formatless_entry());
        v.save(&io, &path).unwrap();

        let v2 = Vault::open(&io, &path, &keychain).unwrap();
        assert_eq!(v2.len(), 4);
    }

    // ----- 4. Vault with many entries round-trips. -----

    #[test]
    fn vault_with_many_entries_round_trips() {
        let dir = fresh_tmp_dir("many_entries");
        let path = dir.join("vault.bin");
        let io = StdVaultIo;
        let keychain = InMemoryKeychain::new();

        let mut v = Vault::open(&io, &path, &keychain).unwrap();
        for i in 0..100 {
            v.register(VaultEntry {
                label: format!("entry-{i:03}"),
                value: format!("value-{i:03}-EXAMPLEbody"),
                entry_kind: VaultEntryKind::SessionMapped {
                    kind: SessionFakeKind::Formatless,
                },
            });
        }
        v.save(&io, &path).unwrap();

        let v2 = Vault::open(&io, &path, &keychain).unwrap();
        assert_eq!(v2.len(), 100);
    }

    // ----- 5. schema_version is read back as 1. -----

    #[test]
    fn vault_schema_version_is_one() {
        let dir = fresh_tmp_dir("schema_version");
        let path = dir.join("vault.bin");
        let io = StdVaultIo;
        let keychain = InMemoryKeychain::new();

        let v = Vault::open(&io, &path, &keychain).unwrap();
        assert_eq!(v.contents.schema_version, format::CURRENT_SCHEMA_VERSION);
        assert_eq!(format::CURRENT_SCHEMA_VERSION, 1);
    }

    // ----- 6. Wrong key cannot decrypt vault. -----

    #[test]
    fn vault_encrypted_with_one_key_cannot_be_decrypted_with_another() {
        let dir = fresh_tmp_dir("wrong_key");
        let path = dir.join("vault.bin");
        let io = StdVaultIo;

        let keychain_a = InMemoryKeychain::new();
        let mut v = Vault::open(&io, &path, &keychain_a).unwrap();
        v.register(sample_ff1_entry());
        v.save(&io, &path).unwrap();

        // Fresh keychain has a different key.
        let keychain_b = InMemoryKeychain::new();
        let err = Vault::open(&io, &path, &keychain_b);
        match err {
            Err(VaultError::AeadDecrypt) => {}
            other => panic!("expected AeadDecrypt error, got {other:?}"),
        }
    }

    // ----- 7. Tampered magic causes BadMagic. -----

    #[test]
    fn vault_with_tampered_magic_is_rejected() {
        let dir = fresh_tmp_dir("bad_magic");
        let path = dir.join("vault.bin");
        let io = StdVaultIo;
        let keychain = InMemoryKeychain::new();

        let v = Vault::open(&io, &path, &keychain).unwrap();
        v.save(&io, &path).unwrap();

        let mut bytes = fs::read(&path).unwrap();
        bytes[0] = b'X'; // tamper with magic
        fs::write(&path, &bytes).unwrap();

        let err = Vault::open(&io, &path, &keychain);
        match err {
            Err(VaultError::BadMagic) => {}
            other => panic!("expected BadMagic, got {other:?}"),
        }
    }

    // ----- 8. Tampered version byte triggers UnsupportedVersion. -----

    #[test]
    fn vault_with_tampered_version_byte_is_rejected() {
        let dir = fresh_tmp_dir("bad_version");
        let path = dir.join("vault.bin");
        let io = StdVaultIo;
        let keychain = InMemoryKeychain::new();

        let v = Vault::open(&io, &path, &keychain).unwrap();
        v.save(&io, &path).unwrap();

        let mut bytes = fs::read(&path).unwrap();
        bytes[16] = 99; // tamper with version
        fs::write(&path, &bytes).unwrap();

        let err = Vault::open(&io, &path, &keychain);
        match err {
            Err(VaultError::UnsupportedVersion(99)) => {}
            other => panic!("expected UnsupportedVersion(99), got {other:?}"),
        }
    }

    // ----- 9. Tampered ciphertext fails AEAD. -----

    #[test]
    fn vault_with_tampered_ciphertext_byte_fails_aead() {
        let dir = fresh_tmp_dir("tampered_ct");
        let path = dir.join("vault.bin");
        let io = StdVaultIo;
        let keychain = InMemoryKeychain::new();

        let mut v = Vault::open(&io, &path, &keychain).unwrap();
        v.register(sample_ff1_entry());
        v.save(&io, &path).unwrap();

        let mut bytes = fs::read(&path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01; // flip one bit of the Poly1305 tag
        fs::write(&path, &bytes).unwrap();

        let err = Vault::open(&io, &path, &keychain);
        match err {
            Err(VaultError::AeadDecrypt) => {}
            other => panic!("expected AeadDecrypt, got {other:?}"),
        }
    }

    // ----- 10. Tampered nonce fails AEAD. -----

    #[test]
    fn vault_with_tampered_nonce_fails_aead() {
        let dir = fresh_tmp_dir("tampered_nonce");
        let path = dir.join("vault.bin");
        let io = StdVaultIo;
        let keychain = InMemoryKeychain::new();

        let mut v = Vault::open(&io, &path, &keychain).unwrap();
        v.register(sample_ff1_entry());
        v.save(&io, &path).unwrap();

        let mut bytes = fs::read(&path).unwrap();
        bytes[AAD_LEN] ^= 0x01; // flip a bit in the nonce
        fs::write(&path, &bytes).unwrap();

        let err = Vault::open(&io, &path, &keychain);
        match err {
            Err(VaultError::AeadDecrypt) => {}
            other => panic!("expected AeadDecrypt, got {other:?}"),
        }
    }

    // ----- 11. File magic at offset 0..16 is exactly INVISIBOOL_VAULT. -----

    #[test]
    fn written_vault_has_exact_magic_bytes() {
        let dir = fresh_tmp_dir("magic_bytes");
        let path = dir.join("vault.bin");
        let io = StdVaultIo;
        let keychain = InMemoryKeychain::new();

        let v = Vault::open(&io, &path, &keychain).unwrap();
        v.save(&io, &path).unwrap();

        let bytes = fs::read(&path).unwrap();
        assert_eq!(&bytes[..16], b"INVISIBOOL_VAULT");
    }

    // ----- 12. Version byte at offset 16 is 1. -----

    #[test]
    fn written_vault_has_version_byte_one() {
        let dir = fresh_tmp_dir("version_byte");
        let path = dir.join("vault.bin");
        let io = StdVaultIo;
        let keychain = InMemoryKeychain::new();

        let v = Vault::open(&io, &path, &keychain).unwrap();
        v.save(&io, &path).unwrap();

        let bytes = fs::read(&path).unwrap();
        assert_eq!(bytes[16], 1);
    }

    // ----- 13. Two writes produce different nonces (random). -----

    #[test]
    fn two_writes_produce_different_nonces() {
        let dir = fresh_tmp_dir("nonce_freshness");
        let path = dir.join("vault.bin");
        let io = StdVaultIo;
        let keychain = InMemoryKeychain::new();

        let v = Vault::open(&io, &path, &keychain).unwrap();
        v.save(&io, &path).unwrap();
        let bytes_1 = fs::read(&path).unwrap();
        v.save(&io, &path).unwrap();
        let bytes_2 = fs::read(&path).unwrap();

        let nonce_1 = &bytes_1[AAD_LEN..AAD_LEN + NONCE_LEN];
        let nonce_2 = &bytes_2[AAD_LEN..AAD_LEN + NONCE_LEN];
        assert_ne!(
            nonce_1, nonce_2,
            "two consecutive writes must produce different nonces; \
             a deterministic nonce would be catastrophic with XChaCha20-Poly1305"
        );
    }

    // ----- 14. Ciphertext does not contain the plaintext bytes. -----

    #[test]
    fn ciphertext_does_not_contain_plaintext_in_the_clear() {
        let dir = fresh_tmp_dir("encrypted_check");
        let path = dir.join("vault.bin");
        let io = StdVaultIo;
        let keychain = InMemoryKeychain::new();

        let unique_marker = "DISTINCTIVE_VALUE_FOR_CT_CHECK_X9Z2";
        let mut v = Vault::open(&io, &path, &keychain).unwrap();
        v.register(VaultEntry {
            label: "ct-check".to_string(),
            value: unique_marker.to_string(),
            entry_kind: VaultEntryKind::SessionMapped {
                kind: SessionFakeKind::Formatless,
            },
        });
        v.save(&io, &path).unwrap();

        let bytes = fs::read(&path).unwrap();
        assert!(
            !bytes
                .windows(unique_marker.len())
                .any(|w| w == unique_marker.as_bytes()),
            "vault file should not contain the plaintext marker in clear bytes"
        );
    }

    // ----- 15. Atomic write: no .tmp.* leftover after success. -----

    #[test]
    fn successful_write_leaves_no_tmp_sibling() {
        let dir = fresh_tmp_dir("no_tmp_leftover");
        let path = dir.join("vault.bin");
        let io = StdVaultIo;
        let keychain = InMemoryKeychain::new();

        let v = Vault::open(&io, &path, &keychain).unwrap();
        v.save(&io, &path).unwrap();

        let orphans = io.list_orphan_tmps(&path).unwrap();
        assert!(orphans.is_empty(), "after successful write: {orphans:?}");
    }

    // ----- 16. Atomic write: failed rename leaves OLD vault intact (sha256). -----

    #[test]
    fn failed_rename_leaves_old_vault_bytes_intact() {
        use sha2::Digest;
        let dir = fresh_tmp_dir("rename_fault");
        let path = dir.join("vault.bin");
        let real_io = StdVaultIo;
        let keychain = InMemoryKeychain::new();

        // Write a real vault first.
        let mut v = Vault::open(&real_io, &path, &keychain).unwrap();
        v.register(sample_ff1_entry());
        v.save(&real_io, &path).unwrap();
        let pre_bytes = fs::read(&path).unwrap();
        let pre_hash = sha2::Sha256::digest(&pre_bytes);

        // Now attempt another save, but inject a rename failure.
        let injectable = InjectableVaultIo::new();
        injectable.fail_next_write_at(AtomicWriteFailAt::AtRename);

        let mut v2 = Vault::open(&real_io, &path, &keychain).unwrap();
        v2.register(VaultEntry {
            label: "would-have-been-saved".to_string(),
            value: "but-rename-failed".to_string(),
            entry_kind: VaultEntryKind::SessionMapped {
                kind: SessionFakeKind::Formatless,
            },
        });
        let result = v2.save(&injectable, &path);

        // The save must error at the rename step.
        match result {
            Err(VaultError::AtomicWrite(AtomicWriteError::AtRename(_))) => {}
            other => panic!("expected AtomicWrite(AtRename(_)), got {other:?}"),
        }

        // The OLD vault file is byte-identical to before the failed write.
        let post_bytes = fs::read(&path).unwrap();
        let post_hash = sha2::Sha256::digest(&post_bytes);
        assert_eq!(
            pre_hash, post_hash,
            "rename failure must leave the old vault byte-identical"
        );
    }

    // ----- 17. Atomic write: failed rename leaves tmp file for orphan scan. -----

    #[test]
    fn failed_rename_leaves_tmp_file_for_orphan_scan() {
        let dir = fresh_tmp_dir("orphan_after_failed_rename");
        let path = dir.join("vault.bin");
        let real_io = StdVaultIo;
        let keychain = InMemoryKeychain::new();

        let v = Vault::open(&real_io, &path, &keychain).unwrap();
        v.save(&real_io, &path).unwrap();

        let injectable = InjectableVaultIo::new();
        injectable.fail_next_write_at(AtomicWriteFailAt::AtRename);

        let _ = v.save(&injectable, &path);

        let orphans = real_io.list_orphan_tmps(&path).unwrap();
        assert!(
            !orphans.is_empty(),
            "expected at least one .tmp.* sibling after failed rename; got {orphans:?}"
        );

        // The next vault open cleans them up.
        let _ = Vault::open(&real_io, &path, &keychain).unwrap();
        let orphans_after_open = real_io.list_orphan_tmps(&path).unwrap();
        assert!(
            orphans_after_open.is_empty(),
            "orphan scan should have removed the tmp file at open; remaining: {orphans_after_open:?}"
        );
    }

    // ----- 18. AtBodyWrite failure surfaces as the typed variant. -----

    #[test]
    fn body_write_failure_returns_typed_variant() {
        let dir = fresh_tmp_dir("body_write_fault");
        let path = dir.join("vault.bin");
        let real_io = StdVaultIo;
        let keychain = InMemoryKeychain::new();

        let v = Vault::open(&real_io, &path, &keychain).unwrap();

        let injectable = InjectableVaultIo::new();
        injectable.fail_next_write_at(AtomicWriteFailAt::AtBodyWrite);
        match v.save(&injectable, &path) {
            Err(VaultError::AtomicWrite(AtomicWriteError::AtBodyWrite(_))) => {}
            other => panic!("expected AtomicWrite(AtBodyWrite(_)), got {other:?}"),
        }
    }

    // ----- 19. Unix file mode after write is 0600. -----

    #[cfg(unix)]
    #[test]
    fn written_vault_has_owner_only_permissions_on_unix() {
        use std::os::unix::fs::PermissionsExt;
        let dir = fresh_tmp_dir("perms");
        let path = dir.join("vault.bin");
        let io = StdVaultIo;
        let keychain = InMemoryKeychain::new();

        let v = Vault::open(&io, &path, &keychain).unwrap();
        v.save(&io, &path).unwrap();

        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "vault file mode should be 0o600 (owner read/write only); got {mode:o}"
        );
    }

    // ----- 20. fetch_or_create generates on first open, reuses on second. -----

    #[test]
    fn first_open_generates_key_second_open_reuses_it() {
        use crate::keychain::{KeychainBackend, KeychainSlot};

        let dir = fresh_tmp_dir("fetch_or_create_path");
        let path = dir.join("vault.bin");
        let io = StdVaultIo;
        let keychain = InMemoryKeychain::new();

        // First open: keychain is empty so a fresh key is generated.
        let v1 = Vault::open(&io, &path, &keychain).unwrap();
        v1.save(&io, &path).unwrap();
        let key_after_first = keychain.fetch(&KeychainSlot::VaultKey).unwrap().unwrap();

        // Second open: keychain has the key, no new generation.
        let _v2 = Vault::open(&io, &path, &keychain).unwrap();
        let key_after_second = keychain.fetch(&KeychainSlot::VaultKey).unwrap().unwrap();

        assert_eq!(
            key_after_first.expose_secret(),
            key_after_second.expose_secret(),
            "second open must reuse the existing key"
        );
    }

    // ----- 21. Vault open propagates keychain Err without overwriting. -----

    #[test]
    fn vault_open_propagates_keychain_fetch_error() {
        use crate::keychain::{KeychainError, KeychainSlot};

        struct AlwaysErrors;
        impl KeychainBackend for AlwaysErrors {
            fn fetch(
                &self,
                _slot: &KeychainSlot,
            ) -> Result<Option<SecretBox<[u8; KEY_LEN]>>, KeychainError> {
                Err(KeychainError::Backend("simulated lock".to_string()))
            }
            fn store(
                &self,
                _slot: &KeychainSlot,
                _key: SecretBox<[u8; KEY_LEN]>,
            ) -> Result<(), KeychainError> {
                Ok(())
            }
            fn delete(&self, _slot: &KeychainSlot) -> Result<(), KeychainError> {
                Ok(())
            }
        }

        let dir = fresh_tmp_dir("keychain_fetch_err");
        let path = dir.join("vault.bin");
        let io = StdVaultIo;
        let kc = AlwaysErrors;

        match Vault::open(&io, &path, &kc) {
            Err(VaultError::Keychain(KeychainError::Backend(msg))) => {
                assert!(msg.contains("simulated lock"));
            }
            other => panic!("expected Keychain(Backend(_)), got {other:?}"),
        }
    }

    // ----- 22. build_engine produces an engine that scrubs registered values. -----

    #[test]
    fn build_engine_produces_engine_that_scrubs_registered_values() {
        let dir = fresh_tmp_dir("build_engine");
        let path = dir.join("vault.bin");
        let io = StdVaultIo;
        let keychain = InMemoryKeychain::new();

        let mut v = Vault::open(&io, &path, &keychain).unwrap();
        v.register(sample_ff1_entry());
        v.save(&io, &path).unwrap();

        let v2 = Vault::open(&io, &path, &keychain).unwrap();
        let engine = v2.build_engine().unwrap();

        let input = "the token is sk-test-EXAMPLEa1b2c3d4e5f6g7 please scrub";
        let scrubbed = engine.scrub(input);
        assert_eq!(scrubbed.scrubbed_count, 1);
        assert!(!scrubbed.output.contains("EXAMPLEa1b2c3d4e5f6g7"));

        // Restore round-trip via FF1 too.
        let restored = engine.restore(&scrubbed.output);
        assert_eq!(restored.output, input);
    }
}
