//! Vault file format and the serializable in-memory representation.
//!
//! ## On-disk layout
//!
//! ```text
//! 0..16   magic    = b"INVISIBOOL_VAULT"   (no NUL padding, 16 bytes exact)
//! 16      version  = 0x01                  (u8)
//! 17..20  reserved = [0x00, 0x00, 0x00]    (alignment + future flag bits)
//! 20..44  nonce    = 24 random bytes       (XChaCha20-Poly1305 192-bit nonce)
//! 44..N   ciphertext_and_tag                (variable length; Poly1305 tag
//!                                            is the last 16 bytes, appended
//!                                            by the AEAD)
//! ```
//!
//! The first 20 bytes are passed to the AEAD as **AAD** (Additional
//! Authenticated Data). Any tampering with the magic, version, or
//! reserved bytes makes decryption fail at the Poly1305 tag check.
//! Version-in-AAD specifically defends against downgrade attacks: a
//! v2 reader cannot accept a v1-encrypted file even if the same vault
//! key was used, because the AAD it authenticates against (containing
//! version=2) does not match the file's bytes (containing version=1).
//!
//! ## Plaintext schema
//!
//! The plaintext (the bytes that get encrypted) is the
//! `serde_json`-encoded form of [`VaultContents`]. The schema_version
//! field is separate from the file-format version above: file-format
//! version describes the cryptographic wrapper, schema_version
//! describes the plaintext layout. They evolve independently.

use serde::{Deserialize, Serialize};

use crate::tokenizer::alphabet::Alphabet;
use crate::tokenizer::fpe::SessionFakeKind;

// ---------- file-format constants ----------

/// Magic bytes identifying an Invisibool vault file. 16 ASCII bytes.
/// In AAD; tampering causes a decryption failure.
pub(super) const MAGIC: &[u8; 16] = b"INVISIBOOL_VAULT";

/// File-format version. Bumped on a cryptographic-wrapper change
/// (different AEAD, different AAD layout, different file structure).
/// In AAD; tampering with this byte (downgrade attack) causes a
/// decryption failure.
pub(super) const VERSION: u8 = 1;

/// Reserved bytes for future format flags or alignment. In AAD;
/// tampering causes a decryption failure.
pub(super) const RESERVED: [u8; 3] = [0, 0, 0];

/// Length of the AAD passed to the AEAD: magic + version + reserved.
pub(super) const AAD_LEN: usize = 20;

/// XChaCha20-Poly1305 nonce length (192 bits = 24 bytes).
pub(super) const NONCE_LEN: usize = 24;

/// Poly1305 tag length, appended to the ciphertext by the AEAD.
pub(super) const TAG_LEN: usize = 16;

/// AEAD-key length: 32 bytes (256 bits) for both XChaCha20-Poly1305
/// and the keychain's stored vault key.
pub(super) const AEAD_KEY_LEN: usize = 32;

/// HKDF `info` string for deriving the vault's AEAD key from the
/// vault key in the keychain. Bumping the `-v1` suffix would let a
/// future M4a rotate the derivation independently of the vault key.
pub(super) const HKDF_INFO_AEAD: &[u8] = b"invisibool-vault-aead-v1";

// ---------- the plaintext schema ----------

/// Plaintext form of the vault. After [`super::Vault::open`] decrypts
/// the file, this is the structure it deserializes from the JSON
/// bytes. Each entry maps one-to-one to one of the engine's
/// [`crate::tokenizer::fpe::RegisteredValue`] variants when the engine
/// is built.
#[derive(Debug, Serialize, Deserialize)]
pub struct VaultContents {
    /// Plaintext-schema version. Independent from the file-format
    /// version (which describes the AEAD wrapper). Bumped only when
    /// the entry shape changes incompatibly.
    pub schema_version: u32,
    /// Registered entries. Order is insignificant - the engine treats
    /// the set unordered.
    pub entries: Vec<VaultEntry>,
}

impl Default for VaultContents {
    fn default() -> Self {
        Self {
            schema_version: CURRENT_SCHEMA_VERSION,
            entries: Vec::new(),
        }
    }
}

/// The current `schema_version` value written for new vaults at M1.
pub(super) const CURRENT_SCHEMA_VERSION: u32 = 1;

/// One registered value, as it lives on disk.
///
/// `value` is a plain `String` (not `Zeroizing<String>`) because
/// `serde_json` parses into plain strings internally; wrapping at this
/// boundary would not actually reduce the in-memory plaintext window
/// during deserialization. The accepted residual is documented in the
/// threat model. Once an entry is consumed by [`VaultEntry::into_registered`],
/// its `value` moves into a `Zeroizing<String>` inside the engine's
/// own `FpeRegistration` / `SessionRegistration` types, so the
/// long-lived in-engine copy IS wiped on eviction.
#[derive(Debug, Serialize, Deserialize)]
pub struct VaultEntry {
    /// Short human-readable label, e.g. "staging-api-token". Not
    /// secret; safe to print in `list` output.
    pub label: String,
    /// The registered plaintext.
    pub value: String,
    /// Whether this entry takes the FF1 path (stateless, restorable
    /// across processes) or the session-mapped path (PII / Card /
    /// Formatless, restorable only in-process or via `--session`).
    pub entry_kind: VaultEntryKind,
}

/// Differentiates an FF1 entry (with the FF1 metadata: tweak, prefix,
/// alphabet) from a session-mapped entry (with just the kind).
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum VaultEntryKind {
    /// FF1-eligible registered value. Restored statelessly via FF1
    /// trial-decrypt; needs its 16-byte tweak, the literal prefix
    /// FF1 preserves, and the alphabet name.
    Fpe {
        tweak: [u8; 16],
        prefix: String,
        /// Canonical alphabet name resolved back to [`Alphabet`] at
        /// load time. Stored as a string (not via `serde` on the
        /// `Alphabet` type) so the vault format stays decoupled from
        /// the engine's `Alphabet` representation.
        alphabet: String,
    },
    /// Session-mapped value (PII, Card, Formatless). Restored only
    /// in-process (via the `watch` daemon's session map) or under an
    /// explicit `--session` file in two-command terminal mode.
    SessionMapped { kind: SessionFakeKind },
}

/// Resolve an alphabet name (as serialized in a `VaultEntry::Fpe`
/// entry) to the engine's [`Alphabet`] constant. Returns `None` for
/// unknown names so the vault loader can surface a typed error.
pub(super) fn resolve_alphabet(name: &str) -> Option<Alphabet> {
    match name {
        "BASE62" => Some(Alphabet::BASE62),
        "BASE32" => Some(Alphabet::BASE32),
        "HEX_LOWER" => Some(Alphabet::HEX_LOWER),
        "HEX_UPPER" => Some(Alphabet::HEX_UPPER),
        "DIGITS" => Some(Alphabet::DIGITS),
        "ALPHA_LOWER" => Some(Alphabet::ALPHA_LOWER),
        "ALPHA_UPPER" => Some(Alphabet::ALPHA_UPPER),
        "BASE36_LOWER" => Some(Alphabet::BASE36_LOWER),
        _ => None,
    }
}

/// The names `resolve_alphabet` accepts. Test-only mirror so the test
/// module can iterate them without depending on the function's
/// internal match.
#[cfg(test)]
pub(super) const KNOWN_ALPHABET_NAMES: &[&str] = &[
    "BASE62",
    "BASE32",
    "HEX_LOWER",
    "HEX_UPPER",
    "DIGITS",
    "ALPHA_LOWER",
    "ALPHA_UPPER",
    "BASE36_LOWER",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_format_constants_are_pinned() {
        // Pin the on-disk layout so a future edit can't silently
        // change the file format and break every existing user's
        // vault. Any deliberate change to these constants must also
        // bump VERSION and add a migration path - both of which are
        // visible at this test.
        assert_eq!(MAGIC, b"INVISIBOOL_VAULT");
        assert_eq!(MAGIC.len(), 16);
        assert_eq!(VERSION, 1);
        assert_eq!(RESERVED, [0u8; 3]);
        assert_eq!(AAD_LEN, 20);
        assert_eq!(NONCE_LEN, 24);
        assert_eq!(TAG_LEN, 16);
        assert_eq!(AEAD_KEY_LEN, 32);
    }

    #[test]
    fn hkdf_info_string_pins_the_aead_subkey_derivation_label() {
        // Changing this string (e.g. v1 -> v2) MUST coincide with a
        // documented vault-key rotation procedure (M4a's `rotate-key`).
        // Pinning the literal here makes any silent edit visible.
        assert_eq!(HKDF_INFO_AEAD, b"invisibool-vault-aead-v1");
    }

    #[test]
    fn resolve_alphabet_handles_every_named_constant() {
        for name in KNOWN_ALPHABET_NAMES {
            let alphabet = resolve_alphabet(name)
                .unwrap_or_else(|| panic!("alphabet name {name} should resolve"));
            // Spot-check radix > 1 so we know we got a real alphabet.
            assert!(alphabet.radix() >= 2, "{name} should have radix >= 2");
        }
    }

    #[test]
    fn resolve_alphabet_returns_none_for_unknown_name() {
        assert!(resolve_alphabet("THIS_IS_NOT_AN_ALPHABET").is_none());
        assert!(resolve_alphabet("").is_none());
        assert!(
            resolve_alphabet("base62").is_none(),
            "lowercase should not match"
        );
    }

    #[test]
    fn vault_contents_serializes_and_round_trips_through_serde_json() {
        let contents = VaultContents {
            schema_version: CURRENT_SCHEMA_VERSION,
            entries: vec![
                VaultEntry {
                    label: "ff1-entry".to_string(),
                    value: "sk-test-EXAMPLEa1b2c3d4e5f6g7".to_string(),
                    entry_kind: VaultEntryKind::Fpe {
                        tweak: [0xABu8; 16],
                        prefix: "sk-test-".to_string(),
                        alphabet: "BASE62".to_string(),
                    },
                },
                VaultEntry {
                    label: "email-entry".to_string(),
                    value: "alice@example.com".to_string(),
                    entry_kind: VaultEntryKind::SessionMapped {
                        kind: SessionFakeKind::Pii(crate::tokenizer::fpe::PiiKind::Email),
                    },
                },
            ],
        };
        let bytes = serde_json::to_vec(&contents).unwrap();
        let restored: VaultContents = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(restored.schema_version, contents.schema_version);
        assert_eq!(restored.entries.len(), 2);
        assert_eq!(restored.entries[0].label, "ff1-entry");
        match &restored.entries[0].entry_kind {
            VaultEntryKind::Fpe {
                tweak,
                prefix,
                alphabet,
            } => {
                assert_eq!(*tweak, [0xABu8; 16]);
                assert_eq!(prefix, "sk-test-");
                assert_eq!(alphabet, "BASE62");
            }
            other => panic!("expected Fpe entry, got {other:?}"),
        }
    }
}
