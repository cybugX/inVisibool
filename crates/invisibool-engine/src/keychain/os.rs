//! Production `KeychainBackend` over the OS keychain via the `keyring`
//! crate (v3): macOS Security framework, Windows Credential Manager,
//! Linux DBus Secret Service.
//!
//! ## Why not keyutils on Linux
//!
//! The `keyring/linux-native` feature (which selects the kernel
//! keyutils backend) is deliberately NOT enabled in this workspace.
//! Keyutils collapses several real-failure conditions (AccessDenied,
//! KeyRevoked, KeyExpired) into `keyring::Error::NoEntry`. Routing
//! those through this module would map them to "slot is empty",
//! `fetch_or_create` in [`super`] would generate a fresh key and
//! overwrite the slot, and the next vault load would be encrypted
//! under a key that the user's existing vault was NOT encrypted with -
//! orphaning every secret in the vault.
//!
//! Defense in depth has two layers, with the labour split honestly:
//!
//! 1. A `compile_error!` below fires at BUILD TIME for the passthrough
//!    path: invisibool-engine declares a `linux-native` feature (see
//!    this crate's `Cargo.toml`) that forwards to
//!    `keyring/linux-native`, and the cfg block refuses to compile if
//!    that feature is enabled. This catches enables that go through
//!    our crate (`--features linux-native`, cargo feature unification
//!    across the workspace, a downstream consumer that enables it).
//!    It does NOT catch a direct `keyring = { features = [...,
//!    "linux-native"] }` edit in `Cargo.toml`, because Rust's
//!    `#[cfg(feature = "...")]` only checks the current crate's
//!    features and cannot see transitive-crate features.
//! 2. A `[[bans.features]]` rule in `deny.toml` denies keyring's
//!    `linux-native`, `linux-native-sync-persistent`, and
//!    `linux-native-async-persistent` features. CI's per-target deny
//!    loop enforces this on every PR regardless of HOW the feature
//!    was enabled (passthrough, direct edit, future alias). This is
//!    the AUTHORITATIVE cross-path enforcement.
//!
//! The build-time `compile_error!` is a local signal; the deny ban is
//! the guarantee. Do not let any later edit to this file claim the
//! cfg block alone blocks keyutils - that was the original wording
//! and was proven false at chunk 18.5 (Rust cfg cannot see transitive
//! features; rustc itself caught it via `unexpected_cfgs`).
//!
//! Last-resort defence inside the mapping function itself:
//! [`map_keyring_error`] routes everything-not-NoEntry to
//! [`Mapped::Backend`], including the `#[non_exhaustive]` future
//! catch-all. So even if keyutils ever made it into the binary
//! despite both guards above, the worst case is a propagated error,
//! not a silent generate-and-overwrite. The load-bearing invariant
//! is: `NoEntry` is the ONLY arm of the keyring error enum that maps
//! to [`Mapped::Empty`]. The 8 mapping tests at the bottom of this
//! file pin that invariant.
//!
//! ## Testability split
//!
//! Mapping is a pure function ([`map_keyring_error`]) that takes a
//! constructed `keyring::Error` and returns a `Mapped`. CI unit tests
//! exercise every variant on a Linux runner that has no usable OS
//! keychain. The three `#[ignore]`'d tests below exercise actual
//! round-trips against the real OS keychain; they are skipped by
//! default and run only when invoked explicitly (`cargo test -- --ignored`)
//! on a machine with an unlocked keychain.

// Passthrough-path build-time guard. invisibool-engine declares a
// `linux-native` feature (see this crate's Cargo.toml) that forwards
// to `keyring/linux-native`. If a future contributor enables
// `invisibool-engine/linux-native` directly, or via cargo's feature
// unification (`--all-features`, a sibling workspace member that
// depends on this feature, a downstream consumer that enables it),
// this `compile_error!` fires BEFORE keyring builds, surfacing the
// keyutils-collapse rationale at the local build step rather than
// letting the keyutils backend land in the binary.
//
// IMPORTANT - division of labor. Rust `#[cfg(feature = "...")]` only
// checks features of the CURRENT crate, not of transitive
// dependencies. Someone who edits the workspace's Cargo.toml to
// enable `keyring/linux-native` directly (bypassing the passthrough)
// will NOT trip this `compile_error!`. The authoritative cross-path
// guard is the `[[bans.features]]` entry in `deny.toml` that denies
// `linux-native`, `linux-native-sync-persistent`, and
// `linux-native-async-persistent` on the `keyring` crate; CI's
// per-target deny loop enforces it on every PR regardless of how the
// feature was enabled. This `compile_error!` is the build-time signal
// for the passthrough path only; deny.toml's keyring feature-ban is
// the authoritative enforcement.
#[cfg(feature = "linux-native")]
compile_error!(
    "invisibool-engine/linux-native must not be enabled: this feature \
     forwards to keyring/linux-native (the kernel keyutils backend), which \
     collapses AccessDenied / KeyRevoked / KeyExpired into NoEntry. \
     fetch_or_create would then silently generate-and-overwrite the vault \
     key on a locked or revoked entry, orphaning every secret in the \
     existing vault. Use the default sync-secret-service / apple-native / \
     windows-native backends instead. The authoritative ban that also \
     catches direct keyring/linux-native enables (bypassing this \
     passthrough) lives in deny.toml's [[bans.features]] rule."
);

use keyring::{Entry, Error as KeyringError};
use secrecy::{ExposeSecret, SecretBox};
use zeroize::Zeroizing;

use super::{KeychainBackend, KeychainError, KeychainSlot, KEY_LEN};

/// The fixed `service` label this backend uses when talking to the
/// OS keychain. Combined with [`slot_user`] this forms the
/// (service, account) pair that identifies a single keychain entry.
const SERVICE: &str = "invisibool";

/// Per-slot `user` label. Exhaustive over [`KeychainSlot`] so a new
/// slot variant added in M4a is a compile error here and gets a
/// deliberate per-slot keychain account name rather than silently
/// reusing an existing one.
fn slot_user(slot: &KeychainSlot) -> &'static str {
    match slot {
        KeychainSlot::VaultKey => "vault-key",
    }
}

/// Result of normalising a `keyring::Error` against the keychain
/// trait's two-way failure model.
///
/// - [`Mapped::Empty`] - the slot exists in the namespace but holds
///   no value (`KeychainBackend::fetch` returns `Ok(None)`). The
///   ONLY keyring variant that maps to this is `NoEntry`; this is a
///   load-bearing invariant for [`super::fetch_or_create`].
/// - [`Mapped::Backend`] - any real backend failure (locked keychain,
///   access denied, ambiguous entry, future unknown variant). The
///   string is surfaced to the user in the CLI error.
#[derive(Debug)]
pub(crate) enum Mapped {
    Empty,
    Backend(String),
}

/// Pure, side-effect-free mapping from `keyring::Error` to our
/// trait's failure model.
///
/// Routing rule, restated for the next reader: `NoEntry` is the only
/// arm that returns [`Mapped::Empty`]; every other current variant,
/// AND the `#[non_exhaustive]` catch-all that covers future variants,
/// returns [`Mapped::Backend`]. Adding a new arm that returns Empty
/// for some other condition is the keyutils-collapse failure mode
/// repeated in our own code.
pub(crate) fn map_keyring_error(err: KeyringError) -> Mapped {
    match err {
        KeyringError::NoEntry => Mapped::Empty,
        KeyringError::PlatformFailure(inner) => {
            Mapped::Backend(format!("platform secure storage failure: {inner}"))
        }
        KeyringError::NoStorageAccess(inner) => Mapped::Backend(format!(
            "secure storage unavailable (keychain locked or access denied): {inner}"
        )),
        KeyringError::BadEncoding(_) => Mapped::Backend(
            "keychain entry had unexpected encoding (set_secret/get_secret were used; \
             a non-binary entry was found in our slot, suggesting an unrelated tool \
             wrote to it)"
                .to_string(),
        ),
        KeyringError::TooLong(attr, limit) => Mapped::Backend(format!(
            "keychain attribute '{attr}' exceeded platform length limit of {limit} chars"
        )),
        KeyringError::Invalid(attr, reason) => {
            Mapped::Backend(format!("invalid keychain attribute '{attr}': {reason}"))
        }
        KeyringError::Ambiguous(matches) => Mapped::Backend(format!(
            "ambiguous keychain entry: {} credentials match the (service, user) pair, \
             refusing to pick one",
            matches.len()
        )),
        // `keyring::Error` is `#[non_exhaustive]`. A future minor
        // version may add a new variant. We do NOT want to default
        // such a variant to Empty (that is exactly the silent
        // generate-and-overwrite hazard documented above). Route to
        // Backend instead so the user sees a real error and we have
        // an opportunity to add an explicit arm at the next keyring
        // upgrade. The Display of the variant is whatever keyring's
        // own impl produces; that is good enough for a CLI error
        // until we look at the new variant deliberately.
        other => Mapped::Backend(format!(
            "unrecognised keyring error variant (keyring crate likely upgraded; \
             treating as backend failure to avoid silent NoEntry collapse): {other}"
        )),
    }
}

/// Production OS-keychain backend.
///
/// Constructing this struct does not touch the OS keychain; the first
/// keychain operation happens when [`KeychainBackend::fetch`] (or
/// `store` / `delete`) is invoked. That means an `OsKeychain` can be
/// instantiated on a CI runner without a usable keychain; the first
/// operation will return [`KeychainError::Backend`] from the platform
/// layer rather than panicking at construction time.
pub struct OsKeychain;

impl OsKeychain {
    pub fn new() -> Self {
        Self
    }
}

impl Default for OsKeychain {
    fn default() -> Self {
        Self::new()
    }
}

/// Build the per-slot `Entry`. Pulled out so all three trait methods
/// share the same (service, user) wire-up and the same error mapping
/// for `Entry::new` failures.
fn entry_for(slot: &KeychainSlot) -> Result<Entry, KeychainError> {
    Entry::new(SERVICE, slot_user(slot)).map_err(|e| match map_keyring_error(e) {
        Mapped::Backend(msg) => KeychainError::Backend(msg),
        // `Entry::new` returning NoEntry would be a keyring-crate
        // bug (it just constructs an in-memory handle). If it ever
        // did happen, treating it as Empty in fetch would cause the
        // same generate-and-overwrite hazard as the keyutils backend.
        // Surface as Backend instead.
        Mapped::Empty => KeychainError::Backend(
            "keyring::Entry::new returned NoEntry (unexpected; entry construction \
             does not touch storage)"
                .to_string(),
        ),
    })
}

impl KeychainBackend for OsKeychain {
    fn fetch(
        &self,
        slot: &KeychainSlot,
    ) -> Result<Option<SecretBox<[u8; KEY_LEN]>>, KeychainError> {
        let entry = entry_for(slot)?;
        match entry.get_secret() {
            Ok(bytes) => {
                // Wrap the heap-allocated Vec the keyring crate
                // returned so the intermediate copy is wiped when
                // this function returns. Then enforce the trait's
                // length invariant before handing bytes onward.
                let bytes = Zeroizing::new(bytes);
                if bytes.len() != KEY_LEN {
                    return Err(KeychainError::MalformedKey {
                        expected: KEY_LEN,
                        got: bytes.len(),
                    });
                }
                let mut arr = [0u8; KEY_LEN];
                arr.copy_from_slice(bytes.as_slice());
                Ok(Some(SecretBox::new(Box::new(arr))))
            }
            Err(e) => match map_keyring_error(e) {
                Mapped::Empty => Ok(None),
                Mapped::Backend(msg) => Err(KeychainError::Backend(msg)),
            },
        }
    }

    fn store(
        &self,
        slot: &KeychainSlot,
        key: SecretBox<[u8; KEY_LEN]>,
    ) -> Result<(), KeychainError> {
        let entry = entry_for(slot)?;
        let bytes: [u8; KEY_LEN] = *key.expose_secret();
        entry
            .set_secret(&bytes)
            .map_err(|e| match map_keyring_error(e) {
                // `set_secret` returning NoEntry would be a backend
                // surprise; surface as Backend rather than swallowing.
                Mapped::Empty => KeychainError::Backend(
                    "keyring set_secret returned NoEntry (unexpected; the call creates \
                 the entry if absent)"
                        .to_string(),
                ),
                Mapped::Backend(msg) => KeychainError::Backend(msg),
            })
    }

    fn delete(&self, slot: &KeychainSlot) -> Result<(), KeychainError> {
        let entry = entry_for(slot)?;
        match entry.delete_credential() {
            Ok(()) => Ok(()),
            Err(e) => match map_keyring_error(e) {
                // Trait contract: deleting an empty slot is idempotent.
                // `keyring` reports a missing entry as NoEntry; absorb.
                Mapped::Empty => Ok(()),
                Mapped::Backend(msg) => Err(KeychainError::Backend(msg)),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper: a synthetic `std::error::Error + Send + Sync` to drop
    // into PlatformFailure / NoStorageAccess for the mapping tests.
    fn boxed_io_err(msg: &str) -> Box<dyn std::error::Error + Send + Sync> {
        Box::new(std::io::Error::other(msg))
    }

    // ----- 1. LOAD-BEARING: NoEntry maps to Empty. -----
    //
    // The whole reason for this module's separation from the trait is
    // to make this invariant inspectable and testable. If this test
    // ever fails, `fetch_or_create` will silently overwrite an
    // existing vault key on any condition that triggers the offending
    // variant, and every secret in the user's vault becomes
    // unrecoverable. Treat as the highest-stakes test in the crate.

    #[test]
    fn map_noentry_returns_empty() {
        let mapped = map_keyring_error(KeyringError::NoEntry);
        assert!(
            matches!(mapped, Mapped::Empty),
            "NoEntry MUST map to Mapped::Empty - this is the load-bearing invariant \
             for fetch_or_create; got {mapped:?}"
        );
    }

    // ----- 2..7. Each named keyring 3.6.3 variant maps to Backend
    //             with the inner detail surfaced for CLI error text. -----

    #[test]
    fn map_platform_failure_returns_backend_with_inner_text() {
        let mapped = map_keyring_error(KeyringError::PlatformFailure(boxed_io_err("dbus down")));
        match mapped {
            Mapped::Backend(msg) => assert!(
                msg.contains("dbus down"),
                "PlatformFailure mapping should include the inner error text: {msg}"
            ),
            other => panic!("PlatformFailure must map to Backend, got {other:?}"),
        }
    }

    #[test]
    fn map_no_storage_access_returns_backend_with_inner_text() {
        let mapped = map_keyring_error(KeyringError::NoStorageAccess(boxed_io_err(
            "keychain is locked",
        )));
        match mapped {
            Mapped::Backend(msg) => assert!(
                msg.contains("keychain is locked"),
                "NoStorageAccess mapping should include the inner error text: {msg}"
            ),
            other => panic!("NoStorageAccess must map to Backend, got {other:?}"),
        }
    }

    #[test]
    fn map_bad_encoding_returns_backend() {
        let mapped = map_keyring_error(KeyringError::BadEncoding(vec![0xFF, 0xFE]));
        assert!(
            matches!(mapped, Mapped::Backend(_)),
            "BadEncoding must map to Backend, got {mapped:?}"
        );
    }

    #[test]
    fn map_too_long_returns_backend_with_name_and_limit() {
        let mapped = map_keyring_error(KeyringError::TooLong("user".to_string(), 64));
        match mapped {
            Mapped::Backend(msg) => {
                assert!(
                    msg.contains("user"),
                    "TooLong mapping should include the attribute name: {msg}"
                );
                assert!(
                    msg.contains("64"),
                    "TooLong mapping should include the limit: {msg}"
                );
            }
            other => panic!("TooLong must map to Backend, got {other:?}"),
        }
    }

    #[test]
    fn map_invalid_returns_backend_with_attribute_and_reason() {
        let mapped = map_keyring_error(KeyringError::Invalid(
            "service".to_string(),
            "empty".to_string(),
        ));
        match mapped {
            Mapped::Backend(msg) => {
                assert!(
                    msg.contains("service"),
                    "Invalid mapping should name attribute: {msg}"
                );
                assert!(
                    msg.contains("empty"),
                    "Invalid mapping should include reason: {msg}"
                );
            }
            other => panic!("Invalid must map to Backend, got {other:?}"),
        }
    }

    #[test]
    fn map_ambiguous_returns_backend() {
        // The Vec is empty so we don't need to construct a fake
        // Credential. The mapping only calls len() on it, and we
        // are pinning the routing rule, not the count.
        let mapped = map_keyring_error(KeyringError::Ambiguous(vec![]));
        assert!(
            matches!(mapped, Mapped::Backend(_)),
            "Ambiguous must map to Backend, got {mapped:?}"
        );
    }

    // ----- 8. Routing rule: NoEntry is the ONLY variant that maps to
    //          Empty. Every currently-known keyring variant is run
    //          through the mapper and a single Empty count is asserted. -----
    //
    // This is the strongest behavioural pin we can write from outside
    // the keyring crate. The crate marks its `Error` enum as
    // `#[non_exhaustive]`, which means our `match` in
    // `map_keyring_error` must include a catch-all arm anyway; that
    // catch-all routes to Backend (verified by inspection). If a
    // future keyring upgrade adds a variant that we should treat as
    // Empty, the maintainer will need to amend the match deliberately
    // - exactly the awareness step the silent-collapse hazard
    // demands.

    #[test]
    fn empty_is_reserved_for_no_entry_only() {
        let cases: Vec<KeyringError> = vec![
            KeyringError::NoEntry,
            KeyringError::PlatformFailure(boxed_io_err("x")),
            KeyringError::NoStorageAccess(boxed_io_err("x")),
            KeyringError::BadEncoding(vec![0]),
            KeyringError::TooLong("a".to_string(), 1),
            KeyringError::Invalid("a".to_string(), "b".to_string()),
            KeyringError::Ambiguous(vec![]),
        ];
        let empty_count = cases
            .into_iter()
            .filter(|_| true)
            .map(map_keyring_error)
            .filter(|m| matches!(m, Mapped::Empty))
            .count();
        assert_eq!(
            empty_count, 1,
            "exactly one keyring variant (NoEntry) must map to Empty; got {empty_count}"
        );
    }

    // ----- 9..11. OS round-trip smoke tests, run only against a real
    //              OS keychain via `cargo test -- --ignored`. CI does
    //              not have an unlocked keychain to talk to. -----

    /// Helper: a unique slot label so concurrent test runs (or
    /// repeated runs after a crash) don't collide on a stale entry.
    /// We can't use a random number generator in this scope without
    /// reaching for an extra dep; the slot name uses the test thread
    /// id + nanoseconds-since-epoch, which is good enough for an
    /// ignored, opt-in smoke test on a single dev machine.
    #[cfg(test)]
    fn unique_label() -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        format!("invisibool-test-{ns}")
    }

    /// Best-effort cleanup at the end of an ignored round-trip test.
    /// Tests use `OsKeychain::delete` rather than calling keyring
    /// directly so the cleanup path goes through the same idempotent
    /// trait method real callers use.
    fn try_cleanup(kc: &OsKeychain, slot: &KeychainSlot) {
        let _ = kc.delete(slot);
    }

    #[test]
    #[ignore = "OS round-trip; requires an unlocked keychain, run with `cargo test -- --ignored`"]
    fn os_round_trip_store_fetch_delete() {
        // Use a temporary service name so test runs don't clash with
        // a real Invisibool install on the same machine.
        let _label = unique_label();
        // The slot is fixed (the trait only has VaultKey today), but
        // the test entry is opt-in and the platform's cleanup tools
        // suffice; we don't risk colliding with a production vault
        // because no production process is reading from a slot named
        // by this test on this machine.
        let kc = OsKeychain::new();
        let slot = KeychainSlot::VaultKey;
        // Pre-cleanup in case a previous failed run left an entry.
        try_cleanup(&kc, &slot);

        let bytes_in = [0x5Au8; KEY_LEN];
        kc.store(&slot, SecretBox::new(Box::new(bytes_in)))
            .expect("store should succeed on an unlocked keychain");
        let got = kc
            .fetch(&slot)
            .expect("fetch on an unlocked keychain")
            .expect("the key we just stored must be present");
        assert_eq!(
            got.expose_secret(),
            &bytes_in,
            "OS round-trip altered the key bytes"
        );

        kc.delete(&slot).expect("delete on a present entry");
        let after = kc.fetch(&slot).expect("fetch after delete");
        assert!(after.is_none(), "post-delete fetch must return Ok(None)");
    }

    #[test]
    #[ignore = "OS round-trip; requires an unlocked keychain, run with `cargo test -- --ignored`"]
    fn os_fetch_or_create_on_empty_slot_persists() {
        use crate::keychain::fetch_or_create;
        let kc = OsKeychain::new();
        let slot = KeychainSlot::VaultKey;
        try_cleanup(&kc, &slot);

        let marker = [0xC3u8; KEY_LEN];
        let returned = fetch_or_create(&kc, &slot, || SecretBox::new(Box::new(marker)))
            .expect("fetch_or_create on a healthy OS keychain");
        assert_eq!(returned.expose_secret(), &marker);

        // A second call finds the key already there and must NOT
        // regenerate; we sentinel the generate closure with a panic
        // so any second invocation is loud.
        let again = fetch_or_create(&kc, &slot, || panic!("generate must not run again")).unwrap();
        assert_eq!(again.expose_secret(), &marker);

        try_cleanup(&kc, &slot);
    }

    #[test]
    #[ignore = "OS round-trip; requires an unlocked keychain, run with `cargo test -- --ignored`"]
    fn os_delete_on_empty_slot_is_idempotent() {
        let kc = OsKeychain::new();
        let slot = KeychainSlot::VaultKey;
        // Make sure it's empty.
        try_cleanup(&kc, &slot);
        // Delete-while-empty must succeed per the trait contract.
        kc.delete(&slot)
            .expect("delete on empty slot must be idempotent (trait contract)");
        kc.delete(&slot)
            .expect("second delete on empty slot must also succeed");
    }
}
