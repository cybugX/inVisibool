//! At-rest key storage behind a swappable backend.
//!
//! The trait + the `InMemoryKeychain` test backend in this module are
//! the M1 footprint. Real macOS Keychain / Windows Credential Manager /
//! Linux Secret Service backends live behind the same trait and are
//! exercised by nightly OS-native smoke tests, NOT by the M1 CLI build,
//! because CI runners have no unlocked keychain to talk to.
//!
//! ## The fetch / store / create contract
//!
//! `fetch` returns `Ok(Some(key))` when the slot has a key, `Ok(None)`
//! when the slot is empty, and `Err` only on a real backend failure
//! (locked keychain, IPC error, secret-service bus down). The trait
//! never collapses "doesn't exist yet" into `Err`, so a caller cannot
//! accidentally interpret a real failure as "I should create a fresh
//! key here" and overwrite something that does exist.
//!
//! `store` overwrites unconditionally. Callers that mean "create if
//! absent" must use [`fetch_or_create`], not raw fetch-then-store
//! (which is racy and hides intent).
//!
//! `fetch_or_create` is the safe default. It runs the `generate`
//! closure at most once, only when the slot is empty, and it persists
//! the generated key into the backend BEFORE returning it to the
//! caller. That ordering is the crash-safety contract: if a process
//! crashes immediately after receiving its vault key, the next process
//! must be able to fetch the same key from the keychain. Without
//! generate-then-store-then-return, a crash between return and the
//! first vault write would leave a vault encrypted under a key that
//! exists nowhere persistently, and every secret in that vault would
//! be unrecoverable.
//!
//! ## Slot naming
//!
//! [`KeychainSlot`] is an enum, not a string. Adding a new slot is a
//! deliberate change to this crate (the home of the project's
//! key-handling code), guarded by exhaustive-match coverage so a
//! caller cannot smuggle in a typo'd slot name from elsewhere.

use secrecy::SecretBox;

pub mod in_memory;

pub use in_memory::InMemoryKeychain;

/// Length of every key stored through this trait. 32 bytes (256 bits)
/// fits both AEAD candidates the vault module may pick from at chunk
/// 18 (AES-256-GCM and ChaCha20-Poly1305) and matches the HKDF-SHA-256
/// output length the FF1 subkey derivation already uses.
pub const KEY_LEN: usize = 32;

/// The named slot a key occupies in the keychain.
///
/// M1 uses only [`KeychainSlot::VaultKey`]. New variants land here when
/// M4a's `rotate-key` and related management surfaces arrive; modifying
/// the enum forces a deliberate review of the key's role rather than
/// letting a typo'd string create a parallel orphan entry.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum KeychainSlot {
    /// The single long-term key the vault file is AEAD-encrypted under.
    /// Generated at first run by [`fetch_or_create`] when this slot is
    /// empty; fetched on every subsequent run.
    VaultKey,
}

/// Reasons a keychain operation can fail. Distinguished from "slot is
/// empty" (which `fetch` returns as `Ok(None)`, never `Err`).
#[derive(Debug)]
pub enum KeychainError {
    /// The OS-level keychain operation failed. The string is the
    /// backend's own error message; surface it to the user in a CLI
    /// error rather than swallowing it.
    Backend(String),
    /// A `fetch` read bytes of the wrong length from the backend.
    /// Defensive: should not happen on a keychain we ourselves wrote
    /// to, but the trait validates so a corrupted entry surfaces as a
    /// typed error rather than producing an FF1 subkey from the wrong
    /// number of bytes.
    MalformedKey { expected: usize, got: usize },
}

impl std::fmt::Display for KeychainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Backend(msg) => write!(f, "keychain backend error: {msg}"),
            Self::MalformedKey { expected, got } => write!(
                f,
                "keychain returned a key of the wrong length: expected {expected} bytes, got {got}"
            ),
        }
    }
}

impl std::error::Error for KeychainError {}

/// Backend for at-rest key storage. The trait is `Send + Sync` so the
/// M1 watch daemon (which runs an event loop on one thread and an IPC
/// server on another) can share a single backend instance across both.
pub trait KeychainBackend: Send + Sync {
    /// Fetch the key in `slot`. `Ok(Some)` on hit, `Ok(None)` on empty
    /// slot, `Err` only on a real backend failure.
    fn fetch(&self, slot: &KeychainSlot)
        -> Result<Option<SecretBox<[u8; KEY_LEN]>>, KeychainError>;

    /// Store `key` into `slot`, overwriting any existing value. Callers
    /// that want "create if absent" semantics must use
    /// [`fetch_or_create`] instead.
    fn store(
        &self,
        slot: &KeychainSlot,
        key: SecretBox<[u8; KEY_LEN]>,
    ) -> Result<(), KeychainError>;

    /// Delete the slot. Idempotent: deleting an empty slot returns
    /// `Ok(())`. `Err` only on a real backend failure.
    fn delete(&self, slot: &KeychainSlot) -> Result<(), KeychainError>;
}

/// Fetch the key in `slot`. If the slot is empty, invoke `generate` to
/// produce a fresh key, store it through `backend`, and return it.
///
/// **Crash-safety contract:** the store happens BEFORE the function
/// returns the generated key to the caller. If a process crashes
/// immediately after this call returns, the next process will find the
/// same key in the keychain. The order is fetch -> (if empty) generate
/// -> store -> return; a future refactor that backgrounds the store
/// would violate this contract and is guarded against by the
/// `fetch_or_create_stores_generated_key_before_returning` test below.
///
/// `generate` runs at most once per call, and only when `fetch`
/// returned `Ok(None)`. If `fetch` returns `Err` (real backend
/// failure), `generate` is NOT invoked, the error is propagated as-is,
/// and the slot is left untouched. The keychain is the source of truth
/// for whether a key exists; a real backend failure is never silently
/// papered over by creating a new key.
///
/// Best-effort atomicity: between `fetch` returning `None` and `store`
/// succeeding, another process could insert a key into the same slot.
/// On a single-user OS keychain with one Invisibool process running at
/// a time (the M1 posture), this race window is empty in practice. The
/// real backends may use OS-level locking for stronger guarantees; the
/// trait does not require it. M4a's `rotate-key` revisits this.
pub fn fetch_or_create<B, F>(
    backend: &B,
    slot: &KeychainSlot,
    generate: F,
) -> Result<SecretBox<[u8; KEY_LEN]>, KeychainError>
where
    B: KeychainBackend + ?Sized,
    F: FnOnce() -> SecretBox<[u8; KEY_LEN]>,
{
    if let Some(existing) = backend.fetch(slot)? {
        return Ok(existing);
    }
    // Slot is empty. Generate, store, then return. Order matters: see
    // the crash-safety contract in the doc-comment above.
    let new_key = generate();
    let bytes_for_store: [u8; KEY_LEN] = {
        use secrecy::ExposeSecret;
        *new_key.expose_secret()
    };
    backend.store(slot, SecretBox::new(Box::new(bytes_for_store)))?;
    Ok(new_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;
    use std::sync::Mutex;

    // ----- helper: a recording proxy backend used by the crash-safety
    // ordering test (test 15) and the error-path tests (13 / 14). -----

    #[derive(Debug, Clone)]
    enum BackendCall {
        Fetch(KeychainSlot),
        Store(KeychainSlot, [u8; KEY_LEN]),
        Delete(KeychainSlot),
    }

    /// Wraps another backend and records every call. The recorded
    /// `Store` event carries a plaintext copy of the bytes the trait
    /// was asked to store; this is acceptable in test code so the
    /// crash-safety test can verify "the backend was handed exactly
    /// the bytes the caller received", and it never leaves the test
    /// module.
    struct RecordingKeychain<B: KeychainBackend> {
        inner: B,
        calls: Mutex<Vec<BackendCall>>,
    }

    impl<B: KeychainBackend> RecordingKeychain<B> {
        fn new(inner: B) -> Self {
            Self {
                inner,
                calls: Mutex::new(Vec::new()),
            }
        }
        fn calls(&self) -> Vec<BackendCall> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl<B: KeychainBackend> KeychainBackend for RecordingKeychain<B> {
        fn fetch(
            &self,
            slot: &KeychainSlot,
        ) -> Result<Option<SecretBox<[u8; KEY_LEN]>>, KeychainError> {
            self.calls
                .lock()
                .unwrap()
                .push(BackendCall::Fetch(slot.clone()));
            self.inner.fetch(slot)
        }
        fn store(
            &self,
            slot: &KeychainSlot,
            key: SecretBox<[u8; KEY_LEN]>,
        ) -> Result<(), KeychainError> {
            let bytes: [u8; KEY_LEN] = *key.expose_secret();
            self.calls
                .lock()
                .unwrap()
                .push(BackendCall::Store(slot.clone(), bytes));
            self.inner.store(slot, key)
        }
        fn delete(&self, slot: &KeychainSlot) -> Result<(), KeychainError> {
            self.calls
                .lock()
                .unwrap()
                .push(BackendCall::Delete(slot.clone()));
            self.inner.delete(slot)
        }
    }

    /// A backend that errors on every operation. Used by the
    /// error-path contract tests (13 / 14) so we don't have to inject
    /// faults into the InMemoryKeychain.
    struct AlwaysErrors {
        fetch_err: bool,
        store_err: bool,
    }

    impl KeychainBackend for AlwaysErrors {
        fn fetch(
            &self,
            _slot: &KeychainSlot,
        ) -> Result<Option<SecretBox<[u8; KEY_LEN]>>, KeychainError> {
            if self.fetch_err {
                Err(KeychainError::Backend(
                    "simulated fetch failure for test".to_string(),
                ))
            } else {
                Ok(None)
            }
        }
        fn store(
            &self,
            _slot: &KeychainSlot,
            _key: SecretBox<[u8; KEY_LEN]>,
        ) -> Result<(), KeychainError> {
            if self.store_err {
                Err(KeychainError::Backend(
                    "simulated store failure for test".to_string(),
                ))
            } else {
                Ok(())
            }
        }
        fn delete(&self, _slot: &KeychainSlot) -> Result<(), KeychainError> {
            Ok(())
        }
    }

    fn marker_key(byte: u8) -> SecretBox<[u8; KEY_LEN]> {
        SecretBox::new(Box::new([byte; KEY_LEN]))
    }

    // ----- 11. SecretBox Debug is redacted (load-bearing for every
    // future surface that ever debug-formats a key-carrying type). -----

    #[test]
    fn secret_box_debug_redacts_the_key_bytes() {
        let marker = [0xCDu8; KEY_LEN];
        let secret: SecretBox<[u8; KEY_LEN]> = SecretBox::new(Box::new(marker));
        let dbg = format!("{secret:?}");
        // The debug-format must not contain the key bytes in any
        // representation a casual grep would catch.
        let hex_marker = "cd".repeat(KEY_LEN);
        let dec_marker = "205";
        assert!(
            !dbg.contains(&hex_marker),
            "SecretBox Debug leaked hex of the key bytes: {dbg}"
        );
        assert!(
            !dbg.contains(dec_marker),
            "SecretBox Debug leaked decimal byte values: {dbg}"
        );
        // It should also clearly mark the redaction so a reader doesn't
        // mistake it for "no value".
        assert!(
            dbg.to_lowercase().contains("redact")
                || dbg.to_lowercase().contains("secret")
                || dbg.to_lowercase().contains("hidden"),
            "SecretBox Debug should signal redaction; got: {dbg}"
        );
    }

    // ----- 12. KeychainError Display surfaces the backend message. -----

    #[test]
    fn keychain_error_display_surfaces_the_backend_message() {
        let err = KeychainError::Backend("keychain is locked".to_string());
        let msg = format!("{err}");
        assert!(
            msg.contains("keychain is locked"),
            "Backend variant Display did not include the backend message: {msg}"
        );
        let err = KeychainError::MalformedKey {
            expected: 32,
            got: 24,
        };
        let msg = format!("{err}");
        assert!(
            msg.contains("32") && msg.contains("24"),
            "MalformedKey Display did not include both lengths: {msg}"
        );
    }

    // ----- 13. Error on fetch propagates and does NOT invoke generate. -----

    #[test]
    fn fetch_or_create_with_fetch_error_returns_error_without_invoking_generate() {
        let backend = AlwaysErrors {
            fetch_err: true,
            store_err: false,
        };
        let generate_calls = Mutex::new(0usize);
        let result = fetch_or_create(&backend, &KeychainSlot::VaultKey, || {
            *generate_calls.lock().unwrap() += 1;
            marker_key(0xAA)
        });
        assert!(result.is_err(), "expected Err on fetch failure");
        assert!(
            matches!(result, Err(KeychainError::Backend(_))),
            "expected Backend error variant"
        );
        assert_eq!(
            *generate_calls.lock().unwrap(),
            0,
            "generate must NOT be invoked when fetch fails - the keychain is the source of truth"
        );
    }

    // ----- 14. Error on store propagates; generated key is not returned. -----

    #[test]
    fn fetch_or_create_with_store_error_returns_error_and_does_not_return_generated_key() {
        let backend = AlwaysErrors {
            fetch_err: false,
            store_err: true,
        };
        let generate_calls = Mutex::new(0usize);
        let result = fetch_or_create(&backend, &KeychainSlot::VaultKey, || {
            *generate_calls.lock().unwrap() += 1;
            marker_key(0xBB)
        });
        assert!(result.is_err(), "expected Err on store failure");
        assert!(
            matches!(result, Err(KeychainError::Backend(_))),
            "expected Backend error variant"
        );
        assert_eq!(
            *generate_calls.lock().unwrap(),
            1,
            "generate should have run exactly once"
        );
        // The generated key was not returned as Ok. Because SecretBox
        // drops at end of scope, its bytes have been wiped. There is
        // no way for the caller to receive a key that the keychain
        // hasn't accepted.
    }

    // ----- 15. Crash-safety ordering: store happens BEFORE return. -----

    #[test]
    fn fetch_or_create_stores_generated_key_before_returning() {
        // If fetch_or_create ever returns a freshly-generated key to
        // the caller, the keychain MUST have already accepted the
        // store. Otherwise a crash between return and the first vault
        // write would encrypt the vault under a key that exists
        // nowhere on disk, making every secret in the vault
        // unrecoverable on next launch.
        let recorder = RecordingKeychain::new(InMemoryKeychain::new());
        let marker = [0xEFu8; KEY_LEN];

        let returned = fetch_or_create(&recorder, &KeychainSlot::VaultKey, || {
            SecretBox::new(Box::new(marker))
        })
        .expect("fetch_or_create succeeds on healthy backend");

        // The returned key is what generate produced.
        assert_eq!(
            returned.expose_secret(),
            &marker,
            "fetch_or_create returned different bytes than generate produced"
        );

        // By the time fetch_or_create returned, the recorder shows
        // exactly fetch-then-store, and store received the same bytes
        // that were returned. A future refactor that backgrounds the
        // store (e.g. spawns a tokio task to persist) would fail this
        // test because the Store event would not yet be recorded.
        let calls = recorder.calls();
        assert_eq!(
            calls.len(),
            2,
            "expected exactly fetch then store; got {calls:?}"
        );
        match &calls[0] {
            BackendCall::Fetch(slot) => assert_eq!(slot, &KeychainSlot::VaultKey),
            other => panic!("first recorded call must be fetch, got {other:?}"),
        }
        match &calls[1] {
            BackendCall::Store(slot, stored_bytes) => {
                assert_eq!(slot, &KeychainSlot::VaultKey);
                assert_eq!(
                    stored_bytes, &marker,
                    "store received different bytes than what was returned to the caller"
                );
            }
            other => panic!("second recorded call must be store, got {other:?}"),
        }
    }

    // ----- 8/9/10. fetch_or_create generate-invocation contracts. -----

    #[test]
    fn fetch_or_create_invokes_generate_exactly_once_on_empty_slot() {
        let backend = InMemoryKeychain::new();
        let generate_calls = Mutex::new(0usize);
        let _ = fetch_or_create(&backend, &KeychainSlot::VaultKey, || {
            *generate_calls.lock().unwrap() += 1;
            marker_key(0x01)
        })
        .unwrap();
        assert_eq!(*generate_calls.lock().unwrap(), 1);
    }

    #[test]
    fn fetch_or_create_does_not_invoke_generate_when_slot_has_value() {
        let backend = InMemoryKeychain::preloaded(KeychainSlot::VaultKey, [0x02; KEY_LEN]);
        let generate_calls = Mutex::new(0usize);
        let returned = fetch_or_create(&backend, &KeychainSlot::VaultKey, || {
            *generate_calls.lock().unwrap() += 1;
            marker_key(0xFF)
        })
        .unwrap();
        assert_eq!(*generate_calls.lock().unwrap(), 0);
        assert_eq!(
            returned.expose_secret(),
            &[0x02u8; KEY_LEN],
            "should have returned the pre-existing key, not the factory's"
        );
    }

    #[test]
    fn fetch_or_create_persists_generated_key_so_next_fetch_finds_it() {
        let backend = InMemoryKeychain::new();
        let _ = fetch_or_create(&backend, &KeychainSlot::VaultKey, || marker_key(0x03)).unwrap();
        let found = backend.fetch(&KeychainSlot::VaultKey).unwrap();
        let found = found.expect("key must be present after fetch_or_create");
        assert_eq!(found.expose_secret(), &[0x03u8; KEY_LEN]);
    }
}
