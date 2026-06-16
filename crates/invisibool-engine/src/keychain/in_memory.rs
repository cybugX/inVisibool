//! In-memory `KeychainBackend` for tests and the engine's own
//! integration suite. Never wired into a shipped CLI binary; the M1
//! CLI selects a real-backend implementation at runtime.
//!
//! Storage is `Mutex<HashMap<KeychainSlot, Zeroizing<[u8; KEY_LEN]>>>`:
//! the inner `Zeroizing` wipes the key bytes when the map entry is
//! removed or the whole map drops, matching the project's
//! zeroize-on-drop discipline. The `Mutex` makes the backend
//! `Send + Sync` so the future watch daemon (event loop + IPC server
//! on different threads) can share one instance, even though M1's M0b
//! tests don't yet exercise concurrent access.

use std::collections::HashMap;
use std::sync::Mutex;

use secrecy::{ExposeSecret, SecretBox};
use zeroize::Zeroizing;

use super::{KeychainBackend, KeychainError, KeychainSlot, KEY_LEN};

/// Test-only in-memory keychain. Operations are infallible at the
/// trait level (no IPC to fail); tests that need to exercise the
/// trait's error paths use a separate mock impl.
pub struct InMemoryKeychain {
    slots: Mutex<HashMap<KeychainSlot, Zeroizing<[u8; KEY_LEN]>>>,
}

impl InMemoryKeychain {
    /// Start empty. The first `fetch_or_create(VaultKey, ...)` call
    /// against this backend will invoke its `generate` closure.
    pub fn new() -> Self {
        Self {
            slots: Mutex::new(HashMap::new()),
        }
    }

    /// Start pre-populated with `key` in `slot`. Used by tests that
    /// exercise the "key already exists" path of `fetch_or_create`.
    pub fn preloaded(slot: KeychainSlot, key: [u8; KEY_LEN]) -> Self {
        let mut map = HashMap::new();
        map.insert(slot, Zeroizing::new(key));
        Self {
            slots: Mutex::new(map),
        }
    }
}

impl Default for InMemoryKeychain {
    fn default() -> Self {
        Self::new()
    }
}

impl KeychainBackend for InMemoryKeychain {
    fn fetch(
        &self,
        slot: &KeychainSlot,
    ) -> Result<Option<SecretBox<[u8; KEY_LEN]>>, KeychainError> {
        let slots = self.slots.lock().expect("InMemoryKeychain mutex poisoned");
        Ok(slots
            .get(slot)
            .map(|bytes| SecretBox::new(Box::new(**bytes))))
    }

    fn store(
        &self,
        slot: &KeychainSlot,
        key: SecretBox<[u8; KEY_LEN]>,
    ) -> Result<(), KeychainError> {
        let bytes: [u8; KEY_LEN] = *key.expose_secret();
        let mut slots = self.slots.lock().expect("InMemoryKeychain mutex poisoned");
        slots.insert(slot.clone(), Zeroizing::new(bytes));
        Ok(())
    }

    fn delete(&self, slot: &KeychainSlot) -> Result<(), KeychainError> {
        let mut slots = self.slots.lock().expect("InMemoryKeychain mutex poisoned");
        slots.remove(slot);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn marker(byte: u8) -> SecretBox<[u8; KEY_LEN]> {
        SecretBox::new(Box::new([byte; KEY_LEN]))
    }

    // ----- 1. fresh backend has no key. -----

    #[test]
    fn new_backend_starts_empty() {
        let kc = InMemoryKeychain::new();
        let got = kc.fetch(&KeychainSlot::VaultKey).unwrap();
        assert!(got.is_none(), "fresh InMemoryKeychain should have no keys");
    }

    // ----- 2. store-then-fetch round-trip. -----

    #[test]
    fn store_then_fetch_round_trips_the_key() {
        let kc = InMemoryKeychain::new();
        let bytes_in = [0x42u8; KEY_LEN];
        kc.store(&KeychainSlot::VaultKey, SecretBox::new(Box::new(bytes_in)))
            .unwrap();
        let out = kc
            .fetch(&KeychainSlot::VaultKey)
            .unwrap()
            .expect("key just stored should be fetched");
        assert_eq!(
            out.expose_secret(),
            &bytes_in,
            "round-tripped bytes should match"
        );
    }

    // ----- 3. fetch returns Ok(None) on empty slot, not Err. -----

    #[test]
    fn fetch_returns_ok_none_on_empty_slot_not_err() {
        let kc = InMemoryKeychain::new();
        match kc.fetch(&KeychainSlot::VaultKey) {
            Ok(None) => {}
            Ok(Some(_)) => panic!("empty slot should not produce a key"),
            Err(e) => panic!("empty slot should be Ok(None), not Err: {e:?}"),
        }
    }

    // ----- 4. delete on empty slot is idempotent. -----

    #[test]
    fn delete_on_empty_slot_is_idempotent() {
        let kc = InMemoryKeychain::new();
        // First delete on empty slot.
        assert!(
            kc.delete(&KeychainSlot::VaultKey).is_ok(),
            "delete on empty slot should succeed"
        );
        // Second delete on still-empty slot.
        assert!(
            kc.delete(&KeychainSlot::VaultKey).is_ok(),
            "second delete on empty slot should also succeed"
        );
    }

    // ----- 5. store then delete then fetch returns None. -----

    #[test]
    fn store_then_delete_then_fetch_returns_none() {
        let kc = InMemoryKeychain::new();
        kc.store(&KeychainSlot::VaultKey, marker(0x55)).unwrap();
        kc.delete(&KeychainSlot::VaultKey).unwrap();
        assert!(kc.fetch(&KeychainSlot::VaultKey).unwrap().is_none());
    }

    // ----- 6. store overwrites unconditionally. -----

    #[test]
    fn store_overwrites_unconditionally() {
        let kc = InMemoryKeychain::new();
        kc.store(&KeychainSlot::VaultKey, marker(0x01)).unwrap();
        kc.store(&KeychainSlot::VaultKey, marker(0x02)).unwrap();
        let out = kc.fetch(&KeychainSlot::VaultKey).unwrap().unwrap();
        assert_eq!(
            out.expose_secret(),
            &[0x02u8; KEY_LEN],
            "second store should have replaced the first"
        );
    }

    // ----- 7. multiple slots are independent. -----
    //
    // Currently only VaultKey exists; this test uses two references to
    // the same variant to confirm the HashMap-shaped storage handles
    // them, and is written so it doesn't have to be revisited when M4a
    // adds new slot variants.

    #[test]
    fn slot_storage_keyed_by_kind_not_by_reference_identity() {
        let kc = InMemoryKeychain::new();
        let slot_a = KeychainSlot::VaultKey;
        let slot_b = KeychainSlot::VaultKey;
        kc.store(&slot_a, marker(0x77)).unwrap();
        let from_b = kc.fetch(&slot_b).unwrap().unwrap();
        assert_eq!(
            from_b.expose_secret(),
            &[0x77u8; KEY_LEN],
            "two values of the same slot variant must hit the same storage entry"
        );
    }

    // ----- preloaded() constructor seeds the backend correctly. -----

    #[test]
    fn preloaded_constructor_seeds_the_slot() {
        let kc = InMemoryKeychain::preloaded(KeychainSlot::VaultKey, [0x99; KEY_LEN]);
        let out = kc
            .fetch(&KeychainSlot::VaultKey)
            .unwrap()
            .expect("preloaded key should be present immediately");
        assert_eq!(out.expose_secret(), &[0x99u8; KEY_LEN]);
    }
}
