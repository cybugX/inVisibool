//! In-memory session map for long-lived processes.
//!
//! Bidirectional `{real ↔ fake}` map with two bounds:
//!
//! - **LRU**: when the map reaches `max_entries`, the least-recently-touched
//!   entry is evicted. Both insertions and lookups update the touch
//!   timestamp, so frequently-used pairs stay alive.
//! - **TTL**: entries not touched for longer than the configured duration
//!   are pruned on every access.
//!
//! Per-session stability follows from `get_or_insert`: the same `real`
//! input always returns the same `fake` until the entry is evicted.
//!
//! The map exists so non-FF1 fakes (PII, cards, detected-but-unregistered
//! high-entropy secrets) can be restored by a long-lived process — the
//! `watch` daemon today, the future proxy daemon tomorrow. Short-lived
//! two-command CLI invocations cannot use this strategy; they use
//! stateless FF1 instead.
//!
//! **Time injection.** Every public operation takes an explicit `now:
//! Instant`. Tests construct successive `Instant`s by adding `Duration`s
//! to `Instant::now()`; production callers pass the real `Instant::now()`.
//! No internal clock means no global state, no flaky time-dependent tests,
//! and a clean shape for the M1 CLI's serialisation hook (the on-disk
//! AEAD-encrypted session file stores `{fake, real}` pairs only — see
//! `entries` and `import`; the timestamps reset to `now` on load).
//!
//! **Collision policy.** `make_fake` is expected to produce unique fakes
//! across calls. If two different `real` values happen to map to the same
//! `fake`, the second insertion overwrites the first and the orphaned
//! `real → fake` direction is cleaned up so the two maps stay consistent
//! (last-write-wins). With the MAC-tagged and reserved-range fakes that
//! M0b ships, collision odds are negligible at any realistic session
//! size, so this policy primarily exists to keep the invariants tight if
//! a poorly-seeded factory is ever wired in.
//!
//! **Secret-bytes lifecycle.** Real values live in two places: as the
//! `real` field of every `Entry` in `by_fake`, and as the key of every
//! entry in `by_real`. Both copies are wiped before deallocation:
//!
//! - `Entry.real` is a `Zeroizing<String>`. When the `Entry` is dropped
//!   — eviction (`evict_lru`), TTL pruning (`prune`), explicit `clear`,
//!   collision overwrite, or the map itself going out of scope — the
//!   `Zeroizing` Drop runs `String::zeroize`, wiping the underlying
//!   bytes before the allocator reclaims them.
//! - `by_real` keys are plain `String` (HashMap keys cannot be mutated
//!   in place, so the `Zeroizing` wrapper is awkward there). Every code
//!   path that removes an entry from `by_real` uses `remove_entry()` to
//!   take ownership of the key and calls `.zeroize()` before letting it
//!   drop. The `Drop` impl on `SessionMap` does the same sweep for any
//!   keys still resident when the map itself goes out of scope.
//!
//! Two residual limitations we cannot close at this layer, both flagged
//! in the threat model:
//!
//! 1. **HashMap resize moves.** When a `HashMap` grows, it copies its
//!    keys and values into a new allocation; the old slots are freed
//!    without zeroization. A real-value byte sequence can linger in the
//!    freed buffer until the allocator reuses it.
//! 2. **Returned clones.** `restore` hands the caller a fresh `String`
//!    copy. Once that copy crosses the function boundary, this map can
//!    no longer track it; the caller is responsible for wrapping it in
//!    `Zeroizing` / `Secret` if its lifetime extends.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use zeroize::{Zeroize, Zeroizing};

/// Bounded bidirectional `{real ↔ fake}` map with LRU + TTL eviction.
pub struct SessionMap {
    max_entries: usize,
    ttl: Duration,
    by_fake: HashMap<String, Entry>,
    by_real: HashMap<String, String>,
}

struct Entry {
    real: Zeroizing<String>,
    last_touched: Instant,
}

impl SessionMap {
    /// Build an empty map. `max_entries` caps memory use; `ttl` caps
    /// how long an unused entry survives.
    pub fn new(max_entries: usize, ttl: Duration) -> Self {
        Self {
            max_entries,
            ttl,
            by_fake: HashMap::new(),
            by_real: HashMap::new(),
        }
    }

    /// Return the fake registered for `real` if one is alive, or call
    /// `make_fake()` to produce a new fake and store the pairing.
    /// Touches the entry's `last_touched` either way. Prunes expired
    /// entries before the lookup and evicts the LRU entry if the new
    /// insertion would exceed `max_entries`.
    pub fn get_or_insert<F>(&mut self, real: &str, now: Instant, make_fake: F) -> String
    where
        F: FnOnce() -> String,
    {
        self.prune(now);

        if let Some(fake) = self.by_real.get(real) {
            let fake = fake.clone();
            if let Some(entry) = self.by_fake.get_mut(&fake) {
                entry.last_touched = now;
            }
            return fake;
        }

        if self.by_fake.len() >= self.max_entries {
            self.evict_lru();
        }

        let fake = make_fake();
        let new = Entry {
            real: Zeroizing::new(real.to_string()),
            last_touched: now,
        };
        // If `fake` collides with an existing entry, the previous owner
        // gets its reverse-direction pointer cleaned up so the two maps
        // stay consistent. Last-write-wins, documented at the module level.
        // The displaced Entry drops here — its Zeroizing<String> wipes
        // the old real value's bytes before deallocation.
        if let Some(old) = self.by_fake.insert(fake.clone(), new) {
            wipe_by_real_key(&mut self.by_real, &old.real);
        }
        self.by_real.insert(real.to_string(), fake.clone());
        fake
    }

    /// Look up the real value behind `fake`. Returns `None` if the
    /// mapping is absent or has expired. Bumps `last_touched` on hit.
    ///
    /// The returned `String` is a fresh allocation; the original copy
    /// inside the map continues to live (Zeroizing-wrapped) until it is
    /// evicted or the map drops. Callers that hold the returned plaintext
    /// across a long lifetime should wrap it in `Zeroizing` themselves.
    pub fn restore(&mut self, fake: &str, now: Instant) -> Option<String> {
        self.prune(now);
        let entry = self.by_fake.get_mut(fake)?;
        entry.last_touched = now;
        Some((*entry.real).clone())
    }

    /// Iterate over every `(fake, real)` pair currently in the map.
    /// Used by the M1 CLI to serialise the session for on-disk AEAD
    /// storage; the iteration order is unspecified.
    pub fn entries(&self) -> impl Iterator<Item = (&str, &str)> {
        self.by_fake
            .iter()
            .map(|(fake, entry)| (fake.as_str(), (*entry.real).as_str()))
    }

    /// Bulk-load `(fake, real)` pairs back into the map. Timestamps are
    /// set to `now` so the loaded session starts a fresh TTL clock.
    /// Used by the M1 CLI to restore a session map after AEAD decryption.
    pub fn import<I, S1, S2>(&mut self, pairs: I, now: Instant)
    where
        I: IntoIterator<Item = (S1, S2)>,
        S1: Into<String>,
        S2: Into<String>,
    {
        for (fake, real) in pairs {
            let fake: String = fake.into();
            let real: String = real.into();
            // If an existing entry's fake collides, its Entry drops
            // here (Zeroizing wipes the old real value). Also wipe the
            // matching by_real key.
            if let Some(old) = self.by_fake.insert(
                fake.clone(),
                Entry {
                    real: Zeroizing::new(real.clone()),
                    last_touched: now,
                },
            ) {
                wipe_by_real_key(&mut self.by_real, &old.real);
            }
            self.by_real.insert(real, fake);
        }
    }

    pub fn len(&self) -> usize {
        self.by_fake.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_fake.is_empty()
    }

    /// Discard every entry. Used by `session clear` at the CLI layer
    /// and by the idle-lock path on the long-lived daemons.
    ///
    /// Wipes `by_real` keys (plaintext String) before their drop and
    /// then clears `by_fake`, whose Entry-side `Zeroizing<String>` wipes
    /// the second copy of each real value as part of HashMap::clear.
    pub fn clear(&mut self) {
        for (mut key, _) in self.by_real.drain() {
            key.zeroize();
        }
        self.by_fake.clear();
    }

    fn prune(&mut self, now: Instant) {
        let ttl = self.ttl;
        let expired: Vec<String> = self
            .by_fake
            .iter()
            .filter(|(_, e)| now.saturating_duration_since(e.last_touched) > ttl)
            .map(|(k, _)| k.clone())
            .collect();
        for fake in expired {
            if let Some(entry) = self.by_fake.remove(&fake) {
                wipe_by_real_key(&mut self.by_real, &entry.real);
                // entry drops here: its Zeroizing<String> wipes the
                // Entry-side copy of the real value.
            }
        }
    }

    fn evict_lru(&mut self) {
        let Some(fake) = self
            .by_fake
            .iter()
            .min_by_key(|(_, e)| e.last_touched)
            .map(|(k, _)| k.clone())
        else {
            return;
        };
        if let Some(entry) = self.by_fake.remove(&fake) {
            wipe_by_real_key(&mut self.by_real, &entry.real);
            // entry drops here: Zeroizing<String> wipes the Entry-side
            // copy of the real value.
        }
    }
}

/// Remove the `by_real` entry whose key equals `real` and explicitly
/// zeroize that key before dropping it. Use this anywhere a real value
/// leaves the map.
fn wipe_by_real_key(by_real: &mut HashMap<String, String>, real: &str) {
    if let Some((mut key, _fake)) = by_real.remove_entry(real) {
        key.zeroize();
        // `key` drops here, post-zeroize; the deallocation is no longer
        // disclosure-relevant.
    }
}

impl Drop for SessionMap {
    fn drop(&mut self) {
        // `by_fake` will drop its Entry values automatically, and each
        // Entry's Zeroizing<String> wipes the Entry-side copy of the
        // real value. The `by_real` HashMap holds plaintext Strings as
        // KEYS, which HashMap drops without zeroizing — so drain them
        // explicitly and wipe each key before its drop.
        for (mut key, _) in self.by_real.drain() {
            key.zeroize();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A small factory helper: returns a fresh "fake-N" string each call.
    fn counting_factory() -> impl FnMut() -> String {
        let mut n = 0;
        move || {
            n += 1;
            format!("fake-{n}")
        }
    }

    fn make_with(capacity: usize, ttl_secs: u64) -> SessionMap {
        SessionMap::new(capacity, Duration::from_secs(ttl_secs))
    }

    // ----- basics -----

    #[test]
    fn new_map_is_empty() {
        let m = make_with(10, 60);
        assert!(m.is_empty());
        assert_eq!(m.len(), 0);
    }

    #[test]
    fn get_or_insert_returns_same_fake_for_same_real() {
        let mut m = make_with(10, 60);
        let mut factory = counting_factory();
        let t0 = Instant::now();
        let a = m.get_or_insert("real-A", t0, &mut factory);
        let b = m.get_or_insert("real-A", t0, &mut factory);
        assert_eq!(a, b);
        assert_eq!(a, "fake-1");
        // Factory was called once: a single insert.
        assert_eq!(m.len(), 1);
    }

    #[test]
    fn get_or_insert_returns_distinct_fakes_for_distinct_reals() {
        let mut m = make_with(10, 60);
        let mut factory = counting_factory();
        let t0 = Instant::now();
        let a = m.get_or_insert("real-A", t0, &mut factory);
        let b = m.get_or_insert("real-B", t0, &mut factory);
        assert_ne!(a, b);
        assert_eq!(m.len(), 2);
    }

    #[test]
    fn restore_round_trips() {
        let mut m = make_with(10, 60);
        let t0 = Instant::now();
        let fake = m.get_or_insert("the-real", t0, || "the-fake".to_string());
        assert_eq!(fake, "the-fake");
        assert_eq!(m.restore("the-fake", t0).as_deref(), Some("the-real"));
    }

    #[test]
    fn restore_returns_none_for_unknown_fake() {
        let mut m = make_with(10, 60);
        let t0 = Instant::now();
        assert_eq!(m.restore("never-stored", t0), None);
    }

    #[test]
    fn clear_empties_both_directions() {
        let mut m = make_with(10, 60);
        let t0 = Instant::now();
        m.get_or_insert("a", t0, || "fake-a".into());
        m.get_or_insert("b", t0, || "fake-b".into());
        m.clear();
        assert!(m.is_empty());
        assert_eq!(m.restore("fake-a", t0), None);
    }

    // ----- LRU eviction -----

    #[test]
    fn insert_at_capacity_evicts_least_recently_touched() {
        let mut m = make_with(2, 60_000); // huge TTL — only LRU matters
        let t0 = Instant::now();
        let _ = m.get_or_insert("a", t0, || "fake-a".into());
        let t1 = t0 + Duration::from_secs(1);
        let _ = m.get_or_insert("b", t1, || "fake-b".into());
        // Touch "a" so it becomes the most-recently-used.
        let t2 = t0 + Duration::from_secs(2);
        let _ = m.restore("fake-a", t2);
        // Insert "c" at t3 — must evict "b" (LRU), not "a".
        let t3 = t0 + Duration::from_secs(3);
        let _ = m.get_or_insert("c", t3, || "fake-c".into());

        assert_eq!(
            m.restore("fake-a", t3 + Duration::from_secs(1)).as_deref(),
            Some("a")
        );
        assert_eq!(
            m.restore("fake-c", t3 + Duration::from_secs(1)).as_deref(),
            Some("c")
        );
        // "b" is gone.
        assert_eq!(m.restore("fake-b", t3 + Duration::from_secs(1)), None);
        assert_eq!(m.len(), 2);
    }

    // ----- TTL eviction -----

    #[test]
    fn entry_expires_after_ttl_without_touch() {
        let mut m = make_with(10, 60);
        let t0 = Instant::now();
        m.get_or_insert("a", t0, || "fake-a".into());
        // Just inside the TTL.
        assert_eq!(
            m.restore("fake-a", t0 + Duration::from_secs(30)).as_deref(),
            Some("a")
        );
        // Past the TTL — prune kicks in.
        assert_eq!(m.restore("fake-a", t0 + Duration::from_secs(120)), None);
        assert!(m.is_empty());
    }

    #[test]
    fn touching_an_entry_refreshes_its_ttl() {
        let mut m = make_with(10, 60);
        let t0 = Instant::now();
        m.get_or_insert("a", t0, || "fake-a".into());
        // Touch every 30 s for 5 minutes — far past the 60 s TTL.
        for k in 1..=10 {
            let t = t0 + Duration::from_secs(30 * k);
            assert!(m.restore("fake-a", t).is_some(), "expired at step {k}");
        }
    }

    #[test]
    fn insert_prunes_expired_before_evaluating_capacity() {
        // Bound = 2, TTL = 60 s. Insert A and B early; let them expire;
        // then insert C — must not evict anything because A and B were
        // already pruned for TTL.
        let mut m = make_with(2, 60);
        let t0 = Instant::now();
        m.get_or_insert("a", t0, || "fake-a".into());
        m.get_or_insert("b", t0, || "fake-b".into());
        let t1 = t0 + Duration::from_secs(120);
        m.get_or_insert("c", t1, || "fake-c".into());
        assert_eq!(m.len(), 1);
        assert_eq!(m.restore("fake-c", t1).as_deref(), Some("c"));
    }

    // ----- entries / import -----

    #[test]
    fn entries_exposes_all_pairs() {
        let mut m = make_with(10, 60);
        let t0 = Instant::now();
        m.get_or_insert("a", t0, || "fake-a".into());
        m.get_or_insert("b", t0, || "fake-b".into());
        let mut got: Vec<(String, String)> = m
            .entries()
            .map(|(f, r)| (f.to_string(), r.to_string()))
            .collect();
        got.sort();
        let mut want = vec![
            ("fake-a".to_string(), "a".to_string()),
            ("fake-b".to_string(), "b".to_string()),
        ];
        want.sort();
        assert_eq!(got, want);
    }

    #[test]
    fn import_round_trips_through_export() {
        let mut m1 = make_with(10, 60);
        let t0 = Instant::now();
        m1.get_or_insert("a", t0, || "fake-a".into());
        m1.get_or_insert("b", t0, || "fake-b".into());
        let pairs: Vec<(String, String)> = m1
            .entries()
            .map(|(f, r)| (f.to_string(), r.to_string()))
            .collect();

        let mut m2 = make_with(10, 60);
        let t1 = Instant::now();
        m2.import(pairs, t1);
        assert_eq!(m2.len(), 2);
        assert_eq!(m2.restore("fake-a", t1).as_deref(), Some("a"));
        assert_eq!(m2.restore("fake-b", t1).as_deref(), Some("b"));
    }

    // ----- wipe-path consistency: by_real cleaned, no orphans -----
    //
    // These tests prove that LRU/TTL/clear don't just remove from
    // by_fake — they also wipe the matching by_real key. If by_real
    // kept an orphan, the next get_or_insert for the evicted real
    // would short-circuit to the stale fake and the factory would not
    // run. The factory-call counter is the canary.

    #[test]
    fn lru_eviction_cleans_by_real_so_reinsertion_is_fresh() {
        let mut m = make_with(2, 60_000); // huge TTL: only LRU matters
        let t0 = Instant::now();
        m.get_or_insert("real-A", t0, || "fake-A".to_string());
        m.get_or_insert("real-B", t0 + Duration::from_secs(1), || {
            "fake-B".to_string()
        });
        // Insert C → evicts real-A (least recently touched).
        m.get_or_insert("real-C", t0 + Duration::from_secs(2), || {
            "fake-C".to_string()
        });

        // Re-insert real-A. If by_real still had an orphaned A → fake-A
        // pointer, this call would return "fake-A" and not invoke the
        // factory. Counter proves the factory ran, which means by_real
        // was wiped during the LRU eviction.
        let mut factory_calls = 0;
        let a_again = m.get_or_insert("real-A", t0 + Duration::from_secs(3), || {
            factory_calls += 1;
            "fake-A2".to_string()
        });
        assert_eq!(a_again, "fake-A2");
        assert_eq!(factory_calls, 1);
    }

    #[test]
    fn ttl_eviction_cleans_by_real_so_reinsertion_is_fresh() {
        let mut m = make_with(10, 60);
        let t0 = Instant::now();
        m.get_or_insert("real-A", t0, || "fake-A".to_string());
        // Walk past TTL so the next public operation prunes A.
        let t1 = t0 + Duration::from_secs(120);
        // A restore call on an unrelated fake still triggers prune.
        let _ = m.restore("does-not-exist", t1);

        let mut factory_calls = 0;
        let a_again = m.get_or_insert("real-A", t1, || {
            factory_calls += 1;
            "fake-A2".to_string()
        });
        assert_eq!(a_again, "fake-A2");
        assert_eq!(factory_calls, 1);
    }

    #[test]
    fn clear_cleans_by_real_so_reinsertion_is_fresh() {
        let mut m = make_with(10, 60);
        let t0 = Instant::now();
        m.get_or_insert("real-A", t0, || "fake-A".to_string());
        m.clear();

        let mut factory_calls = 0;
        let a_again = m.get_or_insert("real-A", t0, || {
            factory_calls += 1;
            "fake-A2".to_string()
        });
        assert_eq!(a_again, "fake-A2");
        assert_eq!(factory_calls, 1);
    }

    // ----- collision policy: last-write-wins, invariants preserved -----

    #[test]
    fn colliding_fake_replaces_previous_pairing_and_cleans_reverse_map() {
        let mut m = make_with(10, 60);
        let t0 = Instant::now();
        m.get_or_insert("real-1", t0, || "SAME-FAKE".to_string());
        // Now a poorly-seeded factory produces the same fake for a
        // different real. The new pairing replaces the old in both
        // directions; the old real becomes un-restorable.
        m.get_or_insert("real-2", t0, || "SAME-FAKE".to_string());
        assert_eq!(m.restore("SAME-FAKE", t0).as_deref(), Some("real-2"));
        // The maps stay in sync: get_or_insert("real-1") sees no
        // mapping and produces a NEW fake rather than returning the
        // stale "SAME-FAKE".
        let again = m.get_or_insert("real-1", t0, || "DIFFERENT-FAKE".to_string());
        assert_eq!(again, "DIFFERENT-FAKE");
        assert_eq!(m.len(), 2);
    }
}
