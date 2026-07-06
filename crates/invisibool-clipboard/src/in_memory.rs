//! In-memory `Clipboard` implementation for tests and the leak
//! harness.
//!
//! `InMemoryClipboard` is `pub` (not `#[cfg(test)]`-gated). Chunk-22
//! learned the hard way that `#[cfg(test)]` does not cross crate
//! boundaries, and a fake clipboard is fail-visible (a leak-harness
//! test on top of it will fire loudly) rather than fail-dangerous
//! (production code accidentally binding it does not leak - it just
//! writes to a local `Vec`). The alternative - gating the fake
//! behind a feature flag - creates friction for every downstream
//! test crate and buys no additional safety.
//!
//! # History-inspection surface
//!
//! Every write, clear, and read is recorded in an append-only
//! history that tests inspect via `history()` and `reads()`.
//! Writes carry the full text and hints; clears are marked
//! distinctly so a caller cannot confuse them with a zero-length
//! write.

use std::sync::{Arc, Mutex};

use zeroize::Zeroizing;

use crate::error::ClipboardError;
use crate::hints::PrivacyHints;
use crate::{Clipboard, ClipboardEvent, Subscription, SubscriptionHandle, WriteToken};

/// A wipe-on-drop, thread-safe, test-only clipboard.
#[derive(Debug, Default)]
pub struct InMemoryClipboard {
    state: Arc<Mutex<InMemoryState>>,
}

struct InMemoryState {
    /// The current clipboard text, wipe-on-drop like the read-side
    /// return type.
    text: Option<Zeroizing<String>>,
    change_count: u64,
    next_token: u64,
    subscribers: Vec<Arc<dyn Fn(ClipboardEvent) + Send + Sync>>,
    history: Vec<HistoryEntry>,
    reads: Vec<InMemoryRead>,
    forced_read_err: Option<ClipboardError>,
}

impl std::fmt::Debug for InMemoryState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Deliberately does NOT format the text field: the whole
        // point of Zeroizing is that the plaintext does not leak
        // through Debug.
        f.debug_struct("InMemoryState")
            .field("has_text", &self.text.is_some())
            .field("change_count", &self.change_count)
            .field("history_len", &self.history.len())
            .field("reads_len", &self.reads.len())
            .finish_non_exhaustive()
    }
}

impl Default for InMemoryState {
    fn default() -> Self {
        Self {
            text: None,
            change_count: 0,
            next_token: 1,
            subscribers: Vec::new(),
            history: Vec::new(),
            reads: Vec::new(),
            forced_read_err: None,
        }
    }
}

/// One entry in the append-only clipboard history.
#[derive(Debug, Clone)]
pub enum HistoryEntry {
    /// A write, ours or a simulated external write.
    Write(InMemoryWrite),
    /// A `clear()` call. Distinguished from a zero-length write so
    /// tests can assert the daemon used the true-clear API where it
    /// should have.
    Clear {
        change_count_after: u64,
        source: WriteSource,
    },
}

/// A recorded clipboard write.
#[derive(Debug, Clone)]
pub struct InMemoryWrite {
    pub token: WriteToken,
    pub change_count_after: u64,
    /// The full written text. Held plaintext because the harness
    /// needs to look for canary substrings; the InMemoryClipboard is
    /// test-only surface.
    pub text: String,
    pub hints: PrivacyHints,
    pub source: WriteSource,
}

/// A recorded clipboard read. The recorded text is a stringified
/// snapshot for harness inspection; the caller of `read_text` still
/// gets a `Zeroizing<String>`.
#[derive(Debug, Clone)]
pub struct InMemoryRead {
    pub at_change_count: u64,
    pub had_text: bool,
    pub snapshot: Option<String>,
}

/// Where a write came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteSource {
    /// Result of a `write_text` or `clear` call on the trait.
    OurWrite,
    /// Result of a `simulate_external_write` test helper: models an
    /// external application (or the user) writing the clipboard.
    SimulatedExternal,
}

impl InMemoryClipboard {
    /// Construct a fresh empty in-memory clipboard.
    pub fn new() -> Self {
        Self::default()
    }

    /// Return a snapshot of the full history in write order.
    pub fn history(&self) -> Vec<HistoryEntry> {
        self.state.lock().expect("mutex poisoned").history.clone()
    }

    /// Return a snapshot of the recorded reads in order.
    pub fn reads(&self) -> Vec<InMemoryRead> {
        self.state.lock().expect("mutex poisoned").reads.clone()
    }

    /// Test helper: simulate an external application (or the user
    /// via a keyboard copy) writing the clipboard. This bumps
    /// `change_count`, updates the current text, notifies subscribers
    /// with `matches_our_write = None`, and appends a
    /// `HistoryEntry::Write` tagged `SimulatedExternal`.
    ///
    /// The `PrivacyHints` recorded on a simulated external write are
    /// `PrivacyHints::NONE` by construction: an external write has
    /// no way of asking for privacy hints, and the harness relies on
    /// this to distinguish daemon writes from external ones.
    pub fn simulate_external_write(&self, text: &str) {
        let mut st = self.state.lock().expect("mutex poisoned");
        st.change_count += 1;
        st.text = Some(Zeroizing::new(text.to_string()));
        let entry = InMemoryWrite {
            // WriteToken(0) is the sentinel for "not one of ours".
            // Real tokens minted by write_text start at 1 (see
            // InMemoryState::default's next_token = 1), so this
            // sentinel cannot collide with a real token.
            token: WriteToken(0),
            change_count_after: st.change_count,
            text: text.to_string(),
            hints: PrivacyHints::NONE,
            source: WriteSource::SimulatedExternal,
        };
        st.history.push(HistoryEntry::Write(entry));
        let cc = st.change_count;
        let subs = st.subscribers.clone();
        drop(st);
        for sub in subs {
            sub(ClipboardEvent {
                change_count: cc,
                matches_our_write: None,
            });
        }
    }

    /// Test helper: cause the next `read_text` call to fail with the
    /// given error. Cleared after one use.
    pub fn force_next_read_fail(&self, err: ClipboardError) {
        self.state.lock().expect("mutex poisoned").forced_read_err = Some(err);
    }
}

impl Clipboard for InMemoryClipboard {
    fn read_text(&self) -> Result<Option<Zeroizing<String>>, ClipboardError> {
        let mut st = self.state.lock().expect("mutex poisoned");
        if let Some(err) = st.forced_read_err.take() {
            return Err(err);
        }
        let snapshot = st.text.as_ref().map(|s| s.as_str().to_string());
        let read = InMemoryRead {
            at_change_count: st.change_count,
            had_text: st.text.is_some(),
            snapshot: snapshot.clone(),
        };
        st.reads.push(read);
        Ok(st
            .text
            .as_ref()
            .map(|s| Zeroizing::new(s.as_str().to_string())))
    }

    fn write_text(&self, text: &str, hints: PrivacyHints) -> Result<WriteToken, ClipboardError> {
        let mut st = self.state.lock().expect("mutex poisoned");
        let token = WriteToken(st.next_token);
        st.next_token += 1;
        st.change_count += 1;
        st.text = Some(Zeroizing::new(text.to_string()));
        let entry = InMemoryWrite {
            token,
            change_count_after: st.change_count,
            text: text.to_string(),
            hints,
            source: WriteSource::OurWrite,
        };
        st.history.push(HistoryEntry::Write(entry));
        let cc = st.change_count;
        let subs = st.subscribers.clone();
        drop(st);
        for sub in subs {
            sub(ClipboardEvent {
                change_count: cc,
                matches_our_write: Some(token),
            });
        }
        Ok(token)
    }

    fn clear(&self) -> Result<(), ClipboardError> {
        let mut st = self.state.lock().expect("mutex poisoned");
        st.change_count += 1;
        st.text = None;
        let cc = st.change_count;
        st.history.push(HistoryEntry::Clear {
            change_count_after: cc,
            source: WriteSource::OurWrite,
        });
        let subs = st.subscribers.clone();
        drop(st);
        for sub in subs {
            sub(ClipboardEvent {
                change_count: cc,
                matches_our_write: None, // A clear has no write token.
            });
        }
        Ok(())
    }

    fn change_count(&self) -> Result<u64, ClipboardError> {
        Ok(self.state.lock().expect("mutex poisoned").change_count)
    }

    fn subscribe(
        &self,
        on_change: Arc<dyn Fn(ClipboardEvent) + Send + Sync>,
    ) -> Result<Subscription, ClipboardError> {
        let mut st = self.state.lock().expect("mutex poisoned");
        st.subscribers.push(on_change.clone());
        drop(st);
        let handle = InMemorySubscription {
            state: self.state.clone(),
            callback: on_change,
        };
        Ok(Subscription::new(Box::new(handle)))
    }
}

/// Cancels an InMemoryClipboard subscription on drop.
struct InMemorySubscription {
    state: Arc<Mutex<InMemoryState>>,
    callback: Arc<dyn Fn(ClipboardEvent) + Send + Sync>,
}

impl SubscriptionHandle for InMemorySubscription {}

impl Drop for InMemorySubscription {
    fn drop(&mut self) {
        let mut st = match self.state.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        st.subscribers.retain(|s| !Arc::ptr_eq(s, &self.callback));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_clipboard_reads_none() {
        let c = InMemoryClipboard::new();
        assert!(c.read_text().unwrap().is_none());
    }

    #[test]
    fn write_then_read_round_trips() {
        let c = InMemoryClipboard::new();
        c.write_text("hello", PrivacyHints::CONCEAL_ALL).unwrap();
        let got = c.read_text().unwrap().unwrap();
        assert_eq!(&*got, "hello");
    }

    #[test]
    fn each_write_bumps_change_count() {
        let c = InMemoryClipboard::new();
        assert_eq!(c.change_count().unwrap(), 0);
        c.write_text("a", PrivacyHints::CONCEAL_ALL).unwrap();
        assert_eq!(c.change_count().unwrap(), 1);
        c.write_text("b", PrivacyHints::CONCEAL_ALL).unwrap();
        assert_eq!(c.change_count().unwrap(), 2);
    }

    #[test]
    fn clear_is_distinct_from_zero_length_write_in_history() {
        let c = InMemoryClipboard::new();
        c.write_text("", PrivacyHints::CONCEAL_ALL).unwrap();
        c.clear().unwrap();
        let hist = c.history();
        assert_eq!(hist.len(), 2);
        assert!(matches!(hist[0], HistoryEntry::Write(_)));
        assert!(matches!(hist[1], HistoryEntry::Clear { .. }));
    }

    #[test]
    fn clear_bumps_change_count_and_wipes_text() {
        let c = InMemoryClipboard::new();
        c.write_text("secret", PrivacyHints::CONCEAL_ALL).unwrap();
        assert_eq!(c.change_count().unwrap(), 1);
        assert!(c.read_text().unwrap().is_some());
        c.clear().unwrap();
        assert_eq!(c.change_count().unwrap(), 2);
        assert!(c.read_text().unwrap().is_none());
    }

    #[test]
    fn subscribe_fires_on_write_and_clear() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let c = InMemoryClipboard::new();
        let count = Arc::new(AtomicUsize::new(0));
        let count_c = count.clone();
        let _sub = c
            .subscribe(Arc::new(move |_ev| {
                count_c.fetch_add(1, Ordering::SeqCst);
            }))
            .unwrap();
        c.write_text("a", PrivacyHints::CONCEAL_ALL).unwrap();
        c.clear().unwrap();
        assert_eq!(count.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn subscribe_marks_our_writes_and_leaves_external_and_clear_unmarked() {
        use std::sync::Mutex as StdMutex;
        let c = InMemoryClipboard::new();
        let events: Arc<StdMutex<Vec<ClipboardEvent>>> = Arc::new(StdMutex::new(Vec::new()));
        let events_c = events.clone();
        let _sub = c
            .subscribe(Arc::new(move |ev| {
                events_c.lock().unwrap().push(ev);
            }))
            .unwrap();
        let token = c.write_text("ours", PrivacyHints::CONCEAL_ALL).unwrap();
        c.simulate_external_write("theirs");
        c.clear().unwrap();
        let ev = events.lock().unwrap().clone();
        assert_eq!(ev.len(), 3);
        assert_eq!(ev[0].matches_our_write, Some(token));
        assert_eq!(ev[1].matches_our_write, None);
        assert_eq!(ev[2].matches_our_write, None);
    }

    #[test]
    fn subscribe_dropping_subscription_stops_further_events() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let c = InMemoryClipboard::new();
        let count = Arc::new(AtomicUsize::new(0));
        let count_c = count.clone();
        let sub = c
            .subscribe(Arc::new(move |_| {
                count_c.fetch_add(1, Ordering::SeqCst);
            }))
            .unwrap();
        c.write_text("a", PrivacyHints::CONCEAL_ALL).unwrap();
        assert_eq!(count.load(Ordering::SeqCst), 1);
        drop(sub);
        c.write_text("b", PrivacyHints::CONCEAL_ALL).unwrap();
        // The callback must not have fired again.
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn history_records_source_correctly() {
        let c = InMemoryClipboard::new();
        c.write_text("ours", PrivacyHints::CONCEAL_ALL).unwrap();
        c.simulate_external_write("theirs");
        let hist = c.history();
        match &hist[0] {
            HistoryEntry::Write(w) => assert_eq!(w.source, WriteSource::OurWrite),
            other => panic!("expected Write, got {other:?}"),
        }
        match &hist[1] {
            HistoryEntry::Write(w) => assert_eq!(w.source, WriteSource::SimulatedExternal),
            other => panic!("expected Write, got {other:?}"),
        }
    }

    #[test]
    fn force_next_read_fail_fires_once() {
        let c = InMemoryClipboard::new();
        c.write_text("x", PrivacyHints::CONCEAL_ALL).unwrap();
        c.force_next_read_fail(ClipboardError::ReadFailed("test".into()));
        assert!(matches!(
            c.read_text().unwrap_err(),
            ClipboardError::ReadFailed(_)
        ));
        // Second read succeeds.
        assert!(c.read_text().unwrap().is_some());
    }

    #[test]
    fn read_records_change_count_and_snapshot() {
        let c = InMemoryClipboard::new();
        c.write_text("abc", PrivacyHints::CONCEAL_ALL).unwrap();
        let _ = c.read_text().unwrap();
        let reads = c.reads();
        assert_eq!(reads.len(), 1);
        assert_eq!(reads[0].at_change_count, 1);
        assert!(reads[0].had_text);
        assert_eq!(reads[0].snapshot.as_deref(), Some("abc"));
    }

    #[test]
    fn debug_impl_of_state_does_not_leak_text() {
        let c = InMemoryClipboard::new();
        c.write_text("very-secret", PrivacyHints::CONCEAL_ALL)
            .unwrap();
        let dbg = format!("{:?}", c.state.lock().unwrap());
        assert!(
            !dbg.contains("very-secret"),
            "state Debug output must not leak the clipboard text, got: {dbg}"
        );
        assert!(dbg.contains("has_text"));
    }
}
