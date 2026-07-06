//! Leak-harness extension for the clipboard trait.
//!
//! `InMemoryClipboard::history()` and `InMemoryClipboard::reads()`
//! give a test-side inspection surface over every write, clear, and
//! read on the clipboard. This test demonstrates the surface a
//! future `watch` daemon will be audited against: no real-secret
//! text (a runtime-generated canary) may appear in any clipboard
//! write except one flagged as a restore-context write with every
//! privacy hint set.
//!
//! The canary is generated at runtime and never committed. If a
//! future daemon binding writes the canary to the clipboard without
//! privacy hints, or emits it as part of a scrub-context write
//! (which was supposed to REPLACE the canary with a fake), the
//! assertions in this test fire.

use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use invisibool_clipboard::{
    Clipboard, ClipboardEvent, HistoryEntry, InMemoryClipboard, PrivacyHints, WriteSource,
};

/// Generate a fresh canary each run so a bug that hard-codes the
/// canary in output cannot pass.
fn fresh_canary() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("canary-{}-{}", std::process::id(), nanos)
}

/// Iterate the history and assert no `OurWrite` carries the canary
/// unless it is a tokenised restore-context write with every privacy
/// hint set. `SimulatedExternal` writes model the user (or another
/// application) putting text on the clipboard - that is the INPUT
/// the daemon exists to catch, not a leak.
fn assert_no_canary_leak(
    clipboard: &InMemoryClipboard,
    canary: &str,
    expected_restore_tokens: &[invisibool_clipboard::WriteToken],
) {
    for entry in clipboard.history() {
        let HistoryEntry::Write(w) = entry else {
            continue;
        };
        // Only OUR writes count as potential leaks; external writes
        // are the input scenario, by definition uncontrolled.
        if w.source != WriteSource::OurWrite {
            continue;
        }
        if !w.text.contains(canary) {
            continue;
        }
        // Our own write contains the canary. It is a leak unless it
        // matches every restore-context bar.
        let allowed =
            expected_restore_tokens.contains(&w.token) && w.hints == PrivacyHints::CONCEAL_ALL;
        assert!(
            allowed,
            "leak: canary appeared in one of our clipboard writes that is not \
             a tokenised restore-context write with CONCEAL_ALL. write = {w:?}",
        );
    }
    // Clears carry no text; subscribed events carry no text; both
    // are structurally leak-safe by trait shape. A future refactor
    // that adds text to either would need to modify the trait
    // definitions and would surface in review.
}

#[test]
fn canary_survives_no_clipboard_write_that_lacks_restore_context() {
    let canary = fresh_canary();
    let c = InMemoryClipboard::new();

    // 1. User copies the canary onto the clipboard.
    c.simulate_external_write(&canary);

    // 2. Simulated daemon-side scrub: read what the user copied,
    //    generate a fake with the same shape (test-side stand-in;
    //    the real engine picks this) and write the fake back with
    //    CONCEAL_ALL. The daemon MUST NOT write the canary.
    let got = c.read_text().unwrap().unwrap();
    assert!(got.contains(&canary), "read must see what the user copied");
    let fake = format!("fake-{}", "x".repeat(canary.len().saturating_sub(5)));
    let _scrub_token = c.write_text(&fake, PrivacyHints::CONCEAL_ALL).unwrap();

    // 3. Simulated daemon-side restore: the user explicitly asks
    //    for a restore, and the daemon writes the real value (the
    //    canary) with CONCEAL_ALL and remembers the token.
    let restore_token = c
        .write_text(&canary, PrivacyHints::CONCEAL_ALL)
        .expect("restore write");

    // 4. Auto-clear: the daemon clears via the true clear API, not
    //    via a zero-length write. The harness asserts the history
    //    entry is a Clear, not a Write.
    c.clear().unwrap();

    // 5. Assertions.
    assert_no_canary_leak(&c, &canary, &[restore_token]);

    let hist = c.history();
    // Expected shape:
    //   0. External write of the canary (SimulatedExternal)
    //   1. Scrub write of the fake (OurWrite, CONCEAL_ALL, no canary)
    //   2. Restore write of the canary (OurWrite, CONCEAL_ALL)
    //   3. Clear (marker distinct from a zero-length write)
    assert_eq!(hist.len(), 4);
    match &hist[3] {
        HistoryEntry::Clear { source, .. } => assert_eq!(*source, WriteSource::OurWrite),
        other => panic!("expected Clear marker, got {other:?}"),
    }

    // A read of the empty post-clear clipboard returns None, which
    // proves the clear wiped the canary from the state.
    assert!(c.read_text().unwrap().is_none());
}

#[test]
fn harness_records_none_hints_writes_so_a_future_audit_can_flag_them() {
    // Recording-fidelity pin. The flagging policy (a real daemon
    // that writes with PrivacyHints::NONE would be a leak channel
    // because clipboard history / cloud sync capture the write)
    // lands with the daemon in a later chunk. This test verifies
    // only that when a write with PrivacyHints::NONE happens, the
    // InMemoryClipboard records it faithfully as all-false, so a
    // future audit can query `hints.any()` and flag the write.
    let c = InMemoryClipboard::new();
    let _ = c.write_text("some-fake", PrivacyHints::NONE).unwrap();
    for entry in c.history() {
        let HistoryEntry::Write(w) = entry else {
            continue;
        };
        if w.source == WriteSource::OurWrite {
            assert!(
                !w.hints.any(),
                "the test wrote with PrivacyHints::NONE; the harness must record all-false so a future audit can distinguish this from a CONCEAL_ALL write"
            );
        }
    }
}

#[test]
fn subscribe_carries_no_clipboard_text_ever() {
    // ClipboardEvent has no text field: this test compiles the shape
    // assertion, and confirms at runtime that a callback observing
    // events cannot derive the clipboard text from the event alone.
    let c = InMemoryClipboard::new();
    let captured: Arc<Mutex<Vec<ClipboardEvent>>> = Arc::new(Mutex::new(Vec::new()));
    let captured_c = captured.clone();
    let _sub = c
        .subscribe(Arc::new(move |ev| {
            captured_c.lock().unwrap().push(ev);
        }))
        .unwrap();

    let canary = fresh_canary();
    let _ = c.write_text(&canary, PrivacyHints::CONCEAL_ALL).unwrap();
    c.simulate_external_write(&canary);
    c.clear().unwrap();

    let events = captured.lock().unwrap().clone();
    assert_eq!(events.len(), 3);
    // The event debug format must not smuggle the text in either.
    for ev in &events {
        let dbg = format!("{ev:?}");
        assert!(
            !dbg.contains(&canary),
            "ClipboardEvent debug output must not contain the clipboard text: {dbg}"
        );
    }
}
