//! Full Xvfb + xclip integration suite for the X11 backend.
//!
//! Each test spins up a fresh Xvfb display, points DISPLAY at it,
//! constructs an `X11Clipboard`, and cross-verifies behavior against
//! xclip - the reference X11 clipboard tool.
//!
//! # Two run modes for the tool-availability check
//!
//! - **Friendly-skip mode (default)**: if Xvfb or xclip is missing on
//!   the runner, the test prints a SKIPPING note to stderr and returns
//!   Ok. Suitable for local dev on a host without X tools.
//! - **Strict mode**: setting `INVISIBOOL_REQUIRE_X_TOOLS=1` makes any
//!   missing tool PANIC the test rather than skip it. CI's Linux test
//!   job sets this env var, and `demo/chunk24.sh`'s container mode sets
//!   it, so a runner image that ever loses xclip or Xvfb fails visibly
//!   instead of quietly passing 11 tests that verified nothing.
//!
//! Test coverage:
//!   - CLIPBOARD ownership + write + read via xclip (plain path).
//!   - xclip owns 1 MiB via INCR; our reader gets all 1 MiB (proves
//!     the INCR reader implementation).
//!   - xclip owns 10 MiB (over cap); our reader returns a typed
//!     ReadFailed error with plain-language message; NEVER returns
//!     a truncated Ok.
//!   - Our write of 1 MiB via INCR is read byte-exact by xclip.
//!   - clear() disowns the CLIPBOARD selection; xclip -o returns empty.
//!   - subscribe() fires on external xclip writes; our own writes
//!     carry the WriteToken; xclip's writes have matches_our_write=None.
//!   - Subscription drop stops further callbacks.
//!   - Callback that calls read_text() completes rather than
//!     deadlocking (the dispatcher-vs-event-thread regression).
//!   - TIMESTAMP conversion returns our acquisition timestamp.
//!   - TARGETS lists UTF8_STRING, STRING, TARGETS, TIMESTAMP - not TEXT.

#![cfg(target_os = "linux")]

use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use invisibool_clipboard::{Clipboard, ClipboardError, ClipboardEvent, PrivacyHints, X11Clipboard};

fn xvfb_available() -> bool {
    which("Xvfb").is_some()
}

fn xclip_available() -> bool {
    which("xclip").is_some()
}

fn which(cmd: &str) -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let p = dir.join(cmd);
        if p.is_file() {
            return Some(p);
        }
    }
    None
}

macro_rules! skip_if_no_x_tools {
    () => {
        if !xvfb_available() || !xclip_available() {
            let msg = format!(
                "X11 tools missing: Xvfb present={}, xclip present={}",
                xvfb_available(),
                xclip_available(),
            );
            if std::env::var("INVISIBOOL_REQUIRE_X_TOOLS").as_deref() == Ok("1") {
                panic!(
                    "{msg}: INVISIBOOL_REQUIRE_X_TOOLS=1 required these tools \
                     to be present; skipping silently would let the runner \
                     image drift out of coverage without anyone noticing",
                );
            }
            eprintln!("SKIPPING: {msg}");
            return;
        }
    };
}

/// A private Xvfb session. Chooses a random display number to avoid
/// collisions between concurrent tests. The Xvfb child is killed on
/// drop.
struct XvfbSession {
    display_num: u32,
    child: Option<Child>,
}

impl XvfbSession {
    fn spawn() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(200);
        let n = NEXT.fetch_add(1, Ordering::SeqCst) as u32;
        let child = Command::new("Xvfb")
            .arg(format!(":{n}"))
            .args(["-screen", "0", "640x480x8", "-nolisten", "tcp"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("Xvfb spawn");
        // Wait for socket to come up.
        let socket = format!("/tmp/.X11-unix/X{n}");
        for _ in 0..50 {
            if std::path::Path::new(&socket).exists() {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        Self {
            display_num: n,
            child: Some(child),
        }
    }

    fn display(&self) -> String {
        format!(":{}", self.display_num)
    }
}

impl Drop for XvfbSession {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// Serialises DISPLAY-mutating tests. Env vars are process-global, so
/// concurrent tests each spawning their own Xvfb race on `set_var`.
/// Locking here is simpler than adopting cargo-test-serial and
/// preserves the "each test owns its Xvfb" test-isolation story.
static DISPLAY_LOCK: Mutex<()> = Mutex::new(());

fn with_display<F: FnOnce()>(session: &XvfbSession, f: F) {
    let _guard = DISPLAY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let prev = std::env::var_os("DISPLAY");
    std::env::set_var("DISPLAY", session.display());
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
    match prev {
        Some(v) => std::env::set_var("DISPLAY", v),
        None => std::env::remove_var("DISPLAY"),
    }
    if let Err(e) = result {
        std::panic::resume_unwind(e);
    }
}

#[must_use = "the returned Child owns the CLIPBOARD selection until dropped; keep it alive"]
fn xclip_owns(session: &XvfbSession, payload: &[u8]) -> XclipOwner {
    let mut child = Command::new("xclip")
        .args(["-selection", "clipboard", "-i"])
        .env("DISPLAY", session.display())
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("xclip -i spawn");
    child
        .stdin
        .as_mut()
        .expect("xclip stdin")
        .write_all_impl(payload);
    // Close stdin so xclip claims ownership.
    drop(child.stdin.take());
    // xclip needs a moment to actually own the selection.
    std::thread::sleep(Duration::from_millis(200));
    XclipOwner { child: Some(child) }
}

/// Wraps the xclip child so Drop kills + waits it, avoiding zombies.
struct XclipOwner {
    child: Option<Child>,
}

impl Drop for XclipOwner {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn xclip_read(session: &XvfbSession) -> Vec<u8> {
    let out = Command::new("xclip")
        .args(["-selection", "clipboard", "-o"])
        .env("DISPLAY", session.display())
        .stderr(Stdio::null())
        .output()
        .expect("xclip -o");
    out.stdout
}

// Local trait to keep the write_all call chain readable.
trait ChildStdinExt {
    fn write_all_impl(&mut self, buf: &[u8]);
}
impl ChildStdinExt for std::process::ChildStdin {
    fn write_all_impl(&mut self, buf: &[u8]) {
        use std::io::Write;
        self.write_all(buf).expect("xclip stdin write");
    }
}

// ---------------- tests ----------------

#[test]
fn write_short_text_and_xclip_reads_it_back_exact() {
    skip_if_no_x_tools!();
    let sess = XvfbSession::spawn();
    with_display(&sess, || {
        let c = X11Clipboard::new().expect("open backend");
        let _tok = c
            .write_text("hello-x11", PrivacyHints::CONCEAL_ALL)
            .unwrap();
        // Allow selection ownership to propagate.
        std::thread::sleep(Duration::from_millis(100));
        let bytes = xclip_read(&sess);
        assert_eq!(bytes, b"hello-x11");
    });
}

#[test]
fn xclip_owns_65k_and_our_reader_gets_all_of_it_plain_path() {
    skip_if_no_x_tools!();
    let sess = XvfbSession::spawn();
    with_display(&sess, || {
        let payload = vec![b'X'; 65_536];
        let _xclip = xclip_owns(&sess, &payload);
        let c = X11Clipboard::new().expect("open backend");
        let got = c.read_text().expect("read").expect("some text");
        assert_eq!(got.len(), payload.len());
        assert!(got.chars().all(|ch| ch == 'X'));
    });
}

#[test]
fn xclip_owns_1mib_and_our_reader_walks_incr_end_to_end() {
    skip_if_no_x_tools!();
    let sess = XvfbSession::spawn();
    with_display(&sess, || {
        let payload = vec![b'A'; 1024 * 1024];
        let _xclip = xclip_owns(&sess, &payload);
        let c = X11Clipboard::new().expect("open backend");
        let got = c.read_text().expect("read").expect("some text");
        // This is the empirical break point from the design review's
        // INCR probe: xclip serves via INCR at this size, so the read
        // works ONLY if our INCR receiver is correct.
        assert_eq!(got.len(), payload.len());
    });
}

#[test]
fn xclip_owns_10mib_over_cap_our_reader_returns_typed_error_not_truncation() {
    skip_if_no_x_tools!();
    let sess = XvfbSession::spawn();
    with_display(&sess, || {
        let payload = vec![b'B'; 10 * 1024 * 1024];
        let _xclip = xclip_owns(&sess, &payload);
        let c = X11Clipboard::new().expect("open backend");
        let err = c.read_text().unwrap_err();
        match err {
            ClipboardError::ReadFailed(msg) => {
                assert!(
                    msg.contains("8 MiB limit"),
                    "expected plain-language 8 MiB limit message, got: {msg}"
                );
                // Must not have returned any bytes.
            }
            other => panic!("expected ReadFailed, got {other:?}"),
        }
    });
}

#[test]
fn our_write_of_1mib_is_read_back_by_xclip_end_to_end() {
    skip_if_no_x_tools!();
    let sess = XvfbSession::spawn();
    with_display(&sess, || {
        let payload: String = "A".repeat(1024 * 1024);
        let c = X11Clipboard::new().expect("open backend");
        let _tok = c.write_text(&payload, PrivacyHints::CONCEAL_ALL).unwrap();
        // Give the event thread a moment to answer the incoming
        // SelectionRequest via INCR.
        std::thread::sleep(Duration::from_millis(200));
        let bytes = xclip_read(&sess);
        assert_eq!(bytes.len(), payload.len());
    });
}

#[test]
fn clear_disowns_selection_and_xclip_o_returns_empty() {
    skip_if_no_x_tools!();
    let sess = XvfbSession::spawn();
    with_display(&sess, || {
        let c = X11Clipboard::new().expect("open backend");
        c.write_text("owned", PrivacyHints::CONCEAL_ALL).unwrap();
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(xclip_read(&sess), b"owned");
        c.clear().unwrap();
        std::thread::sleep(Duration::from_millis(100));
        assert!(xclip_read(&sess).is_empty());
    });
}

#[test]
fn subscribe_fires_on_external_write_and_marks_our_writes() {
    skip_if_no_x_tools!();
    let sess = XvfbSession::spawn();
    with_display(&sess, || {
        let c = X11Clipboard::new().expect("open backend");
        let events: Arc<Mutex<Vec<ClipboardEvent>>> = Arc::new(Mutex::new(Vec::new()));
        let events_c = events.clone();
        let _sub = c
            .subscribe(Arc::new(move |ev| events_c.lock().unwrap().push(ev)))
            .unwrap();

        // Our own write.
        let token = c
            .write_text("ours", PrivacyHints::CONCEAL_ALL)
            .expect("write");

        // External write via xclip.
        let _x1 = xclip_owns(&sess, b"external");

        // Allow XFixes SelectionNotify events to flow.
        std::thread::sleep(Duration::from_millis(500));

        let evs = events.lock().unwrap().clone();
        assert!(
            evs.len() >= 2,
            "expected at least 2 events, got {}",
            evs.len()
        );
        assert!(
            evs.iter().any(|e| e.matches_our_write == Some(token)),
            "expected one event with our WriteToken",
        );
        assert!(
            evs.iter().any(|e| e.matches_our_write.is_none()),
            "expected one event from external xclip write",
        );
    });
}

#[test]
fn dropped_subscription_stops_further_callbacks() {
    skip_if_no_x_tools!();
    let sess = XvfbSession::spawn();
    with_display(&sess, || {
        let c = X11Clipboard::new().expect("open backend");
        let hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let hits_c = hits.clone();
        let sub = c
            .subscribe(Arc::new(move |_| {
                hits_c.fetch_add(1, Ordering::SeqCst);
            }))
            .unwrap();
        c.write_text("before", PrivacyHints::CONCEAL_ALL).unwrap();
        std::thread::sleep(Duration::from_millis(200));
        let before = hits.load(Ordering::SeqCst);
        drop(sub);
        c.write_text("after", PrivacyHints::CONCEAL_ALL).unwrap();
        std::thread::sleep(Duration::from_millis(200));
        let after = hits.load(Ordering::SeqCst);
        assert_eq!(
            after, before,
            "subscription drop should stop callbacks; before={before} after={after}"
        );
    });
}

/// Regression: a subscriber callback that calls `read_text` must
/// complete rather than deadlocking. Proves the dispatcher thread
/// is truly independent of the event-reader thread.
#[test]
fn subscribe_callback_may_call_read_text_without_deadlock() {
    skip_if_no_x_tools!();
    let sess = XvfbSession::spawn();
    with_display(&sess, || {
        let c = Arc::new(X11Clipboard::new().expect("open backend"));
        let c_cb = c.clone();
        let completed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let completed_c = completed.clone();

        let _sub = c
            .subscribe(Arc::new(move |_ev| {
                // The critical proof is that read_text COMPLETES
                // (returns without deadlock) from inside the
                // callback. What content it sees is a race against
                // whichever writer most recently took the selection;
                // the deadlock-vs-liveness question is orthogonal.
                let got = c_cb
                    .read_text()
                    .expect("callback read_text completed without deadlock");
                // Also assert the read produced content (not None) -
                // proving it saw some external write's payload.
                assert!(got.is_some(), "callback read_text returned None");
                completed_c.store(true, Ordering::SeqCst);
            }))
            .unwrap();

        // Fire an XFixes event by having xclip take ownership.
        // The callback runs on the dispatcher thread and calls
        // read_text; if the read completes we know the dispatcher
        // and event threads are truly independent.
        let _x1 = xclip_owns(&sess, b"triggering-external-write");

        // Allow the dispatcher to run and the read to complete.
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while std::time::Instant::now() < deadline {
            if completed.load(Ordering::SeqCst) {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(
            completed.load(Ordering::SeqCst),
            "callback did not complete - dispatcher/event thread deadlock"
        );
    });
}

#[test]
fn timestamp_target_returns_real_non_zero_server_timestamp() {
    skip_if_no_x_tools!();
    let sess = XvfbSession::spawn();
    with_display(&sess, || {
        let c = X11Clipboard::new().expect("open backend");
        c.write_text("owned", PrivacyHints::CONCEAL_ALL).unwrap();
        std::thread::sleep(Duration::from_millis(100));
        // xclip -t TIMESTAMP prints the timestamp as a decimal integer.
        let out = Command::new("xclip")
            .args(["-selection", "clipboard", "-o", "-t", "TIMESTAMP"])
            .env("DISPLAY", sess.display())
            .stderr(Stdio::null())
            .output()
            .expect("xclip TIMESTAMP");
        let s = String::from_utf8_lossy(&out.stdout);
        let trimmed = s.trim();
        // Must be a non-empty parseable non-zero integer. Zero is
        // the CURRENT_TIME sentinel we deliberately avoid by
        // fetching a real server timestamp via a PropertyNotify
        // before SetSelectionOwner. A test that accepted zero
        // would let a regression to CURRENT_TIME slip through.
        assert!(
            !trimmed.is_empty(),
            "xclip TIMESTAMP produced no output; our SetSelectionOwner did not carry a real timestamp"
        );
        let parsed: u64 = trimmed
            .parse()
            .unwrap_or_else(|_| panic!("xclip TIMESTAMP did not parse as decimal: {trimmed:?}"));
        assert!(
            parsed != 0,
            "TIMESTAMP was 0 (the CURRENT_TIME sentinel); we should have fetched a real server time"
        );
    });
}

#[test]
fn targets_advertises_only_supported_targets_not_text() {
    skip_if_no_x_tools!();
    let sess = XvfbSession::spawn();
    with_display(&sess, || {
        let c = X11Clipboard::new().expect("open backend");
        c.write_text("owned", PrivacyHints::CONCEAL_ALL).unwrap();
        std::thread::sleep(Duration::from_millis(100));
        let out = Command::new("xclip")
            .args(["-selection", "clipboard", "-o", "-t", "TARGETS"])
            .env("DISPLAY", sess.display())
            .stderr(Stdio::null())
            .output()
            .expect("xclip TARGETS");
        let s = String::from_utf8_lossy(&out.stdout);
        assert!(
            s.contains("UTF8_STRING"),
            "TARGETS must include UTF8_STRING"
        );
        assert!(s.contains("TARGETS"), "TARGETS must include TARGETS");
        assert!(s.contains("TIMESTAMP"), "TARGETS must include TIMESTAMP");
        assert!(
            !s.contains("\nTEXT\n") && !s.starts_with("TEXT\n") && !s.ends_with("\nTEXT"),
            "TARGETS must NOT include TEXT (design choice: drop it since we do not answer target=TEXT); got: {s:?}",
        );
    });
}
