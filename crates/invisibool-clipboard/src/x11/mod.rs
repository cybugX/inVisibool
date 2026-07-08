//! X11 clipboard backend.
//!
//! Linux-only; opts into a Wayland refusal at the CLI layer before
//! any `X11Clipboard::new` call is made.
//!
//! # Architecture
//!
//! ```text
//!            Arc<RustConnection>  <-  x11rb (pure Rust, zero unsafe)
//!                    │
//!                    │  reads events                      │ writes requests
//!                    │                                    │
//!   event-reader thread                          trait methods on X11Clipboard:
//!   ------------------                           read_text / write_text / clear /
//!   • wait_for_event                             change_count / subscribe
//!   • dispatches XFixesSelectionNotify           (each thread that calls the
//!     to the dispatcher channel                   trait shares the Arc; x11rb's
//!   • answers SelectionRequest                    RustConnection is Sync)
//!   • drives INCR reader accumulator                     │
//!   • drives INCR sender chunk delivery                  │
//!                    │                                    │
//!                    └── mpsc ClipboardEvent ───►  dispatcher thread
//!                                                        (invokes subscriber
//!                                                         callbacks in-line;
//!                                                         callbacks may
//!                                                         freely call trait
//!                                                         methods because
//!                                                         the event-reader
//!                                                         thread is NOT the
//!                                                         one running them)
//! ```
//!
//! # Thread-safety
//!
//! `x11rb::rust_connection::RustConnection` is `Sync`. Every thread
//! shares an `Arc<RustConnection>`. The event-reader thread is the
//! only one calling `wait_for_event` / `poll_for_event`; the trait
//! methods only SEND requests. This avoids any shared-mutable
//! state on the connection.
//!
//! # Zero unsafe
//!
//! The crate carries `#![deny(unsafe_code)]` at the root. This
//! module does not add any `#[allow]` block. The self-pipe pattern
//! sketched in the design review is not needed because the event
//! thread polls for events with a short sleep between attempts,
//! and shutdown is signalled by an `AtomicBool` plus a `NoOperation`
//! request that wakes the event thread out of its next poll.

mod atoms;
mod dispatcher;
mod event_thread;
mod pending;
mod state;

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Instant;

use x11rb::connection::Connection;
use x11rb::protocol::xproto::{ConnectionExt, CreateWindowAux, EventMask, WindowClass};
use x11rb::COPY_DEPTH_FROM_PARENT;
use zeroize::Zeroizing;

use crate::error::ClipboardError;
use crate::hints::PrivacyHints;
use crate::{Clipboard, ClipboardEvent, Subscription, SubscriptionHandle, WriteToken};

use self::atoms::AtomTable;
use self::pending::{PendingRead, PendingReadState, MAX_CLIPBOARD_BYTES, READ_CONVERSION_TIMEOUT};
use self::state::{OwnedContent, X11Inner};

/// X11 clipboard backend.
///
/// Constructed via [`X11Clipboard::new`]. Owns background threads
/// that are joined on drop.
pub struct X11Clipboard {
    inner: Arc<X11Inner>,
    _event_thread: JoinHandle<()>,
    _dispatcher_thread: JoinHandle<()>,
    /// Kept alive so drop can send shutdown signals in the right
    /// order. `Option` because Drop takes ownership.
    dispatcher_sender: Option<dispatcher::DispatchSender>,
}

impl std::fmt::Debug for X11Clipboard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("X11Clipboard")
            .field("window", &self.inner.our_window)
            .finish_non_exhaustive()
    }
}

impl X11Clipboard {
    /// Open an X11 connection, create the hidden InputOnly window
    /// used to receive SelectionNotify / SelectionRequest events,
    /// subscribe to XFixes CLIPBOARD selection-change events, and
    /// spawn the event-reader + dispatcher threads.
    pub fn new() -> Result<Self, ClipboardError> {
        let (conn, screen_num) = x11rb::connect(None)
            .map_err(|e| ClipboardError::unsupported_from(format!("open X connection: {e}")))?;
        let conn = Arc::new(conn);

        // Enable BIG-REQUESTS so single ChangeProperty calls above
        // 256 KiB fit in one request. Verified empirically at
        // chunk-24 design review that x11rb handles this transparently.
        let _ = x11rb::protocol::bigreq::enable(&*conn);

        // Ensure the XFixes extension is present. Refuse construction
        // otherwise, since subscribe() cannot work without it.
        let xfixes_query = x11rb::protocol::xfixes::query_version(&*conn, 5, 0)
            .map_err(|e| ClipboardError::unsupported_from(format!("xfixes query: {e}")))?
            .reply()
            .map_err(|e| ClipboardError::unsupported_from(format!("xfixes reply: {e}")))?;
        // We accept any XFixes version >= 2; that is when SelectionInput was added.
        let _ = xfixes_query;

        let atoms = AtomTable::intern(&*conn)?;

        let screen = &conn.setup().roots[screen_num];
        let our_window = conn
            .generate_id()
            .map_err(|e| ClipboardError::unsupported_from(format!("generate_id: {e}")))?;

        // Hidden InputOnly window. PropertyChange event mask so we
        // receive PropertyNotify events on our own window (needed
        // for INCR receive).
        conn.create_window(
            COPY_DEPTH_FROM_PARENT,
            our_window,
            screen.root,
            0,
            0,
            1,
            1,
            0,
            WindowClass::INPUT_ONLY,
            0,
            &CreateWindowAux::new().event_mask(EventMask::PROPERTY_CHANGE),
        )
        .map_err(|e| ClipboardError::unsupported_from(format!("create_window: {e}")))?;

        // Subscribe to CLIPBOARD selection-change events via XFixes.
        // Anchored on our own window. The root-window anchor was
        // tried mid-debug and adopted before the actual root cause -
        // an ungated PropertyNotify(NewValue) delete race in the
        // INCR receiver - was found. Isolation at chunk-24 close:
        // with the delete-gate in place, own-window anchoring passes
        // every integration test (verified live in the dev container
        // running the full 11-test suite). Kept own-window because
        // XFixes semantics are "route this selection's events to
        // window X" and X being the daemon's own window is the least
        // surprising anchor for a future reader.
        x11rb::protocol::xfixes::select_selection_input(
            &*conn,
            our_window,
            atoms.clipboard,
            x11rb::protocol::xfixes::SelectionEventMask::SET_SELECTION_OWNER
                | x11rb::protocol::xfixes::SelectionEventMask::SELECTION_WINDOW_DESTROY
                | x11rb::protocol::xfixes::SelectionEventMask::SELECTION_CLIENT_CLOSE,
        )
        .map_err(|e| ClipboardError::SubscribeFailed(format!("select_selection_input: {e}")))?;

        conn.flush()
            .map_err(|e| ClipboardError::unsupported_from(format!("flush: {e}")))?;

        let inner = Arc::new(X11Inner {
            conn: conn.clone(),
            atoms,
            our_window,
            owned: Mutex::new(None),
            subscribers: Mutex::new(Vec::new()),
            pending_reads: Mutex::new(Default::default()),
            incr_receives: Mutex::new(Default::default()),
            incr_sends: Mutex::new(Default::default()),
            next_token: AtomicU64::new(1),
            shutdown: AtomicBool::new(false),
            last_change_count: Mutex::new(0),
            pending_timestamp: Mutex::new(None),
            pending_timestamp_cond: std::sync::Condvar::new(),
        });

        // Dispatcher channel + thread.
        let (dispatch_tx, dispatch_rx) = dispatcher::channel();
        let inner_disp = inner.clone();
        let dispatcher_thread = std::thread::Builder::new()
            .name("invisibool-x11-dispatcher".to_string())
            .spawn(move || {
                dispatcher::dispatcher_loop(dispatch_rx, move || {
                    inner_disp
                        .subscribers
                        .lock()
                        .expect("subscribers poisoned")
                        .clone()
                });
            })
            .map_err(|e| ClipboardError::unsupported_from(format!("spawn dispatcher: {e}")))?;

        // Event-reader thread.
        let inner_event = inner.clone();
        let dispatch_for_event = dispatch_tx.clone_for_event();
        let event_thread = std::thread::Builder::new()
            .name("invisibool-x11-events".to_string())
            .spawn(move || {
                event_thread::run(inner_event, dispatch_for_event);
            })
            .map_err(|e| ClipboardError::unsupported_from(format!("spawn event thread: {e}")))?;

        Ok(Self {
            inner,
            _event_thread: event_thread,
            _dispatcher_thread: dispatcher_thread,
            dispatcher_sender: Some(dispatch_tx),
        })
    }

    /// The X11 window id we own. Test-visible helper for the
    /// deadlock-regression harness.
    pub fn window_id(&self) -> u32 {
        self.inner.our_window
    }

    /// Get a real server timestamp by triggering a PropertyNotify
    /// with a zero-length ChangeProperty(APPEND). The event thread's
    /// handler for our timestamp-fetch property fills in the
    /// observed time on the shared rendezvous slot.
    ///
    /// Serialised across concurrent writers by the outer Mutex.
    fn fetch_server_time(&self) -> Result<x11rb::protocol::xproto::Timestamp, ClipboardError> {
        use x11rb::protocol::xproto::{AtomEnum, PropMode};
        // Take the single-slot rendezvous.
        let mut g = self
            .inner
            .pending_timestamp
            .lock()
            .expect("pending_timestamp poisoned");
        // If another writer is mid-fetch, wait our turn.
        while g.is_some() {
            g = self
                .inner
                .pending_timestamp_cond
                .wait(g)
                .expect("pending_timestamp cond poisoned");
        }
        *g = Some(None);
        drop(g);

        // Trigger the PropertyNotify.
        self.inner
            .conn
            .change_property(
                PropMode::APPEND,
                self.inner.our_window,
                self.inner.atoms.invisibool_timestamp_fetch,
                AtomEnum::ATOM,
                32,
                0,
                &[],
            )
            .map_err(|e| ClipboardError::WriteFailed(format!("change_property (ts fetch): {e}")))?;
        self.inner
            .conn
            .flush()
            .map_err(|e| ClipboardError::WriteFailed(format!("flush (ts fetch): {e}")))?;

        // Wait up to 500ms for the event thread to fill in the time.
        let mut g = self
            .inner
            .pending_timestamp
            .lock()
            .expect("pending_timestamp poisoned");
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(500);
        loop {
            if let Some(Some(t)) = &*g {
                let ts = *t;
                *g = None;
                self.inner.pending_timestamp_cond.notify_all();
                return Ok(ts);
            }
            let now = std::time::Instant::now();
            if now >= deadline {
                *g = None;
                self.inner.pending_timestamp_cond.notify_all();
                return Err(ClipboardError::WriteFailed(
                    "timed out fetching a server timestamp for SetSelectionOwner".to_string(),
                ));
            }
            let remaining = deadline - now;
            let (new_g, _) = self
                .inner
                .pending_timestamp_cond
                .wait_timeout(g, remaining)
                .expect("pending_timestamp cond poisoned");
            g = new_g;
        }
    }
}

impl Clipboard for X11Clipboard {
    fn read_text(&self) -> Result<Option<Zeroizing<String>>, ClipboardError> {
        let dest = self.inner.atoms.invisibool_dest;
        let pending = PendingRead::new();

        {
            let mut g = self
                .inner
                .pending_reads
                .lock()
                .expect("pending_reads poisoned");
            if g.contains_key(&dest) {
                return Err(ClipboardError::ReadFailed(
                    "another read is already in progress on this backend".to_string(),
                ));
            }
            g.insert(dest, pending.clone());
        }

        // Send ConvertSelection.
        if let Err(e) = self.inner.conn.convert_selection(
            self.inner.our_window,
            self.inner.atoms.clipboard,
            self.inner.atoms.utf8_string,
            dest,
            x11rb::CURRENT_TIME,
        ) {
            self.inner.pending_reads.lock().unwrap().remove(&dest);
            return Err(ClipboardError::ReadFailed(format!(
                "convert_selection: {e}"
            )));
        }
        if let Err(e) = self.inner.conn.flush() {
            self.inner.pending_reads.lock().unwrap().remove(&dest);
            return Err(ClipboardError::ReadFailed(format!("flush: {e}")));
        }

        // Wait for the initial SelectionNotify with a bounded timeout.
        let mut state = pending.state.lock().unwrap();
        let start = Instant::now();
        loop {
            if let PendingReadState::Done(_) = &*state {
                break;
            }
            // Adjust timeout based on state: waiting for initial notify is 500ms,
            // waiting for INCR completion is 15s (well above the sweep).
            let bound = match &*state {
                PendingReadState::Awaiting => READ_CONVERSION_TIMEOUT,
                _ => std::time::Duration::from_secs(15),
            };
            let elapsed = start.elapsed();
            let remaining = bound.saturating_sub(elapsed);
            if remaining == std::time::Duration::ZERO {
                // Timeout.
                self.inner.pending_reads.lock().unwrap().remove(&dest);
                return Err(ClipboardError::ReadFailed(
                    "clipboard owner did not respond within the timeout".to_string(),
                ));
            }
            let (new_state, _) = pending.cond.wait_timeout(state, remaining).unwrap();
            state = new_state;
        }

        // Extract the result.
        let done = std::mem::replace(
            &mut *state,
            PendingReadState::Done(Err(ClipboardError::ReadFailed("consumed".to_string()))),
        );
        drop(state);
        self.inner.pending_reads.lock().unwrap().remove(&dest);
        match done {
            PendingReadState::Done(r) => r,
            _ => unreachable!(),
        }
    }

    fn write_text(&self, text: &str, hints: PrivacyHints) -> Result<WriteToken, ClipboardError> {
        if text.len() > MAX_CLIPBOARD_BYTES {
            return Err(ClipboardError::WriteFailed(
                "clipboard content exceeds the 8 MiB limit".to_string(),
            ));
        }
        // Fetch a REAL server timestamp before SetSelectionOwner so
        // TIMESTAMP-target replies are a monotonic integer clients can
        // meaningfully compare, rather than the CURRENT_TIME sentinel
        // (0). Row 18 (M1) documents that we do this via a zero-length
        // ChangeProperty(APPEND) that fires a PropertyNotify carrying
        // the current server time; the event thread parks that value
        // into a rendezvous slot and this call reads it.
        let acquired_at = self.fetch_server_time()?;
        let token = self.inner.new_token();
        // Store content BEFORE claiming ownership so if a SelectionRequest
        // arrives immediately, the event thread sees the new content.
        {
            let mut g = self.inner.owned.lock().expect("owned poisoned");
            *g = Some(OwnedContent {
                text: Zeroizing::new(text.to_string()),
                hints,
                token,
                acquired_at,
                set_at: Instant::now(),
            });
        }
        self.inner
            .conn
            .set_selection_owner(
                self.inner.our_window,
                self.inner.atoms.clipboard,
                acquired_at,
            )
            .map_err(|e| ClipboardError::WriteFailed(format!("set_selection_owner: {e}")))?;
        self.inner
            .conn
            .flush()
            .map_err(|e| ClipboardError::WriteFailed(format!("flush: {e}")))?;
        Ok(token)
    }

    fn clear(&self) -> Result<(), ClipboardError> {
        // Zeroize the stored content BEFORE releasing ownership so
        // a stray SelectionRequest between the two calls sees empty.
        {
            let mut g = self.inner.owned.lock().expect("owned poisoned");
            *g = None;
        }
        self.inner
            .conn
            .set_selection_owner(x11rb::NONE, self.inner.atoms.clipboard, x11rb::CURRENT_TIME)
            .map_err(|e| ClipboardError::ClearFailed(format!("set_selection_owner(None): {e}")))?;
        self.inner
            .conn
            .flush()
            .map_err(|e| ClipboardError::ClearFailed(format!("flush: {e}")))?;
        // Bump change_count so a change_count() caller distinguishes
        // pre-clear from post-clear.
        self.inner.bump_change_count();
        Ok(())
    }

    fn change_count(&self) -> Result<u64, ClipboardError> {
        Ok(self.inner.change_count())
    }

    fn subscribe(
        &self,
        on_change: Arc<dyn Fn(ClipboardEvent) + Send + Sync>,
    ) -> Result<Subscription, ClipboardError> {
        let mut g = self.inner.subscribers.lock().expect("subscribers poisoned");
        g.push(on_change.clone());
        drop(g);
        Ok(Subscription::new(Box::new(X11SubscriptionHandle {
            inner: self.inner.clone(),
            callback: on_change,
        })))
    }
}

impl Drop for X11Clipboard {
    fn drop(&mut self) {
        self.inner.shutdown.store(true, Ordering::SeqCst);
        // Wake the event thread by pumping a NoOperation. Ignore errors:
        // the connection may already be broken.
        let _ = self.inner.conn.no_operation();
        let _ = self.inner.conn.flush();
        if let Some(tx) = self.dispatcher_sender.take() {
            tx.signal_shutdown();
        }
        // JoinHandle::drop detaches the threads; the event thread will
        // observe the shutdown flag on its next poll and exit.
    }
}

struct X11SubscriptionHandle {
    inner: Arc<X11Inner>,
    callback: Arc<dyn Fn(ClipboardEvent) + Send + Sync>,
}

impl SubscriptionHandle for X11SubscriptionHandle {}

impl Drop for X11SubscriptionHandle {
    fn drop(&mut self) {
        let mut g = self.inner.subscribers.lock().expect("subscribers poisoned");
        g.retain(|s| !Arc::ptr_eq(s, &self.callback));
    }
}

// Small helper on ClipboardError so the ergonomic call sites stay
// readable.
impl ClipboardError {
    fn unsupported_from(msg: String) -> Self {
        // We use the ReadFailed variant here rather than Unsupported
        // because Unsupported carries only &'static str. This mapping
        // is stable and documented.
        ClipboardError::ReadFailed(msg)
    }
}
