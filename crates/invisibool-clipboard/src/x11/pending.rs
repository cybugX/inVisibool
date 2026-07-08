//! Event-to-waiter routing for read_text, plus per-requestor
//! in-flight INCR state tracking on the owner side.
//!
//! This module is the pending-read registry the design review named.
//! A `read_text` call:
//!   1. Reserves a `PendingRead` entry keyed by our destination
//!      property atom (`INVISIBOOL_DEST` here; more atoms possible
//!      later if concurrent reads to the same target are needed).
//!   2. Sends `ConvertSelection`.
//!   3. Waits on the pending entry's condvar with a 500ms conversion
//!      timeout.
//!   4. The event-reader thread sees `SelectionNotify`, looks up
//!      the pending entry, reads the property, and either completes
//!      the entry (plain path) or promotes it into the INCR receive
//!      tracker (INCR path) which the event thread continues to
//!      feed until done.
//!
//! The dispatcher module (see `dispatcher.rs`) runs subscriber
//! callbacks on a separate thread so a callback that calls
//! `read_text` does not deadlock the event thread that would
//! deliver the SelectionNotify to that read_text call.

use std::collections::HashMap;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use x11rb::protocol::xproto::{Atom, Timestamp, Window};
use zeroize::Zeroizing;

use crate::error::ClipboardError;

/// The initial ConvertSelection round-trip must reply within this
/// bound. Missing SelectionNotify means an unresponsive owner
/// (returned as a typed timeout error, never truncation).
pub(super) const READ_CONVERSION_TIMEOUT: Duration = Duration::from_millis(500);

/// Between INCR chunks, the owner has this long to send the next
/// chunk after we delete the previous one. Missing PropertyNotify
/// past this bound returns a typed timeout error.
pub(super) const INCR_CHUNK_TIMEOUT: Duration = Duration::from_millis(500);

/// Absolute cap on the payload we will accept as read or serve as
/// write. Callers see this as a typed refusal (`ReadFailed` /
/// `WriteFailed`) in plain language, never truncation.
pub(super) const MAX_CLIPBOARD_BYTES: usize = 8 * 1024 * 1024;

/// Plain-request-safe cap. Content up to this size fits in a single
/// `ChangeProperty` on servers without BIG-REQUESTS enabled (which
/// is most X clients). Above this we switch to INCR on the owner
/// side so old readers keep working.
pub(super) const OWNER_SINGLE_SHOT_CAP: usize = 256 * 1024;

/// Per-chunk size when serving content via INCR on the owner side.
pub(super) const OWNER_INCR_CHUNK_SIZE: usize = 64 * 1024;

/// One outstanding `read_text` call. `event thread` completes this
/// by setting `result` and notifying `cond`.
pub(super) struct PendingRead {
    pub cond: Condvar,
    pub state: Mutex<PendingReadState>,
}

pub(super) enum PendingReadState {
    /// Still waiting for the initial SelectionNotify.
    Awaiting,
    /// The event thread promoted this read into INCR mode; the read
    /// call keeps waiting on the same condvar until INCR completes
    /// or fails.
    IncrInProgress,
    /// Done. `read_text` picks up `result` and returns.
    Done(Result<Option<Zeroizing<String>>, ClipboardError>),
}

impl PendingRead {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            cond: Condvar::new(),
            state: Mutex::new(PendingReadState::Awaiting),
        })
    }

    /// Complete this pending read. The next `wait` in `read_text`
    /// will observe `Done` and return.
    pub fn complete(&self, result: Result<Option<Zeroizing<String>>, ClipboardError>) {
        let mut g = self.state.lock().expect("PendingRead state poisoned");
        *g = PendingReadState::Done(result);
        drop(g);
        self.cond.notify_all();
    }

    pub fn set_incr_in_progress(&self) {
        let mut g = self.state.lock().expect("PendingRead state poisoned");
        *g = PendingReadState::IncrInProgress;
        drop(g);
        self.cond.notify_all();
    }
}

/// Registry of pending reads keyed by destination property atom.
pub(super) type PendingReads = HashMap<Atom, Arc<PendingRead>>;

/// Per-read state when receiving via INCR on the reader side. The
/// event thread accumulates chunks into `accumulated`; when the
/// zero-length terminator arrives it completes the paired
/// `PendingRead`.
pub(super) struct IncrReceive {
    pub pending: Arc<PendingRead>,
    /// Bytes accumulated so far. `Zeroizing` because the eventual
    /// text lands in a `Zeroizing<String>`, so the intermediate
    /// buffer must not leak.
    pub accumulated: Zeroizing<Vec<u8>>,
    pub last_chunk_at: std::time::Instant,
}

pub(super) type IncrReceives = HashMap<Atom, IncrReceive>;

/// Per-requestor state when SERVING content via INCR on the owner
/// side. Two clients pasting from us concurrently each get their
/// own entry keyed by (requestor window, target property atom).
pub(super) struct IncrSend {
    pub content: Arc<Zeroizing<String>>,
    pub next_offset: usize,
    #[allow(dead_code)]
    pub timestamp: Timestamp,
    pub target_property: Atom,
    pub requestor: Window,
    pub target: Atom,
    pub started_at: std::time::Instant,
}

pub(super) type IncrSends = HashMap<(Window, Atom), IncrSend>;
