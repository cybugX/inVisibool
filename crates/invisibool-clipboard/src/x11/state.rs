//! Shared state for the X11 backend, threaded across the trait
//! methods, the event-reader thread, and the dispatcher thread.
//!
//! `X11Inner` is the single Arc-shared struct. Every field is either
//! immutable-after-construction (the shared connection, our window
//! id, the atom cache) or wrapped in a `Mutex` for the fields that
//! need to change (the owned clipboard content, the subscriber list,
//! the pending-read registry, the in-flight INCR trackers).

use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Instant;

use x11rb::protocol::xproto::{Timestamp, Window};
use x11rb::rust_connection::RustConnection;
use zeroize::Zeroizing;

use crate::hints::PrivacyHints;
use crate::WriteToken;

use super::atoms::AtomTable;
use super::dispatcher::SubscriberList;
use super::pending::{IncrReceives, IncrSends, PendingReads};

/// One clipboard-writable slot's content.
pub(super) struct OwnedContent {
    pub text: Zeroizing<String>,
    /// Recorded even though X11 has no privacy-hint mechanism (row 18):
    /// tests may audit what hints were passed, and future backends
    /// with real hint support can consult this field.
    #[allow(dead_code)]
    pub hints: PrivacyHints,
    pub token: WriteToken,
    pub acquired_at: Timestamp,
    #[allow(dead_code)]
    pub set_at: Instant,
}

pub(super) struct X11Inner {
    pub conn: Arc<RustConnection>,
    pub atoms: AtomTable,
    pub our_window: Window,

    pub owned: Mutex<Option<OwnedContent>>,
    pub subscribers: Mutex<SubscriberList>,
    pub pending_reads: Mutex<PendingReads>,
    pub incr_receives: Mutex<IncrReceives>,
    pub incr_sends: Mutex<IncrSends>,
    pub next_token: AtomicU64,
    pub shutdown: AtomicBool,
    pub last_change_count: Mutex<u64>,
    /// Single-slot rendezvous for the "fetch a real server timestamp
    /// via a zero-length ChangeProperty(APPEND) + PropertyNotify"
    /// dance. `write_text` sets this to `Some(None)` (waiting), the
    /// event thread's PropertyNotify handler fills in the observed
    /// time, `write_text` reads and clears. Serialised by the outer
    /// `Mutex` so concurrent writers queue rather than race.
    pub pending_timestamp: Mutex<Option<Option<Timestamp>>>,
    pub pending_timestamp_cond: Condvar,
}

impl X11Inner {
    pub fn new_token(&self) -> WriteToken {
        let v = self
            .next_token
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        WriteToken(v)
    }

    pub fn bump_change_count(&self) -> u64 {
        let mut g = self
            .last_change_count
            .lock()
            .expect("change_count poisoned");
        *g += 1;
        *g
    }

    pub fn change_count(&self) -> u64 {
        *self
            .last_change_count
            .lock()
            .expect("change_count poisoned")
    }
}
