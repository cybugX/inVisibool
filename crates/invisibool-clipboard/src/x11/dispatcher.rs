//! Subscriber dispatcher thread.
//!
//! The event-reader thread pushes `ClipboardEvent`s onto an mpsc
//! channel; this thread consumes them and invokes registered
//! subscriber callbacks. The two-thread split is what breaks the
//! deadlock class where a callback calls `read_text`: the event
//! thread that would satisfy that `read_text`'s SelectionNotify is
//! NOT the thread inside the callback, so the read completes
//! naturally.

use std::sync::mpsc;
use std::sync::Arc;

use crate::ClipboardEvent;

/// Every registered subscriber. Cloned into the dispatcher thread
/// on each event so callbacks can freely drop / register more
/// subscriptions.
pub(super) type SubscriberList = Vec<Arc<dyn Fn(ClipboardEvent) + Send + Sync>>;

/// The channel end owned by the event thread.
pub(super) struct DispatchSender {
    tx: mpsc::Sender<DispatchMessage>,
}

pub(super) struct DispatchReceiver {
    rx: mpsc::Receiver<DispatchMessage>,
}

pub(super) enum DispatchMessage {
    Event(ClipboardEvent),
    Shutdown,
}

impl DispatchSender {
    pub fn send_event(&self, ev: ClipboardEvent) {
        // Best-effort: if the dispatcher thread has already exited,
        // dropping the event is safe (we are shutting down).
        let _ = self.tx.send(DispatchMessage::Event(ev));
    }

    pub fn signal_shutdown(&self) {
        let _ = self.tx.send(DispatchMessage::Shutdown);
    }

    /// The event thread takes ownership of a clone-for-event to
    /// keep the original in mod.rs for Drop-time shutdown signalling.
    pub fn clone_for_event(&self) -> Self {
        Self {
            tx: self.tx.clone(),
        }
    }
}

pub(super) fn channel() -> (DispatchSender, DispatchReceiver) {
    let (tx, rx) = mpsc::channel();
    (DispatchSender { tx }, DispatchReceiver { rx })
}

/// The dispatcher-thread loop. Runs until it sees a `Shutdown`
/// message. Callbacks run in-line; a slow callback delays subsequent
/// events but does NOT block the event-reader thread.
pub(super) fn dispatcher_loop(
    rx: DispatchReceiver,
    subscribers_snapshot: impl Fn() -> SubscriberList + Send + 'static,
) {
    while let Ok(msg) = rx.rx.recv() {
        match msg {
            DispatchMessage::Shutdown => break,
            DispatchMessage::Event(ev) => {
                let snapshot = subscribers_snapshot();
                for cb in snapshot {
                    cb(ev.clone());
                }
            }
        }
    }
}
