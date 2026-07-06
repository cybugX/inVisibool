//! Invisibool clipboard trait, privacy hints, in-memory test backend,
//! and display-server detection.
//!
//! # Scope of this crate at the current landing
//!
//! - The `Clipboard` trait, its supporting types, and the required
//!   contract for read / write / clear / change-count / subscribe.
//! - `PrivacyHints`: a struct of four bools with two named constants
//!   (`CONCEAL_ALL` and `NONE`). Deliberately has NO `Default` impl:
//!   all-false is the unsafe posture, not a safe default, and every
//!   call site must make a visible choice.
//! - `InMemoryClipboard`: a full trait implementation used by tests
//!   and by the leak harness. Its history-inspection surface (writes,
//!   clears, reads) is public so tests can assert what the daemon
//!   wrote and with which hints.
//! - `detect_display_server()`: env-var-only Linux resolver that
//!   returns `Wayland` / `X11` / `Headless`; non-Linux platforms
//!   return `NativeDesktop`. Used by the `watch` subcommand to refuse
//!   on Wayland and Headless with a clear message before any daemon
//!   setup runs.
//!
//! # NOT in this landing
//!
//! - The Windows, macOS, and X11 backends. They land in later chunks
//!   against the same trait. Each backend takes narrowly-scoped
//!   `unsafe` for its platform syscalls; this crate itself is
//!   `#![deny(unsafe_code)]` at the root.
//! - The `watch` daemon itself (clipboard listener loop, session-map
//!   integration, self-write suppression, content-checked auto-clear,
//!   visible-indication printing). This crate ships the primitives
//!   the daemon will compose.
//! - A per-platform first-run clipboard-environment warning. Lands
//!   as a defaulted trait method (`platform_warning`) with the first
//!   backend that has something to warn about, so the addition is
//!   non-reshaping.

#![deny(unsafe_code)]

pub mod display_server;
pub mod error;
pub mod hints;
pub mod in_memory;

pub use display_server::{detect_display_server, detect_display_server_from, DisplayServer};
pub use error::ClipboardError;
pub use hints::PrivacyHints;
pub use in_memory::{HistoryEntry, InMemoryClipboard, InMemoryRead, InMemoryWrite, WriteSource};

use std::sync::Arc;

/// A read-write handle to some platform's clipboard.
///
/// Contracts
/// ---------
///
/// - `read_text` returns `Zeroizing<String>`: every text value read
///   from the clipboard is potentially a real secret, and the trait
///   boundary is born wipe-on-drop so the caller gets a wrapper that
///   scrubs its buffer at drop time. Callers who need a plain
///   `String` for downstream use accept the leak of that copy
///   deliberately.
///
/// - `write_text` takes `PrivacyHints` as a **required** parameter.
///   There is no default impl on `PrivacyHints` so a caller cannot
///   write without making a visible choice. `PrivacyHints::CONCEAL_ALL`
///   is the safe posture for daemon writes; `PrivacyHints::NONE` is
///   reserved for writes the caller has decided are public.
///
/// - `clear` invokes the platform's true clear mechanism
///   (`EmptyClipboard` on Windows, `clearContents` on macOS, X11
///   selection ownership relinquishment). It must NOT be emulated by
///   `write_text("", ...)` on the real backends: on X11 an empty
///   write itself lands a clipboard-manager entry, which defeats the
///   auto-clear this method exists to serve. `InMemoryClipboard`
///   models the distinction by recording `HistoryEntry::Clear` in
///   the history rather than a zero-length write.
///
/// - `subscribe` delivers `ClipboardEvent` values that carry NO
///   clipboard text. This is a NOTIFICATION channel: the callback
///   sees a `change_count` and (when we can tell) a `WriteToken`
///   identifying the write as our own. Callers that want to know
///   WHAT changed call `read_text` on the event; that read is
///   inherently racy with subsequent writes and this cannot be
///   closed inside the trait because every platform clipboard API
///   has the same race window. The daemon layer above the trait
///   handles the race by comparing what it reads to what it last
///   wrote before acting.
///
/// - `Subscription`'s `Drop` cancels the subscription. Backends
///   MAY fire the callback once after Drop begins but before it
///   completes (a race between the platform event thread and Drop's
///   teardown). Callback implementations must be safe with respect
///   to that possibility, typically by guarding shared state with
///   `Arc<Mutex<...>>`.
pub trait Clipboard: Send + Sync {
    /// Read the current text on the clipboard.
    ///
    /// Returns `Ok(Some(text))` when the clipboard holds text,
    /// `Ok(None)` when it holds non-text content (an image, empty),
    /// and `Err` on platform failure.
    fn read_text(&self) -> Result<Option<zeroize::Zeroizing<String>>, ClipboardError>;

    /// Write `text` to the clipboard with the given hints.
    fn write_text(&self, text: &str, hints: PrivacyHints) -> Result<WriteToken, ClipboardError>;

    /// Clear the clipboard via the platform's true clear API.
    fn clear(&self) -> Result<(), ClipboardError>;

    /// Return the current change generation counter. Increments on
    /// every write (ours or another application's).
    fn change_count(&self) -> Result<u64, ClipboardError>;

    /// Register a callback fired on every clipboard change.
    ///
    /// The callback receives a `ClipboardEvent` with no text; it must
    /// call `read_text` if it wants to inspect the new contents.
    fn subscribe(
        &self,
        on_change: Arc<dyn Fn(ClipboardEvent) + Send + Sync>,
    ) -> Result<Subscription, ClipboardError>;
}

/// Opaque identifier for a `write_text` call. Backends set
/// `ClipboardEvent::matches_our_write = Some(token)` on the event
/// that resulted from that write, when they can determine it. The
/// determination is content-plus-token based and is honest about
/// its bound: `matches_our_write == Some(_)` means "with high
/// probability our write" (a same-user program writing identical
/// bytes at the same moment could be misclassified). Row 17 in
/// docs/THREAT_MODEL.md states this bound.
///
/// The inner `u64` is `pub(crate)` because only the backends inside
/// this crate mint fresh tokens; downstream consumers compare
/// tokens for equality via the derived `PartialEq` and never
/// construct one directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WriteToken(pub(crate) u64);

/// A clipboard change notification. Carries NO text: the daemon
/// layer reads via `read_text` when it acts on the event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClipboardEvent {
    /// The `change_count` value at the moment of the event.
    pub change_count: u64,
    /// If the backend can identify this event as resulting from one
    /// of our own `write_text` calls, the identifying token; else
    /// `None`. Used by the daemon for self-write suppression.
    pub matches_our_write: Option<WriteToken>,
}

/// An active clipboard-change subscription. Dropping cancels.
pub struct Subscription {
    _handle: Box<dyn SubscriptionHandle>,
}

impl Subscription {
    /// Construct from a backend-specific handle. `pub(crate)` because
    /// only the backends inside this crate produce `SubscriptionHandle`
    /// values and hand them here; downstream code receives an already-
    /// constructed `Subscription` from `Clipboard::subscribe` and never
    /// mints one directly.
    pub(crate) fn new(handle: Box<dyn SubscriptionHandle>) -> Self {
        Self { _handle: handle }
    }
}

impl std::fmt::Debug for Subscription {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Subscription").finish_non_exhaustive()
    }
}

/// Backend-supplied cancellation handle. Its `Drop` performs the
/// backend-specific unsubscribe.
pub trait SubscriptionHandle: Send + Sync {}
