//! Typed errors for the clipboard trait.

use std::fmt;

/// Every way the clipboard trait can fail. Manually implements
/// `Display` and `Error` to keep the crate proc-macro-free.
#[derive(Debug)]
pub enum ClipboardError {
    /// The platform does not support the clipboard operation at all.
    /// The Linux backends return this on Wayland when constructed
    /// directly; the top-level CLI catches Wayland earlier via
    /// `detect_display_server` and prints a richer message, so this
    /// variant is primarily for defence-in-depth.
    Unsupported(&'static str),
    /// Reading the clipboard failed (permission, platform-specific
    /// error, no session).
    ReadFailed(String),
    /// Writing the clipboard failed.
    WriteFailed(String),
    /// Clearing the clipboard failed. Kept separate from
    /// `WriteFailed` because the true-clear APIs differ from write
    /// APIs on every platform.
    ClearFailed(String),
    /// Registering or dispatching a change-event callback failed.
    SubscribeFailed(String),
}

impl fmt::Display for ClipboardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported(reason) => write!(f, "clipboard unsupported: {reason}"),
            Self::ReadFailed(msg) => write!(f, "clipboard read failed: {msg}"),
            Self::WriteFailed(msg) => write!(f, "clipboard write failed: {msg}"),
            Self::ClearFailed(msg) => write!(f, "clipboard clear failed: {msg}"),
            Self::SubscribeFailed(msg) => write!(f, "clipboard subscribe failed: {msg}"),
        }
    }
}

impl std::error::Error for ClipboardError {}
