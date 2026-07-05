//! Typed errors for the control channel.
//!
//! Manual Display + Error impls (no `thiserror`): one fewer proc-macro
//! dep in a security-critical crate; the surface is small enough to
//! spell out by hand.

use std::fmt;
use std::io;

#[derive(Debug)]
pub enum ControlError {
    Io(io::Error),
    FrameTooLarge {
        actual: usize,
        max: usize,
    },
    BadJson(serde_json::Error),
    BadJsonResponse(serde_json::Error),
    UnknownCmd(String),
    PeerUidMismatch {
        peer_uid: u32,
        daemon_uid: u32,
    },
    PeerRejectedForTest,
    SingleInstanceLockHeld {
        path: String,
    },
    StaleSocketCleanupRefused {
        path: String,
        source: io::Error,
    },
    SocketDirWrongMode {
        path: String,
        actual_mode: u32,
        expected_mode: u32,
    },
    SocketFileWrongMode {
        path: String,
        actual_mode: u32,
        expected_mode: u32,
    },
    NoSocketPath,
}

impl fmt::Display for ControlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "io error: {e}"),
            Self::FrameTooLarge { actual, max } => {
                write!(f, "frame size {actual} exceeds max frame size {max}")
            }
            Self::BadJson(e) => write!(f, "received request body was not valid JSON: {e}"),
            Self::BadJsonResponse(e) => {
                write!(f, "received response body was not valid JSON: {e}")
            }
            Self::UnknownCmd(cmd) => write!(f, "unknown command: {cmd}"),
            Self::PeerUidMismatch {
                peer_uid,
                daemon_uid,
            } => write!(
                f,
                "connection rejected: peer uid {peer_uid} != daemon uid {daemon_uid}"
            ),
            Self::PeerRejectedForTest => write!(f, "connection rejected by test verifier"),
            Self::SingleInstanceLockHeld { path } => write!(
                f,
                "another invisibool daemon appears to be running (lock held at {path}). If you believe this is stale, remove {path} and try again."
            ),
            Self::StaleSocketCleanupRefused { path, source } => write!(
                f,
                "stale-socket cleanup refused: {path} exists with permission error {source}. Investigate before removing."
            ),
            Self::SocketDirWrongMode {
                path,
                actual_mode,
                expected_mode,
            } => write!(
                f,
                "socket dir {path} exists with wrong mode {actual_mode:o} (expected {expected_mode:o}); refusing to chmod"
            ),
            Self::SocketFileWrongMode {
                path,
                actual_mode,
                expected_mode,
            } => write!(
                f,
                "socket file {path} has wrong mode {actual_mode:o} (expected {expected_mode:o}) after bind"
            ),
            Self::NoSocketPath => write!(
                f,
                "could not resolve control-socket path: neither XDG_RUNTIME_DIR nor XDG_STATE_HOME nor HOME is set"
            ),
        }
    }
}

impl std::error::Error for ControlError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::BadJson(e) | Self::BadJsonResponse(e) => Some(e),
            Self::StaleSocketCleanupRefused { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl From<io::Error> for ControlError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}
