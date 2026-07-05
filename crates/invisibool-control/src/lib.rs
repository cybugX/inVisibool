//! Invisibool daemon control channel, Linux transport.
//!
//! `pause`, `resume`, `status`, `restore-clipboard`, `session-ls`, and
//! `session-clear` are separate CLI invocations that command the running
//! `watch` daemon. The channel is an owner-only Unix domain socket
//! (`0600` under a `0700` parent), peer-UID verified via `SO_PEERCRED`,
//! carrying a length-prefixed JSON protocol with a 64 KiB max frame
//! size. No secret value ever transits the socket: the daemon writes
//! the clipboard itself on `restore-clipboard`.
//!
//! This crate is the transport foundation. It does not yet include the
//! `watch` daemon, the clipboard listener, the session map, or the
//! handler bodies for `pause | resume | restore-clipboard | session-ls
//! | session-clear`; those land in later M1 chunks against the same
//! wire envelope and `PeerVerifier` trait pinned here.
//!
//! Never TCP, not even loopback. The channel is a UDS or a Windows
//! named pipe, protected by filesystem permissions and peer credentials.
//! A localhost TCP port is reachable by every local user and by many
//! sandboxed apps; a UDS protected by filesystem permissions is not.
//!
//! Unsafe surface. This crate is `#![deny(unsafe_code)]` at the root
//! and cannot be `#![forbid(...)]` because the peer verifier and the
//! flock helper need `unsafe { libc::... }` for syscalls that Rust
//! does not wrap safely. Each `#[allow(unsafe_code)]` sits directly
//! on the specific `unsafe` block that needs it; the total unsafe
//! surface is auditable in `peer.rs` and `lifecycle.rs` alone.

#![deny(unsafe_code)]

pub mod error;
pub mod lifecycle;
pub mod path;
pub mod peer;
pub mod transport;
pub mod wire;

pub use error::ControlError;
pub use peer::{PeerVerifier, UnixPeerVerifier};
pub use transport::{DuplexPair, InMemoryTransport, UnixServer};
pub use wire::{
    ErrorKind, ErrorPayload, Request, Response, SessionEntry, SessionLsData, StatusData,
    MAX_FRAME_BYTES,
};
