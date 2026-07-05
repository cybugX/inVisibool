//! Peer verification for control-channel connections.
//!
//! The trait boundary means concrete verifiers slot in per platform
//! without the wire-format or test code needing to know which
//! syscall is running underneath.
//!
//! Threat class the verifier defends against
//! -----------------------------------------
//! - Foreign-UID processes connecting to the socket (e.g. via a
//!   broken sandbox that shares `$XDG_RUNTIME_DIR`, or a user-
//!   namespace UID-remapping arrangement that presents a different
//!   `SO_PEERCRED` UID than the daemon's).
//!
//! Threat class the verifier does NOT defend against
//! -------------------------------------------------
//! - Same-user processes. A same-user attacker is inside the declared
//!   trust boundary already; the OS keychain has the same boundary.
//!   Peer-UID checks cannot distinguish "the user's shell" from "a
//!   same-user malware process" because they both present the same
//!   `SO_PEERCRED` UID. That is handled by the visible-indication and
//!   auto-clear stack, not here.

use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream;

use crate::error::ControlError;

/// A verifier decides whether an accepted connection should be
/// served or dropped based on peer credentials.
pub trait PeerVerifier {
    /// Return `Ok(())` to accept, `Err(ControlError::PeerUidMismatch)`
    /// or `Err(ControlError::PeerRejectedForTest)` to reject.
    ///
    /// Verifiers must not touch the connection's payload; only
    /// operate on OS-visible peer credentials.
    fn verify(&self, stream: &UnixStream) -> Result<(), ControlError>;
}

/// Reject any peer whose effective UID differs from the daemon's own.
///
/// Implementation
/// --------------
/// Linux: `getsockopt(fd, SOL_SOCKET, SO_PEERCRED)` returns a
/// `struct ucred { pid, uid, gid }`. Only `uid` is compared.
///
/// The verifier caches the daemon's `geteuid()` at construction so
/// no syscall is made on the hot path per accept beyond the
/// getsockopt call itself.
#[derive(Debug, Clone, Copy)]
pub struct UnixPeerVerifier {
    daemon_uid: u32,
}

impl UnixPeerVerifier {
    pub fn new() -> Self {
        // Safety: geteuid() is a leaf syscall with no failure modes.
        #[allow(unsafe_code)]
        let daemon_uid = unsafe { libc::geteuid() };
        Self { daemon_uid }
    }

    /// Construct with an explicit daemon UID. Only used by tests that
    /// want to inject a mismatched value; production always calls
    /// `new()`.
    #[cfg(test)]
    pub fn with_daemon_uid(daemon_uid: u32) -> Self {
        Self { daemon_uid }
    }

    /// The UID this verifier expects to see on every accepted peer.
    pub fn daemon_uid(&self) -> u32 {
        self.daemon_uid
    }
}

impl Default for UnixPeerVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl PeerVerifier for UnixPeerVerifier {
    fn verify(&self, stream: &UnixStream) -> Result<(), ControlError> {
        let peer_uid = read_peer_uid(stream)?;
        if peer_uid == self.daemon_uid {
            Ok(())
        } else {
            Err(ControlError::PeerUidMismatch {
                peer_uid,
                daemon_uid: self.daemon_uid,
            })
        }
    }
}

/// Read the peer's effective UID via `SO_PEERCRED`.
///
/// Isolated so the unsafe block is one small, auditable function.
fn read_peer_uid(stream: &UnixStream) -> Result<u32, ControlError> {
    // libc::ucred layout: { pid: pid_t, uid: uid_t, gid: gid_t }.
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // Safety: fd is valid for the lifetime of the borrowed stream;
    // cred and len are stack-allocated with correct layout for the
    // SO_PEERCRED option; libc validates the socket-level option
    // and writes at most `len` bytes into `cred`.
    #[allow(unsafe_code)]
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if rc != 0 {
        return Err(ControlError::Io(std::io::Error::last_os_error()));
    }
    Ok(cred.uid)
}

/// Accept every peer. Gated behind `#[cfg(test)]` so it is
/// UNREACHABLE from production code paths - a review-item-3 guard
/// against a future refactor accidentally wiring the "accept
/// everyone" verifier into the shipping daemon. Test-only.
#[cfg(test)]
#[derive(Debug, Clone, Copy, Default)]
pub struct AlwaysAcceptVerifier;

#[cfg(test)]
impl PeerVerifier for AlwaysAcceptVerifier {
    fn verify(&self, _stream: &UnixStream) -> Result<(), ControlError> {
        Ok(())
    }
}

/// Reject every peer with a typed error. Also `#[cfg(test)]` - not
/// exported from the library. The daemon-stub binary defines its
/// own local reject-all verifier for reject-mode integration tests
/// so this remains a test-only symbol.
#[cfg(test)]
#[derive(Debug, Clone, Copy, Default)]
pub struct RejectVerifier;

#[cfg(test)]
impl PeerVerifier for RejectVerifier {
    fn verify(&self, _stream: &UnixStream) -> Result<(), ControlError> {
        Err(ControlError::PeerRejectedForTest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn always_accept_returns_ok_on_a_local_stream_pair() {
        let (a, _b) = UnixStream::pair().unwrap();
        assert!(AlwaysAcceptVerifier.verify(&a).is_ok());
    }

    #[test]
    fn reject_verifier_returns_typed_reject() {
        let (a, _b) = UnixStream::pair().unwrap();
        match RejectVerifier.verify(&a).unwrap_err() {
            ControlError::PeerRejectedForTest => {}
            other => panic!("expected PeerRejectedForTest, got {other:?}"),
        }
    }

    #[test]
    fn unix_peer_verifier_accepts_a_same_process_pair() {
        // socketpair connects two ends inside the same process; both
        // have our own euid, so verification must succeed.
        let (a, _b) = UnixStream::pair().unwrap();
        let verifier = UnixPeerVerifier::new();
        verifier
            .verify(&a)
            .expect("same-process socketpair must pass");
    }

    #[test]
    fn unix_peer_verifier_rejects_when_daemon_uid_forged_to_mismatch() {
        // Simulate a foreign-UID peer by constructing the verifier
        // with a daemon_uid the current process doesn't match. This
        // exercises the reject branch without needing a setuid dance.
        let (a, _b) = UnixStream::pair().unwrap();
        // Pick a UID we're guaranteed not to be running as: our own
        // euid XOR'd with 1 (small, deterministic, non-zero delta).
        #[allow(unsafe_code)]
        let real_uid = unsafe { libc::geteuid() };
        let forged_daemon_uid = real_uid ^ 1;
        assert_ne!(real_uid, forged_daemon_uid);
        let verifier = UnixPeerVerifier::with_daemon_uid(forged_daemon_uid);
        match verifier.verify(&a).unwrap_err() {
            ControlError::PeerUidMismatch {
                peer_uid,
                daemon_uid,
            } => {
                assert_eq!(peer_uid, real_uid);
                assert_eq!(daemon_uid, forged_daemon_uid);
            }
            other => panic!("expected PeerUidMismatch, got {other:?}"),
        }
    }

    #[test]
    fn read_peer_uid_returns_our_own_euid() {
        let (a, _b) = UnixStream::pair().unwrap();
        let uid = read_peer_uid(&a).unwrap();
        #[allow(unsafe_code)]
        let euid = unsafe { libc::geteuid() };
        assert_eq!(uid, euid);
    }
}
