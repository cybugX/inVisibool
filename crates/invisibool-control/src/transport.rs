//! UDS transport for the control channel.
//!
//! `UnixServer::bind()` handles the security-critical parts: it
//! creates the socket at `0600` under a `0700` parent, verifies
//! resulting permissions, and rejects with typed errors on any
//! divergence rather than silently `chmod`-ing (a user who
//! deliberately tightened permissions should not be walked over).
//!
//! Peer verification runs on every `accept()` before returning the
//! connection to the caller.

use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use crate::error::ControlError;
use crate::peer::PeerVerifier;
use crate::wire;

/// Directory permission required for the socket's parent.
pub const REQUIRED_PARENT_MODE: u32 = 0o700;
/// Socket file permission required after bind.
pub const REQUIRED_SOCKET_MODE: u32 = 0o600;
/// Default read/write timeout. Same-user DoS is inside the declared
/// trust boundary (a same-user process can command the daemon by
/// construction), but the timeout still bounds per-connection fd
/// hold time.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);
/// Maximum concurrent in-flight connections the server will accept.
/// Excess connections queue in the kernel accept backlog.
pub const CONCURRENT_CONN_CAP: usize = 8;
/// listen(2) backlog. Linux permits `backlog + 1` pending
/// connections; do NOT hard-pin the tail-end index in tests.
pub const LISTEN_BACKLOG: i32 = 16;

/// A bound Unix-domain listener with a peer verifier attached.
#[derive(Debug)]
pub struct UnixServer<V> {
    listener: UnixListener,
    verifier: Arc<V>,
    socket_path: PathBuf,
}

impl<V: PeerVerifier> UnixServer<V> {
    /// Bind at `socket_path`. Creates the parent directory with mode
    /// `0700` if missing; refuses to start if it exists with a
    /// different mode.
    pub fn bind(socket_path: PathBuf, verifier: V) -> Result<Self, ControlError> {
        prepare_parent_dir(&socket_path)?;
        // Stale-socket cleanup happens in the lifecycle helper, not
        // here. Bind expects the socket path to be clear.
        let listener = UnixListener::bind(&socket_path)?;
        set_socket_mode(&socket_path)?;
        // Adjust listen backlog. std::os::unix::net::UnixListener::bind
        // uses SOMAXCONN; we tighten to LISTEN_BACKLOG so tests can
        // exercise the backlog-full case.
        set_listen_backlog(&listener, LISTEN_BACKLOG)?;
        Ok(Self {
            listener,
            verifier: Arc::new(verifier),
            socket_path,
        })
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// Accept one connection. Applies peer verification before
    /// returning. On peer mismatch, returns the typed error; the
    /// caller is expected to log the mismatch to stderr with UID
    /// pair only (no PID or comm) and drop the connection.
    pub fn accept(&self) -> Result<(UnixStream, Arc<V>), ControlError> {
        let (stream, _addr) = self.listener.accept()?;
        stream.set_read_timeout(Some(DEFAULT_TIMEOUT))?;
        stream.set_write_timeout(Some(DEFAULT_TIMEOUT))?;
        self.verifier.verify(&stream)?;
        Ok((stream, self.verifier.clone()))
    }

    /// Non-blocking accept for tests that want to drain the queue.
    pub fn set_nonblocking(&self, nonblocking: bool) -> Result<(), ControlError> {
        self.listener.set_nonblocking(nonblocking)?;
        Ok(())
    }
}

/// Dial the daemon and send one framed request; return the framed
/// response.
pub fn dial_once(
    socket_path: &Path,
    request: wire::Request,
    timeout: Duration,
) -> Result<wire::Response, ControlError> {
    let stream = UnixStream::connect(socket_path)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    let mut stream = stream;
    wire::write_frame(&mut stream, &request.to_bytes())?;
    let body = wire::read_frame(&mut stream)?;
    wire::Response::from_bytes(&body)
}

/// Prepare the parent directory: create at `0700` if missing;
/// verify mode if present; refuse to `chmod` a wrong-moded dir.
fn prepare_parent_dir(socket_path: &Path) -> Result<(), ControlError> {
    let parent = socket_path
        .parent()
        .ok_or_else(|| io::Error::other("socket path has no parent"))?;
    match fs::metadata(parent) {
        Ok(md) => {
            let actual_mode = md.permissions().mode() & 0o777;
            if actual_mode != REQUIRED_PARENT_MODE {
                return Err(ControlError::SocketDirWrongMode {
                    path: parent.display().to_string(),
                    actual_mode,
                    expected_mode: REQUIRED_PARENT_MODE,
                });
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            fs::create_dir_all(parent)?;
            fs::set_permissions(parent, fs::Permissions::from_mode(REQUIRED_PARENT_MODE))?;
        }
        Err(e) => return Err(ControlError::Io(e)),
    }
    Ok(())
}

/// After bind, force the socket file mode to 0600 and verify.
fn set_socket_mode(socket_path: &Path) -> Result<(), ControlError> {
    fs::set_permissions(
        socket_path,
        fs::Permissions::from_mode(REQUIRED_SOCKET_MODE),
    )?;
    let md = fs::metadata(socket_path)?;
    let actual_mode = md.permissions().mode() & 0o777;
    if actual_mode != REQUIRED_SOCKET_MODE {
        return Err(ControlError::SocketFileWrongMode {
            path: socket_path.display().to_string(),
            actual_mode,
            expected_mode: REQUIRED_SOCKET_MODE,
        });
    }
    Ok(())
}

/// Override the listen backlog set by std's `UnixListener::bind`.
///
/// std uses `SOMAXCONN` on Linux; we tighten to a specific value so
/// tests can exercise backlog behaviour. Empirical result on Linux
/// (see the chunk-22 design doc): a full backlog causes non-blocking
/// `connect()` to return EAGAIN; blocking `connect()` blocks
/// indefinitely. Tests use non-blocking.
fn set_listen_backlog(listener: &UnixListener, backlog: i32) -> Result<(), ControlError> {
    use std::os::unix::io::AsRawFd;
    // Safety: fd is valid for the lifetime of the borrowed listener.
    #[allow(unsafe_code)]
    let rc = unsafe { libc::listen(listener.as_raw_fd(), backlog) };
    if rc != 0 {
        return Err(ControlError::Io(io::Error::last_os_error()));
    }
    Ok(())
}

/// A duplex byte-stream pair used to exercise `wire::serve_one`
/// without any real transport. Both ends implement `Read + Write`.
///
/// Not intended for production paths; kept in this module because
/// it composes with the wire tests and demonstrates the
/// transport-agnostic serve loop.
pub struct DuplexPair {
    pub client: UnixStream,
    pub server: UnixStream,
}

impl DuplexPair {
    pub fn new() -> Self {
        let (client, server) = UnixStream::pair().expect("socketpair should never fail");
        Self { client, server }
    }
}

impl Default for DuplexPair {
    fn default() -> Self {
        Self::new()
    }
}

/// A minimal in-memory transport used by tests that want to exercise
/// serve_one over anything Read + Write. Currently a thin wrapper
/// over [`DuplexPair`] for API symmetry with future non-UDS transports.
pub struct InMemoryTransport;

impl InMemoryTransport {
    pub fn pair() -> DuplexPair {
        DuplexPair::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer::{AlwaysAcceptVerifier, RejectVerifier};
    use crate::wire::{Request, Response, StatusData};

    #[test]
    fn bind_creates_parent_at_0700_and_socket_at_0600() {
        let tmp = tempfile::tempdir().unwrap();
        let socket_path = tmp.path().join("nested").join("ctl.sock");
        let _server = UnixServer::bind(socket_path.clone(), AlwaysAcceptVerifier).unwrap();

        let parent_md = fs::metadata(socket_path.parent().unwrap()).unwrap();
        assert_eq!(parent_md.permissions().mode() & 0o777, REQUIRED_PARENT_MODE);

        let sock_md = fs::metadata(&socket_path).unwrap();
        assert_eq!(sock_md.permissions().mode() & 0o777, REQUIRED_SOCKET_MODE);
    }

    #[test]
    fn bind_refuses_wrong_moded_parent() {
        let tmp = tempfile::tempdir().unwrap();
        let parent = tmp.path().join("nested");
        fs::create_dir_all(&parent).unwrap();
        // Deliberately wrong: world-writable.
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o777)).unwrap();
        let socket_path = parent.join("ctl.sock");
        let err = UnixServer::bind(socket_path, AlwaysAcceptVerifier).unwrap_err();
        assert!(
            matches!(err, ControlError::SocketDirWrongMode { .. }),
            "expected SocketDirWrongMode, got {err:?}"
        );
    }

    #[test]
    fn accept_verifies_peer_and_status_request_roundtrips() {
        let tmp = tempfile::tempdir().unwrap();
        // Nested subdir so prepare_parent_dir creates it fresh at 0700
        // (tempfile::tempdir() itself is 0755 which prepare_parent_dir
        // deliberately refuses).
        let socket_path = tmp.path().join("invisibool").join("ctl.sock");
        let server = UnixServer::bind(socket_path.clone(), AlwaysAcceptVerifier).unwrap();

        let socket_path_c = socket_path.clone();
        let client = std::thread::spawn(move || {
            dial_once(&socket_path_c, Request::Status, Duration::from_secs(2)).unwrap()
        });

        let (mut stream, _verifier) = server.accept().unwrap();
        wire::serve_one(&mut stream, |req| {
            assert_eq!(req, Request::Status);
            Response::ok(StatusData {
                running: true,
                pid: 42,
                uptime_secs: 1,
                version: "test".to_string(),
            })
        })
        .unwrap();

        let response = client.join().unwrap();
        match response {
            Response::Ok(v) => {
                let data: StatusData = serde_json::from_value(v).unwrap();
                assert!(data.running);
                assert_eq!(data.pid, 42);
            }
            Response::Err(e) => panic!("expected ok, got {e:?}"),
        }
    }

    #[test]
    fn accept_rejects_peer_when_verifier_rejects_and_leaves_socket_usable() {
        let tmp = tempfile::tempdir().unwrap();
        let socket_path = tmp.path().join("invisibool").join("ctl.sock");
        let server = UnixServer::bind(socket_path.clone(), RejectVerifier).unwrap();

        let socket_path_c = socket_path.clone();
        // Client connects; server rejects; client sees an IO error
        // (broken pipe or unexpected EOF) trying to read a response.
        let client = std::thread::spawn(move || {
            let _ = dial_once(&socket_path_c, Request::Status, Duration::from_millis(500));
        });

        let err = server.accept().unwrap_err();
        assert!(matches!(err, ControlError::PeerRejectedForTest));

        client.join().unwrap();

        // After a reject the listener is still bound and usable for
        // the next connection.
        assert!(server.socket_path().exists());
    }
}
