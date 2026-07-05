// Test-only daemon binary. Bindable by the chunk-22 integration
// tests and by the demo script.
//
// Behavior:
//   - Take a socket path via argv[1].
//   - Acquire the single-instance lock file next to it.
//   - Clean up any stale socket.
//   - Bind at 0600 under a 0700 parent, with the REAL
//     `UnixPeerVerifier::new()` (SO_PEERCRED, checks the peer UID
//     against the daemon's own euid). Same-process integration
//     tests match the daemon's UID and pass verification, so this
//     also exercises the production peer-check path end-to-end.
//   - Serve requests forever. Status returns real pid + uptime;
//     every other command returns NotImplemented per chunk-22 scope.
//   - On stdin close, shut down cleanly (drops release the lock,
//     unlink the socket).
//
// The verifier is override-able via env var so the chunk-22 tests
// can also drive the reject path:
//   INVISIBOOL_DAEMON_STUB_REJECT=1 -> bind with a local `RejectAll`
//     verifier defined below (NOT re-exported from the library -
//     staying local to this binary is a review-item-3 guard against
//     future production code accidentally wiring it up).
//
// Publish-time hazard (review item 3): this binary is declared as
// [[bin]] in crates/invisibool-control/Cargo.toml so integration
// tests can locate it via env!("CARGO_BIN_EXE_daemon-stub"). If
// invisibool-control is ever published to crates.io, `cargo
// install invisibool-control` would install this binary alongside
// the library. The Cargo.toml has a matching pre-publish checklist
// comment; do not publish invisibool-control without first
// gating this [[bin]] behind `required-features` or removing it.

use std::io::Read;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use invisibool_control::lifecycle::{
    cleanup_stale_socket, prepare_parent_dir_0700, SingleInstanceLock,
};
use invisibool_control::peer::{PeerVerifier, UnixPeerVerifier};
use invisibool_control::transport::UnixServer;
use invisibool_control::wire::{serve_one, ErrorKind, Request, Response, StatusData};
use invisibool_control::ControlError;

/// Local reject-all verifier. Kept in this binary so
/// AlwaysAcceptVerifier / RejectVerifier stay `#[cfg(test)]` in the
/// library and cannot be reached from any production path.
#[derive(Debug, Clone, Copy)]
struct RejectAll;

impl PeerVerifier for RejectAll {
    fn verify(&self, _stream: &UnixStream) -> Result<(), ControlError> {
        Err(ControlError::PeerRejectedForTest)
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: daemon-stub <socket-path>");
        std::process::exit(2);
    }
    let socket_path = PathBuf::from(&args[1]);
    let lock_path = socket_path.with_file_name("ctl.lock");

    if let Err(e) = prepare_parent_dir_0700(&socket_path) {
        eprintln!("daemon-stub: prepare parent dir: {e}");
        std::process::exit(3);
    }
    let _lock = match SingleInstanceLock::acquire(lock_path) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("daemon-stub: lock: {e}");
            std::process::exit(4);
        }
    };
    if let Err(e) = cleanup_stale_socket(&socket_path) {
        eprintln!("daemon-stub: stale-socket cleanup: {e}");
        std::process::exit(5);
    }

    let use_reject = std::env::var_os("INVISIBOOL_DAEMON_STUB_REJECT").is_some();
    let started_at = Instant::now();
    let pid = std::process::id();

    let shutdown = Arc::new(AtomicBool::new(false));
    // Read stdin to EOF in a background thread; when it closes,
    // shut down. Tests drive this by closing the child's stdin.
    let shutdown_c = shutdown.clone();
    thread::spawn(move || {
        let mut buf = [0u8; 32];
        while let Ok(n) = std::io::stdin().read(&mut buf) {
            if n == 0 {
                break;
            }
        }
        shutdown_c.store(true, Ordering::SeqCst);
    });

    // Run the accept loop dispatched on the env toggle so each branch
    // is compile-time typed.
    if use_reject {
        run_loop(&socket_path, RejectAll, shutdown, started_at, pid);
    } else {
        run_loop(
            &socket_path,
            UnixPeerVerifier::new(),
            shutdown,
            started_at,
            pid,
        );
    }
}

fn run_loop<V: PeerVerifier + Send + Sync + 'static>(
    socket_path: &std::path::Path,
    verifier: V,
    shutdown: Arc<AtomicBool>,
    started_at: Instant,
    pid: u32,
) {
    let server = match UnixServer::bind(socket_path.to_path_buf(), verifier) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("daemon-stub: bind {}: {e}", socket_path.display());
            std::process::exit(6);
        }
    };
    server.set_nonblocking(true).ok();
    eprintln!("daemon-stub: listening on {}", socket_path.display());
    while !shutdown.load(Ordering::SeqCst) {
        match server.accept() {
            Ok((mut stream, _v)) => {
                thread::spawn(move || {
                    let _ = serve_one(&mut stream, |req| dispatch(req, pid, started_at));
                });
            }
            Err(ControlError::Io(e)) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(20));
            }
            Err(ControlError::PeerUidMismatch {
                peer_uid,
                daemon_uid,
            }) => {
                eprintln!(
                    "control-channel: rejected connection from uid={peer_uid} (expected uid={daemon_uid})"
                );
            }
            Err(ControlError::PeerRejectedForTest) => {
                eprintln!("control-channel: rejected connection (test verifier)");
            }
            Err(e) => {
                eprintln!("daemon-stub: accept: {e}");
            }
        }
    }
    // Drop path unlinks the lock file; explicitly unlink the socket
    // so a fresh daemon can rebind cleanly.
    let _ = std::fs::remove_file(socket_path);
    eprintln!("daemon-stub: shutdown complete");
}

fn dispatch(req: Request, pid: u32, started_at: Instant) -> Response {
    match req {
        Request::Status => Response::ok(StatusData {
            running: true,
            pid,
            uptime_secs: started_at.elapsed().as_secs(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        }),
        Request::Pause => not_implemented("pause"),
        Request::Resume => not_implemented("resume"),
        Request::RestoreClipboard => not_implemented("restore-clipboard"),
        Request::SessionLs => not_implemented("session-ls"),
        Request::SessionClear => not_implemented("session-clear"),
    }
}

fn not_implemented(name: &str) -> Response {
    Response::err(
        ErrorKind::NotImplemented,
        format!("{name} is not yet implemented"),
    )
}
