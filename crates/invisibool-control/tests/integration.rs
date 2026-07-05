//! Chunk-22 integration tests.
//!
//! These spin up the test-only `daemon-stub` binary as a subprocess
//! against a real Unix domain socket, exercising the whole
//! transport + wire + peer stack end-to-end.
//!
//! Each test uses its own tempdir so runs are isolated. The daemon-
//! stub's stdin is closed to trigger clean shutdown at the end.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use invisibool_control::path::resolve_from;
use invisibool_control::transport::{
    dial_once, CONCURRENT_CONN_CAP, DEFAULT_TIMEOUT, LISTEN_BACKLOG,
};
use invisibool_control::wire::{read_frame, write_frame, Request, Response, StatusData};
use invisibool_control::wire::{ErrorKind, MAX_FRAME_BYTES};

/// Path to the compiled daemon-stub binary. Cargo sets
/// `CARGO_BIN_EXE_<name>` for every [[bin]] in the package when
/// building integration tests, giving us a clean absolute path with
/// no directory scanning.
fn daemon_stub_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_daemon-stub"))
}

/// Spawn the daemon-stub against a fresh tempdir. Returns the child,
/// the socket path, and a guard that kills the child on drop.
struct StubHandle {
    child: Option<Child>,
    pub socket_path: PathBuf,
    _tmp: tempfile::TempDir,
}

impl StubHandle {
    fn spawn(env: &[(&str, &str)]) -> Self {
        let tmp = tempfile::tempdir().unwrap();
        // Place the socket under a fresh subdir so
        // prepare_parent_dir_0700 creates it at 0700 (tempdir itself
        // is 0755).
        let socket_path = tmp.path().join("invisibool").join("ctl.sock");
        let mut cmd = Command::new(daemon_stub_path());
        cmd.arg(&socket_path);
        cmd.stdin(Stdio::piped());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());
        for (k, v) in env {
            cmd.env(k, v);
        }
        let child = cmd
            .spawn()
            .expect("daemon-stub must be built by cargo test");

        // Wait up to 2s for the socket to appear.
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline && !socket_path.exists() {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(
            socket_path.exists(),
            "daemon-stub failed to bind socket within 2s"
        );

        Self {
            child: Some(child),
            socket_path,
            _tmp: tmp,
        }
    }
}

impl Drop for StubHandle {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            // Close stdin to trigger clean shutdown.
            drop(child.stdin.take());
            let _ = child.wait();
        }
    }
}

// ---------------------- integration tests ------------------------

/// Path resolver honours XDG_RUNTIME_DIR ahead of XDG_STATE_HOME.
#[test]
fn socket_path_resolution_honours_xdg_env() {
    let paths = resolve_from(
        Some(std::ffi::OsStr::new("/run/user/1000")),
        Some(std::ffi::OsStr::new("/home/u/.local/state")),
        Some(std::ffi::OsStr::new("/home/u")),
    )
    .unwrap();
    assert_eq!(
        paths.socket,
        PathBuf::from("/run/user/1000/invisibool/ctl.sock")
    );
}

/// Real daemon over a real UDS: status roundtrips OK.
#[test]
fn real_uds_status_roundtrips_end_to_end() {
    let handle = StubHandle::spawn(&[]);
    let response =
        dial_once(&handle.socket_path, Request::Status, DEFAULT_TIMEOUT).expect("dial ok");
    match response {
        Response::Ok(v) => {
            let data: StatusData = serde_json::from_value(v).unwrap();
            assert!(data.running);
            assert!(data.pid > 0);
        }
        Response::Err(e) => panic!("expected ok, got err {e:?}"),
    }
}

/// Daemon-absent fallback: dial a socket that does not exist, get an
/// io::ErrorKind::NotFound - the CLI's status handler maps this to
/// the "watch is not running" fallback text.
#[test]
fn daemon_absent_dial_returns_not_found_or_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let missing = tmp.path().join("nope.sock");
    let err = dial_once(&missing, Request::Status, Duration::from_millis(500)).unwrap_err();
    match err {
        invisibool_control::ControlError::Io(e) => {
            assert!(
                matches!(
                    e.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
                ),
                "expected NotFound or ConnectionRefused, got {:?}",
                e.kind()
            );
        }
        other => panic!("expected Io error, got {other:?}"),
    }
}

/// Every deferred command returns not-implemented (typed), not
/// unknown-cmd, not bad-json, not a crash.
#[test]
fn deferred_commands_return_typed_not_implemented() {
    let handle = StubHandle::spawn(&[]);
    for req in [
        Request::Pause,
        Request::Resume,
        Request::RestoreClipboard,
        Request::SessionLs,
        Request::SessionClear,
    ] {
        let response = dial_once(&handle.socket_path, req.clone(), DEFAULT_TIMEOUT)
            .unwrap_or_else(|e| panic!("dial for {req:?}: {e}"));
        match response {
            Response::Err(e) => assert_eq!(
                e.kind,
                ErrorKind::NotImplemented,
                "expected NotImplemented for {req:?}"
            ),
            Response::Ok(_) => panic!("expected err for {req:?}"),
        }
    }
}

/// Frame-too-large: client sends a length prefix over the cap; server
/// returns typed frame-too-large error and does not attempt to buffer
/// a 65-KiB body.
#[test]
fn oversize_frame_returns_typed_frame_too_large() {
    let handle = StubHandle::spawn(&[]);
    let mut stream = UnixStream::connect(&handle.socket_path).unwrap();
    stream.set_read_timeout(Some(DEFAULT_TIMEOUT)).unwrap();
    stream.set_write_timeout(Some(DEFAULT_TIMEOUT)).unwrap();
    // Declare an oversized frame; do NOT send the body.
    stream
        .write_all(&((MAX_FRAME_BYTES + 1) as u32).to_be_bytes())
        .unwrap();
    let body = read_frame(&mut stream).unwrap();
    match Response::from_bytes(&body).unwrap() {
        Response::Err(e) => assert_eq!(e.kind, ErrorKind::FrameTooLarge),
        Response::Ok(_) => panic!("expected err"),
    }
}

/// Bad JSON returns typed bad-json and does NOT echo the offending
/// bytes back in the error message.
#[test]
fn bad_json_body_returns_typed_error_no_payload_echo() {
    let handle = StubHandle::spawn(&[]);
    let mut stream = UnixStream::connect(&handle.socket_path).unwrap();
    stream.set_read_timeout(Some(DEFAULT_TIMEOUT)).unwrap();
    stream.set_write_timeout(Some(DEFAULT_TIMEOUT)).unwrap();
    // 8 bytes of gibberish inside a well-framed request.
    write_frame(&mut stream, b"garbage!").unwrap();
    let body = read_frame(&mut stream).unwrap();
    match Response::from_bytes(&body).unwrap() {
        Response::Err(e) => {
            assert_eq!(e.kind, ErrorKind::BadJson);
            assert!(
                !e.message.contains("garbage!"),
                "error message must not echo the offending payload back: {}",
                e.message
            );
        }
        Response::Ok(_) => panic!("expected err"),
    }
}

/// Unknown command returns typed unknown-cmd, distinct from bad-json.
#[test]
fn unknown_cmd_returns_typed_error_not_bad_json() {
    let handle = StubHandle::spawn(&[]);
    let mut stream = UnixStream::connect(&handle.socket_path).unwrap();
    stream.set_read_timeout(Some(DEFAULT_TIMEOUT)).unwrap();
    stream.set_write_timeout(Some(DEFAULT_TIMEOUT)).unwrap();
    let body = serde_json::to_vec(&serde_json::json!({ "cmd": "not-a-real-command" })).unwrap();
    write_frame(&mut stream, &body).unwrap();
    let response_body = read_frame(&mut stream).unwrap();
    match Response::from_bytes(&response_body).unwrap() {
        Response::Err(e) => {
            assert_eq!(e.kind, ErrorKind::UnknownCmd);
            assert_ne!(e.kind, ErrorKind::BadJson);
        }
        Response::Ok(_) => panic!("expected err"),
    }
}

/// Concurrent connections up to the cap all succeed and roundtrip.
/// This is the safe part of test 8 - the backlog-EAGAIN check runs
/// in its own test below.
#[test]
fn concurrent_connections_up_to_cap_all_succeed() {
    let handle = StubHandle::spawn(&[]);
    let socket_path = handle.socket_path.clone();
    let handles: Vec<_> = (0..CONCURRENT_CONN_CAP)
        .map(|_| {
            let sp = socket_path.clone();
            std::thread::spawn(move || dial_once(&sp, Request::Status, DEFAULT_TIMEOUT))
        })
        .collect();
    let mut ok_count = 0;
    for h in handles {
        match h.join().unwrap() {
            Ok(Response::Ok(_)) => ok_count += 1,
            other => panic!("unexpected: {other:?}"),
        }
    }
    assert_eq!(ok_count, CONCURRENT_CONN_CAP);
}

/// Test 8, grounded in the empirical AF_UNIX backlog behavior on
/// Linux (measured on kernel 6.18 / WSL2, but the semantics come
/// from the mainline kernel):
///
///   - `listen(backlog=N)` sets the accept-queue high-water mark. On
///     Linux the queue actually accepts up to `N+1` pending
///     connections (the +1 is a long-standing SOCK_STREAM quirk).
///   - **BLOCKING `connect()`**: succeeds and queues for the first
///     ~`N+1` calls; **subsequent calls BLOCK INDEFINITELY** until
///     the server `accept()`s. Never observed ECONNREFUSED.
///   - **NON-BLOCKING `connect()`**: succeeds for the first ~`N+1`
///     calls; **subsequent calls return EAGAIN** (errno 11,
///     "Resource temporarily unavailable"). Never observed
///     ECONNREFUSED.
///
/// The chunk-22 design doc's original test-8 expectation
/// ("connections 17+ get ECONNREFUSED when the backlog fills") was
/// wrong; the review-item-4 caller flagged it, and this test bakes
/// the correct kernel behavior in as a regression.
///
/// This test uses the raw socket API to issue non-blocking connect()
/// (std does not expose UDS non-blocking connect). We assert that
/// EAGAIN is observed at least once and ECONNREFUSED is NEVER
/// observed, without hard-pinning the exact index where the
/// transition happens (the `+1` quirk means it can be `N` or `N+1`).
#[test]
fn backlog_full_returns_eagain_not_econnrefused() {
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixListener;

    let tmp = tempfile::tempdir().unwrap();
    // Nested subdir so parent is 0700 when prepare_parent_dir runs.
    let sub = tmp.path().join("invisibool");
    std::fs::create_dir_all(&sub).unwrap();
    let sp = sub.join("ctl.sock");
    let listener = UnixListener::bind(&sp).unwrap();
    // Force a tiny backlog and DO NOT accept: we want the queue to fill.
    #[allow(unsafe_code)]
    unsafe {
        libc::listen(listener.as_raw_fd(), 2);
    };

    let mut saw_eagain = false;
    let mut saw_econnrefused = false;
    for _ in 0..24 {
        #[allow(unsafe_code)]
        let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
        assert!(fd >= 0);
        #[allow(unsafe_code)]
        unsafe {
            let flags = libc::fcntl(fd, libc::F_GETFL, 0);
            libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
        }
        #[allow(unsafe_code)]
        let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
        let path_bytes = sp.as_os_str().as_encoded_bytes();
        for (i, b) in path_bytes.iter().enumerate() {
            if i >= addr.sun_path.len() - 1 {
                break;
            }
            addr.sun_path[i] = *b as libc::c_char;
        }
        let addr_len =
            (std::mem::size_of::<libc::sa_family_t>() + path_bytes.len()) as libc::socklen_t;
        #[allow(unsafe_code)]
        let rc = unsafe { libc::connect(fd, &addr as *const _ as *const libc::sockaddr, addr_len) };
        if rc != 0 {
            #[allow(unsafe_code)]
            let errno = unsafe { *libc::__errno_location() };
            if errno == libc::EAGAIN || errno == libc::EWOULDBLOCK {
                saw_eagain = true;
            } else if errno == libc::ECONNREFUSED {
                saw_econnrefused = true;
            }
        }
        #[allow(unsafe_code)]
        unsafe {
            libc::close(fd);
        }
    }
    assert!(
        saw_eagain,
        "expected to see EAGAIN when the accept queue fills"
    );
    assert!(
        !saw_econnrefused,
        "ECONNREFUSED must NOT be observed on backlog-full - kernel returns EAGAIN"
    );
    // Reference to LISTEN_BACKLOG to keep the import warning-clean
    // (the constant documents the daemon's real listen backlog even
    // though this test overrides it to 2 for tractability).
    let _ = LISTEN_BACKLOG;
}

/// Single-instance lock: two daemon-stubs against the same socket
/// path cannot both run. The second exits non-zero with an "already
/// running" style error; the first is unaffected.
#[test]
fn single_instance_lock_rejects_second_daemon() {
    let handle_a = StubHandle::spawn(&[]);
    // Second stub against the SAME socket path. It exits fast on the
    // lock contention.
    let mut b = Command::new(daemon_stub_path());
    b.arg(&handle_a.socket_path);
    b.stdin(Stdio::piped());
    b.stdout(Stdio::piped());
    b.stderr(Stdio::piped());
    let child_b = b.spawn().unwrap();
    let output_b = child_b.wait_with_output().unwrap();
    assert!(
        !output_b.status.success(),
        "second daemon-stub against a held lock must exit non-zero"
    );
    let stderr = String::from_utf8_lossy(&output_b.stderr);
    assert!(
        stderr.contains("lock") || stderr.contains("already"),
        "second daemon-stub must report a lock-held error: {stderr}"
    );

    // First daemon still works.
    let response = dial_once(&handle_a.socket_path, Request::Status, DEFAULT_TIMEOUT).unwrap();
    assert!(matches!(response, Response::Ok(_)));
}

/// Reject verifier path: daemon accepts the connection at the kernel
/// level then closes without responding. The client's dial fails
/// with an io error (broken pipe / EOF); the daemon's stderr carries
/// the reject log line.
#[test]
fn reject_verifier_closes_connections_without_reply() {
    let handle = StubHandle::spawn(&[("INVISIBOOL_DAEMON_STUB_REJECT", "1")]);
    let attempt = dial_once(
        &handle.socket_path,
        Request::Status,
        Duration::from_millis(500),
    );
    match attempt {
        Ok(other) => panic!("expected io error, got response {other:?}"),
        Err(invisibool_control::ControlError::Io(_)) => {}
        Err(invisibool_control::ControlError::BadJsonResponse(_)) => {}
        Err(other) => panic!("unexpected error type: {other:?}"),
    }
}

/// Wire schema is stable: the JSON bytes of a StatusData response
/// contain exactly the pinned fields.
///
/// This test is BOTH a wire-shape pin and a check that the
/// SessionEntry `real` field never leaks in. It's redundant with
/// the module test but at the integration layer.
#[test]
fn status_wire_response_shape_is_pinned() {
    let handle = StubHandle::spawn(&[]);
    let mut stream = UnixStream::connect(&handle.socket_path).unwrap();
    stream.set_read_timeout(Some(DEFAULT_TIMEOUT)).unwrap();
    stream.set_write_timeout(Some(DEFAULT_TIMEOUT)).unwrap();
    write_frame(&mut stream, &Request::Status.to_bytes()).unwrap();
    let body = read_frame(&mut stream).unwrap();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value.get("ok").and_then(|v| v.as_bool()), Some(true));
    let data = value.get("data").unwrap();
    for field in ["running", "pid", "uptime_secs", "version"] {
        assert!(
            data.get(field).is_some(),
            "status response is missing field `{field}`"
        );
    }
    // Anti-leak: no field named `real`, `secret`, or `value`
    // anywhere in the response.
    let raw = String::from_utf8_lossy(&body);
    for forbidden in ["\"real\"", "\"secret\"", "\"value\""] {
        assert!(
            !raw.contains(forbidden),
            "wire response MUST NOT contain field {forbidden}: {raw}"
        );
    }
}

/// Leak-harness (test 15). Generate a runtime canary, spawn the
/// daemon-stub with the canary in its process environment, drive
/// every wire command, RECORD every byte flowing in both directions
/// on the socket, and assert the canary never appears in the
/// recorded bytes.
///
/// This is a byte-level leak watcher over the control channel: the
/// daemon-stub carries an env var visible to it but not part of any
/// response schema; any accidental reflection into responses would
/// fire this test. When the real `watch` daemon (later chunk) starts
/// integrating with the session map, this same harness pattern is
/// extended to feed the canary through the daemon's clipboard
/// handler; the socket-side pin is stable now.
#[test]
fn leak_harness_canary_never_appears_on_the_wire() {
    // Runtime canary; never committed. Include high-entropy bytes so
    // an incidental substring match is astronomically unlikely.
    let canary = format!(
        "canary-{}-{}-{}",
        std::process::id(),
        Instant::now().elapsed().as_nanos(),
        std::time::UNIX_EPOCH
            .elapsed()
            .map(|d| d.as_nanos())
            .unwrap_or(0),
    );
    let handle = StubHandle::spawn(&[("INVISIBOOL_CANARY_TEST", canary.as_str())]);

    let mut all_bytes: Vec<u8> = Vec::new();
    for req in [
        Request::Status,
        Request::Pause,
        Request::Resume,
        Request::RestoreClipboard,
        Request::SessionLs,
        Request::SessionClear,
    ] {
        let mut stream = UnixStream::connect(&handle.socket_path).unwrap();
        stream.set_read_timeout(Some(DEFAULT_TIMEOUT)).unwrap();
        stream.set_write_timeout(Some(DEFAULT_TIMEOUT)).unwrap();
        let request_bytes = req.to_bytes();
        // Frame the request and record BOTH what we wrote AND what we
        // read. The wire bytes we care about are the daemon's replies,
        // but we also assert the outbound bytes don't leak (the client
        // shouldn't be sending secrets either).
        let mut framed = Vec::new();
        write_frame(&mut framed, &request_bytes).unwrap();
        all_bytes.extend_from_slice(&framed);
        stream.write_all(&framed).unwrap();

        let response_body = read_frame(&mut stream).unwrap();
        let mut framed_response = Vec::new();
        write_frame(&mut framed_response, &response_body).unwrap();
        all_bytes.extend_from_slice(&framed_response);
    }

    // The canary MUST NOT appear anywhere in the recorded bytes.
    let canary_bytes = canary.as_bytes();
    assert!(
        !all_bytes
            .windows(canary_bytes.len())
            .any(|w| w == canary_bytes),
        "leak: canary appeared in recorded socket bytes"
    );
    // Belt-and-braces: also assert on a shorter marker that the whole
    // canary starts with, to catch a partial-write leak.
    let marker = &canary_bytes[..8];
    assert!(
        !all_bytes.windows(marker.len()).any(|w| w == marker),
        "leak: canary prefix appeared in recorded socket bytes"
    );
}

// Wire the Read import so the unused-import lint doesn't fire on it
// even though we don't call it in any test above (kept for future
// Duplex-style tests).
#[allow(dead_code)]
fn _keep_read_import_alive<R: Read>(_: R) {}
