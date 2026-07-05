//! Length-prefixed JSON wire protocol for the control channel.
//!
//! Format
//! ------
//! - 4-byte big-endian `u32` length prefix (call it L).
//! - L bytes of UTF-8 JSON payload.
//! - No trailing bytes. One request-per-connection, one
//!   response-per-connection; both peers close the connection after
//!   the exchange.
//!
//! Max frame size: [`MAX_FRAME_BYTES`] = 64 KiB. The u32 field width
//! and the 64 KiB cap are two independent decisions: the width lets
//! the protocol evolve without a schema break; the cap is a hard
//! defence against a same-user attacker sending a `u32::MAX`-declared
//! frame that would otherwise force a 4 GiB allocation.
//!
//! Request shape: `{ "cmd": "<verb>" }`, no args in chunk 22. Later
//! commands that need args will add an `"args": { ... }` object; the
//! parser tolerates unknown top-level fields today so a `cmd`-only
//! request from an older client still works.
//!
//! Response shape: `{ "ok": true, "data": { ... } }` on success,
//! `{ "ok": false, "error": { "kind": "...", "message": "..." } }`
//! on failure.
//!
//! The response body schemas for the deferred commands are pinned
//! HERE, not in the handler chunks, so a future PR that tries to
//! smuggle a real value into a response must edit this file. In
//! particular [`SessionEntry`] has `fake` and `entity_kind` and NO
//! `real` field; the leak harness watches for that field name to
//! prevent regressions.

use std::io::{Read, Write};

use serde::{Deserialize, Serialize};

use crate::error::ControlError;

/// Cap on payload bytes per frame (does not include the 4-byte length
/// prefix). 64 KiB is generous for any legitimate command (a session
/// with 500 entries fits comfortably) and bounds a same-user memory-
/// exhaustion attempt.
pub const MAX_FRAME_BYTES: usize = 64 * 1024;

/// Every wire command. Handlers for the non-`Status` variants stub
/// with [`ErrorKind::NotImplemented`] in chunk 22; they land with
/// their capabilities in later chunks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    Status,
    Pause,
    Resume,
    RestoreClipboard,
    SessionLs,
    SessionClear,
}

impl Request {
    fn wire_verb(&self) -> &'static str {
        match self {
            Self::Status => "status",
            Self::Pause => "pause",
            Self::Resume => "resume",
            Self::RestoreClipboard => "restore-clipboard",
            Self::SessionLs => "session-ls",
            Self::SessionClear => "session-clear",
        }
    }

    fn from_wire_verb(cmd: &str) -> Option<Self> {
        match cmd {
            "status" => Some(Self::Status),
            "pause" => Some(Self::Pause),
            "resume" => Some(Self::Resume),
            "restore-clipboard" => Some(Self::RestoreClipboard),
            "session-ls" => Some(Self::SessionLs),
            "session-clear" => Some(Self::SessionClear),
            _ => None,
        }
    }

    /// Encode this request as wire bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let obj = serde_json::json!({ "cmd": self.wire_verb() });
        // serde_json::to_vec on a Value never fails.
        serde_json::to_vec(&obj).expect("json serialization of a static object cannot fail")
    }

    /// Decode a request from wire bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ControlError> {
        #[derive(Deserialize)]
        struct Raw {
            cmd: String,
        }
        let raw: Raw = serde_json::from_slice(bytes).map_err(ControlError::BadJson)?;
        Self::from_wire_verb(&raw.cmd).ok_or(ControlError::UnknownCmd(raw.cmd))
    }
}

/// Successful `status` response body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusData {
    pub running: bool,
    pub pid: u32,
    pub uptime_secs: u64,
    pub version: String,
}

/// A single session-map entry as it appears on the wire.
///
/// The `real` field is **deliberately absent**: the daemon writes the
/// clipboard itself on `restore-clipboard`, so no real value ever
/// needs to cross the socket. The leak harness watches every socket
/// byte for the canary secret; any future PR that adds a `real`
/// field here would need to edit this file and would show up in the
/// harness diff.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionEntry {
    pub fake: String,
    pub entity_kind: String,
}

/// Body of a `session-ls` response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionLsData {
    pub entries: Vec<SessionEntry>,
}

/// Typed error kinds. New variants may appear as later chunks land
/// their command handlers; existing kinds do not change their wire
/// spelling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorKind {
    NotImplemented,
    FrameTooLarge,
    BadJson,
    UnknownCmd,
    BadArgs,
    Internal,
}

impl ErrorKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NotImplemented => "not-implemented",
            Self::FrameTooLarge => "frame-too-large",
            Self::BadJson => "bad-json",
            Self::UnknownCmd => "unknown-cmd",
            Self::BadArgs => "bad-args",
            Self::Internal => "internal",
        }
    }

    pub fn from_wire_str(s: &str) -> Option<Self> {
        match s {
            "not-implemented" => Some(Self::NotImplemented),
            "frame-too-large" => Some(Self::FrameTooLarge),
            "bad-json" => Some(Self::BadJson),
            "unknown-cmd" => Some(Self::UnknownCmd),
            "bad-args" => Some(Self::BadArgs),
            "internal" => Some(Self::Internal),
            _ => None,
        }
    }
}

/// The `error` object in a failure response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorPayload {
    pub kind: ErrorKind,
    pub message: String,
}

/// Parsed response. `Ok` carries an untyped JSON `data` payload since
/// the caller knows which command it sent; helpers to extract typed
/// data live below.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Response {
    Ok(serde_json::Value),
    Err(ErrorPayload),
}

impl Response {
    pub fn ok(data: impl Serialize) -> Self {
        Self::Ok(serde_json::to_value(data).expect("data was Serialize; conversion cannot fail"))
    }

    pub fn err(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self::Err(ErrorPayload {
            kind,
            message: message.into(),
        })
    }

    /// Encode as wire bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let value = match self {
            Self::Ok(data) => serde_json::json!({ "ok": true, "data": data }),
            Self::Err(payload) => serde_json::json!({
                "ok": false,
                "error": {
                    "kind": payload.kind.as_str(),
                    "message": &payload.message,
                }
            }),
        };
        serde_json::to_vec(&value).expect("json serialization cannot fail on our own types")
    }

    /// Decode from wire bytes. Returns `ControlError::BadJsonResponse`
    /// for malformed responses (distinct from `BadJson` for requests
    /// so callers can tell which side produced the malformed payload).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ControlError> {
        let value: serde_json::Value =
            serde_json::from_slice(bytes).map_err(ControlError::BadJsonResponse)?;
        match value.get("ok").and_then(|v| v.as_bool()) {
            Some(true) => {
                let data = value
                    .get("data")
                    .cloned()
                    .unwrap_or(serde_json::Value::Null);
                Ok(Self::Ok(data))
            }
            Some(false) => {
                let err = value.get("error").ok_or_else(|| {
                    ControlError::BadJsonResponse(serde::de::Error::custom(
                        "ok=false but no error object",
                    ))
                })?;
                let kind_str = err.get("kind").and_then(|v| v.as_str()).ok_or_else(|| {
                    ControlError::BadJsonResponse(serde::de::Error::custom(
                        "error.kind missing or not a string",
                    ))
                })?;
                let kind = ErrorKind::from_wire_str(kind_str).unwrap_or(ErrorKind::Internal);
                let message = err
                    .get("message")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                Ok(Self::Err(ErrorPayload { kind, message }))
            }
            _ => Err(ControlError::BadJsonResponse(serde::de::Error::custom(
                "response missing ok field",
            ))),
        }
    }

    pub fn into_ok(self) -> Result<serde_json::Value, ErrorPayload> {
        match self {
            Self::Ok(v) => Ok(v),
            Self::Err(e) => Err(e),
        }
    }
}

/// Read one length-prefixed frame from `r`. Enforces
/// [`MAX_FRAME_BYTES`] before allocating the body buffer.
pub fn read_frame<R: Read>(r: &mut R) -> Result<Vec<u8>, ControlError> {
    let mut lenbuf = [0u8; 4];
    r.read_exact(&mut lenbuf)?;
    let len = u32::from_be_bytes(lenbuf) as usize;
    if len > MAX_FRAME_BYTES {
        return Err(ControlError::FrameTooLarge {
            actual: len,
            max: MAX_FRAME_BYTES,
        });
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body)?;
    Ok(body)
}

/// Write one length-prefixed frame to `w`. Refuses to write frames
/// larger than [`MAX_FRAME_BYTES`] rather than truncating.
pub fn write_frame<W: Write>(w: &mut W, body: &[u8]) -> Result<(), ControlError> {
    if body.len() > MAX_FRAME_BYTES {
        return Err(ControlError::FrameTooLarge {
            actual: body.len(),
            max: MAX_FRAME_BYTES,
        });
    }
    let len = (body.len() as u32).to_be_bytes();
    w.write_all(&len)?;
    w.write_all(body)?;
    w.flush()?;
    Ok(())
}

/// Serve one request over a duplex stream:
///
/// 1. Read one framed request.
/// 2. Parse. On bad JSON respond `bad-json`; on unknown cmd respond
///    `unknown-cmd`; on frame-too-large respond `frame-too-large`.
///    Never crash the connection.
/// 3. Call `handler`; write its response as a framed reply.
///
/// The connection is one-shot: the caller closes after this returns.
pub fn serve_one<C, F>(conn: &mut C, handler: F) -> Result<(), ControlError>
where
    C: Read + Write,
    F: FnOnce(Request) -> Response,
{
    let response = match read_frame(conn) {
        Ok(body) => match Request::from_bytes(&body) {
            Ok(req) => handler(req),
            Err(ControlError::BadJson(_)) => Response::err(
                ErrorKind::BadJson,
                "request body was not valid JSON matching the cmd schema",
            ),
            Err(ControlError::UnknownCmd(cmd)) => {
                Response::err(ErrorKind::UnknownCmd, format!("no handler for cmd `{cmd}`"))
            }
            Err(other) => return Err(other),
        },
        Err(ControlError::FrameTooLarge { actual, max }) => Response::err(
            ErrorKind::FrameTooLarge,
            format!("frame size {actual} exceeds max frame size {max}"),
        ),
        Err(other) => return Err(other),
    };
    write_frame(conn, &response.to_bytes())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_request_variant_roundtrips_through_wire_bytes() {
        for req in [
            Request::Status,
            Request::Pause,
            Request::Resume,
            Request::RestoreClipboard,
            Request::SessionLs,
            Request::SessionClear,
        ] {
            let bytes = req.to_bytes();
            let back = Request::from_bytes(&bytes).unwrap();
            assert_eq!(req, back);
        }
    }

    #[test]
    fn ok_response_roundtrips() {
        let data = StatusData {
            running: true,
            pid: 12345,
            uptime_secs: 42,
            version: "0.0.0".to_string(),
        };
        let resp = Response::ok(&data);
        let bytes = resp.to_bytes();
        let back = Response::from_bytes(&bytes).unwrap();
        match back {
            Response::Ok(v) => {
                let parsed: StatusData = serde_json::from_value(v).unwrap();
                assert_eq!(parsed, data);
            }
            Response::Err(_) => panic!("expected ok"),
        }
    }

    #[test]
    fn err_response_roundtrips_every_error_kind() {
        for kind in [
            ErrorKind::NotImplemented,
            ErrorKind::FrameTooLarge,
            ErrorKind::BadJson,
            ErrorKind::UnknownCmd,
            ErrorKind::BadArgs,
            ErrorKind::Internal,
        ] {
            let resp = Response::err(kind.clone(), format!("test {}", kind.as_str()));
            let bytes = resp.to_bytes();
            let back = Response::from_bytes(&bytes).unwrap();
            match back {
                Response::Err(payload) => {
                    assert_eq!(payload.kind, kind);
                    assert!(payload.message.starts_with("test "));
                }
                Response::Ok(_) => panic!("expected err"),
            }
        }
    }

    #[test]
    fn session_ls_wire_shape_has_no_real_field() {
        // If a future refactor adds a `real` field to SessionEntry, this
        // test fires and the change becomes visible.
        let entry = SessionEntry {
            fake: "aB3xY".to_string(),
            entity_kind: "email".to_string(),
        };
        let value = serde_json::to_value(&entry).unwrap();
        assert!(value.get("fake").is_some());
        assert!(value.get("entity_kind").is_some());
        assert!(
            value.get("real").is_none(),
            "SessionEntry MUST NOT carry a `real` field on the wire; no secret value ever transits the control channel"
        );
        // Also assert the SessionLsData wrapper doesn't smuggle one in.
        let data = SessionLsData {
            entries: vec![entry],
        };
        let raw = serde_json::to_string(&data).unwrap();
        assert!(
            !raw.contains("\"real\""),
            "SessionLsData wire bytes MUST NOT contain a `real` field: {raw}"
        );
    }

    #[test]
    fn read_frame_refuses_frames_above_cap() {
        let too_big: usize = MAX_FRAME_BYTES + 1;
        let mut wire = Vec::new();
        wire.extend_from_slice(&(too_big as u32).to_be_bytes());
        // We don't need to actually supply the body; read_frame rejects
        // before reading it.
        let err = read_frame(&mut wire.as_slice()).unwrap_err();
        match err {
            ControlError::FrameTooLarge { actual, max } => {
                assert_eq!(actual, too_big);
                assert_eq!(max, MAX_FRAME_BYTES);
            }
            other => panic!("expected FrameTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn read_frame_refuses_pathological_u32_max() {
        // Same-user attacker sends a declared length of u32::MAX.
        // read_frame must reject BEFORE attempting to allocate 4 GiB.
        let mut wire = Vec::new();
        wire.extend_from_slice(&u32::MAX.to_be_bytes());
        let err = read_frame(&mut wire.as_slice()).unwrap_err();
        match err {
            ControlError::FrameTooLarge { actual, .. } => assert_eq!(actual, u32::MAX as usize),
            other => panic!("expected FrameTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn write_frame_refuses_frames_above_cap() {
        let body = vec![0u8; MAX_FRAME_BYTES + 1];
        let mut out = Vec::new();
        let err = write_frame(&mut out, &body).unwrap_err();
        assert!(matches!(err, ControlError::FrameTooLarge { .. }));
        assert!(
            out.is_empty(),
            "must not write any bytes if the frame is over-cap"
        );
    }

    #[test]
    fn frame_roundtrip_at_wire_boundary() {
        let body = vec![0x5au8; MAX_FRAME_BYTES];
        let mut wire = Vec::new();
        write_frame(&mut wire, &body).unwrap();
        let back = read_frame(&mut wire.as_slice()).unwrap();
        assert_eq!(back.len(), body.len());
        assert_eq!(back, body);
    }

    #[test]
    fn serve_one_status_end_to_end() {
        // Simulate a client-server exchange over an in-memory duplex.
        // We forge an in-memory read cursor + a write buffer wrapped
        // in a struct implementing Read + Write.
        struct Duplex {
            input: std::io::Cursor<Vec<u8>>,
            output: Vec<u8>,
        }
        impl std::io::Read for Duplex {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                self.input.read(buf)
            }
        }
        impl std::io::Write for Duplex {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.output.write(buf)
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let request_bytes = Request::Status.to_bytes();
        let mut wire = Vec::new();
        write_frame(&mut wire, &request_bytes).unwrap();

        let mut duplex = Duplex {
            input: std::io::Cursor::new(wire),
            output: Vec::new(),
        };
        serve_one(&mut duplex, |req| {
            assert_eq!(req, Request::Status);
            Response::ok(StatusData {
                running: true,
                pid: 1,
                uptime_secs: 0,
                version: "test".to_string(),
            })
        })
        .unwrap();

        // The output buffer holds the framed response.
        let response = read_frame(&mut duplex.output.as_slice()).unwrap();
        let parsed = Response::from_bytes(&response).unwrap();
        match parsed {
            Response::Ok(v) => {
                let data: StatusData = serde_json::from_value(v).unwrap();
                assert!(data.running);
            }
            Response::Err(e) => panic!("expected ok, got err: {e:?}"),
        }
    }

    #[test]
    fn serve_one_bad_json_returns_typed_error_not_crash() {
        struct Duplex {
            input: std::io::Cursor<Vec<u8>>,
            output: Vec<u8>,
        }
        impl std::io::Read for Duplex {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                self.input.read(buf)
            }
        }
        impl std::io::Write for Duplex {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.output.write(buf)
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        // Well-framed request with 8 bytes of gibberish body.
        let mut wire = Vec::new();
        write_frame(&mut wire, b"garbage!").unwrap();
        let mut duplex = Duplex {
            input: std::io::Cursor::new(wire),
            output: Vec::new(),
        };
        serve_one(&mut duplex, |_| panic!("handler must NOT run on bad JSON")).unwrap();

        let response = read_frame(&mut duplex.output.as_slice()).unwrap();
        match Response::from_bytes(&response).unwrap() {
            Response::Err(e) => {
                assert_eq!(e.kind, ErrorKind::BadJson);
                // The error message must NOT echo the offending body back.
                assert!(
                    !e.message.contains("garbage!"),
                    "bad-json error message MUST NOT echo the offending payload back: {}",
                    e.message
                );
            }
            Response::Ok(_) => panic!("expected err"),
        }
    }

    #[test]
    fn serve_one_unknown_cmd_returns_typed_error_not_bad_json() {
        struct Duplex {
            input: std::io::Cursor<Vec<u8>>,
            output: Vec<u8>,
        }
        impl std::io::Read for Duplex {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                self.input.read(buf)
            }
        }
        impl std::io::Write for Duplex {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.output.write(buf)
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let body = serde_json::to_vec(&serde_json::json!({ "cmd": "not-a-real-command" })).unwrap();
        let mut wire = Vec::new();
        write_frame(&mut wire, &body).unwrap();
        let mut duplex = Duplex {
            input: std::io::Cursor::new(wire),
            output: Vec::new(),
        };
        serve_one(&mut duplex, |_| {
            panic!("handler must NOT run on unknown cmd")
        })
        .unwrap();

        let response = read_frame(&mut duplex.output.as_slice()).unwrap();
        match Response::from_bytes(&response).unwrap() {
            Response::Err(e) => {
                // Explicit assertion: unknown-cmd is distinct from bad-json.
                assert_eq!(e.kind, ErrorKind::UnknownCmd);
                assert_ne!(e.kind, ErrorKind::BadJson);
            }
            Response::Ok(_) => panic!("expected err"),
        }
    }

    #[test]
    fn serve_one_frame_too_large_returns_typed_error_not_crash() {
        // Client declares a length prefix over the cap. Server must
        // return frame-too-large and not attempt to buffer the body.
        struct Duplex {
            input: std::io::Cursor<Vec<u8>>,
            output: Vec<u8>,
        }
        impl std::io::Read for Duplex {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                self.input.read(buf)
            }
        }
        impl std::io::Write for Duplex {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.output.write(buf)
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let mut wire = Vec::new();
        wire.extend_from_slice(&((MAX_FRAME_BYTES + 1) as u32).to_be_bytes());
        // No body bytes at all. The server must reject before reading them.
        let mut duplex = Duplex {
            input: std::io::Cursor::new(wire),
            output: Vec::new(),
        };
        serve_one(&mut duplex, |_| {
            panic!("handler must NOT run on oversize frame")
        })
        .unwrap();

        let response = read_frame(&mut duplex.output.as_slice()).unwrap();
        match Response::from_bytes(&response).unwrap() {
            Response::Err(e) => assert_eq!(e.kind, ErrorKind::FrameTooLarge),
            Response::Ok(_) => panic!("expected err"),
        }
    }
}
