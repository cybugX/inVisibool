//! Atom interning cache for the X11 backend.
//!
//! X11 atoms are per-server 32-bit integers that name concepts like
//! CLIPBOARD, UTF8_STRING, and INCR. Every atom must be interned via
//! `InternAtom` before it can be used in a request; we cache them
//! at connection setup so hot paths never round-trip to the server
//! for an atom lookup.

use x11rb::connection::Connection;
use x11rb::protocol::xproto::{Atom, ConnectionExt};

use crate::error::ClipboardError;

/// Every atom the X11 backend uses.
#[derive(Debug, Clone, Copy)]
pub(super) struct AtomTable {
    pub clipboard: Atom,
    pub utf8_string: Atom,
    pub string: Atom,
    pub targets: Atom,
    pub timestamp: Atom,
    pub incr: Atom,
    /// The property name we ask requesters to write our conversion
    /// replies to. Also the property name we ask owners to write
    /// their replies to when we read. Naming our own property lets
    /// us route concurrent conversions by property atom.
    pub invisibool_dest: Atom,
    /// Zero-length ChangeProperty(APPEND) on this atom is used
    /// solely to fetch a real server timestamp via the resulting
    /// PropertyNotify event's `time` field, so
    /// SetSelectionOwner can be called with a monotonically-real
    /// time rather than CURRENT_TIME (= 0). See write_text.
    pub invisibool_timestamp_fetch: Atom,
}

impl AtomTable {
    pub(super) fn intern<C: Connection>(conn: &C) -> Result<Self, ClipboardError> {
        Ok(Self {
            clipboard: intern_one(conn, b"CLIPBOARD")?,
            utf8_string: intern_one(conn, b"UTF8_STRING")?,
            string: intern_one(conn, b"STRING")?,
            targets: intern_one(conn, b"TARGETS")?,
            timestamp: intern_one(conn, b"TIMESTAMP")?,
            incr: intern_one(conn, b"INCR")?,
            invisibool_dest: intern_one(conn, b"INVISIBOOL_DEST")?,
            invisibool_timestamp_fetch: intern_one(conn, b"INVISIBOOL_TIMESTAMP_FETCH")?,
        })
    }
}

fn intern_one<C: Connection>(conn: &C, name: &[u8]) -> Result<Atom, ClipboardError> {
    let reply = conn
        .intern_atom(false, name)
        .map_err(|e| ClipboardError::SubscribeFailed(format!("intern_atom: {e}")))?
        .reply()
        .map_err(|e| ClipboardError::SubscribeFailed(format!("intern_atom reply: {e}")))?;
    Ok(reply.atom)
}
