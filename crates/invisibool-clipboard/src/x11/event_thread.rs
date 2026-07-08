//! Event-reader thread.
//!
//! Owns the exclusive `wait_for_event` loop on the shared X
//! connection. Dispatches each event to:
//!
//! - `XFixesSelectionNotify`: emit a `ClipboardEvent` on the
//!   dispatcher channel (self-write suppression via owner-window
//!   comparison), and bump the shared change_count.
//! - `SelectionNotify` on our window: satisfy a pending read from
//!   the pending-read registry. Handles plain, multi-part
//!   (`bytes_after > 0`), and INCR-typed replies. INCR-typed
//!   promotes the pending read into the INCR-receive tracker.
//! - `PropertyNotify(NewValue)` on our window: feed the INCR
//!   receiver. Zero-length property = end of transfer.
//! - `SelectionRequest` on our window: answer per ICCCM. Supports
//!   `UTF8_STRING`, `STRING`, `TARGETS`, `TIMESTAMP`; refuses
//!   `MULTIPLE` and unknown targets with property = None. Large
//!   content is served via INCR (owner side); the INCR sender
//!   state is tracked per (requestor window, property atom).
//! - `PropertyNotify(Deleted)` on a REQUESTOR window: signal that
//!   the requester has consumed the previous INCR chunk and is
//!   ready for the next; send it.
//! - `SelectionClear` on our window: another client took the
//!   selection; drop our owned content.
//!
//! Shutdown: another thread sets `inner.shutdown = true` and sends
//! itself a `NoOperation` request. `wait_for_event` returns; we
//! observe the flag and exit.

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Instant;

use x11rb::connection::Connection;
use x11rb::protocol::xfixes::SelectionNotifyEvent as XfixesSelectionNotify;
use x11rb::protocol::xproto::{
    Atom, AtomEnum, ChangeWindowAttributesAux, ConnectionExt, EventMask, GetPropertyReply,
    PropMode, Property, PropertyNotifyEvent, SelectionNotifyEvent, SelectionRequestEvent, Window,
    SELECTION_NOTIFY_EVENT,
};
use x11rb::protocol::Event;
use x11rb::wrapper::ConnectionExt as _;
use zeroize::Zeroizing;

use crate::error::ClipboardError;
use crate::ClipboardEvent;

use super::dispatcher::DispatchSender;
use super::pending::{
    IncrReceive, IncrSend, INCR_CHUNK_TIMEOUT, MAX_CLIPBOARD_BYTES, OWNER_INCR_CHUNK_SIZE,
    OWNER_SINGLE_SHOT_CAP,
};
use super::state::X11Inner;

pub(super) fn run(inner: Arc<X11Inner>, dispatch: DispatchSender) {
    // Watchdog thread: fires INCR-timeout sweeps periodically without
    // needing the event thread to wake. Cheap because it only touches
    // the two INCR hashmaps.
    let watchdog_inner = inner.clone();
    let _watchdog = std::thread::spawn(move || {
        while !watchdog_inner.shutdown.load(Ordering::SeqCst) {
            std::thread::sleep(std::time::Duration::from_millis(100));
            sweep_incr_receive_timeouts(&watchdog_inner);
            sweep_incr_send_timeouts(&watchdog_inner);
        }
    });

    // The event thread uses wait_for_event so replies to requests
    // WE send while inside a handler are not raced by a concurrent
    // reader consuming socket bytes at the wrong time. Shutdown wake:
    // Drop of X11Clipboard sends a NoOperation which forces a socket
    // round-trip; the shutdown flag flip is then noticed on the next
    // event or on the connection tearing down.
    loop {
        if inner.shutdown.load(Ordering::SeqCst) {
            break;
        }
        match inner.conn.wait_for_event() {
            Ok(event) => handle_event(&inner, &dispatch, event),
            Err(_) => break,
        }
    }
    dispatch.signal_shutdown();
}

fn handle_event(inner: &Arc<X11Inner>, dispatch: &DispatchSender, event: Event) {
    match event {
        Event::XfixesSelectionNotify(ev) => handle_xfixes_selection_notify(inner, dispatch, ev),
        Event::SelectionNotify(ev) => handle_selection_notify(inner, ev),
        Event::SelectionRequest(ev) => handle_selection_request(inner, ev),
        Event::PropertyNotify(ev) => handle_property_notify(inner, ev),
        Event::SelectionClear(ev) if ev.selection == inner.atoms.clipboard => {
            *inner.owned.lock().expect("owned poisoned") = None;
        }
        _ => {}
    }
}

fn handle_xfixes_selection_notify(
    inner: &Arc<X11Inner>,
    dispatch: &DispatchSender,
    ev: XfixesSelectionNotify,
) {
    if ev.selection != inner.atoms.clipboard {
        return;
    }
    let cc = inner.bump_change_count();
    let (matches_our_write, owned_token) = {
        let owned = inner.owned.lock().expect("owned poisoned");
        let token = owned.as_ref().map(|c| c.token);
        (ev.owner == inner.our_window, token)
    };
    dispatch.send_event(ClipboardEvent {
        change_count: cc,
        matches_our_write: if matches_our_write { owned_token } else { None },
    });
}

fn handle_selection_notify(inner: &Arc<X11Inner>, ev: SelectionNotifyEvent) {
    // A SelectionNotify with property = None means the owner refused.
    let dest_property = if ev.property == x11rb::NONE {
        // Look up whichever pending read used INVISIBOOL_DEST and
        // complete it with Ok(None) - refused conversion is not
        // an error, it just means "no text there".
        inner.atoms.invisibool_dest
    } else {
        ev.property
    };
    let pending = {
        let mut g = inner.pending_reads.lock().expect("pending_reads poisoned");
        g.remove(&dest_property)
    };
    let Some(pending) = pending else {
        return;
    };

    if ev.property == x11rb::NONE {
        pending.complete(Ok(None));
        return;
    }

    // Peek WITHOUT delete first so we can classify (INCR vs plain)
    // without destroying content on the plain path (which was racing
    // xclip on a subtle x11rb+CURRENT_TIME timing issue). Then read
    // with delete=true for the actual retrieval.
    let peek = match get_property(inner, ev.requestor, ev.property, false, 0, 8) {
        Ok(r) => r,
        Err(e) => {
            pending.complete(Err(e));
            return;
        }
    };

    if peek.type_ == inner.atoms.incr {
        // Cap check on the announced size hint (if provided).
        // peek.value carries the total size as one u32 in the INCR
        // reply. If the hint exceeds cap we can fail-closed now
        // rather than accumulate.
        if peek.value.len() >= 4 {
            let hint_bytes = [peek.value[0], peek.value[1], peek.value[2], peek.value[3]];
            let hint = u32::from_ne_bytes(hint_bytes) as usize;
            if hint > MAX_CLIPBOARD_BYTES {
                pending.complete(Err(ClipboardError::ReadFailed(
                    "clipboard content exceeds the 8 MiB limit; not scrubbed".to_string(),
                )));
                return;
            }
        }
        // Register the receive slot BEFORE deleting the marker
        // property, so any race that puts a PropertyNotify(NewValue)
        // ahead of our registration is handled correctly.
        pending.set_incr_in_progress();
        {
            let mut g = inner.incr_receives.lock().expect("incr_receives poisoned");
            g.insert(
                dest_property,
                IncrReceive {
                    pending,
                    accumulated: Zeroizing::new(Vec::new()),
                    last_chunk_at: Instant::now(),
                },
            );
        }
        // Delete the marker to signal to the owner: "ready to receive
        // the first data chunk." The owner then sends the next
        // chunk via ChangeProperty, which fires PropertyNotify(NewValue)
        // on our window; handle_incr_receive_chunk accumulates.
        let _ = inner.conn.delete_property(inner.our_window, dest_property);
        let _ = inner.conn.flush();
        return;
    }

    // Plain path. If bytes_after > 0 the payload straddles our
    // receive buffer; loop reading offsets.
    let mut accumulated: Zeroizing<Vec<u8>> = Zeroizing::new(peek.value.clone());
    let mut bytes_after = peek.bytes_after as usize;
    let mut offset = accumulated.len();
    while bytes_after > 0 {
        if accumulated.len() + bytes_after > MAX_CLIPBOARD_BYTES {
            pending.complete(Err(ClipboardError::ReadFailed(
                "clipboard content exceeds the 8 MiB limit; not scrubbed".to_string(),
            )));
            return;
        }
        let next = match get_property(
            inner,
            ev.requestor,
            ev.property,
            false,
            (offset / 4) as u32,
            (MAX_CLIPBOARD_BYTES / 4) as u32,
        ) {
            Ok(r) => r,
            Err(e) => {
                pending.complete(Err(e));
                return;
            }
        };
        accumulated.extend_from_slice(&next.value);
        offset = accumulated.len();
        bytes_after = next.bytes_after as usize;
    }

    complete_plain_read(pending, accumulated);
}

fn complete_plain_read(pending: Arc<super::pending::PendingRead>, buf: Zeroizing<Vec<u8>>) {
    match std::str::from_utf8(&buf) {
        Ok(s) => {
            let z = Zeroizing::new(s.to_string());
            pending.complete(Ok(Some(z)));
        }
        Err(_) => pending.complete(Err(ClipboardError::ReadFailed(
            "clipboard content was not valid UTF-8".to_string(),
        ))),
    }
}

fn handle_property_notify(inner: &Arc<X11Inner>, ev: PropertyNotifyEvent) {
    // Timestamp-fetch rendezvous: our write_text triggered a zero-
    // length ChangeProperty(APPEND) on this atom purely to get a
    // real server timestamp via `ev.time`. Fill the slot and wake
    // the waiter; do NOT proceed to INCR handling for this event.
    if ev.window == inner.our_window && ev.atom == inner.atoms.invisibool_timestamp_fetch {
        let mut g = inner
            .pending_timestamp
            .lock()
            .expect("pending_timestamp poisoned");
        if let Some(slot @ None) = g.as_mut() {
            *slot = Some(ev.time);
            drop(g);
            inner.pending_timestamp_cond.notify_all();
        }
        return;
    }
    match ev.state {
        Property::NEW_VALUE if ev.window == inner.our_window => {
            handle_incr_receive_chunk(inner, ev.atom);
        }
        Property::DELETE => {
            // Owner-side INCR: a requester deleted the property we
            // set, signalling ready for the next chunk.
            let key = (ev.window, ev.atom);
            let has_send = inner
                .incr_sends
                .lock()
                .expect("incr_sends poisoned")
                .contains_key(&key);
            if has_send {
                serve_next_incr_chunk(inner, key);
            }
        }
        _ => {}
    }
}

fn handle_incr_receive_chunk(inner: &Arc<X11Inner>, property: Atom) {
    // ONLY react if we have an active INCR receive for this property.
    // Without this gate, every PropertyNotify(NewValue) on our window
    // - including the ChangeProperty from an owner's plain-path
    // conversion reply - would trigger a delete-during-read and race
    // the SelectionNotify handler, leaving the property empty by
    // the time it is peeked. Regression: chunk-24 integration tests
    // returned Ok(Some("")) without this gate.
    {
        let g = inner.incr_receives.lock().expect("incr_receives poisoned");
        if !g.contains_key(&property) {
            return;
        }
    }
    let peek = match get_property(
        inner,
        inner.our_window,
        property,
        true,
        0,
        (MAX_CLIPBOARD_BYTES / 4) as u32,
    ) {
        Ok(r) => r,
        Err(e) => {
            // Fail the receive with an error.
            let entry = inner
                .incr_receives
                .lock()
                .expect("incr_receives poisoned")
                .remove(&property);
            if let Some(entry) = entry {
                entry.pending.complete(Err(e));
            }
            return;
        }
    };

    if peek.value.is_empty() {
        // End of transfer.
        let entry = inner
            .incr_receives
            .lock()
            .expect("incr_receives poisoned")
            .remove(&property);
        if let Some(mut entry) = entry {
            // Any remaining bytes_after on a zero-length event is
            // ignored per ICCCM.
            let buf = std::mem::take(&mut entry.accumulated);
            complete_plain_read(entry.pending, buf);
        }
        return;
    }

    let mut g = inner.incr_receives.lock().expect("incr_receives poisoned");
    let Some(entry) = g.get_mut(&property) else {
        return;
    };
    // Cap enforcement: refuse rather than truncate.
    if entry.accumulated.len() + peek.value.len() > MAX_CLIPBOARD_BYTES {
        let entry = g.remove(&property).unwrap();
        entry.pending.complete(Err(ClipboardError::ReadFailed(
            "clipboard content exceeds the 8 MiB limit; not scrubbed".to_string(),
        )));
        return;
    }
    entry.accumulated.extend_from_slice(&peek.value);
    entry.last_chunk_at = Instant::now();
}

fn handle_selection_request(inner: &Arc<X11Inner>, ev: SelectionRequestEvent) {
    let atoms = &inner.atoms;
    let notify_property;
    let notify_target = ev.target;

    // MULTIPLE: refused per design.
    // TARGETS: reply with the list.
    if ev.target == atoms.targets {
        let targets: [Atom; 4] = [
            atoms.utf8_string,
            atoms.string,
            atoms.targets,
            atoms.timestamp,
        ];
        if inner
            .conn
            .change_property32(
                PropMode::REPLACE,
                ev.requestor,
                ev.property,
                AtomEnum::ATOM,
                &targets,
            )
            .is_ok()
        {
            notify_property = ev.property;
        } else {
            notify_property = x11rb::NONE;
        }
        return send_selection_notify(inner, &ev, notify_target, notify_property);
    }

    // TIMESTAMP: reply with our acquisition timestamp.
    if ev.target == atoms.timestamp {
        let ts = {
            let g = inner.owned.lock().expect("owned poisoned");
            match g.as_ref() {
                Some(c) => c.acquired_at,
                None => {
                    return send_selection_notify(inner, &ev, notify_target, x11rb::NONE);
                }
            }
        };
        let ok = inner
            .conn
            .change_property32(
                PropMode::REPLACE,
                ev.requestor,
                ev.property,
                AtomEnum::INTEGER,
                &[ts],
            )
            .is_ok();
        notify_property = if ok { ev.property } else { x11rb::NONE };
        return send_selection_notify(inner, &ev, notify_target, notify_property);
    }

    // UTF8_STRING / STRING: serve the content.
    if ev.target == atoms.utf8_string || ev.target == atoms.string {
        let content_snapshot = {
            let g = inner.owned.lock().expect("owned poisoned");
            g.as_ref().map(|c| c.text.as_str().to_string())
        };
        let Some(text) = content_snapshot else {
            return send_selection_notify(inner, &ev, notify_target, x11rb::NONE);
        };
        let bytes = text.as_bytes();

        if bytes.len() <= OWNER_SINGLE_SHOT_CAP {
            let ok = change_property_u8(inner, ev.requestor, ev.property, atoms.utf8_string, bytes)
                .is_ok();
            let notify_property = if ok { ev.property } else { x11rb::NONE };
            return send_selection_notify(inner, &ev, notify_target, notify_property);
        }

        // Owner-side INCR.
        // Watch PropertyChange events on the requestor so we see it
        // delete the property after each chunk.
        let _ = inner.conn.change_window_attributes(
            ev.requestor,
            &ChangeWindowAttributesAux::new().event_mask(EventMask::PROPERTY_CHANGE),
        );

        // Set property type = INCR, format 32, value = total size hint.
        let size_hint = [bytes.len() as u32];
        let ok = inner
            .conn
            .change_property32(
                PropMode::REPLACE,
                ev.requestor,
                ev.property,
                atoms.incr,
                &size_hint,
            )
            .is_ok();
        if !ok {
            return send_selection_notify(inner, &ev, notify_target, x11rb::NONE);
        }

        // Register the INCR send state before flushing the notify
        // so the property-deleted event we may see next is
        // recognised.
        let owned_snapshot = {
            let g = inner.owned.lock().expect("owned poisoned");
            g.as_ref().map(|c| c.text.clone())
        };
        if let Some(text) = owned_snapshot {
            let content = Arc::new(text);
            let mut g = inner.incr_sends.lock().expect("incr_sends poisoned");
            g.insert(
                (ev.requestor, ev.property),
                IncrSend {
                    content,
                    next_offset: 0,
                    timestamp: ev.time,
                    target_property: ev.property,
                    requestor: ev.requestor,
                    target: atoms.utf8_string,
                    started_at: Instant::now(),
                },
            );
        }

        return send_selection_notify(inner, &ev, notify_target, ev.property);
    }

    // MULTIPLE and unknown targets: refuse.
    send_selection_notify(inner, &ev, notify_target, x11rb::NONE);
}

fn serve_next_incr_chunk(inner: &Arc<X11Inner>, key: (Window, Atom)) {
    let (chunk, finished) = {
        let mut g = inner.incr_sends.lock().expect("incr_sends poisoned");
        let Some(entry) = g.get_mut(&key) else {
            return;
        };
        let bytes = entry.content.as_bytes();
        let remaining = bytes.len().saturating_sub(entry.next_offset);
        if remaining == 0 {
            // Send zero-length terminator, then remove entry.
            let _ = change_property_u8(
                inner,
                entry.requestor,
                entry.target_property,
                entry.target,
                &[],
            );
            let _ = inner.conn.flush();
            let _ = g.remove(&key);
            return;
        }
        let take = remaining.min(OWNER_INCR_CHUNK_SIZE);
        let end = entry.next_offset + take;
        let chunk = bytes[entry.next_offset..end].to_vec();
        entry.next_offset = end;
        let done_after = end >= bytes.len();
        (chunk, done_after)
    };

    let _ = change_property_u8(inner, key.0, key.1, inner.atoms.utf8_string, &chunk);
    let _ = inner.conn.flush();

    if finished {
        // Zero-length terminator will be sent on next PropertyNotify(delete).
        // Nothing to do here.
        let _ = finished;
    }
}

fn sweep_incr_receive_timeouts(inner: &Arc<X11Inner>) {
    let now = Instant::now();
    let mut to_fail: Vec<Atom> = Vec::new();
    {
        let g = inner.incr_receives.lock().expect("incr_receives poisoned");
        for (atom, entry) in g.iter() {
            if now.duration_since(entry.last_chunk_at) > INCR_CHUNK_TIMEOUT {
                to_fail.push(*atom);
            }
        }
    }
    if to_fail.is_empty() {
        return;
    }
    let mut g = inner.incr_receives.lock().expect("incr_receives poisoned");
    for atom in to_fail {
        if let Some(entry) = g.remove(&atom) {
            entry.pending.complete(Err(ClipboardError::ReadFailed(
                "clipboard owner did not send the next chunk within the timeout".to_string(),
            )));
        }
    }
}

fn sweep_incr_send_timeouts(inner: &Arc<X11Inner>) {
    // Give owner-side INCR sends 10s to drain before we assume the
    // requestor abandoned the transfer.
    let now = Instant::now();
    let mut g = inner.incr_sends.lock().expect("incr_sends poisoned");
    g.retain(|_, entry| now.duration_since(entry.started_at) < std::time::Duration::from_secs(10));
}

fn send_selection_notify(
    inner: &Arc<X11Inner>,
    request: &SelectionRequestEvent,
    target: Atom,
    property: Atom,
) {
    let notify = SelectionNotifyEvent {
        response_type: SELECTION_NOTIFY_EVENT,
        sequence: 0,
        time: request.time,
        requestor: request.requestor,
        selection: request.selection,
        target,
        property,
    };
    let _ = inner
        .conn
        .send_event(false, request.requestor, EventMask::NO_EVENT, notify);
    let _ = inner.conn.flush();
}

fn get_property(
    inner: &Arc<X11Inner>,
    window: Window,
    property: Atom,
    delete: bool,
    long_offset: u32,
    long_length: u32,
) -> Result<GetPropertyReply, ClipboardError> {
    inner
        .conn
        .get_property(
            delete,
            window,
            property,
            AtomEnum::ANY,
            long_offset,
            long_length,
        )
        .map_err(|e| ClipboardError::ReadFailed(format!("get_property send: {e}")))?
        .reply()
        .map_err(|e| ClipboardError::ReadFailed(format!("get_property reply: {e}")))
}

fn change_property_u8(
    inner: &Arc<X11Inner>,
    window: Window,
    property: Atom,
    type_atom: Atom,
    bytes: &[u8],
) -> Result<(), ClipboardError> {
    inner
        .conn
        .change_property(
            PropMode::REPLACE,
            window,
            property,
            type_atom,
            8,
            bytes.len() as u32,
            bytes,
        )
        .map_err(|e| ClipboardError::WriteFailed(format!("change_property send: {e}")))?;
    Ok(())
}
