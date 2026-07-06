//! Display-server detection for gating `watch` on Linux.
//!
//! The `watch` daemon needs private-clipboard-format hints and a
//! cross-application clipboard change listener. Wayland's core
//! protocol exposes neither: some compositors ship extensions
//! (`ext-data-control-v1` and its predecessors) that fill part of
//! the gap, but they are not supported in this version. The daemon
//! detects Wayland and refuses at startup; the terminal
//! scrub/restore paths are unaffected.
//!
//! Detection order for Linux:
//!   1. `WAYLAND_DISPLAY` set and non-empty -> `Wayland`. This wins
//!      even when `DISPLAY` is also set (the XWayland case: an X11
//!      client running through a Wayland compositor's translation
//!      layer sees both, but the underlying clipboard is Wayland's).
//!   2. `XDG_SESSION_TYPE=wayland` -> `Wayland`.
//!   3. `DISPLAY` set and non-empty -> `X11`.
//!   4. `XDG_SESSION_TYPE=x11` -> `X11`.
//!   5. Neither `DISPLAY` nor `WAYLAND_DISPLAY` set and no
//!      `XDG_SESSION_TYPE` we recognise -> `Headless`.
//!
//! The env-var-based approach is spoofable by a same-user attacker
//! who sets `WAYLAND_DISPLAY=`, but such an attacker is already
//! inside the declared trust boundary (they can command the daemon
//! directly). The failure mode of a successful spoof is a daemon
//! that starts on X11 despite really being on Wayland, then fails
//! at the first clipboard call; there is no leak.
//!
//! Windows and macOS are always `NativeDesktop` and never consult
//! env vars.

use std::ffi::OsStr;

/// Which display server the daemon should target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisplayServer {
    /// X11 (real or a compositor's XWayland if we could not detect
    /// the compositor). The X11 clipboard backend takes over.
    X11,
    /// A native Wayland session. The daemon refuses to start.
    Wayland,
    /// No display server detected. The daemon refuses to start.
    Headless,
    /// Windows or macOS. The OS-native clipboard backend takes over.
    NativeDesktop,
}

/// Detect the current display server. Reads real environment
/// variables on Linux; returns `NativeDesktop` unconditionally on
/// Windows and macOS.
#[cfg(target_os = "linux")]
pub fn detect_display_server() -> DisplayServer {
    detect_display_server_from(
        std::env::var_os("WAYLAND_DISPLAY").as_deref(),
        std::env::var_os("XDG_SESSION_TYPE").as_deref(),
        std::env::var_os("DISPLAY").as_deref(),
    )
}

#[cfg(not(target_os = "linux"))]
pub fn detect_display_server() -> DisplayServer {
    DisplayServer::NativeDesktop
}

/// Pure resolver used by tests and by the real entry point.
pub fn detect_display_server_from(
    wayland_display: Option<&OsStr>,
    xdg_session_type: Option<&OsStr>,
    display: Option<&OsStr>,
) -> DisplayServer {
    let non_empty = |v: Option<&OsStr>| v.map(|s| !s.is_empty()).unwrap_or(false);

    // 1. WAYLAND_DISPLAY wins even when DISPLAY is set: this is the
    //    XWayland case, where the X server exists but the underlying
    //    clipboard is Wayland's.
    if non_empty(wayland_display) {
        return DisplayServer::Wayland;
    }

    // 2. XDG_SESSION_TYPE=wayland: an explicit session type.
    if xdg_session_type == Some(OsStr::new("wayland")) {
        return DisplayServer::Wayland;
    }

    // 3. DISPLAY set and non-empty -> X11.
    if non_empty(display) {
        return DisplayServer::X11;
    }

    // 4. XDG_SESSION_TYPE=x11 -> X11 (rare in practice because a
    //    real X11 session sets DISPLAY, but harmless to honor).
    if xdg_session_type == Some(OsStr::new("x11")) {
        return DisplayServer::X11;
    }

    // 5. Fall through: no display server we can talk to.
    DisplayServer::Headless
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;

    fn os(s: &str) -> OsString {
        OsString::from(s)
    }

    #[test]
    fn wayland_via_wayland_display_env_var() {
        // Case 1: WAYLAND_DISPLAY set, DISPLAY unset.
        assert_eq!(
            detect_display_server_from(Some(&os("wayland-0")), None, None),
            DisplayServer::Wayland,
        );
    }

    #[test]
    fn wayland_via_xdg_session_type() {
        // Case 2: XDG_SESSION_TYPE=wayland, WAYLAND_DISPLAY unset.
        assert_eq!(
            detect_display_server_from(None, Some(&os("wayland")), None),
            DisplayServer::Wayland,
        );
    }

    #[test]
    fn xwayland_still_refuses_wayland_display_wins_over_display() {
        // Case 3: an XWayland client sees both DISPLAY and
        // WAYLAND_DISPLAY set. The underlying clipboard is Wayland's,
        // so WAYLAND_DISPLAY wins and we refuse.
        assert_eq!(
            detect_display_server_from(
                Some(&os("wayland-0")),
                Some(&os("wayland")),
                Some(&os(":0")),
            ),
            DisplayServer::Wayland,
        );
    }

    #[test]
    fn x11_via_display_env_var() {
        // Case 4: real X11 session with DISPLAY set, no
        // WAYLAND_DISPLAY.
        assert_eq!(
            detect_display_server_from(None, None, Some(&os(":0"))),
            DisplayServer::X11,
        );
        // Same with XDG_SESSION_TYPE=x11 for completeness.
        assert_eq!(
            detect_display_server_from(None, Some(&os("x11")), Some(&os(":0"))),
            DisplayServer::X11,
        );
    }

    #[test]
    fn x11_via_xdg_session_type_when_display_unset() {
        // Case 5: XDG_SESSION_TYPE=x11 with no DISPLAY. Rare but
        // permitted; keeps the resolver forgiving.
        assert_eq!(
            detect_display_server_from(None, Some(&os("x11")), None),
            DisplayServer::X11,
        );
    }

    #[test]
    fn headless_when_no_display_env_at_all() {
        // Case 6: nothing set. SSH into a headless server; a
        // container without display forwarding; a systemd unit.
        assert_eq!(
            detect_display_server_from(None, None, None),
            DisplayServer::Headless,
        );
    }

    #[test]
    fn empty_env_var_values_do_not_count_as_set() {
        // WAYLAND_DISPLAY="" and DISPLAY="" are functionally unset
        // and fall through to Headless.
        assert_eq!(
            detect_display_server_from(Some(&os("")), None, Some(&os(""))),
            DisplayServer::Headless,
        );
    }

    #[test]
    fn xdg_session_type_case_sensitive_wayland_uppercase_ignored() {
        // The systemd/logind convention is lowercase. Uppercase
        // variants are not honored; the resolver falls through.
        assert_eq!(
            detect_display_server_from(None, Some(&os("Wayland")), None),
            DisplayServer::Headless,
        );
        assert_eq!(
            detect_display_server_from(None, Some(&os("WAYLAND")), None),
            DisplayServer::Headless,
        );
    }
}
