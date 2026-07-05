//! Control-socket path resolution.
//!
//! Resolution order (Linux):
//!   1. `$XDG_RUNTIME_DIR/invisibool/ctl.sock`
//!   2. `$XDG_STATE_HOME/invisibool/ctl.sock`
//!   3. `$HOME/.local/state/invisibool/ctl.sock`
//!
//! All entry points are pure over their `Option<&OsStr>` arguments
//! so tests exercise every branch on a single-user Linux runner
//! without env-var mutation races. The wrapper
//! [`default_control_paths`] reads real env vars and forwards.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use crate::error::ControlError;

/// The two paths this crate needs: the socket, and the single-
/// instance lock (colocated with the socket).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlPaths {
    pub socket: PathBuf,
    pub lock: PathBuf,
}

const SOCKET_FILENAME: &str = "ctl.sock";
const LOCK_FILENAME: &str = "ctl.lock";
const APP_SUBDIR: &str = "invisibool";

/// Resolve the paths using explicit env-var arguments.
pub fn resolve_from(
    xdg_runtime_dir: Option<&OsStr>,
    xdg_state_home: Option<&OsStr>,
    home: Option<&OsStr>,
) -> Result<ControlPaths, ControlError> {
    let base = pick_base_dir(xdg_runtime_dir, xdg_state_home, home)?;
    let app_dir = base.join(APP_SUBDIR);
    Ok(ControlPaths {
        socket: app_dir.join(SOCKET_FILENAME),
        lock: app_dir.join(LOCK_FILENAME),
    })
}

/// Resolve using the real environment.
pub fn default_control_paths() -> Result<ControlPaths, ControlError> {
    resolve_from(
        std::env::var_os("XDG_RUNTIME_DIR").as_deref(),
        std::env::var_os("XDG_STATE_HOME").as_deref(),
        std::env::var_os("HOME").as_deref(),
    )
}

fn pick_base_dir(
    xdg_runtime_dir: Option<&OsStr>,
    xdg_state_home: Option<&OsStr>,
    home: Option<&OsStr>,
) -> Result<PathBuf, ControlError> {
    // XDG spec: env-var values must be absolute and non-empty; otherwise
    // treat as unset.
    let usable = |v: Option<&OsStr>| -> Option<PathBuf> {
        let v = v?;
        if v.is_empty() {
            return None;
        }
        let p = Path::new(v);
        if !p.is_absolute() {
            return None;
        }
        Some(p.to_path_buf())
    };
    if let Some(runtime) = usable(xdg_runtime_dir) {
        return Ok(runtime);
    }
    if let Some(state) = usable(xdg_state_home) {
        return Ok(state);
    }
    if let Some(home) = usable(home) {
        return Ok(home.join(".local").join("state"));
    }
    Err(ControlError::NoSocketPath)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;

    fn os(s: &str) -> OsString {
        OsString::from(s)
    }

    #[test]
    fn prefers_xdg_runtime_dir_when_set() {
        let paths = resolve_from(
            Some(&os("/run/user/1000")),
            Some(&os("/home/u/.local/state")),
            Some(&os("/home/u")),
        )
        .unwrap();
        assert_eq!(
            paths.socket,
            PathBuf::from("/run/user/1000/invisibool/ctl.sock")
        );
        assert_eq!(
            paths.lock,
            PathBuf::from("/run/user/1000/invisibool/ctl.lock")
        );
    }

    #[test]
    fn falls_back_to_xdg_state_home_when_runtime_dir_unset() {
        let paths = resolve_from(
            None,
            Some(&os("/home/u/.local/state")),
            Some(&os("/home/u")),
        )
        .unwrap();
        assert_eq!(
            paths.socket,
            PathBuf::from("/home/u/.local/state/invisibool/ctl.sock")
        );
    }

    #[test]
    fn falls_back_to_home_default_when_both_xdg_unset() {
        let paths = resolve_from(None, None, Some(&os("/home/u"))).unwrap();
        assert_eq!(
            paths.socket,
            PathBuf::from("/home/u/.local/state/invisibool/ctl.sock")
        );
    }

    #[test]
    fn returns_no_socket_path_when_everything_unset() {
        let err = resolve_from(None, None, None).unwrap_err();
        assert!(matches!(err, ControlError::NoSocketPath));
    }

    #[test]
    fn treats_relative_or_empty_env_vars_as_unset() {
        // XDG spec: relative paths and empty strings must be ignored.
        let paths = resolve_from(
            Some(&os("")),
            Some(&os("relative/path")),
            Some(&os("/home/u")),
        )
        .unwrap();
        // Both XDG values were unusable; fell through to HOME.
        assert_eq!(
            paths.socket,
            PathBuf::from("/home/u/.local/state/invisibool/ctl.sock")
        );
    }
}
