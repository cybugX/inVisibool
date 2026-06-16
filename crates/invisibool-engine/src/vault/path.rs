//! Platform-appropriate default location for the vault file.
//!
//! Linux:   `$XDG_DATA_HOME/invisibool/vault.bin`
//!          (default `~/.local/share/invisibool/vault.bin`)
//! macOS:   `~/Library/Application Support/invisibool/vault.bin`
//! Windows: `%LOCALAPPDATA%\invisibool\data\vault.bin`
//!
//! `data_local_dir()` (not `data_dir()`) is the right choice on
//! Windows specifically because `data_dir()` returns the roaming
//! AppData folder, which Microsoft sync can replicate across devices.
//! A vault file synced through OneDrive defeats the per-device
//! keychain trust model (the local keychain on device A wouldn't
//! decrypt a vault written on device B). On Linux and macOS the two
//! return the same path.

use std::path::PathBuf;

use directories::ProjectDirs;

/// Default vault file path for the current user on the current
/// platform. Returns `None` only if no home directory can be resolved
/// (extremely rare; typically a malformed `$HOME` on Linux, or running
/// as a daemon with no user context).
///
/// Callers may override this with an explicit `--vault <path>` CLI
/// flag at M1; the default path is what `Vault::open` uses when no
/// override is supplied.
pub fn default_vault_path() -> Option<PathBuf> {
    let dirs = ProjectDirs::from("", "", "invisibool")?;
    Some(dirs.data_local_dir().join("vault.bin"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_vault_path_returns_some_on_a_machine_with_a_home_dir() {
        let path =
            default_vault_path().expect("the test runner should have a resolvable home directory");
        assert!(
            path.ends_with("vault.bin"),
            "default vault path should end with vault.bin, got {path:?}"
        );
    }

    #[test]
    fn default_vault_path_contains_the_invisibool_segment() {
        let path = default_vault_path().expect("home directory should resolve");
        let path_str = path.to_string_lossy();
        assert!(
            path_str.contains("invisibool"),
            "default vault path should contain 'invisibool' segment: {path_str}"
        );
    }
}
