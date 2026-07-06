//! Privacy hints for clipboard writes.
//!
//! The four bools map onto the platform-specific clipboard-history
//! and cloud-sync opt-outs the backends will use:
//!
//! - `exclude_from_clipboard_history` -> Windows
//!   `CanIncludeInClipboardHistory=0` custom clipboard format.
//! - `exclude_from_cloud_sync` -> Windows
//!   `CanUploadToCloudClipboard=0` custom clipboard format.
//! - `exclude_from_screen_monitors` -> Windows
//!   `ExcludeClipboardContentFromMonitorProcessing` custom format.
//! - `macos_concealed_type` -> macOS `org.nspasteboard.ConcealedType`
//!   pasteboard type marker (a de-facto convention that compliant
//!   clipboard managers on macOS honor).
//!
//! The X11 backend ignores all four bools: X11 has no privacy-hint
//! concept in the protocol. The InMemory backend records all four
//! for harness inspection.
//!
//! # No `Default` impl
//!
//! This type deliberately has NO `Default`. All-false is the unsafe
//! posture, not a safe default. Every call site chooses between
//! `CONCEAL_ALL` (the daemon's default for its own writes) and
//! `NONE` (a deliberate public write); an accidental
//! `PrivacyHints::default()` will not compile.

/// Set of clipboard-write privacy hints.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrivacyHints {
    /// Ask compliant clipboard-history features to skip this write.
    pub exclude_from_clipboard_history: bool,
    /// Ask compliant cross-device clipboard-sync features to skip
    /// this write.
    pub exclude_from_cloud_sync: bool,
    /// Ask compliant screen-monitor / accessibility observers to
    /// skip this write.
    pub exclude_from_screen_monitors: bool,
    /// Attach the macOS `org.nspasteboard.ConcealedType` marker so
    /// compliant macOS clipboard managers treat this write as
    /// concealed.
    pub macos_concealed_type: bool,
}

impl PrivacyHints {
    /// Every hint on. The correct posture for every write the daemon
    /// makes: scrub replacements, restored real values, session-map
    /// entries the daemon shows on demand.
    pub const CONCEAL_ALL: Self = Self {
        exclude_from_clipboard_history: true,
        exclude_from_cloud_sync: true,
        exclude_from_screen_monitors: true,
        macos_concealed_type: true,
    };

    /// Every hint off. Reserved for callers that have deliberately
    /// decided the write is public. Deliberately named so the choice
    /// is visible in code review.
    pub const NONE: Self = Self {
        exclude_from_clipboard_history: false,
        exclude_from_cloud_sync: false,
        exclude_from_screen_monitors: false,
        macos_concealed_type: false,
    };

    /// `true` when at least one hint is set. The InMemory backend's
    /// leak-harness surface uses this to flag daemon writes that
    /// were made without any privacy hint at all.
    pub fn any(&self) -> bool {
        self.exclude_from_clipboard_history
            || self.exclude_from_cloud_sync
            || self.exclude_from_screen_monitors
            || self.macos_concealed_type
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conceal_all_sets_every_bool() {
        let h = PrivacyHints::CONCEAL_ALL;
        assert!(h.exclude_from_clipboard_history);
        assert!(h.exclude_from_cloud_sync);
        assert!(h.exclude_from_screen_monitors);
        assert!(h.macos_concealed_type);
        assert!(h.any());
    }

    #[test]
    fn none_leaves_every_bool_off() {
        let h = PrivacyHints::NONE;
        assert!(!h.exclude_from_clipboard_history);
        assert!(!h.exclude_from_cloud_sync);
        assert!(!h.exclude_from_screen_monitors);
        assert!(!h.macos_concealed_type);
        assert!(!h.any());
    }

    // The absence of Default is checked at compile time: uncommenting
    // the next line would fail to compile because PrivacyHints has
    // no Default impl.
    //
    //   let _hint = PrivacyHints::default();
}
