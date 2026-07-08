//! Stale-supervisor hint for LegacyMacos early-exit diagnostics.
//!
//! LegacyMacos source-checkout launches normally rebuild helpers before spawn. This
//! module only appends a fallback hint when a supervisor exits early and its
//! mtime still predates the running `mvmctl`.

use std::path::Path;
use std::time::SystemTime;

/// Modified-time of `p`, or `None` when it can't be read.
pub(crate) fn mtime_of(p: &Path) -> Option<SystemTime> {
    std::fs::metadata(p).and_then(|m| m.modified()).ok()
}

/// `Some(hint)` naming `rebuild_cmd` when the supervisor binary predates
/// `mvmctl` (the `cargo run` skew where only `mvmctl` was rebuilt); else `None`.
/// An unknown mtime on either side yields `None` — an installed release has
/// equal-or-newer mtimes, so we never nag there, and we don't guess.
pub(crate) fn stale_aux_binary_hint(
    bin_mtime: Option<SystemTime>,
    self_mtime: Option<SystemTime>,
    rebuild_cmd: &str,
) -> Option<String> {
    let (bin, me) = (bin_mtime?, self_mtime?);
    (bin < me).then(|| {
        format!(
            "The supervisor binary is older than mvmctl and may be stale — rebuild it: {rebuild_cmd}"
        )
    })
}

/// Compare `supervisor_path`'s mtime against the running executable's and return
/// the rebuild hint when the supervisor is older. Consulted on the boot path so
/// a stale per-VM binary is self-diagnosing instead of failing cryptically.
pub(crate) fn supervisor_stale_hint(supervisor_path: &Path, rebuild_cmd: &str) -> Option<String> {
    let self_mtime = std::env::current_exe().ok().as_deref().and_then(mtime_of);
    stale_aux_binary_hint(mtime_of(supervisor_path), self_mtime, rebuild_cmd)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn stale_aux_hint_fires_only_when_binary_predates_mvmctl() {
        let base = SystemTime::UNIX_EPOCH;
        let newer = base + Duration::from_secs(100);
        let cmd = "cargo build -p mvm-vm-host";

        // Binary older than mvmctl → hint naming the rebuild command.
        let hint = stale_aux_binary_hint(Some(base), Some(newer), cmd).expect("expected a hint");
        assert!(
            hint.contains(cmd),
            "hint must name the rebuild command: {hint}"
        );
        assert!(hint.contains("stale"));

        // At-least-as-new binary → no hint (installed release, equal mtimes).
        assert!(stale_aux_binary_hint(Some(newer), Some(base), cmd).is_none());
        assert!(stale_aux_binary_hint(Some(base), Some(base), cmd).is_none());

        // Unknown mtime on either side → no hint (don't guess).
        assert!(stale_aux_binary_hint(None, Some(newer), cmd).is_none());
        assert!(stale_aux_binary_hint(Some(base), None, cmd).is_none());
    }
}
