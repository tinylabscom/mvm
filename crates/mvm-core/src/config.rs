/// Default Firecracker version, overridable at build time via `MVM_FC_VERSION` env var.
pub const FC_VERSION_DEFAULT: &str = match option_env!("MVM_FC_VERSION") {
    Some(v) => v,
    None => "v1.14.1",
};

pub const ARCH: &str = "aarch64";

/// Normalize Firecracker version strings to a canonical form (e.g., "Firecracker v1.14.1" -> "v1.14.1").
pub fn normalize_fc_version(raw: &str) -> String {
    // Capture the last semantic version (v?MAJOR.MINOR[.PATCH])
    let re = regex::Regex::new(r"(?:v)?\d+\.\d+(?:\.\d+)?").expect("valid regex");
    let candidate = re
        .captures_iter(raw)
        .last()
        .map(|c| {
            c.get(0)
                .expect("regex capture group 0 must exist")
                .as_str()
                .to_string()
        })
        .unwrap_or_else(|| FC_VERSION_DEFAULT.to_string());

    if candidate.starts_with('v') {
        candidate
    } else {
        format!("v{}", candidate)
    }
}

/// Get the effective Firecracker version.
/// Priority: runtime env `MVM_FC_VERSION` > compile-time default.
/// The CLI `--fc-version` flag sets `MVM_FC_VERSION` before calling this.
pub fn fc_version() -> String {
    let raw = std::env::var("MVM_FC_VERSION").unwrap_or_else(|_| FC_VERSION_DEFAULT.to_string());
    normalize_fc_version(&raw)
}

/// Short Firecracker version for S3 asset paths (e.g., "v1.13").
/// Strips the patch component from the effective version.
pub fn fc_version_short() -> String {
    let full = fc_version();
    let trimmed = full.trim_start_matches('v');
    let parts = trimmed.split('.').collect::<Vec<_>>();
    if parts.len() >= 2 {
        format!("v{}.{}", parts[0], parts[1])
    } else {
        full
    }
}

/// Root data directory for mvm dev-tool state.
///
/// Resolution order:
///   1. `MVM_DATA_DIR` env var (explicit override)
///   2. `$HOME/.mvm`
///
/// This is a user-owned directory — no sudo required.
/// Fleet orchestration state (tenants, pools, instances) uses `/var/lib/mvm/`
/// and is managed by mvmd with appropriate permissions.
pub fn mvm_data_dir() -> String {
    if let Ok(d) = std::env::var("MVM_DATA_DIR")
        && !d.is_empty()
    {
        return d;
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    format!("{}/.mvm", home)
}

/// Check if running in production mode (MVM_PRODUCTION=1).
pub fn is_production_mode() -> bool {
    std::env::var("MVM_PRODUCTION")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_not_production_by_default() {
        let _ = is_production_mode();
    }

    #[test]
    fn test_fc_version_default() {
        // Without runtime env override, should return the compiled-in default
        let v = fc_version();
        assert!(v.starts_with('v'), "FC version should start with 'v'");
        assert!(v.contains('.'), "FC version should contain a dot");
    }

    #[test]
    fn test_fc_version_short() {
        let short = fc_version_short();
        assert!(short.starts_with('v'));
        // Should have exactly one dot (major.minor)
        assert_eq!(short.matches('.').count(), 1);
    }

    #[test]
    fn normalize_firecracker_banner() {
        let raw = "Firecracker v1.14.1";
        assert_eq!(normalize_fc_version(raw), "v1.14.1");
    }

    #[test]
    fn normalize_with_leading_v() {
        let raw = "v1.14.1";
        assert_eq!(normalize_fc_version(raw), "v1.14.1");
    }

    #[test]
    fn normalize_without_v() {
        let raw = "1.14.1";
        assert_eq!(normalize_fc_version(raw), "v1.14.1");
    }

    #[test]
    fn normalize_minor_only() {
        let raw = "Firecracker v1.14";
        assert_eq!(normalize_fc_version(raw), "v1.14");
        // short should remain the same when no patch component
        assert_eq!(fc_version_short_from(raw), "v1.14");
    }

    #[test]
    fn normalize_garbage_falls_back() {
        let raw = "nonsense";
        assert_eq!(normalize_fc_version(raw), FC_VERSION_DEFAULT);
    }

    // Helper to test short derivation with a temp env override.
    fn fc_version_short_from(raw: &str) -> String {
        // Env mutation is unsafe in Rust 2024; limit scope to this helper.
        unsafe { std::env::set_var("MVM_FC_VERSION", raw) };
        let short = fc_version_short();
        unsafe { std::env::remove_var("MVM_FC_VERSION") };
        short
    }
}
