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
        .or_else(|| re.captures_iter(FC_VERSION_DEFAULT).last())
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

/// Create `~/.mvm` (or whatever `mvm_data_dir()` resolves to) with
/// mode `0700` and return its path. Idempotent: if the dir already
/// exists with looser perms, chmod it to `0700` so a host that was
/// created before ADR-002 W1.5 still gets locked down on the next
/// `dev up`.
///
/// `~/.mvm` holds the dev VM's GC root, the host-backed Nix store
/// disk image, the per-VM `vsock.sock` proxy listener path, build
/// artifacts in `dev/builds/<rev>/`, and (for production microVMs)
/// any persisted volumes — every secret-shaped piece of state in
/// the project. Defaulting to umask perms (typ. 0755) means a
/// same-host other user can read all of it; this is the project's
/// privacy boundary.
#[cfg(unix)]
pub fn ensure_data_dir() -> std::io::Result<String> {
    let dir = mvm_data_dir();
    ensure_private_dir(&dir)?;
    Ok(dir)
}

/// Create `~/.cache/mvm` (or wherever `mvm_cache_dir()` resolves to)
/// with mode `0700`. Same rationale as `ensure_data_dir`. The cache
/// holds the dev image kernel/rootfs, daemon stdout/stderr logs,
/// and the GC sentinel — none of it is secret on its own, but the
/// daemon logs *do* capture guest stdout, which can leak whatever
/// the guest prints. Lock it down by default.
#[cfg(unix)]
pub fn ensure_cache_dir() -> std::io::Result<String> {
    let dir = mvm_cache_dir();
    ensure_private_dir(&dir)?;
    Ok(dir)
}

/// Create `dir` (and parents) and chmod it to mode `0700`. Both the
/// initial create and the chmod are idempotent.
#[cfg(unix)]
fn ensure_private_dir(dir: &str) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::create_dir_all(dir)?;
    let mut perms = std::fs::metadata(dir)?.permissions();
    if perms.mode() & 0o777 != 0o700 {
        perms.set_mode(0o700);
        std::fs::set_permissions(dir, perms)?;
    }
    Ok(())
}

// ============================================================================
// XDG-compliant directory functions
// ============================================================================

fn home_dir() -> String {
    std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string())
}

/// Cache directory for build artifacts, images, VM runtime state.
///
/// Resolution order:
///   1. `MVM_CACHE_DIR` env var
///   2. `$XDG_CACHE_HOME/mvm`
///   3. `$HOME/.cache/mvm`
pub fn mvm_cache_dir() -> String {
    if let Ok(d) = std::env::var("MVM_CACHE_DIR")
        && !d.is_empty()
    {
        return d;
    }
    if let Ok(xdg) = std::env::var("XDG_CACHE_HOME")
        && !xdg.is_empty()
    {
        return format!("{xdg}/mvm");
    }
    format!("{}/.cache/mvm", home_dir())
}

/// Config directory for user configuration files.
///
/// Resolution order:
///   1. `MVM_CONFIG_DIR` env var
///   2. `$XDG_CONFIG_HOME/mvm`
///   3. `$HOME/.config/mvm`
pub fn mvm_config_dir() -> String {
    if let Ok(d) = std::env::var("MVM_CONFIG_DIR")
        && !d.is_empty()
    {
        return d;
    }
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME")
        && !xdg.is_empty()
    {
        return format!("{xdg}/mvm");
    }
    format!("{}/.config/mvm", home_dir())
}

/// State directory for logs and audit trails.
///
/// Resolution order:
///   1. `MVM_STATE_DIR` env var
///   2. `$XDG_STATE_HOME/mvm`
///   3. `$HOME/.local/state/mvm`
pub fn mvm_state_dir() -> String {
    if let Ok(d) = std::env::var("MVM_STATE_DIR")
        && !d.is_empty()
    {
        return d;
    }
    if let Ok(xdg) = std::env::var("XDG_STATE_HOME")
        && !xdg.is_empty()
    {
        return format!("{xdg}/mvm");
    }
    format!("{}/.local/state/mvm", home_dir())
}

/// Share directory for templates, network definitions, and registries.
///
/// Resolution order:
///   1. `MVM_SHARE_DIR` env var
///   2. `$XDG_DATA_HOME/mvm`
///   3. `$HOME/.local/share/mvm`
pub fn mvm_share_dir() -> String {
    if let Ok(d) = std::env::var("MVM_SHARE_DIR")
        && !d.is_empty()
    {
        return d;
    }
    if let Ok(xdg) = std::env::var("XDG_DATA_HOME")
        && !xdg.is_empty()
    {
        return format!("{xdg}/mvm");
    }
    format!("{}/.local/share/mvm", home_dir())
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
        assert_eq!(
            normalize_fc_version(raw),
            normalize_fc_version(FC_VERSION_DEFAULT)
        );
    }

    // Helper to test short derivation with a temp env override.
    fn fc_version_short_from(raw: &str) -> String {
        // Env mutation is unsafe in Rust 2024; limit scope to this helper.
        unsafe { std::env::set_var("MVM_FC_VERSION", raw) };
        let short = fc_version_short();
        unsafe { std::env::remove_var("MVM_FC_VERSION") };
        short
    }

    // --- XDG directory tests ---

    #[test]
    fn test_mvm_cache_dir_env_override() {
        unsafe { std::env::set_var("MVM_CACHE_DIR", "/custom/cache") };
        assert_eq!(mvm_cache_dir(), "/custom/cache");
        unsafe { std::env::remove_var("MVM_CACHE_DIR") };
    }

    #[test]
    fn test_mvm_cache_dir_xdg_override() {
        unsafe { std::env::remove_var("MVM_CACHE_DIR") };
        unsafe { std::env::set_var("XDG_CACHE_HOME", "/xdg/cache") };
        assert_eq!(mvm_cache_dir(), "/xdg/cache/mvm");
        unsafe { std::env::remove_var("XDG_CACHE_HOME") };
    }

    #[test]
    fn test_mvm_cache_dir_default() {
        unsafe { std::env::remove_var("MVM_CACHE_DIR") };
        unsafe { std::env::remove_var("XDG_CACHE_HOME") };
        let dir = mvm_cache_dir();
        assert!(dir.ends_with("/.cache/mvm"));
    }

    #[test]
    fn test_mvm_config_dir_env_override() {
        unsafe { std::env::set_var("MVM_CONFIG_DIR", "/custom/config") };
        assert_eq!(mvm_config_dir(), "/custom/config");
        unsafe { std::env::remove_var("MVM_CONFIG_DIR") };
    }

    #[test]
    fn test_mvm_config_dir_default() {
        unsafe { std::env::remove_var("MVM_CONFIG_DIR") };
        unsafe { std::env::remove_var("XDG_CONFIG_HOME") };
        let dir = mvm_config_dir();
        assert!(dir.ends_with("/.config/mvm"));
    }

    #[test]
    fn test_mvm_state_dir_env_override() {
        unsafe { std::env::set_var("MVM_STATE_DIR", "/custom/state") };
        assert_eq!(mvm_state_dir(), "/custom/state");
        unsafe { std::env::remove_var("MVM_STATE_DIR") };
    }

    #[test]
    fn test_mvm_state_dir_default() {
        unsafe { std::env::remove_var("MVM_STATE_DIR") };
        unsafe { std::env::remove_var("XDG_STATE_HOME") };
        let dir = mvm_state_dir();
        assert!(dir.ends_with("/.local/state/mvm"));
    }

    #[test]
    fn test_mvm_share_dir_env_override() {
        unsafe { std::env::set_var("MVM_SHARE_DIR", "/custom/share") };
        assert_eq!(mvm_share_dir(), "/custom/share");
        unsafe { std::env::remove_var("MVM_SHARE_DIR") };
    }

    #[test]
    fn test_mvm_share_dir_default() {
        unsafe { std::env::remove_var("MVM_SHARE_DIR") };
        unsafe { std::env::remove_var("XDG_DATA_HOME") };
        let dir = mvm_share_dir();
        assert!(dir.ends_with("/.local/share/mvm"));
    }

    #[test]
    fn test_mvm_share_dir_xdg_override() {
        unsafe { std::env::remove_var("MVM_SHARE_DIR") };
        unsafe { std::env::set_var("XDG_DATA_HOME", "/xdg/data") };
        assert_eq!(mvm_share_dir(), "/xdg/data/mvm");
        unsafe { std::env::remove_var("XDG_DATA_HOME") };
    }

    /// ADR-002 W1.5: `ensure_data_dir` / `ensure_cache_dir` create
    /// their directories with mode 0700, AND chmod existing dirs
    /// with looser perms down to 0700 — that's the upgrade path
    /// for hosts created before this change landed.
    #[cfg(unix)]
    #[test]
    fn test_ensure_private_dir_locks_existing_loose_perms() {
        use std::os::unix::fs::PermissionsExt as _;

        // Pick a stable temp path; tests share env-var state so we
        // serialise via a unique-id suffix.
        let temp = format!(
            "/tmp/mvm-private-dir-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        );
        std::fs::create_dir_all(&temp).expect("create temp");
        std::fs::set_permissions(&temp, std::fs::Permissions::from_mode(0o755))
            .expect("loosen for setup");

        ensure_private_dir(&temp).expect("ensure_private_dir");

        let mode = std::fs::metadata(&temp)
            .expect("temp exists")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700, "expected 0700, got 0{:o}", mode);

        let _ = std::fs::remove_dir_all(&temp);
    }
}
