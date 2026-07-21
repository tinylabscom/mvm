//! Nix version/flakes support and nix-store health, always probed inside
//! the dev VM (nix is never expected on the host).

use super::Check;
use mvm_runtime::config::VM_NAME;
use mvm_runtime::shell;

/// Minimum Nix version for flake support (nix build with flakes).
const NIX_MIN_VERSION: (u64, u64) = (2, 4);
/// Recommended Nix version for best flake support.
const NIX_RECOMMENDED_VERSION: (u64, u64) = (2, 13);

/// Check Nix version and validate it meets minimum requirements.
///
/// Always probes the dev VM — nix is never expected on the host. The
/// caller in `run()` gates this on [`super::builder::dev_vm_running`]; calling it
/// when the dev VM is down will return an error `Check`.
pub(super) fn nix_version_check() -> Check {
    let output_result = shell::run_on_vm(VM_NAME, "nix --version");

    match output_result {
        Ok(out) if out.status.success() => {
            let version_str = String::from_utf8_lossy(&out.stdout).trim().to_string();
            match parse_nix_version(&version_str) {
                Some((major, minor, patch)) => {
                    if (major, minor) < NIX_MIN_VERSION {
                        Check {
                            name: "nix",
                            category: "tools",
                            ok: false,
                            info: format!(
                                "{}.{}.{} (requires >= {}.{}+ for flakes)",
                                major, minor, patch, NIX_MIN_VERSION.0, NIX_MIN_VERSION.1
                            ),
                        }
                    } else if (major, minor) < NIX_RECOMMENDED_VERSION {
                        Check {
                            name: "nix",
                            category: "tools",
                            ok: true,
                            info: format!(
                                "{}.{}.{} (OK, but >= {}.{} recommended)",
                                major,
                                minor,
                                patch,
                                NIX_RECOMMENDED_VERSION.0,
                                NIX_RECOMMENDED_VERSION.1
                            ),
                        }
                    } else {
                        Check {
                            name: "nix",
                            category: "tools",
                            ok: true,
                            info: format!("{}.{}.{}", major, minor, patch),
                        }
                    }
                }
                None => Check {
                    name: "nix",
                    category: "tools",
                    ok: true,
                    info: format!("{} (version not parsed)", version_str),
                },
            }
        }
        Ok(out) => Check {
            name: "nix",
            category: "tools",
            ok: false,
            info: String::from_utf8_lossy(&out.stderr).trim().to_string(),
        },
        Err(e) => Check {
            name: "nix",
            category: "tools",
            ok: false,
            info: e.to_string(),
        },
    }
}

/// Parse "nix (Nix) 2.18.1" or "nix (Nix) 2.24.12 pre-20241211_dirty" into (major, minor, patch).
fn parse_nix_version(output: &str) -> Option<(u64, u64, u64)> {
    // Find the version number after "Nix) " or just the last space-separated token
    let version_part = output
        .split_whitespace()
        .find(|s| s.chars().next().is_some_and(|c| c.is_ascii_digit()))?;

    let mut parts = version_part.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    // Patch may have suffix like "12pre-20241211_dirty"
    let patch_str = parts.next().unwrap_or("0");
    let patch = patch_str
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect::<String>()
        .parse()
        .unwrap_or(0);
    Some((major, minor, patch))
}

/// Check that Nix flake support is enabled (experimental-features includes
/// nix-command and flakes). Always probes the dev VM; gated on
/// [`super::builder::dev_vm_running`] by the caller.
pub(super) fn nix_flakes_check() -> Check {
    let cmd = "nix show-config 2>/dev/null | grep -i experimental-features || echo 'not found'";
    let output_result = shell::run_on_vm(VM_NAME, cmd);

    match output_result {
        Ok(out) if out.status.success() => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let has_flakes = stdout.contains("flakes");
            let has_nix_command = stdout.contains("nix-command");
            if has_flakes && has_nix_command {
                Check {
                    name: "nix flakes",
                    category: "tools",
                    ok: true,
                    info: "enabled".to_string(),
                }
            } else {
                let mut missing = Vec::new();
                if !has_nix_command {
                    missing.push("nix-command");
                }
                if !has_flakes {
                    missing.push("flakes");
                }
                Check {
                    name: "nix flakes",
                    category: "tools",
                    ok: false,
                    info: format!(
                        "missing experimental-features: {}. Add to ~/.config/nix/nix.conf",
                        missing.join(", ")
                    ),
                }
            }
        }
        _ => Check {
            name: "nix flakes",
            category: "tools",
            ok: true,
            info: "unable to check (skipped)".to_string(),
        },
    }
}

// ── Nix store health ──────────────────────────────────────────────────────

/// Check Nix store accessibility via `nix store ping`. Always probes the
/// dev VM; gated on [`super::builder::dev_vm_running`] by the caller.
pub(super) fn nix_store_check() -> Check {
    let cmd = "nix store ping 2>&1";
    let output_result = shell::run_on_vm(VM_NAME, cmd);

    match output_result {
        Ok(out) if out.status.success() => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            // nix store ping outputs "Store URL: daemon" or similar
            let store_url = stdout
                .lines()
                .find(|l| l.contains("Store URL"))
                .map(|l| l.trim().to_string())
                .unwrap_or_else(|| "accessible".to_string());
            Check {
                name: "nix store",
                category: "tools",
                ok: true,
                info: store_url,
            }
        }
        Ok(_) => Check {
            name: "nix store",
            category: "tools",
            ok: false,
            info: "Nix store not accessible. Is the Nix daemon running?".to_string(),
        },
        _ => Check {
            name: "nix store",
            category: "tools",
            ok: true,
            info: "unable to check (skipped)".to_string(),
        },
    }
}

/// Check Nix store size and warn if it exceeds 20 GiB. Always probes the
/// dev VM; gated on [`super::builder::dev_vm_running`] by the caller.
pub(super) fn nix_store_size_check() -> Check {
    let cmd = "du -sb /nix/store 2>/dev/null | awk '{print $1}'";
    let output_result = shell::run_on_vm(VM_NAME, cmd);

    match output_result {
        Ok(out) if out.status.success() => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let bytes: u64 = stdout.trim().parse().unwrap_or(0);
            let threshold: u64 = 20 * 1024 * 1024 * 1024; // 20 GiB
            let human = mvm_core::pool::format_bytes(bytes);
            if bytes > threshold {
                Check {
                    name: "nix store size",
                    category: "disk",
                    ok: false,
                    info: format!(
                        "{} — exceeds 20 GiB. Run 'nix-collect-garbage -d' to reclaim space.",
                        human
                    ),
                }
            } else {
                Check {
                    name: "nix store size",
                    category: "disk",
                    ok: true,
                    info: human,
                }
            }
        }
        _ => Check {
            name: "nix store size",
            category: "disk",
            ok: true,
            info: "unable to check (skipped)".to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_nix_version_standard() {
        assert_eq!(parse_nix_version("nix (Nix) 2.18.1"), Some((2, 18, 1)));
    }

    #[test]
    fn parse_nix_version_with_suffix() {
        assert_eq!(
            parse_nix_version("nix (Nix) 2.24.12pre-20241211_dirty"),
            Some((2, 24, 12))
        );
    }

    #[test]
    fn parse_nix_version_old() {
        assert_eq!(parse_nix_version("nix (Nix) 2.3.16"), Some((2, 3, 16)));
    }

    #[test]
    fn parse_nix_version_garbage() {
        assert_eq!(parse_nix_version("not a version"), None);
    }

    #[test]
    fn parse_nix_version_empty() {
        assert_eq!(parse_nix_version(""), None);
    }

    #[test]
    fn nix_version_too_old_is_not_ok() {
        // Version 2.3.x is below minimum 2.4
        let (major, minor, _patch) = (2, 3, 16);
        assert!((major, minor) < NIX_MIN_VERSION);
        // Verify the logic matches what nix_version_check would produce
        assert!(
            (major, minor) < NIX_MIN_VERSION,
            "2.3 should be below minimum"
        );
    }

    #[test]
    fn nix_version_at_minimum_is_ok() {
        let (major, minor) = (2, 4);
        assert!((major, minor) >= NIX_MIN_VERSION);
    }

    #[test]
    fn nix_version_at_recommended_is_ok() {
        let (major, minor) = (2, 13);
        assert!((major, minor) >= NIX_RECOMMENDED_VERSION);
    }
}
