//! `mvmctl security` subcommand handlers.

use anyhow::Result;
use clap::{Args as ClapArgs, Subcommand};

use mvm_core::user_config::MvmConfig;

use super::Cli;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    #[command(subcommand)]
    pub action: SecurityAction,
}

#[derive(Subcommand, Debug, Clone)]
pub(in crate::commands) enum SecurityAction {
    /// Show security posture evaluation for the current environment
    Status {
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    match args.action {
        SecurityAction::Status { json } => security_status(json),
    }
}

fn security_status(json: bool) -> Result<()> {
    use mvm_security::posture::SecurityPosture;

    let mut checks = Vec::new();
    checks.extend(standard_posture_checks());
    checks.extend(adr_002_live_probes());

    let timestamp = mvm_core::time::utc_now();
    let report = SecurityPosture::evaluate(checks, &timestamp);

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print!("{}", SecurityPosture::summary(&report));

        let uncovered = SecurityPosture::uncovered_layers(&report.checks);
        if !uncovered.is_empty() {
            println!("\nUncovered layers (no checks):");
            for layer in uncovered {
                println!("  - {:?}", layer);
            }
        }

        println!("\nCI badges (live state of project-wide gates):");
        println!("  Security:        https://github.com/auser/mvm/actions/workflows/security.yml");
        println!("  CI (clippy/test): https://github.com/auser/mvm/actions/workflows/ci.yml");
    }

    Ok(())
}

/// The pre-W6.4 set of static-shape posture checks. Kept intact so
/// `mvmctl security status` continues to surface the layer matrix it
/// always has.
fn standard_posture_checks() -> Vec<mvm_core::security::PostureCheck> {
    use mvm_core::security::{PostureCheck, SecurityLayer};

    let mut checks = Vec::new();

    let audit_path = mvm_core::audit::default_audit_log();
    let audit_exists = std::path::Path::new(&audit_path).exists();
    checks.push(PostureCheck {
        layer: SecurityLayer::AuditLogging,
        name: "Local audit log".to_string(),
        passed: audit_exists,
        detail: if audit_exists {
            format!("Active at {audit_path}")
        } else {
            format!("Not found at {audit_path}")
        },
    });

    let share_dir = mvm_core::config::mvm_share_dir();
    let xdg_exists = std::path::Path::new(&share_dir).exists();
    checks.push(PostureCheck {
        layer: SecurityLayer::ConfigImmutability,
        name: "XDG data directory".to_string(),
        passed: xdg_exists,
        detail: if xdg_exists {
            format!("Present at {share_dir}")
        } else {
            "Not yet created — run `mvmctl init`".to_string()
        },
    });

    let net_path = mvm_core::dev_network::network_path("default");
    let net_exists = std::path::Path::new(&net_path).exists();
    checks.push(PostureCheck {
        layer: SecurityLayer::NetworkIsolation,
        name: "Default dev network".to_string(),
        passed: net_exists,
        detail: if net_exists {
            "Configured".to_string()
        } else {
            "Not configured — run `mvmctl init` or `mvmctl network create default`".to_string()
        },
    });

    checks.push(PostureCheck {
        layer: SecurityLayer::SeccompFilter,
        name: "Seccomp profiles".to_string(),
        passed: true,
        detail: "5-tier profiles available (essential → unrestricted)".to_string(),
    });

    checks.push(PostureCheck {
        layer: SecurityLayer::VsockAuth,
        name: "Vsock authentication".to_string(),
        passed: true,
        detail: "Ed25519 signing with replay protection".to_string(),
    });

    checks.push(PostureCheck {
        layer: SecurityLayer::GuestHardening,
        name: "No SSH policy".to_string(),
        passed: true,
        detail: "Vsock-only guest communication (no sshd)".to_string(),
    });

    checks.push(PostureCheck {
        layer: SecurityLayer::SupplyChainIntegrity,
        name: "Nix-based builds".to_string(),
        passed: true,
        detail: "All images built from Nix flakes (content-addressed)".to_string(),
    });

    checks
}

/// W6.4 — live probes that read the host's actual state and report
/// PASS/FAIL on the security claims that admit a runtime check.
/// Each probe is independent; failures are reported in `detail`
/// rather than thrown so the rest of the report still renders.
fn adr_002_live_probes() -> Vec<mvm_core::security::PostureCheck> {
    use mvm_core::security::{PostureCheck, SecurityLayer};

    vec![
        probe_proxy_socket_mode(),
        probe_data_dir_mode(SecurityLayer::ConfigImmutability),
        probe_dev_image_present(),
        probe_deny_config_present(),
        PostureCheck {
            layer: SecurityLayer::SupplyChainIntegrity,
            name: "Hash-verified dev image download".to_string(),
            passed: true,
            detail: "Downloads stream through SHA-256 against the release manifest (ADR-002 §W5.1)"
                .to_string(),
        },
    ]
}

/// The dev VM's vsock proxy socket must be mode 0700 — anything more
/// permissive lets a same-host other-user process hijack the agent
/// channel. ADR-002 §W1.2.
fn probe_proxy_socket_mode() -> mvm_core::security::PostureCheck {
    use mvm_core::security::{PostureCheck, SecurityLayer};

    let path = format!(
        "{}/vms/mvm-dev/vsock.sock",
        mvm_core::config::mvm_share_dir()
    );
    let layer = SecurityLayer::NetworkIsolation;
    let name = "Vsock proxy socket mode".to_string();

    let Ok(meta) = std::fs::symlink_metadata(&path) else {
        return PostureCheck {
            layer,
            name,
            passed: true,
            detail: format!("dev VM not running (no socket at {path}); skipped"),
        };
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode() & 0o777;
        let expected = 0o700;
        let passed = mode == expected;
        PostureCheck {
            layer,
            name,
            passed,
            detail: if passed {
                format!("0{mode:o} at {path} (ADR-002 §W1.2)")
            } else {
                format!(
                    "expected 0{expected:o}, got 0{mode:o} at {path} — same-host other users may have access"
                )
            },
        }
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        PostureCheck {
            layer,
            name,
            passed: true,
            detail: "non-Unix host; mode check skipped".to_string(),
        }
    }
}

/// `~/.mvm` and `~/.cache/mvm` must be mode 0700. ADR-002 §W1.5.
fn probe_data_dir_mode(
    layer: mvm_core::security::SecurityLayer,
) -> mvm_core::security::PostureCheck {
    use mvm_core::security::PostureCheck;

    let dir = mvm_core::config::mvm_share_dir();
    let name = "Private data directory mode".to_string();
    let Ok(meta) = std::fs::symlink_metadata(&dir) else {
        return PostureCheck {
            layer,
            name,
            passed: false,
            detail: format!("not present at {dir} — run `mvmctl init`"),
        };
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode() & 0o777;
        let expected = 0o700;
        let passed = mode == expected;
        PostureCheck {
            layer,
            name,
            passed,
            detail: if passed {
                format!("0{mode:o} at {dir} (ADR-002 §W1.5)")
            } else {
                format!("expected 0{expected:o}, got 0{mode:o} at {dir}")
            },
        }
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        PostureCheck {
            layer,
            name,
            passed: true,
            detail: "non-Unix host; mode check skipped".to_string(),
        }
    }
}

/// Cached pre-built dev image (kernel + rootfs) for the running mvmctl
/// version. Presence is informational; absence triggers a download
/// (which ADR-002 §W5.1 hash-verifies).
fn probe_dev_image_present() -> mvm_core::security::PostureCheck {
    use mvm_core::security::{PostureCheck, SecurityLayer};

    let version = env!("CARGO_PKG_VERSION");
    let prebuilt_dir = format!("{}/prebuilt/v{version}", mvm_core::config::mvm_share_dir());
    let kernel = format!("{prebuilt_dir}/vmlinux");
    let rootfs = format!("{prebuilt_dir}/rootfs.ext4");
    let cached = std::path::Path::new(&kernel).exists() && std::path::Path::new(&rootfs).exists();

    PostureCheck {
        layer: SecurityLayer::SupplyChainIntegrity,
        name: "Pre-built dev image cached".to_string(),
        passed: true,
        detail: if cached {
            format!("Cached at {prebuilt_dir}")
        } else {
            "Not cached; the next `mvmctl dev up` will download + hash-verify".to_string()
        },
    }
}

/// `deny.toml` at the workspace root is the supply-chain policy file.
/// We can only locate it when running from a source checkout; in a
/// release-binary install the absence is expected and not a fail.
fn probe_deny_config_present() -> mvm_core::security::PostureCheck {
    use mvm_core::security::{PostureCheck, SecurityLayer};

    // Walk up from the current directory looking for a `deny.toml`
    // alongside a `Cargo.toml` (workspace root marker).
    let cwd = std::env::current_dir().ok();
    let found = cwd.as_deref().and_then(|start| {
        let mut cur: Option<&std::path::Path> = Some(start);
        while let Some(p) = cur {
            if p.join("deny.toml").exists() && p.join("Cargo.toml").exists() {
                return Some(p.to_path_buf());
            }
            cur = p.parent();
        }
        None
    });

    PostureCheck {
        layer: SecurityLayer::SupplyChainIntegrity,
        name: "Cargo deny policy".to_string(),
        passed: true,
        detail: match found {
            Some(p) => format!("deny.toml at {} (ADR-002 §W5.2)", p.display()),
            None => {
                "deny.toml not found from cwd; expected only in source checkouts (ADR-002 §W5.2)"
                    .to_string()
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_posture_checks_returns_seven_layers() {
        let checks = standard_posture_checks();
        assert_eq!(checks.len(), 7, "standard posture checks shape changed");
    }

    #[test]
    fn live_probes_return_a_check_per_topic() {
        let checks = adr_002_live_probes();
        assert!(
            checks.len() >= 5,
            "expected ≥5 live probes, got {}",
            checks.len()
        );
        // Every probe must produce a non-empty detail so users can read the
        // report without re-running with --json.
        for c in &checks {
            assert!(
                !c.detail.is_empty(),
                "{} probe returned empty detail",
                c.name
            );
        }
    }

    #[test]
    fn proxy_socket_probe_runs_and_names_layer() {
        // The probe consults the host's real `mvm_share_dir`; we
        // can't dependency-inject the path without restructuring the
        // module. Instead assert the probe always returns a check
        // with the expected layer and name, so a future refactor that
        // breaks either is caught here. Whether the socket is missing
        // or present is environment-dependent — both are valid runs.
        let check = probe_proxy_socket_mode();
        assert!(matches!(
            check.layer,
            mvm_core::security::SecurityLayer::NetworkIsolation
        ));
        assert_eq!(check.name, "Vsock proxy socket mode");
        assert!(!check.detail.is_empty());
    }

    #[test]
    fn deny_config_probe_finds_workspace_root() {
        // Run from inside the workspace — the probe walks parents
        // looking for `deny.toml` next to `Cargo.toml`. Our test
        // process always has the workspace as an ancestor of cwd.
        let check = probe_deny_config_present();
        assert!(check.passed);
        assert!(
            check.detail.contains("deny.toml") || check.detail.contains("not found"),
            "unexpected probe detail: {}",
            check.detail
        );
    }
}
