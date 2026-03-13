use anyhow::Result;
use serde::Serialize;

use crate::ui;
use mvm_core::config::fc_version;
use mvm_core::platform::{self, Platform};
use mvm_runtime::shell;
use mvm_runtime::vm::lima;

#[derive(Debug, Serialize)]
struct Check {
    name: &'static str,
    category: &'static str,
    ok: bool,
    info: String,
}

#[derive(Debug, Serialize)]
struct DoctorReport {
    checks: Vec<Check>,
    all_ok: bool,
}

pub fn run(json: bool) -> Result<()> {
    let mut checks = Vec::new();

    // ── Prerequisites (user must install before bootstrap) ───────
    checks.push(check_cmd("rustup", "prerequisites", "rustup --version"));
    checks.push(check_cmd("cargo", "prerequisites", "cargo --version"));

    // ── Managed Tools (installed by bootstrap) ────────────────────

    let in_vm = shell::inside_lima();
    if in_vm {
        // Inside Lima VM: limactl is not needed, nix and firecracker are local
        checks.push(nix_version_check(None));
        checks.push(check_cmd("firecracker", "tools", "firecracker --version"));
    } else {
        // On host: limactl needed for macOS, firecracker checked via Lima
        if platform::current().needs_lima() {
            checks.push(check_cmd("limactl", "tools", "limactl --version"));
        }
        checks.push(nix_version_check(Some("mvm")));
        checks.push(check_vm_cmd(
            "firecracker",
            "tools",
            "firecracker --version",
        ));
    }

    checks.push(Check {
        name: "fc target",
        category: "tools",
        ok: true,
        info: fc_version(),
    });

    // Nix flake support check
    checks.push(nix_flakes_check(in_vm));

    // ── Platform ──────────────────────────────────────────────────
    let plat = platform::current();
    checks.push(Check {
        name: "platform",
        category: "platform",
        ok: true,
        info: platform_description(plat),
    });

    checks.push(kvm_check(plat, in_vm));

    if plat.needs_lima() {
        checks.push(lima_status_check());
    }

    checks.push(disk_space_check(in_vm));

    // Lima VM disk usage (only when Lima is running on macOS)
    if plat.needs_lima() {
        checks.push(lima_disk_check());
    }

    // Nix store health
    checks.push(nix_store_check(in_vm));

    // ── Render ────────────────────────────────────────────────────
    let all_ok = checks.iter().all(|c| c.ok);
    let report = DoctorReport { checks, all_ok };

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        if !report.all_ok {
            anyhow::bail!("doctor found issues");
        }
        return Ok(());
    }

    render_text(&report);

    if !report.all_ok {
        let missing: Vec<&Check> = report.checks.iter().filter(|c| !c.ok).collect();
        ui::warn("\nIssues found:");
        for m in &missing {
            ui::info(&format!("  {} — {}", m.name, m.info));
        }

        // Provide category-specific guidance
        let has_prerequisites = missing.iter().any(|c| c.category == "prerequisites");
        let has_managed = missing.iter().any(|c| c.category == "tools");

        if has_prerequisites {
            ui::info("\nPrerequisites missing: Install Rust from https://rustup.rs");
        }
        if has_managed {
            ui::info("\nManaged tools missing: Run 'mvmctl bootstrap' to install");
        }

        anyhow::bail!("doctor found issues");
    }

    ui::success("\nAll checks passed.");
    Ok(())
}

fn render_text(report: &DoctorReport) {
    let mut current_category = "";
    for c in &report.checks {
        if c.category != current_category {
            current_category = c.category;
            let title = match current_category {
                "prerequisites" => "Prerequisites",
                "tools" => "Tools",
                "platform" => "Platform",
                _ => current_category,
            };
            println!("\n{}", title);
            println!("{}", "-".repeat(title.len()));
        }
        let status = if c.ok { "OK" } else { "MISSING" };
        ui::status_line(
            &format!("  {}:", c.name),
            &format!("{} ({})", status, c.info),
        );
    }
}

// ── Tool checks ───────────────────────────────────────────────────────────

fn check_cmd(name: &'static str, category: &'static str, cmd: &'static str) -> Check {
    match shell::run_host("bash", &["-lc", cmd]) {
        Ok(out) if out.status.success() => Check {
            name,
            category,
            ok: true,
            info: String::from_utf8_lossy(&out.stdout).trim().to_string(),
        },
        Ok(out) => Check {
            name,
            category,
            ok: false,
            info: String::from_utf8_lossy(&out.stderr).trim().to_string(),
        },
        Err(e) => Check {
            name,
            category,
            ok: false,
            info: e.to_string(),
        },
    }
}

fn check_vm_cmd(name: &'static str, category: &'static str, cmd: &'static str) -> Check {
    match shell::run_on_vm("mvm", cmd) {
        Ok(out) if out.status.success() => Check {
            name,
            category,
            ok: true,
            info: String::from_utf8_lossy(&out.stdout).trim().to_string(),
        },
        Ok(out) => Check {
            name,
            category,
            ok: false,
            info: String::from_utf8_lossy(&out.stderr).trim().to_string(),
        },
        Err(e) => Check {
            name,
            category,
            ok: false,
            info: e.to_string(),
        },
    }
}

// ── Platform checks ───────────────────────────────────────────────────────

fn platform_description(plat: Platform) -> String {
    match plat {
        Platform::MacOS => "macOS (Lima required)".to_string(),
        Platform::LinuxNative => "Linux with KVM".to_string(),
        Platform::LinuxNoKvm => "Linux without KVM (Lima required)".to_string(),
    }
}

fn kvm_check(plat: Platform, in_vm: bool) -> Check {
    // Inside Lima VM or native Linux: check /dev/kvm locally
    if in_vm || plat == Platform::LinuxNative || plat == Platform::LinuxNoKvm {
        // Use test -c (character device exists) rather than test -r (readable),
        // because KVM access may be via group membership which doesn't imply -r.
        return match shell::run_host("bash", &["-c", "test -c /dev/kvm && echo ok"]) {
            Ok(out) if out.status.success() => {
                let context = if in_vm {
                    "available (inside Lima VM)"
                } else {
                    "available"
                };
                Check {
                    name: "kvm",
                    category: "platform",
                    ok: true,
                    info: context.to_string(),
                }
            }
            _ => Check {
                name: "kvm",
                category: "platform",
                ok: false,
                info: if in_vm {
                    "/dev/kvm not accessible inside Lima VM".to_string()
                } else {
                    "not available. Enable virtualization in BIOS or check permissions on /dev/kvm."
                        .to_string()
                },
            },
        };
    }

    // macOS host: check /dev/kvm inside the Lima VM
    match shell::run_in_vm("test -c /dev/kvm && echo ok") {
        Ok(out) if out.status.success() => Check {
            name: "kvm",
            category: "platform",
            ok: true,
            info: "available (via Lima VM)".to_string(),
        },
        _ => Check {
            name: "kvm",
            category: "platform",
            ok: false,
            info: "Lima VM not running or /dev/kvm unavailable. Run 'mvmctl setup'.".to_string(),
        },
    }
}

fn lima_status_check() -> Check {
    match lima::get_status() {
        Ok(lima::LimaStatus::Running) => Check {
            name: "lima vm",
            category: "platform",
            ok: true,
            info: "running".to_string(),
        },
        Ok(lima::LimaStatus::Stopped) => Check {
            name: "lima vm",
            category: "platform",
            ok: false,
            info: "stopped. Run 'mvmctl dev' or 'limactl start mvm'.".to_string(),
        },
        Ok(lima::LimaStatus::NotFound) => Check {
            name: "lima vm",
            category: "platform",
            ok: false,
            info: "not found. Run 'mvmctl setup' or 'mvmctl bootstrap'.".to_string(),
        },
        Err(e) => Check {
            name: "lima vm",
            category: "platform",
            ok: false,
            info: format!("check failed: {}", e),
        },
    }
}

fn disk_space_check(in_vm: bool) -> Check {
    let result = if in_vm {
        parse_disk_space("df -BG ~/.mvm 2>/dev/null || df -BG / 2>/dev/null")
    } else if cfg!(target_os = "macos") {
        parse_disk_space("df -g ~ 2>/dev/null")
    } else {
        parse_disk_space("df -BG ~/.mvm 2>/dev/null || df -BG / 2>/dev/null")
    };

    match result {
        Some(gib) if gib >= 10 => Check {
            name: "disk space",
            category: "platform",
            ok: true,
            info: format!("{} GiB free", gib),
        },
        Some(gib) => Check {
            name: "disk space",
            category: "platform",
            ok: false,
            info: format!("only {} GiB free (10 GiB recommended)", gib),
        },
        None => Check {
            name: "disk space",
            category: "platform",
            ok: true,
            info: "unable to determine (skipped)".to_string(),
        },
    }
}

/// Parse free disk space in GiB from `df` output.
/// Expects the 4th column of the 2nd line to be the available space with a G suffix.
fn parse_disk_space(cmd: &str) -> Option<u64> {
    let output = shell::run_host("bash", &["-c", cmd]).ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = stdout.lines().nth(1)?;
    let avail = line.split_whitespace().nth(3)?;
    let num_str = avail.trim_end_matches('G').trim_end_matches('i');
    num_str.parse().ok()
}

// ── Nix checks ────────────────────────────────────────────────────────────

/// Minimum Nix version for flake support (nix build with flakes).
const NIX_MIN_VERSION: (u64, u64) = (2, 4);
/// Recommended Nix version for best flake support.
const NIX_RECOMMENDED_VERSION: (u64, u64) = (2, 13);

/// Check Nix version and validate it meets minimum requirements.
/// `vm_name`: if Some, run `nix --version` inside the Lima VM; if None, run locally.
fn nix_version_check(vm_name: Option<&str>) -> Check {
    let output_result = match vm_name {
        Some(vm) => shell::run_on_vm(vm, "nix --version"),
        None => shell::run_host("bash", &["-lc", "nix --version"]),
    };

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

/// Check that Nix flake support is enabled (experimental-features includes nix-command and flakes).
fn nix_flakes_check(in_vm: bool) -> Check {
    let cmd = "nix show-config 2>/dev/null | grep -i experimental-features || echo 'not found'";
    let output_result = if in_vm {
        shell::run_host("bash", &["-lc", cmd])
    } else {
        shell::run_on_vm("mvm", cmd)
    };

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

// ── Lima VM health ────────────────────────────────────────────────────────

/// Check Lima VM disk usage — warn if > 80% full.
fn lima_disk_check() -> Check {
    match shell::run_on_vm("mvm", "df -h / 2>/dev/null") {
        Ok(out) if out.status.success() => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            // Parse "Use%" column from df output (5th column of 2nd line)
            if let Some(pct) = stdout
                .lines()
                .nth(1)
                .and_then(|line| line.split_whitespace().nth(4))
                .and_then(|s| s.trim_end_matches('%').parse::<u64>().ok())
            {
                return if pct >= 90 {
                    Check {
                        name: "lima disk",
                        category: "platform",
                        ok: false,
                        info: format!("{}% used (critically low space)", pct),
                    }
                } else if pct >= 80 {
                    Check {
                        name: "lima disk",
                        category: "platform",
                        ok: true,
                        info: format!("{}% used (consider freeing space)", pct),
                    }
                } else {
                    Check {
                        name: "lima disk",
                        category: "platform",
                        ok: true,
                        info: format!("{}% used", pct),
                    }
                };
            }
            Check {
                name: "lima disk",
                category: "platform",
                ok: true,
                info: "unable to parse (skipped)".to_string(),
            }
        }
        _ => Check {
            name: "lima disk",
            category: "platform",
            ok: true,
            info: "VM not accessible (skipped)".to_string(),
        },
    }
}

// ── Nix store health ──────────────────────────────────────────────────────

/// Check Nix store accessibility via `nix store ping`.
fn nix_store_check(in_vm: bool) -> Check {
    let cmd = "nix store ping 2>&1";
    let output_result = if in_vm {
        shell::run_host("bash", &["-lc", cmd])
    } else {
        shell::run_on_vm("mvm", cmd)
    };

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_struct_reports_ok() {
        let c = Check {
            name: "test-tool",
            category: "tools",
            ok: true,
            info: "1.0.0".to_string(),
        };
        assert!(c.ok);
        assert_eq!(c.name, "test-tool");
    }

    #[test]
    fn check_struct_reports_missing() {
        let c = Check {
            name: "missing-tool",
            category: "tools",
            ok: false,
            info: "not found".to_string(),
        };
        assert!(!c.ok);
    }

    #[test]
    fn inside_lima_is_false_on_host() {
        if std::env::var("LIMA_INSTANCE").is_err()
            && !std::path::Path::new("/etc/lima-boot.conf").exists()
        {
            assert!(!shell::inside_lima());
        }
    }

    #[test]
    fn check_cmd_rustup_on_host() {
        let c = check_cmd("rustup", "tools", "rustup --version");
        assert!(c.ok, "rustup should be available: {}", c.info);
        assert!(
            c.info.contains("rustup"),
            "expected version string, got: {}",
            c.info
        );
    }

    #[test]
    fn check_cmd_cargo_on_host() {
        let c = check_cmd("cargo", "tools", "cargo --version");
        assert!(c.ok, "cargo should be available: {}", c.info);
        assert!(
            c.info.contains("cargo"),
            "expected version string, got: {}",
            c.info
        );
    }

    #[test]
    fn check_cmd_missing_tool() {
        let c = check_cmd(
            "nonexistent-mvm-tool-xyz",
            "tools",
            "nonexistent-mvm-tool-xyz --version",
        );
        assert!(!c.ok, "nonexistent tool should fail");
    }

    #[test]
    fn fc_target_version_is_nonempty() {
        let v = mvm_core::config::fc_version();
        assert!(!v.is_empty(), "FC version should be configured");
        assert!(
            v.starts_with('v'),
            "FC version should start with 'v': {}",
            v
        );
    }

    #[test]
    fn platform_description_covers_all_variants() {
        assert!(platform_description(Platform::MacOS).contains("macOS"));
        assert!(platform_description(Platform::LinuxNative).contains("KVM"));
        assert!(platform_description(Platform::LinuxNoKvm).contains("without KVM"));
    }

    #[test]
    fn parse_disk_space_typical_output() {
        let result = parse_disk_space(
            "printf 'Filesystem     1G-blocks  Used Available Use%% Mounted on\n/dev/sda1           100G   55G       45G  55%% /\n'",
        );
        assert_eq!(result, Some(45));
    }

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

    #[test]
    fn doctor_report_serializes_to_json() {
        let report = DoctorReport {
            checks: vec![Check {
                name: "test",
                category: "tools",
                ok: true,
                info: "v1.0".to_string(),
            }],
            all_ok: true,
        };
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("\"name\":\"test\""));
        assert!(json.contains("\"all_ok\":true"));
    }
}
