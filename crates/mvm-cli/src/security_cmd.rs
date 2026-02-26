use anyhow::Result;

use mvm_core::security::{PostureCheck, SecurityLayer, SecurityPolicy};
use mvm_core::time;
use mvm_runtime::shell;
use mvm_security::posture::SecurityPosture;

use crate::ui;

/// Run the `mvm security status` command.
///
/// Probes the host/Lima VM for security feature availability across
/// [`SecurityLayer`] variants and produces a posture report.
pub fn run(json: bool) -> Result<()> {
    let checks = collect_checks();
    let report = SecurityPosture::evaluate(checks, &time::utc_now());

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    render_text(&report);
    Ok(())
}

/// Collect posture checks by probing the environment.
///
/// Shell-based checks gracefully degrade when Lima is not running.
fn collect_checks() -> Vec<PostureCheck> {
    let vm_available = shell::inside_lima() || vm_is_reachable();

    let mut checks = Vec::new();

    // JailerIsolation — jailer binary available inside VM
    checks.push(if vm_available {
        vm_check(
            SecurityLayer::JailerIsolation,
            "Jailer binary available",
            "command -v jailer >/dev/null 2>&1 && echo yes || echo no",
            |out| out.trim() == "yes",
            "jailer found",
            "jailer not installed",
        )
    } else {
        no_vm_check(SecurityLayer::JailerIsolation, "Jailer binary available")
    });

    // SeccompFilter — strict profile file exists
    checks.push(if vm_available {
        vm_check(
            SecurityLayer::SeccompFilter,
            "Seccomp strict profile",
            "test -f /var/lib/mvm/seccomp/strict.json && echo yes || echo no",
            |out| out.trim() == "yes",
            "/var/lib/mvm/seccomp/strict.json exists",
            "strict seccomp profile not deployed",
        )
    } else {
        no_vm_check(SecurityLayer::SeccompFilter, "Seccomp strict profile")
    });

    // NetworkIsolation — iptables available
    checks.push(if vm_available {
        vm_check(
            SecurityLayer::NetworkIsolation,
            "iptables available",
            "command -v iptables 2>/dev/null",
            |out| !out.trim().is_empty(),
            "iptables found",
            "iptables not installed",
        )
    } else {
        no_vm_check(SecurityLayer::NetworkIsolation, "iptables available")
    });

    // AuditLogging — tenants directory exists
    checks.push(if vm_available {
        vm_check(
            SecurityLayer::AuditLogging,
            "Audit log directory",
            "test -d /var/lib/mvm/tenants && echo yes || echo no",
            |out| out.trim() == "yes",
            "/var/lib/mvm/tenants/ exists",
            "/var/lib/mvm/tenants/ not found",
        )
    } else {
        no_vm_check(SecurityLayer::AuditLogging, "Audit log directory")
    });

    // VsockAuth — check default policy (pure logic, no VM needed)
    let policy = SecurityPolicy::default();
    checks.push(PostureCheck {
        layer: SecurityLayer::VsockAuth,
        name: "Vsock auth enabled".to_string(),
        passed: policy.require_auth,
        detail: if policy.require_auth {
            "require_auth is true".to_string()
        } else {
            "require_auth is false (dev mode default)".to_string()
        },
    });

    // GuestHardening — at least one built template exists
    checks.push(if vm_available {
        vm_check(
            SecurityLayer::GuestHardening,
            "Built template exists",
            "ls /var/lib/mvm/templates/*/current/ 2>/dev/null | head -1",
            |out| !out.trim().is_empty(),
            "built template found",
            "no built templates found",
        )
    } else {
        no_vm_check(SecurityLayer::GuestHardening, "Built template exists")
    });

    checks
}

/// Run a shell command inside the VM and produce a posture check.
fn vm_check(
    layer: SecurityLayer,
    name: &str,
    cmd: &str,
    is_ok: impl FnOnce(&str) -> bool,
    ok_detail: &str,
    fail_detail: &str,
) -> PostureCheck {
    let passed = match shell::run_in_vm_stdout(cmd) {
        Ok(out) => is_ok(&out),
        Err(_) => false,
    };
    PostureCheck {
        layer,
        name: name.to_string(),
        passed,
        detail: if passed {
            ok_detail.to_string()
        } else {
            fail_detail.to_string()
        },
    }
}

/// Produce a failed check when the VM is not reachable.
fn no_vm_check(layer: SecurityLayer, name: &str) -> PostureCheck {
    PostureCheck {
        layer,
        name: name.to_string(),
        passed: false,
        detail: "Lima VM not running".to_string(),
    }
}

/// Quick probe to see if the Lima VM is reachable.
fn vm_is_reachable() -> bool {
    shell::run_in_vm_stdout("echo ok").is_ok()
}

fn render_text(report: &mvm_core::security::PostureReport) {
    let total = report.checks.len();
    let passed = report.checks.iter().filter(|c| c.passed).count();

    let score_line = format!(
        "Security Posture: {:.0}% ({}/{} checks passed)",
        report.score, passed, total
    );
    if report.score >= 80.0 {
        ui::success(&score_line);
    } else if report.score >= 50.0 {
        ui::warn(&score_line);
    } else {
        ui::info(&score_line);
    }

    println!();
    for check in &report.checks {
        let tag = layer_tag(&check.layer);
        let status = if check.passed { "OK" } else { "FAIL" };
        let pad = 40_usize.saturating_sub(check.name.len());
        let dots = ".".repeat(pad);
        ui::status_line(
            &format!("  [{tag}] {} {dots}", check.name),
            &format!("{status} ({})", check.detail),
        );
    }

    let uncovered = SecurityPosture::uncovered_layers(&report.checks);
    if !uncovered.is_empty() {
        let names: Vec<&str> = uncovered.iter().map(|l| layer_name(l)).collect();
        println!(
            "\n  Not evaluated ({} layers): {}",
            uncovered.len(),
            names.join(", ")
        );
    }
}

fn layer_tag(layer: &SecurityLayer) -> &'static str {
    match layer {
        SecurityLayer::JailerIsolation => "JAILER",
        SecurityLayer::CgroupLimits => "CGROUP",
        SecurityLayer::SeccompFilter => "SECCOMP",
        SecurityLayer::NetworkIsolation => "NETWORK",
        SecurityLayer::VsockAuth => "VSOCK",
        SecurityLayer::EncryptionAtRest => "ENC-REST",
        SecurityLayer::EncryptionInTransit => "ENC-TRANSIT",
        SecurityLayer::AuditLogging => "AUDIT",
        SecurityLayer::SecretManagement => "SECRETS",
        SecurityLayer::ConfigImmutability => "CONFIG",
        SecurityLayer::GuestHardening => "GUEST",
        SecurityLayer::SupplyChainIntegrity => "SUPPLY",
    }
}

fn layer_name(layer: &SecurityLayer) -> &'static str {
    match layer {
        SecurityLayer::JailerIsolation => "JailerIsolation",
        SecurityLayer::CgroupLimits => "CgroupLimits",
        SecurityLayer::SeccompFilter => "SeccompFilter",
        SecurityLayer::NetworkIsolation => "NetworkIsolation",
        SecurityLayer::VsockAuth => "VsockAuth",
        SecurityLayer::EncryptionAtRest => "EncryptionAtRest",
        SecurityLayer::EncryptionInTransit => "EncryptionInTransit",
        SecurityLayer::AuditLogging => "AuditLogging",
        SecurityLayer::SecretManagement => "SecretManagement",
        SecurityLayer::ConfigImmutability => "ConfigImmutability",
        SecurityLayer::GuestHardening => "GuestHardening",
        SecurityLayer::SupplyChainIntegrity => "SupplyChainIntegrity",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_posture_check_construction() {
        let check = PostureCheck {
            layer: SecurityLayer::JailerIsolation,
            name: "Jailer binary available".to_string(),
            passed: true,
            detail: "jailer found".to_string(),
        };
        assert!(check.passed);
        assert_eq!(check.layer, SecurityLayer::JailerIsolation);
    }

    #[test]
    fn test_no_vm_check_always_fails() {
        let check = no_vm_check(SecurityLayer::SeccompFilter, "Seccomp strict profile");
        assert!(!check.passed);
        assert!(check.detail.contains("Lima VM not running"));
    }

    #[test]
    fn test_json_output_valid() {
        let checks = vec![
            PostureCheck {
                layer: SecurityLayer::JailerIsolation,
                name: "Jailer binary available".to_string(),
                passed: true,
                detail: "found".to_string(),
            },
            PostureCheck {
                layer: SecurityLayer::VsockAuth,
                name: "Vsock auth enabled".to_string(),
                passed: false,
                detail: "require_auth is false".to_string(),
            },
        ];
        let report = SecurityPosture::evaluate(checks, "2026-02-25T00:00:00Z");
        let json = serde_json::to_string_pretty(&report).unwrap();
        assert!(json.contains("\"score\""));
        assert!(json.contains("JailerIsolation"));
        assert!(json.contains("VsockAuth"));
    }

    #[test]
    fn test_vsock_auth_check_dev_default() {
        let policy = SecurityPolicy::default();
        assert!(!policy.require_auth);
    }

    #[test]
    fn test_layer_tag_coverage() {
        for layer in SecurityLayer::all() {
            let tag = layer_tag(layer);
            assert!(!tag.is_empty());
        }
    }

    #[test]
    fn test_layer_name_coverage() {
        for layer in SecurityLayer::all() {
            let name = layer_name(layer);
            assert!(!name.is_empty());
        }
    }
}
