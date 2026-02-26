use mvm_core::security::{PostureCheck, PostureReport, SecurityLayer};

/// Evaluates security posture from a set of individual checks.
///
/// Computes an overall percentage score (`passed / total * 100`) and
/// produces a timestamped [`PostureReport`].
pub struct SecurityPosture;

impl SecurityPosture {
    /// Evaluate a set of posture checks into an overall report.
    ///
    /// The score is `passed_checks / total_checks * 100.0`.
    /// An empty check list produces a score of 0.
    pub fn evaluate(checks: Vec<PostureCheck>, timestamp: &str) -> PostureReport {
        let total = checks.len();
        let passed = checks.iter().filter(|c| c.passed).count();
        let score = if total == 0 {
            0.0
        } else {
            (passed as f64 / total as f64) * 100.0
        };

        PostureReport {
            checks,
            score,
            timestamp: timestamp.to_string(),
        }
    }

    /// Return which security layers have no checks at all in the given list.
    ///
    /// Useful for detecting uncovered layers that should be evaluated.
    pub fn uncovered_layers(checks: &[PostureCheck]) -> Vec<&'static SecurityLayer> {
        SecurityLayer::all()
            .iter()
            .filter(|layer| !checks.iter().any(|c| &c.layer == *layer))
            .collect()
    }

    /// Return only the checks that failed.
    pub fn failed_checks(checks: &[PostureCheck]) -> Vec<&PostureCheck> {
        checks.iter().filter(|c| !c.passed).collect()
    }

    /// Return only the checks that passed.
    pub fn passed_checks(checks: &[PostureCheck]) -> Vec<&PostureCheck> {
        checks.iter().filter(|c| c.passed).collect()
    }

    /// Produce a human-readable summary of a posture report.
    pub fn summary(report: &PostureReport) -> String {
        let total = report.checks.len();
        let passed = report.checks.iter().filter(|c| c.passed).count();
        let failed = total - passed;

        let mut out = format!(
            "Security Posture: {:.0}% ({}/{} checks passed)\n",
            report.score, passed, total
        );

        if failed > 0 {
            out.push_str("\nFailed checks:\n");
            for check in &report.checks {
                if !check.passed {
                    out.push_str(&format!(
                        "  - [{}] {}: {}\n",
                        layer_tag(&check.layer),
                        check.name,
                        check.detail
                    ));
                }
            }
        }

        out
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

#[cfg(test)]
mod tests {
    use super::*;

    fn make_check(layer: SecurityLayer, name: &str, passed: bool) -> PostureCheck {
        PostureCheck {
            layer,
            name: name.to_string(),
            passed,
            detail: if passed {
                "enabled".to_string()
            } else {
                "not configured".to_string()
            },
        }
    }

    #[test]
    fn test_evaluate_all_passing() {
        let checks = vec![
            make_check(SecurityLayer::JailerIsolation, "jailer", true),
            make_check(SecurityLayer::CgroupLimits, "cgroups", true),
            make_check(SecurityLayer::SeccompFilter, "seccomp", true),
        ];
        let report = SecurityPosture::evaluate(checks, "2026-02-25T00:00:00Z");
        assert_eq!(report.score, 100.0);
        assert_eq!(report.checks.len(), 3);
    }

    #[test]
    fn test_evaluate_mixed() {
        let checks = vec![
            make_check(SecurityLayer::JailerIsolation, "jailer", true),
            make_check(SecurityLayer::CgroupLimits, "cgroups", false),
            make_check(SecurityLayer::SeccompFilter, "seccomp", true),
            make_check(SecurityLayer::VsockAuth, "auth", false),
        ];
        let report = SecurityPosture::evaluate(checks, "2026-02-25T00:00:00Z");
        assert_eq!(report.score, 50.0);
    }

    #[test]
    fn test_evaluate_all_failing() {
        let checks = vec![
            make_check(SecurityLayer::JailerIsolation, "jailer", false),
            make_check(SecurityLayer::CgroupLimits, "cgroups", false),
        ];
        let report = SecurityPosture::evaluate(checks, "2026-02-25T00:00:00Z");
        assert_eq!(report.score, 0.0);
    }

    #[test]
    fn test_evaluate_empty() {
        let report = SecurityPosture::evaluate(vec![], "2026-02-25T00:00:00Z");
        assert_eq!(report.score, 0.0);
        assert!(report.checks.is_empty());
    }

    #[test]
    fn test_uncovered_layers() {
        let checks = vec![
            make_check(SecurityLayer::JailerIsolation, "jailer", true),
            make_check(SecurityLayer::CgroupLimits, "cgroups", true),
        ];
        let uncovered = SecurityPosture::uncovered_layers(&checks);
        // 12 total - 2 covered = 10 uncovered
        assert_eq!(uncovered.len(), 10);
        assert!(!uncovered.contains(&&SecurityLayer::JailerIsolation));
        assert!(!uncovered.contains(&&SecurityLayer::CgroupLimits));
        assert!(uncovered.contains(&&SecurityLayer::SeccompFilter));
    }

    #[test]
    fn test_failed_checks() {
        let checks = vec![
            make_check(SecurityLayer::JailerIsolation, "jailer", true),
            make_check(SecurityLayer::CgroupLimits, "cgroups", false),
            make_check(SecurityLayer::SeccompFilter, "seccomp", false),
        ];
        let failed = SecurityPosture::failed_checks(&checks);
        assert_eq!(failed.len(), 2);
        assert_eq!(failed[0].layer, SecurityLayer::CgroupLimits);
        assert_eq!(failed[1].layer, SecurityLayer::SeccompFilter);
    }

    #[test]
    fn test_passed_checks() {
        let checks = vec![
            make_check(SecurityLayer::JailerIsolation, "jailer", true),
            make_check(SecurityLayer::CgroupLimits, "cgroups", false),
            make_check(SecurityLayer::SeccompFilter, "seccomp", true),
        ];
        let passed = SecurityPosture::passed_checks(&checks);
        assert_eq!(passed.len(), 2);
        assert_eq!(passed[0].layer, SecurityLayer::JailerIsolation);
        assert_eq!(passed[1].layer, SecurityLayer::SeccompFilter);
    }

    #[test]
    fn test_summary_all_passing() {
        let checks = vec![
            make_check(SecurityLayer::JailerIsolation, "jailer", true),
            make_check(SecurityLayer::CgroupLimits, "cgroups", true),
        ];
        let report = SecurityPosture::evaluate(checks, "2026-02-25T00:00:00Z");
        let summary = SecurityPosture::summary(&report);
        assert!(summary.contains("100%"));
        assert!(summary.contains("2/2"));
        assert!(!summary.contains("Failed checks:"));
    }

    #[test]
    fn test_summary_with_failures() {
        let checks = vec![
            make_check(SecurityLayer::JailerIsolation, "jailer", true),
            make_check(SecurityLayer::VsockAuth, "vsock auth", false),
        ];
        let report = SecurityPosture::evaluate(checks, "2026-02-25T00:00:00Z");
        let summary = SecurityPosture::summary(&report);
        assert!(summary.contains("50%"));
        assert!(summary.contains("Failed checks:"));
        assert!(summary.contains("[VSOCK]"));
        assert!(summary.contains("vsock auth"));
    }

    #[test]
    fn test_evaluate_timestamp_preserved() {
        let report = SecurityPosture::evaluate(vec![], "2026-02-25T12:34:56Z");
        assert_eq!(report.timestamp, "2026-02-25T12:34:56Z");
    }

    #[test]
    fn test_evaluate_single_check_score() {
        let checks = vec![make_check(
            SecurityLayer::AuditLogging,
            "audit enabled",
            true,
        )];
        let report = SecurityPosture::evaluate(checks, "2026-02-25T00:00:00Z");
        assert_eq!(report.score, 100.0);
    }

    #[test]
    fn test_layer_tag_coverage() {
        // Ensure every SecurityLayer has a tag (no panic)
        for layer in SecurityLayer::all() {
            let tag = layer_tag(layer);
            assert!(!tag.is_empty());
        }
    }

    #[test]
    fn test_uncovered_layers_all_covered() {
        let checks: Vec<PostureCheck> = SecurityLayer::all()
            .iter()
            .map(|layer| make_check(layer.clone(), "check", true))
            .collect();
        let uncovered = SecurityPosture::uncovered_layers(&checks);
        assert!(uncovered.is_empty());
    }
}
