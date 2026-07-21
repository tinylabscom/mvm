//! Tests for `doctor`'s own public surface (`Check`, `DoctorWorkflow`,
//! `issue_summary_lines`) plus full-`DoctorReport` construction, which
//! spans every submodule's `collect_*` entry point.

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
fn issue_summary_lines_include_every_failed_check() {
    let missing = [
        Check {
            name: "cargo",
            category: "prerequisites",
            ok: false,
            info: "missing".into(),
        },
        Check {
            name: "disk space",
            category: "platform",
            ok: false,
            info: "only 2 GiB free".into(),
        },
    ];
    let refs: Vec<&Check> = missing.iter().collect();

    let lines = issue_summary_lines(&refs);

    assert_eq!(
        lines,
        vec![
            "  cargo — missing".to_string(),
            "  disk space — only 2 GiB free".to_string(),
        ]
    );
}

// ---------------- Workflow scoping ----------------

#[test]
fn workflow_cli_run_includes_all_categories() {
    let cats = DoctorWorkflow::CliRun.relevant_categories();
    for expected in ["prerequisites", "tools", "platform", "security", "disk"] {
        assert!(
            cats.contains(&expected),
            "cli-run missing category {expected}"
        );
    }
}

#[test]
fn workflow_python_and_typescript_sdk_match_cli_run() {
    // The SDK flows share the host requirements with `cli-run` —
    // both ultimately call `mvmctl up` / `mvmctl build` under the
    // hood. If this assertion ever drifts, that's a deliberate
    // workflow-specific check change that needs review.
    assert_eq!(
        DoctorWorkflow::CliRun.relevant_categories(),
        DoctorWorkflow::PythonSdk.relevant_categories()
    );
    assert_eq!(
        DoctorWorkflow::CliRun.relevant_categories(),
        DoctorWorkflow::TypescriptSdk.relevant_categories()
    );
}

#[test]
fn workflow_bundle_run_drops_prerequisites_and_tools() {
    let cats = DoctorWorkflow::BundleRun.relevant_categories();
    assert!(
        !cats.contains(&"prerequisites"),
        "bundle-run must not gate on host rust"
    );
    assert!(
        !cats.contains(&"tools"),
        "bundle-run must not gate on builder VM tools"
    );
    for required in ["platform", "security", "disk"] {
        assert!(cats.contains(&required), "bundle-run needs {required}");
    }
}

#[test]
fn workflow_dev_shell_drops_prerequisites_only() {
    let cats = DoctorWorkflow::DevShell.relevant_categories();
    assert!(
        !cats.contains(&"prerequisites"),
        "dev-shell must not gate on host rustup/cargo — the dev VM owns the toolchain"
    );
    // Dev shell DOES need builder-VM tools.
    assert!(cats.contains(&"tools"));
    assert!(cats.contains(&"platform"));
}

#[test]
fn workflow_as_str_kebab_case() {
    assert_eq!(DoctorWorkflow::CliRun.as_str(), "cli-run");
    assert_eq!(DoctorWorkflow::PythonSdk.as_str(), "python-sdk");
    assert_eq!(DoctorWorkflow::TypescriptSdk.as_str(), "typescript-sdk");
    assert_eq!(DoctorWorkflow::BundleRun.as_str(), "bundle-run");
    assert_eq!(DoctorWorkflow::DevShell.as_str(), "dev-shell");
}

#[test]
fn workflow_serde_renders_kebab_case() {
    // The `--workflow` flag and the JSON output need the same
    // kebab-case string, so the `Serialize` derive must match
    // the clap ValueEnum form. Pin both.
    let json = serde_json::to_string(&DoctorWorkflow::BundleRun).unwrap();
    assert_eq!(json, "\"bundle-run\"");
    let json = serde_json::to_string(&DoctorWorkflow::DevShell).unwrap();
    assert_eq!(json, "\"dev-shell\"");
}

/// Demonstrates the filter behavior: an irrelevant failed
/// check is dropped from the workflow-scoped report.
/// `BundleRun` skips `prerequisites`, so a failed `cargo`
/// check shouldn't appear in a bundle-run-scoped run.
#[test]
fn workflow_filter_drops_irrelevant_failed_checks() {
    let all_checks = [
        Check {
            name: "cargo",
            category: "prerequisites",
            ok: false,
            info: "missing".into(),
        },
        Check {
            name: "platform",
            category: "platform",
            ok: true,
            info: "macOS".into(),
        },
    ];

    let workflow = DoctorWorkflow::BundleRun;
    let relevant = workflow.relevant_categories();
    let filtered: Vec<&Check> = all_checks
        .iter()
        .filter(|c| relevant.contains(&c.category))
        .collect();

    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0].name, "platform");
    // The previously-failing `cargo` check is now invisible, so
    // `all_ok` over the filtered set is `true`.
    let all_ok_filtered = filtered.iter().all(|c| c.ok);
    assert!(all_ok_filtered);
}

// ---------------- Full DoctorReport construction ----------------

#[test]
fn doctor_report_serializes_capability_table() {
    let json = serde_json::to_string(&DoctorReport {
        workflow: None,
        checks: vec![],
        security_posture: security::collect_security_posture(),
        balloon_support: security::collect_balloon_support(),
        warm_start: warm_start::collect_warm_start_support(),
        capability_table: warm_start::collect_capability_table(),
        all_ok: true,
    })
    .unwrap();
    assert!(json.contains("\"capability_table\""), "{json}");
    assert!(json.contains("\"snapshot_tier\""), "{json}");
}

#[test]
fn doctor_report_serializes_warm_start() {
    let json = serde_json::to_string(&DoctorReport {
        workflow: None,
        checks: vec![],
        security_posture: security::collect_security_posture(),
        balloon_support: security::collect_balloon_support(),
        warm_start: warm_start::collect_warm_start_support(),
        capability_table: warm_start::collect_capability_table(),
        all_ok: true,
    })
    .unwrap();
    assert!(json.contains("\"warm_start\""), "{json}");
    assert!(json.contains("\"live-memory\""), "{json}");
}

#[test]
fn doctor_report_serializes_to_json() {
    let report = DoctorReport {
        workflow: None,
        checks: vec![Check {
            name: "test",
            category: "tools",
            ok: true,
            info: "v1.0".to_string(),
        }],
        security_posture: security::collect_security_posture(),
        balloon_support: security::collect_balloon_support(),
        warm_start: warm_start::collect_warm_start_support(),
        capability_table: warm_start::collect_capability_table(),
        all_ok: true,
    };
    let json = serde_json::to_string(&report).unwrap();
    assert!(json.contains("\"name\":\"test\""));
    assert!(json.contains("\"all_ok\":true"));
    assert!(json.contains("\"security_posture\""));
    assert!(json.contains("\"tier\""));
    // Default (no --workflow) omits the field entirely thanks to
    // `#[serde(skip_serializing_if = …)]`.
    assert!(
        !json.contains("\"workflow\""),
        "default report must not serialize the workflow field; got: {json}"
    );
}

#[test]
fn doctor_report_serializes_workflow_when_set() {
    let report = DoctorReport {
        workflow: Some("bundle-run"),
        checks: vec![],
        security_posture: security::collect_security_posture(),
        balloon_support: security::collect_balloon_support(),
        warm_start: warm_start::collect_warm_start_support(),
        capability_table: warm_start::collect_capability_table(),
        all_ok: true,
    };
    let json = serde_json::to_string(&report).unwrap();
    assert!(
        json.contains("\"workflow\":\"bundle-run\""),
        "workflow-scoped report must serialize the field; got: {json}"
    );
}
