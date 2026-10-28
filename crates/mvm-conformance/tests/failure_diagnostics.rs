#[path = "support/failure_diagnostics.rs"]
mod failure_diagnostics;

#[test]
fn collector_hooks_are_available_without_running_commands() {
    let _ = failure_diagnostics::begin_scenario;
    let _ = failure_diagnostics::observe;
    let _ = failure_diagnostics::initialize;
    let _ = failure_diagnostics::finalize;
    assert_eq!(
        failure_diagnostics::DESTINATION_ENV,
        "MVM_E2E_FAILURE_MANIFEST"
    );
}

#[test]
fn workflow_authorizes_only_fresh_isolated_manifest() {
    let workflow = include_str!("../../../.github/workflows/e2e-docs.yml");
    assert!(workflow.contains(
        "MVM_E2E_FAILURE_MANIFEST: ${{ runner.temp }}/failure-manifest-${{ github.run_id }}-${{ github.run_attempt }}-${{ strategy.job-index }}.json"
    ));
    assert!(workflow.contains("id: documented-suite"));
    assert!(workflow.contains("${{ steps.documented-suite.outputs.failure_manifest }}"));
    assert!(workflow.contains("id: failure-export\n        if: always()"));
    assert!(workflow.contains(
        "MVM_E2E_FAILURE_AUTHORIZATION: ${{ steps.documented-suite.outputs.failure_manifest }}"
    ));
    assert!(workflow.contains("python3 scripts/e2e-failure-manifest.py --export"));
    let upload = workflow
        .split("- name: Upload the suite log and VM logs")
        .nth(1)
        .unwrap();
    assert!(upload.contains("${{ steps.failure-export.outputs.failure_manifest }}"));
    assert!(!upload.contains("${{ steps.documented-suite.outputs.failure_manifest }}"));
    let script = include_str!("../../../scripts/e2e-documented-surface.sh");
    assert!(
        script.find("e2e-failure-manifest.py").unwrap()
            < script.find("\"$MVMCTL\" bootstrap").unwrap()
    );
    let runner = include_str!("conformance.rs");
    assert!(
        runner.find("failure_diagnostics::initialize()").unwrap()
            < runner.find("check_mvmctl_freshness()").unwrap()
    );
    assert!(
        runner.find("failure_diagnostics::finalize()").unwrap()
            < runner.find("writer.execution_has_failed()").unwrap()
    );
}

fn initializer(path: &std::path::Path, github_output: &std::path::Path) -> std::process::Output {
    std::process::Command::new("python3")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../scripts/e2e-failure-manifest.py"
        ))
        .env("MVM_E2E_FAILURE_MANIFEST", path)
        .env("GITHUB_OUTPUT", github_output)
        .output()
        .unwrap()
}

fn exporter(
    source: &std::path::Path,
    destination: &std::path::Path,
    github_output: &std::path::Path,
) -> std::process::Output {
    std::process::Command::new("python3")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../scripts/e2e-failure-manifest.py"
        ))
        .arg("--export")
        .env("MVM_E2E_FAILURE_MANIFEST", source)
        .env("MVM_E2E_FAILURE_AUTHORIZATION", source)
        .env("MVM_E2E_FAILURE_EXPORT", destination)
        .env("GITHUB_OUTPUT", github_output)
        .output()
        .unwrap()
}

fn run_script_seam(
    path: &std::path::Path,
    output: &std::path::Path,
    case: &str,
) -> std::process::Output {
    let script = include_str!("../../../scripts/e2e-documented-surface.sh");
    let seam = script
        .split("# Diagnostic initialization")
        .nth(1)
        .unwrap()
        .split("# Prefer an explicit")
        .next()
        .unwrap();
    let seam = seam.split_once('\n').unwrap().1;
    let continuation = if case == "bootstrap_failure" {
        "exit 37"
    } else {
        "\"$DIAGNOSTIC_TEST_EXE\" --exact failure_diagnostics::tests::lifecycle_child --nocapture; exit 37"
    };
    std::process::Command::new("bash")
        .args(["-c", &format!("set -euo pipefail\n{seam}\n{continuation}")])
        .env("REPO", concat!(env!("CARGO_MANIFEST_DIR"), "/../.."))
        .env("MVM_E2E_FAILURE_MANIFEST", path)
        .env("GITHUB_OUTPUT", output)
        .env("DIAGNOSTIC_TEST_EXE", std::env::current_exe().unwrap())
        .env("MVM_DIAGNOSTIC_TEST_CASE", case)
        .output()
        .unwrap()
}
