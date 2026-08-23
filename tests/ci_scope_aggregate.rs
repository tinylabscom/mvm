//! Execute the `Test` aggregate's real shell against a synthetic scope matrix.
//!
//! CI is scope-reduced: the `scope` job classifies changed paths, lanes skip
//! when out of scope, and this aggregate asserts each lane's result *matches*
//! its scope. That arithmetic has a blind spot the lane itself cannot see —
//! a PR only exercises the one scope combination its own changed paths
//! produce. A change that breaks the gate for out-of-scope PRs therefore
//! passes on the PR that makes it, and fails on everyone else's.
//!
//! That is not hypothetical. Removing the kernel job's job-level `if:` made it
//! always run and always report `success`, while the aggregate still required
//! `skipped` when out of scope — which failed every PR not touching a kernel
//! path. The breaking change touched `ci.yml`, which puts the kernel lane *in*
//! scope, so it went green and merged.
//!
//! So these run the extracted script itself rather than restating its rules.
//! A restatement is a second copy of the logic and drifts from it silently;
//! executing the real bytes cannot.

use std::io::Write;
use std::process::{Command, Stdio};

/// Lift the aggregate's `run:` body out of the workflow, dedented.
///
/// Anchored on the step name rather than a line number so reordering the file
/// does not silently start testing a different script.
fn aggregate_script() -> String {
    let workflow = std::fs::read_to_string(".github/workflows/ci.yml")
        .expect("failed to read .github/workflows/ci.yml");
    const STEP: &str = "- name: Require every test lane to pass";
    let step = workflow
        .find(STEP)
        .expect("ci.yml must still have the test-aggregate step");
    let run = workflow[step..]
        .find("run: |")
        .map(|offset| step + offset)
        .expect("the aggregate step must have a run: block");

    let body: Vec<&str> = workflow[run..]
        .lines()
        .skip(1)
        .take_while(|line| line.trim().is_empty() || line.starts_with("          "))
        .collect();
    let script = body
        .iter()
        .map(|line| line.strip_prefix("          ").unwrap_or(line))
        .collect::<Vec<_>>()
        .join("\n");

    // `${{ }}` is interpolated by Actions before the shell ever sees it, so a
    // script containing one is neither executable here nor safe there — even
    // inside a comment. Refuse rather than test something that is not the
    // thing that runs.
    assert!(
        !script.contains("${{"),
        "the aggregate script must be driven purely by env, found an Actions expression:\n{script}"
    );
    assert!(
        script.contains("KERNEL_RESULT"),
        "extracted the wrong block:\n{script}"
    );
    script
}

/// One `needs.*.result` / scope combination fed to the aggregate.
struct Verdict {
    scope_result: &'static str,
    code: &'static str,
    lanes: &'static str,
    bdd_scope: &'static str,
    bdd: &'static str,
    kernel_scope: &'static str,
    kernel: &'static str,
    no_kvm_required: &'static str,
    no_kvm: &'static str,
}

impl Verdict {
    /// An everything-in-scope, everything-green run.
    fn in_scope() -> Self {
        Self {
            scope_result: "success",
            code: "true",
            lanes: "success",
            bdd_scope: "true",
            bdd: "success",
            kernel_scope: "true",
            kernel: "success",
            no_kvm_required: "true",
            no_kvm: "success",
        }
    }

    /// A docs-only run: every lane correctly skipped. The kernel job has no
    /// job-level `if:`, so it still runs and still reports `success`.
    fn out_of_scope() -> Self {
        Self {
            scope_result: "success",
            code: "false",
            lanes: "skipped",
            bdd_scope: "false",
            bdd: "skipped",
            kernel_scope: "false",
            kernel: "success",
            no_kvm_required: "false",
            no_kvm: "skipped",
        }
    }

    /// `true` when the aggregate admits this combination.
    fn accepts(&self) -> bool {
        let mut child = Command::new("bash")
            .arg("-s")
            .env("SCOPE_RESULT", self.scope_result)
            .env("SCOPE_CODE", self.code)
            .env("WORKSPACE_RESULT", self.lanes)
            // The aarch64 lane carries the same `code` scope as the other four
            // in the loop, so it moves with them rather than getting its own
            // field.
            .env("WORKSPACE_AARCH64_RESULT", self.lanes)
            .env("LINUX_RESULT", self.lanes)
            .env("RELEASE_WITNESS_RESULT", self.lanes)
            .env("EBPF_RESULT", self.lanes)
            .env("SCOPE_BDD", self.bdd_scope)
            .env("BDD_RESULT", self.bdd)
            .env("KERNEL_SCOPE", self.kernel_scope)
            .env("KERNEL_RESULT", self.kernel)
            .env("NO_KVM_REQUIRED", self.no_kvm_required)
            .env("NO_KVM_RESULT", self.no_kvm)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("failed to spawn bash");
        child
            .stdin
            .take()
            .expect("piped stdin")
            .write_all(aggregate_script().as_bytes())
            .expect("failed to feed the script to bash");
        child.wait().expect("bash did not exit").success()
    }
}

/// The regression that motivated this file, stated as the property it broke.
///
/// A docs-only PR skips every lane it should and still runs the kernel job,
/// which succeeds with its steps skipped. That must be admitted. Requiring
/// `skipped` from a job that no longer skips left the entire open-PR backlog
/// unmergeable while every individual lane reported green.
#[test]
fn a_fully_out_of_scope_run_is_admitted() {
    assert!(
        Verdict::out_of_scope().accepts(),
        "a PR touching no code, no bdd and no kernel path must pass the aggregate"
    );
}

#[test]
fn a_fully_in_scope_green_run_is_admitted() {
    assert!(Verdict::in_scope().accepts());
}

#[test]
fn an_in_scope_pull_request_may_skip_the_merge_group_only_smoke() {
    assert!(
        Verdict {
            no_kvm_required: "false",
            no_kvm: "skipped",
            ..Verdict::in_scope()
        }
        .accepts()
    );
}

/// The gate must not have been widened into a rubber stamp. Each of these is a
/// real failure that has to keep being caught, in whichever scope it can occur.
#[test]
fn a_genuine_failure_is_still_refused_in_either_scope() {
    let cases: [(&str, Verdict); 7] = [
        (
            "a failing kernel build, in scope",
            Verdict {
                kernel: "failure",
                ..Verdict::in_scope()
            },
        ),
        (
            "a failing kernel build, out of scope",
            Verdict {
                kernel: "failure",
                ..Verdict::out_of_scope()
            },
        ),
        (
            "a failing test lane",
            Verdict {
                lanes: "failure",
                ..Verdict::in_scope()
            },
        ),
        (
            "a test lane that skipped while in scope",
            Verdict {
                lanes: "skipped",
                ..Verdict::in_scope()
            },
        ),
        (
            "a bdd lane that skipped while in scope",
            Verdict {
                bdd: "skipped",
                ..Verdict::in_scope()
            },
        ),
        (
            "the scope job itself failing",
            Verdict {
                scope_result: "failure",
                ..Verdict::in_scope()
            },
        ),
        (
            "the required aarch64 no-KVM smoke failing",
            Verdict {
                no_kvm: "failure",
                ..Verdict::in_scope()
            },
        ),
    ];
    for (what, verdict) in cases {
        assert!(!verdict.accepts(), "the aggregate must refuse {what}");
    }
}

#[test]
fn aggregate_depends_on_the_aarch64_no_kvm_smoke() {
    let workflow = std::fs::read_to_string(".github/workflows/ci.yml")
        .expect("failed to read .github/workflows/ci.yml");
    let test_job = workflow
        .split_once("\n  test:\n")
        .map(|(_, rest)| rest)
        .and_then(|rest| rest.split_once("\n  test-workspace:\n").map(|(job, _)| job))
        .expect("Test aggregate job must remain delimited by test-workspace");
    assert!(
        test_job.contains("aarch64-no-kvm-smoke"),
        "the required Test aggregate must depend on the live no-KVM smoke"
    );
    assert!(test_job.contains("NO_KVM_RESULT"));
}

/// A malformed scope output must fail closed rather than be read as one of the
/// two valid values.
#[test]
fn an_unparseable_scope_is_refused() {
    assert!(
        !Verdict {
            code: "",
            ..Verdict::in_scope()
        }
        .accepts(),
        "an empty code scope must not be treated as a valid classification"
    );
}
