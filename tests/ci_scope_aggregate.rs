//! Execute the `Test` aggregate's real shell against a synthetic scope matrix.
//!
//! CI is scope-reduced: the `scope` job classifies changed paths, lanes skip
//! when out of scope, and this aggregate asserts each lane's result *matches*
//! its scope. Pull requests and merge groups share the deterministic matrix;
//! only integration checks such as Nix and published-image boot differ by
//! event.
//!
//! That is not hypothetical. A lane that lost its job-level `if:` once
//! reported `success` on every run, while the aggregate still required
//! `skipped` when out of scope — which failed every PR not touching that
//! lane's paths. The breaking change touched `ci.yml`, which put the lane *in*
//! scope, so it went green and merged.
//!
//! So these run the extracted script itself rather than restating its rules.
//! A restatement is a second copy of the logic and drifts from it silently;
//! executing the real bytes cannot.

use std::process::{Command, Stdio};

/// Lift one aggregate step's `run:` body out of the workflow, dedented.
///
/// Anchored on the step name rather than a line number so reordering the file
/// does not silently start testing a different script.
fn step_script(step_name: &str, sentinel: &str) -> String {
    let workflow = std::fs::read_to_string(".github/workflows/ci.yml")
        .expect("failed to read .github/workflows/ci.yml");
    let marker = format!("- name: {step_name}");
    let step = workflow
        .find(&marker)
        .unwrap_or_else(|| panic!("ci.yml must still have the {step_name} step"));
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
        script.contains(sentinel),
        "extracted the wrong block:\n{script}"
    );
    script
}

fn aggregate_script() -> String {
    step_script("Require every validation lane to pass", "NIX_RESULT")
}

/// One `needs.*.result` / scope combination fed to the aggregate.
struct Verdict {
    event_name: &'static str,
    scope_result: &'static str,
    code: &'static str,
    /// The `lane-scope` job's result, and the BDD lane scope it published.
    lane_scope: &'static str,
    bdd_scope: &'static str,
    policy: &'static str,
    preflight: &'static str,
    lanes: &'static str,
    /// Kept separate from `lanes` because it follows its own lane scope.
    bdd: &'static str,
    boot: &'static str,
    nix: &'static str,
}

impl Verdict {
    /// An everything-in-scope, everything-green run.
    fn in_scope() -> Self {
        Self {
            event_name: "pull_request",
            scope_result: "success",
            code: "true",
            lane_scope: "success",
            bdd_scope: "true",
            policy: "success",
            preflight: "success",
            lanes: "success",
            bdd: "success",
            boot: "skipped",
            nix: "skipped",
        }
    }

    /// A docs-only run: every lane it should skips.
    fn out_of_scope() -> Self {
        Self {
            event_name: "pull_request",
            scope_result: "success",
            code: "false",
            lane_scope: "skipped",
            bdd_scope: "",
            policy: "success",
            preflight: "skipped",
            lanes: "skipped",
            bdd: "skipped",
            boot: "skipped",
            nix: "skipped",
        }
    }

    /// A code change the BDD lane's scope does not reach: every other lane
    /// runs, BDD skips.
    fn bdd_out_of_scope() -> Self {
        Self {
            bdd_scope: "false",
            bdd: "skipped",
            ..Self::in_scope()
        }
    }

    /// The cumulative merge-group head runs every queue job for an in-scope
    /// code and Nix change.
    fn queue_in_scope() -> Self {
        Self {
            event_name: "merge_group",
            preflight: "skipped",
            boot: "success",
            nix: "success",
            ..Self::in_scope()
        }
    }

    /// A docs-only merge group still executes Nix, while scoped lanes skip.
    fn queue_out_of_scope() -> Self {
        Self {
            event_name: "merge_group",
            preflight: "skipped",
            nix: "success",
            ..Self::out_of_scope()
        }
    }

    /// `true` when the aggregate admits this combination.
    fn accepts(&self) -> bool {
        let mut child = Command::new("bash")
            .arg("-c")
            .arg(aggregate_script())
            .env("EVENT_NAME", self.event_name)
            .env("SCOPE_RESULT", self.scope_result)
            .env("SCOPE_CODE", self.code)
            .env("LANE_SCOPE_RESULT", self.lane_scope)
            .env("SCOPE_BDD", self.bdd_scope)
            .env("PREFLIGHT_RESULT", self.preflight)
            .env("CORE_RESULT", self.lanes)
            .env("POLICY_RESULT", self.policy)
            .env("FEATURES_RESULT", self.lanes)
            .env("FEATURES_SUPPORT_RESULT", self.lanes)
            .env("FEATURES_EMBED_RESULT", self.lanes)
            .env("WORKSPACE_RESULT", self.lanes)
            // The aarch64 workspace lane carries the same `code` scope as the
            // other four in the loop, so it moves with them rather than getting
            // its own field.
            .env("WORKSPACE_AARCH64_RESULT", self.lanes)
            .env("LINUX_RESULT", self.lanes)
            .env("RELEASE_WITNESS_RESULT", self.lanes)
            .env("EBPF_RESULT", self.lanes)
            .env("BDD_RESULT", self.bdd)
            .env("BOOT_RESULT", self.boot)
            .env("NIX_RESULT", self.nix)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("failed to spawn bash");
        child.wait().expect("bash did not exit").success()
    }
}

/// The regression that motivated this file, stated as the property it broke.
///
/// A docs-only PR skips every lane it should. That must be admitted: a gate
/// that demanded otherwise once left the entire open-PR backlog unmergeable
/// while every individual lane reported green.
#[test]
fn a_fully_out_of_scope_run_is_admitted() {
    assert!(
        Verdict::out_of_scope().accepts(),
        "a PR touching no code and no bdd path must pass the aggregate"
    );
}

#[test]
fn a_fully_in_scope_green_run_is_admitted() {
    assert!(Verdict::in_scope().accepts());
    assert!(
        Verdict::bdd_out_of_scope().accepts(),
        "a code change outside the BDD lane's scope must admit a skipped BDD lane"
    );
    assert!(Verdict::queue_in_scope().accepts());
    assert!(Verdict::queue_out_of_scope().accepts());
}

/// The gate must not have been widened into a rubber stamp. Each of these is a
/// real failure that has to keep being caught, in whichever scope it can occur.
#[test]
fn a_genuine_failure_is_still_refused_in_either_scope() {
    let cases: [(&str, Verdict); 17] = [
        (
            "a bdd lane that ran while its lane scope was false",
            Verdict {
                bdd: "success",
                ..Verdict::bdd_out_of_scope()
            },
        ),
        (
            "a bdd lane that skipped while its lane scope was true",
            Verdict {
                bdd: "skipped",
                ..Verdict::in_scope()
            },
        ),
        (
            "a failed lane-scope job, even with BDD skipped",
            Verdict {
                lane_scope: "failure",
                bdd_scope: "",
                bdd: "skipped",
                ..Verdict::in_scope()
            },
        ),
        (
            "a lane-scope job that skipped while code was in scope",
            Verdict {
                lane_scope: "skipped",
                bdd_scope: "",
                bdd: "skipped",
                ..Verdict::in_scope()
            },
        ),
        (
            "a lane-scope job that ran while code was out of scope",
            Verdict {
                lane_scope: "success",
                ..Verdict::out_of_scope()
            },
        ),
        (
            "a missing bdd lane scope while code was in scope",
            Verdict {
                bdd_scope: "",
                bdd: "skipped",
                ..Verdict::in_scope()
            },
        ),
        (
            "a bdd lane scope of true while code was out of scope",
            Verdict {
                bdd_scope: "true",
                ..Verdict::out_of_scope()
            },
        ),
        (
            "a bdd lane that ran while code was out of scope",
            Verdict {
                bdd: "success",
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
            "the scope job itself failing",
            Verdict {
                scope_result: "failure",
                ..Verdict::in_scope()
            },
        ),
        (
            "a failing policy lane",
            Verdict {
                policy: "failure",
                ..Verdict::in_scope()
            },
        ),
        (
            "a failing PR preflight",
            Verdict {
                preflight: "failure",
                ..Verdict::in_scope()
            },
        ),
        (
            "a failing published-image boot ceiling",
            Verdict {
                boot: "failure",
                ..Verdict::queue_in_scope()
            },
        ),
        (
            "a published-image boot that ran while out of scope",
            Verdict {
                boot: "success",
                ..Verdict::queue_out_of_scope()
            },
        ),
        (
            "a failing Nix witness",
            Verdict {
                nix: "failure",
                ..Verdict::queue_in_scope()
            },
        ),
        (
            "a Nix witness that skipped in the queue",
            Verdict {
                nix: "skipped",
                ..Verdict::queue_in_scope()
            },
        ),
    ];
    for (what, verdict) in cases {
        assert!(!verdict.accepts(), "the aggregate must refuse {what}");
    }
}

#[test]
fn aggregate_does_not_depend_on_the_no_kvm_smoke() {
    let workflow = std::fs::read_to_string(".github/workflows/ci.yml")
        .expect("failed to read .github/workflows/ci.yml");
    let test_job = workflow
        .split_once("\n  test:\n")
        .map(|(_, rest)| rest)
        .and_then(|rest| rest.split_once("\n  test-workspace:\n").map(|(job, _)| job))
        .expect("Test aggregate job must remain delimited by test-workspace");
    assert!(
        !test_job.contains("no-kvm-smoke"),
        "the Test aggregate must not depend on the no-KVM smoke; it lives in ci-full.yml"
    );
    assert!(
        !test_job.contains("NO_KVM_RESULT"),
        "the Test aggregate must not reference the no-KVM smoke result"
    );
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
