//! Execute the `Test` aggregate's real shell against synthetic lane results.
//!
//! CI has two tiers. A pull request runs the fast gate — formatting, clippy
//! over the core build and the feature combinations, the policy gates, a
//! compile of every workspace test target and the sharded x86_64 suite. The
//! merge queue runs the same fast gate against the integrated commit. The full
//! matrix — the fast-gate lanes plus every slow lane — runs on a push to main,
//! after the merge. Within each tier the `scope` job still
//! classifies changed paths, lanes skip when out of scope, and this aggregate
//! asserts each lane's result *matches* what its tier and scope require.
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

/// Fast-gate lanes: they run on a pull request and a push, and follow the
/// `code` scope. `CORE_RESULT` is the only one that also runs in the queue.
const GATE_LANES: [&str; 5] = [
    "CORE_RESULT",
    "FEATURE_CLIPPY_RESULT",
    "WINDOWS_RESULT",
    "WINDOWS_IDENTITY_RESULT",
    "WORKSPACE_RESULT",
];

/// The fast-gate lanes the queue skips: they passed on the PR head and run
/// again on push.
const PR_ONLY_LANES: [&str; 4] = [
    "FEATURE_CLIPPY_RESULT",
    "WINDOWS_RESULT",
    "WINDOWS_IDENTITY_RESULT",
    "WORKSPACE_RESULT",
];

/// Full-matrix lanes: skipped on every pull request and in the merge queue,
/// and following the `code` scope on a push to main and a manual dispatch.
const FULL_LANES: [&str; 10] = [
    "FEATURES_RESULT",
    "FEATURES_SUPPORT_RESULT",
    "FEATURES_EMBED_RESULT",
    "WORKSPACE_EXTRAS_RESULT",
    "WORKSPACE_AARCH64_RESULT",
    "LINUX_RESULT",
    "RELEASE_WITNESS_RESULT",
    "MUSL_CONFINEMENT_RESULT",
    "EBPF_RESULT",
    "BOOT_RESULT",
];

/// One `needs.*.result` / scope combination fed to the aggregate.
#[derive(Clone)]
struct Verdict {
    event_name: &'static str,
    scope_result: &'static str,
    code: &'static str,
    /// The documentation-corpus scope. It brings only the BDD lane into scope.
    docs: &'static str,
    nix_scope: &'static str,
    runners_result: &'static str,
    /// Where the runner picker sent the x86_64 workspace suite.
    workspace_runner: &'static str,
    policy: &'static str,
    gate: &'static str,
    /// The hosted suite's archive build, which the self-hosted path skips.
    archive: &'static str,
    full: &'static str,
    bdd: &'static str,
    nix: &'static str,
    /// Per-lane results that override the tier defaults above.
    overrides: Vec<(&'static str, &'static str)>,
}

impl Verdict {
    /// A code change on a pull request: the fast gate runs and passes, and
    /// every full-matrix lane skips.
    fn pr_in_scope() -> Self {
        Self {
            event_name: "pull_request",
            scope_result: "success",
            code: "true",
            docs: "false",
            nix_scope: "true",
            runners_result: "success",
            workspace_runner: "github",
            policy: "success",
            gate: "success",
            archive: "success",
            full: "skipped",
            bdd: "skipped",
            nix: "skipped",
            overrides: Vec::new(),
        }
    }

    /// A pull request touching nothing any lane reads — a plan, a site asset:
    /// only the unscoped policy lane runs.
    fn pr_out_of_scope() -> Self {
        Self {
            code: "false",
            nix_scope: "false",
            gate: "skipped",
            archive: "skipped",
            ..Self::pr_in_scope()
        }
    }

    /// The same code change after the merge, on a push to main: everything runs.
    fn main_in_scope() -> Self {
        Self {
            event_name: "push",
            full: "success",
            bdd: "success",
            nix: "success",
            ..Self::pr_in_scope()
        }
    }

    /// An out-of-scope push: still only the policy lane.
    fn main_out_of_scope() -> Self {
        Self {
            event_name: "push",
            ..Self::pr_out_of_scope()
        }
    }

    /// A pull request confined to the documentation corpus. BDD is the only
    /// lane the corpus brings into scope, and BDD is full-matrix, so the PR
    /// runs nothing beyond the policy lane.
    fn pr_docs_only() -> Self {
        Self {
            docs: "true",
            ..Self::pr_out_of_scope()
        }
    }

    /// That change on a push to main, where the documentation scenarios run.
    fn main_docs_only() -> Self {
        Self {
            docs: "true",
            bdd: "success",
            ..Self::main_out_of_scope()
        }
    }

    /// The same code change at the head of a merge group: Lint core and the
    /// archive build only.
    fn queue_in_scope() -> Self {
        let queue = Self {
            event_name: "merge_group",
            policy: "skipped",
            ..Self::pr_in_scope()
        };
        PR_ONLY_LANES
            .into_iter()
            .fold(queue, |verdict, lane| verdict.with(lane, "skipped"))
    }

    fn with(mut self, lane: &'static str, result: &'static str) -> Self {
        self.overrides.push((lane, result));
        self
    }

    /// `true` when the aggregate admits this combination.
    fn accepts(&self) -> bool {
        let mut command = Command::new("bash");
        command
            .arg("-c")
            .arg(aggregate_script())
            .env("EVENT_NAME", self.event_name)
            .env("SCOPE_RESULT", self.scope_result)
            .env("SCOPE_CODE", self.code)
            .env("SCOPE_DOCS", self.docs)
            .env("SCOPE_NIX", self.nix_scope)
            .env("RUNNERS_RESULT", self.runners_result)
            .env("WORKSPACE_RUNNER", self.workspace_runner)
            .env("POLICY_RESULT", self.policy)
            .env("WORKSPACE_BUILD_RESULT", self.archive)
            .env("BDD_RESULT", self.bdd)
            .env("NIX_RESULT", self.nix);
        for lane in GATE_LANES {
            command.env(lane, self.gate);
        }
        for lane in FULL_LANES {
            command.env(lane, self.full);
        }
        for (lane, result) in &self.overrides {
            command.env(lane, result);
        }
        let mut child = command
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
        Verdict::pr_out_of_scope().accepts(),
        "a PR touching no code and no bdd path must pass the aggregate"
    );
    assert!(Verdict::main_out_of_scope().accepts());
}

#[test]
fn a_fully_in_scope_green_run_is_admitted_on_every_event() {
    assert!(Verdict::pr_in_scope().accepts());
    assert!(Verdict::main_in_scope().accepts());
    assert!(
        Verdict {
            event_name: "workflow_dispatch",
            ..Verdict::main_in_scope()
        }
        .accepts(),
        "a manual dispatch runs the full matrix, like a push to main"
    );
    assert!(
        Verdict {
            nix_scope: "false",
            nix: "skipped",
            ..Verdict::main_in_scope()
        }
        .accepts()
    );
}

/// The pull-request and merge-queue tiers are the fast gate and nothing else.
/// An expensive lane that runs there is a lane whose `if:` lost its event
/// condition, and it puts the hour-long matrix back in front of every merge.
#[test]
fn every_full_matrix_lane_is_refused_on_a_pull_request_and_in_the_queue() {
    assert!(Verdict::queue_in_scope().accepts());
    for lane in FULL_LANES {
        assert!(
            !Verdict::pr_in_scope().with(lane, "success").accepts(),
            "{lane} must not run on a pull request"
        );
        assert!(
            !Verdict::queue_in_scope().with(lane, "success").accepts(),
            "{lane} must not run in the merge queue"
        );
    }
    for (what, verdict) in [
        (
            "BDD",
            Verdict {
                bdd: "success",
                ..Verdict::pr_in_scope()
            },
        ),
        (
            "Nix",
            Verdict {
                nix: "success",
                ..Verdict::pr_in_scope()
            },
        ),
    ] {
        assert!(!verdict.accepts(), "{what} must not run on a pull request");
    }
}

/// The queue re-runs only what a conflict with main can break. A pull-request
/// lane that runs there puts the slow tests back in front of every merge, and
/// the compile and core lint must still run.
#[test]
fn the_queue_runs_only_lint_core_and_the_archive_build() {
    assert!(Verdict::queue_in_scope().accepts());
    for lane in PR_ONLY_LANES {
        assert!(
            !Verdict::queue_in_scope().with(lane, "success").accepts(),
            "{lane} must not run in the merge queue"
        );
    }
    assert!(
        !Verdict::queue_in_scope()
            .with("POLICY_RESULT", "success")
            .accepts()
            && !Verdict {
                policy: "success",
                ..Verdict::queue_in_scope()
            }
            .accepts(),
        "the policy lane must not run in the merge queue"
    );
    assert!(
        !Verdict::queue_in_scope()
            .with("CORE_RESULT", "skipped")
            .accepts()
    );
    assert!(
        !Verdict {
            archive: "skipped",
            ..Verdict::queue_in_scope()
        }
        .accepts(),
        "the queue must compile every test target"
    );
}

/// A push to main is the full matrix. Any lane that skipped there left a
/// merged change untested.
#[test]
fn every_lane_must_run_on_a_push_to_main() {
    for lane in GATE_LANES.into_iter().chain(FULL_LANES) {
        assert!(
            !Verdict::main_in_scope().with(lane, "skipped").accepts(),
            "{lane} must run on a push to main"
        );
    }
    for (what, verdict) in [
        (
            "the workspace archive build",
            Verdict {
                archive: "skipped",
                ..Verdict::main_in_scope()
            },
        ),
        (
            "BDD",
            Verdict {
                bdd: "skipped",
                ..Verdict::main_in_scope()
            },
        ),
        (
            "Nix",
            Verdict {
                nix: "skipped",
                ..Verdict::main_in_scope()
            },
        ),
        (
            "the policy lane",
            Verdict {
                policy: "skipped",
                ..Verdict::main_in_scope()
            },
        ),
    ] {
        assert!(!verdict.accepts(), "{what} must run on a push to main");
    }
}

/// The fast gate is what keeps deterministic failures out of a batched group:
/// formatting and clippy, the feature-combination clippy, the policy gates,
/// the workspace test compile and the unit suite. Each must run on a PR.
#[test]
fn every_fast_gate_lane_must_run_on_a_pull_request() {
    for lane in GATE_LANES {
        assert!(
            !Verdict::pr_in_scope().with(lane, "skipped").accepts(),
            "{lane} must run on a pull request"
        );
        assert!(
            !Verdict::pr_in_scope().with(lane, "failure").accepts(),
            "a failing {lane} must refuse the pull request"
        );
    }
    assert!(
        !Verdict {
            archive: "skipped",
            ..Verdict::pr_in_scope()
        }
        .accepts(),
        "the hosted suite must compile its archive on a pull request"
    );
    assert!(
        !Verdict {
            policy: "skipped",
            ..Verdict::pr_out_of_scope()
        }
        .accepts(),
        "the policy lane runs on every pull request, in scope or not"
    );
}

/// The self-hosted path builds and runs the suite in one shard, so the hosted
/// archive build skips. That is the only lane the picker may move, and only
/// to one of the two runners it can answer.
#[test]
fn the_runner_picker_moves_only_the_archive_build() {
    for base in [Verdict::pr_in_scope(), Verdict::main_in_scope()] {
        assert!(
            Verdict {
                workspace_runner: "hetzner",
                archive: "skipped",
                ..base.clone()
            }
            .accepts(),
            "a self-hosted suite needs no archive"
        );
        assert!(
            !Verdict {
                workspace_runner: "hetzner",
                ..base.clone()
            }
            .accepts(),
            "an archive built for a self-hosted suite is a lane that ignored the picker"
        );
        assert!(
            !Verdict {
                workspace_runner: "hetzner",
                archive: "skipped",
                gate: "skipped",
                ..base.clone()
            }
            .accepts(),
            "the self-hosted suite itself must still run"
        );
        for runner in ["", "self-hosted", "m1"] {
            assert!(
                !Verdict {
                    workspace_runner: runner,
                    ..base.clone()
                }
                .accepts(),
                "workspace runner {runner:?} is not one the picker answers"
            );
        }
        assert!(
            !Verdict {
                runners_result: "failure",
                ..base.clone()
            }
            .accepts(),
            "the picker never fails, so a failure is refused rather than read"
        );
    }
    assert!(
        Verdict {
            workspace_runner: "hetzner",
            ..Verdict::pr_out_of_scope()
        }
        .accepts(),
        "an out-of-scope run skips the suite wherever it would have run"
    );
}

/// A documentation-only change pays for the suite that reads the
/// documentation, and only for that, on a push to main.
#[test]
fn a_docs_only_run_requires_the_bdd_lane_on_main_and_nothing_else() {
    assert!(Verdict::pr_docs_only().accepts());
    assert!(Verdict::main_docs_only().accepts());
    // Code and docs together is just a code run; `docs` adds nothing to it.
    for base in [Verdict::pr_in_scope(), Verdict::main_in_scope()] {
        assert!(
            Verdict {
                docs: "true",
                ..base
            }
            .accepts()
        );
    }
}

/// The failure the docs scope exists for, plus the ways it could be widened
/// into a rubber stamp.
#[test]
fn a_docs_only_run_is_refused_when_its_lane_does_not_match() {
    let cases: [(&str, Verdict); 4] = [
        (
            "a docs-only merge group whose BDD lane skipped",
            Verdict {
                bdd: "skipped",
                ..Verdict::main_docs_only()
            },
        ),
        (
            "a docs-only pull request that ran the BDD lane",
            Verdict {
                bdd: "success",
                ..Verdict::pr_docs_only()
            },
        ),
        (
            "a docs-only merge group whose BDD lane failed",
            Verdict {
                bdd: "failure",
                ..Verdict::main_docs_only()
            },
        ),
        (
            "a docs-only merge group that ran the compile and test lanes",
            Verdict {
                full: "success",
                ..Verdict::main_docs_only()
            },
        ),
    ];
    for (what, verdict) in cases {
        assert!(!verdict.accepts(), "the aggregate must refuse {what}");
    }
}

/// The gate must not have been widened into a rubber stamp. Each of these is a
/// real failure that has to keep being caught, in whichever tier it can occur.
#[test]
fn a_genuine_failure_is_still_refused_in_either_tier() {
    let cases: [(&str, Verdict); 12] = [
        (
            "a bdd lane that ran while out of scope",
            Verdict {
                bdd: "success",
                ..Verdict::main_out_of_scope()
            },
        ),
        (
            "a failing fast-gate lane on a pull request",
            Verdict {
                gate: "failure",
                ..Verdict::pr_in_scope()
            },
        ),
        (
            "a failing fast-gate lane on a push to main",
            Verdict {
                gate: "failure",
                ..Verdict::main_in_scope()
            },
        ),
        (
            "a failing full-matrix lane on a push to main",
            Verdict {
                full: "failure",
                ..Verdict::main_in_scope()
            },
        ),
        (
            "a full-matrix lane that ran while out of scope",
            Verdict {
                full: "success",
                ..Verdict::main_out_of_scope()
            },
        ),
        (
            "a bdd lane that skipped while in scope",
            Verdict {
                bdd: "skipped",
                ..Verdict::main_in_scope()
            },
        ),
        (
            "the scope job itself failing",
            Verdict {
                scope_result: "failure",
                ..Verdict::pr_in_scope()
            },
        ),
        (
            "a failing policy lane",
            Verdict {
                policy: "failure",
                ..Verdict::pr_in_scope()
            },
        ),
        (
            "a Nix job that ran for an unrelated diff",
            Verdict {
                nix_scope: "false",
                ..Verdict::main_in_scope()
            },
        ),
        (
            "an invalid Nix scope",
            Verdict {
                nix_scope: "",
                ..Verdict::main_in_scope()
            },
        ),
        (
            "a failing Nix witness",
            Verdict {
                nix: "failure",
                ..Verdict::main_in_scope()
            },
        ),
        (
            "an event the workflow does not declare",
            Verdict {
                event_name: "schedule",
                ..Verdict::main_in_scope()
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
        "the Test aggregate must not depend on the no-KVM smoke"
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
            ..Verdict::pr_in_scope()
        }
        .accepts(),
        "an empty code scope must not be treated as a valid classification"
    );
    for docs in ["", "yes"] {
        assert!(
            !Verdict {
                docs,
                ..Verdict::main_docs_only()
            }
            .accepts(),
            "docs scope {docs:?} must not be treated as a valid classification"
        );
    }
}

/// Lift the `grep -zE` pattern that decides `{output}=true` out of the scope
/// job.
fn classifier_pattern(output: &str) -> String {
    let workflow = std::fs::read_to_string(".github/workflows/ci.yml")
        .expect("failed to read .github/workflows/ci.yml");
    let lines: Vec<&str> = workflow.lines().collect();
    let marker = format!(r#"echo "{output}=true""#);
    let emit = lines
        .iter()
        .position(|line| line.contains(&marker))
        .unwrap_or_else(|| panic!("the scope job must emit {output}=true"));
    let grep = lines[..emit]
        .iter()
        .rev()
        .find(|line| line.contains("grep -zE"))
        .unwrap_or_else(|| panic!("{output}=true must follow its grep"));
    grep.split_once("grep -zE '")
        .and_then(|(_, rest)| rest.split_once('\''))
        .map(|(pattern, _)| pattern.to_string())
        .unwrap_or_else(|| panic!("the {output} grep must carry a single-quoted pattern: {grep}"))
}

/// `true` when the docs classifier marks a diff naming `paths` as docs.
fn classified_as_docs(paths: &[&str]) -> bool {
    classified_as(&classifier_pattern("docs"), paths)
}

/// `true` when the code classifier puts a diff naming `paths` in the Rust
/// lanes' scope.
fn classified_as_code(paths: &[&str]) -> bool {
    classified_as(&classifier_pattern("code"), paths)
}

/// `true` when `pattern` matches the NUL-separated list naming `paths`.
fn classified_as(pattern: &str, paths: &[&str]) -> bool {
    let mut input = Vec::new();
    for path in paths {
        input.extend_from_slice(path.as_bytes());
        input.push(0);
    }
    let mut child = Command::new("grep")
        .arg("-zE")
        .arg(pattern)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to spawn grep");
    {
        use std::io::Write as _;
        child
            .stdin
            .take()
            .expect("grep stdin")
            .write_all(&input)
            .expect("write the changed-file list");
    }
    child.wait().expect("grep did not exit").success()
}

/// Runs the classifier's real pattern against the NUL-separated list
/// `git diff --name-only -z` produces, so an anchoring or escaping mistake in
/// the YAML shows up here rather than as a lane that never runs.
#[test]
fn the_docs_classifier_matches_the_corpus_and_nothing_near_it() {
    for path in [
        "README.md",
        "AGENTS.md",
        "public/src/content/docs/guides/troubleshooting.md",
        "crates/mvm-sdk/sdks/python/README.md",
        "examples/python/hello-app-with-deps/README.md",
    ] {
        assert!(classified_as_docs(&[path]), "{path} must set docs=true");
    }
    for path in [
        "READMEXmd",
        "README.md.orig",
        "crates/mvm-cli/README.md",
        "public/src/pages/index.astro",
        "specs/plans/example.md",
        "features/suites/s29_doc_examples/docs_coverage.toml",
    ] {
        assert!(
            !classified_as_docs(&[path]),
            "{path} must not set docs=true"
        );
    }
    assert!(
        classified_as_docs(&[
            "specs/plans/example.md",
            "public/src/content/docs/index.mdx"
        ]),
        "one documentation path anywhere in the diff must set docs=true"
    );
}

/// The code scope is what turns every Rust lane on, so a miss here is a
/// change merging without the suite that reads it. Prose a Rust test parses
/// belongs in it; prose nothing compiled reads does not, or a docs edit pays
/// for the whole matrix.
#[test]
fn the_code_classifier_covers_what_rust_reads_and_skips_plain_prose() {
    for path in [
        "Cargo.lock",
        "crates/mvm-core/src/lib.rs",
        "xtask/src/main.rs",
        "tests/cli.rs",
        "nix/lib/mk-guest.nix",
        "model/claims.toml",
        "scripts/ci-linux-coverage.sh",
        ".github/workflows/ci.yml",
        ".github/actions/rust-cache/action.yml",
        "specs/adrs/001-microvm-security-posture.md",
        "CLAUDE.md",
        "CLAUDE.md.sigstore.json",
        "AGENTS.md",
        "README.md",
        "flake.nix",
        "flake.lock",
        "deny.toml",
        "examples/python/hello-app-with-deps/README.md",
        "public/src/content/docs/reference/performance.md",
        "public/src/content/docs/security/cve-demonstrations.md",
        "public/src/content/docs/contributing/development.md",
        "public/src/content/docs/contributing/ai-coding-workflow.md",
    ] {
        assert!(classified_as_code(&[path]), "{path} must set code=true");
    }
    for path in [
        "public/src/content/docs/guides/troubleshooting.md",
        "public/src/pages/index.astro",
        "specs/plans/2026-08-15-example.md",
        "specs/README.md",
        "CHANGELOG.md",
        "docs/README.md",
        "crates.md",
        "README.md.orig",
    ] {
        assert!(
            !classified_as_code(&[path]),
            "{path} must not set code=true"
        );
    }
}
