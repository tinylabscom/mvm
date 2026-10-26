//! Regression checks for the scheduled documented-surface witnesses.

use std::fs;
#[cfg(unix)]
use std::process::Command;
#[cfg(unix)]
use std::time::{Duration, Instant};

/// The reusable workflow that defines the documented-surface jobs.
fn extended_ci() -> String {
    fs::read_to_string(".github/workflows/e2e-docs.yml").expect("read documented-surface workflow")
}

/// So must the release workflow. This is the gate that did not exist: a tag
/// could be cut with only the hermetic BDD lane green, and the hermetic lane
/// boots no guest.
#[test]
fn the_release_workflow_waits_for_the_documented_surface() {
    let workflow =
        fs::read_to_string(".github/workflows/release.yml").expect("read release workflow");
    assert!(
        workflow.contains("uses: ./.github/workflows/e2e-docs.yml"),
        "release.yml must call the shared documented-surface workflow"
    );
    assert!(
        release_gate_problem(&workflow).is_none(),
        "release publication gate is incomplete: {:?}",
        release_gate_problem(&workflow)
    );
    // The documented surface gates promotion, not the signed prerelease.
    let promote = job_block(&workflow, "promote-release");
    assert!(
        promote.contains("needs: [e2e-docs,")
            && promote.contains("needs.e2e-docs.result == 'success'"),
        "promote-release must wait for the documented surface"
    );
    assert!(
        !job_block(&workflow, "release").contains("e2e-docs"),
        "the signed prerelease must not wait for the documented surface"
    );
}

const RELEASE_GATES: &[&str] = &[
    "build",
    "archive-install-smoke",
    "guest-runtime",
    "runtime-proof-candidate",
    "release-archive-smoke",
    "distro-packages",
];

/// Check the publication job, not an earlier job's `!cancelled()` condition.
/// Listing a dependency alone does not enforce success under `!cancelled()`.
/// Require every declared dependency, including future additions, conjunctively.
fn release_gate_problem(workflow: &str) -> Option<String> {
    let release = job_block(workflow, "release");
    let Some(needs) = release
        .lines()
        .find_map(|line| line.strip_prefix("    needs: [")?.strip_suffix(']'))
    else {
        return Some("publication needs must be an explicit inline list".into());
    };
    let needs: Vec<_> = needs.split(',').map(str::trim).collect();
    for required in RELEASE_GATES {
        if !needs.contains(required) {
            return Some(format!("missing publication dependency {required}"));
        }
    }
    let Some(condition) = release
        .lines()
        .find_map(|line| line.strip_prefix("    if: "))
    else {
        return Some("missing publication job condition".into());
    };
    for required in [
        "!cancelled()",
        "github.event_name == 'push'",
        "github.ref_type == 'tag'",
    ] {
        if !condition.contains(required) {
            return Some(format!("missing publication condition {required}"));
        }
    }
    if condition.contains("||") {
        return Some("publication success gates must not have an OR bypass".into());
    }
    for need in needs {
        if need.is_empty() || !condition.contains(&format!("needs.{need}.result == 'success'")) {
            return Some(format!("publication does not require {need} success"));
        }
    }
    None
}

#[test]
fn publication_gate_checks_ignore_other_jobs_and_reject_missing_success() {
    let workflow = fs::read_to_string(".github/workflows/release.yml").unwrap();
    let release = job_block(&workflow, "release");
    let condition = release
        .lines()
        .find(|line| line.starts_with("    if: "))
        .unwrap();
    // Both decoys contain the complete successful condition. Neither may
    // conceal a missing dependency/failed result in the actual release job.
    let surround = |job: &str| {
        format!(
            "jobs:\n  earlier:\n{condition}\n    runs-on: ubuntu-latest\n{job}\n  later:\n{condition}\n    runs-on: ubuntu-latest\n"
        )
    };
    assert_eq!(release_gate_problem(&surround(release)), None);
    for need in RELEASE_GATES {
        let failure = release.replace(
            &format!("needs.{need}.result == 'success'"),
            &format!("needs.{need}.result == 'failure'"),
        );
        assert!(
            release_gate_problem(&surround(&failure)).is_some(),
            "{need}"
        );
        let missing = release.replace(&format!("needs.{need}.result == 'success'"), "true");
        assert!(
            release_gate_problem(&surround(&missing)).is_some(),
            "{need}"
        );
        let missing = release.replace(&format!("{need}, "), "");
        let missing = if missing == release {
            release.replace(&format!(", {need}"), "")
        } else {
            missing
        };
        assert_ne!(missing, release, "fixture must remove dependency {need}");
        assert!(
            release_gate_problem(&surround(&missing)).is_some(),
            "{need}"
        );
    }
    let future = release.replace("needs: [", "needs: [future-positive, ");
    assert!(release_gate_problem(&surround(&future)).is_some());
    let bypass = release.replace("!cancelled()", "!cancelled() || true");
    assert!(release_gate_problem(&surround(&bypass)).is_some());
}

/// The release gate must be stated at the release call site, not inherited.
///
/// No GitHub-hosted macOS runner can boot an mvm guest (issue #3011), so on
/// every hosted host the macOS lane is skipped and the release caller falls
/// back to a committed evidence record instead. The danger in having an opt-out is
/// that the release caller quietly acquires it. Then a tag cuts with no macOS evidence of any kind and
/// nothing says so, which is the same silent-gate failure that let `machine run
/// -it` ship broken on every OCI image.
#[test]
fn releases_still_block_on_a_macos_host_that_cannot_boot_a_guest() {
    let workflow =
        fs::read_to_string(".github/workflows/release.yml").expect("read release workflow");
    assert!(
        workflow.contains("macos_blocks_on_unusable_host: true"),
        "release.yml must block on an unusable macOS host, or a tag is cut with \
         no evidence the documented examples boot on macOS"
    );
}

/// The two callers must disagree, and the default must be the safe one.
///
/// A `workflow_call` input that defaults to false would make every future
/// caller non-blocking by omission — the failure mode this split exists to
/// prevent, reintroduced one level up.
#[test]
fn the_macos_host_gate_defaults_to_blocking() {
    let workflow = extended_ci();
    let inputs = workflow
        .split("jobs:")
        .next()
        .expect("the workflow must declare its triggers before its jobs");
    assert!(
        inputs.contains("macos_blocks_on_unusable_host:"),
        "the shared workflow must declare the macOS host gate as an input"
    );
    assert!(
        inputs.contains("default: true"),
        "the macOS host gate must default to blocking, so a caller that says \
         nothing gets the release-safe behaviour"
    );
}

/// The lane is skipped by the host check, never by a hardcoded runner label.
///
/// Pointing `runs-on` at a self-hosted Apple Silicon runner has to be the whole
/// of resolving #3011. If the skip were keyed to the label rather than to a
/// live `uname`, the lane would keep skipping on hardware that can run it, and
/// the gap would close without anyone noticing the evidence never came back.
#[test]
fn the_macos_lane_runs_whenever_the_host_probe_says_the_host_can_boot() {
    let workflow = extended_ci();
    let check = job_block(&workflow, "e2e-docs-macos-host-check");
    assert!(
        check.contains("uname -m"),
        "the host check must probe the live host, not the runner label"
    );
    assert!(
        check.contains("supported=true"),
        "the host check must report a usable host to its dependents"
    );

    let macos = job_block(&workflow, "e2e-docs-macos");
    assert!(
        macos.contains("needs: e2e-docs-macos-host-check"),
        "the macOS lane must wait on the host check"
    );
    assert!(
        macos.contains("if: needs.e2e-docs-macos-host-check.outputs.supported == 'true'"),
        "the macOS lane must run exactly when the host probe says the host can \
         boot a guest"
    );
}

/// When no runner can produce macOS evidence live, a release must still get it
/// from somewhere.
///
/// The host check used to fail the workflow outright for the release caller.
/// That was honest but terminal: it made a release impossible rather than
/// evidence-backed, and the obvious way out — flipping the input to false —
/// buys a green release by deleting the requirement. The evidence job is the
/// third option: a recorded local run, machine-checked against the tree being
/// tagged. Without this test the job can be deleted and the release goes quiet
/// again, which is the exact failure this file exists to prevent.
#[test]
fn an_unusable_macos_host_falls_back_to_a_checked_evidence_record() {
    let workflow = extended_ci();
    let evidence = job_block(&workflow, "e2e-docs-macos-evidence");

    assert!(
        evidence.contains("needs: e2e-docs-macos-host-check"),
        "the evidence job must wait on the host check, or it cannot know whether \
         a live run was possible"
    );
    assert!(
        evidence.contains("inputs.macos_blocks_on_unusable_host"),
        "the evidence job must be gated on the same input the release caller \
         sets, so callers cannot silently disagree about required macOS evidence"
    );
    assert!(
        evidence.contains("needs.e2e-docs-macos-host-check.outputs.supported != 'true'"),
        "the evidence job must run exactly when the live lane could not, so it \
         retires itself the day a self-hosted Apple Silicon runner lands"
    );
    assert!(
        evidence.contains("check-release-evidence macos-hvf"),
        "the evidence job must actually run the gate that verifies the record \
         covers this tree — a job that only asserts the file exists proves that \
         someone committed a file"
    );
    assert!(
        evidence.contains("fetch-depth: 0"),
        "the gate diffs the recorded commit against HEAD to name what changed; \
         a shallow clone reduces that to 'could not diff the two trees'"
    );
}

/// Each live job's budget must exceed the suite's own deadline.
///
/// These are one budget and they drifted apart twice. At `timeout-minutes: 60`
/// against a 3600s suite the Linux job had zero seconds for setup and died at
/// exactly 60m00s three runs running; at 120 against the same 3600s it had 60
/// minutes of setup and 60 of suite, spent them, and was killed mid-scenario. A
/// killed suite prints no summary, so both readings were "this run proves
/// nothing". The macOS job inherited the 3600s default under a 90-minute
/// budget — the same shape, waiting for its first cold run.
#[test]
fn each_live_job_budget_exceeds_the_suite_deadline() {
    let workflow = extended_ci();

    for job in ["e2e-docs-linux", "e2e-docs-macos"] {
        let block = job_block(&workflow, job);
        let job_minutes: u32 = field_after(block, "timeout-minutes:")
            .unwrap_or_else(|| panic!("{job} must declare a job timeout"))
            .parse()
            .expect("timeout-minutes must be a number");
        let suite_seconds: u32 = field_after(block, "MVM_E2E_TIMEOUT_SECS:")
            .unwrap_or_else(|| {
                panic!("{job} must pin the suite deadline rather than inherit the default")
            })
            .trim_matches('"')
            .parse()
            .expect("MVM_E2E_TIMEOUT_SECS must be a number");

        assert!(
            job_minutes * 60 > suite_seconds,
            "{job}: the job budget ({job_minutes}m) must exceed the suite deadline \
             ({suite_seconds}s) by the whole of setup, or the job is cancelled \
             before the suite can report — and a cancellation names no scenario"
        );
        assert!(
            job_minutes * 60 - suite_seconds >= 3600,
            "{job}: setup measured 54 minutes on 2026-09-02; leave at least an hour \
             of the job budget for it, or the next slow checkout repeats the failure"
        );
        if job == "e2e-docs-linux" {
            assert!(
                suite_seconds >= 10_800,
                "{job}: retain a bounded per-shard deadline with headroom for cold live boots"
            );
        }
    }
}

#[test]
fn linux_documented_surface_requires_both_complete_inventory_shards() {
    let workflow = extended_ci();
    let linux = job_block(&workflow, "e2e-docs-linux");
    let script = documented_surface_script();

    assert!(
        linux.contains("shard: [\"0/2\", \"1/2\"]")
            && linux.contains("MVM_BDD_SHARD: ${{ matrix.shard }}")
            && linux.contains("fail-fast: true"),
        "both disjoint shards remain required, and a failed shard cancels its sibling"
    );
    assert!(
        !script.contains("export MVM_BDD_ONLY_TAG="),
        "the release gate must partition the full inventory, not narrow to a tag"
    );
    assert!(
        script.contains("all shards must pass"),
        "a single green shard must not be presented as full coverage"
    );
}

#[test]
fn macos_documented_surface_uses_isolated_sequential_shards() {
    let workflow = extended_ci();
    let macos = job_block(&workflow, "e2e-docs-macos");

    assert!(
        macos.contains("max-parallel: 1")
            && macos.contains("shard: [\"0/2\", \"1/2\"]")
            && macos.contains("MVM_BDD_SHARD: ${{ matrix.shard }}"),
        "the macOS suite must run both disjoint shards sequentially"
    );
    assert!(
        macos.contains("MVM_E2E_HOME: ${{ github.workspace }}/.mvm-e2e-${{ github.run_id }}-${{ github.run_attempt }}-${{ strategy.job-index }}"),
        "each run attempt and shard must use an isolated E2E home"
    );
    assert!(
        macos.contains("name: e2e-docs-macos-logs-${{ github.run_id }}-${{ github.run_attempt }}-${{ strategy.job-index }}"),
        "each run attempt and shard must upload to a unique artifact name"
    );
    assert!(
        macos.contains(".mvm-e2e-${{ github.run_id }}-${{ github.run_attempt }}-${{ strategy.job-index }}/vms/*/console.log"),
        "uploaded VM logs must come from this shard's isolated home"
    );
    let diagnostics = macos
        .split_once("- name: Dump VMM diagnostics on failure")
        .expect("macOS failure diagnostics step")
        .1;
    assert!(
        diagnostics.contains("for d in \"$MVM_E2E_HOME\"/vms/*/; do")
            && !diagnostics.contains("$HOME"),
        "failure diagnostics must inspect only this shard's isolated home"
    );
    assert!(
        !macos.contains("MVM_BDD_WARM_CLAIM"),
        "macOS must not claim warm-claim coverage without capability opt-in"
    );
}

#[test]
fn documented_launches_are_cold_and_warm_scenarios_override_explicitly() {
    let workflow = extended_ci();
    let linux = job_block(&workflow, "e2e-docs-linux");
    let macos = job_block(&workflow, "e2e-docs-macos");
    let budgets = fs::read_to_string("features/suites/s31_launch_e2e/launch_budget.feature")
        .expect("read launch budget scenarios");
    let launch_modes =
        fs::read_to_string("features/suites/s31_launch_e2e/cli_launch_modes.feature")
            .expect("read launch mode scenarios");
    let launcher = fs::read_to_string("crates/mvm-conformance/tests/steps/launch_e2e.rs")
        .expect("read documented launch steps");

    assert!(
        !linux.contains("MVM_BDD_WARM_CLAIM") && !macos.contains("MVM_BDD_WARM_CLAIM"),
        "release-docs lanes must not advertise the privileged warm-claim capability"
    );
    assert!(
        launcher.contains("const DOCUMENTED_RESIDENCY: &str = \"cold\";")
            && !launcher.contains("default_documented_residency"),
        "a capability opt-in must not make unrelated documented launches warm"
    );
    assert!(
        budgets.contains("Scenario: a cold transient launch reports its dispatch window")
            && budgets.contains("@live @perf_budget @warm_claim\n  Scenario: a warm-residency")
            && budgets
                .contains("@live @perf_budget @warm_claim\n  Scenario: repeated warm launches")
            && budgets.contains("@live @perf_budget @warm_claim\n  Scenario: a second run"),
        "keep cold-launch coverage and gate only the warm-claim benchmarks"
    );
    assert!(
        !launch_modes.contains("And an Alpine warm parent is ready"),
        "ordinary launch scenarios must not prepare an unconditional warm parent"
    );
    let second_run = budgets
        .split("Scenario: a second run of an image claims the standby the first run left")
        .nth(1)
        .expect("keep the automatic standby scenario");
    let launches: Vec<_> = second_run
        .lines()
        .filter(|line| line.trim_start().starts_with("When I launch"))
        .collect();
    assert_eq!(launches.len(), 2, "keep both automatic standby launches");
    assert!(
        launches
            .iter()
            .all(|line| line.ends_with("with env \"MVM_RESIDENCY\" set to \"warm\"")),
        "both automatic standby launches must explicitly request warm residency"
    );
}

#[test]
fn only_native_invocation_positives_require_firecracker() {
    fn tags_for<'a>(feature: &'a str, title: &str) -> std::collections::BTreeSet<&'a str> {
        let lines: Vec<_> = feature.lines().collect();
        let scenario = format!("Scenario: {title}");
        let index = lines
            .iter()
            .position(|line| line.trim() == scenario)
            .expect("keep the documented scenario");
        let mut tags = std::collections::BTreeSet::new();
        for line in lines[..index].iter().rev().map(|line| line.trim()) {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if !line.starts_with('@') {
                break;
            }
            tags.extend(line.split_whitespace());
        }
        tags
    }

    let feature =
        fs::read_to_string("features/suites/s29_doc_examples/documented_build_live.feature")
            .expect("read documented build scenarios");
    assert!(
        feature
            .lines()
            .take_while(|line| !line.trim_start().starts_with("Feature:"))
            .filter(|line| line.trim_start().starts_with('@'))
            .all(|line| !line.split_whitespace().any(|tag| tag == "@firecracker")),
        "do not restrict the whole feature to Firecracker"
    );
    assert_eq!(
        tags_for(&feature, "the documented flake build produces an image"),
        std::collections::BTreeSet::from(["@live", "@release_gate_flake"]),
        "ordinary image building must retain macOS positive coverage"
    );
    assert_eq!(
        tags_for(
            &feature,
            "the documented entrypoint launch runs the compiled workload"
        ),
        std::collections::BTreeSet::from(["@live", "@release_gate_flake", "@firecracker"]),
        "entrypoint invocation must retain its Firecracker positive"
    );
    assert_eq!(
        tags_for(
            &feature,
            "the documented pack build health-boots and signs a frozen workload"
        ),
        std::collections::BTreeSet::from([
            "@live",
            "@documented_pack_live",
            "@firecracker",
            "@runtime_candidate",
        ]),
        "pack health must retain its Firecracker positive"
    );
}

/// First `key value` occurrence in a job block, as a trimmed string.
fn field_after(block: &str, key: &str) -> Option<String> {
    block
        .lines()
        .find_map(|line| line.trim().strip_prefix(key))
        .map(|rest| rest.trim().to_string())
}

fn documented_surface_script() -> String {
    fs::read_to_string("scripts/e2e-documented-surface.sh").expect("read documented-surface runner")
}

/// The images the runner prepares in the shared home, as its array lists them.
fn documented_surface_live_images(script: &str) -> Vec<String> {
    let line = script
        .lines()
        .find_map(|line| line.strip_prefix("E2E_LIVE_IMAGES=("))
        .expect("the runner declares the images it prepares");
    line.trim_end_matches(')')
        .split_whitespace()
        .map(str::to_string)
        .collect()
}

/// Every image a live scenario prepares is prepared by the runner too, under
/// both guest-runtime sources the suite launches with, and a pull that fails
/// stops the run.
///
/// The pull used to be best-effort and ran under the published runtime only. A
/// rootfs is keyed by the runtime injected into it, so every live-home scenario
/// (which selects this checkout's runtime) found its image "not launch-ready",
/// and the journey's `nginx` was never pulled at all; both surfaced an hour
/// later as a dozen scenarios naming an image instead of the pull.
#[test]
fn the_documented_surface_runner_prepares_every_live_image_or_stops() {
    let script = documented_surface_script();
    let images = documented_surface_live_images(&script);

    let mut prepared_by_scenarios = std::collections::BTreeSet::new();
    let mut features = vec![std::path::PathBuf::from("features")];
    while let Some(path) = features.pop() {
        if path.is_dir() {
            for entry in fs::read_dir(&path).expect("read features dir") {
                features.push(entry.expect("feature entry").path());
            }
        } else if path.extension().is_some_and(|ext| ext == "feature") {
            let text = fs::read_to_string(&path).expect("read feature");
            for line in text.lines() {
                if let Some(rest) = line.split("the image \"").nth(1)
                    && let Some((image, tail)) = rest.split_once('"')
                    && tail.contains("is prepared in the live home")
                {
                    prepared_by_scenarios.insert(image.to_string());
                }
            }
        }
    }
    // The journey boots its guest from a step rather than a feature line.
    prepared_by_scenarios.insert("nginx".to_string());
    for image in &prepared_by_scenarios {
        assert!(
            images.contains(image),
            "a live scenario boots {image}, which the runner does not prepare: {images:?}"
        );
    }

    assert!(
        script.contains("E2E_RUNTIME_SOURCES=(download build)"),
        "the runner must prepare each image under both guest-runtime sources"
    );
    assert!(
        script.contains("MVM_RUNTIME_OVERLAY_ACQUIRE_MODE=\"$runtime_source\""),
        "each pull must select the runtime source it prepares for"
    );
    let pulls = script
        .split("e2e_phase images")
        .nth(1)
        .and_then(|rest| rest.split("e2e_phase launch-artifacts").next())
        .expect("the runner has an images phase");
    assert!(
        pulls.contains("exit 1") && !pulls.contains("|| echo"),
        "a failed pull must stop the run:\n{pulls}"
    );
}

/// The builder's store-image flock must lose to the suite deadline.
///
/// `DEFAULT_LOCK_WAIT` is an hour and the suite's deadline defaulted to the
/// same hour. A contended builder therefore consumed the entire run: the
/// waiter could not lose the race, so the suite was killed at the instant the
/// lock wait would have expired, and the contention error was never raised.
/// The scenario was reported as having hung, naming no cause — a live run
/// spent an hour proving nothing.
///
/// Asserting the derivation rather than a literal, because the failure was the
/// two values being *equal*: pinning a number here would go stale the moment
/// either default moved, which is exactly how the tie arose.
#[test]
fn the_builder_lock_wait_cannot_outlast_the_suite_deadline() {
    let script = documented_surface_script();

    assert!(
        script.contains("export MVM_BUILDER_LOCK_WAIT_SECS="),
        "the runner must bound the builder store lock wait, or a contended \
         builder consumes the whole suite budget and reports nothing"
    );
    assert!(
        script.contains("$(( E2E_TIMEOUT_SECS / 4 ))"),
        "the lock wait must be derived from the suite deadline, so raising \
         MVM_E2E_TIMEOUT_SECS cannot silently restore the tie that caused the hang"
    );

    let wait = script
        .find("export MVM_BUILDER_LOCK_WAIT_SECS=")
        .expect("checked above");
    let deadline = script
        .find("E2E_TIMEOUT_SECS=\"${MVM_E2E_TIMEOUT_SECS:-")
        .expect("the runner must define its own deadline");
    assert!(
        deadline < wait,
        "the deadline must be defined before the lock wait derives from it, \
         or the arithmetic reads an empty value and the wait becomes zero"
    );
}

#[test]
fn the_suite_timeout_owns_the_entire_conformance_process_tree() {
    let script = documented_surface_script();

    assert!(
        script.contains("scripts/run-bounded-command.py"),
        "the suite deadline must be enforced by the process-group runner; \
         killing `$!` from a background pipeline only kills tee and leaves \
         cargo, conformance, mvmctl, and the builder alive"
    );
    assert!(
        !script.contains("while kill -0 \"$SUITE_PID\""),
        "the polling timeout watches the pipeline's last PID rather than the \
         owned conformance process tree"
    );
}

#[cfg(unix)]
#[test]
fn the_bounded_runner_terminates_descendants_that_hold_file_locks() {
    let scratch = tempfile::tempdir().expect("create process-tree fixture");
    let lock_path = scratch.path().join("store.lock");
    let ready_path = scratch.path().join("holder.ready");
    let log_path = scratch.path().join("runner.log");
    let holder = concat!(
        "import fcntl, os, time; ",
        "f = open(os.environ[\"LOCK_PATH\"], \"w\"); ",
        "fcntl.flock(f, fcntl.LOCK_EX); ",
        "open(os.environ[\"READY_PATH\"], \"w\").close(); ",
        "time.sleep(30)"
    );
    let shell = format!("python3 -c '{holder}' & wait");

    // Allow cold interpreter startup before exercising descendant cleanup.
    // The child holds the lock for 30 seconds; the runner must release it early.
    for attempt in 1..=2 {
        let _ = fs::remove_file(&ready_path);
        let started = Instant::now();
        let status = Command::new("python3")
            .args([
                "scripts/run-bounded-command.py",
                "--timeout",
                "5",
                "--grace",
                "1",
                "--log",
            ])
            .arg(&log_path)
            .args(["--", "sh", "-c", &shell])
            .env("LOCK_PATH", &lock_path)
            .env("READY_PATH", &ready_path)
            .status()
            .expect("run bounded command helper");

        assert_eq!(status.code(), Some(124), "attempt {attempt} must time out");
        assert!(
            started.elapsed() < Duration::from_secs(15),
            "attempt {attempt} did not terminate its process tree promptly"
        );
        assert!(
            ready_path.is_file(),
            "attempt {attempt}'s descendant never acquired the lock"
        );

        let lock = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)
            .expect("open fixture lock after timeout");
        lock.try_lock().unwrap_or_else(|error| {
            panic!("attempt {attempt}'s descendant still holds the lock: {error}")
        });
    }
}

#[cfg(unix)]
#[test]
fn the_bounded_runner_streams_output_and_preserves_exit_status() {
    let scratch = tempfile::tempdir().expect("create successful command fixture");
    let log_path = scratch.path().join("runner.log");
    let started = Instant::now();
    let status = Command::new("python3")
        .args([
            "scripts/run-bounded-command.py",
            "--timeout",
            "5",
            "--grace",
            "1",
            "--log",
        ])
        .arg(&log_path)
        .args(["--", "sh", "-c", "sleep 30 & echo bounded-marker; exit 7"])
        .status()
        .expect("run bounded command success path");

    assert_eq!(status.code(), Some(7));
    assert!(
        started.elapsed() < Duration::from_secs(15),
        "an outliving descendant kept the output pipe open"
    );
    assert_eq!(
        fs::read_to_string(log_path).expect("read bounded command log"),
        "bounded-marker\n"
    );
}

/// Output must reach the console as it is written, not when a 64 KiB block
/// fills: the live suite prints a line per step, and a lane that times out has
/// to show where it was.
#[cfg(unix)]
#[test]
fn the_bounded_runner_forwards_a_line_while_the_command_still_runs() {
    use std::io::{BufRead as _, BufReader};
    use std::process::Stdio;
    use std::sync::mpsc;

    let scratch = tempfile::tempdir().expect("create streaming fixture");
    let log_path = scratch.path().join("runner.log");
    let mut runner = Command::new("python3")
        .args([
            "scripts/run-bounded-command.py",
            "--timeout",
            "20",
            "--grace",
            "1",
            "--log",
        ])
        .arg(&log_path)
        .args(["--", "sh", "-c", "echo early-marker; sleep 15"])
        .stdout(Stdio::piped())
        .spawn()
        .expect("start bounded runner");
    let stdout = runner.stdout.take().expect("runner stdout");
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut line = String::new();
        let _ = BufReader::new(stdout).read_line(&mut line);
        let _ = tx.send(line);
    });

    let first = rx.recv_timeout(Duration::from_secs(10));
    let _ = runner.kill();
    let _ = runner.wait();
    assert_eq!(
        first.expect("the first line must arrive while the command is still running"),
        "early-marker\n"
    );
}

#[cfg(unix)]
#[test]
fn bounded_cleanup_only_ignores_permission_denial_after_the_child_exits() {
    let status = Command::new("python3")
        .args([
            "-B",
            "-c",
            r#"
import importlib.util
from unittest.mock import Mock, patch
spec = importlib.util.spec_from_file_location("bounded", "scripts/run-bounded-command.py")
bounded = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bounded)
for returncode in [0, 7, None]:
    process = Mock(pid=12345)
    process.poll.return_value = returncode
    with patch.object(bounded.os, "killpg", side_effect=PermissionError()):
        try:
            bounded.terminate_group(process, 0)
        except PermissionError:
            assert returncode is None, "a reaped child must retain its original outcome"
        else:
            assert returncode is not None, "permission errors for a live child must propagate"
            process.wait.assert_called_once()
"#,
        ])
        .status()
        .expect("exercise deterministic process-group cleanup races");
    assert!(status.success());
}

fn root_manifest() -> String {
    fs::read_to_string("Cargo.toml").expect("read root Cargo manifest")
}

fn job_block<'a>(workflow: &'a str, job: &str) -> &'a str {
    let marker = format!("  {job}:\n");
    let start = workflow
        .find(&marker)
        .unwrap_or_else(|| panic!("the documented-surface workflow must define {job}"));
    let rest_start = start + marker.len();
    let rest = &workflow[rest_start..];
    let end = rest
        .match_indices("\n  ")
        .find_map(|(offset, _)| {
            let line = rest[offset + 1..].lines().next()?;
            (!line.starts_with("    ") && line.ends_with(':')).then_some(rest_start + offset)
        })
        .unwrap_or(workflow.len());
    &workflow[start..end]
}

#[test]
fn documented_surface_jobs_build_a_signature_verifying_mvmctl() {
    let workflow = extended_ci();

    for job in ["e2e-docs-linux", "e2e-docs-macos"] {
        let block = job_block(&workflow, job);
        assert!(
            block.contains("MVM_E2E_FEATURES: user,release-artifact-bootstrap"),
            "{job} must verify signed release manifests and compile the explicit published-image path"
        );
        assert!(
            !block.contains("MVM_SKIP_COSIGN_VERIFY"),
            "{job} must not bypass signed-manifest verification"
        );
    }
}

#[test]
fn macos_documented_surface_uses_the_published_workload_kernel() {
    let workflow = extended_ci();
    let macos = job_block(&workflow, "e2e-docs-macos");

    assert!(
        macos.contains("MVM_KERNEL_SOURCE: download"),
        "the macOS witness must not source-build its workload kernel through the builder image it is bootstrapping"
    );
    assert!(
        macos.contains("MVM_BOOT_IMAGE: fetch"),
        "the macOS source checkout must explicitly fetch its published builder image instead of entering unsupported HVF Stage 0 preparation"
    );
}

#[test]
fn local_launch_gate_uses_the_published_workload_kernel() {
    let script = fs::read_to_string("scripts/e2e-launch-modes.sh")
        .expect("read the local launch-gate script");

    assert!(
        script.contains("cargo build --bin mvmctl --features user,embed-host-bins"),
        "`just e2e::launch` must build the manifest verifier through the standard linker before it downloads a published workload kernel"
    );
    assert!(
        script.contains("export MVM_KERNEL_SOURCE=download"),
        "`just e2e::launch` must not route a cold source checkout through the optional libkrun Stage 0 backend"
    );
}

#[test]
fn local_launch_gate_runs_only_launch_features() {
    let script = fs::read_to_string("scripts/e2e-launch-modes.sh")
        .expect("read the local launch-gate script");

    assert!(
        script.contains(
            "s31_launch_e2e/{cli_launch_modes,launch_budget,sdk_and_library_modes}.feature"
        ),
        "`just e2e::launch` must name its three launch feature files explicitly"
    );
    assert!(
        !script.contains("s31_launch_e2e/*.feature"),
        "the broad suite glob also selects documented_setup.feature and makes the launch gate prepare a builder VM"
    );
}

#[test]
fn perf_budget_scenario_prepares_its_parent_immediately_before_launch() {
    let feature = fs::read_to_string("features/suites/s31_launch_e2e/launch_budget.feature")
        .expect("read launch-budget feature");
    let warm_scenario = feature
        .split_once("Scenario: a warm-residency launch meets the documented start budget")
        .expect("warm launch-budget scenario")
        .1;
    let steps = fs::read_to_string("crates/mvm-conformance/tests/steps/launch_e2e.rs")
        .expect("read launch e2e steps");

    assert!(
        warm_scenario.contains("Given an Alpine warm parent is ready"),
        "the performance scenario must create its expiring standby immediately before it claims it"
    );
    assert!(
        steps.contains("given(expr = \"an Alpine warm parent is ready\")")
            && steps.contains("pool warm 1 --image alpine"),
        "the scenario prerequisite must warm the same Alpine/default-size shape the launch claims"
    );
}

#[test]
fn hosted_ubuntu_ci_uses_explicit_release_labels() {
    let ci = ["ci.yml", "ci-main.yml"]
        .map(|name| {
            fs::read_to_string(format!(".github/workflows/{name}")).expect("read CI workflow")
        })
        .join("\n");
    // This is a text guard; historical alias mentions use full-line comments.
    let moving_alias = ci
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .find(|line| line.contains("ubuntu-latest"));
    assert!(
        moving_alias.is_none(),
        "hosted Ubuntu CI must use an explicit supported release: {moving_alias:?}"
    );
    for job in [
        "lint-core",
        "lint-feature-clippy",
        "lint-policy",
        "lint-features-test-support",
        "lint-features-embed",
        "lint-windows",
    ] {
        let body = job_block(&ci, job);
        assert!(
            body.lines()
                .any(|line| line.trim() == "runs-on: ubuntu-24.04"),
            "{job} must actually run on the pinned Ubuntu release"
        );
    }
}

#[test]
fn guest_binary_producer_lanes_install_the_cross_toolchain_before_tests() {
    let ci = ["ci.yml", "ci-main.yml"]
        .map(|name| {
            fs::read_to_string(format!(".github/workflows/{name}")).expect("read CI workflow")
        })
        .join("\n");
    for job in ["test-workspace-build", "test-workspace-aarch64"] {
        let body = job_block(&ci, job);
        let install = body
            .find("- uses: ./.github/actions/install-zigbuild")
            .expect("producer lane installs the pinned cross toolchain");
        let tests = body
            .find("- name: Install cargo-nextest")
            .expect("producer lane runs nextest");
        assert!(install < tests, "{job} must install Zig before tests");
    }

    let shard = fs::read_to_string(".github/workflows/workspace-shard.yml")
        .expect("read workspace shard workflow");
    assert!(shard.contains(
        "- uses: ./.github/actions/install-zigbuild\n        if: inputs.runner_kind == 'github'"
    ));
    assert!(shard.contains("command -v cargo-zigbuild"));
}

fn source_bootstrap_script() -> String {
    fs::read_to_string("scripts/e2e-source-bootstrap.sh").expect("read source bootstrap witness")
}

/// The release lane fetches the builder image the macOS lane already fetches.
///
/// Building it from source put 37 minutes of Stage 0 ahead of 313 scenarios
/// that never examine the image, and a two-hour Stage 0 hang cancelled the lane
/// before a single scenario ran. The fetch is not a trust shortcut: the binary
/// carries `release-artifact-bootstrap`, so the image is held to the pinned
/// boot-image tag's signed checksum manifest.
#[test]
fn linux_documented_surface_fetches_the_pinned_signed_builder_image() {
    let workflow = extended_ci();
    let linux = job_block(&workflow, "e2e-docs-linux");

    assert_eq!(
        field_after(linux, "MVM_BOOT_IMAGE:").as_deref(),
        Some("fetch"),
        "the Linux release lane must fetch the signed builder image rather than run Stage 0"
    );
    assert!(
        field_after(linux, "MVM_E2E_FEATURES:")
            .is_some_and(|features| features.contains("release-artifact-bootstrap")),
        "fetching without the release verifier compiled in refuses outright"
    );
    assert_eq!(
        field_after(linux, "MVM_BUILDER_BACKEND:").as_deref(),
        Some("firecracker"),
        "left unset, the helper the unembedded binary re-executes picks QEMU, \
         which reaches a builder only through Stage 0"
    );
}

/// A lane that drifts back into a source bootstrap must fail fast.
///
/// Stage 0 on a hosted runner needs the distro kernel made readable and the
/// vhost-vsock device handed to the job. Without those grants an accidental
/// Stage 0 dies in seconds; with them it spends the whole budget.
#[test]
fn linux_documented_surface_grants_nothing_stage0_needs() {
    let workflow = extended_ci();
    let linux = job_block(&workflow, "e2e-docs-linux");

    for stage0_only in [
        "/dev/vhost-vsock",
        "/boot/vmlinuz",
        "qemu-system-x86",
        "virtiofsd",
    ] {
        assert!(
            !linux.contains(stage0_only),
            "the fetching release lane must not provision `{stage0_only}` for a Stage 0 it no longer runs"
        );
    }
}

/// Every step of the source witness is fatal, in the order the path runs.
/// The builder image is bootstrapped through the unembedded binary: packing
/// sidecars no longer reaches a builder VM, so this is the step that proves a
/// binary without a payload hands Stage 0 to the helper it produces.
#[test]
fn the_source_bootstrap_witness_runs_the_cold_path_in_order() {
    let script = source_bootstrap_script();
    let steps = [
        "\"$UNEMBEDDED_MVMCTL\" dev sdk-sidecar build",
        "\"$UNEMBEDDED_MVMCTL\" bootstrap",
        "\"$MVMCTL\" machine build --flake \"$FLAKE\"",
    ];
    let mut last = 0;
    for step in steps {
        let at = script
            .find(step)
            .unwrap_or_else(|| panic!("the source witness must run `{step}`"));
        assert!(at > last, "`{step}` ran out of order");
        last = at;
    }
    assert!(
        script.contains("set -euo pipefail"),
        "every step must be fatal"
    );
    let opt_in = script
        .find("export MVM_ALLOW_LOCAL_BUILDER_BUILD=1")
        .expect("the witness must opt into a local builder-image build, or `build` is refused");
    assert!(
        opt_in < script.find("\"$UNEMBEDDED_MVMCTL\" bootstrap").unwrap_or(0),
        "the opt-in must be exported before the builder image is bootstrapped"
    );
    let source_runtime = script
        .find("export MVM_RUNTIME_OVERLAY_ACQUIRE_MODE=build")
        .expect("bootstrap must assemble every guest piece from this tree's guest runtime");
    assert!(
        source_runtime < script.find("\"$UNEMBEDDED_MVMCTL\" bootstrap").unwrap_or(0),
        "the source guest runtime must be selected before bootstrap prepares the pieces"
    );
    assert!(
        !script.contains("|| true") && !script.contains("if ! "),
        "the source witness must not tolerate a failed step"
    );
}

/// A witness that is told to fetch, or handed a warm home, would pass on an
/// image it did not build; one with no image checkout cannot build at all.
/// Every refusal happens before anything is compiled.
#[cfg(unix)]
#[test]
fn the_source_bootstrap_witness_refuses_to_prove_nothing() {
    let warm = tempfile::tempdir().expect("create warm home fixture");
    fs::write(warm.path().join("leftover"), b"x").expect("seed warm home");
    let cold = tempfile::tempdir().expect("create cold home fixture");
    let missing_images = cold.path().join("no-mvm-images-here");

    let cases = [
        ("a warm home", warm.path().to_path_buf(), None, None),
        (
            "MVM_BOOT_IMAGE=fetch",
            cold.path().join("home"),
            Some("fetch"),
            None,
        ),
        (
            "no mvm-images checkout",
            cold.path().join("home"),
            None,
            Some(missing_images.as_path()),
        ),
    ];
    for (case, home, boot_image, images_dir) in cases {
        let mut command = Command::new("bash");
        command
            .arg("scripts/e2e-source-bootstrap.sh")
            .env("MVM_E2E_HOME", &home)
            .env_remove("MVM_BOOT_IMAGE");
        if let Some(value) = boot_image {
            command.env("MVM_BOOT_IMAGE", value);
        }
        if let Some(dir) = images_dir {
            command.env("MVM_IMAGES_DIR", dir);
        }
        let output = command.output().expect("run the source bootstrap witness");
        assert_eq!(
            output.status.code(),
            Some(2),
            "{case} must be refused before any build: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        if images_dir.is_some() {
            assert!(
                String::from_utf8_lossy(&output.stderr).contains("no mvm-images checkout"),
                "{case} must be refused for the missing checkout, not another reason"
            );
        }
    }
}

#[test]
fn both_live_harnesses_report_phase_timings() {
    let documented = documented_surface_script();
    for phase in [
        "build",
        "builder-image",
        "sdk-sidecar",
        "launch-artifacts",
        "suite",
    ] {
        assert!(
            documented.contains(&format!("e2e_phase {phase}\n")),
            "the documented surface must time its `{phase}` phase"
        );
    }
    assert!(
        documented.contains("  e2e_phase_summary "),
        "the documented surface must print its timings on exit, including a failed or killed run"
    );

    let source = source_bootstrap_script();
    for phase in ["build", "sdk-sidecar", "builder-image", "flake-build"] {
        assert!(
            source.contains(&format!("e2e_phase {phase}\n")),
            "the source bootstrap witness must time its `{phase}` phase"
        );
    }
    assert!(
        source.contains("trap 'e2e_phase_summary "),
        "the source bootstrap witness must print its timings on exit"
    );
}

#[cfg(unix)]
#[test]
fn phase_timings_report_each_phase_and_a_total() {
    let scratch = tempfile::tempdir().expect("create step summary fixture");
    let summary = scratch.path().join("step-summary.md");
    let output = Command::new("bash")
        .args([
            "-c",
            "set -euo pipefail; source scripts/e2e-phase-timings.sh; \
             e2e_phase_summary empty; \
             e2e_phase first; e2e_phase second; e2e_phase_summary 'Fixture timings'",
        ])
        .env("GITHUB_STEP_SUMMARY", &summary)
        .output()
        .expect("run the phase timing helper");
    assert!(
        output.status.success(),
        "the helper must work under set -u with no phases recorded: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in [
        "[phase] name=first seconds=0",
        "[phase] name=second seconds=0",
    ] {
        assert!(stdout.contains(line), "missing `{line}` in:\n{stdout}");
    }
    assert!(stdout.contains("total"), "missing total in:\n{stdout}");

    let table = fs::read_to_string(&summary).expect("read step summary");
    assert!(
        table.contains("### Fixture timings")
            && table.contains("| first | 0 |")
            && table.contains("| second | 0 |")
            && table.contains("| total | 0 |"),
        "the step summary must carry the same table:\n{table}"
    );
    assert!(
        !table.contains("### empty"),
        "a run with no phases must not write an empty table"
    );
}

#[test]
fn linux_documented_surface_does_not_depend_on_host_icmp() {
    let workflow = extended_ci();
    let linux = job_block(&workflow, "e2e-docs-linux");

    assert!(
        !linux.contains("ping_group_range"),
        "positive documented egress witnesses use HTTPS because hosted networks may drop ICMP"
    );
}

#[test]
fn documented_surface_installs_a_deterministic_encrypted_backing_fixture() {
    let script = documented_surface_script();

    assert!(
        script.contains("provision_encrypted_backing_probes()")
            && script.contains("\"source\":\"/dev/mapper/mvm-e2e-crypt\",\"fstype\":\"ext4\"")
            && script.contains("'Journal inode: 8'")
            && script.contains("\"type\":\"crypt\"")
            && script.contains("\"$probe_bin/tune2fs\"")
            && script.contains("'FileVault: Yes'")
            && script.contains("export PATH=\"$probe_bin:$PATH\""),
        "live volume and mount-cache scenarios need a declared encrypted-backing fixture; the hosted runner's root disk is not one"
    );
}

#[test]
fn documented_surface_keeps_its_summary_log_in_the_private_e2e_home() {
    let script = documented_surface_script();

    assert!(
        script.contains("SUITE_LOG=\"$(mktemp \"$E2E_HOME/.e2e-suite.XXXXXX\")\""),
        "unrelated temporary-directory cleanup must not erase the suite summary before it is verified"
    );
}

#[test]
fn positive_live_egress_witnesses_use_https_instead_of_external_icmp() {
    let launch = fs::read_to_string("features/suites/s31_launch_e2e/cli_launch_modes.feature")
        .expect("read launch-mode feature");
    let transient =
        fs::read_to_string("features/suites/s5_lifecycle/transient_sandbox_boot.feature")
            .expect("read transient-launch feature");

    for feature in [&launch, &transient] {
        assert!(
            !feature.lines().any(|line| {
                line.contains("--allow-host")
                    && line.contains(" ping ")
                    && !line.contains("default-deny")
            }),
            "a positive egress gate cannot depend on ICMP replies from the hosted runner network"
        );
    }
    assert!(launch.contains("curlimages/curl:8.21.0"));
    assert!(transient.contains("curlimages/curl:8.21.0"));
}

/// No hosted macOS image can boot a guest: arm64 nests Hypervisor.framework
/// (`HV_UNSUPPORTED`), and on Intel the HVF supervisor links as a stub. Both
/// macOS jobs must run on the self-hosted Apple Silicon runner, or the host
/// check silently degrades the release gate to the evidence record again.
#[test]
fn macos_documented_surface_runs_on_the_self_hosted_apple_silicon_runner() {
    let workflow = extended_ci();

    for job in ["e2e-docs-macos-host-check", "e2e-docs-macos"] {
        let block = job_block(&workflow, job);
        assert!(
            block.contains("runs-on: [self-hosted, macOS, ARM64, m1]"),
            "{job} must target the self-hosted Apple Silicon runner"
        );
        for hosted in ["macos-latest", "macos-15-intel"] {
            assert!(
                !block.contains(&format!("runs-on: {hosted}")),
                "{job} must not run on {hosted}, which cannot boot a guest"
            );
        }
    }
}

/// The runner's label must be known to the workflow lint, or CI's actionlint
/// step fails every PR that touches a workflow.
#[test]
fn the_self_hosted_runner_label_is_declared_for_actionlint() {
    let config = fs::read_to_string(".github/actionlint.yaml").expect("read actionlint config");
    assert!(
        config.contains("self-hosted-runner:") && config.contains("- m1"),
        "actionlint must know the `m1` self-hosted label"
    );
}

/// Nobody logs in to the runner to read a failed run, and the suite script
/// deletes its own log on exit — so the job keeps a copy and uploads it.
#[test]
fn macos_documented_surface_uploads_its_log() {
    let workflow = extended_ci();
    let macos = job_block(&workflow, "e2e-docs-macos");

    let run = macos
        .find("just e2e::docs 2>&1 | tee")
        .expect("the macOS lane must tee the suite output to a file it keeps");
    let pipefail = macos
        .find("set -o pipefail")
        .expect("piping the suite through tee needs pipefail");
    assert!(
        pipefail < run,
        "without pipefail the step reports tee's status, and a red suite shows green"
    );
    assert!(
        macos.contains("uses: actions/upload-artifact@"),
        "the macOS lane must upload the kept log"
    );
    assert!(
        macos.contains("if: always()"),
        "upload on success too: a green run's skip tally is how a hole gets noticed"
    );
}

/// The shared toolchain action must work on a self-hosted Mac as its
/// unprivileged runner user.
#[test]
fn the_zig_toolchain_action_runs_without_sudo_or_modern_python_once_provisioned() {
    let action = fs::read_to_string(".github/actions/install-zigbuild/action.yml")
        .expect("read install-zigbuild action");

    let skip = action
        .find(r#"[ "$(zig version)" = "$ZIG_VERSION" ]"#)
        .expect("the action must skip installing a zig that is already the pinned version");
    let sudo = action
        .find("sudo ")
        .expect("hosted runners still install zig with sudo");
    assert!(
        skip < sudo,
        "the already-installed check must come before the first sudo, or the runner user \
         stops at a password prompt"
    );
    assert!(
        !action.contains("import tomllib"),
        "the system python3 on macOS is 3.9 and has no tomllib"
    );
    assert!(
        !action.contains("cargo install cargo-zigbuild"),
        "hosted jobs must not spend ten minutes compiling a published tool binary"
    );
    for expected in [
        "TARGET=x86_64-unknown-linux-gnu",
        "TARGET=aarch64-unknown-linux-gnu",
        "TARGET=x86_64-apple-darwin",
        "TARGET=aarch64-apple-darwin",
        "ARCHIVE=\"cargo-zigbuild-${TARGET}.tar.xz\"",
        "sha256sum -c -",
        "shasum -a 256 -c -",
    ] {
        assert!(
            action.contains(expected),
            "the prebuilt cargo-zigbuild installer must contain {expected:?}"
        );
    }
}

#[test]
fn documented_surface_builds_the_sdk_codegen_driver() {
    let script = documented_surface_script();

    assert!(
        script.contains("cargo build -p xtask"),
        "the SDK drift scenario invokes the compiled xtask binary directly"
    );
}

#[test]
fn hvf_witness_does_not_install_libkrun() {
    let workflow = extended_ci();
    let macos = job_block(&workflow, "e2e-docs-macos");

    assert!(
        !macos.contains("uses: ./.github/actions/install-libkrun"),
        "the HVF witness must not depend on libkrun, which the runner does not carry"
    );
}

#[test]
fn hvf_witness_uses_hvf_for_steady_state_builder_jobs() {
    let workflow = extended_ci();
    let macos = job_block(&workflow, "e2e-docs-macos");

    assert!(
        macos.contains("MVM_BUILDER_BACKEND: hvf"),
        "the HVF witness must build source artifacts inside the downloaded builder image under HVF"
    );
    assert!(
        !macos.contains("brew install qemu"),
        "the HVF witness must not select QEMU's Linux-only Stage 0 host-kernel path"
    );
}

#[test]
fn root_manifest_keeps_libkrun_opt_in_on_macos() {
    let manifest = root_manifest();

    let cli_dependencies: Vec<&str> = manifest
        .lines()
        .filter(|line| line.trim_start().starts_with("mvm-cli ="))
        .collect();
    assert!(
        !cli_dependencies.is_empty(),
        "the root package depends on mvm-cli"
    );
    for line in cli_dependencies {
        assert!(
            !line.contains("libkrun-sys"),
            "no platform's mvm-cli dependency may enable the optional libkrun FFI: {line}"
        );
    }

    let features = manifest
        .split_once("\n[features]\n")
        .expect("root feature section")
        .1
        .split_once("\n[")
        .map_or_else(|| manifest.as_str(), |(section, _)| section);
    assert!(
        features.contains("libkrun-sys = [\"mvm-cli/libkrun-sys\"]"),
        "older macOS libkrun builds retain an explicit root feature"
    );
}

#[test]
fn macos_release_build_carries_isolated_libkrun_tier() {
    let workflow =
        fs::read_to_string(".github/workflows/release.yml").expect("read release workflow");
    let build = job_block(&workflow, "build");
    let archive_smoke = job_block(&workflow, "archive-install-smoke");

    assert!(
        build.contains("scripts/release/build-libkrun-tier.sh"),
        "the macOS release must build the pinned libkrun tier"
    );
    assert!(
        build.contains("gnu-sed") && build.contains("gnu-tar"),
        "the native kernel build must select GNU-compatible archive and text tools"
    );
    assert!(
        build.contains("mvm-hvf-supervisor mvm-libkrun-supervisor"),
        "the macOS archive must package both native backend supervisors"
    );
    assert!(
        build.contains("lib/libkrunfw.dylib"),
        "the archive must require libkrunfw's bare-name compatibility link"
    );
    assert!(
        build.contains("SOURCE-OFFER.txt"),
        "the libkrun release tier must ship corresponding-source directions"
    );
    assert!(
        build.contains("libkrunfw-LGPL-2.1-only.txt"),
        "the libkrun release tier must ship its license inventory"
    );
    assert!(
        archive_smoke.contains("mvm-libkrun-supervisor\" --contract-version"),
        "the archive-install lane must load and probe the packaged supervisor"
    );
    assert!(
        build.contains("--features \"${MVMCTL_RELEASE_FEATURES}\""),
        "mvmctl itself must remain independent of the libkrun FFI"
    );
}

#[test]
fn macos_documented_surface_job_installs_the_embedded_cross_toolchain() {
    let workflow = extended_ci();
    let macos = job_block(&workflow, "e2e-docs-macos");

    assert!(
        macos.contains("uses: ./.github/actions/install-zigbuild"),
        "the macOS build script compiles the embedded Linux binaries and needs the shared cross-toolchain installer"
    );
}

#[test]
fn signature_verifying_build_avoids_the_fast_codegen_link_path() {
    let script = documented_surface_script();

    assert!(
        script.contains(
            "cargo build --profile \"$E2E_PROFILE\" --bin mvmctl --features \"$E2E_FEATURES,embed-host-bins\""
        ),
        "the aws-lc-backed user build must use Cargo's standard compiler and linker path"
    );
    // Checks that `cargo-fast.sh` is never handed `$E2E_FEATURES`, not that it
    // is never handed any feature at all. The blunt form of this assertion —
    // "cargo-fast.sh is not invoked with `--features`" — held only while the
    // featureless arm passed no features, and broke the moment
    // `embed-host-bins` was added to both arms. That flag pulls no aws-lc, so
    // it is fine on the fast path; `$E2E_FEATURES` is the one that is not.
    assert!(
        !script
            .lines()
            .any(|line| line.contains("cargo-fast.sh build") && line.contains("$E2E_FEATURES")),
        "the fast codegen wrapper leaves aws-lc native symbols unresolved"
    );
}

/// The sidecar is still packed through the unembedded binary, after the
/// builder image is acquired: a binary without a host payload must pack both
/// variants on the host from the checkout's guest runtime.
#[test]
fn documented_surface_builds_the_sidecar_through_an_unembedded_cli() {
    let script = documented_surface_script();

    let unembedded_build = script
        .find("cargo build --profile \"$E2E_PROFILE\" --bin mvmctl --features \"$E2E_FEATURES\"")
        .expect("the release-feature lane must build an unembedded witness");
    let embedded_build = script
        .find(
            "cargo build --profile \"$E2E_PROFILE\" --bin mvmctl --features \"$E2E_FEATURES,embed-host-bins\"",
        )
        .expect("the live suite must restore its embedded binary");
    let sidecar_warm = script
        .find("\"$UNEMBEDDED_MVMCTL\" dev sdk-sidecar build")
        .expect("the sidecar warm must execute the unembedded witness");
    let explicit_bootstrap = script
        .find("\"$MVMCTL\" bootstrap")
        .expect("the suite must retain the explicit bootstrap check");

    assert!(unembedded_build < embedded_build);
    assert!(embedded_build < explicit_bootstrap);
    assert!(
        explicit_bootstrap < sidecar_warm,
        "the builder image must be acquired before the sidecar build needs it"
    );
}

/// The macOS lane holds every warm launch to the 300 ms startup ceiling, so
/// it has to measure an optimized build: unoptimized, plan admission alone
/// took most of the budget on its runner. And every binary under test has to
/// come from that one profile, because `mvmctl` launches the helpers and loads
/// the host library that sit beside it.
#[test]
fn the_ceiling_enforcing_macos_lane_builds_every_binary_under_test_optimized() {
    let workflow = extended_ci();
    assert!(
        job_block(&workflow, "e2e-docs-macos").contains("MVM_E2E_PROFILE: release-witness"),
        "the macOS HVF lane must build the binaries it holds to the startup ceiling optimized"
    );

    let script = documented_surface_script();
    assert!(script.contains("MVMCTL=\"$TARGET_DIR/$E2E_PROFILE_DIR/mvmctl\""));
    assert!(script.contains("just payload::supervisors --profile \"$E2E_PROFILE\""));
    assert!(script.contains("build_sdk_hostlib \"$MVMCTL\" \"$E2E_PROFILE\""));
    for line in script.lines().filter(|line| {
        let line = line.trim_start();
        (line.starts_with("cargo build") || line.starts_with("./scripts/cargo-fast.sh build"))
            && line.contains("--bin mvmctl")
    }) {
        assert!(
            line.contains("--profile \"$E2E_PROFILE\""),
            "every mvmctl build must use the lane's profile: {line}"
        );
    }
}

#[test]
fn documented_surface_jobs_install_the_sdk_codegen_runtime() {
    let workflow = extended_ci();

    for job in ["e2e-docs-linux", "e2e-docs-macos"] {
        let block = job_block(&workflow, job);
        assert!(
            block.contains("uses: astral-sh/setup-uv@v8.2.0"),
            "{job} invokes uvx through the SDK drift witness and must use the repository-pinned action"
        );
        assert!(
            block.contains("version: \"0.12.5\""),
            "{job} must pin the uv tool version"
        );
    }
}

/// Neither caller of the documented surface pair-builds guest pieces through
/// mvm-images: the jobs check out no image repository and set no image-arm
/// knob, the release passes no image input, and the runner packs the sidecar
/// from the tree while adopting the Linux-layer dev image from the pinned set.
#[test]
fn the_documented_surface_builds_no_guest_piece_through_mvm_images() {
    let release =
        fs::read_to_string(".github/workflows/release.yml").expect("read release workflow");
    let workflow = extended_ci();
    for (name, text) in [
        ("release.yml", release.as_str()),
        ("e2e-docs.yml", workflow.as_str()),
    ] {
        assert!(
            !text.contains("boot_pinned_images"),
            "{name}: the image-arm input is gone; there is no pair-build arm to choose"
        );
    }
    for job in ["e2e-docs-linux", "e2e-docs-macos"] {
        let block = job_block(&workflow, job);
        for forbidden in [
            "tinylabscom/mvm-images",
            "image-source-ref",
            "MVM_E2E_IMAGES_DIR",
            "MVM_IMAGES_DIR",
            "MVM_FETCH_UNCHANGED_IMAGES",
        ] {
            assert!(
                !block.contains(forbidden),
                "{job} must not reach mvm-images for a guest piece: found `{forbidden}`"
            );
        }
    }

    let script = documented_surface_script();
    for forbidden in ["MVM_E2E_IMAGES_DIR", "MVM_IMAGES_DIR=", "E2E_IMAGE_ENV"] {
        assert!(
            !script.contains(forbidden),
            "the runner must not hand an image checkout to any step: found `{forbidden}`"
        );
    }
    assert!(
        !script.contains("MVM_FETCH_UNCHANGED_IMAGES"),
        "fetch-when-unchanged is gone; the runner must not set its knob"
    );
    assert!(
        script.contains(
            "MVM_HOME=\"$E2E_HOME\" \"$UNEMBEDDED_MVMCTL\" dev sdk-sidecar build --source build"
        ),
        "the sidecar must be packed from the tree"
    );
    assert!(
        script.contains("MVM_HOME=\"$E2E_HOME\" \"$MVMCTL\" image dev ensure"),
        "the dev default image is Linux layer and is installed from the pinned set"
    );
}

#[test]
fn documented_surface_warms_the_source_matched_sdk_sidecar() {
    let script = documented_surface_script();

    assert!(
        script.contains("\"$UNEMBEDDED_MVMCTL\" dev sdk-sidecar build"),
        "the live SDK scenarios must use a sidecar built from the checkout under test"
    );
}

#[test]
fn documented_surface_revalidates_the_source_matched_initramfs() {
    let script = documented_surface_script();
    let warm = script
        .split_once("warm_launch_artifacts() {")
        .expect("warm_launch_artifacts function")
        .1
        .split_once("\n}")
        .expect("warm_launch_artifacts body")
        .0;

    assert!(
        warm.contains("\"$MVMCTL\" machine run --name bdd-warmup"),
        "the warm-up must enter launch resolution so its source fingerprint can evict a stale initramfs"
    );
    assert!(
        !warm.contains("universal initramfs already cached")
            && !warm.contains("find \"$E2E_HOME/cache/initramfs\""),
        "file existence is not freshness: a cached initramfs may contain a guest agent from an older checkout"
    );
}

#[test]
fn standard_supervisor_build_never_enables_libkrun() {
    let just = fs::read_to_string("just/payload/mod.just").expect("read embed module");
    let recipe = just
        .split_once("\nsupervisors")
        .expect("supervisors recipe")
        .1
        .split_once("\n# ")
        .map_or_else(|| just.as_str(), |(recipe, _)| recipe);

    assert!(
        recipe.contains("build -p mvm-hostd --bins"),
        "portable helper binaries must still build on every host"
    );
    assert!(
        !recipe.contains("libkrun"),
        "standard helper builds must not probe for or enable libkrun"
    );

    let optional = just
        .split_once("\nlibkrun-supervisor")
        .expect("explicit libkrun integration recipe")
        .1
        .split_once("\n# ")
        .map_or_else(|| just.as_str(), |(recipe, _)| recipe);
    assert!(
        optional.contains("--bin mvm-libkrun-supervisor --features libkrun-sys"),
        "the optional integration must remain explicitly buildable"
    );
}

/// The suite must create the mvm home private, the way `mvmctl` would.
///
/// With `MVM_E2E_HOME` unset the home falls back to the real `$HOME/.mvm`, and
/// creating it under the caller's umask leaves it 0755 on a CI runner. That is
/// a W1.5 violation the suite's own `doctor` scenario then reports as `data dir
/// mode: MISSING`, so the lane went red for a directory the harness made wrong
/// before mvmctl ever saw it. Nothing repairs it either: the `ensure_home_dir`
/// helper that would has no callers anywhere in the workspace.
#[test]
fn the_documented_surface_creates_its_mvm_home_private() {
    let script = documented_surface_script();
    assert!(
        !script.contains("mkdir -p \"$E2E_HOME\""),
        "the mvm home must not be created bare; the umask makes it 0755 and \
         doctor fails the lane on it"
    );
    assert!(
        script.contains("chmod 700 \"$1\""),
        "the mvm home helper must chmod unconditionally — `mkdir -m` applies the \
         mode only to directories it creates, leaving an already-loose home loose"
    );
}
