//! Regression checks for the scheduled documented-surface witnesses.

use std::fs;
#[cfg(unix)]
use std::process::Command;
#[cfg(unix)]
use std::time::{Duration, Instant};

/// The workflow that defines the documented-surface jobs.
///
/// They used to be inline in `ci-full.yml`, which is why this file is named for
/// Extended CI. They now live in a reusable workflow because `release.yml`
/// needs the identical lane — a release used to be cut without them at all —
/// and `ci-full.yml` calls it rather than declaring its own copy.
fn extended_ci() -> String {
    fs::read_to_string(".github/workflows/e2e-docs.yml").expect("read documented-surface workflow")
}

/// Extended CI must still reach those jobs, by calling the shared workflow.
///
/// Without this, moving them out of `ci-full.yml` would satisfy every
/// assertion below while the nightly run stopped exercising them.
#[test]
fn extended_ci_calls_the_shared_documented_surface_workflow() {
    let workflow =
        fs::read_to_string(".github/workflows/ci-full.yml").expect("read extended CI workflow");
    assert!(
        workflow.contains("uses: ./.github/workflows/e2e-docs.yml"),
        "ci-full.yml must call the shared documented-surface workflow, or the \
         nightly run no longer boots the documented examples"
    );
}

/// Firecracker's snapshot contains absolute device paths. Loading a forked
/// child remaps those paths with a private mount namespace and bind mounts,
/// which requires CAP_SYS_ADMIN on Linux. GitHub's runner user can access KVM
/// after chmod but does not gain that capability, so the live witness must run
/// through the runner's passwordless sudo boundary. Otherwise the parent boots
/// and captures successfully, then every preload fails while entering the
/// mount namespace.
#[test]
fn the_live_warm_claim_runs_with_mount_namespace_privilege() {
    let workflow =
        fs::read_to_string(".github/workflows/ci-full.yml").expect("read extended CI workflow");
    let job = job_block(&workflow, "bdd-live-warm-claim");

    assert!(
        job.contains("sudo --preserve-env=HOME,CARGO_HOME,RUSTUP_HOME,CARGO_TARGET_DIR,RUSTFLAGS,MVM_KERNEL_SOURCE,FC_VERSION"),
        "the live warm-claim process must have mount-namespace privilege, not only /dev/kvm access"
    );
    assert!(
        job.contains("env \"PATH=$PATH\""),
        "the privileged recipe must restore the provisioned runner PATH for cargo and rustc"
    );
    assert!(
        job.contains("\"$HOME/.cargo/bin/just\" bdd-live-warm-claim"),
        "the privileged step must use the runner's absolute just path because sudo replaces PATH"
    );
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
        workflow.contains("needs: [bdd, e2e-docs, build, initramfs-image]"),
        "the release job must wait on e2e-docs, or a tag is published without \
         evidence that the documented examples run"
    );

    // Listing a job in `needs` is not the gate. The publish job runs under
    // `!cancelled()`, which overrides the implicit all-needs-succeeded rule, so
    // a need whose result is not named in the condition is waited for and then
    // ignored. `e2e-docs` was in `needs` and absent from the condition from the
    // day the documented-surface gate landed: the gate existed, was listed, was
    // asserted by the line above, and would have published a release over a
    // completely red lane.
    //
    // Checking the whole `needs` list against the condition, rather than
    // e2e-docs alone, is what makes this catch the *next* one too.
    let condition = workflow
        .lines()
        .find(|line| line.trim_start().starts_with("if: ${{ !cancelled()"))
        .expect("the release job must gate publication on an explicit condition");
    for need in ["bdd", "e2e-docs", "build", "initramfs-image"] {
        assert!(
            condition.contains(&format!("needs.{need}.result == 'success'")),
            "`{need}` is in the release job's `needs` but its result is not \
             required by the publish condition. Under `!cancelled()` that means \
             the job is waited for and its failure ignored — a gate that reads \
             as covered and enforces nothing."
        );
    }
}

/// The release gate must be stated at the release call site, not inherited.
///
/// No GitHub-hosted macOS runner can boot an mvm guest (issue #3011), so on
/// every hosted host the macOS lane is skipped and the release caller falls
/// back to a committed evidence record instead. Extended CI opts out of that
/// requirement nightly — otherwise its red never varies and stops being read at
/// all — and the danger in having an opt-out is that the release caller quietly
/// acquires it too. Then a tag cuts with no macOS evidence of any kind and
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

    let extended =
        fs::read_to_string(".github/workflows/ci-full.yml").expect("read extended CI workflow");
    assert!(
        extended.contains("macos_blocks_on_unusable_host: false"),
        "Extended CI must tolerate the standing hardware gap, or its nightly red \
         reports the same thing for a missing runner as for a regression"
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
         sets, or Extended CI's nightly starts failing on evidence staleness"
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
    }
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

    for attempt in 1..=2 {
        let _ = fs::remove_file(&ready_path);
        let started = Instant::now();
        let status = Command::new("python3")
            .args([
                "scripts/run-bounded-command.py",
                "--timeout",
                "1",
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
            started.elapsed() < Duration::from_secs(5),
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
        .args(["scripts/run-bounded-command.py", "--timeout", "5", "--log"])
        .arg(&log_path)
        .args(["--", "sh", "-c", "sleep 30 & echo bounded-marker; exit 7"])
        .status()
        .expect("run bounded command success path");

    assert_eq!(status.code(), Some(7));
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "an outliving descendant kept the output pipe open"
    );
    assert_eq!(
        fs::read_to_string(log_path).expect("read bounded command log"),
        "bounded-marker\n"
    );
}

fn justfile() -> String {
    fs::read_to_string("Justfile").expect("read Justfile")
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
        "`just e2e-launch` must build the manifest verifier through the standard linker before it downloads a published workload kernel"
    );
    assert!(
        script.contains("export MVM_KERNEL_SOURCE=download"),
        "`just e2e-launch` must not route a cold source checkout through the optional libkrun Stage 0 backend"
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
        "`just e2e-launch` must name its three launch feature files explicitly"
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

fn ci_full() -> String {
    fs::read_to_string(".github/workflows/ci-full.yml").expect("read Extended CI workflow")
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

/// The cold source path keeps a live witness of its own.
#[test]
fn extended_ci_runs_the_cold_source_bootstrap_witness() {
    let workflow = ci_full();
    let job = job_block(&workflow, "source-bootstrap-linux");

    assert!(
        job.contains("run: just e2e-source-bootstrap"),
        "the nightly source bootstrap job must run the dedicated witness"
    );
    assert!(
        job.contains("MVM_E2E_HOME: ${{ runner.temp }}/source-bootstrap-home"),
        "the witness needs a cold home under the runner's temp directory"
    );
    assert!(
        field_after(job, "MVM_BOOT_IMAGE:").is_none(),
        "the source witness must not be pointed at the published image"
    );
    assert!(
        justfile().contains("e2e-source-bootstrap:\n    ./scripts/e2e-source-bootstrap.sh"),
        "the recipe must run the source bootstrap witness"
    );
}

/// The job runs checkout-controlled Nix inputs on a KVM host; it gets a
/// read-only token and runs only in the canonical repository.
#[test]
fn the_source_bootstrap_job_is_least_privilege() {
    let workflow = ci_full();
    let job = job_block(&workflow, "source-bootstrap-linux");

    assert!(
        job.contains("permissions:\n      contents: read\n"),
        "the source bootstrap job must hold a read-only token and nothing else"
    );
    assert!(
        job.contains("if: github.repository == 'tinylabscom/mvm'"),
        "the source bootstrap job must not run on forks"
    );
}

/// Stage 0's builder timeout is two hours; a job budget below that reports a
/// hang as a cancellation instead of as the builder error that names it.
#[test]
fn the_source_bootstrap_budget_outlasts_the_stage0_builder_timeout() {
    let workflow = ci_full();
    let job = job_block(&workflow, "source-bootstrap-linux");
    let minutes: u64 = field_after(job, "timeout-minutes:")
        .and_then(|value| value.parse().ok())
        .expect("the source bootstrap job must declare a budget");

    assert!(
        minutes > 120 + 30,
        "timeout-minutes {minutes} leaves no room for setup beyond a two-hour Stage 0"
    );
}

/// A refusing Stage 0 guest explains itself only on its console.
#[test]
fn the_source_bootstrap_job_keeps_the_guest_consoles_of_a_failed_run() {
    let workflow = ci_full();
    let job = job_block(&workflow, "source-bootstrap-linux");

    assert!(
        job.contains("if: failure()")
            && job.contains("uses: actions/upload-artifact@v7")
            && job.contains("${{ runner.temp }}/source-bootstrap-home/vms/*/console.log"),
        "a failed source bootstrap must upload the guest consoles that name the cause"
    );
}

#[test]
fn the_source_bootstrap_job_makes_the_stage0_boot_files_readable() {
    let workflow = ci_full();
    let job = job_block(&workflow, "source-bootstrap-linux");

    assert!(
        job.contains("sudo chmod a+r")
            && job.contains("/boot/vmlinuz-${KERNEL_RELEASE}")
            && job.contains("/boot/initrd.img-${KERNEL_RELEASE}"),
        "the unprivileged QEMU Stage 0 process must be able to read the hosted runner kernel and initramfs"
    );
}

#[test]
fn the_source_bootstrap_job_grants_stage0_vhost_vsock_access() {
    let workflow = ci_full();
    let job = job_block(&workflow, "source-bootstrap-linux");

    assert!(
        job.contains("test -c /dev/vhost-vsock")
            && job.contains("sudo chown \"$(id -u):$(id -g)\" /dev/vhost-vsock")
            && job.contains("sudo chmod 0600 /dev/vhost-vsock")
            && job.contains("test -r /dev/vhost-vsock && test -w /dev/vhost-vsock"),
        "the unprivileged QEMU Stage 0 process must own and be able to open the hosted vhost-vsock device"
    );
}

#[test]
fn the_source_bootstrap_job_installs_qemu_for_stage0() {
    let workflow = ci_full();
    let job = job_block(&workflow, "source-bootstrap-linux");

    assert!(
        job.contains("packages: libcap-ng-dev lld qemu-system-x86 qemu-utils virtiofsd"),
        "the QEMU Stage 0 builder must be installed before the source bootstrap"
    );
}

/// Every step of the source witness is fatal, in the order the path runs.
#[test]
fn the_source_bootstrap_witness_runs_the_cold_path_in_order() {
    let script = source_bootstrap_script();
    let steps = [
        "\"$UNEMBEDDED_MVMCTL\" build sdk-sidecar build",
        "\"$MVMCTL\" bootstrap",
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
    assert!(
        !script.contains("|| true") && !script.contains("if ! "),
        "the source witness must not tolerate a failed step"
    );
}

/// A witness that is told to fetch, or handed a warm home, would pass on an
/// image it did not build. Both refusals happen before anything is compiled.
#[cfg(unix)]
#[test]
fn the_source_bootstrap_witness_refuses_to_prove_nothing() {
    let warm = tempfile::tempdir().expect("create warm home fixture");
    fs::write(warm.path().join("leftover"), b"x").expect("seed warm home");
    let cold = tempfile::tempdir().expect("create cold home fixture");

    let cases = [
        ("a warm home", warm.path().to_path_buf(), None),
        (
            "MVM_BOOT_IMAGE=fetch",
            cold.path().join("home"),
            Some("fetch"),
        ),
    ];
    for (case, home, boot_image) in cases {
        let mut command = Command::new("bash");
        command
            .arg("scripts/e2e-source-bootstrap.sh")
            .env("MVM_E2E_HOME", &home)
            .env_remove("MVM_BOOT_IMAGE");
        if let Some(value) = boot_image {
            command.env("MVM_BOOT_IMAGE", value);
        }
        let output = command.output().expect("run the source bootstrap witness");
        assert_eq!(
            output.status.code(),
            Some(2),
            "{case} must be refused before any build: {}",
            String::from_utf8_lossy(&output.stderr)
        );
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
            && script.contains("/dev/mapper/mvm-e2e-crypt")
            && script.contains("' crypt\"")
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
        .find("just e2e-docs 2>&1 | tee")
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

    let arm64 = manifest
        .split_once(
            "[target.'cfg(all(target_os = \"macos\", target_arch = \"aarch64\"))'.dependencies]",
        )
        .expect("Apple Silicon dependency section")
        .1
        .split_once("\n[")
        .map_or_else(|| manifest.as_str(), |(section, _)| section);
    let arm64_cli = arm64
        .lines()
        .find(|line| line.trim_start().starts_with("mvm-cli ="))
        .expect("Apple Silicon mvm-cli dependency");
    assert!(
        arm64_cli.contains("features = [\"builder-vm\"]"),
        "Apple Silicon keeps builder orchestration for the native HVF path"
    );
    assert!(
        !arm64_cli.contains("libkrun-sys"),
        "Apple Silicon HVF builds must not require optional libkrun headers"
    );

    let intel = manifest
        .split_once(
            "[target.'cfg(all(target_os = \"macos\", target_arch = \"x86_64\"))'.dependencies]",
        )
        .expect("Intel macOS dependency section")
        .1
        .split_once("\n[")
        .map_or_else(|| manifest.as_str(), |(section, _)| section);
    let intel_cli = intel
        .lines()
        .find(|line| line.trim_start().starts_with("mvm-cli ="))
        .expect("Intel macOS mvm-cli dependency");
    assert!(
        intel_cli.contains("features = [\"builder-vm\"]"),
        "Intel HVF keeps builder orchestration without linking libkrun"
    );
    assert!(
        !intel_cli.contains("libkrun-sys"),
        "Intel HVF must not enable the ARM-only libkrun dependency"
    );

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
fn macos_release_build_is_libkrun_free() {
    let workflow =
        fs::read_to_string(".github/workflows/release.yml").expect("read release workflow");
    let build = job_block(&workflow, "build");

    assert!(
        !build.contains("uses: ./.github/actions/install-libkrun"),
        "standard macOS release builds must not install libkrun"
    );
    assert!(
        !build.contains("libkrun-sys"),
        "released mvmctl binaries and helpers must not link optional libkrun FFI"
    );
    assert!(
        !build.contains("--bin mvm-libkrun-supervisor"),
        "standard macOS release artifacts must not build the libkrun supervisor"
    );
    assert!(
        !build.contains("mvm-hvf-supervisor mvm-libkrun-supervisor"),
        "standard macOS release artifacts must not package the libkrun supervisor"
    );
    assert!(
        build.contains("--features \"${MVMCTL_RELEASE_FEATURES}\""),
        "the release build must use the platform-neutral feature set directly"
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
        script.contains("cargo build --bin mvmctl --features \"$E2E_FEATURES,embed-host-bins\""),
        "the aws-lc-backed user build must use Cargo's standard compiler and linker path"
    );
    // Checks that `cargo-fast.sh` is never handed `$E2E_FEATURES`, not that it
    // is never handed any feature at all. The blunt form of this assertion —
    // "cargo-fast.sh is not invoked with `--features`" — held only while the
    // featureless arm passed no features, and broke the moment
    // `embed-host-bins` was added to both arms. That flag pulls no aws-lc, so
    // it is fine on the fast path; `$E2E_FEATURES` is the one that is not.
    assert!(
        !script.contains("./scripts/cargo-fast.sh build --bin mvmctl --features \"$E2E_FEATURES"),
        "the fast codegen wrapper leaves aws-lc native symbols unresolved"
    );
}

/// The sidecar is still built through the unembedded binary, but after the
/// builder image is acquired: the embedded binary fetches and verifies it once,
/// so the helper the unembedded binary re-executes finds it ready instead of
/// being compiled only to acquire it.
#[test]
fn documented_surface_builds_the_sidecar_through_an_unembedded_cli() {
    let script = documented_surface_script();

    let unembedded_build = script
        .find("cargo build --bin mvmctl --features \"$E2E_FEATURES\"")
        .expect("the release-feature lane must build an unembedded witness");
    let embedded_build = script
        .find("cargo build --bin mvmctl --features \"$E2E_FEATURES,embed-host-bins\"")
        .expect("the live suite must restore its embedded binary");
    let sidecar_warm = script
        .find("\"$UNEMBEDDED_MVMCTL\" build sdk-sidecar build")
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

#[test]
fn documented_surface_warms_the_source_matched_sdk_sidecar() {
    let script = documented_surface_script();

    assert!(
        script.contains("\"$UNEMBEDDED_MVMCTL\" build sdk-sidecar build"),
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
    let just = justfile();
    let recipe = just
        .split_once("\nbuild-supervisors")
        .expect("build-supervisors recipe")
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
        .split_once("\nbuild-libkrun-supervisor")
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

/// The hosted TCG boot must print its captured log however it dies.
///
/// Bundle preparation emits directly to the job log and is bounded to verified
/// fixture assembly. The remaining guest boot is redirected wholesale to a
/// file, so its diagnostic tail must be armed before the run starts.
#[test]
fn the_no_kvm_smoke_prints_its_boot_log_on_any_failure() {
    let workflow =
        fs::read_to_string(".github/workflows/ci-full.yml").expect("read extended CI workflow");
    let boot_trap = workflow
        .find("trap 'echo \"::group::mvmctl bundle-run log (tail)\"")
        .expect("the installed-bundle step must dump its log from an EXIT trap");
    let boot = workflow
        .find("--manifest \"$installed_sha\"")
        .expect("the installed-bundle boot must remain present");
    assert!(
        boot_trap < boot,
        "the boot log dump must be armed before the installed-bundle run"
    );
}
