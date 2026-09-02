//! Regression checks for the scheduled documented-surface witnesses.

use std::fs;

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
}

fn documented_surface_script() -> String {
    fs::read_to_string("scripts/e2e-documented-surface.sh").expect("read documented-surface runner")
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
}

#[test]
fn linux_documented_surface_makes_the_stage0_boot_files_readable() {
    let workflow = extended_ci();
    let linux = job_block(&workflow, "e2e-docs-linux");

    assert!(
        linux.contains("sudo chmod a+r")
            && linux.contains("/boot/vmlinuz-${KERNEL_RELEASE}")
            && linux.contains("/boot/initrd.img-${KERNEL_RELEASE}"),
        "the unprivileged QEMU Stage 0 process must be able to read the hosted runner kernel and initramfs"
    );
}

#[test]
fn linux_documented_surface_grants_stage0_vhost_vsock_access() {
    let workflow = extended_ci();
    let linux = job_block(&workflow, "e2e-docs-linux");

    assert!(
        linux.contains("test -c /dev/vhost-vsock")
            && linux.contains("sudo chown \"$(id -u):$(id -g)\" /dev/vhost-vsock")
            && linux.contains("sudo chmod 0600 /dev/vhost-vsock")
            && linux.contains("test -r /dev/vhost-vsock && test -w /dev/vhost-vsock"),
        "the unprivileged QEMU Stage 0 process must own and be able to open the hosted vhost-vsock device"
    );
}

#[test]
fn linux_documented_surface_installs_virtiofsd_for_stage0_shares() {
    let workflow = extended_ci();
    let linux = job_block(&workflow, "e2e-docs-linux");

    assert!(
        linux.contains("packages: libcap-ng-dev lld qemu-system-x86 qemu-utils virtiofsd"),
        "the QEMU builder must install virtiofsd before sharing the checkout with Stage 0"
    );
}

#[test]
fn linux_documented_surface_grants_unprivileged_icmp_to_the_runner_group() {
    let workflow = extended_ci();
    let linux = job_block(&workflow, "e2e-docs-linux");

    assert!(
        linux.contains("sudo sysctl -w net.ipv4.ping_group_range=\"0 2147483647\"")
            && linux.contains(
                "read -r ping_gid_min ping_gid_max < <(sysctl -n net.ipv4.ping_group_range)"
            )
            && linux.contains("test \"$ping_gid_min\" = \"0\"")
            && linux.contains("test \"$ping_gid_max\" = \"2147483647\""),
        "the documented ping witnesses need the runner group admitted to unprivileged ICMP sockets"
    );
}

#[test]
fn macos_documented_surface_uses_an_intel_runner_with_hvf_access() {
    let workflow = extended_ci();
    let macos = job_block(&workflow, "e2e-docs-macos");

    assert!(
        macos.contains("runs-on: macos-15-intel"),
        "the arm64 hosted runner rejects hv_vm_create with HV_UNSUPPORTED"
    );
    assert!(
        !macos.contains("runs-on: macos-latest"),
        "macos-latest currently selects an arm64 VM without nested HVF"
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
fn intel_hvf_witness_does_not_install_arm_only_libkrun_firmware() {
    let workflow = extended_ci();
    let macos = job_block(&workflow, "e2e-docs-macos");

    assert!(
        !macos.contains("uses: ./.github/actions/install-libkrun"),
        "the Intel HVF witness cannot install libkrunfw, whose formula requires arm64"
    );
}

#[test]
fn intel_hvf_witness_uses_hvf_for_steady_state_builder_jobs() {
    let workflow = extended_ci();
    let macos = job_block(&workflow, "e2e-docs-macos");

    assert!(
        macos.contains("MVM_BUILDER_BACKEND: hvf"),
        "the Intel witness must build source artifacts inside the downloaded builder image under HVF"
    );
    assert!(
        !macos.contains("brew install qemu"),
        "the Intel witness must not select QEMU's Linux-only Stage 0 host-kernel path"
    );
    assert!(
        macos.contains("timeout-minutes: 90"),
        "the cold HVF builder job and live HVF scenarios need a bounded but realistic deadline"
    );
}

#[test]
fn root_manifest_enables_libkrun_only_on_apple_silicon() {
    let manifest = root_manifest();

    let arm64 = manifest
        .split_once(
            "[target.'cfg(all(target_os = \"macos\", target_arch = \"aarch64\"))'.dependencies]",
        )
        .expect("Apple Silicon dependency section")
        .1
        .split_once("\n[")
        .map_or_else(|| manifest.as_str(), |(section, _)| section);
    assert!(
        arm64.contains("features = [\"builder-vm\", \"libkrun-sys\"]"),
        "Apple Silicon keeps the libkrun-backed builder path"
    );

    let intel = manifest
        .split_once(
            "[target.'cfg(all(target_os = \"macos\", target_arch = \"x86_64\"))'.dependencies]",
        )
        .expect("Intel macOS dependency section")
        .1
        .split_once("\n[")
        .map_or_else(|| manifest.as_str(), |(section, _)| section);
    assert!(
        intel.contains("features = [\"builder-vm\"]"),
        "Intel HVF keeps builder orchestration without linking libkrun"
    );
    assert!(
        !intel.contains("libkrun-sys"),
        "Intel HVF must not enable the ARM-only libkrun dependency"
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

#[test]
fn documented_surface_cold_builds_the_sidecar_through_an_unembedded_cli() {
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
    assert!(embedded_build < sidecar_warm);
    assert!(sidecar_warm < explicit_bootstrap);
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
fn supervisor_build_requires_a_detected_libkrun_header() {
    let just = justfile();
    let recipe = just
        .split_once("build-supervisors:")
        .expect("build-supervisors recipe")
        .1
        .split_once("\n# ")
        .map_or_else(|| just.as_str(), |(recipe, _)| recipe);

    assert!(
        recipe.contains("build -p mvm-hostd --bins"),
        "portable helper binaries must still build on every host"
    );
    let header_gate = recipe
        .find("if [[ -f \"$header\" ]]")
        .expect("the optional libkrun helper must require a detected header");
    let libkrun_build = recipe
        .find("--bin mvm-libkrun-supervisor --features libkrun-sys")
        .expect("the optional libkrun helper build must remain present");

    assert!(
        libkrun_build > header_gate,
        "the libkrun-sys helper must only build after a real header is found"
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

/// The aarch64 smoke must print its captured log however it dies.
///
/// The boot is redirected wholesale to a file, and the tail used to sit inside
/// the wrong-exit-code branch, so a run killed before reaching that branch
/// printed nothing at all: the job reported `exit code 143` over an empty step
/// with no way to tell what the guest had been doing. A lane that cannot say
/// why it failed is one nobody can fix.
#[test]
fn the_aarch64_smoke_prints_its_boot_log_on_any_failure() {
    let workflow =
        fs::read_to_string(".github/workflows/ci-full.yml").expect("read extended CI workflow");
    let trap = workflow
        .find("trap 'echo \"::group::mvmctl first-boot log (tail)\"")
        .expect("the first-boot step must dump its log from an EXIT trap");
    let branch = workflow
        .find("expected guest exit code 7 from first boot")
        .expect("the first-boot step must still assert the exit code");
    assert!(
        trap < branch,
        "the log dump must be armed before the run, or a death that skips the \
         exit-code branch still prints nothing"
    );
}
