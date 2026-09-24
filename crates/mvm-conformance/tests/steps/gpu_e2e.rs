//! GPU-over-vsock end-to-end witness steps (issue #3567).
//!
//! The positive scenario boots a real `--gpu` microVM on a GPU-less host —
//! the endpoint answers through the deterministic stub backend — mounts a
//! staging dir with a guest probe binary and the glibc shim cdylibs, and
//! asserts both the guest-observed stub answers and the host-side
//! `gpu-endpoint.log` lines proving each call landed on the endpoint. The
//! negative scenario boots without `--gpu` and asserts the GPU vsock
//! channel is absent: the probe's dial is refused and no endpoint exists
//! in the VM state dir.

use std::path::{Path, PathBuf};
use std::process::Command;

use cucumber::{given, then, when};

use crate::steps::cli::run_mvmctl_isolated_live_home_argv;
use crate::world::CliWorld;

/// Guest path the staging mount maps to. Mounts outside `/data` and
/// `/work` are refused by the mount policy, and `/mvm` is protected, so
/// the probe dlopens the shims by absolute path instead of relying on the
/// activation's loader-path injection (which targets the runtime overlay's
/// own shim set).
/// Placeholder the feature text uses where the host staging path belongs.
const STAGING_PLACEHOLDER: &str = "@STAGING@";

/// Sonames the staging dir must carry — the drop-in names a workload links.
const STAGED_SHIMS: [(&str, &str); 2] = [
    ("libcuda.so", "libcuda.so.1"),
    ("libnvidia_ml.so", "libnvidia-ml.so.1"),
];

#[given(expr = "a gpu probe staging dir")]
fn gpu_probe_staging(world: &mut CliWorld) {
    let staging = tempfile::tempdir().expect("create gpu probe staging dir");
    let target = guest_target_triple();
    let out_dir = staging.path().join("target");
    // Two invocations: a `--example` flag narrows cargo's build to the
    // example's package, so the shims build separately.
    let invocations = [
        vec![
            "zigbuild",
            "--release",
            "--target",
            &target,
            "-p",
            "mvm-gpu-shim-core",
            "--example",
            "gpu_guest_probe",
        ],
        vec![
            "zigbuild",
            "--release",
            "--target",
            &target,
            "-p",
            "mvm-gpu-cuda-shim",
            "-p",
            "mvm-gpu-nvml-shim",
        ],
    ];
    for invocation in invocations {
        let mut cmd = Command::new("cargo");
        cmd.args(&invocation)
            .current_dir(workspace_root())
            .env("CARGO_TARGET_DIR", &out_dir)
            .env_remove("RUSTFLAGS")
            .env_remove("RUSTUP_TOOLCHAIN");
        let status = cmd.status().unwrap_or_else(|error| {
            panic!(
                "spawn `cargo {}` (is the pinned zig toolchain on PATH?): {error}",
                invocation.join(" ")
            )
        });
        assert!(
            status.success(),
            "cargo {} exited with {status}",
            invocation.join(" ")
        );
    }
    let release = out_dir.join(target).join("release");
    let bin_dir = staging.path().join("bin");
    std::fs::create_dir_all(&bin_dir).expect("create staging bin dir");
    std::fs::copy(
        release.join("examples/gpu_guest_probe"),
        bin_dir.join("gpu_guest_probe"),
    )
    .expect("copy the guest probe binary into staging");
    for (artifact, soname) in STAGED_SHIMS {
        std::fs::copy(release.join(artifact), bin_dir.join(soname))
            .unwrap_or_else(|error| panic!("copy {artifact} into staging: {error}"));
    }
    world.gpu_probe_staging = Some(staging);
}

/// The guest triple mirrors the host arch: the live lane boots guests for
/// the host's own architecture on both Apple Silicon and x86_64 runners.
fn guest_target_triple() -> &'static str {
    match std::env::consts::ARCH {
        "aarch64" => "aarch64-unknown-linux-gnu",
        "x86_64" => "x86_64-unknown-linux-gnu",
        other => panic!("no guest target triple for host arch {other}"),
    }
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .canonicalize()
        .expect("workspace root must exist")
}

#[when(expr = "I run mvmctl in an isolated live home with a gpu staging mount and {string}")]
fn run_mvmctl_gpu_staging(world: &mut CliWorld, args: String) {
    let staging = world
        .gpu_probe_staging
        .as_ref()
        .expect("the gpu probe staging dir step ran first")
        .path()
        .join("bin");
    let substituted = args.replace(STAGING_PLACEHOLDER, &staging.to_string_lossy());
    run_mvmctl_isolated_live_home_argv(
        world,
        mvm_conformance::doc_examples::tokenize(&substituted),
    );
}

#[then(expr = "the gpu endpoint log for vm {word} records the probe calls")]
fn gpu_endpoint_log_records(world: &mut CliWorld, vm: String) {
    let home = live_home_path(world);
    let state_dir = mvm_core::config::vm_state_dir_at(&home, &vm);
    let log_path = state_dir.join(mvm_vmm::host::gpu_endpoint_spawn::GPU_ENDPOINT_LOG_FILE);
    let log = std::fs::read_to_string(&log_path).unwrap_or_else(|error| {
        panic!("read the gpu endpoint log {}: {error}", log_path.display())
    });
    assert!(
        log.contains("listening on"),
        "gpu endpoint log has no startup line:\n{log}"
    );
    // The probe's call chains: cuInit does not reach the wire (the shim
    // answers it locally), so the witness ops are the ones that must
    // round-trip to the endpoint.
    for op in [
        "device_get_count",
        "device_get_name",
        "nvml_device_get_name",
    ] {
        assert!(
            log.contains(&format!("op={op}")),
            "gpu endpoint log missing op={op}:\n{log}"
        );
    }
}

#[then(expr = "the vm {word} state dir has no gpu endpoint")]
fn vm_has_no_gpu_endpoint(world: &mut CliWorld, vm: String) {
    let home = live_home_path(world);
    let state_dir = mvm_core::config::vm_state_dir_at(&home, &vm);
    for file in [
        mvm_vmm::host::gpu_endpoint_spawn::GPU_ENDPOINT_LOG_FILE,
        mvm_vmm::host::gpu_endpoint_spawn::GPU_ENDPOINT_PID_FILE,
    ] {
        assert!(
            !state_dir.join(file).exists(),
            "{} exists although the launch carried no --gpu",
            state_dir.join(file).display()
        );
    }
}

fn live_home_path(world: &CliWorld) -> &Path {
    world
        .last_live_home
        .as_deref()
        .expect("a live-home mvmctl step ran first")
}
