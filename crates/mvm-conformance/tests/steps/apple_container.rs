//! Steps for the Apple Container backend's hermetic contracts: artifact
//! resolution fails closed with a typed, hint-carrying error; a cached
//! kernel is trusted only with a matching digest sidecar; auto-select
//! never lands on the backend; and the launch-config kernel substitution
//! replaces exactly the kernel path. These drive the real backend code and
//! never start a VM, so they run in the normal hermetic BDD gate.

use cucumber::{given, then, when};
use mvm_core::vm_backend::VmBackend as _;
use mvm_core::vm_backend::VmStartConfig;
use mvm_runtime::apple_container_backend::{
    AppleContainerBackend, AppleContainerError, kernel_override_config,
};

use crate::world::{CliWorld, MvmHomeGuard};

#[given("an isolated mvm home for the apple-container backend")]
fn isolated_home(world: &mut CliWorld) {
    let home = tempfile::tempdir().expect("create scenario home");
    world.mvm_home_guard = Some(MvmHomeGuard::new(home.path()));
    world.isolated_home = Some(home);
}

#[when("I start the apple-container backend with a minimal config")]
fn start_minimal(world: &mut CliWorld) {
    let err = AppleContainerBackend::new()
        .start(&VmStartConfig::default())
        .expect_err("start must fail with no kernel in the isolated cache");
    let AppleContainerError::ArtifactMissing { what, path, hint } = err
        .downcast_ref::<AppleContainerError>()
        .expect("the failure must be the typed artifact error")
    else {
        panic!("the failure must be the artifact-missing variant");
    };
    world.apple_container_error = Some((what.to_string(), path.clone(), hint.to_string()));
}

#[then("the start fails with a missing-artifact error naming the container kernel")]
fn error_names_kernel(world: &mut CliWorld) {
    let (what, _, _) = world
        .apple_container_error
        .as_ref()
        .expect("a prior step must capture the start failure");
    assert!(
        what.contains("kernel"),
        "the artifact error must name the container kernel: {what}"
    );
}

#[then(expr = "the error names the artifact cache path under {string}")]
fn error_names_cache_path(world: &mut CliWorld, segment: String) {
    let (_, path, _) = world
        .apple_container_error
        .as_ref()
        .expect("a prior step must capture the start failure");
    assert!(
        path.contains(&segment),
        "the artifact error must name a path under {segment:?}: {path}"
    );
}

#[then("the error carries the fetch hint")]
fn error_carries_hint(world: &mut CliWorld) {
    let (_, _, hint) = world
        .apple_container_error
        .as_ref()
        .expect("a prior step must capture the start failure");
    assert!(
        hint.contains("container kernel"),
        "the hint must say where the kernel comes from: {hint}"
    );
}

#[when("I ask for the auto-selected backend")]
fn auto_select(world: &mut CliWorld) {
    let kind = mvm_runtime::backend::AnyBackend::auto_select().kind();
    world.auto_selected_kind = Some(format!("{kind:?}"));
}

#[then("the selected backend is not apple-container")]
fn not_apple_container(world: &mut CliWorld) {
    let kind = world
        .auto_selected_kind
        .as_deref()
        .expect("a prior step must resolve the auto-selected backend");
    assert_ne!(
        kind, "AppleContainer",
        "auto-select must never land on the opt-in backend"
    );
}

/// Write `bytes` as the cached kernel, plus `sidecar` as its
/// `vmlinux.blake3` pin when given, into the isolated home's artifact dir.
fn stage_kernel(world: &CliWorld, bytes: &[u8], sidecar: Option<&str>) {
    let home = world
        .isolated_home
        .as_ref()
        .expect("a prior step must isolate the mvm home");
    let dir = home
        .path()
        .join("cache")
        .join(mvm_runtime::apple_container::artifacts::ARTIFACT_DIR_NAME);
    std::fs::create_dir_all(&dir).expect("create artifact dir");
    std::fs::write(
        dir.join(mvm_runtime::apple_container::artifacts::KERNEL_FILE_NAME),
        bytes,
    )
    .expect("write kernel");
    if let Some(sidecar) = sidecar {
        std::fs::write(
            dir.join(mvm_runtime::apple_container::artifacts::KERNEL_DIGEST_FILE_NAME),
            sidecar,
        )
        .expect("write digest sidecar");
    }
}

/// Lowercase-hex BLAKE3 of `bytes`, for a sidecar that honestly pins the
/// fake kernel it sits beside.
fn blake3_hex(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

#[given("an apple-container kernel is cached in the isolated home")]
fn cache_kernel(world: &mut CliWorld) {
    // The fake kernel is staged with the digest sidecar a real operator
    // would record: without the matching pin the artifact is untrusted.
    let bytes = b"fake-kernel-bytes";
    let sidecar = blake3_hex(bytes);
    stage_kernel(world, bytes, Some(&sidecar));
}

#[given("an apple-container kernel is cached with a sidecar that does not match its bytes")]
fn cache_kernel_tampered(world: &mut CliWorld) {
    // A well-formed pin for different bytes — the attestation must reject
    // the kernel even though the sidecar parses.
    let wrong = blake3_hex(b"different-kernel-bytes");
    stage_kernel(world, b"fake-kernel-bytes", Some(&wrong));
}

#[when("I start the apple-container backend and capture the attestation failure")]
fn start_capture_attestation_failure(world: &mut CliWorld) {
    let err = AppleContainerBackend::new()
        .start(&VmStartConfig::default())
        .expect_err("start must fail closed on a kernel that fails attestation");
    let AppleContainerError::ArtifactUntrusted { path, reason, hint } = err
        .downcast_ref::<AppleContainerError>()
        .expect("the failure must be the typed untrusted-artifact error")
    else {
        panic!("the failure must be the untrusted-artifact variant");
    };
    world.apple_container_untrusted = Some((reason.clone(), path.clone(), (*hint).to_string()));
}

#[then("the failure is the untrusted-artifact digest error")]
fn failure_is_untrusted(world: &mut CliWorld) {
    let (reason, path, hint) = world
        .apple_container_untrusted
        .as_ref()
        .expect("a prior step must capture the attestation failure");
    assert!(
        reason.contains("do not match the pinned digest"),
        "the error must say the bytes failed attestation: {reason}"
    );
    assert!(
        path.contains("apple-container"),
        "the error must name the cached kernel path: {path}"
    );
    assert!(
        hint.contains("b3sum"),
        "the hint must say how to record the digest: {hint}"
    );
}

#[then("the failure names the pinned and actual digests")]
fn failure_names_digests(world: &mut CliWorld) {
    let (reason, _, _) = world
        .apple_container_untrusted
        .as_ref()
        .expect("a prior step must capture the attestation failure");
    let pinned = blake3_hex(b"different-kernel-bytes");
    let actual = blake3_hex(b"fake-kernel-bytes");
    assert!(
        reason.contains(&pinned),
        "the error must name the pinned digest {pinned}: {reason}"
    );
    assert!(
        reason.contains(&actual),
        "the error must name the actual digest {actual}: {reason}"
    );
}

#[when("I apply the backend's kernel substitution to a caller config")]
fn apply_substitution(world: &mut CliWorld) {
    let kernel =
        mvm_runtime::apple_container::artifacts::resolve().expect("the cached kernel must resolve");
    let caller = VmStartConfig {
        name: "bdd-apple-container".to_string(),
        kernel_path: Some("/caller/supplied/Image".to_string()),
        ..Default::default()
    };
    let overridden = kernel_override_config(&caller, &kernel);
    world.overridden_kernel_path = overridden.kernel_path;
}

#[then("the kernel path is the cached apple-container kernel, not the caller's kernel")]
fn kernel_is_the_cached_one(world: &mut CliWorld) {
    let kernel_path = world
        .overridden_kernel_path
        .as_deref()
        .expect("a prior step must apply the substitution");
    assert!(
        kernel_path.contains("apple-container"),
        "the kernel path must be the cached container kernel: {kernel_path}"
    );
    assert_ne!(
        kernel_path, "/caller/supplied/Image",
        "a caller-supplied kernel must never win over the backend's own"
    );
}

#[when("I ask the admitted workload funnel for the apple-container backend")]
fn admitted_funnel(world: &mut CliWorld) {
    // The funnel boundary is pure permission — it matches the backend kind
    // and never probes the artifact cache, so no isolated home is needed.
    let backend = mvm_runtime::backend::AnyBackend::from_hypervisor("apple-container");
    let workload = mvm_runtime::workload_backend::require_workload_backend(&backend)
        .expect("the admitted funnel must accept the apple-container backend");
    world.apple_container_workload_kind = Some(format!("{:?}", workload.kind()));
}

#[then("the funnel accepts it as a workload backend of kind apple-container")]
fn funnel_accepts(world: &mut CliWorld) {
    let kind = world
        .apple_container_workload_kind
        .as_deref()
        .expect("a prior step must ask the admitted funnel");
    assert_eq!(
        kind, "AppleContainer",
        "the funnel must return the backend under its own kind"
    );
}
