//! An embedder depends on `mvm-client` alone.
//!
//! Every type a Rust program names to author a workload, launch a machine,
//! drive its guest and read the results is reachable through `mvm_client::`.
//! This file imports nothing else from the workspace, so a re-export that
//! goes missing fails to compile here rather than sending an embedder to a
//! second crate.

use mvm_client::authoring::{
    app, entrypoint_command, local_path, nix_packages, resources, workload,
};
use mvm_client::grants::{CpuGrant, Grants, WallClockGrant};
use mvm_client::guest::{FsEntry, FsEntryKind, FsStat, ProcInfo, ProcStart, ProcWaitEvent};
use mvm_client::{
    AccessMode, EgressGrant, ExecutionPlan, HostPort, LaunchOutcome, LaunchRequest,
    LaunchVolumeSpec, LifecycleMode, LocalBackend, MachineInventoryRecord, MachineSecretRef,
    MachineSpec, MachineState, MvmClient, MvmError, RootfsSource, RootfsSourceParseError,
    SignedExecutionPlan, WorkloadPosture, error_codes,
};

/// The launch request and every part of it are nameable from here.
#[test]
fn a_launch_request_is_built_from_client_types_alone() {
    let image: RootfsSource = "docker.io/library/alpine:3.20"
        .parse()
        .expect("an OCI reference parses");
    let grants = Grants {
        cpu: Some(CpuGrant::Share { millicores: 500 }),
        wall_clock: Some(WallClockGrant::Secs {
            secs: std::num::NonZeroU32::new(60).unwrap(),
        }),
        egress: Some(EgressGrant {
            allow: vec![HostPort::new("api.example.com", 443)],
        }),
        ..Grants::default()
    };
    let request = LaunchRequest::builder(LifecycleMode::Persistent, image)
        .name("embedder")
        .cpus(2)
        .memory_mib(256)
        .grants(grants)
        .volume(LaunchVolumeSpec {
            volume: "work".into(),
            guest_path: "/data/work".into(),
            access: AccessMode::ReadOnly,
        })
        .secret_ref(MachineSecretRef {
            tenant: "local".into(),
            name: "api".into(),
            placeholder_var: Some("API_KEY".into()),
            guest_path: None,
            destinations: vec!["api.example.com".into()],
        })
        .build()
        .expect("a complete request builds");
    assert_eq!(request.name(), Some("embedder"));
    assert_eq!(request.mode(), LifecycleMode::Persistent);
}

/// A refusal carries a stable code an embedder can branch on without a
/// second crate.
#[test]
fn refusals_carry_codes_from_the_client_surface() {
    let image: RootfsSource = "alpine".parse().unwrap();
    let error: MvmError = LaunchRequest::builder(LifecycleMode::Persistent, image)
        .build()
        .expect_err("a persistent machine needs a name");
    assert_eq!(error.code(), error_codes::INVALID_SPEC);
    assert!(!error.retryable());
    let empty: RootfsSourceParseError = "  ".parse::<RootfsSource>().unwrap_err();
    assert_eq!(empty, RootfsSourceParseError::Empty);
}

/// The authoring surface builds a workload through the same dependency.
#[test]
fn a_workload_is_authored_through_the_client() {
    let built = workload("embedder")
        .app(
            app("hello")
                .source(local_path("."))
                .image(nix_packages(["bash"]))
                .entrypoint(entrypoint_command(["bash", "-lc", "echo hi"]))
                .resources(resources(1, 256, 512))
                .build()
                .expect("the app builds"),
        )
        .build()
        .expect("the workload builds");
    assert_eq!(built.id, "embedder");
}

/// Result, inventory, guest and plan types are nameable too. A function that
/// takes each one is enough: it does not compile if one goes missing.
#[test]
fn result_and_payload_types_are_nameable() {
    fn _launched(_: &LaunchOutcome, _: &MachineState, _: &MachineSpec) {}
    fn _listed(record: &MachineInventoryRecord) -> WorkloadPosture {
        record.build_mode
    }
    fn _guest(_: ProcStart, _: &ProcWaitEvent, _: &ProcInfo, _: &FsEntry, _: &FsStat) {}
    fn _plans(_: &ExecutionPlan, _: &SignedExecutionPlan) {}
    fn _client(_: &dyn MvmClient, _: &LocalBackend) {}
    assert_eq!(FsEntryKind::Dir, FsEntryKind::Dir);
}
