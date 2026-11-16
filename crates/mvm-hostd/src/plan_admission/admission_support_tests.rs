#![cfg(test)]

use super::test_support::*;
use super::*;

fn plan_pinning(kernel_sha256: Option<&str>) -> ExecutionPlan {
    let mut plan = mvm_core::plan::test_support::PlanFixture::new().build();
    plan.environment = kernel_sha256.map(|k| mvm_core::plan::EnvironmentRef {
        kernel_sha256: k.to_string(),
    });
    plan
}

fn write_kernel(dir: &std::path::Path, bytes: &[u8]) -> std::path::PathBuf {
    let p = dir.join("vmlinux");
    std::fs::write(&p, bytes).expect("write kernel fixture");
    p
}

/// The pinned kernel is the one on disk: the boot proceeds.
#[test]
fn matching_kernel_digest_is_admitted() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let kernel = write_kernel(tmp.path(), b"workload-kernel");
    let sha = mvm_core::crypto::image_verify::sha256_file(&kernel).expect("hash");
    enforce_admitted_environment(Some(kernel.as_path()), &plan_pinning(Some(&sha)))
        .expect("matching kernel must be admitted");
}

/// A different kernel than the plan pinned is refused: same plan, same
/// image, a kernel swapped underneath — a substitution that would be
/// invisible if nothing in the plan described the environment.
#[test]
fn substituted_kernel_is_refused() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let kernel = write_kernel(tmp.path(), b"workload-kernel");
    let sha = mvm_core::crypto::image_verify::sha256_file(&kernel).expect("hash");
    std::fs::write(&kernel, b"a-general-purpose-kernel").expect("swap kernel");

    let err = enforce_admitted_environment(Some(kernel.as_path()), &plan_pinning(Some(&sha)))
        .expect_err("a substituted kernel must be refused");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("admitted-environment mismatch"),
        "error must name the mismatch, got: {msg}"
    );
}

/// Dropping the kernel path must not be a way around the pin.
#[test]
fn pinned_plan_with_no_kernel_path_is_refused() {
    let err = enforce_admitted_environment(None, &plan_pinning(Some(&"a".repeat(64))))
        .expect_err("a pinned plan with no kernel path must be refused");
    assert!(format!("{err:#}").contains("supplies no kernel path"));
}

/// Plans that pin nothing still boot — every plan written before the field
/// existed, and backends that carry their own bundled kernel.
#[test]
fn unpinned_plan_is_unaffected() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let kernel = write_kernel(tmp.path(), b"whatever");
    enforce_admitted_environment(Some(kernel.as_path()), &plan_pinning(None))
        .expect("an unpinned plan must be unaffected");
    enforce_admitted_environment(None, &plan_pinning(None))
        .expect("an unpinned plan with no kernel must be unaffected");
}

/// A musl guest cannot load the glibc cdylib, and the failure would
/// otherwise land inside the guest at `dlopen` time as a relocation error
/// naming a symbol the operator never heard of. Refuse on the host, where
/// the cause can be named.
/// Stage a rootfs whose `mvm-meta.json` records `libc`, and hand back the
/// rootfs path the launch would boot.
fn rootfs_recording_libc(dir: &std::path::Path, libc: GuestLibc) -> String {
    let sidecar =
        mvm_build::builder_vm::GuestSidecar::for_oci_run("fixture", false, false).with_libc(libc);
    sidecar.write_to_dir(dir).expect("write mvm-meta.json");
    dir.join("rootfs.ext4").to_string_lossy().into_owned()
}

/// The launch-shaped entry point reads the image's libc off the rootfs
/// rather than taking it on trust, so a caller cannot pass a libc that
/// disagrees with the image it is about to boot.
#[test]
fn the_launch_gate_reads_the_libc_off_the_rootfs_it_is_given() {
    let dir = tempfile::tempdir().expect("tempdir");
    let plan = plan_binding(&["host.kv.v1"]);

    let musl_rootfs = rootfs_recording_libc(dir.path(), GuestLibc::Musl);
    enforce_sdk_sidecar_for_launch(
        &musl_rootfs,
        &[sdk_sidecar_volume_for(GuestLibc::Musl)],
        &plan,
    )
    .expect("a musl image may load the musl sidecar");

    let err = enforce_sdk_sidecar_for_launch(
        &musl_rootfs,
        &[sdk_sidecar_volume_for(GuestLibc::Glibc)],
        &plan,
    )
    .expect_err("a musl image must not receive the glibc sidecar");
    let msg = err.to_string();
    assert!(msg.contains("musl") && msg.contains("glibc"), "{msg}");
}

/// A rootfs with no sidecar beside it records nothing, and an image whose
/// libc cannot be established is refused rather than assumed loadable.
#[test]
fn the_launch_gate_refuses_an_image_recording_no_libc() {
    let dir = tempfile::tempdir().expect("tempdir");
    let plan = plan_binding(&["host.kv.v1"]);
    let rootfs = dir
        .path()
        .join("rootfs.ext4")
        .to_string_lossy()
        .into_owned();

    let err =
        enforce_sdk_sidecar_for_launch(&rootfs, &[sdk_sidecar_volume_for(GuestLibc::Musl)], &plan)
            .expect_err("an image of unknown libc must not receive a sidecar");

    assert!(
        err.to_string().contains("records no libc"),
        "the refusal must say the image is the unknown side: {err}"
    );
}

/// A sidecar whose path carries no libc segment cannot be identified, and
/// an unidentifiable variant is refused rather than assumed to match. Any
/// path this layout did not write reads that way — the check is on what the
/// launch config presents, not on where it came from.
#[test]
fn a_sidecar_filed_under_no_libc_is_refused() {
    use mvm_core::vm_backend::{VmVolume, VmVolumeKind};
    let plan = plan_binding(&["host.kv.v1"]);
    let unkeyed = VmVolume {
        host: "/cache/sdk-sidecar/1.2.3/aarch64/sdk.ext4".into(),
        guest: mvm_core::plan::SDK_SIDECAR_GUEST_PATH.into(),
        read_only: true,
        kind: VmVolumeKind::Disk,
        ..Default::default()
    };

    let err = enforce_sdk_sidecar_attachment(&[unkeyed], &plan, GuestLibc::Musl)
        .expect_err("a sidecar of unknown variant must not be attached");

    assert!(
        err.to_string().contains("`mvmctl bootstrap`"),
        "the refusal must say how to repopulate the cache: {err}"
    );
}

#[test]
fn a_sidecar_the_guest_cannot_load_is_refused_before_boot() {
    let plan = plan_binding(&["host.kv.v1"]);
    let err = enforce_sdk_sidecar_attachment(
        &[sdk_sidecar_volume_for(GuestLibc::Glibc)],
        &plan,
        GuestLibc::Musl,
    )
    .expect_err("a musl image must not receive the glibc sidecar");
    let msg = err.to_string();
    assert!(msg.contains("musl"), "must name the image's libc: {msg}");
    assert!(msg.contains("glibc"), "must name the sidecar's libc: {msg}");
    assert!(
        msg.contains("host.kv.v1"),
        "must name the binding that asked for it: {msg}"
    );
}

/// Unknown is the arm a permissive default would wave through. It covers an
/// image materialized before mvm recorded the libc, so the message has to
/// say how to make it known rather than just refusing.
#[test]
fn an_unknown_libc_is_refused_and_says_how_to_resolve_it() {
    let plan = plan_binding(&["host.kv.v1"]);
    let err = enforce_sdk_sidecar_attachment(
        &[sdk_sidecar_volume()],
        &plan,
        mvm_build::guest_libc::GuestLibc::Unknown,
    )
    .expect_err("an unrecorded libc must not be attached on a guess");
    let msg = err.to_string();
    assert!(
        msg.contains("re-pull or rebuild"),
        "must name the remedy: {msg}"
    );
}

/// The libc gate must sit behind the binding check: a workload that binds
/// no SDK service carries no sidecar, so its libc is irrelevant and must
/// not refuse the boot.
#[test]
fn an_unbound_workload_is_unaffected_by_its_libc() {
    let plan = plan_binding(&[]);
    assert!(
        enforce_sdk_sidecar_attachment(&[], &plan, mvm_build::guest_libc::GuestLibc::Unknown)
            .is_ok()
    );
}

/// A workload that binds no SDK host service gets no sidecar, and nothing
/// may attach one behind the plan's back.
#[test]
fn no_sdk_binding_means_no_sidecar_attachment() {
    let plan = plan_binding(&[]);
    assert!(enforce_sdk_sidecar_attachment(&[], &plan, LOADABLE_LIBC).is_ok());

    let err = enforce_sdk_sidecar_attachment(&[sdk_sidecar_volume()], &plan, LOADABLE_LIBC)
        .expect_err("an unauthorized sidecar must be refused");
    let msg = err.to_string();
    assert!(msg.contains("binds no SDK host service"), "{msg}");
}

/// An unrelated host-service binding is not an SDK binding: it must not pull
/// the glibc sidecar into an ordinary workload.
#[test]
fn unrelated_service_binding_does_not_require_the_sidecar() {
    let plan = plan_binding(&["broker.v1", "host.other.v1"]);
    assert!(enforce_sdk_sidecar_attachment(&[], &plan, LOADABLE_LIBC).is_ok());
    assert!(enforce_sdk_sidecar_attachment(&[sdk_sidecar_volume()], &plan, LOADABLE_LIBC).is_err());
}

/// A bound SDK host service with the sidecar attached read-only is admitted.
#[test]
fn sdk_binding_with_a_read_only_sidecar_is_admitted() {
    for service in mvm_core::plan::SDK_HOST_SERVICES {
        let plan = plan_binding(&[service]);
        assert!(
            enforce_sdk_sidecar_attachment(&[sdk_sidecar_volume()], &plan, LOADABLE_LIBC).is_ok(),
            "{service} bound + sidecar attached read-only must be admitted"
        );
    }
}

/// Wasm has neither block devices nor a native dynamic loader, so the
/// ext4-hosted SDK cdylib cannot reach that tier. Refuse in terms of the
/// requested service before the backend leaks a synthetic disk-volume
/// implementation detail.
#[test]
fn wasm_sdk_binding_is_refused_at_the_delivery_seam() {
    let plan = plan_binding(&["host.time.v1"]);
    let err =
        enforce_sdk_sidecar_backend_compatibility(mvm_core::vm_backend::BackendKind::Wasm, &plan)
            .expect_err("wasm cannot receive or load the SDK sidecar");
    let msg = err.to_string();
    assert!(msg.contains("wasm"), "{msg}");
    assert!(msg.contains("host.time.v1"), "{msg}");
    assert!(msg.contains("SDK host service"), "{msg}");
    assert!(!msg.contains("DiskVolumeNotSupported"), "{msg}");
}

#[test]
fn microvm_backend_keeps_the_sdk_sidecar_delivery_path() {
    let plan = plan_binding(&["host.time.v1"]);
    assert!(
        enforce_sdk_sidecar_backend_compatibility(
            mvm_core::vm_backend::BackendKind::Firecracker,
            &plan,
        )
        .is_ok()
    );
}

#[test]
fn direct_protocol_binding_requires_no_sidecar_and_refuses_a_stray_one() {
    let mut plan = plan_binding(&["host.kv.v1"]);
    plan.sdk_uses_sidecar = false;

    assert!(
        enforce_sdk_sidecar_backend_compatibility(mvm_core::vm_backend::BackendKind::Wasm, &plan,)
            .is_ok()
    );
    assert!(enforce_sdk_sidecar_attachment(&[], &plan, LOADABLE_LIBC).is_ok());

    let err = enforce_sdk_sidecar_attachment(&[sdk_sidecar_volume()], &plan, LOADABLE_LIBC)
        .expect_err("a direct-protocol plan must refuse a stray sidecar");
    assert!(err.to_string().contains("sdk_uses_sidecar=false"), "{err}");
}

/// A bound SDK host service with no sidecar attachment fails closed, and the
/// message names the binding that demanded it without leaking file bytes.
#[test]
fn sdk_binding_without_the_sidecar_fails_closed() {
    let plan = plan_binding(&["host.kv.v1"]);
    let err = enforce_sdk_sidecar_attachment(&[], &plan, LOADABLE_LIBC)
        .expect_err("a required-but-absent sidecar must refuse the launch");
    let msg = err.to_string();
    assert!(msg.contains("host.kv.v1"), "{msg}");
    assert!(
        msg.contains(mvm_core::plan::SDK_SIDECAR_GUEST_PATH),
        "{msg}"
    );
}

/// The sidecar is read-only by contract: a writable or directory-share
/// attachment at the sidecar mount point is a different, unadmitted shape.
#[test]
fn a_writable_or_dir_share_sidecar_fails_closed() {
    let plan = plan_binding(&["host.audit.v1"]);

    let writable = mvm_core::vm_backend::VmVolume {
        read_only: false,
        ..sdk_sidecar_volume()
    };
    let err =
        enforce_sdk_sidecar_attachment(&[writable], &plan, LOADABLE_LIBC).expect_err("rw refused");
    assert!(err.to_string().contains("read-only"), "{err}");

    let share = mvm_core::vm_backend::VmVolume {
        materialized_image: Some("/state/mount.ext4".to_string()),
        ..sdk_sidecar_volume()
    };
    let err =
        enforce_sdk_sidecar_attachment(&[share], &plan, LOADABLE_LIBC).expect_err("share refused");
    assert!(err.to_string().contains("disk image"), "{err}");
}

/// Two attachments racing for the same mount point is ambiguous — refuse
/// rather than let mount order decide which cdylib the workload loads.
#[test]
fn duplicate_sidecar_attachments_fail_closed() {
    let plan = plan_binding(&["host.time.v1"]);
    let dup = [sdk_sidecar_volume(), sdk_sidecar_volume()];
    let err =
        enforce_sdk_sidecar_attachment(&dup, &plan, LOADABLE_LIBC).expect_err("duplicates refused");
    assert!(err.to_string().contains("exactly one"), "{err}");
}

/// Unrelated volumes are untouched by the sidecar gate in either direction.
#[test]
fn unrelated_volumes_are_ignored_by_the_sidecar_gate() {
    use mvm_core::vm_backend::{VmVolume, VmVolumeKind};
    let other = VmVolume {
        host: "/h/data.img".into(),
        guest: "/data".into(),
        read_only: false,
        kind: VmVolumeKind::Disk,
        ..Default::default()
    };
    assert!(
        enforce_sdk_sidecar_attachment(
            std::slice::from_ref(&other),
            &plan_binding(&[]),
            LOADABLE_LIBC
        )
        .is_ok()
    );
    let bound = plan_binding(&["host.cost.v1"]);
    assert!(
        enforce_sdk_sidecar_attachment(
            &[other.clone(), sdk_sidecar_volume()],
            &bound,
            LOADABLE_LIBC
        )
        .is_ok()
    );
    assert!(
        enforce_sdk_sidecar_attachment(std::slice::from_ref(&other), &bound, LOADABLE_LIBC)
            .is_err(),
        "an unrelated volume must not satisfy the sidecar requirement"
    );
}

/// The signed plan round-trips its service bindings, so the gate decides on
/// the same bytes the signature covers.
#[test]
fn service_bindings_survive_plan_serialization() {
    let plan = plan_binding(&["host.audit.v1", "broker.v1"]);
    let json = serde_json::to_string(&plan).expect("plan serializes");
    let back: ExecutionPlan = serde_json::from_str(&json).expect("plan round-trips");
    assert_eq!(back.services, plan.services);
    assert!(mvm_core::plan::sdk_sidecar_required(&back));
    assert!(enforce_sdk_sidecar_attachment(&[sdk_sidecar_volume()], &back, LOADABLE_LIBC).is_ok());
}

/// An empty builder must refuse to finish, naming the first
/// required field it is missing — never substituting a default.
#[test]
fn an_empty_builder_names_the_first_missing_field() {
    let Err(err) = AdmitAndStartParams::builder().build() else {
        panic!("an empty AdmitAndStartParams builder must not build");
    };
    assert_eq!(
        err,
        BuilderError::missing("AdmitAndStartParams", "synthesis")
    );
}

/// The launch decision record names the plan it launched — in the
/// scenario it describes and in the attestation it binds to.
///
/// Deleting either `plan_id` leaves a record that says a workload was
/// launched but not which signed plan authorized it, and the scenario's
/// `plan_id` is part of the record's content address, so dropping it also
/// re-addresses the decision. Both deletions survived mutation because
/// nothing read the fields back.
#[test]
fn a_launch_decision_record_binds_the_plan_it_launched() {
    let plan = mvm_core::plan::test_support::PlanFixture::new()
        .plan_id("plan-under-launch")
        .build();

    let record = launch_decision_record(&plan, "firecracker");

    assert_eq!(record.category, DecisionCategory::Launch);
    assert_eq!(
        record.scenario.plan_id.as_deref(),
        Some("plan-under-launch"),
        "the scenario must name the launched plan"
    );
    assert_eq!(
        record.attestation.plan_id.as_deref(),
        Some("plan-under-launch"),
        "the attestation binding must name the launched plan"
    );
}
