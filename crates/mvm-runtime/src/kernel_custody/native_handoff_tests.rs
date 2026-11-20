//! Kernel handoff only: synthetic runtime members do not prove a release runtime.
use super::*;
use mvm_core::canonical_linux::PreparedCanonicalLinux;
use mvm_core::util::test_env::TestEnv;
use std::sync::Arc;

#[path = "../../../mvm-core/src/image_set/fixtures/prepared_owner.rs"]
mod prepared_owner;
use prepared_owner::prepared_owner;

#[test]
#[ignore = "actual pinned public kernel required; no VM, download, or native runtime authentication"]
fn exact_final_config_and_physical_recipe_are_checked_before_native_effects() {
    // Isolate process-wide payload registration from every other test.
    const MARKER: &str = "MVM_KERNEL_HANDOFF_UNIT_CHILD";
    const NAME: &str = "kernel_custody::native_handoff_tests::exact_final_config_and_physical_recipe_are_checked_before_native_effects";
    if std::env::var_os(MARKER).is_none() {
        let output = mvm_core::env_hygiene::helper_command(std::env::current_exe().unwrap())
            .args(["--exact", NAME, "--ignored", "--nocapture"])
            .env(MARKER, "1")
            .env(
                "MVM_TEST_CANONICAL_KERNEL",
                std::env::var_os("MVM_TEST_CANONICAL_KERNEL").unwrap(),
            )
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
        return;
    }
    struct Payload(std::path::PathBuf);
    impl mvm_build::builder_boot::BootPayloadSource for Payload {
        fn boot_payload(
            &self,
        ) -> std::result::Result<
            mvm_build::builder_boot::BuilderBootPayload,
            mvm_build::builder_boot::BootPayloadError,
        > {
            mvm_build::builder_boot::BuilderBootPayload::builder()
                .host_bin_dir(&self.0)
                .build()
        }
    }
    let payload = tempfile::tempdir().unwrap();
    // Logical ABI fixture only. None of these placeholder helpers is executed.
    for name in mvm_build::host_payload_manifest::host_binary_names() {
        std::fs::write(payload.path().join(name), name.as_bytes()).unwrap();
    }
    mvm_build::builder_boot::register_boot_payload_source(Box::new(Payload(payload.path().into())));
    let home = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.isolate_mvm_home(home.path());
    let owner = prepared_owner(BackendKind::Hvf);
    let mut config = VmStartConfig {
        name: "kernel-physical-unit".into(),
        ..Default::default()
    };
    owner.bind_to_config(&mut config).unwrap();
    let lease = RuntimeLifecycleLease::acquire(&config.name).unwrap();
    assert!(!has_retained_kernel(&lease).unwrap());
    assert!(KernelBoundLaunch::bind(config.clone(), BackendKind::Qemu, &lease).is_err());
    let bound = KernelBoundLaunch::bind(config, BackendKind::Hvf, &lease).unwrap();
    assert!(Arc::ptr_eq(
        bound.config().canonical_kernel.as_ref().unwrap(),
        &owner
    ));
    let mut spec = VmmSpec {
        name: bound.config().name.clone(),
        kernel: KernelImage::Path(owner.kernel_path()),
        initramfs: None,
        cmdline: String::new(),
        vcpus: 1,
        cpu_grant: None,
        allowed_cpus: None,
        memory_mib: 512,
        mem_initial_mib: None,
        blocks: vec![],
        vsock: vec![],
        console: mvm_vmm::driver::spec::ConsoleCapture {
            log_path: home.path().join("unused.log"),
        },
        shares: vec![],
        trusted_builder: false,
        builder_egress_endpoint: None,
        plan_binding: None,
    };
    bound.before_boot(&spec).unwrap();
    spec.kernel = KernelImage::Path(home.path().join("substitute"));
    assert!(bound.before_boot(&spec).is_err());
    spec.kernel = KernelImage::Path(owner.kernel_path());
    spec.name = "wrong-vm".into();
    assert!(bound.before_boot(&spec).is_err());
    spec.name = bound.config().name.clone();
    bound.before_boot(&spec).unwrap();
    // Replace the original pathname AFTER the last preflight. The descriptor
    // handed to the native loader still owns the already verified clone.
    std::fs::remove_file(owner.kernel_path()).unwrap();
    std::fs::write(owner.kernel_path(), b"replacement after before_boot").unwrap();
    let held = bound.kernel.as_ref().unwrap();
    assert_eq!(
        mvm_core::crypto::image_verify::sha256_reader(held.file().try_clone().unwrap()).unwrap(),
        owner.kernel_sha256(),
    );
    assert!(bound.before_boot(&spec).is_err());
    let generation = owner.generation_dir().to_owned();
    drop(bound);
    drop(owner);
    assert!(generation.exists());
    assert!(has_retained_kernel(&lease).unwrap());
    assert!(
        read_record(&lease.canonical_kernel_record())
            .unwrap()
            .instance
            .is_none()
    );
    // No driver was called: this is failed-start retention, not a boot/stop witness.
}

/// A driver handle whose process-table witness and HVF witness both answer.
/// The Firecracker observation must bind the process, never the instance.
#[cfg(target_os = "linux")]
struct DualWitnessVm {
    id: mvm_core::vm_backend::VmId,
    process: Option<mvm_vmm::host::process_identity::ProcessIdentity>,
}

#[cfg(target_os = "linux")]
impl mvm_vmm::driver::traits::RunningVm for DualWitnessVm {
    fn id(&self) -> &mvm_core::vm_backend::VmId {
        &self.id
    }
    fn wait(&self) -> Result<mvm_core::vm_backend::VmExitStatus> {
        unreachable!("an observation fixture never waits")
    }
    fn kill(&self) -> Result<()> {
        unreachable!("an observation fixture never kills")
    }
    fn pause(&self) -> Result<()> {
        unreachable!("an observation fixture never pauses")
    }
    fn resume(&self) -> Result<()> {
        unreachable!("an observation fixture never resumes")
    }
    fn status(&self) -> Result<mvm_core::vm_backend::VmStatus> {
        unreachable!("an observation fixture never reports status")
    }
    fn vsock_connect(
        &self,
        _guest_port: u32,
    ) -> Result<Box<dyn mvm_vmm::driver::traits::DuplexStream>> {
        unreachable!("an observation fixture never dials")
    }
    fn process_identity(&self) -> Result<Option<mvm_vmm::host::process_identity::ProcessIdentity>> {
        Ok(self.process.clone())
    }
    fn authenticated_hvf_instance(
        &self,
    ) -> Result<Option<mvm_core::protocol::hvf_control::HvfInstance>> {
        Ok(Some(mvm_core::protocol::hvf_control::HvfInstance {
            vm_id: self.id.0.clone(),
            boot_nonce: [7; 32],
        }))
    }
}

#[cfg(target_os = "linux")]
fn bound_firecracker_launch(
    name: &str,
) -> (
    Arc<PreparedCanonicalLinux>,
    KernelBoundLaunch,
    RuntimeLifecycleLease,
) {
    let owner = prepared_owner(BackendKind::Firecracker);
    let mut config = VmStartConfig {
        name: name.into(),
        ..Default::default()
    };
    owner.bind_to_config(&mut config).unwrap();
    let lease = RuntimeLifecycleLease::acquire(&config.name).unwrap();
    let bound = KernelBoundLaunch::bind(config, BackendKind::Firecracker, &lease).unwrap();
    (owner, bound, lease)
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires the actual pinned public kernel in MVM_TEST_CANONICAL_KERNEL; boots no VM"]
fn canonical_kernel_publication_requires_live_owner_and_retires_claims() {
    use crate::trusted_snapshot_service::{BootInputBudget, TrustedSnapshotService};
    use mvm_fs::snapshot_store::SnapshotId;
    use mvm_fs::trusted_snapshot::UnsupportedTrustedSnapshotBackend;

    let home = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.isolate_mvm_home(home.path());
    let owner = prepared_owner(BackendKind::Firecracker);
    let mut config = VmStartConfig {
        name: "sealed-kernel-unit".into(),
        ..Default::default()
    };
    owner.bind_to_config(&mut config).unwrap();
    let size = owner.kernel_declaration().size;
    let backend = Arc::new(UnsupportedTrustedSnapshotBackend);
    let service = TrustedSnapshotService::with_boot_input_budget(
        backend.clone(),
        BootInputBudget::new(size, 1).unwrap(),
    );
    let id = SnapshotId::new("signed-kernel");
    let handle = service
        .publish_canonical_kernel(id.clone(), &config)
        .unwrap();
    assert!(
        service
            .publish_canonical_kernel(id.clone(), &config)
            .is_err()
    );
    assert!(
        service
            .publish_canonical_kernel(SnapshotId::new("over-budget"), &config)
            .is_err()
    );
    let mut wrong = config.clone();
    wrong.name = "another-vm".into();
    assert!(service.claim_boot_input(&handle, &wrong).is_err());
    let other = TrustedSnapshotService::with_boot_input_budget(
        backend,
        BootInputBudget::new(size, 1).unwrap(),
    );
    assert!(other.claim_boot_input(&handle, &config).is_err());
    let lease = service.claim_boot_input(&handle, &config).unwrap();
    let mut first_byte = [0];
    lease.read_exact_at(&mut first_byte, 0).unwrap();
    let original = owner.kernel_file().unwrap();
    let mut expected = [0];
    std::os::unix::fs::FileExt::read_exact_at(&original, &mut expected, 0).unwrap();
    assert_eq!(first_byte, expected);
    assert!(lease.read_exact_at(&mut first_byte, size).is_err());
    assert!(service.remove_boot_input(&handle).is_err());
    assert!(service.claim_boot_input(&handle, &config).is_err());
    drop(lease);
    service.remove_boot_input(&handle).unwrap();
    let new_handle = service.publish_canonical_kernel(id, &config).unwrap();
    assert_ne!(handle, new_handle);
    assert!(service.claim_boot_input(&handle, &config).is_err());
    service.remove_boot_input(&new_handle).unwrap();
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires the actual pinned public kernel in MVM_TEST_CANONICAL_KERNEL; boots no VM"]
fn observe_booted_binds_the_firecracker_process_witness_not_an_hvf_instance() {
    let home = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.isolate_mvm_home(home.path());

    // A live process stands in for the Firecracker the driver just observed.
    let mut child = std::process::Command::new("sleep")
        .arg("60")
        .spawn()
        .unwrap();

    let name = "kernel-fc-dispatch-unit";
    let (owner, bound, lease) = bound_firecracker_launch(name);
    let identity =
        mvm_vmm::host::process_identity::ProcessIdentity::capture(name, child.id()).unwrap();
    let vm = DualWitnessVm {
        id: mvm_core::vm_backend::VmId(name.into()),
        process: Some(identity.clone()),
    };
    bound.observe_booted(&vm).unwrap();
    let record = read_record(&lease.canonical_kernel_record()).unwrap();
    assert_eq!(record.process.as_ref(), Some(&identity));
    assert!(
        record.instance.is_none(),
        "the Firecracker branch must bind the process witness, never an HVF instance"
    );
    drop(bound);
    drop(owner);
    drop(lease);

    // A started VM with no observable process retains the generation, keeps
    // the record unbound, and blocks the name against reuse.
    let name = "kernel-fc-dispatch-unobserved";
    let (owner, bound, lease) = bound_firecracker_launch(name);
    let vm = DualWitnessVm {
        id: mvm_core::vm_backend::VmId(name.into()),
        process: None,
    };
    let error = bound.observe_booted(&vm).unwrap_err();
    assert!(
        format!("{error:#}").contains("no observable process identity"),
        "{error:#}"
    );
    assert!(has_retained_kernel(&lease).unwrap());
    let record = read_record(&lease.canonical_kernel_record()).unwrap();
    assert!(record.process.is_none() && record.instance.is_none());
    drop(bound);
    drop(owner);
    let rebound = prepared_owner(BackendKind::Firecracker);
    let mut config = VmStartConfig {
        name: name.into(),
        ..Default::default()
    };
    rebound.bind_to_config(&mut config).unwrap();
    let error = KernelBoundLaunch::bind(config, BackendKind::Firecracker, &lease)
        .err()
        .expect("a retained generation must block reuse of the VM name");
    assert!(format!("{error:#}").contains("still retained"), "{error:#}");
    drop(rebound);
    drop(lease);

    // A driver answering for another VM is never bound to this record, and a
    // process witness naming another VM is refused just the same.
    let name = "kernel-fc-dispatch-other";
    let (owner, bound, lease) = bound_firecracker_launch(name);
    let vm = DualWitnessVm {
        id: mvm_core::vm_backend::VmId("someone-else".into()),
        process: Some(identity.clone()),
    };
    let error = bound.observe_booted(&vm).unwrap_err();
    assert!(
        format!("{error:#}").contains("driver returned another VM"),
        "{error:#}"
    );
    let vm = DualWitnessVm {
        id: mvm_core::vm_backend::VmId(name.into()),
        process: Some(identity.clone()),
    };
    let error = bound.observe_booted(&vm).unwrap_err();
    assert!(
        format!("{error:#}").contains("kernel reader identity belongs to another VM"),
        "{error:#}"
    );
    let record = read_record(&lease.canonical_kernel_record()).unwrap();
    assert!(record.process.is_none() && record.instance.is_none());
    drop(bound);
    drop(owner);
    drop(lease);

    child.kill().unwrap();
    child.wait().unwrap();
}
