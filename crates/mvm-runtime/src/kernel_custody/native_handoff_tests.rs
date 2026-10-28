//! Kernel handoff only: synthetic runtime members do not prove a release runtime.
use super::*;
use mvm_core::canonical_linux::PreparedCanonicalLinux;
use mvm_core::plan::bundle::*;
use mvm_core::util::test_env::TestEnv;
use std::sync::Arc;

#[path = "../../../mvm-core/src/image_set/fixtures/published_root.rs"]
mod published_root;

fn prepared_owner(backend: BackendKind) -> Arc<PreparedCanonicalLinux> {
    let kernel = std::fs::read(
        std::env::var_os("MVM_TEST_CANONICAL_KERNEL").expect("actual pinned public kernel"),
    )
    .unwrap();
    let key = ed25519_dalek::SigningKey::from_bytes(&[74; 32]);
    struct Publisher(ed25519_dalek::VerifyingKey);
    impl TrustStore for Publisher {
        fn lookup(&self, id: &KeyId) -> Option<ed25519_dalek::VerifyingKey> {
            (id == &key_id_from_pubkey(&self.0)).then_some(self.0)
        }
    }
    let mut payload = vec![
        ("kernel", kernel),
        ("linux.json", published_root::MANIFEST.to_vec()),
        ("linux.bundle", published_root::BUNDLE.to_vec()),
        ("revocations.json", include_bytes!("../../../mvm-core/tests/fixtures/image-set-revocations/revocation-list-v1/revocations.json").to_vec()),
        ("revocations.bundle", include_bytes!("../../../mvm-core/tests/fixtures/image-set-revocations/revocation-list-v1/revocations.json.bundle").to_vec()),
    ];
    for name in [
        "runtime.tar.gz",
        "runtime.sha256",
        "runtime.bundle",
        "runtime.sha256.bundle",
        "overlay",
        "overlay.verity",
        "initrd",
    ] {
        payload.push((
            name,
            b"synthetic runtime: never native runtime authority".to_vec(),
        ));
    }
    let manifest: BundleManifest = serde_json::from_value(serde_json::json!({
        "schema_version": 7, "publisher": "unit-only", "key_id": key_id_from_pubkey(&key.verifying_key()),
        "arch": mvm_core::arch::GuestArch::host().to_string(), "created_at": "2026-10-16T00:00:00Z",
        "artifacts": payload.iter().map(|(name,bytes)| serde_json::json!({
            "name": name, "path": format!("artifacts/{name}"),
            "role": match *name { "kernel" => "kernel", "initrd" => "initrd", _ => "other" },
            "sha256": sha256_hex(bytes), "size_bytes": bytes.len(),
        })).collect::<Vec<_>>(),
        "members": [{
            "class": "embedded_cli_boot_assets", "manifest_artifact": "linux.json",
            "version": "0.24.0", "arch": mvm_core::arch::GuestArch::host().to_string(),
            "archive_artifact": "runtime.tar.gz", "checksum_artifact": "runtime.sha256",
            "signature_bundle_artifact": "runtime.bundle", "checksum_signature_bundle_artifact": "runtime.sha256.bundle",
            "overlay_artifact": "overlay", "overlay_verity_artifact": "overlay.verity",
            "initramfs_artifact": "initrd", "overlay_roothash": "a".repeat(64),
            "protocol_version": 2, "min_supported_protocol_version": 2,
        }, {
            "class": "canonical_linux_proof", "manifest_artifact": "linux.json",
            "signature_bundle_artifact": "linux.bundle", "revocation_document_artifact": "revocations.json",
            "revocation_signature_bundle_artifact": "revocations.bundle",
        }]
    })).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let archive = directory.path().join("unit.mvmpkg");
    let payload = payload
        .into_iter()
        .map(|(name, bytes)| (format!("artifacts/{name}"), bytes))
        .collect();
    std::fs::write(&archive, write_bundle(&manifest, &key, payload).unwrap()).unwrap();
    let trust = Publisher(key.verifying_key());
    let pin = verify_bundle_file(&archive, &trust)
        .unwrap()
        .plan_artifact();
    let enrolled = FsTrustStore::default_path().unwrap();
    mvm_core::config::create_private_dir(enrolled.root()).unwrap();
    std::fs::write(
        enrolled.root().join(format!("{}.pub", manifest.key_id.0)),
        key.verifying_key().to_bytes(),
    )
    .unwrap();
    Arc::new(
        mvm_core::canonical_linux::prepare_canonical_linux(
            &archive,
            &pin,
            backend,
            mvm_build::stage0_kernel::current_image_set_protocol_support(),
        )
        .unwrap(),
    )
}

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
