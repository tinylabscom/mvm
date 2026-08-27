//! Firecracker-driver tests that assert runtime orchestration rather than
//! VMM mechanics.
//!
//! `FcDriver` itself lives in `mvm-backends`, but these four reach for
//! `workload_runner`, `test_support`, and the `WasmBackend` capability row —
//! all orchestration this crate owns. They stayed here rather than following
//! the driver down, because stubbing what they call would have hollowed out
//! what they check.

#[cfg(test)]
mod tests {
    use mvm_backends::driver::FcDriver;
    use mvm_core::vm_backend::VmBackend;
    use mvm_vmm::driver::spec::VmmSpec;
    use mvm_vmm::driver::traits::VmmDriver;

    /// The selectable driver matrix distinguishes saved-state support from
    /// arbitrary snapshot support. Firecracker advertises the pool because its
    /// refill path now publishes a paused, no-NIC child and its claim path
    /// resumes that child only after fresh channel wiring.
    #[test]
    fn firecracker_and_hvf_advertise_the_live_standby_pool() {
        use crate::driver::hvf::HvfDriver;
        use crate::wasm_backend::WasmBackend;
        use mvm_backends::driver::LibkrunDriver;
        use mvm_backends::driver::QemuDriver;
        use mvm_backends::mock::MockDriver;

        assert!(FcDriver::new().capabilities().standby_pool);
        assert!(!LibkrunDriver::new().capabilities().standby_pool);
        assert!(HvfDriver::new().capabilities().standby_pool);
        assert!(!MockDriver::default().capabilities().standby_pool);
        assert!(!QemuDriver::new().capabilities().standby_pool);
        assert!(!WasmBackend::new().capabilities().standby_pool);
    }

    /// The metadata the spawn path writes for a factory parent must be exactly
    /// what `FcVmFullControl::rootfs_path()` reads back, or a live capture
    /// fails closed for want of a resolvable rootfs. Proven by running the real
    /// derivation (launch config → parent config → recorded metadata) and then
    /// resolving it through the real capture control — no boot, no KVM.
    #[test]
    fn the_parent_metadata_the_spawn_path_writes_resolves_through_the_capture_control() {
        use crate::workload_runner::factory_parent_config;
        use mvm_core::util::test_env::TestEnv;
        use mvm_core::vm_backend::{StandbySpec, StartMode, VmStartConfig};
        use mvm_vmm::checkpoint::VmFullControl as _;

        let mut env = TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.set("MVM_HOME", tmp.path());

        let image = tmp.path().join("rootfs.ext4");
        std::fs::write(&image, b"fake-rootfs").unwrap();

        let launch = VmStartConfig {
            name: "workload-a".into(),
            rootfs_path: image.display().to_string(),
            kernel_path: Some("/img/vmlinux".into()),
            cpus: 2,
            memory_mib: 512,
            runtime_overlay_path: Some("/img/runtime.ext4".into()),
            runtime_overlay_verity_path: Some("/img/runtime.verity".into()),
            runtime_overlay_roothash: Some("b".repeat(64)),
            ..Default::default()
        };
        let spec = StandbySpec {
            id: "standby-parent-1".into(),
            template_id: None,
            kernel_path: "/img/vmlinux".into(),
            kernel_sha256: "a".repeat(64),
            vcpus: 2,
            mem_mib: 512,
            signing_key_path: "/keys/host-signer.ed25519".into(),
            signer_id: "host:test".into(),
            binding_nonce: "b".repeat(64),
            control_socket: tmp.path().join("control.sock").display().to_string(),
            vm_state_dir: tmp.path().join("standby-parent-1").display().to_string(),
            image_path: Some(image.display().to_string()),
            image_sha256: Some("c".repeat(64)),
            vsock_egress: mvm_vmm::host::egress_shared::effective_vsock_egress(&launch),
        };

        let parent_cfg = factory_parent_config(&launch, &spec).unwrap();
        mvm_vmm::host::runtime_meta::record_from_start_config(
            &spec.id,
            StartMode::Detached,
            &parent_cfg,
        )
        .unwrap();

        let control = mvm_backends::fc::FcVmFullControl::new(&spec.id);
        assert_eq!(control.rootfs_path().unwrap(), image);
    }

    /// A parent warmed for an egress-allowing launch boots the guest's egress
    /// client — and that is the *only* thing the enablement changes.
    ///
    /// The enablement reaches the parent as a policy that answers "egress
    /// allowed", because that is what the cmdline token is derived from. This
    /// pins that the policy buys the parent nothing else: flipping it leaves the
    /// device set the driver configures byte-identical, so an egress-enabled
    /// parent hands a restored child the same vsock-only machine a deny-all one
    /// does. (That the set itself carries no guest NIC is enforced structurally
    /// by the workspace's vsock-only-egress token gate over this file.)
    #[test]
    fn an_egress_enabled_parent_boots_the_token_and_nothing_else_changes() {
        use crate::workload_runner::{factory_parent_config, factory_parent_spec};
        use mvm_core::network_policy::{HostPort, NetworkPolicy};
        use mvm_core::util::test_env::TestEnv;
        use mvm_core::vm_backend::{StandbySpec, VmStartConfig};

        let mut env = TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.set("MVM_HOME", tmp.path());

        let image = tmp.path().join("rootfs.ext4");
        std::fs::write(&image, b"fake-rootfs").unwrap();

        let deny_all_launch = VmStartConfig {
            name: "workload-a".into(),
            rootfs_path: image.display().to_string(),
            kernel_path: Some("/img/vmlinux".into()),
            cpus: 2,
            memory_mib: 512,
            runtime_overlay_path: Some("/img/runtime.ext4".into()),
            runtime_overlay_verity_path: Some("/img/runtime.verity".into()),
            runtime_overlay_roothash: Some("b".repeat(64)),
            ..Default::default()
        };
        let egress_launch = VmStartConfig {
            network_policy: NetworkPolicy::allow_list(vec![HostPort::new("api.example.com", 443)]),
            ..deny_all_launch.clone()
        };
        let spec_for = |launch: &VmStartConfig| StandbySpec {
            id: "standby-egress-parent".into(),
            template_id: None,
            kernel_path: "/img/vmlinux".into(),
            kernel_sha256: "a".repeat(64),
            vcpus: 2,
            mem_mib: 512,
            signing_key_path: "/keys/host-signer.ed25519".into(),
            signer_id: "host:test".into(),
            binding_nonce: "b".repeat(64),
            control_socket: tmp.path().join("control.sock").display().to_string(),
            vm_state_dir: tmp
                .path()
                .join("standby-egress-parent")
                .display()
                .to_string(),
            image_path: Some(image.display().to_string()),
            image_sha256: Some("c".repeat(64)),
            vsock_egress: mvm_vmm::host::egress_shared::effective_vsock_egress(launch),
        };
        let parent_boot = |launch: &VmStartConfig| {
            let spec = spec_for(launch);
            let cfg = factory_parent_config(launch, &spec).unwrap();
            let boot = factory_parent_spec(
                &cfg,
                std::path::Path::new(&spec.vm_state_dir),
                |virtiofs_root, has_disk| {
                    FcDriver::new().workload_base_bootargs(virtiofs_root, has_disk)
                },
            );
            (spec.vsock_egress, boot)
        };

        let (deny_enabled, deny_boot) = parent_boot(&deny_all_launch);
        let (egress_enabled, egress_boot) = parent_boot(&egress_launch);
        assert!(!deny_enabled);
        assert!(
            egress_enabled,
            "fixture must warm an egress-enabled parent, or it proves nothing"
        );

        assert!(
            egress_boot.cmdline.contains("mvm.vsock_egress=1"),
            "the parent must boot the guest egress client: {}",
            egress_boot.cmdline
        );
        assert!(
            !egress_boot.cmdline.contains("api.example.com"),
            "the parent's cmdline must name no destination: {}",
            egress_boot.cmdline
        );

        // Everything the driver would configure apart from the boot args is
        // identical between the two enablements. `/boot-source` is excluded
        // because it is where the cmdline lands, and that the cmdline matches the
        // workload's is asserted where both are assembled, not here.
        let device_set = |boot: &VmmSpec| {
            mvm_backends::driver::fc::fc_config_api_puts(
                boot,
                "/img/vmlinux",
                "/state/w/runtime/v.sock",
                "/state/w",
            )
            .into_iter()
            .filter(|p| p.path != "/boot-source")
            .map(|p| (p.path, p.body))
            .collect::<Vec<_>>()
        };
        assert_eq!(
            device_set(&egress_boot),
            device_set(&deny_boot),
            "the egress enablement must add no device to a warm parent"
        );
    }
}
