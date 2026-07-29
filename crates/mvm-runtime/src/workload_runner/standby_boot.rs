//! The factory parent's boot inputs, derived from the launch it will serve.
//!
//! A warm parent is captured whole and every child is restored out of that
//! saved memory, so the child inherits the parent's device model and kernel
//! cmdline rather than deriving its own. A parent that boots a different shape
//! than a workload does therefore hands that difference to every child it ever
//! produces — which makes "the parent boots like a workload" a correctness
//! property, not a convenience.
//!
//! So the parent's inputs are never written a second time here. The launch's
//! own `VmStartConfig` — already carrying whatever the CLI resolved for it,
//! including the verity-sealed runtime overlay that is the single source of the
//! guest agent — is reduced to a factory parent's and handed to the same
//! mappers a workload boot uses: [`workload_device_spec`] for the device model
//! and [`cmdline::runner_cmdline`] for the kernel cmdline.
//!
//! The reduction is written as an exhaustive destructure plus an exhaustive
//! struct literal, both without a `..` rest. Adding a field to `VmStartConfig`
//! stops this file compiling until someone decides whether it describes the
//! guest's boot (carried) or the workload's authority (dropped). That compile
//! error is the guard: the alternative is a boot-shape field that silently
//! reaches workloads and silently misses parents, which is exactly how the
//! parent came to boot without the runtime overlay.

use std::path::Path;

use mvm_core::policy::network_policy::NetworkPolicy;
use mvm_core::vm_backend::{RuntimeSourcePolicy, StandbyError, StandbySpec, VmStartConfig};

use crate::driver::VmmSpec;
use crate::workload_runner::cmdline;
use crate::workload_runner::spec_map::workload_device_spec;

/// Refuse a factory parent whose boot inputs describe a guest that cannot reach
/// an agent, naming the missing piece.
///
/// A parent is booted only to be captured, so one that boots into a panic costs
/// the launch a doomed boot and yields nothing to claim, and the symptom a
/// caller sees is an agent-readiness timeout that says nothing about the cause.
/// Two launch shapes produce exactly that. A required runtime overlay that was
/// never attached: on the overlay-only runtime the overlay is the single source
/// of the guest binaries, so an overlay-lean rootfs without it has no agent for
/// `/init` to exec. And a verity-sealed rootfs with no resolvable initramfs:
/// the initramfs is PID 1 on a sealed boot, and it is what verifies the rootfs
/// and mounts that overlay — without it the drives are attached but nothing
/// mounts them.
fn ensure_parent_can_reach_an_agent(
    id: &str,
    config: &VmStartConfig,
) -> std::result::Result<(), StandbyError> {
    if config.runtime_source_policy == RuntimeSourcePolicy::RequiredOverlay
        && cmdline::runtime_overlay(config).is_none()
    {
        return Err(StandbyError::SpawnFailed(format!(
            "standby '{id}' would boot without the runtime overlay its launch requires: the \
             overlay is the only source of the guest agent, so the parent would panic before it \
             could be captured"
        )));
    }
    if config.verity_path.is_some()
        && config.roothash.is_some()
        && cmdline::effective_initrd(config).is_none()
    {
        return Err(StandbyError::SpawnFailed(format!(
            "standby '{id}' has a verity-sealed rootfs but no resolvable initramfs: the \
             initramfs is PID 1 on a sealed boot, so without it nothing verifies the rootfs or \
             mounts the runtime overlay the guest agent lives on"
        )));
    }
    Ok(())
}

/// Reduce `launch` to the launch config of the factory parent recorded as
/// `spec`: the guest's boot shape carried verbatim, every field that carries
/// workload authority or per-launch identity dropped.
///
/// The parent's identity, resources, kernel and rootfs are taken from `spec`
/// rather than from `launch`, because those four are the pool's own compat key
/// — a claim matches a parent on them. Sourcing them from the record that will
/// be matched is what stops the recorded key from describing something other
/// than what actually booted.
pub fn factory_parent_config(
    launch: &VmStartConfig,
    spec: &StandbySpec,
) -> std::result::Result<VmStartConfig, StandbyError> {
    let image = spec.image_path.as_deref().ok_or_else(|| {
        StandbyError::SpawnFailed(format!("standby '{}' has no rootfs image to boot", spec.id))
    })?;

    let VmStartConfig {
        // ── Per-launch identity and workload authority. A factory parent runs
        // no workload: it holds no plan, no tenant, no secrets, no volumes and
        // no ports; its egress is deny-all because it has no gated endpoint to
        // route through; it pre-opens no console listeners; and it never
        // replenishes a pool of its own. Each is dropped here, so a parent is
        // incapable of carrying one rather than merely expected not to.
        name: _,
        template_id: _,
        rootfs_path: _,
        kernel_path: _,
        revision_hash: _,
        flake_ref: _,
        profile: _,
        cpus: _,
        memory_mib: _,
        ports: _,
        volumes: _,
        config_files: _,
        secret_files: _,
        runner_dir: _,
        tenant_id: _,
        plan_json: _,
        bundle_json: _,
        warm_pool_size: _,
        network_policy: _,
        dev_console: _,
        // ── The guest's boot shape: carried verbatim, because a child inherits
        // all of it from the parent's restored memory.
        virtiofs_root,
        initrd_path,
        verity_path,
        roothash,
        runtime_overlay_path,
        runtime_overlay_verity_path,
        runtime_overlay_roothash,
        runtime_overlay_version,
        runtime_source_policy,
        mem_initial_mib,
    } = launch;

    let parent = VmStartConfig {
        name: spec.id.clone(),
        template_id: spec.template_id.clone(),
        rootfs_path: image.to_string(),
        kernel_path: Some(spec.kernel_path.clone()),
        cpus: u32::from(spec.vcpus),
        memory_mib: spec.mem_mib,
        virtiofs_root: virtiofs_root.clone(),
        initrd_path: initrd_path.clone(),
        verity_path: verity_path.clone(),
        roothash: roothash.clone(),
        runtime_overlay_path: runtime_overlay_path.clone(),
        runtime_overlay_verity_path: runtime_overlay_verity_path.clone(),
        runtime_overlay_roothash: runtime_overlay_roothash.clone(),
        runtime_overlay_version: runtime_overlay_version.clone(),
        runtime_source_policy: *runtime_source_policy,
        mem_initial_mib: *mem_initial_mib,
        revision_hash: String::new(),
        flake_ref: String::new(),
        profile: None,
        ports: Vec::new(),
        volumes: Vec::new(),
        config_files: Vec::new(),
        secret_files: Vec::new(),
        runner_dir: None,
        tenant_id: None,
        plan_json: None,
        bundle_json: None,
        warm_pool_size: 0,
        network_policy: NetworkPolicy::deny_all(),
        dev_console: false,
    };

    ensure_parent_can_reach_an_agent(&spec.id, &parent)?;
    Ok(parent)
}

/// The factory parent's `VmmSpec`, assembled by the same mappers a workload
/// boot uses, so a drive or cmdline token added to the workload's boot reaches
/// the parent's too.
///
/// One divergence is deliberate and covered by the tests below: the vsock
/// channel list, which [`workload_device_spec`] leaves empty. A workload wires
/// its agent, egress, exit and (when admitted) broker channels to host sockets;
/// a parent wires none because it has no endpoint and no broker to wire them
/// to. The guest's vsock *device* is identical either way — the driver
/// configures it unconditionally — so this costs the parent no device-model
/// divergence.
///
/// A second divergence is **not** covered, and no test here can cover it: the
/// per-VM grant tokens. [`cmdline::workload_cmdline`] appends whatever
/// [`crate::hvf_bootargs::grant_tokens`] derives from the named VM's
/// `verb-grant.json` sidecar, and a factory parent holds no plan, so it has no
/// sidecar by construction and emits none. The transient run path mints no
/// sidecar today, which is the only reason the two cmdlines currently agree;
/// the moment it does, a workload's cmdline gains `mvm.verb_grant=`,
/// `mvm.require_grant=` and `mvm.host_signer_pub=` that the parent's never
/// carries — and the shape-equality tests keep passing, because their fixtures
/// have no sidecar on either side. A child inherits its parent's cmdline out of
/// restored memory rather than deriving its own, so that divergence would reach
/// every child; resolving it is part of the work that must land before a warm
/// pool is armed.
pub fn factory_parent_spec(
    config: &VmStartConfig,
    state_dir: &Path,
    base_bootargs: impl Fn(bool, bool) -> String,
) -> VmmSpec {
    let cmdline = cmdline::runner_cmdline(config, state_dir, base_bootargs);
    workload_device_spec(config, &cmdline, &state_dir.join("console.log"))
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::path::PathBuf;
    use std::sync::MutexGuard;

    use mvm_core::util::test_env::TestEnv;
    use mvm_core::vm_backend::{RuntimeSourcePolicy, VmVolume, VmVolumeKind};

    use crate::workload_runner::spec_map::{WorkloadSockets, WorkloadSpecInputs, workload_spec};

    /// Point `MVM_HOME` at an empty directory for the caller's lifetime.
    ///
    /// Every cmdline assembled here runs `grant_tokens`, which reads
    /// `<MVM_HOME>/vms/<name>/verb-grant.json` for whichever VM name the fixture
    /// used. Left alone, that is the developer's real home: a machine that
    /// happens to have a VM of the fixture's name with a grant sidecar would
    /// fail these tests for a reason that has nothing to do with the code. Same
    /// isolation, taken in the same order, as the sibling shape guard in
    /// `runner`.
    fn isolated_home() -> (TestEnv, tempfile::TempDir, MutexGuard<'static, ()>) {
        let lock = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.set("MVM_HOME", home.path());
        (env, home, lock)
    }

    /// The Firecracker base: a verity boot (`has_disk == false`) carries only
    /// the console, and the disk shape adds root/init.
    fn fc_base(_virtiofs_root: bool, has_disk: bool) -> String {
        let console = "console=ttyS0 reboot=k panic=1 net.ifnames=0";
        if has_disk {
            format!("{console} root=/dev/vda rw rootwait init=/init")
        } else {
            console.to_string()
        }
    }

    /// A sealed launch of the shape the live Firecracker workload path
    /// produces: verity-sealed rootfs, the sibling initramfs that runs the
    /// verity setup, and the required runtime overlay carrying the guest agent.
    fn sealed_launch(dir: &Path) -> VmStartConfig {
        let rootfs = dir.join("rootfs.ext4");
        let verity = dir.join("rootfs.verity");
        let initrd = dir.join("rootfs.initrd");
        std::fs::write(&rootfs, b"rootfs").unwrap();
        std::fs::write(&verity, b"verity").unwrap();
        std::fs::write(&initrd, b"initrd").unwrap();
        VmStartConfig {
            name: "workload-a".into(),
            rootfs_path: rootfs.display().to_string(),
            kernel_path: Some(dir.join("vmlinux").display().to_string()),
            verity_path: Some(verity.display().to_string()),
            roothash: Some("a".repeat(64)),
            runtime_overlay_path: Some(dir.join("overlay.ext4").display().to_string()),
            runtime_overlay_verity_path: Some(dir.join("overlay.verity").display().to_string()),
            runtime_overlay_roothash: Some("b".repeat(64)),
            runtime_overlay_version: Some("0.18.0".into()),
            runtime_source_policy: RuntimeSourcePolicy::RequiredOverlay,
            cpus: 2,
            memory_mib: 512,
            ..Default::default()
        }
    }

    fn standby_spec_for(launch: &VmStartConfig, dir: &Path) -> StandbySpec {
        StandbySpec {
            id: "standby-abc".into(),
            template_id: None,
            kernel_path: launch.kernel_path.clone().unwrap(),
            kernel_sha256: "c".repeat(64),
            vcpus: u8::try_from(launch.cpus).unwrap(),
            mem_mib: launch.memory_mib,
            signing_key_path: "/keys/host-signer.ed25519".into(),
            signer_id: "host:test".into(),
            binding_nonce: "d".repeat(64),
            control_socket: dir.join("control.sock").display().to_string(),
            vm_state_dir: dir.join("standby-abc").display().to_string(),
            image_path: Some(launch.rootfs_path.clone()),
            image_sha256: Some("e".repeat(64)),
        }
    }

    fn workload_boot(launch: &VmStartConfig, state_dir: &Path) -> VmmSpec {
        workload_spec(&WorkloadSpecInputs {
            config: launch,
            sockets: WorkloadSockets {
                agent: Path::new("/run/agent.sock"),
                egress_gateway: Path::new("/run/egress.sock"),
                exit: Path::new("/run/workload.exit"),
                broker: None,
                console_data: Vec::new(),
            },
            cmdline: cmdline::runner_cmdline(launch, state_dir, fc_base),
            console_log: state_dir.join("console.log"),
        })
    }

    /// The regression guard for the shipped defect: the parent booted a bare
    /// rootfs with base bootargs while the workload booted four drives and the
    /// verity/overlay cmdline tokens, so the parent's `/init` found no guest
    /// agent and the kernel panicked.
    ///
    /// This asserts equivalence rather than a hard-coded drive/token list on
    /// purpose: a future drive or cmdline token added to the workload path has
    /// to appear on the parent too, or this fails — which is the only way the
    /// two shapes stay in step without anyone remembering to keep them there.
    #[test]
    fn parent_boots_the_same_device_model_and_cmdline_the_workload_does() {
        let _home = isolated_home();
        let tmp = tempfile::tempdir().unwrap();
        let launch = sealed_launch(tmp.path());
        let spec = standby_spec_for(&launch, tmp.path());

        let workload = workload_boot(&launch, &tmp.path().join("workload-a"));
        let parent_cfg = factory_parent_config(&launch, &spec).unwrap();
        let parent = factory_parent_spec(&parent_cfg, Path::new(&spec.vm_state_dir), fc_base);

        assert_eq!(
            parent.blocks, workload.blocks,
            "the parent must attach the workload's whole disk stack, overlay included"
        );
        assert_eq!(
            parent.cmdline, workload.cmdline,
            "the parent must boot the workload's kernel cmdline, verity and runtime-source \
             tokens included"
        );
        assert_eq!(parent.kernel, workload.kernel);
        assert_eq!(parent.initramfs, workload.initramfs);
        assert_eq!(parent.vcpus, workload.vcpus);
        assert_eq!(parent.memory_mib, workload.memory_mib);
        assert_eq!(parent.mem_initial_mib, workload.mem_initial_mib);
        assert!(!parent.trusted_builder);
    }

    /// The one boot-shape difference a factory parent cannot close, pinned so
    /// the launch-path gate that exists for it is not dropped as redundant.
    ///
    /// `mvm.vsock_egress=1` starts the guest's in-guest egress client, and it is
    /// emitted iff the launch's policy allows egress. A parent is deny-all by
    /// construction: it has no gated endpoint to route through, and it is shared
    /// across claims, so carrying one launch's policy would hand that launch's
    /// shape to the next claim — the policy is not part of the compat key. Since
    /// a child inherits its parent's cmdline out of restored memory rather than
    /// deriving its own, an egress-allowing launch served warm would come up
    /// with no network at all, silently. `warm_eligible_launch` on the CLI side
    /// therefore refuses that shape outright and it cold-boots.
    ///
    /// What this asserts is narrower than it looks: for *this fixture*, which
    /// carries no verb-grant sidecar on either side, the egress token is the
    /// only difference. It is not a claim that the two cmdlines can differ by at
    /// most one token in production — the per-VM grant tokens
    /// (`mvm.verb_grant=`, `mvm.require_grant=`, `mvm.host_signer_pub=`) come
    /// from a sidecar a factory parent never has, so a workload carrying one
    /// diverges by those too, silently and without failing anything here. See
    /// [`factory_parent_spec`]'s note. Within the covered surface, a second
    /// token appearing here means something else has started depending on the
    /// parent's stripped-down config.
    #[test]
    fn an_egress_allowing_launch_diverges_by_one_token_which_is_why_the_pool_refuses_it() {
        let _home = isolated_home();
        let tmp = tempfile::tempdir().unwrap();
        let mut launch = sealed_launch(tmp.path());
        launch.network_policy = mvm_core::network_policy::NetworkPolicy::allow_list(vec![
            mvm_core::network_policy::HostPort::new("api.example.com", 443),
        ]);
        let spec = standby_spec_for(&launch, tmp.path());

        let workload = workload_boot(&launch, &tmp.path().join("workload-a"));
        let parent_cfg = factory_parent_config(&launch, &spec).unwrap();
        let parent = factory_parent_spec(&parent_cfg, Path::new(&spec.vm_state_dir), fc_base);

        assert!(
            !parent_cfg.network_policy.allows_egress(),
            "a parent has no gated endpoint and is shared, so it stays deny-all"
        );
        assert!(
            workload.cmdline.contains("mvm.vsock_egress=1"),
            "fixture must exercise the egress token: {}",
            workload.cmdline
        );
        assert!(
            !parent.cmdline.contains("mvm.vsock_egress"),
            "a deny-all parent must not carry the egress token: {}",
            parent.cmdline
        );
        assert_eq!(
            workload.cmdline,
            format!("{} mvm.vsock_egress=1", parent.cmdline),
            "the egress token must be the only difference between the two cmdlines"
        );
        assert_eq!(
            parent.blocks, workload.blocks,
            "the disk stack must still match — the policy changes no device"
        );
    }

    /// The same guard, stated against the concrete symptoms the live run
    /// recorded, so a failure names what the guest will miss rather than only
    /// that two values differ.
    #[test]
    fn parent_carries_the_overlay_drives_and_runtime_tokens_the_guest_agent_needs() {
        let _home = isolated_home();
        let tmp = tempfile::tempdir().unwrap();
        let launch = sealed_launch(tmp.path());
        let spec = standby_spec_for(&launch, tmp.path());
        let parent_cfg = factory_parent_config(&launch, &spec).unwrap();
        let parent = factory_parent_spec(&parent_cfg, Path::new(&spec.vm_state_dir), fc_base);

        let nodes: Vec<String> = parent.blocks.iter().map(|b| b.device_node()).collect();
        assert_eq!(
            nodes,
            vec!["/dev/vda", "/dev/vdb", "/dev/vdc", "/dev/vdd"],
            "rootfs, its verity sidecar, the runtime overlay and the overlay's verity sidecar"
        );
        assert!(parent.blocks.iter().all(|b| b.read_only));

        for token in [
            "mvm.roothash=",
            "mvm.data=/dev/vda",
            "mvm.hash=/dev/vdb",
            "mvm.runtime_roothash=",
            "mvm.runtime_data=/dev/vdc",
            "mvm.runtime_hash=/dev/vdd",
            "mvm.runtime_source_policy=required_overlay",
        ] {
            assert!(
                parent.cmdline.contains(token),
                "parent cmdline missing {token}: {}",
                parent.cmdline
            );
        }
    }

    #[test]
    fn parent_drops_every_workload_authority_field_the_launch_carried() {
        let _home = isolated_home();
        let tmp = tempfile::tempdir().unwrap();
        let mut launch = sealed_launch(tmp.path());
        launch.plan_json = Some("{\"signed\":\"plan\"}".into());
        launch.bundle_json = Some("{\"pin\":\"bundle\"}".into());
        launch.tenant_id = Some("tenant-a".into());
        launch.warm_pool_size = 4;
        launch.dev_console = true;
        launch.network_policy = NetworkPolicy::unrestricted();
        launch.volumes = vec![VmVolume {
            host: tmp.path().join("data.img").display().to_string(),
            guest: "/data".into(),
            size: String::new(),
            read_only: false,
            kind: VmVolumeKind::Disk,
            encrypted: false,
        }];
        let spec = standby_spec_for(&launch, tmp.path());

        let parent_cfg = factory_parent_config(&launch, &spec).unwrap();
        assert_eq!(parent_cfg.plan_json, None);
        assert_eq!(parent_cfg.bundle_json, None);
        assert_eq!(parent_cfg.tenant_id, None);
        assert_eq!(parent_cfg.warm_pool_size, 0);
        assert!(!parent_cfg.dev_console);
        assert!(parent_cfg.volumes.is_empty());
        assert!(parent_cfg.secret_files.is_empty());
        assert!(parent_cfg.config_files.is_empty());
        assert!(
            !parent_cfg.network_policy.allows_egress(),
            "a parent has no gated endpoint, so it must not be allowed off the box"
        );

        let parent = factory_parent_spec(&parent_cfg, Path::new(&spec.vm_state_dir), fc_base);
        assert!(
            parent.vsock.is_empty(),
            "a factory parent wires no host channels: no endpoint, no broker"
        );
        assert_eq!(
            parent.blocks.len(),
            4,
            "the workload's extra volume must not follow the parent"
        );
        assert!(
            !parent.cmdline.contains("mvm.uvols="),
            "parent cmdline leaked a user-volume manifest: {}",
            parent.cmdline
        );
    }

    #[test]
    fn parent_identity_and_resources_come_from_the_pool_record_not_the_launch() {
        let tmp = tempfile::tempdir().unwrap();
        let launch = sealed_launch(tmp.path());
        let mut spec = standby_spec_for(&launch, tmp.path());
        spec.template_id = Some("tpl-7".into());

        let parent_cfg = factory_parent_config(&launch, &spec).unwrap();
        assert_eq!(parent_cfg.name, spec.id);
        assert_eq!(parent_cfg.template_id.as_deref(), Some("tpl-7"));
        assert_eq!(parent_cfg.kernel_path, Some(spec.kernel_path.clone()));
        assert_eq!(parent_cfg.rootfs_path, spec.image_path.clone().unwrap());
        assert_eq!(parent_cfg.cpus, u32::from(spec.vcpus));
        assert_eq!(parent_cfg.memory_mib, spec.mem_mib);
    }

    #[test]
    fn factory_parent_config_refuses_a_record_without_a_rootfs_image() {
        let tmp = tempfile::tempdir().unwrap();
        let launch = sealed_launch(tmp.path());
        let mut spec = standby_spec_for(&launch, tmp.path());
        spec.image_path = None;

        let err = factory_parent_config(&launch, &spec)
            .expect_err("a parent with no rootfs cannot boot the shape a workload does");
        assert!(
            format!("{err}").contains("no rootfs image"),
            "unexpected refusal: {err}"
        );
    }

    /// The overlay carries the guest agent, so a parent that would boot without
    /// one is refused up front instead of booting into the panic the live run
    /// recorded — and the refusal names the overlay rather than surfacing as an
    /// agent-readiness timeout.
    #[test]
    fn factory_parent_config_refuses_a_required_overlay_launch_carrying_no_overlay() {
        let tmp = tempfile::tempdir().unwrap();
        let mut launch = sealed_launch(tmp.path());
        launch.runtime_overlay_path = None;
        launch.runtime_overlay_verity_path = None;
        launch.runtime_overlay_roothash = None;
        let spec = standby_spec_for(&launch, tmp.path());

        let err = factory_parent_config(&launch, &spec)
            .expect_err("a required-overlay launch with no overlay cannot boot a guest agent");
        assert!(
            format!("{err}").contains("runtime overlay"),
            "unexpected refusal: {err}"
        );
    }

    /// On a sealed boot the initramfs is PID 1: it verifies the rootfs and
    /// mounts the overlay. Without one the drives are attached and nothing
    /// mounts them, which is the second shape of the same failure.
    #[test]
    fn factory_parent_config_refuses_a_sealed_rootfs_with_no_resolvable_initramfs() {
        let tmp = tempfile::tempdir().unwrap();
        let launch = sealed_launch(tmp.path());
        std::fs::remove_file(tmp.path().join("rootfs.initrd")).unwrap();
        let spec = standby_spec_for(&launch, tmp.path());

        let err = factory_parent_config(&launch, &spec)
            .expect_err("a sealed rootfs with no initramfs has no PID 1 to mount the overlay");
        assert!(
            format!("{err}").contains("initramfs"),
            "unexpected refusal: {err}"
        );
    }

    /// The guard is keyed on the launch's own policy, so an unsealed
    /// rootfs-only launch — a dev image with the agent baked in — still warms.
    #[test]
    fn factory_parent_config_admits_a_rootfs_only_launch_with_no_overlay() {
        let tmp = tempfile::tempdir().unwrap();
        let rootfs = tmp.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"rootfs").unwrap();
        let launch = VmStartConfig {
            name: "workload-a".into(),
            rootfs_path: rootfs.display().to_string(),
            kernel_path: Some(tmp.path().join("vmlinux").display().to_string()),
            cpus: 2,
            memory_mib: 512,
            ..Default::default()
        };
        let spec = standby_spec_for(&launch, tmp.path());

        let parent = factory_parent_config(&launch, &spec)
            .expect("a rootfs-only launch needs no overlay to reach its agent");
        assert_eq!(
            parent.runtime_source_policy,
            RuntimeSourcePolicy::RootfsOnly
        );
    }

    #[test]
    fn parent_console_is_captured_into_its_own_state_dir() {
        let _home = isolated_home();
        let tmp = tempfile::tempdir().unwrap();
        let launch = sealed_launch(tmp.path());
        let spec = standby_spec_for(&launch, tmp.path());
        let parent_cfg = factory_parent_config(&launch, &spec).unwrap();
        let state_dir = PathBuf::from(&spec.vm_state_dir);
        let parent = factory_parent_spec(&parent_cfg, &state_dir, fc_base);
        assert_eq!(parent.console.log_path, state_dir.join("console.log"));
    }
}
