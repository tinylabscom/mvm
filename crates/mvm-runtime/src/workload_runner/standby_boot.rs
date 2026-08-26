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
//! and [`cmdline::runner_cmdline_without_hostname`] for the kernel cmdline. A
//! parent cannot carry a workload hostname because the pool may serve more
//! than one named child; claim-time identity delivery installs the child name.
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
use mvm_vmm::host::cmdline;
use mvm_vmm::host::spec_map::workload_device_spec;
use mvm_vmm::host::spec_map::{WorkloadSockets, workload_vsock_ports};

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

/// The parent's stand-in for the launch's egress *enablement*, and nothing else.
///
/// The guest's `mvm.vsock_egress=1` token is derived from
/// `network_policy.allows_egress()`, and a restored child inherits its cmdline
/// out of the parent's saved memory rather than deriving its own — so whether a
/// child's guest runs an egress client at all is settled at the parent's boot.
/// The parent therefore has to boot the token the launch would, which means its
/// config has to answer `allows_egress()` the way the launch's effective
/// enablement does.
///
/// What it must *not* carry is any destination. There is no "egress on, no
/// hosts" policy shape, so the enablement rides the only host-free one: it names
/// nothing the launch asked for, and a parent has no NIC, no egress endpoint and
/// no gateway to route a destination to in any case. The allow-list stays where
/// it is enforced — host-side, on the claimed child's own endpoint, from that
/// child's own launch policy — so a shared parent holds nothing per-launch to
/// hand to the next claim, and the pool partitions on the boolean alone.
fn parent_egress_enablement(enabled: bool) -> NetworkPolicy {
    if enabled {
        NetworkPolicy::unrestricted()
    } else {
        NetworkPolicy::deny_all()
    }
}

/// Reduce `launch` to the launch config of the factory parent recorded as
/// `spec`: the guest's boot shape carried verbatim, every field that carries
/// workload authority or per-launch identity dropped.
///
/// The parent's identity, resources, kernel, rootfs and guest egress enablement
/// are taken from `spec` rather than from `launch`, because those are the pool's
/// own compat key — a claim matches a parent on them. Sourcing them from the
/// record that will be matched is what stops the recorded key from describing
/// something other than what actually booted.
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
        // no ports; it pre-opens no console listeners; and it never replenishes a
        // pool of its own. Each is dropped here, so a parent is incapable of
        // carrying one rather than merely expected not to. `network_policy` is
        // dropped for the same reason and its enablement half re-derived from
        // `spec` below — a parent boots whether the guest runs an egress client,
        // never which destinations one may reach.
        name: _,
        template_id: _,
        rootfs_path: _,
        kernel_path: _,
        revision_hash: _,
        flake_ref: _,
        profile: _,
        cpus: _,
        // A factory parent is not the workload, so it is not what any grant was
        // admitted for. A child is spawned under its own admitted plan and
        // takes its bound from there; inheriting this launch's would bind a
        // parent to a grant made for something else.
        cpu_grant: _,
        memory_mib: _,
        ports: _,
        volumes: _,
        extensions: _,
        extension_plan_id: _,
        service_proxies: _,
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
        cpu_grant: None,
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
        extensions: Vec::new(),
        extension_plan_id: None,
        service_proxies: Vec::new(),
        config_files: Vec::new(),
        secret_files: Vec::new(),
        runner_dir: None,
        tenant_id: None,
        plan_json: None,
        bundle_json: None,
        warm_pool_size: 0,
        network_policy: parent_egress_enablement(spec.vsock_egress),
        dev_console: false,
    };

    ensure_parent_can_reach_an_agent(&spec.id, &parent)?;
    Ok(parent)
}

/// The factory parent's `VmmSpec`, assembled by the same mappers a workload
/// boot uses, so a drive or boot-shape cmdline token added to the workload's
/// boot reaches the parent's too. The hostname is intentionally excluded: a
/// shared parent has no child's identity until the claim handshake.
///
/// Saved-state parents deliberately carry no host channels. The live-HVF
/// variant below adds authority-free stable agent, egress, broker, and exit
/// paths so a paused resident parent can be handed off without changing its
/// device model; those paths are connected to child-owned endpoints only at
/// claim time.
///
/// A second divergence is **not** covered, and no test here can cover it: the
/// per-VM grant tokens. [`cmdline::workload_cmdline`] appends whatever
/// [`crate::backends::hvf::bootargs::grant_tokens`] derives from the named VM's
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
///
/// `state_dir` is also the second input to the guest's egress token, which is
/// suppressed for a state dir holding a secret-bearing plan. A factory parent
/// holds no plan, so nothing writes one beside it and that half is inert here:
/// the parent's token follows [`StandbySpec::vsock_egress`] alone, which is
/// exactly the value a claim matches on.
pub fn factory_parent_spec(
    config: &VmStartConfig,
    state_dir: &Path,
    base_bootargs: impl Fn(bool, bool) -> String,
) -> VmmSpec {
    factory_parent_spec_inner(config, state_dir, base_bootargs, false)
}

/// Build the factory parent shape for the native HVF live handoff. The stable
/// paths are inert until a claim links them to the child's own host channels.
#[cfg(test)]
pub fn factory_parent_spec_live(
    config: &VmStartConfig,
    state_dir: &Path,
    base_bootargs: impl Fn(bool, bool) -> String,
) -> VmmSpec {
    factory_parent_spec_inner(config, state_dir, base_bootargs, true)
}

fn factory_parent_spec_inner(
    config: &VmStartConfig,
    state_dir: &Path,
    base_bootargs: impl Fn(bool, bool) -> String,
    live_handoff: bool,
) -> VmmSpec {
    let cmdline = cmdline::runner_cmdline_without_hostname(config, state_dir, base_bootargs);
    if !live_handoff {
        return workload_device_spec(config, &cmdline, &state_dir.join("console.log"));
    }
    let agent = mvm_core::config::vm_hvf_agent_socket_at(state_dir);
    let egress = state_dir.join("standby-egress.sock");
    let exit = state_dir.join("workload.exit");
    let broker = state_dir.join("standby-broker.sock");
    let sockets = WorkloadSockets {
        agent: &agent,
        egress_gateway: Some(&egress),
        exit: &exit,
        broker: Some(&broker),
        console_data: Vec::new(),
    };
    VmmSpec {
        vsock: workload_vsock_ports(&sockets),
        ..workload_device_spec(config, &cmdline, &state_dir.join("console.log"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::path::PathBuf;
    use std::sync::MutexGuard;

    use mvm_core::util::test_env::TestEnv;
    use mvm_core::vm_backend::{RuntimeSourcePolicy, VmVolume, VmVolumeKind};
    use mvm_net::channel::GuestService;

    use mvm_vmm::host::spec_map::{WorkloadSockets, WorkloadSpecInputs, workload_spec};

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
    /// the console, and the disk shape adds rootwait/init (never a `root=`
    /// declaration — Firecracker appends the authoritative one from the root
    /// drive's flags).
    fn fc_base(_virtiofs_root: bool, has_disk: bool) -> String {
        let console = "console=ttyS0 reboot=k panic=1 net.ifnames=0";
        if has_disk {
            format!("{console} rootwait init=/init")
        } else {
            console.to_string()
        }
    }

    /// A sealed launch of the shape the live Firecracker workload path
    /// produces: verity-sealed rootfs, the universal initramfs that runs the
    /// verity setup, and the required runtime overlay carrying the guest agent.
    fn sealed_launch(dir: &Path, home: &Path) -> VmStartConfig {
        let rootfs = dir.join("rootfs.ext4");
        let verity = dir.join("rootfs.verity");
        std::fs::write(&rootfs, b"rootfs").unwrap();
        std::fs::write(&verity, b"verity").unwrap();
        VmStartConfig {
            name: "workload-a".into(),
            rootfs_path: rootfs.display().to_string(),
            kernel_path: Some(dir.join("vmlinux").display().to_string()),
            initrd_path: Some(cmdline::seed_universal_initramfs(home)),
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

    /// The pool record a spawn for `launch` would write. `vsock_egress` comes
    /// from the same shared derivation the CLI's compat-key builder uses, so
    /// these fixtures exercise the value a real claim would match on rather than
    /// one hand-set here.
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
            vsock_egress: mvm_vmm::host::egress_shared::effective_vsock_egress(launch),
        }
    }

    fn workload_boot(launch: &VmStartConfig, state_dir: &Path) -> VmmSpec {
        workload_spec(&WorkloadSpecInputs {
            // A warm parent's own boot mints and attaches its drive through the
            // cold path; this factory spec carries none of its own.
            identity_drive: None,
            config: launch,
            sockets: WorkloadSockets {
                agent: Path::new("/run/agent.sock"),
                egress_gateway: Some(Path::new("/run/egress.sock")),
                exit: Path::new("/run/workload.exit"),
                broker: None,
                console_data: Vec::new(),
            },
            cmdline: cmdline::runner_cmdline(launch, state_dir, fc_base),
            console_log: state_dir.join("console.log"),
        })
    }

    fn without_per_boot_tokens(cmdline: &str) -> String {
        cmdline
            .split_whitespace()
            .filter(|token| {
                !token.starts_with("mvm.hostname=") && !token.starts_with("mvm.hostepoch=")
            })
            .collect::<Vec<_>>()
            .join(" ")
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
        let (_env, home, _lock) = isolated_home();
        let tmp = tempfile::tempdir().unwrap();
        let launch = sealed_launch(tmp.path(), home.path());
        let spec = standby_spec_for(&launch, tmp.path());

        let workload = workload_boot(&launch, &tmp.path().join("workload-a"));
        let parent_cfg = factory_parent_config(&launch, &spec).unwrap();
        let parent = factory_parent_spec(&parent_cfg, Path::new(&spec.vm_state_dir), fc_base);

        assert_eq!(
            parent.blocks, workload.blocks,
            "the parent must attach the workload's whole disk stack, overlay included"
        );
        assert_eq!(
            without_per_boot_tokens(&parent.cmdline),
            without_per_boot_tokens(&workload.cmdline),
            "the parent must boot the workload's kernel cmdline, verity and runtime-source \
             tokens included, leaving claim identity for post-restore"
        );
        assert!(!parent.cmdline.contains("mvm.hostname="));
        assert_eq!(parent.kernel, workload.kernel);
        assert_eq!(parent.initramfs, workload.initramfs);
        assert_eq!(parent.vcpus, workload.vcpus);
        assert_eq!(parent.memory_mib, workload.memory_mib);
        assert_eq!(parent.mem_initial_mib, workload.mem_initial_mib);
    }

    /// An egress-allowing launch: the parent must boot the same shape cmdline
    /// the workload does, egress token included and claim identity excluded.
    ///
    /// `mvm.vsock_egress=1` starts the guest's in-guest egress client, and a
    /// restored child inherits it from the parent's saved memory rather than
    /// deriving its own — so a parent that dropped the token would hand every
    /// child a guest with no network at all, silently. Equality is the assertion
    /// (not "contains the token") because that is the property a child depends
    /// on: whatever the workload path adds, the parent adds too.
    #[test]
    fn a_parent_warmed_for_an_egress_allowing_launch_boots_the_launchs_own_cmdline() {
        let (_env, home, _lock) = isolated_home();
        let tmp = tempfile::tempdir().unwrap();
        let mut launch = sealed_launch(tmp.path(), home.path());
        launch.network_policy = mvm_core::network_policy::NetworkPolicy::allow_list(vec![
            mvm_core::network_policy::HostPort::new("api.example.com", 443),
        ]);
        let spec = standby_spec_for(&launch, tmp.path());
        assert!(
            spec.vsock_egress,
            "fixture must warm an egress-enabled parent, or it proves nothing"
        );

        let workload = workload_boot(&launch, &tmp.path().join("workload-a"));
        let parent_cfg = factory_parent_config(&launch, &spec).unwrap();
        let parent = factory_parent_spec(&parent_cfg, Path::new(&spec.vm_state_dir), fc_base);

        assert!(
            workload.cmdline.contains("mvm.vsock_egress=1"),
            "fixture must exercise the egress token: {}",
            workload.cmdline
        );
        assert_eq!(
            without_per_boot_tokens(&parent.cmdline),
            without_per_boot_tokens(&workload.cmdline),
            "a parent warmed for an egress-allowing launch must boot that launch's cmdline"
        );
        assert_eq!(
            parent.blocks, workload.blocks,
            "the disk stack must still match — the policy changes no device"
        );
    }

    /// The enablement the parent carries names no destination the launch asked
    /// for. A parent is shared across claims, so anything per-launch on it would
    /// reach the next claim; the allow-list is resolved host-side on the claimed
    /// child's own endpoint instead, and never rides the parent.
    #[test]
    fn the_parent_carries_the_egress_enablement_but_none_of_the_launchs_destinations() {
        let (_env, home, _lock) = isolated_home();
        let tmp = tempfile::tempdir().unwrap();
        let mut launch = sealed_launch(tmp.path(), home.path());
        launch.network_policy = mvm_core::network_policy::NetworkPolicy::allow_list(vec![
            mvm_core::network_policy::HostPort::new("api.example.com", 443),
            mvm_core::network_policy::HostPort::new("secret.internal", 8443),
        ]);
        let spec = standby_spec_for(&launch, tmp.path());

        let parent_cfg = factory_parent_config(&launch, &spec).unwrap();

        assert!(
            parent_cfg.network_policy.allows_egress(),
            "the parent must boot the launch's egress enablement"
        );
        let label = parent_cfg.network_policy.posture_label();
        for host in ["api.example.com", "secret.internal"] {
            assert!(
                !label.contains(host),
                "a shared parent must carry no launch destination, got: {label}"
            );
        }
        assert_ne!(
            parent_cfg.network_policy, launch.network_policy,
            "the parent must not be handed the launch's own policy"
        );
    }

    /// A deny-all launch's parent stays deny-all, and its cmdline still matches
    /// the workload's exactly — the enablement is a boolean, so flipping it must
    /// not perturb anything else.
    #[test]
    fn a_parent_warmed_for_a_deny_all_launch_boots_no_egress_client() {
        let (_env, home, _lock) = isolated_home();
        let tmp = tempfile::tempdir().unwrap();
        let launch = sealed_launch(tmp.path(), home.path());
        let spec = standby_spec_for(&launch, tmp.path());
        assert!(
            !spec.vsock_egress,
            "the default launch policy is deny-all, so no egress client is warmed"
        );

        let workload = workload_boot(&launch, &tmp.path().join("workload-a"));
        let parent_cfg = factory_parent_config(&launch, &spec).unwrap();
        let parent = factory_parent_spec(&parent_cfg, Path::new(&spec.vm_state_dir), fc_base);

        assert!(!parent_cfg.network_policy.allows_egress());
        assert!(
            !workload.cmdline.contains("mvm.vsock_egress"),
            "a deny-all workload boots no egress client: {}",
            workload.cmdline
        );
        assert_eq!(
            without_per_boot_tokens(&parent.cmdline),
            without_per_boot_tokens(&workload.cmdline)
        );
        assert!(!parent.cmdline.contains("mvm.hostname="));
    }

    /// The case that must never come out permissive. A secret-bearing workload's
    /// outbound traffic belongs to the host-side substitution endpoint, so a cold
    /// boot suppresses the guest's own egress client even though the policy allows
    /// egress. The pool keys on that *effective* value, so the parent warmed for
    /// such a launch suppresses it too; the remaining difference is only the
    /// child hostname delivered after restore.
    #[test]
    fn a_secret_bearing_launch_warms_a_parent_with_no_egress_client_either() {
        let (_env, home, _lock) = isolated_home();
        let tmp = tempfile::tempdir().unwrap();
        let mut launch = sealed_launch(tmp.path(), home.path());
        launch.network_policy = mvm_core::network_policy::NetworkPolicy::allow_list(vec![
            mvm_core::network_policy::HostPort::new("api.example.com", 443),
        ]);
        launch.plan_json = Some(mvm_vmm::host::egress_shared::plan_json_with_one_bound_secret());
        let spec = standby_spec_for(&launch, tmp.path());
        assert!(
            launch.network_policy.allows_egress(),
            "fixture must exercise the suppression, not a deny-all policy"
        );
        assert!(
            !spec.vsock_egress,
            "a secret-bearing launch must warm a parent with no egress client"
        );

        // The cold boot the parent is compared against: the admitted plan is
        // persisted beside the VM before it starts, which is what makes the
        // cold-boot token suppress itself.
        let workload_dir = tmp.path().join("workload-a");
        std::fs::create_dir_all(&workload_dir).unwrap();
        std::fs::write(
            workload_dir.join("plan.json"),
            launch.plan_json.as_deref().unwrap(),
        )
        .unwrap();
        let workload = workload_boot(&launch, &workload_dir);

        let parent_cfg = factory_parent_config(&launch, &spec).unwrap();
        let parent = factory_parent_spec(&parent_cfg, Path::new(&spec.vm_state_dir), fc_base);

        assert!(
            !workload.cmdline.contains("mvm.vsock_egress"),
            "a secret-bearing cold boot suppresses the guest egress client: {}",
            workload.cmdline
        );
        assert!(
            !parent.cmdline.contains("mvm.vsock_egress"),
            "so must the parent warmed for it: {}",
            parent.cmdline
        );
        assert_eq!(
            without_per_boot_tokens(&parent.cmdline),
            without_per_boot_tokens(&workload.cmdline)
        );
        assert!(!parent.cmdline.contains("mvm.hostname="));
        assert!(!parent_cfg.network_policy.allows_egress());
        assert_eq!(parent_cfg.plan_json, None, "a parent still holds no plan");
    }

    /// The same guard, stated against the concrete symptoms the live run
    /// recorded, so a failure names what the guest will miss rather than only
    /// that two values differ.
    ///
    /// The universal initramfs receives the roothashes and device paths over the
    /// authenticated activation channel, so the parent keeps those secrets off
    /// the kernel cmdline while still attaching the complete sealed disk stack.
    #[test]
    fn parent_carries_the_overlay_drives_and_runtime_tokens_the_guest_agent_needs() {
        let (_env, home, _lock) = isolated_home();
        let tmp = tempfile::tempdir().unwrap();
        let launch = sealed_launch(tmp.path(), home.path());
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

        assert!(
            parent
                .cmdline
                .contains("mvm.runtime_source_policy=required_overlay"),
            "parent cmdline missing runtime-source policy: {}",
            parent.cmdline
        );
        for legacy_token in [
            "mvm.roothash=",
            "mvm.data=/dev/vda",
            "mvm.hash=/dev/vdb",
            "mvm.runtime_roothash=",
            "mvm.runtime_data=/dev/vdc",
            "mvm.runtime_hash=/dev/vdd",
        ] {
            assert!(
                !parent.cmdline.contains(legacy_token),
                "parent cmdline leaked legacy token {legacy_token}: {}",
                parent.cmdline
            );
        }
    }

    /// The universal-initramfs counterpart: that PID 1 is handed the same
    /// roothashes and device paths over vsock, so carrying them on the cmdline
    /// would leak the boot secrets of a sealed image into a kernel argument the
    /// guest can read from `/proc/cmdline`.
    #[test]
    fn parent_on_the_universal_initramfs_carries_no_roothash_tokens() {
        let (_env, home, _lock) = isolated_home();
        let tmp = tempfile::tempdir().unwrap();
        let launch = sealed_launch(tmp.path(), home.path());
        let spec = standby_spec_for(&launch, tmp.path());
        let parent_cfg = factory_parent_config(&launch, &spec).unwrap();
        let parent = factory_parent_spec(&parent_cfg, Path::new(&spec.vm_state_dir), fc_base);

        assert!(
            crate::microvm::booted_with_universal_initramfs(&parent_cfg),
            "fixture must resolve as a universal-initramfs boot"
        );
        for legacy in [
            "mvm.roothash=",
            "mvm.data=/dev/vda",
            "mvm.hash=/dev/vdb",
            "mvm.runtime_roothash=",
            "mvm.runtime_data=/dev/vdc",
            "mvm.runtime_hash=/dev/vdd",
        ] {
            assert!(
                !parent.cmdline.contains(legacy),
                "parent cmdline carries legacy token {legacy}: {}",
                parent.cmdline
            );
        }
        assert!(
            parent
                .cmdline
                .contains("mvm.runtime_source_policy=required_overlay"),
            "parent cmdline missing runtime-source policy: {}",
            parent.cmdline
        );
    }

    #[test]
    fn parent_drops_every_workload_authority_field_the_launch_carried() {
        let (_env, home, _lock) = isolated_home();
        let tmp = tempfile::tempdir().unwrap();
        let mut launch = sealed_launch(tmp.path(), home.path());
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

        let parent = factory_parent_spec(&parent_cfg, Path::new(&spec.vm_state_dir), fc_base);
        // The enablement the guest boots with is all the parent takes from the
        // launch's policy. Its channels are stable, authority-free handoff
        // paths; no child endpoint or broker is attached until claim time.
        assert!(
            parent.vsock.iter().all(|port| {
                port.host_uds.to_string_lossy().contains("standby")
                    || port.service == GuestService::MachineControl
                    || port.service == GuestService::WorkloadExit
            }),
            "a factory parent may only wire stable standby paths"
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
    fn live_parent_uses_stable_handoff_channels_without_workload_endpoints() {
        let (_env, home, _lock) = isolated_home();
        let tmp = tempfile::tempdir().unwrap();
        let launch = sealed_launch(tmp.path(), home.path());
        let spec = standby_spec_for(&launch, tmp.path());
        let parent_cfg = factory_parent_config(&launch, &spec).unwrap();
        let parent = factory_parent_spec_live(&parent_cfg, Path::new(&spec.vm_state_dir), fc_base);

        let ports: std::collections::HashMap<_, _> = parent
            .vsock
            .iter()
            .map(|port| (port.service, port.host_uds.clone()))
            .collect();
        assert!(
            ports[&GuestService::MachineControl]
                .to_string_lossy()
                .contains("hvf-agent.sock")
        );
        assert!(
            ports[&GuestService::NetworkFlow]
                .to_string_lossy()
                .ends_with("standby-egress.sock")
        );
        assert!(
            ports[&GuestService::Broker]
                .to_string_lossy()
                .ends_with("standby-broker.sock")
        );
        assert!(
            ports[&GuestService::WorkloadExit]
                .to_string_lossy()
                .ends_with("workload.exit")
        );
    }

    #[test]
    fn parent_identity_and_resources_come_from_the_pool_record_not_the_launch() {
        let (_env, home, _lock) = isolated_home();
        let tmp = tempfile::tempdir().unwrap();
        let launch = sealed_launch(tmp.path(), home.path());
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
        let (_env, home, _lock) = isolated_home();
        let tmp = tempfile::tempdir().unwrap();
        let launch = sealed_launch(tmp.path(), home.path());
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
        let (_env, home, _lock) = isolated_home();
        let tmp = tempfile::tempdir().unwrap();
        let mut launch = sealed_launch(tmp.path(), home.path());
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
        let (_env, home, _lock) = isolated_home();
        let tmp = tempfile::tempdir().unwrap();
        let mut launch = sealed_launch(tmp.path(), home.path());
        launch.initrd_path = None;
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
        let (_env, home, _lock) = isolated_home();
        let tmp = tempfile::tempdir().unwrap();
        let launch = sealed_launch(tmp.path(), home.path());
        let spec = standby_spec_for(&launch, tmp.path());
        let parent_cfg = factory_parent_config(&launch, &spec).unwrap();
        let state_dir = PathBuf::from(&spec.vm_state_dir);
        let parent = factory_parent_spec(&parent_cfg, &state_dir, fc_base);
        assert_eq!(parent.console.log_path, state_dir.join("console.log"));
    }
}
