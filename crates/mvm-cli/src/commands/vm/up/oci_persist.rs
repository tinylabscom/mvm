//! Persistent-machine boot path for OCI-image / manifest-backed VMs —
//! resolves the runtime-source policy, the effective kernel/initrd, and
//! runs admission before handing the prepared `VmStartConfig` to the
//! selected backend.

use anyhow::{Context, Result};

use mvm_core::domain::instance::InstanceReadiness;
use mvm_core::naming::validate_vm_name;
use mvm_hostd::plan_admission::{
    InMemoryNonceLedger, populate_audit_substrate, stash_plan_for_bridge, thread_tenant_id,
};
use mvm_runtime::image;

use crate::commands::env::builder_vm::{ensure_workload_kernel, ensure_workload_verity_initrd};
use crate::commands::runtime_overlay::{RuntimeOverlayAcquireMode, runtime_overlay_acquire_mode};
use crate::commands::vm::shared::VmStartParams;

use crate::commands::vm::readiness::record_vm_readiness;

use super::admission::{
    AdmitPlanForBootParams, admit_plan_for_boot, attach_guest_boot_config, emit_failed_if,
    emit_launched_if, enforce_shares_if, guest_profile_for_boot,
};
use super::kernel::persistent_oci_uses_prod_kernel;
use super::policy::shares_from_volume_cfg;
use super::runtime_source::{
    attach_runtime_overlay_if_cached, attach_universal_initramfs_if_cached,
    emit_runtime_source_status,
};

/// Whether the admitted plan must be persisted to `<state_dir>/plan.json`
/// *before* `backend.start()`. Every backend whose `start()` reads that file
/// off disk to decide whether to stand up its egress endpoint needs the pre-start
/// persist:
///
/// - **Firecracker / libkrun / hvf**: the runner-backed endpoint reads
///   `<state_dir>/plan.json` during endpoint setup.
///
/// QEMU is excluded: it reads the in-memory config and must not overwrite the
/// persisted plan.
pub(crate) fn persists_plan_before_start(hypervisor: &str) -> bool {
    matches!(hypervisor, "firecracker" | "libkrun" | "hvf")
}

pub(in crate::commands::vm) fn load_workload_ir(
    workload_ir_path: Option<&std::path::Path>,
) -> Result<Option<mvm_protocol::ir::Workload>> {
    let Some(ir_path) = workload_ir_path else {
        return Ok(None);
    };
    let bytes = std::fs::read(ir_path)
        .with_context(|| format!("reading workload IR at {}", ir_path.display()))?;
    let workload: mvm_protocol::ir::Workload = serde_json::from_slice(&bytes)
        .with_context(|| format!("parsing workload IR at {}", ir_path.display()))?;
    Ok(Some(workload))
}

pub(in crate::commands) struct PersistentImageStartParams<'a> {
    pub name: &'a str,
    pub image_label: &'a str,
    pub resolved_digest: &'a str,
    pub rootfs_path: &'a std::path::Path,
    pub profile: &'a str,
    pub cpus: u32,
    pub memory_mib: u32,
    pub mem_initial_mib: Option<u32>,
    pub volumes: &'a [image::RuntimeVolume],
    pub network_policy: mvm_core::network_policy::NetworkPolicy,
    /// Concrete backend selected by the caller.
    pub backend_name: &'a str,
    /// Skip plan-admission signing (test escape).
    pub no_supervisor: bool,
    /// Pre-built kernel path: skips `ensure_workload_kernel` when set.
    pub kernel_path: Option<String>,
    /// Raw `--agent-verb` strings from the CLI. Empty ⇒ use the computed
    /// sealed-prod default.
    pub agent_verb: Vec<String>,
    /// True when the caller will run a trailing `-- argv` command after boot
    /// (i.e. the machine is booted only to exec an ad-hoc command). An ad-hoc
    /// command issues the DevOnly `Exec` verb, so the admitted plan must NOT
    /// carry an attenuated ProdSafe-only grant. Baked-entrypoint boots (no
    /// trailing argv, non-dev profile) may still receive the grant.
    pub has_ad_hoc_argv: bool,
}

fn persistent_oci_rootfs_requires_overlay_policy(rootfs_path: &std::path::Path) -> bool {
    let runtime_lean = rootfs_path
        .parent()
        .and_then(|dir| {
            mvm_build::builder_vm::GuestSidecar::read_from_dir(dir)
                .ok()
                .flatten()
        })
        .map(|sidecar| sidecar.runtime_lean)
        .unwrap_or(false);
    let (verity_path, roothash) =
        mvm_runtime::microvm::probe_verity_sidecar(&rootfs_path.to_string_lossy());
    runtime_lean && verity_path.is_some() && roothash.is_some()
}

pub(crate) fn persistent_oci_effective_initrd(
    rootfs_path: &std::path::Path,
    runtime_source_policy: mvm_core::vm_backend::RuntimeSourcePolicy,
) -> Result<Option<String>> {
    if runtime_source_policy == mvm_core::vm_backend::RuntimeSourcePolicy::RequiredOverlay
        && runtime_overlay_acquire_mode() == RuntimeOverlayAcquireMode::BuildFromSourceCheckout
        && crate::commands::env::builder_vm::find_builder_vm_flake_is_source_checkout()
    {
        return Ok(Some(ensure_workload_verity_initrd()?));
    }
    let sibling = rootfs_path
        .parent()
        .map(|dir| dir.join("rootfs.initrd"))
        .filter(|path| path.is_file())
        .map(|path| path.display().to_string());
    if sibling.is_some() {
        return Ok(sibling);
    }
    if runtime_source_policy == mvm_core::vm_backend::RuntimeSourcePolicy::RequiredOverlay {
        return Ok(Some(ensure_workload_verity_initrd()?));
    }
    Ok(None)
}

fn register_vm_name(vm_name: &str, network_name: &str) {
    // Through the client boundary: mvm-client owns the host name-registry reach
    // (load → deregister-stale → register → save), so the CLI stays off the
    // runtime crate's registry internals.
    mvm_client::register_machine(&mvm_client::MachineRegistration::minimal(
        vm_name,
        network_name,
    ));
}

pub(in crate::commands) fn start_persistent_oci_machine(
    params: PersistentImageStartParams<'_>,
) -> Result<()> {
    let PersistentImageStartParams {
        name,
        image_label,
        resolved_digest,
        rootfs_path,
        profile,
        cpus,
        memory_mib,
        mem_initial_mib,
        volumes,
        network_policy,
        backend_name,
        no_supervisor,
        kernel_path,
        agent_verb,
        has_ad_hoc_argv,
    } = params;
    validate_vm_name(name).with_context(|| format!("Invalid VM name: {:?}", name))?;
    register_vm_name(name, "default");
    let image_sealed = crate::commands::vm::agent_verbs::image_is_sealed(rootfs_path);
    let overlay_required_oci = persistent_oci_rootfs_requires_overlay_policy(rootfs_path);
    let (verity_path, roothash) =
        mvm_runtime::microvm::probe_verity_sidecar(&rootfs_path.to_string_lossy());
    let runtime_source_policy = mvm_core::vm_backend::select_runtime_source_policy(
        mvm_core::vm_backend::RuntimeSourcePolicySelection {
            backend_name: Some(backend_name),
            sealed: image_sealed || overlay_required_oci,
            root_strategy: Some(mvm_core::vm_backend::RuntimeSourceRootStrategy::BlockExt4),
            launch_kind: mvm_core::vm_backend::RuntimeSourceLaunchKind::WorkloadImage,
        },
    );
    let kernel_path = if let Some(k) = kernel_path {
        k
    } else {
        // Required-overlay OCI boots must stay on the workload/prod kernel lane
        // even if the machine profile is `dev`, otherwise a runtime-lean sealed
        // root can silently boot with a dev-tier kernel cache fallback.
        //
        // The rootfs is supplied (OCI image / manifest); we need only a kernel.
        // Resolve just the workload kernel — same as the transient OCI path
        // (`exec.rs`) — rather than building/downloading a whole default-microvm
        // image whose rootfs we'd discard.
        ensure_workload_kernel(persistent_oci_uses_prod_kernel(
            profile,
            runtime_source_policy,
        ))?
    };
    let initrd_path = persistent_oci_effective_initrd(rootfs_path, runtime_source_policy)?;

    let admission_ledger = InMemoryNonceLedger::new();
    let admission = admit_plan_for_boot(AdmitPlanForBootParams {
        tenant: "local",
        vm_name: name,
        backend_name,
        rootfs_path,
        precomputed_image_sha256: None,
        cpus,
        mem_mib: u64::from(memory_mib),
        seccomp_tier: mvm_core::plan::PlanSeccompTier::Standard,
        secret_release: mvm_core::plan::SecretReleasePolicy::default(),
        secrets: vec![],
        no_supervisor,
        ledger: &admission_ledger,
        keys_dir: None,
        audit_dir: None,
        policy_dir: None,
        bundle_pin: None,
        deps_volume: None,
        shares: shares_from_volume_cfg(volumes),
        redaction: mvm_core::policy::RedactionPolicy::default(),
        network_policy: network_policy.clone(),
        agent_verb_override: agent_verb.to_vec(),
        // Persistent machines carrying a trailing argv run an ad-hoc Exec (DevOnly);
        // they must not receive an attenuated ProdSafe-only grant. Baked-entrypoint
        // boots (no argv, non-dev profile) keep the grant.
        restrict_agent_verbs: crate::commands::vm::agent_verbs::grant_eligible(
            false,
            has_ad_hoc_argv,
            profile == "dev",
            image_sealed,
        ),
        services: Vec::new(),
    })?;
    let mut start_config = VmStartParams {
        name: name.to_string(),
        rootfs_path: rootfs_path.display().to_string(),
        vmlinux_path: kernel_path,
        initrd_path,
        verity_path,
        roothash,
        revision_hash: resolved_digest.to_string(),
        flake_ref: format!("oci:{image_label}"),
        profile: Some(profile.to_string()),
        cpus,
        memory_mib,
        mem_initial_mib,
        volumes,
        config_files: &[],
        secret_files: &[],
        port_mappings: &[],
        // Persistent named machines are long-lived; they are not transient
        // auto-named launches and are never claimed from the warm standby pool.
        warm_pool_size: 0,
        network_policy,
    }
    .into_start_config();
    start_config.runtime_source_policy = runtime_source_policy;
    // A persistent named/detached machine is dev-accessible for its lifetime:
    // `machine run -t` boots through here, and `machine shell` / `machine
    // console` attach to it later. Pre-open the interactive-console data range
    // so those attaches reach the agent's dynamic data port on the
    // per-port-UDS backends (libkrun, HVF). Claim 15 still bars a sealed prod
    // guest at the agent + `enforce_accessible_gate`, leaving the listeners
    // inert there.
    start_config.dev_console = true;
    attach_runtime_overlay_if_cached(&mut start_config, backend_name)?;
    attach_universal_initramfs_if_cached(&mut start_config)?;
    emit_runtime_source_status(&start_config);
    if let Some(ctx) = admission.as_ref() {
        thread_tenant_id(&mut start_config, &ctx.admitted);
        populate_audit_substrate(&mut start_config, &ctx.admitted, ctx.policy_bundle.as_ref())?;
        let guest_profile = guest_profile_for_boot(profile == "dev", rootfs_path);
        attach_guest_boot_config(&mut start_config, ctx, guest_profile)?;
        if persists_plan_before_start(backend_name) {
            stash_plan_for_bridge(&start_config)?;
        }
    }
    enforce_shares_if(&admission, &start_config.volumes)?;
    // VMM selection + workload-support check + start move behind the facade; the
    // admission gate (above) and the launched/failed emits stay here.
    if let Err(err) = mvm_client::start_prepared(backend_name, &start_config) {
        let err = anyhow::anyhow!("{err}");
        emit_failed_if(&admission, "backend-start", &err);
        return Err(err);
    }
    emit_launched_if(&admission, backend_name, true);
    record_vm_readiness(name, InstanceReadiness::LaunchAccepted);
    mvm_core::audit_emit!(VmStart, vm: name);
    Ok(())
}

#[cfg(test)]
mod runtime_source_policy_for_workload_boot_tests {
    static ENV_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    use mvm_core::util::test_env::TestEnv;
    use mvm_core::vm_backend::RuntimeSourcePolicy;

    #[test]
    fn firecracker_sealed_boot_requires_overlay() {
        assert_eq!(
            mvm_core::vm_backend::select_runtime_source_policy(
                mvm_core::vm_backend::RuntimeSourcePolicySelection {
                    backend_name: Some("firecracker"),
                    sealed: true,
                    root_strategy: Some(mvm_core::vm_backend::RuntimeSourceRootStrategy::BlockExt4),
                    launch_kind: mvm_core::vm_backend::RuntimeSourceLaunchKind::WorkloadImage,
                }
            ),
            RuntimeSourcePolicy::RequiredOverlay
        );
    }

    #[test]
    fn firecracker_unsealed_block_boot_requires_overlay() {
        // Unsealed block workloads now require the overlay too — the overlay is
        // the single source of guest binaries, so a missing overlay fails closed
        // instead of falling back to the baked rootfs copy.
        assert_eq!(
            mvm_core::vm_backend::select_runtime_source_policy(
                mvm_core::vm_backend::RuntimeSourcePolicySelection {
                    backend_name: Some("firecracker"),
                    sealed: false,
                    root_strategy: Some(mvm_core::vm_backend::RuntimeSourceRootStrategy::BlockExt4),
                    launch_kind: mvm_core::vm_backend::RuntimeSourceLaunchKind::WorkloadImage,
                }
            ),
            RuntimeSourcePolicy::RequiredOverlay
        );
    }

    #[test]
    fn libkrun_sealed_boot_requires_overlay() {
        assert_eq!(
            mvm_core::vm_backend::select_runtime_source_policy(
                mvm_core::vm_backend::RuntimeSourcePolicySelection {
                    backend_name: Some("libkrun"),
                    sealed: true,
                    root_strategy: Some(mvm_core::vm_backend::RuntimeSourceRootStrategy::BlockExt4),
                    launch_kind: mvm_core::vm_backend::RuntimeSourceLaunchKind::WorkloadImage,
                }
            ),
            RuntimeSourcePolicy::RequiredOverlay
        );
    }

    #[test]
    fn persistent_oci_runtime_lean_verity_root_requires_overlay_policy() {
        let dir = tempfile::tempdir().unwrap();
        let rootfs = dir.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"rootfs").unwrap();
        std::fs::write(dir.path().join("rootfs.verity"), b"verity").unwrap();
        std::fs::write(
            dir.path().join("rootfs.roothash"),
            format!("{}\n", "a".repeat(64)),
        )
        .unwrap();
        mvm_build::builder_vm::GuestSidecar::for_oci_run("oci:test", true, true)
            .write_to_dir(dir.path())
            .unwrap();

        assert!(super::persistent_oci_rootfs_requires_overlay_policy(
            &rootfs
        ));
    }

    #[test]
    fn persistent_oci_rootfs_without_verity_stays_prefer_overlay() {
        let dir = tempfile::tempdir().unwrap();
        let rootfs = dir.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"rootfs").unwrap();
        mvm_build::builder_vm::GuestSidecar::for_oci_run("oci:test", true, true)
            .write_to_dir(dir.path())
            .unwrap();

        assert!(!super::persistent_oci_rootfs_requires_overlay_policy(
            &rootfs
        ));
    }

    #[test]
    fn persistent_oci_required_overlay_prefers_sibling_initrd() {
        let _env_lock = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let rootfs = dir.path().join("rootfs.ext4");
        let initrd = dir.path().join("rootfs.initrd");
        std::fs::write(&rootfs, b"rootfs").unwrap();
        std::fs::write(&initrd, b"initrd").unwrap();
        let mut env = TestEnv::new();
        env.set(
            crate::commands::runtime_overlay::RUNTIME_OVERLAY_ACQUIRE_MODE_ENV,
            "download",
        );

        let resolved =
            super::persistent_oci_effective_initrd(&rootfs, RuntimeSourcePolicy::RequiredOverlay)
                .unwrap();

        assert_eq!(
            resolved.as_deref(),
            Some(initrd.to_str().expect("utf-8 initrd path"))
        );
    }

    #[test]
    fn persistent_oci_required_overlay_falls_back_to_cached_verity_initrd() {
        let _env_lock = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let rootfs = dir.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"rootfs").unwrap();

        let cache = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(cache.path());
        env.set(
            crate::commands::runtime_overlay::RUNTIME_OVERLAY_ACQUIRE_MODE_ENV,
            "download",
        );

        let initrd_dir = cache
            .path()
            .join("cache")
            .join("verity-initrd")
            .join(env!("CARGO_PKG_VERSION"))
            .join(if cfg!(target_arch = "aarch64") {
                "aarch64"
            } else {
                "x86_64"
            });
        std::fs::create_dir_all(&initrd_dir).unwrap();
        std::fs::write(initrd_dir.join("rootfs.initrd"), b"initrd").unwrap();

        let resolved =
            super::persistent_oci_effective_initrd(&rootfs, RuntimeSourcePolicy::RequiredOverlay)
                .unwrap();

        assert_eq!(
            resolved.as_deref(),
            Some(
                initrd_dir
                    .join("rootfs.initrd")
                    .to_str()
                    .expect("utf-8 cached initrd path")
            )
        );
    }

    #[test]
    fn persistent_oci_required_overlay_source_checkout_ignores_stale_sibling_initrd() {
        let _env_lock = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let Some(workspace_root) =
            crate::commands::runtime_overlay::runtime_overlay_source_checkout_root()
        else {
            return;
        };

        let dir = tempfile::tempdir().unwrap();
        let rootfs = dir.path().join("rootfs.ext4");
        let sibling = dir.path().join("rootfs.initrd");
        std::fs::write(&rootfs, b"rootfs").unwrap();
        std::fs::write(&sibling, b"stale-initrd").unwrap();

        let cache = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(cache.path());
        env.set(
            crate::commands::runtime_overlay::RUNTIME_OVERLAY_ACQUIRE_MODE_ENV,
            "build",
        );

        let initrd_dir = cache
            .path()
            .join("cache")
            .join("verity-initrd")
            .join(env!("CARGO_PKG_VERSION"))
            .join(if cfg!(target_arch = "aarch64") {
                "aarch64"
            } else {
                "x86_64"
            });
        std::fs::create_dir_all(&initrd_dir).unwrap();
        std::fs::write(initrd_dir.join("rootfs.initrd"), b"fresh-initrd").unwrap();
        let fingerprint =
            mvm_build::guest_agent_build::runtime_overlay_source_checkout_fingerprint(
                &workspace_root,
            )
            .unwrap();
        std::fs::write(
            initrd_dir.join("SOURCE_FINGERPRINT"),
            format!("{fingerprint}\n"),
        )
        .unwrap();

        let resolved =
            super::persistent_oci_effective_initrd(&rootfs, RuntimeSourcePolicy::RequiredOverlay)
                .unwrap();

        assert_eq!(
            resolved.as_deref(),
            Some(
                initrd_dir
                    .join("rootfs.initrd")
                    .to_str()
                    .expect("utf-8 cached initrd path")
            )
        );
    }

    #[test]
    fn persistent_oci_required_overlay_forces_prod_kernel_even_on_dev_profile() {
        assert!(super::super::kernel::persistent_oci_uses_prod_kernel(
            "dev",
            RuntimeSourcePolicy::RequiredOverlay
        ));
    }

    #[test]
    fn persistent_oci_prefer_overlay_keeps_dev_kernel_lane_for_dev_profile() {
        assert!(!super::super::kernel::persistent_oci_uses_prod_kernel(
            "dev",
            RuntimeSourcePolicy::PreferOverlay
        ));
    }

    #[test]
    fn persistent_oci_non_dev_profiles_keep_prod_kernel_lane() {
        assert!(super::super::kernel::persistent_oci_uses_prod_kernel(
            "prod",
            RuntimeSourcePolicy::PreferOverlay
        ));
    }
}

#[cfg(test)]
mod persists_plan_before_start_tests {
    use super::*;

    #[test]
    fn persists_plan_before_start_covers_the_substitution_backends() {
        // The substitution endpoint reads <state_dir>/plan.json inside start() to
        // decide whether to spawn, so every backend that spawns it must persist the
        // plan first — including the hvf backend. QEMU must not (it would
        // overwrite the in-memory config).
        for hv in ["firecracker", "libkrun", "hvf"] {
            assert!(
                persists_plan_before_start(hv),
                "{hv} spawns the substitution endpoint and must persist plan.json"
            );
        }
        assert!(!persists_plan_before_start("qemu"));
        assert!(!persists_plan_before_start("mock"));
    }
}
