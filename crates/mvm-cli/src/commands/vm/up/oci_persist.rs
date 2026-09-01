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

use crate::commands::env::builder_vm::ensure_workload_kernel;
use crate::commands::vm::shared::VmStartParams;

use crate::commands::vm::readiness::record_vm_readiness;

use super::admission::{
    AdmitPlanForBootParams, admit_plan_for_boot_with_ingress, attach_guest_boot_config,
    emit_failed_if, emit_launched_if, enforce_kernel_if, enforce_shares_if, guest_profile_for_boot,
};
use super::policy::shares_from_volume_cfg;
use super::runtime_source::{
    attach_runtime_overlay_if_cached, attach_universal_initramfs_if_cached,
    emit_runtime_source_status,
};

fn preopen_console_for_profile(profile: &str) -> bool {
    profile == "dev"
}

/// Whether the admitted plan must be persisted to `<state_dir>/plan.json`
/// *before* `backend.start()`. Every backend whose `start()` reads that file
/// off disk to decide whether to stand up its egress endpoint needs the pre-start
/// persist:
///
/// - **Firecracker / libkrun / hvf / apple-container**: the runner-backed
///   endpoint reads `<state_dir>/plan.json` during endpoint setup. The
///   apple-container backend holds the same HVF runner, so its `start()` reads
///   the same file.
///
/// QEMU is excluded: it reads the in-memory config and must not overwrite the
/// persisted plan.
pub(crate) fn persists_plan_before_start(hypervisor: &str) -> bool {
    matches!(
        hypervisor,
        "firecracker" | "libkrun" | "hvf" | "apple-container"
    )
}

pub(in crate::commands) fn load_workload_ir(
    workload_ir_path: Option<&std::path::Path>,
) -> Result<Option<mvm_contract::ir::Workload>> {
    let Some(ir_path) = workload_ir_path else {
        return Ok(None);
    };
    let bytes = std::fs::read(ir_path)
        .with_context(|| format!("reading workload IR at {}", ir_path.display()))?;
    let workload: mvm_contract::ir::Workload = serde_json::from_slice(&bytes)
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
    /// Loopback ingress mappings persisted with the machine.
    pub ports: &'a [String],
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
    /// The machine spec's resolved permission set, baked into the signed plan
    /// on every start. Its egress dimension is already reflected in
    /// [`network_policy`](Self::network_policy), which the caller derived from
    /// the same spec.
    pub grants: Option<mvm_contract::grants::Grants>,
}

fn machine_port_ingress(ports: &[String]) -> Result<Vec<mvm_core::plan::IngressMapping>> {
    ports
        .iter()
        .enumerate()
        .map(|(index, mapping)| {
            let (host, guest) = crate::commands::shared::parse_port_spec(mapping)?;
            let mapping_id = u16::try_from(index + 1)
                .context("too many declared ingress mappings for the signed plan")?;
            mvm_core::plan::IngressMapping::builder()
                .mapping_id(mapping_id)
                .protocol(mvm_core::plan::IngressProtocol::Tcp)
                .host_addr("127.0.0.1")
                .host_port(host)
                .guest_addr("127.0.0.1")
                .guest_port(guest)
                .transform(mvm_core::plan::IngressTransform::Opaque)
                .build()
                .with_context(|| format!("lowering declared ingress mapping {mapping:?}"))
        })
        .collect()
}

/// Resolve the initrd a persistent OCI boot should carry.
///
/// Sealed OCI boots rely on the universal initramfs; the legacy per-rootfs
/// verity initrd is no longer supported. The universal initramfs attach step
/// later in the boot sets `initrd_path`, so this function returns `None` and
/// lets that step own the initramfs.
///
/// This is the boot-policy contract surface the dev-only conformance harness
/// drives directly; it is re-exported at `mvm_cli::boot_policy` for that
/// harness and is not a general-purpose API.
pub fn persistent_oci_effective_initrd(_rootfs_path: &std::path::Path) -> Result<Option<String>> {
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
        mut cpus,
        memory_mib,
        mem_initial_mib,
        volumes,
        network_policy,
        ports,
        backend_name,
        no_supervisor,
        kernel_path,
        agent_verb,
        has_ad_hoc_argv,
        grants,
    } = params;
    validate_vm_name(name).with_context(|| format!("Invalid VM name: {:?}", name))?;
    if let Some(granted) = mvm_client::clamp_vcpus_for_backend(backend_name, cpus) {
        crate::ui::warn(&format!(
            "{backend_name} supports at most {granted} vCPU(s); {cpus} requested, booting with {granted}"
        ));
        tracing::info!(
            backend = backend_name,
            requested = cpus,
            granted,
            "vcpu request clamped to the backend ceiling"
        );
        cpus = granted;
    }
    let mut prepared_volumes =
        super::super::volume::merge_registered_volumes_for_launch(name, volumes)
            .context("resolving registered local volumes before admission")?;
    let volumes = &prepared_volumes.volumes;
    register_vm_name(name, "default");
    let (verity_path, roothash) =
        mvm_runtime::microvm::probe_verity_sidecar(&rootfs_path.to_string_lossy());
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
        ensure_workload_kernel()?
    };
    let initrd_path = persistent_oci_effective_initrd(rootfs_path)?;

    let admission_ledger = InMemoryNonceLedger::new();
    let ingress = machine_port_ingress(ports)?;
    let admission = admit_plan_for_boot_with_ingress(
        AdmitPlanForBootParams {
            network_mode: crate::commands::machine::preflight_network(),
            tenant: "local",
            vm_name: name,
            backend_name,
            rootfs_path,
            kernel_path: Some(std::path::Path::new(&kernel_path)),
            precomputed_image_sha256: None,
            boot_artifact_identity: None,
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
            ),
            services: Vec::new(),
            grants,
            // The typed kind of the backend this start resolved, so the grant gate
            // measures a declared bound against the mechanisms that tier has rather
            // than refusing for want of an answer.
            backend_kind: Some(mvm_client::backend_kind_for(backend_name)),
            entrypoint: crate::commands::vm::entrypoint_resolve::ResolvedEntrypoint::unresolved(
                "the persistent OCI start path resolves no entrypoint",
            ),
        },
        ingress,
    )?;
    let mut start_config = VmStartParams::builder()
        .name(name.to_string())
        .rootfs_path(rootfs_path.display().to_string())
        .vmlinux_path(kernel_path)
        .initrd_path(initrd_path)
        .verity_path(verity_path)
        .roothash(roothash)
        .revision_hash(resolved_digest.to_string())
        .flake_ref(format!("oci:{image_label}"))
        .profile(profile.to_string())
        .cpus(cpus)
        .memory_mib(memory_mib)
        .mem_initial_mib(mem_initial_mib)
        .volumes(volumes)
        .config_files(&[])
        .secret_files(&[])
        .port_mappings(&[])
        // Persistent named machines are long-lived; they are not transient
        // auto-named launches and are never claimed from the warm standby pool.
        .warm_pool_size(0)
        .network_policy(network_policy)
        .build()?
        .into_start_config();
    // Only dev-profile machines can be attached to later with `machine shell`
    // or `machine console`. Keep the host-side console listeners absent for
    // sealed production boots; the guest profile and verb grant remain the
    // authoritative RPC gates as well.
    start_config.dev_console = preopen_console_for_profile(profile);
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
    // Against the config the backend is about to be handed, not the local the
    // plan was synthesized from — that is what makes this a check rather than a
    // restatement of what admission already believed.
    enforce_kernel_if(
        &admission,
        start_config
            .kernel_path
            .as_deref()
            .map(std::path::Path::new),
    )?;
    // VMM selection + workload-support check + start move behind the facade; the
    // admission gate (above) and the launched/failed emits stay here.
    if let Err(err) = mvm_client::start_prepared(backend_name, &start_config) {
        let err = anyhow::anyhow!("{err}");
        emit_failed_if(&admission, "backend-start", &err);
        return Err(err);
    }
    prepared_volumes.commit();
    // After the start, because a cgroup quota is read back off a process that
    // does not exist until then. This is the call that puts the backend's
    // `apply_grants` on the path `mvmctl` boots: without it the tier is
    // computed correctly and reported to nobody.
    super::grants_report::report_enforced_grants(&admission, backend_name, name);
    emit_launched_if(&admission, backend_name, true);
    record_vm_readiness(name, InstanceReadiness::LaunchAccepted);
    mvm_core::audit_emit!(VmStart, vm: name);
    Ok(())
}

#[cfg(test)]
mod persistent_oci_boot_tests {
    static ENV_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    use mvm_core::util::test_env::TestEnv;

    #[test]
    fn machine_ports_lower_to_admitted_flowmux_ingress() {
        let mappings = super::machine_port_ingress(&["18080:80".into(), "8443:443".into()])
            .expect("valid CLI ports lower to ingress mappings");

        assert_eq!(mappings.len(), 2);
        assert_eq!(mappings[0].mapping_id, 1);
        assert_eq!(mappings[0].host_addr, "127.0.0.1");
        assert_eq!(mappings[0].host_port, 18080);
        assert_eq!(mappings[0].guest_addr, "127.0.0.1");
        assert_eq!(mappings[0].guest_port, 80);
        assert_eq!(mappings[0].protocol, mvm_core::plan::IngressProtocol::Tcp);
        assert_eq!(
            mappings[0].transform,
            mvm_core::plan::IngressTransform::Opaque
        );
        assert_eq!(mappings[1].mapping_id, 2);
        assert_eq!(mappings[1].host_port, 8443);
        assert_eq!(mappings[1].guest_port, 443);
    }

    #[test]
    fn persistent_oci_console_preopen_is_limited_to_dev_profile() {
        assert!(super::preopen_console_for_profile("dev"));
        assert!(!super::preopen_console_for_profile("prod"));
        assert!(!super::preopen_console_for_profile("sealed-prod"));
    }

    #[test]
    fn persistent_oci_required_overlay_returns_no_initrd() {
        let _env_lock = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let rootfs = dir.path().join("rootfs.ext4");
        let sibling = dir.path().join("rootfs.initrd");
        std::fs::write(&rootfs, b"rootfs").unwrap();
        // A sibling legacy initrd, if present, must be ignored.
        std::fs::write(&sibling, b"legacy-initrd").unwrap();

        let resolved = super::persistent_oci_effective_initrd(&rootfs).unwrap();

        assert_eq!(resolved, None, "legacy initrd must not be returned");
    }

    /// exactly the way the real build/install path lays it out.
    fn seed_warm_universal_initramfs(mvm_home: &std::path::Path) {
        let version = env!("CARGO_PKG_VERSION");
        let arch = mvm_core::arch::GuestArch::host();
        let source = mvm_home.join("source");
        std::fs::create_dir_all(&source).unwrap();
        // The installer verifies the image against its hash sidecar, so the
        // fixture has to match what the build emits: a real gzip stream, the
        // SHA-256 of the uncompressed payload, and the compressed length.
        let payload = b"cpio-payload";
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        std::io::Write::write_all(&mut encoder, payload).unwrap();
        let image = encoder.finish().unwrap();
        std::fs::write(source.join("initramfs.cpio.gz"), &image).unwrap();
        std::fs::write(
            source.join("initramfs.hash"),
            format!(
                "{}\n",
                hex::encode(<sha2::Sha256 as sha2::Digest>::digest(payload))
            ),
        )
        .unwrap();
        std::fs::write(source.join("initramfs.size"), format!("{}\n", image.len())).unwrap();
        std::fs::write(source.join("VERSION"), version).unwrap();

        let cache_root = mvm_home.join("cache").join("initramfs");
        mvm_build::initramfs::install_initramfs_into_cache(&source, &cache_root, version, arch)
            .unwrap();
        // A warm cache in a source checkout has to say what built it, or the
        // fingerprint eviction treats it as stale and discards it.
        if let Some(workspace_root) =
            crate::commands::runtime_overlay::runtime_overlay_source_checkout_root()
            && let Ok(fingerprint) =
                mvm_build::guest_agent_build::runtime_overlay_source_checkout_fingerprint(
                    &workspace_root,
                )
        {
            mvm_build::initramfs::record_source_fingerprint(
                &cache_root,
                version,
                arch,
                &fingerprint,
            )
            .unwrap();
        }
    }

    #[test]
    fn persistent_oci_warm_universal_initramfs_skips_legacy_resolution_without_sibling() {
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
        seed_warm_universal_initramfs(cache.path());

        let resolved = super::persistent_oci_effective_initrd(&rootfs).unwrap();

        // The universal initramfs attach step later in the boot supplies the
        // initramfs, so the effective initrd is always empty here.
        assert_eq!(resolved, None);
    }

    #[test]
    fn persistent_oci_warm_universal_initramfs_skips_source_checkout_verity_build() {
        let _env_lock = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let Some(_workspace_root) =
            crate::commands::runtime_overlay::runtime_overlay_source_checkout_root()
        else {
            // The source-checkout branch only exists in a source checkout.
            return;
        };

        let dir = tempfile::tempdir().unwrap();
        let rootfs = dir.path().join("rootfs.ext4");
        let sibling = dir.path().join("rootfs.initrd");
        std::fs::write(&rootfs, b"rootfs").unwrap();
        std::fs::write(&sibling, b"initrd").unwrap();

        let cache = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(cache.path());
        env.set(
            crate::commands::runtime_overlay::RUNTIME_OVERLAY_ACQUIRE_MODE_ENV,
            "build",
        );
        seed_warm_universal_initramfs(cache.path());

        let resolved = super::persistent_oci_effective_initrd(&rootfs).unwrap();

        // Source-checkout mode previously refreshed a legacy verity initrd.
        // That path is no longer supported; the universal initramfs attach
        // step owns the initramfs, so no initrd is resolved here.
        assert_eq!(resolved, None);
    }
}

#[cfg(test)]
mod persists_plan_before_start_tests {
    use super::*;

    #[test]
    fn persists_plan_before_start_covers_the_substitution_backends() {
        // The substitution endpoint reads <state_dir>/plan.json inside start() to
        // decide whether to spawn, so every backend that spawns it must persist the
        // plan first — including the hvf backend and the apple-container backend,
        // which holds the same HVF runner. QEMU must not (it would
        // overwrite the in-memory config).
        for hv in ["firecracker", "libkrun", "hvf", "apple-container"] {
            assert!(
                persists_plan_before_start(hv),
                "{hv} spawns the substitution endpoint and must persist plan.json"
            );
        }
        assert!(!persists_plan_before_start("qemu"));
        assert!(!persists_plan_before_start("mock"));
    }
}
