//! Persistent-machine boot path for OCI-image / manifest-backed VMs —
//! resolves the runtime-source policy, the effective kernel/initrd, and
//! runs admission before handing the prepared `VmStartConfig` to the
//! selected backend.

use anyhow::{Context, Result};

use mvm_core::domain::instance::InstanceReadiness;
use mvm_core::naming::validate_vm_name;
use mvm_hostd::plan_admission::InMemoryNonceLedger;

use crate::launch::start_params::VmStartParams;

use crate::record_readiness as record_vm_readiness;

use super::runtime_source::{
    attach_runtime_overlay_if_cached_version_verified, attach_universal_initramfs_if_cached,
    attach_universal_initramfs_with_verified_release, emit_runtime_source_status,
};
use crate::admission::policy::shares_from_volume_cfg;
use crate::admission::{
    AdmitPlanForBootParams, admit_plan_for_boot_configured_ingress, attach_guest_boot_config,
    emit_failed, emit_launched, guest_profile_for_boot,
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
pub use mvm_hostd::plan_admission::persists_plan_before_start;

pub use crate::admission::secrets::load_workload_ir;

pub struct PersistentImageStartParams<'a> {
    pub name: &'a str,
    pub image_label: &'a str,
    pub resolved_digest: &'a str,
    pub rootfs_path: &'a std::path::Path,
    pub profile: &'a str,
    pub cpus: u32,
    pub memory_mib: u32,
    pub mem_initial_mib: Option<u32>,
    /// The machine's volumes, already merged with its registered ones and
    /// leased for this launch. The leases are committed once the backend has
    /// started and released if it does not.
    pub prepared_volumes: crate::volume::LaunchPreparation,
    pub network_policy: mvm_core::network_policy::NetworkPolicy,
    /// Loopback ingress mappings persisted with the machine.
    pub ports: &'a [String],
    /// Concrete backend selected by the caller.
    pub backend_name: &'a str,
    /// The workload kernel to boot, or `None` for the in-memory mock, which
    /// boots nothing. Resolved by the
    /// caller: the CLI may build one through the builder VM, and a library
    /// embedder never builds.
    pub kernel_path: Option<String>,
    /// Raw `--agent-verb` strings from the CLI. Empty ⇒ use the computed
    /// sealed-prod default.
    pub agent_verb: Vec<String>,
    /// Opaque commitment persisted with and admitted for this machine.
    pub caller_commitment: Option<mvm_core::plan::CallerCommitment>,
    /// Publisher-verified image pack to bind on every start, if selected.
    pub registry_pack_image: Option<mvm_core::registry_pack::PackPin>,
    /// Initial committed project generation restored from the machine spec.
    pub policy_generation: Option<&'a mvm_core::plan::AssetIdentity>,
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
    pub mailbox: Option<mvm_contract::protocol::mailbox::MailboxGrant>,
    /// GPU remoting plane from the persisted spec (`--gpu` at create/start).
    pub gpu: bool,
    /// Optional host GPU ordinal persisted with the machine.
    pub gpu_device: Option<u32>,
    /// Local workload source directory to scan for project instruction files and
    /// policies on each start, when the persistent machine came from one.
    pub workload_dir: Option<&'a std::path::Path>,
    /// The machine's recorded secret references, already validated against
    /// the caller's secret service.
    pub secrets: crate::admission::secrets::ResolvedPlanSecrets,
    /// The backend that starts the VM, an instance of `backend_name`.
    pub backend: mvm_runtime::backend::AnyBackend,
}

/// The network mode every newly admitted networked workload uses: the
/// authenticated, host-mediated FlowMux endpoint. The raw-packet mode is
/// retired.
pub fn preflight_network() -> mvm_contract::plan::NetworkMode {
    mvm_contract::plan::NetworkMode::HostVsockProxy
}

/// Parse a port mapping: `HOST:GUEST`, or a single port used on both sides.
pub fn parse_port_spec(spec: &str) -> Result<(u16, u16)> {
    if let Some((local, guest)) = spec.split_once(':') {
        let local: u16 = local
            .parse()
            .with_context(|| format!("invalid local port '{}'", local))?;
        let guest: u16 = guest
            .parse()
            .with_context(|| format!("invalid guest port '{}'", guest))?;
        Ok((local, guest))
    } else {
        let port: u16 = spec
            .parse()
            .with_context(|| format!("invalid port '{}'", spec))?;
        Ok((port, port))
    }
}

fn machine_port_ingress(ports: &[String]) -> Result<Vec<mvm_core::plan::IngressMapping>> {
    ports
        .iter()
        .enumerate()
        .map(|(index, mapping)| {
            let (host, guest) = parse_port_spec(mapping)?;
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
    crate::register_machine(&crate::MachineRegistration {
        vm_dir: mvm_core::config::vm_state_dir(vm_name)
            .to_string_lossy()
            .into_owned(),
        ..crate::MachineRegistration::minimal(vm_name, network_name)
    });
}

/// Admit and start a persistent machine. Returns the admitted plan the
/// machine booted under.
pub fn start_persistent_oci_machine(
    params: PersistentImageStartParams<'_>,
) -> Result<mvm_hostd::plan_admission::AdmittedPlan> {
    let lifecycle = mvm_runtime::vm::instance_snapshot::MachineLifecycleLock::acquire(params.name)?;
    start_persistent_with_prepared(params, None, &lifecycle)
}

pub(super) fn start_persistent_oci_machine_in_lifecycle(
    params: PersistentImageStartParams<'_>,
    lifecycle: &mvm_runtime::vm::instance_snapshot::MachineLifecycleLock,
) -> Result<mvm_hostd::plan_admission::AdmittedPlan> {
    start_persistent_with_prepared(params, None, lifecycle)
}

pub(super) fn start_prepared_persistent_oci_machine_in_lifecycle(
    params: PersistentImageStartParams<'_>,
    prepared: &crate::image_cache::prepared::ValidatedPrepared,
    lifecycle: &mvm_runtime::vm::instance_snapshot::MachineLifecycleLock,
) -> Result<mvm_hostd::plan_admission::AdmittedPlan> {
    crate::image_cache::prepared::require_backend(
        &prepared.selection,
        params.backend_name,
        params.backend.name(),
    )?;
    start_persistent_with_prepared(params, Some(prepared), lifecycle)
}

fn start_persistent_with_prepared<'a>(
    params: PersistentImageStartParams<'a>,
    prepared: Option<&'a crate::image_cache::prepared::ValidatedPrepared>,
    lifecycle: &mvm_runtime::vm::instance_snapshot::MachineLifecycleLock,
) -> Result<mvm_hostd::plan_admission::AdmittedPlan> {
    lifecycle
        .require_name(params.name)
        .map_err(mvm_hostd::plan_admission::CliStartFailure::StateNotOwned)?;
    lifecycle
        .require_cold_state()
        .map_err(mvm_hostd::plan_admission::CliStartFailure::StateNotOwned)?;
    // The steps of this one launch share a single check of the signed runtime
    // release; the next launch checks again.
    let _runtime_proofs = mvm_build::guest_runtime::evidence::LaunchProofScope::begin();
    let prepared_boot = prepare_persistent_boot(params, prepared)?;
    finish_admitted_persistent(prepared_boot, lifecycle)
}

struct PreparedPersistentBoot<'a> {
    backend: mvm_runtime::backend::AnyBackend,
    start_config: mvm_core::vm_backend::VmStartConfig,
    prepared_volumes: crate::volume::LaunchPreparation,
    /// The resolved policy the start config carries and the endpoint builds
    /// its gate from — the probe witnesses the gate this exact value admits.
    network_policy: mvm_core::network_policy::NetworkPolicy,
    source: PersistentAdmissionSource<'a>,
}

struct PersistentAdmissionSource<'a> {
    prepared: Option<&'a crate::image_cache::prepared::ValidatedPrepared>,
    rootfs_path: &'a std::path::Path,
    profile: &'a str,
    cpus: u32,
    ports: &'a [String],
    backend_name: &'a str,
    agent_verb: Vec<String>,
    caller_commitment: Option<mvm_core::plan::CallerCommitment>,
    registry_pack_image: Option<mvm_core::registry_pack::PackPin>,
    policy_generation: Option<&'a mvm_core::plan::AssetIdentity>,
    has_ad_hoc_argv: bool,
    grants: Option<mvm_contract::grants::Grants>,
    mailbox: Option<mvm_contract::protocol::mailbox::MailboxGrant>,
    workload_dir: Option<&'a std::path::Path>,
    resolved_secrets: crate::admission::secrets::ResolvedPlanSecrets,
    bundle_archive: Option<std::path::PathBuf>,
}

fn prepare_persistent_boot<'a>(
    params: PersistentImageStartParams<'a>,
    prepared: Option<&'a crate::image_cache::prepared::ValidatedPrepared>,
) -> Result<PreparedPersistentBoot<'a>> {
    let PersistentImageStartParams {
        name,
        image_label,
        resolved_digest,
        rootfs_path,
        profile,
        mut cpus,
        memory_mib,
        mem_initial_mib,
        prepared_volumes,
        network_policy,
        ports,
        backend_name,
        kernel_path,
        agent_verb,
        caller_commitment,
        registry_pack_image,
        policy_generation,
        has_ad_hoc_argv,
        grants,
        mailbox,
        gpu,
        gpu_device,
        workload_dir,
        secrets: resolved_secrets,
        backend,
    } = params;
    validate_vm_name(name).with_context(|| format!("Invalid VM name: {:?}", name))?;
    if policy_generation.is_some() {
        anyhow::ensure!(
            resolved_secrets.secrets.is_empty(),
            "committed persistent machines cannot start with secret references outside their stored policy"
        );
    }
    if let Some(granted) = crate::clamp_vcpus_for_backend(backend_name, cpus) {
        mvm_runtime::ui::warn(&format!(
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
    crate::admission::instructions::refuse_wasm_host_snapshots(
        backend.kind(),
        &prepared_volumes
            .volumes
            .iter()
            .filter_map(|volume| {
                volume.materialized_image.as_deref().map(|image| {
                    crate::admission::instructions::MaterializedMount {
                        host_path: std::path::PathBuf::from(&volume.host),
                        image_path: std::path::PathBuf::from(image),
                    }
                })
            })
            .collect::<Vec<_>>(),
    )?;
    let volumes = &prepared_volumes.volumes;
    register_vm_name(name, "default");
    let (verity_path, roothash) =
        mvm_runtime::microvm::probe_verity_sidecar(&rootfs_path.to_string_lossy());
    let initrd_path = persistent_oci_effective_initrd(rootfs_path)?;
    let bundle_archive = super::bundle_runtime::installed_archive_for_rootfs(rootfs_path)?;

    let mut start_config = VmStartParams::builder()
        .name(name.to_string())
        .rootfs_path(rootfs_path.display().to_string())
        .vmlinux_path(kernel_path.unwrap_or_default())
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
        .network_policy(network_policy.clone())
        .gpu(gpu)
        .gpu_device(gpu_device)
        .build()?
        .into_start_config();
    // Only dev-profile machines can be attached to later with `machine shell`
    // or `machine console`. Keep the host-side console listeners absent for
    // sealed production boots; the guest profile and verb grant remain the
    // authoritative RPC gates as well.
    start_config.dev_console = preopen_console_for_profile(profile);
    Ok(PreparedPersistentBoot {
        backend,
        start_config,
        prepared_volumes,
        network_policy,
        source: PersistentAdmissionSource {
            prepared,
            rootfs_path,
            profile,
            cpus,
            ports,
            backend_name,
            agent_verb,
            caller_commitment,
            registry_pack_image,
            policy_generation,
            has_ad_hoc_argv,
            grants,
            mailbox,
            workload_dir,
            resolved_secrets,
            bundle_archive,
        },
    })
}

#[cfg(unix)]
fn complete_writable_images(
    config: &mvm_core::vm_backend::VmStartConfig,
    images: &mut mvm_vmm::driver::prepared_disks::WritableVolumeImages,
) -> Result<()> {
    for volume in &config.volumes {
        if volume.read_only {
            continue;
        }
        let source = std::path::Path::new(volume.block_source());
        if images.iter().any(|(path, _)| path == source) {
            continue;
        }
        let size_mib = mvm_core::util::parse_human_size(&volume.size)?;
        let lock = mvm_build::builder_vm_runtime::ensure_persistent_volume_image(
            source,
            u64::from(size_mib) * 1024 * 1024,
            false,
        )?;
        if let Some(image) = lock.into_image() {
            images.push(image);
        }
    }
    Ok(())
}

fn finish_admitted_persistent(
    prepared_boot: PreparedPersistentBoot<'_>,
    lifecycle: &mvm_runtime::vm::instance_snapshot::MachineLifecycleLock,
) -> Result<mvm_hostd::plan_admission::AdmittedPlan> {
    let PreparedPersistentBoot {
        backend,
        start_config,
        mut prepared_volumes,
        network_policy,
        source,
    } = prepared_boot;
    let PersistentAdmissionSource {
        prepared,
        rootfs_path,
        profile,
        cpus,
        ports,
        backend_name,
        agent_verb,
        caller_commitment,
        registry_pack_image,
        policy_generation,
        has_ad_hoc_argv,
        grants,
        mailbox,
        workload_dir,
        resolved_secrets,
        bundle_archive,
    } = source;
    let name_label = start_config.name.clone();
    let name = name_label.as_str();
    #[cfg(unix)]
    let images = (|| -> Result<_> {
        let mut images = prepared_volumes.take_writable_images();
        complete_writable_images(&start_config, &mut images)?;
        Ok(images)
    })()?;
    #[cfg(not(unix))]
    let images = Vec::new();
    let instruction_mounts = prepared_volumes
        .volumes
        .iter()
        .filter_map(|volume| {
            volume.materialized_image.as_deref().map(|image| {
                crate::admission::instructions::MaterializedMount {
                    host_path: std::path::PathBuf::from(&volume.host),
                    image_path: std::path::PathBuf::from(image),
                }
            })
        })
        .collect::<Vec<_>>();
    let shares = shares_from_volume_cfg(&prepared_volumes.volumes);
    let configured_images_dir = mvm_build::image_source::configured_images_dir();
    let network_policy_for_admission = network_policy.clone();
    let dispatched = mvm_hostd::plan_admission::boot_vm(
        mvm_hostd::plan_admission::PreparePersistentParams {
            backend: &backend,
            config: start_config,
            writable_images: images,
            lifecycle,
        },
        |config| {
            let release = attach_runtime_overlay_if_cached_version_verified(
                config,
                backend_name,
                None,
                None,
            )?;
            match release {
                Some(release) => {
                    attach_universal_initramfs_with_verified_release(
                        config,
                        backend_name,
                        &release,
                    )?;
                    Ok(Some(release))
                }
                None => {
                    attach_universal_initramfs_if_cached(config, backend_name)?;
                    Ok(None)
                }
            }
        },
        |config, verified_runtime| {
            let admission_ledger = InMemoryNonceLedger::new();
            let ingress = machine_port_ingress(ports)?;
            let admission_params = AdmitPlanForBootParams {
                bundle_sizing: Default::default(),
                mailbox,
                gpu: config.gpu,
                instructions: crate::admission::InstructionSources::for_workload(workload_dir)
                    .with_mount_roots(&[])
                    .with_materialized_mounts(&instruction_mounts),
                outputs: Vec::new(),
                network_mode: preflight_network(),
                tenant: "local",
                vm_name: name,
                backend_name,
                configured_images_dir: configured_images_dir.as_deref(),
                rootfs_path,
                kernel_path: config.kernel_path.as_deref().map(std::path::Path::new),
                precomputed_image_sha256: None,
                boot_artifact_identity: None,
                runtime_config: Some(config),
                cpus,
                mem_mib: u64::from(config.memory_mib),
                seccomp_tier: mvm_core::plan::PlanSeccompTier::Standard,
                secret_release: resolved_secrets.secret_release,
                secrets: resolved_secrets.secrets,
                caller_commitment,
                ledger: &admission_ledger,
                keys_dir: None,
                audit_dir: None,
                policy_dir: None,
                bundle_pin: bundle_archive
                    .as_deref()
                    .map(crate::admission::BundlePin::boots),
                bundle_posture: None,
                deps_volume: None,
                shares,
                assets: registry_pack_image
                    .into_iter()
                    .map(crate::admission::AssetSpec::RegistryPack)
                    .chain(
                        policy_generation
                            .cloned()
                            .map(crate::admission::AssetSpec::CommittedPolicy),
                    )
                    .collect(),
                redaction: mvm_core::policy::RedactionPolicy::default(),
                network_policy: network_policy_for_admission,
                agent_verb_override: agent_verb,
                restrict_agent_verbs: crate::admission::agent_verbs::grant_eligible(
                    false,
                    has_ad_hoc_argv,
                    profile == "dev",
                ),
                services: Vec::new(),
                grants,
                backend_kind: Some(crate::backend_kind_for(backend_name)),
                entrypoint: crate::admission::entrypoint_resolve::ResolvedEntrypoint::for_launch(
                    rootfs_path,
                    has_ad_hoc_argv,
                ),
            };
            let admission = match (prepared, verified_runtime) {
                (Some(prepared), runtime) => crate::admission::admit_prepared_plan_for_boot(
                    admission_params,
                    ingress,
                    prepared,
                    runtime,
                ),
                (None, Some(runtime)) => {
                    crate::admission::admit_plan_for_boot_configured_ingress_with_verified_runtime(
                        admission_params,
                        ingress,
                        runtime,
                    )
                }
                (None, None) => admit_plan_for_boot_configured_ingress(admission_params, ingress),
            }?;
            for volume in &mut config.volumes {
                if admission
                    .admitted
                    .plan()
                    .shares
                    .iter()
                    .any(|share| share.host_path == volume.host && share.read_only)
                {
                    volume.read_only = true;
                }
            }
            emit_runtime_source_status(config);
            let guest_profile = guest_profile_for_boot(profile == "dev", rootfs_path);
            attach_guest_boot_config(config, &admission, guest_profile)?;
            let crate::admission::AdmissionContext {
                admitted,
                emitter,
                policy_bundle,
                host_signer_public_path,
            } = admission;
            Ok(mvm_hostd::plan_admission::PersistentAdmission {
                admitted,
                emitter,
                policy_bundle,
                continuation: host_signer_public_path,
            })
        },
    );
    let dispatched = retain_uncertain_dispatch_custody(dispatched, &mut prepared_volumes)?;
    let mvm_hostd::plan_admission::PreparedPersistent {
        vm_id,
        admission,
        config: dispatched_config,
    } = dispatched;
    let mvm_hostd::plan_admission::PersistentAdmission {
        admitted,
        emitter,
        policy_bundle,
        continuation: host_signer_public_path,
    } = admission;
    let admission = crate::admission::AdmissionContext {
        admitted,
        emitter,
        policy_bundle,
        host_signer_public_path,
    };
    let started = crate::boot::StartedVm::from_started(backend, vm_id);
    // Admission proves the signed policy verified; the probe proves the gate
    // the endpoint actually built from it took effect. It runs before the
    // guest-readiness wait and fails closed: a gate that cannot be witnessed
    // is rolled back exactly like a guest that never became ready.
    if let Err(error) = super::egress_gate_probe::require_running_gate(
        name,
        &started,
        admission.admitted.plan(),
        &network_policy,
    ) {
        let error = anyhow::Error::new(error);
        // The backend owns the abort. A failed abort means the VMM may still
        // hold block-device file descriptors, so the owner leases and
        // registry stay committed for recovery — the same unresolved-abort
        // shape the guest-readiness failure uses.
        let abort_is_unresolved = started.backend().abort_start(started.vm_id()).is_err();
        if abort_is_unresolved {
            prepared_volumes.commit();
        }
        audit_detached_readiness_failure(
            &admission,
            name,
            "egress-gate",
            &error,
            abort_is_unresolved,
        );
        if !abort_is_unresolved {
            // The failure record and session seal live under the runtime
            // state directory, so cleanup must follow audit finalization.
            if let Err(cleanup_error) =
                crate::local::cleanup_confirmed_launch_abort(name, lifecycle)
            {
                tracing::warn!(
                    error = %cleanup_error,
                    machine = name,
                    "removing runtime state after a failed egress-gate probe failed"
                );
            }
        }
        return Err(error);
    }
    let mailbox_posture = admission.admitted.mailbox_posture();
    // The guest asserts a mailbox exactly when the plan grants one, so the
    // host side starts here or the launch is rolled back.
    if let Err(error) = mvm_hostd::mailbox_process::serve_started(
        started.backend(),
        started.vm_id(),
        &dispatched_config,
        mailbox_posture.as_ref(),
    ) {
        return Err(finish_post_start_failure(
            &admission,
            &mut prepared_volumes,
            name,
            "mailbox-process",
            error,
            PostStartFailure::Mailbox,
            lifecycle,
        ));
    }
    // A backend accepting a start only means its host process was spawned.
    // Detached callers must not observe success until the authenticated guest
    // control plane is actually serving; failure rolls the partial start back
    // before any launch acceptance, lease commit, or launched audit record.
    if let Err(error) =
        super::detached::require_serving_guest(name, &started, std::time::Duration::from_secs(30))
    {
        let abort_is_unresolved = error.abort_is_unresolved();
        let error = anyhow::Error::new(error);
        if abort_is_unresolved {
            // The VMM may still hold block-device file descriptors. Preserve
            // the owner leases and registry for recovery; releasing or
            // re-sealing here could admit a second attachment while it lives.
            prepared_volumes.commit();
        }
        audit_detached_readiness_failure(
            &admission,
            name,
            "guest-readiness",
            &error,
            abort_is_unresolved,
        );
        if !abort_is_unresolved {
            // The failure record and session seal live under the runtime
            // state directory, so cleanup must follow audit finalization.
            if let Err(cleanup_error) =
                crate::local::cleanup_confirmed_launch_abort(name, lifecycle)
            {
                tracing::warn!(
                    error = %cleanup_error,
                    machine = name,
                    "removing runtime state after completed launch abort failed"
                );
            }
        }
        return Err(error);
    }
    // After the start, because a cgroup quota is read back off a process that
    // does not exist until then. This is the call that puts the backend's
    // `apply_grants` on the path `mvmctl` boots: without it the tier is
    // computed correctly and reported to nobody. A failure here has already
    // stopped the VM, so the volume leases are released rather than committed.
    if let Err(error) = super::grants_report::report_enforced_grants(&admission, &started) {
        return Err(finish_post_start_failure(
            &admission,
            &mut prepared_volumes,
            name,
            "grants",
            error,
            PostStartFailure::HostRollback,
            lifecycle,
        ));
    }
    // File what this boot committed against the host budget before the volume
    // leases commit: every later admission's committed-total check sums these
    // per-VM records, and a boot that never wrote one was invisible to it.
    // Fatal, like the grants step above — the VM stops rather than stay up as
    // a machine the host's accounting never saw, and the uncommitted leases
    // release with the rollback.
    if let Err(error) =
        super::budget_charge::record_persistent_boot_charge(&admission, name, &started)
    {
        return Err(finish_post_start_failure(
            &admission,
            &mut prepared_volumes,
            name,
            "host-budget",
            error,
            PostStartFailure::HostRollback,
            lifecycle,
        ));
    }
    prepared_volumes.commit();
    emit_launched(&admission, backend_name, true);
    record_vm_readiness(name, InstanceReadiness::LaunchAccepted);
    mvm_core::audit_emit!(VmStart, vm: name);
    Ok(admission.admitted)
}

fn retain_uncertain_dispatch_custody<T>(
    dispatched: Result<T>,
    prepared_volumes: &mut crate::volume::LaunchPreparation,
) -> Result<T> {
    match dispatched {
        Ok(dispatched) => Ok(dispatched),
        Err(error)
            if crate::admission::cli_start_failure_kind(&error)
                == Some(crate::admission::CliStartFailureKind::UncertainStop) =>
        {
            prepared_volumes.commit();
            Err(error)
        }
        Err(error) => Err(error),
    }
}

enum PostStartFailure {
    Mailbox,
    HostRollback,
}

fn finish_post_start_failure(
    admission: &crate::admission::AdmissionContext,
    prepared_volumes: &mut crate::volume::LaunchPreparation,
    name: &str,
    stage: &str,
    error: anyhow::Error,
    source: PostStartFailure,
    lifecycle: &mvm_runtime::vm::instance_snapshot::MachineLifecycleLock,
) -> anyhow::Error {
    let uncertain = match source {
        PostStartFailure::Mailbox => {
            error.is::<mvm_hostd::mailbox_process::MailboxStopUnconfirmed>()
        }
        PostStartFailure::HostRollback => {
            error.is::<mvm_hostd::plan_admission::UndoLaunchFailure>()
        }
    };
    if uncertain {
        prepared_volumes.commit();
        crate::launch::record_unsealed_end(
            Some((&admission.emitter, admission.admitted.plan())),
            crate::launch::UnsealedEnd::new(name, crate::launch::UnsealedReason::StopFailed)
                .error(format!("{stage}: {error:#}")),
        );
    } else {
        match source {
            PostStartFailure::Mailbox => emit_failed(admission, stage, &error),
            PostStartFailure::HostRollback => {
                crate::admission::seal_recorded_failure(
                    &admission.emitter,
                    admission.admitted.plan(),
                );
            }
        }
        if let Err(cleanup_error) = crate::local::cleanup_confirmed_launch_abort(name, lifecycle) {
            tracing::warn!(error = %cleanup_error, machine = name, "removing runtime state after confirmed rollback failed");
        }
    }
    error
}

/// Audit a detached launch whose post-start readiness stage failed and the
/// partial start is being rolled back. `stage` names the failed stage
/// ("guest-readiness", "egress-gate"); a resolved abort is a `plan.failed`
/// under that stage, an unresolved abort a `plan.teardown_failed` that keeps
/// the session unsealed for recovery.
fn audit_detached_readiness_failure(
    admission: &crate::admission::AdmissionContext,
    name: &str,
    stage: &str,
    error: &anyhow::Error,
    abort_is_unresolved: bool,
) {
    if abort_is_unresolved {
        crate::launch::record_unsealed_end(
            Some((&admission.emitter, admission.admitted.plan())),
            crate::launch::UnsealedEnd::new(name, crate::launch::UnsealedReason::StopFailed)
                .error(format!("{error:#}")),
        );
    } else {
        emit_failed(admission, stage, error);
    }
}

#[cfg(test)]
mod persistent_oci_boot_tests {
    static ENV_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    use crate::admission::admit_plan_tests::admitted_libkrun;
    use mvm_core::util::test_env::TestEnv;

    #[test]
    fn persistent_client_lock_mismatch_refuses_before_name_or_state_preparation() {
        use crate::volume::VolumeService as _;

        let _env_lock = ENV_TEST_LOCK.lock().expect("env test lock");
        let home = tempfile::tempdir().expect("home");
        let mut env = TestEnv::new();
        env.isolate_mvm_home(home.path());
        let lifecycle =
            mvm_runtime::vm::instance_snapshot::MachineLifecycleLock::acquire("lock-owner")
                .expect("lifecycle");
        let name = "other-machine";
        let prepared_volumes = crate::volume::LocalVolumeService::new()
            .acquire_launch_lease(
                &crate::volume::LaunchLeaseRequest::builder(name)
                    .expect("valid name")
                    .build(),
            )
            .expect("empty volume preparation");
        let params = super::PersistentImageStartParams {
            name,
            image_label: "fixture",
            resolved_digest: "sha256:fixture",
            rootfs_path: std::path::Path::new("/store/rootfs.ext4"),
            profile: "dev",
            cpus: 1,
            memory_mib: 512,
            mem_initial_mib: None,
            prepared_volumes,
            network_policy: mvm_core::network_policy::NetworkPolicy::deny_all(),
            ports: &[],
            backend_name: "mock",
            kernel_path: None,
            agent_verb: Vec::new(),
            caller_commitment: None,
            registry_pack_image: None,
            policy_generation: None,
            has_ad_hoc_argv: false,
            grants: None,
            mailbox: None,
            gpu: false,
            gpu_device: None,
            workload_dir: None,
            secrets: crate::admission::secrets::ResolvedPlanSecrets {
                secrets: Vec::new(),
                secret_release: mvm_core::plan::SecretReleasePolicy::default(),
            },
            backend: mvm_runtime::AnyBackend::from_hypervisor("mock"),
        };

        let error = super::start_persistent_with_prepared(params, None, &lifecycle)
            .expect_err("another machine's lifecycle lock must refuse");

        assert!(matches!(
            error.downcast_ref::<mvm_hostd::plan_admission::CliStartFailure>(),
            Some(mvm_hostd::plan_admission::CliStartFailure::StateNotOwned(_))
        ));
        assert!(!mvm_core::config::vm_state_dir(name).exists());
        let registry =
            mvm_runtime::vm::name_registry::VmNameRegistry::load(&crate::name_registry_path())
                .expect("registry");
        assert!(registry.lookup(name).is_none());
    }

    #[cfg(feature = "test-support")]
    #[test]
    fn persistent_required_audit_failure_refuses_before_backend_dispatch() {
        use crate::volume::VolumeService as _;

        let _env_lock = ENV_TEST_LOCK.lock().expect("env test lock");
        let home = tempfile::tempdir().expect("home");
        let mut env = TestEnv::new();
        env.isolate_mvm_home(home.path());
        let name = "persistent-required-audit";
        let lifecycle = mvm_runtime::vm::instance_snapshot::MachineLifecycleLock::acquire(name)
            .expect("lifecycle");
        let rootfs = home.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"rootfs").expect("rootfs");
        let audit = mvm_core::config::mvm_audit_dir();
        std::fs::create_dir_all(&audit).expect("audit directory");
        std::fs::create_dir(audit.join("local.jsonl")).expect("block audit chain file");
        let prepared_volumes = crate::volume::LocalVolumeService::new()
            .acquire_launch_lease(
                &crate::volume::LaunchLeaseRequest::builder(name)
                    .expect("valid name")
                    .build(),
            )
            .expect("empty volume preparation");
        let mock = mvm_runtime::MockBackend::new();
        let params = super::PersistentImageStartParams {
            name,
            image_label: "fixture",
            resolved_digest: "sha256:fixture",
            rootfs_path: &rootfs,
            profile: "prod",
            cpus: 1,
            memory_mib: 512,
            mem_initial_mib: None,
            prepared_volumes,
            network_policy: mvm_core::network_policy::NetworkPolicy::deny_all(),
            ports: &[],
            backend_name: "mock",
            kernel_path: None,
            agent_verb: Vec::new(),
            caller_commitment: None,
            registry_pack_image: None,
            policy_generation: None,
            has_ad_hoc_argv: false,
            grants: None,
            mailbox: None,
            gpu: false,
            gpu_device: None,
            workload_dir: None,
            secrets: crate::admission::secrets::ResolvedPlanSecrets {
                secrets: Vec::new(),
                secret_release: mvm_core::plan::SecretReleasePolicy::default(),
            },
            backend: mvm_runtime::AnyBackend::Mock(mock.clone()),
        };

        let error = super::start_persistent_with_prepared(params, None, &lifecycle)
            .expect_err("required audit failure must refuse");

        assert!(
            format!("{error:#}").contains("audit") || format!("{error:#}").contains("directory"),
            "{error:#}"
        );
        assert_eq!(mock.count(), 0, "audit refusal precedes backend start");
    }

    #[cfg(feature = "test-support")]
    #[test]
    fn persistent_dispatch_uncertainty_commits_volume_lease_custody() {
        use crate::volume::VolumeService as _;

        let _env_lock = ENV_TEST_LOCK.lock().expect("env test lock");
        let home = tempfile::tempdir().expect("home");
        let mut env = TestEnv::new();
        env.isolate_mvm_home(home.path());
        let volume = mvm_runtime::image::RuntimeVolume {
            host: home
                .path()
                .join("attached.ext4")
                .to_string_lossy()
                .into_owned(),
            guest: "/data".into(),
            size: "1M".into(),
            read_only: true,
            ..Default::default()
        };
        let mut volumes = crate::volume::LocalVolumeService::new()
            .acquire_launch_lease(
                &crate::volume::LaunchLeaseRequest::builder("dispatch-owner")
                    .expect("valid name")
                    .explicit_volumes(vec![volume.clone()])
                    .build(),
            )
            .expect("volume preparation");
        let error: anyhow::Error = mvm_hostd::plan_admission::CliStartFailure::UncertainStop(
            anyhow::anyhow!("native start retains unresolved custody"),
        )
        .into();

        super::retain_uncertain_dispatch_custody::<()>(Err(error), &mut volumes)
            .expect_err("uncertain dispatch remains failed");
        drop(volumes);

        assert!(
            crate::volume::LocalVolumeService::new()
                .acquire_launch_lease(
                    &crate::volume::LaunchLeaseRequest::builder("competing-owner")
                        .expect("valid name")
                        .explicit_volumes(vec![volume])
                        .build(),
                )
                .is_err(),
            "dispatch uncertainty retains the original volume lease"
        );
    }

    #[cfg(feature = "test-support")]
    #[test]
    fn persistent_uncertain_stop_retains_runtime_name_and_volume_lease() {
        use crate::volume::VolumeService as _;
        use mvm_core::vm_backend::VmBackend as _;

        let _env_lock = ENV_TEST_LOCK.lock().expect("env test lock");
        let home = tempfile::tempdir().expect("home");
        let mut env = TestEnv::new();
        env.isolate_mvm_home(home.path());
        let name = "persistent-grant-stop-fails";
        let lifecycle = mvm_runtime::vm::instance_snapshot::MachineLifecycleLock::acquire(name)
            .expect("lifecycle");
        let (admission, _keys, audit_dir) = admitted_libkrun(name, None);
        let state = mvm_core::config::vm_state_dir(name);
        std::fs::create_dir_all(&state).expect("runtime state");
        super::register_vm_name(name, "default");
        let volume_path = home.path().join("attached.ext4");
        let volume = mvm_runtime::image::RuntimeVolume {
            host: volume_path.to_string_lossy().into_owned(),
            guest: "/data".into(),
            size: "1M".into(),
            read_only: true,
            ..Default::default()
        };
        let mut volumes = crate::volume::LocalVolumeService::new()
            .acquire_launch_lease(
                &crate::volume::LaunchLeaseRequest::builder(name)
                    .expect("valid name")
                    .explicit_volumes(vec![volume.clone()])
                    .build(),
            )
            .expect("volume preparation");
        let mock = mvm_runtime::MockBackend::new()
            .with_failing_apply_grants()
            .with_failing_stop();
        let id = mock
            .start(&mvm_core::vm_backend::VmStartConfig {
                name: name.into(),
                ..Default::default()
            })
            .expect("started VM");
        let error = mvm_hostd::plan_admission::apply_persistent_grants_or_undo_launch(
            &mvm_runtime::backend::AnyBackend::Mock(mock.clone()),
            &id,
            &admission.admitted,
            Some(&admission.emitter),
        )
        .expect_err("grants refusal");
        super::finish_post_start_failure(
            &admission,
            &mut volumes,
            name,
            "grants",
            error,
            super::PostStartFailure::HostRollback,
            &lifecycle,
        );
        drop(volumes);

        assert_eq!(mock.count(), 1, "unconfirmed stop may still be live");
        assert!(state.exists(), "runtime evidence remains for recovery");
        assert!(
            crate::volume::LocalVolumeService::new()
                .acquire_launch_lease(
                    &crate::volume::LaunchLeaseRequest::builder("competing-owner")
                        .expect("valid name")
                        .explicit_volumes(vec![volume])
                        .build(),
                )
                .is_err(),
            "the original owner retains its volume lease"
        );
        let registry =
            mvm_runtime::vm::name_registry::VmNameRegistry::load(&crate::name_registry_path())
                .expect("name registry");
        assert!(registry.lookup(name).is_some(), "name custody remains");
        let chain =
            std::fs::read_to_string(audit_dir.path().join("local.jsonl")).expect("audit chain");
        assert!(chain.contains("plan.teardown_failed"), "{chain}");
        assert!(!chain.contains("plan.failed"), "{chain}");
        assert!(!chain.contains("plan.launched"), "{chain}");
        assert!(!chain.contains("session.sealed"), "{chain}");
    }

    #[test]
    fn readiness_audit_seals_completed_abort_but_leaves_unresolved_abort_unsealed() {
        let _env_lock = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(home.path());

        let (resolved, _resolved_keys, resolved_audit) = admitted_libkrun("resolved-abort", None);
        let resolved_error = anyhow::Error::new(
            crate::launch::detached::DetachedReadinessError::RolledBack {
                name: "resolved-abort".into(),
                timeout_secs: 1,
            },
        );
        super::audit_detached_readiness_failure(
            &resolved,
            "resolved-abort",
            "guest-readiness",
            &resolved_error,
            false,
        );
        let resolved_chain = std::fs::read_to_string(resolved_audit.path().join("local.jsonl"))
            .expect("resolved chain");
        assert!(resolved_chain.contains("plan.failed"), "{resolved_chain}");
        assert!(
            resolved_chain.contains("guest-readiness"),
            "{resolved_chain}"
        );
        assert!(
            resolved_chain.contains("session.sealed"),
            "{resolved_chain}"
        );
        assert!(
            !resolved_chain.contains("plan.launched"),
            "{resolved_chain}"
        );

        let (unresolved, _unresolved_keys, unresolved_audit) =
            admitted_libkrun("unresolved-abort", None);
        let unresolved_error = anyhow::Error::new(
            crate::launch::detached::DetachedReadinessError::AbortUnresolved {
                name: "unresolved-abort".into(),
                timeout_secs: 1,
                source: anyhow::anyhow!("VMM still alive"),
            },
        );
        super::audit_detached_readiness_failure(
            &unresolved,
            "unresolved-abort",
            "guest-readiness",
            &unresolved_error,
            true,
        );
        let unresolved_chain = std::fs::read_to_string(unresolved_audit.path().join("local.jsonl"))
            .expect("unresolved chain");
        assert!(
            unresolved_chain.contains("plan.teardown_failed"),
            "{unresolved_chain}"
        );
        assert!(
            unresolved_chain.contains("stop-failed"),
            "{unresolved_chain}"
        );
        assert!(
            !unresolved_chain.contains("plan.failed"),
            "{unresolved_chain}"
        );
        assert!(
            !unresolved_chain.contains("session.sealed"),
            "{unresolved_chain}"
        );
        assert!(
            !unresolved_chain.contains("plan.launched"),
            "{unresolved_chain}"
        );
    }

    /// The gate probe's failure audits under its own stage label, sibling to
    /// "guest-readiness", with the same resolved/unresolved abort semantics.
    #[test]
    fn egress_gate_failure_audits_under_its_own_stage() {
        let _env_lock = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(home.path());

        let probe_error = || {
            anyhow::Error::new(
                super::super::egress_gate_probe::EgressGateProbeError::VerdictMismatch {
                    host: "192.0.2.1".into(),
                    port: 9,
                    expected: mvm_core::substitution_wire::GateProbeExpect::Deny,
                    actual: mvm_core::substitution_wire::GateProbeVerdict::Admit,
                    reason: None,
                },
            )
        };

        let (resolved, _resolved_keys, resolved_audit) =
            admitted_libkrun("egress-gate-resolved", None);
        super::audit_detached_readiness_failure(
            &resolved,
            "egress-gate-resolved",
            "egress-gate",
            &probe_error(),
            false,
        );
        let resolved_chain = std::fs::read_to_string(resolved_audit.path().join("local.jsonl"))
            .expect("resolved chain");
        assert!(resolved_chain.contains("plan.failed"), "{resolved_chain}");
        assert!(resolved_chain.contains("egress-gate"), "{resolved_chain}");
        assert!(
            !resolved_chain.contains("guest-readiness"),
            "the probe failure is not audited as a guest-readiness failure: {resolved_chain}"
        );
        assert!(
            resolved_chain.contains("session.sealed"),
            "{resolved_chain}"
        );
        assert!(
            !resolved_chain.contains("plan.launched"),
            "{resolved_chain}"
        );

        let (unresolved, _unresolved_keys, unresolved_audit) =
            admitted_libkrun("egress-gate-unresolved", None);
        super::audit_detached_readiness_failure(
            &unresolved,
            "egress-gate-unresolved",
            "egress-gate",
            &probe_error(),
            true,
        );
        let unresolved_chain = std::fs::read_to_string(unresolved_audit.path().join("local.jsonl"))
            .expect("unresolved chain");
        assert!(
            unresolved_chain.contains("plan.teardown_failed"),
            "{unresolved_chain}"
        );
        assert!(
            !unresolved_chain.contains("plan.failed"),
            "{unresolved_chain}"
        );
        assert!(
            !unresolved_chain.contains("session.sealed"),
            "{unresolved_chain}"
        );
    }

    #[test]
    fn persistent_registration_records_the_runtime_directory() {
        use mvm_runtime::vm::reconcile::{FsRuntimeView, RuntimeView};

        let _env_lock = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(home.path());
        let vm_name = "persistent-registration";
        let state_dir = mvm_core::config::vm_state_dir(vm_name);
        std::fs::create_dir_all(&state_dir).unwrap();

        super::register_vm_name(vm_name, "default");

        let registry =
            mvm_runtime::vm::name_registry::VmNameRegistry::load(&crate::name_registry_path())
                .unwrap();
        let registration = registry.vms.get(vm_name).expect("registered machine");
        assert_eq!(registration.vm_dir, state_dir.to_string_lossy());
        let view = FsRuntimeView::new(home.path().join("vms"));
        assert!(view.state_present(registration));
    }

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
            crate::launch::runtime_overlay::runtime_overlay_source_checkout_root()
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
            crate::launch::runtime_overlay::RUNTIME_OVERLAY_ACQUIRE_MODE_ENV,
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
            crate::launch::runtime_overlay::runtime_overlay_source_checkout_root()
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
            crate::launch::runtime_overlay::RUNTIME_OVERLAY_ACQUIRE_MODE_ENV,
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

#[cfg(test)]
mod port_spec_tests {
    use super::parse_port_spec;

    #[test]
    fn test_parse_port_spec_single() {
        let (local, guest) = parse_port_spec("3000").unwrap();
        assert_eq!(local, 3000);
        assert_eq!(guest, 3000);
    }

    #[test]
    fn test_parse_port_spec_mapping() {
        let (local, guest) = parse_port_spec("8080:3000").unwrap();
        assert_eq!(local, 8080);
        assert_eq!(guest, 3000);
    }

    #[test]
    fn test_parse_port_spec_invalid() {
        assert!(parse_port_spec("abc").is_err());
        assert!(parse_port_spec("abc:3000").is_err());
        assert!(parse_port_spec("3000:abc").is_err());
        assert!(parse_port_spec("99999").is_err());
    }
}
