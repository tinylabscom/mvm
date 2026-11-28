use std::num::{NonZeroU32, NonZeroU64};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use mvm_contract::grants::{CpuGrant, Grants, WallClockGrant};
use mvm_contract::plan::{ExecutionPlan, PlanSeccompTier, SecretReleasePolicy};
use mvm_contract::protocol::actor_budget::{ActorBudget, ActorResources};
use mvm_contract::protocol::broker::ServiceId;
use mvm_contract::protocol::mailbox::{
    AuthorizationDomainId, BootId, ContentType, ExecutionEpoch, MailboxGrant, MailboxId,
    MailboxRetentionPolicy, TenantId,
};
use mvm_contract::protocol::workload_actor::{
    ActorBindingId, ActorProtocolVersion, ControllerIdentity, DelegationDepth, LifecycleGrant,
    LifecycleOperation, WorkflowBinding, WorkflowRole,
};
use mvm_core::arch::GuestArch;
use mvm_core::network_policy::NetworkPolicy;
use mvm_core::plan::{SynthesisInput, synthesize_plan};
use mvm_core::protocol::runtime_release::{
    CliRuntimeLaunchBinding, RuntimeBindingProvenance, RuntimeLaunchBinding,
};
use mvm_fs::ext4::{Node, Owner};
use mvm_hostd::actor_bootstrap::{ActorBootstrap, NamedActorTemplate};
use mvm_hostd::actor_lifecycle::local_mailboxes::ActorMailboxPolicy;
use mvm_hostd::actor_lifecycle::{ActorConstraints, ColdLaunch, TemplateDefinition};
use mvm_hostd::actor_reservations::ReservationCeilings;

#[cfg(test)]
#[path = "prepare_tests.rs"]
mod tests;

const MIB: u64 = 1024 * 1024;
// Explicit enforced share and reservation charge, independent of vCPU count.
const CPU_MILLICORES: u32 = 500;

pub(super) fn prepare(
    source: &Path,
    evidence: &Path,
    kernel: &Path,
    parent_binary: &Path,
    worker_binary: &Path,
) -> Result<ActorBootstrap> {
    for path in [source, evidence, kernel, parent_binary, worker_binary] {
        ensure!(path.is_absolute(), "all witness inputs must be absolute");
    }
    ensure!(
        evidence.components().all(|component| matches!(
            component,
            std::path::Component::RootDir | std::path::Component::Normal(_)
        )),
        "evidence path must not contain traversal"
    );
    let evidence_parent = evidence
        .parent()
        .context("evidence parent absent")?
        .canonicalize()?;
    ensure!(
        evidence_parent.starts_with("/private/tmp") && evidence_parent != Path::new("/private/tmp"),
        "evidence must be inside a new private /tmp witness directory"
    );
    ensure!(
        source.join("Cargo.toml").is_file(),
        "source root is not a workspace"
    );
    ensure!(
        !evidence.exists(),
        "evidence directory must be new; retained state is never overwritten"
    );
    let home = mvm_core::config::mvm_home_strict()?;
    ensure!(
        home == evidence.join("mvm"),
        "MVM_HOME must be NEW_EVIDENCE_DIR/mvm"
    );
    mvm_core::config::create_private_dir(evidence)?;
    mvm_core::config::create_private_dir(&home)?;
    std::fs::write(evidence.join("owned-witness"), b"actor-live-hvf-v1\n")?;
    // Explicit fixture policy, confined to a newly created home, not user defaults.
    let config = mvm_core::user_config::MvmConfig {
        host_budget_memory_mib: Some(2048),
        host_budget_cpu_millicores: Some(4000),
        max_mailbox_retention_ms: Some(60_000),
        ..Default::default()
    };
    mvm_core::user_config::save(&config, None)?;
    let cache = PathBuf::from(mvm_core::config::mvm_cache_dir());
    let version = env!("CARGO_PKG_VERSION");
    let runtime = mvm_build::guest_runtime::resolve_or_build_source_guest_runtime(
        &cache,
        version,
        GuestArch::Aarch64,
        source,
    )?;
    let overlay = mvm_build::runtime_overlay::build_runtime_overlay_from_guest_runtime(
        &cache,
        version,
        GuestArch::Aarch64,
        &runtime,
    )?;
    let initramfs = mvm_build::initramfs::build_initramfs_from_guest_runtime(
        &cache,
        version,
        GuestArch::Aarch64,
        &runtime,
    )?;
    let runtime_binding = RuntimeLaunchBinding::CliAssembly(CliRuntimeLaunchBinding {
        provenance: RuntimeBindingProvenance::Source {
            version: version.into(),
            arch: GuestArch::Aarch64,
            archive_sha256: runtime.digest,
        },
        overlay_path: overlay.overlay_ext4,
        overlay_verity_path: overlay.sidecar,
        initramfs_path: initramfs.image_path,
        overlay_roothash: overlay.roothash,
    });
    let signer = mvm_hostd::audit::host_keypair::load_or_init()?;
    let parent_root = rootfs(evidence, "parent", parent_binary)?;
    let worker_root = rootfs(evidence, "worker", worker_binary)?;
    let keys = signer
        .secret_path
        .parent()
        .context("key directory absent")?;
    let parent_mailbox = grant(keys)?;
    let child_mailbox = grant(keys)?;
    let mut parent = plan(
        "actor-live-parent",
        &parent_root,
        kernel,
        parent_mailbox,
        true,
    )?;
    let worker = plan(
        "actor-live-worker",
        &worker_root,
        kernel,
        child_mailbox,
        false,
    )?;
    let parent_launch = launch(&parent_root, kernel, runtime_binding.clone());
    let worker_launch = launch(&worker_root, kernel, runtime_binding);
    let child_charge = charge(&worker, &worker_launch)?;
    let parent_charge = ActorResources {
        controllers: 1,
        ..charge(&parent, &parent_launch)?
    };
    let mut total = child_charge
        .checked_add(parent_charge)
        .context("fixture budget overflow")?;
    // Both launches are sequential, and Running releases concurrent-launch credit.
    total.concurrent_launches = 1;
    let budget = ActorBudget {
        resources: total,
        max_total_attempts: 2,
    };
    let constraints = ActorConstraints {
        ceilings: ReservationCeilings {
            tenant: budget,
            workflow: budget,
            controller: budget,
        },
        parent_charge,
        child_resources: worker.resources.clone(),
        network: NetworkPolicy::deny_all(),
        effective_policy: Default::default(),
        capabilities: vec![],
        mailbox_policy: ActorMailboxPolicy {
            tenant: TenantId::from_bytes(rand::random()),
            authorization_domain: AuthorizationDomainId::from_bytes(rand::random()),
            content_types: vec![ContentType::parse("application/octet-stream", 1)?],
            max_payload_bytes: 1024,
            max_messages_per_minute: 60,
            max_send_attempts: 8,
            max_outstanding_calls: 1,
            max_queue_contribution_bytes: 4096,
            max_storage_bytes: 8 * MIB,
            policy_epoch: 1,
            not_before_unix_ms: parent.valid_from.unix_millis(),
            expires_at_unix_ms: parent.valid_until.unix_millis(),
        },
    };
    parent.workflow = Some(WorkflowBinding {
        version: ActorProtocolVersion::V1,
        workflow_id: ActorBindingId::new("actor-live")?,
        constraint_snapshot_digest: constraints.digest()?,
        role: WorkflowRole::Controller {
            grant: LifecycleGrant {
                id: ActorBindingId::new("actor-live")?,
                controller: ControllerIdentity {
                    tenant: parent.tenant.clone(),
                    workload: parent.workload.clone(),
                    execution_epoch: ExecutionEpoch::new(parent.execution_epoch)?,
                    boot_id: BootId::from_bytes(rand::random()),
                    generation: NonZeroU64::new(1).context("one is nonzero")?,
                },
                depth: DelegationDepth::One,
                templates: vec![],
                operations: vec![
                    LifecycleOperation::Launch,
                    LifecycleOperation::ObserveChild,
                    LifecycleOperation::ReleaseChild,
                ],
                not_before_unix_ms: parent.valid_from.unix_millis(),
                expires_at_unix_ms: parent.valid_until.unix_millis(),
                workflow_deadline_unix_ms: parent.valid_until.unix_millis(),
            },
        },
    });
    let bootstrap = ActorBootstrap {
        version: 1,
        parent,
        launch: parent_launch,
        templates: vec![NamedActorTemplate {
            id: ActorBindingId::new("worker")?,
            definition: TemplateDefinition {
                plan: worker,
                launch: worker_launch,
                effective_policy: Default::default(),
                capabilities: vec![],
                charge: child_charge,
            },
        }],
        constraints,
        host_budget: budget,
    }
    .provision()?;
    std::fs::write(
        evidence.join("bootstrap.json"),
        serde_json::to_vec_pretty(&bootstrap)?,
    )?;
    Ok(bootstrap)
}

fn plan(
    name: &str,
    rootfs: &Path,
    kernel: &Path,
    mailbox: MailboxGrant,
    controller: bool,
) -> Result<ExecutionPlan> {
    let image_hash = mvm_core::crypto::image_verify::sha256_file(rootfs)?;
    let kernel_hash = mvm_core::crypto::image_verify::sha256_file(kernel)?;
    let mut plan = synthesize_plan(
        &SynthesisInput::builder()
            .vm_name(name)
            .tenant("actor-live")
            .backend_name("hvf")
            .image_name(name)
            .image_sha256(&image_hash)
            .kernel_sha256(kernel_hash.as_str())
            .seccomp_tier(PlanSeccompTier::Network)
            .secret_release(SecretReleasePolicy::None)
            .secrets(vec![])
            .network_mode(Default::default())
            .grants(Grants {
                cpu: Some(CpuGrant::Share {
                    millicores: CPU_MILLICORES,
                }),
                wall_clock: Some(WallClockGrant::Secs {
                    secs: NonZeroU32::new(240).expect("240 seconds is nonzero"),
                }),
                ..Default::default()
            })
            .cpus(1)
            .mem_mib(256)
            .disk_mib(std::fs::metadata(rootfs)?.len().div_ceil(MIB))
            .boot_timeout_secs(60)
            .destroy_on_exit(true)
            .shares(vec![])
            .redaction(Default::default())
            .reversible_replacement(Default::default())
            .audit_labels(Default::default())
            .services(if controller {
                vec![ServiceId::parse("host.actor.v1")?]
            } else {
                vec![]
            })
            .stream_edges(vec![])
            .stream_retention(Default::default())
            .mailbox(mailbox)
            .build()?,
    )?;
    plan.sdk_uses_sidecar = false;
    plan.image.entrypoint_present = true;
    plan.valid_until = plan.valid_from.checked_add_secs(240).expect("in range");
    Ok(plan)
}

fn grant(keys: &Path) -> Result<MailboxGrant> {
    let mailbox = MailboxId::from_bytes(rand::random());
    let epoch = ExecutionEpoch::new(1)?;
    Ok(MailboxGrant {
        mailbox,
        epoch,
        authority_key: mvm_hostd::mailbox_launch::authority_key_for(keys, &mailbox, epoch)?
            .to_bytes(),
        report: None,
        retention: Some(MailboxRetentionPolicy::new(60_000)?),
        service_blind: None,
    })
}

fn launch(rootfs: &Path, kernel: &Path, runtime: RuntimeLaunchBinding) -> ColdLaunch {
    ColdLaunch {
        rootfs_path: rootfs.display().to_string(),
        kernel_path: Some(kernel.display().to_string()),
        runtime,
        verity_path: None,
        roothash: None,
        config_files: vec![],
        network_policy: NetworkPolicy::deny_all(),
        sdk_sidecar: None,
        sdk_source_checkout: None,
    }
}

fn charge(plan: &ExecutionPlan, launch: &ColdLaunch) -> Result<ActorResources> {
    let config = launch.config(plan)?;
    let mut artifact_bytes = std::fs::metadata(&config.rootfs_path)?.len();
    for path in [
        config.kernel_path,
        config.initrd_path,
        config.runtime_overlay_path,
        config.runtime_overlay_verity_path,
    ]
    .into_iter()
    .flatten()
    {
        artifact_bytes = artifact_bytes
            .checked_add(std::fs::metadata(path)?.len())
            .context("artifact bytes overflow")?;
    }
    Ok(ActorResources {
        live_vms: 1,
        resident_vmms: 1,
        concurrent_launches: 1,
        memory_bytes: 512 * MIB,
        cpu_millicores: CPU_MILLICORES.into(),
        disk_bytes: plan.resources.disk_mib * MIB,
        artifact_bytes,
        mailbox_bytes: 8 * MIB,
        file_descriptors: 512,
        host_sockets: 32,
        vsock_channels: 32,
        ..Default::default()
    })
}

fn rootfs(evidence: &Path, role: &str, binary: &Path) -> Result<PathBuf> {
    let executable = std::fs::read(binary)?;
    ensure!(
        executable.starts_with(b"\x7fELF"),
        "guest example must be a Linux ELF"
    );
    let mut nodes: Vec<_> = [
        "/etc",
        "/etc/mvm",
        "/usr",
        "/usr/lib",
        "/usr/lib/mvm",
        "/usr/lib/mvm/wrappers",
        "/dev",
        "/dev/pts",
        "/dev/shm",
        "/proc",
        "/sys",
        "/run",
        "/tmp",
        "/mvm",
        "/mvm/runtime",
        "/mvm/sdk",
        "/mnt",
        "/work",
        "/data",
    ]
    .into_iter()
    .map(|path| Node::Dir {
        path: path.into(),
        mode: 0o755,
        xattrs: vec![],
        owner: Owner::ROOT,
    })
    .collect();
    for (path, mode, data) in [
        ("/usr/lib/mvm/wrappers/actor", 0o555, executable),
        (
            "/etc/mvm/entrypoint",
            0o444,
            b"/usr/lib/mvm/wrappers/actor\n".to_vec(),
        ),
        ("/etc/mvm/variant", 0o444, b"dev\n".to_vec()),
        (
            "/etc/passwd",
            0o444,
            b"root:x:0:0:root:/root:/bin/false\nmvm:x:901:901:workload:/work:/bin/false\n".to_vec(),
        ),
        ("/etc/group", 0o444, b"root:x:0:\nmvm:x:901:\n".to_vec()),
    ] {
        nodes.push(Node::File {
            path: path.into(),
            mode,
            data,
            xattrs: vec![],
            owner: Owner::ROOT,
        });
    }
    let artifact_dir = evidence.join(role);
    std::fs::create_dir(&artifact_dir)?;
    let path = artifact_dir.join("rootfs.ext4");
    std::fs::write(
        &path,
        mvm_fs::ext4::build_image(nodes, &Default::default())?,
    )?;
    mvm_build::builder_vm::GuestSidecar {
        name: format!("actor-live-{role}"),
        accessible: true,
        sealed: false,
        entrypoint_kind: "command".into(),
        entrypoint_argv: vec!["/usr/lib/mvm/wrappers/actor".into()],
        init_system: "initramfs-agent".into(),
        expected_boot_ms: 0,
        agent_binary: "real".into(),
        rootless_entrypoint: true,
        hypervisor: "hvf".into(),
        overlay_aware: true,
        runtime_lean: true,
        image_tag: String::new(),
        source: "built-local".into(),
        built_at: mvm_core::util::time::utc_now_rfc3339(),
        // The runtime binding, not this workload image, supplies the agent.
        protocol_version: 0,
        generator_rev: String::new(),
        libc: mvm_build::guest_libc::GuestLibc::Unknown,
    }
    .write_to_dir(&artifact_dir)?;
    Ok(path)
}
