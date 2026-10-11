//! Admission and capability inheritance for checkpoint forks.

use anyhow::{Context, Result, bail};
use mvm_core::checkpoint::{CheckpointId, CheckpointMeta};
use mvm_core::plan::SecretBinding;
use mvm_hostd::audit::plan_persist;
use mvm_runtime::checkpoint::CheckpointStore;
use serde::{Deserialize, Serialize};

use crate::launch::runtime_source::prepare_fork_boot_artifacts;

/// Whether the child is an ordinary fork or an exec-journal replay.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum ForkIntent {
    Ordinary,
    Replay,
}

/// Owned fork inputs, independent of command-line parsing.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct ForkRequest {
    pub id: CheckpointId,
    pub new_id: Option<String>,
    pub boot: bool,
    pub hypervisor: String,
    pub cpus: Option<u32>,
    pub memory: Option<String>,
    pub declared_secrets: Vec<SecretBinding>,
    pub allow_secret_drop: bool,
    pub intent: ForkIntent,
    pub tenant: String,
}

/// A completed fork. The checkpoint is the child's sealed lineage record.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ForkReport {
    pub schema_version: u32,
    pub action: String,
    pub parent_id: CheckpointId,
    pub child_vm_name: String,
    pub booted: bool,
    pub checkpoint: CheckpointMeta,
}

impl super::Checkpoints {
    /// Re-admit and materialize a fresh child, preserving signed lineage.
    pub fn fork(
        &self,
        request: &ForkRequest,
        observer: &mut dyn crate::entrypoint::CallObserver,
    ) -> Result<ForkReport> {
        use mvm_core::checkpoint::CheckpointClass;
        let parent = self.read(&request.id)?;
        crate::validate_vm_name(&parent.vm_name)?;
        if request.intent == ForkIntent::Replay && parent.class != CheckpointClass::VmFull {
            bail!("machine replay requires a vm_full checkpoint");
        }
        let name = request
            .new_id
            .clone()
            .unwrap_or_else(|| format!("{}-fork-{}", request.id.as_str(), now_unix()));
        crate::validate_vm_name(&name)?;
        if name == parent.vm_name {
            bail!("a checkpoint fork must use a fresh VM name");
        }
        let _lifecycle = mvm_runtime::vm::instance_snapshot::lock_resume(&name)?;
        if mvm_core::config::vm_state_dir(&name).try_exists()? {
            bail!("fork target {name:?} already has VM state; choose a fresh name");
        }
        observer.vm_named(&name);
        let secrets = if request.declared_secrets.is_empty()
            || (parent.class == CheckpointClass::FsQuick && !request.boot)
        {
            request.declared_secrets.clone()
        } else {
            crate::admission::secrets::ResolvedPlanSecrets::from_bindings(
                request.declared_secrets.clone(),
            )
            .bind_approval(&crate::secret::SecretService::local()?, &request.tenant)?
            .secrets
        };
        let meta = match parent.class {
            CheckpointClass::VmFull => {
                super::fork_vm_full::fork_vm_full_arm(super::fork_vm_full::ForkVmFullArmParams {
                    store: &self.store,
                    checkpoint: &request.id,
                    new_id: Some(name.clone()),
                    cpus_override: request.cpus,
                    memory_override: request.memory.as_deref(),
                    tenant: &request.tenant,
                    declared_secrets: &secrets,
                    allow_secret_drop: request.allow_secret_drop,
                    intent: request.intent,
                })?
            }
            CheckpointClass::FsQuick => fork_fs_quick(&self.store, request, &name, &secrets)?,
        };
        Ok(ForkReport {
            schema_version: 1,
            action: "fork".into(),
            parent_id: request.id.clone(),
            child_vm_name: name,
            booted: request.boot || parent.class == CheckpointClass::VmFull,
            checkpoint: meta,
        })
    }
}

fn fork_fs_quick(
    store: &CheckpointStore,
    request: &ForkRequest,
    name: &str,
    secrets: &[SecretBinding],
) -> Result<CheckpointMeta> {
    use mvm_runtime::checkpoint::{ForkParams, ForkParentLiveness, fork_checkpoint};
    if !request.boot && !secrets.is_empty() {
        bail!(
            "--secret requires --boot for an fs_quick fork because an unbooted clone has no child plan"
        );
    }
    if request.boot {
        validate_fork_secret_policy(
            &request.id,
            store,
            &request.tenant,
            secrets,
            request.allow_secret_drop,
        )?;
    }
    let now = now_unix();
    let dest_dir = mvm_core::config::vm_state_dir(name);
    let anchor = super::SignedChainAnchor::load()
        .context("loading the signed audit chain to verify the fork parent")?;
    let meta = fork_checkpoint(
        store,
        ForkParams {
            checkpoint: request.id.clone(),
            child_id: CheckpointId::new(format!("fork-{name}-{now}")),
            child_vm_name: name.to_owned(),
            dest_dir: dest_dir.clone(),
            created_unix: now,
            parent_liveness: ForkParentLiveness::MustBeStopped,
            child_plan_json: None,
            child_tenant_id: None,
        },
        &anchor,
    )
    .with_context(|| format!("forking checkpoint {:?}", request.id.as_str()))?;
    bind_checkpoint_forked(&request.id, &meta, name, store, secrets, &request.tenant)?;
    if request.boot {
        boot_forked_child(store, request, name, &dest_dir.join("rootfs.ext4"), secrets)?;
    }
    Ok(meta)
}

fn boot_forked_child(
    store: &CheckpointStore,
    request: &ForkRequest,
    name: &str,
    rootfs: &std::path::Path,
    secrets: &[SecretBinding],
) -> Result<()> {
    use crate::admission::{AdmitPlanForBootParams, InheritedBundle, admit_plan_for_boot};
    use mvm_runtime::backend::AnyBackend;
    let hypervisor =
        crate::launch::machine_start::resolve_effective_hypervisor(&request.hypervisor);
    AnyBackend::require_hypervisor_selectable(&hypervisor)?;
    let parent = store.read_meta(&request.id)?;
    let bundle = InheritedBundle::of_parent_vm(&parent.vm_name)?;
    let verbs = parent_agent_verb_override(&request.id, store);
    let (cpus, memory) = resolve_fork_resources(request, store)?;
    let mut start = fork_start_config(name, rootfs, cpus, memory);
    prepare_fork_boot_artifacts(
        &mut start,
        &hypervisor,
        parent.runtime_overlay_version.as_deref(),
    )?;
    let ledger = mvm_hostd::plan_admission::InMemoryNonceLedger::new();
    let admission = admit_plan_for_boot(AdmitPlanForBootParams {
        instructions: Default::default(),
        outputs: Vec::new(),
        network_mode: parent_network_mode(&request.id, store),
        tenant: &request.tenant,
        vm_name: name,
        backend_name: &hypervisor,
        configured_images_dir: mvm_build::image_source::configured_images_dir().as_deref(),
        rootfs_path: rootfs,
        kernel_path: start.kernel_path.as_deref().map(std::path::Path::new),
        precomputed_image_sha256: None,
        boot_artifact_identity: None,
        cpus,
        mem_mib: u64::from(memory),
        seccomp_tier: mvm_core::plan::PlanSeccompTier::Standard,
        secret_release: crate::admission::secrets::release_for_bindings(secrets),
        secrets: secrets.to_vec(),
        caller_commitment: None,
        ledger: &ledger,
        keys_dir: None,
        audit_dir: None,
        policy_dir: None,
        bundle_pin: bundle.as_ref().map(InheritedBundle::pin),
        bundle_posture: None,
        deps_volume: None,
        shares: Vec::new(),
        assets: Vec::new(),
        redaction: Default::default(),
        tools: Default::default(),
        network_policy: mvm_core::network_policy::NetworkPolicy::deny_all(),
        agent_verb_override: verbs,
        restrict_agent_verbs: true,
        services: Vec::new(),
        grants: None,
        backend_kind: None,
        entrypoint: crate::admission::entrypoint_resolve::ResolvedEntrypoint::unresolved(
            "a checkpoint fork boots the image the parent booted; this path resolves no entrypoint",
        ),
    })?;
    populate_fork_rootfs_verity(&mut start, rootfs)?;
    mvm_hostd::plan_admission::populate_audit_substrate(
        &mut start,
        &admission.admitted,
        admission.policy_bundle.as_ref(),
    )?;
    if crate::launch::persistent::persists_plan_before_start(&hypervisor) {
        mvm_hostd::plan_admission::stash_plan_for_bridge(&start)?;
    }
    let backend = AnyBackend::from_hypervisor(&hypervisor);
    if let Err(error) = backend.start(&start) {
        crate::admission::emit_failed(&admission, "backend-start", &error);
        return Err(error);
    }
    crate::admission::emit_launched(&admission, &hypervisor, true);
    Ok(())
}

fn resolve_fork_resources(request: &ForkRequest, store: &CheckpointStore) -> Result<(u32, u32)> {
    let (parent_cpus, parent_memory) = parent_plan_resources(&request.id, store);
    let defaults = mvm_core::user_config::load(None);
    let cpus = request
        .cpus
        .or(parent_cpus)
        .unwrap_or(defaults.default_cpus);
    let memory = match request.memory.as_deref() {
        Some(value) => {
            mvm_core::util::parse_human_size(value).context("parsing --memory for --boot")?
        }
        None => parent_memory.unwrap_or(defaults.default_memory_mib),
    };
    Ok((cpus, memory))
}

fn fork_start_config(
    name: &str,
    rootfs: &std::path::Path,
    cpus: u32,
    memory_mib: u32,
) -> mvm_core::vm_backend::VmStartConfig {
    mvm_core::vm_backend::VmStartConfig {
        name: name.to_owned(),
        rootfs_path: rootfs.to_string_lossy().into_owned(),
        cpus,
        memory_mib,
        ..Default::default()
    }
}

fn parent_plan_resources(
    checkpoint: &CheckpointId,
    store: &CheckpointStore,
) -> (Option<u32>, Option<u32>) {
    let Ok(meta) = store.read_meta(checkpoint) else {
        return (None, None);
    };
    let Ok(plan) = plan_persist::read_plan(&meta.vm_name) else {
        return (None, None);
    };
    (
        Some(plan.resources.cpus),
        Some(plan.resources.mem_mib as u32),
    )
}

fn populate_fork_rootfs_verity(
    start: &mut mvm_core::vm_backend::VmStartConfig,
    rootfs: &std::path::Path,
) -> Result<()> {
    let dir = rootfs.parent().unwrap_or(std::path::Path::new("."));
    let verity = dir.join("rootfs.verity");
    let roothash = dir.join("rootfs.roothash");
    if verity.exists() && roothash.exists() {
        start.verity_path = Some(
            verity
                .to_str()
                .context("rootfs.verity path is not UTF-8")?
                .to_owned(),
        );
        start.roothash = Some(
            std::fs::read_to_string(&roothash)
                .with_context(|| format!("reading {}", roothash.display()))?
                .trim()
                .to_owned(),
        );
    }
    Ok(())
}

pub(super) fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

pub(super) fn read_grant_envelope_for(
    vm_name: &str,
) -> Option<mvm_core::protocol::vm_backend::VerbGrantEnvelope> {
    let path = mvm_core::config::vm_state_dir(vm_name).join("verb-grant.json");
    serde_json::from_slice(&std::fs::read(path).ok()?).ok()
}

pub(super) fn grant_predecessor_from_vm_name(
    vm_name: &str,
) -> Option<(String, mvm_core::plan::Nonce)> {
    let envelope = read_grant_envelope_for(vm_name)?;
    Some((
        envelope.grant.session_id,
        mvm_core::plan::Nonce::from_hex(&envelope.plan_nonce_hex).ok()?,
    ))
}

pub(super) fn parent_agent_verb_override(
    checkpoint: &CheckpointId,
    store: &CheckpointStore,
) -> Vec<String> {
    let Ok(meta) = store.read_meta(checkpoint) else {
        return Vec::new();
    };
    let Ok(plan) = plan_persist::read_plan(&meta.vm_name) else {
        return Vec::new();
    };
    plan.agent_verbs
        .unwrap_or_default()
        .into_iter()
        .map(|verb| verb.as_str().to_string())
        .collect()
}

pub(super) fn parent_network_mode(
    checkpoint: &CheckpointId,
    store: &CheckpointStore,
) -> mvm_contract::plan::NetworkMode {
    let fallback = crate::launch::persistent::preflight_network();
    let Ok(meta) = store.read_meta(checkpoint) else {
        return fallback;
    };
    plan_persist::read_plan(&meta.vm_name)
        .map(|plan| plan.network_mode)
        .unwrap_or(fallback)
}

fn parent_secret_names(checkpoint: &CheckpointId, store: &CheckpointStore) -> Vec<String> {
    let Ok(meta) = store.read_meta(checkpoint) else {
        return Vec::new();
    };
    let Ok(plan) = plan_persist::read_plan(&meta.vm_name) else {
        return Vec::new();
    };
    plan.secrets
        .into_iter()
        .map(|binding| binding.name)
        .collect()
}

fn dropped_parent_secret_names(parent: &[String], declared: &[SecretBinding]) -> Vec<String> {
    let names: std::collections::BTreeSet<_> = declared
        .iter()
        .map(|binding| binding.name.as_str())
        .collect();
    parent
        .iter()
        .filter(|name| !names.contains(name.as_str()))
        .cloned()
        .collect()
}

fn enforce_secret_attenuation(dropped: &[String], allow_secret_drop: bool) -> Result<()> {
    if !dropped.is_empty() && !allow_secret_drop {
        bail!(
            "fork child would drop parent secret bindings: {}. Redeclare each required binding with --secret NAME, or pass --allow-secret-drop to attenuate them intentionally",
            dropped.join(", ")
        );
    }
    Ok(())
}

pub(super) fn validate_fork_secret_policy(
    checkpoint: &CheckpointId,
    store: &CheckpointStore,
    tenant: &str,
    declared: &[SecretBinding],
    allow_secret_drop: bool,
) -> Result<()> {
    let bindings = mvm_hostd::keyholder::FileBindingStore::default_location()
        .context("opening the child tenant's secret-binding store")?;
    resolve_fork_secret_audit(tenant, declared, &bindings)?;
    let dropped = dropped_parent_secret_names(&parent_secret_names(checkpoint, store), declared);
    enforce_secret_attenuation(&dropped, allow_secret_drop)?;
    if !dropped.is_empty() {
        tracing::warn!(
            secrets = %dropped.join(", "),
            count = dropped.len(),
            "fork child intentionally drops parent secret bindings"
        );
    }
    Ok(())
}

fn resolve_fork_secret_audit(
    tenant: &str,
    declared: &[SecretBinding],
    bindings: &dyn mvm_hostd::keyholder::BindingStore,
) -> Result<Vec<mvm_hostd::audit::bind::CheckpointForkSecretBinding>> {
    use mvm_core::plan::SecretSource;
    declared.iter().filter_map(|binding| match &binding.source {
        SecretSource::Keystore { address } => Some((binding, address)),
        SecretSource::External { .. } => None,
    }).map(|(binding, address)| {
        let metadata = bindings.get(tenant, address)
            .with_context(|| format!("reading binding {address:?} for tenant {tenant:?}"))?
            .ok_or_else(|| anyhow::anyhow!(
                "secret {address:?} has no binding in child tenant {tenant:?}; bind it for that tenant before forking"
            ))?;
        Ok(mvm_hostd::audit::bind::CheckpointForkSecretBinding {
            name: binding.name.clone(),
            allowed_hosts: mvm_core::crypto::secret_binding::plan_binding_hosts(binding, address, &metadata)?,
        })
    }).collect()
}

pub(super) fn bind_checkpoint_forked(
    parent: &CheckpointId,
    child: &CheckpointMeta,
    child_vm_name: &str,
    store: &CheckpointStore,
    declared_secrets: &[SecretBinding],
    tenant: &str,
) -> Result<()> {
    let parent_vm_name = store.read_meta(parent).ok().map(|meta| meta.vm_name);
    let plan = match plan_persist::read_plan(&child.vm_name).or_else(|_| {
        match parent_vm_name.as_deref() {
            Some(name) => plan_persist::read_plan(name),
            None => Err(anyhow::anyhow!("parent checkpoint has no recorded vm_name")),
        }
    }) {
        Ok(plan) => plan,
        Err(error) => {
            tracing::warn!(%error, "no persisted plan for fork; checkpoint.forked emitted without chain binding");
            return Ok(());
        }
    };
    let signer = match mvm_hostd::audit::host_keypair::load_or_init() {
        Ok(signer) => signer,
        Err(error) => {
            tracing::warn!(%error, "host signer unavailable; chain entry skipped");
            return Ok(());
        }
    };
    let emitter = mvm_hostd::audit::emitter::AuditEmitter::new(signer.signing)
        .map(|emitter| emitter.with_receipts())
        .context("refusing an unaudited fork: audit emitter unavailable")?;
    let bindings = mvm_hostd::keyholder::FileBindingStore::default_location()
        .context("opening the child tenant's secret-binding store for fork audit")?;
    let secret_bindings = resolve_fork_secret_audit(tenant, declared_secrets, &bindings)?;
    mvm_hostd::audit::bind::bind_checkpoint_forked(
        &emitter,
        &plan,
        parent,
        child,
        child_vm_name,
        &secret_bindings,
    )
    .context("refusing an unaudited fork")?;
    Ok(())
}

#[cfg(test)]
#[path = "fork_regression.rs"]
mod regression;
