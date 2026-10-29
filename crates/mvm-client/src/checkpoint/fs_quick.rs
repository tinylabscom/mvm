//! Configured, authenticated FsQuick fork preparation and publication.
//!
//! These objects carry source facts, not admission or native execution authority.
//! The configured namespace is trusted against concurrent same-UID replacement.
//! Static opened-handle preflights precede canonical path-rooted readers; they
//! do not turn those later reads into same-FD custody or atomic reservations.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use mvm_core::checkpoint::{CheckpointDigest, CheckpointId, CheckpointMeta};
use mvm_core::plan::{ExecutionPlan, SecretBinding};
use mvm_hostd::audit::emitter::AuditEmitter;
use mvm_runtime::checkpoint::{CheckpointChainAnchor, CheckpointStore};

use crate::secret::SecretService;

#[cfg(all(test, unix))]
mod tests;

/// Phase whose operation refused or failed. No phase implies execution authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForkPhase {
    Classification,
    Preparation,
    Materialization,
    Publication,
    Admission,
    ChildLaunch,
}

/// Attempted artifact locations, not proof that either artifact is complete.
#[derive(Debug)]
pub struct ArtifactLocation {
    vm_directory: PathBuf,
    checkpoint_directory: PathBuf,
}

impl ArtifactLocation {
    pub fn vm_directory(&self) -> &Path {
        &self.vm_directory
    }

    pub fn checkpoint_directory(&self) -> &Path {
        &self.checkpoint_directory
    }
}

/// A failure retains its real source and, after copy begins, locations to inspect.
#[derive(Debug)]
pub struct ForkError {
    phase: ForkPhase,
    artifact: Option<ArtifactLocation>,
    source: anyhow::Error,
}

impl ForkError {
    fn new(phase: ForkPhase, source: anyhow::Error) -> Self {
        Self {
            phase,
            artifact: None,
            source,
        }
    }

    pub fn phase(&self) -> ForkPhase {
        self.phase
    }

    pub fn artifact(&self) -> Option<&ArtifactLocation> {
        self.artifact.as_ref()
    }
}

impl std::fmt::Display for ForkError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "FsQuick fork {:?} failed: {}",
            self.phase, self.source
        )?;
        if let Some(location) = &self.artifact {
            write!(
                formatter,
                "; inspect retained or attempted artifacts at {} and {}",
                location.vm_directory.display(),
                location.checkpoint_directory.display()
            )?;
        }
        Ok(())
    }
}

impl std::error::Error for ForkError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.source.as_ref())
    }
}

/// Plain fork intent. Fields neither select authority roots nor grant admission.
pub struct ForkRequest<'a> {
    pub checkpoint: &'a CheckpointId,
    pub child_name: Option<String>,
    pub declared_secrets: &'a [SecretBinding],
    pub allow_secret_drop: bool,
}

/// Configured mutation service, deliberately separate from the read-only catalog.
pub struct FsQuickForks {
    store: CheckpointStore,
}

impl FsQuickForks {
    /// Use only the existing configured checkpoint namespace.
    pub fn open() -> Self {
        Self {
            store: CheckpointStore::open(),
        }
    }

    /// Bounded classification without requiring FsQuick keys, tenant or signer.
    pub fn classify(&self, id: &CheckpointId) -> std::result::Result<CheckpointMeta, ForkError> {
        classify(&self.store, id).map_err(|error| ForkError::new(ForkPhase::Classification, error))
    }

    pub fn prepare_unbooted(
        &self,
        request: ForkRequest<'_>,
    ) -> std::result::Result<PreparedFsQuickFork<'_>, ForkError> {
        prepare(self, request, PreparationIntent::Unbooted)
            .map_err(|error| ForkError::new(ForkPhase::Preparation, error))
    }

    /// Authenticate original facts and issuer prerequisites before the adapter
    /// selects a tenant. Tenant selection can initialize ordinary user config.
    pub fn prepare_boot(
        &self,
        request: ForkRequest<'_>,
    ) -> std::result::Result<PreparedFsQuickBoot<'_>, ForkError> {
        let declared = request.declared_secrets;
        let prepared = prepare(self, request, PreparationIntent::Boot)
            .map_err(|error| ForkError::new(ForkPhase::Preparation, error))?;
        Ok(PreparedFsQuickBoot {
            prepared,
            declared: declared.to_vec(),
        })
    }
}

#[derive(Clone, Copy)]
enum PreparationIntent {
    Unbooted,
    Boot,
}

/// Authenticated preparation only, NOT admission or boot permission.
///
/// Original authentication, drop policy, destination and existing issuer
/// prerequisites have completed. The same captured facts and signing custody
/// remain private. This stage cannot copy or publish, and does not select or
/// initialize a tenant, config or secret metadata service.
///
/// ```compile_fail
/// use mvm_client::checkpoint::fs_quick::PreparedFsQuickBoot;
/// fn cannot_copy(stage: PreparedFsQuickBoot<'_>) {
///     let _ = stage.materialize_and_publish();
/// }
/// ```
pub struct PreparedFsQuickBoot<'a> {
    prepared: PreparedFsQuickFork<'a>,
    declared: Vec<SecretBinding>,
}

impl<'a> PreparedFsQuickBoot<'a> {
    /// Consume the authenticated stage with the adapter's once-selected child
    /// tenant. Canonical metadata validation/auditing follows, without copying
    /// config policy, inheriting the parent tenant or inventing copy approval.
    pub fn for_tenant(
        mut self,
        child_tenant: String,
    ) -> std::result::Result<PreparedFsQuickFork<'a>, ForkError> {
        let service = if self.declared.is_empty() {
            None
        } else {
            Some(
                SecretService::local()
                    .map_err(|error| ForkError::new(ForkPhase::Preparation, error.into()))?,
            )
        };
        let effective = match &service {
            Some(service) => effective_child_bindings(service, &child_tenant, &self.declared)
                .map_err(|error| ForkError::new(ForkPhase::Preparation, error))?,
            None => Vec::new(),
        };
        self.prepared.child_tenant = Some(child_tenant);
        self.prepared.effective = effective;
        self.prepared.service = service;
        Ok(self.prepared)
    }
}

/// Private captured preparation. Not cloneable, serializable or constructible.
///
/// Copy cannot be called separately from publication through the public API.
///
/// ```compile_fail
/// use mvm_client::checkpoint::fs_quick::PreparedFsQuickFork;
/// fn cannot_skip_publication(prepared: PreparedFsQuickFork<'_>) {
///     let _ = prepared.materialize();
/// }
/// ```
pub struct PreparedFsQuickFork<'a> {
    store: &'a CheckpointStore,
    parent: CheckpointMeta,
    plan: ExecutionPlan,
    anchor: StrictAnchor,
    emitter: AuditEmitter,
    child_id: CheckpointId,
    name: String,
    destination: PathBuf,
    now: u64,
    child_tenant: Option<String>,
    effective: Vec<SecretBinding>,
    service: Option<SecretService>,
}

impl PreparedFsQuickFork<'_> {
    fn location(&self) -> ArtifactLocation {
        ArtifactLocation {
            vm_directory: self.destination.clone(),
            checkpoint_directory: self.store.dir_for(&self.child_id),
        }
    }

    fn failure(&self, phase: ForkPhase, source: anyhow::Error) -> ForkError {
        ForkError {
            phase,
            artifact: Some(self.location()),
            source,
        }
    }

    /// Copy and publish as one consuming operation. Publication failure is an
    /// error with retained locations, never success or a claimed rollback.
    pub fn materialize_and_publish(
        self,
    ) -> std::result::Result<MaterializedFsQuickFork, ForkError> {
        self.revalidate()
            .map_err(|error| ForkError::new(ForkPhase::Preparation, error))?;
        let child = self
            .materialize()
            .map_err(|error| self.failure(ForkPhase::Materialization, error))?;
        self.publish(&child)
            .map_err(|error| self.failure(ForkPhase::Publication, error))?;
        let location = self.location();
        Ok(MaterializedFsQuickFork {
            parent: self.parent,
            plan: self.plan,
            child,
            name: self.name,
            location,
            child_tenant: self.child_tenant,
            effective: self.effective,
            service: self.service,
        })
    }

    fn materialize(&self) -> Result<CheckpointMeta> {
        if classify(self.store, &self.parent.id)? != self.parent {
            bail!("parent checkpoint changed during fork preparation");
        }
        absent(&self.destination)?;
        absent(&self.store.dir_for(&self.child_id))?;
        mvm_runtime::checkpoint::fork_checkpoint(
            self.store,
            mvm_runtime::checkpoint::ForkParams {
                checkpoint: self.parent.id.clone(),
                child_id: self.child_id.clone(),
                child_vm_name: self.name.clone(),
                dest_dir: self.destination.clone(),
                created_unix: self.now,
                parent_liveness: mvm_runtime::checkpoint::ForkParentLiveness::MustBeStopped,
                child_plan_json: None,
                child_tenant_id: None,
            },
            &self.anchor,
        )
    }

    fn publish(&self, child: &CheckpointMeta) -> Result<()> {
        if child.id != self.child_id
            || child.vm_name != self.name
            || child.parent.as_ref() != Some(&self.parent.meta_digest)
        {
            bail!("materialized fork identity does not match its prepared parent");
        }
        if classify(self.store, &self.parent.id)? != self.parent {
            bail!("parent checkpoint changed during materialization");
        }
        let bindings = self
            .effective
            .iter()
            .map(
                |binding| mvm_hostd::audit::bind::CheckpointForkSecretBinding {
                    name: binding.name.clone(),
                    allowed_hosts: binding.destinations.clone(),
                },
            )
            .collect::<Vec<_>>();
        mvm_hostd::audit::bind::bind_checkpoint_forked(
            &self.emitter,
            &self.plan,
            &self.parent.id,
            child,
            &self.name,
            &bindings,
        )
        .context("lineage publication failed")
    }

    fn revalidate(&self) -> Result<()> {
        revalidate(
            self.service.as_ref(),
            self.child_tenant.as_deref(),
            &self.effective,
        )
    }
}

/// Published data and captured settings; this is not an admitted plan or permit.
pub struct MaterializedFsQuickFork {
    parent: CheckpointMeta,
    plan: ExecutionPlan,
    child: CheckpointMeta,
    name: String,
    location: ArtifactLocation,
    child_tenant: Option<String>,
    effective: Vec<SecretBinding>,
    service: Option<SecretService>,
}

impl MaterializedFsQuickFork {
    pub fn checkpoint(&self) -> &CheckpointMeta {
        &self.child
    }
    pub fn parent_plan(&self) -> &ExecutionPlan {
        &self.plan
    }
    pub fn parent_meta(&self) -> &CheckpointMeta {
        &self.parent
    }
    pub fn child_name(&self) -> &str {
        &self.name
    }
    pub fn destination(&self) -> &Path {
        &self.location.vm_directory
    }
    pub fn child_tenant(&self) -> Option<&str> {
        self.child_tenant.as_deref()
    }
    pub fn bindings(&self) -> &[SecretBinding] {
        &self.effective
    }

    /// Require the real admitted owner before the adapter reaches its backend.
    /// Actual per-use SecretUse approval remains the live endpoint's job.
    pub fn validate_admitted_plan(
        &self,
        admitted: &mvm_hostd::plan_admission::AdmittedPlan,
    ) -> std::result::Result<(), ForkError> {
        self.validate_child_data(admitted.plan())
            .map_err(|error| self.retained_failure(ForkPhase::Admission, error))
    }

    fn validate_child_data(&self, child: &ExecutionPlan) -> Result<()> {
        validate_child_data(
            child,
            &self.name,
            self.child_tenant.as_deref(),
            &self.effective,
            self.service.as_ref(),
        )
    }

    pub fn retained_error(&self, source: anyhow::Error) -> ForkError {
        self.retained_failure(ForkPhase::ChildLaunch, source)
    }

    fn retained_failure(&self, phase: ForkPhase, source: anyhow::Error) -> ForkError {
        ForkError {
            phase,
            artifact: Some(ArtifactLocation {
                vm_directory: self.location.vm_directory.clone(),
                checkpoint_directory: self.location.checkpoint_directory.clone(),
            }),
            source,
        }
    }
}

// Private comparison seam for synthetic test data. The public checker accepts
// only an actual AdmittedPlan owner, never an externally supplied plain plan.
fn validate_child_data(
    child: &ExecutionPlan,
    name: &str,
    tenant: Option<&str>,
    effective: &[SecretBinding],
    service: Option<&SecretService>,
) -> Result<()> {
    if Some(child.tenant.0.as_str()) != tenant
        || child.workload.0 != name
        || child.secrets != effective
    {
        bail!("admitted child does not retain the prepared fork secret bindings");
    }
    revalidate(service, tenant, effective)
}

struct Creation {
    digest: CheckpointDigest,
    tenant: String,
    plan_id: String,
}

struct StrictAnchor {
    recorded: std::collections::HashMap<String, Creation>,
}

impl CheckpointChainAnchor for StrictAnchor {
    fn recorded_creation_digest(&self, meta: &CheckpointMeta) -> Result<Option<CheckpointDigest>> {
        Ok(self
            .recorded
            .get(meta.id.as_str())
            .map(|entry| entry.digest.clone()))
    }

    fn recorded_creation_tenant(&self, meta: &CheckpointMeta) -> Result<Option<String>> {
        Ok(self
            .recorded
            .get(meta.id.as_str())
            .map(|entry| entry.tenant.clone()))
    }
}

fn revalidate(
    service: Option<&SecretService>,
    tenant: Option<&str>,
    effective: &[SecretBinding],
) -> Result<()> {
    if let Some(service) = service {
        let current = effective_child_bindings(
            service,
            tenant.context("boot tenant is missing")?,
            effective,
        )?;
        if current != effective {
            bail!("fork secret policy changed after preparation; refusing stale signed bindings");
        }
    }
    Ok(())
}

fn effective_child_bindings(
    service: &SecretService,
    tenant: &str,
    declared: &[SecretBinding],
) -> Result<Vec<SecretBinding>> {
    use mvm_core::crypto::secret_binding::{SecretApproval, plan_binding_hosts};
    use mvm_core::plan::SecretSource;
    crate::admission::secrets::validate_secret_sources(declared)?;
    let mut effective = Vec::with_capacity(declared.len());
    for binding in declared {
        let SecretSource::Keystore { address } = &binding.source else {
            unreachable!("sources validated before metadata access");
        };
        // Canonical get ok/miss/err auditing, without revealing a value or
        // minting a substitution placeholder.
        let stored = service
            .metadata(tenant, address)?
            .context("fork secret is missing")?
            .binding
            .context("fork secret binding is missing")?;
        if !stored.inject.admits(stored.auth_type) {
            bail!("fork secret injection mode is incompatible with its authentication type");
        }
        let destinations = plan_binding_hosts(binding, address, &stored)?;
        if destinations.is_empty() {
            // [] is dynamic stored policy, not a representable pinned deny-all.
            bail!("strict fork requires a nonempty effective secret destination set");
        }
        let mut bound = binding.clone();
        bound.destinations = destinations;
        bound.approval_required |= stored.approve == SecretApproval::Ask;
        effective.push(bound);
    }
    Ok(effective)
}

fn absent(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        _ => bail!("fork destination is occupied or cannot be inspected"),
    }
}

#[cfg(not(unix))]
fn classify(_store: &CheckpointStore, _id: &CheckpointId) -> Result<CheckpointMeta> {
    bail!("guarded checkpoint classification is unsupported on this host")
}

#[cfg(not(unix))]
fn prepare<'a>(
    _service: &'a FsQuickForks,
    _request: ForkRequest<'_>,
    _intent: PreparationIntent,
) -> Result<PreparedFsQuickFork<'a>> {
    bail!("guarded FsQuick forks are unsupported on this host")
}

#[cfg(unix)]
use guarded::{classify, prepare};

#[cfg(unix)]
mod guarded {
    use super::*;
    use mvm_core::transcript::local_store::LocalTranscriptStore;
    use std::collections::{BTreeSet, HashMap};
    use std::fs::{File, OpenOptions};
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    pub(super) const MAX_FORK_PLAN_BYTES: u64 = 4 * 1024 * 1024;
    pub(super) const MAX_CHECKPOINT_META_BYTES: u64 = 4 * 1024 * 1024;
    pub(super) const MAX_CHECKPOINT_STORE_ENTRIES: usize = 256;
    const METADATA_READ_BUDGET: u64 = 64 * 1024 * 1024;

    fn private_directory(path: &Path) -> Result<()> {
        let metadata = std::fs::symlink_metadata(path)
            .context("required existing fork authority directory is unavailable")?;
        mvm_core::private_fs::require_current_owner(&metadata)?;
        if !metadata.is_dir() || metadata.mode() & 0o7777 != 0o700 {
            bail!("fork authority directory must be existing, owned and private");
        }
        Ok(())
    }

    fn authority_file(path: &Path, allowed_modes: &[u32]) -> Result<File> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(path)
            .context("required existing fork authority file is unavailable")?;
        let metadata = file.metadata().context("reading fork authority metadata")?;
        mvm_core::private_fs::require_current_owner(&metadata)?;
        if !metadata.is_file()
            || metadata.nlink() != 1
            || !allowed_modes.contains(&(metadata.mode() & 0o7777))
        {
            bail!("fork authority file must be regular, owned, private and single-link");
        }
        Ok(file)
    }

    fn read_checkpoint(
        store: &CheckpointStore,
        id: &CheckpointId,
        remaining: &mut u64,
    ) -> Result<CheckpointMeta> {
        private_directory(store.root())?;
        private_directory(&store.dir_for(id))?;
        let file = authority_file(&store.dir_for(id).join("meta.json"), &[0o600])?;
        let limit = MAX_CHECKPOINT_META_BYTES.min(
            remaining
                .checked_sub(1)
                .context("checkpoint metadata read budget exceeded")?,
        );
        if file.metadata()?.len() > limit {
            bail!("checkpoint metadata exceeds the 4 MiB member or 64 MiB aggregate bound");
        }
        let mut bytes = Vec::new();
        file.take(limit + 1)
            .read_to_end(&mut bytes)
            .context("reading bounded checkpoint metadata")?;
        *remaining -= bytes.len() as u64;
        if bytes.len() as u64 > limit {
            bail!("checkpoint metadata exceeds the 4 MiB member or 64 MiB aggregate bound");
        }
        let meta: CheckpointMeta = serde_json::from_slice(&bytes)
            .map_err(|_| anyhow::anyhow!("checkpoint metadata is malformed"))?;
        if meta.id != *id {
            bail!("checkpoint metadata ID does not match its directory");
        }
        Ok(meta)
    }

    pub(super) fn classify(store: &CheckpointStore, id: &CheckpointId) -> Result<CheckpointMeta> {
        super::super::validated_id(id.as_str())?;
        let mut remaining = METADATA_READ_BUDGET;
        read_checkpoint(store, id, &mut remaining)
    }

    fn preflight_store(store: &CheckpointStore) -> Result<()> {
        private_directory(store.root())?;
        let mut remaining = METADATA_READ_BUDGET;
        for (examined, entry) in std::fs::read_dir(store.root())?.enumerate() {
            if examined >= MAX_CHECKPOINT_STORE_ENTRIES {
                bail!("checkpoint store exceeds the 256 examined-entry bound");
            }
            let entry = entry?;
            let name = entry.file_name();
            let name = name
                .to_str()
                .context("checkpoint directory name is unsupported")?;
            if name.starts_with('.') {
                continue;
            }
            let kind = entry.file_type()?;
            if kind.is_symlink() {
                bail!("checkpoint store member must not be a symlink");
            }
            if !kind.is_dir() {
                continue;
            }
            let id = super::super::validated_id(name)
                .map_err(|_| anyhow::anyhow!("checkpoint directory ID is invalid"))?;
            read_checkpoint(store, &id, &mut remaining)?;
        }
        // Canonical by-digest ancestry lookup reopens paths. Static availability
        // preflight is not hostile concurrent replacement protection.
        Ok(())
    }

    pub(super) fn load_anchor(
        home: &Path,
        keys: &LocalTranscriptStore,
    ) -> Result<(StrictAnchor, ed25519_dalek::VerifyingKey)> {
        private_directory(home)?;
        let dir = home.join("audit");
        private_directory(&dir)?;
        let verifying = keys
            .existing_host_public_key()
            .context("existing host verification authority is required")?;
        let mut bases = BTreeSet::new();
        for member in std::fs::read_dir(&dir).context("reading existing audit directory")? {
            let path = member?.path();
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .context("audit member name is not supported")?;
            if name.ends_with(".jsonl") {
                authority_file(&path, &[0o600, 0o644])?;
            }
            if mvm_core::config::is_host_lifecycle_chain(&path)
                && let Some(base) = mvm_core::config::lifecycle_chain_base(name)
            {
                bases.insert(base.to_owned());
            }
        }
        if bases.is_empty() {
            bail!("authenticated original checkpoint history is missing");
        }
        let mut recorded = HashMap::new();
        for base in bases {
            let history =
                mvm_core::audit_verify::set::read_verified_history(&dir, &base, &verifying)
                    .map_err(|_| {
                        anyhow::anyhow!("original checkpoint history failed verification")
                    })?;
            if history.pruned.is_some() {
                bail!("pruned history cannot establish unambiguous original checkpoint policy");
            }
            for segment in history.segments {
                for entry in segment
                    .entries
                    .context("verified lifecycle entries are unavailable")?
                {
                    if entry.tenant.0 != base {
                        bail!("verified audit tenant does not match its lifecycle chain");
                    }
                    use mvm_hostd::audit::emitter::checkpoint_audit as k;
                    let (id_key, digest_key) = if entry.event == k::CREATED_EVENT {
                        (k::LABEL_CHECKPOINT_ID, k::LABEL_META_DIGEST)
                    } else if entry.event == k::FORKED_EVENT {
                        (k::LABEL_CHILD_ID, k::LABEL_CHILD_DIGEST)
                    } else {
                        continue;
                    };
                    let id = entry
                        .labels
                        .get(id_key)
                        .context("checkpoint creation ID is missing")?;
                    let digest = entry
                        .labels
                        .get(digest_key)
                        .context("checkpoint creation digest is missing")?;
                    let value = Creation {
                        digest: CheckpointDigest::parse(digest.clone())?,
                        tenant: entry.tenant.0,
                        plan_id: entry.plan_id.0,
                    };
                    if recorded.insert(id.clone(), value).is_some() {
                        bail!("duplicate or conflicting original checkpoint creation evidence");
                    }
                }
            }
        }
        Ok((StrictAnchor { recorded }, verifying))
    }

    fn original_plan(
        home: &Path,
        anchor: &StrictAnchor,
        parent: &CheckpointMeta,
    ) -> Result<ExecutionPlan> {
        mvm_core::naming::validate_vm_name(&parent.vm_name)?;
        private_directory(&home.join("vms"))?;
        private_directory(&mvm_core::config::vm_state_dir(&parent.vm_name))?;
        let path = mvm_hostd::audit::plan_persist::plan_path(&parent.vm_name)?;
        let mut bytes = Vec::new();
        authority_file(&path, &[0o600])?
            .take(MAX_FORK_PLAN_BYTES + 1)
            .read_to_end(&mut bytes)
            .context("reading bounded original-plan candidate")?;
        if bytes.len() as u64 > MAX_FORK_PLAN_BYTES {
            bail!("original-plan candidate exceeds the 4 MiB bound");
        }
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| anyhow::anyhow!("original-plan candidate is malformed"))?;
        let plan = mvm_core::plan::plan_from_admitted_json(text)
            .map_err(|_| anyhow::anyhow!("original-plan candidate is malformed"))?;
        mvm_core::plan::verify_plan_id(&plan)
            .map_err(|_| anyhow::anyhow!("original-plan candidate is not content-addressed"))?;
        if anchor
            .recorded
            .get(parent.id.as_str())
            .map(|entry| entry.plan_id.as_str())
            != Some(plan.plan_id.0.as_str())
            || anchor.recorded_creation_tenant(parent)?.as_deref() != Some(plan.tenant.0.as_str())
            || plan.workload.0 != parent.vm_name
        {
            bail!("plan candidate does not match authenticated original checkpoint identity");
        }
        crate::admission::secrets::validate_secret_sources(&plan.secrets)?;
        Ok(plan)
    }

    pub(super) fn prepare<'a>(
        service: &'a FsQuickForks,
        request: ForkRequest<'_>,
        intent: PreparationIntent,
    ) -> Result<PreparedFsQuickFork<'a>> {
        crate::admission::secrets::validate_secret_sources(request.declared_secrets)?;
        if matches!(intent, PreparationIntent::Unbooted) && !request.declared_secrets.is_empty() {
            bail!(
                "--secret requires --boot for an fs_quick fork because an unbooted clone has no child plan"
            );
        }
        let parent = classify(&service.store, request.checkpoint)?;
        if parent.class != mvm_core::checkpoint::CheckpointClass::FsQuick {
            bail!("strict fork requires an fs_quick checkpoint");
        }
        let home = mvm_core::config::mvm_home_strict()?;
        let keys = LocalTranscriptStore::open(&home)
            .context("existing fork authority root is required")?;
        let (anchor, history_key) = load_anchor(&home, &keys)?;
        preflight_store(&service.store)?;
        mvm_runtime::checkpoint::verify_lineage(&service.store, request.checkpoint, &anchor)?;
        let plan = original_plan(&home, &anchor, &parent)?;
        let dropped = plan
            .secrets
            .iter()
            .filter(|original| {
                !request
                    .declared_secrets
                    .iter()
                    .any(|binding| binding.name == original.name)
            })
            .map(|binding| binding.name.as_str())
            .collect::<Vec<_>>();
        if !dropped.is_empty() && !request.allow_secret_drop {
            bail!(
                "fork child would drop parent secret bindings: {}. Redeclare each required binding with --secret NAME, or pass --allow-secret-drop to attenuate them intentionally",
                dropped.join(", ")
            );
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let name = request
            .child_name
            .unwrap_or_else(|| format!("{}-fork-{now}", request.checkpoint.as_str()));
        mvm_core::naming::validate_vm_name(&name)?;
        let child_id = super::super::validated_id(&format!("fork-{name}-{now}"))?;
        if name == parent.vm_name || child_id == *request.checkpoint {
            bail!("fork destination must differ from the parent");
        }
        let destination = mvm_core::config::vm_state_dir(&name);
        absent(&destination)?;
        absent(&service.store.dir_for(&child_id))?;
        let keys =
            LocalTranscriptStore::open(&home).context("existing fork signing root is required")?;
        let (signing, verifying) = keys
            .existing_host_keypair()
            .context("existing matching host signing authority is required")?;
        if history_key != verifying {
            bail!("fork verification authority changed");
        }
        private_directory(&home)?;
        private_directory(&home.join("audit"))?;
        let mut emitter = AuditEmitter::with_dir(signing, &home.join("audit"))?;
        if matches!(intent, PreparationIntent::Boot) {
            emitter = emitter.with_receipts();
        }
        Ok(PreparedFsQuickFork {
            store: &service.store,
            parent,
            plan,
            anchor,
            emitter,
            child_id,
            name,
            destination,
            now,
            child_tenant: None,
            effective: Vec::new(),
            service: None,
        })
    }
}
