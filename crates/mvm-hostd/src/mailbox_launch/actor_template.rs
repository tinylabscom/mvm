//! Immutable, encrypted endpoint bindings, installed before an actor boots.

use std::fs;
use std::io::{Error, ErrorKind, Result};
use std::path::{Path, PathBuf};

use ed25519_dalek::SigningKey;
use mvm_contract::plan::ExecutionPlan;
use mvm_contract::protocol::mailbox::{
    CapabilityId, CapabilityOperations, MailboxAddress, MailboxMessageKind, MailboxOperation,
    PrincipalId, SignedMailboxCapability,
};
use mvm_contract::protocol::mailbox::{ExecutionEpoch, MailboxGrant, MailboxId};
use mvm_core::crypto::aead::{self, Key};
use mvm_core::private_fs;
use mvm_core::util::atomic_io::{NewFile, sync_dir, write_private, write_private_new};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::{ENCRYPTION_ROOT, MailboxTemplate, derive, derive_with, derived_keys};

const DIRECTORY: &str = "actor-mailbox-templates";
const MAX_BYTES: u64 = 64 * 1024;
const MAX_ENDPOINTS: usize = 4096;
const MAX_PEERS: usize = 64;
const DOMAIN: &[u8] = b"mvm.actor-mailbox.template.v1";

pub(crate) fn current_time_ms() -> Result<i64> {
    let duration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(Error::other)?;
    i64::try_from(duration.as_millis()).map_err(Error::other)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ActorEndpointTemplate {
    pub workload: String,
    pub snapshot_digest: [u8; 32],
    pub max_storage_bytes: u64,
    pub max_send_attempts: u32,
    pub membership: mvm_contract::protocol::workload_actor::WorkflowBinding,
    pub grant: MailboxGrant,
    pub template: MailboxTemplate,
    pub parent: Option<MailboxGrant>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    endpoint: ActorEndpointTemplate,
    revoked: bool,
    admitted_plan: Option<[u8; 32]>,
}

fn refused() -> Error {
    Error::new(ErrorKind::PermissionDenied, "actor mailbox binding refused")
}

fn path(keys_dir: &Path, grant: &MailboxGrant) -> PathBuf {
    keys_dir.join(DIRECTORY).join(format!(
        "{}-{}.sealed",
        hex::encode(grant.mailbox.as_bytes()),
        grant.epoch.get()
    ))
}

fn sealing_key(keys_dir: &Path, grant: &MailboxGrant) -> Result<Key> {
    let root = Key::load(&keys_dir.join(ENCRYPTION_ROOT))?;
    Ok(Key::from_bytes(*derive(
        root.expose_bytes(),
        DOMAIN,
        &grant.mailbox,
        grant.epoch,
    )))
}

fn aad(grant: &MailboxGrant) -> Result<Vec<u8>> {
    serde_json::to_vec(&(DOMAIN, grant)).map_err(Error::other)
}

fn read(keys_dir: &Path, grant: &MailboxGrant) -> Result<Record> {
    let bytes = crate::admission_budget::read_private(&path(keys_dir, grant), MAX_BYTES as usize)
        .map_err(Error::other)?
        .ok_or_else(refused)?;
    let plaintext = Zeroizing::new(
        aead::open(&sealing_key(keys_dir, grant)?, &bytes, &aad(grant)?).map_err(|_| refused())?,
    );
    let record: Record = serde_json::from_slice(&plaintext).map_err(|_| refused())?;
    if record.endpoint.grant != *grant {
        return Err(refused());
    }
    Ok(record)
}

/// Absence permits legacy serving; corruption and revocation never fall back.
pub(crate) fn load(keys_dir: &Path, grant: &MailboxGrant) -> Result<Option<ActorEndpointTemplate>> {
    match fs::symlink_metadata(path(keys_dir, grant)) {
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
        Ok(_) => {}
    }
    let record = read(keys_dir, grant)?;
    if record.revoked {
        return Err(refused());
    }
    Ok(Some(record.endpoint))
}

/// Require exact signed workflow/workload bindings, including on helper restart.
pub(crate) fn verify_plan(
    keys_dir: &Path,
    plan: &ExecutionPlan,
) -> Result<Option<ActorEndpointTemplate>> {
    let Some(grant) = plan.mailbox else {
        return Ok(None);
    };
    if grant.epoch.get() != plan.execution_epoch {
        return Err(refused());
    }
    let template = load(keys_dir, &grant)?;
    match (&plan.workflow, &template) {
        (None, None) => {}
        (Some(workflow), Some(template))
            if template.workload == plan.workload.0
                && template.membership == *workflow
                && workflow.constraint_snapshot_digest
                    == mvm_contract::assurance::Sha256Digest::from_bytes(
                        &template.snapshot_digest,
                    ) => {}
        _ => return Err(refused()),
    }
    if let Some(template) = &template {
        let record = read(keys_dir, &template.grant)?;
        if let Some(bound) = record.admitted_plan
            && bound != plan_binding(plan)?
        {
            return Err(refused());
        }
    }
    Ok(template)
}

pub(crate) fn install(keys_dir: &Path, endpoint: ActorEndpointTemplate) -> Result<()> {
    let grant = endpoint.grant;
    let derived = derived_keys(keys_dir, &grant.mailbox, grant.epoch)?;
    if derived.authority.verifying_key().to_bytes() != grant.authority_key {
        return Err(refused());
    }
    endpoint
        .template
        .capability
        .validate_bounds()
        .map_err(|_| refused())?;
    let directory = keys_dir.join(DIRECTORY);
    private_fs::ensure_private_dir(&directory)?;
    sync_dir(keys_dir).map_err(Error::other)?;
    let target = path(keys_dir, &grant);
    let _lock = crate::admission_budget::acquire_lock(&directory.join("registry.lock"))
        .map_err(Error::other)?;
    if fs::symlink_metadata(&target).is_ok() {
        let record = read(keys_dir, &grant)?;
        return if !record.revoked && record.endpoint == endpoint {
            Ok(())
        } else {
            Err(refused())
        };
    }
    Key::load_or_create(&keys_dir.join(ENCRYPTION_ROOT))?;
    if fs::read_dir(&directory)?.count() > MAX_ENDPOINTS {
        return Err(refused());
    }
    let record = Record {
        endpoint,
        revoked: false,
        admitted_plan: None,
    };
    let plaintext = Zeroizing::new(serde_json::to_vec(&record).map_err(Error::other)?);
    let sealed = aead::seal(&sealing_key(keys_dir, &grant)?, &plaintext, &aad(&grant)?);
    if sealed.len() as u64 > MAX_BYTES {
        return Err(refused());
    }
    let registry = registry_directory(keys_dir, &grant);
    private_fs::ensure_private_dir(&registry)?;
    private_fs::sync_managed_directory_chain(keys_dir, &registry)?;
    if write_private_new(&target, &sealed)? != NewFile::Created {
        return Err(refused());
    }
    Ok(())
}

/// Retain a durable tombstone and accepted history; never remint this epoch.
pub(crate) fn revoke(keys_dir: &Path, grant: &MailboxGrant) -> Result<()> {
    let target = path(keys_dir, grant);
    let _lock =
        crate::admission_budget::acquire_lock(&keys_dir.join(DIRECTORY).join("registry.lock"))
            .map_err(Error::other)?;
    let mut record = read(keys_dir, grant)?;
    record.revoked = true;
    let plaintext = Zeroizing::new(serde_json::to_vec(&record).map_err(Error::other)?);
    let sealed = aead::seal(&sealing_key(keys_dir, grant)?, &plaintext, &aad(grant)?);
    write_private(&target, &sealed)
}

/// A fresh workload identity yields a fresh, host-derived mailbox identity.
pub(crate) fn child_mailbox(
    keys_dir: &Path,
    parent: &MailboxGrant,
    workload: &str,
    epoch: ExecutionEpoch,
) -> Result<MailboxId> {
    let derived = derived_keys(keys_dir, &parent.mailbox, parent.epoch)?;
    Ok(MailboxId::from_bytes(*derive_with(
        &derived.root,
        b"mvm.actor.child-mailbox.v1",
        &parent.mailbox,
        epoch,
        workload.as_bytes(),
    )))
}

/// Build a template without consulting the legacy operator-wide override.
pub(crate) fn base_template(
    keys_dir: &Path,
    grant: &MailboxGrant,
    now: i64,
) -> Result<MailboxTemplate> {
    let derived = derived_keys(keys_dir, &grant.mailbox, grant.epoch)?;
    Ok(super::default_template(&derived, grant, now))
}

pub(crate) fn signed_capability(
    keys_dir: &Path,
    endpoint: &ActorEndpointTemplate,
) -> Result<mvm_contract::protocol::mailbox::SignedMailboxCapability> {
    let derived = derived_keys(keys_dir, &endpoint.grant.mailbox, endpoint.grant.epoch)?;
    mvm_core::mailbox::sign_capability(endpoint.template.capability.clone(), &derived.authority)
        .map_err(Error::other)
}

/// Only this endpoint's private keys cross its launcher-to-helper pipe.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActorEndpointMaterial {
    workload: String,
    snapshot_digest: [u8; 32],
    plan_binding: [u8; 32],
    grant: MailboxGrant,
    pub address: MailboxAddress,
    pub epoch: ExecutionEpoch,
    pub template: MailboxTemplate,
    pub registry_directory: PathBuf,
    pub max_storage_bytes: u64,
    pub max_send_attempts: u32,
    sender: [u8; 32],
    authority: [u8; 32],
    registry_key: [u8; 32],
    state_key: [u8; 32],
}

impl std::fmt::Debug for ActorEndpointMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ActorEndpointMaterial")
            .finish_non_exhaustive()
    }
}

impl Drop for ActorEndpointMaterial {
    fn drop(&mut self) {
        use zeroize::Zeroize as _;
        self.sender.zeroize();
        self.authority.zeroize();
        self.registry_key.zeroize();
        self.state_key.zeroize();
    }
}

impl ActorEndpointMaterial {
    /// Verify a launcher handoff using only this endpoint's keys and signed plan.
    pub fn verify_plan(&self, plan: &ExecutionPlan) -> Result<()> {
        let Some(workflow) = &plan.workflow else {
            return Err(refused());
        };
        if self.workload != plan.workload.0
            || plan.plan_id != mvm_core::plan::compute_plan_id(plan)
            || plan.mailbox != Some(self.grant)
            || plan_binding(plan)? != self.plan_binding
            || self.grant.epoch.get() != plan.execution_epoch
            || workflow.constraint_snapshot_digest
                != mvm_contract::assurance::Sha256Digest::from_bytes(&self.snapshot_digest)
            || self.authority_key().verifying_key().to_bytes() != self.grant.authority_key
            || self.template.capability.address != self.address
            || self.address.mailbox != self.grant.mailbox
            || self.template.capability.subject != self.address.recipient
            || self.sender_key().verifying_key().to_bytes() != *self.address.recipient.as_bytes()
        {
            return Err(refused());
        }
        Ok(())
    }

    pub fn sender_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.sender)
    }
    pub fn authority_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.authority)
    }
    pub fn state_key(&self) -> Key {
        Key::from_bytes(self.state_key)
    }
    /// Stable associated-data binding for state retained beyond the current process.
    pub fn plan_binding(&self) -> [u8; 32] {
        self.plan_binding
    }

    /// Resolve only a canonical, admitted peer in this endpoint's sealed registry.
    pub fn peer(&self, address: &MailboxAddress) -> Result<ActorPeerBinding> {
        let path = peer_path(&self.registry_directory, address)?;
        let record = read_peer(&path, &self.registry_key, self.address)?;
        if record.revoked
            || record.binding.parent_plan_binding.is_none()
            || record.binding.child_plan_binding.is_none()
            || record.binding.local_address() != self.address
            || record.binding.peer_address() != *address
        {
            return Err(refused());
        }
        Ok(record.binding)
    }

    #[cfg(test)]
    pub(crate) fn set_test_peer_socket(
        &self,
        address: &MailboxAddress,
        socket: PathBuf,
    ) -> Result<()> {
        let path = peer_path(&self.registry_directory, address)?;
        let mut record = read_peer(&path, &self.registry_key, self.address)?;
        record.binding.peer_socket = socket;
        let plaintext = Zeroizing::new(serde_json::to_vec(&record).map_err(Error::other)?);
        let sealed = aead::seal(
            &Key::from_bytes(self.registry_key),
            &plaintext,
            &peer_aad(self.address, &path)?,
        );
        write_private(&path, &sealed)
    }

    /// Enumerate this endpoint's bounded active peers, without exposing a root key.
    pub fn peers(&self) -> Result<Vec<ActorPeerBinding>> {
        let mut peers = Vec::new();
        let mut entries = 0usize;
        for entry in fs::read_dir(&self.registry_directory)? {
            let path = entry?.path();
            if path.file_name().is_some_and(|name| name == "registry.lock") {
                continue;
            }
            entries += 1;
            if entries > MAX_PEERS {
                return Err(refused());
            }
            let record = read_peer(&path, &self.registry_key, self.address)?;
            if !record.revoked
                && record.binding.parent_plan_binding.is_some()
                && record.binding.child_plan_binding.is_some()
            {
                peers.push(record.binding);
            }
        }
        Ok(peers)
    }
}

/// The direction of a fixed parent/child pair, never a guest-selected role.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActorPeerRole {
    Parent,
    Child,
}

/// Pair-specific payload keys and already-signed operation ceilings.
///
/// The child gets no parent authority private key and no parent-wide inbox key.
/// A Reply capability is issued per call by the parent's endpoint owner, never
/// by turning the Call's Send capability around.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActorPeerBinding {
    pub role: ActorPeerRole,
    pub parent_address: MailboxAddress,
    pub child_address: MailboxAddress,
    pub parent_plan_binding: Option<[u8; 32]>,
    pub child_plan_binding: Option<[u8; 32]>,
    pub epoch: ExecutionEpoch,
    pub call: MailboxTemplate,
    pub reply_header: mvm_contract::protocol::mailbox::MailboxEnvelopeHeader,
    pub reply_routing: mvm_contract::protocol::mailbox::MailboxRoutingFrame,
    pub send_capability: SignedMailboxCapability,
    pub parent_receive: SignedMailboxCapability,
    pub child_receive: SignedMailboxCapability,
    pub parent_authority_key: [u8; 32],
    pub child_authority_key: [u8; 32],
    pub parent_sender_key: [u8; 32],
    pub child_sender_key: [u8; 32],
    pub peer_socket: PathBuf,
    call_key: [u8; 32],
    reply_key: [u8; 32],
}

impl std::fmt::Debug for ActorPeerBinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ActorPeerBinding").finish_non_exhaustive()
    }
}

impl Drop for ActorPeerBinding {
    fn drop(&mut self) {
        use zeroize::Zeroize as _;
        self.call_key.zeroize();
        self.reply_key.zeroize();
    }
}

impl ActorPeerBinding {
    pub fn call_key(&self) -> Key {
        Key::from_bytes(self.call_key)
    }
    pub fn reply_key(&self) -> Key {
        Key::from_bytes(self.reply_key)
    }
    pub fn local_address(&self) -> MailboxAddress {
        match self.role {
            ActorPeerRole::Parent => self.parent_address,
            ActorPeerRole::Child => self.child_address,
        }
    }
    pub fn peer_address(&self) -> MailboxAddress {
        match self.role {
            ActorPeerRole::Parent => self.child_address,
            ActorPeerRole::Child => self.parent_address,
        }
    }
}

/// Derive only the VM-scoped handoff after verifying its exact admitted plan.
pub fn endpoint_material(
    keys_dir: &Path,
    plan: &ExecutionPlan,
) -> Result<Option<ActorEndpointMaterial>> {
    if plan.plan_id != mvm_core::plan::compute_plan_id(plan) {
        return Err(refused());
    }
    let Some(endpoint) = verify_plan(keys_dir, plan)? else {
        return Ok(None);
    };
    {
        let _lock =
            crate::admission_budget::acquire_lock(&keys_dir.join(DIRECTORY).join("registry.lock"))
                .map_err(Error::other)?;
        let mut record = read(keys_dir, &endpoint.grant)?;
        let binding = plan_binding(plan)?;
        if record.revoked
            || record
                .admitted_plan
                .is_some_and(|current| current != binding)
        {
            return Err(refused());
        }
        if record.admitted_plan.is_none() {
            record.admitted_plan = Some(binding);
            let clear = Zeroizing::new(serde_json::to_vec(&record).map_err(Error::other)?);
            let sealed = aead::seal(
                &sealing_key(keys_dir, &endpoint.grant)?,
                &clear,
                &aad(&endpoint.grant)?,
            );
            write_private(&path(keys_dir, &endpoint.grant), &sealed)?;
        }
    }
    if let Some(parent_grant) = endpoint.parent {
        let parent = read(keys_dir, &parent_grant)?;
        if parent.revoked || parent.admitted_plan.is_none() {
            return Err(refused());
        }
        install_pair(keys_dir, &parent.endpoint, &endpoint)?;
    }
    let mut material = material(keys_dir, &endpoint)?;
    material.plan_binding = plan_binding(plan)?;
    material.state_key = *derive_with(
        &material.state_key,
        b"mvm.actor.admitted-state.v1",
        &endpoint.grant.mailbox,
        endpoint.grant.epoch,
        &material.plan_binding,
    );
    Ok(Some(material))
}

fn plan_binding(plan: &ExecutionPlan) -> Result<[u8; 32]> {
    use sha2::{Digest, Sha256};
    Ok(Sha256::digest(
        serde_json::to_vec(&(
            "mvm.actor.admitted-plan.v1",
            &plan.plan_id,
            &plan.nonce,
            &plan.workflow,
            plan.mailbox,
        ))
        .map_err(Error::other)?,
    )
    .into())
}

fn registry_directory(keys_dir: &Path, grant: &MailboxGrant) -> PathBuf {
    keys_dir.join("actor-mailbox-peers").join(format!(
        "{}-{}",
        hex::encode(grant.mailbox.as_bytes()),
        grant.epoch.get()
    ))
}

fn material(keys_dir: &Path, endpoint: &ActorEndpointTemplate) -> Result<ActorEndpointMaterial> {
    let grant = &endpoint.grant;
    let registry_directory = registry_directory(keys_dir, grant);
    let metadata = fs::symlink_metadata(&registry_directory)?;
    private_fs::require_current_owner(&metadata)?;
    if !metadata.is_dir() || private_fs::mode_bits(&registry_directory, &metadata)? & 0o077 != 0 {
        return Err(refused());
    }
    let keys = derived_keys(keys_dir, &grant.mailbox, grant.epoch)?;
    let root = Key::load(&keys_dir.join(ENCRYPTION_ROOT))?;
    Ok(ActorEndpointMaterial {
        workload: endpoint.workload.clone(),
        snapshot_digest: endpoint.snapshot_digest,
        plan_binding: [0; 32],
        grant: *grant,
        address: endpoint.template.capability.address,
        epoch: grant.epoch,
        template: endpoint.template.clone(),
        registry_directory,
        max_storage_bytes: endpoint.max_storage_bytes,
        max_send_attempts: endpoint.max_send_attempts,
        sender: keys.sender.to_bytes(),
        authority: keys.authority.to_bytes(),
        registry_key: *derive(
            root.expose_bytes(),
            b"mvm.actor.peer-registry.v1",
            &grant.mailbox,
            grant.epoch,
        ),
        state_key: *derive(
            root.expose_bytes(),
            b"mvm.actor.conversation-state.v1",
            &grant.mailbox,
            grant.epoch,
        ),
    })
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PeerRecord {
    binding: ActorPeerBinding,
    revoked: bool,
}

fn peer_path(directory: &Path, address: &MailboxAddress) -> Result<PathBuf> {
    use sha2::{Digest, Sha256};
    let bytes = serde_json::to_vec(address).map_err(Error::other)?;
    Ok(directory.join(format!("{}.sealed", hex::encode(Sha256::digest(bytes)))))
}

fn peer_aad(local: MailboxAddress, path: &Path) -> Result<Vec<u8>> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(refused)?;
    let digest = name.strip_suffix(".sealed").ok_or_else(refused)?;
    if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(refused());
    }
    serde_json::to_vec(&("mvm.actor.peer-binding.v1", local, digest)).map_err(Error::other)
}

fn read_peer(path: &Path, key: &[u8; 32], local: MailboxAddress) -> Result<PeerRecord> {
    let bytes = crate::admission_budget::read_private(path, MAX_BYTES as usize)
        .map_err(Error::other)?
        .ok_or_else(refused)?;
    let plaintext = Zeroizing::new(
        aead::open(&Key::from_bytes(*key), &bytes, &peer_aad(local, path)?)
            .map_err(|_| refused())?,
    );
    let record: PeerRecord = serde_json::from_slice(&plaintext).map_err(|_| refused())?;
    if record.binding.local_address() != local
        || peer_path(
            path.parent().ok_or_else(refused)?,
            &record.binding.peer_address(),
        )? != path
    {
        return Err(refused());
    }
    Ok(record)
}

fn install_peer(material: &ActorEndpointMaterial, binding: ActorPeerBinding) -> Result<()> {
    private_fs::ensure_private_dir(&material.registry_directory)?;
    let parent = material.registry_directory.parent().ok_or_else(refused)?;
    sync_dir(parent).map_err(Error::other)?;
    sync_dir(parent.parent().ok_or_else(refused)?).map_err(Error::other)?;
    let lock_path = material.registry_directory.join("registry.lock");
    let _lock = crate::admission_budget::acquire_lock(&lock_path).map_err(Error::other)?;
    let peer = binding.peer_address();
    let path = peer_path(&material.registry_directory, &peer)?;
    match fs::symlink_metadata(&path) {
        Ok(_) => {
            let mut record = read_peer(&path, &material.registry_key, material.address)?;
            if record.revoked
                || record
                    .binding
                    .parent_plan_binding
                    .is_some_and(|old| Some(old) != binding.parent_plan_binding)
                || record
                    .binding
                    .child_plan_binding
                    .is_some_and(|old| Some(old) != binding.child_plan_binding)
            {
                return Err(refused());
            }
            record.binding.parent_plan_binding = binding.parent_plan_binding;
            record.binding.child_plan_binding = binding.child_plan_binding;
            if record.binding != binding {
                return Err(refused());
            }
            let clear = Zeroizing::new(serde_json::to_vec(&record).map_err(Error::other)?);
            let sealed = aead::seal(
                &Key::from_bytes(material.registry_key),
                &clear,
                &peer_aad(material.address, &path)?,
            );
            return write_private(&path, &sealed);
        }
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    // Tombstones count too: forgetting a peer would erase its replay/revocation boundary.
    if fs::read_dir(&material.registry_directory)?.count() > MAX_PEERS {
        return Err(refused());
    }
    let record = PeerRecord {
        binding,
        revoked: false,
    };
    let plaintext = Zeroizing::new(serde_json::to_vec(&record).map_err(Error::other)?);
    let sealed = aead::seal(
        &Key::from_bytes(material.registry_key),
        &plaintext,
        &peer_aad(material.address, &path)?,
    );
    if sealed.len() as u64 > MAX_BYTES {
        return Err(refused());
    }
    if write_private_new(&path, &sealed)? != NewFile::Created {
        return Err(refused());
    }
    Ok(())
}

struct CapabilityScope<'a> {
    operation: MailboxOperation,
    kind: MailboxMessageKind,
    subject: PrincipalId,
    label: &'a [u8],
}

fn sign_for(
    keys_dir: &Path,
    endpoint: &ActorEndpointTemplate,
    mut grant: mvm_contract::protocol::mailbox::MailboxCapabilityGrant,
    scope: CapabilityScope<'_>,
) -> Result<SignedMailboxCapability> {
    let keys = derived_keys(keys_dir, &endpoint.grant.mailbox, endpoint.grant.epoch)?;
    grant.capability_id = CapabilityId::from_bytes(*derive_with(
        &keys.root,
        scope.label,
        &endpoint.grant.mailbox,
        endpoint.grant.epoch,
        scope.subject.as_bytes(),
    ));
    grant.subject = scope.subject;
    grant.operations = CapabilityOperations::from_operations(&[scope.operation]);
    grant.message_kinds = vec![scope.kind];
    mvm_core::mailbox::sign_capability(grant, &keys.authority).map_err(Error::other)
}

pub(crate) fn install_pair(
    keys_dir: &Path,
    parent: &ActorEndpointTemplate,
    child: &ActorEndpointTemplate,
) -> Result<()> {
    use sha2::{Digest, Sha256};

    if parent.grant.epoch != child.grant.epoch {
        return Err(refused());
    }
    let parent_keys = material(keys_dir, parent)?;
    let child_keys = material(keys_dir, child)?;
    let send = sign_for(
        keys_dir,
        child,
        child.template.capability.clone(),
        CapabilityScope {
            operation: MailboxOperation::Send,
            kind: MailboxMessageKind::Call,
            subject: parent_keys.address.recipient,
            label: b"mvm.actor.call-send.v1",
        },
    )?;
    let parent_receive = sign_for(
        keys_dir,
        parent,
        parent.template.capability.clone(),
        CapabilityScope {
            operation: MailboxOperation::Receive,
            kind: MailboxMessageKind::Reply,
            subject: parent_keys.address.recipient,
            label: b"mvm.actor.result-receive.v1",
        },
    )?;
    let child_receive = sign_for(
        keys_dir,
        child,
        child.template.capability.clone(),
        CapabilityScope {
            operation: MailboxOperation::Receive,
            kind: MailboxMessageKind::Call,
            subject: child_keys.address.recipient,
            label: b"mvm.actor.call-receive.v1",
        },
    )?;
    let root = Key::load(&keys_dir.join(ENCRYPTION_ROOT))?;
    let pair_key = |label| {
        *derive_with(
            root.expose_bytes(),
            label,
            &child.grant.mailbox,
            child.grant.epoch,
            parent.grant.mailbox.as_bytes(),
        )
    };
    let mut call = child.template.clone();
    call.capability = send.grant.clone();
    call.header.sender = parent_keys.address.recipient;
    call.header.capability_id = send.grant.capability_id;
    call.header.encryption.key_id = Sha256::digest(pair_key(b"mvm.actor.call-payload.v1")).into();
    // The caller must replace this with its newly issued one-call Reply capability.
    call.header.reply_to = None;
    let mut reply_header = parent.template.header.clone();
    reply_header.sender = child_keys.address.recipient;
    reply_header.kind = MailboxMessageKind::Reply;
    reply_header.reply_to = None;
    reply_header.capability_id = CapabilityId::from_bytes([0; 32]);
    reply_header.encryption.key_id = Sha256::digest(pair_key(b"mvm.actor.reply-payload.v1")).into();
    reply_header.expires_at_unix_ms = call.header.expires_at_unix_ms;
    let mut reply_routing = parent.template.routing.clone();
    reply_routing.expires_at_unix_ms = reply_header.expires_at_unix_ms;
    reply_routing.destination_route_token =
        mvm_contract::protocol::mailbox::DestinationRouteToken::from_bytes(pair_key(
            b"mvm.actor.reply-route.v1",
        ));
    let mut binding = ActorPeerBinding {
        role: ActorPeerRole::Parent,
        parent_address: parent_keys.address,
        child_address: child_keys.address,
        parent_plan_binding: read(keys_dir, &parent.grant)?.admitted_plan,
        child_plan_binding: read(keys_dir, &child.grant)?.admitted_plan,
        epoch: child.grant.epoch,
        call,
        reply_header,
        reply_routing,
        send_capability: send,
        parent_receive,
        child_receive,
        parent_authority_key: parent.grant.authority_key,
        child_authority_key: child.grant.authority_key,
        parent_sender_key: parent_keys.sender_key().verifying_key().to_bytes(),
        child_sender_key: child_keys.sender_key().verifying_key().to_bytes(),
        peer_socket: mvm_core::config::vm_mailbox_socket_at(&mvm_core::config::vm_state_dir(
            &child.workload,
        )),
        call_key: pair_key(b"mvm.actor.call-payload.v1"),
        reply_key: pair_key(b"mvm.actor.reply-payload.v1"),
    };
    install_peer(&parent_keys, binding.clone())?;
    binding.role = ActorPeerRole::Child;
    binding.peer_socket =
        mvm_core::config::vm_mailbox_socket_at(&mvm_core::config::vm_state_dir(&parent.workload));
    install_peer(&child_keys, binding)
}

fn revoke_peer(material: &ActorEndpointMaterial, peer: MailboxAddress) -> Result<()> {
    let _lock =
        crate::admission_budget::acquire_lock(&material.registry_directory.join("registry.lock"))
            .map_err(Error::other)?;
    let path = peer_path(&material.registry_directory, &peer)?;
    let mut record = read_peer(&path, &material.registry_key, material.address)?;
    record.revoked = true;
    let plaintext = Zeroizing::new(serde_json::to_vec(&record).map_err(Error::other)?);
    let sealed = aead::seal(
        &Key::from_bytes(material.registry_key),
        &plaintext,
        &peer_aad(material.address, &path)?,
    );
    write_private(&path, &sealed)
}

pub(crate) fn verify_pair(
    keys_dir: &Path,
    parent: &ActorEndpointTemplate,
    child: &ActorEndpointTemplate,
) -> Result<()> {
    let parent_keys = material(keys_dir, parent)?;
    let child_keys = material(keys_dir, child)?;
    let mut outgoing = read_peer(
        &peer_path(&parent_keys.registry_directory, &child_keys.address)?,
        &parent_keys.registry_key,
        parent_keys.address,
    )?;
    let incoming = read_peer(
        &peer_path(&child_keys.registry_directory, &parent_keys.address)?,
        &child_keys.registry_key,
        child_keys.address,
    )?;
    if outgoing.revoked || incoming.revoked {
        return Err(refused());
    }
    let outgoing = &mut outgoing.binding;
    let incoming = &incoming.binding;
    outgoing.role = ActorPeerRole::Child;
    outgoing.peer_socket =
        mvm_core::config::vm_mailbox_socket_at(&mvm_core::config::vm_state_dir(&parent.workload));
    if *outgoing != *incoming
        || incoming.parent_authority_key != parent.grant.authority_key
        || incoming.child_authority_key != child.grant.authority_key
        || incoming.parent_sender_key != parent_keys.sender_key().verifying_key().to_bytes()
        || incoming.child_sender_key != child_keys.sender_key().verifying_key().to_bytes()
    {
        return Err(refused());
    }
    Ok(())
}

pub(crate) fn revoke_pair(keys_dir: &Path, child: &ActorEndpointTemplate) -> Result<()> {
    let parent_grant = child.parent.as_ref().ok_or_else(refused)?;
    let parent = read(keys_dir, parent_grant)?.endpoint;
    let parent_keys = material(keys_dir, &parent)?;
    let child_keys = material(keys_dir, child)?;
    revoke_peer(&parent_keys, child_keys.address)?;
    revoke_peer(&child_keys, parent_keys.address)
}

pub(crate) fn reap(
    keys_dir: &Path,
    grant: &MailboxGrant,
    snapshot_digest: [u8; 32],
    capability: &SignedMailboxCapability,
) -> Result<()> {
    let child = read(keys_dir, grant)?.endpoint;
    if child.snapshot_digest != snapshot_digest
        || signed_capability(keys_dir, &child)? != *capability
    {
        return Err(refused());
    }
    revoke_pair(keys_dir, &child)?;
    revoke(keys_dir, grant)
}

/// Tombstone only the deterministic endpoint and any pair halves installed by an attempt.
pub(crate) fn reap_attempt(
    keys_dir: &Path,
    parent: &ActorEndpointTemplate,
    child: &ActorEndpointTemplate,
) -> Result<()> {
    match fs::symlink_metadata(path(keys_dir, &child.grant)) {
        Ok(_) => {}
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    }
    let record = read(keys_dir, &child.grant)?;
    if record.endpoint != *child || child.parent != Some(parent.grant) {
        return Err(refused());
    }
    let parent_keys = material(keys_dir, parent)?;
    let child_keys = material(keys_dir, child)?;
    // Check both halves before mutating either; a partial install may have only one.
    let halves = [
        (&parent_keys, child_keys.address),
        (&child_keys, parent_keys.address),
    ];
    let mut present = Vec::new();
    for (owner, peer) in halves {
        let path = peer_path(&owner.registry_directory, &peer)?;
        match fs::symlink_metadata(&path) {
            Ok(_) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        }
        let record = read_peer(&path, &owner.registry_key, owner.address)?;
        let binding = &record.binding;
        if binding.parent_address != parent_keys.address
            || binding.child_address != child_keys.address
            || binding.epoch != child.grant.epoch
            || binding.parent_authority_key != parent.grant.authority_key
            || binding.child_authority_key != child.grant.authority_key
            || binding.parent_sender_key != parent_keys.sender_key().verifying_key().to_bytes()
            || binding.child_sender_key != child_keys.sender_key().verifying_key().to_bytes()
        {
            return Err(refused());
        }
        present.push((owner, peer));
    }
    for (owner, peer) in present {
        revoke_peer(owner, peer)?;
    }
    revoke(keys_dir, &child.grant)
}

#[cfg(test)]
mod attempt_cleanup_tests {
    use super::*;
    use crate::actor_lifecycle::{ActorMailboxes, local_mailboxes::tests::setup};

    #[test]
    fn partial_attempt_cleanup_is_exact_and_repeatable() {
        for missing_halves in 0..=2 {
            let (dir, owner, parent_plan, child_plan, _environment) = setup();
            let derived = owner.derive(&parent_plan, &child_plan).unwrap();
            let parent = read(dir.path(), &parent_plan.mailbox.unwrap())
                .unwrap()
                .endpoint;
            let child = read(dir.path(), &derived.grant).unwrap().endpoint;
            let parent_keys = material(dir.path(), &parent).unwrap();
            let child_keys = material(dir.path(), &child).unwrap();
            let paths = [
                peer_path(&child_keys.registry_directory, &parent_keys.address).unwrap(),
                peer_path(&parent_keys.registry_directory, &child_keys.address).unwrap(),
            ];
            for path in paths.iter().take(missing_halves) {
                fs::remove_file(path).unwrap();
            }
            let mut sibling_plan = child_plan.clone();
            sibling_plan.workload.0 = "cleanup-sibling".into();
            let sibling = owner.derive(&parent_plan, &sibling_plan).unwrap();
            assert!(parent_keys.peer(&sibling.address).is_err());
            sibling_plan.mailbox = Some(sibling.grant);
            sibling_plan.plan_id = mvm_core::plan::compute_plan_id(&sibling_plan);
            let sibling_keys = endpoint_material(dir.path(), &sibling_plan)
                .unwrap()
                .unwrap();
            assert!(parent_keys.peer(&sibling.address).is_ok());
            assert!(sibling_keys.peer(&parent_keys.address).is_ok());
            let mut foreign = child_plan.clone();
            foreign.tenant.0 = "foreign-tenant".into();
            assert!(owner.reap_attempt(&parent_plan, &foreign).is_err());
            assert!(!read(dir.path(), &derived.grant).unwrap().revoked);
            owner.reap_attempt(&parent_plan, &child_plan).unwrap();
            owner.reap_attempt(&parent_plan, &child_plan).unwrap();
            assert!(read(dir.path(), &derived.grant).unwrap().revoked);
            assert!(parent_keys.peer(&sibling.address).is_ok());
            assert!(sibling_keys.peer(&parent_keys.address).is_ok());
            assert!(!read(dir.path(), &sibling.grant).unwrap().revoked);
            for path in paths.iter().skip(missing_halves) {
                let keys = if path.parent() == Some(child_keys.registry_directory.as_path()) {
                    &child_keys
                } else {
                    &parent_keys
                };
                assert!(
                    read_peer(path, &keys.registry_key, keys.address)
                        .unwrap()
                        .revoked
                );
            }
        }
    }

    #[test]
    fn absent_attempt_cleanup_does_not_install_an_endpoint() {
        let (dir, owner, parent, child, _environment) = setup();
        owner.reap_attempt(&parent, &child).unwrap();
        owner.reap_attempt(&parent, &child).unwrap();
        let derived = owner.derive(&parent, &child).unwrap();
        assert!(!read(dir.path(), &derived.grant).unwrap().revoked);
    }
}
