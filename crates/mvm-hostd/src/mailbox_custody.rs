//! Retained, host-local mailbox keys and their signed restart binding.
//!
//! This is a trusted-host crash-recovery primitive, not an independent
//! rollback witness or an attested key-release boundary.

use std::fs::OpenOptions;
use std::io::{Error, ErrorKind, Read};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, ensure};
use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _};
use mvm_contract::plan::{Nonce, PlanId};
use mvm_contract::protocol::mailbox::{
    BootId, EncryptionAlgorithm, ExecutionEpoch, MailboxAddress, MailboxRetentionPolicy,
};
use mvm_core::crypto::aead::Key;
use mvm_core::mailbox::journal::{HistoryKeyCustody, HistoryKeyRef, JournalError};
use mvm_core::plan::ExecutionPlan;
use mvm_core::util::atomic_io::{atomic_write_new, sync_dir};
use rand::Rng as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use crate::audit::host_keypair::{PUBLIC_FILENAME, SECRET_FILENAME};
use crate::mailbox_launch::derive_launch_keys;
use crate::plan_admission::{MailboxLaunchPosture, MailboxPostureHandoff};

const DOMAIN: &[u8] = b"mvm.mailbox.local-custody.v1\0";
const KEY_VERSION: u32 = 1;
const KEY_BYTES: usize = 96;
const MAX_MANIFEST_BYTES: u64 = 4096;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Binding {
    plan_id: PlanId,
    plan_nonce: Nonce,
    vm_name: String,
    address: MailboxAddress,
    epoch: ExecutionEpoch,
    retention_ms: u64,
    authority_key: [u8; 32],
    host_signer: [u8; 32],
    key_version: u32,
    history: HistoryKeyRef,
    payload_key_id: [u8; 32],
    anchor_key_id: [u8; 32],
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedBinding {
    binding: Binding,
    signature: Vec<u8>,
}

#[derive(Serialize)]
struct Identity<'a> {
    plan_id: &'a PlanId,
    plan_nonce: &'a Nonce,
    vm_name: &'a str,
    address: MailboxAddress,
    epoch: ExecutionEpoch,
    retention_ms: u64,
}

/// Three independent purpose keys in one no-clobber, fsynced private bundle.
///
/// Only the manifest is signed; the key IDs bind every bundle component to it.
/// Neither the bundle nor this type contains a per-launch mailbox secret.
pub(crate) struct RetainedMailboxKeys {
    binding: Binding,
    material: Zeroizing<[u8; KEY_BYTES]>,
}

pub(crate) struct MailboxStoragePaths {
    pub(crate) journal: PathBuf,
    pub(crate) anchor: PathBuf,
    pub(crate) source_intents: PathBuf,
}

fn paths(keys_dir: &Path, identity: &Identity<'_>) -> Result<(PathBuf, PathBuf)> {
    let digest = Sha256::digest(serde_jcs::to_vec(identity)?);
    let name = hex::encode(digest);
    let directory = keys_dir.join("mailbox-local-v1");
    Ok((
        directory.join(format!("{name}.keys")),
        directory.join(format!("{name}.manifest")),
    ))
}

fn signed_bytes(binding: &Binding) -> Result<Vec<u8>> {
    let mut bytes = DOMAIN.to_vec();
    bytes.extend(serde_jcs::to_vec(binding)?);
    Ok(bytes)
}

fn existing_host_signer(keys_dir: &Path) -> Result<SigningKey> {
    let (signer, _) = mvm_core::crypto::ed25519_keypair::load_existing(
        &keys_dir.join(SECRET_FILENAME),
        &keys_dir.join(PUBLIC_FILENAME),
    )
    .context("retained mailbox custody needs the existing host signer")?;
    Ok(signer)
}

fn read_private(path: &Path, maximum: u64) -> Result<Zeroizing<Vec<u8>>> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let meta = file.metadata()?;
    ensure!(
        meta.is_file()
            && meta.nlink() == 1
            && meta.len() <= maximum
            && meta.permissions().mode() & 0o077 == 0,
        "retained mailbox custody member is not a bounded private single-link file"
    );
    let mut bytes = Zeroizing::new(Vec::new());
    file.by_ref().take(maximum + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= maximum,
        "mailbox custody member grew while reading"
    );
    Ok(bytes)
}

fn identity<'a>(
    keys_dir: &Path,
    plan: &'a ExecutionPlan,
    vm_name: &'a str,
    address: MailboxAddress,
) -> Result<Identity<'a>> {
    let grant = plan
        .mailbox
        .context("admitted plan does not grant a mailbox")?;
    let retention_ms = grant
        .retention
        .context("admitted plan does not declare local mailbox retention")?
        .retention_ms();
    ensure!(
        address.mailbox == grant.mailbox && plan.image.name == vm_name,
        "mailbox custody identity does not match the admitted VM"
    );
    // Only the host-trusted template's address is checked here; the transient
    // seed is never used to open retained ciphertext or re-sign history.
    let (policy, _) = derive_launch_keys(keys_dir, &grant, &Key::random())?.trust();
    ensure!(
        address
            == MailboxAddress {
                tenant: policy.context.expected_tenant,
                authorization_domain: policy.context.expected_authorization_domain,
                mailbox: policy.context.expected_mailbox,
                recipient: policy.context.expected_recipient,
            },
        "mailbox custody address does not match host-trusted template"
    );
    Ok(Identity {
        plan_id: &plan.plan_id,
        plan_nonce: &plan.nonce,
        vm_name,
        address,
        epoch: grant.epoch,
        retention_ms,
    })
}

impl RetainedMailboxKeys {
    /// First launch provisions once; subsequent launches require the exact
    /// existing signed manifest. A partial first write cannot be replaced.
    pub(crate) fn provision_or_open(
        keys_dir: &Path,
        plan: &ExecutionPlan,
        vm_name: &str,
        posture: &MailboxLaunchPosture,
        current_boot: Option<BootId>,
        address: MailboxAddress,
    ) -> Result<Self> {
        posture.verify(plan, vm_name)?;
        let identity = identity(keys_dir, plan, vm_name, address)?;
        let (bundle, manifest) = paths(keys_dir, &identity)?;
        let mut existing = false;
        for path in [&bundle, &manifest] {
            match std::fs::symlink_metadata(path) {
                Ok(_) => existing = true,
                Err(error) if error.kind() == ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        if existing {
            Self::open_existing(
                keys_dir,
                plan,
                vm_name,
                &posture.handoff(current_boot),
                current_boot,
                address,
            )
        } else {
            Self::provision(keys_dir, plan, vm_name, posture, address)
        }
    }

    /// Host-local storage remains outside the per-VM state directory so a VM
    /// teardown cannot erase accepted history or its high-water mark.
    pub(crate) fn storage_paths(&self, keys_dir: &Path) -> Result<MailboxStoragePaths> {
        let binding = &self.binding;
        let identity = Identity {
            plan_id: &binding.plan_id,
            plan_nonce: &binding.plan_nonce,
            vm_name: &binding.vm_name,
            address: binding.address,
            epoch: binding.epoch,
            retention_ms: binding.retention_ms,
        };
        let (bundle, _) = paths(keys_dir, &identity)?;
        Ok(MailboxStoragePaths {
            journal: bundle.with_extension("journal"),
            anchor: bundle.with_extension("anchor"),
            source_intents: bundle.with_extension("intents"),
        })
    }

    /// Provision once under a verified launch posture; an interrupted first
    /// provision leaves an orphan bundle and refuses instead of replacing it.
    pub(crate) fn provision(
        keys_dir: &Path,
        plan: &ExecutionPlan,
        vm_name: &str,
        posture: &MailboxLaunchPosture,
        address: MailboxAddress,
    ) -> Result<Self> {
        posture.verify(plan, vm_name)?;
        let identity = identity(keys_dir, plan, vm_name, address)?;
        let signer = existing_host_signer(keys_dir)?;
        let (bundle_path, manifest_path) = paths(keys_dir, &identity)?;
        mvm_core::private_fs::ensure_private_dir(
            bundle_path.parent().context("mailbox custody directory")?,
        )?;
        sync_dir(keys_dir)?;
        ensure!(
            !bundle_path.exists() && !manifest_path.exists(),
            "mailbox custody already exists; use existing-only recovery"
        );
        let mut material = Zeroizing::new([0u8; KEY_BYTES]);
        rand::rng().fill_bytes(&mut *material);
        let history = HistoryKeyRef::new(
            address,
            identity.epoch,
            Sha256::digest(&material[..32]).into(),
            KEY_VERSION,
        )?;
        let binding = Binding {
            plan_id: plan.plan_id.clone(),
            plan_nonce: plan.nonce.clone(),
            vm_name: vm_name.to_owned(),
            address,
            epoch: identity.epoch,
            retention_ms: identity.retention_ms,
            authority_key: plan.mailbox.context("mailbox grant")?.authority_key,
            host_signer: signer.verifying_key().to_bytes(),
            key_version: KEY_VERSION,
            history,
            payload_key_id: Sha256::digest(&material[32..64]).into(),
            anchor_key_id: Sha256::digest(&material[64..]).into(),
        };
        atomic_write_new(&bundle_path, &material[..])?;
        sync_dir(bundle_path.parent().context("mailbox custody directory")?)?;
        let signed = SignedBinding {
            signature: signer.sign(&signed_bytes(&binding)?).to_bytes().to_vec(),
            binding: binding.clone(),
        };
        atomic_write_new(&manifest_path, &serde_json::to_vec(&signed)?)?;
        sync_dir(
            manifest_path
                .parent()
                .context("mailbox custody directory")?,
        )?;
        Ok(Self { binding, material })
    }

    /// Recover only an existing manifest and exact key bundle under the current
    /// host signer. A missing/rotated signer, manifest or purpose key refuses.
    pub(crate) fn open_existing(
        keys_dir: &Path,
        plan: &ExecutionPlan,
        vm_name: &str,
        posture: &MailboxPostureHandoff,
        current_boot: Option<BootId>,
        address: MailboxAddress,
    ) -> Result<Self> {
        posture.verify(plan, vm_name, current_boot)?;
        let identity = identity(keys_dir, plan, vm_name, address)?;
        let signer = existing_host_signer(keys_dir)?;
        let (bundle_path, manifest_path) = paths(keys_dir, &identity)?;
        let directory = bundle_path.parent().context("mailbox custody directory")?;
        let directory_meta = std::fs::symlink_metadata(directory)?;
        ensure!(
            directory_meta.file_type().is_dir() && directory_meta.permissions().mode() & 0o077 == 0,
            "retained mailbox custody directory is not private"
        );
        let manifest: SignedBinding =
            serde_json::from_slice(&read_private(&manifest_path, MAX_MANIFEST_BYTES)?)?;
        let signature: [u8; 64] = manifest.signature.as_slice().try_into().map_err(|_| {
            Error::new(ErrorKind::InvalidData, "invalid mailbox manifest signature")
        })?;
        signer.verifying_key().verify(
            &signed_bytes(&manifest.binding)?,
            &Signature::from_bytes(&signature),
        )?;
        let binding = manifest.binding;
        ensure!(
            binding.plan_id == *identity.plan_id
                && binding.plan_nonce == *identity.plan_nonce
                && binding.vm_name == identity.vm_name
                && binding.address == address
                && binding.epoch == identity.epoch
                && binding.retention_ms == identity.retention_ms
                && binding.authority_key == plan.mailbox.context("mailbox grant")?.authority_key
                && binding.host_signer == signer.verifying_key().to_bytes()
                && binding.key_version == KEY_VERSION
                && binding.history.address() == address
                && binding.history.execution_epoch() == identity.epoch
                && binding.history.algorithm() == EncryptionAlgorithm::AES_256_GCM
                && binding.history.version() == KEY_VERSION,
            "retained mailbox custody scope or authority changed"
        );
        let bytes = read_private(&bundle_path, KEY_BYTES as u64)?;
        ensure!(
            bytes.len() == KEY_BYTES,
            "mailbox custody key bundle length changed"
        );
        let mut material = Zeroizing::new([0u8; KEY_BYTES]);
        material.copy_from_slice(&bytes);
        let history_id: [u8; 32] = Sha256::digest(&material[..32]).into();
        let payload_id: [u8; 32] = Sha256::digest(&material[32..64]).into();
        let anchor_id: [u8; 32] = Sha256::digest(&material[64..]).into();
        ensure!(
            binding.history.key_id() == &history_id
                && binding.payload_key_id == payload_id
                && binding.anchor_key_id == anchor_id,
            "retained mailbox purpose key changed"
        );
        Ok(Self { binding, material })
    }

    pub(crate) fn history_reference(&self) -> HistoryKeyRef {
        self.binding.history
    }

    pub(crate) fn address(&self) -> MailboxAddress {
        self.binding.address
    }

    pub(crate) fn epoch(&self) -> ExecutionEpoch {
        self.binding.epoch
    }

    pub(crate) fn retention(&self) -> Result<MailboxRetentionPolicy> {
        MailboxRetentionPolicy::new(self.binding.retention_ms)
            .context("signed mailbox retention is invalid")
    }

    pub(crate) fn authority_key(&self) -> [u8; 32] {
        self.binding.authority_key
    }

    pub(crate) fn payload_key(&self) -> Key {
        Key::from_bytes(
            self.material[32..64]
                .try_into()
                .expect("fixed payload key length"),
        )
    }

    pub(crate) fn payload_key_id(&self) -> [u8; 32] {
        self.binding.payload_key_id
    }

    pub(crate) fn anchor_key(&self) -> [u8; 32] {
        self.material[64..]
            .try_into()
            .expect("fixed anchor key length")
    }
}

impl HistoryKeyCustody for RetainedMailboxKeys {
    fn load_existing(&self, reference: &HistoryKeyRef) -> Result<Key, JournalError> {
        if reference != &self.binding.history {
            return Err(JournalError::HistoryKeyMismatch);
        }
        Ok(Key::from_bytes(
            self.material[..32]
                .try_into()
                .expect("fixed history key length"),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_contract::protocol::mailbox::{
        AuthorizationDomainId, MailboxGrant, MailboxId, MailboxRetentionPolicy,
    };
    use mvm_core::plan::{Variant, compute_plan_id, test_support::PlanFixture};
    use std::fs;

    fn setup() -> (tempfile::TempDir, ExecutionPlan, MailboxAddress) {
        let dir = tempfile::tempdir_in("/tmp").expect("private test home");
        crate::audit::host_keypair::load_or_init_at(dir.path()).expect("host signer");
        let mailbox = MailboxId::from_bytes([4; 32]);
        let mut plan = PlanFixture::new().build();
        plan.mailbox = Some(MailboxGrant {
            mailbox,
            authority_key: crate::mailbox_launch::authority_key_for(
                dir.path(),
                &mailbox,
                ExecutionEpoch::new(1).expect("epoch"),
            )
            .expect("mailbox authority")
            .to_bytes(),
            epoch: ExecutionEpoch::new(1).expect("epoch"),
            report: None,
            retention: Some(MailboxRetentionPolicy::new(10_000).expect("signed retention")),
        });
        plan.plan_id = compute_plan_id(&plan);
        let (policy, _) =
            derive_launch_keys(dir.path(), &plan.mailbox.expect("grant"), &Key::random())
                .expect("host mailbox keys")
                .trust();
        let address = MailboxAddress {
            tenant: policy.context.expected_tenant,
            authorization_domain: policy.context.expected_authorization_domain,
            mailbox: policy.context.expected_mailbox,
            recipient: policy.context.expected_recipient,
        };
        (dir, plan, address)
    }

    #[test]
    fn local_custody_requires_and_binds_the_signed_retention_window() {
        let (dir, plan, address) = setup();
        let vm = plan.image.name.as_str();
        let posture = MailboxLaunchPosture::for_test(&plan, Variant::Dev);
        let mut absent = plan.clone();
        absent.mailbox.as_mut().expect("grant").retention = None;
        absent.plan_id = compute_plan_id(&absent);
        let absent_posture = MailboxLaunchPosture::for_test(&absent, Variant::Dev);
        assert!(
            RetainedMailboxKeys::provision(dir.path(), &absent, vm, &absent_posture, address,)
                .is_err(),
            "legacy signed plans cannot provision local custody"
        );
        let retained = RetainedMailboxKeys::provision(dir.path(), &plan, vm, &posture, address)
            .expect("declared retention");
        assert_eq!(retained.binding.retention_ms, 10_000);
        assert!(
            RetainedMailboxKeys::open_existing(
                dir.path(),
                &absent,
                vm,
                &absent_posture.handoff(None),
                None,
                address,
            )
            .is_err(),
            "legacy signed plans cannot recover local custody either"
        );

        let mut changed = plan.clone();
        changed.mailbox.as_mut().expect("grant").retention =
            Some(MailboxRetentionPolicy::new(20_000).expect("changed window"));
        changed.plan_id = compute_plan_id(&changed);
        let changed_posture = MailboxLaunchPosture::for_test(&changed, Variant::Dev);
        assert!(
            RetainedMailboxKeys::open_existing(
                dir.path(),
                &changed,
                vm,
                &changed_posture.handoff(None),
                None,
                address,
            )
            .is_err(),
            "a different signed retention policy cannot inherit prior custody"
        );
        let identity = identity(dir.path(), &plan, vm, address).expect("trusted identity");
        let (_, manifest) = paths(dir.path(), &identity).expect("scope path");
        let mut forged: serde_json::Value =
            serde_json::from_slice(&fs::read(&manifest).expect("signed manifest"))
                .expect("manifest JSON");
        forged["binding"]["retention_ms"] = serde_json::json!(20_000);
        fs::write(
            &manifest,
            serde_json::to_vec(&forged).expect("forged manifest"),
        )
        .expect("alter manifest");
        assert!(
            RetainedMailboxKeys::open_existing(
                dir.path(),
                &plan,
                vm,
                &posture.handoff(None),
                None,
                address,
            )
            .is_err(),
            "a modified manifest window must fail signature verification"
        );
    }

    #[test]
    fn purpose_keys_and_signed_manifest_survive_restart_without_launch_secret() {
        let (dir, plan, address) = setup();
        let vm = plan.image.name.as_str();
        let posture = MailboxLaunchPosture::for_test(&plan, Variant::Dev);
        let source_state = dir.path().join("source-vm");
        fs::create_dir(&source_state).expect("source VM state");
        let before = RetainedMailboxKeys::provision(dir.path(), &plan, vm, &posture, address)
            .expect("first provision");
        assert_ne!(
            before.payload_key().expose_bytes(),
            before
                .load_existing(&before.history_reference())
                .unwrap()
                .expose_bytes()
        );
        assert_ne!(
            before.anchor_key(),
            *before.payload_key().expose_bytes(),
            "anchor key must be a separate purpose"
        );
        let payload_id: [u8; 32] = Sha256::digest(before.payload_key().expose_bytes()).into();
        assert_eq!(before.payload_key_id(), payload_id);
        assert!(
            RetainedMailboxKeys::provision(dir.path(), &plan, vm, &posture, address).is_err(),
            "existing custody must never mint a replacement"
        );
        let reference = before.history_reference();
        let history = *before
            .load_existing(&reference)
            .expect("history key")
            .expose_bytes();
        let payload = *before.payload_key().expose_bytes();
        let anchor = before.anchor_key();
        drop(before);
        fs::remove_dir(&source_state).expect("source teardown");

        let recovered = RetainedMailboxKeys::open_existing(
            dir.path(),
            &plan,
            vm,
            &posture.handoff(None),
            None,
            address,
        )
        .expect("restart loads only retained custody");
        assert_eq!(recovered.history_reference(), reference);
        assert_eq!(
            *recovered
                .load_existing(&reference)
                .expect("key")
                .expose_bytes(),
            history
        );
        assert_eq!(*recovered.payload_key().expose_bytes(), payload);
        assert_eq!(recovered.anchor_key(), anchor);
        let wrong = HistoryKeyRef::new(address, plan.mailbox.expect("grant").epoch, [8; 32], 2)
            .expect("foreign version");
        assert!(matches!(
            recovered.load_existing(&wrong),
            Err(JournalError::HistoryKeyMismatch)
        ));
        let mut next_epoch = plan.clone();
        let mut next_grant = next_epoch.mailbox.expect("grant");
        next_grant.epoch = ExecutionEpoch::new(2).expect("next epoch");
        next_epoch.mailbox = Some(next_grant);
        next_epoch.plan_id = compute_plan_id(&next_epoch);
        let next_posture = MailboxLaunchPosture::for_test(&next_epoch, Variant::Dev);
        assert!(
            RetainedMailboxKeys::open_existing(
                dir.path(),
                &next_epoch,
                vm,
                &next_posture.handoff(None),
                None,
                address,
            )
            .is_err(),
            "another execution epoch cannot inherit this key version"
        );
    }

    #[test]
    fn retained_keys_reopen_the_same_encrypted_envelope_and_local_acceptance() {
        use mvm_contract::protocol::mailbox::DeliveryOutcome;
        use mvm_core::mailbox::frame::OutboxMessage;
        use mvm_core::mailbox::journal::{
            FileJournalAnchor, JournalAdmission, JournalLimits, MailboxJournal,
        };

        let (dir, plan, address) = setup();
        let vm = plan.image.name.as_str();
        let posture = MailboxLaunchPosture::for_test(&plan, Variant::Dev);
        let source_state = dir.path().join("source-vm");
        fs::create_dir(&source_state).expect("source VM state");
        let keys = RetainedMailboxKeys::provision(dir.path(), &plan, vm, &posture, address)
            .expect("verified first provision");
        let derived = derive_launch_keys(dir.path(), &plan.mailbox.expect("grant"), &Key::random())
            .expect("mailbox signing material")
            .with_retained(&keys)
            .expect("bind retained purpose keys to the canonical template");
        let (signer, journal_key, anchor_key) = derived.durable_material();
        assert_eq!(
            journal_key,
            *keys
                .load_existing(&keys.history_reference())
                .expect("history key")
                .expose_bytes()
        );
        assert_eq!(anchor_key, keys.anchor_key());
        let (policy, mut sealer) = derived.trust();
        let payload_key = keys.payload_key();
        assert_eq!(
            *policy.encryption_key.expose_bytes(),
            *payload_key.expose_bytes()
        );
        assert_eq!(sealer.header.encryption.key_id, keys.payload_key_id());
        let (capability, envelope) = sealer
            .seal(OutboxMessage::new(
                policy.context.expected_recipient,
                b"hello".to_vec(),
            ))
            .expect("seal under retained payload key");
        let journal_root = dir.path().join("recipient-journal");
        let anchor_path = dir.path().join("recipient-anchor");
        let limits = JournalLimits {
            max_records: 4,
            max_bytes: 64 * 1024,
        };
        let anchor = FileJournalAnchor::open(&anchor_path, address, keys.anchor_key())
            .expect("local anchor genesis");
        let mut journal = MailboxJournal::open_local_with_custody(
            &journal_root,
            keys.history_reference(),
            signer.verifying_key(),
            limits,
            &keys,
            &anchor,
            keys.retention().expect("signed window"),
        )
        .expect("empty recipient journal");
        let accepted = journal
            .admit_local(
                JournalAdmission {
                    envelope: &envelope,
                    capability: &capability,
                    context: &policy.context,
                    encryption_key: &payload_key,
                    sender_key: &policy.sender_key,
                    signer: &signer,
                },
                &anchor,
            )
            .expect("local encrypted acceptance");
        assert_eq!(
            accepted.receipt.outcome,
            DeliveryOutcome::AcceptedLocalDurable
        );
        assert_eq!(journal.tip(), anchor.tip());
        drop(journal);
        drop(anchor);
        drop(keys);
        fs::remove_dir(&source_state).expect("source teardown");

        let keys = RetainedMailboxKeys::open_existing(
            dir.path(),
            &plan,
            vm,
            &posture.handoff(None),
            None,
            address,
        )
        .expect("authenticated restart binding");
        let anchor = FileJournalAnchor::open(&anchor_path, address, keys.anchor_key())
            .expect("retained local anchor");
        let mut journal = MailboxJournal::open_local_with_custody(
            &journal_root,
            keys.history_reference(),
            signer.verifying_key(),
            limits,
            &keys,
            &anchor,
            keys.retention().expect("signed window"),
        )
        .expect("decrypt and authenticate retained envelope");
        let retry = journal
            .admit_local(
                JournalAdmission {
                    envelope: &envelope,
                    capability: &capability,
                    context: &policy.context,
                    encryption_key: &keys.payload_key(),
                    sender_key: &policy.sender_key,
                    signer: &signer,
                },
                &anchor,
            )
            .expect("recover original signed receipt");
        assert_eq!(
            serde_jcs::to_vec(&retry).expect("retry bytes"),
            serde_jcs::to_vec(&accepted).expect("original bytes")
        );
        assert_eq!(anchor.tip().cursor, 1, "a retry cannot append");
    }

    #[test]
    fn recovery_refuses_missing_or_changed_keys_and_signed_scope() {
        let (dir, plan, address) = setup();
        let vm = plan.image.name.as_str();
        let posture = MailboxLaunchPosture::for_test(&plan, Variant::Dev);
        let handoff = posture.handoff(None);
        assert!(
            RetainedMailboxKeys::open_existing(dir.path(), &plan, vm, &handoff, None, address)
                .is_err(),
            "recovery never creates missing key material"
        );
        RetainedMailboxKeys::provision(dir.path(), &plan, vm, &posture, address)
            .expect("first provision");
        let identity = identity(dir.path(), &plan, vm, address).expect("trusted identity");
        let (bundle, manifest) = paths(dir.path(), &identity).expect("scope path");
        let mut foreign = address;
        foreign.authorization_domain = AuthorizationDomainId::from_bytes([9; 32]);
        assert!(
            RetainedMailboxKeys::open_existing(dir.path(), &plan, vm, &handoff, None, foreign)
                .is_err(),
            "a different domain cannot borrow this history"
        );
        let mut changed = fs::read(&bundle).expect("bundle");
        changed[0] ^= 1;
        fs::write(&bundle, changed).expect("tamper bundle");
        assert!(
            RetainedMailboxKeys::open_existing(dir.path(), &plan, vm, &handoff, None, address)
                .is_err(),
            "recomputed key ID must reject changed material"
        );
        fs::write(&manifest, b"{}").expect("tamper manifest");
        assert!(
            RetainedMailboxKeys::open_existing(dir.path(), &plan, vm, &handoff, None, address)
                .is_err(),
            "unsigned metadata cannot authorize reopening"
        );
    }

    #[test]
    fn interrupted_provision_does_not_replace_an_orphan_key_bundle() {
        let (dir, plan, address) = setup();
        let vm = plan.image.name.as_str();
        let posture = MailboxLaunchPosture::for_test(&plan, Variant::Dev);
        let trusted = identity(dir.path(), &plan, vm, address).expect("trusted scope");
        let (bundle, manifest) = paths(dir.path(), &trusted).expect("scope path");
        mvm_core::private_fs::ensure_private_dir(bundle.parent().expect("bundle directory"))
            .expect("private key directory");
        atomic_write_new(&bundle, &[7; KEY_BYTES]).expect("crash after key publication");
        sync_dir(bundle.parent().expect("bundle directory")).expect("durable orphan");

        assert!(
            RetainedMailboxKeys::provision(dir.path(), &plan, vm, &posture, address).is_err(),
            "an orphan must not be overwritten with another key"
        );
        assert!(
            !manifest.exists(),
            "failed provision must not claim custody"
        );
        assert!(
            RetainedMailboxKeys::open_existing(
                dir.path(),
                &plan,
                vm,
                &posture.handoff(None),
                None,
                address,
            )
            .is_err(),
            "recovery cannot adopt an unsigned orphan"
        );
        assert_eq!(fs::read(bundle).expect("orphan retained"), [7; KEY_BYTES]);
    }

    #[test]
    fn recovery_refuses_missing_signer_and_symlinked_material() {
        let (dir, plan, address) = setup();
        let vm = plan.image.name.as_str();
        let posture = MailboxLaunchPosture::for_test(&plan, Variant::Dev);
        RetainedMailboxKeys::provision(dir.path(), &plan, vm, &posture, address)
            .expect("first provision");
        let handoff = posture.handoff(None);
        let identity = identity(dir.path(), &plan, vm, address).expect("trusted identity");
        let (bundle, _) = paths(dir.path(), &identity).expect("scope path");
        let copy = bundle.with_extension("copy");
        fs::rename(&bundle, &copy).expect("relocate bundle");
        std::os::unix::fs::symlink(&copy, &bundle).expect("symlink bundle");
        assert!(
            RetainedMailboxKeys::open_existing(dir.path(), &plan, vm, &handoff, None, address)
                .is_err(),
            "private material cannot be a symlink"
        );
        fs::remove_file(&bundle).expect("remove test symlink");
        fs::rename(&copy, &bundle).expect("restore bundle");
        let rotated = SigningKey::from_bytes(&[66; 32]);
        fs::write(dir.path().join(SECRET_FILENAME), rotated.to_bytes())
            .expect("rotate test signer secret");
        fs::write(
            dir.path().join(PUBLIC_FILENAME),
            rotated.verifying_key().to_bytes(),
        )
        .expect("rotate test signer public key");
        assert!(
            RetainedMailboxKeys::open_existing(dir.path(), &plan, vm, &handoff, None, address)
                .is_err(),
            "signer rotation cannot silently adopt retained history"
        );
        fs::remove_file(dir.path().join(SECRET_FILENAME)).expect("remove test signer");
        assert!(
            RetainedMailboxKeys::open_existing(dir.path(), &plan, vm, &handoff, None, address)
                .is_err(),
            "recovery cannot silently mint a replacement signer"
        );
    }
}
