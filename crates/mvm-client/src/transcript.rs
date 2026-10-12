//! Host-local lifecycle and verified export of opt-in forensic network captures.
//!
//! `arm` provisions a capture (per-capture data key wrapped under the host KEK
//! into the manifest) and records it in the audit log; the live byte-capture
//! that fills a capture's chunks happens at the host bridge, out of band. `list`
//! enumerates captures, `disarm` seals one, and `export` verifies + decrypts a
//! sealed capture (failing closed on tamper / wrong key / bound). Every
//! mutation/export emits a local audit kind; disarm also emits a signed chain
//! anchor. Raw payload bytes never enter diagnostics or audit records. Export
//! only reads existing keys and capture files (but records its audit outcome).
//! `reconcile` retires one sealed capture's payload once its authenticated
//! at-rest deadline passes, preserving the manifest and the signed evidence.
//! This service does not control the lifetime of the live capture producer.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Serialize;

use mvm_core::config;
use mvm_core::crypto::aead;
use mvm_core::policy::audit::{LocalAuditBuilder, LocalAuditKind, event};
use mvm_core::transcript::{
    self, CaptureBinding, CaptureBounds, MANIFEST_FILENAME, RetentionPolicy,
    TRANSCRIPT_KEK_RECIPIENT as KEK_RECIPIENT, TranscriptManifest, TranscriptWriter,
    TranscriptWriterConfig,
};
use mvm_hostd::audit::emitter::AuditEmitter;
use mvm_hostd::audit::plan_persist::{PLAN_FILENAME, read_plan_at};
use mvm_hostd::supervisor::audit::{
    LABEL_CAPTURE_ID, LABEL_CHUNK_COUNT, LABEL_TRANSCRIPT_ROOT, LABEL_VM_NAME,
    TRANSCRIPT_SEALED_EVENT,
};
use mvm_hostd::supervisor::verify_audit_chain_entries;

use mvm_hostd::audit::host_keypair::{PUBLIC_FILENAME, SECRET_FILENAME};

pub use mvm_hostd::audit::transcript_retirement::RetirementOutcome;

// Bound untrusted manifest decoding independently of its declared capture budget.
const MAX_MANIFEST_BYTES: u64 = 64 * 1024 * 1024;

/// One row of `transcript list`.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CaptureSummary {
    pub capture_id: String,
    pub tenant: String,
    pub vm: String,
    pub session: Option<String>,
    pub chunks: usize,
    pub bytes: u64,
}

/// Where captures, keys, and the audit log live. Carried so tests can point at
/// temp dirs instead of the real `~/.mvm` tree.
pub struct TranscriptService {
    transcripts_dir: PathBuf,
    keys_dir: PathBuf,
    vms_dir: PathBuf,
    audit_dir: PathBuf,
    verifying_key_path: PathBuf,
    /// Audit-log path override (tests). `None` → the default local audit log.
    audit_path: Option<PathBuf>,
}

impl TranscriptService {
    /// Use the configured host-local storage roots without opening or creating them.
    pub fn from_config() -> Self {
        let keys_dir = config::mvm_keys_dir();
        Self {
            transcripts_dir: config::mvm_transcripts_dir(),
            verifying_key_path: keys_dir.join(PUBLIC_FILENAME),
            keys_dir,
            vms_dir: config::vms_dir(),
            audit_dir: config::mvm_audit_dir(),
            audit_path: None,
        }
    }

    /// Use an isolated host-local storage tree, including its local audit log.
    /// This constructor performs no I/O and does not confer remote file access.
    pub fn at_home(home: &Path) -> Self {
        let keys_dir = home.join("keys");
        Self {
            transcripts_dir: home.join("transcripts"),
            verifying_key_path: keys_dir.join(PUBLIC_FILENAME),
            keys_dir,
            vms_dir: home.join("vms"),
            audit_dir: home.join("audit"),
            audit_path: Some(home.join("audit.jsonl")),
        }
    }

    fn capture_dir(&self, tenant: &str, capture_id: &str) -> PathBuf {
        config::transcript_capture_dir_at(&self.transcripts_dir, tenant, capture_id)
    }

    fn load_manifest(
        &self,
        tenant: &str,
        capture_id: &str,
    ) -> Result<(PathBuf, TranscriptManifest)> {
        validate_component(tenant)?;
        validate_component(capture_id)?;
        let dir = self.capture_dir(tenant, capture_id);
        let path = dir.join(MANIFEST_FILENAME);
        use std::io::Read as _;
        let file = std::fs::File::open(&path).context("opening capture manifest")?;
        let mut raw = Vec::new();
        file.take(MAX_MANIFEST_BYTES + 1)
            .read_to_end(&mut raw)
            .context("reading capture manifest")?;
        anyhow::ensure!(
            raw.len() as u64 <= MAX_MANIFEST_BYTES,
            "capture manifest exceeds size limit"
        );
        let manifest: TranscriptManifest = serde_json::from_slice(&raw)
            .map_err(|_| anyhow::anyhow!("invalid capture manifest"))?;
        validate_manifest_identity(&manifest)?;
        Ok((dir, manifest))
    }

    /// Provision private capture metadata and keys; this does not start a producer.
    pub fn arm(
        &self,
        tenant: &str,
        vm: &str,
        session: Option<&str>,
        bounds: CaptureBounds,
    ) -> Result<String> {
        validate_component(tenant)?;
        validate_component(vm)?;
        if let Some(session) = session {
            validate_session(session)?;
        }
        anyhow::ensure!(
            bounds.max_duration_secs > 0 && bounds.max_duration_secs <= 3600,
            "protected capture duration must be between 1 and 3600 seconds"
        );
        let capture_id = uuid::Uuid::new_v4().to_string();
        let dir = self.capture_dir(tenant, &capture_id);
        config::create_private_dir(&self.transcripts_dir)?;
        config::create_private_dir(self.transcripts_dir.join(tenant))?;
        config::create_private_dir(&dir)
            .with_context(|| format!("creating capture dir {}", dir.display()))?;

        // Per-capture data key, wrapped under the host KEK for the manifest.
        let kek = transcript::load_or_init_kek(&self.keys_dir)
            .context("loading the host transcript KEK")?;
        let data_key = aead::Key::random();
        let wrapped = transcript::wrap_data_key(&kek, &data_key);

        let cfg = TranscriptWriterConfig {
            capture_id: capture_id.clone(),
            binding: CaptureBinding {
                tenant_id: tenant.to_string(),
                vm_name: vm.to_string(),
                session_id: session.map(str::to_string),
            },
            bounds,
            // A forensic capture of discrete frames is right to stop at its
            // bound rather than quietly drop the start of what it recorded.
            retention: RetentionPolicy::FailClosed,
            at_rest: Some(transcript::AtRestRetention::default()),
            generation_budget: None,
            payload_encoding: Default::default(),
            created_unix_secs: transcript::retention_now()?,
            recipient: KEK_RECIPIENT.to_string(),
            wrapped_data_key_b64: wrapped,
        };
        // No chunks yet — the live bridge sink fills them out of band.
        let manifest = TranscriptWriter::new(&dir, data_key, cfg)?.seal();
        write_manifest(&dir, &manifest)?;

        self.audit(LocalAuditKind::TranscriptArmed, vm)
            .detail(format!(
                "tenant={tenant} vm={vm} capture={capture_id} max_bytes={} max_chunks={}",
                bounds.max_bytes, bounds.max_chunks
            ))
            .emit();
        Ok(capture_id)
    }

    /// Anchor a capture against its persisted admitted plan. The persistence
    /// helper accepts both bare local plans and signed admission envelopes;
    /// this operation does not re-admit the plan or choose a new trust policy.
    /// Refuses while a live producer holds the capture directory's writer
    /// lease.
    pub fn disarm(&self, tenant: &str, capture_id: &str) -> Result<()> {
        validate_component(tenant)?;
        validate_component(capture_id)?;
        let dir = self.capture_dir(tenant, capture_id);
        let lease = transcript::secure_cleanup::CaptureDirectory::for_writer(&dir)
            .context("cannot disarm a capture with an active producer")?;
        let mut manifest = lease
            .read_manifest()
            .map_err(|_| anyhow::anyhow!("invalid capture manifest"))?;
        validate_manifest_identity(&manifest)?;
        self.validate_manifest_binding(tenant, capture_id, &manifest)?;

        let plan_path = self
            .vms_dir
            .join(&manifest.binding.vm_name)
            .join(PLAN_FILENAME);
        let plan = read_plan_at(&plan_path)
            .map_err(|_| anyhow::anyhow!("reading admitted transcript plan.json failed"))?;
        if plan.tenant.0 != manifest.binding.tenant_id {
            anyhow::bail!("admitted plan tenant does not match transcript tenant");
        }
        if plan.workload.0 != manifest.binding.vm_name {
            anyhow::bail!("admitted plan workload does not match transcript VM");
        }

        if manifest.at_rest.is_some() && manifest.sealed_unix_secs.is_none() {
            // The exclusive directory lease excludes a live protected writer.
            // Reconstructed counters are a floor; preserve the opened lifetime.
            transcript::recover_abandoned_at(&mut manifest, transcript::retention_now()?)?;
            write_manifest(&dir, &manifest)?;
        }
        let signer = mvm_hostd::audit::host_keypair::load_or_init_at(&self.keys_dir)
            .context("loading the host signer to anchor the sealed transcript")?;
        match self.matching_chain_anchors(tenant, capture_id, &manifest)? {
            0 => AuditEmitter::with_dir(signer.signing, &self.audit_dir)
                .context("opening the host audit chain for the sealed transcript")?
                .emit_transcript_sealed(
                    &plan,
                    capture_id,
                    &manifest.binding.vm_name,
                    &manifest.sealed_root_hex,
                    manifest.chunks.len(),
                    manifest.adopted,
                )
                .context("anchoring the sealed transcript in the host audit chain")?,
            1 => {}
            count => anyhow::bail!(
                "expected at most one host-signed transcript seal in the audit chain for capture {capture_id}, found {count}"
            ),
        }

        self.audit(LocalAuditKind::TranscriptSealed, &manifest.binding.vm_name)
            .detail(format!(
                "tenant={tenant} vm={} capture={capture_id} chunks={}",
                manifest.binding.vm_name,
                manifest.chunks.len()
            ))
            .emit();
        Ok(())
    }

    /// Retire one sealed capture's payload once its authenticated at-rest
    /// deadline has passed. Authority comes from the signed seal in the host
    /// chain, never from the VM's current plan; the existing host signer is
    /// required and a missing one is never minted.
    pub fn reconcile(&self, tenant: &str, capture_id: &str) -> Result<RetirementOutcome> {
        use mvm_hostd::audit::transcript_retirement::{RetirementContext, reconcile_capture};
        let (_, manifest) = self.load_manifest(tenant, capture_id)?;
        self.validate_manifest_binding(tenant, capture_id, &manifest)?;
        let trusted = self.trusted_verifying_key()?;
        if manifest.at_rest.is_some() && manifest.sealed_unix_secs.is_some() {
            transcript::evidence::authenticated_retirement(&self.audit_dir, &trusted, &manifest)?;
        }
        let (signing, verifying) = mvm_core::crypto::ed25519_keypair::load_existing(
            &self.keys_dir.join(SECRET_FILENAME),
            &self.verifying_key_path,
        )
        .map_err(|_| anyhow::anyhow!("existing host signer is unavailable; refusing reconcile"))?;
        anyhow::ensure!(
            verifying == trusted,
            "host signer does not match trusted audit key"
        );
        let emitter = AuditEmitter::with_dir(signing, &self.audit_dir)?;
        let relative = PathBuf::from(tenant).join(capture_id);
        reconcile_capture(
            RetirementContext {
                root: &self.transcripts_dir,
                relative_capture: &relative,
                capture_id,
                tenant,
                vm: &manifest.binding.vm_name,
                emitter: &emitter,
            },
            transcript::retention_now()?,
        )
    }

    /// List metadata only, without decrypting payloads or creating keys.
    pub fn list(&self, tenant_filter: Option<&str>) -> Result<Vec<CaptureSummary>> {
        if let Some(tenant) = tenant_filter {
            validate_component(tenant)?;
        }
        let mut rows = Vec::new();
        let tenants = read_subdirs(&self.transcripts_dir);
        for tenant in tenants {
            if let Some(want) = tenant_filter
                && want != tenant
            {
                continue;
            }
            for capture_id in read_subdirs(&self.transcripts_dir.join(&tenant)) {
                let Ok((_d, m)) = self.load_manifest(&tenant, &capture_id) else {
                    continue;
                };
                rows.push(CaptureSummary {
                    capture_id,
                    tenant: m.binding.tenant_id.clone(),
                    vm: m.binding.vm_name.clone(),
                    session: m.binding.session_id.clone(),
                    chunks: m.chunks.len(),
                    bytes: m
                        .chunks
                        .iter()
                        .fold(0u64, |sum, c| sum.saturating_add(c.size_bytes)),
                });
            }
        }
        rows.sort_by(|a, b| a.capture_id.cmp(&b.capture_id));
        Ok(rows)
    }

    /// Verify the host-signed seal and decrypt with the original existing key.
    /// The returned bytes are intentionally payload; they are never included in
    /// metadata reports or diagnostic records. Capture/key files are not written.
    pub fn export(&self, tenant: &str, capture_id: &str) -> Result<Vec<u8>> {
        let (dir, manifest) = self.load_manifest(tenant, capture_id)?;
        let vm = manifest.binding.vm_name.clone();

        let recover = || -> Result<Vec<u8>> {
            self.verify_chain_anchor(tenant, capture_id, &manifest)?;
            if manifest.at_rest.is_some() {
                let trusted = self.trusted_verifying_key()?;
                anyhow::ensure!(
                    !transcript::evidence::authenticated_retirement(
                        &self.audit_dir,
                        &trusted,
                        &manifest,
                    )?,
                    "transcript payload has authenticated retirement evidence"
                );
            }
            let kek = transcript::load_kek(&self.keys_dir)
                .context("loading the host transcript KEK")?
                .context(
                    "host transcript KEK is missing; existing captures require their original key",
                )?;
            let data_key = transcript::unwrap_data_key(&kek, &manifest.wrapped_data_key_b64)
                .map_err(|_| anyhow::anyhow!("unwrapping the per-capture key failed"))?;
            transcript::export(&manifest, &dir, &data_key)
                .map_err(|_| anyhow::anyhow!("verifying + decrypting transcript failed"))
        };

        match recover() {
            Ok(bytes) => {
                self.audit(LocalAuditKind::TranscriptExported, &vm)
                    .detail(format!(
                        "tenant={tenant} vm={vm} capture={capture_id} bytes={}",
                        bytes.len()
                    ))
                    .emit();
                Ok(bytes)
            }
            Err(e) => {
                self.audit(LocalAuditKind::TranscriptRefused, &vm)
                    .detail(format!(
                        "tenant={tenant} vm={vm} capture={capture_id} reason=verification_or_key_failure"
                    ))
                    .emit();
                Err(e)
            }
        }
    }

    fn verify_chain_anchor(
        &self,
        tenant: &str,
        capture_id: &str,
        manifest: &TranscriptManifest,
    ) -> Result<()> {
        let count = self.matching_chain_anchors(tenant, capture_id, manifest)?;
        if count != 1 {
            anyhow::bail!(
                "expected exactly one host-signed transcript seal in the audit chain for capture {capture_id}, found {count}"
            );
        }
        Ok(())
    }

    fn validate_manifest_binding(
        &self,
        tenant: &str,
        capture_id: &str,
        manifest: &TranscriptManifest,
    ) -> Result<()> {
        validate_component(&manifest.binding.vm_name)?;
        transcript::verify_sealed_root(manifest)
            .map_err(|_| anyhow::anyhow!("verifying transcript manifest root failed"))?;
        if manifest.capture_id != capture_id || manifest.binding.tenant_id != tenant {
            anyhow::bail!(
                "transcript binding does not match requested tenant/capture ({tenant}/{capture_id})"
            );
        }
        Ok(())
    }

    fn matching_chain_anchors(
        &self,
        tenant: &str,
        capture_id: &str,
        manifest: &TranscriptManifest,
    ) -> Result<usize> {
        self.validate_manifest_binding(tenant, capture_id, manifest)?;

        let verifying_key = self.trusted_verifying_key()?;
        let chain_path = self.audit_dir.join(format!("{tenant}.jsonl"));
        if !chain_path.exists() {
            return Ok(0);
        }
        let entries = verify_audit_chain_entries(&chain_path, &verifying_key)
            .map_err(|_| anyhow::anyhow!("verifying audit chain failed"))?;
        let matching: Vec<_> = entries
            .iter()
            .filter(|entry| {
                entry.tenant.0 == tenant
                    && entry.event == TRANSCRIPT_SEALED_EVENT
                    && entry
                        .labels
                        .get(LABEL_CAPTURE_ID)
                        .is_some_and(|value| value == capture_id)
            })
            .collect();
        let expected_chunks = manifest.chunks.len().to_string();
        for entry in &matching {
            if entry.labels.get(LABEL_VM_NAME) != Some(&manifest.binding.vm_name)
                || entry.labels.get(LABEL_TRANSCRIPT_ROOT) != Some(&manifest.sealed_root_hex)
                || entry.labels.get(LABEL_CHUNK_COUNT) != Some(&expected_chunks)
            {
                anyhow::bail!(
                    "host-signed transcript seal does not match capture {capture_id} binding, root, or chunk count"
                );
            }
        }
        Ok(matching.len())
    }

    fn trusted_verifying_key(&self) -> Result<ed25519_dalek::VerifyingKey> {
        crate::audit::query::load_verifying_key(&self.verifying_key_path)
            .map_err(|_| anyhow::anyhow!("loading trusted host audit verifying key failed"))
    }

    fn audit(&self, kind: LocalAuditKind, vm: &str) -> LocalAuditBuilder {
        let b = event(kind).vm_name(vm);
        match &self.audit_path {
            Some(p) => b.to_path(p.clone()),
            None => b,
        }
    }
}

fn write_manifest(dir: &Path, manifest: &TranscriptManifest) -> Result<()> {
    let path = dir.join(MANIFEST_FILENAME);
    let json = serde_json::to_string_pretty(manifest)?;
    mvm_core::util::atomic_io::write_private(&path, json.as_bytes())
        .with_context(|| format!("writing {}", path.display()))
}

fn validate_component(value: &str) -> Result<()> {
    transcript::check_safe_name(value)?;
    anyhow::ensure!(
        !value.is_empty()
            && value.len() <= 128
            && value != "."
            && value != ".."
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.')),
        "invalid transcript identifier"
    );
    Ok(())
}

/// Identity fields of an untrusted manifest, checked before any path use.
fn validate_manifest_identity(manifest: &TranscriptManifest) -> Result<()> {
    validate_component(&manifest.capture_id)?;
    validate_component(&manifest.binding.tenant_id)?;
    validate_component(&manifest.binding.vm_name)?;
    if let Some(session) = &manifest.binding.session_id {
        validate_session(session)?;
    }
    Ok(())
}

fn validate_session(value: &str) -> Result<()> {
    anyhow::ensure!(
        value.len() <= 256 && !value.chars().any(char::is_control),
        "invalid transcript session"
    );
    Ok(())
}

/// Immediate subdirectory names of `dir` (empty if `dir` is missing).
fn read_subdirs(dir: &Path) -> Vec<String> {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    rd.flatten()
        .filter(|e| e.path().is_dir())
        .filter_map(|e| e.file_name().into_string().ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::transcript::Direction;

    fn ctx(root: &Path) -> TranscriptService {
        TranscriptService {
            transcripts_dir: root.join("transcripts"),
            keys_dir: root.join("keys"),
            vms_dir: root.join("vms"),
            audit_dir: root.join("chain-audit"),
            verifying_key_path: root.join("keys/host-signer.pub"),
            audit_path: Some(root.join("audit.jsonl")),
        }
    }

    fn persist_plan(c: &TranscriptService, tenant: &str, vm: &str) {
        use std::os::unix::fs::PermissionsExt as _;

        let plan = mvm_core::plan::test_support::PlanFixture::new()
            .tenant(tenant)
            .workload(vm)
            .plan_id(format!("transcript-{vm}"))
            .build();
        let vm_dir = c.vms_dir.join(vm);
        std::fs::create_dir_all(&vm_dir).unwrap();
        let path = vm_dir.join(mvm_hostd::audit::plan_persist::PLAN_FILENAME);
        std::fs::write(&path, serde_json::to_vec_pretty(&plan).unwrap()).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    fn trusted_host_key(c: &TranscriptService) -> ed25519_dalek::SigningKey {
        use ed25519_dalek::SigningKey;

        let key = SigningKey::from_bytes(&[7u8; 32]);
        std::fs::create_dir_all(c.verifying_key_path.parent().unwrap()).unwrap();
        std::fs::write(&c.verifying_key_path, key.verifying_key().to_bytes()).unwrap();
        key
    }

    fn anchor(c: &TranscriptService, manifest: &TranscriptManifest, root: &str) {
        use mvm_hostd::audit::emitter::AuditEmitter;

        let key = trusted_host_key(c);
        let emitter = AuditEmitter::with_dir(key, &c.audit_dir).unwrap();
        let plan = mvm_core::plan::test_support::PlanFixture::new()
            .tenant(&manifest.binding.tenant_id)
            .plan_id("transcript-test-plan")
            .build();
        emitter
            .emit_transcript_sealed(
                &plan,
                &manifest.capture_id,
                &manifest.binding.vm_name,
                root,
                manifest.chunks.len(),
                manifest.adopted,
            )
            .unwrap();
    }

    fn anchor_manifest(c: &TranscriptService, manifest: &TranscriptManifest) {
        anchor(c, manifest, &manifest.sealed_root_hex);
    }

    fn bounds() -> CaptureBounds {
        CaptureBounds {
            max_duration_secs: 3600,
            max_bytes: 1 << 20,
            max_chunks: 1000,
        }
    }

    #[test]
    fn reconciliation_before_expiry_does_not_need_current_plan() {
        let root = tempfile::tempdir().unwrap();
        let c = ctx(root.path());
        persist_plan(&c, "local", "vm1");
        let id = c.arm("local", "vm1", None, bounds()).unwrap();
        c.disarm("local", &id).unwrap();
        std::fs::remove_file(c.vms_dir.join("vm1").join(PLAN_FILENAME)).unwrap();
        c.reconcile("local", &id).unwrap();
        // A different tenant's replacement plan must not supply authority.
        persist_plan(&c, "replacement-tenant", "vm1");
        c.reconcile("local", &id).unwrap();
    }

    #[test]
    fn signed_partial_retirement_survives_removal_of_current_plan() {
        use mvm_core::transcript::evidence::{
            TRANSCRIPT_RETIRED_EVENT, authenticated_retirement_at, labels,
        };
        let root = tempfile::tempdir().unwrap();
        let c = ctx(root.path());
        persist_plan(&c, "local", "vm1");
        let id = c.arm("local", "vm1", None, bounds()).unwrap();
        let (dir, opened) = c.load_manifest("local", &id).unwrap();
        let kek = transcript::load_kek(&c.keys_dir).unwrap().unwrap();
        let key = transcript::unwrap_data_key(&kek, &opened.wrapped_data_key_b64).unwrap();
        let mut writer = TranscriptWriter::new(
            &dir,
            key,
            TranscriptWriterConfig {
                capture_id: id.clone(),
                binding: opened.binding,
                bounds: CaptureBounds {
                    max_bytes: 4 * transcript::SEGMENT_MAX_CIPHERTEXT_BYTES,
                    ..opened.bounds
                },
                retention: opened.retention,
                at_rest: opened.at_rest,
                generation_budget: None,
                payload_encoding: Default::default(),
                created_unix_secs: 100,
                recipient: opened.recipient,
                wrapped_data_key_b64: opened.wrapped_data_key_b64,
            },
        )
        .unwrap();
        let payload = vec![b'x'; transcript::SEGMENT_MAX_CIPHERTEXT_BYTES as usize / 2];
        writer.push(Direction::Stdout, &payload).unwrap();
        writer.push(Direction::Stdout, &payload).unwrap();
        let terminal = writer.finalize_at(200).unwrap();
        assert_ne!(terminal.chunks[0].file, terminal.chunks[1].file);
        write_manifest(&dir, &terminal).unwrap();
        drop(writer);
        c.disarm("local", &id).unwrap();
        let trusted = crate::audit::query::load_verifying_key(&c.verifying_key_path).unwrap();
        let (mut entry, _) =
            authenticated_retirement_at(&c.audit_dir, &trusted, &terminal, Some(605_000)).unwrap();
        entry.event = TRANSCRIPT_RETIRED_EVENT.into();
        entry.labels = labels(&terminal).unwrap();
        let (signing, _) = mvm_core::crypto::ed25519_keypair::load_existing(
            &c.keys_dir
                .join(mvm_hostd::audit::host_keypair::SECRET_FILENAME),
            &c.verifying_key_path,
        )
        .unwrap();
        AuditEmitter::with_dir(signing, &c.audit_dir)
            .unwrap()
            .emit_entry_for_evidence(&entry, mvm_hostd::audit::evidence::EvidenceReceipt::Omitted)
            .unwrap();
        // This fixture isolates historical authority from current plan state.
        // Actual partial-unlink fault boundaries are exercised in core cleanup.
        std::fs::remove_file(dir.join(&terminal.chunks[0].file)).unwrap();
        std::fs::remove_file(c.vms_dir.join("vm1").join(PLAN_FILENAME)).unwrap();
        let evidence = std::fs::read(c.audit_dir.join("local.jsonl")).unwrap();
        c.reconcile("local", &id).unwrap();
        c.reconcile("local", &id).unwrap();
        assert!(!dir.join(&terminal.chunks[1].file).exists());
        assert_eq!(
            std::fs::read(c.audit_dir.join("local.jsonl")).unwrap(),
            evidence
        );
        assert_eq!(c.load_manifest("local", &id).unwrap().1, terminal);
    }

    #[test]
    fn operator_reconcile_expires_only_authorized_payload_and_preserves_evidence() {
        let root = tempfile::tempdir().unwrap();
        let c = ctx(root.path());
        persist_plan(&c, "local", "vm1");
        let id = c.arm("local", "vm1", None, bounds()).unwrap();
        let (dir, opened) = c.load_manifest("local", &id).unwrap();
        assert_eq!(opened.at_rest, Some(transcript::AtRestRetention::default()));
        let kek = transcript::load_kek(&c.keys_dir).unwrap().unwrap();
        let key = transcript::unwrap_data_key(&kek, &opened.wrapped_data_key_b64).unwrap();
        let mut writer = TranscriptWriter::new(
            &dir,
            key,
            TranscriptWriterConfig {
                capture_id: id.clone(),
                binding: opened.binding,
                bounds: opened.bounds,
                retention: opened.retention,
                at_rest: opened.at_rest,
                generation_budget: None,
                payload_encoding: Default::default(),
                created_unix_secs: 100,
                recipient: opened.recipient,
                wrapped_data_key_b64: opened.wrapped_data_key_b64,
            },
        )
        .unwrap();
        writer
            .push(Direction::Stdout, b"synthetic retention marker")
            .unwrap();
        let terminal = writer.finalize_at(200).unwrap();
        write_manifest(&dir, &terminal).unwrap();
        assert!(
            c.disarm("local", &id).is_err(),
            "live writer lease excludes control"
        );
        drop(writer);
        c.disarm("local", &id).unwrap();
        // Historical cleanup cannot depend on mutable or deleted VM state.
        std::fs::remove_file(c.vms_dir.join("vm1").join(PLAN_FILENAME)).unwrap();
        let original = std::fs::read(dir.join(MANIFEST_FILENAME)).unwrap();
        assert!(
            c.export("local", &id).is_err(),
            "deadline refuses before cleanup"
        );
        assert!(dir.join(&terminal.chunks[0].file).exists());
        std::fs::write(dir.join("foreign"), b"synthetic foreign").unwrap();
        let signer_path = c
            .keys_dir
            .join(mvm_hostd::audit::host_keypair::SECRET_FILENAME);
        let original_signer = std::fs::read(&signer_path).unwrap();
        std::fs::remove_file(&signer_path).unwrap();
        assert!(c.reconcile("local", &id).is_err());
        assert!(
            !signer_path.exists(),
            "reconciliation must not mint a signer"
        );
        assert!(dir.join(&terminal.chunks[0].file).exists());
        mvm_core::util::atomic_io::write_private(&signer_path, &original_signer).unwrap();
        c.reconcile("local", &id).unwrap();
        c.reconcile("local", &id).unwrap();
        assert!(!dir.join(&terminal.chunks[0].file).exists());
        assert_eq!(
            std::fs::read(dir.join(MANIFEST_FILENAME)).unwrap(),
            original
        );
        assert_eq!(
            std::fs::read(dir.join("foreign")).unwrap(),
            b"synthetic foreign"
        );
        assert!(c.export("local", &id).is_err());
        let evidence = std::fs::read_to_string(c.audit_dir.join("local.jsonl")).unwrap();
        assert!(!evidence.contains("synthetic retention marker"));
        assert!(evidence.contains("transcript.retired"));
    }

    fn audit_contains(c: &TranscriptService, token: &str) -> bool {
        std::fs::read_to_string(c.audit_path.as_ref().unwrap())
            .map(|s| s.contains(token))
            .unwrap_or(false)
    }

    #[test]
    fn arm_creates_a_manifest_with_a_wrapped_key_and_audits() {
        let d = tempfile::tempdir().unwrap();
        let c = ctx(d.path());
        let id = c.arm("t1", "vm1", Some("s1"), bounds()).unwrap();
        let (_dir, m) = c.load_manifest("t1", &id).unwrap();
        assert_eq!(m.binding.vm_name, "vm1");
        assert_eq!(m.binding.session_id.as_deref(), Some("s1"));
        assert!(!m.wrapped_data_key_b64.is_empty(), "data key is wrapped");
        assert!(m.chunks.is_empty(), "armed capture has no chunks yet");
        assert!(audit_contains(&c, "transcript_armed"));
    }

    #[test]
    fn list_reports_armed_captures() {
        let d = tempfile::tempdir().unwrap();
        let c = ctx(d.path());
        let id = c.arm("t1", "vm1", None, bounds()).unwrap();
        c.arm("t2", "vm2", None, bounds()).unwrap();
        let all = c.list(None).unwrap();
        assert_eq!(all.len(), 2);
        let only_t1 = c.list(Some("t1")).unwrap();
        assert_eq!(only_t1.len(), 1);
        assert_eq!(only_t1[0].capture_id, id);
        assert_eq!(only_t1[0].vm, "vm1");
    }

    #[test]
    fn disarm_emits_one_host_signed_seal_from_the_persisted_plan() {
        let d = tempfile::tempdir().unwrap();
        let c = ctx(d.path());
        persist_plan(&c, "t1", "vm1");
        let id = c.arm("t1", "vm1", None, bounds()).unwrap();
        c.disarm("t1", &id).unwrap();
        c.disarm("t1", &id).unwrap();

        let (_dir, manifest) = c.load_manifest("t1", &id).unwrap();
        c.verify_chain_anchor("t1", &id, &manifest).unwrap();
        let key = crate::audit::query::load_verifying_key(&c.verifying_key_path).unwrap();
        let entries = verify_audit_chain_entries(&c.audit_dir.join("t1.jsonl"), &key).unwrap();
        let seals: Vec<_> = entries
            .iter()
            .filter(|entry| entry.event == TRANSCRIPT_SEALED_EVENT)
            .collect();
        assert_eq!(seals.len(), 1, "repeated disarm must not fork evidence");
        assert_eq!(
            seals[0].labels.get(LABEL_TRANSCRIPT_ROOT),
            Some(&manifest.sealed_root_hex)
        );
        assert!(audit_contains(&c, "transcript_sealed"));
    }

    #[test]
    fn disarm_refuses_without_the_vms_persisted_plan() {
        let d = tempfile::tempdir().unwrap();
        let c = ctx(d.path());
        let id = c.arm("t1", "vm1", None, bounds()).unwrap();

        let err = c
            .disarm("t1", &id)
            .expect_err("an unbound transcript must not be declared sealed");

        assert!(format!("{err:#}").contains("plan.json"));
        assert!(!c.audit_dir.join("t1.jsonl").exists());
        assert!(!audit_contains(&c, "transcript_sealed"));
    }

    #[test]
    fn disarm_refuses_a_plan_from_a_different_tenant() {
        let d = tempfile::tempdir().unwrap();
        let c = ctx(d.path());
        persist_plan(&c, "other-tenant", "vm1");
        let id = c.arm("t1", "vm1", None, bounds()).unwrap();

        let err = c
            .disarm("t1", &id)
            .expect_err("a cross-tenant plan must not anchor the transcript");

        assert!(format!("{err:#}").contains("tenant"));
        assert!(!c.audit_dir.join("t1.jsonl").exists());
        assert!(!audit_contains(&c, "transcript_sealed"));
    }

    #[test]
    fn export_round_trips_captured_chunks_and_audits() {
        let d = tempfile::tempdir().unwrap();
        let c = ctx(d.path());
        let id = c.arm("t1", "vm1", None, bounds()).unwrap();

        // Simulate the live sink: rewrite the manifest with real encrypted
        // chunks under the same (unwrapped) data key.
        let (dir, manifest) = c.load_manifest("t1", &id).unwrap();
        let kek = transcript::load_or_init_kek(&c.keys_dir).unwrap();
        let data_key = transcript::unwrap_data_key(&kek, &manifest.wrapped_data_key_b64).unwrap();
        let mut w = TranscriptWriter::new(
            &dir,
            data_key,
            TranscriptWriterConfig {
                capture_id: manifest.capture_id.clone(),
                binding: manifest.binding.clone(),
                bounds: manifest.bounds,
                retention: manifest.retention,
                at_rest: manifest.at_rest,
                generation_budget: manifest.generation_budget,
                payload_encoding: manifest.payload_encoding,
                created_unix_secs: manifest.created_unix_secs,
                recipient: manifest.recipient.clone(),
                wrapped_data_key_b64: manifest.wrapped_data_key_b64.clone(),
            },
        )
        .unwrap();
        w.push(Direction::Egress, b"GET / HTTP/1.1\r\n").unwrap();
        w.push(Direction::Ingress, b"HTTP/1.1 200 OK\r\n").unwrap();
        let sealed = w.seal();
        write_manifest(&dir, &sealed).unwrap();
        anchor_manifest(&c, &sealed);

        let out = c.export("t1", &id).unwrap();
        assert_eq!(out, b"GET / HTTP/1.1\r\nHTTP/1.1 200 OK\r\n");
        assert!(audit_contains(&c, "transcript_exported"));
    }

    #[test]
    fn export_refuses_a_missing_key_without_replacing_it() {
        let d = tempfile::tempdir().unwrap();
        let c = ctx(d.path());
        let id = c.arm("t1", "vm1", None, bounds()).unwrap();
        let (_dir, manifest) = c.load_manifest("t1", &id).unwrap();
        anchor_manifest(&c, &manifest);
        let key_path = c.keys_dir.join(transcript::TRANSCRIPT_KEK_FILENAME);
        let original_key = std::fs::read(&key_path).unwrap();
        std::fs::remove_file(&key_path).unwrap();

        let err = c
            .export("t1", &id)
            .expect_err("missing key must refuse export");
        assert!(format!("{err:#}").contains("host transcript KEK is missing"));
        assert!(!key_path.exists(), "export must not mint a replacement key");
        assert!(audit_contains(&c, "transcript_refused"));
        assert!(!audit_contains(&c, "transcript_exported"));

        // Recovery requires the original key, not a newly generated one.
        mvm_core::util::atomic_io::write_private(&key_path, &original_key).unwrap();
        assert!(c.export("t1", &id).unwrap().is_empty());
        assert_eq!(std::fs::read(&key_path).unwrap(), original_key);
    }

    #[test]
    fn export_refuses_a_tampered_chunk_and_audits_refusal() {
        let d = tempfile::tempdir().unwrap();
        let c = ctx(d.path());
        let id = c.arm("t1", "vm1", None, bounds()).unwrap();
        let (dir, manifest) = c.load_manifest("t1", &id).unwrap();
        let kek = transcript::load_or_init_kek(&c.keys_dir).unwrap();
        let data_key = transcript::unwrap_data_key(&kek, &manifest.wrapped_data_key_b64).unwrap();
        let mut w = TranscriptWriter::new(
            &dir,
            data_key,
            TranscriptWriterConfig {
                capture_id: manifest.capture_id.clone(),
                binding: manifest.binding.clone(),
                bounds: manifest.bounds,
                retention: manifest.retention,
                at_rest: manifest.at_rest,
                generation_budget: manifest.generation_budget,
                payload_encoding: manifest.payload_encoding,
                created_unix_secs: manifest.created_unix_secs,
                recipient: manifest.recipient.clone(),
                wrapped_data_key_b64: manifest.wrapped_data_key_b64.clone(),
            },
        )
        .unwrap();
        w.push(Direction::Egress, b"secret").unwrap();
        let sealed = w.seal();
        write_manifest(&dir, &sealed).unwrap();
        anchor_manifest(&c, &sealed);
        // Same-length byte flip → hash mismatch on export.
        let mut ct = std::fs::read(dir.join("0.seg")).unwrap();
        ct[0] ^= 0xff;
        std::fs::write(dir.join("0.seg"), &ct).unwrap();

        assert!(c.export("t1", &id).is_err());
        assert!(audit_contains(&c, "transcript_refused"));
    }

    #[test]
    fn export_refuses_when_the_host_signed_anchor_is_missing() {
        let d = tempfile::tempdir().unwrap();
        let c = ctx(d.path());
        let id = c.arm("t1", "vm1", None, bounds()).unwrap();
        trusted_host_key(&c);

        let err = c
            .export("t1", &id)
            .expect_err("unanchored evidence is refused");
        assert!(err.to_string().contains("audit chain"));
        assert!(audit_contains(&c, "transcript_refused"));
    }

    #[test]
    fn export_refuses_when_the_host_signed_root_does_not_match() {
        let d = tempfile::tempdir().unwrap();
        let c = ctx(d.path());
        let id = c.arm("t1", "vm1", None, bounds()).unwrap();
        let (_dir, manifest) = c.load_manifest("t1", &id).unwrap();
        anchor(&c, &manifest, &"00".repeat(32));

        let err = c
            .export("t1", &id)
            .expect_err("mismatched signed root is refused");
        assert!(err.to_string().contains("does not match"));
        assert!(audit_contains(&c, "transcript_refused"));
    }

    #[test]
    fn export_refuses_a_tampered_host_audit_chain() {
        let d = tempfile::tempdir().unwrap();
        let c = ctx(d.path());
        let id = c.arm("t1", "vm1", None, bounds()).unwrap();
        let (_dir, manifest) = c.load_manifest("t1", &id).unwrap();
        anchor_manifest(&c, &manifest);

        let path = c.audit_dir.join("t1.jsonl");
        let chain = std::fs::read_to_string(&path).unwrap();
        std::fs::write(
            &path,
            chain.replace("gateway.transcript_sealed", "gateway.forged"),
        )
        .unwrap();

        let err = c.export("t1", &id).expect_err("tampered chain is refused");
        assert!(err.to_string().contains("verifying audit chain"));
        assert!(audit_contains(&c, "transcript_refused"));
    }

    #[test]
    fn export_of_unknown_capture_errors() {
        let d = tempfile::tempdir().unwrap();
        let c = ctx(d.path());
        assert!(c.export("t1", "does-not-exist").is_err());
    }

    #[test]
    fn metadata_and_failed_reads_do_not_create_storage_or_keys() {
        let d = tempfile::tempdir().unwrap();
        let home = d.path().join("absent");
        let c = TranscriptService::at_home(&home);
        assert!(c.list(None).unwrap().is_empty());
        assert!(c.export("t1", "missing").is_err());
        assert!(!home.exists());
        for invalid in ["../escape", "/absolute", ".", "..", "line\nbreak"] {
            assert!(c.arm(invalid, "vm1", None, bounds()).is_err());
            assert!(c.export("t1", invalid).is_err());
        }
        assert!(!home.exists());
    }

    #[test]
    fn arm_creates_private_capture_metadata() {
        use std::os::unix::fs::PermissionsExt as _;
        let d = tempfile::tempdir().unwrap();
        let c = ctx(d.path());
        let id = c.arm("t1", "vm1", None, bounds()).unwrap();
        assert_eq!(uuid::Uuid::parse_str(&id).unwrap().get_version_num(), 4);
        let dir = c.capture_dir("t1", &id);
        for (path, expected) in [
            (dir.clone(), 0o700),
            (dir.join(MANIFEST_FILENAME), 0o600),
            (c.keys_dir.join(transcript::TRANSCRIPT_KEK_FILENAME), 0o600),
        ] {
            assert_eq!(
                std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
                expected
            );
        }
    }

    #[test]
    fn disarm_accepts_the_existing_signed_admitted_plan_shape() {
        let d = tempfile::tempdir().unwrap();
        let c = ctx(d.path());
        persist_plan(&c, "t1", "vm1");
        let path = c.vms_dir.join("vm1").join(PLAN_FILENAME);
        let plan = read_plan_at(&path).unwrap();
        // Admission may trust a fleet signer rather than the local audit signer.
        let signer = ed25519_dalek::SigningKey::from_bytes(&[29; 32]);
        let signed = mvm_core::plan::sign_plan(&plan, &signer, "fleet-signer");
        mvm_core::util::atomic_io::write_private(&path, &serde_json::to_vec(&signed).unwrap())
            .unwrap();
        let id = c.arm("t1", "vm1", None, bounds()).unwrap();
        c.disarm("t1", &id).unwrap();
        assert!(c.export("t1", &id).unwrap().is_empty());
    }

    #[test]
    fn export_refuses_wrong_audit_key_without_changing_capture_or_keys() {
        let d = tempfile::tempdir().unwrap();
        let c = ctx(d.path());
        let id = c.arm("t1", "vm1", None, bounds()).unwrap();
        let (dir, manifest) = c.load_manifest("t1", &id).unwrap();
        anchor_manifest(&c, &manifest);
        let wrong = ed25519_dalek::SigningKey::from_bytes(&[13; 32])
            .verifying_key()
            .to_bytes();
        std::fs::write(&c.verifying_key_path, wrong).unwrap();
        let manifest_path = dir.join(MANIFEST_FILENAME);
        let before = std::fs::read(&manifest_path).unwrap();
        let key_path = c.keys_dir.join(transcript::TRANSCRIPT_KEK_FILENAME);
        let key_before = std::fs::read(&key_path).unwrap();
        assert!(c.export("t1", &id).is_err());
        assert_eq!(std::fs::read(manifest_path).unwrap(), before);
        assert_eq!(std::fs::read(key_path).unwrap(), key_before);
        assert_eq!(std::fs::read(&c.verifying_key_path).unwrap(), wrong);
        assert!(
            !c.keys_dir
                .join(mvm_hostd::audit::host_keypair::SECRET_FILENAME)
                .exists()
        );
    }

    #[test]
    fn malformed_metadata_diagnostics_are_bounded_and_redacted() {
        let d = tempfile::tempdir().unwrap();
        let c = ctx(d.path());
        let id = c.arm("t1", "vm1", None, bounds()).unwrap();
        let path = c.capture_dir("t1", &id).join(MANIFEST_FILENAME);
        let secret = "private-payload-marker".repeat(1000);
        std::fs::write(&path, format!(r#"{{"format_version":"{secret}"}}"#)).unwrap();
        let err = c.export("t1", &id).unwrap_err();
        assert!(format!("{err:#}").len() < 100);
        assert!(!format!("{err:#}").contains("private-payload-marker"));
        assert!(c.list(None).unwrap().is_empty());
        let file = std::fs::File::create(path).unwrap();
        file.set_len(MAX_MANIFEST_BYTES + 1).unwrap();
        assert!(
            c.export("t1", &id)
                .unwrap_err()
                .to_string()
                .contains("size limit")
        );
    }
}
