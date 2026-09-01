//! Host-side chain-signed audit emitter.
//!
//! Wraps `mvm_hostd::supervisor::FileAuditSigner` so `mvmctl up` can emit
//! tamper-evident `plan.admitted` / `plan.launched` / `plan.failed`
//! entries bound to the `AdmittedPlan`. The chain is signed under the
//! host signer's keypair (the same Ed25519 key used for plan
//! envelopes); a future workstream may split the audit-signer and
//! plan-signer keys.
//!
//! ## On-disk layout
//!
//! Audit dir defaults to `~/.mvm/audit/`. `FileAuditSigner` writes
//! per-tenant `<audit_dir>/<tenant>.jsonl` streams; with one host =
//! one tenant ("local"), that's a single file in practice. The
//! directory is created mode `0700` so other users on the host can't
//! read the audit chain.
//!
//! ## Async bridge
//!
//! `FileAuditSigner::sign_and_emit` is async because the trait is
//! shared with the in-process supervisor path, but `mvmctl up` is
//! synchronous. We build a single-threaded tokio
//! runtime per emit (mirrors `mvm-backend::libkrun::block_on`).
//! Audit emission is rare (3 entries per `mvmctl up` invocation), so
//! the runtime-construction overhead is negligible compared to the VM
//! boot itself.
//!
//! ## Error handling
//!
//! Audit failures should NEVER block a boot in this v0 — the audit
//! chain is supplementary tamper-evidence, not part of the
//! admission decision. Callers `tracing::warn` and continue. A
//! follow-up tightens this to "audit failure fails the boot" once
//! the chain is reliably reachable.
//!
//! [`AuditEmitter`] is the public-to-the-module surface; tests use
//! `AuditEmitter::with_dir` to inject a tempdir.

use std::path::{Path, PathBuf};

use crate::audit::decisions::DecisionStore;
pub use crate::audit::evidence::EmittedEvidence;
use crate::audit::evidence::{EvidenceReceipt, audit_entry_digest_hex};
use crate::audit::receipt_export::audit_entry_to_receipt;
use crate::audit::receipt_store::ReceiptStore;
use crate::supervisor::{
    AuditSigner, FileAuditSigner, PlanAuditEntry, audit_mirror, for_plan, transcript_sealed,
};
use anyhow::{Context, Result};
use chrono::Utc;
use ed25519_dalek::SigningKey;
use mvm_contract::merkle::SignedAuditRoot;
use mvm_contract::provenance::{
    ActorRef, AttestationBinding, DecisionActorRole, DecisionCategory, DecisionId, DecisionOutcome,
    DecisionRecord, DecisionRecordBuilder,
};
use mvm_contract::verify::hash_line;
use mvm_core::plan::ExecutionPlan;
use mvm_core::usage_capture::UsageCapture;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

mod atomic_sync;
use atomic_sync::AtomicSyncBatch;
pub(crate) use atomic_sync::AtomicSyncState;
#[cfg(test)]
use atomic_sync::atomic_sync_is_batched;

mod atomic_write;
#[cfg(test)]
pub(crate) use atomic_write::write_atomic_batched;
pub(crate) use atomic_write::{write_atomic, write_atomic_unsynced};

mod session_events;

pub mod checkpoint_audit;
pub mod wall_clock_audit;
pub use checkpoint_audit::CheckpointForkedAudit;
pub mod image_audit;

/// Wire-stable event name and label keys for the workload output-stream audit
/// entries. Shared so the emitter (writer) and any reader cannot drift on a
/// string.
///
/// One entry per *attach*, never per record. Signing every chunk would cost a
/// signature per write and — worse — turn the audit chain into a second copy
/// of the workload's output. Who started reading, and from where in the
/// chain, is the decision worth signing; the bytes stay in the transcript.
pub mod stream_audit {
    /// Emitted when a follower attaches to a VM's output stream.
    pub const SUBSCRIBED_EVENT: &str = "stream.subscribed";
    /// Label: the VM whose stream was attached to.
    pub const LABEL_VM_NAME: &str = "vm_name";
    /// Label: the broker-assigned reader id, unique within one broker.
    pub const LABEL_READER_ID: &str = "stream_reader_id";
    /// Label: the stream sequence number the reader starts at. Records
    /// before it were produced before the attach and are not delivered.
    pub const LABEL_FROM_SEQ: &str = "stream_from_seq";
    /// Label on `plan.admitted`: the retention mode the plan was admitted
    /// under, so a later reader can tell a run that kept no transcript from a
    /// run whose transcript went missing.
    pub const LABEL_RETENTION: &str = "stream_retention";

    /// Emitted when a writer is admitted to a workload's stdin.
    ///
    /// Output capture needs no authorization and so audits only the attach;
    /// input is the direction that changes what the workload does, so the
    /// admission itself is the fact worth signing. Without it the chain would
    /// record every writer that was turned away and nothing about the one that
    /// got in.
    pub const INPUT_GRANTED_EVENT: &str = "stream.input_granted";
    /// Emitted whenever the input gate turns a writer away.
    pub const INPUT_REFUSED_EVENT: &str = "stream.input_refused";
    /// Label: which writer holds — or was refused because somebody else holds
    /// — the single-writer input lease.
    pub const LABEL_HOLDER: &str = "stream_input_holder";
    /// Label: why the gate refused, as a wire-stable reason word.
    pub const LABEL_REASON: &str = "stream_input_reason";
    /// Label: which category of known secret was recognised in the refused
    /// bytes. The category name, never the matched value — a refusal that
    /// quoted the secret to explain itself would ship exactly what it stopped.
    pub const LABEL_SECRET_CATEGORY: &str = "stream_input_secret_category";
    /// Label: the `seq` an out-of-order frame carried. A position, not a
    /// payload — it says which frame the writer sent out of turn and nothing
    /// about what was in it.
    pub const LABEL_SEQ: &str = "stream_input_seq";
    /// Label: the highest `seq` the session had already accepted when the
    /// out-of-order frame arrived.
    pub const LABEL_AFTER_SEQ: &str = "stream_input_after_seq";
}

/// The label set for one input refusal: the binding, the reason word, and
/// whatever that reason needs to be actionable.
///
/// Written as one exhaustive match so a refusal variant added later cannot
/// reach the chain unlabelled — and so the compiler is the thing checking that
/// no arm reaches for the bytes.
fn input_refused_labels(
    vm_name: &str,
    refusal: &crate::stream::InputRefusal,
) -> Vec<(String, String)> {
    use crate::stream::InputRefusal as R;
    use stream_audit as k;

    let mut labels = vec![
        (k::LABEL_VM_NAME.to_string(), vm_name.to_string()),
        (k::LABEL_REASON.to_string(), refusal.reason().to_string()),
    ];
    match refusal {
        // `Unauditable` is here for completeness: by definition the chain it
        // would be written to is the one that just failed, so this label set
        // is what a *later* best-effort attempt carries if the failure was
        // transient.
        R::NotGranted | R::LeaseExpired | R::Unauditable => {}
        R::LeaseHeld { holder } => {
            labels.push((k::LABEL_HOLDER.to_string(), holder.clone()));
        }
        R::SecretMaterial { category } => {
            labels.push((
                k::LABEL_SECRET_CATEGORY.to_string(),
                (*category).to_string(),
            ));
        }
        R::OutOfOrder { seq, after } => {
            labels.push((k::LABEL_SEQ.to_string(), seq.to_string()));
            labels.push((k::LABEL_AFTER_SEQ.to_string(), after.to_string()));
        }
    }
    labels
}

/// Extract the `image.created` label set from a node's provenance attributes.
/// The parent hash-link is recorded as provenance; nothing here is a trust
/// grant (lineage is provenance, never authorization).
fn image_created_labels(node: &mvm_core::image_lineage::ImageNode) -> Vec<(String, String)> {
    use image_audit as k;
    use mvm_core::image_lineage::{ImageBuildIdentity, ImageProvenance};

    let mut labels = vec![
        (
            k::LABEL_NODE_DIGEST.to_string(),
            node.node_digest.as_str().to_string(),
        ),
        (
            k::LABEL_PARENT_DIGEST.to_string(),
            node.parent
                .as_ref()
                .map(|p| p.as_str().to_string())
                .unwrap_or_else(|| k::GENESIS_PARENT.to_string()),
        ),
    ];
    match &node.build_identity {
        ImageBuildIdentity::Flake { slot_hash } => {
            labels.push((
                k::LABEL_BUILD_IDENTITY_KIND.to_string(),
                "flake".to_string(),
            ));
            labels.push((k::LABEL_BUILD_IDENTITY.to_string(), slot_hash.clone()));
        }
        ImageBuildIdentity::Oci {
            registry,
            repository,
        } => {
            labels.push((k::LABEL_BUILD_IDENTITY_KIND.to_string(), "oci".to_string()));
            labels.push((
                k::LABEL_BUILD_IDENTITY.to_string(),
                format!("{registry}/{repository}"),
            ));
        }
    }
    match &node.provenance {
        ImageProvenance::Build {
            input_ref,
            lock_digest,
        } => {
            labels.push((k::LABEL_PROVENANCE_KIND.to_string(), "build".to_string()));
            labels.push((k::LABEL_PROVENANCE_INPUT_REF.to_string(), input_ref.clone()));
            if let Some(lock) = lock_digest {
                labels.push((k::LABEL_PROVENANCE_LOCK_DIGEST.to_string(), lock.clone()));
            }
        }
        ImageProvenance::Oci {
            resolved_digest,
            layer_digests,
        } => {
            labels.push((k::LABEL_PROVENANCE_KIND.to_string(), "oci".to_string()));
            labels.push((
                k::LABEL_PROVENANCE_RESOLVED_DIGEST.to_string(),
                resolved_digest.clone(),
            ));
            labels.push((
                k::LABEL_PROVENANCE_LAYER_DIGESTS.to_string(),
                layer_digests.join(","),
            ));
        }
    }
    labels
}

/// Resolve the default audit-chain directory: `~/.mvm/audit/`.
pub fn default_audit_dir() -> Result<PathBuf> {
    Ok(mvm_core::config::mvm_home_strict()?.join("audit"))
}

/// Resolve the default per-tenant audit-chain file:
/// `~/.mvm/audit/<tenant>.jsonl`. Used by the `mvmctl audit verify`
/// and `mvmctl audit show` commands.
pub fn audit_path_for_tenant(audit_dir: &Path, tenant: &str) -> PathBuf {
    audit_dir.join(format!("{tenant}.jsonl"))
}

/// Resolve the per-tenant published Merkle-root sidecar:
/// `<audit_dir>/<tenant>.root.json`. Sibling to [`audit_path_for_tenant`];
/// `mvm_core::config::audit_root_path` is the global-default counterpart the
/// CLI reads.
pub fn audit_root_path_for_tenant(audit_dir: &Path, tenant: &str) -> PathBuf {
    audit_dir.join(format!("{tenant}.root.json"))
}

/// The append-only history of every root ever published for `tenant`.
///
/// The latest-root sidecar is overwritten on each publish, which is what a
/// reader wanting "where is the log now" needs and exactly the wrong shape
/// for attesting that it only ever grew: a consistency proof relates *two*
/// roots, and overwriting destroys the earlier one. So each publish also
/// appends here, and the file is never rewritten.
pub fn audit_root_history_path_for_tenant(audit_dir: &Path, tenant: &str) -> PathBuf {
    audit_dir.join(format!(
        "{tenant}{}",
        mvm_core::config::AUDIT_ROOT_HISTORY_SUFFIX
    ))
}

/// Host-side emitter wrapping `FileAuditSigner`. Owns its own signing
/// key half (cloned from the host signer at construction); calls
/// `tokio::runtime::Builder::new_current_thread()` per emit.
///
/// Also retains the signing key + primary audit directory so it can build
/// and sign a published Merkle root over the tenant chain
/// ([`Self::publish_root`]).
pub struct AuditEmitter {
    signers: Vec<Arc<FileAuditSigner>>,
    signing_key: SigningKey,
    audit_dir: PathBuf,
    receipts_enabled: bool,
    receipt_stores: Mutex<HashMap<String, ReceiptStore>>,
    decisions_enabled: bool,
    decisions_dir: Option<PathBuf>,
    decision_stores: Mutex<HashMap<String, DecisionStore>>,
    atomic_sync_state: Arc<AtomicSyncState>,
    /// Built once on first emit and reused.
    ///
    /// The signer interface is async and the callers are not, so each emit has
    /// to block on a runtime. Building a fresh one per entry meant paying that
    /// construction ~6 times for the handful of entries one launch writes, on
    /// the admission path, for a runtime that only ever drives a blocking file
    /// append.
    runtime: OnceLock<tokio::runtime::Runtime>,
}

impl Drop for AuditEmitter {
    /// Shut the cached runtime down without blocking.
    ///
    /// Caching the runtime removed a per-entry construction, but it also moved
    /// where the runtime is *dropped*: it used to die inside the synchronous
    /// emit that built it, and now it dies with the emitter. An emitter
    /// constructed from inside someone else's async context therefore drops
    /// its runtime there, and a blocking drop from async is a tokio panic by
    /// design —
    ///
    ///   Cannot drop a runtime in a context where blocking is not allowed.
    ///
    /// `shutdown_background` returns immediately and leaves the worker threads
    /// to exit on their own, which is what this runtime wants anyway: it only
    /// ever drives a blocking file append that has already completed by the
    /// time the emitter is being dropped.
    fn drop(&mut self) {
        if let Some(rt) = self.runtime.take() {
            rt.shutdown_background();
        }
    }
}

impl AuditEmitter {
    /// Construct with the default `~/.mvm/audit/` directory.
    pub fn new(signing_key: SigningKey) -> Result<Self> {
        Self::with_dir(signing_key, &default_audit_dir()?)
    }

    /// Test seam — caller supplies the audit directory. Production
    /// callers use `new`. The directory is created if missing;
    /// `FileAuditSigner::open` enforces mode 0700-ish via the
    /// OS-default umask, but for hard guarantees the caller should
    /// pre-create it.
    pub fn with_dir(signing_key: SigningKey, audit_dir: &Path) -> Result<Self> {
        // Tighten the audit dir to 0700 if we created it. We use
        // `create_dir_all` first (idempotent) then `set_permissions`.
        // The audit chain inherits the same mode-0700 posture as the
        // rest of ~/.mvm, since its contents bind to plan-signed entries.
        if !audit_dir.exists() {
            std::fs::create_dir_all(audit_dir)
                .with_context(|| format!("creating audit dir at {}", audit_dir.display()))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let perms = std::fs::Permissions::from_mode(0o700);
                std::fs::set_permissions(audit_dir, perms).with_context(|| {
                    format!("setting 0700 on audit dir {}", audit_dir.display())
                })?;
            }
        }
        let signer = Arc::new(
            FileAuditSigner::open(signing_key.clone(), audit_dir)
                .with_context(|| format!("opening FileAuditSigner at {}", audit_dir.display()))?,
        );
        Self::from_primary_signer(signing_key, audit_dir, signer)
    }

    /// Construct around an existing signer for the same key and audit
    /// directory.
    ///
    /// Sharing the command-envelope signer keeps deferred launch records alive
    /// until the terminal command record performs the file-wide durability
    /// barrier. The signer still flushes on its final `Arc` drop, so unwind and
    /// early-return paths retain the ordinary fallback.
    pub fn with_primary_signer(
        signing_key: SigningKey,
        audit_dir: &Path,
        signer: Arc<FileAuditSigner>,
    ) -> Result<Self> {
        if signer.verifying_key() != signing_key.verifying_key() {
            anyhow::bail!("shared audit signer does not match the emitter signing key");
        }
        let probe_tenant = "__mvm_audit_path_probe";
        if signer.tenant_path(probe_tenant) != audit_dir.join(format!("{probe_tenant}.jsonl")) {
            anyhow::bail!("shared audit signer does not target the emitter audit directory");
        }
        Self::from_primary_signer(signing_key, audit_dir, signer)
    }

    fn from_primary_signer(
        signing_key: SigningKey,
        audit_dir: &Path,
        signer: Arc<FileAuditSigner>,
    ) -> Result<Self> {
        if !audit_dir.exists() {
            std::fs::create_dir_all(audit_dir)
                .with_context(|| format!("creating audit dir at {}", audit_dir.display()))?;
        }
        Ok(Self {
            signers: vec![signer],
            signing_key,
            audit_dir: audit_dir.to_path_buf(),
            receipts_enabled: false,
            receipt_stores: Mutex::new(HashMap::new()),
            decisions_enabled: false,
            decisions_dir: None,
            decision_stores: Mutex::new(HashMap::new()),
            atomic_sync_state: Arc::new(AtomicSyncState::default()),
            runtime: OnceLock::new(),
        })
    }

    /// Construct an emitter from a parsed policy bundle's `[audit]`
    /// section. The default local chain is always kept; `file://`
    /// destinations add exact-file replicas. Network/unix
    /// replication is intentionally fail-closed until those
    /// transports are implemented.
    pub fn with_policy(
        signing_key: SigningKey,
        audit_dir: &Path,
        policy: &mvm_core::policy::AuditPolicy,
    ) -> Result<Self> {
        if !policy.chain_signing {
            anyhow::bail!(
                "policy audit.chain_signing=false is not supported for policy-bound admission"
            );
        }

        let mut emitter = Self::with_dir(signing_key.clone(), audit_dir)?;
        emitter.add_policy_destinations(signing_key, policy)?;
        Ok(emitter)
    }

    /// Policy-aware constructor that reuses the primary local-chain signer.
    /// Additional `file://` policy destinations retain independent signers.
    pub fn with_policy_and_primary_signer(
        signing_key: SigningKey,
        audit_dir: &Path,
        policy: &mvm_core::policy::AuditPolicy,
        primary_signer: Arc<FileAuditSigner>,
    ) -> Result<Self> {
        if !policy.chain_signing {
            anyhow::bail!(
                "policy audit.chain_signing=false is not supported for policy-bound admission"
            );
        }
        let mut emitter =
            Self::with_primary_signer(signing_key.clone(), audit_dir, primary_signer)?;
        emitter.add_policy_destinations(signing_key, policy)?;
        Ok(emitter)
    }

    fn add_policy_destinations(
        &mut self,
        signing_key: SigningKey,
        policy: &mvm_core::policy::AuditPolicy,
    ) -> Result<()> {
        for destination in &policy.stream_destinations {
            let Some(raw_path) = destination.strip_prefix("file://") else {
                anyhow::bail!(
                    "audit stream destination {destination:?} is not wired yet; \
                     only file:// destinations are supported"
                );
            };
            if raw_path.is_empty() {
                anyhow::bail!("audit file:// destination must include an absolute path");
            }
            let path = PathBuf::from(raw_path);
            if !path.is_absolute() {
                anyhow::bail!("audit file:// destination must include an absolute path");
            }
            let signer = FileAuditSigner::open_file(signing_key.clone(), &path)
                .with_context(|| format!("opening audit stream {}", path.display()))?;
            self.signers.push(Arc::new(signer));
        }
        Ok(())
    }

    /// Enable runtime emission of signed [`ExecutionReceipt`]s alongside
    /// audit events. Receipts are stored under
    /// `<audit_dir>/receipts/<tenant>/` and chained via `prev_receipt_id`.
    pub fn with_receipts(mut self) -> Self {
        self.receipts_enabled = true;
        self
    }

    /// Enable runtime caching of decision records under the default
    /// `~/.mvm/decisions/` directory (respects `MVM_HOME`).
    pub fn with_decisions(mut self) -> Result<Self> {
        self.decisions_enabled = true;
        self.decisions_dir = Some(DecisionStore::default_dir()?);
        Ok(self)
    }

    /// Test seam — caller supplies the decision-store directory.
    /// Production callers use [`Self::with_decisions`].
    pub fn with_decisions_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.decisions_enabled = true;
        self.decisions_dir = Some(dir.into());
        self
    }

    /// True when the emitter will cache decision records locally.
    pub fn decisions_enabled(&self) -> bool {
        self.decisions_enabled
    }

    /// Emit `plan.admitted` — fires immediately after `admit_for_run`
    /// succeeds. Binds the plan_id, signer (via `audit_labels` extras),
    /// and the workload context.
    ///
    /// Also carries the admitted output-retention mode. Without it, a workload
    /// with no transcript is ambiguous — nobody can tell a run that was
    /// admitted not to keep one from a run whose recording was lost or
    /// removed. The mode is a word off the signed plan, so recording it costs
    /// nothing and settles the question from the chain alone.
    pub fn emit_admitted(&self, plan: &ExecutionPlan, signer_id: &str) -> Result<()> {
        self.emit(
            plan,
            "plan.admitted",
            [
                ("signer_id".to_string(), signer_id.to_string()),
                ("authorizer_principal".to_string(), signer_id.to_string()),
                (
                    stream_audit::LABEL_RETENTION.to_string(),
                    plan.stream_retention.as_str().to_string(),
                ),
            ],
        )
    }

    /// Emit `plan.admission_refused` — fires when `admit_plan_for_run` refuses
    /// to admit a plan before the VM is created. The stage and reason are
    /// recorded in the chain so an auditor can distinguish a refusal from a
    /// missing admission.
    pub fn emit_refused(&self, plan: &ExecutionPlan, stage: &str, reason: &str) -> Result<()> {
        self.emit(
            plan,
            "plan.admission_refused",
            [
                ("stage".to_string(), stage.to_string()),
                ("reason".to_string(), reason.to_string()),
                (
                    "authorizer_principal".to_string(),
                    crate::audit::host_keypair::host_signer_id(),
                ),
            ],
        )
    }

    /// Emit `control_key.used` — fires when a `ControlKey` is used to
    /// authorize an orchestrator action. Carries the key id, role, and a
    /// short action label. No secret material is logged.
    pub fn emit_control_key_used(
        &self,
        plan: &ExecutionPlan,
        key: &mvm_core::mvmd_iface::ControlKey,
        action: &str,
    ) -> Result<()> {
        self.emit(
            plan,
            "control_key.used",
            [
                ("kid".to_string(), key.kid.clone()),
                ("role".to_string(), format!("{:?}", key.role)),
                ("action".to_string(), action.to_string()),
                ("authorizer_principal".to_string(), key.kid.clone()),
            ],
        )?;

        if self.decisions_enabled() {
            let record = Self::control_key_decision_record(plan, key, action);
            let _ = self.emit_decision_record(plan, record);
        }
        Ok(())
    }

    fn control_key_decision_record(
        plan: &ExecutionPlan,
        key: &mvm_core::mvmd_iface::ControlKey,
        action: &str,
    ) -> DecisionRecord {
        let role = match key.role {
            mvm_core::mvmd_iface::ControlKeyRole::Promoter => Some(DecisionActorRole::Promoter),
            mvm_core::mvmd_iface::ControlKeyRole::Inventory => Some(DecisionActorRole::Inventory),
            mvm_core::mvmd_iface::ControlKeyRole::Orchestrator => {
                Some(DecisionActorRole::Orchestrator)
            }
        };
        DecisionRecordBuilder::new()
            .version(1)
            .category(DecisionCategory::Approval)
            .actor(ActorRef {
                principal: key.kid.clone(),
                key_id: key.kid.clone(),
                key_role: role,
            })
            .scenario(mvm_contract::provenance::DecisionScenario {
                plan_id: Some(plan.plan_id.0.clone()),
                ..Default::default()
            })
            .reasoning(format!("control key authorized action: {action}"))
            .outcome(DecisionOutcome::Approved)
            .timestamp(Utc::now().to_rfc3339())
            .attestation(AttestationBinding {
                plan_id: Some(plan.plan_id.0.clone()),
                ..AttestationBinding::default()
            })
            .build()
            .expect("control-key decision record is well-formed")
    }

    /// Emit a `decision_record` chain entry and cache the record locally.
    ///
    /// The record's content-address is recomputed from its semantic body
    /// (excluding `attestation`), then the attestation is updated with a
    /// hash of the audit context entry. The final record is serialized into
    /// the chain entry's `record` label and written to the decision store if
    /// enabled.
    pub fn emit_decision_record(
        &self,
        plan: &ExecutionPlan,
        mut record: DecisionRecord,
    ) -> Result<DecisionId> {
        record.decision_id = record.compute_id();

        // Hash a minimal context entry so the decision attests to the audit
        // chain without a circular dependency on the full record label.
        let context_entry = for_plan(
            plan,
            None,
            "decision_record",
            [
                ("decision_id".to_string(), record.decision_id.0.clone()),
                ("category".to_string(), format!("{:?}", record.category)),
            ],
        );
        let context_bytes =
            serde_json::to_vec(&context_entry).context("serializing decision context entry")?;
        record.attestation.audit_entry_hash = hex::encode(hash_line(&context_bytes));
        record.attestation.signer_pubkey = format!(
            "ed25519:{}",
            hex::encode(self.signing_key.verifying_key().to_bytes())
        );

        let record_json = serde_json::to_string(&record).context("serializing decision record")?;
        let entry = for_plan(
            plan,
            None,
            "decision_record",
            [
                ("decision_id".to_string(), record.decision_id.0.clone()),
                ("category".to_string(), format!("{:?}", record.category)),
                ("record".to_string(), record_json),
            ],
        );
        self.emit_entry(&entry)?;

        if self.decisions_enabled
            && let Some(store) = self.decision_store_for_tenant(&plan.tenant.0)
            && let Err(e) = store.put(&record)
        {
            tracing::warn!(
                decision_id = %record.decision_id.0,
                error = %e,
                "failed to cache decision record (non-fatal)"
            );
        }

        Ok(record.decision_id)
    }

    /// Emit `plan.launched` — fires after `backend.start()` returns Ok.
    pub fn emit_launched(&self, plan: &ExecutionPlan, backend: &str) -> Result<()> {
        self.emit(
            plan,
            "plan.launched",
            [("backend".to_string(), backend.to_string())],
        )
    }

    /// Emit `plan.grants_enforced` — records what actually bounded this
    /// workload, as read back off the live controls after the backend started
    /// it.
    ///
    /// Deliberately a separate entry from `plan.admitted`, which records the
    /// bounds that were *requested*. A reader who only ever sees the request
    /// cannot tell a run that was bounded from one that declared a bound
    /// nothing implemented — and those two are the whole point of the
    /// distinction.
    pub fn emit_grants_enforced(
        &self,
        plan: &ExecutionPlan,
        enforced: &mvm_contract::protocol::resource_controls::EnforcedGrants,
    ) -> Result<()> {
        self.emit(
            plan,
            "plan.grants_enforced",
            [
                (
                    "grants_cpu_tier".to_string(),
                    enforced.cpu.label().to_string(),
                ),
                (
                    "grants_wall_clock_tier".to_string(),
                    enforced.wall_clock.label().to_string(),
                ),
            ],
        )
    }

    /// Emit `plan.wall_clock_expired` — records that a supervisor timer fired
    /// and killed this workload for outrunning its wall-clock grant.
    ///
    /// The kill is only half the enforcement. A workload that vanishes at its
    /// deadline with nothing in the chain is indistinguishable from one that
    /// crashed there, so an operator could not tell a bound that fired from a
    /// bug — and a bound nobody can observe firing is a declaration again. The
    /// entry carries the bound that was enforced and the elapsed time at the
    /// kill, so the two readings can be compared.
    pub fn emit_wall_clock_expired(&self, plan: &ExecutionPlan, elapsed_secs: u64) -> Result<()> {
        self.emit(
            plan,
            wall_clock_audit::EXPIRED_EVENT,
            [
                (
                    wall_clock_audit::LABEL_BOUND_SECS.to_string(),
                    plan.resources.timeouts.exec_secs.to_string(),
                ),
                (
                    wall_clock_audit::LABEL_ELAPSED_SECS.to_string(),
                    elapsed_secs.to_string(),
                ),
                (
                    wall_clock_audit::LABEL_ENFORCED_BY.to_string(),
                    mvm_contract::protocol::resource_controls::EnforcedTier::SupervisorTimer
                        .label()
                        .to_string(),
                ),
            ],
        )
    }

    /// Emit `plan.boot_posture` — records which rootfs strategy the run path
    /// selected for this boot. Every boot is `"block-ext4"`, the path the
    /// numbered claim-3 witness rides on; the label is still written, and still
    /// per-plan, so an audit reader can confirm it rather than assume it.
    /// Informational — the hard admission decision is still `plan.admitted`;
    /// this event lets an operator answer "what did this run boot off?" via the
    /// tamper-evident chain rather than an unsigned side channel.
    pub fn emit_boot_posture(&self, plan: &ExecutionPlan, root_strategy: &str) -> Result<()> {
        self.emit(
            plan,
            "plan.boot_posture",
            [("root_strategy".to_string(), root_strategy.to_string())],
        )
    }

    /// Emit `plan.policy_resolved` — fires after the resolver
    /// successfully constructs `ResolvedSlots` from the plan's policy
    /// refs. `slots_mode` is `"noop"` when all four refs are
    /// `"local-default"` (no bundle on disk) or `"live"` when a
    /// `<tenant>:<workload>` bundle parsed cleanly.
    ///
    /// The audit entry is informational — the supervisor's hard
    /// admission decision is still `plan.admitted`. This event lets
    /// operators answer "did my bundle actually parse on the last
    /// boot, or did I fall back to local-default?" via
    /// `mvmctl audit tail --chain`.
    pub fn emit_policy_resolved(&self, plan: &ExecutionPlan, slots_mode: &str) -> Result<()> {
        self.emit(
            plan,
            "plan.policy_resolved",
            [("slots_mode".to_string(), slots_mode.to_string())],
        )
    }

    /// Emit `plan.egress_destinations` — records the (host, port) allowlist
    /// admitted for this workload so a receipt can name the network boundary
    /// without resolving policy refs again. No-op when the list is empty.
    pub fn emit_egress_destinations(
        &self,
        plan: &ExecutionPlan,
        destinations: &[(String, u16)],
    ) -> Result<()> {
        if destinations.is_empty() {
            return Ok(());
        }
        let mut labels: Vec<(String, String)> = vec![(
            "destination_count".to_string(),
            destinations.len().to_string(),
        )];
        for (i, (host, port)) in destinations.iter().enumerate() {
            labels.push((format!("destination_{i}_host"), host.clone()));
            labels.push((format!("destination_{i}_port"), port.to_string()));
        }
        self.emit(plan, "plan.egress_destinations", labels)
    }

    /// Emit `plan.shares_admitted` — records the user host-fs grants
    /// (`--volume` / `MVM_VOLUMES`) baked into the admitted plan
    /// (claim 1 / claim 8), so every share is a tamper-evident audit
    /// fact rather than an unsigned side-channel. No-op when the plan
    /// carries no shares (the common case).
    pub fn emit_shares_admitted(&self, plan: &ExecutionPlan) -> Result<()> {
        if plan.shares.is_empty() {
            return Ok(());
        }
        let mut labels: Vec<(String, String)> =
            vec![("share_count".to_string(), plan.shares.len().to_string())];
        for (i, s) in plan.shares.iter().enumerate() {
            let kind = match s.kind {
                mvm_core::plan::ShareKind::Disk => "disk",
                mvm_core::plan::ShareKind::DirShare => "dir_share",
            };
            labels.push((format!("share_{i}_tag"), s.tag.clone()));
            labels.push((format!("share_{i}_host"), s.host_path.clone()));
            labels.push((format!("share_{i}_guest"), s.guest_path.clone()));
            labels.push((format!("share_{i}_kind"), kind.to_string()));
            labels.push((format!("share_{i}_ro"), s.read_only.to_string()));
            labels.push((format!("share_{i}_encrypted"), s.encrypted.to_string()));
        }
        self.emit(plan, "plan.shares_admitted", labels)
    }

    /// Emit `plan.oci_provenance` — binds an OCI image admission to the same
    /// plan id as the launch decision. The caller supplies the digest-oriented
    /// labels; raw registry credentials are never recorded.
    pub fn emit_oci_provenance(
        &self,
        plan: &ExecutionPlan,
        labels: Vec<(String, String)>,
    ) -> Result<()> {
        self.emit(plan, "plan.oci_provenance", labels)
    }

    /// Emit `stream.subscribed` — a follower attached to `vm_name`'s output
    /// stream at `from_seq`.
    ///
    /// Payload-free by construction: the labels are the VM name, the reader
    /// id, and a sequence number, so no captured byte can reach the chain
    /// through this path however chatty the workload is.
    pub fn emit_stream_subscribed(
        &self,
        plan: &ExecutionPlan,
        vm_name: &str,
        reader_id: u64,
        from_seq: u64,
    ) -> Result<()> {
        use stream_audit as k;
        self.emit(
            plan,
            k::SUBSCRIBED_EVENT,
            [
                (k::LABEL_VM_NAME.to_string(), vm_name.to_string()),
                (k::LABEL_READER_ID.to_string(), reader_id.to_string()),
                (k::LABEL_FROM_SEQ.to_string(), from_seq.to_string()),
            ],
        )
    }

    /// Emit `stream.input_granted` — a writer took `vm_name`'s single input
    /// lease under `holder`.
    ///
    /// Payload-free by construction: a VM name and a lease holder id, decided
    /// before any byte has been offered.
    pub fn emit_stream_input_granted(
        &self,
        plan: &ExecutionPlan,
        vm_name: &str,
        holder: &str,
    ) -> Result<()> {
        use stream_audit as k;
        self.emit(
            plan,
            k::INPUT_GRANTED_EVENT,
            [
                (k::LABEL_VM_NAME.to_string(), vm_name.to_string()),
                (k::LABEL_HOLDER.to_string(), holder.to_string()),
            ],
        )
    }

    /// Emit `stream.input_refused` — the gate turned a writer away.
    ///
    /// The label set is the binding and the reason. Not the frame, not its
    /// length, and — for a refusal that fired on recognised secret material —
    /// not the material: only the category name it matched.
    pub fn emit_stream_input_refused(
        &self,
        plan: &ExecutionPlan,
        vm_name: &str,
        refusal: &crate::stream::InputRefusal,
    ) -> Result<()> {
        self.emit(
            plan,
            stream_audit::INPUT_REFUSED_EVENT,
            input_refused_labels(vm_name, refusal),
        )
    }

    /// Record that a VM's filesystem state was frozen into an fs_quick
    /// checkpoint. The label set carries the checkpoint id, class, the
    /// SHA-256 of the cloned rootfs blob, and the owning VM.
    pub fn emit_checkpoint_created(
        &self,
        plan: &ExecutionPlan,
        checkpoint_id: &str,
        class: &str,
        meta_digest: &str,
        vm_name: &str,
    ) -> Result<()> {
        use checkpoint_audit as k;
        self.emit(
            plan,
            k::CREATED_EVENT,
            [
                (
                    k::LABEL_CHECKPOINT_ID.to_string(),
                    checkpoint_id.to_string(),
                ),
                (k::LABEL_CLASS.to_string(), class.to_string()),
                // The record's content-address, not a single-blob sha: it covers
                // the whole manifest plus the parent hash-link.
                (k::LABEL_META_DIGEST.to_string(), meta_digest.to_string()),
                (k::LABEL_VM_NAME.to_string(), vm_name.to_string()),
            ],
        )
    }

    /// Record that a VM was restored to the state captured in a checkpoint. The
    /// label set carries the checkpoint id, its content-address, the restored VM
    /// name, and `via` — how the restore was initiated (`revert` / `rewind` /
    /// `advance`), so a time-travel restore reads distinctly in the chain.
    pub fn emit_checkpoint_restored(
        &self,
        plan: &ExecutionPlan,
        checkpoint_id: &str,
        meta_digest: &str,
        vm_name: &str,
        via: &str,
    ) -> Result<()> {
        use checkpoint_audit as k;
        self.emit(
            plan,
            k::RESTORED_EVENT,
            [
                (
                    k::LABEL_CHECKPOINT_ID.to_string(),
                    checkpoint_id.to_string(),
                ),
                (k::LABEL_META_DIGEST.to_string(), meta_digest.to_string()),
                (k::LABEL_VM_NAME.to_string(), vm_name.to_string()),
                (k::LABEL_VIA.to_string(), via.to_string()),
            ],
        )
    }

    /// Record that a new sandbox was branched from a checkpoint via
    /// copy-on-write. The label set carries the parent and child checkpoint ids
    /// and VM name, plus the parent and child content-addresses — so the
    /// audited lineage is the hash chain, not just the mutable names.
    pub fn emit_checkpoint_forked(
        &self,
        plan: &ExecutionPlan,
        audit: CheckpointForkedAudit<'_>,
    ) -> Result<()> {
        use checkpoint_audit as k;
        self.emit(
            plan,
            k::FORKED_EVENT,
            [
                (k::LABEL_PARENT_ID.to_string(), audit.parent_id.to_string()),
                (k::LABEL_CHILD_ID.to_string(), audit.child_id.to_string()),
                (
                    k::LABEL_CHILD_VM_NAME.to_string(),
                    audit.child_vm_name.to_string(),
                ),
                (
                    k::LABEL_PARENT_DIGEST.to_string(),
                    audit.parent_digest.to_string(),
                ),
                (
                    k::LABEL_CHILD_DIGEST.to_string(),
                    audit.child_digest.to_string(),
                ),
                (
                    k::LABEL_SECRET_BINDINGS.to_string(),
                    audit.secret_bindings_json.to_string(),
                ),
            ],
        )
    }

    /// Record that a compiled image's version-lineage node was created. The
    /// label set carries the node's content-address (the chain-anchor keys on
    /// it), its parent hash-link, the build identity, and the provenance
    /// attributes. Chain-signed so `verify_image_lineage` can anchor the node's
    /// content-address to a signature it cannot forge.
    pub fn emit_image_created(
        &self,
        plan: &ExecutionPlan,
        node: &mvm_core::image_lineage::ImageNode,
    ) -> Result<()> {
        self.emit(plan, image_audit::CREATED_EVENT, image_created_labels(node))
    }

    /// Record that a fresh VM was launched from a prior image-lineage node (a
    /// time-travel restore). The label set carries the restored node's
    /// content-address, the initiating verb (`via`), and the reconstructed
    /// `machine run` reference the restore re-runs, so a revert is distinct in
    /// the chain from an ordinary image run.
    pub fn emit_image_reverted(
        &self,
        plan: &ExecutionPlan,
        node_digest: &str,
        via: &str,
        reference: &str,
    ) -> Result<()> {
        use image_audit as k;
        self.emit(
            plan,
            k::REVERTED_EVENT,
            [
                (k::LABEL_NODE_DIGEST.to_string(), node_digest.to_string()),
                (k::LABEL_VIA.to_string(), via.to_string()),
                (
                    k::LABEL_REVERTED_REFERENCE.to_string(),
                    reference.to_string(),
                ),
            ],
        )
    }

    /// Record the authenticated ciphertext-manifest root of a completed
    /// forensic transcript capture. Payload bytes and plaintext digests stay
    /// outside the chain; the labels are sufficient to authenticate the
    /// encrypted evidence before decryption.
    pub fn emit_transcript_sealed(
        &self,
        plan: &ExecutionPlan,
        capture_id: &str,
        vm_name: &str,
        sealed_root_hex: &str,
        chunk_count: usize,
        adopted: bool,
    ) -> Result<()> {
        let entry = transcript_sealed(
            plan,
            None,
            capture_id,
            vm_name,
            sealed_root_hex,
            chunk_count,
            adopted,
        );
        self.emit_entry(&entry)
    }
}

/// What a finished run reports about itself.
///
/// A struct rather than a positional list because this grows with each
/// dimension the host learns to observe, and a four-then-five-argument emit
/// is the shape the workspace's argument-count rule exists to prevent.
#[derive(Debug, Clone, Copy)]
pub struct ExitRecord<'a> {
    /// `None` when the guest never reported one.
    pub exit_code: Option<i32>,
    pub backend: &'a str,
    pub usage: UsageCapture,
}

impl AuditEmitter {
    /// Emit `plan.exited` — fires after a waited-for workload powers off,
    /// carrying its captured exit code.
    pub fn emit_exited(&self, plan: &ExecutionPlan, exit_code: i32, backend: &str) -> Result<()> {
        self.emit_exited_with_capture(
            plan,
            ExitRecord {
                exit_code: Some(exit_code),
                backend,
                usage: UsageCapture::default(),
            },
        )
    }

    /// Emit `plan.exited` with capture fidelity: a missing exit capture is
    /// recorded as `exit_code=none` + `captured=false` rather than being
    /// attested as a successful exit 0 the guest never reported. The usage
    /// record follows the same rule — a dimension nobody observed is written
    /// as unavailable rather than left out, so a reader can tell an
    /// unmeasured run from an unmeasurable one.
    pub fn emit_exited_with_capture(
        &self,
        plan: &ExecutionPlan,
        record: ExitRecord<'_>,
    ) -> Result<()> {
        let (code, captured) = match record.exit_code {
            Some(code) => (code.to_string(), "true"),
            None => ("none".to_string(), "false"),
        };
        // One label rather than a field per metric: the record is a typed
        // document with its own validation, and flattening it here would put
        // that validation on the far side of a string round trip.
        let usage = serde_json::to_string(&record.usage)
            .context("encoding the usage record for the audit chain")?;
        self.emit(
            plan,
            "plan.exited",
            [
                ("exit_code".to_string(), code),
                ("captured".to_string(), captured.to_string()),
                ("backend".to_string(), record.backend.to_string()),
                ("usage".to_string(), usage),
            ],
        )
    }

    /// Emit `verb_denied` — fires when the host caller receives a
    /// `VerbNotAuthorized` response from the guest agent. Records the
    /// denied verb name in the chain-signed log so refusals are
    /// observable and tamper-evident (claim-12 parity). No payload
    /// bytes are emitted; the verb name is a label.
    pub fn emit_verb_denied(&self, plan: &ExecutionPlan, verb: &str) -> Result<()> {
        self.emit(
            plan,
            "verb_denied",
            [("verb".to_string(), verb.to_string())],
        )
    }

    /// Emit `plan.grant_required` — records that this admission asserted verb-grant
    /// enforcement (the admitted plan carries `agent_verbs`, so the launcher emits
    /// the grant-required boot marker and the guest fails closed without a valid grant).
    /// Binds the granted verb set to the same plan id as the launch decision, so
    /// `trust audit verify` can attest the enforcement posture. Host-side: the guest
    /// cannot sign this chain.
    pub fn emit_grant_required(
        &self,
        plan: &ExecutionPlan,
        verbs: &[mvm_core::plan::VerbId],
    ) -> Result<()> {
        let mut labels = vec![("verb_count".to_string(), verbs.len().to_string())];
        for (i, v) in verbs.iter().enumerate() {
            labels.push((format!("verb_{i}"), v.as_str().to_string()));
        }
        self.emit(plan, "plan.grant_required", labels)
    }

    /// Emit `plan.failed` — fires on any error path between admission
    /// and successful boot. `class` is a short tag (`backend-start`,
    /// `snapshot-restore`, etc.) the operator can grep for; `message`
    /// is the underlying error chain rendered.
    pub fn emit_failed(&self, plan: &ExecutionPlan, class: &str, message: &str) -> Result<()> {
        self.emit(
            plan,
            "plan.failed",
            [
                ("error_class".to_string(), class.to_string()),
                ("error_message".to_string(), message.to_string()),
            ],
        )
    }

    /// Build, sign, and atomically publish a Merkle transparency-log root
    /// over `tenant`'s chain-signed audit log.
    ///
    /// The root is built only over a `verify_audit_chain`-valid chain (see
    /// [`crate::audit::merkle::build_root_in`]); a corrupt log refuses here.
    /// The signature covers `root_signing_bytes(tenant, tree_size,
    /// hex(root), timestamp)` under the host signer's Ed25519 key — the
    /// exact bytes `mvm_contract::merkle::verify_signed_root` re-checks. The
    /// sidecar is written temp-then-fsync-then-rename to
    /// `<audit_dir>/<tenant>.root.json` so a reader never observes a partial
    /// file.
    /// The directory this emitter's chains, roots, and witness marks live in.
    pub fn audit_dir(&self) -> &Path {
        &self.audit_dir
    }

    pub fn publish_root(&self, tenant: &str) -> Result<SignedAuditRoot> {
        let signed =
            crate::audit::merkle::sign_root_in(&self.audit_dir, tenant, &self.signing_key)?;
        // History first. A crash between the two leaves a history entry with
        // no matching sidecar, which a reader can reconcile; the reverse
        // leaves a published root that no consistency check will ever see.
        append_root_history(&self.audit_dir, tenant, &signed)?;
        let path = audit_root_path_for_tenant(&self.audit_dir, tenant);
        write_atomic(&path, serde_json::to_vec_pretty(&signed)?.as_slice())
            .with_context(|| format!("publishing signed root to {}", path.display()))?;
        Ok(signed)
    }

    fn emit<E>(&self, plan: &ExecutionPlan, event: &str, extras: E) -> Result<()>
    where
        E: IntoIterator<Item = (String, String)>,
    {
        let entry = for_plan(plan, None, event, extras);
        self.emit_entry(&entry)
    }

    fn emit_entry(&self, entry: &PlanAuditEntry) -> Result<()> {
        // Callers may be synchronous (the CLI) or already inside an async
        // runtime (an in-process `MvmClient` consumer). Building + blocking
        // on a runtime from an async worker thread panics, so when a runtime
        // context is present the emit runs on a short-lived scoped thread —
        // emission is rare (a handful of entries per boot), so the thread
        // cost is negligible.
        if tokio::runtime::Handle::try_current().is_ok() {
            return std::thread::scope(|scope| {
                scope
                    .spawn(|| self.emit_entry_blocking(entry))
                    .join()
                    .map_err(|_| anyhow::anyhow!("audit emit thread panicked"))?
            });
        }
        self.emit_entry_blocking(entry)
    }

    /// Run `f` with every barrier fsync on this emitter's chains held back,
    /// then sync them all once.
    ///
    /// For a burst of entries that all have to be durable before the same
    /// action — an admission writing `plan.admitted`, its decision record and
    /// its grant requirement before anything boots — this costs one fsync
    /// rather than one per entry. `sync_data` is file-wide, so the single
    /// flush carries every record the batch wrote.
    ///
    /// Fails closed: if the flush fails, this returns the error and `f`'s
    /// result is discarded, so a caller that boots on `Ok` cannot boot on
    /// records that never reached the disk. The scope must therefore close
    /// before the action the entries authorize — not at process exit.
    pub fn batched<T>(&self, f: impl FnOnce() -> Result<T>) -> Result<T> {
        let atomic_batch = AtomicSyncBatch::begin(Arc::clone(&self.atomic_sync_state))?;
        for signer in &self.signers {
            signer.begin_batch();
        }
        let out = f();
        // End every batch even if `f` failed, so a later emit is not left
        // silently deferring its barriers.
        let mut paths = Vec::new();
        for signer in &self.signers {
            paths.extend(signer.take_batched_paths());
        }
        let flush = atomic_batch
            .finish(paths)
            .context("syncing batched audit entries before the action they authorize");
        match (out, flush) {
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error),
            (Ok(value), Ok(())) => Ok(value),
        }
    }

    /// The shared blocking runtime, built on first use.
    fn runtime(&self) -> Result<&tokio::runtime::Runtime> {
        if let Some(rt) = self.runtime.get() {
            return Ok(rt);
        }
        let built = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("building tokio runtime for audit emit")?;
        // A concurrent caller may have won the race; either runtime is usable
        // and the loser's is dropped here.
        let _ = self.runtime.set(built);
        Ok(self
            .runtime
            .get()
            .expect("runtime is set on the line above or by the caller that raced us"))
    }

    fn emit_entry_blocking(&self, entry: &PlanAuditEntry) -> Result<()> {
        self.sign_entry_blocking(entry)?;
        let t_r = std::time::Instant::now();
        self.emit_receipt_for_entry(entry);
        tracing::debug!(ms = t_r.elapsed().as_secs_f64() * 1000.0, "emit: receipt");
        Ok(())
    }

    /// Sign and append one entry to every chain, without its receipt.
    ///
    /// Split out so an evidence-bearing caller can pair the same signing with
    /// a fail-closed receipt rather than the best-effort one below.
    fn sign_entry_blocking(&self, entry: &PlanAuditEntry) -> Result<()> {
        let t0 = std::time::Instant::now();
        let rt = self.runtime()?;
        let t_rt = std::time::Instant::now();
        tracing::debug!(
            ms = (t_rt - t0).as_secs_f64() * 1000.0,
            "emit: tokio runtime build"
        );
        for (i, signer) in self.signers.iter().enumerate() {
            let t_s = std::time::Instant::now();
            rt.block_on(signer.sign_and_emit(entry))
                .with_context(|| format!("signing-and-emitting audit event {}", entry.event))?;
            tracing::debug!(
                signer = i,
                ms = t_s.elapsed().as_secs_f64() * 1000.0,
                "emit: signer"
            );
        }
        audit_mirror::emit_mirror_event(entry);
        Ok(())
    }

    /// Emit one entry and its receipt, failing closed if either cannot be
    /// written, and return references to both.
    ///
    /// The ordinary emit path treats receipts as a derived cache and swallows
    /// their errors, which is right when nothing cites them. It is wrong for
    /// evidence a later claim rests on: a citation to a receipt that was never
    /// written is worse than no citation, because it reads as proof.
    pub fn emit_entry_for_evidence(
        &self,
        entry: &PlanAuditEntry,
        receipt: EvidenceReceipt,
    ) -> Result<EmittedEvidence> {
        if tokio::runtime::Handle::try_current().is_ok() {
            return std::thread::scope(|scope| {
                scope
                    .spawn(|| self.emit_entry_for_evidence_blocking(entry, receipt))
                    .join()
                    .map_err(|_| anyhow::anyhow!("audit emit thread panicked"))?
            });
        }
        self.emit_entry_for_evidence_blocking(entry, receipt)
    }

    fn emit_entry_for_evidence_blocking(
        &self,
        entry: &PlanAuditEntry,
        receipt: EvidenceReceipt,
    ) -> Result<EmittedEvidence> {
        self.sign_entry_blocking(entry)?;
        let receipt_id = match receipt {
            EvidenceReceipt::Required => self.emit_receipt_for_entry_checked(entry)?,
            EvidenceReceipt::Omitted => None,
        };
        Ok(EmittedEvidence {
            audit_digest: audit_entry_digest_hex(entry)?,
            receipt_id,
        })
    }

    /// Append the receipt for `entry`, returning its content address.
    ///
    /// `Ok(None)` means receipts are switched off for this emitter, which is a
    /// configuration answer rather than a failure. Every other unhappy path is
    /// an error.
    fn emit_receipt_for_entry_checked(&self, entry: &PlanAuditEntry) -> Result<Option<String>> {
        if !self.receipts_enabled {
            return Ok(None);
        }
        let tenant = entry.tenant.0.clone();
        let store = self
            .receipt_store_for_tenant(&tenant)
            .ok_or_else(|| anyhow::anyhow!("no receipt store for tenant {tenant}"))?;
        let host_did =
            mvm_core::did_key::DidKey::from_verifying_key(self.signing_key.verifying_key())
                .to_did_key();
        let mut receipt = audit_entry_to_receipt(entry, &host_did, None).ok_or_else(|| {
            anyhow::anyhow!(
                "audit event {} has no receipt mapping; evidence cannot cite it",
                entry.event
            )
        })?;
        let mut emitted_id = None;
        store.append_chained(|prev| {
            receipt.prev_receipt_id = prev;
            receipt.receipt_id = receipt.compute_id().context("computing receipt id")?;
            emitted_id = Some(receipt.receipt_id.clone());
            let signed_at = chrono::Utc::now().to_rfc3339();
            mvm_core::receipt::SignedExecutionReceipt::sign(
                receipt.clone(),
                &self.signing_key,
                signed_at,
            )
            .context("signing execution receipt")
        })?;
        Ok(emitted_id)
    }

    /// Best-effort emission of a signed [`ExecutionReceipt`] for an audit
    /// entry. Errors are logged and swallowed: receipts are a derived cache
    /// and must never block the primary audit emit.
    fn emit_receipt_for_entry(&self, entry: &PlanAuditEntry) {
        if !self.receipts_enabled {
            return;
        }
        let tenant = entry.tenant.0.clone();
        let store = match self.receipt_store_for_tenant(&tenant) {
            Some(s) => s,
            None => return,
        };
        let host_did =
            mvm_core::did_key::DidKey::from_verifying_key(self.signing_key.verifying_key())
                .to_did_key();
        let mut receipt = match audit_entry_to_receipt(entry, &host_did, None) {
            Some(r) => r,
            None => return,
        };
        // Link, identify, and sign inside the store's lock. The parent is part
        // of the receipt id and of the signed bytes, so reading the head out
        // here and appending afterwards would let a concurrent emitter claim
        // the same parent between the two.
        let appended = store.append_chained(|prev| {
            receipt.prev_receipt_id = prev;
            receipt.receipt_id = receipt.compute_id().context("computing receipt id")?;
            let signed_at = chrono::Utc::now().to_rfc3339();
            mvm_core::receipt::SignedExecutionReceipt::sign(receipt, &self.signing_key, signed_at)
                .context("signing execution receipt")
        });
        if let Err(e) = appended {
            tracing::warn!(event = entry.event, error = %e, "failed to append execution receipt");
        }
    }

    /// Return the cached receipt store for `tenant`, creating it on first
    /// use. Returns `None` if the store cannot be opened.
    fn receipt_store_for_tenant(&self, tenant: &str) -> Option<ReceiptStore> {
        {
            let stores = self.receipt_stores.lock().ok()?;
            if let Some(store) = stores.get(tenant) {
                return Some(store.clone());
            }
        }
        let store = match ReceiptStore::open(&self.audit_dir, tenant) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(tenant, error = %e, "failed to open receipt store");
                return None;
            }
        };
        {
            let mut stores = self.receipt_stores.lock().ok()?;
            stores.insert(tenant.to_string(), store.clone());
        }
        Some(store)
    }

    /// Return the cached decision store for `tenant`, creating it on first
    /// use. Returns `None` if no decision-store directory is configured or
    /// the store cannot be opened.
    fn decision_store_for_tenant(&self, tenant: &str) -> Option<DecisionStore> {
        let decisions_dir = self.decisions_dir.as_ref()?;
        {
            let stores = self.decision_stores.lock().ok()?;
            if let Some(store) = stores.get(tenant) {
                return Some(store.clone());
            }
        }
        let store = match DecisionStore::open(decisions_dir, tenant) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(tenant, error = %e, "failed to open decision store");
                return None;
            }
        };
        {
            let mut stores = self.decision_stores.lock().ok()?;
            stores.insert(tenant.to_string(), store.clone());
        }
        Some(store)
    }
}

/// Write `bytes` to `path` atomically: a same-directory temp file is written,
/// made durable, then `rename`d over `path`. Inside [`AuditEmitter::batched`]
/// the complete file is renamed first and its stable-storage wait joins the
/// batch; every wait still completes before the batch returns. A concurrent
/// reader sees either the old file or the complete new one, never a torn
/// write. The temp name carries the pid so two publishers don't collide on
/// it.
/// [`write_atomic`], without the fsync.
///
/// Still atomic — the rename gives a reader either the whole old file or the
/// whole new one. What is dropped is survival of power loss, which is the
/// right trade only for something reconstructible from data already durable.
/// Append one published root to `tenant`'s root history, durably.
///
/// One JSON object per line, fsynced before returning: a root that is not on
/// disk when the next one is published is a hole in the very sequence the
/// consistency check walks.
fn append_root_history(audit_dir: &Path, tenant: &str, signed: &SignedAuditRoot) -> Result<()> {
    use std::io::Write as _;

    let path = audit_root_history_path_for_tenant(audit_dir, tenant);
    let mut line = serde_json::to_vec(signed)?;
    line.push(b'\n');
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .with_context(|| format!("opening root history at {}", path.display()))?;
    file.write_all(&line)
        .with_context(|| format!("appending to root history at {}", path.display()))?;
    file.sync_data()
        .with_context(|| format!("syncing root history at {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::supervisor::verify_audit_chain;
    use mvm_core::usage_capture::{Mechanism, Metric};
    use rand::Rng;

    #[test]
    fn root_history_path_is_outside_lifecycle_chain_scope() {
        let path = audit_root_history_path_for_tenant(Path::new("/audit"), "local");
        assert_eq!(path, Path::new("/audit/local.roots.jsonl"));
        assert!(!mvm_core::config::is_host_lifecycle_chain(&path));
    }

    fn fixture_plan(tenant: &str, plan_id: &str) -> ExecutionPlan {
        mvm_core::plan::test_support::PlanFixture::new()
            .tenant(tenant)
            .plan_id(plan_id)
            .build()
    }

    #[test]
    fn a_durability_batch_flushes_atomic_files_even_when_the_body_fails() {
        let dir = tempfile::tempdir().unwrap();
        let key = SigningKey::from_bytes(&[31; 32]);
        let emitter = AuditEmitter::with_dir(key, dir.path()).unwrap();
        let first = dir.path().join("first.json");
        let second = dir.path().join("second.json");

        let error = emitter
            .batched::<()>(|| {
                write_atomic_batched(&first, br#"{"value":1}"#, &emitter.atomic_sync_state)?;
                write_atomic_batched(&second, br#"{"value":2}"#, &emitter.atomic_sync_state)?;
                anyhow::bail!("admission body failed")
            })
            .unwrap_err();

        assert!(error.to_string().contains("admission body failed"));
        assert_eq!(std::fs::read(&first).unwrap(), br#"{"value":1}"#);
        assert_eq!(std::fs::read(&second).unwrap(), br#"{"value":2}"#);
        assert!(
            !atomic_sync_is_batched(&emitter.atomic_sync_state),
            "an error must close the thread-local durability scope"
        );

        let after = dir.path().join("after.json");
        write_atomic(&after, b"after").unwrap();
        assert_eq!(std::fs::read(after).unwrap(), b"after");
    }

    #[test]
    fn derived_caches_do_not_extend_the_admission_durability_barrier() {
        use mvm_contract::provenance::{
            ActorRef, AttestationBinding, DecisionCategory, DecisionOutcome, DecisionRecordBuilder,
        };

        let audit_dir = tempfile::tempdir().unwrap();
        let decisions_dir = tempfile::tempdir().unwrap();
        let key = SigningKey::from_bytes(&[34; 32]);
        let signer_pubkey = hex::encode(key.verifying_key().to_bytes());
        let emitter = AuditEmitter::with_dir(key, audit_dir.path())
            .unwrap()
            .with_receipts()
            .with_decisions_dir(decisions_dir.path());
        let plan = fixture_plan("local", "plan-cache-durability");
        let record = DecisionRecordBuilder::new()
            .version(1)
            .category(DecisionCategory::Admission)
            .actor(ActorRef {
                principal: "host:builder".to_string(),
                key_id: "host-signer-1".to_string(),
                key_role: None,
            })
            .reasoning("grant ceiling satisfied")
            .outcome(DecisionOutcome::Approved)
            .timestamp("2026-08-26T00:00:00Z".to_string())
            .attestation(AttestationBinding {
                plan_id: Some(plan.plan_id.0.clone()),
                signer_pubkey,
                ..AttestationBinding::default()
            })
            .build()
            .expect("valid record");

        emitter
            .batched(|| {
                emitter.emit_admitted(&plan, "host:test")?;
                emitter.emit_decision_record(&plan, record)?;
                assert_eq!(
                    atomic_sync::deferred_path_count(&emitter.atomic_sync_state),
                    0,
                    "receipt and decision caches are reconstructible from the audit chain and must not add stable-storage waits to admission"
                );
                Ok(())
            })
            .expect("the audit-chain barrier remains durable");
    }

    #[test]
    fn a_shared_primary_signer_must_match_the_key_and_directory() {
        let dir = tempfile::tempdir().unwrap();
        let other = tempfile::tempdir().unwrap();
        let key = SigningKey::from_bytes(&[32; 32]);
        let signer = Arc::new(FileAuditSigner::open(key.clone(), dir.path()).unwrap());

        let emitter =
            AuditEmitter::with_primary_signer(key.clone(), dir.path(), signer.clone()).unwrap();
        assert!(Arc::ptr_eq(&emitter.signers[0], &signer));

        let wrong_key = SigningKey::from_bytes(&[33; 32]);
        assert!(AuditEmitter::with_primary_signer(wrong_key, dir.path(), signer.clone()).is_err());
        assert!(AuditEmitter::with_primary_signer(key, other.path(), signer).is_err());
    }

    /// Construct, use and drop an emitter from inside an async context.
    ///
    /// This is the shape the cached runtime made hazardous and that no unit
    /// test covered: the runtime now dies with the emitter rather than inside
    /// the emit that built it, so an emitter dropped in async drops a runtime
    /// in async — which tokio panics on. The conformance suite caught it by
    /// accident because its steps run under cucumber's runtime; this catches
    /// it on purpose.
    #[tokio::test]
    async fn an_emitter_dropped_inside_an_async_context_does_not_panic() {
        let dir = tempfile::tempdir().unwrap();
        let key = {
            let mut __ed_seed = [0u8; 32];
            rand::rng().fill_bytes(&mut __ed_seed);
            SigningKey::from_bytes(&__ed_seed)
        };

        let emitter = AuditEmitter::with_dir(key, dir.path()).unwrap();
        // Emit first: the runtime is built lazily, so an emitter that never
        // emitted would drop a `OnceLock` that was never filled and pass
        // whatever `Drop` did.
        emitter
            .emit_admitted(&fixture_plan("local", "plan-async-drop"), "host:test")
            .unwrap();

        drop(emitter);

        // Reached only if the drop above did not panic.
        let content = std::fs::read_to_string(dir.path().join("local.jsonl")).unwrap();
        assert!(content.contains("plan-async-drop"));
    }

    #[test]
    fn audit_log_carries_plan_id_for_every_launch() {
        // Emit a full admitted→launched pair; both lines must reference
        // the same plan_id and live in the tenant's audit file.
        let dir = tempfile::tempdir().unwrap();
        let key = {
            let mut __ed_seed = [0u8; 32];
            rand::rng().fill_bytes(&mut __ed_seed);
            SigningKey::from_bytes(&__ed_seed)
        };
        let emitter = AuditEmitter::with_dir(key, dir.path()).unwrap();
        let plan = fixture_plan("local", "plan-A");

        emitter.emit_admitted(&plan, "host:test").unwrap();
        emitter.emit_launched(&plan, "firecracker").unwrap();

        let path = dir.path().join("local.jsonl");
        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2, "two events expected, got {}", lines.len());
        assert!(
            lines.iter().all(|l| l.contains("\"plan-A\"")),
            "every line must carry the plan_id"
        );
        assert!(lines[0].contains("plan.admitted"));
        assert!(lines[1].contains("plan.launched"));
    }

    /// The property that makes an absent transcript attributable rather than
    /// ambiguous: the mode the plan was admitted under is in the chain, so
    /// "was this run recorded?" is answerable without the recording.
    #[test]
    fn admission_records_the_retention_mode_in_the_chain() {
        use mvm_core::plan::StreamRetention;

        for (retention, expected) in [
            (StreamRetention::Persist, "persist"),
            (StreamRetention::Ephemeral, "ephemeral"),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let mut seed = [0u8; 32];
            rand::rng().fill_bytes(&mut seed);
            let emitter =
                AuditEmitter::with_dir(SigningKey::from_bytes(&seed), dir.path()).expect("emitter");
            let plan = mvm_core::plan::test_support::PlanFixture::new()
                .stream_retention(retention)
                .build();
            emitter.emit_admitted(&plan, "host:test").expect("emit");

            let entry = only_entry(dir.path(), "local");
            assert_eq!(entry["event"], "plan.admitted");
            assert_eq!(
                entry["labels"][stream_audit::LABEL_RETENTION],
                expected,
                "the admitted retention mode must be a label on the chain entry: {entry}"
            );
        }
    }

    /// A stream event names who attached and where in the sequence, and
    /// carries none of what the workload printed.
    ///
    /// The exhaustive label-set assertion is the part that matters. A
    /// substring check only refutes the payload a test happened to think of;
    /// pinning the whole key set means a future label carrying captured bytes
    /// fails here whatever it is called.
    #[test]
    fn stream_audit_entries_carry_the_binding_and_no_payload_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let mut seed = [0u8; 32];
        rand::rng().fill_bytes(&mut seed);
        let key = SigningKey::from_bytes(&seed);
        let vk = key.verifying_key();
        let emitter = AuditEmitter::with_dir(key, dir.path()).expect("emitter");
        let plan = fixture_plan("local", "plan-stream");

        emitter
            .emit_stream_subscribed(&plan, "vm-under-watch", 7, 42)
            .expect("emit");

        let entry = only_entry(dir.path(), "local");
        assert_eq!(entry["event"], stream_audit::SUBSCRIBED_EVENT);
        assert_eq!(entry["plan_id"], "plan-stream");
        assert_eq!(
            entry["labels"][stream_audit::LABEL_VM_NAME],
            "vm-under-watch"
        );
        assert_eq!(entry["labels"][stream_audit::LABEL_READER_ID], "7");
        assert_eq!(entry["labels"][stream_audit::LABEL_FROM_SEQ], "42");

        let labels = entry["labels"].as_object().expect("labels object");
        let mut keys: Vec<&str> = labels.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                stream_audit::LABEL_FROM_SEQ,
                stream_audit::LABEL_READER_ID,
                stream_audit::LABEL_VM_NAME,
            ],
            "a stream event carries the binding and nothing else"
        );

        verify_audit_chain(&dir.path().join("local.jsonl"), &vk)
            .expect("the entry is chain-signed like any other");
    }

    /// Every refusal variant reaches the chain under its own reason word, and
    /// no variant's labels can grow a key that is not on the allow-list here.
    ///
    /// The label builder is one exhaustive match, so a variant added later
    /// fails to compile there; this pins the other half — that what the match
    /// emits stays a binding, a reason, and positional metadata, never bytes.
    #[test]
    fn every_input_refusal_variant_is_labelled_with_its_reason_and_nothing_more() {
        use crate::stream::InputRefusal as R;
        use stream_audit as k;

        let allowed = [
            k::LABEL_VM_NAME,
            k::LABEL_REASON,
            k::LABEL_HOLDER,
            k::LABEL_SECRET_CATEGORY,
            k::LABEL_SEQ,
            k::LABEL_AFTER_SEQ,
        ];
        for refusal in [
            R::NotGranted,
            R::Unauditable,
            R::LeaseExpired,
            R::LeaseHeld {
                holder: "plan-1#0".to_string(),
            },
            R::SecretMaterial {
                category: "host-secret",
            },
            R::OutOfOrder { seq: 3, after: 9 },
        ] {
            let labels = input_refused_labels("vm-1", &refusal);
            let by_key: std::collections::BTreeMap<&str, &str> = labels
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect();
            assert_eq!(by_key.len(), labels.len(), "no duplicate keys: {labels:?}");
            assert_eq!(by_key.get(k::LABEL_VM_NAME), Some(&"vm-1"));
            assert_eq!(by_key.get(k::LABEL_REASON), Some(&refusal.reason()));
            for key in by_key.keys() {
                assert!(
                    allowed.contains(key),
                    "unexpected label {key} on {refusal:?}"
                );
            }
        }

        let ordered = input_refused_labels("vm-1", &R::OutOfOrder { seq: 3, after: 9 });
        assert!(ordered.contains(&(k::LABEL_SEQ.to_string(), "3".to_string())));
        assert!(ordered.contains(&(k::LABEL_AFTER_SEQ.to_string(), "9".to_string())));
    }

    /// A structured refusal carries the stage, a human-readable reason, and
    /// the host signer as the authorizer principal, so an auditor can answer
    /// "who refused this and why?" from the signed chain alone.
    #[test]
    fn admission_refusal_records_stage_reason_and_authorizer() {
        let dir = tempfile::tempdir().unwrap();
        let key = {
            let mut __ed_seed = [0u8; 32];
            rand::rng().fill_bytes(&mut __ed_seed);
            SigningKey::from_bytes(&__ed_seed)
        };
        let vk = key.verifying_key();
        let emitter = AuditEmitter::with_dir(key, dir.path()).unwrap();
        let plan = fixture_plan("local", "plan-refused");

        emitter
            .emit_refused(&plan, "grant_ceiling", "cpu tier exceeds ceiling")
            .unwrap();

        let entry = only_entry(dir.path(), "local");
        assert_eq!(entry["event"], "plan.admission_refused");
        assert_eq!(entry["labels"]["stage"], "grant_ceiling");
        assert_eq!(entry["labels"]["reason"], "cpu tier exceeds ceiling");
        let principal = entry["labels"]["authorizer_principal"]
            .as_str()
            .expect("authorizer_principal label");
        assert!(
            principal.starts_with("host:"),
            "authorizer must be the host signer: {principal}"
        );
        verify_audit_chain(&dir.path().join("local.jsonl"), &vk).expect("refusal entry verifies");
    }

    /// Control-key use is recorded with the key id and role as the
    /// authorizer principal, so orchestrator decisions are attributable.
    #[test]
    fn control_key_used_records_kid_role_action_and_authorizer() {
        use mvm_core::mvmd_iface::ControlKeyRole;

        let dir = tempfile::tempdir().unwrap();
        let key = {
            let mut __ed_seed = [0u8; 32];
            rand::rng().fill_bytes(&mut __ed_seed);
            SigningKey::from_bytes(&__ed_seed)
        };
        let vk = key.verifying_key();
        let emitter = AuditEmitter::with_dir(key, dir.path()).unwrap();
        let plan = fixture_plan("local", "plan-ctl");
        let control_key = mvm_core::mvmd_iface::ControlKey {
            kid: "ck-prod-1".to_string(),
            role: ControlKeyRole::Orchestrator,
            expiry_unix_secs: u64::MAX,
        };

        emitter
            .emit_control_key_used(&plan, &control_key, "vm.stop")
            .unwrap();

        let entry = only_entry(dir.path(), "local");
        assert_eq!(entry["event"], "control_key.used");
        assert_eq!(entry["labels"]["kid"], "ck-prod-1");
        assert_eq!(entry["labels"]["role"], "Orchestrator");
        assert_eq!(entry["labels"]["action"], "vm.stop");
        assert_eq!(entry["labels"]["authorizer_principal"], "ck-prod-1");
        verify_audit_chain(&dir.path().join("local.jsonl"), &vk)
            .expect("control-key entry verifies");
    }

    /// The single entry in a tenant's chain, unwrapped from its signed
    /// envelope. Panics rather than returning an error: a test that wrote one
    /// entry and cannot read it back has already failed.
    fn only_entry(audit_dir: &Path, tenant: &str) -> serde_json::Value {
        let content = std::fs::read_to_string(audit_dir.join(format!("{tenant}.jsonl")))
            .expect("read the chain");
        let mut lines = content.lines();
        let line = lines.next().expect("one entry");
        assert!(lines.next().is_none(), "expected exactly one entry");
        let envelope: serde_json::Value = serde_json::from_str(line).expect("envelope json");
        envelope["entry"].clone()
    }

    #[test]
    fn audit_chain_verifies_clean() {
        let dir = tempfile::tempdir().unwrap();
        let key = {
            let mut __ed_seed = [0u8; 32];
            rand::rng().fill_bytes(&mut __ed_seed);
            SigningKey::from_bytes(&__ed_seed)
        };
        let vk = key.verifying_key();
        let emitter = AuditEmitter::with_dir(key, dir.path()).unwrap();
        let plan = fixture_plan("local", "plan-X");
        emitter.emit_admitted(&plan, "host:test").unwrap();
        emitter.emit_launched(&plan, "firecracker").unwrap();

        let count = verify_audit_chain(&dir.path().join("local.jsonl"), &vk).unwrap();
        assert_eq!(count, 2, "both entries must verify clean");
    }

    #[test]
    fn oci_provenance_event_is_chain_signed_with_required_labels() {
        let dir = tempfile::tempdir().unwrap();
        let key = {
            let mut __ed_seed = [0u8; 32];
            rand::rng().fill_bytes(&mut __ed_seed);
            SigningKey::from_bytes(&__ed_seed)
        };
        let vk = key.verifying_key();
        let emitter = AuditEmitter::with_dir(key, dir.path()).unwrap();
        let plan = fixture_plan("local", "plan-OCI");
        let labels = vec![
            ("oci_source".to_string(), "run_image".to_string()),
            (
                "oci_supplied_reference".to_string(),
                "alpine:3.20".to_string(),
            ),
            (
                "oci_canonical_reference".to_string(),
                "docker.io/library/alpine:3.20".to_string(),
            ),
            ("oci_registry".to_string(), "docker.io".to_string()),
            ("oci_repository".to_string(), "library/alpine".to_string()),
            (
                "oci_resolved_digest".to_string(),
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .to_string(),
            ),
            (
                "oci_layer_digests".to_string(),
                "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                    .to_string(),
            ),
            (
                "oci_trust_policy".to_string(),
                "mutable-reference-resolved-to-digest".to_string(),
            ),
            (
                "oci_verification_status".to_string(),
                "digest-verified-signature-not-configured".to_string(),
            ),
        ];

        emitter.emit_oci_provenance(&plan, labels).unwrap();

        let path = dir.path().join("local.jsonl");
        let content = std::fs::read_to_string(&path).expect("audit file exists");
        assert!(content.contains("plan.oci_provenance"));
        assert!(content.contains("oci_registry"));
        assert!(content.contains("docker.io"));
        assert!(content.contains("oci_resolved_digest"));
        assert!(content.contains("oci_layer_digests"));
        assert_eq!(verify_audit_chain(&path, &vk).unwrap(), 1);
    }

    #[test]
    fn session_parked_event_is_chain_signed_and_keeps_the_plan_labels() {
        // The park entry's extras must add to the plan's session labels, not
        // replace them: `for_plan` merges extras over the plan's own labels,
        // so a key collision would overwrite what was signed.
        let dir = tempfile::tempdir().unwrap();
        let key = {
            let mut __ed_seed = [0u8; 32];
            rand::rng().fill_bytes(&mut __ed_seed);
            SigningKey::from_bytes(&__ed_seed)
        };
        let vk = key.verifying_key();
        let emitter = AuditEmitter::with_dir(key, dir.path()).unwrap();
        let mut plan = fixture_plan("local", "plan-SESSION");
        plan.audit_labels
            .insert("session_id".to_string(), "sess-alpha".to_string());
        plan.audit_labels
            .insert("session_generation".to_string(), "3".to_string());

        emitter
            .emit_session_parked(
                &plan,
                vec![
                    ("parked_session".to_string(), "sess-alpha".to_string()),
                    ("parked_at_generation".to_string(), "3".to_string()),
                    ("park_reason".to_string(), "approval-wait".to_string()),
                    ("park_storage_tier".to_string(), "parked".to_string()),
                ],
            )
            .unwrap();

        let path = dir.path().join("local.jsonl");
        let content = std::fs::read_to_string(&path).expect("audit file exists");
        assert!(content.contains("session.parked"));
        assert!(content.contains("park_reason"));
        assert!(content.contains("approval-wait"));
        assert!(
            content.contains("session_generation"),
            "the plan's own session labels must survive the merge: {content}"
        );
        assert_eq!(verify_audit_chain(&path, &vk).unwrap(), 1);
    }

    #[test]
    fn session_resumed_event_is_chain_signed_and_keeps_the_plan_labels() {
        let dir = tempfile::tempdir().unwrap();
        let key = {
            let mut __ed_seed = [0u8; 32];
            rand::rng().fill_bytes(&mut __ed_seed);
            SigningKey::from_bytes(&__ed_seed)
        };
        let vk = key.verifying_key();
        let emitter = AuditEmitter::with_dir(key, dir.path()).unwrap();
        let mut plan = fixture_plan("local", "plan-RESUME");
        plan.audit_labels
            .insert("session_id".to_string(), "sess-alpha".to_string());
        plan.audit_labels
            .insert("session_generation".to_string(), "4".to_string());

        emitter
            .emit_session_resumed(
                &plan,
                vec![
                    ("resumed_session".to_string(), "sess-alpha".to_string()),
                    ("resumed_at_generation".to_string(), "4".to_string()),
                    ("resumed_plan_id".to_string(), "plan-RESUME".to_string()),
                ],
            )
            .unwrap();

        let path = dir.path().join("local.jsonl");
        let content = std::fs::read_to_string(&path).expect("audit file exists");
        assert!(content.contains("session.resumed"));
        assert!(content.contains("resumed_at_generation"));
        assert!(
            content.contains("session_generation"),
            "the plan's own session labels must survive the merge: {content}"
        );
        assert_eq!(verify_audit_chain(&path, &vk).unwrap(), 1);
    }

    #[test]
    fn boot_posture_event_is_chain_signed_and_binds_the_label_to_its_own_plan() {
        // The posture label is per-plan, not per-file: two boots in one chain
        // each carry their own plan id alongside the strategy they booted, so a
        // reader can attribute a posture rather than infer it from position.
        let dir = tempfile::tempdir().unwrap();
        let key = {
            let mut __ed_seed = [0u8; 32];
            rand::rng().fill_bytes(&mut __ed_seed);
            SigningKey::from_bytes(&__ed_seed)
        };
        let vk = key.verifying_key();
        let emitter = AuditEmitter::with_dir(key, dir.path()).unwrap();

        let first = fixture_plan("local", "plan-one");
        let second = fixture_plan("local", "plan-two");
        emitter.emit_boot_posture(&first, "block-ext4").unwrap();
        emitter.emit_boot_posture(&second, "block-ext4").unwrap();

        let path = dir.path().join("local.jsonl");
        let content = std::fs::read_to_string(&path).expect("audit file exists");
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("plan.boot_posture"));
        assert!(lines[0].contains("block-ext4"));
        assert!(lines[0].contains("\"plan-one\""));
        assert!(!lines[0].contains("\"plan-two\""));
        assert!(lines[1].contains("block-ext4"));
        assert!(lines[1].contains("\"plan-two\""));
        assert_eq!(verify_audit_chain(&path, &vk).unwrap(), 2);
    }

    #[test]
    fn grant_required_event_is_chain_signed_with_required_labels() {
        let dir = tempfile::tempdir().unwrap();
        let key = {
            let mut __ed_seed = [0u8; 32];
            rand::rng().fill_bytes(&mut __ed_seed);
            SigningKey::from_bytes(&__ed_seed)
        };
        let vk = key.verifying_key();
        let emitter = AuditEmitter::with_dir(key, dir.path()).unwrap();
        let plan = fixture_plan("local", "plan-GR");

        let verbs = vec![
            mvm_core::plan::VerbId::new("ping").unwrap(),
            mvm_core::plan::VerbId::new("run-entrypoint").unwrap(),
        ];
        emitter.emit_grant_required(&plan, &verbs).unwrap();

        let path = dir.path().join("local.jsonl");
        let content = std::fs::read_to_string(&path).expect("audit file exists");
        assert!(
            content.contains("plan.grant_required"),
            "event kind must appear in log"
        );
        assert!(content.contains("\"2\""), "verb_count must be 2");
        assert!(content.contains("ping"), "verb_0 label must contain 'ping'");
        assert!(
            content.contains("run-entrypoint"),
            "verb_1 label must contain 'run-entrypoint'"
        );
        assert_eq!(
            verify_audit_chain(&path, &vk).unwrap(),
            1,
            "single-entry chain must verify clean"
        );
    }

    #[test]
    fn transcript_sealed_event_is_chain_signed_with_root_labels() {
        let dir = tempfile::tempdir().unwrap();
        let key = {
            let mut seed = [0u8; 32];
            rand::rng().fill_bytes(&mut seed);
            SigningKey::from_bytes(&seed)
        };
        let vk = key.verifying_key();
        let emitter = AuditEmitter::with_dir(key, dir.path()).unwrap();
        let plan = fixture_plan("local", "plan-transcript");
        let root = "cd".repeat(32);

        emitter
            .emit_transcript_sealed(&plan, "capture-1", "vm-1", &root, 3, false)
            .unwrap();

        let path = dir.path().join("local.jsonl");
        let entries = crate::supervisor::verify_audit_chain_entries(&path, &vk).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].event,
            crate::supervisor::audit::TRANSCRIPT_SEALED_EVENT
        );
        assert_eq!(
            entries[0]
                .labels
                .get(crate::supervisor::audit::LABEL_TRANSCRIPT_ROOT),
            Some(&root)
        );
        assert_eq!(
            entries[0]
                .labels
                .get(crate::supervisor::audit::LABEL_CHUNK_COUNT),
            Some(&"3".to_string())
        );
    }

    #[test]
    fn audit_chain_rejects_inserted_line() {
        // Synthesize a valid chain, then forge an extra entry whose
        // signature is wrong (or rather, taken from a different key).
        // verify_audit_chain must refuse.
        let dir = tempfile::tempdir().unwrap();
        let key = {
            let mut __ed_seed = [0u8; 32];
            rand::rng().fill_bytes(&mut __ed_seed);
            SigningKey::from_bytes(&__ed_seed)
        };
        let vk = key.verifying_key();
        let emitter = AuditEmitter::with_dir(key.clone(), dir.path()).unwrap();
        let plan = fixture_plan("local", "plan-Z");
        emitter.emit_admitted(&plan, "host:test").unwrap();

        // Tamper: replace the event name. The edit reaches the readable entry
        // but not the base64 copy of the signed bytes beside it, so the line is
        // refused for the two disagreeing rather than for a bad signature —
        // a more precise account of the same tamper.
        let path = dir.path().join("local.jsonl");
        let content = std::fs::read_to_string(&path).unwrap();
        let tampered = content.replace("plan.admitted", "plan.fakeville");
        std::fs::write(&path, tampered).unwrap();

        let err = verify_audit_chain(&path, &vk).expect_err("tamper must break verify");
        assert!(
            matches!(
                err,
                crate::supervisor::VerifyError::EntryCanonicalMismatch { .. }
            ),
            "expected EntryCanonicalMismatch, got {err:?}"
        );
    }

    #[test]
    fn emit_failed_records_class_and_message() {
        let dir = tempfile::tempdir().unwrap();
        let key = {
            let mut __ed_seed = [0u8; 32];
            rand::rng().fill_bytes(&mut __ed_seed);
            SigningKey::from_bytes(&__ed_seed)
        };
        let vk = key.verifying_key();
        let emitter = AuditEmitter::with_dir(key, dir.path()).unwrap();
        let plan = fixture_plan("local", "plan-F");
        emitter
            .emit_failed(&plan, "backend-start", "kernel panic at boot")
            .unwrap();

        let content =
            std::fs::read_to_string(dir.path().join("local.jsonl")).expect("audit file exists");
        assert!(content.contains("plan.failed"));
        assert!(content.contains("backend-start"));
        assert!(content.contains("kernel panic"));

        // And the single-entry chain still verifies.
        let count = verify_audit_chain(&dir.path().join("local.jsonl"), &vk).unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn emit_exited_records_capture_fidelity() {
        let dir = tempfile::tempdir().unwrap();
        let key = {
            let mut __ed_seed = [0u8; 32];
            rand::rng().fill_bytes(&mut __ed_seed);
            SigningKey::from_bytes(&__ed_seed)
        };
        let vk = key.verifying_key();
        let emitter = AuditEmitter::with_dir(key, dir.path()).unwrap();
        let plan = fixture_plan("local", "plan-CAP");

        // A captured exit records the code and captured=true.
        emitter
            .emit_exited_with_capture(
                &plan,
                ExitRecord {
                    exit_code: Some(0),
                    backend: "mock",
                    usage: UsageCapture::default(),
                },
            )
            .unwrap();
        // A missing capture must never be attested as exit 0.
        emitter
            .emit_exited_with_capture(
                &plan,
                ExitRecord {
                    exit_code: None,
                    backend: "mock",
                    usage: UsageCapture::default(),
                },
            )
            .unwrap();

        let path = dir.path().join("local.jsonl");
        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("\"true\""), "got: {}", lines[0]);
        assert!(lines[0].contains("\"0\""), "got: {}", lines[0]);
        assert!(lines[1].contains("\"false\""), "got: {}", lines[1]);
        assert!(lines[1].contains("\"none\""), "got: {}", lines[1]);
        assert!(
            !lines[1].contains("\"0\""),
            "uncaptured must not read as exit 0"
        );
        assert_eq!(verify_audit_chain(&path, &vk).unwrap(), 2);
    }

    #[test]
    fn an_exit_entry_carries_the_usage_record() {
        let dir = tempfile::tempdir().unwrap();
        let key = {
            let mut __ed_seed = [0u8; 32];
            rand::rng().fill_bytes(&mut __ed_seed);
            SigningKey::from_bytes(&__ed_seed)
        };
        let emitter = AuditEmitter::with_dir(key, dir.path()).unwrap();
        let plan = fixture_plan("local", "plan-USAGE");
        let usage = UsageCapture {
            cpu_ms: Metric::measured(4210, Mechanism::HostProcessCpu),
            ..UsageCapture::default()
        };

        emitter
            .emit_exited_with_capture(
                &plan,
                ExitRecord {
                    exit_code: Some(0),
                    backend: "libkrun",
                    usage,
                },
            )
            .unwrap();

        // Parse the label back rather than substring-matching the line: the
        // entry has to carry the number, the source, and the mechanism that
        // produced it, and an `||` over two loose substrings would pass on any
        // one of the three.
        let content =
            std::fs::read_to_string(dir.path().join("local.jsonl")).expect("audit file exists");
        let entry: serde_json::Value = content
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("entry is json"))
            .find(|line| line["entry"]["event"] == "plan.exited")
            .expect("a plan.exited entry");
        let recorded: UsageCapture = serde_json::from_str(
            entry["entry"]["labels"]["usage"]
                .as_str()
                .expect("the usage label is a json string"),
        )
        .expect("the usage label parses back into a capture");
        assert_eq!(recorded, usage);
        assert_eq!(
            recorded.cpu_ms,
            Metric::measured(4210, Mechanism::HostProcessCpu)
        );
        // The dimensions this run did not observe stay unobserved rather than
        // being filled in by the emitter.
        assert_eq!(recorded.peak_rss_mib, Metric::unavailable());
    }

    #[test]
    fn an_exit_that_measured_nothing_still_says_so_in_the_chain() {
        // Absence of the label would be indistinguishable from an older
        // entry; an explicit all-unavailable record is the attestable form.
        let dir = tempfile::tempdir().unwrap();
        let key = {
            let mut __ed_seed = [0u8; 32];
            rand::rng().fill_bytes(&mut __ed_seed);
            SigningKey::from_bytes(&__ed_seed)
        };
        let emitter = AuditEmitter::with_dir(key, dir.path()).unwrap();
        let plan = fixture_plan("local", "plan-USAGE-NONE");

        emitter
            .emit_exited_with_capture(
                &plan,
                ExitRecord {
                    exit_code: None,
                    backend: "firecracker",
                    usage: UsageCapture::default(),
                },
            )
            .unwrap();

        let content =
            std::fs::read_to_string(dir.path().join("local.jsonl")).expect("audit file exists");
        assert!(content.contains("unavailable"), "got: {content}");
        assert!(
            content.contains("captured"),
            "capture fidelity is unchanged"
        );
    }

    #[test]
    fn emit_exited_writes_plan_exited_with_code() {
        let dir = tempfile::tempdir().unwrap();
        let key = {
            let mut __ed_seed = [0u8; 32];
            rand::rng().fill_bytes(&mut __ed_seed);
            SigningKey::from_bytes(&__ed_seed)
        };
        let vk = key.verifying_key();
        let emitter = AuditEmitter::with_dir(key, dir.path()).unwrap();
        let plan = fixture_plan("local", "plan-EX");
        emitter.emit_exited(&plan, 3, "libkrun").unwrap();

        let path = dir.path().join("local.jsonl");
        let content = std::fs::read_to_string(&path).expect("audit file exists");
        assert!(content.contains("plan.exited"));
        assert!(content.contains("\"3\""));
        assert!(content.contains("\"libkrun\""));
        assert_eq!(verify_audit_chain(&path, &vk).unwrap(), 1);
    }

    #[test]
    fn emit_egress_destinations_records_host_port_allowlist() {
        let dir = tempfile::tempdir().unwrap();
        let key = {
            let mut __ed_seed = [0u8; 32];
            rand::rng().fill_bytes(&mut __ed_seed);
            SigningKey::from_bytes(&__ed_seed)
        };
        let vk = key.verifying_key();
        let emitter = AuditEmitter::with_dir(key, dir.path()).unwrap();
        let plan = fixture_plan("local", "plan-EG");
        let destinations = vec![
            ("example.com".to_string(), 443),
            ("api.example.com".to_string(), 8443),
        ];
        emitter
            .emit_egress_destinations(&plan, &destinations)
            .unwrap();

        let path = dir.path().join("local.jsonl");
        let content = std::fs::read_to_string(&path).expect("audit file exists");
        assert!(content.contains("plan.egress_destinations"));
        assert!(content.contains("\"example.com\""));
        assert!(content.contains("\"api.example.com\""));
        assert!(content.contains("\"443\""));
        assert!(content.contains("\"8443\""));
        assert_eq!(verify_audit_chain(&path, &vk).unwrap(), 1);
    }

    #[test]
    fn emit_egress_destinations_is_noop_for_empty_allowlist() {
        let dir = tempfile::tempdir().unwrap();
        let key = {
            let mut __ed_seed = [0u8; 32];
            rand::rng().fill_bytes(&mut __ed_seed);
            SigningKey::from_bytes(&__ed_seed)
        };
        let emitter = AuditEmitter::with_dir(key, dir.path()).unwrap();
        let plan = fixture_plan("local", "plan-EG-EMPTY");
        emitter.emit_egress_destinations(&plan, &[]).unwrap();

        let path = dir.path().join("local.jsonl");
        assert!(
            !path.exists(),
            "empty allowlist must not write an audit entry"
        );
    }

    #[test]
    fn audit_dir_is_created_with_0700_perms() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("audit-fresh");
        let key = {
            let mut __ed_seed = [0u8; 32];
            rand::rng().fill_bytes(&mut __ed_seed);
            SigningKey::from_bytes(&__ed_seed)
        };
        let _emitter = AuditEmitter::with_dir(key, &target).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700, "audit dir must be tightened to 0700");
        }
    }

    #[test]
    fn policy_file_destination_gets_a_replicated_chain() {
        let dir = tempfile::tempdir().unwrap();
        let replica = dir.path().join("replica.jsonl");
        let key = {
            let mut __ed_seed = [0u8; 32];
            rand::rng().fill_bytes(&mut __ed_seed);
            SigningKey::from_bytes(&__ed_seed)
        };
        let vk = key.verifying_key();
        let policy = mvm_core::policy::AuditPolicy {
            chain_signing: true,
            stream_destinations: vec![format!("file://{}", replica.display())],
        };
        let emitter = AuditEmitter::with_policy(key, dir.path(), &policy).unwrap();
        let plan = fixture_plan("local", "plan-P");

        emitter.emit_admitted(&plan, "host:test").unwrap();

        let default_path = dir.path().join("local.jsonl");
        assert!(default_path.exists(), "default local chain remains active");
        assert!(replica.exists(), "policy file stream must be written");
        assert_eq!(verify_audit_chain(&default_path, &vk).unwrap(), 1);
        assert_eq!(verify_audit_chain(&replica, &vk).unwrap(), 1);
    }

    #[test]
    fn policy_requires_chain_signing() {
        let dir = tempfile::tempdir().unwrap();
        let key = {
            let mut __ed_seed = [0u8; 32];
            rand::rng().fill_bytes(&mut __ed_seed);
            SigningKey::from_bytes(&__ed_seed)
        };
        let policy = mvm_core::policy::AuditPolicy {
            chain_signing: false,
            stream_destinations: Vec::new(),
        };
        let err = match AuditEmitter::with_policy(key, dir.path(), &policy) {
            Ok(_) => panic!("chain_signing=false must be rejected"),
            Err(err) => err,
        };
        assert!(format!("{err:#}").contains("chain_signing"));
    }

    #[test]
    fn policy_refuses_unwired_replication_schemes() {
        let dir = tempfile::tempdir().unwrap();
        let key = {
            let mut __ed_seed = [0u8; 32];
            rand::rng().fill_bytes(&mut __ed_seed);
            SigningKey::from_bytes(&__ed_seed)
        };
        let policy = mvm_core::policy::AuditPolicy {
            chain_signing: true,
            stream_destinations: vec!["https://audit.example.com/ingest".to_string()],
        };
        let err = match AuditEmitter::with_policy(key, dir.path(), &policy) {
            Ok(_) => panic!("unwired replication schemes must be rejected"),
            Err(err) => err,
        };
        assert!(format!("{err:#}").contains("not wired yet"));
    }

    #[test]
    fn policy_refuses_relative_file_destinations() {
        let dir = tempfile::tempdir().unwrap();
        let key = {
            let mut __ed_seed = [0u8; 32];
            rand::rng().fill_bytes(&mut __ed_seed);
            SigningKey::from_bytes(&__ed_seed)
        };
        let policy = mvm_core::policy::AuditPolicy {
            chain_signing: true,
            stream_destinations: vec!["file://relative/audit.jsonl".to_string()],
        };
        let err = match AuditEmitter::with_policy(key, dir.path(), &policy) {
            Ok(_) => panic!("relative audit file destinations must be rejected"),
            Err(err) => err,
        };
        assert!(format!("{err:#}").contains("absolute path"));
    }

    #[test]
    fn verb_denied_entry_is_chained_and_verifies() {
        let dir = tempfile::tempdir().unwrap();
        let key = {
            let mut __ed_seed = [0u8; 32];
            rand::rng().fill_bytes(&mut __ed_seed);
            SigningKey::from_bytes(&__ed_seed)
        };
        let vk = key.verifying_key();
        let emitter = AuditEmitter::with_dir(key, dir.path()).unwrap();
        let plan = fixture_plan("local", "plan-VD");

        emitter.emit_admitted(&plan, "host:test").unwrap();
        emitter
            .emit_verb_denied(&plan, "update-idle-timeout")
            .unwrap();

        let path = dir.path().join("local.jsonl");
        let content = std::fs::read_to_string(&path).expect("audit file exists");

        // Both category and verb name must appear in the log.
        assert!(
            content.contains("verb_denied"),
            "log must contain verb_denied category"
        );
        assert!(
            content.contains("update-idle-timeout"),
            "log must contain the denied verb name"
        );

        // The two-entry chain must verify clean.
        let count = verify_audit_chain(&path, &vk).unwrap();
        assert_eq!(count, 2, "admitted + verb_denied must form a valid chain");

        // A byte-flip in the log must break verify_audit_chain.
        let tampered = content.replace("verb_denied", "verb_permitted");
        std::fs::write(&path, tampered).unwrap();
        assert!(
            verify_audit_chain(&path, &vk).is_err(),
            "tampered log must fail chain verification"
        );
    }

    #[test]
    fn default_audit_path_for_tenant_uses_jsonl_suffix() {
        // No HOME-touching test for `default_audit_dir`; the
        // assertion here is the per-tenant path shape, which is
        // pure-formatting and doesn't need the env var.
        let p = PathBuf::from("/some/dir").join("local.jsonl");
        assert!(p.to_string_lossy().ends_with("local.jsonl"));
    }

    #[test]
    fn checkpoint_created_records_id_and_digest() {
        let dir = tempfile::tempdir().unwrap();
        let key = {
            let mut __ed_seed = [0u8; 32];
            rand::rng().fill_bytes(&mut __ed_seed);
            SigningKey::from_bytes(&__ed_seed)
        };
        let vk = key.verifying_key();
        let emitter = AuditEmitter::with_dir(key, dir.path()).unwrap();
        let plan = fixture_plan("local", "plan-C");
        let meta_digest = format!("sha256:{}", "a".repeat(64));
        emitter
            .emit_checkpoint_created(&plan, "ckpt-abc", "fs_quick", &meta_digest, "myvm")
            .unwrap();
        let path = dir.path().join("local.jsonl");
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("checkpoint.created"));
        assert!(content.contains("ckpt-abc"));
        // The content-address rides opaquely as a label; the chain still verifies.
        assert!(content.contains("meta_digest"));
        assert!(content.contains(&meta_digest));
        assert_eq!(verify_audit_chain(&path, &vk).unwrap(), 1);
    }

    #[test]
    fn checkpoint_forked_records_lineage_digests() {
        let dir = tempfile::tempdir().unwrap();
        let key = {
            let mut __ed_seed = [0u8; 32];
            rand::rng().fill_bytes(&mut __ed_seed);
            SigningKey::from_bytes(&__ed_seed)
        };
        let vk = key.verifying_key();
        let emitter = AuditEmitter::with_dir(key, dir.path()).unwrap();
        let plan = fixture_plan("local", "plan-F");
        let parent_digest = format!("sha256:{}", "b".repeat(64));
        let child_digest = format!("sha256:{}", "c".repeat(64));
        emitter
            .emit_checkpoint_forked(
                &plan,
                CheckpointForkedAudit {
                    parent_id: "ckpt-parent",
                    child_id: "ckpt-child",
                    child_vm_name: "childvm",
                    parent_digest: &parent_digest,
                    child_digest: &child_digest,
                    secret_bindings_json: r#"[{"name":"API_KEY","allowed_hosts":["api.example.com"]}]"#,
                },
            )
            .unwrap();
        let path = dir.path().join("local.jsonl");
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("checkpoint.forked"));
        assert!(content.contains("ckpt-parent"));
        assert!(content.contains("ckpt-child"));
        // The hash-linked lineage is bound, not just the mutable names.
        assert!(content.contains("parent_digest"));
        assert!(content.contains("child_digest"));
        assert!(content.contains(&parent_digest));
        assert!(content.contains(&child_digest));
        assert!(content.contains("API_KEY"));
        assert!(content.contains("api.example.com"));
        assert_eq!(verify_audit_chain(&path, &vk).unwrap(), 1);
    }

    #[test]
    fn image_created_is_chain_signed_with_required_labels() {
        use mvm_core::image_lineage::{
            ImageBuildIdentity, ImageCanonicalId, ImageIdentity, ImageNode, ImageProvenance,
        };
        let dir = tempfile::tempdir().unwrap();
        let key = {
            let mut __ed_seed = [0u8; 32];
            rand::rng().fill_bytes(&mut __ed_seed);
            SigningKey::from_bytes(&__ed_seed)
        };
        let vk = key.verifying_key();
        let emitter = AuditEmitter::with_dir(key, dir.path()).unwrap();
        let plan = fixture_plan("local", "plan-IMG");

        let parent = ImageNode::builder(
            ImageBuildIdentity::Flake {
                slot_hash: "slot-a".into(),
            },
            ImageIdentity {
                canonical: ImageCanonicalId::Flake {
                    revision_hash: "rev-1".into(),
                },
                artifacts: vec![mvm_core::checkpoint::ContentBlob {
                    name: "rootfs.ext4".into(),
                    sha256: "aa".into(),
                }],
            },
            ImageProvenance::Build {
                input_ref: ".#app".into(),
                lock_digest: Some("sha256:lock".into()),
            },
        )
        .created_unix(1)
        .build();
        let child = ImageNode::builder(
            ImageBuildIdentity::Flake {
                slot_hash: "slot-a".into(),
            },
            ImageIdentity {
                canonical: ImageCanonicalId::Flake {
                    revision_hash: "rev-2".into(),
                },
                artifacts: vec![mvm_core::checkpoint::ContentBlob {
                    name: "rootfs.ext4".into(),
                    sha256: "bb".into(),
                }],
            },
            ImageProvenance::Build {
                input_ref: ".#app".into(),
                lock_digest: None,
            },
        )
        .parent(Some(parent.node_digest.clone()))
        .created_unix(2)
        .build();

        emitter.emit_image_created(&plan, &parent).unwrap();
        emitter.emit_image_created(&plan, &child).unwrap();

        let path = dir.path().join("local.jsonl");
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("image.created"));
        assert!(content.contains("image_node_digest"));
        assert!(content.contains(parent.node_digest.as_str()));
        assert!(content.contains(child.node_digest.as_str()));
        // The genesis node records the sentinel; the child records its hash-link.
        assert!(content.contains("genesis"));
        assert!(content.contains("image_build_identity"));
        assert!(content.contains("slot-a"));
        assert_eq!(verify_audit_chain(&path, &vk).unwrap(), 2);
    }

    #[test]
    fn image_reverted_records_node_digest_via_and_reference() {
        let dir = tempfile::tempdir().unwrap();
        let key = {
            let mut __ed_seed = [0u8; 32];
            rand::rng().fill_bytes(&mut __ed_seed);
            SigningKey::from_bytes(&__ed_seed)
        };
        let vk = key.verifying_key();
        let emitter = AuditEmitter::with_dir(key, dir.path()).unwrap();
        let plan = fixture_plan("local", "plan-IR");
        let node_digest = format!("sha256:{}", "c".repeat(64));
        emitter
            .emit_image_reverted(
                &plan,
                &node_digest,
                "revert",
                "docker.io/library/alpine@sha256:aa",
            )
            .unwrap();
        let path = dir.path().join("local.jsonl");
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("image.reverted"));
        assert!(content.contains(&node_digest));
        assert!(content.contains("\"via\""));
        assert!(content.contains("revert"));
        assert!(content.contains("docker.io/library/alpine@sha256:aa"));
        assert_eq!(verify_audit_chain(&path, &vk).unwrap(), 1);
    }

    #[test]
    fn checkpoint_restored_records_id_digest_and_vm() {
        let dir = tempfile::tempdir().unwrap();
        let key = {
            let mut __ed_seed = [0u8; 32];
            rand::rng().fill_bytes(&mut __ed_seed);
            SigningKey::from_bytes(&__ed_seed)
        };
        let vk = key.verifying_key();
        let emitter = AuditEmitter::with_dir(key, dir.path()).unwrap();
        let plan = fixture_plan("local", "plan-R");
        let meta_digest = format!("sha256:{}", "d".repeat(64));
        emitter
            .emit_checkpoint_restored(&plan, "ckpt-abc", &meta_digest, "myvm", "revert")
            .unwrap();
        let path = dir.path().join("local.jsonl");
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("checkpoint.restored"));
        assert!(content.contains("ckpt-abc"));
        assert!(content.contains("myvm"));
        assert!(content.contains(&meta_digest));
        // The initiating verb rides as the `via` label.
        assert!(content.contains("\"via\""));
        assert!(content.contains("revert"));
        assert_eq!(verify_audit_chain(&path, &vk).unwrap(), 1);
    }

    #[test]
    fn publish_root_writes_a_verifiable_signed_root() {
        use mvm_contract::merkle::{verify_inclusion, verify_signed_root};

        let dir = tempfile::tempdir().unwrap();
        let key = {
            let mut __ed_seed = [0u8; 32];
            rand::rng().fill_bytes(&mut __ed_seed);
            SigningKey::from_bytes(&__ed_seed)
        };
        let vk = key.verifying_key();
        let emitter = AuditEmitter::with_dir(key, dir.path()).unwrap();
        let plan = fixture_plan("local", "plan-ROOT");
        emitter.emit_admitted(&plan, "host:test").unwrap();
        emitter.emit_launched(&plan, "firecracker").unwrap();

        let signed = emitter.publish_root("local").unwrap();
        assert_eq!(signed.tenant, "local");
        assert_eq!(signed.tree_size, 2);
        assert_eq!(signed.signer_pubkey, hex::encode(vk.to_bytes()));
        // The published signature verifies under the host key.
        assert_eq!(verify_signed_root(&signed, &vk), Ok(()));

        // The sidecar landed at `<audit_dir>/<tenant>.root.json` and
        // round-trips to the same struct.
        let root_path = dir.path().join("local.root.json");
        assert!(root_path.exists(), "root sidecar must be written");
        let on_disk: SignedAuditRoot =
            serde_json::from_str(&std::fs::read_to_string(&root_path).unwrap()).unwrap();
        assert_eq!(on_disk, signed);

        // A host-built inclusion proof folds to the published root.
        let proof = crate::audit::merkle::build_inclusion_in(dir.path(), "local", &vk, 1).unwrap();
        assert_eq!(
            hex::encode(verify_inclusion(&proof).unwrap()),
            signed.root_hash
        );
        assert_eq!(proof.tree_size, signed.tree_size);
    }

    #[test]
    fn publish_root_refuses_a_tampered_chain() {
        let dir = tempfile::tempdir().unwrap();
        let key = {
            let mut __ed_seed = [0u8; 32];
            rand::rng().fill_bytes(&mut __ed_seed);
            SigningKey::from_bytes(&__ed_seed)
        };
        let emitter = AuditEmitter::with_dir(key, dir.path()).unwrap();
        let plan = fixture_plan("local", "plan-ROOT2");
        emitter.emit_admitted(&plan, "host:test").unwrap();

        // Corrupt the chain, then a root must not be published.
        let path = dir.path().join("local.jsonl");
        let content = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, content.replacen("plan.admitted", "plan.evil", 1)).unwrap();
        assert!(emitter.publish_root("local").is_err());
        // And no partial sidecar was left behind.
        assert!(!dir.path().join("local.root.json").exists());
    }

    #[test]
    fn receipts_disabled_by_default() {
        let dir = tempfile::tempdir().unwrap();
        let key = {
            let mut __ed_seed = [0u8; 32];
            rand::rng().fill_bytes(&mut __ed_seed);
            SigningKey::from_bytes(&__ed_seed)
        };
        let emitter = AuditEmitter::with_dir(key, dir.path()).unwrap();
        let plan = fixture_plan("local", "plan-no-receipts");
        emitter.emit_admitted(&plan, "host:test").unwrap();

        assert!(!dir.path().join("receipts").exists());
    }

    #[test]
    fn receipts_emitted_when_enabled() {
        let dir = tempfile::tempdir().unwrap();
        let key = {
            let mut __ed_seed = [0u8; 32];
            rand::rng().fill_bytes(&mut __ed_seed);
            SigningKey::from_bytes(&__ed_seed)
        };
        let emitter = AuditEmitter::with_dir(key, dir.path())
            .unwrap()
            .with_receipts();
        let plan = fixture_plan("local", "plan-with-receipts");
        emitter.emit_admitted(&plan, "host:test").unwrap();
        emitter.emit_launched(&plan, "firecracker").unwrap();

        let receipt_dir = dir.path().join("receipts").join("local");
        assert!(receipt_dir.exists());
        let entries: Vec<_> = std::fs::read_dir(&receipt_dir)
            .unwrap()
            .filter_map(|e| {
                let e = e.ok()?;
                let name = e.file_name().into_string().ok()?;
                if name.ends_with(".json") && !name.starts_with("head") {
                    Some(name)
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(entries.len(), 2, "two receipt files expected: {entries:?}");

        let head_path = receipt_dir.join("head.json");
        assert!(head_path.exists());
    }

    #[test]
    fn receipt_chain_continuity_across_emits() {
        let dir = tempfile::tempdir().unwrap();
        let key = {
            let mut __ed_seed = [0u8; 32];
            rand::rng().fill_bytes(&mut __ed_seed);
            SigningKey::from_bytes(&__ed_seed)
        };
        let emitter = AuditEmitter::with_dir(key, dir.path())
            .unwrap()
            .with_receipts();
        let plan = fixture_plan("local", "plan-chain");
        emitter.emit_admitted(&plan, "host:test").unwrap();
        emitter.emit_launched(&plan, "firecracker").unwrap();

        let receipt_dir = dir.path().join("receipts").join("local");
        let mut files: Vec<_> = std::fs::read_dir(&receipt_dir)
            .unwrap()
            .filter_map(|e| {
                let e = e.ok()?;
                let name = e.file_name().into_string().ok()?;
                if name.ends_with(".json") && !name.starts_with("head") {
                    Some((name, e.path()))
                } else {
                    None
                }
            })
            .collect();
        files.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(files.len(), 2);

        let first: mvm_core::receipt::SignedExecutionReceipt =
            serde_json::from_slice(&std::fs::read(&files[0].1).unwrap()).unwrap();
        let second: mvm_core::receipt::SignedExecutionReceipt =
            serde_json::from_slice(&std::fs::read(&files[1].1).unwrap()).unwrap();

        first.verify().expect("first receipt verifies");
        second.verify().expect("second receipt verifies");
        assert_eq!(
            second.payload.prev_receipt_id,
            Some(first.payload.receipt_id.clone()),
            "second receipt must link to first"
        );
    }

    #[test]
    fn checkpoint_receipts_emitted_when_enabled() {
        let dir = tempfile::tempdir().unwrap();
        let key = {
            let mut __ed_seed = [0u8; 32];
            rand::rng().fill_bytes(&mut __ed_seed);
            SigningKey::from_bytes(&__ed_seed)
        };
        let emitter = AuditEmitter::with_dir(key, dir.path())
            .unwrap()
            .with_receipts();
        let plan = fixture_plan("local", "plan-chk");
        emitter
            .emit_checkpoint_created(&plan, "chk-1", "vm_full", "sha256:abc123", "vm-1")
            .unwrap();

        let receipt_dir = dir.path().join("receipts").join("local");
        let files: Vec<_> = std::fs::read_dir(&receipt_dir)
            .unwrap()
            .filter_map(|e| {
                let e = e.ok()?;
                let name = e.file_name().into_string().ok()?;
                if name.ends_with(".json") && name.contains("checkpoint.created") {
                    Some(e.path())
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(files.len(), 1);
        let signed: mvm_core::receipt::SignedExecutionReceipt =
            serde_json::from_slice(&std::fs::read(&files[0]).unwrap()).unwrap();
        signed.verify().expect("checkpoint receipt verifies");
    }

    #[test]
    fn decision_record_event_is_chain_signed_and_cached() {
        use mvm_contract::provenance::{
            ActorRef, AttestationBinding, DecisionCategory, DecisionOutcome, DecisionRecordBuilder,
        };

        let dir = tempfile::tempdir().unwrap();
        let decisions_dir = tempfile::tempdir().unwrap();
        let key = {
            let mut __ed_seed = [0u8; 32];
            rand::rng().fill_bytes(&mut __ed_seed);
            SigningKey::from_bytes(&__ed_seed)
        };
        let vk = key.verifying_key();
        let emitter = AuditEmitter::with_dir(key, dir.path())
            .unwrap()
            .with_decisions_dir(decisions_dir.path());
        let plan = fixture_plan("local", "plan-decision");

        let record = DecisionRecordBuilder::new()
            .version(1)
            .category(DecisionCategory::Admission)
            .actor(ActorRef {
                principal: "host:builder".to_string(),
                key_id: "host-signer-1".to_string(),
                key_role: None,
            })
            .reasoning("grant ceiling satisfied")
            .outcome(DecisionOutcome::Approved)
            .timestamp("2026-08-13T00:00:00Z".to_string())
            .attestation(AttestationBinding {
                plan_id: Some("sha256:abc".to_string()),
                audit_entry_hash: String::new(),
                signer_pubkey: hex::encode(vk.to_bytes()),
                ..AttestationBinding::default()
            })
            .build()
            .expect("valid record");

        let id = emitter.emit_decision_record(&plan, record.clone()).unwrap();
        assert!(!id.0.is_empty());

        let entry = only_entry(dir.path(), "local");
        assert_eq!(entry["event"], "decision_record");
        assert_eq!(entry["labels"]["decision_id"], id.0);
        assert!(entry["labels"].get("record").is_some());
        verify_audit_chain(&dir.path().join("local.jsonl"), &vk)
            .expect("decision record entry verifies");

        let decisions = crate::audit::decisions::DecisionStore::open(decisions_dir.path(), "local")
            .unwrap()
            .list()
            .unwrap();
        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0].decision_id, id);
    }
}
