//! Turning a parked durable agent session back into an admitted one.
//!
//! Lives here rather than beside the session store because it is the lowest
//! point in the graph that can reach both halves it needs: `mvm-hostd` depends
//! on `mvm-runtime` (the session store, the checkpoint store) and owns the
//! admission gate, and the dependency does not run the other way.
//!
//! A resume is a re-admission, not an inheritance. The parked record carries
//! the session's identity — its id, generation, journal cursor, approval head,
//! resume point — and nothing about the workload, so the caller supplies the
//! image, kernel and size in a [`ResumePlanMaterial`]. Keeping that split is
//! what stops the session record drifting into a second, staler copy of the
//! plan.

use anyhow::{Context, Result};
use std::path::Path;

use mvm_contract::plan::types::AuditLabels;
use mvm_contract::protocol::agent_session::AgentSessionId;
use mvm_core::checkpoint::{ApprovalHead, CheckpointMeta, ROOTFS_BLOB, ROOTFS_VERITY_BLOB};
use mvm_core::plan::{
    AttestationMode, PlanSeccompTier, SecretReleasePolicy, SynthesisInput, Variant,
};
use mvm_core::protocol::vm_backend::VmStartConfig;
use mvm_runtime::agent_session::{
    AgentSessionRecord, AgentSessionStore, SandboxResidency, StorageTier,
};
use mvm_runtime::checkpoint::CheckpointStore;

use crate::plan_admission::{AdmittedPlan, Clock, InMemoryNonceLedger, RunPosture};

/// What a resume needs that the session record deliberately does not hold.
///
/// These describe the workload rather than the session: they change on their
/// own schedule (a rebuilt image, a resized sandbox), and recording them in the
/// session record would make it a duplicate of the plan that has to be kept in
/// step with one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResumePlanMaterial {
    /// Runtime profile the resumed sandbox boots on (`hvf`, `libkrun`, ...).
    pub backend_name: String,
    /// Image reference recorded in the signed plan.
    pub image_name: String,
    /// Lowercase-hex SHA-256 of the rootfs the resume boots.
    pub image_sha256: String,
    /// Lowercase-hex SHA-256 of the kernel, or `None` for a backend that
    /// carries its own.
    pub kernel_sha256: Option<String>,
    pub cpus: u32,
    pub mem_mib: u64,
}

/// Build the plan-synthesis input for resuming `record`.
///
/// Follows the local-run path's field choices ([`crate::run`]) everywhere a
/// resume does not deliberately differ, so the two admission paths cannot drift
/// into disagreeing about what a conservative default is.
#[must_use]
pub fn synthesis_for_resume<'a>(
    record: &'a AgentSessionRecord,
    material: &'a ResumePlanMaterial,
) -> SynthesisInput<'a> {
    SynthesisInput {
        // The session, not the parent sandbox. A resumed workload that ran
        // under the previous residency's name would attribute its actions to a
        // residency that had already ended.
        vm_name: record.session_id.as_str(),
        // The same local-run tenant, shared with `crate::run` rather than
        // copied, so both paths admit under one label.
        tenant: Some(crate::run::LOCAL_TENANT),
        backend_name: &material.backend_name,
        image_name: &material.image_name,
        image_sha256: &material.image_sha256,
        kernel_sha256: material.kernel_sha256.as_deref(),
        image_cosign_bundle: None,
        intent: None,
        seccomp_tier: PlanSeccompTier::Standard,
        network_policy_ref: None,
        fs_policy_ref: None,
        egress_policy_ref: None,
        tool_policy_ref: None,
        secret_release: SecretReleasePolicy::None,
        secrets: Vec::new(),
        audit_event_prefix: None,
        network_mode: Default::default(),
        ingress: Vec::new(),
        // The local-run path takes the caller's grants; a resume has no
        // surface to declare any, so it declares none and the host ceiling
        // has nothing to measure.
        grants: None,
        cpus: material.cpus,
        mem_mib: material.mem_mib,
        disk_mib: 0,
        // Taken from the local-run path unchanged: nothing about a resume
        // makes a different boot timeout right.
        boot_timeout_secs: 60,
        // A resumed session outlives the call that admits it — that is what
        // being durable means — so the teardown intent a run-to-completion
        // workload records would be wrong here.
        destroy_on_exit: false,
        bundle_pin: None,
        deps_volume: None,
        // The local-run path projects its caller's volumes; a resume carries
        // none, so no host-fs share is admitted.
        shares: Vec::new(),
        redaction: Default::default(),
        reversible_replacement: Default::default(),
        audit_labels: session_audit_labels(record),
        agent_verbs: None,
        services: Vec::new(),
        stream_edges: Vec::new(),
        stream_retention: Default::default(),
        extensions: Vec::new(),
        attestation_mode: AttestationMode::Noop,
    }
}

/// The session identity every audit entry under this plan should carry.
///
/// `SynthesisInput.audit_labels` serializes inside the signed payload and is
/// inherited by each chain-signed entry, so this is what lets a reader of the
/// chain say *which residency* acted. Without it two resumes of one session
/// produce plans differing only by nonce and validity window.
fn session_audit_labels(record: &AgentSessionRecord) -> AuditLabels {
    let mut labels = AuditLabels::new();
    labels.insert(
        "session_id".to_string(),
        record.session_id.as_str().to_string(),
    );
    // The generation this resume *opens*, not the one on the record. Synthesis
    // runs before the transition, so the record still holds the parent's — and
    // `AgentSessionRecord::resume` is about to write this value. Labelling the
    // parent's would put every audit entry one residency behind, which is
    // worse than carrying no label at all.
    labels.insert(
        "session_generation".to_string(),
        (record.generation + 1).to_string(),
    );
    // Both of the following are omitted rather than blanked when absent: an
    // empty string reads in the chain as a value that was checked and found
    // empty, where a missing key reads as a value that was never there.
    if let Some(parent) = record.parent_checkpoint.as_ref() {
        labels.insert("session_parent_checkpoint".to_string(), parent.to_string());
    }
    if let Some(head) = record.approval_head.as_ref() {
        labels.insert("session_approval_head".to_string(), head.to_string());
    }
    labels
}

/// What a resume is asked for, in one struct.
///
/// A params struct rather than six positional arguments: the values are three
/// borrowed references, two integers and an option, and a positional call could
/// transpose the two integers with nothing to catch it.
pub struct ResumeRequest<'a> {
    /// Which parked session to bring back.
    pub session_id: &'a AgentSessionId,
    /// The generation the caller believes the record is at. A record that has
    /// moved on is one the caller is no longer describing, and the store's
    /// fence refuses it.
    pub expected_generation: u64,
    /// The approval ledger's head right now. The store refuses when it differs
    /// from the head recorded at park time, so a resume cannot silently run
    /// under grants the session was never admitted for.
    pub current_approval_head: Option<&'a ApprovalHead>,
    /// The workload half of the plan, which the session record does not hold.
    pub material: &'a ResumePlanMaterial,
    /// Host signer key directory. `None` uses the host's canonical one.
    pub host_signer_keys_dir: Option<&'a Path>,
    pub now_unix: u64,
}

/// A session brought back into residency: the advanced record, and the plan
/// that authorized it.
#[derive(Debug)]
pub struct ResumedSession {
    /// The record as written, at the new generation.
    pub record: AgentSessionRecord,
    /// The plan this residency was admitted under. Holding one is proof
    /// admission ran — it cannot be built any other way.
    pub admitted: AdmittedPlan,
    /// The resume point, as it was read and verified during this resume.
    ///
    /// Handed back rather than left for a caller to re-read: a caller that
    /// resolved it again would be building on bytes nobody checked in between,
    /// which is the gap the verification exists to close.
    pub resume_point: CheckpointMeta,
}

/// The posture a resume is admitted under.
///
/// `without_backend` because this function stops at an admitted plan and does
/// not boot: there is no backend object to measure a declared grant against,
/// and `RunPosture`'s own doc says guessing a tier from a label is the mistake
/// that lets a mislabelled plan pick its own resource controls. `Dev` because
/// the resume path has no way yet to carry a sealed-production request — when
/// it grows one, this becomes a field of `ResumeRequest` rather than a constant.
fn resume_posture() -> RunPosture {
    RunPosture::without_backend(Variant::Dev)
}

/// Turn a parked session back into an admitted one.
///
/// Admission runs before the record transition, deliberately: no step that can
/// refuse runs after the record has moved, so a refusal leaves the session
/// parked and resumable rather than half-resumed. A record advanced to a
/// generation that no admitted plan corresponds to would be worse than no
/// resume at all — the session would claim a residency nothing authorized.
///
/// Admission is not literally the last fallible step: the store applies its
/// generation and approval-head fences inside `resume`, after this function has
/// already signed a plan. That is the right place for them — they are the
/// store's invariants and duplicating them here is how the two copies start
/// disagreeing — and it costs nothing that matters, because the store writes
/// only on success. The plan admitted for a fence-refused resume is dropped
/// unused; it reaches no backend.
///
/// A resume is a re-admission and not an inheritance: the plan it admits names
/// this session, is freshly signed, and carries its own nonce and validity
/// window. Nothing of the previous residency's authority carries over.
pub fn resume_session(
    sessions: &AgentSessionStore,
    checkpoints: &CheckpointStore,
    req: &ResumeRequest<'_>,
    clock: &dyn Clock,
    ledger: &InMemoryNonceLedger,
) -> Result<ResumedSession> {
    let record = sessions.load(req.session_id)?;
    if record.state != SandboxResidency::Hibernated {
        anyhow::bail!(
            "session {} is not parked, so it cannot be resumed",
            req.session_id.as_str()
        );
    }

    // Resolve and verify the resume point before building anything from it: a
    // plan synthesized over a tampered checkpoint would be a correctly signed
    // statement about the wrong bytes.
    let digest = record.parent_checkpoint.as_ref().ok_or_else(|| {
        anyhow::anyhow!(
            "session {} records no resume point",
            req.session_id.as_str()
        )
    })?;
    let parent = checkpoints
        .by_digest(digest)?
        .ok_or_else(|| anyhow::anyhow!("resume point {digest} is not in the checkpoint store"))?;
    // `by_digest` matches on the record's stored `meta_digest` as written, and
    // `verify_content` hashes blobs against the record's stored
    // `content[].sha256` as written — both trust the same file a tamperer who
    // can edit a blob can also edit. Recomputing the digest from the record's
    // own fields closes that: a rewritten `content[].sha256` moves
    // `compute_meta_digest()` away from the stored `meta_digest`, so the two
    // no longer agree and this refuses before content is even hashed. Content
    // verification alone catches neither a tampered blob (this closes that)
    // nor an unaudited checkpoint reliably — the latter needs lineage
    // verification against a signed chain anchor, which stays absent: no
    // caller here holds one yet.
    let recomputed = parent.compute_meta_digest();
    if recomputed != parent.meta_digest {
        anyhow::bail!(
            "resume point {digest} failed integrity: stored meta_digest {} does not match its own recomputed digest {} (record edited after it was sealed)",
            parent.meta_digest,
            recomputed
        );
    }
    mvm_runtime::checkpoint::verify_content(checkpoints, &parent)?;

    let input = synthesis_for_resume(&record, req.material);
    let admitted = crate::plan_admission::admit_for_run(
        &input,
        clock,
        ledger,
        req.host_signer_keys_dir,
        None,
        resume_posture(),
    )?;

    // Only now: the transition. Everything above can refuse without having
    // moved the record.
    let record = sessions.resume(
        req.session_id,
        req.expected_generation,
        req.current_approval_head,
        req.now_unix,
    )?;

    Ok(ResumedSession {
        record,
        admitted,
        resume_point: parent,
    })
}

/// What a cold boot needs beyond the session record and its resume point.
///
/// A params struct rather than six positional arguments: four of the fields are
/// borrows and two of those are paths, which a positional call could transpose
/// with nothing to catch it.
pub struct ColdBootParams<'a> {
    /// The session being resumed. Supplies the VM identity and nothing else — a
    /// cold boot takes its shape from the resume point and the material.
    pub record: &'a AgentSessionRecord,
    /// The resume point, already integrity-checked by the caller. Taken as a
    /// verified value rather than a digest so this cannot be reached with an
    /// unverified one.
    pub parent: &'a CheckpointMeta,
    /// Where the resume point's blobs are read from.
    pub checkpoints: &'a CheckpointStore,
    /// The workload half of the plan, so the launch config and the signed plan
    /// agree on size.
    pub material: &'a ResumePlanMaterial,
    /// The session's own state directory: the resume point's blobs are staged
    /// here and the boot reads them from here.
    pub state_dir: &'a Path,
    /// Kernel this boot loads, or `None` for a backend carrying its own. When
    /// the material names a `kernel_sha256`, the plan pins the digest of the
    /// file at this path and the admitted-environment gate refuses a mismatch.
    /// On x86 Firecracker the VMM loads an ELF sibling extracted from this
    /// file, so the pin covers the source file rather than the bytes that
    /// execute; callers that need an execute-time pin must pin the ELF.
    pub kernel_path: Option<&'a Path>,
}

/// Build the launch config for a cold-tier resume: a fresh boot from the resume
/// point's filesystem, under the session's own identity.
///
/// Follows `fork_checkpoint`'s mechanism, which is the fs_quick branch — clone
/// every blob of the parent's content manifest out of the checkpoint store into
/// a directory the child owns, and boot from those copies. Its vm_full sibling
/// is the memory-restore path, which is what a `Parked` session would need and
/// is not what a cold boot does.
///
/// The staging is not incidental. Naming the store's own blob as the boot rootfs
/// would let a running guest write through to the checkpoint, so the next resume
/// of the same session would fail its integrity check against bytes the guest
/// itself changed. The session boots from its own copy for the same reason a
/// fork does.
pub fn cold_boot_config(params: ColdBootParams<'_>) -> Result<VmStartConfig> {
    if !params
        .parent
        .content
        .iter()
        .any(|blob| blob.name == ROOTFS_BLOB)
    {
        anyhow::bail!(
            "resume point {} names no {ROOTFS_BLOB} blob, so a cold boot has nothing to boot from",
            params.parent.meta_digest
        );
    }

    let verity = has_verity_pair(params.parent)?;
    stage_resume_point(params.checkpoints, params.parent, params.state_dir)?;

    let memory_mib = u32::try_from(params.material.mem_mib).map_err(|_| {
        anyhow::anyhow!(
            "resume material asks for {} MiB, which does not fit the launch config's memory field",
            params.material.mem_mib
        )
    })?;

    let mut config = VmStartConfig {
        // The session id, which is also the admitted plan's `vm_name`, so the
        // started VM and the plan that authorized it agree on identity.
        name: params.record.session_id.as_str().to_string(),
        rootfs_path: params.state_dir.join(ROOTFS_BLOB).display().to_string(),
        kernel_path: params.kernel_path.map(|k| k.display().to_string()),
        cpus: params.material.cpus,
        memory_mib,
        ..VmStartConfig::default()
    };

    if verity {
        config.verity_path = Some(
            params
                .state_dir
                .join(ROOTFS_VERITY_BLOB)
                .display()
                .to_string(),
        );
        config.roothash = Some(read_roothash(params.state_dir)?);
    }

    // A runtime-lean rootfs needs the guest agent from the overlay. The cache
    // resolver uses the current host package version, matching the fresh-run path.
    crate::run::attach_runtime_overlay_from_cache(&mut config, &params.material.backend_name)?;

    Ok(config)
}

/// True when the resume point carries a complete dm-verity sidecar set.
///
/// A checkpoint with only one of the two files is malformed: the hash tree is
/// useless without the root hash, and a root hash without a tree cannot verify
/// anything. Refusing here keeps the failure close to the data declaration.
fn has_verity_pair(parent: &CheckpointMeta) -> Result<bool> {
    let has_verity = parent
        .content
        .iter()
        .any(|blob| blob.name == ROOTFS_VERITY_BLOB);
    let has_roothash = parent
        .content
        .iter()
        .any(|blob| blob.name == ROOTFS_ROOTHASH_BLOB);
    anyhow::ensure!(
        has_verity == has_roothash,
        "resume point {} has an incomplete dm-verity sidecar set (verity={verity}, roothash={rothash})",
        parent.meta_digest,
        verity = has_verity,
        rothash = has_roothash
    );
    Ok(has_verity)
}

/// Read the lowercase-hex root hash from the staged `rootfs.roothash` file.
fn read_roothash(state_dir: &Path) -> Result<String> {
    let path = state_dir.join(ROOTFS_ROOTHASH_BLOB);
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("reading root hash at {}", path.display()))?;
    Ok(text.trim().to_string())
}

const ROOTFS_ROOTHASH_BLOB: &str = "rootfs.roothash";

/// Clone every blob of `parent`'s content manifest into `state_dir`.
///
/// Every blob rather than only the rootfs: the manifest carries the guest
/// sidecars a sealed image needs beside its rootfs, and staging only the rootfs
/// would leave them where nothing could later name them.
///
/// A stale copy left by an earlier residency is removed first. It is not the
/// resume point's bytes — the guest that wrote it has ended — and cloning onto
/// an existing file refuses.
fn stage_resume_point(
    checkpoints: &CheckpointStore,
    parent: &CheckpointMeta,
    state_dir: &Path,
) -> Result<()> {
    std::fs::create_dir_all(state_dir)
        .with_context(|| format!("creating session state dir {}", state_dir.display()))?;
    let content_dir = checkpoints.content_dir(&parent.id);
    for blob in &parent.content {
        let dst = state_dir.join(&blob.name);
        if dst.exists() {
            std::fs::remove_file(&dst)
                .with_context(|| format!("removing stale {}", dst.display()))?;
        }
        mvm_runtime::base::cow::clone_rootfs_for_instance(&content_dir.join(&blob.name), &dst)
            .with_context(|| format!("staging resume-point blob {}", blob.name))?;
    }
    Ok(())
}

/// Labels that ride a `session.resumed` audit entry.
///
/// Kept in the hostd module rather than the CLI so both the boot and no-boot
/// resume paths can carry the same fields, and so a boot that fails after the
/// record moved still writes the same entry shape.
fn resume_audit_labels(
    record: &AgentSessionRecord,
    admitted: &AdmittedPlan,
) -> Vec<(String, String)> {
    vec![
        (
            "resumed_session".to_string(),
            record.session_id.as_str().to_string(),
        ),
        (
            "resumed_at_generation".to_string(),
            record.generation.to_string(),
        ),
        ("resumed_plan_id".to_string(), admitted.plan_id().0.clone()),
    ]
}

/// Emit `session.resumed` for a transition that already happened.
///
/// Best-effort at the call site: a failure to sign the chain is logged but does
/// not stop the boot, because the chain is a witness to a record that is already
/// on disk, not a precondition for it.
fn emit_session_resumed(
    emitter: &crate::audit::emitter::AuditEmitter,
    record: &AgentSessionRecord,
    admitted: &AdmittedPlan,
) {
    if let Err(error) =
        emitter.emit_session_resumed(admitted.plan(), resume_audit_labels(record, admitted))
    {
        tracing::warn!(
            session_id = record.session_id.as_str(),
            plan_id = %admitted.plan_id().0,
            "session resume was not recorded in the audit chain: {error:#}"
        );
    }
}

/// What a resume-and-boot is asked for: the resume itself, plus the launch
/// shape the session record does not hold.
pub struct ResumeBootRequest<'a> {
    /// The resume half, unchanged — this path admits through exactly the same
    /// request a boot-less resume does.
    pub resume: &'a ResumeRequest<'a>,
    /// The backend that boots the resumed sandbox.
    pub backend: &'a mvm_runtime::AnyBackend,
    /// The session's own state directory, where the resume point is staged.
    pub state_dir: &'a Path,
    /// Kernel this boot loads, or `None` for a backend carrying its own.
    pub kernel_path: Option<&'a Path>,
    /// Optional chain-signed emitter for the launch records.
    pub emitter: Option<&'a crate::audit::emitter::AuditEmitter>,
}

/// A resumed session that is also running: the advanced record and the machine.
#[derive(Debug)]
pub struct BootedSession {
    /// The record as written, at the new generation.
    pub record: AgentSessionRecord,
    /// The started VM, carrying the plan it was admitted under. Holding one is
    /// proof both admission and the shared post-admission gates ran.
    pub started: crate::plan_admission::StartedMachine,
}

/// Refuse a tier whose resume path is not built.
///
/// `Cold` alone: it resumes by a fresh boot, which is what this path does.
/// Cold-booting a `Parked` session would silently discard the memory image the
/// operator believes is being restored — data loss reported as success — and
/// `Resident` would abandon a live paused process rather than claim it. Both
/// refuse by name so the operator learns which path is missing rather than
/// getting a sandbox that lost their work.
///
/// A record with no tier at all refuses for the same reason: nothing here can
/// tell whether a memory image is waiting for it.
fn require_cold_tier(record: &AgentSessionRecord) -> Result<()> {
    match record.storage_tier {
        Some(StorageTier::Cold) => Ok(()),
        Some(StorageTier::Parked) => anyhow::bail!(
            "session {} is parked at the parked tier, whose memory-image restore is not built; \
             booting it cold would discard the memory image it was parked with",
            record.session_id.as_str()
        ),
        Some(StorageTier::Resident) => anyhow::bail!(
            "session {} is parked at the resident tier, whose standby claim is not built; \
             booting it cold would abandon the paused sandbox still holding its memory",
            record.session_id.as_str()
        ),
        None => anyhow::bail!(
            "session {} records no storage tier, so there is no way to tell whether a memory \
             image is waiting for it; refusing rather than booting cold",
            record.session_id.as_str()
        ),
    }
}

/// Resume a parked session and boot it: admit, transition, **then** start.
///
/// The record moves before the VM does. Both orders can fail, and the question
/// is which wreckage an operator can act on. A VM started before the record
/// moved is an orphan: the session still reads as parked, nothing associates the
/// running sandbox with it, and no later operation will reap it. A record moved
/// before a boot that then failed is an active session with nothing running —
/// visible in `agent-session ls`, attributable to a signed plan, and something
/// the operator can retry or park again. The second is recoverable and the first
/// is not, so the transition goes first.
///
/// The tier gate runs before either, so a refusal for an unbuilt tier leaves the
/// record exactly as parked — the same property `resume_session` holds for its
/// own refusals.
///
/// Only the `Cold` tier boots. See [`require_cold_tier`].
pub fn resume_and_boot(
    sessions: &AgentSessionStore,
    checkpoints: &CheckpointStore,
    req: &ResumeBootRequest<'_>,
    clock: &dyn Clock,
    ledger: &InMemoryNonceLedger,
) -> Result<BootedSession> {
    // Before anything that can move the record or sign a plan: a tier this path
    // cannot serve must cost nothing.
    //
    // Only for a parked record. A session that is not parked has no meaningful
    // tier — nothing put one there — and `resume_session` refuses it a step
    // later with the reason that actually helps, rather than this gate
    // reporting a missing tier for a session whose real problem is that it is
    // still running.
    let record = sessions.load(req.resume.session_id)?;
    if record.state == SandboxResidency::Hibernated {
        require_cold_tier(&record)?;
    }

    let resumed = resume_session(sessions, checkpoints, req.resume, clock, ledger)?;

    // The record moved before this point. Log the transition in the chain now,
    // before anything that can fail to boot: a boot failure must not erase the
    // fact that a signed plan authorized the transition.
    if let Some(emitter) = req.emitter {
        emit_session_resumed(emitter, &resumed.record, &resumed.admitted);
    }

    let config = cold_boot_config(ColdBootParams {
        record: &resumed.record,
        parent: &resumed.resume_point,
        checkpoints,
        material: req.resume.material,
        state_dir: req.state_dir,
        kernel_path: req.kernel_path,
    })?;

    // The shared post-admission tail, not a second admission: the plan
    // `resume_session` signed is the one this boots under, so there is exactly
    // one signed authority for this residency.
    let started =
        crate::plan_admission::start_admitted(crate::plan_admission::StartAdmittedParams {
            backend: req.backend,
            admitted: resumed.admitted,
            config,
            policy_bundle: None,
            emitter: req.emitter,
            assurance: None,
        })?;

    Ok(BootedSession {
        record: resumed.record,
        started,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_contract::grants::ceiling::GrantCeiling;
    use mvm_contract::protocol::agent_session::AgentSessionId;
    use mvm_core::checkpoint::{CheckpointDigest, CheckpointId, CheckpointMeta};
    use mvm_core::util::test_env::TestEnv;
    use mvm_runtime::agent_session::{
        AgentSessionRecord, AgentSessionStore, ParkInput, ParkReason, SandboxResidency,
    };
    use mvm_runtime::checkpoint::{CaptureFsQuickParams, CheckpointStore, capture_fs_quick};
    use std::path::Path;
    use tempfile::TempDir;

    /// A well-formed approval head, distinguished by its repeated byte.
    fn head_of(byte: &str) -> ApprovalHead {
        ApprovalHead::parse(format!("sha256:{}", byte.repeat(32))).unwrap()
    }

    /// A session that has been parked and names a resume point.
    ///
    /// Goes through the public `park` transition rather than writing
    /// `Hibernated` into the literal, so the fixture cannot drift into a state
    /// the state machine would never produce.
    fn parked_record(id: &str) -> AgentSessionRecord {
        parked_record_at(id, ParkReason::ApprovalWait)
    }

    /// The same fixture parked for a given reason, which is what picks the
    /// storage tier. Going through `select_tier` rather than writing a tier into
    /// the literal keeps the fixture on the state machine's own mapping.
    fn parked_record_at(id: &str, reason: ParkReason) -> AgentSessionRecord {
        let active = AgentSessionRecord {
            session_id: AgentSessionId::parse(id).unwrap(),
            generation: 1,
            state: SandboxResidency::Active,
            members: vec!["vm-alpha".to_string()],
            parent_checkpoint: Some(
                CheckpointDigest::parse(format!("sha256:{}", "1a".repeat(32))).unwrap(),
            ),
            created_unix: 1_755_000_000,
            updated_unix: 1_755_000_000,
            journal_cursor: 7,
            approval_head: None,
            storage_tier: None,
            park_reason: None,
        };
        active
            .park(
                &ParkInput {
                    reason,
                    journal_cursor: 7,
                    // A real recorded head, so a request that passes the wrong
                    // one — or none — has something to be refused against.
                    approval_head: Some(head_of("ab")),
                },
                1_755_000_100,
            )
            .unwrap()
    }

    fn material() -> ResumePlanMaterial {
        ResumePlanMaterial {
            backend_name: "hvf".to_string(),
            image_name: "demo".to_string(),
            image_sha256: "ab".repeat(32),
            kernel_sha256: Some("cd".repeat(32)),
            cpus: 2,
            mem_mib: 512,
        }
    }

    #[test]
    fn the_plan_is_named_for_the_session_not_the_parent() {
        // A resume must not inherit the parent's identity: the plan it admits
        // names this session, so anything the resumed sandbox does is
        // attributable to this residency rather than the one before it.
        let rec = parked_record("sess-alpha");
        let m = material();
        let input = synthesis_for_resume(&rec, &m);
        assert_eq!(input.vm_name, "sess-alpha");
    }

    #[test]
    fn the_material_fields_reach_the_plan_input() {
        let rec = parked_record("sess-alpha");
        let m = material();
        let input = synthesis_for_resume(&rec, &m);
        assert_eq!(input.backend_name, "hvf");
        assert_eq!(input.image_sha256, m.image_sha256);
        assert_eq!(input.kernel_sha256, m.kernel_sha256.as_deref());
        assert_eq!(input.cpus, 2);
        assert_eq!(input.mem_mib, 512);
        assert!(input.ingress.is_empty());
    }
    /// A host reading its own isolated config, so a ceiling assertion measures
    /// the directory this test wrote and never the developer's real one.
    ///
    /// Mirrors `plan_admission`'s `host_with_ceiling`, which is `#[cfg(test)]`
    /// in a sibling module and so not importable here.
    fn isolated_host(ceiling: GrantCeiling) -> (TestEnv, TempDir) {
        let home = tempfile::tempdir().expect("scratch mvm home");
        let mut env = TestEnv::new();
        env.isolate_mvm_home(home.path());
        let cfg = mvm_core::user_config::MvmConfig {
            max_cpu_millicores: ceiling.max_cpu_millicores,
            max_memory_mib: ceiling.max_memory_mib,
            max_wall_clock_secs: ceiling.max_wall_clock_secs,
            ..mvm_core::user_config::MvmConfig::default()
        };
        mvm_core::user_config::save(&cfg, None).expect("writing the host config");
        // Precondition, not decoration: if isolation did not hold, the ceiling
        // every assertion below rests on is some other directory's.
        assert_eq!(
            mvm_core::user_config::load(None).grant_ceiling(),
            ceiling,
            "the isolated host must read back the ceiling it was configured with"
        );
        (env, home)
    }

    /// Isolate the host and install the runtime artifact a real HVF cold boot
    /// now requires. The fixture goes through the shared overlay reader and
    /// cache installer so the resolver verifies the same ext4 payload,
    /// checksums, version, and sidecars as production.
    fn isolated_host_with_runtime_overlay() -> (TestEnv, TempDir) {
        use mvm_build::runtime_overlay::{InstallOptions, install_overlay_into_cache};
        use mvm_fs::ext4::Node;
        use mvm_fs::overlay::{REQUIRED_OVERLAY_GUEST_PATHS, read_overlay_artifact_from_dir};

        let (env, home) = isolated_host(GrantCeiling::default());
        let source = home.path().join("runtime-overlay-source");
        std::fs::create_dir_all(&source).expect("create runtime overlay source");
        let nodes = REQUIRED_OVERLAY_GUEST_PATHS
            .iter()
            .map(|path| Node::File {
                path: path.to_string(),
                mode: 0o755,
                data: b"session-resume-runtime-stub".to_vec(),
                xattrs: Vec::new(),
            })
            .collect();
        let ext4 = mvm_fs::ext4::build_image(nodes).expect("build runtime overlay fixture");
        std::fs::write(source.join("overlay.ext4"), ext4).expect("write overlay ext4");
        std::fs::write(source.join("overlay.verity"), b"verity-sidecar")
            .expect("write overlay verity sidecar");
        std::fs::write(
            source.join("overlay.roothash"),
            format!("{}\n", "ab".repeat(32)),
        )
        .expect("write overlay root hash");
        std::fs::write(
            source.join("VERSION"),
            format!("{}\n", env!("CARGO_PKG_VERSION")),
        )
        .expect("write overlay version");

        let artifact = read_overlay_artifact_from_dir(&source, std::env::consts::ARCH)
            .expect("read runtime overlay fixture");
        install_overlay_into_cache(
            &artifact,
            &home.path().join("cache"),
            &InstallOptions { overwrite: true },
        )
        .expect("install runtime overlay fixture");
        (env, home)
    }

    /// Stage a checkpoint whose content blob is really on disk and really
    /// hashes to what its record says, so `verify_content` has something to
    /// pass on and something to be tampered out from under.
    ///
    /// Goes through the public `capture_fs_quick` — the same call the
    /// checkpoint module's own fixtures use — rather than hand-writing a
    /// `meta.json` beside a file.
    fn seed_checkpoint(store: &CheckpointStore, tmp: &Path, id: &str) -> CheckpointMeta {
        let rootfs = tmp.join("rootfs.ext4");
        std::fs::write(&rootfs, b"fake-ext4-bytes").unwrap();
        capture_fs_quick(
            store,
            CaptureFsQuickParams {
                id: CheckpointId::new(id),
                vm_name: "vm-alpha".into(),
                rootfs,
                supervisor_config_digest: "d".into(),
                runtime_overlay_version: None,
                tag: None,
                created_unix: 1,
                quiesced: true,
                grants: None,
            },
        )
        .unwrap()
    }

    /// The two stores and the signer dir a resume runs against.
    struct Fixture {
        tmp: TempDir,
        sessions: AgentSessionStore,
        checkpoints: CheckpointStore,
        keys: TempDir,
    }

    impl Fixture {
        fn new() -> Self {
            let tmp = tempfile::tempdir().unwrap();
            Self {
                sessions: AgentSessionStore::at(tmp.path().join("sessions")),
                checkpoints: CheckpointStore::at(tmp.path().join("checkpoints")),
                keys: tempfile::tempdir().unwrap(),
                tmp,
            }
        }

        fn request<'a>(
            &'a self,
            record: &'a AgentSessionRecord,
            material: &'a ResumePlanMaterial,
        ) -> ResumeRequest<'a> {
            ResumeRequest {
                session_id: &record.session_id,
                expected_generation: record.generation,
                current_approval_head: record.approval_head.as_ref(),
                material,
                host_signer_keys_dir: Some(self.keys.path()),
                now_unix: 1_755_000_200,
            }
        }

        fn resume(&self, req: &ResumeRequest<'_>) -> anyhow::Result<ResumedSession> {
            resume_session(
                &self.sessions,
                &self.checkpoints,
                req,
                &crate::plan_admission::SystemClock,
                &crate::plan_admission::InMemoryNonceLedger::new(),
            )
        }
    }

    /// Assert the on-disk record is still exactly as parked. That a refusal is
    /// observable this way is the whole point of admitting last.
    fn assert_still_parked(fx: &Fixture, record: &AgentSessionRecord) {
        let on_disk = fx.sessions.load(&record.session_id).unwrap();
        assert_eq!(on_disk.state, SandboxResidency::Hibernated);
        assert_eq!(on_disk.generation, record.generation);
        assert_eq!(
            on_disk, *record,
            "a refused resume must not touch the record"
        );
    }

    #[test]
    fn a_resume_admits_a_plan_and_advances_the_generation() {
        let (_env, _home) = isolated_host(GrantCeiling::default());
        let fx = Fixture::new();
        let parent = seed_checkpoint(&fx.checkpoints, fx.tmp.path(), "cp-parent");

        let mut rec = parked_record("sess-alpha");
        rec.parent_checkpoint = Some(parent.meta_digest.clone());
        fx.sessions.write(&rec).unwrap();

        let m = material();
        let resumed = fx
            .resume(&fx.request(&rec, &m))
            .expect("a parked session with an intact resume point resumes");

        assert_eq!(resumed.record.state, SandboxResidency::Active);
        assert_eq!(
            resumed.record.generation,
            rec.generation + 1,
            "a resume opens the next residency"
        );
        assert!(!resumed.admitted.plan_id().0.is_empty());
        assert_eq!(resumed.admitted.plan().workload.0, "sess-alpha");
        // And the transition is durable, not merely returned.
        let on_disk = fx.sessions.load(&rec.session_id).unwrap();
        assert_eq!(on_disk.state, SandboxResidency::Active);
        assert_eq!(on_disk.generation, rec.generation + 1);
    }

    #[test]
    fn the_generation_label_matches_the_generation_the_transition_writes() {
        // The label is computed before the transition, so it is a prediction of
        // what `AgentSessionRecord::resume` will write. Nothing couples the two
        // — if the increment ever changes, the label drifts silently and every
        // audit entry names the wrong residency. This reads both back off one
        // real resume and compares them.
        let (_env, _home) = isolated_host(GrantCeiling::default());
        let fx = Fixture::new();
        let parent = seed_checkpoint(&fx.checkpoints, fx.tmp.path(), "cp-parent");

        let mut rec = parked_record("sess-alpha");
        rec.parent_checkpoint = Some(parent.meta_digest.clone());
        fx.sessions.write(&rec).unwrap();

        let m = material();
        let resumed = fx.resume(&fx.request(&rec, &m)).unwrap();
        assert_eq!(
            resumed
                .admitted
                .plan()
                .audit_labels
                .get("session_generation"),
            Some(&resumed.record.generation.to_string()),
            "the signed label must name the generation the record actually took"
        );
    }

    #[test]
    fn a_missing_parent_checkpoint_refuses_before_admission() {
        let (_env, _home) = isolated_host(GrantCeiling::default());
        let fx = Fixture::new();

        // The fixture's resume point is a digest the store has never held.
        let rec = parked_record("sess-alpha");
        fx.sessions.write(&rec).unwrap();

        let m = material();
        let err = fx
            .resume(&fx.request(&rec, &m))
            .expect_err("a resume point absent from the store must refuse");
        assert!(
            err.to_string().contains("checkpoint store"),
            "the refusal must name what was missing: {err}"
        );
        assert_still_parked(&fx, &rec);
    }

    #[test]
    fn a_tampered_parent_checkpoint_refuses_before_admission() {
        let (_env, _home) = isolated_host(GrantCeiling::default());
        let fx = Fixture::new();
        let parent = seed_checkpoint(&fx.checkpoints, fx.tmp.path(), "cp-parent");

        let mut rec = parked_record("sess-alpha");
        rec.parent_checkpoint = Some(parent.meta_digest.clone());
        fx.sessions.write(&rec).unwrap();

        // Byte-flip the content blob the stored record still vouches for.
        let blob = fx.checkpoints.content_dir(&parent.id).join("rootfs.ext4");
        std::fs::write(&blob, b"tampered").unwrap();

        let m = material();
        let err = fx
            .resume(&fx.request(&rec, &m))
            .expect_err("a tampered resume point must refuse");
        assert!(
            err.to_string().contains("integrity"),
            "the refusal must be the integrity check: {err}"
        );
        assert_still_parked(&fx, &rec);
    }

    #[test]
    fn a_blob_tampered_alongside_its_recorded_hash_still_refuses() {
        // The attack `verify_content` alone cannot catch: an attacker who can
        // edit a content blob can edit the record beside it. Rewrite the
        // blob's recorded sha256 to match the tampered bytes and leave
        // `meta_digest` untouched — `by_digest` still finds the record (it
        // matches on `meta_digest` as stored) and `verify_content` passes (it
        // hashes against `content[].sha256` as stored). The digest self-check
        // is what catches this: `content` feeds `compute_meta_digest`, so a
        // rewritten `content[].sha256` moves the recomputed digest away from
        // the stored `meta_digest`.
        let (_env, _home) = isolated_host(GrantCeiling::default());
        let fx = Fixture::new();
        let parent = seed_checkpoint(&fx.checkpoints, fx.tmp.path(), "cp-parent");

        let mut rec = parked_record("sess-alpha");
        rec.parent_checkpoint = Some(parent.meta_digest.clone());
        fx.sessions.write(&rec).unwrap();

        let blob_path = fx.checkpoints.content_dir(&parent.id).join("rootfs.ext4");
        let tampered = b"tampered-and-rehashed";
        std::fs::write(&blob_path, tampered).unwrap();
        let tampered_sha256 = mvm_core::crypto::image_verify::sha256_file(&blob_path).unwrap();

        let mut forged = fx.checkpoints.read_meta(&parent.id).unwrap();
        let blob = forged
            .content
            .iter_mut()
            .find(|b| b.name == "rootfs.ext4")
            .expect("the seeded checkpoint records a rootfs blob");
        blob.sha256 = tampered_sha256;
        // Precondition: the forgery is content-consistent (verify_content
        // alone would pass it) but digest-inconsistent (compute_meta_digest
        // now disagrees with the untouched meta_digest).
        assert_ne!(forged.compute_meta_digest(), forged.meta_digest);
        fx.checkpoints.write_meta(&forged).unwrap();

        let m = material();
        let err = fx
            .resume(&fx.request(&rec, &m))
            .expect_err("a record forged to vouch for its own tampered blob must refuse");
        assert!(
            err.to_string().contains("integrity"),
            "the refusal must be the digest self-check: {err}"
        );
        assert_still_parked(&fx, &rec);
    }

    #[test]
    fn an_active_session_cannot_be_resumed() {
        let (_env, _home) = isolated_host(GrantCeiling::default());
        let fx = Fixture::new();
        let parent = seed_checkpoint(&fx.checkpoints, fx.tmp.path(), "cp-parent");

        let mut rec = parked_record("sess-alpha");
        rec.parent_checkpoint = Some(parent.meta_digest.clone());
        // Put it back into residency: there is nothing parked to resume.
        let live = rec.resume(1_755_000_150).unwrap();
        fx.sessions.write(&live).unwrap();

        let m = material();
        let err = fx
            .resume(&fx.request(&live, &m))
            .expect_err("an active session has no parked state to resume");
        assert!(err.to_string().contains("not parked"), "{err}");
        assert_eq!(fx.sessions.load(&live.session_id).unwrap(), live);
    }

    #[test]
    fn a_refused_admission_leaves_the_session_parked() {
        // The ordering property: no step that can refuse runs after the record
        // has moved. A host whose ceiling refuses this workload must leave the
        // record parked and resumable — a record advanced to a generation no
        // admitted plan corresponds to would claim a residency nothing
        // authorized.
        let (_env, _home) = isolated_host(GrantCeiling {
            max_memory_mib: Some(128),
            ..Default::default()
        });
        let fx = Fixture::new();
        let parent = seed_checkpoint(&fx.checkpoints, fx.tmp.path(), "cp-parent");

        let mut rec = parked_record("sess-alpha");
        rec.parent_checkpoint = Some(parent.meta_digest.clone());
        fx.sessions.write(&rec).unwrap();

        // 512 MiB of material against a 128 MiB ceiling: every step before
        // admission succeeds, and admission itself refuses.
        let m = material();
        assert!(m.mem_mib > 128, "the fixture must exceed the ceiling");
        let err = fx
            .resume(&fx.request(&rec, &m))
            .expect_err("a workload above the host ceiling must not be admitted");
        assert!(
            err.to_string().contains("memory_mib"),
            "the refusal must be the ceiling, not an earlier step: {err}"
        );
        assert_still_parked(&fx, &rec);
    }
    #[test]
    fn the_audit_labels_name_the_session_and_the_generation_the_resume_opens() {
        // The plan has to name the residency, not just the session: two
        // resumes of one session otherwise synthesize plans differing only by
        // nonce, and an auditor reading the chain cannot tell which residency
        // acted. That is the whole reason a resume re-admits instead of
        // inheriting.
        let rec = parked_record("sess-alpha");
        let m = material();
        let input = synthesis_for_resume(&rec, &m);

        let label = |k: &str| input.audit_labels.get(k).map(String::as_str);
        assert_eq!(label("session_id"), Some("sess-alpha"));
        // Synthesis runs *before* the transition, so the record still carries
        // the parent generation. The label must name the one the resume opens,
        // which is what `AgentSessionRecord::resume` goes on to write.
        assert_eq!(rec.generation, 1, "the record has not transitioned yet");
        assert_eq!(label("session_generation"), Some("2"));

        let parent = rec.parent_checkpoint.as_ref().unwrap().to_string();
        assert_eq!(label("session_parent_checkpoint"), Some(parent.as_str()));
        let head = rec.approval_head.as_ref().unwrap().to_string();
        assert_eq!(label("session_approval_head"), Some(head.as_str()));
    }

    /// The three inputs a cold-boot config is assembled from, staged together.
    ///
    /// Reuses `seed_checkpoint` + `parked_record` rather than a second fixture
    /// style, so a change to what a resume point looks like reaches these tests.
    fn cold_boot_fixture(fx: &Fixture) -> (AgentSessionRecord, CheckpointMeta) {
        let parent = seed_checkpoint(&fx.checkpoints, fx.tmp.path(), "cp-parent");
        let mut rec = parked_record("sess-alpha");
        rec.parent_checkpoint = Some(parent.meta_digest.clone());
        (rec, parent)
    }

    #[test]
    fn a_cold_boot_config_names_the_resume_points_rootfs() {
        // Not an arbitrary path: the bytes behind `rootfs_path` must be the
        // resume point's, which is the whole reason the resume point exists.
        let (_env, _home) = isolated_host_with_runtime_overlay();
        let fx = Fixture::new();
        let state = fx.tmp.path().join("state");
        let (rec, parent) = cold_boot_fixture(&fx);
        let m = material();

        let cfg = cold_boot_config(ColdBootParams {
            record: &rec,
            parent: &parent,
            checkpoints: &fx.checkpoints,
            material: &m,
            state_dir: &state,
            kernel_path: None,
        })
        .expect("an intact resume point yields a cold-boot config");

        assert_eq!(
            cfg.rootfs_path,
            state.join("rootfs.ext4").display().to_string(),
            "the boot rootfs must be the session's own staged copy"
        );
        let staged = std::fs::read(&cfg.rootfs_path).expect("the staged rootfs must be on disk");
        let source =
            std::fs::read(fx.checkpoints.content_dir(&parent.id).join("rootfs.ext4")).unwrap();
        assert_eq!(
            staged, source,
            "the staged copy must carry the resume point's bytes"
        );
    }

    #[test]
    fn the_cold_boot_config_and_the_admitted_plan_agree_on_identity() {
        // The started VM and the plan that authorized it must name the same
        // thing. A config named anything else boots a machine the plan does not
        // describe.
        let (_env, _home) = isolated_host_with_runtime_overlay();
        let fx = Fixture::new();
        let state = fx.tmp.path().join("state");
        let (rec, parent) = cold_boot_fixture(&fx);
        let m = material();

        let cfg = cold_boot_config(ColdBootParams {
            record: &rec,
            parent: &parent,
            checkpoints: &fx.checkpoints,
            material: &m,
            state_dir: &state,
            kernel_path: None,
        })
        .unwrap();

        assert_eq!(cfg.name, rec.session_id.as_str());
        assert_eq!(
            cfg.name,
            synthesis_for_resume(&rec, &m).vm_name,
            "the config name must be the plan's vm_name"
        );
    }

    #[test]
    fn a_resume_point_without_a_rootfs_blob_is_refused() {
        // Refused here, naming what is missing, rather than at `backend.start`
        // with an opaque failure about a path that was never going to exist.
        let fx = Fixture::new();
        let state = fx.tmp.path().join("state");
        let (rec, mut parent) = cold_boot_fixture(&fx);
        parent.content.retain(|blob| blob.name != "rootfs.ext4");
        let m = material();

        let err = cold_boot_config(ColdBootParams {
            record: &rec,
            parent: &parent,
            checkpoints: &fx.checkpoints,
            material: &m,
            state_dir: &state,
            kernel_path: None,
        })
        .expect_err("a resume point with no rootfs blob must be refused");
        assert!(
            err.to_string().contains("rootfs.ext4"),
            "the refusal must name what was missing: {err}"
        );
    }

    // ───────────────────────────────────────────────────────────────
    // resume_and_boot: the tier gate and the admit -> transition -> boot order
    // ───────────────────────────────────────────────────────────────

    /// A resume point, a record parked at `reason`'s tier, and a kernel on disk
    /// whose digest the material pins.
    ///
    /// The kernel is real rather than a fixed string because the plan pins
    /// `kernel_sha256`, and the admitted-environment gate inside the shared boot
    /// tail hashes whatever path the config supplies against that pin. A fixture
    /// naming a kernel that does not hash to the pin would be refused by the
    /// gate, and the test would pass for the wrong reason.
    fn boot_fixture(
        fx: &Fixture,
        reason: ParkReason,
    ) -> (AgentSessionRecord, ResumePlanMaterial, std::path::PathBuf) {
        let parent = seed_checkpoint(&fx.checkpoints, fx.tmp.path(), "cp-parent");
        let mut rec = parked_record_at("sess-alpha", reason);
        rec.parent_checkpoint = Some(parent.meta_digest.clone());
        fx.sessions.write(&rec).unwrap();

        let kernel = fx.tmp.path().join("vmlinux");
        std::fs::write(&kernel, b"resume-kernel").unwrap();
        let mut m = material();
        m.kernel_sha256 = Some(mvm_core::crypto::image_verify::sha256_file(&kernel).unwrap());
        (rec, m, kernel)
    }

    #[test]
    fn a_cold_tier_resume_with_boot_starts_the_sandbox() {
        let (_env, _home) = isolated_host_with_runtime_overlay();
        let fx = Fixture::new();
        let (rec, m, kernel) = boot_fixture(&fx, ParkReason::RetentionDemotion);
        assert_eq!(
            rec.storage_tier,
            Some(StorageTier::Cold),
            "the fixture must be the tier under test"
        );
        let backend = mvm_runtime::AnyBackend::from_hypervisor("mock");
        let state = fx.tmp.path().join("state");

        let req = fx.request(&rec, &m);
        let booted = resume_and_boot(
            &fx.sessions,
            &fx.checkpoints,
            &ResumeBootRequest {
                resume: &req,
                backend: &backend,
                state_dir: &state,
                kernel_path: Some(&kernel),
                emitter: None,
            },
            &crate::plan_admission::SystemClock,
            &crate::plan_admission::InMemoryNonceLedger::new(),
        )
        .expect("a cold-tier resume must boot");

        // The record moved, and it moved before the boot.
        assert_eq!(booted.record.state, SandboxResidency::Active);
        assert_eq!(booted.record.generation, rec.generation + 1);
        // The VM is running under the session's own name, which is also the
        // admitted plan's workload name.
        assert_eq!(booted.started.vm_id.0, rec.session_id.as_str());
        assert_eq!(
            backend.status(&booted.started.vm_id).unwrap(),
            mvm_core::vm_backend::VmStatus::Running
        );
        assert_eq!(
            booted.started.admitted.plan().workload.0,
            rec.session_id.as_str()
        );
    }

    #[test]
    fn a_parked_tier_resume_with_boot_is_refused_and_leaves_the_session_parked() {
        // Cold-booting a `Parked` session would discard the memory image the
        // operator believes is being restored. The refusal comes before the
        // transition, so the session stays parked and resumable once the
        // restore path exists.
        let (_env, _home) = isolated_host(GrantCeiling::default());
        let fx = Fixture::new();
        let (rec, m, kernel) = boot_fixture(&fx, ParkReason::ApprovalWait);
        assert_eq!(rec.storage_tier, Some(StorageTier::Parked));
        let backend = mvm_runtime::AnyBackend::from_hypervisor("mock");
        let state = fx.tmp.path().join("state");

        let req = fx.request(&rec, &m);
        let err = resume_and_boot(
            &fx.sessions,
            &fx.checkpoints,
            &ResumeBootRequest {
                resume: &req,
                backend: &backend,
                state_dir: &state,
                kernel_path: Some(&kernel),
                emitter: None,
            },
            &crate::plan_admission::SystemClock,
            &crate::plan_admission::InMemoryNonceLedger::new(),
        )
        .expect_err("a parked-tier resume must not cold-boot");
        let text = format!("{err:#}");
        assert!(
            text.contains("parked"),
            "the refusal must name the tier: {text}"
        );
        assert!(
            text.contains("not built"),
            "the refusal must say the path is unbuilt: {text}"
        );
        assert_still_parked(&fx, &rec);
        assert!(
            backend.list().unwrap().is_empty(),
            "a refused resume must not start a VM"
        );
    }

    #[test]
    fn a_resident_tier_resume_with_boot_is_refused_and_leaves_the_session_parked() {
        let (_env, _home) = isolated_host(GrantCeiling::default());
        let fx = Fixture::new();
        let (rec, m, kernel) = boot_fixture(&fx, ParkReason::Idle);
        assert_eq!(rec.storage_tier, Some(StorageTier::Resident));
        let backend = mvm_runtime::AnyBackend::from_hypervisor("mock");
        let state = fx.tmp.path().join("state");

        let req = fx.request(&rec, &m);
        let err = resume_and_boot(
            &fx.sessions,
            &fx.checkpoints,
            &ResumeBootRequest {
                resume: &req,
                backend: &backend,
                state_dir: &state,
                kernel_path: Some(&kernel),
                emitter: None,
            },
            &crate::plan_admission::SystemClock,
            &crate::plan_admission::InMemoryNonceLedger::new(),
        )
        .expect_err("a resident-tier resume must not cold-boot");
        let text = format!("{err:#}");
        assert!(
            text.contains("resident"),
            "the refusal must name the tier: {text}"
        );
        assert!(
            text.contains("not built"),
            "the refusal must say the path is unbuilt: {text}"
        );
        assert_still_parked(&fx, &rec);
        assert!(backend.list().unwrap().is_empty());
    }

    #[test]
    fn a_resume_without_boot_admits_and_transitions_and_starts_nothing() {
        // The unchanged behaviour, asserted against a live backend rather than
        // by inspection: `resume_session` must still stop at an admitted plan.
        let (_env, _home) = isolated_host(GrantCeiling::default());
        let fx = Fixture::new();
        let (rec, m, _kernel) = boot_fixture(&fx, ParkReason::RetentionDemotion);
        let backend = mvm_runtime::AnyBackend::from_hypervisor("mock");

        let resumed = fx.resume(&fx.request(&rec, &m)).expect("resume admits");

        assert_eq!(resumed.record.state, SandboxResidency::Active);
        assert_eq!(resumed.record.generation, rec.generation + 1);
        assert!(
            backend.list().unwrap().is_empty(),
            "resume without --boot must start nothing"
        );
    }

    #[test]
    fn a_session_parked_without_an_approval_head_gets_no_head_label() {
        // An absent label is honest; an empty-string one would read in the
        // audit chain as a head that was checked and found blank.
        let mut rec = parked_record("sess-alpha");
        rec.approval_head = None;
        let m = material();
        let input = synthesis_for_resume(&rec, &m);
        assert_eq!(input.audit_labels.get("session_approval_head"), None);
        assert_eq!(
            input.audit_labels.get("session_id").map(String::as_str),
            Some("sess-alpha")
        );
    }

    #[test]
    fn a_resume_whose_approval_head_moved_is_refused() {
        // The head recorded at park is the ledger state the session was last
        // admitted under. If the ledger moved while it waited, the grants this
        // resume would run under are not the ones it was admitted for.
        let (_env, _home) = isolated_host(GrantCeiling::default());
        let fx = Fixture::new();
        let parent = seed_checkpoint(&fx.checkpoints, fx.tmp.path(), "cp-parent");

        let mut rec = parked_record("sess-alpha");
        rec.parent_checkpoint = Some(parent.meta_digest.clone());
        fx.sessions.write(&rec).unwrap();

        let m = material();
        let moved = head_of("cd");
        assert_ne!(Some(&moved), rec.approval_head.as_ref());
        let mut req = fx.request(&rec, &m);
        req.current_approval_head = Some(&moved);

        let err = fx
            .resume(&req)
            .expect_err("a ledger that moved while parked must refuse the resume");
        assert!(
            err.to_string().contains("approval head"),
            "the refusal must be the approval fence: {err}"
        );
        assert_still_parked(&fx, &rec);
    }

    #[test]
    fn a_resume_claiming_the_wrong_generation_is_refused() {
        // The orchestrator's own passthrough, not the store's fence: the store
        // has its own tests for the comparison, and none of them can tell
        // whether this function forwards the caller's expectation or
        // substitutes the record's own generation, which would always match.
        let (_env, _home) = isolated_host(GrantCeiling::default());
        let fx = Fixture::new();
        let parent = seed_checkpoint(&fx.checkpoints, fx.tmp.path(), "cp-parent");

        let mut rec = parked_record("sess-alpha");
        rec.parent_checkpoint = Some(parent.meta_digest.clone());
        fx.sessions.write(&rec).unwrap();

        let m = material();
        let mut req = fx.request(&rec, &m);
        req.expected_generation = rec.generation + 5;

        let err = fx
            .resume(&req)
            .expect_err("a caller working from a superseded record must be refused");
        assert!(err.to_string().contains("generation"), "{err}");
        assert_still_parked(&fx, &rec);
    }

    #[test]
    fn cold_boot_config_stages_and_names_verity_sidecars() {
        use mvm_core::checkpoint::ContentBlob;
        let (_env, _home) = isolated_host_with_runtime_overlay();
        let fx = Fixture::new();
        let state = fx.tmp.path().join("state");
        let mut parent = seed_checkpoint(&fx.checkpoints, fx.tmp.path(), "cp-verity");

        // Inject verity sidecars into the content manifest and onto disk.
        // The digests are not load-bearing for this unit: `cold_boot_config`
        // stages by blob name and does not re-verify the manifest here.
        let verity_bytes = b"verity-tree";
        let roothash = "abc123def456";
        let content_dir = fx.checkpoints.content_dir(&parent.id);
        std::fs::write(content_dir.join(ROOTFS_VERITY_BLOB), verity_bytes).unwrap();
        std::fs::write(content_dir.join(ROOTFS_ROOTHASH_BLOB), roothash).unwrap();
        parent.content.push(ContentBlob {
            name: ROOTFS_VERITY_BLOB.into(),
            sha256: "0".repeat(64),
        });
        parent.content.push(ContentBlob {
            name: ROOTFS_ROOTHASH_BLOB.into(),
            sha256: "1".repeat(64),
        });
        let rec = parked_record("sess-alpha");

        let cfg = cold_boot_config(ColdBootParams {
            record: &rec,
            parent: &parent,
            checkpoints: &fx.checkpoints,
            material: &material(),
            state_dir: &state,
            kernel_path: None,
        })
        .expect("verity-bearing checkpoint yields a config");

        assert_eq!(
            cfg.verity_path,
            Some(state.join(ROOTFS_VERITY_BLOB).display().to_string())
        );
        assert_eq!(cfg.roothash, Some(roothash.to_string()));
    }

    #[test]
    fn cold_boot_config_refuses_incomplete_verity_sidecar_set() {
        use mvm_core::checkpoint::ContentBlob;
        let fx = Fixture::new();
        let state = fx.tmp.path().join("state");
        let mut parent = seed_checkpoint(&fx.checkpoints, fx.tmp.path(), "cp-broken");
        // Only the verity tree, no roothash.
        let verity_bytes = b"verity-tree";
        let content_dir = fx.checkpoints.content_dir(&parent.id);
        std::fs::write(content_dir.join(ROOTFS_VERITY_BLOB), verity_bytes).unwrap();
        parent.content.push(ContentBlob {
            name: ROOTFS_VERITY_BLOB.into(),
            sha256: "0".repeat(64),
        });
        let rec = parked_record("sess-alpha");

        let err = cold_boot_config(ColdBootParams {
            record: &rec,
            parent: &parent,
            checkpoints: &fx.checkpoints,
            material: &material(),
            state_dir: &state,
            kernel_path: None,
        })
        .expect_err("incomplete verity set must be refused");
        assert!(
            err.to_string().contains("incomplete dm-verity"),
            "refusal must name the sidecar problem: {err}"
        );
    }

    #[test]
    fn a_booting_resume_records_session_resumed_before_the_boot() {
        let (_env, _home) = isolated_host_with_runtime_overlay();
        let fx = Fixture::new();
        let parent = seed_checkpoint(&fx.checkpoints, fx.tmp.path(), "cp-audit");
        let mut rec = parked_record_at("sess-alpha", ParkReason::RetentionDemotion);
        rec.parent_checkpoint = Some(parent.meta_digest.clone());
        fx.sessions.write(&rec).unwrap();

        let kernel = fx.tmp.path().join("vmlinux");
        std::fs::write(&kernel, b"resume-kernel").unwrap();
        let mut m = material();
        m.kernel_sha256 = Some(mvm_core::crypto::image_verify::sha256_file(&kernel).unwrap());

        let audit_dir = fx.tmp.path().join("audit");
        let signer = ed25519_dalek::SigningKey::from_bytes(&[29u8; 32]);
        let emitter = crate::audit::emitter::AuditEmitter::with_dir(signer, &audit_dir)
            .expect("emitter")
            .with_receipts();

        let req = fx.request(&rec, &m);
        let state = fx.tmp.path().join("state");
        let backend = mvm_runtime::AnyBackend::from_hypervisor("mock");
        let booted = resume_and_boot(
            &fx.sessions,
            &fx.checkpoints,
            &ResumeBootRequest {
                resume: &req,
                backend: &backend,
                state_dir: &state,
                kernel_path: Some(&kernel),
                emitter: Some(&emitter),
            },
            &crate::plan_admission::SystemClock,
            &crate::plan_admission::InMemoryNonceLedger::new(),
        )
        .expect("cold-tier resume must boot");

        let chain = std::fs::read_to_string(audit_dir.join("local.jsonl"))
            .expect("audit chain file written");
        assert!(
            chain.contains("session.resumed"),
            "chain must record the resume: {chain}"
        );
        assert!(
            chain.contains("resumed_at_generation"),
            "resume entry must carry generation label: {chain}"
        );
        assert_eq!(
            booted.record.generation,
            rec.generation + 1,
            "the booted record must be the new generation"
        );
    }
}
