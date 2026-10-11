//! Host-local implementation of the durable agent-session service.

use super::dto::*;
use anyhow::{Context, Result, ensure};
use mvm_contract::protocol::agent_session::AgentSessionId;
use mvm_core::checkpoint::{ApprovalHead, CheckpointDigest};
use mvm_hostd::audit::emitter::AuditEmitter;
use mvm_hostd::plan_admission::{InMemoryNonceLedger, SystemClock};
use mvm_hostd::session_resume::{ResumeOutcome, ResumePlanMaterial};
use mvm_runtime::agent_session::{
    AgentSessionRecord, AgentSessionStore, GenerationFence, ParkInput,
    ParkReason as StoredParkReason, TransitionResult,
};
use mvm_runtime::checkpoint::CheckpointStore;
use std::fs::{File, OpenOptions};
use std::path::Path;

/// Host-local durable session service. Stores and admission objects stay private.
pub struct AgentSessions {
    sessions: AgentSessionStore,
    checkpoints: CheckpointStore,
}

impl AgentSessions {
    #[must_use]
    pub fn local() -> Self {
        Self {
            sessions: AgentSessionStore::open(),
            checkpoints: CheckpointStore::open(),
        }
    }

    /// Use explicit persistent store roots, including in offline integrations.
    #[must_use]
    pub fn at(sessions: impl AsRef<Path>, checkpoints: impl AsRef<Path>) -> Self {
        Self {
            sessions: AgentSessionStore::at(sessions.as_ref().to_path_buf()),
            checkpoints: CheckpointStore::at(checkpoints.as_ref().to_path_buf()),
        }
    }

    pub fn open(&self, request: &OpenRequest) -> Result<SessionReport> {
        let id = parse_id(&request.session_id)?;
        let parent = request
            .resume_point
            .as_deref()
            .map(CheckpointDigest::parse)
            .transpose()
            .map_err(|e| anyhow::anyhow!("invalid --resume-point: {e}"))?;
        let _lock = self.lock(&id)?;
        ensure!(
            !self.sessions.exists(&id),
            "agent session '{}' already exists on this host",
            request.session_id
        );
        let now = now_unix();
        let record = AgentSessionRecord::opened(id, request.members.clone(), parent, now);
        self.sessions.write(&record)?;
        report(&record, now)
    }

    pub fn list(&self) -> Result<Vec<SessionReport>> {
        let now = now_unix();
        self.sessions
            .list()?
            .iter()
            .map(|record| report(record, now))
            .collect()
    }

    pub fn show(&self, session_id: &str) -> Result<SessionReport> {
        let id = parse_id(session_id)?;
        let record = self
            .sessions
            .load(&id)
            .with_context(|| format!("no agent session '{session_id}' on this host"))?;
        report(&record, now_unix())
    }

    pub fn park(&self, request: &ParkRequest) -> Result<TransitionReport> {
        let id = parse_id(&request.session_id)?;
        let input = ParkInput {
            reason: parse_reason(&request.reason)?,
            journal_cursor: request.journal_cursor,
            approval_head: approval_head(request.approval_head.as_deref())?,
            retain_for_secs: request
                .retain_for
                .as_deref()
                .map(|raw| retention("--retain-for", raw))
                .transpose()?,
        };
        let _lock = self.lock(&id)?;
        self.require_exists(&id)?;
        let now = now_unix();
        let result = self
            .sessions
            .park(&id, fence(request.expected_generation), input, now)?;
        transition_report(Transition::Park, result, now)
    }

    pub fn renew(&self, request: &RenewRequest) -> Result<TransitionReport> {
        let id = parse_id(&request.session_id)?;
        let extend_for_secs = retention("--for", &request.extend_for)?;
        let _lock = self.lock(&id)?;
        self.require_exists(&id)?;
        let now = now_unix();
        let result = self.sessions.renew(
            &id,
            mvm_runtime::agent_session::RenewRequest {
                generation: fence(request.expected_generation),
                expected_deadline_unix: request.expected_deadline,
                extend_for_secs,
            },
            now,
        )?;
        transition_report(Transition::Renew, result, now)
    }

    /// Re-admit a development session. The host admission service owns signed
    /// claims, checkpoint integrity, approval fences, and boot cleanup.
    pub fn resume(&self, request: &ResumeRequest) -> Result<TransitionReport> {
        if request.boot && request.kernel_sha256.is_some() && request.kernel.is_none() {
            anyhow::bail!(
                "--boot with --kernel-sha256 also needs --kernel <path>: the admitted plan pins              that digest, and the boot hashes the file it is given against it"
            );
        }
        let id = parse_id(&request.session_id)?;
        let approval_head = approval_head(request.approval_head.as_deref())?;
        let _lock = self.lock(&id)?;
        self.require_exists(&id)?;
        let material = ResumePlanMaterial {
            backend_name: request.backend.clone(),
            image_name: request.image.clone(),
            image_sha256: request.image_sha256.clone(),
            kernel_sha256: request.kernel_sha256.clone(),
            cpus: request.cpus,
            mem_mib: request.mem_mib,
        };
        let now = now_unix();
        let resume = mvm_hostd::session_resume::ResumeRequest {
            session_id: &id,
            generation: fence(request.expected_generation),
            current_approval_head: approval_head.as_ref(),
            material: &material,
            host_signer_keys_dir: None,
            now_unix: now,
        };
        if request.boot {
            let state_dir = mvm_core::config::vm_state_dir(id.as_str());
            let emitter = host_emitter()?;
            let boot = crate::ResumeBootLocalRequest::builder()
                .sessions(&self.sessions)
                .checkpoints(&self.checkpoints)
                .resume(&resume)
                .backend_name(&request.backend)
                .state_dir(&state_dir)
                .kernel_path(request.kernel.as_deref())
                .emitter(Some(&emitter))
                .build()?;
            let booted =
                crate::resume_and_boot_local(&boot, &SystemClock, &InMemoryNonceLedger::new())?;
            return Ok(TransitionReport {
                transition: Transition::Resume,
                replayed: false,
                session: report(&booted.record, now)?,
                admitted_plan_id: Some(booted.started.admitted.plan_id().0.clone()),
                booted_sandbox: Some(booted.started.vm_id.0),
                warnings: Vec::new(),
            });
        }
        match mvm_hostd::session_resume::resume_session(
            &self.sessions,
            &self.checkpoints,
            &resume,
            &SystemClock,
            &InMemoryNonceLedger::new(),
        )? {
            ResumeOutcome::Resumed(resumed) => {
                let plan_id = resumed.admitted.plan_id().0.clone();
                let audit = host_emitter().and_then(|emitter| {
                    emitter.emit_session_resumed(
                        resumed.admitted.plan(),
                        vec![
                            ("resumed_session".into(), id.as_str().into()),
                            (
                                "resumed_at_generation".into(),
                                resumed.record.generation.to_string(),
                            ),
                            ("resumed_plan_id".into(), plan_id.clone()),
                        ],
                    )
                });
                Ok(TransitionReport {
                    transition: Transition::Resume,
                    replayed: false,
                    session: report(&resumed.record, now)?,
                    admitted_plan_id: Some(plan_id),
                    booted_sandbox: None,
                    warnings: audit_warnings(&resumed.record, "resumed", "resume", audit),
                })
            }
            ResumeOutcome::Replayed(replayed) => Ok(TransitionReport {
                transition: Transition::Resume,
                replayed: true,
                session: report(&replayed.record, now)?,
                admitted_plan_id: Some(replayed.admitted_plan_id),
                booted_sandbox: None,
                warnings: Vec::new(),
            }),
        }
    }

    fn require_exists(&self, id: &AgentSessionId) -> Result<()> {
        ensure!(
            self.sessions.exists(id),
            "no agent session '{}' on this host",
            id.as_str()
        );
        Ok(())
    }

    /// Hold one persistent inode across the read/admit/write/audit transaction.
    /// Never unlink it: waiters must contend on the same inode on every retry.
    fn lock(&self, id: &AgentSessionId) -> Result<File> {
        let root = self.sessions.root().join(".locks");
        mvm_core::config::create_private_dir(&root)?;
        // The store scans child directories for session.json. Even a valid
        // session named "session.json" must never create that record filename
        // inside the lock directory.
        let path = root.join(format!("{}.lock", id.as_str()));
        if let Ok(meta) = std::fs::symlink_metadata(&path) {
            ensure!(
                meta.is_file() && !meta.file_type().is_symlink(),
                "agent-session lock is not a regular file"
            );
        }
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(path)
            .context("opening agent-session lock")?;
        file.lock().context("locking agent session")?;
        Ok(file)
    }
}

fn now_unix() -> u64 {
    mvm_core::util::time::now_unix_secs()
}

fn parse_id(raw: &str) -> Result<AgentSessionId> {
    AgentSessionId::parse(raw).map_err(|e| anyhow::anyhow!("invalid session id '{raw}': {e}"))
}

fn approval_head(raw: Option<&str>) -> Result<Option<ApprovalHead>> {
    raw.map(ApprovalHead::parse)
        .transpose()
        .map_err(|e| anyhow::anyhow!("invalid --approval-head: {e}"))
}

fn fence(generation: Option<u64>) -> GenerationFence {
    generation.map_or(GenerationFence::ReadCurrent, GenerationFence::Observed)
}

fn retention(flag: &str, raw: &str) -> Result<u64> {
    mvm_core::crypto::policy::parse_ttl(raw)
        .map(|d| d.as_secs())
        .map_err(|e| anyhow::anyhow!("invalid {flag}: {e}"))
}

fn parse_reason(raw: &str) -> Result<StoredParkReason> {
    match raw {
        "approval-wait" => Ok(StoredParkReason::ApprovalWait),
        "idle" => Ok(StoredParkReason::Idle),
        "host-shutdown" => Ok(StoredParkReason::HostShutdown),
        "operator" => Ok(StoredParkReason::Operator),
        "retention-demotion" => Ok(StoredParkReason::RetentionDemotion),
        other => anyhow::bail!(
            "unknown park reason '{other}'; accepted: approval-wait, idle, host-shutdown, operator, retention-demotion"
        ),
    }
}

fn report(record: &AgentSessionRecord, now: u64) -> Result<SessionReport> {
    let mut view: SessionReport = serde_json::from_value(serde_json::to_value(record)?)?;
    view.retention = record
        .retention_status(now)
        .map(|status| serde_json::from_value(serde_json::to_value(status)?))
        .transpose()?;
    Ok(view)
}

fn host_emitter() -> Result<AuditEmitter> {
    let signer = mvm_hostd::audit::host_keypair::load_or_init()
        .context("loading the host signer to sign the session entry")?;
    AuditEmitter::new(signer.signing)
        .context("opening the audit chain to record the session transition")
}

fn transition_report(
    transition: Transition,
    result: TransitionResult,
    now: u64,
) -> Result<TransitionReport> {
    let replayed = result.is_replay();
    let record = result.into_record();
    let warnings = if replayed {
        Vec::new()
    } else {
        let audit = audit_transition(transition, &record);
        match transition {
            Transition::Park => audit_warnings(&record, "parked", "park", audit),
            Transition::Renew => audit_warnings(&record, "renewed", "renewal", audit),
            Transition::Resume => unreachable!("resume owns its admitted plan"),
        }
    };
    Ok(TransitionReport {
        transition,
        replayed,
        session: report(&record, now)?,
        admitted_plan_id: None,
        booted_sandbox: None,
        warnings,
    })
}

fn audit_warnings(
    record: &AgentSessionRecord,
    verb: &str,
    noun: &str,
    audit: Result<()>,
) -> Vec<String> {
    audit
        .err()
        .map(|error| {
            format!(
                "session {} {verb}, but the {noun} was not recorded in the audit chain: {error:#}",
                record.session_id.as_str(),
            )
        })
        .into_iter()
        .collect()
}

fn audit_transition(transition: Transition, record: &AgentSessionRecord) -> Result<()> {
    let member = record.members.first().ok_or_else(|| {
        anyhow::anyhow!(
            "session {} records no member sandbox, so there is no admitted plan to bind to",
            record.session_id.as_str(),
        )
    })?;
    let plan = mvm_hostd::audit::plan_persist::read_plan(member)
        .with_context(|| format!("reading the admitted plan of member sandbox '{member}'"))?;
    let emitter = host_emitter()?;
    match transition {
        Transition::Park => {
            let mut extras = vec![
                ("parked_session".into(), record.session_id.as_str().into()),
                ("parked_at_generation".into(), record.generation.to_string()),
            ];
            if let Some(reason) = record.park_reason {
                let name = match reason {
                    StoredParkReason::ApprovalWait => "approval-wait",
                    StoredParkReason::Idle => "idle",
                    StoredParkReason::HostShutdown => "host-shutdown",
                    StoredParkReason::Operator => "operator",
                    StoredParkReason::RetentionDemotion => "retention-demotion",
                };
                extras.push(("park_reason".into(), name.into()));
            }
            if let Some(tier) = record.storage_tier {
                let name = match tier {
                    mvm_runtime::agent_session::StorageTier::Resident => "resident",
                    mvm_runtime::agent_session::StorageTier::Parked => "parked",
                    mvm_runtime::agent_session::StorageTier::Cold => "cold",
                };
                extras.push(("park_storage_tier".into(), name.into()));
            }
            if let Some(until) = record.retain_until_unix {
                extras.push(("park_retain_until_unix".into(), until.to_string()));
            }
            emitter.emit_session_parked(&plan, extras)
        }
        Transition::Renew => {
            let mut extras = vec![
                ("renewed_session".into(), record.session_id.as_str().into()),
                (
                    "renewed_at_generation".into(),
                    record.generation.to_string(),
                ),
            ];
            if let Some(until) = record.retain_until_unix {
                extras.push(("renewed_until_unix".into(), until.to_string()));
            }
            if let Some(from) = record
                .last_transition
                .as_ref()
                .and_then(|t| t.identity.observed.get("retain_until_unix"))
                .and_then(Option::as_ref)
            {
                extras.push(("renewed_from_unix".into(), from.clone()));
            }
            emitter.emit_session_renewed(&plan, extras)
        }
        Transition::Resume => anyhow::bail!("resume audit requires its admitted plan"),
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
