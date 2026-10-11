use anyhow::{Context, Result};
use mvm_contract::protocol::agent_session::AgentSessionId;
use mvm_runtime::agent_session::AgentSessionStore;
use mvm_runtime::agent_session::replay::{prepare_replay, timeline_base};
use mvm_runtime::agent_session::replay_input::ReplayInputStore;

use super::{Checkpoints, SignedChainAnchor, validated_id};
use crate::replay::{PreparedSessionReplay, SessionReplayRequest, replay_target_name};

impl Checkpoints {
    pub(crate) fn prepare_session_replay(
        &self,
        request: &SessionReplayRequest,
    ) -> Result<PreparedSessionReplay> {
        let session_id = AgentSessionId::parse(request.session_id.clone()).map_err(|error| {
            anyhow::anyhow!("invalid session id '{}': {error}", request.session_id)
        })?;
        let from = request.from.as_deref().map(validated_id).transpose()?;
        let record = AgentSessionStore::open().load(&session_id)?;
        let inputs = ReplayInputStore::open();
        let from = match from {
            Some(id) => id,
            None => timeline_base(&self.store, &record)?,
        };
        self.read(&from)?;
        let anchor = SignedChainAnchor::load().context("loading the signed audit chain")?;
        let plan = prepare_replay(&self.store, &inputs, &from, &record, &anchor)
            .with_context(|| format!("planning the replay of session {session_id}"))?;
        let target = replay_target_name(&from, request.as_name.as_deref())?;
        Ok(PreparedSessionReplay::new(plan, inputs, target))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::replay::ReplayService;
    use mvm_core::checkpoint::{
        ApprovalHead, CheckpointClass, CheckpointId, CheckpointKeyDomain, CheckpointMeta,
        SessionBinding,
    };
    use mvm_core::util::test_env::TestEnv;
    use mvm_runtime::agent_session::replay_input::ReplayInputBinding;
    use mvm_runtime::agent_session::{AgentSessionRecord, SandboxResidency};

    fn seed() -> (SessionReplayRequest, AgentSessionRecord, CheckpointMeta) {
        let session_id = AgentSessionId::parse("replay-source").unwrap();
        let inputs = ReplayInputStore::open();
        let input = inputs
            .record(
                ReplayInputBinding {
                    session_id: session_id.clone(),
                    generation: 2,
                    journal_cursor: 7,
                },
                b"private prompt never belongs in the summary",
            )
            .unwrap();
        let binding = |cursor, digest| SessionBinding {
            session_id: session_id.clone(),
            generation: 2,
            journal_cursor: cursor,
            approval_head: ApprovalHead::from_bytes(&[3; 32]),
            replay_input_digest: digest,
        };
        let base =
            CheckpointMeta::builder(CheckpointId::new("base"), CheckpointClass::VmFull, "source")
                .key_domain(CheckpointKeyDomain::tenant("local").unwrap())
                .session(Some(binding(4, None)))
                .build();
        let step =
            CheckpointMeta::builder(CheckpointId::new("step"), CheckpointClass::VmFull, "source")
                .key_domain(CheckpointKeyDomain::tenant("local").unwrap())
                .parent(Some(base.meta_digest.clone()))
                .session(Some(binding(7, Some(input.artifact_digest))))
                .build();
        let checkpoints = Checkpoints::open();
        let emitter = mvm_hostd::audit::emitter::AuditEmitter::new(
            mvm_hostd::audit::host_keypair::load_or_init()
                .unwrap()
                .signing,
        )
        .unwrap();
        let plan = mvm_core::plan::test_support::PlanFixture::new()
            .tenant("local")
            .build();
        for meta in [&base, &step] {
            checkpoints.store.write_meta(meta).unwrap();
            mvm_hostd::audit::bind::bind_checkpoint_created(&emitter, &plan, meta).unwrap();
        }
        let record = AgentSessionRecord {
            session_id,
            generation: 2,
            state: SandboxResidency::Active,
            members: vec!["source".into()],
            parent_checkpoint: Some(step.meta_digest.clone()),
            created_unix: 1,
            updated_unix: 2,
            journal_cursor: 7,
            approval_head: None,
            storage_tier: None,
            park_reason: None,
            retain_until_unix: None,
            last_transition: None,
        };
        AgentSessionStore::open().write(&record).unwrap();
        (
            SessionReplayRequest {
                session_id: record.session_id.as_str().into(),
                from: Some("base".into()),
                as_name: Some("replay-child".into()),
            },
            record,
            base,
        )
    }

    #[test]
    fn facade_prepares_signed_session_without_exposing_prompt_bytes() {
        let mut env = TestEnv::new();
        let home = tempfile::tempdir().unwrap();
        env.set("MVM_HOME", home.path());
        let (request, _, _) = seed();
        let prepared = ReplayService::open().prepare_session(&request).unwrap();
        let summary = prepared.summary();
        assert_eq!(summary.checkpoint.as_str(), "base");
        assert_eq!(summary.restored_name, "replay-child");
        assert_eq!(summary.checkpoint_cursor, 4);
        assert_eq!(summary.inputs.len(), 1);
        assert_eq!(summary.inputs[0].journal_cursor, 7);
        let json = serde_json::to_string(summary).unwrap();
        assert!(!json.contains("private prompt"));
        assert_eq!(
            serde_json::from_str::<crate::replay::SessionReplaySummary>(&json).unwrap(),
            *summary
        );
        assert_eq!(
            serde_json::from_str::<SessionReplayRequest>(&serde_json::to_string(&request).unwrap())
                .unwrap(),
            request
        );
    }

    #[test]
    fn one_shot_dry_run_verifies_without_forking_or_dispatching() {
        let mut env = TestEnv::new();
        let home = tempfile::tempdir().unwrap();
        env.isolate_mvm_home(home.path());
        let (selection, _, _) = seed();
        let request = crate::replay::SessionReplayRunRequest {
            selection,
            dry_run: true,
            timeout_secs: 1,
            tenant: "local".into(),
        };
        let mut output = crate::entrypoint::CapturedOutput::default();
        let report = ReplayService::open()
            .run_session(&request, &mut output)
            .unwrap();
        assert_eq!(report.summary.inputs.len(), 1);
        assert!(report.execution.is_none());
        assert!(!mvm_core::config::vm_state_dir("replay-child").exists());
        assert!(output.stdout.is_empty() && output.stderr.is_empty());
        assert!(
            !serde_json::to_string(&report)
                .unwrap()
                .contains("private prompt")
        );
    }

    #[test]
    fn one_shot_refuses_unsigned_timeline_before_forking() {
        let mut env = TestEnv::new();
        let home = tempfile::tempdir().unwrap();
        env.isolate_mvm_home(home.path());
        let (selection, _, mut base) = seed();
        base.tag = Some("unsigned change".into());
        base.meta_digest = base.compute_meta_digest();
        Checkpoints::open().store.write_meta(&base).unwrap();
        let request = crate::replay::SessionReplayRunRequest {
            selection,
            dry_run: false,
            timeout_secs: 1,
            tenant: "local".into(),
        };
        let mut output = crate::entrypoint::CapturedOutput::default();
        assert!(
            ReplayService::open()
                .run_session(&request, &mut output)
                .is_err()
        );
        assert!(!mvm_core::config::vm_state_dir("replay-child").exists());
        assert!(output.stdout.is_empty() && output.stderr.is_empty());
    }

    #[test]
    fn facade_refuses_bad_ids_before_loading_sessions() {
        let root = tempfile::tempdir().unwrap();
        let service = ReplayService::with_checkpoints(Checkpoints::at(root.path()));
        let mut request = SessionReplayRequest {
            session_id: "../invalid".into(),
            from: None,
            as_name: None,
        };
        let error = service.prepare_session(&request).err().unwrap();
        assert!(error.to_string().starts_with("invalid session id"));
        request.session_id = "valid-session".into();
        request.from = Some("../invalid".into());
        let error = service.prepare_session(&request).err().unwrap();
        assert_eq!(
            error.to_string(),
            "invalid checkpoint id \"../invalid\": must not contain '/', '\\', '..', NUL, or control characters"
        );
    }

    #[test]
    fn facade_refuses_wrong_session_generation_and_unsigned_rebinding() {
        let mut env = TestEnv::new();
        let home = tempfile::tempdir().unwrap();
        env.set("MVM_HOME", home.path());
        let (request, mut record, mut base) = seed();
        record.generation += 1;
        AgentSessionStore::open().write(&record).unwrap();
        let error = ReplayService::open()
            .prepare_session(&request)
            .err()
            .unwrap();
        assert!(
            format!("{error:#}")
                .contains("replay checkpoint session identity or generation does not match")
        );
        record.generation -= 1;
        AgentSessionStore::open().write(&record).unwrap();
        base.key_domain = CheckpointKeyDomain::tenant("other-tenant").unwrap();
        base.meta_digest = base.compute_meta_digest();
        Checkpoints::open().store.write_meta(&base).unwrap();
        let error = ReplayService::open()
            .prepare_session(&request)
            .err()
            .unwrap();
        assert!(
            format!("{error:#}").contains("verifying replay checkpoint base"),
            "{error:#}"
        );
    }
}
