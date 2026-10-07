//! Verified replay planning and ordered input delivery.
//!
//! Restoring the VM remains the caller's responsibility because that operation
//! must pass through the backend's ordinary admission path. This module makes
//! the handoff strict: only a chain-verified, session-bound `vm_full`
//! checkpoint can produce a plan, and each decrypted input is delivered with
//! its content-address as the downstream idempotency identity.

use anyhow::{Context, Result, bail};
use mvm_contract::protocol::agent_session::AgentSessionId;
use mvm_core::checkpoint::{CheckpointClass, CheckpointId};

use crate::checkpoint::{CheckpointChainAnchor, CheckpointStore, verify_lineage};

use super::AgentSessionRecord;
use super::replay_input::{ReplayInputRef, ReplayInputStore};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayPlan {
    pub checkpoint: CheckpointId,
    pub session_id: AgentSessionId,
    pub generation: u64,
    pub checkpoint_cursor: u64,
    pub inputs: Vec<ReplayInputRef>,
}

/// Prepare an ordered replay after verifying the checkpoint and its complete
/// ancestry against the signed audit chain.
pub fn prepare_replay(
    checkpoints: &CheckpointStore,
    inputs: &ReplayInputStore,
    checkpoint: &CheckpointId,
    session: &AgentSessionRecord,
    anchor: &dyn CheckpointChainAnchor,
) -> Result<ReplayPlan> {
    verify_lineage(checkpoints, checkpoint, anchor)
        .with_context(|| format!("verifying replay checkpoint {checkpoint}"))?;
    let meta = checkpoints.read_meta(checkpoint)?;
    if meta.class != CheckpointClass::VmFull {
        bail!("replay requires a vm_full checkpoint");
    }
    let binding = meta
        .session
        .context("replay checkpoint has no durable agent-session binding")?;
    if binding.session_id != session.session_id || binding.generation != session.generation {
        bail!("replay checkpoint session identity or generation does not match");
    }
    let tip = session
        .parent_checkpoint
        .as_ref()
        .context("agent session has no committed replay checkpoint")?;
    let mut cursor = tip.clone();
    let mut descendants = Vec::new();
    let mut visited = std::collections::HashSet::new();
    while cursor != meta.meta_digest {
        if !visited.insert(cursor.clone()) {
            bail!("replay checkpoint timeline contains a cycle");
        }
        let step = checkpoints
            .by_digest(&cursor)?
            .with_context(|| format!("committed replay checkpoint {cursor} is missing"))?;
        cursor = step.parent.clone().context(
            "committed replay checkpoint does not descend from the requested checkpoint",
        )?;
        descendants.push(step);
    }
    descendants.reverse();
    if descendants.is_empty() {
        bail!("no recorded replay inputs follow the checkpoint cursor");
    }
    verify_lineage(
        checkpoints,
        &descendants.last().expect("non-empty").id,
        anchor,
    )
    .context("verifying committed replay checkpoint timeline")?;
    let mut recorded = Vec::with_capacity(descendants.len());
    let mut last_cursor = binding.journal_cursor;
    for step in descendants {
        if step.class != CheckpointClass::VmFull {
            bail!("replay step timeline contains a non-vm_full checkpoint");
        }
        let step_binding = step
            .session
            .context("replay step checkpoint has no durable agent-session binding")?;
        if step_binding.session_id != session.session_id
            || step_binding.generation != session.generation
            || step_binding.journal_cursor <= last_cursor
        {
            bail!("replay step checkpoint session binding does not advance one timeline");
        }
        let artifact_digest = step_binding
            .replay_input_digest
            .clone()
            .context("replay step checkpoint has no encrypted input binding")?;
        let reference = ReplayInputRef {
            binding: super::replay_input::ReplayInputBinding {
                session_id: step_binding.session_id,
                generation: step_binding.generation,
                journal_cursor: step_binding.journal_cursor,
            },
            artifact_digest,
        };
        drop(inputs.load(&reference).with_context(|| {
            format!(
                "validating replay input at cursor {}",
                reference.binding.journal_cursor
            )
        })?);
        last_cursor = reference.binding.journal_cursor;
        recorded.push(reference);
    }
    if last_cursor != session.journal_cursor {
        bail!("replay checkpoint tip does not match the session journal cursor");
    }
    // Every input recorded between the checkpoint and the tip must be on the
    // timeline. One recorded without a committed step changed the guest in a
    // way no checkpoint holds; replaying around it would skip it silently.
    if let Some(unstepped) = inputs
        .after(
            &session.session_id,
            session.generation,
            binding.journal_cursor,
        )?
        .into_iter()
        .filter(|input| input.binding.journal_cursor <= session.journal_cursor)
        .find(|input| !recorded.contains(input))
    {
        bail!(
            "the input recorded at journal cursor {} has no step checkpoint; the \
             timeline cannot be replayed past it",
            unstepped.binding.journal_cursor
        );
    }
    Ok(ReplayPlan {
        checkpoint: checkpoint.clone(),
        session_id: binding.session_id,
        generation: binding.generation,
        checkpoint_cursor: binding.journal_cursor,
        inputs: recorded,
    })
}

/// The checkpoint a session's recorded timeline starts from: its base, found
/// by following the hash links back from the session's current resume point.
/// Replaying from it re-delivers every prompt the session has committed.
///
/// # Errors
/// A session with no resume point, a link that does not resolve, or a cycle.
pub fn timeline_base(
    checkpoints: &CheckpointStore,
    session: &AgentSessionRecord,
) -> Result<CheckpointId> {
    let mut cursor = session
        .parent_checkpoint
        .clone()
        .context("agent session has no committed replay checkpoint")?;
    let mut visited = std::collections::HashSet::new();
    loop {
        if !visited.insert(cursor.clone()) {
            bail!("replay checkpoint timeline contains a cycle");
        }
        let meta = checkpoints
            .by_digest(&cursor)?
            .with_context(|| format!("committed replay checkpoint {cursor} is missing"))?;
        match meta.parent {
            Some(parent) => cursor = parent,
            None => return Ok(meta.id),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayDispatchOutcome {
    Applied,
    Duplicate,
}

/// A replay target must durably deduplicate on `reference.artifact_digest`.
/// That identity is passed before the plaintext input so a crash after target
/// execution but before the caller records progress cannot execute the step a
/// second time.
pub trait ReplayDispatcher {
    fn dispatch(
        &mut self,
        reference: &ReplayInputRef,
        input: &[u8],
    ) -> Result<ReplayDispatchOutcome>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayReport {
    pub applied: usize,
    pub duplicates: usize,
    pub last_cursor: u64,
}

impl ReplayPlan {
    /// Decrypt and deliver every planned input in journal order. Delivery stops
    /// at the first error; a retry is safe only because the dispatcher is
    /// required to deduplicate the artifact content-address.
    pub fn dispatch(
        &self,
        inputs: &ReplayInputStore,
        dispatcher: &mut dyn ReplayDispatcher,
    ) -> Result<ReplayReport> {
        let mut applied = 0;
        let mut duplicates = 0;
        let mut last_cursor = self.checkpoint_cursor;
        for reference in &self.inputs {
            let input = inputs.load(reference).with_context(|| {
                format!(
                    "loading replay input at cursor {}",
                    reference.binding.journal_cursor
                )
            })?;
            match dispatcher.dispatch(reference, input.as_slice())? {
                ReplayDispatchOutcome::Applied => applied += 1,
                ReplayDispatchOutcome::Duplicate => duplicates += 1,
            }
            last_cursor = reference.binding.journal_cursor;
        }
        Ok(ReplayReport {
            applied,
            duplicates,
            last_cursor,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_session::replay_input::ReplayInputBinding;
    use mvm_core::checkpoint::{ApprovalHead, CheckpointDigest, CheckpointMeta, SessionBinding};

    struct MatchingAnchor;

    impl CheckpointChainAnchor for MatchingAnchor {
        fn recorded_creation_digest(
            &self,
            meta: &CheckpointMeta,
        ) -> Result<Option<CheckpointDigest>> {
            Ok(Some(meta.meta_digest.clone()))
        }

        fn recorded_creation_tenant(&self, _meta: &CheckpointMeta) -> Result<Option<String>> {
            Ok(Some("local".to_string()))
        }
    }

    struct RecordingDispatcher {
        seen: Vec<(String, Vec<u8>)>,
        duplicate_cursor: u64,
    }

    impl ReplayDispatcher for RecordingDispatcher {
        fn dispatch(
            &mut self,
            reference: &ReplayInputRef,
            input: &[u8],
        ) -> Result<ReplayDispatchOutcome> {
            self.seen
                .push((reference.artifact_digest.clone(), input.to_vec()));
            Ok(
                if reference.binding.journal_cursor == self.duplicate_cursor {
                    ReplayDispatchOutcome::Duplicate
                } else {
                    ReplayDispatchOutcome::Applied
                },
            )
        }
    }

    #[test]
    fn dispatch_decrypts_in_cursor_order_and_preserves_idempotency_identity() {
        let temp = tempfile::tempdir().unwrap();
        let store = ReplayInputStore::at(temp.path().join("sessions"), temp.path().join("keys"));
        let session_id = AgentSessionId::parse("replay-engine").unwrap();
        let binding = |journal_cursor| ReplayInputBinding {
            session_id: session_id.clone(),
            generation: 4,
            journal_cursor,
        };
        store.record(binding(8), b"second").unwrap();
        store.record(binding(5), b"first").unwrap();
        let plan = ReplayPlan {
            checkpoint: CheckpointId::new("step-3"),
            session_id: session_id.clone(),
            generation: 4,
            checkpoint_cursor: 3,
            inputs: store.after(&session_id, 4, 3).unwrap(),
        };
        let mut dispatcher = RecordingDispatcher {
            seen: Vec::new(),
            duplicate_cursor: 5,
        };

        let report = plan.dispatch(&store, &mut dispatcher).unwrap();

        assert_eq!(report.applied, 1);
        assert_eq!(report.duplicates, 1);
        assert_eq!(report.last_cursor, 8);
        assert_eq!(dispatcher.seen[0].1, b"first");
        assert_eq!(dispatcher.seen[1].1, b"second");
        assert!(
            dispatcher
                .seen
                .iter()
                .all(|(digest, _)| digest.starts_with("sha256:"))
        );
    }

    #[test]
    fn planning_requires_a_chain_verified_matching_session_checkpoint() {
        let temp = tempfile::tempdir().unwrap();
        let checkpoints = CheckpointStore::at(temp.path().join("checkpoints"));
        let inputs = ReplayInputStore::at(temp.path().join("sessions"), temp.path().join("keys"));
        let session_id = AgentSessionId::parse("planned-replay").unwrap();
        let checkpoint = CheckpointMeta::builder(
            CheckpointId::new("planned-step"),
            CheckpointClass::VmFull,
            "worker",
        )
        .created_unix(1)
        .supervisor_config_digest("config")
        .session(Some(SessionBinding {
            session_id: session_id.clone(),
            generation: 2,
            journal_cursor: 4,
            approval_head: ApprovalHead::parse(format!("sha256:{}", "a".repeat(64))).unwrap(),
            replay_input_digest: None,
        }))
        .build();
        checkpoints.write_meta(&checkpoint).unwrap();
        let input = inputs
            .record(
                ReplayInputBinding {
                    session_id: session_id.clone(),
                    generation: 2,
                    journal_cursor: 7,
                },
                b"next step",
            )
            .unwrap();
        let step = CheckpointMeta::builder(
            CheckpointId::new("planned-step-7"),
            CheckpointClass::VmFull,
            "worker",
        )
        .parent(Some(checkpoint.meta_digest.clone()))
        .created_unix(2)
        .supervisor_config_digest("config")
        .session(Some(SessionBinding {
            session_id: session_id.clone(),
            generation: 2,
            journal_cursor: 7,
            approval_head: ApprovalHead::parse(format!("sha256:{}", "a".repeat(64))).unwrap(),
            replay_input_digest: Some(input.artifact_digest.clone()),
        }))
        .build();
        checkpoints.write_meta(&step).unwrap();
        let record = AgentSessionRecord {
            session_id: session_id.clone(),
            generation: 2,
            state: crate::agent_session::SandboxResidency::Active,
            members: vec!["worker".to_string()],
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

        let plan = prepare_replay(
            &checkpoints,
            &inputs,
            &checkpoint.id,
            &record,
            &MatchingAnchor,
        )
        .unwrap();
        assert_eq!(plan.checkpoint_cursor, 4);
        assert_eq!(plan.inputs.len(), 1);

        let other = AgentSessionId::parse("other-session").unwrap();
        let mut other_record = record.clone();
        other_record.session_id = other;
        assert!(
            prepare_replay(
                &checkpoints,
                &inputs,
                &checkpoint.id,
                &other_record,
                &MatchingAnchor,
            )
            .is_err()
        );

        let artifact = temp
            .path()
            .join("sessions/planned-replay/replay-inputs/generation-2/cursor-7.json");
        let mut stored: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&artifact).unwrap()).unwrap();
        stored["ciphertext_b64"] = serde_json::Value::String("changed".to_string());
        mvm_core::atomic_io::atomic_write_durable(
            &artifact,
            &serde_json::to_vec_pretty(&stored).unwrap(),
        )
        .unwrap();
        assert!(
            prepare_replay(
                &checkpoints,
                &inputs,
                &checkpoint.id,
                &record,
                &MatchingAnchor,
            )
            .is_err(),
            "an input replacement cannot match the digest sealed into its step checkpoint"
        );
    }
}
