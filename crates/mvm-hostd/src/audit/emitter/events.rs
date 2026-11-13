//! Chain event emitters and their wire-stable audit label namespaces,
//! grouped by event family.

use super::AuditEmitter;
use anyhow::{Context, Result};
use mvm_core::plan::ExecutionPlan;

use crate::stream::InputRefusal;

pub mod agent_prompt_audit {
    //! Chain-signed records for prompts delivered to a guest's resident agent.
    //!
    //! A prompt is the most sensitive input an agent session carries, so these
    //! entries name it only by content digest and size. Who was prompted, where in
    //! the session's journal, and which encrypted replay artifact holds the bytes
    //! is the decision worth signing; the prompt and the answer stay out of the
    //! chain. A refusal is recorded as the existing `verb_denied` entry, the same
    //! one every other grant refusal produces.

    use crate::audit::emitter::AuditEmitter;
    use anyhow::Result;
    use mvm_core::plan::ExecutionPlan;

    /// Emitted once a prompt is accepted into the session journal and recorded,
    /// before it is sent to the guest.
    pub const DELIVERED_EVENT: &str = "agent.prompt_delivered";
    /// Emitted when the guest has answered, or the delivery failed.
    pub const COMPLETED_EVENT: &str = "agent.prompt_completed";
    /// Label: the machine whose agent was prompted.
    pub const LABEL_VM_NAME: &str = "vm_name";
    /// Label: the agent session the prompt belongs to.
    pub const LABEL_SESSION_ID: &str = "agent_session_id";
    /// Label: the session generation.
    pub const LABEL_GENERATION: &str = "agent_session_generation";
    /// Label: the journal cursor the prompt was accepted at.
    pub const LABEL_JOURNAL_CURSOR: &str = "journal_cursor";
    /// Label: `sha256:<hex>` of the prompt bytes.
    pub const LABEL_PROMPT_SHA256: &str = "prompt_sha256";
    /// Label: the prompt's length in bytes.
    pub const LABEL_PROMPT_BYTES: &str = "prompt_bytes";
    /// Label: content address of the encrypted replay artifact.
    pub const LABEL_REPLAY_INPUT: &str = "replay_input_digest";
    /// Label: `live` for an operator prompt, `replay` for a re-delivery.
    pub const LABEL_DELIVERY: &str = "delivery";
    /// Label: how the delivery ended, a closed vocabulary.
    pub const LABEL_OUTCOME: &str = "outcome";

    /// Whether a prompt was sent by a caller or re-sent from a recorded step.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum PromptDelivery {
        Live,
        Replay,
    }

    impl PromptDelivery {
        fn label(self) -> &'static str {
            match self {
                Self::Live => "live",
                Self::Replay => "replay",
            }
        }
    }

    /// Where one prompt sits: the machine, its session, and its journal position.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct PromptAuditBinding {
        pub vm_name: String,
        pub session_id: String,
        pub generation: u64,
        pub journal_cursor: u64,
        pub delivery: PromptDelivery,
    }

    impl PromptAuditBinding {
        fn labels(&self) -> [(String, String); 5] {
            [
                (LABEL_VM_NAME.to_string(), self.vm_name.clone()),
                (LABEL_SESSION_ID.to_string(), self.session_id.clone()),
                (LABEL_GENERATION.to_string(), self.generation.to_string()),
                (
                    LABEL_JOURNAL_CURSOR.to_string(),
                    self.journal_cursor.to_string(),
                ),
                (
                    LABEL_DELIVERY.to_string(),
                    self.delivery.label().to_string(),
                ),
            ]
        }
    }

    /// The prompt as the chain may see it: its digest and size, never its bytes.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct PromptFingerprint {
        /// `sha256:<hex>` of the prompt.
        pub sha256: String,
        /// Length of the prompt in bytes.
        pub bytes: usize,
        /// Content address of the encrypted replay artifact holding the prompt.
        pub replay_input_digest: String,
    }

    impl PromptFingerprint {
        /// Fingerprint `prompt`, naming the artifact it was recorded under.
        #[must_use]
        pub fn of(prompt: &[u8], replay_input_digest: &str) -> Self {
            use sha2::Digest as _;
            Self {
                sha256: format!("sha256:{}", hex::encode(sha2::Sha256::digest(prompt))),
                bytes: prompt.len(),
                replay_input_digest: replay_input_digest.to_string(),
            }
        }
    }

    impl AuditEmitter {
        /// Record that a prompt is about to reach the guest. Callers send the
        /// prompt only after this returns `Ok`: a prompt the chain does not hold
        /// is a prompt that was not delivered.
        pub fn emit_agent_prompt_delivered(
            &self,
            plan: &ExecutionPlan,
            binding: &PromptAuditBinding,
            prompt: &PromptFingerprint,
        ) -> Result<()> {
            let mut labels = binding.labels().to_vec();
            labels.extend([
                (LABEL_PROMPT_SHA256.to_string(), prompt.sha256.clone()),
                (LABEL_PROMPT_BYTES.to_string(), prompt.bytes.to_string()),
                (
                    LABEL_REPLAY_INPUT.to_string(),
                    prompt.replay_input_digest.clone(),
                ),
            ]);
            self.emit(plan, DELIVERED_EVENT, labels)
        }

        /// Record how a delivered prompt ended. `outcome` is a closed-vocabulary
        /// label such as `exited:0` or `failed:timeout`, never agent output.
        pub fn emit_agent_prompt_completed(
            &self,
            plan: &ExecutionPlan,
            binding: &PromptAuditBinding,
            outcome: &str,
        ) -> Result<()> {
            let mut labels = binding.labels().to_vec();
            labels.push((LABEL_OUTCOME.to_string(), outcome.to_string()));
            self.emit(plan, COMPLETED_EVENT, labels)
        }
    }
}

pub mod checkpoint_audit {
    //! Wire-stable event names and label keys for checkpoint audit entries.
    //!
    //! Shared so the emitter and lineage chain-anchor cannot drift on a string and
    //! silently defeat chain-anchored lineage verification.

    /// Emitted when a VM's state is frozen into a checkpoint.
    pub const CREATED_EVENT: &str = "checkpoint.created";
    /// Emitted when a VM is resumed from a vm_full checkpoint (same identity).
    pub const RESTORED_EVENT: &str = "checkpoint.restored";
    /// Emitted when a new sandbox is branched from a checkpoint.
    pub const FORKED_EVENT: &str = "checkpoint.forked";

    /// Label: the checkpoint's own id (created/restored).
    pub const LABEL_CHECKPOINT_ID: &str = "checkpoint_id";
    /// Label: the checkpoint's content-address (created/restored).
    pub const LABEL_META_DIGEST: &str = "meta_digest";
    /// Label: the checkpoint class (created).
    pub const LABEL_CLASS: &str = "class";
    /// Label: the owning VM name (created/restored).
    pub const LABEL_VM_NAME: &str = "vm_name";
    /// Label: how a restore was initiated (`revert` / `rewind` / `advance`).
    pub const LABEL_VIA: &str = "via";
    /// Label: the parent checkpoint id (forked).
    pub const LABEL_PARENT_ID: &str = "parent_id";
    /// Label: the child (new) checkpoint id (forked).
    pub const LABEL_CHILD_ID: &str = "child_id";
    /// Label: the child VM name (forked).
    pub const LABEL_CHILD_VM_NAME: &str = "child_vm_name";
    /// Label: the parent's content-address, i.e. the child's hash-link (forked).
    pub const LABEL_PARENT_DIGEST: &str = "parent_digest";
    /// Label: the child's content-address (forked).
    pub const LABEL_CHILD_DIGEST: &str = "child_digest";
    /// Label: JSON array of child binding names and destination allow-lists.
    /// This never contains keystore addresses, providers, or secret values.
    pub const LABEL_SECRET_BINDINGS: &str = "secret_bindings";

    /// Complete non-secret label payload for a `checkpoint.forked` event.
    pub struct CheckpointForkedAudit<'a> {
        pub parent_id: &'a str,
        pub child_id: &'a str,
        pub child_vm_name: &'a str,
        pub parent_digest: &'a str,
        pub child_digest: &'a str,
        pub secret_bindings_json: &'a str,
    }
}

pub mod display_audit {
    //! Chain-signed records for host-to-guest display input.
    //!
    //! Payload-free by construction: an input event is recorded as its kind and a
    //! count, never the key, the text, or the coordinates. A human typing a
    //! password through an attended display is the case this plane exists for, so
    //! the chain must be unable to hold one.

    use std::collections::BTreeMap;

    use crate::audit::emitter::AuditEmitter;
    use anyhow::Result;
    use mvm_core::plan::ExecutionPlan;

    /// A writer was admitted to a workload's display input.
    pub const GRANTED_EVENT: &str = "display.granted";
    /// A display input writer or frame was turned away.
    pub const REFUSED_EVENT: &str = "display.refused";
    /// A batch of display input events was delivered toward the guest.
    pub const INPUT_EVENT: &str = "display.input_event";
    /// A human began typing a credential; recording pauses from here.
    pub const CREDENTIAL_ENTRY_BEGIN_EVENT: &str = "display.credential_entry_begin";
    /// The credential entry ended; recording resumes.
    pub const CREDENTIAL_ENTRY_END_EVENT: &str = "display.credential_entry_end";
    /// Label: the VM whose display was driven.
    pub const LABEL_VM_NAME: &str = "vm_name";
    /// Label: the display input lease holder.
    pub const LABEL_HOLDER: &str = "display_input_holder";
    /// Label: why the gate refused, as a wire-stable reason word.
    pub const LABEL_REASON: &str = "display_input_reason";
    /// Label: the writer's frame sequence number.
    pub const LABEL_SEQ: &str = "display_input_seq";
    /// Label: total events in the delivered batch.
    pub const LABEL_EVENT_COUNT: &str = "display_input_events";
    /// Label: per-kind counts, `kind=count` joined by commas in kind order.
    pub const LABEL_EVENT_KINDS: &str = "display_input_kinds";
    /// Label: whether the run was admitted as attended.
    pub const LABEL_ATTENDED: &str = "display_input_attended";

    impl AuditEmitter {
        /// Emit `display.granted`: a writer took a VM's display input lease.
        pub fn emit_display_granted(
            &self,
            plan: &ExecutionPlan,
            vm_name: &str,
            holder: &str,
            attended: bool,
        ) -> Result<()> {
            self.emit(
                plan,
                GRANTED_EVENT,
                [
                    (LABEL_VM_NAME.to_string(), vm_name.to_string()),
                    (LABEL_HOLDER.to_string(), holder.to_string()),
                    (LABEL_ATTENDED.to_string(), attended.to_string()),
                ],
            )
        }

        /// Emit `display.refused`: the binding and the reason word, nothing about
        /// the events that were refused.
        pub fn emit_display_refused(
            &self,
            plan: &ExecutionPlan,
            vm_name: &str,
            reason: &str,
        ) -> Result<()> {
            self.emit(
                plan,
                REFUSED_EVENT,
                [
                    (LABEL_VM_NAME.to_string(), vm_name.to_string()),
                    (LABEL_REASON.to_string(), reason.to_string()),
                ],
            )
        }

        /// Emit `display.input_event` for one delivered batch: how many events of
        /// each kind, never what they carried.
        pub fn emit_display_input_events(
            &self,
            plan: &ExecutionPlan,
            vm_name: &str,
            holder: &str,
            seq: u64,
            kinds: &BTreeMap<&'static str, u32>,
        ) -> Result<()> {
            let total: u64 = kinds.values().map(|count| u64::from(*count)).sum();
            let rendered = kinds
                .iter()
                .map(|(kind, count)| format!("{kind}={count}"))
                .collect::<Vec<_>>()
                .join(",");
            self.emit(
                plan,
                INPUT_EVENT,
                [
                    (LABEL_VM_NAME.to_string(), vm_name.to_string()),
                    (LABEL_HOLDER.to_string(), holder.to_string()),
                    (LABEL_SEQ.to_string(), seq.to_string()),
                    (LABEL_EVENT_COUNT.to_string(), total.to_string()),
                    (LABEL_EVENT_KINDS.to_string(), rendered),
                ],
            )
        }

        /// Emit the start or end of a credential entry window.
        pub fn emit_display_credential_entry(
            &self,
            plan: &ExecutionPlan,
            vm_name: &str,
            holder: &str,
            began: bool,
        ) -> Result<()> {
            let event = if began {
                CREDENTIAL_ENTRY_BEGIN_EVENT
            } else {
                CREDENTIAL_ENTRY_END_EVENT
            };
            self.emit(
                plan,
                event,
                [
                    (LABEL_VM_NAME.to_string(), vm_name.to_string()),
                    (LABEL_HOLDER.to_string(), holder.to_string()),
                ],
            )
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use mvm_contract::stream::{DisplayInputEvent, DisplayInputFrame};
        use mvm_core::plan::test_support::PlanFixture;

        #[test]
        fn an_input_event_entry_carries_kinds_and_counts_and_nothing_typed() {
            let dir = tempfile::tempdir().unwrap();
            let emitter =
                AuditEmitter::with_dir(ed25519_dalek::SigningKey::from_bytes(&[3; 32]), dir.path())
                    .unwrap();
            let frame = DisplayInputFrame {
                seq: 7,
                events: vec![
                    DisplayInputEvent::Text {
                        text: "hunter2".into(),
                    },
                    DisplayInputEvent::Key {
                        key: "Enter".into(),
                        pressed: true,
                    },
                    DisplayInputEvent::Key {
                        key: "Enter".into(),
                        pressed: false,
                    },
                ],
            };
            emitter
                .emit_display_input_events(
                    &PlanFixture::new().build(),
                    "attended-vm",
                    "holder#1",
                    frame.seq,
                    &frame.kind_counts(),
                )
                .unwrap();

            let mut chain = String::new();
            for entry in std::fs::read_dir(dir.path()).unwrap() {
                let path = entry.unwrap().path();
                if path.extension().is_some_and(|ext| ext == "jsonl") {
                    chain.push_str(&std::fs::read_to_string(path).unwrap());
                }
            }
            assert!(chain.contains(INPUT_EVENT), "{chain}");
            assert!(chain.contains("key=2,text=1"), "{chain}");
            assert!(
                !chain.contains("hunter2") && !chain.contains("Enter"),
                "{chain}"
            );
        }
    }
}

pub mod drive_audit {
    //! Chain-signed refusal records for the grant-gated drive plane.

    use crate::audit::emitter::AuditEmitter;
    use anyhow::Result;
    use mvm_agentd::vsock::DriveRefusal;
    use mvm_core::plan::ExecutionPlan;

    /// Wire-stable event name for a drive refusal.
    pub const REFUSED_EVENT: &str = "drive.refused";
    /// Label naming the machine whose drive request was refused.
    pub const LABEL_VM_NAME: &str = "vm_name";
    /// Label carrying the payload-free refusal reason.
    pub const LABEL_REASON: &str = "drive_refusal_reason";

    impl AuditEmitter {
        /// Emit a payload-free, chain-signed drive refusal.
        pub fn emit_drive_refused(
            &self,
            plan: &ExecutionPlan,
            vm_name: &str,
            refusal: DriveRefusal,
        ) -> Result<()> {
            self.emit(
                plan,
                REFUSED_EVENT,
                [
                    (LABEL_VM_NAME.to_string(), vm_name.to_string()),
                    (LABEL_REASON.to_string(), refusal.reason().to_string()),
                ],
            )
        }
    }
}

pub mod grants_audit {
    //! Wire-stable event name and label keys for what bounded a workload, and for a
    //! memory ceiling that fired.
    //!
    //! Shared so the launch path, the supervisor and any reader asserting on an
    //! entry cannot drift on a string.

    use anyhow::Result;
    use mvm_contract::protocol::resource_controls::{
        EnforcedCeiling, EnforcedGrants, EnforcedTier,
    };
    use mvm_core::plan::ExecutionPlan;

    use crate::audit::emitter::AuditEmitter;

    /// Label: the mechanism that bounded CPU.
    pub const LABEL_CPU_TIER: &str = "grants_cpu_tier";
    /// Label: the mechanism that bounded wall clock.
    pub const LABEL_WALL_CLOCK_TIER: &str = "grants_wall_clock_tier";
    /// Label: the mechanism holding the VMM's memory ceiling.
    pub const LABEL_MEMORY_TIER: &str = "grants_memory_tier";
    /// Label: the memory ceiling read back, in bytes. Absent when declared.
    pub const LABEL_MEMORY_MAX_BYTES: &str = "grants_memory_max_bytes";
    /// Label: the mechanism holding the VMM's task ceiling.
    pub const LABEL_TASKS_TIER: &str = "grants_tasks_tier";
    /// Label: the task ceiling read back. Absent when declared.
    pub const LABEL_TASKS_MAX: &str = "grants_tasks_max";

    /// Emitted when the kernel killed a workload's VMM for crossing its memory
    /// ceiling.
    pub const MEMORY_LIMIT_EXCEEDED_EVENT: &str = "plan.memory_limit_exceeded";
    /// Label: the ceiling the scope carried, in bytes, when it reported one.
    pub const LABEL_KILLED_AT_BYTES: &str = "memory_max_bytes";
    /// Label: which mechanism killed it.
    pub const LABEL_ENFORCED_BY: &str = "enforced_by";

    impl AuditEmitter {
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
            enforced: &EnforcedGrants,
        ) -> Result<()> {
            self.emit(
                plan,
                "plan.grants_enforced",
                enforced_grants_labels(enforced),
            )
        }

        /// Emit `plan.memory_limit_exceeded` — records that the kernel killed this
        /// workload's VMM for crossing the memory ceiling its scope carried.
        ///
        /// Without it, a VMM stopped by its ceiling and one that crashed look the
        /// same from the chain, and a bound nobody can observe firing is a
        /// declaration again.
        pub fn emit_memory_limit_exceeded(
            &self,
            plan: &ExecutionPlan,
            exceeded: &mvm_core::spawn_scope::MemoryLimitExceeded,
        ) -> Result<()> {
            let mut labels = vec![(
                LABEL_ENFORCED_BY.to_string(),
                EnforcedTier::Cgroup2MemoryMax.label().to_string(),
            )];
            if let Some(bytes) = exceeded.memory_max_bytes {
                labels.push((LABEL_KILLED_AT_BYTES.to_string(), bytes.to_string()));
            }
            self.emit(plan, MEMORY_LIMIT_EXCEEDED_EVENT, labels)
        }
    }

    /// The labels naming what bounded each dimension, and the ceiling values read
    /// back where a ceiling holds.
    ///
    /// Tiers and read-back values, never requested numbers: a run that asked for
    /// 1.5 cores and got nothing must not leave a record that mentions 1.5 cores,
    /// or the audit trail asserts an enforcement that did not happen.
    #[must_use]
    pub fn enforced_grants_labels(enforced: &EnforcedGrants) -> Vec<(String, String)> {
        let mut labels = vec![
            (LABEL_CPU_TIER.to_string(), enforced.cpu.label().to_string()),
            (
                LABEL_WALL_CLOCK_TIER.to_string(),
                enforced.wall_clock.label().to_string(),
            ),
        ];
        push_ceiling(
            &mut labels,
            LABEL_MEMORY_TIER,
            LABEL_MEMORY_MAX_BYTES,
            enforced.memory,
        );
        push_ceiling(
            &mut labels,
            LABEL_TASKS_TIER,
            LABEL_TASKS_MAX,
            enforced.tasks,
        );
        labels
    }

    fn push_ceiling(
        labels: &mut Vec<(String, String)>,
        tier_key: &str,
        value_key: &str,
        ceiling: EnforcedCeiling,
    ) {
        labels.push((tier_key.to_string(), ceiling.tier().label().to_string()));
        if let Some(limit) = ceiling.limit() {
            labels.push((value_key.to_string(), limit.to_string()));
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn label<'a>(labels: &'a [(String, String)], key: &str) -> Option<&'a str> {
            labels
                .iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v.as_str())
        }

        #[test]
        fn enforced_ceilings_are_labelled_with_their_tier_and_read_back_value() {
            let labels = enforced_grants_labels(&EnforcedGrants {
                cpu: EnforcedTier::Declared,
                wall_clock: EnforcedTier::Declared,
                memory: EnforcedCeiling::enforced(EnforcedTier::Cgroup2MemoryMax, 805_306_368),
                tasks: EnforcedCeiling::enforced(EnforcedTier::Cgroup2PidsMax, 1024),
            });
            assert_eq!(
                label(&labels, LABEL_MEMORY_TIER),
                Some("cgroup2:memory.max")
            );
            assert_eq!(label(&labels, LABEL_MEMORY_MAX_BYTES), Some("805306368"));
            assert_eq!(label(&labels, LABEL_TASKS_TIER), Some("cgroup2:pids.max"));
            assert_eq!(label(&labels, LABEL_TASKS_MAX), Some("1024"));
        }

        #[test]
        fn a_declared_ceiling_is_named_but_carries_no_number() {
            // A number beside "declared" would read as a bound that held.
            let labels = enforced_grants_labels(&EnforcedGrants::all_declared());
            assert_eq!(label(&labels, LABEL_MEMORY_TIER), Some("declared"));
            assert_eq!(label(&labels, LABEL_TASKS_TIER), Some("declared"));
            assert_eq!(label(&labels, LABEL_MEMORY_MAX_BYTES), None);
            assert_eq!(label(&labels, LABEL_TASKS_MAX), None);
            assert_eq!(label(&labels, LABEL_CPU_TIER), Some("declared"));
            assert_eq!(label(&labels, LABEL_WALL_CLOCK_TIER), Some("declared"));
        }
    }
}

pub mod image_audit {
    //! Wire-stable image version-lineage audit labels.

    /// Emitted when a compiled image's version-lineage node is created.
    pub const CREATED_EVENT: &str = "image.created";
    /// Emitted when a fresh VM is launched from a prior image-lineage node.
    pub const REVERTED_EVENT: &str = "image.reverted";
    /// Label: how a restore was initiated (`revert` / `rewind` / `advance`).
    pub const LABEL_VIA: &str = "via";
    /// Label: the reconstructed `machine run` reference a restore re-runs.
    pub const LABEL_REVERTED_REFERENCE: &str = "image_reverted_reference";
    /// Label: the node's own content-address. The chain-anchor keys on this.
    pub const LABEL_NODE_DIGEST: &str = "image_node_digest";
    /// Label: the predecessor node's content-address.
    pub const LABEL_PARENT_DIGEST: &str = "image_parent_digest";
    /// Label: the build-identity discriminant (`"flake"` / `"oci"`).
    pub const LABEL_BUILD_IDENTITY_KIND: &str = "image_build_identity_kind";
    /// Label: the build-identity value.
    pub const LABEL_BUILD_IDENTITY: &str = "image_build_identity";
    /// Label: the provenance discriminant (`"build"` / `"oci"`).
    pub const LABEL_PROVENANCE_KIND: &str = "image_provenance_kind";
    /// Label: the build-provenance input reference.
    pub const LABEL_PROVENANCE_INPUT_REF: &str = "image_provenance_input_ref";
    /// Label: the build-provenance lock digest, when recorded.
    pub const LABEL_PROVENANCE_LOCK_DIGEST: &str = "image_provenance_lock_digest";
    /// Label: the OCI-provenance resolved manifest digest.
    pub const LABEL_PROVENANCE_RESOLVED_DIGEST: &str = "image_provenance_resolved_digest";
    /// Label: the OCI-provenance layer digest set (comma-joined).
    pub const LABEL_PROVENANCE_LAYER_DIGESTS: &str = "image_provenance_layer_digests";
    /// Sentinel for a genesis (parentless) node.
    pub const GENESIS_PARENT: &str = "genesis";
}

pub mod instruction_audit {
    //! Chain-signed records of instruction-file provenance verdicts.
    //!
    //! Before a boot, every agent instruction file the boot copies into the guest
    //! is verified against the operator's trust policy. Each verdict is recorded
    //! here, bound to the plan the boot was admitted under, whether the policy
    //! then refuses the boot, warns, or only records. The labels name the file,
    //! its digest and the verdict — never the file's content.

    use anyhow::Result;
    use mvm_core::plan::ExecutionPlan;

    use crate::audit::emitter::AuditEmitter;

    /// The verdict an instruction-file record carries.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub enum InstructionTrustEvent {
        /// Signed by a publisher the policy trusts.
        Verified,
        /// No signature beside the file.
        Unsigned,
        /// Refused for a named reason: a blocked digest, a signature from an
        /// untrusted publisher, a signature that does not verify, or a file that
        /// could not be read. Whether the boot was actually stopped is the
        /// record's `action` label, which follows the enforcement mode.
        Blocked,
    }

    impl InstructionTrustEvent {
        /// The chain event name.
        #[must_use]
        pub fn as_str(self) -> &'static str {
            match self {
                InstructionTrustEvent::Verified => "trust.instruction_verified",
                InstructionTrustEvent::Unsigned => "trust.instruction_unsigned",
                InstructionTrustEvent::Blocked => "trust.instruction_blocked",
            }
        }
    }

    impl AuditEmitter {
        /// Emit one instruction-file verdict under `plan`.
        pub fn emit_instruction_trust(
            &self,
            plan: &ExecutionPlan,
            event: InstructionTrustEvent,
            labels: Vec<(String, String)>,
        ) -> Result<()> {
            self.emit(plan, event.as_str(), labels)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::audit::emitter::AuditEmitter;
        use ed25519_dalek::SigningKey;

        #[test]
        fn event_names_are_the_documented_wire_names() {
            assert_eq!(
                InstructionTrustEvent::Verified.as_str(),
                "trust.instruction_verified"
            );
            assert_eq!(
                InstructionTrustEvent::Unsigned.as_str(),
                "trust.instruction_unsigned"
            );
            assert_eq!(
                InstructionTrustEvent::Blocked.as_str(),
                "trust.instruction_blocked"
            );
        }

        #[test]
        fn a_verdict_is_appended_to_the_tenant_chain_with_its_labels() {
            let dir = tempfile::tempdir().unwrap();
            let emitter =
                AuditEmitter::with_dir(SigningKey::from_bytes(&[5; 32]), dir.path()).unwrap();
            let plan = mvm_core::plan::test_support::PlanFixture::new()
                .tenant("local")
                .plan_id("plan-instruction-emit")
                .build();
            emitter
                .emit_instruction_trust(
                    &plan,
                    InstructionTrustEvent::Blocked,
                    vec![
                        ("path".to_string(), "/w/CLAUDE.md".to_string()),
                        ("reason".to_string(), "bad_signature".to_string()),
                    ],
                )
                .unwrap();
            let chain = std::fs::read_to_string(dir.path().join("local.jsonl")).unwrap();
            let line = chain.lines().last().expect("one entry");
            let entry: serde_json::Value = serde_json::from_str(line).unwrap();
            assert_eq!(entry["entry"]["event"], "trust.instruction_blocked");
            assert_eq!(entry["entry"]["labels"]["path"], "/w/CLAUDE.md");
            assert_eq!(entry["entry"]["labels"]["reason"], "bad_signature");
        }
    }
}

pub mod stream_audit {
    //! Wire-stable event names and label keys for the workload output-stream audit.
    //!
    //! Shared by the emitter and readers so the strings cannot drift. One entry is
    //! signed per attach, never per record: output bytes stay in the transcript.

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

pub mod guest_memory_audit {
    //! Wire-stable event name and label keys for the guest-memory scrub entry.
    //!
    //! Counts only. The entry says how much of a guest's RAM the teardown
    //! scrubbed and that none of it read non-zero afterwards; it never carries
    //! an address or a byte of what was in memory.

    /// Emitted by the supervisor after it scrubbed the guest's RAM at teardown.
    pub const SCRUBBED_EVENT: &str = "plan.guest_memory_scrubbed";
    /// Label: which backend's mapping was scrubbed.
    pub const LABEL_BACKEND: &str = "backend";
    /// Label: size of the guest RAM mapping, in bytes.
    pub const LABEL_MAPPED_BYTES: &str = "mapped_bytes";
    /// Label: pages the scrub found resident and zeroed.
    pub const LABEL_SCRUBBED_PAGES: &str = "scrubbed_pages";
    /// Label: bytes still non-zero after the scrub; zero when it worked.
    pub const LABEL_NONZERO_BYTES_AFTER: &str = "nonzero_bytes_after";
    /// Label: whether the whole mapping was scrubbed or only its resident pages.
    pub const LABEL_WHOLE_MAPPING: &str = "whole_mapping";

    /// What a teardown scrub reports, as the facts the entry carries.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct GuestMemoryScrub {
        pub backend: &'static str,
        pub mapped_bytes: u64,
        pub scrubbed_pages: u64,
        pub nonzero_bytes_after: u64,
        pub whole_mapping: bool,
    }
}

pub mod wall_clock_audit {
    //! Wire-stable event name and label keys for wall-clock enforcement entries.
    //!
    //! Shared so the supervisor that emits an entry and any reader asserting on it
    //! cannot drift on a string.

    /// Emitted when a supervisor timer killed a workload at its deadline.
    pub const EXPIRED_EVENT: &str = "plan.wall_clock_expired";
    /// Label: the bound that was enforced, in seconds.
    pub const LABEL_BOUND_SECS: &str = "wall_clock_secs";
    /// Label: wall-clock seconds actually elapsed when the timer fired.
    pub const LABEL_ELAPSED_SECS: &str = "elapsed_secs";
    /// Label: which mechanism killed it, so the entry names a fact rather than
    /// leaving the reader to infer one.
    pub const LABEL_ENFORCED_BY: &str = "enforced_by";
}

impl AuditEmitter {
    /// Emit `plan.guest_memory_scrubbed` — what the teardown scrub did to the
    /// guest's RAM, as counts. It is the durable half of the self-destruction
    /// claim: the scrub's own record is a file the VM's state directory loses
    /// when the VM is cleaned up, and this entry is signed into the chain
    /// before that happens.
    pub fn emit_guest_memory_scrubbed(
        &self,
        plan: &ExecutionPlan,
        scrub: &guest_memory_audit::GuestMemoryScrub,
    ) -> Result<()> {
        self.emit(
            plan,
            guest_memory_audit::SCRUBBED_EVENT,
            [
                (
                    guest_memory_audit::LABEL_BACKEND.to_string(),
                    scrub.backend.to_string(),
                ),
                (
                    guest_memory_audit::LABEL_MAPPED_BYTES.to_string(),
                    scrub.mapped_bytes.to_string(),
                ),
                (
                    guest_memory_audit::LABEL_SCRUBBED_PAGES.to_string(),
                    scrub.scrubbed_pages.to_string(),
                ),
                (
                    guest_memory_audit::LABEL_NONZERO_BYTES_AFTER.to_string(),
                    scrub.nonzero_bytes_after.to_string(),
                ),
                (
                    guest_memory_audit::LABEL_WHOLE_MAPPING.to_string(),
                    scrub.whole_mapping.to_string(),
                ),
            ],
        )
    }
}

impl AuditEmitter {
    /// Record only a completion produced by the original native custody owner.
    pub fn emit_native_completed(
        &self,
        plan: &ExecutionPlan,
        completion: &mvm_runtime::workload_runner::runner::NativeCompletion,
    ) -> Result<()> {
        anyhow::ensure!(
            completion.evidence().instance.vm_id == plan.workload.0
                && completion.evidence().rootfs_sha256 == plan.image.sha256,
            "original native completion differs from its admitted workload or image"
        );
        let evidence = serde_json::to_string(completion.evidence())
            .context("encoding native completion observations")?;
        self.emit(
            plan,
            "plan.native_completed",
            [
                ("native_completion".to_owned(), evidence),
                (
                    "bundle_sha256".to_owned(),
                    plan.bundle
                        .as_ref()
                        .map(|bundle| bundle.bundle_sha256.clone())
                        .unwrap_or_default(),
                ),
            ],
        )
    }
}

impl AuditEmitter {
    /// Emit `plan.teardown_failed`: the session's VM could not be shown to be
    /// stopped, or its exit and seal could not be written, so the session is
    /// deliberately left `UNSEALED`. `reason` is a short tag (`stop-failed`,
    /// `seal-failed`); `message` is the rendered error chain. The entry is the
    /// record of why a session that ended carries no seal.
    pub fn emit_teardown_failed(
        &self,
        plan: &ExecutionPlan,
        reason: &str,
        message: &str,
    ) -> Result<()> {
        self.emit(
            plan,
            "plan.teardown_failed",
            [
                ("reason".to_string(), reason.to_string()),
                ("error_message".to_string(), message.to_string()),
            ],
        )
    }

    /// Emit `session.parked` — a durable agent session released its sandbox.
    ///
    /// Bound to the plan the parked residency was admitted under, so the chain
    /// records which authorization the session was running with when it
    /// stopped. The caller supplies the labels; they name the session, the
    /// generation, the reason and the storage tier, and carry nothing the
    /// session was working on.
    pub fn emit_session_parked(
        &self,
        plan: &ExecutionPlan,
        labels: Vec<(String, String)>,
    ) -> Result<()> {
        self.emit(plan, "session.parked", labels)
    }

    /// Emit `session.resumed` — a parked durable agent session was
    /// re-admitted into a new residency.
    ///
    /// Bound to the freshly signed plan the resume admitted, which is the
    /// authority the new residency runs under. Nothing of the previous
    /// residency's authority carries over, and neither does its plan.
    pub fn emit_session_resumed(
        &self,
        plan: &ExecutionPlan,
        labels: Vec<(String, String)>,
    ) -> Result<()> {
        self.emit(plan, "session.resumed", labels)
    }

    /// Emit `session.renewed` — a parked durable agent session's retention
    /// deadline was moved later.
    ///
    /// Bound to the same plan a park entry is, the one the parked residency
    /// was admitted under: a renewal changes how long the host holds that
    /// residency, not what it is authorized to do.
    pub fn emit_session_renewed(
        &self,
        plan: &ExecutionPlan,
        labels: Vec<(String, String)>,
    ) -> Result<()> {
        self.emit(plan, "session.renewed", labels)
    }
}

/// Keep the binding and actionable reason without copying workload bytes.
pub(super) fn input_refused_labels(vm_name: &str, refusal: &InputRefusal) -> Vec<(String, String)> {
    let mut labels = vec![
        (stream_audit::LABEL_VM_NAME.to_string(), vm_name.to_string()),
        (
            stream_audit::LABEL_REASON.to_string(),
            refusal.reason().to_string(),
        ),
    ];
    match refusal {
        // An unauditable refusal can be recorded only if a later attempt
        // succeeds after the signing failure was transient.
        InputRefusal::NotGranted | InputRefusal::LeaseExpired | InputRefusal::Unauditable => {}
        InputRefusal::LeaseHeld { holder } => {
            labels.push((stream_audit::LABEL_HOLDER.to_string(), holder.clone()));
        }
        InputRefusal::SecretMaterial { category } => {
            labels.push((
                stream_audit::LABEL_SECRET_CATEGORY.to_string(),
                (*category).to_string(),
            ));
        }
        InputRefusal::OutOfOrder { seq, after } => {
            labels.push((stream_audit::LABEL_SEQ.to_string(), seq.to_string()));
            labels.push((stream_audit::LABEL_AFTER_SEQ.to_string(), after.to_string()));
        }
    }
    labels
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every refusal variant reaches the chain under its own reason word, and
    /// no variant's labels can grow a key outside this allow-list.
    #[test]
    fn every_input_refusal_variant_is_labelled_with_its_reason_and_nothing_more() {
        let allowed = [
            stream_audit::LABEL_VM_NAME,
            stream_audit::LABEL_REASON,
            stream_audit::LABEL_HOLDER,
            stream_audit::LABEL_SECRET_CATEGORY,
            stream_audit::LABEL_SEQ,
            stream_audit::LABEL_AFTER_SEQ,
        ];
        for refusal in [
            InputRefusal::NotGranted,
            InputRefusal::Unauditable,
            InputRefusal::LeaseExpired,
            InputRefusal::LeaseHeld {
                holder: "plan-1#0".to_string(),
            },
            InputRefusal::SecretMaterial {
                category: "host-secret",
            },
            InputRefusal::OutOfOrder { seq: 3, after: 9 },
        ] {
            let labels = input_refused_labels("vm-1", &refusal);
            let by_key: std::collections::BTreeMap<&str, &str> = labels
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect();
            assert_eq!(by_key.len(), labels.len(), "no duplicate keys: {labels:?}");
            assert_eq!(by_key.get(stream_audit::LABEL_VM_NAME), Some(&"vm-1"));
            assert_eq!(
                by_key.get(stream_audit::LABEL_REASON),
                Some(&refusal.reason())
            );
            for key in by_key.keys() {
                assert!(
                    allowed.contains(key),
                    "unexpected label {key} on {refusal:?}"
                );
            }
        }

        let ordered = input_refused_labels("vm-1", &InputRefusal::OutOfOrder { seq: 3, after: 9 });
        assert!(ordered.contains(&(stream_audit::LABEL_SEQ.to_string(), "3".to_string())));
        assert!(ordered.contains(&(stream_audit::LABEL_AFTER_SEQ.to_string(), "9".to_string())));
    }
}
