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

use mvm_core::plan::{PlanSeccompTier, SecretReleasePolicy, SynthesisInput};
use mvm_runtime::agent_session::AgentSessionRecord;

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
        l3_network: None,
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
        audit_labels: Default::default(),
        agent_verbs: None,
        services: Vec::new(),
        stream_edges: Vec::new(),
        stream_retention: Default::default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_contract::protocol::agent_session::AgentSessionId;
    use mvm_core::checkpoint::CheckpointDigest;
    use mvm_runtime::agent_session::{AgentSessionRecord, ParkInput, ParkReason, SandboxResidency};

    /// A session that has been parked and names a resume point.
    ///
    /// Goes through the public `park` transition rather than writing
    /// `Hibernated` into the literal, so the fixture cannot drift into a state
    /// the state machine would never produce.
    fn parked_record(id: &str) -> AgentSessionRecord {
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
                    reason: ParkReason::ApprovalWait,
                    journal_cursor: 7,
                    approval_head: None,
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
    }
}
