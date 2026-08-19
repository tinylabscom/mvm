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

use anyhow::Result;
use std::path::Path;

use mvm_contract::protocol::agent_session::AgentSessionId;
use mvm_core::checkpoint::ApprovalHead;
use mvm_core::plan::{PlanSeccompTier, SecretReleasePolicy, SynthesisInput, Variant};
use mvm_runtime::agent_session::{AgentSessionRecord, AgentSessionStore, SandboxResidency};
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
/// Admission runs before the record transition, deliberately: it is the last
/// step that can fail, so a refusal leaves the session parked and resumable
/// rather than half-resumed. A record advanced to a generation that no admitted
/// plan corresponds to would be worse than no resume at all — the session would
/// claim a residency nothing authorized.
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
    // Content only. This catches a blob edited after the checkpoint was sealed;
    // it does not catch a checkpoint that was never audited, which needs a
    // signed chain anchor the caller would have to supply and no caller holds.
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

    Ok(ResumedSession { record, admitted })
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
                runtime_source_policy: None,
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
        // The ordering property. Admission is the last step that can fail, so a
        // host whose ceiling refuses this workload must leave the record parked
        // and resumable — a record advanced to a generation no admitted plan
        // corresponds to would claim a residency nothing authorized.
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
}
