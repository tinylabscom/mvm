//! Arming a warm-claimed child's bounds in the supervisor it inherits.
//!
//! A resident standby parent boots before any workload exists, so its
//! supervisor starts with no plan and arms nothing. A claim then hands that
//! paused parent to a child admitted under a plan of its own, and the process
//! that owns the guest from then on is still the parent's supervisor. Without
//! this module the child ran with neither its wall-clock bound nor its session
//! idle timeout enforced, although a cold boot of the same plan had both.
//!
//! The handoff carries the child's admitted plan, bound into the handoff
//! signature, and the supervisor arms from it exactly what it arms at a cold
//! boot, with the same refusal: a bound it cannot audit stops the child rather
//! than letting it run unbounded. That includes the unit timer: a child whose
//! topology unit declares a liveness period, or writes a cell, gets the same
//! deadline owner and cell digest here as it would from its own supervisor.
//! The parent has not been told the claim committed at that point — the host
//! is still waiting on the child's identity handshake — so a refused arm fails
//! the claim instead of half-admitting it.

use std::path::Path;

use anyhow::{Context, Result};
use mvm_vmm::hvf_handoff::AcceptedHandoff;

use crate::supervisor::lifecycle::liveness_expiry::LivenessGuard;
use crate::supervisor::lifecycle::wall_clock::{SupervisorTimerInputs, WallClockGuard};

/// What the supervisor holds for a claimed child. Dropping it stands every
/// timer in it down.
#[derive(Default)]
pub struct ClaimedChildBounds {
    wall_clock: Option<WallClockGuard>,
    unit_timer: Option<LivenessGuard>,
}

impl ClaimedChildBounds {
    /// Whether the child's wall-clock bound is being held.
    #[must_use]
    pub fn wall_clock_armed(&self) -> bool {
        self.wall_clock.is_some()
    }

    /// Whether the child's unit timer, its liveness deadline and cell digest,
    /// is running.
    #[must_use]
    pub fn unit_timer_armed(&self) -> bool {
        self.unit_timer.is_some()
    }
}

/// Arm the wall-clock timer, the session expiry watcher and the unit timer
/// for the child `accepted` names, from the plan it was admitted under.
///
/// Nothing is armed when the claim carried no plan. The session watcher is
/// armed whenever there is one, because it decides for itself whether the
/// child is a session.
///
/// # Errors
/// The plan is not JSON, cannot be decoded, or declares a wall-clock bound or
/// a unit timer whose record could not be audited.
pub fn arm_for_claimed_child(
    accepted: &AcceptedHandoff,
    pid_file: &Path,
) -> Result<ClaimedChildBounds> {
    arm_child_with_policy(accepted, pid_file, false)
}

pub fn arm_for_claimed_child_preserving_evidence(
    accepted: &AcceptedHandoff,
    pid_file: &Path,
) -> Result<ClaimedChildBounds> {
    arm_child_with_policy(accepted, pid_file, true)
}

fn arm_child_with_policy(
    accepted: &AcceptedHandoff,
    pid_file: &Path,
    retain_evidence: bool,
) -> Result<ClaimedChildBounds> {
    let Some(plan_json) = accepted.admitted_plan.as_deref() else {
        return Ok(ClaimedChildBounds::default());
    };
    let binding = mvm_vmm::host::spec_map::plan_binding_for(plan_json)
        .context("the claimed child's admitted plan is not JSON")?;
    let vm_state_dir = mvm_core::config::vm_state_dir(&accepted.child_vm_name);
    let inputs = SupervisorTimerInputs {
        plan_json: Some(&binding.plan_json),
        audit_dir: Some(&binding.audit_dir),
        signing_key_path: Some(&binding.signing_key_path),
        vm_state_dir: &vm_state_dir,
        pid_file,
    };
    let killer = || -> Box<dyn crate::supervisor::lifecycle::wall_clock::WorkloadKiller> {
        if retain_evidence {
            Box::new(inputs.preserving_exit_killer())
        } else {
            Box::new(inputs.exit_killer())
        }
    };
    let wall_clock = crate::supervisor::lifecycle::wall_clock::arm_for_supervisor(inputs, killer())
        .context("arming the claimed child's wall-clock bound")?;
    crate::supervisor::lifecycle::session_expiry::arm_for_supervisor(&inputs, killer());
    let unit_timer = crate::supervisor::lifecycle::liveness_expiry::arm_for_supervisor(&inputs)
        .context("arming the claimed child's unit timer")?;
    Ok(ClaimedChildBounds {
        wall_clock,
        unit_timer,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use mvm_core::util::test_env::TestEnv;

    struct Home {
        _env: TestEnv,
        _dir: tempfile::TempDir,
    }

    fn isolated_home() -> Home {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut env = TestEnv::new();
        env.isolate_mvm_home(dir.path());
        Home {
            _env: env,
            _dir: dir,
        }
    }

    fn signed_plan_with_bound(exec_secs: u32) -> String {
        let mut plan = mvm_core::plan::test_support::PlanFixture::new().build();
        plan.resources.timeouts.exec_secs = exec_secs;
        let signed = mvm_core::plan::sign_plan(&plan, &SigningKey::from_bytes(&[5u8; 32]), "host");
        serde_json::to_string(&signed).expect("encode the signed plan")
    }

    fn handoff(plan: Option<String>) -> AcceptedHandoff {
        AcceptedHandoff {
            child_vm_name: "claimed-child".into(),
            admitted_plan: plan,
        }
    }

    #[test]
    fn a_claimed_child_with_a_bound_gets_the_timer_a_cold_boot_would() {
        let _home = isolated_home();
        std::fs::create_dir_all(mvm_core::config::mvm_audit_dir()).unwrap();
        std::fs::create_dir_all(mvm_core::config::mvm_keys_dir()).unwrap();
        let pid_file = mvm_core::config::vm_state_dir("standby-parent").join("hvf.pid");
        // Far beyond the test's life; the guard is dropped at the end of it,
        // which stands the timer down.
        let guard = arm_for_claimed_child(&handoff(Some(signed_plan_with_bound(3600))), &pid_file)
            .expect("a bounded plan with an audit chain arms");
        assert!(
            guard.wall_clock_armed(),
            "the child's wall-clock bound is enforced"
        );
        assert!(!guard.unit_timer_armed(), "the plan names no topology unit");
    }

    #[test]
    fn a_claim_without_a_plan_or_a_bound_arms_no_timer() {
        let _home = isolated_home();
        let pid_file = mvm_core::config::vm_state_dir("standby-parent").join("hvf.pid");
        for plan in [None, Some(signed_plan_with_bound(0))] {
            let bounds = arm_for_claimed_child(&handoff(plan), &pid_file).unwrap();
            assert!(!bounds.wall_clock_armed() && !bounds.unit_timer_armed());
        }
    }

    const TENANT: &str = "acme";
    const CHILD: &str = "claimed-child";

    /// Admit a topology whose one unit is the claimed child, declaring
    /// `period_ms`, and return the child's plan bound to it and signed.
    fn signed_plan_for_unit(period_ms: Option<u32>) -> String {
        use mvm_contract::plan::topology::{
            CorePlacement, CryptoSuite, SealedTransitions, TOPOLOGY_SCHEMA_VERSION, Topology,
            TopologyBinding, Unit, UnitResources, UnitRole,
        };
        use mvm_core::plan::{TenantId, WorkloadId};

        let mut plan = mvm_core::plan::test_support::PlanFixture::new()
            .tenant(TENANT)
            .workload(CHILD)
            .build();
        let now = chrono::Utc::now();
        let topology = Topology {
            schema_version: TOPOLOGY_SCHEMA_VERSION,
            tenant: TenantId(TENANT.into()),
            generation: 1,
            valid_from: now - chrono::Duration::hours(1),
            valid_until: now + chrono::Duration::days(1),
            suite: CryptoSuite::CLASSICAL,
            units: vec![Unit {
                workload: WorkloadId(CHILD.into()),
                role: UnitRole::Worker,
                recipe: mvm_contract::assurance::Sha256Digest::from_bytes(&[7; 32]),
                resources: UnitResources {
                    cpus: 1,
                    mem_mib: 64,
                    disk_mib: 64,
                },
                placement: CorePlacement::Floating,
                min_isolation: None,
                permits: SealedTransitions::default(),
                liveness_period_ms: period_ms.and_then(std::num::NonZeroU32::new),
                require_isolated_cores: false,
            }],
            standby_pairs: Vec::new(),
            cells: Vec::new(),
            edges: Vec::new(),
            succession: Vec::new(),
        };
        let keys = mvm_core::config::mvm_keys_dir();
        let signer = crate::audit::host_keypair::load_or_init_at(&keys).expect("host signer");
        let emitter = crate::audit::emitter::AuditEmitter::with_dir(
            signer.signing.clone(),
            &mvm_core::config::mvm_audit_dir(),
        )
        .expect("emitter");
        crate::topology_admission::admit_topology(
            &crate::topology_admission::TopologyAdmissionRequest {
                tenant: &topology.tenant,
                signed: &crate::topology_admission::sign_topology_as_host(&topology, Some(&keys))
                    .expect("signs"),
                backend: mvm_core::vm_backend::BackendKind::Hvf,
                measured_failover: None,
                host_cpus: &crate::topology_admission::HostCpus {
                    scope_cpuset: false,
                    online: None,
                    isolated: None,
                    live: Vec::new(),
                },
                clock: &mvm_core::time::SystemClock,
                host_signer_keys_dir: Some(&keys),
                emitter: &emitter,
            },
        )
        .expect("the topology is admitted on HVF");
        plan.topology = Some(TopologyBinding {
            topology: topology.digest(),
            unit: WorkloadId(CHILD.into()),
        });
        plan.plan_id = mvm_core::plan::compute_plan_id(&plan);
        serde_json::to_string(&mvm_core::plan::sign_plan(&plan, &signer.signing, "host"))
            .expect("encode the signed plan")
    }

    #[test]
    fn a_claimed_child_whose_unit_declares_a_liveness_period_gets_its_deadline_owner() {
        let _home = isolated_home();
        let pid_file = mvm_core::config::vm_state_dir("standby-parent").join("hvf.pid");
        let bounds =
            arm_for_claimed_child(&handoff(Some(signed_plan_for_unit(Some(5_000)))), &pid_file)
                .expect("a watched unit with an audit chain arms");
        assert!(
            bounds.unit_timer_armed(),
            "the child's deadline has an owner"
        );
        // The timer's first pass resolves the mvm home; let it, before the
        // isolated home is handed back.
        let passed = mvm_core::config::liveness_dir_at(Path::new(&mvm_core::config::mvm_home()));
        let started = std::time::Instant::now();
        while !passed.exists() {
            assert!(
                started.elapsed() < std::time::Duration::from_secs(30),
                "the armed timer never made a pass"
            );
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }

    #[test]
    fn a_claimed_child_whose_unit_declares_no_period_starts_no_unit_timer() {
        let _home = isolated_home();
        let pid_file = mvm_core::config::vm_state_dir("standby-parent").join("hvf.pid");
        let bounds =
            arm_for_claimed_child(&handoff(Some(signed_plan_for_unit(None))), &pid_file).unwrap();
        assert!(!bounds.unit_timer_armed());
    }

    #[test]
    fn a_watched_claimed_child_with_no_audit_chain_fails_the_claim() {
        let _home = isolated_home();
        let pid_file = mvm_core::config::vm_state_dir("standby-parent").join("hvf.pid");
        let plan = signed_plan_for_unit(Some(5_000));
        // The handoff derives the key location from the home; without the key
        // the expiry could not be recorded.
        std::fs::remove_dir_all(mvm_core::config::mvm_keys_dir()).unwrap();
        let error = arm_for_claimed_child(&handoff(Some(plan)), &pid_file)
            .err()
            .expect("a deadline nobody could record is refused");
        assert!(format!("{error:#}").contains("unit timer"), "{error:#}");
    }

    #[test]
    fn an_unreadable_plan_refuses_rather_than_running_unbounded() {
        let _home = isolated_home();
        let pid_file = mvm_core::config::vm_state_dir("standby-parent").join("hvf.pid");
        assert!(arm_for_claimed_child(&handoff(Some("not json".into())), &pid_file).is_err());
        assert!(
            arm_for_claimed_child(&handoff(Some("{\"not\":\"a plan\"}".into())), &pid_file)
                .is_err()
        );
    }
}
