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
//! than letting it run unbounded. The parent has not been told the claim
//! committed at that point — the host is still waiting on the child's identity
//! handshake — so a refused arm fails the claim instead of half-admitting it.

use std::path::{Path, PathBuf};
use std::sync::mpsc::Receiver;

use anyhow::{Context, Result};
use mvm_vmm::hvf_handoff::AcceptedHandoff;

use super::wall_clock::{SupervisorTimerInputs, WallClockGuard};

/// Exit code for a claimed child whose bound could not be armed; the same one
/// a cold boot refuses with.
const REFUSED_BOUND_EXIT_CODE: i32 = 7;

/// Arm the wall-clock timer and the session expiry watcher for the child
/// `accepted` names, from the plan it was admitted under.
///
/// `Ok(None)` when there is no wall-clock bound to hold: the claim carried no
/// plan, or its plan declares none. The session watcher is armed either way
/// when there is a plan, because it decides for itself whether the child is a
/// session.
///
/// # Errors
/// The plan is not JSON, cannot be decoded, or declares a bound whose kill
/// could not be audited.
pub fn arm_for_claimed_child(
    accepted: &AcceptedHandoff,
    pid_file: &Path,
) -> Result<Option<WallClockGuard>> {
    let Some(plan_json) = accepted.admitted_plan.as_deref() else {
        return Ok(None);
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
    let guard = super::wall_clock::arm_for_supervisor(inputs)
        .context("arming the claimed child's wall-clock bound")?;
    super::session_expiry::arm_for_supervisor(&inputs);
    Ok(guard)
}

/// Wait on `accepted` for the handoff this standby parent takes, then arm the
/// claimed child's bounds and hold them for the rest of the process.
///
/// The thread ends without arming anything if the parent is never claimed:
/// the sender goes with the VM.
pub fn arm_on_handoff(accepted: Receiver<AcceptedHandoff>, pid_file: PathBuf) {
    let spawned = std::thread::Builder::new()
        .name("mvm-claimed-child".to_string())
        .spawn(move || {
            let Ok(handoff) = accepted.recv() else {
                return;
            };
            match arm_for_claimed_child(&handoff, &pid_file) {
                Ok(guard) => {
                    // Dropping the guard stands the timer down, so it lives on
                    // this thread for as long as the process does.
                    let _guard = guard;
                    loop {
                        std::thread::park();
                    }
                }
                Err(e) => {
                    eprintln!(
                        "supervisor: refusing claimed child {}: {e:#}",
                        handoff.child_vm_name
                    );
                    std::process::exit(REFUSED_BOUND_EXIT_CODE);
                }
            }
        });
    if let Err(e) = spawned {
        eprintln!("supervisor: cannot watch for a claim, so cannot bound one: {e}");
        std::process::exit(REFUSED_BOUND_EXIT_CODE);
    }
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
        assert!(guard.is_some(), "the child's wall-clock bound is enforced");
    }

    #[test]
    fn a_claim_without_a_plan_or_a_bound_arms_no_timer() {
        let _home = isolated_home();
        let pid_file = mvm_core::config::vm_state_dir("standby-parent").join("hvf.pid");
        assert!(
            arm_for_claimed_child(&handoff(None), &pid_file)
                .unwrap()
                .is_none()
        );
        assert!(
            arm_for_claimed_child(&handoff(Some(signed_plan_with_bound(0))), &pid_file)
                .unwrap()
                .is_none()
        );
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
