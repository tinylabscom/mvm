//! The no-root-workload gate: the agent refuses to spawn workload code while
//! it is still uid 0.
//!
//! The agent has five distinct workload-spawn sites — the entrypoint runner,
//! the exec stream, the console, the lifecycle hooks, and the worker pool —
//! and none of them sets a uid. Every one inherits whatever identity the agent
//! is serving under. Guarding each site individually would therefore guard the
//! symptom five times over and still miss the sixth site someone adds later.
//!
//! The property that actually matters is a single one: **the agent is not root
//! at the moment it serves a request that runs workload code**. That is one
//! check over `Verb::spawns_workload_process`, placed on the one path every
//! request already traverses.
//!
//! This gate is a backstop, not the mechanism. The mechanism is the privilege
//! drop during activation; the gate exists so a boot path that never reaches
//! that drop fails closed and names the verb it refused, instead of silently
//! running the workload as root.

use super::*;

/// The live real uid, or `None` where the host has no such notion. A non-Linux
/// build has nothing for this gate to assert and says so, rather than
/// fabricating a uid that would make the check vacuously pass.
#[must_use]
pub fn current_uid() -> Option<u32> {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: getuid() has no precondition and cannot fail.
        Some(unsafe { libc::getuid() })
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

/// The refusal a request earns given the live uid, or `None` to proceed.
/// Pure over its inputs so the policy is testable without a guest.
#[must_use]
pub fn workload_privilege_refusal(req: &GuestRequest, uid: Option<u32>) -> Option<GuestResponse> {
    let uid = uid?;
    if uid != 0 || !req.verb().spawns_workload_process() {
        return None;
    }
    Some(GuestResponse::WorkloadPrivilegeRefused {
        verb: req.kind_name().to_string(),
        uid,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exec() -> GuestRequest {
        GuestRequest::Exec {
            command: String::new(),
            stdin: None,
            timeout_secs: None,
        }
    }

    /// The gate fires for a workload-spawning verb served as root, and names
    /// both the verb and the uid so the refusal diagnoses itself.
    #[test]
    fn root_exec_is_refused_and_self_describing() {
        let resp = workload_privilege_refusal(&exec(), Some(0));
        let Some(GuestResponse::WorkloadPrivilegeRefused { verb, uid }) = resp else {
            panic!("root exec was not refused: {resp:?}");
        };
        assert_eq!(verb, "exec");
        assert_eq!(uid, 0);
    }

    /// A dropped agent serves the same verb normally — the gate is inert once
    /// the privilege drop has happened, which is the overwhelmingly common case.
    #[test]
    fn workload_uid_passes() {
        assert!(
            workload_privilege_refusal(&exec(), Some(crate::guest_mount::WORKLOAD_UID)).is_none()
        );
    }

    /// A verb that spawns nothing is unaffected even at root, so a root agent
    /// can still answer liveness and status probes — which is what makes the
    /// refusal observable from the host instead of looking like a hang.
    #[test]
    fn non_spawning_verb_passes_at_root() {
        assert!(workload_privilege_refusal(&GuestRequest::Ping, Some(0)).is_none());
    }

    /// Absent a uid (non-Linux build) the gate asserts nothing rather than
    /// guessing. Stated as a test so the vacuous branch is deliberate.
    #[test]
    fn no_uid_means_no_opinion() {
        assert!(workload_privilege_refusal(&exec(), None).is_none());
    }

    /// `ActivateEnvironment` runs the mounts and the pivot, so it legitimately
    /// executes while still root. If the gate ever caught it, no guest could
    /// reach the privilege drop at all and every backend would hard-fail —
    /// this is the one classification that must not drift.
    #[test]
    fn activation_is_never_refused_at_root() {
        assert!(!Verb::ActivateEnvironment.spawns_workload_process());
    }

    /// Every verb classified as workload-spawning is refused at root, and every
    /// verb not so classified is not. Iterating `Verb::ALL` means a verb added
    /// later is covered without anyone remembering to extend this test.
    #[test]
    fn classification_is_total_over_every_verb() {
        let spawning: Vec<_> = Verb::ALL
            .iter()
            .filter(|v| v.spawns_workload_process())
            .map(|v| v.name())
            .collect();
        assert_eq!(
            spawning,
            vec![
                "Exec",
                "ExecBatch",
                "RunEntrypoint",
                "RunExtension",
                "RunDetached",
                "ConsoleOpen",
                "ProcStart",
                "RunCode",
            ],
            "the set of workload-spawning verbs changed: confirm the new set is \
             correct, then update this list"
        );
    }
}
