//! Live witness for what a workload holds after the agent spawns it.
//!
//! Opt-in like the other privileged witnesses: it needs
//! `MVM_GUEST_PRIVILEGED_TESTS=1` and root. The identity change happens in a
//! spawned child between fork and exec, exactly where the entrypoint spawn does
//! it, so the test process itself is left untouched.

use super::{
    RESTORE_AGENT_CAPABILITIES, WORKLOAD_GID, WORKLOAD_UID, assume_identity_retaining,
    drop_workload_capability_bounding_set, privilege_tests::privileged,
};
use std::os::unix::process::CommandExt as _;

/// The agent's own state: `CAP_KILL | CAP_SYS_TIME`.
const AGENT_CAPABILITIES: &str = "0000000002000020";
const NONE: &str = "0000000000000000";

/// `/proc/self/status` of a child that became the agent identity and then, if
/// `as_workload`, went through the workload spawn step before exec.
fn status_of_spawned_child(as_workload: bool) -> String {
    let mut command = mvm_core::env_hygiene::helper_command("/bin/cat");
    command.arg("/proc/self/status");
    // SAFETY: the closure runs between fork and exec and calls only
    // allocation-free libc wrappers.
    unsafe {
        command.pre_exec(move || {
            assume_identity_retaining(WORKLOAD_UID, WORKLOAD_GID, RESTORE_AGENT_CAPABILITIES)?;
            if as_workload {
                drop_workload_capability_bounding_set()?;
            }
            Ok(())
        });
    }
    let output = command
        .output()
        .expect("spawn a child under the agent identity");
    assert!(output.status.success(), "{output:?}");
    String::from_utf8(output.stdout).expect("status is UTF-8")
}

fn field(status: &str, name: &str) -> String {
    status
        .lines()
        .find_map(|line| line.strip_prefix(name)?.strip_prefix(':'))
        .map(str::trim)
        .unwrap_or_else(|| panic!("no {name} line in:\n{status}"))
        .to_string()
}

#[test]
fn a_workload_spawned_by_the_agent_holds_no_capabilities() {
    if !privileged() {
        return;
    }
    // The control: without the workload step the child keeps what the agent
    // holds. This is what makes the assertions below mean something; if the
    // setup ever stops producing ambient capabilities, this fails first
    // instead of the real check passing for the wrong reason.
    let agent = status_of_spawned_child(false);
    for set in ["CapPrm", "CapEff", "CapAmb"] {
        assert_eq!(field(&agent, set), AGENT_CAPABILITIES, "control {set}");
    }

    let workload = status_of_spawned_child(true);
    assert_eq!(field(&workload, "Uid"), "901\t901\t901\t901");
    for set in ["CapPrm", "CapEff", "CapInh", "CapAmb"] {
        assert_eq!(field(&workload, set), NONE, "{set} after the workload step");
    }
    assert_eq!(field(&workload, "NoNewPrivs"), "1");
}
