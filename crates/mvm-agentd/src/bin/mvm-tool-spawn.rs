//! `mvm-tool-spawn` — the privileged declared-tool spawn helper.
//!
//! Started by the guest init as [`TOOL_SPAWN_IDENTITY`] before the
//! privilege drop, only when the signed verb grant maps declared
//! executables. It binds the mediation socket, and for each shim request:
//! proves the peer's `/proc/<pid>/exe` is a signed declared path; asks the
//! host through the plan-authorized broker service `host.tool.v1`; and on
//! an allow executes the store copy of the original binary as the workload
//! uid in the tool group, leading a new session with the requester's stdio
//! and working directory, registering a bound invocation with the agent's
//! attribution table. Everything else fails closed.

#[cfg(target_os = "linux")]
fn main() {
    std::process::exit(mvm_agentd::tool_spawn::run_helper());
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("mvm-tool-spawn runs only inside a Linux guest");
    std::process::exit(1);
}
