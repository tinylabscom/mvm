//! `mvm-tool-shim` — the workload-facing shadow installed at each declared
//! tool's executable path at activation.
//!
//! The workload runs this exactly as it would have run the tool; the shim
//! reports the exact invocation to the `mvm-tool-spawn` helper over an
//! abstract socket and, only after the helper confirms a host allow,
//! becomes a thin supervisor: it forwards signals to the real tool (which
//! the helper started from its protected store) and exits with the tool's
//! status. On any refusal or mediation failure it exits
//! `MEDIATION_REFUSED_EXIT` without the tool ever running. The shim holds
//! no key and no capability: the enforcement is the store the helper
//! alone can read, not this binary.

#[cfg(target_os = "linux")]
fn main() {
    std::process::exit(mvm_agentd::tool_spawn::run_shim());
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("mvm-tool-shim runs only inside a Linux guest");
    std::process::exit(126);
}
