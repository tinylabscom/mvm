use anyhow::Result;
use std::process::Output;

/// Abstraction for running Linux commands.
///
/// On macOS: routes Linux-only commands into the shared builder VM.
/// On native Linux: runs them directly on the host.
///
/// This trait decouples the "where scripts run" question from the rest
/// of the codebase. Build, VM-lifecycle, and Linux-only networking code
/// can accept a `&dyn LinuxEnv` instead of hardcoding one concrete
/// execution boundary.
pub trait LinuxEnv: Send + Sync {
    /// Run a bash script, capturing output.
    fn run(&self, script: &str) -> Result<Output>;

    /// Run a bash script with output visible to the user (inherited stdio).
    fn run_visible(&self, script: &str) -> Result<()>;

    /// Run a bash script and return stdout as a trimmed String.
    fn run_stdout(&self, script: &str) -> Result<String>;

    /// Run a bash script, capturing both stdout and stderr (piped, not inherited).
    fn run_capture(&self, script: &str) -> Result<Output>;
}
