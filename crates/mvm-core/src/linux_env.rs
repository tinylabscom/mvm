use anyhow::Result;
use std::process::Output;

/// Abstraction for running Linux commands.
///
/// On macOS: delegates to a Lima VM via `limactl shell`.
/// On native Linux with KVM: runs bash directly on the host.
/// In the future: could route to OrbStack, UTM, or a remote host.
///
/// This trait decouples the "where scripts run" question from the rest
/// of the codebase. All VM lifecycle, build, and networking code can
/// accept a `&dyn LinuxEnv` instead of hardcoding Lima.
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
