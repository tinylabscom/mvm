use anyhow::Result;

use crate::shell;

const JAILER_PATH: &str = "/usr/local/bin/jailer";

/// Check if the Firecracker jailer binary is available inside the VM.
pub fn jailer_available() -> Result<bool> {
    let out = shell::run_in_vm_stdout(&format!("test -x {} && echo yes || echo no", JAILER_PATH))?;
    Ok(out.trim() == "yes")
}
