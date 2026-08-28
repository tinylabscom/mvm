//! Host/dev-VM command presence probes and the pinned cross-compile
//! toolchain (zig + cargo-zigbuild) version probe.

use super::Check;
use mvm_runtime::config::VM_NAME;
use mvm_runtime::shell;

pub(super) fn check_cmd(name: &'static str, category: &'static str, args: &[&str]) -> Check {
    match shell::run_host(name, args) {
        Ok(out) if out.status.success() => Check {
            name,
            category,
            ok: true,
            info: String::from_utf8_lossy(&out.stdout).trim().to_string(),
        },
        Ok(out) => Check {
            name,
            category,
            ok: false,
            info: String::from_utf8_lossy(&out.stderr).trim().to_string(),
        },
        Err(e) => Check {
            name,
            category,
            ok: false,
            info: format!("{e:#}"),
        },
    }
}

pub(super) fn check_vm_cmd(name: &'static str, category: &'static str, cmd: &'static str) -> Check {
    match shell::run_on_vm(VM_NAME, cmd) {
        Ok(out) if out.status.success() => Check {
            name,
            category,
            ok: true,
            info: String::from_utf8_lossy(&out.stdout).trim().to_string(),
        },
        Ok(out) => Check {
            name,
            category,
            ok: false,
            info: String::from_utf8_lossy(&out.stderr).trim().to_string(),
        },
        Err(e) => Check {
            name,
            category,
            ok: false,
            info: format!("{e:#}"),
        },
    }
}

/// Pinned cross-compile toolchain versions, parsed at build time from
/// the workspace's [workspace.metadata.mvm.toolchain] block.
pub struct ZigbuildProbe {
    pub pinned_zig: String,
    pub pinned_cargo_zigbuild: String,
    pub pinned_target: String,
    pub installed_zig: Option<String>,
    pub installed_cargo_zigbuild: Option<String>,
}

/// Read the pinned versions baked in at compile time and probe the
/// installed versions on the host. Used by `mvmctl doctor` to warn
/// when contributor toolchain drifts from the pin.
pub fn probe_zigbuild() -> ZigbuildProbe {
    ZigbuildProbe {
        pinned_zig: env!("MVM_PINNED_ZIG").to_string(),
        pinned_cargo_zigbuild: env!("MVM_PINNED_CARGO_ZIGBUILD").to_string(),
        pinned_target: env!("MVM_PINNED_TARGET").to_string(),
        installed_zig: which_version("zig", &["version"]),
        installed_cargo_zigbuild: which_version("cargo-zigbuild", &["--version"]),
    }
}

/// Returns the trimmed stdout of `cmd <args...>` when the process
/// runs and exits 0; returns `None` for any failure mode (binary
/// not found, non-zero exit, non-UTF-8 output). Used by tool-presence
/// probes where "I couldn't ask the tool its version" is reported
/// as "not usefully installed" — the caller surfaces that to the
/// doctor output, not as a hard error.
fn which_version(cmd: &str, args: &[&str]) -> Option<String> {
    let out = std::process::Command::new(cmd).args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_cmd_rustup_on_host() {
        let c = check_cmd("rustup", "tools", &["--version"]);
        assert!(c.ok, "rustup should be available: {}", c.info);
        assert!(
            c.info.contains("rustup"),
            "expected version string, got: {}",
            c.info
        );
    }

    #[test]
    fn check_cmd_cargo_on_host() {
        let c = check_cmd("cargo", "tools", &["--version"]);
        assert!(c.ok, "cargo should be available: {}", c.info);
        assert!(
            c.info.contains("cargo"),
            "expected version string, got: {}",
            c.info
        );
    }

    #[test]
    fn check_cmd_missing_tool() {
        let c = check_cmd("nonexistent-mvm-tool-xyz", "tools", &["--version"]);
        assert!(!c.ok, "nonexistent tool should fail");
    }

    #[test]
    fn a_spawn_failure_reports_why_it_failed() {
        let c = check_cmd("nonexistent-mvm-tool-xyz", "tools", &["--version"]);
        assert!(
            c.info.contains("nonexistent-mvm-tool-xyz"),
            "expected the command to be named, got: {}",
            c.info
        );
        assert!(
            c.info.contains("os error"),
            "a spawn failure must carry the underlying OS error, not just the \
             context line — without it doctor reports a reason-free failure and \
             an intermittent one cannot be told from a missing tool. got: {}",
            c.info
        );
    }
}
