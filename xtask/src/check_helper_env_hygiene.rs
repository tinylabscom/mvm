//! `xtask check-helper-env-hygiene`
//!
//! The host helper processes `mvmctl` starts are built by
//! `mvm_core::env_hygiene::helper_command`, which strips the loader, shell,
//! interpreter and password-manager-session variables the helper would
//! otherwise inherit. A helper started with a bare `Command::new` inherits
//! `LD_PRELOAD`, `BASH_ENV` or a vault session token from whoever ran
//! `mvmctl`, and nothing else would notice.
//!
//! The gate pins the spawn sites by name: each entry of [`HELPER_SPAWNS`]
//! is a file and the header of the function or `impl` block that starts the
//! helper. Inside that body the production code must call `helper_command(`
//! and must not call `Command::new(`. Comments, string literals and
//! `#[cfg(test)]` items are blanked first, so neither a comment naming the
//! constructor nor a test fixture spawning `sleep` can satisfy or trip it.
//!
//! What it does not do is discover a *new* helper spawn written somewhere
//! else. Telling "starts a helper" from "runs `codesign`" needs to know what
//! the program is, which a text gate cannot; a whole-tree ban on
//! `Command::new` would fire on hundreds of tool invocations and be switched
//! off rather than obeyed. A new helper spawn joins this list in the change
//! that adds it.

use anyhow::{Result, bail};
use std::path::Path;

use crate::rust_source::{blank_comments_and_strings, strip_cfg_test_items};

/// The constructor every helper spawn goes through.
const SANITIZER: &str = "helper_command(";

/// The unsanitized constructor a helper spawn must not use.
const RAW: &str = "Command::new(";

/// `(file, header)`: the body opened by the first `{` after `header` starts a
/// host helper process.
const HELPER_SPAWNS: &[(&str, &str)] = &[
    (
        "crates/mvm-vmm/src/host/network_endpoint_spawn.rs",
        "fn spawn_network_endpoint(",
    ),
    (
        "crates/mvm-vmm/src/host/gpu_endpoint_spawn.rs",
        "fn endpoint_command(",
    ),
    (
        "crates/mvm-vmm/src/host/broker_services_spawn.rs",
        "fn spawn_detached_with_config(",
    ),
    ("crates/mvm-vmm/src/host/shell/exec.rs", "fn run_host("),
    (
        "crates/mvm-vmm/src/host/shell/exec.rs",
        "fn run_host_visible(",
    ),
    ("crates/mvm-vmm/src/host/shell/exec.rs", "fn run_on_vm("),
    (
        "crates/mvm-vmm/src/host/shell/exec.rs",
        "fn run_on_vm_visible(",
    ),
    (
        "crates/mvm-vmm/src/host/shell/exec.rs",
        "fn run_on_vm_capture(",
    ),
    (
        "crates/mvm-vmm/src/host/linux_env.rs",
        "impl LinuxEnv for NativeEnv",
    ),
    (
        "crates/mvm-backends/src/driver/libkrun.rs",
        "fn bounded_supervisor_command(",
    ),
    (
        "crates/mvm-backends/src/driver/hvf.rs",
        "fn bounded_supervisor_command(",
    ),
    (
        "crates/mvm-backends/src/driver/hvf_restore.rs",
        "fn bounded_restore_command(",
    ),
    (
        "crates/mvm-backends/src/driver/qemu.rs",
        "fn bounded_qemu_command(",
    ),
    (
        "crates/mvm-backends/src/driver/qemu_process.rs",
        "fn spawn_vsock_bridges(",
    ),
    ("crates/mvm-backends/src/driver/fc.rs", "fn fc_sudo_signal("),
    (
        "crates/mvm-hostd/src/supervisor/services/spawn.rs",
        "impl SubprocessSpawner for ProcessSpawner",
    ),
    (
        "crates/mvm-hostd/src/bin/mvm-host-agent.rs",
        "fn spawn_worker(",
    ),
    (
        "crates/mvm-hostd/src/bin/mvm-host-agent.rs",
        "fn spawn_signer_helper(",
    ),
    (
        "crates/mvm-build/src/builder_egress_process.rs",
        "fn builder_egress_supervisor_command(",
    ),
    (
        "crates/mvm-build/src/libkrun_builder.rs",
        "fn spawn_supervisor_in_background(",
    ),
    (
        "crates/mvm-build/src/qemu_builder.rs",
        "fn run_stage0_qemu(",
    ),
    (
        "crates/mvm-build/src/qemu_builder.rs",
        "fn run_shell_script_qemu(",
    ),
    ("crates/mvm-build/src/qemu_builder.rs", "fn run_build_qemu("),
    (
        "crates/mvm-build/src/builder_vm_bootstrap.rs",
        "fn builder_vm_helper_command(",
    ),
];

pub fn run(workspace: &Path) -> Result<()> {
    let mut failures = Vec::new();
    for (file, header) in HELPER_SPAWNS {
        let path = workspace.join(file);
        let raw = std::fs::read_to_string(&path).map_err(|e| {
            anyhow::anyhow!("helper spawn site {file} is listed but unreadable: {e}")
        })?;
        if let Err(problem) = check_site(&raw, header) {
            failures.push(format!("{file} `{header}`: {problem}"));
        }
    }
    if !failures.is_empty() {
        bail!(
            "check-helper-env-hygiene: {} helper spawn site(s) bypass the environment filter:\n  {}\n\
             Build the helper's command with `mvm_core::env_hygiene::helper_command(program)` so it \
             does not inherit loader, shell, interpreter or password-manager session variables. \
             If the spawn moved, update HELPER_SPAWNS in xtask/src/check_helper_env_hygiene.rs.",
            failures.len(),
            failures.join("\n  ")
        );
    }
    eprintln!(
        "check-helper-env-hygiene: {} host helper spawn sites build their command through the environment filter",
        HELPER_SPAWNS.len()
    );
    Ok(())
}

/// Check one site: the production body after `header` calls the sanitizer and
/// never the raw constructor.
fn check_site(raw: &str, header: &str) -> std::result::Result<(), String> {
    let production = strip_cfg_test_items(&blank_comments_and_strings(raw));
    let body = body_after(&production, header)?;
    if body.contains(RAW) {
        return Err(format!("calls `{RAW}` instead of `{SANITIZER}`"));
    }
    if !body.contains(SANITIZER) {
        return Err(format!("never calls `{SANITIZER}`"));
    }
    Ok(())
}

/// The brace-delimited body opened by the first `{` after the one production
/// occurrence of `header`.
fn body_after<'a>(production: &'a str, header: &str) -> std::result::Result<&'a str, String> {
    let mut matches = production.match_indices(header);
    let Some((start, _)) = matches.next() else {
        return Err("header not found in production code".to_string());
    };
    if matches.next().is_some() {
        return Err("header is ambiguous; it occurs more than once".to_string());
    }
    let open = production[start..]
        .find('{')
        .map(|offset| start + offset)
        .ok_or_else(|| "no body follows the header".to_string())?;
    let mut depth = 0usize;
    for (offset, c) in production[open..].char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Ok(&production[open..=open + offset]);
                }
            }
            _ => {}
        }
    }
    Err("the body never closes".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEADER: &str = "fn spawn_helper(";

    #[test]
    fn a_site_built_through_the_filter_passes() {
        let src = "fn spawn_helper(bin: &Path) -> Command {\n    let mut c = mvm_core::env_hygiene::helper_command(bin);\n    c.arg(\"--x\");\n    c\n}\n";
        assert_eq!(check_site(src, HEADER), Ok(()));
    }

    #[test]
    fn a_raw_command_is_refused_even_beside_the_filter() {
        let src = "fn spawn_helper(bin: &Path) {\n    let _ = helper_command(bin);\n    let c = Command::new(bin);\n}\n";
        assert!(
            check_site(src, HEADER)
                .unwrap_err()
                .contains("Command::new(")
        );
    }

    #[test]
    fn a_site_that_never_filters_is_refused() {
        let src =
            "fn spawn_helper(bin: &Path) {\n    let c = std::process::Command::new(bin);\n}\n";
        assert!(check_site(src, HEADER).is_err());
        let src = "fn spawn_helper(bin: &Path) {\n    spawn_something_else(bin);\n}\n";
        assert!(check_site(src, HEADER).unwrap_err().contains("never calls"));
    }

    #[test]
    fn a_comment_or_string_cannot_satisfy_the_gate() {
        let src = "fn spawn_helper(bin: &Path) {\n    // helper_command(bin)\n    let s = \"helper_command(\";\n    spawn(bin);\n}\n";
        assert!(check_site(src, HEADER).is_err());
    }

    #[test]
    fn a_raw_command_in_a_comment_or_test_does_not_trip_it() {
        let src = "fn spawn_helper(bin: &Path) {\n    // was Command::new(bin)\n    let c = helper_command(bin);\n}\n\n#[cfg(test)]\nmod tests {\n    fn spawn_helper(x: u8) { let c = Command::new(\"sleep\"); }\n}\n";
        assert_eq!(check_site(src, HEADER), Ok(()));
    }

    #[test]
    fn a_missing_or_ambiguous_header_fails_closed() {
        let src = "fn other() { helper_command(x); }\n";
        assert!(check_site(src, HEADER).unwrap_err().contains("not found"));
        let src = "fn spawn_helper(a: u8) { helper_command(a); }\nfn spawn_helper(b: u8) { helper_command(b); }\n";
        assert!(check_site(src, HEADER).unwrap_err().contains("ambiguous"));
    }

    #[test]
    fn only_the_named_body_is_checked() {
        let src = "fn spawn_helper(bin: &Path) {\n    if x { helper_command(bin); }\n}\nfn run_codesign() { Command::new(\"codesign\"); }\n";
        assert_eq!(check_site(src, HEADER), Ok(()));
    }

    #[test]
    fn every_listed_site_passes_in_this_tree() {
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("xtask sits in the workspace root");
        run(workspace).expect("every helper spawn site uses the environment filter");
    }
}
