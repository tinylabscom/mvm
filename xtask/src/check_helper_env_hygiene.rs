//! `xtask check-helper-env-hygiene`
//!
//! The host helper processes `mvmctl` starts are built by
//! `mvm_core::env_hygiene::helper_command`, which strips the loader, shell,
//! interpreter and password-manager-session variables the helper would
//! otherwise inherit. A helper started with a bare `Command::new` inherits
//! `LD_PRELOAD`, `BASH_ENV` or a vault session token from whoever ran
//! `mvmctl`, and nothing else would notice.
//!
//! The gate pins the helper spawn sites by name: each entry of [`HELPER_SPAWNS`]
//! is a file and the header of the function or `impl` block that starts the
//! helper. Inside that body the production code must call `helper_command(`
//! and must not call `Command::new(`. Comments, string literals and
//! `#[cfg(test)]` items are blanked first, so neither a comment naming the
//! constructor nor a test fixture spawning `sleep` can satisfy or trip it.
//!
//! A whole-crate inventory also finds new raw `Command::new` constructors.
//! Existing guest and tool launches form a pinned per-file baseline; adding
//! another raw constructor fails until it is classified. A new host helper
//! belongs in the named list and uses the filter. The inventory permits
//! removing raw constructors without an inventory edit.

use anyhow::{Result, bail};
use regex::Regex;
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::OnceLock;

use crate::fs_walk::for_each_file;
use crate::rust_source::{blank_comments_and_strings, strip_cfg_test_items};

/// The constructor every helper spawn goes through.
const SANITIZER: &str = "helper_command(";

/// The unsanitized constructor a helper spawn must not use.
const RAW: &str = "Command::new(";

fn raw_constructor_count(code: &str) -> usize {
    static RAW_CONSTRUCTOR: OnceLock<Regex> = OnceLock::new();
    RAW_CONSTRUCTOR
        .get_or_init(|| {
            Regex::new(r"\bCommand\s*::\s*new\s*\(")
                .expect("valid static raw process constructor expression")
        })
        .find_iter(code)
        .count()
}

/// Existing raw constructors outside the named host-helper spawn seams.
/// Counts pin every production file so a new raw launch, even in a new file,
/// requires classification before the gate can pass.
const EXISTING_RAW_COMMAND_COUNTS: &[(&str, usize)] = &[
    ("crates/mvm-agentd/src/bin/mvm-builder-agent.rs", 1),
    ("crates/mvm-agentd/src/bin/mvm-guest-agent/handlers.rs", 1),
    ("crates/mvm-agentd/src/bin/mvm-guest-agent/health.rs", 1),
    (
        "crates/mvm-agentd/src/bin/mvm-guest-agent/interactive.rs",
        2,
    ),
    ("crates/mvm-agentd/src/bin/mvm-oci-entrypoint.rs", 1),
    ("crates/mvm-agentd/src/bin/mvm-runner.rs", 1),
    ("crates/mvm-agentd/src/bin/mvm-seccomp-apply.rs", 1),
    ("crates/mvm-agentd/src/builder_agent.rs", 1),
    ("crates/mvm-agentd/src/builder_build.rs", 2),
    ("crates/mvm-agentd/src/crng_reseed/helper.rs", 1),
    ("crates/mvm-agentd/src/entrypoint.rs", 1),
    ("crates/mvm-agentd/src/exec_stream.rs", 2),
    ("crates/mvm-agentd/src/guest_bootstrap.rs", 5),
    ("crates/mvm-agentd/src/guest_net.rs", 2),
    ("crates/mvm-agentd/src/lifecycle_hooks.rs", 2),
    ("crates/mvm-agentd/src/process_rpc.rs", 1),
    ("crates/mvm-agentd/src/worker_pool.rs", 1),
    ("crates/mvm-build/src/bin/mvm-host-vm-init.rs", 16),
    ("crates/mvm-build/src/bin/mvm-host-vm-init/boot_stage.rs", 1),
    (
        "crates/mvm-build/src/bin/mvm-host-vm-init/builder_hooks.rs",
        4,
    ),
    ("crates/mvm-build/src/bin/mvm-host-vm-init/install.rs", 1),
    ("crates/mvm-build/src/bin/mvm-host-vm-init/workload.rs", 1),
    ("crates/mvm-build/src/bin/stage0-init.rs", 6),
    ("crates/mvm-build/src/bin/stage0-init/kernel_emit.rs", 1),
    ("crates/mvm-build/src/bin/stage0-init/store_gc.rs", 2),
    ("crates/mvm-build/src/builder_vm_image.rs", 1),
    ("crates/mvm-build/src/builder_vm_runtime.rs", 1),
    ("crates/mvm-build/src/builder_vm_transport.rs", 1),
    ("crates/mvm-build/src/builderd.rs", 2),
    ("crates/mvm-build/src/embed_toolchain.rs", 8),
    ("crates/mvm-build/src/guest_agent_build.rs", 3),
    ("crates/mvm-build/src/image_source/build.rs", 2),
    ("crates/mvm-build/src/image_source/git.rs", 1),
    ("crates/mvm-build/src/libkrun_builder.rs", 2),
    ("crates/mvm-build/src/provenance_mark.rs", 1),
    ("crates/mvm-build/src/qemu_builder.rs", 3),
    ("crates/mvm-build/src/runtime_overlay.rs", 1),
    ("crates/mvm-build/src/stage0.rs", 1),
    ("crates/mvm-capture/src/collect/package.rs", 3),
    ("crates/mvm-capture/src/collect/trace.rs", 2),
    ("crates/mvm-capture/src/verify.rs", 1),
    ("crates/mvm-cli/src/bench/cold_launch_runner.rs", 1),
    ("crates/mvm-cli/src/bootstrap.rs", 1),
    ("crates/mvm-cli/src/commands/bootstrap.rs", 1),
    ("crates/mvm-cli/src/commands/build/kernel.rs", 1),
    ("crates/mvm-cli/src/commands/build/sandbox_record.rs", 1),
    ("crates/mvm-cli/src/commands/deps/audit.rs", 2),
    ("crates/mvm-cli/src/commands/env/artifact_verify.rs", 1),
    ("crates/mvm-cli/src/commands/env/builder_vm/test_pair.rs", 1),
    (
        "crates/mvm-cli/src/commands/env/builder_vm/vm_helpers.rs",
        1,
    ),
    ("crates/mvm-cli/src/commands/env/uninstall.rs", 1),
    ("crates/mvm-cli/src/commands/image/trust.rs", 1),
    ("crates/mvm-cli/src/commands/ops/config.rs", 1),
    ("crates/mvm-cli/src/commands/vm/run_plan.rs", 1),
    ("crates/mvm-cli/src/commands/vm/sdk_no_vm.rs", 1),
    ("crates/mvm-cli/src/doctor/security_checks.rs", 6),
    ("crates/mvm-cli/src/doctor/toolchain.rs", 1),
    ("crates/mvm-cli/src/exec.rs", 1),
    ("crates/mvm-cli/src/host_binaries/payload_build.rs", 2),
    ("crates/mvm-cli/src/update.rs", 1),
    ("crates/mvm-client/src/secret/source.rs", 1),
    ("crates/mvm-core/src/crypto/key_rotation.rs", 1),
    ("crates/mvm-core/src/env_hygiene.rs", 1),
    ("crates/mvm-core/src/platform/platform.rs", 2),
    ("crates/mvm-core/src/spawn_scope.rs", 3),
    ("crates/mvm-fs/src/oci_to_rootfs/ext4.rs", 1),
    ("crates/mvm-fs/src/oci_to_rootfs/verity.rs", 1),
    ("crates/mvm-hostd/src/bin/mvm-hvf-supervisor.rs", 3),
    ("crates/mvm-hostd/src/supervisor/firewall/linux_nft.rs", 1),
    ("crates/mvm-runtime/examples/hvf-relay-egress.rs", 1),
    ("crates/mvm-runtime/src/microvm/run_info.rs", 1),
    ("crates/mvm-runtime/src/storage/backend.rs", 1),
    (
        "crates/mvm-runtime/src/storage/volume/encrypted_linux.rs",
        7,
    ),
    ("crates/mvm-setpriv/src/lib.rs", 1),
    ("crates/mvm-vmm/src/host/aux_bin.rs", 1),
    ("crates/mvm-vmm/src/host/codesign.rs", 3),
    ("crates/mvm-vmm/src/host/shell/exec.rs", 1),
];

/// `(file, header)`: the body opened by the first `{` after `header` starts a
/// host helper process.
const HELPER_SPAWNS: &[(&str, &str)] = &[
    (
        "crates/mvm-runtime/src/host_shell.rs",
        "impl mvm_core::build_env::ShellEnvironment for HostShellEnvironment",
    ),
    ("crates/mvm-vmm/src/host/aux_bin.rs", "fn probe_contract("),
    (
        "crates/mvm-hostd/src/health_probe.rs",
        "fn restart_command_for(",
    ),
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
    let mut production = Vec::new();
    for_each_file(
        &workspace.join("crates"),
        Some("rs"),
        &mut |path, source| {
            let relative = path.strip_prefix(workspace).unwrap_or(path);
            let file = relative.to_string_lossy().replace('\\', "/");
            if file.contains("/tests/") || file.ends_with("/tests.rs") {
                return;
            }
            production.push((
                file,
                strip_cfg_test_items(&blank_comments_and_strings(source)),
            ));
        },
    )?;
    let sources: Vec<_> = production
        .iter()
        .map(|(file, code)| (file.as_str(), code.as_str()))
        .collect();
    failures.extend(unreviewed_raw_command_sites(&sources));
    if !failures.is_empty() {
        bail!(
            "check-helper-env-hygiene: {} spawn-site or raw-constructor inventory violation(s):\n  {}\n\
             Build host helpers with `mvm_core::env_hygiene::helper_command(program)`. \
             Classify a changed raw tool launch before updating the inventory.",
            failures.len(),
            failures.join("\n  ")
        );
    }
    eprintln!(
        "check-helper-env-hygiene: {} host helper spawn sites use the filter; new raw constructors require review",
        HELPER_SPAWNS.len(),
    );
    Ok(())
}

fn unreviewed_raw_command_sites(sources: &[(&str, &str)]) -> Vec<String> {
    let reviewed: BTreeMap<_, _> = EXISTING_RAW_COMMAND_COUNTS.iter().copied().collect();
    let mut actual = BTreeMap::new();
    for &(file, code) in sources {
        let count = raw_constructor_count(code);
        if count > 0 {
            actual.insert(file, count);
        }
    }
    actual
        .iter()
        .filter(|(file, count)| **count > reviewed.get(**file).copied().unwrap_or(0))
        .map(|(file, count)| {
            format!(
                "{file}: {count} raw process constructor(s), reviewed {:?}",
                reviewed.get(file)
            )
        })
        .collect()
}

/// Check one site: the production body after `header` calls the sanitizer and
/// never the raw constructor.
fn check_site(raw: &str, header: &str) -> std::result::Result<(), String> {
    let production = strip_cfg_test_items(&blank_comments_and_strings(raw));
    let body = body_after(&production, header)?;
    if raw_constructor_count(body) > 0 {
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
        let spaced = "fn spawn_helper(bin: &Path) {\n    let _ = helper_command(bin);\n    let c = Command :: new (bin);\n}\n";
        assert!(check_site(spaced, HEADER).is_err());
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
    fn a_new_raw_command_outside_the_pinned_sites_is_discovered() {
        let production = [(
            "crates/mvm-hostd/src/new_helper.rs",
            "fn start() { Command :: new (helper).spawn(); }",
        )];
        let failures = unreviewed_raw_command_sites(&production);
        assert_eq!(failures.len(), 1);
        assert!(failures[0].contains("new_helper.rs"));
    }

    #[test]
    fn every_listed_site_passes_in_this_tree() {
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("xtask sits in the workspace root");
        run(workspace).expect("every helper spawn site uses the environment filter");
    }
}
