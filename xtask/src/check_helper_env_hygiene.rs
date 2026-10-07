//! `xtask check-helper-env-hygiene`
//!
//! The host processes `mvmctl` and the host daemons start are built by
//! `mvm_core::env_hygiene::helper_command`, which strips the loader, shell,
//! interpreter and password-manager-session variables the child would
//! otherwise inherit. A child started with a bare `Command::new` inherits
//! `LD_PRELOAD`, `BASH_ENV` or a vault session token from whoever ran
//! `mvmctl`, and nothing else would notice.
//!
//! Two checks hold that line.
//!
//! The named seams: each entry of [`HELPER_SPAWNS`] is a file and the header
//! of the function or `impl` block that starts a helper. Inside that body the
//! production code must call `helper_command(` and must not call
//! `Command::new(`.
//!
//! The inventory: every `.rs` file under `crates/` is scanned for raw process
//! creation — a `Command::new(` constructor, or a direct `fork`/`exec*` call —
//! and each one found must match an entry of [`RAW_SITES`]. An entry is keyed
//! by file, enclosing function and the call itself including its program
//! argument, so replacing `Command::new("ip")` with `Command::new("bash")` in
//! an exempt function is a new, unclassified site. An entry no longer matched
//! by the tree is stale and fails too, so the list cannot carry slack for a
//! later swap to consume. Only a process that is not started on the host may
//! stay raw, and every entry says why.
//!
//! Comments, string literals and `#[cfg(test)]` items are blanked before
//! either check, so neither a comment naming a constructor nor a test fixture
//! spawning `sleep` can satisfy or trip them. Files under `tests/` are test
//! harnesses, not processes `mvmctl` starts, and are not scanned.

use anyhow::{Result, bail};
use regex::Regex;
use std::path::Path;
use std::sync::OnceLock;

use crate::fs_walk::for_each_file;
use crate::rust_source::{blank_comments_and_strings, strip_cfg_test_items};

/// The constructor every helper spawn goes through.
const SANITIZER: &str = "helper_command(";

/// The unsanitized constructor a helper spawn must not use.
const RAW: &str = "Command::new(";

fn raw_constructor() -> &'static Regex {
    static RAW_CONSTRUCTOR: OnceLock<Regex> = OnceLock::new();
    RAW_CONSTRUCTOR.get_or_init(|| {
        Regex::new(r"\bCommand\s*::\s*new\s*\(")
            .expect("valid static raw process constructor expression")
    })
}

/// A direct process-creation call that bypasses `Command` altogether: bare,
/// or through `libc::` or `nix::unistd::`. Any other path or a method receiver
/// names something else (`checkpoint::fork(params)` forks a VM), and a process
/// `fork` takes no arguments.
fn raw_process_call() -> &'static Regex {
    static RAW_CALL: OnceLock<Regex> = OnceLock::new();
    RAW_CALL.get_or_init(|| {
        Regex::new(
            r"(?:^|[^.\w:])(?:(?:\w+::)*(?:libc|unistd)::)?(?:(fork|vfork)\s*\(\s*\)|(execv|execve|execvp|execvpe|execl|execlp|execle|posix_spawn|posix_spawnp)\s*\()",
        )
        .expect("valid static raw process call expression")
    })
}

fn raw_constructor_count(code: &str) -> usize {
    raw_constructor().find_iter(code).count()
}

/// Why a raw process creation is not a host spawn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Where {
    /// Runs inside a workload guest: the guest agent, its helpers, the guest
    /// init and privilege-drop binaries.
    Guest,
    /// Runs inside the builder VM, or Stage 0 that boots it.
    BuilderVm,
    /// On the host, and the filter's own constructor: it has to start from a
    /// `Command` to strip it. The enclosing function must remove what it
    /// strips.
    Filter,
    /// On the host, started by a direct `exec` with the environment the
    /// filter returns. The enclosing function must call it.
    FilteredExec,
}

impl Where {
    /// What the enclosing function's body must contain, for the places that
    /// are on the host.
    fn witnesses(self) -> &'static [&'static str] {
        match self {
            Self::Guest | Self::BuilderVm => &[],
            Self::Filter => &["scrub_command(", "env_remove("],
            Self::FilteredExec => &["env_hygiene::filtered_env("],
        }
    }
}

/// One raw process creation the inventory accepts.
struct RawSite {
    file: &'static str,
    /// The nearest enclosing `fn`, or `"<module>"` outside any.
    function: &'static str,
    /// `Command::new(<argument as written>)`, or the bare call name for a
    /// direct `fork`/`exec*`.
    call: &'static str,
    place: Where,
    reason: &'static str,
}

const fn guest(
    file: &'static str,
    function: &'static str,
    call: &'static str,
    reason: &'static str,
) -> RawSite {
    RawSite {
        file,
        function,
        call,
        place: Where::Guest,
        reason,
    }
}

const fn builder(
    file: &'static str,
    function: &'static str,
    call: &'static str,
    reason: &'static str,
) -> RawSite {
    RawSite {
        file,
        function,
        call,
        place: Where::BuilderVm,
        reason,
    }
}

const fn on_host(
    file: &'static str,
    function: &'static str,
    call: &'static str,
    place: Where,
    reason: &'static str,
) -> RawSite {
    RawSite {
        file,
        function,
        call,
        place,
        reason,
    }
}

/// Every raw process creation under `crates/`. Each is outside the host, or is
/// the filter itself.
const RAW_SITES: &[RawSite] = &[
    builder(
        "crates/mvm-agentd/src/bin/mvm-builder-agent.rs",
        "child_command",
        "Command::new(program)",
        "the builder agent, inside the builder VM",
    ),
    guest(
        "crates/mvm-agentd/src/bin/mvm-guest-agent/health.rs",
        "run_shell_with_timeout",
        "Command::new(\"/bin/sh\")",
        "a workload health check, run by the guest agent",
    ),
    guest(
        "crates/mvm-agentd/src/bin/mvm-guest-agent/interactive.rs",
        "do_run_detached_with",
        "Command::new(program)",
        "a detached workload process, started by the guest agent",
    ),
    guest(
        "crates/mvm-agentd/src/bin/mvm-guest-agent/interactive.rs",
        "do_run_detached_with",
        "Command::new(&exit_report_bin)",
        "a detached workload process, started by the guest agent",
    ),
    guest(
        "crates/mvm-agentd/src/bin/mvm-oci-entrypoint.rs",
        "main",
        "Command::new(&config.argv[0])",
        "the OCI image entrypoint, exec'd inside the guest",
    ),
    guest(
        "crates/mvm-agentd/src/bin/mvm-runner.rs",
        "dispatch",
        "Command::new(config.language.interpreter())",
        "the workload language runtime, started inside the guest",
    ),
    guest(
        "crates/mvm-agentd/src/bin/mvm-seccomp-apply.rs",
        "main",
        "Command::new(&cmd)",
        "execs the workload under its seccomp filter, inside the guest",
    ),
    builder(
        "crates/mvm-agentd/src/builder_agent.rs",
        "child_command",
        "Command::new(program)",
        "the builder agent, inside the builder VM",
    ),
    builder(
        "crates/mvm-agentd/src/builder_build.rs",
        "run_nix_build",
        "Command::new(\"sh\")",
        "a nix build run by the builder agent inside the builder VM",
    ),
    builder(
        "crates/mvm-agentd/src/builder_build.rs",
        "run_nix_build",
        "Command::new(\"sh\")",
        "a nix build run by the builder agent inside the builder VM",
    ),
    guest(
        "crates/mvm-agentd/src/console.rs",
        "spawn_shell",
        "fork",
        "the dev console shell, forked by the guest agent",
    ),
    guest(
        "crates/mvm-agentd/src/console.rs",
        "spawn_shell",
        "execve",
        "the dev console shell, forked by the guest agent",
    ),
    guest(
        "crates/mvm-agentd/src/crng_reseed/helper.rs",
        "spawn",
        "Command::new(&self.executable)",
        "the CRNG reseed helper, started by the guest agent",
    ),
    guest(
        "crates/mvm-agentd/src/entrypoint.rs",
        "execute_streaming",
        "Command::new(&program)",
        "the workload entrypoint, run by the guest agent",
    ),
    guest(
        "crates/mvm-agentd/src/exec_stream.rs",
        "stream_exec_mediated",
        "Command::new(program)",
        "a guest process streamed over vsock by the guest agent",
    ),
    guest(
        "crates/mvm-agentd/src/exec_stream.rs",
        "stream_exec_with_environment",
        "Command::new(\"/bin/sh\")",
        "a guest process streamed over vsock by the guest agent",
    ),
    guest(
        "crates/mvm-agentd/src/guest_bootstrap.rs",
        "run_one",
        "Command::new(&path)",
        "guest init services and loopback setup, inside the guest",
    ),
    guest(
        "crates/mvm-agentd/src/guest_bootstrap.rs",
        "spawn_one",
        "Command::new(path)",
        "guest init services and loopback setup, inside the guest",
    ),
    guest(
        "crates/mvm-agentd/src/guest_bootstrap.rs",
        "spawn_one_as",
        "Command::new(path)",
        "guest init services and loopback setup, inside the guest",
    ),
    guest(
        "crates/mvm-agentd/src/guest_bootstrap.rs",
        "busybox_loopback_up",
        "Command::new(busybox)",
        "guest init services and loopback setup, inside the guest",
    ),
    guest(
        "crates/mvm-agentd/src/guest_bootstrap.rs",
        "busybox_loopback_up",
        "Command::new(busybox)",
        "guest init services and loopback setup, inside the guest",
    ),
    guest(
        "crates/mvm-agentd/src/guest_net.rs",
        "seed_resolv_conf_bytes",
        "Command::new(\"/bin/busybox\")",
        "guest resolver and DHCP setup, inside the guest",
    ),
    guest(
        "crates/mvm-agentd/src/guest_net.rs",
        "configure_guest_network",
        "Command::new(\"/bin/udhcpc\")",
        "guest resolver and DHCP setup, inside the guest",
    ),
    guest(
        "crates/mvm-agentd/src/lifecycle_hooks.rs",
        "status",
        "Command::new(script_path)",
        "a workload lifecycle hook, run by the guest agent",
    ),
    guest(
        "crates/mvm-agentd/src/lifecycle_hooks.rs",
        "spawn",
        "Command::new(script_path)",
        "a workload lifecycle hook, run by the guest agent",
    ),
    guest(
        "crates/mvm-agentd/src/process_rpc.rs",
        "build_command",
        "Command::new(argv0)",
        "a process started over the guest process API, inside the guest",
    ),
    guest(
        "crates/mvm-agentd/src/worker_pool.rs",
        "spawn_worker",
        "Command::new(&program)",
        "a workload worker, spawned by the guest agent",
    ),
    builder(
        "crates/mvm-build/src/bin/mvm-host-vm-init/boot_stage.rs",
        "stage1",
        "Command::new(stage2)",
        "the builder VM's init",
    ),
    builder(
        "crates/mvm-build/src/bin/mvm-host-vm-init/builder_hooks.rs",
        "seal_rootfs_journal",
        "Command::new(E2FSCK)",
        "the builder VM's init",
    ),
    builder(
        "crates/mvm-build/src/bin/mvm-host-vm-init/builder_hooks.rs",
        "attach",
        "Command::new(UTIL_LINUX_LOSETUP)",
        "the builder VM's init",
    ),
    builder(
        "crates/mvm-build/src/bin/mvm-host-vm-init/builder_hooks.rs",
        "drop",
        "Command::new(UTIL_LINUX_LOSETUP)",
        "the builder VM's init",
    ),
    builder(
        "crates/mvm-build/src/bin/mvm-host-vm-init/builder_hooks.rs",
        "spawn_hook",
        "Command::new(HOOK_PATH)",
        "the builder VM's init",
    ),
    builder(
        "crates/mvm-build/src/bin/mvm-host-vm-init/install.rs",
        "run_with_env",
        "Command::new(program)",
        "the builder VM's init",
    ),
    builder(
        "crates/mvm-build/src/bin/mvm-host-vm-init/workload.rs",
        "command",
        "Command::new(FIRECRACKER_BIN)",
        "the builder VM's init",
    ),
    builder(
        "crates/mvm-build/src/bin/mvm-host-vm-init.rs",
        "agent_spawn_command",
        "Command::new(\"/bin/busybox\")",
        "the builder VM's init",
    ),
    builder(
        "crates/mvm-build/src/bin/mvm-host-vm-init.rs",
        "fork_vsock_egress_client_if_requested",
        "Command::new(\"/bin/busybox\")",
        "the builder VM's init",
    ),
    builder(
        "crates/mvm-build/src/bin/mvm-host-vm-init.rs",
        "fork_vsock_egress_client_if_requested",
        "Command::new(&egress_client)",
        "the builder VM's init",
    ),
    builder(
        "crates/mvm-build/src/bin/mvm-host-vm-init.rs",
        "spawn_builderd",
        "Command::new(mvm_build::builder_boot::guest_host_binary(\"mvm-builderd\"))",
        "the builder VM's init",
    ),
    builder(
        "crates/mvm-build/src/bin/mvm-host-vm-init.rs",
        "prepare_builder_nix_permissions",
        "Command::new(program)",
        "the builder VM's init",
    ),
    builder(
        "crates/mvm-build/src/bin/mvm-host-vm-init.rs",
        "import_seeded_closure",
        "Command::new(\"/sbin/nix-store\")",
        "the builder VM's init",
    ),
    builder(
        "crates/mvm-build/src/bin/mvm-host-vm-init.rs",
        "stage_disk_transport_input",
        "Command::new(\"/bin/busybox\")",
        "the builder VM's init",
    ),
    builder(
        "crates/mvm-build/src/bin/mvm-host-vm-init.rs",
        "restage_disk_transport_job",
        "Command::new(\"/bin/busybox\")",
        "the builder VM's init",
    ),
    builder(
        "crates/mvm-build/src/bin/mvm-host-vm-init.rs",
        "collect_disk_transport_output",
        "Command::new(\"/bin/busybox\")",
        "the builder VM's init",
    ),
    builder(
        "crates/mvm-build/src/bin/mvm-host-vm-init.rs",
        "run_modprobe",
        "Command::new(\"/bin/busybox\")",
        "the builder VM's init",
    ),
    builder(
        "crates/mvm-build/src/bin/mvm-host-vm-init.rs",
        "build_isolated_command",
        "Command::new(\"/bin/sh\")",
        "the builder VM's init",
    ),
    builder(
        "crates/mvm-build/src/bin/mvm-host-vm-init.rs",
        "build_isolated_command",
        "Command::new(\"unshare\")",
        "the builder VM's init",
    ),
    builder(
        "crates/mvm-build/src/bin/mvm-host-vm-init.rs",
        "seed_nix_store",
        "Command::new(\"/bin/cp\")",
        "the builder VM's init",
    ),
    builder(
        "crates/mvm-build/src/bin/mvm-host-vm-init.rs",
        "load_seeded_nix_db",
        "Command::new(\"/sbin/nix-store\")",
        "the builder VM's init",
    ),
    builder(
        "crates/mvm-build/src/bin/mvm-host-vm-init.rs",
        "format_ext4",
        "Command::new(\"/sbin/mkfs.ext4\")",
        "the builder VM's init",
    ),
    builder(
        "crates/mvm-build/src/bin/mvm-host-vm-init.rs",
        "power_off",
        "Command::new(\"/bin/sync\")",
        "the builder VM's init",
    ),
    builder(
        "crates/mvm-build/src/bin/stage0-init/kernel_emit.rs",
        "emit_resolved_config",
        "Command::new(nix)",
        "Stage 0's init, inside the bootstrap VM",
    ),
    builder(
        "crates/mvm-build/src/bin/stage0-init/store_gc.rs",
        "protect_seed_from_collection",
        "Command::new(&nix_store)",
        "Stage 0's init, inside the bootstrap VM",
    ),
    builder(
        "crates/mvm-build/src/bin/stage0-init/store_gc.rs",
        "run_store_gc",
        "Command::new(&nix)",
        "Stage 0's init, inside the bootstrap VM",
    ),
    builder(
        "crates/mvm-build/src/bin/stage0-init.rs",
        "best_effort_raise_loopback",
        "Command::new(busybox)",
        "Stage 0's init, inside the bootstrap VM",
    ),
    builder(
        "crates/mvm-build/src/bin/stage0-init.rs",
        "best_effort_raise_loopback",
        "Command::new(busybox)",
        "Stage 0's init, inside the bootstrap VM",
    ),
    builder(
        "crates/mvm-build/src/bin/stage0-init.rs",
        "fork_vsock_egress_client",
        "Command::new(egress_client)",
        "Stage 0's init, inside the bootstrap VM",
    ),
    builder(
        "crates/mvm-build/src/bin/stage0-init.rs",
        "ext4_format_command",
        "Command::new(mkfs)",
        "Stage 0's init, inside the bootstrap VM",
    ),
    builder(
        "crates/mvm-build/src/bin/stage0-init.rs",
        "build_and_copy",
        "Command::new(&nix)",
        "Stage 0's init, inside the bootstrap VM",
    ),
    builder(
        "crates/mvm-build/src/bin/stage0-init.rs",
        "build_and_copy",
        "Command::new(&nix)",
        "Stage 0's init, inside the bootstrap VM",
    ),
    builder(
        "crates/mvm-build/src/builderd.rs",
        "run",
        "Command::new(program)",
        "mvm-builderd, the daemon inside the builder VM",
    ),
    builder(
        "crates/mvm-build/src/builderd.rs",
        "run_builder_rootfs_command",
        "Command::new(&runner)",
        "mvm-builderd, the daemon inside the builder VM",
    ),
    guest(
        "crates/mvm-setpriv/src/lib.rs",
        "run",
        "Command::new(&invocation.command)",
        "execs the workload after the privilege drop, inside the guest",
    ),
    on_host(
        "crates/mvm-core/src/env_hygiene.rs",
        "helper_command_with",
        "Command::new(program)",
        Where::Filter,
        "the constructor every host helper is built by",
    ),
    on_host(
        "crates/mvm-cli/build.rs",
        "helper_command",
        "Command::new(program)",
        Where::Filter,
        "the build script's constructor over the same denylist; it cannot depend on mvm-core",
    ),
    on_host(
        "crates/mvm-cli/src/commands/seccomp_audit.rs",
        "run_linux",
        "fork",
        Where::FilteredExec,
        "the tracee must stop itself before exec, which `Command` cannot do",
    ),
    on_host(
        "crates/mvm-cli/src/commands/seccomp_audit.rs",
        "run_linux",
        "execvpe",
        Where::FilteredExec,
        "execs the audited command with the filtered environment",
    ),
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
        "fn mvmctl_command_for(",
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
    let mut sources = Vec::new();
    for_each_file(
        &workspace.join("crates"),
        Some("rs"),
        &mut |path, source| {
            let relative = path.strip_prefix(workspace).unwrap_or(path);
            let file = relative.to_string_lossy().replace('\\', "/");
            if file.contains("/tests/") || file.ends_with("/tests.rs") {
                return;
            }
            sources.push((file, source.to_string()));
        },
    )?;
    let found: Vec<FoundSite> = sources
        .iter()
        .flat_map(|(file, source)| raw_sites_in(file, source))
        .collect();
    failures.extend(unclassified_raw_sites(&found, RAW_SITES));
    failures.extend(unwitnessed_host_sites(&sources, RAW_SITES));
    if !failures.is_empty() {
        bail!(
            "check-helper-env-hygiene: {} spawn-site or raw-process inventory violation(s):\n  {}\n\
             Build a host process with `mvm_core::env_hygiene::helper_command(program)`. \
             Only a process started inside a guest or the builder VM may stay raw, \
             with an entry in RAW_SITES saying why.",
            failures.len(),
            failures.join("\n  ")
        );
    }
    eprintln!(
        "check-helper-env-hygiene: {} named helper seams use the filter; \
         {} raw process creations are all outside the host",
        HELPER_SPAWNS.len(),
        found.len(),
    );
    Ok(())
}

/// A raw process creation found in production code.
#[derive(Debug, Clone, PartialEq, Eq)]
struct FoundSite {
    file: String,
    line: usize,
    function: String,
    call: String,
}

/// Every raw process creation in `source`'s production code.
fn raw_sites_in(file: &str, source: &str) -> Vec<FoundSite> {
    let production = strip_cfg_test_items(&blank_comments_and_strings(source));
    // The blanker keeps every char in place, so a char index into the blanked
    // text addresses the same char of the original.
    let original: Vec<char> = source.chars().collect();
    let blanked: Vec<char> = production.chars().collect();
    let char_index = |byte: usize| production[..byte].chars().count();
    let mut sites = Vec::new();
    for found in raw_constructor().find_iter(&production) {
        let open = char_index(found.end()) - 1;
        let argument = parenthesized(&blanked, &original, open);
        sites.push(FoundSite {
            file: file.to_string(),
            line: line_of(&production, found.start()),
            function: enclosing_function(&production[..found.start()]),
            call: format!("Command::new({argument})"),
        });
    }
    for captures in raw_process_call().captures_iter(&production) {
        let name = captures
            .get(1)
            .or_else(|| captures.get(2))
            .expect("one call name is captured");
        let before = &production[..name.start()];
        if before.trim_end().ends_with("fn") {
            continue;
        }
        sites.push(FoundSite {
            file: file.to_string(),
            line: line_of(&production, name.start()),
            function: enclosing_function(before),
            call: name.as_str().to_string(),
        });
    }
    sites.sort_by_key(|site| site.line);
    sites
}

fn line_of(text: &str, byte: usize) -> usize {
    text[..byte].matches('\n').count() + 1
}

/// The name of the last `fn` declared before the end of `before`.
fn enclosing_function(before: &str) -> String {
    static FN_NAME: OnceLock<Regex> = OnceLock::new();
    FN_NAME
        .get_or_init(|| Regex::new(r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)").expect("valid fn regex"))
        .captures_iter(before)
        .last()
        .map_or_else(|| "<module>".to_string(), |c| c[1].to_string())
}

/// The original text between the `(` at char `open` and its matching `)`,
/// with whitespace collapsed and a trailing comma dropped. Parens are matched
/// on the blanked text, so a paren inside a string literal is not counted.
fn parenthesized(blanked: &[char], original: &[char], open: usize) -> String {
    let mut depth = 0usize;
    let mut close = blanked.len();
    for (index, &c) in blanked.iter().enumerate().skip(open) {
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    close = index;
                    break;
                }
            }
            _ => {}
        }
    }
    let inner: String = original[open + 1..close].iter().collect();
    let collapsed = inner.split_whitespace().collect::<Vec<_>>().join(" ");
    collapsed.trim_end_matches(',').trim().to_string()
}

/// Match each found site against one unused entry of `allowed`. A found site
/// with no entry, an entry with no reason, and an entry nothing matched all
/// fail.
fn unclassified_raw_sites(found: &[FoundSite], allowed: &[RawSite]) -> Vec<String> {
    let mut used = vec![false; allowed.len()];
    let mut failures = Vec::new();
    for site in found {
        let entry = allowed.iter().enumerate().position(|(index, entry)| {
            !used[index]
                && entry.file == site.file
                && entry.function == site.function
                && entry.call == site.call
        });
        match entry {
            Some(index) => used[index] = true,
            None => failures.push(format!(
                "{}:{}: unclassified raw process creation `{}` in `fn {}`",
                site.file, site.line, site.call, site.function
            )),
        }
    }
    for (entry, used) in allowed.iter().zip(used) {
        if entry.reason.trim().is_empty() {
            failures.push(format!(
                "{} `fn {}` `{}`: a {:?} exemption must say why",
                entry.file, entry.function, entry.call, entry.place
            ));
        }
        if !used {
            failures.push(format!(
                "{} `fn {}` `{}`: stale RAW_SITES entry; nothing in the tree matches it",
                entry.file, entry.function, entry.call
            ));
        }
    }
    failures
}

/// A raw site on the host whose enclosing function does not do the filtering
/// its place claims.
fn unwitnessed_host_sites(sources: &[(String, String)], allowed: &[RawSite]) -> Vec<String> {
    let mut failures = Vec::new();
    for entry in allowed {
        let witnesses = entry.place.witnesses();
        if witnesses.is_empty() {
            continue;
        }
        let Some((_, source)) = sources.iter().find(|(file, _)| file == entry.file) else {
            continue;
        };
        let production = strip_cfg_test_items(&blank_comments_and_strings(source));
        let header = format!("fn {}(", entry.function);
        match body_after(&production, &header) {
            Ok(body) if witnesses.iter().any(|w| body.contains(w)) => {}
            Ok(_) => failures.push(format!(
                "{} `fn {}`: a {:?} site must call one of {witnesses:?}",
                entry.file, entry.function, entry.place
            )),
            Err(problem) => {
                failures.push(format!("{} `fn {}`: {problem}", entry.file, entry.function))
            }
        }
    }
    failures
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

    const GUEST_FILE: &str = "crates/mvm-agentd/src/guest_net.rs";

    fn guest_ip_site() -> [RawSite; 1] {
        [guest(
            GUEST_FILE,
            "bring_up",
            "Command::new(\"ip\")",
            "runs in the guest agent",
        )]
    }

    #[test]
    fn sites_are_keyed_by_file_function_and_program() {
        let src =
            "fn bring_up() {\n    let _ = Command::new(\n        \"ip\",\n    ).status();\n}\n";
        let found = raw_sites_in(GUEST_FILE, src);
        assert_eq!(
            found,
            vec![FoundSite {
                file: GUEST_FILE.to_string(),
                line: 2,
                function: "bring_up".to_string(),
                call: "Command::new(\"ip\")".to_string(),
            }]
        );
        assert!(unclassified_raw_sites(&found, &guest_ip_site()).is_empty());
    }

    #[test]
    fn a_new_raw_command_outside_the_pinned_sites_is_discovered() {
        let found = raw_sites_in(
            "crates/mvm-hostd/src/new_helper.rs",
            "fn start() { Command :: new (helper).spawn(); }",
        );
        let failures = unclassified_raw_sites(&found, &[]);
        assert_eq!(failures.len(), 1);
        assert!(failures[0].contains("new_helper.rs:1"), "{failures:?}");
        assert!(failures[0].contains("Command::new(helper)"), "{failures:?}");
    }

    #[test]
    fn swapping_one_raw_call_for_another_in_an_exempt_function_is_caught() {
        let swapped =
            "fn bring_up() {\n    let _ = Command::new(\"bash\").arg(\"-c\").status();\n}\n";
        let failures = unclassified_raw_sites(&raw_sites_in(GUEST_FILE, swapped), &guest_ip_site());
        assert_eq!(failures.len(), 2, "{failures:?}");
        assert!(
            failures[0].contains("Command::new(\"bash\")"),
            "{failures:?}"
        );
        assert!(failures[1].contains("stale"), "{failures:?}");
    }

    #[test]
    fn a_second_raw_call_beside_an_exempt_one_is_caught() {
        let doubled = "fn bring_up() {\n    Command::new(\"ip\");\n    Command::new(\"ip\");\n}\n";
        let failures = unclassified_raw_sites(&raw_sites_in(GUEST_FILE, doubled), &guest_ip_site());
        assert_eq!(failures.len(), 1, "{failures:?}");
        assert!(failures[0].contains(":3:"), "{failures:?}");
    }

    #[test]
    fn a_raw_bash_spawn_on_the_host_is_refused() {
        let src = "pub fn teardown(dir: &Path) {\n    let _ = std::process::Command::new(\"bash\")\n        .args([\"-c\", \"rm -rf x\"])\n        .status();\n}\n";
        // Against the real list: no entry admits a raw shell in a host file.
        // Every other entry reads as stale here, since this one file is all
        // the scan was given.
        let failures: Vec<String> =
            unclassified_raw_sites(&raw_sites_in("crates/mvm-cli/src/exec.rs", src), RAW_SITES)
                .into_iter()
                .filter(|failure| failure.contains("unclassified"))
                .collect();
        assert_eq!(failures.len(), 1, "{failures:?}");
        assert!(
            failures[0].contains("crates/mvm-cli/src/exec.rs:2")
                && failures[0].contains("Command::new(\"bash\")")
                && failures[0].contains("fn teardown"),
            "{failures:?}"
        );
    }

    #[test]
    fn a_direct_fork_or_exec_is_discovered_but_not_its_declaration() {
        let src = "extern \"C\" { fn execve(p: *const u8) -> i32; }\nfn run() {\n    match unsafe { nix::unistd::fork() } { _ => {} }\n    nix::unistd::execvp(&p, &a);\n    cmd.exec();\n    parse_execve(line);\n}\n";
        let calls: Vec<_> = raw_sites_in("crates/mvm-cli/src/x.rs", src)
            .into_iter()
            .map(|site| (site.line, site.function, site.call))
            .collect();
        assert_eq!(
            calls,
            vec![
                (3, "run".to_string(), "fork".to_string()),
                (4, "run".to_string(), "execvp".to_string()),
            ]
        );
    }

    #[test]
    fn a_stale_or_unexplained_entry_fails() {
        let unexplained = [builder(GUEST_FILE, "bring_up", "Command::new(\"ip\")", " ")];
        let failures = unclassified_raw_sites(&[], &unexplained);
        assert!(
            failures.iter().any(|f| f.contains("must say why")),
            "{failures:?}"
        );
        assert!(failures.iter().any(|f| f.contains("stale")), "{failures:?}");
    }

    #[test]
    fn a_raw_command_in_a_comment_string_or_test_is_not_a_site() {
        let src = "fn f() {\n    // Command::new(\"bash\")\n    let s = \"Command::new(x)\";\n}\n#[cfg(test)]\nmod tests {\n    fn t() { std::process::Command::new(\"sleep\"); }\n}\n";
        assert!(raw_sites_in("crates/mvm-cli/src/x.rs", src).is_empty());
    }

    #[test]
    fn a_filtered_exec_must_call_the_filter_in_its_function() {
        let file = "crates/mvm-cli/src/commands/seccomp_audit.rs";
        let entry = [on_host(
            file,
            "run_linux",
            "fork",
            Where::FilteredExec,
            "why",
        )];
        let unfiltered = "fn run_linux() {\n    let pid = unsafe { nix::unistd::fork() };\n}\n";
        let failures =
            unwitnessed_host_sites(&[(file.to_string(), unfiltered.to_string())], &entry);
        assert_eq!(failures.len(), 1, "{failures:?}");
        assert!(failures[0].contains("filtered_env"), "{failures:?}");
        let filtered = "fn run_linux() {\n    let env = mvm_core::env_hygiene::filtered_env(&r);\n    let pid = unsafe { nix::unistd::fork() };\n}\n";
        assert!(
            unwitnessed_host_sites(&[(file.to_string(), filtered.to_string())], &entry).is_empty()
        );
    }

    #[test]
    fn every_listed_site_passes_in_this_tree() {
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("xtask sits in the workspace root");
        run(workspace).expect("every helper spawn site uses the environment filter");
    }
}
