//! Shared helpers used by multiple `commands/*` submodules.
//!
//! Extracted mechanically from `commands/mod.rs` — no behavior changes.

use anyhow::{Context, Result};
use serde::Serialize;
use std::sync::{Arc, Mutex};

use crate::bootstrap;
use crate::ui;

use mvm_runtime::config;
use mvm_runtime::shell;
use mvm_runtime::vm::{firecracker, image, lima, microvm};

/// Parameters for building a `VmStartConfig` from runtime-specific types.
pub(super) struct VmStartParams<'a> {
    pub(super) name: String,
    pub(super) rootfs_path: String,
    pub(super) vmlinux_path: String,
    pub(super) initrd_path: Option<String>,
    pub(super) revision_hash: String,
    pub(super) flake_ref: String,
    pub(super) profile: Option<String>,
    pub(super) cpus: u32,
    pub(super) memory_mib: u32,
    pub(super) volumes: &'a [image::RuntimeVolume],
    pub(super) config_files: &'a [microvm::DriveFile],
    pub(super) secret_files: &'a [microvm::DriveFile],
    pub(super) port_mappings: &'a [config::PortMapping],
}

impl VmStartParams<'_> {
    pub(super) fn into_start_config(self) -> mvm_core::vm_backend::VmStartConfig {
        mvm_core::vm_backend::VmStartConfig {
            name: self.name,
            rootfs_path: self.rootfs_path,
            kernel_path: Some(self.vmlinux_path),
            initrd_path: self.initrd_path,
            revision_hash: self.revision_hash,
            flake_ref: self.flake_ref,
            profile: self.profile,
            cpus: self.cpus,
            memory_mib: self.memory_mib,
            ports: self
                .port_mappings
                .iter()
                .map(|p| mvm_core::vm_backend::VmPortMapping {
                    host: p.host,
                    guest: p.guest,
                })
                .collect(),
            volumes: self
                .volumes
                .iter()
                .map(|v| mvm_core::vm_backend::VmVolume {
                    host: v.host.clone(),
                    guest: v.guest.clone(),
                    size: v.size.clone(),
                    read_only: v.read_only,
                })
                .collect(),
            config_files: self
                .config_files
                .iter()
                .map(|f| mvm_core::vm_backend::VmFile {
                    name: f.name.clone(),
                    content: f.content.clone(),
                    mode: f.mode,
                })
                .collect(),
            secret_files: self
                .secret_files
                .iter()
                .map(|f| mvm_core::vm_backend::VmFile {
                    name: f.name.clone(),
                    content: f.content.clone(),
                    mode: f.mode,
                })
                .collect(),
            runner_dir: None,
        }
    }
}

/// Global registry of spawned child PIDs so the signal handler can clean them up.
pub(super) static CHILD_PIDS: std::sync::LazyLock<Arc<Mutex<Vec<u32>>>> =
    std::sync::LazyLock::new(|| Arc::new(Mutex::new(Vec::new())));

/// When true, the Ctrl-C handler does nothing — console mode forwards
/// raw bytes to the guest instead.
pub(super) static IN_CONSOLE_MODE: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

// ============================================================================
// Structured JSON event output for --json mode
// ============================================================================

/// Structured event emitted during sync/build operations in --json mode.
#[derive(Debug, Serialize)]
pub(super) struct PhaseEvent {
    timestamp: String,
    command: &'static str,
    phase: String,
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl PhaseEvent {
    pub(super) fn new(command: &'static str, phase: &str, status: &'static str) -> Self {
        Self {
            timestamp: chrono::Utc::now().to_rfc3339(),
            command,
            phase: phase.to_string(),
            status,
            message: None,
            error: None,
        }
    }

    pub(super) fn with_message(mut self, msg: &str) -> Self {
        self.message = Some(msg.to_string());
        self
    }

    pub(super) fn with_error(mut self, err: &str) -> Self {
        self.error = Some(err.to_string());
        self
    }

    pub(super) fn emit(&self) {
        if let Ok(json) = serde_json::to_string(self) {
            println!("{}", json);
        }
    }
}

// ============================================================================
// Clap value parsers — run at argument-parse time for early validation
// ============================================================================

/// Validate a VM name at Clap parse time.
pub(super) fn clap_vm_name(s: &str) -> Result<String, String> {
    mvm_core::naming::validate_vm_name(s).map_err(|e| e.to_string())?;
    Ok(s.to_owned())
}

/// Validate a Nix flake reference at Clap parse time.
pub(super) fn clap_flake_ref(s: &str) -> Result<String, String> {
    mvm_core::naming::validate_flake_ref(s).map_err(|e| e.to_string())?;
    Ok(s.to_owned())
}

/// Validate a port spec (`PORT` or `HOST:GUEST`) at Clap parse time.
pub(super) fn clap_port_spec(s: &str) -> Result<String, String> {
    if s.is_empty() {
        return Err("port spec must not be empty".to_owned());
    }
    if let Some((host_part, guest_part)) = s.split_once(':') {
        host_part
            .parse::<u16>()
            .map_err(|_| format!("invalid host port {:?} in {:?}", host_part, s))?;
        guest_part
            .parse::<u16>()
            .map_err(|_| format!("invalid guest port {:?} in {:?}", guest_part, s))?;
    } else {
        s.parse::<u16>()
            .map_err(|_| format!("invalid port {:?} — expected PORT or HOST:GUEST", s))?;
    }
    Ok(s.to_owned())
}

/// Validate a volume spec (`host:/guest` or `host:/guest:size`) at Clap parse time.
pub(super) fn clap_volume_spec(s: &str) -> Result<String, String> {
    if s.is_empty() {
        return Err("volume spec must not be empty".to_owned());
    }
    let parts: Vec<&str> = s.splitn(3, ':').collect();
    if parts.len() < 2 || parts[0].is_empty() || parts[1].is_empty() {
        return Err(format!(
            "invalid volume {:?} — expected host:/guest or host:/guest:size",
            s
        ));
    }
    Ok(s.to_owned())
}

// ============================================================================
// Misc helpers
// ============================================================================

pub(super) fn shell_escape(s: &str) -> String {
    if s.contains(' ') || s.contains('\'') || s.contains('"') {
        format!("'{}'", s.replace('\'', "'\\''"))
    } else {
        s.to_string()
    }
}

pub(super) fn human_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes}B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1}K", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1}M", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.1}G", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

/// Wait for the guest agent to respond to a Ping over vsock.
/// Returns true if the agent is reachable within `timeout_secs`.
pub(super) fn wait_for_guest_agent(vm_id: &str, timeout_secs: u64) -> bool {
    use std::io::{Read, Write};
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
    let ping = serde_json::to_vec(&mvm_guest::vsock::GuestRequest::Ping).unwrap_or_default();
    let len_bytes = (ping.len() as u32).to_be_bytes();

    while std::time::Instant::now() < deadline {
        if let Ok(mut s) =
            mvm_apple_container::vsock_connect(vm_id, mvm_guest::vsock::GUEST_AGENT_PORT)
            && s.write_all(&len_bytes).is_ok()
            && s.write_all(&ping).is_ok()
            && s.flush().is_ok()
        {
            let mut resp_len = [0u8; 4];
            if s.read_exact(&mut resp_len).is_ok() {
                return true;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    false
}

/// Tell the guest agent to start a vsock→TCP forwarder for the given port.
pub(super) fn request_port_forward(vm_id: &str, guest_port: u16) -> Result<u32> {
    let mut stream = mvm_apple_container::vsock_connect(vm_id, mvm_guest::vsock::GUEST_AGENT_PORT)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    mvm_guest::vsock::start_port_forward_on(&mut stream, guest_port)
}

/// Resolve a VM name to its absolute directory path inside the Lima VM
/// and verify it is running.
pub(super) fn resolve_running_vm(name: &str) -> Result<String> {
    if bootstrap::is_lima_required() {
        lima::require_running()?;
    }

    let abs_vms = shell::run_in_vm_stdout(&format!("echo {}", config::VMS_DIR))?;
    let abs_dir = format!("{}/{}", abs_vms, name);
    let pid_file = format!("{}/fc.pid", abs_dir);

    if !firecracker::is_vm_running(&pid_file)? {
        anyhow::bail!(
            "VM '{}' is not running. Use 'mvmctl status' to list running VMs.",
            name
        );
    }

    Ok(abs_dir)
}

/// Resolve a flake reference: relative/absolute paths are canonicalized,
/// remote refs (containing `:`) pass through unchanged.
pub(super) fn resolve_flake_ref(flake_ref: &str) -> Result<String> {
    if flake_ref.contains(':') {
        // Remote ref like "github:user/repo" — pass through
        return Ok(flake_ref.to_string());
    }

    // Local path — canonicalize to absolute
    let path = std::path::Path::new(flake_ref);
    let canonical = path
        .canonicalize()
        .with_context(|| format!("Flake path '{}' does not exist", flake_ref))?;

    Ok(canonical.to_string_lossy().to_string())
}

/// Resolve CLI network flags into a `NetworkPolicy`.
/// `--network-preset` and `--network-allow` are mutually exclusive.
pub(super) fn resolve_network_policy(
    preset: Option<&str>,
    allow: &[String],
) -> Result<mvm_core::network_policy::NetworkPolicy> {
    use mvm_core::network_policy::{HostPort, NetworkPolicy, NetworkPreset};

    match (preset, allow.is_empty()) {
        (Some(_), false) => {
            anyhow::bail!("--network-preset and --network-allow are mutually exclusive")
        }
        (Some(name), true) => {
            let p: NetworkPreset = name.parse()?;
            Ok(NetworkPolicy::preset(p))
        }
        (None, false) => {
            let rules: Vec<HostPort> = allow
                .iter()
                .map(|s| s.parse())
                .collect::<Result<Vec<_>>>()?;
            Ok(NetworkPolicy::allow_list(rules))
        }
        (None, true) => Ok(NetworkPolicy::default()),
    }
}

/// Parse a port spec like `3000` or `8080:3000` into `(local, guest)`.
pub(super) fn parse_port_spec(spec: &str) -> Result<(u16, u16)> {
    if let Some((local, guest)) = spec.split_once(':') {
        let local: u16 = local
            .parse()
            .with_context(|| format!("invalid local port '{}'", local))?;
        let guest: u16 = guest
            .parse()
            .with_context(|| format!("invalid guest port '{}'", guest))?;
        Ok((local, guest))
    } else {
        let port: u16 = spec
            .parse()
            .with_context(|| format!("invalid port '{}'", spec))?;
        Ok((port, port))
    }
}

/// Parse multiple port specs into `PortMapping` values.
pub(super) fn parse_port_specs(specs: &[String]) -> Result<Vec<mvm_runtime::config::PortMapping>> {
    specs
        .iter()
        .map(|s| {
            let (host, guest) = parse_port_spec(s)?;
            Ok(mvm_runtime::config::PortMapping { host, guest })
        })
        .collect()
}

/// Convert port mappings into a `DriveFile` for the config drive.
/// Writes `export MVM_PORT_MAP="3333:3000,3334:3002"`.
pub(super) fn ports_to_drive_file(
    ports: &[mvm_runtime::config::PortMapping],
) -> Option<microvm::DriveFile> {
    if ports.is_empty() {
        return None;
    }
    let map_str = ports
        .iter()
        .map(|p| format!("{}:{}", p.host, p.guest))
        .collect::<Vec<_>>()
        .join(",");
    Some(microvm::DriveFile {
        name: "mvm-ports.env".to_string(),
        content: format!("export MVM_PORT_MAP=\"{}\"\n", map_str),
        mode: 0o444,
    })
}

/// Convert env var specs ("KEY=VALUE") into a `DriveFile` for the config drive.
pub(super) fn env_vars_to_drive_file(env_vars: &[String]) -> Option<microvm::DriveFile> {
    if env_vars.is_empty() {
        return None;
    }
    let content = env_vars
        .iter()
        .map(|kv| format!("export {}", kv))
        .collect::<Vec<_>>()
        .join("\n");
    Some(microvm::DriveFile {
        name: "mvm-env.env".to_string(),
        content: format!("{}\n", content),
        mode: 0o444,
    })
}

/// Read all regular files from a directory into `DriveFile` entries.
pub(super) fn read_dir_to_drive_files(
    dir: &str,
    default_mode: u32,
) -> Result<Vec<microvm::DriveFile>> {
    let mut files = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            files.push(microvm::DriveFile {
                name: entry.file_name().to_string_lossy().to_string(),
                content: std::fs::read_to_string(entry.path())?,
                mode: default_mode,
            });
        }
    }
    Ok(files)
}

/// Parsed volume specification from the `--volume/-v` CLI flag.
pub(super) enum VolumeSpec {
    /// Inject host directory contents onto a drive (2-part: `host_dir:/guest/path`).
    DirInject {
        host_dir: String,
        guest_mount: String,
    },
    /// Persistent ext4 volume with explicit size (3-part: `host:/guest/path:size`).
    Persistent(image::RuntimeVolume),
}

pub(super) fn parse_volume_spec(spec: &str) -> Result<VolumeSpec> {
    let parts: Vec<&str> = spec.splitn(3, ':').collect();
    match parts.len() {
        2 => Ok(VolumeSpec::DirInject {
            host_dir: parts[0].to_string(),
            guest_mount: parts[1].to_string(),
        }),
        3 => Ok(VolumeSpec::Persistent(image::RuntimeVolume {
            host: parts[0].to_string(),
            guest: parts[1].to_string(),
            size: parts[2].to_string(),
            read_only: false,
        })),
        _ => anyhow::bail!(
            "Invalid volume '{}'. Expected host_dir:/guest/path or host:/guest/path:size",
            spec
        ),
    }
}

// ============================================================================
// Error hints
// ============================================================================

/// Wrap a command result with actionable hints for common errors.
pub(super) fn with_hints(result: Result<()>) -> Result<()> {
    if let Err(ref e) = result {
        let msg = format!("{:#}", e);
        if msg.contains("limactl: command not found") || msg.contains("limactl: not found") {
            ui::warn("Hint: Install Lima with 'brew install lima' or run 'mvmctl bootstrap'.");
        } else if msg.contains("firecracker: command not found")
            || msg.contains("firecracker: not found")
        {
            ui::warn("Hint: Run 'mvmctl setup' to install Firecracker.");
        } else if msg.contains("/dev/kvm") {
            ui::warn(
                "Hint: Enable KVM/virtualization in your BIOS or VM settings.\n      \
                 On macOS, KVM is available inside the Lima VM.",
            );
        } else if msg.contains("Permission denied") && msg.contains(".mvm") {
            ui::warn("Hint: Check directory permissions on ~/.mvm (set MVM_DATA_DIR to override).");
        } else if msg.contains("nix: command not found") || msg.contains("nix: not found") {
            ui::warn("Hint: Nix is installed inside the Lima VM. Run 'mvmctl shell' first.");
        } else if msg.contains("Lima VM is not running") || msg.contains("VM is not started") {
            ui::warn(
                "Hint: Start the dev environment with 'mvmctl dev' or run 'mvmctl setup' \
                 to initialise it first.",
            );
        } else if msg.contains("already exists") && msg.contains("template") {
            ui::warn("Hint: Use '--force' to overwrite the existing template.");
        } else if msg.contains("error: builder for") && msg.contains("failed with exit code") {
            ui::warn(
                "Hint: Nix build failed. Check the log above for the failing derivation.\n      \
                 Common fixes: ensure flake inputs are up to date ('nix flake update'), \
                 or check your flake.nix for syntax errors.",
            );
        } else if msg.contains("does not provide attribute")
            || msg.contains("flake has no")
            || msg.contains("does not provide a package")
        {
            ui::warn(
                "Hint: Flake attribute not found. Your flake.lock may be stale.\n      \
                 Try: nix flake update (inside the Lima VM or flake directory).",
            );
        } else if msg.contains("No space left on device") || msg.contains("ENOSPC") {
            ui::warn(
                "Hint: Disk full. Run 'mvmctl doctor' to check space, \
                 or run 'nix-collect-garbage -d' inside the Lima VM.",
            );
        } else if msg.contains("timed out") || msg.contains("connection refused") {
            ui::warn(
                "Hint: The Lima VM may be unresponsive. Try 'mvmctl status' or \
                 restart with 'mvmctl stop && mvmctl dev'.",
            );
        } else if msg.contains("hash mismatch") && msg.contains("got:") {
            ui::warn(
                "Hint: Fixed-output derivation hash changed. Run \
                 'mvmctl template build <name> --update-hash' to recompute.",
            );
        } else if msg.contains("does it exist?") && msg.contains("template") {
            ui::warn("Hint: List available templates with 'mvmctl template list'.");
        }
    }
    result
}
