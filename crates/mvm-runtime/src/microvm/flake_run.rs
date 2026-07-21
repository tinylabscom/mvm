//! Flake-based run: multi-VM with bridge networking.

use anyhow::Result;
use tracing::{instrument, warn};

use crate::base::config::VmSlot;
use crate::base::shell::run_in_vm;
use crate::base::ui;
use crate::firecracker;
use crate::image::RuntimeVolume;
use crate::network_tunnel_spawn::{
    NetworkTunnelListener, NetworkTunnelWorkerSpawnParams,
    spawn_network_tunnel_worker_if_configured,
};

use super::daemon::{api_put_socket, start_vm_firecracker};
use super::guards::FirecrackerGuard;
use super::{firecracker_vsock_uds_path, require_linux_env};

// ============================================================================
// Flake-based run: multi-VM with bridge networking
// ============================================================================

/// A file to inject onto a config or secrets drive before boot.
#[derive(Debug, Clone)]
pub struct DriveFile {
    /// Destination filename inside the drive (e.g., "openclaw.json").
    pub name: String,
    /// File contents (inline).
    pub content: String,
    /// Unix permissions (octal). Config files: 0o444, secrets: 0o400.
    pub mode: u32,
}

impl Default for DriveFile {
    fn default() -> Self {
        Self {
            name: String::new(),
            content: String::new(),
            mode: 0o444,
        }
    }
}

/// Configuration for running a Firecracker VM from flake-built artifacts.
pub struct FlakeRunConfig {
    /// VM name (user-provided or auto-generated).
    pub name: String,
    /// Network slot for this VM.
    pub slot: VmSlot,
    /// Absolute path to the kernel image on the Linux host.
    pub vmlinux_path: String,
    /// Absolute path to the initial ramdisk (NixOS stage-1), if present.
    pub initrd_path: Option<String>,
    /// Absolute path to the root filesystem on the Linux host.
    pub rootfs_path: String,
    /// Absolute path to the dm-verity sidecar (Merkle hash tree) on
    /// the Linux host. Present when the flake was built with
    /// `verifiedBoot = true` (the production default).
    /// Must be paired with `roothash`.
    pub verity_path: Option<String>,
    /// 64-char lowercase-hex root hash from `rootfs.roothash`. Baked
    /// into the kernel cmdline as `dm-mod.create=`.
    pub roothash: Option<String>,
    /// Absolute path to the mvm runtime overlay ext4. When all three
    /// `runtime_overlay_*` fields are `Some`, this drive is attached
    /// as `/dev/vdc` and `mvm-verity-init` bind-mounts it at
    /// `/sysroot/mvm/runtime`.
    pub runtime_overlay_path: Option<String>,
    /// Absolute path to the runtime overlay verity sidecar; attached
    /// as `/dev/vdd`.
    pub runtime_overlay_verity_path: Option<String>,
    /// 64-char lowercase-hex root hash for the overlay; baked into
    /// the cmdline as `mvm.runtime_roothash=`.
    pub runtime_overlay_roothash: Option<String>,
    /// Declared guest-runtime source contract carried through the kernel
    /// cmdline so the guest launcher can distinguish required-overlay vs
    /// preferred-overlay boots.
    pub runtime_source_policy: mvm_core::vm_backend::RuntimeSourcePolicy,
    /// Nix store revision hash.
    pub revision_hash: String,
    /// Original flake reference (for display / status).
    pub flake_ref: String,
    /// Flake profile name (e.g. "worker", "gateway"), if specified.
    pub profile: Option<String>,
    /// Number of vCPUs.
    pub cpus: u32,
    /// Memory cap in MiB.
    pub memory: u32,
    /// Initial host commitment in MiB when opting into virtio-balloon.
    /// `None` = full commitment at boot (legacy default). `Some(n)`
    /// attaches a virtio-balloon device pre-inflated to
    /// `memory - n` MiB so the host commits only `n` MiB at boot;
    /// the host-side controller can PATCH the balloon target at
    /// runtime via Firecracker's `/balloon` endpoint.
    pub mem_initial: Option<u32>,
    /// Extra volumes to attach (mounted via config drive, not SSH).
    pub volumes: Vec<RuntimeVolume>,
    /// Extra files to write onto the config drive.
    pub config_files: Vec<DriveFile>,
    /// Extra files to write onto the secrets drive.
    pub secret_files: Vec<DriveFile>,
    /// Declared port mappings (host:guest) for forwarding and guest config.
    pub ports: Vec<crate::base::config::PortMapping>,
    /// Network policy controlling outbound traffic from this VM.
    pub network_policy: mvm_core::network_policy::NetworkPolicy,
    /// Optional shared guest-TUN ↔ host tunnel runtime config.
    pub network_tunnel: Option<mvm_core::protocol::network_tunnel::TunnelRuntimeConfig>,
}

impl FlakeRunConfig {
    /// Validate resource bounds and required fields.
    pub fn validate(&self) -> Result<()> {
        if self.cpus == 0 || self.cpus > 32 {
            anyhow::bail!("cpus must be between 1 and 32 (got {})", self.cpus);
        }
        if self.memory < 128 || self.memory > 65536 {
            anyhow::bail!(
                "memory must be between 128 and 65536 MiB (got {})",
                self.memory
            );
        }
        if let Some(initial) = self.mem_initial {
            // The balloon device must leave the guest with some
            // headroom; 0-byte commitment doesn't boot, and a value
            // >= memory is nonsensical (balloon would claim 0 or
            // negative pages). The CLI clamps these via filter() but
            // backends are the second line of defence.
            if initial == 0 {
                anyhow::bail!(
                    "mem_initial must be > 0 when set; got 0 (use None to opt out of balloon)"
                );
            }
            if initial >= self.memory {
                anyhow::bail!(
                    "mem_initial ({initial}) must be strictly less than memory ({}); \
                     the balloon needs a non-zero inflation target",
                    self.memory
                );
            }
        }
        if self.name.is_empty() {
            anyhow::bail!("VM name must not be empty");
        }
        if self.vmlinux_path.is_empty() {
            anyhow::bail!("vmlinux_path must not be empty");
        }
        if self.rootfs_path.is_empty() {
            anyhow::bail!("rootfs_path must not be empty");
        }
        Ok(())
    }
}

/// Boot a Firecracker VM from flake-built artifacts (headless).
///
/// Each VM gets its own directory under `<mvm_home>/vms/<name>/` with a
/// separate Firecracker socket, PID file, and log.  The bridge network
/// is shared, but each VM has its own TAP device and guest IP.
#[instrument(skip_all, fields(name = %config.name))]
pub fn run_from_build(config: &FlakeRunConfig) -> Result<()> {
    config.validate()?;
    require_linux_env()?;

    let slot = &config.slot;

    // Check if this VM name is already running
    let abs_dir = slot.vm_dir.clone();
    let abs_socket = format!("{}/fc.socket", abs_dir);
    let pid_file = format!("{}/fc.pid", abs_dir);

    if firecracker::is_vm_running(&pid_file)? {
        ui::info(&format!("VM '{}' is already running.", slot.name));
        ui::info("Use 'mvmctl stop <name>' to shut it down first.");
        return Ok(());
    }

    run_configured_firecracker(config, &abs_dir, &abs_socket, true)
}

/// Finish launching a Firecracker VM whose daemon has already been started in
/// the slot directory. Used by the standby pool: warming pays the daemon spawn
/// cost; claiming still configures the exact admitted workload before
/// `InstanceStart`.
#[instrument(skip_all, fields(name = %config.name))]
pub fn run_from_prestarted_build(
    config: &FlakeRunConfig,
    abs_dir: &str,
    abs_socket: &str,
) -> Result<()> {
    config.validate()?;
    require_linux_env()?;

    let expected_dir = config.slot.vm_dir.clone();
    if expected_dir != abs_dir {
        anyhow::bail!(
            "prestarted Firecracker dir mismatch for '{}': expected {}, got {}",
            config.slot.name,
            expected_dir,
            abs_dir
        );
    }
    let pid_file = format!("{}/fc.pid", abs_dir);
    if !firecracker::is_vm_running(&pid_file)? {
        anyhow::bail!(
            "prestarted Firecracker daemon for '{}' is not running",
            config.slot.name
        );
    }

    run_configured_firecracker(config, abs_dir, abs_socket, false)
}

/// The egress policy for this run's Firecracker TAP.
///
/// Firecracker is the one workload backend that stands up a routable TAP NIC
/// with a kernel firewall (libkrun/HVF carry egress solely over the vsock
/// tunnel). When this run also configures a userspace egress tunnel, that
/// tunnel is the auditable egress seam and must be the *only* one: applying
/// the run's allow-list to the TAP as well would let a guest bring the NIC up
/// itself and egress straight to the allow-listed hosts, bypassing the
/// tunnel's audit/substitution gate. So a tunnel-present run pins the TAP to
/// deny-all; the tunnel worker still receives the real policy to enforce.
/// A no-tunnel run keeps the run's policy on the TAP (the direct-NIC path,
/// including `--net` broad egress).
pub(super) fn firecracker_tap_policy(
    config: &FlakeRunConfig,
) -> mvm_core::network_policy::NetworkPolicy {
    config
        .network_policy
        .nic_policy_behind_tunnel(config.network_tunnel.is_some())
}

fn run_configured_firecracker(
    config: &FlakeRunConfig,
    abs_dir: &str,
    abs_socket: &str,
    start_daemon: bool,
) -> Result<()> {
    let slot = &config.slot;

    // A workload guest is vsock-only: it attaches no routable NIC, so there is
    // no host TAP / bridge to provision and no kernel-firewall egress moat to
    // arm. Claim-10 egress enforcement lives on the host-side vsock egress
    // endpoint's `EgressGate` (spawned below), matching libkrun/HVF.

    // Spawn `mvm-bridge` alongside the Firecracker VM.
    // The sidecar runs under
    // `mvm-jailer-lite` confinement (seccomp + Landlock), verifies the
    // operator-pinned passt SHA256, inherits both halves of a
    // socketpair from this process, and runs
    // `mvm-supervisor::gateway_bridge` with `BridgeEndpoints::Passt`.
    //
    // The guard kills the bridge on early return / panic between
    // spawn and the FC VM's boot completion; after the VM is healthy
    // the guard's child is detached and a watchdog thread takes over
    // (writes `fc-bridge.pid` and SIGTERMs the FC VM on bridge death
    // via `fc.pid`, hard-fail policy).
    //
    // No-op on non-Linux hosts (this Firecracker spawn path is Linux-only; the
    // shared sidecar binary lives at `crates/mvm-hostd/src/bin/mvm-bridge.rs`).
    //
    // Opt-in via MVM_GATEWAY_BRIDGE=1, the same gate the libkrun/hvf
    // gateway-bridge factory sits behind: the FC bridge lane is not yet
    // working end-to-end (its confinement spec doesn't grant the
    // observer-allowlist path it reads post-confinement), and its
    // watchdog hard-fail policy would tear down an otherwise healthy
    // VM. Before the egress moat landed, no producer wrote `plan.json`
    // pre-boot on this path, so the bridge never actually spawned;
    // the gate preserves that default while the moat (the vsock egress
    // endpoint below) runs unconditionally.
    #[cfg(target_os = "linux")]
    let mut bridge_guard = if std::env::var("MVM_GATEWAY_BRIDGE").as_deref() == Ok("1") {
        super::egress_bridge::spawn_fc_bridge(&config.slot.name, abs_dir)?
    } else {
        tracing::debug!(
            vm = %config.slot.name,
            "MVM_GATEWAY_BRIDGE not set; skipping mvm-bridge sidecar"
        );
        super::egress_bridge::AttachedBridgeGuard { child: None }
    };

    if start_daemon {
        // Start Firecracker daemon in per-VM directory.
        start_vm_firecracker(abs_dir, abs_socket)?;
    }
    let mut fc_guard = FirecrackerGuard::new(abs_dir);

    // Spawn the substitution endpoint BEFORE configuring boot args, so the
    // placeholders it mints land in `vm_substitution_env_path` and
    // `configure_flake_microvm` can carry them on the cmdline (`mvm.secret_env=`)
    // into a sealed entrypoint. The endpoint binds the per-port host UDS the
    // guest reaches over vsock and self-enforces the resolved egress policy — no
    // TAP, no nft REDIRECT. The guard reaps the endpoint if any step below fails
    // before the VM is fully up. Defused for a deny-all secret-free run.
    #[cfg(target_os = "linux")]
    let mut endpoint_guard = super::egress_bridge::spawn_egress_endpoint(config, abs_dir)?;
    let mut tunnel_guard =
        spawn_network_tunnel_worker_if_configured(NetworkTunnelWorkerSpawnParams {
            state_dir: &mvm_core::config::vm_state_dir(&config.name),
            runtime_config: config.network_tunnel.as_ref(),
            listener: config
                .network_tunnel
                .as_ref()
                .map(|tunnel| NetworkTunnelListener::Vsock(tunnel.guest_port)),
            network_policy: Some(&config.network_policy),
        })?;

    // Configure VM via Firecracker API
    super::boot_config::configure_flake_microvm(config, abs_dir, abs_socket)?;

    // Boot the instance
    ui::info("Starting microVM...");
    std::thread::sleep(std::time::Duration::from_millis(15));
    api_put_socket(
        abs_socket,
        "/actions",
        r#"{"action_type": "InstanceStart"}"#,
    )?;

    // Make vsock socket accessible to the current user
    let vsock = firecracker_vsock_uds_path(abs_dir);
    if let Err(e) = run_in_vm(&format!(
        "sudo chmod 0666 {vsock} 2>/dev/null",
        vsock = vsock,
    )) {
        warn!("failed to chmod vsock socket: {e}");
    }

    // Persist run info for `mvm status`
    super::run_info::write_vm_run_info(config, abs_dir)?;

    // VM is healthy. Detach the bridge guard so its child outlives
    // this stack frame; persist the bridge PID to
    // `<abs_dir>/fc-bridge.pid` and spawn the watchdog thread that
    // SIGTERMs the FC VM if the bridge dies (hard-fail bridge crash
    // policy).
    //
    // A failure here is non-fatal: the VM is already running. We log
    // and proceed; the guard remains attached, so the bridge will be
    // killed at function exit — observers lose flow events but the
    // workload is fine. The next `stop_vm` reaps any orphan via the
    // PID file if it was persisted.
    #[cfg(target_os = "linux")]
    if let Err(e) = super::egress_bridge::detach_and_spawn_bridge_watchdog(
        &config.slot.name,
        abs_dir,
        &mut bridge_guard,
    ) {
        warn!(
            vm = %config.slot.name,
            "detach/watchdog setup for mvm-bridge failed (non-fatal): {e}"
        );
    }

    // The egress endpoint spawned pre-boot is the whole moat now: it self-gates
    // egress over the guest's vsock channel, so there is no post-boot nft
    // REDIRECT to install once the guest is healthy.

    // VM is fully started — defuse guards so normal stop path handles cleanup
    fc_guard.defuse();
    #[cfg(target_os = "linux")]
    endpoint_guard.defuse();
    tunnel_guard.defuse();

    ui::banner(&[
        &format!("MicroVM '{}' is running!", config.name),
        "",
        &format!("  Guest IP: {}", slot.guest_ip),
        &format!("  Revision: {}", config.revision_hash),
        "",
        &format!("Use 'mvmctl stop {}' to shut down this VM.", config.name),
        "Use 'mvmctl status' to list all running VMs.",
    ]);

    Ok(())
}

/// Generate shell commands to inject `DriveFile`s into a mounted drive.
///
/// Each file is written via `sudo tee` with shell-escaped content, then
/// `chmod`'d to the requested permission mode. The caller must have the
/// drive mounted at `$MOUNT_DIR` before these commands run.
fn drive_file_inject_commands(files: &[DriveFile]) -> String {
    let mut cmds = String::new();
    for f in files {
        let escaped = f.content.replace('\'', "'\\''");
        let mode = format!("{:04o}", f.mode);
        // Stage the file into `$STAGE`; `mkfs.ext4 -d` copies the staged
        // tree into the image at format time (preserving mode), so no
        // loop mount / sudo is needed on the drive-build hot path.
        cmds.push_str(&format!(
            "echo '{content}' > \"$STAGE/{name}\"\nchmod {mode} \"$STAGE/{name}\"\n",
            content = escaped,
            name = f.name,
            mode = mode,
        ));
    }
    cmds
}

/// Create a config drive (mvm-config label) with config.json and role-specific toml.
pub fn create_dev_config_drive(abs_dir: &str, config: &FlakeRunConfig) -> Result<String> {
    let path = format!("{}/config.ext4", abs_dir);
    let slot = &config.slot;

    let config_json = serde_json::json!({
        "instance_id": config.name,
        "guest_ip": slot.guest_ip,
        "role": config.profile.as_deref().unwrap_or("worker"),
    });
    let escaped_json = config_json.to_string().replace('\'', "'\\''");

    // Determine role-specific config filename and stub content
    let role = config.profile.as_deref().unwrap_or("worker");
    let toml_name = format!("{}.toml", role);
    let toml_content = format!("# Dev-mode {} config stub\n", role);
    let escaped_toml = toml_content.replace('\'', "'\\''");

    // Build injection commands for custom config files
    let extra_cmds = drive_file_inject_commands(&config.config_files);

    // Populate-at-format via `mkfs.ext4 -d`: stage the files on the host,
    // then format the image directly from the staging dir. This replaces a
    // `mkfs` + loop `mount`/`tee`/`umount` round-trip (a sudo round-trip
    // that cost hundreds of ms per drive) with a single mkfs call.
    run_in_vm(&format!(
        r#"
        set -e
        STAGE=$(mktemp -d)
        echo '{json}' > "$STAGE/config.json"
        echo '{toml}' > "$STAGE/{toml_name}"
        chmod 0444 "$STAGE/config.json" "$STAGE/{toml_name}"
        {extra}
        rm -f {path}
        truncate -s 4M {path}
        mkfs.ext4 -q -L mvm-config -d "$STAGE" {path}
        rm -rf "$STAGE"
        chmod 0644 {path}
        "#,
        path = path,
        json = escaped_json,
        toml = escaped_toml,
        toml_name = toml_name,
        extra = extra_cmds,
    ))?;
    Ok(path)
}

/// Create a secrets drive (mvm-secrets label) with a stub secrets.json plus extra files.
pub fn create_dev_secrets_drive(abs_dir: &str, secret_files: &[DriveFile]) -> Result<String> {
    let path = format!("{}/secrets.ext4", abs_dir);

    let extra_cmds = drive_file_inject_commands(secret_files);

    // Populate-at-format via `mkfs.ext4 -d` (see `create_dev_config_drive`):
    // no loop mount, so a no-secrets workload no longer pays a sudo
    // mount/umount round-trip for an empty drive.
    run_in_vm(&format!(
        r#"
        set -e
        STAGE=$(mktemp -d)
        echo '{{}}' > "$STAGE/secrets.json"
        chmod 0400 "$STAGE/secrets.json"
        {extra}
        rm -f {path}
        truncate -s 4M {path}
        mkfs.ext4 -q -L mvm-secrets -d "$STAGE" {path}
        rm -rf "$STAGE"
        chmod 0600 {path}
        "#,
        path = path,
        extra = extra_cmds,
    ))?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drive_file_default() {
        let f = DriveFile::default();
        assert!(f.name.is_empty());
        assert!(f.content.is_empty());
        assert_eq!(f.mode, 0o444);
    }

    #[test]
    fn firecracker_tap_policy_denies_tap_when_tunnel_present() {
        // A tunnel-carried FC run must default-deny its TAP so egress can only
        // leave through the audited vsock tunnel — the TAP allow-list would
        // otherwise be a bypass. The tunnel worker keeps the real policy
        // (`network_policy` on the config is untouched).
        let mut config = baseline_run_config(None);
        config.network_policy = mvm_core::network_policy::NetworkPolicy::allow_list(vec![
            mvm_core::network_policy::HostPort::new("1.1.1.1", 443),
        ]);
        config.network_tunnel = Some(mvm_core::protocol::network_tunnel::TunnelRuntimeConfig {
            guest_port: 5302,
            session: mvm_core::protocol::network_tunnel::TunnelSessionConfig {
                tenant_id: "t".to_string(),
                vm_id: "vm-1".to_string(),
                boot_id: "boot-1".to_string(),
                session_nonce: "nonce-1".to_string(),
                requested_features: mvm_core::protocol::network_tunnel::TunnelFeatures {
                    ipv4: true,
                    ..mvm_core::protocol::network_tunnel::TunnelFeatures::default()
                },
                maximum_frame_size: 4096,
            },
        });

        assert_eq!(
            firecracker_tap_policy(&config),
            mvm_core::network_policy::NetworkPolicy::deny_all(),
            "tunnel-present FC TAP must be deny-all"
        );
        // The run's policy is preserved for the tunnel worker to enforce.
        assert!(config.network_policy.allows_egress());
    }

    #[test]
    fn firecracker_tap_policy_passes_policy_through_without_tunnel() {
        // No tunnel → the TAP is the egress path and keeps the run's policy.
        let mut config = baseline_run_config(None);
        config.network_policy = mvm_core::network_policy::NetworkPolicy::allow_list(vec![
            mvm_core::network_policy::HostPort::new("example.com", 443),
        ]);
        config.network_tunnel = None;
        assert_eq!(firecracker_tap_policy(&config), config.network_policy);
    }

    fn baseline_run_config(mem_initial: Option<u32>) -> FlakeRunConfig {
        FlakeRunConfig {
            name: "v".to_string(),
            slot: VmSlot::new("v", 0),
            vmlinux_path: "/k/vmlinux".to_string(),
            initrd_path: None,
            rootfs_path: "/k/rootfs.ext4".to_string(),
            verity_path: None,
            roothash: None,
            runtime_overlay_path: None,
            runtime_overlay_verity_path: None,
            runtime_overlay_roothash: None,
            runtime_source_policy: mvm_core::vm_backend::RuntimeSourcePolicy::PreferOverlay,
            revision_hash: "abc".to_string(),
            flake_ref: "/p".to_string(),
            profile: None,
            cpus: 2,
            memory: 1024,
            mem_initial,
            volumes: Vec::new(),
            config_files: Vec::new(),
            secret_files: Vec::new(),
            ports: Vec::new(),
            network_policy: mvm_core::network_policy::NetworkPolicy::default(),
            network_tunnel: None,
        }
    }

    #[test]
    fn flake_run_config_validate_accepts_none_mem_initial() {
        baseline_run_config(None).validate().unwrap();
    }

    #[test]
    fn flake_run_config_validate_accepts_valid_mem_initial() {
        // 256 < 1024 → balloon device gets `1024 - 256 = 768` MiB
        // inflation, host commits 256 MiB.
        baseline_run_config(Some(256)).validate().unwrap();
    }

    #[test]
    fn flake_run_config_validate_rejects_zero_mem_initial() {
        let err = baseline_run_config(Some(0))
            .validate()
            .expect_err("rejects zero mem_initial");
        let msg = format!("{err:#}");
        assert!(msg.contains("mem_initial"), "msg was: {msg}");
    }

    #[test]
    fn flake_run_config_validate_rejects_mem_initial_equal_to_memory() {
        let err = baseline_run_config(Some(1024))
            .validate()
            .expect_err("rejects mem_initial == memory");
        assert!(format!("{err:#}").contains("strictly less than"));
    }

    #[test]
    fn flake_run_config_validate_rejects_mem_initial_above_memory() {
        let err = baseline_run_config(Some(2048))
            .validate()
            .expect_err("rejects mem_initial > memory");
        assert!(format!("{err:#}").contains("strictly less than"));
    }

    #[test]
    fn drive_file_construction() {
        let f = DriveFile {
            name: "openclaw.json".into(),
            content: r#"{"gateway":{"port":18789}}"#.into(),
            mode: 0o444,
        };
        assert_eq!(f.name, "openclaw.json");
        assert!(f.content.contains("gateway"));
        assert_eq!(f.mode, 0o444);
    }

    #[test]
    fn drive_file_inject_commands_empty() {
        let cmds = drive_file_inject_commands(&[]);
        assert!(cmds.is_empty());
    }

    #[test]
    fn drive_file_inject_commands_single_file() {
        let files = vec![DriveFile {
            name: "test.txt".into(),
            content: "hello world".into(),
            mode: 0o444,
        }];
        let cmds = drive_file_inject_commands(&files);
        assert!(cmds.contains("hello world"));
        assert!(cmds.contains("test.txt"));
        assert!(cmds.contains("0444"));
    }

    #[test]
    fn drive_file_inject_commands_escapes_quotes() {
        let files = vec![DriveFile {
            name: "config.json".into(),
            content: "it's a test".into(),
            mode: 0o400,
        }];
        let cmds = drive_file_inject_commands(&files);
        // Single quotes in content should be escaped for shell safety
        assert!(cmds.contains(r"'\''"));
        assert!(cmds.contains("0400"));
    }

    #[test]
    fn drive_file_inject_commands_multiple_files() {
        let files = vec![
            DriveFile {
                name: "a.txt".into(),
                content: "aaa".into(),
                mode: 0o444,
            },
            DriveFile {
                name: "b.env".into(),
                content: "KEY=val".into(),
                mode: 0o400,
            },
        ];
        let cmds = drive_file_inject_commands(&files);
        assert!(cmds.contains("a.txt"));
        assert!(cmds.contains("b.env"));
        assert!(cmds.contains("KEY=val"));
    }
}
