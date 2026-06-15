use anyhow::{Context, Result};
use tracing::{instrument, warn};

use crate::base::config::*;
use crate::base::shell::{run_in_vm, run_in_vm_stdout, run_in_vm_visible, shell_quote};
use crate::base::ui;
use crate::image::RuntimeVolume;
use crate::network_provider::BridgeTapNetworkProvider;
use crate::{firecracker, network};
use mvm_network::{NetHandle, NetworkProvider, NetworkSpec};

// ============================================================================
// RAII resource guards — prevent leaks when VM launch fails partway through
// ============================================================================

/// RAII guard for a Firecracker process started inside the Lima VM.
///
/// On drop, kills the Firecracker process using the PID file and cleans up
/// the API socket. Call `defuse()` after a successful launch to prevent
/// cleanup (ownership transfers to the normal stop path).
pub struct FirecrackerGuard {
    /// Absolute path to the VM directory inside the Lima VM (contains fc.pid, fc.socket).
    abs_dir: Option<String>,
}

impl FirecrackerGuard {
    /// Create a new guard for a Firecracker process in the given directory.
    pub fn new(abs_dir: &str) -> Self {
        Self {
            abs_dir: Some(abs_dir.to_string()),
        }
    }

    /// Defuse the guard — prevents cleanup on drop.
    /// Call this after the VM has been fully started and run-info written.
    pub fn defuse(&mut self) {
        self.abs_dir = None;
    }
}

impl Drop for FirecrackerGuard {
    fn drop(&mut self) {
        if let Some(ref dir) = self.abs_dir {
            warn!(dir = %dir, "FirecrackerGuard: killing orphaned Firecracker process");
            if let Err(e) = run_in_vm(&format!(
                r#"
                if [ -f {dir}/fc.pid ]; then
                    sudo kill "$(cat {dir}/fc.pid)" 2>/dev/null || true
                    rm -f {dir}/fc.pid
                elif [ -f {dir}/.fc-pid ]; then
                    sudo kill "$(cat {dir}/.fc-pid)" 2>/dev/null || true
                    rm -f {dir}/.fc-pid
                fi
                sudo rm -f {dir}/fc.socket
                "#,
                dir = dir,
            )) {
                warn!("FirecrackerGuard: cleanup failed: {e}");
            }
        }
    }
}

/// RAII guard for a TAP network interface created inside the Lima VM.
///
/// On drop, destroys the TAP device. Call `defuse()` after a successful
/// launch to prevent cleanup (ownership transfers to the normal stop path).
pub struct TapGuard {
    slot: Option<VmSlot>,
}

impl TapGuard {
    /// Create a new guard for a TAP device associated with the given slot.
    pub fn new(slot: &VmSlot) -> Self {
        Self {
            slot: Some(slot.clone()),
        }
    }

    /// Defuse the guard — prevents cleanup on drop.
    pub fn defuse(&mut self) {
        self.slot = None;
    }
}

impl Drop for TapGuard {
    fn drop(&mut self) {
        if let Some(ref slot) = self.slot {
            warn!(tap = %slot.tap_dev, "TapGuard: destroying orphaned TAP device");
            if let Err(e) = network::tap_destroy(slot) {
                warn!("TapGuard: cleanup failed: {e}");
            }
        }
    }
}

/// RAII reaper for the per-VM substitution endpoint when it is spawned
/// **before** boot (the placeholders it mints must ride the boot
/// cmdline). If a later boot step fails and returns before the endpoint
/// is fully wired, `Drop` reaps it so its decrypted-secret process can't outlive
/// a failed launch. Defused once the VM is fully up (the normal `stop_vm` path
/// then owns teardown, same as `FirecrackerGuard`/`TapGuard`).
#[cfg(target_os = "linux")]
pub struct EndpointGuard {
    vm_name: Option<String>,
}

#[cfg(target_os = "linux")]
impl EndpointGuard {
    fn new(vm_name: &str) -> Self {
        Self {
            vm_name: Some(vm_name.to_string()),
        }
    }
    fn defuse(&mut self) {
        self.vm_name = None;
    }
}

#[cfg(target_os = "linux")]
impl Drop for EndpointGuard {
    fn drop(&mut self) {
        if let Some(ref name) = self.vm_name {
            warn!(vm = %name, "EndpointGuard: reaping orphaned substitution endpoint");
            crate::substitution_spawn::reap_substitution_endpoint(
                &mvm_core::config::vm_state_dir(name),
                name,
            );
        }
    }
}

/// Ensure we have a Linux execution environment.
///
/// Today this is always a no-op: native Linux runs Firecracker directly,
/// macOS runs libkrun, and the Lima fallback is gone.
/// Kept as a function so callers stay well-formed; remove once every
/// callsite is audited and the call itself can be dropped.
fn require_linux_env() -> Result<()> {
    Ok(())
}

/// Resolve MICROVM_DIR (~) to an absolute path inside the Lima VM.
fn resolve_microvm_dir() -> Result<String> {
    run_in_vm_stdout(&format!("echo {}", MICROVM_DIR))
}

/// Resolve a per-VM directory path (~ expansion) inside the Lima VM.
pub fn resolve_vm_dir(slot: &VmSlot) -> Result<String> {
    run_in_vm_stdout(&format!("echo {}", slot.vm_dir))
}

/// Resolve the absolute directory path for a running VM by name.
pub fn resolve_running_vm_dir(name: &str) -> Result<String> {
    let abs_vms = run_in_vm_stdout(&format!("echo {}", VMS_DIR))?;
    Ok(format!("{}/{}", abs_vms, name))
}

/// Firecracker binds the vsock UDS at `<dir>/v.sock`, but the host-side
/// transport resolves it via `vsock_uds_path` = `<dir>/runtime/v.sock`
/// (the convention the template/slot launch and the mock agent share).
/// Expose the socket under `runtime/` so `wait_for_guest_agent` finds it.
/// Best-effort; a dangling symlink until InstanceStart binds the socket.
fn expose_vsock_runtime_symlink(dir: &str) {
    if let Err(e) = run_in_vm(&format!(
        "mkdir -p {dir}/runtime && ln -sf ../v.sock {dir}/runtime/v.sock"
    )) {
        warn!("failed to expose vsock UDS under runtime/: {e}");
    }
}

/// Resolve the path to the per-VM serial console log file.
///
/// The host-side netinit-audit emitter
/// (`netinit_audit::emit_for_vm`) reads this file after the
/// agent is ready and parses the netinit Report from the
/// captured `__MVM_NETINIT_REPORT__` line. The path follows the
/// existing convention (`<vm_dir>/console.log`); a backend
/// that doesn't split console + hypervisor logs returns a
/// path that may not exist, which the caller treats as
/// "no netinit report available" rather than an error.
pub fn vm_console_log_path(vm_name: &str) -> Result<std::path::PathBuf> {
    let abs_dir = resolve_running_vm_dir(vm_name)?;
    Ok(std::path::PathBuf::from(format!("{abs_dir}/console.log")))
}

/// Start the Firecracker daemon inside the Lima VM (background).
#[instrument(skip_all)]
fn start_firecracker_daemon(abs_dir: &str) -> Result<()> {
    ui::info("Starting Firecracker...");
    run_in_vm_visible(&format!(
        r#"
        mkdir -p {dir}
        sudo rm -f {socket}
        rm -f {dir}/v.sock
        touch {dir}/console.log {dir}/firecracker.log
        sudo bash -c 'nohup setsid firecracker --api-sock {socket} --enable-pci \
            </dev/null >{dir}/console.log 2>{dir}/firecracker.log &
            echo $! > {dir}/.fc-pid'

        echo "[mvm] Waiting for API socket..."
        for i in $(seq 1 30); do
            [ -S {socket} ] && break
            sleep 0.1
        done

        if [ ! -S {socket} ]; then
            echo "[mvm] ERROR: API socket did not appear." >&2
            exit 1
        fi
        echo "[mvm] Firecracker started."
        "#,
        socket = API_SOCKET,
        dir = abs_dir,
    ))
}

/// Start a Firecracker daemon in a per-VM directory with its own socket.
#[instrument(skip_all)]
pub fn start_vm_firecracker(abs_dir: &str, abs_socket: &str) -> Result<()> {
    ui::info("Starting Firecracker...");
    run_in_vm_visible(&format!(
        r#"
        mkdir -p {dir}
        sudo rm -f {socket}
        rm -f {dir}/v.sock
        touch {dir}/console.log {dir}/firecracker.log
        sudo bash -c 'nohup setsid firecracker --api-sock {socket} --enable-pci \
            </dev/null >{dir}/console.log 2>{dir}/firecracker.log &
            echo $! > {dir}/fc.pid'

        echo "[mvm] Waiting for API socket..."
        for i in $(seq 1 30); do
            [ -S {socket} ] && break
            sleep 0.1
        done

        if [ ! -S {socket} ]; then
            echo "[mvm] ERROR: API socket did not appear." >&2
            exit 1
        fi
        echo "[mvm] Firecracker started."
        "#,
        socket = abs_socket,
        dir = abs_dir,
    ))
}

/// Send API PUT request to Firecracker via its Unix socket.
fn api_put(path: &str, data: &str) -> Result<()> {
    api_put_socket(API_SOCKET, path, data)
}

/// Send API PUT request to a specific Firecracker socket.
///
/// `data` is written to a temp file and passed via `curl --data @<file>`
/// so the body never traverses the shell — guards against the
/// `--data '{json}'` shape where a single-quote in `data` would
/// escape into the host shell (`specs/01-project.md` flagged the v1
/// shape's quoting fragility). `socket` and `path` are
/// `shell_quote`d defensively.
#[instrument(skip_all, fields(path))]
pub fn api_put_socket(socket: &str, path: &str, data: &str) -> Result<()> {
    fc_api_call("PUT", socket, path, Some(data))
}

/// Send API PATCH request to a specific Firecracker socket.
#[instrument(skip_all, fields(path))]
pub fn api_patch_socket(socket: &str, path: &str, data: &str) -> Result<()> {
    fc_api_call("PATCH", socket, path, Some(data))
}

/// Shared body for FC's PUT/PATCH calls. Writes `data` (if Some) to a
/// `NamedTempFile`, then shells out to curl with `--data @<file>` so
/// the JSON body never goes through bash. All paths flowing into the
/// script are `shell_quote`d.
fn fc_api_call(method: &str, socket: &str, path: &str, data: Option<&str>) -> Result<()> {
    use std::io::Write;
    let q_socket = shell_quote(socket);
    let url = format!("http://localhost{path}");
    let q_url = shell_quote(&url);
    let q_path = shell_quote(path);

    let (data_arg, _body_holder) = match data {
        Some(body) => {
            let mut tmp = tempfile::NamedTempFile::new()
                .with_context(|| "creating temp file for FC API body")?;
            tmp.write_all(body.as_bytes())
                .with_context(|| "writing FC API body to temp file")?;
            tmp.flush()
                .with_context(|| "flushing FC API body to temp file")?;
            let path_str = tmp.path().to_string_lossy().into_owned();
            let q_body_path = shell_quote(&path_str);
            (
                format!(
                    "--data @{q_body_path} -H 'Content-Type: application/json'",
                    q_body_path = &q_body_path[..]
                ),
                Some(tmp),
            )
        }
        None => (String::new(), None),
    };

    let script = format!(
        r#"
        set -eu
        response=$(sudo curl -s -w "\n%{{http_code}}" -X {method} --unix-socket {q_socket} \
            {data_arg} {q_url})
        code=$(printf '%s' "$response" | tail -n1)
        body=$(printf '%s' "$response" | sed '$d')
        if [ "$code" -ge 400 ]; then
            echo "[mvm] ERROR: {method} $(printf '%s' {q_path}) returned $code: $body" >&2
            exit 1
        fi
        "#,
    );
    run_in_vm_visible(&script)
    // _body_holder drops at function exit, deleting the temp file.
}

/// Configure the microVM via the Firecracker API (dev-mode, legacy).
#[instrument(skip_all)]
fn configure_microvm(state: &MvmState, abs_dir: &str) -> Result<()> {
    ui::info("Configuring logger...");
    api_put(
        "/logger",
        &format!(
            r#"{{"log_path": "{dir}/firecracker.log", "level": "Debug", "show_level": true, "show_log_origin": true}}"#,
            dir = abs_dir,
        ),
    )?;

    let kernel_path = format!("{}/{}", abs_dir, state.kernel);
    // A plain mkGuest workload emits no kernel (mkGuest's `kernel` input is
    // optional), so the build dir may carry only a rootfs. Fall back to the
    // cached builder-VM kernel exactly like the QEMU workload path does;
    // `ensure_fc_loadable_kernel` below extracts an FC-loadable ELF if it's
    // a bzImage.
    let kernel_path = if std::path::Path::new(&kernel_path).is_file() {
        kernel_path
    } else {
        let arch = if cfg!(target_arch = "aarch64") {
            "aarch64"
        } else {
            "x86_64"
        };
        let fallback = std::path::PathBuf::from(mvm_core::config::mvm_cache_dir())
            .join("builder-vm")
            .join(arch)
            .join("vmlinux");
        anyhow::ensure!(
            fallback.is_file(),
            "firecracker workload has no bootable kernel: the build produced no \
             {kernel_path} and no cached builder kernel exists at {}. Run a build / \
             `mvmctl dev up` to populate the builder VM image first.",
            fallback.display()
        );
        fallback.display().to_string()
    };
    let rootfs_path = format!("{}/{}", abs_dir, state.rootfs);

    // Use kernel cmdline IP params (no SSH-based guest network config).
    // net.ifnames=0 forces classic eth0 naming when PCI is enabled.
    let kernel_boot_args = format!(
        "console=ttyS0 reboot=k panic=1 net.ifnames=0 ip={guest}::{gateway}:255.255.255.252::eth0:off",
        guest = GUEST_IP,
        gateway = TAP_IP,
    );

    // Extract an FC-loadable ELF vmlinux if this kernel is a bzImage
    // (no-op for an already-ELF kernel). Same as the flake path below.
    let kernel_path =
        mvm_build::fc_kernel::ensure_fc_loadable_kernel(std::path::Path::new(&kernel_path))
            .with_context(|| format!("preparing FC-loadable kernel from {kernel_path}"))?;

    ui::info(&format!("Setting boot source: {}", state.kernel));
    api_put(
        "/boot-source",
        &format!(
            r#"{{"kernel_image_path": "{kernel}", "boot_args": "{args}"}}"#,
            kernel = kernel_path.display(),
            args = kernel_boot_args,
        ),
    )?;

    ui::info(&format!("Setting rootfs: {}", state.rootfs));
    api_put(
        "/drives/rootfs",
        &format!(
            r#"{{"drive_id": "rootfs", "path_on_host": "{rootfs}", "is_root_device": true, "is_read_only": false}}"#,
            rootfs = rootfs_path,
        ),
    )?;

    ui::info("Setting network interface...");
    api_put(
        "/network-interfaces/net1",
        &format!(
            r#"{{"iface_id": "net1", "guest_mac": "{mac}", "host_dev_name": "{tap}"}}"#,
            mac = FC_MAC,
            tap = TAP_DEV,
        ),
    )?;

    ui::info("Setting vsock device...");
    api_put(
        "/vsock",
        &format!(
            r#"{{"vsock_id": "vsock0", "guest_cid": {cid}, "uds_path": "{dir}/v.sock"}}"#,
            cid = mvm_guest::vsock::GUEST_CID,
            dir = abs_dir,
        ),
    )?;

    expose_vsock_runtime_symlink(abs_dir);

    Ok(())
}

/// Full start sequence: network, firecracker, configure, boot (headless).
///
/// MicroVMs never have SSH enabled. They run as headless workloads and
/// communicate via vsock. Use `mvmctl shell` to access the Lima VM environment.
#[instrument(skip_all)]
pub fn start() -> Result<()> {
    require_linux_env()?;

    // Check if already running
    if firecracker::is_running()? {
        ui::info("Firecracker is already running.");
        ui::info("Use 'mvmctl stop' to shut down, then 'mvmctl start' to restart.");
        return Ok(());
    }

    // Read state file for asset paths
    let state = read_state_or_discover()?;

    // Resolve ~/microvm to absolute path so it works in both user and sudo contexts
    let abs_dir = resolve_microvm_dir()?;

    // Set up networking
    network::setup()?;

    let _vm_span = tracing::info_span!("vm_start").entered();
    let vm_start = std::time::Instant::now();

    // Start Firecracker daemon
    start_firecracker_daemon(&abs_dir)?;
    let mut fc_guard = FirecrackerGuard::new(&abs_dir);

    // Configure microVM
    configure_microvm(&state, &abs_dir)?;

    // Start the instance
    ui::info("Starting microVM...");
    std::thread::sleep(std::time::Duration::from_millis(15));
    api_put("/actions", r#"{"action_type": "InstanceStart"}"#)?;

    mvm_core::observability::metrics::global()
        .vm_start_duration_ms
        .store(
            vm_start.elapsed().as_millis() as u64,
            std::sync::atomic::Ordering::Relaxed,
        );

    // Make vsock socket accessible to the current user
    if let Err(e) = run_in_vm(&format!("sudo chmod 0666 {}/v.sock 2>/dev/null", abs_dir)) {
        warn!("failed to chmod vsock socket: {e}");
    }

    // VM is fully started — defuse guard so normal stop path handles cleanup
    fc_guard.defuse();

    ui::banner(&[
        "MicroVM is running!",
        "",
        &format!("  Guest IP: {}", GUEST_IP),
        "",
        "Use 'mvmctl status' to check the microVM.",
        "Use 'mvmctl stop' to shut down the microVM.",
        "Use 'mvmctl shell' to access the Lima VM environment.",
    ]);

    Ok(())
}

/// Stop the microVM: kill Firecracker, clean up networking (legacy dev-mode).
#[instrument(skip_all)]
pub fn stop() -> Result<()> {
    require_linux_env()?;

    if !firecracker::is_running()? {
        ui::info("MicroVM is not running.");
        return Ok(());
    }

    ui::info("Stopping microVM...");

    // Try graceful shutdown via API
    if let Err(e) = run_in_vm(&format!(
        r#"sudo curl -s -X PUT --unix-socket {socket} \
            --data '{{"action_type": "SendCtrlAltDel"}}' \
            "http://localhost/actions" 2>/dev/null || true"#,
        socket = API_SOCKET,
    )) {
        warn!("failed to send graceful shutdown to VM: {e}");
    }

    // Give it a moment, then force kill
    std::thread::sleep(std::time::Duration::from_secs(2));

    run_in_vm(&format!(
        r#"
        if [ -f {dir}/.fc-pid ]; then
            sudo kill $(cat {dir}/.fc-pid) 2>/dev/null || true
            rm -f {dir}/.fc-pid
        fi
        sudo pkill -x firecracker 2>/dev/null || true
        sudo rm -f {socket}
        rm -f {dir}/.mvm-run-info
        rm -f {dir}/v.sock
        "#,
        dir = MICROVM_DIR,
        socket = API_SOCKET,
    ))?;

    // Tear down networking
    network::teardown()?;

    ui::success("MicroVM stopped.");
    Ok(())
}

/// Read the state file, or discover assets by listing files.
fn read_state_or_discover() -> Result<MvmState> {
    let json = run_in_vm_stdout(&format!(
        "cat {dir}/.mvm-state 2>/dev/null || echo 'null'",
        dir = MICROVM_DIR,
    ))?;

    if let Ok(state) = serde_json::from_str::<MvmState>(&json)
        && !state.kernel.is_empty()
        && !state.rootfs.is_empty()
        && !state.ssh_key.is_empty()
    {
        return Ok(state);
    }

    // Discover from files
    let kernel = run_in_vm_stdout(&format!(
        "cd {} && ls vmlinux-* 2>/dev/null | tail -1",
        MICROVM_DIR
    ))?;
    let rootfs = run_in_vm_stdout(&format!(
        "cd {} && ls *.ext4 2>/dev/null | tail -1",
        MICROVM_DIR
    ))?;
    let ssh_key = run_in_vm_stdout(&format!(
        "cd {} && ls *.id_rsa 2>/dev/null | tail -1",
        MICROVM_DIR
    ))?;

    if kernel.is_empty() || rootfs.is_empty() || ssh_key.is_empty() {
        anyhow::bail!(
            "Missing microVM assets in {}. Run 'mvmctl setup' first.\n  kernel={:?} rootfs={:?} ssh_key={:?}",
            MICROVM_DIR,
            kernel,
            rootfs,
            ssh_key,
        );
    }

    Ok(MvmState {
        kernel,
        rootfs,
        ssh_key,
        fc_pid: None,
    })
}

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
    /// Absolute path to the kernel image inside the Lima VM.
    pub vmlinux_path: String,
    /// Absolute path to the initial ramdisk (NixOS stage-1), if present.
    pub initrd_path: Option<String>,
    /// Absolute path to the root filesystem inside the Lima VM.
    pub rootfs_path: String,
    /// Absolute path to the dm-verity sidecar (Merkle hash tree) inside
    /// the Lima VM. Present when the flake was built with
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
/// Each VM gets its own directory under ~/microvm/vms/<name>/ with a
/// separate Firecracker socket, PID file, and log.  The bridge network
/// is shared, but each VM has its own TAP device and guest IP.
#[instrument(skip_all, fields(name = %config.name))]
pub fn run_from_build(config: &FlakeRunConfig) -> Result<()> {
    config.validate()?;
    require_linux_env()?;

    let slot = &config.slot;

    // Check if this VM name is already running
    let abs_dir = resolve_vm_dir(slot)?;
    let abs_socket = format!("{}/fc.socket", abs_dir);
    let pid_file = format!("{}/fc.pid", abs_dir);

    if firecracker::is_vm_running(&pid_file)? {
        ui::info(&format!("VM '{}' is already running.", slot.name));
        ui::info("Use 'mvmctl stop <name>' to shut it down first.");
        return Ok(());
    }

    // Provision the VM's bridge+TAP network + egress policy through the
    // NetworkProvider seam. `provision` is transactional
    // — it drops the TAP itself if the policy apply fails — and the TapGuard
    // below re-arms to tear the TAP down if a *later* start step fails. Same
    // operations, same order, as the direct calls this replaces.
    BridgeTapNetworkProvider::new()
        .provision(
            &mvm_core::protocol::vm_backend::VmId(slot.name.clone()),
            &NetworkSpec {
                policy: config.network_policy.clone(),
                slot_index: slot.index,
            },
        )
        .map_err(|e| anyhow::anyhow!("network provision: {e}"))?;
    let mut tap_guard = TapGuard::new(slot);

    // Spawn `mvm-firecracker-bridge` alongside the Firecracker VM.
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
    // No-op on non-Linux hosts (the bridge is Linux-only — see
    // `crates/mvm-firecracker-bridge/src/main.rs`).
    //
    // Opt-in via MVM_GATEWAY_BRIDGE=1, the same gate the libkrun/Vz
    // gateway-bridge factory sits behind: the FC bridge lane is not yet
    // working end-to-end (its confinement spec doesn't grant the
    // observer-allowlist path it reads post-confinement), and its
    // watchdog hard-fail policy would tear down an otherwise healthy
    // VM. Before the egress moat landed, no producer wrote `plan.json`
    // pre-boot on this path, so the bridge never actually spawned;
    // the gate preserves that default while the moat (substitution
    // endpoint + nft redirect below) runs unconditionally.
    #[cfg(target_os = "linux")]
    let mut bridge_guard = if std::env::var("MVM_GATEWAY_BRIDGE").as_deref() == Ok("1") {
        spawn_fc_bridge(&config.slot.name, &abs_dir)?
    } else {
        tracing::debug!(
            vm = %config.slot.name,
            "MVM_GATEWAY_BRIDGE not set; skipping mvm-firecracker-bridge sidecar"
        );
        AttachedBridgeGuard { child: None }
    };

    // Start Firecracker daemon in per-VM directory
    start_vm_firecracker(&abs_dir, &abs_socket)?;
    let mut fc_guard = FirecrackerGuard::new(&abs_dir);

    // Spawn the substitution endpoint BEFORE configuring boot args,
    // so the placeholders it mints land in
    // `vm_substitution_env_path` and `configure_flake_microvm` can carry them on
    // the cmdline (`mvm.secret_env=`) into a sealed entrypoint. The endpoint
    // binds its listener now; the nft REDIRECT that feeds it is installed
    // post-boot (the TAP must exist). The guard reaps the endpoint if any step
    // below fails before the VM is fully up. No-op without egress secrets.
    #[cfg(target_os = "linux")]
    let mut endpoint_guard = spawn_egress_endpoint(config)?;

    // Configure VM via Firecracker API
    configure_flake_microvm(config, &abs_dir, &abs_socket)?;

    // Boot the instance
    ui::info("Starting microVM...");
    std::thread::sleep(std::time::Duration::from_millis(15));
    api_put_socket(
        &abs_socket,
        "/actions",
        r#"{"action_type": "InstanceStart"}"#,
    )?;

    // Make vsock socket accessible to the current user
    if let Err(e) = run_in_vm(&format!("sudo chmod 0666 {}/v.sock 2>/dev/null", abs_dir)) {
        warn!("failed to chmod vsock socket: {e}");
    }

    // Persist run info for `mvm status`
    write_vm_run_info(config, &abs_dir)?;

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
    if let Err(e) = detach_and_spawn_bridge_watchdog(&config.slot.name, &abs_dir, &mut bridge_guard)
    {
        warn!(
            vm = %config.slot.name,
            "detach/watchdog setup for mvm-firecracker-bridge failed (non-fatal): {e}"
        );
    }

    // When the admitted plan carries secret bindings, stand up this
    // VM's transparent egress moat now that the guest is healthy:
    //   1. spawn the per-VM substitution endpoint with the terminator listener
    //      bound on a per-slot host port, and
    //   2. install the nft TAP prerouting REDIRECT that steers the guest's
    //      outbound :80 to that terminator.
    // Fail closed: a secret-bearing workload must not keep running without its
    // substitution path, so any failure rolls the VM back. Linux-only (nft +
    // the FC path itself). The plan source is the same `plan.json` the bridge
    // parsed; a missing/unsigned file means a legacy/non-admitted boot with no
    // secrets — nothing to install.
    #[cfg(target_os = "linux")]
    if let Err(e) = install_egress_redirect(config) {
        // Roll back the running VM + its network. The guards were about to be
        // defused; instead let them fire by returning before defuse — but the
        // bridge watchdog already detached, so tear down explicitly. `stop_vm`
        // reaps the substitution endpoint, so the (still-armed) endpoint_guard's
        // Drop is then a harmless no-op.
        warn!(vm = %config.slot.name, "egress redirect install failed; rolling back VM: {e}");
        let _ = stop_vm(&config.slot.name);
        return Err(e);
    }

    // VM is fully started — defuse guards so normal stop path handles cleanup
    fc_guard.defuse();
    tap_guard.defuse();
    #[cfg(target_os = "linux")]
    endpoint_guard.defuse();

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

/// Restore a Firecracker VM from a template snapshot (instant start).
///
/// Instead of cold-booting, this loads a pre-captured snapshot where the
/// VM was already healthy. Config and secrets drives are created fresh
/// with the caller's runtime files and must be placed at the paths the
/// snapshot expects (matching the temporary VM used during snapshot creation).
///
/// The VM configuration (vCPUs, memory, drive IDs, network) must match
/// what was used when the snapshot was created.
#[instrument(skip_all, fields(template_id, name = %config.name))]
pub fn restore_from_template_snapshot(
    template_id: &str,
    config: &FlakeRunConfig,
    snapshot_dir: &str,
    _snapshot_info: &mvm_core::template::SnapshotInfo,
) -> Result<()> {
    config.validate()?;
    require_linux_env()?;

    // Verify the integrity sidecar *before* doing anything else: a
    // tampered snapshot must not cause
    // bridge ensure / TAP create / Firecracker spawn — none of those
    // should happen if we're going to refuse the bytes anyway. A
    // missing sidecar is a non-fatal warning unless
    // `MVM_SNAPSHOT_HMAC_STRICT=1`.
    crate::base::snapshot_integrity::verify_snapshot_artifacts(snapshot_dir)?;

    let slot = &config.slot;

    // Check if this VM name is already running
    let abs_dir = resolve_vm_dir(slot)?;
    let abs_socket = format!("{}/fc.socket", abs_dir);
    let pid_file = format!("{}/fc.pid", abs_dir);

    if firecracker::is_vm_running(&pid_file)? {
        ui::info(&format!("VM '{}' is already running.", slot.name));
        ui::info("Use 'mvmctl stop <name>' to shut it down first.");
        return Ok(());
    }

    // Provision the VM's bridge+TAP network + egress policy through the
    // NetworkProvider seam. `provision` is transactional
    // — it drops the TAP itself if the policy apply fails — and the TapGuard
    // below re-arms to tear the TAP down if a *later* start step fails. Same
    // operations, same order, as the direct calls this replaces.
    BridgeTapNetworkProvider::new()
        .provision(
            &mvm_core::protocol::vm_backend::VmId(slot.name.clone()),
            &NetworkSpec {
                policy: config.network_policy.clone(),
                slot_index: slot.index,
            },
        )
        .map_err(|e| anyhow::anyhow!("network provision: {e}"))?;
    let mut tap_guard = TapGuard::new(slot);

    // Copy snapshot files to per-VM directory
    run_in_vm(&format!(
        "mkdir -p {dir} && cp {snap}/vmstate.bin {dir}/vmstate.bin && cp {snap}/mem.bin {dir}/mem.bin",
        snap = snapshot_dir,
        dir = abs_dir,
    ))?;

    // Create config and secrets drives in the new VM directory with fresh runtime data
    ui::info("Creating config drive...");
    let config_drive = create_dev_config_drive(&abs_dir, config)?;
    ui::info("Creating secrets drive...");
    let secrets_drive = create_dev_secrets_drive(&abs_dir, &config.secret_files)?;

    // The snapshot expects drives at the template runtime directory.
    // Create per-instance symlinks from template runtime paths to the instance drives.
    // This allows multiple concurrent instances from the same template, each with
    // their own config/secrets, while the snapshot finds drives at expected paths.
    //
    // Use flock to serialize symlink creation + snapshot load to prevent race conditions
    // when multiple instances start simultaneously.
    let template_runtime_dir = format!(
        "{}/templates/{}/runtime",
        mvm_core::config::mvm_data_dir(),
        template_id
    );
    let lock_file = format!("{}.lock", template_runtime_dir);

    // Start Firecracker daemon in per-VM directory (before acquiring lock)
    start_vm_firecracker(&abs_dir, &abs_socket)?;
    let mut fc_guard = FirecrackerGuard::new(&abs_dir);

    // Atomic operation: create symlinks + load snapshot (serialized by flock)
    ui::info("Loading snapshot...");
    let vmstate_path = format!("{}/vmstate.bin", abs_dir);
    let mem_path = format!("{}/mem.bin", abs_dir);
    run_in_vm(&format!(
        r#"
        # Create lock directory
        mkdir -p {runtime_dir}

        # Use flock to serialize symlink creation and snapshot load
        (
            flock -x 200 || exit 1

            # Remove old symlinks (from previous instance that finished loading)
            rm -f {runtime_dir}/config.ext4 {runtime_dir}/secrets.ext4 {runtime_dir}/v.sock

            # Create symlinks to this instance's drives and vsock socket location
            ln -s {config} {runtime_dir}/config.ext4
            ln -s {secrets} {runtime_dir}/secrets.ext4
            ln -s {abs_dir}/v.sock {runtime_dir}/v.sock

            # Load snapshot (Firecracker opens the drives via symlinks)
            response=$(sudo curl -s -w "\n%{{http_code}}" --unix-socket {socket} -X PUT \
                -H 'Content-Type: application/json' \
                -d '{{"snapshot_path": "{vmstate}", "mem_backend": {{"backend_type": "File", "backend_path": "{mem}"}}, "enable_diff_snapshots": false}}' \
                'http://localhost/snapshot/load')
            code=$(echo "$response" | tail -1)
            body=$(echo "$response" | sed '$d')
            if [ "$code" -ge 400 ]; then
                echo "[mvm] ERROR: PUT /snapshot/load returned $code: $body" >&2
                exit 1
            fi
        ) 200>{lock_file}
        "#,
        runtime_dir = template_runtime_dir,
        lock_file = lock_file,
        config = config_drive,
        secrets = secrets_drive,
        socket = abs_socket,
        vmstate = vmstate_path,
        mem = mem_path,
    ))?;

    // Resume vCPUs
    ui::info("Resuming VM from snapshot...");
    api_patch_socket(&abs_socket, "/vm", r#"{"state": "Resumed"}"#)?;

    // Make vsock socket accessible
    if let Err(e) = run_in_vm(&format!("sudo chmod 0666 {}/v.sock 2>/dev/null", abs_dir)) {
        warn!("failed to chmod vsock socket: {e}");
    }

    // Post-restore: remount drives and restart services with fresh config/secrets.
    if !config.config_files.is_empty() || !config.secret_files.is_empty() {
        let vsock_path = format!("{}/v.sock", abs_dir);
        ui::info("Sending post-restore signal (remounting drives, restarting services)...");
        // Wait for guest agent to be reachable after resume (may take a moment).
        let mut agent_ready = false;
        for attempt in 0..30 {
            if mvm_guest::vsock::ping_at(&vsock_path).unwrap_or(false) {
                agent_ready = true;
                break;
            }
            if attempt == 29 {
                ui::warn(
                    "Guest agent not reachable after resume. Config/secrets may not be loaded.",
                );
            }
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
        if agent_ready {
            match mvm_guest::vsock::post_restore_at(&vsock_path) {
                Ok(true) => ui::info("Post-restore complete."),
                Ok(false) => ui::warn("Post-restore signal returned failure."),
                Err(e) => ui::warn(&format!(
                    "Post-restore failed: {}. Services may need manual restart.",
                    e
                )),
            }
        }
    }

    // Persist run info
    write_vm_run_info(config, &abs_dir)?;

    // VM is fully restored — defuse guards so normal stop path handles cleanup
    fc_guard.defuse();
    tap_guard.defuse();

    ui::banner(&[
        &format!("MicroVM '{}' restored from snapshot!", config.name),
        "",
        &format!("  Guest IP: {}", slot.guest_ip),
        &format!("  Revision: {}", config.revision_hash),
        "",
        &format!("Use 'mvmctl stop {}' to shut down this VM.", config.name),
        "Use 'mvmctl status' to list all running VMs.",
    ]);

    Ok(())
}

/// Pause the vCPUs of a running Firecracker VM.
///
/// Sends `PATCH /vm` with `{"state":"Paused"}` to the per-VM control
/// socket. The VMM stays alive; vCPUs stop scheduling. Used by mvmd's
/// sleep path (snapshot-on-sleep, restore-on-wake).
///
/// Errors loudly if the VM is not running rather than silently treating
/// it as a no-op — a stale `pause` against a vanished VM should surface
/// the inconsistency, not be swallowed.
#[instrument(skip_all, fields(name))]
pub fn pause_vm(name: &str) -> Result<()> {
    require_linux_env()?;

    let abs_vms = run_in_vm_stdout(&format!("echo {}", VMS_DIR))?;
    let abs_dir = format!("{}/{}", abs_vms.trim(), name);
    let pid_file = format!("{}/fc.pid", abs_dir);
    let socket = format!("{}/fc.socket", abs_dir);

    if !firecracker::is_vm_running(&pid_file)? {
        anyhow::bail!("VM '{}' is not running", name);
    }

    let q_socket = shell_quote(&socket);
    run_in_vm(&format!(
        r#"sudo curl -fsS -X PATCH --unix-socket {q_socket} \
            -H 'Content-Type: application/json' \
            -d '{{"state":"Paused"}}' \
            'http://localhost/vm'"#,
    ))
    .with_context(|| format!("PATCH /vm Paused for VM '{}'", name))?;
    Ok(())
}

/// Resume vCPUs of a paused Firecracker VM.
///
/// Counterpart to [`pause_vm`]. Sends `PATCH /vm` with
/// `{"state":"Resumed"}` to the per-VM control socket.
#[instrument(skip_all, fields(name))]
pub fn resume_vm(name: &str) -> Result<()> {
    require_linux_env()?;

    let abs_vms = run_in_vm_stdout(&format!("echo {}", VMS_DIR))?;
    let abs_dir = format!("{}/{}", abs_vms.trim(), name);
    let pid_file = format!("{}/fc.pid", abs_dir);
    let socket = format!("{}/fc.socket", abs_dir);

    if !firecracker::is_vm_running(&pid_file)? {
        anyhow::bail!("VM '{}' is not running", name);
    }

    let q_socket = shell_quote(&socket);
    run_in_vm(&format!(
        r#"sudo curl -fsS -X PATCH --unix-socket {q_socket} \
            -H 'Content-Type: application/json' \
            -d '{{"state":"Resumed"}}' \
            'http://localhost/vm'"#,
    ))
    .with_context(|| format!("PATCH /vm Resumed for VM '{}'", name))?;
    Ok(())
}

/// Stop a specific named VM.
#[instrument(skip_all, fields(name))]
/// Adjust the virtio-balloon inflation target for a running FC VM.
///
/// `target_inflate_mib` is the amount the balloon should claim back
/// from the guest. The guest's effective commitment is `memory -
/// target_inflate_mib`. Firecracker expresses this through its
/// `PATCH /balloon` endpoint with `amount_mib`.
///
/// Returns an error if the VM was started without
/// `mem_initial.is_some()` — no balloon device exists to PATCH.
/// Firecracker surfaces this as HTTP 400 with a clear message.
pub fn balloon_set_target(name: &str, target_inflate_mib: u32) -> Result<()> {
    require_linux_env()?;

    let abs_vms = run_in_vm_stdout(&format!("echo {}", VMS_DIR))?;
    let abs_dir = format!("{}/{}", abs_vms.trim(), name);
    let pid_file = format!("{}/fc.pid", abs_dir);
    let socket = format!("{}/fc.socket", abs_dir);

    if !firecracker::is_vm_running(&pid_file)? {
        anyhow::bail!("VM '{}' is not running", name);
    }

    let q_socket = shell_quote(&socket);
    run_in_vm(&format!(
        r#"sudo curl -fsS -X PATCH --unix-socket {q_socket} \
            -H 'Content-Type: application/json' \
            -d '{{"amount_mib":{target}}}' \
            'http://localhost/balloon'"#,
        target = target_inflate_mib,
    ))
    .with_context(|| {
        format!(
            "PATCH /balloon (amount_mib={target_inflate_mib}) for VM '{name}'; \
             VM may have been launched without `mem_initial` (no balloon device)"
        )
    })?;
    Ok(())
}

/// Read the current balloon state of a running FC VM.
///
/// Returns the inflation amount in MiB. `0` means the balloon is
/// fully deflated (guest has all of `memory`). Combined with the
/// VM's declared `memory` cap (e.g. from `list_vms()`), the host
/// reclaim controller derives the effective commitment.
pub fn balloon_state(name: &str) -> Result<u32> {
    require_linux_env()?;

    let abs_vms = run_in_vm_stdout(&format!("echo {}", VMS_DIR))?;
    let abs_dir = format!("{}/{}", abs_vms.trim(), name);
    let pid_file = format!("{}/fc.pid", abs_dir);
    let socket = format!("{}/fc.socket", abs_dir);

    if !firecracker::is_vm_running(&pid_file)? {
        anyhow::bail!("VM '{}' is not running", name);
    }

    let q_socket = shell_quote(&socket);
    let body = run_in_vm_stdout(&format!(
        r#"sudo curl -fsS --unix-socket {q_socket} 'http://localhost/balloon'"#,
    ))
    .with_context(|| format!("GET /balloon for VM '{name}'"))?;

    let parsed: serde_json::Value = serde_json::from_str(body.trim())
        .with_context(|| format!("parse /balloon response: {body:?}"))?;
    let amount = parsed
        .get("amount_mib")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| anyhow::anyhow!("/balloon response missing amount_mib: {body}"))?;
    Ok(amount as u32)
}

pub fn stop_vm(name: &str) -> Result<()> {
    require_linux_env()?;

    let abs_vms = run_in_vm_stdout(&format!("echo {}", VMS_DIR))?;
    let abs_dir = format!("{}/{}", abs_vms, name);
    let pid_file = format!("{}/fc.pid", abs_dir);
    let socket = format!("{}/fc.socket", abs_dir);

    // Tear down this VM's egress substitution moat BEFORE the
    // not-running early return. The endpoint is a live host process holding the
    // workload's DECRYPTED secrets and the nft REDIRECT table outlives the guest;
    // if an FC VM crashes/OOMs on its own, a later `stop_vm` must still reap the
    // moat — decrypted secrets must not outlive the guest, even on a crash. Both
    // are best-effort + idempotent (no-op when the VM carried no secrets). The
    // substitution sidecars live under `vm_state_dir(name)`, NOT the VMS_DIR
    // `abs_dir`. Mirrors qemu.rs ordering (reap-before-not-running-return).
    crate::substitution_spawn::reap_substitution_endpoint(
        &mvm_core::config::vm_state_dir(name),
        name,
    );
    #[cfg(target_os = "linux")]
    if let Err(e) = crate::egress_redirect::teardown_by_name(name) {
        warn!(vm = %name, "remove egress redirect table: {e}");
    }

    if !firecracker::is_vm_running(&pid_file)? {
        ui::info(&format!("VM '{}' is not running.", name));
        return Ok(());
    }

    ui::info(&format!("Stopping VM '{}'...", name));

    // Ask the guest to power down via ACPI (SendCtrlAltDel), then poll for a
    // clean exit on a tight cadence. A headless workload guest has no
    // power-button handler, so the former unconditional 2s sleep-then-kill made
    // every `down` cost two seconds for nothing — escalate to a hard kill the
    // moment the short graceful window lapses instead of always waiting it out.
    if let Err(e) = run_in_vm(&format!(
        r#"sudo curl -s -X PUT --unix-socket {socket} \
            --data '{{"action_type": "SendCtrlAltDel"}}' \
            "http://localhost/actions" 2>/dev/null || true"#,
        socket = socket,
    )) {
        warn!("failed to send graceful shutdown to VM: {e}");
    }

    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(250);
    let mut exited_gracefully = false;
    while std::time::Instant::now() < deadline {
        if !firecracker::is_vm_running(&pid_file)? {
            exited_gracefully = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }

    // Clean up the API socket either way; only fall back to a hard kill when
    // the guest ignored the ACPI request within the graceful window.
    if exited_gracefully {
        run_in_vm(&format!("sudo rm -f {socket}", socket = socket))?;
    } else {
        run_in_vm(&format!(
            r#"
            if [ -f {pid} ]; then
                sudo kill $(cat {pid}) 2>/dev/null || true
            fi
            sudo rm -f {socket}
            "#,
            pid = pid_file,
            socket = socket,
        ))?;
    }

    // Read run info to find the TAP device to destroy
    if let Some(info) = read_vm_run_info_from(&abs_dir)
        && let Some(ref vm_name) = info.name
    {
        // Reconstruct slot to find TAP name — scan for the index
        if let Some(idx) = read_slot_index(&abs_dir) {
            // Tear down through the NetworkProvider seam:
            // best-effort drain of the iptables policy + TAP, symmetric with
            // the provision path.
            let handle = NetHandle {
                vm: mvm_core::protocol::vm_backend::VmId(vm_name.clone()),
                tag: idx.to_string(),
            };
            if let Err(e) = BridgeTapNetworkProvider::new().teardown(handle) {
                warn!("network teardown: {e}");
            }
        }
    }

    // Remove the VM directory
    if let Err(e) = run_in_vm(&format!("rm -rf {}", abs_dir)) {
        warn!("failed to remove VM directory: {e}");
    }

    ui::success(&format!("VM '{}' stopped.", name));
    Ok(())
}

/// Stop all running VMs.
#[instrument(skip_all)]
pub fn stop_all_vms() -> Result<()> {
    require_linux_env()?;

    let vms = list_vms()?;
    if vms.is_empty() {
        ui::info("No VMs are running.");
        return Ok(());
    }

    for info in &vms {
        if let Some(ref name) = info.name {
            stop_vm(name)?;
        }
    }

    // Clean up bridge if no VMs left
    let remaining = list_vms()?;
    if remaining.is_empty() {
        network::bridge_teardown()?;
    }

    Ok(())
}

/// Show logs from a named VM.
///
/// By default shows the guest serial console (`console.log`).
/// With `hypervisor=true`, shows Firecracker hypervisor logs (`firecracker.log`).
pub fn logs(name: &str, follow: bool, lines: u32, hypervisor: bool) -> Result<()> {
    require_linux_env()?;

    let abs_vms = run_in_vm_stdout(&format!("echo {}", VMS_DIR))?;
    let filename = if hypervisor {
        "firecracker.log"
    } else {
        "console.log"
    };
    let log_file = format!("{}/{}/{}", abs_vms, name, filename);

    // Check the log file exists; fall back to firecracker.log for VMs started before
    // the console.log split.
    let exists = run_in_vm_stdout(&format!("[ -f {} ] && echo yes || echo no", log_file))?;
    if exists.trim() != "yes" {
        if !hypervisor {
            // Try legacy location (pre-split VMs wrote everything to firecracker.log)
            let fallback = format!("{}/{}/firecracker.log", abs_vms, name);
            let fb_exists =
                run_in_vm_stdout(&format!("[ -f {} ] && echo yes || echo no", fallback))?;
            if fb_exists.trim() == "yes" {
                ui::warn(
                    "console.log not found; showing firecracker.log (VM started before log split)",
                );
                return show_log_file(&fallback, follow, lines);
            }
        }
        anyhow::bail!("No logs found for VM '{}' (is the name correct?)", name);
    }

    show_log_file(&log_file, follow, lines)
}

fn show_log_file(log_file: &str, follow: bool, lines: u32) -> Result<()> {
    if follow {
        run_in_vm_visible(&format!("tail -f {}", log_file))?;
    } else {
        let output = run_in_vm_stdout(&format!("tail -n {} {}", lines, log_file))?;
        print!("{}", output);
    }
    Ok(())
}

// ============================================================================
// VM diagnostics
// ============================================================================

/// Result of layered VM diagnostics. Each field represents one diagnostic
/// check that works independently of vsock connectivity.
#[derive(Debug, serde::Serialize)]
pub struct DiagnoseResult {
    pub fc_alive: bool,
    pub fc_pid: Option<u32>,
    pub fc_api_responsive: bool,
    pub fc_machine_config: Option<serde_json::Value>,
    pub vsock_exists: bool,
    pub console_warnings: Vec<String>,
    pub fc_log_errors: Vec<String>,
    pub agent_reachable: bool,
    pub agent_error: Option<String>,
    pub worker_status: Option<String>,
    pub last_busy_at: Option<String>,
    pub probe_results: Vec<mvm_guest::probes::ProbeResult>,
    pub integration_results: Vec<mvm_guest::integrations::IntegrationStateReport>,
    pub suggestions: Vec<String>,
}

/// Known-bad patterns in console log output.
const CONSOLE_WARNING_PATTERNS: &[&str] = &[
    "Kernel panic",
    "Out of memory",
    "Killed process",
    "BUG:",
    "Call Trace:",
    "oom-kill:",
    "invoked oom-killer",
];

/// Run layered diagnostics on a named VM.
///
/// Checks each layer independently so that useful information is returned
/// even when vsock is broken (e.g. guest agent crashed, OOM, kernel panic).
#[instrument(skip_all, fields(name))]
pub fn diagnose_vm(name: &str) -> Result<DiagnoseResult> {
    require_linux_env()?;

    let abs_vms = run_in_vm_stdout(&format!("echo {}", VMS_DIR))?;
    let abs_dir = format!("{}/{}", abs_vms, name);

    // Check VM directory exists
    let dir_exists = run_in_vm_stdout(&format!("[ -d '{}' ] && echo yes || echo no", abs_dir))?;
    if dir_exists.trim() != "yes" {
        anyhow::bail!(
            "VM directory not found: {}. The VM '{}' may not exist.",
            abs_dir,
            name
        );
    }

    let mut result = DiagnoseResult {
        fc_alive: false,
        fc_pid: None,
        fc_api_responsive: false,
        fc_machine_config: None,
        vsock_exists: false,
        console_warnings: Vec::new(),
        fc_log_errors: Vec::new(),
        agent_reachable: false,
        agent_error: None,
        worker_status: None,
        last_busy_at: None,
        probe_results: Vec::new(),
        integration_results: Vec::new(),
        suggestions: Vec::new(),
    };

    // Layer 1: FC process alive?
    let pid_check = run_in_vm_stdout(&format!(
        r#"if [ -f '{dir}/fc.pid' ]; then
            pid=$(cat '{dir}/fc.pid')
            if [ -f "/proc/$pid/comm" ] && [ "$(cat /proc/$pid/comm)" = "firecracker" ]; then
                echo "alive:$pid"
            else
                echo "dead:$pid"
            fi
        else
            echo "nopid"
        fi"#,
        dir = abs_dir,
    ))?;
    let pid_check = pid_check.trim();
    if let Some(pid_str) = pid_check.strip_prefix("alive:") {
        result.fc_alive = true;
        result.fc_pid = pid_str
            .parse()
            .map_err(|e| warn!("failed to parse firecracker PID '{}': {}", pid_str, e))
            .ok();
    } else if let Some(pid_str) = pid_check.strip_prefix("dead:") {
        result.fc_pid = pid_str
            .parse()
            .map_err(|e| warn!("failed to parse firecracker PID '{}': {}", pid_str, e))
            .ok();
        result.suggestions.push(format!(
            "Firecracker process (pid {}) is dead. Run: mvmctl stop {}",
            pid_str, name,
        ));
    } else {
        result
            .suggestions
            .push(format!("No fc.pid file found. Run: mvmctl stop {}", name));
    }

    // Layer 2: FC API responsive?
    if result.fc_alive {
        let api_output = run_in_vm_stdout(&format!(
            "sudo curl -sf --unix-socket '{dir}/fc.socket' 'http://localhost/machine-config' 2>/dev/null || echo FAIL",
            dir = abs_dir,
        ))?;
        let api_output = api_output.trim();
        if api_output != "FAIL" {
            result.fc_api_responsive = true;
            result.fc_machine_config = serde_json::from_str(api_output)
                .map_err(|e| warn!("failed to parse FC machine config: {}", e))
                .ok();
        }
    }

    // Layer 3: Vsock socket exists?
    let sock_check = run_in_vm_stdout(&format!(
        "[ -S '{dir}/v.sock' ] && echo yes || echo no",
        dir = abs_dir,
    ))?;
    result.vsock_exists = sock_check.trim() == "yes";
    if !result.vsock_exists && result.fc_alive {
        result.suggestions.push(
            "Vsock socket missing despite FC running — vsock device may not be configured.".into(),
        );
    }

    // Layer 4: Console log warnings
    let console_tail = run_in_vm_stdout(&format!(
        "tail -n 200 '{dir}/console.log' 2>/dev/null || true",
        dir = abs_dir,
    ))?;
    for line in console_tail.lines() {
        for pattern in CONSOLE_WARNING_PATTERNS {
            if line.contains(pattern) {
                result.console_warnings.push(line.trim().to_string());
                break;
            }
        }
    }
    if !result.console_warnings.is_empty() {
        result.suggestions.push(format!(
            "Console log contains warnings. Run: mvmctl logs {} -n 200",
            name,
        ));
    }

    // Layer 5: FC log errors
    let fc_log_tail = run_in_vm_stdout(&format!(
        "tail -n 100 '{dir}/firecracker.log' 2>/dev/null || true",
        dir = abs_dir,
    ))?;
    for line in fc_log_tail.lines() {
        if line.contains("ERROR") {
            result.fc_log_errors.push(line.trim().to_string());
        }
    }

    // Layer 6: Guest agent reachable? (short timeout)
    if result.vsock_exists {
        let vsock_path = format!("{}/v.sock", abs_dir);
        match mvm_guest::vsock::ping_at(&vsock_path) {
            Ok(true) => {
                result.agent_reachable = true;
            }
            Ok(false) => {
                result.agent_error = Some("Ping returned false".into());
                result
                    .suggestions
                    .push("Guest agent not responding to ping.".into());
            }
            Err(e) => {
                result.agent_error = Some(e.to_string());
                if !result.fc_alive {
                    result
                        .suggestions
                        .push("Firecracker process is dead — guest agent cannot respond.".into());
                } else {
                    result.suggestions.push(
                        "Guest agent unreachable. Check if mvm-guest-agent service is running inside the guest.".into(),
                    );
                }
            }
        }
    }

    // Layer 7: If agent reachable, get detailed status
    if result.agent_reachable {
        let vsock_path = format!("{}/v.sock", abs_dir);
        if let Ok(mvm_guest::vsock::GuestResponse::WorkerStatus {
            status,
            last_busy_at,
        }) = mvm_guest::vsock::query_worker_status_at(&vsock_path)
        {
            result.worker_status = Some(status);
            result.last_busy_at = last_busy_at;
        }
        result.integration_results =
            mvm_guest::vsock::query_integration_status_at(&vsock_path).unwrap_or_default();
        result.probe_results =
            mvm_guest::vsock::query_probe_status_at(&vsock_path).unwrap_or_default();

        // Check for failing health checks
        let failing: Vec<&str> = result
            .integration_results
            .iter()
            .filter(|ig| !ig.health.as_ref().is_some_and(|h| h.healthy))
            .map(|ig| ig.name.as_str())
            .chain(
                result
                    .probe_results
                    .iter()
                    .filter(|p| !p.healthy)
                    .map(|p| p.name.as_str()),
            )
            .collect();
        if !failing.is_empty() {
            result.suggestions.push(format!(
                "Failing health checks: {}. Run: mvmctl vm inspect {}",
                failing.join(", "),
                name,
            ));
        }
    }

    Ok(result)
}

/// List all running VMs by scanning ~/microvm/vms/*/run-info.json.
#[instrument(skip_all)]
pub fn list_vms() -> Result<Vec<RunInfo>> {
    let output = run_in_vm_stdout(&format!(
        "for f in {dir}/*/run-info.json; do [ -f \"$f\" ] && cat \"$f\"; done 2>/dev/null || true",
        dir = VMS_DIR,
    ))?;

    let mut vms = Vec::new();
    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Ok(info) = serde_json::from_str::<RunInfo>(line) {
            // Verify the VM is actually running
            if let Some(ref name) = info.name {
                let abs_vms = run_in_vm_stdout(&format!("echo {}", VMS_DIR))?;
                let pid_file = format!("{}/{}/fc.pid", abs_vms, name);
                if firecracker::is_vm_running(&pid_file).unwrap_or(false) {
                    vms.push(info);
                }
            }
        }
    }

    Ok(vms)
}

/// Allocate the next free slot index by scanning existing VMs.
pub fn allocate_slot(name: &str) -> Result<VmSlot> {
    let output = run_in_vm_stdout(&format!(
        r#"for f in {dir}/*/run-info.json; do [ -f "$f" ] && cat "$f"; done 2>/dev/null || true"#,
        dir = VMS_DIR,
    ))?;

    let mut used_indices: Vec<u8> = Vec::new();
    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Ok(info) = serde_json::from_str::<serde_json::Value>(line)
            && let Some(idx) = info.get("slot_index").and_then(|v| v.as_u64())
        {
            used_indices.push(idx as u8);
        }
    }

    // Find first free index (0..253, since IP = index + 2, max 255)
    for i in 0..253u8 {
        if !used_indices.contains(&i) {
            return Ok(VmSlot::new(name, i));
        }
    }

    anyhow::bail!("No free VM slots available (max 253 VMs)")
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
        cmds.push_str(&format!(
            "echo '{content}' | sudo tee \"$MOUNT_DIR/{name}\" >/dev/null\nsudo chmod {mode} \"$MOUNT_DIR/{name}\"\n",
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

    run_in_vm(&format!(
        r#"
        rm -f {path}
        truncate -s 4M {path}
        mkfs.ext4 -q -L mvm-config {path}

        MOUNT_DIR=$(mktemp -d)
        sudo mount {path} "$MOUNT_DIR"
        echo '{json}' | sudo tee "$MOUNT_DIR/config.json" >/dev/null
        echo '{toml}' | sudo tee "$MOUNT_DIR/{toml_name}" >/dev/null
        sudo chmod 0444 "$MOUNT_DIR/config.json" "$MOUNT_DIR/{toml_name}"
        {extra}
        sudo umount "$MOUNT_DIR"
        rmdir "$MOUNT_DIR"
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

    run_in_vm(&format!(
        r#"
        rm -f {path}
        truncate -s 4M {path}
        mkfs.ext4 -q -L mvm-secrets {path}

        MOUNT_DIR=$(mktemp -d)
        sudo mount {path} "$MOUNT_DIR"
        echo '{{}}' | sudo tee "$MOUNT_DIR/secrets.json" >/dev/null
        sudo chmod 0400 "$MOUNT_DIR/secrets.json"
        {extra}
        sudo umount "$MOUNT_DIR"
        rmdir "$MOUNT_DIR"
        chmod 0600 {path}
        "#,
        path = path,
        extra = extra_cmds,
    ))?;
    Ok(path)
}

/// Probe the directory containing `rootfs_path` (inside the Lima VM)
/// for the dm-verity sidecar files emitted by mkGuest when
/// `verifiedBoot = true`. Returns `(Some(verity_path), Some(roothash))`
/// when both files are present and the roothash decodes to a 64-char
/// hex string; otherwise `(None, None)` so callers fall back to the
/// unverified-boot path.
pub fn probe_verity_sidecar(rootfs_path: &str) -> (Option<String>, Option<String>) {
    use crate::base::shell::{run_in_vm, run_in_vm_stdout};
    use std::path::Path;

    let Some(parent) = Path::new(rootfs_path).parent() else {
        return (None, None);
    };
    let parent = parent.to_string_lossy();
    let verity = format!("{parent}/rootfs.verity");
    let roothash_file = format!("{parent}/rootfs.roothash");

    if run_in_vm(&format!("[ -f {verity} ]")).is_err() {
        return (None, None);
    }
    let Ok(raw) = run_in_vm_stdout(&format!("cat {roothash_file}")) else {
        return (None, None);
    };
    let hash = raw.trim().to_string();
    if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return (None, None);
    }
    (Some(verity), Some(hash))
}

/// Build the cmdline fragment consumed by `mvm-verity-init`
/// (the PID 1 in the verity initramfs). Pure function for unit
/// testing — `None` is returned when verity is disabled (no
/// `roothash`). When the three runtime-overlay fields are also
/// present, the fragment includes the `mvm.runtime_*` knobs the
/// init binary reads to set up the second dm-verity target and
/// bind-mount it at `/sysroot/mvm/runtime`.
pub fn build_verity_cmdline_args(
    roothash: Option<&str>,
    overlay_roothash: Option<&str>,
) -> Option<String> {
    let h = roothash?;
    let base = format!("mvm.roothash={h} mvm.data=/dev/vda mvm.hash=/dev/vdb");
    match overlay_roothash {
        Some(oh) => Some(format!(
            "{base} mvm.runtime_roothash={oh} mvm.runtime_data=/dev/vdc mvm.runtime_hash=/dev/vdd"
        )),
        None => Some(base),
    }
}

/// Resolve whether the runtime-overlay drives should be attached
/// alongside the rootfs verity sidecar. Returns the
/// `(overlay_ext4_path, overlay_verity_sidecar_path,
/// overlay_roothash)` triple only when all three are present —
/// any missing field disables the overlay attachment so a
/// half-configured workload boots through the legacy
/// rootfs-verity-only path instead of failing with a partial
/// drive map.
pub fn resolved_runtime_overlay(config: &FlakeRunConfig) -> Option<(&str, &str, &str)> {
    Some((
        config.runtime_overlay_path.as_deref()?,
        config.runtime_overlay_verity_path.as_deref()?,
        config.runtime_overlay_roothash.as_deref()?,
    ))
}

/// Configure a flake-built microVM via the Firecracker API (multi-VM).
#[instrument(skip_all, fields(name = %config.name))]
pub fn configure_flake_microvm(config: &FlakeRunConfig, abs_dir: &str, socket: &str) -> Result<()> {
    configure_flake_microvm_with_drives_dir(config, abs_dir, socket, abs_dir)
}

/// Configure a flake-built microVM with custom config/secrets drive location.
/// This allows template snapshots to use template-relative drive paths.
/// The vsock socket is also placed in drives_dir for snapshot portability.
#[instrument(skip_all, fields(name = %config.name))]
pub fn configure_flake_microvm_with_drives_dir(
    config: &FlakeRunConfig,
    abs_dir: &str,
    socket: &str,
    drives_dir: &str,
) -> Result<()> {
    let slot = &config.slot;

    ui::info("Configuring logger...");
    api_put_socket(
        socket,
        "/logger",
        &format!(
            r#"{{"log_path": "{dir}/firecracker.log", "level": "Debug", "show_level": true, "show_log_origin": true}}"#,
            dir = abs_dir,
        ),
    )?;

    // Boot args: pass guest IP and gateway via kernel cmdline.
    // When initrd is present (NixOS guest or verity initrd), the initrd
    // handles root mounting. When absent (minimal guest, no verity),
    // the kernel mounts /dev/vda directly.
    let base_args = format!(
        "console=ttyS0 reboot=k panic=1 net.ifnames=0 mvm.ip={ip}/24 mvm.gw={gw}",
        ip = slot.guest_ip,
        gw = BRIDGE_IP,
    );

    // dm-verity boot path: when verity is on, the kernel
    // mounts the verity initramfs first, which is `mvm-verity-init`
    // (PID 1) — that binary reads `mvm.roothash=…` from the cmdline,
    // builds the verity device-mapper target via raw ioctls, mounts
    // /dev/mapper/root, and switch_root's to /sysroot/init.
    //
    // We deliberately do NOT add `root=/dev/dm-0` here: Firecracker on
    // aarch64 unconditionally appends `root=/dev/vda ro` after our
    // boot_args, and the kernel uses last-wins for `root=`. By owning
    // the pivot in userspace via the initramfs, the kernel's `root=`
    // setting becomes irrelevant — `mvm-verity-init` chooses the real
    // root explicitly via `mount` + `switch_root`.
    let verity_initrd_path = config
        .verity_path
        .as_deref()
        .zip(config.roothash.as_deref())
        .and_then(|_| {
            // Convention from `nix/flake.nix`: the verity initrd lives
            // at `<rev_dir>/rootfs.initrd`, alongside `rootfs.{ext4,
            // verity,roothash}`. Fall back to `None` if the file isn't
            // present (older templates that pre-date the initrd path).
            std::path::Path::new(&config.rootfs_path)
                .parent()
                .map(|p| format!("{}/rootfs.initrd", p.display()))
        })
        .filter(|p| std::path::Path::new(p).exists());
    // The runtime overlay only has a consumer when verity is on —
    // `mvm-verity-init` is the PID 1 that reads
    // `mvm.runtime_roothash=` and bind-mounts the overlay at
    // `/sysroot/mvm/runtime`. Outside the verity boot path there's
    // no init to mount the drives, so we'd just be reserving virtio
    // slots for nothing. Drop the overlay silently when verity is
    // off rather than failing the boot — the caller didn't ask for
    // verity, so the overlay is moot.
    let overlay = if config.roothash.is_some() {
        resolved_runtime_overlay(config)
    } else {
        None
    };
    let verity_args: Option<String> =
        build_verity_cmdline_args(config.roothash.as_deref(), overlay.map(|(_, _, h)| h));

    // Pick the initrd to attach: caller-supplied (NixOS stage-1) wins
    // over the verity initrd. They can't both be present in practice —
    // the production minimal-init path doesn't use a NixOS stage-1 —
    // but the precedence is documented for future contributors.
    let effective_initrd = config
        .initrd_path
        .clone()
        .or_else(|| verity_initrd_path.clone());

    let boot_args = if effective_initrd.is_some() {
        // initrd owns root mounting. Verity adds the cmdline knobs the
        // initramfs reads to construct /dev/mapper/root.
        match &verity_args {
            Some(extra) => format!("{base_args} {extra}"),
            None => base_args,
        }
    } else {
        format!("root=/dev/vda rw rootwait init=/init {base_args}")
    };

    // A fresh FC boot attaches no secrets drive, so the per-VM
    // egress intermediate cert reaches the sealed guest via the kernel cmdline.
    // `mvmctl up` staged it in `egress-intermediate.json`; `/init` decodes the
    // `mvm.egress_ca=` token into the guest trust bundle (cert only — the key
    // stays host-side in the terminator endpoint).
    let boot_args = match egress_ca_cmdline_token(&config.slot.name) {
        Some(token) => format!("{boot_args} {token}"),
        None => boot_args,
    };
    // The substitution endpoint spawned pre-boot minted the
    // workload's placeholders and wrote them to
    // `vm_substitution_env_path`. Carry them on the cmdline (`mvm.secret_env=`)
    // so `/init` exports `$VAR=placeholder` into a sealed entrypoint (placeholders
    // only, never values). Absent ⇒ no secrets / no endpoint.
    let boot_args = match secret_env_cmdline_token(&config.slot.name) {
        Some(token) => format!("{boot_args} {token}"),
        None => boot_args,
    };

    // FC's x86_64 loader needs an uncompressed ELF `vmlinux`, but the
    // published default-microvm x86_64 kernel is a bzImage (named `vmlinux`),
    // which FC rejects with "Invalid Elf magic number". Extract the embedded ELF
    // to a cached sibling once and boot from that. No-op for an already-ELF
    // kernel (aarch64 `Image`, or a fixed image).
    let kernel_for_boot =
        mvm_build::fc_kernel::ensure_fc_loadable_kernel(std::path::Path::new(&config.vmlinux_path))
            .with_context(|| {
                format!("preparing FC-loadable kernel from {}", config.vmlinux_path)
            })?;
    let kernel_for_boot = kernel_for_boot.display();

    ui::info(&format!("Setting boot source: {kernel_for_boot}"));
    let boot_source = match &effective_initrd {
        Some(initrd) => {
            ui::info(&format!("Using initrd: {}", initrd));
            format!(
                r#"{{"kernel_image_path": "{kernel}", "boot_args": "{args}", "initrd_path": "{initrd}"}}"#,
                kernel = kernel_for_boot,
                args = boot_args,
                initrd = initrd,
            )
        }
        None => {
            format!(
                r#"{{"kernel_image_path": "{kernel}", "boot_args": "{args}"}}"#,
                kernel = kernel_for_boot,
                args = boot_args,
            )
        }
    };
    api_put_socket(socket, "/boot-source", &boot_source)?;

    ui::info(&format!(
        "Setting machine config: {} vCPUs, {} MiB",
        config.cpus, config.memory
    ));
    api_put_socket(
        socket,
        "/machine-config",
        &format!(
            r#"{{"vcpu_count": {cpus}, "mem_size_mib": {mem}}}"#,
            cpus = config.cpus,
            mem = config.memory,
        ),
    )?;

    // Verity-on means the rootfs is read-only and re-mounted via
    // /dev/dm-0; opening a writable handle would let any host process
    // mutate the bytes the Merkle tree was built against and silently
    // break the integrity check.
    let rootfs_read_only = config.verity_path.is_some();
    ui::info(&format!("Setting rootfs: {}", config.rootfs_path));
    api_put_socket(
        socket,
        "/drives/rootfs",
        &format!(
            r#"{{"drive_id": "rootfs", "path_on_host": "{rootfs}", "is_root_device": true, "is_read_only": {ro}}}"#,
            rootfs = config.rootfs_path,
            ro = rootfs_read_only,
        ),
    )?;

    // dm-verity Merkle tree → /dev/vdb. Firecracker assigns drive
    // letters in API-call order, so this PUT must precede the config /
    // secrets drives below. Always mounted read-only — modifying the
    // hash tree would break verity at the next read.
    if let Some(verity_path) = &config.verity_path {
        ui::info(&format!("Attaching dm-verity sidecar: {}", verity_path));
        api_put_socket(
            socket,
            "/drives/verity",
            &format!(
                r#"{{"drive_id": "verity", "path_on_host": "{path}", "is_root_device": false, "is_read_only": true}}"#,
                path = verity_path,
            ),
        )?;
    }

    // mvm runtime overlay: when the workload opted in,
    // attach the overlay ext4 + its verity sidecar as the third and
    // fourth virtio-blk drives. Order matters — Firecracker assigns
    // drive letters in API-call order, so this pair must follow
    // `/drives/verity` and precede the config/secrets drives so the
    // overlay maps to `/dev/vdc` (data) and `/dev/vdd` (hash), which
    // the verity-init cmdline knobs `mvm.runtime_data=/dev/vdc` and
    // `mvm.runtime_hash=/dev/vdd` (built above) name explicitly.
    // Both are read-only: writing the overlay would break the
    // Merkle-tree check at the next read, same posture as
    // `/drives/verity`.
    if let Some((overlay_path, overlay_verity_path, _)) = overlay {
        ui::info(&format!("Attaching runtime overlay ext4: {}", overlay_path));
        api_put_socket(
            socket,
            "/drives/runtime_overlay",
            &format!(
                r#"{{"drive_id": "runtime_overlay", "path_on_host": "{path}", "is_root_device": false, "is_read_only": true}}"#,
                path = overlay_path,
            ),
        )?;
        ui::info(&format!(
            "Attaching runtime overlay verity sidecar: {}",
            overlay_verity_path
        ));
        api_put_socket(
            socket,
            "/drives/runtime_verity",
            &format!(
                r#"{{"drive_id": "runtime_verity", "path_on_host": "{path}", "is_root_device": false, "is_read_only": true}}"#,
                path = overlay_verity_path,
            ),
        )?;
    }

    // Create and attach mvm-config drive (config.json + role.toml)
    ui::info("Creating config drive...");
    let config_drive = create_dev_config_drive(drives_dir, config)?;
    api_put_socket(
        socket,
        "/drives/config",
        &format!(
            r#"{{"drive_id": "config", "path_on_host": "{path}", "is_root_device": false, "is_read_only": true}}"#,
            path = config_drive,
        ),
    )?;

    // Create and attach mvm-secrets drive (stub secrets.json + extra secret files)
    ui::info("Creating secrets drive...");
    let secrets_drive = create_dev_secrets_drive(drives_dir, &config.secret_files)?;
    api_put_socket(
        socket,
        "/drives/secrets",
        &format!(
            r#"{{"drive_id": "secrets", "path_on_host": "{path}", "is_root_device": false, "is_read_only": true}}"#,
            path = secrets_drive,
        ),
    )?;

    for (idx, vol) in config.volumes.iter().enumerate() {
        let drive_id = format!("vol{}", idx);
        let mode = if vol.read_only { "ro" } else { "rw" };
        ui::info(&format!(
            "Attaching volume {} -> {} (size {}, {mode})",
            vol.host, vol.guest, vol.size
        ));
        api_put_socket(
            socket,
            &format!("/drives/{}", drive_id),
            &format!(
                r#"{{"drive_id": "{id}", "path_on_host": "{host}", "is_root_device": false, "is_read_only": {ro}}}"#,
                id = drive_id,
                host = vol.host,
                ro = vol.read_only,
            ),
        )?;
    }

    ui::info(&format!(
        "Setting network interface: {} (MAC {})",
        slot.tap_dev, slot.mac
    ));
    api_put_socket(
        socket,
        "/network-interfaces/net1",
        &format!(
            r#"{{"iface_id": "net1", "guest_mac": "{mac}", "host_dev_name": "{tap}"}}"#,
            mac = slot.mac,
            tap = slot.tap_dev,
        ),
    )?;

    ui::info("Setting vsock device...");
    api_put_socket(
        socket,
        "/vsock",
        &format!(
            r#"{{"vsock_id": "vsock0", "guest_cid": {cid}, "uds_path": "{dir}/v.sock"}}"#,
            cid = mvm_guest::vsock::GUEST_CID,
            dir = drives_dir,
        ),
    )?;
    expose_vsock_runtime_symlink(drives_dir);

    // Virtio-balloon. Only attached when the workload opted in via
    // `mem_initial`. The device boots pre-inflated to `memory -
    // mem_initial` MiB so the host commits only `mem_initial` MiB
    // until the reclaim controller deflates the balloon.
    //
    // `deflate_on_oom = true` is mandatory: under guest memory
    // pressure the device must yield pages back, otherwise the guest
    // OOM-kills the workload while the host still has memory it
    // could give back. `stats_polling_interval_s = 1` lets the host
    // controller poll real guest commitment without driving the
    // guest's stat refresh too aggressively.
    if let Some(initial) = config.mem_initial {
        let amount_mib = config.memory.saturating_sub(initial);
        ui::info(&format!(
            "Attaching virtio-balloon (cap {} MiB, initial commit {} MiB, balloon {} MiB)",
            config.memory, initial, amount_mib
        ));
        api_put_socket(
            socket,
            "/balloon",
            &format!(
                r#"{{"amount_mib": {amount}, "deflate_on_oom": true, "stats_polling_interval_s": 1}}"#,
                amount = amount_mib,
            ),
        )?;
    }

    Ok(())
}

/// Persist run info for a named VM.
#[instrument(skip_all, fields(name = %config.name))]
pub fn write_vm_run_info(config: &FlakeRunConfig, abs_dir: &str) -> Result<()> {
    let info = RunInfo {
        schema_version: 1,
        mode: "flake".to_string(),
        name: Some(config.name.clone()),
        revision: Some(config.revision_hash.clone()),
        flake_ref: Some(config.flake_ref.clone()),
        guest_ip: Some(config.slot.guest_ip.clone()),
        profile: config.profile.clone(),
        guest_user: String::new(),
        cpus: config.cpus,
        memory: config.memory,
        ports: config.ports.clone(),
    };

    // Also store slot_index for allocation tracking
    let mut json_value = serde_json::to_value(&info)?;
    if let Some(obj) = json_value.as_object_mut() {
        obj.insert(
            "slot_index".to_string(),
            serde_json::Value::Number(config.slot.index.into()),
        );
    }

    let json = serde_json::to_string(&json_value)?;
    run_in_vm(&format!(
        "echo '{}' > {dir}/run-info.json",
        json,
        dir = abs_dir,
    ))?;
    Ok(())
}

/// Read run info for a named VM.
#[instrument(skip_all, fields(name))]
pub fn read_vm_run_info(name: &str) -> Result<RunInfo> {
    let abs_vms = run_in_vm_stdout(&format!("echo {}", VMS_DIR))?;
    let abs_dir = format!("{}/{}", abs_vms.trim(), name);
    read_vm_run_info_from(&abs_dir)
        .ok_or_else(|| anyhow::anyhow!("No run-info found for VM '{}'. Is it running?", name))
}

/// Current schema version for `RunInfo` files.
const RUN_INFO_SCHEMA_VERSION: u32 = 1;

/// Registered migrations for `RunInfo` (indexed by the version they produce).
/// Currently empty — framework is wired but no field changes have occurred yet.
const RUN_INFO_MIGRATIONS: &[mvm_core::migration::MigrateFn] = &[];

/// Read run info from a specific VM directory, applying schema migrations if needed.
fn read_vm_run_info_from(abs_dir: &str) -> Option<RunInfo> {
    let json = run_in_vm_stdout(&format!(
        "cat {dir}/run-info.json 2>/dev/null || echo 'null'",
        dir = abs_dir,
    ))
    .ok()?;
    let raw: serde_json::Value = serde_json::from_str(&json).ok()?;
    let from = mvm_core::migration::schema_version_of(&raw);
    let migrated =
        mvm_core::migration::migrate(raw, from, RUN_INFO_SCHEMA_VERSION, RUN_INFO_MIGRATIONS)
            .map_err(|e| tracing::warn!("run-info migration failed: {e}"))
            .ok()?;
    serde_json::from_value(migrated).ok()
}

/// Read the slot_index from a VM's run-info.json.
fn read_slot_index(abs_dir: &str) -> Option<u8> {
    let json = run_in_vm_stdout(&format!(
        "cat {dir}/run-info.json 2>/dev/null || echo 'null'",
        dir = abs_dir,
    ))
    .ok()?;
    let value: serde_json::Value = serde_json::from_str(&json).ok()?;
    value.get("slot_index")?.as_u64().map(|v| v as u8)
}

/// Check whether a PID is alive on the current OS.
///
/// On Linux: checks for `/proc/<pid>` existence (no signal needed).
/// On macOS: runs `kill -0 <pid>` via the shell.
pub fn is_pid_alive(pid: u32) -> bool {
    #[cfg(target_os = "linux")]
    {
        std::path::Path::new(&format!("/proc/{}", pid)).exists()
    }
    #[cfg(not(target_os = "linux"))]
    {
        std::process::Command::new("kill")
            .args(["-0", &pid.to_string()])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }
}

/// Scan `VMS_DIR` inside the Lima VM for orphaned entries — run-info.json files
/// whose stored Firecracker PID is no longer alive.
///
/// Returns a list of VM names with orphaned state files.
pub fn find_orphaned_vms() -> Result<Vec<String>> {
    // List all run-info.json files and check each PID in a single shell script.
    let output = run_in_vm_stdout(&format!(
        r#"for dir in {vms_dir}/*/; do
            name=$(basename "$dir")
            rif="${{dir}}run-info.json"
            if [ ! -f "$rif" ]; then continue; fi
            pid=$(cat "$rif" 2>/dev/null | grep -o '"fc_pid":[0-9]*' | grep -o '[0-9]*$' | head -1)
            if [ -z "$pid" ]; then continue; fi
            if ! kill -0 "$pid" 2>/dev/null; then
                echo "$name"
            fi
        done 2>/dev/null || true"#,
        vms_dir = VMS_DIR,
    ))?;

    Ok(output
        .lines()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect())
}

/// Remove orphaned `run-info.json` entries from `VMS_DIR`.
///
/// In dry-run mode: lists orphaned entries without deleting.
/// In normal mode: removes the orphaned files and logs each removal.
pub fn cleanup_orphaned_vms(dry_run: bool) -> Result<()> {
    let orphans = find_orphaned_vms()?;

    if orphans.is_empty() {
        ui::success("No orphaned VM state files found.");
        return Ok(());
    }

    if dry_run {
        ui::info(&format!(
            "Would remove {} orphaned VM state file(s):",
            orphans.len()
        ));
        for name in &orphans {
            println!("  {}", name);
        }
        return Ok(());
    }

    for name in &orphans {
        let result = run_in_vm(&format!(
            "rm -f {vms_dir}/{name}/run-info.json",
            vms_dir = VMS_DIR,
            name = name,
        ));
        match result {
            Ok(_) => {
                ui::success(&format!("Removed orphaned state for VM '{}'", name));
                tracing::info!(vm = %name, "removed orphaned run-info.json");
            }
            Err(e) => {
                tracing::warn!(vm = %name, "failed to remove orphaned run-info.json: {e}");
            }
        }
    }

    Ok(())
}

/// Read persisted run info (returns None if file doesn't exist), with migration.
pub fn read_run_info() -> Option<RunInfo> {
    let json = run_in_vm_stdout(&format!(
        "cat {dir}/.mvm-run-info 2>/dev/null || echo 'null'",
        dir = MICROVM_DIR,
    ))
    .ok()?;
    let raw: serde_json::Value = serde_json::from_str(&json).ok()?;
    let from = mvm_core::migration::schema_version_of(&raw);
    let migrated =
        mvm_core::migration::migrate(raw, from, RUN_INFO_SCHEMA_VERSION, RUN_INFO_MIGRATIONS)
            .map_err(|e| tracing::warn!("run-info migration failed: {e}"))
            .ok()?;
    serde_json::from_value(migrated).ok()
}

// ============================================================================
// mvm-firecracker-bridge spawn + watchdog (Linux only)
//
// Mirrors Vz's `AttachedDrainerGuard` shape
// (`crates/mvm-backend/src/vz.rs`) — Drop kills+waits the child on
// early return, `detach()` hands ownership to the caller which
// records the PID in
// `<state_dir>/fc-bridge.pid` and lets the watchdog thread inherit it.
// The bridge is Linux-only so every helper is `#[cfg(target_os = "linux")]`;
// non-Linux builds compile but never call into this path.
// ============================================================================

/// PID file the bridge watchdog writes inside `<abs_dir>`. Lives next
/// to `fc.pid` so the watchdog (and a future `stop_vm` reaper) can find
/// the bridge with the same `<abs_dir>` it already resolves for the
/// FC VM itself.
#[cfg(target_os = "linux")]
const FC_BRIDGE_PID_FILE_NAME: &str = "fc-bridge.pid";

/// RAII guard for a spawned `mvm-firecracker-bridge` child. Mirrors
/// the Vz `AttachedDrainerGuard` pattern: dropping the guard kills +
/// waits the child so an early return / panic between bridge spawn
/// and VM boot completion cleans up the bridge process.
///
/// After successful boot, `detach_and_spawn_bridge_watchdog` takes
/// the `Child` out via `.take()`; the watchdog thread inherits the
/// handle and the OS keeps the bridge alive.
#[cfg(target_os = "linux")]
struct AttachedBridgeGuard {
    child: Option<std::process::Child>,
}

#[cfg(target_os = "linux")]
impl AttachedBridgeGuard {
    /// Hand off the spawned bridge to the OS — used after the FC VM
    /// boots cleanly so the bridge outlives `run_from_build`'s stack
    /// frame. Returns the `Child` for the caller to record its PID
    /// in the on-disk reaper file before the handle is dropped
    /// without `kill()` firing.
    fn detach(&mut self) -> Option<std::process::Child> {
        self.child.take()
    }
}

#[cfg(target_os = "linux")]
impl Drop for AttachedBridgeGuard {
    fn drop(&mut self) {
        if let Some(mut c) = self.child.take() {
            let pid = c.id();
            if let Err(e) = c.kill() {
                warn!(
                    bridge_pid = pid,
                    error = %e,
                    "AttachedBridgeGuard: kill mvm-firecracker-bridge failed on drop"
                );
            }
            if let Err(e) = c.wait() {
                warn!(
                    bridge_pid = pid,
                    error = %e,
                    "AttachedBridgeGuard: wait mvm-firecracker-bridge failed on drop"
                );
            }
        }
    }
}

/// Resolve `MVM_PASST_PATH` (or default `/usr/bin/passt`) without
/// touching std::env in tests. Pure helper so the bridge spawn block
/// stays compact.
#[cfg(target_os = "linux")]
fn passt_path_from_env_or_default() -> std::path::PathBuf {
    std::env::var_os("MVM_PASST_PATH")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("/usr/bin/passt"))
}

/// Resolve the `mvm-firecracker-bridge` binary path, checking three
/// sources in order. Pure resolver — exercised directly from tests
/// without touching `std::env`. Mirrors the Vz
/// `resolve_vz_drainer_path_inner` shape.
#[cfg(target_os = "linux")]
fn resolve_fc_bridge_path_inner(
    env_override: Option<&std::path::Path>,
    current_exe: Option<&std::path::Path>,
    manifest_dir: &std::path::Path,
) -> Result<std::path::PathBuf> {
    if let Some(path) = env_override {
        if path.is_file() {
            return Ok(path.to_path_buf());
        }
        anyhow::bail!(
            "MVM_FC_BRIDGE_PATH points at {} which is not a file",
            path.display()
        );
    }
    if let Some(exe) = current_exe
        && let Some(dir) = exe.parent()
    {
        let candidate = dir.join("mvm-firecracker-bridge");
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    // Workspace target dir — `crates/mvm-backend` → workspace root is
    // two `..` up; the target dir is rooted there.
    if let Some(workspace_root) = manifest_dir.parent().and_then(std::path::Path::parent) {
        for variant in ["release", "debug"] {
            let candidate = workspace_root
                .join("target")
                .join(variant)
                .join("mvm-firecracker-bridge");
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }
    anyhow::bail!(
        "mvm-firecracker-bridge binary not found. Looked for: $MVM_FC_BRIDGE_PATH, \
         alongside the current exe, and <workspace>/target/{{release,debug}}/mvm-firecracker-bridge. \
         Build with `cargo build -p mvm-firecracker-bridge`."
    )
}

/// Production wrapper around `resolve_fc_bridge_path_inner` that
/// reads `std::env` + `current_exe` + `CARGO_MANIFEST_DIR`. Keep the
/// test seam in `_inner` so unit tests don't race on env state.
#[cfg(target_os = "linux")]
fn resolve_fc_bridge_path() -> Result<std::path::PathBuf> {
    let env_override = std::env::var_os("MVM_FC_BRIDGE_PATH").map(std::path::PathBuf::from);
    let current_exe = std::env::current_exe().ok();
    let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    resolve_fc_bridge_path_inner(
        env_override.as_deref(),
        current_exe.as_deref(),
        &manifest_dir,
    )
}

/// Stand up this VM's transparent egress substitution moat (endpoint +
/// terminator + nft TAP REDIRECT) when the admitted plan carries
/// secret bindings. Called after the FC guest is healthy.
///
/// The plan lives at `vm_state_dir(name)/plan.json` (the same file
/// `spawn_fc_bridge` parses — `mvm_data_dir()/vms/<name>`, NOT the `abs_dir`
/// VMS_DIR tree). The substitution pid + env sidecars also land under
/// `vm_state_dir` so the invoke path's `vm_substitution_env_path` lookup
/// resolves identically to the QEMU backend.
///
/// Fail-closed: any error propagates so the caller rolls back the VM. A
/// missing/unsigned `plan.json` (legacy / non-admitted boot) or a plan with no
/// secrets is a clean no-op — there's nothing to substitute.
///
/// The installed [`EgressRedirect`] is `persist`ed (not dropped): the VM keeps
/// running after this returns, and `stop_vm` removes the nft table by name.
///
/// Shared plan decode: `Some((secrets, tenant))` when the admitted
/// plan carries egress secrets, else `None` (legacy / non-admitted / no-secret
/// boot — nothing to wire). A missing `plan.json` or an undecodable placeholder
/// plan is the no-op path, not an error.
#[cfg(target_os = "linux")]
fn decode_plan_secrets(
    state_dir: &std::path::Path,
) -> Result<
    Option<(
        Vec<mvm_core::plan::SecretBinding>,
        mvm_core::policy::RedactionPolicy,
        String,
    )>,
> {
    let plan_path = state_dir.join("plan.json");
    let plan_json = match std::fs::read_to_string(&plan_path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(anyhow::anyhow!(
                "read plan.json at {} for egress substitution: {e}",
                plan_path.display()
            ));
        }
    };
    // Both producers land here: the pre-start persist writes the bare
    // `ExecutionPlan` (the shape the firecracker bridge parses too) and the
    // gateway-bridge stash writes the signed envelope. Accept either.
    let plan = match mvm_core::plan::plan_from_admitted_json(&plan_json) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "plan.json not a decodable admitted plan; skipping egress substitution");
            return Ok(None);
        }
    };
    if plan.secrets.is_empty() {
        return Ok(None);
    }
    Ok(Some((plan.secrets, plan.redaction, plan.tenant.0)))
}

/// Spawn the per-VM substitution endpoint **before** the guest boots,
/// so the `(var → placeholder)` pairs it mints (and
/// writes to `vm_substitution_env_path`) are available when `boot_args` is built
/// and can ride the cmdline (`mvm.secret_env=`) into a sealed entrypoint. Binds
/// the terminator listener too; the nft REDIRECT that feeds it is installed
/// post-boot by [`install_egress_redirect`] (it needs the guest's TAP). No-op
/// when the plan carries no egress secrets. Returns an armed [`EndpointGuard`]
/// the caller defuses once the VM is fully up.
#[cfg(target_os = "linux")]
fn spawn_egress_endpoint(config: &FlakeRunConfig) -> Result<EndpointGuard> {
    use crate::egress_redirect::terminator_port_for;
    use crate::substitution_spawn::spawn_substitution_endpoint;
    use std::net::SocketAddr;

    let name = &config.slot.name;
    let state_dir = mvm_core::config::vm_state_dir(name);
    let Some((secrets, redaction, tenant)) = decode_plan_secrets(&state_dir)? else {
        return Ok(EndpointGuard { vm_name: None });
    };

    // Per-slot terminator port so concurrent VMs never collide host-side.
    // 0.0.0.0: a PREROUTING REDIRECT delivers the forwarded packet to a local
    // socket on the host, so the terminator must accept on the host's addrs.
    let term_port = terminator_port_for(config.slot.index);
    let listen = SocketAddr::from(([0, 0, 0, 0], term_port));
    // `mvmctl up` staged the per-VM name-constrained intermediate (cert+key) in
    // the sidecar. Hand the KEY to the endpoint so the `https` terminator can
    // mint per-SNI leaves; it never reaches the guest. Absent ⇒ `http`-only.
    let tls_intermediate = read_egress_intermediate(&state_dir)?;
    spawn_substitution_endpoint(crate::substitution_spawn::SubstitutionSpawnParams {
        vm_name: name,
        state_dir: &state_dir,
        tenant: &tenant,
        secrets: &secrets,
        redaction: &redaction,
        transport: crate::substitution_spawn::EndpointTransport::Vsock {
            port: mvm_guest::vsock::SUBSTITUTION_PORT,
        },
        terminator_listen: Some(listen),
        tls_intermediate,
    })?;
    Ok(EndpointGuard::new(name))
}

/// Install the per-VM nft TAP REDIRECT (`:80`/`:443` → the terminator)
/// **after** the guest boots (the TAP exists). No-op when the plan carries no
/// egress secrets. Persists the table so it outlives this frame; `stop_vm`
/// removes it by name.
#[cfg(target_os = "linux")]
fn install_egress_redirect(config: &FlakeRunConfig) -> Result<()> {
    use crate::egress_redirect::{EgressRedirect, terminator_port_for};

    let name = &config.slot.name;
    let state_dir = mvm_core::config::vm_state_dir(name);
    if decode_plan_secrets(&state_dir)?.is_none() {
        return Ok(());
    }
    let term_port = terminator_port_for(config.slot.index);
    let redirect = EgressRedirect::install(name, &config.slot.tap_dev, term_port)?;
    redirect.persist();
    Ok(())
}

/// The `mvm.egress_ca=<hex>` kernel-cmdline token for `vm_name`,
/// or `None` when the VM has no staged intermediate (no secrets / no https leg).
/// Reads the **cert** from the per-VM `egress-intermediate.json` sidecar (the key
/// is never put on the cmdline / in the guest). Best-effort: a malformed/missing
/// sidecar yields `None` rather than blocking boot — the worst case is the guest
/// can't trust host-terminated TLS, and the claim-12 host allow-list still holds.
fn egress_ca_cmdline_token(vm_name: &str) -> Option<String> {
    let path = mvm_core::config::vm_state_dir(vm_name).join("egress-intermediate.json");
    let bytes = std::fs::read(&path).ok()?;
    let v: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    let cert = v["cert_pem"].as_str()?;
    mvm_core::vm_backend::encode_egress_ca_cmdline(cert)
}

/// The `mvm.secret_env=<hex>` cmdline token for `vm_name`, or `None`
/// when the VM has no secrets. Reads the `(var, placeholder)`
/// pairs the pre-boot substitution endpoint minted into `vm_substitution_env_path`
/// (a JSON array of `[var, placeholder]`) and encodes them — **placeholders only**,
/// never values (claim 13). Best-effort: a missing/malformed handshake yields
/// `None` rather than blocking boot.
fn secret_env_cmdline_token(vm_name: &str) -> Option<String> {
    let path = mvm_core::config::vm_substitution_env_path(vm_name);
    let bytes = std::fs::read(&path).ok()?;
    let pairs: Vec<(String, String)> = serde_json::from_slice(&bytes).ok()?;
    mvm_core::vm_backend::encode_secret_env_cmdline(&pairs)
}

/// Read the per-VM egress intermediate (`cert_pem` + `key_pem`)
/// `mvmctl up` persisted at `<state_dir>/egress-intermediate.json` (host-only,
/// mode 0600). Returns `None` when absent (no https leg) — a missing file is the
/// no-secret path, not an error. The key is host-side material only;
/// it is handed to the terminator endpoint and never written to a guest drive.
#[cfg(target_os = "linux")]
fn read_egress_intermediate(state_dir: &std::path::Path) -> Result<Option<(String, String)>> {
    let path = state_dir.join("egress-intermediate.json");
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(anyhow::anyhow!("read {}: {e}", path.display())),
    };
    let v: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|e| anyhow::anyhow!("parse {}: {e}", path.display()))?;
    let cert = v["cert_pem"].as_str();
    let key = v["key_pem"].as_str();
    match (cert, key) {
        (Some(c), Some(k)) => Ok(Some((c.to_string(), k.to_string()))),
        _ => Err(anyhow::anyhow!(
            "{} missing cert_pem/key_pem",
            path.display()
        )),
    }
}

/// Spawn the `mvm-firecracker-bridge` sibling. Creates a UNIX
/// socketpair, clears `O_CLOEXEC` on both halves in the child via
/// `CommandExt::pre_exec` so they survive `execve`, then pipes the
/// `BridgeConfigJson` document to the child's stdin. Both fds stay
/// owned by the child; the parent closes its handles via
/// `libc::close` after spawn so the supervisor process doesn't leak
/// an fd per VM boot.
///
/// Reads `plan.json` (required) + `bundle.json` (optional) from the
/// per-VM state dir `~/.mvm/vms/<vm_name>/` where the producer
/// (`stash_plan_for_bridge` in `mvm-cli`) wrote them at mode 0600.
///
/// Returns an [`AttachedBridgeGuard`] still holding the `Child`; the
/// caller either lets it fall out of scope on early-return (the Drop
/// impl kills + waits the child) or calls
/// [`detach_and_spawn_bridge_watchdog`] after the FC VM confirms boot
/// to detach the handle and start the watchdog.
///
/// `vm_name` labels the bridge thread + audit chain `vm` field;
/// `abs_dir` is the FC VM's state dir inside the host's filesystem
/// (where `fc.pid` lands so the watchdog can find it).
#[cfg(target_os = "linux")]
fn spawn_fc_bridge(vm_name: &str, abs_dir: &str) -> Result<AttachedBridgeGuard> {
    use std::io::Write;
    use std::os::fd::{AsRawFd, IntoRawFd};
    use std::os::unix::process::CommandExt;

    // ── Step 1: locate the bridge binary + verify producer stashed
    //            plan.json. The bridge is the trust boundary for the
    //            envelope (it parses but doesn't re-verify); the
    //            producer side (`mvm-cli::stash_plan_for_bridge`) is
    //            responsible for putting a freshly-admitted plan
    //            here. A missing file means a non-admitted boot —
    //            legacy path, no bridge.
    let bridge_bin = resolve_fc_bridge_path()
        .with_context(|| "locate mvm-firecracker-bridge binary".to_string())?;

    let data_dir = std::path::PathBuf::from(mvm_core::config::mvm_data_dir());
    let state_dir = data_dir.join("vms").join(vm_name);
    let plan_path = state_dir.join("plan.json");
    let bundle_path = state_dir.join("bundle.json");
    let plan_json = match std::fs::read_to_string(&plan_path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            tracing::debug!(
                vm = %vm_name,
                "no plan.json at {}; skipping mvm-firecracker-bridge (legacy path)",
                plan_path.display()
            );
            return Ok(AttachedBridgeGuard { child: None });
        }
        Err(e) => {
            return Err(anyhow::anyhow!(
                "read plan.json at {} (Plan 113 §Task 13 producer): {e}",
                plan_path.display()
            ));
        }
    };
    let bundle_json = match std::fs::read_to_string(&bundle_path) {
        Ok(s) => Some(s),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => {
            return Err(anyhow::anyhow!(
                "read bundle.json at {}: {e}",
                bundle_path.display()
            ));
        }
    };

    // ── Step 2: substrate paths the bridge needs to bind/read. All
    //            relative to `mvm_data_dir()` so an `MVM_DATA_DIR`
    //            override (tests, mvmd) transparently re-roots the
    //            whole tree.
    let audit_dir = data_dir.join("audit");
    let audit_socket = audit_dir.join(format!("gateway-{vm_name}.sock"));
    let keys_dir = data_dir.join("keys");
    let signing_key_path = keys_dir.join("host-signer.ed25519");
    let passt_path = passt_path_from_env_or_default();
    let passt_hashes_path = data_dir.join("passt-hashes.toml");

    // ── Step 3: create the socketpair. Both halves go to the child
    //            (one feeds passt, one feeds the supervisor's gateway
    //            loop — see `mvm_hostd::supervisor::gateway_bridge::
    //            BridgeEndpoints::Passt`). We use stdlib pairs which
    //            arrive with FD_CLOEXEC set; the `pre_exec` block
    //            clears CLOEXEC in the child before `execve` so the
    //            kernel preserves both fds.
    let (gateway_socket, supervisor_socket) = std::os::unix::net::UnixStream::pair()
        .map_err(|e| anyhow::anyhow!("create passt/supervisor socketpair: {e}"))?;
    let gateway_raw = gateway_socket.as_raw_fd();
    let supervisor_raw = supervisor_socket.as_raw_fd();

    let bridge_cfg = serde_json::json!({
        "vm_name": vm_name,
        "audit_dir": audit_dir,
        "audit_socket": audit_socket,
        "keys_dir": keys_dir,
        "signing_key_path": signing_key_path,
        "passt_path": passt_path,
        "passt_hashes_path": passt_hashes_path,
        "gateway_fd_raw": gateway_raw,
        "supervisor_fd_raw": supervisor_raw,
        "plan_json": plan_json,
        "bundle_json": bundle_json,
    });

    tracing::info!(
        vm = %vm_name,
        bridge = %bridge_bin.display(),
        gateway_fd = gateway_raw,
        supervisor_fd = supervisor_raw,
        "spawning mvm-firecracker-bridge with inherited socketpair fds"
    );

    let mut cmd = std::process::Command::new(&bridge_bin);
    cmd.stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::inherit());

    // SAFETY: `pre_exec` runs in the child between fork and exec.
    // Both raw fds (`gateway_raw`, `supervisor_raw`) are valid in the
    // child's fd table because the child inherits the parent's table
    // post-fork; clearing FD_CLOEXEC via `fcntl(F_SETFD)` is a
    // syscall wrapper with no side effects beyond the fd flag. We
    // only call libc; no allocation, no Rust runtime entry-points
    // are invoked. The closure captures `gateway_raw` and
    // `supervisor_raw` (Copy `i32`s); no shared state.
    unsafe {
        cmd.pre_exec(move || {
            for raw in [gateway_raw, supervisor_raw] {
                let flags = libc::fcntl(raw, libc::F_GETFD);
                if flags < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                let new_flags = flags & !libc::FD_CLOEXEC;
                if libc::fcntl(raw, libc::F_SETFD, new_flags) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }

    let mut child = cmd
        .spawn()
        .map_err(|e| anyhow::anyhow!("spawn {}: {e}", bridge_bin.display()))?;

    // ── Step 4: parent-side fd hygiene. The child inherited both
    //            socketpair fds (CLOEXEC cleared via pre_exec); the
    //            parent's copies are still open. Without closing
    //            them here the supervisor leaks two fds per VM boot.
    //            We give up Rust ownership via `into_raw_fd` (skipping
    //            the stdlib's Drop close) and then `libc::close`
    //            explicitly so the error path is auditable.
    //
    //            CRITICAL: close BEFORE the stdin write below. The
    //            `fork+execve` has already happened by the time
    //            `spawn()` returns, so the child holds its own fd
    //            table entries via the inherited dup. If the
    //            following `.stdin.take().ok_or_else(...)?` or
    //            `write_all(...)?` returns `Err`, an early-return
    //            after this point would otherwise leak both fds in
    //            the parent (the raw fd is not owned by Rust drop
    //            once `into_raw_fd` has been called).
    let parent_gateway_fd = gateway_socket.into_raw_fd();
    let parent_supervisor_fd = supervisor_socket.into_raw_fd();
    // SAFETY: both raw fds came from `UnixStream::pair` + `into_raw_fd`
    // immediately above. They are valid, owned by this process, and
    // no other code path in this function reads them. After
    // `libc::close` they MUST NOT be referenced again — we don't.
    // Closing the parent's copies does not affect the child: the
    // child's fd table received its own dup of each fd during the
    // post-spawn fork+execve, so the kernel keeps the underlying
    // socket endpoints alive on the child side.
    unsafe {
        libc::close(parent_gateway_fd);
        libc::close(parent_supervisor_fd);
    }

    child
        .stdin
        .take()
        .ok_or_else(|| anyhow::anyhow!("mvm-firecracker-bridge stdin was not piped"))?
        .write_all(bridge_cfg.to_string().as_bytes())
        .map_err(|e| anyhow::anyhow!("pipe BridgeConfigJson to stdin: {e}"))?;

    // Reference `abs_dir` here so the parent layer doesn't get a
    // dead-arg lint when the bridge contract evolves to consume it
    // (planned: read fc.pid path from the host paths struct rather
    // than reconstructing it in the watchdog). Today the watchdog
    // builds its own path from `abs_dir` so this is just keeping the
    // signature wired.
    let _ = abs_dir;

    Ok(AttachedBridgeGuard { child: Some(child) })
}

/// Atomically write the bridge PID file at mode 0600. Same shape as
/// Vz's `write_drainer_pid_file` — tmp + rename so a concurrent
/// reader (a future `stop_vm` reaper) never sees a partial value.
#[cfg(target_os = "linux")]
fn write_fc_bridge_pid_file(path: &std::path::Path, pid: u32) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("bridge pid path has no parent: {}", path.display()))?;
    let tmp = parent.join(format!("{FC_BRIDGE_PID_FILE_NAME}.tmp"));
    {
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(|e| anyhow::anyhow!("open {} for write: {e}", tmp.display()))?;
        writeln!(f, "{pid}").map_err(|e| anyhow::anyhow!("write bridge pid: {e}"))?;
        let _ = f.sync_all();
    }
    std::fs::rename(&tmp, path)
        .map_err(|e| anyhow::anyhow!("rename {} -> {}: {e}", tmp.display(), path.display()))?;
    Ok(())
}

/// Once the FC VM is healthy, take the bridge `Child` out of its
/// guard, persist its PID under `<abs_dir>/fc-bridge.pid` (mode 0600),
/// then spawn the watchdog thread that observes the child via
/// `wait()`. On bridge death the watchdog SIGTERMs the FC VM via
/// `<abs_dir>/fc.pid` (hard-fail bridge crash policy).
///
/// No-op when the guard is empty (legacy path with no admitted plan).
#[cfg(target_os = "linux")]
fn detach_and_spawn_bridge_watchdog(
    vm_name: &str,
    abs_dir: &str,
    guard: &mut AttachedBridgeGuard,
) -> Result<()> {
    let Some(mut child) = guard.detach() else {
        return Ok(());
    };
    let pid = child.id();
    let pid_path = std::path::PathBuf::from(abs_dir).join(FC_BRIDGE_PID_FILE_NAME);
    write_fc_bridge_pid_file(&pid_path, pid)?;

    let fc_pid_path = format!("{abs_dir}/fc.pid");
    let vm = vm_name.to_string();
    std::thread::spawn(move || {
        let exit = child.wait();
        warn!(
            vm = %vm,
            bridge_pid = pid,
            ?exit,
            "mvm-firecracker-bridge exited; SIGTERM'ing Firecracker VM (hard-fail policy)"
        );
        match std::fs::read_to_string(&fc_pid_path) {
            Ok(pid_str) => match pid_str.trim().parse::<libc::pid_t>() {
                Ok(fc_pid) => {
                    // SAFETY: `libc::kill(pid, SIGTERM)` is a syscall
                    // wrapper. SIGTERM to an arbitrary pid_t is well-
                    // defined (kernel resolves or returns ESRCH); no
                    // Rust invariants are touched.
                    let rc = unsafe { libc::kill(fc_pid, libc::SIGTERM) };
                    if rc != 0 {
                        let err = std::io::Error::last_os_error();
                        warn!(
                            vm = %vm,
                            fc_pid,
                            error = %err,
                            "watchdog: SIGTERM to Firecracker VM failed"
                        );
                    }
                }
                Err(e) => warn!(
                    vm = %vm,
                    fc_pid_path = %fc_pid_path,
                    error = %e,
                    "watchdog: parse fc.pid failed; VM may already be gone"
                ),
            },
            Err(e) => warn!(
                vm = %vm,
                fc_pid_path = %fc_pid_path,
                error = %e,
                "watchdog: read fc.pid failed; VM may already be gone"
            ),
        }
    });
    Ok(())
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

    // ------------------------------------------------------------------
    // verity cmdline + runtime-overlay attachment
    // ------------------------------------------------------------------

    /// 64-char lowercase hex used wherever a roothash is needed.
    /// Two distinct values so cmdline tests can prove the rootfs
    /// hash and the overlay hash flow through the right knobs.
    const ROOTFS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000001";
    const OVERLAY_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000002";

    #[test]
    fn build_verity_cmdline_args_none_without_roothash() {
        assert_eq!(build_verity_cmdline_args(None, None), None);
        // Overlay hash alone without rootfs verity is a nonsense
        // input — we shouldn't synthesize a half cmdline.
        assert_eq!(
            build_verity_cmdline_args(None, Some(OVERLAY_HASH)),
            None,
            "overlay-only input should not produce a cmdline"
        );
    }

    #[test]
    fn build_verity_cmdline_args_rootfs_only_matches_legacy_shape() {
        let got =
            build_verity_cmdline_args(Some(ROOTFS_HASH), None).expect("rootfs verity → cmdline");
        assert_eq!(
            got,
            format!("mvm.roothash={ROOTFS_HASH} mvm.data=/dev/vda mvm.hash=/dev/vdb"),
        );
        assert!(!got.contains("runtime_"));
    }

    #[test]
    fn build_verity_cmdline_args_with_overlay_appends_runtime_knobs() {
        let got = build_verity_cmdline_args(Some(ROOTFS_HASH), Some(OVERLAY_HASH))
            .expect("rootfs + overlay verity → cmdline");
        // Rootfs knobs come first, overlay knobs append at the end —
        // mvm-verity-init parses tokens left-to-right and only the
        // last assignment wins for a duplicate key, so order is
        // load-bearing if rootfs/overlay were ever to share a key.
        // The runtime keys are distinct names today, but pinning
        // the order keeps the contract obvious.
        assert!(got.starts_with(&format!("mvm.roothash={ROOTFS_HASH} ")));
        assert!(got.contains(&format!("mvm.runtime_roothash={OVERLAY_HASH}")));
        assert!(got.contains("mvm.runtime_data=/dev/vdc"));
        assert!(got.contains("mvm.runtime_hash=/dev/vdd"));
    }

    #[test]
    fn resolved_runtime_overlay_requires_all_three_fields() {
        let mut cfg = baseline_run_config(None);
        cfg.roothash = Some(ROOTFS_HASH.into());
        // All three None ⇒ no overlay.
        assert!(resolved_runtime_overlay(&cfg).is_none());

        // Only path set ⇒ no overlay.
        cfg.runtime_overlay_path = Some("/k/rootfs.runtime.ext4".into());
        assert!(resolved_runtime_overlay(&cfg).is_none());

        // Path + verity sidecar set, hash missing ⇒ no overlay.
        cfg.runtime_overlay_verity_path = Some("/k/rootfs.runtime.verity".into());
        assert!(resolved_runtime_overlay(&cfg).is_none());

        // All three present ⇒ Some.
        cfg.runtime_overlay_roothash = Some(OVERLAY_HASH.into());
        let (p, vp, h) = resolved_runtime_overlay(&cfg).expect("complete triple resolves");
        assert_eq!(p, "/k/rootfs.runtime.ext4");
        assert_eq!(vp, "/k/rootfs.runtime.verity");
        assert_eq!(h, OVERLAY_HASH);
    }

    #[test]
    fn resolved_runtime_overlay_ignored_when_verity_off() {
        // Mirrors the gate inside `configure_flake_microvm_…`: a
        // workload with overlay fields set but verity off has no
        // consumer for the drives. The free function itself
        // doesn't enforce this — it's the caller's job — but
        // documenting the convention here keeps the linkage
        // visible to future readers.
        let mut cfg = baseline_run_config(None);
        cfg.roothash = None; // verity off
        cfg.runtime_overlay_path = Some("/k/rootfs.runtime.ext4".into());
        cfg.runtime_overlay_verity_path = Some("/k/rootfs.runtime.verity".into());
        cfg.runtime_overlay_roothash = Some(OVERLAY_HASH.into());
        // The triple is structurally complete, so the resolver
        // returns Some — the gate lives in the caller.
        assert!(resolved_runtime_overlay(&cfg).is_some());
        // And the cmdline builder refuses to synthesize anything
        // overlay-related when rootfs verity is off — together,
        // these two behaviours make the configure_flake path
        // skip the drive attachments.
        assert_eq!(build_verity_cmdline_args(None, Some(OVERLAY_HASH)), None,);
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

    #[test]
    fn console_warning_patterns_detect_kernel_panic() {
        let lines = "Booting Linux\nKernel panic - not syncing: VFS\ndone";
        let mut warnings = Vec::new();
        for line in lines.lines() {
            for pattern in CONSOLE_WARNING_PATTERNS {
                if line.contains(pattern) {
                    warnings.push(line.to_string());
                    break;
                }
            }
        }
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("Kernel panic"));
    }

    #[test]
    fn console_warning_patterns_detect_oom() {
        let lines = "init done\nOut of memory: Killed process 123\nnormal line";
        let mut warnings = Vec::new();
        for line in lines.lines() {
            for pattern in CONSOLE_WARNING_PATTERNS {
                if line.contains(pattern) {
                    warnings.push(line.to_string());
                    break;
                }
            }
        }
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("Out of memory"));
    }

    #[test]
    fn console_warning_patterns_skip_clean_log() {
        let lines = "Booting Linux\nStarting services\nAll services ready";
        let mut warnings = Vec::new();
        for line in lines.lines() {
            for pattern in CONSOLE_WARNING_PATTERNS {
                if line.contains(pattern) {
                    warnings.push(line.to_string());
                    break;
                }
            }
        }
        assert!(warnings.is_empty());
    }

    /// Verify the log-and-continue error policy works: when a cleanup
    /// operation returns Err, the enclosing function should NOT propagate it.
    /// This tests the log-and-continue pattern used throughout the codebase.
    #[test]
    fn test_log_and_continue_pattern_does_not_propagate_errors() {
        use crate::base::shell_mock;

        // Install a mock that fails for all commands.
        let _guard = shell_mock::install_handler(|_script: &str| shell_mock::MockResponse {
            exit_code: 1,
            stdout: String::new(),
        });

        // Simulate the log-and-continue pattern used in cleanup paths.
        // This is the exact pattern from instance/lifecycle.rs, microvm.rs, etc.
        fn cleanup_with_log_and_continue() -> anyhow::Result<()> {
            // These operations would fail (mock returns exit code 1),
            // but run_in_vm returns Ok(output) — the error is in exit status.
            // The real pattern: if let Err(e) = operation() { warn!(...) }
            if let Err(e) = crate::base::shell::run_in_vm("kill -9 12345 2>/dev/null || true") {
                tracing::warn!("failed to kill process: {e}");
            }
            if let Err(e) =
                crate::base::shell::run_in_vm("sudo ip link del tap0 2>/dev/null || true")
            {
                tracing::warn!("failed to destroy TAP: {e}");
            }
            if let Err(e) = crate::base::shell::run_in_vm("rm -rf /tmp/test-dir") {
                tracing::warn!("failed to remove directory: {e}");
            }

            // The function should still succeed.
            Ok(())
        }

        let result = cleanup_with_log_and_continue();
        assert!(
            result.is_ok(),
            "log-and-continue cleanup must not propagate errors: {:?}",
            result.err()
        );
    }

    #[test]
    fn diagnose_result_serializes_to_json() {
        let result = DiagnoseResult {
            fc_alive: true,
            fc_pid: Some(12345),
            fc_api_responsive: true,
            fc_machine_config: Some(serde_json::json!({"vcpu_count": 2})),
            vsock_exists: true,
            console_warnings: vec![],
            fc_log_errors: vec![],
            agent_reachable: true,
            agent_error: None,
            worker_status: Some("idle".into()),
            last_busy_at: None,
            probe_results: vec![],
            integration_results: vec![],
            suggestions: vec![],
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"fc_alive\":true"));
        assert!(json.contains("\"fc_pid\":12345"));
    }

    #[test]
    fn firecracker_guard_defuse_prevents_cleanup() {
        use crate::base::shell_mock;

        let call_count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = call_count.clone();
        let _handler = shell_mock::install_handler(move |_script: &str| {
            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            shell_mock::MockResponse {
                exit_code: 0,
                stdout: String::new(),
            }
        });

        {
            let mut guard = FirecrackerGuard::new("/tmp/test-vm");
            guard.defuse();
            // guard drops here — should NOT call shell
        }

        assert_eq!(
            call_count.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "defused FirecrackerGuard must not run cleanup"
        );
    }

    #[test]
    fn firecracker_guard_runs_cleanup_on_drop() {
        use crate::base::shell_mock;

        let scripts = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let scripts_clone = scripts.clone();
        let _handler = shell_mock::install_handler(move |script: &str| {
            scripts_clone
                .lock()
                .expect("mutex must not be poisoned")
                .push(script.to_string());
            shell_mock::MockResponse {
                exit_code: 0,
                stdout: String::new(),
            }
        });

        {
            let _guard = FirecrackerGuard::new("/tmp/test-vm");
            // guard drops here without defuse — should run cleanup
        }

        let captured = scripts.lock().expect("mutex must not be poisoned");
        assert_eq!(captured.len(), 1, "FirecrackerGuard must call cleanup once");
        assert!(
            captured[0].contains("fc.pid") || captured[0].contains(".fc-pid"),
            "cleanup must reference PID file"
        );
        assert!(
            captured[0].contains("/tmp/test-vm"),
            "cleanup must reference the VM directory"
        );
    }

    #[test]
    fn tap_guard_defuse_prevents_cleanup() {
        use crate::base::shell_mock;

        let call_count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = call_count.clone();
        let _handler = shell_mock::install_handler(move |_script: &str| {
            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            shell_mock::MockResponse {
                exit_code: 0,
                stdout: String::new(),
            }
        });

        {
            let mut guard = TapGuard::new(&VmSlot::new("test-vm", 0));
            guard.defuse();
        }

        assert_eq!(
            call_count.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "defused TapGuard must not run cleanup"
        );
    }

    #[test]
    fn tap_guard_runs_cleanup_on_drop() {
        use crate::base::shell_mock;

        let scripts = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let scripts_clone = scripts.clone();
        let _handler = shell_mock::install_handler(move |script: &str| {
            scripts_clone
                .lock()
                .expect("mutex must not be poisoned")
                .push(script.to_string());
            shell_mock::MockResponse {
                exit_code: 0,
                stdout: String::new(),
            }
        });

        {
            let _guard = TapGuard::new(&VmSlot::new("test-vm", 0));
        }

        let captured = scripts.lock().expect("mutex must not be poisoned");
        assert_eq!(captured.len(), 1, "TapGuard must call cleanup once");
        assert!(
            captured[0].contains("ip link del"),
            "cleanup must destroy TAP device"
        );
    }

    #[test]
    fn firecracker_guard_tolerates_cleanup_failure() {
        use crate::base::shell_mock;

        let _handler = shell_mock::install_handler(|_script: &str| shell_mock::MockResponse {
            exit_code: 1,
            stdout: String::new(),
        });

        // Should not panic even though cleanup shell command fails
        {
            let _guard = FirecrackerGuard::new("/tmp/nonexistent-vm");
        }
    }

    // is_pid_alive
    #[test]
    fn test_is_pid_alive_current_process() {
        // The current process is definitely alive.
        let my_pid = std::process::id();
        assert!(is_pid_alive(my_pid), "current process must be alive");
    }

    #[test]
    fn test_is_pid_alive_impossible_pid() {
        // PID 999999999 exceeds the maximum Linux PID (4194304) and will never exist.
        assert!(
            !is_pid_alive(999_999_999),
            "impossible PID must not be alive"
        );
    }

    // ──── Verity ──────────────────────────────────────────────────────
    //
    // The host-side cmdline shape and DM-table construction now live
    // in `mvm-verity-init` (initramfs PID 1) — those are exercised by
    // the live boot regression in `specs/runbooks/w3-verified-boot.md`.
    // The unit test below covers the only host-side helper still
    // running on the cold-boot path: the sidecar path probe.

    #[test]
    fn probe_verity_sidecar_returns_none_for_path_without_parent() {
        // A bare relative path with no parent triggers the early-return
        // branch — should not shell out, should not panic.
        let (v, h) = probe_verity_sidecar("rootfs.ext4");
        // Either the parent is "" and the probe falls through to a
        // shell call that fails, or we return early. Both produce
        // (None, None); the assertion catches either way.
        assert!(v.is_none());
        assert!(h.is_none());
    }

    // ───────────────────────────────────────────────────────────────
    // mvm-firecracker-bridge spawn helpers
    // ───────────────────────────────────────────────────────────────

    #[test]
    #[cfg(target_os = "linux")]
    fn resolve_fc_bridge_path_inner_honors_env_var() {
        // Pure resolver — exercised without touching process env. The
        // override must point at a real file or the call errors.
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let manifest_dir = std::path::PathBuf::from("/nonexistent/manifest");
        let resolved = resolve_fc_bridge_path_inner(Some(tmp.path()), None, &manifest_dir)
            .expect("env override resolves");
        assert_eq!(resolved, tmp.path());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn resolve_fc_bridge_path_inner_env_pointing_at_missing_file_errors() {
        let manifest_dir = std::path::PathBuf::from("/nonexistent/manifest");
        let bogus = std::path::Path::new("/definitely/not/there/mvm-firecracker-bridge");
        let err = resolve_fc_bridge_path_inner(Some(bogus), None, &manifest_dir)
            .expect_err("missing file must error");
        assert!(
            err.to_string().contains("not a file"),
            "error explains why: {err}"
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn resolve_fc_bridge_path_inner_missing_env_falls_back_to_adjacent() {
        // No env override, but a sibling binary exists next to the
        // current exe → resolver returns it.
        let tmp_dir = tempfile::tempdir().unwrap();
        let exe = tmp_dir.path().join("mvmctl");
        std::fs::write(&exe, b"#!fake").unwrap();
        let bridge = tmp_dir.path().join("mvm-firecracker-bridge");
        std::fs::write(&bridge, b"#!fake").unwrap();
        let manifest_dir = std::path::PathBuf::from("/nonexistent/manifest");
        let resolved =
            resolve_fc_bridge_path_inner(None, Some(&exe), &manifest_dir).expect("adjacent hit");
        assert_eq!(resolved, bridge);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn resolve_fc_bridge_path_inner_errors_when_nothing_found() {
        // All three sources miss → actionable error naming the binary
        // + the override env var so operators know how to fix it.
        let manifest_dir = std::path::PathBuf::from("/nonexistent/manifest");
        let err = resolve_fc_bridge_path_inner(None, None, &manifest_dir)
            .expect_err("no candidate must error");
        let msg = err.to_string();
        assert!(
            msg.contains("mvm-firecracker-bridge") && msg.contains("MVM_FC_BRIDGE_PATH"),
            "error names the binary + override env var: {msg}"
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn attached_bridge_guard_kills_child_on_drop() {
        // Spawn a long-lived `sleep` and wrap it; dropping the guard
        // must kill the process. Poll `kill(pid, 0)` after drop to
        // assert the child is reaped.
        let child = std::process::Command::new("sleep")
            .arg("60")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn sleep");
        let pid = child.id() as libc::pid_t;
        {
            let _guard = AttachedBridgeGuard { child: Some(child) };
            // SAFETY: kill(pid, 0) is a syscall wrapper that returns
            // 0 if the process exists. No UB.
            assert_eq!(
                unsafe { libc::kill(pid, 0) },
                0,
                "sleep should be alive while guard owns it"
            );
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
        while std::time::Instant::now() < deadline {
            // SAFETY: see above.
            if unsafe { libc::kill(pid, 0) } != 0 {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        // SAFETY: see above.
        assert_ne!(
            unsafe { libc::kill(pid, 0) },
            0,
            "sleep must be dead after guard drop"
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn attached_bridge_guard_detach_leaves_child_running() {
        // `detach` takes the Child out so dropping the guard does NOT
        // kill the process. The test reaps the detached child manually
        // to avoid leaking it past the test boundary.
        let child = std::process::Command::new("sleep")
            .arg("60")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn sleep");
        let pid = child.id() as libc::pid_t;
        let mut guard = AttachedBridgeGuard { child: Some(child) };
        let detached = guard.detach().expect("detach yields the child");
        drop(guard);
        // SAFETY: kill(pid, 0) is the standard liveness probe.
        assert_eq!(
            unsafe { libc::kill(pid, 0) },
            0,
            "sleep must still be alive after detach"
        );
        // Clean up so the test doesn't leak the process.
        // SAFETY: SIGKILL to a pid we just verified is ours.
        unsafe { libc::kill(pid, libc::SIGKILL) };
        let mut detached = detached;
        let _ = detached.wait();
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn attached_bridge_guard_empty_drop_is_noop() {
        // Legacy / no-admission path returns an empty guard. Dropping
        // it must not panic and must not attempt any process ops.
        let guard = AttachedBridgeGuard { child: None };
        drop(guard);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn write_fc_bridge_pid_file_creates_mode_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fc-bridge.pid");
        write_fc_bridge_pid_file(&path, 12345).expect("write");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "bridge pid file must be mode 0600 (got {mode:o})"
        );
        let body = std::fs::read_to_string(&path).unwrap();
        assert_eq!(body.trim(), "12345");
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn passt_path_default_when_env_unset() {
        // Production resolver — touches std::env. We test the unset
        // path which yields /usr/bin/passt; the set path is exercised
        // implicitly by `mvmctl up` integration tests.
        let saved = std::env::var_os("MVM_PASST_PATH");
        // SAFETY: scoped env var swap restored below.
        unsafe { std::env::remove_var("MVM_PASST_PATH") };
        let p = passt_path_from_env_or_default();
        assert_eq!(p, std::path::PathBuf::from("/usr/bin/passt"));
        // SAFETY: restore prior value (or remove).
        unsafe {
            match saved {
                Some(v) => std::env::set_var("MVM_PASST_PATH", v),
                None => std::env::remove_var("MVM_PASST_PATH"),
            }
        }
    }
}
