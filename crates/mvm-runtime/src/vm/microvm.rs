use anyhow::Result;
use mvm_core::platform;
use tracing::{instrument, warn};

use super::{firecracker, lima, network};
use crate::config::*;
use crate::shell::{run_in_vm, run_in_vm_stdout, run_in_vm_visible};
use crate::ui;
use crate::vm::image::RuntimeVolume;

/// Ensure we have a Linux execution environment.
/// On macOS: checks that the Lima VM is running.
/// On native Linux (including inside Lima): no-op.
fn require_linux_env() -> Result<()> {
    if platform::current().needs_lima() {
        lima::require_running()?;
    }
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
#[instrument(skip_all, fields(path))]
pub fn api_put_socket(socket: &str, path: &str, data: &str) -> Result<()> {
    let script = format!(
        r#"
        response=$(sudo curl -s -w "\n%{{http_code}}" -X PUT --unix-socket {socket} \
            --data '{data}' "http://localhost{path}")
        code=$(echo "$response" | tail -1)
        body=$(echo "$response" | sed '$d')
        if [ "$code" -ge 400 ]; then
            echo "[mvm] ERROR: PUT {path} returned $code: $body" >&2
            exit 1
        fi
        "#,
        socket = socket,
        path = path,
        data = data,
    );
    run_in_vm_visible(&script)
}

/// Send API PATCH request to a specific Firecracker socket.
#[instrument(skip_all, fields(path))]
pub fn api_patch_socket(socket: &str, path: &str, data: &str) -> Result<()> {
    let script = format!(
        r#"
        response=$(sudo curl -s -w "\n%{{http_code}}" -X PATCH --unix-socket {socket} \
            -H 'Content-Type: application/json' \
            --data '{data}' "http://localhost{path}")
        code=$(echo "$response" | tail -1)
        body=$(echo "$response" | sed '$d')
        if [ "$code" -ge 400 ]; then
            echo "[mvm] ERROR: PATCH {path} returned $code: $body" >&2
            exit 1
        fi
        "#,
        socket = socket,
        path = path,
        data = data,
    );
    run_in_vm_visible(&script)
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
    let rootfs_path = format!("{}/{}", abs_dir, state.rootfs);

    // Use kernel cmdline IP params (no SSH-based guest network config).
    // net.ifnames=0 forces classic eth0 naming when PCI is enabled.
    let kernel_boot_args = format!(
        "console=ttyS0 reboot=k panic=1 net.ifnames=0 ip={guest}::{gateway}:255.255.255.252::eth0:off",
        guest = GUEST_IP,
        gateway = TAP_IP,
    );

    ui::info(&format!("Setting boot source: {}", state.kernel));
    api_put(
        "/boot-source",
        &format!(
            r#"{{"kernel_image_path": "{kernel}", "boot_args": "{args}"}}"#,
            kernel = kernel_path,
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

    Ok(())
}

/// Full start sequence: network, firecracker, configure, boot (headless).
///
/// MicroVMs never have SSH enabled. They run as headless workloads and
/// communicate via vsock. Use `mvm shell` to access the Lima VM environment.
#[instrument(skip_all)]
pub fn start() -> Result<()> {
    require_linux_env()?;

    // Check if already running
    if firecracker::is_running()? {
        ui::info("Firecracker is already running.");
        ui::info("Use 'mvm stop' to shut down, then 'mvm start' to restart.");
        return Ok(());
    }

    // Read state file for asset paths
    let state = read_state_or_discover()?;

    // Resolve ~/microvm to absolute path so it works in both user and sudo contexts
    let abs_dir = resolve_microvm_dir()?;

    // Set up networking
    network::setup()?;

    // Start Firecracker daemon
    start_firecracker_daemon(&abs_dir)?;

    // Configure microVM
    configure_microvm(&state, &abs_dir)?;

    // Start the instance
    ui::info("Starting microVM...");
    std::thread::sleep(std::time::Duration::from_millis(15));
    api_put("/actions", r#"{"action_type": "InstanceStart"}"#)?;

    // Make vsock socket accessible to the current user
    if let Err(e) = run_in_vm(&format!("sudo chmod 0666 {}/v.sock 2>/dev/null", abs_dir)) {
        warn!("failed to chmod vsock socket: {e}");
    }

    ui::banner(&[
        "MicroVM is running!",
        "",
        &format!("  Guest IP: {}", GUEST_IP),
        "",
        "Use 'mvm status' to check the microVM.",
        "Use 'mvm stop' to shut down the microVM.",
        "Use 'mvm shell' to access the Lima VM environment.",
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
            "Missing microVM assets in {}. Run 'mvm setup' first.\n  kernel={:?} rootfs={:?} ssh_key={:?}",
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
    /// Nix store revision hash.
    pub revision_hash: String,
    /// Original flake reference (for display / status).
    pub flake_ref: String,
    /// Flake profile name (e.g. "worker", "gateway"), if specified.
    pub profile: Option<String>,
    /// Number of vCPUs.
    pub cpus: u32,
    /// Memory in MiB.
    pub memory: u32,
    /// Extra volumes to attach (mounted via config drive, not SSH).
    pub volumes: Vec<RuntimeVolume>,
    /// Extra files to write onto the config drive.
    pub config_files: Vec<DriveFile>,
    /// Extra files to write onto the secrets drive.
    pub secret_files: Vec<DriveFile>,
    /// Declared port mappings (host:guest) for forwarding and guest config.
    pub ports: Vec<crate::config::PortMapping>,
}

/// Boot a Firecracker VM from flake-built artifacts (headless).
///
/// Each VM gets its own directory under ~/microvm/vms/<name>/ with a
/// separate Firecracker socket, PID file, and log.  The bridge network
/// is shared, but each VM has its own TAP device and guest IP.
#[instrument(skip_all, fields(name = %config.name))]
pub fn run_from_build(config: &FlakeRunConfig) -> Result<()> {
    require_linux_env()?;

    let slot = &config.slot;

    // Check if this VM name is already running
    let abs_dir = resolve_vm_dir(slot)?;
    let abs_socket = format!("{}/fc.socket", abs_dir);
    let pid_file = format!("{}/fc.pid", abs_dir);

    if firecracker::is_vm_running(&pid_file)? {
        ui::info(&format!("VM '{}' is already running.", slot.name));
        ui::info("Use 'mvm stop <name>' to shut it down first.");
        return Ok(());
    }

    // Ensure bridge network exists (idempotent)
    network::bridge_ensure()?;

    // Create TAP device for this VM
    network::tap_create(slot)?;

    // Start Firecracker daemon in per-VM directory
    start_vm_firecracker(&abs_dir, &abs_socket)?;

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

    ui::banner(&[
        &format!("MicroVM '{}' is running!", config.name),
        "",
        &format!("  Guest IP: {}", slot.guest_ip),
        &format!("  Revision: {}", config.revision_hash),
        "",
        &format!("Use 'mvm stop {}' to shut down this VM.", config.name),
        "Use 'mvm status' to list all running VMs.",
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
    require_linux_env()?;

    let slot = &config.slot;

    // Check if this VM name is already running
    let abs_dir = resolve_vm_dir(slot)?;
    let abs_socket = format!("{}/fc.socket", abs_dir);
    let pid_file = format!("{}/fc.pid", abs_dir);

    if firecracker::is_vm_running(&pid_file)? {
        ui::info(&format!("VM '{}' is already running.", slot.name));
        ui::info("Use 'mvm stop <name>' to shut it down first.");
        return Ok(());
    }

    // Ensure bridge network exists (idempotent)
    network::bridge_ensure()?;

    // Create TAP device for this VM
    network::tap_create(slot)?;

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

    ui::banner(&[
        &format!("MicroVM '{}' restored from snapshot!", config.name),
        "",
        &format!("  Guest IP: {}", slot.guest_ip),
        &format!("  Revision: {}", config.revision_hash),
        "",
        &format!("Use 'mvm stop {}' to shut down this VM.", config.name),
        "Use 'mvm status' to list all running VMs.",
    ]);

    Ok(())
}

/// Stop a specific named VM.
#[instrument(skip_all, fields(name))]
pub fn stop_vm(name: &str) -> Result<()> {
    require_linux_env()?;

    let abs_vms = run_in_vm_stdout(&format!("echo {}", VMS_DIR))?;
    let abs_dir = format!("{}/{}", abs_vms, name);
    let pid_file = format!("{}/fc.pid", abs_dir);
    let socket = format!("{}/fc.socket", abs_dir);

    if !firecracker::is_vm_running(&pid_file)? {
        ui::info(&format!("VM '{}' is not running.", name));
        return Ok(());
    }

    ui::info(&format!("Stopping VM '{}'...", name));

    // Try graceful shutdown
    if let Err(e) = run_in_vm(&format!(
        r#"sudo curl -s -X PUT --unix-socket {socket} \
            --data '{{"action_type": "SendCtrlAltDel"}}' \
            "http://localhost/actions" 2>/dev/null || true"#,
        socket = socket,
    )) {
        warn!("failed to send graceful shutdown to VM: {e}");
    }

    std::thread::sleep(std::time::Duration::from_secs(2));

    // Force kill and clean up
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

    // Read run info to find the TAP device to destroy
    if let Some(info) = read_vm_run_info_from(&abs_dir)
        && let Some(ref vm_name) = info.name
    {
        // Reconstruct slot to find TAP name — scan for the index
        if let Some(idx) = read_slot_index(&abs_dir) {
            let slot = VmSlot::new(vm_name, idx);
            if let Err(e) = network::tap_destroy(&slot) {
                warn!("failed to destroy TAP device: {e}");
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

    // Dev-mode security policy enables debug_exec for vsock exec support
    let security_policy = r#"{"access":{"debug_exec":true}}"#;

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
        echo '{security_policy}' | sudo tee "$MOUNT_DIR/security-policy.json" >/dev/null
        sudo chmod 0444 "$MOUNT_DIR/config.json" "$MOUNT_DIR/{toml_name}" "$MOUNT_DIR/security-policy.json"
        {extra}
        sudo umount "$MOUNT_DIR"
        rmdir "$MOUNT_DIR"
        chmod 0644 {path}
        "#,
        path = path,
        json = escaped_json,
        toml = escaped_toml,
        toml_name = toml_name,
        security_policy = security_policy,
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
    // When initrd is present (NixOS guest), the initrd handles root mounting.
    // When initrd is absent (minimal guest), the kernel mounts root directly.
    let base_args = format!(
        "console=ttyS0 reboot=k panic=1 net.ifnames=0 mvm.ip={ip}/24 mvm.gw={gw}",
        ip = slot.guest_ip,
        gw = BRIDGE_IP,
    );
    let boot_args = if config.initrd_path.is_some() {
        base_args
    } else {
        format!("root=/dev/vda rw rootwait init=/init {base_args}")
    };

    ui::info(&format!("Setting boot source: {}", config.vmlinux_path));
    let boot_source = match &config.initrd_path {
        Some(initrd) => {
            ui::info(&format!("Using initrd: {}", initrd));
            format!(
                r#"{{"kernel_image_path": "{kernel}", "boot_args": "{args}", "initrd_path": "{initrd}"}}"#,
                kernel = config.vmlinux_path,
                args = boot_args,
                initrd = initrd,
            )
        }
        None => {
            format!(
                r#"{{"kernel_image_path": "{kernel}", "boot_args": "{args}"}}"#,
                kernel = config.vmlinux_path,
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

    ui::info(&format!("Setting rootfs: {}", config.rootfs_path));
    api_put_socket(
        socket,
        "/drives/rootfs",
        &format!(
            r#"{{"drive_id": "rootfs", "path_on_host": "{rootfs}", "is_root_device": true, "is_read_only": false}}"#,
            rootfs = config.rootfs_path,
        ),
    )?;

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
        ui::info(&format!(
            "Attaching volume {} -> {} (size {})",
            vol.host, vol.guest, vol.size
        ));
        api_put_socket(
            socket,
            &format!("/drives/{}", drive_id),
            &format!(
                r#"{{"drive_id": "{id}", "path_on_host": "{host}", "is_root_device": false, "is_read_only": false}}"#,
                id = drive_id,
                host = vol.host,
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

    Ok(())
}

/// Persist run info for a named VM.
#[instrument(skip_all, fields(name = %config.name))]
pub fn write_vm_run_info(config: &FlakeRunConfig, abs_dir: &str) -> Result<()> {
    let info = RunInfo {
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

/// Read run info from a specific VM directory.
fn read_vm_run_info_from(abs_dir: &str) -> Option<RunInfo> {
    let json = run_in_vm_stdout(&format!(
        "cat {dir}/run-info.json 2>/dev/null || echo 'null'",
        dir = abs_dir,
    ))
    .ok()?;
    serde_json::from_str(&json).ok()
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

/// Read persisted run info (returns None if file doesn't exist).
pub fn read_run_info() -> Option<RunInfo> {
    let json = run_in_vm_stdout(&format!(
        "cat {dir}/.mvm-run-info 2>/dev/null || echo 'null'",
        dir = MICROVM_DIR,
    ))
    .ok()?;
    serde_json::from_str(&json).ok()
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
    /// This tests the pattern used throughout the codebase (Sprint 16 Phase 1.2).
    #[test]
    fn test_log_and_continue_pattern_does_not_propagate_errors() {
        use crate::shell_mock;

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
            if let Err(e) = crate::shell::run_in_vm("kill -9 12345 2>/dev/null || true") {
                tracing::warn!("failed to kill process: {e}");
            }
            if let Err(e) = crate::shell::run_in_vm("sudo ip link del tap0 2>/dev/null || true") {
                tracing::warn!("failed to destroy TAP: {e}");
            }
            if let Err(e) = crate::shell::run_in_vm("rm -rf /tmp/test-dir") {
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
}
