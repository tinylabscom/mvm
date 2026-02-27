use anyhow::Result;
use mvm_core::platform;

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
fn resolve_vm_dir(slot: &VmSlot) -> Result<String> {
    run_in_vm_stdout(&format!("echo {}", slot.vm_dir))
}

/// Start the Firecracker daemon inside the Lima VM (background).
fn start_firecracker_daemon(abs_dir: &str) -> Result<()> {
    ui::info("Starting Firecracker...");
    run_in_vm_visible(&format!(
        r#"
        mkdir -p {dir}
        sudo rm -f {socket}
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
fn start_vm_firecracker(abs_dir: &str, abs_socket: &str) -> Result<()> {
    ui::info("Starting Firecracker...");
    run_in_vm_visible(&format!(
        r#"
        mkdir -p {dir}
        sudo rm -f {socket}
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
fn api_put_socket(socket: &str, path: &str, data: &str) -> Result<()> {
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

/// Configure the microVM via the Firecracker API (dev-mode, legacy).
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
    let _ = run_in_vm(&format!("sudo chmod 0666 {}/v.sock 2>/dev/null", abs_dir));

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
pub fn stop() -> Result<()> {
    require_linux_env()?;

    if !firecracker::is_running()? {
        ui::info("MicroVM is not running.");
        return Ok(());
    }

    ui::info("Stopping microVM...");

    // Try graceful shutdown via API
    let _ = run_in_vm(&format!(
        r#"sudo curl -s -X PUT --unix-socket {socket} \
            --data '{{"action_type": "SendCtrlAltDel"}}' \
            "http://localhost/actions" 2>/dev/null || true"#,
        socket = API_SOCKET,
    ));

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
}

/// Boot a Firecracker VM from flake-built artifacts (headless).
///
/// Each VM gets its own directory under ~/microvm/vms/<name>/ with a
/// separate Firecracker socket, PID file, and log.  The bridge network
/// is shared, but each VM has its own TAP device and guest IP.
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
    let _ = run_in_vm(&format!("sudo chmod 0666 {}/v.sock 2>/dev/null", abs_dir));

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

/// Stop a specific named VM.
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
    let _ = run_in_vm(&format!(
        r#"sudo curl -s -X PUT --unix-socket {socket} \
            --data '{{"action_type": "SendCtrlAltDel"}}' \
            "http://localhost/actions" 2>/dev/null || true"#,
        socket = socket,
    ));

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
            let _ = network::tap_destroy(&slot);
        }
    }

    // Remove the VM directory
    let _ = run_in_vm(&format!("rm -rf {}", abs_dir));

    ui::success(&format!("VM '{}' stopped.", name));
    Ok(())
}

/// Stop all running VMs.
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

/// List all running VMs by scanning ~/microvm/vms/*/run-info.json.
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

/// Create a config drive (mvm-config label) with config.json and role-specific toml.
fn create_dev_config_drive(abs_dir: &str, config: &FlakeRunConfig) -> Result<String> {
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
        sudo umount "$MOUNT_DIR"
        rmdir "$MOUNT_DIR"
        chmod 0644 {path}
        "#,
        path = path,
        json = escaped_json,
        toml = escaped_toml,
        toml_name = toml_name,
        security_policy = security_policy,
    ))?;
    Ok(path)
}

/// Create a secrets drive (mvm-secrets label) with a stub secrets.json.
fn create_dev_secrets_drive(abs_dir: &str) -> Result<String> {
    let path = format!("{}/secrets.ext4", abs_dir);
    run_in_vm(&format!(
        r#"
        rm -f {path}
        truncate -s 4M {path}
        mkfs.ext4 -q -L mvm-secrets {path}

        MOUNT_DIR=$(mktemp -d)
        sudo mount {path} "$MOUNT_DIR"
        echo '{{}}' | sudo tee "$MOUNT_DIR/secrets.json" >/dev/null
        sudo chmod 0400 "$MOUNT_DIR/secrets.json"
        sudo umount "$MOUNT_DIR"
        rmdir "$MOUNT_DIR"
        chmod 0600 {path}
        "#,
        path = path,
    ))?;
    Ok(path)
}

/// Configure a flake-built microVM via the Firecracker API (multi-VM).
fn configure_flake_microvm(config: &FlakeRunConfig, abs_dir: &str, socket: &str) -> Result<()> {
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

    // Boot args: pass guest IP and gateway via kernel cmdline so the
    // NixOS guest (systemd-networkd + mvm-network-config service) can
    // configure eth0 without DHCP.
    let boot_args = format!(
        "console=ttyS0 reboot=k panic=1 net.ifnames=0 mvm.ip={ip}/24 mvm.gw={gw}",
        ip = slot.guest_ip,
        gw = BRIDGE_IP,
    );

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
    let config_drive = create_dev_config_drive(abs_dir, config)?;
    api_put_socket(
        socket,
        "/drives/config",
        &format!(
            r#"{{"drive_id": "config", "path_on_host": "{path}", "is_root_device": false, "is_read_only": true}}"#,
            path = config_drive,
        ),
    )?;

    // Create and attach mvm-secrets drive (stub secrets.json)
    ui::info("Creating secrets drive...");
    let secrets_drive = create_dev_secrets_drive(abs_dir)?;
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
            dir = abs_dir,
        ),
    )?;

    Ok(())
}

/// Persist run info for a named VM.
fn write_vm_run_info(config: &FlakeRunConfig, abs_dir: &str) -> Result<()> {
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
