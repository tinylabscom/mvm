//! Legacy single-VM lifecycle: configure/start/stop the dev-mode microVM.

use anyhow::{Context, Result};
use tracing::{instrument, warn};

use crate::base::config::{FC_MAC, GUEST_IP, MICROVM_DIR, MvmState, TAP_DEV, TAP_IP};
use crate::base::shell::{run_in_vm, run_in_vm_stdout};
use crate::base::ui;
use crate::{firecracker, network};

use super::daemon::{
    api_put_socket, firecracker_api_socket_path, prepare_vsock_runtime_dir,
    start_firecracker_daemon,
};
use super::guards::FirecrackerGuard;
use super::{firecracker_vsock_uds_path, require_linux_env, resolve_microvm_dir};

/// Configure the microVM via the Firecracker API (dev-mode, legacy).
#[instrument(skip_all)]
fn configure_microvm(state: &MvmState, abs_dir: &str) -> Result<()> {
    let api_socket = firecracker_api_socket_path(abs_dir);
    ui::info("Configuring logger...");
    api_put_socket(
        &api_socket,
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
             `mvmctl bootstrap` to populate the builder VM image first.",
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
    api_put_socket(
        &api_socket,
        "/boot-source",
        &format!(
            r#"{{"kernel_image_path": "{kernel}", "boot_args": "{args}"}}"#,
            kernel = kernel_path.display(),
            args = kernel_boot_args,
        ),
    )?;

    ui::info(&format!("Setting rootfs: {}", state.rootfs));
    api_put_socket(
        &api_socket,
        "/drives/rootfs",
        &format!(
            r#"{{"drive_id": "rootfs", "path_on_host": "{rootfs}", "is_root_device": true, "is_read_only": false}}"#,
            rootfs = rootfs_path,
        ),
    )?;

    ui::info("Setting network interface...");
    api_put_socket(
        &api_socket,
        "/network-interfaces/net1",
        &format!(
            r#"{{"iface_id": "net1", "guest_mac": "{mac}", "host_dev_name": "{tap}"}}"#,
            mac = FC_MAC,
            tap = TAP_DEV,
        ),
    )?;

    ui::info("Setting vsock device...");
    prepare_vsock_runtime_dir(abs_dir);
    let vsock = firecracker_vsock_uds_path(abs_dir);
    api_put_socket(
        &api_socket,
        "/vsock",
        &format!(
            r#"{{"vsock_id": "vsock0", "guest_cid": {cid}, "uds_path": "{vsock}"}}"#,
            cid = mvm_agentd::vsock::GUEST_CID,
            vsock = vsock,
        ),
    )?;

    Ok(())
}

/// Full start sequence: network, firecracker, configure, boot (headless).
///
/// MicroVMs never have SSH enabled. They run as headless workloads and
/// communicate via vsock. Use `mvmctl console` for interactive guest access
/// (dev-mode only).
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
    api_put_socket(
        &firecracker_api_socket_path(&abs_dir),
        "/actions",
        r#"{"action_type": "InstanceStart"}"#,
    )?;

    mvm_core::observability::metrics::global()
        .vm_start_duration_ms
        .store(
            vm_start.elapsed().as_millis() as u64,
            std::sync::atomic::Ordering::Relaxed,
        );

    // Make vsock socket accessible to the current user
    let vsock = firecracker_vsock_uds_path(&abs_dir);
    if let Err(e) = run_in_vm(&format!(
        "sudo chmod 0666 {vsock} 2>/dev/null",
        vsock = vsock,
    )) {
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
        "Use 'mvmctl console' for interactive guest access (dev-mode only).",
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

    let api_socket = firecracker_api_socket_path(MICROVM_DIR);

    // Try graceful shutdown via API
    if let Err(e) = run_in_vm(&format!(
        r#"sudo curl -s -X PUT --unix-socket {socket} \
            --data '{{"action_type": "SendCtrlAltDel"}}' \
            "http://localhost/actions" 2>/dev/null || true"#,
        socket = api_socket,
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
        rm -f {vsock} {dir}/v.sock
        "#,
        dir = MICROVM_DIR,
        socket = api_socket,
        vsock = firecracker_vsock_uds_path(MICROVM_DIR),
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

    if kernel.is_empty() || rootfs.is_empty() {
        anyhow::bail!(
            "Missing microVM assets in {}. Run 'mvmctl setup' first.\n  kernel={:?} rootfs={:?}",
            MICROVM_DIR,
            kernel,
            rootfs,
        );
    }

    Ok(MvmState {
        kernel,
        rootfs,
        fc_pid: None,
    })
}
