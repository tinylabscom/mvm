use anyhow::{Context, Result};
use std::collections::BTreeMap;

use mvm_core::build_env::BuildEnvironment;
use mvm_core::instance::InstanceNet;
use mvm_core::tenant::TenantNet;

use crate::build::{BUILDER_DIR, BUILDER_OUTPUT_DISK_MIB, BUILDER_SSH_USER, builder_ssh_key_path};
use crate::scripts::render_script;

/// Boot an ephemeral Firecracker builder VM for SSH-driven builds. Returns the FC process PID.
pub(crate) fn boot_builder(
    env: &dyn BuildEnvironment,
    run_dir: &str,
    builder_net: &InstanceNet,
    tenant_net: &TenantNet,
    vcpus: u8,
    mem_mib: u32,
) -> Result<u32> {
    env.log_info("Booting builder VM...");

    // Set up TAP device for builder
    env.setup_tap(builder_net, &tenant_net.bridge_name)?;

    // Generate FC config inline as JSON (avoids depending on mvm-runtime FcConfig types)
    let fc_config_json = serde_json::json!({
        "boot-source": {
            "kernel_image_path": format!("{}/vmlinux", BUILDER_DIR),
            "boot_args": format!(
                "keep_bootcon console=ttyS0 reboot=k panic=1 pci=off ip={}::{}:255.255.255.0::eth0:off",
                builder_net.guest_ip, builder_net.gateway_ip,
            ),
        },
        "drives": [{
            "drive_id": "rootfs",
            "path_on_host": format!("{}/rootfs.ext4", BUILDER_DIR),
            "is_root_device": true,
            "is_read_only": false,
        }],
        "network-interfaces": [{
            "iface_id": "net1",
            "guest_mac": builder_net.mac,
            "host_dev_name": builder_net.tap_dev,
        }],
        "machine-config": {
            "vcpu_count": vcpus,
            "mem_size_mib": mem_mib,
        },
    });

    let config_json = serde_json::to_string_pretty(&fc_config_json)?;
    let config_path = format!("{}/fc-builder.json", run_dir);
    let socket_path = format!("{}/firecracker.socket", run_dir);
    let log_path = format!("{}/firecracker.log", run_dir);
    let pid_path = format!("{}/fc.pid", run_dir);

    // Write FC config
    env.shell_exec(&format!(
        "cat > {} << 'MVMEOF'\n{}\nMVMEOF",
        config_path, config_json
    ))?;

    // Launch Firecracker in background
    let mut launch_ctx = BTreeMap::new();
    launch_ctx.insert("run_dir", run_dir.to_string());
    launch_ctx.insert("socket", socket_path.clone());
    launch_ctx.insert("config", config_path.clone());
    launch_ctx.insert("log", log_path.clone());
    launch_ctx.insert("pid", pid_path.clone());
    env.shell_exec(&render_script("launch_firecracker_ssh", &launch_ctx)?)?;

    // Read the PID
    let pid_str = env.shell_exec_stdout(&format!("cat {}", pid_path))?;
    let pid: u32 = pid_str
        .trim()
        .parse()
        .with_context(|| format!("Failed to parse builder PID: {:?}", pid_str))?;

    env.log_info(&format!("Builder VM started (PID: {})", pid));

    // Wait for builder VM to be SSH-accessible
    env.log_info("Waiting for builder VM to become ready...");
    env.shell_exec(&format!(
        r#"
        for i in $(seq 1 60); do
            if ssh -o StrictHostKeyChecking=no -o ConnectTimeout=2 \
                   -o PasswordAuthentication=no -o BatchMode=yes -i {key} \
                   {user}@{ip} true 2>/dev/null; then
                echo "Builder ready after ${{i}}s"
                exit 0
            fi
            sleep 1
        done
        echo "Builder VM did not become ready in 60s" >&2
        exit 1
        "#,
        ip = builder_net.guest_ip,
        key = builder_ssh_key_path(),
        user = BUILDER_SSH_USER,
    ))?;

    // Probe permissions of injected authorized_keys for quick debugging
    let _ = env.shell_exec_visible(&format!(
        r#"
        ssh -o StrictHostKeyChecking=no -o PasswordAuthentication=no -o BatchMode=yes -i {key} {user}@{ip} '
            echo "[mvm] auth probe (user: {user})"
            ls -l /root/.ssh 2>/dev/null || true
            ls -l /root/.ssh/authorized_keys 2>/dev/null || true
            stat -c "mode:%a uid:%u gid:%g %n" /root/.ssh/authorized_keys 2>/dev/null || true
            if [ -f /home/ubuntu/.ssh/authorized_keys ]; then
                ls -l /home/ubuntu/.ssh/authorized_keys 2>/dev/null || true
                stat -c "mode:%a uid:%u gid:%g %n" /home/ubuntu/.ssh/authorized_keys 2>/dev/null || true
            fi
        '
        "#,
        ip = builder_net.guest_ip,
        key = builder_ssh_key_path(),
        user = BUILDER_SSH_USER,
    ));

    Ok(pid)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn boot_builder_vsock(
    env: &dyn BuildEnvironment,
    run_dir: &str,
    builder_net: &InstanceNet,
    tenant_net: &TenantNet,
    vcpus: u8,
    mem_mib: u32,
    out_disk: &str,
    in_disk: Option<&str>,
    vsock_uds: &str,
) -> Result<u32> {
    env.log_info("Booting builder VM (vsock)...");
    env.setup_tap(builder_net, &tenant_net.bridge_name)?;
    env.shell_exec(&format!(
        "truncate -s {}M {disk} && mkfs.ext4 -F {disk} >/dev/null",
        BUILDER_OUTPUT_DISK_MIB,
        disk = out_disk
    ))?;

    let mut drives = vec![
        serde_json::json!({
            "drive_id": "rootfs",
            "path_on_host": format!("{}/rootfs.ext4", BUILDER_DIR),
            "is_root_device": true,
            "is_read_only": false,
        }),
        serde_json::json!({
            "drive_id": "buildout",
            "path_on_host": out_disk,
            "is_root_device": false,
            "is_read_only": false,
        }),
    ];
    if let Some(input_disk) = in_disk {
        drives.push(serde_json::json!({
            "drive_id": "buildin",
            "path_on_host": input_disk,
            "is_root_device": false,
            "is_read_only": true,
        }));
    }

    let fc_config_json = serde_json::json!({
        "boot-source": {
            "kernel_image_path": format!("{}/vmlinux", BUILDER_DIR),
            "boot_args": format!(
                "keep_bootcon console=ttyS0 reboot=k panic=1 pci=off ip={}::{}:255.255.255.0::eth0:off",
                builder_net.guest_ip, builder_net.gateway_ip,
            ),
        },
        "drives": drives,
        "network-interfaces": [{
            "iface_id": "net1",
            "guest_mac": builder_net.mac,
            "host_dev_name": builder_net.tap_dev,
        }],
        "machine-config": {
            "vcpu_count": vcpus,
            "mem_size_mib": mem_mib,
        },
        "vsock": {
            "vsock_id": "vsock0",
            "guest_cid": mvm_guest::vsock::GUEST_CID,
            "uds_path": vsock_uds,
        }
    });

    let config_json = serde_json::to_string_pretty(&fc_config_json)?;
    let config_path = format!("{}/fc-builder.json", run_dir);
    let socket_path = format!("{}/firecracker.socket", run_dir);
    let log_path = format!("{}/firecracker.log", run_dir);
    let pid_path = format!("{}/fc.pid", run_dir);
    env.shell_exec(&format!(
        "cat > {} << 'MVMEOF'\n{}\nMVMEOF",
        config_path, config_json
    ))?;

    let mut launch_ctx = BTreeMap::new();
    launch_ctx.insert("run_dir", run_dir.to_string());
    launch_ctx.insert("socket", socket_path.clone());
    launch_ctx.insert("config", config_path.clone());
    launch_ctx.insert("log", log_path.clone());
    launch_ctx.insert("pid", pid_path.clone());
    env.shell_exec(&render_script("launch_firecracker_vsock", &launch_ctx)?)?;

    let pid_str = env.shell_exec_stdout(&format!("cat {}", pid_path))?;
    let pid: u32 = pid_str.trim().parse()?;
    env.log_info(&format!("Builder VM started (PID: {})", pid));
    Ok(pid)
}

/// Tear down the builder VM.
pub(crate) fn teardown_builder(
    env: &dyn BuildEnvironment,
    pid: u32,
    builder_net: &InstanceNet,
    run_dir: &str,
) -> Result<()> {
    env.log_info("Tearing down builder VM...");

    let _ = env.shell_exec(&format!(
        "kill {} 2>/dev/null || true; sleep 1; kill -9 {} 2>/dev/null || true",
        pid, pid
    ));

    let _ = env.teardown_tap(&builder_net.tap_dev);

    let _ = env.shell_exec(&format!("rm -rf {}", run_dir));

    Ok(())
}
