use anyhow::{Context, Result};

use crate::shell;

const JAILER_PATH: &str = "/usr/local/bin/jailer";

/// Compute a unique uid/gid for a jailed Firecracker instance.
///
/// Formula: 10000 + (tenant_net_id * 256) + ip_offset
/// tenant_net_id is coordinator-assigned and cluster-unique, guaranteeing no collisions.
pub fn compute_uid(tenant_net_id: u16, ip_offset: u8) -> u32 {
    10000 + (tenant_net_id as u32 * 256) + ip_offset as u32
}

/// Check if the Firecracker jailer binary is available inside the VM.
pub fn jailer_available() -> Result<bool> {
    let out = shell::run_in_vm_stdout(&format!("test -x {} && echo yes || echo no", JAILER_PATH))?;
    Ok(out.trim() == "yes")
}

/// Set up the jail directory structure for a Firecracker instance.
///
/// Creates chroot at `<instance_dir>/jail/root/` with device nodes
/// and hard-links to kernel, rootfs, and config.
fn setup_jail_dir(
    instance_dir: &str,
    kernel_path: &str,
    rootfs_path: &str,
    config_path: Option<&str>,
    data_disk_path: Option<&str>,
    secrets_disk_path: Option<&str>,
) -> Result<String> {
    let jail_root = format!("{}/jail/root", instance_dir);

    let mut link_cmds = format!(
        r#"
        mkdir -p {root}/dev/net
        # Create device nodes
        [ -e {root}/dev/kvm ] || mknod {root}/dev/kvm c 10 232 2>/dev/null || true
        [ -e {root}/dev/net/tun ] || mknod {root}/dev/net/tun c 10 200 2>/dev/null || true
        # Hard-link artifacts (avoids copies, same filesystem)
        ln -f {kernel} {root}/vmlinux 2>/dev/null || cp {kernel} {root}/vmlinux
        ln -f {rootfs} {root}/rootfs.ext4 2>/dev/null || cp {rootfs} {root}/rootfs.ext4
        "#,
        root = jail_root,
        kernel = kernel_path,
        rootfs = rootfs_path,
    );

    if let Some(config) = config_path {
        link_cmds.push_str(&format!("cp {} {}/fc.json\n", config, jail_root));
    }

    if let Some(data) = data_disk_path {
        link_cmds.push_str(&format!(
            "ln -f {} {}/data.ext4 2>/dev/null || cp {} {}/data.ext4\n",
            data, jail_root, data, jail_root
        ));
    }

    if let Some(secrets) = secrets_disk_path {
        link_cmds.push_str(&format!(
            "ln -f {} {}/secrets.ext4 2>/dev/null || cp {} {}/secrets.ext4\n",
            secrets, jail_root, secrets, jail_root
        ));
    }

    shell::run_in_vm(&link_cmds)
        .with_context(|| format!("Failed to set up jail directory at {}", jail_root))?;

    Ok(jail_root)
}

/// Launch Firecracker via the jailer with chroot isolation.
///
/// Sets up a per-instance jail with unique uid/gid, device nodes,
/// and hard-linked artifacts. Returns the PID of the jailer process.
///
/// The API socket is created inside the jail at `<jail_root>/firecracker.socket`.
/// `config_path` is None for snapshot-restore mode (wake).
#[allow(clippy::too_many_arguments)]
pub fn launch_jailed(
    instance_dir: &str,
    instance_id: &str,
    tenant_net_id: u16,
    ip_offset: u8,
    kernel_path: &str,
    rootfs_path: &str,
    config_path: Option<&str>,
    data_disk_path: Option<&str>,
    secrets_disk_path: Option<&str>,
    seccomp_filter: Option<&str>,
    log_path: &str,
    pid_path: &str,
) -> Result<(u32, String)> {
    let uid = compute_uid(tenant_net_id, ip_offset);
    let jail_root = setup_jail_dir(
        instance_dir,
        kernel_path,
        rootfs_path,
        config_path,
        data_disk_path,
        secrets_disk_path,
    )?;

    // The API socket path from the host's perspective
    let socket_path = format!("{}/firecracker.socket", jail_root);

    let config_arg = if config_path.is_some() {
        "--config-file /fc.json".to_string()
    } else {
        String::new()
    };

    let seccomp_arg = seccomp_filter
        .map(|p| format!("--seccomp-filter {}", p))
        .unwrap_or_default();

    let jail_base = format!("{}/jail", instance_dir);
    shell::run_in_vm(&format!(
        r#"
        rm -f {socket}
        {jailer} \
            --id {id} \
            --exec-file $(which firecracker) \
            --uid {uid} \
            --gid {uid} \
            --chroot-base-dir {jail_base} \
            -- \
            --api-sock /firecracker.socket \
            {config_arg} \
            {seccomp_arg} \
            --log-path {log} \
            --level Info \
            &
        JAIL_PID=$!
        echo $JAIL_PID > {pid}
        disown $JAIL_PID

        # Wait for API socket
        for i in $(seq 1 30); do
            [ -S {socket} ] && break
            sleep 0.1
        done
        "#,
        jailer = JAILER_PATH,
        id = instance_id,
        uid = uid,
        jail_base = jail_base,
        config_arg = config_arg,
        seccomp_arg = seccomp_arg,
        socket = socket_path,
        log = log_path,
        pid = pid_path,
    ))
    .with_context(|| format!("Failed to launch jailed Firecracker for {}", instance_id))?;

    let pid_str = shell::run_in_vm_stdout(&format!("cat {}", pid_path))?;
    let pid: u32 = pid_str
        .trim()
        .parse()
        .with_context(|| format!("Failed to parse jailer PID: {:?}", pid_str))?;

    Ok((pid, socket_path))
}

/// Launch Firecracker directly (no jailer).
///
/// Used as a fallback when the jailer binary is not available.
/// `config_path` is None for snapshot-restore mode (wake).
/// Returns (PID, socket_path).
pub fn launch_direct(
    config_path: Option<&str>,
    socket_path: &str,
    log_path: &str,
    pid_path: &str,
    seccomp_filter: Option<&str>,
) -> Result<u32> {
    let config_arg = match config_path {
        Some(path) => format!("--config-file {}", path),
        None => String::new(),
    };

    let seccomp_arg = seccomp_filter
        .map(|p| format!("--seccomp-filter {}", p))
        .unwrap_or_default();

    shell::run_in_vm(&format!(
        r#"
        rm -f {socket}
        firecracker \
            --api-sock {socket} \
            {config_arg} \
            {seccomp_arg} \
            --log-path {log} \
            --level Info \
            &
        FC_PID=$!
        echo $FC_PID > {pid}
        disown $FC_PID

        # Wait for API socket
        for i in $(seq 1 30); do
            [ -S {socket} ] && break
            sleep 0.1
        done
        "#,
        socket = socket_path,
        config_arg = config_arg,
        seccomp_arg = seccomp_arg,
        log = log_path,
        pid = pid_path,
    ))
    .with_context(|| "Failed to launch Firecracker directly")?;

    let pid_str = shell::run_in_vm_stdout(&format!("cat {}", pid_path))?;
    let pid: u32 = pid_str
        .trim()
        .parse()
        .with_context(|| format!("Failed to parse FC PID: {:?}", pid_str))?;

    Ok(pid)
}

/// Extract the IP offset from a guest IP address (last octet).
pub fn ip_offset_from_guest_ip(guest_ip: &str) -> u8 {
    guest_ip
        .rsplit('.')
        .next()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

/// Clean up jail directory for a destroyed instance.
pub fn cleanup_jail(instance_dir: &str) -> Result<()> {
    shell::run_in_vm(&format!("rm -rf {}/jail", instance_dir))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_uid_no_collision() {
        let uid_a = compute_uid(3, 5);
        let uid_b = compute_uid(17, 5);
        assert_ne!(uid_a, uid_b);

        let uid_c = compute_uid(3, 10);
        assert_ne!(uid_a, uid_c);
    }

    #[test]
    fn test_compute_uid_deterministic() {
        assert_eq!(compute_uid(3, 5), 10000 + 3 * 256 + 5);
        assert_eq!(compute_uid(0, 0), 10000);
        assert_eq!(compute_uid(4095, 254), 10000 + 4095 * 256 + 254);
    }

    #[test]
    fn test_compute_uid_range() {
        // Minimum uid is 10000 (tenant 0, offset 0)
        assert_eq!(compute_uid(0, 0), 10000);
        // Maximum uid: tenant_net_id max 4095, offset max 254
        let max_uid = compute_uid(4095, 254);
        assert_eq!(max_uid, 10000 + 4095 * 256 + 254);
        // Should not overflow into system reserved range
        assert!(max_uid < u32::MAX);
    }

    #[test]
    fn test_ip_offset_from_guest_ip() {
        assert_eq!(ip_offset_from_guest_ip("10.240.3.5"), 5);
        assert_eq!(ip_offset_from_guest_ip("10.240.3.254"), 254);
        assert_eq!(ip_offset_from_guest_ip("192.168.1.1"), 1);
    }

    #[test]
    fn test_ip_offset_from_guest_ip_invalid() {
        assert_eq!(ip_offset_from_guest_ip(""), 0);
        assert_eq!(ip_offset_from_guest_ip("not-an-ip"), 0);
    }
}
