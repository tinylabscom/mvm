//! Apple Virtualization.framework backend for mvm.
//!
//! On macOS (Apple Silicon), this crate uses `objc2-virtualization` to call
//! Virtualization.framework directly from Rust. VMs boot with VZLinuxBootLoader
//! using our Nix-built kernel + ext4 rootfs — same as Firecracker, sub-second
//! startup, no OCI, no XPC daemon, no Swift.
//!
//! On other platforms, all functions return "not available" errors.

#[cfg(target_os = "macos")]
mod macos;

/// Check if Apple Virtualization is available on this platform.
pub fn is_available() -> bool {
    #[cfg(target_os = "macos")]
    {
        cfg!(target_arch = "aarch64")
    }
    #[cfg(not(target_os = "macos"))]
    {
        false
    }
}

/// Start a VM from a local kernel + ext4 rootfs using Virtualization.framework.
pub fn start(
    id: &str,
    kernel_path: &str,
    rootfs_path: &str,
    cpus: u32,
    memory_mib: u64,
) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        macos::start_vm(id, kernel_path, rootfs_path, cpus, memory_mib)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (id, kernel_path, rootfs_path, cpus, memory_mib);
        Err("Apple Virtualization not available on this platform".to_string())
    }
}

/// Stop a running VM.
pub fn stop(id: &str) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        macos::stop_vm(id)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = id;
        Err("Apple Virtualization not available on this platform".to_string())
    }
}

/// Install a launchd agent to run the VM in the background.
/// Uses resolved kernel/rootfs paths directly (build already done).
/// Ensure the binary has the virtualization entitlement, signing if needed.
/// On non-macOS this is a no-op.
pub fn ensure_signed() {
    #[cfg(target_os = "macos")]
    {
        macos::ensure_signed();
    }
}

pub fn install_launchd_direct(
    id: &str,
    kernel_path: &str,
    rootfs_path: &str,
    cpus: u32,
    memory_mib: u64,
    ports: &[String],
) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        macos::install_launchd_direct(id, kernel_path, rootfs_path, cpus, memory_mib, ports)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (id, kernel_path, rootfs_path, cpus, memory_mib, ports);
        Err("launchd not available on this platform".to_string())
    }
}

/// Discover the guest's IP address via ARP scanning.
pub fn discover_guest_ip(timeout_secs: u64) -> Option<String> {
    #[cfg(target_os = "macos")]
    {
        macos::discover_guest_ip(std::time::Duration::from_secs(timeout_secs))
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = timeout_secs;
        None
    }
}

/// Start a port proxy from localhost:host_port to guest tcp/guest_port via vsock.
pub fn start_port_proxy(vm_id: &str, host_port: u16, guest_port: u16) {
    #[cfg(target_os = "macos")]
    {
        macos::start_port_proxy(vm_id, host_port, guest_port);
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (vm_id, host_port, guest_port);
    }
}

/// Connect to the guest vsock on the given port, returning a Unix stream.
///
/// The VM must have been started in this process (in-process VM tracking).
/// Returns a `UnixStream` wrapping the vsock connection's file descriptor.
pub fn vsock_connect(id: &str, port: u32) -> Result<std::os::unix::net::UnixStream, String> {
    #[cfg(target_os = "macos")]
    {
        macos::vsock_connect(id, port)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (id, port);
        Err("Apple Virtualization not available on this platform".to_string())
    }
}

/// Path to the cross-process vsock proxy Unix socket for VM `id`.
///
/// The dev daemon (started by `mvmctl dev up`) listens on this path and
/// forwards each connection to the in-process VZVirtualMachine vsock,
/// allowing other `mvmctl` invocations to talk to the dev VM.
pub fn vsock_proxy_path(id: &str) -> std::path::PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    std::path::PathBuf::from(format!("{home}/.mvm/vms/{id}/vsock.sock"))
}

/// Connect to VM `id`'s guest vsock, falling back to the cross-process
/// proxy socket when the VM isn't running in this process.
///
/// Resolution order:
///   1. In-process Virtualization.framework reference (works only in the
///      daemon process that called [`start`]).
///   2. The proxy Unix socket at [`vsock_proxy_path`] (the daemon listens
///      there for cross-process clients).
///
/// Returns a clear error when neither is reachable so callers can decide
/// whether to surface the message or auto-start the dev daemon.
pub fn vsock_connect_any(id: &str, port: u32) -> Result<std::os::unix::net::UnixStream, String> {
    if let Ok(stream) = vsock_connect(id, port) {
        return Ok(stream);
    }
    let proxy = vsock_proxy_path(id);
    if !proxy.exists() {
        return Err(format!(
            "dev VM '{id}' is not running (no in-process VM and no proxy socket at {})",
            proxy.display(),
        ));
    }
    use std::io::Write as _;
    let mut stream = std::os::unix::net::UnixStream::connect(&proxy)
        .map_err(|e| format!("connect proxy {}: {e}", proxy.display()))?;
    stream
        .write_all(&port.to_le_bytes())
        .map_err(|e| format!("write proxy port: {e}"))?;
    Ok(stream)
}

/// Guest agent vsock port.
pub const GUEST_AGENT_PORT: u32 = 52;

/// List running VM IDs.
pub fn list_ids() -> Vec<String> {
    #[cfg(target_os = "macos")]
    {
        macos::list_vm_ids()
    }
    #[cfg(not(target_os = "macos"))]
    {
        vec![]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_available() {
        let _ = is_available();
    }

    #[test]
    fn test_list_ids_empty() {
        // No VMs running in test
        let _ = list_ids();
    }

    #[test]
    fn test_vsock_proxy_path_under_home() {
        // Whatever HOME points at, the path must resolve below it and end
        // with the conventional segment used by the dev daemon.
        let path = vsock_proxy_path("some-vm");
        let suffix = std::path::Path::new(".mvm/vms/some-vm/vsock.sock");
        assert!(
            path.ends_with(suffix),
            "expected path to end with {} but got {}",
            suffix.display(),
            path.display(),
        );
    }

    #[test]
    fn test_vsock_connect_any_reports_missing_proxy() {
        // No VM is running in this process and the synthesised proxy
        // socket path does not exist — the helper must surface a clear
        // message pointing at the missing socket so callers can decide
        // whether to auto-start the dev daemon or surface the error.
        let id = "never-existed-vm-id-for-tests";
        let err = vsock_connect_any(id, GUEST_AGENT_PORT)
            .expect_err("connect must fail when neither in-process nor proxy is available");
        assert!(err.contains(id), "got: {err}");
        assert!(err.contains("not running"), "got: {err}");
        assert!(err.contains("vsock.sock"), "got: {err}");
    }
}
