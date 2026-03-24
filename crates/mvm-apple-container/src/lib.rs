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
}
