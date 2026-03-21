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
/// Replays the current CLI args (minus -d) via launchd.
pub fn install_launchd(id: &str) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        macos::install_launchd_agent(id)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = id;
        Err("launchd not available on this platform".to_string())
    }
}

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
