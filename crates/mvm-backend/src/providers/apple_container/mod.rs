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

use std::path::{Path, PathBuf};

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

/// Optional dm-verity attestation alongside a rootfs. When `Some`, the
/// backend attaches the Merkle tree as a second VirtioBlk device and
/// boots the VM with the verity initramfs at `initrd_path`, which
/// reads `mvm.roothash=` from the kernel cmdline, builds the
/// device-mapper target via raw ioctls, and `switch_root`s to the
/// real init. ADR-002 §W3.
///
/// All three fields must be present together — a verity sidecar
/// without a root hash is unverifiable, a root hash without the
/// sidecar is unconstructible, and either without the initramfs has
/// no way to wire up the device-mapper target before the kernel
/// commits to a root device. `None` means the backend boots the
/// rootfs as `/dev/vda rw` with no integrity check (the dev-VM
/// exemption from ADR-002 §W3.4).
#[derive(Debug, Clone)]
pub struct VerityConfig<'a> {
    /// Path to `rootfs.verity` (the Merkle hash tree).
    pub verity_path: &'a str,
    /// 64-char lowercase hex root hash.
    pub roothash: &'a str,
    /// Path to the verity initramfs (cpio.gz). Baked alongside the
    /// rootfs by `mkGuest` when `verifiedBoot = true`.
    pub initrd_path: &'a str,
}

/// Start a VM from a local kernel + ext4 rootfs using Virtualization.framework.
///
/// Convenience wrapper around `start_with_verity` for callers that don't
/// (yet) ship a verity sidecar — typically the dev VM, which is exempt
/// from verified boot per ADR-002 §W3.4.
pub fn start(
    id: &str,
    kernel_path: &str,
    rootfs_path: &str,
    cpus: u32,
    memory_mib: u64,
) -> Result<(), String> {
    start_with_verity(id, kernel_path, rootfs_path, cpus, memory_mib, None)
}

/// Start a VM with optional dm-verity sidecar.
///
/// When `verity` is Some, the kernel cmdline carries `dm-mod.create=…`
/// alongside `root=/dev/dm-0`, the rootfs.verity file is attached as
/// a second VirtioBlk device, and the kernel constructs the verity
/// target before init runs. A tampered ext4 fails verity setup and
/// panics in early boot. ADR-002 §W3.2.
pub fn start_with_verity(
    id: &str,
    kernel_path: &str,
    rootfs_path: &str,
    cpus: u32,
    memory_mib: u64,
    verity: Option<VerityConfig<'_>>,
) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        macos::start_vm(id, kernel_path, rootfs_path, cpus, memory_mib, verity)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (id, kernel_path, rootfs_path, cpus, memory_mib, verity);
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
/// The owning daemon (started by `mvmctl dev up`, or any other path that
/// calls [`start`]) listens on this path and forwards each connection to
/// the in-process VZVirtualMachine vsock, allowing other `mvmctl`
/// invocations to talk to the VM.
pub fn vsock_proxy_path(id: &str) -> std::path::PathBuf {
    #[cfg(target_os = "macos")]
    {
        macos::proxy_socket_path(id)
    }
    #[cfg(not(target_os = "macos"))]
    {
        mvm_core::config::vm_vsock_proxy_socket(id)
    }
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
    // 1. In-process Virtualization.framework reference.
    if let Ok(stream) = vsock_connect(id, port) {
        return Ok(stream);
    }
    // 2. Apple-Container cross-process proxy socket. The proxy multiplexes
    //    every port over one socket, so the client writes the target port as
    //    a 4-byte LE prefix before talking the guest protocol.
    let proxy = vsock_proxy_path(id);
    if proxy.exists() {
        use std::io::Write as _;
        let mut stream = std::os::unix::net::UnixStream::connect(&proxy)
            .map_err(|e| format!("connect proxy {}: {e}", proxy.display()))?;
        stream
            .write_all(&port.to_le_bytes())
            .map_err(|e| format!("write proxy port: {e}"))?;
        return Ok(stream);
    }
    // 3. libkrun per-port socket. A dev VM booted via the libkrun backend
    //    exposes one socket *per port* at `~/.mvm/vms/<id>/vsock-<port>.sock`,
    //    so we connect directly — no port handshake. Without this branch a
    //    healthy libkrun dev VM is misreported as "not running" (#582), which
    //    is exactly what broke `dev up`'s console attach on macOS+libkrun.
    //    Path comes from `mvm_core::config` — the single source of truth the
    //    console transport (`mvm::vsock_transport::LibkrunTransport`) shares,
    //    so the two resolvers can no longer drift (the #582 root cause).
    let libkrun = mvm_core::config::vm_vsock_port_socket(id, port);
    if libkrun.exists() {
        return std::os::unix::net::UnixStream::connect(&libkrun)
            .map_err(|e| format!("connect libkrun vsock {}: {e}", libkrun.display()));
    }
    Err(format!(
        "dev VM '{id}' is not running (no in-process VM, no proxy socket at {}, no libkrun socket at {})",
        proxy.display(),
        libkrun.display(),
    ))
}

/// Guest agent vsock port.
///
/// Must stay in lockstep with `mvm_guest::vsock::GUEST_AGENT_PORT`.
/// Duplicated here because `mvm-apple-container` is a leaf crate that
/// can't depend on `mvm-guest`. See the doc comment on the canonical
/// definition for why this lives at 5252 (>1023, so `bind(2)` succeeds
/// under W4.5's reduced agent capability set).
pub const GUEST_AGENT_PORT: u32 = 5252;

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

/// Outcome of attempting to sign one binary.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SignReport {
    pub path: PathBuf,
    /// Whether codesign was (re)applied during this call.
    pub applied: bool,
    /// Whether both VZ + Hypervisor entitlements are present after.
    pub entitlements_present: bool,
}

/// `Some(true/false)` on macOS (both required entitlements present?),
/// `None` on platforms where the question is meaningless.
pub fn entitlements_present(path: &Path) -> Option<bool> {
    #[cfg(target_os = "macos")]
    {
        Some(macos::entitlements_present(path))
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = path;
        None
    }
}

/// Ad-hoc re-sign each target with the VZ + Hypervisor entitlements and
/// report the post-sign state. No-op (empty) off macOS.
pub fn sign_binaries(targets: &[PathBuf]) -> Vec<SignReport> {
    #[cfg(target_os = "macos")]
    {
        targets.iter().map(|p| macos::sign_path(p)).collect()
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = targets;
        Vec::new()
    }
}

#[cfg(test)]
mod sign_api_tests {
    use super::*;

    #[test]
    fn sign_report_is_serializable() {
        let r = SignReport {
            path: std::path::PathBuf::from("/tmp/mvmctl"),
            applied: true,
            entitlements_present: true,
        };
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("\"applied\":true"));
        assert!(json.contains("\"entitlements_present\":true"));
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn entitlements_present_is_none_off_macos() {
        assert!(entitlements_present(std::path::Path::new("/bin/sh")).is_none());
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn sign_binaries_is_noop_off_macos() {
        let targets = vec![std::path::PathBuf::from("/bin/sh")];
        assert!(sign_binaries(&targets).is_empty());
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
    fn test_vsock_proxy_path_matches_core_helper() {
        // The proxy path is the single source of truth in mvm-core::config;
        // both this provider and the connector must resolve to it identically
        // (the #582 drift class). Assert equality rather than a $HOME-shaped
        // suffix so the test honors MVM_DATA_DIR like production does.
        let path = vsock_proxy_path("some-vm");
        assert_eq!(path, mvm_core::config::vm_vsock_proxy_socket("some-vm"));
        assert!(
            path.ends_with("vms/some-vm/vsock.sock"),
            "got {}",
            path.display()
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

    #[test]
    fn vsock_connect_any_consults_libkrun_socket() {
        // #582 regression: a libkrun dev VM's per-port socket must be part of
        // the resolution chain, so the "not running" error names it (a real
        // socket is connected — exercised end-to-end by core_demo_e2e).
        let err = vsock_connect_any("never-existed-vm-582", GUEST_AGENT_PORT)
            .expect_err("no VM, no sockets → error");
        assert!(
            err.contains("libkrun socket"),
            "error must name the libkrun socket: {err}"
        );
    }
}
