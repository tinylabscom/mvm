//! Bridge-inserting configure path + [`run_supervisor_with_bridge`].
//!
//! Mirrors the plain `configure` / `run_supervisor` path in `start.rs`
//! but interposes the gateway audit bridge between libkrun and the
//! userspace network gateway (`passt` / native gateway) so every
//! virtio-net frame can be spliced, sniffed, and audited. Refuses the
//! no-NIC networking modes — those go through `run_supervisor` instead.

#[cfg(all(feature = "libkrun-sys", target_family = "unix"))]
use std::os::fd::{AsRawFd, OwnedFd};

#[cfg(all(feature = "libkrun-sys", target_family = "unix"))]
use crate::context::{KrunContext, NetworkingMode};
#[cfg(feature = "libkrun-sys")]
use crate::error::{Error, install_hint, is_available};
#[cfg(feature = "libkrun-sys")]
use crate::supervisor::SupervisorConfig;

#[cfg(feature = "libkrun-sys")]
use crate::start::install_shutdown_handler;
#[cfg(all(feature = "libkrun-sys", target_family = "unix"))]
use crate::start::{GatewayHandle, configure_pre_net};

#[cfg(all(feature = "libkrun-sys", target_family = "unix"))]
use crate::sys;

#[cfg(all(feature = "libkrun-sys", target_family = "unix"))]
use crate::{native_gateway, passt};

/// Endpoint fds the gateway audit bridge needs to splice between
/// libkrun and the userspace network gateway (`passt` / native gateway).
///
/// Constructed by `configure_with_gateway_for_bridge` alongside
/// the libkrun `sys::Context` and a [`GatewayHandle`] that keeps
/// the gateway child process alive. Consumed by the bridge factory
/// closure passed to [`run_supervisor_with_bridge`], which builds
/// `mvm_hostd::supervisor::gateway_bridge::BridgeEndpoints` from these
/// values and calls `spawn_bridge_thread`.
///
/// Variants mirror `BridgeEndpoints` one-for-one so the bin can
/// convert without case analysis: `Passt` → `BridgeEndpoints::Passt`,
/// `LibkrunNativeGateway` → `BridgeEndpoints::LibkrunNativeGateway`.
#[cfg(all(feature = "libkrun-sys", target_family = "unix"))]
pub enum BridgeFds {
    /// Linux libkrun + passt. Both sides are `SOCK_STREAM`:
    /// - `gateway_fd` is the parent half of passt's socketpair;
    ///   the bridge reads/writes raw virtio-net frames from passt.
    /// - `supervisor_fd` is the supervisor half of an inner
    ///   `socketpair(2)` whose other half was handed to libkrun via
    ///   `add_net_unixstream_fd`; the bridge reads/writes the same
    ///   raw frames toward libkrun.
    ///
    /// The bridge thread `tokio::io::copy_bidirectional`s the two
    /// halves, sniffs first-byte-per-direction to emit
    /// `gateway.flow_opened` audit entries, and emits paired
    /// `gateway.flow_closed` on EOF or bridge error.
    Passt {
        gateway_fd: OwnedFd,
        supervisor_fd: OwnedFd,
    },
    /// macOS libkrun + native gateway. `SOCK_DGRAM`:
    /// - `gateway_socket_path` is the path the gateway bound its
    ///   listener at on spawn.
    /// - `supervisor_listen_path` is where libkrun has been told
    ///   to connect (via `add_net_unixgram_path`); the bridge
    ///   binds a `UnixDatagram` there inside its thread before
    ///   libkrun's net device probes.
    ///
    /// libkrun is an anonymous unixgram client — the bridge caches
    /// its autobind peer address from the first `recv_from`, then
    /// uses `send_to(peer, …)` for the ingress direction.
    LibkrunNativeGateway {
        gateway_socket_path: std::path::PathBuf,
        supervisor_listen_path: std::path::PathBuf,
    },
}

/// Bridge-inserting variant of `configure_with_gateway`. Spawns
/// passt / native gateway, then
/// interposes a supervisor-owned socket pair (`Passt`) or listener
/// path (`LibkrunNativeGateway`) between libkrun and the gateway so the
/// gateway audit bridge can splice every byte through itself.
///
/// Refuses [`NetworkingMode::Tsi`] and [`NetworkingMode::VsockDirect`].
/// The bridge path is defined only for virtio-net-backed guests today;
/// callers that need a no-NIC direct path must use the legacy
/// [`run_supervisor`](crate::run_supervisor) entry point.
#[cfg(all(feature = "libkrun-sys", target_family = "unix"))]
fn configure_with_gateway_for_bridge(
    ctx: &KrunContext,
    bridge_scratch_dir: &std::path::Path,
) -> Result<(sys::Context, GatewayHandle, BridgeFds), Error> {
    // Admission gate — refuse no-gateway modes before any FFI call so
    // the rejection is observable in unit tests that don't link
    // libkrun (configure_pre_net calls `sys::Context::new`, which
    // is real FFI). Moving the check up also avoids leaking a
    // `sys::Context` on the refusal path.
    if matches!(
        ctx.networking,
        NetworkingMode::Tsi | NetworkingMode::VsockDirect
    ) {
        return Err(Error::Io {
            context: format!(
                "configure_with_gateway_for_bridge refuses {:?}: \
                 bridge mode requires a virtio-net-backed gateway path. \
                 Use run_supervisor for no-NIC direct VMs.",
                ctx.networking
            ),
        });
    }
    let krun = configure_pre_net(ctx)?;
    let (handle, bridge_fds) = match &ctx.networking {
        NetworkingMode::Tsi | NetworkingMode::VsockDirect => unreachable!("refused above"),
        NetworkingMode::Passt { mac, scratch_dir } => {
            let mut handle =
                passt::spawn(std::path::Path::new(scratch_dir)).map_err(|e| Error::Io {
                    context: format!("spawning passt for bridged NetworkingMode::Passt: {e}"),
                })?;
            // Take the passt-parent fd (faces passt). PasstHandle
            // keeps the child alive via Drop; `take_socket` leaves
            // the handle's `child` field in place.
            let gateway_fd = handle.take_socket().ok_or_else(|| Error::Io {
                context: "PasstHandle::take_socket returned None — \
                            handle's parent_socket was already taken"
                    .to_string(),
            })?;
            // Build the inner SOCK_STREAM socketpair. One half goes
            // to libkrun; libkrun dups across `start_enter`, so we
            // can close our copy of that half right after the
            // add_net_* call. The other half stays with the bridge.
            let (inner_libkrun, inner_supervisor) =
                bridge_socketpair_stream().map_err(|e| Error::Io {
                    context: format!("creating bridge socketpair (passt): {e}"),
                })?;
            krun.add_net_unixstream_fd(
                inner_libkrun.as_raw_fd(),
                mac,
                sys::PASST_NET_FEATURES,
                /* flags = */ 0,
            )?;
            // libkrun has dup'd; close our copy of the libkrun half.
            drop(inner_libkrun);
            (
                GatewayHandle::Passt(handle),
                BridgeFds::Passt {
                    gateway_fd,
                    supervisor_fd: inner_supervisor,
                },
            )
        }
        NetworkingMode::NativeGateway {
            mac,
            scratch_dir,
            native_config,
        } => {
            let handle = native_gateway::spawn(
                std::path::Path::new(scratch_dir),
                native_config.as_deref().map(std::path::Path::new),
            )
            .map_err(|e| Error::Io {
                context: format!(
                    "spawning native gateway for bridged NetworkingMode::NativeGateway: {e}"
                ),
            })?;
            // Snapshot the gateway bind path before moving the handle
            // into GatewayHandle::NativeGateway — the bridge needs it to
            // connect for the egress direction.
            let gateway_socket_path = handle.socket_path().to_path_buf();
            // Pick a fresh path inside the per-VM bridge scratch
            // dir for the supervisor-side listener. The bridge
            // thread binds it; libkrun's add_net_unixgram_path
            // stores the path and connects lazily at net-device
            // probe time (well after the bridge has bound).
            std::fs::create_dir_all(bridge_scratch_dir).map_err(|e| Error::Io {
                context: format!(
                    "create bridge scratch dir {}: {e}",
                    bridge_scratch_dir.display()
                ),
            })?;
            let supervisor_listen_path = bridge_scratch_dir.join("bridge-libkrun.sock");
            // Defensive: if a previous run left a stale socket
            // file at this path the bridge bind would fail with
            // EADDRINUSE. Pre-unlink under our umask.
            let _ = std::fs::remove_file(&supervisor_listen_path);
            krun.add_net_unixgram_path(
                &supervisor_listen_path,
                mac,
                sys::PASST_NET_FEATURES,
                sys::NET_FLAG_VFKIT | sys::NET_FLAG_DHCP_CLIENT,
            )?;
            (
                GatewayHandle::NativeGateway(handle),
                BridgeFds::LibkrunNativeGateway {
                    gateway_socket_path,
                    supervisor_listen_path,
                },
            )
        }
    };
    Ok((krun, handle, bridge_fds))
}

/// Build a `SOCK_STREAM` socketpair for the bridge's inner pair
/// (libkrun ↔ supervisor). Mirrors `passt::make_socketpair` but
/// kept here so the bridge insertion path doesn't need to leak
/// passt internals into the bridge module signature.
#[cfg(all(feature = "libkrun-sys", target_family = "unix"))]
fn bridge_socketpair_stream() -> std::io::Result<(OwnedFd, OwnedFd)> {
    use std::os::fd::FromRawFd;
    let mut fds: [libc::c_int; 2] = [-1, -1];
    // SAFETY: socketpair fills `fds` with two valid file descriptors
    // on success (return 0); on failure (return -1) the array is
    // untouched and we return errno.
    let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: kernel returned two valid fds.
    let a = unsafe { OwnedFd::from_raw_fd(fds[0]) };
    let b = unsafe { OwnedFd::from_raw_fd(fds[1]) };
    Ok((a, b))
}

/// Supervisor entry point that runs the per-VM gateway audit bridge.
/// Mirrors [`run_supervisor`](crate::run_supervisor) but interposes
/// the bridge between libkrun and the userspace network gateway,
/// then hands the resulting `BridgeFds` to a caller-supplied
/// factory closure (which builds and spawns the bridge thread).
///
/// The factory runs synchronously after libkrun is configured but
/// before `start_enter` is called. Typical implementation:
///
/// ```ignore
/// run_supervisor_with_bridge(&cfg, |bridge_fds| {
///     let endpoints = match bridge_fds {
///         BridgeFds::Passt { gateway_fd, supervisor_fd } => {
///             mvm_hostd::supervisor::gateway_bridge::BridgeEndpoints::Passt {
///                 gateway_fd, supervisor_fd,
///             }
///         }
///         BridgeFds::LibkrunNativeGateway { gateway_socket_path, supervisor_listen_path } => {
///             mvm_hostd::supervisor::gateway_bridge::BridgeEndpoints::LibkrunNativeGateway {
///                 gateway_socket_path, supervisor_listen_path,
///             }
///         }
///     };
///     let bridge_cfg = mvm_hostd::supervisor::gateway_bridge::BridgeConfig { /* … */ };
///     let _join = mvm_hostd::supervisor::gateway_bridge::spawn_bridge_thread(endpoints, bridge_cfg);
/// })?;
/// ```
///
/// The bridge thread runs concurrently with `krun_start_enter`,
/// which blocks until the guest exits and then calls `exit()` on
/// the process — reaping the bridge thread without graceful join.
///
/// Claim-10 admission gates:
/// 1. `cfg.validate_audit_substrate()` — refuses configs missing
///    the audit-substrate paths or carrying an out-of-policy
///    signing key.
/// 2. `configure_with_gateway_for_bridge` refuses
///    `NetworkingMode::Tsi`.
#[cfg(feature = "libkrun-sys")]
pub fn run_supervisor_with_bridge<F>(
    cfg: &SupervisorConfig,
    bridge_factory: F,
) -> Result<std::convert::Infallible, Error>
where
    F: FnOnce(BridgeFds),
{
    // Claim-10 admission gate 1 — audit substrate fields.
    cfg.validate_audit_substrate().map_err(|e| Error::Io {
        context: format!("claim-10 admission: validate_audit_substrate refused: {e}"),
    })?;

    // Standard supervisor setup mirrors `run_supervisor`.
    std::fs::create_dir_all(&cfg.vm_state_dir).map_err(|e| Error::Io {
        context: format!("create_dir_all {}: {e}", cfg.vm_state_dir),
    })?;
    let pid_path = cfg.pid_file();
    let pid = std::process::id().to_string();
    std::fs::write(&pid_path, &pid).map_err(|e| Error::Io {
        context: format!("write pid file {}: {e}", pid_path.display()),
    })?;
    if !is_available() {
        return Err(Error::NotInstalled {
            install_hint: install_hint(),
        });
    }

    // Bridge scratch lives inside the per-VM state dir so it's
    // reaped by the standard `mvmctl cache prune` walker.
    let bridge_scratch_dir = std::path::PathBuf::from(&cfg.vm_state_dir).join("bridge");
    let (krun, _gateway_handle, bridge_fds) =
        configure_with_gateway_for_bridge(&cfg.krun, &bridge_scratch_dir)?;

    // Hand the bridge fds to the factory. The factory spawns the
    // bridge thread before we enter libkrun — so by the time
    // `start_enter` brings up the guest's net device, the bridge
    // is already serving / listening on both ends.
    bridge_factory(bridge_fds);

    install_shutdown_handler(&krun)?;
    krun.start_enter()
}

// Every test below exercises `configure_with_gateway_for_bridge` /
// `bridge_socketpair_stream`, both gated `all(feature = "libkrun-sys",
// target_family = "unix")` — gate the whole module the same way so
// `use super::*` isn't left importing nothing on the default build.
#[cfg(all(test, feature = "libkrun-sys", target_family = "unix"))]
mod tests {
    use super::*;

    #[test]
    fn bridge_socketpair_stream_returns_two_distinct_fds() {
        use std::os::fd::AsRawFd;
        let (a, b) = bridge_socketpair_stream().expect("socketpair");
        assert_ne!(a.as_raw_fd(), b.as_raw_fd());
        assert!(a.as_raw_fd() >= 0);
        assert!(b.as_raw_fd() >= 0);
    }

    #[test]
    fn configure_with_gateway_for_bridge_refuses_tsi() {
        // TSI bypasses virtio-net entirely and violates the
        // claim-10 no-bypass invariant. The refusal must fire
        // before configure_pre_net (which touches FFI) so the
        // test passes on hosts without libkrun installed.
        let ctx = KrunContext::new("vm", "/k", "/r"); // defaults to NetworkingMode::Tsi
        assert!(matches!(ctx.networking, NetworkingMode::Tsi));
        let scratch = std::path::PathBuf::from("/tmp/mvm-bridge-test-tsi-refusal");
        let result = configure_with_gateway_for_bridge(&ctx, &scratch);
        // Avoid `expect_err` because Result::expect_err requires Debug
        // on the Ok type, and `sys::Context` is FFI-opaque without one.
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("Tsi networking must be refused"),
        };
        match err {
            Error::Io { context } => {
                assert!(
                    context.contains("Tsi"),
                    "error context must name Tsi: {context}"
                );
                assert!(
                    context.contains("virtio-net-backed gateway path"),
                    "error context must cite the bridge requirement: {context}"
                );
            }
            other => panic!("expected Error::Io with Tsi message, got {other:?}"),
        }
    }

    #[test]
    fn configure_with_gateway_for_bridge_refuses_vsock_direct() {
        let ctx = KrunContext::new("vm", "/k", "/r").with_vsock_direct();
        let scratch = std::path::PathBuf::from("/tmp/mvm-bridge-test-vsock-direct-refusal");
        let result = configure_with_gateway_for_bridge(&ctx, &scratch);
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("VsockDirect networking must be refused"),
        };
        match err {
            Error::Io { context } => {
                assert!(
                    context.contains("VsockDirect"),
                    "error context must name VsockDirect: {context}"
                );
                assert!(
                    context.contains("virtio-net-backed gateway path"),
                    "error context must cite the bridge requirement: {context}"
                );
            }
            other => panic!("expected Error::Io with VsockDirect message, got {other:?}"),
        }
    }
}
