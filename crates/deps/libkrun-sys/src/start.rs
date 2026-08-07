//! Boot path: turn a [`KrunContext`] into a running libkrun guest.
//!
//! [`start`] configures libkrun and returns without blocking (useful for
//! exercising the wrapper end-to-end); [`start_enter`] configures and
//! then blocks in `krun_start_enter` until the guest exits. `configure`
//! and `configure_pre_net` are the shared FFI-application internals both
//! paths — and [`crate::run_supervisor`] / [`crate::run_supervisor_with_bridge`]
//! — build on.

use crate::context::KrunContext;
#[cfg(feature = "libkrun-sys")]
use crate::context::NetworkingMode;
use crate::error::{Error, install_hint, is_available};
#[cfg(feature = "libkrun-sys")]
use std::path::Path;

#[cfg(feature = "libkrun-sys")]
use crate::sys;

#[cfg(all(feature = "libkrun-sys", target_family = "unix"))]
use crate::{native_gateway, passt};

/// Start a libkrun guest from `ctx`.
///
/// With the `libkrun-sys` feature enabled, this allocates a libkrun
/// configuration context, applies CPU/memory, kernel, rootfs, and
/// vsock-port configuration through the FFI, then frees the context
/// and returns `Ok(())`. It does **not** call `krun_start_enter`
/// (which blocks until the guest exits) — that's [`start_enter`].
/// The call exists so consumers can exercise the wrapper end-to-end
/// on a host with libkrun installed.
///
/// Without the feature, returns [`Error::NotYetWired`].
pub fn start(ctx: &KrunContext) -> Result<(), Error> {
    if !is_available() {
        return Err(Error::NotInstalled {
            install_hint: install_hint(),
        });
    }
    #[cfg(not(feature = "libkrun-sys"))]
    {
        let _ = ctx;
        Err(Error::NotYetWired {
            tracking: "specs/plans/57-libkrun-spike.md W3+W4",
        })
    }
    #[cfg(feature = "libkrun-sys")]
    {
        start_via_ffi(ctx)
    }
}

/// Apply every `KrunContext` field to a freshly-allocated libkrun
/// configuration context. Shared between [`start`] (configure + drop)
/// and [`start_enter`] (configure + boot).
///
/// Split into `configure_pre_net` (everything except networking) + a
/// per-caller networking decision. `configure` itself is the
/// no-gateway path used by the spike/smoke binaries; real
/// consumers go through `run_supervisor`, which owns a passt child
/// process for the libkrun lifetime via `configure_with_passt`.
#[cfg(feature = "libkrun-sys")]
fn configure(ctx: &KrunContext) -> Result<sys::Context, Error> {
    let krun = configure_pre_net(ctx)?;
    if !matches!(
        ctx.networking,
        NetworkingMode::Tsi | NetworkingMode::VsockDirect
    ) {
        return Err(Error::Io {
            context: format!(
                "{:?} requires the supervisor entry point; call \
                 `run_supervisor` rather than `start` / `start_enter` directly",
                ctx.networking
            ),
        });
    }
    Ok(krun)
}

/// Owning handle to whichever userspace network gateway the supervisor
/// spawned for this guest. Lives for the libkrun
/// process lifetime so the gateway is reaped when the guest exits.
#[cfg(all(feature = "libkrun-sys", target_family = "unix"))]
pub enum GatewayHandle {
    /// Not using a virtio-net backend.
    None,
    /// passt child (Linux).
    Passt(passt::PasstHandle),
    /// Native gateway child (macOS / cross-platform fallback).
    NativeGateway(native_gateway::NativeGatewayHandle),
}

/// configure() variant that owns the network-gateway child process
/// for the lifetime of the returned
/// context. Used by [`run_supervisor`](crate::run_supervisor) when
/// `NetworkingMode::{Passt, NativeGateway}` is set. The handle Drop's after
/// libkrun finishes consuming the socket and the guest exits.
#[cfg(all(feature = "libkrun-sys", target_family = "unix"))]
pub(super) fn configure_with_gateway(
    ctx: &KrunContext,
) -> Result<(sys::Context, GatewayHandle), Error> {
    let krun = configure_pre_net(ctx)?;
    let handle = match &ctx.networking {
        NetworkingMode::Tsi | NetworkingMode::VsockDirect => GatewayHandle::None,
        NetworkingMode::Passt { mac, scratch_dir } => {
            let handle =
                passt::spawn(std::path::Path::new(scratch_dir)).map_err(|e| Error::Io {
                    context: format!("spawning passt for NetworkingMode::Passt: {e}"),
                })?;
            krun.add_net_unixstream_fd(
                handle.socket_fd(),
                mac,
                sys::PASST_NET_FEATURES,
                /* flags = */ 0,
            )?;
            GatewayHandle::Passt(handle)
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
                context: format!("spawning native gateway for NetworkingMode::NativeGateway: {e}"),
            })?;
            // The native gateway speaks libkrun's "vfkit mode" framing on the
            // unixgram socket; NET_FLAG_VFKIT (see sys::NET_FLAG_VFKIT)
            // is libkrun's required signal to emit the magic-byte
            // handshake. NET_FLAG_DHCP_CLIENT (libkrun 1.18.0+) tells
            // libkrun's net device to bring the interface up via its
            // in-guest DHCP client against the gateway's DHCP server, so
            // the guest sees a fully-configured eth0 without needing
            // an in-guest udhcpc race. libkrun's own
            // vfkit gateway tests use both.
            krun.add_net_unixgram_path(
                handle.socket_path(),
                mac,
                sys::PASST_NET_FEATURES,
                sys::NET_FLAG_VFKIT | sys::NET_FLAG_DHCP_CLIENT,
            )?;
            GatewayHandle::NativeGateway(handle)
        }
    };
    Ok((krun, handle))
}

/// Every part of `configure` that doesn't touch the networking
/// backend. Shared between the plain `configure` path and
/// `configure_with_gateway`.
#[cfg(feature = "libkrun-sys")]
pub(super) fn configure_pre_net(ctx: &KrunContext) -> Result<sys::Context, Error> {
    validate_boot_config(ctx)?;
    let krun = sys::Context::new()?;
    krun.set_vm_config(ctx.vcpus, ctx.ram_mib)?;

    if let Some(root_dir) = &ctx.root_dir {
        let entry = ctx
            .guest_entrypoint
            .as_ref()
            .expect("validate_boot_config guarantees root_dir is paired with guest_entrypoint");
        krun.set_root(Path::new(root_dir))?;
        let argv_owned: Vec<&str> = if entry.argv.is_empty() {
            // Default argv[0] to the entry name for libkrun's exec.
            let basename = entry
                .path
                .rsplit('/')
                .next()
                .filter(|s| !s.is_empty())
                .unwrap_or(entry.path.as_str());
            vec![basename]
        } else {
            entry.argv.iter().map(String::as_str).collect()
        };
        let envp_owned: Vec<&str> = entry.envp.iter().map(String::as_str).collect();
        krun.set_guest_entrypoint(Path::new(&entry.path), &argv_owned, &envp_owned)?;
    } else {
        let kernel_path = ctx
            .kernel_path
            .as_ref()
            .expect("validate_boot_config guarantees kernel_path is set when root_dir is absent");
        // A `mkGuest` workload image ships no kernel — boot libkrun's
        // bundled libkrunfw kernel (TSI + vsock). When the declared kernel
        // file is absent, materialize the bundled one at that path (idempotent;
        // the `Raw` set_kernel below loads the file directly, so the bundled
        // load/entry addrs aren't needed here). Builder / interactive images
        // carry a real built kernel and skip this. Single source for every
        // caller (up / invoke / run) so none re-implements the fallback.
        if !Path::new(kernel_path).exists() {
            sys::extract_bundled_kernel(Path::new(kernel_path))?;
        }
        let initramfs_path = ctx.initramfs_path.as_deref().map(Path::new);
        krun.set_kernel(
            Path::new(kernel_path),
            ctx.kernel_format,
            initramfs_path,
            ctx.kernel_cmdline.as_deref(),
        )?;
        if let Some(rootfs) = &ctx.rootfs_path {
            krun.add_disk("root", Path::new(rootfs), false)?;
        }
    }

    for disk in &ctx.extra_disks {
        krun.add_disk(&disk.id, Path::new(&disk.path), disk.read_only)?;
    }
    for mount in &ctx.virtio_fs_mounts {
        let path = Path::new(&mount.host_path);
        match (mount.shm_size, mount.read_only) {
            (Some(shm_size), true) => krun.add_virtiofs3(&mount.tag, path, shm_size, true)?,
            (Some(shm_size), false) => krun.add_virtiofs2(&mount.tag, path, shm_size)?,
            (None, _) => krun.add_virtiofs(&mount.tag, path)?,
        }
    }
    if matches!(ctx.networking, NetworkingMode::VsockDirect) {
        krun.disable_implicit_vsock()?;
        krun.add_vsock(/* tsi_features = */ 0)?;
    }
    for &port in &ctx.vsock_ports {
        let socket = ctx.vsock_socket_path(port);
        // Defensive: a prior VM run (clean stop or crash) leaves this
        // listener socket behind — the stop path doesn't unlink it —
        // and add_vsock_port2(listen=true) binds here, failing EEXIST
        // (rc -17) on the stale file. Pre-unlink, mirroring the native-gateway
        // bridge socket above. Keeps repeated builder VM starts idempotent.
        let _ = std::fs::remove_file(&socket);
        krun.add_vsock_port2(port, &socket, /* listen = */ true)?;
    }
    for &port in &ctx.host_listen_ports {
        let socket = ctx.host_listen_socket_path(port);
        // listen=false: the host (supervisor) binds the listener; do NOT
        // pre-unlink — the supervisor created it. libkrun proxies guest
        // connects on `port` to that socket.
        krun.add_vsock_port2(port, &socket, /* listen = */ false)?;
    }
    if let Some(console_path) = &ctx.console_output_path {
        krun.set_console_output(Path::new(console_path))?;
    }
    Ok(krun)
}

/// Validate that the boot fields on `ctx` describe exactly one of the
/// supported shapes: (kernel + rootfs), (kernel + initramfs), or
/// (root_dir + guest_entrypoint). Anything else is a programming
/// error — we'd otherwise pass nonsense to libkrun and watch it
/// fail late with an opaque rc.
///
/// Always-on so unit tests can exercise it without the `libkrun-sys`
/// feature. `configure_pre_net` is the only non-test caller and is
/// gated behind that feature, so the dead-code allow keeps the
/// non-feature library build quiet.
#[cfg_attr(not(feature = "libkrun-sys"), allow(dead_code))]
fn validate_boot_config(ctx: &KrunContext) -> Result<(), Error> {
    let has_kernel = ctx.kernel_path.is_some();
    let has_rootfs = ctx.rootfs_path.is_some();
    let has_initramfs = ctx.initramfs_path.is_some();
    let has_root_dir = ctx.root_dir.is_some();
    let has_entry = ctx.guest_entrypoint.is_some();

    if has_root_dir {
        if has_kernel || has_rootfs || has_initramfs {
            return Err(Error::Io {
                context: "KrunContext.root_dir is mutually exclusive with kernel_path, \
                          rootfs_path, and initramfs_path"
                    .to_string(),
            });
        }
        if !has_entry {
            return Err(Error::Io {
                context: "KrunContext.root_dir requires guest_entrypoint to be set".to_string(),
            });
        }
        return Ok(());
    }

    if !has_kernel {
        return Err(Error::Io {
            context: "KrunContext needs kernel_path (with rootfs_path or initramfs_path) or \
                      root_dir; none set"
                .to_string(),
        });
    }
    if has_rootfs == has_initramfs {
        return Err(Error::Io {
            context: "KrunContext kernel mode requires exactly one of rootfs_path or \
                      initramfs_path"
                .to_string(),
        });
    }
    Ok(())
}

#[cfg(feature = "libkrun-sys")]
fn start_via_ffi(ctx: &KrunContext) -> Result<(), Error> {
    let _krun = configure(ctx)?;
    // `krun_start_enter` deliberately not invoked here — that's
    // [`start_enter`]. Dropping the context frees it cleanly through
    // `Context::Drop`.
    Ok(())
}

/// Boot a libkrun guest from `ctx` and block until it exits.
///
/// Configures libkrun the same way [`start`] does, then calls
/// `krun_start_enter`. libkrun's
/// `start_enter` calls `exit()` on the calling process with the
/// guest's exit code when the guest powers off cleanly, so this
/// function does not return on success — its return type is
/// [`std::convert::Infallible`] in the `Ok` arm.
///
/// Use cases:
/// - the smoke binary (`crates/mvm-libkrun/examples/libkrun-smoke.rs`)
///   that validates a real Nix-built kernel + ext4 rootfs boots on
///   macOS Apple Silicon;
/// - one-shot guest invocations where the caller wants the process
///   to exit alongside the guest.
///
/// **Not yet suitable** for `LibkrunBackend::start()` — that consumer
/// needs the surrounding mvmctl process to keep running after the VM
/// boots, which the blocking-thread + per-VM registry lifecycle
/// provides instead.
///
/// Without the `libkrun-sys` feature, returns [`Error::NotYetWired`].
pub fn start_enter(ctx: &KrunContext) -> Result<std::convert::Infallible, Error> {
    if !is_available() {
        return Err(Error::NotInstalled {
            install_hint: install_hint(),
        });
    }
    #[cfg(not(feature = "libkrun-sys"))]
    {
        let _ = ctx;
        Err(Error::NotYetWired {
            tracking: "specs/plans/57-libkrun-spike.md W3",
        })
    }
    #[cfg(feature = "libkrun-sys")]
    {
        let krun = configure(ctx)?;
        install_shutdown_handler(&krun)?;
        krun.start_enter()
    }
}

/// Best-effort SIGTERM handler that drops the supervisor process
/// immediately, so `mvmctl stop` / `kill -TERM <pid>` *may* reap it
/// without the 5-second SIGKILL escalation `LibkrunBackend::stop`
/// would otherwise hit.
///
/// "Best-effort" because libkrun's signal-mask behavior under
/// `krun_start_enter` is empirically inconsistent: the same binary
/// killed manually from a shell exits in ~100 ms, but when spawned
/// by `LibkrunBackend::start` (via `std::process::Command`) the
/// handler installed here doesn't always run before
/// `LibkrunBackend::stop` falls back to `SIGKILL` at 5 s. The
/// inconsistency seems to come from libkrun blocking SIGTERM on
/// every thread mid-`start_enter`, so the kernel can't always find
/// a thread to deliver to. Installing the handler is still net
/// positive: in the manual-stop path it lets the process exit
/// cleanly, and in the spawned-by-LibkrunBackend path it's a no-op
/// that doesn't *hurt*.
///
/// More robust options investigated and rejected:
/// - `krun_get_shutdown_eventfd` returns a valid fd on Homebrew's
///   libkrun 1.17.4 but the header docs it as gated on
///   `krun_start_event` (libkrun-efi only); writes to the fd vanish
///   under the `start_enter` entry point we use.
/// - A dedicated `sigwait` thread spawned before `start_enter`
///   makes `krun_start_enter` itself return `-EINVAL` (rc -22).
///   libkrun appears to want exclusive control of the process's
///   signal mask. Don't do that.
#[cfg(feature = "libkrun-sys")]
pub(super) fn install_shutdown_handler(_krun: &sys::Context) -> Result<(), Error> {
    extern "C" fn handle_sigterm(_sig: libc::c_int) {
        // Reap our native gateway first, then exit. Without this, `mvmctl stop`
        // / `kill -TERM` tears down the supervisor but orphans the gateway
        // (re-parented to init), which keeps holding any inherited fd
        // and accumulates as a leaked daemon. `kill(2)` and the atomic
        // load are async-signal-safe (signal-safety(7)); `_exit` is too.
        // Status 143 = 128 + SIGTERM, the shell convention for "killed
        // by SIGTERM".
        let gateway_pid = crate::native_gateway::RUNNING_NATIVE_GATEWAY_PID
            .load(std::sync::atomic::Ordering::SeqCst);
        unsafe {
            if gateway_pid > 0 {
                libc::kill(gateway_pid, libc::SIGTERM);
            }
            libc::_exit(143);
        }
    }

    // SAFETY: `sigaction` is async-signal-safe and we pass a
    // properly-zeroed `sigaction` struct. The handler we install is
    // itself signal-safe (single `_exit` call).
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = handle_sigterm as *const () as usize;
        sa.sa_flags = 0;
        libc::sigemptyset(&mut sa.sa_mask);
        if libc::sigaction(libc::SIGTERM, &sa, std::ptr::null_mut()) != 0 {
            return Err(Error::Io {
                context: format!(
                    "sigaction(SIGTERM) failed: {}",
                    std::io::Error::last_os_error()
                ),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_boot_config_accepts_kernel_plus_rootfs() {
        let ctx = KrunContext::new("vm", "/k", "/r");
        validate_boot_config(&ctx).expect("kernel + rootfs is valid");
    }

    #[test]
    fn validate_boot_config_accepts_kernel_plus_initramfs() {
        let ctx = KrunContext::new_initramfs("vm", "/k", "/i");
        validate_boot_config(&ctx).expect("kernel + initramfs is valid");
    }

    #[test]
    fn validate_boot_config_accepts_root_dir_plus_entrypoint() {
        let ctx = KrunContext::new_root_dir("vm", "/host/root", "/init");
        validate_boot_config(&ctx).expect("root_dir + entrypoint is valid");
    }

    #[test]
    fn validate_boot_config_rejects_root_dir_with_kernel() {
        let mut ctx = KrunContext::new_root_dir("vm", "/host/root", "/init");
        ctx.kernel_path = Some("/k".to_string());
        let err = validate_boot_config(&ctx).expect_err("mixing root_dir + kernel must fail");
        assert!(
            matches!(err, Error::Io { ref context } if context.contains("root_dir is mutually exclusive")),
            "got {err:?}"
        );
    }

    #[test]
    fn validate_boot_config_rejects_root_dir_with_rootfs() {
        let mut ctx = KrunContext::new_root_dir("vm", "/host/root", "/init");
        ctx.rootfs_path = Some("/r".to_string());
        validate_boot_config(&ctx).expect_err("mixing root_dir + rootfs must fail");
    }

    #[test]
    fn validate_boot_config_rejects_root_dir_with_initramfs() {
        let mut ctx = KrunContext::new_root_dir("vm", "/host/root", "/init");
        ctx.initramfs_path = Some("/i".to_string());
        validate_boot_config(&ctx).expect_err("mixing root_dir + initramfs must fail");
    }

    #[test]
    fn validate_boot_config_rejects_root_dir_without_entrypoint() {
        let mut ctx = KrunContext::new_root_dir("vm", "/host/root", "/init");
        ctx.guest_entrypoint = None;
        let err = validate_boot_config(&ctx).expect_err("root_dir without entrypoint must fail");
        assert!(
            matches!(err, Error::Io { ref context } if context.contains("guest_entrypoint")),
            "got {err:?}"
        );
    }

    #[test]
    fn validate_boot_config_rejects_empty_context() {
        let mut ctx = KrunContext::new("vm", "/k", "/r");
        ctx.kernel_path = None;
        ctx.rootfs_path = None;
        validate_boot_config(&ctx).expect_err("no kernel, no root_dir → reject");
    }

    #[test]
    fn validate_boot_config_rejects_kernel_with_both_rootfs_and_initramfs() {
        let mut ctx = KrunContext::new("vm", "/k", "/r");
        ctx.initramfs_path = Some("/i".to_string());
        validate_boot_config(&ctx)
            .expect_err("kernel + both rootfs and initramfs is ambiguous → reject");
    }

    /// When libkrun isn't installed on the host, `start` short-circuits
    /// before touching the FFI — works the same way with or without
    /// the `libkrun-sys` feature.
    #[test]
    fn start_errors_when_not_installed() {
        if is_available() {
            // Host has libkrun; this test exercises the fast-fail path,
            // not the FFI surface, so skip.
            return;
        }
        let ctx = KrunContext::new("vm", "/k", "/r");
        let err = start(&ctx).expect_err("scaffolding errors without libkrun");
        assert!(matches!(err, Error::NotInstalled { .. }));
    }
}
