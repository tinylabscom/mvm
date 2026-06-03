//! Safe wrappers around the bindgen-generated libkrun FFI.
//!
//! Only compiled when the `libkrun-sys` feature is on. The wrappers
//! translate libkrun's "negative i32 = errno" convention into
//! `Result<_, super::Error>` and own all `CString` conversions for
//! path arguments. Each wrapper is one FFI call deep.
//!
//! `krun_start_enter` is not called from here — it blocks until the
//! guest exits and is the W3+W4 lifecycle scope. The Plan 57 W1
//! deliverable is the bindings + thin wrapper only; consumers exercise
//! the configuration calls today and pick up boot in a later PR.

#![allow(
    non_upper_case_globals,
    non_camel_case_types,
    non_snake_case,
    dead_code,
    clippy::missing_safety_doc,
    clippy::too_many_arguments
)]

use std::ffi::CString;
use std::path::Path;

use crate::Error;
use mvm_core::kernel_format::KernelFormat;

mod bindings {
    include!(concat!(env!("OUT_DIR"), "/libkrun_sys.rs"));
}

/// Plan 87: the `features` mask `krun_add_net_unixstream` expects for
/// passt as the userspace network proxy. Mirrors the
/// `COMPAT_NET_FEATURES` macro in libkrun.h:344 — a compound `|` of
/// the NET_FEATURE_* constants that bindgen can't always fold into a
/// single value. Re-deriving in Rust keeps the canonical mask close
/// to the call site that uses it.
pub const PASST_NET_FEATURES: u32 = (1 << 0)   // NET_FEATURE_CSUM
    | (1 << 1)   // NET_FEATURE_GUEST_CSUM
    | (1 << 7)   // NET_FEATURE_GUEST_TSO4
    | (1 << 10)  // NET_FEATURE_GUEST_UFO
    | (1 << 11)  // NET_FEATURE_HOST_TSO4
    | (1 << 14); // NET_FEATURE_HOST_UFO

/// Plan 88 W5 fix: `NET_FLAG_VFKIT` from `libkrun.h`. libkrun rejects
/// `krun_add_net_unixgram(c_path, ...)` with -EINVAL unless this flag
/// is set, because the unixgram backend needs to know whether to
/// emit the vfkit magic-byte handshake gvproxy expects on
/// `-listen-vfkit`. Without the flag libkrun assumes raw frames and
/// fails closed at config time — that's the rc -22 the W5 smoke
/// surfaced.
pub const NET_FLAG_VFKIT: u32 = 1 << 0;

/// `NET_FLAG_DHCP_CLIENT` from `libkrun.h` (added in libkrun 1.18.0).
/// Enables libkrun's in-guest DHCP client so the guest doesn't need
/// to run `udhcpc`/`dhclient` itself — libkrun sees the DHCP-OFFER
/// from gvproxy's built-in DHCP server, configures the interface,
/// and the guest kernel hands the application a fully-configured
/// `eth0`. libkrun's own gvproxy test
/// (`tests/test_cases/src/test_net/gvproxy.rs`) passes
/// `NET_FLAG_VFKIT | NET_FLAG_DHCP_CLIENT`; mirroring that here is
/// what makes the macOS smoke succeed end-to-end on libkrun 1.18.0+.
pub const NET_FLAG_DHCP_CLIENT: u32 = 1 << 1;

/// Plan 88 W5 diagnostic: enable libkrun's internal logger. Wrapper
/// for `krun_init_log` (libkrun.h). Targets a file descriptor
/// (`target_fd = 2` → stderr) at the given level. `style` and
/// `options` follow the C signature; pass 0 / 0 unless you have a
/// reason. Used by `mvm-libkrun-supervisor` when `MVM_KRUN_LOG` is
/// set — surfaces device-attach traces (`mmio[net] set_irq_line`,
/// `net::unixgram network proxy socket fd ...`) that don't appear
/// via `krun_set_log_level` alone.
pub fn init_log(target_fd: i32, level: LogLevel, style: u32, options: u32) -> Result<(), Error> {
    check(unsafe { bindings::krun_init_log(target_fd, level.as_u32(), style, options) })
}

/// Map a canonical `KernelFormat` to the libkrun FFI constant.
///
/// Returns `Err` for `Image` and `Pe` — libkrun has no FFI constant for
/// uncompressed arm64 `Image` or uncompressed PE. Callers should use
/// the bundled kernel or a compressed variant (`image_gz`, `pe_gz`).
fn to_krun_format(f: KernelFormat) -> Result<u32, Error> {
    Ok(match f {
        KernelFormat::Raw => bindings::KRUN_KERNEL_FORMAT_RAW,
        KernelFormat::Elf => bindings::KRUN_KERNEL_FORMAT_ELF,
        KernelFormat::PeGz => bindings::KRUN_KERNEL_FORMAT_PE_GZ,
        KernelFormat::ImageBz2 => bindings::KRUN_KERNEL_FORMAT_IMAGE_BZ2,
        KernelFormat::ImageGz => bindings::KRUN_KERNEL_FORMAT_IMAGE_GZ,
        KernelFormat::ImageZstd => bindings::KRUN_KERNEL_FORMAT_IMAGE_ZSTD,
        KernelFormat::Image | KernelFormat::Pe => {
            return Err(Error::Io {
                context: format!(
                    "libkrun cannot load uncompressed {f:?}; \
                    use the bundled kernel or a compressed format"
                ),
            });
        }
    })
}

/// Log-level constants matching `KRUN_LOG_LEVEL_*` in libkrun.h.
#[derive(Debug, Clone, Copy)]
pub enum LogLevel {
    Off,
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl LogLevel {
    fn as_u32(self) -> u32 {
        match self {
            LogLevel::Off => 0,
            LogLevel::Error => 1,
            LogLevel::Warn => 2,
            LogLevel::Info => 3,
            LogLevel::Debug => 4,
            LogLevel::Trace => 5,
        }
    }
}

/// Owned libkrun configuration context. Frees the underlying ctx_id on
/// drop so callers don't have to thread cleanup through every error
/// path.
pub struct Context {
    ctx_id: u32,
}

impl Context {
    /// Allocate a new libkrun configuration context.
    pub fn new() -> Result<Self, Error> {
        let rc = unsafe { bindings::krun_create_ctx() };
        if rc < 0 {
            return Err(Error::Krun(rc));
        }
        // krun_create_ctx returns the ctx id as a non-negative i32.
        Ok(Self { ctx_id: rc as u32 })
    }

    pub fn id(&self) -> u32 {
        self.ctx_id
    }

    pub fn set_vm_config(&self, num_vcpus: u8, ram_mib: u32) -> Result<(), Error> {
        check(unsafe { bindings::krun_set_vm_config(self.ctx_id, num_vcpus, ram_mib) })
    }

    pub fn set_root_disk(&self, disk_path: &Path) -> Result<(), Error> {
        let path = cstring(disk_path)?;
        check(unsafe { bindings::krun_set_root_disk(self.ctx_id, path.as_ptr()) })
    }

    /// Set a host directory as the guest's root, exported via
    /// virtiofs. libkrun's bundled kernel boots transparently — no
    /// `set_kernel` call is needed. Must be paired with
    /// [`Self::set_guest_entrypoint`] so libkrun knows what to run
    /// as PID 1.
    ///
    /// Mutually exclusive with `set_root_disk` and `set_kernel`. The
    /// `KrunContext` layer in `lib.rs` enforces this at the type level;
    /// here we just forward to the FFI.
    pub fn set_root(&self, root_path: &Path) -> Result<(), Error> {
        let path = cstring(root_path)?;
        check(unsafe { bindings::krun_set_root(self.ctx_id, path.as_ptr()) })
    }

    /// Set the entrypoint libkrun launches inside the guest (wraps
    /// `krun_set_exec`). `entry_path` is relative to the directory
    /// set via [`Self::set_root`]. `argv` is passed verbatim (libkrun
    /// appends the required trailing NULL); per libkrun.h, `argv[0]`
    /// should be the entrypoint name. `envp` is the environment block;
    /// pass an empty slice for "inherit nothing" (libkrun does not
    /// propagate the host env).
    pub fn set_guest_entrypoint(
        &self,
        entry_path: &Path,
        argv: &[&str],
        envp: &[&str],
    ) -> Result<(), Error> {
        let entry = cstring(entry_path)?;
        let argv_owned: Vec<CString> = argv
            .iter()
            .map(|a| CString::new(*a).map_err(|_| Error::InvalidCString))
            .collect::<Result<_, _>>()?;
        let envp_owned: Vec<CString> = envp
            .iter()
            .map(|e| CString::new(*e).map_err(|_| Error::InvalidCString))
            .collect::<Result<_, _>>()?;
        let mut argv_ptrs: Vec<*const std::os::raw::c_char> =
            argv_owned.iter().map(|c| c.as_ptr()).collect();
        argv_ptrs.push(std::ptr::null());
        let mut envp_ptrs: Vec<*const std::os::raw::c_char> =
            envp_owned.iter().map(|c| c.as_ptr()).collect();
        envp_ptrs.push(std::ptr::null());
        check(unsafe {
            bindings::krun_set_exec(
                self.ctx_id,
                entry.as_ptr(),
                argv_ptrs.as_ptr(),
                envp_ptrs.as_ptr(),
            )
        })
    }

    pub fn set_kernel(
        &self,
        kernel_path: &Path,
        kernel_format: KernelFormat,
        initramfs: Option<&Path>,
        cmdline: Option<&str>,
    ) -> Result<(), Error> {
        let kernel = cstring(kernel_path)?;
        let initramfs = match initramfs {
            Some(p) => Some(cstring(p)?),
            None => None,
        };
        let cmdline = match cmdline {
            Some(s) => Some(CString::new(s).map_err(|_| Error::InvalidCString)?),
            None => None,
        };
        let initramfs_ptr = initramfs.as_ref().map_or(std::ptr::null(), |s| s.as_ptr());
        let cmdline_ptr = cmdline.as_ref().map_or(std::ptr::null(), |s| s.as_ptr());
        let format_u32 = to_krun_format(kernel_format)?;
        check(unsafe {
            bindings::krun_set_kernel(
                self.ctx_id,
                kernel.as_ptr(),
                format_u32,
                initramfs_ptr,
                cmdline_ptr,
            )
        })
    }

    pub fn add_vsock(&self, tsi_features: u32) -> Result<(), Error> {
        check(unsafe { bindings::krun_add_vsock(self.ctx_id, tsi_features) })
    }

    pub fn add_vsock_port(&self, port: u32, host_path: &Path) -> Result<(), Error> {
        let path = cstring(host_path)?;
        check(unsafe { bindings::krun_add_vsock_port(self.ctx_id, port, path.as_ptr()) })
    }

    /// Like [`Self::add_vsock_port`], but explicitly states which side
    /// listens. With `listen = true` ("guest expects connections to
    /// be initiated from host side"), libkrun creates a unix socket
    /// **listener** at `host_path`; sibling host processes connect to
    /// it as clients and libkrun forwards the connection to the
    /// guest's `AF_VSOCK` server. This is the right mode for mvm's
    /// guest agent, which always listens on `GUEST_AGENT_PORT`. With
    /// `listen = false`, libkrun does not create the file — the host
    /// is expected to bind a listener at `host_path` and libkrun
    /// proxies guest-initiated connects to it.
    pub fn add_vsock_port2(&self, port: u32, host_path: &Path, listen: bool) -> Result<(), Error> {
        let path = cstring(host_path)?;
        check(unsafe { bindings::krun_add_vsock_port2(self.ctx_id, port, path.as_ptr(), listen) })
    }

    pub fn add_virtiofs(&self, tag: &str, host_path: &Path) -> Result<(), Error> {
        let tag = CString::new(tag).map_err(|_| Error::InvalidCString)?;
        let path = cstring(host_path)?;
        check(unsafe { bindings::krun_add_virtiofs(self.ctx_id, tag.as_ptr(), path.as_ptr()) })
    }

    pub fn add_disk(&self, block_id: &str, disk_path: &Path, read_only: bool) -> Result<(), Error> {
        let block = CString::new(block_id).map_err(|_| Error::InvalidCString)?;
        let path = cstring(disk_path)?;
        check(unsafe {
            bindings::krun_add_disk(self.ctx_id, block.as_ptr(), path.as_ptr(), read_only)
        })
    }

    pub fn set_console_output(&self, host_path: &Path) -> Result<(), Error> {
        let path = cstring(host_path)?;
        check(unsafe { bindings::krun_set_console_output(self.ctx_id, path.as_ptr()) })
    }

    /// Add a virtio-net device backed by a unixstream userspace network
    /// proxy (Plan 87 W1 — passt + virtio-net replacing TSI).
    ///
    /// `fd` is one end of an `AF_UNIX SOCK_STREAM` socketpair; the other
    /// end is handed to the network proxy (passt) at spawn. libkrun
    /// owns its half of the socket from this point — it must remain
    /// open until `start_enter` is called, after which libkrun consumes
    /// it.
    ///
    /// Calling this disables libkrun's default TSI backend (per
    /// `libkrun.h:358`: "If no network interface is added, libkrun
    /// will automatically enable the TSI backend"). Subsequent
    /// `krun_set_port_map` calls return -ENOTSUP — passt manages port
    /// forwarding via its own DHCP + NAT path.
    ///
    /// `mac` is a 6-byte hardware address. Pass [0xAE, 0xAD, 0xBE,
    /// 0xEF, 0x00, 0x01] (locally-administered, unicast) for the
    /// default mvm builder VM.
    ///
    /// `features` is the virtio-net feature mask; for passt the
    /// canonical value is `COMPAT_NET_FEATURES` (definition mirrored
    /// from `libkrun.h:344`).
    pub fn add_net_unixstream_fd(
        &self,
        fd: i32,
        mac: &[u8; 6],
        features: u32,
        flags: u32,
    ) -> Result<(), Error> {
        // libkrun's `krun_add_net_unixstream` takes `c_path` and `fd`
        // as mutually-exclusive args (one is null/-1, the other is
        // populated). We always take the fd path — the socketpair
        // lives entirely in the parent process, no path on disk.
        check(unsafe {
            bindings::krun_add_net_unixstream(
                self.ctx_id,
                std::ptr::null(),
                fd,
                mac.as_ptr() as *mut u8,
                features,
                flags,
            )
        })
    }

    /// Add a virtio-net device backed by a unixgram userspace network
    /// proxy (Plan 88 W1 — gvproxy on macOS replacing passt). Mirror
    /// of [`Self::add_net_unixstream_fd`] but uses libkrun's
    /// `krun_add_net_unixgram` which takes a *path* to a listening
    /// unix-domain socket rather than a pre-opened fd — gvproxy
    /// creates the listener itself when invoked with
    /// `--listen-vfkit <path>`, and libkrun's host-side code
    /// connects to that path.
    ///
    /// `c_path` and `fd` are mutually exclusive in the C API; we
    /// always take the path arm so the caller (typically
    /// `mvm-libkrun::gvproxy::spawn`) owns the socket lifecycle.
    /// Pass `socket_path` as the path the gvproxy child listens on.
    ///
    /// Calling this disables libkrun's TSI backend (same as the
    /// unixstream wrapper). `features` should be
    /// [`super::PASST_NET_FEATURES`] — the macro is named after
    /// passt but `COMPAT_NET_FEATURES` in `libkrun.h:344` applies
    /// to both passt and gvproxy (`krun_set_gvproxy_path` lists it).
    pub fn add_net_unixgram_path(
        &self,
        socket_path: &Path,
        mac: &[u8; 6],
        features: u32,
        flags: u32,
    ) -> Result<(), Error> {
        let path = cstring(socket_path)?;
        check(unsafe {
            bindings::krun_add_net_unixgram(
                self.ctx_id,
                path.as_ptr(),
                /* fd = */ -1,
                mac.as_ptr() as *mut u8,
                features,
                flags,
            )
        })
    }

    /// Returns the shutdown eventfd. The caller is responsible for
    /// closing it (libkrun documents that the fd is owned by the
    /// caller once returned).
    pub fn shutdown_eventfd(&self) -> Result<i32, Error> {
        let rc = unsafe { bindings::krun_get_shutdown_eventfd(self.ctx_id) };
        if rc < 0 { Err(Error::Krun(rc)) } else { Ok(rc) }
    }

    /// Block the calling thread, starting the guest. libkrun's
    /// `krun_start_enter` calls `exit()` on success with the guest's
    /// status; on failure it returns a negative errno. Plan 57 W1
    /// surfaces the wrapper but does not call it from `crate::start` —
    /// that lands in W3 + W4 alongside the registry that owns the
    /// blocking thread.
    pub fn start_enter(&self) -> Result<std::convert::Infallible, Error> {
        let rc = unsafe { bindings::krun_start_enter(self.ctx_id) };
        // On success the call does not return; if we observe one, it's
        // an error path.
        Err(Error::Krun(rc))
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        let rc = unsafe { bindings::krun_free_ctx(self.ctx_id) };
        if rc < 0 {
            tracing::warn!(
                ctx_id = self.ctx_id,
                rc,
                "krun_free_ctx returned non-zero on drop"
            );
        }
    }
}

// libkrunfw's bundled kernel — Plan 86 / Plan 72 W5.D bullet 10.
//
// libkrunfw ships a TSI-patched Linux kernel image inside its dynamic
// library (`libkrunfw.5.dylib` on macOS, `libkrunfw.so.5` on Linux).
// The symbol `krunfw_get_kernel` returns a pointer to those kernel
// bytes plus the load + entry addresses libkrun expects when booting
// against them.
//
// We extract the kernel exactly once per `mvmctl` process at runtime
// and write it to a stable cache path, then hand that path to
// libkrun's `KrunContext.kernel_path`. The bundled kernel is the
// only kernel where libkrun's TSI mode (Transparent Socket
// Impersonation — the AF_INET-over-vsock path) is known to work
// correctly. Stock nixpkgs kernels lack the patches; our in-repo
// port of the libkrunfw patches (nix/images/builder-vm/kernel/)
// kernel-oops's on socket close against nixpkgs 6.12.87.
//
// The bundled-kernel approach matches libkrun's own documented
// expectation: every libkrun-using consumer either uses this kernel
// or accepts that AF_INET sockets won't work in the guest.
#[link(name = "krunfw")]
unsafe extern "C" {
    fn krunfw_get_kernel(load_addr: *mut u64, entry_addr: *mut u64, size: *mut usize) -> *const u8;
}

/// Result of [`extract_bundled_kernel`]: a path to the kernel bytes on
/// disk plus the load + entry addresses libkrun's `set_kernel` call
/// will pair with that path.
#[derive(Debug, Clone)]
pub struct BundledKernel {
    pub path: std::path::PathBuf,
    pub load_addr: u64,
    pub entry_addr: u64,
    pub size: usize,
}

/// Extract the TSI-patched kernel bundled in `libkrunfw` and write it
/// to `target_path`. Idempotent — if `target_path` already exists with
/// the same byte length the call short-circuits and returns the cached
/// load/entry addresses.
///
/// `target_path` SHOULD be a stable per-host location (e.g.
/// `~/.cache/mvm/libkrunfw/vmlinux`) so subsequent invocations skip the
/// copy. Errors propagate as [`Error::Init`] with a description of the
/// failed step.
pub fn extract_bundled_kernel(target_path: &Path) -> Result<BundledKernel, Error> {
    let mut load_addr: u64 = 0;
    let mut entry_addr: u64 = 0;
    let mut size: usize = 0;

    // SAFETY: `krunfw_get_kernel` returns a pointer into libkrunfw's
    // own `.rodata` segment — valid for the lifetime of the process.
    // The three output pointers we pass are all non-null and aligned.
    // The returned slice is read-only.
    let bytes_ptr = unsafe { krunfw_get_kernel(&mut load_addr, &mut entry_addr, &mut size) };

    if bytes_ptr.is_null() || size == 0 {
        return Err(Error::Io {
            context: "krunfw_get_kernel returned null/zero — libkrunfw missing or version mismatch"
                .to_string(),
        });
    }

    // SAFETY: `bytes_ptr` is non-null and points to `size` initialised
    // bytes inside libkrunfw's `.rodata` (lifetime = process). Treating
    // the slice as read-only is correct.
    let bytes = unsafe { std::slice::from_raw_parts(bytes_ptr, size) };

    if let Some(parent) = target_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| Error::Io {
            context: format!(
                "creating libkrunfw kernel cache parent {}: {e}",
                parent.display()
            ),
        })?;
    }

    let needs_write = match std::fs::metadata(target_path) {
        Ok(meta) => meta.len() != size as u64,
        Err(_) => true,
    };
    if needs_write {
        // Write atomically — staging file + rename so a concurrent
        // mvmctl process can't observe a torn write.
        let staging = target_path.with_extension("staging");
        std::fs::write(&staging, bytes).map_err(|e| Error::Io {
            context: format!("writing libkrunfw kernel to {}: {e}", staging.display()),
        })?;
        std::fs::rename(&staging, target_path).map_err(|e| Error::Io {
            context: format!(
                "promoting {} -> {}: {e}",
                staging.display(),
                target_path.display()
            ),
        })?;
    }

    Ok(BundledKernel {
        path: target_path.to_path_buf(),
        load_addr,
        entry_addr,
        size,
    })
}

pub fn set_log_level(level: LogLevel) -> Result<(), Error> {
    check(unsafe { bindings::krun_set_log_level(level.as_u32()) })
}

fn check(rc: i32) -> Result<(), Error> {
    if rc < 0 { Err(Error::Krun(rc)) } else { Ok(()) }
}

fn cstring(path: &Path) -> Result<CString, Error> {
    let s = path.to_str().ok_or(Error::InvalidCString)?;
    CString::new(s).map_err(|_| Error::InvalidCString)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_and_drop_context() {
        // Smoke test: the FFI links cleanly and an empty context can be
        // allocated + freed. Doesn't boot a VM (that's W3) — just proves
        // the wrapper round-trips through libkrun.
        let ctx = Context::new().expect("libkrun ctx allocation succeeds on a host with libkrun");
        assert!(ctx.id() < u32::MAX);
        // Drop runs krun_free_ctx; assertion is the absence of a panic.
    }

    #[test]
    fn log_level_is_settable() {
        // `set_log_level` is the first FFI call any process does — it
        // touches no resources beyond the global logger. A round-trip
        // here catches a broken link without needing a ctx.
        set_log_level(LogLevel::Warn).expect("krun_set_log_level returns zero");
    }

    #[test]
    fn vm_config_round_trips() {
        let ctx = Context::new().expect("ctx allocation");
        ctx.set_vm_config(1, 128).expect("vm config accepted");
    }
}
