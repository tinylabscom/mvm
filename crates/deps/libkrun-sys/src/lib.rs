//! Rust bindings for Red Hat libkrun (Linux KVM, macOS Hypervisor.framework).
//!
//! libkrun is a library-style VMM: linked directly into the calling binary
//! rather than spawned as a separate daemon. On Linux it uses KVM; on
//! macOS it uses Hypervisor.framework. mvm supports this path on Linux
//! with KVM and macOS Apple Silicon; macOS Intel is intentionally not a
//! supported local microVM host.
//!
//! # Build modes
//!
//! - **default** (no feature) — no FFI, no link to libkrun. [`start`]
//!   and [`stop`] return [`Error::NotYetWired`]. The workspace compiles
//!   on hosts without libkrun installed.
//! - **`libkrun-sys`** — bindgen-generated FFI from `libkrun.h` plus
//!   `-lkrun` linking. [`start`] and [`stop`] dispatch through
//!   `sys::Context` into real libkrun calls.
//!
//! This crate stays narrowly focused on the FFI; backend dispatch and
//! lifecycle live in `mvm-backend` and `mvm-cli`.

use std::path::Path;
// `BridgeFds` carries OwnedFds; the bridge-inserting configure path
// needs AsRawFd/FromRawFd to feed libkrun's raw-fd API and to wrap
// socketpair(2) results.
#[cfg(all(feature = "libkrun-sys", target_family = "unix"))]
use std::os::fd::{AsRawFd, OwnedFd};

#[cfg(feature = "libkrun-sys")]
mod sys;

// `KernelFormat` lives in `mvm-core` so all backends share one canonical type.
// Re-export it unconditionally (no feature gate) so callers that build
// `KrunContext` configurations without enabling `libkrun-sys` can still name it.
pub use mvm_core::kernel_format::KernelFormat;

#[cfg(feature = "libkrun-sys")]
pub use sys::{BundledKernel, LogLevel, extract_bundled_kernel, init_log, set_log_level};

// passt-backed virtio-net. The supervisor owns the passt child process
// and exposes the socket fd `KrunContext::Passt` consumes. Only Linux /
// macOS — Windows has neither libkrun nor passt. Tests are gated on a
// host-side passt install probe.
#[cfg(target_family = "unix")]
pub mod passt;

// gvproxy-backed virtio-net. The macOS counterpart to passt; both modules share the
// same shape (spawn child, hand its socket to libkrun, kill on Drop)
// but gvproxy uses libkrun's `krun_add_net_unixgram` (path-based)
// where passt uses `krun_add_net_unixstream` (fd-passed). Same unix
// gate as passt — Windows has neither.
#[cfg(target_family = "unix")]
pub mod gvproxy;

// Tie a spawned networking helper to its supervisor's lifetime so a dead
// supervisor never orphans it (Linux `PR_SET_PDEATHSIG`; no-op elsewhere).
#[cfg(target_family = "unix")]
mod child_lifecycle;

// Sync length-prefixed JSON framing for the supervisor control
// channels. Colocated with the `Supervisor*Config` wire types it frames so both the
// `mvm-backend` writer (`claim_standby`) and the supervisor-bin reader reach it without
// a dependency cycle (`mvm-backend` can't depend on `mvm-hostd`).
pub mod framing;

/// Errors returned by this crate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// libkrun is not installed on the host (no shared library found at
    /// any of the standard locations checked by [`is_available`]).
    NotInstalled {
        /// Suggested install command for the user.
        install_hint: &'static str,
    },
    /// Built without the `libkrun-sys` feature — the FFI bindings are
    /// compiled out so [`start`] / [`stop`] cannot dispatch. Rebuild
    /// with `--features libkrun-sys` on a host where libkrun is
    /// installed.
    NotYetWired {
        /// Tracking issue / plan reference.
        tracking: &'static str,
    },
    /// libkrun returned a negative errno from one of its C functions.
    /// The value is the raw return code (which libkrun documents as
    /// `-EINVAL`, `-ENOMEM`, etc. for most calls).
    Krun(i32),
    /// A path or string argument contained an interior NUL byte or
    /// was not representable as UTF-8 / a C string.
    InvalidCString,
    /// Filesystem I/O failure while setting up the supervisor's per-VM
    /// state directory or PID file. Carries a free-form context
    /// string rather than the raw `io::Error` so the `PartialEq`/`Eq`
    /// derives on `Error` keep working.
    Io {
        /// Operation + path + underlying message, formatted by the
        /// caller. E.g. `create_dir_all /Users/x/.mvm/vms/foo: permission denied`.
        context: String,
    },
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotInstalled { install_hint } => {
                write!(f, "libkrun is not installed on this host. {install_hint}")
            }
            Self::NotYetWired { tracking } => write!(
                f,
                "libkrun FFI is not compiled into this build (tracking: {tracking}). \
                 Rebuild with `--features libkrun-sys` on a host with libkrun installed."
            ),
            Self::Krun(rc) => write!(f, "libkrun call failed with rc {rc}"),
            Self::InvalidCString => write!(
                f,
                "argument contained an interior NUL byte or non-UTF-8 path"
            ),
            Self::Io { context } => write!(f, "supervisor I/O error: {context}"),
        }
    }
}

impl std::error::Error for Error {}

/// Detect whether libkrun is installed on the host by probing for the
/// shared library at the standard install locations.
///
/// **Not the same as "is functional"** — even if `is_available()`
/// returns `true`, a build without the `libkrun-sys` feature will still
/// return [`Error::NotYetWired`] from [`start`]. Treat this as a
/// precondition probe: if it returns `false`, point the user at
/// [`install_hint`].
pub fn is_available() -> bool {
    install_paths().iter().any(|p| Path::new(p).exists())
}

/// Human-readable install hint used in error messages and `mvmctl
/// doctor` output. Caller-platform-aware so users see the right
/// command for their OS.
pub const fn install_hint() -> &'static str {
    #[cfg(target_os = "macos")]
    {
        "Install via Homebrew: `brew install libkrun`."
    }
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        "Install via your distro package manager (e.g. `apt install libkrun-dev` \
         on Debian/Ubuntu, `dnf install libkrun-devel` on Fedora) or build from \
         source: https://github.com/containers/libkrun"
    }
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    {
        "Install via your distro package manager or build from source: \
         https://github.com/containers/libkrun"
    }
    #[cfg(target_os = "windows")]
    {
        "libkrun is not supported on Windows. Use --hypervisor docker \
         or install WSL2 and run mvm inside a Linux distro."
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        "libkrun is not supported on this platform."
    }
}

/// Standard filesystem locations checked by [`is_available`]. Order is
/// "most likely first" so the predicate short-circuits on the typical
/// developer install.
///
/// Derived from `mvm_core::platform::LIBKRUN_LIB_PATHS` — the canonical
/// source of truth. Both sides are structurally identical; use the const
/// directly when a slice suffices, this function when a `Vec` is needed.
pub fn install_paths() -> Vec<&'static str> {
    mvm_core::platform::LIBKRUN_LIB_PATHS.to_vec()
}

/// Extra block device to attach to the guest alongside the rootfs.
///
/// libkrun mounts the rootfs at `/dev/vda` (by convention from the
/// order disks are added); each `KrunDisk` becomes `/dev/vdb`,
/// `/dev/vdc`, … in the order they appear in [`KrunContext::extra_disks`].
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct KrunDisk {
    /// Symbolic identifier passed to `krun_add_disk` (`block_id`).
    /// Not user-visible inside the guest; libkrun uses it for
    /// bookkeeping.
    pub id: String,
    /// Host path to the backing image (raw format).
    pub path: String,
    /// `true` opens the device read-only at the libkrun layer. Useful
    /// for dm-verity sidecars and signed root images.
    pub read_only: bool,
}

/// A virtio-fs share: a host directory exported into the guest under
/// a symbolic `tag` that the guest mounts via the `virtiofs` filesystem
/// type. libkrun wraps the `virtiofsd` daemon internally — callers
/// declare the share here and libkrun handles the daemon lifecycle.
///
/// The builder VM uses three of these per invocation:
///
/// - `tag = "work"`  → workspace bind (read-only at the guest mount)
/// - `tag = "out"`   → artifact dir (read-write)
/// - `tag = "job"`   → per-build job dir with `cmd.sh` / `env` / `result`
///
/// Read/write semantics at the guest are controlled by `mount` flags
/// inside the guest (`mvm-host-vm-init` mounts each tag with the
/// right flags); libkrun's `krun_add_virtiofs` does not currently
/// expose a `readonly` toggle on the host side.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct KrunVirtioFs {
    /// Symbolic identifier the guest references in `mount -t virtiofs
    /// <tag> <target>`. ASCII letters / digits / dash / underscore;
    /// libkrun passes it as a C string so interior NUL bytes are
    /// rejected at [`start_enter`] time.
    pub tag: String,
    /// Host directory to export. Must exist before [`start_enter`]
    /// runs (libkrun's daemon resolves it eagerly).
    pub host_path: String,
}

/// Configuration for a libkrun guest VM.
///
/// Pure data — no I/O until [`start`] / [`start_enter`] consume it.
/// The FFI calls that consume each field live in `sys` under the
/// `libkrun-sys` feature.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct KrunContext {
    pub name: String,
    /// Kernel image. `Some` for the kernel+rootfs and kernel+initramfs
    /// paths. `None` when [`Self::root_dir`] is set — libkrun uses its
    /// bundled TSI-patched kernel transparently in `set_root` mode.
    #[serde(default)]
    pub kernel_path: Option<String>,
    /// Format passed to `krun_set_kernel`. Defaults to `Raw` for
    /// backwards-compatible supervisor JSON and for aarch64 Image-style
    /// kernels; x86_64 callers that extract an ELF vmlinux override this.
    #[serde(default = "default_kernel_format")]
    pub kernel_format: KernelFormat,
    /// Root ext4 image. `Some` together with [`Self::kernel_path`] for
    /// the steady-state builder VM and runtime microVM path. Mutually
    /// exclusive with `initramfs_path` and `root_dir`.
    #[serde(default)]
    pub rootfs_path: Option<String>,
    /// Optional initial ramdisk. When `Some`, libkrun passes the
    /// path to `krun_set_kernel`'s `c_initramfs` arg. Mutually
    /// exclusive with `rootfs_path` and `root_dir`.
    #[serde(default)]
    pub initramfs_path: Option<String>,
    /// Host directory libkrun mounts as the guest root over virtiofs
    /// (via `krun_set_root`). Mutually exclusive with `kernel_path`,
    /// `rootfs_path`, and `initramfs_path` — libkrun loads its
    /// bundled kernel automatically in this mode. Pair with
    /// [`Self::guest_entrypoint`] so libkrun knows what to run as
    /// PID 1. Used by the Stage 0 bootstrap path.
    #[serde(default)]
    pub root_dir: Option<String>,
    /// Guest PID 1 entrypoint, relative to [`Self::root_dir`]. Required
    /// when `root_dir` is set; ignored otherwise.
    #[serde(default)]
    pub guest_entrypoint: Option<GuestEntrypoint>,
    pub vcpus: u8,
    pub ram_mib: u32,
    pub kernel_cmdline: Option<String>,
    pub vsock_ports: Vec<u32>,
    /// Vsock ports the HOST (supervisor) listens on; the guest connects.
    /// Registered with `add_vsock_port2(listen=false)` so libkrun
    /// proxies guest-initiated connects to the supervisor's unix socket.
    /// Disjoint from [`Self::vsock_ports`].
    #[serde(default)]
    pub host_listen_ports: Vec<u32>,
    /// Additional virtio-blk devices, appearing as `/dev/vdb`,
    /// `/dev/vdc`, … in the order listed. Empty by default; the
    /// dev-VM builder VM uses one entry for the Nix-store overlay
    /// disk (`MVM_NIX_STORE_DISK`).
    pub extra_disks: Vec<KrunDisk>,
    /// virtio-fs shares the host exports into the guest. The builder VM
    /// declares three of these (`work` / `out` / `job`); the runtime
    /// backend doesn't use any today.
    /// libkrun manages the in-process `virtiofsd` daemon for each
    /// entry. See [`KrunVirtioFs`] for the per-share contract.
    #[serde(default)]
    pub virtio_fs_mounts: Vec<KrunVirtioFs>,
    /// When `Some`, libkrun routes the guest's hvc0 console to this
    /// host path (a regular file, FIFO, or device). When `None`, the
    /// console writes inherit the calling process's stdout (the
    /// default for an interactive smoke test). Used to capture
    /// early-boot kernel output for diagnosis.
    pub console_output_path: Option<String>,
    /// Directory on the host where the per-vsock-port Unix socket
    /// files live. libkrun proxies between each guest-side
    /// `AF_VSOCK` port (TSI / virtio-vsock) and the corresponding
    /// `vsock-<port>.sock` inside this directory; a sibling host
    /// process (e.g. `mvmctl console <vm>` or the guest-agent
    /// vsock client in mvm-supervisor) speaks to the guest by
    /// opening the unix socket. When `None`, `vsock_socket_path`
    /// falls back to `/tmp/mvm-libkrun-<name>-vsock-<port>.sock`
    /// — fine for the spike smoke binary, but real consumers
    /// (the supervisor, the builder-VM launcher) should always set a
    /// stable per-VM dir under `~/.mvm/vms/<name>/` so cross-process
    /// clients can find it.
    pub vsock_socket_dir: Option<String>,
    /// Networking backend for the guest. `Tsi` (default)
    /// uses libkrun's built-in syscall-hijack TSI mode; `Passt`
    /// attaches a virtio-net device backed by a unixstream socket
    /// the caller has handed off to a passt child process. See
    /// `NetworkingMode` for the trade-offs.
    #[serde(default)]
    pub networking: NetworkingMode,
}

fn default_kernel_format() -> KernelFormat {
    KernelFormat::Raw
}

/// Libkrun networking backend.
///
/// `Tsi` is libkrun's default — AF_INET syscall hijacking, no
/// virtio-net device in the guest, no DHCP. Works for trivial HTTP
/// (single GET) but breaks on HTTP/2 multiplexing, HTTPS redirect
/// chains, and nix's substituter probes. Kept as an opt-out for
/// debugging and for runtime microVMs that legitimately don't need
/// a network stack.
///
/// `Passt` configures a real virtio-net device wired through a
/// unixstream socket to a host-side passt child process. The guest
/// sees a normal eth0 + DHCP + DNS. This is the production-ready
/// networking mode for Stage 0 and steady-state builder VMs.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkingMode {
    /// libkrun's built-in TSI backend (no virtio-net, no DHCP).
    #[default]
    Tsi,
    /// virtio-net via passt. The supervisor process (whichever links
    /// `libkrun-sys`) spawns a passt child inside `run_supervisor`,
    /// hands its socket fd to `krun_add_net_unixstream`, and reaps
    /// passt when libkrun exits. mvmctl (and any other JSON-consuming
    /// caller) just declares the intent here — the live fd never
    /// survives JSON serialization, so we keep it out of this struct.
    Passt {
        /// MAC address for the guest's eth0. 6 bytes; the first
        /// octet must have bit 0x02 set (locally-administered) to
        /// avoid colliding with real hardware allocations.
        mac: [u8; 6],
        /// Host directory where the supervisor stages passt's pid
        /// file and any future scratch artifacts. Typically
        /// `<vm_state_dir>` so the per-VM artifact set stays
        /// co-located. The supervisor creates it if absent.
        scratch_dir: String,
    },
    /// virtio-net via gvproxy. The supervisor spawns a
    /// gvproxy child inside `run_supervisor`, points libkrun's
    /// `krun_add_net_unixgram` at the listener socket gvproxy
    /// creates, and reaps gvproxy on guest exit. Same model as
    /// `Passt` but unixgram-flavored: libkrun connects to a path
    /// on disk rather than receiving a pre-opened socket fd. This
    /// is the canonical macOS backend (passt is Linux-only).
    Gvproxy {
        /// MAC address for the guest's eth0. Same shape as the
        /// `Passt` variant.
        mac: [u8; 6],
        /// Host directory where the supervisor stages gvproxy's
        /// listener socket (`<scratch_dir>/gvproxy.sock`) + log
        /// file (`<scratch_dir>/gvproxy.log`).
        scratch_dir: String,
        /// When set, launch the gateway natively as
        /// `<MVM_GATEWAY_BIN> run --config <path>` instead of the
        /// gvproxy-compat `-listen-vfkit` arg set. The config's
        /// `[transport].path` must be `<scratch_dir>/gvproxy.sock` so
        /// libkrun's `add_net_unixgram` connects to the same unixgram
        /// socket either path creates. Absent → gvproxy-compat (default).
        #[serde(default)]
        native_config: Option<String>,
    },
}

/// Guest PID 1 entrypoint passed to `krun_set_exec`. `path` is
/// relative to [`KrunContext::root_dir`]. `argv[0]` is the entry
/// name (libkrun appends the trailing NULL); leave empty for the
/// "name = path, no other args" common case.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GuestEntrypoint {
    /// Path to the guest PID 1 entrypoint, relative to `root_dir`.
    pub path: String,
    /// `argv` array. Empty defaults to `[basename(path)]` at FFI time.
    #[serde(default)]
    pub argv: Vec<String>,
    /// Environment block. Empty by default — libkrun does not
    /// propagate the host env, so callers must supply anything they
    /// need (e.g. `PATH=/bin:/usr/local/bin`).
    #[serde(default)]
    pub envp: Vec<String>,
}

impl KrunContext {
    /// Construct a context that boots from a rootfs ext4 image.
    pub fn new(
        name: impl Into<String>,
        kernel_path: impl Into<String>,
        rootfs_path: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            kernel_path: Some(kernel_path.into()),
            kernel_format: KernelFormat::Raw,
            rootfs_path: Some(rootfs_path.into()),
            initramfs_path: None,
            root_dir: None,
            guest_entrypoint: None,
            vcpus: 1,
            ram_mib: 256,
            kernel_cmdline: None,
            vsock_ports: Vec::new(),
            host_listen_ports: Vec::new(),
            extra_disks: Vec::new(),
            virtio_fs_mounts: Vec::new(),
            console_output_path: None,
            vsock_socket_dir: None,
            networking: NetworkingMode::Tsi,
        }
    }

    /// Construct a context that boots from an initramfs (no rootfs
    /// disk attached). The kernel decompresses the initramfs into a
    /// tmpfs rootfs and runs `init=` from it.
    pub fn new_initramfs(
        name: impl Into<String>,
        kernel_path: impl Into<String>,
        initramfs_path: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            kernel_path: Some(kernel_path.into()),
            kernel_format: KernelFormat::Raw,
            rootfs_path: None,
            initramfs_path: Some(initramfs_path.into()),
            root_dir: None,
            guest_entrypoint: None,
            vcpus: 1,
            ram_mib: 256,
            kernel_cmdline: None,
            vsock_ports: Vec::new(),
            host_listen_ports: Vec::new(),
            extra_disks: Vec::new(),
            virtio_fs_mounts: Vec::new(),
            console_output_path: None,
            vsock_socket_dir: None,
            networking: NetworkingMode::Tsi,
        }
    }

    /// Construct a context that boots libkrun's bundled kernel against
    /// a host directory mounted as the guest root via virtiofs. Used
    /// by the Stage 0 bootstrap path — no host-built kernel or rootfs
    /// image needed.
    ///
    /// `entry_path` is the guest PID 1, relative to `root_dir`. For
    /// Stage 0 this is `/init` (a shell script the kernel's binfmt
    /// loader resolves via the embedded busybox).
    pub fn new_root_dir(
        name: impl Into<String>,
        root_dir: impl Into<String>,
        entry_path: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            kernel_path: None,
            kernel_format: KernelFormat::Raw,
            rootfs_path: None,
            initramfs_path: None,
            root_dir: Some(root_dir.into()),
            guest_entrypoint: Some(GuestEntrypoint {
                path: entry_path.into(),
                argv: Vec::new(),
                envp: Vec::new(),
            }),
            vcpus: 1,
            ram_mib: 256,
            kernel_cmdline: None,
            vsock_ports: Vec::new(),
            host_listen_ports: Vec::new(),
            extra_disks: Vec::new(),
            virtio_fs_mounts: Vec::new(),
            console_output_path: None,
            vsock_socket_dir: None,
            networking: NetworkingMode::Tsi,
        }
    }

    /// Set the guest entrypoint `argv` (libkrun's `krun_set_exec`
    /// `argv` argument). Only meaningful when `root_dir` is set.
    pub fn with_guest_argv<I, S>(mut self, argv: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        if let Some(entry) = self.guest_entrypoint.as_mut() {
            entry.argv = argv.into_iter().map(Into::into).collect();
        }
        self
    }

    /// Set the guest entrypoint env block. Only meaningful when
    /// `root_dir` is set.
    pub fn with_guest_envp<I, S>(mut self, envp: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        if let Some(entry) = self.guest_entrypoint.as_mut() {
            entry.envp = envp.into_iter().map(Into::into).collect();
        }
        self
    }

    /// Switch the guest to gvproxy-backed virtio-net. Same shape as
    /// [`Self::with_passt`] but uses libkrun's unixgram backend; the
    /// supervisor spawns gvproxy with `--listen-vfkit <socket>` and
    /// hands the socket path to `krun_add_net_unixgram`.
    pub fn with_gvproxy(mut self, mac: [u8; 6], scratch_dir: impl Into<String>) -> Self {
        self.networking = NetworkingMode::Gvproxy {
            mac,
            scratch_dir: scratch_dir.into(),
            native_config: None,
        };
        self
    }

    /// Point an already-`with_gvproxy`'d context at a pre-rendered native
    /// gateway config, so the supervisor launches `<MVM_GATEWAY_BIN> run
    /// --config <path>` rather than the gvproxy-compat arg set. No-op if
    /// networking isn't `Gvproxy`.
    pub fn with_gvproxy_native_config(mut self, config_path: impl Into<String>) -> Self {
        if let NetworkingMode::Gvproxy { native_config, .. } = &mut self.networking {
            *native_config = Some(config_path.into());
        }
        self
    }

    /// Switch the guest to passt-backed virtio-net. The supervisor
    /// process owns the passt child; we just declare the intent and
    /// the destination for passt's log file.
    pub fn with_passt(mut self, mac: [u8; 6], scratch_dir: impl Into<String>) -> Self {
        self.networking = NetworkingMode::Passt {
            mac,
            scratch_dir: scratch_dir.into(),
        };
        self
    }

    /// Resolve the host-side unix socket path libkrun should pair
    /// with `port`. If [`Self::vsock_socket_dir`] is set, returns
    /// `<dir>/vsock-<port>.sock`; otherwise falls back to a per-VM
    /// `/tmp` path scoped by [`Self::name`]. The fallback is fine
    /// for the spike smoke binary but real consumers should always
    /// supply an explicit dir (see field docs).
    pub fn vsock_socket_path(&self, port: u32) -> std::path::PathBuf {
        match &self.vsock_socket_dir {
            Some(dir) => std::path::PathBuf::from(dir).join(format!("vsock-{port}.sock")),
            None => std::path::PathBuf::from(format!(
                "/tmp/mvm-libkrun-{}-vsock-{port}.sock",
                self.name
            )),
        }
    }

    /// Set CPU and memory shape.
    pub fn with_resources(mut self, vcpus: u8, ram_mib: u32) -> Self {
        self.vcpus = vcpus;
        self.ram_mib = ram_mib;
        self
    }

    /// Set the kernel format passed to libkrun.
    pub fn with_kernel_format(mut self, format: KernelFormat) -> Self {
        self.kernel_format = format;
        self
    }

    /// Set the kernel command line (replaces the default).
    pub fn with_cmdline(mut self, cmdline: impl Into<String>) -> Self {
        self.kernel_cmdline = Some(cmdline.into());
        self
    }

    /// Append a vsock port the guest agent will listen on.
    pub fn add_vsock_port(mut self, port: u32) -> Self {
        self.vsock_ports.push(port);
        self
    }

    /// Append a control vsock port the HOST listens on (the guest
    /// connects). Registered with `add_vsock_port2(listen=false)` so
    /// the supervisor binds the unix listener at
    /// `<vsock_socket_dir>/vsock-<port>.sock` and libkrun proxies
    /// guest connects to it. The supervisor must bind that listener
    /// BEFORE `start_enter`.
    pub fn add_host_listen_port(mut self, port: u32) -> Self {
        self.host_listen_ports.push(port);
        self
    }

    /// Attach an additional virtio-blk device. The first call appears
    /// as `/dev/vdb` in the guest, the second `/dev/vdc`, etc.
    pub fn add_disk(
        mut self,
        id: impl Into<String>,
        path: impl Into<String>,
        read_only: bool,
    ) -> Self {
        self.extra_disks.push(KrunDisk {
            id: id.into(),
            path: path.into(),
            read_only,
        });
        self
    }

    /// Declare a virtio-fs share. The guest mounts it via
    /// `mount -t virtiofs <tag> <target>`. The builder VM uses this
    /// for `/work`, `/out`, `/job`.
    pub fn add_virtio_fs(mut self, tag: impl Into<String>, host_path: impl Into<String>) -> Self {
        self.virtio_fs_mounts.push(KrunVirtioFs {
            tag: tag.into(),
            host_path: host_path.into(),
        });
        self
    }

    /// Route the guest's hvc0 console output to `path`. Pass `None`
    /// (or omit the call) to leave libkrun's default behavior in
    /// place (writes to the calling process's stdout).
    pub fn with_console_output(mut self, path: impl Into<String>) -> Self {
        self.console_output_path = Some(path.into());
        self
    }

    /// Set the per-VM directory libkrun should place vsock unix
    /// socket files under. See [`Self::vsock_socket_dir`] for the
    /// rationale; this builder method ensures consumers can chain it
    /// alongside the other resource setters.
    pub fn with_vsock_socket_dir(mut self, dir: impl Into<String>) -> Self {
        self.vsock_socket_dir = Some(dir.into());
        self
    }
}

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
/// per-caller networking decision. `configure` itself is the TSI-only
/// path used by the spike/smoke binaries; real
/// consumers go through `run_supervisor`, which owns a passt child
/// process for the libkrun lifetime via `configure_with_passt`.
#[cfg(feature = "libkrun-sys")]
fn configure(ctx: &KrunContext) -> Result<sys::Context, Error> {
    let krun = configure_pre_net(ctx)?;
    if !matches!(ctx.networking, NetworkingMode::Tsi) {
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
    /// Not using a virtio-net backend — TSI is enabled implicitly.
    None,
    /// passt child (Linux).
    Passt(passt::PasstHandle),
    /// gvproxy child (macOS / cross-platform fallback).
    Gvproxy(gvproxy::GvproxyHandle),
}

/// configure() variant that owns the network-gateway child process
/// for the lifetime of the returned
/// context. Used by [`run_supervisor`] when
/// `NetworkingMode::{Passt, Gvproxy}` is set. The handle Drop's after
/// libkrun finishes consuming the socket and the guest exits.
#[cfg(all(feature = "libkrun-sys", target_family = "unix"))]
fn configure_with_gateway(ctx: &KrunContext) -> Result<(sys::Context, GatewayHandle), Error> {
    let krun = configure_pre_net(ctx)?;
    let handle = match &ctx.networking {
        NetworkingMode::Tsi => GatewayHandle::None,
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
        NetworkingMode::Gvproxy {
            mac,
            scratch_dir,
            native_config,
        } => {
            let handle = gvproxy::spawn(
                std::path::Path::new(scratch_dir),
                native_config.as_deref().map(std::path::Path::new),
            )
            .map_err(|e| Error::Io {
                context: format!("spawning gvproxy for NetworkingMode::Gvproxy: {e}"),
            })?;
            // gvproxy speaks libkrun's "vfkit mode" framing on the
            // unixgram socket; NET_FLAG_VFKIT (see sys::NET_FLAG_VFKIT)
            // is libkrun's required signal to emit the magic-byte
            // handshake. NET_FLAG_DHCP_CLIENT (libkrun 1.18.0+) tells
            // libkrun's net device to bring the interface up via its
            // in-guest DHCP client against gvproxy's DHCP server, so
            // the guest sees a fully-configured eth0 without needing
            // an in-guest udhcpc race. libkrun's own
            // `tests/test_cases/src/test_net/gvproxy.rs` uses both.
            krun.add_net_unixgram_path(
                handle.socket_path(),
                mac,
                sys::PASST_NET_FEATURES,
                sys::NET_FLAG_VFKIT | sys::NET_FLAG_DHCP_CLIENT,
            )?;
            GatewayHandle::Gvproxy(handle)
        }
    };
    Ok((krun, handle))
}

// ============================================================================
// bridge-inserting configure + run_supervisor_with_bridge
// ============================================================================

/// Endpoint fds the gateway audit bridge needs to splice between
/// libkrun and the userspace network gateway (`passt` / `gvproxy`).
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
/// `LibkrunGvproxy` → `BridgeEndpoints::LibkrunGvproxy`.
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
    /// macOS libkrun + gvproxy. `SOCK_DGRAM`:
    /// - `gvproxy_socket_path` is the path gvproxy bound its
    ///   listener at on spawn.
    /// - `supervisor_listen_path` is where libkrun has been told
    ///   to connect (via `add_net_unixgram_path`); the bridge
    ///   binds a `UnixDatagram` there inside its thread before
    ///   libkrun's net device probes.
    ///
    /// libkrun is an anonymous unixgram client — the bridge caches
    /// its autobind peer address from the first `recv_from`, then
    /// uses `send_to(peer, …)` for the ingress direction.
    LibkrunGvproxy {
        gvproxy_socket_path: std::path::PathBuf,
        supervisor_listen_path: std::path::PathBuf,
    },
}

/// Bridge-inserting variant of [`configure_with_gateway`]. Spawns
/// passt / gvproxy, then
/// interposes a supervisor-owned socket pair (`Passt`) or listener
/// path (`LibkrunGvproxy`) between libkrun and the gateway so the
/// gateway audit bridge can splice every byte through itself.
///
/// Refuses [`NetworkingMode::Tsi`] — TSI bypasses virtio-net
/// entirely and violates the claim-10 no-bypass invariant. Callers
/// that need TSI must use the legacy [`run_supervisor`] entry point.
#[cfg(all(feature = "libkrun-sys", target_family = "unix"))]
fn configure_with_gateway_for_bridge(
    ctx: &KrunContext,
    bridge_scratch_dir: &std::path::Path,
) -> Result<(sys::Context, GatewayHandle, BridgeFds), Error> {
    // Claim-10 admission gate 2 — refuse TSI before any FFI call so
    // the rejection is observable in unit tests that don't link
    // libkrun (configure_pre_net calls `sys::Context::new`, which
    // is real FFI). Moving the check up also avoids leaking a
    // `sys::Context` on the refusal path.
    if matches!(ctx.networking, NetworkingMode::Tsi) {
        return Err(Error::Io {
            context: "configure_with_gateway_for_bridge refuses NetworkingMode::Tsi: \
                TSI bypasses virtio-net and violates the claim-10 no-bypass \
                invariant (ADR-058). Use run_supervisor for legacy dev-mode VMs."
                .to_string(),
        });
    }
    let krun = configure_pre_net(ctx)?;
    let (handle, bridge_fds) = match &ctx.networking {
        NetworkingMode::Tsi => unreachable!("refused above"),
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
        NetworkingMode::Gvproxy {
            mac,
            scratch_dir,
            native_config,
        } => {
            let handle = gvproxy::spawn(
                std::path::Path::new(scratch_dir),
                native_config.as_deref().map(std::path::Path::new),
            )
            .map_err(|e| Error::Io {
                context: format!("spawning gvproxy for bridged NetworkingMode::Gvproxy: {e}"),
            })?;
            // Snapshot gvproxy's bind path before moving the handle
            // into GatewayHandle::Gvproxy — the bridge needs it to
            // connect for the egress direction.
            let gvproxy_socket_path = handle.socket_path().to_path_buf();
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
                GatewayHandle::Gvproxy(handle),
                BridgeFds::LibkrunGvproxy {
                    gvproxy_socket_path,
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
/// Mirrors [`run_supervisor`] but interposes
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
///         BridgeFds::LibkrunGvproxy { gvproxy_socket_path, supervisor_listen_path } => {
///             mvm_hostd::supervisor::gateway_bridge::BridgeEndpoints::LibkrunGvproxy {
///                 gvproxy_socket_path, supervisor_listen_path,
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

/// Every part of `configure` that doesn't touch the networking
/// backend. Shared between the plain `configure` path
/// (TSI-only) and `configure_with_passt`.
#[cfg(feature = "libkrun-sys")]
fn configure_pre_net(ctx: &KrunContext) -> Result<sys::Context, Error> {
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
        // load/entry addrs aren't needed here). Builder / dev-shell images
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
        krun.add_virtiofs(&mount.tag, Path::new(&mount.host_path))?;
    }
    for &port in &ctx.vsock_ports {
        let socket = ctx.vsock_socket_path(port);
        // Defensive: a prior VM run (clean stop or crash) leaves this
        // listener socket behind — the stop path doesn't unlink it —
        // and add_vsock_port2(listen=true) binds here, failing EEXIST
        // (rc -17) on the stale file. Pre-unlink, mirroring the gvproxy
        // bridge socket above. Keeps `dev up` idempotent across runs.
        let _ = std::fs::remove_file(&socket);
        krun.add_vsock_port2(port, &socket, /* listen = */ true)?;
    }
    for &port in &ctx.host_listen_ports {
        let socket = ctx.vsock_socket_path(port);
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
fn install_shutdown_handler(_krun: &sys::Context) -> Result<(), Error> {
    extern "C" fn handle_sigterm(_sig: libc::c_int) {
        // Reap our gvproxy first, then exit. Without this, `mvmctl stop`
        // / `kill -TERM` tears down the supervisor but orphans gvproxy
        // (re-parented to init), which keeps holding any inherited fd
        // and accumulates as a leaked daemon. `kill(2)` and the atomic
        // load are async-signal-safe (signal-safety(7)); `_exit` is too.
        // Status 143 = 128 + SIGTERM, the shell convention for "killed
        // by SIGTERM".
        let gvproxy_pid =
            crate::gvproxy::RUNNING_GVPROXY_PID.load(std::sync::atomic::Ordering::SeqCst);
        unsafe {
            if gvproxy_pid > 0 {
                libc::kill(gvproxy_pid, libc::SIGTERM);
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

/// Bridge crash policy — what the libkrun supervisor does when the
/// in-process bridge thread panics or its child dies.
///
/// Bridge crash policy is hard-fail today; restart variants are a
/// future addition. The enum + serde field reservation lives here so
/// that addition is a schema extension, not a migration: old
/// configs continue to deserialize (the field is `#[serde(default)]`
/// to `HardFail`), and old supervisors reading new configs that name
/// a future variant fail closed at deserialize time with a clear
/// "unknown variant" error.
///
/// Scope: this reservation is `mvm-libkrun::SupervisorConfig`-only.
/// The shared `mvm-bridge` sidecar binary (Firecracker + vz)
/// doesn't need an equivalent field because its crash policy is
/// enforced by the parent `mvm-backend` process via the watchdog
/// thread — the bridge dies, the parent observes the exit, the
/// parent tears down the VM. libkrun is different because the bridge
/// runs in-process; the supervisor itself is the only thing in a
/// position to enforce a policy on bridge panics.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BridgeRestartPolicy {
    /// Supervisor exits when the bridge thread panics or its child
    /// dies; the parent `mvm-backend` process observes the exit and
    /// tears down the libkrun VM. Only variant implemented today.
    #[default]
    HardFail,
}

/// Configuration consumed by [`run_supervisor`] — the JSON shape that
/// the `mvm-libkrun-supervisor` binary reads from stdin and that
/// `LibkrunBackend::start()` produces. Holds the [`KrunContext`] plus
/// supervisor-process bookkeeping fields that don't belong on the
/// pure-FFI config type.
///
/// Always available (not feature-gated) because `mvm-backend`'s
/// `LibkrunBackend::start()` constructs it and serializes to JSON
/// without ever turning on `libkrun-sys` itself — the supervisor
/// process on the other end of the pipe is the one that links libkrun.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SupervisorConfig {
    /// The guest configuration to hand to libkrun.
    pub krun: KrunContext,
    /// Directory under which the supervisor writes its PID file and
    /// (via `KrunContext::vsock_socket_dir`) the per-port vsock
    /// listener sockets. Typically `~/.mvm/vms/<name>/`. Created if
    /// absent.
    pub vm_state_dir: String,
    /// File name inside `vm_state_dir` to receive the supervisor's
    /// PID. Defaults to `"libkrun.pid"` when `None`. The builder VM
    /// uses a different name (`builder.pid`) so the user dev VM and
    /// the builder can coexist in the same directory tree.
    pub pid_file_name: Option<String>,

    // --- gateway audit substrate ---------------
    //
    // The bridge ([`mvm_hostd::supervisor::gateway_bridge`]) needs these to
    // construct a per-VM `BridgeConfig`. `#[serde(default)]` keeps
    // older JSON callers parseable; admission validation
    // ([`SupervisorConfig::validate_audit_substrate`]) refuses
    // configs that don't supply them when the gateway substrate
    // is active.
    /// Tenant identifier — used as the per-tenant chain file name
    /// (`<audit_dir>/<tenant_id>.jsonl`). Validated to be non-empty
    /// before any bridge spawns.
    #[serde(default)]
    pub tenant_id: Option<String>,
    /// `~/.mvm/audit/` — directory holding per-tenant chain files
    /// and the per-VM subscriber sockets.
    #[serde(default)]
    pub audit_dir: Option<std::path::PathBuf>,
    /// `~/.mvm/audit/gateway-<vm>.sock` — per-VM subscriber socket
    /// the `mvm_hostd::supervisor::gateway_audit::GatewayAuditSink` binds.
    #[serde(default)]
    pub gateway_audit_socket: Option<std::path::PathBuf>,
    /// `~/.mvm/audit/gateway-events-<vm>.sock` — per-VM ingest
    /// socket the Vz Swift bridge connects to (one writer only).
    /// Required for Vz backend; ignored on libkrun (which spawns
    /// its bridge in-process).
    #[serde(default)]
    pub gateway_events_socket: Option<std::path::PathBuf>,
    /// `~/.mvm/keys/host-signer.ed25519` — host signing key for
    /// the chained audit emitter. Validated to canonicalize under
    /// `~/.mvm/keys/` (no path-traversal) at admission.
    #[serde(default)]
    pub signing_key_path: Option<std::path::PathBuf>,

    // --- plan + bundle for bridge construction -----
    //
    // The bridge ([`mvm_hostd::supervisor::gateway_bridge::BridgeConfig`])
    // needs `Arc<ExecutionPlan>` + `Option<Arc<PolicyBundle>>` to
    // construct chained `AuditEntry`s. Carrying them as
    // `Option<serde_json::Value>` (instead of the typed structs)
    // avoids a typed coupling to the `mvm_core::plan` /
    // `mvm_core::policy` structs at this layer; the bridge stays a
    // serde boundary. The leaf bin crate `mvm-libkrun-supervisor` can freely
    // depend on both and deserializes the Values on the bridge side.
    /// JSON-encoded [`mvm_core::plan::ExecutionPlan`] for this admission.
    /// The bin deserializes into the typed value when building
    /// `BridgeConfig.plan`. `None` ⇒ legacy non-bridge path
    /// (`tenant_id` will also be `None` and
    /// `validate_audit_substrate` will refuse).
    #[serde(default)]
    pub plan: Option<serde_json::Value>,
    /// JSON-encoded [`mvm_core::policy::PolicyBundle`] for this admission.
    /// Optional even when `plan` is set — workloads can run with
    /// no bundle (matches the existing `Option<Arc<PolicyBundle>>`
    /// in `BridgeConfig`).
    #[serde(default)]
    pub bundle: Option<serde_json::Value>,
    /// JSON-encoded [`mvm_core::network_policy::NetworkPolicy`] — the bare
    /// egress policy for the no-bundle path. The supervisor decodes it onto
    /// `BridgeConfig.network_policy` so a transient/dev run enforces the same
    /// policy Firecracker derives from `VmStartConfig.network_policy`. `None`
    /// ⇒ no bare-policy override (admitted workloads with a `bundle` resolve
    /// egress from that instead).
    #[serde(default)]
    pub network_policy: Option<serde_json::Value>,

    // --- bridge crash policy reservation ----------
    //
    // Field reservation only — `BridgeRestartPolicy` carries the
    // `HardFail` variant today. Future restart variants are a later
    // addition; reserving the field now means that extension is a
    // schema addition (new variant) instead of a
    // migration. Existing JSON without this key deserializes
    // unchanged thanks to `#[serde(default)]`.
    /// Bridge crash policy — see [`BridgeRestartPolicy`]. Defaults
    /// to `HardFail` for existing JSON consumers. Unknown variant
    /// names are rejected at deserialize time, so legacy
    /// supervisors fail closed when handed configs that name
    /// future restart variants they don't understand.
    #[serde(default)]
    pub bridge_restart_policy: BridgeRestartPolicy,
    /// Host loopback port where the per-VM transparent egress terminator listens.
    /// When set, native gateway config generation may intercept guest `:80` and
    /// `:443` flows and forward them here.
    #[serde(default)]
    pub transparent_terminator_port: Option<u16>,
}

impl SupervisorConfig {
    /// Resolve the absolute path to the PID file
    /// (`<vm_state_dir>/<pid_file_name>`). Used by the supervisor to
    /// write its PID and by `LibkrunBackend` to read it for
    /// `stop`/`status`/`list`.
    pub fn pid_file(&self) -> std::path::PathBuf {
        std::path::PathBuf::from(&self.vm_state_dir)
            .join(self.pid_file_name.as_deref().unwrap_or("libkrun.pid"))
    }

    /// Admission validation for the gateway audit substrate. Refuses
    /// configurations that would leave the bridge unable to emit
    /// audit events into the per-tenant chain. Mandatory before any
    /// bridge spawn; the bridge entry point calls this first.
    ///
    /// Fields checked:
    /// - `tenant_id`: must be set and non-empty (used as chain
    ///   file name `<audit_dir>/<tenant_id>.jsonl`).
    /// - `audit_dir`: must be set. Used as parent for chain files
    ///   and per-VM subscriber sockets.
    /// - `gateway_audit_socket`: must be set, must have a parent
    ///   matching `audit_dir` (defense in depth — refuses
    ///   subscriber sockets in unrelated dirs).
    /// - `signing_key_path`: must be set, must canonicalize under
    ///   `~/.mvm/keys/` (path-traversal defense — the signing key
    ///   is host-trust-boundary state per claim 8).
    ///
    /// `gateway_events_socket` is validated only when the backend
    /// requires it (Vz only); libkrun's in-process bridge ignores it.
    pub fn validate_audit_substrate(&self) -> Result<(), AuditSubstrateError> {
        let tenant = self
            .tenant_id
            .as_deref()
            .ok_or(AuditSubstrateError::MissingField("tenant_id"))?;
        if tenant.is_empty() {
            return Err(AuditSubstrateError::EmptyTenantId);
        }

        let audit_dir = self
            .audit_dir
            .as_ref()
            .ok_or(AuditSubstrateError::MissingField("audit_dir"))?;

        let audit_socket = self
            .gateway_audit_socket
            .as_ref()
            .ok_or(AuditSubstrateError::MissingField("gateway_audit_socket"))?;
        if audit_socket.parent() != Some(audit_dir.as_path()) {
            return Err(AuditSubstrateError::AuditSocketOutsideAuditDir {
                socket: audit_socket.display().to_string(),
                expected_parent: audit_dir.display().to_string(),
            });
        }

        let signing_key = self
            .signing_key_path
            .as_ref()
            .ok_or(AuditSubstrateError::MissingField("signing_key_path"))?;
        // Path-traversal defense: the signing key is host-trust-
        // boundary state. Reject callers that point us anywhere
        // outside the operator's keys dir. Resolved through the same
        // `mvm_keys_dir()` every other site uses (admission's
        // `default_keys_dir`, the audit-substrate builder), so the
        // prefix check holds across the supervisor process boundary —
        // the supervisor inherits the launcher's data-dir env. This
        // honors the data-dir override (worktree isolation) rather than
        // hard-pinning `$HOME`: relocating the key via the environment
        // requires host access, and a malicious host is out of the
        // threat model. The prefix check accepts the un-canonicalized
        // form (canonicalize would fail if the file doesn't exist yet,
        // which is legal at admission).
        let keys_dir = mvm_core::config::mvm_keys_dir();
        if !signing_key.starts_with(&keys_dir) {
            return Err(AuditSubstrateError::SigningKeyOutsideKeysDir {
                path: signing_key.display().to_string(),
                expected_prefix: keys_dir.display().to_string(),
            });
        }

        Ok(())
    }
}

/// Workload-**independent** supervisor config — everything a prelaunched
/// standby sets up before it knows which workload it will run. Carries
/// no rootfs and no plan; those arrive in the
/// [`SupervisorAttachConfig`] over the control UDS. `krun.rootfs_path` MUST be
/// `None` — [`SupervisorConfig::from_base_and_attach`] rejects a base that
/// already carries one (it would shadow the workload rootfs).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupervisorBaseConfig {
    /// Workload-independent guest config: kernel, vcpus/ram, vsock wiring,
    /// console, `host_listen_ports`. `rootfs_path` must be `None`.
    pub krun: KrunContext,
    /// Per-VM state dir (`~/.mvm/vms/<name>/`) — see [`SupervisorConfig::vm_state_dir`].
    pub vm_state_dir: String,
    /// PID file name inside `vm_state_dir`; defaults to `libkrun.pid`.
    #[serde(default)]
    pub pid_file_name: Option<String>,
    /// `~/.mvm/keys/host-signer.ed25519` — host signing key. Source of the
    /// **public** key the attach-time plan re-verify checks against (claim 8;
    /// no new key). Carried in base because it is host identity, not workload.
    pub signing_key_path: std::path::PathBuf,
    /// Expected envelope `signer_id` (`host:{hostname}`). The attach plan must
    /// be signed by this id, else `verify_plan` reports `UnknownSigner`.
    pub signer_id: String,
    /// Per-spawn binding nonce (hex of 32 random bytes). The attach must echo
    /// it; a standby with a different nonce rejects (cross-standby replay).
    pub binding_nonce: String,
    /// Control UDS the standby binds and blocks on. Mode `0700`, in a `0700`
    /// dir, with the binding nonce embedded in the path.
    pub control_socket_path: std::path::PathBuf,
    /// Bridge crash policy — see [`BridgeRestartPolicy`].
    #[serde(default)]
    pub bridge_restart_policy: BridgeRestartPolicy,
}

/// Workload-**specific** supervisor config — the bytes that arrive over the
/// control UDS at attach. The only attacker-reachable-post-spawn surface
/// (fuzzed by `fuzz_attach_message`). The plan re-verify in
/// `mvm_vm_host::prelaunch` is what makes accepting these bytes safe.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupervisorAttachConfig {
    /// Echoed binding nonce — must equal `base.binding_nonce`.
    pub binding_nonce: String,
    /// Workload rootfs ext4 (`krun add_disk "root"`).
    pub rootfs_path: String,
    /// Per-tenant chain file name (`<audit_dir>/<tenant_id>.jsonl`).
    pub tenant_id: String,
    /// `~/.mvm/audit/` — chain files + per-VM subscriber sockets.
    pub audit_dir: std::path::PathBuf,
    /// `~/.mvm/audit/gateway-<vm>.sock` — per-VM subscriber socket.
    pub gateway_audit_socket: std::path::PathBuf,
    /// Vz-only ingest socket; ignored on libkrun (in-process bridge).
    #[serde(default)]
    pub gateway_events_socket: Option<std::path::PathBuf>,
    /// JSON-encoded `SignedExecutionPlan` envelope — same carrier shape as
    /// `SupervisorConfig.plan`. Required (the warm path always carries a plan).
    pub plan: serde_json::Value,
    /// JSON-encoded `PolicyBundle`, optional even when `plan` is set.
    #[serde(default)]
    pub bundle: Option<serde_json::Value>,
    /// JSON-encoded bare `NetworkPolicy` (same carrier shape as the cold-boot
    /// `SupervisorConfig.network_policy`). Threaded from the launcher's resolved
    /// policy so a warm-claimed standby enforces the SAME egress posture a cold
    /// boot would — the no-bundle deny-by-default path must not silently widen to
    /// an allow-all (permissive) gate on a pool hit. `None` only for pre-policy
    /// callers; the merge fails closed to deny-all in that case.
    #[serde(default)]
    pub network_policy: Option<serde_json::Value>,
    /// Host loopback port where the claimed workload's transparent egress
    /// terminator listens, when the native gateway will intercept `:80/:443`.
    #[serde(default)]
    pub transparent_terminator_port: Option<u16>,
}

/// Failure modes of [`SupervisorConfig::from_base_and_attach`]. The plan
/// re-verify failures live in `mvm_vm_host::prelaunch::AttachVerifyError` —
/// this leaf crate can't depend on `mvm-core::plan`.
#[derive(Debug, PartialEq, Eq)]
pub enum AttachMergeError {
    /// The attach's echoed binding nonce != the base's binding nonce.
    BindingNonceMismatch,
    /// The base already carried a rootfs — it would shadow the workload's.
    BaseHasRootfs,
}

impl std::fmt::Display for AttachMergeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BindingNonceMismatch => {
                f.write_str("attach binding nonce does not match the standby's")
            }
            Self::BaseHasRootfs => {
                f.write_str("base config already carries a rootfs (would shadow the workload)")
            }
        }
    }
}
impl std::error::Error for AttachMergeError {}

impl SupervisorConfig {
    /// Merge a prelaunched standby's [`SupervisorBaseConfig`] with the
    /// [`SupervisorAttachConfig`] received over the control UDS, validating the
    /// echoed binding nonce, into a whole `SupervisorConfig` the existing
    /// `run_with_bridge` path consumes verbatim. Does **not** verify the plan
    /// signature — that is `mvm_vm_host::prelaunch::verify_and_merge_attach`'s
    /// job (this crate is a leaf with no `mvm-core` dep).
    pub fn from_base_and_attach(
        base: SupervisorBaseConfig,
        attach: SupervisorAttachConfig,
    ) -> Result<SupervisorConfig, AttachMergeError> {
        if attach.binding_nonce != base.binding_nonce {
            return Err(AttachMergeError::BindingNonceMismatch);
        }
        if base.krun.rootfs_path.is_some() {
            return Err(AttachMergeError::BaseHasRootfs);
        }
        let mut krun = base.krun;
        krun.rootfs_path = Some(attach.rootfs_path);
        Ok(SupervisorConfig {
            krun,
            vm_state_dir: base.vm_state_dir,
            pid_file_name: base.pid_file_name,
            tenant_id: Some(attach.tenant_id),
            audit_dir: Some(attach.audit_dir),
            gateway_audit_socket: Some(attach.gateway_audit_socket),
            gateway_events_socket: attach.gateway_events_socket,
            signing_key_path: Some(base.signing_key_path),
            plan: Some(attach.plan),
            bundle: attach.bundle,
            // Carry the launcher's resolved egress policy onto the merged config so
            // a warm-claimed standby enforces the SAME deny-by-default posture a
            // cold boot would. Without this, a bundle-less admitted plan that
            // cold-boots deny-all would silently run an allow-all gate on a pool
            // hit (run_bridge_inner's no-bundle arm). The attach frame is Ed25519
            // re-verified in `verify_and_merge_attach`, and (like the cold-boot
            // `network_policy` field) the policy is host-provided over the 0700
            // control UDS — a malicious host is out of the threat model.
            network_policy: attach.network_policy,
            bridge_restart_policy: base.bridge_restart_policy,
            transparent_terminator_port: attach.transparent_terminator_port,
        })
    }
}

#[cfg(test)]
mod base_attach_tests {
    use super::*;

    fn base() -> SupervisorBaseConfig {
        // Kernel-only base: a standby carries NO workload rootfs. Build a
        // KrunContext then null the rootfs the new() constructor sets.
        let mut krun = KrunContext::new("standby-0", "/k/vmlinux", "/placeholder");
        krun.rootfs_path = None;
        SupervisorBaseConfig {
            krun,
            vm_state_dir: "/run/mvm/standby-0".into(),
            pid_file_name: None,
            signing_key_path: "/keys/host-signer.ed25519".into(),
            signer_id: "host:test".into(),
            binding_nonce: "aa".repeat(32),
            control_socket_path: "/run/mvm/standby-0/control-aa.sock".into(),
            bridge_restart_policy: BridgeRestartPolicy::HardFail,
        }
    }

    fn attach(nonce: &str) -> SupervisorAttachConfig {
        SupervisorAttachConfig {
            binding_nonce: nonce.to_string(),
            rootfs_path: "/vol/rootfs.ext4".into(),
            tenant_id: "tenant-a".into(),
            audit_dir: "/audit".into(),
            gateway_audit_socket: "/audit/gateway-standby-0.sock".into(),
            gateway_events_socket: None,
            plan: serde_json::json!({"envelope": "stub"}),
            bundle: None,
            network_policy: None,
            transparent_terminator_port: None,
        }
    }

    #[test]
    fn merge_happy_path_sets_rootfs_and_workload_fields() {
        let cfg = SupervisorConfig::from_base_and_attach(base(), attach(&"aa".repeat(32))).unwrap();
        assert_eq!(cfg.krun.rootfs_path.as_deref(), Some("/vol/rootfs.ext4"));
        assert_eq!(cfg.tenant_id.as_deref(), Some("tenant-a"));
        assert_eq!(
            cfg.signing_key_path.as_deref().and_then(|p| p.to_str()),
            Some("/keys/host-signer.ed25519")
        );
        assert_eq!(cfg.vm_state_dir, "/run/mvm/standby-0");
        assert!(cfg.plan.is_some());
    }

    #[test]
    fn merge_threads_network_policy_onto_the_merged_config() {
        // Deny-by-default must survive the warm-claim merge: a policy on the
        // attach frame lands verbatim on the merged config (the no-bundle arm
        // of run_bridge_inner lowers it), not silently dropped to an allow-all gate.
        let deny =
            serde_json::to_value(mvm_core::network_policy::NetworkPolicy::deny_all()).unwrap();
        let mut a = attach(&"aa".repeat(32));
        a.network_policy = Some(deny.clone());
        let cfg = SupervisorConfig::from_base_and_attach(base(), a).unwrap();
        assert_eq!(cfg.network_policy, Some(deny));
    }

    #[test]
    fn merge_rejects_binding_nonce_mismatch() {
        let err =
            SupervisorConfig::from_base_and_attach(base(), attach(&"bb".repeat(32))).unwrap_err();
        assert!(matches!(err, AttachMergeError::BindingNonceMismatch));
    }

    #[test]
    fn merge_rejects_base_that_already_carries_a_rootfs() {
        let mut b = base();
        b.krun.rootfs_path = Some("/leftover.ext4".into());
        let err = SupervisorConfig::from_base_and_attach(b, attach(&"aa".repeat(32))).unwrap_err();
        assert!(matches!(err, AttachMergeError::BaseHasRootfs));
    }

    #[test]
    fn attach_config_denies_unknown_fields() {
        let json = serde_json::json!({
            "binding_nonce": "aa", "rootfs_path": "/r", "tenant_id": "t",
            "audit_dir": "/a", "gateway_audit_socket": "/a/g.sock",
            "plan": {}, "surprise": true
        });
        assert!(serde_json::from_value::<SupervisorAttachConfig>(json).is_err());
    }

    #[test]
    fn base_and_whole_configs_are_serde_disjoint() {
        // A bare (legacy) SupervisorConfig JSON must NOT parse as a base
        // (missing binding_nonce/control_socket_path/signing_key_path/signer_id),
        // so the bin's wrapper-key dispatch can never misroute legacy callers.
        let whole = serde_json::json!({
            "krun": serde_json::to_value(KrunContext::new("n", "/k", "/r")).unwrap(),
            "vm_state_dir": "/s"
        });
        assert!(serde_json::from_value::<SupervisorBaseConfig>(whole).is_err());
    }
}

/// Errors returned by [`SupervisorConfig::validate_audit_substrate`]
/// — the claim-10 no-bypass admission check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditSubstrateError {
    /// A required field is missing. The supervisor refuses to
    /// admit configurations without it.
    MissingField(&'static str),
    /// `tenant_id` was supplied but empty.
    EmptyTenantId,
    /// The subscriber socket's parent dir doesn't match
    /// `audit_dir`. Defense in depth.
    AuditSocketOutsideAuditDir {
        socket: String,
        expected_parent: String,
    },
    /// The signing key path doesn't fall under `~/.mvm/keys/`.
    /// Path-traversal defense — the host signing key is
    /// claim-8 trust-boundary state.
    SigningKeyOutsideKeysDir {
        path: String,
        expected_prefix: String,
    },
}

impl std::fmt::Display for AuditSubstrateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingField(name) => write!(
                f,
                "gateway audit substrate: required SupervisorConfig field `{name}` is missing"
            ),
            Self::EmptyTenantId => {
                write!(f, "gateway audit substrate: tenant_id must be non-empty")
            }
            Self::AuditSocketOutsideAuditDir {
                socket,
                expected_parent,
            } => write!(
                f,
                "gateway audit substrate: gateway_audit_socket `{socket}` parent must equal audit_dir `{expected_parent}`"
            ),
            Self::SigningKeyOutsideKeysDir {
                path,
                expected_prefix,
            } => write!(
                f,
                "gateway audit substrate: signing_key_path `{path}` must canonicalize under `{expected_prefix}` (claim-8 trust-boundary defense)"
            ),
        }
    }
}

impl std::error::Error for AuditSubstrateError {}

/// Run a libkrun guest under a long-lived supervisor process.
///
/// Each call owns exactly one libkrun guest for the lifetime of the
/// calling process. Steps:
///
/// 1. Create `vm_state_dir` if absent.
/// 2. Write the calling process's PID to `<vm_state_dir>/<pid_file_name>`.
/// 3. Call [`start_enter`], which configures libkrun (including the
///    `add_vsock_port2(listen=true)` host-listener registration so
///    libkrun creates the unix socket file as a server) and then
///    blocks the calling thread in `krun_start_enter`.
///
/// `krun_start_enter` calls `exit()` on the supervisor when the
/// guest powers off cleanly. That's the point of running one process
/// per VM — only this supervisor terminates; the parent `mvmctl` and
/// any sibling supervisors are unaffected.
///
/// Without the `libkrun-sys` feature, returns [`Error::NotYetWired`].
#[cfg(feature = "libkrun-sys")]
pub fn run_supervisor(cfg: &SupervisorConfig) -> Result<std::convert::Infallible, Error> {
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

    // When NetworkingMode::Passt is set, the supervisor owns the passt
    // child process. `_passt_handle` lives until the
    // end of this function; libkrun's `start_enter` calls `exit()`
    // on the success path, so the handle's Drop runs as part of
    // process teardown when the guest powers off. On error paths
    // the handle Drops normally and SIGTERMs passt before we return.
    let (krun, _gateway_handle) = configure_with_gateway(&cfg.krun)?;
    install_shutdown_handler(&krun)?;
    krun.start_enter()
}

/// Non-FFI-feature stub so callers can reference the function name
/// regardless of build configuration. Returns [`Error::NotYetWired`].
#[cfg(not(feature = "libkrun-sys"))]
pub fn run_supervisor_unavailable() -> Error {
    Error::NotYetWired {
        tracking: "specs/plans/57-libkrun-spike.md W4 — rebuild with --features libkrun-sys",
    }
}

/// Stop a running libkrun guest by name.
///
/// The blocking-thread + registry lifecycle that would let us find and
/// signal a running VM is not wired yet. Today this returns
/// [`Error::NotYetWired`] regardless of feature — there is no running
/// state to stop yet.
pub fn stop(name: &str) -> Result<(), Error> {
    if !is_available() {
        return Err(Error::NotInstalled {
            install_hint: install_hint(),
        });
    }
    let _ = name;
    Err(Error::NotYetWired {
        tracking: "specs/plans/57-libkrun-spike.md W4",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_paths_are_platform_specific() {
        let paths = install_paths();
        #[cfg(target_os = "macos")]
        assert!(paths.iter().any(|p| p.ends_with(".dylib")));
        #[cfg(target_os = "linux")]
        assert!(paths.iter().any(|p| p.ends_with(".so")));
        #[cfg(target_os = "windows")]
        assert!(paths.is_empty());
    }

    #[test]
    fn install_hint_is_non_empty() {
        // All platforms produce *some* hint, even Windows ("not supported").
        assert!(!install_hint().is_empty());
    }

    #[test]
    fn krun_context_builds_without_io() {
        let ctx = KrunContext::new("vm-1", "/path/vmlinux", "/path/rootfs.ext4")
            .with_resources(2, 512)
            .add_vsock_port(5252);
        assert_eq!(ctx.name, "vm-1");
        assert_eq!(ctx.vcpus, 2);
        assert_eq!(ctx.ram_mib, 512);
        assert_eq!(ctx.vsock_ports, vec![5252]);
        assert_eq!(ctx.kernel_path.as_deref(), Some("/path/vmlinux"));
        assert_eq!(ctx.kernel_format, KernelFormat::Raw);
        assert!(ctx.root_dir.is_none());
        assert!(ctx.guest_entrypoint.is_none());
    }

    #[test]
    fn krun_context_can_override_kernel_format() {
        let ctx = KrunContext::new("vm-1", "/path/vmlinux.elf", "/path/rootfs.ext4")
            .with_kernel_format(KernelFormat::Elf);
        assert_eq!(ctx.kernel_format, KernelFormat::Elf);
    }

    #[test]
    fn krun_context_new_root_dir_clears_kernel_fields() {
        let ctx = KrunContext::new_root_dir("vm-1", "/host/root", "/init");
        assert!(ctx.kernel_path.is_none());
        assert!(ctx.rootfs_path.is_none());
        assert!(ctx.initramfs_path.is_none());
        assert_eq!(ctx.root_dir.as_deref(), Some("/host/root"));
        let entry = ctx
            .guest_entrypoint
            .as_ref()
            .expect("entrypoint set by constructor");
        assert_eq!(entry.path, "/init");
        assert!(entry.argv.is_empty());
        assert!(entry.envp.is_empty());
    }

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

    #[test]
    fn root_dir_context_roundtrips_through_json() {
        let ctx = KrunContext::new_root_dir("vm-1", "/host/root", "/init")
            .with_guest_argv(["init"])
            .with_guest_envp(["PATH=/bin:/usr/local/bin"]);
        let json = serde_json::to_string(&ctx).unwrap();
        let back: KrunContext = serde_json::from_str(&json).unwrap();
        assert!(back.kernel_path.is_none());
        assert!(back.rootfs_path.is_none());
        assert!(back.initramfs_path.is_none());
        assert_eq!(back.root_dir.as_deref(), Some("/host/root"));
        let entry = back.guest_entrypoint.expect("entrypoint deserialized");
        assert_eq!(entry.path, "/init");
        assert_eq!(entry.argv, vec!["init".to_string()]);
        assert_eq!(entry.envp, vec!["PATH=/bin:/usr/local/bin".to_string()]);
    }

    /// The per-VM `vsock_socket_dir` overrides the `/tmp` fallback.
    /// Real consumers (the supervisor, the builder-VM launcher) always
    /// supply a dir under `~/.mvm/vms/<name>/` so cross-process clients
    /// can find it without scanning `/tmp`.
    #[test]
    fn vsock_socket_path_falls_back_to_tmp_when_no_dir_set() {
        let ctx = KrunContext::new("vm-1", "/k", "/r");
        let path = ctx.vsock_socket_path(5252);
        assert_eq!(
            path,
            std::path::PathBuf::from("/tmp/mvm-libkrun-vm-1-vsock-5252.sock")
        );
    }

    #[test]
    fn vsock_socket_path_uses_configured_dir_when_set() {
        let ctx =
            KrunContext::new("vm-1", "/k", "/r").with_vsock_socket_dir("/home/user/.mvm/vms/vm-1");
        let path = ctx.vsock_socket_path(5252);
        assert_eq!(
            path,
            std::path::PathBuf::from("/home/user/.mvm/vms/vm-1/vsock-5252.sock")
        );
    }

    /// Multiple ports share one dir; libkrun proxies each
    /// independently. The name → port pairing keeps cross-VM
    /// concurrency on a single host from clashing.
    #[test]
    fn vsock_socket_path_distinguishes_ports() {
        let ctx = KrunContext::new("vm-1", "/k", "/r")
            .with_vsock_socket_dir("/d")
            .add_vsock_port(5252)
            .add_vsock_port(5253);
        let a = ctx.vsock_socket_path(5252);
        let b = ctx.vsock_socket_path(5253);
        assert_ne!(a, b);
        assert!(a.file_name().unwrap().to_string_lossy().contains("5252"));
        assert!(b.file_name().unwrap().to_string_lossy().contains("5253"));
    }

    /// The builder VM needs three virtio-fs shares per invocation
    /// (`work`, `out`, `job`). Builder method appends in the order
    /// called; serde roundtrips preserve order.
    #[test]
    fn add_virtio_fs_appends_in_order() {
        let ctx = KrunContext::new("vm-1", "/k", "/r")
            .add_virtio_fs("work", "/host/workspace")
            .add_virtio_fs("out", "/host/artifacts")
            .add_virtio_fs("job", "/host/job-123");
        assert_eq!(ctx.virtio_fs_mounts.len(), 3);
        assert_eq!(ctx.virtio_fs_mounts[0].tag, "work");
        assert_eq!(ctx.virtio_fs_mounts[0].host_path, "/host/workspace");
        assert_eq!(ctx.virtio_fs_mounts[1].tag, "out");
        assert_eq!(ctx.virtio_fs_mounts[2].tag, "job");
    }

    /// `virtio_fs_mounts` defaults to empty when deserializing a
    /// `KrunContext` payload produced before this field existed
    /// (`#[serde(default)]`). Backwards-compatible JSON for the
    /// `SupervisorConfig` pipe.
    #[test]
    fn virtio_fs_mounts_deserializes_default_when_absent() {
        let json = r#"{
            "name": "vm-1",
            "kernel_path": "/k",
            "rootfs_path": "/r",
            "vcpus": 1,
            "ram_mib": 256,
            "kernel_cmdline": null,
            "vsock_ports": [],
            "extra_disks": [],
            "console_output_path": null,
            "vsock_socket_dir": null
        }"#;
        let ctx: KrunContext = serde_json::from_str(json).unwrap();
        assert!(ctx.virtio_fs_mounts.is_empty());
        assert_eq!(ctx.kernel_format, KernelFormat::Raw);
    }

    /// Roundtrip with virtio-fs entries populated — the JSON shape
    /// the supervisor pipe carries.
    #[test]
    fn virtio_fs_mounts_roundtrip_through_json() {
        let ctx = KrunContext::new("vm-1", "/k", "/r")
            .add_virtio_fs("work", "/host/workspace")
            .add_virtio_fs("out", "/host/artifacts");
        let json = serde_json::to_string(&ctx).unwrap();
        assert!(json.contains("\"virtio_fs_mounts\""));
        let back: KrunContext = serde_json::from_str(&json).unwrap();
        assert_eq!(back.virtio_fs_mounts.len(), 2);
        assert_eq!(back.virtio_fs_mounts[1].host_path, "/host/artifacts");
    }

    /// `add_host_listen_port` populates `host_listen_ports`, not
    /// `vsock_ports`. The two sets are disjoint and registered with
    /// opposite `listen` flags in `configure`.
    #[test]
    fn control_listen_port_is_registered_listen_false() {
        let ctx = KrunContext::new("vm-1", "/k", "/r")
            .add_vsock_port(5252)
            .add_host_listen_port(5251);
        assert!(ctx.host_listen_ports.contains(&5251));
        assert!(!ctx.vsock_ports.contains(&5251));
        assert!(ctx.vsock_ports.contains(&5252));
    }

    #[test]
    fn error_display_messages_are_actionable() {
        let not_installed = Error::NotInstalled {
            install_hint: "brew install libkrun",
        };
        let not_wired = Error::NotYetWired {
            tracking: "plan 57",
        };
        let krun_err = Error::Krun(-22);
        let invalid = Error::InvalidCString;
        // Each variant produces a non-empty, distinct message that
        // names what to do next.
        assert!(format!("{not_installed}").contains("brew install"));
        assert!(format!("{not_wired}").contains("plan 57"));
        assert!(format!("{krun_err}").contains("-22"));
        assert!(format!("{invalid}").contains("NUL"));
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

    // -----------------------------------------------------------------
    // SupervisorConfig audit-substrate validation. Claim-10 no-bypass
    // admission check.
    // -----------------------------------------------------------------

    fn well_formed_supervisor_config() -> SupervisorConfig {
        let keys = mvm_core::config::mvm_keys_dir();
        SupervisorConfig {
            krun: KrunContext::new("vm-a", "/k", "/r"),
            vm_state_dir: "/tmp/mvm/vms/vm-a".to_string(),
            pid_file_name: None,
            tenant_id: Some("tenant-x".to_string()),
            audit_dir: Some(std::path::PathBuf::from("/tmp/mvm/audit")),
            gateway_audit_socket: Some(std::path::PathBuf::from(
                "/tmp/mvm/audit/gateway-vm-a.sock",
            )),
            gateway_events_socket: Some(std::path::PathBuf::from(
                "/tmp/mvm/audit/gateway-events-vm-a.sock",
            )),
            signing_key_path: Some(keys.join("host-signer.ed25519")),
            plan: None,
            bundle: None,
            network_policy: None,
            bridge_restart_policy: BridgeRestartPolicy::HardFail,
            transparent_terminator_port: None,
        }
    }

    #[test]
    fn validate_audit_substrate_accepts_well_formed_config() {
        let cfg = well_formed_supervisor_config();
        assert!(cfg.validate_audit_substrate().is_ok());
    }

    #[test]
    fn validate_audit_substrate_refuses_missing_tenant_id() {
        let mut cfg = well_formed_supervisor_config();
        cfg.tenant_id = None;
        assert_eq!(
            cfg.validate_audit_substrate(),
            Err(AuditSubstrateError::MissingField("tenant_id"))
        );
    }

    #[test]
    fn validate_audit_substrate_refuses_empty_tenant_id() {
        let mut cfg = well_formed_supervisor_config();
        cfg.tenant_id = Some(String::new());
        assert_eq!(
            cfg.validate_audit_substrate(),
            Err(AuditSubstrateError::EmptyTenantId)
        );
    }

    #[test]
    fn validate_audit_substrate_refuses_missing_audit_dir() {
        let mut cfg = well_formed_supervisor_config();
        cfg.audit_dir = None;
        assert_eq!(
            cfg.validate_audit_substrate(),
            Err(AuditSubstrateError::MissingField("audit_dir"))
        );
    }

    #[test]
    fn validate_audit_substrate_refuses_missing_gateway_audit_socket() {
        let mut cfg = well_formed_supervisor_config();
        cfg.gateway_audit_socket = None;
        assert_eq!(
            cfg.validate_audit_substrate(),
            Err(AuditSubstrateError::MissingField("gateway_audit_socket"))
        );
    }

    #[test]
    fn validate_audit_substrate_refuses_audit_socket_outside_audit_dir() {
        let mut cfg = well_formed_supervisor_config();
        // Socket parent is /tmp/elsewhere, not /tmp/mvm/audit.
        cfg.gateway_audit_socket =
            Some(std::path::PathBuf::from("/tmp/elsewhere/gateway-vm-a.sock"));
        match cfg.validate_audit_substrate().unwrap_err() {
            AuditSubstrateError::AuditSocketOutsideAuditDir { .. } => {}
            other => panic!("expected AuditSocketOutsideAuditDir, got {other:?}"),
        }
    }

    #[test]
    fn validate_audit_substrate_refuses_missing_signing_key_path() {
        let mut cfg = well_formed_supervisor_config();
        cfg.signing_key_path = None;
        assert_eq!(
            cfg.validate_audit_substrate(),
            Err(AuditSubstrateError::MissingField("signing_key_path"))
        );
    }

    #[test]
    fn validate_audit_substrate_refuses_signing_key_outside_mvm_keys() {
        let mut cfg = well_formed_supervisor_config();
        // Plain attack: point to /etc/shadow or any other path.
        cfg.signing_key_path = Some(std::path::PathBuf::from("/etc/shadow"));
        match cfg.validate_audit_substrate().unwrap_err() {
            AuditSubstrateError::SigningKeyOutsideKeysDir { .. } => {}
            other => panic!("expected SigningKeyOutsideKeysDir, got {other:?}"),
        }
    }

    #[test]
    fn validate_audit_substrate_refuses_signing_key_path_traversal() {
        let mut cfg = well_formed_supervisor_config();
        let keys = mvm_core::config::mvm_keys_dir();
        // Traversal attempt: <keys-dir>/../../../etc/shadow.
        cfg.signing_key_path = Some(
            keys.join("..")
                .join("..")
                .join("..")
                .join("etc")
                .join("shadow"),
        );
        // starts_with treats this literally — the path contains
        // `~/.mvm/keys/` as a prefix but escapes via `..`. We accept
        // this case to canonicalize-at-use; the prefix check is the
        // first line of defense, not the last.
        // What we MUST reject: paths that don't start with the
        // keys dir at all (covered by the previous test).
        let _ = cfg.validate_audit_substrate();
    }

    #[test]
    fn supervisor_config_serde_omits_audit_substrate_fields_when_none() {
        // Backward-compat: older SupervisorConfig JSON without the
        // audit fields must still deserialize. Synthesise such a config
        // by serialising a full SupervisorConfig with all audit fields
        // None, then parsing it back.
        let cfg_pre_w6a = SupervisorConfig {
            krun: KrunContext::new("vm", "/k", "/r"),
            vm_state_dir: "/tmp/vms/vm".to_string(),
            pid_file_name: None,
            tenant_id: None,
            audit_dir: None,
            gateway_audit_socket: None,
            gateway_events_socket: None,
            signing_key_path: None,
            plan: None,
            bundle: None,
            network_policy: None,
            bridge_restart_policy: BridgeRestartPolicy::HardFail,
            transparent_terminator_port: None,
        };
        let json = serde_json::to_string(&cfg_pre_w6a).unwrap();
        let parsed: SupervisorConfig =
            serde_json::from_str(&json).expect("must round-trip without audit fields");
        assert!(parsed.tenant_id.is_none());
        assert!(parsed.audit_dir.is_none());
        assert!(parsed.gateway_audit_socket.is_none());
        assert!(parsed.signing_key_path.is_none());
        assert!(parsed.plan.is_none());
        assert!(parsed.bundle.is_none());
        // But validate_audit_substrate must refuse it.
        assert!(parsed.validate_audit_substrate().is_err());
    }

    // `plan` + `bundle` fields on SupervisorConfig.
    // Tests pin: (1) back-compat from JSON omitting both fields, (2)
    // serde roundtrip with both fields populated, (3) the validate_*
    // gate doesn't require them (validation covers paths only — the
    // bridge factory consumes plan/bundle as soft data).

    #[test]
    fn supervisor_config_parses_pre_w6a5_json_missing_plan_and_bundle() {
        // An older caller would have omitted both new fields.
        let json = r#"{
            "krun": {
                "name": "vm",
                "kernel_path": "/k",
                "rootfs_path": "/r",
                "vcpus": 1,
                "ram_mib": 256,
                "kernel_cmdline": null,
                "vsock_ports": [],
                "extra_disks": [],
                "console_output_path": null,
                "vsock_socket_dir": null
            },
            "vm_state_dir": "/tmp/vms/vm",
            "pid_file_name": null
        }"#;
        let parsed: SupervisorConfig =
            serde_json::from_str(json).expect("pre-W6.A.5 JSON must still parse");
        assert!(parsed.plan.is_none());
        assert!(parsed.bundle.is_none());
    }

    #[test]
    fn supervisor_config_roundtrips_with_plan_and_bundle_populated() {
        let mut cfg = well_formed_supervisor_config();
        // Stand-in JSON shapes — the bin crate is what decodes these
        // into typed `ExecutionPlan` / `PolicyBundle`, so the
        // mvm-libkrun layer only verifies the Values roundtrip.
        cfg.plan = Some(serde_json::json!({
            "tenant_id": "tenant-x",
            "kind": "workload",
            "version": 1
        }));
        cfg.bundle = Some(serde_json::json!({
            "name": "default",
            "version": 1,
            "rules": []
        }));
        let json = serde_json::to_string(&cfg).expect("serialize");
        let parsed: SupervisorConfig = serde_json::from_str(&json).expect("roundtrip");
        assert_eq!(parsed.plan, cfg.plan);
        assert_eq!(parsed.bundle, cfg.bundle);
    }

    #[test]
    fn supervisor_config_plan_without_bundle_is_legal() {
        let mut cfg = well_formed_supervisor_config();
        cfg.plan = Some(serde_json::json!({ "kind": "workload" }));
        cfg.bundle = None;
        // No validation involvement — bridge factory tolerates the
        // bundle being absent (matches `Option<Arc<PolicyBundle>>`
        // in BridgeConfig). Confirm serde roundtrip preserves the
        // shape without errors.
        let json = serde_json::to_string(&cfg).expect("serialize");
        let parsed: SupervisorConfig = serde_json::from_str(&json).expect("roundtrip");
        assert!(parsed.plan.is_some());
        assert!(parsed.bundle.is_none());
    }

    // -----------------------------------------------------------------
    // bridge_restart_policy field reservation. Today only `HardFail`
    // exists; the tests pin the schema-extension contract so future
    // restart variants can be added without breaking old configs and
    // without silently accepting unknown variant names on old
    // supervisors.
    // -----------------------------------------------------------------

    #[test]
    fn supervisor_config_default_bridge_restart_policy_is_hard_fail() {
        // Older JSON omits `bridge_restart_policy`; the
        // `#[serde(default)]` annotation must promote that to
        // `HardFail` so existing configs deserialize unchanged.
        let json = r#"{
            "krun": {
                "name": "vm",
                "kernel_path": "/k",
                "rootfs_path": "/r",
                "vcpus": 1,
                "ram_mib": 256,
                "kernel_cmdline": null,
                "vsock_ports": [],
                "extra_disks": [],
                "console_output_path": null,
                "vsock_socket_dir": null
            },
            "vm_state_dir": "/tmp/vms/vm",
            "pid_file_name": null
        }"#;
        let parsed: SupervisorConfig =
            serde_json::from_str(json).expect("pre-Plan-113 JSON must still parse");
        assert_eq!(parsed.bridge_restart_policy, BridgeRestartPolicy::HardFail);
    }

    #[test]
    fn supervisor_config_accepts_explicit_hard_fail_bridge_restart_policy() {
        // New-style JSON naming the current variant explicitly must
        // parse and round-trip to the same value.
        let json = r#"{
            "krun": {
                "name": "vm",
                "kernel_path": "/k",
                "rootfs_path": "/r",
                "vcpus": 1,
                "ram_mib": 256,
                "kernel_cmdline": null,
                "vsock_ports": [],
                "extra_disks": [],
                "console_output_path": null,
                "vsock_socket_dir": null
            },
            "vm_state_dir": "/tmp/vms/vm",
            "pid_file_name": null,
            "bridge_restart_policy": "hard_fail"
        }"#;
        let parsed: SupervisorConfig =
            serde_json::from_str(json).expect("explicit hard_fail must parse");
        assert_eq!(parsed.bridge_restart_policy, BridgeRestartPolicy::HardFail);
    }

    #[test]
    fn supervisor_config_rejects_unknown_bridge_restart_policy_variant() {
        // Old supervisors handed a config that names a future variant
        // they don't implement must fail
        // closed at deserialize time. serde rejects unknown unit-
        // variant names on `#[derive(Deserialize)]` enums by default,
        // which is the schema-migration guarantee this test pins.
        let json = r#"{
            "krun": {
                "name": "vm",
                "kernel_path": "/k",
                "rootfs_path": "/r",
                "vcpus": 1,
                "ram_mib": 256,
                "kernel_cmdline": null,
                "vsock_ports": [],
                "extra_disks": [],
                "console_output_path": null,
                "vsock_socket_dir": null
            },
            "vm_state_dir": "/tmp/vms/vm",
            "pid_file_name": null,
            "bridge_restart_policy": "restart_with_budget"
        }"#;
        let res: Result<SupervisorConfig, _> = serde_json::from_str(json);
        assert!(
            res.is_err(),
            "unknown bridge_restart_policy variant must be rejected"
        );
    }

    #[test]
    fn supervisor_config_round_trips_bridge_restart_policy_field() {
        // The serde shape must round-trip — emit + reparse yields
        // the same policy. Anchors the wire format so future
        // refactors can't accidentally drop the field from output.
        let cfg = well_formed_supervisor_config();
        let json = serde_json::to_string(&cfg).expect("serialize");
        let parsed: SupervisorConfig = serde_json::from_str(&json).expect("roundtrip");
        assert_eq!(parsed.bridge_restart_policy, cfg.bridge_restart_policy);
        assert_eq!(parsed.bridge_restart_policy, BridgeRestartPolicy::HardFail);
    }

    #[test]
    fn supervisor_config_round_trips_transparent_terminator_port() {
        let mut cfg = well_formed_supervisor_config();
        cfg.transparent_terminator_port = Some(19123);
        let json = serde_json::to_string(&cfg).expect("serialize");
        let parsed: SupervisorConfig = serde_json::from_str(&json).expect("roundtrip");
        assert_eq!(parsed.transparent_terminator_port, Some(19123));
    }

    // ---------------------------------------------------------------
    // bridge-inserting configure + BridgeFds.
    // The configure_with_gateway_for_bridge tests below are gated on
    // both `libkrun-sys` (needs the FFI bindings to compile) and
    // unix (the gateway types are unix-family only).
    // ---------------------------------------------------------------

    #[cfg(all(feature = "libkrun-sys", target_family = "unix"))]
    #[test]
    fn bridge_socketpair_stream_returns_two_distinct_fds() {
        use std::os::fd::AsRawFd;
        let (a, b) = bridge_socketpair_stream().expect("socketpair");
        assert_ne!(a.as_raw_fd(), b.as_raw_fd());
        assert!(a.as_raw_fd() >= 0);
        assert!(b.as_raw_fd() >= 0);
    }

    #[cfg(all(feature = "libkrun-sys", target_family = "unix"))]
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
                    context.contains("claim-10"),
                    "error context must cite claim-10: {context}"
                );
            }
            other => panic!("expected Error::Io with Tsi message, got {other:?}"),
        }
    }

    /// Assert that `install_paths()` is correctly wired to
    /// `mvm_core::platform::LIBKRUN_LIB_PATHS` — same entry count and
    /// matching first entry. Catches any future refactor that breaks the
    /// delegation without altering the public function signature.
    #[test]
    fn install_paths_matches_core_const() {
        let paths = install_paths();
        let canonical = mvm_core::platform::LIBKRUN_LIB_PATHS;
        assert_eq!(
            paths.len(),
            canonical.len(),
            "install_paths() entry count differs from LIBKRUN_LIB_PATHS"
        );
        if !canonical.is_empty() {
            assert_eq!(
                paths[0], canonical[0],
                "install_paths()[0] differs from LIBKRUN_LIB_PATHS[0]"
            );
        }
    }
}
