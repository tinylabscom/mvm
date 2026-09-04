//! [`KrunContext`] — the pure-data description of a libkrun guest VM,
//! plus its supporting types (extra disks, virtio-fs shares, the
//! networking backend enum, and the guest PID 1 entrypoint). No I/O
//! happens until [`crate::start`] / [`crate::start_enter`] consume a
//! context; the FFI calls that apply each field live in `sys` under
//! the `libkrun-sys` feature.

// `KernelFormat` lives in `mvm-core` so all backends share one canonical type.
// Re-export it unconditionally (no feature gate) so callers that build
// `KrunContext` configurations without enabling `libkrun-sys` can still name it.
pub use mvm_core::kernel_format::KernelFormat;

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
    /// rejected at [`start_enter`](crate::start_enter) time.
    pub tag: String,
    /// Host directory to export. Must exist before
    /// [`start_enter`](crate::start_enter) runs (libkrun's daemon
    /// resolves it eagerly).
    pub host_path: String,
    /// DAX window size in bytes. `None` disables DAX for this share;
    /// `Some(n)` maps host file pages directly into the guest address
    /// space up to `n` bytes.
    #[serde(default)]
    pub shm_size: Option<u64>,
    /// Force the host-side export read-only. Requires libkrun's
    /// `krun_add_virtiofs3`; older wrappers fall back to v1 when this
    /// is false and `shm_size` is `None`.
    #[serde(default)]
    pub read_only: bool,
}

/// A per-port override for the host-side unix socket a host-listen
/// vsock port pairs with, replacing the dir-derived
/// `vsock-<port>.sock` path for that one port. See
/// [`KrunContext::host_listen_socket_path`].
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HostListenOverride {
    /// The host-listen port this override applies to. Must also
    /// appear in [`KrunContext::host_listen_ports`] for libkrun to
    /// register it.
    pub port: u32,
    /// Host unix socket path libkrun should proxy guest connects on
    /// `port` to, instead of the derived `vsock_socket_path(port)`.
    pub socket_path: String,
}

/// Configuration for a libkrun guest VM.
///
/// Pure data — no I/O until [`start`](crate::start) /
/// [`start_enter`](crate::start_enter) consume it. The FFI calls that
/// consume each field live in `sys` under the `libkrun-sys` feature.
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
    /// Per-port overrides of the host-listen socket path, for ports
    /// that should proxy to an explicit UDS instead of the
    /// dir-derived `vsock-<port>.sock` path. Empty by default — no
    /// current construction site populates this; see
    /// [`Self::host_listen_socket_path`].
    #[serde(default)]
    pub host_listen_port_overrides: Vec<HostListenOverride>,
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
    /// uses libkrun's built-in syscall-hijack TSI mode; `VsockDirect`
    /// adds an explicit virtio-vsock device with no guest NIC and no
    /// implicit TSI transport; `Passt` attaches a virtio-net device
    /// backed by a unixstream socket the caller has handed off to a
    /// guest. See `NetworkingMode` for the trade-offs.
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
/// `VsockDirect` is the no-NIC counterpart: add an explicit
/// virtio-vsock device with zero TSI feature bits so the guest still
/// gets AF_VSOCK but libkrun's implicit AF_INET/AF_UNIX transport is
/// not enabled. This is the no-guest-NIC builder / direct-path shape.
///
/// `Passt` configures a real virtio-net device wired through a
/// unixstream socket to a host-side child process. The guest
/// sees a normal eth0 + DHCP + DNS. This is the production-ready
/// networking mode for Stage 0 and steady-state builder VMs.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkingMode {
    /// libkrun's built-in TSI backend (no virtio-net, no DHCP).
    #[default]
    Tsi,
    /// Explicit virtio-vsock device with no implicit TSI transport and
    /// no virtio-net guest NIC.
    VsockDirect,
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
            host_listen_port_overrides: Vec::new(),
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
            host_listen_port_overrides: Vec::new(),
            extra_disks: Vec::new(),
            virtio_fs_mounts: Vec::new(),
            console_output_path: None,
            vsock_socket_dir: None,
            networking: NetworkingMode::Tsi,
        }
    }

    /// Construct a low-level context that boots libkrun's bundled kernel
    /// against a host directory mounted as the guest root via virtiofs.
    /// Production and builder callers use block roots; this remains as a
    /// faithful wrapper around libkrun's public C API.
    ///
    /// `entry_path` is the guest PID 1, relative to `root_dir`.
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
            host_listen_port_overrides: Vec::new(),
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

    /// Switch the guest to an explicit virtio-vsock device with no
    /// implicit TSI backend and no guest NIC.
    pub fn with_vsock_direct(mut self) -> Self {
        self.networking = NetworkingMode::VsockDirect;
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

    /// Append a control vsock port the HOST listens on, AND pin its
    /// host-side socket to an explicit `uds` path instead of the
    /// dir-derived one. Equivalent to calling
    /// [`Self::add_host_listen_port`] followed by
    /// [`Self::set_host_listen_socket_override`].
    pub fn add_host_listen_port_at(mut self, port: u32, uds: impl Into<String>) -> Self {
        self.host_listen_ports.push(port);
        self.set_host_listen_socket_override(port, uds);
        self
    }

    /// Pin the host-side socket for an already-registered (or
    /// about-to-be-registered) host-listen `port` to an explicit
    /// `uds` path, overriding the dir-derived default. See
    /// [`Self::host_listen_socket_path`] for the resolution order.
    pub fn set_host_listen_socket_override(&mut self, port: u32, uds: impl Into<String>) {
        self.host_listen_port_overrides.push(HostListenOverride {
            port,
            socket_path: uds.into(),
        });
    }

    /// Resolve the host-side unix socket path for a host-listen
    /// `port`: the last-registered [`HostListenOverride`] entry for
    /// `port` if one exists, else the dir-derived
    /// [`Self::vsock_socket_path`]. `None` overrides (the common
    /// case today) make this byte-identical to calling
    /// `vsock_socket_path` directly.
    pub fn host_listen_socket_path(&self, port: u32) -> std::path::PathBuf {
        match self
            .host_listen_port_overrides
            .iter()
            .rev()
            .find(|o| o.port == port)
        {
            Some(o) => std::path::PathBuf::from(&o.socket_path),
            None => self.vsock_socket_path(port),
        }
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
            shm_size: None,
            read_only: false,
        });
        self
    }

    /// Declare a virtio-fs share with explicit DAX and read-only flags.
    pub fn add_virtio_fs_full(
        mut self,
        tag: impl Into<String>,
        host_path: impl Into<String>,
        shm_size: Option<u64>,
        read_only: bool,
    ) -> Self {
        self.virtio_fs_mounts.push(KrunVirtioFs {
            tag: tag.into(),
            host_path: host_path.into(),
            shm_size,
            read_only,
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

#[cfg(test)]
mod tests {
    use super::*;

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
        let ctx = KrunContext::new("vm-1", "/k", "/r")
            .with_vsock_socket_dir("/home/user/mvm-home/vms/vm-1");
        let path = ctx.vsock_socket_path(5252);
        assert_eq!(
            path,
            std::path::PathBuf::from("/home/user/mvm-home/vms/vm-1/vsock-5252.sock")
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
        assert!(ctx.host_listen_port_overrides.is_empty());
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
    fn with_vsock_direct_switches_networking_mode() {
        let ctx = KrunContext::new("vm", "/k", "/r").with_vsock_direct();
        assert!(matches!(ctx.networking, NetworkingMode::VsockDirect));
    }

    /// Non-regression: a context with no overrides resolves
    /// `host_listen_socket_path` to exactly the same path
    /// `vsock_socket_path` returns today — byte-identical, not just
    /// equal in shape.
    #[test]
    fn host_listen_socket_path_matches_derived_path_when_no_override() {
        let ctx = KrunContext::new("vm-1", "/k", "/r")
            .with_vsock_socket_dir("/home/user/mvm-home/vms/vm-1")
            .add_host_listen_port(5253);
        assert!(ctx.host_listen_port_overrides.is_empty());
        assert_eq!(
            ctx.host_listen_socket_path(5253),
            ctx.vsock_socket_path(5253)
        );
    }

    /// `add_host_listen_port_at` registers the port AND pins its
    /// socket path; a different, non-overridden port keeps resolving
    /// to the derived path.
    #[test]
    fn add_host_listen_port_at_registers_port_and_override() {
        let ctx = KrunContext::new("vm-1", "/k", "/r")
            .with_vsock_socket_dir("/d")
            .add_host_listen_port_at(5253, "/run/mvm/egress-endpoint.sock")
            .add_host_listen_port(5251);
        assert!(ctx.host_listen_ports.contains(&5253));
        assert_eq!(
            ctx.host_listen_socket_path(5253),
            std::path::PathBuf::from("/run/mvm/egress-endpoint.sock")
        );
        // The non-overridden port still resolves to the dir-derived path.
        assert_eq!(
            ctx.host_listen_socket_path(5251),
            ctx.vsock_socket_path(5251)
        );
    }

    /// `set_host_listen_socket_override` can be applied to a port
    /// already registered via `add_host_listen_port` — the resolver
    /// picks it up regardless of registration order.
    #[test]
    fn set_host_listen_socket_override_applies_to_registered_port() {
        let mut ctx = KrunContext::new("vm-1", "/k", "/r")
            .with_vsock_socket_dir("/d")
            .add_host_listen_port(5253);
        ctx.set_host_listen_socket_override(5253, "/run/mvm/egress-endpoint.sock");
        assert_eq!(
            ctx.host_listen_socket_path(5253),
            std::path::PathBuf::from("/run/mvm/egress-endpoint.sock")
        );
    }

    /// `KrunContext` serde roundtrip with `host_listen_port_overrides`
    /// populated.
    #[test]
    fn host_listen_port_overrides_roundtrip_through_json() {
        let ctx = KrunContext::new("vm-1", "/k", "/r")
            .add_host_listen_port_at(5253, "/run/mvm/egress-endpoint.sock");
        let json = serde_json::to_string(&ctx).unwrap();
        assert!(json.contains("\"host_listen_port_overrides\""));
        let back: KrunContext = serde_json::from_str(&json).unwrap();
        assert_eq!(back.host_listen_port_overrides.len(), 1);
        assert_eq!(
            back.host_listen_socket_path(5253),
            std::path::PathBuf::from("/run/mvm/egress-endpoint.sock")
        );
    }
}
