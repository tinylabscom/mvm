//! PID 1 of the Stage 0 bootstrap VM — the **nix-tarball seed**.
//! Boots under **two** builder backends (selected by the `mvm.backend=qemu`
//! kernel cmdline marker), carrying the official Nix release tarball's
//! `/nix/store` + this binary as `/init` — no Alpine, no apk, no busybox.
//!
//! **libkrun**: the seed root arrives over virtiofs (`krun_set_root`) on
//! libkrunfw's bundled kernel; shares are virtio-fs; we copy the seed
//! `/nix/store` into a tmpfs and bind it over `/nix` (virtiofs writes fail
//! under FUSE). The guest brings `eth0` up through the shared
//! `mvm_guest::guest_net` path so DHCP and the static gateway fallback stay
//! aligned with the steady-state builder VM, while the host can still pass an
//! explicit resolver through `/out/stage0-build.conf` when the passt/libkrun
//! path needs one before the proxy-driven build starts.
//!
//! **QEMU** (Linux/x86_64): the stock distro kernel +
//! initramfs mount the seed as an **ext4** root (`/dev/vda`, writable — so
//! `/nix` needs no tmpfs copy), shares are ext4 block disks (`vdb`/`vdc`/`vdd`),
//! and networking is QEMU slirp's fixed addresses configured statically over
//! ioctls (no DHCP, no passt). Proven E2E on x86_64 (kernel built + copied to
//! `/out`).
//!
//! Either way: `nix build` the in-repo builder-VM flake, copy the artifacts to
//! `/out`, and power off. The host side (`stage0::materialize_root_dir` /
//! `qemu_builder`) lays down the seed and writes this binary as `/init`.

use std::process::ExitCode;

fn main() -> ExitCode {
    #[cfg(target_os = "linux")]
    {
        linux::run()
    }
    #[cfg(not(target_os = "linux"))]
    {
        // The seed init only ever runs inside the Linux Stage 0 guest. The
        // crate still compiles on macOS/Windows contributor hosts (the bin
        // is cross-compiled to aarch64-musl + embedded by
        // mvm-cli/build.rs) so workspace builds stay green.
        eprintln!("stage0-init: only runs as PID 1 inside the Linux Stage 0 guest");
        ExitCode::FAILURE
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use sha2::{Digest, Sha256};
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};
    use std::process::{Command, ExitCode, Stdio};

    const STAGE0_PROXY_ADDR: &str = "127.0.0.1:8443";

    /// Where nix runs from (its store paths are absolute `/nix/store/...`).
    const NIX_TARGET: &str = "/nix";
    /// Bind of the original (virtiofs) seed `/nix` so we can still read the
    /// seed store after mounting a fresh tmpfs over `/nix`.
    const NIX_SEED_RO: &str = "/nix-seed-ro";
    /// Stage 0's dedicated persistent Nix-store block device. The libkrun
    /// launcher attaches this before the virtio-fs shares, so it enumerates as
    /// `/dev/vda`. QEMU uses `/dev/vda` as the rootfs, so this is libkrun-only.
    const STAGE0_NIX_STORE_DEV: &str = "/dev/vda";
    /// Mount point for the persistent Stage 0 Nix store before binding it over
    /// `/nix`.
    const STAGE0_NIX_STORE_MOUNT: &str = "/nix-stage0-store";
    /// Marker written next to `store/` and `var/` on the persistent Stage 0
    /// store. It binds reuse to the seed store fingerprint, not to mutable Nix
    /// build output added later.
    const STAGE0_NIX_STORE_MARKER: &str = "/nix-stage0-store/.mvm-stage0-nix-store";
    const STAGE0_NIX_STORE_MARKER_SCHEMA_VERSION: u32 = 1;
    const VSOCK_ONLY_CMDLINE_TOKEN: &str = "mvm.vsock_only=1";
    const VSOCK_ONLY_ENV_VAR: &str = "MVM_VSOCK_ONLY";

    pub fn run() -> ExitCode {
        // libkrunfw's bundled kernel hands PID 1 a low RLIMIT_NOFILE on some
        // arches (x86_64 hit EMFILE copying the seed store to tmpfs). As PID 1
        // / root we can raise both soft and hard limits; do it before any
        // fd-heavy work.
        raise_fd_limit();
        if let Err(e) = setup() {
            eprintln!("stage0-init: FATAL: {e}");
            // Best-effort power off so the host sees the VM exit rather than
            // hang; the absence of /out artifacts is the failure signal.
            return power_off();
        }
        match build_and_copy() {
            Ok(()) => {
                eprintln!("stage0-init: done; halting");
                power_off()
            }
            Err(e) => {
                eprintln!("stage0-init: build failed: {e}");
                power_off()
            }
        }
    }

    /// Raise `RLIMIT_NOFILE` so the recursive seed-store copy (and `nix`
    /// itself) don't hit `EMFILE` under the bundled kernel's low default.
    /// Best-effort: as PID 1/root we can lift the hard limit, but a kernel
    /// ceiling below 65536 just clamps — we then take whatever the hard
    /// limit allows. Never fatal.
    fn raise_fd_limit() {
        // SAFETY: getrlimit/setrlimit with a valid resource id + struct ptr.
        unsafe {
            let want = libc::rlimit {
                rlim_cur: 65536,
                rlim_max: 65536,
            };
            if libc::setrlimit(libc::RLIMIT_NOFILE, &want) == 0 {
                return;
            }
            // Hard ceiling below 65536: raise the soft limit to the hard limit.
            let mut cur = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            if libc::getrlimit(libc::RLIMIT_NOFILE, &mut cur) == 0 {
                cur.rlim_cur = cur.rlim_max;
                let _ = libc::setrlimit(libc::RLIMIT_NOFILE, &cur);
            }
        }
    }

    /// True when stage0-init runs under the **QEMU** builder backend
    /// (Linux) vs **libkrun**. The QEMU launcher passes `mvm.backend=qemu`
    /// on the kernel cmdline; libkrun does not. This drives every host-vs-VMM
    /// difference: share transport (ext4 block disks vs virtiofs), the nix
    /// store layout (writable ext4 root vs tmpfs copy), and networking
    /// (QEMU slirp's fixed addresses vs libkrun's DHCP gateway).
    fn is_qemu() -> bool {
        std::fs::read_to_string("/proc/cmdline")
            .map(|c| c.contains("mvm.backend=qemu"))
            .unwrap_or(false)
    }

    fn vsock_only_mode(cmdline: &str) -> bool {
        cmdline.contains(VSOCK_ONLY_CMDLINE_TOKEN)
            || std::env::var_os(VSOCK_ONLY_ENV_VAR).as_deref() == Some("1".as_ref())
    }

    /// Mounts the pseudo-filesystems + the host shares, then makes `/nix` a
    /// writable store. libkrun supplies eth0 (DHCP); under QEMU the Debian
    /// initramfs brings up eth0 from the `ip=` cmdline.
    fn setup() -> Result<(), String> {
        mount_pseudofs()?;
        // `/dev/null` insurance — some libkrun set_root boots reach
        // userspace without it, which then masks every `2>/dev/null`
        // downstream. `|| Ok` it: devtmpfs usually creates it.
        if !Path::new("/dev/null").exists() {
            mknod_null();
        }

        let qemu = is_qemu();
        let cmdline = std::fs::read_to_string("/proc/cmdline").unwrap_or_default();
        eprintln!(
            "stage0-init: backend = {}",
            if qemu { "qemu" } else { "libkrun" }
        );

        // Host shares. libkrun presents them over virtio-fs by tag; QEMU as
        // ext4 block disks (the initramfs already loaded virtio_blk for the
        // ext4 root, so vdb/vdc/vdd enumerate with no extra modules — no
        // virtiofsd, no 9p). Order matches the device order on the QEMU
        // cmdline (vda=seed root, then work/out/mvm-bins).
        let shares: &[(&str, &str, &str)] = if qemu {
            &[
                ("/dev/vdb", "/work", "ext4"),
                ("/dev/vdc", "/out", "ext4"),
                ("/dev/vdd", "/mvm-bins", "ext4"),
            ]
        } else {
            &[
                ("work", "/work", "virtiofs"),
                ("out", "/out", "virtiofs"),
                ("mvm-bins", "/mvm-bins", "virtiofs"),
            ]
        };
        for (source, target, fstype) in shares {
            std::fs::create_dir_all(target).map_err(|e| format!("create {target}: {e}"))?;
            mount_fs(source, target, fstype)?;
            if !is_mountpoint(target) {
                return Err(format!("{target} ({fstype}) mount did not take"));
            }
        }

        if qemu {
            // The QEMU root is a writable ext4 seed, so `/nix` is already a
            // writable store — no virtiofs-over-FUSE problem, no tmpfs copy
            // (and no EMFILE). nix writes directly to `/nix/store`.
            configure_network_qemu()?;
            log_net_state();
        } else {
            if vsock_only_mode(&cmdline) {
                eprintln!(
                    "stage0-init: vsock-only marker present; skipping guest NIC bring-up and using vsock-only egress path"
                );
            } else if Path::new("/sys/class/net/eth0").exists() {
                eprintln!("stage0-init: configuring libkrun guest network via shared guest_net");
                mvm_guest::guest_net::configure_guest_network("eth0", &cmdline, "192.168.127.3")?;
                eprintln!("stage0-init: shared guest_net completed");
            } else {
                eprintln!("stage0-init: no eth0 present; using vsock-only egress path");
            }
            log_net_state();
            setup_nix_store()?;
        }
        let conf = read_build_conf("/out/stage0-build.conf");
        configure_nix_runtime(qemu, &conf)?;
        Ok(())
    }

    /// Statically configure the guest NIC for QEMU user-mode networking
    /// (slirp), which hands out fixed addresses: guest `10.0.2.15/24`,
    /// gateway `10.0.2.2`, DNS `10.0.2.3`. There's no DHCP and no passt, and
    /// the kernel passes `ip=` to userspace (modular virtio_net), so we set
    /// the address + default route over ioctls ourselves. The interface name
    /// is detected (the kernel renames eth0→ensN under predictable naming).
    fn configure_network_qemu() -> Result<(), String> {
        let iface = find_net_iface().ok_or("no non-loopback interface present")?;
        eprintln!("stage0-init: net config {iface} = 10.0.2.15/24 gw 10.0.2.2 (slirp)");
        mvm_guest::guest_net::configure_static(&iface, "10.0.2.15", "255.255.255.0", "10.0.2.2")
    }

    /// The non-loopback interface name from `/sys/class/net` (e.g. `ens3`).
    fn find_net_iface() -> Option<String> {
        std::fs::read_dir("/sys/class/net")
            .ok()?
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .find(|n| n != "lo")
    }

    /// Diagnostic dump of the guest's network state under QEMU — so a boot log
    /// shows whether the initramfs `ip=` autoconfig brought eth0 up (address +
    /// default route) before we rely on it for the nix fetch.
    fn log_net_state() {
        let ifaces = std::fs::read_dir("/sys/class/net")
            .map(|d| {
                d.filter_map(|e| e.ok().map(|e| e.file_name().to_string_lossy().into_owned()))
                    .collect::<Vec<_>>()
                    .join(",")
            })
            .unwrap_or_else(|_| "<none>".into());
        let route = std::fs::read_to_string("/proc/net/route").unwrap_or_default();
        let default_route = route
            .lines()
            .skip(1)
            .any(|l| l.split_whitespace().nth(1) == Some("00000000"));
        eprintln!("stage0-init: net ifaces=[{ifaces}] default_route={default_route}");
    }

    /// DNS + nix store state the seed rootfs doesn't ship. QEMU uses its fixed
    /// slirp DNS (`10.0.2.3`). The libkrun path normally keeps the resolver
    /// already present in the guest, but accepts an explicit host-selected
    /// resolver via `/out/stage0-build.conf` when Stage 0 needs one before the
    /// proxy-driven build takes over.
    fn configure_nix_runtime(qemu: bool, conf: &HashMap<String, String>) -> Result<(), String> {
        std::fs::create_dir_all("/etc").map_err(|e| format!("create /etc: {e}"))?;
        if qemu || !Path::new("/etc/resolv.conf").exists() {
            let resolver = resolver_seed(qemu, conf)?;
            std::fs::write("/etc/resolv.conf", resolver)
                .map_err(|e| format!("write /etc/resolv.conf: {e}"))?;
        }
        for d in ["/nix/var", "/nix/var/nix", "/nix/var/log/nix"] {
            std::fs::create_dir_all(d).map_err(|e| format!("create {d}: {e}"))?;
        }
        Ok(())
    }

    struct Stage0VsockEgress {
        handle: Option<mvm_build::egress_proxy::VsockProxyHandle>,
    }

    impl Stage0VsockEgress {
        fn start() -> Result<Self, String> {
            let handle = mvm_build::egress_proxy::start_vsock_proxy(
                STAGE0_PROXY_ADDR,
                mvm_build::egress_proxy::ConnectPolicy::Unrestricted,
            )
            .map_err(|e| {
                format!("start Stage 0 vsock CONNECT proxy at {STAGE0_PROXY_ADDR}: {e}")
            })?;
            Ok(Self {
                handle: Some(handle),
            })
        }
    }

    impl Drop for Stage0VsockEgress {
        fn drop(&mut self) {
            if let Some(mut handle) = self.handle.take() {
                handle.shutdown();
            }
        }
    }

    fn resolver_seed(qemu: bool, conf: &HashMap<String, String>) -> Result<Vec<u8>, String> {
        if qemu {
            return Ok(b"nameserver 10.0.2.3\n".to_vec());
        }

        if let Some(resolver) = conf.get("MVM_STAGE0_RESOLVER") {
            if mvm_guest::guest_net::parse_ipv4(resolver).is_none() {
                return Err(format!(
                    "invalid MVM_STAGE0_RESOLVER {resolver:?} in /out/stage0-build.conf"
                ));
            }
            return Ok(format!("nameserver {resolver}\n").into_bytes());
        }

        Ok(b"nameserver 192.168.127.1\n".to_vec())
    }

    /// Standard PID-1 pseudo-filesystems. libkrun's kernel pre-mounts some;
    /// `mount_fs_idempotent` treats EBUSY as success.
    fn mount_pseudofs() -> Result<(), String> {
        mount_fs_idempotent("proc", "/proc", "proc")?;
        mount_fs_idempotent("sysfs", "/sys", "sysfs")?;
        mount_fs_idempotent("devtmpfs", "/dev", "devtmpfs")?;
        mount_fs_idempotent("tmpfs", "/tmp", "tmpfs")?;
        mount_fs_idempotent("tmpfs", "/run", "tmpfs")?;
        let _ = std::fs::create_dir_all("/dev/shm");
        mount_fs_idempotent("tmpfs", "/dev/shm", "tmpfs")?;
        // nix's build sandbox opens /dev/ptmx → needs devpts at /dev/pts.
        let _ = std::fs::create_dir_all("/dev/pts");
        mount_fs_idempotent("devpts", "/dev/pts", "devpts")?;
        Ok(())
    }

    /// Make `/nix` a writable, non-virtiofs store. The seed `/nix` arrives on
    /// the libkrun virtiofs RootDir; overlayfs-over-virtiofs writes fail
    /// (`nix build` → `creating /nix/store/.links: ECONNRESET` — a FUSE
    /// backend error).
    ///
    /// Fast path: mount the dedicated persistent ext4 `/dev/vda`, seed it once
    /// from the verified RootDir store, then bind it over `/nix` on every later
    /// boot. If the current seed lacks `mkfs.ext4` and the disk is still blank,
    /// fall back to the old tmpfs copy so the bootstrap remains functional.
    fn setup_nix_store() -> Result<(), String> {
        match setup_persistent_nix_store() {
            Ok(()) => return Ok(()),
            Err(e) => eprintln!(
                "stage0-init: persistent Stage 0 /nix store unavailable ({e}); falling back to tmpfs seed copy"
            ),
        }

        // Copy BEFORE hiding the seed: mount a tmpfs at NIX_SEED_RO, copy the
        // seed `/nix/store` (still directly readable on the virtiofs root)
        // into it, then bind it over `/nix`. nix then runs from the tmpfs.
        std::fs::create_dir_all(NIX_SEED_RO).map_err(|e| format!("create {NIX_SEED_RO}: {e}"))?;
        mount_fs("tmpfs", NIX_SEED_RO, "tmpfs")?;
        let seed_store = Path::new(NIX_TARGET).join("store");
        let dst_store = Path::new(NIX_SEED_RO).join("store");
        std::fs::create_dir_all(&dst_store)
            .map_err(|e| format!("create {}: {e}", dst_store.display()))?;
        let n_src = std::fs::read_dir(&seed_store)
            .map(|d| d.count())
            .unwrap_or(0);
        copy_tree(&seed_store, &dst_store)
            .map_err(|e| format!("copying seed nix store to tmpfs: {e}"))?;
        let n_dst = std::fs::read_dir(&dst_store)
            .map(|d| d.count())
            .unwrap_or(0);
        eprintln!("stage0-init: copied seed store: {n_src} -> {n_dst} entries");
        // Now make the tmpfs copy be `/nix`.
        bind_mount(NIX_SEED_RO, NIX_TARGET)?;
        Ok(())
    }

    fn setup_persistent_nix_store() -> Result<(), String> {
        if !Path::new(STAGE0_NIX_STORE_DEV).exists() {
            return Err(format!("{STAGE0_NIX_STORE_DEV} is not present"));
        }

        std::fs::create_dir_all(STAGE0_NIX_STORE_MOUNT)
            .map_err(|e| format!("create {STAGE0_NIX_STORE_MOUNT}: {e}"))?;
        mount_stage0_nix_store()?;

        let seed_store = Path::new(NIX_TARGET).join("store");
        let expected_marker = stage0_nix_store_marker(&seed_store)?;
        if persistent_nix_store_matches(&expected_marker) {
            eprintln!(
                "stage0-init: reusing persistent Stage 0 Nix store at {STAGE0_NIX_STORE_DEV}"
            );
            bind_mount(STAGE0_NIX_STORE_MOUNT, NIX_TARGET)?;
            return Ok(());
        }
        if persistent_nix_store_matches_seed(&seed_store)? {
            std::fs::write(STAGE0_NIX_STORE_MARKER, expected_marker)
                .map_err(|e| format!("write {STAGE0_NIX_STORE_MARKER}: {e}"))?;
            eprintln!(
                "stage0-init: adopting host-prepopulated Stage 0 Nix store at {STAGE0_NIX_STORE_DEV}"
            );
            bind_mount(STAGE0_NIX_STORE_MOUNT, NIX_TARGET)?;
            return Ok(());
        }

        eprintln!(
            "stage0-init: initializing persistent Stage 0 Nix store at {STAGE0_NIX_STORE_DEV}"
        );
        clear_dir_children(Path::new(STAGE0_NIX_STORE_MOUNT))
            .map_err(|e| format!("clearing {STAGE0_NIX_STORE_MOUNT}: {e}"))?;
        let dst_store = Path::new(STAGE0_NIX_STORE_MOUNT).join("store");
        std::fs::create_dir_all(&dst_store)
            .map_err(|e| format!("create {}: {e}", dst_store.display()))?;
        let n_src = std::fs::read_dir(&seed_store)
            .map(|d| d.count())
            .unwrap_or(0);
        copy_tree(&seed_store, &dst_store)
            .map_err(|e| format!("copying seed nix store to persistent disk: {e}"))?;
        let n_dst = std::fs::read_dir(&dst_store)
            .map(|d| d.count())
            .unwrap_or(0);
        std::fs::write(STAGE0_NIX_STORE_MARKER, expected_marker)
            .map_err(|e| format!("write {STAGE0_NIX_STORE_MARKER}: {e}"))?;
        eprintln!("stage0-init: seeded persistent store: {n_src} -> {n_dst} entries");
        bind_mount(STAGE0_NIX_STORE_MOUNT, NIX_TARGET)?;
        Ok(())
    }

    fn mount_stage0_nix_store() -> Result<(), String> {
        match mount_fs(STAGE0_NIX_STORE_DEV, STAGE0_NIX_STORE_MOUNT, "ext4") {
            Ok(()) => return Ok(()),
            Err(first_mount_err) => {
                let Some(mkfs) = find_mkfs_ext4() else {
                    return Err(format!(
                        "{first_mount_err}; mkfs.ext4 not available in seed"
                    ));
                };
                eprintln!(
                    "stage0-init: formatting {STAGE0_NIX_STORE_DEV} for persistent Stage 0 store ({first_mount_err})"
                );
                format_ext4_with(&mkfs, STAGE0_NIX_STORE_DEV)?;
            }
        }
        mount_fs(STAGE0_NIX_STORE_DEV, STAGE0_NIX_STORE_MOUNT, "ext4")
    }

    fn find_mkfs_ext4() -> Option<PathBuf> {
        [
            "/sbin/mkfs.ext4",
            "/bin/mkfs.ext4",
            "/usr/sbin/mkfs.ext4",
            "/usr/bin/mkfs.ext4",
        ]
        .into_iter()
        .map(PathBuf::from)
        .find(|p| p.is_file())
    }

    fn format_ext4_with(mkfs: &Path, dev: &str) -> Result<(), String> {
        let blocks_4k = device_size_4k_blocks(dev)?;
        let status = Command::new(mkfs)
            .args(["-F", "-q", "-b", "4096", dev, &blocks_4k.to_string()])
            .status()
            .map_err(|e| format!("spawn {}: {e}", mkfs.display()))?;
        if !status.success() {
            return Err(format!(
                "{} exit {}",
                mkfs.display(),
                status.code().unwrap_or(-1)
            ));
        }
        Ok(())
    }

    fn device_size_4k_blocks(dev: &str) -> Result<u64, String> {
        let basename = Path::new(dev)
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or_else(|| format!("device path {dev} has no basename"))?;
        let sys_path = format!("/sys/class/block/{basename}/size");
        let sectors_str =
            std::fs::read_to_string(&sys_path).map_err(|e| format!("read {sys_path}: {e}"))?;
        let sectors: u64 = sectors_str
            .trim()
            .parse()
            .map_err(|e| format!("parse {sys_path} = {sectors_str:?}: {e}"))?;
        Ok(sectors / 8)
    }

    fn persistent_nix_store_matches(expected_marker: &str) -> bool {
        Path::new(STAGE0_NIX_STORE_MOUNT).join("store").is_dir()
            && std::fs::read_to_string(STAGE0_NIX_STORE_MARKER)
                .is_ok_and(|marker| marker == expected_marker)
    }

    fn persistent_nix_store_matches_seed(seed_store: &Path) -> Result<bool, String> {
        let mounted_store = Path::new(STAGE0_NIX_STORE_MOUNT).join("store");
        if !mounted_store.is_dir() {
            return Ok(false);
        }
        Ok(seed_store_entries_hash(&mounted_store)? == seed_store_entries_hash(seed_store)?)
    }

    fn stage0_nix_store_marker(seed_store: &Path) -> Result<String, String> {
        Ok(format!(
            "schema_version={STAGE0_NIX_STORE_MARKER_SCHEMA_VERSION}\nseed_store_entries_sha256={}\n",
            seed_store_entries_hash(seed_store)?
        ))
    }

    fn seed_store_entries_hash(seed_store: &Path) -> Result<String, String> {
        let mut entries = std::fs::read_dir(seed_store)
            .map_err(|e| format!("read {}: {e}", seed_store.display()))?
            .map(|entry| {
                entry
                    .map(|entry| entry.file_name().to_string_lossy().into_owned())
                    .map_err(|e| format!("read entry under {}: {e}", seed_store.display()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        entries.sort_unstable();

        let mut hasher = Sha256::new();
        for entry in entries {
            hasher.update(entry.as_bytes());
            hasher.update(b"\n");
        }
        Ok(hex::encode(hasher.finalize()))
    }

    fn clear_dir_children(dir: &Path) -> std::io::Result<()> {
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            let file_type = entry.file_type()?;
            if file_type.is_dir() {
                std::fs::remove_dir_all(path)?;
            } else {
                std::fs::remove_file(path)?;
            }
        }
        Ok(())
    }

    /// Recursively copy `src` -> `dst` preserving symlinks + file modes
    /// (the seed has no `cp`). Iterative to avoid deep-tree recursion limits.
    /// Hardlinks degrade to copies — fine for a one-shot bootstrap store.
    fn copy_tree(src: &Path, dst: &Path) -> std::io::Result<()> {
        let mut stack = vec![(src.to_path_buf(), dst.to_path_buf())];
        while let Some((from_dir, to_dir)) = stack.pop() {
            std::fs::create_dir_all(&to_dir)?;
            for entry in std::fs::read_dir(&from_dir)? {
                let entry = entry?;
                let ft = entry.file_type()?;
                let from = entry.path();
                let to = to_dir.join(entry.file_name());
                if ft.is_symlink() {
                    let target = std::fs::read_link(&from)?;
                    let _ = std::fs::remove_file(&to);
                    std::os::unix::fs::symlink(&target, &to)?;
                } else if ft.is_dir() {
                    stack.push((from, to));
                } else {
                    std::fs::copy(&from, &to)?; // preserves permissions
                }
            }
        }
        Ok(())
    }

    /// `nix build` the builder-VM flake, then copy kernel + rootfs to /out.
    /// The host-side contract (`/out/stage0-build.conf`, output modes) is the
    /// same one `dev up` / `kernel build` write.
    fn build_and_copy() -> Result<(), String> {
        let nix = find_seed_bin("nix")?;
        let nix_collect_garbage = find_seed_bin("nix-collect-garbage")?;
        let cacert = find_seed_cacert()?;

        // Env: HOME / MVM_WORKSPACE_PATH / MVM_HOST_BIN_DIR for the nix build.
        std::fs::create_dir_all("/root").ok();
        let nix_path = nix
            .parent()
            .map(|bindir| {
                let path = std::env::var("PATH").unwrap_or_default();
                format!("{}:{path}", bindir.display())
            })
            .unwrap_or_default();
        // Console diagnostics (the console.log persists across the power-off;
        // /out gets cleaned up on failure). Confirms the seed nix is runnable
        // before the long build.
        eprintln!("stage0-init: nix = {}", nix.display());
        match Command::new(&nix).arg("--version").output() {
            Ok(o) => eprintln!(
                "stage0-init: nix --version: {}{}",
                String::from_utf8_lossy(&o.stdout).trim(),
                String::from_utf8_lossy(&o.stderr).trim()
            ),
            Err(e) => eprintln!("stage0-init: nix --version failed to spawn: {e}"),
        }

        // Optional host-dropped build config (single-attr / kernel-only
        // modes); absent it, build the full image.
        let conf = read_build_conf("/out/stage0-build.conf");
        let workspace_root = workspace_root_for_build(&conf)?;
        // SAFETY: this is PID 1, single-threaded at this point — no other
        // thread can observe a torn environment. `set_var` is `unsafe` in
        // edition 2024 only for that thread-safety reason.
        // CA bundle = HTTPS trust for cache.nixos.org / flake inputs (libkrun
        // gives us DNS; `nss-cacert` from the seed gives the trust roots).
        // PATH = the seed nix's own bin dir (curl/xz/etc. live beside `nix`).
        unsafe {
            std::env::set_var("HOME", "/root");
            std::env::set_var("MVM_WORKSPACE_PATH", &workspace_root);
            std::env::set_var("MVM_HOST_BIN_DIR", "/mvm-bins");
            std::env::set_var("NIX_SSL_CERT_FILE", &cacert);
            // Force single-user (local store) — the seed has no nix-daemon;
            // an empty NIX_REMOTE makes nix build directly as root.
            std::env::set_var("NIX_REMOTE", "");
            if !nix_path.is_empty() {
                std::env::set_var("PATH", nix_path);
            }
        }
        maybe_collect_stage0_nix_garbage(&nix_collect_garbage);
        let attr = conf
            .get("MVM_STAGE0_BUILD_ATTR")
            .cloned()
            .unwrap_or_else(|| "default".into());
        let mode = conf
            .get("MVM_STAGE0_OUTPUT_MODE")
            .cloned()
            .unwrap_or_else(|| "image".into());
        let arch = machine_arch()?;
        let flake_ref = format!(
            "path:{}/nix/images/builder-vm#packages.{arch}-linux.{attr}",
            workspace_root.display()
        );
        let extra_build_flags = stage0_nix_extra_flags(&conf)?;

        eprintln!("stage0-init: building {flake_ref} (output_mode={mode})");
        let proxy = if is_qemu() {
            None
        } else {
            eprintln!(
                "stage0-init: starting local CONNECT-over-vsock egress proxy at {STAGE0_PROXY_ADDR}"
            );
            Some(Stage0VsockEgress::start()?)
        };
        let mut cmd = Command::new(&nix);
        cmd.args([
            "build",
            &flake_ref,
            "--extra-experimental-features",
            "nix-command flakes",
            // Single-user root bootstrap: the seed has no `nixbld` build
            // users + no daemon, so build directly as root (empty
            // build-users-group). Keep the DEFAULT sandbox — it gives
            // each build a clean env (its own /bin/sh + toolchain),
            // independent of the minimal seed rootfs; disabling it makes
            // builds fail on the seed's missing `/bin`, `gcc`, etc.
            "--option",
            "build-users-group",
            "",
            "--option",
            "connect-timeout",
            "30",
            "--max-jobs",
            "1",
            "--no-link",
            "--no-write-lock-file",
            "--impure",
            "--print-out-paths",
            "--print-build-logs",
        ]);
        cmd.args(&extra_build_flags);
        if proxy.is_some() {
            for (k, v) in stage0_proxy_env() {
                cmd.env(k, v);
            }
            // The NIC-less libkrun Stage 0 path depends on proxy env for every
            // networked Nix step. Keep the inner Nix work unsandboxed inside
            // the already-isolated VM so fetch/build subprocesses inherit the
            // same proxy and substituter settings as the outer `nix build`.
            cmd.env("NIX_CONFIG", stage0_nix_config_for_vsock_proxy());
        }
        // Echo nix's `--print-build-logs` to the guest's own stderr, which the
        // host captures to `console.log` live — that's what makes the otherwise-
        // silent multi-minute build tailable from the host.
        let (status, stderr_log, stdout) =
            run_streaming(cmd, &mut std::io::stderr()).map_err(|e| format!("nix build: {e}"))?;
        drop(proxy);

        // Persist the full log to /out (a virtio-fs share) for host-side
        // post-mortem at ~/.cache/mvm/builder-vm/.../nix-stderr.log.
        let _ = std::fs::write("/out/nix-stderr.log", &stderr_log);
        if !status.success() {
            return Err(format!("nix build exit {}", status.code().unwrap_or(-1)));
        }
        maybe_collect_stage0_nix_garbage(&nix_collect_garbage);
        let store_path = stdout.trim().to_string();
        if store_path.is_empty() {
            return Err("nix build emitted no /nix/store path".into());
        }
        copy_artifacts(Path::new(&store_path), &mode)?;

        // Best-effort: also emit the resolved `.config` so the host can report
        // the `=y` symbol count without a CI round-trip. The configfile is a
        // cached build dep of the kernel just built, so this realises instantly.
        // A failure here never fails the kernel build — the kernel is the
        // artifact that matters.
        if mode == "kernel"
            && let Some(config_attr) = conf.get("MVM_STAGE0_CONFIG_ATTR")
            && let Err(e) = emit_resolved_config(&nix, &arch, &workspace_root, config_attr)
        {
            eprintln!("stage0-init: skipping kernel-config emit: {e}");
        }
        Ok(())
    }

    /// Realise the resolved-`.config` flake attr and copy it to
    /// `/out/mvm-kernel.config`. Cheap — it's a cached dependency of the
    /// kernel just built.
    fn emit_resolved_config(
        nix: &Path,
        arch: &str,
        workspace_root: &Path,
        config_attr: &str,
    ) -> Result<(), String> {
        let flake_ref = format!(
            "path:{}/nix/images/builder-vm#packages.{arch}-linux.{config_attr}",
            workspace_root.display()
        );
        let conf = read_build_conf("/out/stage0-build.conf");
        let extra_build_flags = stage0_nix_extra_flags(&conf)?;
        let mut cmd = Command::new(nix);
        cmd.args([
            "build",
            &flake_ref,
            "--extra-experimental-features",
            "nix-command flakes",
            "--option",
            "build-users-group",
            "",
            "--max-jobs",
            "1",
            "--no-link",
            "--no-write-lock-file",
            "--impure",
            "--print-out-paths",
        ]);
        cmd.args(&extra_build_flags);
        let out = cmd.output().map_err(|e| format!("nix build config: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "nix build config exit {}",
                out.status.code().unwrap_or(-1)
            ));
        }
        let store_path = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if store_path.is_empty() {
            return Err("config build emitted no /nix/store path".into());
        }
        copy_deref(Path::new(&store_path), Path::new("/out/mvm-kernel.config"))
    }

    fn maybe_collect_stage0_nix_garbage(nix_collect_garbage: &Path) {
        let gc_cap_kib = mvm_build::builder_vm_runtime::builder_store_gc_cap_kib();
        let store_kib = match nix_filesystem_used_kib(Path::new(NIX_TARGET)) {
            Ok(store_kib) => store_kib,
            Err(e) => {
                eprintln!("stage0-init: unable to measure /nix filesystem usage: {e}");
                return;
            }
        };
        if store_kib <= gc_cap_kib {
            return;
        }

        eprintln!(
            "stage0-init: /nix store {store_kib} KiB > cap {gc_cap_kib} KiB; running nix-collect-garbage --delete-older-than 14d"
        );
        match Command::new(nix_collect_garbage)
            .args(["--delete-older-than", "14d"])
            .output()
        {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                if !stdout.trim().is_empty() {
                    eprint!("{stdout}");
                }
                let stderr = String::from_utf8_lossy(&output.stderr);
                if !stderr.trim().is_empty() {
                    eprint!("{stderr}");
                }
                if !output.status.success() {
                    eprintln!(
                        "stage0-init: nix-collect-garbage exited {} (continuing)",
                        output.status.code().unwrap_or(-1)
                    );
                }
            }
            Err(e) => eprintln!("stage0-init: failed to spawn nix-collect-garbage: {e}"),
        }
    }

    fn nix_filesystem_used_kib(path: &Path) -> Result<u64, String> {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;

        let c_path = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| format!("{} contains interior NUL", path.display()))?;
        let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
        // SAFETY: c_path is a valid NUL-terminated path and stat points to
        // writable memory for libc to initialize.
        let rc = unsafe { libc::statvfs(c_path.as_ptr(), stat.as_mut_ptr()) };
        if rc != 0 {
            return Err(format!(
                "statvfs {}: {}",
                path.display(),
                std::io::Error::last_os_error()
            ));
        }
        // SAFETY: statvfs succeeded, so libc initialized `stat`.
        let stat = unsafe { stat.assume_init() };
        let used_blocks = stat.f_blocks.saturating_sub(stat.f_bavail);
        let block_size = u128::from(stat.f_frsize.max(stat.f_bsize));
        let used_bytes = u128::from(used_blocks) * block_size;
        Ok((used_bytes / 1024) as u64)
    }

    fn workspace_root_for_build(conf: &HashMap<String, String>) -> Result<PathBuf, String> {
        if let Some(archive_path) = conf.get("MVM_STAGE0_WORKSPACE_ARCHIVE") {
            localize_override_source_at(Path::new("/nix"), "stage0-work", archive_path)?;
            return Ok(PathBuf::from("/nix/stage0-work"));
        }
        Ok(PathBuf::from("/work"))
    }

    /// Spawn `cmd`, streaming its stderr line-by-line to `live` (flushed per
    /// line so a host tailing the console sees progress as it arrives) while
    /// accumulating the full stderr for a post-mortem log, and capturing stdout
    /// (nix's single trailing out-path). Returns `(status, stderr_log, stdout)`.
    ///
    /// Draining stderr to EOF before reading stdout can't deadlock here: nix
    /// writes only the short out-path to stdout (well under the pipe buffer), so
    /// it never blocks waiting for us to read it.
    fn run_streaming(
        mut cmd: Command,
        live: &mut dyn std::io::Write,
    ) -> Result<(std::process::ExitStatus, Vec<u8>, String), String> {
        use std::io::{BufRead, Read};
        let mut child = cmd
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("spawn: {e}"))?;

        let mut stderr_log: Vec<u8> = Vec::new();
        if let Some(child_stderr) = child.stderr.take() {
            let reader = std::io::BufReader::new(child_stderr);
            for chunk in reader.split(b'\n') {
                let Ok(mut chunk) = chunk else { break };
                chunk.push(b'\n');
                let _ = live.write_all(&chunk);
                let _ = live.flush();
                stderr_log.extend_from_slice(&chunk);
            }
        }
        let mut stdout = String::new();
        if let Some(mut child_stdout) = child.stdout.take() {
            let _ = child_stdout.read_to_string(&mut stdout);
        }
        let status = child.wait().map_err(|e| format!("wait: {e}"))?;
        Ok((status, stderr_log, stdout))
    }

    /// Output by mode: image = kernel + rootfs.ext4 + cmdline; kernel =
    /// kernel only; rootfs = rootfs + cmdline only.
    fn copy_artifacts(out: &Path, mode: &str) -> Result<(), String> {
        if mode != "rootfs" {
            let kernel = ["vmlinux", "Image", "bzImage"]
                .iter()
                .map(|n| out.join(n))
                .find(|p| p.is_file())
                .ok_or_else(|| format!("no kernel in {}", out.display()))?;
            copy_deref(&kernel, Path::new("/out/vmlinux"))?;
        }
        if mode != "kernel" {
            let rootfs = out.join("rootfs.ext4");
            if !rootfs.is_file() {
                return Err(format!("no rootfs.ext4 in {}", out.display()));
            }
            copy_deref(&rootfs, Path::new("/out/rootfs.ext4"))?;
            let cmdline = out.join("cmdline.txt");
            if cmdline.is_file() {
                let _ = copy_deref(&cmdline, Path::new("/out/cmdline.txt"));
            }
        }
        Ok(())
    }

    // ---- helpers ----------------------------------------------------------

    fn mount_fs(source: &str, target: &str, fstype: &str) -> Result<(), String> {
        use nix::mount::{MsFlags, mount};
        mount(
            Some(source),
            target,
            Some(fstype),
            MsFlags::empty(),
            None::<&str>,
        )
        .map_err(|e| format!("mount {source} -> {target} ({fstype}): {e}"))
    }

    fn mount_fs_idempotent(source: &str, target: &str, fstype: &str) -> Result<(), String> {
        // The nix seed rootfs is minimal (no /tmp, /run, …) and `mount(2)`
        // needs the target dir to exist — create it first.
        let _ = std::fs::create_dir_all(target);
        match mount_fs(source, target, fstype) {
            Ok(()) => Ok(()),
            Err(e) if e.contains("EBUSY") => {
                eprintln!("stage0-init: {target} ({fstype}) already mounted (EBUSY) — continuing");
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    fn bind_mount(source: &str, target: &str) -> Result<(), String> {
        use nix::mount::{MsFlags, mount};
        mount(
            Some(source),
            target,
            None::<&str>,
            MsFlags::MS_BIND,
            None::<&str>,
        )
        .map_err(|e| format!("bind {source} -> {target}: {e}"))
    }

    fn is_mountpoint(target: &str) -> bool {
        // A path is a mountpoint when its st_dev differs from its parent's.
        let (Ok(here), Some(parent)) = (std::fs::metadata(target), Path::new(target).parent())
        else {
            return false;
        };
        let Ok(up) = std::fs::metadata(parent) else {
            return false;
        };
        use std::os::unix::fs::MetadataExt;
        here.dev() != up.dev()
    }

    fn mknod_null() {
        // mknod /dev/null c 1 3; ignore errors (libkrun may already have it).
        use std::ffi::CString;
        if let Ok(path) = CString::new("/dev/null") {
            // SAFETY: standard char-device node, fixed major/minor 1/3.
            unsafe {
                libc::mknod(path.as_ptr(), libc::S_IFCHR | 0o666, libc::makedev(1, 3));
            }
        }
    }

    /// Glob the seed store for a `*-<pkg>-*/bin/<bin>` executable. Store
    /// paths are hash-prefixed, so we discover rather than hardcode.
    fn find_seed_bin(bin: &str) -> Result<PathBuf, String> {
        let store = Path::new("/nix/store");
        let entries = std::fs::read_dir(store).map_err(|e| format!("read /nix/store: {e}"))?;
        for e in entries.flatten() {
            let cand = e.path().join("bin").join(bin);
            if cand.is_file() {
                return Ok(cand);
            }
        }
        Err(format!(
            "seed store has no bin/{bin} (is the nix tarball seed intact?)"
        ))
    }

    /// Find the seed's CA bundle (`nss-cacert`) for `NIX_SSL_CERT_FILE`.
    fn find_seed_cacert() -> Result<PathBuf, String> {
        let store = Path::new("/nix/store");
        let entries = std::fs::read_dir(store).map_err(|e| format!("read /nix/store: {e}"))?;
        for e in entries.flatten() {
            let name = e.file_name();
            if name.to_string_lossy().contains("nss-cacert") {
                let bundle = e.path().join("etc/ssl/certs/ca-bundle.crt");
                if bundle.is_file() {
                    return Ok(bundle);
                }
            }
        }
        Err("seed store has no nss-cacert ca-bundle.crt".into())
    }

    /// `uname -m` via libc (no coreutils in the seed). aarch64 / x86_64.
    fn machine_arch() -> Result<String, String> {
        let mut uts: libc::utsname = unsafe { std::mem::zeroed() };
        // SAFETY: uname writes into the provided utsname struct.
        if unsafe { libc::uname(&mut uts) } != 0 {
            return Err("uname() failed".into());
        }
        let bytes: Vec<u8> = uts
            .machine
            .iter()
            .take_while(|&&c| c != 0)
            .map(|&c| c as u8)
            .collect();
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }

    /// Minimal `KEY=VALUE` / `KEY="VALUE"` reader for the optional
    /// host-dropped build conf.
    fn read_build_conf(path: &str) -> std::collections::HashMap<String, String> {
        let mut map = std::collections::HashMap::new();
        let Ok(text) = std::fs::read_to_string(path) else {
            return map;
        };
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((k, v)) = line.split_once('=') {
                let v = v.trim().trim_matches('"').trim_matches('\'');
                map.insert(k.trim().to_string(), v.to_string());
            }
        }
        map
    }

    fn stage0_nix_extra_flags(conf: &HashMap<String, String>) -> Result<Vec<String>, String> {
        stage0_nix_extra_flags_with_localized_inputs(conf, Path::new("/nix/stage0-inputs"))
    }

    fn stage0_nix_extra_flags_with_localized_inputs(
        conf: &HashMap<String, String>,
        local_root: &Path,
    ) -> Result<Vec<String>, String> {
        let mut args = Vec::new();
        if truthy_env_value(conf.get("MVM_STAGE0_OFFLINE")) {
            args.push("--offline".to_string());
        }
        let mut override_keys = conf
            .keys()
            .filter(|key| key.starts_with("MVM_STAGE0_OVERRIDE_INPUT_"))
            .cloned()
            .collect::<Vec<_>>();
        override_keys.sort();
        for key in override_keys {
            let value = conf
                .get(&key)
                .ok_or_else(|| format!("{key} disappeared during Stage 0 config read"))?;
            let (input_path, guest_path) = value.split_once('=').ok_or_else(|| {
                format!("invalid {key} value {value:?}; expected <input_path>=<guest_path>")
            })?;
            let localized = localize_override_source_at(local_root, input_path, guest_path)?;
            args.push("--override-input".to_string());
            args.push(input_path.to_string());
            args.push(format!("path:{}", localized.display()));
        }
        Ok(args)
    }

    fn truthy_env_value(value: Option<&String>) -> bool {
        value.is_some_and(|value| matches!(value.trim(), "1" | "true" | "yes" | "on"))
    }

    fn stage0_proxy_env() -> [(&'static str, &'static str); 4] {
        [
            ("HTTPS_PROXY", "http://127.0.0.1:8443"),
            ("HTTP_PROXY", "http://127.0.0.1:8443"),
            ("https_proxy", "http://127.0.0.1:8443"),
            ("http_proxy", "http://127.0.0.1:8443"),
        ]
    }

    fn stage0_nix_config_for_vsock_proxy() -> &'static str {
        "experimental-features = nix-command flakes\n\
         sandbox = false\n\
         build-users-group =\n\
         max-jobs = 1\n\
         cores = 0\n\
         substituters = https://cache.nixos.org/\n\
         trusted-public-keys = cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY="
    }

    fn localize_override_source_at(
        local_root: &Path,
        input_path: &str,
        guest_path: &str,
    ) -> Result<PathBuf, String> {
        let source = Path::new(guest_path);
        if !source.exists() {
            return Err(format!(
                "override input {input_path} source {} does not exist",
                source.display()
            ));
        }

        std::fs::create_dir_all(local_root)
            .map_err(|e| format!("create {}: {e}", local_root.display()))?;
        let target = local_root.join(input_path.replace('/', "__"));
        if target.exists() {
            if target.is_dir() {
                std::fs::remove_dir_all(&target)
                    .map_err(|e| format!("remove {}: {e}", target.display()))?;
            } else {
                std::fs::remove_file(&target)
                    .map_err(|e| format!("remove {}: {e}", target.display()))?;
            }
        }

        if guest_path.ends_with(".tar.gz") {
            extract_tar_gz_strip_root_path(source, &target)?;
        } else if source.is_dir() {
            copy_tree(source, &target)
                .map_err(|e| format!("copy {} -> {}: {e}", source.display(), target.display()))?;
        } else {
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| format!("create {}: {e}", parent.display()))?;
            }
            std::fs::copy(source, &target)
                .map_err(|e| format!("copy {} -> {}: {e}", source.display(), target.display()))?;
        }
        Ok(target)
    }

    fn extract_tar_gz_strip_root_path(src: &Path, dest: &Path) -> Result<(), String> {
        let parent = dest
            .parent()
            .ok_or_else(|| format!("{} has no parent", dest.display()))?;
        std::fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
        let temp = tempfile::tempdir_in(parent)
            .map_err(|e| format!("create tempdir under {}: {e}", parent.display()))?;
        let file = std::fs::File::open(src).map_err(|e| format!("open {}: {e}", src.display()))?;
        let decoder = flate2::read::GzDecoder::new(file);
        let mut archive = tar::Archive::new(decoder);
        archive.unpack(temp.path()).map_err(|e| {
            format!(
                "unpack {} into {}: {e}",
                src.display(),
                temp.path().display()
            )
        })?;
        let mut entries = std::fs::read_dir(temp.path())
            .map_err(|e| format!("read {}: {e}", temp.path().display()))?
            .filter_map(|entry| entry.ok())
            .collect::<Vec<_>>();
        if entries.len() != 1 {
            return Err(format!(
                "expected one top-level directory when unpacking {} into {}, found {}",
                src.display(),
                temp.path().display(),
                entries.len()
            ));
        }
        let extracted = entries.pop().expect("one entry present").path();
        if dest.exists() {
            if dest.is_dir() {
                std::fs::remove_dir_all(dest)
                    .map_err(|e| format!("remove {}: {e}", dest.display()))?;
            } else {
                std::fs::remove_file(dest)
                    .map_err(|e| format!("remove {}: {e}", dest.display()))?;
            }
        }
        std::fs::rename(&extracted, dest)
            .map_err(|e| format!("move {} to {}: {e}", extracted.display(), dest.display()))?;
        Ok(())
    }

    fn copy_deref(src: &Path, dst: &Path) -> Result<(), String> {
        // `cp -L`: follow the store symlink and copy the real file.
        std::fs::copy(src, dst)
            .map(|_| ())
            .map_err(|e| format!("copy {} -> {}: {e}", src.display(), dst.display()))
    }

    fn power_off() -> ExitCode {
        use nix::sys::reboot::{RebootMode, reboot};
        // SAFETY: sync() takes no args and cannot fail.
        unsafe {
            libc::sync();
        }
        match reboot(RebootMode::RB_POWER_OFF) {
            Ok(_) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("stage0-init: reboot syscall failed: {e}");
                ExitCode::FAILURE
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::configure_nix_runtime;
        use super::nix_filesystem_used_kib;
        use super::resolver_seed;
        use super::run_streaming;
        use super::stage0_nix_config_for_vsock_proxy;
        use super::stage0_nix_extra_flags;
        use super::stage0_nix_extra_flags_with_localized_inputs;
        use super::stage0_proxy_env;
        use std::collections::HashMap;
        use std::path::Path;
        use std::process::Command;

        #[test]
        fn streams_stderr_live_keeps_full_log_and_captures_stdout() {
            // Mimic nix: build logs to stderr, the out-path to stdout.
            let mut cmd = Command::new("sh");
            cmd.args([
                "-c",
                "printf 'log1\\nlog2\\n' >&2; printf '/nix/store/abc\\n'",
            ]);
            let mut live: Vec<u8> = Vec::new();
            let (status, stderr_log, stdout) = run_streaming(cmd, &mut live).unwrap();
            assert!(status.success());
            // Echoed live to the console sink…
            assert_eq!(live, b"log1\nlog2\n");
            // …and accumulated for the post-mortem log.
            assert_eq!(stderr_log, b"log1\nlog2\n");
            // out-path captured from stdout.
            assert_eq!(stdout.trim(), "/nix/store/abc");
        }

        #[test]
        fn propagates_nonzero_exit_with_log() {
            let mut cmd = Command::new("sh");
            cmd.args(["-c", "echo boom >&2; exit 7"]);
            let mut live: Vec<u8> = Vec::new();
            let (status, stderr_log, _stdout) = run_streaming(cmd, &mut live).unwrap();
            assert_eq!(status.code(), Some(7));
            assert_eq!(stderr_log, b"boom\n");
        }

        #[test]
        fn resolver_seed_prefers_qemu_builtin_dns() {
            assert_eq!(
                resolver_seed(true, &HashMap::new()).unwrap(),
                b"nameserver 10.0.2.3\n"
            );
        }

        #[test]
        fn configure_nix_runtime_libkrun_leaves_existing_resolver_seed_alone() {
            let tmp = tempfile::tempdir().unwrap();
            let old = std::env::current_dir().unwrap();
            std::env::set_current_dir(tmp.path()).unwrap();
            std::fs::create_dir_all("etc").unwrap();
            std::fs::write("etc/resolv.conf", "nameserver 192.168.127.1\n").unwrap();
            configure_nix_runtime(false, &HashMap::new()).unwrap();
            assert_eq!(
                std::fs::read_to_string("etc/resolv.conf").unwrap(),
                "nameserver 192.168.127.1\n"
            );
            std::env::set_current_dir(old).unwrap();
        }

        #[test]
        fn resolver_seed_uses_host_override_for_libkrun() {
            let mut conf = HashMap::new();
            conf.insert("MVM_STAGE0_RESOLVER".to_string(), "10.10.0.53".to_string());
            assert_eq!(
                resolver_seed(false, &conf).unwrap(),
                b"nameserver 10.10.0.53\n"
            );
        }

        #[test]
        fn resolver_seed_rejects_invalid_host_override() {
            let mut conf = HashMap::new();
            conf.insert("MVM_STAGE0_RESOLVER".to_string(), "not-an-ip".to_string());
            let err = resolver_seed(false, &conf).unwrap_err();
            assert!(err.contains("invalid MVM_STAGE0_RESOLVER"));
        }

        #[test]
        fn stage0_proxy_env_uses_http_connect_only() {
            assert_eq!(
                stage0_proxy_env(),
                [
                    ("HTTPS_PROXY", "http://127.0.0.1:8443"),
                    ("HTTP_PROXY", "http://127.0.0.1:8443"),
                    ("https_proxy", "http://127.0.0.1:8443"),
                    ("http_proxy", "http://127.0.0.1:8443"),
                ]
            );
        }

        #[test]
        fn stage0_nix_config_for_vsock_proxy_disables_inner_sandbox() {
            let config = stage0_nix_config_for_vsock_proxy();
            assert!(config.contains("sandbox = false"));
            assert!(config.contains("build-users-group ="));
            assert!(config.contains("substituters = https://cache.nixos.org/"));
        }

        #[test]
        fn stage0_nix_extra_flags_adds_offline_and_override_inputs() {
            let tmp = tempfile::tempdir().unwrap();
            let source_root = tmp.path().join("source");
            std::fs::create_dir_all(source_root.join("nixpkgs-root")).unwrap();
            std::fs::create_dir_all(source_root.join("microvm-root")).unwrap();
            std::fs::write(source_root.join("nixpkgs-root/flake.nix"), "{}").unwrap();
            std::fs::write(source_root.join("microvm-root/flake.nix"), "{}").unwrap();
            let nixpkgs_archive = source_root.join("nixpkgs.tar.gz");
            let microvm_archive = source_root.join("microvm.tar.gz");
            build_test_archive(
                &source_root.join("nixpkgs-root"),
                &nixpkgs_archive,
                "source",
            );
            build_test_archive(
                &source_root.join("microvm-root"),
                &microvm_archive,
                "source",
            );
            let mut conf = HashMap::new();
            conf.insert("MVM_STAGE0_OFFLINE".to_string(), "1".to_string());
            conf.insert(
                "MVM_STAGE0_OVERRIDE_INPUT_1".to_string(),
                format!("microvm={}", microvm_archive.display()),
            );
            conf.insert(
                "MVM_STAGE0_OVERRIDE_INPUT_0".to_string(),
                format!("nixpkgs={}", nixpkgs_archive.display()),
            );
            let local_root = tmp.path().join("localized");
            assert_eq!(
                stage0_nix_extra_flags_with_localized_inputs(&conf, &local_root).unwrap(),
                vec![
                    "--offline".to_string(),
                    "--override-input".to_string(),
                    "nixpkgs".to_string(),
                    format!("path:{}", local_root.join("nixpkgs").display()),
                    "--override-input".to_string(),
                    "microvm".to_string(),
                    format!("path:{}", local_root.join("microvm").display()),
                ]
            );
            assert!(local_root.join("nixpkgs/flake.nix").is_file());
            assert!(local_root.join("microvm/flake.nix").is_file());
        }

        fn build_test_archive(src: &Path, dest: &Path, root_name: &str) {
            let file = std::fs::File::create(dest).unwrap();
            let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
            let mut archive = tar::Builder::new(encoder);
            archive.append_dir_all(root_name, src).unwrap();
            let encoder = archive.into_inner().unwrap();
            encoder.finish().unwrap();
        }

        #[test]
        fn stage0_nix_extra_flags_rejects_malformed_override() {
            let mut conf = HashMap::new();
            conf.insert(
                "MVM_STAGE0_OVERRIDE_INPUT_0".to_string(),
                "missing-separator".to_string(),
            );
            let err = stage0_nix_extra_flags(&conf).unwrap_err();
            assert!(err.contains("expected <input_path>=<guest_path>"));
        }

        #[test]
        fn nix_filesystem_used_kib_reports_nonzero_usage() {
            let used = nix_filesystem_used_kib(Path::new("/")).unwrap();
            assert!(used > 0);
        }
    }
}
