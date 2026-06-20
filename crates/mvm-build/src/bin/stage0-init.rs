//! PID 1 of the Stage 0 bootstrap VM — the **nix-tarball seed**.
//! Boots under **two** builder backends (selected by the `mvm.backend=qemu`
//! kernel cmdline marker), carrying the official Nix release tarball's
//! `/nix/store` + this binary as `/init` — no Alpine, no apk, no busybox.
//!
//! **libkrun** (macOS/aarch64): the seed root arrives over virtiofs
//! (`krun_set_root`) on libkrunfw's bundled kernel; shares are virtio-fs; we
//! copy the seed `/nix/store` into a tmpfs and bind it over `/nix` (virtiofs
//! writes fail under FUSE); eth0 + DHCP come from libkrun, so we just point
//! `/etc/resolv.conf` at gvproxy's gateway. Proven E2E on aarch64.
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
    use std::path::{Path, PathBuf};
    use std::process::{Command, ExitCode, Stdio};

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
            log_qemu_net_state();
        } else {
            setup_nix_store()?;
        }
        configure_nix_runtime(qemu)?;
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
    fn log_qemu_net_state() {
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

    /// DNS + nix store state the seed rootfs doesn't ship. Neither VMM writes
    /// `/etc/resolv.conf`, so point it at the gateway's resolver — `192.168.127.1`
    /// for libkrun/gvproxy, and QEMU user-mode networking's built-in DNS at
    /// `10.0.2.3` (fixed; no DHCP, no passt). nix needs it to reach
    /// cache.nixos.org. Also seed the local store dirs so nix runs single-user.
    fn configure_nix_runtime(qemu: bool) -> Result<(), String> {
        std::fs::create_dir_all("/etc").map_err(|e| format!("create /etc: {e}"))?;
        let resolver: &[u8] = if qemu {
            b"nameserver 10.0.2.3\n"
        } else {
            b"nameserver 192.168.127.1\n"
        };
        std::fs::write("/etc/resolv.conf", resolver)
            .map_err(|e| format!("write /etc/resolv.conf: {e}"))?;
        for d in ["/nix/var", "/nix/var/nix", "/nix/var/log/nix"] {
            std::fs::create_dir_all(d).map_err(|e| format!("create {d}: {e}"))?;
        }
        Ok(())
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
        // SAFETY: this is PID 1, single-threaded at this point — no other
        // thread can observe a torn environment. `set_var` is `unsafe` in
        // edition 2024 only for that thread-safety reason.
        // CA bundle = HTTPS trust for cache.nixos.org / flake inputs (libkrun
        // gives us DNS; `nss-cacert` from the seed gives the trust roots).
        // PATH = the seed nix's own bin dir (curl/xz/etc. live beside `nix`).
        unsafe {
            std::env::set_var("HOME", "/root");
            std::env::set_var("MVM_WORKSPACE_PATH", "/work");
            std::env::set_var("MVM_HOST_BIN_DIR", "/mvm-bins");
            std::env::set_var("NIX_SSL_CERT_FILE", &cacert);
            // Force single-user (local store) — the seed has no nix-daemon;
            // an empty NIX_REMOTE makes nix build directly as root.
            std::env::set_var("NIX_REMOTE", "");
            if !nix_path.is_empty() {
                std::env::set_var("PATH", nix_path);
            }
        }

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
        let attr = conf
            .get("MVM_STAGE0_BUILD_ATTR")
            .cloned()
            .unwrap_or_else(|| "default".into());
        let mode = conf
            .get("MVM_STAGE0_OUTPUT_MODE")
            .cloned()
            .unwrap_or_else(|| "image".into());
        let arch = machine_arch()?;
        let flake_ref = format!("path:/work/nix/images/builder-vm#packages.{arch}-linux.{attr}");

        eprintln!("stage0-init: building {flake_ref} (output_mode={mode})");
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
        // Echo nix's `--print-build-logs` to the guest's own stderr, which the
        // host captures to `console.log` live — that's what makes the otherwise-
        // silent multi-minute build tailable from the host.
        let (status, stderr_log, stdout) =
            run_streaming(cmd, &mut std::io::stderr()).map_err(|e| format!("nix build: {e}"))?;

        // Persist the full log to /out (a virtio-fs share) for host-side
        // post-mortem at ~/.cache/mvm/builder-vm/.../nix-stderr.log.
        let _ = std::fs::write("/out/nix-stderr.log", &stderr_log);
        if !status.success() {
            return Err(format!("nix build exit {}", status.code().unwrap_or(-1)));
        }
        let store_path = stdout.trim().to_string();
        if store_path.is_empty() {
            return Err("nix build emitted no /nix/store path".into());
        }
        copy_artifacts(Path::new(&store_path), &mode)
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
    /// host-dropped build conf — the host only ever writes two plain
    /// assignments (`MVM_STAGE0_BUILD_ATTR`, `MVM_STAGE0_OUTPUT_MODE`).
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
        use super::run_streaming;
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
    }
}
