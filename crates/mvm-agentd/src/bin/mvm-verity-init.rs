//! Early-userspace verity-init (PID 1 in the verity initramfs).
//!
//! Runs from a tiny initramfs baked by `mkGuest` when
//! `verifiedBoot = true`. The kernel-cmdline `dm-mod.create=` path
//! doesn't work for our microVM hypervisors because Firecracker
//! (and HVF) auto-append `root=/dev/vda ro` to the cmdline on
//! aarch64; the kernel uses last-wins for `root=`, so a verity
//! `root=/dev/dm-0` we set ourselves is silently overridden. We
//! solve that by owning the boot pivot in userspace: this binary
//! mounts an initramfs first, builds the verity device-mapper
//! target via raw ioctls, mounts `/dev/mapper/root` at `/sysroot`,
//! then `switch_root`s to the real init at `/sysroot/init`.
//!
//! Cmdline contract (set by the host's start_vm path):
//!
//!   mvm.roothash=<64-hex>          required; rootfs dm-verity root hash
//!   `mvm.data=<dev-path>`            defaults to /dev/vda
//!   `mvm.hash=<dev-path>`            defaults to /dev/vdb
//!
//!   mvm.runtime_roothash=<64-hex>  optional; mvm runtime overlay
//!                                  dm-verity root hash. When present
//!                                  the init runs a second dm-verity
//!                                  setup and bind-mounts the result
//!                                  read-only at /sysroot/mvm/runtime.
//!                                  Absent: legacy boot path — no
//!                                  overlay attached, /mvm/runtime
//!                                  empty in the guest. The backend
//!                                  wiring threads this arg through;
//!                                  existing Nix-built images that
//!                                  haven't been refactored for the
//!                                  overlay continue to boot unchanged.
//!   `mvm.runtime_data=<dev-path>`    defaults to /dev/vdc
//!   `mvm.runtime_hash=<dev-path>`    defaults to /dev/vdd
//!
//! On any failure this binary panics — kernel re-init isn't safe from
//! PID 1 in the initramfs, and panic'ing surfaces the failure on the
//! console (visible in `firecracker.log`) rather than silently falling
//! back to the unverified rootfs.
//!
//! Linux-only. Builds as a stub on other platforms so the workspace
//! still compiles on macOS. Cmdline parsing lives in the cross-platform
//! [`config`] submodule so the cmdline parser is unit-testable from
//! macOS host builds.

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("mvm-verity-init: Linux-only binary; not buildable on this target");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
fn main() {
    if let Err(e) = linux::run() {
        eprintln!("mvm-verity-init: FATAL: {e}");
        let _ = std::fs::write("/dev/console", format!("mvm-verity-init: FATAL: {e}\n"));
        std::thread::sleep(std::time::Duration::from_millis(200));
        std::process::exit(1);
    }
}

/// Cross-platform cmdline parsing. Lives outside the `linux`
/// submodule so unit tests can exercise it on a macOS host
/// without the Linux-only ioctl scaffolding compiling.
mod config {
    /// Validated dm-verity setup parameters parsed from
    /// `/proc/cmdline`. Constructed by [`Self::parse`]; consumed
    /// by the Linux init flow which builds the dm-mapper target
    /// from these fields.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct VeritySetupConfig {
        /// Rootfs configuration. Always present (the legacy
        /// `mvm.roothash=` arg is the only required cmdline
        /// arg).
        pub rootfs: VerityTargetConfig,
        /// Runtime overlay configuration, if `mvm.runtime_roothash=`
        /// was present. Absent: legacy boot, no overlay mount.
        pub runtime: Option<VerityTargetConfig>,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct VerityTargetConfig {
        pub roothash: String,
        pub data_dev: String,
        pub hash_dev: String,
    }

    impl VeritySetupConfig {
        /// Parse a kernel cmdline (the verbatim contents of
        /// `/proc/cmdline`).
        ///
        /// Fails closed on:
        /// - missing `mvm.roothash=`
        /// - rootfs or runtime roothash that isn't 64 lowercase
        ///   hex chars
        pub fn parse(cmdline: &str) -> Result<Self, String> {
            let mut rootfs_roothash: Option<String> = None;
            let mut rootfs_data = "/dev/vda".to_string();
            let mut rootfs_hash = "/dev/vdb".to_string();
            let mut runtime_roothash: Option<String> = None;
            let mut runtime_data = "/dev/vdc".to_string();
            let mut runtime_hash = "/dev/vdd".to_string();

            for tok in cmdline.split_whitespace() {
                if let Some(v) = tok.strip_prefix("mvm.roothash=") {
                    rootfs_roothash = Some(v.trim_matches('"').to_string());
                } else if let Some(v) = tok.strip_prefix("mvm.data=") {
                    rootfs_data = v.trim_matches('"').to_string();
                } else if let Some(v) = tok.strip_prefix("mvm.hash=") {
                    rootfs_hash = v.trim_matches('"').to_string();
                } else if let Some(v) = tok.strip_prefix("mvm.runtime_roothash=") {
                    runtime_roothash = Some(v.trim_matches('"').to_string());
                } else if let Some(v) = tok.strip_prefix("mvm.runtime_data=") {
                    runtime_data = v.trim_matches('"').to_string();
                } else if let Some(v) = tok.strip_prefix("mvm.runtime_hash=") {
                    runtime_hash = v.trim_matches('"').to_string();
                }
            }

            let rootfs_roothash =
                rootfs_roothash.ok_or_else(|| "no mvm.roothash= on kernel cmdline".to_string())?;
            validate_roothash(&rootfs_roothash, "mvm.roothash")?;

            let runtime = if let Some(rh) = runtime_roothash {
                validate_roothash(&rh, "mvm.runtime_roothash")?;
                Some(VerityTargetConfig {
                    roothash: rh,
                    data_dev: runtime_data,
                    hash_dev: runtime_hash,
                })
            } else {
                None
            };

            Ok(VeritySetupConfig {
                rootfs: VerityTargetConfig {
                    roothash: rootfs_roothash,
                    data_dev: rootfs_data,
                    hash_dev: rootfs_hash,
                },
                runtime,
            })
        }
    }

    fn validate_roothash(rh: &str, name: &str) -> Result<(), String> {
        if rh.len() != 64
            || !rh
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        {
            return Err(format!(
                "invalid {name}={rh:?} (expected 64 lowercase hex chars)"
            ));
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        const FAKE_HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        const FAKE_HASH_2: &str =
            "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

        #[test]
        fn parses_legacy_rootfs_only_cmdline() {
            let cfg =
                VeritySetupConfig::parse(&format!("foo=bar mvm.roothash={FAKE_HASH} baz=qux"))
                    .expect("parse");
            assert_eq!(cfg.rootfs.roothash, FAKE_HASH);
            assert_eq!(cfg.rootfs.data_dev, "/dev/vda");
            assert_eq!(cfg.rootfs.hash_dev, "/dev/vdb");
            assert!(
                cfg.runtime.is_none(),
                "legacy cmdline must yield no runtime config; got {:?}",
                cfg.runtime
            );
        }

        #[test]
        fn parses_runtime_overlay_cmdline() {
            let cfg = VeritySetupConfig::parse(&format!(
                "mvm.roothash={FAKE_HASH} mvm.runtime_roothash={FAKE_HASH_2}"
            ))
            .expect("parse");
            assert_eq!(cfg.rootfs.roothash, FAKE_HASH);
            let runtime = cfg.runtime.expect("runtime config present");
            assert_eq!(runtime.roothash, FAKE_HASH_2);
            assert_eq!(runtime.data_dev, "/dev/vdc");
            assert_eq!(runtime.hash_dev, "/dev/vdd");
        }

        #[test]
        fn parses_overridden_device_paths_for_both_targets() {
            let cfg = VeritySetupConfig::parse(&format!(
                "mvm.roothash={FAKE_HASH} mvm.data=/dev/sda1 mvm.hash=/dev/sda2 \
                 mvm.runtime_roothash={FAKE_HASH_2} mvm.runtime_data=/dev/sda3 mvm.runtime_hash=/dev/sda4"
            ))
            .expect("parse");
            assert_eq!(cfg.rootfs.data_dev, "/dev/sda1");
            assert_eq!(cfg.rootfs.hash_dev, "/dev/sda2");
            let runtime = cfg.runtime.unwrap();
            assert_eq!(runtime.data_dev, "/dev/sda3");
            assert_eq!(runtime.hash_dev, "/dev/sda4");
        }

        #[test]
        fn rejects_missing_rootfs_roothash() {
            let err = VeritySetupConfig::parse("foo=bar baz=qux").unwrap_err();
            assert!(err.contains("mvm.roothash"), "{err}");
        }

        #[test]
        fn rejects_short_rootfs_roothash() {
            let err = VeritySetupConfig::parse("mvm.roothash=abc").unwrap_err();
            assert!(err.contains("64"), "{err}");
        }

        #[test]
        fn rejects_uppercase_rootfs_roothash() {
            let upper = "ABCDEF0123456789".repeat(4);
            let err = VeritySetupConfig::parse(&format!("mvm.roothash={upper}")).unwrap_err();
            assert!(err.contains("lowercase"), "{err}");
        }

        #[test]
        fn rejects_short_runtime_roothash() {
            let err = VeritySetupConfig::parse(&format!(
                "mvm.roothash={FAKE_HASH} mvm.runtime_roothash=abc"
            ))
            .unwrap_err();
            assert!(err.contains("mvm.runtime_roothash"), "{err}");
        }

        #[test]
        fn rejects_uppercase_runtime_roothash() {
            let upper = "ABCDEF0123456789".repeat(4);
            let err = VeritySetupConfig::parse(&format!(
                "mvm.roothash={FAKE_HASH} mvm.runtime_roothash={upper}"
            ))
            .unwrap_err();
            assert!(err.contains("lowercase"), "{err}");
        }

        #[test]
        fn handles_quoted_values_for_legacy_rootfs() {
            // The legacy code stripped `"` from values to handle
            // quoted cmdline args. Keep that behaviour for both
            // legacy and new args.
            let cfg = VeritySetupConfig::parse(&format!(
                "mvm.roothash=\"{FAKE_HASH}\" mvm.data=\"/dev/vda\""
            ))
            .expect("parse");
            assert_eq!(cfg.rootfs.roothash, FAKE_HASH);
            assert_eq!(cfg.rootfs.data_dev, "/dev/vda");
        }

        #[test]
        fn handles_quoted_values_for_runtime_overlay() {
            let cfg = VeritySetupConfig::parse(&format!(
                "mvm.roothash={FAKE_HASH} mvm.runtime_roothash=\"{FAKE_HASH_2}\""
            ))
            .expect("parse");
            assert_eq!(cfg.runtime.unwrap().roothash, FAKE_HASH_2);
        }

        #[test]
        fn ignores_unrelated_kernel_args() {
            // Cmdline carries lots of unrelated args
            // (console=hvc0, init=…, etc.). Parser must not
            // trip on them.
            let cfg = VeritySetupConfig::parse(&format!(
                "console=hvc0 root=/dev/vda ro init=/sbin/init \
                 mvm.roothash={FAKE_HASH} mvm.runtime_roothash={FAKE_HASH_2} \
                 random.trust_cpu=on"
            ))
            .expect("parse");
            assert_eq!(cfg.rootfs.roothash, FAKE_HASH);
            assert_eq!(cfg.runtime.unwrap().roothash, FAKE_HASH_2);
        }

        #[test]
        fn handles_empty_cmdline() {
            assert!(VeritySetupConfig::parse("").is_err());
        }

        #[cfg(target_os = "linux")]
        #[test]
        fn hash_start_block_uses_superblock_when_sidecar_has_extra_block() {
            let data_blocks = 9_448;
            let hash_dev_size = 76 * 4_096;
            assert_eq!(
                crate::linux::choose_hash_start_block(data_blocks, hash_dev_size)
                    .expect("hash start block"),
                1
            );
        }

        #[cfg(target_os = "linux")]
        #[test]
        fn hash_start_block_accepts_no_superblock_sidecars() {
            let data_blocks = 9_448;
            let hash_dev_size = 75 * 4_096;
            assert_eq!(
                crate::linux::choose_hash_start_block(data_blocks, hash_dev_size)
                    .expect("hash start block"),
                0
            );
        }

        #[cfg(target_os = "linux")]
        #[test]
        fn hash_start_block_rejects_truncated_sidecars() {
            let data_blocks = 9_448;
            let hash_dev_size = 74 * 4_096;
            let err =
                crate::linux::choose_hash_start_block(data_blocks, hash_dev_size).unwrap_err();
            assert!(err.contains("hash device too small"), "{err}");
        }
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::ffi::CString;
    use std::fs;
    use std::io;
    use std::os::fd::AsRawFd;
    use std::path::Path;

    // ── DM ioctl constants and structs (mirror /usr/include/linux/dm-ioctl.h)
    //
    // The kernel header lives in `linux-libc-dev`; we don't pull
    // bindgen/headers into the guest closure. Hand-coded constants
    // are fine here — DM ioctl is a stable kernel ABI.

    const DM_VERSION_MAJOR: u32 = 4;
    const DM_VERSION_MINOR: u32 = 0;
    const DM_VERSION_PATCH: u32 = 0;

    const DM_NAME_LEN: usize = 128;
    const DM_UUID_LEN: usize = 129;
    // After the fixed fields, dm_ioctl includes 7 bytes of `data` for
    // padding/early data; we keep that shape so ioctls match the
    // kernel struct layout.
    const DM_DATA_LEN: usize = 7;

    const DM_READONLY_FLAG: u32 = 1 << 0;
    const DM_EXISTS_FLAG: u32 = 1 << 2;

    // Command numbers from the enum at /usr/include/linux/dm-ioctl.h.
    const DM_VERSION_CMD: u32 = 0;
    const DM_DEV_CREATE_CMD: u32 = 3;
    const DM_DEV_SUSPEND_CMD: u32 = 6;
    const DM_TABLE_LOAD_CMD: u32 = 9;

    const DM_IOCTL: u32 = 0xfd;
    // _IOWR(0xfd, n, struct dm_ioctl): the libc helpers don't expose
    // _IOWR cleanly so we inline the value. Direction=3, size=312
    // (sizeof(struct dm_ioctl) on 64-bit Linux).
    const DM_IOCTL_STRUCT_SIZE: u32 = 312;
    fn iowr(nr: u32) -> u64 {
        // ((dir << 30) | (size << 16) | (type << 8) | nr)
        // dir=3 (IOC_READ|IOC_WRITE), size=DM_IOCTL_STRUCT_SIZE.
        // Returns u64 because the request value is wider on glibc
        // (c_ulong = u64) than on musl (c_int = i32) — we cast at
        // the ioctl call site to whatever libc says is correct.
        ((3u32 << 30) | (DM_IOCTL_STRUCT_SIZE << 16) | (DM_IOCTL << 8) | nr) as u64
    }

    // `[u8; 129]` doesn't auto-derive Default; we provide one by hand
    // so `..Default::default()` works on the call sites below.
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct DmIoctl {
        version: [u32; 3],
        data_size: u32,
        data_start: u32,
        target_count: u32,
        open_count: i32,
        flags: u32,
        event_nr: u32,
        padding: u32,
        dev: u64,
        name: [u8; DM_NAME_LEN],
        uuid: [u8; DM_UUID_LEN],
        data: [u8; DM_DATA_LEN],
    }

    impl Default for DmIoctl {
        fn default() -> Self {
            Self {
                version: [0; 3],
                data_size: 0,
                data_start: 0,
                target_count: 0,
                open_count: 0,
                flags: 0,
                event_nr: 0,
                padding: 0,
                dev: 0,
                name: [0; DM_NAME_LEN],
                uuid: [0; DM_UUID_LEN],
                data: [0; DM_DATA_LEN],
            }
        }
    }

    // The fixed-payload ioctls report `data_size = DM_IOCTL_STRUCT_SIZE` and
    // the kernel reads/writes exactly that many bytes from the header. Pin the
    // constant to the real struct size so the `dm_ioctl_fixed` soundness
    // argument (a `&mut DmIoctl` fully backs the access) can't silently rot if
    // the layout changes.
    //
    // The offsets extend that to the field level: this is the struct the
    // dm-verity table is built from on the verified-boot path, so drift is a
    // verity setup failure reported as an unrelated errno. Derived on Linux
    // 6.8 from linux/dm-ioctl.h with cc sizeof/offsetof/_Alignof, not read
    // off the Rust definition.
    const _: () = {
        use std::mem::{align_of, offset_of, size_of};

        assert!(DM_IOCTL_STRUCT_SIZE as usize == size_of::<DmIoctl>());
        assert!(size_of::<DmIoctl>() == 312);
        assert!(align_of::<DmIoctl>() == 8);
        assert!(offset_of!(DmIoctl, version) == 0);
        assert!(offset_of!(DmIoctl, data_size) == 12);
        assert!(offset_of!(DmIoctl, data_start) == 16);
        assert!(offset_of!(DmIoctl, target_count) == 20);
        assert!(offset_of!(DmIoctl, dev) == 40);
        assert!(offset_of!(DmIoctl, name) == 48);
    };

    #[repr(C)]
    struct DmTargetSpec {
        sector_start: u64,
        length: u64,
        status: i32,
        next: u32,
        target_type: [u8; 16],
        // followed by NUL-terminated parameter string + alignment padding
    }

    const _: () = {
        use std::mem::{align_of, offset_of, size_of};

        assert!(size_of::<DmTargetSpec>() == 40);
        assert!(align_of::<DmTargetSpec>() == 8);
        assert!(offset_of!(DmTargetSpec, sector_start) == 0);
        assert!(offset_of!(DmTargetSpec, length) == 8);
        assert!(offset_of!(DmTargetSpec, status) == 16);
        assert!(offset_of!(DmTargetSpec, next) == 20);
        assert!(offset_of!(DmTargetSpec, target_type) == 24);
    };

    pub fn run() -> Result<(), String> {
        msg("mvm-verity-init: starting");

        // ── 1. Mount /proc + /dev so we can read the cmdline and create
        //    block-device nodes if missing. The initramfs ships these
        //    as empty directories.
        do_mount("proc", "/proc", "proc", 0, "")?;
        do_mount("devtmpfs", "/dev", "devtmpfs", 0, "")?;

        // ── 2. Parse /proc/cmdline for the verity parameters.
        // Cross-platform parser lives in `crate::config`; this
        // block just consumes its result.
        let cmdline =
            fs::read_to_string("/proc/cmdline").map_err(|e| format!("read /proc/cmdline: {e}"))?;
        let cfg = crate::config::VeritySetupConfig::parse(&cmdline)?;
        let roothash = &cfg.rootfs.roothash;
        let data_dev = &cfg.rootfs.data_dev;
        let hash_dev = &cfg.rootfs.hash_dev;
        msg(&format!(
            "mvm-verity-init: rootfs data={data_dev} hash={hash_dev} roothash={}…",
            &roothash[..12]
        ));
        if let Some(rt) = cfg.runtime.as_ref() {
            msg(&format!(
                "mvm-verity-init: overlay data={} hash={} roothash={}…",
                rt.data_dev,
                rt.hash_dev,
                &rt.roothash[..12]
            ));
        }

        // ── 3. Compute the verity table line(s).
        //
        //   <start> <num-sectors> verity 1 <data-dev> <hash-dev>
        //          <data-block-size> <hash-block-size>
        //          <num-data-blocks> <hash-start-block>
        //          <algo> <root-hash> <salt>
        //
        // Salt is zero (matches mkGuest's pinned `--salt=00…00`).
        //
        // `data-block-size` comes from the ext4 superblock on the data
        // device. Older sealed images and the runtime overlay still use
        // 1 KiB blocks, while the newer in-process OCI rootfs path emits
        // 4 KiB ext4 blocks. The guest must reconstruct the verity table
        // from the image's actual on-disk geometry, not a baked constant.
        // The hash tree itself stays at 4 KiB because that's the typical
        // veritysetup default and gives a reasonable fan-out.
        //
        // `hash_start_block` depends on the sidecar layout. `veritysetup format`
        // writes a 512-byte verity superblock at offset 0 and puts the Merkle
        // tree at block 1; the pure in-process path writes the no-superblock
        // layout and starts the tree at block 0. We detect which artifact we
        // have from the hash-device geometry so both cached layouts boot.
        // ── 4. Open /dev/mapper/control (auto-created by devtmpfs).
        let ctrl = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/mapper/control")
            .map_err(|e| format!("open /dev/mapper/control: {e}"))?;
        let fd = ctrl.as_raw_fd();

        // 4a. DM_VERSION — sanity-check the kernel speaks the same protocol.
        let mut io = base_ioctl();
        dm_ioctl_fixed(fd, DM_VERSION_CMD, &mut io).map_err(|e| format!("DM_VERSION: {e}"))?;
        msg(&format!(
            "mvm-verity-init: dm-ioctl kernel version {}.{}.{}",
            io.version[0], io.version[1], io.version[2]
        ));

        // 4b-d. Set up the rootfs verity target (name="root").
        setup_verity_target(fd, "root", data_dev, hash_dev, roothash)?;

        // ── 5. Mount /dev/mapper/root at /sysroot. The initramfs ships
        //    /sysroot as an empty mount target. Read-only — verity is
        //    incompatible with writes.
        let root_dm = resolved_dm_device("root")?;
        do_mount(&root_dm, "/sysroot", "ext4", libc::MS_RDONLY, "")?;
        msg("mvm-verity-init: /sysroot mounted (verity-protected)");

        // ── 5b. mvm runtime overlay disk. When the backend has
        //    threaded `mvm.runtime_roothash=` through the cmdline,
        //    set up the second dm-verity target and mount it RO at
        //    /sysroot/mvm/runtime. The target path MUST exist
        //    in the rootfs (the mkGuest refactor creates it as an
        //    empty dir); a missing dir surfaces as a mount-time
        //    EACCES that's actionable.
        //
        //    Absent `mvm.runtime_roothash=` → legacy boot path,
        //    no overlay attached, /mvm/runtime stays empty in
        //    the guest. Existing Nix-built images boot unchanged
        //    through this branch until the backend starts
        //    populating the cmdline arg.
        if let Some(rt) = cfg.runtime.as_ref() {
            setup_verity_target(fd, "runtime", &rt.data_dev, &rt.hash_dev, &rt.roothash)?;
            let runtime_dm = resolved_dm_device("runtime")?;
            do_mount(
                &runtime_dm,
                "/sysroot/mvm/runtime",
                "ext4",
                libc::MS_RDONLY,
                "",
            )?;
            msg("mvm-verity-init: /sysroot/mvm/runtime mounted (verity-protected overlay)");
        }

        // ── 6. Move /proc and /dev into /sysroot so the real init has
        //    them already, then switch_root to /sysroot/init.
        for (src, dst) in [("/proc", "/sysroot/proc"), ("/dev", "/sysroot/dev")] {
            // Best-effort: real init can re-mount if these don't exist
            // in the rootfs (the minimal-init script already does).
            let _ = fs::create_dir_all(dst);
            if let Err(e) = move_mount(src, dst) {
                msg(&format!(
                    "mvm-verity-init: warn: move-mount {src} → {dst}: {e}"
                ));
            }
        }

        // chdir to /sysroot, mount-move it onto /, then exec /init.
        // This is the canonical switch_root(8) sequence.
        do_chdir("/sysroot")?;
        do_mount(".", "/", "", libc::MS_MOVE, "")?;
        do_chroot(".")?;
        do_chdir("/")?;

        msg("mvm-verity-init: switching to /init");
        run_init("/init", &["/init"])?;
        unreachable!("exec returned without error");
    }

    // ────────── helpers ──────────

    fn msg(s: &str) {
        // Console writes: best-effort. The initramfs may not have
        // /dev/console mounted before we mount /dev (step 1).
        let _ = fs::write("/dev/console", format!("{s}\n"));
        let _ = io::Write::flush(&mut io::stderr());
        eprintln!("{s}");
    }

    fn base_ioctl() -> DmIoctl {
        let mut io = DmIoctl {
            version: [DM_VERSION_MAJOR, DM_VERSION_MINOR, DM_VERSION_PATCH],
            data_size: DM_IOCTL_STRUCT_SIZE,
            data_start: 0,
            ..Default::default()
        };
        // data_start and data_size are recomputed for variable-payload
        // commands (TABLE_LOAD); fixed-payload commands keep
        // data_size = sizeof(DmIoctl) and data_start = 0.
        io.flags = DM_EXISTS_FLAG;
        io
    }

    fn write_name(buf: &mut [u8; DM_NAME_LEN], s: &str) {
        let bytes = s.as_bytes();
        let n = bytes.len().min(DM_NAME_LEN - 1);
        buf[..n].copy_from_slice(&bytes[..n]);
        buf[n] = 0;
    }

    /// Run the canonical four-ioctl sequence (DEV_CREATE → TABLE_LOAD →
    /// DEV_SUSPEND-with-flags-cleared) to register and activate one
    /// dm-verity target named `device_name` over `data_dev` + `hash_dev`
    /// with the given `roothash`. After this returns, the kernel has
    /// either `/dev/mapper/<name>` (when udev or a similar daemon is
    /// around) or `/dev/dm-<index>` (initramfs without udev — see
    /// [`resolved_dm_device`]).
    ///
    /// Parameters are pinned to the values the rest of the boot path
    /// expects:
    ///
    /// - `data-block-size` — probed from the ext4 superblock on the data
    ///   device so both older 1 KiB-block images and newer 4 KiB-block
    ///   OCI rootfs images boot correctly.
    /// - `hash-block-size = 4096` — veritysetup default.
    /// - `hash_start_block = 1` when the sidecar carries the verity
    ///   superblock in block 0, else `0` for the no-superblock
    ///   layout the in-process builder emits.
    /// - `algorithm = sha256`, `salt = 64 hex zeros` — match
    ///   `mvm_fs::oci_to_rootfs::verity::VeritysetupOptions::default()`.
    fn setup_verity_target(
        fd: i32,
        device_name: &str,
        data_dev: &str,
        hash_dev: &str,
        roothash: &str,
    ) -> Result<(), String> {
        const HASH_BLOCK_SIZE: u64 = 4096;
        let data_block_size = probe_ext4_block_size(data_dev)?;
        let data_size = block_device_size(data_dev)?;
        let hash_size = block_device_size(hash_dev)?;
        if !data_size.is_multiple_of(data_block_size) {
            return Err(format!(
                "{device_name}: data device {data_dev} size {data_size} not multiple of {data_block_size}"
            ));
        }
        let data_blocks = data_size / data_block_size;
        let num_sectors = data_blocks * (data_block_size / 512);
        let hash_start_block = choose_hash_start_block(data_blocks, hash_size)?;
        let salt = "0".repeat(64);
        let table_args = format!(
            "1 {data_dev} {hash_dev} {data_block_size} {HASH_BLOCK_SIZE} {data_blocks} {hash_start_block} sha256 {roothash} {salt}"
        );
        msg(&format!(
            "mvm-verity-init: {device_name} verity table = {num_sectors} sectors, {data_blocks} data blocks, data_block_size={data_block_size}"
        ));
        if hash_start_block == 0 {
            msg(&format!(
                "mvm-verity-init: {device_name} sidecar has no verity superblock; using hash_start_block=0"
            ));
        }

        // DM_DEV_CREATE — register the device by name (no table yet).
        let mut io = base_ioctl();
        write_name(&mut io.name, device_name);
        dm_ioctl_fixed(fd, DM_DEV_CREATE_CMD, &mut io)
            .map_err(|e| format!("DM_DEV_CREATE({device_name}): {e}"))?;
        msg(&format!("mvm-verity-init: DM_DEV_CREATE({device_name}) ok"));

        // DM_TABLE_LOAD — push the verity target into the inactive table.
        // `build_table_payload` already sets DM_READONLY_FLAG in the header
        // bytes, so we pass the buffer straight to the kernel — no typed
        // deref through the (only u8-aligned) `Vec` pointer is needed.
        let payload = build_table_payload(device_name, num_sectors, "verity", &table_args)?;
        let mut buf = vec![0u8; payload.len()];
        buf.copy_from_slice(&payload);
        let header_ptr = buf.as_mut_ptr().cast::<DmIoctl>();
        // SAFETY: `header_ptr` is the start of `buf`, whose bytes are the
        // header + target-spec + params payload `build_table_payload` wrote;
        // its `data_size` field spans the whole buffer, bounding the kernel's
        // copy. The kernel copies bytes from userspace, so the u8-aligned
        // pointer is a valid ioctl argument. `fd` is the open control fd.
        unsafe {
            do_ioctl(fd, iowr(DM_TABLE_LOAD_CMD), header_ptr)
                .map_err(|e| format!("DM_TABLE_LOAD({device_name}): {e}"))?;
        }
        msg(&format!("mvm-verity-init: DM_TABLE_LOAD({device_name}) ok"));

        // DM_DEV_SUSPEND with flags=0 → resume = activate the loaded table.
        let mut io = base_ioctl();
        write_name(&mut io.name, device_name);
        dm_ioctl_fixed(fd, DM_DEV_SUSPEND_CMD, &mut io)
            .map_err(|e| format!("DM_DEV_SUSPEND(resume, {device_name}): {e}"))?;
        msg(&format!("mvm-verity-init: dm-verity {device_name} active"));
        Ok(())
    }

    pub(super) fn choose_hash_start_block(data_blocks: u64, hash_size: u64) -> Result<u64, String> {
        const HASH_BLOCK_SIZE: u64 = 4096;
        if !hash_size.is_multiple_of(HASH_BLOCK_SIZE) {
            return Err(format!(
                "hash device size {hash_size} is not a multiple of {HASH_BLOCK_SIZE}"
            ));
        }
        let hash_blocks = hash_size / HASH_BLOCK_SIZE;
        let tree_blocks = verity_tree_block_count(data_blocks, HASH_BLOCK_SIZE);
        if hash_blocks > tree_blocks {
            Ok(1)
        } else if hash_blocks >= tree_blocks {
            Ok(0)
        } else {
            Err(format!(
                "hash device too small: need at least {tree_blocks} hash blocks for {data_blocks} data blocks, got {hash_blocks}"
            ))
        }
    }

    fn verity_tree_block_count(data_blocks: u64, hash_block_size: u64) -> u64 {
        const DIGEST_SIZE: u64 = 32;
        let hashes_per_block = hash_block_size / DIGEST_SIZE;
        let mut level_hashes = data_blocks.max(1);
        let mut total_blocks = 0;
        loop {
            let level_blocks = level_hashes.div_ceil(hashes_per_block).max(1);
            total_blocks += level_blocks;
            if level_blocks == 1 {
                return total_blocks;
            }
            level_hashes = level_blocks;
        }
    }

    /// Resolve the device path for a freshly-created dm-verity
    /// target named `name`. Prefer `/dev/mapper/<name>` (set up
    /// by udev when available); otherwise look up the dynamic
    /// `/dev/dm-<minor>` node by scanning `/sys/block/dm-*/dm/name`.
    /// The minor is not predictable from creation order when earlier
    /// targets are absent, so the name-based lookup is required.
    fn resolved_dm_device(name: &str) -> Result<String, String> {
        let mapper = format!("/dev/mapper/{name}");
        if Path::new(&mapper).exists() {
            return Ok(mapper);
        }
        let sys_block = Path::new("/sys/block");
        let entries = match std::fs::read_dir(sys_block) {
            Ok(e) => e,
            Err(e) => return Err(format!("read /sys/block: {e}")),
        };
        for entry in entries {
            let entry = match entry {
                Ok(e) => e,
                Err(e) => return Err(format!("read /sys/block entry: {e}")),
            };
            let fname = entry.file_name();
            let fname = fname.to_string_lossy();
            if !fname.starts_with("dm-") {
                continue;
            }
            let name_file = entry.path().join("dm/name");
            let dm_name = match std::fs::read_to_string(&name_file) {
                Ok(n) => n,
                Err(_) => continue,
            };
            if dm_name.trim() == name {
                return Ok(format!("/dev/{fname}"));
            }
        }
        Err(format!(
            "no /sys/block/dm-* device named {name} after DM_DEV_SUSPEND"
        ))
    }

    /// Construct a DM_TABLE_LOAD payload: a `DmIoctl` header followed by a
    /// `DmTargetSpec` and the parameter string. Alignment to 8 bytes is
    /// required between successive `dm_target_spec`s; we have only one
    /// target so we pad once.
    fn build_table_payload(
        device_name: &str,
        sectors: u64,
        target_type: &str,
        params: &str,
    ) -> Result<Vec<u8>, String> {
        use std::mem::size_of;
        let header_size = size_of::<DmIoctl>();
        let spec_size = size_of::<DmTargetSpec>();
        // Parameter string is NUL-terminated, then padded to 8-byte
        // alignment for the next spec (we have only one, so padding
        // to total alignment is what matters).
        let params_nul = params.len() + 1;
        let total_unaligned = header_size + spec_size + params_nul;
        let aligned_total = total_unaligned.div_ceil(8) * 8;

        let mut buf = vec![0u8; aligned_total];

        // Header.
        let header = DmIoctl {
            version: [DM_VERSION_MAJOR, DM_VERSION_MINOR, DM_VERSION_PATCH],
            data_size: aligned_total as u32,
            data_start: header_size as u32,
            target_count: 1,
            open_count: 0,
            flags: DM_EXISTS_FLAG | DM_READONLY_FLAG,
            event_nr: 0,
            padding: 0,
            dev: 0,
            name: {
                let mut n = [0u8; DM_NAME_LEN];
                write_name(&mut n, device_name);
                n
            },
            uuid: [0u8; DM_UUID_LEN],
            data: [0u8; DM_DATA_LEN],
        };
        // SAFETY: `header` is a live `DmIoctl`, so the source is valid for
        // `header_size` bytes; `buf` is `aligned_total >= header_size` bytes,
        // so the destination is too. The stack value and the heap buffer are
        // distinct allocations, and a byte copy imposes no alignment.
        unsafe {
            std::ptr::copy_nonoverlapping(
                (&header as *const DmIoctl).cast::<u8>(),
                buf.as_mut_ptr(),
                header_size,
            );
        }

        // Target spec.
        let mut tt = [0u8; 16];
        let n = target_type.len().min(15);
        tt[..n].copy_from_slice(&target_type.as_bytes()[..n]);
        let spec = DmTargetSpec {
            sector_start: 0,
            length: sectors,
            status: 0,
            // `next` = bytes from this spec to the next; with one
            // target it's the offset to end-of-payload (kernel uses
            // it to seek; setting to total - data_start is canonical).
            next: (aligned_total - header_size) as u32,
            target_type: tt,
        };
        // SAFETY: `spec` is a live `DmTargetSpec`, valid for `spec_size`
        // bytes; `buf` reserves `header_size + spec_size + params_nul` bytes,
        // so the region at offset `header_size` holds `spec_size` bytes
        // in-bounds. Distinct allocations; a byte copy needs no alignment.
        unsafe {
            std::ptr::copy_nonoverlapping(
                (&spec as *const DmTargetSpec).cast::<u8>(),
                buf.as_mut_ptr().add(header_size),
                spec_size,
            );
        }

        // Parameter string + NUL.
        let params_off = header_size + spec_size;
        buf[params_off..params_off + params.len()].copy_from_slice(params.as_bytes());
        buf[params_off + params.len()] = 0;

        if aligned_total > u32::MAX as usize {
            return Err("verity payload exceeds u32".to_string());
        }
        Ok(buf)
    }

    fn block_device_size(path: &str) -> Result<u64, String> {
        // BLKGETSIZE64 = _IOR(0x12, 114, size_t) = 0x80081272 on 64-bit Linux.
        // libc::Ioctl is c_ulong on glibc and c_int on musl; we cast
        // to libc::Ioctl at the call site so both build.
        const BLKGETSIZE64: u64 = 0x80081272;
        let f = fs::File::open(path).map_err(|e| format!("open {path}: {e}"))?;
        let mut size: u64 = 0;
        // SAFETY: `f` is an open file for `path`; BLKGETSIZE64 writes one
        // `u64` into `size`, a live, aligned out-param valid for the call.
        let rc = unsafe { libc::ioctl(f.as_raw_fd(), BLKGETSIZE64 as libc::Ioctl, &mut size) };
        if rc != 0 {
            return Err(format!(
                "BLKGETSIZE64 on {path}: {}",
                io::Error::last_os_error()
            ));
        }
        Ok(size)
    }

    fn probe_ext4_block_size(path: &str) -> Result<u64, String> {
        const SUPERBLOCK_OFFSET: u64 = 1024;
        const LOG_BLOCK_SIZE_OFFSET: usize = 0x18;
        const MAGIC_OFFSET: usize = 0x38;
        const EXT4_SUPER_MAGIC: u16 = 0xef53;

        let file = fs::File::open(path).map_err(|e| format!("open {path}: {e}"))?;
        let mut superblock = [0u8; 1024];
        std::os::unix::fs::FileExt::read_exact_at(&file, &mut superblock, SUPERBLOCK_OFFSET)
            .map_err(|e| format!("read ext4 superblock from {path}: {e}"))?;

        let magic = u16::from_le_bytes([superblock[MAGIC_OFFSET], superblock[MAGIC_OFFSET + 1]]);
        if magic != EXT4_SUPER_MAGIC {
            return Err(format!(
                "{path} ext4 superblock magic mismatch: expected 0x{EXT4_SUPER_MAGIC:04x}, got 0x{magic:04x}"
            ));
        }

        let log_block_size = u32::from_le_bytes(
            superblock[LOG_BLOCK_SIZE_OFFSET..LOG_BLOCK_SIZE_OFFSET + 4]
                .try_into()
                .map_err(|_| format!("parse ext4 log block size from {path}"))?,
        );
        if log_block_size > 6 {
            return Err(format!(
                "{path} ext4 log block size {log_block_size} is out of range"
            ));
        }

        Ok(1024u64 << log_block_size)
    }

    /// Issue a device-mapper ioctl on the `/dev/mapper/control` fd.
    ///
    /// # Safety
    ///
    /// `fd` must be an open file descriptor for `/dev/mapper/control`, and
    /// `arg` must point to an initialized value laid out as `request`
    /// expects: a `DmIoctl` header whose `data_size` field covers every byte
    /// the kernel reads or writes — the fixed struct for VERSION/CREATE/
    /// SUSPEND, or the header + target-spec + params payload for TABLE_LOAD.
    /// The pointee must stay valid for the duration of the call.
    unsafe fn do_ioctl<T>(fd: libc::c_int, request: u64, arg: *mut T) -> Result<i32, String> {
        // SAFETY: the caller upholds the fd/arg contract above; `request`
        // encodes the size the kernel copies. The Ioctl-type discrepancy is
        // the same as block_device_size — cast at the boundary to whatever
        // libc says is correct for this target.
        let rc = unsafe { libc::ioctl(fd, request as libc::Ioctl, arg) };
        if rc < 0 {
            return Err(io::Error::last_os_error().to_string());
        }
        Ok(rc)
    }

    /// Safe wrapper for the fixed-payload dm ioctls (VERSION, DEV_CREATE,
    /// DEV_SUSPEND). For these the kernel reads and writes exactly
    /// `size_of::<DmIoctl>()` bytes — `base_ioctl` sets `data_size =
    /// DM_IOCTL_STRUCT_SIZE`, pinned equal to the struct size by the
    /// `const _` assertion above — so a `&mut DmIoctl` fully backs the access.
    fn dm_ioctl_fixed(fd: i32, cmd: u32, io: &mut DmIoctl) -> Result<(), String> {
        // SAFETY: `fd` is the open /dev/mapper/control descriptor; `io` is a
        // live, aligned `DmIoctl` whose `data_size` bounds the kernel's access
        // to the struct itself.
        unsafe { do_ioctl(fd, iowr(cmd), io as *mut DmIoctl) }?;
        Ok(())
    }

    fn do_mount(
        source: &str,
        target: &str,
        fstype: &str,
        flags: libc::c_ulong,
        data: &str,
    ) -> Result<(), String> {
        // Best-effort: target may not exist if we forgot to bake it
        // into the initramfs; create it.
        let _ = fs::create_dir_all(target);
        let src = CString::new(source).map_err(|_| "source has NUL".to_string())?;
        let tgt = CString::new(target).map_err(|_| "target has NUL".to_string())?;
        let typ = CString::new(fstype).map_err(|_| "fstype has NUL".to_string())?;
        let dat = CString::new(data).map_err(|_| "data has NUL".to_string())?;
        // SAFETY: all four arguments are NUL-terminated C strings whose
        // backing CStrings live to the end of this function; libc::mount reads
        // them and does not retain them past the call.
        let rc = unsafe {
            libc::mount(
                src.as_ptr(),
                tgt.as_ptr(),
                typ.as_ptr(),
                flags,
                dat.as_ptr().cast(),
            )
        };
        if rc != 0 {
            return Err(format!(
                "mount({source} → {target}, {fstype}): {}",
                io::Error::last_os_error()
            ));
        }
        Ok(())
    }

    fn move_mount(src: &str, dst: &str) -> Result<(), String> {
        do_mount(src, dst, "", libc::MS_MOVE, "")
    }

    fn do_chdir(path: &str) -> Result<(), String> {
        let p = CString::new(path).map_err(|_| "chdir path has NUL".to_string())?;
        // SAFETY: `p` is a valid NUL-terminated C string that outlives the call.
        let rc = unsafe { libc::chdir(p.as_ptr()) };
        if rc != 0 {
            return Err(format!("chdir({path}): {}", io::Error::last_os_error()));
        }
        Ok(())
    }

    fn do_chroot(path: &str) -> Result<(), String> {
        let p = CString::new(path).map_err(|_| "chroot path has NUL".to_string())?;
        // SAFETY: `p` is a valid NUL-terminated C string that outlives the call.
        let rc = unsafe { libc::chroot(p.as_ptr()) };
        if rc != 0 {
            return Err(format!("chroot({path}): {}", io::Error::last_os_error()));
        }
        Ok(())
    }

    fn run_init(prog: &str, argv: &[&str]) -> Result<(), String> {
        let cprog = CString::new(prog).map_err(|_| "prog has NUL".to_string())?;
        let cargs: Vec<CString> = argv
            .iter()
            .map(|a| CString::new(*a).unwrap_or_default())
            .collect();
        let mut argv_ptrs: Vec<*const libc::c_char> = cargs.iter().map(|c| c.as_ptr()).collect();
        argv_ptrs.push(std::ptr::null());
        // SAFETY: `cprog` is a NUL-terminated program path; `argv_ptrs` is a
        // NULL-terminated array of pointers into `cargs`, all of which outlive
        // the call. On success execv replaces the process image and never
        // returns; on failure it returns and leaves the strings valid.
        let rc = unsafe { libc::execv(cprog.as_ptr(), argv_ptrs.as_ptr()) };
        if rc != 0 {
            return Err(format!("execv({prog}): {}", io::Error::last_os_error()));
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::{choose_hash_start_block, probe_ext4_block_size};
        use std::io::{Seek, SeekFrom, Write};

        fn write_superblock_image(log_block_size: u32) -> tempfile::NamedTempFile {
            let mut image = tempfile::NamedTempFile::new().expect("temp image");
            image
                .as_file_mut()
                .set_len(8 * 1024)
                .expect("set temp image length");
            image
                .as_file_mut()
                .seek(SeekFrom::Start(1024))
                .expect("seek to ext4 superblock");
            let mut superblock = [0u8; 1024];
            superblock[0x18..0x1c].copy_from_slice(&log_block_size.to_le_bytes());
            superblock[0x38..0x3a].copy_from_slice(&0xef53u16.to_le_bytes());
            image
                .as_file_mut()
                .write_all(&superblock)
                .expect("write ext4 superblock");
            image
        }

        #[test]
        fn probe_ext4_block_size_reads_1k_block_images() {
            let image = write_superblock_image(0);
            assert_eq!(
                probe_ext4_block_size(image.path().to_str().expect("temp path"))
                    .expect("block size"),
                1024
            );
        }

        #[test]
        fn probe_ext4_block_size_reads_4k_block_images() {
            let image = write_superblock_image(2);
            assert_eq!(
                probe_ext4_block_size(image.path().to_str().expect("temp path"))
                    .expect("block size"),
                4096
            );
        }

        #[test]
        fn probe_ext4_block_size_rejects_bad_magic() {
            let mut image = tempfile::NamedTempFile::new().expect("temp image");
            image
                .as_file_mut()
                .set_len(8 * 1024)
                .expect("set temp image length");
            let err = probe_ext4_block_size(image.path().to_str().expect("temp path"))
                .expect_err("bad magic must fail");
            assert!(err.contains("magic mismatch"), "{err}");
        }

        #[test]
        fn choose_hash_start_block_accepts_exact_no_superblock_layout() {
            let data_blocks = 8_456;
            let hash_dev_size = 68 * 4_096;
            assert_eq!(
                choose_hash_start_block(data_blocks, hash_dev_size).expect("hash start block"),
                0
            );
        }
    }
}
