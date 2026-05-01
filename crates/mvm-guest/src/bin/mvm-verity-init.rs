//! Early-userspace verity-init (PID 1 in the verity initramfs).
//!
//! ADR-002 §W3 — runs from a tiny initramfs baked by `mkGuest` when
//! `verifiedBoot = true`. The kernel-cmdline `dm-mod.create=` path
//! doesn't work for our microVM hypervisors because Firecracker
//! (and Apple VZ) auto-append `root=/dev/vda ro` to the cmdline on
//! aarch64; the kernel uses last-wins for `root=`, so a verity
//! `root=/dev/dm-0` we set ourselves is silently overridden. We
//! solve that by owning the boot pivot in userspace: this binary
//! mounts an initramfs first, builds the verity device-mapper
//! target via raw ioctls, mounts `/dev/mapper/root` at `/sysroot`,
//! then `switch_root`s to the real init at `/sysroot/init`.
//!
//! Cmdline contract (set by the host's start_vm path):
//!
//!   mvm.roothash=<64-hex>      required; the dm-verity root hash
//!   mvm.data=<dev-path>        defaults to /dev/vda
//!   mvm.hash=<dev-path>        defaults to /dev/vdb
//!
//! On any failure this binary panics — kernel re-init isn't safe from
//! PID 1 in the initramfs, and panic'ing surfaces the failure on the
//! console (visible in `firecracker.log`) rather than silently falling
//! back to the unverified rootfs.
//!
//! Linux-only. Builds as a stub on other platforms so the workspace
//! still compiles on macOS.

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

    #[repr(C)]
    struct DmTargetSpec {
        sector_start: u64,
        length: u64,
        status: i32,
        next: u32,
        target_type: [u8; 16],
        // followed by NUL-terminated parameter string + alignment padding
    }

    pub fn run() -> Result<(), String> {
        msg("mvm-verity-init: starting");

        // ── 1. Mount /proc + /dev so we can read the cmdline and create
        //    block-device nodes if missing. The initramfs ships these
        //    as empty directories.
        do_mount("proc", "/proc", "proc", 0, "")?;
        do_mount("devtmpfs", "/dev", "devtmpfs", 0, "")?;

        // ── 2. Parse /proc/cmdline for the verity parameters.
        let cmdline =
            fs::read_to_string("/proc/cmdline").map_err(|e| format!("read /proc/cmdline: {e}"))?;
        let mut roothash: Option<String> = None;
        let mut data_dev = "/dev/vda".to_string();
        let mut hash_dev = "/dev/vdb".to_string();
        for tok in cmdline.split_whitespace() {
            if let Some(v) = tok.strip_prefix("mvm.roothash=") {
                roothash = Some(v.trim_matches('"').to_string());
            } else if let Some(v) = tok.strip_prefix("mvm.data=") {
                data_dev = v.trim_matches('"').to_string();
            } else if let Some(v) = tok.strip_prefix("mvm.hash=") {
                hash_dev = v.trim_matches('"').to_string();
            }
        }
        let roothash = roothash.ok_or_else(|| "no mvm.roothash= on kernel cmdline".to_string())?;
        if roothash.len() != 64 || !roothash.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(format!(
                "invalid mvm.roothash={roothash:?} (expected 64 hex chars)"
            ));
        }
        msg(&format!(
            "mvm-verity-init: data={data_dev} hash={hash_dev} roothash={}…",
            &roothash[..12]
        ));

        // ── 3. Compute the verity table line.
        //
        //   <start> <num-sectors> verity 1 <data-dev> <hash-dev>
        //          <data-block-size> <hash-block-size>
        //          <num-data-blocks> <hash-start-block>
        //          <algo> <root-hash> <salt>
        //
        // Salt is zero (matches mkGuest's pinned `--salt=00…00`).
        //
        // `data-block-size = 1024` (NOT 4096) so the device's logical
        // block size matches the ext4 we ship — mkGuest builds the
        // rootfs with mke2fs's default 1 KiB blocks at our typical
        // 200 MB image size, and the kernel's ext4 refuses to mount
        // when FS block size < device logical block size. The hash
        // tree itself stays at 4 KiB because that's the typical
        // veritysetup default and gives a reasonable fan-out.
        //
        // `hash_start_block = 1` (NOT 0): `veritysetup format` writes a
        // 512-byte "verity superblock" at offset 0 of the sidecar that
        // stores tree metadata (UUID, hash type, salt). The actual
        // Merkle tree starts at block 1. Setting hash_start_block=0
        // makes the kernel read the superblock as a hash node and
        // report `metadata block 0 is corrupted`. The `--no-superblock`
        // veritysetup flag would let us use 0, but keeping the
        // superblock is what makes `veritysetup verify` work against
        // the artifact (used by the runbook + CI).
        const DATA_BLOCK_SIZE: u64 = 1024;
        const HASH_BLOCK_SIZE: u64 = 4096;
        let data_size = block_device_size(&data_dev)?;
        if !data_size.is_multiple_of(DATA_BLOCK_SIZE) {
            return Err(format!(
                "data device size {data_size} not multiple of {DATA_BLOCK_SIZE}"
            ));
        }
        let data_blocks = data_size / DATA_BLOCK_SIZE;
        let num_sectors = data_blocks * (DATA_BLOCK_SIZE / 512);
        let salt = "0".repeat(64);
        let table_args = format!(
            "1 {data_dev} {hash_dev} {DATA_BLOCK_SIZE} {HASH_BLOCK_SIZE} {data_blocks} 1 sha256 {roothash} {salt}"
        );
        msg(&format!(
            "mvm-verity-init: verity table = {num_sectors} sectors, {data_blocks} data blocks"
        ));

        // ── 4. Open /dev/mapper/control (auto-created by devtmpfs).
        let ctrl = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/mapper/control")
            .map_err(|e| format!("open /dev/mapper/control: {e}"))?;
        let fd = ctrl.as_raw_fd();

        // 4a. DM_VERSION — sanity-check the kernel speaks the same protocol.
        let mut io = base_ioctl();
        unsafe {
            do_ioctl(fd, iowr(DM_VERSION_CMD), &mut io).map_err(|e| format!("DM_VERSION: {e}"))?;
        }
        msg(&format!(
            "mvm-verity-init: dm-ioctl kernel version {}.{}.{}",
            io.version[0], io.version[1], io.version[2]
        ));

        // 4b. DM_DEV_CREATE — make /dev/mapper/root (no table yet).
        let mut io = base_ioctl();
        write_name(&mut io.name, "root");
        unsafe {
            do_ioctl(fd, iowr(DM_DEV_CREATE_CMD), &mut io)
                .map_err(|e| format!("DM_DEV_CREATE: {e}"))?;
        }
        msg("mvm-verity-init: DM_DEV_CREATE ok");

        // 4c. DM_TABLE_LOAD — push the verity target into the inactive table.
        let payload = build_table_payload(num_sectors, "verity", &table_args)?;
        let mut buf = vec![0u8; payload.len()];
        buf.copy_from_slice(&payload);
        // The struct lives at the head of the buffer; mutate via cast.
        let header_ptr = buf.as_mut_ptr().cast::<DmIoctl>();
        unsafe {
            (*header_ptr).flags |= DM_READONLY_FLAG;
            do_ioctl(fd, iowr(DM_TABLE_LOAD_CMD), header_ptr)
                .map_err(|e| format!("DM_TABLE_LOAD: {e}"))?;
        }
        msg("mvm-verity-init: DM_TABLE_LOAD ok");

        // 4d. DM_DEV_SUSPEND with flags=0 → resume = activate the loaded table.
        // (DM_SUSPEND_FLAG bit 1 set means "suspend"; cleared means "resume".)
        let mut io = base_ioctl();
        write_name(&mut io.name, "root");
        unsafe {
            do_ioctl(fd, iowr(DM_DEV_SUSPEND_CMD), &mut io)
                .map_err(|e| format!("DM_DEV_SUSPEND(resume): {e}"))?;
        }
        msg("mvm-verity-init: dm-verity device active");

        // ── 5. Mount /dev/mapper/root at /sysroot. The initramfs ships
        //    /sysroot as an empty mount target. Read-only — verity is
        //    incompatible with writes.
        if !Path::new("/dev/mapper/root").exists() {
            // /dev/mapper/<name> nodes are usually created by udev.
            // In an initramfs without udev, the kernel's devtmpfs
            // creates /dev/dm-N but not the /dev/mapper/<name> symlink.
            // Fall back to /dev/dm-0 in that case — it's the same
            // device, just a different name.
            if !Path::new("/dev/dm-0").exists() {
                return Err(
                    "neither /dev/mapper/root nor /dev/dm-0 exists after DM_DEV_SUSPEND"
                        .to_string(),
                );
            }
            do_mount("/dev/dm-0", "/sysroot", "ext4", libc::MS_RDONLY, "")?;
        } else {
            do_mount("/dev/mapper/root", "/sysroot", "ext4", libc::MS_RDONLY, "")?;
        }
        msg("mvm-verity-init: /sysroot mounted (verity-protected)");

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

    /// Construct a DM_TABLE_LOAD payload: a `DmIoctl` header followed by a
    /// `DmTargetSpec` and the parameter string. Alignment to 8 bytes is
    /// required between successive `dm_target_spec`s; we have only one
    /// target so we pad once.
    fn build_table_payload(
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
                write_name(&mut n, "root");
                n
            },
            uuid: [0u8; DM_UUID_LEN],
            data: [0u8; DM_DATA_LEN],
        };
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
        let rc = unsafe { libc::ioctl(f.as_raw_fd(), BLKGETSIZE64 as libc::Ioctl, &mut size) };
        if rc != 0 {
            return Err(format!(
                "BLKGETSIZE64 on {path}: {}",
                io::Error::last_os_error()
            ));
        }
        Ok(size)
    }

    unsafe fn do_ioctl<T>(fd: libc::c_int, request: u64, arg: *mut T) -> Result<i32, String> {
        // Same Ioctl-type discrepancy as block_device_size; cast at
        // the boundary to whatever libc says is correct for this
        // target.
        let rc = unsafe { libc::ioctl(fd, request as libc::Ioctl, arg) };
        if rc < 0 {
            return Err(io::Error::last_os_error().to_string());
        }
        Ok(rc)
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
        let rc = unsafe { libc::chdir(p.as_ptr()) };
        if rc != 0 {
            return Err(format!("chdir({path}): {}", io::Error::last_os_error()));
        }
        Ok(())
    }

    fn do_chroot(path: &str) -> Result<(), String> {
        let p = CString::new(path).map_err(|_| "chroot path has NUL".to_string())?;
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
        let rc = unsafe { libc::execv(cprog.as_ptr(), argv_ptrs.as_ptr()) };
        if rc != 0 {
            return Err(format!("execv({prog}): {}", io::Error::last_os_error()));
        }
        Ok(())
    }
}
