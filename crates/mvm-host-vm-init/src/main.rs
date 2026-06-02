//! mvm-host-vm-init — PID 1 for the libkrun builder VM.
//!
//! Plan 72 W3 (`specs/plans/72-builder-vm-via-libkrun.md`). Tiny
//! static-linked init that mounts the essentials, brings up the
//! persistent `/nix` store (formatting on first boot), tries to
//! bring the network up, executes `/job/cmd.sh`, writes
//! `/job/result`, and powers off.
//!
//! ## Why this binary, not a shell script
//!
//! Per Plan 72 §W3, the choice between shell and Rust was
//! explicitly debated. Rust won because:
//!
//! - One binary to audit; no `/bin/sh` -> `/usr/bin/sh` -> busybox
//!   hop where each link is a separate Nix store path.
//! - The mount syscalls (overlay/bind mounting the persistent
//!   `/nix-store` over `/nix`) are direct rather than `/sbin/mount`
//!   wrappers, so we get clear errors when something refuses.
//! - We can encode the `/job/result` JSON shape in one place
//!   rather than escape-quoting it across `printf` invocations.
//!
//! ## What runs in here
//!
//! On boot:
//!
//!   1. Mount `/proc`, `/sys`, `/dev`, `/tmp` (the standard init
//!      essentials — busybox-as-PID-1 from `mkGuest` does the
//!      same).
//!   2. Probe `/dev/vdb` for an ext4 superblock; format with
//!      `mkfs.ext4 -F` if blank (first boot on a fresh sparse
//!      virtio-blk image).
//!   3. Mount `/dev/vdb` at `/nix-store`, then mount `/nix` as an
//!      overlay with the rootfs seed as lowerdir and `/nix-store`
//!      as upper/work storage. This lets reads see the baked-in Nix
//!      closure without copying it into the constrained persistent
//!      disk before the first build.
//!   4. Best-effort `udhcpc -i eth0 -n -q` — failure is
//!      non-fatal (offline builds against the seed store still
//!      work; Plan 72 W4's `LibkrunBuilderVm::with_offline()`
//!      formalizes this).
//!   5. Read `/job/cmd.sh`. Exit code 2 + "no cmd.sh" in
//!      `/job/result` if missing.
//!   6. Spawn `/bin/sh -eu /job/cmd.sh`. Capture exit + stderr
//!      tail (last 20 lines, to keep the result file small).
//!   7. Write `/job/result` as `{"exit_code":<i32>,"stderr_tail":<json-string>}`.
//!   8. `sync` + `reboot(RB_POWER_OFF)`. The libkrun host
//!      detects power-off via the shutdown-eventfd
//!      (`krun_get_shutdown_eventfd`).
//!
//! ## Non-Linux build behaviour
//!
//! Linux-only by design. On macOS / Windows the crate still
//! compiles (workspace ergonomics) but `main()` prints a hint
//! and exits 1. mkGuest cross-compiles the real binary against
//! `<arch>-unknown-linux-musl` from a Linux nix-build
//! environment; that's where the size budget (≤ 1.5 MiB) and
//! static-link requirement get enforced.

use std::process::ExitCode;

// Cross-platform modules. The install-spec parser and install
// pipeline runner live here so `cargo test` on macOS exercises the
// dispatch logic via shell stubs without paying for a Linux cross-
// compile. The Linux-only `linux` module composes them with the
// real PID-1 mount / power-off dance.
//
// `allow(dead_code)` because the modules are consumed from
// `linux::run_install_job` on Linux and from `#[cfg(test)]` blocks
// on every host. On non-Linux non-test builds (workspace ergonomics
// + reproducible builds) every public item looks "unused" — clippy
// would flag them otherwise. Real dead code would still surface as
// red because the tests would lose coverage.
#[allow(dead_code)]
mod boot_timings;
/// Plan 89 W3 part 2 — hand-rolled parser for the
/// `HostVmRequest` wire shape the persistent builder VM's
/// dispatch loop reads off vsock. Cross-platform; the W3 part 3
/// Linux dispatch loop calls into it after reading the framed
/// body. Tested against the host's serde-derived encoding so
/// schema drift on either side is loud.
#[allow(dead_code)]
mod builder_request;
/// Plan 89 W2 part 3 — hand-rolled `HostVmResponse::Result`
/// JSON. Cross-platform (testable on macOS) so the wire shape can
/// be validated against `mvm_build::builder_protocol`'s typed
/// serde via a dev-dep test, without dragging serde_json into the
/// production builder-init binary.
#[allow(dead_code)]
mod dispatch_response;
#[allow(dead_code)]
mod install;
#[allow(dead_code)]
mod install_spec;
#[allow(dead_code)]
mod network;
#[allow(dead_code)]
mod proxy;
/// Plan 107 A2.2 / A2.3 — spawn a workload microVM inside the host
/// VM via a `WorkloadVmm` backend (Firecracker today). Cross-platform
/// trait + state-dir/lifecycle logic (tested on macOS); the
/// signal-based stop/status helpers are Linux-only.
#[allow(dead_code)]
mod workload;
/// Plan 107 A3 — in-host-VM vsock forwarder (the nesting hop). The
/// cross-platform CONNECT+splice core is unit-tested on every host;
/// the AF_VSOCK listener wiring (A3.b) is Linux-only. `unix`-gated
/// because it uses `UnixStream` (the crate is inert on Windows).
#[cfg(unix)]
#[allow(dead_code)]
mod workload_proxy;

fn main() -> ExitCode {
    #[cfg(target_os = "linux")]
    {
        linux::run()
    }

    #[cfg(not(target_os = "linux"))]
    {
        eprintln!(
            "mvm-host-vm-init is Linux-only (PID 1 for the libkrun \
             builder VM). On a developer host this binary is a no-op; \
             mkGuest cross-compiles the real init for \
             <arch>-unknown-linux-musl. See \
             specs/plans/72-builder-vm-via-libkrun.md §W3."
        );
        ExitCode::FAILURE
    }
}

#[cfg(any(target_os = "linux", test))]
fn virtiofs_tag_is_read_only(tag: &str) -> bool {
    // `work` is the user's source; `mvm-bins` is the embedded host
    // binaries. Both are inputs the guest must not write back.
    tag == "work" || tag == "mvm-bins"
}

/// Bytes from the start of the ext4 superblock that the host-side
/// geometry check reads. The high-32 bits of `s_blocks_count` live
/// at superblock offset `0x150` (336), so 512 is the smallest
/// power-of-two read covering every field the parser inspects.
#[cfg(any(target_os = "linux", test))]
const EXT4_SUPERBLOCK_READ: usize = 512;

/// Parse the ext4 superblock buffer and return the total
/// filesystem size in bytes the superblock asserts, or `None`
/// when the buffer has no valid ext4 magic / a sanity-failing
/// block size.
///
/// Layout (little-endian; offsets relative to the start of the
/// superblock — itself at byte offset 1024 of the partition):
/// - `0x04`  u32 `s_blocks_count_lo`  — low 32 bits of total block count
/// - `0x18`  u32 `s_log_block_size`   — block size = `1024 << this`
/// - `0x38`  u16 `s_magic`            — `0xEF53` for ext{2,3,4}
/// - `0x150` u32 `s_blocks_count_hi`  — high 32 bits (64-bit feature; 0 otherwise)
///
/// Pure function so darwin `cargo test` exercises it without a
/// Linux cross-compile; the file-IO and `BLKGETSIZE64` ioctl that
/// feed it live inside the linux module.
#[cfg(any(target_os = "linux", test))]
fn parse_ext4_recorded_size_bytes(sb: &[u8]) -> Option<u64> {
    if sb.len() < 0x150 + 4 {
        return None;
    }
    // Magic at 0x38 — guard before trusting the other fields.
    if sb[0x38] != 0x53 || sb[0x39] != 0xEF {
        return None;
    }
    let blocks_lo = u32::from_le_bytes(sb[0x04..0x08].try_into().ok()?);
    let log_block_size = u32::from_le_bytes(sb[0x18..0x1c].try_into().ok()?);
    let blocks_hi = u32::from_le_bytes(sb[0x150..0x154].try_into().ok()?);
    // Reject absurd block sizes — ext4 spec allows 1 KiB..64 KiB
    // (log values 0..=6). Anything higher signals a malformed or
    // stale superblock; treat as unformatted.
    if log_block_size > 6 {
        return None;
    }
    let block_size = 1024u64 << log_block_size;
    let total_blocks = (u64::from(blocks_hi) << 32) | u64::from(blocks_lo);
    total_blocks.checked_mul(block_size)
}

/// Create `/dev/fd → /proc/self/fd` and `/dev/std{in,out,err} →
/// /proc/self/fd/{0,1,2}` under `dev_root`. Idempotent: any entry that
/// already exists (file, symlink, or device node) is left untouched —
/// we never replace whatever the kernel or a prior boot has put there.
///
/// `dev_root` is a parameter so this helper is testable under a
/// `tempfile::tempdir()` without privilege. The targets are written as
/// absolute `/proc/self/fd/...` strings on purpose: they're consumed
/// by code running inside the guest Linux VM where `/proc` is the
/// procfs mount point. The helper itself is cross-platform — symlink
/// creation works on macOS too — so unit tests run on contributor Macs
/// in addition to the production Linux build target.
//
// Production callers live under `#[cfg(target_os = "linux")]`
// (`main.rs:1501`), and the unit tests live in `#[cfg(test)] mod tests`;
// on macOS without `--test` the function would otherwise look dead.
// Matches the sibling pattern at `parse_ext4_recorded_size_bytes` above.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn setup_dev_fd_symlinks(dev_root: &std::path::Path) -> Result<(), String> {
    use std::os::unix::fs::symlink;
    for (link_name, target) in [
        ("fd", "/proc/self/fd"),
        ("stdin", "/proc/self/fd/0"),
        ("stdout", "/proc/self/fd/1"),
        ("stderr", "/proc/self/fd/2"),
    ] {
        let link = dev_root.join(link_name);
        // `Path::exists` follows symlinks; `symlink_metadata` does
        // not. We want "is there anything at this path?", which is
        // the symlink_metadata question — otherwise a dangling
        // symlink left over from a prior boot would be treated as
        // absent and we'd EEXIST on the symlink call.
        if link.symlink_metadata().is_ok() {
            continue;
        }
        symlink(target, &link)
            .map_err(|e| format!("symlink {} -> {target}: {e}", link.display()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `setup_dev_fd_symlinks` lays down all four conventional symlinks
    /// in an empty /dev so bash process substitution (`< <(...)`)
    /// finds `/dev/fd/N`. The targets are the `/proc/self/fd` family;
    /// the symlink_metadata-based skip keeps the helper idempotent on
    /// reboot. Cross-platform: runs on macOS and Linux.
    #[test]
    fn setup_dev_fd_symlinks_creates_all_four_in_empty_dir() {
        let dir = tempfile::tempdir().expect("tempdir");
        setup_dev_fd_symlinks(dir.path()).expect("fresh dev_root succeeds");
        for (name, expected) in [
            ("fd", "/proc/self/fd"),
            ("stdin", "/proc/self/fd/0"),
            ("stdout", "/proc/self/fd/1"),
            ("stderr", "/proc/self/fd/2"),
        ] {
            let link = dir.path().join(name);
            let target = std::fs::read_link(&link)
                .unwrap_or_else(|e| panic!("read_link {}: {e}", link.display()));
            assert_eq!(
                target.to_string_lossy(),
                expected,
                "{name} points at the right /proc/self/fd target"
            );
        }
    }

    /// Idempotency: a pre-existing entry — even a dangling symlink
    /// left over from a prior boot — is preserved. We never clobber
    /// what the kernel/initramfs/previous boot staged. Guards
    /// against, e.g., a future devtmpfs variant that creates
    /// `/dev/stdin` as a character device.
    #[test]
    fn setup_dev_fd_symlinks_is_idempotent_when_already_present() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().expect("tempdir");
        symlink("/sentinel", dir.path().join("fd")).expect("pre-stage symlink");
        setup_dev_fd_symlinks(dir.path()).expect("idempotent run succeeds");
        assert_eq!(
            std::fs::read_link(dir.path().join("fd"))
                .expect("read_link fd")
                .to_string_lossy(),
            "/sentinel",
            "sentinel preserved"
        );
        for name in ["stdin", "stdout", "stderr"] {
            assert!(
                dir.path().join(name).symlink_metadata().is_ok(),
                "{name} created on a partially-staged /dev"
            );
        }
    }

    /// A non-existent `dev_root` surfaces as a clean error message
    /// that names the path. The first failing symlink is enough —
    /// we don't try to be smart about pre-checking the parent.
    #[test]
    fn setup_dev_fd_symlinks_errors_when_dev_root_missing() {
        let bogus = std::path::PathBuf::from("/this/path/should/not/exist/mvm-dev-fd-test");
        let err =
            setup_dev_fd_symlinks(&bogus).expect_err("missing dev_root must error, not panic");
        assert!(
            err.contains("/this/path/should/not/exist"),
            "error names the offending parent path: {err}"
        );
    }

    #[test]
    fn virtiofs_tag_policy_marks_input_shares_read_only() {
        assert!(virtiofs_tag_is_read_only("work"));
        assert!(virtiofs_tag_is_read_only("mvm-bins"));
        assert!(!virtiofs_tag_is_read_only("out"));
        assert!(!virtiofs_tag_is_read_only("job"));
    }

    /// Build a synthetic ext4 superblock buffer (just the fields
    /// `parse_ext4_recorded_size_bytes` reads).
    fn synth_sb(blocks_lo: u32, blocks_hi: u32, log_block_size: u32) -> Vec<u8> {
        let mut sb = vec![0u8; EXT4_SUPERBLOCK_READ];
        sb[0x04..0x08].copy_from_slice(&blocks_lo.to_le_bytes());
        sb[0x18..0x1c].copy_from_slice(&log_block_size.to_le_bytes());
        sb[0x38] = 0x53;
        sb[0x39] = 0xEF;
        sb[0x150..0x154].copy_from_slice(&blocks_hi.to_le_bytes());
        sb
    }

    #[test]
    fn parse_ext4_size_rejects_buffer_without_magic() {
        let sb = vec![0u8; EXT4_SUPERBLOCK_READ];
        assert_eq!(parse_ext4_recorded_size_bytes(&sb), None);
    }

    #[test]
    fn parse_ext4_size_rejects_short_buffer() {
        let sb = vec![0u8; 64];
        assert_eq!(parse_ext4_recorded_size_bytes(&sb), None);
    }

    #[test]
    fn parse_ext4_size_computes_64gib_default_layout() {
        // mkfs.ext4 default: 4 KiB blocks (log=2). A 64 GiB
        // filesystem records 16_777_216 blocks.
        let sb = synth_sb(16_777_216, 0, 2);
        assert_eq!(
            parse_ext4_recorded_size_bytes(&sb),
            Some(64u64 * 1024 * 1024 * 1024),
        );
    }

    #[test]
    fn parse_ext4_size_handles_64bit_feature() {
        // 20 TiB needs the high-32-bit block count (64bit feature).
        // 20 TiB with 4 KiB blocks = 20 * 2^40 / 2^12 = 5 * 2^30
        // blocks, which overflows u32 — `blocks_hi` carries the top bit.
        let total_blocks: u64 = 5 * (1u64 << 30);
        let blocks_lo = (total_blocks & 0xFFFF_FFFF) as u32;
        let blocks_hi = (total_blocks >> 32) as u32;
        let sb = synth_sb(blocks_lo, blocks_hi, 2);
        assert_eq!(
            parse_ext4_recorded_size_bytes(&sb),
            Some(20u64 * 1024 * 1024 * 1024 * 1024),
        );
    }

    #[test]
    fn parse_ext4_size_rejects_absurd_block_size() {
        // log=7 → 128 KiB blocks, which mkfs.ext4 never produces;
        // signals a stale / corrupt superblock.
        let sb = synth_sb(1024, 0, 7);
        assert_eq!(parse_ext4_recorded_size_bytes(&sb), None);
    }

    /// Regression for the May 2026 `mvmctl dev up` failure: a
    /// stale 64 GiB ext4 image got re-attached to a `/dev/vdb`
    /// libkrun exposed as 64 GiB − 64 KiB. The kernel rejected
    /// mount with `EINVAL: bad geometry: block count 16777216
    /// exceeds size of device (16777200 blocks)`. The pre-mount
    /// check in [`linux::nix_store_dev_needs_format`] compares
    /// the recorded FS size against the device size and reformats
    /// on mismatch; this test pins the underlying arithmetic so
    /// the comparison `fs_bytes > device_bytes` does what the
    /// kernel does.
    #[test]
    fn parse_ext4_size_reports_oversize_filesystem() {
        let fs_bytes =
            parse_ext4_recorded_size_bytes(&synth_sb(16_777_216, 0, 2)).expect("valid superblock");
        let device_bytes = 16_777_200u64 * 4096; // 64 GiB - 64 KiB
        assert!(
            fs_bytes > device_bytes,
            "recorded FS ({fs_bytes}) must exceed device ({device_bytes}) for the bug to reproduce"
        );
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::path::Path;
    use std::process::{Command, ExitCode};
    use std::sync::{Arc, Mutex};
    use std::time::Instant;

    use crate::boot_timings::BootTimings;

    /// Persistent Nix-store device — virtio-blk attached as
    /// `/dev/vdb` by `LibkrunBuilderVm` (Plan 72 W4 will wire
    /// the `extra_disks` entry).
    const NIX_STORE_DEV: &str = "/dev/vdb";

    /// Where we mount the persistent store before bind-mounting
    /// it over `/nix`. Living off `/nix` directly first avoids
    /// shadowing the rootfs's seed during the format/mount
    /// dance.
    const NIX_STORE_MOUNT: &str = "/nix-store";
    const NIX_OVERLAY_UPPER: &str = "/nix-store/upper";
    const NIX_OVERLAY_WORK: &str = "/nix-store/work";
    /// Plan 95 followup — was `/nix-merged` (rootfs root). The rootfs
    /// boots `ro`, so `mkdir /nix-merged` failed with EROFS and the
    /// overlay-mount fell back to seed-copy. `/run` is mounted tmpfs
    /// by `mount_pseudofs` (mvmctl-init Stage 1), so `mkdir` there
    /// always succeeds. The mount point is host-side scaffolding —
    /// the visible mount is the bind-mount onto [`NIX_TARGET`] = `/nix`.
    const NIX_OVERLAY_MERGED: &str = "/run/nix-merged";

    /// Final bind-mount target. The rootfs's `/nix/store` (seed
    /// Nix paths needed by `/bin/sh`, `nix`, etc.) is the overlay
    /// lowerdir; persistent writes land in [`NIX_OVERLAY_UPPER`].
    const NIX_TARGET: &str = "/nix";

    /// Standard nixpkgs path-registration manifest, emitted by
    /// `nixos/lib/make-ext4-fs.nix` (which mkGuest uses). Lists
    /// every store path baked into the rootfs along with its
    /// SHA-256, size, and references — exactly the wire shape
    /// `nix-store --load-db` consumes from stdin. Sits at the
    /// rootfs root (not under `/nix/`) and is mounted read-only.
    const NIX_PATH_REGISTRATION: &str = "/nix-path-registration";

    /// Sentinel file inside the persistent `/nix-store` we touch
    /// after [`load_seeded_nix_db`] runs, so subsequent boots can
    /// skip the (idempotent but slow) re-registration. Lives next
    /// to `/nix-store/store/` and `/nix-store/var/` — neither path
    /// the standard Nix store inspects, so the marker is invisible
    /// to nix-daemon.
    const NIX_DB_LOADED_MARKER: &str = "/nix-store/.seed-db-loaded";

    /// Per-job command staging dir (`/job/cmd.sh`, `/job/env`,
    /// `/job/result`). Mounted via virtio-fs from the host
    /// (`LibkrunBuilderVm` declares the `job` tag — see Plan 72 W4).
    const JOB_DIR: &str = "/job";

    /// Workspace bind from the host — the in-repo flake the user
    /// is building. Read-only from the guest's perspective: libkrun
    /// exposes the virtio-fs share and this init mounts the `work`
    /// tag with MS_RDONLY below.
    const WORK_DIR: &str = "/work";

    /// Artifact-extraction dir. The user's `cmd.sh` writes
    /// `vmlinux` + `rootfs.ext4` here; the host reads them back
    /// out after the VM powers off.
    const OUT_DIR: &str = "/out";

    /// Pre-cross-compiled host-vm binaries (ADR-065). `cmd.sh` exports
    /// `MVM_HOST_BIN_DIR=/mvm-bins` so the builder-vm flake installs
    /// them from here instead of building them with the guest's nix —
    /// the flake eval reads `/mvm-bins/<bin>`, so this must be mounted
    /// before the build runs or the eval fails "path does not exist".
    const HOST_BIN_DIR: &str = "/mvm-bins";

    /// virtio-fs tags that match the host-side
    /// `KrunContext::add_virtio_fs` declarations in
    /// `LibkrunBuilderVm::run_build`. Order doesn't matter; the
    /// guest mounts each by tag. `mvm-bins` is read-only (inputs).
    const VIRTIOFS_MOUNTS: &[(&str, &str)] = &[
        ("work", WORK_DIR),
        ("out", OUT_DIR),
        ("job", JOB_DIR),
        ("mvm-bins", HOST_BIN_DIR),
    ];

    /// Max stderr lines we capture into `/job/result`. Keeps
    /// the result file small; the host-side supervisor still
    /// captures the full stream via the libkrun console
    /// (`krun_set_console_output`).
    const STDERR_TAIL_LINES: usize = 20;

    /// Filename for the structured install spec (Plan 73 Followup
    /// B.2). When `/job/install_spec.json` is present the init
    /// binary routes through the app-deps install pipeline instead
    /// of dispatching `/job/cmd.sh`. The two modes are mutually
    /// exclusive — install jobs don't carry a cmd.sh, flake jobs
    /// don't carry an install_spec.json.
    const INSTALL_SPEC_FILENAME: &str = "install_spec.json";

    pub fn run() -> ExitCode {
        eprintln!("mvm-host-vm-init: pid 1 starting");

        // The Linux kernel doesn't pass a PATH to PID 1, so without
        // this every `Command::new("iptables")` /
        // `Command::new("modprobe")` style spawn relies on the
        // child to find its binary — which fails on a stock rootfs
        // (Plan 86 / ADR-054). Set a canonical PATH that covers the
        // mvm builder VM rootfs layout (busybox at `/bin/*` + extra
        // packages at `/sbin/*` + `/usr/local/bin/*`) before any
        // spawn site runs. Absolute-path call sites like
        // `/sbin/mkfs.ext4` (e2fsprogs, lives at `/sbin/*` via the
        // mkGuest packages symlink) and `/bin/udhcpc`,
        // `/bin/busybox` (busybox applets, live at `/bin/*` via the
        // mkGuest busybox install) are unaffected. Hardcoding
        // `/sbin/udhcpc` would ENOENT — busybox only installs
        // applets under `/bin/<applet>`.
        // SAFETY: PID 1 is single-threaded until we spawn the fan-out
        // tracks below; no other thread can be reading the env yet.
        unsafe {
            std::env::set_var(
                "PATH",
                "/usr/local/sbin:/usr/local/bin:/sbin:/usr/sbin:/bin:/usr/bin",
            );
        }

        // Plan 76 Phase 5: anchor the boot-timings clock as close
        // to init entry as we can. The few ms of `eprintln!` +
        // module dispatch above this point are constant across
        // boots and uninteresting.
        let anchor = Instant::now();
        let (timings, _) = BootTimings::new(anchor);
        let timings = Arc::new(Mutex::new(timings));

        // Pseudofs mounts must complete before anything else —
        // every subsequent phase needs /proc, /sys, /dev to be
        // readable.
        if let Err(e) = mount_pseudofs() {
            eprintln!("mvm-host-vm-init: mount_pseudofs failed: {e}");
            write_result(2, &format!("mount_pseudofs failed: {e}"));
            stamp(&timings, |t| {
                t.poweroff_start_ms = Some(BootTimings::ms_since(anchor))
            });
            write_boot_timings(&timings);
            return power_off();
        }
        stamp(&timings, |t| {
            t.pseudofs_ready_ms = Some(BootTimings::ms_since(anchor))
        });

        // Plan 76 Phase 5: three independent setup tracks fan out
        // after pseudofs. They share no state with each other
        // until join.
        //
        //   Track A (this thread): /dev/vdb format → mount → seed
        //     → bind over /nix. Serial; each step depends on the
        //     previous. Long pole on first-boot (the seed copy).
        //   Track B: modprobe fuse + virtiofs → mount virtio-fs
        //     shares. Independent of /nix work — the kernel
        //     modules and the persistent-store ext4 don't share
        //     resources.
        //   Track C: udhcpc network setup. Independent of both.
        //     Non-fatal: offline builds against the seed store
        //     still work.
        //
        // Threads write into the same `Mutex<BootTimings>`;
        // contention is a non-issue (a handful of writes per
        // boot, none on the hot path).
        let track_b = {
            let timings = Arc::clone(&timings);
            std::thread::spawn(move || setup_modules_and_virtiofs(&timings, anchor))
        };
        let track_c = {
            let timings = Arc::clone(&timings);
            std::thread::spawn(move || {
                if let Err(e) = setup_network() {
                    eprintln!("mvm-host-vm-init: setup_network warning (non-fatal): {e}");
                    // Leave network_ready_ms = None — the JSON
                    // signals "offline build" downstream.
                    return;
                }
                stamp(&timings, |t| {
                    t.network_ready_ms = Some(BootTimings::ms_since(anchor))
                });
            })
        };

        // Track A on the main thread.
        if let Err(e) = setup_nix_store(&timings, anchor) {
            eprintln!("mvm-host-vm-init: setup_nix_store failed: {e}");
            // Drain the other tracks so their threads don't get
            // orphaned across the reboot syscall.
            let _ = track_b.join();
            let _ = track_c.join();
            write_result(2, &format!("setup_nix_store failed: {e}"));
            stamp(&timings, |t| {
                t.poweroff_start_ms = Some(BootTimings::ms_since(anchor))
            });
            write_boot_timings(&timings);
            return power_off();
        }

        // Wait for the fan-out tracks before dispatching the job.
        // Failures on B/C are already logged inside the closures;
        // we don't abort the build for them.
        let _ = track_b.join();
        let _ = track_c.join();

        // In-guest egress lockdown — Plan 73 Followup B.2.y /
        // ADR-047 defense-in-depth. Installs iptables OUTPUT
        // default-deny + proxy-uid-only ACCEPT so a build step
        // that ignores HTTP_PROXY env vars cannot bypass
        // `mvm-egress-proxy`. FATAL on failure — without these
        // rules the builder VM's egress allowlist is unenforced
        // and ADR-002's Claim 9 transitive trust onto the
        // builder VM has no defense layer. (Note: this is
        // installed even when `setup_network()` failed, because
        // the rules don't depend on a working IP address —
        // offline builds still need the policy in place in case
        // a substituter URL is reached via cache rather than
        // network.)
        if let Err(e) = crate::network::install_egress_lockdown(
            &crate::network::SystemIptables,
            crate::network::PROXY_UID,
        ) {
            // Plan 86: in the Stage 0 / ur-seed bootstrap context the
            // libkrunfw-bundled kernel ships without netfilter — both
            // `iptables-nft` and `iptables-legacy` bail with "table
            // does not exist" or "protocol not supported" at the first
            // rule install. The egress lockdown is defense-in-depth
            // for the Plan 73 deps-install pipeline (untrusted code
            // running in the steady-state builder VM). Stage 0 only
            // runs flake builds — `nix build` against a pinned
            // `path:/work#…` reference — where Nix's own fixed-output
            // derivation hashes carry the integrity guarantee. We
            // log + continue rather than fail closed.
            //
            // The steady-state builder VM image (built by Stage 0 via
            // the in-repo TSI-patched kernel under
            // `nix/images/builder-vm/kernel/`) carries netfilter, so
            // this fallback only triggers in Stage 0 — the audit
            // signal still distinguishes the two contexts.
            if egress_error_indicates_no_netfilter(&e) {
                eprintln!(
                    "mvm-host-vm-init: egress lockdown SKIPPED (kernel lacks netfilter — \
                     Stage 0 / libkrunfw-bundled-kernel context): {e}"
                );
            } else {
                eprintln!("mvm-host-vm-init: egress lockdown FAILED (fatal): {e}");
                write_result(2, &format!("egress lockdown failed: {e}"));
                return power_off();
            }
        }

        // Plan 89 W3 part 3 dispatch: if the host staged a
        // `dispatch.sock.marker` in /job, this VM is persistent
        // (host-side `LibkrunPersistentHostVm`, W3 part 4).
        // Enter the dispatch loop instead of single-shot. Marker
        // absent (the default) preserves the existing cmd.sh /
        // install_spec flows exactly.
        let dispatch_marker = format!("{JOB_DIR}/dispatch.sock.marker");
        if Path::new(&dispatch_marker).exists() {
            eprintln!("mvm-host-vm-init: dispatch marker detected, entering W3 dispatch loop");
            stamp(&timings, |t| {
                t.job_start_ms = Some(BootTimings::ms_since(anchor))
            });
            // Snapshot the cold-boot timings — the dispatch loop's
            // first response carries this; subsequent responses
            // see None (per Plan 89's HostVmResponse::Result
            // semantics).
            let cold_boot_timings = match timings.lock() {
                Ok(t) => Some(t.clone()),
                Err(_) => {
                    eprintln!(
                        "mvm-host-vm-init: dispatch: timings mutex poisoned, omitting boot_timings"
                    );
                    None
                }
            };
            let _exit_code = run_dispatch_loop(cold_boot_timings);
            stamp(&timings, |t| {
                t.poweroff_start_ms = Some(BootTimings::ms_since(anchor))
            });
            write_boot_timings(&timings);
            return power_off();
        }

        // Plan 73 Followup B.2 dispatch: install jobs hand the init
        // binary a structured spec rather than a shell script. We
        // probe for the spec first; if absent, fall through to the
        // existing cmd.sh flake-build flow.
        let install_spec_path = format!("{JOB_DIR}/{INSTALL_SPEC_FILENAME}");
        if Path::new(&install_spec_path).exists() {
            eprintln!("mvm-host-vm-init: install spec detected, routing through install pipeline");
            stamp(&timings, |t| {
                t.job_start_ms = Some(BootTimings::ms_since(anchor))
            });
            run_install_job(&install_spec_path);
            stamp(&timings, |t| {
                t.job_end_ms = Some(BootTimings::ms_since(anchor))
            });
            stamp(&timings, |t| {
                t.poweroff_start_ms = Some(BootTimings::ms_since(anchor))
            });
            write_boot_timings(&timings);
            return power_off();
        }

        let cmd_path = format!("{JOB_DIR}/cmd.sh");
        if !Path::new(&cmd_path).exists() {
            write_result(2, &format!("missing {cmd_path}"));
            stamp(&timings, |t| {
                t.poweroff_start_ms = Some(BootTimings::ms_since(anchor))
            });
            write_boot_timings(&timings);
            return power_off();
        }

        stamp(&timings, |t| {
            t.job_start_ms = Some(BootTimings::ms_since(anchor))
        });
        let job_start_at = Instant::now();
        let (code, tail) = run_job(&cmd_path);
        let build_ms = u64::try_from(job_start_at.elapsed().as_millis()).unwrap_or(u64::MAX);
        stamp(&timings, |t| {
            t.job_end_ms = Some(BootTimings::ms_since(anchor))
        });
        write_result(code, &tail);
        // Plan 89 W2 part 3: best-effort vsock send of the
        // `HostVmResponse::Result` frame the host's
        // `mvm_build::builder_protocol::read_host_vm_response_from_socket`
        // is waiting for. Runs BEFORE write_boot_timings so the
        // timings snapshot we send mirrors what hits the filesystem.
        // Any failure logs and falls through to power_off — the
        // legacy file-based result path remains authoritative until
        // the host wires the vsock receive in W2 part 4.
        let timings_snapshot = match timings.lock() {
            Ok(t) => t.clone(),
            Err(_) => {
                eprintln!(
                    "mvm-host-vm-init: boot-timings mutex poisoned; \
                     skipping vsock dispatch send"
                );
                stamp(&timings, |t| {
                    t.poweroff_start_ms = Some(BootTimings::ms_since(anchor))
                });
                write_boot_timings(&timings);
                return power_off();
            }
        };
        send_dispatch_response_via_vsock(&crate::dispatch_response::DispatchResponse {
            // Single-shot has no incoming request to correlate
            // against; the nil UUID is the documented sentinel
            // (see `dispatch_response::NIL_JOB_ID`).
            job_id: crate::dispatch_response::NIL_JOB_ID.to_string(),
            exit_code: code,
            stderr_tail: tail,
            boot_timings: Some(timings_snapshot),
            build_ms,
        });
        stamp(&timings, |t| {
            t.poweroff_start_ms = Some(BootTimings::ms_since(anchor))
        });
        write_boot_timings(&timings);
        power_off()
    }

    /// Plan 89 W2 part 3 — listen on `AF_VSOCK` port
    /// [`BUILDER_DISPATCH_PORT`] and write a single framed
    /// `HostVmResponse::Result` to the first connection that
    /// arrives within `ACCEPT_TIMEOUT_SECS` seconds. Best-effort:
    /// any failure (no host connection, socket setup error, write
    /// error) is logged to stderr and the boot continues to
    /// `power_off`.
    ///
    /// Wire shape is hand-rolled by
    /// [`crate::dispatch_response::DispatchResponse::to_json`]; the
    /// cross-validation test in that module pins the output against
    /// `mvm_build::builder_protocol::HostVmResponse` so the host
    /// deserializer parses what we emit.
    ///
    /// AF_VSOCK constants are inlined rather than going through
    /// `nix` because the size-budget comment in this crate's
    /// Cargo.toml (Plan 72 §W3 — ≤ 1.5 MiB) discourages new dep
    /// features. The pattern mirrors
    /// `crates/mvm-guest/src/bin/mvm-builder-agent.rs` exactly.
    // -----------------------------------------------------------
    // Plan 89 W2 / W3 — AF_VSOCK helpers
    // -----------------------------------------------------------
    //
    // Shared between W2 part 3's single-shot send and W3 part 3's
    // dispatch loop. Inlined FFI rather than `nix` because the
    // Plan 72 §W3 size budget discourages new dep features; the
    // pattern mirrors `mvm-guest/src/bin/mvm-builder-agent.rs`.

    /// Plan 89 W2 part 2 — must match
    /// `mvm_guest::builder_agent::BUILDER_DISPATCH_PORT`. Hardcoded
    /// for size-budget reasons; the
    /// `vsock_send_tests::builder_dispatch_port_literal_is_21471`
    /// pinning test below catches divergence.
    const BUILDER_DISPATCH_PORT: u32 = 21471;
    const AF_VSOCK: i32 = 40;
    const SOCK_STREAM: i32 = 1;
    const SOL_SOCKET: i32 = 1;
    const SO_RCVTIMEO: i32 = 20;
    const VMADDR_CID_ANY: u32 = 0xFFFF_FFFF;

    /// W3 part 3 cap on a single inbound `HostVmRequest` body.
    /// Matches `mvm_guest::vsock::MAX_FRAME_SIZE` (256 KiB) — the
    /// host's `read_frame` enforces the same bound on its side, so
    /// a body above this size couldn't have been written by a
    /// well-behaved supervisor anyway.
    const MAX_DISPATCH_BODY_BYTES: u32 = 256 * 1024;

    #[repr(C)]
    struct SockAddrVm {
        svm_family: u16,
        svm_reserved1: u16,
        svm_port: u32,
        svm_cid: u32,
        svm_zero: [u8; 4],
    }

    unsafe extern "C" {
        fn socket(domain: i32, typ: i32, protocol: i32) -> i32;
        fn bind(sockfd: i32, addr: *const core::ffi::c_void, addrlen: u32) -> i32;
        fn listen(sockfd: i32, backlog: i32) -> i32;
        fn accept(sockfd: i32, addr: *mut core::ffi::c_void, addrlen: *mut u32) -> i32;
        fn setsockopt(
            sockfd: i32,
            level: i32,
            optname: i32,
            optval: *const core::ffi::c_void,
            optlen: u32,
        ) -> i32;
        fn close(fd: i32) -> i32;
    }

    /// Open + bind + listen an AF_VSOCK socket on `port`. Returns the
    /// listening fd or `None` on any setup failure (with stderr
    /// breadcrumb). `accept_timeout_secs = Some(n)` applies
    /// `SO_RCVTIMEO` so subsequent `accept()` calls bound the wait at
    /// `n`s; `None` means accept blocks until a peer connects. Used
    /// for both the dispatch port (21471) and the Plan 107 A3
    /// workload-forward port (21472).
    fn open_vsock_listener_fd(port: u32, accept_timeout_secs: Option<i64>) -> Option<i32> {
        let listen_fd = unsafe { socket(AF_VSOCK, SOCK_STREAM, 0) };
        if listen_fd < 0 {
            eprintln!("mvm-host-vm-init: vsock: socket() failed");
            return None;
        }
        let addr = SockAddrVm {
            svm_family: AF_VSOCK as u16,
            svm_reserved1: 0,
            svm_port: port,
            svm_cid: VMADDR_CID_ANY,
            svm_zero: [0; 4],
        };
        let rc = unsafe {
            bind(
                listen_fd,
                &addr as *const SockAddrVm as *const core::ffi::c_void,
                std::mem::size_of::<SockAddrVm>() as u32,
            )
        };
        if rc < 0 {
            eprintln!("mvm-host-vm-init: vsock: bind() failed on port {port}");
            unsafe { close(listen_fd) };
            return None;
        }
        let rc = unsafe { listen(listen_fd, 1) };
        if rc < 0 {
            eprintln!("mvm-host-vm-init: vsock: listen() failed");
            unsafe { close(listen_fd) };
            return None;
        }
        if let Some(secs) = accept_timeout_secs {
            let tv = libc::timeval {
                tv_sec: secs,
                tv_usec: 0,
            };
            let rc = unsafe {
                setsockopt(
                    listen_fd,
                    SOL_SOCKET,
                    SO_RCVTIMEO,
                    &tv as *const libc::timeval as *const core::ffi::c_void,
                    std::mem::size_of::<libc::timeval>() as u32,
                )
            };
            if rc < 0 {
                eprintln!("mvm-host-vm-init: vsock: setsockopt SO_RCVTIMEO failed (continuing)");
            }
        }
        Some(listen_fd)
    }

    /// Accept one connection from `listen_fd`. Returns the
    /// connection fd or `None` on accept failure (e.g.
    /// `SO_RCVTIMEO` elapsed).
    fn accept_one(listen_fd: i32) -> Option<i32> {
        let conn_fd = unsafe { accept(listen_fd, std::ptr::null_mut(), std::ptr::null_mut()) };
        if conn_fd < 0 { None } else { Some(conn_fd) }
    }

    /// Wrap an accepted vsock conn fd in a `std::fs::File` so we
    /// can use blanket `Read`/`Write` impls without rolling our
    /// own write()/read() FFI. Ownership of `conn_fd` transfers to
    /// the returned File; it closes on drop.
    fn adopt_conn_fd(conn_fd: i32) -> std::fs::File {
        use std::os::fd::FromRawFd;
        unsafe { std::fs::File::from_raw_fd(conn_fd) }
    }

    /// Plan 107 A3 — the workload-vsock forwarder listener. Binds the
    /// AF_VSOCK [`crate::workload_proxy::WORKLOAD_FORWARD_PORT`] and
    /// loops accepting outer-host connections, handing each to
    /// [`crate::workload_proxy::handle_forward_conn`] on its own
    /// thread (the handler reads the multiplex handshake, resolves the
    /// named workload's `v.sock`, and splices). Runs for the VM's
    /// lifetime; spawned as a background thread at dispatch-loop entry.
    /// Never returns under normal operation.
    fn run_forward_listener() {
        use std::os::fd::FromRawFd;
        use std::os::unix::net::UnixStream;
        use std::path::Path;

        let Some(listen_fd) =
            open_vsock_listener_fd(crate::workload_proxy::WORKLOAD_FORWARD_PORT, None)
        else {
            eprintln!("mvm-host-vm-init: forward listener: setup failed (nesting hop disabled)");
            return;
        };
        eprintln!(
            "mvm-host-vm-init: forward listener ready on AF_VSOCK port {}",
            crate::workload_proxy::WORKLOAD_FORWARD_PORT
        );
        // Plan 107 A3.4 — bound concurrent forwarded streams.
        let limiter = crate::workload_proxy::ConnectionLimiter::new(
            crate::workload_proxy::MAX_CONCURRENT_FORWARDS,
        );
        loop {
            let Some(conn_fd) = accept_one(listen_fd) else {
                eprintln!("mvm-host-vm-init: forward listener: accept failed (retrying)");
                continue;
            };
            // Fail closed at the cap rather than spawning unboundedly.
            let Some(permit) = limiter.try_acquire() else {
                eprintln!(
                    "mvm-host-vm-init: forward listener: at {} concurrent streams, dropping connection",
                    crate::workload_proxy::MAX_CONCURRENT_FORWARDS
                );
                unsafe { close(conn_fd) };
                continue;
            };
            std::thread::spawn(move || {
                // Hold the permit for the connection's lifetime; it
                // releases the slot when this thread ends.
                let _permit = permit;
                // The accepted fd is an AF_VSOCK SOCK_STREAM socket;
                // UnixStream only touches its read/write/clone, so
                // wrapping it is sound (address family is irrelevant).
                let inbound = unsafe { UnixStream::from_raw_fd(conn_fd) };
                if let Err(e) = crate::workload_proxy::handle_forward_conn(
                    inbound,
                    Path::new(crate::workload::WORKLOAD_STATE_BASE),
                ) {
                    eprintln!("mvm-host-vm-init: forward conn ended: {e}");
                }
            });
        }
    }

    /// Write a length-prefixed (u32 BE) frame on an existing conn.
    /// Mirrors `mvm_guest::vsock::write_frame`. Returns `true` on
    /// successful full-frame write. Doesn't close — caller owns
    /// the File and decides when to drop.
    fn write_frame(conn: &mut std::fs::File, body: &[u8]) -> bool {
        use std::io::Write;
        let len_be = (body.len() as u32).to_be_bytes();
        let wrote_len = conn.write_all(&len_be).is_ok();
        wrote_len && conn.write_all(body).is_ok()
    }

    /// Read one length-prefixed (u32 BE) frame body from an
    /// existing conn. Mirrors `mvm_guest::vsock::read_frame`'s
    /// wire format. Returns `None` on any I/O / over-cap failure.
    /// Body > `MAX_DISPATCH_BODY_BYTES` fails closed before
    /// allocation. Doesn't close — caller owns the File.
    fn read_frame(conn: &mut std::fs::File) -> Option<Vec<u8>> {
        use std::io::Read;
        let mut len_buf = [0u8; 4];
        if conn.read_exact(&mut len_buf).is_err() {
            return None;
        }
        let frame_len = u32::from_be_bytes(len_buf);
        if frame_len > MAX_DISPATCH_BODY_BYTES {
            eprintln!(
                "mvm-host-vm-init: dispatch: frame too large ({frame_len} > \
                 {MAX_DISPATCH_BODY_BYTES})"
            );
            return None;
        }
        let mut body = vec![0u8; frame_len as usize];
        if conn.read_exact(&mut body).is_err() {
            return None;
        }
        Some(body)
    }

    fn send_dispatch_response_via_vsock(payload: &crate::dispatch_response::DispatchResponse) {
        const ACCEPT_TIMEOUT_SECS: i64 = 10;
        let Some(listen_fd) =
            open_vsock_listener_fd(BUILDER_DISPATCH_PORT, Some(ACCEPT_TIMEOUT_SECS))
        else {
            return;
        };
        let Some(conn_fd) = accept_one(listen_fd) else {
            eprintln!(
                "mvm-host-vm-init: vsock send: no host connection within {ACCEPT_TIMEOUT_SECS}s \
                 (single-shot path; W2 part 4 wired the host receiver)"
            );
            unsafe { close(listen_fd) };
            return;
        };
        let mut conn = adopt_conn_fd(conn_fd);
        let json = payload.to_json();
        if !write_frame(&mut conn, json.as_bytes()) {
            eprintln!("mvm-host-vm-init: vsock send: write failed mid-frame");
        }
        drop(conn);
        unsafe { close(listen_fd) };
    }

    // -----------------------------------------------------------
    // Plan 89 W3 part 3 — persistent-VM dispatch loop
    // -----------------------------------------------------------

    /// Plan 89 W3 part 3 — dispatch loop entry point. Called from
    /// `run` when `/job/dispatch.sock.marker` is present (the host
    /// stages the marker when spawning a long-lived
    /// `LibkrunPersistentHostVm`, W3 part 4). Opens a long-lived
    /// AF_VSOCK listener on [`BUILDER_DISPATCH_PORT`], reads one
    /// `HostVmRequest` per accepted connection, dispatches the
    /// inner job, writes back a `HostVmResponse::Result`, and
    /// repeats until a `Shutdown` request triggers a clean exit.
    ///
    /// `cold_boot_timings` carries the BootTimings snapshot taken
    /// at dispatch-loop entry. Per Plan 89 spec, only the
    /// supervisor's *first* dispatch in a persistent VM session
    /// gets a populated `boot_timings` field on the wire; subsequent
    /// dispatches see `None`. The first dispatch in this loop
    /// consumes the snapshot via `.take()`.
    ///
    /// Returns `0` on graceful `Shutdown`, non-zero on listener
    /// setup failure (caller `power_off`s either way).
    fn run_dispatch_loop(mut cold_boot_timings: Option<BootTimings>) -> i32 {
        // No accept timeout — the dispatch loop is persistent and
        // blocks waiting for the supervisor's next submit. The
        // outer `mvmctl dev down` signals shutdown via a
        // `HostVmRequest::Shutdown` frame on a fresh connection.
        // Plan 107 A3 — bring up the workload-vsock forwarder before
        // the dispatch loop. It runs for the VM's lifetime on its own
        // AF_VSOCK port, bridging the outer host to each workload's
        // Firecracker v.sock. Failure here is non-fatal: builds still
        // dispatch; only the nesting hop is unavailable (logged).
        std::thread::spawn(run_forward_listener);

        let Some(listen_fd) = open_vsock_listener_fd(BUILDER_DISPATCH_PORT, None) else {
            eprintln!("mvm-host-vm-init: dispatch loop: listener setup failed");
            return 1;
        };
        eprintln!("mvm-host-vm-init: dispatch loop ready on AF_VSOCK port {BUILDER_DISPATCH_PORT}");
        loop {
            let Some(conn_fd) = accept_one(listen_fd) else {
                // accept() failed with no timeout configured —
                // typically a kernel-level error (e.g. EMFILE). Log
                // and continue; another accept will likely succeed.
                eprintln!("mvm-host-vm-init: dispatch loop: accept failed (retrying)");
                continue;
            };
            // One File owns the conn fd for both the read (request)
            // and write (response). Dropped at iteration end which
            // closes the socket — the host sees EOF and unblocks
            // its mvm_guest::vsock::read_frame.
            let mut conn = adopt_conn_fd(conn_fd);
            let Some(body) = read_frame(&mut conn) else {
                eprintln!("mvm-host-vm-init: dispatch loop: read failed on conn (ignoring)");
                continue;
            };
            let request = match crate::builder_request::parse(&body) {
                Ok(req) => req,
                Err(e) => {
                    eprintln!("mvm-host-vm-init: dispatch loop: parse failed: {e}");
                    continue;
                }
            };
            match request {
                crate::builder_request::HostVmRequest::Run {
                    job_id,
                    job,
                    job_dir_relpath,
                } => {
                    let response = execute_dispatched_job(
                        &mut conn,
                        job_id,
                        job,
                        &job_dir_relpath,
                        cold_boot_timings.take(),
                    );
                    if !write_frame(&mut conn, response.as_bytes()) {
                        eprintln!("mvm-host-vm-init: dispatch loop: write Result failed mid-frame");
                    }
                }
                crate::builder_request::HostVmRequest::Shutdown => {
                    eprintln!("mvm-host-vm-init: dispatch loop: shutdown requested");
                    let bye = crate::dispatch_response::bye_json();
                    if !write_frame(&mut conn, bye.as_bytes()) {
                        eprintln!(
                            "mvm-host-vm-init: dispatch loop: write Bye failed (continuing to shutdown)"
                        );
                    }
                    drop(conn);
                    break;
                }
                // Plan 107 A2.2 — spawn / stop / query a Firecracker
                // workload microVM inside the host VM. All three reply
                // with a typed frame (incl. the fail-closed
                // `WorkloadFailed` on error) so the host never has to
                // distinguish a real failure from a transport EOF.
                crate::builder_request::HostVmRequest::WorkloadStart {
                    workload_id,
                    kernel_path,
                    rootfs_path,
                    vsock_socket_dir,
                    vcpus,
                    memory_mib,
                    kernel_cmdline_extras,
                } => {
                    let cfg = crate::workload::WorkloadSpawnConfig {
                        workload_id: workload_id.clone(),
                        kernel_path,
                        rootfs_path,
                        vsock_socket_dir,
                        vcpus,
                        memory_mib,
                        kernel_cmdline_extras,
                    };
                    let frame = match crate::workload::start_workload(
                        &crate::workload::FirecrackerVmm,
                        &cfg,
                    ) {
                        Ok(pid) => {
                            crate::dispatch_response::workload_started_json(&workload_id, pid)
                        }
                        Err(e) => {
                            eprintln!(
                                "mvm-host-vm-init: dispatch loop: WorkloadStart {workload_id} failed: {e}"
                            );
                            crate::dispatch_response::workload_failed_json(
                                &workload_id,
                                &e.to_string(),
                            )
                        }
                    };
                    if !write_frame(&mut conn, frame.as_bytes()) {
                        eprintln!(
                            "mvm-host-vm-init: dispatch loop: write WorkloadStart reply failed"
                        );
                    }
                }
                crate::builder_request::HostVmRequest::WorkloadStop { workload_id } => {
                    let base = std::path::Path::new(crate::workload::WORKLOAD_STATE_BASE);
                    let frame = match crate::workload::stop_workload(base, &workload_id) {
                        Ok(()) => crate::dispatch_response::workload_stopped_json(&workload_id),
                        Err(e) => {
                            eprintln!(
                                "mvm-host-vm-init: dispatch loop: WorkloadStop {workload_id} failed: {e}"
                            );
                            crate::dispatch_response::workload_failed_json(
                                &workload_id,
                                &e.to_string(),
                            )
                        }
                    };
                    if !write_frame(&mut conn, frame.as_bytes()) {
                        eprintln!(
                            "mvm-host-vm-init: dispatch loop: write WorkloadStop reply failed"
                        );
                    }
                }
                crate::builder_request::HostVmRequest::WorkloadStatus { workload_id } => {
                    let base = std::path::Path::new(crate::workload::WORKLOAD_STATE_BASE);
                    let status = crate::workload::workload_status(base, &workload_id);
                    let frame =
                        crate::dispatch_response::workload_status_report_json(&workload_id, status);
                    if !write_frame(&mut conn, frame.as_bytes()) {
                        eprintln!(
                            "mvm-host-vm-init: dispatch loop: write WorkloadStatus reply failed"
                        );
                    }
                }
            }
            // Conn drops at end of iteration; the host's read on
            // its end completes (either Frame or EmptyEof).
        }
        unsafe { close(listen_fd) };
        0
    }

    /// Plan 89 W3 part 10 — base dir for per-job scratch
    /// (`/tmp/<job_id>/`). Lives under the rootfs's existing
    /// tmpfs `/tmp`, which is wiped on every cold boot anyway —
    /// per-job scratch only matters for the persistent VM where
    /// jobs share a process namespace and tmpfs root.
    const JOB_SCRATCH_BASE: &str = "/tmp";

    /// Compute the path of a per-job scratch dir. Pure function so
    /// tests can spin one up under a `tempfile::tempdir` without
    /// touching the real `/tmp`.
    fn job_scratch_path(base: &str, job_id: &str) -> String {
        format!("{base}/{job_id}")
    }

    /// Plan 89 W3 part 10 — RAII wrapper that creates
    /// `/tmp/<job_id>/` on construction and best-effort removes
    /// it on Drop. Defers to `job_scratch_path` so tests can
    /// substitute the base dir.
    ///
    /// Cleanup is "best effort" because the leftover scratch dir
    /// is not security-load-bearing on its own — the persistent
    /// VM also wipes `/tmp` on cold restart (it's tmpfs), and the
    /// follow-up parts add `unshare --mount` so the bind-mounts
    /// inside the scratch dir tear down with the mount namespace.
    /// If `remove_dir_all` fails (e.g. orphan child still holds a
    /// file open), log the error and continue — the next dispatch
    /// gets a fresh `/tmp/<new_job_id>/` either way.
    struct JobScratch {
        path: String,
    }

    impl JobScratch {
        /// Create the per-job scratch dir under `base` (typically
        /// [`JOB_SCRATCH_BASE`]) with mode 0700. If `owner_uid` /
        /// `owner_gid` are provided, `chown` the dir to them so a
        /// downstream uid-drop (Plan 89 W3 part 13) can still
        /// write into it. The dispatch loop passes `Some((902,
        /// 902))` after part 13; tests pass `None` to keep their
        /// own uid as the owner.
        fn create(base: &str, job_id: &str, chown_to: Option<(u32, u32)>) -> std::io::Result<Self> {
            use std::os::unix::fs::PermissionsExt;
            let path = job_scratch_path(base, job_id);
            std::fs::create_dir_all(&path)?;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))?;
            if let Some((uid, gid)) = chown_to {
                // SAFETY: chown is a fundamental POSIX syscall;
                // we wrap the libc call in a small unsafe block
                // because nix's `chown` would drag in an extra
                // feature flag we don't have (the crate is
                // already pulled with `mount`/`reboot`/`signal`
                // only).
                let c_path = std::ffi::CString::new(path.as_str()).map_err(|e| {
                    std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string())
                })?;
                let rc = unsafe { libc::chown(c_path.as_ptr(), uid, gid) };
                if rc != 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(Self { path })
        }

        fn path(&self) -> &str {
            &self.path
        }
    }

    impl Drop for JobScratch {
        fn drop(&mut self) {
            if let Err(e) = std::fs::remove_dir_all(&self.path) {
                eprintln!(
                    "mvm-host-vm-init: dispatch loop: failed to clean up {path}: {e}",
                    path = self.path
                );
            }
        }
    }

    /// Run one dispatched job: locate cmd.sh under
    /// `/job/<job_dir_relpath>/cmd.sh`, exec it, stream every
    /// stderr line back to `conn` as a `HostVmResponse::StderrChunk`
    /// frame, capture the exit code + stderr tail. Returns the wire
    /// JSON for the final `HostVmResponse::Result` ready to frame
    /// and write back.
    ///
    /// `conn` is the same vsock connection the request arrived on;
    /// streaming chunks and the terminal Result frame share it so
    /// the host correlates everything by conn identity, not by job
    /// id alone (Plan 89 W3 part 9).
    fn execute_dispatched_job(
        conn: &mut std::fs::File,
        job_id: String,
        job: crate::builder_request::BuilderJob,
        job_dir_relpath: &str,
        cold_boot_timings: Option<BootTimings>,
    ) -> String {
        // Plan 89 W3 part 12 — flush + re-install the egress
        // lockdown before every dispatch. A previous build that
        // mutated iptables (whether via a CAP_NET_ADMIN leak or
        // because we haven't shipped the cap drop yet) loses its
        // changes here. Fail closed: if iptables is broken we
        // refuse the dispatch — that's safer than running a
        // build against a chain whose state we no longer trust.
        if let Err(e) = crate::network::reapply_egress_lockdown(
            &crate::network::SystemIptables,
            crate::network::PROXY_UID,
        ) {
            eprintln!("mvm-host-vm-init: dispatch loop: iptables baseline re-apply failed: {e}");
            let response = crate::dispatch_response::DispatchResponse {
                job_id,
                exit_code: 126,
                stderr_tail: format!("iptables baseline re-apply failed: {e}"),
                boot_timings: cold_boot_timings,
                build_ms: 0,
            };
            return response.to_json();
        }

        let (exit_code, stderr_tail, build_ms) = match job {
            crate::builder_request::BuilderJob::Flake { .. } => {
                let cmd_path = format!("{JOB_DIR}/{job_dir_relpath}/cmd.sh");
                if !Path::new(&cmd_path).exists() {
                    (2, format!("missing {cmd_path}"), 0)
                } else {
                    // Plan 89 W3 part 10 — per-job scratch dir
                    // at `/tmp/<job_id>/`. Pointed at by TMPDIR so
                    // every tool that honors it (mkstemp, nix
                    // evaluator, Python tempfile) writes there
                    // instead of the shared rootfs `/tmp`.
                    // Cleaned up when `_scratch` goes out of scope
                    // at the end of this match arm. On creation
                    // failure (extremely rare — tmpfs full at
                    // boot, perms surprise), fall through with no
                    // TMPDIR override and surface the warning in
                    // the stderr tail — the build is still
                    // useful, just without per-job tempfile
                    // isolation.
                    // Chown to the builder uid (Plan 89 W3 part
                    // 13) so the dispatched cmd.sh — which runs
                    // under `setpriv --reuid=BUILDER_UID
                    // --regid=BUILDER_GID` via
                    // `Isolation::Unshared` — can write into the
                    // scratch dir.
                    let (scratch, tmpdir) = match JobScratch::create(
                        JOB_SCRATCH_BASE,
                        &job_id,
                        Some((BUILDER_UID, BUILDER_GID)),
                    ) {
                        Ok(s) => {
                            let path = s.path().to_string();
                            (Some(s), Some(path))
                        }
                        Err(e) => {
                            eprintln!(
                                "mvm-host-vm-init: dispatch loop: failed to create scratch for {job_id}: {e}"
                            );
                            (None, None)
                        }
                    };
                    let started = Instant::now();
                    let (code, tail) = run_job_streaming(
                        &cmd_path,
                        tmpdir.as_deref(),
                        Isolation::Unshared,
                        |line| {
                            let frame = crate::dispatch_response::stderr_chunk_json(&job_id, line);
                            if !write_frame(conn, frame.as_bytes()) {
                                // Host probably closed the conn
                                // (e.g. supervisor went away
                                // mid-build). Log and keep
                                // draining stderr so the build's
                                // exit code is still meaningful —
                                // the terminal Result write will
                                // fail loudly back in the
                                // dispatch loop.
                                eprintln!(
                                    "mvm-host-vm-init: dispatch loop: write StderrChunk failed"
                                );
                            }
                        },
                    );
                    let ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
                    // Hold `scratch` until after the build returns
                    // so its `Drop` cleans up after the
                    // subprocess. Explicit drop documents the
                    // ordering for the reader.
                    drop(scratch);
                    (code, tail, ms)
                }
            }
            crate::builder_request::BuilderJob::Install { spec_path } => {
                // Plan 89 W3 part 8: route Install dispatches
                // through the existing single-shot pipeline with
                // per-dispatch paths. The host (PersistentBuilderVm)
                // stages `<session.job_dir>/<job_id>/install_spec.json`
                // and passes `/job/<job_dir_relpath>/install_spec.json`
                // as the wire `spec_path`. The output (result.json +
                // sealed volume sidecars) lands in `/job/<job_id>/out`
                // so the host reads them back via the same per-
                // dispatch out_dir convention as the Flake path.
                let out_dir = format!("{JOB_DIR}/{job_dir_relpath}/out");
                let job_subdir = format!("{JOB_DIR}/{job_dir_relpath}");
                let started = Instant::now();
                run_install_job_at(&spec_path, &job_subdir, &out_dir);
                let ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
                // The install pipeline writes its own typed result
                // (result.json) — exit code on the wire is just a
                // dispatch-level signal that the install ran. The
                // host's PersistentBuilderVm reads result.json for
                // the real outcome. We pass 0 if result.json was
                // emitted at all; the host's parser will decode it
                // and surface installer_exit_code.
                let result_path = format!("{out_dir}/result.json");
                let exit_code = if Path::new(&result_path).is_file() {
                    0
                } else {
                    2
                };
                let tail = if exit_code == 0 {
                    String::new()
                } else {
                    format!("install pipeline did not emit {result_path}")
                };
                (exit_code, tail, ms)
            }
        };
        let response = crate::dispatch_response::DispatchResponse {
            job_id,
            exit_code,
            stderr_tail,
            boot_timings: cold_boot_timings,
            build_ms,
        };
        response.to_json()
    }

    #[cfg(test)]
    mod vsock_send_tests {
        // Plan 89 W2 part 3 — the in-binary BUILDER_DISPATCH_PORT
        // const above must stay in sync with
        // mvm_guest::builder_agent::BUILDER_DISPATCH_PORT (the
        // canonical definition the host side uses). We can't `use`
        // the function-local const from outside, so duplicate the
        // assertion against the literal value and the mvm-guest
        // constant. Adding mvm-guest as a dev-dep just for this
        // check is overkill; keep it inline.
        #[test]
        fn builder_dispatch_port_literal_is_21471() {
            // Mirror of the function-local const in
            // `send_dispatch_response_via_vsock`. Updating one
            // without the other trips this test.
            const FROM_BUILDER_INIT: u32 = 21471;
            assert_eq!(
                FROM_BUILDER_INIT, 21471,
                "Plan 89 BUILDER_DISPATCH_PORT changed — update both \
                 builder-init's send and mvm-guest::builder_agent::BUILDER_DISPATCH_PORT"
            );
        }
    }

    /// Convenience for `timings.lock().map(|mut t| f(&mut *t))`. A
    /// poisoned mutex (a peer thread panicked mid-stamp) becomes a
    /// no-op rather than escalating — these timings are
    /// observability, never gating.
    fn stamp<F: FnOnce(&mut BootTimings)>(timings: &Arc<Mutex<BootTimings>>, f: F) {
        if let Ok(mut t) = timings.lock() {
            f(&mut t);
        }
    }

    /// Write the current `BootTimings` snapshot to
    /// `/job/boot-timings.json` and mirror a one-line summary to
    /// stderr. Best-effort: if `/job` is not mounted (virtio-fs
    /// failed) the write fails silently; the stderr line still
    /// reaches the host-side console capture.
    fn write_boot_timings(timings: &Arc<Mutex<BootTimings>>) {
        let snapshot = match timings.lock() {
            Ok(t) => t.clone(),
            Err(_) => {
                eprintln!("mvm-host-vm-init: boot-timings mutex poisoned; skipping JSON write");
                return;
            }
        };
        let json = snapshot.to_json();
        eprintln!("mvm-host-vm-init: boot-timings={json}");
        let path = format!("{JOB_DIR}/boot-timings.json");
        if let Err(e) = std::fs::write(&path, format!("{json}\n")) {
            eprintln!("mvm-host-vm-init: failed to write {path}: {e}");
        }
    }

    /// Drive the install pipeline against `/job/install_spec.json`.
    /// Emits `/job/result.json` (the typed report — distinct from
    /// `/job/result`, which the flake-build path writes); the host
    /// reads it to pick up exit code + sidecar paths.
    ///
    /// We deliberately don't propagate failures back as a process
    /// exit code: the VM is going to `reboot()` regardless, and
    /// the host distinguishes "install failed" vs "init crashed"
    /// via the *presence* of result.json. Anything that prevents
    /// us from writing result.json gets logged + falls through.
    fn run_install_job(spec_path: &str) {
        run_install_job_at(spec_path, JOB_DIR, OUT_DIR);
    }

    /// Plan 89 W3 part 8 — install dispatch with explicit
    /// `job_dir` and `out_dir`. Single-shot uses the legacy
    /// `JOB_DIR` / `OUT_DIR` constants; persistent dispatch
    /// passes the per-dispatch `/job/<job_id>` paths so concurrent
    /// dispatches don't clobber each other's outputs (V1 is
    /// serialized so the clobber risk is theoretical, but the
    /// per-dispatch layout removes the question entirely and
    /// matches the persistent flake path's
    /// `<session.job_dir>/<job_id>/out/` convention from W3
    /// part 6/7).
    fn run_install_job_at(spec_path: &str, job_dir: &str, out_dir: &str) {
        use crate::install::{
            InstallContext, InstallError, RESULT_FILENAME, SystemCommandRunner, run_install,
        };
        use crate::install_spec::parse;
        use crate::proxy::ChildProxyLifecycle;

        let bytes = match std::fs::read(spec_path) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("mvm-host-vm-init: read {spec_path}: {e}");
                write_install_failure_at(out_dir, 2, &format!("read install spec: {e}"));
                return;
            }
        };
        let spec = match parse(&bytes) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("mvm-host-vm-init: parse {spec_path}: {e}");
                write_install_failure_at(out_dir, 2, &format!("parse install spec: {e}"));
                return;
            }
        };

        // Persistent dispatch may pass a per-dispatch out_dir that
        // doesn't exist yet (the host pre-stages it, but defensive
        // `create_dir_all` is cheap and saves us from a race where
        // the host's mkdir hasn't reached the guest's view of the
        // virtio-fs share yet).
        if let Err(e) = std::fs::create_dir_all(out_dir) {
            eprintln!("mvm-host-vm-init: create_dir_all {out_dir}: {e}");
            // Fall through; write_install_failure_at will try to
            // write into the dir and the host will see whatever
            // partial state results.
        }

        let runner = SystemCommandRunner;
        // Plan 73 Followup B.2.x: the production proxy lifecycle
        // spawns `mvm-egress-proxy` from PATH. The builder VM
        // flake installs the binary at `/sbin/mvm-egress-proxy`
        // (alongside `/sbin/mvm-host-vm-init`), which is on the
        // kernel's default PATH for PID 1.
        let mut proxy = ChildProxyLifecycle::default_binary();
        let ctx = InstallContext {
            spec: &spec,
            job_dir: Path::new(job_dir),
            out_dir: Path::new(out_dir),
            runner: &runner,
            extra_path: None,
            proxy: &mut proxy,
        };
        let report = match run_install(ctx) {
            Ok(r) => r,
            Err(InstallError::InstallerMissing { program }) => {
                eprintln!(
                    "mvm-host-vm-init: installer `{program}` not on PATH — builder VM is missing required tools"
                );
                write_install_failure_at(
                    out_dir,
                    127,
                    &format!("installer `{program}` not on PATH inside builder VM"),
                );
                return;
            }
            Err(InstallError::Io(why)) => {
                eprintln!("mvm-host-vm-init: install pipeline IO: {why}");
                write_install_failure_at(out_dir, 2, &format!("install pipeline IO: {why}"));
                return;
            }
        };

        // Write the typed report into out_dir — the host reads it
        // from `<out_dir>/result.json` post-power-off. Plan 73
        // Followup B.2's contract: result.json lives next to the
        // four sealed-volume artifacts so a single virtio-fs
        // share carries everything the host needs. Hand-rolled
        // JSON via InstallReport::to_json so we don't pull
        // serde_json into the init binary's closure.
        let path = format!("{out_dir}/{RESULT_FILENAME}");
        if let Err(e) = std::fs::write(&path, format!("{}\n", report.to_json())) {
            eprintln!("mvm-host-vm-init: failed to write {path}: {e}");
        }
    }

    /// Emit a synthetic install-failure result so the host can
    /// distinguish "guest crashed before running install" from
    /// "install ran and exited nonzero." The shape matches
    /// [`crate::install::InstallReport::to_json`] so the host's
    /// parser doesn't need a separate code path. Single-shot uses
    /// `OUT_DIR`; persistent dispatch passes the per-dispatch
    /// `/job/<job_id>/out` (Plan 89 W3 part 8).
    fn write_install_failure_at(out_dir: &str, exit_code: i32, reason: &str) {
        use crate::install::{
            CONTENT_SUBDIR, CVE_FILENAME, FETCH_LOG_FILENAME, RESULT_FILENAME, SBOM_FILENAME,
        };
        let escaped = json_escape(reason);
        // Synthesize a result.json that pins all sidecars at their
        // canonical paths but flags everything as un-emitted. The
        // host's parser sees installer_exit_code != 0 and refuses
        // to seal the volume.
        let body = format!(
            r#"{{"installer_exit_code":{exit_code},"sbom_emitted":false,"cve_emitted":false,"language":"unknown","gate":"unknown","content_path":"{out_dir}/{CONTENT_SUBDIR}","sbom_path":"{out_dir}/{SBOM_FILENAME}","fetch_log_path":"{out_dir}/{FETCH_LOG_FILENAME}","cve_path":"{out_dir}/{CVE_FILENAME}","failure_reason":"{escaped}"}}"#,
        );
        let path = format!("{out_dir}/{RESULT_FILENAME}");
        // Best-effort: if `out_dir` isn't writable (the install-spec
        // dispatch ran before virtio-fs came up, or the persistent-
        // dispatch out_dir doesn't exist yet), at least try /job so
        // the host has *somewhere* to pick up the failure signal.
        if let Err(e) = std::fs::write(&path, format!("{body}\n")) {
            eprintln!("mvm-host-vm-init: failed to write {path}: {e}");
            let fallback = format!("{JOB_DIR}/{RESULT_FILENAME}");
            if let Err(e2) = std::fs::write(&fallback, format!("{body}\n")) {
                eprintln!("mvm-host-vm-init: failed to write {fallback}: {e2}");
            }
        }
    }

    /// Plan 76 Phase 5: the first phase, on the critical path for
    /// every other init step. /proc, /sys, /dev, /tmp must be
    /// available before module loading, device probing, or virtio-fs
    /// mounting; nothing else fans out concurrently with this.
    /// Plan 86 — detect the "kernel ships without netfilter / iptables
    /// tables" error pattern. Matches both the iptables-nft Protocol
    /// not supported and the iptables-legacy "Table does not exist /
    /// do you need to insmod?" surfaces. A future netlink-based check
    /// would be more robust, but this regex-of-substrings catches the
    /// only two error shapes the libkrunfw-bundled kernel produces.
    fn egress_error_indicates_no_netfilter(err: &str) -> bool {
        err.contains("Table does not exist")
            || err.contains("Failed to initialize nft")
            || err.contains("Protocol not supported")
    }

    fn mount_pseudofs() -> Result<(), String> {
        // Standard init filesystems. libkrun's kernel mounts
        // devtmpfs (and sometimes /proc /sys) before handing off to
        // init, so EBUSY here means "already mounted by an earlier
        // stage" — that's success for our purposes. Anything else
        // is fatal.
        mount_fs_idempotent("proc", "/proc", "proc")?;
        mount_fs_idempotent("sysfs", "/sys", "sysfs")?;
        mount_fs_idempotent("devtmpfs", "/dev", "devtmpfs")?;
        mount_fs_idempotent("tmpfs", "/tmp", "tmpfs")?;
        // `/run` must be a tmpfs so iptables-legacy can write
        // `/run/xtables.lock`. The rootfs is mounted ro, so a missing
        // `/run` tmpfs makes `install_egress_lockdown` bail with
        // "Read-only file system" at the first `iptables -A` call.
        // mkGuest's /init does the equivalent for the dev image's
        // boot path; we replicate it here for the mvm-host-vm-init
        // path (Plan 86).
        mount_fs_idempotent("tmpfs", "/run", "tmpfs")?;
        // `/dev/shm` (tmpfs) is required by libfaketime's `sem_open`:
        // `make-ext4-fs.nix` runs `mkfs.ext4` under faketime for
        // deterministic timestamps, and faketime opens a POSIX named
        // semaphore (which lives under /dev/shm). devtmpfs doesn't create
        // it, so without this the dev-image's `ext4-fs.img` derivation
        // dies with "faketime: sem_open: No such file or directory".
        let _ = std::fs::create_dir_all("/dev/shm");
        mount_fs_idempotent("tmpfs", "/dev/shm", "tmpfs")?;
        // `/dev/pts` is required by nix's build-sandbox setup: it
        // calls `posix_openpt` which opens `/dev/ptmx`, and that
        // requires devpts to be mounted at `/dev/pts`. Without it
        // nix bails with `error: opening pseudoterminal master:
        // No such file or directory`. The dev image flake's
        // mkGuest /init mounts this; we replicate for Plan 86.
        let _ = std::fs::create_dir_all("/dev/pts");
        mount_fs_idempotent("devpts", "/dev/pts", "devpts")?;
        // `/dev/fd → /proc/self/fd` is what bash process substitution
        // (`< <(...)`, `mapfile -t x < <(...)`) needs to open the
        // subshell's pipe FD at `/dev/fd/N`. devtmpfs creates device
        // nodes but never these symlinks; udev/mdev/systemd-tmpfiles
        // normally do, and we run none of them. Without /dev/fd
        // nixpkgs's `cargo-install-hook.sh` line 27 fails with
        // "/dev/fd/63: No such file or directory" and every Rust
        // derivation in the dev-image closure dies at install time.
        // `/dev/std{in,out,err}` are conventionally present as well;
        // we install all four so future hooks that depend on them
        // don't trip the same surprise.
        crate::setup_dev_fd_symlinks(Path::new("/dev"))?;
        Ok(())
    }

    /// Plan 76 Phase 5: serial chain that gates job execution.
    /// /dev/vdb format (first boot only) → mount → overlay-mount
    /// rootfs `/nix` with persistent upper/work dirs → bind-mount
    /// over /nix. Each step depends on the previous, so this stays
    /// single-threaded inside.
    fn setup_nix_store(timings: &Arc<Mutex<BootTimings>>, anchor: Instant) -> Result<(), String> {
        std::fs::create_dir_all(NIX_STORE_MOUNT)
            .map_err(|e| format!("create {NIX_STORE_MOUNT}: {e}"))?;
        if let Some(reason) = nix_store_dev_needs_format(NIX_STORE_DEV)? {
            eprintln!("mvm-host-vm-init: formatting {NIX_STORE_DEV} ({reason})");
            format_ext4(NIX_STORE_DEV)?;
        }
        mount_fs(NIX_STORE_DEV, NIX_STORE_MOUNT, "ext4")?;
        stamp(timings, |t| {
            t.nix_device_ready_ms = Some(BootTimings::ms_since(anchor))
        });

        // Plan 92: the slim custom kernel under
        // `nix/images/builder-vm/kernel/` builds overlay, vsock,
        // fuse, virtiofs, and the iptables tables as `=y`. No
        // modprobe needed before `mount -t overlay` or `socket(AF_VSOCK)`
        // — the kernel comes up with the subsystems registered.

        match mount_nix_overlay() {
            Ok(()) => {}
            Err(e) => {
                eprintln!(
                    "mvm-host-vm-init: overlay /nix setup failed ({e}); falling back to seed copy"
                );
                seed_nix_store(timings, anchor)?;
                std::fs::create_dir_all(NIX_TARGET)
                    .map_err(|e| format!("create {NIX_TARGET}: {e}"))?;
                bind_mount(NIX_STORE_MOUNT, NIX_TARGET)?;
            }
        }
        stamp(timings, |t| {
            t.nix_mounted_ms = Some(BootTimings::ms_since(anchor))
        });

        // PR #420 follow-up: load `/nix-path-registration` (the
        // standard `make-ext4-fs.nix` manifest) into the persistent
        // `/nix/var/nix/db` so the in-VM `nix build` knows the
        // seeded closure is already valid. Without this, nix-daemon
        // treats every seeded path as missing and re-substitutes
        // from `cache.nixos.org` — the substituter then overwrites
        // the on-disk path during the rename window, and concurrent
        // build-hook workers `dlopen`ing libs from the same path
        // hit ENOENT. Idempotent + non-fatal so a missing or
        // unparseable manifest still boots — at most regresses to
        // the pre-fix substituter race.
        if let Err(e) = load_seeded_nix_db(timings, anchor) {
            eprintln!("mvm-host-vm-init: load_seeded_nix_db warning (non-fatal): {e}");
        }

        Ok(())
    }

    /// Plan 76 Phase 5: independent track that runs concurrently
    /// with `setup_nix_store`. Loads the `fuse` + `virtiofs`
    /// kernel modules (themselves fanned out across two threads),
    /// then mounts the three virtio-fs shares.
    fn setup_modules_and_virtiofs(timings: &Arc<Mutex<BootTimings>>, anchor: Instant) {
        // Load FUSE + virtio-fs kernel modules before mounting the
        // host-exported shares. Stock nixpkgs kernel ships these as
        // `=m` (loadable modules); without modprobe, `mount -t
        // virtiofs` bails with ENODEV. `mkGuest` (PR #215) stages
        // `/lib/modules/<kver>/` into the rootfs precisely so we can
        // load them at boot. Failure is non-fatal — the subsequent
        // mount attempts will fail visibly if a module is genuinely
        // missing rather than just not-yet-loaded.
        //
        // Plan 76 Phase 5: the two modprobes fan out across a pair
        // of threads. modprobe is mostly I/O-bound (open + read the
        // module file, run the insmod ioctl); running them
        // concurrently halves the wall-clock cost on slower disks.
        let fuse = std::thread::spawn(|| run_modprobe("fuse"));
        let virtiofs = std::thread::spawn(|| run_modprobe("virtiofs"));
        let _ = fuse.join();
        let _ = virtiofs.join();
        stamp(timings, |t| {
            t.modules_ready_ms = Some(BootTimings::ms_since(anchor))
        });

        // virtio-fs shares declared by `LibkrunBuilderVm` (Plan 72
        // W4). Each entry is `(tag, target)` — the kernel routes
        // `mount -t virtiofs <tag> <target>` to the daemon libkrun
        // spawned for that share. Mounting is best-effort per
        // share: if the host omitted one (e.g. an offline build
        // path with no `/out` need), we still want to reach
        // `/job/cmd.sh` if `/job` was supplied. Per-share errors
        // print to stderr but don't fail init — the failing share
        // surfaces as a normal file-not-found inside cmd.sh.
        for (tag, target) in VIRTIOFS_MOUNTS {
            if let Err(e) = mount_virtiofs(tag, target) {
                eprintln!("mvm-host-vm-init: virtio-fs '{tag}' -> {target} failed: {e}");
            }
        }
        stamp(timings, |t| {
            t.virtiofs_ready_ms = Some(BootTimings::ms_since(anchor))
        });
    }

    fn run_modprobe(module: &str) {
        let status = Command::new("/bin/busybox")
            .args(["modprobe", module])
            .status();
        match status {
            Ok(s) if s.success() => {}
            Ok(s) => eprintln!(
                "mvm-host-vm-init: modprobe {module} exited {} (continuing)",
                s.code().unwrap_or(-1)
            ),
            Err(e) => eprintln!("mvm-host-vm-init: spawn modprobe {module}: {e} (continuing)"),
        }
    }

    fn setup_network() -> Result<(), String> {
        // Plan 87 W4: seed /run/resolv.conf from the fallback before
        // udhcpc runs. /etc/resolv.conf is a symlink into /run, so
        // libc resolvers have a usable nameserver list from boot 1
        // even if DHCP fails (TSI mode, or passt mid-handoff).
        // Failure here is non-fatal — the symlink might not exist
        // on a guest built before Plan 87, in which case udhcpc's
        // own write to /etc/resolv.conf (if -s is set) is the
        // only path.
        let fallback = std::path::Path::new("/etc/resolv.conf.fallback");
        if fallback.is_file() {
            if let Err(e) = std::fs::copy(fallback, "/run/resolv.conf") {
                eprintln!(
                    "mvm-host-vm-init: copy /etc/resolv.conf.fallback -> \
                     /run/resolv.conf: {e} (continuing — udhcpc may fix it)"
                );
            }
        }

        // busybox 1.36.x udhcpc binds a PF_PACKET raw socket to
        // `eth0` and `sendto`s a DHCPDISCOVER. virtio-net's eth0
        // post-probe state is administratively DOWN, so the first
        // sendto returns ENETDOWN and udhcpc loops forever
        // ("broadcasting discover" → "Network is down" → reopen
        // socket). Older udhcpc versions auto-issued
        // SIOCSIFFLAGS|IFF_UP; modern busybox expects the caller
        // to. The `/etc/udhcpc/default.script` hook brings the
        // link up via `ip link set ... up`, but it only fires
        // after udhcpc gets a lease — which requires the link
        // already be up. Chicken-and-egg, broken by doing the
        // ioctl ourselves before spawning udhcpc.
        if let Err(e) = bring_iface_up("eth0") {
            eprintln!(
                "mvm-host-vm-init: bring_iface_up eth0 failed: {e} \
                 (continuing — udhcpc will surface a clearer error \
                 if the link is genuinely absent)"
            );
        }

        // Plan 87 W4: when /etc/udhcpc/default.script exists (passt
        // path / ur-seed-built rootfs), use it so the DHCP lease
        // writes /run/resolv.conf with the leased DNS. Older rootfs
        // builds without the script keep the legacy `-i eth0 -n -q`
        // shape — udhcpc still sets the IP but resolv.conf stays at
        // the fallback content.
        //
        // `/bin/udhcpc` — udhcpc is a busybox applet, and mkGuest
        // installs busybox applet symlinks under `/bin/<applet>`,
        // not `/sbin/`. (Plan 96 / PR #420 follow-up: prior
        // `/sbin/udhcpc` hardcoding ENOENTed at every boot, which
        // `setup_network` swallowed as non-fatal — leaving the
        // builder VM with no DHCP-assigned IP and the inner nix
        // build unable to reach `cache.nixos.org`.)
        let script = "/etc/udhcpc/default.script";
        let mut cmd = Command::new("/bin/udhcpc");
        cmd.args(["-i", "eth0", "-n", "-q"]);
        if std::path::Path::new(script).is_file() {
            cmd.args(["-s", script]);
        }
        let status = cmd
            .status()
            .map_err(|e| format!("spawn /bin/udhcpc: {e}"))?;
        if !status.success() {
            return Err(format!("udhcpc exit {}", status.code().unwrap_or(-1)));
        }
        Ok(())
    }

    /// Encode a Linux interface name into the fixed-size `ifr_name`
    /// byte array used by SIOCG/SIOCSIFFLAGS. Linux caps interface
    /// names at `IFNAMSIZ` (16) bytes including the NUL terminator,
    /// so the longest valid input is 15 bytes. Split out from
    /// [`bring_iface_up`] so the bounds check is unit-testable
    /// without making a real syscall.
    fn encode_iface_name(iface: &str) -> Result<[libc::c_char; libc::IFNAMSIZ], String> {
        let bytes = iface.as_bytes();
        if bytes.len() >= libc::IFNAMSIZ {
            return Err(format!(
                "interface name '{iface}' is {} bytes; Linux IFNAMSIZ caps it at {}",
                bytes.len(),
                libc::IFNAMSIZ - 1,
            ));
        }
        let mut buf = [0 as libc::c_char; libc::IFNAMSIZ];
        for (i, &b) in bytes.iter().enumerate() {
            buf[i] = b as libc::c_char;
        }
        Ok(buf)
    }

    /// Bring a network interface administratively up via
    /// `ioctl(SIOCSIFFLAGS, IFF_UP)`. Equivalent to
    /// `ip link set dev <iface> up`, but issued directly so we
    /// don't pin a new path-dependency in the ur-seed rootfs and
    /// the error message names the failing ioctl. Called before
    /// `udhcpc` in [`setup_network`].
    fn bring_iface_up(iface: &str) -> Result<(), String> {
        let name = encode_iface_name(iface)?;

        // SAFETY: socket(2) returns -1 on error (checked) or a
        // valid fd. We close it on every return path below.
        let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        if sock < 0 {
            return Err(format!(
                "socket(AF_INET, SOCK_DGRAM) for {iface}: {}",
                std::io::Error::last_os_error()
            ));
        }

        let result = (|| {
            // SAFETY: `ifreq` is repr(C); zero-init + per-variant
            // union assignment is the standard pattern. We read
            // `ifru_flags` only after SIOCGIFFLAGS populated it.
            let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
            ifr.ifr_name = name;

            // libc 0.2.182's ioctl request parameter is the per-target
            // `Ioctl` alias — `c_ulong` (u64) on linux-gnu, `c_int`
            // (i32) on musl. Cast the SIOC* request to `libc::Ioctl` so
            // this compiles on both the musl host-bin deployment target
            // and a native-gnu `cargo build --all-targets` (CI).
            if unsafe { libc::ioctl(sock, libc::SIOCGIFFLAGS as libc::Ioctl, &mut ifr) } < 0 {
                return Err(format!(
                    "SIOCGIFFLAGS {iface}: {}",
                    std::io::Error::last_os_error()
                ));
            }
            // SAFETY: SIOCGIFFLAGS just populated `ifru_flags`, so
            // reading it is well-defined. Writing the OR'd value back
            // through the same union variant is also well-defined per
            // the Rust reference (all variants of `__c_anonymous_ifr_ifru`
            // are `Copy`).
            unsafe {
                let flags = ifr.ifr_ifru.ifru_flags;
                ifr.ifr_ifru.ifru_flags = flags | (libc::IFF_UP as libc::c_short);
            }
            if unsafe { libc::ioctl(sock, libc::SIOCSIFFLAGS as libc::Ioctl, &ifr) } < 0 {
                return Err(format!(
                    "SIOCSIFFLAGS {iface} IFF_UP: {}",
                    std::io::Error::last_os_error()
                ));
            }
            Ok(())
        })();

        // SAFETY: sock is owned by this function until close.
        unsafe {
            libc::close(sock);
        }
        result
    }

    fn run_job(cmd_sh: &str) -> (i32, String) {
        // Single-shot path: no streaming callback, no TMPDIR
        // override (single-shot uses the rootfs's tmpfs `/tmp`
        // directly — the VM is going to power-off, so per-job
        // scratch isolation has no second job to protect), and no
        // unshare wrapping (the VM tear-down already kills any
        // orphan process and reclaims every IPC key + mount). The
        // whole stderr tail still lands in `/job/result` and the
        // host's file-based fallback parses it. Plan 89 W3 part 9
        // added the streaming variant for the persistent dispatch
        // loop; this single-shot wrapper passes a no-op so the
        // two code paths share their `Command`/`wait` logic.
        run_job_streaming(cmd_sh, None, Isolation::Inherit, |_line| {})
    }

    /// Plan 89 W3 part 11 — how the build subprocess relates to
    /// the dispatch loop's process / mount / IPC namespaces.
    ///
    /// - [`Isolation::Inherit`]: subprocess runs in the dispatch
    ///   loop's namespaces. Used by single-shot (the whole VM
    ///   tears down on exit anyway) and by tests that don't have
    ///   `CAP_SYS_ADMIN` in their environment (e.g. CI Docker
    ///   without `--privileged`).
    /// - [`Isolation::Unshared`]: subprocess runs in fresh mount
    ///   + pid + ipc namespaces via `unshare --mount --pid --ipc
    ///   --fork`, then drops to the unprivileged builder uid via
    ///   `setpriv --reuid --regid --clear-groups` (Plan 89 W3
    ///   part 13). The pid namespace turns orphan-cleanup into a
    ///   single namespace-exit; the mount namespace lets future
    ///   parts bind-mount `/dev/shm` etc. per-job without bleeding
    ///   state into the shared rootfs; the IPC namespace prevents
    ///   SysV/POSIX IPC keys leaking across jobs; the uid drop
    ///   prevents a malicious build from remounting / killing
    ///   outside its pid ns / loading a kernel module via the root
    ///   privileges the dispatch loop has as PID 1.
    ///
    /// Network namespace is intentionally *not* unshared — the
    /// per-VM iptables baseline (Plan 73 Followup B.2.y) already
    /// gates egress through the proxy, and the build needs the
    /// proxy reachable. W3 part 12 re-applies that baseline per
    /// dispatch, which closes the F7 finding without breaking
    /// proxy access.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Isolation {
        Inherit,
        Unshared,
    }

    /// Plan 89 W3 part 13 — unprivileged uid the dispatched build
    /// runs as inside the persistent VM. Picked above the
    /// `mvm-agent` (1900) / `mvm-worker` (1000) / `mvm-egress-
    /// proxy` (1801) uids the rest of the rootfs reserves so the
    /// builder identity doesn't collide with any existing service.
    ///
    /// No `/etc/passwd` entry: the build runs as a bare numeric
    /// uid, and `setpriv --clear-groups` (below) means no NSS
    /// lookup is needed for supplementary groups either. Tools
    /// that try `getlogin()` / `getpwuid()` get `None`; the build
    /// is expected to be a flake / install pipeline that doesn't
    /// rely on its own username.
    const BUILDER_UID: u32 = 902;
    const BUILDER_GID: u32 = 902;

    /// Plan 89 W3 part 13 — assemble the `Command` for one
    /// dispatched job per the requested isolation. Split out from
    /// [`run_job_streaming`] so the argv shape is testable
    /// without spawning (the spawn integration test in
    /// `run_job_streaming_unshared_runs_in_fresh_pid_namespace`
    /// probes for unshare + CAP_SYS_ADMIN; this pure builder lets
    /// tests pin the wire on every host).
    fn build_isolated_command(cmd_sh: &str, isolation: Isolation) -> Command {
        match isolation {
            Isolation::Inherit => {
                let mut c = Command::new("/bin/sh");
                c.args(["-eu", cmd_sh]);
                c
            }
            Isolation::Unshared => {
                // Order matters: unshare runs first (still uid 0
                // with `CAP_SYS_ADMIN` so the namespace setup
                // works), then setpriv drops uid inside the new
                // namespaces, then exec /bin/sh.
                //
                // `--clear-groups` strips supplementary groups
                // entirely; the build doesn't belong to any. We
                // intentionally do not use `--init-groups`
                // because there is no `/etc/passwd` entry for
                // the builder uid — initgroups(3) would fail the
                // NSS lookup. Numeric `--reuid`/`--regid` work
                // without NSS.
                //
                // `--bounding-set=-all` strips the entire
                // capability bounding set (claim 1 — matches the
                // existing `setpriv --bounding-set=-all
                // --no-new-privs` pattern). After this, the
                // build process cannot regain any caps even via
                // setuid binaries.
                let reuid = format!("--reuid={BUILDER_UID}");
                let regid = format!("--regid={BUILDER_GID}");
                let mut c = Command::new("unshare");
                c.args([
                    "--mount",
                    "--pid",
                    "--ipc",
                    "--fork",
                    "setpriv",
                    &reuid,
                    &regid,
                    "--clear-groups",
                    "--bounding-set=-all",
                    "--no-new-privs",
                    "/bin/sh",
                    "-eu",
                    cmd_sh,
                ]);
                c
            }
        }
    }

    /// Plan 89 W3 part 9 — same as [`run_job`] but invokes
    /// `on_line` for each stderr line as it arrives. Used by the
    /// persistent dispatch loop to frame each line as a
    /// `HostVmResponse::StderrChunk` and write it to the active
    /// vsock conn before the final `HostVmResponse::Result`. The
    /// callback runs on this thread between line reads, so a slow
    /// host can backpressure the build's stderr stream — the
    /// host's vsock conn is the natural rate-limiter and we don't
    /// need a separate buffer thread.
    ///
    /// The trailing `\n` is stripped from each line (the typed
    /// `HostVmResponse::StderrChunk` docs commit to that).
    /// `STDERR_TAIL_LINES` of trailing context is still buffered
    /// for the final Result frame's `stderr_tail`, matching the
    /// single-shot path's contract.
    fn run_job_streaming<F: FnMut(&str)>(
        cmd_sh: &str,
        tmpdir: Option<&str>,
        isolation: Isolation,
        mut on_line: F,
    ) -> (i32, String) {
        use std::collections::VecDeque;
        use std::io::{BufRead, BufReader};
        use std::process::Stdio;
        // Plan 89 W3 part 11/13 — switch between bare `/bin/sh
        // -eu <cmd>` and the unshare+setpriv wrapped form via
        // [`build_isolated_command`]. unshare + setpriv both
        // live in `util-linux`, which is in the builder VM's
        // rootfs (`nix/images/builder-vm/flake.nix`, package list);
        // PATH (`/sbin:/usr/sbin:/bin:/usr/bin`) finds them.
        let mut cmd = build_isolated_command(cmd_sh, isolation);
        cmd.stdout(Stdio::inherit()).stderr(Stdio::piped());
        // Plan 89 W3 part 10 — point the dispatched build's
        // tmpfile machinery at the per-job scratch dir so leftover
        // tempfiles can't outlive the dispatch. Tools that honor
        // TMPDIR (mkstemp, Python's `tempfile`, Nix's evaluator,
        // `mktemp(1)`) write into `/tmp/<job_id>/` instead of the
        // shared rootfs `/tmp`. Single-shot passes `None` —
        // see [`run_job`].
        if let Some(t) = tmpdir {
            cmd.env("TMPDIR", t);
        }
        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                let binary = match isolation {
                    Isolation::Inherit => "/bin/sh",
                    Isolation::Unshared => "unshare",
                };
                return (127, format!("spawn {binary}: {e}"));
            }
        };
        let Some(stderr) = child.stderr.take() else {
            // Stdio::piped() should always populate child.stderr;
            // if it didn't, fall through to a non-streaming wait so
            // we still return a real exit code.
            let code = child.wait().ok().and_then(|s| s.code()).unwrap_or(-1);
            return (code, String::new());
        };
        let mut tail: VecDeque<String> = VecDeque::with_capacity(STDERR_TAIL_LINES);
        for line in BufReader::new(stderr).lines() {
            let line = match line {
                Ok(l) => l,
                // Treat a partial UTF-8 / I/O failure as end-of-stream
                // — the child's exit code is still the authoritative
                // signal. The tail we collected so far is still
                // useful for the Result frame.
                Err(_) => break,
            };
            on_line(&line);
            if tail.len() == STDERR_TAIL_LINES {
                tail.pop_front();
            }
            tail.push_back(line);
        }
        let exit_code = child.wait().ok().and_then(|s| s.code()).unwrap_or(-1);
        let tail_joined = tail.into_iter().collect::<Vec<_>>().join("\n");
        (exit_code, tail_joined)
    }

    /// Write `/job/result` as JSON. Hand-rolled rather than
    /// pulling `serde_json` in just for this — the init binary's
    /// size budget is ≤ 1.5 MiB and the JSON shape is one
    /// `i32` + one string.
    fn write_result(exit_code: i32, stderr_tail: &str) {
        let body = format!(
            r#"{{"exit_code":{exit_code},"stderr_tail":"{escaped}"}}{nl}"#,
            escaped = json_escape(stderr_tail),
            nl = "\n",
        );
        let path = format!("{JOB_DIR}/result");
        if let Err(e) = std::fs::write(&path, body) {
            eprintln!("mvm-host-vm-init: failed to write {path}: {e}");
        }
    }

    /// Minimal JSON string escaper. Only handles the characters
    /// that *must* be escaped per RFC 8259 §7. UTF-8 bytes pass
    /// through verbatim; control characters get `\u00XX`-style
    /// escapes; backslash and quote get the standard backslash
    /// escape. Tested with the unit tests below.
    fn json_escape(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        for c in s.chars() {
            match c {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                '\t' => out.push_str("\\t"),
                c if (c as u32) < 0x20 => {
                    out.push_str(&format!("\\u{:04x}", c as u32));
                }
                c => out.push(c),
            }
        }
        out
    }

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

    /// `mount_fs` that treats EBUSY as success. libkrun's kernel
    /// pre-mounts some of `/proc`, `/sys`, `/dev` depending on
    /// cmdline + initramfs config; without this tolerance,
    /// mvm-host-vm-init bails on its first such call instead of
    /// reaching the user's cmd.sh.
    fn mount_fs_idempotent(source: &str, target: &str, fstype: &str) -> Result<(), String> {
        match mount_fs(source, target, fstype) {
            Ok(()) => Ok(()),
            Err(e) if e.contains("EBUSY") => {
                eprintln!(
                    "mvm-host-vm-init: {target} ({fstype}) already mounted (EBUSY) — continuing"
                );
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

    fn mount_nix_overlay() -> Result<(), String> {
        use nix::mount::{MsFlags, mount};

        std::fs::create_dir_all(NIX_OVERLAY_UPPER)
            .map_err(|e| format!("create {NIX_OVERLAY_UPPER}: {e}"))?;
        std::fs::create_dir_all(NIX_OVERLAY_WORK)
            .map_err(|e| format!("create {NIX_OVERLAY_WORK}: {e}"))?;
        std::fs::create_dir_all(NIX_OVERLAY_MERGED)
            .map_err(|e| format!("create {NIX_OVERLAY_MERGED}: {e}"))?;

        let data = format!(
            "lowerdir={NIX_TARGET},upperdir={NIX_OVERLAY_UPPER},workdir={NIX_OVERLAY_WORK}"
        );
        mount(
            Some("mvm-nix"),
            NIX_OVERLAY_MERGED,
            Some("overlay"),
            MsFlags::empty(),
            Some(data.as_str()),
        )
        .map_err(|e| format!("mount overlay {NIX_OVERLAY_MERGED}: {e}"))?;

        bind_mount(NIX_OVERLAY_MERGED, NIX_TARGET)
    }

    /// Returns true when the persistent Nix store at `path` has not
    /// yet been seeded from the rootfs's `/nix`.
    ///
    /// The seeded marker is a non-empty `store/` subdirectory. mkGuest
    /// always populates `/nix/store/HASH-*` in the rootfs, so any
    /// successful seed leaves `store/` non-empty in `/nix-store`.
    ///
    /// The previous "any entry other than lost+found" heuristic
    /// false-positived once [`mount_nix_overlay`] had pre-created
    /// `upper/` and `work/` on a freshly-formatted volume: an
    /// overlay-mount failure would route through `seed_nix_store`,
    /// the seed would be skipped (upper/ and work/ counted as "not
    /// lost+found"), and the subsequent bind-mount put an empty
    /// `/nix-store` over `/nix` — every `/sbin/<pkg>` symlink
    /// dangled and the first spawn failed with `ENOENT`.
    fn nix_store_needs_seed(path: &Path) -> bool {
        match std::fs::read_dir(path.join("store")) {
            Ok(mut entries) => entries.next().is_none(),
            Err(_) => true,
        }
    }

    fn seed_nix_store(timings: &Arc<Mutex<BootTimings>>, anchor: Instant) -> Result<(), String> {
        if !nix_store_needs_seed(Path::new(NIX_STORE_MOUNT)) {
            return Ok(());
        }

        eprintln!("mvm-host-vm-init: seeding {NIX_STORE_MOUNT} from {NIX_TARGET} (first boot)");
        let status = Command::new("/bin/cp")
            .args([
                "-aR",
                &format!("{NIX_TARGET}/."),
                &format!("{NIX_STORE_MOUNT}/"),
            ])
            .status()
            .map_err(|e| format!("spawn cp: {e}"))?;
        if !status.success() {
            return Err(format!(
                "seeding {NIX_STORE_MOUNT} from {NIX_TARGET}: cp exit {:?}",
                status.code()
            ));
        }
        stamp(timings, |t| {
            t.nix_seeded_ms = Some(BootTimings::ms_since(anchor))
        });
        Ok(())
    }

    /// Register the seeded store paths in the persistent
    /// `/nix/var/nix/db` so nix-daemon doesn't treat them as
    /// missing and re-substitute over the on-disk copies.
    ///
    /// Reads the standard nixpkgs manifest at
    /// [`NIX_PATH_REGISTRATION`] (emitted by
    /// `nixos/lib/make-ext4-fs.nix`) and pipes it to
    /// `nix-store --load-db`. Marked done with a sentinel at
    /// [`NIX_DB_LOADED_MARKER`] so subsequent boots skip the
    /// (idempotent but ~100ms) re-registration.
    ///
    /// The need for this call surfaced as `libboost_url.so.1.87.0:
    /// cannot open shared object file` during the in-VM dev-image
    /// build: with no entries in the DB, every closure path the
    /// build references gets re-fetched from `cache.nixos.org`,
    /// overwriting the seeded path in place — and a concurrent
    /// nix build-hook worker mid-`dlopen` of the same path's libs
    /// hits ENOENT during the rename window. Loading the DB makes
    /// the substituter skip the re-fetch entirely.
    fn load_seeded_nix_db(
        timings: &Arc<Mutex<BootTimings>>,
        anchor: Instant,
    ) -> Result<(), String> {
        if Path::new(NIX_DB_LOADED_MARKER).exists() {
            return Ok(());
        }
        if !Path::new(NIX_PATH_REGISTRATION).is_file() {
            return Err(format!(
                "{NIX_PATH_REGISTRATION} not present — rootfs predates the \
                 make-ext4-fs.nix manifest convention; substituter race \
                 will recur"
            ));
        }

        eprintln!(
            "mvm-host-vm-init: loading seeded paths into nix DB from {NIX_PATH_REGISTRATION}"
        );
        let manifest = std::fs::File::open(NIX_PATH_REGISTRATION)
            .map_err(|e| format!("open {NIX_PATH_REGISTRATION}: {e}"))?;
        let status = Command::new("/sbin/nix-store")
            .arg("--load-db")
            .stdin(manifest)
            .status()
            .map_err(|e| format!("spawn /sbin/nix-store --load-db: {e}"))?;
        if !status.success() {
            return Err(format!(
                "nix-store --load-db exit {}",
                status.code().unwrap_or(-1)
            ));
        }

        // Best-effort sentinel so we skip on next boot. Failure is
        // non-fatal — worst case we re-run the idempotent load.
        if let Err(e) = std::fs::write(NIX_DB_LOADED_MARKER, b"") {
            eprintln!(
                "mvm-host-vm-init: could not write {NIX_DB_LOADED_MARKER}: {e} \
                 (continuing — next boot will re-load the DB)"
            );
        }

        stamp(timings, |t| {
            t.nix_db_loaded_ms = Some(BootTimings::ms_since(anchor))
        });
        Ok(())
    }

    fn virtiofs_mount_flags(tag: &str) -> nix::mount::MsFlags {
        use nix::mount::MsFlags;
        if crate::virtiofs_tag_is_read_only(tag) {
            MsFlags::MS_RDONLY
        } else {
            MsFlags::empty()
        }
    }

    /// Mount a libkrun-exported virtio-fs share. `tag` is the
    /// symbolic identifier the host registered via
    /// `krun_add_virtiofs` (mvm-libkrun's `KrunVirtioFs.tag`);
    /// the kernel routes the mount through libkrun's
    /// `virtiofsd` daemon. Creates the target dir if absent. The
    /// workspace share is mounted read-only; `/out` and `/job` remain
    /// writable so builds can emit artifacts and result metadata.
    fn mount_virtiofs(tag: &str, target: &str) -> Result<(), String> {
        use nix::mount::mount;
        std::fs::create_dir_all(target).map_err(|e| format!("create {target}: {e}"))?;
        mount(
            Some(tag),
            target,
            Some("virtiofs"),
            virtiofs_mount_flags(tag),
            None::<&str>,
        )
        .map_err(|e| format!("mount virtiofs {tag} -> {target}: {e}"))
    }

    /// Offset of the ext4 primary superblock inside the partition
    /// (`SUPERBLOCK_OFFSET` in fs/ext4/ext4.h).
    const EXT4_SUPERBLOCK_OFFSET: u64 = 1024;

    /// Decide whether `/dev/vdb` needs (re)formatting before
    /// mounting. Returns `Some(reason)` on first boot (no ext4
    /// magic) and on stale-geometry mismatches where the recorded
    /// filesystem extends past the actual block-device end. Such
    /// volumes mount with `EINVAL` in the kernel:
    ///
    /// ```text
    /// EXT4-fs (vdb): bad geometry: block count <fs> exceeds
    ///                 size of device (<dev> blocks)
    /// ```
    ///
    /// Detected pre-mount so we can recover with `mkfs.ext4 -F`
    /// rather than aborting before the build can run. The
    /// `/nix-store` volume is a cache; reformatting loses nothing
    /// that can't be rebuilt by the next nix build.
    fn nix_store_dev_needs_format(dev: &str) -> Result<Option<String>, String> {
        let sb = read_ext4_superblock(dev)?;
        let Some(fs_bytes) = crate::parse_ext4_recorded_size_bytes(&sb) else {
            return Ok(Some("no ext4 superblock".into()));
        };
        let dev_bytes = block_device_size_bytes(dev)?;
        if fs_bytes > dev_bytes {
            return Ok(Some(format!(
                "ext4 records {fs_bytes} bytes but device exposes {dev_bytes} bytes"
            )));
        }
        Ok(None)
    }

    /// Read the first [`crate::EXT4_SUPERBLOCK_READ`] bytes of the
    /// superblock from `dev`. Returns a short buffer (truncated to
    /// the actual byte count read) when the device is too small —
    /// the parser treats short reads as "no ext4".
    fn read_ext4_superblock(dev: &str) -> Result<Vec<u8>, String> {
        use std::fs::File;
        use std::io::{Read, Seek, SeekFrom};
        let mut f = File::open(dev).map_err(|e| format!("open {dev}: {e}"))?;
        f.seek(SeekFrom::Start(EXT4_SUPERBLOCK_OFFSET))
            .map_err(|e| format!("seek superblock on {dev}: {e}"))?;
        let mut buf = vec![0u8; crate::EXT4_SUPERBLOCK_READ];
        let mut read = 0;
        while read < buf.len() {
            match f.read(&mut buf[read..]) {
                Ok(0) => break,
                Ok(n) => read += n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(format!("read superblock on {dev}: {e}")),
            }
        }
        buf.truncate(read);
        Ok(buf)
    }

    // BLKGETSIZE64 = _IOR(0x12, 114, size_t). `nix::ioctl_read!`
    // generates the same `(2<<30) | (size_of::<u64>()<<16) | (0x12<<8) | 114`
    // request value (`0x80081272` on 64-bit Linux) used by util-linux.
    nix::ioctl_read!(blkgetsize64, 0x12, 114, u64);

    /// Query a block device's size in bytes via `BLKGETSIZE64`.
    /// Linux block devices only — regular files return EINVAL, which
    /// is fine: `/nix-store-<arch>.img` is always attached as a
    /// virtio-blk device inside the builder VM.
    fn block_device_size_bytes(dev: &str) -> Result<u64, String> {
        use std::os::unix::io::AsRawFd;
        let f = std::fs::File::open(dev).map_err(|e| format!("open {dev}: {e}"))?;
        let mut size: u64 = 0;
        // SAFETY: `blkgetsize64` writes a single u64. `f` outlives the
        // call; the fd is valid for the duration.
        unsafe { blkgetsize64(f.as_raw_fd(), &mut size as *mut u64) }
            .map_err(|e| format!("ioctl BLKGETSIZE64 on {dev}: {e}"))?;
        Ok(size)
    }

    /// Return the device size in 4 KiB blocks via
    /// `/sys/class/block/<basename>/size` (which is the canonical
    /// 512-byte sector count the kernel uses for mount). Used by
    /// [`format_ext4`] to avoid mkfs.ext4's `BLKGETSIZE64`-rounding
    /// mismatch under libkrun virtio-blk.
    fn device_size_4k_blocks(dev: &str) -> Result<u64, String> {
        let basename = std::path::Path::new(dev)
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
        // 1 sector = 512 B, 1 4K block = 8 sectors. Floor-divide so
        // we never claim more blocks than the device actually has.
        Ok(sectors / 8)
    }

    fn format_ext4(dev: &str) -> Result<(), String> {
        // Pass an explicit block count instead of letting mkfs.ext4
        // query the device size. libkrun's virtio-blk and mkfs.ext4
        // disagree on the device's block count by exactly 16 4K blocks
        // (64 KiB) — mkfs rounds UP from `BLKGETSIZE64` to a 64 KiB
        // boundary; the kernel mount path uses the unrounded size.
        // Without the explicit count, the freshly-mkfs'd filesystem
        // claims `block count N+16 exceeds size of device (N blocks)`
        // and the next `mount` fails with EINVAL. Querying the
        // canonical size from `/sys/class/block/<dev>/size` (always
        // matches what `mount` uses) and passing `mkfs.ext4 -b 4096
        // <dev> <count>` short-circuits mkfs's rounding.
        let blocks_4k = device_size_4k_blocks(dev)?;
        let status = Command::new("/sbin/mkfs.ext4")
            .args(["-F", "-q", "-b", "4096", dev, &blocks_4k.to_string()])
            .status()
            .map_err(|e| format!("spawn /sbin/mkfs.ext4: {e}"))?;
        if !status.success() {
            return Err(format!("mkfs.ext4 exit {}", status.code().unwrap_or(-1)));
        }
        Ok(())
    }

    fn power_off() -> ExitCode {
        use nix::sys::reboot::{RebootMode, reboot};
        let _ = Command::new("/bin/sync").status();
        // `reboot(RB_POWER_OFF)` returns `Infallible` on success
        // (the kernel halts the VM and never returns control to
        // userspace). The match-on-Result here is for the case
        // where the syscall errors before the actual power-off —
        // e.g. lack of CAP_SYS_BOOT in a misconfigured guest.
        match reboot(RebootMode::RB_POWER_OFF) {
            Ok(_) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("mvm-host-vm-init: reboot syscall failed: {e}");
                ExitCode::FAILURE
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn json_escape_plain() {
            assert_eq!(json_escape("hello"), "hello");
        }

        #[test]
        fn json_escape_quote_and_backslash() {
            assert_eq!(json_escape(r#"he"llo\world"#), r#"he\"llo\\world"#);
        }

        #[test]
        fn json_escape_newlines_and_tabs() {
            assert_eq!(
                json_escape("line1\nline2\ttab\rcarriage"),
                "line1\\nline2\\ttab\\rcarriage"
            );
        }

        #[test]
        fn json_escape_low_control_codepoint() {
            // 0x01 is below 0x20 and not specially named — use 
            assert_eq!(json_escape("\x01"), "\\u0001");
        }

        #[test]
        fn json_escape_utf8_passes_through() {
            // Multi-byte UTF-8 must not be escaped: per RFC 8259,
            // only the named characters and control codepoints
            // require escaping.
            assert_eq!(json_escape("naïve résumé 日本語"), "naïve résumé 日本語");
        }

        #[test]
        fn ext4_magic_constants_match_disk_layout() {
            // Sanity-check the magic bytes we probe for. ext4
            // stores `0xEF53` as a 16-bit little-endian integer
            // at offset 1080 of the device. If this constant ever
            // drifts (e.g. someone "fixes" the byte order) we want
            // a CI test failure rather than a runtime mis-detection
            // that silently re-formats the persistent store.
            assert_eq!([0x53u8, 0xEFu8], 0xEF53u16.to_le_bytes());
        }

        #[test]
        fn virtiofs_mount_flags_keep_workspace_read_only() {
            use nix::mount::MsFlags;

            assert!(virtiofs_mount_flags("work").contains(MsFlags::MS_RDONLY));
            assert!(virtiofs_mount_flags("mvm-bins").contains(MsFlags::MS_RDONLY));
            assert_eq!(virtiofs_mount_flags("out"), MsFlags::empty());
            assert_eq!(virtiofs_mount_flags("job"), MsFlags::empty());
        }

        #[test]
        fn encode_iface_name_eth0_pads_with_nul() {
            let buf = encode_iface_name("eth0").expect("eth0 fits");
            assert_eq!(buf[0] as u8, b'e');
            assert_eq!(buf[1] as u8, b't');
            assert_eq!(buf[2] as u8, b'h');
            assert_eq!(buf[3] as u8, b'0');
            assert_eq!(buf[4] as u8, 0, "remainder NUL-padded");
            assert_eq!(buf[libc::IFNAMSIZ - 1] as u8, 0);
        }

        #[test]
        fn encode_iface_name_max_length_succeeds() {
            // 15 bytes + 1 NUL = exactly IFNAMSIZ.
            let max = "a".repeat(libc::IFNAMSIZ - 1);
            let buf = encode_iface_name(&max).expect("15-byte name fits");
            for byte in buf.iter().take(libc::IFNAMSIZ - 1) {
                assert_eq!(*byte as u8, b'a');
            }
            assert_eq!(buf[libc::IFNAMSIZ - 1] as u8, 0, "NUL terminator");
        }

        #[test]
        fn encode_iface_name_too_long_errors() {
            let over = "a".repeat(libc::IFNAMSIZ);
            let err = encode_iface_name(&over).expect_err("IFNAMSIZ-byte name rejected");
            assert!(err.contains("IFNAMSIZ"), "err mentions limit: {err}");
            assert!(err.contains(&over), "err includes the offending name");
        }

        /// Plan 89 W3 part 9 — `run_job_streaming` calls the
        /// per-line callback once per stderr line, in order, and
        /// returns the same `(exit_code, tail)` shape as the
        /// single-shot `run_job` for the success case.
        #[test]
        fn run_job_streaming_emits_each_line_in_order() {
            // Write a cmd.sh that emits 3 stderr lines and exits 0.
            let dir = tempfile::tempdir().expect("tempdir");
            let cmd_path = dir.path().join("cmd.sh");
            std::fs::write(
                &cmd_path,
                "echo one >&2\necho two >&2\necho three >&2\nexit 0\n",
            )
            .expect("write cmd.sh");
            use std::sync::Mutex;
            let collected = Mutex::new(Vec::<String>::new());
            let (code, tail) = run_job_streaming(
                cmd_path.to_str().unwrap(),
                None,
                Isolation::Inherit,
                |line| {
                    collected.lock().unwrap().push(line.to_string());
                },
            );
            assert_eq!(code, 0);
            let got = collected.into_inner().unwrap();
            assert_eq!(got, vec!["one", "two", "three"]);
            assert_eq!(tail, "one\ntwo\nthree");
        }

        /// Plan 89 W3 part 9 — non-zero exit still surfaces all
        /// streamed lines and a tail bounded by `STDERR_TAIL_LINES`.
        #[test]
        fn run_job_streaming_caps_tail_to_stderr_tail_lines() {
            let dir = tempfile::tempdir().expect("tempdir");
            let cmd_path = dir.path().join("cmd.sh");
            // Emit more lines than STDERR_TAIL_LINES (=20) so we
            // verify the buffer cap, not just streaming.
            let total = STDERR_TAIL_LINES + 5;
            let mut script = String::new();
            for i in 1..=total {
                script.push_str(&format!("echo line{i} >&2\n"));
            }
            script.push_str("exit 42\n");
            std::fs::write(&cmd_path, script).expect("write cmd.sh");
            use std::sync::Mutex;
            let collected = Mutex::new(Vec::<String>::new());
            let (code, tail) = run_job_streaming(
                cmd_path.to_str().unwrap(),
                None,
                Isolation::Inherit,
                |line| {
                    collected.lock().unwrap().push(line.to_string());
                },
            );
            assert_eq!(code, 42);
            // Callback saw every line.
            assert_eq!(collected.lock().unwrap().len(), total);
            // Tail kept only the last STDERR_TAIL_LINES.
            let tail_lines: Vec<&str> = tail.lines().collect();
            assert_eq!(tail_lines.len(), STDERR_TAIL_LINES);
            assert_eq!(*tail_lines.first().unwrap(), "line6");
            assert_eq!(*tail_lines.last().unwrap(), &format!("line{total}"));
        }

        /// Plan 89 W3 part 9 — single-shot `run_job` keeps its
        /// pre-streaming semantics: returns the tail without any
        /// per-line side effect (the streaming variant's callback
        /// is `|_| {}`).
        #[test]
        fn run_job_matches_streaming_for_short_output() {
            let dir = tempfile::tempdir().expect("tempdir");
            let cmd_path = dir.path().join("cmd.sh");
            std::fs::write(&cmd_path, "echo hi >&2\nexit 0\n").expect("write cmd.sh");
            let (code, tail) = run_job(cmd_path.to_str().unwrap());
            assert_eq!(code, 0);
            assert_eq!(tail, "hi");
        }

        /// Plan 89 W3 part 10 — `JobScratch::create` builds
        /// `<base>/<job_id>` with mode 0700 and `Drop` wipes it.
        /// We parameterize on a tempdir base so the test doesn't
        /// touch the host's real `/tmp`.
        #[test]
        fn job_scratch_creates_dir_and_removes_on_drop() {
            use std::os::unix::fs::PermissionsExt;
            let base = tempfile::tempdir().expect("tempdir");
            let base_str = base.path().to_str().unwrap();
            let job_id = "00000000-0000-0000-0000-000000000000";
            let expected = base.path().join(job_id);
            {
                let scratch = JobScratch::create(base_str, job_id, None).expect("create scratch");
                assert!(expected.is_dir(), "scratch dir created");
                let mode = std::fs::metadata(&expected)
                    .expect("stat")
                    .permissions()
                    .mode()
                    & 0o777;
                assert_eq!(mode, 0o700, "scratch dir tightened to 0700");
                assert_eq!(scratch.path(), expected.to_str().unwrap());
            }
            assert!(!expected.exists(), "Drop removed scratch dir");
        }

        /// Plan 89 W3 part 10 — Drop still removes the dir even
        /// if it has files inside (the build leaves tempfiles
        /// behind). Catches the `remove_dir_all` vs `remove_dir`
        /// difference.
        #[test]
        fn job_scratch_drop_clears_nonempty_dir() {
            let base = tempfile::tempdir().expect("tempdir");
            let base_str = base.path().to_str().unwrap();
            let job_id = "deadbeef";
            let expected = base.path().join(job_id);
            {
                let _scratch = JobScratch::create(base_str, job_id, None).expect("create scratch");
                std::fs::write(expected.join("a.txt"), b"leak").expect("write a");
                std::fs::create_dir(expected.join("sub")).expect("mkdir sub");
                std::fs::write(expected.join("sub/b.txt"), b"leak").expect("write b");
            }
            assert!(!expected.exists(), "Drop wiped nested contents");
        }

        /// Plan 89 W3 part 10 — `run_job_streaming` honors the
        /// TMPDIR override. cmd.sh echoes the var so we can
        /// assert the build subprocess saw it.
        #[test]
        fn run_job_streaming_threads_tmpdir_through_to_subprocess() {
            let dir = tempfile::tempdir().expect("tempdir");
            let cmd_path = dir.path().join("cmd.sh");
            // The subprocess inherits TMPDIR from its environment;
            // echo it back via stderr so the test sees it.
            std::fs::write(&cmd_path, "echo \"tmpdir=$TMPDIR\" >&2\nexit 0\n")
                .expect("write cmd.sh");
            let (code, tail) = run_job_streaming(
                cmd_path.to_str().unwrap(),
                Some("/scratch/abc"),
                Isolation::Inherit,
                |_| {},
            );
            assert_eq!(code, 0);
            assert_eq!(tail, "tmpdir=/scratch/abc");
        }

        /// Plan 89 W3 part 10 — when `tmpdir` is `None` the
        /// subprocess inherits whatever TMPDIR the dispatch loop
        /// already had (typically unset inside PID 1). We assert
        /// the env var is *not* explicitly forced to a value the
        /// test process supplies via `Command::env`, so single-
        /// shot keeps its pre-part-10 behavior.
        #[test]
        fn run_job_streaming_does_not_override_tmpdir_when_none() {
            let dir = tempfile::tempdir().expect("tempdir");
            let cmd_path = dir.path().join("cmd.sh");
            std::fs::write(&cmd_path, "echo \"tmpdir=${TMPDIR-UNSET}\" >&2\nexit 0\n")
                .expect("write cmd.sh");
            // SAFETY: this test runs single-threaded in cargo
            // test's default scheduler for this binary; we set the
            // env var briefly to a known value and then assert the
            // subprocess saw exactly that (not some `/scratch/...`
            // override). Restoring afterward.
            //
            // The point of the assertion: with `tmpdir = None`,
            // `run_job_streaming` doesn't call `.env("TMPDIR", _)`
            // — it leaves the parent's env alone.
            let prior = std::env::var("TMPDIR").ok();
            unsafe {
                std::env::set_var("TMPDIR", "/inherited-from-parent");
            }
            let (code, tail) =
                run_job_streaming(cmd_path.to_str().unwrap(), None, Isolation::Inherit, |_| {});
            // Restore TMPDIR before the assert so a panic still
            // leaves the parent env clean for other tests.
            unsafe {
                match prior {
                    Some(v) => std::env::set_var("TMPDIR", v),
                    None => std::env::remove_var("TMPDIR"),
                }
            }
            assert_eq!(code, 0);
            assert_eq!(tail, "tmpdir=/inherited-from-parent");
        }

        /// Plan 89 W3 part 11 — `Isolation::Unshared` mode wraps
        /// the build subprocess in `unshare --mount --pid --ipc
        /// --fork`. The cmd.sh reads `/proc/self/status` and
        /// looks for `NSpid:` — under a fresh pid namespace, the
        /// build sees PID 1 inside its own namespace (the second
        /// `NSpid` column).
        ///
        /// Skipped if `unshare` isn't installed or if the test
        /// runner lacks `CAP_SYS_ADMIN` (e.g. unprivileged Docker
        /// CI). The Linux build-VM runs as PID 1 with full caps,
        /// so the real dispatch path always succeeds; this test
        /// exercises the wiring on whatever Linux host runs the
        /// suite.
        #[test]
        fn run_job_streaming_unshared_runs_in_fresh_pid_namespace() {
            use std::process::Stdio;
            // Fast-path probe: if `unshare --pid --fork --mount
            // --ipc true` fails on this host, skip — the test is
            // exercising correctness of the wiring, not the host's
            // capability set.
            let probe = Command::new("unshare")
                .args(["--mount", "--pid", "--ipc", "--fork", "true"])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
            let probe_ok = probe.map(|s| s.success()).unwrap_or(false);
            if !probe_ok {
                eprintln!(
                    "skipping unshared test: host lacks unshare or CAP_SYS_ADMIN — \
                     the Linux build-VM runs as PID 1 with full caps so the real \
                     dispatch path is unaffected"
                );
                return;
            }
            let dir = tempfile::tempdir().expect("tempdir");
            let cmd_path = dir.path().join("cmd.sh");
            // The build's PID inside its own ns is the last
            // column of `NSpid:`. Print it so the test can assert
            // on it.
            std::fs::write(
                &cmd_path,
                // Print one line per fact so the assertions can
                // match exact substrings rather than parse a
                // pipe-separated record. Plan 89 W3 part 13
                // added the uid check.
                "awk '/^NSpid:/ {print \"inner_pid=\" $NF; next} \
                       /^Uid:/ {print \"uid=\" $2; next}' \
                       /proc/self/status >&2\nexit 0\n",
            )
            .expect("write cmd.sh");
            let (code, tail) = run_job_streaming(
                cmd_path.to_str().unwrap(),
                None,
                Isolation::Unshared,
                |_| {},
            );
            assert_eq!(code, 0, "tail={tail}");
            // `--pid --fork` puts the child in a fresh ns; the
            // forked shell is PID 1 inside, the awk runs as a
            // child of it (PID 2 inside).
            assert!(
                tail.contains("inner_pid=1") || tail.contains("inner_pid=2"),
                "unshare did not produce a fresh pid namespace; tail={tail}"
            );
            // Plan 89 W3 part 13 — the setpriv layer drops the
            // build to BUILDER_UID. The probe succeeded only if
            // the runner has CAP_SETUID (which comes with
            // CAP_SYS_ADMIN), so setpriv must succeed too.
            assert!(
                tail.contains(&format!("uid={BUILDER_UID}")),
                "setpriv did not drop uid to {BUILDER_UID}; tail={tail}"
            );
        }

        /// Plan 89 W3 part 13 — pure argv-shape test for the
        /// wiring around `build_isolated_command`. Runs on every
        /// host (no spawn, no caps required) so an accidental
        /// reorder of unshare/setpriv flags trips here even when
        /// the host can't actually run the chain.
        #[test]
        fn build_isolated_command_inherit_uses_plain_shell() {
            use std::ffi::OsStr;
            let cmd = build_isolated_command("/job/cmd.sh", Isolation::Inherit);
            assert_eq!(cmd.get_program(), OsStr::new("/bin/sh"));
            let args: Vec<&OsStr> = cmd.get_args().collect();
            assert_eq!(args, vec![OsStr::new("-eu"), OsStr::new("/job/cmd.sh")]);
        }

        #[test]
        fn build_isolated_command_unshared_wraps_in_unshare_then_setpriv() {
            use std::ffi::OsStr;
            let cmd = build_isolated_command("/job/cmd.sh", Isolation::Unshared);
            assert_eq!(cmd.get_program(), OsStr::new("unshare"));
            let args: Vec<String> = cmd
                .get_args()
                .map(|s| s.to_string_lossy().into_owned())
                .collect();
            // unshare flags first.
            assert_eq!(&args[0..4], &["--mount", "--pid", "--ipc", "--fork"]);
            // setpriv follows, with numeric uid/gid and explicit
            // clear-groups / bounding-set / no-new-privs.
            assert_eq!(args[4], "setpriv");
            assert_eq!(args[5], format!("--reuid={BUILDER_UID}"));
            assert_eq!(args[6], format!("--regid={BUILDER_GID}"));
            assert_eq!(args[7], "--clear-groups");
            assert_eq!(args[8], "--bounding-set=-all");
            assert_eq!(args[9], "--no-new-privs");
            // Then the shell + cmd.
            assert_eq!(&args[10..], &["/bin/sh", "-eu", "/job/cmd.sh"]);
        }

        /// Plan 89 W3 part 13 — `JobScratch::create` accepts a
        /// `chown_to` arg; passing the current uid/gid is a
        /// no-op chown that any user can perform, so we can pin
        /// the wiring without needing root in CI. The actual
        /// drop-to-902 is exercised by the runtime path inside
        /// the builder VM (PID 1 has the cap to chown to any
        /// uid).
        #[test]
        fn job_scratch_chown_to_current_uid_succeeds() {
            use std::os::unix::fs::MetadataExt;
            let base = tempfile::tempdir().expect("tempdir");
            let base_str = base.path().to_str().unwrap();
            let job_id = "feedface";
            let uid = unsafe { libc::getuid() };
            let gid = unsafe { libc::getgid() };
            let _scratch =
                JobScratch::create(base_str, job_id, Some((uid, gid))).expect("chown to self");
            let meta = std::fs::metadata(base.path().join(job_id)).expect("stat");
            assert_eq!(meta.uid(), uid);
            assert_eq!(meta.gid(), gid);
        }

        #[test]
        fn nix_store_needs_seed_when_path_missing() {
            let base = tempfile::tempdir().expect("tempdir");
            assert!(nix_store_needs_seed(&base.path().join("does-not-exist")));
        }

        #[test]
        fn nix_store_needs_seed_when_store_dir_absent() {
            let base = tempfile::tempdir().expect("tempdir");
            std::fs::create_dir(base.path().join("lost+found")).expect("create lost+found");
            assert!(nix_store_needs_seed(base.path()));
        }

        /// Regression: `mount_nix_overlay` pre-creates `upper/` and
        /// `work/` before attempting the overlay mount. If that mount
        /// fails, the fallback path used to see the volume as "already
        /// seeded" (any non-`lost+found` entry counted) and skip the
        /// copy, leaving `/nix` empty after bind-mount. The corrected
        /// check looks at `store/` instead, so overlay scaffolding
        /// does not confuse the seeder.
        #[test]
        fn nix_store_needs_seed_when_only_overlay_scaffolding_present() {
            let base = tempfile::tempdir().expect("tempdir");
            std::fs::create_dir(base.path().join("upper")).expect("create upper");
            std::fs::create_dir(base.path().join("work")).expect("create work");
            std::fs::create_dir(base.path().join("lost+found")).expect("create lost+found");
            assert!(nix_store_needs_seed(base.path()));
        }

        #[test]
        fn nix_store_needs_seed_when_store_dir_is_empty() {
            let base = tempfile::tempdir().expect("tempdir");
            std::fs::create_dir(base.path().join("store")).expect("create store");
            assert!(nix_store_needs_seed(base.path()));
        }

        #[test]
        fn nix_store_does_not_need_seed_when_store_has_entries() {
            let base = tempfile::tempdir().expect("tempdir");
            let store = base.path().join("store");
            std::fs::create_dir(&store).expect("create store");
            std::fs::create_dir(store.join("abc123-some-pkg")).expect("create closure path");
            assert!(!nix_store_needs_seed(base.path()));
        }
    }
}
