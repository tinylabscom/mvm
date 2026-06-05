//! QEMU builder backend (Plan 166 / ADR-072) — the **Linux** dev/builder VMM.
//!
//! QEMU is the portable, apt-installable Linux builder substrate: it uses
//! `/dev/kvm` when present (fast) and TCG software emulation otherwise (slow,
//! but works anywhere — CI runners, nested VMs, containers). On macOS the
//! built-in equivalent is Vz; QEMU is Linux-only. Firecracker remains the
//! production runtime (ADR-001/072).
//!
//! Stage 0 reuses the same nix-tarball seed + `stage0-init` as the libkrun
//! path (selected by the `mvm.backend=qemu` kernel cmdline marker), but boots
//! it with **stock components**: the host distro kernel + initramfs (which
//! carry the modular virtio/ext4 drivers) mount the seed as an **ext4** root,
//! the shares are ext4 block disks, and networking is QEMU user-mode (slirp)
//! configured statically by `stage0-init` — no libkrun, no libkrunfw, no
//! custom kernel, no passt. Proven end-to-end on x86_64 (Plan 166 Phase 1:
//! the builder kernel compiled + `vmlinux` landed in `/out`).
//!
//! Host-side packing/extraction uses `mkfs.ext4 -d` + `debugfs rdump` rather
//! than loop mounts, so the builder runs as a normal user in the `kvm` group —
//! no root.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::builder_vm::{BuilderArtifacts, BuilderJob, BuilderMounts, BuilderVm, BuilderVmError};

/// QEMU-backed builder VM (Linux). Constructed with `::default()`; no I/O at
/// construction — the first I/O is in `run_stage0`.
#[derive(Debug, Default)]
pub struct QemuBuilderVm;

impl QemuBuilderVm {
    pub fn new() -> Self {
        Self
    }
}

impl BuilderVm for QemuBuilderVm {
    fn run_build(
        &self,
        _job: &BuilderJob,
        _mounts: &BuilderMounts,
    ) -> Result<BuilderArtifacts, BuilderVmError> {
        // Phase 1 implements Stage 0 (the from-source builder-VM bootstrap).
        // Steady-state `run_build` on QEMU is Plan 166 Phase 2.
        Err(BuilderVmError::VmmUnavailable {
            requested: "qemu-run-build".to_string(),
            reason: "the QEMU builder backend implements Stage 0 today; \
                     steady-state run_build is Plan 166 Phase 2."
                .to_string(),
        })
    }

    fn run_stage0(
        &self,
        guest_root_dir: &Path,
        entry_path: &str,
        workspace_dir: &Path,
        artifact_out: &Path,
        host_bin_dir: &Path,
    ) -> Result<(), BuilderVmError> {
        run_stage0_qemu(
            guest_root_dir,
            entry_path,
            workspace_dir,
            artifact_out,
            host_bin_dir,
        )
    }
}

/// Max wall-clock for a Stage 0 QEMU run (kernel compile + downloads). Wraps
/// the qemu child in `timeout` so a hung guest can't block forever.
const STAGE0_TIMEOUT_SECS: u32 = 3600;

/// Ext4 image sizes (sparse — `set_len` + `mkfs.ext4 -d` only touch real
/// content). The seed disk holds the whole build closure nix downloads.
const SEED_IMG_BYTES: u64 = 30 * 1024 * 1024 * 1024;
const OUT_IMG_BYTES: u64 = 4 * 1024 * 1024 * 1024;

fn run_stage0_qemu(
    guest_root_dir: &Path,
    entry_path: &str,
    workspace_dir: &Path,
    artifact_out: &Path,
    host_bin_dir: &Path,
) -> Result<(), BuilderVmError> {
    let qemu_bin = locate_qemu()?;
    let (kernel, initrd) = locate_host_kernel()?;
    let kvm = kvm_available();
    if !kvm {
        eprintln!(
            "[mvm] QEMU running unaccelerated (TCG) — no /dev/kvm; the Stage 0 \
             build will be slow."
        );
    }

    // Work dir for the ext4 images, beside the artifact output.
    let work = artifact_out
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(format!("qemu-stage0-{}", std::process::id()));
    std::fs::create_dir_all(&work).map_err(|e| io_err("creating QEMU work dir", &work, e))?;
    let console_log = work.join("console.log");

    // 1. Pack the seed + shares as ext4 disks (no loop mounts — mkfs.ext4 -d).
    //    Device order = -drive order: vda=seed, vdb=work, vdc=out, vdd=mvm-bins.
    let vda = work.join("seed.ext4");
    let vdb = work.join("work.ext4");
    let vdc = work.join("out.ext4");
    let vdd = work.join("mvm-bins.ext4");
    // The Debian initramfs's init-bottom *moves* the early-boot pseudo-fs
    // mounts (/dev, /run, /sys, /proc) into the new root before exec'ing
    // /init, which needs those mountpoint dirs to already exist in the seed.
    // libkrun never hits this (it has no initramfs), so the shared
    // materialize doesn't create them — do it here for the QEMU boot.
    for d in ["dev", "proc", "sys", "run", "tmp", "etc"] {
        let p = guest_root_dir.join(d);
        std::fs::create_dir_all(&p).map_err(|e| io_err("creating seed mountpoint", &p, e))?;
    }
    pack_ext4(guest_root_dir, &vda, SEED_IMG_BYTES)?;
    // /work: pack a filtered copy that drops the heavy build/VCS dirs the nix
    // workspace filter ignores anyway (`target/`, `.git`, …) — otherwise a
    // multi-GB `target/` would bloat the disk + pack time for nothing.
    let work_src = work.join("work-src");
    copy_tree_filtered(
        workspace_dir,
        &work_src,
        &["target", ".git", ".claude", "node_modules"],
    )?;
    pack_ext4(
        &work_src,
        &vdb,
        dir_size_bytes(&work_src) + 256 * 1024 * 1024,
    )?;
    let _ = std::fs::remove_dir_all(&work_src);
    pack_ext4(artifact_out, &vdc, OUT_IMG_BYTES)?;
    pack_ext4(host_bin_dir, &vdd, 256 * 1024 * 1024)?;

    // 2. Launch QEMU (the Plan 166 validated recipe), serial → console.log.
    let append =
        format!("console=ttyS0 root=/dev/vda rw init={entry_path} mvm.backend=qemu panic=-1");
    let mut cmd = Command::new("timeout");
    cmd.arg(STAGE0_TIMEOUT_SECS.to_string()).arg(&qemu_bin);
    cmd.args(["-m", "8G", "-smp", "6"]);
    if kvm {
        cmd.args(["-enable-kvm", "-cpu", "host"]);
    } else {
        cmd.args(["-cpu", "max"]);
    }
    cmd.arg("-kernel").arg(&kernel);
    cmd.arg("-initrd").arg(&initrd);
    cmd.arg("-append").arg(&append);
    for disk in [&vda, &vdb, &vdc, &vdd] {
        cmd.arg("-drive")
            .arg(format!("file={},if=virtio,format=raw", disk.display()));
    }
    cmd.args([
        "-netdev",
        "user,id=n0",
        "-device",
        "virtio-net-pci,netdev=n0",
    ]);
    cmd.args(["-display", "none"]);
    cmd.arg("-serial")
        .arg(format!("file:{}", console_log.display()));
    cmd.args(["-monitor", "none", "-no-reboot"]);

    let status = cmd
        .status()
        .map_err(|e| BuilderVmError::NixBuildFailed(format!("spawning qemu ({qemu_bin}): {e}")))?;

    // 3. Decide success from the serial log (the qemu exit code is just the
    //    guest poweroff). `stage0-init` prints a stable terminal line.
    let log = std::fs::read_to_string(&console_log).unwrap_or_default();
    if !status.success() && status.code() == Some(124) {
        return Err(BuilderVmError::NixBuildFailed(format!(
            "QEMU Stage 0 timed out after {STAGE0_TIMEOUT_SECS}s; console at {}",
            console_log.display()
        )));
    }
    if log.contains("stage0-init: build failed") {
        return Err(BuilderVmError::NixBuildFailed(format!(
            "nix build failed inside the QEMU Stage 0 guest; console at {}\n{}",
            console_log.display(),
            tail(&log, 20)
        )));
    }
    if !log.contains("stage0-init: done; halting") {
        return Err(BuilderVmError::ExtractionFailed(format!(
            "QEMU Stage 0 did not reach a clean halt; console at {}\n{}",
            console_log.display(),
            tail(&log, 20)
        )));
    }

    // 4. Pull the artifacts back out of the /out ext4 into `artifact_out`
    //    (debugfs rdump — no mount). The caller validates + promotes them.
    extract_out_artifacts(&vdc, artifact_out)?;

    // Best-effort: drop the (large) disk images now the build is done. Keep
    // console.log in `work` for post-mortem.
    for img in [&vda, &vdb, &vdc, &vdd] {
        let _ = std::fs::remove_file(img);
    }
    Ok(())
}

/// Recursively copy `src` into `dst`, skipping any directory whose name is in
/// `exclude` (at any depth). Files copied, symlinks recreated. Used to stage a
/// `/work` tree without the heavy `target/`/`.git` dirs before packing it.
fn copy_tree_filtered(src: &Path, dst: &Path, exclude: &[&str]) -> Result<(), BuilderVmError> {
    std::fs::create_dir_all(dst).map_err(|e| io_err("creating staging dir", dst, e))?;
    let mut stack = vec![(src.to_path_buf(), dst.to_path_buf())];
    while let Some((from, to)) = stack.pop() {
        for entry in std::fs::read_dir(&from).map_err(|e| io_err("reading", &from, e))? {
            let entry = entry.map_err(|e| io_err("reading entry", &from, e))?;
            let ft = entry
                .file_type()
                .map_err(|e| io_err("file_type", &from, e))?;
            let name = entry.file_name();
            let src_p = entry.path();
            let dst_p = to.join(&name);
            if ft.is_dir() {
                if exclude.contains(&name.to_string_lossy().as_ref()) {
                    continue;
                }
                std::fs::create_dir_all(&dst_p).map_err(|e| io_err("mkdir", &dst_p, e))?;
                stack.push((src_p, dst_p));
            } else if ft.is_symlink() {
                let target =
                    std::fs::read_link(&src_p).map_err(|e| io_err("readlink", &src_p, e))?;
                let _ = std::fs::remove_file(&dst_p);
                std::os::unix::fs::symlink(&target, &dst_p)
                    .map_err(|e| io_err("symlink", &dst_p, e))?;
            } else {
                std::fs::copy(&src_p, &dst_p).map_err(|e| io_err("copy", &src_p, e))?;
            }
        }
    }
    Ok(())
}

/// Create + populate an ext4 image from a directory tree without mounting it
/// (`mkfs.ext4 -d`). Sparse: the file is `set_len`'d to `size`, but only real
/// content occupies disk.
fn pack_ext4(src_dir: &Path, img: &Path, size: u64) -> Result<(), BuilderVmError> {
    std::fs::File::create(img)
        .and_then(|f| f.set_len(size))
        .map_err(|e| io_err("creating ext4 image", img, e))?;
    let status = Command::new("mkfs.ext4")
        .args(["-F", "-q", "-d"])
        .arg(src_dir)
        .arg(img)
        .status()
        .map_err(|e| {
            BuilderVmError::ExtractionFailed(format!("spawning mkfs.ext4 (install e2fsprogs): {e}"))
        })?;
    if !status.success() {
        return Err(BuilderVmError::ExtractionFailed(format!(
            "mkfs.ext4 -d {} -> {} exited {}",
            src_dir.display(),
            img.display(),
            status.code().unwrap_or(-1)
        )));
    }
    Ok(())
}

/// Extract the builder artifacts from the `/out` ext4 image into `dest` using
/// `debugfs rdump` (no mount). Copies the known artifact names if present.
fn extract_out_artifacts(out_img: &Path, dest: &Path) -> Result<(), BuilderVmError> {
    let tmp = dest.join(".qemu-out-extract");
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).map_err(|e| io_err("creating extract dir", &tmp, e))?;
    let status = Command::new("debugfs")
        .arg("-R")
        .arg(format!("rdump / {}", tmp.display()))
        .arg(out_img)
        .status()
        .map_err(|e| {
            BuilderVmError::ExtractionFailed(format!("spawning debugfs (install e2fsprogs): {e}"))
        })?;
    if !status.success() {
        return Err(BuilderVmError::ExtractionFailed(format!(
            "debugfs rdump of {} exited {}",
            out_img.display(),
            status.code().unwrap_or(-1)
        )));
    }
    for name in [
        "vmlinux",
        "Image",
        "bzImage",
        "rootfs.ext4",
        "cmdline.txt",
        "nix-stderr.log",
    ] {
        let from = tmp.join(name);
        if from.is_file() {
            std::fs::copy(&from, dest.join(name))
                .map_err(|e| io_err("copying extracted artifact", &from, e))?;
        }
    }
    let _ = std::fs::remove_dir_all(&tmp);
    Ok(())
}

/// `qemu-system-<host-arch>` on `$PATH`. The builder/Stage 0 guest is always
/// same-arch as the host (we boot the host's kernel).
fn locate_qemu() -> Result<String, BuilderVmError> {
    let bin = match std::env::consts::ARCH {
        "x86_64" => "qemu-system-x86_64",
        "aarch64" => "qemu-system-aarch64",
        other => {
            return Err(BuilderVmError::VmmUnavailable {
                requested: "qemu".to_string(),
                reason: format!("no QEMU system emulator mapped for host arch `{other}`"),
            });
        }
    };
    which::which(bin)
        .map(|_| bin.to_string())
        .map_err(|_| BuilderVmError::VmmUnavailable {
            requested: "qemu".to_string(),
            reason: format!(
                "`{bin}` not found on $PATH. Install QEMU \
                 (`apt install qemu-system-x86 qemu-utils` / `dnf install qemu-system-x86`)."
            ),
        })
}

/// The running kernel's `vmlinuz` + `initrd.img` under `/boot`. The stock
/// initramfs carries the modular virtio/ext4 drivers Stage 0 needs.
fn locate_host_kernel() -> Result<(PathBuf, PathBuf), BuilderVmError> {
    let release = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map_err(|e| BuilderVmError::VmmUnavailable {
            requested: "qemu-stage0-kernel".to_string(),
            reason: format!("reading /proc/sys/kernel/osrelease: {e}"),
        })?
        .trim()
        .to_string();
    let kernel = PathBuf::from(format!("/boot/vmlinuz-{release}"));
    let initrd = PathBuf::from(format!("/boot/initrd.img-{release}"));
    if !kernel.is_file() || !initrd.is_file() {
        return Err(BuilderVmError::VmmUnavailable {
            requested: "qemu-stage0-kernel".to_string(),
            reason: format!(
                "the QEMU Stage 0 boots the host kernel + initramfs, but \
                 {} and/or {} are missing. Install the distro kernel + \
                 initramfs-tools.",
                kernel.display(),
                initrd.display()
            ),
        });
    }
    Ok((kernel, initrd))
}

fn kvm_available() -> bool {
    // /dev/kvm present + readable+writable for this process.
    Path::new("/dev/kvm").exists()
        && std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/kvm")
            .is_ok()
}

fn dir_size_bytes(dir: &Path) -> u64 {
    fn walk(p: &Path, acc: &mut u64) {
        if let Ok(rd) = std::fs::read_dir(p) {
            for e in rd.flatten() {
                let path = e.path();
                match e.file_type() {
                    Ok(ft) if ft.is_dir() => walk(&path, acc),
                    Ok(ft) if ft.is_file() => {
                        *acc += e.metadata().map(|m| m.len()).unwrap_or(0);
                    }
                    _ => {}
                }
            }
        }
    }
    let mut acc = 0;
    walk(dir, &mut acc);
    acc
}

fn tail(s: &str, n: usize) -> String {
    let lines: Vec<&str> = s.lines().collect();
    lines[lines.len().saturating_sub(n)..].join("\n")
}

fn io_err(ctx: &str, path: &Path, e: std::io::Error) -> BuilderVmError {
    BuilderVmError::ExtractionFailed(format!("{ctx} {}: {e}", path.display()))
}
