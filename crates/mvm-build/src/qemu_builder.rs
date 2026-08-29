//! QEMU builder backend — the **Linux** dev/builder VMM.
//!
//! QEMU is the portable, apt-installable Linux builder substrate: it uses
//! `/dev/kvm` when present (fast) and TCG software emulation otherwise (slow,
//! but works anywhere — CI runners, nested VMs, containers). On macOS the
//! built-in equivalent is libkrun (or HVF on macOS 26+); QEMU is Linux-only.
//! Firecracker remains the production runtime.
//!
//! Stage 0 reuses the same nix-tarball seed + `stage0-init` as the libkrun
//! path (selected by the `mvm.backend=qemu` kernel cmdline marker), but boots
//! it with **stock components**: the host distro kernel + initramfs (which
//! carry the modular virtio/ext4 drivers) mount the seed as an **ext4** root,
//! the shares are ext4 block disks, and guest egress rides `vhost-vsock`
//! through the same read-only builder endpoint contract as the other backends
//! — no libkrun, no libkrunfw, no custom kernel, no slirp. Proven end-to-end
//! on x86_64 (the builder kernel compiled + `vmlinux` landed in `/out`).
//!
//! Host-side packing/extraction uses `mkfs.ext4 -d` + allow-listed `debugfs
//! dump` calls rather than loop mounts, so the builder runs as a normal user in
//! the `kvm` group — no root and no guest-ownership restoration.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

use crate::builder_vm::{BuilderArtifacts, BuilderJob, BuilderMounts, BuilderVm, BuilderVmError};
#[cfg(feature = "builder-vm")]
use crate::builder_vm_runtime::{CLOSURE_SEED_TAG, acquire_nix_store_image_lock_named};
#[cfg(feature = "builder-vm")]
use crate::libkrun_builder::{
    BuilderEndpointTransport, BuilderRuntimeOverlayAttachment, BuilderShellJob, BuilderShellResult,
    BuilderVmImage, BuilderVsockEgressEndpoint, DEFAULT_NIX_STORE_MIB,
    builder_virtiofs_runtime_overlay_attachment, builder_vm_cache_dir,
    prepopulate_stage0_nix_store_image, require_runtime_overlay_ext4, stage0_nix_store_image_name,
};
use mvm_core::config::DEFAULT_MVM_HOME_DIR_NAME;
use mvm_fs::overlay::CHECKSUM_MANIFEST_FILE;
use mvm_fs::sdk_sidecar::{SDK_SIDECAR_IMAGE_FILE, SDK_SIDECAR_VERSION_FILE};
use mvm_vmm::qemu_arch::{
    machine_for_arch as qemu_machine_for_arch, serial_console_for_arch as qemu_console_for_arch,
};

/// QEMU-backed builder VM (Linux). Constructed with `::default()`; no I/O at
/// construction — the first I/O is in `run_stage0`.
#[derive(Debug, Default)]
pub struct QemuBuilderVm;

impl QemuBuilderVm {
    pub fn new() -> Self {
        Self
    }

    /// Run a narrow builder shell job on the QEMU builder backend.
    ///
    /// This mirrors the libkrun shell-job contract used by OCI rootfs
    /// materialization: `/work` is the input tree, `/out` is the artifact
    /// directory, `/job/cmd.sh` is executed by `mvm-host-vm-init`, and caller
    /// extra disks enumerate after the persistent Nix-store disk.
    #[cfg(feature = "builder-vm")]
    pub fn run_shell_script(
        &self,
        job: &BuilderShellJob,
    ) -> Result<BuilderShellResult, BuilderVmError> {
        run_shell_script_qemu(job)
    }
}

impl BuilderVm for QemuBuilderVm {
    fn run_build(
        &self,
        job: &BuilderJob,
        mounts: &BuilderMounts,
    ) -> Result<BuilderArtifacts, BuilderVmError> {
        // Steady-state builds. The real impl lives in
        // `run_build_qemu` behind the `builder-vm` feature (it reaches into
        // `libkrun_builder`'s cache/image helpers, which link `libkrun-sys`).
        // `qemu_builder` itself is ungated so it compiles everywhere; the
        // backend is only ever *constructed* under `builder-vm` (via
        // `builder_backend_select`), so the non-feature arm is dead in
        // practice but keeps the default build green.
        run_build_qemu(job, mounts)
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
const STAGE0_TIMEOUT_SECS: u32 = 14_400;
const QEMU_BUILDER_VSOCK_EGRESS_TOKEN: &str = "mvm.vsock_egress=1";
const QEMU_BUILDER_VSOCK_EGRESS_PORT_TOKEN_PREFIX: &str = "mvm.vsock_egress_port=";
const QEMU_BUILDER_VSOCK_EGRESS_PORT_BASE: u32 = 45_253;
const QEMU_STAGE0_VSOCK_GUEST_MODULES: &[&str] = &[
    "vsock.ko",
    "vmw_vsock_virtio_transport_common.ko",
    "vmw_vsock_virtio_transport.ko",
];
const QEMU_STAGE0_OUT_ARTIFACT_NAMES: &[&str] = &[
    "vmlinux",
    "Image",
    "bzImage",
    "rootfs.ext4",
    "cmdline.txt",
    "manifest.json",
    "mvm-kernel.config",
    "nix-stderr.log",
    SDK_SIDECAR_IMAGE_FILE,
    SDK_SIDECAR_VERSION_FILE,
    CHECKSUM_MANIFEST_FILE,
];

/// Directories `copy_tree_filtered` drops when staging a `/work` tree for
/// packing — the heavy build/VCS/state dirs the Nix workspace filter ignores
/// anyway. Shared with the libkrun Stage 0 path (`libkrun_builder`), which
/// packs `/work` onto an ext4 disk the same way this QEMU path does.
pub(crate) const WORK_TREE_EXCLUDE_DIRS: &[&str] = &[
    "target",
    ".git",
    ".claude",
    "node_modules",
    DEFAULT_MVM_HOME_DIR_NAME,
    ".mvm-test",
    ".worktrees",
    ".cargo",
    "result",
    ".direnv",
    ".build",
];

/// Ext4 image sizes (sparse — `set_len` + `mkfs.ext4 -d` only touch real
/// content). The seed disk holds the whole build closure nix downloads.
const SEED_IMG_BYTES: u64 = 30 * 1024 * 1024 * 1024;
const OUT_IMG_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const WORK_EXT4_FILE_OVERHEAD_BYTES: u64 = 16 * 1024;
const WORK_EXT4_DIR_OVERHEAD_BYTES: u64 = 4 * 1024;
const WORK_EXT4_FIXED_HEADROOM_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DirStats {
    file_bytes: u64,
    file_count: u64,
    dir_count: u64,
}

impl DirStats {
    fn work_ext4_size_bytes(self) -> u64 {
        self.file_bytes
            + self.file_count * WORK_EXT4_FILE_OVERHEAD_BYTES
            + self.dir_count * WORK_EXT4_DIR_OVERHEAD_BYTES
            + WORK_EXT4_FIXED_HEADROOM_BYTES
    }
}

fn run_stage0_qemu(
    guest_root_dir: &Path,
    entry_path: &str,
    workspace_dir: &Path,
    artifact_out: &Path,
    host_bin_dir: &Path,
) -> Result<(), BuilderVmError> {
    let qemu_bin = locate_qemu()?;
    let (kernel, initrd) = locate_host_kernel()?;
    #[cfg(feature = "builder-vm")]
    let nix_store_lock = {
        let image = BuilderVmImage::new_root_dir(guest_root_dir.to_path_buf(), entry_path);
        let lock = acquire_nix_store_image_lock_named(
            &builder_vm_cache_dir(),
            &stage0_nix_store_image_name(),
            u64::from(DEFAULT_NIX_STORE_MIB),
        )?;
        prepopulate_stage0_nix_store_image(&image, lock.path())?;
        lock
    };
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
    copy_tree_filtered(workspace_dir, &work_src, WORK_TREE_EXCLUDE_DIRS)?;
    pack_ext4(&work_src, &vdb, dir_stats(&work_src).work_ext4_size_bytes())?;
    let _ = std::fs::remove_dir_all(&work_src);
    pack_ext4(artifact_out, &vdc, OUT_IMG_BYTES)?;
    let host_bins_src = work.join("host-bins-src");
    copy_tree_filtered(host_bin_dir, &host_bins_src, &[])?;
    stage_qemu_vsock_guest_modules(&host_bins_src)?;
    pack_ext4(&host_bins_src, &vdd, 256 * 1024 * 1024)?;
    let _ = std::fs::remove_dir_all(&host_bins_src);

    // 2. Launch QEMU (the validated recipe), serial → console.log.
    let egress_port = allocate_qemu_builder_egress_port();
    let hostepoch = crate::builder_vm::builder_hostepoch_cmdline_token();
    let serial_console = qemu_console_for_arch(std::env::consts::ARCH);
    let append = format!(
        "console={serial_console} root=/dev/vda rw init={entry_path} mvm.backend=qemu {QEMU_BUILDER_VSOCK_EGRESS_TOKEN} {QEMU_BUILDER_VSOCK_EGRESS_PORT_TOKEN_PREFIX}{egress_port} {hostepoch} panic=-1"
    );
    let guest_cid = allocate_qemu_builder_guest_cid();
    // Both statements sit behind the same feature: the endpoint type only
    // exists with `builder-vm`, and so does the identity it needs. Gating only
    // one of them compiles on a dev host and fails on the feature-gated
    // target, which is exactly what happened the first time.
    #[cfg(feature = "builder-vm")]
    let (identity_material, identity_drive) =
        crate::libkrun_builder::stage_builder_flowmux_identity(&work)?;
    #[cfg(feature = "builder-vm")]
    let egress_endpoint = BuilderVsockEgressEndpoint::spawn_with_transport(
        &work,
        BuilderEndpointTransport::Vsock { port: egress_port },
        identity_material.spawn_config(),
    )?;
    let mut cmd = Command::new("timeout");
    cmd.arg(STAGE0_TIMEOUT_SECS.to_string()).arg(&qemu_bin);
    let mem_arg = format!("{QEMU_BUILD_MEMORY_MIB}M");
    cmd.args(["-m", &mem_arg, "-smp", &QEMU_BUILD_VCPUS.to_string()]);
    if let Some(machine) = qemu_machine_for_arch(std::env::consts::ARCH) {
        cmd.args(["-machine", machine]);
    }
    if kvm {
        cmd.args(["-enable-kvm", "-cpu", "host"]);
    } else {
        cmd.args(["-cpu", "max"]);
    }
    cmd.arg("-kernel").arg(&kernel);
    cmd.arg("-initrd").arg(&initrd);
    cmd.arg("-append").arg(
        crate::builder_cmdline::checked_builder_cmdline(append)
            .map_err(BuilderVmError::NixBuildFailed)?,
    );
    for disk in [&vda, &vdb, &vdc, &vdd] {
        cmd.arg("-drive")
            .arg(format!("file={},if=virtio,format=raw", disk.display()));
    }
    #[cfg(feature = "builder-vm")]
    attach_stage0_identity_and_store(&mut cmd, &identity_drive, nix_store_lock.path());
    cmd.arg("-device")
        .arg(format!("vhost-vsock-pci,guest-cid={guest_cid}"));
    cmd.args(["-display", "none"]);
    cmd.arg("-serial")
        .arg(format!("file:{}", console_log.display()));
    cmd.args(["-monitor", "none", "-no-reboot"]);

    let status = cmd
        .status()
        .map_err(|e| BuilderVmError::NixBuildFailed(format!("spawning qemu ({qemu_bin}): {e}")))?;
    #[cfg(feature = "builder-vm")]
    drop(egress_endpoint);

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
            "QEMU Stage 0 exited with {status} before reaching a clean halt; console at {}\n{}",
            console_log.display(),
            tail(&log, 20)
        )));
    }

    // 4. Pull the allow-listed artifacts back out of the /out ext4 into
    //    `artifact_out` (debugfs dump — no mount or ownership restoration).
    //    The caller validates + promotes them.
    extract_out_artifacts(&vdc, artifact_out)?;

    // Best-effort: drop the (large) disk images now the build is done. Keep
    // console.log in `work` for post-mortem.
    for img in [&vda, &vdb, &vdc, &vdd] {
        let _ = std::fs::remove_file(img);
    }
    Ok(())
}

/// Attach the two host-owned Stage 0 data disks exactly once and in a stable
/// order: the read-only FlowMux identity followed by the writable Nix store.
#[cfg(any(feature = "builder-vm", test))]
fn attach_stage0_identity_and_store(cmd: &mut Command, identity_drive: &Path, nix_store: &Path) {
    cmd.arg("-drive").arg(format!(
        "file={},if=virtio,format=raw,readonly=on",
        identity_drive.display()
    ));
    cmd.arg("-drive")
        .arg(format!("file={},if=virtio,format=raw", nix_store.display()));
}

/// Recursively copy `src` into `dst`, skipping any directory whose name is in
/// `exclude` (at any depth). Files copied, symlinks recreated. Used to stage a
/// `/work` tree without the heavy `target/`/`.git` dirs before packing it.
/// `pub(crate)` so the libkrun Stage 0 path can stage its own filtered
/// `/work` copy with the same walk instead of a second implementation.
/// Directories this copy must never descend into, resolved to real paths
/// rather than matched by name.
///
/// `exclude` is a list of *names*, which is fine for `target/` and `.git` —
/// they are named by convention. It is not fine for two cases that are
/// defined by where they are, not what they are called:
///
/// - **The destination.** When `dst` lives under `src`, a name-matched filter
///   walks the copy into its own output and keeps going until the path
///   exceeds `PATH_MAX`. That is always a bug, whatever the directory is
///   called.
/// - **`MVM_HOME`.** The default name is on the exclude list, but the
///   variable can point anywhere. Pointed inside the checkout under any other
///   name — `.mvm-verify`, say — it was copied, and since Stage 0 stages into
///   `MVM_HOME/cache/builder-vm/vms/...` that is the first case again.
fn resolved_copy_barriers(src: &Path, dst: &Path) -> Vec<PathBuf> {
    let mut barriers = Vec::new();
    let real = |p: &Path| std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    let src_real = real(src);

    let dst_real = real(dst);
    if dst_real.starts_with(&src_real) {
        barriers.push(dst_real);
    }

    let home = PathBuf::from(mvm_core::config::mvm_home());
    let home_real = real(&home);
    if home_real.starts_with(&src_real) {
        barriers.push(home_real);
    }
    barriers
}

pub(crate) fn copy_tree_filtered(
    src: &Path,
    dst: &Path,
    exclude: &[&str],
) -> Result<(), BuilderVmError> {
    std::fs::create_dir_all(dst).map_err(|e| io_err("creating staging dir", dst, e))?;
    let barriers = resolved_copy_barriers(src, dst);
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
                if !barriers.is_empty() {
                    let real = std::fs::canonicalize(&src_p).unwrap_or_else(|_| src_p.clone());
                    if barriers.iter().any(|b| real.starts_with(b)) {
                        continue;
                    }
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

#[cfg(test)]
mod copy_barrier_tests {
    use super::{WORK_TREE_EXCLUDE_DIRS, copy_tree_filtered};
    use mvm_core::util::test_env::TestEnv;

    /// The reported failure: a staging destination inside the tree being
    /// copied. Name-matched filtering walked into it and kept going until the
    /// path outgrew `PATH_MAX` (ENAMETOOLONG), roughly ten levels deep.
    #[test]
    fn a_destination_inside_the_source_is_not_copied_into_itself() {
        let root = tempfile::tempdir().expect("tempdir");
        let src = root.path().join("checkout");
        std::fs::create_dir_all(src.join("crates")).expect("mkdir");
        std::fs::write(src.join("crates/lib.rs"), b"fn main() {}").expect("write");

        // The destination lives under the source, named nothing special.
        let dst = src.join("stage0-work/work-src");
        copy_tree_filtered(&src, &dst, WORK_TREE_EXCLUDE_DIRS).expect("copy");

        assert!(
            dst.join("crates/lib.rs").is_file(),
            "real content is copied"
        );
        // The defect was unbounded recursion, not the empty parent directory
        // the walk leaves behind on its way past the destination. What must
        // not exist is a *copy of the destination inside the destination* —
        // the first turn of the loop that ran until ENAMETOOLONG.
        assert!(
            !dst.join("stage0-work/work-src").exists(),
            "the copy must not descend into its own destination"
        );
        assert!(
            !dst.join("stage0-work/work-src/crates").exists(),
            "and must not carry content around that loop"
        );
    }

    /// `MVM_HOME` under a name the exclude list does not know. Stage 0 stages
    /// into `MVM_HOME/cache/...`, so copying it is the recursion above by
    /// another route — and the name list cannot see it coming.
    #[test]
    fn an_mvm_home_inside_the_source_is_skipped_whatever_it_is_called() {
        let root = tempfile::tempdir().expect("tempdir");
        let src = root.path().join("checkout");
        std::fs::create_dir_all(src.join("crates")).expect("mkdir");
        std::fs::write(src.join("crates/lib.rs"), b"fn main() {}").expect("write");

        let home = src.join(".mvm-verify");
        std::fs::create_dir_all(home.join("cache/builder-vm")).expect("mkdir");
        std::fs::write(home.join("cache/builder-vm/huge.img"), b"x").expect("write");

        // `isolate_mvm_home` moves HOME with MVM_HOME and restores both on
        // drop. Setting MVM_HOME alone leaves the test able to read the
        // developer's real home, which `xtask check-test-home-isolation`
        // refuses — it caught this exact pair.
        let mut env = TestEnv::new();
        env.isolate_mvm_home(&home);

        let dst = root.path().join("out");
        copy_tree_filtered(&src, &dst, WORK_TREE_EXCLUDE_DIRS).expect("copy");

        assert!(
            dst.join("crates/lib.rs").is_file(),
            "real content is copied"
        );
        assert!(
            !dst.join(".mvm-verify").exists(),
            "the resolved MVM_HOME must be skipped even under an unknown name"
        );
    }

    /// The barrier is about location, not name: an `.mvm-verify` that is *not*
    /// the active `MVM_HOME` is ordinary content and must still be copied.
    #[test]
    fn a_directory_that_merely_shares_the_name_is_still_copied() {
        let root = tempfile::tempdir().expect("tempdir");
        let src = root.path().join("checkout");
        std::fs::create_dir_all(src.join(".mvm-verify")).expect("mkdir");
        std::fs::write(src.join(".mvm-verify/notes.md"), b"not a home").expect("write");

        let mut env = TestEnv::new();
        env.isolate_mvm_home(root.path().join("elsewhere"));

        let dst = root.path().join("out");
        copy_tree_filtered(&src, &dst, WORK_TREE_EXCLUDE_DIRS).expect("copy");

        assert!(
            dst.join(".mvm-verify/notes.md").is_file(),
            "a same-named directory that is not the active home is content"
        );
    }
}

fn stage_qemu_vsock_guest_modules(host_bins_dir: &Path) -> Result<(), BuilderVmError> {
    let release = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map_err(|e| BuilderVmError::VmmUnavailable {
            requested: "qemu-stage0-vsock-modules".to_string(),
            reason: format!("reading /proc/sys/kernel/osrelease: {e}"),
        })?
        .trim()
        .to_string();
    let module_root = PathBuf::from(format!("/lib/modules/{release}/kernel/net/vmw_vsock"));
    let dest_dir = host_bins_dir.join("vsock-modules");
    std::fs::create_dir_all(&dest_dir)
        .map_err(|e| io_err("creating stage0 vsock module dir", &dest_dir, e))?;
    for module in QEMU_STAGE0_VSOCK_GUEST_MODULES {
        let src = locate_qemu_vsock_module(&module_root, module).ok_or_else(|| {
            BuilderVmError::VmmUnavailable {
                requested: "qemu-stage0-vsock-modules".to_string(),
                reason: format!(
                    "required guest vsock module {} missing on host; install the distro kernel modules package for {}",
                    module_root.join(module).display(),
                    release
                ),
            }
        })?;
        let dst = dest_dir.join(module);
        if src.extension().is_some_and(|extension| extension == "zst") {
            let output = Command::new("zstd")
                .args(["--quiet", "--decompress", "--stdout"])
                .arg(&src)
                .output()
                .map_err(|e| io_err("decompressing stage0 vsock guest module", &src, e))?;
            if !output.status.success() {
                return Err(BuilderVmError::ExtractionFailed(format!(
                    "decompressing stage0 vsock guest module {} failed with {}",
                    src.display(),
                    output.status
                )));
            }
            std::fs::write(&dst, output.stdout)
                .map_err(|e| io_err("writing decompressed stage0 vsock guest module", &dst, e))?;
        } else {
            std::fs::copy(&src, &dst)
                .map_err(|e| io_err("copying stage0 vsock guest module", &src, e))?;
        }
    }
    Ok(())
}

fn locate_qemu_vsock_module(module_root: &Path, module: &str) -> Option<PathBuf> {
    let uncompressed = module_root.join(module);
    if uncompressed.is_file() {
        return Some(uncompressed);
    }
    let compressed = module_root.join(format!("{module}.zst"));
    compressed.is_file().then_some(compressed)
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
/// allow-listed `debugfs dump` calls (no mount). Omitting `dump -p` is
/// deliberate: Stage 0 writes root-owned guest files, while the host extractor
/// is an unprivileged process and must not attempt to restore guest ownership.
fn extract_out_artifacts(out_img: &Path, dest: &Path) -> Result<(), BuilderVmError> {
    let tmp = dest.join(".qemu-out-extract");
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).map_err(|e| io_err("creating extract dir", &tmp, e))?;
    for name in QEMU_STAGE0_OUT_ARTIFACT_NAMES {
        let from = tmp.join(name);
        let status = Command::new("debugfs")
            .arg("-R")
            .arg(debugfs_dump_request(name, &from))
            .arg(out_img)
            .status()
            .map_err(|e| {
                BuilderVmError::ExtractionFailed(format!(
                    "spawning debugfs (install e2fsprogs): {e}"
                ))
            })?;
        if status.success() && from.is_file() {
            std::fs::copy(&from, dest.join(name))
                .map_err(|e| io_err("copying extracted artifact", &from, e))?;
        }
    }
    let _ = std::fs::remove_dir_all(&tmp);
    Ok(())
}

fn debugfs_dump_request(name: &str, destination: &Path) -> String {
    format!("dump /{name} {}", destination.display())
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

fn dir_stats(dir: &Path) -> DirStats {
    fn walk(p: &Path, stats: &mut DirStats) {
        if let Ok(rd) = std::fs::read_dir(p) {
            for e in rd.flatten() {
                let path = e.path();
                match e.file_type() {
                    Ok(ft) if ft.is_dir() => {
                        stats.dir_count += 1;
                        walk(&path, stats);
                    }
                    Ok(ft) if ft.is_file() => {
                        stats.file_count += 1;
                        stats.file_bytes += e.metadata().map(|m| m.len()).unwrap_or(0);
                    }
                    _ => {}
                }
            }
        }
    }
    let mut stats = DirStats {
        file_bytes: 0,
        file_count: 0,
        dir_count: 0,
    };
    walk(dir, &mut stats);
    stats
}

#[cfg(test)]
mod tests {
    use super::{
        DEFAULT_MVM_HOME_DIR_NAME, DirStats, QEMU_STAGE0_OUT_ARTIFACT_NAMES,
        QEMU_STAGE0_VSOCK_GUEST_MODULES, WORK_EXT4_DIR_OVERHEAD_BYTES,
        WORK_EXT4_FILE_OVERHEAD_BYTES, WORK_EXT4_FIXED_HEADROOM_BYTES, WORK_TREE_EXCLUDE_DIRS,
        attach_stage0_identity_and_store, copy_tree_filtered, debugfs_dump_request, dir_stats,
        locate_qemu_vsock_module,
    };
    use std::fs;

    #[test]
    fn stage0_attaches_one_identity_before_one_nix_store() {
        let mut command = std::process::Command::new("qemu-system-test");
        let identity = std::path::Path::new("/tmp/flowmux-identity.ext4");
        let store = std::path::Path::new("/tmp/nix-store.img");

        attach_stage0_identity_and_store(&mut command, identity, store);

        let args: Vec<_> = command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            args,
            vec![
                "-drive",
                "file=/tmp/flowmux-identity.ext4,if=virtio,format=raw,readonly=on",
                "-drive",
                "file=/tmp/nix-store.img,if=virtio,format=raw",
            ]
        );
    }

    #[test]
    fn qemu_stage0_vsock_guest_module_list_is_ordered_by_dependency() {
        assert_eq!(
            QEMU_STAGE0_VSOCK_GUEST_MODULES,
            &[
                "vsock.ko",
                "vmw_vsock_virtio_transport_common.ko",
                "vmw_vsock_virtio_transport.ko"
            ]
        );
    }

    #[test]
    fn qemu_stage0_extracts_manifest_sidecar() {
        assert!(QEMU_STAGE0_OUT_ARTIFACT_NAMES.contains(&"manifest.json"));
    }

    #[test]
    fn qemu_stage0_extracts_resolved_kernel_config() {
        assert!(
            QEMU_STAGE0_OUT_ARTIFACT_NAMES.contains(&"mvm-kernel.config"),
            "QEMU Stage 0 must retain the config required for verified kernel publication"
        );
    }

    #[test]
    fn qemu_stage0_extracts_sdk_sidecar_bundle() {
        for artifact in ["sdk.ext4", "VERSION", "checksums-sha256.txt"] {
            assert!(
                QEMU_STAGE0_OUT_ARTIFACT_NAMES.contains(&artifact),
                "QEMU Stage 0 must retain SDK-sidecar artifact {artifact}"
            );
        }
    }

    #[test]
    fn qemu_stage0_dump_does_not_restore_guest_ownership() {
        let request = debugfs_dump_request("sdk.ext4", std::path::Path::new("/tmp/sdk.ext4"));

        assert_eq!(request, "dump /sdk.ext4 /tmp/sdk.ext4");
        assert!(!request.contains("rdump"));
        assert!(!request.contains(" -p"));
    }

    #[test]
    fn work_ext4_size_accounts_for_metadata_overhead() {
        let stats = DirStats {
            file_bytes: 1024,
            file_count: 2,
            dir_count: 3,
        };
        assert_eq!(
            stats.work_ext4_size_bytes(),
            1024 + 2 * WORK_EXT4_FILE_OVERHEAD_BYTES
                + 3 * WORK_EXT4_DIR_OVERHEAD_BYTES
                + WORK_EXT4_FIXED_HEADROOM_BYTES
        );
    }

    #[test]
    fn dir_stats_counts_files_dirs_and_bytes() {
        let temp = tempfile::tempdir().expect("tempdir");
        fs::create_dir_all(temp.path().join("a/b")).expect("mkdir");
        fs::write(temp.path().join("root.txt"), b"root").expect("root file");
        fs::write(temp.path().join("a/nested.txt"), b"nested").expect("nested file");
        std::os::unix::fs::symlink("nested.txt", temp.path().join("a/link.txt")).expect("symlink");

        let stats = dir_stats(temp.path());
        assert_eq!(stats.file_count, 2);
        assert_eq!(stats.dir_count, 2);
        assert_eq!(stats.file_bytes, 10);
    }

    #[test]
    fn work_tree_copy_excludes_runtime_state_dirs() {
        let source = tempfile::tempdir().expect("tempdir");
        let destination = tempfile::tempdir().expect("tempdir");
        fs::write(source.path().join("README"), b"workspace").expect("workspace file");
        for state_dir in [DEFAULT_MVM_HOME_DIR_NAME, ".mvm-test"] {
            fs::create_dir_all(source.path().join(state_dir).join("cache"))
                .expect("state directory");
            fs::write(
                source.path().join(state_dir).join("cache").join("payload"),
                b"runtime state",
            )
            .expect("state file");
        }

        copy_tree_filtered(source.path(), destination.path(), WORK_TREE_EXCLUDE_DIRS)
            .expect("copy filtered work tree");

        assert_eq!(
            fs::read(destination.path().join("README")).expect("read workspace file"),
            b"workspace"
        );
        assert!(!destination.path().join(DEFAULT_MVM_HOME_DIR_NAME).exists());
        assert!(!destination.path().join(".mvm-test").exists());
    }

    #[test]
    fn qemu_vsock_module_lookup_accepts_compressed_modules() {
        let module_root = tempfile::tempdir().expect("tempdir");
        fs::write(module_root.path().join("vsock.ko.zst"), b"compressed")
            .expect("compressed module");

        assert_eq!(
            locate_qemu_vsock_module(module_root.path(), "vsock.ko"),
            Some(module_root.path().join("vsock.ko.zst"))
        );
    }

    #[test]
    fn stage0_workspace_copy_excludes_local_build_state() {
        let source = tempfile::tempdir().expect("source tempdir");
        let destination = tempfile::tempdir().expect("destination tempdir");
        for name in [".mvm-test", ".worktrees", ".cargo", "result"] {
            fs::create_dir(source.path().join(name)).expect("excluded directory");
            fs::write(source.path().join(name).join("state"), name).expect("excluded state");
        }
        fs::write(source.path().join("kept.txt"), "kept").expect("kept file");

        copy_tree_filtered(source.path(), destination.path(), WORK_TREE_EXCLUDE_DIRS)
            .expect("copy filtered workspace");

        assert!(destination.path().join("kept.txt").exists());
        for name in [".mvm-test", ".worktrees", ".cargo", "result"] {
            assert!(!destination.path().join(name).exists(), "{name} was copied");
        }
    }
}

fn tail(s: &str, n: usize) -> String {
    let lines: Vec<&str> = s.lines().collect();
    lines[lines.len().saturating_sub(n)..].join("\n")
}

fn io_err(ctx: &str, path: &Path, e: std::io::Error) -> BuilderVmError {
    BuilderVmError::ExtractionFailed(format!("{ctx} {}: {e}", path.display()))
}

// ───────────────────────────────────────────────────────────────────
// Steady-state QEMU builds (`run_build`).
//
// Stage 0 boots the stock distro kernel + initramfs to *produce* the
// builder image. `run_build` boots the image Stage 0 emitted — the mvm
// builder `vmlinux` + `rootfs.ext4`. That kernel carries
// virtio-blk/net/pci/console + virtio-fs + ext4 *built-in*, so it mounts
// the ext4 rootfs directly with no initramfs and no ext4-disk-share
// workaround, and `mvm-host-vm-init` (PID 1, UNCHANGED) mounts the same
// virtio-fs tags + persistent `/dev/vdb` nix store it does under
// libkrun/HVF, runs `/job/cmd.sh`, writes `/job/result`, and powers off.
//
// Devices, matched to what the unchanged guest expects:
//   - vda  virtio-blk  the builder `rootfs.ext4` (mounted `ro`)
//   - vdb  virtio-blk  the persistent nix-store image (`/nix` overlay upper)
//   - virtio-fs tags `work` `out` `job` `mvm-bins` over vhost-user/virtiofsd
//   - virtio-net-pci + user-mode (slirp); slirp's DHCP feeds the guest's
//     `udhcpc -i eth0` (we force `net.ifnames=0` so the NIC comes up `eth0`)
//
// The job protocol is the shared one (`stage_job_dir` writes /job/cmd.sh;
// `finalize_flake_job` reads /job/result), so `BuilderArtifacts` is
// byte-identical regardless of which VMM ran the build.

/// Guest RAM (MiB) + vCPUs for QEMU Stage 0 and steady-state builds. Leave
/// enough headroom for QEMU and the Linux host on a common 8 GiB / 4-vCPU
/// development machine.
const QEMU_BUILD_MEMORY_MIB: u32 = 6144;
const QEMU_BUILD_VCPUS: u8 = 4;

#[cfg(not(feature = "builder-vm"))]
fn run_build_qemu(
    job: &BuilderJob,
    mounts: &BuilderMounts,
) -> Result<BuilderArtifacts, BuilderVmError> {
    let _ = (job, mounts);
    Err(BuilderVmError::VmmUnavailable {
        requested: "qemu-run-build".to_string(),
        reason: "the QEMU builder backend requires the `builder-vm` feature".to_string(),
    })
}

#[cfg(feature = "builder-vm")]
fn run_shell_script_qemu(job: &BuilderShellJob) -> Result<BuilderShellResult, BuilderVmError> {
    use crate::builder_vm_runtime::{
        acquire_nix_store_image_lock, builder_vm_timeout, read_job_result_with_diagnostics,
        shell_job_exit_error, stage_closure_seed_dir, stage_shell_job_dir,
    };
    use crate::libkrun_builder::{
        BuilderVmImage, DEFAULT_NIX_STORE_MIB, builder_vm_cache_dir, ensure_builder_vm_image,
        host_arch_tag, unique_job_id,
    };

    validate_shell_job(job)?;

    let qemu_bin = locate_qemu()?;
    let (virtiofsd_bin, virtiofsd_flavor) =
        crate::virtiofsd::locate_virtiofsd().map_err(|e| BuilderVmError::VmmUnavailable {
            requested: "virtiofsd".to_string(),
            reason: format!("{e:#}"),
        })?;
    let (kernel, rootfs, image_cmdline) = match ensure_builder_vm_image()? {
        BuilderVmImage::Rootfs {
            kernel_path,
            rootfs_path,
            cmdline,
        } => (kernel_path, rootfs_path, cmdline),
        BuilderVmImage::RootDir { .. } => {
            return Err(BuilderVmError::ExtractionFailed(
                "QEMU shell jobs require a steady-state Rootfs builder image but got a RootDir \
                 (Stage 0) image. Re-bootstrap the builder VM."
                    .to_string(),
            ));
        }
    };
    let nix_store_lock = acquire_nix_store_image_lock(
        &builder_vm_cache_dir(),
        host_arch_tag(),
        u64::from(DEFAULT_NIX_STORE_MIB),
    )?;

    let job_id = unique_job_id();
    let job_dir = builder_vm_cache_dir().join("jobs").join(&job_id);
    stage_shell_job_dir(&job_dir, &job.script)?;
    tracing::info!(
        job_dir = %job_dir.display(),
        "builder VM shell job dir staged"
    );

    let vm_name = format!("mvm-builder-qemu-shell-{job_id}");
    let vm_state_dir = builder_vm_cache_dir().join("vms").join(&vm_name);
    std::fs::create_dir_all(&vm_state_dir)
        .map_err(|e| io_err("creating QEMU builder VM state dir", &vm_state_dir, e))?;
    let console_log = vm_state_dir.join("console.log");

    let kvm = kvm_available();
    if !kvm {
        eprintln!(
            "[mvm] QEMU running unaccelerated (TCG) — no /dev/kvm; this shell job will be slow."
        );
    }

    // Attach the resolved builder image's seeded closure NAR, when it
    // carries one, as a fourth read-only share — the same per-arch cache
    // dir `ensure_builder_vm_image` just read the kernel/rootfs from.
    let closure_nar =
        crate::builder_pack::closure_nar_path(&builder_vm_cache_dir().join(host_arch_tag()));
    let closure_share_dir = closure_nar
        .as_deref()
        .map(|nar| stage_closure_seed_dir(nar, &vm_state_dir))
        .transpose()?;

    let shares = qemu_shares_with_closure_seed(
        vec![
            ("work", job.work_dir.as_path()),
            ("out", job.artifact_out.as_path()),
            ("job", job_dir.as_path()),
        ],
        closure_share_dir.as_deref(),
    );
    let mut virtiofsd = crate::virtiofsd::VirtiofsdGuard::default();
    for (tag, dir) in shares.iter().copied() {
        let sock = qemu_virtiofs_socket_path(&job_id, tag);
        virtiofsd
            .spawn(
                crate::virtiofsd::SpawnParams::new(
                    &virtiofsd_bin,
                    virtiofsd_flavor,
                    tag,
                    &sock,
                    dir,
                )
                .read_only(false),
            )
            .map_err(|e| BuilderVmError::VmmUnavailable {
                requested: "virtiofsd".to_string(),
                reason: format!("{e:#}"),
            })?;
    }

    // The QEMU builder is always a lean Rootfs builder, so the runtime overlay
    // is required — fail closed rather than booting a builder whose guest agent
    // can never launch (it bakes none of its guest binaries).
    let runtime_overlay = require_runtime_overlay_ext4()
        .map_err(|e| BuilderVmError::RuntimeOverlayUnavailable(format!("{e:#}")))?;
    let egress_port = allocate_qemu_builder_egress_port();
    let overlay_cmdline = qemu_runtime_overlay_attachment(
        &BuilderVmImage::Rootfs {
            kernel_path: kernel.clone(),
            rootfs_path: rootfs.clone(),
            cmdline: image_cmdline.clone(),
        },
        Some(runtime_overlay.as_path()),
    )
    .ok_or_else(|| {
        BuilderVmError::RuntimeOverlayUnavailable(
            "resolved runtime overlay did not produce a builder attachment".to_string(),
        )
    })?
    .cmdline;
    let cmdline = qemu_build_cmdline(&overlay_cmdline, egress_port);
    let guest_cid = allocate_qemu_builder_guest_cid();
    let timeout_secs = builder_vm_timeout()?.as_secs();
    let mem_arg = format!("{QEMU_BUILD_MEMORY_MIB}M");
    let mut cmd = Command::new("timeout");
    cmd.arg(timeout_secs.to_string()).arg(&qemu_bin);
    cmd.args(["-m", &mem_arg, "-smp", &QEMU_BUILD_VCPUS.to_string()]);
    if let Some(machine) = qemu_machine_for_arch(std::env::consts::ARCH) {
        cmd.args(["-machine", machine]);
    }
    if kvm {
        cmd.args(["-enable-kvm", "-cpu", "host"]);
    } else {
        cmd.args(["-cpu", "max"]);
    }
    cmd.arg("-kernel").arg(&kernel);
    cmd.arg("-append").arg(
        crate::builder_cmdline::checked_builder_cmdline(cmdline.clone())
            .map_err(BuilderVmError::NixBuildFailed)?,
    );
    cmd.arg("-drive")
        .arg(format!("file={},if=virtio,format=raw", rootfs.display()));
    cmd.arg("-drive").arg(format!(
        "file={},if=virtio,format=raw",
        nix_store_lock.path().display()
    ));
    cmd.arg("-drive").arg(format!(
        "file={},if=virtio,format=raw,readonly=on",
        runtime_overlay.display()
    ));
    for disk in &job.extra_disks {
        let read_only = if disk.read_only { ",readonly=on" } else { "" };
        cmd.arg("-drive").arg(format!(
            "file={},if=virtio,format=raw{read_only}",
            disk.path.display()
        ));
    }
    cmd.args([
        "-object",
        &format!("memory-backend-memfd,id=mem,size={mem_arg},share=on"),
        "-numa",
        "node,memdev=mem",
    ]);
    for (tag, _) in shares.iter().copied() {
        let sock = qemu_virtiofs_socket_path(&job_id, tag);
        cmd.arg("-chardev")
            .arg(format!("socket,id=vfs-{tag},path={}", sock.display()));
        cmd.arg("-device").arg(format!(
            "vhost-user-fs-pci,queue-size=1024,chardev=vfs-{tag},tag={tag}"
        ));
    }
    let (identity_material, identity_drive) =
        crate::libkrun_builder::stage_builder_flowmux_identity(&vm_state_dir)?;
    let egress_endpoint = BuilderVsockEgressEndpoint::spawn_with_transport(
        &vm_state_dir,
        BuilderEndpointTransport::Vsock { port: egress_port },
        identity_material.spawn_config(),
    )?;
    cmd.arg("-drive").arg(format!(
        "file={},if=virtio,format=raw,readonly=on",
        identity_drive.display()
    ));
    cmd.arg("-device")
        .arg(format!("vhost-vsock-pci,guest-cid={guest_cid}"));
    cmd.args(["-display", "none"]);
    cmd.arg("-serial")
        .arg(format!("file:{}", console_log.display()));
    cmd.args(["-monitor", "none", "-no-reboot"]);

    let status = cmd
        .status()
        .map_err(|e| BuilderVmError::NixBuildFailed(format!("spawning qemu ({qemu_bin}): {e}")))?;
    drop(egress_endpoint);
    drop(virtiofsd);

    if !status.success() && status.code() == Some(124) {
        return Err(BuilderVmError::NixBuildFailed(format!(
            "QEMU builder VM shell job timed out after {timeout_secs}s; console at {}",
            console_log.display()
        )));
    }
    if !status.success() {
        return Err(BuilderVmError::NixBuildFailed(format!(
            "QEMU builder VM shell job exited {}; console at {}",
            status.code().unwrap_or(-1),
            console_log.display()
        )));
    }

    let result = read_job_result_with_diagnostics(&job_dir, &vm_state_dir)?;
    if result.exit_code != 0 {
        return Err(shell_job_exit_error(result.exit_code, &result.stderr_tail));
    }
    drop(nix_store_lock);
    Ok(BuilderShellResult {
        job_dir,
        vm_state_dir,
    })
}

#[cfg(feature = "builder-vm")]
fn validate_shell_job(job: &BuilderShellJob) -> Result<(), BuilderVmError> {
    for disk in &job.extra_disks {
        if disk.id.trim().is_empty() {
            return Err(BuilderVmError::ExtractionFailed(
                "extra disk id is empty".to_string(),
            ));
        }
        if !disk.path.is_file() {
            return Err(BuilderVmError::ExtractionFailed(format!(
                "extra disk path does not exist or is not a file: {}",
                disk.path.display()
            )));
        }
    }
    if !job.work_dir.is_dir() {
        return Err(BuilderVmError::ExtractionFailed(format!(
            "shell job work_dir must be a directory: {}",
            job.work_dir.display()
        )));
    }
    std::fs::create_dir_all(&job.artifact_out)
        .map_err(|e| io_err("creating artifact_out", &job.artifact_out, e))?;
    if job.script.trim().is_empty() {
        return Err(BuilderVmError::NixBuildFailed(
            "builder shell script is empty".to_string(),
        ));
    }
    Ok(())
}

#[cfg(feature = "builder-vm")]
fn run_build_qemu(
    job: &BuilderJob,
    mounts: &BuilderMounts,
) -> Result<BuilderArtifacts, BuilderVmError> {
    use crate::builder_vm_runtime::{
        acquire_nix_store_image_lock, builder_vm_timeout, finalize_flake_job, finalize_install_job,
        stage_closure_seed_dir, stage_job_dir,
    };
    use crate::libkrun_builder::{
        BuilderVmImage, DEFAULT_NIX_STORE_MIB, builder_vm_cache_dir, ensure_builder_vm_image,
        host_arch_tag, unique_job_id,
    };

    // 1. Validate caller inputs early — clearer than a QEMU launch failure.
    validate_build_mounts(mounts)?;
    validate_build_job(job)?;

    // 2. Locate the host tooling up front.
    let qemu_bin = locate_qemu()?;
    let (virtiofsd_bin, virtiofsd_flavor) =
        crate::virtiofsd::locate_virtiofsd().map_err(|e| BuilderVmError::VmmUnavailable {
            requested: "virtiofsd".to_string(),
            reason: format!("{e:#}"),
        })?;

    // 3. Resolve the cached builder image (kernel + rootfs + cmdline) the
    //    Stage 0 path promoted. `run_build` never takes the RootDir shape.
    let (kernel, rootfs, image_cmdline) = match ensure_builder_vm_image()? {
        BuilderVmImage::Rootfs {
            kernel_path,
            rootfs_path,
            cmdline,
        } => (kernel_path, rootfs_path, cmdline),
        BuilderVmImage::RootDir { .. } => {
            return Err(BuilderVmError::ExtractionFailed(
                "QEMU run_build requires a steady-state Rootfs builder image but got a RootDir \
                 (Stage 0) image. Re-bootstrap the builder VM."
                    .to_string(),
            ));
        }
    };

    // 4. Allocate / lock the persistent `/nix-store` virtio-blk image
    //    (vdb). Shared with the libkrun/HVF builders via the same flock so
    //    a warm store carries across backends; the lock serialises writers.
    let nix_store_lock = acquire_nix_store_image_lock(
        &builder_vm_cache_dir(),
        host_arch_tag(),
        u64::from(DEFAULT_NIX_STORE_MIB),
    )?;

    // 5. Stage the per-build job dir (Flake → cmd.sh; Install → spec).
    let job_id = unique_job_id();
    let job_dir = builder_vm_cache_dir().join("jobs").join(&job_id);
    stage_job_dir(
        &job_dir,
        job,
        mounts.staged_user_flake.as_deref(),
        // Override mode mounts the workspace at /work; stage its filtered
        // cargo tree so the build can pin `mvm/mvm-workspace` to it.
        mounts
            .staged_user_flake
            .as_ref()
            .map(|_| mounts.flake_src.as_path()),
    )?;

    // 6. Per-VM state dir + serial console log (the same console.log
    //    convention the libkrun path uses for post-mortem).
    let vm_name = format!("mvm-builder-qemu-{job_id}");
    let vm_state_dir = builder_vm_cache_dir().join("vms").join(&vm_name);
    std::fs::create_dir_all(&vm_state_dir)
        .map_err(|e| io_err("creating QEMU builder VM state dir", &vm_state_dir, e))?;
    let console_log = vm_state_dir.join("console.log");

    // 7. KVM vs TCG.
    let kvm = kvm_available();
    if !kvm {
        eprintln!("[mvm] QEMU running unaccelerated (TCG) — no /dev/kvm; this build will be slow.");
    }

    // 8. Bring up one virtiofsd per share BEFORE QEMU (QEMU connects to
    //    their sockets as a client at launch, so they must be ready). The
    //    guest mounts each by tag; `work`/`mvm-bins` are inputs it mounts
    //    read-only (`virtiofs_tag_is_read_only`), `out`/`job` read-write.
    // Attach the resolved builder image's seeded closure NAR, when it
    // carries one, as a fifth read-only share — the same per-arch cache
    // dir `ensure_builder_vm_image` just read the kernel/rootfs from.
    let closure_nar =
        crate::builder_pack::closure_nar_path(&builder_vm_cache_dir().join(host_arch_tag()));
    let closure_share_dir = closure_nar
        .as_deref()
        .map(|nar| stage_closure_seed_dir(nar, &vm_state_dir))
        .transpose()?;

    let shares = qemu_shares_with_closure_seed(
        vec![
            ("work", mounts.flake_src.as_path()),
            ("out", mounts.artifact_out.as_path()),
            ("job", job_dir.as_path()),
            ("mvm-bins", mounts.host_bin_dir.as_path()),
        ],
        closure_share_dir.as_deref(),
    );
    let mut virtiofsd = crate::virtiofsd::VirtiofsdGuard::default();
    for (tag, dir) in shares.iter().copied() {
        let sock = qemu_virtiofs_socket_path(&job_id, tag);
        virtiofsd
            .spawn(
                crate::virtiofsd::SpawnParams::new(
                    &virtiofsd_bin,
                    virtiofsd_flavor,
                    tag,
                    &sock,
                    dir,
                )
                .read_only(false),
            )
            .map_err(|e| BuilderVmError::VmmUnavailable {
                requested: "virtiofsd".to_string(),
                reason: format!("{e:#}"),
            })?;
    }

    // 9. Build the QEMU cmdline from the image's (swap hvc0 for the native
    //    QEMU serial console, force eth0, mark the backend); `root=/dev/vda ro
    //    init=…` ride unchanged.
    // The QEMU builder is always a lean Rootfs builder, so the runtime overlay
    // is required — fail closed rather than booting a builder whose guest agent
    // can never launch (it bakes none of its guest binaries).
    let runtime_overlay = require_runtime_overlay_ext4()
        .map_err(|e| BuilderVmError::RuntimeOverlayUnavailable(format!("{e:#}")))?;
    let egress_port = allocate_qemu_builder_egress_port();
    let overlay_cmdline = qemu_runtime_overlay_attachment(
        &BuilderVmImage::Rootfs {
            kernel_path: kernel.clone(),
            rootfs_path: rootfs.clone(),
            cmdline: image_cmdline.clone(),
        },
        Some(runtime_overlay.as_path()),
    )
    .ok_or_else(|| {
        BuilderVmError::RuntimeOverlayUnavailable(
            "resolved runtime overlay did not produce a builder attachment".to_string(),
        )
    })?
    .cmdline;
    let cmdline = qemu_build_cmdline(&overlay_cmdline, egress_port);
    let guest_cid = allocate_qemu_builder_guest_cid();

    // 10. Launch QEMU, serial → console.log, wrapped in `timeout`.
    let timeout_secs = builder_vm_timeout()?.as_secs();
    let mem_arg = format!("{QEMU_BUILD_MEMORY_MIB}M");
    let mut cmd = Command::new("timeout");
    cmd.arg(timeout_secs.to_string()).arg(&qemu_bin);
    cmd.args(["-m", &mem_arg, "-smp", &QEMU_BUILD_VCPUS.to_string()]);
    if let Some(machine) = qemu_machine_for_arch(std::env::consts::ARCH) {
        cmd.args(["-machine", machine]);
    }
    if kvm {
        cmd.args(["-enable-kvm", "-cpu", "host"]);
    } else {
        cmd.args(["-cpu", "max"]);
    }
    cmd.arg("-kernel").arg(&kernel);
    cmd.arg("-append").arg(
        crate::builder_cmdline::checked_builder_cmdline(cmdline.clone())
            .map_err(BuilderVmError::NixBuildFailed)?,
    );
    // Root disk (vda) + persistent nix store (vdb). The guest mounts vda
    // `ro`, so the cached `rootfs.ext4` stays pristine across builds even
    // though the block device is attached writable (mirrors libkrun). vdb
    // lands at `/dev/vdb`, exactly where mvm-host-vm-init expects it.
    cmd.arg("-drive")
        .arg(format!("file={},if=virtio,format=raw", rootfs.display()));
    cmd.arg("-drive").arg(format!(
        "file={},if=virtio,format=raw",
        nix_store_lock.path().display()
    ));
    cmd.arg("-drive").arg(format!(
        "file={},if=virtio,format=raw,readonly=on",
        runtime_overlay.display()
    ));
    // Shared memory backend required by vhost-user-fs (virtiofs). Its size
    // MUST equal `-m`.
    cmd.args([
        "-object",
        &format!("memory-backend-memfd,id=mem,size={mem_arg},share=on"),
        "-numa",
        "node,memdev=mem",
    ]);
    for (tag, _) in shares.iter().copied() {
        let sock = qemu_virtiofs_socket_path(&job_id, tag);
        cmd.arg("-chardev")
            .arg(format!("socket,id=vfs-{tag},path={}", sock.display()));
        cmd.arg("-device").arg(format!(
            "vhost-user-fs-pci,queue-size=1024,chardev=vfs-{tag},tag={tag}"
        ));
    }
    let (identity_material, identity_drive) =
        crate::libkrun_builder::stage_builder_flowmux_identity(&vm_state_dir)?;
    let egress_endpoint = BuilderVsockEgressEndpoint::spawn_with_transport(
        &vm_state_dir,
        BuilderEndpointTransport::Vsock { port: egress_port },
        identity_material.spawn_config(),
    )?;
    cmd.arg("-drive").arg(format!(
        "file={},if=virtio,format=raw,readonly=on",
        identity_drive.display()
    ));
    cmd.arg("-device")
        .arg(format!("vhost-vsock-pci,guest-cid={guest_cid}"));
    cmd.args(["-display", "none"]);
    cmd.arg("-serial")
        .arg(format!("file:{}", console_log.display()));
    cmd.args(["-monitor", "none", "-no-reboot"]);

    let status = cmd
        .status()
        .map_err(|e| BuilderVmError::NixBuildFailed(format!("spawning qemu ({qemu_bin}): {e}")))?;
    drop(egress_endpoint);

    // 11. virtiofsd is no longer needed once QEMU has exited.
    drop(virtiofsd);

    if !status.success() && status.code() == Some(124) {
        return Err(BuilderVmError::NixBuildFailed(format!(
            "QEMU builder VM timed out after {timeout_secs}s; console at {}",
            console_log.display()
        )));
    }

    // 12. Per-variant finalize via the shared job protocol — identical to
    //     the libkrun/HVF paths, so the BuilderArtifacts is byte-identical
    //     regardless of VMM. Flake reads /job/result + validates
    //     /out/rootfs.ext4; Install reads /out/result.json.
    let artifacts = match job {
        BuilderJob::Flake { .. } => finalize_flake_job(&job_dir, &mounts.artifact_out, &job_id),
        BuilderJob::Install { .. } => finalize_install_job(&mounts.artifact_out),
    }?;
    drop(nix_store_lock);
    Ok(artifacts)
}

#[cfg(feature = "builder-vm")]
fn qemu_virtiofs_socket_path(job_id: &str, tag: &str) -> PathBuf {
    // AF_UNIX paths cap at ~108 bytes on Linux. Cache roots can be deeply
    // nested in worktrees, so keep QEMU virtiofs sockets under /tmp and rely
    // on VirtiofsdGuard to remove them.
    PathBuf::from(format!("/tmp/mvm-vfs-{job_id}-{tag}.sock"))
}

/// Append the closure-seed share to `base` iff `closure_share_dir` is
/// `Some`, mirroring the libkrun path's `closure_seed_share`. Pulled out as
/// its own pure step (no qemu/virtiofsd spawn) so the "attach a share iff
/// the resolved image carries a closure" decision is unit-testable without
/// booting anything.
#[cfg(feature = "builder-vm")]
fn qemu_shares_with_closure_seed<'a>(
    mut base: Vec<(&'a str, &'a Path)>,
    closure_share_dir: Option<&'a Path>,
) -> Vec<(&'a str, &'a Path)> {
    if let Some(dir) = closure_share_dir {
        base.push((CLOSURE_SEED_TAG, dir));
    }
    base
}

/// Validate the caller's mount paths before launching QEMU. Mirrors
/// `LibkrunBuilderVm::validate_mounts` minus the libkrun-specific
/// non-UTF-8/CString guard (QEMU takes paths as process args).
#[cfg(feature = "builder-vm")]
fn validate_build_mounts(mounts: &BuilderMounts) -> Result<(), BuilderVmError> {
    if !mounts.flake_src.is_dir() {
        return Err(BuilderVmError::ExtractionFailed(format!(
            "flake source must be an existing directory: {}",
            mounts.flake_src.display()
        )));
    }
    if !mounts.host_bin_dir.is_dir() {
        return Err(BuilderVmError::ExtractionFailed(format!(
            "host_bin_dir must be an existing directory: {}",
            mounts.host_bin_dir.display()
        )));
    }
    std::fs::create_dir_all(&mounts.artifact_out)
        .map_err(|e| io_err("creating artifact_out", &mounts.artifact_out, e))?;
    Ok(())
}

/// Validate the job description. Same checks as
/// `LibkrunBuilderVm::validate_job`.
#[cfg(feature = "builder-vm")]
fn validate_build_job(job: &BuilderJob) -> Result<(), BuilderVmError> {
    match job {
        BuilderJob::Flake {
            flake_ref,
            attr_path,
        } => {
            if flake_ref.trim().is_empty() {
                return Err(BuilderVmError::NixBuildFailed(
                    "BuilderJob.flake_ref is empty".to_string(),
                ));
            }
            if attr_path.trim().is_empty() {
                return Err(BuilderVmError::NixBuildFailed(
                    "BuilderJob.attr_path is empty".to_string(),
                ));
            }
        }
        BuilderJob::Install { spec_path } => {
            if !spec_path.is_file() {
                return Err(BuilderVmError::ExtractionFailed(format!(
                    "BuilderJob::Install spec_path does not exist or is not a file: {}",
                    spec_path.display()
                )));
            }
        }
    }
    Ok(())
}

fn allocate_qemu_builder_guest_cid() -> u32 {
    static NEXT_QEMU_BUILDER_GUEST_CID: AtomicU32 = AtomicU32::new(0);

    let pid_component = std::process::id().saturating_mul(16);
    let next = NEXT_QEMU_BUILDER_GUEST_CID.fetch_add(1, Ordering::Relaxed);
    10_000u32.saturating_add(pid_component).saturating_add(next)
}

fn allocate_qemu_builder_egress_port() -> u32 {
    static NEXT_QEMU_BUILDER_EGRESS_PORT: AtomicU32 = AtomicU32::new(0);

    QEMU_BUILDER_VSOCK_EGRESS_PORT_BASE
        .saturating_add(std::process::id().saturating_mul(16))
        .saturating_add(NEXT_QEMU_BUILDER_EGRESS_PORT.fetch_add(1, Ordering::Relaxed))
}

#[cfg(feature = "builder-vm")]
fn qemu_runtime_overlay_attachment<'a>(
    image: &'a BuilderVmImage,
    runtime_overlay: Option<&'a Path>,
) -> Option<BuilderRuntimeOverlayAttachment<'a>> {
    builder_virtiofs_runtime_overlay_attachment(image, runtime_overlay)
}

/// Adapt the cached builder-image kernel cmdline for a QEMU boot. The
/// image cmdline is libkrun-flavoured (`console=hvc0 root=/dev/vda ro
/// rootfstype=ext4 init=/sbin/mvm-host-vm-init`); for QEMU we swap the
/// virtio-console for the serial line QEMU captures to `console.log`,
/// opt the guest into the shared vsock egress relay, mark
/// `mvm.backend=qemu`, and set `panic=-1` so a guest panic reboots →
/// `-no-reboot` makes QEMU exit (the host then surfaces the missing
/// `/job/result` as a crash).
///
/// `root=/dev/vda ro init=…` are preserved from the image verbatim — the
/// guest mounts the rootfs **read-only** (matching libkrun's proven
/// contract), so the shared cached image stays pristine across builds.
/// (`ro` is the proven guest contract and protects the cache — the guest
/// writes only to the `/dev/vdb` overlay, the virtio-fs shares, and tmpfs.)
///
/// Idempotent: running it on its own output is a no-op.
#[cfg(any(feature = "builder-vm", test))]
fn qemu_build_cmdline(image_cmdline: &str, egress_port: u32) -> String {
    qemu_build_cmdline_for_arch(image_cmdline, egress_port, std::env::consts::ARCH)
}

#[cfg(any(feature = "builder-vm", test))]
fn qemu_build_cmdline_for_arch(image_cmdline: &str, egress_port: u32, arch: &str) -> String {
    let mut s = image_cmdline.trim().to_string();
    let serial_console = qemu_console_for_arch(arch);
    let serial_console_token = format!("console={serial_console}");
    if s.contains("console=hvc0") {
        s = s.replace("console=hvc0", &serial_console_token);
    } else if !s.split_whitespace().any(|t| t == serial_console_token) {
        s = format!("{serial_console_token} {s}");
    }
    for tok in [
        "mvm.backend=qemu",
        QEMU_BUILDER_VSOCK_EGRESS_TOKEN,
        "panic=-1",
    ] {
        if !s.split_whitespace().any(|t| t == tok) {
            s.push(' ');
            s.push_str(tok);
        }
    }
    let egress_port_token = format!("{QEMU_BUILDER_VSOCK_EGRESS_PORT_TOKEN_PREFIX}{egress_port}");
    if !s.split_whitespace().any(|t| t == egress_port_token) {
        s.push(' ');
        s.push_str(&egress_port_token);
    }
    s
}

#[cfg(test)]
mod vsock_module_tests {
    use super::*;

    #[cfg(feature = "builder-vm")]
    use crate::libkrun_builder::{BuilderExtraDisk, BuilderShellJob};

    #[cfg(feature = "builder-vm")]
    #[test]
    fn qemu_runtime_overlay_keeps_virtiofs_transport() {
        let image = BuilderVmImage::new(
            PathBuf::from("/img/Image"),
            PathBuf::from("/img/rootfs.ext4"),
            "console=hvc0 root=/dev/vda".to_string(),
        );
        let overlay = Path::new("/cache/runtime-overlay.ext4");
        let attachment = qemu_runtime_overlay_attachment(&image, Some(overlay))
            .expect("QEMU rootfs builders attach the runtime overlay");

        assert_eq!(attachment.disk_path, overlay);
        assert!(attachment.read_only);
        assert!(attachment.cmdline.contains("mvm.runtime_data=/dev/vdc"));
        assert!(!attachment.cmdline.contains("mvm.builder_transport=disk"));
        assert!(!attachment.cmdline.contains("mvm.builder_input="));
        assert!(!attachment.cmdline.contains("mvm.builder_output="));
    }

    #[cfg(feature = "builder-vm")]
    #[test]
    fn qemu_shares_omit_closure_seed_when_absent() {
        let base = vec![("work", Path::new("/w")), ("out", Path::new("/o"))];
        let shares = qemu_shares_with_closure_seed(base.clone(), None);
        assert_eq!(shares, base);
    }

    #[cfg(feature = "builder-vm")]
    #[test]
    fn qemu_shares_append_closure_seed_when_present() {
        let base = vec![("work", Path::new("/w")), ("out", Path::new("/o"))];
        let closure_dir = Path::new("/vm-state/closure-seed");
        let shares = qemu_shares_with_closure_seed(base, Some(closure_dir));
        assert_eq!(
            shares,
            vec![
                ("work", Path::new("/w")),
                ("out", Path::new("/o")),
                (CLOSURE_SEED_TAG, closure_dir),
            ]
        );
    }

    #[test]
    fn x86_64_cmdline_swaps_hvc0_for_serial_and_adds_qemu_markers() {
        let img = "console=hvc0 root=/dev/vda ro rootfstype=ext4 init=/sbin/mvm-host-vm-init";
        let out = qemu_build_cmdline_for_arch(img, 45253, "x86_64");
        assert!(out.contains("console=ttyS0"), "got: {out}");
        assert!(!out.contains("hvc0"), "got: {out}");
        // init + root + ro are preserved from the image verbatim.
        assert!(out.contains("init=/sbin/mvm-host-vm-init"), "got: {out}");
        assert!(out.contains("root=/dev/vda"), "got: {out}");
        assert!(out.split_whitespace().any(|t| t == "ro"), "got: {out}");
        // QEMU markers appended.
        assert!(
            out.split_whitespace().any(|t| t == "mvm.backend=qemu"),
            "got: {out}"
        );
        assert!(
            out.split_whitespace()
                .any(|t| t == QEMU_BUILDER_VSOCK_EGRESS_TOKEN),
            "got: {out}"
        );
        assert!(
            out.split_whitespace().any(|t| t == "panic=-1"),
            "got: {out}"
        );
        assert!(
            out.split_whitespace()
                .any(|t| t == "mvm.vsock_egress_port=45253"),
            "got: {out}"
        );
    }

    #[test]
    fn qemu_builder_guest_cid_allocator_never_returns_reserved_host_values() {
        let cid = allocate_qemu_builder_guest_cid();
        assert!(
            cid > 2,
            "cid must stay above the reserved host slots: {cid}"
        );
    }

    #[test]
    fn aarch64_qemu_stage0_selects_virt_machine() {
        assert_eq!(qemu_machine_for_arch("aarch64"), Some("virt"));
    }

    #[test]
    fn aarch64_qemu_uses_pl011_serial_console() {
        let out = qemu_build_cmdline_for_arch(
            "console=hvc0 root=/dev/vda ro init=/sbin/mvm-host-vm-init",
            45253,
            "aarch64",
        );
        assert!(out.contains("console=ttyAMA0"), "got: {out}");
        assert!(!out.contains("console=ttyS0"), "got: {out}");
    }

    #[test]
    fn x86_64_qemu_stage0_keeps_default_machine() {
        assert_eq!(qemu_machine_for_arch("x86_64"), None);
    }

    #[test]
    fn qemu_builder_defaults_leave_host_headroom() {
        assert_eq!(QEMU_BUILD_MEMORY_MIB, 6144);
        assert_eq!(QEMU_BUILD_VCPUS, 4);
        assert_eq!(STAGE0_TIMEOUT_SECS, 14_400);
    }

    #[test]
    fn cmdline_is_idempotent() {
        let once = qemu_build_cmdline_for_arch(
            "console=hvc0 root=/dev/vda ro init=/sbin/mvm-host-vm-init",
            45253,
            "aarch64",
        );
        let twice = qemu_build_cmdline_for_arch(&once, 45253, "aarch64");
        assert_eq!(once, twice);
    }

    #[test]
    fn cmdline_adds_serial_when_no_console_present() {
        let out = qemu_build_cmdline_for_arch(
            "root=/dev/vda ro init=/sbin/mvm-host-vm-init",
            45253,
            "x86_64",
        );
        assert!(out.starts_with("console=ttyS0 "), "got: {out}");
    }

    #[test]
    fn cmdline_preserves_runtime_overlay_tokens() {
        let out = qemu_build_cmdline(
            "console=hvc0 root=/dev/vda ro init=/sbin/mvm-host-vm-init \
             mvm.runtime_data=/dev/vdc",
            45253,
        );
        assert!(out.contains("mvm.runtime_data=/dev/vdc"), "got: {out}");
    }

    #[cfg(feature = "builder-vm")]
    #[test]
    fn shell_job_validation_rejects_missing_extra_disk_before_launch() {
        let work = tempfile::tempdir().expect("work");
        let out = tempfile::tempdir().expect("out");
        let job = BuilderShellJob {
            work_dir: work.path().to_path_buf(),
            artifact_out: out.path().to_path_buf(),
            script: "true".to_string(),
            extra_disks: vec![BuilderExtraDisk {
                id: "oci-rootfs".to_string(),
                path: out.path().join("missing.ext4"),
                read_only: false,
            }],
        };

        let err = validate_shell_job(&job).expect_err("missing extra disk refused");
        assert!(
            err.to_string().contains("extra disk path does not exist"),
            "{err}"
        );
    }

    #[cfg(feature = "builder-vm")]
    #[test]
    fn virtiofs_socket_path_stays_below_linux_unix_socket_limit() {
        let path = qemu_virtiofs_socket_path("1781841830517-1343691", "work");
        let rendered = path.to_string_lossy();

        assert!(rendered.starts_with("/tmp/mvm-vfs-"), "{rendered}");
        assert!(rendered.len() < 108, "{rendered}");
    }

    #[cfg(feature = "builder-vm")]
    #[test]
    #[ignore = "live: needs Linux with qemu-system + a bootstrapped rootfs-backed builder image"]
    fn live_qemu_builder_runtime_overlay_is_read_only() {
        use crate::libkrun_builder::{BuilderVmImage, ensure_builder_vm_image};

        let image =
            ensure_builder_vm_image().expect("builder VM image must already be bootstrapped");
        assert!(
            matches!(image, BuilderVmImage::Rootfs { .. }),
            "live proof needs the steady-state rootfs-backed builder image"
        );

        let tmp = tempfile::tempdir().expect("tempdir");
        let work_dir = tmp.path().join("work");
        let artifact_out = tmp.path().join("out");
        std::fs::create_dir_all(&work_dir).expect("create work_dir");

        let job = BuilderShellJob {
            work_dir,
            artifact_out: artifact_out.clone(),
            script: r#"
set -eu
cat /proc/mounts > /job/proc-mounts.txt
cat /proc/cmdline > /job/proc-cmdline.txt
grep ' /mvm/runtime ' /proc/mounts > /job/runtime-mount.txt || true
if [ ! -s /job/runtime-mount.txt ]; then
  echo "/mvm/runtime missing from /proc/mounts" >&2
  echo "/proc/cmdline: $(cat /proc/cmdline)" >&2
  cat /proc/mounts >&2
  exit 1
fi
if ! grep -q ' /mvm/runtime .* ro[, ]' /job/runtime-mount.txt; then
  echo "runtime overlay mount is not read-only" >&2
  echo "/proc/cmdline: $(cat /proc/cmdline)" >&2
  cat /job/runtime-mount.txt >&2
  exit 1
fi
if touch /mvm/runtime/probe-write 2>/job/runtime-touch.err; then
  echo "runtime overlay unexpectedly writable" >&2
  echo "/proc/cmdline: $(cat /proc/cmdline)" >&2
  exit 1
fi
"#
            .to_string(),
            extra_disks: Vec::new(),
        };

        let result = QemuBuilderVm
            .run_shell_script(&job)
            .expect("builder shell job must succeed");
        let mount_line = std::fs::read_to_string(result.job_dir.join("runtime-mount.txt"))
            .expect("read runtime-mount.txt");
        let touch_err = std::fs::read_to_string(result.job_dir.join("runtime-touch.err"))
            .expect("read runtime-touch.err");
        assert!(
            mount_line.contains("/mvm/runtime"),
            "proof artifact must contain the runtime mount line: {mount_line}"
        );
        assert!(
            mount_line.contains(" ro,") || mount_line.ends_with(" ro"),
            "runtime overlay mount must be read-only: {mount_line}"
        );
        assert!(
            touch_err.contains("Read-only file system"),
            "write attempt must fail with EROFS: {touch_err}"
        );
        assert!(
            result.vm_state_dir.join("console.log").exists(),
            "live proof must leave a console log for diagnosis"
        );
    }

    /// Stage 0 delegates the host-owned disks to the single-purpose helper once.
    ///
    /// The FlowMux identity image was attached twice, which consumed a device
    /// letter and pushed the Nix store one slot further down the enumeration —
    /// past where the guest looked for it. The guest then fell back to
    /// enumeration order and selected the 32 KiB identity image as its store,
    /// failing closed on every Stage 0 kernel build.
    #[test]
    fn stage0_calls_host_owned_disk_attachment_once() {
        let src = include_str!("qemu_builder.rs");
        let block = src
            .split_once("for disk in [&vda, &vdb, &vdc, &vdd]")
            .expect("stage 0 still attaches its disks here")
            .1
            .split_once("\"-device\"")
            .expect("the drive list ends before the vsock device")
            .0;

        let calls = block.matches("attach_stage0_identity_and_store(").count();
        assert_eq!(
            calls, 1,
            "the host-owned Stage 0 disks are attached through the helper {calls} times; \
             duplicate attachment re-letters every disk behind them"
        );
    }
}
