//! How this PID 1 got here, and stage 1 of the builder boot payload.
//!
//! A builder guest's PID 1 is this binary in one of three roles
//! ([`BootRole`]): stage 1, unpacked from the boot payload; stage 2, the same
//! binary re-executed by stage 1 from its tmpfs copy; or a direct boot from an
//! image's baked copy. Stages 2 and direct are the builder init proper; they
//! differ only in what is already mounted ([`PseudoFs`]).
//!
//! ## Stage 1
//!
//! The kernel unpacks the payload `mvmctl` loaded as the initramfs and runs
//! its `/init`, which is this binary. Stage 1 turns the payload into the
//! builder's PID 1:
//!
//! 1. mounts `/proc`, `/sys`, `/dev`, `/run` and `/tmp` in the initramfs;
//! 2. checks the payload against the digest on the kernel command line;
//! 3. copies it to `/run/mvm/host-bins` on the `/run` tmpfs;
//! 4. mounts the builder image read-only;
//! 5. checks the image's boot ABI and that it has a `/run` to carry the
//!    tmpfs into;
//! 6. frees the initramfs copies, pivots into the image, and
//! 7. re-executes itself from the tmpfs copy as stage 2 — today's
//!    `mvm-host-vm-init`, still PID 1.
//!
//! Any refusal prints one [`REFUSAL_MARKER`] line naming what failed and
//! powers the VM off. There is no fallback: a payload that cannot be verified,
//! or an image outside the supported ABI range, is a wrong answer if booted.

use std::path::Path;

use mvm_build::builder_boot::{
    BootAbiError, BootPayloadError, IMAGE_ABI_MARKER, Stage1CmdlineError, check_image_abi,
    parse_image_abi_marker, payload_supported_abis,
};
use mvm_core::image_set::BuilderBootAbi;

/// The console line every stage-1 refusal starts with.
pub(crate) const REFUSAL_MARKER: &str = "mvm-host-vm-init: stage1 refused:";

/// Which role this process plays at boot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BootRole {
    /// PID 1 unpacked from the boot payload, still inside the initramfs.
    Stage1,
    /// Re-executed by stage 1 from the payload's tmpfs copy.
    Stage2,
    /// Booted from a builder image's own baked copy, with no payload.
    Direct,
}

/// Decide the role from what this process can observe: its pid, whether the
/// payload's manifest is on disk, and the stage marker stage 1 exports.
pub(crate) fn boot_role(pid: u32, payload_present: bool, stage_env: Option<&str>) -> BootRole {
    if stage_env == Some(mvm_build::builder_boot::STAGE2) {
        BootRole::Stage2
    } else if pid == 1 && payload_present {
        BootRole::Stage1
    } else {
        BootRole::Direct
    }
}

/// Which pseudo-filesystems a stage-2 or direct PID 1 still has to mount.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PseudoFs {
    /// A direct boot: nothing is mounted yet.
    MountAll,
    /// Stage 2 of a payload boot. Stage 1 mounted `/proc`, `/sys`, `/dev`,
    /// `/run` and `/tmp` and carried them across the pivot; a fresh tmpfs on
    /// `/run` would hide the payload this process is running from.
    CarriedByStage1,
}

/// The mounts every PID 1 needs before anything else, as
/// `(source, target, fstype)`. `/run` must be a tmpfs: the rootfs is mounted
/// read-only and runtime state (locks, sockets, pid files) lives there.
pub(crate) fn base_pseudofs_mounts(
    pseudo_fs: PseudoFs,
) -> &'static [(&'static str, &'static str, &'static str)] {
    const ALL: &[(&str, &str, &str)] = &[
        ("proc", "/proc", "proc"),
        ("sysfs", "/sys", "sysfs"),
        ("devtmpfs", "/dev", "devtmpfs"),
        ("tmpfs", "/tmp", "tmpfs"),
        ("tmpfs", "/run", "tmpfs"),
    ];
    match pseudo_fs {
        PseudoFs::MountAll => ALL,
        PseudoFs::CarriedByStage1 => &[],
    }
}

/// PID 1's `PATH`: the payload's copies first, so a builder booted from the
/// payload resolves `mvm-host-vm-init` and `mvm-builderd` to the copies the
/// running `mvmctl` supplied rather than stale ones an older image baked;
/// then the builder image's layout (busybox at `/bin/*`, extra packages at
/// `/sbin/*` and `/usr/local/bin/*`). The payload directory does not exist on
/// a direct boot and is skipped.
pub(crate) fn pid1_path() -> String {
    format!(
        "{}:/usr/local/sbin:/usr/local/bin:/sbin:/usr/sbin:/bin:/usr/bin",
        mvm_build::builder_boot::RUNTIME_HOST_BIN_DIR
    )
}

/// Run PID 1 in the role this process finds itself in.
#[cfg(target_os = "linux")]
pub(crate) fn run_pid1() -> std::process::ExitCode {
    let payload_manifest = Path::new("/")
        .join(mvm_build::builder_boot::PAYLOAD_DIR_IN_INITRAMFS)
        .join(mvm_build::builder_boot::PAYLOAD_MANIFEST_NAME);
    let stage = std::env::var(mvm_build::builder_boot::STAGE_ENV).ok();
    match boot_role(
        std::process::id(),
        payload_manifest.is_file(),
        stage.as_deref(),
    ) {
        BootRole::Stage1 => run(),
        BootRole::Stage2 => crate::linux::run(PseudoFs::CarriedByStage1),
        BootRole::Direct => crate::linux::run(PseudoFs::MountAll),
    }
}

/// Why stage 1 stopped.
#[derive(Debug, thiserror::Error)]
pub(crate) enum Stage1Refusal {
    #[error(transparent)]
    Cmdline(#[from] Stage1CmdlineError),
    #[error(transparent)]
    Payload(#[from] BootPayloadError),
    #[error(transparent)]
    Abi(#[from] BootAbiError),
    #[error("reading {IMAGE_ABI_MARKER} from the builder image: {0}")]
    AbiMarkerUnreadable(std::io::Error),
    #[error(
        "the builder image has no /run directory to carry the payload's tmpfs into; \
         it does not meet the builder boot ABI"
    )]
    NoRunMountPoint,
    #[error("root device {device} did not appear within {secs}s")]
    RootDeviceTimeout { device: String, secs: u64 },
    #[error("{0}")]
    Mount(String),
    #[error("re-executing from the payload copy: {0}")]
    Exec(std::io::Error),
}

/// The console line a refusal is reported on.
pub(crate) fn refusal_line(refusal: &Stage1Refusal) -> String {
    format!("{REFUSAL_MARKER} {refusal}")
}

/// The checks against the mounted image at `root`: its boot ABI must be one
/// this payload boots, and it must have a `/run` for the pivot to carry the
/// payload's tmpfs into.
pub(crate) fn check_image(root: &Path) -> Result<BuilderBootAbi, Stage1Refusal> {
    let marker_path = root.join(IMAGE_ABI_MARKER.trim_start_matches('/'));
    let marker = match std::fs::read_to_string(&marker_path) {
        Ok(contents) => Some(contents),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(Stage1Refusal::AbiMarkerUnreadable(e)),
    };
    let abi = parse_image_abi_marker(marker.as_deref())?;
    check_image_abi(abi, payload_supported_abis())?;
    if !root.join("run").is_dir() {
        return Err(Stage1Refusal::NoRunMountPoint);
    }
    Ok(abi)
}

#[cfg(target_os = "linux")]
use linux::run;

#[cfg(target_os = "linux")]
mod linux {
    use std::convert::Infallible;
    use std::os::unix::process::CommandExt;
    use std::path::Path;
    use std::process::{Command, ExitCode};
    use std::time::{Duration, Instant};

    use mvm_agentd::guest_mount;
    use mvm_agentd::vsock::RootfsConfig;
    use mvm_build::builder_boot::{
        PAYLOAD_DIR_IN_INITRAMFS, RUNTIME_HOST_BIN_DIR, STAGE_ENV, STAGE1_MEMBER, STAGE2,
        install_payload, parse_stage1_cmdline, verify_unpacked_payload,
    };

    use super::{Stage1Refusal, check_image};

    /// How long the root device may take to appear. Virtio-blk probes
    /// asynchronously, so the node is not always there when PID 1 starts.
    const ROOT_DEVICE_WAIT: Duration = Duration::from_secs(30);

    /// Run stage 1. Returns only to power the VM off after a refusal: success
    /// replaces this process image with stage 2.
    pub(crate) fn run() -> ExitCode {
        eprintln!("mvm-host-vm-init: stage1 starting from the boot payload");
        match stage1() {
            Ok(never) => match never {},
            Err(refusal) => {
                eprintln!("{}", super::refusal_line(&refusal));
                crate::linux::power_off()
            }
        }
    }

    fn stage1() -> Result<Infallible, Stage1Refusal> {
        guest_mount::mount_early_filesystems().map_err(mount_error)?;
        let cmdline = std::fs::read_to_string("/proc/cmdline")
            .map_err(|e| Stage1Refusal::Mount(format!("reading /proc/cmdline: {e}")))?;
        let boot = parse_stage1_cmdline(&cmdline)?;

        let payload_dir = Path::new("/").join(PAYLOAD_DIR_IN_INITRAMFS);
        let manifest = verify_unpacked_payload(&payload_dir, &boot.payload)?;
        install_payload(&payload_dir, &manifest, Path::new(RUNTIME_HOST_BIN_DIR))?;

        wait_for_device(&boot.root_device)?;
        let root = guest_mount::mount_rootfs(&RootfsConfig {
            data_dev: boot.root_device.clone(),
            hash_dev: None,
            roothash: None,
            virtiofs_tag: None,
            in_place: false,
        })
        .map_err(mount_error)?;
        let abi = check_image(&root)?;
        eprintln!(
            "mvm-host-vm-init: stage1 payload {} verified; builder image {} is boot ABI {abi}",
            boot.payload, boot.root_device
        );

        // The initramfs is RAM for as long as the VM runs; the tmpfs copy is
        // all that is needed from here on.
        let _ = std::fs::remove_dir_all(&payload_dir);
        let _ = std::fs::remove_file("/init");

        guest_mount::pivot_to_root(&root).map_err(mount_error)?;
        let stage2 = Path::new(RUNTIME_HOST_BIN_DIR).join(STAGE1_MEMBER);
        Err(Stage1Refusal::Exec(
            Command::new(stage2).env(STAGE_ENV, STAGE2).exec(),
        ))
    }

    fn mount_error(e: guest_mount::MountError) -> Stage1Refusal {
        Stage1Refusal::Mount(e.to_string())
    }

    fn wait_for_device(device: &str) -> Result<(), Stage1Refusal> {
        let deadline = Instant::now() + ROOT_DEVICE_WAIT;
        while !Path::new(device).exists() {
            if Instant::now() >= deadline {
                return Err(Stage1Refusal::RootDeviceTimeout {
                    device: device.to_string(),
                    secs: ROOT_DEVICE_WAIT.as_secs(),
                });
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_payload_init_is_stage1_only_as_pid_1_before_the_handover() {
        assert_eq!(boot_role(1, true, None), BootRole::Stage1);
        assert_eq!(boot_role(1, true, Some("2")), BootRole::Stage2);
        assert_eq!(boot_role(1, false, Some("2")), BootRole::Stage2);
        // A baked image booted with `init=` has no payload on disk.
        assert_eq!(boot_role(1, false, None), BootRole::Direct);
        // A subcommand run inside a running builder is not PID 1.
        assert_eq!(boot_role(812, true, None), BootRole::Direct);
    }

    fn image_root(marker: Option<&str>, with_run: bool) -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        if let Some(marker) = marker {
            std::fs::create_dir_all(root.path().join("etc/mvm")).unwrap();
            std::fs::write(root.path().join("etc/mvm/builder-boot-abi"), marker).unwrap();
        }
        if with_run {
            std::fs::create_dir(root.path().join("run")).unwrap();
        }
        root
    }

    #[test]
    fn a_legacy_image_without_a_marker_is_abi_0() {
        let root = image_root(None, true);
        assert_eq!(check_image(root.path()).unwrap(), BuilderBootAbi::LEGACY);
    }

    #[test]
    fn a_payload_image_is_abi_1() {
        let root = image_root(Some("1\n"), true);
        assert_eq!(check_image(root.path()).unwrap(), BuilderBootAbi::PAYLOAD);
    }

    #[test]
    fn an_image_above_the_supported_range_is_refused() {
        let root = image_root(Some("2\n"), true);
        let refusal = check_image(root.path()).unwrap_err().to_string();
        assert!(
            refusal.contains("ABI 2") && refusal.contains("0..=1"),
            "{refusal}"
        );
    }

    #[test]
    fn an_image_missing_run_is_refused() {
        let root = image_root(Some("1\n"), false);
        assert!(matches!(
            check_image(root.path()).unwrap_err(),
            Stage1Refusal::NoRunMountPoint
        ));
    }

    /// A refusal is one console line the host can find, naming what failed.
    #[test]
    fn every_refusal_is_one_marked_line() {
        let refusals = [
            Stage1Refusal::RootDeviceTimeout {
                device: "/dev/vda".to_string(),
                secs: 30,
            },
            Stage1Refusal::Mount("mount(/dev/vda -> /mnt/root, ext4): EINVAL".to_string()),
            Stage1Refusal::Exec(std::io::Error::from(std::io::ErrorKind::NotFound)),
            Stage1Refusal::NoRunMountPoint,
        ];
        for refusal in &refusals {
            let line = refusal_line(refusal);
            assert!(line.starts_with(REFUSAL_MARKER), "{line}");
            assert!(!line.contains('\n'), "{line}");
        }
        assert!(refusal_line(&refusals[0]).contains("/dev/vda"));
    }

    #[test]
    fn a_direct_boot_mounts_the_base_pseudo_filesystems() {
        let targets: Vec<&str> = base_pseudofs_mounts(PseudoFs::MountAll)
            .iter()
            .map(|(_, target, _)| *target)
            .collect();
        assert_eq!(targets, ["/proc", "/sys", "/dev", "/tmp", "/run"]);
    }

    /// Stage 1 carried these across the pivot. A second `/run` tmpfs would
    /// hide the payload binaries stage 2 is executing from.
    #[test]
    fn stage2_mounts_nothing_stage1_carried_across() {
        assert!(base_pseudofs_mounts(PseudoFs::CarriedByStage1).is_empty());
        for (_, target, _) in base_pseudofs_mounts(PseudoFs::MountAll) {
            assert!(
                mvm_agentd::guest_mount::PIVOT_MOVED_MOUNTS.contains(target),
                "{target} is skipped in stage 2 but stage 1 does not carry it"
            );
        }
    }

    #[test]
    fn pid1_resolves_the_payload_copies_first() {
        let path = pid1_path();
        let first = path.split(':').next().unwrap();
        assert_eq!(first, mvm_build::builder_boot::RUNTIME_HOST_BIN_DIR);
        assert!(path.contains(":/sbin:"), "{path}");
    }

    /// Stage 2 runs from the payload's tmpfs copy, so the directory it lives
    /// in has to be one the pivot carries into the builder image.
    #[test]
    fn the_payload_copy_survives_the_pivot() {
        let top = mvm_build::builder_boot::RUNTIME_HOST_BIN_DIR
            .split('/')
            .nth(1)
            .map(|first| format!("/{first}"))
            .unwrap();
        assert!(
            mvm_agentd::guest_mount::PIVOT_MOVED_MOUNTS.contains(&top.as_str()),
            "{top} is not carried across the pivot"
        );
    }
}
