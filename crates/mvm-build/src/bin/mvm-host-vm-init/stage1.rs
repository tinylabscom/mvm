//! Stage 1: PID 1 of the builder boot payload.
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
pub(crate) use linux::run;

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
