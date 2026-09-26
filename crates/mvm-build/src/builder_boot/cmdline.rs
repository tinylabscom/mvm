//! The builder boot contract's kernel command line: the one the host writes
//! for every builder backend, and what the guest's stage 1 reads back from it.

use std::path::{Path, PathBuf};

use thiserror::Error;

use super::PAYLOAD_CMDLINE_KEY;
use super::payload::PayloadDigest;
use crate::builder_vm_transport::{
    BUILDER_INPUT_DEVICE, BUILDER_OUTPUT_DEVICE, BUILDER_RUNTIME_DEVICE, BUILDER_VSOCK_EGRESS_TOKEN,
};

/// The PID 1 a legacy builder image bakes, reached with `init=` when a boot
/// carries no payload.
const BAKED_INIT: &str = "/sbin/mvm-host-vm-init";

/// The console tokens a libkrun builder boots with. libkrun's console is a
/// virtio-console (`hvc0`). Declared here rather than beside the libkrun
/// builder so every backend's console base is visible to the contract's tests
/// whether or not the libkrun backend is compiled in.
pub const LIBKRUN_BUILDER_CONSOLE_BASE: &str = "console=hvc0 panic=-1 loglevel=8";

/// How one builder boot reaches its PID 1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuilderBoot {
    /// The boot payload at `initramfs`, whose `/init` the kernel runs and which
    /// verifies itself against `digest`.
    Payload {
        initramfs: PathBuf,
        digest: PayloadDigest,
    },
    /// No payload: the image's own baked `mvm-host-vm-init`. Only a legacy
    /// image (boot ABI 0) has one.
    Baked,
}

impl BuilderBoot {
    /// The initramfs the VMM must load, if this boot has one.
    pub fn initramfs(&self) -> Option<&Path> {
        match self {
            Self::Payload { initramfs, .. } => Some(initramfs),
            Self::Baked => None,
        }
    }

    pub fn payload_digest(&self) -> Option<&PayloadDigest> {
        match self {
            Self::Payload { digest, .. } => Some(digest),
            Self::Baked => None,
        }
    }

    /// The one token that differs between the two. A payload boot names no
    /// `init=`: the kernel runs the initramfs `/init`, and an `init=` naming a
    /// path the image may not have would only mislead whoever reads the line.
    fn init_token(&self) -> String {
        match self {
            Self::Payload { digest, .. } => format!("{PAYLOAD_CMDLINE_KEY}={digest}"),
            Self::Baked => format!("init={BAKED_INIT}"),
        }
    }
}

/// The builder kernel command line, for every backend.
///
/// `console_base` is the backend's own console and panic tokens — the one part
/// that differs per VMM, because each exposes a different console device.
/// Everything after it is the contract: the read-only root on `/dev/vda`, the
/// boot's PID 1, the disk transport's input and output devices, the vsock
/// egress relay, and the runtime overlay on `/dev/vde` when the boot attaches
/// one. Four backends used to assemble this separately, and drifted: that is
/// how Firecracker once booted with HVF's console.
pub fn builder_boot_cmdline(
    console_base: &str,
    boot: &BuilderBoot,
    runtime_overlay: bool,
) -> String {
    let mut tokens = vec![
        console_base.trim().to_string(),
        "root=/dev/vda ro rootfstype=ext4 rootwait".to_string(),
        boot.init_token(),
        format!(
            "mvm.builder_transport=disk mvm.builder_input={BUILDER_INPUT_DEVICE} \
             mvm.builder_output={BUILDER_OUTPUT_DEVICE} {BUILDER_VSOCK_EGRESS_TOKEN}"
        ),
    ];
    if runtime_overlay {
        tokens.push(format!("mvm.runtime_data={BUILDER_RUNTIME_DEVICE}"));
    }
    tokens.retain(|token| !token.is_empty());
    tokens.join(" ")
}

/// What stage 1 needs from `/proc/cmdline`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stage1Cmdline {
    /// The digest the payload's `MANIFEST` must hash to.
    pub payload: PayloadDigest,
    /// The builder image's block device, mounted read-only as the new root.
    pub root_device: String,
}

/// Why stage 1 cannot proceed from the command line it was given.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum Stage1CmdlineError {
    #[error("the kernel command line carries no {PAYLOAD_CMDLINE_KEY}= digest")]
    NoPayloadDigest,
    #[error("{PAYLOAD_CMDLINE_KEY}={0:?} is not a SHA-256 digest")]
    BadPayloadDigest(String),
    #[error("the kernel command line names no root= device")]
    NoRootDevice,
    #[error("the builder root must be ext4, not {0}")]
    UnsupportedRootFs(String),
}

/// The value of the last `key=` token. The kernel lets a later token override
/// an earlier one, and a VMM may append its own `root=` after ours.
fn last_value<'a>(cmdline: &'a str, key: &str) -> Option<&'a str> {
    cmdline
        .split_whitespace()
        .filter_map(|token| token.strip_prefix(key)?.strip_prefix('='))
        .next_back()
}

/// Parse what stage 1 needs, refusing a command line that would have it guess.
pub fn parse_stage1_cmdline(cmdline: &str) -> Result<Stage1Cmdline, Stage1CmdlineError> {
    let digest =
        last_value(cmdline, PAYLOAD_CMDLINE_KEY).ok_or(Stage1CmdlineError::NoPayloadDigest)?;
    let payload = PayloadDigest::parse(digest)
        .map_err(|_| Stage1CmdlineError::BadPayloadDigest(digest.to_string()))?;
    let root_device = last_value(cmdline, "root")
        .filter(|device| !device.is_empty())
        .ok_or(Stage1CmdlineError::NoRootDevice)?
        .to_string();
    if let Some(fstype) = last_value(cmdline, "rootfstype")
        && fstype != "ext4"
    {
        return Err(Stage1CmdlineError::UnsupportedRootFs(fstype.to_string()));
    }
    Ok(Stage1Cmdline {
        payload,
        root_device,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIGEST: &str = "15ed68a00c9fed2e2cdb9c479b20cd770271b6a9df721e1ebf065e8e42b77ba0";

    fn payload_boot() -> BuilderBoot {
        BuilderBoot::Payload {
            initramfs: PathBuf::from("/state/boot-payload.cpio"),
            digest: PayloadDigest::parse(DIGEST).unwrap(),
        }
    }

    #[test]
    fn a_payload_boot_names_its_digest_and_no_init() {
        let line = builder_boot_cmdline("console=ttyAMA0 panic=-1", &payload_boot(), false);
        assert_eq!(
            line,
            format!(
                "console=ttyAMA0 panic=-1 root=/dev/vda ro rootfstype=ext4 rootwait \
                 mvm.boot_payload={DIGEST} mvm.builder_transport=disk \
                 mvm.builder_input=/dev/vdc mvm.builder_output=/dev/vdd mvm.vsock_egress=1"
            )
        );
        assert!(!line.contains("init="), "{line}");
    }

    #[test]
    fn a_baked_boot_names_the_images_own_init() {
        let line = builder_boot_cmdline("console=hvc0", &BuilderBoot::Baked, true);
        assert!(line.contains(" init=/sbin/mvm-host-vm-init "), "{line}");
        assert!(!line.contains(PAYLOAD_CMDLINE_KEY), "{line}");
        assert!(line.ends_with(" mvm.runtime_data=/dev/vde"), "{line}");
        assert_eq!(BuilderBoot::Baked.initramfs(), None);
    }

    /// What the host writes, the guest must read back.
    #[test]
    fn stage1_reads_the_line_the_host_writes() {
        let line = builder_boot_cmdline("console=ttyS0", &payload_boot(), true);
        let parsed = parse_stage1_cmdline(&line).unwrap();
        assert_eq!(Some(&parsed.payload), payload_boot().payload_digest());
        assert_eq!(parsed.root_device, "/dev/vda");
    }

    #[test]
    fn reads_the_digest_and_the_root_device() {
        let parsed = parse_stage1_cmdline(&format!(
            "console=ttyAMA0 root=/dev/vda ro rootfstype=ext4 rootwait mvm.boot_payload={DIGEST}"
        ))
        .unwrap();
        assert_eq!(parsed.payload.as_str(), DIGEST);
        assert_eq!(parsed.root_device, "/dev/vda");
    }

    /// Firecracker appends its own `root=` after the spec's cmdline.
    #[test]
    fn the_last_root_wins() {
        let parsed = parse_stage1_cmdline(&format!(
            "root=/dev/vdz mvm.boot_payload={DIGEST} root=/dev/vda ro"
        ))
        .unwrap();
        assert_eq!(parsed.root_device, "/dev/vda");
    }

    #[test]
    fn a_missing_or_malformed_digest_is_refused() {
        assert_eq!(
            parse_stage1_cmdline("root=/dev/vda").unwrap_err(),
            Stage1CmdlineError::NoPayloadDigest
        );
        assert_eq!(
            parse_stage1_cmdline("root=/dev/vda mvm.boot_payload=abc").unwrap_err(),
            Stage1CmdlineError::BadPayloadDigest("abc".to_string())
        );
    }

    #[test]
    fn a_missing_root_or_a_foreign_filesystem_is_refused() {
        assert_eq!(
            parse_stage1_cmdline(&format!("mvm.boot_payload={DIGEST}")).unwrap_err(),
            Stage1CmdlineError::NoRootDevice
        );
        assert_eq!(
            parse_stage1_cmdline(&format!(
                "root=/dev/vda rootfstype=xfs mvm.boot_payload={DIGEST}"
            ))
            .unwrap_err(),
            Stage1CmdlineError::UnsupportedRootFs("xfs".to_string())
        );
    }

    #[test]
    fn a_key_is_matched_whole() {
        assert_eq!(
            last_value("rootwait root=/dev/vda", "root"),
            Some("/dev/vda")
        );
        assert_eq!(last_value("rootfstype=ext4", "root"), None);
    }
}
