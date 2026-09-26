//! The builder boot contract's kernel command line, read from the guest side.

use thiserror::Error;

use super::PAYLOAD_CMDLINE_KEY;
use super::payload::PayloadDigest;

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
