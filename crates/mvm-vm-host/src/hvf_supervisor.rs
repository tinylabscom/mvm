//! Config contract for `mvm-hvf-supervisor` — the per-VM host process for the
//! raw HVF macOS backend (Plan 214). `mvm_backend::hvf` writes this as JSON on
//! the supervisor's stdin; the supervisor boots the guest via
//! `mvm_backend::hvf::boot_kernel` and captures its console.
//!
//! `#[serde(deny_unknown_fields)]` keeps the host↔supervisor contract
//! fail-closed (claim 4.1 / W4.1): an unexpected field is a hard parse error,
//! never a silently-ignored option.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Everything the supervisor needs to boot one guest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HvfSupervisorConfig {
    /// arm64 `Image` to boot.
    pub kernel: PathBuf,
    /// Optional initramfs (cpio, gzip-or-raw).
    #[serde(default)]
    pub initramfs: Option<PathBuf>,
    /// Optional virtio-blk backing image.
    #[serde(default)]
    pub disk: Option<PathBuf>,
    /// Attach a virtio-vsock device.
    #[serde(default)]
    pub vsock: bool,
    /// Where to write the captured guest console.
    pub console_log: PathBuf,
    /// Where to write this process's PID once booting starts (the backend polls
    /// for it to confirm launch, and reads it to stop/status the VM).
    pub pid_file: PathBuf,
    /// Run budget in seconds — a booting kernel never exits on its own, so the
    /// guest is forced out after this long. The backend sets it from the VM's
    /// requested lifetime.
    pub timeout_secs: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_roundtrip_with_all_fields() {
        let cfg = HvfSupervisorConfig {
            kernel: "/k/Image".into(),
            initramfs: Some("/k/initrd.cpio".into()),
            disk: Some("/k/disk.img".into()),
            vsock: true,
            console_log: "/state/console.log".into(),
            pid_file: "/state/hvf.pid".into(),
            timeout_secs: 30,
        };
        let json = serde_json::to_string(&cfg).unwrap();
        assert_eq!(
            serde_json::from_str::<HvfSupervisorConfig>(&json).unwrap(),
            cfg
        );
    }

    #[test]
    fn optional_fields_default() {
        let json =
            r#"{"kernel":"/k/Image","console_log":"/c.log","pid_file":"/p.pid","timeout_secs":5}"#;
        let cfg: HvfSupervisorConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.initramfs, None);
        assert_eq!(cfg.disk, None);
        assert!(!cfg.vsock);
        assert_eq!(cfg.timeout_secs, 5);
    }

    #[test]
    fn unknown_field_is_rejected() {
        // deny_unknown_fields: a typo'd / unexpected field fails closed.
        let json =
            r#"{"kernel":"/k","console_log":"/c","pid_file":"/p","timeout_secs":1,"bogus":1}"#;
        assert!(serde_json::from_str::<HvfSupervisorConfig>(json).is_err());
    }
}
