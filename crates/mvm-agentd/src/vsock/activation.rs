//! Activation protocol for PID-1 initramfs boot (Plan 270).
//!
//! The host sends `ActivateEnvironment` over vsock after the kernel has
//! booted the universal initramfs.  The message carries the dm-verity
//! rootfs/runtime-overlay parameters and any virtio-fs custom volumes the
//! workload admitted.  The agent validates the message, mounts the
//! environment, drops privilege, and transitions from the `Awaiting`
//! boot state to `Activated`.

use serde::{Deserialize, Serialize};

/// Host-to-guest activation message.  This is the only control verb
/// accepted before privilege drop in PID-1 initramfs mode.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ActivateEnvironment {
    /// Rootfs dm-verity configuration.  The data device becomes the
    /// guest's `/` after activation.
    pub rootfs: RootfsConfig,
    /// Runtime-overlay dm-verity configuration.  Mounted read-only at
    /// `/mvm/runtime` inside the rootfs before pivot.
    pub runtime: RuntimeOverlayConfig,
    /// Optional virtio-fs volumes mounted after the rootfs and runtime
    /// overlay are in place.
    #[serde(default)]
    pub volumes: Vec<VolumeConfig>,
    /// Optional verb-grant envelope to pin before serving operational
    /// RPCs.  When present, the activation message itself must be signed
    /// by the host-signer trust anchor.
    #[serde(default)]
    pub verb_grant_envelope: Option<mvm_core::protocol::vm_backend::VerbGrantEnvelope>,
}

/// dm-verity block-device target.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct RootfsConfig {
    /// Data device path, e.g. `/dev/vda`.
    pub data_dev: String,
    /// Hash-tree device path, e.g. `/dev/vdb`.
    pub hash_dev: String,
    /// 64-character lowercase hex dm-verity root hash.
    pub roothash: String,
}

/// dm-verity runtime-overlay target.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct RuntimeOverlayConfig {
    /// Data device path, e.g. `/dev/vdc`.
    pub data_dev: String,
    /// Hash-tree device path, e.g. `/dev/vdd`.
    pub hash_dev: String,
    /// 64-character lowercase hex dm-verity root hash.
    pub roothash: String,
}

/// virtio-fs volume to mount after rootfs activation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct VolumeConfig {
    /// virtio-fs tag advertised by the host for this share.
    pub tag: String,
    /// Absolute guest mountpoint.  Must pass `MountPathPolicy`.
    pub mountpoint: String,
    /// Mount read-only when `true`.
    #[serde(default)]
    pub read_only: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn activate_environment_roundtrips() {
        let env = ActivateEnvironment {
            rootfs: RootfsConfig {
                data_dev: "/dev/vda".to_string(),
                hash_dev: "/dev/vdb".to_string(),
                roothash: "a".repeat(64),
            },
            runtime: RuntimeOverlayConfig {
                data_dev: "/dev/vdc".to_string(),
                hash_dev: "/dev/vdd".to_string(),
                roothash: "b".repeat(64),
            },
            volumes: vec![VolumeConfig {
                tag: "data".to_string(),
                mountpoint: "/mnt/data".to_string(),
                read_only: true,
            }],
            verb_grant_envelope: None,
        };
        let json = serde_json::to_string(&env).expect("serialize");
        let parsed: ActivateEnvironment = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.rootfs.data_dev, "/dev/vda");
        assert_eq!(parsed.runtime.roothash, "b".repeat(64));
        assert_eq!(parsed.volumes.len(), 1);
        assert!(parsed.volumes[0].read_only);
    }

    #[test]
    fn activate_environment_rejects_unknown_fields() {
        let json = r#"{
            "rootfs": {"data_dev":"/dev/vda","hash_dev":"/dev/vdb","roothash":"00"},
            "runtime": {"data_dev":"/dev/vdc","hash_dev":"/dev/vdd","roothash":"11"},
            "unknown": 1
        }"#;
        assert!(serde_json::from_str::<ActivateEnvironment>(json).is_err());
    }
}
