//! Activation protocol for PID-1 initramfs boot.
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
    /// Rootfs configuration.  The data device (or virtio-fs tag) becomes
    /// the guest's `/` after activation.
    pub rootfs: RootfsConfig,
    /// Runtime-overlay dm-verity configuration, when the boot carries an
    /// overlay.  Mounted read-only at `/mvm/runtime` inside the rootfs
    /// before pivot.  `None` for a rootfs-only boot.
    #[serde(default)]
    pub runtime: Option<RuntimeOverlayConfig>,
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

/// Root device the guest mounts as `/`.  Three shapes, selected by which
/// optional fields are set:
///
/// - **dm-verity block** (`roothash` + `hash_dev`): create the `root`
///   dm-verity target and mount it read-only.
/// - **plain block** (neither): mount `data_dev` read-only without
///   verification (unverified dev-tier boot).
/// - **virtio-fs root** (`virtiofs_tag`): mount the virtio-fs tag read-only
///   as the root — the block-less dev-tier boot.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct RootfsConfig {
    /// Data device path, e.g. `/dev/vda`.  Empty for a virtio-fs root.
    pub data_dev: String,
    /// Hash-tree device path, e.g. `/dev/vdb`.  Present only for a dm-verity
    /// rootfs.
    #[serde(default)]
    pub hash_dev: Option<String>,
    /// 64-character lowercase hex dm-verity root hash.  Absent for an
    /// unverified plain-block root.
    #[serde(default)]
    pub roothash: Option<String>,
    /// virtio-fs tag to mount as the root instead of a block device.
    #[serde(default)]
    pub virtiofs_tag: Option<String>,
}

/// dm-verity runtime-overlay target.  The runtime overlay is always
/// verity-sealed, so its fields stay required when it is present.
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
                hash_dev: Some("/dev/vdb".to_string()),
                roothash: Some("a".repeat(64)),
                virtiofs_tag: None,
            },
            runtime: Some(RuntimeOverlayConfig {
                data_dev: "/dev/vdc".to_string(),
                hash_dev: "/dev/vdd".to_string(),
                roothash: "b".repeat(64),
            }),
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
        assert_eq!(
            parsed.runtime.as_ref().map(|r| r.roothash.as_str()),
            Some("b".repeat(64).as_str())
        );
        assert_eq!(parsed.volumes.len(), 1);
        assert!(parsed.volumes[0].read_only);
    }

    #[test]
    fn activate_environment_roundtrips_unverified_and_rootfs_only() {
        // Unverified plain-block root, no runtime overlay: every optional
        // field absent, and the JSON carries none of them.
        let env = ActivateEnvironment {
            rootfs: RootfsConfig {
                data_dev: "/dev/vda".to_string(),
                hash_dev: None,
                roothash: None,
                virtiofs_tag: None,
            },
            runtime: None,
            volumes: Vec::new(),
            verb_grant_envelope: None,
        };
        let json = serde_json::to_string(&env).expect("serialize");
        let parsed: ActivateEnvironment = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.rootfs.roothash, None);
        assert_eq!(parsed.rootfs.hash_dev, None);
        assert!(parsed.runtime.is_none());

        // virtio-fs root.
        let env = ActivateEnvironment {
            rootfs: RootfsConfig {
                data_dev: String::new(),
                hash_dev: None,
                roothash: None,
                virtiofs_tag: Some("mvmroot".to_string()),
            },
            runtime: None,
            volumes: Vec::new(),
            verb_grant_envelope: None,
        };
        let json = serde_json::to_string(&env).expect("serialize");
        let parsed: ActivateEnvironment = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.rootfs.virtiofs_tag.as_deref(), Some("mvmroot"));
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
