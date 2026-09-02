//! Activation protocol for PID-1 initramfs boot.
//!
//! The host sends `ActivateEnvironment` over vsock after the kernel has
//! booted the universal initramfs.  The message carries the dm-verity
//! rootfs/runtime-overlay parameters and any virtio-fs custom volumes the
//! workload admitted.  The agent validates the message, mounts the
//! environment, drops privilege, and transitions from the `Awaiting`
//! boot state to `Activated`.

use mvm_contract::assurance::{AssuranceId, Sha256Digest};
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
    /// Exact optional extension identities admitted by the signed plan.
    #[serde(default)]
    pub extensions: Vec<ExtensionConfig>,
    /// Optional verb-grant envelope to pin before serving operational
    /// RPCs.  When present, the activation message itself must be signed
    /// by the host-signer trust anchor.
    #[serde(default)]
    pub verb_grant_envelope: Option<mvm_core::protocol::vm_backend::VerbGrantEnvelope>,
}

/// One read-only extension artifact mounted for identity-only dispatch.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ExtensionConfig {
    pub binding: mvm_contract::protocol::extension_pack::ExtensionPlanBinding,
    pub plan_id: AssuranceId,
    pub mountpoint: String,
    pub device: String,
}

/// Identity-bound input for one optional extension invocation. There is no
/// program, argv, environment, mount, destination, or host path on this wire.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ExtensionDispatch {
    pub extension_id: mvm_contract::protocol::extension_pack::ExtensionId,
    pub pack_digest: [u8; 32],
    pub contract_digest: [u8; 32],
    pub request_id: AssuranceId,
    pub session_id: AssuranceId,
    pub campaign_id: AssuranceId,
    pub trial_id: AssuranceId,
    pub plan_id: AssuranceId,
    pub idempotency_key: AssuranceId,
    pub grant_digest: Sha256Digest,
    pub nonce: AssuranceId,
    pub input: Vec<u8>,
}

impl ExtensionDispatch {
    /// Exact identity a controller must echo to cancel this invocation.
    #[must_use]
    pub fn cancellation(&self) -> ExtensionCancellation {
        ExtensionCancellation {
            extension_id: self.extension_id.clone(),
            pack_digest: self.pack_digest,
            contract_digest: self.contract_digest,
            request_id: self.request_id.clone(),
            session_id: self.session_id.clone(),
            campaign_id: self.campaign_id.clone(),
            trial_id: self.trial_id.clone(),
            plan_id: self.plan_id.clone(),
            idempotency_key: self.idempotency_key.clone(),
            grant_digest: self.grant_digest.clone(),
            nonce: self.nonce.clone(),
        }
    }
}

/// Identity-only cancellation for one active optional-extension invocation.
/// It deliberately carries no process selector, signal, path, or cleanup
/// scope; the guest resolves the already-admitted process from this identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ExtensionCancellation {
    pub extension_id: mvm_contract::protocol::extension_pack::ExtensionId,
    pub pack_digest: [u8; 32],
    pub contract_digest: [u8; 32],
    pub request_id: AssuranceId,
    pub session_id: AssuranceId,
    pub campaign_id: AssuranceId,
    pub trial_id: AssuranceId,
    pub plan_id: AssuranceId,
    pub idempotency_key: AssuranceId,
    pub grant_digest: Sha256Digest,
    pub nonce: AssuranceId,
}

/// Root device the guest mounts as `/`.  Three mount shapes, selected by
/// which optional fields are set, plus one mount-free shape:
///
/// - **dm-verity block** (`roothash` + `hash_dev`): create the `root`
///   dm-verity target and mount it read-only.
/// - **plain block** (neither): mount `data_dev` read-only without
///   verification (unverified dev-tier boot).
/// - **virtio-fs root** (`virtiofs_tag`): mount the virtio-fs tag read-only
///   as the root — the block-less dev-tier boot.
/// - **in place** (`in_place`): the runtime already owns `/` — a
///   shared-kernel container whose root is the image itself. Nothing is
///   mounted and no pivot happens; activation is the privilege drop and
///   the gate flip only.
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
    /// The root is already in place (shared-kernel container tier): skip
    /// the rootfs mount and the pivot entirely. Mutually exclusive with
    /// every other field — a host that sets this alongside a device, hash,
    /// or tag gets a validation error from the agent, not a silent choice.
    #[serde(default)]
    pub in_place: bool,
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

/// Device kind for a boot-time user volume.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum VolumeConfigKind {
    /// Host directory exposed through a named virtio-fs tag.
    #[default]
    VirtioFs,
    /// Persistent ext4 image exposed as a virtio-blk device.
    Block,
}

/// User volume to mount after rootfs activation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct VolumeConfig {
    /// Stable attachment identifier. For virtio-fs this is the advertised tag;
    /// for block devices it preserves the host's `uvol{index}` identity.
    pub tag: String,
    /// Absolute guest mountpoint.  Must pass `MountPathPolicy`.
    pub mountpoint: String,
    /// Mount read-only when `true`.
    #[serde(default)]
    pub read_only: bool,
    /// Attachment kind. Missing on older messages means virtio-fs.
    #[serde(default)]
    pub kind: VolumeConfigKind,
    /// Guest block device for [`VolumeConfigKind::Block`]. Must be absent for
    /// virtio-fs and is validated against the bounded `/dev/vd[a-z]` range.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device: Option<String>,
    /// ext4 volume label on the attached image, when the host wrote one.
    ///
    /// Preferred over [`Self::device`] for a block volume: a device node names
    /// whichever image landed in that slot, so a slot-order change mounts the
    /// wrong one and succeeds. Matching the label proves the guest mounted the
    /// image the host meant. `None` falls back to the node.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
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
                in_place: false,
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
                kind: VolumeConfigKind::VirtioFs,
                device: None,
                label: None,
            }],
            extensions: Vec::new(),
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
                in_place: false,
            },
            runtime: None,
            volumes: Vec::new(),
            extensions: Vec::new(),
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
                in_place: false,
            },
            runtime: None,
            volumes: Vec::new(),
            extensions: Vec::new(),
            verb_grant_envelope: None,
        };
        let json = serde_json::to_string(&env).expect("serialize");
        let parsed: ActivateEnvironment = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.rootfs.virtiofs_tag.as_deref(), Some("mvmroot"));
    }

    #[test]
    fn legacy_volume_config_defaults_to_virtiofs() {
        let volume: VolumeConfig =
            serde_json::from_str(r#"{"tag":"data","mountpoint":"/data","read_only":true}"#)
                .expect("deserialize legacy volume config");
        assert!(matches!(volume.kind, VolumeConfigKind::VirtioFs));
        assert_eq!(volume.device, None);
    }

    #[test]
    fn in_place_root_roundtrips_and_defaults_absent() {
        // In-place (container) root: only the flag is set.
        let env = ActivateEnvironment {
            rootfs: RootfsConfig {
                data_dev: String::new(),
                hash_dev: None,
                roothash: None,
                virtiofs_tag: None,
                in_place: true,
            },
            runtime: None,
            volumes: Vec::new(),
            extensions: Vec::new(),
            verb_grant_envelope: None,
        };
        let json = serde_json::to_string(&env).expect("serialize");
        let parsed: ActivateEnvironment = serde_json::from_str(&json).expect("deserialize");
        assert!(parsed.rootfs.in_place);

        // Older messages carry no `in_place` key at all; it defaults to the
        // mount-owning boot shapes.
        let legacy = r#"{"rootfs":{"data_dev":"/dev/vda"}}"#;
        let parsed: ActivateEnvironment = serde_json::from_str(legacy).expect("deserialize");
        assert!(!parsed.rootfs.in_place);
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
