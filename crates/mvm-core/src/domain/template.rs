use sha2::Digest;

use crate::arch::GuestArch;
use serde::{Deserialize, Serialize};

/// Current schema version for persisted state files.
pub const CURRENT_SCHEMA_VERSION: u32 = 1;

fn default_schema_version() -> u32 {
    CURRENT_SCHEMA_VERSION
}

/// Complete template configuration that can define multiple variants/roles.
/// Typically loaded from a TOML file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateConfig {
    /// Optional base name used when a variant omits `name`.
    #[serde(default)]
    pub template_id: String,
    pub flake_ref: String,
    /// Default profile if a variant omits it.
    #[serde(default = "default_profile")]
    pub profile: String,
    pub variants: Vec<TemplateVariant>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateVariant {
    /// Template name for this variant; if empty, falls back to the template id.
    #[serde(default)]
    pub name: String,
    #[serde(default = "default_profile")]
    pub profile: String,
    pub vcpus: u8,
    pub mem_mib: u32,
    #[serde(default)]
    pub data_disk_mib: u32,
}

fn default_profile() -> String {
    "minimal".to_string()
}

/// Global template definition (tenant-agnostic base image).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateSpec {
    /// Schema version for forward-compatible migrations. Current: 1.
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    pub template_id: String,
    pub flake_ref: String,
    pub profile: String,
    pub vcpus: u8,
    pub mem_mib: u32,
    /// Initial host commitment in MiB when the template opts into
    /// virtio-balloon. `None` keeps the legacy "commit `mem_mib` at
    /// boot" behaviour; `Some(n)` sources `VmStartConfig::mem_initial_mib`
    /// from the template when `mvmctl up` doesn't override it on the
    /// CLI or via `--config`. Backward-compat: missing field
    /// deserialises to `None` for templates that predate the schema.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mem_initial_mib: Option<u32>,
    pub data_disk_mib: u32,
    pub created_at: String,
    pub updated_at: String,
    /// Default network policy applied when `mvmctl up` / `mvmctl exec`
    /// don't override it on the CLI. Lets templates ship with their
    /// intended posture baked in
    /// (e.g. `claude-code-vm` defaults to the `agent` preset) so
    /// operators don't have to remember `--network-preset agent` per
    /// invocation. Backward-compat: existing `template.json` files
    /// that predate this field deserialize as `None` (open egress,
    /// matching prior behaviour).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_network_policy: Option<crate::policy::network_policy::NetworkPolicy>,
}

/// Path helpers
pub fn templates_base_dir() -> String {
    format!("{}/templates", crate::config::mvm_home())
}

pub fn template_dir(template_id: &str) -> String {
    format!("{}/{}", templates_base_dir(), template_id)
}

pub fn template_spec_path(template_id: &str) -> String {
    format!("{}/template.json", template_dir(template_id))
}

/// Artifacts base dir for a template.
pub fn template_artifacts_dir(template_id: &str) -> String {
    format!("{}/artifacts", template_dir(template_id))
}

/// Specific revision dir for a template.
pub fn template_revision_dir(template_id: &str, revision: &str) -> String {
    format!("{}/{}", template_artifacts_dir(template_id), revision)
}

/// Symlink to current revision.
pub fn template_current_symlink(template_id: &str) -> String {
    format!("{}/current", template_dir(template_id))
}

/// Snapshot directory within a template revision.
pub fn template_snapshot_dir(template_id: &str, revision: &str) -> String {
    format!("{}/snapshot", template_revision_dir(template_id, revision))
}

/// The immutable inputs that make a snapshot restore-compatible.
///
/// Recovery must not infer compatibility from the VM name or from whichever
/// backend happens to be selected at restore time. Every field is part of the
/// snapshot identity: a changed backend, tool version, architecture, resource
/// shape, image, or policy requires a cold boot or a newly captured snapshot.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SnapshotCompatibility {
    /// Backend that produced the snapshot (for example, `firecracker`).
    pub backend: String,
    /// Backend/runtime version that produced the snapshot.
    pub backend_version: String,
    /// Guest architecture captured by the snapshot.
    pub architecture: GuestArch,
    /// vCPU count captured by the snapshot.
    pub vcpus: u8,
    /// Guest memory captured by the snapshot.
    pub mem_mib: u32,
    /// Content digest of the boot image.
    pub image_sha256: String,
    /// Digest of the effective policy bound to the boot.
    pub policy_digest: String,
}

/// A snapshot cannot be restored under a different immutable input.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SnapshotCompatibilityError {
    #[error(
        "snapshot compatibility mismatch for {field}: snapshot={snapshot:?}, current={current:?}"
    )]
    Mismatch {
        field: &'static str,
        snapshot: String,
        current: String,
    },
    #[error("snapshot compatibility metadata is missing; capture a new snapshot before restoring")]
    Missing,
}

impl SnapshotCompatibility {
    /// Validate that this snapshot was produced for the requested restore
    /// contract. The first mismatch is returned with both values so the CLI
    /// can provide an actionable refusal.
    pub fn check_against(&self, current: &Self) -> Result<(), SnapshotCompatibilityError> {
        let checks = [
            ("backend", self.backend.clone(), current.backend.clone()),
            (
                "backend_version",
                self.backend_version.clone(),
                current.backend_version.clone(),
            ),
            (
                "architecture",
                self.architecture.to_string(),
                current.architecture.to_string(),
            ),
            ("vcpus", self.vcpus.to_string(), current.vcpus.to_string()),
            (
                "mem_mib",
                self.mem_mib.to_string(),
                current.mem_mib.to_string(),
            ),
            (
                "image_sha256",
                self.image_sha256.clone(),
                current.image_sha256.clone(),
            ),
            (
                "policy_digest",
                self.policy_digest.clone(),
                current.policy_digest.clone(),
            ),
        ];
        if let Some((field, snapshot, current)) = checks
            .into_iter()
            .find(|(_, snapshot, current)| snapshot != current)
        {
            return Err(SnapshotCompatibilityError::Mismatch {
                field,
                snapshot,
                current,
            });
        }
        Ok(())
    }
}

/// Metadata about a template's pre-built snapshot.
///
/// Created by `mvmctl build --snapshot` after booting the VM and
/// waiting for the service to become healthy. Used by `mvmctl up
/// --manifest` to restore the VM instantly instead of cold-booting.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SnapshotInfo {
    pub created_at: String,
    pub vmstate_size_bytes: u64,
    pub mem_size_bytes: u64,
    /// Boot args used when the snapshot was created (must match on restore).
    pub boot_args: String,
    /// vCPU count at snapshot time (must match on restore).
    pub vcpus: u8,
    /// Memory MiB at snapshot time (must match on restore).
    pub mem_mib: u32,
    /// Immutable compatibility contract for the snapshot. `None` is retained
    /// only for reading legacy metadata; restore code must reject it.
    #[serde(default)]
    pub compatibility: Option<SnapshotCompatibility>,
}

impl SnapshotInfo {
    /// Check the snapshot's compatibility contract, refusing legacy metadata
    /// that predates the contract instead of guessing whether it is safe.
    pub fn check_compatibility(
        &self,
        current: &SnapshotCompatibility,
    ) -> Result<(), SnapshotCompatibilityError> {
        self.compatibility
            .as_ref()
            .ok_or(SnapshotCompatibilityError::Missing)?
            .check_against(current)
    }
}

/// Describes what kind of pre-built artifact a template provides.
///
/// All backends support `Image` (cold boot from immutable artifacts). A
/// `Snapshot` is valid only when its compatibility contract matches the
/// selected backend's recovery capability.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TemplateKind {
    /// Pre-built rootfs image only — cold-boot on every start.
    /// Supported by all backends.
    Image,
    /// Pre-built rootfs + Firecracker memory snapshot — warm-start.
    /// Only supported by backends with snapshot capability.
    Snapshot(SnapshotInfo),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateRevision {
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    pub revision_hash: String,
    pub flake_ref: String,
    pub flake_lock_hash: String,
    pub artifact_paths: crate::pool::ArtifactPaths,
    pub built_at: String,
    pub profile: String,
    pub vcpus: u8,
    pub mem_mib: u32,
    pub data_disk_mib: u32,
    #[serde(default)]
    pub snapshot: Option<SnapshotInfo>,
    /// Build mode the revision was produced with. `"dev"` =
    /// `mvm_build::pipeline::BuildMode::Dev` (dev guest agent +
    /// accessible image); `"prod"` (or absent) = `BuildMode::Prod`
    /// (sealed image, no `do_exec`). Recorded on the revision so a
    /// subsequent rebuild round-trips the same posture without the
    /// user having to re-pass `--dev`/`--prod`.
    ///
    /// Optional + `default` so older on-disk revisions that predate
    /// the field parse without a migration. Missing on read is treated as
    /// `BuildMode::Prod` at the consumer site (the same default
    /// `BuildModeFlags::resolve()` picks).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build_mode: Option<String>,
}

impl TemplateRevision {
    /// Composite cache key from the two dimensions that define a unique build
    /// output: flake.lock content and Nix profile.
    ///
    /// The historical `role` component was dropped: role is a fleet concept
    /// (mvmd's territory) and role-shaped flake variants live behind `profile`
    /// (`packages.<system>.gateway` vs `packages.<system>.worker`) or
    /// `passthru` inside the flake itself. The field it was read from is gone
    /// too; a revision JSON that still carries `role` simply ignores it.
    pub fn cache_key(&self) -> String {
        let mut hasher = sha2::Sha256::new();
        hasher.update(self.flake_lock_hash.as_bytes());
        hasher.update(b":");
        hasher.update(self.profile.as_bytes());
        hex::encode(hasher.finalize())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pool::ArtifactPaths;

    fn make_revision(flake_lock_hash: &str, profile: &str) -> TemplateRevision {
        TemplateRevision {
            schema_version: CURRENT_SCHEMA_VERSION,
            revision_hash: "abc123".to_string(),
            flake_ref: ".".to_string(),
            flake_lock_hash: flake_lock_hash.to_string(),
            artifact_paths: ArtifactPaths {
                vmlinux: "vmlinux".to_string(),
                rootfs: "rootfs.ext4".to_string(),
                fc_base_config: "fc-base.json".to_string(),
                initrd: None,
                sizes: None,
            },
            built_at: "2025-01-01T00:00:00Z".to_string(),
            profile: profile.to_string(),
            vcpus: 2,
            mem_mib: 1024,
            data_disk_mib: 0,
            snapshot: None,
            build_mode: None,
        }
    }

    #[test]
    fn same_inputs_same_cache_key() {
        let a = make_revision("lock1", "minimal");
        let b = make_revision("lock1", "minimal");
        assert_eq!(a.cache_key(), b.cache_key());
    }

    #[test]
    fn different_profile_different_cache_key() {
        let a = make_revision("lock1", "minimal");
        let b = make_revision("lock1", "full");
        assert_ne!(a.cache_key(), b.cache_key());
    }

    #[test]
    fn different_flake_different_cache_key() {
        let a = make_revision("lock1", "minimal");
        let b = make_revision("lock2", "minimal");
        assert_ne!(a.cache_key(), b.cache_key());
    }

    #[test]
    fn cache_key_depends_on_flake_lock_not_revision_hash() {
        let mut a = make_revision("same-lock", "minimal");
        a.revision_hash = "rev-aaa".to_string();
        let mut b = make_revision("same-lock", "minimal");
        b.revision_hash = "rev-zzz".to_string();
        // Different revision hashes but same flake_lock/profile → same cache key
        assert_eq!(a.cache_key(), b.cache_key());
    }

    #[test]
    fn build_mode_does_not_affect_cache_key() {
        // build_mode is a posture flag (dev vs prod). It's recorded on
        // the revision so a rebuild round-trips it, but the cache key
        // (flake_lock + profile) shouldn't care. Two revisions with
        // the same lockfile + profile but different build_mode strings
        // still hit the same cache slot.
        let mut a = make_revision("lock1", "minimal");
        a.build_mode = Some("dev".to_string());
        let mut b = make_revision("lock1", "minimal");
        b.build_mode = Some("prod".to_string());
        assert_eq!(a.cache_key(), b.cache_key());
    }

    #[test]
    fn build_mode_roundtrips_through_serde() {
        let mut rev = make_revision("lock1", "minimal");
        rev.build_mode = Some("dev".to_string());
        let json = serde_json::to_string(&rev).unwrap();
        assert!(json.contains("\"build_mode\":\"dev\""), "got: {json}");
        let back: TemplateRevision = serde_json::from_str(&json).unwrap();
        assert_eq!(back.build_mode.as_deref(), Some("dev"));
    }

    #[test]
    fn missing_build_mode_deserializes_as_none() {
        // Older on-disk revision.json files don't carry the
        // `build_mode` field. Parsing must succeed and yield `None`
        // (consumers treat that as `BuildMode::Prod`, matching the
        // default `BuildModeFlags::resolve()`).
        let mut rev = make_revision("lock1", "minimal");
        rev.build_mode = None;
        let json = serde_json::to_string(&rev).unwrap();
        assert!(
            !json.contains("build_mode"),
            "absent field should not serialize: {json}"
        );
        let back: TemplateRevision = serde_json::from_str(&json).unwrap();
        assert!(back.build_mode.is_none());
    }

    fn snapshot_contract() -> SnapshotCompatibility {
        SnapshotCompatibility {
            backend: "libkrun".into(),
            backend_version: "1.2.3".into(),
            architecture: GuestArch::Aarch64,
            vcpus: 2,
            mem_mib: 1024,
            image_sha256: "a".repeat(64),
            policy_digest: "b".repeat(64),
        }
    }

    #[test]
    fn snapshot_compatibility_checks_every_restore_input() {
        let expected = snapshot_contract();
        let mut actual = expected.clone();
        actual.policy_digest = "c".repeat(64);
        let err = expected.check_against(&actual).unwrap_err();
        assert!(matches!(
            err,
            SnapshotCompatibilityError::Mismatch {
                field: "policy_digest",
                ..
            }
        ));

        type CompatibilityMutator = fn(&mut SnapshotCompatibility);
        let cases: [(&str, CompatibilityMutator); 7] = [
            ("backend", |c: &mut SnapshotCompatibility| {
                c.backend = "qemu".into()
            }),
            ("backend_version", |c: &mut SnapshotCompatibility| {
                c.backend_version = "9".into()
            }),
            ("architecture", |c: &mut SnapshotCompatibility| {
                c.architecture = GuestArch::X86_64
            }),
            ("vcpus", |c: &mut SnapshotCompatibility| c.vcpus = 4),
            ("mem_mib", |c: &mut SnapshotCompatibility| c.mem_mib = 2048),
            ("image_sha256", |c: &mut SnapshotCompatibility| {
                c.image_sha256 = "d".repeat(64)
            }),
            ("policy_digest", |c: &mut SnapshotCompatibility| {
                c.policy_digest = "e".repeat(64)
            }),
        ];
        for (field, mutate) in cases {
            let mut current = expected.clone();
            mutate(&mut current);
            let err = expected.check_against(&current).unwrap_err();
            assert!(
                matches!(err, SnapshotCompatibilityError::Mismatch { field: got, .. } if got == field),
                "expected {field}, got {err:?}"
            );
        }
    }

    #[test]
    fn legacy_snapshot_without_compatibility_is_rejected() {
        let info = SnapshotInfo {
            created_at: "2025-03-01T00:00:00Z".into(),
            vmstate_size_bytes: 1,
            mem_size_bytes: 1,
            boot_args: String::new(),
            vcpus: 1,
            mem_mib: 64,
            compatibility: None,
        };
        assert_eq!(
            info.check_compatibility(&snapshot_contract()),
            Err(SnapshotCompatibilityError::Missing)
        );
    }

    #[test]
    fn snapshot_info_serde_roundtrip() {
        let info = SnapshotInfo {
            created_at: "2025-03-01T00:00:00Z".to_string(),
            vmstate_size_bytes: 1024,
            mem_size_bytes: 1048576,
            boot_args: "root=/dev/vda rw init=/init console=ttyS0".to_string(),
            vcpus: 2,
            mem_mib: 1024,
            compatibility: None,
        };
        let json = serde_json::to_string(&info).unwrap();
        let back: SnapshotInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(back.vcpus, 2);
        assert_eq!(back.mem_mib, 1024);
        assert_eq!(back.vmstate_size_bytes, 1024);
    }

    #[test]
    fn revision_without_snapshot_deserializes() {
        let json = r#"{
            "revision_hash": "abc",
            "flake_ref": ".",
            "flake_lock_hash": "lock1",
            "artifact_paths": {
                "vmlinux": "vmlinux",
                "rootfs": "rootfs.ext4",
                "fc_base_config": "fc-base.json"
            },
            "built_at": "2025-01-01T00:00:00Z",
            "profile": "minimal",
            "role": "worker",
            "vcpus": 2,
            "mem_mib": 1024,
            "data_disk_mib": 0
        }"#;
        let rev: TemplateRevision = serde_json::from_str(json).unwrap();
        assert!(rev.snapshot.is_none());
    }

    #[test]
    fn revision_with_snapshot_deserializes() {
        let rev = make_revision("lock1", "minimal");
        let mut rev = rev;
        rev.snapshot = Some(SnapshotInfo {
            created_at: "2025-03-01T00:00:00Z".to_string(),
            vmstate_size_bytes: 512,
            mem_size_bytes: 2048,
            boot_args: "console=ttyS0".to_string(),
            vcpus: 2,
            mem_mib: 1024,
            compatibility: None,
        });
        let json = serde_json::to_string(&rev).unwrap();
        let back: TemplateRevision = serde_json::from_str(&json).unwrap();
        assert!(back.snapshot.is_some());
        assert_eq!(back.snapshot.unwrap().mem_size_bytes, 2048);
    }

    #[test]
    fn template_snapshot_dir_format() {
        let dir = template_snapshot_dir("my-tmpl", "abc123");
        assert!(dir.ends_with("/templates/my-tmpl/artifacts/abc123/snapshot"));
    }

    #[test]
    fn template_kind_image_serde_roundtrip() {
        let kind = TemplateKind::Image;
        let json = serde_json::to_string(&kind).unwrap();
        let parsed: TemplateKind = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, TemplateKind::Image);
    }

    #[test]
    fn template_kind_snapshot_serde_roundtrip() {
        let snap = SnapshotInfo {
            created_at: "2025-03-01T00:00:00Z".to_string(),
            vmstate_size_bytes: 1024,
            mem_size_bytes: 2048,
            boot_args: "console=ttyS0".to_string(),
            vcpus: 2,
            mem_mib: 512,
            compatibility: None,
        };
        let kind = TemplateKind::Snapshot(snap.clone());
        let json = serde_json::to_string(&kind).unwrap();
        let parsed: TemplateKind = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, TemplateKind::Snapshot(snap));
    }

    #[test]
    fn template_spec_default_network_policy_omitted_for_back_compat() {
        // Older template.json files don't have the field; they
        // must still parse (Option<…> defaults to None) and round-trip
        // without spuriously emitting `"default_network_policy":null`.
        let json_pre_plan_32 = r#"{
            "schema_version": 1,
            "template_id": "legacy",
            "flake_ref": ".",
            "profile": "minimal",
            "role": "worker",
            "vcpus": 2,
            "mem_mib": 1024,
            "data_disk_mib": 0,
            "created_at": "2025-01-01T00:00:00Z",
            "updated_at": "2025-01-01T00:00:00Z"
        }"#;
        let parsed: TemplateSpec = serde_json::from_str(json_pre_plan_32).unwrap();
        assert!(parsed.default_network_policy.is_none());
        let reserialized = serde_json::to_string(&parsed).unwrap();
        assert!(
            !reserialized.contains("default_network_policy"),
            "field should be skipped when None to keep round-trip stable: {reserialized}"
        );
    }

    #[test]
    fn template_spec_with_network_policy_roundtrips() {
        use crate::policy::network_policy::{NetworkPolicy, NetworkPreset};
        let spec = TemplateSpec {
            schema_version: CURRENT_SCHEMA_VERSION,
            template_id: "claude-code-vm".to_string(),
            flake_ref: ".".to_string(),
            profile: "minimal".to_string(),
            vcpus: 2,
            mem_mib: 1024,
            mem_initial_mib: None,
            data_disk_mib: 0,
            created_at: "2025-01-01T00:00:00Z".to_string(),
            updated_at: "2025-01-01T00:00:00Z".to_string(),
            default_network_policy: Some(NetworkPolicy::preset(NetworkPreset::Agent)),
        };
        let json = serde_json::to_string(&spec).unwrap();
        let parsed: TemplateSpec = serde_json::from_str(&json).unwrap();
        assert_eq!(
            parsed.default_network_policy,
            Some(NetworkPolicy::preset(NetworkPreset::Agent))
        );
    }
}
