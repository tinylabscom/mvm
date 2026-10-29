//! Untrusted inputs identifying a guest-runtime release. Verification is owned
//! by the build layer; deserialization never grants launch authority.

use crate::arch::GuestArch;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct RuntimeReleaseProof {
    pub archive: PathBuf,
    pub checksum: PathBuf,
    pub signature_bundle: PathBuf,
    pub archive_sha256: String,
    pub version: String,
    pub arch: GuestArch,
}

/// Untrusted record of the artifacts selected for a launch. A checkpoint must
/// authenticate this record and reverify its release and artifact bytes before
/// using it; reading a metadata file does not create runtime authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "runtime", rename_all = "snake_case", deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum RuntimeLaunchBinding {
    CliAssembly(CliRuntimeLaunchBinding),
    LegacyBundle {
        proof: super::vm_backend::LegacyBundleRuntimeProof,
        rootfs_path: PathBuf,
        initramfs_path: Option<PathBuf>,
    },
    LegacyPortable {
        proof: super::vm_backend::LegacyPortableRuntimeProof,
        rootfs_path: PathBuf,
        kernel_path: PathBuf,
        overlay_path: PathBuf,
        overlay_verity_path: PathBuf,
        initramfs_path: PathBuf,
        overlay_roothash: String,
        version: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct CliRuntimeLaunchBinding {
    pub provenance: RuntimeBindingProvenance,
    pub overlay_path: PathBuf,
    pub overlay_verity_path: PathBuf,
    pub initramfs_path: PathBuf,
    pub overlay_roothash: String,
}

/// Deserialized provenance remains a request for the corresponding verifier,
/// never a verification result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum RuntimeBindingProvenance {
    Release {
        proof: RuntimeReleaseProof,
    },
    Source {
        version: String,
        arch: GuestArch,
        archive_sha256: String,
    },
}

impl RuntimeLaunchBinding {
    pub fn apply_to_config(&self, config: &mut super::vm_backend::VmStartConfig) {
        match self {
            Self::CliAssembly(binding) => {
                config.legacy_bundle_runtime = None;
                binding.apply_to_config(config);
            }
            Self::LegacyPortable {
                proof,
                rootfs_path,
                kernel_path,
                overlay_path,
                overlay_verity_path,
                initramfs_path,
                overlay_roothash,
                version,
            } => {
                config.rootfs_path = rootfs_path.display().to_string();
                config.kernel_path = Some(kernel_path.display().to_string());
                config.initrd_path = Some(initramfs_path.display().to_string());
                config.runtime_overlay_path = Some(overlay_path.display().to_string());
                config.runtime_overlay_verity_path =
                    Some(overlay_verity_path.display().to_string());
                config.runtime_overlay_roothash = Some(overlay_roothash.clone());
                config.runtime_overlay_version = Some(version.clone());
                config.legacy_portable_runtime = Some(proof.clone());
                config.legacy_bundle_runtime = None;
                config.runtime_release_proof = None;
                config.source_runtime_archive_sha256 = None;
                config.unsigned_runtime_development = false;
                config.bundle_boot_assets = None;
            }
            Self::LegacyBundle {
                proof,
                rootfs_path,
                initramfs_path,
            } => {
                config.rootfs_path = rootfs_path.display().to_string();
                config.initrd_path = initramfs_path
                    .as_ref()
                    .map(|path| path.display().to_string());
                config.legacy_bundle_runtime = Some(proof.clone());
                config.legacy_portable_runtime = None;
                config.bundle_boot_assets = None;
                config.runtime_overlay_version = None;
                config.runtime_overlay_path = None;
                config.runtime_overlay_verity_path = None;
                config.runtime_overlay_roothash = None;
                config.runtime_release_proof = None;
                config.unsigned_runtime_development = false;
                config.source_runtime_archive_sha256 = None;
            }
        }
    }
}

impl CliRuntimeLaunchBinding {
    /// Copy untrusted selection data, not authority. Callers must authenticate
    /// the enclosing record and verify these artifacts before executing them.
    pub fn apply_to_config(&self, config: &mut super::vm_backend::VmStartConfig) {
        config.legacy_bundle_runtime = None;
        config.legacy_portable_runtime = None;
        config.bundle_boot_assets = None;
        config.runtime_overlay_version = Some(self.version().to_owned());
        config.runtime_overlay_path = Some(self.overlay_path.display().to_string());
        config.runtime_overlay_verity_path = Some(self.overlay_verity_path.display().to_string());
        config.initrd_path = Some(self.initramfs_path.display().to_string());
        config.runtime_overlay_roothash = Some(self.overlay_roothash.clone());
        config.runtime_release_proof = self.release_proof().cloned();
        config.unsigned_runtime_development = self.release_proof().is_none();
        config.source_runtime_archive_sha256 = match &self.provenance {
            RuntimeBindingProvenance::Release { .. } => None,
            RuntimeBindingProvenance::Source { archive_sha256, .. } => Some(archive_sha256.clone()),
        };
    }

    pub fn release_proof(&self) -> Option<&RuntimeReleaseProof> {
        match &self.provenance {
            RuntimeBindingProvenance::Release { proof } => Some(proof),
            RuntimeBindingProvenance::Source { .. } => None,
        }
    }

    pub fn version(&self) -> &str {
        match &self.provenance {
            RuntimeBindingProvenance::Release { proof } => &proof.version,
            RuntimeBindingProvenance::Source { version, .. } => version,
        }
    }

    pub fn arch(&self) -> GuestArch {
        match &self.provenance {
            RuntimeBindingProvenance::Release { proof } => proof.arch,
            RuntimeBindingProvenance::Source { arch, .. } => *arch,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proof_roundtrips_but_rejects_a_claimed_verification_flag() {
        let proof = RuntimeReleaseProof {
            archive: "/release/archive".into(),
            checksum: "/release/checksum".into(),
            signature_bundle: "/release/signature".into(),
            archive_sha256: "a".repeat(64),
            version: "1.2.3".into(),
            arch: GuestArch::X86_64,
        };
        let mut value = serde_json::to_value(&proof).unwrap();
        let decoded: RuntimeReleaseProof = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(decoded.archive_sha256, proof.archive_sha256);
        value["verified"] = true.into();
        assert!(serde_json::from_value::<RuntimeReleaseProof>(value).is_err());
        let binding = CliRuntimeLaunchBinding {
            provenance: RuntimeBindingProvenance::Release { proof },
            overlay_path: "/private/runtime-one/overlay.ext4".into(),
            overlay_verity_path: "/private/runtime-one/overlay.verity".into(),
            initramfs_path: "/private/runtime-one/initramfs.cpio.gz".into(),
            overlay_roothash: "b".repeat(64),
        };
        let wrapped = RuntimeLaunchBinding::CliAssembly(binding.clone());
        let value = serde_json::to_value(&wrapped).unwrap();
        assert_eq!(
            serde_json::from_value::<RuntimeLaunchBinding>(value).unwrap(),
            wrapped
        );
        let mut unknown = serde_json::to_value(&wrapped).unwrap();
        unknown["verified"] = true.into();
        assert!(serde_json::from_value::<RuntimeLaunchBinding>(unknown).is_err());
        let mut untagged = serde_json::to_value(&wrapped).unwrap();
        untagged.as_object_mut().unwrap().remove("runtime");
        assert!(serde_json::from_value::<RuntimeLaunchBinding>(untagged).is_err());
        let source = CliRuntimeLaunchBinding {
            provenance: RuntimeBindingProvenance::Source {
                version: "1.2.3".into(),
                arch: GuestArch::X86_64,
                archive_sha256: "c".repeat(64),
            },
            ..binding
        };
        assert!(source.release_proof().is_none());
        assert_eq!(source.version(), "1.2.3");
        assert_eq!(source.arch(), GuestArch::X86_64);
        let source = RuntimeLaunchBinding::CliAssembly(source);
        let value = serde_json::to_value(&source).unwrap();
        assert_eq!(
            serde_json::from_value::<RuntimeLaunchBinding>(value.clone()).unwrap(),
            source
        );
        let mut missing_digest = value;
        missing_digest["provenance"]
            .as_object_mut()
            .unwrap()
            .remove("archive_sha256");
        assert!(serde_json::from_value::<RuntimeLaunchBinding>(missing_digest).is_err());
        let mut config = super::super::vm_backend::VmStartConfig::default();
        source.apply_to_config(&mut config);
        assert_eq!(config.source_runtime_archive_sha256, Some("c".repeat(64)));
        wrapped.apply_to_config(&mut config);
        assert_eq!(config.source_runtime_archive_sha256, None);
    }
}
