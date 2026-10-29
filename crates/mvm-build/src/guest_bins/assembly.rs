//! Signed declarations of deterministic boot artifacts built from archive members.

use super::{GuestBinsArtifact, GuestBinsError};
use mvm_core::arch::GuestArch;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Identifies the in-process ext4, verity, cpio and gzip assembly recipe.
pub const RUNTIME_ASSEMBLY_FORMAT: u32 = 1;

/// A producer must be built from the protocol source it is declaring. Refuse a
/// different checkout rather than labeling its binaries with host constants.
#[tracing::instrument(skip_all)]
pub(crate) fn verify_protocol_source(workspace: &std::path::Path) -> Result<(), GuestBinsError> {
    let source = workspace.join("crates/mvm-agentd/src/vsock/mod.rs");
    let expected = mvm_agentd::vsock::COMPILED_PROTOCOL_SOURCE;
    if std::fs::read(&source)?.as_slice() != expected {
        return Err(GuestBinsError::Assembly(
            "guest protocol source differs from the producer; rebuild mvmctl from the selected checkout"
                .into(),
        ));
    }
    Ok(())
}

/// These claims become authenticated only when the containing archive is signed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeAssembly {
    pub assembly_format: u32,
    pub arch: GuestArch,
    pub protocol_version: u32,
    pub min_supported_protocol_version: u32,
    pub overlay_sha256: String,
    pub overlay_verity_sha256: String,
    pub overlay_roothash: String,
    pub initramfs_sha256: String,
}

impl RuntimeAssembly {
    pub fn validate(&self, arch: GuestArch) -> Result<(), GuestBinsError> {
        if self.assembly_format != RUNTIME_ASSEMBLY_FORMAT
            || self.arch != arch
            || self.protocol_version == 0
            || self.min_supported_protocol_version == 0
            || self.min_supported_protocol_version > self.protocol_version
            || [
                &self.overlay_sha256,
                &self.overlay_verity_sha256,
                &self.overlay_roothash,
                &self.initramfs_sha256,
            ]
            .into_iter()
            .any(|digest| !crate::guest_runtime::is_archive_digest(digest))
        {
            return Err(GuestBinsError::Assembly(format!(
                "invalid runtime declaration for {arch}"
            )));
        }
        Ok(())
    }
}

impl GuestBinsArtifact {
    /// Compute declarations before signing, using only this artifact's captured bytes.
    /// No installed cache, source fingerprint or previously assembled output is trusted.
    pub fn declare_runtime_assemblies(&mut self) -> Result<(), GuestBinsError> {
        let staging = tempfile::tempdir()?;
        let root = staging.path().join("members");
        std::fs::create_dir(&root)?;
        let mut arches = std::collections::BTreeSet::new();
        for (name, member) in &self.members {
            let path = root.join(name);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&path, &member.bytes)?;
            if let super::GuestBinsMember::InitramfsAgent { arch } =
                super::GuestBinsMember::parse(name)?
            {
                arches.insert(arch);
            }
        }
        let runtime = crate::guest_runtime::GuestRuntime {
            root,
            // Used only as a cache label in this fresh private directory.
            digest: super::sha256_hex(b"private runtime assembly"),
            manifest: self.manifest(),
            release_proof: None,
        };
        let cache = staging.path().join("cache");
        let mut declarations = BTreeMap::new();
        for arch in arches {
            let declaration = derive_runtime_assembly(&runtime, arch, &cache)?;
            declarations.insert(arch, declaration);
        }
        self.assemblies = declarations;
        Ok(())
    }
}

/// Derive from captured archive members in a fresh private cache. This is a byte
/// assembly operation, not a guest compiler invocation or release authentication.
#[tracing::instrument(skip_all)]
pub(crate) fn derive_runtime_assembly(
    runtime: &crate::guest_runtime::GuestRuntime,
    arch: GuestArch,
    private_cache: &std::path::Path,
) -> Result<RuntimeAssembly, GuestBinsError> {
    let overlay = crate::runtime_overlay::build_runtime_overlay_from_guest_runtime(
        private_cache,
        &runtime.manifest.version,
        arch,
        runtime,
    )
    .map_err(|error| GuestBinsError::Assembly(error.to_string()))?;
    let initramfs = crate::initramfs::build_initramfs_from_guest_runtime(
        private_cache,
        &runtime.manifest.version,
        arch,
        runtime,
    )
    .map_err(|error| GuestBinsError::Assembly(error.to_string()))?;
    let declaration = RuntimeAssembly {
        assembly_format: RUNTIME_ASSEMBLY_FORMAT,
        arch,
        protocol_version: mvm_agentd::vsock::PROTOCOL_VERSION,
        min_supported_protocol_version: mvm_agentd::vsock::MIN_SUPPORTED_PROTOCOL_VERSION,
        overlay_sha256: super::sha256_hex(&std::fs::read(overlay.overlay_ext4)?),
        overlay_verity_sha256: super::sha256_hex(&std::fs::read(overlay.sidecar)?),
        overlay_roothash: overlay.roothash,
        initramfs_sha256: super::sha256_hex(&std::fs::read(initramfs.image_path)?),
    };
    declaration.validate(arch)?;
    Ok(declaration)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guest_bins::{GuestBinsFingerprints, MemberBytes};
    use crate::guest_libc::GuestLibc;
    use mvm_core::image_set::{GitCommit, WorktreeState};

    fn artifact() -> GuestBinsArtifact {
        let mut artifact = GuestBinsArtifact::new(
            "1.2.3",
            GuestBinsFingerprints {
                guest_source: "a".repeat(64),
                sdk_cdylib: "b".repeat(64),
            },
            crate::image_source::RepoIdentity {
                commit: GitCommit::new("c".repeat(40)).unwrap(),
                worktree: WorktreeState::Clean,
            },
        );
        for arch in [GuestArch::Aarch64, GuestArch::X86_64] {
            for name in crate::guest_agent_build::RUNTIME_OVERLAY_SEALED_BINS
                .into_iter()
                .chain(crate::guest_agent_build::RUNTIME_OVERLAY_ADDON_BINS)
                .chain(["mvm-oci-entrypoint", "mvm-setpriv"])
            {
                artifact.members.insert(
                    format!("{arch}/bin/{name}"),
                    MemberBytes {
                        mode: 0o555,
                        bytes: format!("{arch}/{name}").into_bytes(),
                    },
                );
            }
            artifact.members.insert(
                format!("{arch}/initramfs/mvm-guest-agent"),
                MemberBytes {
                    mode: 0o555,
                    bytes: format!("{arch}/sealed-agent").into_bytes(),
                },
            );
            for libc in [GuestLibc::Glibc, GuestLibc::Musl] {
                for library in crate::guest_bins::GPU_SHIM_CDYLIBS {
                    artifact.members.insert(
                        format!("{arch}/lib/{libc}/{}", library.soname),
                        MemberBytes {
                            mode: 0o644,
                            bytes: format!("{arch}/{libc}/{}", library.soname).into_bytes(),
                        },
                    );
                }
            }
        }
        artifact.members.insert(
            "sdk-py/mvm/__init__.py".into(),
            MemberBytes {
                mode: 0o644,
                bytes: b"# sdk".to_vec(),
            },
        );
        artifact
    }

    #[test]
    fn declarations_are_deterministic_and_bound_to_exact_members() {
        let mut first = artifact();
        first.declare_runtime_assemblies().unwrap();
        let mut second = artifact();
        second.declare_runtime_assemblies().unwrap();
        assert_eq!(first.assemblies, second.assemblies);
        assert_eq!(first.to_bytes().unwrap(), second.to_bytes().unwrap());
        for (arch, declaration) in &first.assemblies {
            declaration.validate(*arch).unwrap();
            assert_eq!(
                declaration.protocol_version,
                mvm_agentd::vsock::PROTOCOL_VERSION
            );
            let bytes = serde_json::to_vec(declaration).unwrap();
            assert_eq!(
                *declaration,
                serde_json::from_slice::<RuntimeAssembly>(&bytes).unwrap()
            );
        }
        second
            .members
            .get_mut("x86_64/bin/mvm-guest-agent")
            .unwrap()
            .bytes
            .push(1);
        second.declare_runtime_assemblies().unwrap();
        assert_ne!(
            first.assemblies[&GuestArch::X86_64].overlay_sha256,
            second.assemblies[&GuestArch::X86_64].overlay_sha256
        );
        assert_eq!(
            first.assemblies[&GuestArch::Aarch64],
            second.assemblies[&GuestArch::Aarch64]
        );
        assert_eq!(
            first.assemblies[&GuestArch::X86_64].initramfs_sha256,
            second.assemblies[&GuestArch::X86_64].initramfs_sha256
        );
        second
            .members
            .get_mut("x86_64/initramfs/mvm-guest-agent")
            .unwrap()
            .bytes
            .push(1);
        second.declare_runtime_assemblies().unwrap();
        assert_ne!(
            first.assemblies[&GuestArch::X86_64].initramfs_sha256,
            second.assemblies[&GuestArch::X86_64].initramfs_sha256
        );
    }

    #[test]
    fn foreign_protocol_source_is_not_labeled_with_producer_constants() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("crates/mvm-agentd/src/vsock/mod.rs");
        std::fs::create_dir_all(source.parent().unwrap()).unwrap();
        std::fs::write(&source, mvm_agentd::vsock::COMPILED_PROTOCOL_SOURCE).unwrap();
        verify_protocol_source(dir.path()).unwrap();
        std::fs::write(&source, b"pub const PROTOCOL_VERSION: u32 = 99;").unwrap();
        assert!(verify_protocol_source(dir.path()).is_err());
    }
}
