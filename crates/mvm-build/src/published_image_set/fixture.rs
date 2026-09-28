//! A signed-root-shaped image set served from a directory, for tests.
//!
//! [`ImageSetFixture::complete`] starts from a set that passes every check
//! [`PublishedImageSet::acquire_from`] makes: shaped to the shipped lock, every
//! member the current train requires, compatible with this host. A test then
//! publishes the member bytes it is about and edits whatever it wants refused.
//! [`ImageSetFixture::serve_from`] writes the root and the served bytes into a
//! directory and returns a source whose lock pins that exact root.
//!
//! No fixture can carry a publisher signature, so acquiring from one needs
//! `MVM_SKIP_COSIGN_VERIFY`; the signature rung has its own witnesses in
//! [`crate::release_signature`].
//!
//! [`PublishedImageSet::acquire_from`]: super::PublishedImageSet::acquire_from

use std::collections::BTreeMap;
use std::path::Path;

use chrono::{TimeZone, Utc};
use mvm_core::image_set::{
    ArtifactFormat, ArtifactName, BootProtocol, GitCommit, ImageSetManifest, ImageSetMember,
    ImageSetProducer, ImageSetRequirement, ImageSetRole, ImageTrainLock, MemberArtifact,
    MemberTarget, NixInputs, ReleaseProducer, RevocationChannel,
};
use mvm_core::packs::{FlakeLockIdentity, SbomReference, Sha256Hex};

use super::ImageSetSource;

/// An image set under construction, and the bytes served for its artifacts.
pub struct ImageSetFixture {
    manifest: ImageSetManifest,
    served: BTreeMap<String, Vec<u8>>,
}

impl ImageSetFixture {
    /// A complete release of the shipped lock's set whose members each declare
    /// one placeholder artifact that is never served.
    pub fn complete() -> Self {
        let train = mvm_core::image_set::image_train_lock();
        let lock = &train.image_set;
        let manifest = ImageSetManifest {
            schema_version: mvm_core::image_set::IMAGE_SET_SCHEMA_VERSION,
            set_version: lock.release_tag.version().clone(),
            issued_at: Utc.with_ymd_and_hms(2026, 9, 16, 0, 0, 0).unwrap(),
            producer: ImageSetProducer::Release(ReleaseProducer {
                repository: lock.repository.clone(),
                workflow: lock.signing_identity.workflow.clone(),
                release_tag: lock.release_tag.clone(),
                source_commit: commit('a'),
            }),
            mvm_source_commit: commit('b'),
            compatibility: train.compatibility.clone(),
            nix_inputs: NixInputs {
                flake_locks: vec![FlakeLockIdentity {
                    reference: "nix/images/builder-vm".to_string(),
                    lock_hash: Sha256Hex::from_bytes(b"flake.lock"),
                }],
                source_revisions: Vec::new(),
            },
            revocation_channel: Some(
                RevocationChannel::new(format!(
                    "https://github.com/{}/releases/download/revocations/revocations.json",
                    lock.repository
                ))
                .unwrap(),
            ),
            supersedes: None,
            members: ImageSetRequirement::current_train()
                .members()
                .iter()
                .map(|required| placeholder_member(required.role, required.target))
                .collect(),
        };
        Self {
            manifest,
            served: BTreeMap::new(),
        }
    }

    /// Declare `bytes` as the only artifact of the `role` member for `target`,
    /// adding the member if the set lacks it, and serve those bytes.
    #[must_use]
    pub fn publish(
        mut self,
        role: ImageSetRole,
        target: MemberTarget,
        name: &str,
        bytes: Vec<u8>,
    ) -> Self {
        let artifact = MemberArtifact {
            name: ArtifactName::new(name).unwrap(),
            format: ArtifactFormat::TarGz,
            sha256: Sha256Hex::from_bytes(&bytes),
            size: u64::try_from(bytes.len()).unwrap(),
        };
        let index = match self.position(role, target) {
            Some(index) => index,
            None => {
                self.manifest.members.push(placeholder_member(role, target));
                self.manifest.members.len() - 1
            }
        };
        self.manifest.members[index].artifacts = vec![artifact];
        self.served.insert(name.to_string(), bytes);
        self
    }

    /// Serve `bytes` under `name` while the root keeps declaring whatever it
    /// declared before.
    #[must_use]
    pub fn serve_instead(mut self, name: &str, bytes: Vec<u8>) -> Self {
        self.served.insert(name.to_string(), bytes);
        self
    }

    /// Drop the `role` member for `target` from the root.
    #[must_use]
    pub fn without_member(mut self, role: ImageSetRole, target: MemberTarget) -> Self {
        if let Some(index) = self.position(role, target) {
            self.manifest.members.remove(index);
        }
        self
    }

    /// Write the root and every served artifact into `dir`, and return a
    /// source whose lock pins exactly this root.
    pub fn serve_from(&self, dir: &Path) -> ImageSetSource {
        let mut train: ImageTrainLock = mvm_core::image_set::image_train_lock().clone();
        let root = serde_json::to_vec(&self.manifest).unwrap();
        train.image_set.manifest_sha256 = Sha256Hex::from_bytes(&root);
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join(train.image_set.manifest_asset.as_str()), &root).unwrap();
        for (name, bytes) in &self.served {
            std::fs::write(dir.join(name), bytes).unwrap();
        }
        ImageSetSource::new(train, format!("file://{}", dir.display()))
    }

    fn position(&self, role: ImageSetRole, target: MemberTarget) -> Option<usize> {
        self.manifest
            .members
            .iter()
            .position(|member| member.role == role && member.target == target)
    }
}

fn commit(fill: char) -> GitCommit {
    GitCommit::new(fill.to_string().repeat(40)).unwrap()
}

fn placeholder_member(role: ImageSetRole, target: MemberTarget) -> ImageSetMember {
    let name = format!("{role}-{target}.placeholder");
    ImageSetMember {
        role,
        target,
        boot_protocol: role.is_bootable().then_some(BootProtocol::LinuxDirect),
        artifacts: vec![MemberArtifact {
            name: ArtifactName::new(name.as_str()).unwrap(),
            format: ArtifactFormat::Text,
            sha256: Sha256Hex::from_bytes(name.as_bytes()),
            size: 1,
        }],
        required_capabilities: Vec::new(),
        pack_hash: Some(Sha256Hex::from_bytes(format!("pack:{name}").as_bytes())),
        sbom: Some(SbomReference {
            uri: format!("https://example.test/sbom/{name}.cdx.json"),
            sha256: Sha256Hex::from_bytes(format!("sbom:{name}").as_bytes()),
        }),
    }
}
