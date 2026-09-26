//! Locally built sets: the producer's wire shape, the structural rules each
//! producer brings, the release verifier refusing a local set, and every
//! refusal `verify_local_image_set` makes.

use std::path::PathBuf;

use super::*;
use crate::image_set::verify::verify_checked;
use crate::packs::KeylessTrust;

/// A set exactly as the image repository's `scripts/emit-local-manifest.py`
/// writes it: two members over a clean image checkout and a dirty mvm
/// checkout. A drift between that emitter and this parser fails here.
const EMITTED: &str = r#"{
  "schema_version": 2,
  "set_version": "0.0.0-local",
  "issued_at": "2026-01-01T00:00:00Z",
  "producer": {
    "local_checkouts": {
      "images": {
        "commit": "50bc307e1252d853ee6ab884ee9aac88ea663abf",
        "worktree": {
          "state": "clean"
        }
      },
      "mvm": {
        "commit": "f62ac50d84e0e3b7b76da75223f51018b9e87148",
        "worktree": {
          "state": "dirty",
          "fingerprint": "74037151d623ccabd3cd9bbf2d49dcb0844bee909bab25bed1953a9c8ad7f69e"
        }
      }
    }
  },
  "mvm_source_commit": "f62ac50d84e0e3b7b76da75223f51018b9e87148",
  "compatibility": {
    "guest_agent_protocol": {
      "min": 2,
      "max": 3
    },
    "builder_cache_contract": 1,
    "builder_boot_abi": 0
  },
  "nix_inputs": {
    "flake_locks": [
      {
        "reference": "mvm-images:flake.lock",
        "lock_hash": "1f7ae32f922602ae33e03b8fd880f0d4292372d0b352dceadea6cded9e7246fe"
      },
      {
        "reference": "mvm-images:kernel/flake.lock",
        "lock_hash": "861b2372a47a5bfceecaf67ca69feabc71bb07904dbd76788d5ff9f477c44aeb"
      }
    ],
    "source_revisions": []
  },
  "members": [
    {
      "role": { "workload_kernel": "default_tenant" },
      "target": {
        "arch": "aarch64"
      },
      "boot_protocol": "linux_direct",
      "artifacts": [
        {
          "name": "workload-kernel-aarch64-vmlinux",
          "format": {
            "kernel": "image"
          },
          "sha256": "a698d6f82e95c10873bc586950fbcef2464290376d47f5e7e6c4f436bdebfff1",
          "size": 14
        }
      ],
      "required_capabilities": [
        "virtio_vsock"
      ]
    },
    {
      "role": "runtime_overlay",
      "target": {
        "arch": "aarch64"
      },
      "artifacts": [
        {
          "name": "runtime-overlay-aarch64-overlay.ext4",
          "format": "ext4",
          "sha256": "be168fc20dd24264ed99b4a41f30c541e9fbced4f6b021d311e95b3a09b9e21c",
          "size": 14
        }
      ],
      "required_capabilities": [
        "virtio_blk"
      ]
    }
  ]
}
"#;

/// The bytes the emitter hashed for [`EMITTED`]'s two artifacts.
const EMITTED_ARTIFACTS: [(&str, &[u8]); 2] = [
    ("workload-kernel-aarch64-vmlinux", b"vmlinux bytes\n"),
    ("runtime-overlay-aarch64-overlay.ext4", b"overlay bytes\n"),
];

fn identity(fill: char, worktree: WorktreeState) -> RepoIdentity {
    RepoIdentity {
        commit: commit(fill),
        worktree,
    }
}

fn dirty(seed: &str) -> WorktreeState {
    WorktreeState::Dirty {
        fingerprint: sha(seed),
    }
}

fn checkouts() -> LocalCheckouts {
    LocalCheckouts {
        images: identity('d', WorktreeState::Clean),
        mvm: identity('e', dirty("mvm tree")),
    }
}

/// The release fixture rebuilt as a local aarch64 build: local producer, no
/// release-only fields, and only the members an aarch64 guest can use.
fn local_manifest() -> ImageSetManifest {
    let mut manifest = manifest();
    let local = checkouts();
    manifest.mvm_source_commit = local.mvm.commit.clone();
    manifest.producer = ImageSetProducer::LocalCheckouts(local);
    manifest.set_version = version("0.0.0-local");
    manifest.revocation_channel = None;
    manifest.compatibility.builder_boot_abi = Some(BuilderBootAbi::LEGACY);
    manifest
        .members
        .retain(|member| member.target.admits(GuestArch::Aarch64));
    for member in &mut manifest.members {
        member.pack_hash = None;
        member.sbom = None;
    }
    manifest
}

fn accept_signature(_: &[u8], _: &[u8], _: &KeylessTrust) -> Result<(), ImageSetError> {
    Ok(())
}

/// A set on disk: its manifest bytes and a directory of artifacts whose
/// declared digests and sizes are what was written.
struct Staged {
    dir: tempfile::TempDir,
    manifest_bytes: Vec<u8>,
}

impl Staged {
    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn verify(
        &self,
        current: &LocalCheckouts,
        arch: GuestArch,
        roles: &[ImageSetRole],
    ) -> Result<LocalImageSet, ImageSetError> {
        verify_local_image_set(
            &LocalImageSetVerification::new(&self.manifest_bytes, self.dir.path(), current, arch)
                .require_roles(roles),
        )
    }

    fn verify_fresh(&self) -> Result<LocalImageSet, ImageSetError> {
        self.verify(&checkouts(), GuestArch::Aarch64, &[])
    }
}

fn stage(mut manifest: ImageSetManifest) -> Staged {
    let dir = tempfile::tempdir().unwrap();
    for member in &mut manifest.members {
        for artifact in &mut member.artifacts {
            let bytes: Vec<u8> = artifact.name.as_str().bytes().cycle().take(256).collect();
            std::fs::write(dir.path().join(artifact.name.as_str()), &bytes).unwrap();
            artifact.sha256 = Sha256Hex::from_bytes(&bytes);
            artifact.size = bytes.len() as u64;
        }
    }
    Staged {
        manifest_bytes: serde_json::to_vec(&manifest).unwrap(),
        dir,
    }
}

fn stage_raw(manifest_bytes: &[u8]) -> Staged {
    Staged {
        dir: tempfile::tempdir().unwrap(),
        manifest_bytes: manifest_bytes.to_vec(),
    }
}

mod builder_boot_abi {
    use super::*;

    /// Until the image emitter writes the field, every existing local set
    /// omits it, and those sets still bake their binaries. Reading a missing
    /// ABI as the legacy one keeps them usable through the transition.
    #[test]
    fn a_local_set_without_one_reads_as_the_legacy_abi() {
        let mut manifest = local_manifest();
        manifest.compatibility.builder_boot_abi = None;
        stage(manifest.clone())
            .verify_fresh()
            .expect("a local set without the field is accepted");
        assert_eq!(
            manifest.compatibility.builder_boot_abi_or_legacy(),
            BuilderBootAbi::LEGACY
        );
    }

    #[test]
    fn a_local_set_declaring_one_is_accepted() {
        for abi in [BuilderBootAbi::LEGACY, BuilderBootAbi::PAYLOAD] {
            let mut manifest = local_manifest();
            manifest.compatibility.builder_boot_abi = Some(abi);
            stage(manifest).verify_fresh().unwrap();
        }
    }

    /// The emitted fixture carries the field the image repository's emitter
    /// writes.
    #[test]
    fn the_emitted_shape_declares_its_abi() {
        let manifest: ImageSetManifest = serde_json::from_str(EMITTED).unwrap();
        assert_eq!(
            manifest.compatibility.builder_boot_abi,
            Some(BuilderBootAbi::LEGACY)
        );
    }
}

mod wire {
    use super::*;

    #[test]
    fn a_release_producer_keeps_its_flat_shape() {
        let json = serde_json::to_value(manifest()).unwrap();
        let producer = json["producer"].as_object().unwrap();
        let mut keys: Vec<&str> = producer.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            ["release_tag", "repository", "source_commit", "workflow"]
        );
    }

    #[test]
    fn a_local_producer_is_local_checkouts_and_nothing_else() {
        let manifest = local_manifest();
        let json = serde_json::to_value(&manifest).unwrap();
        let producer = json["producer"].as_object().unwrap();
        assert_eq!(
            producer.keys().collect::<Vec<_>>(),
            ["local_checkouts"],
            "a local producer must name no release field"
        );
        assert!(json.get("revocation_channel").is_none());
        for member in json["members"].as_array().unwrap() {
            assert!(member.get("pack_hash").is_none());
            assert!(member.get("sbom").is_none());
        }
        round_trip(&manifest);
        round_trip(&manifest.producer);
    }

    #[test]
    fn a_producer_naming_a_release_and_local_checkouts_does_not_parse() {
        let mut json = serde_json::to_value(local_manifest()).unwrap();
        let producer = json["producer"].as_object_mut().unwrap();
        producer.insert("repository".into(), "tinylabscom/mvm-images".into());
        producer.insert("workflow".into(), ".github/workflows/release.yml".into());
        let err = serde_json::from_value::<ImageSetManifest>(json).unwrap_err();
        assert!(
            err.to_string()
                .contains("cannot also name a release (repository, workflow)"),
            "{err}"
        );
    }

    #[test]
    fn a_producer_naming_neither_or_half_a_release_does_not_parse() {
        for producer in [
            serde_json::json!({}),
            serde_json::json!({"repository": "tinylabscom/mvm-images"}),
            serde_json::json!({
                "repository": "tinylabscom/mvm-images",
                "workflow": ".github/workflows/release.yml",
                "release_tag": "v1.0.0"
            }),
        ] {
            let mut json = serde_json::to_value(manifest()).unwrap();
            json["producer"] = producer.clone();
            let err = serde_json::from_value::<ImageSetManifest>(json).unwrap_err();
            assert!(
                err.to_string().contains("neither local_checkouts"),
                "{producer}: {err}"
            );
        }
    }

    #[test]
    fn a_local_producer_refuses_unknown_fields() {
        let manifest = local_manifest();
        for path in [
            &["producer", "local_checkouts"][..],
            &["producer", "local_checkouts", "mvm"],
            &["producer", "local_checkouts", "images", "worktree"],
        ] {
            assert!(
                parse_with_extra_field::<ImageSetManifest>(&manifest, path).is_err(),
                "unknown field at {path:?} must be refused"
            );
        }
    }

    #[test]
    fn a_worktree_state_is_tagged_and_closed() {
        assert_eq!(
            serde_json::to_value(WorktreeState::Clean).unwrap(),
            serde_json::json!({"state": "clean"})
        );
        assert_eq!(
            serde_json::to_value(dirty("x")).unwrap(),
            serde_json::json!({"state": "dirty", "fingerprint": sha("x").as_str()})
        );
        for refused in [
            serde_json::json!({"state": "modified"}),
            serde_json::json!({"state": "dirty"}),
            serde_json::json!({"state": "dirty", "fingerprint": "abc"}),
            serde_json::json!({"state": "clean", "fingerprint": sha("x").as_str()}),
            serde_json::json!("clean"),
        ] {
            assert!(
                serde_json::from_value::<WorktreeState>(refused.clone()).is_err(),
                "{refused} must not parse"
            );
        }
    }

    #[test]
    fn the_emitters_output_parses_as_a_local_set() {
        let manifest: ImageSetManifest = serde_json::from_str(EMITTED).unwrap();
        validate_structure(&manifest).unwrap();
        let local = manifest.producer.local_checkouts().unwrap();
        assert_eq!(local.images.worktree, WorktreeState::Clean);
        assert!(local.mvm.worktree.is_dirty());
        assert!(manifest.producer.release().is_none());
    }
}

mod structure {
    use super::*;

    fn refused(manifest: &ImageSetManifest) -> ImageSetError {
        let err = validate_structure(manifest).unwrap_err();
        assert_eq!(err.stage(), ImageSetStage::Structure, "{err}");
        err
    }

    #[test]
    fn a_release_without_a_revocation_channel_is_refused() {
        let mut manifest = manifest();
        manifest.revocation_channel = None;
        assert!(matches!(
            refused(&manifest),
            ImageSetError::ReleaseFieldMissing {
                field: "revocation_channel"
            }
        ));
    }

    #[test]
    fn a_release_member_without_its_pack_or_sbom_is_refused() {
        let mut without_pack = manifest();
        without_pack.members[1].pack_hash = None;
        assert!(matches!(
            refused(&without_pack),
            ImageSetError::ReleaseMemberFieldMissing {
                field: "pack_hash",
                ..
            }
        ));
        let mut without_sbom = manifest();
        without_sbom.members[1].sbom = None;
        assert!(matches!(
            refused(&without_sbom),
            ImageSetError::ReleaseMemberFieldMissing { field: "sbom", .. }
        ));
    }

    #[test]
    fn a_local_set_carrying_release_fields_is_refused() {
        let release = manifest();

        let mut with_channel = local_manifest();
        with_channel.revocation_channel = release.revocation_channel.clone();
        assert!(matches!(
            refused(&with_channel),
            ImageSetError::LocalFieldPresent {
                field: "revocation_channel"
            }
        ));

        let mut with_lineage = local_manifest();
        with_lineage.supersedes = Some(Supersedes {
            set_version: version("0.0.0-earlier"),
            manifest_sha256: sha("earlier"),
        });
        assert!(matches!(
            refused(&with_lineage),
            ImageSetError::LocalFieldPresent {
                field: "supersedes"
            }
        ));

        let mut with_pack = local_manifest();
        with_pack.members[0].pack_hash = release.members[0].pack_hash.clone();
        assert!(matches!(
            refused(&with_pack),
            ImageSetError::LocalMemberFieldPresent {
                field: "pack_hash",
                ..
            }
        ));

        let mut with_sbom = local_manifest();
        with_sbom.members[0].sbom = release.members[0].sbom.clone();
        assert!(matches!(
            refused(&with_sbom),
            ImageSetError::LocalMemberFieldPresent { field: "sbom", .. }
        ));
    }

    #[test]
    fn a_local_set_naming_another_mvm_commit_is_refused() {
        let mut manifest = local_manifest();
        manifest.mvm_source_commit = commit('f');
        assert!(matches!(
            refused(&manifest),
            ImageSetError::LocalMvmCommitMismatch { declared, recorded }
                if declared == commit('f') && recorded == commit('e')
        ));
    }

    #[test]
    fn a_local_set_version_names_no_release_tag() {
        validate_structure(&local_manifest()).unwrap();
    }
}

mod release_path {
    use super::*;

    fn lock_pinning(bytes: &[u8]) -> ImageLock {
        let release_tag = ReleaseTag::new("v0.0.0-local").unwrap();
        ImageLock {
            schema_version: IMAGE_LOCK_SCHEMA_VERSION,
            repository: RepositorySlug::new("tinylabscom/mvm-images").unwrap(),
            manifest_asset: ArtifactName::new(LOCAL_SET_MANIFEST_NAME).unwrap(),
            manifest_sha256: Sha256Hex::from_bytes(bytes),
            signing_identity: SigningIdentity {
                workflow: WorkflowPath::new(".github/workflows/release.yml").unwrap(),
                tag_ref: TagRef::for_tag(&release_tag),
            },
            release_tag,
        }
    }

    /// Even with a lock pinning its exact bytes and a signature check that
    /// accepts anything, a local set is not a release.
    #[test]
    fn the_release_verifier_refuses_a_local_set() {
        let set = stage(local_manifest());
        let lock = lock_pinning(&set.manifest_bytes);
        let request = ImageSetVerification::new(&set.manifest_bytes, b"", &lock, set.dir.path());
        let err = verify_checked(&request, accept_signature).unwrap_err();
        assert!(matches!(err, ImageSetError::NotARelease), "{err}");
        assert_eq!(err.stage(), ImageSetStage::Provenance);
    }

    #[test]
    fn check_against_lock_refuses_a_local_set() {
        let manifest = local_manifest();
        let lock = lock_pinning(&serde_json::to_vec(&manifest).unwrap());
        let err = check_against_lock(&manifest, &lock.manifest_sha256, &lock).unwrap_err();
        assert!(matches!(err, ImageSetError::NotARelease), "{err}");
    }

    #[test]
    fn a_verified_release_reports_its_producer_and_the_release_tier() {
        let set = stage(manifest());
        let manifest: ImageSetManifest = serde_json::from_slice(&set.manifest_bytes).unwrap();
        let lock = lock_for(&manifest);
        let request = ImageSetVerification::new(&set.manifest_bytes, b"", &lock, set.dir.path());
        let verified = verify_checked(&request, accept_signature).unwrap();
        assert_eq!(&verified.release, release(&manifest));
        assert_eq!(verified.tier(), ImageTrustTier::VerifiedRelease);
    }

    #[cfg(unix)]
    #[test]
    fn the_release_verifier_refuses_a_symlinked_artifact() {
        let set = stage(manifest());
        let manifest: ImageSetManifest = serde_json::from_slice(&set.manifest_bytes).unwrap();
        let name = manifest.members[0].artifacts[0].name.to_string();
        let outside = tempfile::tempdir().unwrap();
        let real = outside.path().join("real");
        std::fs::rename(set.path(&name), &real).unwrap();
        std::os::unix::fs::symlink(&real, set.path(&name)).unwrap();
        let lock = lock_for(&manifest);
        let request = ImageSetVerification::new(&set.manifest_bytes, b"", &lock, set.dir.path());
        let err = verify_checked(&request, accept_signature).unwrap_err();
        assert!(
            matches!(err, ImageSetError::ArtifactNotRegularFile { .. }),
            "{err}"
        );
    }
}

mod local_path {
    use super::*;

    fn assert_stage(err: &ImageSetError, stage: ImageSetStage) {
        assert_eq!(err.stage(), stage, "{err}");
    }

    #[test]
    fn the_emitters_output_verifies_at_the_local_dev_tier() {
        let set = stage_raw(EMITTED.as_bytes());
        for (name, bytes) in EMITTED_ARTIFACTS {
            std::fs::write(set.path(name), bytes).unwrap();
        }
        let manifest: ImageSetManifest = serde_json::from_str(EMITTED).unwrap();
        let current = manifest.producer.local_checkouts().unwrap().clone();

        let read = set
            .verify(
                &current,
                GuestArch::Aarch64,
                &[
                    ImageSetRole::WorkloadKernel(WorkloadImageProfile::DefaultTenant),
                    ImageSetRole::RuntimeOverlay,
                ],
            )
            .unwrap();

        assert_eq!(read.tier(), ImageTrustTier::LocalDev);
        assert_eq!(read.checkouts, current);
        assert_eq!(read.artifacts.len(), 2);
        assert_eq!(
            read.manifest_sha256,
            Sha256Hex::from_bytes(EMITTED.as_bytes())
        );
    }

    #[test]
    fn a_fresh_set_verifies_and_reports_every_artifact() {
        let manifest = local_manifest();
        let expected: usize = manifest.members.iter().map(|m| m.artifacts.len()).sum();
        let set = stage(manifest);
        let read = set.verify_fresh().unwrap();
        assert_eq!(read.artifacts.len(), expected);
        assert!(
            read.artifacts
                .iter()
                .all(|a| a.path.starts_with(set.dir.path()))
        );
    }

    #[test]
    fn a_local_file_claiming_a_release_is_refused() {
        let mut release = manifest();
        release
            .members
            .retain(|member| member.target.admits(GuestArch::Aarch64));
        let set = stage(release);
        let err = set.verify_fresh().unwrap_err();
        assert!(
            matches!(&err, ImageSetError::LocalSetClaimsRelease { repository, .. }
                if repository.as_str() == "tinylabscom/mvm-images"),
            "{err}"
        );
        assert_stage(&err, ImageSetStage::Provenance);
    }

    #[test]
    fn a_set_built_from_another_image_commit_is_stale() {
        let set = stage(local_manifest());
        let mut current = checkouts();
        current.images.commit = commit('9');
        let err = set.verify(&current, GuestArch::Aarch64, &[]).unwrap_err();
        assert!(
            matches!(
                &err,
                ImageSetError::StaleLocalSet {
                    checkout: "mvm-images",
                    ..
                }
            ),
            "{err}"
        );
        assert_stage(&err, ImageSetStage::Freshness);
    }

    #[test]
    fn a_set_built_before_an_mvm_edit_is_stale() {
        let set = stage(local_manifest());
        let mut current = checkouts();
        current.mvm.worktree = dirty("mvm tree, edited since");
        let err = set.verify(&current, GuestArch::Aarch64, &[]).unwrap_err();
        assert!(
            matches!(&err, ImageSetError::StaleLocalSet { checkout: "mvm", recorded, current }
                if recorded.worktree == dirty("mvm tree")
                    && current.worktree == dirty("mvm tree, edited since")),
            "{err}"
        );
    }

    #[test]
    fn a_set_from_a_dirty_tree_is_stale_once_the_tree_is_clean() {
        let set = stage(local_manifest());
        let mut current = checkouts();
        current.mvm.worktree = WorktreeState::Clean;
        let err = set.verify(&current, GuestArch::Aarch64, &[]).unwrap_err();
        assert!(
            matches!(
                err,
                ImageSetError::StaleLocalSet {
                    checkout: "mvm",
                    ..
                }
            ),
            "{err}"
        );
    }

    #[test]
    fn a_set_for_another_architecture_is_refused() {
        let set = stage(local_manifest());
        let err = set
            .verify(&checkouts(), GuestArch::X86_64, &[])
            .unwrap_err();
        assert!(
            matches!(&err, ImageSetError::WrongArchitecture { requested, available, .. }
                if *requested == GuestArch::X86_64 && available == &[ARM]),
            "{err}"
        );
        assert_stage(&err, ImageSetStage::Selection);
    }

    #[test]
    fn a_set_mixing_architectures_is_refused() {
        let mut manifest = local_manifest();
        let mut foreign = manifest.members[0].clone();
        foreign.target = X86;
        for artifact in &mut foreign.artifacts {
            artifact.name = ArtifactName::new(format!("{}-x86", artifact.name)).unwrap();
        }
        manifest.members.push(foreign);
        let set = stage(manifest);
        let err = set.verify_fresh().unwrap_err();
        assert!(
            matches!(
                err,
                ImageSetError::WrongArchitecture {
                    requested: GuestArch::Aarch64,
                    ..
                }
            ),
            "{err}"
        );
    }

    #[test]
    fn a_missing_role_is_refused() {
        let mut manifest = local_manifest();
        let musl = ImageSetRole::SdkSidecar(GuestLibc::Musl);
        manifest.members.retain(|member| member.role != musl);
        let set = stage(manifest);
        let err = set
            .verify(
                &checkouts(),
                GuestArch::Aarch64,
                &[
                    ImageSetRole::WorkloadKernel(WorkloadImageProfile::DefaultTenant),
                    musl,
                ],
            )
            .unwrap_err();
        assert!(
            matches!(&err, ImageSetError::Incomplete { missing }
                if missing == &[RequiredMember { role: musl, target: ARM }]),
            "{err}"
        );
        assert_stage(&err, ImageSetStage::Completeness);
    }

    #[test]
    fn an_architecture_independent_role_is_required_as_one() {
        let set = stage(local_manifest());
        set.verify(
            &checkouts(),
            GuestArch::Aarch64,
            &[ImageSetRole::QemuWasmSmokePack],
        )
        .unwrap();
    }

    #[test]
    fn an_artifact_name_that_leaves_the_directory_does_not_parse() {
        for name in ["../escape", "/etc/passwd", "nested/file", "..", "."] {
            let mut json = serde_json::to_value(local_manifest()).unwrap();
            json["members"][0]["artifacts"][0]["name"] = name.into();
            let set = stage_raw(&serde_json::to_vec(&json).unwrap());
            let err = set.verify_fresh().unwrap_err();
            assert!(
                matches!(err, ImageSetError::UnparseableManifest { .. }),
                "{name}: {err}"
            );
            assert_stage(&err, ImageSetStage::Parse);
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_artifact_is_refused_even_with_the_right_bytes() {
        let set = stage(local_manifest());
        let manifest: ImageSetManifest = serde_json::from_slice(&set.manifest_bytes).unwrap();
        let name = manifest.members[0].artifacts[0].name.to_string();
        let outside = tempfile::tempdir().unwrap();
        let real = outside.path().join("real");
        std::fs::rename(set.path(&name), &real).unwrap();
        std::os::unix::fs::symlink(&real, set.path(&name)).unwrap();

        let err = set.verify_fresh().unwrap_err();
        assert!(
            matches!(&err, ImageSetError::ArtifactNotRegularFile { name: refused, .. }
                if refused.as_str() == name),
            "{err}"
        );
        assert_stage(&err, ImageSetStage::Artifacts);
    }

    #[test]
    fn a_directory_in_place_of_an_artifact_is_refused() {
        let set = stage(local_manifest());
        let manifest: ImageSetManifest = serde_json::from_slice(&set.manifest_bytes).unwrap();
        let name = manifest.members[0].artifacts[0].name.to_string();
        std::fs::remove_file(set.path(&name)).unwrap();
        std::fs::create_dir(set.path(&name)).unwrap();
        let err = set.verify_fresh().unwrap_err();
        assert!(
            matches!(err, ImageSetError::ArtifactNotRegularFile { .. }),
            "{err}"
        );
    }

    #[test]
    fn a_changed_or_missing_artifact_is_refused() {
        let set = stage(local_manifest());
        let manifest: ImageSetManifest = serde_json::from_slice(&set.manifest_bytes).unwrap();
        let name = manifest.members[0].artifacts[0].name.to_string();
        let mut bytes = std::fs::read(set.path(&name)).unwrap();
        bytes[0] ^= 0xff;
        std::fs::write(set.path(&name), &bytes).unwrap();
        assert!(matches!(
            set.verify_fresh().unwrap_err(),
            ImageSetError::ArtifactDigestMismatch { .. }
        ));
        std::fs::remove_file(set.path(&name)).unwrap();
        assert!(matches!(
            set.verify_fresh().unwrap_err(),
            ImageSetError::ArtifactMissing { .. }
        ));
    }

    #[test]
    fn bytes_that_are_not_a_manifest_are_refused() {
        let err = stage_raw(b"{\"schema_version\": 1")
            .verify_fresh()
            .unwrap_err();
        assert_stage(&err, ImageSetStage::Parse);
    }

    #[test]
    fn a_set_the_host_cannot_speak_to_is_refused_when_asked() {
        let set = stage(local_manifest());
        let current = checkouts();
        let host = HostProtocolSupport {
            guest_agent_protocol: ProtocolRange::new(5, 6).unwrap(),
            builder_cache_contract: 4,
            builder_boot_abi: BuilderBootAbiRange::new(
                BuilderBootAbi::LEGACY,
                BuilderBootAbi::PAYLOAD,
            )
            .unwrap(),
        };
        let err = verify_local_image_set(
            &LocalImageSetVerification::new(
                &set.manifest_bytes,
                set.dir.path(),
                &current,
                GuestArch::Aarch64,
            )
            .with_host_protocols(&host),
        )
        .unwrap_err();
        assert_stage(&err, ImageSetStage::ProtocolCompatibility);
    }
}
