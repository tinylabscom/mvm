//! `mvmctl image boot verify` — check a published image set, offline.
//!
//! Reads the four inputs a verification needs from disk and hands them to
//! `mvm_core::image_set::verify_image_set`, which owns every stage. This module
//! adds nothing to what is checked; it only reads the inputs, and says which
//! stage refused. Nothing here touches the network or the boot image cache.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use mvm_core::image_set::{
    ImageLock, ImageSetError, ImageSetRequirement, ImageSetVerification, VerifiedImageSet,
    verify_image_set,
};
use serde_json::json;

/// What `mvmctl image boot verify` was asked to check.
#[derive(Debug, Clone)]
pub(in crate::commands) struct VerifyRequest {
    pub manifest: PathBuf,
    pub bundle: PathBuf,
    pub lock: PathBuf,
    pub artifacts: PathBuf,
    pub require_complete: bool,
    pub json: bool,
}

/// The inputs as read from disk, before any of them is trusted.
struct VerifyInputs {
    manifest_bytes: Vec<u8>,
    bundle_bytes: Vec<u8>,
    lock: ImageLock,
}

impl VerifyInputs {
    fn read(request: &VerifyRequest) -> Result<Self> {
        let manifest_bytes = read_input("image set manifest", &request.manifest)?;
        let bundle_bytes = read_input("signature bundle", &request.bundle)?;
        let lock = read_lock(&request.lock)?;
        require_directory(&request.artifacts)?;
        Ok(Self {
            manifest_bytes,
            bundle_bytes,
            lock,
        })
    }
}

fn read_input(what: &str, path: &Path) -> Result<Vec<u8>> {
    std::fs::read(path).with_context(|| format!("cannot read {what} {}", path.display()))
}

/// The lock is the trust root, so a lock that does not parse is refused before
/// anything is compared against it. TOML, because that is the format of the
/// checked-in `images.lock` an image-set pin will live in.
fn read_lock(path: &Path) -> Result<ImageLock> {
    let bytes = read_input("image lock", path)?;
    let text = std::str::from_utf8(&bytes)
        .with_context(|| format!("{} is not UTF-8 text", path.display()))?;
    toml::from_str(text).with_context(|| format!("{} is not a valid image lock", path.display()))
}

fn require_directory(path: &Path) -> Result<()> {
    if path.is_dir() {
        Ok(())
    } else {
        bail!("artifact directory {} is not a directory", path.display())
    }
}

/// Run every verification stage. The outer `Result` is an input that could not
/// be read; the inner one is the verifier's verdict.
fn verify(request: &VerifyRequest) -> Result<Result<VerifiedImageSet, ImageSetError>> {
    let inputs = VerifyInputs::read(request)?;
    let requirement = ImageSetRequirement::current_train();
    let mut verification = ImageSetVerification::new(
        &inputs.manifest_bytes,
        &inputs.bundle_bytes,
        &inputs.lock,
        &request.artifacts,
    );
    if request.require_complete {
        verification = verification.require(&requirement);
    }
    Ok(verify_image_set(&verification))
}

/// One line naming the stage first, so a reader learns how far the set got
/// before reading why it stopped.
fn refusal_message(error: &ImageSetError) -> String {
    format!("image set refused at the {} stage: {error}", error.stage())
}

fn verified_json(verified: &VerifiedImageSet) -> serde_json::Value {
    json!({
        "verified": true,
        "set_version": verified.manifest.set_version.as_str(),
        "release_tag": verified.release.release_tag.as_str(),
        "manifest_sha256": verified.manifest_sha256.as_str(),
        "signer_key_id": verified.signer_key_id.0,
        "artifacts": verified.artifacts.iter().map(|artifact| json!({
            "role": artifact.role.to_string(),
            "target": artifact.target.to_string(),
            "name": artifact.name.as_str(),
            "sha256": artifact.sha256.as_str(),
            "size": artifact.size,
        })).collect::<Vec<_>>(),
    })
}

fn refused_json(error: &ImageSetError) -> serde_json::Value {
    json!({
        "verified": false,
        "stage": error.stage().label(),
        "reason": error.to_string(),
    })
}

fn verified_text(verified: &VerifiedImageSet) -> String {
    let mut text = format!(
        "Image set {} ({}) verified.\n  manifest sha256: {}\n  signer key id:   {}\n  artifacts:       {}\n",
        verified.manifest.set_version,
        verified.release.release_tag,
        verified.manifest_sha256.as_str(),
        verified.signer_key_id.0,
        verified.artifacts.len(),
    );
    for artifact in &verified.artifacts {
        text.push_str(&format!(
            "    {}/{} {} {} ({} bytes)\n",
            artifact.role,
            artifact.target,
            artifact.name,
            artifact.sha256.as_str(),
            artifact.size,
        ));
    }
    text
}

pub(super) fn run(request: &VerifyRequest) -> Result<()> {
    let verdict = verify(request)?;
    if request.json {
        let value = match &verdict {
            Ok(verified) => verified_json(verified),
            Err(error) => refused_json(error),
        };
        println!("{}", serde_json::to_string_pretty(&value)?);
    } else if let Ok(verified) = &verdict {
        // The report is the command's output, not commentary, so it bypasses
        // the opt-in chatter channel.
        print!("{}", verified_text(verified));
    }
    verdict
        .map(drop)
        .map_err(|error| anyhow!(refusal_message(&error)))
}

#[cfg(test)]
mod tests {
    use mvm_core::image_set::{
        ImageSetManifest, ImageSetStage, ReleaseTag, RepositorySlug, SigningIdentity, TagRef,
        WorkflowPath, validate_structure,
    };
    use mvm_core::packs::Sha256Hex;

    use super::*;

    /// A one-member set in the exact shape the pack-signing smoke workflow
    /// writes, so a drift between that workflow and the parser fails here
    /// rather than on a nightly run.
    const MANIFEST: &str = r#"{
      "schema_version": 1,
      "set_version": "0.0.0-smoke",
      "issued_at": "2026-01-01T00:00:00Z",
      "producer": {
        "repository": "tinylabscom/mvm",
        "workflow": ".github/workflows/pack-signing-smoke.yml",
        "release_tag": "v0.0.0-smoke",
        "source_commit": "0000000000000000000000000000000000000000"
      },
      "mvm_source_commit": "0000000000000000000000000000000000000000",
      "compatibility": {"guest_agent_protocol": {"min": 1, "max": 1}, "builder_cache_contract": 1},
      "nix_inputs": {
        "flake_locks": [{"reference": "smoke", "lock_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}],
        "source_revisions": []
      },
      "revocation_channel": "https://example.test/revocations.json",
      "members": [{
        "role": "workload_kernel",
        "target": {"arch": "x86_64"},
        "boot_protocol": "linux_direct",
        "artifacts": [{
          "name": "vmlinux",
          "format": {"kernel": "elf"},
          "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          "size": 12
        }],
        "required_capabilities": ["virtio_vsock"],
        "pack_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "sbom": {"uri": "https://example.test/sbom.txt", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}
      }]
    }"#;

    /// Files on disk for one request; the directory lives as long as the test.
    struct Staged {
        _dir: tempfile::TempDir,
        request: VerifyRequest,
    }

    fn lock_pinning(bytes: &[u8], repository: &str, workflow: &str, tag: &str) -> ImageLock {
        let release_tag = ReleaseTag::new(tag).unwrap();
        ImageLock {
            schema_version: mvm_core::image_set::IMAGE_LOCK_SCHEMA_VERSION,
            repository: RepositorySlug::new(repository).unwrap(),
            manifest_asset: mvm_core::image_set::ArtifactName::new("image-set.json").unwrap(),
            manifest_sha256: Sha256Hex::from_bytes(bytes),
            signing_identity: SigningIdentity {
                workflow: WorkflowPath::new(workflow).unwrap(),
                tag_ref: TagRef::for_tag(&release_tag),
            },
            release_tag,
        }
    }

    fn stage(manifest: &[u8], bundle: &[u8], lock: &ImageLock) -> Staged {
        let dir = tempfile::tempdir().unwrap();
        let artifacts = dir.path().join("artifacts");
        std::fs::create_dir(&artifacts).unwrap();
        let path = |name: &str| dir.path().join(name);
        std::fs::write(path("manifest.json"), manifest).unwrap();
        std::fs::write(path("manifest.json.bundle"), bundle).unwrap();
        std::fs::write(path("images.lock"), toml::to_string(lock).unwrap()).unwrap();
        let request = VerifyRequest {
            manifest: path("manifest.json"),
            bundle: path("manifest.json.bundle"),
            lock: path("images.lock"),
            artifacts,
            require_complete: false,
            json: false,
        };
        Staged { _dir: dir, request }
    }

    fn refused(staged: &Staged) -> ImageSetError {
        verify(&staged.request)
            .expect("every input is readable")
            .expect_err("the set must be refused")
    }

    #[test]
    fn the_smoke_workflow_manifest_shape_parses_and_is_well_formed() {
        let manifest: ImageSetManifest =
            serde_json::from_str(MANIFEST).expect("the workflow's manifest shape must parse");
        validate_structure(&manifest).expect("the workflow's manifest must be well formed");
    }

    #[test]
    fn a_manifest_the_lock_does_not_pin_is_refused_at_the_digest() {
        let lock = lock_pinning(
            b"other bytes",
            "tinylabscom/mvm",
            ".github/workflows/release.yml",
            "v0.0.0-smoke",
        );
        let staged = stage(MANIFEST.as_bytes(), b"", &lock);

        let err = refused(&staged);

        assert_eq!(err.stage(), ImageSetStage::ManifestDigest, "got: {err}");
        let message = refusal_message(&err);
        assert!(
            message.starts_with("image set refused at the manifest-digest stage: "),
            "the stage must lead the message: {message}"
        );
    }

    #[test]
    fn a_refusal_exits_nonzero_and_names_the_stage() {
        let lock = lock_pinning(
            b"other bytes",
            "tinylabscom/mvm",
            ".github/workflows/release.yml",
            "v0.0.0-smoke",
        );
        let staged = stage(MANIFEST.as_bytes(), b"", &lock);

        let err = run(&staged.request).expect_err("a refused set must fail the command");

        assert!(
            err.to_string().contains("manifest-digest stage"),
            "got: {err}"
        );
    }

    #[test]
    fn the_json_refusal_carries_the_stage_label() {
        let err = ImageSetError::SignatureInvalid {
            identity: "someone".to_string(),
            reason: "no".to_string(),
        };

        let value = refused_json(&err);

        assert_eq!(value["verified"], false);
        assert_eq!(value["stage"], "signature");
        assert!(value["reason"].as_str().unwrap().contains("someone"));
    }

    #[test]
    fn an_unreadable_input_is_named() {
        let lock = lock_pinning(
            MANIFEST.as_bytes(),
            "tinylabscom/mvm",
            ".github/workflows/release.yml",
            "v0.0.0-smoke",
        );
        let staged = stage(MANIFEST.as_bytes(), b"", &lock);
        std::fs::remove_file(&staged.request.bundle).unwrap();

        let err = verify(&staged.request).expect_err("a missing bundle file is an input error");

        assert!(
            err.to_string().contains("cannot read signature bundle"),
            "got: {err}"
        );
    }

    #[test]
    fn a_lock_that_does_not_parse_is_refused_before_verification() {
        let lock = lock_pinning(
            MANIFEST.as_bytes(),
            "tinylabscom/mvm",
            ".github/workflows/release.yml",
            "v0.0.0-smoke",
        );
        let staged = stage(MANIFEST.as_bytes(), b"", &lock);
        let text = std::fs::read_to_string(&staged.request.lock).unwrap();
        let branch_bound = text.replace("refs/tags/v0.0.0-smoke", "refs/heads/main");
        assert_ne!(text, branch_bound, "the fixture must name the tag ref");
        std::fs::write(&staged.request.lock, branch_bound).unwrap();

        let err = verify(&staged.request).expect_err("a branch-bound lock must not parse");

        assert!(
            err.to_string().contains("is not a valid image lock"),
            "got: {err}"
        );
    }

    #[test]
    fn an_artifact_path_that_is_not_a_directory_is_refused() {
        let lock = lock_pinning(
            MANIFEST.as_bytes(),
            "tinylabscom/mvm",
            ".github/workflows/release.yml",
            "v0.0.0-smoke",
        );
        let mut staged = stage(MANIFEST.as_bytes(), b"", &lock);
        staged.request.artifacts = staged.request.manifest.clone();

        let err = verify(&staged.request).expect_err("a file is not an artifact directory");

        assert!(err.to_string().contains("is not a directory"), "got: {err}");
    }

    #[test]
    fn a_verified_set_reports_every_artifact() {
        let manifest: ImageSetManifest = serde_json::from_str(MANIFEST).unwrap();
        let member = &manifest.members[0];
        let artifact = &member.artifacts[0];
        let verified = VerifiedImageSet {
            release: manifest.producer.release().unwrap().clone(),
            manifest_sha256: Sha256Hex::from_bytes(MANIFEST.as_bytes()),
            signer_key_id: mvm_core::plan::bundle::key_id_from_identity("someone"),
            artifacts: vec![mvm_core::image_set::VerifiedArtifact {
                role: member.role,
                target: member.target,
                name: artifact.name.clone(),
                path: PathBuf::from("/artifacts/vmlinux"),
                sha256: artifact.sha256.clone(),
                size: artifact.size,
            }],
            manifest,
        };

        let value = verified_json(&verified);
        let text = verified_text(&verified);

        assert_eq!(value["verified"], true);
        assert_eq!(value["set_version"], "0.0.0-smoke");
        assert_eq!(value["artifacts"][0]["role"], "workload_kernel");
        assert_eq!(value["artifacts"][0]["target"], "x86_64");
        assert_eq!(value["artifacts"][0]["name"], "vmlinux");
        assert!(text.contains("Image set 0.0.0-smoke (v0.0.0-smoke) verified."));
        assert!(text.contains("workload_kernel/x86_64 vmlinux"));
    }

    /// The real release bundle `mvm-build` and `mvm-core` already verify: a
    /// `v0.18.0-rc.1` release-workflow signature over a checksum manifest. It is
    /// the only committed genuine Sigstore signature, so it is how this command
    /// is shown to reach the real verifier.
    #[cfg(feature = "manifest-verify")]
    mod release_bundle {
        use super::*;

        const ASSET: &str = "builder-vm-aarch64-checksums-sha256.txt";

        fn fixture(name: &str) -> PathBuf {
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../mvm-build/tests/fixtures/release-signature/v0.18.0-rc.1")
                .join(name)
        }

        fn staged_under(workflow: &str) -> Staged {
            let payload = std::fs::read(fixture(ASSET)).unwrap();
            let bundle = std::fs::read(fixture(&format!("{ASSET}.bundle"))).unwrap();
            let lock = lock_pinning(&payload, "tinylabscom/mvm", workflow, "v0.18.0-rc.1");
            stage(&payload, &bundle, &lock)
        }

        /// The control: under the identity that really signed, the signature
        /// passes and only the parse refuses, because the payload is a checksum
        /// file rather than an image set.
        #[test]
        fn the_signing_identity_passes_the_signature_and_stops_at_the_parse() {
            let staged = staged_under(".github/workflows/release.yml");

            let err = refused(&staged);

            assert_eq!(err.stage(), ImageSetStage::Parse, "got: {err}");
        }

        #[test]
        fn another_workflow_is_refused_at_the_signature() {
            let staged = staged_under(".github/workflows/release-boot-image.yml");

            let err = refused(&staged);

            assert_eq!(err.stage(), ImageSetStage::Signature, "got: {err}");
            assert!(
                refusal_message(&err).contains("signature stage"),
                "got: {err}"
            );
        }
    }
}
