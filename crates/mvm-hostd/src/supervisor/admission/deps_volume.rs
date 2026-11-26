//! Re-verification of the sealed application-dependency volume a plan pins.
//!
//! No launch path calls this today: no boot path puts a
//! [`DepsVolumeBinding`] into a plan, and admission does not read one.

use std::path::{Path, PathBuf};

use mvm_core::deps_audit::{FILE_MANIFEST, VolumeError, verify_sealed_volume};
use mvm_core::plan::DepsVolumeBinding;
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Why a pinned deps volume was refused.
#[derive(Debug, Error)]
pub enum DepsVolumeError {
    /// The on-disk content re-derives a different volume hash than the plan
    /// pinned: the volume changed after it was sealed or after the plan was
    /// signed.
    #[error(
        "deps-volume tampered: plan pinned volume_hash {expected}, computed {actual} from on-disk content"
    )]
    Tampered { expected: String, actual: String },

    /// The on-disk `meta.json` bytes do not hash to the pinned
    /// `manifest_sha256`, even though the volume hash matched.
    #[error(
        "deps-volume manifest sha mismatch: plan pinned {expected}, computed {actual} from on-disk meta.json"
    )]
    ManifestMismatch { expected: String, actual: String },

    /// The pinned volume is missing, unreadable, or fails its own seal.
    #[error("deps-volume missing or unreadable at {}: {source}", path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: VolumeError,
    },
}

/// Re-derive the volume under `<volumes_root>/<volume_hash>/` and compare it
/// with `binding`.
///
/// Two checks, both fail-closed: the recomputed volume hash must equal the
/// pin, and the on-disk `meta.json` bytes must hash to the pinned
/// `manifest_sha256`. The second is a separate pin because
/// `verify_sealed_volume` only proves the manifest matches the artifacts, not
/// which manifest it is.
///
/// # Errors
///
/// Returns [`DepsVolumeError`] when the volume is missing, fails its seal, or
/// differs from either pin.
pub fn verify_deps_volume_binding(
    volumes_root: &Path,
    binding: &DepsVolumeBinding,
) -> Result<(), DepsVolumeError> {
    let volume_dir = volumes_root.join(&binding.volume_hash);
    let computed = verify_sealed_volume(&volume_dir).map_err(|source| DepsVolumeError::Io {
        path: volume_dir.clone(),
        source,
    })?;
    if computed != binding.volume_hash {
        return Err(DepsVolumeError::Tampered {
            expected: binding.volume_hash.clone(),
            actual: computed,
        });
    }

    let manifest_path = volume_dir.join(FILE_MANIFEST);
    let manifest_bytes = std::fs::read(&manifest_path).map_err(|source| DepsVolumeError::Io {
        path: volume_dir.clone(),
        source: VolumeError::Io {
            path: manifest_path.clone(),
            source,
        },
    })?;
    let manifest_sha = hex::encode(Sha256::digest(&manifest_bytes));
    if manifest_sha != binding.manifest_sha256 {
        return Err(DepsVolumeError::ManifestMismatch {
            expected: binding.manifest_sha256.clone(),
            actual: manifest_sha,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::deps_audit::{FILE_CVE, VolumeSealResult, seal_volume};
    use std::collections::BTreeMap;
    use std::fs;

    /// Seal a volume and place it at `<root>/<dir_name>/`.
    fn sealed_volume_at(
        root: &Path,
        dir_name: Option<&str>,
    ) -> (PathBuf, VolumeSealResult, String) {
        let staging = root.join("staging");
        let content = staging.join("content");
        fs::create_dir_all(content.join("sub")).unwrap();
        fs::write(content.join("a.txt"), b"alpha\n").unwrap();
        fs::write(content.join("sub").join("b.txt"), b"beta\n").unwrap();
        let sbom = staging.join("sbom.cdx.json");
        fs::write(&sbom, br#"{"bomFormat":"CycloneDX","specVersion":"1.5"}"#).unwrap();
        let fetch_log = staging.join("fetch.log");
        fs::write(&fetch_log, b"GET https://pypi.org/simple/requests/\n").unwrap();
        let cve = staging.join(FILE_CVE);
        fs::write(&cve, br#"{"results":[]}"#).unwrap();

        let sealed = seal_volume(
            &content,
            &sbom,
            &fetch_log,
            &cve,
            "2026-05-13T00:00:00Z",
            BTreeMap::new(),
        )
        .expect("seal");
        fs::write(staging.join(FILE_MANIFEST), &sealed.manifest_bytes).unwrap();
        let manifest_sha = hex::encode(Sha256::digest(&sealed.manifest_bytes));
        let dir = root.join(dir_name.unwrap_or(&sealed.volume_hash));
        fs::rename(&staging, &dir).unwrap();
        (dir, sealed, manifest_sha)
    }

    fn binding(volume_hash: &str, manifest_sha256: &str) -> DepsVolumeBinding {
        DepsVolumeBinding::new(volume_hash, manifest_sha256).expect("binding shape")
    }

    #[test]
    fn a_matching_volume_verifies() {
        let tmp = tempfile::tempdir().unwrap();
        let (_dir, sealed, manifest_sha) = sealed_volume_at(tmp.path(), None);
        verify_deps_volume_binding(tmp.path(), &binding(&sealed.volume_hash, &manifest_sha))
            .expect("pristine volume verifies");
    }

    #[test]
    fn a_cve_report_changed_after_seal_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let (dir, sealed, manifest_sha) = sealed_volume_at(tmp.path(), None);
        fs::write(dir.join(FILE_CVE), b"{\"results\":[\"FORGED\"]}").unwrap();

        let err =
            verify_deps_volume_binding(tmp.path(), &binding(&sealed.volume_hash, &manifest_sha))
                .expect_err("tampered volume refused");
        assert!(
            matches!(
                err,
                DepsVolumeError::Io {
                    source: VolumeError::HashMismatch { kind: "cve", .. },
                    ..
                }
            ),
            "{err:?}"
        );
    }

    #[test]
    fn a_missing_volume_directory_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let hash = "0".repeat(64);
        let err = verify_deps_volume_binding(tmp.path(), &binding(&hash, &"1".repeat(64)))
            .expect_err("missing volume refused");
        match err {
            DepsVolumeError::Io { path, source } => {
                assert!(path.ends_with(&hash));
                assert!(matches!(source, VolumeError::Missing(_)));
            }
            other => panic!("expected Io(Missing), got {other:?}"),
        }
    }

    #[test]
    fn a_volume_stored_under_another_hash_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let claimed = "d".repeat(64);
        let (_dir, sealed, manifest_sha) = sealed_volume_at(tmp.path(), Some(&claimed));
        let err = verify_deps_volume_binding(tmp.path(), &binding(&claimed, &manifest_sha))
            .expect_err("wrong pin refused");
        match err {
            DepsVolumeError::Tampered { expected, actual } => {
                assert_eq!(expected, claimed);
                assert_eq!(actual, sealed.volume_hash);
            }
            other => panic!("expected Tampered, got {other:?}"),
        }
    }

    #[test]
    fn a_wrong_manifest_pin_is_refused_even_when_the_volume_hash_matches() {
        let tmp = tempfile::tempdir().unwrap();
        let (_dir, sealed, _manifest_sha) = sealed_volume_at(tmp.path(), None);
        let bogus = "f".repeat(64);
        let err = verify_deps_volume_binding(tmp.path(), &binding(&sealed.volume_hash, &bogus))
            .expect_err("wrong manifest pin refused");
        match err {
            DepsVolumeError::ManifestMismatch { expected, actual } => {
                assert_eq!(expected, bogus);
                assert_ne!(actual, bogus);
            }
            other => panic!("expected ManifestMismatch, got {other:?}"),
        }
    }
}
