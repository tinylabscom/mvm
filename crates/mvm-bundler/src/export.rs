//! Reading the artifacts, building the manifest, sealing the archive.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use chrono::Utc;
use mvm_core::guest_sidecar::SIDECAR_FILENAME;
use mvm_core::plan::bundle::{
    ARTIFACTS_DIR, ArtifactRole, BUNDLE_SCHEMA_VERSION, BundleArtifact, BundleManifest, KeyId,
    VerityInfo, sha256_hex, write_bundle,
};

use crate::debug;
use crate::inputs::BundleExportInputs;
use crate::signer::BundleSigner;

const KERNEL_NAME: &str = "vmlinux";
const ROOTFS_NAME: &str = "rootfs.ext4";
const INITRD_NAME: &str = "initrd";
const VERITY_NAME: &str = "rootfs.verity";

/// A bundle that was written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportedBundle {
    /// Where the archive was written.
    pub path: PathBuf,
    /// The archive's size on disk.
    pub size_bytes: u64,
    /// The key the manifest was signed under.
    pub key_id: KeyId,
}

/// Seal the artifacts `inputs` names into a `.mvmpkg` signed by `signer`.
///
/// Nothing is written unless the whole bundle could be built: a rootfs with an
/// incomplete dm-verity binding or no guest sidecar is refused first. The
/// debug summary, when asked for, is written after the archive, so a summary
/// that cannot be written fails the call with the archive already on disk.
///
/// Artifacts are held in memory while the archive is assembled, as they are
/// when a bundle is verified.
pub fn export_bundle_with_signer(
    inputs: &BundleExportInputs<'_>,
    signer: &dyn BundleSigner,
) -> Result<ExportedBundle> {
    refuse_summary_over_archive(inputs)?;

    let mut contents = BundleContents::default();
    contents.push(
        KERNEL_NAME,
        ArtifactRole::Kernel,
        read_artifact("kernel", inputs.vmlinux)?,
    );
    contents.push(
        ROOTFS_NAME,
        ArtifactRole::Rootfs,
        read_artifact("rootfs", inputs.rootfs)?,
    );
    if let Some(initrd) = inputs.initrd {
        contents.push(
            INITRD_NAME,
            ArtifactRole::Initrd,
            read_artifact("initrd", initrd)?,
        );
    }
    let verity = contents.push_verity(inputs.verity_bytes, inputs.roothash)?;
    contents.push(
        SIDECAR_FILENAME,
        ArtifactRole::Other,
        read_guest_sidecar(inputs.rootfs)?,
    );

    let key_id = signer.key_id();
    let manifest = manifest_for(inputs, signer, &key_id, contents.artifacts, verity);
    let archive = write_bundle(&manifest, signer.signing_key(), contents.payload)
        .context("sealing bundle (manifest + signature + artifacts)")?;

    write_creating_parent(inputs.out, &archive, "bundle")?;
    if let Some(debug_out) = &inputs.debug_out {
        let summary = debug::render(debug_out.format, inputs.out, &archive, &manifest)?;
        write_creating_parent(&debug_out.path, &summary, "bundle debug summary")?;
    }

    Ok(ExportedBundle {
        path: inputs.out.to_path_buf(),
        size_bytes: archive.len() as u64,
        key_id,
    })
}

/// A summary aimed at the archive's own path would replace the bundle with a
/// description of it, and the call would still report success.
fn refuse_summary_over_archive(inputs: &BundleExportInputs<'_>) -> Result<()> {
    if let Some(debug_out) = &inputs.debug_out {
        anyhow::ensure!(
            debug_out.path != inputs.out,
            "the debug summary and the bundle are both set to {}; give the summary its own path",
            inputs.out.display()
        );
    }
    Ok(())
}

/// The guest sidecar the runtime admission gate looks for sits beside the
/// rootfs image.
pub fn guest_sidecar_path(rootfs: &str) -> Result<PathBuf> {
    Path::new(rootfs)
        .parent()
        .map(|dir| dir.join(SIDECAR_FILENAME))
        .ok_or_else(|| anyhow::anyhow!("rootfs path {rootfs} has no parent directory"))
}

/// The manifest entries and the bytes they describe, kept in step.
#[derive(Default)]
struct BundleContents {
    artifacts: Vec<BundleArtifact>,
    payload: Vec<(String, Vec<u8>)>,
}

impl BundleContents {
    fn push(&mut self, name: &str, role: ArtifactRole, bytes: Vec<u8>) {
        let path = format!("{ARTIFACTS_DIR}/{name}");
        self.artifacts.push(BundleArtifact {
            name: name.to_string(),
            role,
            path: path.clone(),
            sha256: sha256_hex(&bytes),
            size_bytes: bytes.len() as u64,
        });
        self.payload.push((path, bytes));
    }

    /// Carry the dm-verity sidecar and return the binding the manifest records.
    ///
    /// A sidecar without a root hash, or the reverse, is a misbuild. It is
    /// refused rather than exported unsealed: dropping the half that is there
    /// would turn a verified rootfs into an unverified one without saying so.
    fn push_verity(
        &mut self,
        sidecar: Option<&[u8]>,
        roothash: Option<&str>,
    ) -> Result<Option<VerityInfo>> {
        match (sidecar, roothash) {
            (Some(sidecar), Some(roothash)) => {
                self.push(
                    VERITY_NAME,
                    ArtifactRole::VerityHashSidecar,
                    sidecar.to_vec(),
                );
                Ok(Some(VerityInfo {
                    roothash: roothash.to_string(),
                    sidecar_artifact: VERITY_NAME.to_string(),
                }))
            }
            (Some(_), None) | (None, Some(_)) => anyhow::bail!(
                "template carries an incomplete dm-verity binding (sidecar without roothash, or vice versa); rebuild before exporting"
            ),
            (None, None) => Ok(None),
        }
    }
}

fn read_artifact(what: &str, path: &str) -> Result<Vec<u8>> {
    std::fs::read(path).with_context(|| format!("reading {what} at {path}"))
}

/// The runtime refuses to boot a rootfs whose sidecar is missing, so a bundle
/// exported without it is unbootable on arrival: it installs, and the failure
/// only surfaces at admission on the target host. Fail here instead.
fn read_guest_sidecar(rootfs: &str) -> Result<Vec<u8>> {
    let path = guest_sidecar_path(rootfs)?;
    std::fs::read(&path).with_context(|| {
        format!(
            "reading guest sidecar at {} — rebuild the template before exporting",
            path.display()
        )
    })
}

fn manifest_for(
    inputs: &BundleExportInputs<'_>,
    signer: &dyn BundleSigner,
    key_id: &KeyId,
    artifacts: Vec<BundleArtifact>,
    verity: Option<VerityInfo>,
) -> BundleManifest {
    BundleManifest {
        schema_version: BUNDLE_SCHEMA_VERSION,
        publisher: signer.publisher_id(),
        key_id: key_id.clone(),
        arch: inputs.arch_label.to_string(),
        kernel_version: None,
        profile: inputs.profile.map(str::to_string),
        workload_label: inputs.label.clone(),
        created_at: Utc::now().to_rfc3339(),
        labels: Default::default(),
        artifacts,
        members: Vec::new(),
        verity,
        resources: inputs.resources.clone(),
    }
}

fn write_creating_parent(path: &Path, bytes: &[u8], what: &str) -> Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating parent dir {}", parent.display()))?;
    }
    std::fs::write(path, bytes).with_context(|| format!("writing {what} to {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sidecar_resolves_beside_the_rootfs() {
        assert_eq!(
            guest_sidecar_path("/slots/abc/artifacts/rootfs.ext4").unwrap(),
            Path::new("/slots/abc/artifacts/mvm-meta.json")
        );
    }

    #[test]
    fn rootfs_without_a_parent_directory_is_refused() {
        assert!(guest_sidecar_path("/").is_err());
    }

    #[test]
    fn contents_keep_manifest_entries_and_payload_in_step() {
        let mut contents = BundleContents::default();
        contents.push(KERNEL_NAME, ArtifactRole::Kernel, b"kernel".to_vec());

        let entry = &contents.artifacts[0];
        assert_eq!(entry.path, "artifacts/vmlinux");
        assert_eq!(entry.size_bytes, 6);
        assert_eq!(entry.sha256, sha256_hex(b"kernel"));
        assert_eq!(
            contents.payload,
            vec![("artifacts/vmlinux".to_string(), b"kernel".to_vec())]
        );
    }

    #[test]
    fn half_a_verity_binding_adds_nothing() {
        let mut contents = BundleContents::default();
        assert!(contents.push_verity(Some(b"tree"), None).is_err());
        assert!(contents.push_verity(None, Some("ab")).is_err());
        assert!(contents.artifacts.is_empty());
        assert!(contents.payload.is_empty());
    }
}
