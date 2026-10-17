//! Reading the artifacts, building the manifest, sealing the archive.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use chrono::Utc;
use mvm_core::crypto::image_verify::sha256_file;
use mvm_core::guest_sidecar::SIDECAR_FILENAME;
use mvm_core::plan::bundle::{
    ARTIFACTS_DIR, ArtifactRole, BUNDLE_MEMBERS_MIN_SCHEMA, BundleArtifact, BundleManifest,
    BundleMember, BundlePayload, BundleSecurityPosture, BundleSizeBudget, KeyId, VerityInfo,
    sha256_hex, write_bundle_to,
};
use mvm_core::plan::types::BuildProvenance;

use crate::debug;
use crate::inputs::{BundleExportInputs, PostureInputs};
use crate::signer::{AsManifestSigner, BundleSigner};

const KERNEL_NAME: &str = "vmlinux";
const ROOTFS_NAME: &str = "rootfs.ext4";
const INITRD_NAME: &str = "initrd";
const VERITY_NAME: &str = "rootfs.verity";
const BOOT_MANIFEST_NAME: &str = "boot-image-set.json";
const LINUX_SIGNATURE_NAME: &str = "boot-image-set.json.bundle";
const REVOCATIONS_NAME: &str = "image-set-revocations.json";
const REVOCATIONS_SIGNATURE_NAME: &str = "image-set-revocations.json.bundle";

#[cfg(test)]
#[path = "export/canonical_tests.rs"]
mod canonical_tests;

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
/// Each artifact file is hashed in one streaming pass and copied into the
/// archive in another, through a fixed buffer, so a multi-GiB rootfs is never
/// held in memory. Its size is checked against the bundle caps before either.
/// The archive is written to an invocation-private `<out>.<pid>.<n>.partial`, created only once the manifest
/// is signed, and renamed into place when complete.
pub fn export_bundle_with_signer(
    inputs: &BundleExportInputs<'_>,
    signer: &dyn BundleSigner,
) -> Result<ExportedBundle> {
    export_bundle_at(inputs, signer, Utc::now())
}

fn export_bundle_at(
    inputs: &BundleExportInputs<'_>,
    signer: &dyn BundleSigner,
    now: chrono::DateTime<Utc>,
) -> Result<ExportedBundle> {
    refuse_summary_over_archive(inputs)?;
    anyhow::ensure!(
        inputs.boot_assets.is_none() || inputs.cli_boot_assets.is_none(),
        "cannot mix CLI and legacy boot assets"
    );
    anyhow::ensure!(
        inputs.canonical_linux_proof.is_none()
            || (inputs.cli_boot_assets.is_some() && inputs.boot_assets.is_none()),
        "canonical Linux proof requires one selected CLI boot closure"
    );

    let mut contents = BundleContents::default();
    contents.push_file(KERNEL_NAME, ArtifactRole::Kernel, "kernel", inputs.vmlinux)?;
    contents.push_file(ROOTFS_NAME, ArtifactRole::Rootfs, "rootfs", inputs.rootfs)?;
    if let Some(initrd) = inputs.initrd {
        contents.push_file(INITRD_NAME, ArtifactRole::Initrd, "initrd", initrd)?;
    }
    let verity = contents.push_verity(inputs.verity_bytes, inputs.roothash)?;
    contents.push(
        SIDECAR_FILENAME,
        ArtifactRole::Other,
        read_guest_sidecar(inputs.rootfs)?,
    )?;
    if let Some(boot) = &inputs.boot_assets {
        contents.push_boot_assets(boot, inputs.arch_label)?;
    }
    if let Some(boot) = &inputs.cli_boot_assets {
        anyhow::ensure!(
            inputs.boot_assets.is_none(),
            "cannot mix CLI and legacy boot assets"
        );
        contents.push_cli_boot_assets(boot, inputs.arch_label)?;
    }
    if let Some(proof) = &inputs.canonical_linux_proof {
        let boot = inputs
            .cli_boot_assets
            .as_ref()
            .context("canonical Linux proof requires the selected CLI boot closure")?;
        contents.push_canonical_linux_proof(proof, boot, now)?;
    }

    let key_id = signer.key_id();
    let members = declarations_for(inputs, &contents.artifacts, verity.is_some());
    let manifest = manifest_for(inputs, signer, &key_id, contents.artifacts, members, verity);
    let mut output = PartialOutput::new(inputs.out);
    let sealed = write_bundle_to(
        &manifest,
        &AsManifestSigner(signer),
        contents.payload,
        &mut output,
    )
    .context("sealing bundle (manifest + signature + artifacts)");
    let size_bytes = output.finish(sealed)?;

    if let Some(debug_out) = &inputs.debug_out {
        let archive_sha256 = sha256_file(inputs.out)
            .with_context(|| format!("hashing the bundle at {}", inputs.out.display()))?;
        let summary = debug::render(
            debug_out.format,
            inputs.out,
            debug::ArchiveIdentity {
                sha256: archive_sha256,
                size_bytes,
            },
            &manifest,
        )?;
        write_creating_parent(&debug_out.path, &summary, "bundle debug summary")?;
    }

    Ok(ExportedBundle {
        path: inputs.out.to_path_buf(),
        size_bytes,
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
    payload: Vec<(String, BundlePayload)>,
    budget: BundleSizeBudget,
}

impl BundleContents {
    fn push_canonical_linux_proof(
        &mut self,
        proof: &crate::CanonicalLinuxProofInputs<'_>,
        boot: &crate::CliBootAssetsInputs<'_>,
        now: chrono::DateTime<Utc>,
    ) -> Result<()> {
        use mvm_core::image_set::{ImageSetRequirement, ImageSetVerification, image_train_lock};
        anyhow::ensure!(
            proof.root.manifest_bytes() == boot.manifest_bytes
                && proof.root.root().manifest_sha256() == boot.manifest_sha256,
            "canonical publisher proof differs from the selected Linux boot manifest"
        );
        let feed = mvm_core::image_set_revocation::verify_image_set_revocations(
            proof.revocations.document(),
            proof.revocations.signature_bundle(),
            now,
            None,
        )?;
        let requirement = ImageSetRequirement::current_train();
        let request = ImageSetVerification::new(
            proof.root.manifest_bytes(),
            proof.root.signature_bundle(),
            &image_train_lock().image_set,
            Path::new(""),
        )
        .require(&requirement)
        .with_revocations(&feed);
        mvm_core::image_set::verify_image_set_root(&request)?;
        // The CLI closure check above already binds the actual kernel inventory
        // to this SAME Linux manifest. Preserve originals, never reserialize.
        for (name, bytes) in [
            (LINUX_SIGNATURE_NAME, proof.root.signature_bundle()),
            (REVOCATIONS_NAME, proof.revocations.document()),
            (
                REVOCATIONS_SIGNATURE_NAME,
                proof.revocations.signature_bundle(),
            ),
        ] {
            self.push(name, ArtifactRole::Other, bytes.to_vec())?;
        }
        Ok(())
    }

    fn push_boot_assets(&mut self, boot: &crate::BootAssetsInputs<'_>, arch: &str) -> Result<()> {
        use mvm_core::arch::GuestArch;
        use mvm_core::image_set::ImageSetManifest;
        use mvm_core::plan::bundle::select_boot_asset_members;

        anyhow::ensure!(
            sha256_hex(boot.manifest_bytes) == boot.manifest_sha256.as_str(),
            "boot image-set manifest does not match its authenticated pin"
        );
        anyhow::ensure!(
            boot.manifest_bytes.len() as u64
                <= mvm_core::plan::bundle::MAX_IMAGE_SET_MANIFEST_BYTES,
            "boot image-set manifest exceeds size limit"
        );
        let arch = match arch {
            "x86_64" => GuestArch::X86_64,
            "aarch64" => GuestArch::Aarch64,
            other => anyhow::bail!("unknown boot-assets architecture {other}"),
        };
        let manifest: ImageSetManifest = serde_json::from_slice(boot.manifest_bytes)?;
        let members = select_boot_asset_members(&manifest, arch)?;
        self.push(
            BOOT_MANIFEST_NAME,
            ArtifactRole::Other,
            boot.manifest_bytes.to_vec(),
        )?;
        for (member, path) in members
            .into_iter()
            .zip([boot.runtime_overlay, boot.initramfs])
        {
            anyhow::ensure!(
                member.artifacts.len() == 1,
                "runtime role must declare one archive"
            );
            let artifact = &member.artifacts[0];
            let name = artifact.name.as_str();
            anyhow::ensure!(
                !self.artifacts.iter().any(|item| item.name == name),
                "duplicate boot artifact name {name}"
            );
            self.push_file(
                name,
                ArtifactRole::Other,
                "boot asset",
                path.to_str().context("boot asset path is not UTF-8")?,
            )?;
            let declared = self
                .artifacts
                .last()
                .context("boot artifact was not declared")?;
            anyhow::ensure!(
                declared.sha256 == artifact.sha256.as_str(),
                "boot asset {name} digest mismatch"
            );
            anyhow::ensure!(
                declared.size_bytes == artifact.size,
                "boot asset {name} size mismatch"
            );
        }
        Ok(())
    }

    fn push_cli_boot_assets(
        &mut self,
        boot: &crate::CliBootAssetsInputs<'_>,
        arch: &str,
    ) -> Result<()> {
        use mvm_core::arch::GuestArch;
        use mvm_core::image_set::ImageSetManifest;
        use mvm_core::plan::bundle::select_cli_boot_kernel;

        anyhow::ensure!(
            boot.manifest_bytes.len() as u64
                <= mvm_core::plan::bundle::MAX_IMAGE_SET_MANIFEST_BYTES
                && sha256_hex(boot.manifest_bytes) == boot.manifest_sha256.as_str(),
            "CLI boot image-set manifest does not match its authenticated pin or size limit"
        );
        anyhow::ensure!(
            boot.runtime.arch == arch && boot.runtime.manifest_artifact == BOOT_MANIFEST_NAME,
            "CLI boot runtime architecture or manifest identity differs from export"
        );
        let arch = match arch {
            "x86_64" => GuestArch::X86_64,
            "aarch64" => GuestArch::Aarch64,
            other => anyhow::bail!("unknown CLI boot architecture {other}"),
        };
        let manifest: ImageSetManifest = serde_json::from_slice(boot.manifest_bytes)?;
        let member = select_cli_boot_kernel(&manifest, arch)?;
        let [kernel] = member.artifacts.as_slice() else {
            anyhow::bail!("CLI boot kernel must declare one artifact");
        };
        let bundled = self
            .artifacts
            .iter()
            .find(|artifact| artifact.role == ArtifactRole::Kernel)
            .context("CLI boot kernel missing")?;
        anyhow::ensure!(
            bundled.sha256 == kernel.sha256.as_str() && bundled.size_bytes == kernel.size,
            "CLI boot kernel differs from the original Linux image set"
        );
        self.push(
            BOOT_MANIFEST_NAME,
            ArtifactRole::Other,
            boot.manifest_bytes.to_vec(),
        )?;
        let mut names = std::collections::BTreeSet::new();
        for (name, path) in boot.artifacts {
            anyhow::ensure!(names.insert(*name), "duplicate CLI boot artifact {name}");
            if let Some(existing) = self
                .artifacts
                .iter()
                .find(|artifact| artifact.name == *name)
            {
                anyhow::ensure!(
                    existing.role == ArtifactRole::Initrd
                        && *name == boot.runtime.initramfs_artifact
                        && existing.sha256 == sha256_file(path)?
                        && existing.size_bytes == std::fs::metadata(path)?.len(),
                    "CLI boot artifact {name} conflicts with an existing artifact"
                );
            } else {
                self.push_file(
                    name,
                    ArtifactRole::Other,
                    "CLI boot asset",
                    path.to_str().context("CLI boot asset path is not UTF-8")?,
                )?;
            }
        }
        Ok(())
    }

    /// Declare an input file, refusing it before it is read when it would put
    /// the bundle past a size cap. The file is hashed here, streaming, and
    /// read again only when the archive is written.
    fn push_file(&mut self, name: &str, role: ArtifactRole, what: &str, path: &str) -> Result<()> {
        let size_bytes = std::fs::metadata(path)
            .with_context(|| format!("reading {what} at {path}"))?
            .len();
        self.budget
            .admit(path, size_bytes)
            .with_context(|| format!("{what} at {path} cannot be bundled"))?;
        let sha256 =
            sha256_file(Path::new(path)).with_context(|| format!("reading {what} at {path}"))?;
        self.declare(
            name,
            role,
            sha256,
            size_bytes,
            BundlePayload::File(PathBuf::from(path)),
        );
        Ok(())
    }

    /// Declare an artifact already in memory.
    fn push(&mut self, name: &str, role: ArtifactRole, bytes: Vec<u8>) -> Result<()> {
        let size_bytes = bytes.len() as u64;
        self.budget
            .admit(name, size_bytes)
            .with_context(|| format!("{name} cannot be bundled"))?;
        let sha256 = sha256_hex(&bytes);
        self.declare(name, role, sha256, size_bytes, BundlePayload::Bytes(bytes));
        Ok(())
    }

    fn declare(
        &mut self,
        name: &str,
        role: ArtifactRole,
        sha256: String,
        size_bytes: u64,
        payload: BundlePayload,
    ) {
        let path = format!("{ARTIFACTS_DIR}/{name}");
        self.artifacts.push(BundleArtifact {
            name: name.to_string(),
            role,
            path: path.clone(),
            sha256,
            size_bytes,
        });
        self.payload.push((path, payload));
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
                )?;
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

/// The declaration members an export carries, in a fixed order so the same
/// inputs always produce the same manifest.
fn declarations_for(
    inputs: &BundleExportInputs<'_>,
    artifacts: &[BundleArtifact],
    verity_protected: bool,
) -> Vec<BundleMember> {
    let mut members = Vec::new();
    if let Some(boot) = &inputs.cli_boot_assets {
        members.push(BundleMember::EmbeddedCliBootAssets(boot.runtime.clone()));
    }
    if inputs.canonical_linux_proof.is_some() {
        members.push(BundleMember::CanonicalLinuxProof(
            mvm_core::plan::bundle::CanonicalLinuxProof {
                manifest_artifact: BOOT_MANIFEST_NAME.into(),
                signature_bundle_artifact: LINUX_SIGNATURE_NAME.into(),
                revocation_document_artifact: REVOCATIONS_NAME.into(),
                revocation_signature_bundle_artifact: REVOCATIONS_SIGNATURE_NAME.into(),
            },
        ));
    }
    if inputs.boot_assets.is_some() {
        members.push(BundleMember::EmbeddedBootAssets {
            manifest_artifact: BOOT_MANIFEST_NAME.to_string(),
        });
    }
    if let Some(cmdline) = inputs.cmdline {
        members.push(BundleMember::KernelCmdline {
            cmdline: cmdline.trim_end().to_string(),
        });
    }
    if let Some(posture) = inputs.posture {
        members.push(BundleMember::SecurityPosture(posture_for(
            posture,
            verity_protected,
        )));
    }
    if let Some(provenance) = &inputs.provenance {
        members.push(BundleMember::BuildProvenance(bind_provenance(
            provenance.clone(),
            artifacts,
        )));
    }
    if let Some(environment) = &inputs.environment {
        members.push(BundleMember::Environment(environment.clone()));
    }
    members
}

/// The lowest schema that carries every member this export seals, so a
/// bundle stays readable by the oldest reader that understands it: 3 for
/// plain declarations, 4 for historical boot assets, 5 for an environment
/// descriptor, 6 for a portable CLI-runtime closure, and 7 for canonical
/// Linux publisher/revocation evidence.
fn schema_for(members: &[BundleMember]) -> u32 {
    members
        .iter()
        .map(BundleMember::minimum_schema_version)
        .max()
        .unwrap_or(BUNDLE_MEMBERS_MIN_SCHEMA)
}

fn posture_for(posture: PostureInputs, verity_protected: bool) -> BundleSecurityPosture {
    BundleSecurityPosture {
        profile: posture.profile,
        verity_protected,
        requires_auth: posture.requires_auth,
        allows_volumes: posture.allows_volumes,
        allows_egress: posture.allows_egress,
    }
}

/// Record the digests of the kernel, rootfs, and initramfs actually sealed.
fn bind_provenance(
    mut provenance: BuildProvenance,
    artifacts: &[BundleArtifact],
) -> BuildProvenance {
    let digest = |role: ArtifactRole| {
        artifacts
            .iter()
            .find(|artifact| artifact.role == role)
            .map(|artifact| artifact.sha256.clone())
    };
    provenance.artifacts.kernel = digest(ArtifactRole::Kernel);
    provenance.artifacts.rootfs = digest(ArtifactRole::Rootfs);
    provenance.artifacts.initramfs = digest(ArtifactRole::Initrd);
    provenance
}

fn manifest_for(
    inputs: &BundleExportInputs<'_>,
    signer: &dyn BundleSigner,
    key_id: &KeyId,
    artifacts: Vec<BundleArtifact>,
    members: Vec<BundleMember>,
    verity: Option<VerityInfo>,
) -> BundleManifest {
    BundleManifest {
        schema_version: schema_for(&members),
        publisher: signer.publisher_id(),
        key_id: key_id.clone(),
        arch: inputs.arch_label.to_string(),
        kernel_version: None,
        profile: inputs.profile.map(str::to_string),
        workload_label: inputs.label.clone(),
        created_at: Utc::now().to_rfc3339(),
        labels: Default::default(),
        artifacts,
        members,
        verity,
        resources: inputs.resources.clone(),
    }
}

/// The archive being written, at an invocation-private `<out>.<pid>.<n>.partial`
/// until it is complete.
///
/// The file and its parent directories are created on the first byte, which
/// the archive writer emits only after the manifest is validated and signed,
/// so a refused export leaves nothing on disk. A failed write removes the
/// partial file; a finished one is renamed over `out`.
struct PartialOutput<'a> {
    out: &'a Path,
    partial: PathBuf,
    file: Option<std::fs::File>,
    written: u64,
}

impl<'a> PartialOutput<'a> {
    fn new(out: &'a Path) -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut partial = out.as_os_str().to_owned();
        partial.push(format!(".{}.{n}.partial", std::process::id()));
        Self {
            out,
            partial: PathBuf::from(partial),
            file: None,
            written: 0,
        }
    }

    fn open(&mut self) -> std::io::Result<&mut std::fs::File> {
        if self.file.is_none() {
            if let Some(parent) = self.out.parent()
                && !parent.as_os_str().is_empty()
            {
                std::fs::create_dir_all(parent)?;
            }
            self.file = Some(
                std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&self.partial)?,
            );
        }
        self.file
            .as_mut()
            .ok_or_else(|| std::io::Error::other("partial bundle file was not opened"))
    }

    /// Promote the archive when `sealed` succeeded; remove it otherwise.
    /// Returns the archive's size.
    fn finish(mut self, sealed: Result<()>) -> Result<u64> {
        let promoted = sealed.and_then(|()| {
            let file = self.open().context("creating the bundle file")?;
            file.sync_all().context("syncing the bundle file")?;
            std::fs::rename(&self.partial, self.out)
                .with_context(|| format!("writing bundle to {}", self.out.display()))
        });
        if promoted.is_err() && self.file.is_some() {
            // Best effort: the error being returned is the one that matters.
            let _ = std::fs::remove_file(&self.partial);
        }
        promoted.map(|()| self.written)
    }
}

impl std::io::Write for PartialOutput<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.open()?.write(buf)?;
        self.written += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self.file.as_mut() {
            Some(file) => file.flush(),
            None => Ok(()),
        }
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
        contents
            .push(KERNEL_NAME, ArtifactRole::Kernel, b"kernel".to_vec())
            .unwrap();

        let entry = &contents.artifacts[0];
        assert_eq!(entry.path, "artifacts/vmlinux");
        assert_eq!(entry.size_bytes, 6);
        assert_eq!(entry.sha256, sha256_hex(b"kernel"));
        assert!(matches!(
            contents.payload.as_slice(),
            [(path, BundlePayload::Bytes(bytes))] if path == "artifacts/vmlinux" && bytes == b"kernel"
        ));
    }

    #[test]
    fn a_file_is_declared_from_a_streaming_hash_and_carried_by_path() {
        let dir = tempfile::tempdir().unwrap();
        let rootfs = dir.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"rootfs").unwrap();
        let mut contents = BundleContents::default();
        contents
            .push_file(
                ROOTFS_NAME,
                ArtifactRole::Rootfs,
                "rootfs",
                rootfs.to_str().unwrap(),
            )
            .unwrap();

        assert_eq!(contents.artifacts[0].sha256, sha256_hex(b"rootfs"));
        assert!(matches!(
            contents.payload.as_slice(),
            [(_, BundlePayload::File(path))] if *path == rootfs
        ));
    }

    #[test]
    fn a_refused_seal_leaves_no_partial_file() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("dist").join("app.mvmpkg");
        let mut output = PartialOutput::new(&out);
        std::io::Write::write_all(&mut output, b"half an archive").unwrap();

        let err = output
            .finish(Err(anyhow::anyhow!("signer refused")))
            .unwrap_err();

        assert!(format!("{err:#}").contains("signer refused"));
        assert!(!out.exists());
        assert!(!dir.path().join("dist").join("app.mvmpkg.partial").exists());
    }

    #[test]
    fn two_exports_to_one_destination_stage_in_distinct_files() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("app.mvmpkg");
        let mut first = PartialOutput::new(&out);
        let mut second = PartialOutput::new(&out);
        assert_ne!(first.partial, second.partial);
        std::io::Write::write_all(&mut first, b"first").unwrap();
        std::io::Write::write_all(&mut second, b"second").unwrap();

        // One invocation failing removes only its own staging file.
        second
            .finish(Err(anyhow::anyhow!("signer refused")))
            .unwrap_err();
        assert_eq!(first.finish(Ok(())).unwrap(), 5);
        assert_eq!(std::fs::read(&out).unwrap(), b"first");
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
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
