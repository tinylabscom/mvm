//! Reading the artifacts, building the manifest, sealing the archive.

use std::io::{Read, Seek};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use chrono::Utc;
use mvm_core::crypto::image_verify::{sha256_file, sha256_reader};
use mvm_core::guest_sidecar::SIDECAR_FILENAME;
use mvm_core::plan::bundle::{
    ARTIFACTS_DIR, ArtifactRole, BUNDLE_MEMBERS_MIN_SCHEMA, BundleArtifact, BundleManifest,
    BundleMember, BundlePayload, BundleSecurityPosture, BundleSizeBudget, KeyId, VerityInfo,
    sha256_hex, write_bundle_to,
};
use mvm_core::plan::types::BuildProvenance;
use mvm_core::util::atomic_io::StagedFile;

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

/// A sealed archive owned by this invocation, not yet visible at its final name.
///
/// Call [`Self::abort`] when validation fails to observe cleanup failures.
/// Dropping it also attempts cleanup, but cannot report errors.
#[derive(Debug)]
#[must_use]
pub struct StagedBundle {
    output: StagedFile,
    exported: ExportedBundle,
    summary: Option<PendingSummary>,
}

#[derive(Debug)]
struct PendingSummary {
    path: PathBuf,
    bytes: Vec<u8>,
}

impl StagedBundle {
    /// Parse the actual sealed archive's first member through the owned file.
    /// The writer puts the manifest first; no artifact payload is scanned.
    pub fn manifest(&mut self) -> Result<BundleManifest> {
        use mvm_core::plan::bundle::MANIFEST_FILENAME;

        const MAX_MANIFEST_BYTES: u64 = 16 * 1024 * 1024;
        let file = self.output.file_mut();
        file.rewind()
            .context("rewinding staged bundle for manifest")?;
        let mut archive = tar::Archive::new(file.take(MAX_MANIFEST_BYTES + 1024));
        let mut entries = archive
            .entries()
            .context("reading staged bundle manifest")?;
        let mut entry = entries
            .next()
            .transpose()
            .context("reading staged bundle manifest header")?
            .with_context(|| format!("{MANIFEST_FILENAME} missing from sealed bundle"))?;
        anyhow::ensure!(
            entry.path()?.as_ref() == Path::new(MANIFEST_FILENAME),
            "{MANIFEST_FILENAME} missing from sealed bundle head"
        );
        anyhow::ensure!(
            entry.size() <= MAX_MANIFEST_BYTES,
            "{MANIFEST_FILENAME} exceeds {MAX_MANIFEST_BYTES}-byte limit"
        );
        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes)?;
        anyhow::ensure!(
            bytes.len() as u64 == entry.size(),
            "truncated {MANIFEST_FILENAME} in sealed bundle"
        );
        serde_json::from_slice(&bytes).context("parsing sealed manifest.json")
    }

    /// Hash the same owned sealed file used by [`Self::manifest`].
    pub fn sha256(&mut self) -> Result<String> {
        let file = self.output.file_mut();
        file.rewind()
            .context("rewinding staged bundle for hashing")?;
        sha256_reader(file).context("hashing staged bundle")
    }

    /// Publish only to the destination captured from the export inputs.
    /// An existing destination is never replaced or removed.
    /// An optional summary is then published create-only; a summary failure
    /// reports that the archive was published and leaves that archive intact.
    pub fn publish(mut self) -> Result<ExportedBundle> {
        if let Err(error) = self.output.publish() {
            return Err(self.abort(error));
        }
        if let Some(summary) = self.summary.take() {
            write_summary(&summary.path, &summary.bytes).with_context(|| {
                format!(
                    "archive was published to {}; debug summary was not published",
                    self.exported.path.display()
                )
            })?;
        }
        Ok(self.exported)
    }

    /// Preserve the original failure while reporting any staging cleanup error.
    /// This never removes a final pathname, even after publication succeeded.
    pub fn abort(mut self, error: anyhow::Error) -> anyhow::Error {
        match self.output.cleanup() {
            Ok(()) => error,
            Err(cleanup) => {
                error.context(format!("owned bundle staging cleanup failed: {cleanup:#}"))
            }
        }
    }
}

/// Seal the artifacts `inputs` names into a `.mvmpkg` signed by `signer`.
///
/// Nothing is written unless the whole bundle could be built: a rootfs with an
/// incomplete dm-verity binding or no guest sidecar is refused first.
/// Manifest, hash and summary-rendering failures happen before publication.
/// Summary publication follows archive publication and never replaces a file.
pub fn export_bundle_with_signer(
    inputs: &BundleExportInputs<'_>,
    signer: &dyn BundleSigner,
) -> Result<ExportedBundle> {
    stage_bundle_with_signer(inputs, signer)?.publish()
}

/// Seal an archive privately for validation before exclusive publication.
///
/// Each artifact file is hashed in one streaming pass and copied into the
/// archive in another, through a fixed buffer, so a multi-GiB rootfs is never
/// held in memory. Its size is checked against the bundle caps before either.
/// Staging is created only once the manifest is signed.
pub fn stage_bundle_with_signer(
    inputs: &BundleExportInputs<'_>,
    signer: &dyn BundleSigner,
) -> Result<StagedBundle> {
    stage_bundle_at(inputs, signer, Utc::now())
}

#[cfg(test)]
fn export_bundle_at(
    inputs: &BundleExportInputs<'_>,
    signer: &dyn BundleSigner,
    now: chrono::DateTime<Utc>,
) -> Result<ExportedBundle> {
    stage_bundle_at(inputs, signer, now)?.publish()
}

fn stage_bundle_at(
    inputs: &BundleExportInputs<'_>,
    signer: &dyn BundleSigner,
    now: chrono::DateTime<Utc>,
) -> Result<StagedBundle> {
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

    for (name, path) in inputs.supplemental_artifacts {
        anyhow::ensure!(
            !name.is_empty()
                && *name != "."
                && *name != ".."
                && !name.contains(['/', '\\', ':', '\0']),
            "supplemental artifact name must be a safe basename: {name:?}"
        );
        anyhow::ensure!(
            ![
                KERNEL_NAME,
                ROOTFS_NAME,
                INITRD_NAME,
                VERITY_NAME,
                SIDECAR_FILENAME,
                BOOT_MANIFEST_NAME,
                LINUX_SIGNATURE_NAME,
                REVOCATIONS_NAME,
                REVOCATIONS_SIGNATURE_NAME,
                mvm_core::registry_pack_boot::APPLICATION_ROOT_HASH_MEMBER_NAME,
                "guest-runtime.tar.gz",
                "guest-runtime.sha256",
                "guest-runtime.bundle",
                "guest-runtime.sha256.bundle",
                "runtime-overlay.ext4",
                "runtime-overlay.verity",
            ]
            .contains(name),
            "reserved supplemental artifact name: {name}"
        );
        // Match existing file inputs' symlink following, but never hash a device or FIFO.
        anyhow::ensure!(
            std::fs::metadata(path)
                .with_context(|| format!("reading supplemental artifact {}", path.display()))?
                .is_file(),
            "supplemental artifact must resolve to a regular file: {}",
            path.display()
        );
        contents.push_file(
            name,
            ArtifactRole::Other,
            "supplemental artifact",
            path.to_str()
                .context("supplemental artifact path is not UTF-8")?,
        )?;
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
    let (output, size_bytes) = output.finish(sealed)?;
    let mut staged = StagedBundle {
        output,
        exported: ExportedBundle {
            path: inputs.out.to_path_buf(),
            size_bytes,
            key_id,
        },
        summary: None,
    };

    let post_validate = (|| {
        if let Some(debug_out) = &inputs.debug_out {
            let archive_sha256 = staged.sha256()?;
            let manifest = staged.manifest()?;
            let summary = debug::render(
                debug_out.format,
                inputs.out,
                debug::ArchiveIdentity {
                    sha256: archive_sha256,
                    size_bytes,
                },
                &manifest,
            )?;
            staged.summary = Some(PendingSummary {
                path: debug_out.path.clone(),
                bytes: summary,
            });
        }
        Ok(())
    })();
    if let Err(error) = post_validate {
        return Err(staged.abort(error));
    }

    Ok(staged)
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
        )?;
        Ok(())
    }

    /// Declare an artifact already in memory.
    fn push(&mut self, name: &str, role: ArtifactRole, bytes: Vec<u8>) -> Result<()> {
        let size_bytes = bytes.len() as u64;
        self.budget
            .admit(name, size_bytes)
            .with_context(|| format!("{name} cannot be bundled"))?;
        let sha256 = sha256_hex(&bytes);
        self.declare(name, role, sha256, size_bytes, BundlePayload::Bytes(bytes))?;
        Ok(())
    }

    fn declare(
        &mut self,
        name: &str,
        role: ArtifactRole,
        sha256: String,
        size_bytes: u64,
        payload: BundlePayload,
    ) -> Result<()> {
        let path = format!("{ARTIFACTS_DIR}/{name}");
        anyhow::ensure!(
            !self
                .artifacts
                .iter()
                .any(|artifact| artifact.name == name || artifact.path == path),
            "duplicate bundle artifact name or path: {name}"
        );
        self.artifacts.push(BundleArtifact {
            name: name.to_string(),
            role,
            path: path.clone(),
            sha256,
            size_bytes,
        });
        self.payload.push((path, payload));
        Ok(())
    }

    /// Carry the dm-verity sidecar and return the binding the manifest records.
    /// Also sign its raw root hash as `Other`: 64 lowercase ASCII hex bytes
    /// followed by one LF. Consumers must not synthesize this member.
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
                let hash = mvm_core::packs::Sha256Hex::new(roothash)?;
                self.push(
                    VERITY_NAME,
                    ArtifactRole::VerityHashSidecar,
                    sidecar.to_vec(),
                )?;
                self.push(
                    mvm_core::registry_pack_boot::APPLICATION_ROOT_HASH_MEMBER_NAME,
                    ArtifactRole::Other,
                    format!("{}\n", hash.as_str()).into_bytes(),
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
    let mut manifest = BundleManifest {
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
    };
    if inputs.local_build {
        mvm_core::plan::bundle::mark_local_build(&mut manifest);
    }
    manifest
}

/// A lazy private staging writer.
///
/// The file and its parent directories are created on the first byte, which
/// the archive writer emits only after the manifest is validated and signed,
/// so a refused export leaves nothing on disk. A failed write removes the
/// private file; a finished one remains private for post-seal validation.
struct PartialOutput<'a> {
    out: &'a Path,
    file: Option<StagedFile>,
    written: u64,
}

impl<'a> PartialOutput<'a> {
    fn new(out: &'a Path) -> Self {
        Self {
            out,
            file: None,
            written: 0,
        }
    }

    fn open(&mut self) -> std::io::Result<&mut std::fs::File> {
        if self.file.is_none() {
            self.file = Some(StagedFile::new(self.out).map_err(std::io::Error::other)?);
        }
        self.file
            .as_mut()
            .map(StagedFile::file_mut)
            .ok_or_else(|| std::io::Error::other("partial bundle file was not opened"))
    }

    /// Return the owned sealed file, or explicitly clean up a failed write.
    fn finish(mut self, sealed: Result<()>) -> Result<(StagedFile, u64)> {
        let sealed = sealed.and_then(|()| {
            let file = self.open().context("creating the bundle file")?;
            file.sync_all().context("syncing the bundle file")
        });
        if let Err(error) = sealed {
            return Err(match self.file.as_mut().map(StagedFile::cleanup) {
                Some(Err(cleanup)) => {
                    error.context(format!("owned bundle staging cleanup failed: {cleanup:#}"))
                }
                Some(Ok(())) | None => error,
            });
        }
        Ok((
            self.file.context("sealed bundle file was not opened")?,
            self.written,
        ))
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
            Some(file) => file.file_mut().flush(),
            None => Ok(()),
        }
    }
}

fn write_summary(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating parent dir {}", parent.display()))?;
    }
    // Let the filesystem decide whether names alias. Exclusive creation also
    // refuses case-folded names and links without replacing their entries.
    mvm_core::util::atomic_io::atomic_write_new(path, bytes)
        .with_context(|| format!("writing bundle debug summary to {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    struct TestSigner(ed25519_dalek::SigningKey);

    impl BundleSigner for TestSigner {
        fn publisher_id(&self) -> String {
            "host:test".to_string()
        }

        fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
            self.0.verifying_key()
        }

        fn sign(&self, canonical_manifest: &[u8]) -> Result<[u8; 64]> {
            use ed25519_dalek::Signer as _;
            Ok(self.0.sign(canonical_manifest).to_bytes())
        }
    }

    #[test]
    fn local_build_inputs_stamp_the_signed_origin_label() {
        let inputs = BundleExportInputs::new(
            "/tmp/kernel",
            "/tmp/rootfs",
            "x86_64-linux",
            Path::new("/tmp/app.mvmpkg"),
        )
        .local_build();
        let signer = TestSigner(ed25519_dalek::SigningKey::from_bytes(&[7; 32]));
        let manifest = manifest_for(
            &inputs,
            &signer,
            &signer.key_id(),
            Vec::new(),
            Vec::new(),
            None,
        );
        assert_eq!(
            manifest
                .labels
                .get(mvm_core::plan::bundle::BUNDLE_ORIGIN_LABEL)
                .map(String::as_str),
            Some(mvm_core::plan::bundle::LOCAL_BUILD_ORIGIN)
        );
    }

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
        assert_eq!(std::fs::read_dir(out.parent().unwrap()).unwrap().count(), 0);
    }

    fn raw_staged(out: &Path, bytes: &[u8]) -> StagedBundle {
        let mut output = StagedFile::new(out).unwrap();
        output.file_mut().write_all(bytes).unwrap();
        StagedBundle {
            output,
            exported: ExportedBundle {
                path: out.to_path_buf(),
                size_bytes: bytes.len() as u64,
                key_id: KeyId("test".into()),
            },
            summary: None,
        }
    }

    #[test]
    fn a_destination_created_after_staging_is_preserved_and_our_staging_is_removed() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("app.mvmpkg");
        let staged = raw_staged(&out, b"mine");
        std::fs::write(&out, b"theirs").unwrap();

        staged.publish().unwrap_err();

        assert_eq!(std::fs::read(&out).unwrap(), b"theirs");
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn abort_preserves_the_failure_and_foreign_destination_and_removes_only_our_staging() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("app.mvmpkg");
        let staged = raw_staged(&out, b"mine");
        std::fs::write(&out, b"theirs").unwrap();

        let error = staged.abort(anyhow::anyhow!("hash failed"));

        assert_eq!(error.to_string(), "hash failed");
        assert_eq!(std::fs::read(&out).unwrap(), b"theirs");
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    fn archive_entry(path: &str, bytes: &[u8]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append_data(&mut header, path, bytes).unwrap();
        builder.into_inner().unwrap()
    }

    #[test]
    fn an_archive_without_a_manifest_is_not_taken_as_sealed() {
        use mvm_core::plan::bundle::MANIFEST_FILENAME;

        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("bundle");
        let archive = archive_entry("artifacts/vmlinux", b"k");
        let mut staged = raw_staged(&out, &archive);
        let error = staged.manifest().unwrap_err();
        assert!(error.to_string().contains(MANIFEST_FILENAME));
        let error = staged.abort(error);
        assert!(error.to_string().contains(MANIFEST_FILENAME));
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[test]
    fn malformed_empty_truncated_and_oversized_manifests_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("bundle");
        for archive in [
            Vec::new(),
            archive_entry("manifest.json", b"not JSON"),
            archive_entry("manifest.json", &vec![b' '; 16 * 1024 * 1024 + 1]),
        ] {
            let mut staged = raw_staged(&out, &archive);
            let error = staged.manifest().unwrap_err();
            staged.abort(error);
            assert!(!out.exists());
        }
        let mut archive = archive_entry("manifest.json", b"{}");
        archive.truncate(513);
        let mut staged = raw_staged(&out, &archive);
        assert!(staged.manifest().is_err());
        drop(staged);
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[test]
    fn hash_reads_the_owned_file_and_reports_read_failures() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("bundle");
        let mut staged = raw_staged(&out, b"sealed");
        std::fs::write(&out, b"foreign").unwrap();
        assert_eq!(staged.sha256().unwrap(), sha256_hex(b"sealed"));
        assert_eq!(staged.sha256().unwrap(), sha256_hex(b"sealed"));
        let original = std::mem::replace(
            staged.output.file_mut(),
            std::fs::File::open(dir.path()).unwrap(),
        );
        assert!(staged.sha256().is_err());
        *staged.output.file_mut() = original;
        staged.abort(anyhow::anyhow!("validation failed"));
        assert_eq!(std::fs::read(&out).unwrap(), b"foreign");
    }

    #[test]
    fn abort_and_interrupted_sealing_surface_cleanup_failure_and_preserve_original_error() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("bundle");
        let staged = raw_staged(&out, b"sealed");
        let namespace = std::fs::read_dir(dir.path())
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        std::fs::write(namespace.join("foreign"), b"preserved").unwrap();
        let error = staged.abort(anyhow::anyhow!("revision validation failed"));
        assert!(format!("{error:#}").contains("revision validation failed"));
        assert!(error.to_string().contains("cleanup"));
        assert_eq!(
            std::fs::read(namespace.join("foreign")).unwrap(),
            b"preserved"
        );
        assert!(!out.exists());

        let other = dir.path().join("other");
        let mut output = PartialOutput::new(&other);
        output.write_all(b"interrupted").unwrap();
        let namespace = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| path != &namespace)
            .unwrap();
        std::fs::write(namespace.join("foreign"), b"preserved").unwrap();
        let error = output
            .finish(Err(anyhow::anyhow!("write interrupted")))
            .unwrap_err();
        assert!(format!("{error:#}").contains("write interrupted"));
        assert!(error.to_string().contains("cleanup"));
        assert_eq!(
            std::fs::read(namespace.join("foreign")).unwrap(),
            b"preserved"
        );
        assert!(!other.exists());
    }

    #[test]
    fn summary_alias_and_parent_failure_preserve_the_archive() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("bundle");
        std::fs::write(&archive, b"preserved").unwrap();
        let alias = dir.path().join(".").join("bundle");
        assert!(write_summary(&alias, b"summary").is_err());
        assert_eq!(std::fs::read(&archive).unwrap(), b"preserved");
        let not_directory = dir.path().join("file");
        std::fs::write(&not_directory, b"preserved").unwrap();
        assert!(write_summary(&not_directory.join("summary"), b"summary").is_err());
        assert_eq!(std::fs::read(&not_directory).unwrap(), b"preserved");
    }

    #[cfg(unix)]
    #[test]
    fn summary_creation_refuses_links_to_the_archive() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("bundle");
        std::fs::write(&archive, b"preserved").unwrap();
        let symlink = dir.path().join("summary-symlink");
        std::os::unix::fs::symlink(&archive, &symlink).unwrap();
        assert!(write_summary(&symlink, b"summary").is_err());
        assert!(std::fs::symlink_metadata(&symlink).unwrap().is_symlink());
        let hardlink = dir.path().join("summary-hardlink");
        std::fs::hard_link(&archive, &hardlink).unwrap();
        assert!(write_summary(&hardlink, b"summary").is_err());
        assert_eq!(std::fs::read(&archive).unwrap(), b"preserved");
        assert_eq!(std::fs::read(&symlink).unwrap(), b"preserved");
        assert_eq!(std::fs::read(&hardlink).unwrap(), b"preserved");
    }

    #[cfg(unix)]
    #[test]
    fn two_exports_to_one_destination_stage_in_distinct_files() {
        use std::os::unix::fs::MetadataExt;

        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("app.mvmpkg");
        let mut first = PartialOutput::new(&out);
        let mut second = PartialOutput::new(&out);
        first.write_all(b"first").unwrap();
        second.write_all(b"second").unwrap();
        let first_identity = first.open().unwrap().metadata().unwrap();
        let second_identity = second.open().unwrap().metadata().unwrap();
        assert_ne!(
            (first_identity.dev(), first_identity.ino()),
            (second_identity.dev(), second_identity.ino()),
        );
        assert!(!out.exists());

        // One invocation failing removes only its own staging file.
        second
            .finish(Err(anyhow::anyhow!("signer refused")))
            .unwrap_err();
        let (mut owned, size) = first.finish(Ok(())).unwrap();
        assert_eq!(size, 5);
        owned.file_mut().rewind().unwrap();
        let mut bytes = Vec::new();
        owned.file_mut().read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"first");
        owned.publish().unwrap();
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
