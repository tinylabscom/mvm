//! Authored Yocto rootfs archives are inputs, not pre-verified MVM images.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use flate2::read::GzDecoder;
use mvm_contract::pack_spec::PackTarget;
use mvm_fs::oci::unpack::{SetidPolicy, UnpackOptions, UnpackReport, XattrPolicy, unpack_layer};
use serde::Deserialize;

use crate::oci_runtime_inject::{ImageRuntimeConfig, MvmRuntimeBinaries};
use crate::run_image::{InjectAndMaterializeRequest, RootfsMaterializationPolicy};

const MAX_INPUT_MANIFEST_BYTES: u64 = 64 * 1024;
const MAX_ARCHIVE_BYTES: u64 = 8 * 1024 * 1024 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InputManifest {
    schema_version: u32,
    target: PackTarget,
    machine: String,
    layers: BTreeMap<String, String>,
    rootfs_archive_sha256: String,
}

/// Snapshot of a pinned producer archive and its separately supplied build metadata.
pub struct YoctoInput {
    archive: PathBuf,
    manifest: PathBuf,
    manifest_digest: String,
    archive_digest: String,
    machine: String,
}

impl YoctoInput {
    /// Capture exact input bytes before using them; refuse an archive not named by the manifest.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed or incompatible metadata, I/O failures, or a digest mismatch.
    pub fn stage(
        manifest_path: &Path,
        archive_path: &Path,
        target: PackTarget,
        work: &Path,
    ) -> Result<Self> {
        let metadata = fs::metadata(manifest_path)
            .with_context(|| format!("stat Yocto input manifest {}", manifest_path.display()))?;
        ensure!(
            metadata.is_file() && metadata.len() <= MAX_INPUT_MANIFEST_BYTES,
            "Yocto input manifest must be a regular file at most {MAX_INPUT_MANIFEST_BYTES} bytes"
        );
        let bytes = fs::read(manifest_path)
            .with_context(|| format!("read Yocto input manifest {}", manifest_path.display()))?;
        let manifest: InputManifest =
            serde_json::from_slice(&bytes).context("parse Yocto input manifest")?;
        validate_manifest(&manifest, target)?;

        let metadata = fs::metadata(archive_path)
            .with_context(|| format!("stat Yocto rootfs archive {}", archive_path.display()))?;
        ensure!(
            metadata.is_file() && (1..=MAX_ARCHIVE_BYTES).contains(&metadata.len()),
            "Yocto rootfs archive must be a regular file between 1 and {MAX_ARCHIVE_BYTES} bytes"
        );
        let archive = work.join("yocto-rootfs.tar.gz");
        fs::copy(archive_path, &archive)
            .with_context(|| format!("stage Yocto archive {}", archive_path.display()))?;
        let archive_digest = mvm_core::crypto::image_verify::sha256_file(&archive)?;
        ensure!(
            archive_digest == manifest.rootfs_archive_sha256,
            "Yocto rootfs archive does not match the input manifest digest"
        );
        let manifest_path = work.join("yocto-inputs.json");
        fs::write(&manifest_path, &bytes).context("stage Yocto input manifest")?;
        Ok(Self {
            archive,
            manifest: manifest_path,
            manifest_digest: mvm_core::plan::bundle::sha256_hex(&bytes),
            archive_digest,
            machine: manifest.machine,
        })
    }

    /// Unpack the retained archive with bounded, path-safe OCI layer handling.
    ///
    /// # Errors
    ///
    /// Returns an error for unsafe members, decompression failures, or changed source bytes.
    pub fn unpack(&self, root: &Path) -> Result<UnpackReport> {
        fs::create_dir(root).with_context(|| format!("create Yocto root {}", root.display()))?;
        let archive = File::open(&self.archive).context("open retained Yocto archive")?;
        let policy = UnpackOptions {
            setid_policy: SetidPolicy::RefuseUnsigned,
            xattr_policy: XattrPolicy::DropAll,
            ..UnpackOptions::default()
        };
        let report = unpack_layer(GzDecoder::new(archive), root, &policy, None)
            .context("unpack Yocto rootfs with bounded path validation")?;
        ensure!(
            report.refused.is_empty(),
            "Yocto rootfs archive contains refused entries: {:?}",
            report.refused
        );
        ensure!(
            report.xattrs_dropped == 0 && report.whiteouts_applied == 0,
            "Yocto rootfs archive contains unsupported xattrs or OCI whiteouts"
        );
        let current = mvm_core::crypto::image_verify::sha256_file(&self.archive)?;
        ensure!(
            current == self.archive_digest,
            "retained Yocto rootfs archive changed while unpacking"
        );
        Ok(report)
    }

    /// Build a sealed MVM rootfs from the producer's exact archive bytes.
    ///
    /// # Errors
    ///
    /// Refuses unsafe archive entries, unavailable guest binaries, unsupported
    /// rootfs nodes, or any failure to emit a complete verity-protected image.
    pub fn materialize(
        &self,
        cache_root: &Path,
        output: &Path,
        entrypoint: &ImageRuntimeConfig,
        binaries: &MvmRuntimeBinaries,
    ) -> Result<()> {
        ensure!(
            output.file_name().is_some_and(|name| name == "rootfs.ext4"),
            "Yocto materialization output must be named rootfs.ext4"
        );
        let parent = output
            .parent()
            .context("Yocto rootfs output has no parent")?;
        fs::create_dir_all(parent).context("create Yocto materialization directory")?;
        let root = parent.join("yocto-unpacked");
        let report = self.unpack(&root)?;
        let mut owners = mvm_fs::ownership::OwnerTable::new();
        owners.absorb(&report.ownership);
        crate::run_image::inject_and_materialize(
            InjectAndMaterializeRequest::builder(cache_root, &root, output, &self.machine)
                .entrypoint(Some(entrypoint))
                .runtime_binaries(Some(binaries))
                .materialization_policy(RootfsMaterializationPolicy::InProcessOnly)
                .sealed(true)
                .deferred_nodes(report.deferred_nodes)
                .owners(owners)
                .build(),
        )
        .context("inject MVM runtime and seal Yocto rootfs")
    }

    /// The retained manifest bytes that must be included in a signed pack.
    pub fn manifest_path(&self) -> &Path {
        &self.manifest
    }

    /// SHA-256 of the retained, parsed input manifest.
    pub fn manifest_digest(&self) -> &str {
        &self.manifest_digest
    }

    /// SHA-256 of the retained root filesystem archive.
    pub fn archive_digest(&self) -> &str {
        &self.archive_digest
    }

    /// Yocto machine declared by the producer.
    pub fn machine(&self) -> &str {
        &self.machine
    }
}

fn validate_manifest(manifest: &InputManifest, target: PackTarget) -> Result<()> {
    ensure!(
        manifest.schema_version == 1,
        "unsupported Yocto input manifest version"
    );
    ensure!(
        manifest.target == target,
        "Yocto image target differs from pack target"
    );
    ensure!(
        !manifest.machine.is_empty()
            && manifest
                .machine
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.')),
        "invalid Yocto machine"
    );
    ensure!(
        !manifest.layers.is_empty(),
        "Yocto input has no pinned layers"
    );
    for (name, revision) in &manifest.layers {
        ensure!(
            !name.is_empty()
                && name
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.'))
                && matches!(revision.len(), 40 | 64)
                && is_lower_hex(revision),
            "Yocto input has an invalid layer name or revision"
        );
    }
    ensure!(
        manifest.rootfs_archive_sha256.len() == 64 && is_lower_hex(&manifest.rootfs_archive_sha256),
        "Yocto rootfs archive digest must be 64 lowercase hex characters"
    );
    Ok(())
}

fn is_lower_hex(s: &str) -> bool {
    s.bytes()
        .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_binaries(dir: &Path) -> MvmRuntimeBinaries {
        let write = |name: &str| {
            let path = dir.join(name);
            fs::write(&path, name).unwrap();
            path
        };
        MvmRuntimeBinaries {
            agent: write("mvm-guest-agent"),
            netinit: write("mvm-guest-netinit"),
            egress_client: write("mvm-egress-client"),
            entrypoint_runner: write("mvm-oci-entrypoint"),
        }
    }

    fn archive_with_hello_mode(mode: u32) -> Vec<u8> {
        let gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        let mut tar = tar::Builder::new(gzip);
        let mut header = tar::Header::new_gnu();
        header.set_size(6);
        header.set_mode(mode);
        header.set_cksum();
        tar.append_data(&mut header, "srv/app/hello", b"hello\n".as_slice())
            .unwrap();
        tar.into_inner().unwrap().finish().unwrap()
    }

    fn archive_with_hello() -> Vec<u8> {
        archive_with_hello_mode(0o755)
    }

    fn manifest(digest: &str) -> String {
        format!(
            r#"{{"schema_version":1,"target":"aarch64-linux","machine":"qemuarm64","layers":{{"poky":"{}"}},"rootfs_archive_sha256":"{digest}"}}"#,
            "a".repeat(40)
        )
    }

    #[test]
    fn refuses_unpinned_or_wrong_target_inputs() {
        let manifest: InputManifest = serde_json::from_str(&manifest(&"b".repeat(64))).unwrap();
        assert!(validate_manifest(&manifest, PackTarget::Aarch64Linux).is_ok());
        assert!(validate_manifest(&manifest, PackTarget::X86_64Linux).is_err());
        let mut missing = manifest;
        missing.layers.clear();
        assert!(validate_manifest(&missing, PackTarget::Aarch64Linux).is_err());
    }

    #[test]
    fn altered_archive_refuses_before_unpack() {
        let tmp = tempfile::tempdir().unwrap();
        let archive = tmp.path().join("rootfs.tar.gz");
        fs::write(&archive, b"not the pinned archive").unwrap();
        let inputs = tmp.path().join("inputs.json");
        fs::write(&inputs, manifest(&"b".repeat(64))).unwrap();
        let work = tmp.path().join("work");
        fs::create_dir(&work).unwrap();
        let err = YoctoInput::stage(&inputs, &archive, PackTarget::Aarch64Linux, &work)
            .err()
            .unwrap();
        assert!(err.to_string().contains("does not match"), "{err:#}");
        assert!(!work.join("yocto-inputs.json").exists());
    }

    #[test]
    fn a_directory_cannot_be_used_as_a_rootfs_archive() {
        let tmp = tempfile::tempdir().unwrap();
        let inputs = tmp.path().join("inputs.json");
        fs::write(&inputs, manifest(&"b".repeat(64))).unwrap();
        let work = tmp.path().join("work");
        fs::create_dir(&work).unwrap();
        let err = YoctoInput::stage(&inputs, tmp.path(), PackTarget::Aarch64Linux, &work)
            .err()
            .unwrap();
        assert!(err.to_string().contains("regular file"), "{err:#}");
    }

    #[test]
    fn unsigned_setuid_member_is_refused_before_materialization() {
        let tmp = tempfile::tempdir().unwrap();
        let bytes = archive_with_hello_mode(0o4755);
        let archive = tmp.path().join("rootfs.tar.gz");
        fs::write(&archive, &bytes).unwrap();
        let manifest_path = tmp.path().join("inputs.json");
        fs::write(
            &manifest_path,
            manifest(&mvm_core::plan::bundle::sha256_hex(&bytes)),
        )
        .unwrap();
        let work = tmp.path().join("work");
        fs::create_dir(&work).unwrap();
        let input = YoctoInput::stage(&manifest_path, &archive, PackTarget::Aarch64Linux, &work)
            .expect("input is pinned");

        let err = input.unpack(&work.join("root")).err().unwrap();
        assert!(err.to_string().contains("refused entries"), "{err:#}");
    }

    #[test]
    fn pinned_archive_is_staged_and_unpacked_in_a_private_tree() {
        let tmp = tempfile::tempdir().unwrap();
        let archive = tmp.path().join("rootfs.tar.gz");
        let bytes = archive_with_hello();
        fs::write(&archive, &bytes).unwrap();
        let inputs = tmp.path().join("inputs.json");
        let digest = mvm_core::plan::bundle::sha256_hex(&bytes);
        fs::write(&inputs, manifest(&digest)).unwrap();
        let work = tmp.path().join("work");
        fs::create_dir(&work).unwrap();

        let input = YoctoInput::stage(&inputs, &archive, PackTarget::Aarch64Linux, &work)
            .expect("pin and snapshot inputs");
        fs::write(&archive, b"later source changes").unwrap();
        let report = input.unpack(&work.join("root")).expect("unpack held bytes");
        assert!(report.refused.is_empty());
        assert_eq!(
            fs::read(work.join("root/srv/app/hello")).unwrap(),
            b"hello\n"
        );
        assert_eq!(input.archive_digest, digest);
    }

    #[test]
    fn pinned_archive_materializes_with_a_matching_verity_pair() {
        let tmp = tempfile::tempdir().unwrap();
        let archive = tmp.path().join("rootfs.tar.gz");
        let bytes = archive_with_hello();
        fs::write(&archive, &bytes).unwrap();
        let inputs = tmp.path().join("inputs.json");
        fs::write(
            &inputs,
            manifest(&mvm_core::plan::bundle::sha256_hex(&bytes)),
        )
        .unwrap();
        let work = tmp.path().join("work");
        fs::create_dir(&work).unwrap();
        let input = YoctoInput::stage(&inputs, &archive, PackTarget::Aarch64Linux, &work)
            .expect("snapshot pinned image");
        let output = work.join("materialized/rootfs.ext4");
        let entrypoint = ImageRuntimeConfig {
            argv: vec!["/srv/app/hello".into()],
            env: Vec::new(),
            working_dir: None,
        };
        let binaries = fake_binaries(tmp.path());

        input
            .materialize(tmp.path(), &output, &entrypoint, &binaries)
            .expect("materialize and seal");

        let rootfs = fs::read(&output).unwrap();
        let pair = mvm_fs::ext4::verity::format(&rootfs, &[0u8; 32], 4096, 4096);
        assert_eq!(
            fs::read(output.with_extension("verity")).unwrap(),
            pair.hash_tree
        );
        assert_eq!(
            fs::read_to_string(output.with_extension("roothash"))
                .unwrap()
                .trim(),
            mvm_fs::ext4::verity::to_hex(&pair.root_hash)
        );
        let sidecar = crate::builder_vm::GuestSidecar::read_from_dir(output.parent().unwrap())
            .unwrap()
            .unwrap();
        assert!(sidecar.sealed);
        assert_eq!(sidecar.entrypoint_argv, entrypoint.argv);
    }

    #[test]
    #[ignore = "requires a native Yocto archive and its pinned inputs"]
    fn native_archive_materializes_without_a_builder_vm() {
        let archive = PathBuf::from(
            std::env::var_os("MVM_YOCTO_TEST_ARCHIVE").expect("set MVM_YOCTO_TEST_ARCHIVE"),
        );
        let inputs = PathBuf::from(
            std::env::var_os("MVM_YOCTO_TEST_INPUTS").expect("set MVM_YOCTO_TEST_INPUTS"),
        );
        let tmp = tempfile::tempdir().unwrap();
        let work = tmp.path().join("work");
        fs::create_dir(&work).unwrap();
        let input = YoctoInput::stage(&inputs, &archive, PackTarget::Aarch64Linux, &work)
            .expect("pin the real Yocto output");
        let output = work.join("materialized/rootfs.ext4");
        let entrypoint = ImageRuntimeConfig {
            argv: vec!["/srv/app/hello".into()],
            env: Vec::new(),
            working_dir: Some("/srv/app".into()),
        };
        input
            .materialize(tmp.path(), &output, &entrypoint, &fake_binaries(tmp.path()))
            .expect("import, inject test binaries, and seal");
        let rootfs = fs::read(&output).unwrap();
        let pair = mvm_fs::ext4::verity::format(&rootfs, &[0u8; 32], 4096, 4096);
        assert_eq!(
            fs::read(output.with_extension("verity")).unwrap(),
            pair.hash_tree
        );
        assert_eq!(
            fs::read_to_string(output.with_extension("roothash"))
                .unwrap()
                .trim(),
            mvm_fs::ext4::verity::to_hex(&pair.root_hash)
        );
        eprintln!(
            "Yocto import: rootfs={} verity={} bytes",
            rootfs.len(),
            pair.hash_tree.len()
        );
    }
}
