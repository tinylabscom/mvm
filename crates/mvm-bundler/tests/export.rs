//! Exports a small bundle from files on disk and reads it back through the
//! verifier a consumer would use.

use std::path::{Path, PathBuf};

use ed25519_dalek::{SigningKey, VerifyingKey};
use mvm_bundler::{
    BundleExportInputs, BundleSigner, DebugOutput, ExportedBundle, export_bundle_with_signer,
};
use mvm_core::plan::bundle::{
    ArtifactRole, BundleVerifyError, KeyId, TrustStore, VerifiedBundle, bundle_sha256,
    key_id_from_pubkey, read_and_verify_bundle,
};

const KERNEL: &[u8] = b"kernel bytes";
const ROOTFS: &[u8] = b"rootfs bytes";
const INITRD: &[u8] = b"initrd bytes";
const VERITY: &[u8] = b"verity hash tree";
const SIDECAR: &[u8] = br#"{"accessible":false}"#;
const ROOTHASH: &str = "abababababababababababababababababababababababababababababababab";

struct TestSigner {
    key: SigningKey,
}

impl TestSigner {
    fn new(seed: u8) -> Self {
        Self {
            key: SigningKey::from_bytes(&[seed; 32]),
        }
    }
}

impl BundleSigner for TestSigner {
    fn publisher_id(&self) -> String {
        "test:publisher".to_string()
    }

    fn signing_key(&self) -> &SigningKey {
        &self.key
    }
}

/// A signer that names a key other than the one it signs with.
struct MislabelledSigner {
    key: SigningKey,
    claimed: KeyId,
}

impl BundleSigner for MislabelledSigner {
    fn publisher_id(&self) -> String {
        "test:mislabelled".to_string()
    }

    fn signing_key(&self) -> &SigningKey {
        &self.key
    }

    fn key_id(&self) -> KeyId {
        self.claimed.clone()
    }
}

/// Trusts exactly one publisher key.
struct OneKey(VerifyingKey);

impl TrustStore for OneKey {
    fn lookup(&self, key_id: &KeyId) -> Option<VerifyingKey> {
        (*key_id == key_id_from_pubkey(&self.0)).then_some(self.0)
    }
}

/// A built template's artifact directory, as `mvmctl bundle export` finds it.
struct Slot {
    dir: tempfile::TempDir,
}

impl Slot {
    fn new() -> Self {
        let slot = Self {
            dir: tempfile::tempdir().expect("tempdir"),
        };
        slot.write("vmlinux", KERNEL);
        slot.write("rootfs.ext4", ROOTFS);
        slot.write("mvm-meta.json", SIDECAR);
        slot
    }

    fn write(&self, name: &str, bytes: &[u8]) {
        std::fs::write(self.dir.path().join(name), bytes).expect("write artifact");
    }

    fn path(&self, name: &str) -> String {
        self.dir.path().join(name).to_string_lossy().into_owned()
    }

    fn out(&self) -> PathBuf {
        self.dir.path().join("out").join("app.mvmpkg")
    }
}

fn verify(out: &Path, signer: &TestSigner) -> Result<VerifiedBundle, BundleVerifyError> {
    let archive = std::fs::read(out).expect("read exported bundle");
    read_and_verify_bundle(&archive, &OneKey(signer.key.verifying_key()))
}

/// A refused export leaves neither the archive nor the directory it would
/// have created for it.
fn assert_nothing_written(out: &Path) {
    assert!(!out.exists(), "{} was written", out.display());
    let parent = out.parent().expect("out has a parent");
    assert!(!parent.exists(), "{} was created", parent.display());
}

fn export(inputs: &BundleExportInputs<'_>, signer: &TestSigner) -> ExportedBundle {
    export_bundle_with_signer(inputs, signer).expect("export")
}

#[test]
fn an_exported_bundle_verifies_under_the_signers_key() {
    let slot = Slot::new();
    let (vmlinux, rootfs, out) = (slot.path("vmlinux"), slot.path("rootfs.ext4"), slot.out());
    let signer = TestSigner::new(7);
    let inputs = BundleExportInputs::new(&vmlinux, &rootfs, "aarch64", &out)
        .profile("minimal")
        .resources(2, 512)
        .label("app");

    let exported = export(&inputs, &signer);

    let bundle = verify(&out, &signer).expect("the export verifies");
    assert_eq!(bundle.key_id, exported.key_id);
    assert_eq!(bundle.artifacts["artifacts/vmlinux"], KERNEL);
    assert_eq!(bundle.artifacts["artifacts/rootfs.ext4"], ROOTFS);
    assert_eq!(bundle.artifacts["artifacts/mvm-meta.json"], SIDECAR);

    let manifest = &bundle.manifest;
    assert_eq!(manifest.publisher, "test:publisher");
    assert_eq!(manifest.arch, "aarch64");
    assert_eq!(manifest.profile.as_deref(), Some("minimal"));
    assert_eq!(manifest.workload_label.as_deref(), Some("app"));
    assert!(manifest.verity.is_none());
    assert!(manifest.find_by_role(&ArtifactRole::Initrd).is_none());
    let resources = manifest.resources.as_ref().expect("resources recorded");
    assert_eq!((resources.vcpus, resources.mem_mib), (2, 512));
    let sidecar = manifest.find_by_name("mvm-meta.json").expect("sidecar");
    assert_eq!(sidecar.role, ArtifactRole::Other);
}

#[test]
fn an_export_with_no_profile_or_resources_records_neither() {
    let slot = Slot::new();
    let (vmlinux, rootfs, out) = (slot.path("vmlinux"), slot.path("rootfs.ext4"), slot.out());
    let signer = TestSigner::new(7);

    export(
        &BundleExportInputs::new(&vmlinux, &rootfs, "aarch64", &out),
        &signer,
    );

    let manifest = verify(&out, &signer).expect("the export verifies").manifest;
    assert!(manifest.profile.is_none());
    assert!(manifest.resources.is_none());
    assert!(manifest.workload_label.is_none());
}

#[test]
fn the_report_describes_the_file_that_was_written() {
    let slot = Slot::new();
    let (vmlinux, rootfs, out) = (slot.path("vmlinux"), slot.path("rootfs.ext4"), slot.out());
    let signer = TestSigner::new(7);

    let exported = export(
        &BundleExportInputs::new(&vmlinux, &rootfs, "aarch64", &out),
        &signer,
    );

    assert_eq!(exported.path, out);
    assert_eq!(
        exported.size_bytes,
        std::fs::metadata(&out).expect("stat").len()
    );
    assert_eq!(
        exported.key_id,
        key_id_from_pubkey(&signer.key.verifying_key())
    );
}

#[test]
fn an_initrd_and_a_verity_binding_are_carried() {
    let slot = Slot::new();
    slot.write("initrd", INITRD);
    let (vmlinux, rootfs, initrd, out) = (
        slot.path("vmlinux"),
        slot.path("rootfs.ext4"),
        slot.path("initrd"),
        slot.out(),
    );
    let signer = TestSigner::new(7);
    let inputs = BundleExportInputs::new(&vmlinux, &rootfs, "x86_64", &out)
        .initrd(&initrd)
        .verity(VERITY, ROOTHASH);

    export(&inputs, &signer);

    let bundle = verify(&out, &signer).expect("the export verifies");
    assert_eq!(bundle.artifacts["artifacts/initrd"], INITRD);
    assert_eq!(bundle.artifacts["artifacts/rootfs.verity"], VERITY);
    let verity = bundle.manifest.verity.as_ref().expect("verity recorded");
    assert_eq!(verity.roothash, ROOTHASH);
    assert_eq!(verity.sidecar_artifact, "rootfs.verity");
    let sidecar = bundle
        .manifest
        .find_by_role(&ArtifactRole::VerityHashSidecar)
        .expect("verity artifact");
    assert_eq!(sidecar.name, "rootfs.verity");
}

#[test]
fn half_a_verity_binding_is_refused_and_writes_nothing() {
    let slot = Slot::new();
    let (vmlinux, rootfs, out) = (slot.path("vmlinux"), slot.path("rootfs.ext4"), slot.out());
    let signer = TestSigner::new(7);

    let mut sidecar_only = BundleExportInputs::new(&vmlinux, &rootfs, "aarch64", &out);
    sidecar_only.verity_bytes = Some(VERITY);
    let mut roothash_only = BundleExportInputs::new(&vmlinux, &rootfs, "aarch64", &out);
    roothash_only.roothash = Some(ROOTHASH);

    for inputs in [sidecar_only, roothash_only] {
        let err = export_bundle_with_signer(&inputs, &signer).expect_err("refused");
        assert!(
            err.to_string().contains("incomplete dm-verity binding"),
            "{err:#}"
        );
        assert_nothing_written(&out);
    }
}

#[test]
fn a_rootfs_without_its_sidecar_is_refused_and_writes_nothing() {
    let slot = Slot::new();
    std::fs::remove_file(slot.dir.path().join("mvm-meta.json")).expect("remove sidecar");
    let (vmlinux, rootfs, out) = (slot.path("vmlinux"), slot.path("rootfs.ext4"), slot.out());

    let err = export_bundle_with_signer(
        &BundleExportInputs::new(&vmlinux, &rootfs, "aarch64", &out),
        &TestSigner::new(7),
    )
    .expect_err("refused");

    let message = format!("{err:#}");
    assert!(message.contains("reading guest sidecar at"), "{message}");
    assert!(message.contains("rebuild the template"), "{message}");
    assert_nothing_written(&out);
}

#[test]
fn a_missing_kernel_is_named() {
    let slot = Slot::new();
    let (vmlinux, rootfs, out) = (slot.path("absent"), slot.path("rootfs.ext4"), slot.out());

    let err = export_bundle_with_signer(
        &BundleExportInputs::new(&vmlinux, &rootfs, "aarch64", &out),
        &TestSigner::new(7),
    )
    .expect_err("refused");

    assert!(
        err.to_string()
            .contains(&format!("reading kernel at {vmlinux}")),
        "{err:#}"
    );
}

#[test]
fn a_signer_naming_another_key_is_refused_and_writes_nothing() {
    let slot = Slot::new();
    let (vmlinux, rootfs, out) = (slot.path("vmlinux"), slot.path("rootfs.ext4"), slot.out());
    let signer = MislabelledSigner {
        key: SigningKey::from_bytes(&[7; 32]),
        claimed: key_id_from_pubkey(&SigningKey::from_bytes(&[8; 32]).verifying_key()),
    };

    let err = export_bundle_with_signer(
        &BundleExportInputs::new(&vmlinux, &rootfs, "aarch64", &out),
        &signer,
    )
    .expect_err("refused");

    assert!(format!("{err:#}").contains("does not match"), "{err:#}");
    assert_nothing_written(&out);
}

#[test]
fn a_bundle_from_an_untrusted_signer_does_not_verify() {
    let slot = Slot::new();
    let (vmlinux, rootfs, out) = (slot.path("vmlinux"), slot.path("rootfs.ext4"), slot.out());
    export(
        &BundleExportInputs::new(&vmlinux, &rootfs, "aarch64", &out),
        &TestSigner::new(7),
    );

    let err = verify(&out, &TestSigner::new(8)).expect_err("another publisher's key");

    assert!(matches!(err, BundleVerifyError::UnknownKey { .. }), "{err}");
}

#[test]
fn a_tampered_export_does_not_verify() {
    let slot = Slot::new();
    let (vmlinux, rootfs, out) = (slot.path("vmlinux"), slot.path("rootfs.ext4"), slot.out());
    let signer = TestSigner::new(7);
    export(
        &BundleExportInputs::new(&vmlinux, &rootfs, "aarch64", &out),
        &signer,
    );

    let mut archive = std::fs::read(&out).expect("read");
    let at = archive
        .windows(ROOTFS.len())
        .position(|window| window == ROOTFS)
        .expect("rootfs bytes in the archive");
    archive[at] ^= 0xff;

    let err = read_and_verify_bundle(&archive, &OneKey(signer.key.verifying_key()))
        .expect_err("tampered rootfs");
    assert!(
        matches!(err, BundleVerifyError::ArtifactSha256Mismatch { .. }),
        "{err}"
    );
}

#[test]
fn the_debug_summary_describes_the_exported_archive() {
    let slot = Slot::new();
    let (vmlinux, rootfs, out) = (slot.path("vmlinux"), slot.path("rootfs.ext4"), slot.out());
    let debug_path = slot.dir.path().join("debug").join("summary.json");
    let signer = TestSigner::new(7);
    let inputs = BundleExportInputs::new(&vmlinux, &rootfs, "aarch64", &out)
        .debug_out(DebugOutput::json(&debug_path));

    let exported = export(&inputs, &signer);

    let archive = std::fs::read(&out).expect("read");
    let summary: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&debug_path).expect("read summary"))
            .expect("summary is JSON");
    assert_eq!(summary["bundle_path"], out.display().to_string());
    assert_eq!(summary["bundle_sha256"], bundle_sha256(&archive));
    assert_eq!(summary["size_bytes"], exported.size_bytes);
    assert_eq!(summary["manifest"]["key_id"], exported.key_id.0);
    assert_eq!(summary["manifest"]["arch"], "aarch64");
    let names: Vec<&str> = summary["manifest"]["artifacts"]
        .as_array()
        .expect("artifacts")
        .iter()
        .map(|artifact| artifact["name"].as_str().expect("name"))
        .collect();
    assert_eq!(names, ["vmlinux", "rootfs.ext4", "mvm-meta.json"]);
}

#[test]
fn a_debug_summary_aimed_at_the_bundle_path_is_refused() {
    let slot = Slot::new();
    let (vmlinux, rootfs, out) = (slot.path("vmlinux"), slot.path("rootfs.ext4"), slot.out());
    let inputs = BundleExportInputs::new(&vmlinux, &rootfs, "aarch64", &out)
        .debug_out(DebugOutput::json(&out));

    let err = export_bundle_with_signer(&inputs, &TestSigner::new(7)).expect_err("refused");

    assert!(
        err.to_string().contains("give the summary its own path"),
        "{err:#}"
    );
    assert_nothing_written(&out);
}

#[test]
fn no_debug_summary_is_written_unless_asked_for() {
    let slot = Slot::new();
    let (vmlinux, rootfs, out) = (slot.path("vmlinux"), slot.path("rootfs.ext4"), slot.out());

    export(
        &BundleExportInputs::new(&vmlinux, &rootfs, "aarch64", &out),
        &TestSigner::new(7),
    );

    let written: Vec<_> = std::fs::read_dir(out.parent().expect("out dir"))
        .expect("read out dir")
        .map(|entry| entry.expect("entry").file_name())
        .collect();
    assert_eq!(written, ["app.mvmpkg"]);
}
