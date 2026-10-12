//! Building a flake and sealing what it produced into a signed `.mvmpkg`.
//!
//! [`build_and_export_bundle`] is the library form of building an image and
//! then running `mvmctl bundle export` on it: one flake build in a builder VM,
//! then the same export, under the caller's signer.
//!
//! ## Which processes can build
//!
//! The build runs on the builder backend the host resolves to.
//! [`build_and_export_bundle`] registers the HVF and Firecracker builders
//! before it resolves one, so every backend is constructible here, as it is in
//! `mvmctl`.
//!
//! What a library process lacks is the builder boot payload: `mvmctl` embeds
//! mvm's builder binaries and hands them to each builder boot, and nothing
//! else carries them. A builder image that bakes its own binaries boots
//! without one. An image that relies on the payload is refused before it
//! boots, and the refusal names the missing payload rather than the image.
//! Such a caller runs the build through `mvmctl`, or hands its own builder to
//! [`build_and_export_bundle_on`].
//!
//! ## What is trusted
//!
//! The builder guest is not. It never holds the signing key: the signer lives
//! in this process and is asked for a signature only by the export, after the
//! guest has powered off. Before that, every file the bundle will carry is
//! checked by [`verify_builder_output`], and [`export_builder_result`] takes
//! only the [`VerifiedBuilderOutput`] that check returns, so there is no way to
//! sign builder output that skipped it.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use mvm_build::builder_orchestrator::{
    BuildRequest, BuilderResult, run_builder_for_request, run_builder_for_request_on,
};
pub use mvm_build::builder_output::{VerifiedBuilderOutput, verify_builder_output};
use mvm_build::builder_vm::BuilderVm;

use mvm_core::plan::types::{BuildProvenance, InputKind};

use crate::bundle::{BundleExportInputs, BundleSigner, DebugOutput, export_bundle_with_signer};

/// One flake attribute to build and the bundle to seal it into.
#[derive(Debug, Clone)]
pub struct BuilderBundleRequest {
    /// The flake's source directory, mounted read-only at `/work`.
    pub workspace_root: PathBuf,
    /// The flake reference as the builder sees it, for example `/work`.
    pub flake_ref: String,
    /// The attribute to build, for example `packages.aarch64-linux.default`.
    pub attr_path: String,
    /// Where the builder writes the rootfs, the kernel, and the sidecar.
    pub artifact_out: PathBuf,
    /// A host directory to reuse as the builder's Nix store, if any.
    pub host_nix_store: Option<PathBuf>,
    /// The directory holding mvm's builder binaries.
    pub host_bin_dir: PathBuf,
    /// The guest architecture the flake attribute builds for.
    pub arch_label: String,
    /// The build profile to record in the manifest, if there is one.
    pub profile: Option<String>,
    /// Human-readable workload label to record in the manifest.
    pub label: Option<String>,
    /// Where the `.mvmpkg` is written.
    pub bundle_out: PathBuf,
    /// Where to write a summary of the export, if anywhere.
    pub debug_out: Option<DebugOutput>,
}

impl BuilderBundleRequest {
    /// The flake attribute this request builds, pinned by the lock file the
    /// build recorded, as the bundle's build input. The exporter binds it to
    /// the digests of what it seals.
    fn provenance(&self, built: &BuilderResult) -> BuildProvenance {
        BuildProvenance {
            input_kind: InputKind::NixFlake,
            input_ref: format!("{}#{}", self.flake_ref, self.attr_path),
            lock_digest: built.lock_hash.clone(),
            builder_id: None,
            artifacts: Default::default(),
        }
    }

    fn build_request(&self) -> BuildRequest {
        BuildRequest {
            workspace_root: self.workspace_root.clone(),
            flake_ref: self.flake_ref.clone(),
            attr_path: self.attr_path.clone(),
            artifact_out: self.artifact_out.clone(),
            host_nix_store: self.host_nix_store.clone(),
            host_bin_dir: self.host_bin_dir.clone(),
        }
    }
}

/// The bundle a build was sealed into.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuilderBundleResult {
    pub bundle_path: PathBuf,
}

/// Build `request`'s flake on the builder backend this host resolves to, and
/// seal the result into a `.mvmpkg` signed by `signer`.
pub fn build_and_export_bundle(
    request: &BuilderBundleRequest,
    signer: &dyn BundleSigner,
) -> Result<BuilderBundleResult> {
    mvm_runtime::builder_runner::register_driver_backed_builders();
    let built = run_builder_for_request(&request.build_request())?;
    export_builder_result(&verify_builder_output(&built)?, request, signer)
}

/// As [`build_and_export_bundle`], on a builder the caller supplies.
pub fn build_and_export_bundle_on(
    request: &BuilderBundleRequest,
    signer: &dyn BundleSigner,
    builder: &dyn BuilderVm,
) -> Result<BuilderBundleResult> {
    let built = run_builder_for_request_on(&request.build_request(), builder)?;
    export_builder_result(&verify_builder_output(&built)?, request, signer)
}

/// Seal a verified build into a `.mvmpkg` signed by `signer`.
///
/// A flake build records no vCPU or memory sizing, so the bundle carries none
/// and a launch from it starts from the launching host's defaults.
pub fn export_builder_result(
    verified: &VerifiedBuilderOutput,
    request: &BuilderBundleRequest,
    signer: &dyn BundleSigner,
) -> Result<BuilderBundleResult> {
    let kernel = verified.kernel().with_context(|| {
        format!(
            "the build of {} produced no kernel; a bundle needs one to boot",
            request.attr_path
        )
    })?;
    let verity_bytes = verified
        .verity()
        .map(|verity| {
            std::fs::read(verity.hash_tree()).with_context(|| {
                format!("reading verity sidecar at {}", verity.hash_tree().display())
            })
        })
        .transpose()?;

    let exported = export_bundle_with_signer(
        &BundleExportInputs {
            vmlinux: utf8(kernel)?,
            initrd: verified.initrd().map(utf8).transpose()?,
            rootfs: utf8(verified.rootfs())?,
            verity_bytes: verity_bytes.as_deref(),
            roothash: verified.verity().map(|verity| verity.roothash()),
            profile: request.profile.as_deref(),
            resources: None,
            arch_label: &request.arch_label,
            label: request.label.clone(),
            cmdline: None,
            posture: None,
            provenance: Some(request.provenance(verified.build())),
            boot_assets: None,
            out: &request.bundle_out,
            debug_out: request.debug_out.clone(),
        },
        signer,
    )?;
    Ok(BuilderBundleResult {
        bundle_path: exported.path,
    })
}

fn utf8(path: &Path) -> Result<&str> {
    path.to_str()
        .with_context(|| format!("artifact path {} is not valid UTF-8", path.display()))
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use ed25519_dalek::{SigningKey, VerifyingKey};
    use mvm_build::builder_vm::{
        BuilderArtifacts, BuilderCapabilities, BuilderJob, BuilderMounts, BuilderVmError,
        SIDECAR_FILENAME,
    };
    use mvm_core::plan::bundle::{
        ArtifactRole, KeyId, TrustStore, VerifiedBundle, key_id_from_pubkey, read_and_verify_bundle,
    };

    use super::*;

    const ROOTHASH: &str = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";

    /// The least a sidecar must say for the runtime to boot its rootfs.
    const ADMITTED_SIDECAR: &[u8] = br#"{"overlayAware":true,"runtimeLean":true}"#;

    /// An initrd and a complete dm-verity pair, as a build leaves them.
    const INITRD_AND_VERITY: &[(&str, &[u8])] = &[
        ("initrd", b"initrd"),
        ("rootfs.verity", b"hash tree"),
        ("rootfs.roothash", ROOTHASH.as_bytes()),
    ];

    struct TestSigner(SigningKey);

    impl BundleSigner for TestSigner {
        fn publisher_id(&self) -> String {
            "test:publisher".to_string()
        }

        fn verifying_key(&self) -> VerifyingKey {
            self.0.verifying_key()
        }

        fn sign(&self, canonical_manifest: &[u8]) -> anyhow::Result<[u8; 64]> {
            Ok(ed25519_dalek::Signer::sign(&self.0, canonical_manifest).to_bytes())
        }
    }

    /// A signer that records whether it was ever asked to sign.
    struct WatchedSigner {
        inner: TestSigner,
        asked: std::cell::Cell<u32>,
    }

    impl WatchedSigner {
        fn new() -> Self {
            Self {
                inner: TestSigner(SigningKey::from_bytes(&[3; 32])),
                asked: std::cell::Cell::new(0),
            }
        }
    }

    impl BundleSigner for WatchedSigner {
        fn publisher_id(&self) -> String {
            self.inner.publisher_id()
        }

        fn verifying_key(&self) -> VerifyingKey {
            self.inner.verifying_key()
        }

        fn sign(&self, canonical_manifest: &[u8]) -> anyhow::Result<[u8; 64]> {
            self.asked.set(self.asked.get() + 1);
            self.inner.sign(canonical_manifest)
        }
    }

    struct OneKey(VerifyingKey);

    impl TrustStore for OneKey {
        fn lookup(&self, key_id: &KeyId) -> Option<VerifyingKey> {
            (*key_id == key_id_from_pubkey(&self.0)).then_some(self.0)
        }
    }

    /// Writes what a flake build leaves behind; `extra` names the optional
    /// files to add beside the rootfs.
    struct StubBuilder {
        kernel: bool,
        extra: &'static [(&'static str, &'static [u8])],
        /// Replace this output member with a link to `target`, as a guest
        /// that wanted the host to read `target` would.
        link: Option<(&'static str, std::path::PathBuf)>,
    }

    impl StubBuilder {
        fn new(kernel: bool, extra: &'static [(&'static str, &'static [u8])]) -> Self {
            Self {
                kernel,
                extra,
                link: None,
            }
        }
    }

    impl BuilderVm for StubBuilder {
        fn run_build(
            &self,
            _job: &BuilderJob,
            mounts: &BuilderMounts,
        ) -> Result<BuilderArtifacts, BuilderVmError> {
            let out = &mounts.artifact_out;
            std::fs::write(out.join("rootfs.ext4"), b"rootfs").unwrap();
            std::fs::write(out.join(SIDECAR_FILENAME), ADMITTED_SIDECAR).unwrap();
            if self.kernel {
                std::fs::write(out.join("vmlinux"), b"kernel").unwrap();
            }
            for (name, bytes) in self.extra {
                std::fs::write(out.join(name), bytes).unwrap();
            }
            if let Some((name, target)) = &self.link {
                std::fs::remove_file(out.join(name)).unwrap();
                std::os::unix::fs::symlink(target, out.join(name)).unwrap();
            }
            Ok(BuilderArtifacts::Image {
                rootfs_path: out.join("rootfs.ext4"),
                kernel_path: self.kernel.then(|| out.join("vmlinux")),
                revision_hash: "deadbeefcafebabe".to_string(),
                lock_hash: None,
                accessible: None,
            })
        }

        fn run_stage0(
            &self,
            _guest_root_dir: &Path,
            _entry_path: &str,
            _workspace_dir: &Path,
            _artifact_out: &Path,
            _host_bin_dir: &Path,
        ) -> Result<(), BuilderVmError> {
            Err(BuilderVmError::NotYetImplemented)
        }

        fn capabilities(&self) -> BuilderCapabilities {
            BuilderCapabilities::default()
        }
    }

    fn request(root: &Path) -> BuilderBundleRequest {
        for dir in ["workspace", "out", "bins"] {
            std::fs::create_dir_all(root.join(dir)).unwrap();
        }
        BuilderBundleRequest {
            workspace_root: root.join("workspace"),
            flake_ref: "/work".to_string(),
            attr_path: "packages.aarch64-linux.default".to_string(),
            artifact_out: root.join("out"),
            host_nix_store: None,
            host_bin_dir: root.join("bins"),
            arch_label: "aarch64".to_string(),
            profile: Some("minimal".to_string()),
            label: Some("app".to_string()),
            bundle_out: root.join("dist").join("app.mvmpkg"),
            debug_out: None,
        }
    }

    fn verify(path: &Path, signer: &TestSigner) -> VerifiedBundle {
        let archive = std::fs::read(path).expect("read bundle");
        read_and_verify_bundle(&archive, &OneKey(signer.0.verifying_key())).expect("verifies")
    }

    #[test]
    fn a_build_is_sealed_into_a_bundle_that_verifies() {
        let tmp = tempfile::tempdir().unwrap();
        let request = request(tmp.path());
        let signer = TestSigner(SigningKey::from_bytes(&[3; 32]));
        let builder = StubBuilder::new(true, &[]);

        let result = build_and_export_bundle_on(&request, &signer, &builder).expect("bundle");

        assert_eq!(result.bundle_path, request.bundle_out);
        let bundle = verify(&result.bundle_path, &signer);
        assert_eq!(bundle.artifacts["artifacts/vmlinux"], b"kernel");
        assert_eq!(bundle.artifacts["artifacts/rootfs.ext4"], b"rootfs");
        assert_eq!(
            bundle.artifacts["artifacts/mvm-meta.json"],
            ADMITTED_SIDECAR
        );
        let manifest = bundle.manifest;
        assert_eq!(manifest.arch, "aarch64");
        assert_eq!(manifest.profile.as_deref(), Some("minimal"));
        assert_eq!(manifest.workload_label.as_deref(), Some("app"));
        assert!(manifest.resources.is_none());
        assert!(manifest.verity.is_none());
        let provenance = manifest.build_provenance().expect("provenance recorded");
        assert_eq!(provenance.input_ref, "/work#packages.aarch64-linux.default");
        assert_eq!(
            provenance.artifacts.rootfs,
            Some(mvm_core::plan::sha256_hex(b"rootfs"))
        );
    }

    #[test]
    fn an_initrd_and_a_verity_pair_beside_the_rootfs_are_carried() {
        let tmp = tempfile::tempdir().unwrap();
        let request = request(tmp.path());
        let signer = TestSigner(SigningKey::from_bytes(&[3; 32]));
        let builder = StubBuilder::new(true, INITRD_AND_VERITY);

        let result = build_and_export_bundle_on(&request, &signer, &builder).expect("bundle");

        let bundle = verify(&result.bundle_path, &signer);
        assert_eq!(bundle.artifacts["artifacts/initrd"], b"initrd");
        assert_eq!(bundle.artifacts["artifacts/rootfs.verity"], b"hash tree");
        assert_eq!(
            bundle.manifest.verity.as_ref().map(|v| v.roothash.as_str()),
            Some(ROOTHASH)
        );
        assert!(
            bundle
                .manifest
                .find_by_role(&ArtifactRole::Initrd)
                .is_some()
        );
    }

    #[test]
    fn a_build_with_no_kernel_is_refused_and_writes_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let request = request(tmp.path());
        let builder = StubBuilder::new(false, &[]);

        let err = build_and_export_bundle_on(
            &request,
            &TestSigner(SigningKey::from_bytes(&[3; 32])),
            &builder,
        )
        .expect_err("no kernel");

        assert!(format!("{err:#}").contains("produced no kernel"), "{err:#}");
        assert!(!request.bundle_out.exists());
    }

    #[test]
    fn the_debug_summary_is_written_when_asked_for() {
        let tmp = tempfile::tempdir().unwrap();
        let debug_path = tmp.path().join("summary.json");
        let request = BuilderBundleRequest {
            debug_out: Some(DebugOutput::json(&debug_path)),
            ..request(tmp.path())
        };
        let builder = StubBuilder::new(true, &[]);

        build_and_export_bundle_on(
            &request,
            &TestSigner(SigningKey::from_bytes(&[3; 32])),
            &builder,
        )
        .expect("bundle");

        let summary: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&debug_path).expect("summary")).unwrap();
        assert_eq!(summary["manifest"]["arch"], "aarch64");
    }

    /// A compromised builder cannot see the host key, but it can name a file
    /// in its output after one. If the host read through that name, the key
    /// would be sealed into a bundle the host then signs and ships.
    #[test]
    fn output_that_links_to_the_signing_key_is_refused_before_the_signer_is_asked() {
        let tmp = tempfile::tempdir().unwrap();
        let request = request(tmp.path());
        let keys = tmp.path().join("keys");
        crate::bundle::HostBundleSigner::load_at(&keys).expect("host key");
        let key_file = keys.join("host-signer.ed25519");
        assert!(
            key_file.is_file(),
            "the host key exists where a guest would aim"
        );

        for member in ["rootfs.ext4", "vmlinux", SIDECAR_FILENAME] {
            let _ = std::fs::remove_dir_all(&request.artifact_out);
            std::fs::create_dir_all(&request.artifact_out).unwrap();
            let signer = WatchedSigner::new();
            let builder = StubBuilder {
                link: Some((member, key_file.clone())),
                ..StubBuilder::new(true, &[])
            };

            let err = build_and_export_bundle_on(&request, &signer, &builder)
                .expect_err("a linked member is refused");

            assert_eq!(
                mvm_build::builder_orchestrator::failure_category(&err),
                mvm_build::builder_job_contract::FailureCategory::OutputContract,
                "{member}: {err:#}"
            );
            assert_eq!(signer.asked.get(), 0, "{member}: the signer was asked");
            assert!(
                !request.bundle_out.exists(),
                "{member}: a bundle was written"
            );
        }
    }

    #[test]
    fn output_the_runtime_would_not_boot_is_refused_before_the_signer_is_asked() {
        let tmp = tempfile::tempdir().unwrap();
        let request = request(tmp.path());
        let signer = WatchedSigner::new();
        let builder = StubBuilder::new(true, &[(SIDECAR_FILENAME, br#"{"overlayAware":false}"#)]);

        let err = build_and_export_bundle_on(&request, &signer, &builder).expect_err("refused");

        assert!(format!("{err:#}").contains("would not boot"), "{err:#}");
        assert_eq!(signer.asked.get(), 0);
        assert!(!request.bundle_out.exists());
    }

    /// The probe a boot uses drops a malformed root hash and boots unsealed.
    /// An export that did the same would sign a rootfs the build meant to seal
    /// as an unsealed one.
    #[test]
    fn a_malformed_verity_root_hash_is_refused_not_exported_unsealed() {
        let tmp = tempfile::tempdir().unwrap();
        let request = request(tmp.path());
        let signer = WatchedSigner::new();
        let builder = StubBuilder::new(
            true,
            &[
                ("rootfs.verity", b"hash tree"),
                ("rootfs.roothash", b"not a root hash"),
            ],
        );

        let err = build_and_export_bundle_on(&request, &signer, &builder).expect_err("refused");

        assert!(format!("{err:#}").contains("64-hex"), "{err:#}");
        assert_eq!(signer.asked.get(), 0);
        assert!(!request.bundle_out.exists());
    }

    #[test]
    fn verified_output_is_signed_exactly_once() {
        let tmp = tempfile::tempdir().unwrap();
        let request = request(tmp.path());
        let signer = WatchedSigner::new();

        build_and_export_bundle_on(&request, &signer, &StubBuilder::new(true, &[]))
            .expect("bundle");

        assert_eq!(signer.asked.get(), 1);
        verify(&request.bundle_out, &signer.inner);
    }
}
