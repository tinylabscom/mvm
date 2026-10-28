//! Explicit offline proof preparation, separate from read-only archive preview.
//!
//! This may advance the existing signed image-set revocation store. It does not
//! admit a plan, start a backend, or make the prepared owner a native capability.

use crate as mvm_core;
#[cfg(feature = "host-state")]
use anyhow::Context;
use anyhow::{Result, ensure};
#[cfg(feature = "host-state")]
use chrono::{DateTime, Utc};
use mvm_core::arch::GuestArch;
#[cfg(feature = "host-state")]
use mvm_core::image_set::HostProtocolSupport;
use mvm_core::image_set::ImageSetMember;
#[cfg(feature = "host-state")]
use mvm_core::image_set::{
    BackendImageSupport, BootProtocol, ImageSetRequirement, ImageSetRole, ImageSetVerification,
    image_train_lock, select_member, verify_image_set_root,
};
#[cfg(feature = "host-state")]
use mvm_core::image_set_revocation::ImageSetRevocationStore;
#[cfg(feature = "host-state")]
use mvm_core::image_set_revocation::{
    verify_image_set_artifacts_under_revocations, verify_image_set_revocations,
};
#[cfg(feature = "host-state")]
use mvm_core::packs::PackRevocationChecker;
use mvm_core::plan::bundle::{CapturedCanonicalLinuxInputs, PlanArtifact};
#[cfg(feature = "host-state")]
use mvm_core::plan::bundle::{FsTrustStore, capture_canonical_linux_inputs};
use mvm_core::vm_backend::BackendKind;
#[cfg(feature = "host-state")]
use std::fs::File;
#[cfg(feature = "host-state")]
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

/// Owns a private selected-kernel view and the exact original application proof.
/// No public fields, deserializer, path-based constructor or native permission.
/// Backend integration must retain this SAME owner and bind its pin, architecture
/// and backend to the actual admitted operation before any native effects.
#[derive(Debug)]
pub struct PreparedCanonicalLinux {
    inputs: CapturedCanonicalLinuxInputs,
    #[cfg(feature = "host-state")]
    view_guard: Mutex<Option<tempfile::TempDir>>,
    view_path: std::path::PathBuf,
    declaration: ImageSetMember,
    arch: GuestArch,
    backend: BackendKind,
    #[cfg(feature = "host-state")]
    store: ImageSetRevocationStore,
    #[cfg(feature = "host-state")]
    host_protocols: HostProtocolSupport,
    #[cfg(feature = "host-state")]
    home: std::path::PathBuf,
    bound_vm: Mutex<Option<String>>,
    native_claimed: AtomicBool,
}

impl PreparedCanonicalLinux {
    pub fn verify_bundle_manifest(
        &self,
        manifest: &crate::plan::bundle::BundleManifest,
    ) -> Result<()> {
        ensure!(
            manifest == self.inputs.manifest(),
            "canonical owner belongs to another bundle declaration"
        );
        Ok(())
    }
    pub fn generation_dir(&self) -> &Path {
        self.inputs.generation_dir()
    }
    pub fn kernel_path(&self) -> std::path::PathBuf {
        self.view_path
            .join(self.declaration.artifacts[0].name.as_str())
    }
    /// Digest selected by the canonical signed Linux root, not by the app key.
    pub fn kernel_sha256(&self) -> &str {
        self.declaration.artifacts[0].sha256.as_str()
    }

    /// Original canonical signed declaration, for checking a held kernel file.
    /// This is byte evidence, not native launch authority.
    pub fn kernel_declaration(&self) -> &crate::image_set::MemberArtifact {
        &self.declaration.artifacts[0]
    }

    /// Bind this SAME in-process owner to one VM, not a path/hash claim.
    pub fn bind_to_config(
        self: &Arc<Self>,
        config: &mut crate::vm_backend::VmStartConfig,
    ) -> Result<()> {
        crate::naming::validate_vm_name(&config.name)?;
        let mut bound = self
            .bound_vm
            .lock()
            .map_err(|_| anyhow::anyhow!("kernel binding poisoned"))?;
        ensure!(
            bound.as_ref().is_none_or(|name| name == &config.name),
            "kernel owner belongs to another VM"
        );
        ensure!(
            !self.native_claimed.load(Ordering::Acquire),
            "kernel owner already used for native handoff"
        );
        *bound = Some(config.name.clone());
        config.kernel_path = Some(self.kernel_path().display().to_string());
        config.canonical_kernel = Some(Arc::clone(self));
        Ok(())
    }

    #[cfg(feature = "host-state")]
    pub fn verify_config(
        self: &Arc<Self>,
        config: &crate::vm_backend::VmStartConfig,
        backend: BackendKind,
        host: &HostProtocolSupport,
    ) -> Result<()> {
        ensure!(
            config
                .canonical_kernel
                .as_ref()
                .is_some_and(|actual| Arc::ptr_eq(actual, self)),
            "launch substituted the canonical kernel owner"
        );
        ensure!(
            self.bound_vm
                .lock()
                .map_err(|_| anyhow::anyhow!("kernel binding poisoned"))?
                .as_deref()
                == Some(config.name.as_str()),
            "kernel owner VM binding differs"
        );
        ensure!(
            backend == self.backend && crate::config::mvm_home_strict()? == self.home,
            "kernel owner backend or consumer home differs"
        );
        ensure!(
            host.base_image_contract == self.host_protocols.base_image_contract
                && host.builder_cache_contract == self.host_protocols.builder_cache_contract
                && host.builder_boot_abi == self.host_protocols.builder_boot_abi,
            "kernel owner protocol support differs from actual launch"
        );
        ensure!(
            config.kernel_path.as_deref() == self.kernel_path().to_str(),
            "launch substituted the selected kernel path"
        );
        self.kernel_file()?;
        Ok(())
    }

    /// Single-use resource retention. Cleanup requires actual backend lifetime
    /// evidence; dropping this owner after a failed start never deletes readers.
    #[cfg(feature = "host-state")]
    pub fn retain_for_native_handoff(
        self: &Arc<Self>,
        config: &crate::vm_backend::VmStartConfig,
        backend: BackendKind,
        host: &HostProtocolSupport,
    ) -> Result<()> {
        self.verify_config(config, backend, host)?;
        ensure!(
            self.native_claimed
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_ok(),
            "kernel owner already handed to a native reader"
        );
        self.inputs.retain_generation()?;
        if let Some(view) = self
            .view_guard
            .lock()
            .map_err(|_| anyhow::anyhow!("kernel view guard poisoned"))?
            .take()
        {
            let retained = view.keep();
            ensure!(
                retained.starts_with(self.inputs.generation_dir()),
                "kernel view retention moved outside its generation"
            );
        }
        Ok(())
    }
    pub fn pin(&self) -> &PlanArtifact {
        self.inputs.pin()
    }
    pub fn arch(&self) -> GuestArch {
        self.arch
    }
    pub fn backend(&self) -> BackendKind {
        self.backend
    }

    /// Re-authenticate against the SAME consumer store at actual use time.
    /// This returns checked bytes, not launch permission or a teardown receipt.
    #[cfg(feature = "host-state")]
    pub fn kernel_file(&self) -> Result<File> {
        self.kernel_file_at(Utc::now())
    }

    #[cfg(feature = "host-state")]
    fn kernel_file_at(&self, now: DateTime<Utc>) -> Result<File> {
        let policy = self.store.load(now)?;
        let declaration =
            select_canonical_kernel(&self.inputs, self.backend, &policy, &self.host_protocols)?;
        ensure!(
            declaration == self.declaration,
            "canonical kernel selection changed"
        );
        let artifact = &declaration.artifacts[0];
        let manifest = read_member(
            &self.inputs,
            &self.inputs.proof().manifest_artifact,
            4 * 1024 * 1024,
        )?;
        let signature = read_member(
            &self.inputs,
            &self.inputs.proof().signature_bundle_artifact,
            1024 * 1024,
        )?;
        let host = &self.host_protocols;
        let request = ImageSetVerification::new(
            &manifest,
            &signature,
            &image_train_lock().image_set,
            &self.view_path,
        )
        .with_workload_protocols(host);
        // The policy wrapper owns an authenticated, fresh store load. The
        // canonical verifier checks the actual private view under that policy.
        mvm_core::image_set::verify_image_set_artifacts(
            &request.with_revocations(&policy),
            std::slice::from_ref(&artifact.name),
        )?;
        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
        let mut file = options.open(self.view_path.join(artifact.name.as_str()))?;
        let metadata = file.metadata()?;
        ensure!(
            metadata.is_file() && metadata.len() == artifact.size,
            "retained kernel size/type changed"
        );
        let digest = mvm_core::crypto::image_verify::sha256_reader(
            Read::by_ref(&mut file).take(artifact.size + 1),
        )?;
        ensure!(
            digest == artifact.sha256.as_str(),
            "retained kernel bytes changed"
        );
        file.seek(SeekFrom::Start(0))?;
        Ok(file)
    }
}

/// Backends that hold the canonical kernel by descriptor at boot and produce
/// lifetime evidence (an authenticated instance, or a process-table identity)
/// before the generation may be released. Every other backend is refused.
pub fn supports_lifetime_custody(backend: BackendKind) -> bool {
    (cfg!(unix) && backend == BackendKind::Hvf)
        || (cfg!(target_os = "linux") && backend == BackendKind::Firecracker)
}

/// Explicitly prepare a pinned bundle's canonical Linux proof offline.
///
/// Unlike `check-artifact`, successful preparation may apply the original
/// signed feed through the existing rollback-protected store. Missing, stale,
/// invalid, revoked or rolled-back evidence refuses. No download, trust-key
/// enrollment, source build, runtime selection or native start occurs here.
#[cfg(feature = "host-state")]
pub fn prepare_canonical_linux(
    archive: &Path,
    pin: &PlanArtifact,
    backend: BackendKind,
    host_protocols: HostProtocolSupport,
) -> Result<PreparedCanonicalLinux> {
    let inputs = capture_canonical_linux_inputs(archive, pin, &FsTrustStore::default_path()?)?;
    prepare_with_clock(inputs, backend, host_protocols, Utc::now)
}

#[cfg(feature = "host-state")]
fn prepare_with_clock(
    inputs: CapturedCanonicalLinuxInputs,
    backend: BackendKind,
    host_protocols: HostProtocolSupport,
    now: impl Fn() -> DateTime<Utc>,
) -> Result<PreparedCanonicalLinux> {
    let arch = GuestArch::require_host(&inputs.manifest().arch)?;
    let proof = inputs.proof();
    let document = read_member(&inputs, &proof.revocation_document_artifact, 1024 * 1024)?;
    let signature = read_member(
        &inputs,
        &proof.revocation_signature_bundle_artifact,
        1024 * 1024,
    )?;
    let candidate = verify_image_set_revocations(&document, &signature, now(), None)?;
    let declaration = select_canonical_kernel(&inputs, backend, &candidate, &host_protocols)?;
    let artifact = &declaration.artifacts[0];
    ensure!(
        inputs.kernel().sha256 == artifact.sha256.as_str()
            && inputs.kernel().size_bytes == artifact.size,
        "application kernel differs from canonical Linux declaration"
    );
    let view = tempfile::Builder::new()
        .prefix("selected-")
        .tempdir_in(inputs.generation_dir())?;
    crate::config::create_private_dir(view.path())?;
    let path = view.path().join(artifact.name.as_str());
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)?;
    std::io::copy(
        &mut inputs
            .open_artifact(&inputs.kernel().name)?
            .take(artifact.size + 1),
        &mut output,
    )?;
    output.sync_all()?;
    drop(output);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400))?;
    }
    let manifest = read_member(&inputs, &proof.manifest_artifact, 4 * 1024 * 1024)?;
    let root_signature = read_member(&inputs, &proof.signature_bundle_artifact, 1024 * 1024)?;
    let host = &host_protocols;
    let request = ImageSetVerification::new(
        &manifest,
        &root_signature,
        &image_train_lock().image_set,
        view.path(),
    )
    .with_workload_protocols(host);
    verify_image_set_artifacts_under_revocations(
        request,
        std::slice::from_ref(&artifact.name),
        &candidate,
    )?;
    // No feed update occurs until the root and actual selected kernel bytes
    // have verified. The existing store independently enforces its newer local
    // checkpoint; bundled older evidence cannot replace it.
    let store = ImageSetRevocationStore::in_mvm_home();
    store.update(&document, &signature, now())?;
    let prepared = PreparedCanonicalLinux {
        inputs,
        view_path: view.path().to_owned(),
        view_guard: Mutex::new(Some(view)),
        declaration,
        arch,
        backend,
        store,
        host_protocols,
        home: crate::config::mvm_home_strict()?,
        bound_vm: Mutex::new(None),
        native_claimed: AtomicBool::new(false),
    };
    // Recheck effective current policy after update (including a concurrent
    // policy advance), not just the feed that happened to be bundled.
    prepared.kernel_file_at(now())?;
    Ok(prepared)
}

#[cfg(feature = "host-state")]
fn read_member(inputs: &CapturedCanonicalLinuxInputs, name: &str, limit: u64) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    inputs
        .open_artifact(name)?
        .take(limit + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        !bytes.is_empty() && bytes.len() as u64 <= limit,
        "missing or oversized Linux proof input"
    );
    Ok(bytes)
}

#[cfg(feature = "host-state")]
fn select_canonical_kernel(
    inputs: &CapturedCanonicalLinuxInputs,
    backend: BackendKind,
    policy: &dyn PackRevocationChecker,
    host: &HostProtocolSupport,
) -> Result<ImageSetMember> {
    let arch = GuestArch::require_host(&inputs.manifest().arch)?;
    let manifest = read_member(inputs, &inputs.proof().manifest_artifact, 4 * 1024 * 1024)?;
    let signature = read_member(
        inputs,
        &inputs.proof().signature_bundle_artifact,
        1024 * 1024,
    )?;
    select_from_root(&manifest, &signature, arch, backend, policy, host)
}

#[cfg(feature = "host-state")]
fn select_from_root(
    manifest: &[u8],
    signature: &[u8],
    arch: GuestArch,
    backend: BackendKind,
    policy: &dyn PackRevocationChecker,
    host: &HostProtocolSupport,
) -> Result<ImageSetMember> {
    use mvm_core::image_set::WorkloadImageProfile;
    ensure!(
        matches!(
            backend,
            BackendKind::Firecracker | BackendKind::Hvf | BackendKind::Libkrun | BackendKind::Qemu
        ),
        "canonical kernel preparation requires a kernel-booting backend"
    );
    let requirement = ImageSetRequirement::current_train();
    let request = ImageSetVerification::new(
        manifest,
        signature,
        &image_train_lock().image_set,
        Path::new(""),
    )
    .require(&requirement)
    .with_workload_protocols(host)
    .with_revocations(policy);
    let root = verify_image_set_root(&request)?;
    let support = BackendImageSupport::for_backend(backend).context("backend cannot boot Linux")?;
    let selected = select_member(
        root.manifest(),
        ImageSetRole::WorkloadKernel(WorkloadImageProfile::DefaultTenant),
        arch,
        &support,
    )?;
    ensure!(
        selected.build_mode.is_none()
            && selected.boot_protocol == Some(BootProtocol::LinuxDirect)
            && selected.artifacts.len() == 1,
        "canonical production kernel selection is ambiguous"
    );
    Ok(selected.clone())
}

#[cfg(all(test, unix, feature = "manifest-verify", feature = "host-state"))]
use crate::image_set::published_root;

#[cfg(all(test, unix, feature = "manifest-verify", feature = "host-state"))]
mod tests {
    #[test]
    fn lifetime_custody_is_limited_to_backends_with_exit_evidence() {
        assert!(super::supports_lifetime_custody(BackendKind::Hvf) == cfg!(unix));
        assert!(
            super::supports_lifetime_custody(BackendKind::Firecracker) == cfg!(target_os = "linux")
        );
        for backend in [BackendKind::Libkrun, BackendKind::Qemu] {
            assert!(!super::supports_lifetime_custody(backend));
        }
    }

    use super::*;
    use ed25519_dalek::{SigningKey, VerifyingKey};
    use mvm_core::image_set::{ImageSetManifest, WorkloadImageProfile};
    use mvm_core::packs::{RevocationStatus, Sha256Hex};
    use mvm_core::plan::bundle::{
        ArtifactRole, BundleArtifact, BundleManifest, BundleMember, CanonicalLinuxProof,
        EmbeddedCliBootAssets, KeyId, TrustStore, key_id_from_pubkey, sha256_hex,
        verify_bundle_file, write_bundle,
    };
    use mvm_core::util::test_env::TestEnv;
    use std::path::PathBuf;

    const FEED: &[u8] = include_bytes!(
        "../tests/fixtures/image-set-revocations/revocation-list-v1/revocations.json"
    );
    const FEED_SIGNATURE: &[u8] = include_bytes!(
        "../tests/fixtures/image-set-revocations/revocation-list-v1/revocations.json.bundle"
    );
    fn inside_window() -> DateTime<Utc> {
        "2026-10-15T12:00:00Z".parse().unwrap()
    }
    fn test_host() -> HostProtocolSupport {
        // Logical protocol fixture, not measured native-host readiness.
        HostProtocolSupport {
            base_image_contract: crate::image_set::BaseImageContractRange::SUPPORTED,
            builder_cache_contract: image_train_lock().compatibility.builder_cache_contract,
            builder_boot_abi: crate::image_set::BuilderBootAbiRange::LEGACY_ONLY,
        }
    }
    fn prepare_with_clock(
        inputs: CapturedCanonicalLinuxInputs,
        backend: BackendKind,
        now: impl Fn() -> DateTime<Utc>,
    ) -> Result<PreparedCanonicalLinux> {
        super::prepare_with_clock(inputs, backend, test_host(), now)
    }
    fn select_from_root(
        manifest: &[u8],
        signature: &[u8],
        arch: GuestArch,
        backend: BackendKind,
        policy: &dyn PackRevocationChecker,
    ) -> Result<ImageSetMember> {
        super::select_from_root(manifest, signature, arch, backend, policy, &test_host())
    }
    fn select_canonical_kernel(
        inputs: &CapturedCanonicalLinuxInputs,
        backend: BackendKind,
        policy: &dyn PackRevocationChecker,
    ) -> Result<ImageSetMember> {
        super::select_canonical_kernel(inputs, backend, policy, &test_host())
    }
    struct AppTrust(VerifyingKey);
    impl TrustStore for AppTrust {
        fn lookup(&self, id: &KeyId) -> Option<VerifyingKey> {
            (id == &key_id_from_pubkey(&self.0)).then_some(self.0)
        }
    }
    struct Frame {
        _directory: tempfile::TempDir,
        archive: PathBuf,
        pin: PlanArtifact,
        trust: AppTrust,
    }
    impl Frame {
        fn capture(&self) -> Result<CapturedCanonicalLinuxInputs> {
            capture_canonical_linux_inputs(&self.archive, &self.pin, &self.trust)
        }
    }
    // Kernel-proof-only fixture. Synthetic CLI runtime fields below are NOT
    // release-runtime authentication and cannot satisfy shared plan admission.
    fn frame(
        kernel: &[u8],
        linux: &[u8],
        root_signature: &[u8],
        feed_signature: &[u8],
        canonical: bool,
    ) -> Frame {
        let directory = tempfile::tempdir().unwrap();
        let archive = directory.path().join("app.mvmpkg");
        let key = SigningKey::from_bytes(&[73; 32]);
        let runtime = EmbeddedCliBootAssets {
            manifest_artifact: "linux.json".into(),
            version: "0.24.0".into(),
            arch: GuestArch::host().to_string(),
            archive_artifact: "runtime.tar.gz".into(),
            checksum_artifact: "runtime.sha256".into(),
            signature_bundle_artifact: "runtime.bundle".into(),
            checksum_signature_bundle_artifact: "runtime.sha256.bundle".into(),
            overlay_artifact: "overlay".into(),
            overlay_verity_artifact: "overlay.verity".into(),
            initramfs_artifact: "initrd".into(),
            overlay_roothash: "a".repeat(64),
            protocol_version: 2,
            min_supported_protocol_version: 2,
        };
        let mut members = vec![BundleMember::EmbeddedCliBootAssets(runtime)];
        if canonical {
            members.push(BundleMember::CanonicalLinuxProof(CanonicalLinuxProof {
                manifest_artifact: "linux.json".into(),
                signature_bundle_artifact: "linux.bundle".into(),
                revocation_document_artifact: "revocations.json".into(),
                revocation_signature_bundle_artifact: "revocations.bundle".into(),
            }));
        }
        let mut payload: Vec<(String, Vec<u8>)> = [
            ("kernel", kernel),
            ("linux.json", linux),
            ("linux.bundle", root_signature),
            ("revocations.json", FEED),
            ("revocations.bundle", feed_signature),
        ]
        .into_iter()
        .map(|(name, bytes)| (format!("artifacts/{name}"), bytes.to_vec()))
        .collect();
        for name in [
            "runtime.tar.gz",
            "runtime.sha256",
            "runtime.bundle",
            "runtime.sha256.bundle",
            "overlay",
            "overlay.verity",
            "initrd",
        ] {
            payload.push((format!("artifacts/{name}"), b"test-only runtime".to_vec()));
        }
        let manifest = BundleManifest {
            schema_version: 7,
            publisher: "test-only-application".into(),
            key_id: key_id_from_pubkey(&key.verifying_key()),
            arch: GuestArch::host().to_string(),
            kernel_version: None,
            profile: None,
            workload_label: None,
            created_at: "2026-10-15T00:00:00Z".into(),
            labels: Default::default(),
            members,
            verity: None,
            resources: None,
            artifacts: payload
                .iter()
                .map(|(path, bytes)| {
                    let name = path.strip_prefix("artifacts/").unwrap();
                    BundleArtifact {
                        name: name.into(),
                        path: path.clone(),
                        role: match name {
                            "kernel" => ArtifactRole::Kernel,
                            "initrd" => ArtifactRole::Initrd,
                            _ => ArtifactRole::Other,
                        },
                        sha256: sha256_hex(bytes),
                        size_bytes: bytes.len() as u64,
                    }
                })
                .collect(),
        };
        std::fs::write(&archive, write_bundle(&manifest, &key, payload).unwrap()).unwrap();
        let trust = AppTrust(key.verifying_key());
        let pin = verify_bundle_file(&archive, &trust)
            .unwrap()
            .plan_artifact();
        Frame {
            _directory: directory,
            archive,
            pin,
            trust,
        }
    }
    fn coherent_application_replacement(kernel: &[u8]) -> Vec<u8> {
        let mut linux: ImageSetManifest = serde_json::from_slice(published_root::MANIFEST).unwrap();
        let member = linux
            .members
            .iter_mut()
            .find(|member| {
                member.role == ImageSetRole::WorkloadKernel(WorkloadImageProfile::DefaultTenant)
                    && member.target.admits(GuestArch::host())
                    && member.build_mode.is_none()
            })
            .unwrap();
        member.artifacts[0].sha256 = Sha256Hex::from_bytes(kernel);
        member.artifacts[0].size = kernel.len() as u64;
        serde_json::to_vec(&linux).unwrap()
    }
    #[test]
    fn preparation_refuses_coherent_application_resigning_without_policy_side_effects() {
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(home.path());
        let kernel = b"application replacement";
        let linux = coherent_application_replacement(kernel);
        let f = frame(kernel, &linux, published_root::BUNDLE, FEED_SIGNATURE, true);
        let inputs = f.capture().unwrap(); // Real outer app signature and inventory pass.
        let error = prepare_with_clock(inputs, BackendKind::Qemu, inside_window).unwrap_err();
        assert!(format!("{error:#}").contains("digest"));
        assert!(!mvm_core::config::image_set_revocation_store_dir().exists());
        assert!(
            ImageSetRevocationStore::in_mvm_home()
                .load(inside_window())
                .is_err()
        );
    }
    #[test]
    fn preparation_refuses_expired_or_substituted_feed_and_missing_member() {
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(home.path());
        let kernel = b"replacement";
        let linux = coherent_application_replacement(kernel);
        let f = frame(kernel, &linux, published_root::BUNDLE, FEED_SIGNATURE, true);
        let error = prepare_with_clock(f.capture().unwrap(), BackendKind::Qemu, || {
            "2026-12-01T00:00:00Z".parse().unwrap()
        })
        .unwrap_err();
        assert!(format!("{error:#}").contains("expired"));
        let substituted = frame(
            kernel,
            &linux,
            published_root::BUNDLE,
            published_root::BUNDLE,
            true,
        );
        assert!(
            prepare_with_clock(
                substituted.capture().unwrap(),
                BackendKind::Qemu,
                inside_window
            )
            .is_err()
        );
        let missing = frame(
            kernel,
            &linux,
            published_root::BUNDLE,
            FEED_SIGNATURE,
            false,
        );
        assert!(missing.capture().is_err());
        assert!(!mvm_core::config::image_set_revocation_store_dir().exists());
        assert!(
            ImageSetRevocationStore::in_mvm_home()
                .load(inside_window())
                .is_err()
        );
    }
    #[test]
    fn canonical_selector_rejects_signature_role_substitution_and_revoked_policy() {
        struct Revoked;
        impl PackRevocationChecker for Revoked {
            fn status(&self, _: &KeyId, _: &Sha256Hex) -> RevocationStatus {
                RevocationStatus::Revoked {
                    reason: "unit policy withdrawal".into(),
                }
            }
        }
        let feed =
            verify_image_set_revocations(FEED, FEED_SIGNATURE, inside_window(), None).unwrap();
        let selected = select_from_root(
            published_root::MANIFEST,
            published_root::BUNDLE,
            GuestArch::host(),
            BackendKind::Qemu,
            &feed,
        )
        .unwrap();
        assert_eq!(
            selected.role,
            ImageSetRole::WorkloadKernel(WorkloadImageProfile::DefaultTenant)
        );
        assert!(
            select_from_root(
                published_root::MANIFEST,
                FEED_SIGNATURE,
                GuestArch::host(),
                BackendKind::Qemu,
                &feed
            )
            .is_err()
        );
        // Genuine root signature; this test checker only exercises policy
        // plumbing, not a purported signed revocation publication.
        assert!(
            select_from_root(
                published_root::MANIFEST,
                published_root::BUNDLE,
                GuestArch::host(),
                BackendKind::Qemu,
                &Revoked
            )
            .is_err()
        );
        assert!(
            select_from_root(
                published_root::MANIFEST,
                published_root::BUNDLE,
                GuestArch::host(),
                BackendKind::Mock,
                &feed
            )
            .is_err()
        );
    }
    #[test]
    #[ignore = "requires the actual pinned public kernel in MVM_TEST_CANONICAL_KERNEL; no download"]
    fn genuine_owner_rejects_substitution_and_retains_failed_start_generation() {
        let kernel = std::fs::read(
            std::env::var_os("MVM_TEST_CANONICAL_KERNEL").expect("public kernel path"),
        )
        .unwrap();
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(home.path());
        let frame = frame(
            &kernel,
            published_root::MANIFEST,
            published_root::BUNDLE,
            FEED_SIGNATURE,
            true,
        );
        let owner = Arc::new(
            prepare_with_clock(frame.capture().unwrap(), BackendKind::Hvf, inside_window).unwrap(),
        );
        let mut config = crate::vm_backend::VmStartConfig {
            name: "canonical-owner-unit".into(),
            ..Default::default()
        };
        owner.bind_to_config(&mut config).unwrap();
        owner
            .verify_config(&config, BackendKind::Hvf, &test_host())
            .unwrap();
        let mut replaced = config.clone();
        replaced.kernel_path = Some("/tmp/not-the-owned-kernel".into());
        assert!(
            owner
                .verify_config(&replaced, BackendKind::Hvf, &test_host())
                .is_err()
        );
        replaced = config.clone();
        replaced.name = "another-vm".into();
        assert!(
            owner
                .verify_config(&replaced, BackendKind::Hvf, &test_host())
                .is_err()
        );
        assert!(
            owner
                .verify_config(&config, BackendKind::Qemu, &test_host())
                .is_err()
        );
        let mut protocols = test_host();
        protocols.builder_cache_contract += 1;
        assert!(
            owner
                .verify_config(&config, BackendKind::Hvf, &protocols)
                .is_err()
        );
        let other = Arc::new(
            prepare_with_clock(frame.capture().unwrap(), BackendKind::Hvf, inside_window).unwrap(),
        );
        replaced = config.clone();
        replaced.canonical_kernel = Some(other);
        assert!(
            owner
                .verify_config(&replaced, BackendKind::Hvf, &test_host())
                .is_err()
        );
        let generation = owner.generation_dir().to_owned();
        let selected = owner.kernel_path();
        owner
            .retain_for_native_handoff(&config, BackendKind::Hvf, &test_host())
            .unwrap();
        assert!(
            owner
                .retain_for_native_handoff(&config, BackendKind::Hvf, &test_host())
                .is_err()
        );
        assert!(owner.bind_to_config(&mut config).is_err());
        // Model a failed native start by dropping every in-process owner.
        // No driver was invoked: this tests retention, not physical lifetime.
        drop(replaced);
        drop(config);
        let moved = owner;
        drop(moved);
        assert!(selected.exists());
        assert!(generation.exists());
        // Test-owned generation has never had a native reader.
        std::fs::remove_dir_all(generation).unwrap();
    }

    #[test]
    #[ignore = "requires the actual pinned public kernel in MVM_TEST_CANONICAL_KERNEL; no download"]
    fn genuine_kernel_preparation_is_owned_rechecked_and_not_native_admission() {
        let path = std::env::var_os("MVM_TEST_CANONICAL_KERNEL").expect("public kernel path");
        let kernel = std::fs::read(path).unwrap();
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(home.path());
        let f = frame(
            &kernel,
            published_root::MANIFEST,
            published_root::BUNDLE,
            FEED_SIGNATURE,
            true,
        );
        struct WithdrawnForUnit;
        impl PackRevocationChecker for WithdrawnForUnit {
            fn status(&self, _: &KeyId, _: &Sha256Hex) -> RevocationStatus {
                RevocationStatus::Revoked {
                    reason: "unit selected-root withdrawal".into(),
                }
            }
        }
        // Actual schema7 capture and genuine root signature; the withdrawal
        // decision is synthetic unit policy, not a signed v2 publication.
        assert!(
            select_canonical_kernel(&f.capture().unwrap(), BackendKind::Qemu, &WithdrawnForUnit)
                .is_err()
        );
        let prepared =
            prepare_with_clock(f.capture().unwrap(), BackendKind::Qemu, inside_window).unwrap();
        assert_eq!(prepared.pin(), &f.pin);
        let retry_inputs = f.capture().unwrap();
        let mutation =
            prepare_with_clock(f.capture().unwrap(), BackendKind::Qemu, inside_window).unwrap();
        let mutation_path = mutation
            .view_path
            .join(mutation.declaration.artifacts[0].name.as_str());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&mutation_path, std::fs::Permissions::from_mode(0o600))
                .unwrap();
        }
        std::fs::write(&mutation_path, b"changed selected bytes").unwrap();
        assert!(mutation.kernel_file_at(inside_window()).is_err());
        drop(mutation);
        let state_directory = mvm_core::config::image_set_revocation_store_dir();
        let state_before_substitution = std::fs::read(state_directory.join("feed.json")).unwrap();
        let checkpoint_before_substitution =
            std::fs::read(state_directory.join("checkpoint.json")).unwrap();
        let substituted = frame(
            &kernel,
            published_root::MANIFEST,
            FEED_SIGNATURE,
            FEED_SIGNATURE,
            true,
        );
        assert!(
            prepare_with_clock(
                substituted.capture().unwrap(),
                BackendKind::Qemu,
                inside_window
            )
            .is_err()
        );
        assert_eq!(
            std::fs::read(state_directory.join("feed.json")).unwrap(),
            state_before_substitution
        );
        assert_eq!(
            std::fs::read(state_directory.join("checkpoint.json")).unwrap(),
            checkpoint_before_substitution
        );
        let selected_path = prepared.view_path.clone();
        std::fs::write(&f.archive, b"original application path changed").unwrap();
        let moved = prepared;
        let digest = mvm_core::crypto::image_verify::sha256_reader(
            moved.kernel_file_at(inside_window()).unwrap(),
        )
        .unwrap();
        assert_eq!(digest, sha256_hex(&kernel));
        assert!(
            moved
                .kernel_file_at("2026-12-01T00:00:00Z".parse().unwrap())
                .is_err()
        );
        // Deterministically simulate the checkpoint-first boundary of an
        // interrupted/concurrent trusted local advance. Publication 2 here is
        // synthetic host state, NOT a claimed genuine signed v2 publication.
        let directory = mvm_core::config::image_set_revocation_store_dir();
        let checkpoint_path = directory.join("checkpoint.json");
        let state_path = directory.join("feed.json");
        let mut newer = moved
            .store
            .load(inside_window())
            .unwrap()
            .checkpoint()
            .clone();
        newer.publication += 1;
        newer.issued_at += chrono::Duration::seconds(1);
        newer.sha256 = Sha256Hex::from_bytes(b"synthetic checkpoint-first advance");
        let checkpoint_bytes = serde_json::to_vec(&newer).unwrap();
        std::fs::write(&checkpoint_path, &checkpoint_bytes).unwrap();
        let state_before = std::fs::read(&state_path).unwrap();
        assert!(
            moved.kernel_file_at(inside_window()).is_err(),
            "an already prepared owner must recheck effective current policy"
        );
        let error = prepare_with_clock(retry_inputs, BackendKind::Qemu, inside_window).unwrap_err();
        assert!(format!("{error:#}").contains("rolled back"), "{error:#}");
        assert_eq!(std::fs::read(&checkpoint_path).unwrap(), checkpoint_bytes);
        assert_eq!(std::fs::read(&state_path).unwrap(), state_before);
        drop(moved);
        assert!(!selected_path.exists());
    }
}
