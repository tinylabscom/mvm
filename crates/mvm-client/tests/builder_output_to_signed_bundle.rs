//! Builder output to a host-signed `.mvmpkg`, end to end, without booting.
//!
//! A staged workspace goes to a builder, the builder's output comes back over
//! the disk transport, the host checks it and signs it under the host key, and
//! a second home that trusts only that key's public half verifies and installs
//! the bundle.
//!
//! The guest is the one part played here: [`TarGuest`] reads the job the host
//! staged and writes the output tree the job script writes, then packs it onto
//! an output disk. Everything after that is the host's real path —
//! `read_output_disk`, `finalize_flake_job`, the orchestrator, the output
//! check, the bundler, and the registry install. The live counterpart, which
//! boots a real builder, is the `@live` bundle scenario in
//! `features/suites/s29_doc_examples/documented_build_live.feature`.

use std::path::{Path, PathBuf};

use ed25519_dalek::VerifyingKey;
use mvm_build::builder_disk_transport::{create_output_disk, read_output_disk, write_output_disk};
use mvm_build::builder_job_contract::{
    BUILDER_JOB_CONTRACT_VERSION, FailureCategory, JobOutcome, RESULT_FILE,
};
use mvm_build::builder_orchestrator::failure_category;
use mvm_build::builder_vm::{
    BuilderArtifacts, BuilderCapabilities, BuilderJob, BuilderMounts, BuilderVm, BuilderVmError,
    SIDECAR_FILENAME,
};
use mvm_build::builder_vm_runtime::{finalize_flake_job, stage_job_dir};
use mvm_client::bundle::{BundleSigner, HostBundleSigner};
use mvm_client::{BuilderBundleRequest, build_and_export_bundle_on};
use mvm_core::plan::bundle::{BundleRegistry, FsTrustStore, TrustStore, key_id_from_pubkey};

const ROOTFS: &[u8] = b"an ext4 image the flake built";
const KERNEL: &[u8] = b"a kernel the flake built";
const SIDECAR: &[u8] = br#"{"overlayAware":true,"runtimeLean":true}"#;
const HOST_KEY_FILE: &str = "host-signer.ed25519";

/// What the guest does with an output member.
#[derive(Clone)]
enum Member {
    Bytes(&'static [u8]),
    /// A link to a host path. The guest cannot read the host, but it chooses
    /// what its tar says, and a tar can say "this name is a link".
    LinkTo(PathBuf),
}

/// A builder guest that runs the staged job by writing its outputs.
struct TarGuest {
    scratch: PathBuf,
    rootfs: Member,
}

impl TarGuest {
    /// The output tree the job script leaves in `/out`, plus the outcome the
    /// guest init folds in beside it.
    fn write_out_tree(&self, tree: &Path) {
        std::fs::create_dir_all(tree).unwrap();
        match &self.rootfs {
            Member::Bytes(bytes) => std::fs::write(tree.join("rootfs.ext4"), bytes).unwrap(),
            Member::LinkTo(target) => {
                std::os::unix::fs::symlink(target, tree.join("rootfs.ext4")).unwrap();
            }
        }
        std::fs::write(tree.join("vmlinux"), KERNEL).unwrap();
        std::fs::write(tree.join(SIDECAR_FILENAME), SIDECAR).unwrap();
        let outcome = JobOutcome {
            contract_version: BUILDER_JOB_CONTRACT_VERSION,
            exit_code: 0,
            stderr_tail: String::new(),
            failure: None,
            build_ms: Some(1),
        };
        std::fs::write(
            tree.join(RESULT_FILE),
            serde_json::to_vec(&outcome).unwrap(),
        )
        .unwrap();
    }

    /// Pack `tree` onto `disk` as the guest's tar. Links stay links, the way
    /// the guest's own tar writes them.
    fn pack(tree: &Path, disk: &Path) {
        create_output_disk(disk, 1 << 20).unwrap();
        if std::fs::read_dir(tree)
            .unwrap()
            .all(|e| e.unwrap().file_type().unwrap().is_file())
        {
            write_output_disk(tree, disk).unwrap();
            return;
        }
        let file = std::fs::OpenOptions::new().write(true).open(disk).unwrap();
        let mut archive = tar::Builder::new(file);
        archive.follow_symlinks(false);
        archive.append_dir_all(".", tree).unwrap();
        archive.finish().unwrap();
    }
}

impl BuilderVm for TarGuest {
    fn run_build(
        &self,
        job: &BuilderJob,
        mounts: &BuilderMounts,
    ) -> Result<BuilderArtifacts, BuilderVmError> {
        // The host stages the job the guest reads.
        let job_dir = self.scratch.join("job");
        stage_job_dir(&job_dir, job, None, Some(&mounts.flake_src))?;
        assert!(job_dir.join("cmd.sh").is_file(), "the job script is staged");

        let tree = self.scratch.join("guest-out");
        self.write_out_tree(&tree);
        let disk = self.scratch.join("output.img");
        Self::pack(&tree, &disk);

        // From here on it is the host.
        read_output_disk(&disk, &mounts.artifact_out)
            .map_err(|e| BuilderVmError::ExtractionFailed(format!("{e:#}")))?;
        finalize_flake_job(&mounts.artifact_out, &mounts.artifact_out, "smoke-job")
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

/// One home that builds and signs, and the minimal workspace it builds.
struct Publisher {
    root: tempfile::TempDir,
}

impl Publisher {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let workspace = root.path().join("workspace");
        std::fs::create_dir_all(&workspace).unwrap();
        std::fs::write(
            workspace.join("flake.nix"),
            b"{ outputs = { self }: { }; }\n",
        )
        .unwrap();
        for dir in ["out", "bins", "guest"] {
            std::fs::create_dir_all(root.path().join(dir)).unwrap();
        }
        Self { root }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.root.path().join(name)
    }

    fn signer(&self) -> HostBundleSigner {
        HostBundleSigner::load_at(&self.path("keys")).unwrap()
    }

    fn key_file(&self) -> PathBuf {
        self.path("keys").join(HOST_KEY_FILE)
    }

    fn request(&self) -> BuilderBundleRequest {
        BuilderBundleRequest {
            workspace_root: self.path("workspace"),
            flake_ref: "/work".to_string(),
            attr_path: "packages.aarch64-linux.default".to_string(),
            artifact_out: self.path("out"),
            host_nix_store: None,
            host_bin_dir: self.path("bins"),
            arch_label: "aarch64".to_string(),
            profile: None,
            label: Some("smoke".to_string()),
            bundle_out: self.path("dist/smoke.mvmpkg"),
            debug_out: None,
        }
    }

    fn guest(&self, rootfs: Member) -> TarGuest {
        TarGuest {
            scratch: self.path("guest"),
            rootfs,
        }
    }
}

/// Enrol `key` the way `mvmctl trust add` does: its raw public bytes, named
/// by key id, in the trust directory.
fn trust_only(dir: &Path, key: &VerifyingKey) -> FsTrustStore {
    std::fs::create_dir_all(dir).unwrap();
    let key_id = key_id_from_pubkey(key);
    std::fs::write(dir.join(format!("{}.pub", key_id.0)), key.to_bytes()).unwrap();
    FsTrustStore::new(dir)
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Every regular file under `dir`.
fn files_under(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut pending = vec![dir.to_path_buf()];
    while let Some(next) = pending.pop() {
        for entry in std::fs::read_dir(&next).unwrap() {
            let entry = entry.unwrap();
            let kind = entry.file_type().unwrap();
            if kind.is_dir() {
                pending.push(entry.path());
            } else if kind.is_file() {
                out.push(entry.path());
            }
        }
    }
    out
}

#[test]
fn a_staged_workspace_builds_seals_and_installs_in_a_home_that_trusts_only_the_public_key() {
    let publisher = Publisher::new();
    let signer = publisher.signer();
    let request = publisher.request();

    let sealed =
        build_and_export_bundle_on(&request, &signer, &publisher.guest(Member::Bytes(ROOTFS)))
            .expect("the build is sealed");

    // The private key is nowhere the guest could have read, and not in what
    // was shipped.
    let seed = std::fs::read(publisher.key_file()).unwrap();
    let archive = std::fs::read(&sealed.bundle_path).unwrap();
    assert!(
        !contains(&archive, &seed),
        "the bundle carries the private key"
    );
    for path in files_under(&publisher.path("guest"))
        .into_iter()
        .chain(files_under(&publisher.path("workspace")))
    {
        assert!(
            !contains(&std::fs::read(&path).unwrap(), &seed),
            "{} carries the private key",
            path.display()
        );
    }

    // A home with nothing but the public half verifies and installs it.
    let consumer = tempfile::tempdir().unwrap();
    let trust = trust_only(
        &consumer.path().join("trusted-publishers"),
        &signer.verifying_key(),
    );
    let installed = BundleRegistry::new(consumer.path().join("bundles"))
        .install_file(&sealed.bundle_path, &trust, false)
        .expect("installs in a home that trusts the host key");

    assert_eq!(installed.manifest.key_id, signer.key_id());
    assert_eq!(
        std::fs::read(installed.root.join("artifacts/rootfs.ext4")).unwrap(),
        ROOTFS
    );
    assert_eq!(
        std::fs::read(installed.root.join("artifacts/vmlinux")).unwrap(),
        KERNEL
    );
    assert_eq!(
        std::fs::read(installed.root.join("artifacts").join(SIDECAR_FILENAME)).unwrap(),
        SIDECAR
    );
    let provenance = installed
        .manifest
        .build_provenance()
        .expect("the build is recorded");
    assert_eq!(provenance.input_ref, "/work#packages.aarch64-linux.default");
    assert_eq!(
        provenance.artifacts.rootfs,
        Some(mvm_core::plan::sha256_hex(ROOTFS))
    );
}

#[test]
fn a_home_that_does_not_trust_the_host_key_refuses_the_bundle() {
    let publisher = Publisher::new();
    let sealed = build_and_export_bundle_on(
        &publisher.request(),
        &publisher.signer(),
        &publisher.guest(Member::Bytes(ROOTFS)),
    )
    .expect("the build is sealed");

    let consumer = tempfile::tempdir().unwrap();
    let stranger = ed25519_dalek::SigningKey::from_bytes(&[42; 32]).verifying_key();
    let trust = trust_only(&consumer.path().join("trusted-publishers"), &stranger);
    assert!(trust.lookup(&publisher.signer().key_id()).is_none());

    BundleRegistry::new(consumer.path().join("bundles"))
        .install_file(&sealed.bundle_path, &trust, false)
        .expect_err("an untrusted publisher is refused");
}

/// A compromised guest cannot read the host key, but it can hand back a tar
/// whose rootfs is a link to it. Followed, that link would put the private
/// key into a bundle signed by that same key.
#[test]
fn a_guest_that_links_its_rootfs_to_the_host_key_gets_nothing_signed() {
    let publisher = Publisher::new();
    let signer = publisher.signer();
    let request = publisher.request();
    let key_file = publisher.key_file();
    let seed = std::fs::read(&key_file).unwrap();

    let err = build_and_export_bundle_on(
        &request,
        &signer,
        &publisher.guest(Member::LinkTo(key_file)),
    )
    .expect_err("a linked rootfs is refused");

    assert_eq!(failure_category(&err), FailureCategory::OutputContract);
    assert!(format!("{err:#}").contains("symbolic link"), "{err:#}");
    assert!(!request.bundle_out.exists(), "nothing was sealed");
    for path in files_under(&request.artifact_out) {
        assert!(
            !contains(&std::fs::read(&path).unwrap(), &seed),
            "{} holds the host key",
            path.display()
        );
    }
}
