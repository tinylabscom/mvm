//! Protected checkpoint capture, storage, mirroring, and restore.

use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Result;
use mvm_core::checkpoint::{
    CheckpointDigest, CheckpointId, CheckpointKeyDomain, CheckpointMeta, CheckpointProtection,
    ContentBlob, DeviceAnchors,
};
use mvm_core::crypto::checkpoint_object::{DomainKeys, ObjectFrame, ObjectKind, seal};
use mvm_fs::snapshot_store::FsSnapshotStore;
use sha2::Digest as _;

use super::*;
use crate::vm::snapshot_key::SnapshotKey;

/// A run of bytes that must never appear in anything a protected capture
/// leaves on disk.
const MARKER: &[u8] = b"PLAINTEXT-CHECKPOINT-MARKER:";

/// Custody over fixed roots: one per domain, chosen by the test.
struct FixedCustody {
    root: u8,
    refuse: bool,
}

impl FixedCustody {
    fn with_root(root: u8) -> Arc<Self> {
        Arc::new(Self {
            root,
            refuse: false,
        })
    }

    fn refusing() -> Arc<Self> {
        Arc::new(Self {
            root: 0,
            refuse: true,
        })
    }
}

impl CheckpointKeyCustody for FixedCustody {
    fn domain_keys(&self, domain: &CheckpointKeyDomain) -> Result<DomainKeys, CheckpointKeyError> {
        if self.refuse {
            return Err(CheckpointKeyError::Host(
                crate::vm::snapshot_key::SnapshotKeyError::Missing,
            ));
        }
        derive_domain_keys(
            domain,
            &SnapshotKey::from_bytes(vec![self.root; 32]).unwrap(),
        )
    }
}

fn protected_store(root: &Path) -> CheckpointStore {
    CheckpointStore::at(root).with_key_custody(FixedCustody::with_root(7))
}

fn keys(domain: &CheckpointKeyDomain) -> DomainKeys {
    FixedCustody::with_root(7).domain_keys(domain).unwrap()
}

/// Two full chunks of marked bytes, a zero chunk, and a short tail.
fn marked_bytes(salt: u8) -> Vec<u8> {
    let chunk = chunks::CHUNK_SIZE;
    let mut bytes = Vec::with_capacity(chunk * 3 + 4096);
    while bytes.len() < chunk * 2 {
        bytes.extend_from_slice(MARKER);
        bytes.push(salt);
    }
    bytes.truncate(chunk * 2);
    bytes.extend(std::iter::repeat_n(0u8, chunk));
    bytes.extend_from_slice(MARKER);
    bytes.extend(std::iter::repeat_n(salt, 4096 - MARKER.len()));
    bytes
}

fn write_rootfs(dir: &Path, salt: u8) -> PathBuf {
    std::fs::create_dir_all(dir).unwrap();
    let rootfs = dir.join("rootfs.ext4");
    std::fs::write(&rootfs, marked_bytes(salt)).unwrap();
    std::fs::write(dir.join("rootfs.verity"), [MARKER, b"verity"].concat()).unwrap();
    std::fs::write(dir.join("rootfs.roothash"), [MARKER, b"roothash"].concat()).unwrap();
    rootfs
}

fn capture_quick(
    store: &CheckpointStore,
    source: &Path,
    id: &str,
    domain: CheckpointKeyDomain,
) -> Result<CheckpointMeta> {
    capture_fs_quick(
        store,
        CaptureFsQuickParams {
            id: CheckpointId::new(id),
            vm_name: format!("vm-{id}"),
            rootfs: source.to_path_buf(),
            supervisor_config_digest: "cfg".into(),
            runtime_overlay_version: None,
            tag: None,
            created_unix: 1,
            quiesced: true,
            grants: None,
            key_domain: domain,
        },
    )
}

struct MarkedControl {
    rootfs: PathBuf,
    config: PathBuf,
    events: RefCell<Vec<&'static str>>,
}

impl MarkedControl {
    fn new(dir: &Path) -> Self {
        let rootfs = write_rootfs(dir, 1);
        let config = dir.join("supervisor-config.json");
        std::fs::write(&config, [MARKER, b"config"].concat()).unwrap();
        Self {
            rootfs,
            config,
            events: RefCell::new(Vec::new()),
        }
    }
}

impl VmFullControl for MarkedControl {
    fn pause(&self) -> Result<()> {
        self.events.borrow_mut().push("pause");
        Ok(())
    }
    fn resume(&self) -> Result<()> {
        self.events.borrow_mut().push("resume");
        Ok(())
    }
    fn save_memory(&self, memory_path: &Path) -> Result<()> {
        std::fs::write(memory_path, marked_bytes(9)).unwrap();
        std::fs::write(
            format!("{}.machine-id", memory_path.display()),
            [MARKER, b"machine-id"].concat(),
        )
        .unwrap();
        Ok(())
    }
    fn rootfs_path(&self) -> Result<PathBuf> {
        Ok(self.rootfs.clone())
    }
    fn extra_content(&self, content_dir: &Path) -> Result<Vec<ContentBlob>> {
        let path = content_dir.join(mvm_core::checkpoint::HVF_FRAME_BLOB);
        std::fs::write(&path, [MARKER, b"frame"].concat()).unwrap();
        Ok(vec![ContentBlob {
            name: mvm_core::checkpoint::HVF_FRAME_BLOB.into(),
            sha256: sha256_file_hex(&path)?,
        }])
    }
    fn supervisor_config_path(&self) -> Result<Option<PathBuf>> {
        Ok(Some(self.config.clone()))
    }
    fn device_anchors(&self) -> Result<DeviceAnchors> {
        Ok(DeviceAnchors {
            rootfs: self.rootfs.clone(),
            rootfs_verity: Some(self.rootfs.with_file_name("rootfs.verity")),
            config: None,
            secrets: None,
            identity: None,
            vsock: PathBuf::from("/tmp/vsock"),
        })
    }
}

fn vm_full_params(id: &str, domain: CheckpointKeyDomain, config: &Path) -> CaptureVmFullParams {
    CaptureVmFullParams {
        id: CheckpointId::new(id),
        vm_name: format!("vm-{id}"),
        supervisor_config_digest: "cfg".into(),
        runtime_overlay_version: None,
        supervisor_config_src: Some(config.to_path_buf()),
        tag: None,
        created_unix: 1,
        retain_paused: false,
        grants: None,
        parent: None,
        session: None,
        workspace_volumes: Vec::new(),
        key_domain: domain,
    }
}

fn capture_full(store: &CheckpointStore, dir: &Path, id: &str) -> CheckpointMeta {
    let control = MarkedControl::new(dir);
    capture_vm_full(
        store,
        vm_full_params(id, CheckpointKeyDomain::host(), &control.config),
        &control,
    )
    .unwrap()
}

fn regular_files(root: &Path) -> Vec<PathBuf> {
    if !root.exists() {
        return Vec::new();
    }
    chunks::regular_files_recursive(root).unwrap()
}

fn assert_no_plaintext(root: &Path) {
    for path in regular_files(root) {
        let bytes = std::fs::read(&path).unwrap();
        assert!(
            !bytes.windows(MARKER.len()).any(|window| window == MARKER),
            "{} holds plaintext",
            path.display()
        );
    }
}

struct Audited;
impl CheckpointChainAnchor for Audited {
    fn recorded_creation_tenant(&self, _meta: &CheckpointMeta) -> Result<Option<String>> {
        Ok(Some("local".into()))
    }
    fn recorded_creation_digest(&self, meta: &CheckpointMeta) -> Result<Option<CheckpointDigest>> {
        Ok(Some(meta.compute_meta_digest()))
    }
}

fn fork_quick(
    store: &CheckpointStore,
    parent: &CheckpointMeta,
    dest: &Path,
) -> Result<CheckpointMeta> {
    fork_checkpoint(
        store,
        ForkParams {
            checkpoint: parent.id.clone(),
            child_id: CheckpointId::new(format!("{}-child", parent.id)),
            child_vm_name: "child".into(),
            dest_dir: dest.to_path_buf(),
            created_unix: 2,
            parent_liveness: ForkParentLiveness::MustBeStopped,
            child_plan_json: None,
            child_tenant_id: None,
        },
        &Audited,
    )
}

fn first_chunk_link(store: &CheckpointStore, meta: &CheckpointMeta) -> PathBuf {
    let membership = store.content_dir(&meta.id).join(chunks::MEMBERSHIP_DIR);
    let mut links = regular_files(&membership);
    links.sort();
    links.into_iter().next().expect("a stored chunk")
}

fn replace_file(path: &Path, bytes: &[u8]) {
    std::fs::remove_file(path).unwrap();
    std::fs::write(path, bytes).unwrap();
}

// ── capture ──────────────────────────────────────────────────────────────────

#[test]
fn a_capture_without_a_key_refuses_before_the_vm_is_paused_or_anything_staged() {
    let tmp = tempfile::tempdir().unwrap();
    let store =
        CheckpointStore::at(tmp.path().join("store")).with_key_custody(FixedCustody::refusing());
    let control = MarkedControl::new(&tmp.path().join("vm"));
    let error = capture_vm_full(
        &store,
        vm_full_params("nokey", CheckpointKeyDomain::host(), &control.config),
        &control,
    )
    .expect_err("a capture whose key cannot be admitted must refuse");
    assert!(
        format!("{error:#}").contains("host snapshot key"),
        "{error:#}"
    );
    assert!(
        control.events.borrow().is_empty(),
        "the VM was never paused"
    );
    assert!(regular_files(store.root()).is_empty(), "nothing was staged");

    let quick = capture_quick(
        &store,
        &write_rootfs(&tmp.path().join("q"), 2),
        "nokey-quick",
        CheckpointKeyDomain::host(),
    );
    assert!(quick.is_err());
    assert!(regular_files(store.root()).is_empty());
}

#[cfg(unix)]
#[test]
fn staging_is_admitted_private_before_a_capture_writes_plaintext() {
    use std::os::unix::fs::PermissionsExt as _;
    let tmp = tempfile::tempdir().unwrap();
    let store = protected_store(&tmp.path().join("store"));
    let staging_root = store.root().join(staging::STAGING_DIR);
    std::fs::create_dir_all(&staging_root).unwrap();
    std::fs::set_permissions(&staging_root, std::fs::Permissions::from_mode(0o755)).unwrap();

    capture_quick(
        &store,
        &write_rootfs(&tmp.path().join("s"), 3),
        "s",
        CheckpointKeyDomain::host(),
    )
    .unwrap();
    let mode = std::fs::metadata(&staging_root)
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o700, "a widened staging area is narrowed before use");

    // A staging area that is a link elsewhere is never written through.
    std::fs::remove_dir_all(&staging_root).unwrap();
    let elsewhere = tmp.path().join("elsewhere");
    std::fs::create_dir_all(&elsewhere).unwrap();
    std::os::unix::fs::symlink(&elsewhere, &staging_root).unwrap();
    let error = capture_quick(
        &store,
        &write_rootfs(&tmp.path().join("t"), 4),
        "t",
        CheckpointKeyDomain::host(),
    )
    .expect_err("a linked staging area is refused");
    assert!(
        format!("{error:#}").contains("not a directory"),
        "{error:#}"
    );
    assert!(regular_files(&elsewhere).is_empty());
}

#[test]
fn a_protected_capture_leaves_only_sealed_objects_at_rest() {
    let tmp = tempfile::tempdir().unwrap();
    let store = protected_store(&tmp.path().join("store"));
    let quick = capture_quick(
        &store,
        &write_rootfs(&tmp.path().join("q"), 5),
        "quick",
        CheckpointKeyDomain::host(),
    )
    .unwrap();
    let full = capture_full(&store, &tmp.path().join("vm"), "full");

    for meta in [&quick, &full] {
        assert_eq!(meta.protection, CheckpointProtection::SealedV1);
        assert_eq!(meta.compute_meta_digest(), meta.meta_digest);
        let content = store.content_dir(&meta.id);
        sealed::ensure_only_sealed(&content, &meta.content).unwrap();
    }
    assert_no_plaintext(store.root());
}

#[test]
fn every_blob_including_backend_extras_is_a_sealed_envelope_in_its_domain() {
    let tmp = tempfile::tempdir().unwrap();
    let store = protected_store(&tmp.path().join("store"));
    let full = capture_full(&store, &tmp.path().join("vm"), "full");
    let names: Vec<&str> = full.content.iter().map(|b| b.name.as_str()).collect();
    for expected in [
        "rootfs.ext4",
        "memory.bin",
        "machine-id",
        mvm_core::checkpoint::HVF_FRAME_BLOB,
        SUPERVISOR_CONFIG_FILE_NAME,
        "rootfs.verity",
        "device-anchors.json",
    ] {
        assert!(
            names.contains(&expected),
            "{expected} missing from {names:?}"
        );
    }
    let content = store.content_dir(&full.id);
    for blob in &full.content {
        let bytes = std::fs::read(sealed::index_path(&content, &blob.name)).unwrap();
        let frame = ObjectFrame::parse(&bytes).unwrap();
        assert_eq!(frame.kind(), ObjectKind::Index, "{}", blob.name);
        assert_eq!(frame.domain(), "host");
    }
    let objects = regular_files(&store.root().join(chunks::OBJECTS_DIR));
    assert!(!objects.is_empty());
    for object in objects {
        let bytes = std::fs::read(&object).unwrap();
        let frame = ObjectFrame::parse(&bytes).unwrap();
        assert_eq!(frame.kind(), ObjectKind::Chunk);
        assert_eq!(
            object.file_name().unwrap().to_string_lossy(),
            frame.reference().to_string()
        );
    }
}

#[cfg(unix)]
#[test]
fn deduplication_shares_objects_within_a_domain_and_never_across_domains() {
    use std::os::unix::fs::MetadataExt as _;
    let tmp = tempfile::tempdir().unwrap();
    let store = protected_store(&tmp.path().join("store"));
    let source = tmp.path().join("same");
    let a = CheckpointKeyDomain::tenant("a").unwrap();
    let b = CheckpointKeyDomain::tenant("b").unwrap();
    let a1 = capture_quick(&store, &write_rootfs(&source, 6), "a1", a.clone()).unwrap();
    let a2 = capture_quick(&store, &write_rootfs(&source, 6), "a2", a).unwrap();
    let b1 = capture_quick(&store, &write_rootfs(&source, 6), "b1", b).unwrap();

    let inode = |meta: &CheckpointMeta| {
        std::fs::metadata(first_chunk_link(&store, meta))
            .unwrap()
            .ino()
    };
    assert_eq!(
        inode(&a1),
        inode(&a2),
        "one domain stores identical chunks once"
    );
    assert_ne!(
        inode(&a1),
        inode(&b1),
        "another domain never shares an object"
    );
    let name = |meta: &CheckpointMeta| {
        first_chunk_link(&store, meta)
            .file_name()
            .unwrap()
            .to_owned()
    };
    assert_ne!(name(&a1), name(&b1), "references are keyed per domain");
}

#[test]
fn an_existing_object_is_reused_only_after_it_opens_as_the_same_chunk() {
    let tmp = tempfile::tempdir().unwrap();
    let store = protected_store(&tmp.path().join("store"));
    let a = CheckpointKeyDomain::tenant("a").unwrap();
    let b = CheckpointKeyDomain::tenant("b").unwrap();
    let source = write_rootfs(&tmp.path().join("src"), 8);
    let first_chunk = &std::fs::read(&source).unwrap()[..chunks::CHUNK_SIZE];

    // Plant, under the name tenant b's chunk will be filed as, an object
    // sealed for tenant a: same plaintext, wrong domain.
    let name = keys(&b)
        .reference_for(ObjectKind::Chunk, first_chunk)
        .unwrap()
        .to_string();
    let foreign = seal(&keys(&a), ObjectKind::Chunk, first_chunk).unwrap();
    let pool = chunks::ObjectPool::new(store.root(), &b).unwrap();
    let planted = pool.object_path_for(&name);
    std::fs::create_dir_all(planted.parent().unwrap()).unwrap();
    std::fs::write(&planted, &foreign.bytes).unwrap();

    let error = capture_quick(&store, &source, "b1", b).expect_err("a foreign object is refused");
    assert!(format!("{error:#}").contains("did not open"), "{error:#}");
    assert_eq!(
        std::fs::read(&planted).unwrap(),
        foreign.bytes,
        "never overwritten"
    );
    assert!(
        store.read_meta(&CheckpointId::new("b1")).is_err(),
        "nothing published"
    );
}

#[test]
fn snapshot_mirrors_receive_only_opaque_content() {
    let tmp = tempfile::tempdir().unwrap();
    let mut env = mvm_core::util::test_env::TestEnv::new();
    env.set("MVM_HOME", tmp.path().join("home"));
    let store = protected_store(&tmp.path().join("store"));
    let snapshots = FsSnapshotStore::new(tmp.path().join("snapshots")).unwrap();
    let control = MarkedControl::new(&tmp.path().join("vm"));
    let meta = capture_vm_full_into_snapshot_store(
        &store,
        vm_full_params("mirrored", CheckpointKeyDomain::host(), &control.config),
        &control,
        &snapshots,
    )
    .unwrap();
    assert!(meta.snapshot_id.is_some());
    assert!(!regular_files(snapshots.root()).is_empty());
    assert_no_plaintext(snapshots.root());
    assert_no_plaintext(store.root());

    let trusted = RecordingBackend::default();
    let control = MarkedControl::new(&tmp.path().join("vm2"));
    let meta = capture_vm_full_to_trusted_snapshot_backend(
        &store,
        vm_full_params("trusted", CheckpointKeyDomain::host(), &control.config),
        &control,
        &trusted,
    )
    .unwrap();
    let staged = trusted
        .staged
        .lock()
        .unwrap()
        .clone()
        .expect("the backend was handed content");
    assert!(!staged.is_empty());
    for (name, bytes) in staged {
        assert!(
            !bytes.windows(MARKER.len()).any(|window| window == MARKER),
            "the trusted mirror was handed plaintext in {}",
            name.display()
        );
    }
    assert!(meta.snapshot_id.unwrap().starts_with("trusted-checkpoint-"));
}

/// A published file's path relative to the publication, and its bytes.
type StagedFile = (PathBuf, Vec<u8>);

/// A trusted backend that records every file it is asked to publish, by its
/// path relative to the published directory.
#[derive(Default)]
struct RecordingBackend {
    staged: std::sync::Mutex<Option<Vec<StagedFile>>>,
}

impl mvm_fs::trusted_snapshot::TrustedSnapshotBackend for RecordingBackend {
    fn stage(
        &self,
        _id: &mvm_fs::snapshot_store::SnapshotId,
        source: &Path,
    ) -> std::io::Result<()> {
        let files = regular_files(source)
            .into_iter()
            .map(|path| {
                let bytes = std::fs::read(&path).unwrap();
                (path.strip_prefix(source).unwrap().to_path_buf(), bytes)
            })
            .collect();
        *self.staged.lock().unwrap() = Some(files);
        Ok(())
    }
    fn seal(&self, _id: &mvm_fs::snapshot_store::SnapshotId) -> std::io::Result<()> {
        Ok(())
    }
    fn validate(
        &self,
        _id: &mvm_fs::snapshot_store::SnapshotId,
        _manifest_digest: &str,
        _trusted_signer: &[u8; 32],
    ) -> std::io::Result<()> {
        Ok(())
    }
    fn materialize(
        &self,
        _id: &mvm_fs::snapshot_store::SnapshotId,
        dst: &Path,
    ) -> std::io::Result<mvm_fs::clone::CloneStrategy> {
        for (path, bytes) in self.staged.lock().unwrap().iter().flatten() {
            let target = dst.join(path);
            std::fs::create_dir_all(target.parent().unwrap())?;
            std::fs::write(target, bytes)?;
        }
        Ok(mvm_fs::clone::CloneStrategy::Copied)
    }
    fn remove(&self, _id: &mvm_fs::snapshot_store::SnapshotId) -> std::io::Result<()> {
        Ok(())
    }
    fn name(&self) -> &'static str {
        "recording"
    }
}

#[test]
fn a_failed_protected_capture_publishes_nothing_and_keeps_the_last_generation() {
    let tmp = tempfile::tempdir().unwrap();
    let store = protected_store(&tmp.path().join("store"));
    let first = capture_quick(
        &store,
        &write_rootfs(&tmp.path().join("g1"), 10),
        "gen",
        CheckpointKeyDomain::host(),
    )
    .unwrap();

    // The next generation's first chunk collides with a corrupt pool entry,
    // so sealing fails partway through.
    let source = write_rootfs(&tmp.path().join("g2"), 11);
    let chunk = &std::fs::read(&source).unwrap()[..chunks::CHUNK_SIZE];
    let name = keys(&CheckpointKeyDomain::host())
        .reference_for(ObjectKind::Chunk, chunk)
        .unwrap()
        .to_string();
    let planted = chunks::ObjectPool::new(store.root(), &CheckpointKeyDomain::host())
        .unwrap()
        .object_path_for(&name);
    std::fs::create_dir_all(planted.parent().unwrap()).unwrap();
    std::fs::write(&planted, b"torn object").unwrap();
    capture_quick(&store, &source, "gen", CheckpointKeyDomain::host())
        .expect_err("a capture that cannot seal everything refuses");

    assert_eq!(
        store.read_meta(&first.id).unwrap(),
        first,
        "last generation kept"
    );
    verify_content(&store, &first).unwrap();
    assert!(
        regular_files(&store.root().join(staging::STAGING_DIR)).is_empty(),
        "the failed attempt's staging, plaintext included, is gone"
    );
    let dest = tmp.path().join("restored");
    fork_quick(&store, &first, &dest).unwrap();
    assert_eq!(
        std::fs::read(dest.join("rootfs.ext4")).unwrap(),
        marked_bytes(10)
    );
}

#[test]
fn a_tenant_checkpoint_never_opens_under_the_host_domains_keys() {
    struct HostKeysForEveryone;
    impl CheckpointKeyCustody for HostKeysForEveryone {
        fn domain_keys(
            &self,
            _domain: &CheckpointKeyDomain,
        ) -> Result<DomainKeys, CheckpointKeyError> {
            Ok(keys(&CheckpointKeyDomain::host()))
        }
    }
    let tmp = tempfile::tempdir().unwrap();
    let store = protected_store(&tmp.path().join("store"));
    let tenant = CheckpointKeyDomain::tenant("acme").unwrap();
    let meta = capture_quick(
        &store,
        &write_rootfs(&tmp.path().join("t"), 12),
        "t",
        tenant,
    )
    .unwrap();

    let confused =
        CheckpointStore::at(store.root()).with_key_custody(Arc::new(HostKeysForEveryone));
    let error = verify_content(&confused, &meta).expect_err("host keys never open tenant content");
    assert!(format!("{error:#}").contains("Domain"), "{error:#}");
}

// ── restore ──────────────────────────────────────────────────────────────────

#[test]
fn a_protected_fs_quick_checkpoint_forks_to_the_captured_bytes() {
    let tmp = tempfile::tempdir().unwrap();
    let store = protected_store(&tmp.path().join("store"));
    let parent = capture_quick(
        &store,
        &write_rootfs(&tmp.path().join("p"), 13),
        "p",
        CheckpointKeyDomain::host(),
    )
    .unwrap();
    let dest = tmp.path().join("child");
    let child = fork_quick(&store, &parent, &dest).unwrap();
    assert_eq!(child.protection, CheckpointProtection::SealedV1);
    assert_eq!(
        std::fs::read(dest.join("rootfs.ext4")).unwrap(),
        marked_bytes(13)
    );
    assert_eq!(
        std::fs::read(dest.join("rootfs.verity")).unwrap(),
        [MARKER, b"verity"].concat()
    );
    let leftovers: Vec<_> = regular_files(&dest)
        .into_iter()
        .filter(|path| path.to_string_lossy().contains(sealed::SEALED_INDEX_SUFFIX))
        .collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");
    assert!(
        !store.root().join(chunks::MATERIALIZATIONS_DIR).exists(),
        "protected content never enters the shared materialization cache"
    );
    assert_eq!(
        materialized_blob_sha256(&store, &parent, "rootfs.ext4").unwrap(),
        hex::encode(sha2::Sha256::digest(marked_bytes(13)))
    );
}

/// The rootfs and memory bytes, manifest, and staging dir a restore saw.
type SeenRestoreInputs = (Vec<u8>, Vec<u8>, Vec<ContentBlob>, PathBuf);

#[derive(Default)]
struct SeenRestore {
    seen: RefCell<Option<SeenRestoreInputs>>,
}

impl VmFullRestore for SeenRestore {
    fn restore(
        &self,
        _target_vm: &str,
        rootfs_src: &Path,
        memory: &Path,
        machine_id: &Path,
        config_src: Option<&Path>,
        content: &[ContentBlob],
    ) -> Result<()> {
        assert_eq!(
            std::fs::read(machine_id).unwrap(),
            [MARKER, b"machine-id"].concat()
        );
        assert_eq!(
            std::fs::read(config_src.expect("the launch config is staged")).unwrap(),
            [MARKER, b"config"].concat()
        );
        *self.seen.borrow_mut() = Some((
            std::fs::read(rootfs_src).unwrap(),
            std::fs::read(memory).unwrap(),
            content.to_vec(),
            rootfs_src.parent().unwrap().to_path_buf(),
        ));
        Ok(())
    }
}

#[test]
fn a_protected_vm_full_checkpoint_restores_from_private_staging_it_then_removes() {
    let tmp = tempfile::tempdir().unwrap();
    let store = protected_store(&tmp.path().join("store"));
    let meta = capture_full(&store, &tmp.path().join("vm"), "full");
    let restorer = SeenRestore::default();
    restore_checkpoint(
        &store,
        RestoreParams {
            checkpoint: meta.id.clone(),
            target_vm: "vm-full".into(),
            tenant: "local".into(),
        },
        &restorer,
        &Audited,
    )
    .unwrap();
    let (rootfs, memory, content, scratch) = restorer.seen.borrow_mut().take().unwrap();
    assert_eq!(rootfs, marked_bytes(1));
    assert_eq!(memory, marked_bytes(9));
    assert!(
        scratch.starts_with(store.root()),
        "staging lives with the store"
    );
    assert!(
        !scratch.exists(),
        "the restore removed its plaintext staging"
    );
    // A backend that verifies on load is handed the plaintext digests.
    let frame = content
        .iter()
        .find(|blob| blob.name == mvm_core::checkpoint::HVF_FRAME_BLOB)
        .unwrap();
    assert_eq!(
        frame.sha256,
        hex::encode(sha2::Sha256::digest([MARKER, b"frame"].concat()))
    );
    assert!(!store.root().join(chunks::MATERIALIZATIONS_DIR).exists());
}

#[test]
fn a_protected_vm_full_fork_hands_the_restorer_plaintext_digests() {
    let tmp = tempfile::tempdir().unwrap();
    let store = protected_store(&tmp.path().join("store"));
    let parent = capture_full(&store, &tmp.path().join("vm"), "parent");
    let plan = mvm_core::plan::test_support::PlanFixture::new()
        .tenant("local")
        .workload("fc-childvm")
        .build();
    let signer = ed25519_dalek::SigningKey::from_bytes(&[91u8; 32]);
    let signed = mvm_core::plan::sign_plan(&plan, &signer, "test-signer");
    let seen: RefCell<Option<Vec<ContentBlob>>> = RefCell::new(None);
    let dest = tmp.path().join("child");
    let restore = |child: &RestoredChild<'_>| -> Result<()> {
        *seen.borrow_mut() = Some(child.content.to_vec());
        Ok(())
    };
    let child = fork_vm_full(
        &store,
        ForkParams {
            checkpoint: parent.id.clone(),
            child_id: CheckpointId::new("child"),
            child_vm_name: "child-vm".into(),
            dest_dir: dest.clone(),
            created_unix: 2,
            parent_liveness: ForkParentLiveness::MayBeRunning,
            child_plan_json: Some(serde_json::to_string(&signed).unwrap()),
            child_tenant_id: Some("local".into()),
        },
        &restore,
        &Audited,
    )
    .unwrap();
    assert_eq!(child.protection, CheckpointProtection::SealedV1);
    let content = seen.into_inner().unwrap();
    let memory = content.iter().find(|b| b.name == "memory.bin").unwrap();
    assert_eq!(
        memory.sha256,
        hex::encode(sha2::Sha256::digest(marked_bytes(9)))
    );
    assert_eq!(
        std::fs::read(dest.join("memory.bin")).unwrap(),
        marked_bytes(9)
    );
}

#[test]
fn the_wrong_key_releases_no_plaintext() {
    let tmp = tempfile::tempdir().unwrap();
    let store = protected_store(&tmp.path().join("store"));
    let meta = capture_quick(
        &store,
        &write_rootfs(&tmp.path().join("p"), 14),
        "p",
        CheckpointKeyDomain::host(),
    )
    .unwrap();
    let wrong = CheckpointStore::at(store.root()).with_key_custody(FixedCustody::with_root(8));
    assert!(verify_content(&wrong, &meta).is_err());
    let dest = tmp.path().join("dest");
    materialize_checkpoint_blobs(&wrong, &meta, &dest).expect_err("wrong key refuses");
    assert!(
        regular_files(&dest).is_empty(),
        "nothing, not even a partial file, is left"
    );
}

#[test]
fn a_protected_record_needs_custody_and_a_legacy_one_is_never_read_as_protected() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("store");
    let protected = capture_quick(
        &protected_store(&root),
        &write_rootfs(&tmp.path().join("p"), 15),
        "protected",
        CheckpointKeyDomain::host(),
    )
    .unwrap();
    let legacy_store = CheckpointStore::at(&root);
    let error = verify_content(&legacy_store, &protected).expect_err("no custody, no opening");
    assert!(format!("{error:#}").contains("no key custody"), "{error:#}");

    let legacy = capture_quick(
        &legacy_store,
        &write_rootfs(&tmp.path().join("l"), 16),
        "legacy",
        CheckpointKeyDomain::host(),
    )
    .unwrap();
    assert_eq!(legacy.protection, CheckpointProtection::Unprotected);
    // A store with custody reads it as what it is.
    let custodial = protected_store(&root);
    verify_content(&custodial, &legacy).unwrap();
    let dest = tmp.path().join("legacy-child");
    fork_quick(&custodial, &legacy, &dest).unwrap();
    assert_eq!(
        std::fs::read(dest.join("rootfs.ext4")).unwrap(),
        marked_bytes(16)
    );

    // Relabelling it protected is digest drift, and the sealed path finds
    // nothing it would accept.
    let mut relabelled = legacy.clone();
    relabelled.protection = CheckpointProtection::SealedV1;
    assert_ne!(relabelled.compute_meta_digest(), relabelled.meta_digest);
    let error = verify_content(&custodial, &relabelled).expect_err("no sealed index");
    assert!(
        format!("{error:#}").contains("no sealed index"),
        "{error:#}"
    );
}

#[test]
fn tampered_missing_replayed_and_rebound_content_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let store = protected_store(&tmp.path().join("store"));
    let host = CheckpointKeyDomain::host;
    let capture = |id: &str, salt: u8| {
        capture_quick(
            &store,
            &write_rootfs(&tmp.path().join(id), salt),
            id,
            host(),
        )
        .unwrap()
    };
    let refused = |meta: &CheckpointMeta, what: &str| {
        let dest = tmp.path().join(format!("dest-{what}"));
        let error = fork_quick(&store, meta, &dest).expect_err(what);
        assert!(
            regular_files(&dest).is_empty(),
            "{what}: plaintext released"
        );
        format!("{error:#}")
    };

    // A flipped byte in a chunk object.
    let a = capture("a", 20);
    let link = first_chunk_link(&store, &a);
    let mut bytes = std::fs::read(&link).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    replace_file(&link, &bytes);
    assert!(refused(&a, "tampered chunk").contains("did not open"));

    // A missing chunk object.
    let b = capture("b", 21);
    std::fs::remove_file(first_chunk_link(&store, &b)).unwrap();
    assert!(refused(&b, "missing chunk").contains("missing"));

    // A sealed index flipped, or replayed from another checkpoint.
    let c = capture("c", 22);
    let d = capture("d", 23);
    let c_index = sealed::index_path(&store.content_dir(&c.id), "rootfs.ext4");
    let d_index = sealed::index_path(&store.content_dir(&d.id), "rootfs.ext4");
    replace_file(&c_index, &std::fs::read(&d_index).unwrap());
    assert!(refused(&c, "replayed index").contains("sealed index failed integrity"));

    // A valid object of the same domain rebound under another chunk's name.
    let e = capture("e", 24);
    let links = {
        let mut all = regular_files(&store.content_dir(&e.id).join(chunks::MEMBERSHIP_DIR));
        all.sort();
        all
    };
    assert!(links.len() >= 2);
    replace_file(&links[0], &std::fs::read(&links[1]).unwrap());
    assert!(refused(&e, "rebound chunk").contains("did not open"));

    // An object sealed under another domain, filed under this one's name.
    let f = capture("f", 25);
    let link = first_chunk_link(&store, &f);
    let foreign = seal(
        &keys(&CheckpointKeyDomain::tenant("other").unwrap()),
        ObjectKind::Chunk,
        &marked_bytes(25)[..chunks::CHUNK_SIZE],
    )
    .unwrap();
    replace_file(&link, &foreign.bytes);
    assert!(refused(&f, "cross-domain object").contains("did not open"));
}

#[test]
fn a_warm_claim_opens_a_protected_parent_and_keeps_nothing_opaque_beside_it() {
    let tmp = tempfile::tempdir().unwrap();
    let mut env = mvm_core::util::test_env::TestEnv::new();
    env.set("MVM_HOME", tmp.path().join("home"));
    let store = protected_store(&tmp.path().join("store"));
    let snapshots = FsSnapshotStore::new(tmp.path().join("snapshots")).unwrap();
    let control = MarkedControl::new(&tmp.path().join("vm"));
    let parent = capture_vm_full_into_snapshot_store(
        &store,
        vm_full_params("warm", CheckpointKeyDomain::host(), &control.config),
        &control,
        &snapshots,
    )
    .unwrap();
    store.write_meta(&parent).unwrap();
    let dst = tmp.path().join("claim");
    crate::warm_snapshot::materialize_child_from_parent(
        &store, &snapshots, &parent.id, &Audited, &dst,
    )
    .unwrap();
    assert_eq!(
        std::fs::read(dst.join("rootfs.ext4")).unwrap(),
        marked_bytes(1)
    );
    assert_eq!(
        std::fs::read(dst.join("memory.bin")).unwrap(),
        marked_bytes(9)
    );
    assert!(!dst.join(chunks::MEMBERSHIP_DIR).exists());
    assert!(!sealed::index_path(&dst, "rootfs.ext4").exists());

    let trusted = RecordingBackend::default();
    let control = MarkedControl::new(&tmp.path().join("vm2"));
    let parent = capture_vm_full_to_trusted_snapshot_backend(
        &store,
        vm_full_params("warm-trusted", CheckpointKeyDomain::host(), &control.config),
        &control,
        &trusted,
    )
    .unwrap();
    let dst = tmp.path().join("trusted-claim");
    crate::warm_snapshot::materialize_child_from_trusted_parent(
        &store, &trusted, &parent.id, &Audited, &dst,
    )
    .unwrap();
    assert_eq!(
        std::fs::read(dst.join("memory.bin")).unwrap(),
        marked_bytes(9)
    );
}

#[test]
fn an_abandoned_protected_capture_and_its_orphaned_objects_are_reclaimed() {
    let tmp = tempfile::tempdir().unwrap();
    let store = protected_store(&tmp.path().join("store"));
    let kept = capture_quick(
        &store,
        &write_rootfs(&tmp.path().join("k"), 30),
        "kept",
        CheckpointKeyDomain::host(),
    )
    .unwrap();
    let gone = capture_quick(
        &store,
        &write_rootfs(&tmp.path().join("g"), 31),
        "gone",
        CheckpointKeyDomain::host(),
    )
    .unwrap();
    // A capture that died after sealing, leaving its staging behind under a
    // pid that no longer runs, holds only sealed bytes.
    let abandoned = store
        .root()
        .join(staging::STAGING_DIR)
        .join("2147483646-1-0-gone");
    std::fs::create_dir_all(&abandoned).unwrap();
    std::fs::rename(store.dir_for(&gone.id), abandoned.join("dead")).unwrap();
    assert_no_plaintext(store.root());

    let report = prune_unreferenced_content(&store, false).unwrap();
    assert!(
        report.objects > 0,
        "the dead capture's objects are reclaimed"
    );
    assert!(!abandoned.exists());
    verify_content(&store, &kept).unwrap();
    let dest = tmp.path().join("kept-child");
    fork_quick(&store, &kept, &dest).unwrap();
    assert_eq!(
        std::fs::read(dest.join("rootfs.ext4")).unwrap(),
        marked_bytes(30)
    );
}
