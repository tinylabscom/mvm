//! What a capture leaves behind when it stops partway.
//!
//! A crash can land between any two writes of a capture. Whatever it
//! interrupts, the store must hold either the complete new checkpoint or no
//! checkpoint under that name, never a record whose digests disagree with its
//! blobs, and never a previous checkpoint damaged by the attempt to replace it.

use std::path::{Path, PathBuf};

use anyhow::Result;
use mvm_core::checkpoint::{CheckpointId, CheckpointMeta, DeviceAnchors};

use super::*;

/// A backend double whose memory image is `memory` and whose device-anchor
/// query fails when `fail_after_blobs` is set. The anchor query runs after the
/// memory, rootfs, and machine-id blobs are already in the content directory,
/// so the failure stands in for a crash between the blob writes and the record
/// that names them.
struct Control {
    rootfs: PathBuf,
    memory: &'static [u8],
    fail_after_blobs: bool,
}

impl VmFullControl for Control {
    fn pause(&self) -> Result<()> {
        Ok(())
    }
    fn resume(&self) -> Result<()> {
        Ok(())
    }
    fn save_memory(&self, memory_path: &Path) -> Result<()> {
        std::fs::write(memory_path, self.memory)?;
        std::fs::write(format!("{}.machine-id", memory_path.display()), b"mid")?;
        Ok(())
    }
    fn rootfs_path(&self) -> Result<PathBuf> {
        Ok(self.rootfs.clone())
    }
    fn device_anchors(&self) -> Result<DeviceAnchors> {
        anyhow::ensure!(!self.fail_after_blobs, "injected fault after blob writes");
        Ok(DeviceAnchors {
            rootfs: self.rootfs.clone(),
            rootfs_verity: None,
            config: None,
            secrets: None,
            identity: None,
            vsock: self.rootfs.with_file_name("v.sock"),
        })
    }
}

struct Fixture {
    temp: tempfile::TempDir,
    store: CheckpointStore,
    rootfs: PathBuf,
}

fn fixture() -> Fixture {
    let tmp = tempfile::tempdir().unwrap();
    let store = CheckpointStore::at(tmp.path().join("store"));
    let rootfs = tmp.path().join("live-rootfs.ext4");
    std::fs::write(&rootfs, b"disk").unwrap();
    Fixture {
        temp: tmp,
        store,
        rootfs,
    }
}

fn params(id: &str) -> CaptureVmFullParams {
    CaptureVmFullParams {
        id: CheckpointId::new(id),
        vm_name: "vm".into(),
        supervisor_config_digest: "d".into(),
        runtime_overlay_version: None,
        supervisor_config_src: None,
        tag: None,
        created_unix: 1,
        retain_paused: false,
        grants: None,
    }
}

fn capture(fx: &Fixture, id: &str, memory: &'static [u8], fail: bool) -> Result<CheckpointMeta> {
    capture_vm_full(
        &fx.store,
        params(id),
        &Control {
            rootfs: fx.rootfs.clone(),
            memory,
            fail_after_blobs: fail,
        },
    )
}

/// Every directory entry under the store root, so a test can assert nothing
/// was left behind rather than only that `list()` does not show it.
fn store_entries(store: &CheckpointStore) -> Vec<String> {
    let mut names: Vec<String> = match std::fs::read_dir(store.root()) {
        Ok(entries) => entries
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect(),
        Err(_) => Vec::new(),
    };
    names.sort();
    names
}

#[test]
fn a_capture_that_fails_after_writing_blobs_leaves_nothing_under_its_name() {
    let fx = fixture();
    capture(&fx, "c1", b"mem", true).unwrap_err();

    assert!(
        !fx.store.dir_for(&CheckpointId::new("c1")).exists(),
        "blobs of an unfinished capture must not sit under the checkpoint's name"
    );
    assert!(fx.store.list().unwrap().is_empty());
}

#[test]
fn a_failed_recapture_leaves_the_previous_checkpoint_intact_and_verifying() {
    let fx = fixture();
    let first = capture(&fx, "c1", b"first memory", false).unwrap();

    capture(&fx, "c1", b"second memory", true).unwrap_err();

    let stored = fx.store.read_meta(&first.id).unwrap();
    assert_eq!(stored, first);
    verify_content(&fx.store, &stored)
        .expect("a failed attempt to replace a checkpoint must not damage it");
    let restored = fx.temp.path().join("restored-memory.bin");
    chunks::materialize_blob(
        &fx.store.content_dir(&first.id),
        first
            .content
            .iter()
            .find(|blob| blob.name == "memory.bin")
            .unwrap(),
        &restored,
    )
    .unwrap();
    assert_eq!(std::fs::read(restored).unwrap(), b"first memory");
}

#[test]
fn a_successful_capture_leaves_only_the_checkpoint_and_the_empty_staging_area() {
    let fx = fixture();
    let meta = capture(&fx, "c1", b"mem", false).unwrap();
    verify_content(&fx.store, &meta).unwrap();

    assert_eq!(store_entries(&fx.store), vec![".objects", ".staging", "c1"]);
    let staging: Vec<_> = std::fs::read_dir(fx.store.root().join(".staging"))
        .unwrap()
        .collect();
    assert!(staging.is_empty(), "staging left behind: {staging:?}");
}

#[test]
fn a_successful_recapture_replaces_the_previous_checkpoint_whole() {
    let fx = fixture();
    capture(&fx, "c1", b"first memory", false).unwrap();
    let second = capture(&fx, "c1", b"second memory", false).unwrap();

    let stored = fx.store.read_meta(&second.id).unwrap();
    assert_eq!(stored, second);
    verify_content(&fx.store, &stored).unwrap();
    assert_eq!(store_entries(&fx.store), vec![".objects", ".staging", "c1"]);
}

/// What the store holds for `id` after a stop: nothing, or a record whose
/// blobs verify. Returns the stored record when there is one.
fn absent_or_verifying(store: &CheckpointStore, id: &CheckpointId) -> Option<CheckpointMeta> {
    let listed: Vec<_> = store
        .list()
        .expect("a crash must never leave a record list() cannot read")
        .into_iter()
        .filter(|meta| &meta.id == id)
        .collect();
    match listed.as_slice() {
        [] => None,
        [meta] => {
            verify_content(store, meta).expect("a listed checkpoint must verify");
            Some(meta.clone())
        }
        more => panic!("{} records for one id", more.len()),
    }
}

/// Stage a capture of `id` whose memory image is `memory`, and return the
/// staged capture and the record it would commit. Mirrors the capture path's
/// use of the staging area without a backend in the way.
fn stage<'a>(
    store: &'a CheckpointStore,
    id: &str,
    memory: &[u8],
) -> (staging::StagedCapture<'a>, CheckpointMeta) {
    let staged = staging::StagedCapture::begin(store, &CheckpointId::new(id)).unwrap();
    let content = staged.content_dir();
    let memory_source = content.join(".memory-source");
    let rootfs_source = content.join(".rootfs-source");
    std::fs::write(&memory_source, memory).unwrap();
    std::fs::write(&rootfs_source, b"disk").unwrap();
    let pool = chunks::ObjectPool::new(store.root(), &Default::default()).unwrap();
    let blobs = vec![
        chunks::chunk_blob(&pool, &content, "memory.bin", &memory_source, false).unwrap(),
        chunks::chunk_blob(&pool, &content, "rootfs.ext4", &rootfs_source, true).unwrap(),
    ];
    std::fs::remove_file(memory_source).unwrap();
    std::fs::remove_file(rootfs_source).unwrap();
    let meta = CheckpointMeta::builder(CheckpointId::new(id), CheckpointClass::VmFull, "vm")
        .content(blobs)
        .supervisor_config_digest("d")
        .created_unix(1)
        .build();
    (staged, meta)
}

#[test]
fn a_crash_between_chunk_object_and_index_publication_leaves_no_checkpoint() {
    let fx = fixture();
    let staged =
        staging::StagedCapture::begin(&fx.store, &CheckpointId::new("object-only")).unwrap();
    let pool = chunks::ObjectPool::new(fx.store.root(), &Default::default()).unwrap();
    pool.store_and_link(&staged.content_dir(), b"object written before its index")
        .unwrap();

    std::mem::forget(staged);

    assert!(
        absent_or_verifying(&fx.store, &CheckpointId::new("object-only")).is_none(),
        "an object without an authenticated index must not publish a checkpoint"
    );
}

/// Run the first `steps` commit steps and then stop as a crash would: no
/// further step, and no cleanup.
fn commit_then_crash(mut staged: staging::StagedCapture<'_>, meta: &CheckpointMeta, steps: usize) {
    let plan = staged.plan().unwrap();
    for step in plan.iter().take(steps) {
        staged.run(step, meta).unwrap();
    }
    std::mem::forget(staged);
}

/// The commit's length, and how many of its steps have run once the rename
/// that makes a checkpoint appear has.
fn plan_shape(store: &CheckpointStore) -> (usize, usize) {
    let plan = stage(store, "probe", b"m").0.plan().unwrap();
    let publish = plan
        .iter()
        .position(|step| *step == staging::CommitStep::Publish)
        .expect("a commit publishes");
    (plan.len(), publish + 1)
}

#[test]
fn a_crash_at_any_point_of_a_first_capture_leaves_it_absent_or_complete() {
    let fx = fixture();
    let (plan_len, published_after) = plan_shape(&fx.store);

    for steps in 0..=plan_len {
        let id = format!("c{steps}");
        let (staged, meta) = stage(&fx.store, &id, b"memory");
        commit_then_crash(staged, &meta, steps);

        let stored = absent_or_verifying(&fx.store, &CheckpointId::new(&id));
        // The rename is the only step that makes a checkpoint appear.
        assert_eq!(
            stored.is_some(),
            steps >= published_after,
            "after {steps} steps"
        );
        if let Some(stored) = stored {
            assert_eq!(stored, meta, "after {steps} steps");
        }
    }
}

#[test]
fn a_crash_at_any_point_of_a_recapture_leaves_the_old_or_the_new_checkpoint_or_none() {
    let fx = fixture();
    let (plan_len, published_after) = plan_shape(&fx.store);

    for steps in 0..=plan_len {
        let id = format!("c{steps}");
        let (first, old) = stage(&fx.store, &id, b"old memory");
        first.commit(&old).unwrap();
        let (second, new) = stage(&fx.store, &id, b"new memory");
        commit_then_crash(second, &new, steps);

        let stored = absent_or_verifying(&fx.store, &CheckpointId::new(&id));
        // Between moving the old checkpoint aside and moving the new one in,
        // the name is empty; before that it is the old one, after it the new.
        let expected = match steps {
            s if s >= published_after => Some(&new),
            s if s == published_after - 1 => None,
            _ => Some(&old),
        };
        assert_eq!(stored.as_ref(), expected, "after {steps} steps");
    }
}

#[test]
fn verify_reports_the_first_failing_blob_in_manifest_order() {
    let fx = fixture();
    let meta = capture(&fx, "c1", b"mem", false).unwrap();
    let content = fx.store.content_dir(&meta.id);
    // Damage every blob, so whichever worker finishes first, the report must
    // still name the manifest's first blob.
    for blob in &meta.content {
        if chunks::is_chunked_blob(&content, blob) {
            let path = chunks::stored_chunk_paths(&content, blob)
                .unwrap()
                .into_iter()
                .next()
                .unwrap();
            make_writable(&path);
            std::fs::write(path, b"tampered").unwrap();
        } else {
            std::fs::write(content.join(&blob.name), b"tampered").unwrap();
        }
    }
    let err = verify_content(&fx.store, &meta).unwrap_err().to_string();
    assert!(
        err.contains(&format!("{:?}", meta.content[0].name)),
        "expected the first manifest blob in: {err}"
    );
}

#[test]
fn verify_refuses_a_missing_blob() {
    let fx = fixture();
    let meta = capture(&fx, "c1", b"mem", false).unwrap();
    let content = fx.store.content_dir(&meta.id);
    let memory = meta
        .content
        .iter()
        .find(|blob| blob.name == "memory.bin")
        .unwrap();
    let path = chunks::stored_chunk_paths(&content, memory)
        .unwrap()
        .into_iter()
        .next()
        .unwrap();
    std::fs::remove_file(path).unwrap();
    verify_content(&fx.store, &meta).unwrap_err();
}

fn make_writable(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    #[cfg(not(unix))]
    {
        let mut permissions = std::fs::metadata(path).unwrap().permissions();
        permissions.set_readonly(false);
        std::fs::set_permissions(path, permissions).unwrap();
    }
}

/// Serial against parallel verification of a realistically sized checkpoint,
/// plus what making the capture durable costs. Prints; asserts only that both
/// verifications accept the checkpoint.
///
/// Run with `cargo nextest run -p mvm-runtime --lib --run-ignored only
/// verify_timing --no-capture`. Sizes default to a 2 GiB memory image and a
/// 1 GiB rootfs; `MVM_VERIFY_TIMING_MEMORY_MIB` and
/// `MVM_VERIFY_TIMING_ROOTFS_MIB` override them.
#[test]
#[ignore = "writes several GiB and prints timings; run explicitly"]
fn verify_timing() {
    use std::io::Write as _;
    use std::time::Instant;

    fn mib_from_env(var: &str, default: u64) -> u64 {
        std::env::var(var)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(default)
    }
    fn write_blob(path: &Path, mib: u64, seed: u8) {
        let mut chunk = vec![0u8; 1 << 20];
        let mut file = std::io::BufWriter::new(std::fs::File::create(path).unwrap());
        for i in 0..mib {
            for (j, byte) in chunk.iter_mut().enumerate() {
                *byte = seed ^ (i as u8) ^ (j as u8);
            }
            file.write_all(&chunk).unwrap();
        }
        file.flush().unwrap();
    }
    fn best_of<F: FnMut()>(runs: usize, mut f: F) -> std::time::Duration {
        (0..runs)
            .map(|_| {
                let start = Instant::now();
                f();
                start.elapsed()
            })
            .min()
            .unwrap()
    }

    let memory_mib = mib_from_env("MVM_VERIFY_TIMING_MEMORY_MIB", 2048);
    let rootfs_mib = mib_from_env("MVM_VERIFY_TIMING_ROOTFS_MIB", 1024);
    let tmp = tempfile::tempdir().unwrap();
    let store = CheckpointStore::at(tmp.path().join("store"));
    let staged = staging::StagedCapture::begin(&store, &CheckpointId::new("bench")).unwrap();
    let content = staged.content_dir();
    write_blob(&content.join("memory.bin"), memory_mib, 0x5a);
    write_blob(&content.join("rootfs.ext4"), rootfs_mib, 0xa5);
    let blobs = sha256_files_parallel(vec![
        content.join("memory.bin"),
        content.join("rootfs.ext4"),
    ])
    .into_iter()
    .zip(["memory.bin", "rootfs.ext4"])
    .map(|(sha256, name)| ContentBlob {
        name: name.into(),
        sha256: sha256.unwrap(),
    })
    .collect();
    let meta = CheckpointMeta::builder(CheckpointId::new("bench"), CheckpointClass::VmFull, "vm")
        .content(blobs)
        .supervisor_config_digest("d")
        .created_unix(1)
        .build();

    let start = Instant::now();
    staged.commit(&meta).unwrap();
    let commit = start.elapsed();

    let dir = store.content_dir(&meta.id);
    let serial = best_of(3, || {
        for blob in &meta.content {
            assert_eq!(sha256_file_hex(&dir.join(&blob.name)).unwrap(), blob.sha256);
        }
    });
    let parallel = best_of(3, || verify_content(&store, &meta).unwrap());

    let cpus = std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get);
    println!(
        "verify_timing: memory {memory_mib} MiB + rootfs {rootfs_mib} MiB, {cpus} cpus\n  \
         durable commit (sync blobs, meta, dirs, rename): {commit:?}\n  \
         serial verify (best of 3):   {serial:?}\n  \
         parallel verify (best of 3): {parallel:?}\n  \
         speedup: {:.2}x",
        serial.as_secs_f64() / parallel.as_secs_f64()
    );
}

/// Serial against per-chunk parallel verification at the three acceptance
/// sizes. The synthetic index repeats one nonzero object so the benchmark
/// hashes the full logical byte count without consuming 7 GiB of disk.
#[test]
#[ignore = "hashes 42 GiB across repeated runs and prints timings; run explicitly"]
fn chunk_verify_timing() {
    use std::time::Instant;

    fn best_of<F: FnMut()>(runs: usize, mut f: F) -> std::time::Duration {
        (0..runs)
            .map(|_| {
                let start = Instant::now();
                f();
                start.elapsed()
            })
            .min()
            .unwrap()
    }

    let tmp = tempfile::tempdir().unwrap();
    let store = CheckpointStore::at(tmp.path().join("store"));
    let pool = chunks::ObjectPool::new(store.root(), &Default::default()).unwrap();
    let cpus = std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get);

    for gib in [1u64, 2, 4] {
        let content = tmp.path().join(format!("{gib}-gib-content"));
        let blob = chunks::repeated_chunk_blob_for_benchmark(
            &pool,
            &content,
            "memory.bin",
            gib * 1024 * 1024 * 1024,
        )
        .unwrap();
        let serial = best_of(3, || {
            chunks::verify_blob_serial(&content, &blob).unwrap();
        });
        let parallel = best_of(3, || {
            chunks::verify_blob(&content, &blob).unwrap();
        });
        println!(
            "chunk_verify_timing: {gib} GiB logical, {cpus} cpus\n  \
             serial (best of 3):   {serial:?}\n  \
             parallel (best of 3): {parallel:?}\n  \
             speedup: {:.2}x",
            serial.as_secs_f64() / parallel.as_secs_f64()
        );
    }
}
