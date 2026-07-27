//! Step definitions for the warm-snapshot clone scenario.
//!
//! These steps exercise `mvm_fs::snapshot_store` directly — content-addressed
//! `create`/`materialize`/dedup — with no VM boot, proving the storage-layer
//! value proposition of a warm snapshot: materializing an instance is a
//! copy-on-write clone of a pre-built artifact, not a rebuild.

use std::fs;

use cucumber::{given, then, when};

use mvm_fs::snapshot_store::{FsSnapshotStore, SnapshotStore};

use crate::world::CliWorld;

#[given(expr = "a content-addressed warm snapshot built from a template rootfs artifact")]
fn build_warm_snapshot(world: &mut CliWorld) {
    let tmp = tempfile::tempdir().expect("create snapshot scenario tempdir");
    let store = FsSnapshotStore::new(tmp.path().join("store")).expect("open snapshot store");

    // Synthetic template rootfs artifact with an interior zero run so this
    // also exercises the sparse-copy fallback path, not just the reflink
    // fast path.
    let mut artifact = vec![0xAA_u8; 4096];
    artifact.extend(std::iter::repeat_n(0u8, 65536));
    artifact.extend(vec![0xBB_u8; 4096]);
    let source_path = tmp.path().join("template-rootfs.img");
    fs::write(&source_path, &artifact).expect("write template rootfs artifact");

    let id = store
        .create_content_addressed(&source_path)
        .expect("store warm snapshot");

    world.snapshot_source_path = Some(source_path);
    world.snapshot_source_bytes = Some(artifact);
    world.snapshot_id = Some(id);
    world.snapshot_store = Some(store);
    world.snapshot_tmp = Some(tmp);
}

#[when(expr = "the warm snapshot is cloned into a fresh instance")]
fn clone_into_instance(world: &mut CliWorld) {
    let tmp = world
        .snapshot_tmp
        .as_ref()
        .expect("a warm snapshot must be built first");
    let store = world
        .snapshot_store
        .as_ref()
        .expect("a warm snapshot must be built first");
    let id = world
        .snapshot_id
        .as_ref()
        .expect("a warm snapshot must be built first");

    let instance_path = tmp.path().join("instance.img");
    store
        .materialize(id, &instance_path)
        .expect("materialize warm snapshot into instance");
    world.snapshot_instance_path = Some(instance_path);
}

#[then(expr = "the instance byte-equals the warm snapshot")]
fn instance_byte_equals(world: &mut CliWorld) {
    let instance_path = world
        .snapshot_instance_path
        .as_ref()
        .expect("the warm snapshot must be cloned into an instance first");
    let expected = world
        .snapshot_source_bytes
        .as_ref()
        .expect("a warm snapshot must be built first");

    let actual = fs::read(instance_path).expect("read materialized instance");
    assert_eq!(
        &actual, expected,
        "materialized instance must byte-equal the stored warm snapshot"
    );
}

#[then(expr = "mutating the instance does not change the stored warm snapshot")]
fn mutating_instance_is_isolated(world: &mut CliWorld) {
    let instance_path = world
        .snapshot_instance_path
        .as_ref()
        .expect("the warm snapshot must be cloned into an instance first")
        .clone();
    let store = world
        .snapshot_store
        .as_ref()
        .expect("a warm snapshot must be built first");
    let id = world
        .snapshot_id
        .as_ref()
        .expect("a warm snapshot must be built first");
    let expected = world
        .snapshot_source_bytes
        .as_ref()
        .expect("a warm snapshot must be built first")
        .clone();
    let tmp = world
        .snapshot_tmp
        .as_ref()
        .expect("a warm snapshot must be built first");

    fs::write(&instance_path, b"mutated instance content").expect("mutate instance in place");

    // Re-materialize a fresh instance and check it still carries the
    // original bytes — proving the mutation above never reached the store.
    let recheck_path = tmp.path().join("instance-recheck.img");
    store
        .materialize(id, &recheck_path)
        .expect("re-materialize warm snapshot after instance mutation");
    let recheck = fs::read(&recheck_path).expect("read re-materialized instance");
    assert_eq!(
        recheck, expected,
        "stored warm snapshot must be unaffected by mutating a materialized instance"
    );
}

#[then(
    expr = "re-storing the identical artifact reuses the existing snapshot rather than rebuilding it"
)]
fn restoring_identical_artifact_dedups(world: &mut CliWorld) {
    let store = world
        .snapshot_store
        .as_ref()
        .expect("a warm snapshot must be built first");
    let id = world
        .snapshot_id
        .as_ref()
        .expect("a warm snapshot must be built first");
    let source_path = world
        .snapshot_source_path
        .as_ref()
        .expect("a warm snapshot must be built first");

    let id_again = store
        .create_content_addressed(source_path)
        .expect("re-store identical template rootfs artifact");
    assert_eq!(
        id_again.id(),
        id.id(),
        "re-storing identical content must reuse the existing content-addressed id"
    );

    let entries: Vec<_> = fs::read_dir(store.root())
        .expect("read snapshot store root")
        .collect();
    assert_eq!(
        entries.len(),
        1,
        "identical content must be stored exactly once, not rebuilt as a second copy"
    );
    assert_eq!(
        store.refcount(id).expect("read snapshot refcount"),
        2,
        "reusing an existing snapshot must bump its refcount, not duplicate storage"
    );
}
