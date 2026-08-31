use std::path::{Path, PathBuf};

const IMAGE_NAME: &str = "service-plane-fixtures.ext4";
const CAPACITY: &str = "64M";
const CAPACITY_BYTES: u64 = 64 * 1024 * 1024;

pub(crate) fn image_path(root: &tempfile::TempDir) -> PathBuf {
    root.path().join(IMAGE_NAME)
}

pub(crate) fn materialize(fixture_root: &Path) -> tempfile::TempDir {
    let disk_root = tempfile::tempdir().expect("create service-plane fixture disk directory");
    let options = mvm_fs::rootfs::MaterializeOptions::default()
        .with_unsupported_node_policy(mvm_fs::rootfs::UnsupportedNodePolicy::Reject)
        .with_volume_label(b"mvm-bdd-fixture");
    let image =
        mvm_fs::rootfs::materialize_ext4_pure(fixture_root, &image_path(&disk_root), &options)
            .expect("materialize service-plane fixture ext4");
    assert!(
        image.size_bytes <= CAPACITY_BYTES,
        "service-plane fixture exceeded its declared 64 MiB volume capacity"
    );
    disk_root
}

pub(crate) fn command(service: &str, image: &Path) -> String {
    format!(
        "run --runtime python --host-service {service} --volume {}:/work/fixtures:{CAPACITY}:ro --timeout 300 -- python /work/fixtures/kv_roundtrip.py",
        image.display()
    )
}
