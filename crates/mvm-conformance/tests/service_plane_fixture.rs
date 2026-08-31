mod support;

use std::io::{Read as _, Seek as _};

#[test]
fn live_service_plane_fixture_is_a_read_only_ext4_volume() {
    let workspace = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root");
    let source = workspace.join("features/suites/s30_service_plane/fixtures");
    let disk_root = support::service_plane_fixture::materialize(&source);
    let disk = support::service_plane_fixture::image_path(&disk_root);

    let mut image = std::fs::File::open(&disk).expect("open fixture image");
    image
        .seek(std::io::SeekFrom::Start(1024 + 56))
        .expect("seek to ext4 magic");
    let mut magic = [0_u8; 2];
    image.read_exact(&mut magic).expect("read ext4 magic");
    assert_eq!(u16::from_le_bytes(magic), 0xef53);

    let command = support::service_plane_fixture::command("host.kv.v1", &disk);
    assert!(command.contains("--volume "));
    assert!(command.contains(":/work/fixtures:64M:ro"));
    assert!(command.contains("--host-service host.kv.v1"));
    assert!(command.contains("python /work/fixtures/kv_roundtrip.py"));
    assert!(!command.contains("--mount"));
}

#[test]
fn live_service_plane_scenarios_do_not_require_directory_shares() {
    let workspace = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let feature = std::fs::read_to_string(
        workspace.join("features/suites/s30_service_plane/host_kv.feature"),
    )
    .expect("read host service-plane feature");

    for scenario in [
        "a booted workload round-trips a key through the broker",
        "an unbound workload is refused from inside the guest",
    ] {
        assert!(
            feature.contains(&format!("@live @sdk_sidecar\n  Scenario: {scenario}")),
            "default-backend volume witness {scenario:?} must not require virtio-fs"
        );
    }
    assert!(!feature.contains("@live @sdk_sidecar @dir_share"));
}
