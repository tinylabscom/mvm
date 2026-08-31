mod support;

#[test]
fn live_service_plane_fixture_is_a_read_only_mount() {
    let workspace = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root");
    let source = workspace.join("features/suites/s30_service_plane/fixtures");
    assert!(source.join("kv_roundtrip.py").is_file());

    let command = support::service_plane_fixture::command("host.kv.v1", &source);
    assert!(command.contains("--mount "));
    assert!(command.contains(":/work/fixtures:ro"));
    assert!(command.contains("--host-service host.kv.v1"));
    assert!(command.contains("python /work/fixtures/kv_roundtrip.py"));
    assert!(!command.contains("--volume"));
}

#[test]
fn live_service_plane_scenarios_do_not_require_virtio_fs() {
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
            "default-backend block-image mount witness {scenario:?} must not require virtio-fs"
        );
    }
    assert!(!feature.contains("@live @sdk_sidecar @dir_share"));
}
