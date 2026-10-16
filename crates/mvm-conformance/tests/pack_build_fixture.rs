#[path = "support/pack_build_fixture.rs"]
mod fixture;

#[test]
fn live_pack_fixture_uses_a_separate_source_tree_and_a_successful_entrypoint() {
    let dir = tempfile::tempdir().unwrap();
    fixture::stage(dir.path());
    let spec: mvm_contract::pack_spec::PackSpec =
        serde_json::from_slice(&std::fs::read(dir.path().join("pack.json")).unwrap()).unwrap();
    assert_eq!(
        spec.source,
        mvm_contract::pack_spec::PackSource::Local { path: "app".into() }
    );
    assert_eq!(spec.entrypoint, ["cat", "/app/hello.txt"]);
    assert_eq!(
        std::fs::read(dir.path().join("app/hello.txt")).unwrap(),
        b"pack health witness\n"
    );
    assert!(!dir.path().join("app/build.mvmpkg").exists());
    assert!(!dir.path().join("app/pack.lock.json").exists());
}

#[test]
fn live_pack_build_witness_drives_the_documented_request_shape() {
    let feature =
        include_str!("../../../features/suites/s29_doc_examples/documented_build_live.feature");
    let commands = mvm_conformance::doc_examples::live_scenario_commands(feature);
    assert!(
        commands
            .iter()
            .any(|args| args == &["pack", "build", "pack.json", "--out", "build.mvmpkg"])
    );
}
