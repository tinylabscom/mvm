#[path = "support/pack_build_fixture.rs"]
mod fixture;

#[test]
fn candidate_prefix_is_used_only_for_live_pack_production() {
    for (command, live, expected) in [
        ("build pack.json --out app.mvmpkg", true, true),
        ("build pack.json --out app.mvmpkg", false, false),
        ("build alpine --from image --out app.mvmpkg", true, true),
        ("build alpine --from image --out app.mvmpkg", false, false),
        ("bundle inspect app.mvmpkg", true, false),
        ("pack pull acme/hello", true, false),
        ("machine run --manifest app.mvmpkg", true, false),
        ("machine check-artifact app.mvmpkg", true, false),
        ("pack compile", true, false),
    ] {
        let arguments = mvm_conformance::doc_examples::tokenize(command);
        let selected = fixture::producer_binary(&arguments, live, Some("/producer/mvmctl".into()));
        assert_eq!(selected.is_some(), expected, "{command}");
    }
}

#[test]
fn revocation_update_names_both_signed_inputs() {
    let args = fixture::revocation_update_args(std::path::Path::new("/r"));
    let args: Vec<_> = args.iter().map(|a| a.to_string_lossy()).collect();
    assert_eq!(
        args,
        [
            "image",
            "revocations",
            "update",
            "--document",
            "/r/revocations.json",
            "--bundle",
            "/r/revocations.json.bundle"
        ]
    );
}

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
            .any(|args| args == &["build", "pack.json", "--out", "build.mvmpkg"])
    );
}
