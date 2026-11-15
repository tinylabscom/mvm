use mvm_contract::plan::types::EnvironmentRef;

#[test]
fn kernel_only_environment_preserves_legacy_bytes_and_refuses_runtime_field() {
    let legacy = br#"{"kernel_sha256":"kernel"}"#;
    let environment: EnvironmentRef = serde_json::from_slice(legacy).expect("legacy environment");
    assert_eq!(
        serde_json::to_vec(&environment).expect("serializable environment"),
        legacy
    );
    let with_runtime = br#"{"kernel_sha256":"kernel","runtime":null}"#;
    assert!(
        serde_json::from_slice::<EnvironmentRef>(with_runtime).is_err(),
        "runtime identity belongs on the plan, not the kernel environment"
    );
}
