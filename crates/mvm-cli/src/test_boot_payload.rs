//! Process-isolated test fixtures; never used for real boots.

const CHILD: &str = "MVM_BASE_CONTRACT_TEST_CHILD";
const FRESH_CHILD: &str = "MVM_FRESH_PROCESS_TEST_CHILD";

pub(crate) fn in_payload_capable_test_process(module: &str, name: &str) -> bool {
    in_test_process(module, name, CHILD)
}

pub(crate) fn in_fresh_test_process(module: &str, name: &str) -> bool {
    in_test_process(module, name, FRESH_CHILD)
}

fn in_test_process(module: &str, name: &str, marker: &str) -> bool {
    let module = module
        .split_once("::")
        .expect("test module includes crate")
        .1;
    let test = format!("{module}::{name}");
    if std::env::var(marker).as_deref() == Ok(test.as_str()) {
        return true;
    }
    let output = mvm_core::env_hygiene::helper_command(std::env::current_exe().unwrap())
        .args(["--exact", &test, "--nocapture"])
        .env_remove(CHILD)
        .env_remove(FRESH_CHILD)
        .env(marker, &test)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "isolated test child failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("test result: ok. 1 passed"),
        "the isolated child must execute exactly the requested test"
    );
    false
}

pub(crate) fn register_fixture_payload() {
    struct FixturePayload(tempfile::TempDir);
    impl mvm_build::builder_boot::BootPayloadSource for FixturePayload {
        fn boot_payload(
            &self,
        ) -> Result<
            mvm_build::builder_boot::BuilderBootPayload,
            mvm_build::builder_boot::BootPayloadError,
        > {
            mvm_build::builder_boot::BuilderBootPayload::builder()
                .host_bin_dir(self.0.path())
                .build()
        }
    }
    assert!(
        std::env::var_os(CHILD).is_some(),
        "register the process-global payload source only in an isolated test child"
    );
    let payload = tempfile::tempdir().unwrap();
    for name in mvm_build::host_payload_manifest::host_binary_names() {
        std::fs::write(payload.path().join(name), name.as_bytes()).unwrap();
    }
    let source = FixturePayload(payload);
    mvm_build::builder_boot::BootPayloadSource::boot_payload(&source).unwrap();
    mvm_build::builder_boot::register_boot_payload_source(Box::new(source));
}
