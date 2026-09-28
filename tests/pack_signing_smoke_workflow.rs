use std::fs;

#[test]
fn image_set_smoke_fixture_keeps_the_dummy_kernel_size_literal() {
    let workflow = fs::read_to_string(".github/workflows/pack-signing-smoke.yml")
        .expect("read pack-signing smoke workflow");

    assert!(
        workflow.contains("printf 'dummy-kernel'   > smoke/vmlinux"),
        "workflow must keep the fixed dummy kernel payload this regression test describes"
    );
    assert!(
        workflow.contains("\"size\": 12"),
        "workflow must pin the smoke image-set manifest to the dummy kernel's 12-byte size"
    );
}
