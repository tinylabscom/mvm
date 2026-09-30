use std::process::Command;

#[test]
fn disposable_gcp_controller_cleans_up_every_tested_exit_path() {
    let status = Command::new("bash")
        .arg("scripts/run-cve-2026-80521-gcp.test.sh")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .status()
        .expect("run the disposable GCP controller test");
    assert!(status.success(), "controller lifecycle test failed");
}
