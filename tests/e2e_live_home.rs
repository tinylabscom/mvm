#![cfg(unix)]

#[test]
fn live_suite_commands_share_the_prepared_home() {
    let output = std::process::Command::new("python3")
        .arg("scripts/test_e2e_live_home.py")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("run live-home regression tests");
    assert!(
        output.status.success(),
        "live-home regression failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
