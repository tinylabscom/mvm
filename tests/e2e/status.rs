use super::harness::mvmctl;

/// `ls` on a clean system should list VMs or show "No running".
#[test]
fn status_on_clean_system_produces_meaningful_output() {
    let assert = mvmctl().arg("ls").assert();
    let output = assert.get_output();
    let code = output.status.code().unwrap_or(-1);
    assert_ne!(code, 2, "ls should not produce a parse error");

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("NAME")
            || combined.contains("No running")
            || combined.contains("limactl"),
        "ls should produce meaningful output, got: {combined}"
    );
}

/// Plan 40 dropped the `ps`/`status` aliases on `ls`.
#[test]
fn ps_alias_is_unrecognized() {
    mvmctl().args(["ps", "--help"]).assert().failure().code(2);
}

#[test]
fn status_alias_is_unrecognized() {
    mvmctl()
        .args(["status", "--help"])
        .assert()
        .failure()
        .code(2);
}
