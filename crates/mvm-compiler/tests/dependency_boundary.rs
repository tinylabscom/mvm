//! Compiler stages consume contracts, never SDK facades or execution backends.

#[test]
fn compiler_does_not_link_authoring_or_execution_crates() {
    let output = std::process::Command::new(env!("CARGO"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args([
            "tree",
            "--locked",
            "--offline",
            "-p",
            "mvm-compiler",
            "--edges",
            "normal,build,dev",
            "--prefix",
            "none",
        ])
        .output()
        .expect("cargo tree runs");
    assert!(
        output.status.success(),
        "cargo tree failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let tree = String::from_utf8(output.stdout).expect("dependency tree is UTF-8");
    for forbidden in [
        "mvm-sdk",
        "mvm-core",
        "mvm-client",
        "mvm-runtime",
        "mvm-build",
        "mvm-bundler",
        "mvm-agentd",
        "mvm-host-services",
    ] {
        assert!(
            !tree
                .lines()
                .any(|line| line.split_whitespace().next() == Some(forbidden)),
            "compiler must not depend on {forbidden}:\n{tree}"
        );
    }
}
