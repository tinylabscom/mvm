//! The SDK reaches machine lifecycle through the mvm-client trait's subprocess
//! impl, never by linking the runtime backend — that would form a dependency
//! cycle (sdk -> client[local] -> backend -> build -> sdk). This sentinel fails
//! if `mvm-backend` ever appears in mvm-sdk's dependency tree.

#[test]
fn sdk_does_not_link_mvm_backend() {
    let out = std::process::Command::new(env!("CARGO"))
        .args(["tree", "-p", "mvm-sdk", "-e", "no-dev", "--prefix", "none"])
        .output()
        .expect("cargo tree runs");
    assert!(out.status.success(), "cargo tree failed");
    let tree = String::from_utf8_lossy(&out.stdout);
    assert!(
        !tree
            .lines()
            .any(|l| l.trim_start().starts_with("mvm-backend ")),
        "mvm-sdk must not link mvm-backend (dependency cycle):\n{tree}"
    );
}
