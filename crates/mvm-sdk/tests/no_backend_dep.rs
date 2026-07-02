//! The default SDK stays independent from the client facade so it does not add
//! crates to mvmctl's default closure. The opt-in facade reaches machine
//! lifecycle through the mvm-client trait's subprocess impl, never by linking
//! the runtime backend — that would form a dependency cycle.

fn cargo_tree(args: &[&str]) -> String {
    let out = std::process::Command::new(env!("CARGO"))
        .args(args)
        .output()
        .expect("cargo tree runs");
    assert!(out.status.success(), "cargo tree failed");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn tree_contains_crate(tree: &str, crate_name: &str) -> bool {
    let needle = format!("{crate_name} ");
    tree.lines()
        .any(|line| line.trim_start().starts_with(&needle))
}

#[test]
fn default_sdk_does_not_link_mvm_client_or_backend() {
    let tree = cargo_tree(&["tree", "-p", "mvm-sdk", "-e", "no-dev", "--prefix", "none"]);
    assert!(
        !tree_contains_crate(&tree, "mvm-client"),
        "default mvm-sdk must not link mvm-client:\n{tree}"
    );
    assert!(
        !tree_contains_crate(&tree, "mvm-backend"),
        "default mvm-sdk must not link mvm-backend:\n{tree}"
    );
}

#[test]
fn client_facade_sdk_does_not_link_mvm_backend() {
    let tree = cargo_tree(&[
        "tree",
        "-p",
        "mvm-sdk",
        "-e",
        "no-dev",
        "--prefix",
        "none",
        "--features",
        "client-facade",
    ]);
    assert!(
        tree_contains_crate(&tree, "mvm-client"),
        "client-facade feature must link mvm-client:\n{tree}"
    );
    assert!(
        !tree_contains_crate(&tree, "mvm-backend"),
        "mvm-sdk client-facade must not link mvm-backend (dependency cycle):\n{tree}"
    );
}
