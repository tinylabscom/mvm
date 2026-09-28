//! The SDK authors workloads and never drives a machine, so it stays
//! independent from the client surface and adds nothing to mvmctl's default
//! closure. Linking the runtime backend (`mvm-client`'s `LocalBackend`) here
//! would form a dependency cycle: `mvm-client` depends on this crate.

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
fn default_sdk_does_not_link_client_surface_or_backend() {
    let tree = cargo_tree(&["tree", "-p", "mvm-sdk", "-e", "no-dev", "--prefix", "none"]);
    // The heavy client crate (LocalBackend) and the runtime backend must never
    // reach the default closure.
    assert!(
        !tree_contains_crate(&tree, "mvm-client"),
        "default mvm-sdk must not link mvm-client:\n{tree}"
    );
    assert!(
        !tree_contains_crate(&tree, "mvm-runtime"),
        "default mvm-sdk must not link mvm-runtime:\n{tree}"
    );
    // The client surface (`mvm-core/client`) is off, so its `async-trait` glue
    // stays out of the default build.
    assert!(
        !tree_contains_crate(&tree, "async-trait"),
        "default mvm-sdk must not pull async-trait (client surface off):\n{tree}"
    );
}
