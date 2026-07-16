//! The default SDK stays independent from the client facade so it does not add
//! crates to mvmctl's default closure. The opt-in facade reaches machine
//! lifecycle through the shared `MvmClient` trait (in `mvm-core`'s `client`
//! module) via a subprocess impl, never by linking the runtime backend
//! (`mvm-client`'s `LocalBackend`) — that would form a dependency cycle.

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

#[test]
fn client_facade_enables_the_trait_without_the_backend() {
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
    // The facade turns on `mvm-core/client`, so the async-trait glue appears...
    assert!(
        tree_contains_crate(&tree, "async-trait"),
        "client-facade must enable the mvm-core client surface (async-trait):\n{tree}"
    );
    // ...but the runtime backend must NOT — that is the cycle guard.
    assert!(
        !tree_contains_crate(&tree, "mvm-runtime"),
        "mvm-sdk client-facade must not link mvm-runtime (dependency cycle):\n{tree}"
    );
    // And it must not drag in the heavy `mvm-client` crate (LocalBackend) either.
    assert!(
        !tree_contains_crate(&tree, "mvm-client"),
        "mvm-sdk client-facade must not link mvm-client (LocalBackend):\n{tree}"
    );
}
