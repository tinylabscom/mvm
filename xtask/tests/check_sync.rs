use std::process::Command;

#[test]
fn xtask_check_sync_passes_on_main() {
    // Use `cargo run -p xtask --` rather than `cargo xtask` — the
    // workspace ships no `[alias]` section in .cargo/config.toml, so
    // the `xtask` subcommand only resolves on contributor machines
    // that have set up the alias manually. CI runners don't.
    // A nested Cargo invocation must not write into the parent test run's
    // target directory. In particular, replacing an unversioned `.rlib`
    // while the parent is preparing doctests can leave rustdoc holding an
    // artifact produced by a different toolchain or feature set.
    let target_dir = tempfile::tempdir().expect("isolated nested Cargo target");
    let status = Command::new("cargo")
        .args(["run", "-p", "xtask", "--", "check-mvm-host-binaries-sync"])
        .env("CARGO_TARGET_DIR", target_dir.path())
        .status()
        .expect("spawn cargo run -p xtask --");
    assert!(
        status.success(),
        "xtask reported a sync drift between Rust manifest and Nix attrset"
    );
}
