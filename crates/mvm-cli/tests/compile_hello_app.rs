//! `mvmctl compile <app.py>` lowers the `@mvm.app` decorator to build
//! artifacts statically — the host walks the AST, it never imports or
//! runs the script. Locks the decorator entry path so the stale "v1
//! only handles IR JSON" behavior can't creep back.

use assert_cmd::cargo::CommandCargoExt;
use std::process::Command;

#[test]
fn compile_hello_app_lowers_decorator_to_flake() {
    let out = tempfile::tempdir().expect("tmp out");
    let app = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../examples/python/hello-app/app.py"
    );

    #[allow(deprecated)]
    let st = Command::cargo_bin("mvmctl")
        .expect("locate mvmctl")
        .args([
            "build",
            "compile",
            app,
            "--out",
            out.path().to_str().unwrap(),
        ])
        .status()
        .expect("spawn mvmctl compile");

    assert!(st.success(), "mvmctl compile <app.py> failed");
    assert!(out.path().join("flake.nix").exists(), "flake.nix emitted");
    assert!(
        out.path().join("launch.json").exists(),
        "launch.json emitted"
    );
}
