//! `mvmctl compile <app.ts>` lowers the `mvm.app({...})(fn)` site to build
//! artifacts statically — the host walks the AST via tree-sitter-typescript,
//! it never runs `tsx`/`node`. Sibling of `compile_hello_app.rs` (Python).
//!
//! Also locks the Node framework-strip: the bundled `src/app.ts` must carry
//! no `mvm` reference (the guest rootfs ships no SDK) and the `mvm.app(...)`
//! wrapper must be unwrapped to the bare function so `greet` resolves.

use assert_cmd::cargo::CommandCargoExt;
use std::process::Command;

#[test]
fn compile_hello_app_ts_lowers_and_strips_framework() {
    let out = tempfile::tempdir().expect("tmp out");
    let app = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../examples/typescript/hello-app/app.ts"
    );

    #[allow(deprecated)]
    let st = Command::cargo_bin("mvmctl")
        .expect("locate mvmctl")
        .args(["compile", app, "--out", out.path().to_str().unwrap()])
        .status()
        .expect("spawn mvmctl compile");

    assert!(st.success(), "mvmctl compile <app.ts> failed");
    assert!(out.path().join("flake.nix").exists(), "flake.nix emitted");
    assert!(
        out.path().join("launch.json").exists(),
        "launch.json emitted"
    );

    let bundled =
        std::fs::read_to_string(out.path().join("src/app.ts")).expect("bundled src/app.ts emitted");
    // Execution-relevant SDK references must be gone (a doc comment that
    // merely mentions `mvm` is harmless — comments don't run).
    assert!(
        !bundled.contains("mvm-sdk"),
        "the `mvm-sdk` import must be stripped, got:\n{bundled}"
    );
    assert!(
        !bundled.contains("= mvm.app("),
        "the `mvm.app(...)` wrapper must be unwrapped, got:\n{bundled}"
    );
    assert!(
        bundled.contains("export const greet ="),
        "greet declaration preserved, got:\n{bundled}"
    );
    assert!(
        bundled.contains("=> `hello ${name}`"),
        "bare function body preserved, got:\n{bundled}"
    );
}

/// A Node workload that ships an npm lockfile gets a reproducible build-time
/// `node_modules` build (nixpkgs importNpmLock) baked into the RO app image —
/// no boot-time install, no runtime mount. The user's dep import survives the
/// framework strip; only the `mvm-sdk` import is removed.
#[test]
fn compile_hello_app_ts_with_deps_bakes_node_modules_at_build_time() {
    let out = tempfile::tempdir().expect("tmp out");
    let app = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../examples/typescript/hello-app-with-deps/app.ts"
    );

    #[allow(deprecated)]
    let st = Command::cargo_bin("mvmctl")
        .expect("locate mvmctl")
        .args(["compile", app, "--out", out.path().to_str().unwrap()])
        .status()
        .expect("spawn mvmctl compile");
    assert!(st.success(), "mvmctl compile <app.ts with deps> failed");

    // The lockfile must ride along in the bundle so the flake's `nodeHasLock`
    // predicate fires and the build installs node_modules.
    assert!(
        out.path().join("src/package-lock.json").exists(),
        "bundled package-lock.json drives the build-time install"
    );

    let bundled =
        std::fs::read_to_string(out.path().join("src/app.ts")).expect("bundled src/app.ts emitted");
    assert!(!bundled.contains("mvm-sdk"), "mvm-sdk import stripped");
    assert!(
        bundled.contains(r#"import isNumber from "is-number""#),
        "the user's npm dependency import must survive the strip, got:\n{bundled}"
    );

    // The generated flake must take the reproducible importNpmLock build path.
    let flake = std::fs::read_to_string(out.path().join("flake.nix")).expect("flake.nix emitted");
    assert!(
        flake.contains("pkgs.buildNpmPackage"),
        "npm build path emitted"
    );
    assert!(
        flake.contains("pkgs.importNpmLock { npmRoot = ./src; }"),
        "hash-free importNpmLock path emitted"
    );
}
