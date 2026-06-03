//! `mvmctl compile` warns when a Node workload's `package.json` deps won't be
//! installed: no lockfile at all, or a pnpm/yarn lockfile the npm-only
//! build-time bake can't consume. Without these the gap is silent — the
//! bundle copies the source with no `node_modules` and the miss only shows up
//! as a runtime import failure. Plan 145 WS-B/WS-C.

use assert_cmd::cargo::CommandCargoExt;
use std::process::Command;

const APP_TS: &str = r#"import * as mvm from "mvm-sdk";
export const greet = mvm.app({
  image: mvm.node_image({ node: "22" }),
})((name: string): string => `hi ${name}`);
"#;

const PACKAGE_JSON: &str =
    r#"{"name":"warn-fixture","type":"module","dependencies":{"is-number":"^7.0.0"}}"#;

/// Compile `app.ts` plus the given sibling files (name → contents) and return
/// (success, stderr). The temp dir is the manifest dir, so lockfile detection
/// scans exactly these files.
fn compile_with(files: &[(&str, &str)]) -> (bool, String) {
    let dir = tempfile::tempdir().expect("tmp dir");
    std::fs::write(dir.path().join("app.ts"), APP_TS).unwrap();
    for (name, body) in files {
        std::fs::write(dir.path().join(name), body).unwrap();
    }
    let out = tempfile::tempdir().expect("tmp out");
    #[allow(deprecated)]
    let output = Command::cargo_bin("mvmctl")
        .expect("locate mvmctl")
        .args([
            "compile",
            dir.path().join("app.ts").to_str().unwrap(),
            "--out",
            out.path().to_str().unwrap(),
        ])
        .output()
        .expect("spawn mvmctl compile");
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

#[test]
fn warns_when_package_json_has_no_lockfile() {
    let (ok, stderr) = compile_with(&[("package.json", PACKAGE_JSON)]);
    assert!(ok, "compile should still succeed; stderr:\n{stderr}");
    assert!(
        stderr.contains("no lockfile") && stderr.contains("npm install"),
        "expected a no-lockfile warning, got:\n{stderr}"
    );
}

#[test]
fn warns_that_pnpm_lockfile_is_not_baked() {
    let (ok, stderr) = compile_with(&[
        ("package.json", PACKAGE_JSON),
        ("pnpm-lock.yaml", "lockfileVersion: '9.0'\n"),
    ]);
    assert!(ok, "compile should still succeed; stderr:\n{stderr}");
    assert!(
        stderr.contains("pnpm-lock.yaml") && stderr.contains("npm-only"),
        "expected an npm-only warning for pnpm, got:\n{stderr}"
    );
}

#[test]
fn no_warning_when_npm_lockfile_present() {
    // package-lock.json → the nix-native bake handles it; stay quiet.
    let (ok, stderr) = compile_with(&[
        ("package.json", PACKAGE_JSON),
        ("package-lock.json", r#"{"lockfileVersion":3}"#),
    ]);
    assert!(ok, "compile should succeed; stderr:\n{stderr}");
    assert!(
        !stderr.contains("warning:"),
        "npm lockfile must not warn, got:\n{stderr}"
    );
}
