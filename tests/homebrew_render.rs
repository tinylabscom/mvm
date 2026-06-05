//! Verifies render-formula.sh fills every placeholder from a checksums file.

use std::path::PathBuf;
use std::process::Command;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn render_formula_fills_all_placeholders() {
    let tmp = tempfile::tempdir().unwrap();
    let checks = tmp.path().join("checksums-sha256.txt");
    std::fs::write(
        &checks,
        // No x86_64-apple-darwin (Intel mac) — that target is deferred.
        "aaaa  mvmctl-aarch64-apple-darwin.tar.gz\n\
         cccc  mvmctl-aarch64-unknown-linux-gnu.tar.gz\n\
         dddd  mvmctl-x86_64-unknown-linux-gnu.tar.gz\n",
    )
    .unwrap();
    let out = tmp.path().join("mvmctl.rb");

    let status = Command::new("sh")
        .arg(repo_root().join("packaging/homebrew/render-formula.sh"))
        .arg("0.15.2")
        .arg(&checks)
        .arg(&out)
        .status()
        .unwrap();
    assert!(status.success());

    let rendered = std::fs::read_to_string(&out).unwrap();
    assert!(!rendered.contains("@@"), "no placeholder should remain");
    assert!(rendered.contains("version \"0.15.2\""));
    assert!(rendered.contains("sha256 \"aaaa\""));
    assert!(rendered.contains("sha256 \"dddd\""));
}
