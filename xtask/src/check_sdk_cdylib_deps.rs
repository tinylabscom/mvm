//! `xtask check-sdk-cdylib-deps`
//!
//! Keep the default `mvm-sdk` library closure suitable for the in-guest
//! host-services cdylib. The C ABI is synchronous JSON-over-vsock and must not
//! inherit the host-side remote deployment transport or its TLS/async stack.

use anyhow::{Context, Result, bail};
use std::path::Path;
use std::process::Command;

const FORBIDDEN: &[&str] = &["mvm-http", "ring", "rustls", "tokio", "tokio-rustls"];

pub fn run(workspace: &Path) -> Result<()> {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let output = Command::new(&cargo)
        .current_dir(workspace)
        .env_remove("RUSTC_WRAPPER")
        .args([
            "tree",
            "-p",
            "mvm-sdk",
            "-e",
            "no-dev,no-build",
            "--prefix",
            "none",
            "--locked",
        ])
        .output()
        .context("running `cargo tree -p mvm-sdk -e no-dev,no-build`")?;

    if !output.status.success() {
        bail!(
            "cargo tree failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    let tree = String::from_utf8_lossy(&output.stdout);
    let found = forbidden_hits(&tree, FORBIDDEN);
    if !found.is_empty() {
        bail!(
            "check-sdk-cdylib-deps: mvm-sdk's default non-dev closure pulls host-only HTTP/TLS/async dependencies ({}). Keep remote transport behind an off-by-default feature so the host-services cdylib remains cross-compilable without a C TLS stack.",
            found.join(", ")
        );
    }

    eprintln!(
        "check-sdk-cdylib-deps: clean (mvm-sdk default non-dev closure has no host HTTP/TLS/async stack)"
    );
    Ok(())
}

fn forbidden_hits<'a>(tree: &'a str, forbidden: &[&str]) -> Vec<&'a str> {
    let mut found: Vec<&str> = tree
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .filter(|name| forbidden.contains(name))
        .collect();
    found.sort_unstable();
    found.dedup();
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forbidden_transport_stack_is_reported_once_per_crate() {
        let tree = "mvm-sdk v0.18.0\nmvm-http v0.18.0\nrustls v0.23.0\nring v0.17.0\ntokio v1.52.0\ntokio v1.52.0 (*)\n";
        assert_eq!(
            forbidden_hits(tree, FORBIDDEN),
            vec!["mvm-http", "ring", "rustls", "tokio"]
        );
    }

    #[test]
    fn similarly_named_crates_do_not_false_positive() {
        let tree = "mvm-sdk v0.18.0\nrustls-pemfile v2.0.0\ntokio-util v0.7.0\n";
        assert!(forbidden_hits(tree, FORBIDDEN).is_empty());
    }
}
