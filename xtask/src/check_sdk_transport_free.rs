//! `xtask check-sdk-transport-free`
//!
//! Assert that `mvm-sdk`'s **default** feature closure pulls no HTTPS/async
//! transport stack.
//!
//! `nix/packages/mvm-sdk-cdylib.nix` builds `--package mvm-sdk --lib` to
//! produce `libmvm_host_services.so`, the in-guest C ABI every language SDK
//! loads. That object speaks JSON over the vsock broker and needs no HTTP
//! client and no async runtime, but it is compiled from the whole crate — so a
//! dependency added for a host-side path lands inside the guest.
//!
//! It also breaks builds. `ring` carries C and platform assembly, so a
//! `mvm-http` in the default closure means the cdylib cannot be built for
//! `aarch64-unknown-linux-musl` without a musl C cross-compiler, and cannot be
//! built for `wasm32-unknown-unknown` at all. Both are targets the SDK surface
//! is meant to reach.
//!
//! Like `check-core-runtime-free`, this is deliberately *not* part of
//! `check-forbidden-deps`: those crates are legitimately in `Cargo.lock` (the
//! CLI enables `mvm-sdk/deploy-remote`, and plenty of host-side crates use
//! them). What must stay true is narrower — a *default* `mvm-sdk` build links
//! none of them — which is a feature-resolution fact read from `cargo tree`.

use anyhow::{Context, Result, bail};
use std::path::Path;
use std::process::Command;

/// Transport crates that must not appear in mvm-sdk's default tree. `mvm-http`
/// is the direct dependency; the other three are what it drags in, listed
/// explicitly so the failure names the actual cost rather than one manifest
/// line.
const TRANSPORT_CRATES: &[&str] = &["mvm-http", "rustls", "ring", "tokio"];

pub fn run(workspace: &Path) -> Result<()> {
    // `-e no-dev` excludes dev-deps: mvm-sdk keeps a tokio dev-dep for the
    // gated facade's `#[tokio::test]`s, which never reaches the cdylib.
    // Resolved with default features, so a member enabling `deploy-remote` in
    // the default closure surfaces here and trips the gate.
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let output = Command::new(&cargo)
        .current_dir(workspace)
        .args([
            "tree", "-p", "mvm-sdk", "-e", "no-dev", "--prefix", "none", "--locked",
        ])
        .output()
        .context("running `cargo tree -p mvm-sdk -e no-dev`")?;

    if !output.status.success() {
        bail!(
            "cargo tree failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    let tree = String::from_utf8_lossy(&output.stdout);
    let mut found: Vec<&str> = tree
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .filter(|name| TRANSPORT_CRATES.contains(name))
        .collect();
    found.sort_unstable();
    found.dedup();

    if !found.is_empty() {
        bail!(
            "check-sdk-transport-free: mvm-sdk's default build pulls an HTTPS/async transport \
             stack ({}). That closure is what `libmvm_host_services.so` is compiled from, so \
             this ships an HTTP client into every guest and — because `ring` carries C and \
             platform assembly — breaks the musl and wasm builds of the same object. Keep the \
             remote deploy transport behind `mvm-sdk/deploy-remote`; a workspace member likely \
             enabled it in the default closure.",
            found.join(", ")
        );
    }

    eprintln!(
        "check-sdk-transport-free: clean (mvm-sdk default closure pulls no mvm-http/rustls/ring/tokio)"
    );
    Ok(())
}
