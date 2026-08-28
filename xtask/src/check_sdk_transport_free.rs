//! `xtask check-sdk-transport-free`
//!
//! Two properties of the SDK crates' **default** feature closures.
//!
//! 1. Neither `mvm-sdk` nor `mvm-host-services` pulls an HTTPS/async transport
//!    stack. For `mvm-sdk` that keeps `rustls`/`ring`/`tokio` out of every
//!    `mvmctl` build that never deploys; the remote transport lives behind its
//!    `deploy-remote` feature, which the CLI enables.
//!
//! 2. `mvm-host-services` additionally pulls nothing that compiles C.
//!
//! The second is the load-bearing one. `nix/packages/mvm-sdk-cdylib.nix` builds
//! `--package mvm-host-services --lib` to produce `libmvm_host_services.so`,
//! the in-guest C ABI every language SDK loads. A C dependency in that closure
//! means the object cannot be cross-compiled to
//! `aarch64-unknown-linux-musl` without a musl C toolchain, and cannot be built
//! for `wasm32-unknown-unknown` at all — both targets the SDK surface is meant
//! to reach.
//!
//! That is exactly what a shared crate cost before the split: the FFI lived in
//! `mvm-sdk`, so the guest object was compiled from a crate that also holds the
//! decorator parser (five tree-sitter C parsers) and the deploy record
//! (`blake3`'s NEON path). "Pure Rust by construction" is only by construction
//! if something checks it.
//!
//! `cc` is the proxy for "compiles C": a crate with C source declares it as a
//! build-dependency, so it appears in the full tree even though it never
//! appears in a `-e no-dev,no-build` one.
//!
//! Like `check-core-runtime-free`, this is deliberately *not* part of
//! `check-forbidden-deps`: that check is lockfile-name-based, and every crate
//! named here is legitimately in `Cargo.lock`. What must stay true is narrower
//! — which crates a *particular* default closure resolves to — so it is read
//! from `cargo tree`.

use anyhow::{Context, Result, bail};
use std::path::Path;
use std::process::Command;

/// Transport crates that must not appear in either SDK closure. `mvm-http` is
/// the dependency an author would add; the other three are what it drags in,
/// listed explicitly so the failure names the actual cost rather than one
/// manifest line.
const TRANSPORT_CRATES: &[&str] = &["mvm-http", "rustls", "ring", "tokio"];

/// Resolve a package's dependency tree to a flat set of crate names.
///
/// `--prefix none` makes every line start with the crate name. `include_build`
/// selects whether build-dependencies are walked: they are what reveal a C
/// dependency, and irrelevant to the transport question.
fn tree_crates(workspace: &Path, package: &str, include_build: bool) -> Result<Vec<String>> {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let edges = if include_build {
        "no-dev"
    } else {
        "no-dev,no-build"
    };
    let output = Command::new(&cargo)
        .current_dir(workspace)
        .args([
            "tree", "-p", package, "-e", edges, "--prefix", "none", "--locked",
        ])
        .output()
        .with_context(|| format!("running `cargo tree -p {package} -e {edges}`"))?;

    if !output.status.success() {
        bail!(
            "cargo tree -p {package} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    let mut names: Vec<String> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .map(str::to_string)
        .collect();
    names.sort_unstable();
    names.dedup();
    Ok(names)
}

pub fn run(workspace: &Path) -> Result<()> {
    for package in ["mvm-sdk", "mvm-host-services"] {
        // `-e no-dev` excludes dev-deps: `mvm-sdk` keeps a tokio dev-dep for
        // the gated facade's `#[tokio::test]`s, which reaches nothing shipped.
        let crates = tree_crates(workspace, package, false)?;
        let found: Vec<&str> = crates
            .iter()
            .map(String::as_str)
            .filter(|name| TRANSPORT_CRATES.contains(name))
            .collect();
        if !found.is_empty() {
            bail!(
                "check-sdk-transport-free: {package}'s default build pulls an HTTPS/async \
                 transport stack ({}). Keep the remote deploy transport behind \
                 `mvm-sdk/deploy-remote`; a workspace member likely enabled it in the default \
                 closure. `ring` also carries C and platform assembly, which breaks the musl \
                 and wasm builds of `libmvm_host_services.so`.",
                found.join(", ")
            );
        }
    }

    // Build-dependencies included: `cc` is how a crate with C source announces
    // itself, and it appears nowhere else.
    let cdylib_closure = tree_crates(workspace, "mvm-host-services", true)?;
    if cdylib_closure.iter().any(|name| name == "cc") {
        bail!(
            "check-sdk-transport-free: mvm-host-services pulls a crate that compiles C (`cc` is \
             in its build-dependency tree). That crate is compiled into \
             `libmvm_host_services.so`, so this breaks cross-compiling the in-guest object to \
             aarch64-unknown-linux-musl without a musl C toolchain, and to \
             wasm32-unknown-unknown at all. The C ABI speaks JSON over the vsock broker — keep \
             its closure pure Rust and leave C-carrying dependencies in `mvm-sdk`."
        );
    }

    eprintln!(
        "check-sdk-transport-free: clean (mvm-sdk and mvm-host-services pull no \
         mvm-http/rustls/ring/tokio; the cdylib closure compiles no C)"
    );
    Ok(())
}
