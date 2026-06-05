//! `xtask check-guest-agent-runtime-free`
//!
//! Plan 124 Phase A. Assert that `mvm-guest`'s non-dev closure pulls no
//! async runtime — `tokio` — nor the async glue that drags it in
//! (`async-trait`, and the async `rtnetlink`/`netlink-packet-route`
//! netlink stack). The agent's request-serving path is synchronous
//! `std::thread` + `Mutex`/`Condvar` (see `worker_pool.rs`, `vsock.rs`);
//! the *only* async surface is `netinit`'s rtnetlink installer, which
//! Phase A Task A3 replaces with synchronous raw netlink over
//! `linux-raw-sys`. Once A3 lands, this set vanishes and the gate is the
//! regression backstop that keeps it gone.
//!
//! **Target matters.** `tokio`/`rtnetlink`/`netlink-packet-route` are
//! `cfg(target_os = "linux")` deps (host-side mvmctl builds on macOS skip
//! them). `cargo tree` resolves for the *host* target by default, so on a
//! macOS dev host the gated stack is invisible and the gate would pass
//! vacuously. We pin `--target aarch64-unknown-linux-musl` (the guest's
//! real target) so the check sees the closure the guest actually links.
//! `cargo tree` resolves a target's cfg graph without the rustup std
//! target installed, so this is portable across contributor hosts and CI.
//!
//! Sibling of `check-core-runtime-free` (plan 126 B5) — same lockfile-vs-
//! feature-resolution rationale: `tokio` is legitimately in `Cargo.lock`
//! (mvm-hostd et al. pull it), so a name-based lockfile check can't
//! express "not in *this crate's* tree". `cargo tree` can.

use anyhow::{Context, Result, bail};
use std::path::Path;
use std::process::Command;

/// The async closure the lean guest agent must not carry (Plan 124 A3).
/// `tokio` is the runtime; `async-trait` is the async-fn-in-trait glue
/// the old `RouteInstaller` needed; `rtnetlink`/`netlink-packet-route`
/// are the async netlink stack that pulled both in.
const FORBIDDEN: &[&str] = &["tokio", "async-trait", "rtnetlink", "netlink-packet-route"];

/// The guest's real build target. The async stack above is
/// `cfg(target_os = "linux")`-gated, invisible to a default (host) tree
/// on a macOS contributor host — pin a Linux target so the gate is real.
const GUEST_TARGET: &str = "aarch64-unknown-linux-musl";

pub fn run(workspace: &Path) -> Result<()> {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let output = Command::new(&cargo)
        .current_dir(workspace)
        .args([
            "tree",
            "-p",
            "mvm-guest",
            "-e",
            "no-dev",
            "--prefix",
            "none",
            "--locked",
            "--target",
            GUEST_TARGET,
        ])
        .output()
        .context("running `cargo tree -p mvm-guest -e no-dev --target <guest>`")?;

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
            "check-guest-agent-runtime-free: mvm-guest's non-dev closure pulls the async \
             networking stack ({}) on {GUEST_TARGET}. Plan 124 A3 replaces netinit's \
             rtnetlink installer with synchronous raw netlink (linux-raw-sys), which drops \
             tokio + async-trait. If you're seeing this after A3, the async stack crept back \
             — keep the agent's request-serving path synchronous.",
            found.join(", ")
        );
    }

    eprintln!(
        "check-guest-agent-runtime-free: clean (mvm-guest non-dev closure on {GUEST_TARGET} \
         pulls no tokio/async-trait/rtnetlink)"
    );
    Ok(())
}

/// Parse `cargo tree --prefix none` output (one crate per line, name
/// first) and return the sorted-unique forbidden crates present. Shared
/// shape with `check_core_runtime_free` — keyed on the exact crate name
/// so `tokio-util` never false-positives for `tokio`.
fn forbidden_hits<'a>(tree: &'a str, forbidden: &[&str]) -> Vec<&'a str> {
    let mut hits: Vec<&str> = tree
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .filter(|name| forbidden.contains(name))
        .collect();
    hits.sort_unstable();
    hits.dedup();
    hits
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_tree_has_no_async_stack() {
        let tree = "mvm-guest v0.15.2\nanyhow v1.0.99\nlibc v0.2.0\nserde v1.0.0\n";
        assert!(forbidden_hits(tree, FORBIDDEN).is_empty());
    }

    #[test]
    fn tree_with_async_stack_is_flagged() {
        // What the guest's Linux tree looks like today, pre-A3.
        let tree = "mvm-guest v0.15.2\nasync-trait v0.1.89 (proc-macro)\nrtnetlink v0.14.1\n\
                    netlink-packet-route v0.19.0\ntokio v1.49.0\ntokio v1.49.0 (*)\n";
        assert_eq!(
            forbidden_hits(tree, FORBIDDEN),
            vec!["async-trait", "netlink-packet-route", "rtnetlink", "tokio"]
        );
    }

    #[test]
    fn dedups_repeated_tokio_lines() {
        // `cargo tree` prints `(*)` dedup markers for repeated subtrees;
        // the parser must collapse them to one hit.
        let tree = "mvm-guest v0.15.2\ntokio v1.49.0\ntokio v1.49.0 (*)\n";
        assert_eq!(forbidden_hits(tree, FORBIDDEN), vec!["tokio"]);
    }

    #[test]
    fn substring_match_does_not_false_positive() {
        // `tokio-util`/`tokio-macros` are not `tokio`; key on exact name.
        let tree = "mvm-guest v0.15.2\ntokio-util v0.7.0\ntokio-macros v2.0.0\n";
        assert!(forbidden_hits(tree, FORBIDDEN).is_empty());
    }
}
