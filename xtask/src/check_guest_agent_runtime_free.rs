//! `xtask check-guest-agent-runtime-free`
//!
//! Assert that `mvm-agentd`'s non-dev closure pulls no
//! async runtime — `tokio` — nor the async glue that drags it in
//! (`async-trait`, and the async `rtnetlink`/`netlink-packet-route`
//! netlink stack). The agent's request-serving path is synchronous
//! `std::thread` + `Mutex`/`Condvar` (see `worker_pool.rs`, `vsock.rs`);
//! the *only* async surface is `netinit`'s rtnetlink installer, which a
//! synchronous raw-netlink installer over `linux-raw-sys` replaces. Once
//! that lands, this set vanishes and the gate is the
//! regression backstop that keeps it gone.
//!
//! The same scan runs over `mvm-builder-guest` and `mvm-setpriv`, the other
//! two binaries shipped inside a guest, and additionally name-bans the crates
//! only a `host-state`-gated `mvm-core` module can pull in (`bs58`,
//! `unicode-normalization`, `keyring`, the `toml` parser stack, and the
//! `regex` stack): a guest binary resolving one of those means it started
//! depending on a host-state-gated `mvm-core` module, which is the boundary
//! the feature exists to draw. `tar` and `aho-corasick` are owned by the
//! feature too but reach guest binaries through legitimate independent edges,
//! so they are policed by the `host-state` feature-edge check instead of a
//! name ban.
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
//! Sibling of `check-core-runtime-free` — same lockfile-vs-
//! feature-resolution rationale: `tokio` is legitimately in `Cargo.lock`
//! (mvm-hostd et al. pull it), so a name-based lockfile check can't
//! express "not in *this crate's* tree". `cargo tree` can.

use anyhow::{Context, Result, bail};
use std::path::Path;
use std::process::Command;

/// Heavy deps the lean guest agent's default closure must not carry.
/// `tokio` is the async runtime; `async-trait` is the async-fn-in-trait
/// glue the old `RouteInstaller` needed; `rtnetlink`/`netlink-packet-route`
/// are the async netlink stack that pulled both in.
/// `schemars` is the protocol-schema-codegen dep — it's an
/// optional, off-by-default `schema`-feature dep used only by the
/// `emit_protocol_schema` bin at build time, and must never reach the
/// runtime agent's default closure.
///
/// The OpenTelemetry family is here for a different reason: guest
/// telemetry leaves only through the authenticated vsock telemetry session
/// to the host collector, and an exporter in the agent would be a second,
/// direct path out of the guest.
const FORBIDDEN: &[&str] = &[
    "tokio",
    "async-trait",
    "rtnetlink",
    "netlink-packet-route",
    "schemars",
    "opentelemetry",
    "opentelemetry_sdk",
    "opentelemetry-otlp",
    "opentelemetry-proto",
    "tracing-opentelemetry",
];

/// Crates that only a `host-state`-gated `mvm-core` module can pull into a
/// guest closure. Name-banned outright: no guest binary has another
/// legitimate edge to them. (`tar` and `aho-corasick` are *not* here —
/// `mvm-builder-guest` declares its own `tar` edge for
/// `builder_disk_transport`, and a general-purpose matcher like
/// `aho-corasick` is a legitimate direct guest edge should one appear;
/// those edges are policed by the feature check below, which
/// fires only when the `host-state` feature itself is enabled.)
const HOST_STATE_OWNED: &[&str] = &[
    "bs58",
    "unicode-normalization",
    "keyring",
    "toml",
    "toml_edit",
    "toml_datetime",
    "toml_write",
    "serde_spanned",
    "winnow",
    "regex",
    "regex-automata",
    "regex-syntax",
];

/// The guest's real build target. The async stack above is
/// `cfg(target_os = "linux")`-gated, invisible to a default (host) tree
/// on a macOS contributor host — pin a Linux target so the gate is real.
const GUEST_TARGET: &str = "aarch64-unknown-linux-musl";

/// The binaries that ship inside a guest.
const GUEST_PACKAGES: &[&str] = &["mvm-agentd", "mvm-builder-guest", "mvm-setpriv"];

pub fn run(workspace: &Path) -> Result<()> {
    for package in GUEST_PACKAGES {
        check_one(workspace, package)?;
        check_no_host_state_feature(workspace, package)?;
    }
    eprintln!(
        "check-guest-agent-runtime-free: clean ({:?} non-dev closures on {GUEST_TARGET} \
         pull no tokio/async-trait/rtnetlink, no host-state-owned dep, and do not enable \
         mvm-core/host-state)",
        GUEST_PACKAGES
    );
    Ok(())
}

/// Fail if any non-dev edge in the guest package's graph enables
/// `mvm-core/host-state`. Feature edges, not crate names: `host-state` marks
/// exactly the modules a guest must never link, and several of the crates it
/// owns (`tar`, `aho-corasick`) also reach guest binaries through legitimate
/// independent edges, so a name ban cannot express this. The inverted
/// `cargo tree -i mvm-core` on `features,no-dev` prints one
/// `mvm-core feature "host-state"` line per enabling edge; dev-only enablers
/// (a host crate's dev-dependency on the guest package's test helpers) are
/// filtered out by `no-dev`.
fn check_no_host_state_feature(workspace: &Path, package: &str) -> Result<()> {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let output = Command::new(&cargo)
        .current_dir(workspace)
        .args([
            "tree",
            "-p",
            package,
            "-e",
            "features,no-dev",
            "--prefix",
            "none",
            "--locked",
            "--target",
            GUEST_TARGET,
            "-i",
            "mvm-core",
        ])
        .output()
        .context("running `cargo tree -e features,no-dev -i mvm-core` for a guest package")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // A guest package with no mvm-core edge at all (mvm-setpriv links
        // libc only) has no inverted tree to scan — trivially clean.
        if stderr.contains("did not match any packages") {
            return Ok(());
        }
        bail!("cargo tree failed: {}", stderr.trim());
    }

    let tree = String::from_utf8_lossy(&output.stdout);
    if host_state_feature_present(&tree) {
        bail!(
            "check-guest-agent-runtime-free: {package}'s non-dev feature graph on \
             {GUEST_TARGET} enables mvm-core/host-state — a guest binary must not depend on \
             the host-state-gated mvm-core modules (did_key, workload_address, command_gate, \
             threat_classifier, keystore/secret_store, pii, receipt, stream_client, \
             registry_pack*, toml_loader, train_lock, domain::manifest, user_config, \
             config::fc_version, plan::bundle archive I/O). Drop the \
             reference; do not enable `host-state` for a guest crate."
        );
    }
    Ok(())
}

/// True when the inverted `cargo tree -e features -i mvm-core` output carries
/// at least one edge enabling `mvm-core/host-state`. `cargo tree` prints one
/// `mvm-core feature "host-state"` line per enabling edge under a `└──`/`├──`
/// tree prefix; the quote-terminated name keeps another feature of the same
/// crate from matching.
fn host_state_feature_present(tree: &str) -> bool {
    tree.lines()
        .any(|line| line.contains("mvm-core feature \"host-state\""))
}

fn check_one(workspace: &Path, package: &str) -> Result<()> {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let output = Command::new(&cargo)
        .current_dir(workspace)
        .args([
            "tree",
            "-p",
            package,
            "-e",
            "no-dev",
            "--prefix",
            "none",
            "--locked",
            "--target",
            GUEST_TARGET,
        ])
        .output()
        .context("running `cargo tree -p <guest> -e no-dev --target <guest>`")?;

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
            "check-guest-agent-runtime-free: {package}'s non-dev closure pulls the async \
             networking stack ({}) on {GUEST_TARGET}. Plan 124 A3 replaces netinit's \
             rtnetlink installer with synchronous raw netlink (linux-raw-sys), which drops \
             tokio + async-trait. If you're seeing this after A3, the async stack crept back \
             — keep the agent's request-serving path synchronous.",
            found.join(", ")
        );
    }

    let host_state_hits = forbidden_hits(&tree, HOST_STATE_OWNED);
    if !host_state_hits.is_empty() {
        bail!(
            "check-guest-agent-runtime-free: {package}'s non-dev closure on {GUEST_TARGET} \
             pulls host-state-owned dep(s) {} — a guest binary must not depend on the \
             `host-state`-gated mvm-core modules (did_key, workload_address, command_gate, \
             threat_classifier, keystore/secret_store, pii, registry_pack*, toml_loader, \
             train_lock, domain::manifest, user_config, config::fc_version, \
             plan::bundle::stream). Drop the reference; do not enable \
             `host-state` for a guest crate.",
            host_state_hits.join(", ")
        );
    }

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
        let tree = "mvm-agentd v0.15.2\nanyhow v1.0.99\nlibc v0.2.0\nserde v1.0.0\n";
        assert!(forbidden_hits(tree, FORBIDDEN).is_empty());
    }

    #[test]
    fn tree_with_async_stack_is_flagged() {
        // What the guest's Linux tree looks like before the
        // synchronous-netlink migration.
        let tree = "mvm-agentd v0.15.2\nasync-trait v0.1.89 (proc-macro)\nrtnetlink v0.14.1\n\
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
        let tree = "mvm-agentd v0.15.2\ntokio v1.49.0\ntokio v1.49.0 (*)\n";
        assert_eq!(forbidden_hits(tree, FORBIDDEN), vec!["tokio"]);
    }

    #[test]
    fn a_direct_guest_exporter_is_flagged() {
        let tree = "mvm-agentd v0.15.2\nopentelemetry v0.31.0\nopentelemetry-otlp v0.31.0\n";
        assert_eq!(
            forbidden_hits(tree, FORBIDDEN),
            vec!["opentelemetry", "opentelemetry-otlp"]
        );
    }

    #[test]
    fn substring_match_does_not_false_positive() {
        // `tokio-util`/`tokio-macros` are not `tokio`; key on exact name.
        let tree = "mvm-agentd v0.15.2\ntokio-util v0.7.0\ntokio-macros v2.0.0\n";
        assert!(forbidden_hits(tree, FORBIDDEN).is_empty());
    }

    #[test]
    fn host_state_owned_deps_are_flagged() {
        let tree = "mvm-builder-guest v0.24.2\nbs58 v0.5.1\nunicode-normalization v0.1.25\n";
        assert_eq!(
            forbidden_hits(tree, HOST_STATE_OWNED),
            vec!["bs58", "unicode-normalization"]
        );
    }

    #[test]
    fn toml_and_regex_stacks_are_flagged() {
        // The parser stacks only a host-state module can pull in; the leaves
        // are banned too so a partial edge (a guest crate depending on
        // `toml_edit` or `regex-syntax` directly) is caught just the same.
        let tree = "mvm-agentd v0.25.0\ntoml v0.8.23\ntoml_edit v0.22.27\nserde_spanned v0.6.9\n\
                    winnow v0.7.15\nregex v1.12.4\nregex-automata v0.4.14\nregex-syntax v0.8.11\n";
        assert_eq!(
            forbidden_hits(tree, HOST_STATE_OWNED),
            vec![
                "regex",
                "regex-automata",
                "regex-syntax",
                "serde_spanned",
                "toml",
                "toml_edit",
                "winnow"
            ]
        );
    }

    #[test]
    fn host_state_scan_ignores_unrelated_crates() {
        // Exact-match only: a minimal guest crate such as `mvm-setpriv`
        // links just libc and must pass.
        let tree = "mvm-setpriv v0.24.2\nlibc v0.2.0\n";
        assert!(forbidden_hits(tree, HOST_STATE_OWNED).is_empty());
    }

    #[test]
    fn host_state_feature_line_is_detected() {
        // The inverted feature tree prints one line per enabling edge; a
        // different feature of the same crate must not match.
        let enabled = "mvm-core feature \"default\"\n└── mvm-core feature \"host-state\"\n";
        let other = "mvm-core feature \"default\"\n└── mvm-core feature \"test-support\"\n";
        assert!(host_state_feature_present(enabled));
        assert!(!host_state_feature_present(other));
    }
}
