//! A workload guest has exactly one way out.
//!
//! It used to have two, with different capabilities: a loopback listener that
//! tunnelled (`CONNECT`/SOCKS5) but could not substitute a credential, and a
//! second one that could substitute but only for an absolute-URI request and
//! refused to tunnel. Which one a request took was decided by whichever proxy
//! variable the workload's toolchain happened to read, so whether the host
//! substituted a credential was a property of the client library rather than of
//! the signed plan.
//!
//! The host now terminates a tunnel to a destination the plan binds a
//! credential to, so the tunnelling listener carries everything and the second
//! one is retired. This test is what keeps it retired: a reintroduced listener
//! would restore the split silently, because both halves work in isolation.

use std::path::{Path, PathBuf};

/// Names the retired listener was reachable by. Each is specific enough that a
/// surviving match is the listener itself and not an unrelated word — the one
/// surviving proxy legitimately forwards `http://` requests, so "forward" alone
/// would match code that must stay.
const RETIRED: &[&str] = &[
    "mvm-forward-proxy",
    "forward_proxy",
    "FORWARD_PROXY",
    "/mvm/runtime/forward-proxy",
    "127.0.0.1:18080",
];

/// Everything that ships or builds. Deliberately not `specs/`, which records
/// what the tree used to do and must keep saying so.
const ROOTS: &[&str] = &[
    "crates", "examples", "features", "nix", "scripts", "src", "tests", "xtask",
];

/// This file names every retired string in order to look for it.
const SELF: &str = "one_guest_egress_entry_point.rs";

fn repo_dir() -> PathBuf {
    PathBuf::from(
        std::env::var("CARGO_MANIFEST_DIR")
            .expect("CARGO_MANIFEST_DIR is set by cargo for integration tests"),
    )
}

/// Every readable file under `dir`, skipping build output and version control.
fn files_under(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name == "target" || name == ".git" || name == "node_modules" || name == SELF {
            continue;
        }
        match entry.file_type() {
            Ok(kind) if kind.is_dir() => files_under(&path, out),
            Ok(kind) if kind.is_file() => out.push(path),
            _ => {}
        }
    }
}

#[test]
fn nothing_that_ships_names_the_retired_second_guest_proxy() {
    let repo = repo_dir();
    let mut files = Vec::new();
    for root in ROOTS {
        files_under(&repo.join(root), &mut files);
    }
    assert!(
        files.len() > 100,
        "the scan found only {} files — it is not looking at the tree",
        files.len()
    );

    let mut hits = Vec::new();
    for path in &files {
        let Ok(content) = std::fs::read_to_string(path) else {
            continue; // Binary fixture; nothing to read.
        };
        for needle in RETIRED {
            if content.contains(needle) {
                hits.push(format!("{} names `{needle}`", path.display()));
            }
        }
    }

    assert!(
        hits.is_empty(),
        "the second guest egress listener is retired; a workload has one way out \
         and the host decides what is substituted:\n  {}",
        hits.join("\n  ")
    );
}

/// The surviving listener is named by the one helper that builds a workload's
/// proxy environment, so a caller cannot point a workload somewhere else
/// without changing the definition everything else reads.
#[test]
fn the_surviving_listener_has_one_definition() {
    assert_eq!(
        mvm_core::guest_netd::DEFAULT_EGRESS_PROXY_LISTEN,
        "127.0.0.1:1080"
    );
    let env: std::collections::HashMap<String, String> =
        mvm_core::guest_netd::proxy_env_vars(mvm_core::guest_netd::DEFAULT_EGRESS_PROXY_LISTEN)
            .into_iter()
            .collect();
    for var in ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"] {
        assert_eq!(
            env.get(var).map(String::as_str),
            Some("http://127.0.0.1:1080"),
            "{var} must name the one listener"
        );
    }
    assert_eq!(
        env.get("ALL_PROXY").map(String::as_str),
        Some("socks5h://127.0.0.1:1080"),
        "and the SOCKS form must be the same endpoint, so a client that prefers \
         it does not land somewhere else"
    );
}
