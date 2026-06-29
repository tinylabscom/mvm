//! `xtask check-vsock-only-egress`
//!
//! ADR-100: a workload guest's only off-guest channel is vsock — there is **no
//! guest NIC**, and egress flows guest → vsock → the host gateway. This gate
//! locks that in for the converged vsock-only path (the portable `vmm` device
//! model + the raw-HVF backend): a regression that attaches a virtio-net device,
//! a tap, or a userspace net gateway to that path re-introduces a guest NIC and
//! fails closed here.
//!
//! Scope note: Firecracker / libkrun / vz still attach a virtio-net NIC today and
//! are converging onto the vsock gateway separately (ADR-100 step 2) — they are
//! deliberately **out of scope** for this gate until that lands, so it guards only
//! the directories that are supposed to already be NIC-free.

use anyhow::{Result, bail};
use regex::Regex;
use std::path::{Path, PathBuf};

/// Directories that implement the vsock-only path and must stay NIC-free.
const GUARDED_DIRS: &[&str] = &["crates/mvm-backend/src/vmm", "crates/mvm-backend/src/hvf"];

/// Tokens that signal a guest NIC / userspace net gateway on the data path.
/// `virtio_net`/`virtio-net`, a virtio net device id, tap attach, or the
/// userspace gateways (passt/gvproxy) appearing here would mean a guest NIC.
const FORBIDDEN: &[&str] = &[
    "virtio_net",
    "virtio-net",
    "VIRTIO_ID_NET",
    "add_net",
    "tap0",
    "passt",
    "gvproxy",
];

pub fn run(workspace: &Path) -> Result<()> {
    let re = Regex::new(&FORBIDDEN.join("|")).expect("static regex");
    let mut rs_files = Vec::new();
    for dir in GUARDED_DIRS {
        collect_rs_files(&workspace.join(dir), &mut rs_files)?;
    }

    let mut hits = Vec::new();
    for file in &rs_files {
        let text = std::fs::read_to_string(file).unwrap_or_default();
        for (n, line) in text.lines().enumerate() {
            // Skip comments — the gate is about code, and prose may mention NICs
            // (e.g. "no guest NIC") to explain the invariant.
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") || trimmed.starts_with('*') {
                continue;
            }
            if re.is_match(line) {
                hits.push(format!(
                    "{}:{}: {}",
                    file.strip_prefix(workspace).unwrap_or(file).display(),
                    n + 1,
                    line.trim()
                ));
            }
        }
    }

    if !hits.is_empty() {
        bail!(
            "check-vsock-only-egress: a guest NIC / net gateway token appears on the \
             vsock-only path (ADR-100 — no guest NIC; egress is vsock-mediated):\n{}",
            hits.join("\n")
        );
    }
    eprintln!(
        "check-vsock-only-egress: clean ({} files; the vmm + hvf path is NIC-free)",
        rs_files.len()
    );
    Ok(())
}

fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    if !dir.is_dir() {
        return Ok(());
    }
    for entry in std::fs::read_dir(dir)?.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rs_files(&path, out)?;
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
    Ok(())
}
