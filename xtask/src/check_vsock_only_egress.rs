//! `xtask check-vsock-only-egress`
//!
//! vsock-only egress: a workload guest's only off-guest channel is vsock — there is **no
//! guest NIC**, and egress flows guest → vsock → the host endpoint seam. This gate
//! locks that in for the converged vsock-only path (the portable `vmm` device
//! model + the raw-HVF backend): a regression that attaches a virtio-net device,
//! a tap, or a userspace net gateway to that path re-introduces a guest NIC and
//! fails closed here.
//!
//! Scope note: this gate covers the converged workload paths and fails closed
//! if any of them grows a guest NIC or alternate host gateway.

use anyhow::{Result, bail};
use regex::Regex;
use std::path::{Path, PathBuf};

/// Files/directories that implement the current no-guest-NIC path. These must
/// stay free of guest-NIC and legacy helper tokens.
const GUARDED_PATHS: &[&str] = &[
    "crates/mvm-runtime/src/vmm",
    "crates/mvm-runtime/src/hvf",
    "crates/mvm-runtime/src/libkrun.rs",
    "crates/mvm-runtime/src/vsock_egress_bridge",
];

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
    let re = forbidden_regex();
    let rs_files = guarded_rs_files(workspace)?;
    let hits = scan_files_forbidden(workspace, &rs_files, &re);

    if !hits.is_empty() {
        bail!(
            "check-vsock-only-egress: a guest NIC / net gateway token appears on the \
             vsock-only path (vsock-only egress — no guest NIC; egress is vsock-mediated):\n{}",
            hits.join("\n")
        );
    }
    eprintln!(
        "check-vsock-only-egress: clean ({} files; the vmm/HVF workload path is NIC-free)",
        rs_files.len()
    );
    Ok(())
}

fn forbidden_regex() -> Regex {
    Regex::new(&FORBIDDEN.join("|")).expect("static regex")
}

fn guarded_rs_files(workspace: &Path) -> Result<Vec<PathBuf>> {
    let mut rs_files = Vec::new();
    for guarded in GUARDED_PATHS {
        collect_rs_files(&workspace.join(guarded), &mut rs_files)?;
    }
    Ok(rs_files)
}

fn collect_rs_files(path: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    if path.is_file() {
        if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path.to_path_buf());
        }
        return Ok(());
    }
    if !path.is_dir() {
        return Ok(());
    }
    for entry in std::fs::read_dir(path)?.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rs_files(&path, out)?;
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
    Ok(())
}

fn scan_files_forbidden(workspace: &Path, files: &[PathBuf], re: &Regex) -> Vec<String> {
    let mut hits = Vec::new();
    for file in files {
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
    hits
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guarded_rs_files_collects_directory_and_file_entries() {
        let root = tempfile::tempdir().expect("tempdir");
        let dir = root.path().join("guarded-dir");
        std::fs::create_dir_all(&dir).expect("create dir");
        let nested = dir.join("nested.rs");
        std::fs::write(&nested, "fn ok() {}\n").expect("write nested");
        let single = root.path().join("single.rs");
        std::fs::write(&single, "fn solo() {}\n").expect("write single");

        let mut files = Vec::new();
        collect_rs_files(&dir, &mut files).expect("collect dir");
        collect_rs_files(&single, &mut files).expect("collect file");
        files.sort();

        assert_eq!(files, vec![nested, single]);
    }

    #[test]
    fn scan_files_forbidden_skips_comments_and_flags_code_tokens() {
        let root = tempfile::tempdir().expect("tempdir");
        let file = root.path().join("gate.rs");
        std::fs::write(
            &file,
            "// gvproxy mentioned in comment only\n\
             fn ok() { let _note = \"guest NIC\"; }\n\
             let _ = passt;\n",
        )
        .expect("write gate file");

        let hits = scan_files_forbidden(root.path(), &[file], &forbidden_regex());
        assert_eq!(hits.len(), 1, "got {hits:?}");
        assert!(hits[0].contains("passt"), "got {hits:?}");
    }
}
