//! `xtask check-vsock-only-egress`
//!
//! vsock-only egress: a workload guest's only off-guest channel is vsock — there is **no
//! guest NIC**, and egress flows guest → vsock → the host endpoint seam. This gate
//! locks that in for the converged vsock-only path (the portable `vmm` device
//! model + the per-backend `VmmDriver` workload drivers): a regression that
//! attaches a virtio-net device, a tap, or a userspace net gateway to that path
//! re-introduces a guest NIC and fails closed here.
//!
//! Scope note: this gate covers the converged workload paths — the ones a real
//! `mvmctl up`/`mvmctl run` boot goes through — and fails closed if any of them
//! grows a guest NIC or alternate host gateway. It deliberately excludes two
//! kinds of code that legitimately mention these tokens without being a
//! workload-NIC regression:
//!
//! * `crates/mvm-backends/src/legacy/` — the pre-`VmmDriver` backend shims.
//!   Every production launch path (`AnyBackend`'s hvf/libkrun/fc/qemu
//!   variants) goes through `crate::driver`, not these; the legacy shims are
//!   identity/capability delegates plus a bench/example-only boot path
//!   (`mvm-cli/src/bench/probe.rs`, `examples/hvf-backend-*.rs`). QEMU's
//!   legacy shell in particular attaches a real `virtio-net-pci` slirp NIC on
//!   purpose — QEMU is a Tier-2 dev/test backend never used by `mvmd`, and
//!   ADR-001 deliberately does not wire claim-10 egress enforcement into it.
//! * `crates/mvm-backends/src/fc/snapshot.rs` — parses Firecracker's
//!   `network-interfaces` snapshot field *in order to assert it is empty*
//!   (`assert_vsock_only_device_model`). Guarding this file would flag its
//!   own fail-closed check and its negative-path tests as violations.
//!
//! `crates/mvm-backends/src/driver/qemu.rs` is excluded for the same
//! ADR-001 reason as the legacy QEMU shell above: QEMU is dev/test-only and
//! out of the claim-10 workload tier.

use anyhow::{Result, bail};
use regex::Regex;
use std::path::{Path, PathBuf};

/// Files/directories that implement the current no-guest-NIC workload path.
/// These must stay free of guest-NIC and legacy helper tokens.
///
/// Every entry here must exist — `run` treats a missing entry as a hard
/// error rather than silently scanning zero files, because that's exactly
/// how this gate went vacuous before: a refactor moved every one of these
/// paths and nothing noticed.
const GUARDED_PATHS: &[&str] = &[
    // Portable, hypervisor-agnostic device model (virtio-mmio: console,
    // block, entropy, vsock). No hypervisor FFI, no NIC device, shared by
    // every backend that drives it (HVF today).
    "crates/mvm-vmm/src/vmm",
    // The vsock egress seam — the single claim-10 decision point every
    // workload backend's substitution endpoint shares.
    "crates/mvm-vmm/src/vsock_egress_bridge",
    // `FcDriver` — Firecracker's sole production `VmmDriver` workload path.
    "crates/mvm-backends/src/driver/fc.rs",
    // `HvfDriver` — HVF's sole production `VmmDriver` workload path.
    "crates/mvm-backends/src/driver/hvf.rs",
    // Booting a fresh HVF VMM from a checkpoint — same production family as
    // `hvf.rs`, same NIC-less contract.
    "crates/mvm-backends/src/driver/hvf_restore.rs",
    // `LibkrunDriver` — libkrun's sole production `VmmDriver` workload path.
    "crates/mvm-backends/src/driver/libkrun.rs",
];

/// Below this many scanned files, treat the guard list as broken rather than
/// trust a "clean" result — the second backstop for the failure mode that
/// let this gate rot silently: a near-empty scan reads as passing even
/// though it is barely checking anything.
const MIN_EXPECTED_FILES: usize = 20;

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
    "network-interfaces",
    "iface_id",
    "host_dev_name",
];

pub fn run(workspace: &Path) -> Result<()> {
    check_guarded_paths_exist(workspace)?;

    let re = forbidden_regex();
    let rs_files = guarded_rs_files(workspace)?;

    check_scanned_file_floor(rs_files.len())?;

    let hits = scan_files_forbidden(workspace, &rs_files, &re);

    if !hits.is_empty() {
        bail!(
            "check-vsock-only-egress: a guest NIC / net gateway token appears on the \
             vsock-only path (vsock-only egress — no guest NIC; egress is vsock-mediated):\n{}",
            hits.join("\n")
        );
    }
    eprintln!(
        "check-vsock-only-egress: clean — {} files scanned across {} guarded paths, \
         no guest-NIC/net-gateway token found. The vmm/HVF/libkrun/FC workload path is NIC-free.",
        rs_files.len(),
        GUARDED_PATHS.len(),
    );
    Ok(())
}

/// Every entry in `GUARDED_PATHS` must exist on disk. A guard that silently
/// scans zero files because its targets moved reads as a passing check —
/// which is exactly the bug this function exists to prevent from recurring.
fn check_guarded_paths_exist(workspace: &Path) -> Result<()> {
    let missing: Vec<&str> = GUARDED_PATHS
        .iter()
        .filter(|guarded| !workspace.join(guarded).exists())
        .copied()
        .collect();

    if !missing.is_empty() {
        bail!(
            "check-vsock-only-egress: GUARDED_PATHS is stale — the following guarded \
             path(s) do not exist on disk and the check would silently scan nothing for \
             them:\n{}\n\
             Update GUARDED_PATHS in xtask/src/check_vsock_only_egress.rs to point at \
             wherever this code actually moved.",
            missing.join("\n")
        );
    }
    Ok(())
}

/// A scan that covers far fewer files than the guarded paths hold is a broken
/// gate, not a clean result — the second backstop against silent rot.
fn check_scanned_file_floor(scanned: usize) -> Result<()> {
    if scanned < MIN_EXPECTED_FILES {
        bail!(
            "check-vsock-only-egress: only {scanned} files scanned across {} guarded paths — \
             below the expected floor of {MIN_EXPECTED_FILES}. Either GUARDED_PATHS has \
             drifted from the real workload code again, or a path resolved to something \
             far smaller than it should. Treating this as a broken gate rather than a \
             clean result.",
            GUARDED_PATHS.len(),
        );
    }
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
    fn every_guarded_path_exists_in_this_workspace() {
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        check_guarded_paths_exist(&workspace).expect("GUARDED_PATHS must point at live code");
    }

    #[test]
    fn check_guarded_paths_exist_names_every_stale_entry() {
        let empty = tempfile::tempdir().expect("tempdir");
        let err = check_guarded_paths_exist(empty.path()).expect_err("empty tree must fail");
        let msg = err.to_string();
        for guarded in GUARDED_PATHS {
            assert!(msg.contains(guarded), "{guarded} missing from: {msg}");
        }
    }

    #[test]
    fn check_scanned_file_floor_rejects_a_near_empty_scan() {
        // The exact failure this backstop exists for: the guard list rotted,
        // nothing matched, and zero files read as "clean".
        let err = check_scanned_file_floor(0).expect_err("zero files must fail");
        assert!(err.to_string().contains("only 0 files scanned"));

        check_scanned_file_floor(MIN_EXPECTED_FILES).expect("at the floor is fine");
        check_scanned_file_floor(MIN_EXPECTED_FILES - 1).expect_err("below the floor must fail");
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
