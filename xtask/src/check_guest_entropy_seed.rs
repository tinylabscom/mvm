//! `xtask check-guest-entropy-seed`
//!
//! Every guest boots with a device tree the VMM builds, and that tree must
//! carry `/chosen/rng-seed`.
//!
//! A workload guest has almost no interrupt jitter before its virtio-rng driver
//! probes. Without a credited bootloader seed the CSPRNG can therefore take
//! seconds to initialise — and the guest agent mints an Ed25519 identity key at
//! startup, so its first `getrandom(2)` blocks for that entire window before the
//! control plane comes up. Steady-state virtio-rng and the early boot seed are
//! complementary.
//!
//! The seed itself is unit-tested in `mvm_runtime::vmm::fdt`, which compiles
//! everywhere. The *call site* cannot be: the HVF boot path is
//! `#[cfg(all(target_os = "macos", target_arch = "aarch64"))]` and CI is
//! Linux-only, so no test that runs in CI ever links it. This gate covers
//! that hole by reading the source instead — a file that builds a device tree
//! must also obtain a seed to put in it.
//!
//! Fails on both regressions worth catching: a new VMM boot path that forgets
//! the seed, and someone deleting the seeding from the existing one.

use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};

/// The FDT builder's own module: it defines `build_dtb` and `fresh_rng_seed`
/// and exercises both with and without a seed, so it is not a call site.
const DEFINING_MODULE: &str = "crates/mvm-runtime/src/vmm/fdt.rs";

pub fn run(workspace: &Path) -> Result<()> {
    let mut rs_files = Vec::new();
    collect_rs_files(&workspace.join("crates"), &mut rs_files)?;

    let mut unseeded = Vec::new();
    let mut callers = 0usize;
    for file in &rs_files {
        let rel = file
            .strip_prefix(workspace)
            .unwrap_or(file)
            .to_string_lossy()
            .replace('\\', "/");
        if rel == DEFINING_MODULE || !rel.contains("/src/") {
            continue;
        }
        let src =
            std::fs::read_to_string(file).with_context(|| format!("reading {}", file.display()))?;
        if !src.contains("build_dtb(") {
            continue;
        }
        callers += 1;
        // The seed has to come from somewhere; requiring the helper keeps
        // every boot path on one source of per-boot host entropy rather than
        // letting one grow its own (a fixed or reused seed would hand two
        // guests the same CSPRNG starting state).
        if !src.contains("fresh_rng_seed") {
            unseeded.push(rel);
        }
    }

    if !unseeded.is_empty() {
        bail!(
            "check-guest-entropy-seed: {} file(s) build a guest device tree without seeding \
             its CSPRNG: {}.\n\
             Pass `Some(&fdt::fresh_rng_seed())` as `build_dtb`'s `rng_seed`. Without it the \
             guest has no credited entropy before its virtio-rng driver probes, so its first \
             `getrandom(2)` can block for seconds at boot.",
            unseeded.len(),
            unseeded.join(", ")
        );
    }

    // A gate that matches nothing passes vacuously forever. If the last caller
    // is renamed or moved, say so rather than reporting success.
    if callers == 0 {
        bail!(
            "check-guest-entropy-seed: found no `build_dtb(` call sites outside {DEFINING_MODULE}. \
             The gate is no longer covering anything — update it to match where the device tree \
             is built now."
        );
    }

    println!("check-guest-entropy-seed: {callers} device-tree boot path(s) seed the guest CSPRNG");
    Ok(())
}

fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    if !dir.is_dir() {
        return Ok(());
    }
    for entry in std::fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        let path = entry?.path();
        if path.is_dir() {
            if path.file_name().is_some_and(|n| n == "target") {
                continue;
            }
            collect_rs_files(&path, out)?;
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
    Ok(())
}
