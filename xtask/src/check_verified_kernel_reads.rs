//! `xtask check-verified-kernel-reads`
//!
//! A workload kernel is served from the cache only when its bytes match a
//! recorded digest. `resolve_kernel` is where that check happens, and
//! `VerifiedKernel` exists so a cache hit cannot be spelled as a bare path.
//!
//! The type did its job for the arm that used it and nothing for the arms that
//! did not. `cached_kernel_path` is public — it has to be, callers need the
//! location for an error message — and it returns a perfectly usable
//! `PathBuf`. So two call sites took it and booted whatever sat there: the
//! Firecracker arm of the client's per-backend resolution, and the CLI's
//! kernel-less-image fallback, which formatted the path itself. Both looked
//! right, both were the weakest check of any boot route, and both passed every
//! test in the tree.
//!
//! This gate says: a file that asks for the cache location must also resolve
//! through the verified seam. It is co-presence within a file, not a proof that
//! the resolved value is the one used — a file could still resolve in one
//! function and use a bare path in another. A type that made the path
//! unusable would be stronger, but `cached_kernel_path` is legitimately needed
//! for diagnostics at exactly the sites that must not boot from it, so the
//! honest cheap control is to make a bare use visible in review rather than
//! impossible.

use anyhow::{Result, bail};
use std::path::Path;

/// Asking where the cached kernel lives.
const LOCATION: &str = "cached_kernel_path";

/// Checking that what lives there is what should.
const VERIFIED_SEAM: &str = "resolve_kernel";

/// The module that defines both, plus the digest helpers. Not a "caller".
const DEFINING_FILE: &str = "crates/mvm-build/src/kernel_fetch.rs";

/// Files that may name the location without resolving through the seam.
///
/// A test lane that *stages* a kernel is the legitimate case: it writes the
/// bytes and records the digest, which is a producer, not a reader. Adding a
/// production launch path here re-opens the hole this gate closes.
const ALLOWED_UNVERIFIED: &[&str] = &[
    // Live E2E lane: seeds MVM_E2E_KERNEL into the cache and records its
    // digest, then boots through the normal verified read.
    "crates/mvm-client/tests/launch_lifecycle_live.rs",
    // Stages pinned, unpinned and tampered kernels to assert which of them
    // `resolve_workload_kernel` will serve. It names the location because
    // that is the fixture it writes.
    "crates/mvm-client/src/launch/tests.rs",
    // Names the location as the *destination* it copies an already-resolved
    // kernel into, so the scenario's home carries one. The kernel it copies
    // came from `workload_kernel_path`, which resolves through the seam.
    "crates/mvm-conformance/tests/steps/volume.rs",
];

pub fn run(workspace: &Path) -> Result<()> {
    let mut offenders: Vec<String> = Vec::new();
    let mut verified_sites = 0usize;

    let mut files: Vec<(String, String)> = Vec::new();
    crate::fs_walk::for_each_file(&workspace.join("crates"), Some("rs"), &mut |path, text| {
        if text.contains(LOCATION) {
            let rel = path
                .strip_prefix(workspace)
                .unwrap_or(path)
                .to_string_lossy()
                .replace('\\', "/");
            files.push((rel, text.to_string()));
        }
    })?;

    for (rel, text) in files {
        if rel == DEFINING_FILE || ALLOWED_UNVERIFIED.contains(&rel.as_str()) {
            continue;
        }
        if text.contains(VERIFIED_SEAM) {
            verified_sites += 1;
            continue;
        }
        for (i, line) in text.lines().enumerate() {
            if line.contains(LOCATION) {
                offenders.push(format!("{rel}:{}: {}", i + 1, line.trim()));
            }
        }
    }

    if !offenders.is_empty() {
        for o in &offenders {
            eprintln!("[error] {o}");
        }
        bail!(
            "check-verified-kernel-reads: {} site(s) take the workload-kernel cache path without \
             calling `{VERIFIED_SEAM}`. A path that exists is not a kernel that verified — that \
             is how an intact kernel from the wrong build boots, which reads as a mysterious \
             guest failure rather than a cache fault. Resolve through the seam and use \
             `VerifiedKernel::path`, or add the file to ALLOWED_UNVERIFIED if it stages a kernel \
             rather than reading one.",
            offenders.len()
        );
    }

    // A gate that polices a symbol nobody calls passes for the wrong reason.
    if verified_sites == 0 {
        bail!(
            "check-verified-kernel-reads: no file outside {DEFINING_FILE} pairs `{LOCATION}` with \
             `{VERIFIED_SEAM}`. Either they were renamed — update this gate — or every read moved \
             behind another seam, in which case re-point it there."
        );
    }

    eprintln!(
        "check-verified-kernel-reads: clean ({verified_sites} site(s) resolve through the \
         verified seam)"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn workspace_with(files: &[(&str, &str)]) -> tempfile::TempDir {
        let tmp = tempfile::tempdir().unwrap();
        for (rel, body) in files {
            let p = tmp.path().join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, body).unwrap();
        }
        tmp
    }

    /// A reader that does it correctly, so the vacuity check is satisfied.
    fn verified_reader() -> (&'static str, &'static str) {
        (
            "crates/mvm-client/src/launch/mod.rs",
            "fn k() { resolve_kernel(&c, &a, \"workload\", false); cached_kernel_path(&c, &a, \
             \"workload\"); }",
        )
    }

    #[test]
    fn a_reader_that_resolves_through_the_seam_passes() {
        let tmp = workspace_with(&[verified_reader()]);
        assert!(run(tmp.path()).is_ok());
    }

    #[test]
    fn a_bare_path_read_is_refused() {
        let tmp = workspace_with(&[
            verified_reader(),
            (
                "crates/mvm-runtime/src/workload_runner/boot.rs",
                "fn boot() { let p = cached_kernel_path(&c, &a, \"workload\"); if p.is_file() {} }",
            ),
        ]);
        let err = run(tmp.path()).unwrap_err().to_string();
        assert!(err.contains("without calling"), "{err}");
    }

    #[test]
    fn a_staging_lane_on_the_allow_list_passes() {
        let tmp = workspace_with(&[
            verified_reader(),
            (
                "crates/mvm-client/tests/launch_lifecycle_live.rs",
                "fn seed() { let d = cached_kernel_path(&c, &a, \"workload\"); }",
            ),
        ]);
        assert!(run(tmp.path()).is_ok());
    }

    #[test]
    fn the_defining_file_is_not_treated_as_a_caller() {
        let tmp = workspace_with(&[
            verified_reader(),
            (
                "crates/mvm-build/src/kernel_fetch.rs",
                "pub fn cached_kernel_path() {}",
            ),
        ]);
        assert!(run(tmp.path()).is_ok());
    }

    #[test]
    fn a_workspace_with_no_verified_reader_is_refused_as_vacuous() {
        let tmp = workspace_with(&[(
            "crates/mvm-build/src/kernel_fetch.rs",
            "pub fn cached_kernel_path() {}",
        )]);
        let err = run(tmp.path()).unwrap_err().to_string();
        assert!(err.contains("no file outside"), "{err}");
    }
}
