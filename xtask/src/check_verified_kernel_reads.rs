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
//!
//! That check only ever looked at files naming `cached_kernel_path`, which left
//! it blind to the way the layout was most often written: by hand. Nine call
//! sites rebuilt `<cache>/kernels/<arch>/<variant>` with their own `join`
//! chains, and one of them — the BDD harness picking the kernel every
//! `@workload_kernel` scenario boots — selected it with a bare `is_file()`.
//! It was invisible here for as long as it spelled the path itself, and became
//! visible the moment it was routed through the helper. A gate that only sees
//! the disciplined callers reports on the population least likely to be wrong.
//!
//! So there are two checks now, and the second is what makes the first
//! complete: the layout may be built in exactly one place, which forces every
//! caller into the seam check above. The third is a drift alarm for shell,
//! which cannot call a Rust helper and so can only be held to "do not name the
//! retired location".

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

/// Building the kernel cache layout rather than asking for it.
///
/// The first `join` of the layout is enough: every hand-rolled form starts
/// here, and matching one component keeps the check from depending on how the
/// rest of the chain is spelled or wrapped.
const HANDROLLED_LAYOUT: &str = r#".join("kernels")"#;

/// The retired location. Kernels moved out of the builder-VM cache directory
/// because Stage 0 replaces that directory wholesale, taking any kernel inside
/// it with them.
const RETIRED_LAYOUT: &str = "builder-vm";

/// Shell that legitimately names the current kernel cache location.
///
/// Scripts cannot call the Rust helper, so they are held to the weaker rule:
/// name the current location, never the retired one.
const SHELL_ROOT: &str = "scripts";

/// Flag `.join("kernels")` outside the module that owns the layout.
///
/// The layout has one definition for the same reason a kernel has one digest:
/// a second copy is a second thing to keep in sync, and the copies drift
/// silently because each one works.
fn handrolled_layout_offenders(workspace: &Path) -> Result<Vec<String>> {
    let mut offenders = Vec::new();
    crate::fs_walk::for_each_file(&workspace.join("crates"), Some("rs"), &mut |path, text| {
        let rel = relative(workspace, path);
        if rel == DEFINING_FILE || !text.contains(HANDROLLED_LAYOUT) {
            return;
        }
        for (i, line) in text.lines().enumerate() {
            if line.contains(HANDROLLED_LAYOUT) {
                offenders.push(format!("{rel}:{}: {}", i + 1, line.trim()));
            }
        }
    })?;
    Ok(offenders)
}

/// Flag shell that still points at the pre-relocation kernel location.
///
/// Narrower than the Rust checks by necessity, and aimed at exactly the failure
/// it is named for: a relocation that updates the Rust and leaves a script
/// looking where kernels used to live. That script does not error — it finds
/// nothing, and a lane quietly stops covering what it claims to.
fn stale_shell_offenders(workspace: &Path) -> Result<Vec<String>> {
    let mut offenders = Vec::new();
    crate::fs_walk::for_each_file(
        &workspace.join(SHELL_ROOT),
        Some("sh"),
        &mut |path, text| {
            let rel = relative(workspace, path);
            for (i, line) in text.lines().enumerate() {
                if line.contains(RETIRED_LAYOUT) && line.contains("kernels") {
                    offenders.push(format!("{rel}:{}: {}", i + 1, line.trim()));
                }
            }
        },
    )?;
    Ok(offenders)
}

fn relative(workspace: &Path, path: &Path) -> String {
    path.strip_prefix(workspace)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

pub fn run(workspace: &Path) -> Result<()> {
    let handrolled = handrolled_layout_offenders(workspace)?;
    if !handrolled.is_empty() {
        for o in &handrolled {
            eprintln!("[error] {o}");
        }
        bail!(
            "check-verified-kernel-reads: {} site(s) build the kernel cache layout by hand \
             instead of calling `kernel_cache_dir` / `{LOCATION}`. A hand-rolled path is \
             invisible to the verified-read check below, which is how an unverified read of the \
             workload kernel survived in the BDD harness: it spelled the layout itself, so \
             nothing looked at it. Build the path through {DEFINING_FILE}.",
            handrolled.len()
        );
    }

    let stale_shell = stale_shell_offenders(workspace)?;
    if !stale_shell.is_empty() {
        for o in &stale_shell {
            eprintln!("[error] {o}");
        }
        bail!(
            "check-verified-kernel-reads: {} shell line(s) look for kernels under `{RETIRED_LAYOUT}`, \
             which is not where they live. Stage 0 replaces that directory wholesale, which is \
             why they moved out of it. A script pointed there finds nothing and reports no \
             error, so the lane it feeds silently stops covering what it claims to.",
            stale_shell.len()
        );
    }

    let mut offenders: Vec<String> = Vec::new();
    let mut verified_sites = 0usize;

    let mut files: Vec<(String, String)> = Vec::new();
    crate::fs_walk::for_each_file(&workspace.join("crates"), Some("rs"), &mut |path, text| {
        if text.contains(LOCATION) {
            files.push((relative(workspace, path), text.to_string()));
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

    /// The regression this gate did not catch. Before the layout had one
    /// definition, this file was invisible: no `cached_kernel_path`, so the
    /// verified-read check never looked at it, and it booted whatever sat at a
    /// path it spelled itself.
    #[test]
    fn a_handrolled_layout_is_refused_even_without_naming_the_helper() {
        let tmp = workspace_with(&[
            verified_reader(),
            (
                "crates/mvm-conformance/tests/conformance.rs",
                "fn k() { let p = cache.join(\"kernels\").join(arch).join(\"workload\"); \
                 p.is_file().then_some(p) }",
            ),
        ]);
        let err = run(tmp.path()).unwrap_err().to_string();
        assert!(
            err.contains("build the kernel cache layout by hand"),
            "{err}"
        );
    }

    /// The allow-list governs the verified-read check, not the one-definition
    /// rule. A staging lane may read the location without verifying; it may not
    /// keep its own copy of where that location is.
    #[test]
    fn the_allow_list_does_not_excuse_a_handrolled_layout() {
        let tmp = workspace_with(&[
            verified_reader(),
            (
                "crates/mvm-client/tests/launch_lifecycle_live.rs",
                "fn seed() { let d = c.join(\"kernels\").join(a).join(\"workload\"); }",
            ),
        ]);
        let err = run(tmp.path()).unwrap_err().to_string();
        assert!(
            err.contains("build the kernel cache layout by hand"),
            "{err}"
        );
    }

    #[test]
    fn the_module_that_owns_the_layout_may_build_it() {
        let tmp = workspace_with(&[
            verified_reader(),
            (
                "crates/mvm-build/src/kernel_fetch.rs",
                "pub fn kernel_cache_dir(c: &Path) -> PathBuf { c.join(\"kernels\") }\n\
                 pub fn cached_kernel_path() {}",
            ),
        ]);
        assert!(run(tmp.path()).is_ok());
    }

    /// The other straggler: a shell lane still looking where kernels used to
    /// live. It finds nothing and says nothing, so the seam it feeds goes dark.
    #[test]
    fn shell_pointed_at_the_retired_location_is_refused() {
        let tmp = workspace_with(&[
            verified_reader(),
            (
                "scripts/e2e-launch-modes.sh",
                "KERNEL=\"$(find \"$HOME/cache/builder-vm\" -name vmlinux -path '*kernels*')\"",
            ),
        ]);
        let err = run(tmp.path()).unwrap_err().to_string();
        assert!(err.contains("which is not where they live"), "{err}");
    }

    #[test]
    fn shell_naming_the_current_location_passes() {
        let tmp = workspace_with(&[
            verified_reader(),
            (
                "scripts/e2e-launch-modes.sh",
                "KERNEL=\"$(find \"$HOME/cache/kernels\" -name vmlinux -path '*workload*')\"",
            ),
        ]);
        assert!(run(tmp.path()).is_ok());
    }

    /// The builder VM's *own* kernel legitimately lives in that directory, and
    /// a script naming it is not the failure this looks for.
    #[test]
    fn shell_naming_the_builder_vms_own_kernel_is_not_flagged() {
        let tmp = workspace_with(&[
            verified_reader(),
            (
                "scripts/measure-hvf-density.sh",
                "seed=\"${CACHE_DIR}/builder-vm/${arch}/vmlinux\"",
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
