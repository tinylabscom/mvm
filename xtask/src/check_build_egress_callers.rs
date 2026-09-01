//! `xtask check-build-egress-callers`
//!
//! `NetworkPolicy::trusted_build_egress()` returns unrestricted egress. It
//! exists because the Stage-0 builder VM and dev shells fetch from arbitrary
//! Nix substituters and forges, so no tight allow-list is possible there yet.
//! Cloud-metadata and link-local stay blocked by the always-on mandatory deny,
//! and the constructor is deliberately one named, greppable symbol so every
//! broad-egress grant is auditable.
//!
//! Its doc says: **never use it for a workload** (`mvmctl run`/`up`/`invoke`),
//! which default to `deny_all`. That sentence is the whole of claim 10 for this
//! constructor — and until this gate, nothing enforced it. A future workload
//! path could call it and turn off default-deny egress with every test green,
//! because a doc comment is not a control.
//!
//! This is the third instance of one shape in this tree: a correct mechanism
//! that nothing wires shut. `verify_fetched_kernel` hashed a kernel against its
//! pin and had no caller; `resolve_kernel` handed back a bare path so nothing
//! signalled a skipped check. Both were real, both were invisible, and both
//! were "obviously fine" by inspection.
//!
//! The gate is an allow-list of call sites rather than a type. A type would be
//! stronger, but `NetworkPolicy` flows through most of the tree and threading a
//! builder-only variant through it would be a large change to prevent a
//! mistake nobody has made yet. An allow-list keeps the cost proportionate and
//! makes adding a call site a reviewable, explicit act — which is the property
//! that was missing.

use anyhow::{Result, bail};
use std::path::Path;

/// The symbol whose call sites are restricted.
const SYMBOL: &str = "trusted_build_egress";

/// Files permitted to call it, relative to the workspace root.
///
/// Every entry must be builder or dev infrastructure. A workload launch path
/// must never appear here: adding one silently disables default-deny egress
/// for the workloads it launches, which is exactly what claim 10 asserts does
/// not happen.
const ALLOWED_CALLERS: &[&str] = &[
    // The builder VM's own launch policy.
    "crates/mvm-runtime/src/builder_runner/runner.rs",
    // The libkrun builder's supervisor config.
    "crates/mvm-build/src/libkrun_builder.rs",
    // The persistent HVF builder's endpoint, which is the same trusted builder
    // tier as `runner.rs` above and differs only in lifetime: the session
    // outlives the command that starts it, so it spawns its own endpoint
    // rather than inheriting the one-shot runner's. It carries no untrusted
    // workload — a workload microVM never boots from this policy.
    "crates/mvm-runtime/src/builder_runner/hvf_persistent.rs",
];

/// The file that defines the constructor, plus its own tests. Not a "caller"
/// in the sense this gate polices.
const DEFINING_FILE: &str = "crates/mvm-contract/src/policy/network_policy.rs";

/// Tests that assert properties *of* the constructor, from outside the
/// defining file. Same reasoning as [`DEFINING_FILE`]: naming the symbol in
/// order to pin its behaviour is the opposite of routing a workload through
/// it, and a gate that forbids testing the thing it polices would push the
/// property out of the suite entirely.
const PROPERTY_TEST_FILES: &[&str] = &[
    // Pins that `trusted_build_egress` stays a *separately named* constructor
    // rather than an alias of `unrestricted()` — the distinction this gate
    // exists to keep greppable.
    "crates/mvm-contract/tests/egress_predicate_algebra.rs",
];

pub fn run(workspace: &Path) -> Result<()> {
    let mut offenders: Vec<String> = Vec::new();
    let mut allowed_hits = 0usize;

    let mut files: Vec<(String, String)> = Vec::new();
    crate::fs_walk::for_each_file(&workspace.join("crates"), Some("rs"), &mut |path, text| {
        if text.contains(SYMBOL) {
            let rel = path
                .strip_prefix(workspace)
                .unwrap_or(path)
                .to_string_lossy()
                .replace('\\', "/");
            files.push((rel, text.to_string()));
        }
    })?;

    for (rel, text) in files {
        if rel == DEFINING_FILE || PROPERTY_TEST_FILES.contains(&rel.as_str()) {
            continue;
        }
        if ALLOWED_CALLERS.contains(&rel.as_str()) {
            allowed_hits += 1;
            continue;
        }

        for (i, line) in text.lines().enumerate() {
            if line.contains(SYMBOL) {
                offenders.push(format!("{rel}:{}: {}", i + 1, line.trim()));
            }
        }
    }

    if !offenders.is_empty() {
        for o in &offenders {
            eprintln!("[error] {o}");
        }
        bail!(
            "check-build-egress-callers: {} call site(s) of `{SYMBOL}` outside the builder/dev \
             allow-list. That constructor returns unrestricted egress; a workload reaching it \
             turns off claim 10's default-deny for everything it launches. If the new site is \
             genuinely builder or dev infrastructure, add it to ALLOWED_CALLERS — deliberately, \
             and say why in the commit.",
            offenders.len()
        );
    }

    // A silently-empty allow-list would make this gate vacuous: it would pass
    // just as happily if the constructor were deleted or renamed, and nobody
    // would notice it had stopped checking anything.
    if allowed_hits == 0 {
        bail!(
            "check-build-egress-callers: found no calls to `{SYMBOL}` at any allow-listed site. \
             Either the constructor was renamed — in which case update this gate — or the \
             builder no longer grants broad egress, in which case delete the allow-list entries \
             so the gate cannot pass vacuously."
        );
    }

    eprintln!(
        "check-build-egress-callers: clean ({allowed_hits} builder/dev call site(s); no workload \
         path reaches unrestricted egress)"
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

    /// The real allow-listed caller, so the vacuity check is satisfied.
    fn allowed_caller() -> (&'static str, &'static str) {
        (
            "crates/mvm-runtime/src/builder_runner/runner.rs",
            "fn x() { let p = NetworkPolicy::trusted_build_egress(); }",
        )
    }

    #[test]
    fn an_allow_listed_builder_caller_passes() {
        let tmp = workspace_with(&[allowed_caller()]);
        assert!(run(tmp.path()).is_ok());
    }

    #[test]
    fn a_workload_path_calling_it_is_refused() {
        let tmp = workspace_with(&[
            allowed_caller(),
            (
                "crates/mvm-runtime/src/workload_runner/runner.rs",
                "fn boot() { let p = NetworkPolicy::trusted_build_egress(); }",
            ),
        ]);
        let err = run(tmp.path()).unwrap_err().to_string();
        assert!(err.contains("outside the builder/dev allow-list"), "{err}");
    }

    #[test]
    fn the_defining_file_is_not_treated_as_a_caller() {
        let tmp = workspace_with(&[
            allowed_caller(),
            (
                "crates/mvm-contract/src/policy/network_policy.rs",
                "pub fn trusted_build_egress() -> Self { Self::unrestricted() }",
            ),
        ]);
        assert!(run(tmp.path()).is_ok());
    }

    #[test]
    fn an_empty_allow_list_hit_is_refused_rather_than_passing_vacuously() {
        // The failure mode this gate is meant to avoid being an instance of:
        // passing because it found nothing to check.
        let tmp = workspace_with(&[("crates/mvm-core/src/lib.rs", "fn unrelated() {}")]);
        let err = run(tmp.path()).unwrap_err().to_string();
        assert!(err.contains("no calls to"), "{err}");
    }
}
