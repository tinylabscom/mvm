//! `xtask check-duplicate-majors`
//!
//! Assert no *new* crate enters the workspace graph at two
//! semver-incompatible major versions (a ratchet). A duplicate major means
//! both versions compile into the tree: more build time, more code shipped,
//! and two copies of a type that cannot be passed across the boundary between
//! the two halves of the graph. The OCI/TLS stack (`http`/`hyper`/`reqwest`/
//! `base64` 0.x↔1.x) was the historical offender; the workspace consolidation
//! unified it on single majors. This gate stops the set from *growing* and
//! ratchets down as the remaining duplicates are removed.
//!
//! The scan reads `cargo metadata` (the full resolved graph from `Cargo.lock`,
//! every platform), so the result is deterministic regardless of the host
//! running it. Two versions are "duplicate majors" when their compatibility
//! key differs: the major for `>=1.0.0`, or the minor for `0.x` (where a minor
//! bump is breaking under Cargo's semver rules).

use anyhow::{Context, Result, bail};
use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;

/// Crates known to resolve at more than one major today. Baseline recaptured
/// 2026-08-10 from `cargo metadata --locked` (ratcheted 44 → 11 entries).
/// Remove an entry freely once the duplication is gone (the gate flags stale
/// entries); adding one must be justified in the PR that does — it admits a
/// new duplicate major into the build.
///
/// This list is measured over `cargo metadata --locked`: the full graph, all
/// targets and features, dev-dependencies included. `deny.toml`'s `skip` list
/// ratchets the same property over cargo-deny's *filtered* graph, which drops
/// dev-only edges and unenabled optional deps — so this list is strictly the
/// larger of the two. An entry here with no counterpart there is expected
/// whenever the duplication is dev-only or sits behind an optional dep nobody
/// enables; it is not evidence that either list has rotted.
const ALLOWLIST: &[&str] = &[
    // Both bitflags majors are transitive; mvm depends on neither directly.
    // The 1.x side comes from vmm-sys-util, whose latest release still declares
    // bitflags ^1.0 with no feature selecting 2.x. See deny.toml's matching
    // entry for the full audit.
    "bitflags",
    // `criterion` (the mvm-fs benchmark harness) pulls itertools 0.10, while
    // cucumber / derive-more / indexmap / zerotrie already resolve itertools
    // 0.14. Both majors are dev-only/test paths; criterion has no 0.14-compatible
    // release.
    "itertools",
    "getrandom",
    "hashbrown",
    // nom 8 is pulled only by the cargo-fuzz tooling in the fuzz member crates.
    // nom 7 used to enter behind rcgen's `x509-parser` feature; dropping that
    // feature took the whole ASN.1 stack with it, so the shipped closure now
    // carries no nom at all and this entry covers the fuzz tooling alone.
    "nom",
    // async-trait 0.1.92 requires syn 3 to stay compatible with current nightly
    // Clippy; other proc macros have not yet converged from syn 1 and 2.
    "syn",
    // The in-house VMM's rust-vmm virtio stack (virtio-queue) resolves
    // vmm-sys-util 0.15 while the Linux KVM stack (kvm-bindings/kvm-ioctls)
    // pins 0.12.1; the two rust-vmm families track different vmm-sys-util
    // majors until they converge.
    "vmm-sys-util",
    // sysinfo remains on the Windows 0.52 family while Tokio and current
    // Windows support crates use the 0.53 target shims. These are host-only.
    "windows-core",
    "windows-sys",
    "windows-targets",
    "windows_aarch64_gnullvm",
    "windows_aarch64_msvc",
    "windows_i686_gnu",
    "windows_i686_gnullvm",
    "windows_i686_msvc",
    "windows_x86_64_gnu",
    "windows_x86_64_gnullvm",
    "windows_x86_64_msvc",
];

pub fn run(workspace: &Path) -> Result<()> {
    let packages = resolved_packages(workspace)?;
    let found = duplicate_major_names(&packages);

    let regressions = regressions(&found, ALLOWLIST);
    if !regressions.is_empty() {
        bail!(
            "check-duplicate-majors: {} crate(s) newly resolve at two incompatible majors: {}.\n\
             A duplicate major compiles both versions into the build. Unify on one major \
             (align the dependents' version requirements), or, if it is genuinely unavoidable, \
             add the crate name to ALLOWLIST in xtask/src/check_duplicate_majors.rs with a \
             one-line justification in the PR.",
            regressions.len(),
            regressions.join(", ")
        );
    }

    let stale = stale_allowlist(&found, ALLOWLIST);
    if !stale.is_empty() {
        eprintln!(
            "check-duplicate-majors: clean ({} known duplicate-major crates); \
             {} allowlist entry(ies) no longer duplicated — drop from ALLOWLIST: {}",
            found.len(),
            stale.len(),
            stale.join(", ")
        );
    } else {
        eprintln!(
            "check-duplicate-majors: clean ({} known duplicate-major crates, all allowlisted)",
            found.len()
        );
    }
    Ok(())
}

/// `(name, version)` for every package in the resolved graph.
fn resolved_packages(workspace: &Path) -> Result<Vec<(String, String)>> {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let output = Command::new(&cargo)
        .current_dir(workspace)
        .args(["metadata", "--format-version", "1", "--locked"])
        .output()
        .context("running `cargo metadata --format-version 1 --locked`")?;
    if !output.status.success() {
        bail!(
            "cargo metadata failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let meta: serde_json::Value =
        serde_json::from_slice(&output.stdout).context("parsing cargo metadata JSON")?;
    let packages = meta
        .get("packages")
        .and_then(|p| p.as_array())
        .context("cargo metadata has no `packages` array")?;
    Ok(packages
        .iter()
        .filter_map(|p| {
            let name = p.get("name")?.as_str()?.to_string();
            let version = p.get("version")?.as_str()?.to_string();
            Some((name, version))
        })
        .collect())
}

/// Cargo's semver-compatibility key: the major for `>=1.0.0`, else the minor
/// for `0.x` (a `0.x` minor bump is breaking). Trailing pre-release/build
/// metadata is ignored — it does not change compatibility for this purpose.
fn compat_key(version: &str) -> (u64, u64) {
    let core = version.split('+').next().unwrap_or(version);
    let core = core.split('-').next().unwrap_or(core);
    let mut parts = core.split('.');
    let major = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    let minor = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    if major > 0 { (major, 0) } else { (0, minor) }
}

/// Names that resolve at two or more incompatible compatibility keys, sorted.
fn duplicate_major_names(packages: &[(String, String)]) -> Vec<String> {
    let mut by_name: BTreeMap<&str, Vec<(u64, u64)>> = BTreeMap::new();
    for (name, version) in packages {
        by_name.entry(name).or_default().push(compat_key(version));
    }
    by_name
        .into_iter()
        .filter_map(|(name, mut keys)| {
            keys.sort_unstable();
            keys.dedup();
            (keys.len() > 1).then(|| name.to_string())
        })
        .collect()
}

/// Found duplicate-major crates not covered by the allowlist (regressions).
fn regressions<'a>(found: &'a [String], allow: &[&str]) -> Vec<&'a str> {
    found
        .iter()
        .map(String::as_str)
        .filter(|name| !allow.contains(name))
        .collect()
}

/// Allowlist entries that no longer have a duplicate major (ratchet-down hint).
fn stale_allowlist<'a>(found: &[String], allow: &'a [&str]) -> Vec<&'a str> {
    let found_set: std::collections::HashSet<&str> = found.iter().map(String::as_str).collect();
    allow
        .iter()
        .copied()
        .filter(|name| !found_set.contains(name))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compat_key_uses_major_for_one_and_up() {
        assert_eq!(compat_key("1.2.3"), (1, 0));
        assert_eq!(compat_key("2.0.0"), (2, 0));
        assert_eq!(compat_key("10.4.1"), (10, 0));
    }

    #[test]
    fn compat_key_uses_minor_for_zero_major() {
        assert_eq!(compat_key("0.4.5"), (0, 4));
        assert_eq!(compat_key("0.21.7"), (0, 21));
        assert_eq!(compat_key("0.22.1"), (0, 22));
    }

    #[test]
    fn compat_key_strips_prerelease_and_build() {
        assert_eq!(compat_key("1.0.0-alpha.1"), (1, 0));
        assert_eq!(compat_key("0.5.0+build.7"), (0, 5));
    }

    #[test]
    fn detects_incompatible_majors() {
        let pkgs = vec![
            ("base64".to_string(), "0.21.7".to_string()),
            ("base64".to_string(), "0.22.1".to_string()),
            ("http".to_string(), "0.2.12".to_string()),
            ("http".to_string(), "1.4.0".to_string()),
        ];
        assert_eq!(duplicate_major_names(&pkgs), vec!["base64", "http"]);
    }

    #[test]
    fn same_major_different_patch_is_not_a_duplicate() {
        let pkgs = vec![
            ("serde".to_string(), "1.0.0".to_string()),
            ("serde".to_string(), "1.0.99".to_string()),
        ];
        assert!(duplicate_major_names(&pkgs).is_empty());
    }

    #[test]
    fn same_version_twice_is_not_a_duplicate() {
        let pkgs = vec![
            ("aho-corasick".to_string(), "1.1.4".to_string()),
            ("aho-corasick".to_string(), "1.1.4".to_string()),
        ];
        assert!(duplicate_major_names(&pkgs).is_empty());
    }

    #[test]
    fn regressions_are_found_minus_allowlist() {
        let found = vec!["base64".to_string(), "newdup".to_string()];
        assert_eq!(regressions(&found, &["base64"]), vec!["newdup"]);
    }

    #[test]
    fn stale_allowlist_is_allow_minus_found() {
        let found = vec!["base64".to_string()];
        assert_eq!(stale_allowlist(&found, &["base64", "gone"]), vec!["gone"]);
    }
}
