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
    // faster-hex optionally requires defmt ^0.3; 0.3.101 is an upstream
    // compatibility shim that non-optionally re-exports defmt 1.1 through
    // defmt10 ^1. This metadata-only duplication is absent from the selected
    // Linux all-feature closure.
    "defmt",
    // Existing wasmparser 0.244 uses hashbrown 0.15's default hasher
    // (foldhash 0.1.5); required gix-index 0.55 uses hashbrown 0.17's
    // defaults (foldhash 0.2.0). gix-hashtable and indexmap disable those
    // defaults. Their incompatible requirements have no feature-only unification.
    "foldhash",
    "getrandom",
    "hashbrown",
    // nom 8 is pulled only by the cargo-fuzz tooling in the fuzz member crates.
    // nom 7 used to enter behind rcgen's `x509-parser` feature; dropping that
    // feature took the whole ASN.1 stack with it, so the shipped closure now
    // carries no nom at all and this entry covers the fuzz tooling alone.
    "nom",
    // sigstore-verify 0.15 aligned on RustCrypto 0.11, so most of the old
    // 0.10-vs-0.11 duplicates are gone. block-buffer/const-oid/cpufeatures/
    // crypto-common/digest still appear because gix pulls in a sha1 crate that
    // uses the 0.10 digest line.
    "block-buffer",
    "const-oid",
    "cpufeatures",
    "crypto-common",
    "digest",
    "ryu-js",
    // sysinfo remains on an older Windows API family than Tokio and the
    // current Windows support crates. These are host-only.
    "windows-core",
    "windows-sys",
    // sigstore-crypto 0.15 uses der 0.7 / spki 0.7 / pem-rfc7468 0.6, while
    // p256 0.14 (the CryptoProvider backend) pulls der 0.8 / spki 0.8 /
    // pem-rfc7468 0.7. Both pairs are forced by these two crates' constraints;
    // neither can be collapsed without forking one of them.
    "der",
    "pem-rfc7468",
    "spki",
];

type DuplicateMajors<'a> = BTreeMap<&'a str, Vec<(u64, u64)>>;

pub(crate) fn run(workspace: &Path) -> Result<()> {
    let packages = resolved_packages(workspace)?;
    let found = duplicate_majors(&packages);

    let regressions = regressions(&found, ALLOWLIST);
    if !regressions.is_empty() {
        bail!(
            "check-duplicate-majors: {} crate(s) newly resolve at two incompatible majors: {}.\n\
             A duplicate major compiles both versions into the build. Unify on one major \
             (align the dependents' version requirements), or, if it is genuinely unavoidable, \
             obtain explicit approval for a narrowly justified dependency-policy change.",
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

/// Crates resolving at two or more compatibility keys, with sorted unique keys.
fn duplicate_majors(packages: &[(String, String)]) -> DuplicateMajors<'_> {
    let mut by_name = DuplicateMajors::new();
    for (name, version) in packages {
        by_name.entry(name).or_default().push(compat_key(version));
    }
    by_name
        .into_iter()
        .filter_map(|(name, mut keys)| {
            keys.sort_unstable();
            keys.dedup();
            (keys.len() > 1).then_some((name, keys))
        })
        .collect()
}

/// Duplicate-major crates outside the baseline.
fn regressions<'a>(found: &DuplicateMajors<'a>, allow: &[&str]) -> Vec<&'a str> {
    found
        .iter()
        .filter_map(|(&name, _)| (!allow.contains(&name)).then_some(name))
        .collect()
}

/// Allowlist entries that no longer have a duplicate major (ratchet-down hint).
fn stale_allowlist<'a>(found: &DuplicateMajors<'_>, allow: &'a [&str]) -> Vec<&'a str> {
    allow
        .iter()
        .copied()
        .filter(|name| !found.contains_key(name))
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
        assert_eq!(
            duplicate_majors(&pkgs),
            BTreeMap::from([
                ("base64", vec![(0, 21), (0, 22)]),
                ("http", vec![(0, 2), (1, 0)]),
            ])
        );
    }

    #[test]
    fn same_major_different_patch_is_not_a_duplicate() {
        let pkgs = vec![
            ("serde".to_string(), "1.0.0".to_string()),
            ("serde".to_string(), "1.0.99".to_string()),
        ];
        assert!(duplicate_majors(&pkgs).is_empty());
    }

    #[test]
    fn same_version_twice_is_not_a_duplicate() {
        let pkgs = vec![
            ("aho-corasick".to_string(), "1.1.4".to_string()),
            ("aho-corasick".to_string(), "1.1.4".to_string()),
        ];
        assert!(duplicate_majors(&pkgs).is_empty());
    }

    #[test]
    fn regressions_are_found_minus_allowlist() {
        let found = BTreeMap::from([
            ("base64", vec![(0, 21), (0, 22)]),
            ("newdup", vec![(1, 0), (2, 0)]),
        ]);
        assert_eq!(regressions(&found, &["base64"]), vec!["newdup"]);
    }

    #[test]
    fn stale_allowlist_is_allow_minus_found() {
        let found = BTreeMap::from([("base64", vec![(0, 21), (0, 22)])]);
        assert_eq!(stale_allowlist(&found, &["base64", "gone"]), vec!["gone"]);
    }

    fn package_regressions(packages: &[(&str, &[&str])]) -> Vec<String> {
        let packages: Vec<_> = packages
            .iter()
            .flat_map(|(name, versions)| {
                versions
                    .iter()
                    .map(move |version| (name.to_string(), version.to_string()))
            })
            .collect();
        regressions(&duplicate_majors(&packages), ALLOWLIST)
            .into_iter()
            .map(str::to_string)
            .collect()
    }

    #[test]
    fn former_coordinator_compatibility_pairs_are_rejected() {
        assert_eq!(
            package_regressions(&[
                ("syn", &["2.0.100", "3.0.0"]),
                ("winnow", &["0.7.13", "1.0.0"]),
            ]),
            ["syn", "winnow"]
        );
    }

    #[test]
    fn former_coordinator_pairs_reject_a_third_compatibility_key() {
        for extra in ["0.9.0", "1.0.0", "4.0.0"] {
            assert_eq!(
                package_regressions(&[("syn", &["2.0.100", "3.0.0", extra])]),
                ["syn"],
                "unexpected syn {extra}"
            );
        }
        for extra in ["0.6.0", "0.8.0", "2.0.0"] {
            assert_eq!(
                package_regressions(&[("winnow", &["0.7.13", "1.0.0", extra])]),
                ["winnow"],
                "unexpected winnow {extra}"
            );
        }
    }

    #[test]
    fn other_compatibility_pairs_are_rejected() {
        for (name, versions) in [
            ("syn", ["1.0.0", "2.0.0"]),
            ("syn", ["1.0.0", "3.0.0"]),
            ("syn", ["2.0.0", "4.0.0"]),
            ("syn", ["3.0.0", "4.0.0"]),
            ("winnow", ["0.6.0", "1.0.0"]),
            ("winnow", ["0.8.0", "1.0.0"]),
            ("winnow", ["0.7.0", "2.0.0"]),
            ("winnow", ["1.0.0", "2.0.0"]),
        ] {
            assert_eq!(
                package_regressions(&[(name, &versions)]),
                [name],
                "{name} {versions:?}"
            );
        }
    }

    #[test]
    fn duplicate_detection_uses_compatibility_keys_not_package_counts() {
        assert_eq!(
            package_regressions(&[
                ("syn", &["3.1.1", "2.0.100", "3.0.0", "2.0.101", "3.0.0"]),
                ("winnow", &["1.2.3", "0.7.13", "1.0.0", "0.7.14", "0.7.13"]),
            ]),
            ["syn", "winnow"]
        );
        assert!(
            package_regressions(&[
                ("syn", &["2.0.100", "2.0.101"]),
                ("winnow", &["0.7.13", "0.7.14"]),
            ])
            .is_empty()
        );
    }

    #[test]
    fn all_unapproved_duplicates_are_reported() {
        assert_eq!(
            package_regressions(&[
                ("syn", &["2.0.100", "3.0.0"]),
                ("winnow", &["0.7.13", "1.0.0"]),
                ("unrelated", &["1.0.0", "2.0.0"]),
            ]),
            ["syn", "unrelated", "winnow"]
        );
    }

    #[test]
    fn existing_baseline_remains_name_only() {
        for name in ALLOWLIST {
            assert!(
                package_regressions(&[(name, &["0.1.0", "1.0.0", "2.0.0"])]).is_empty(),
                "baseline exception {name}"
            );
        }
        assert!(!ALLOWLIST.contains(&"syn"));
        assert!(!ALLOWLIST.contains(&"winnow"));
    }

    #[test]
    fn cargo_deny_has_no_coordinator_compatibility_exceptions() {
        let config: toml::Value = include_str!("../../deny.toml").parse().unwrap();
        let skips: Vec<_> = config["bans"]["skip"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(toml::Value::as_str)
            .filter(|entry| entry.starts_with("syn") || entry.starts_with("winnow"))
            .collect();
        assert!(skips.is_empty(), "{skips:?}");
    }
}
