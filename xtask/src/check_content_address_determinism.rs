//! `xtask check-content-address-determinism`
//!
//! The plan_id and checkpoint content-addresses are `sha256(serde_json(...))`
//! over a value whose object keys must serialize in a stable order. `serde_json`
//! sorts object keys only while its `preserve_order` feature is **off**; with it
//! on, keys emit in insertion order and the same logical content can hash two
//! ways across builds — silently breaking every content-address and its
//! hash-linked lineage.
//!
//! Nothing in the normal dependency graph enables `preserve_order` today, and
//! the feature resolver keeps build-dependency features (some transitive
//! build-deps do pull it in) separate from the normal-dependency unit. This gate
//! pins that invariant: the **non-build** `serde_json` unit reachable from
//! `mvm-core` and `mvm-contract` must not carry `preserve_order`. It reads the
//! resolved feature set from `cargo tree` rather than the lockfile, because
//! whether a feature is on is a resolution fact, not a lockfile-name fact — the
//! same posture as `check-core-runtime-free`.

use anyhow::{Context, Result, bail};
use std::path::Path;
use std::process::Command;

/// Crates whose runtime `serde_json` unit derives content-addresses.
const CRATES: &[&str] = &["mvm-core", "mvm-contract"];

/// The feature whose presence on `serde_json` would break key-order determinism.
const FORBIDDEN_FEATURE: &str = "preserve_order";

pub fn run(workspace: &Path) -> Result<()> {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let mut offenders: Vec<String> = Vec::new();
    for crate_name in CRATES {
        let tree = serde_json_normal_tree(&cargo, workspace, crate_name)?;
        for line in serde_json_lines_with(&tree, FORBIDDEN_FEATURE) {
            offenders.push(format!("{crate_name}: {line}"));
        }
    }

    if !offenders.is_empty() {
        bail!(
            "check-content-address-determinism: a non-build serde_json unit reachable from \
             mvm-core/mvm-contract carries the `{FORBIDDEN_FEATURE}` feature. That makes \
             serde_json emit object keys in insertion order instead of sorted order, so the \
             plan_id and checkpoint content-addresses would hash non-deterministically across \
             builds. A workspace member likely enabled it on a normal (non-build) serde_json \
             dependency. Offending unit(s):\n  {}",
            offenders.join("\n  ")
        );
    }

    eprintln!(
        "check-content-address-determinism: clean (serde_json reachable from \
         mvm-core/mvm-contract has no `{FORBIDDEN_FEATURE}`)"
    );
    Ok(())
}

/// `cargo tree` for `crate_name`'s **normal** dependency unit, with each node's
/// resolved feature set. `-e no-dev,no-build` excludes dev- and build-deps so
/// the serde_json shown is the one linked into the crate's runtime code — the
/// unit whose key-order determinism the content-addresses depend on.
fn serde_json_normal_tree(cargo: &str, workspace: &Path, crate_name: &str) -> Result<String> {
    let output = Command::new(cargo)
        .current_dir(workspace)
        .args([
            "tree",
            "-p",
            crate_name,
            "-e",
            "no-dev,no-build",
            "--prefix",
            "none",
            "--format",
            "{p} {f}",
            "--locked",
        ])
        .output()
        .with_context(|| format!("running `cargo tree -p {crate_name} -e no-dev,no-build`"))?;

    if !output.status.success() {
        bail!(
            "cargo tree failed for {crate_name}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Lines of a `cargo tree --prefix none --format "{p} {f}"` dump that are the
/// `serde_json` **package** and whose resolved feature set contains `feature`.
///
/// Keyed on the first column being exactly `serde_json`, so a feature named
/// `serde_json` on some other crate's line (e.g. `tracing-subscriber`) is never
/// mistaken for the crate itself.
fn serde_json_lines_with(tree: &str, feature: &str) -> Vec<String> {
    tree.lines()
        .filter(|line| line.split_whitespace().next() == Some("serde_json"))
        .filter(|line| line_lists_feature(line, feature))
        .map(|line| line.trim().to_string())
        .collect()
}

/// Whether `line` lists `feature` as one of its comma-joined features. The `{f}`
/// column is comma-separated; splitting each whitespace token on `,` and testing
/// whole-token equality avoids matching a version or a substring.
fn line_lists_feature(line: &str, feature: &str) -> bool {
    line.split_whitespace()
        .flat_map(|tok| tok.split(','))
        .any(|f| f == feature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_tree_has_no_offenders() {
        let tree = "mvm-core v0.18.0 \n\
                    serde_json v1.0.150 alloc,default,float_roundtrip,std\n\
                    serde v1.0.0 alloc,derive,std\n";
        assert!(serde_json_lines_with(tree, "preserve_order").is_empty());
    }

    #[test]
    fn preserve_order_on_serde_json_is_flagged() {
        // Proof of teeth: the serde_json unit carrying preserve_order is caught.
        let tree = "mvm-core v0.18.0 \n\
                    serde_json v1.0.150 alloc,default,preserve_order,std (*)\n";
        let hits = serde_json_lines_with(tree, "preserve_order");
        assert_eq!(hits.len(), 1);
        assert!(hits[0].contains("preserve_order"));
    }

    #[test]
    fn preserve_order_on_another_crate_is_not_serde_json() {
        // `serde_json` appears here only as a FEATURE of another crate, which
        // also (synthetically) carries `preserve_order`. The gate keys on the
        // package in column 1, so neither is mistaken for the serde_json crate.
        let tree = "tracing-subscriber v0.3.23 alloc,serde_json,preserve_order,std\n\
                    serde_json v1.0.150 alloc,std\n";
        assert!(serde_json_lines_with(tree, "preserve_order").is_empty());
    }

    #[test]
    fn real_shape_line_with_version_and_dedup_marker_parses() {
        // The exact `{p} {f}` shape cargo tree emits, including the `(*)`
        // dedup marker: no false positive on preserve_order, real features found.
        let tree = "serde_json v1.0.150 alloc,default,float_roundtrip,std (*)\n";
        assert!(serde_json_lines_with(tree, "preserve_order").is_empty());
        assert_eq!(serde_json_lines_with(tree, "float_roundtrip").len(), 1);
    }
}
