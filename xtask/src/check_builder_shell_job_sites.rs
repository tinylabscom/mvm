//! `xtask check-builder-shell-job-sites`
//!
//! The builder VM's stable API is the typed `mvm-builderd` request set, not a
//! free-form shell job. The legacy "controlled shell-job" channel
//! (`builder_protocol::HostVmRequest::Run` and the older
//! `builder_agent::HostVmRequest::Build`) is being migrated onto
//! `builderd_client::BuilderdClient`; until that lands, this gate freezes the
//! set of source files that *construct* a shell-job request so a new
//! normal-path shell job can't be added in a new location while the migration
//! is in flight.
//!
//! This is a file-level allowlist (like `check-guest-images-no-builder-tools`):
//! a construction in any non-`bin/` source file outside the allowlist fails.
//! `bin/` is excluded — the in-guest `mvm-host-vm-init` legitimately *parses*
//! requests on the builder side. As WS-D removes a host-side dispatch site,
//! drop its file from the allowlist (the gate flags stale entries).

use anyhow::{Context, Result, bail};
use regex::Regex;
use std::path::{Path, PathBuf};

/// Source files allowed to construct a legacy builder shell-job request.
/// Host-side dispatch: `persistent_builder.rs` (dev_build) and
/// `pipeline/vsock_builder.rs` (pool_build) — the two WS-D will route through
/// `BuilderdClient`. Protocol-definition + guest-agent files carry the type
/// and its tests.
const ALLOWLIST: &[&str] = &[
    "crates/mvm-build/src/persistent_builder.rs",
    "crates/mvm-build/src/pipeline/vsock_builder.rs",
    "crates/mvm-build/src/builder_protocol.rs",
    "crates/mvm-guest/src/builder_agent.rs",
];

pub fn run(workspace: &Path) -> Result<()> {
    let re = Regex::new(r"HostVmRequest::(Run|Build)\s*\{").expect("static regex");
    let mut rs_files = Vec::new();
    collect_rs_files(&workspace.join("crates"), &mut rs_files)?;

    let mut hits = Vec::new();
    for file in &rs_files {
        let rel = file
            .strip_prefix(workspace)
            .unwrap_or(file)
            .to_string_lossy()
            .replace('\\', "/");
        // Only library/source code under `*/src/`, never `tests/`/`examples/`
        // (match-arm bindings there have braces but aren't dispatch sites).
        // `bin/` is the in-guest builder side, which parses requests.
        if !rel.contains("/src/") || rel.contains("/bin/") {
            continue;
        }
        let src =
            std::fs::read_to_string(file).with_context(|| format!("reading {}", file.display()))?;
        if re.is_match(&src) {
            hits.push(rel);
        }
    }
    hits.sort();
    hits.dedup();

    let offenders = offenders(&hits, ALLOWLIST);
    if !offenders.is_empty() {
        bail!(
            "check-builder-shell-job-sites: {} file(s) construct a legacy builder shell-job \
             request outside the allowlist: {}.\n\
             Drive builder work through the typed `mvm-builderd` API (`BuilderdClient`) instead \
             of `HostVmRequest::Run`/`Build`. If this is a sanctioned dispatch site, add it to \
             ALLOWLIST in xtask/src/check_builder_shell_job_sites.rs with a justification.",
            offenders.len(),
            offenders.join(", ")
        );
    }

    let stale = stale(&hits, ALLOWLIST);
    if !stale.is_empty() {
        eprintln!(
            "check-builder-shell-job-sites: clean ({} dispatch site(s)); {} allowlist entry(ies) \
             no longer construct a shell-job request — drop from ALLOWLIST as routing lands: {}",
            hits.len(),
            stale.len(),
            stale.join(", ")
        );
    } else {
        eprintln!(
            "check-builder-shell-job-sites: clean ({} shell-job construction site(s), all allowlisted)",
            hits.len()
        );
    }
    Ok(())
}

fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    if !dir.is_dir() {
        return Ok(());
    }
    for entry in std::fs::read_dir(dir).with_context(|| format!("reading dir {}", dir.display()))? {
        let path = entry?.path();
        if path.is_dir() {
            // Skip build output and VCS noise.
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name == "target" || name == ".git" {
                continue;
            }
            collect_rs_files(&path, out)?;
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
    Ok(())
}

/// Hit files not covered by the allowlist (new shell-job sites).
fn offenders<'a>(hits: &'a [String], allow: &[&str]) -> Vec<&'a str> {
    hits.iter()
        .map(String::as_str)
        .filter(|f| !allow.contains(f))
        .collect()
}

/// Allowlist entries that no longer construct a shell-job request (ratchet hint).
fn stale<'a>(hits: &[String], allow: &'a [&str]) -> Vec<&'a str> {
    let hit_set: std::collections::HashSet<&str> = hits.iter().map(String::as_str).collect();
    allow
        .iter()
        .copied()
        .filter(|f| !hit_set.contains(f))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_site_is_an_offender() {
        let hits = vec![
            "crates/mvm-build/src/persistent_builder.rs".to_string(),
            "crates/mvm-build/src/sneaky_new_dispatch.rs".to_string(),
        ];
        assert_eq!(
            offenders(&hits, ALLOWLIST),
            vec!["crates/mvm-build/src/sneaky_new_dispatch.rs"]
        );
    }

    #[test]
    fn all_allowlisted_has_no_offenders() {
        let hits: Vec<String> = ALLOWLIST.iter().map(|s| s.to_string()).collect();
        assert!(offenders(&hits, ALLOWLIST).is_empty());
    }

    #[test]
    fn removed_dispatch_site_is_stale() {
        // WS-D routed vsock_builder.rs through BuilderdClient → it stops matching.
        let hits = vec![
            "crates/mvm-build/src/persistent_builder.rs".to_string(),
            "crates/mvm-build/src/builder_protocol.rs".to_string(),
            "crates/mvm-guest/src/builder_agent.rs".to_string(),
        ];
        assert_eq!(
            stale(&hits, ALLOWLIST),
            vec!["crates/mvm-build/src/pipeline/vsock_builder.rs"]
        );
    }

    #[test]
    fn regex_matches_construction_not_match_arm() {
        let re = Regex::new(r"HostVmRequest::(Run|Build)\s*\{").unwrap();
        assert!(re.is_match("let r = HostVmRequest::Run {"));
        assert!(re.is_match("HostVmRequest::Build {"));
        // A match arm binding (`HostVmRequest::Run { job_id, .. } =>`) also has
        // a brace, so it is intentionally treated as a reference site too; the
        // file-level allowlist covers both. A bare path with no brace does not.
        assert!(!re.is_match("matches!(x, HostVmRequest::Run)"));
    }
}
