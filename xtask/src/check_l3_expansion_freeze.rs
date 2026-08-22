//! `xtask check-l3-expansion-freeze`
//!
//! The raw-packet workload networking path is frozen while its replacement is
//! built. Frozen means two things, and this gate is both of them:
//!
//! - **No new entrants.** A non-test reference to one of the retired symbols
//!   may appear only in a file that already had one. The allowlist below is an
//!   explicit file list, not a pattern.
//! - **It can only shrink.** An allowlist entry that no longer matches
//!   anything fails the gate, so a file that gets cleaned up must be struck
//!   from the list in the same change. Without that arm the list would decay
//!   into a permanent exemption set, which is the failure mode every
//!   long-lived allowlist has.
//!
//! This gate is temporary by construction. It is deleted along with the last
//! allowlist entry, and replaced by a permanent single-network-path gate and a
//! socket-owner gate once the raw-packet stack is gone. Tests are out of scope
//! on purpose: a test that pins today's behaviour of code scheduled for
//! deletion is doing its job, and forcing it onto an allowlist would make the
//! list grow for the wrong reason.

use anyhow::{Context, Result, bail};
use regex::Regex;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// The retired symbols. Matched on word boundaries and case-sensitively, so
/// `refuse_raw_ip_stack` and the `l3-vsock` prose spelling do not trip it.
const FROZEN: &[&str] = &[
    "L3Vsock",
    "raw_ip_stack",
    "NetworkControl",
    "NetworkData",
    "spawn_netd",
    "host_datapath",
];

/// Files that already reference a frozen symbol and are scheduled for deletion
/// or migration. **Append nothing.** Entries leave as the stack is removed; an
/// entry that stops matching is a hard failure, which is what makes the list
/// monotonically shrink.
const ALLOWLIST: &[&str] = &[
    // The IR compatibility boundary still names the rejected legacy field.
    "crates/mvm-contract/src/ir/workload.rs",
    // CLI compatibility input still names the rejected legacy field.
    "crates/mvm-cli/src/commands/machine/runtime.rs",
    // Decorator compatibility boundaries still name the rejected kwarg.
    "crates/mvm-sdk/src/decorator/python.rs",
    "crates/mvm-sdk/src/decorator/value.rs",
];

/// Path fragments that mark a file as test code, which this gate does not read.
const TEST_MARKERS: &[&str] = &[
    "/tests/",
    "/tests.rs",
    "/test_support.rs",
    "/fuzz/",
    "/benches/",
];

/// Trees the gate never reads: the gate and the plan/ADR record that describe
/// the retirement, plus VCS and build output.
const EXEMPT: &[&str] = &[
    "xtask/src/check_l3_expansion_freeze.rs",
    "specs/",
    "CHANGELOG.md",
];

const SKIP_DIRS: &[&str] = &[
    ".git",
    ".claude",
    ".mvm-test",
    ".mvm-verify",
    "target",
    "node_modules",
    ".worktrees",
    "dist",
    ".astro",
];

pub fn run(workspace: &Path) -> Result<()> {
    let re = frozen_regex()?;
    let mut new_entrants: Vec<String> = Vec::new();
    let mut matched_allowlist: BTreeSet<&str> = BTreeSet::new();
    let mut scanned = 0usize;

    for path in walk(workspace)? {
        let rel = relative(workspace, &path);
        if is_skipped(&rel) {
            continue;
        }
        let Ok(body) = std::fs::read_to_string(&path) else {
            continue; // binary or unreadable
        };
        scanned += 1;
        let allowed = allowlist_entry_for(&rel);
        for (i, line) in body.lines().enumerate() {
            for m in re.find_iter(line) {
                match allowed {
                    Some(entry) => {
                        matched_allowlist.insert(entry);
                    }
                    None => new_entrants.push(format!("{rel}:{}: {}", i + 1, m.as_str())),
                }
            }
        }
    }

    if !new_entrants.is_empty() {
        bail!(
            "check-l3-expansion-freeze: {} new non-test reference(s) to a frozen \
             raw-packet networking symbol:\n  {}\n\n\
             The in-guest IP stack is frozen while the single flow-aware vsock path is \
             built, and the allowlist in this gate may only shrink. Route the work \
             through the guest loopback adapters or a typed connector instead of \
             extending the retired stack.",
            new_entrants.len(),
            joined(&new_entrants)
        );
    }

    let stale: Vec<&str> = ALLOWLIST
        .iter()
        .copied()
        .filter(|e| !matched_allowlist.contains(e))
        .collect();
    if !stale.is_empty() {
        bail!(
            "check-l3-expansion-freeze: {} allowlist entr(y/ies) no longer reference a \
             frozen symbol:\n  {}\n\n\
             Delete them from ALLOWLIST in the same change that cleaned the file. The \
             allowlist is the remaining-work ledger; an entry that no longer matches is \
             a permanent exemption in the making.",
            stale.len(),
            stale.join("\n  ")
        );
    }

    eprintln!(
        "check-l3-expansion-freeze: frozen ({scanned} text file(s) scanned, \
         {} allowlist entr(y/ies) remaining)",
        ALLOWLIST.len()
    );
    Ok(())
}

fn frozen_regex() -> Result<Regex> {
    Regex::new(&format!(r"\b({})\b", FROZEN.join("|"))).context("compile frozen-symbol regex")
}

fn relative(workspace: &Path, path: &Path) -> String {
    path.strip_prefix(workspace)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

/// Whether the gate reads this file at all.
///
/// Test code and the retirement's own record are out of scope; a lockfile
/// carries transitive names we do not control.
fn is_skipped(rel: &str) -> bool {
    if EXEMPT.iter().any(|e| rel.starts_with(e) || rel == *e) {
        return true;
    }
    if rel.ends_with(".lock") {
        return true;
    }
    let probe = format!("/{rel}");
    TEST_MARKERS.iter().any(|m| probe.contains(m))
        || probe
            .rsplit('/')
            .next()
            .is_some_and(|f| f.starts_with("test_") && f.ends_with(".py"))
}

/// The allowlist entry covering `rel`, if any. A trailing `/` entry covers a
/// directory; anything else is an exact file.
fn allowlist_entry_for(rel: &str) -> Option<&'static str> {
    ALLOWLIST.iter().copied().find(|e| {
        if e.ends_with('/') {
            rel.starts_with(e)
        } else {
            rel == *e
        }
    })
}

fn joined(hits: &[String]) -> String {
    let shown = hits
        .iter()
        .take(40)
        .cloned()
        .collect::<Vec<_>>()
        .join("\n  ");
    if hits.len() > 40 {
        format!("{shown}\n  ... and {} more", hits.len() - 40)
    } else {
        shown
    }
}

/// Every file under `root`, skipping [`SKIP_DIRS`] and never following a
/// symlink — `nix build` drops a `result` symlink into the repo root pointing
/// at `/nix/store`, and following it would walk the store.
fn walk(root: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if file_type.is_symlink() {
                continue;
            }
            let path = entry.path();
            if file_type.is_dir() {
                let name = entry.file_name().to_string_lossy().into_owned();
                if SKIP_DIRS.contains(&name.as_str()) {
                    continue;
                }
                stack.push(path);
            } else {
                out.push(path);
            }
        }
    }
    out.sort();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn workspace() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
    }

    /// The whole point: the tree is frozen today, and stays frozen.
    #[test]
    fn the_workspace_is_frozen() {
        run(&workspace()).expect("no new raw-packet references and no stale allowlist entries");
    }

    #[test]
    fn every_frozen_symbol_is_matched_on_a_word_boundary() {
        let re = frozen_regex().expect("regex");
        for sym in FROZEN {
            assert!(re.is_match(sym), "{sym} does not match its own pattern");
        }
        // A compatibility helper may embed a frozen symbol after an underscore,
        // which is a word character — so it must not trip the gate.
        assert!(!re.is_match("reject_raw_ip_stack_input"));
        // Prose spells the mode with a hyphen; only the type name is frozen.
        assert!(!re.is_match("l3-vsock"));
    }

    #[test]
    fn a_new_non_test_file_would_be_flagged() {
        let re = frozen_regex().expect("regex");
        let synthetic = "crates/mvm-runtime/src/some_new_module.rs";
        assert!(
            allowlist_entry_for(synthetic).is_none(),
            "a file nobody allowlisted must not be covered"
        );
        assert!(!is_skipped(synthetic), "a src file is in scope");
        assert!(re.is_match("let mode = NetworkMode::L3Vsock;"));
    }

    #[test]
    fn test_paths_are_out_of_scope() {
        for rel in [
            "crates/mvm-hostd/tests/network_endpoint_bin.rs",
            "crates/mvm-cli/src/commands/machine/tests.rs",
            "crates/mvm-core/src/plan/test_support.rs",
            "crates/mvm-agentd/fuzz/fuzz_targets/x.rs",
            "crates/mvm-sdk/sdks/python/tests/test_hooks_and_helpers.py",
        ] {
            assert!(is_skipped(rel), "{rel} should be out of scope");
        }
    }

    #[test]
    fn the_retirement_record_is_out_of_scope() {
        assert!(is_skipped(
            "specs/plans/316-single-flow-vsock-networking.md"
        ));
        assert!(is_skipped("specs/adrs/036-l3-tun-over-vsock.md"));
        assert!(is_skipped("xtask/src/check_l3_expansion_freeze.rs"));
    }

    #[test]
    fn a_directory_entry_covers_its_files_and_a_file_entry_does_not_prefix_match() {
        assert_eq!(
            allowlist_entry_for("crates/mvm-sdk/src/decorator/python.rs"),
            Some("crates/mvm-sdk/src/decorator/python.rs")
        );
        assert_eq!(
            allowlist_entry_for("crates/mvm-contract/src/ir/workload.rs"),
            Some("crates/mvm-contract/src/ir/workload.rs")
        );
        assert_eq!(
            allowlist_entry_for("crates/mvm-contract/src/ir/workload_extra.rs"),
            None
        );
    }

    /// A stale entry is a hard failure, which is what makes the list shrink.
    #[test]
    fn the_allowlist_has_no_duplicates() {
        let unique: BTreeSet<&&str> = ALLOWLIST.iter().collect();
        assert_eq!(
            unique.len(),
            ALLOWLIST.len(),
            "duplicate allowlist entries hide a stale one"
        );
    }

    /// Claude worktrees nested inside the main checkout carry independent
    /// branch states and must not be scanned as if they were part of the
    /// source tree.
    #[test]
    fn claude_worktrees_are_not_scanned() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let nested = tmp
            .path()
            .join(".claude")
            .join("worktrees")
            .join("old-branch");
        std::fs::create_dir_all(&nested).expect("create nested worktree");
        std::fs::write(
            nested.join("legacy.rs"),
            "let mode = NetworkMode::L3Vsock;\n",
        )
        .expect("write legacy source");
        std::fs::write(tmp.path().join("source.rs"), "// clean\n").expect("write source file");

        let found = walk(tmp.path()).expect("walk temp tree");
        assert!(
            found.iter().all(|p| !p.ends_with("legacy.rs")),
            "walker descended into .claude/worktrees: {found:?}"
        );
        assert!(
            found.iter().any(|p| p.ends_with("source.rs")),
            "walker skipped the real source file: {found:?}"
        );
    }
}
