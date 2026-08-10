//! `xtask check-no-gateway-names`
//!
//! Workload egress converged on vsock: a workload guest has no NIC, and bytes
//! leave only through the per-VM substitution endpoint. The userspace network
//! gateways that predate that convergence — and the third-party binaries they
//! named — are gone from the tree, and this gate keeps them gone.
//!
//! Why a gate rather than a one-off sweep: the stack was already inert for
//! months before it was deleted (`MVM_NETWORKING` was read only to log that it
//! was ignored, and the supervisor's own comment called the native-gateway
//! hook "historical"). Dead code that still compiles is dead code that grows
//! back — and while it exists it reads as a second, live egress model with its
//! own policy surface next to the real one.
//!
//! This complements `check-vsock-only-egress`, which forbids the same tokens
//! on a handful of specific runtime paths. This one covers the whole tree.

use anyhow::{Context, Result, bail};
use regex::Regex;
use std::path::{Path, PathBuf};

/// Names that must not appear anywhere outside the exemptions below.
///
/// Matched on word boundaries: `passthru` (a Nix attribute) and
/// `passthrough` both contain "passt" as a substring, and flagging those
/// would make the gate unusable.
const FORBIDDEN: &[&str] = &["passt", "gvproxy", "rvproxy"];

/// Matches that are not references to the removed subsystem.
///
/// `hetzner-rvproxy` is the filename of an SSH key for a Linux test box. The
/// box predates and outlives the gateway that shares part of its name, and the
/// key cannot be renamed from here — a doc that tells someone how to reach the
/// box has to spell the path they actually type.
const ALLOWED_IN_CONTEXT: &[&str] = &["hetzner-rvproxy"];

/// Paths the gate does not read.
///
/// The first two are the gates themselves — a lint that forbids a token has
/// to name it. The rest are dated, point-in-time records: research notes and
/// archived sprint/backlog documents describe what was true when they were
/// written, and rewriting them would falsify the record rather than clean it.
/// Live documentation is *not* exempt.
const EXEMPT: &[&str] = &[
    "xtask/src/check_no_gateway_names.rs",
    "xtask/src/check_vsock_only_egress.rs",
    "specs/notes/",
    "specs/research/",
    "specs/backlog/",
    "CHANGELOG.md",
];

/// Directories never worth walking: VCS internals and build output. The
/// generated ones matter because they are not gitignore-aware from here — a
/// locally-built docs bundle under `public/dist/` mirrors `public/src/` and
/// would fail the gate on prose that has already been corrected at the source.
const SKIP_DIRS: &[&str] = &[
    ".git",
    "target",
    "node_modules",
    ".worktrees",
    "dist",
    ".astro",
];

pub fn run(workspace: &Path) -> Result<()> {
    let pattern = format!(r"\b({})\b", FORBIDDEN.join("|"));
    let re = Regex::new(&pattern).context("compile forbidden-name regex")?;

    let mut hits: Vec<String> = Vec::new();
    let mut scanned = 0usize;
    for path in walk(workspace)? {
        let rel = path
            .strip_prefix(workspace)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        if EXEMPT.iter().any(|e| rel.starts_with(e) || rel == *e) {
            continue;
        }
        // Lockfiles carry transitive crate names we do not control.
        if rel.ends_with(".lock") {
            continue;
        }
        let Ok(body) = std::fs::read_to_string(&path) else {
            continue; // binary or unreadable — nothing to match
        };
        scanned += 1;
        for (i, line) in body.lines().enumerate() {
            for m in re.find_iter(line) {
                if is_allowed_in_context(line, m.start(), m.end()) {
                    continue;
                }
                hits.push(format!("{rel}:{}: {}", i + 1, m.as_str()));
            }
        }
    }

    if !hits.is_empty() {
        let shown: Vec<&String> = hits.iter().take(40).collect();
        bail!(
            "check-no-gateway-names: {} reference(s) to a removed network gateway:\n  {}{}\n\n\
             A workload guest has no NIC; egress leaves over vsock through the per-VM \
             substitution endpoint. If you are re-introducing a guest-NIC gateway, that is \
             an ADR-001 claim-10 change and needs the ADR updated first — not a new mention \
             of the old one.",
            hits.len(),
            shown
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join("\n  "),
            if hits.len() > shown.len() {
                format!("\n  ... and {} more", hits.len() - shown.len())
            } else {
                String::new()
            }
        );
    }

    eprintln!("check-no-gateway-names: clean ({scanned} text file(s) scanned)");
    Ok(())
}

/// Whether the match at `start..end` falls inside an allowed longer token.
///
/// Span-precise on purpose: skipping the whole line would mean one mention of
/// the test box's key path silently excused a real reference sitting beside it.
fn is_allowed_in_context(line: &str, start: usize, end: usize) -> bool {
    ALLOWED_IN_CONTEXT.iter().any(|allowed| {
        line.match_indices(allowed)
            .any(|(at, _)| at <= start && end <= at + allowed.len())
    })
}

/// Every file under `root`, skipping [`SKIP_DIRS`].
fn walk(root: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            // `file_type()` does NOT follow symlinks, and `Path::is_dir()`
            // does. That difference is the whole point: `nix build` drops a
            // `result` symlink into the repo root pointing at `/nix/store`,
            // and following it would walk the store — millions of files, and
            // matches from code that is not ours. A symlink cycle would not
            // terminate at all. Nothing in the tree is reachable only through
            // a symlink, so skipping them loses no coverage.
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if file_type.is_symlink() {
                continue;
            }
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().into_owned();
            if file_type.is_dir() {
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

    fn re() -> Regex {
        Regex::new(&format!(r"\b({})\b", FORBIDDEN.join("|"))).unwrap()
    }

    /// The whole point: the tree is clean today, and stays clean.
    #[test]
    fn the_workspace_is_free_of_gateway_names() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        run(&root).expect("no references to a removed network gateway");
    }

    /// A symlinked directory is not descended into.
    ///
    /// `nix build` drops a `result` symlink pointing at `/nix/store`; walking
    /// through it would scan the store — enormous, and full of third-party
    /// text this gate has no business judging. A symlink cycle would not
    /// terminate. `Path::is_dir()` follows symlinks and `DirEntry::file_type()`
    /// does not, which is why the walker uses the latter.
    #[test]
    fn a_symlinked_directory_is_not_followed() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = tmp.path().join("root");
        let outside = tmp.path().join("outside");
        std::fs::create_dir_all(&root).expect("root");
        std::fs::create_dir_all(&outside).expect("outside");
        std::fs::write(outside.join("leak.txt"), "gvproxy\n").expect("write");
        std::fs::write(root.join("clean.txt"), "nothing here\n").expect("write");

        #[cfg(unix)]
        std::os::unix::fs::symlink(&outside, root.join("result")).expect("symlink");
        #[cfg(not(unix))]
        return;

        let found = walk(&root).expect("walk");
        assert!(
            found.iter().all(|p| !p.ends_with("leak.txt")),
            "walker followed a symlink out of the tree: {found:?}"
        );
        // ...and the gate itself passes despite the planted name behind it.
        run(&root).expect("a symlinked tree must not fail the gate");
    }

    /// `passthru` is a Nix attribute used throughout the builder pipeline and
    /// `passthrough` appears in CLI flag tests. A substring match would flag
    /// both and force the gate to be switched off.
    #[test]
    fn substrings_of_ordinary_words_are_not_matched() {
        let re = re();
        for ok in [
            "let passthru_attr = format!(\"{}.passthru.mvm\", attr);",
            "fn run_accepts_passthrough_flags() {",
            "nix eval --json \"#.passthru.rootfs.passthru.mvm\"",
        ] {
            assert!(!re.is_match(ok), "false positive on: {ok}");
        }
    }

    /// The SSH key filename for the Linux test box is not a reference to the
    /// removed subsystem, and a doc that tells someone how to reach that box
    /// has to spell the path they actually type.
    #[test]
    fn the_test_box_ssh_key_path_is_allowed() {
        let re = re();
        let line = "ssh -i ~/.ssh/hetzner-rvproxy root@example";
        assert!(re.is_match(line), "the bare regex still matches");
        let m = re.find(line).expect("match");
        assert!(
            is_allowed_in_context(line, m.start(), m.end()),
            "but the context allowance covers it"
        );
    }

    /// The allowance is span-precise: a real reference on the same line as the
    /// box's key path is still caught.
    #[test]
    fn an_allowed_token_does_not_excuse_the_rest_of_its_line() {
        let re = re();
        let line = "ssh -i ~/.ssh/hetzner-rvproxy root@box  # then start gvproxy";
        let caught: Vec<&str> = re
            .find_iter(line)
            .filter(|m| !is_allowed_in_context(line, m.start(), m.end()))
            .map(|m| m.as_str())
            .collect();
        assert_eq!(caught, vec!["gvproxy"]);
    }

    #[test]
    fn the_forbidden_names_are_matched() {
        let re = re();
        for bad in [
            "brew install slp/krun/gvproxy",
            "  spawning passt for the guest NIC",
            "let cfg = rvproxy::config();",
            "- 'passt'",
        ] {
            assert!(re.is_match(bad), "missed: {bad}");
        }
    }

    /// A gate that forbids a token has to name it, so its own source and the
    /// sibling egress gate are exempt — but nothing else is, or the gate would
    /// quietly stop covering live documentation.
    #[test]
    fn exemptions_are_narrow() {
        assert!(EXEMPT.contains(&"xtask/src/check_no_gateway_names.rs"));
        for live in [
            "CLAUDE.md",
            "README.md",
            "specs/adrs/",
            "public/src/",
            "crates/",
            "nix/",
        ] {
            assert!(
                !EXEMPT.iter().any(|e| live.starts_with(e)),
                "{live} must not be exempt"
            );
        }
    }
}
