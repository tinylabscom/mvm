//! `xtask check-private-mvm-dirs`
//!
//! Every directory that holds secret-shaped state under the mvm home must be
//! made with [`mvm_core::config::create_private_dir`], never with a bare
//! `std::fs::create_dir_all`.
//!
//! The distinction is not decoration. `create_dir_all` creates each *missing
//! ancestor* at the process umask — typically 0755 — so asking for
//! `~/.mvm/audit/<tenant>` when `~/.mvm` does not exist yet produces a
//! world-traversable home no matter how tightly the leaf is then chmodded. The
//! sites this gate covers each hand-rolled exactly that: `create_dir_all`
//! followed by a `set_permissions(0o700)` on the leaf alone, which reads at a
//! glance as though the mode had been handled.
//!
//! The claimed posture is "`~/.mvm` and every child is 0700", enforced by nothing
//! at all: `ensure_home_dir` and `ensure_cache_dir` were `pub` and correct and
//! had zero callers, while a comment in the cleanup planner described the
//! repair as something the next command performed. It did not.
//!
//! **Deliberately scoped, not workspace-wide.** There are roughly a thousand
//! `create_dir_all` calls in this tree and the overwhelming majority are
//! honest — temp dirs, unpacked guest rootfs trees, caller-named `--out`
//! directories, build scratch. A rule that flagged those would be turned off
//! within a week, which is the failure mode `check-vcpu-ceilings` documents at
//! length. So this gate watches the modules that own the *secret-bearing
//! roots* — the audit chain, the host signing key, per-VM state, volumes —
//! where the path is always under the mvm home and the mode always matters.
//!
//! What it therefore does **not** reach: a deep path created somewhere else
//! under an already-0700 root. That is cosmetic rather than a leak, because
//! traversal requires execute permission on every ancestor and the root denies
//! it — but it is a real gap in the letter of that claim, and is not covered here.
//!
//! Comments and string literals are blanked first via [`crate::rust_source`],
//! then test-only items are removed. Fixture directory creation is not a
//! production ownership decision; production after a test module is still scanned.

use anyhow::{Result, bail};
use std::path::Path;

/// Modules owning a secret-bearing root under the mvm home.
const WATCHED: &[&str] = &["crates/mvm-hostd/src/audit", "crates/mvm-client/src/volume"];

/// The call this gate refuses in those modules.
const BANNED: &str = "create_dir_all";

/// The owned-state helper; caller-selected parents use `create_output_parent`.
const REQUIRED: &str = "create_private_dir";

/// Sites that must keep using the raw call, with the reason.
///
/// `atomic_write` creates the parent of a file it is about to rename into
/// place, and is called with paths both inside and outside the mvm home (an
/// operator's `--out` export target among them). Tightening a directory the
/// user named is not ours to do, and the audit roots it *does* touch are
/// already created privately by the emitter before any write reaches it.
const ALLOWED: &[&str] = &["crates/mvm-hostd/src/audit/emitter/atomic_write.rs"];

pub(crate) fn run(workspace: &Path) -> Result<()> {
    let mut findings: Vec<String> = Vec::new();
    let mut converted = 0usize;

    for dir in WATCHED {
        let root = workspace.join(dir);
        if !root.is_dir() {
            bail!("{dir} is not a directory; check-private-mvm-dirs is scanning a stale path");
        }
        for file in rust_files(&root)? {
            let relative = file
                .strip_prefix(workspace)
                .unwrap_or(&file)
                .display()
                .to_string();
            if ALLOWED.contains(&relative.as_str()) {
                continue;
            }
            let raw = std::fs::read_to_string(&file)
                .map_err(|e| anyhow::anyhow!("reading {}: {e}", file.display()))?;
            let body = crate::rust_source::strip_cfg_test_items(
                &crate::rust_source::blank_comments_and_strings(&raw),
            );

            for (line_no, line) in body.lines().enumerate() {
                if line.contains(REQUIRED) || line.contains("create_output_parent") {
                    converted += 1;
                }
                if line.contains(BANNED) {
                    findings.push(format!(
                        "{relative}:{}: `{BANNED}` under a secret-bearing mvm root. It creates \
                         every missing ancestor at the process umask, so chmodding the leaf \
                         afterwards still leaves a world-traversable directory above it. Use \
                         `mvm_core::config::{REQUIRED}`, which locks the whole chain from the \
                         mvm home down and repairs components that already exist.",
                        line_no + 1
                    ));
                }
            }
        }
    }

    if !findings.is_empty() {
        bail!(
            "bare directory creation under a secret-bearing mvm root:\n\n{}\n",
            findings.join("\n\n")
        );
    }

    // A gate that passes because every call has been deleted has stopped
    // watching anything. The same floor `check-vcpu-ceilings` keeps.
    if converted == 0 {
        bail!(
            "expected at least one `{REQUIRED}` call across {WATCHED:?}; found none. Private \
             directory creation having vanished entirely is a question, not a pass."
        );
    }

    println!(
        "check-private-mvm-dirs: {converted} private-dir call(s), no bare creation under a \
         secret-bearing root"
    );
    Ok(())
}

pub(crate) fn rust_files(root: &Path) -> Result<Vec<std::path::PathBuf>> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)
            .map_err(|e| anyhow::anyhow!("reading {}: {e}", dir.display()))?
        {
            let path = entry
                .map_err(|e| anyhow::anyhow!("reading an entry of {}: {e}", dir.display()))?
                .path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
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

    fn workspace_with(source: &str, file: &str) -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        for dir in WATCHED {
            std::fs::create_dir_all(root.path().join(dir)).unwrap();
        }
        let path = root.path().join(file);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, source).unwrap();
        root
    }

    #[test]
    fn nested_test_bodies_are_excluded_but_later_production_is_checked() {
        let source = r#"
            fn private() { mvm_core::config::create_private_dir(path); }
            #[cfg(test)]
            mod tests {
                mod nested {
                    fn fixture() { std::fs::create_dir_all(path); }
                }
            }
            fn output() { mvm_core::config::create_output_parent(path); }
        "#;
        let root = workspace_with(source, "crates/mvm-hostd/src/audit/sample.rs");
        run(root.path()).unwrap();
        std::fs::write(
            root.path().join("crates/mvm-hostd/src/audit/sample.rs"),
            format!("{source}\nfn production() {{ std::fs::create_dir_all(path); }}"),
        )
        .unwrap();
        assert!(
            run(root.path())
                .unwrap_err()
                .to_string()
                .contains("sample.rs")
        );
    }

    #[test]
    fn a_policy_helper_on_the_same_line_cannot_hide_raw_production_creation() {
        let root = workspace_with(
            "fn f() { create_output_parent(a); std::fs::create_dir_all(b); }",
            "crates/mvm-hostd/src/audit/sample.rs",
        );
        assert!(run(root.path()).is_err());
    }

    #[test]
    fn only_the_exact_existing_atomic_writer_path_is_exempt() {
        let root = workspace_with(
            "fn f() { std::fs::create_dir_all(path); }",
            "crates/mvm-hostd/src/audit/unrelated/emitter/atomic_write.rs",
        );
        assert!(
            run(root.path())
                .unwrap_err()
                .to_string()
                .contains("unrelated")
        );
    }

    #[test]
    fn passes_on_this_workspace() {
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("workspace root")
            .to_path_buf();
        run(&workspace).expect("the tree must satisfy its own private-dir rule");
    }

    #[test]
    fn a_comment_naming_the_banned_call_does_not_trip_the_gate() {
        let blanked = crate::rust_source::blank_comments_and_strings(
            "// create_dir_all is what this replaces\nlet x = create_private_dir(p);\n",
        );
        assert!(
            !blanked.lines().next().expect("first line").contains(BANNED),
            "the comment scanner must blank a mention in prose, or this gate fails on its own docs"
        );
    }
}
