//! `xtask check-thin-cli`
//!
//! `mvmctl`'s commands are meant to be thin callers over `mvm-client`: a
//! capability lands in the library first, and the CLI, the host library the
//! SDKs load, and the MCP adapter all call it there. A command that reaches
//! past the client into `mvm_hostd` or `mvm_runtime` holds logic no other
//! surface can reach, and the SDKs lose parity without anyone deciding they
//! should.
//!
//! This gate fails when production code under `crates/mvm-cli/src/commands`
//! names either crate, unless the file is in [`ALLOWLIST`] for that crate.
//! The allowlist was seeded with every file that reached either crate when
//! the gate was introduced: it records debt, not approval. It only shrinks —
//! an entry whose file no longer reaches the crate it is listed for fails the
//! gate too, so the entry is removed in the change that pays the debt down
//! and cannot quietly re-admit the reach later.
//!
//! A reach is the crate's name as a token in code: a `use`, a qualified path,
//! or an alias. Comments, string literals, `#[cfg(test)]` items, files gated
//! by an inner `#![cfg(test)]`, and files under a `tests/` directory are not
//! reaches; test code may build fixtures however it needs to.
//!
//! The narrower `check-cli-runtime-surface` gate bans two specific runtime
//! reaches everywhere in `mvm-cli`, with per-file exemptions that carry their
//! own reasons; this one is the crate-level ratchet over the command tree.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::{Result, bail};

use crate::fs_walk::for_each_file;
use crate::rust_source::{blank_comments_and_strings, strip_cfg_test_items};

/// A crate below the client that a command must not reach.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Below {
    Hostd,
    Runtime,
}

impl Below {
    const ALL: [Below; 2] = [Below::Hostd, Below::Runtime];

    fn crate_name(self) -> &'static str {
        match self {
            Below::Hostd => "mvm_hostd",
            Below::Runtime => "mvm_runtime",
        }
    }
}

const HOSTD: &[Below] = &[Below::Hostd];
const RUNTIME: &[Below] = &[Below::Runtime];
const BOTH: &[Below] = &[Below::Hostd, Below::Runtime];

/// Files under `crates/mvm-cli/src/commands` that still reach a crate below
/// the client, and which. Every entry is existing debt; remove it when the
/// logic moves into `mvm-client`.
const ALLOWLIST: &[(&str, &[Below])] = &[
    // Command dispatch and top-level verbs.
    ("agent_session.rs", BOTH),
    ("bootstrap.rs", HOSTD),
    ("builder_shell_job.rs", RUNTIME),
    ("cmd_audit.rs", HOSTD),
    ("mod.rs", BOTH),
    ("pool.rs", BOTH),
    // Builds, bundles and the builder VM.
    ("build/build.rs", RUNTIME),
    ("build/image_lineage.rs", BOTH),
    ("build/persistent_builder.rs", RUNTIME),
    ("build/sandbox_record.rs", HOSTD),
    ("build/trace_secret_scan.rs", HOSTD),
    ("build/validate.rs", RUNTIME),
    ("bundle/export.rs", RUNTIME),
    ("env/bootstrap.rs", RUNTIME),
    ("env/builder_vm/default_microvm.rs", RUNTIME),
    ("env/builder_vm/kernel.rs", RUNTIME),
    ("env/builder_vm/local_pair.rs", RUNTIME),
    ("env/builder_vm/shell_job.rs", RUNTIME),
    ("env/cleanup.rs", RUNTIME),
    ("env/setup.rs", RUNTIME),
    ("env/sign.rs", RUNTIME),
    // Images and manifests.
    ("image/base_image.rs", RUNTIME),
    ("image/materialize.rs", RUNTIME),
    ("image/pull_core.rs", RUNTIME),
    ("manifest/export_oci.rs", RUNTIME),
    ("manifest/info.rs", RUNTIME),
    ("manifest/ls.rs", RUNTIME),
    ("manifest/prune.rs", RUNTIME),
    ("manifest/rm.rs", RUNTIME),
    ("manifest/verify.rs", RUNTIME),
    // Machine lifecycle.
    ("machine/checkpoint.rs", RUNTIME),
    ("machine/input_journal.rs", RUNTIME),
    ("machine/mod.rs", RUNTIME),
    ("machine/prewarm.rs", RUNTIME),
    ("machine/runtime.rs", RUNTIME),
    // Audit, cache, secrets, storage and trust operations.
    ("ops/audit.rs", BOTH),
    ("ops/audit/sessions.rs", HOSTD),
    ("ops/audit_posture.rs", HOSTD),
    ("ops/cache.rs", BOTH),
    ("ops/reconcile.rs", RUNTIME),
    ("ops/secret.rs", HOSTD),
    ("ops/transcript.rs", HOSTD),
    ("shared/resolve.rs", RUNTIME),
    ("storage/gc.rs", RUNTIME),
    ("storage/info.rs", RUNTIME),
    ("trust/instructions.rs", HOSTD),
    // Runs, checkpoints, workspaces and the audit-chain readers behind them.
    ("vm/artifact.rs", RUNTIME),
    ("vm/audit_chain.rs", HOSTD),
    ("vm/checkpoint.rs", BOTH),
    ("vm/checkpoint/fork_vm_full.rs", BOTH),
    ("vm/checkpoint/lineage.rs", BOTH),
    ("vm/checkpoint/prompt_step.rs", RUNTIME),
    ("vm/checkpoint/revert.rs", BOTH),
    ("vm/checkpoint/timeline.rs", RUNTIME),
    ("vm/checkpoint/vm_state.rs", RUNTIME),
    ("vm/console.rs", RUNTIME),
    ("vm/exec.rs", BOTH),
    ("vm/host_signer.rs", HOSTD),
    ("vm/invoke.rs", BOTH),
    ("vm/outputs.rs", HOSTD),
    ("vm/phase_timing.rs", RUNTIME),
    ("vm/plan_persist.rs", HOSTD),
    ("vm/prompt_replay.rs", RUNTIME),
    ("vm/run_plan.rs", HOSTD),
    ("vm/session.rs", RUNTIME),
    ("vm/volume.rs", RUNTIME),
    ("vm/workspace.rs", RUNTIME),
    ("vm/workspace_apply.rs", RUNTIME),
];

pub fn run(workspace: &Path) -> Result<()> {
    let root = workspace.join("crates/mvm-cli/src/commands");
    let mut found: BTreeMap<String, Vec<Reach>> = BTreeMap::new();
    for_each_file(&root, Some("rs"), &mut |path, src| {
        let rel = path
            .strip_prefix(&root)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/");
        if is_test_path(&rel) {
            return;
        }
        let reaches = reaches_in(src);
        if !reaches.is_empty() {
            found.insert(rel, reaches);
        }
    })?;

    let verdict = judge(&found, ALLOWLIST);
    if verdict.is_clean() {
        eprintln!(
            "check-thin-cli: clean ({} allowlisted file(s) still reach below mvm-client; \
             no new reach)",
            ALLOWLIST.len()
        );
        return Ok(());
    }
    bail!("check-thin-cli:\n{}", verdict.report());
}

/// One reach: the crate and the 1-based line it is named on.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Reach {
    below: Below,
    line: usize,
}

/// Every reach in one file's production code.
fn reaches_in(src: &str) -> Vec<Reach> {
    if file_is_all_test(src) {
        return Vec::new();
    }
    let code = strip_cfg_test_items(&blank_comments_and_strings(src));
    let mut reaches = Vec::new();
    for (idx, line) in code.lines().enumerate() {
        for below in Below::ALL {
            if names_token(line, below.crate_name()) {
                reaches.push(Reach {
                    below,
                    line: idx + 1,
                });
            }
        }
    }
    reaches
}

/// Whether `token` appears in `line` as a whole identifier.
fn names_token(line: &str, token: &str) -> bool {
    let is_ident = |c: char| c.is_ascii_alphanumeric() || c == '_';
    line.match_indices(token).any(|(at, _)| {
        let before = line[..at].chars().next_back();
        let after = line[at + token.len()..].chars().next();
        !before.is_some_and(is_ident) && !after.is_some_and(is_ident)
    })
}

/// What the scan found, against what the allowlist admits.
#[derive(Debug, Default)]
struct Verdict {
    /// `file:line: crate` for each reach no entry admits.
    unlisted: Vec<String>,
    /// `file: crate` for each entry whose file no longer reaches that crate.
    stale: Vec<String>,
}

impl Verdict {
    fn is_clean(&self) -> bool {
        self.unlisted.is_empty() && self.stale.is_empty()
    }

    fn report(&self) -> String {
        let mut out = String::new();
        if !self.unlisted.is_empty() {
            out.push_str(&format!(
                "{} reach(es) below mvm-client in a command. Put the logic in mvm-client and \
                 call it from the command, so the host library and the SDKs reach it too:\n",
                self.unlisted.len()
            ));
            for line in &self.unlisted {
                out.push_str(&format!("  {line}\n"));
            }
        }
        if !self.stale.is_empty() {
            out.push_str(&format!(
                "{} allowlist entr(ies) no longer needed. Remove them from ALLOWLIST in \
                 xtask/src/check_thin_cli.rs so the reach cannot come back unnoticed:\n",
                self.stale.len()
            ));
            for line in &self.stale {
                out.push_str(&format!("  {line}\n"));
            }
        }
        out
    }
}

fn judge(found: &BTreeMap<String, Vec<Reach>>, allowlist: &[(&str, &[Below])]) -> Verdict {
    let admitted = |file: &str, below: Below| {
        allowlist
            .iter()
            .any(|(path, crates)| *path == file && crates.contains(&below))
    };
    let mut verdict = Verdict::default();
    for (file, reaches) in found {
        for reach in reaches {
            if !admitted(file, reach.below) {
                verdict.unlisted.push(format!(
                    "{file}:{}: {}",
                    reach.line,
                    reach.below.crate_name()
                ));
            }
        }
    }
    for (file, crates) in allowlist {
        let present: BTreeSet<Below> = found
            .get(*file)
            .map(|reaches| reaches.iter().map(|r| r.below).collect())
            .unwrap_or_default();
        for below in *crates {
            if !present.contains(below) {
                verdict
                    .stale
                    .push(format!("{file}: {}", below.crate_name()));
            }
        }
    }
    verdict
}

fn is_test_path(rel: &str) -> bool {
    rel.ends_with("_test.rs") || rel.split('/').any(|seg| seg == "tests")
}

/// A file gated entirely to test builds by an inner `#![cfg(test)]`.
fn file_is_all_test(src: &str) -> bool {
    src.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with("//"))
        .take_while(|line| line.starts_with("#!["))
        .any(|line| line.starts_with("#![cfg(test)]"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn found(entries: &[(&str, &str)]) -> BTreeMap<String, Vec<Reach>> {
        entries
            .iter()
            .map(|(file, src)| (file.to_string(), reaches_in(src)))
            .filter(|(_, reaches)| !reaches.is_empty())
            .collect()
    }

    #[test]
    fn a_use_and_a_qualified_path_are_reaches() {
        let reaches = reaches_in(
            "use mvm_hostd::supervisor::PlanAuditEntry;\n\
             fn f() { mvm_runtime::vm::name_registry::registry_path(); }\n",
        );
        assert_eq!(
            reaches,
            [
                Reach {
                    below: Below::Hostd,
                    line: 1
                },
                Reach {
                    below: Below::Runtime,
                    line: 2
                },
            ]
        );
    }

    #[test]
    fn an_alias_is_a_reach() {
        assert_eq!(reaches_in("use mvm_runtime as rt;\n").len(), 1);
    }

    #[test]
    fn comments_strings_and_longer_identifiers_are_not_reaches() {
        let src = "// mvm_hostd::supervisor is where this used to live\n\
                   /* mvm_runtime::vm */\n\
                   const S: &str = \"mvm_runtime::vm\";\n\
                   use not_mvm_hostd_shim::x;\n\
                   use mvm_runtime_extra::y;\n";
        assert!(reaches_in(src).is_empty(), "{:?}", reaches_in(src));
    }

    #[test]
    fn test_code_is_not_a_reach() {
        let src = "fn prod() {}\n\
                   #[cfg(test)]\n\
                   mod tests {\n\
                   use mvm_hostd::audit::emitter::AuditEmitter;\n\
                   }\n\
                   fn later() { mvm_runtime::x(); }\n";
        let reaches = reaches_in(src);
        assert_eq!(reaches.len(), 1, "{reaches:?}");
        assert_eq!(reaches[0].line, 6);
        assert!(reaches_in("#![cfg(test)]\nuse mvm_hostd::x;\n").is_empty());
        assert!(is_test_path("vm/tests/fixture.rs"));
        assert!(is_test_path("vm/explain_test.rs"));
        assert!(!is_test_path("vm/explain.rs"));
    }

    #[test]
    fn a_new_reach_fails_and_names_its_line() {
        let verdict = judge(&found(&[("vm/new.rs", "\nuse mvm_hostd::x;\n")]), &[]);
        assert_eq!(verdict.unlisted, ["vm/new.rs:2: mvm_hostd"]);
        assert!(verdict.stale.is_empty());
        assert!(!verdict.is_clean());
    }

    #[test]
    fn an_allowlisted_reach_passes() {
        let verdict = judge(
            &found(&[("vm/old.rs", "use mvm_hostd::x;\n")]),
            &[("vm/old.rs", HOSTD)],
        );
        assert!(verdict.is_clean(), "{verdict:?}");
    }

    /// An entry admits only the crate it names: a file listed for hostd that
    /// starts reaching the runtime is a new reach.
    #[test]
    fn an_entry_is_scoped_to_its_crates() {
        let src = "use mvm_hostd::x;\nuse mvm_runtime::y;\n";
        let verdict = judge(&found(&[("vm/old.rs", src)]), &[("vm/old.rs", HOSTD)]);
        assert_eq!(verdict.unlisted, ["vm/old.rs:2: mvm_runtime"]);
        assert!(judge(&found(&[("vm/old.rs", src)]), &[("vm/old.rs", BOTH)]).is_clean());
    }

    /// Paying the debt down without removing the entry fails, so the list
    /// only shrinks.
    #[test]
    fn a_stale_entry_fails() {
        let verdict = judge(
            &found(&[("vm/old.rs", "use mvm_hostd::x;\n")]),
            &[("vm/old.rs", BOTH), ("vm/gone.rs", RUNTIME)],
        );
        assert_eq!(
            verdict.stale,
            ["vm/old.rs: mvm_runtime", "vm/gone.rs: mvm_runtime"]
        );
        assert!(verdict.unlisted.is_empty());
    }

    #[test]
    fn the_allowlist_has_no_duplicate_files() {
        let mut files: Vec<&str> = ALLOWLIST.iter().map(|(file, _)| *file).collect();
        files.sort_unstable();
        let total = files.len();
        files.dedup();
        assert_eq!(files.len(), total, "a file is listed twice");
        assert!(ALLOWLIST.iter().all(|(_, crates)| !crates.is_empty()));
    }
}
