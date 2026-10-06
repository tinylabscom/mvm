//! Permanent guard for the one path by which a workspace reaches the host
//! tree.
//!
//! A reviewed workspace apply writes the operator's working tree, so every
//! write has to go through the signed sequence in `mvm_client::workspace_apply`:
//! a signed snapshot of the pre-images, a durable marker, the commit, a signed
//! mutation entry, and a restore when that entry cannot be shown written. The
//! apply store in `mvm-fs` can write the host tree on its own; it is the
//! engine's job to never let it do so outside that sequence.
//!
//! Two rules hold that in place:
//!
//! 1. Production code may name `ApplyStore` only inside the store itself and
//!    the engine. A second caller — a CLI shortcut, an SDK fast path, another
//!    crate — would be a second write path, and that is how `undo` and `redo`
//!    once committed without their signed entries.
//! 2. Inside the engine, the store's host-tree `commit` is called exactly once,
//!    in `commit_audited`, after the snapshot is recorded and the marker armed.

use std::path::Path;

use anyhow::{Context, Result, bail};

use crate::fs_walk::for_each_file;
use crate::rust_source::{blank_comments_and_strings, strip_cfg_test_items};

/// Where the apply store may be named in production code.
const STORE_OWNERS: &[&str] = &[
    "crates/mvm-fs/src/workspace_apply/",
    "crates/mvm-client/src/workspace_apply/",
];
const ENGINE: &str = "crates/mvm-client/src/workspace_apply/mod.rs";
/// Every store method the engine may call. Each either writes nothing to the
/// host tree or is part of the signed sequence and its recovery. A method
/// missing here is refused until someone decides which it is — `undo_latest`
/// was once a method that committed on its own, with no signed entry.
const ENGINE_STORE_CALLS: &[&str] = &[
    "open",
    "recover_source",
    "uncertain_signed_audits",
    "pending_signed_audits",
    "rollback_unverifiable",
    "rollback_unsealed",
    "settle_uncertain_signed_audit",
    "seal_signed_audit",
    "stage",
    "stage_undo",
    "stage_redo",
    "arm_signed_audit",
    "commit",
];
const SEQUENCE_FN: &str = "fn commit_audited(";

pub fn run(workspace: &Path) -> Result<()> {
    let mut violations = Vec::new();
    for root in ["crates", "src"] {
        let dir = workspace.join(root);
        if !dir.is_dir() {
            continue;
        }
        for_each_file(&dir, Some("rs"), &mut |path, source| {
            let relative = path.strip_prefix(workspace).unwrap_or(path);
            let relative = relative.to_string_lossy().replace('\\', "/");
            violations.extend(store_reaches(&relative, source));
        })?;
    }
    if !violations.is_empty() {
        bail!(
            "check-single-workspace-write-path: the workspace apply store is named outside the \
             signed engine, which would be a second path to the host tree. Go through \
             `mvm_client::workspace_apply` instead:\n  {}",
            violations.join("\n  ")
        );
    }

    let engine = std::fs::read_to_string(workspace.join(ENGINE))
        .with_context(|| format!("read {ENGINE}"))?;
    if let Some(problem) = engine_sequence_problem(&engine) {
        bail!("check-single-workspace-write-path: {ENGINE}: {problem}");
    }

    eprintln!(
        "check-single-workspace-write-path: clean — the apply store is reached only through the \
         engine, and the engine commits the host tree from one signed sequence"
    );
    Ok(())
}

/// Production reaches of the apply store in one file, as `path:line`.
fn store_reaches(relative: &str, source: &str) -> Vec<String> {
    if STORE_OWNERS.iter().any(|owner| relative.starts_with(owner)) || is_test_file(relative) {
        return Vec::new();
    }
    let code = production(source);
    code.match_indices("ApplyStore")
        .filter(|(index, _)| is_identifier_at(&code, *index, "ApplyStore"))
        .map(|(index, _)| format!("{relative}:{}", line_of(&code, index)))
        .collect()
}

/// The engine must commit the host tree from exactly one place, the signed
/// sequence, and arm the audit marker before it does.
fn engine_sequence_problem(engine: &str) -> Option<String> {
    let code = production(engine);
    if let Some(call) = unlisted_store_call(&code) {
        return Some(format!(
            "the engine calls the store's `{call}`, which is not in the reviewed list; decide \
             whether it writes the host tree and, if it does, route it through `{SEQUENCE_FN}`"
        ));
    }
    let commits: Vec<usize> = code
        .match_indices(".commit(")
        .map(|(index, _)| index)
        .collect();
    if commits.len() != 1 {
        return Some(format!(
            "expected exactly one host-tree `.commit(` call, in `{SEQUENCE_FN}`, found {}",
            commits.len()
        ));
    }
    let Some(sequence) = code.find(SEQUENCE_FN) else {
        return Some(format!("the signed sequence `{SEQUENCE_FN}` is gone"));
    };
    let body_end = function_end(&code, sequence);
    let commit = commits[0];
    if !(sequence..body_end).contains(&commit) {
        return Some(format!(
            "the host-tree `.commit(` at line {} is outside `{SEQUENCE_FN}`",
            line_of(&code, commit)
        ));
    }
    let body = &code[sequence..body_end];
    let commit_in_body = commit - sequence;
    for (required, what) in [
        (".record_snapshot(", "record the signed snapshot"),
        (".arm_signed_audit(", "arm the durable audit marker"),
    ] {
        match body.find(required) {
            Some(at) if at < commit_in_body => {}
            _ => {
                return Some(format!(
                    "`{SEQUENCE_FN}` must {what} (`{required}`) before it commits"
                ));
            }
        }
    }
    if !body[commit_in_body..].contains("seal_apply_or_rollback(") {
        return Some(format!(
            "`{SEQUENCE_FN}` must seal the signed entry or restore the host after it commits"
        ));
    }
    None
}

/// The first `store.<method>(` / `ApplyStore::<method>(` call naming a method
/// outside [`ENGINE_STORE_CALLS`].
fn unlisted_store_call(code: &str) -> Option<String> {
    for receiver in ["store.", "ApplyStore::"] {
        for (index, _) in code.match_indices(receiver) {
            if !is_identifier_at(code, index, receiver.trim_end_matches(['.', ':'])) {
                continue;
            }
            let rest = &code[index + receiver.len()..];
            let name: String = rest
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            let called = rest[name.len()..].trim_start().starts_with('(');
            if called && !name.is_empty() && !ENGINE_STORE_CALLS.contains(&name.as_str()) {
                return Some(name);
            }
        }
    }
    None
}

fn production(source: &str) -> String {
    strip_cfg_test_items(&blank_comments_and_strings(source))
}

fn is_test_file(relative: &str) -> bool {
    relative.contains("/tests/")
        || relative.ends_with("/tests.rs")
        || relative.ends_with("_test.rs")
        || relative.ends_with("_tests.rs")
}

fn is_identifier_at(code: &str, index: usize, ident: &str) -> bool {
    let before = code[..index].chars().next_back();
    let after = code[index + ident.len()..].chars().next();
    let continues = |c: Option<char>| c.is_some_and(|c| c.is_alphanumeric() || c == '_');
    !continues(before) && !continues(after)
}

fn line_of(code: &str, index: usize) -> usize {
    code[..index].bytes().filter(|byte| *byte == b'\n').count() + 1
}

/// The byte just past the closing brace of the function starting at `start`.
fn function_end(code: &str, start: usize) -> usize {
    let Some(open) = code[start..].find('{').map(|at| start + at) else {
        return code.len();
    };
    let mut depth = 0usize;
    for (offset, byte) in code[open..].bytes().enumerate() {
        match byte {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return open + offset + 1;
                }
            }
            _ => {}
        }
    }
    code.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENGINE_OK: &str = r#"
impl WorkspaceApplier<'_> {
    fn commit_audited(&self, staged: &StagedApply) -> Result<String> {
        record_snapshot_then_commit(
            || self.audit.record_snapshot(entry),
            || {
                self.store.arm_signed_audit(staged)?;
                self.store.commit(staged, dir).map_err(Into::into)
            },
        )?;
        seal_apply_or_rollback(|| a(), || b(), |c| d(c))?;
        Ok(root)
    }
}
"#;

    #[test]
    fn the_engine_and_the_store_may_name_the_store() {
        let source = "use mvm_fs::workspace_apply::store::ApplyStore;";
        assert!(store_reaches("crates/mvm-client/src/workspace_apply/mod.rs", source).is_empty());
        assert!(store_reaches("crates/mvm-fs/src/workspace_apply/store.rs", source).is_empty());
    }

    #[test]
    fn any_other_production_reach_is_a_second_write_path() {
        let source = "fn quick() {\n    let s = ApplyStore::open(root)?;\n    s.commit(&x, d)?;\n}";
        assert_eq!(
            store_reaches("crates/mvm-cli/src/commands/vm/quick_apply.rs", source),
            ["crates/mvm-cli/src/commands/vm/quick_apply.rs:2"]
        );
        assert_eq!(
            store_reaches("crates/mvm-hostlib/src/workspace.rs", "use x::ApplyStore;").len(),
            1
        );
    }

    #[test]
    fn tests_comments_strings_and_longer_names_are_not_reaches() {
        let source = "// ApplyStore in a comment\nconst S: &str = \"ApplyStore\";\nstruct ApplyStoreRoot;\n#[cfg(test)]\nmod t { use super::ApplyStore; }\n";
        assert!(store_reaches("crates/mvm-cli/src/x.rs", source).is_empty());
        assert!(store_reaches("crates/mvm-cli/tests/apply.rs", "use ApplyStore;").is_empty());
        assert!(store_reaches("crates/mvm-cli/src/x/tests.rs", "use ApplyStore;").is_empty());
    }

    #[test]
    fn the_signed_sequence_passes() {
        assert_eq!(engine_sequence_problem(ENGINE_OK), None);
    }

    #[test]
    fn a_second_commit_in_the_engine_is_refused() {
        let engine = format!(
            "{ENGINE_OK}\nfn undo(&self) {{ self.store.commit(&s, d)?; self.audit.record(e)?; }}"
        );
        let problem = engine_sequence_problem(&engine).expect("a second commit");
        assert!(problem.contains("exactly one"), "{problem}");
    }

    #[test]
    fn a_commit_moved_out_of_the_sequence_is_refused() {
        let engine = ENGINE_OK
            .replace(
                "self.store.commit(staged, dir).map_err(Into::into)",
                "Ok(())",
            )
            .replace(
                "Ok(root)\n    }\n}",
                "Ok(root)\n    }\n    fn other(&self) { self.store.commit(s, d); }\n}",
            );
        let problem = engine_sequence_problem(&engine).expect("commit outside the sequence");
        assert!(problem.contains("outside"), "{problem}");
    }

    #[test]
    fn committing_before_the_marker_or_without_the_seal_is_refused() {
        let unarmed = ENGINE_OK.replace("self.store.arm_signed_audit(staged)?;", "");
        assert!(
            engine_sequence_problem(&unarmed)
                .expect("no marker")
                .contains("arm_signed_audit")
        );
        let unsealed = ENGINE_OK.replace("seal_apply_or_rollback(|| a(), || b(), |c| d(c))?;", "");
        assert!(
            engine_sequence_problem(&unsealed)
                .expect("no seal")
                .contains("restore")
        );
        let unsnapshotted = ENGINE_OK.replace("self.audit.record_snapshot(entry)", "Ok(())");
        assert!(
            engine_sequence_problem(&unsnapshotted)
                .expect("no snapshot")
                .contains("record_snapshot")
        );
    }

    #[test]
    fn a_store_method_that_commits_on_its_own_is_refused() {
        let engine =
            format!("{ENGINE_OK}\nfn undo(&self) {{ let r = self.store.undo_latest(dir)?; }}");
        let problem = engine_sequence_problem(&engine).expect("an unreviewed store call");
        assert!(problem.contains("`undo_latest`"), "{problem}");
        let reviewed = format!("{ENGINE_OK}\nfn undo(&self) {{ self.store.stage_undo(dir)?; }}");
        assert_eq!(engine_sequence_problem(&reviewed), None);
    }

    #[test]
    fn a_missing_sequence_is_refused() {
        let problem = engine_sequence_problem("fn x() { s.commit(a, b); }").expect("no sequence");
        assert!(problem.contains("is gone"), "{problem}");
    }
}
