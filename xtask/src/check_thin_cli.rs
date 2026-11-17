//! `xtask check-thin-cli`
//!
//! `mvmctl`'s commands are meant to be thin callers over `mvm-client`: a
//! capability lands in the library first, and the CLI, the host library the
//! SDKs load, and the MCP adapter all call it there. A command that reaches
//! past the client into `mvm_hostd`, `mvm_runtime` or `mvm_build` holds logic
//! no other surface can reach, and the SDKs lose parity without anyone
//! deciding they should.
//!
//! This gate fails when production code names one of those crates, unless the
//! file is in [`ALLOWLIST`] for that crate. `mvm_hostd` and `mvm_runtime` are
//! checked under `crates/mvm-cli/src/commands`; `mvm_build` is checked across
//! all of `crates/mvm-cli/src`, because builds are reached from `doctor`,
//! `exec`, `bootstrap` and the helper modules as well as from commands.
//! The allowlist was seeded with every file that reached a crate when the
//! crate was added to the gate: it records debt, not approval. It counts
//! files that reach, never lines of code, and sets no size ceiling. It only shrinks —
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
    Build,
}

impl Below {
    const ALL: [Below; 3] = [Below::Hostd, Below::Runtime, Below::Build];

    fn crate_name(self) -> &'static str {
        match self {
            Below::Hostd => "mvm_hostd",
            Below::Runtime => "mvm_runtime",
            Below::Build => "mvm_build",
        }
    }

    /// Whether a file (relative to `crates/mvm-cli/src`) is under this
    /// crate's gate.
    fn covers(self, rel: &str) -> bool {
        match self {
            Below::Hostd | Below::Runtime => rel.starts_with("commands/"),
            Below::Build => true,
        }
    }
}

#[cfg(test)]
const HOSTD: &[Below] = &[Below::Hostd];
#[cfg(test)]
const RUNTIME: &[Below] = &[Below::Runtime];
const BUILD: &[Below] = &[Below::Build];
#[cfg(test)]
const BOTH: &[Below] = &[Below::Hostd, Below::Runtime];

/// Files under `crates/mvm-cli/src` (paths relative to it) that still reach a
/// crate below the client, and which. Every entry is existing debt; remove it
/// when the logic moves into `mvm-client`. Entries only ever leave: a new one
/// must not be added to admit a new reach, and the `mvm_hostd` and
/// `mvm_runtime` debt is already zero.
const ALLOWLIST: &[(&str, &[Below])] = &[
    ("commands/build/build.rs", BUILD),
    ("commands/build/guest_bins.rs", BUILD),
    ("commands/build/image_set.rs", BUILD),
    ("commands/build/kernel.rs", BUILD),
    ("commands/build/persistent_builder.rs", BUILD),
    ("commands/build/runtime_overlay.rs", BUILD),
    ("commands/build/sdk_sidecar.rs", BUILD),
    ("commands/build/validate.rs", BUILD),
    ("commands/builder_shell_job.rs", BUILD),
    ("commands/deps/audit.rs", BUILD),
    ("commands/deps/capture.rs", BUILD),
    ("commands/deps/inspect.rs", BUILD),
    ("commands/deps/install.rs", BUILD),
    ("commands/deps/live_capture.rs", BUILD),
    ("commands/env/bootstrap.rs", BUILD),
    ("commands/env/builder_vm.rs", BUILD),
    ("commands/env/builder_vm/bootstrap.rs", BUILD),
    ("commands/env/builder_vm/default_microvm.rs", BUILD),
    ("commands/env/builder_vm/kernel.rs", BUILD),
    ("commands/env/builder_vm/local_pair.rs", BUILD),
    ("commands/env/builder_vm/shell_job.rs", BUILD),
    ("commands/env/builder_vm/stage0_artifact.rs", BUILD),
    ("commands/env/builder_vm/stage0_cache.rs", BUILD),
    ("commands/env/cleanup.rs", BUILD),
    ("commands/env/verify_runtime.rs", BUILD),
    ("commands/image/boot/verify.rs", BUILD),
    ("commands/image/build_layer.rs", BUILD),
    ("commands/image/dev.rs", BUILD),
    ("commands/mod.rs", BUILD),
    ("commands/pack/build.rs", BUILD),
    ("commands/shared/parse.rs", BUILD),
    ("commands/vm/checkpoint.rs", BUILD),
    ("commands/vm/checkpoint/fork_vm_full.rs", BUILD),
    ("commands/vm/exec.rs", BUILD),
    ("commands/vm/exec/composition.rs", BUILD),
    ("commands/vm/exec/image_source.rs", BUILD),
    ("commands/vm/up/kernel.rs", BUILD),
    ("exec.rs", BUILD),
    ("exec/sidecar_selection.rs", BUILD),
    ("exec/transient.rs", BUILD),
    ("host_binaries/manifest.rs", BUILD),
    ("host_binaries/mod.rs", BUILD),
    ("host_binaries/source.rs", BUILD),
    ("lib.rs", BUILD),
];

pub(crate) fn run(workspace: &Path) -> Result<()> {
    let root = workspace.join("crates/mvm-cli/src");
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
        let mut reaches = reaches_in(src);
        reaches.retain(|reach| reach.below.covers(&rel));
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

/// A file only compiled into test builds, by the naming the CLI uses for the
/// `#[cfg(test)] mod` files its parents declare.
fn is_test_path(rel: &str) -> bool {
    let name = rel.rsplit('/').next().unwrap_or(rel);
    name.ends_with("_test.rs")
        || name.ends_with("_tests.rs")
        || name == "tests.rs"
        || name.starts_with("test_")
        || rel.split('/').any(|seg| seg == "tests")
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
        assert!(is_test_path("env/builder_vm/tests.rs"));
        assert!(is_test_path("env/published_fetch_tests.rs"));
        assert!(is_test_path("test_boot_payload.rs"));
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

    /// `mvm_build` is gated across the whole CLI source; the other two only
    /// under `commands/`.
    #[test]
    fn scope_is_per_crate() {
        assert!(Below::Build.covers("doctor/nix_checks.rs"));
        assert!(Below::Build.covers("commands/vm/up.rs"));
        assert!(!Below::Hostd.covers("doctor/security.rs"));
        assert!(Below::Runtime.covers("commands/vm/up.rs"));
        assert_eq!(reaches_in("use mvm_build::x;\n")[0].below, Below::Build);
        let verdict = judge(&found(&[("doctor/a.rs", "use mvm_build::x;\n")]), &[]);
        assert_eq!(verdict.unlisted, ["doctor/a.rs:1: mvm_build"]);
        assert!(
            judge(
                &found(&[("doctor/a.rs", "use mvm_build::x;\n")]),
                &[("doctor/a.rs", BUILD)]
            )
            .is_clean()
        );
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
