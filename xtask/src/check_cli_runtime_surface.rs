//! `xtask check-cli-runtime-surface`
//!
//! `mvm-cli` drives sandboxes through the `mvm-client` facade, not by reaching
//! into `mvm-runtime` internals. Two reaches are banned in mvm-cli's
//! drive-a-machine code, each with its own allowlist of legitimately-direct
//! files:
//!
//! 1. `name-registry` — `mvm_runtime::vm::name_registry` (registration, TTL,
//!    readiness, gc). Route through mvm-client: `record_readiness` /
//!    `readiness_of` / `register_machine` / `touch_activity` / `set_ttl` /
//!    `gc_stale_registrations`.
//! 2. `any-backend` — `AnyBackend` VMM dispatch. Route through mvm-client:
//!    `start_prepared` / `backend_is_running` / `backend_stop_by_name` /
//!    `list_machines` / `stop_machine` / ….
//!
//! Legitimately-direct callers — the store surfaces (checkpoint/snapshot), the
//! streaming/interactive verbs (exec/invoke/session), and the build /
//! diagnostics substrate that only *selects* a backend — earn a rule-scoped
//! `EXEMPTIONS` entry with a reason. Test code (`#[cfg(test)]` ranges, `tests/`
//! files, `*_test.rs`) and comments are never flagged.

use anyhow::{Result, bail};
use std::path::Path;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Rule {
    NameRegistry,
    AnyBackend,
}

impl Rule {
    fn label(self) -> &'static str {
        match self {
            Rule::NameRegistry => "name-registry",
            Rule::AnyBackend => "any-backend",
        }
    }

    /// The code substring that marks the reach.
    fn needle(self) -> &'static str {
        match self {
            Rule::NameRegistry => "mvm_runtime::vm::name_registry",
            Rule::AnyBackend => "AnyBackend",
        }
    }
}

const ALL_RULES: &[Rule] = &[Rule::NameRegistry, Rule::AnyBackend];

/// (path relative to `crates/mvm-cli/src`, exempted rule classes, reason).
/// Scoped to the narrowest rule the file legitimately needs.
const EXEMPTIONS: &[(&str, &[Rule], &str)] = &[
    (
        "commands/vm/snapshot.rs",
        &[Rule::NameRegistry],
        "store surface: manages ~/.mvm snapshot bookkeeping directly, not a drive-a-machine op",
    ),
    (
        "commands/vm/checkpoint.rs",
        &[Rule::AnyBackend],
        "store surface: checkpoint / fork / restore over the CoW rootfs",
    ),
    (
        "commands/vm/checkpoint/vm_state.rs",
        &[Rule::AnyBackend],
        "same store surface as commands/vm/checkpoint.rs — the VM-state and \
         backend-capability probes moved here when the parent crossed the \
         production file-size cap. Listed per file for the reason the entry below \
         gives: a directory prefix would exempt whatever lands beside it next",
    ),
    (
        "commands/vm/checkpoint/fork_vm_full.rs",
        &[Rule::AnyBackend],
        "same store surface as commands/vm/checkpoint.rs — the vm_full fork arms live in \
         their own file only because the parent crossed the production file-size cap. \
         Listed per file rather than by directory prefix deliberately: a prefix would \
         silently exempt whatever lands beside it next",
    ),
    (
        "commands/vm/exec.rs",
        &[Rule::AnyBackend],
        "streaming exec-over-vsock: selects the backend for the transient exec VM",
    ),
    (
        "commands/vm/invoke.rs",
        &[Rule::AnyBackend],
        "streaming invoke: backend selection for the entrypoint boot",
    ),
    (
        "commands/vm/session.rs",
        &[Rule::AnyBackend],
        "streaming session: backend selection for resume",
    ),
    (
        "commands/pool.rs",
        &[Rule::AnyBackend],
        "pool build substrate: backend selection",
    ),
    (
        "commands/machine/lifecycle.rs",
        &[Rule::AnyBackend],
        "backend selection: validates the requested hypervisor name is available before          handing the machine off to the runtime",
    ),
    (
        "commands/pool.rs",
        &[Rule::NameRegistry],
        "registry-lock handoff: hands the runtime the registry's location so \
         acquire_registry_lock can serialize the standby-parent reserve against the \
         child-name mint via ClaimContext; performs no registration op itself",
    ),
    (
        "commands/build/build.rs",
        &[Rule::AnyBackend],
        "build substrate: backend selection",
    ),
    (
        "doctor/security.rs",
        &[Rule::AnyBackend],
        "diagnostics: probes the auto-selected backend",
    ),
    (
        "exec.rs",
        &[Rule::AnyBackend],
        "shared backend-selection helpers (from_hypervisor / auto_select) the CLI dispatches through",
    ),
    (
        "exec/session.rs",
        &[Rule::AnyBackend],
        "same helpers as exec.rs: the warm-session lifecycle split out of it, not a new reach",
    ),
    (
        "exec/transient.rs",
        &[Rule::AnyBackend],
        "same helpers as exec.rs: the transient boot/teardown lifecycle split out of it",
    ),
    (
        "exec/guest_run.rs",
        &[Rule::AnyBackend],
        "same helpers as exec.rs: the in-guest dispatch leg split out of it",
    ),
    (
        "bench/probe.rs",
        &[Rule::AnyBackend],
        "live benchmark probe: directly boots and stops a libkrun probe VM to sample boot marks and process footprint",
    ),
];

pub fn run(workspace: &Path) -> Result<()> {
    let root = workspace.join("crates/mvm-cli/src");
    let mut hits: Vec<String> = Vec::new();
    walk(&root, &mut |path| scan_file(&root, path, &mut hits))?;

    if !hits.is_empty() {
        bail!(
            "check-cli-runtime-surface: {} mvm-runtime reach(es) in mvm-cli drive-a-machine code.\n\
             Route them through the mvm-client facade (record_readiness / register_machine /\n\
             set_ttl / gc_stale_registrations / start_prepared / backend_stop_by_name / …). A\n\
             legitimately-direct caller (a store surface, a streaming verb, or build/diagnostics\n\
             backend selection) earns a rule-scoped EXEMPTIONS entry in\n\
             xtask/src/check_cli_runtime_surface.rs, with a reason.\n{}",
            hits.len(),
            hits.join("\n")
        );
    }
    eprintln!(
        "check-cli-runtime-surface: clean (mvm-cli drives machines through the mvm-client facade)"
    );
    Ok(())
}

fn scan_file(root: &Path, path: &Path, hits: &mut Vec<String>) {
    if path.extension().and_then(|e| e.to_str()) != Some("rs") {
        return;
    }
    let rel = path
        .strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/");
    if is_test_path(&rel) {
        return;
    }
    let Ok(src) = std::fs::read_to_string(path) else {
        return;
    };
    for hit in scan_source(&rel, &src) {
        hits.push(hit);
    }
}

/// Scan one file's source; returns formatted hit lines. Pure so unit tests can
/// drive it with fixture text. A reach is flagged when its needle appears in the
/// code (not a comment), outside any `#[cfg(test)]` range, and the file is not
/// exempt for that rule.
fn scan_source(rel: &str, src: &str) -> Vec<String> {
    if file_is_all_test(src) {
        return Vec::new();
    }
    let mut hits = Vec::new();
    let test_ranges = test_line_ranges(src);

    for (idx, raw) in src.lines().enumerate() {
        let line = idx + 1;
        if in_ranges(line, &test_ranges) {
            continue;
        }
        let code = strip_line_comment(raw);
        for &rule in ALL_RULES {
            if code.contains(rule.needle()) && !exempt(rel, rule) {
                hits.push(format!("  {rel}:{line}: [{}] {}", rule.label(), raw.trim()));
            }
        }
    }
    hits
}

/// Drop a `//` line comment so a reach named only in prose is not flagged. Best
/// effort: the first `//` wins (a `//` inside a string literal is vanishingly
/// unlikely on a line that also names these runtime paths).
fn strip_line_comment(line: &str) -> &str {
    match line.find("//") {
        Some(pos) => &line[..pos],
        None => line,
    }
}

fn exempt(rel: &str, rule: Rule) -> bool {
    EXEMPTIONS
        .iter()
        .any(|(path, rules, _reason)| *path == rel && rules.contains(&rule))
}

fn is_test_path(rel: &str) -> bool {
    rel.ends_with("_test.rs") || rel.split('/').any(|seg| seg == "tests")
}

/// A file gated entirely to test builds via an inner `#![cfg(test)]` attribute.
fn file_is_all_test(src: &str) -> bool {
    for line in src.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with("//") {
            continue;
        }
        if t.starts_with("#![") {
            if t.starts_with("#![cfg(test)]") {
                return true;
            }
            continue;
        }
        break;
    }
    false
}

/// Line ranges (1-based, inclusive) covered by a `#[cfg(test)]` item: from the
/// attribute to the first later lone `}` at indentation ≤ the attribute's. A
/// textual tripwire, not a parser — same heuristic as the sibling literal lint.
fn test_line_ranges(src: &str) -> Vec<(usize, usize)> {
    let lines: Vec<&str> = src.lines().collect();
    let mut ranges = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let trimmed = lines[i].trim_start();
        if is_test_cfg_opener(trimmed) {
            let indent = lines[i].len() - trimmed.len();
            let start = i + 1;
            let mut end = lines.len();
            let mut j = i + 1;
            while j < lines.len() {
                let l = lines[j];
                let li = l.len() - l.trim_start().len();
                if l.trim() == "}" && li <= indent {
                    end = j + 1;
                    break;
                }
                j += 1;
            }
            ranges.push((start, end));
            i = end;
        } else {
            i += 1;
        }
    }
    ranges
}

fn is_test_cfg_opener(trimmed: &str) -> bool {
    trimmed.starts_with("#[cfg(test)]")
        || trimmed.starts_with("#[cfg(all(test")
        || trimmed.starts_with("#[cfg(any(test")
}

fn in_ranges(line: usize, ranges: &[(usize, usize)]) -> bool {
    ranges.iter().any(|(a, b)| line >= *a && line <= *b)
}

fn walk(dir: &Path, f: &mut dyn FnMut(&Path)) -> Result<()> {
    if !dir.is_dir() {
        return Ok(());
    }
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if path.is_dir() {
            if matches!(name, "target" | ".git" | "node_modules") {
                continue;
            }
            walk(&path, f)?;
        } else {
            f(&path);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const PLAIN: &str = "commands/vm/up.rs";

    #[test]
    fn flags_name_registry_reach() {
        let out = scan_source(
            PLAIN,
            "let p = mvm_runtime::vm::name_registry::registry_path();\n",
        );
        assert_eq!(out.len(), 1, "{out:?}");
        assert!(out[0].contains("[name-registry]"), "{out:?}");
    }

    #[test]
    fn flags_any_backend_reach() {
        let out = scan_source(PLAIN, "let b = AnyBackend::from_hypervisor(name);\n");
        assert_eq!(out.len(), 1, "{out:?}");
        assert!(out[0].contains("[any-backend]"), "{out:?}");
    }

    #[test]
    fn ignores_reach_in_a_line_comment() {
        assert!(
            scan_source(
                PLAIN,
                "// the old AnyBackend::list_all() scan\nlet x = 1;\n"
            )
            .is_empty()
        );
        assert!(
            scan_source(PLAIN, "let x = 1; // mvm_runtime::vm::name_registry note\n").is_empty()
        );
    }

    #[test]
    fn skips_cfg_test_block() {
        let src = "fn prod() {}\n\
                   #[cfg(test)]\n\
                   mod tests {\n\
                   fn t() { let p = mvm_runtime::vm::name_registry::registry_path(); }\n\
                   }\n";
        assert!(
            scan_source(PLAIN, src).is_empty(),
            "{:?}",
            scan_source(PLAIN, src)
        );
    }

    #[test]
    fn cfg_test_block_does_not_bleed_into_following_production() {
        let src = "#[cfg(test)]\n\
                   mod tests {\n\
                   fn t() { let b = AnyBackend::from_hypervisor(n); }\n\
                   }\n\
                   fn prod() { let b = AnyBackend::from_hypervisor(n); }\n";
        let out = scan_source(PLAIN, src);
        assert_eq!(out.len(), 1, "{out:?}");
        assert!(
            out[0].contains(":5:"),
            "should flag the production line, {out:?}"
        );
    }

    #[test]
    fn exemption_is_rule_scoped() {
        let snap = "commands/vm/snapshot.rs";
        // snapshot is exempt for name-registry…
        assert!(
            scan_source(
                snap,
                "let p = mvm_runtime::vm::name_registry::registry_path();\n"
            )
            .is_empty()
        );
        // …but a stray AnyBackend dispatch there still trips.
        let out = scan_source(snap, "let b = AnyBackend::from_hypervisor(n);\n");
        assert_eq!(out.len(), 1, "{out:?}");
        assert!(out[0].contains("[any-backend]"), "{out:?}");
    }

    #[test]
    fn any_backend_exempt_file_allows_selection() {
        assert!(scan_source("exec.rs", "let b = AnyBackend::auto_select();\n").is_empty());
        assert!(
            scan_source(
                "commands/pool.rs",
                "let b = AnyBackend::from_hypervisor(hv);\n"
            )
            .is_empty()
        );
    }
}
