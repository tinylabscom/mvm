//! `xtask check-audit-positional`
//!
//! Flags any direct call to the positional `mvm_core::audit::emit(…)`
//! / `emit_to(…)` helpers or the chained `audit::event(…).…emit()`
//! builder. New code should use the `audit_emit!` macro
//! (`crates/mvm-core/src/policy/audit.rs`), which collapses every
//! common shape to a single line and makes adding a future optional
//! field a one-method change in the builder.
//!
//! Companion to `scripts/migrate-audit-emit.sh`. Together they cover
//! the workflow:
//!
//!   * Sweep: `./scripts/migrate-audit-emit.sh` rewrites the four
//!     common shapes via perl regex.
//!   * Audit: `cargo xtask check-audit-positional` reports anything
//!     the sweep skipped, line by line, so a human can finish the
//!     migration.
//!
//! Opt-out: add `// allow(audit-positional): <reason>` on the line
//! above the offending call (one line per call). Reasons land in the
//! lint output so audit bypasses stay visible. Use this only when
//! the macro genuinely cannot express the call (e.g. an integration
//! test that pins legacy positional `emit(…)` against a future
//! refactor).
//!
//! Scope: scans `crates/*/src/**/*.rs`. The audit module itself
//! (`crates/mvm-core/src/policy/audit.rs`) is exempt because the
//! shim functions and the builder API live there.

use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};

const AUDIT_MODULE_PATH: &str = "mvm-core/src/policy/audit.rs";

/// Run the lint over `crates/*/src/**/*.rs` rooted at `workspace`.
pub(crate) fn run(workspace: &Path) -> Result<()> {
    let crates_dir = workspace.join("crates");
    if !crates_dir.is_dir() {
        bail!(
            "expected workspace crates dir at {}; got nothing",
            crates_dir.display()
        );
    }

    let mut findings: Vec<Finding> = Vec::new();
    visit_rust_files(&crates_dir, &mut |path| -> Result<()> {
        if path
            .to_str()
            .is_some_and(|p| p.ends_with(AUDIT_MODULE_PATH))
        {
            // The audit module defines the shims themselves.
            return Ok(());
        }
        let source =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        findings.extend(lint_source(path, &source));
        Ok(())
    })?;

    if findings.is_empty() {
        eprintln!("check-audit-positional: clean (scanned crates/*/src/**/*.rs)");
        return Ok(());
    }

    eprintln!(
        "check-audit-positional: {} positional audit-emit call site(s) — \
         migrate to the `audit_emit!` macro or annotate with \
         `// allow(audit-positional): <reason>`",
        findings.len()
    );
    for f in &findings {
        eprintln!("  {}:{} — {}", f.path.display(), f.line, f.snippet);
    }
    std::process::exit(1);
}

#[derive(Debug, Clone)]
struct Finding {
    path: PathBuf,
    line: usize,
    snippet: String,
}

fn visit_rust_files(dir: &Path, cb: &mut dyn FnMut(&Path) -> Result<()>) -> Result<()> {
    for entry in std::fs::read_dir(dir).with_context(|| format!("reading dir {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default();
            if matches!(name, "target" | "node_modules" | ".git" | ".cargo") {
                continue;
            }
            visit_rust_files(&path, cb)?;
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            cb(&path)?;
        }
    }
    Ok(())
}

/// One pattern set per legacy entry point. Substrings are enough —
/// false positives on strings inside comments / string literals are
/// rare in practice and the opt-out is cheap; the lint runs once per
/// CI build, so a few extra characters per match are negligible.
const POSITIONAL_NEEDLES: &[&str] = &[
    "mvm_core::audit::emit(",
    "mvm_core::audit::emit_to(",
    "mvm_core::audit::event(",
];

fn lint_source(path: &Path, source: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let lines: Vec<&str> = source.lines().collect();

    for (i, raw) in lines.iter().enumerate() {
        let line = *raw;
        let needle = match POSITIONAL_NEEDLES.iter().find(|n| line.contains(**n)) {
            Some(n) => *n,
            None => continue,
        };

        // Walk back up to 2 lines for an `allow(audit-positional)`
        // opt-out. Matches the shape used by the secret-types lint
        // so contributors learn one convention.
        if has_allow_in_window(&lines, i.saturating_sub(2), i + 1) {
            continue;
        }

        // `audit::event(…)` chains are only a violation if they
        // terminate in `.emit()`. The chained builder is the new
        // public surface; the bare `event(K)` call returns a
        // `LocalAuditBuilder` that the `audit_emit!` macro consumes
        // — flagging `event(…)` indiscriminately would catch the
        // macro's expansion site itself (post-cpp, in a real build
        // we never see the expansion, but the lint reads source so
        // it would). Practical disambiguation: only flag chains
        // that look terminal — anything within ~10 lines reaching
        // `.emit()` qualifies. The lint never sees expanded macro
        // calls, so this is safe.
        if needle == "mvm_core::audit::event(" {
            let look_ahead = lines.len().min(i + 10);
            let chain_text: String = lines[i..look_ahead].join(" ");
            if !chain_text.contains(".emit()") {
                continue;
            }
        }

        findings.push(Finding {
            path: path.to_path_buf(),
            line: i + 1,
            snippet: line.trim().to_string(),
        });
    }

    findings
}

fn has_allow_in_window(lines: &[&str], start: usize, end: usize) -> bool {
    lines[start..end]
        .iter()
        .any(|l| l.contains("allow(audit-positional)"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lint_flags_positional_emit() {
        let src = r#"
fn foo() {
    mvm_core::audit::emit(Kind::Foo, None, None);
}
"#;
        let findings = lint_source(Path::new("x.rs"), src);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].snippet.contains("mvm_core::audit::emit"));
    }

    #[test]
    fn lint_flags_chained_event_with_emit() {
        let src = r#"
fn foo() {
    mvm_core::audit::event(Kind::Foo)
        .detail("x")
        .emit();
}
"#;
        let findings = lint_source(Path::new("x.rs"), src);
        assert_eq!(findings.len(), 1, "got {findings:?}");
    }

    #[test]
    fn lint_allows_opt_out_comment() {
        let src = r#"
fn foo() {
    // allow(audit-positional): test fixture pins the legacy shape
    mvm_core::audit::emit(Kind::Foo, None, None);
}
"#;
        let findings = lint_source(Path::new("x.rs"), src);
        assert!(findings.is_empty(), "got {findings:?}");
    }

    #[test]
    fn lint_ignores_macro_definition_callsite() {
        // The macro expands to `event(…)…emit()` but is invoked as
        // `audit_emit!(…)`. The lint only sees source, so the macro
        // call site looks clean — and that's the point.
        let src = r#"
fn foo() {
    mvm_core::audit_emit!(Kind::Foo);
}
"#;
        let findings = lint_source(Path::new("x.rs"), src);
        assert!(findings.is_empty());
    }

    #[test]
    fn lint_does_not_flag_bare_event_without_emit() {
        // Bare `event(…)` returning the builder without terminating
        // is fine (used in the macro). Only chains that go through
        // `.emit()` count as violations.
        let src = r#"
fn foo() {
    let _builder = mvm_core::audit::event(Kind::Foo);
}
"#;
        let findings = lint_source(Path::new("x.rs"), src);
        assert!(findings.is_empty());
    }
}
