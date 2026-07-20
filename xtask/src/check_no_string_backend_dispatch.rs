//! `xtask check-no-string-backend-dispatch`
//!
//! Backend dispatch must branch on the typed `VmBackend::kind()` discriminant
//! (`BackendKind`), never on the stringly `VmBackend::name()`. A string
//! comparison against a backend name is fragile — a typo silently falls
//! through — and a removed backend can leave a dead string arm behind
//! forever, since nothing forces the comparison to stay exhaustive.
//! `BackendKind` is a closed enum: removing or adding a variant is a compile
//! error at every `match` site that dispatches on it.
//!
//! Flags an equality comparison of `name()`'s return value against one of
//! the known backend selector literals, or a `matches!` macro call over
//! `name()` against a set of string literals, anywhere under `crates/`. The
//! literal set is scoped to actual backend selectors (rather than matching
//! any `name() == "…"` in the workspace) so the lint doesn't false-positive
//! on an unrelated type that happens to expose its own `name()` accessor.
//! Use `.kind()` and a descriptor capability flag, a `VmBackend` trait
//! method, or an exhaustive `match` on `BackendKind` instead.

use anyhow::{Context, Result, bail};
use regex::Regex;
use std::path::Path;

/// The full known-backend-selector set, including the retired `vz` — a
/// reintroduced `vz` arm is exactly the regression this lint exists to
/// catch, since there is no `BackendKind::Vz` for it to belong to.
const BACKEND_SELECTORS: &str = "firecracker|libkrun|hvf|qemu|mock|vz";

/// This file's own doc comment above describes the banned shapes in prose
/// rather than as literal comparisons, so it never matches its own
/// patterns — no self-exemption entry needed. Kept that way deliberately:
/// if a future edit here ever adds a literal comparison, the lint should
/// catch it same as anywhere else.
fn patterns() -> [Regex; 2] {
    [
        Regex::new(&format!(r#"\.name\(\)\s*==\s*"({BACKEND_SELECTORS})""#))
            .expect("name-equality pattern is valid"),
        Regex::new(&format!(
            r#"matches!\([^)]*\.name\(\)[^)]*"({BACKEND_SELECTORS})""#
        ))
        .expect("matches! pattern is valid"),
    ]
}

pub fn run(workspace: &Path) -> Result<()> {
    let crates_dir = workspace.join("crates");
    if !crates_dir.is_dir() {
        bail!("expected workspace crates dir at {}", crates_dir.display());
    }
    let patterns = patterns();
    let mut findings: Vec<String> = Vec::new();
    visit_rust_files(&crates_dir, &mut |path| -> Result<()> {
        let src =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        for (i, line) in src.lines().enumerate() {
            if patterns.iter().any(|re| re.is_match(line)) {
                findings.push(format!("{}:{}: {}", path.display(), i + 1, line.trim()));
            }
        }
        Ok(())
    })?;

    if findings.is_empty() {
        eprintln!(
            "check-no-string-backend-dispatch: clean (no backend.name() == \"…\" / matches!(…name()…) dispatch)"
        );
        return Ok(());
    }
    eprintln!(
        "check-no-string-backend-dispatch: {} stringly backend-name dispatch site(s) — \
         branch on VmBackend::kind() -> BackendKind instead of comparing name():",
        findings.len()
    );
    for f in &findings {
        eprintln!("  {f}");
    }
    bail!(
        "check-no-string-backend-dispatch: {} stringly backend dispatch site(s)",
        findings.len()
    );
}

fn visit_rust_files(dir: &Path, f: &mut dyn FnMut(&Path) -> Result<()>) -> Result<()> {
    for entry in std::fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        let path = entry?.path();
        if path.is_dir() {
            if path.file_name().is_some_and(|n| n == "target") {
                continue;
            }
            visit_rust_files(&path, f)?;
        } else if path.extension().is_some_and(|e| e == "rs") {
            f(&path)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(root: &Path, name: &str, body: &str) {
        let dir = root.join("crates/x/src");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(name), body).unwrap();
    }

    #[test]
    fn name_equality_comparison_is_flagged() {
        let tmp = tempfile::tempdir().unwrap();
        write(
            tmp.path(),
            "bad.rs",
            "fn f(b: &dyn VmBackend) -> bool { b.name() == \"libkrun\" }\n",
        );
        assert!(run(tmp.path()).is_err());
    }

    #[test]
    fn dead_vz_arm_is_flagged() {
        let tmp = tempfile::tempdir().unwrap();
        write(
            tmp.path(),
            "bad.rs",
            "fn f(b: &dyn VmBackend) -> bool { b.name() == \"vz\" }\n",
        );
        assert!(run(tmp.path()).is_err());
    }

    #[test]
    fn matches_macro_on_name_is_flagged() {
        let tmp = tempfile::tempdir().unwrap();
        write(
            tmp.path(),
            "bad.rs",
            "fn f(b: &dyn VmBackend) -> bool { matches!(b.name(), \"firecracker\" | \"hvf\") }\n",
        );
        assert!(run(tmp.path()).is_err());
    }

    #[test]
    fn kind_based_dispatch_does_not_match() {
        let tmp = tempfile::tempdir().unwrap();
        write(
            tmp.path(),
            "ok.rs",
            "fn f(b: &dyn VmBackend) -> bool { b.kind() == BackendKind::Libkrun }\n",
        );
        assert!(run(tmp.path()).is_ok());
    }

    #[test]
    fn matches_macro_on_kind_does_not_match() {
        let tmp = tempfile::tempdir().unwrap();
        write(
            tmp.path(),
            "ok.rs",
            "fn f(b: &dyn VmBackend) -> bool { matches!(b.kind(), BackendKind::Firecracker | BackendKind::Hvf) }\n",
        );
        assert!(run(tmp.path()).is_ok());
    }

    #[test]
    fn unrelated_name_call_does_not_match() {
        let tmp = tempfile::tempdir().unwrap();
        write(
            tmp.path(),
            "ok.rs",
            "fn f(v: &Vm) -> bool { v.name() == \"my-vm\" }\n",
        );
        assert!(run(tmp.path()).is_ok());
    }
}
