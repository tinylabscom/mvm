//! `xtask check-witness-citations`
//!
//! Prose that names a witness must name one that exists.
//!
//! `check-claim-catalog` already verifies the witnesses named in the claims
//! ledger table. Nothing verified the ones cited *around* it, and that is where
//! the drift went: `CLAUDE.md` cited a witness that exists nowhere in the tree
//! and was believed for months, and a CI job was "corrected" to a name no
//! workflow defines. Both read as evidence. Neither was.
//!
//! ## The check
//!
//! In the prose files that make claims, every backticked identifier shaped
//! like a Rust test name (`snake_case`, no spaces) or a CI job name
//! (`kebab-case`) must appear *somewhere* in the sources or workflows. Accepted
//! ADRs additionally resolve concrete workspace paths and `mvm_*` module
//! paths. Proposed ADRs are excluded because they are allowed to describe code
//! that does not exist yet. That is deliberately weaker than "is a witness":
//! it asks only whether the name denotes anything at all.
//!
//! Weak is the point. A stricter rule — every cited test must be a declared
//! witness — would fire on the many legitimate mentions of ordinary functions
//! and fields, and a gate that cries wolf gets deleted. This one has no false
//! positives worth the name: a real symbol appears in the tree, and a
//! fabricated one does not.
//!
//! "Appears in the tree" means appears in **code**, not in a comment or a
//! string literal. See [`crate::prose_citations`] for why that distinction
//! turned out to be load-bearing rather than fussy.
//!
//! ## What it does not catch
//!
//! A citation naming a real symbol that is not actually a witness for the
//! claim beside it. That needs semantics this cannot have. What it catches is
//! the failure that actually happened twice: a name nobody ever wrote.

use anyhow::{Result, bail};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

use crate::prose_citations::{
    PROSE, Resolver, backticked_with_line, ignored_set, is_kebab_job, is_snake_ident,
};

/// Run the gate.
///
/// # Errors
///
/// When a prose file cites a test- or job-shaped name that appears nowhere in
/// the sources or workflows.
pub fn run(root: &Path) -> Result<()> {
    let resolver = Resolver::build(root);
    let ignored = ignored_set();

    let mut errors = Vec::new();
    let mut checked = 0usize;

    for rel in prose_files(root) {
        let path = root.join(&rel);
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let absent = crate::check_asserted_absence::absent_line_numbers(&text);
        let mut seen: HashSet<String> = HashSet::new();
        let is_adr = rel.starts_with("specs/adrs/");
        for (lineno, line, token) in backticked_with_line(&text) {
            // A name inside an absence region is asserted *not* to exist.
            // `check-asserted-absence` owns it; requiring it to resolve here
            // would make the two gates contradict each other.
            if absent.contains(&lineno) {
                continue;
            }
            let token = token.trim();
            if ignored.contains(token) || !seen.insert(token.to_string()) {
                continue;
            }
            if is_adr && let Some(kind) = CitationKind::classify(token) {
                checked += 1;
                if !kind.resolves(root, &resolver, token) {
                    errors.push(format!(
                        "{rel}: cites `{token}`, which does not resolve in the workspace. If it is \
                         a witness or implementation path, it does not exist; if it was renamed, \
                         the prose still names the old one."
                    ));
                }
            } else if is_snake_ident(token) {
                checked += 1;
                if !resolver.resolves(token) {
                    errors.push(format!(
                        "{rel}: cites `{token}`, which appears nowhere in the Rust sources. If it \
                         is a witness, it does not exist; if it was renamed, the prose still \
                         names the old one."
                    ));
                }
            } else if is_kebab_job(token) && line.contains("job") {
                checked += 1;
                if !resolver.resolves(token) {
                    errors.push(format!(
                        "{rel}: cites `{token}`, which no workflow defines. A job name that \
                         resolves to nothing reads as enforcement that is not there."
                    ));
                }
            }
        }
    }

    if !errors.is_empty() {
        for err in &errors {
            eprintln!("[error] {err}");
        }
        bail!(
            "check-witness-citations: {} citation(s) name something that does not exist",
            errors.len()
        );
    }

    println!("check-witness-citations: clean ({checked} citations resolved)");
    Ok(())
}

/// Citation shapes that make an implementation claim rather than merely
/// formatting prose, a command, or a configuration value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CitationKind {
    Symbol,
    QualifiedSymbol,
    WorkspacePath,
}

impl CitationKind {
    fn classify(token: &str) -> Option<Self> {
        if is_workspace_path(token) {
            return Some(Self::WorkspacePath);
        }
        if is_qualified_symbol(token) {
            return Some(Self::QualifiedSymbol);
        }
        if is_snake_ident(token) {
            return Some(Self::Symbol);
        }
        None
    }

    fn resolves(self, root: &Path, resolver: &Resolver, token: &str) -> bool {
        match self {
            Self::Symbol => resolver.resolves(token),
            Self::QualifiedSymbol => qualified_symbol_resolves(root, resolver, token),
            Self::WorkspacePath => {
                root.join(token).exists()
                    || resolver.in_code(crate::prose_citations::strip_rs_suffix(token))
            }
        }
    }
}

fn is_workspace_path(token: &str) -> bool {
    if token.contains(['<', '>', '*']) || token.contains("...") {
        return false;
    }
    [
        "crates/", ".github/", "nix/", "scripts/", "specs/", "src/", "xtask/",
    ]
    .iter()
    .any(|prefix| token.starts_with(prefix))
}

fn is_qualified_symbol(token: &str) -> bool {
    token.contains("::")
        && token.split("::").all(|segment| {
            !segment.is_empty()
                && segment
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        })
}

fn qualified_symbol_resolves(root: &Path, resolver: &Resolver, token: &str) -> bool {
    let segments: Vec<&str> = token.split("::").collect();
    let Some(first) = segments.first().copied() else {
        return false;
    };
    let Some(leaf) = segments.last().copied() else {
        return false;
    };

    if first.starts_with("mvm_") || first.starts_with("mvm-") {
        return mvm_crate_path_resolves(root, &segments);
    }

    resolver.in_code(leaf)
}

fn mvm_crate_path_resolves(root: &Path, segments: &[&str]) -> bool {
    let crate_name = segments[0].replace('_', "-");
    let src = root.join("crates").join(crate_name).join("src");
    if !src.is_dir() {
        return false;
    }
    if segments.len() == 1 {
        return true;
    }

    let rest = &segments[1..];
    if module_path_exists(&src, rest) {
        return true;
    }

    let Some((leaf, modules)) = rest.split_last() else {
        return false;
    };
    let Some(module_root) = module_root(&src, modules) else {
        return false;
    };
    rust_tree_contains(&module_root, leaf)
}

fn module_path_exists(src: &Path, modules: &[&str]) -> bool {
    if modules.is_empty() {
        return false;
    }
    let joined = modules
        .iter()
        .fold(PathBuf::from(src), |path, segment| path.join(segment));
    joined.is_dir() || joined.with_extension("rs").is_file() || joined.join("mod.rs").is_file()
}

fn module_root(src: &Path, modules: &[&str]) -> Option<PathBuf> {
    if modules.is_empty() {
        return Some(src.to_path_buf());
    }
    let joined = modules
        .iter()
        .fold(PathBuf::from(src), |path, segment| path.join(segment));
    if joined.is_dir() {
        Some(joined)
    } else {
        let file = joined.with_extension("rs");
        file.is_file().then_some(file)
    }
}

fn rust_tree_contains(path: &Path, token: &str) -> bool {
    if path.is_file() {
        return std::fs::read_to_string(path).is_ok_and(|body| {
            crate::rust_source::blank_comments_and_strings(&body).contains(token)
        });
    }

    let Ok(entries) = std::fs::read_dir(path) else {
        return false;
    };
    entries.flatten().any(|entry| {
        let path = entry.path();
        (path.is_dir() && rust_tree_contains(&path, token))
            || (path.extension().is_some_and(|ext| ext == "rs")
                && std::fs::read_to_string(&path).is_ok_and(|body| {
                    crate::rust_source::blank_comments_and_strings(&body).contains(token)
                }))
    })
}

fn prose_files(root: &Path) -> Vec<String> {
    let mut files: Vec<String> = PROSE.iter().map(|rel| (*rel).to_string()).collect();
    let adrs = root.join("specs/adrs");
    let Ok(entries) = std::fs::read_dir(&adrs) else {
        return files;
    };
    let mut accepted: Vec<String> = entries
        .flatten()
        .filter_map(|entry| {
            let path = entry.path();
            if path.extension().is_none_or(|ext| ext != "md") {
                return None;
            }
            let text = std::fs::read_to_string(&path).ok()?;
            if !is_accepted_adr(&text) {
                return None;
            }
            path.strip_prefix(root)
                .ok()
                .map(|rel| rel.to_string_lossy().to_string())
        })
        .collect();
    accepted.sort();
    files.extend(accepted);
    files.sort();
    files.dedup();
    files
}

fn is_accepted_adr(text: &str) -> bool {
    let mut after_status_heading = false;
    for line in text.lines().take(30) {
        let normalized = line.trim().trim_matches('*').trim();
        if let Some(status) = normalized.strip_prefix("Status:") {
            return status.trim_start().starts_with("Accepted");
        }
        if normalized.eq_ignore_ascii_case("## Status") {
            after_status_heading = true;
            continue;
        }
        if after_status_heading && !normalized.is_empty() {
            return normalized.starts_with("Accepted");
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_adr(root: &Path, name: &str, status: &str, body: &str) {
        let dir = root.join("specs/adrs");
        std::fs::create_dir_all(&dir).expect("create ADR fixture directory");
        std::fs::write(
            dir.join(name),
            format!("# Fixture ADR\n\n## Status\n\n{status}.\n\n{body}\n"),
        )
        .expect("write ADR fixture");
    }

    /// The gate must pass on the tree as it stands.
    #[test]
    fn the_prose_in_the_tree_resolves() {
        run(&crate::workspace_root()).expect("cited witnesses resolve");
    }

    #[test]
    fn an_accepted_adr_cannot_name_a_missing_witness() {
        let tmp = tempfile::tempdir().expect("tempdir");
        write_adr(
            tmp.path(),
            "001-fixture.md",
            "Accepted",
            "The witness is `this_witness_does_not_exist`.",
        );

        assert!(run(tmp.path()).is_err());
    }

    #[test]
    fn a_proposed_adr_may_name_a_future_witness() {
        let tmp = tempfile::tempdir().expect("tempdir");
        write_adr(
            tmp.path(),
            "001-fixture.md",
            "Proposed",
            "The future witness is `this_witness_does_not_exist`.",
        );

        run(tmp.path()).expect("proposed ADRs may describe code that does not exist yet");
    }

    #[test]
    fn an_accepted_adr_may_name_live_code_and_paths() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let src = tmp.path().join("crates/mvm-core/src");
        std::fs::create_dir_all(&src).expect("create crate fixture");
        std::fs::write(src.join("lib.rs"), "pub mod real;\n").expect("write crate root");
        std::fs::write(src.join("real.rs"), "pub fn live_witness_exists() {}\n")
            .expect("write live witness");
        write_adr(
            tmp.path(),
            "001-fixture.md",
            "Accepted",
            "The `live_witness_exists` witness is in `mvm_core::real` at \
             `crates/mvm-core/src/real.rs`.",
        );

        run(tmp.path()).expect("live accepted-ADR citations resolve");
    }

    #[test]
    fn an_accepted_adr_cannot_name_a_missing_workspace_path() {
        let tmp = tempfile::tempdir().expect("tempdir");
        write_adr(
            tmp.path(),
            "001-fixture.md",
            "Accepted",
            "The implementation lives at `crates/missing/src/lib.rs`.",
        );

        assert!(run(tmp.path()).is_err());
    }

    #[test]
    fn an_accepted_adr_cannot_name_a_missing_mvm_module() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(tmp.path().join("crates/mvm-core/src"))
            .expect("create crate fixture");
        std::fs::write(
            tmp.path().join("crates/mvm-core/src/lib.rs"),
            "pub mod real;\n",
        )
        .expect("write crate fixture");
        write_adr(
            tmp.path(),
            "001-fixture.md",
            "Accepted",
            "The implementation is `mvm_core::missing`.",
        );

        assert!(run(tmp.path()).is_err());
    }
}
