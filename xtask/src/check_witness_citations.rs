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
//! (`kebab-case`) must appear *somewhere* in the sources or workflows. That is
//! deliberately weaker than "is a witness": it asks only whether the name
//! denotes anything at all.
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
use std::path::Path;

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

    for rel in PROSE {
        let path = root.join(rel);
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let absent = crate::check_asserted_absence::absent_line_numbers(&text);
        let mut seen: HashSet<String> = HashSet::new();
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
            if is_snake_ident(token) {
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The gate must pass on the tree as it stands.
    #[test]
    fn the_prose_in_the_tree_resolves() {
        run(&crate::workspace_root()).expect("cited witnesses resolve");
    }
}
