//! `xtask check-asserted-absence`
//!
//! Prose that says a name was never written must stay right about that.
//!
//! # Why the other direction needed a gate too
//!
//! `check-witness-citations` holds one direction: a cited identifier must
//! resolve. The opposite direction was doing real work and had nothing behind
//! it. `CLAUDE.md` carries paragraphs recording that six named tests for claim
//! 13, and five for claim 12, do not exist and never did — the residue of a
//! fabrication that survived months precisely because nothing checked this
//! file. Those paragraphs are the correction. They decay the instant somebody
//! writes a function with one of those names, and until now nothing would have
//! noticed.
//!
//! The file already states the convention it was following:
//!
//! > named — in quotes rather than backticks, because backticks assert a real
//! > identifier and these are names nobody ever wrote
//!
//! A convention held by hand across two paragraphs is a convention that lasts
//! until the next editor. This makes it mechanical.
//!
//! # The regions
//!
//! Absence is claimed explicitly, never inferred:
//!
//! ```markdown
//! <!-- absent:begin -->
//! …paragraph naming identifiers that must not exist…
//! <!-- absent:end -->
//! ```
//!
//! Inside a region every backticked or quoted token shaped like an identifier
//! must resolve to nothing. Outside one the gate is silent, so ordinary prose
//! that happens to quote a word cannot trip it.
//!
//! # Three ways to fail
//!
//! | Failure | Why |
//! |---|---|
//! | A named identifier resolves | The absence claim is now false |
//! | A region names nothing checkable | An empty region is a marker someone forgot to fill, not a passing check |
//! | Unbalanced or nested markers | The region's extent is ambiguous, so what it asserts is unknown |
//!
//! The middle row is the one that keeps this gate from rotting into
//! decoration. A region that checks nothing passes trivially, forever.

use anyhow::{Result, bail};
use std::collections::BTreeSet;
use std::path::Path;

use crate::prose_citations::{
    PROSE, Resolver, backticked, ignored_set, is_kebab_job, is_screaming_env, is_snake_ident,
    quoted, strip_rs_suffix,
};

/// Opens a region asserting that the names inside it do not exist.
const BEGIN: &str = "<!-- absent:begin -->";

/// Closes the region opened by [`BEGIN`].
const END: &str = "<!-- absent:end -->";

/// A span of prose asserting that the identifiers it names do not exist.
#[derive(Debug, PartialEq, Eq)]
pub struct Region {
    /// 1-based line of the opening marker.
    pub begin: usize,
    /// 1-based line of the closing marker.
    pub end: usize,
    /// The lines between the markers, exclusive.
    pub body: String,
}

/// Parse the absence regions in `text`.
///
/// # Errors
///
/// When a marker is unbalanced or a region opens inside another.
pub fn regions(text: &str) -> Result<Vec<Region>> {
    let mut out = Vec::new();
    let mut open: Option<(usize, Vec<&str>)> = None;
    let mut in_fence = false;

    for (idx, line) in text.lines().enumerate() {
        let lineno = idx + 1;
        // A fenced example showing the markers is documentation, not a live
        // assertion. Without this, the paragraph in `CLAUDE.md` explaining the
        // convention would itself be a region, and the placeholder name in it
        // would be under gate.
        if line.trim_start().starts_with("```") {
            in_fence = !in_fence;
            continue;
        }
        if in_fence {
            if let Some((_, body)) = open.as_mut() {
                body.push(line);
            }
            continue;
        }
        match line.trim() {
            BEGIN => {
                if let Some((start, _)) = open {
                    bail!("line {lineno}: absent:begin inside the region opened at line {start}");
                }
                open = Some((lineno, Vec::new()));
            }
            END => {
                let Some((start, body)) = open.take() else {
                    bail!("line {lineno}: absent:end with no matching absent:begin");
                };
                out.push(Region {
                    begin: start,
                    end: lineno,
                    body: body.join("\n"),
                });
            }
            _ => {
                if let Some((_, body)) = open.as_mut() {
                    body.push(line);
                }
            }
        }
    }

    if let Some((start, _)) = open {
        bail!("line {start}: absent:begin is never closed");
    }
    Ok(out)
}

/// Every line number covered by an absence region, markers included.
///
/// `check-witness-citations` uses this to stand down inside a region: a name
/// asserted absent there must not simultaneously be required to resolve.
#[must_use]
pub fn absent_line_numbers(text: &str) -> BTreeSet<usize> {
    let mut out = BTreeSet::new();
    if let Ok(found) = regions(text) {
        for region in found {
            out.extend(region.begin..=region.end);
        }
    }
    out
}

/// The identifier-shaped tokens a region claims do not exist.
#[must_use]
pub fn claimed_absent(body: &str) -> Vec<String> {
    let ignored = ignored_set();
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    for raw in backticked(body).into_iter().chain(quoted(body)) {
        let token = strip_rs_suffix(raw.trim()).to_string();
        if ignored.contains(token.as_str()) {
            continue;
        }
        let checkable = is_snake_ident(&token) || is_kebab_job(&token) || is_screaming_env(&token);
        if checkable && seen.insert(token.clone()) {
            out.push(token);
        }
    }
    out
}

/// What one file's regions produced.
#[derive(Debug, Default)]
pub struct Outcome {
    /// One message per failed absence claim or malformed region.
    pub errors: Vec<String>,
    /// Names whose absence was confirmed.
    pub checked: usize,
    /// Regions seen, well-formed or not.
    pub regions: usize,
}

/// Check every absence region in one document.
///
/// Split out from [`run`] so the rules can be tested against a real resolver
/// without needing a document in the tree that violates them — a gate whose
/// only test is "the tree passes" cannot tell you it would catch anything.
#[must_use]
pub fn check_text(rel: &str, text: &str, resolver: &Resolver) -> Outcome {
    let mut out = Outcome::default();
    let found = match regions(text) {
        Ok(found) => found,
        Err(err) => {
            out.errors.push(format!("{rel}: {err}"));
            return out;
        }
    };
    for region in found {
        out.regions += 1;
        let names = claimed_absent(&region.body);
        if names.is_empty() {
            out.errors.push(format!(
                "{rel}: the absence region at lines {}-{} names nothing checkable. A region that \
                 asserts nothing passes forever; fill it or remove it.",
                region.begin, region.end
            ));
            continue;
        }
        for token in names {
            out.checked += 1;
            if resolver.resolves(&token) {
                out.errors.push(format!(
                    "{rel}: lines {}-{} assert that `{token}` does not exist, but it now resolves \
                     in the tree. Either the prose is stale, or something was written under a \
                     name this file says nobody ever wrote.",
                    region.begin, region.end
                ));
            }
        }
    }
    out
}

/// Run the gate.
///
/// # Errors
///
/// When a name asserted absent resolves, a region names nothing checkable, or
/// the markers are unbalanced.
pub fn run(root: &Path) -> Result<()> {
    let resolver = Resolver::build(root);
    let mut errors = Vec::new();
    let mut checked = 0usize;
    let mut region_count = 0usize;

    for rel in PROSE {
        let path = root.join(rel);
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let outcome = check_text(rel, &text, &resolver);
        errors.extend(outcome.errors);
        checked += outcome.checked;
        region_count += outcome.regions;
    }

    if !errors.is_empty() {
        for err in &errors {
            eprintln!("[error] {err}");
        }
        bail!(
            "check-asserted-absence: {} absence claim(s) no longer hold",
            errors.len()
        );
    }

    println!(
        "check-asserted-absence: clean ({checked} name(s) still absent across {region_count} \
         region(s))"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wrap(body: &str) -> String {
        format!("intro\n{BEGIN}\n{body}\n{END}\ntail\n")
    }

    #[test]
    fn a_region_is_parsed_with_its_bounds_and_body() {
        let found = regions(&wrap("names `a_symbol_name_here`")).expect("parses");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].begin, 2);
        assert_eq!(found[0].end, 4);
        assert_eq!(found[0].body, "names `a_symbol_name_here`");
    }

    #[test]
    fn an_unclosed_region_is_refused() {
        let err = regions(&format!("{BEGIN}\nbody\n"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("never closed"), "{err}");
    }

    #[test]
    fn a_close_without_an_open_is_refused() {
        let err = regions(&format!("body\n{END}\n")).unwrap_err().to_string();
        assert!(err.contains("no matching"), "{err}");
    }

    #[test]
    fn a_nested_region_is_refused() {
        let err = regions(&format!("{BEGIN}\n{BEGIN}\n{END}\n"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("inside the region"), "{err}");
    }

    /// The convention has to be documentable without the documentation
    /// becoming a live claim.
    #[test]
    fn markers_inside_a_fence_are_an_example_not_a_region() {
        let doc = format!("prose\n```markdown\n{BEGIN}\n`x_y_z`\n{END}\n```\nmore\n");
        assert!(regions(&doc).expect("parses").is_empty());
    }

    #[test]
    fn both_quoted_and_backticked_names_are_claimed() {
        // Backticked spans are collected first, then quoted ones.
        let names = claimed_absent("\"quoted_symbol_name\" and `backticked_symbol_name`");
        assert_eq!(names, vec!["backticked_symbol_name", "quoted_symbol_name"]);
    }

    #[test]
    fn a_file_named_target_is_claimed_without_its_extension() {
        assert_eq!(
            claimed_absent("`fuzz_service_call.rs`"),
            vec!["fuzz_service_call"]
        );
    }

    #[test]
    fn prose_that_is_not_an_identifier_is_not_claimed() {
        assert!(claimed_absent("\"none of them exist\" and `plan_id`").is_empty());
    }

    #[test]
    fn absent_line_numbers_cover_the_markers_and_the_body() {
        let lines = absent_line_numbers(&wrap("names `a_symbol_name_here`"));
        assert_eq!(lines.into_iter().collect::<Vec<_>>(), vec![2, 3, 4]);
    }

    /// The gate must pass on the tree as it stands.
    #[test]
    fn the_absence_claims_in_the_tree_still_hold() {
        run(&crate::workspace_root()).expect("asserted-absent names are still absent");
    }

    /// The failure this exists to catch: prose still denying a name that has
    /// since been written.
    #[test]
    fn a_name_that_now_exists_fails_its_absence_claim() {
        let resolver = Resolver::build(&crate::workspace_root());
        let out = check_text("fixture.md", &wrap("`verify_audit_chain`"), &resolver);
        assert_eq!(out.regions, 1);
        assert_eq!(out.errors.len(), 1, "{:?}", out.errors);
        assert!(out.errors[0].contains("now resolves"), "{:?}", out.errors);
    }

    #[test]
    fn a_name_that_does_not_exist_passes() {
        let resolver = Resolver::build(&crate::workspace_root());
        let out = check_text(
            "fixture.md",
            &wrap("`no_such_symbol_was_ever_written_here`"),
            &resolver,
        );
        assert!(out.errors.is_empty(), "{:?}", out.errors);
        assert_eq!(out.checked, 1);
    }

    /// A region that checks nothing would pass forever; that is decoration,
    /// not a gate.
    #[test]
    fn an_empty_region_is_refused() {
        let resolver = Resolver::build(&crate::workspace_root());
        let out = check_text("fixture.md", &wrap("nothing checkable in here"), &resolver);
        assert_eq!(out.errors.len(), 1, "{:?}", out.errors);
        assert!(
            out.errors[0].contains("names nothing checkable"),
            "{:?}",
            out.errors
        );
    }

    #[test]
    fn a_malformed_region_is_reported_rather_than_ignored() {
        let resolver = Resolver::build(&crate::workspace_root());
        let out = check_text("fixture.md", &format!("{BEGIN}\nbody\n"), &resolver);
        assert_eq!(out.errors.len(), 1, "{:?}", out.errors);
        assert!(out.errors[0].contains("never closed"), "{:?}", out.errors);
    }
}
