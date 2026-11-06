//! `xtask check-documented-env`
//!
//! A user-facing page that tells an operator to set `MVM_FOO` is making a
//! promise that something reads it. When the reader is deleted the page keeps
//! the promise, and nothing fails: the variable is silently ignored.
//!
//! Every `MVM_*` name in `public/src/content/docs` must therefore appear in at
//! least one file that is not prose (code, scripts, workflows, nix, tests). A
//! name that is documented but only ever read by the page's own inline script,
//! or by another repository, goes in `xtask/data/documented-env-allowlist.toml`
//! with the reason. The list is a ratchet: an entry that starts resolving, or
//! that no page documents any more, is reported stale and must be deleted.
//!
//! This reads text. A name assembled at run time (`format!("MVM_{x}")`) is not
//! seen, which can only make the gate stricter, never quieter.

use anyhow::{Context, Result, bail};
use regex::Regex;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

const DOCS_DIR: &str = "public/src/content/docs";
const ALLOWLIST: &str = "xtask/data/documented-env-allowlist.toml";

fn name_pattern() -> Regex {
    Regex::new(r"\bMVM_[A-Z0-9_]*[A-Z0-9]\b").expect("static pattern")
}

fn names_in(re: &Regex, text: &str) -> BTreeSet<String> {
    re.find_iter(text).map(|m| m.as_str().to_string()).collect()
}

/// Whether a file is prose, so a mention in it is documentation and not use.
fn is_prose(rel: &str) -> bool {
    rel.starts_with("specs/")
        || rel.starts_with(&format!("{DOCS_DIR}/"))
        || rel.ends_with(".md")
        || rel.ends_with(".mdx")
        || rel.ends_with(".lock")
        || rel == ALLOWLIST
}

/// The violations for one documented set against what the tree references.
fn evaluate(
    documented: &BTreeMap<String, String>,
    referenced: &BTreeSet<String>,
    allowed: &BTreeMap<String, String>,
) -> Vec<String> {
    let mut out = Vec::new();
    for (name, page) in documented {
        if !referenced.contains(name) && !allowed.contains_key(name) {
            out.push(format!(
                "{name} (documented in {page}) is read, set or mentioned by nothing outside prose; \
                 delete the documentation or list it in {ALLOWLIST} with the reason"
            ));
        }
    }
    for (name, reason) in allowed {
        if !documented.contains_key(name) {
            out.push(format!(
                "{name}: stale allowlist entry ({reason}); no page documents it any more"
            ));
        } else if referenced.contains(name) {
            out.push(format!(
                "{name}: stale allowlist entry ({reason}); something now references it"
            ));
        }
    }
    out
}

fn parse_allowlist(raw: &str) -> Result<BTreeMap<String, String>> {
    let value: toml::Value = raw.parse().with_context(|| format!("parse {ALLOWLIST}"))?;
    let mut out = BTreeMap::new();
    for entry in value
        .get("allow")
        .and_then(|v| v.as_array())
        .map(Vec::as_slice)
        .unwrap_or_default()
    {
        let name = entry.get("name").and_then(|v| v.as_str());
        let reason = entry.get("reason").and_then(|v| v.as_str());
        match (name, reason) {
            (Some(n), Some(r)) if !r.trim().is_empty() => {
                out.insert(n.to_string(), r.to_string());
            }
            _ => bail!("{ALLOWLIST}: every [[allow]] entry needs a name and a non-empty reason"),
        }
    }
    Ok(out)
}

pub(crate) fn run(workspace: &Path) -> Result<()> {
    let re = name_pattern();
    let mut documented = BTreeMap::new();
    let mut referenced = BTreeSet::new();
    crate::fs_walk::for_each_file(workspace, None, &mut |path, text| {
        let rel = path
            .strip_prefix(workspace)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/");
        let names = names_in(&re, text);
        if rel.starts_with(&format!("{DOCS_DIR}/")) {
            for n in names {
                documented.entry(n).or_insert_with(|| rel.clone());
            }
        } else if !is_prose(&rel) {
            referenced.extend(names);
        }
    })?;
    let raw = std::fs::read_to_string(workspace.join(ALLOWLIST))
        .with_context(|| format!("read {ALLOWLIST}"))?;
    let allowed = parse_allowlist(&raw)?;
    let violations = evaluate(&documented, &referenced, &allowed);
    if !violations.is_empty() {
        bail!(
            "check-documented-env: {} violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        );
    }
    println!(
        "check-documented-env: {} documented MVM_* names, {} allowlisted",
        documented.len(),
        allowed.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(a, b)| (a.to_string(), b.to_string()))
            .collect()
    }

    #[test]
    fn extracts_whole_names_only() {
        let re = name_pattern();
        let got = names_in(&re, "set MVM_HOME and `MVM_E2E_*`, not XMVM_FOO or MVM_");
        // A wildcard prefix such as `MVM_E2E_*` is not a variable name.
        assert_eq!(got, ["MVM_HOME".to_string()].into());
    }

    #[test]
    fn a_documented_name_nothing_references_is_a_violation() {
        let v = evaluate(&map(&[("MVM_GONE", "a.md")]), &BTreeSet::new(), &map(&[]));
        assert_eq!(v.len(), 1);
        assert!(v[0].contains("MVM_GONE"));
    }

    #[test]
    fn a_referenced_or_allowlisted_name_passes() {
        let refd: BTreeSet<String> = ["MVM_LIVE".to_string()].into();
        let v = evaluate(
            &map(&[("MVM_LIVE", "a.md"), ("MVM_INLINE", "a.md")]),
            &refd,
            &map(&[("MVM_INLINE", "read by the page's own script")]),
        );
        assert!(v.is_empty(), "{v:?}");
    }

    #[test]
    fn allowlist_entries_may_only_shrink() {
        let refd: BTreeSet<String> = ["MVM_NOW_READ".to_string()].into();
        let v = evaluate(
            &map(&[("MVM_NOW_READ", "a.md")]),
            &refd,
            &map(&[
                ("MVM_NOW_READ", "was inline"),
                ("MVM_UNDOCUMENTED", "page deleted"),
            ]),
        );
        assert_eq!(v.len(), 2);
        assert!(v.iter().all(|m| m.contains("stale allowlist entry")));
    }

    #[test]
    fn allowlist_requires_a_reason() {
        assert!(parse_allowlist("[[allow]]\nname = \"MVM_X\"\nreason = \" \"\n").is_err());
        assert!(parse_allowlist("[[allow]]\nname = \"MVM_X\"\nreason = \"why\"\n").is_ok());
    }

    #[test]
    fn prose_is_not_a_reference() {
        assert!(is_prose("specs/adrs/001.md"));
        assert!(is_prose("CLAUDE.md"));
        assert!(!is_prose("scripts/e2e.sh"));
        assert!(!is_prose("crates/x/src/lib.rs"));
    }
}
