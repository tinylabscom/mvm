//! `xtask check-honesty`
//!
//! R2: every claim has one of three honesty levels, and the suite must not
//! blur them. An `open` claim is measured and reported, never asserted. A
//! `some-true` claim is reproduced from an authority, not established here.
//! This gate scans public-facing documentation for assertive words attached
//! to `open` or `some-true` IDs and fails if it finds any.
//!
//! The structural half of R2 (every claim has exactly one level, every
//! some-true claim cites an authority) is enforced by `check-conformance`.
//! This gate is the behavioural half.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::Deserialize;

/// Assertive words that present a claim as established.
const ASSERTIVE: &[&str] = &[
    "proves",
    "proven",
    "proof that",
    "guarantees",
    "establishes",
    "demonstrates that",
    "shows that",
    "confirms",
];

/// Claim register subset needed for the honesty check.
#[derive(Debug, Deserialize)]
struct ClaimsFile {
    #[serde(default)]
    claim: Vec<Claim>,
}

#[derive(Debug, Deserialize)]
struct Claim {
    id: String,
    level: Level,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum Level {
    SomeTrue,
    Build,
    Open,
}

/// Authority register.
#[derive(Debug, Deserialize)]
struct AuthoritiesFile {
    #[serde(default)]
    authority: Vec<Authority>,
}

#[derive(Debug, Deserialize)]
struct Authority {
    id: String,
}

/// Run the R2 behavioural gate.
pub fn run(workspace: &Path) -> Result<()> {
    let claims: ClaimsFile = read_toml(&workspace.join("model/claims.toml"))?;
    let authorities: AuthoritiesFile = read_toml(&workspace.join("model/authorities.toml"))?;

    let open_ids: BTreeSet<&str> = claims
        .claim
        .iter()
        .filter(|c| matches!(c.level, Level::Open))
        .map(|c| c.id.as_str())
        .collect();
    let authority_ids: BTreeSet<&str> = authorities
        .authority
        .iter()
        .map(|a| a.id.as_str())
        .collect();

    let mut violations = Vec::new();

    // Docs that are public-facing or normative.
    let mut docs: Vec<PathBuf> = vec![
        workspace.join("README.md"),
        workspace.join("CONFORMANCE.md"),
    ];
    let public_docs = workspace.join("public/src/content/docs");
    if public_docs.is_dir() {
        gather_md(&public_docs, &mut docs)?;
    }

    for doc in docs {
        let rel = doc
            .strip_prefix(workspace)
            .unwrap_or(&doc)
            .to_string_lossy()
            .replace('\\', "/");
        let text =
            std::fs::read_to_string(&doc).with_context(|| format!("reading {}", doc.display()))?;
        for (i, line) in text.lines().enumerate() {
            let lower = line.to_lowercase();
            for id in &open_ids {
                if !line.contains(id) {
                    continue;
                }
                if let Some(word) = ASSERTIVE.iter().find(|w| lower.contains(*w)) {
                    violations.push(format!(
                        "R2: {rel}:{}: `{id}` is an `open` claim --- measured and reported, \
                         never asserted --- but this line says `{word}`.\n    {}",
                        i + 1,
                        line.trim()
                    ));
                }
            }
            for id in &authority_ids {
                if !line.contains(id) {
                    continue;
                }
                if let Some(word) = ASSERTIVE.iter().find(|w| lower.contains(*w)) {
                    violations.push(format!(
                        "R2: {rel}:{}: `{id}` is cited, not established here, but this line \
                         says `{word}`.\n    {}",
                        i + 1,
                        line.trim()
                    ));
                }
            }
        }
    }

    if !violations.is_empty() {
        bail!(
            "R2: honesty levels are load-bearing.\n\n{}",
            violations.join("\n\n")
        );
    }

    eprintln!("check-honesty: clean (R2)");
    Ok(())
}

fn read_toml<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))
}

fn gather_md(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            gather_md(&path, out)?;
        } else if path.extension().is_some_and(|e| e == "md" || e == "mdx") {
            out.push(path);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assertive_vocabulary_is_recognised() {
        for word in ASSERTIVE {
            let line = format!("MVM-OPEN-01 {word} the result is exact");
            assert!(
                ASSERTIVE.iter().any(|w| line.to_lowercase().contains(*w)),
                "{word} must be recognised"
            );
        }
        let honest = "MVM-OPEN-01 reports the result with its confidence interval";
        assert!(!ASSERTIVE.iter().any(|w| honest.to_lowercase().contains(*w)));
    }
}
