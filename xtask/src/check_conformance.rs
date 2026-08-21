//! `xtask check-conformance`
//!
//! The model is the single source of every conformance claim (R1). This gate
//! loads `model/*.toml`, validates its internal consistency (R2), resolves
//! every witness token to a real function or CI lane, and regenerates
//! `CONFORMANCE.md` so the documentation cannot drift from the register.
//!
//! Run with `--write` to refresh the generated file after editing the model.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::Deserialize;

/// Path to the generated conformance doc, relative to the workspace root.
pub const CONFORMANCE_PATH: &str = "CONFORMANCE.md";

/// One of the three honesty levels (R2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Level {
    /// A fact reproduced from an authority. Not established here.
    SomeTrue,
    /// Constructed here and validated against its oracle.
    Build,
    /// Measured and reported, never asserted.
    Open,
}

impl Level {
    /// String token used in TOML and generated docs.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SomeTrue => "some-true",
            Self::Build => "build",
            Self::Open => "open",
        }
    }
}

/// `model/claims.toml` --- the conformance ID register.
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct Claims {
    /// Schema tag.
    pub spec: String,
    /// One row per claim.
    #[serde(default)]
    pub claim: Vec<Claim>,
}

/// One registered conformance claim.
#[derive(Debug, Clone, Deserialize)]
pub struct Claim {
    /// The ID, e.g. `MVM-SEC-01`.
    pub id: String,
    /// The honesty level of the claim (R2).
    pub level: Level,
    /// The Gherkin suite the scenario belongs to.
    pub suite: String,
    /// What the ID claims.
    pub statement: String,
    /// Typed witnesses: `fn:NAME` or `ci:NAME`.
    #[serde(default)]
    pub witnesses: Vec<String>,
}

/// `model/authorities.toml` --- what this repository cites rather than proves.
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct Authorities {
    /// Schema tag.
    pub spec: String,
    /// One row per cited authority.
    #[serde(default)]
    pub authority: Vec<Authority>,
}

/// A cited authority.
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct Authority {
    /// Stable identifier.
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// What a third party needs to find the source.
    pub citation: String,
    /// A checksum over the committed artifact, or `none`.
    pub checksum: String,
    /// Why there is no checksum, when there is none.
    #[serde(default)]
    pub checksum_reason: String,
    /// What the authority says.
    pub statement: String,
    /// Conformance IDs that are evidence this library realizes it.
    #[serde(default)]
    pub realized_by: Vec<String>,
}

/// `model/ledger.toml` --- honesty ledger for non-ID claims.
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct Ledger {
    /// Schema tag.
    pub spec: String,
    /// One row per claim.
    #[serde(default)]
    pub claim: Vec<LedgerClaim>,
}

/// A non-ID claim.
#[derive(Debug, Clone, Deserialize)]
pub struct LedgerClaim {
    /// Identifier, e.g. `OPEN-01` or `AUTH-01`.
    pub id: String,
    /// Honesty level.
    pub level: Level,
    /// What is claimed.
    pub statement: String,
    /// Authority for `some-true` claims.
    #[serde(default)]
    pub authority: Option<String>,
}

/// Everything `model/*.toml` says.
#[derive(Debug, Clone)]
pub struct Model {
    /// Conformance ID register.
    pub claims: Claims,
    /// Cited authorities.
    pub authorities: Authorities,
    /// Non-ID claim ledger.
    pub ledger: Ledger,
}

impl Model {
    /// Load the model from a workspace root.
    pub fn load(root: &Path) -> Result<Self> {
        Ok(Self {
            claims: read_toml(&root.join("model/claims.toml"))?,
            authorities: read_toml(&root.join("model/authorities.toml"))?,
            ledger: read_toml(&root.join("model/ledger.toml"))?,
        })
    }

    /// Cross-check the model against itself.
    pub fn check(&self) -> Result<()> {
        let mut seen: BTreeSet<&str> = BTreeSet::new();
        for claim in &self.claims.claim {
            if !seen.insert(&claim.id) {
                bail!("{}: claim ID registered twice", claim.id);
            }
            if claim.statement.trim().is_empty() {
                bail!("{}: claim statement must not be empty", claim.id);
            }
            if claim.suite.trim().is_empty() {
                bail!("{}: claim must name a Gherkin suite", claim.id);
            }
            if claim.witnesses.is_empty() {
                bail!("{}: claim must have at least one witness", claim.id);
            }
            for w in &claim.witnesses {
                if !(w.starts_with("fn:") || w.starts_with("ci:")) {
                    bail!("{}: witness `{w}` must start with `fn:` or `ci:`", claim.id);
                }
            }
        }

        for authority in &self.authorities.authority {
            if authority.citation.trim().is_empty() {
                bail!("{}: authority citation must not be empty", authority.id);
            }
            if authority.checksum == "none" && authority.checksum_reason.trim().is_empty() {
                bail!(
                    "{}: no checksum and no reason. A missing checksum must be a stated fact.",
                    authority.id
                );
            }
            for id in &authority.realized_by {
                if self.claims.claim.iter().all(|c| c.id != *id) {
                    bail!(
                        "{}: realized_by references unknown claim ID {id}",
                        authority.id
                    );
                }
            }
        }

        for claim in &self.ledger.claim {
            match claim.level {
                Level::SomeTrue => {
                    if claim.authority.is_none() {
                        bail!(
                            "{}: a some-true ledger claim must name an authority",
                            claim.id
                        );
                    }
                }
                Level::Build | Level::Open => {
                    // No additional structural requirements for these levels
                    // in the ledger; the honesty lint enforces how they are
                    // talked about.
                }
            }
        }

        // Every some-true claim in the register must cite an authority that
        // exists and names it back.
        for claim in &self.claims.claim {
            if claim.level != Level::SomeTrue {
                continue;
            }
            let citing = self
                .authorities
                .authority
                .iter()
                .find(|a| a.realized_by.contains(&claim.id));
            if citing.is_none() {
                bail!(
                    "{}: some-true claim must be realized_by an authority in model/authorities.toml",
                    claim.id
                );
            }
        }

        Ok(())
    }
}

fn read_toml<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))
}

/// Render `CONFORMANCE.md` from the model.
pub fn render_conformance(model: &Model) -> String {
    let mut out = String::new();
    out.push_str("<!-- @generated by `cargo run -p xtask -- check-conformance --write` from model/*.toml. -->\n");
    out.push_str("<!-- Do not edit. R1: the model is the single source. -->\n\n");
    out.push_str("# CONFORMANCE\n\n");
    out.push_str("The conformance claim register. Every claim has a scenario in ");
    out.push_str("`features/suites/` and at least one witness function or CI lane. ");
    out.push_str("`cargo run -p xtask -- check-conformance` fails if this file drifts ");
    out.push_str("from `model/*.toml`.\n\n");

    out.push_str("The three honesty levels (R2):\n\n");
    out.push_str("| Level | Meaning |\n");
    out.push_str("| --- | --- |\n");
    out.push_str(
        "| `some-true` | A fact reproduced from an authority. **Not established here.** |\n",
    );
    out.push_str(
        "| `build` | Constructed here and validated against its oracle. Evidence, not proof. |\n",
    );
    out.push_str("| `open` | Measured and reported. **Never asserted.** |\n\n");

    // Group claims by suite.
    let mut by_suite: BTreeMap<&str, Vec<&Claim>> = BTreeMap::new();
    for claim in &model.claims.claim {
        by_suite.entry(&claim.suite).or_default().push(claim);
    }

    for (suite, claims) in &by_suite {
        out.push_str(&format!("## {suite}\n\n"));
        out.push_str("| ID | Level | Statement | Witnesses |\n");
        out.push_str("| --- | --- | --- | --- |\n");
        for claim in claims {
            let statement = escape_cell(&claim.statement);
            let witnesses = claim
                .witnesses
                .iter()
                .map(|w| format!("`{w}`"))
                .collect::<Vec<_>>()
                .join(", ");
            out.push_str(&format!(
                "| `{}` | `{}` | {statement} | {witnesses} |\n",
                claim.id,
                claim.level.as_str()
            ));
        }
        out.push('\n');
    }

    if !model.authorities.authority.is_empty() {
        out.push_str("## Cited authorities\n\n");
        out.push_str("Never re-derived, vendored, or gated on.\n\n");
        out.push_str("| ID | Name | Citation | Realized by |\n");
        out.push_str("| --- | --- | --- | --- |\n");
        for authority in &model.authorities.authority {
            let citation = escape_cell(&authority.citation);
            let realized = if authority.realized_by.is_empty() {
                "--".to_string()
            } else {
                authority
                    .realized_by
                    .iter()
                    .map(|id| format!("`{id}`"))
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            out.push_str(&format!(
                "| `{}` | {} | {citation} | {realized} |\n",
                authority.id,
                escape_cell(&authority.name)
            ));
        }
        out.push('\n');
    }

    if !model.ledger.claim.is_empty() {
        out.push_str("## Claims that are not conformance IDs\n\n");
        out.push_str("| ID | Level | Statement |\n");
        out.push_str("| --- | --- | --- |\n");
        for claim in &model.ledger.claim {
            out.push_str(&format!(
                "| `{}` | `{}` | {} |\n",
                claim.id,
                claim.level.as_str(),
                escape_cell(&claim.statement)
            ));
        }
    }

    out
}

fn escape_cell(text: &str) -> String {
    text.replace('\n', " ").replace('|', "\\|")
}

/// Resolve every witness token to an existing function or CI lane.
pub fn resolve_witnesses(workspace: &Path, model: &Model) -> Result<()> {
    let mut missing = Vec::new();

    for claim in &model.claims.claim {
        for witness in &claim.witnesses {
            let resolved = match witness.split_once(':') {
                Some(("fn", name)) => resolve_fn(workspace, name),
                Some(("ci", name)) => resolve_ci(workspace, name),
                _ => false,
            };
            if !resolved {
                missing.push(format!("{}: {}", claim.id, witness));
            }
        }
    }

    if !missing.is_empty() {
        bail!(
            "check-conformance: the following witnesses were not found:\n{}",
            missing.join("\n")
        );
    }

    Ok(())
}

fn resolve_fn(workspace: &Path, name: &str) -> bool {
    let crates = workspace.join("crates");
    let Ok(entries) = std::fs::read_dir(&crates) else {
        return false;
    };
    let needle = format!("fn {name}(");
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        for sub in ["src", "tests"] {
            let dir = path.join(sub);
            if dir.is_dir() && search_dir(&dir, &needle) {
                return true;
            }
        }
    }
    false
}

/// Resolve a `ci:` witness through the shared anchor rules.
///
/// This was its own substring scan — `text.contains(name)` over every
/// workflow — which is the weaker of the two implementations the repo had
/// for one question. It matched a name in a comment as readily as a live
/// job, so a deleted lane kept its witness green, and it could not see a
/// gate that runs inside the policy driver rather than as its own step.
/// `claims_ledger::ci_anchors` already answered both correctly for
/// `check-claim-catalog`; there is no reason for a second answer here.
fn resolve_ci(workspace: &Path, name: &str) -> bool {
    let workflows = workspace.join(".github/workflows");
    let Ok(entries) = std::fs::read_dir(&workflows) else {
        return false;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "yml" || e == "yaml")
            && let Ok(text) = std::fs::read_to_string(&path)
            && crate::claims_ledger::ci_anchors(&text)
                .iter()
                .any(|anchor| anchor == name)
        {
            return true;
        }
    }
    false
}

fn search_dir(dir: &Path, needle: &str) -> bool {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return false;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() && search_dir(&path, needle) {
            return true;
        }
        if path.extension().is_some_and(|e| e == "rs")
            && let Ok(text) = std::fs::read_to_string(&path)
            && text.contains(needle)
        {
            return true;
        }
    }
    false
}

/// Run the gate.
pub fn run(workspace: &Path, write: bool) -> Result<()> {
    let model = Model::load(workspace)?;
    model.check()?;
    resolve_witnesses(workspace, &model)?;

    let rendered = render_conformance(&model);
    let path: PathBuf = workspace.join(CONFORMANCE_PATH);

    if write {
        std::fs::write(&path, rendered)?;
        eprintln!("wrote {}", path.display());
        return Ok(());
    }

    let committed = std::fs::read_to_string(&path)
        .with_context(|| format!("reading {} (run with --write to create it)", path.display()))?;
    if committed != rendered {
        bail!(
            "{} is stale: it disagrees with model/*.toml.\n\
             R1: a claim cannot exist in the documentation without a register row. \
             Run `cargo run -p xtask -- check-conformance --write`.",
            path.display()
        );
    }

    eprintln!(
        "check-conformance: CONFORMANCE.md equals the model ({} claims)",
        model.claims.claim.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn model_loads_and_checks() {
        // Resolve workspace root from this test binary's location:
        // crates/mvm-conformance/tests/ -> .../worktree root.
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(1)
            .expect("xtask is one level below the worktree root")
            .to_path_buf();
        let model = Model::load(&root).expect("model loads");
        model.check().expect("model checks");
    }

    #[test]
    fn render_is_deterministic() {
        let model = Model {
            claims: Claims {
                spec: "test".into(),
                claim: vec![Claim {
                    id: "MVM-TEST-01".into(),
                    level: Level::Build,
                    suite: "test_suite".into(),
                    statement: "A test claim".into(),
                    witnesses: vec!["fn:test_fn".into()],
                }],
            },
            authorities: Authorities {
                spec: "test".into(),
                authority: vec![],
            },
            ledger: Ledger {
                spec: "test".into(),
                claim: vec![],
            },
        };
        let rendered = render_conformance(&model);
        assert!(rendered.contains("MVM-TEST-01"));
        assert!(rendered.contains("A test claim"));
        assert!(rendered.contains("fn:test_fn"));
    }
}
