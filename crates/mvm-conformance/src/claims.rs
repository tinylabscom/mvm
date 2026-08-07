//! Shared helpers for the R3 conformance claim register.
//!
//! Loads `model/claims.toml`, discovers the Gherkin scenarios under
//! `features/suites/`, and resolves claim witnesses to real code or CI
//! artifacts. Kept in the library so both the meta unit-test gate and the
//! cucumber BDD claim scenarios use exactly the same definition of
//! "registered", "implemented", and "witnessed".

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde::Deserialize;

/// One of the three honesty levels (R2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Level {
    /// Established by a real implementation / proof.
    Build,
    /// Established by an external, audited process (e.g. CI gate).
    SomeTrue,
    /// Intentionally still open / aspirational.
    Open,
}

impl Level {
    /// String used in Gherkin tags and the claim register.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Build => "build",
            Self::SomeTrue => "some-true",
            Self::Open => "open",
        }
    }
}

#[derive(Debug, Deserialize)]
struct ClaimsFile {
    #[serde(default)]
    claim: Vec<Claim>,
}

/// A single row from `model/claims.toml`.
#[derive(Debug, Clone, Deserialize)]
pub struct Claim {
    pub id: String,
    pub level: Level,
    #[serde(default)]
    pub suite: String,
    #[serde(default)]
    pub statement: String,
    #[serde(default)]
    pub witnesses: Vec<String>,
}

/// A parsed Gherkin scenario, limited to the fields the claim gate needs.
#[derive(Debug, Clone)]
pub struct Scenario {
    pub id: String,
    pub level: String,
    pub statement: String,
    pub suite: String,
    pub steps: Vec<String>,
}

/// Repository root: `crates/mvm-conformance` is two levels below it.
pub fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crates/mvm-conformance is two levels below the repo root")
        .to_path_buf()
}

/// Load every claim from `model/claims.toml`.
pub fn load_claims(root: &Path) -> Vec<Claim> {
    let text = std::fs::read_to_string(root.join("model/claims.toml"))
        .expect("model/claims.toml must exist");
    toml::from_str::<ClaimsFile>(&text)
        .expect("model/claims.toml must parse")
        .claim
}

/// Look up a claim by id.
pub fn find_claim(root: &Path, id: &str) -> Option<Claim> {
    load_claims(root).into_iter().find(|claim| claim.id == id)
}

/// Parse every scenario from `features/suites/**/*.feature`.
pub fn load_scenarios(root: &Path) -> Vec<Scenario> {
    let suites_dir = root.join("features/suites");
    let mut entries: Vec<_> = std::fs::read_dir(&suites_dir)
        .expect("features/suites must exist")
        .filter_map(Result::ok)
        .collect();
    entries.sort_by_key(|e| e.path());

    let mut scenarios = Vec::new();
    for entry in entries {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let suite_name = path.file_name().unwrap().to_string_lossy().to_string();
        let mut files: Vec<_> = std::fs::read_dir(&path)
            .expect("suite dir must be readable")
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|e| e == "feature"))
            .collect();
        files.sort();

        for file in files {
            let text = std::fs::read_to_string(&file).expect("feature file must be readable");
            scenarios.extend(parse_feature(&suite_name, &text));
        }
    }
    scenarios
}

fn looks_like_id(tag: &str) -> bool {
    let mut parts = tag.split('-');
    let first = parts.next();
    let rest: Vec<&str> = parts.collect();
    first == Some("MVM")
        && rest.len() >= 2
        && rest[..rest.len() - 1]
            .iter()
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_uppercase()))
        && rest
            .last()
            .is_some_and(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
}

fn parse_feature(suite: &str, text: &str) -> Vec<Scenario> {
    let mut out = Vec::new();
    let mut pending_tags: Vec<String> = Vec::new();
    let mut current: Option<Scenario> = None;

    for raw in text.lines() {
        let line = raw.trim();
        if line.starts_with('@') {
            pending_tags = line
                .split_whitespace()
                .map(|t| t.trim_start_matches('@').to_string())
                .collect();
        } else if let Some(rest) = line.strip_prefix("Scenario:") {
            if let Some(done) = current.take() {
                out.push(done);
            }
            let id = pending_tags
                .first()
                .filter(|t| looks_like_id(t))
                .cloned()
                .unwrap_or_default();
            let level = if id.is_empty() {
                String::new()
            } else {
                pending_tags.get(1).cloned().unwrap_or_default()
            };
            current = Some(Scenario {
                id,
                level,
                statement: rest.trim().to_string(),
                suite: suite.to_string(),
                steps: Vec::new(),
            });
            pending_tags.clear();
        } else if let Some(scenario) = current.as_mut() {
            for keyword in ["Given ", "When ", "Then ", "And ", "But "] {
                if let Some(step) = line.strip_prefix(keyword) {
                    scenario.steps.push(format!("{keyword}{step}"));
                    break;
                }
            }
        }
    }
    if let Some(done) = current.take() {
        out.push(done);
    }
    out
}

/// True when at least one scenario tagged with the claim id exists in
/// `features/suites/` and has steps.
pub fn has_suite_scenario(root: &Path, claim: &Claim) -> bool {
    let suites_dir = root.join("features/suites");
    let Ok(entries) = std::fs::read_dir(&suites_dir) else {
        return false;
    };

    for entry in entries.filter_map(Result::ok) {
        let suite_dir = entry.path();
        if !suite_dir.is_dir() {
            continue;
        }
        let suite_name = suite_dir.file_name().unwrap().to_string_lossy().to_string();
        let Ok(files) = std::fs::read_dir(&suite_dir) else {
            continue;
        };
        for file in files.filter_map(Result::ok) {
            let path = file.path();
            if path.extension().is_some_and(|e| e == "feature")
                && let Ok(text) = std::fs::read_to_string(&path)
            {
                for scenario in parse_feature(&suite_name, &text) {
                    if scenario.id == claim.id && !scenario.steps.is_empty() {
                        return true;
                    }
                }
            }
        }
    }
    false
}

/// Resolve a single witness string to a real artifact.
///
/// Witness forms:
/// - `fn:<name>` — a Rust function `fn name(` in `crates/*/src` or `crates/*/tests`.
/// - `ci:<name>` — a substring appearing in `.github/workflows/*.yml` or `*.yaml`.
pub fn resolve_witness(root: &Path, witness: &str) -> bool {
    match witness.split_once(':') {
        Some(("fn", name)) => resolve_fn(root, name),
        Some(("ci", name)) => resolve_ci(root, name),
        _ => false,
    }
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

fn resolve_ci(workspace: &Path, name: &str) -> bool {
    let workflows = workspace.join(".github/workflows");
    let Ok(entries) = std::fs::read_dir(&workflows) else {
        return false;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "yml" || e == "yaml")
            && let Ok(text) = std::fs::read_to_string(&path)
            && text.contains(name)
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

/// Resolve every witness on a claim. Returns the list of unresolved witnesses
/// (empty when the claim is fully witnessed).
pub fn unresolved_witnesses(root: &Path, claim: &Claim) -> Vec<String> {
    claim
        .witnesses
        .iter()
        .filter(|w| !resolve_witness(root, w))
        .cloned()
        .collect()
}

/// All claim ids that appear in `model/claims.toml`.
pub fn registered_ids(root: &Path) -> BTreeSet<String> {
    load_claims(root).into_iter().map(|c| c.id).collect()
}

/// All scenario ids discovered from feature files.
pub fn scenario_ids(root: &Path) -> BTreeSet<String> {
    load_scenarios(root)
        .into_iter()
        .map(|s| s.id)
        .filter(|id| !id.is_empty())
        .collect()
}
