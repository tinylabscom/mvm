//! R2/R3 meta-gate for the conformance claim register.
//!
//! R3: every capability begins as a register row, then a Gherkin scenario,
//! then a witness. This test loads `model/claims.toml`, parses every
//! `features/suites/**/*.feature` file for ID/level tags, and fails if:
//!   - a registered claim has no scenario,
//!   - a scenario names an unregistered ID,
//!   - a scenario's level tag disagrees with the register,
//!   - a registered claim has no resolvable witness.
//!
//! R2: the honesty levels only mean something if the suite respects them.
//! The structural half (every claim has exactly one level, every some-true
//! claim cites an authority) is enforced by `xtask check-conformance`. The
//! behavioural half --- that no `open` claim is asserted as established ---
//! is enforced by `xtask check-honesty`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde::Deserialize;

/// One of the three honesty levels (R2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum Level {
    SomeTrue,
    Build,
    Open,
}

impl Level {
    const fn as_str(self) -> &'static str {
        match self {
            Self::SomeTrue => "some-true",
            Self::Build => "build",
            Self::Open => "open",
        }
    }
}

#[derive(Debug, Deserialize)]
struct ClaimsFile {
    #[serde(default)]
    claim: Vec<Claim>,
}

#[derive(Debug, Deserialize)]
struct Claim {
    id: String,
    level: Level,
    #[serde(default)]
    witnesses: Vec<String>,
}

#[derive(Debug, Clone)]
struct Scenario {
    id: String,
    level: String,
    statement: String,
    suite: String,
    steps: Vec<String>,
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crates/mvm-conformance is two levels below the repo root")
        .to_path_buf()
}

fn load_claims(root: &Path) -> Vec<Claim> {
    let text = std::fs::read_to_string(root.join("model/claims.toml"))
        .expect("model/claims.toml must exist");
    toml::from_str::<ClaimsFile>(&text)
        .expect("model/claims.toml must parse")
        .claim
}

fn load_scenarios(root: &Path) -> Vec<Scenario> {
    let suites_dir = root.join("features/suites");
    let mut scenarios = Vec::new();
    let mut entries: Vec<_> = std::fs::read_dir(&suites_dir)
        .expect("features/suites must exist")
        .filter_map(Result::ok)
        .collect();
    entries.sort_by_key(|e| e.path());

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
    // Conformance IDs use the form MVM-SEC-01, MVM-NET-12, etc.
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
            // If the first tag is a conformance ID and the second is a level,
            // treat them as such. Otherwise the tags are cucumber runtime tags
            // (@wip, @live, @firecracker, @bundle).
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

#[test]
fn every_registered_claim_has_a_scenario_and_witness() {
    let root = repo_root();
    let claims = load_claims(&root);
    let scenarios = load_scenarios(&root);

    let by_scenario: BTreeMap<&str, &Scenario> =
        scenarios.iter().map(|s| (s.id.as_str(), s)).collect();

    let mut errors = Vec::new();

    for claim in &claims {
        let Some(scenario) = by_scenario.get(claim.id.as_str()) else {
            errors.push(format!(
                "R3: {} is registered but has no scenario in features/suites/",
                claim.id
            ));
            continue;
        };
        if scenario.level != claim.level.as_str() {
            errors.push(format!(
                "R2: {} is tagged `{}` in {} but `{}` in the register",
                claim.id,
                scenario.level,
                scenario.suite,
                claim.level.as_str()
            ));
        }
        if scenario.steps.is_empty() {
            errors.push(format!(
                "R3: scenario `{}` in {} has no steps",
                scenario.statement, scenario.suite
            ));
        }

        let mut unresolved = Vec::new();
        for witness in &claim.witnesses {
            let ok = match witness.split_once(':') {
                Some(("fn", name)) => resolve_fn(&root, name),
                Some(("ci", name)) => resolve_ci(&root, name),
                _ => false,
            };
            if !ok {
                unresolved.push(witness.clone());
            }
        }
        if !unresolved.is_empty() {
            errors.push(format!(
                "R3: {} has unresolved witnesses: {}",
                claim.id,
                unresolved.join(", ")
            ));
        }
    }

    let registered: BTreeSet<&str> = claims.iter().map(|c| c.id.as_str()).collect();
    for scenario in &scenarios {
        if scenario.id.is_empty() {
            // Untagged scenarios are allowed: they exercise product behaviour
            // that is not (yet) part of the formal claim register.
            continue;
        }
        if !registered.contains(scenario.id.as_str()) {
            errors.push(format!(
                "R3: scenario `{}` in {} names `{}`, which is not in the register",
                scenario.statement, scenario.suite, scenario.id
            ));
        }
    }

    assert!(
        errors.is_empty(),
        "conformance meta-gate failed:\n\n{}",
        errors.join("\n")
    );

    eprintln!(
        "R3 meta-gate: {} registered claims, {} scenarios",
        claims.len(),
        scenarios.len()
    );
}
