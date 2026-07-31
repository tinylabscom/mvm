//! `xtask check-claim-catalog`
//!
//! mvm's security claims (CLAUDE.md §"Security model") are each backed
//! by named tests and CI lanes. Prose drifts: a witness gets renamed,
//! the claim paragraph still names the old one, and nothing notices.
//! This lint makes the claims ledger table embedded in
//! `specs/adrs/001-microvm-security-posture.md` the machine-checked map
//! from each claim to its witnesses and fails when a named witness no
//! longer exists in the tree — the same "catalog can't outrun reality"
//! discipline an arc42 Ch.10 architecture doc enforces, scoped to what
//! is mechanically checkable.
//!
//! The table parser lives in `claims_ledger`, shared with
//! `check-mutation-witnesses`, which derives its mutation surface from
//! the same rows. This gate asserts a witness *exists*; that one asks
//! whether the witness can actually detect the property breaking.
//!
//! The ledger also carries degenerate claim frontmatter (status
//! `Shipped`, no gated phrases) so `check-no-overclaim` — which scans
//! `specs/adrs/**/*.md` for embedded claim frontmatter blocks — treats
//! it as an inert, already-shipped claim rather than choking on missing
//! frontmatter.

use crate::claims_ledger::{self, Row, Witness};
use anyhow::{Context, Result, bail};
use std::path::Path;

const KNOWN_STATUSES: [&str; 4] = ["Shipped", "Preview", "Planned", "Not-claimed"];

pub fn run(workspace: &Path) -> Result<()> {
    let rows = claims_ledger::load(workspace)?;

    let model_path = workspace.join("model").join("claims.toml");
    let model_toml = std::fs::read_to_string(&model_path)
        .with_context(|| format!("reading {}", model_path.display()))?;

    let mut errors: Vec<String> = Vec::new();
    structural_checks(&rows, &mut errors);
    ledger_witnesses_are_known_to_the_model(&rows, &model_toml, &mut errors);

    let mut needles: Vec<Needle> = Vec::new();
    for row in &rows {
        for w in &row.witnesses {
            needles.push(Needle::new(row.number, w));
        }
    }

    resolve_fn_needles(workspace, &mut needles)?;
    resolve_ci_needles(workspace, &mut needles)?;

    for n in &needles {
        if !n.found {
            errors.push(format!(
                "claim {}: witness `{}` not found in the tree",
                n.claim, n.token
            ));
        }
    }

    if !errors.is_empty() {
        for e in &errors {
            eprintln!("[error] {e}");
        }
        bail!(
            "check-claim-catalog: {} problem(s) in the claims ledger (specs/adrs/001-microvm-security-posture.md)",
            errors.len()
        );
    }

    eprintln!(
        "check-claim-catalog: clean ({} claims, {} witnesses verified)",
        rows.len(),
        needles.len()
    );
    Ok(())
}

struct Needle {
    claim: u32,
    token: String,
    /// The literal substring that must be present in the relevant files.
    search: String,
    kind: Kind,
    found: bool,
}

enum Kind {
    Fn,
    Ci,
}

impl Needle {
    fn new(claim: u32, w: &Witness) -> Self {
        let (search, kind) = match w {
            Witness::Fn(name) => (format!("fn {name}("), Kind::Fn),
            Witness::Ci(name) => (name.clone(), Kind::Ci),
        };
        Self {
            claim,
            token: w.token(),
            search,
            kind,
            found: false,
        }
    }
}

/// Every witness the ADR ledger names must also appear in
/// `model/claims.toml` for the same claim.
///
/// R1 makes the model the single source, so the ledger table is allowed to
/// be a representative anchor — a subset — but never to name a witness the
/// model has never heard of. Nothing else compares the two: this gate
/// resolves the ledger's witnesses against the tree, `check-conformance`
/// compares the model against `CONFORMANCE.md`, and
/// `check-mutation-witnesses` derives its surface from the ledger. A
/// witness added to the ADR table but not to the model was invisible to
/// all three, which is how two claims had already drifted.
fn ledger_witnesses_are_known_to_the_model(
    rows: &[Row],
    model_toml: &str,
    errors: &mut Vec<String>,
) {
    for row in rows {
        let id = format!("MVM-SEC-{:02}", row.number);
        let Some(model) = model_claim_witnesses(model_toml, &id) else {
            errors.push(format!(
                "claim {}: ledger row has no `[[claim]]` with id = \"{id}\" in model/claims.toml",
                row.number
            ));
            continue;
        };
        for w in &row.witnesses {
            let token = w.token();
            if !model.contains(&token) {
                errors.push(format!(
                    "claim {}: ledger names witness `{token}` that model/claims.toml does not \
                     list for {id}. The model is the single source — add it there first.",
                    row.number
                ));
            }
        }
    }
}

/// The `witnesses = [...]` tokens recorded for `id` in `model/claims.toml`.
///
/// Deliberately a small hand parser rather than a serde model: this gate
/// must keep working when the claim schema grows a field, and it only ever
/// needs one of them.
fn model_claim_witnesses(model_toml: &str, id: &str) -> Option<Vec<String>> {
    let needle = format!("id = \"{id}\"");
    let start = model_toml.find(&needle)?;
    let rest = &model_toml[start..];
    // Stop at the next claim so a missing `witnesses` key cannot silently
    // borrow the following claim's list.
    let scope_end = rest[needle.len()..]
        .find("[[claim]]")
        .map_or(rest.len(), |i| i + needle.len());
    let scope = &rest[..scope_end];
    let list_start = scope.find("witnesses = [")? + "witnesses = [".len();
    let list_end = list_start + scope[list_start..].find(']')?;
    Some(
        scope[list_start..list_end]
            .split(',')
            .map(|t| t.trim().trim_matches('"').to_string())
            .filter(|t| !t.is_empty())
            .collect(),
    )
}

fn structural_checks(rows: &[Row], errors: &mut Vec<String>) {
    let mut nums: Vec<u32> = rows.iter().map(|r| r.number).collect();
    nums.sort_unstable();
    for pair in nums.windows(2) {
        if pair[0] == pair[1] {
            errors.push(format!("duplicate claim number {}", pair[0]));
        }
    }
    // Claim numbers must form a contiguous 1..=N run — a gap means a
    // claim was dropped without renumbering, or a row is mis-typed.
    for (i, n) in nums.iter().enumerate() {
        let expected = u32::try_from(i + 1).unwrap_or(u32::MAX);
        if *n != expected {
            errors.push(format!(
                "claim numbers are not contiguous 1..={}: expected {expected}, found {n}",
                rows.len()
            ));
            break;
        }
    }
    for r in rows {
        if r.claim.is_empty() {
            errors.push(format!("claim {}: empty claim statement", r.number));
        }
        if r.authority.is_empty() {
            errors.push(format!("claim {}: empty authority column", r.number));
        }
        if r.witnesses.is_empty() {
            errors.push(format!("claim {}: no witnesses", r.number));
        }
        if !KNOWN_STATUSES.contains(&r.status.as_str()) {
            errors.push(format!(
                "claim {}: unknown status {:?} (expected one of {KNOWN_STATUSES:?})",
                r.number, r.status
            ));
        }
    }
}

fn resolve_fn_needles(workspace: &Path, needles: &mut [Needle]) -> Result<()> {
    if !needles.iter().any(|n| matches!(n.kind, Kind::Fn)) {
        return Ok(());
    }
    let crates = workspace.join("crates");
    claims_ledger::for_each_file(&crates, Some("rs"), &mut |_, content| {
        mark(needles, Kind::Fn, content);
    })?;
    Ok(())
}

fn resolve_ci_needles(workspace: &Path, needles: &mut [Needle]) -> Result<()> {
    if !needles.iter().any(|n| matches!(n.kind, Kind::Ci)) {
        return Ok(());
    }
    let workflows = workspace.join(".github").join("workflows");
    claims_ledger::for_each_file(&workflows, None, &mut |_, content| {
        let anchors = ci_anchors(content);
        for n in needles.iter_mut() {
            if matches!(n.kind, Kind::Ci) && !n.found {
                n.found = anchors.iter().any(|a| a == &n.search);
            }
        }
    })?;
    Ok(())
}

/// The exact names a `ci:` witness may resolve to: a job key, or a token
/// written in parentheses inside a step name.
///
/// This used to be a substring search over the whole file, so a witness
/// matched a mention in a comment as happily as a live job — `ci:fuzz`
/// resolved against the word "fuzz" anywhere in any workflow, including the
/// prose explaining why the job exists. A deleted job kept its witness green.
///
/// Matching is by equality, not containment, which is what makes a rename
/// visible. A job's descriptive `name:` — say `Supply chain — cargo-deny
/// (with a bracketed spec citation)` — deliberately does *not* anchor
/// `cargo-deny`; only the `cargo-deny:` key does. Renaming that key now
/// fails the gate even though the words survive in the display name.
///
/// The parenthesised form exists because the ledger points at steps as well
/// as jobs, and the repo already has a convention for it: a step backing a
/// claim carries its token in parentheses, as in
/// `Fuzz bounded DNS codec (fuzz-dns-codec)`.
fn ci_anchors(content: &str) -> Vec<String> {
    let mut anchors = Vec::new();
    let mut in_jobs = false;
    for line in content.lines() {
        if line.starts_with("jobs:") {
            in_jobs = true;
            continue;
        }
        if in_jobs && !line.trim().is_empty() && !line.starts_with(' ') {
            in_jobs = false;
        }
        let trimmed = line.trim_start();
        if trimmed.starts_with('#') {
            continue;
        }
        if in_jobs
            && let Some(key) = line.strip_prefix("  ")
            && !key.starts_with(' ')
            && let Some(name) = key.strip_suffix(':')
            && !name.is_empty()
            && name
                .chars()
                .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
        {
            anchors.push(name.to_string());
        }
        let step_name = trimmed
            .strip_prefix("- name:")
            .or_else(|| trimmed.strip_prefix("name:"));
        if let Some(rest) = step_name {
            anchors.extend(parenthesised_tokens(rest));
        }
    }
    anchors
}

/// Tokens written `(like-this)` inside a step name. Only bare
/// identifier-shaped contents count, so a bracketed spec citation with
/// spaces and punctuation contributes nothing.
fn parenthesised_tokens(name: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = name;
    while let Some(open) = rest.find('(') {
        let after = &rest[open + 1..];
        let Some(close) = after.find(')') else { break };
        let inner = &after[..close];
        if !inner.is_empty()
            && inner
                .chars()
                .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
        {
            out.push(inner.to_string());
        }
        rest = &after[close + 1..];
    }
    out
}

fn mark(needles: &mut [Needle], kind: Kind, content: &str) {
    let want = matches!(kind, Kind::Fn);
    for n in needles.iter_mut() {
        if matches!(n.kind, Kind::Fn) == want && !n.found && content.contains(&n.search) {
            n.found = true;
        }
    }
}

#[cfg(test)]
mod model_sync_tests {
    use super::*;

    const MODEL: &str = r#"
spec = "mvm/1"

[[claim]]
id = "MVM-SEC-01"
level = "build"
suite = "s"
statement = "st"
witnesses = [
    "fn:known_one",
    "ci:known-lane",
]

[[claim]]
id = "MVM-SEC-02"
level = "build"
suite = "s"
statement = "st"
witnesses = ["fn:other"]
"#;

    fn row(number: u32, witnesses: Vec<Witness>) -> Row {
        Row {
            number,
            claim: "c".into(),
            witnesses,
            authority: "a".into(),
            status: "Shipped".into(),
        }
    }

    #[test]
    fn ledger_witness_absent_from_the_model_is_rejected() {
        let rows = vec![row(1, vec![Witness::Fn("ghost".into())])];
        let mut errors = Vec::new();
        ledger_witnesses_are_known_to_the_model(&rows, MODEL, &mut errors);
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert!(errors[0].contains("fn:ghost"), "{}", errors[0]);
        assert!(errors[0].contains("MVM-SEC-01"), "{}", errors[0]);
    }

    #[test]
    fn ledger_subset_of_the_model_is_accepted() {
        // The ledger is documented as a representative anchor, so naming
        // fewer witnesses than the model is legal.
        let rows = vec![row(1, vec![Witness::Ci("known-lane".into())])];
        let mut errors = Vec::new();
        ledger_witnesses_are_known_to_the_model(&rows, MODEL, &mut errors);
        assert!(errors.is_empty(), "{errors:?}");
    }

    #[test]
    fn ledger_row_with_no_model_claim_is_rejected() {
        let rows = vec![row(9, vec![Witness::Fn("known_one".into())])];
        let mut errors = Vec::new();
        ledger_witnesses_are_known_to_the_model(&rows, MODEL, &mut errors);
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert!(errors[0].contains("MVM-SEC-09"), "{}", errors[0]);
    }

    #[test]
    fn witness_lookup_does_not_borrow_the_next_claims_list() {
        // A claim whose own `witnesses` key is missing must not silently
        // pick up the following claim's list.
        let model = r#"
[[claim]]
id = "MVM-SEC-01"
level = "build"

[[claim]]
id = "MVM-SEC-02"
witnesses = ["fn:belongs_to_two"]
"#;
        assert_eq!(model_claim_witnesses(model, "MVM-SEC-01"), None);
        assert_eq!(
            model_claim_witnesses(model, "MVM-SEC-02"),
            Some(vec!["fn:belongs_to_two".to_string()])
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claims_ledger::{extract_ledger_section, parse_rows};

    #[test]
    fn structural_flags_noncontiguous_and_bad_status() {
        let src = "\
| # | Claim | Witnesses | Authority | Status |
|---|-------|-----------|-----------|--------|
| 1 | a | fn:x | auth | Shipped |
| 3 | b | fn:y | auth | Cheese |
";
        let rows = parse_rows(src).unwrap();
        let mut errors = Vec::new();
        structural_checks(&rows, &mut errors);
        assert!(errors.iter().any(|e| e.contains("not contiguous")));
        assert!(errors.iter().any(|e| e.contains("unknown status")));
    }

    #[test]
    fn structural_flags_duplicate_numbers() {
        let src = "\
| # | Claim | Witnesses | Authority | Status |
|---|-------|-----------|-----------|--------|
| 1 | a | fn:x | auth | Shipped |
| 1 | b | fn:y | auth | Shipped |
";
        let rows = parse_rows(src).unwrap();
        let mut errors = Vec::new();
        structural_checks(&rows, &mut errors);
        assert!(
            errors
                .iter()
                .any(|e| e.contains("duplicate claim number 1"))
        );
    }

    #[test]
    fn fn_needle_resolves_against_a_source_tree() {
        let tmp = tempfile::tempdir().unwrap();
        let src_dir = tmp.path().join("crates").join("demo").join("src");
        std::fs::create_dir_all(&src_dir).unwrap();
        std::fs::write(
            src_dir.join("lib.rs"),
            "pub fn foo_one() {}\n#[test]\nfn bar_two() {}\n",
        )
        .unwrap();

        let mut needles = vec![
            Needle::new(1, &Witness::Fn("foo_one".into())),
            Needle::new(1, &Witness::Fn("missing_fn".into())),
        ];
        resolve_fn_needles(tmp.path(), &mut needles).unwrap();
        assert!(needles[0].found, "foo_one should resolve");
        assert!(!needles[1].found, "missing_fn should not resolve");
    }

    #[test]
    fn ci_needle_resolves_against_workflow_files() {
        let tmp = tempfile::tempdir().unwrap();
        let wf = tmp.path().join(".github").join("workflows");
        std::fs::create_dir_all(&wf).unwrap();
        std::fs::write(wf.join("ci.yml"), "jobs:\n  my-lane:\n    name: My Lane\n").unwrap();

        let mut needles = vec![
            Needle::new(1, &Witness::Ci("my-lane".into())),
            Needle::new(1, &Witness::Ci("ghost-lane".into())),
        ];
        resolve_ci_needles(tmp.path(), &mut needles).unwrap();
        assert!(needles[0].found);
        assert!(!needles[1].found);
    }

    #[test]
    fn extract_ledger_section_slices_between_markers() {
        let source = "# ADR\n\nsome prose\n\n<!-- claims-catalog:begin -->\nTABLE HERE\n<!-- claims-catalog:end -->\n\nmore prose\n";
        let section = extract_ledger_section(source).unwrap();
        assert_eq!(section, "\nTABLE HERE\n");
    }

    #[test]
    fn extract_ledger_section_ignores_unrelated_tables_outside_markers() {
        let source = "\
| ID | STRIDE | Adv. | Threat | Mitigation |
| --- | --- | --- | --- | --- |
| X-S1 | S | G | some threat | some mitigation |

<!-- claims-catalog:begin -->
| # | Claim | Witnesses | Authority | Status |
|---|-------|-----------|-----------|--------|
| 1 | First claim | fn:foo_one | seccomp | Shipped |
<!-- claims-catalog:end -->
";
        let section = extract_ledger_section(source).unwrap();
        let rows = parse_rows(section).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].number, 1);
    }

    #[test]
    fn extract_ledger_section_errors_without_markers() {
        assert!(extract_ledger_section("no markers here").is_err());
    }
}

#[cfg(test)]
mod ci_anchor_tests {
    use super::*;

    const WORKFLOW: &str = r#"name: Security
# A comment mentioning ghost-job and fuzz-in-prose.
on:
  schedule:
    - cron: "17 4 * * *"
jobs:
  cargo-deny:
    name: Supply chain — cargo-deny
    steps:
      - name: cargo deny check
        run: cargo deny check
  fuzz:
    name: Fuzz — parsers
    steps:
      - name: Fuzz bounded DNS codec (fuzz-dns-codec)
        run: cargo fuzz run fuzz_dns_codec
"#;

    #[test]
    fn a_job_key_is_an_anchor() {
        let a = ci_anchors(WORKFLOW);
        assert!(a.iter().any(|x| x == "cargo-deny"), "{a:?}");
        assert!(a.iter().any(|x| x == "fuzz"), "{a:?}");
    }

    #[test]
    fn a_parenthesised_step_token_is_an_anchor() {
        assert!(ci_anchors(WORKFLOW).iter().any(|x| x == "fuzz-dns-codec"));
    }

    /// A job's descriptive name must not anchor its key. This is what makes
    /// renaming `cargo-deny:` visible even though the words survive in
    /// `name: Supply chain — cargo-deny`.
    #[test]
    fn a_descriptive_name_does_not_anchor_the_key() {
        let a = ci_anchors("jobs:\n  renamed:\n    name: Supply chain — cargo-deny (ADR-001)\n");
        assert!(a.iter().any(|x| x == "renamed"), "{a:?}");
        assert!(
            !a.iter().any(|x| x == "cargo-deny"),
            "the display name must not stand in for the key: {a:?}"
        );
    }

    /// Only identifier-shaped parentheticals count, so citation text is not
    /// mistaken for a witness token.
    #[test]
    fn non_identifier_parentheticals_are_ignored() {
        assert!(parenthesised_tokens("Supply chain (ADR-001 §W5.2)").is_empty());
        assert_eq!(
            parenthesised_tokens("Codec (fuzz-dns-codec)"),
            vec!["fuzz-dns-codec".to_string()]
        );
    }

    /// The whole point. A witness naming a job that does not exist used to
    /// resolve against the word appearing in a comment.
    #[test]
    fn a_comment_mention_is_not_an_anchor() {
        let a = ci_anchors(WORKFLOW);
        assert!(
            !a.iter().any(|x| x.contains("ghost-job")),
            "a comment must not anchor a witness: {a:?}"
        );
    }

    /// `run:` bodies are not anchors either — otherwise renaming a step but
    /// keeping its command would still look witnessed.
    #[test]
    fn a_run_body_is_not_an_anchor() {
        let a = ci_anchors(WORKFLOW);
        assert!(!a.iter().any(|x| x.starts_with("cargo fuzz run")), "{a:?}");
    }

    /// Top-level keys that merely sit at some indent are not job keys.
    #[test]
    fn only_keys_inside_jobs_count() {
        let a = ci_anchors(WORKFLOW);
        assert!(!a.iter().any(|x| x == "schedule"), "{a:?}");
    }
}
