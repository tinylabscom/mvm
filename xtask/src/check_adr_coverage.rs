//! `cargo xtask check-adr-coverage` — surface architectural decisions
//! that have no in-code references.
//!
//! ADR coverage is a soft proxy for "the decision is actually
//! implemented, not just documented." An ADR with zero `ADR-NNN`
//! references in source/tests/docs is either stale (decision was
//! reversed and the doc was forgotten), unimplemented (decision
//! was made but the code never landed), or genuinely
//! reference-free (e.g. a process ADR that doesn't touch code).
//! All three are worth surfacing for review. ADR bodies do not increment that
//! coverage count, but their ADR-number and section-qualified references are
//! still checked for existence.
//!
//! Output format mirrors `cargo deny` for grep-ability and CI
//! integration. (Example shapes; this comment deliberately splits
//! the ADR prefix so the scanner doesn't pick up the example as a
//! real reference.)
//!
//! ```text
//! [error] <ADR>-042 referenced in code but the file
//!         specs/adrs/042-*.md does not exist
//! [warn]  <ADR>-007 (slug) — 0 in-code references
//! [info]  <ADR>-002 (slug) — 312 in-code references
//! ```
//!
//! Exit code:
//!   - 0 → all referenced ADRs exist; "info" lines may still appear.
//!   - 1 → at least one reference points at a non-existent ADR.
//!     Bare "warn" (0 references on an existing ADR) is *not* a
//!     hard fail — a process ADR may legitimately not appear in
//!     code. CI lanes that want a strict mode can grep for
//!     `[warn]` and fail externally.

use anyhow::{Context, Result};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

/// ADR file pattern: `NNN-slug.md` where NNN is 3+ digits.
/// `specs/adrs/013-libkrun-libkrun-microvm-nix-pivot.md` →
/// `(13, "libkrun-libkrun-microvm-nix-pivot")`.
fn parse_adr_filename(name: &str) -> Option<(u32, String)> {
    let stem = name.strip_suffix(".md")?;
    let (num, rest) = stem.split_once('-')?;
    let n: u32 = num.parse().ok()?;
    Some((n, rest.to_string()))
}

/// In-code reference pattern: `ADR-N`, `ADR-NN`, or `ADR-NNN`.
/// Matches `ADR-001`, `ADR-007`, `ADR-7`, etc. Case-sensitive on
/// `ADR` so we don't pick up `adr-`-prefixed filenames.
///
/// mvm ADR numbers are 1–3 digits. Cross-repo references like
/// `ADR-0023` (the mvmd convention is 4-digit) are *not* mvm ADRs;
/// matching those would surface false-positive "broken refs" against
/// mvm's `specs/adrs/` directory. Cap the digit run at 3 to reject
/// the 4-digit mvmd form cleanly.
fn extract_adr_refs(body: &str) -> Vec<u32> {
    let mut out = Vec::new();
    let bytes = body.as_bytes();
    let mut i = 0;
    while i + 4 < bytes.len() {
        if &bytes[i..i + 4] == b"ADR-" {
            let mut j = i + 4;
            while j < bytes.len() && bytes[j].is_ascii_digit() {
                j += 1;
            }
            let width = j - (i + 4);
            // Reject zero-digit (`ADR-` followed by no digit) and 4+
            // digit runs (mvmd's `ADR-NNNN` form is not an mvm ADR).
            if (1..=3).contains(&width)
                && let Ok(s) = std::str::from_utf8(&bytes[i + 4..j])
                && let Ok(n) = s.parse::<u32>()
            {
                out.push(n);
            }
            i = j;
        } else {
            i += 1;
        }
    }
    out
}

/// Scan a directory tree for `ADR-N` references, returning a count
/// keyed by ADR number. Skips:
///   - `target/`, `node_modules/`, `.git/` (build/dependency dirs)
///   - `specs/adrs/` (the ADRs themselves; self-references are
///     bookkeeping, not coverage)
///   - files larger than 1 MiB (build artifacts the workspace may
///     have committed, e.g. generated docs)
fn scan_for_refs(root: &Path) -> Result<BTreeMap<u32, usize>> {
    let mut counts: BTreeMap<u32, usize> = BTreeMap::new();
    let skip_dirs: BTreeSet<&str> = ["target", "node_modules", ".git", "public"]
        .iter()
        .copied()
        .collect();
    let adrs_dir = root.join("specs/adrs");

    visit(&root.to_path_buf(), &mut counts, &skip_dirs, &adrs_dir)?;
    Ok(counts)
}

/// Scan only ADR bodies for references used by other ADRs.
///
/// These references participate in the existence check but deliberately do
/// not count as implementation coverage: an ADR citing itself or another ADR
/// is documentation, not evidence that the decision is present in code.
fn scan_adr_refs(root: &Path) -> Result<BTreeMap<u32, usize>> {
    let dir = root.join("specs/adrs");
    let mut refs = BTreeMap::new();
    if !dir.exists() {
        return Ok(refs);
    }
    for entry in fs::read_dir(&dir).with_context(|| format!("reading {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        if !entry.file_type()?.is_file()
            || path.extension().and_then(|extension| extension.to_str()) != Some("md")
        {
            continue;
        }
        let body = fs::read_to_string(&path)
            .with_context(|| format!("reading ADR references from {}", path.display()))?;
        let own_number = path
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(parse_adr_filename)
            .map(|(number, _)| number);
        for number in extract_adr_refs(&body) {
            if own_number == Some(number) {
                continue;
            }
            *refs.entry(number).or_insert(0) += 1;
        }
    }
    Ok(refs)
}

fn visit(
    dir: &PathBuf,
    counts: &mut BTreeMap<u32, usize>,
    skip_dirs: &BTreeSet<&str>,
    adrs_dir: &Path,
) -> Result<()> {
    let entries = fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))?;
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;
        let name = entry.file_name().to_string_lossy().to_string();

        if file_type.is_dir() {
            if skip_dirs.contains(name.as_str()) || name.starts_with('.') {
                continue;
            }
            // Self-references inside specs/adrs/ would inflate the
            // count — every ADR refers to itself in its own body.
            if path == adrs_dir {
                continue;
            }
            visit(&path, counts, skip_dirs, adrs_dir)?;
            continue;
        }

        if !file_type.is_file() {
            continue;
        }

        // A changelog records what a commit message said, not what exists
        // now. It is generated from git history, so a subject naming an ADR
        // that was renumbered or never landed reappears on the next release
        // however many times the line is edited out.
        if path.file_name().and_then(|n| n.to_str()) == Some("CHANGELOG.md") {
            continue;
        }

        // Cheap pre-filter on extension. Binary files (images,
        // lockfiles, etc.) can't carry meaningful ADR refs even if
        // they happen to contain the byte sequence.
        let scan = matches!(
            path.extension().and_then(|e| e.to_str()),
            Some(
                "rs" | "md"
                    | "toml"
                    | "yaml"
                    | "yml"
                    | "nix"
                    | "json"
                    | "txt"
                    | "sh"
                    | "py"
                    | "ts"
                    | "tsx"
                    | "js"
                    | "jsx"
                    | "html"
            )
        );
        if !scan {
            continue;
        }
        let meta = entry.metadata()?;
        if meta.len() > 1_048_576 {
            continue;
        }

        let body = match fs::read_to_string(&path) {
            Ok(s) => s,
            Err(_) => continue, // not UTF-8; skip
        };
        for n in extract_adr_refs(&body) {
            *counts.entry(n).or_insert(0) += 1;
        }
    }
    Ok(())
}

/// Discover ADRs in `specs/adrs/` and `public/src/content/docs/contributing/adr/`.
/// Returns a map `number → slug`. The public-docs directory carries a
/// handful of user-facing ADRs (currently 001 + 013) that are NOT
/// duplicated under `specs/adrs/`; discovering both directories means
/// references to those numbers resolve cleanly without forcing every
/// public ADR to also live in `specs/adrs/`.
fn discover_adrs(root: &Path) -> Result<BTreeMap<u32, String>> {
    let dirs = [
        root.join("specs/adrs"),
        root.join("public/src/content/docs/contributing/adr"),
    ];
    let mut out = BTreeMap::new();
    for dir in &dirs {
        if !dir.exists() {
            continue;
        }
        for entry in fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().to_string();
            if let Some((n, slug)) = parse_adr_filename(&name) {
                // First-wins so `specs/adrs/` takes precedence when
                // an ADR number happens to exist in both directories
                // (a future drift signal worth catching, but not
                // something this lint should hard-fail on).
                out.entry(n).or_insert(slug);
            }
        }
    }
    Ok(out)
}

fn discover_adr_paths(root: &Path) -> Result<BTreeMap<u32, PathBuf>> {
    let dirs = [
        root.join("specs/adrs"),
        root.join("public/src/content/docs/contributing/adr"),
    ];
    let mut out = BTreeMap::new();
    for dir in &dirs {
        if !dir.exists() {
            continue;
        }
        for entry in fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().to_string();
            if let Some((number, _)) = parse_adr_filename(&name) {
                out.entry(number).or_insert_with(|| entry.path());
            }
        }
    }
    Ok(out)
}

#[derive(Debug, Eq, PartialEq)]
struct AdrSectionRef {
    source: String,
    number: u32,
    section: String,
}

fn extract_adr_section_refs(source: &str, body: &str) -> Vec<AdrSectionRef> {
    let mut refs = Vec::new();
    let mut offset = 0usize;
    while let Some(found) = body[offset..].find("ADR-") {
        let digits_start = offset + found + 4;
        let digits_end = body[digits_start..]
            .find(|character: char| !character.is_ascii_digit())
            .map_or(body.len(), |relative| digits_start + relative);
        let width = digits_end.saturating_sub(digits_start);
        if !(1..=3).contains(&width) {
            offset = digits_end.max(digits_start + 1);
            continue;
        }
        let Ok(number) = body[digits_start..digits_end].parse::<u32>() else {
            offset = digits_end.max(digits_start + 1);
            continue;
        };
        let after_number = body[digits_end..].trim_start();
        let Some(after_marker) = after_number.strip_prefix('§') else {
            offset = digits_end;
            continue;
        };
        let after_marker = after_marker.trim_start();
        let section = if let Some(quoted) = after_marker.strip_prefix('"') {
            quoted.find('"').map(|end| quoted[..end].trim().to_string())
        } else {
            let end = after_marker
                .find(|character: char| {
                    !(character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-'))
                })
                .unwrap_or(after_marker.len());
            let value = after_marker[..end].trim_end_matches(['.', '_', '-']);
            (!value.is_empty()).then(|| value.to_string())
        };
        if let Some(section) = section
            && !section.is_empty()
        {
            refs.push(AdrSectionRef {
                source: source.to_string(),
                number,
                section,
            });
        }
        offset = digits_end;
    }
    refs
}

fn scan_adr_section_refs(root: &Path) -> Result<Vec<AdrSectionRef>> {
    let dir = root.join("specs/adrs");
    let mut refs = Vec::new();
    if !dir.exists() {
        return Ok(refs);
    }
    for entry in fs::read_dir(&dir).with_context(|| format!("reading {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        if !entry.file_type()?.is_file()
            || path.extension().and_then(|extension| extension.to_str()) != Some("md")
        {
            continue;
        }
        let body = fs::read_to_string(&path)
            .with_context(|| format!("reading ADR section references from {}", path.display()))?;
        let source = path.strip_prefix(root).unwrap_or(&path).to_string_lossy();
        refs.extend(extract_adr_section_refs(&source, &body));
    }
    Ok(refs)
}

fn normalized_heading(value: &str) -> String {
    value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn section_resolves(body: &str, section: &str) -> bool {
    let needle = normalized_heading(section);
    !needle.is_empty()
        && body.lines().any(|line| {
            let trimmed = line.trim_start();
            let heading = trimmed.trim_start_matches('#').trim_start();
            trimmed.starts_with('#') && normalized_heading(heading).starts_with(&needle)
        })
}

/// Numbers whose ADR file doesn't (yet) exist but whose in-code
/// references are intentional. Each entry pairs the ADR number with a
/// one-line rationale that appears in the lint output, so future
/// auditors can see why the reference was tolerated.
///
/// Adding a new entry here should always be paired with a follow-up
/// to either (a) write the real ADR, (b) replace references with a
/// successor ADR, or (c) delete the references entirely. The
/// allowlist exists to keep the CI signal clean while that work is
/// sequenced, not to make broken references permanent.
const KNOWN_MISSING_ADRS: &[(u32, &str)] = &[
    (
        106,
        "cited by ADR-001's claim-3 row for the block+ext4 dm-verity scoping; the file was never \
         written or was deleted — the scoping rationale must move into ADR-001 itself (#3318)",
    ),
    (
        107,
        "cited by ADR-001 as the sole authority for why virtiofs-root does not witness claim 3; \
         the file does not exist, so a numbered claim's backend exclusion rests on nothing (#3318)",
    ),
    (
        9,
        "function-call entrypoints — split across ADR-005/008/010/011 during the function-service \
         refactor; references to the original ADR-009 number are historical",
    ),
    (
        15,
        "legacy plan-era ADR reference; no canonical doc shipped — replace refs with the relevant \
         ADR-008/028/029 (encryption layering) or delete during a follow-up sweep",
    ),
    (
        16,
        "single legacy ref; superseded by the encryption-substrate ADRs (042 / 008) — delete in a \
         follow-up sweep",
    ),
    (
        17,
        "legacy refs predating the cross-platform-strategy split — successor is ADR-009",
    ),
    (
        18,
        "47 refs to a legacy provider-CLI concept — successor is ADR-006 (mvm-provider-cli-contract)",
    ),
    (
        19,
        "legacy refs; no canonical doc shipped — follow-up sweep should replace with the relevant \
         function-service ADR (008/010) or delete",
    ),
    (
        20,
        "legacy refs to a runtime-overlay precursor — successor is ADR-005 (runtime-overlay-composition, folded into the function-call-entrypoints canonical)",
    ),
    (
        26,
        "single legacy ref to an unwritten ADR — delete or rewrite in a follow-up",
    ),
    (
        28,
        "legacy refs to an unwritten ADR; concept folded into ADR-008 (iroh-aware encryption and \
         encryption substrate, post-consolidation)",
    ),
    (29, "single legacy ref; concept folded into ADR-008"),
    (
        36,
        "AI-agent threat model — flagged TBD in the SOC 2 controls mapping under ADR-001 \
         §\"Compliance mapping\"; ADR pending the agent threat model write-up",
    ),
    (
        999,
        "test literal inside this xtask's own unit tests (extract_adr_refs_finds_padded_and_unpadded) \
         — the scanner sees its own test fixture",
    ),
];

const KNOWN_MISSING_ADR_SECTIONS: &[(u32, &str, &str)] = &[
    (
        1,
        "w2",
        "legacy security-workstream label; ADR-001 has no matching heading (#3318)",
    ),
    (
        1,
        "w22",
        "legacy security-workstream label; ADR-001 has no matching heading (#3318)",
    ),
    (
        1,
        "w3",
        "legacy security-workstream label; ADR-001 has no matching heading (#3318)",
    ),
    (
        1,
        "w41",
        "legacy security-workstream label; ADR-001 has no matching heading (#3318)",
    ),
    (
        1,
        "w43",
        "legacy security-workstream label; ADR-001 has no matching heading (#3318)",
    ),
    (
        1,
        "w5",
        "legacy security-workstream label; ADR-001 has no matching heading (#3318)",
    ),
    (
        1,
        "w51",
        "legacy security-workstream label; ADR-001 has no matching heading (#3318)",
    ),
    (
        1,
        "w52",
        "legacy security-workstream label; ADR-001 has no matching heading (#3318)",
    ),
];

/// Run the check; print findings; return Err on any `[error]` line.
pub fn run(workspace: &Path) -> Result<()> {
    let adrs = discover_adrs(workspace)?;
    let adr_paths = discover_adr_paths(workspace)?;
    let refs = scan_for_refs(workspace)?;
    let mut existence_refs = refs.clone();
    for (number, count) in scan_adr_refs(workspace)? {
        *existence_refs.entry(number).or_insert(0) += count;
    }

    let mut errors = 0usize;
    let known_missing: BTreeMap<u32, &'static str> = KNOWN_MISSING_ADRS.iter().copied().collect();
    let known_missing_sections: BTreeMap<(u32, &'static str), &'static str> =
        KNOWN_MISSING_ADR_SECTIONS
            .iter()
            .map(|(number, section, reason)| ((*number, *section), *reason))
            .collect();

    // 1. References to non-existent ADRs (typos or stale refs).
    //    Allowlisted numbers emit `[warn]` with the rationale; the
    //    rest are hard errors.
    for (&n, &count) in &existence_refs {
        if adrs.contains_key(&n) {
            continue;
        }
        if let Some(reason) = known_missing.get(&n) {
            println!(
                "[warn]  ADR-{n:03} referenced {count}x; allowlisted as known-missing: {reason}"
            );
        } else {
            println!(
                "[error] ADR-{n:03} referenced {count}x in code, but \
                 specs/adrs/{n:03}-*.md does not exist"
            );
            errors += 1;
        }
    }

    // 2. Section-qualified ADR references must name a heading in the target
    //    document. A valid ADR number with a fabricated section is still a
    //    broken citation.
    for reference in scan_adr_section_refs(workspace)? {
        let Some(path) = adr_paths.get(&reference.number) else {
            continue;
        };
        let body = fs::read_to_string(path)
            .with_context(|| format!("reading ADR headings from {}", path.display()))?;
        if !section_resolves(&body, &reference.section) {
            let normalized = normalized_heading(&reference.section);
            if let Some(reason) =
                known_missing_sections.get(&(reference.number, normalized.as_str()))
            {
                println!(
                    "[warn]  {} cites ADR-{:03} §{}; allowlisted as known-missing: {}",
                    reference.source, reference.number, reference.section, reason
                );
                continue;
            }
            println!(
                "[error] {} cites ADR-{:03} §{}, but that ADR has no matching heading",
                reference.source, reference.number, reference.section
            );
            errors += 1;
        }
    }

    // 3. ADRs with zero in-code references. Soft warning — process
    //    ADRs may legitimately have zero code mentions.
    for (&n, slug) in adrs.iter() {
        match refs.get(&n).copied().unwrap_or(0) {
            0 => println!("[warn]  ADR-{n:03} ({slug}) — 0 in-code references"),
            c => println!("[info]  ADR-{n:03} ({slug}) — {c} in-code references"),
        }
    }

    println!(
        "\nADRs discovered: {}; ADRs referenced: {}; broken refs: {errors}",
        adrs.len(),
        refs.iter().filter(|(n, _)| adrs.contains_key(n)).count(),
    );

    if errors > 0 {
        anyhow::bail!(
            "check-adr-coverage: {errors} broken ADR reference{}",
            if errors == 1 { "" } else { "s" }
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_adr_filename_picks_number_and_slug() {
        assert_eq!(
            parse_adr_filename("002-microvm-security-posture.md"),
            Some((2, "microvm-security-posture".to_string()))
        );
        assert_eq!(
            parse_adr_filename("013-libkrun-libkrun-microvm-nix-pivot.md"),
            Some((13, "libkrun-libkrun-microvm-nix-pivot".to_string()))
        );
    }

    #[test]
    fn parse_adr_filename_rejects_non_adrs() {
        assert_eq!(parse_adr_filename("README.md"), None);
        assert_eq!(parse_adr_filename("not-a-number-slug.md"), None);
        assert_eq!(parse_adr_filename("0xx-bogus.md"), None);
    }

    #[test]
    fn extract_adr_refs_finds_padded_and_unpadded() {
        let body = "See ADR-007 for the pivot; ADR-2 the security \
                    posture; ADR-012 for CI policy.";
        let refs = extract_adr_refs(body);
        assert_eq!(refs, vec![7, 2, 12]);
    }

    #[test]
    fn extract_adr_refs_handles_no_matches() {
        assert!(extract_adr_refs("no decisions referenced here").is_empty());
        assert!(extract_adr_refs("adr-002 lowercase shouldn't match").is_empty());
    }

    #[test]
    fn extract_adr_refs_handles_section_suffix() {
        // ADR refs in code often carry a section suffix; our extractor
        // pulls just the number.
        let body = "ADR-001 §W4.3 / ADR-007§\"Boot budget\"";
        let refs = extract_adr_refs(body);
        assert_eq!(refs, vec![1, 7]);
    }

    #[test]
    fn extract_adr_refs_rejects_four_digit_mvmd_form() {
        // mvmd uses 4-digit ADR numbers (e.g. `ADR-0023` for mvmd's
        // host-services-delegation ADR). Cross-repo references to
        // mvmd ADRs are NOT mvm ADRs and must not be reported as
        // broken mvm references.
        let body = "see mvmd ADR-0023 for the cross-VM trust model";
        let refs = extract_adr_refs(body);
        assert!(refs.is_empty(), "4-digit ADR refs must be skipped");

        // Mixed: mvm ADR-007 alongside mvmd ADR-0007 — only the
        // 3-digit mvm form should land in the output.
        let mixed = "ADR-007 plus mvmd ADR-0007 in the same line";
        let refs = extract_adr_refs(mixed);
        assert_eq!(refs, vec![7]);
    }

    /// Build the literal `ADR-N` token at runtime so this source file
    /// doesn't itself trip the workspace `check-adr-coverage` pass.
    /// The xtask command scans the workspace including this very
    /// file; a literal `ADR-999` here would look like a real broken
    /// reference and fail CI.
    fn adr_token(n: u32) -> String {
        format!("{}-{:03}", "ADR", n)
    }

    #[test]
    fn run_against_fixture_workspace() {
        // Build a tiny fixture: one existing ADR, one source file
        // referencing it, and a second source file referencing a
        // non-existent ADR.
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = tmp.path();
        std::fs::create_dir_all(root.join("specs/adrs")).unwrap();
        let adr1 = adr_token(1);
        std::fs::write(
            root.join("specs/adrs/001-fixture.md"),
            format!("# {adr1} — fixture\n"),
        )
        .unwrap();
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(root.join("src/a.rs"), format!("// see {adr1}\n")).unwrap();
        let adr_missing = adr_token(998);
        std::fs::write(
            root.join("src/b.rs"),
            format!("// see {adr_missing} (does not exist)\n"),
        )
        .unwrap();

        let result = run(root);
        assert!(result.is_err(), "broken ref must surface as Err");
    }

    #[test]
    fn a_missing_adr_referenced_only_by_an_adr_is_still_an_error() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = tmp.path();
        std::fs::create_dir_all(root.join("specs/adrs")).unwrap();
        let adr1 = adr_token(1);
        let adr_missing = adr_token(998);
        std::fs::write(
            root.join("specs/adrs/001-fixture.md"),
            format!("# {adr1}\n\nThis decision depends on {adr_missing}.\n"),
        )
        .unwrap();

        assert!(
            run(root).is_err(),
            "an ADR must not be allowed to cite a missing ADR"
        );
    }

    #[test]
    fn adr_references_are_existence_evidence_not_implementation_coverage() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = tmp.path();
        std::fs::create_dir_all(root.join("specs/adrs")).unwrap();
        let adr1 = adr_token(1);
        let adr2 = adr_token(2);
        std::fs::write(
            root.join("specs/adrs/001-fixture.md"),
            format!("# {adr1}\n\nThis decision depends on {adr2}.\n"),
        )
        .unwrap();
        std::fs::write(
            root.join("specs/adrs/002-fixture.md"),
            format!("# {adr2}\n"),
        )
        .unwrap();

        assert!(scan_for_refs(root).unwrap().is_empty());
        assert_eq!(scan_adr_refs(root).unwrap().get(&2), Some(&1));
        run(root).expect("an ADR-to-ADR reference to an existing ADR is valid");
    }

    #[test]
    fn an_adr_section_reference_must_name_a_real_heading() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = tmp.path();
        std::fs::create_dir_all(root.join("specs/adrs")).unwrap();
        let adr1 = adr_token(1);
        let adr2 = adr_token(2);
        std::fs::write(
            root.join("specs/adrs/001-fixture.md"),
            format!("# {adr1}\n\nSee {adr2} §Missing.\n"),
        )
        .unwrap();
        std::fs::write(
            root.join("specs/adrs/002-fixture.md"),
            format!("# {adr2}\n\n## Present\n"),
        )
        .unwrap();

        assert!(run(root).is_err(), "a missing section must fail the gate");
    }

    #[test]
    fn quoted_and_symbolic_adr_sections_resolve() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = tmp.path();
        std::fs::create_dir_all(root.join("specs/adrs")).unwrap();
        let adr1 = adr_token(1);
        let adr2 = adr_token(2);
        std::fs::write(
            root.join("specs/adrs/001-fixture.md"),
            format!("# {adr1}\n\nSee {adr2} §P1 and {adr2} §\"Named boundary\".\n"),
        )
        .unwrap();
        std::fs::write(
            root.join("specs/adrs/002-fixture.md"),
            format!("# {adr2}\n\n## P1 — First property\n\n## Named boundary\n"),
        )
        .unwrap();

        run(root).expect("real ADR section headings resolve");
    }

    /// A changelog is generated from commit subjects. One naming an ADR that
    /// was renumbered or never landed is a fact about the commit, not a claim
    /// the ADR exists — and editing the line out only holds until the next
    /// release regenerates it.
    #[test]
    fn a_changelog_reference_to_a_missing_adr_is_not_a_broken_ref() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = tmp.path();
        std::fs::create_dir_all(root.join("specs/adrs")).unwrap();
        let adr1 = adr_token(1);
        std::fs::write(
            root.join("specs/adrs/001-fixture.md"),
            format!("# {adr1} — fixture\n"),
        )
        .unwrap();
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(root.join("src/a.rs"), format!("// see {adr1}\n")).unwrap();

        let adr_missing = adr_token(998);
        std::fs::write(
            root.join("CHANGELOG.md"),
            format!("- **adr**: {adr_missing} something that never landed\n"),
        )
        .unwrap();

        run(root).expect("a changelog citing a missing ADR must not fail the gate");

        // The exemption is the changelog, not the number: the same reference
        // from source is still a broken ref.
        std::fs::write(root.join("src/b.rs"), format!("// see {adr_missing}\n")).unwrap();
        assert!(
            run(root).is_err(),
            "the same missing ADR cited from source must still fail"
        );
    }

    #[test]
    fn run_against_clean_fixture_succeeds() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = tmp.path();
        std::fs::create_dir_all(root.join("specs/adrs")).unwrap();
        let adr1 = adr_token(1);
        std::fs::write(
            root.join("specs/adrs/001-fixture.md"),
            format!("# {adr1} — fixture\n"),
        )
        .unwrap();
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(root.join("src/a.rs"), format!("// see {adr1}\n")).unwrap();

        run(root).expect("clean fixture must pass");
    }
}
