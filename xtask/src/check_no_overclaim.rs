//! `xtask check-no-overclaim`
//!
//! Refuses any user-facing repo text that uses phrases declared
//! "gated" by a claim whose status is not `Shipped`.
//!
//! Claim frontmatter blocks live embedded inside ADR bodies under
//! `specs/adrs/**/*.md` (each consolidated claim doc keeps its
//! original YAML frontmatter, wrapped in a "consolidated from the
//! former per-claim doc" section). The lint scans every ADR file
//! for `---`-delimited blocks, skips blocks that don't declare a
//! `claim:` key (an ADR's own title/status/date frontmatter, or an
//! example inside a fenced code block), parses the rest as claim
//! frontmatter, and builds a `phrase → (claim, status, exempt_paths)`
//! index. It then walks the workspace, scans `.md` and `.rs` files,
//! and reports any path that contains a gated phrase and is not in
//! the claim's `exempt_paths`.
//!
//! A claim with status `Shipped` admits its phrases everywhere — the
//! gate disengages. A claim with status `Planned` or `Preview` keeps
//! its phrases off user-facing surface. A claim with status
//! `Not-claimed` is treated like `Planned`: phrases stay gated.
//!
//! Default-skipped paths (independent of claim exempt_paths):
//! `target/`, `.git/`, `.worktrees/`, `node_modules/`, `result/`,
//! `result-*`, `.direnv/`, `.cargo/`. These are build outputs or
//! sibling-worktree state, not authoring surface.

use anyhow::{Context, Result, bail};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub fn run(workspace: &Path) -> Result<()> {
    let adrs_dir = workspace.join("specs").join("adrs");
    if !adrs_dir.is_dir() {
        bail!(
            "expected ADR dir at {}; got nothing. Did the specs/adrs consolidation land?",
            adrs_dir.display()
        );
    }

    let claims = load_claims(&adrs_dir)?;
    let active: Vec<&Claim> = claims
        .iter()
        .filter(|c| c.status != Status::Shipped)
        .collect();

    if active.is_empty() {
        eprintln!(
            "check-no-overclaim: no active gates (all claims at status Shipped or claims/ empty)"
        );
        return Ok(());
    }

    let mut findings: Vec<Finding> = Vec::new();
    visit_text_files(workspace, &mut |rel_path, abs_path| -> Result<()> {
        let source = std::fs::read_to_string(abs_path)
            .with_context(|| format!("reading {}", abs_path.display()))?;
        for claim in &active {
            if path_is_exempt(rel_path, &claim.exempt_paths) {
                continue;
            }
            for phrase in &claim.gated_phrases {
                if let Some(line_no) = find_phrase(&source, phrase) {
                    findings.push(Finding {
                        path: rel_path.to_path_buf(),
                        line: line_no,
                        phrase: phrase.clone(),
                        claim: claim.id.clone(),
                        status: claim.status,
                    });
                }
            }
        }
        Ok(())
    })?;

    if findings.is_empty() {
        eprintln!(
            "check-no-overclaim: clean ({} active claim gate(s), scanned workspace text)",
            active.len()
        );
        return Ok(());
    }

    eprintln!(
        "check-no-overclaim: {} finding(s) across {} claim(s)",
        findings.len(),
        active.len()
    );
    for f in &findings {
        eprintln!(
            "  {}:{} — phrase {:?} is gated by claim {} (status: {}). \
             Add the path to the claim's `exempt_paths` if intentional, \
             or flip the claim to `Shipped` once its CI gate passes.",
            f.path.display(),
            f.line,
            f.phrase,
            f.claim,
            f.status.as_str(),
        );
    }
    std::process::exit(1);
}

#[derive(Debug, Clone)]
struct Claim {
    id: String,
    status: Status,
    gated_phrases: Vec<String>,
    exempt_paths: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Status {
    Planned,
    Preview,
    Shipped,
    NotClaimed,
}

impl Status {
    fn parse(s: &str) -> Option<Self> {
        match s.trim() {
            "Planned" => Some(Self::Planned),
            "Preview" => Some(Self::Preview),
            "Shipped" => Some(Self::Shipped),
            "Not-claimed" | "NotClaimed" => Some(Self::NotClaimed),
            _ => None,
        }
    }
    fn as_str(&self) -> &'static str {
        match self {
            Self::Planned => "Planned",
            Self::Preview => "Preview",
            Self::Shipped => "Shipped",
            Self::NotClaimed => "Not-claimed",
        }
    }
}

#[derive(Debug, Clone)]
struct Finding {
    path: PathBuf,
    line: usize,
    phrase: String,
    claim: String,
    status: Status,
}

/// Recursively scan `dir` for `.md` files and pull every embedded claim
/// frontmatter block out of each one.
fn load_claims(dir: &Path) -> Result<Vec<Claim>> {
    let mut out = Vec::new();
    collect_claims(dir, &mut out)?;
    out.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(out)
}

fn collect_claims(dir: &Path, out: &mut Vec<Claim>) -> Result<()> {
    for entry in
        std::fs::read_dir(dir).with_context(|| format!("reading ADR dir {}", dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_claims(&path, out)?;
            continue;
        }
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        if !name.ends_with(".md") {
            continue;
        }
        let source = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        for block in extract_frontmatter_blocks(&source) {
            if let Some(claim) = claim_from_frontmatter(&path, &block)? {
                out.push(claim);
            }
        }
    }
    Ok(())
}

/// Scan `source` for every `---`-delimited block (a line that is
/// exactly `---`, up to the next such line) and return each block's
/// inner lines. Blocks inside fenced code (```` ``` ```` or `~~~`)
/// are skipped — an ADR's "## File format" section can legitimately
/// show an example frontmatter template inside a fence, and that
/// template (`status: Planned | Preview | ...`) is not a real claim.
fn extract_frontmatter_blocks(source: &str) -> Vec<Vec<String>> {
    let lines: Vec<&str> = source.lines().collect();
    let mut blocks = Vec::new();
    let mut in_fence = false;
    let mut i = 0;
    while i < lines.len() {
        if is_fence_delimiter(lines[i]) {
            in_fence = !in_fence;
            i += 1;
            continue;
        }
        if in_fence || lines[i].trim() != "---" {
            i += 1;
            continue;
        }
        // Found an opening delimiter outside a fence; scan forward
        // for the matching close, tracking fences within the search
        // so a fenced example between the two `---` lines can't
        // supply a spurious close.
        let mut j = i + 1;
        let mut inner_fence = false;
        let mut close = None;
        while j < lines.len() {
            if is_fence_delimiter(lines[j]) {
                inner_fence = !inner_fence;
            } else if !inner_fence && lines[j].trim() == "---" {
                close = Some(j);
                break;
            }
            j += 1;
        }
        match close {
            Some(close) => {
                blocks.push(lines[i + 1..close].iter().map(|s| s.to_string()).collect());
                i = close + 1;
            }
            // Unterminated opening delimiter (e.g. a lone `---`
            // markdown thematic break later in the file) — stop
            // looking for frontmatter blocks in this file.
            None => break,
        }
    }
    blocks
}

fn is_fence_delimiter(line: &str) -> bool {
    let t = line.trim_start();
    t.starts_with("```") || t.starts_with("~~~")
}

/// Parse one frontmatter block's lines into scalar and list fields.
/// The format is fixed (we control the authors and the file format),
/// so handwritten parsing avoids the serde_yaml dep.
fn parse_frontmatter_fields(
    lines: &[String],
) -> (BTreeMap<String, String>, BTreeMap<String, Vec<String>>) {
    let mut scalars: BTreeMap<String, String> = BTreeMap::new();
    let mut lists: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut current_list: Option<String> = None;
    for raw in lines {
        let line = raw.trim_end();
        if let Some(item) = strip_list_item(line) {
            if let Some(key) = current_list.as_deref() {
                lists.entry(key.to_string()).or_default().push(item);
            }
            continue;
        }
        if let Some((key, value)) = split_kv(line) {
            current_list = None;
            if value.is_empty() {
                // Start of a list-valued key like `gated_phrases:`.
                current_list = Some(key.to_string());
                lists.entry(key.to_string()).or_default();
            } else {
                scalars.insert(key.to_string(), value.to_string());
            }
        }
    }
    (scalars, lists)
}

/// Parse a frontmatter block into a `Claim`, or `Ok(None)` when the
/// block has no `claim:` key — i.e. it isn't a claim doc at all (an
/// ADR's own title/status/date header is the common case).
fn claim_from_frontmatter(path: &Path, lines: &[String]) -> Result<Option<Claim>> {
    let (mut scalars, mut lists) = parse_frontmatter_fields(lines);
    let Some(id) = scalars.remove("claim") else {
        return Ok(None);
    };
    let status_str = scalars.get("status").ok_or_else(|| {
        anyhow::anyhow!(
            "{}: claim `{id}` frontmatter block missing `status:` field",
            path.display()
        )
    })?;
    let status = Status::parse(status_str).ok_or_else(|| {
        anyhow::anyhow!(
            "{}: claim `{id}` has unknown status {:?}. Expected Planned, Preview, Shipped, or Not-claimed.",
            path.display(),
            status_str
        )
    })?;
    let gated_phrases = lists.remove("gated_phrases").unwrap_or_default();
    let exempt_paths = lists.remove("exempt_paths").unwrap_or_default();

    Ok(Some(Claim {
        id,
        status,
        gated_phrases,
        exempt_paths,
    }))
}

/// Parse a `- "value"` or `- value` list item.
fn strip_list_item(line: &str) -> Option<String> {
    let trimmed = line.trim_start();
    let rest = trimmed.strip_prefix("- ")?;
    // Strip surrounding quotes if present.
    let s = rest.trim();
    let unquoted = s.strip_prefix('"').and_then(|s| s.strip_suffix('"'));
    Some(unquoted.unwrap_or(s).to_string())
}

/// Parse a `key: value` line; returns `(key, value)` with value
/// trimmed. Returns `None` if the line isn't a key/value pair.
fn split_kv(line: &str) -> Option<(&str, &str)> {
    let colon = line.find(':')?;
    let key = line[..colon].trim();
    let value = line[colon + 1..].trim();
    if key.is_empty() || key.contains(' ') {
        return None;
    }
    Some((key, value))
}

/// Find the 1-indexed line number on which `phrase` first appears in
/// `source`, or `None` if absent. Phrases are matched literally
/// (substring), case-sensitive.
fn find_phrase(source: &str, phrase: &str) -> Option<usize> {
    for (i, line) in source.lines().enumerate() {
        if line.contains(phrase) {
            return Some(i + 1);
        }
    }
    None
}

/// True if `rel_path` matches any of the claim's `exempt_paths`
/// globs. Globs support `**` (any depth) and `*` (single segment).
fn path_is_exempt(rel_path: &Path, exempt_paths: &[String]) -> bool {
    let s = rel_path.to_string_lossy();
    let s = s.replace('\\', "/");
    exempt_paths.iter().any(|pattern| glob_match(pattern, &s))
}

/// Match `path` against a glob pattern with `**` and `*` support.
/// Simple recursive matcher; we don't need full glob semantics
/// (character classes, brace expansion, etc.) for the gate file
/// shape.
fn glob_match(pattern: &str, path: &str) -> bool {
    glob_match_bytes(pattern.as_bytes(), path.as_bytes())
}

fn glob_match_bytes(pat: &[u8], s: &[u8]) -> bool {
    // Recursive matching. Cheap because patterns and paths are short.
    if pat.is_empty() {
        return s.is_empty();
    }
    if pat.starts_with(b"**") {
        // `**` consumes any number of characters (including `/`).
        // Skip an optional `/` after `**`.
        let after_double = &pat[2..];
        let next = if after_double.starts_with(b"/") {
            &after_double[1..]
        } else {
            after_double
        };
        for i in 0..=s.len() {
            if glob_match_bytes(next, &s[i..]) {
                return true;
            }
        }
        return false;
    }
    if pat.starts_with(b"*") {
        // `*` consumes any number of non-`/` characters.
        for i in 0..=s.len() {
            if i > 0 && s[i - 1] == b'/' {
                break;
            }
            if glob_match_bytes(&pat[1..], &s[i..]) {
                return true;
            }
        }
        return false;
    }
    if s.is_empty() {
        return false;
    }
    if pat[0] == s[0] {
        return glob_match_bytes(&pat[1..], &s[1..]);
    }
    false
}

fn visit_text_files(root: &Path, cb: &mut dyn FnMut(&Path, &Path) -> Result<()>) -> Result<()> {
    visit_inner(root, root, cb)
}

fn visit_inner(
    root: &Path,
    dir: &Path,
    cb: &mut dyn FnMut(&Path, &Path) -> Result<()>,
) -> Result<()> {
    for entry in std::fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_string();
        if path.is_dir() {
            if matches!(
                name.as_str(),
                "target"
                    | ".git"
                    | ".worktrees"
                    | ".claude/worktrees"
                    | "node_modules"
                    | "result"
                    | ".direnv"
                    | ".cargo"
            ) || name.starts_with("result-")
            {
                continue;
            }
            visit_inner(root, &path, cb)?;
        } else if matches!(
            path.extension().and_then(|e| e.to_str()),
            Some("md") | Some("rs") | Some("toml") | Some("nix")
        ) {
            let rel = path.strip_prefix(root).unwrap_or(&path).to_path_buf();
            cb(&rel, &path)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parse the single frontmatter block in `src` (test-only sugar
    /// over `extract_frontmatter_blocks` + `claim_from_frontmatter`,
    /// mirroring the old standalone-file parse path).
    fn parse_one_claim(path: &Path, src: &str) -> Result<Claim> {
        let blocks = extract_frontmatter_blocks(src);
        let block = blocks
            .first()
            .ok_or_else(|| anyhow::anyhow!("no frontmatter block found"))?;
        claim_from_frontmatter(path, block)?
            .ok_or_else(|| anyhow::anyhow!("block has no `claim:` field"))
    }

    #[test]
    fn parses_claim_frontmatter() {
        let src = "\
---
claim: 10-test
status: Planned
gated_phrases:
  - \"foo bar\"
  - \"baz\"
exempt_paths:
  - \"specs/**\"
---

# body
";
        let claim = parse_one_claim(Path::new("test.md"), src).unwrap();
        assert_eq!(claim.id, "10-test");
        assert_eq!(claim.status, Status::Planned);
        assert_eq!(claim.gated_phrases, vec!["foo bar", "baz"]);
        assert_eq!(claim.exempt_paths, vec!["specs/**"]);
    }

    #[test]
    fn shipped_status_disengages_gate() {
        let src = "\
---
claim: 9-test
status: Shipped
gated_phrases:
  - \"never gated\"
exempt_paths: []
---

body
";
        let claim = parse_one_claim(Path::new("test.md"), src).unwrap();
        assert_eq!(claim.status, Status::Shipped);
    }

    #[test]
    fn rejects_unknown_status() {
        let src = "\
---
claim: 1
status: Cheese
---
";
        let err = parse_one_claim(Path::new("test.md"), src).unwrap_err();
        assert!(err.to_string().contains("unknown status"));
    }

    #[test]
    fn non_claim_frontmatter_block_is_skipped() {
        // An ADR's own title/status/date header carries no `claim:`
        // key — it must not be mistaken for a claim doc.
        let src = "\
---
title: \"ADR-001: something\"
status: Accepted
date: 2026-04-30
---

## Body
";
        let blocks = extract_frontmatter_blocks(src);
        assert_eq!(blocks.len(), 1);
        assert!(
            claim_from_frontmatter(Path::new("adr.md"), &blocks[0])
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn fenced_example_frontmatter_is_not_extracted() {
        // The claims README's "## File format" section shows an
        // example template inside a ```markdown fence. That example's
        // `status:` value is a human-readable placeholder, not a real
        // status — it must never be parsed as a claim.
        let src = "\
## File format

```markdown
---
claim: <kebab-case-id>
status: Planned | Preview | Shipped | Not-claimed
---

# Claim <N>
```

more prose
";
        assert!(extract_frontmatter_blocks(src).is_empty());
    }

    #[test]
    fn multiple_blocks_in_one_file_are_all_found() {
        let src = "\
---
title: \"ADR-017\"
status: Proposed
---

## Claim 10 (consolidated)

---
claim: 10-oci-image-provenance
status: Shipped
gated_phrases:
  - \"any OCI image\"
exempt_paths: []
---

more prose
";
        let blocks = extract_frontmatter_blocks(src);
        assert_eq!(blocks.len(), 2);
        assert!(
            claim_from_frontmatter(Path::new("adr.md"), &blocks[0])
                .unwrap()
                .is_none()
        );
        let claim = claim_from_frontmatter(Path::new("adr.md"), &blocks[1])
            .unwrap()
            .unwrap();
        assert_eq!(claim.id, "10-oci-image-provenance");
        assert_eq!(claim.gated_phrases, vec!["any OCI image"]);
    }

    #[test]
    fn unterminated_delimiter_yields_no_block() {
        let src = "prose\n\n---\nlone thematic break below, no closing pair\n\nmore prose\n";
        assert!(extract_frontmatter_blocks(src).is_empty());
    }

    #[test]
    fn load_claims_walks_adrs_dir_recursively() {
        let tmp = tempfile::tempdir().unwrap();
        let adrs = tmp.path().join("specs").join("adrs");
        std::fs::create_dir_all(&adrs).unwrap();
        // The gated phrase deliberately isn't a real one — this whole
        // file is `.rs` text that the workspace-wide scan in `run()`
        // would itself pick up if it ever matched a live claim's gate.
        std::fs::write(
            adrs.join("002-example.md"),
            "\
---
title: \"ADR-001\"
status: Accepted
---

---
claim: fixture-example-claim
status: Preview
gated_phrases:
  - \"totally-fictional-gated-phrase-for-testing\"
exempt_paths:
  - \"specs/**\"
---
",
        )
        .unwrap();

        let claims = load_claims(&adrs).unwrap();
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].id, "fixture-example-claim");
        assert_eq!(claims[0].status, Status::Preview);
    }

    #[test]
    fn glob_matches_prefix_and_doublestar() {
        assert!(glob_match("specs/**", "specs/plans/75.md"));
        assert!(glob_match("specs/**", "specs/adrs/049.md"));
        assert!(!glob_match("specs/**", "public/docs/index.md"));
        assert!(glob_match("CHANGELOG.md", "CHANGELOG.md"));
        assert!(glob_match("**/*.md", "public/docs/index.md"));
        assert!(!glob_match("*.md", "public/docs/index.md"));
    }

    #[test]
    fn find_phrase_returns_first_line() {
        let s = "alpha\nbeta\nfoo bar baz\nquux\n";
        assert_eq!(find_phrase(s, "foo bar"), Some(3));
        assert_eq!(find_phrase(s, "missing"), None);
    }

    #[test]
    fn list_item_strips_quotes() {
        assert_eq!(strip_list_item("  - \"hello\""), Some("hello".to_string()));
        assert_eq!(strip_list_item("- bare"), Some("bare".to_string()));
        assert_eq!(strip_list_item("not a list"), None);
    }

    #[test]
    fn key_value_splits_correctly() {
        assert_eq!(split_kv("claim: 10-foo"), Some(("claim", "10-foo")));
        assert_eq!(split_kv("status:Planned"), Some(("status", "Planned")));
        assert_eq!(split_kv("gated_phrases:"), Some(("gated_phrases", "")));
        // Lines that aren't `key: value` should not parse.
        assert_eq!(split_kv("just text"), None);
    }
}
