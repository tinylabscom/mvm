//! `xtask check-no-overclaim`
//!
//! Refuses any user-facing repo text that uses phrases declared
//! "gated" by a claim file in `specs/claims/` whose status is not
//! `Shipped`.
//!
//! The lint reads every `specs/claims/*.md` (excluding `README.md`),
//! parses its YAML frontmatter, and builds a `phrase → (claim, status,
//! exempt_paths)` index. It then walks the workspace, scans `.md` and
//! `.rs` files, and reports any path that contains a gated phrase and
//! is not in the claim's `exempt_paths`.
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
    let claims_dir = workspace.join("specs").join("claims");
    if !claims_dir.is_dir() {
        bail!(
            "expected claims dir at {}; got nothing. Did plan 75 W0 land?",
            claims_dir.display()
        );
    }

    let claims = load_claims(&claims_dir)?;
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

fn load_claims(claims_dir: &Path) -> Result<Vec<Claim>> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(claims_dir)
        .with_context(|| format!("reading claims dir {}", claims_dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            continue;
        }
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        if !name.ends_with(".md") || name == "README.md" {
            continue;
        }
        let source = std::fs::read_to_string(&path)
            .with_context(|| format!("reading claim file {}", path.display()))?;
        let claim = parse_claim_frontmatter(&path, &source)?;
        out.push(claim);
    }
    out.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(out)
}

/// Minimal frontmatter parser. The format is fixed (we control the
/// authors and the file format), so handwritten parsing avoids the
/// serde_yaml dep.
fn parse_claim_frontmatter(path: &Path, source: &str) -> Result<Claim> {
    let mut lines = source.lines();
    if lines.next().map(str::trim) != Some("---") {
        bail!(
            "{}: expected frontmatter delimiter `---` on line 1",
            path.display()
        );
    }
    let mut scalars: BTreeMap<String, String> = BTreeMap::new();
    let mut lists: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut current_list: Option<String> = None;
    for raw in &mut lines {
        let line = raw.trim_end();
        if line.trim() == "---" {
            break;
        }
        if let Some(item) = strip_list_item(line) {
            let key = current_list.as_deref().ok_or_else(|| {
                anyhow::anyhow!(
                    "{}: list item {:?} without a preceding `key:` line",
                    path.display(),
                    item
                )
            })?;
            lists.entry(key.to_string()).or_default().push(item);
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

    let id = scalars
        .get("claim")
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("{}: missing `claim:` field", path.display()))?;
    let status_str = scalars
        .get("status")
        .ok_or_else(|| anyhow::anyhow!("{}: missing `status:` field", path.display()))?;
    let status = Status::parse(status_str).ok_or_else(|| {
        anyhow::anyhow!(
            "{}: unknown status {:?}. Expected Planned, Preview, Shipped, or Not-claimed.",
            path.display(),
            status_str
        )
    })?;
    let gated_phrases = lists.remove("gated_phrases").unwrap_or_default();
    let exempt_paths = lists.remove("exempt_paths").unwrap_or_default();

    Ok(Claim {
        id,
        status,
        gated_phrases,
        exempt_paths,
    })
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
                "target" | ".git" | ".worktrees" | "node_modules" | "result" | ".direnv" | ".cargo"
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
        let claim = parse_claim_frontmatter(Path::new("test.md"), src).unwrap();
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
        let claim = parse_claim_frontmatter(Path::new("test.md"), src).unwrap();
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
        let err = parse_claim_frontmatter(Path::new("test.md"), src).unwrap_err();
        assert!(err.to_string().contains("unknown status"));
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
