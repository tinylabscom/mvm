//! Protected-paths policy — the segment-aware path-class gate for
//! guest-authored file trees. Pure data plus a pure matcher: enforcement
//! at the output-collection chokepoint and at read-write share admission
//! consumes the shared [`ProtectedPathSet`] so a path class cannot drift
//! between verdicts.
//!
//! The policy rides inline in the signed `ExecutionPlan`: the posture is
//! an admitted decision, and a relaxed (`off`) posture exists only as a
//! signed one. Matching is case-sensitive and total — traversal and
//! malformed input never match, never panic.

use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

/// Shipped protected path classes: CI, build, and test control files a
/// guest must not hand back to the host as "work product", plus signing
/// and environment key material. Directory classes use the `/**` tree
/// syntax; the two key-material classes match at any depth.
pub const DEFAULT_PROTECTED_PATHS: &[&str] = &[
    ".github/workflows/**",
    ".git/hooks/**",
    ".gitlab-ci.yml",
    "cloudbuild.yaml",
    "mvm.toml",
    "**/.env",
    "**/*.pem",
];

/// The path classes protected by default, as [`ProtectedPath`] values.
fn default_protected_paths() -> Vec<ProtectedPath> {
    DEFAULT_PROTECTED_PATHS
        .iter()
        .map(|p| ProtectedPath::new(*p))
        .collect()
}

/// Disposition of the protected-paths gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum ProtectedPathsMode {
    /// Guest-authored trees touching a protected class are refused.
    #[default]
    Enforce,
    /// Gate disabled. Only legitimate as a signed decision — an absent
    /// field means the enforcing default, never `off`.
    Off,
}

/// One segment-aware protected path pattern. The syntax is per segment:
///
/// - `a/b` matches exactly that relative path (`mvm.toml`).
/// - `a/b/**` matches the directory `a/b` and everything beneath it
///   (`.github/workflows/**`). This is the one canonical tree syntax.
/// - `**` matches zero or more whole segments, so `**/.env` matches at any
///   depth, including the repository root.
/// - `*` inside a segment matches any run of characters within that
///   segment, so `**/*.pem` matches any PEM file at any depth.
///
/// Matching is case-sensitive. Malformed patterns — empty segments after
/// normalization, `.` or `..` segments — never match anything.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(transparent)]
pub struct ProtectedPath(String);

impl ProtectedPath {
    /// Wrap a pattern string as written. Validation is the matcher's job:
    /// a malformed pattern matches nothing rather than failing construction,
    /// so a signed policy can never panic an enforcement point.
    pub fn new(pattern: impl Into<String>) -> Self {
        Self(pattern.into())
    }

    /// The pattern exactly as written in the policy.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A signed protected-paths policy: disposition plus the protected classes.
///
/// `paths` defaults to the shipped [`DEFAULT_PROTECTED_PATHS`] set — an
/// absent or empty list means the default posture, not "protect nothing"
/// (that is what [`ProtectedPathsMode::Off`] is for). `extra` carries
/// operator extensions matched after (and in addition to) `paths`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct ProtectedPathsPolicy {
    /// Gate disposition. Default `enforce`.
    #[serde(default)]
    pub mode: ProtectedPathsMode,
    /// Protected path classes. Empty means the shipped default set.
    #[serde(default = "default_protected_paths")]
    pub paths: Vec<ProtectedPath>,
    /// Operator extensions, matched after (and in addition to) `paths`.
    #[serde(default)]
    pub extra: Vec<ProtectedPath>,
}

impl Default for ProtectedPathsPolicy {
    fn default() -> Self {
        Self {
            mode: ProtectedPathsMode::Enforce,
            paths: default_protected_paths(),
            extra: Vec::new(),
        }
    }
}

impl ProtectedPathsPolicy {
    /// The matcher over the effective set (`paths` then `extra`), or
    /// `None` when the signed policy disables the gate.
    #[must_use]
    pub fn matcher(&self) -> Option<ProtectedPathSet> {
        if self.mode == ProtectedPathsMode::Off {
            return None;
        }
        Some(ProtectedPathSet::new(
            self.paths.iter().chain(self.extra.iter()),
        ))
    }
}

/// A pure, ordered matcher over a set of protected path classes.
///
/// The set is evaluated in declaration order so a refusal can name the
/// class that matched first. Total: every input yields an answer and no
/// input panics — traversal and malformed paths simply never match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectedPathSet {
    patterns: Vec<ProtectedPath>,
}

impl ProtectedPathSet {
    /// Build a matcher over `paths`, preserving declaration order.
    pub fn new<'a>(paths: impl IntoIterator<Item = &'a ProtectedPath>) -> Self {
        Self {
            patterns: paths.into_iter().cloned().collect(),
        }
    }

    /// True when no pattern was registered.
    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }

    /// True when `rel_path` falls in a protected class.
    pub fn contains(&self, rel_path: &str) -> bool {
        self.first_match(rel_path).is_some()
    }

    /// The first declared pattern that `rel_path` matches, if any.
    pub fn first_match(&self, rel_path: &str) -> Option<&ProtectedPath> {
        let segments = input_segments(rel_path)?;
        self.patterns
            .iter()
            .find(|p| pattern_matches(p.as_str(), &segments))
    }
}

/// Split a caller-supplied relative path into segments. `None` — never a
/// match — for empty input and for any `..` segment: a guest tree entry
/// that traverses out of the tree has no legitimate interpretation here.
/// Leading separators (absolute input), repeated separators, and `.`
/// segments are skipped, so both `.github/x` and `/.github/x` are
/// answered deterministically.
fn input_segments(rel_path: &str) -> Option<Vec<&str>> {
    let mut out = Vec::new();
    for seg in rel_path.split('/') {
        match seg {
            "" | "." => {}
            ".." => return None,
            name => out.push(name),
        }
    }
    if out.is_empty() {
        return None;
    }
    Some(out)
}

/// Split a policy pattern into segments. Malformed patterns — no
/// segments, any empty segment (a leading, trailing, or repeated
/// separator), or any `.`/`..` segment — yield `None` and so never
/// match: a pattern that cannot be read canonically fails closed rather
/// than guessing.
fn pattern_segments(pattern: &str) -> Option<Vec<&str>> {
    let mut out = Vec::new();
    for seg in pattern.split('/') {
        match seg {
            "" => return None,
            "." | ".." => return None,
            name => out.push(name),
        }
    }
    Some(out)
}

fn pattern_matches(pattern: &str, path: &[&str]) -> bool {
    let Some(pattern) = pattern_segments(pattern) else {
        return false;
    };
    segments_match(&pattern, path)
}

/// `**` as a whole segment crosses directories (zero or more segments);
/// any other segment must match exactly, subject to intra-segment `*`.
fn segments_match(pattern: &[&str], path: &[&str]) -> bool {
    let Some((head, rest)) = pattern.split_first() else {
        return path.is_empty();
    };
    if head == &"**" {
        return (0..=path.len()).any(|skip| segments_match(rest, &path[skip..]));
    }
    let Some((first, path_rest)) = path.split_first() else {
        return false;
    };
    segment_matches(head.as_bytes(), first.as_bytes()) && segments_match(rest, path_rest)
}

/// Intra-segment wildcard: `*` matches any run of characters within the
/// segment. Segments never contain `/`, so this never crosses directories.
fn segment_matches(pattern: &[u8], name: &[u8]) -> bool {
    match pattern.split_first() {
        None => name.is_empty(),
        Some((b'*', rest)) => (0..=name.len()).any(|take| segment_matches(rest, &name[take..])),
        Some((ch, rest)) => {
            let Some((first, name_rest)) = name.split_first() else {
                return false;
            };
            ch == first && segment_matches(rest, name_rest)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_set() -> ProtectedPathSet {
        ProtectedPathsPolicy::default()
            .matcher()
            .expect("the default policy enforces")
    }

    #[test]
    fn protected_paths_policy_roundtrips_through_serde() {
        let policy = ProtectedPathsPolicy {
            mode: ProtectedPathsMode::Off,
            extra: vec![ProtectedPath::new("build/**")],
            ..ProtectedPathsPolicy::default()
        };

        let json = serde_json::to_string(&policy).expect("policy serializes");
        let back: ProtectedPathsPolicy = serde_json::from_str(&json).expect("policy deserializes");
        assert_eq!(policy, back);
        assert!(matches!(back.mode, ProtectedPathsMode::Off));
        assert_eq!(back.extra.len(), 1);
        assert_eq!(back.extra[0].as_str(), "build/**");
        assert!(!back.paths.is_empty(), "the default set roundtrips");
    }

    #[test]
    fn default_policy_enforces_the_default_path_set() {
        let policy = ProtectedPathsPolicy::default();
        assert!(matches!(policy.mode, ProtectedPathsMode::Enforce));
        assert_eq!(policy.paths.len(), DEFAULT_PROTECTED_PATHS.len());
        assert!(policy.extra.is_empty());
    }

    #[test]
    fn an_absent_paths_list_deserializes_as_the_default_set() {
        let policy: ProtectedPathsPolicy =
            serde_json::from_str(r#"{"mode":"enforce"}"#).expect("partial policy deserializes");
        assert!(matches!(policy.mode, ProtectedPathsMode::Enforce));
        assert_eq!(policy.paths.len(), DEFAULT_PROTECTED_PATHS.len());
    }

    #[test]
    fn matcher_respects_segment_boundaries() {
        let set = default_set();
        assert!(
            !set.contains(".github/workflowsfoo"),
            "a shared string prefix is not the protected directory"
        );
        assert!(
            !set.contains(".git/hooks.d/installed"),
            "`.git/hooks.d` is a sibling of the protected tree, not inside it"
        );
        assert!(!set.contains("src/mvm.toml.bak"));
    }

    #[test]
    fn exact_files_match_exactly() {
        let set = default_set();
        for path in ["mvm.toml", ".gitlab-ci.yml", "cloudbuild.yaml"] {
            assert!(set.contains(path), "{path} is an exact protected file");
        }
        assert!(!set.contains("nested/mvm.toml"), "exact means exact");
    }

    #[test]
    fn tree_patterns_match_everything_beneath_the_directory() {
        let set = default_set();
        for path in [
            ".github/workflows",
            ".github/workflows/ci.yml",
            ".github/workflows/nested/deeper.yml",
            ".git/hooks/pre-commit",
        ] {
            assert!(set.contains(path), "{path} is inside a protected tree");
        }
        assert!(
            !set.contains(".github/dependabot.yml"),
            "the parent directory is not protected"
        );
    }

    #[test]
    fn env_and_pem_globs_match_at_any_depth() {
        let set = default_set();
        for path in [".env", "config/.env", "a/b/c/.env"] {
            assert!(set.contains(path), "{path} is key material at any depth");
        }
        for path in ["key.pem", "keys/tenant.pem", "a/b/c/tls.pem"] {
            assert!(set.contains(path), "{path} is a PEM file at any depth");
        }
        assert!(!set.contains("src/env.rs"), "`env` without the dot is code");
        assert!(
            !set.contains("docs/pem.md"),
            "a mention is not key material"
        );
    }

    #[test]
    fn dot_dot_traversal_never_matches() {
        let set = default_set();
        for path in [
            "../mvm.toml",
            ".github/../mvm.toml",
            "a/../../.github/workflows/ci.yml",
            "src/../../../etc/passwd",
        ] {
            assert!(
                !set.contains(path),
                "traversal out of the tree must never match: {path}"
            );
            assert!(set.first_match(path).is_none());
        }
    }

    #[test]
    fn absolute_and_messy_input_is_answered_deterministically() {
        let set = default_set();
        // A leading separator does not change the verdict — the path is
        // read as the same relative segments — and never panics.
        assert!(set.contains("/.github/workflows/ci.yml"));
        assert!(set.contains("./mvm.toml"));
        assert!(set.contains(".//mvm.toml"));
        assert!(!set.contains("/"));
        assert!(!set.contains(""));
        assert!(!set.contains("."));
        assert!(!set.contains("./"));
    }

    #[test]
    fn first_match_reports_the_declared_pattern() {
        let policy = ProtectedPathsPolicy {
            mode: ProtectedPathsMode::Enforce,
            paths: vec![ProtectedPath::new(".github/workflows/**")],
            extra: vec![ProtectedPath::new("**/.env")],
        };
        let set = policy.matcher().expect("enforcing policy has a matcher");
        assert_eq!(
            set.first_match(".github/workflows/ci.yml")
                .map(ProtectedPath::as_str),
            Some(".github/workflows/**")
        );
        assert_eq!(
            set.first_match("a/.env").map(ProtectedPath::as_str),
            Some("**/.env")
        );
        assert!(set.first_match("src/main.rs").is_none());
    }

    #[test]
    fn off_mode_carries_no_matcher() {
        let policy = ProtectedPathsPolicy {
            mode: ProtectedPathsMode::Off,
            ..ProtectedPathsPolicy::default()
        };
        assert!(policy.matcher().is_none());
    }

    #[test]
    fn malformed_patterns_never_match() {
        let patterns = [
            ProtectedPath::new(""),
            ProtectedPath::new("a//b"),
            ProtectedPath::new("../mvm.toml"),
            ProtectedPath::new("a/./b"),
        ];
        let set = ProtectedPathSet::new(&patterns);
        assert!(!set.contains("mvm.toml"));
        assert!(!set.contains("a/b"));
        assert!(!set.contains("../mvm.toml"));
    }
}
