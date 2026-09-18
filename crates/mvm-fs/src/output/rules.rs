//! Per-name and per-path refusals for collected outputs.
//!
//! Names come out of a guest-authored directory, so each is checked on its own
//! before it is joined into a path, and the joined path is checked again with
//! the same escape rules the OCI unpacker applies to a layer. The second check
//! is not redundant decoration: it is what keeps a future change to how names
//! are joined from quietly reopening an escape the first one closed.

use crate::oci::unpack::{RefusalReason, escaping_path_refusal};

use super::{MAX_DEPTH, MAX_PATH_BYTES, OutputRefusal};

/// Which path rule a refused name or path broke.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathRule {
    Absolute,
    Traversal,
    CurrentDirectory,
    EmptyComponent,
    NulByte,
    Separator,
    NotUtf8,
    TooLong,
    TooDeep,
}

impl PathRule {
    pub fn audit_tag(self) -> &'static str {
        match self {
            Self::Absolute => "absolute_path",
            Self::Traversal => "traversal_segment",
            Self::CurrentDirectory => "current_directory_segment",
            Self::EmptyComponent => "empty_component",
            Self::NulByte => "nul_byte",
            Self::Separator => "separator_in_name",
            Self::NotUtf8 => "not_utf8",
            Self::TooLong => "path_too_long",
            Self::TooDeep => "path_too_deep",
        }
    }
}

impl std::fmt::Display for PathRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Absolute => "it is absolute",
            Self::Traversal => "it has a `..` segment",
            Self::CurrentDirectory => "it has a `.` segment",
            Self::EmptyComponent => "it has an empty component",
            Self::NulByte => "it contains a NUL byte",
            Self::Separator => "a single name contains `/`",
            Self::NotUtf8 => "it is not valid UTF-8",
            Self::TooLong => "it is longer than the path bound",
            Self::TooDeep => "it is nested deeper than the depth bound",
        })
    }
}

fn refuse(raw: &[u8], rule: PathRule) -> OutputRefusal {
    OutputRefusal::Path {
        path: String::from_utf8_lossy(raw).into_owned(),
        rule,
    }
}

/// Validate one directory-entry name and return it as UTF-8.
///
/// The host this lands on may not store a name that is not UTF-8, and the
/// manifest records paths as text, so such a name refuses rather than being
/// rewritten into something the guest did not write.
pub fn validate_name(raw: &[u8]) -> Result<&str, OutputRefusal> {
    if raw.is_empty() {
        return Err(refuse(raw, PathRule::EmptyComponent));
    }
    if raw.contains(&0) {
        return Err(refuse(raw, PathRule::NulByte));
    }
    if raw.contains(&b'/') {
        return Err(refuse(raw, PathRule::Separator));
    }
    match raw {
        b"." => return Err(refuse(raw, PathRule::CurrentDirectory)),
        b".." => return Err(refuse(raw, PathRule::Traversal)),
        _ => {}
    }
    std::str::from_utf8(raw).map_err(|_| refuse(raw, PathRule::NotUtf8))
}

/// Validate a normalized relative output path: the OCI unpacker's escape
/// rules, then the stricter shape an output path must have.
pub fn validate_relative_path(raw: &[u8]) -> Result<(), OutputRefusal> {
    if let Some(reason) = escaping_path_refusal(raw) {
        let rule = match reason {
            RefusalReason::AbsolutePath => PathRule::Absolute,
            _ => PathRule::Traversal,
        };
        return Err(refuse(raw, rule));
    }
    if raw.contains(&0) {
        return Err(refuse(raw, PathRule::NulByte));
    }
    if raw.len() > MAX_PATH_BYTES {
        return Err(refuse(raw, PathRule::TooLong));
    }
    let mut depth = 0usize;
    for segment in raw.split(|b| *b == b'/') {
        match segment {
            b"" => return Err(refuse(raw, PathRule::EmptyComponent)),
            b"." => return Err(refuse(raw, PathRule::CurrentDirectory)),
            _ => depth += 1,
        }
    }
    if depth > MAX_DEPTH {
        return Err(refuse(raw, PathRule::TooDeep));
    }
    std::str::from_utf8(raw)
        .map(|_| ())
        .map_err(|_| refuse(raw, PathRule::NotUtf8))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name_rule(raw: &[u8]) -> Option<PathRule> {
        match validate_name(raw) {
            Ok(_) => None,
            Err(OutputRefusal::Path { rule, .. }) => Some(rule),
            Err(other) => panic!("unexpected refusal {other}"),
        }
    }

    fn path_rule(raw: &[u8]) -> Option<PathRule> {
        match validate_relative_path(raw) {
            Ok(()) => None,
            Err(OutputRefusal::Path { rule, .. }) => Some(rule),
            Err(other) => panic!("unexpected refusal {other}"),
        }
    }

    #[test]
    fn ordinary_names_are_accepted() {
        for raw in [
            &b"result.json"[..],
            b"..hidden",
            b"a.b",
            "résumé".as_bytes(),
        ] {
            assert_eq!(name_rule(raw), None, "{raw:?}");
        }
    }

    #[test]
    fn each_name_rule_refuses_its_own_shape() {
        assert_eq!(name_rule(b""), Some(PathRule::EmptyComponent));
        assert_eq!(name_rule(b"a\0b"), Some(PathRule::NulByte));
        assert_eq!(name_rule(b"a/b"), Some(PathRule::Separator));
        assert_eq!(name_rule(b"."), Some(PathRule::CurrentDirectory));
        assert_eq!(name_rule(b".."), Some(PathRule::Traversal));
        assert_eq!(name_rule(&[0xff, 0xfe]), Some(PathRule::NotUtf8));
    }

    #[test]
    fn ordinary_relative_paths_are_accepted() {
        for raw in [&b"out"[..], b"a/b/c.txt", b"..foo/bar", b"a/..b"] {
            assert_eq!(path_rule(raw), None, "{}", String::from_utf8_lossy(raw));
        }
    }

    #[test]
    fn each_path_rule_refuses_its_own_shape() {
        assert_eq!(path_rule(b"/etc/passwd"), Some(PathRule::Absolute));
        assert_eq!(path_rule(b"a/../../x"), Some(PathRule::Traversal));
        assert_eq!(path_rule(b".."), Some(PathRule::Traversal));
        assert_eq!(path_rule(b"a//b"), Some(PathRule::EmptyComponent));
        assert_eq!(path_rule(b""), Some(PathRule::EmptyComponent));
        assert_eq!(path_rule(b"a/"), Some(PathRule::EmptyComponent));
        assert_eq!(path_rule(b"./a"), Some(PathRule::CurrentDirectory));
        assert_eq!(path_rule(b"a\0b"), Some(PathRule::NulByte));
        assert_eq!(path_rule(&[b'a', b'/', 0xff]), Some(PathRule::NotUtf8));
    }

    #[test]
    fn length_and_depth_bounds_refuse_just_past_the_limit() {
        let long = vec![b'a'; MAX_PATH_BYTES + 1];
        assert_eq!(path_rule(&long), Some(PathRule::TooLong));
        assert_eq!(path_rule(&vec![b'a'; MAX_PATH_BYTES]), None);

        let at_limit = vec!["d"; MAX_DEPTH].join("/");
        assert_eq!(path_rule(at_limit.as_bytes()), None);
        let too_deep = vec!["d"; MAX_DEPTH + 1].join("/");
        assert_eq!(path_rule(too_deep.as_bytes()), Some(PathRule::TooDeep));
    }

    #[test]
    fn the_escape_rules_are_the_unpackers_own() {
        // The two host-side extractors must not disagree about what escapes.
        for raw in [&b"/abs"[..], b"x/../y", b"fine/path"] {
            let unpacker = escaping_path_refusal(raw).is_some();
            let output = matches!(
                path_rule(raw),
                Some(PathRule::Absolute | PathRule::Traversal)
            );
            assert_eq!(unpacker, output, "{}", String::from_utf8_lossy(raw));
        }
    }

    #[test]
    fn audit_tags_are_distinct() {
        let rules = [
            PathRule::Absolute,
            PathRule::Traversal,
            PathRule::CurrentDirectory,
            PathRule::EmptyComponent,
            PathRule::NulByte,
            PathRule::Separator,
            PathRule::NotUtf8,
            PathRule::TooLong,
            PathRule::TooDeep,
        ];
        let tags: std::collections::HashSet<_> = rules.iter().map(|r| r.audit_tag()).collect();
        assert_eq!(tags.len(), rules.len());
    }
}
