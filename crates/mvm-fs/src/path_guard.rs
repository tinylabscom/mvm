//! The shared escape rule for slash-separated image and archive paths.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PathEscape {
    Absolute,
    Traversal,
}

/// Check segments, never substrings: `..foo` is a name; `../foo` escapes.
/// Callers layer their format-specific shape and size rules on top.
pub(crate) fn escaping_path_refusal(raw_path: &[u8]) -> Option<PathEscape> {
    if raw_path.first() == Some(&b'/') {
        return Some(PathEscape::Absolute);
    }
    if raw_path.split(|b| *b == b'/').any(|seg| seg == b"..") {
        return Some(PathEscape::Traversal);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slash_paths_refuse_escape_segments_without_rewriting_names() {
        for path in [b"/etc".as_slice(), b"/"] {
            assert_eq!(escaping_path_refusal(path), Some(PathEscape::Absolute));
        }
        for path in [b"../etc".as_slice(), b"dir/../etc", b"dir/.."] {
            assert_eq!(escaping_path_refusal(path), Some(PathEscape::Traversal));
        }
        for path in [
            b"./etc/".as_slice(),
            b"dir/..hidden",
            b"dir\\name",
            b"C:/name",
            b"",
        ] {
            assert_eq!(escaping_path_refusal(path), None);
        }
    }
}
