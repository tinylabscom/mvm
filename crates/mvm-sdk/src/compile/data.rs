//! Token-list helper for embedded curated word lists.
//!
//! Used by [`crate::compile::reachability`] to load
//! language-extension lists from `data/*.txt`. Comment lines (`#`) and
//! blank lines are stripped; surrounding whitespace is trimmed.

pub(crate) fn parse_lines(text: &'static str) -> Vec<&'static str> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::parse_lines;

    #[test]
    fn python_extensions_list_loads() {
        let exts = parse_lines(include_str!("../../data/python_extensions.txt"));
        assert_eq!(exts, vec!["py"]);
    }

    #[test]
    fn node_extensions_list_loads() {
        let exts = parse_lines(include_str!("../../data/node_extensions.txt"));
        assert!(exts.contains(&"ts"));
        assert!(exts.contains(&"mjs"));
    }
}
