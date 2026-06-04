//! Token-list helper for embedded curated word lists.
//!
//! Each list lives under `crates/<crate>/data/<name>.txt`, one token
//! per line, with `#`-prefixed and blank lines ignored. The list is
//! pulled into the binary at compile time via `include_str!` and
//! parsed once into a `Vec<&'static str>` on first access. Update a
//! list by editing its `.txt` file and rebuilding — no validator
//! code change needed.

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
    fn supported_languages_list_loads_and_includes_wasm() {
        let langs = parse_lines(include_str!("../../data/supported_languages.txt"));
        assert!(langs.contains(&"python"));
        assert!(langs.contains(&"node"));
        assert!(langs.contains(&"wasm"));
    }

    #[test]
    fn secret_field_tokens_list_loads_with_no_blank_or_comment_entries() {
        let tokens = parse_lines(include_str!("../../data/secret_field_tokens.txt"));
        assert!(!tokens.is_empty());
        assert!(tokens.iter().all(|t| !t.is_empty() && !t.starts_with('#')));
        // Auth credentials tier.
        assert!(tokens.contains(&"password"));
        assert!(tokens.contains(&"api_key"));
        // Financial / government identifiers tier.
        assert!(tokens.contains(&"ssn"));
        assert!(tokens.contains(&"credit_card"));
        assert!(tokens.contains(&"iban"));
    }
}
