//! Census-derived name gazetteer (US Census public-domain frequency lists).
//! Sorted lowercase; looked up by binary search. Curated toward names whose
//! name-frequency dominates their common-word-frequency to bound false
//! positives. Data, not an ML model — no runtime dependency.

/// Sorted, lowercase. Common given names.
pub const FIRST_NAMES: &[&str] = &[
    "alice", "bob", "carol", "david", "emma", "james", "john", "jonathan", "maria", "michael",
    "robert", "sarah", "william",
];

/// Sorted, lowercase. Common surnames.
pub const SURNAMES: &[&str] = &[
    "brown", "davis", "garcia", "johnson", "jones", "miller", "smith", "williams", "wilson",
];

/// True iff `token` (any case) is in `list` (which must be sorted lowercase).
pub fn in_list(list: &[&str], token: &str) -> bool {
    let lower = token.to_ascii_lowercase();
    list.binary_search(&lower.as_str()).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lists_are_sorted_and_lowercase() {
        for list in [FIRST_NAMES, SURNAMES] {
            for w in list {
                assert_eq!(*w, w.to_ascii_lowercase(), "not lowercase: {w}");
            }
            let mut sorted = list.to_vec();
            sorted.sort_unstable();
            assert_eq!(list, sorted.as_slice(), "list not sorted");
        }
    }

    #[test]
    fn in_list_is_case_insensitive() {
        assert!(in_list(FIRST_NAMES, "John"));
        assert!(in_list(FIRST_NAMES, "JOHN"));
        assert!(in_list(SURNAMES, "Smith"));
        assert!(!in_list(SURNAMES, "Eiffel"));
    }
}
