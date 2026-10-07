//! Comparison of secret bytes without a data-dependent early exit.

/// Whether `a` and `b` hold the same bytes, in time that depends only on
/// their lengths. A plain `==` returns at the first differing byte, which
/// tells a caller who can repeat guesses how long a prefix it got right; this
/// reads every byte whatever it finds.
#[must_use]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equal_bytes_compare_equal_and_any_difference_does_not() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"xbc"));
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert!(constant_time_eq(b"", b""));
    }
}
