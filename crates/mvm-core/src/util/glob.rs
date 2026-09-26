//! Shell-style wildcard matching.
//!
//! One matcher for every "does this name fit the operator's pattern" question
//! in the workspace: command blocklists and audit event-kind filters both go
//! through it, so `*` and `?` mean the same thing wherever a user types them.

/// Simple glob pattern matching against the full text.
///
/// Supports `*` (matches zero or more characters) and `?` (matches exactly
/// one character). The pattern is matched against the entire input text.
pub fn glob_match(pattern: &str, text: &str) -> bool {
    let p = pattern.as_bytes();
    let t = text.as_bytes();
    let mut pi = 0;
    let mut ti = 0;
    let mut star_pi: Option<usize> = None;
    let mut star_ti = 0;

    while ti < t.len() {
        if pi < p.len() && (p[pi] == b'?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == b'*' {
            star_pi = Some(pi);
            star_ti = ti;
            pi += 1;
        } else if let Some(sp) = star_pi {
            pi = sp + 1;
            star_ti += 1;
            ti = star_ti;
        } else {
            return false;
        }
    }

    // Consume trailing stars.
    while pi < p.len() && p[pi] == b'*' {
        pi += 1;
    }

    pi == p.len()
}

#[cfg(test)]
mod tests {
    use super::glob_match;

    #[test]
    fn dotted_event_kinds_match_by_prefix_and_suffix() {
        assert!(glob_match("plan.*", "plan.admitted"));
        assert!(glob_match("*.sealed", "session.sealed"));
        assert!(glob_match("plan.?xited", "plan.exited"));
        assert!(!glob_match("plan.*", "session.sealed"));
        assert!(glob_match("*", ""));
        assert!(!glob_match("?", ""));
    }
}
