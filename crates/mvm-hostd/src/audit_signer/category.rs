//! Audit category allow-list (Plan 104 §H-L1.2, ADR-062).
//!
//! The wire envelope carries `category` as an opaque snake_case string —
//! the audit-signer doesn't pull in `mvm-supervisor`'s enum, but it does
//! refuse unknown categories so that a confused or hostile caller can't
//! seed the chain with categories that downstream tooling won't recognise.
//!
//! Keep this list in sync with `mvm-supervisor::audit_recorder::EventCategory::as_str`.

/// Categories the audit-signer will accept on `AppendEntry`.
pub const ALLOWED_CATEGORIES: &[&str] = &[
    "cmd",
    "lifecycle",
    "secret",
    "flow",
    "plan",
    "policy",
    "key",
    "host",
    "audit",
    // ADR-062 — workload-emitted via `host.audit.v1` in `mvm-broker`.
    "workload_audit",
];

/// True iff `category` is in the allow-list.
pub fn is_allowed(category: &str) -> bool {
    ALLOWED_CATEGORIES.contains(&category)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowed_categories_include_workload_audit() {
        assert!(is_allowed("workload_audit"));
    }

    #[test]
    fn allowed_categories_include_system_set() {
        for c in ["cmd", "lifecycle", "plan", "flow", "audit", "host"] {
            assert!(is_allowed(c), "{c} should be allowed");
        }
    }

    #[test]
    fn rejects_unknown_categories() {
        assert!(!is_allowed(""));
        assert!(!is_allowed("Cmd")); // case-sensitive
        assert!(!is_allowed("workloadaudit"));
        assert!(!is_allowed("../../etc/passwd"));
    }
}
