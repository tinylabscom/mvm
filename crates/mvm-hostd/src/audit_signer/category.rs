//! Audit category allow-list.
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
    "dns",
    // Workload-emitted via `host.audit.v1` in `mvm-broker`.
    "workload_audit",
    // Assurance campaign records. Emitted by the broker, which records through
    // the audit-signer rather than an `AuditEmitter` it does not have.
    "assurance",
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
    fn the_assurance_category_is_accepted() {
        // The broker records campaign probes through the signer, so a refused
        // category there would mean a boundary attempt with no record — which
        // the probe path treats as a reason to refuse the probe outright.
        assert!(is_allowed("assurance"));
        assert!(!is_allowed("assurance_probe"));
    }

    #[test]
    fn allowed_categories_include_system_set() {
        for c in [
            "cmd",
            "lifecycle",
            "secret",
            "flow",
            "plan",
            "policy",
            "key",
            "host",
            "audit",
            "dns",
            "workload_audit",
        ] {
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
