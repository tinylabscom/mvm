//! Operator-policy validation.
//!
//! The validators refuse a policy bundle naming an inspector or an audit
//! stream scheme this build does not know, so a typo fails at resolution.

use thiserror::Error;

use mvm_core::policy::EgressPolicy;

/// The inspector names `EgressPolicy::disabled_inspectors` accepts;
/// [`validate_egress_policy_inspector_names`] uses this list to fail-loud
/// on typos. No inspector chain is built from the policy today.
///
/// Order is cheap/precise first, body inspectors last — keep it
/// that way if you add a name.
pub const KNOWN_INSPECTOR_NAMES: &[&str] = &[
    "destination_policy",
    "ssrf_guard",
    "secrets_scanner",
    "injection_guard",
    "pii_redactor",
];

/// Validation error for [`validate_egress_policy_inspector_names`].
///
/// The error carries the offending row index + the operator-supplied
/// name + the list of valid names so a single error message tells
/// the operator exactly which `[egress].disabled_inspectors` entry
/// to fix and what to put there instead.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum EgressPolicyValidationError {
    #[error(
        "disabled_inspectors[{index}] = {name:?} is not a known inspector name; \
         valid names are {valid:?}"
    )]
    UnknownDisabledInspector {
        index: usize,
        name: String,
        valid: &'static [&'static str],
    },
}

/// Verify every name in `policy.disabled_inspectors` matches a known
/// inspector (member of [`KNOWN_INSPECTOR_NAMES`]).
///
/// The policy resolver in `mvm-client` calls this at admission to fail
/// loud on typos (e.g. `["ssr_guard"]`).
pub fn validate_egress_policy_inspector_names(
    policy: &EgressPolicy,
) -> Result<(), EgressPolicyValidationError> {
    for (index, name) in policy.disabled_inspectors.iter().enumerate() {
        if !KNOWN_INSPECTOR_NAMES.contains(&name.as_str()) {
            return Err(EgressPolicyValidationError::UnknownDisabledInspector {
                index,
                name: name.clone(),
                valid: KNOWN_INSPECTOR_NAMES,
            });
        }
    }
    Ok(())
}

/// URL schemes accepted in [`mvm_core::policy::AuditPolicy::stream_destinations`].
/// The supervisor's eventual audit-stream replicator will emit each
/// entry to its matching backend; validating shape at admission means a typo
/// (`fil:///var/log/...` vs `file:///var/log/...`) fails the boot
/// loudly instead of silently dropping audit emissions.
pub const KNOWN_AUDIT_STREAM_SCHEMES: &[&str] = &["file://", "unix://", "https://", "http://"];

/// Validation error for [`validate_audit_policy_stream_destinations`].
///
/// The error names the offending row index + the operator-supplied
/// value + the accepted scheme list so a single error message tells
/// the operator exactly which `[audit].stream_destinations` entry to
/// fix.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuditPolicyValidationError {
    #[error(
        "stream_destinations[{index}] = {value:?} doesn't use a known URL scheme; \
         valid prefixes are {valid:?}"
    )]
    UnknownStreamScheme {
        index: usize,
        value: String,
        valid: &'static [&'static str],
    },
}

/// Verify every entry in `policy.stream_destinations` starts with a
/// known scheme prefix.
///
/// The supervisor's eventual replicator (waiting on the mvm-hostd
/// lift) is the consumer; this function is the *admission-time*
/// shape gate so an operator who typo'd `htpps://` doesn't think
/// they've configured TLS audit replication while the boot proceeds
/// in silence.
pub fn validate_audit_policy_stream_destinations(
    policy: &mvm_core::policy::AuditPolicy,
) -> Result<(), AuditPolicyValidationError> {
    for (index, value) in policy.stream_destinations.iter().enumerate() {
        if !KNOWN_AUDIT_STREAM_SCHEMES
            .iter()
            .any(|scheme| value.starts_with(scheme))
        {
            return Err(AuditPolicyValidationError::UnknownStreamScheme {
                index,
                value: value.clone(),
                valid: KNOWN_AUDIT_STREAM_SCHEMES,
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dev_egress_policy(allow_plain_http: bool) -> EgressPolicy {
        EgressPolicy {
            mode: Some("l3_plus_l7".to_string()),
            allow_list: vec![("api.openai.com".to_string(), 443)],
            allow_plain_http,
            body_cap_bytes: 0,
            disabled_inspectors: vec![],
            redaction: Default::default(),
            reversible_replacement: Default::default(),
        }
    }

    #[test]
    fn known_inspector_names_are_pinned() {
        // The validator's list is part of the policy format: a bundle that
        // names any of these must keep passing admission.
        assert_eq!(
            KNOWN_INSPECTOR_NAMES,
            &[
                "destination_policy",
                "ssrf_guard",
                "secrets_scanner",
                "injection_guard",
                "pii_redactor",
            ]
        );
    }

    #[test]
    fn validate_egress_policy_passes_known_names() {
        let mut policy = dev_egress_policy(false);
        policy.disabled_inspectors = vec!["ssrf_guard".to_string(), "pii_redactor".to_string()];
        validate_egress_policy_inspector_names(&policy).expect("known names");
    }

    #[test]
    fn validate_egress_policy_passes_empty_list() {
        // Empty disabled_inspectors is the common case (all
        // inspectors enabled). Must validate cleanly.
        let policy = dev_egress_policy(false);
        validate_egress_policy_inspector_names(&policy).expect("empty list");
    }

    #[test]
    fn validate_egress_policy_refuses_typo_with_row_index() {
        let mut policy = dev_egress_policy(false);
        policy.disabled_inspectors = vec![
            "ssrf_guard".to_string(),
            "secrets_scaner".to_string(), // typo
        ];
        let err = validate_egress_policy_inspector_names(&policy).expect_err("typo");
        match err {
            EgressPolicyValidationError::UnknownDisabledInspector { index, name, valid } => {
                assert_eq!(index, 1);
                assert_eq!(name, "secrets_scaner");
                assert_eq!(valid, KNOWN_INSPECTOR_NAMES);
            }
        }
    }

    #[test]
    fn validate_audit_policy_accepts_known_schemes() {
        let policy = mvm_core::policy::AuditPolicy {
            chain_signing: true,
            stream_destinations: vec![
                "file:///var/log/mvm/audit.jsonl".to_string(),
                "https://audit.example.com/ingest".to_string(),
                "unix:///run/audit.sock".to_string(),
            ],
        };
        validate_audit_policy_stream_destinations(&policy).expect("known schemes ok");
    }

    #[test]
    fn validate_audit_policy_passes_empty_destinations() {
        // Empty stream_destinations is the common case — no audit
        // replication configured. Must validate cleanly.
        let policy = mvm_core::policy::AuditPolicy::default();
        validate_audit_policy_stream_destinations(&policy).expect("empty ok");
    }

    #[test]
    fn validate_audit_policy_refuses_typo_with_row_index() {
        let policy = mvm_core::policy::AuditPolicy {
            chain_signing: true,
            stream_destinations: vec![
                "file:///var/log/mvm/audit.jsonl".to_string(),
                "htpps://audit.example.com/ingest".to_string(), // typo
            ],
        };
        let err = validate_audit_policy_stream_destinations(&policy).expect_err("typo");
        match err {
            AuditPolicyValidationError::UnknownStreamScheme {
                index,
                value,
                valid,
            } => {
                assert_eq!(index, 1);
                assert_eq!(value, "htpps://audit.example.com/ingest");
                assert!(valid.contains(&"https://"));
                assert!(valid.contains(&"file://"));
            }
        }
    }

    #[test]
    fn validate_audit_policy_refuses_scheme_less_value() {
        let policy = mvm_core::policy::AuditPolicy {
            chain_signing: true,
            stream_destinations: vec!["/var/log/audit.jsonl".to_string()],
        };
        let err = validate_audit_policy_stream_destinations(&policy).expect_err("no scheme");
        match err {
            AuditPolicyValidationError::UnknownStreamScheme { index, value, .. } => {
                assert_eq!(index, 0);
                assert_eq!(value, "/var/log/audit.jsonl");
            }
        }
    }

    #[test]
    fn validate_egress_policy_first_unknown_wins() {
        // Returns on the first bad row — `index` reflects the
        // earliest offender so operators fix in source order.
        let mut policy = dev_egress_policy(false);
        policy.disabled_inspectors = vec![
            "destination_policy".to_string(),
            "no_such_inspector".to_string(),
            "another_bad_name".to_string(),
        ];
        let err = validate_egress_policy_inspector_names(&policy).expect_err("first wins");
        match err {
            EgressPolicyValidationError::UnknownDisabledInspector { index, name, .. } => {
                assert_eq!(index, 1);
                assert_eq!(name, "no_such_inspector");
            }
        }
    }
}
