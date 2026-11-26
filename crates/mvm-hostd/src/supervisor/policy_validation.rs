//! Operator-policy validation and the canonical egress inspector chain.
//!
//! The validators refuse a policy bundle naming an inspector or an audit
//! stream scheme this build does not know, so a typo fails at resolution
//! instead of silently disabling a control. The chain builders keep the
//! inspector names those validators accept tied to the inspectors that exist.

use std::sync::Arc;

use thiserror::Error;

use mvm_core::policy::EgressPolicy;

use crate::supervisor::inspection::circuit_breaker::{CircuitBreaker, InspectorReporter};
use crate::supervisor::inspection::destination::DestinationPolicy;
use crate::supervisor::inspection::injection_guard::InjectionGuard;
use crate::supervisor::inspection::inspector::{Inspector, InspectorChain};
use crate::supervisor::inspection::pii_redactor::PiiRedactor;
use crate::supervisor::inspection::secrets_scanner::SecretsScanner;
use crate::supervisor::inspection::ssrf_guard::SsrfGuard;

/// Stable identifiers for every inspector the canonical
/// [`build_inspector_chain`] wires. Matches each inspector's
/// `Inspector::name()` return value. Operators reference these
/// names in `EgressPolicy::disabled_inspectors`; [`validate_egress_policy_inspector_names`]
/// uses this list to fail-loud on typos.
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
/// `build_inspector_chain` itself stays lenient — it silently skips
/// unknown names so in-process callers that own their config can
/// extend the disabled list ahead of inspector additions. This
/// function is the *admission-time* tightening: the policy
/// resolver in `mvm-cli` calls this to fail loud on typos
/// (e.g. `["ssr_guard"]` would silently leave SSRF enforced; not
/// catching that at admission means the operator thinks they
/// disabled it).
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

/// Build an [`InspectorChain`] from the workload's [`EgressPolicy`].
/// Order is cheap/most-precise checks first, body
/// inspectors last (so a destination-denied request never pays the
/// cost of body scanning).
///
/// `policy.disabled_inspectors` filters out by name — empty == every
/// inspector enabled. The named inspectors must match
/// `Inspector::name()` strings exactly.
///
/// When `breakers` is `Some`, each inspector is wrapped in a
/// [`CircuitBreaker`] that shares the supplied
/// [`InspectorReporter`]. The chain length is unchanged — wrappers
/// preserve the wrapped inspector's `name()` so audit binding stays
/// intact.
///
/// Public so the resolver in `mvm-client`'s `admission::policy_resolver`
/// can build the same canonical chain when it turns a parsed bundle
/// into a `ResolvedSlots`. Keeping the order in one place avoids
/// chain-shape drift between the in-process supervisor path and
/// the CLI resolver.
pub fn build_inspector_chain(
    policy: &EgressPolicy,
    breakers: Option<Arc<InspectorReporter>>,
) -> InspectorChain {
    let disabled = |name: &'static str| policy.disabled_inspectors.iter().any(|d| d == name);
    let wrap = |inner: Box<dyn Inspector>| -> Box<dyn Inspector> {
        match &breakers {
            Some(r) => Box::new(CircuitBreaker::new(inner, r.clone())),
            None => inner,
        }
    };
    let mut chain = InspectorChain::new();
    if !disabled("destination_policy") {
        let dp = DestinationPolicy::new(
            policy
                .allow_list
                .iter()
                .map(|(host, port)| (host.as_str(), *port)),
        );
        chain.push(wrap(Box::new(dp) as Box<dyn Inspector>));
    }
    if !disabled("ssrf_guard") {
        chain.push(wrap(Box::new(SsrfGuard::new())));
    }
    if !disabled("secrets_scanner") {
        chain.push(wrap(Box::new(SecretsScanner::with_default_rules())));
    }
    if !disabled("injection_guard") {
        chain.push(wrap(Box::new(InjectionGuard::with_default_rules())));
    }
    if !disabled("pii_redactor") {
        chain.push(wrap(Box::new(PiiRedactor::with_default_rules())));
    }
    chain
}

/// Same as [`build_inspector_chain`] but the PII inspector is
/// constructed from a parsed [`mvm_core::policy::PiiPolicy`] (mode +
/// category filter) instead of hardwired to defaults. Used by the
/// resolver so a tenant bundle's `[pii]` section actually
/// drives runtime behavior (Mode::Detect / Redact / Block, scoped to
/// a category subset).
///
/// Returns the same canonical chain order as `build_inspector_chain`.
/// The PII inspector is *skipped entirely* when `pii.mode =
/// "disabled"` (the kill-switch for analytics workloads
/// that scrub PII upstream) — same effect as adding `"pii_redactor"`
/// to `disabled_inspectors`, but expressed through the more
/// operator-natural `pii.mode` field.
///
/// Refuses unknown `pii.mode` / `pii.categories[i]` values via
/// `PiiPolicyError` so a typo fails the boot loudly at admission
/// rather than silently scanning fewer categories than intended.
pub fn build_pii_inspector_chain(
    egress: &EgressPolicy,
    pii: &mvm_core::policy::PiiPolicy,
    breakers: Option<Arc<InspectorReporter>>,
) -> Result<InspectorChain, crate::supervisor::inspection::pii_redactor::PiiPolicyError> {
    let disabled = |name: &'static str| egress.disabled_inspectors.iter().any(|d| d == name);
    let wrap = |inner: Box<dyn Inspector>| -> Box<dyn Inspector> {
        match &breakers {
            Some(r) => Box::new(CircuitBreaker::new(inner, r.clone())),
            None => inner,
        }
    };
    let mut chain = InspectorChain::new();
    if !disabled("destination_policy") {
        let dp = DestinationPolicy::new(
            egress
                .allow_list
                .iter()
                .map(|(host, port)| (host.as_str(), *port)),
        );
        chain.push(wrap(Box::new(dp) as Box<dyn Inspector>));
    }
    if !disabled("ssrf_guard") {
        chain.push(wrap(Box::new(SsrfGuard::new())));
    }
    if !disabled("secrets_scanner") {
        chain.push(wrap(Box::new(SecretsScanner::with_default_rules())));
    }
    if !disabled("injection_guard") {
        chain.push(wrap(Box::new(InjectionGuard::with_default_rules())));
    }
    if !disabled("pii_redactor")
        && let Some(red) = PiiRedactor::from_policy(pii)?
    {
        chain.push(wrap(Box::new(red)));
    }
    Ok(chain)
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
    fn build_inspector_chain_honours_disabled_inspectors() {
        let mut policy = dev_egress_policy(false);
        policy.disabled_inspectors =
            vec!["secrets_scanner".to_string(), "pii_redactor".to_string()];
        let chain = build_inspector_chain(&policy, None);
        // 5 default inspectors minus 2 disabled = 3.
        assert_eq!(chain.len(), 3);
    }

    #[test]
    fn build_inspector_chain_full_default() {
        let policy = dev_egress_policy(false);
        let chain = build_inspector_chain(&policy, None);
        // All 5 inspectors present.
        assert_eq!(chain.len(), 5);
    }

    #[test]
    fn known_inspector_names_matches_chain_inspectors() {
        // Each name in KNOWN_INSPECTOR_NAMES must actually disable a
        // chain slot. Any drift between this constant and the
        // canonical build_inspector_chain order is a bug.
        for &name in KNOWN_INSPECTOR_NAMES {
            let mut policy = dev_egress_policy(false);
            policy.disabled_inspectors = vec![name.to_string()];
            let chain = build_inspector_chain(&policy, None);
            assert_eq!(
                chain.len(),
                KNOWN_INSPECTOR_NAMES.len() - 1,
                "disabling {name:?} should drop exactly one inspector from the chain"
            );
        }
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

    fn dev_pii_policy() -> mvm_core::policy::PiiPolicy {
        mvm_core::policy::PiiPolicy {
            mode: None,
            categories: vec![],
        }
    }

    #[test]
    fn build_pii_inspector_chain_default_matches_default_chain() {
        // No PII policy override → chain length matches the lenient
        // 5-inspector default. Proves the new function is a strict
        // superset of `build_inspector_chain`'s shape.
        let egress = dev_egress_policy(false);
        let pii = dev_pii_policy();
        let chain = build_pii_inspector_chain(&egress, &pii, None).expect("default ok");
        assert_eq!(chain.len(), 5);
    }

    #[test]
    fn build_pii_inspector_chain_drops_inspector_when_mode_disabled() {
        // `pii.mode = "disabled"` is the operator-natural kill-switch;
        // semantically equivalent to adding `"pii_redactor"` to
        // `disabled_inspectors`. The chain shrinks to 4.
        let egress = dev_egress_policy(false);
        let pii = mvm_core::policy::PiiPolicy {
            mode: Some("disabled".to_string()),
            categories: vec![],
        };
        let chain = build_pii_inspector_chain(&egress, &pii, None).expect("disabled ok");
        assert_eq!(chain.len(), 4);
    }

    #[test]
    fn build_pii_inspector_chain_honors_redact_mode() {
        // `pii.mode = "redact"` keeps the inspector in the chain but
        // its internal Mode flips to Redact. We can't easily inspect
        // the internal Mode through the InspectorChain trait surface,
        // but we can prove from_policy preserves mode by going
        // through the redactor constructor directly.
        let pii = mvm_core::policy::PiiPolicy {
            mode: Some("redact".to_string()),
            categories: vec![],
        };
        let red = PiiRedactor::from_policy(&pii)
            .expect("ok")
            .expect("not disabled");
        assert_eq!(
            red.mode(),
            crate::supervisor::inspection::pii_redactor::Mode::Redact
        );
    }

    #[test]
    fn build_pii_inspector_chain_refuses_unknown_mode() {
        let egress = dev_egress_policy(false);
        let pii = mvm_core::policy::PiiPolicy {
            mode: Some("paranoid".to_string()),
            categories: vec![],
        };
        let err = build_pii_inspector_chain(&egress, &pii, None).expect_err("typo");
        match err {
            crate::supervisor::inspection::pii_redactor::PiiPolicyError::UnknownMode {
                value,
                valid,
            } => {
                assert_eq!(value, "paranoid");
                assert!(valid.contains(&"detect"));
                assert!(valid.contains(&"disabled"));
            }
            other => panic!("expected UnknownMode, got {other:?}"),
        }
    }

    #[test]
    fn build_pii_inspector_chain_refuses_unknown_category() {
        let egress = dev_egress_policy(false);
        let pii = mvm_core::policy::PiiPolicy {
            mode: Some("detect".to_string()),
            categories: vec!["email".to_string(), "license_plate".to_string()],
        };
        let err = build_pii_inspector_chain(&egress, &pii, None).expect_err("typo");
        match err {
            crate::supervisor::inspection::pii_redactor::PiiPolicyError::UnknownCategory {
                index,
                name,
                valid,
            } => {
                assert_eq!(index, 1);
                assert_eq!(name, "license_plate");
                assert!(valid.contains(&"email"));
                assert!(valid.contains(&"us_ssn"));
            }
            other => panic!("expected UnknownCategory, got {other:?}"),
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

    // ---- circuit-breaker wiring ----

    #[test]
    fn build_inspector_chain_without_breakers_has_raw_inspectors() {
        // Sanity: when no reporter is wired the chain is unchanged.
        let policy = dev_egress_policy(false);
        let chain = build_inspector_chain(&policy, None);
        assert_eq!(chain.len(), 5);
    }

    #[test]
    fn build_inspector_chain_with_breakers_preserves_length_and_names() {
        // Wrapping must be invisible to the chain interface — same
        // count, same names — so audit binding (which keys on
        // Inspector::name) stays intact.
        let reporter = Arc::new(
            crate::supervisor::inspection::circuit_breaker::InspectorReporter::new(
                crate::supervisor::inspection::circuit_breaker::CircuitBreakerConfig::default(),
            ),
        );
        let policy = dev_egress_policy(false);
        let chain = build_inspector_chain(&policy, Some(reporter));
        assert_eq!(chain.len(), 5);
        let dbg = format!("{chain:?}");
        for name in [
            "destination_policy",
            "ssrf_guard",
            "secrets_scanner",
            "injection_guard",
            "pii_redactor",
        ] {
            assert!(
                dbg.contains(name),
                "expected wrapped chain to expose {name}, got {dbg}"
            );
        }
    }
}
