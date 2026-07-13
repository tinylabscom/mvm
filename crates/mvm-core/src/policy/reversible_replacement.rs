//! Per-destination reversible replacement policy plus shared token /
//! correlation / proof types for owned-path exact restore.

use serde::{Deserialize, Serialize};

/// Sensitive classes v1 handles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SensitiveClass {
    Secret,
    Pii,
}

/// Runtime-owned surfaces where exact-token replacement / reinjection can run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RewriteSurface {
    RequestHeader,
    RequestBody,
    ResponseHeader,
    ResponseBody,
}

/// Fail-closed fallback when reinjection is skipped or denied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ReversibleFallback {
    #[default]
    Redact,
    PassThrough,
}

/// Opaque request-scoped token handed to an external sink.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct OpaqueRewriteToken(pub String);

/// Correlation id for one owned request/response flow.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RewriteFlowId(pub String);

/// Proof record for one replace or reinject event. Carries metadata and keyed
/// digests only — never plaintext.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RewriteProofRecord {
    pub flow_id: RewriteFlowId,
    pub event_index: u64,
    pub class: SensitiveClass,
    pub surface: RewriteSurface,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field_name: Option<String>,
    pub offset: usize,
    pub original_len: usize,
    pub rewritten_len: usize,
    pub token_id: OpaqueRewriteToken,
    pub original_hmac_sha256: String,
    pub rewritten_hmac_sha256: String,
    pub policy_decision: String,
    pub authorization_decision: String,
}

/// Per-destination replace / reinject behavior.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct ReversibleReplacementAction {
    /// Global on/off switch for the destination.
    pub enabled: bool,
    /// Which sensitive classes are handled. Empty while enabled means the v1
    /// default: both secrets and PII.
    pub classes: Vec<SensitiveClass>,
    /// Which outbound surfaces are replaced. Empty while enabled means request
    /// headers + body.
    pub replace_surfaces: Vec<RewriteSurface>,
    /// Which inbound owned surfaces are reinjected. Empty while enabled means
    /// response headers + body.
    pub reinject_surfaces: Vec<RewriteSurface>,
    /// Fail-closed fallback when reinjection is skipped or denied.
    pub fallback: ReversibleFallback,
}

impl ReversibleReplacementAction {
    pub fn handles_class(&self, class: SensitiveClass) -> bool {
        self.enabled && (self.classes.is_empty() || self.classes.contains(&class))
    }

    pub fn replaces_on(&self, surface: RewriteSurface) -> bool {
        self.enabled
            && if self.replace_surfaces.is_empty() {
                matches!(
                    surface,
                    RewriteSurface::RequestHeader | RewriteSurface::RequestBody
                )
            } else {
                self.replace_surfaces.contains(&surface)
            }
    }

    pub fn reinjects_on(&self, surface: RewriteSurface) -> bool {
        self.enabled
            && if self.reinject_surfaces.is_empty() {
                matches!(
                    surface,
                    RewriteSurface::ResponseHeader | RewriteSurface::ResponseBody
                )
            } else {
                self.reinject_surfaces.contains(&surface)
            }
    }
}

/// One host-pattern override.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReversibleReplacementProfile {
    pub host: String,
    pub action: ReversibleReplacementAction,
}

/// A workload's reversible replacement policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct ReversibleReplacementPolicy {
    pub default: ReversibleReplacementAction,
    pub profiles: Vec<ReversibleReplacementProfile>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enabled_action_defaults_to_secret_and_pii_on_owned_request_and_response_surfaces() {
        let action = ReversibleReplacementAction {
            enabled: true,
            ..Default::default()
        };
        assert!(action.handles_class(SensitiveClass::Secret));
        assert!(action.handles_class(SensitiveClass::Pii));
        assert!(action.replaces_on(RewriteSurface::RequestHeader));
        assert!(action.replaces_on(RewriteSurface::RequestBody));
        assert!(!action.replaces_on(RewriteSurface::ResponseBody));
        assert!(action.reinjects_on(RewriteSurface::ResponseHeader));
        assert!(action.reinjects_on(RewriteSurface::ResponseBody));
        assert!(!action.reinjects_on(RewriteSurface::RequestBody));
    }

    #[test]
    fn policy_roundtrips_and_rejects_unknown_fields() {
        let json = r#"{
            "default": {
              "enabled": true,
              "classes": ["secret", "pii"],
              "replace_surfaces": ["request_body"],
              "reinject_surfaces": ["response_body"]
            },
            "profiles": [
              {
                "host": "api.openai.com",
                "action": {
                  "enabled": true,
                  "replace_surfaces": ["request_header", "request_body"]
                }
              }
            ]
        }"#;
        let policy: ReversibleReplacementPolicy = serde_json::from_str(json).unwrap();
        let roundtrip = serde_json::from_str::<ReversibleReplacementPolicy>(
            &serde_json::to_string(&policy).unwrap(),
        )
        .unwrap();
        assert_eq!(policy, roundtrip);
        assert!(
            serde_json::from_str::<ReversibleReplacementPolicy>(
                r#"{"default":{},"profiles":[],"bogus":1}"#
            )
            .is_err()
        );
    }
}
