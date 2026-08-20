//! The guest↔host substitution-endpoint wire contract.
//!
//! The guest's SDK routes a secret-bearing request to the host substitution
//! endpoint over a host-local socket as a length-prefixed JSON `WireRequest`;
//! the endpoint replies with a `WireResponse`. The contract lives in
//! `mvm-core` so the in-guest client (`mvm-guest`) and the host server
//! (`mvm-hostd`) serialize the **exact same** bytes — a drifted copy on either
//! side would silently break substitution.
//!
//! No secret bytes are defined here: the request carries an opaque placeholder
//! (in a header value); the response is the destination's reply or a refusal.
//! `body_b64` is base64 so the JSON stays compact and binary-safe; callers
//! encode/decode at the edges.

use std::fmt;

use serde::{Deserialize, Serialize};

/// A request the guest routed to the substitution endpoint. A header value may
/// carry an opaque placeholder where a credential goes; the host substitutes it
/// toward the bound destination and forwards to `url`.
///
/// `deny_unknown_fields` fails closed on an unexpected field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireRequest {
    pub method: String,
    /// The real destination URL (e.g. `https://api.openai.com/v1/...`).
    pub url: String,
    pub headers: Vec<(String, String)>,
    /// Base64 of the request body. Empty string = no body.
    #[serde(default)]
    pub body_b64: String,
}

/// The endpoint's reply: the destination's response, or a refusal (unbound
/// destination, unknown placeholder, malformed request, forward failure). A
/// refusal never carries a secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum WireResponse {
    Ok {
        status: u16,
        headers: Vec<(String, String)>,
        body_b64: String,
    },
    Refused {
        message: String,
    },
}

/// The head of a typed HTTP flow on the FlowMux `Http` class: everything about
/// the request except its body, which follows as `HttpRequestBody` frames.
///
/// `body_len` is what terminates the request. The alternative — treating a
/// half-close as the end — would make "the guest finished sending" and "the
/// guest went away mid-body" the same event on the host, and the host would
/// forward a truncated request rather than refusing it.
///
/// `deny_unknown_fields` fails closed on an unexpected field, like every other
/// host-guest type here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpFlowHead {
    pub method: String,
    /// The real destination URL. May carry `mvm-secret-<hex>` placeholders,
    /// which the host resolves; the guest never holds the real credential.
    pub url: String,
    pub headers: Vec<(String, String)>,
    /// Exact body length to expect across the following body frames.
    pub body_len: u64,
}

/// The head of the response on a typed HTTP flow. The body follows as
/// `HttpResponseBody` frames and the exchange ends with `HttpComplete`.
///
/// A refusal never carries a secret, matching [`WireResponse::Refused`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case", deny_unknown_fields)]
pub enum HttpFlowResponseHead {
    Ok {
        status: u16,
        headers: Vec<(String, String)>,
        /// Exact decoded body length when the upstream declared one. `None`
        /// means the body is streamed until `HttpComplete`; receivers still
        /// enforce their independent hard byte ceiling.
        body_len: Option<u64>,
    },
    Refused {
        message: String,
    },
}

/// A `SecretResolver` request over the fleet secret-resolution socket
/// (mvmd's tenant vault, or the standalone `mvm-network-endpoint`'s
/// local fallback): resolve `name` to its raw credential value, bound to
/// `allowed_hosts` for this workload. `auth_type` is the snake_case
/// `AuthType` label (kept as a bare string here so `mvm-core` doesn't need
/// to depend on `mvm-sdk`'s IR).
///
/// `deny_unknown_fields` fails closed on an unexpected field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolveWireRequest {
    pub name: String,
    pub allowed_hosts: Vec<String>,
    pub auth_type: String,
}

/// The resolver's reply: the resolved value (base64) or a refusal. A
/// refusal never carries a secret.
///
/// `Debug` is hand-written (not derived): the `Ok` variant's `value_b64` is
/// the raw credential, base64-encoded but otherwise unprotected, so a
/// derived `Debug` would print it verbatim into any log or panic message
/// that formats this type. See [`fmt::Debug for ResolveWireResponse`].
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum ResolveWireResponse {
    Ok { value_b64: String },
    Refused { message: String },
}

impl fmt::Debug for ResolveWireResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ResolveWireResponse::Ok { .. } => f
                .debug_struct("Ok")
                .field("value_b64", &"<redacted>")
                .finish(),
            ResolveWireResponse::Refused { message } => {
                f.debug_struct("Refused").field("message", message).finish()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_request_roundtrips() {
        let req = WireRequest {
            method: "POST".into(),
            url: "https://api.openai.com/v1".into(),
            headers: vec![("authorization".into(), "Bearer mvm-secret-abc".into())],
            body_b64: "e30=".into(),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert_eq!(serde_json::from_str::<WireRequest>(&json).unwrap(), req);
    }

    #[test]
    fn wire_request_body_defaults_to_empty() {
        let req: WireRequest =
            serde_json::from_str(r#"{"method":"GET","url":"https://x/","headers":[]}"#).unwrap();
        assert_eq!(req.body_b64, "");
    }

    #[test]
    fn wire_request_rejects_unknown_fields() {
        let bad = r#"{"method":"GET","url":"https://x/","headers":[],"evil":1}"#;
        assert!(serde_json::from_str::<WireRequest>(bad).is_err());
    }

    #[test]
    fn wire_response_tagged_roundtrip() {
        for resp in [
            WireResponse::Ok {
                status: 200,
                headers: vec![("content-type".into(), "application/json".into())],
                body_b64: "cG9uZw==".into(),
            },
            WireResponse::Refused {
                message: "destination not bound".into(),
            },
        ] {
            let json = serde_json::to_string(&resp).unwrap();
            assert_eq!(serde_json::from_str::<WireResponse>(&json).unwrap(), resp);
        }
    }

    #[test]
    fn wire_response_refused_uses_snake_case_tag() {
        let json = serde_json::to_string(&WireResponse::Refused {
            message: "x".into(),
        })
        .unwrap();
        assert!(json.contains(r#""result":"refused""#), "got: {json}");
    }

    #[test]
    fn streaming_http_response_head_roundtrips_without_a_length() {
        let head = HttpFlowResponseHead::Ok {
            status: 200,
            headers: vec![("transfer-encoding".into(), "chunked".into())],
            body_len: None,
        };
        let json = serde_json::to_string(&head).unwrap();
        assert_eq!(
            serde_json::from_str::<HttpFlowResponseHead>(&json).unwrap(),
            head
        );
    }

    #[test]
    fn resolve_wire_request_roundtrips() {
        let req = ResolveWireRequest {
            name: "openai".into(),
            allowed_hosts: vec!["api.openai.com".into()],
            auth_type: "bearer".into(),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert_eq!(
            serde_json::from_str::<ResolveWireRequest>(&json).unwrap(),
            req
        );
    }

    #[test]
    fn resolve_wire_request_rejects_unknown_fields() {
        let bad = r#"{"name":"openai","allowed_hosts":[],"auth_type":"bearer","evil":1}"#;
        assert!(serde_json::from_str::<ResolveWireRequest>(bad).is_err());
    }

    #[test]
    fn resolve_wire_response_tagged_roundtrip() {
        for resp in [
            ResolveWireResponse::Ok {
                value_b64: "c2stbGl2ZS14eHg=".into(),
            },
            ResolveWireResponse::Refused {
                message: "secret not bound".into(),
            },
        ] {
            let json = serde_json::to_string(&resp).unwrap();
            assert_eq!(
                serde_json::from_str::<ResolveWireResponse>(&json).unwrap(),
                resp
            );
        }
    }

    #[test]
    fn resolve_wire_response_refused_uses_snake_case_tag() {
        let json = serde_json::to_string(&ResolveWireResponse::Refused {
            message: "x".into(),
        })
        .unwrap();
        assert!(json.contains(r#""result":"refused""#), "got: {json}");
    }

    #[test]
    fn resolve_wire_response_ok_debug_redacts_the_value() {
        let resp = ResolveWireResponse::Ok {
            value_b64: "c2stbGl2ZS14eHg=".into(),
        };
        let debug = format!("{resp:?}");
        assert!(!debug.contains("c2stbGl2ZS14eHg="), "leaked value: {debug}");
        assert!(debug.contains("<redacted>"), "got: {debug}");
    }

    #[test]
    fn resolve_wire_response_refused_debug_shows_the_message() {
        let resp = ResolveWireResponse::Refused {
            message: "secret not bound".into(),
        };
        let debug = format!("{resp:?}");
        assert!(debug.contains("secret not bound"), "got: {debug}");
    }
}
