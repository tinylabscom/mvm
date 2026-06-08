//! Plan 129 / ADR-067 §1 — the guest↔host substitution-endpoint wire contract.
//!
//! The guest's SDK routes a secret-bearing request to the host substitution
//! endpoint over a host-local socket as a length-prefixed JSON [`WireRequest`];
//! the endpoint replies with a [`WireResponse`]. The contract lives in
//! `mvm-core` so the in-guest client (`mvm-guest`) and the host server
//! (`mvm-hostd`) serialize the **exact same** bytes — a drifted copy on either
//! side would silently break substitution.
//!
//! No secret bytes are defined here: the request carries an opaque placeholder
//! (in a header value); the response is the destination's reply or a refusal.
//! `body_b64` is base64 so the JSON stays compact and binary-safe; callers
//! encode/decode at the edges.

use serde::{Deserialize, Serialize};

/// A request the guest routed to the substitution endpoint. A header value may
/// carry an opaque placeholder where a credential goes; the host substitutes it
/// toward the bound destination and forwards to `url`.
///
/// `deny_unknown_fields` fails closed on an unexpected field (W4.1).
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
}
