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
    /// The real destination URL. The host substitutes placeholders only in
    /// headers, so it refuses a request whose URL carries one.
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

/// The one kind of request a host-internal endpoint connection carries. The
/// guest SDK's substitution request shares the socket with a witness-only
/// gate probe, so the serve loop demultiplexes on the frame body instead of
/// binding one request type per listener.
///
/// `untagged` keeps the wire backward-compatible: every frame a previous
/// client sent is exactly a [`WireRequest`], so `Forward` is tried first and
/// only a frame without `method`/`url`/`headers` falls through to
/// [`GateProbeRequest`]. A frame matching neither fails the parse, which
/// fails the connection closed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum EndpointRequest {
    /// A secret-bearing substitution request, forwarded toward the bound
    /// destination.
    Forward(WireRequest),
    /// A witness-only probe of the running egress gate (see
    /// [`GateProbeRequest`]).
    GateProbe(GateProbeRequest),
}

/// Cap on the samples one gate probe carries. The launcher sends at most a
/// deny sample and an admit sample; the cap bounds a hostile or broken peer's
/// frame before the gate is asked anything.
pub const MAX_GATE_PROBE_SAMPLES: usize = 4;

/// A witness-only probe asking the running egress gate to decide a handful of
/// `host:port` samples. The probe never substitutes, never opens a forward
/// leg, and never writes an audit record: it only observes the verdicts the
/// live gate gives, so a launch can tell "the policy was admitted" apart from
/// "the running gate actually enforces it".
///
/// `deny_unknown_fields` fails closed on an unexpected field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GateProbeRequest {
    pub samples: Vec<GateProbeSample>,
}

/// One destination the probe asks the gate to decide, with the verdict the
/// caller expects from the *signed policy it already admitted*.
///
/// `deny_unknown_fields` fails closed on an unexpected field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GateProbeSample {
    pub host: String,
    pub port: u16,
    pub expect: GateProbeExpect,
}

/// The verdict a probe sample expects, derived from the admitted policy —
/// the sample selection is data access over the policy's rules, never a
/// second policy evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateProbeExpect {
    /// The policy admits this destination.
    Admit,
    /// The policy refuses this destination.
    Deny,
}

/// The endpoint's reply to a [`GateProbeRequest`]: one outcome per sample, in
/// request order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateProbeResponse {
    pub results: Vec<GateProbeOutcome>,
}

/// The running gate's verdict for one sample. `reason` carries the gate's own
/// explanation for a `deny` (its `DenyReason` display form) so a mismatch
/// reads as a sentence rather than a code; it is absent for `admit` and
/// `malformed`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateProbeOutcome {
    pub host: String,
    pub port: u16,
    pub verdict: GateProbeVerdict,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// What the running gate actually decided for a sample.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateProbeVerdict {
    /// The gate admitted the destination.
    Admit,
    /// The gate refused the destination.
    Deny,
    /// The gate could not parse the sample as a destination.
    Malformed,
}

/// 16 MiB cap on one endpoint frame, matching the substitution endpoint's own
/// `MAX_FRAME_BYTES` so both ends of the socket enforce the same bound.
pub const MAX_ENDPOINT_FRAME_BYTES: usize = 16 * 1024 * 1024;

/// Write one endpoint frame: a 4-byte big-endian length prefix followed by
/// the payload bytes. This is the exact format the endpoint socket has always
/// spoken; the helpers live beside the wire types so every caller frames
/// identical bytes.
pub fn write_frame(writer: &mut impl std::io::Write, payload: &[u8]) -> std::io::Result<()> {
    let len = u32::try_from(payload.len())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "frame too large"))?;
    writer.write_all(&len.to_be_bytes())?;
    writer.write_all(payload)?;
    writer.flush()
}

/// Read one endpoint frame written by [`write_frame`], refusing a length
/// prefix above [`MAX_ENDPOINT_FRAME_BYTES`] before allocating the body
/// buffer. A truncated length prefix or body surfaces as `UnexpectedEof`.
pub fn read_frame(reader: &mut impl std::io::Read) -> std::io::Result<Vec<u8>> {
    let mut len = [0u8; 4];
    reader.read_exact(&mut len)?;
    let n = u32::from_be_bytes(len) as usize;
    if n > MAX_ENDPOINT_FRAME_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "frame too large",
        ));
    }
    let mut buf = vec![0u8; n];
    reader.read_exact(&mut buf)?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn probe_request() -> GateProbeRequest {
        GateProbeRequest {
            samples: vec![
                GateProbeSample {
                    host: "192.0.2.1".into(),
                    port: 9,
                    expect: GateProbeExpect::Deny,
                },
                GateProbeSample {
                    host: "api.example.com".into(),
                    port: 443,
                    expect: GateProbeExpect::Admit,
                },
            ],
        }
    }

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

    #[test]
    fn gate_probe_request_roundtrips() {
        let req = probe_request();
        let json = serde_json::to_string(&req).unwrap();
        assert_eq!(
            serde_json::from_str::<GateProbeRequest>(&json).unwrap(),
            req
        );
    }

    #[test]
    fn gate_probe_expect_uses_snake_case() {
        let json = serde_json::to_string(&GateProbeExpect::Admit).unwrap();
        assert_eq!(json, r#""admit""#);
        let json = serde_json::to_string(&GateProbeExpect::Deny).unwrap();
        assert_eq!(json, r#""deny""#);
    }

    #[test]
    fn gate_probe_response_roundtrips() {
        let resp = GateProbeResponse {
            results: vec![
                GateProbeOutcome {
                    host: "192.0.2.1".into(),
                    port: 9,
                    verdict: GateProbeVerdict::Deny,
                    reason: Some("192.0.2.1:9 is not admitted".into()),
                },
                GateProbeOutcome {
                    host: "api.example.com".into(),
                    port: 443,
                    verdict: GateProbeVerdict::Admit,
                    reason: None,
                },
                GateProbeOutcome {
                    host: "".into(),
                    port: 0,
                    verdict: GateProbeVerdict::Malformed,
                    reason: None,
                },
            ],
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert_eq!(
            serde_json::from_str::<GateProbeResponse>(&json).unwrap(),
            resp
        );
        // An absent reason must not appear as a null the server never sends.
        assert!(!json.contains("null"), "got: {json}");
    }

    #[test]
    fn gate_probe_verdict_uses_snake_case() {
        for (verdict, label) in [
            (GateProbeVerdict::Admit, "admit"),
            (GateProbeVerdict::Deny, "deny"),
            (GateProbeVerdict::Malformed, "malformed"),
        ] {
            let json = serde_json::to_string(&verdict).unwrap();
            assert_eq!(json, format!(r#""{label}""#), "got: {json}");
        }
    }

    #[test]
    fn gate_probe_request_rejects_unknown_fields() {
        let bad = r#"{"samples":[],"evil":1}"#;
        assert!(serde_json::from_str::<GateProbeRequest>(bad).is_err());
    }

    #[test]
    fn endpoint_request_untagged_parses_forward_first() {
        let wire = WireRequest {
            method: "POST".into(),
            url: "https://api.openai.com/v1".into(),
            headers: vec![],
            body_b64: String::new(),
        };
        let json = serde_json::to_string(&wire).unwrap();
        assert_eq!(
            serde_json::from_str::<EndpointRequest>(&json).unwrap(),
            EndpointRequest::Forward(wire)
        );
    }

    #[test]
    fn endpoint_request_untagged_parses_gate_probe_second() {
        let req = probe_request();
        let json = serde_json::to_string(&req).unwrap();
        assert_eq!(
            serde_json::from_str::<EndpointRequest>(&json).unwrap(),
            EndpointRequest::GateProbe(req)
        );
    }

    #[test]
    fn endpoint_request_untagged_rejects_garbage() {
        // Neither a WireRequest (no method/url/headers) nor a probe (no
        // samples): the frame must fail the parse, closing the connection.
        let garbage = r#"{"question":{"tool":"shell"}}"#;
        assert!(serde_json::from_str::<EndpointRequest>(garbage).is_err());
    }

    #[test]
    fn frame_roundtrips_through_a_cursor() {
        let payload = serde_json::to_vec(&probe_request()).unwrap();
        let mut buf = std::io::Cursor::new(Vec::new());
        write_frame(&mut buf, &payload).unwrap();
        let written = buf.get_ref().len();
        assert_eq!(
            written,
            payload.len() + 4,
            "frame is the 4-byte prefix plus the body"
        );
        buf.set_position(0);
        let read_back = read_frame(&mut buf).unwrap();
        assert_eq!(read_back, payload);
        assert_eq!(
            buf.position() as usize,
            written,
            "exactly one frame is consumed"
        );
    }

    #[test]
    fn read_frame_refuses_an_oversize_length_prefix_before_allocating() {
        let mut buf = std::io::Cursor::new((MAX_ENDPOINT_FRAME_BYTES as u32 + 1).to_be_bytes());
        let err = read_frame(&mut buf).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn read_frame_errors_on_a_truncated_length_prefix() {
        let mut buf = std::io::Cursor::new([0u8, 0, 1]);
        let err = read_frame(&mut buf).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn read_frame_errors_on_a_truncated_body() {
        let mut buf = std::io::Cursor::new([&5u32.to_be_bytes()[..], b"{\"a\""].concat());
        let err = read_frame(&mut buf).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
    }
}
