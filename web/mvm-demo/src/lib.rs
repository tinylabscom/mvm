//! `#[wasm_bindgen]` shim exposing the wasm demo core to a browser Worker.
//!
//! The Worker calls this crate to make governance decisions (egress allow/deny,
//! placeholder substitution) using the same `mvm-contract` code the host tier
//! uses. This file stays a dumb adapter; the logic and tests live in
//! `mvm-contract`.

use mvm_contract::ir::host_is_bound as host_is_bound_core;
use mvm_contract::policy::dns_pin::DnsPinRegistry;
use mvm_contract::policy::projection::{Proto, canonicalize_network_policy};
use mvm_contract::substitution::{find_placeholder, substitute_into};
use mvm_contract::verify::{
    PlanAuditEntry, SignedEnvelope, hash_line as hash_line_core, seal as seal_core,
    verify_audit_chain_bytes, verifying_key_from_hex,
};
use wasm_bindgen::prelude::*;

/// Parse a `NetworkPolicy` JSON string and return whether the policy would
/// admit an egress to `url`.
///
/// Returns `{"ok":true,"allowed":true}` or
/// `{"ok":false,"error":"…"}`.
#[wasm_bindgen]
pub fn decide_egress(policy_json: &str, url: &str) -> String {
    let outcome = (|| -> Result<bool, String> {
        let policy = serde_json::from_str(policy_json).map_err(|e| format!("parse policy: {e}"))?;
        let pins = DnsPinRegistry::default();
        let canonical = canonicalize_network_policy(&policy, &pins, DEMO_NOW)
            .map_err(|e| format!("canonicalize policy: {e}"))?;
        let (host, port) = parse_url_host_port(url)?;
        let ip =
            lookup_host(&host).ok_or_else(|| format!("demo fixture has no IP for host: {host}"))?;
        Ok(canonical.permits(&Proto::Tcp, ip, port))
    })();

    match outcome {
        Ok(allowed) => serde_json::json!({ "ok": true, "allowed": allowed }).to_string(),
        Err(e) => serde_json::json!({ "ok": false, "error": e }).to_string(),
    }
}

/// Replace the first placeholder token found in `text` with `value`.
///
/// Returns `{"ok":true,"text":"…"}` or `{"ok":false,"error":"…"}`.
#[wasm_bindgen]
pub fn substitute_placeholder(text: &str, value: &str) -> String {
    match find_placeholder(text) {
        Some(ph) => {
            let out = substitute_into(text, ph, value);
            serde_json::json!({ "ok": true, "text": out }).to_string()
        }
        None => serde_json::json!({ "ok": false, "error": "no placeholder found" }).to_string(),
    }
}

/// Verify a chain-signed audit stream against an Ed25519 public key.
///
/// Returns `{"ok":true,"count":N,"entries":[…]}` on success or
/// `{"ok":false,"error":"…"}` on failure.
#[wasm_bindgen]
pub fn verify(chain_bytes: &str, pubkey_hex: &str) -> String {
    let outcome = verifying_key_from_hex(pubkey_hex)
        .and_then(|key| verify_audit_chain_bytes(chain_bytes, &key));
    match outcome {
        Ok(chain) => serde_json::json!({
            "ok": true,
            "count": chain.count,
            "entries": chain.entries,
        })
        .to_string(),
        Err(e) => serde_json::json!({ "ok": false, "error": e.to_string() }).to_string(),
    }
}

/// Check whether `destination` is in the secret's `allowed_hosts` list.
///
/// `allowed_hosts_json` is a JSON array of host patterns; `destination` is
/// the host:port string from the egress request. Returns
/// `{"ok":true,"bound":true}` or `{"ok":false,"error":"…"}`.
#[wasm_bindgen]
pub fn host_is_bound(allowed_hosts_json: &str, destination: &str) -> String {
    let outcome = (|| -> Result<bool, String> {
        let allowed: Vec<String> =
            serde_json::from_str(allowed_hosts_json).map_err(|e| format!("parse hosts: {e}"))?;
        Ok(host_is_bound_core(&allowed, destination))
    })();
    match outcome {
        Ok(bound) => serde_json::json!({ "ok": true, "bound": bound }).to_string(),
        Err(e) => serde_json::json!({ "ok": false, "error": e }).to_string(),
    }
}

/// Sign an audit entry into a chain link that follows `prev_hash`.
///
/// `entry_json` is a `PlanAuditEntry`; `prev_hash_hex` is the 64-char hex of
/// the previous line's SHA-256 (genesis is 64 zeroes); `signing_key_hex` is
/// the 64-char hex Ed25519 private key. Returns the JSON `SignedEnvelope` or
/// an error object.
#[wasm_bindgen]
pub fn seal(entry_json: &str, prev_hash_hex: &str, signing_key_hex: &str) -> String {
    let outcome = (|| -> Result<String, String> {
        let entry: PlanAuditEntry =
            serde_json::from_str(entry_json).map_err(|e| format!("parse entry: {e}"))?;
        let prev_hash = decode_hex32(prev_hash_hex).map_err(|e| format!("prev_hash: {e}"))?;
        let signing_key = ed25519_signing_key_from_hex(signing_key_hex)?;
        let envelope: SignedEnvelope<PlanAuditEntry> =
            seal_core(entry, prev_hash, &signing_key).map_err(|e| format!("seal: {e}"))?;
        serde_json::to_string(&envelope).map_err(|e| format!("serialize envelope: {e}"))
    })();
    match outcome {
        Ok(json) => serde_json::json!({ "ok": true, "envelope": json }).to_string(),
        Err(e) => serde_json::json!({ "ok": false, "error": e }).to_string(),
    }
}

/// SHA-256 of `bytes` exposed for the demo so the Worker can advance the
/// chain hash without re-implementing the hashing rule.
#[wasm_bindgen]
pub fn hash_line(bytes: &[u8]) -> Vec<u8> {
    hash_line_core(bytes).to_vec()
}

fn ed25519_signing_key_from_hex(hex: &str) -> Result<ed25519_dalek::SigningKey, String> {
    let bytes = decode_hex32(hex)?;
    Ok(ed25519_dalek::SigningKey::from_bytes(&bytes))
}

fn decode_hex32(input: &str) -> Result<[u8; 32], String> {
    let s = input.trim();
    let s = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    if s.len() != 64 {
        return Err(format!("expected 64 hex chars, got {}", s.len()));
    }
    let mut out = [0u8; 32];
    let bytes = s.as_bytes();
    for (i, slot) in out.iter_mut().enumerate() {
        let hi = hex_nibble(bytes[i * 2])?;
        let lo = hex_nibble(bytes[i * 2 + 1])?;
        *slot = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_nibble(c: u8) -> Result<u8, String> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(format!("non-hex character {:?}", c as char)),
    }
}

/// Fixed "now" for the demo so the policy projection is deterministic.
const DEMO_NOW: &str = "2026-08-12T00:00:00Z";

fn parse_url_host_port(url: &str) -> Result<(String, u16), String> {
    // Demo-only: accept "https://host:port/path" or "host:port".
    let without_scheme = url.rsplit("//").next().unwrap_or(url);
    let host_port = without_scheme.split('/').next().unwrap_or(without_scheme);
    let (host, port) = match host_port.split_once(':') {
        Some((h, p)) => {
            let port = p.parse().map_err(|_| format!("bad port: {p}"))?;
            (h.to_string(), port)
        }
        None => (host_port.to_string(), 443),
    };
    Ok((host, port))
}

fn lookup_host(host: &str) -> Option<core::net::IpAddr> {
    // Demo-only fixed hostname→IP fixture. DNS pinning is out of scope for
    // the browser sandbox; the page states this limitation plainly.
    match host {
        "api.openai.com" => Some(core::net::IpAddr::V4(core::net::Ipv4Addr::new(
            13, 65, 147, 86,
        ))),
        "api.github.com" => Some(core::net::IpAddr::V4(core::net::Ipv4Addr::new(
            140, 82, 121, 6,
        ))),
        _ => None,
    }
}

/// Run one of the three curated demo scenarios.
///
/// `scenario` is one of `allowed`, `denied`, `unbound`. `policy_json` is the
/// visitor-edited allow-list. Returns a JSON string describing the module
/// view, destination view, and audit event kind.
#[wasm_bindgen]
pub fn run_scenario(scenario: &str, policy_json: &str) -> String {
    let url = "https://api.openai.com/v1/chat/completions";
    let placeholder = "mvm-secret-deadbeef";
    let secret_value = "sk-real-openai-key";

    let outcome = (|| -> Result<serde_json::Value, String> {
        let decision = serde_json::from_str::<serde_json::Value>(&decide_egress(policy_json, url))
            .map_err(|e| format!("decision parse: {e}"))?;
        let allowed = decision["allowed"].as_bool().unwrap_or(false);

        let module_view = format!("Authorization: Bearer {placeholder}");

        if !allowed {
            return Ok(serde_json::json!({
                "ok": true,
                "scenario": scenario,
                "allowed": false,
                "module_view": module_view,
                "destination_view": null,
                "audit_event": "egress.refused",
            }));
        }

        // Bound-check: only the `allowed` scenario has the secret bound to
        // api.openai.com; the `unbound` scenario admits the host but does not
        // bind the secret to it.
        let bound = match scenario {
            "allowed" => true,
            "unbound" => false,
            _ => false,
        };

        if !bound {
            return Ok(serde_json::json!({
                "ok": true,
                "scenario": scenario,
                "allowed": true,
                "module_view": module_view,
                "destination_view": "Authorization: Bearer <placeholder-dropped>",
                "audit_event": "secret.placeholder_dropped",
            }));
        }

        let substituted = serde_json::from_str::<serde_json::Value>(&substitute_placeholder(
            &module_view,
            secret_value,
        ))
        .map_err(|e| format!("substitution parse: {e}"))?;
        let destination_view = substituted["text"].as_str().unwrap_or("");

        Ok(serde_json::json!({
            "ok": true,
            "scenario": scenario,
            "allowed": true,
            "module_view": module_view,
            "destination_view": destination_view,
            "audit_event": "secret.substituted",
        }))
    })();

    match outcome {
        Ok(v) => v.to_string(),
        Err(e) => serde_json::json!({ "ok": false, "error": e }).to_string(),
    }
}
