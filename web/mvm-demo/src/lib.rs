//! `#[wasm_bindgen]` shim exposing the wasm demo core to a browser Worker.
//!
//! The Worker calls this crate to make governance decisions (egress allow/deny,
//! placeholder substitution) using the same `mvm-contract` code the host tier
//! uses. This file stays a dumb adapter; the logic and tests live in
//! `mvm-contract`.

use mvm_contract::policy::dns_pin::DnsPinRegistry;
use mvm_contract::policy::projection::{Proto, canonicalize_network_policy};
use mvm_contract::substitution::{find_placeholder, substitute_into};
use mvm_contract::verify::{verify_audit_chain_bytes, verifying_key_from_hex};
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
