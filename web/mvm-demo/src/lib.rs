//! `#[wasm_bindgen]` shim exposing the wasm demo core to a browser Worker.
//!
//! The Worker calls this crate to make governance decisions (egress allow/deny,
//! placeholder substitution) using the same `mvm-contract` code the host tier
//! uses. This file stays a dumb adapter; the logic and tests live in
//! `mvm-contract`.

use std::collections::BTreeMap;

use mvm_contract::ir::host_is_bound as host_is_bound_core;
use mvm_contract::policy::dns_pin::{DnsPin, DnsPinRegistry};
use mvm_contract::policy::network_policy::NetworkPolicy;
use mvm_contract::policy::projection::{Proto, canonicalize_network_policy};
use mvm_contract::substitution::{find_placeholder, substitute_into};
use mvm_contract::verify::{
    PlanAuditEntry, SignedEnvelope, hash_line as hash_line_core, seal as seal_core,
    verify_audit_chain_bytes, verifying_key_from_hex,
};
use wasm_bindgen::prelude::*;

/// Human-readable limitation notice for the browser tier. The page renders this
/// from Rust so the disclaimer cannot drift from the code.
const CAPABILITY_NOTICE: &str = "This page enforces the same mvm NetworkPolicy, authority, and audit semantics that the host WasmBackend enforces, but it does so inside the browser's own WebAssembly engine rather than host wasmtime. The guest is a wasm32-wasip1 workload, not a hardware-virtualized Linux kernel, so this is a browser-tier sandbox — not an isolation boundary.";

fn demo_pins() -> DnsPinRegistry {
    let mut pins = DnsPinRegistry::new();
    pins.add(DnsPin::at(
        "api.openai.com",
        vec![core::net::IpAddr::V4(core::net::Ipv4Addr::new(
            13, 65, 147, 86,
        ))],
        DEMO_NOW,
        "2099-01-01T00:00:00Z",
    ));
    pins.add(DnsPin::at(
        "api.github.com",
        vec![core::net::IpAddr::V4(core::net::Ipv4Addr::new(
            140, 82, 121, 6,
        ))],
        DEMO_NOW,
        "2099-01-01T00:00:00Z",
    ));
    // Deterministic demo-only host. The browser Worker intercepts this host
    // and returns a mock response, so the allow path always succeeds without
    // depending on external CORS behavior or live DNS.
    pins.add(DnsPin::at(
        "echo.mvm.local",
        vec![core::net::IpAddr::V4(core::net::Ipv4Addr::new(
            192, 0, 2, 1,
        ))],
        DEMO_NOW,
        "2099-01-01T00:00:00Z",
    ));
    pins
}
const DEMO_URL: &str = "https://api.openai.com/v1/chat/completions";
const DEMO_PLACEHOLDER_TOKEN: &str = "mvm-secret-deadbeef";
const DEMO_SECRET_VALUE: &str = "sk-real-openai-key";
const DEMO_SIGNING_KEY_HEX: &str =
    "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
const DEMO_ALLOWED_HOSTS: &[&str] = &["api.openai.com", "echo.mvm.local"];

#[wasm_bindgen]
pub fn demo_capability_notice() -> String {
    String::from(CAPABILITY_NOTICE)
}

#[wasm_bindgen]
pub fn demo_signing_key_hex() -> String {
    String::from(DEMO_SIGNING_KEY_HEX)
}

#[wasm_bindgen]
pub fn demo_verifying_key_hex() -> String {
    let key = ed25519_signing_key_from_hex(DEMO_SIGNING_KEY_HEX)
        .expect("demo signing key is a valid 64-char hex secret");
    hex32(&key.verifying_key().to_bytes())
}

#[wasm_bindgen]
pub fn decide_egress(policy_json: &str, url: &str) -> String {
    match decide_egress_core(policy_json, url) {
        Ok(allowed) => serde_json::json!({ "ok": true, "allowed": allowed }).to_string(),
        Err(e) => serde_json::json!({ "ok": false, "error": e }).to_string(),
    }
}

fn decide_egress_core(policy_json: &str, url: &str) -> Result<bool, String> {
    let policy: NetworkPolicy =
        serde_json::from_str(policy_json).map_err(|e| format!("parse policy: {e}"))?;
    let pins = demo_pins();
    let canonical = canonicalize_network_policy(&policy, &pins, DEMO_NOW)
        .map_err(|e| format!("canonicalize policy: {e}"))?;
    let (host, port) = parse_url_host_port(url)?;
    let ip = lookup_host(host).ok_or_else(|| {
        format!(
            "browser demo cannot resolve host '{host}' (only api.openai.com, api.github.com, and echo.mvm.local have pinned IPs in this demo)",
        )
    })?;
    Ok(canonical.permits(&Proto::Tcp, ip, port))
}

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

#[wasm_bindgen]
pub fn validate_network_policy(policy_json: &str) -> String {
    let outcome = (|| -> Result<(), String> {
        let policy: NetworkPolicy =
            serde_json::from_str(policy_json).map_err(|e| format!("parse policy: {e}"))?;
        let _ = canonicalize_network_policy(&policy, &demo_pins(), DEMO_NOW)
            .map_err(|e| format!("canonicalize policy: {e}"))?;
        Ok(())
    })();
    match outcome {
        Ok(()) => serde_json::json!({ "ok": true }).to_string(),
        Err(e) => serde_json::json!({ "ok": false, "error": e }).to_string(),
    }
}

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

/// Run one of the three curated demo scenarios.
///
/// `scenario` is one of `allowed`, `denied`, `unbound`. `policy_json` is the
/// visitor-edited allow-list. `timestamp` is an RFC 3339 UTC timestamp for the
/// audit entry. Returns a JSON string describing the module view, destination
/// view, audit event kind, and a signed chain line.
#[wasm_bindgen]
pub fn run_scenario(scenario: &str, policy_json: &str, timestamp: &str) -> String {
    match run_scenario_core(scenario, policy_json, timestamp) {
        Ok(outcome) => serde_json::json!({
            "ok": true,
            "scenario": outcome.scenario,
            "allowed": outcome.allowed,
            "module_view": outcome.module_view,
            "destination_view": outcome.destination_view,
            "audit_event": outcome.audit_event,
            "chain_line": outcome.chain_line,
        })
        .to_string(),
        Err(e) => serde_json::json!({ "ok": false, "error": e }).to_string(),
    }
}

struct ScenarioOutcome {
    scenario: String,
    allowed: bool,
    module_view: String,
    destination_view: Option<String>,
    audit_event: String,
    chain_line: serde_json::Value,
}

fn run_scenario_core(
    scenario: &str,
    policy_json: &str,
    timestamp: &str,
) -> Result<ScenarioOutcome, String> {
    if !matches!(scenario, "allowed" | "denied" | "unbound") {
        return Err(format!("unknown scenario: {scenario}"));
    }

    let module_view = format!("Authorization: Bearer {DEMO_PLACEHOLDER_TOKEN}");
    let policy: NetworkPolicy =
        serde_json::from_str(policy_json).map_err(|e| format!("parse policy: {e}"))?;
    let canonical = canonicalize_network_policy(&policy, &demo_pins(), DEMO_NOW)
        .map_err(|e| format!("canonicalize policy: {e}"))?;
    let (demo_host, demo_port) = parse_url_host_port(DEMO_URL)?;
    let allowed = canonical.permits(
        &Proto::Tcp,
        lookup_host(demo_host).ok_or("demo fixture IP missing")?,
        demo_port,
    );

    if !allowed {
        let entry = audit_entry(timestamp, scenario, "egress.refused", None);
        return Ok(ScenarioOutcome {
            scenario: scenario.to_string(),
            allowed: false,
            module_view,
            destination_view: None,
            audit_event: "egress.refused".to_string(),
            chain_line: seal_entry(&entry)?,
        });
    }

    let bound = scenario == "allowed"
        && host_is_bound_core(
            &DEMO_ALLOWED_HOSTS
                .iter()
                .map(|h| h.to_string())
                .collect::<Vec<_>>(),
            demo_host,
        );
    if !bound {
        let entry = audit_entry(timestamp, scenario, "secret.placeholder_dropped", None);
        return Ok(ScenarioOutcome {
            scenario: scenario.to_string(),
            allowed: true,
            module_view,
            destination_view: Some("Authorization: Bearer <placeholder-dropped>".to_string()),
            audit_event: "secret.placeholder_dropped".to_string(),
            chain_line: seal_entry(&entry)?,
        });
    }

    let destination_view = substitute_into(&module_view, DEMO_PLACEHOLDER_TOKEN, DEMO_SECRET_VALUE);
    let mut labels = BTreeMap::new();
    labels.insert("destination".to_string(), demo_host.to_string());
    let entry = audit_entry(timestamp, scenario, "secret.substituted", Some(labels));
    Ok(ScenarioOutcome {
        scenario: scenario.to_string(),
        allowed: true,
        module_view,
        destination_view: Some(destination_view),
        audit_event: "secret.substituted".to_string(),
        chain_line: seal_entry(&entry)?,
    })
}

fn audit_entry(
    timestamp: &str,
    scenario: &str,
    event: &str,
    labels: Option<BTreeMap<String, String>>,
) -> PlanAuditEntry {
    let mut labels = labels.unwrap_or_default();
    labels.insert("scenario".to_string(), scenario.to_string());
    PlanAuditEntry {
        caller_commitment: None,
        timestamp: timestamp.to_string(),
        tenant: "demo".to_string(),
        plan_id: "plan-browser-demo".to_string(),
        plan_version: 1,
        bundle_id: None,
        bundle_version: None,
        image_name: "mvm-demo-module".to_string(),
        image_sha256: "0000000000000000000000000000000000000000000000000000000000000000"
            .to_string(),
        event: event.to_string(),
        labels,
    }
}

fn seal_entry(entry: &PlanAuditEntry) -> Result<serde_json::Value, String> {
    let prev_hash = [0u8; 32];
    let signing_key = ed25519_signing_key_from_hex(DEMO_SIGNING_KEY_HEX)?;
    let envelope =
        seal_core(entry.clone(), prev_hash, &signing_key).map_err(|e| format!("seal: {e}"))?;
    let json = serde_json::to_string(&envelope).map_err(|e| format!("serialize envelope: {e}"))?;
    serde_json::from_str(&json).map_err(|e| format!("reparse envelope: {e}"))
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

fn hex32(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_nibble(c: u8) -> Result<u8, String> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(format!("non-hex character {:?}", c as char)),
    }
}

fn parse_url_host_port(url: &str) -> Result<(&str, u16), String> {
    let without_scheme = url.rsplit("//").next().unwrap_or(url);
    let host_port = without_scheme.split('/').next().unwrap_or(without_scheme);
    match host_port.split_once(':') {
        Some((h, p)) => {
            let port = p.parse().map_err(|_| format!("bad port: {p}"))?;
            Ok((h, port))
        }
        None => Ok((host_port, 443)),
    }
}

fn lookup_host(host: &str) -> Option<core::net::IpAddr> {
    match host {
        "api.openai.com" => Some(core::net::IpAddr::V4(core::net::Ipv4Addr::new(
            13, 65, 147, 86,
        ))),
        "api.github.com" => Some(core::net::IpAddr::V4(core::net::Ipv4Addr::new(
            140, 82, 121, 6,
        ))),
        "echo.mvm.local" => Some(core::net::IpAddr::V4(core::net::Ipv4Addr::new(
            192, 0, 2, 1,
        ))),
        _ => None,
    }
}

/// Fixed "now" for the demo so the policy projection is deterministic.
const DEMO_NOW: &str = "2026-08-12T00:00:00Z";

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_bytes(name: &str) -> Vec<u8> {
        let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        std::fs::read(manifest.join("fixtures").join(format!("{name}.opt.wasm")))
            .expect("read fixture")
    }

    #[test]
    fn demo_verifying_key_is_stable() {
        assert_eq!(
            demo_verifying_key_hex(),
            "ff57575dc7af8bfc4d0837cc1ce2017b686a88145dc5579a958e3462fe9a908e"
        );
    }

    #[test]
    fn capability_notice_lists_browser_limitation() {
        let notice = demo_capability_notice();
        assert!(notice.contains("browser\'s own WebAssembly engine"));
        assert!(notice.contains("not an isolation boundary"));
    }

    #[test]
    fn fixture_modules_never_hold_the_real_secret() {
        for name in ["allowed", "denied", "unbound"] {
            let bytes = fixture_bytes(name);
            assert!(
                !bytes
                    .windows(DEMO_SECRET_VALUE.len())
                    .any(|w| w == DEMO_SECRET_VALUE.as_bytes()),
                "{name}.opt.wasm must never contain the real secret value"
            );
            assert!(
                bytes
                    .windows(DEMO_PLACEHOLDER_TOKEN.len())
                    .any(|w| w == DEMO_PLACEHOLDER_TOKEN.as_bytes()),
                "{name}.opt.wasm must contain the placeholder token the guest holds"
            );
        }
    }

    #[test]
    fn allowed_scenario_substitutes_secret_and_audits() {
        let policy = r#"{"type":"allowlist","rules":[{"host":"api.openai.com","port":443}]}"#;
        let out =
            run_scenario_core("allowed", policy, "2026-08-12T00:00:00Z").expect("allowed runs");
        assert!(out.allowed);
        assert!(out.module_view.contains(DEMO_PLACEHOLDER_TOKEN));
        assert!(!out.module_view.contains(DEMO_SECRET_VALUE));
        let dest = out.destination_view.expect("destination view present");
        assert!(dest.contains(DEMO_SECRET_VALUE));
        assert!(!dest.contains(DEMO_PLACEHOLDER_TOKEN));
        assert_eq!(out.audit_event, "secret.substituted");
        assert!(out.chain_line.get("signature").is_some());
    }

    #[test]
    fn denied_scenario_refuses_and_audits() {
        let policy = r#"{"type":"allowlist","rules":[]}"#;
        let out = run_scenario_core("denied", policy, "2026-08-12T00:00:00Z").expect("denied runs");
        assert!(!out.allowed);
        assert!(out.destination_view.is_none());
        assert_eq!(out.audit_event, "egress.refused");
    }

    #[test]
    fn unbound_scenario_drops_placeholder_and_audits() {
        let policy = r#"{"type":"allowlist","rules":[{"host":"api.openai.com","port":443}]}"#;
        let out =
            run_scenario_core("unbound", policy, "2026-08-12T00:00:00Z").expect("unbound runs");
        assert!(out.allowed);
        let dest = out.destination_view.expect("destination view present");
        assert!(!dest.contains(DEMO_SECRET_VALUE));
        assert!(!dest.contains(DEMO_PLACEHOLDER_TOKEN));
        assert_eq!(out.audit_event, "secret.placeholder_dropped");
    }

    #[test]
    fn fixture_parity_matches_host_witness_outcomes() {
        // The host witness (crates/mvm-hostd/tests/wasm_egress_witness.rs)
        // asserts the same three outcomes: allowed => substituted, denied =>
        // refused, unbound => placeholder dropped. The browser core uses the
        // same mvm-contract functions, so the scenarios must produce identical
        // event kinds.
        let allowed = run_scenario_core(
            "allowed",
            r#"{"type":"allowlist","rules":[{"host":"api.openai.com","port":443}]}"#,
            "2026-08-12T00:00:00Z",
        )
        .expect("allowed runs");
        assert_eq!(allowed.audit_event, "secret.substituted");

        let denied = run_scenario_core(
            "denied",
            r#"{"type":"allowlist","rules":[]}"#,
            "2026-08-12T00:00:00Z",
        )
        .expect("denied runs");
        assert_eq!(denied.audit_event, "egress.refused");

        let unbound = run_scenario_core(
            "unbound",
            r#"{"type":"allowlist","rules":[{"host":"api.openai.com","port":443}]}"#,
            "2026-08-12T00:00:00Z",
        )
        .expect("unbound runs");
        assert_eq!(unbound.audit_event, "secret.placeholder_dropped");
    }
}
