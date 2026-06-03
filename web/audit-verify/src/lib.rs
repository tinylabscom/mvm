//! `#[wasm_bindgen]` shim exposing `mvm-verify` to a browser tab.
//!
//! The page (`index.html`) hands this two strings — the audit JSONL the
//! operator downloaded and the host signer's Ed25519 public key in hex —
//! and renders the JSON this returns. No host, no server: the wasm runs
//! the exact same chain verification `mvm-supervisor` runs natively
//! (ADR-069). Keeping the logic in `mvm-verify` (a real, tested
//! workspace crate) means this file stays a dumb adapter.

use mvm_verify::{verify_audit_chain_bytes, verifying_key_from_hex};
use wasm_bindgen::prelude::*;

/// Verify a chain-signed audit stream against an Ed25519 public key.
///
/// `jsonl` is the audit log text; `pubkey_hex` is the 32-byte key as 64
/// hex chars (optional `0x`). Returns a JSON string:
/// `{"ok":true,"count":N,"entries":[…]}` on success, or
/// `{"ok":false,"error":"…"}` on any failure (bad key, tamper, broken
/// chain). Returning JSON-as-string keeps the dependency surface to
/// `serde_json` alone — no `serde-wasm-bindgen`.
#[wasm_bindgen]
pub fn verify(jsonl: &str, pubkey_hex: &str) -> String {
    let outcome =
        verifying_key_from_hex(pubkey_hex).and_then(|key| verify_audit_chain_bytes(jsonl, &key));
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
