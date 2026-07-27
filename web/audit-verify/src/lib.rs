//! `#[wasm_bindgen]` shim exposing `mvm_protocol::verify` to a browser tab.
//!
//! The page (`index.html`) hands this two strings — the audit JSONL the
//! operator downloaded and the host signer's Ed25519 public key in hex —
//! and renders the JSON this returns. No host, no server: the wasm runs
//! the exact same chain verification `mvm-supervisor` runs natively.
//! Keeping the logic in `mvm-protocol` (a real, tested workspace crate)
//! means this file stays a dumb adapter.

use mvm_protocol::merkle::{
    InclusionProof, SignedAuditRoot, verify_inclusion as merkle_verify_inclusion,
    verify_signed_root as merkle_verify_signed_root,
};
use mvm_protocol::verify::{verify_audit_chain_bytes, verifying_key_from_hex};
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

/// Verify that an [`InclusionProof`] is internally consistent — it folds to
/// its own embedded root. This is only HALF a membership check: it does not
/// prove membership in a real published log. Use [`verify_membership`] to
/// bind the proof to a host-signed root.
///
/// `proof_json` is the serialized proof. Returns
/// `{"ok":true,"leaf_index":i,"tree_size":n,"root":"<hex>"}` on success or
/// `{"ok":false,"error":"…"}` otherwise.
#[wasm_bindgen]
pub fn verify_inclusion(proof_json: &str) -> String {
    let outcome = serde_json::from_str::<InclusionProof>(proof_json)
        .map_err(|e| format!("decode proof: {e}"))
        .and_then(|proof| {
            merkle_verify_inclusion(&proof)
                .map(|_| proof)
                .map_err(|e| e.to_string())
        });
    match outcome {
        Ok(proof) => serde_json::json!({
            "ok": true,
            "leaf_index": proof.leaf_index,
            "tree_size": proof.tree_size,
            "root": proof.root,
        })
        .to_string(),
        Err(e) => serde_json::json!({ "ok": false, "error": e }).to_string(),
    }
}

/// Verify a [`SignedAuditRoot`]'s Ed25519 signature against a trusted host
/// key. `pubkey_hex` is the 32-byte key as 64 hex chars. Returns
/// `{"ok":true,"tenant":"…","tree_size":n,"root":"<hex>"}` on success or
/// `{"ok":false,"error":"…"}` otherwise.
#[wasm_bindgen]
pub fn verify_signed_root(root_json: &str, pubkey_hex: &str) -> String {
    let outcome = (|| -> Result<SignedAuditRoot, String> {
        let vk = verifying_key_from_hex(pubkey_hex).map_err(|e| e.to_string())?;
        let root: SignedAuditRoot =
            serde_json::from_str(root_json).map_err(|e| format!("decode root: {e}"))?;
        merkle_verify_signed_root(&root, &vk).map_err(|e| e.to_string())?;
        Ok(root)
    })();
    match outcome {
        Ok(root) => serde_json::json!({
            "ok": true,
            "tenant": root.tenant,
            "tree_size": root.tree_size,
            "root": root.root_hash,
        })
        .to_string(),
        Err(e) => serde_json::json!({ "ok": false, "error": e }).to_string(),
    }
}

/// The full inclusion-membership check a browser runs with no server: the
/// exact composition `mvmctl trust audit verify-inclusion` enforces
/// host-side. In order, fail-closed:
///   1. the signed root verifies under the trusted host key;
///   2. the inclusion proof is internally consistent;
///   3. the proof binds to THIS signed root (`root` + `tree_size` match).
///
/// A self-consistent proof over a different (unsigned) root is rejected at
/// step 3. Returns `{"ok":true,…}` naming the bound root on success, or
/// `{"ok":false,"error":"<which check failed>"}`.
#[wasm_bindgen]
pub fn verify_membership(proof_json: &str, root_json: &str, pubkey_hex: &str) -> String {
    let outcome = (|| -> Result<InclusionProof, String> {
        let vk = verifying_key_from_hex(pubkey_hex).map_err(|e| e.to_string())?;
        let proof: InclusionProof =
            serde_json::from_str(proof_json).map_err(|e| format!("decode proof: {e}"))?;
        let root: SignedAuditRoot =
            serde_json::from_str(root_json).map_err(|e| format!("decode root: {e}"))?;
        merkle_verify_signed_root(&root, &vk)
            .map_err(|e| format!("signed-root verification failed: {e}"))?;
        merkle_verify_inclusion(&proof)
            .map_err(|e| format!("inclusion-proof verification failed: {e}"))?;
        if proof.root != root.root_hash {
            return Err(format!(
                "root binding failed: proof root {} does not match the host-signed root {}",
                proof.root, root.root_hash
            ));
        }
        if proof.tree_size != root.tree_size {
            return Err(format!(
                "tree-size binding failed: proof tree_size {} does not match the host-signed \
                 tree_size {}",
                proof.tree_size, root.tree_size
            ));
        }
        Ok(proof)
    })();
    match outcome {
        Ok(proof) => serde_json::json!({
            "ok": true,
            "leaf_index": proof.leaf_index,
            "tree_size": proof.tree_size,
            "root": proof.root,
        })
        .to_string(),
        Err(e) => serde_json::json!({ "ok": false, "error": e }).to_string(),
    }
}
