//! Chain-signed audit for egress secrets (claim 13).
//!
//! Two events, both in the `Secret` category, both carrying **metadata only** —
//! the secret name, the destination, the auth-type — and **never the value**.
//! This is claim 13's "no raw secret value crosses the audit chain": the label
//! set is fixed and value-free, so a chain reader (or a leaked chain file)
//! learns *where* a secret went, never *what* it is. The entries ride the same
//! chain-signed stream as the claim-8 plan events, so `verify_audit_chain`
//! (surfaced by `mvmctl audit verify`) detects any tampering.

use mvm_sdk::ir::AuthType;

use crate::supervisor::audit_recorder::{EventCategory, Recorder, RecorderError};

fn auth_type_label(t: AuthType) -> &'static str {
    match t {
        AuthType::Sigv4 => "sigv4",
        AuthType::Hmac => "hmac",
        AuthType::Bearer => "bearer",
        AuthType::Basic => "basic",
    }
}

/// Emit `secret.substituted { name, destination, auth_type }` — one per secret
/// the endpoint substituted into an outbound request. Metadata only (claim 13).
pub async fn emit_secret_substituted(
    recorder: &Recorder,
    secret_name: &str,
    destination: &str,
    auth_type: AuthType,
) -> Result<(), RecorderError> {
    recorder
        .record_unbound(
            EventCategory::Secret,
            "secret.substituted",
            [
                ("name".to_string(), secret_name.to_string()),
                ("destination".to_string(), destination.to_string()),
                (
                    "auth_type".to_string(),
                    auth_type_label(auth_type).to_string(),
                ),
            ],
        )
        .await
}

/// Emit `secret.redacted { destination, categories }` — the egress redactor
/// masked an *undeclared* secret-shaped / PII run out of an outbound request
/// before forwarding. `categories` is the comma-joined set
/// of rule names that fired (e.g. `openai-key,email`); the matched bytes are
/// never recorded (claim 13).
pub async fn emit_secret_redacted(
    recorder: &Recorder,
    destination: &str,
    categories: &str,
) -> Result<(), RecorderError> {
    recorder
        .record_unbound(
            EventCategory::Secret,
            "secret.redacted",
            [
                ("destination".to_string(), destination.to_string()),
                ("categories".to_string(), categories.to_string()),
            ],
        )
        .await
}

/// Emit `secret.placeholder_dropped { destination }` — a placeholder smuggled
/// onto the raw egress wire was dropped. Metadata only.
pub async fn emit_secret_placeholder_dropped(
    recorder: &Recorder,
    destination: &str,
) -> Result<(), RecorderError> {
    recorder
        .record_unbound(
            EventCategory::Secret,
            "secret.placeholder_dropped",
            [("destination".to_string(), destination.to_string())],
        )
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::supervisor::audit_file::{FileAuditSigner, verify_audit_chain};
    use ed25519_dalek::SigningKey;
    use mvm_core::plan::TenantId;
    use std::sync::Arc;
    use tempfile::tempdir;

    fn recorder_at(file: &std::path::Path) -> (Recorder, ed25519_dalek::VerifyingKey) {
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let vk = signing.verifying_key();
        let signer = FileAuditSigner::open_file(signing, file).unwrap();
        (
            Recorder::new(Arc::new(signer), TenantId("local".into())),
            vk,
        )
    }

    // The signed `entry` payloads only — the claim-13 surface. The opaque
    // base64 `signature`/`prev_hash` fields carry arbitrary bytes that can spell
    // any substring (the signature covers a wall-clock timestamp, so it varies
    // per run); scanning them for value leaks is nondeterministic and wrong.
    fn entry_payloads(chain: &str) -> String {
        chain
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| {
                let v: serde_json::Value = serde_json::from_str(l).unwrap();
                v["entry"].to_string()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[tokio::test]
    async fn substituted_event_is_metadata_only_and_chain_verifies() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("audit.jsonl");
        let (recorder, vk) = recorder_at(&file);

        emit_secret_substituted(&recorder, "openai", "api.openai.com", AuthType::Bearer)
            .await
            .unwrap();

        let chain = std::fs::read_to_string(&file).unwrap();
        assert!(chain.contains("secret.substituted"));
        assert!(chain.contains("openai"));
        assert!(chain.contains("api.openai.com"));
        assert!(chain.contains("bearer"));
        // claim 13: the value never appears in the signed entry.
        let payloads = entry_payloads(&chain);
        assert!(
            !payloads.contains("sk-live"),
            "audit chain must not carry the secret value: {payloads}"
        );

        assert_eq!(verify_audit_chain(&file, &vk).unwrap(), 1);
    }

    #[tokio::test]
    async fn a_tampered_entry_fails_verification() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("audit.jsonl");
        let (recorder, vk) = recorder_at(&file);
        emit_secret_substituted(&recorder, "openai", "api.openai.com", AuthType::Bearer)
            .await
            .unwrap();

        // Flip the destination label after signing.
        let tampered = std::fs::read_to_string(&file)
            .unwrap()
            .replace("api.openai.com", "evil.example.com");
        std::fs::write(&file, tampered).unwrap();
        assert!(verify_audit_chain(&file, &vk).is_err());
    }

    #[tokio::test]
    async fn redacted_event_records_categories_and_destination_only() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("audit.jsonl");
        let (recorder, vk) = recorder_at(&file);

        emit_secret_redacted(&recorder, "api.openai.com", "openai-key,email")
            .await
            .unwrap();

        let chain = std::fs::read_to_string(&file).unwrap();
        assert!(chain.contains("secret.redacted"));
        assert!(chain.contains("api.openai.com"));
        assert!(chain.contains("openai-key,email"));
        // claim 13: the masked bytes / value never appear — only category names.
        let payloads = entry_payloads(&chain);
        assert!(
            !payloads.contains("sk-") && !payloads.contains("XXX"),
            "audit chain must carry no matched bytes: {payloads}"
        );
        assert_eq!(verify_audit_chain(&file, &vk).unwrap(), 1);
    }

    #[tokio::test]
    async fn placeholder_dropped_event_records_destination() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("audit.jsonl");
        let (recorder, vk) = recorder_at(&file);
        emit_secret_placeholder_dropped(&recorder, "evil.example.com")
            .await
            .unwrap();
        let chain = std::fs::read_to_string(&file).unwrap();
        assert!(chain.contains("secret.placeholder_dropped"));
        assert!(chain.contains("evil.example.com"));
        assert_eq!(verify_audit_chain(&file, &vk).unwrap(), 1);
    }
}
