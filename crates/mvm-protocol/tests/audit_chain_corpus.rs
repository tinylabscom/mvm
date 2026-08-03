//! The `no_std` verifier, over the same frozen bytes the host verifier reads.
//!
//! Two implementations of the audit-chain format live in this workspace: the
//! file-based host verifier in `mvm-hostd`, and the `no_std` mirror here that
//! also builds for wasm and bare metal. An oracle bar means little if each only
//! ever sees input it produced itself, so both read one committed corpus.
//!
//! The corpus is embedded with `include_str!` rather than read at runtime,
//! which is what lets this same test execute under `wasm32-wasip1` where there
//! is no filesystem to read from. `mvm-hostd` owns generating it — see the
//! `frozen_corpus` module there — and asserts it still matches what the signer
//! emits, so the two ends cannot drift apart silently.

use mvm_protocol::verify::{AuditVerifyError, verify_audit_chain_bytes, verifying_key_from_hex};

const CHAIN: &str = include_str!("../../../tests/vectors/audit-chain-v1.jsonl");
const PUBKEY_HEX: &str = include_str!("../../../tests/vectors/audit-chain-v1.pubkey");

/// The key type is private to `verify`, so hand the parsed key straight to
/// each call rather than naming it.
macro_rules! key {
    () => {
        verifying_key_from_hex(PUBKEY_HEX.trim()).expect("corpus verifying key parses")
    };
}

#[test]
fn no_std_verifier_accepts_the_same_corpus_the_host_verifier_does() {
    let verified = verify_audit_chain_bytes(CHAIN, &key!())
        .expect("the no_std mirror must accept a chain the host signer wrote");

    assert_eq!(verified.count, 3);
    assert_eq!(verified.entries[0].event, "plan.launched");
    assert_eq!(verified.entries[1].event, "plan.admitted");
    assert_eq!(verified.entries[2].event, "checkpoint.forked");
    assert_eq!(verified.entries[0].tenant, "tenant-frozen");
}

#[test]
fn optional_bundle_fields_survive_the_mirror() {
    // `bundle_id`/`bundle_version` are `skip_serializing_if = "Option::is_none"`
    // upstream. If the mirror disagreed about when they appear on the wire, the
    // signed bytes would not reconstruct and the signature would fail — so this
    // is really a check that both sides agree on absence, not just presence.
    let verified = verify_audit_chain_bytes(CHAIN, &key!()).expect("corpus verifies");
    let admitted = &verified.entries[1];
    assert_eq!(admitted.event, "plan.admitted");
}

#[test]
fn content_address_labels_round_trip_through_the_mirror() {
    // Chain-anchored lineage reads these values back, so an implementation
    // that dropped or reordered labels would break fork verification while
    // still "verifying" the chain.
    let forked_line = CHAIN.lines().nth(2).expect("third entry present");
    let envelope: mvm_protocol::verify::SignedEnvelope =
        serde_json::from_str(forked_line).expect("mirror parses the forked entry");

    assert_eq!(
        envelope
            .entry
            .labels
            .get("parent_digest")
            .map(String::as_str),
        Some(format!("sha256:{}", "b".repeat(64)).as_str())
    );
    assert_eq!(
        envelope
            .entry
            .labels
            .get("child_digest")
            .map(String::as_str),
        Some(format!("sha256:{}", "c".repeat(64)).as_str())
    );
}

#[test]
fn a_tampered_corpus_is_rejected() {
    let tampered = CHAIN.replacen("plan.launched", "plan.hijacked", 1);
    let err = verify_audit_chain_bytes(&tampered, &key!())
        .expect_err("a mutated event name must not verify");
    assert_eq!(err, AuditVerifyError::SignatureInvalid { line: 0 });
}

#[test]
fn a_reordered_corpus_breaks_the_chain() {
    // Signatures alone do not order entries; the `prev_hash` spine does. Swap
    // two validly-signed lines and the chain must fail even though every
    // signature on its own is intact.
    let lines: Vec<&str> = CHAIN.lines().collect();
    let swapped = format!("{}\n{}\n{}\n", lines[1], lines[0], lines[2]);
    assert!(
        verify_audit_chain_bytes(&swapped, &key!()).is_err(),
        "reordering validly-signed entries must not verify"
    );
}
