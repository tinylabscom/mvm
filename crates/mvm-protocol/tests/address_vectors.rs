//! Replay vectors: frozen inputs and the addresses they must produce.
//!
//! The tests already covering these two surfaces are *relational* — a hash is
//! stable for identical input, independent of key order, different for
//! different values, and 64 hex characters long. Every one of those still
//! passes if the canonicalization changes and every address in the tree moves
//! at once, which is exactly the drift that matters: a `serde_jcs` bump, a
//! serde field reorder, or a normalization change silently re-addresses
//! artifacts that are already published.
//!
//! A frozen expected value is the only kind of test that catches it. These are
//! seeded from current shipped behaviour, so they pin what ships today rather
//! than asserting what it ought to be — including the fact that `ir_hash` does
//! not NFC-normalize, which is recorded here as a vector rather than silently
//! changed.
//!
//! **Regenerating is a deliberate act.** `MVM_PRINT_ADDRESS_VECTORS=1` prints
//! the computed values instead of asserting. If a diff to this file is not
//! accompanied by a reason an address legitimately moved, the change is a bug.

use mvm_protocol::ir::ir_hash;
use mvm_protocol::merkle::{interior_hash, leaf_hash, merkle_root};
use serde_json::json;

/// Print-instead-of-assert mode, for reseeding after an intended change.
fn printing() -> bool {
    std::env::var_os("MVM_PRINT_ADDRESS_VECTORS").is_some()
}

fn check(surface: &str, name: &str, actual: &str, expected: &str) {
    if printing() {
        println!("{surface}\t{name}\t{actual}");
        return;
    }
    assert_eq!(
        actual, expected,
        "{surface}/{name}: address moved. If this was intended, say why in the \
         commit — every published artifact addressed by this surface just changed."
    );
}

fn hex32(b: &[u8; 32]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[test]
fn ir_hash_vectors_are_frozen() {
    let cases: &[(&str, serde_json::Value, &str)] = &[
        (
            "empty-object",
            json!({}),
            "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
        ),
        (
            "empty-array",
            json!([]),
            "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
        ),
        (
            "flat-scalars",
            json!({"a": 1, "b": "two", "c": true, "d": null}),
            "eb2c149467b56cfad324e3c07e2eb850f0481017871fe2250e3d21c9d0ba1fdc",
        ),
        (
            "key-order-differs-from-flat-scalars",
            json!({"d": null, "c": true, "b": "two", "a": 1}),
            "eb2c149467b56cfad324e3c07e2eb850f0481017871fe2250e3d21c9d0ba1fdc",
        ),
        (
            "nested",
            json!({"outer": {"inner": [1, 2, {"deep": "value"}]}}),
            "e361435609b30f7c00566014faf6bfb266eab37e191e625d3de7ade4c5ef8b59",
        ),
        // The Unicode cases are where canonicalizers actually diverge. JCS
        // sorts by UTF-16 code unit, which is not the same order as UTF-8 or
        // as codepoint once astral-plane keys are involved.
        (
            "astral-plane-keys",
            json!({"\u{1F600}": 1, "\u{FFFD}": 2, "z": 3}),
            "7b73feb282b2355e697ecfe8ab79d2ef3ad555b714ed783ce1fc0efe41c541de",
        ),
        // NFC and NFD forms of the same grapheme. `ir_hash` does not normalize,
        // so these are two different addresses. That is the shipped behaviour;
        // pinning it means a future decision to normalize shows up here.
        (
            "nfc-precomposed",
            json!({"k": "\u{00E9}"}),
            "0ca09f1dffb485d259fc791100d48ad7ae9c17f52a2bb07b608c0e28fbca34a1",
        ),
        (
            "nfd-decomposed",
            json!({"k": "e\u{0301}"}),
            "4cb477ab754099c91e4c79f77deaab085090978b8abbc981c8eefde872575da8",
        ),
    ];

    for (name, input, expected) in cases {
        let actual = ir_hash(input).expect("serializable");
        check("ir_hash", name, &actual, expected);
    }
}

#[test]
fn merkle_vectors_are_frozen() {
    // RFC 6962 domain separation: a leaf is prefixed 0x00, an interior node
    // 0x01, which is what stops a leaf being replayed as an interior node.
    let leaf = leaf_hash(b"entry-one");
    check(
        "merkle.leaf",
        "entry-one",
        &hex32(&leaf),
        "08f1800af44efa4a000b998ebc592b80a4002acab27af8284ae855fee53c85ad",
    );

    let interior = interior_hash(&leaf_hash(b"a"), &leaf_hash(b"b"));
    check(
        "merkle.interior",
        "a|b",
        &hex32(&interior),
        "b137985ff484fb600db93107c77b0365c80d78f5b429ded0fd97361d077999eb",
    );

    let cases: &[(&str, &[&str], &str)] = &[
        (
            "single-leaf",
            &["only"],
            "48823b3c6133664ce7b6219a005ad5ed7b5a91a69a0aa800cc51ce1cd4086955",
        ),
        (
            "two-leaves",
            &["a", "b"],
            "b137985ff484fb600db93107c77b0365c80d78f5b429ded0fd97361d077999eb",
        ),
        // An odd count is where a Merkle implementation most often diverges:
        // RFC 6962 promotes the tail rather than duplicating it, which is what
        // makes it immune to the duplicate-leaf forgery Bitcoin's tree allows.
        (
            "three-leaves-odd-tail",
            &["a", "b", "c"],
            "36642e73c2540ab121e3a6bf9545b0a24982cd830eb13d3cd19de3ce6c021ec1",
        ),
        (
            "five-leaves",
            &["a", "b", "c", "d", "e"],
            "fe14a5426fbd70c0fa73f52342afed0da0bd23c4838662ccf6b88a3070ead97b",
        ),
    ];

    for (name, leaves, expected) in cases {
        let root = merkle_root(leaves);
        check("merkle.root", name, &hex32(&root), expected);
    }
}
