//! Frozen vectors for the audit chain's canonical signed bytes.
//!
//! `address_vectors.rs` covers `ir_hash` and the Merkle tree. The audit
//! chain's signed bytes — the thing a third party actually verifies — had no
//! frozen vector, and `mvm-contract` is meant to reach the browser, so a
//! second verifier implementation is coming.
//!
//! These pin the three cases where independent JSON implementations actually
//! diverge, and which the existing corpus exercises none of:
//!
//! 1. **A non-ASCII string.** Escaping is where encoders differ: `é` may be
//!    emitted raw as UTF-8 or as `é`, and the two are different bytes
//!    under the same signature.
//! 2. **An integer above 2^53.** Beyond that, a JSON number cannot round-trip
//!    through an IEEE-754 double, and an implementation that parses numbers as
//!    doubles silently changes the value.
//! 3. **A float where an integer is expected.** It must be refused, not
//!    rounded — rounding turns a malformed line into a valid-looking one.
//!
//! What these tests pin is the *decision*, not just today's behaviour: a
//! second implementation that accepts what these refuse is wrong, and one that
//! refuses what these accept is wrong.

use mvm_contract::verify::PlanAuditEntry;

/// The minimum shape, with one field swapped per case.
fn entry_json(plan_version: &str, tenant: &str) -> String {
    format!(
        r#"{{"timestamp":"2020-01-01T00:00:00Z","tenant":"{tenant}","plan_id":"p",
"plan_version":{plan_version},"image_name":"i","image_sha256":"s","event":"plan.admitted",
"labels":{{}}}}"#
    )
    .replace('\n', "")
}

/// Non-ASCII survives a decode/encode round trip **byte for byte**.
///
/// The assertion that matters is the re-encoded bytes, not the decoded string.
/// A verifier that decodes `é` correctly but re-emits it as `é` computes a
/// different hash over the same logical entry, and the chain breaks for a
/// reason nobody can see by reading either copy.
#[test]
fn non_ascii_round_trips_byte_for_byte() {
    // Raw UTF-8 in the source bytes, deliberately not escaped.
    let json = entry_json("1", "té-nant-日本-🔒");
    let entry: PlanAuditEntry = serde_json::from_str(&json).expect("a non-ASCII tenant must parse");
    assert_eq!(entry.tenant, "té-nant-日本-🔒");

    let reencoded = serde_json::to_vec(&entry).expect("re-encode");
    let decoded_again: PlanAuditEntry =
        serde_json::from_slice(&reencoded).expect("re-encoded bytes must parse");
    assert_eq!(
        decoded_again, entry,
        "a non-ASCII entry must survive decode -> encode -> decode unchanged"
    );

    // And the bytes are raw UTF-8, not \u escapes: an implementation that
    // escapes non-ASCII produces different signed bytes for the same entry.
    let as_str = String::from_utf8(reencoded).expect("canonical bytes are UTF-8");
    assert!(
        as_str.contains("té-nant-日本-🔒"),
        "non-ASCII must be emitted raw, not \\u-escaped: {as_str}"
    );
    assert!(
        !as_str.contains("\\u00e9"),
        "an escaped encoding is different bytes under the same signature: {as_str}"
    );
}

/// An integer past the double-precision boundary is refused, not rounded.
///
/// Note *why* it is refused today: `plan_version` is a `u32`, so 2^53+1 is out
/// of range for a narrower reason than the precision boundary. That is a
/// stronger refusal than the one this vector is about, and it means **the
/// precision concern is currently unexercised by the type system** — a future
/// `u64` or `i64` field in the signed entry would not inherit this protection
/// and would need its own vector. Pinned here so that gap is visible rather
/// than discovered by a verifier that disagrees.
#[test]
fn an_integer_past_the_double_boundary_is_refused_not_rounded() {
    // 2^53 + 1: the smallest integer an IEEE-754 double cannot represent.
    let json = entry_json("9007199254740993", "tenant");
    let parsed: Result<PlanAuditEntry, _> = serde_json::from_str(&json);
    assert!(
        parsed.is_err(),
        "2^53+1 must be refused; silently rounding it changes what was signed"
    );

    // The boundary value itself is also out of u32 range, so both sides of the
    // boundary refuse today. Asserted so a widening of the field type shows up
    // here as a behaviour change rather than as silence.
    let at_boundary = entry_json("9007199254740992", "tenant");
    assert!(
        serde_json::from_str::<PlanAuditEntry>(&at_boundary).is_err(),
        "2^53 is likewise outside the current field type"
    );
}

/// A float where an integer is expected is refused, including a float that
/// happens to be integral.
///
/// `1.0` is the interesting one. An implementation that accepts it "because it
/// is really an integer" has decided that two distinct byte sequences are the
/// same entry, which is exactly the ambiguity a signature must not have.
#[test]
fn a_float_is_refused_even_when_it_is_integral() {
    for value in ["1.5", "1.0", "1e2", "0.0"] {
        let json = entry_json(value, "tenant");
        assert!(
            serde_json::from_str::<PlanAuditEntry>(&json).is_err(),
            "float literal {value} must be refused in an integer field, not coerced"
        );
    }
}

/// Integers that *are* in range still parse, so the refusals above are about
/// shape rather than a parser that rejects everything.
#[test]
fn an_ordinary_integer_still_parses() {
    let entry: PlanAuditEntry =
        serde_json::from_str(&entry_json("7", "tenant")).expect("a plain integer must parse");
    assert_eq!(entry.plan_version, 7);
}

/// Key order does not change the decoded entry, but it *does* change the
/// bytes. Pinned because it is the other place two implementations diverge:
/// one that re-serializes from a `HashMap` emits a different order per run.
#[test]
fn labels_serialize_in_a_stable_order() {
    let json = r#"{"timestamp":"2020-01-01T00:00:00Z","tenant":"t","plan_id":"p","plan_version":1,"image_name":"i","image_sha256":"s","event":"e","labels":{"zulu":"1","alpha":"2","mike":"3"}}"#;
    let entry: PlanAuditEntry = serde_json::from_str(json).expect("parses");

    let once = serde_json::to_vec(&entry).expect("encode");
    let twice = serde_json::to_vec(&entry).expect("encode again");
    assert_eq!(once, twice, "encoding must be deterministic across calls");

    let as_str = String::from_utf8(once).expect("utf8");
    let alpha = as_str.find("alpha").expect("alpha present");
    let mike = as_str.find("mike").expect("mike present");
    let zulu = as_str.find("zulu").expect("zulu present");
    assert!(
        alpha < mike && mike < zulu,
        "labels must serialize in sorted key order regardless of input order: {as_str}"
    );
}
