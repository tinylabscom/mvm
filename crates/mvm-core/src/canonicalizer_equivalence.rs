//! Drift-lock between the two RFC 8785 realizations this workspace carries.
//!
//! `mvm_contract::ir::canonicalize` (the load-bearing hand-rolled `no_std`
//! JCS writer that feeds `ir_hash`) and `serde_jcs` (the canonicalizer used by
//! [`crate::workload_address::workload_address`]) are independent
//! implementations of the same canonical form. Nothing else proves they emit
//! byte-identical output, so a change to either one could silently make an
//! `ir_hash` disagree with the unnormalized JCS bytes used to derive a
//! `WorkloadAddress` for the same workload.
//!
//! These tests assert byte-for-byte agreement over a corpus of divergence-prone
//! `Workload` shapes (astral-plane map keys, escaped string values, large
//! integers, nested/empty containers), plus the digest chain
//! `ir_hash == hex(sha256(serde_jcs))`. `WorkloadAddress` applies the UOR-ADDR
//! Unicode NFC normalization boundary before hashing, so it is intentionally
//! a separate identity for non-NFC input.
//!
//! The two realizations already agree on every shape, including astral-plane
//! keys: both order object keys by Unicode scalar value. The hand-rolled writer
//! sorts `str` keys directly; `serde_jcs` sorts on each key's serialized UTF-8
//! bytes, whose lexicographic order is identical to scalar-value order. So this
//! is a lock against future drift, not a witness of an existing gap.
//! Test-only; it introduces no runtime code.

#[cfg(test)]
mod tests {
    use crate::workload_address::workload_address;
    use mvm_contract::ir::{
        App, Entrypoint, EnvValue, Image, Resources, Source, Workload, canonicalize, ir_hash,
    };
    use sha2::{Digest, Sha256};
    use std::collections::BTreeMap;

    fn base_workload() -> Workload {
        Workload {
            schema_version: "0.1".to_string(),
            id: "hello".to_string(),
            apps: vec![base_app()],
            volumes: vec![],
            extensions: BTreeMap::new(),
        }
    }

    fn base_app() -> App {
        App {
            name: "hello".to_string(),
            source: Source::LocalPath {
                path: ".".to_string(),
                include: vec!["**".to_string()],
                exclude: vec![],
            },
            image: Image::NixPackages {
                packages: vec!["python312".to_string()],
            },
            entrypoints: vec![Entrypoint::Command {
                command: vec!["python".to_string(), "-m".to_string(), "hello".to_string()],
                working_dir: "/app".to_string(),
                env: BTreeMap::new(),
            }],
            env: BTreeMap::new(),
            mounts: vec![],
            network: None,
            resources: Resources {
                cpu_cores: 1,
                memory_mb: 256,
                rootfs_size_mb: 512,
            },
            dependencies: None,
            threat_tier: Default::default(),
            addons: vec![],
            hooks: Default::default(),
            files: vec![],
            health_check: None,
        }
    }

    fn literal(value: &str) -> EnvValue {
        EnvValue::Literal {
            value: value.to_string(),
        }
    }

    /// Divergence-prone corpus, each entry `(label, workload)`.
    fn corpus() -> Vec<(&'static str, Workload)> {
        let mut cases: Vec<(&'static str, Workload)> = Vec::new();

        cases.push(("base", base_workload()));

        // The key probe. RFC 8785 mandates ordering object keys by UTF-16 code
        // units, under which U+10000 sorts before U+FFFF (its leading surrogate
        // 0xD800 < 0xFFFF) — opposite to a scalar-value sort. serde_jcs 0.1.0
        // does NOT implement that: it orders keys by their UTF-8 byte value,
        // which coincides with the hand-rolled writer's scalar-value `str` sort.
        // This entry pins that coincidence as a drift-lock; it is not evidence
        // of RFC 8785 conformance (see this module's header).
        {
            let mut w = base_workload();
            w.extensions
                .insert("\u{FFFF}".to_string(), serde_json::json!(1));
            w.extensions
                .insert("\u{10000}".to_string(), serde_json::json!(2));
            w.extensions
                .insert("\u{1F600}".to_string(), serde_json::json!(3));
            w.extensions.insert("a".to_string(), serde_json::json!(4));
            cases.push(("astral-plane-extension-keys", w));
        }

        // Same probe, second string-keyed map: an app's env.
        {
            let mut w = base_workload();
            let mut env = BTreeMap::new();
            env.insert("\u{10000}".to_string(), literal("astral"));
            env.insert("\u{FFFF}".to_string(), literal("bmp-max"));
            env.insert("\u{1F600}".to_string(), literal("emoji"));
            w.apps[0].env = env;
            cases.push(("astral-plane-env-keys", w));
        }

        // Escaping parity: control chars, quote, backslash, newline in a value.
        {
            let mut w = base_workload();
            let mut env = BTreeMap::new();
            env.insert(
                "escapes".to_string(),
                literal("a\"b\\c\nd\te\rf\u{08}g\u{0c}h\u{01}i\u{1f}j"),
            );
            w.apps[0].env = env;
            cases.push(("escaped-string-values", w));
        }

        // Multi-byte BMP characters in values should already agree.
        {
            let mut w = base_workload();
            let mut env = BTreeMap::new();
            env.insert("bmp".to_string(), literal("café 你好 Ω"));
            w.apps[0].env = env;
            cases.push(("multibyte-bmp-values", w));
        }

        // Large integer fields near the u32 ceiling.
        {
            let mut w = base_workload();
            w.apps[0].resources = Resources {
                cpu_cores: u16::MAX,
                memory_mb: u32::MAX,
                rootfs_size_mb: u32::MAX - 1,
            };
            cases.push(("large-integers", w));
        }

        // Nested arrays/objects and empty containers in the extension bag.
        {
            let mut w = base_workload();
            w.extensions.insert(
                "nested".to_string(),
                serde_json::json!({
                    "z": [3, 2, 1],
                    "a": {"b": {"c": [true, false, null]}},
                    "empty_obj": {},
                    "empty_arr": [],
                }),
            );
            cases.push(("nested-and-empty-containers", w));
        }

        cases
    }

    fn hex_sha256(bytes: &[u8]) -> String {
        hex::encode(Sha256::digest(bytes))
    }

    /// Report the first differing byte so a regression points at *where* the
    /// two realizations drift, not merely *that* they do.
    fn assert_same_bytes(label: &str, hand_rolled: &[u8], jcs: &[u8]) {
        if hand_rolled == jcs {
            return;
        }
        let at = hand_rolled
            .iter()
            .zip(jcs.iter())
            .position(|(a, b)| a != b)
            .unwrap_or_else(|| hand_rolled.len().min(jcs.len()));
        panic!(
            "canonical byte divergence for {label:?} at offset {at}\n  ir::canonicalize: {}\n  serde_jcs:        {}",
            String::from_utf8_lossy(hand_rolled),
            String::from_utf8_lossy(jcs),
        );
    }

    #[test]
    fn ir_canonicalize_matches_serde_jcs_byte_for_byte() {
        for (label, w) in corpus() {
            let hand_rolled = canonicalize(&w).expect("canonicalize").into_bytes();
            let jcs = serde_jcs::to_vec(&w).expect("serde_jcs");
            assert_same_bytes(label, &hand_rolled, &jcs);
        }
    }

    #[test]
    fn ir_hash_digest_chain_agrees_end_to_end() {
        for (label, w) in corpus() {
            let jcs = serde_jcs::to_vec(&w).expect("serde_jcs");
            let ih = ir_hash(&w).expect("ir_hash");
            assert_eq!(ih, hex_sha256(&jcs), "ir_hash vs sha256(jcs) for {label:?}");
        }
    }

    #[test]
    fn workload_address_normalizes_unicode_before_hashing() {
        let mut composed = base_workload();
        composed.id = "café".to_string();
        let mut decomposed = base_workload();
        decomposed.id = "cafe\u{301}".to_string();

        let composed_address = workload_address(&composed).expect("workload address");
        let decomposed_address = workload_address(&decomposed).expect("workload address");
        assert_eq!(composed_address, decomposed_address);
        assert_ne!(
            ir_hash(&composed).expect("ir hash"),
            ir_hash(&decomposed).expect("ir hash"),
            "the internal IR fingerprint remains byte-oriented"
        );
    }
}
