//! The cross-language canonical goldens. Every authoring SDK (Rust, Python,
//! TypeScript, Kotlin) must emit exactly these bytes for the matching fixture,
//! so the lock's `spec_sha256` is the same whichever language authored it.
use mvm_contract::pack_spec::PackSpec;
use sha2::{Digest, Sha256};

const FIXTURES: [&str; 3] = ["minimal", "python", "claude-style"];

/// Every golden, embedded rather than read at runtime: the contract's tests
/// also run under `wasm32-wasip1`, where the sandbox has no filesystem.
const GOLDENS: [(&str, &[u8]); 9] = [
    (
        "minimal.json",
        include_bytes!("fixtures/pack-spec-v1/minimal.json"),
    ),
    (
        "python.json",
        include_bytes!("fixtures/pack-spec-v1/python.json"),
    ),
    (
        "claude-style.json",
        include_bytes!("fixtures/pack-spec-v1/claude-style.json"),
    ),
    (
        "canonical/minimal.json",
        include_bytes!("fixtures/pack-spec-v1/canonical/minimal.json"),
    ),
    (
        "canonical/minimal.sha256",
        include_bytes!("fixtures/pack-spec-v1/canonical/minimal.sha256"),
    ),
    (
        "canonical/python.json",
        include_bytes!("fixtures/pack-spec-v1/canonical/python.json"),
    ),
    (
        "canonical/python.sha256",
        include_bytes!("fixtures/pack-spec-v1/canonical/python.sha256"),
    ),
    (
        "canonical/claude-style.json",
        include_bytes!("fixtures/pack-spec-v1/canonical/claude-style.json"),
    ),
    (
        "canonical/claude-style.sha256",
        include_bytes!("fixtures/pack-spec-v1/canonical/claude-style.sha256"),
    ),
];

fn fixture(path: &str) -> Vec<u8> {
    GOLDENS
        .iter()
        .find(|(name, _)| *name == path)
        .map(|(_, bytes)| bytes.to_vec())
        .unwrap_or_else(|| panic!("{path}: no embedded golden"))
}

#[test]
fn canonical_goldens_are_what_the_contract_emits() {
    for name in FIXTURES {
        let spec: PackSpec = serde_json::from_slice(&fixture(&format!("{name}.json"))).unwrap();
        let canonical = spec.canonical_json().unwrap();
        assert_eq!(
            canonical,
            fixture(&format!("canonical/{name}.json")),
            "{name}: canonical golden is stale"
        );
        let digest: String = Sha256::digest(&canonical)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let recorded = String::from_utf8(fixture(&format!("canonical/{name}.sha256"))).unwrap();
        assert_eq!(
            digest,
            recorded.trim_end(),
            "{name}: digest golden is stale"
        );
    }
}

#[test]
fn canonical_goldens_are_fixed_points() {
    for name in FIXTURES {
        let golden = fixture(&format!("canonical/{name}.json"));
        let spec: PackSpec = serde_json::from_slice(&golden).unwrap();
        assert_eq!(spec.canonical_json().unwrap(), golden, "{name}");
        assert!(!golden.ends_with(b"\n"), "{name}: no trailing newline");
    }
}
