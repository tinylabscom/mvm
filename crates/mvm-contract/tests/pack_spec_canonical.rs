//! The cross-language canonical goldens. Every authoring SDK (Rust, Python,
//! TypeScript, Kotlin) must emit exactly these bytes for the matching fixture,
//! so the lock's `spec_sha256` is the same whichever language authored it.
use mvm_contract::pack_spec::PackSpec;
use sha2::{Digest, Sha256};

const FIXTURES: [&str; 3] = ["minimal", "python", "claude-style"];

fn fixture(path: &str) -> Vec<u8> {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/pack-spec-v1/");
    std::fs::read(format!("{dir}{path}")).unwrap_or_else(|e| panic!("{path}: {e}"))
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
