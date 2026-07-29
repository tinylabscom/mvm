// Adversarial fuzz for the hardened snapshot-frame parser and the
// restore-load metadata parsers.
//
// Feeds arbitrary bytes to:
//
//   * `mvm_core::snapshot_frame::parse_header` / `parse_sections`
//   * `serde_json` deserialization of `IntegritySidecar`
//     (`~/.mvm/instances/<vm>/snapshot/integrity.json`)
//   * `serde_json` deserialization of `CheckpointMeta`
//     (`~/.mvm/checkpoints/<id>/meta.json`)
//
// The single property asserted is crash-freedom: every host↔snapshot
// type is `#[serde(deny_unknown_fields)]`, so a hostile metadata
// stream must fail closed with a parse error rather than panic,
// allocate unboundedly, or silently accept unexpected fields.
//
// CI gate: `.github/workflows/security.yml::fuzz`.

#![no_main]

use libfuzzer_sys::fuzz_target;
use mvm_core::checkpoint::CheckpointMeta;
use mvm_core::crypto::snapshot_hmac::IntegritySidecar;
use mvm_core::snapshot_frame::{parse_header, parse_sections};

fuzz_target!(|data: &[u8]| {
    // Snapshot-frame binary surface.
    let _ = parse_header(data);
    if let Ok(sections) = parse_sections(data) {
        for section in &sections {
            let bytes = section.data(data);
            assert!(section.region.offset + bytes.len() <= data.len());
        }
    }

    // Restore-load metadata surfaces: integrity sidecar and checkpoint meta.
    // Both are strict JSON with `deny_unknown_fields`; arbitrary bytes must
    // not panic the deserializer.
    let _ = serde_json::from_slice::<IntegritySidecar>(data);
    let _ = serde_json::from_slice::<CheckpointMeta>(data);
});
