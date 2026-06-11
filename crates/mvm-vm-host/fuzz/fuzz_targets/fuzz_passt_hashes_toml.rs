// Fuzz the operator-curated `~/.mvm/passt-hashes.toml` parser.
//
// `verify_passt_hash` (`crates/mvm-firecracker-bridge/src/parse.rs`)
// reads this file BEFORE installing `mvm-jailer-lite` confinement so
// the bridge can emit a clean remediation hint on a missing or
// malformed allowlist (Cardoso minimum-viable-policy — the operator-
// pinned allowlist is the supply-chain gate). A panic in the TOML
// parser surfaces as a hard process death before the FlowEvent
// pipeline is up.
//
// The operator-managed format is a single-key TOML doc:
//
//   sha256 = ["<hex>", ...]
//
// `#[serde(deny_unknown_fields)]` is asserted by the unit tests
// (`verify_passt_hash_rejects_unknown_field_in_hashes_file`); this
// fuzz target is the no-panic complement. Harness goal is "never
// panic on any input"; `toml::de::Error` is the expected outcome for
// malformed bytes.

#![no_main]

use libfuzzer_sys::fuzz_target;
use mvm_vm_host::firecracker_bridge::parse::PasstHashesFile;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = toml::from_str::<PasstHashesFile>(s);
    }
});
