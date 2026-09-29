//! Per-VM telemetry collector: a thin entry over
//! `mvm_hostd::telemetry_collector::run_from_config`.
//!
//! Spawned by the workload runner when telemetry is provisioned for a boot;
//! reads its configuration as one JSON document on stdin (unknown fields
//! fail closed), owns the VM's telemetry session for as long as it lives,
//! and is reaped with SIGTERM at VM teardown. It holds no signing key: the
//! handshake is signed through the delegated resident signer.

use std::io::Read;

fn main() {
    let mut raw = String::new();
    if let Err(e) = std::io::stdin().read_to_string(&mut raw) {
        eprintln!("mvm-telemetry-collector: reading config from stdin: {e}");
        std::process::exit(2);
    }
    let config: mvm_vmm::host::telemetry_collector_spawn::TelemetryCollectorProcessConfig =
        match serde_json::from_str(&raw) {
            Ok(config) => config,
            Err(e) => {
                eprintln!("mvm-telemetry-collector: invalid config: {e}");
                std::process::exit(2);
            }
        };
    if let Err(e) = mvm_hostd::telemetry_collector::run_from_config(config) {
        eprintln!("mvm-telemetry-collector: {e:#}");
        std::process::exit(1);
    }
}
