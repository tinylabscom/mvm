// Fuzz the restore-load device-model parser.
//
// `RestoredDeviceModel` is a `serde_json` view over Firecracker's own
// `GET /vm/config` response body, read by `FirecrackerIO::restored_device_model`
// after a snapshot load. That body is Firecracker-controlled, not mvm-controlled,
// and the sole no-NIC device-model guard the warm-restore path relies on to keep
// a restored VMM off the network sits directly downstream of this parse — a
// panic here would crash the resume path (a host DoS) instead of failing closed.
// This target asserts `parse_restored_device_model` never panics on any input.

#![no_main]

use libfuzzer_sys::fuzz_target;
use mvm_runtime::microvm::parse_restored_device_model;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    let _ = parse_restored_device_model(s);
});
