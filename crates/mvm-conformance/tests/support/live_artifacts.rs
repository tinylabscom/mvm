use std::path::Path;

use mvm_build::guest_libc::GuestLibc;
use mvm_core::arch::GuestArch;
use mvm_fs::sdk_sidecar::SdkSidecarResolver;

/// Read the slot from this build, never from an unrelated warm-home template.
pub(crate) fn built_manifest_slot(stdout: &[u8]) -> Option<String> {
    String::from_utf8_lossy(stdout).lines().find_map(|line| {
        let event: serde_json::Value = serde_json::from_str(line).ok()?;
        if event["command"] != "build"
            || event["phase"] != "manifest"
            || event["status"] != "completed"
        {
            return None;
        }
        let slot = event["slot_hash"].as_str()?;
        (slot.len() == 64 && slot.bytes().all(|byte| byte.is_ascii_hexdigit()))
            .then(|| slot.to_owned())
    })
}

/// Probe the one installed artifact source a live launch resolves: the
/// version-keyed sidecar this CLI assembled from its guest runtime. Resolution
/// is cache-only and retains the artifact integrity checks.
pub(crate) fn sdk_sidecar_cached_in(cache: &Path) -> bool {
    let arch_dir = GuestArch::host().to_string();
    [GuestLibc::Glibc, GuestLibc::Musl].into_iter().any(|libc| {
        SdkSidecarResolver::new(cache.to_path_buf(), env!("CARGO_PKG_VERSION").into())
            .resolve(&arch_dir, libc)
            .is_ok()
    })
}
