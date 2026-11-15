//! Chain-audit labels for the identity pinned in a signed execution plan.

use mvm_contract::plan::RuntimeIdentity;

pub(crate) fn runtime_identity_labels(runtime: &RuntimeIdentity) -> Vec<(String, String)> {
    let mut labels = vec![
        (
            "runtime_archive_sha256".to_string(),
            runtime.archive_sha256.as_str(),
        ),
        ("runtime_version".to_string(), runtime.version.as_str()),
        ("runtime_arch".to_string(), runtime.arch.as_str()),
        (
            "runtime_signer_identity".to_string(),
            runtime.signer_identity.as_str(),
        ),
        (
            "runtime_signer_issuer".to_string(),
            runtime.signer_issuer.as_str(),
        ),
    ];
    for (prefix, digests) in [
        ("runtime_declaration", &runtime.declaration),
        ("runtime_selected", &runtime.selected),
    ] {
        labels.extend([
            (
                format!("{prefix}_overlay_sha256"),
                digests.overlay_sha256.as_str(),
            ),
            (
                format!("{prefix}_overlay_verity_sha256"),
                digests.overlay_verity_sha256.as_str(),
            ),
            (
                format!("{prefix}_overlay_roothash"),
                digests.overlay_roothash.as_str(),
            ),
            (
                format!("{prefix}_initramfs_sha256"),
                digests.initramfs_sha256.as_str(),
            ),
        ]);
    }
    labels
        .into_iter()
        .map(|(key, value)| (key, value.to_string()))
        .collect()
}
