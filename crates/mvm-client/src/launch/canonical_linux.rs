//! Explicit consumer preparation through the shared canonical kernel owner.
//! Backend and admission code use the same core type, not parallel verifiers.

use anyhow::Result;
use mvm_core::plan::bundle::{FsTrustStore, PlanArtifact};
use mvm_core::vm_backend::BackendKind;
use std::path::Path;

pub use mvm_core::canonical_linux::PreparedCanonicalLinux;

/// May advance the canonical signed revocation store; never a read-only
/// preview or native-start permission.
pub fn prepare_canonical_linux(
    archive: &Path,
    pin: &PlanArtifact,
    backend: BackendKind,
) -> Result<PreparedCanonicalLinux> {
    let trust = mvm_core::registry_pack::application_bundle::trust_for_installed_archive(
        FsTrustStore::default_path()?,
        archive,
    );
    mvm_core::canonical_linux::prepare_canonical_linux(
        archive,
        pin,
        backend,
        mvm_build::stage0_kernel::current_image_set_protocol_support(),
        &trust,
    )
}
