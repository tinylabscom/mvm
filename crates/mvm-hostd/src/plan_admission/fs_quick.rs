//! Fresh-runtime preparation for a materialized filesystem checkpoint child.

use anyhow::Result;
use mvm_core::vm_backend::VmStartConfig;

use super::start::{LaunchSource, prepare_launch};

/// A materialized filesystem fork prepared through fresh runtime verification and admission.
pub struct PreparedFilesystemFork<A> {
    config: VmStartConfig,
    verified_runtime: Option<std::sync::Arc<mvm_runtime::runtime_evidence::VerifiedRuntimeSet>>,
    admission: A,
}

impl<A> PreparedFilesystemFork<A> {
    /// Return the exact prepared config, retained runtime evidence and admission.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        VmStartConfig,
        Option<std::sync::Arc<mvm_runtime::runtime_evidence::VerifiedRuntimeSet>>,
        A,
    ) {
        (self.config, self.verified_runtime, self.admission)
    }
}

/// Prepare a materialized filesystem fork as a fresh cold launch.
///
/// # Errors
/// Propagates attachment, selected-runtime verification, or admission refusal
/// before any backend dispatch.
pub fn prepare_filesystem_fork<A>(
    config: VmStartConfig,
    backend_kind: mvm_core::vm_backend::BackendKind,
    attach: impl FnOnce(
        &mut VmStartConfig,
    ) -> Result<
        Option<std::sync::Arc<mvm_build::guest_runtime::evidence::VerifiedReleaseRuntime>>,
    >,
    admit: impl FnOnce(
        &mut VmStartConfig,
        Option<&mvm_runtime::runtime_evidence::VerifiedRuntimeSet>,
    ) -> Result<A>,
) -> Result<PreparedFilesystemFork<A>> {
    let prepared = prepare_launch(
        LaunchSource::FilesystemFork { backend_kind },
        config,
        attach,
        admit,
    )?;
    Ok(PreparedFilesystemFork {
        config: prepared.config,
        verified_runtime: prepared.verified_runtime,
        admission: prepared.admission,
    })
}
