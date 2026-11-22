//! Shared resolve/attach/verify/admit preparation state.

use anyhow::Result;
use mvm_core::vm_backend::VmStartConfig;

use super::{CliStartFailure, LaunchSource};

pub(crate) struct PreparedLaunch<A> {
    pub(crate) config: VmStartConfig,
    pub(crate) verified_runtime:
        Option<std::sync::Arc<mvm_runtime::runtime_evidence::VerifiedRuntimeSet>>,
    pub(crate) admission: A,
}

pub(crate) fn prepare_launch<A>(
    source: LaunchSource<'_>,
    mut config: VmStartConfig,
    attach: impl FnOnce(
        &mut VmStartConfig,
    ) -> Result<
        Option<std::sync::Arc<mvm_build::guest_runtime::evidence::VerifiedReleaseRuntime>>,
    >,
    admit: impl FnOnce(
        &mut VmStartConfig,
        Option<&mvm_runtime::runtime_evidence::VerifiedRuntimeSet>,
    ) -> Result<A>,
) -> Result<PreparedLaunch<A>> {
    match source {
        LaunchSource::Persistent { lifecycle } | LaunchSource::LocalTransient { lifecycle } => {
            lifecycle
                .require_name(&config.name)
                .map_err(CliStartFailure::StateNotOwned)?;
            lifecycle
                .require_cold_state()
                .map_err(CliStartFailure::StateNotOwned)?;
        }
        LaunchSource::OperatorTrial { backend_kind }
        | LaunchSource::FilesystemFork { backend_kind }
        | LaunchSource::CliCold { backend_kind }
        | LaunchSource::Entrypoint { backend_kind }
        | LaunchSource::PortableEntrypoint { backend_kind } => {
            tracing::trace!(
                backend = backend_kind.as_str(),
                "preparing selected cold source"
            );
        }
    }

    let release = attach(&mut config)?;
    let verified_runtime = match release {
        Some(release) => Some(std::sync::Arc::new(
            mvm_runtime::runtime_evidence::verify_release_runtime_set(&config, release)?,
        )),
        None => mvm_runtime::runtime_evidence::verify_selected_release_runtime_set(&config)?
            .map(std::sync::Arc::new),
    };
    let admission = admit(&mut config, verified_runtime.as_deref())?;
    Ok(PreparedLaunch {
        config,
        verified_runtime,
        admission,
    })
}
