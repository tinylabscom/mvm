//! Workload backend selection on the client facade.

use mvm_runtime::AnyBackend;

/// Name of the workload backend selected by the canonical host ladder.
///
/// Keeps callers on the client facade instead of coupling them to the runtime
/// backend enum merely to resolve the standard platform default.
#[must_use]
pub fn auto_selected_backend_name() -> String {
    AnyBackend::auto_select().name().to_string()
}

/// Select the backend for an explicit `--hypervisor` name, refusing a
/// selector this build cannot serve.
///
/// Frontends hold the returned handle only to pass it back to the client and
/// to the CLI's own presentation helpers; backend construction and validation
/// stay behind the client.
pub fn selectable_backend_for_hypervisor(name: &str) -> anyhow::Result<AnyBackend> {
    AnyBackend::require_hypervisor_selectable(name)?;
    Ok(AnyBackend::from_hypervisor(name))
}
