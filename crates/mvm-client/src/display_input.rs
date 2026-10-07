//! Embedder-facing access to an admitted display-input session.

use anyhow::{Context, Result};

pub use mvm_hostd::display::DisplayAuthority;
pub use mvm_hostd::stream::{DisplayInputRoute, DisplayInputRouteError};

/// Load the input grant that was sealed when the machine was admitted.
/// An absent grant means the display is view-only.
pub fn load_authority(name: &str) -> Result<Option<DisplayAuthority>> {
    DisplayAuthority::load(name)
        .with_context(|| format!("load the display input authority for {name:?}"))
}

/// Arm cleanup for an attended input session before accepting viewer input.
pub fn on_interrupt(
    cleanup: impl FnOnce() + Send + 'static,
) -> mvm_runtime::interrupt_cleanup::InterruptCleanup {
    mvm_runtime::interrupt_cleanup::on_interrupt("display input session", cleanup)
}
