//! Explicit image preparation and verified, cache-only launch resolution.

pub mod acquisition;
pub mod bootstrap;
pub mod capabilities;
pub mod default_microvm;
pub mod environment;
pub mod host_helpers;
mod image_ops;
pub mod kernel;
pub mod local_pair;
pub mod prepared;
pub(crate) use crate::maintenance::cache::staging as stage0_cache;
pub use image_ops::validate_dev_image_artifacts;
mod stage0_artifact;
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
/// Synthetic image-checkout fixtures shared by client and CLI tests through
/// the existing `test-support` feature, never through source-path inclusion.
pub mod test_pair;

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod verification;

// Informational diagnostics do not determine acquisition policy.
mod ui {
    pub fn success(message: &str) {
        tracing::info!("{message}");
    }
    pub fn info(message: &str) {
        tracing::info!("{message}");
    }
    pub fn warn(message: &str) {
        tracing::warn!("{message}");
    }
    /// Printed whatever the verbosity: reserved for the few lines an operator
    /// (or a smoke test reading plain output) must see.
    pub fn notice(message: &str) {
        mvm_runtime::ui::notice(message);
    }
}

fn images_built_from_source() -> bool {
    matches!(
        mvm_build::image_source::resolve_current_source(),
        Ok(mvm_build::image_source::ImageSource::LocalCheckout(_))
    )
}

fn report_recorded_boot_tier(what: &str, path: &std::path::Path) {
    if let Some(tier) = mvm_build::image_source::recorded_tier_for(path) {
        tracing::info!("{what}: {tier} (as recorded with the image)");
    }
}
