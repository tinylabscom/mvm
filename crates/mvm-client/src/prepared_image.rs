//! Development-only, persistent-only reuse of prepared registry OCI images.
//!
//! A selection is expected data, never authorization. Launch resolves it again
//! under current MVM checks and refuses changes before admission.
//!
//! Expected selections cannot be supplied to the raw transient signing seam:
//!
//! ```compile_fail
//! fn inject(
//!     request: &mut mvm_hostd::run::LocalRunRequest,
//!     selection: mvm_client::prepared_image::PreparedOciSelection,
//! ) {
//!     request.prepared_image = Some(selection);
//! }
//! ```
//!
//! Nor can callers mint prepared provenance through public persistent params:
//!
//! ```compile_fail
//! fn inject(
//!     params: &mut mvm_client::launch::persistent::PersistentImageStartParams<'_>,
//!     selection: mvm_client::prepared_image::PreparedOciSelection,
//! ) {
//!     params.prepared_image = Some(selection);
//! }
//! ```

pub use crate::image_cache::prepared::{PreparedImageContext, select};
pub use mvm_core::prepared_image::{
    PreparedImageError, PreparedImageErrorKind, PreparedImageRemedy, PreparedImageTrust,
    PreparedOciSelection,
};
