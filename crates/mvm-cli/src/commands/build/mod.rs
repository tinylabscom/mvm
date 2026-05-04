//! Build & artifact commands — flake/Mvmfile builds + flake validation.
//! (Plan 40: `image` catalog moved to top-level `catalog` module;
//! `flake` validation renamed to `validate`.)

#[allow(clippy::module_inception)]
pub(super) mod build;
pub(super) mod validate;

pub(super) use super::{Cli, shared};
