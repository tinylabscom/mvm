//! Build & artifact commands — flake/Mvmfile builds, templates, image catalog.

#[allow(clippy::module_inception)]
pub(super) mod build;
pub(super) mod flake;
pub(super) mod image;
pub(super) mod template;

pub(super) use super::{Cli, shared};
