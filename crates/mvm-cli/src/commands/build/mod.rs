//! Build & artifact commands — flake/Mvmfile builds + flake validation.
//! The `image` catalog lives in the top-level `catalog` module; `flake`
//! validation is the `validate` subcommand.

#[allow(clippy::module_inception)]
pub(super) mod build;
pub(super) mod compile;
pub(super) mod group;
pub(super) mod kernel;
/// `mvmctl persistent-builder` user-facing verb. Wires the
/// host-side `LibkrunPersistentHostVm` and
/// `PersistentBuilderSupervisor` together via three subcommands
/// (start / submit / stop) so contributors can exercise the
/// dispatch path end-to-end without going through `mvmctl dev up`.
/// Gated on the `builder-vm` feature because the host-side types
/// it dispatches into (`LibkrunPersistentHostVm` etc.) only
/// exist with that feature — `mvm-cli`'s default features include
/// it, so production builds always have this verb.
#[cfg(feature = "builder-vm")]
pub(super) mod persistent_builder;
/// Shared helpers for the SDK record-mode auto-exec path. Used by
/// `mvmctl compile <Sandbox-script>` and `mvmctl run --mode plan`.
pub(in crate::commands) mod sandbox_record;
pub(super) mod validate;

pub(super) use super::{Cli, shared};
