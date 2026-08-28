//! Build & artifact commands — flake/Mvmfile builds, runtime-overlay and SDK
//! sidecar prebuilds, and flake validation.
//! The `image` catalog lives in the top-level `catalog` module; `flake`
//! validation is the `validate` subcommand.

pub(super) mod address;
#[allow(clippy::module_inception)]
pub(in crate::commands) mod build;
pub(super) mod compile;
pub(super) mod group;
#[cfg(feature = "builder-vm")]
pub mod hvf_builder_image;
/// Records an audited image-lineage node after a successful flake build, so
/// every compiled image produces a tamper-evident version-chain record anchored
/// in the host-signed audit log.
pub(in crate::commands) mod image_lineage;
/// Shared IR-JSON input loading (`--from-ir` / positional / `-` stdin) for the
/// build-time verbs that read a Workload document.
pub(super) mod ir_input;
pub(super) mod kernel;
/// `mvmctl persistent-builder` user-facing verb. Wires the
/// host-side `LibkrunPersistentHostVm` and
/// `PersistentBuilderSupervisor` together via three subcommands
/// (start / submit / stop) so contributors can exercise the
/// dispatch path end-to-end without going through a full build.
/// Gated on the `builder-vm` feature because the host-side types
/// it dispatches into (`LibkrunPersistentHostVm` etc.) only
/// exist with that feature — `mvm-cli`'s default features include
/// it, so production builds always have this verb.
#[cfg(feature = "builder-vm")]
pub(super) mod persistent_builder;
pub(super) mod runtime_overlay;
/// Shared helpers for the SDK record-mode auto-exec path. Used by
/// `mvmctl compile <Sandbox-script>` and `mvmctl run --mode plan`.
pub(in crate::commands) mod sandbox_record;
pub(super) mod sdk_sidecar;
/// Host-side secret scan over a runtime recording. Walks every place
/// raw bytes can hide (env literals, argv, decoded FilesWrite payloads)
/// and reports findings. Used by `run --mode plan` to hard-refuse
/// admission and by `compile` to warn.
pub(in crate::commands) mod trace_secret_scan;
pub(super) mod validate;

pub(super) use super::{Cli, shared};
