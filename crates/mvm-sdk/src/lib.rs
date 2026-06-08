//! mvm-sdk — build-time Rust SDK for declaring mvm workloads.
//!
//! Per ADR-0015: builder-pattern surface (no globals), build-time DSL
//! only in v1 (no `Session`/`RemoteFunction`), corpus byte-identity
//! gates release.
//!
//! # Two-layer architecture (ADR-0003)
//!
//! - **Lower layer:** the IR types are re-exported as-is from
//!   `mvm-ir`. No codegen; the Rust IR types are already
//!   `serde + JsonSchema + deny_unknown_fields`, which satisfies the
//!   schema-driven contract that Python and TypeScript SDKs achieve via
//!   `datamodel-code-generator` / `json-schema-to-typescript`.
//! - **Upper layer:** hand-authored builders rooted at [`workload`] and
//!   [`app`].
//!
//! # Subprocess contract (ADR-0002)
//!
//! [`emit`] honors `MVM_IR_OUT`: when set, writes the canonical IR
//! to that path and returns `Ok(())`. When unset, writes to stdout.
//! Validation errors and write errors return non-zero through
//! [`EmitError`].
//!
//! # Example
//!
//! ```no_run
//! use mvm_sdk::*;
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let wl = workload("hello")
//!         .app(
//!             app("hello")
//!                 .source(local_path("."))
//!                 .image(nix_packages(["python312"]))
//!                 .entrypoint(entrypoint_command(["python", "-m", "hello"]))
//!                 .resources(resources(1, 256, 512))
//!                 .build()?,
//!         )
//!         .build()?;
//!     emit(&wl)?;
//!     Ok(())
//! }
//! ```

mod builder;
mod ctor;
mod emit;
mod error;

/// The canonical `Workload` IR — validate, canonicalize, hash, hooks,
/// addon, version. Folded in from the former `mvm-ir` crate (plan 121
/// A3); the SDK is its only consumer alongside mvm-cli (mvmd does not
/// consume the IR). Authoring + runtime SDKs lower to these types.
pub mod ir;

/// Author-side machinery for composable attested addons. Ported from
/// `mvmforge-addon`. Exposes `addon::{manifest, lockfile, validator,
/// registry, archive, sbom, verify}` plus re-exports the consumer-side
/// IR shapes (`AddonUse`, `AddonRef`, `AddonTier`, `ThreatTier`) for
/// one-stop authoring.
pub mod addon;

/// Compile pipeline — Workload IR to staged build artifacts. Ported
/// from `mvmforge/src/{archive,source,reachability,...}.rs`. Phase 2a
/// exposes the source-bundling primitives (`archive_dir`,
/// `copy_source`, `rehash`, `discover_python_reachable`,
/// `discover_node_reachable`, `detect_language`); Phases 2b–2c add
/// the rest. Phase 9 adds `deps_audit` — the sealed-volume primitives
/// behind the application-dependency audit pipeline (ADR-047).
pub mod compile;

/// Static decorator parser — extracts `@mvm.app(...)` kwargs from a
/// user's Python or TypeScript source file and lowers them to a
/// `Workload` IR. Pure tree-sitter; never imports the user's code.
/// Closed `mvm.*` helper allowlist; non-literal kwargs rejected.
pub mod decorator;

/// Deploy-bundle assembly + shipping for mvmd-owned control-plane flows.
/// Builds the single signed `.tar.gz` (compile output + embedded
/// `mvmd-spec.json`) described in mvmd ADR-0020 and ships it via
/// `MvmdClient::ship`.
pub mod deploy;

/// Runtime record-mode core — recording shape + lowering. SDK port
/// Phase 7. The host SDKs (Python, TypeScript) build a
/// `RuntimeRecording` from imperative `Sandbox` calls; this module
/// lowers it into the same `Workload` IR the decorator path
/// produces, so the flake renderer is shared.
pub mod runtime;

// Prelude — every previously-public item lives here so
// `use mvm_sdk::*;` resolves identically across the split.
pub use builder::{AppBuilder, WorkloadBuilder, app, workload};
pub use ctor::deps::{no_deps, node_deps, node_deps_with, python_deps, python_deps_with};
pub use ctor::entrypoint::{EntrypointExt, entrypoint_command, entrypoint_function};
pub use ctor::image::{nix_packages, oci_base};
pub use ctor::network::{
    NetworkExt, dns_none, dns_resolver, dns_system, egress, host_port, network,
};
pub use ctor::resources::resources;
pub use ctor::source::{local_path, nix_derivation, oci_image};
pub use emit::{emit, emit_json};
pub use error::{BuildError, EmitError};

// Phase 7a — runtime record-mode lowering. The CLI's
// `mvmctl compile --from-recording` and the auto-exec path both
// reach in through these re-exports.
pub use runtime::{
    KNOWN_BASE_IMAGES, LowerError, RecordedOp, RuntimeRecording, SandboxCreate, compile_recording,
    resolve_base_image,
};

// IR type re-exports — public surface aliases consumed by downstream
// fixtures (the corpus byte-identity gate from ADR-0015) and tests.
pub use crate::ir::{
    App as IrApp, Dependencies as IrDependencies, Entrypoint as IrEntrypoint,
    EnvValue as IrEnvValue, Format as IrFormat, HostPort, Image as IrImage, Mount as IrMount,
    MountMode, MountSource, Network as IrNetwork, NetworkDns as IrNetworkDns,
    NetworkEgress as IrNetworkEgress, NetworkMode as IrNetworkMode, NodeTool as IrNodeTool,
    PortForward as IrPortForward, PortProto, PythonTool as IrPythonTool, Resources as IrResources,
    SecretMount, SecretRef, Source as IrSource, ValidationError, Volume as IrVolume,
    Workload as IrWorkload, ir_hash,
};
