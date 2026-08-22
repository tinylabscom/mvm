#![deny(unsafe_code)]
//! mvm-sdk — Rust SDK for declaring, recording, and driving mvm workloads.
//!
//! Builder-pattern surface (no globals), build-time DSL only in v1 (no
//! `Session`/`RemoteFunction`); corpus byte-identity gates release.
//!
//! # Two-layer architecture
//!
//! - **Lower layer:** the IR types are re-exported as-is from the
//!   [`ir`] module. No codegen; the Rust IR types are already
//!   `serde + JsonSchema + deny_unknown_fields`, which satisfies the
//!   schema-driven contract that Python and TypeScript SDKs achieve via
//!   `datamodel-code-generator` / `json-schema-to-typescript`.
//! - **Upper layer:** hand-authored builders rooted at [`workload`] and
//!   [`app`].
//!
//! # Subprocess contract
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
//!
//! Machine lifecycle wrappers are available through [`MachineRun`],
//! [`MachineCreate`], [`MachineCheckArtifact`], and [`Machine`]. They shell to
//! `mvmctl machine ...` so OCI pull, admission, artifact verification,
//! networking, receipts, audit, and persistent machine state remain owned by
//! the CLI path. The optional `client-facade` feature also exposes a
//! subprocess-backed `MvmClient` implementation.

mod builder;
mod ctor;
pub mod ctor_registry;
mod emit;
pub mod env;
mod error;
pub mod error_taxonomy;
#[cfg(feature = "client-facade")]
pub mod facade;
pub mod machine;

/// The canonical `Workload` IR — validate, canonicalize, hash, hooks,
/// addon, version. Lives in the `no_std` foundation crate `mvm-contract`
/// (wasm-clean, alongside the audit-log verifier) and is re-exported
/// here unchanged so the SDK's authoring API keeps `mvm_sdk::ir::…`
/// working. Authoring + runtime SDKs lower to these types.
pub use mvm_contract::ir;
pub use mvm_contract::policy::approval;
/// Durable agent session identifiers, commands, events, cursors, and the
/// transport-neutral reference journal.
pub use mvm_contract::protocol::agent_session;

/// Author-side machinery for composable attested addons. Exposes
/// `addon::{manifest, lockfile, validator, registry, archive, sbom,
/// verify}` plus re-exports the consumer-side IR shapes (`AddonUse`,
/// `AddonRef`, `AddonTier`, `ThreatTier`) for one-stop authoring.
pub mod addon;

/// Compile pipeline — Workload IR to staged build artifacts. Exposes
/// the source-bundling primitives (`archive_dir`, `copy_source`,
/// `rehash`, `discover_python_reachable`, `discover_node_reachable`,
/// `detect_language`) plus `deps_audit` — the sealed-volume primitives
/// behind the application-dependency audit pipeline.
pub mod compile;

/// Static decorator parser — extracts `@mvm.app(...)` kwargs from a
/// user's Python or TypeScript source file and lowers them to a
/// `Workload` IR. Pure tree-sitter; never imports the user's code.
/// Closed `mvm.*` helper allowlist; non-literal kwargs rejected.
pub mod decorator;

/// In-guest host-services C-ABI cdylib (`libmvm_host_services.so`) loaded by
/// the Python and TypeScript SDKs. Unsafe code is confined to this module.
#[allow(unsafe_code)]
mod host_services_ffi;

/// Deploy-bundle assembly and local attestation for mvmd-owned control-plane
/// flows. Builds the single `.tar.gz` (compile output plus embedded
/// `mvmd-spec.json`) and exposes the authenticated shipping seam.
pub mod deploy;

/// Runtime record-mode core — recording shape + lowering. The host
/// SDKs (Python, TypeScript) build a `RuntimeRecording` from
/// imperative `Sandbox` calls; this module lowers it into the same
/// `Workload` IR the decorator path produces, so the flake renderer is
/// shared.
pub mod runtime;

/// Runtime read surface — follow a live workload's stdout/stderr/trace from a
/// program instead of shelling out to `mvmctl logs`. Records arrive
/// hash-chain verified with their bytes verbatim. The same reader
/// `mvm-client` exposes; both re-export `mvm-core`'s.
pub mod stream;

// Prelude — every previously-public item lives here so
// `use mvm_sdk::*;` resolves identically across the split.
pub use builder::{AppBuilder, WorkloadBuilder, app, workload};
pub use ctor::addon::{AddonUseExt, UNRESOLVED_SHA256, addon_use_local, addon_use_registry};
pub use ctor::concurrency::{ConcurrencyExt, warm_process};
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
pub use machine::{
    MVM_CLI_BIN_ENV, Machine, MachineCheckArtifact, MachineCheckArtifactBuilder, MachineClient,
    MachineCreate, MachineCreateBuilder, MachineError, MachineExecBuilder, MachineInspect,
    MachineInspectBuilder, MachineLogs, MachineLogsBuilder, MachineLs, MachineLsBuilder,
    MachineResult, MachineRm, MachineRmBuilder, MachineRun, MachineRunBuilder, MachineShellBuilder,
    MachineStartBuilder, MachineStopBuilder,
};

// Runtime record-mode lowering. The CLI's
// `mvmctl compile --from-recording` and the auto-exec path both
// reach in through these re-exports.
pub use runtime::{
    Divergence, KNOWN_BASE_IMAGES, LowerError, RecordedOp, RuntimeRecording, SandboxCreate,
    compile_recording, compile_recording_with_findings, recording_sha256_hex, resolve_base_image,
    verify_recording_digest,
};

// IR type re-exports — public surface aliases consumed by downstream
// fixtures (the corpus byte-identity gate) and tests.
pub use crate::ir::{
    App as IrApp, Dependencies as IrDependencies, Entrypoint as IrEntrypoint,
    EnvValue as IrEnvValue, Format as IrFormat, HostPort, Image as IrImage, Mount as IrMount,
    MountMode, MountSource, Network as IrNetwork, NetworkDns as IrNetworkDns,
    NetworkEgress as IrNetworkEgress, NetworkMode as IrNetworkMode, NodeTool as IrNodeTool,
    PortForward as IrPortForward, PortProto, PortTransform, PythonTool as IrPythonTool,
    Resources as IrResources, SecretMount, SecretRef, Source as IrSource, ValidationError,
    Volume as IrVolume, Workload as IrWorkload, ir_hash,
};
