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
/// the rest.
pub mod compile;

/// Static decorator parser — extracts `@mvm.app(...)` kwargs from a
/// user's Python source file and lowers them to a `Workload` IR. Pure
/// tree-sitter; never imports the user's code. Closed `mvm.*` helper
/// allowlist; non-literal kwargs rejected. TypeScript parser is a
/// follow-up.
pub mod decorator;

use mvm_ir::{
    App, Dependencies, Entrypoint, EnvValue, Format, Image, Mount, Network, NetworkDns,
    NetworkEgress, NetworkMode, NodeTool, PortForward, PythonTool, Resources, Source, Volume,
    Workload,
};
use std::collections::BTreeMap;

pub use mvm_ir::{
    App as IrApp, Dependencies as IrDependencies, Entrypoint as IrEntrypoint,
    EnvValue as IrEnvValue, Format as IrFormat, HostPort, Image as IrImage, Mount as IrMount,
    MountMode, MountSource, Network as IrNetwork, NetworkDns as IrNetworkDns,
    NetworkEgress as IrNetworkEgress, NetworkMode as IrNetworkMode, NodeTool as IrNodeTool,
    PortForward as IrPortForward, PortProto, PythonTool as IrPythonTool, Resources as IrResources,
    SecretMount, SecretRef, Source as IrSource, Volume as IrVolume, Workload as IrWorkload,
};

const SCHEMA_VERSION: &str = "0.1";

// ────────────────────────────────────────────────────────────────────
// Errors
// ────────────────────────────────────────────────────────────────────

/// Errors surfaced when constructing a [`Workload`] or [`App`] via the
/// builders. The builders enforce required-field presence at
/// `.build()` time so the rest of the SDK can take typed values.
#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    #[error("workload requires at least one app (call `.app(...)` before `.build()`)")]
    EmptyWorkload,
    #[error("app `{name}` is missing required field `{field}`")]
    MissingField { name: String, field: &'static str },
}

/// Errors surfaced by [`emit`] / [`emit_json`].
#[derive(Debug, thiserror::Error)]
pub enum EmitError {
    #[error("workload validation failed: {0:?}")]
    Validation(Vec<mvm_ir::ValidationError>),
    #[error("canonicalization failed: {0}")]
    Canonicalize(serde_json::Error),
    #[error("write to MVM_IR_OUT path `{0}` failed: {1}")]
    Write(String, std::io::Error),
    #[error("write to stdout failed: {0}")]
    Stdout(std::io::Error),
}

// ────────────────────────────────────────────────────────────────────
// Workload builder
// ────────────────────────────────────────────────────────────────────

/// Start declaring a workload with the given id.
pub fn workload(id: impl Into<String>) -> WorkloadBuilder {
    WorkloadBuilder {
        id: id.into(),
        apps: Vec::new(),
        volumes: Vec::new(),
    }
}

#[must_use = "WorkloadBuilder is lazy — call .build() to produce a Workload"]
pub struct WorkloadBuilder {
    id: String,
    apps: Vec<App>,
    volumes: Vec<Volume>,
}

impl WorkloadBuilder {
    pub fn app(mut self, app: App) -> Self {
        self.apps.push(app);
        self
    }

    pub fn volume(mut self, volume: Volume) -> Self {
        self.volumes.push(volume);
        self
    }

    pub fn build(self) -> Result<Workload, BuildError> {
        if self.apps.is_empty() {
            return Err(BuildError::EmptyWorkload);
        }
        Ok(Workload {
            schema_version: SCHEMA_VERSION.to_string(),
            id: self.id,
            apps: self.apps,
            volumes: self.volumes,
            extensions: BTreeMap::new(),
        })
    }
}

// ────────────────────────────────────────────────────────────────────
// App builder
// ────────────────────────────────────────────────────────────────────

/// Start declaring an app within the workload.
pub fn app(name: impl Into<String>) -> AppBuilder {
    AppBuilder {
        name: name.into(),
        source: None,
        image: None,
        entrypoints: Vec::new(),
        env: BTreeMap::new(),
        mounts: Vec::new(),
        network: None,
        resources: None,
        dependencies: None,
    }
}

#[must_use = "AppBuilder is lazy — call .build() to produce an App"]
pub struct AppBuilder {
    name: String,
    source: Option<Source>,
    image: Option<Image>,
    entrypoints: Vec<Entrypoint>,
    env: BTreeMap<String, EnvValue>,
    mounts: Vec<Mount>,
    network: Option<Network>,
    resources: Option<Resources>,
    dependencies: Option<Dependencies>,
}

impl AppBuilder {
    pub fn source(mut self, source: Source) -> Self {
        self.source = Some(source);
        self
    }

    pub fn image(mut self, image: Image) -> Self {
        self.image = Some(image);
        self
    }

    /// Add an entrypoint. Single-entrypoint apps call this once; multi-
    /// function apps (per IR ADR-0014 Phase 2) call it multiple times
    /// with `Entrypoint::Function` variants whose `primary` flags are
    /// validator-checked downstream.
    pub fn entrypoint(mut self, ep: Entrypoint) -> Self {
        self.entrypoints.push(ep);
        self
    }

    pub fn resources(mut self, r: Resources) -> Self {
        self.resources = Some(r);
        self
    }

    pub fn env(mut self, key: impl Into<String>, value: EnvValue) -> Self {
        self.env.insert(key.into(), value);
        self
    }

    pub fn mount(mut self, m: Mount) -> Self {
        self.mounts.push(m);
        self
    }

    pub fn network(mut self, n: Network) -> Self {
        self.network = Some(n);
        self
    }

    pub fn dependencies(mut self, d: Dependencies) -> Self {
        self.dependencies = Some(d);
        self
    }

    pub fn build(self) -> Result<App, BuildError> {
        let source = self.source.ok_or(BuildError::MissingField {
            name: self.name.clone(),
            field: "source",
        })?;
        let image = self.image.ok_or(BuildError::MissingField {
            name: self.name.clone(),
            field: "image",
        })?;
        let resources = self.resources.ok_or(BuildError::MissingField {
            name: self.name.clone(),
            field: "resources",
        })?;
        if self.entrypoints.is_empty() {
            return Err(BuildError::MissingField {
                name: self.name,
                field: "entrypoint",
            });
        }
        Ok(App {
            name: self.name,
            source,
            image,
            entrypoints: self.entrypoints,
            env: self.env,
            mounts: self.mounts,
            network: self.network,
            resources,
            dependencies: self.dependencies,
            threat_tier: Default::default(),
            addons: vec![],
            hooks: Default::default(),
        })
    }
}

// ────────────────────────────────────────────────────────────────────
// Source / image / entrypoint constructors
// ────────────────────────────────────────────────────────────────────

/// Bundle the source tree at `path` (relative to the manifest dir).
/// Default include is `["**"]`; override via [`SourceLocalBuilder`].
pub fn local_path(path: impl Into<String>) -> Source {
    Source::LocalPath {
        path: path.into(),
        include: vec!["**".to_string()],
        exclude: Vec::new(),
    }
}

/// Reference a Nix derivation expression.
pub fn nix_derivation(expr: impl Into<String>) -> Source {
    Source::NixDerivation { expr: expr.into() }
}

/// Reference a digest-pinned OCI image as the bundled source.
pub fn oci_image(reference: impl Into<String>, digest: impl Into<String>) -> Source {
    Source::OciImage {
        reference: reference.into(),
        digest: digest.into(),
    }
}

/// Build the runtime image from a list of Nix package attribute paths.
pub fn nix_packages<I, S>(packages: I) -> Image
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    Image::NixPackages {
        packages: packages.into_iter().map(Into::into).collect(),
    }
}

/// Build the runtime image from a digest-pinned OCI base.
pub fn oci_base(reference: impl Into<String>, digest: impl Into<String>) -> Image {
    Image::OciBase {
        reference: reference.into(),
        digest: digest.into(),
    }
}

/// Command-style entrypoint (legacy v0 shape). Working dir defaults to
/// `/app`.
pub fn entrypoint_command<I, S>(command: I) -> Entrypoint
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    Entrypoint::Command {
        command: command.into_iter().map(Into::into).collect(),
        working_dir: "/app".to_string(),
        env: BTreeMap::new(),
    }
}

/// Function-call entrypoint (plan 0003 / ADR-0009). Defaults to
/// `format = json`, `working_dir = /app`, `primary = false`. Use
/// [`EntrypointExt`] chained setters to override.
pub fn entrypoint_function(
    language: impl Into<String>,
    module: impl Into<String>,
    function: impl Into<String>,
) -> Entrypoint {
    Entrypoint::Function {
        language: language.into(),
        module: module.into(),
        function: function.into(),
        format: Format::Json,
        working_dir: "/app".to_string(),
        env: BTreeMap::new(),
        args_schema: None,
        return_schema: None,
        extra_imports: Vec::new(),
        primary: false,
        concurrency: None,
    }
}

/// Chained-setter extensions on [`Entrypoint`]. Bring into scope via
/// `use mvm_sdk::*;` (the trait is re-exported from the prelude).
/// Methods that don't apply to a given variant (e.g. `with_format` on
/// a `Command` entrypoint) panic with a clear message — caller error,
/// not a runtime concern.
pub trait EntrypointExt: Sized {
    fn with_format(self, format: Format) -> Self;
    fn with_primary(self, primary: bool) -> Self;
    fn with_working_dir(self, working_dir: impl Into<String>) -> Self;
    fn with_env(self, key: impl Into<String>, value: EnvValue) -> Self;
    /// Supply an explicit JSON Schema for the function's args. Mirrors
    /// the Python SDK's `args_schema=` and the TypeScript SDK's
    /// `argsSchema:`. Pass `serde_json::Map<String, Value>` (typically
    /// constructed via `serde_json::json!({...}).as_object().cloned()`).
    ///
    /// The host's `mvm emit` step will auto-derive args/return
    /// schemas from the entry source per ADR-0016 when these fields
    /// are unset; explicit values supplied via these setters always
    /// win. SDK-layer byte-identity tests that hit corpus fixtures
    /// expecting auto-derived shapes need to set these explicitly,
    /// since the SDK's `emit_json` doesn't run signature extraction
    /// (no source-tree access in the pure-IR build path).
    fn with_args_schema(self, schema: serde_json::Map<String, serde_json::Value>) -> Self;
    fn with_return_schema(self, schema: serde_json::Map<String, serde_json::Value>) -> Self;
}

impl EntrypointExt for Entrypoint {
    fn with_format(self, fmt: Format) -> Self {
        match self {
            Entrypoint::Function {
                language,
                module,
                function,
                working_dir,
                env,
                args_schema,
                return_schema,
                extra_imports,
                primary,
                concurrency,
                ..
            } => Entrypoint::Function {
                language,
                module,
                function,
                format: fmt,
                working_dir,
                env,
                args_schema,
                return_schema,
                extra_imports,
                primary,
                concurrency,
            },
            Entrypoint::Command { .. } => {
                panic!("with_format only applies to function-call entrypoints")
            }
        }
    }

    fn with_primary(self, p: bool) -> Self {
        match self {
            Entrypoint::Function {
                language,
                module,
                function,
                format,
                working_dir,
                env,
                args_schema,
                return_schema,
                extra_imports,
                concurrency,
                ..
            } => Entrypoint::Function {
                language,
                module,
                function,
                format,
                working_dir,
                env,
                args_schema,
                return_schema,
                extra_imports,
                primary: p,
                concurrency,
            },
            Entrypoint::Command { .. } => {
                panic!("with_primary only applies to function-call entrypoints")
            }
        }
    }

    fn with_working_dir(self, wd: impl Into<String>) -> Self {
        let wd = wd.into();
        match self {
            Entrypoint::Function {
                language,
                module,
                function,
                format,
                env,
                args_schema,
                return_schema,
                extra_imports,
                primary,
                concurrency,
                ..
            } => Entrypoint::Function {
                language,
                module,
                function,
                format,
                working_dir: wd,
                env,
                args_schema,
                return_schema,
                extra_imports,
                primary,
                concurrency,
            },
            Entrypoint::Command { command, env, .. } => Entrypoint::Command {
                command,
                working_dir: wd,
                env,
            },
        }
    }

    fn with_env(self, key: impl Into<String>, value: EnvValue) -> Self {
        match self {
            Entrypoint::Function {
                language,
                module,
                function,
                format,
                working_dir,
                mut env,
                args_schema,
                return_schema,
                extra_imports,
                primary,
                concurrency,
            } => {
                env.insert(key.into(), value);
                Entrypoint::Function {
                    language,
                    module,
                    function,
                    format,
                    working_dir,
                    env,
                    args_schema,
                    return_schema,
                    extra_imports,
                    primary,
                    concurrency,
                }
            }
            Entrypoint::Command {
                command,
                working_dir,
                mut env,
            } => {
                env.insert(key.into(), value);
                Entrypoint::Command {
                    command,
                    working_dir,
                    env,
                }
            }
        }
    }

    fn with_args_schema(self, schema: serde_json::Map<String, serde_json::Value>) -> Self {
        match self {
            Entrypoint::Function {
                language,
                module,
                function,
                format,
                working_dir,
                env,
                return_schema,
                extra_imports,
                primary,
                concurrency,
                ..
            } => Entrypoint::Function {
                language,
                module,
                function,
                format,
                working_dir,
                env,
                args_schema: Some(mvm_ir::JsonSchemaShape(schema)),
                return_schema,
                extra_imports,
                primary,
                concurrency,
            },
            Entrypoint::Command { .. } => {
                panic!("with_args_schema only applies to function-call entrypoints")
            }
        }
    }

    fn with_return_schema(self, schema: serde_json::Map<String, serde_json::Value>) -> Self {
        match self {
            Entrypoint::Function {
                language,
                module,
                function,
                format,
                working_dir,
                env,
                args_schema,
                extra_imports,
                primary,
                concurrency,
                ..
            } => Entrypoint::Function {
                language,
                module,
                function,
                format,
                working_dir,
                env,
                args_schema,
                return_schema: Some(mvm_ir::JsonSchemaShape(schema)),
                extra_imports,
                primary,
                concurrency,
            },
            Entrypoint::Command { .. } => {
                panic!("with_return_schema only applies to function-call entrypoints")
            }
        }
    }
}

/// VM resource declaration.
pub fn resources(cpu_cores: u16, memory_mb: u32, rootfs_size_mb: u32) -> Resources {
    Resources {
        cpu_cores,
        memory_mb,
        rootfs_size_mb,
    }
}

// ────────────────────────────────────────────────────────────────────
// Network constructors
// ────────────────────────────────────────────────────────────────────

/// Network policy with the given mode. Use [`NetworkExt`] chained
/// setters to declare ports, egress allowlist, peers, and DNS.
pub fn network(mode: NetworkMode) -> Network {
    Network {
        mode,
        ports: Vec::new(),
        egress: None,
        peers: Vec::new(),
        dns: None,
    }
}

/// Chained-setter extensions on [`Network`]. Bring into scope via
/// `use mvm_sdk::*;`.
pub trait NetworkExt: Sized {
    fn with_port(self, port: PortForward) -> Self;
    fn with_egress(self, egress: NetworkEgress) -> Self;
    fn with_peers<I, S>(self, peers: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>;
    fn with_dns(self, dns: NetworkDns) -> Self;
}

impl NetworkExt for Network {
    fn with_port(mut self, port: PortForward) -> Self {
        self.ports.push(port);
        self
    }

    fn with_egress(mut self, egress: NetworkEgress) -> Self {
        self.egress = Some(egress);
        self
    }

    fn with_peers<I, S>(mut self, peers: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.peers = peers.into_iter().map(Into::into).collect();
        self
    }

    fn with_dns(mut self, dns: NetworkDns) -> Self {
        self.dns = Some(dns);
        self
    }
}

/// Build an egress allowlist from `(host, port)` pairs.
pub fn egress<I>(allowlist: I) -> NetworkEgress
where
    I: IntoIterator<Item = mvm_ir::HostPort>,
{
    NetworkEgress {
        allowlist: allowlist.into_iter().collect(),
    }
}

/// Build a host:port pair for an egress allowlist entry.
pub fn host_port(host: impl Into<String>, port: u16) -> mvm_ir::HostPort {
    mvm_ir::HostPort {
        host: host.into(),
        port,
    }
}

pub fn dns_none() -> NetworkDns {
    NetworkDns::None
}

pub fn dns_system() -> NetworkDns {
    NetworkDns::System
}

pub fn dns_resolver(host: impl Into<String>, port: u16) -> NetworkDns {
    NetworkDns::Resolver {
        host: host.into(),
        port,
    }
}

// ────────────────────────────────────────────────────────────────────
// Dependency constructors
// ────────────────────────────────────────────────────────────────────

/// Python lockfile dependency (`uv.lock` by default).
pub fn python_deps(lockfile: impl Into<String>) -> Dependencies {
    python_deps_with(lockfile, PythonTool::Uv)
}

pub fn python_deps_with(lockfile: impl Into<String>, tool: PythonTool) -> Dependencies {
    Dependencies::Python {
        lockfile: lockfile.into(),
        tool,
    }
}

/// Node lockfile dependency (`pnpm-lock.yaml` by default).
pub fn node_deps(lockfile: impl Into<String>) -> Dependencies {
    node_deps_with(lockfile, NodeTool::Pnpm)
}

pub fn node_deps_with(lockfile: impl Into<String>, tool: NodeTool) -> Dependencies {
    Dependencies::Node {
        lockfile: lockfile.into(),
        tool,
    }
}

/// Explicit "no runtime dependencies" — bypasses the host's lockfile
/// checks for stdlib-only workloads.
pub fn no_deps() -> Dependencies {
    Dependencies::None
}

// ────────────────────────────────────────────────────────────────────
// Emit
// ────────────────────────────────────────────────────────────────────

/// Emit the workload's canonical IR per the ADR-0002 subprocess
/// contract. Honors `MVM_IR_OUT`: when set, writes to that path;
/// when unset, writes to stdout.
pub fn emit(workload: &Workload) -> Result<(), EmitError> {
    let canonical = emit_json(workload)?;
    match std::env::var("MVM_IR_OUT") {
        Ok(path) => std::fs::write(&path, &canonical).map_err(|e| EmitError::Write(path, e)),
        Err(_) => {
            use std::io::Write;
            std::io::stdout()
                .write_all(canonical.as_bytes())
                .map_err(EmitError::Stdout)
        }
    }
}

/// Validate, canonicalize (RFC 8785), and return the canonical IR as a
/// String. Use [`emit`] when you want the ADR-0002 subprocess
/// behavior; this is the in-process variant for tests and embedding.
pub fn emit_json(workload: &Workload) -> Result<String, EmitError> {
    if let Err(errors) = mvm_ir::validate(workload) {
        return Err(EmitError::Validation(errors));
    }
    mvm_ir::canonicalize(workload).map_err(EmitError::Canonicalize)
}

// ────────────────────────────────────────────────────────────────────
// Re-exports — keep at the bottom so the upper-layer surface is
// the natural top-of-file read for users of the SDK.
// ────────────────────────────────────────────────────────────────────

#[allow(unused_imports)]
pub use mvm_ir::{ValidationError, ir_hash};

// Suppress warnings for the unused IR re-exports when downstream
// crates don't touch them — they're public API conveniences.
#[allow(dead_code)]
const _ASSERT_PORTFORWARD_USED: Option<PortForward> = None;
