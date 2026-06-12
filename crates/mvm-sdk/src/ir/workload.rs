use crate::ir::addon::{AddonUse, ThreatTier};
use crate::ir::hooks::Hooks;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A file materialized into the workload's rootfs at build time.
/// Replaces the legacy "write a file via a before_start shell hook"
/// path — content and destination are carried as data and baked
/// directly, so neither ever reaches a shell line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MaterializedFile {
    /// Absolute destination path in the guest rootfs.
    pub path: String,
    /// STANDARD-alphabet base64 of the file's bytes. Decoded at
    /// build time by the Nix factory; never decoded in a guest shell.
    pub bytes_b64: String,
    /// Octal mode string (e.g. `"0644"`). `None` → the factory's
    /// default (`0644`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Workload {
    pub schema_version: String,
    pub id: String,
    pub apps: Vec<App>,
    #[serde(default)]
    pub volumes: Vec<Volume>,
    #[serde(default)]
    pub extensions: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct App {
    pub name: String,
    pub source: Source,
    pub image: Image,
    /// One or more entrypoints. v0 single-function workloads have a
    /// one-element list; multi-function apps have multiple
    /// `Entrypoint::Function` entries with exactly one marked
    /// `primary = true`. Command-style entrypoints are always
    /// a single-element list.
    pub entrypoints: Vec<Entrypoint>,
    #[serde(default)]
    pub env: BTreeMap<String, EnvValue>,
    #[serde(default)]
    pub mounts: Vec<Mount>,
    #[serde(default)]
    pub network: Option<Network>,
    pub resources: Resources,
    /// Dependency declaration.
    ///
    /// Function-entrypoint workloads must declare this explicitly —
    /// either point at a hash-pinned lockfile or assert
    /// `kind = "none"` if the workload only needs stdlib. The host's
    /// `mvm validate` enforces existence + per-format hash-pin
    /// heuristic and rejects unpinned entries with `E_UNPINNED_DEPS`.
    ///
    /// Optional for command-style entrypoints (preserved v0
    /// behavior) until a future ADR flips that default.
    #[serde(default)]
    pub dependencies: Option<Dependencies>,
    /// Threat tier of the consumer (this app). Combined with the
    /// `[security].trust_tier` of each addon to drive mvmd's
    /// SMT-affinity scheduler matrix. Defaults to
    /// `Untrusted` (most protective). Workloads that run only
    /// first-party reviewed code can opt into `Trusted` for finer
    /// packing in mvmd's scheduler. **Skip-serialized when default
    /// (`Untrusted`)** so legacy corpus fixtures stay byte-identical;
    /// the default is the maximally-protective value.
    #[serde(default, skip_serializing_if = "ThreatTier::is_default")]
    pub threat_tier: ThreatTier,
    /// Composable addon-uses. Each entry pulls a sha-attested addon
    /// from the registry (or a local-path during development); mvmd
    /// instantiates each addon-use as a separate microVM and bridges
    /// it to this app over the workload mesh.
    ///
    /// Empty list (or absent field) = no addons; preserves the v0
    /// behavior. Each entry is validated against the lockfile by
    /// `addon::resolve_and_validate` (sibling to `compile::compile`,
    /// hermetic boundary preserved).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub addons: Vec<AddonUse>,
    /// Lifecycle hooks. Each phase is a `Vec<HookCmd>`; the compiler
    /// unions addon hooks (in attachment order) before the app's hooks.
    /// `Hooks::is_empty()` skip-serializes the field so v0 IR
    /// documents that don't carry `hooks` remain byte-identical.
    #[serde(default, skip_serializing_if = "Hooks::is_empty")]
    pub hooks: Hooks,
    /// Files baked into the rootfs at build time (was: FilesWrite
    /// before_start shell hooks).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub files: Vec<MaterializedFile>,
}

impl App {
    /// Return the workload's primary entrypoint — the function the
    /// substrate dispatches when `mvmctl invoke <id>` is called with
    /// no `--fn` selector. For single-entrypoint apps (the v0 shape
    /// and the most common case) this is the sole entry. For multi-
    /// function apps this is the entry with `primary: true`.
    /// Validator-side rules guarantee exactly one
    /// such entry exists; this helper falls back to the first
    /// entrypoint to keep panic-free behavior on un-validated IR.
    pub fn primary_entrypoint(&self) -> &Entrypoint {
        self.entrypoints
            .iter()
            .find(|ep| matches!(ep, Entrypoint::Function { primary: true, .. }))
            .or_else(|| self.entrypoints.first())
            .expect("App must have at least one entrypoint (validate() rejects empty)")
    }

    /// True iff this app declares a workload command — a `Command`
    /// argv or a `Function` dispatch target. The IR cannot represent
    /// "no declared entrypoint" (validate() rejects empty
    /// `entrypoints`), so for any validated SDK app this is true; the
    /// predicate is the single named signal the compile gate reads
    /// instead of re-deriving "is there a command?" inline. The
    /// admission gate enforces the same property one layer down, via the
    /// `SignedImageRef.entrypoint_present` wire field (a different crate —
    /// no shared symbol crosses the boundary). An idle image
    /// (`["sleep","infinity"]`) IS a declared command, so it is unaffected.
    pub fn has_declared_entrypoint(&self) -> bool {
        !self.entrypoints.is_empty()
    }
}

/// Per-app dependency declaration.
///
/// The host validates the lockfile exists in the bundled source
/// tree and that it's pinned (every entry carries hashes the
/// install step can verify). The actual install runs at image
/// build time inside the upstream-mvm Nix factory; this IR field
/// is the *declaration* shape, not the install machinery.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Dependencies {
    /// Python dependency lockfile.
    Python {
        /// Path to the lockfile, relative to `app.source.path`.
        lockfile: String,
        tool: PythonTool,
    },
    /// Node.js dependency lockfile.
    Node {
        /// Path to the lockfile, relative to `app.source.path`.
        lockfile: String,
        tool: NodeTool,
    },
    /// Explicit "no runtime dependencies" — workload only needs the
    /// language stdlib. Bypasses the host's lockfile checks.
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PythonTool {
    /// `uv.lock` (TOML, hash-pinned).
    Uv,
    /// `requirements.txt` rendered with `pip-compile --generate-hashes`
    /// (or equivalent), every requirement carries `--hash=sha256:...`.
    PipTools,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum NodeTool {
    /// `pnpm-lock.yaml` (every dep carries `integrity:`).
    Pnpm,
    /// `package-lock.json` v3 (every dep carries `integrity` + `resolved`).
    Npm,
    /// `yarn.lock` (Yarn classic v1) — every entry carries an
    /// `integrity "sha512-..."` line.
    Yarn,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Source {
    LocalPath {
        path: String,
        #[serde(default = "default_include")]
        include: Vec<String>,
        #[serde(default)]
        exclude: Vec<String>,
    },
    NixDerivation {
        expr: String,
    },
    OciImage {
        reference: String,
        digest: String,
    },
}

fn default_include() -> Vec<String> {
    vec!["**".to_string()]
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Image {
    NixPackages { packages: Vec<String> },
    OciBase { reference: String, digest: String },
}

/// How the wrapper inside the microVM is dispatched.
///
/// `Command` is the legacy shape: an explicit argv that runs once at
/// boot. `Function` is the function-call shape: a long-running
/// language wrapper baked into the image dispatches a
/// named function whose return value is encoded back to the caller per
/// the declared serialization format.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Entrypoint {
    /// Command-style entrypoint: the wrapper exec's `command` once at
    /// boot. Existing v0 shape, preserved.
    Command {
        command: Vec<String>,
        #[serde(default = "default_working_dir")]
        working_dir: String,
        #[serde(default)]
        env: BTreeMap<String, EnvValue>,
    },
    /// Function-call entrypoint: a baked per-language wrapper at
    /// `/etc/mvm/entrypoint` reads stdin,
    /// dispatches `module:function` per the declared `format`, writes
    /// the return on stdout. The host SDK calls
    /// `mvmctl invoke <workload> --stdin <encoded>` to invoke.
    ///
    /// `module` and `function` together name the dispatch target as
    /// the wrapper resolves it; the exact resolution rule is
    /// language-specific (e.g. Python `importlib.import_module(module)
    /// .function`). `format` selects the serialization the wrapper
    /// uses on stdin and stdout. Both are baked at image build time;
    /// nothing about dispatch is decided at call time except the
    /// args bytes.
    Function {
        /// Language whose shim renderer / Nix factory mvm
        /// dispatches to when compiling this entrypoint. Open string
        /// validated mvm-side; current allowlist is in
        /// `validate.rs::SUPPORTED_LANGUAGES`. Adding a language is
        /// a one-PR change in mvm — no IR schema bump. SDKs set this
        /// from their own language at
        /// registration time (`"python"` for the Python SDK,
        /// `"node"` for the TypeScript SDK); users can override
        /// for cross-language manifest authoring (e.g. authoring a
        /// Python workload from the TypeScript SDK).
        ///
        /// Replaces the earlier closed-enum `runtime: Runtime` field.
        /// Pre-1.0 schema bump.
        language: String,
        /// Module identifier (e.g. Python dotted path
        /// `pkg.subpkg.mod`, TypeScript module path `./src/mod`).
        module: String,
        /// Function identifier within the module.
        function: String,
        /// Serialization format for stdin args + stdout return.
        /// Closed enum: `Json` or `Msgpack` (code-executing serializer
        /// formats are forbidden).
        format: Format,
        #[serde(default = "default_working_dir")]
        working_dir: String,
        #[serde(default)]
        env: BTreeMap<String, EnvValue>,
        /// JSON Schema for the inbound args payload. Validated at
        /// build time for secret-shaped field names; will gate
        /// per-call payloads at the wrapper once the upstream-mvm
        /// factory wires it. Shape: a strict subset of JSON Schema
        /// (object/array/string/integer/number/boolean/null/enum/oneOf).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        args_schema: Option<JsonSchemaShape>,
        /// JSON Schema for the return value. Same shape constraints as
        /// `args_schema`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        return_schema: Option<JsonSchemaShape>,
        /// Extra modules to bundle beyond what the host's reachability
        /// walker discovers from the entry module. Use for dynamic
        /// imports, plugin loaders, and other paths the static AST walk
        /// can't follow. Each entry is a module
        /// identifier resolved relative to `working_dir` per the
        /// language's import rules.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        extra_imports: Vec<String>,
        /// Marks this entry as the workload's default function — the
        /// one `mvmctl invoke <id>` (no `--fn` selector) dispatches
        /// to. Multi-function apps require exactly one entrypoint to
        /// be primary; single-function apps mark
        /// their sole entrypoint primary by convention.
        #[serde(default)]
        primary: bool,
        /// Opt-in concurrency model for this entrypoint.
        ///
        /// When `None`, the function runs under the cold model: a fresh
        /// wrapper process per invocation. When `Some(WarmProcess(...))`,
        /// mvm bakes a long-running wrapper that handles many
        /// sequential calls without respawning, dispatched via mvm's
        /// warm-process worker pool. Warm-process is opt-in because
        /// state can leak across calls.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        concurrency: Option<Concurrency>,
    },
}

/// Concurrency model for a function-entrypoint.
///
/// Open enum tagged on `kind` so future tiers (`InProcessConcurrent`,
/// `Pool`, …) can be added without breaking existing IR. Today the
/// only variant is `WarmProcess` — a long-running wrapper handling
/// many sequential calls per worker, with bounded recycling.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Concurrency {
    /// Warm-process tier: wrapper stays alive across calls, recycled
    /// on call-count or RSS thresholds. Cold safety guarantees no
    /// longer hold.
    WarmProcess(WarmProcessConfig),
}

/// Tuning knobs for the warm-process tier.
///
/// Validated mvm-side: `pool_size ∈ [1,64]`,
/// `max_calls_per_worker >= 100`, `max_rss_mb <= app.resources.memory_mb`,
/// `in_process != Concurrent` (deferred to a follow-up ADR).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WarmProcessConfig {
    /// Recycle a worker after this many dispatches. Bounds memory
    /// growth from per-call interpreter state. Lower bound 100 —
    /// anything smaller cancels the warm-tier benefit.
    pub max_calls_per_worker: u64,
    /// Recycle a worker if its RSS exceeds this (MiB). Must not
    /// exceed `app.resources.memory_mb`.
    pub max_rss_mb: u64,
    /// Number of worker processes per microVM. v0.2 ships with `1`
    /// being the typical value; up to 64 is allowed.
    pub pool_size: usize,
    /// In-process dispatch mode. Only `Serial` is supported in v0.2;
    /// `Concurrent` is reserved for a follow-up ADR.
    pub in_process: InProcessMode,
    /// Optional cap on the number of pending calls queued in front
    /// of the pool. When unset, mvm picks a default. When set,
    /// callers receive backpressure once the queue is full.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_queue_depth: Option<usize>,
}

/// In-worker dispatch model. Only `Serial` is implemented in v0.2;
/// `Concurrent` (multiple in-flight calls per worker via async) is
/// rejected at parse time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum InProcessMode {
    /// One call at a time per worker.
    Serial,
    /// Multiple concurrent calls per worker. Reserved; rejected
    /// at validation time until a follow-up ADR.
    Concurrent,
}

/// Pass-through JSON-Schema-shaped value. We don't strongly type this
/// in Rust — it's a `serde_json::Value` constrained at deserialization
/// to be an object. The host walks it at validation time to enforce
/// the closed shape and reject secret-shaped field names; the wrapper
/// (when wired upstream) uses it for inbound payload validation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JsonSchemaShape(pub serde_json::Map<String, serde_json::Value>);

impl schemars::JsonSchema for JsonSchemaShape {
    fn schema_name() -> String {
        "JsonSchemaShape".to_string()
    }

    fn json_schema(_: &mut schemars::r#gen::SchemaGenerator) -> schemars::schema::Schema {
        // We accept an open object; constraints are enforced at
        // validate() time, not at the schema layer.
        schemars::schema::Schema::Object(schemars::schema::SchemaObject {
            instance_type: Some(schemars::schema::SingleOrVec::Single(Box::new(
                schemars::schema::InstanceType::Object,
            ))),
            ..Default::default()
        })
    }
}

/// Serialization format for function-entrypoint stdin / stdout.
/// Closed enum — adding a variant is a wire change reviewed against
/// the no-code-execution rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Format {
    /// JSON over UTF-8. Default for v1 — debugs cleanly with `cat`.
    Json,
    /// MessagePack. Opt-in for byte-/float-fidelity workloads.
    Msgpack,
}

fn default_working_dir() -> String {
    "/app".to_string()
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum EnvValue {
    Literal {
        value: String,
    },
    SecretRef {
        #[serde(rename = "ref")]
        reference: SecretRef,
    },
}

// allow(secret-debug): metadata-only — `name` is a secret-store key (not the
// secret value), `mount` is a delivery shape (env-var name or file path), and
// `auth_type`/`allowed_hosts` say how + where the secret is used on egress. No
// secret bytes ever live in this struct.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SecretRef {
    pub name: String,
    pub mount: SecretMount,
    /// How the keyholder uses the secret on egress (signer vs injector).
    pub auth_type: AuthType,
    /// The hosts the substituted credential may reach — the claim-12 binding.
    /// Supports `*.` subdomain wildcards (see [`host_matches`]). An empty list
    /// is an unbound secret, rejected at validation (`SecretWithoutBinding`).
    pub allowed_hosts: Vec<String>,
    /// Non-secret SigV4 parameters, present only for `auth_type = Sigv4`. The
    /// secret value is the secret-access-key; these name the credential scope
    /// (operator-set in the binding, reconstructed onto the ref at admission).
    /// `None` for every other auth type.
    #[serde(default)]
    pub sigv4: Option<Sigv4Params>,
}

/// The non-secret half of a SigV4 credential: the public access-key id and the
/// credential scope (`region`/`service`). The signing key (the AWS
/// secret-access-key) is **not** here — it lives in the secret store and never
/// leaves the signer. Identifying but not secret, so Debug is safe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Sigv4Params {
    /// The AWS access-key id (e.g. `AKIA…`). Public; pairs with the
    /// secret-access-key the signer holds.
    pub access_key_id: String,
    /// Credential-scope region (e.g. `us-east-1`).
    pub region: String,
    /// Credential-scope service (e.g. `s3`, `execute-api`).
    pub service: String,
}

/// How a secret authenticates an outbound request, so the keyholder picks the
/// right path: `Sigv4`/`Hmac` are *signed* (the key never leaves the signer);
/// `Bearer`/`Basic` are *injected* credentials.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AuthType {
    Sigv4,
    Hmac,
    Bearer,
    Basic,
}

/// Whether `host` is permitted by an `allowed_hosts` `pattern`. Exact match, or
/// a `*.suffix` wildcard that matches any subdomain of `suffix` at any depth but
/// NOT the apex `suffix` itself — the leading dot stops a registrable lookalike
/// (`*.example.com` rejects `evilexample.com`). Case-insensitive.
pub fn host_matches(pattern: &str, host: &str) -> bool {
    let pattern = pattern.to_ascii_lowercase();
    let host = host.to_ascii_lowercase();
    match pattern.strip_prefix("*.") {
        Some(suffix) => host.ends_with(&format!(".{suffix}")),
        None => pattern == host,
    }
}

// allow(secret-debug): metadata-only — variants carry the env-var name
// or filesystem path the secret will be delivered at, not the secret
// itself. The actual material is resolved at admission time.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SecretMount {
    Env { var: String },
    File { path: String },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Mount {
    pub target: String,
    pub source: MountSource,
    pub mode: MountMode,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum MountSource {
    Volume {
        name: String,
    },
    HostPath {
        path: String,
    },
    Tmpfs {
        size_mb: u32,
    },
    /// Open extension point: a mount source resolved by a registered
    /// `MountProvider` (S3, Hetzner Volume, NFS, …). `config` is the
    /// provider's own schema — the IR doesn't interpret it, so new sources
    /// plug in without a core-enum edit. An unregistered provider is
    /// rejected at resolve time (`MountError::UnknownFsProvider`), never
    /// silently defaulted. See `mvm_storage::mount_provider`.
    External {
        provider: String,
        config: serde_json::Value,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MountMode {
    Ro,
    Rw,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Network {
    pub mode: NetworkMode,
    #[serde(default)]
    pub ports: Vec<PortForward>,
    /// Granular egress allowlist. Each entry names a `host:port`
    /// pair the guest may dial. Wildcard hosts
    /// (`*`, `0.0.0.0`, `::`, `0.0.0.0/0`, `::/0`) are rejected with
    /// `E_NETWORK_WILDCARD`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub egress: Option<NetworkEgress>,
    /// Cross-workload reachability allowlist. Each entry is a
    /// workload id this app is allowed to talk to via the substrate's
    /// internal mesh. Validated against the `^[a-z][a-z0-9-]{0,62}$`
    /// id pattern.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub peers: Vec<String>,
    /// DNS posture. `Some(None_)` = no resolver;
    /// `Some(System)` = inherit substrate default; `Some(Resolver)` =
    /// pin a single host:port resolver. Default (None) means
    /// "unspecified — substrate picks based on `mode`".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns: Option<NetworkDns>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NetworkEgress {
    /// Allowed `host:port` destinations. Hosts may be IP literals or
    /// hostnames; CIDRs are rejected. Empty list means "no egress" —
    /// distinct from `mode = "none"` which removes the TAP entirely.
    pub allowlist: Vec<HostPort>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HostPort {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum NetworkDns {
    /// No DNS resolver — name resolution will fail. Use when the
    /// guest only contacts hosts by IP literal.
    None,
    /// Inherit the substrate's default resolver (mvm-side decision).
    /// May be tightened or rejected for prod-mode images in a
    /// future ADR.
    System,
    /// Pin to a specific resolver host:port.
    Resolver { host: String, port: u16 },
}

// `Copy`/`Eq` dropped when the open `Custom` variant arrived: its owned
// `String` + `serde_json::Value` (Value isn't `Eq`) can't be either. Same
// shape as `MountSource`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum NetworkMode {
    None,
    Bridge,
    Host,
    /// Open extension point: a mesh/VPN network resolved by a registered
    /// `NetworkProvider` (WireGuard, Tailscale, …). `config` is the
    /// provider's own schema; the IR doesn't interpret it, so a mesh plugs
    /// in without a core-enum edit. The guest's `netinit` reads a `Custom`
    /// config off the config-device. mvm builds none of the mesh logic — the
    /// impl is mvmd's; this is only the seam.
    Custom {
        provider: String,
        config: serde_json::Value,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PortForward {
    pub guest: u16,
    pub host: u16,
    pub proto: PortProto,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PortProto {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Resources {
    pub cpu_cores: u16,
    pub memory_mb: u32,
    pub rootfs_size_mb: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Volume {
    pub name: String,
    pub size_mb: u32,
    pub persist: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app_with(entrypoints: Vec<Entrypoint>) -> App {
        App {
            name: "hello".into(),
            source: Source::LocalPath {
                path: ".".into(),
                include: vec!["**".into()],
                exclude: vec![],
            },
            image: Image::NixPackages {
                packages: vec!["python312".into()],
            },
            entrypoints,
            env: Default::default(),
            mounts: vec![],
            network: None,
            resources: Resources {
                cpu_cores: 1,
                memory_mb: 256,
                rootfs_size_mb: 512,
            },
            dependencies: None,
            threat_tier: Default::default(),
            addons: vec![],
            hooks: Default::default(),
            files: vec![],
        }
    }

    fn minimal_app() -> App {
        app_with(vec![Entrypoint::Command {
            command: vec!["true".into()],
            working_dir: "/app".into(),
            env: Default::default(),
        }])
    }

    #[test]
    fn materialized_file_serde_roundtrip() {
        let f = MaterializedFile {
            path: "/app/.env".to_string(),
            bytes_b64: "aGk=".to_string(),
            mode: Some("0600".to_string()),
        };
        let json = serde_json::to_string(&f).unwrap();
        let back: MaterializedFile = serde_json::from_str(&json).unwrap();
        assert_eq!(f, back);
    }

    #[test]
    fn materialized_file_mode_defaults_to_none_and_is_omitted() {
        let f = MaterializedFile {
            path: "/app/x".to_string(),
            bytes_b64: "eA==".to_string(),
            mode: None,
        };
        let v = serde_json::to_value(&f).unwrap();
        assert!(
            v.get("mode").is_none(),
            "None mode must be omitted from the wire"
        );
    }

    #[test]
    fn app_files_defaults_empty_and_is_omitted_when_empty() {
        // An App with no materialized files must serialize without a `files` key
        // (back-compat with existing workloads).
        let json = serde_json::to_value(minimal_app()).unwrap();
        assert!(json.get("files").is_none(), "empty files must be skipped");
    }

    #[test]
    fn materialized_file_rejects_unknown_field() {
        let r: Result<MaterializedFile, _> =
            serde_json::from_str(r#"{"path":"/a","bytes_b64":"eA==","bogus":1}"#);
        assert!(r.is_err(), "deny_unknown_fields must reject extras");
    }

    #[test]
    fn has_declared_entrypoint_true_for_command_and_function() {
        let cmd = app_with(vec![Entrypoint::Command {
            command: vec!["python".into(), "-m".into(), "hello".into()],
            working_dir: "/app".into(),
            env: Default::default(),
        }]);
        assert!(cmd.has_declared_entrypoint());

        let func = app_with(vec![Entrypoint::Function {
            language: "python".into(),
            module: "adder".into(),
            function: "add".into(),
            format: Format::Json,
            working_dir: "/app".into(),
            env: Default::default(),
            args_schema: None,
            return_schema: None,
            extra_imports: vec![],
            primary: true,
            concurrency: None,
        }]);
        assert!(func.has_declared_entrypoint());
    }

    #[test]
    fn has_declared_entrypoint_false_for_empty_entrypoints() {
        assert!(!app_with(vec![]).has_declared_entrypoint());
    }

    #[test]
    fn secret_ref_carries_auth_type_and_hosts_never_bytes() {
        // The reference says HOW the secret is used (auth_type, so
        // the keyholder picks signer vs injector) and WHERE it may go
        // (allowed_hosts — the claim-12 binding). Still no bytes.
        let r: SecretRef = serde_json::from_str(
            r#"{"name":"openai","mount":{"kind":"env","var":"OPENAI_API_KEY"},"auth_type":"bearer","allowed_hosts":["api.openai.com"]}"#,
        )
        .unwrap();
        assert_eq!(r.auth_type, AuthType::Bearer);
        assert_eq!(r.allowed_hosts, ["api.openai.com"]);
        // deny_unknown_fields keeps a stray "value" out — no secret bytes in the IR.
        assert!(
            serde_json::from_str::<SecretRef>(
                r#"{"name":"x","mount":{"kind":"env","var":"X"},"value":"sk-..."}"#
            )
            .is_err()
        );
    }

    #[test]
    fn host_matches_handles_wildcards_and_lookalikes() {
        // Exact match.
        assert!(host_matches("api.openai.com", "api.openai.com"));
        assert!(!host_matches("api.openai.com", "evil.com"));
        // `*.` matches any subdomain depth, case-insensitively…
        assert!(host_matches("*.example.com", "api.example.com"));
        assert!(host_matches("*.example.com", "a.b.example.com"));
        assert!(host_matches("API.Example.COM", "api.example.com"));
        // …but NOT the apex, and the leading dot guards a registrable lookalike.
        assert!(!host_matches("*.example.com", "example.com"));
        assert!(!host_matches("*.example.com", "evilexample.com"));
    }
}
