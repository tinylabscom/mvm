//! `mvmctl exec` — boot a transient microVM, run one command, tear down.
//!
//! Composes existing primitives: template artifact resolution → backend
//! start → vsock guest agent → backend stop. The "what to run" is modeled
//! as a tagged enum so future variants (mvmforge `launch.json`, baked-in
//! template entrypoint) can be added without churning the inline-command
//! surface.
//!
//! Dev-mode only: the guest agent's Exec handler is gated at compile time
//! by the `interactive` Cargo feature. Production guest binaries are built
//! without `interactive`, so the handler is not present and `exec` returns
//! "exec not available" regardless of any runtime configuration.

use anyhow::{Context, Result, anyhow};
use mvm_core::vm_backend::{RequiredCapabilities, VmId, VmStartConfig, VmVolume};
use mvm_runtime::backend::AnyBackend;
use mvm_runtime::vsock_transport;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::Path;

use crate::ui;

/// Exit code the CLI returns when a guest command exceeds its `--timeout`.
/// Matches GNU `timeout(1)` so scripts can branch on it.
pub const EXEC_TIMEOUT_EXIT_CODE: i32 = 124;

/// Human-facing message for a command killed by its `--timeout`. `None`
/// timeout ⇒ no duration suffix (e.g. the interactive console path).
pub(crate) fn timeout_exit_message(timeout_secs: Option<u64>) -> String {
    let suffix = timeout_secs
        .map(|s| format!(" after {s}s"))
        .unwrap_or_default();
    format!("error: command timed out{suffix}")
}

/// Where to source the command that runs inside the transient microVM.
///
/// Marked `non_exhaustive` so future variants (e.g. baked-in template
/// entrypoint) can be added without breaking match arms in callers outside
/// this crate.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum ExecTarget {
    /// Argv supplied directly on the CLI.
    Inline { argv: Vec<String> },
    /// Entrypoint sourced from an mvmforge `launch.json` workload IR.
    ///
    /// v1 supports single-app workloads only. Multi-app workloads require
    /// orchestration that's out of scope for `mvmctl exec`.
    LaunchPlan { entrypoint: LaunchEntrypoint },
    // Future variants (do not implement until needed):
    // TemplateEntrypoint,               // entrypoint baked into template metadata
}

/// Resolved entrypoint extracted from an mvmforge `launch.json`.
///
/// Mirrors the subset of the v0 IR that `mvmctl exec` needs:
///   - `command` — argv to exec inside the guest.
///   - `working_dir` — optional `cd` target before exec.
///   - `env` — merged from `apps[].env` (lower precedence) and
///     `apps[].entrypoint.env` (higher precedence), per mvmforge semantics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchEntrypoint {
    pub command: Vec<String>,
    pub working_dir: Option<String>,
    pub env: BTreeMap<String, String>,
}

/// One `--add-dir host:guest[:mode]` mapping.
///
/// The host directory is materialized into a small ext4 image attached as
/// an extra Firecracker drive, then mounted at `guest_path` by a wrapper
/// script before the user's command runs. When `read_only` is false
/// (mode `:rw`), guest writes land in the ext4 image and are rsynced
/// back to the host directory after the command exits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddDir {
    pub host_path: String,
    pub guest_path: String,
    pub read_only: bool,
}

impl AddDir {
    /// Parse a `host:guest[:mode]` spec.
    ///
    /// The first colon splits host from guest. An optional trailing
    /// `:ro` or `:rw` selects the mount mode (default `:ro`). Other
    /// trailing tokens that look like a mode (no slash, alphanumeric)
    /// are rejected to catch typos. Guest paths that legitimately
    /// contain colons remain supported as long as the trailing
    /// component is unambiguously path-shaped (contains a slash).
    pub fn parse(spec: &str) -> Result<Self> {
        let (host, rest) = spec.split_once(':').ok_or_else(|| {
            anyhow::anyhow!("--add-dir '{spec}': expected 'host:guest[:mode]', missing ':'")
        })?;
        if host.is_empty() {
            anyhow::bail!("--add-dir '{spec}': host path must not be empty");
        }

        let (guest, read_only) = match rest.rsplit_once(':') {
            Some((path, "ro")) => (path, true),
            Some((path, "rw")) => (path, false),
            Some((_, tail)) if looks_like_mode_typo(tail) => {
                anyhow::bail!("--add-dir '{spec}': unknown mode '{tail}' (expected 'ro' or 'rw')");
            }
            _ => (rest, true),
        };

        if guest.is_empty() {
            anyhow::bail!("--add-dir '{spec}': guest path must not be empty");
        }
        if !guest.starts_with('/') {
            anyhow::bail!("--add-dir '{spec}': guest path must be absolute (start with '/')");
        }
        Ok(Self {
            host_path: expand_tilde(host),
            guest_path: guest.to_string(),
            read_only,
        })
    }
}

fn looks_like_mode_typo(tail: &str) -> bool {
    !tail.is_empty()
        && tail.len() <= 8
        && !tail.contains('/')
        && tail.chars().all(|c| c.is_ascii_alphanumeric())
}

fn expand_tilde(path: &str) -> String {
    if let Some(rest) = path.strip_prefix("~/")
        && let Ok(home) = std::env::var("HOME")
    {
        return format!("{home}/{rest}");
    }
    path.to_string()
}

/// Where the VM's disk image and kernel come from.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum ImageSource {
    /// A registered template (resolved via `template::lifecycle::template_artifacts`).
    Template(String),
    /// Pre-built kernel + rootfs paths (e.g., the cached dev image).
    Prebuilt {
        kernel_path: String,
        rootfs_path: String,
        initrd_path: Option<String>,
        /// Display label used in messages and `flake_ref` (no functional effect).
        label: String,
        /// When set, a candidate to boot from a read-only **virtiofs root**
        /// serving the unpacked+injected OCI tree instead of `rootfs_path`. Only
        /// the OCI `run --image` path sets it; the run-path tier gate
        /// ([`mvm_build::run_image::select_root_strategy`]) makes the final call
        /// from this candidate + the backend capability + sealed state.
        virtiofs_oci_root: Option<VirtiofsOciRoot>,
    },
}

/// A candidate unpacked OCI tree to boot as a virtiofs root, carried from OCI
/// resolution to the run-path tier gate.
#[derive(Debug, Clone)]
pub struct VirtiofsOciRoot {
    /// Host path of the unpacked+injected OCI tree to serve read-only.
    pub tree_dir: String,
    /// Whether this is a `--prod` run — a hard disqualifier for the dev-tier
    /// virtiofs path (the gate keeps prod on Option B / block+ext4).
    pub prod: bool,
}

pub fn runtime_source_policy_for(
    image: &ImageSource,
    backend_name: &str,
    sealed: bool,
    root_strategy: mvm_build::run_image::RootStrategy,
) -> mvm_core::vm_backend::RuntimeSourcePolicy {
    if matches!(
        image,
        ImageSource::Prebuilt {
            virtiofs_oci_root: Some(_),
            ..
        }
    ) && root_strategy == mvm_build::run_image::RootStrategy::BlockExt4
    {
        return mvm_core::vm_backend::RuntimeSourcePolicy::RequiredOverlay;
    }
    let launch_kind = match image {
        ImageSource::Template(_) => mvm_core::vm_backend::RuntimeSourceLaunchKind::WorkloadImage,
        ImageSource::Prebuilt { .. } => {
            mvm_core::vm_backend::RuntimeSourceLaunchKind::InjectedRootfs
        }
    };
    let root_strategy = match root_strategy {
        mvm_build::run_image::RootStrategy::VirtiofsRoot => {
            mvm_core::vm_backend::RuntimeSourceRootStrategy::VirtiofsRoot
        }
        mvm_build::run_image::RootStrategy::BlockExt4 => {
            mvm_core::vm_backend::RuntimeSourceRootStrategy::BlockExt4
        }
    };
    mvm_core::vm_backend::select_runtime_source_policy(
        mvm_core::vm_backend::RuntimeSourcePolicySelection {
            backend_name: Some(backend_name),
            sealed,
            root_strategy: Some(root_strategy),
            launch_kind,
        },
    )
}

#[cfg(test)]
mod runtime_source_policy_tests {
    use super::*;

    #[test]
    fn templates_require_overlay_on_block_boots() {
        // A block-rooted flake/template workload sources its guest binaries from
        // the overlay, so it fails closed when the overlay is unavailable rather
        // than silently falling back to the baked rootfs copy.
        assert_eq!(
            runtime_source_policy_for(
                &ImageSource::Template("t".into()),
                "libkrun",
                false,
                mvm_build::run_image::RootStrategy::BlockExt4,
            ),
            mvm_core::vm_backend::RuntimeSourcePolicy::RequiredOverlay
        );
    }

    #[test]
    fn prebuilt_oci_virtiofs_roots_stay_rootfs_only() {
        let image = ImageSource::Prebuilt {
            kernel_path: "/k".into(),
            rootfs_path: "/r".into(),
            initrd_path: None,
            label: "oci".into(),
            virtiofs_oci_root: Some(VirtiofsOciRoot {
                tree_dir: "/tree".into(),
                prod: false,
            }),
        };
        assert_eq!(
            runtime_source_policy_for(
                &image,
                "hvf",
                false,
                mvm_build::run_image::RootStrategy::VirtiofsRoot,
            ),
            mvm_core::vm_backend::RuntimeSourcePolicy::RootfsOnly
        );
    }

    #[test]
    fn prebuilt_oci_block_roots_require_overlay() {
        let image = ImageSource::Prebuilt {
            kernel_path: "/k".into(),
            rootfs_path: "/r".into(),
            initrd_path: None,
            label: "oci".into(),
            virtiofs_oci_root: Some(VirtiofsOciRoot {
                tree_dir: "/tree".into(),
                prod: false,
            }),
        };
        assert_eq!(
            runtime_source_policy_for(
                &image,
                "hvf",
                false,
                mvm_build::run_image::RootStrategy::BlockExt4,
            ),
            mvm_core::vm_backend::RuntimeSourcePolicy::RequiredOverlay
        );
    }
}

/// The run-path tier gate: return the tree to boot as a virtiofs root, or `None`
/// to use the block rootfs. `select_root_strategy` is the single authority — it
/// can never yield virtiofs for a prod or sealed workload, nor on a
/// non-virtiofs-capable backend. Only an OCI `Prebuilt` carrying a candidate can
/// reach virtiofs at all; every other image source is `None`.
fn resolve_virtiofs_root(
    image: &ImageSource,
    backend_virtiofs_root: bool,
    sealed: bool,
) -> Option<String> {
    let ImageSource::Prebuilt {
        virtiofs_oci_root: Some(candidate),
        ..
    } = image
    else {
        return None;
    };
    match mvm_build::run_image::select_root_strategy(mvm_build::run_image::RootStrategySelection {
        backend_virtiofs_root,
        prod: candidate.prod,
        sealed,
    }) {
        mvm_build::run_image::RootStrategy::VirtiofsRoot => Some(candidate.tree_dir.clone()),
        mvm_build::run_image::RootStrategy::BlockExt4 => None,
    }
}

fn effective_transient_initrd(
    image: &ImageSource,
    explicit_initrd: Option<&str>,
    rootfs_path: &str,
    runtime_source_policy: mvm_core::vm_backend::RuntimeSourcePolicy,
    root_strategy: mvm_build::run_image::RootStrategy,
) -> Result<Option<String>> {
    if let Some(path) = explicit_initrd {
        return Ok(Some(path.to_string()));
    }
    if root_strategy != mvm_build::run_image::RootStrategy::BlockExt4 {
        return Ok(None);
    }
    let ImageSource::Prebuilt {
        virtiofs_oci_root: Some(_),
        ..
    } = image
    else {
        return Ok(None);
    };
    crate::commands::vm::up::persistent_oci_effective_initrd(
        std::path::Path::new(rootfs_path),
        runtime_source_policy,
    )
}

/// All inputs to the orchestrator.
#[derive(Debug, Clone)]
pub struct ExecRequest {
    /// Optional VM identity for a foreground transient run. Absent generates a
    /// throwaway name.
    pub name: Option<String>,
    pub image: ImageSource,
    pub cpus: u32,
    pub memory_mib: u32,
    /// Opt into virtio-balloon. `None` keeps the legacy "commit
    /// memory_mib at boot" behaviour; `Some(n)` commits only `n` MiB
    /// initially and lets the host-side reclaim controller adjust.
    /// See [`VmStartConfig::mem_initial_mib`].
    ///
    /// [`VmStartConfig::mem_initial_mib`]:
    ///     mvm_core::vm_backend::VmStartConfig::mem_initial_mib
    pub mem_initial_mib: Option<u32>,
    pub add_dirs: Vec<AddDir>,
    pub env: Vec<(String, String)>,
    pub target: ExecTarget,
    /// Timeout for the in-guest command in seconds. `None` ⇒ no per-command
    /// kill (the default for interactive/ad-hoc exec).
    pub timeout_secs: Option<u64>,
    /// Run the command attached to a PTY instead of pipe-streamed stdio.
    pub pty: bool,
    /// Effective egress policy for the transient VM. Defaults to
    /// `deny_all`; `--net` / `--allow-host` widen it. Threaded onto
    /// `VmStartConfig.network_policy` so every backend enforces the same
    /// value.
    pub network_policy: mvm_core::network_policy::NetworkPolicy,
    /// Warm-pool size for this transient run. `> 0` makes the run
    /// eligible to claim a pre-booted standby (skipping cold boot) and to
    /// replenish the pool after teardown; `0` always cold-boots. Resolved from
    /// `MachineRunMode::warm_pool_size` — nonzero only for throwaway auto-named
    /// transient/interactive-transient runs.
    pub warm_pool_size: u32,
    /// Bytes to forward to the guest `Exec` frame's stdin field. Empty ⇒ no
    /// stdin (`GuestRequest::Exec.stdin = None`). Set from piped host stdin
    /// when the host is not a TTY; always empty for PTY / interactive modes.
    pub stdin: Vec<u8>,
    /// Recorded liveness declaration (phase A: presence only). Persisted with a
    /// persistent machine so it survives + is inspectable; not yet probed.
    pub healthcheck: Option<mvm_protocol::ir::HealthCheck>,
    /// Requested workload hypervisor (from `--hypervisor`), or `None` to
    /// auto-detect. Kept here so `run_inner`'s backend selection agrees with the
    /// admit/build sites that read it off `RunArgs`.
    pub hypervisor: Option<String>,
}

pub(crate) fn select_exec_backend(
    image_requested: bool,
    network_policy: &mvm_core::network_policy::NetworkPolicy,
    requested: Option<&str>,
) -> Result<AnyBackend> {
    // CLI `--hypervisor` wins over the MVM_HYPERVISOR/MVM_BACKEND env override.
    let backend_override = requested
        .and_then(normalize_backend_override)
        .or_else(explicit_hypervisor_override);
    let backend_name = select_backend_name_for_egress(
        backend_override.as_deref(),
        image_requested,
        network_policy,
        "OCI --image runs with outbound egress enabled",
    )?;
    Ok(AnyBackend::from_hypervisor(&backend_name))
}

/// An explicit workload-backend override from the environment. The transient
/// run path otherwise auto-detects the backend; this lets `MVM_HYPERVISOR`
/// (or `MVM_BACKEND`) pin it — e.g. `libkrun`, whose vsock-tunnel egress path
/// the auto-detected default would otherwise never select on this host. Every
/// `select_exec_backend` call site reads the same value, so the admitted plan's
/// backend and the boot backend agree.
fn explicit_hypervisor_override() -> Option<String> {
    ["MVM_HYPERVISOR", "MVM_BACKEND"]
        .into_iter()
        .filter_map(std::env::var_os)
        .find_map(|raw| normalize_backend_override(&raw.to_string_lossy()))
}

/// Normalize a backend-override string (trim + lowercase); a blank value yields
/// `None` so an empty env var is treated as "unset" rather than an invalid
/// backend name.
fn normalize_backend_override(raw: &str) -> Option<String> {
    let value = raw.trim().to_ascii_lowercase();
    (!value.is_empty()).then_some(value)
}

pub(crate) fn select_backend_name_for_egress(
    backend_override: Option<&str>,
    image_requested: bool,
    network_policy: &mvm_core::network_policy::NetworkPolicy,
    workload: &str,
) -> Result<String> {
    if let Some(backend_name) = backend_override {
        validate_backend_for_egress(backend_name, image_requested, network_policy, workload)?;
        return Ok(backend_name.to_string());
    }

    if !requires_vsock_proxy_backend(image_requested, network_policy) {
        return Ok(AnyBackend::auto_select().name().to_string());
    }

    AnyBackend::select_capable_available(&vsock_proxy_backend_requirements())
        .map(|backend| backend.name().to_string())
        .map_err(|e| anyhow!("{workload} require a NIC-less host-vsock-proxy backend: {e}"))
}

pub(crate) fn validate_backend_for_egress(
    backend_name: &str,
    image_requested: bool,
    network_policy: &mvm_core::network_policy::NetworkPolicy,
    workload: &str,
) -> Result<()> {
    if !requires_vsock_proxy_backend(image_requested, network_policy) {
        return Ok(());
    }

    let backend = AnyBackend::from_hypervisor(backend_name);
    let missing = backend
        .capabilities()
        .shortfall(&vsock_proxy_backend_requirements());
    if missing.is_empty() {
        let available = backend
            .is_available()
            .with_context(|| format!("probing backend {backend_name} availability"))?;
        if available {
            return Ok(());
        }
        anyhow::bail!(
            "{workload} require a NIC-less host-vsock-proxy backend; backend {backend_name} is unavailable on this host"
        );
    }

    anyhow::bail!(
        "{workload} require a NIC-less host-vsock-proxy backend; backend {backend_name} lacks [{}]",
        missing.join(", ")
    );
}

fn requires_vsock_proxy_backend(
    image_requested: bool,
    network_policy: &mvm_core::network_policy::NetworkPolicy,
) -> bool {
    image_requested && network_policy.allows_egress()
}

fn vsock_proxy_backend_requirements() -> RequiredCapabilities {
    RequiredCapabilities {
        vsock: true,
        no_routable_guest_nic: true,
        host_vsock_proxy: true,
        ..Default::default()
    }
}

pub(crate) fn validate_image_egress_backend(
    backend: &AnyBackend,
    image_requested: bool,
    network_policy: &mvm_core::network_policy::NetworkPolicy,
) -> Result<()> {
    if !image_requested || !network_policy.allows_egress() {
        return Ok(());
    }
    let caps = backend.capabilities();
    if caps.vsock && caps.no_routable_guest_nic && caps.host_vsock_proxy {
        return Ok(());
    }
    anyhow::bail!(
        "OCI --image runs with outbound egress enabled require a NIC-less host-vsock-proxy backend; \
         backend {} does not advertise {{vsock,no_routable_guest_nic,host_vsock_proxy}}",
        backend.name()
    );
}

pub(crate) fn validate_image_egress_backend_name(
    backend_name: &str,
    image_requested: bool,
    network_policy: &mvm_core::network_policy::NetworkPolicy,
) -> Result<()> {
    let backend = AnyBackend::from_hypervisor(backend_name);
    validate_image_egress_backend(&backend, image_requested, network_policy)
}

fn request_uses_vsock_proxy_backend(req: &ExecRequest) -> bool {
    matches!(
        &req.image,
        ImageSource::Prebuilt {
            virtiofs_oci_root: Some(_),
            ..
        }
    ) && req.network_policy.allows_egress()
}

/// Build the IR healthcheck from the CLI flags. A shell command string becomes
/// an exec argv the guest agent runs (`/bin/sh -lc <cmd>`). `None` command ⇒ no
/// healthcheck (a plain task).
pub fn build_healthcheck(
    cmd: Option<&str>,
    interval_secs: u32,
    timeout_secs: u32,
    retries: u32,
    start_period_secs: u32,
) -> Option<mvm_protocol::ir::HealthCheck> {
    let cmd = cmd?;
    Some(mvm_protocol::ir::HealthCheck {
        command: vec!["/bin/sh".into(), "-lc".into(), cmd.to_string()],
        interval_secs,
        timeout_secs,
        retries,
        start_period_secs,
    })
}

impl ExecRequest {
    /// Convert the target into a single shell command string suitable for
    /// `GuestRequest::Exec`. Argv is shell-quoted and prefixed with `exec`
    /// so the process inherits the wrapper's stdio.
    pub fn target_command(&self) -> String {
        match &self.target {
            ExecTarget::Inline { argv } => quote_argv_for_exec(argv),
            ExecTarget::LaunchPlan { entrypoint } => quote_argv_for_exec(&entrypoint.command),
        }
    }
}

fn quote_argv_for_exec(argv: &[String]) -> String {
    let quoted: Vec<String> = argv.iter().map(|a| shell_quote(a)).collect();
    format!("exec {}", quoted.join(" "))
}

// ---------------------------------------------------------------------------
// mvmforge launch.json parser
// ---------------------------------------------------------------------------

/// Permissive deserialization shapes for the two JSON documents mvmforge
/// produces:
///
/// 1. **LaunchPlan artifact** (`<artifact-dir>/launch.json` from
///    `mvmforge compile`): top-level `entrypoint` + `env`, plus
///    `flake_attribute` / `workload_id` / `artifact_format_version`
///    metadata. This is the canonical handoff to mvm.
/// 2. **Workload IR manifest** (`mvmforge emit` stdout, also accepted by
///    `mvmforge compile` as input): top-level `apps[]` with
///    `apps[].entrypoint`. Useful for callers that wire mvmforge's emitter
///    to `mvmctl exec` without going through `compile`.
///
/// `deny_unknown_fields` is intentionally NOT set so newer mvmforge
/// releases that add optional fields don't break parsing.
#[derive(Debug, Deserialize)]
struct RawLaunchPlan {
    /// Present only on the LaunchPlan artifact shape.
    #[serde(default)]
    entrypoint: Option<RawLaunchEntrypoint>,
    /// Present only on the LaunchPlan artifact shape (top-level env merged
    /// under `entrypoint.env`).
    #[serde(default)]
    env: BTreeMap<String, String>,
    /// Present only on the Workload IR shape.
    #[serde(default)]
    apps: Vec<RawLaunchApp>,
}

#[derive(Debug, Deserialize)]
struct RawLaunchApp {
    #[serde(default)]
    name: Option<String>,
    entrypoint: RawLaunchEntrypoint,
    #[serde(default)]
    env: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct RawLaunchEntrypoint {
    #[serde(default)]
    command: Vec<String>,
    #[serde(default)]
    working_dir: Option<String>,
    #[serde(default)]
    env: BTreeMap<String, String>,
}

/// Read and parse an mvmforge document from disk.
///
/// Accepts either the LaunchPlan artifact (`mvmforge compile`'s `launch.json`)
/// or the Workload IR manifest (`mvmforge emit` stdout). The shape is
/// auto-detected. v1 supports single-app workloads only — IR with multiple
/// `apps[]` entries is rejected.
pub fn load_launch_plan(path: &Path) -> Result<LaunchEntrypoint> {
    let bytes =
        std::fs::read(path).with_context(|| format!("reading launch plan '{}'", path.display()))?;
    let raw: RawLaunchPlan = serde_json::from_slice(&bytes)
        .with_context(|| format!("parsing launch plan '{}' as JSON", path.display()))?;
    parse_launch_plan(raw, &path.display().to_string())
}

fn parse_launch_plan(raw: RawLaunchPlan, source: &str) -> Result<LaunchEntrypoint> {
    let RawLaunchPlan {
        entrypoint: top_entrypoint,
        env: top_env,
        apps,
    } = raw;
    match (top_entrypoint, apps.is_empty()) {
        (Some(entrypoint), true) => parse_launch_artifact(entrypoint, top_env, source),
        (None, false) => parse_workload_ir(apps, source),
        (Some(_), false) => anyhow::bail!(
            "launch plan '{source}': both top-level `entrypoint` and `apps[]` present — pick one shape (mvmforge launch.json artifact or Workload IR manifest)",
        ),
        (None, true) => anyhow::bail!(
            "launch plan '{source}': missing both top-level `entrypoint` (mvmforge launch.json artifact) and `apps[]` (Workload IR manifest)",
        ),
    }
}

/// Parse the LaunchPlan artifact shape emitted by `mvmforge compile`.
fn parse_launch_artifact(
    entrypoint: RawLaunchEntrypoint,
    top_env: BTreeMap<String, String>,
    source: &str,
) -> Result<LaunchEntrypoint> {
    if entrypoint.command.is_empty() {
        anyhow::bail!("launch plan '{source}': entrypoint.command must be non-empty");
    }
    // mvmforge: top-level env is merged under (overridden by) entrypoint.env.
    let mut merged = top_env;
    for (k, v) in entrypoint.env {
        merged.insert(k, v);
    }
    Ok(LaunchEntrypoint {
        command: entrypoint.command,
        working_dir: entrypoint.working_dir,
        env: merged,
    })
}

/// Parse the Workload IR manifest shape (top-level `apps[]`).
fn parse_workload_ir(apps: Vec<RawLaunchApp>, source: &str) -> Result<LaunchEntrypoint> {
    if apps.len() > 1 {
        let names: Vec<&str> = apps
            .iter()
            .map(|a| a.name.as_deref().unwrap_or("<unnamed>"))
            .collect();
        anyhow::bail!(
            "launch plan '{source}' has {} apps ({}); `mvmctl exec` v1 supports single-app workloads only",
            apps.len(),
            names.join(", "),
        );
    }
    let RawLaunchApp {
        name: _,
        entrypoint,
        env: app_env,
    } = apps.into_iter().next().expect("apps non-empty");
    if entrypoint.command.is_empty() {
        anyhow::bail!("launch plan '{source}': entrypoint.command must be non-empty");
    }
    // mvmforge: app.env is merged under (overridden by) entrypoint.env.
    let mut merged = app_env;
    for (k, v) in entrypoint.env {
        merged.insert(k, v);
    }
    Ok(LaunchEntrypoint {
        command: entrypoint.command,
        working_dir: entrypoint.working_dir,
        env: merged,
    })
}

/// Quote a single argument for inclusion in a shell command line.
///
/// Wraps in single quotes and escapes embedded single quotes the
/// portable POSIX way (`'` → `'\''`).
pub fn shell_quote(arg: &str) -> String {
    let mut out = String::with_capacity(arg.len() + 2);
    out.push('\'');
    for ch in arg.chars() {
        if ch == '\'' {
            out.push_str(r"'\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

/// Build the wrapper script that runs inside the guest:
///   1. mounts each `--add-dir` ext4 image read-only by label
///   2. exports launch-plan-derived env vars (when target is LaunchPlan)
///   3. exports CLI `--env` vars (CLI overrides launch-plan)
///   4. cds into `working_dir` (when target is LaunchPlan and it's set)
///   5. execs the resolved command
///
/// `add_dir_labels` is the parallel list of ext4 labels assigned to each
/// `AddDir` (in the same order as `req.add_dirs`).
///
/// Env precedence (lowest → highest): launch-plan app.env → launch-plan
/// entrypoint.env → CLI `--env`. The first two are merged in
/// `parse_launch_plan`; CLI wins by being emitted last.
pub fn build_guest_wrapper(req: &ExecRequest, add_dir_labels: &[String]) -> String {
    let mut script = String::from("set -e\n");
    for (dir, label) in req.add_dirs.iter().zip(add_dir_labels.iter()) {
        let mount_point = shell_quote(&dir.guest_path);
        let label_q = shell_quote(label);
        let mount_opts = if dir.read_only { " -o ro" } else { "" };
        script.push_str(&format!(
            "mkdir -p {mount_point}\nmount LABEL={label_q} {mount_point}{mount_opts}\n",
        ));
    }
    if let ExecTarget::LaunchPlan { entrypoint } = &req.target {
        for (k, v) in &entrypoint.env {
            script.push_str(&format!("export {k}={}\n", shell_quote(v)));
        }
    }
    for (k, v) in &req.env {
        script.push_str(&format!("export {k}={}\n", shell_quote(v)));
    }
    if let ExecTarget::LaunchPlan { entrypoint } = &req.target
        && let Some(wd) = &entrypoint.working_dir
    {
        script.push_str(&format!("cd {}\n", shell_quote(wd)));
    }
    script.push_str(&req.target_command());
    script.push('\n');
    script
}

/// Generate a transient VM name for an exec invocation.
pub fn transient_vm_name() -> String {
    mvm_core::naming::generate_machine_name()
}

/// Whether a transient run should pre-open interactive console data sockets.
///
/// `true` only when the caller requested a PTY (`pty`) AND the image is not
/// sealed (`image_sealed == false`). A verity-backed OCI/dev image may still be
/// interactive, so sealing/accessibility must follow the image sidecar rather
/// than the presence of verity sidecars alone.
pub fn transient_run_dev_console(pty: bool, image_sealed: bool) -> bool {
    pty && !image_sealed
}

/// Remove the transient VM's host state dir (`~/.mvm/vms/<name>`, which also
/// holds any `--add-dir` extra images) once the VM is stopped. Host-side
/// `std::fs` — never `run_in_vm`, which targets a path *inside* the guest and
/// (on macOS) would wake a builder VM to `rm` a path that isn't there, leaking
/// the real host dir. Runs for every transient run, `--add-dir` or not: the
/// backend writes `hvf.pid` / `console.log` here regardless, so a plain OCI
/// launch created the dir and must clean it up too. Best-effort — teardown must
/// never fail on a cleanup error.
fn remove_transient_state_dir(staging_dir: &str) {
    match std::fs::remove_dir_all(staging_dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            tracing::debug!(error = %e, dir = staging_dir, "transient state dir cleanup failed");
        }
    }
}

/// Decide whether snapshot restore is safe for this request.
///
/// Only enabled for the trivial case: a registered template (so the image
/// has a snapshot at all), no `--add-dir` extras (so the drive layout
/// matches the snapshot's recorded layout), and a backend that advertises
/// snapshot support. Adding `--add-dir` would change the drive count and
/// break the snapshot — that case stays cold-boot for now.
pub fn snapshot_eligible(
    image: &ImageSource,
    add_dirs: &[AddDir],
    snap_present: bool,
    backend_supports_snapshots: bool,
) -> bool {
    if !backend_supports_snapshots || !snap_present || !add_dirs.is_empty() {
        return false;
    }
    matches!(image, ImageSource::Template(_))
}

/// Captured stdout/stderr/exit-code from a one-shot exec.
///
/// `run_captured` returns this instead of streaming guest output to the
/// CLI's terminal. The MCP server consumes it to assemble a `tools/call`
/// response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecOutput {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

/// Run the request and capture stdout/stderr instead of streaming.
///
/// Same orchestration as [`run`]: boot a transient microVM, dispatch
/// the command via the guest agent's `Exec` over vsock, tear down.
/// The only difference is what happens with the guest's stdout/stderr
/// — captured into the returned [`ExecOutput`] instead of inherited
/// to the parent process's terminal.
///
/// Used by `mvmctl mcp` to build MCP `tools/call run` responses; the
/// CLI's interactive `mvmctl exec` keeps using [`run`] (streaming) so
/// human ergonomics don't regress.
pub fn run_captured(req: ExecRequest, admit: Option<&SessionAdmit<'_>>) -> Result<ExecOutput> {
    run_inner(req, /* capture = */ true, admit, None, None)
        .map(|either| either.right().expect("capture mode returns ExecOutput"))
}

/// Like [`run_captured`], but also reports the resolved boot posture into
/// `posture` so the command layer can chain-audit it (`plan.boot_posture`).
pub fn run_captured_with_posture(
    req: ExecRequest,
    admit: Option<&SessionAdmit<'_>>,
    posture: &PostureSink,
    runtime_source_policy: &RuntimeSourcePolicySink,
) -> Result<ExecOutput> {
    run_inner(
        req,
        /* capture = */ true,
        admit,
        Some(posture),
        Some(runtime_source_policy),
    )
    .map(|either| either.right().expect("capture mode returns ExecOutput"))
}

/// Run the request: boot, run, tear down.
///
/// Returns the guest command's exit code. On orchestrator failure (boot,
/// agent unreachable, vsock error), returns an error; the VM is torn down
/// best-effort before returning.
pub fn run(req: ExecRequest, admit: Option<&SessionAdmit<'_>>) -> Result<i32> {
    run_inner(req, /* capture = */ false, admit, None, None)
        .map(|either| either.left().expect("streaming mode returns exit code"))
}

/// Like [`run`], but also reports the resolved boot posture into `posture` so
/// the command layer can chain-audit it (`plan.boot_posture`).
pub fn run_with_posture(
    req: ExecRequest,
    admit: Option<&SessionAdmit<'_>>,
    posture: &PostureSink,
    runtime_source_policy: &RuntimeSourcePolicySink,
) -> Result<i32> {
    run_inner(
        req,
        /* capture = */ false,
        admit,
        Some(posture),
        Some(runtime_source_policy),
    )
    .map(|either| either.left().expect("streaming mode returns exit code"))
}

/// Tagged union for the two return shapes [`run`] and [`run_captured`]
/// share. Internal — the public API exposes the unboxed variants.
enum Either<L, R> {
    Left(L),
    Right(R),
}
impl<L, R> Either<L, R> {
    fn left(self) -> Option<L> {
        match self {
            Either::Left(l) => Some(l),
            Either::Right(_) => None,
        }
    }
    fn right(self) -> Option<R> {
        match self {
            Either::Right(r) => Some(r),
            Either::Left(_) => None,
        }
    }
}

/// Side channel by which [`run_inner`] reports the resolved boot posture (which
/// rootfs strategy the run-path tier gate selected) back to the command layer,
/// which records it on the chain-signed admission log (`plan.boot_posture`).
/// The command layer reads it after the run returns. `None` means the caller
/// does not audit posture (MCP / session boots, which never reach virtiofs).
pub type PostureSink = std::cell::Cell<mvm_build::run_image::RootStrategy>;
pub type RuntimeSourcePolicySink = std::cell::Cell<mvm_core::vm_backend::RuntimeSourcePolicy>;

/// A backend that advertises a host-vsock egress proxy carries all guest
/// egress over vsock with no routable guest NIC. The L3 packet tunnel is a
/// second, incompatible egress data plane for the same workload — and its
/// guest bring-up writes `/etc/resolv.conf`, which fails on a read-only
/// sealed rootfs. A workload must boot with exactly one egress data plane,
/// so drop the tunnel for host-vsock-proxy backends; backends without one
/// (their only vsock-only egress IS this tunnel) keep it.
fn drop_l3_tunnel_for_host_vsock_proxy(config: &mut VmStartConfig, backend: &AnyBackend) {
    if config.network_tunnel.is_some() && backend.capabilities().host_vsock_proxy {
        config.network_tunnel = None;
    }
}

fn run_inner(
    req: ExecRequest,
    capture: bool,
    admit: Option<&SessionAdmit<'_>>,
    posture: Option<&PostureSink>,
    runtime_source_policy_sink: Option<&RuntimeSourcePolicySink>,
) -> Result<Either<i32, ExecOutput>> {
    let backend = select_exec_backend(
        request_uses_vsock_proxy_backend(&req),
        &req.network_policy,
        req.hypervisor.as_deref(),
    )?;

    // Phase timing (off unless `MVM_PHASE_TIMING` is set): capture a
    // host-monotonic mark at each run seam, then emit a one-line breakdown
    // at teardown. When disabled every mark stays `None` and costs nothing.
    let timing = crate::commands::vm::phase_timing::enabled();
    let t_start = timing.then(std::time::Instant::now);

    // Resolve image artifacts: either a named template or a pre-built pair.
    // For templates, also probe for a pre-built snapshot so we can skip the
    // cold-boot cost when the request is snapshot-eligible.
    let resolved = resolve_image_artifacts(&req.image)?;

    let t_image_resolved = timing.then(std::time::Instant::now);

    // Build read-only ext4 images for each --add-dir, staged in a transient
    // VMS subdirectory so cleanup is straightforward.
    let AddDirStaging {
        vm_name,
        staging_dir,
        volumes,
        add_dir_labels,
    } = stage_add_dir_volumes(&req)?;

    // Snapshot eligibility, the dm-verity sidecar probe, the virtiofs-root
    // tier gate, and the effective initrd all fall out of the resolved image
    // + backend capabilities; see `resolve_boot_strategy`.
    let boot = resolve_boot_strategy(&req, &backend, &resolved)?;

    // Report the resolved strategy to the command layer for chain-audit. This is
    // the single source of truth — the same value that drives the boot below —
    // so the `plan.boot_posture` entry can never diverge from what actually
    // booted.
    if let Some(sink) = posture {
        sink.set(boot.root_strategy);
    }
    if let Some(sink) = runtime_source_policy_sink {
        sink.set(boot.runtime_source_policy);
    }
    let mut use_snapshot = boot.use_snapshot;

    let t_drives_ready = timing.then(std::time::Instant::now);

    // Template-restore VMs run without plan admission. Leave tenant_id /
    // plan_json / bundle_json at their None defaults (via
    // `..Default::default()`) so the libkrun/HVF backends take the legacy
    // `run_supervisor` dispatch. Routing template restores through
    // admission would add an `admit_for_run` call here and a
    // `populate_audit_substrate` invocation after the struct literal.
    let mut start_config = build_start_config(&req, &vm_name, &resolved, &boot, &volumes);
    // The tunnel worker spawns on the cold-boot path, not snapshot-restore.
    if start_config.network_tunnel.is_some() {
        use_snapshot = false;
    }

    // Admit the transient run as a locally-signed workload. Setting
    // tenant_id + plan_json makes the libkrun/HVF supervisor spawn the gateway
    // bridge (so it enforces `network_policy` + chain-audits the run) instead
    // of the legacy unfiltered path; on Firecracker the policy already enforces
    // via the FlakeRunConfig firewall. Force cold boot when admitted — the
    // bridge spawn is on the cold-boot path, not snapshot-restore.
    if let Some(admit_fn) = admit
        && let Some(sub) = admit_fn(std::path::Path::new(&resolved.rootfs), &vm_name)?
    {
        start_config.tenant_id = Some(sub.tenant_id);
        start_config.plan_json = Some(sub.plan_json);
        start_config.bundle_json = sub.bundle_json;
        start_config.config_files.extend(sub.config_files);
        use_snapshot = false;
    }
    crate::commands::vm::up::attach_runtime_overlay_if_cached(&mut start_config, backend.name())?;
    crate::commands::vm::up::emit_runtime_source_status(&start_config);
    drop_l3_tunnel_for_host_vsock_proxy(&mut start_config, &backend);
    let t_admitted = timing.then(std::time::Instant::now);

    // Reap stale standbys, try a warm-pool claim, then fall back to
    // snapshot-restore / cold boot. See `boot_transient_vm`.
    let boot_attempt = BootAttempt {
        backend: &backend,
        start_config: &start_config,
        resolved: &resolved,
        staging_dir: &staging_dir,
    };
    let vm_name = boot_transient_vm(vm_name, use_snapshot, &boot_attempt)?;
    let t_backend_started = timing.then(std::time::Instant::now);

    // Install Ctrl-C handler that tears the VM down.
    let interrupted = install_ctrlc_teardown(&vm_name, backend.name());

    // Run the command + always tear down.
    let run_outcome = run_in_guest(&vm_name, &req, &add_dir_labels, capture, timing);
    let t_command_done = timing.then(std::time::Instant::now);
    let (result, t_vsock_ready) = match run_outcome {
        Ok((either, vsock_ready)) => (Ok(either), vsock_ready),
        Err(e) => (Err(e), None),
    };

    teardown_transient_vm(
        &backend,
        &vm_name,
        &start_config,
        &req.add_dirs,
        &staging_dir,
    );
    let t_torn_down = timing.then(std::time::Instant::now);

    // Emit the phase breakdown when every seam was marked (i.e. timing was
    // enabled and the run reached teardown without an early return).
    if let (
        Some(start),
        Some(image_resolved),
        Some(drives_ready),
        Some(admitted),
        Some(backend_started),
        Some(vsock_ready),
        Some(command_done),
        Some(torn_down),
    ) = (
        t_start,
        t_image_resolved,
        t_drives_ready,
        t_admitted,
        t_backend_started,
        t_vsock_ready,
        t_command_done,
        t_torn_down,
    ) {
        let marks = crate::commands::vm::phase_timing::RunPhaseMarks {
            start,
            image_resolved,
            drives_ready,
            admitted,
            backend_started,
            vsock_ready,
            command_done,
            torn_down,
        };
        eprintln!("{}", marks.to_timings().render());
    }

    if interrupted.load(std::sync::atomic::Ordering::SeqCst) {
        anyhow::bail!("interrupted");
    }
    result
}

/// Kernel/rootfs/initrd + provenance resolved from `req.image`: either a
/// named template lookup (which also probes for a snapshot) or a pre-built
/// kernel/rootfs pair carried through as-is.
struct ResolvedImage {
    vmlinux: String,
    initrd: Option<String>,
    rootfs: String,
    revision: String,
    flake_ref: String,
    profile: Option<String>,
    snap_info: Option<mvm_core::template::SnapshotInfo>,
    template_id: Option<String>,
}

/// Resolve image artifacts: either a named template or a pre-built pair. For
/// templates, also probe for a pre-built snapshot so the caller can skip the
/// cold-boot cost when the request turns out to be snapshot-eligible.
fn resolve_image_artifacts(image: &ImageSource) -> Result<ResolvedImage> {
    match image {
        ImageSource::Template(name) => {
            let (spec, vmlinux, initrd, rootfs, rev) =
                mvm_runtime::vm::template::lifecycle::template_artifacts_dispatched(name)
                    .with_context(|| format!("Loading template '{name}'"))?;
            let snap_info =
                mvm_runtime::vm::template::lifecycle::template_snapshot_info_dispatched(name)
                    .ok()
                    .flatten();
            Ok(ResolvedImage {
                vmlinux,
                initrd,
                rootfs,
                revision: rev,
                flake_ref: spec.flake_ref.clone(),
                profile: Some(spec.profile.clone()),
                snap_info,
                template_id: Some(name.clone()),
            })
        }
        ImageSource::Prebuilt {
            kernel_path,
            rootfs_path,
            initrd_path,
            label,
            ..
        } => Ok(ResolvedImage {
            vmlinux: kernel_path.clone(),
            initrd: initrd_path.clone(),
            rootfs: rootfs_path.clone(),
            revision: String::new(),
            flake_ref: label.clone(),
            profile: None,
            snap_info: None,
            template_id: None,
        }),
    }
}

/// Per-`--add-dir` staging: a small RO ext4 image built for each host
/// directory mapping, plus the VM name / staging dir the images live under.
struct AddDirStaging {
    vm_name: String,
    staging_dir: String,
    volumes: Vec<mvm_runtime::image::RuntimeVolume>,
    add_dir_labels: Vec<String>,
}

/// Build read-only ext4 images for each `--add-dir`, staged in a transient
/// VM's `extras` subdirectory so cleanup is straightforward.
fn stage_add_dir_volumes(req: &ExecRequest) -> Result<AddDirStaging> {
    let vm_name = req.name.clone().unwrap_or_else(transient_vm_name);
    let staging_dir = mvm_core::config::vm_state_dir(&vm_name)
        .join("extras")
        .display()
        .to_string();
    let mut volumes: Vec<mvm_runtime::image::RuntimeVolume> = Vec::new();
    let mut add_dir_labels: Vec<String> = Vec::new();
    for (idx, dir) in req.add_dirs.iter().enumerate() {
        let label = format!("mvm-extra-{idx}");
        let image_path = format!("{staging_dir}/extra-{idx}.ext4");
        mvm_runtime::image::build_dir_image_ro(&dir.host_path, &label, &image_path).with_context(
            || {
                format!(
                    "preparing --add-dir image for '{}' -> '{}'",
                    dir.host_path, dir.guest_path
                )
            },
        )?;
        volumes.push(mvm_runtime::image::RuntimeVolume {
            host: image_path,
            guest: dir.guest_path.clone(),
            size: String::new(),
            read_only: dir.read_only,
            // `--add-dir` builds an RO ext4 image, so this is a disk.
            ..Default::default()
        });
        add_dir_labels.push(label);
    }
    Ok(AddDirStaging {
        vm_name,
        staging_dir,
        volumes,
        add_dir_labels,
    })
}

/// The run-path tier gate's outputs for one boot: whether the request is
/// still snapshot-restore eligible, the dm-verity sidecar (if any), the
/// virtiofs root candidate, the resolved rootfs strategy + runtime source
/// policy, and the effective initrd.
struct BootStrategy {
    use_snapshot: bool,
    verity_path: Option<String>,
    roothash: Option<String>,
    virtiofs_root: Option<String>,
    root_strategy: mvm_build::run_image::RootStrategy,
    runtime_source_policy: mvm_core::vm_backend::RuntimeSourcePolicy,
    effective_initrd: Option<String>,
}

/// Resolve the boot strategy for `resolved`: snapshot eligibility, the
/// dm-verity sidecar probe, the virtiofs-root tier gate, the runtime source
/// policy, and the effective initrd. All of these fall out of the resolved
/// image + `req` + the backend's capabilities.
fn resolve_boot_strategy(
    req: &ExecRequest,
    backend: &AnyBackend,
    resolved: &ResolvedImage,
) -> Result<BootStrategy> {
    // Snapshot path is taken when the request is eligible; otherwise cold boot.
    let use_snapshot = snapshot_eligible(
        &req.image,
        &req.add_dirs,
        resolved.snap_info.is_some(),
        backend.capabilities().snapshots,
    );

    // Probe for the verity sidecar alongside the rootfs: production microVMs
    // ship `rootfs.verity` + `rootfs.roothash` next to `rootfs.ext4`. Their
    // absence is the dev-VM exemption. This is host-local and side-effect-free;
    // foreground OCI launches must never boot the builder/dev VM just to probe.
    let (verity_path, roothash) = mvm_runtime::microvm::probe_verity_sidecar(&resolved.rootfs);

    // Run-path tier gate: a virtiofs-capable backend + a non-prod, non-sealed OCI
    // dev run boots from the unpacked tree over virtio-fs (no ext4 materialize);
    // prod, sealed, and block backends stay on the materialized rootfs (claim 3).
    let virtiofs_root = resolve_virtiofs_root(
        &req.image,
        backend.capabilities().virtiofs_root,
        verity_path.is_some(),
    );
    let root_strategy = if virtiofs_root.is_some() {
        mvm_build::run_image::RootStrategy::VirtiofsRoot
    } else {
        mvm_build::run_image::RootStrategy::BlockExt4
    };
    let runtime_source_policy = runtime_source_policy_for(
        &req.image,
        backend.name(),
        verity_path.is_some(),
        root_strategy,
    );
    let effective_initrd = effective_transient_initrd(
        &req.image,
        resolved.initrd.as_deref(),
        &resolved.rootfs,
        runtime_source_policy,
        root_strategy,
    )?;

    Ok(BootStrategy {
        use_snapshot,
        verity_path,
        roothash,
        virtiofs_root,
        root_strategy,
        runtime_source_policy,
        effective_initrd,
    })
}

/// Build the `VmStartConfig` for the transient boot from the resolved image +
/// boot-strategy state. Admission (tenant/plan binding) and the runtime
/// overlay attach happen in the caller, after this returns — this only
/// assembles the struct.
fn build_start_config(
    req: &ExecRequest,
    vm_name: &str,
    resolved: &ResolvedImage,
    boot: &BootStrategy,
    volumes: &[mvm_runtime::image::RuntimeVolume],
) -> VmStartConfig {
    // Pre-open console data sockets for interactive PTY runs against
    // non-sealed images. OCI/dev images can carry verity sidecars and still be
    // interactive, so the sidecar's sealed bit is the load-bearing signal here.
    let image_sealed = crate::commands::vm::image_is_sealed(std::path::Path::new(&resolved.rootfs));
    let dev_console = transient_run_dev_console(req.pty, image_sealed);

    VmStartConfig {
        name: vm_name.to_string(),
        rootfs_path: resolved.rootfs.clone(),
        virtiofs_root: boot.virtiofs_root.clone(),
        kernel_path: Some(resolved.vmlinux.clone()),
        initrd_path: boot.effective_initrd.clone(),
        verity_path: boot.verity_path.clone(),
        roothash: boot.roothash.clone(),
        dev_console,
        revision_hash: resolved.revision.clone(),
        flake_ref: resolved.flake_ref.clone(),
        profile: resolved.profile.clone(),
        cpus: req.cpus,
        memory_mib: req.memory_mib,
        mem_initial_mib: req.mem_initial_mib,
        ports: Vec::new(),
        volumes: volumes
            .iter()
            .map(|v| VmVolume {
                host: v.host.clone(),
                guest: v.guest.clone(),
                size: v.size.clone(),
                read_only: v.read_only,
                kind: v.kind,
                encrypted: v.encrypted,
            })
            .collect(),
        config_files: Vec::new(),
        secret_files: Vec::new(),
        runner_dir: None,
        network_policy: req.network_policy.clone(),
        // Derive the userspace L3 egress tunnel from the resolved policy: an
        // admitted allow-list gets a `mvm-network-tunnel-worker` (the smoltcp
        // forwarder) whose gate enforces exactly those flows; deny-all /
        // unrestricted return None (no forwarding tunnel). The identity is
        // minted here so the guest cmdline token and the host worker's
        // expected-session validate against identical values.
        network_tunnel: mvm_runtime::network_tunnel_for_launch(
            &req.network_policy,
            mvm_runtime::TunnelLaunchIdentity {
                tenant_id: "local".to_string(),
                vm_id: vm_name.to_string(),
                boot_id: uuid::Uuid::new_v4().to_string(),
                session_nonce: uuid::Uuid::new_v4().to_string(),
            },
        ),
        warm_pool_size: req.warm_pool_size,
        runtime_source_policy: boot.runtime_source_policy,
        ..Default::default()
    }
}

/// Everything [`boot_transient_vm`] needs beyond the caller-varying
/// `vm_name` / `use_snapshot`.
struct BootAttempt<'a> {
    backend: &'a AnyBackend,
    start_config: &'a VmStartConfig,
    resolved: &'a ResolvedImage,
    staging_dir: &'a str,
}

/// Boot the transient VM: try to claim a warm standby first, then a
/// snapshot restore (when eligible), then fall back to a cold boot from
/// `attempt.start_config`. Reaps expired standbys first — best-effort TTL
/// housekeeping since there is no daemon to do it between invocations.
///
/// Returns the effective VM name — a claimed standby runs under its own
/// standby id, not `vm_name`. On a cold-boot failure the `--add-dir`
/// staging is cleaned up and the error is returned, exactly as the inline
/// boot sequence this replaces used to do.
fn boot_transient_vm(
    vm_name: String,
    use_snapshot: bool,
    attempt: &BootAttempt<'_>,
) -> Result<String> {
    // Reap dead/expired standbys before claiming/booting. There is no daemon, so
    // this on-use reap is what enforces the standby TTL between invocations —
    // without it a one-off run (or runs against different images) leaves warm
    // spares resident until a manual `cache prune`. Best-effort; never blocks.
    crate::commands::pool::reap_stale_standbys_best_effort();

    // Reap state dirs a killed or crashed prior transient run left behind: a
    // SIGKILL or a closed terminal skips teardown, so `~/.mvm/vms/<name>` leaks.
    // Narrow orphan-only reap — no registry convergence or resume — so a
    // throwaway launch stays side-effect free; shields this run's own name,
    // whose dir may exist before its supervisor comes up.
    let _ = mvm_runtime::vm::reconcile::reap_orphan_state_dirs(Some(vm_name.as_str()));

    // Try a warm-pool claim before snapshot/cold-boot. A claimed standby is
    // pre-booted to agent-ready and runs under its own standby-id, so the
    // returned name diverges from `vm_name` — the caller rebinds it for the
    // Ctrl-C handler, run_in_guest, and teardown. try_warm_claim gates
    // internally (warm_pool_size > 0, admitted tenant + signed plan threaded
    // into start_config, no extra volumes, backend supports the pool); any
    // miss/error fails open to the snapshot/cold-boot paths.
    let (vm_name, warm_claimed) = match crate::commands::pool::try_warm_claim(
        attempt.backend,
        attempt.start_config,
        false,
        None,
    ) {
        Ok(Some(id)) => {
            ui::info(&format!(
                "Claimed a warm standby ({}) — skipping cold boot.",
                id.0
            ));
            (id.0, true)
        }
        Ok(None) => (vm_name, false),
        Err(e) => {
            tracing::warn!(error = %e, "warm-claim attempt errored; cold-booting");
            (vm_name, false)
        }
    };

    let booted = warm_claimed
        || if use_snapshot {
            let tmpl = attempt
                .resolved
                .template_id
                .as_deref()
                .expect("snapshot_eligible only true for ImageSource::Template");
            let snap = attempt
                .resolved
                .snap_info
                .as_ref()
                .expect("snapshot_eligible requires snap_info.is_some()");
            ui::info(&format!(
                "Restoring transient VM '{vm_name}' from template '{tmpl}' snapshot..."
            ));
            match restore_via_snapshot(&vm_name, tmpl, snap, attempt.start_config) {
                Ok(()) => true,
                Err(e) => {
                    // macOS backends without Firecracker (HVF, libkrun) return os
                    // error 95 (EOPNOTSUPP) on vsock snapshots; cold boot still
                    // works there. Fall back rather than failing the whole exec.
                    ui::warn(&format!("Snapshot restore failed: {e}; cold-booting."));
                    false
                }
            }
        } else {
            false
        };

    if !booted {
        ui::info(&format!("Booting transient VM '{vm_name}'..."));
        if let Err(e) = attempt.backend.start(attempt.start_config) {
            remove_transient_state_dir(attempt.staging_dir);
            return Err(e).context("starting transient microVM");
        }
    }
    Ok(vm_name)
}

/// Arm the Ctrl-C handler for this transient run: on interrupt, flag the
/// returned `AtomicBool` and best-effort stop the VM immediately, rather
/// than waiting for the in-flight guest command to return. The normal
/// teardown sequence still runs afterward when the run returns — this only
/// shortens the window an interrupted VM stays up.
fn install_ctrlc_teardown(
    vm_name: &str,
    backend_name: &str,
) -> std::sync::Arc<std::sync::atomic::AtomicBool> {
    let interrupted = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let handler_interrupted = interrupted.clone();
    let vm_name = vm_name.to_string();
    let backend_name = backend_name.to_string();
    let _ = crate::signal::set_ctrlc_handler(move || {
        handler_interrupted.store(true, std::sync::atomic::Ordering::SeqCst);
        let backend = AnyBackend::from_hypervisor(&backend_name);
        let _ = backend.stop_transient(&VmId(vm_name.clone()));
    });
    interrupted
}

/// Tear down the transient VM after the guest command finishes (or fails to
/// dispatch): stop the backend VM, top up the warm pool toward its target,
/// sync back any writable `--add-dir` mounts, and remove the staging dir.
///
/// The caller invokes this unconditionally after capturing the guest
/// command's `Result` in a local — there is no `?` between the backend
/// start and this call, so teardown always runs on both the success and
/// error paths.
fn teardown_transient_vm(
    backend: &AnyBackend,
    vm_name: &str,
    start_config: &VmStartConfig,
    add_dirs: &[AddDir],
    staging_dir: &str,
) {
    let _ = backend.stop_transient(&VmId(vm_name.to_string()));

    // Top the warm pool back toward target after the run (best-effort,
    // no-daemon replenish-on-use). No-ops when `warm_pool_size == 0`; the
    // image-bound boot+capture rewarm the removed Vz backend used to do
    // stays explicit via `pool warm` so teardown does not spawn background
    // work that can contend with foreground launches.
    if let Err(e) = crate::commands::pool::replenish_after_launch(backend, start_config) {
        tracing::debug!(error = %e, "pool replenish skipped (best-effort)");
    }

    // Writable --add-dir uses rsync-back. With the VM stopped the
    // ext4 image is no longer in use, so we mount it host-side and rsync
    // its contents over the host directory before nuking the staging dir.
    // Failures here are warned but do not override the guest exit code.
    for (idx, dir) in add_dirs.iter().enumerate() {
        if dir.read_only {
            continue;
        }
        let image_path = format!("{staging_dir}/extra-{idx}.ext4");
        if let Err(e) = mvm_runtime::image::rsync_image_to_host(&image_path, &dir.host_path) {
            ui::warn(&format!(
                "writable --add-dir sync-back failed for '{}' -> '{}': {e:#}",
                dir.host_path, dir.guest_path,
            ));
        }
    }

    remove_transient_state_dir(staging_dir);
}

/// Restore a transient microVM from a template snapshot instead of cold-booting.
///
/// Mirrors the snapshot path in `cmd_run`: allocate a slot, build a
/// `FlakeRunConfig` matching the snapshot's recorded layout, then call
/// `microvm::restore_from_template_snapshot`. The caller is responsible for
/// ensuring the request is `snapshot_eligible` first (no `--add-dir`,
/// template image source).
fn restore_via_snapshot(
    vm_name: &str,
    template_id: &str,
    snap_info: &mvm_core::template::SnapshotInfo,
    start_config: &VmStartConfig,
) -> Result<()> {
    let slot = mvm_runtime::microvm::allocate_slot(vm_name)?;
    let run_config = mvm_runtime::microvm::FlakeRunConfig {
        name: vm_name.to_string(),
        slot,
        vmlinux_path: start_config.kernel_path.clone().unwrap_or_default(),
        initrd_path: start_config.initrd_path.clone(),
        rootfs_path: start_config.rootfs_path.clone(),
        verity_path: start_config.verity_path.clone(),
        roothash: start_config.roothash.clone(),
        runtime_overlay_path: start_config.runtime_overlay_path.clone(),
        runtime_overlay_verity_path: start_config.runtime_overlay_verity_path.clone(),
        runtime_overlay_roothash: start_config.runtime_overlay_roothash.clone(),
        runtime_source_policy: start_config.runtime_source_policy,
        revision_hash: start_config.revision_hash.clone(),
        flake_ref: start_config.flake_ref.clone(),
        profile: start_config.profile.clone(),
        cpus: start_config.cpus,
        memory: start_config.memory_mib,
        // Inherit the balloon decision from the start_config. The
        // snapshot path is rare for balloon-enabled workloads (FC
        // snapshots don't checkpoint balloon state cleanly), but
        // we preserve the field so a future fix doesn't have to
        // re-thread it.
        mem_initial: start_config.mem_initial_mib,
        // Snapshot-eligible callers have no extra volumes; if that ever
        // changes the snapshot layout will mismatch and Firecracker will
        // refuse to load — `snapshot_eligible` enforces this.
        volumes: Vec::new(),
        config_files: Vec::new(),
        secret_files: Vec::new(),
        ports: Vec::new(),
        // Inherit the resolved egress policy so a restored transient VM
        // enforces the same posture as a cold-boot one.
        network_policy: start_config.network_policy.clone(),
        network_tunnel: start_config.network_tunnel.clone(),
    };
    let rev = if mvm_core::manifest::is_slot_hash_dirname(template_id) {
        mvm_runtime::vm::template::lifecycle::current_revision_id_for_slot(template_id)?
    } else {
        mvm_runtime::vm::template::lifecycle::current_revision_id(template_id)?
    };
    let snap_dir = if mvm_core::manifest::is_slot_hash_dirname(template_id) {
        mvm_core::manifest::slot_snapshot_dir(template_id, &rev)
    } else {
        mvm_core::template::template_snapshot_dir(template_id, &rev)
    };
    mvm_runtime::microvm::restore_from_template_snapshot(
        template_id,
        &run_config,
        &snap_dir,
        snap_info,
    )
}

/// Send the wrapped command to the guest agent and either stream
/// stdout/stderr (default) or capture them (when `capture=true`).
///
/// `capture=true` is used by [`run_captured`] / `mvmctl mcp` to assemble
/// MCP `tools/call` responses; the streaming path keeps the existing
/// `mvmctl exec` ergonomics.
fn run_in_guest(
    vm_name: &str,
    req: &ExecRequest,
    labels: &[String],
    capture: bool,
    timing: bool,
) -> Result<(Either<i32, ExecOutput>, Option<std::time::Instant>)> {
    use std::io::Write as _;
    if !wait_for_agent(vm_name, 30) {
        anyhow::bail!("guest agent did not become reachable within 30s");
    }
    // Agent reachable over vsock: the command is about to be dispatched.
    let vsock_ready = timing.then(std::time::Instant::now);
    let wrapper = build_guest_wrapper(req, labels);

    if req.pty {
        let pty = pty_console_request(req, labels, wrapper);
        let exit_code =
            crate::commands::vm::console::run_pty_argv_for_exit(vm_name, pty.argv, pty.env)?;
        return Ok((Either::Left(exit_code), vsock_ready));
    }

    let transport = vsock_transport::for_vm(vm_name)?;
    let mut stream = transport.connect(mvm_agentd::vsock::GUEST_AGENT_PORT)?;
    // Inbound vsock RPC audit. exec.rs is a top-level module that can't
    // reach the private `commands::shared` re-export, so inline the audit
    // emit here. The detail format matches
    // `commands::shared::vsock::emit_vsock_rpc_audit`:
    // `scope=rpc,direction=in,kind=vsock,verb=<kebab-name>`.
    let verb = "exec";
    mvm_core::audit_emit!(
        NetworkPolicyAllow,
        vm: vm_name,
        "scope=rpc,direction=in,kind=vsock,verb={verb}",
        verb = verb,
    );

    let mut out = Vec::<u8>::new();
    let mut err = Vec::<u8>::new();
    let stdin_str = if req.stdin.is_empty() {
        None
    } else {
        Some(String::from_utf8_lossy(&req.stdin).into_owned())
    };
    let terminal = mvm_agentd::vsock::send_exec_streaming(
        &mut stream,
        &wrapper,
        stdin_str,
        req.timeout_secs,
        |event| match event {
            mvm_agentd::vsock::ExecEvent::Stdout { chunk } => {
                if capture {
                    out.extend_from_slice(chunk);
                } else {
                    let mut so = std::io::stdout();
                    let _ = so.write_all(chunk);
                    let _ = so.flush();
                }
            }
            mvm_agentd::vsock::ExecEvent::Stderr { chunk } => {
                if capture {
                    err.extend_from_slice(chunk);
                } else {
                    let mut se = std::io::stderr();
                    let _ = se.write_all(chunk);
                    let _ = se.flush();
                }
            }
            _ => {}
        },
    )?;
    let exit_code = match terminal {
        mvm_agentd::vsock::ExecEvent::Exit { code } => code,
        mvm_agentd::vsock::ExecEvent::TimedOut => {
            let msg = timeout_exit_message(req.timeout_secs);
            if capture {
                err.extend_from_slice(format!("{msg}\n").as_bytes());
            } else {
                eprintln!("{msg}");
            }
            EXEC_TIMEOUT_EXIT_CODE
        }
        other => anyhow::bail!("unexpected terminal exec event: {other:?}"),
    };

    let either = if capture {
        Either::Right(ExecOutput {
            exit_code,
            stdout: String::from_utf8_lossy(&out).into_owned(),
            stderr: String::from_utf8_lossy(&err).into_owned(),
        })
    } else {
        Either::Left(exit_code)
    };
    Ok((either, vsock_ready))
}

struct PtyConsoleRequest {
    argv: Vec<String>,
    env: Vec<(String, String)>,
}

fn pty_console_request(req: &ExecRequest, labels: &[String], wrapper: String) -> PtyConsoleRequest {
    match &req.target {
        ExecTarget::Inline { argv } if direct_pty_inline_argv(argv, req, labels) => {
            PtyConsoleRequest {
                argv: argv.clone(),
                env: req.env.clone(),
            }
        }
        _ => PtyConsoleRequest {
            argv: vec!["/bin/sh".to_string(), "-lc".to_string(), wrapper],
            env: Vec::new(),
        },
    }
}

fn direct_pty_inline_argv(req_argv: &[String], req: &ExecRequest, labels: &[String]) -> bool {
    labels.is_empty()
        && req.add_dirs.is_empty()
        && req_argv.first().is_some_and(|argv0| argv0.starts_with('/'))
}

// ---------------------------------------------------------------------------
// Warm-VM session primitives
// ---------------------------------------------------------------------------
//
// `mvmctl exec` and `mvmctl mcp tools/call run` (cold) both go through
// `run_inner` above — boot, run, tear down. The MCP `session=ID` path
// needs to keep the VM alive across many calls. The three primitives
// below split that lifecycle apart so the dispatcher can:
//
//   1. boot once   → SessionVm handle
//   2. dispatch N  → ExecOutput per call
//   3. tear down   → on idle / max / close / shutdown
//
// They deliberately NOT support `--add-dir` (volumes, rsync-back,
// staging dirs) — session VMs are meant for inference workloads
// against a clean closure, not interactive file mounts.

/// Handle to a long-running session microVM.
///
/// Owns nothing beyond the VM name; backend selection is repeated at
/// teardown so the handle stays trivially `Send + Sync`.
pub struct SessionVm {
    pub vm_name: String,
}

/// Boot a session microVM from a registered template. Snapshot-resume
/// is taken when the template has one and the backend supports it
/// (matches the eligibility rule in [`snapshot_eligible`] for the
/// no-`--add-dir` case), unless an admission hook supplies per-boot
/// state that must ride the fresh boot path.
///
/// `vm_name_prefix` becomes the human-readable part of the VM name —
/// callers typically pass `"mcp-session-<short-id>"` so `mvmctl ls`
/// shows which MCP session a VM belongs to.
/// The audit substrate an admitted plan contributes to a session VM so the
/// backend spawns the substitution endpoint (the guest never holds a raw
/// secret). The caller (`invoke --from-workload-ir`) admits the workload's
/// lowered secrets and hands these JSON-serialized fields back; `boot_session_vm`
/// threads them into the `VmStartConfig`. Strings (not typed `mvm-core::plan` values)
/// so this module carries no admission-type dep. **Do not log `plan_json`** — the
/// signed envelope carries secret bindings.
pub struct SessionAuditSubstrate {
    pub tenant_id: String,
    pub plan_json: String,
    pub bundle_json: Option<String>,
    pub config_files: Vec<mvm_core::vm_backend::VmFile>,
}

/// Admission callback: given the resolved rootfs + the generated vm_name (both
/// known only inside `boot_session_vm`), produce the audit substrate, or `None`
/// when the workload declares no secrets. Lives in the caller so admission stays
/// in the command layer; `boot_session_vm` just applies the result.
pub type SessionAdmit<'a> =
    dyn Fn(&std::path::Path, &str) -> Result<Option<SessionAuditSubstrate>> + 'a;

pub fn boot_session_vm(
    env: &str,
    vm_name_prefix: &str,
    cpus: u32,
    memory_mib: u32,
    network_policy: &mvm_core::network_policy::NetworkPolicy,
    admit: Option<&SessionAdmit<'_>>,
) -> Result<SessionVm> {
    let (spec, vmlinux, initrd, rootfs, rev) =
        mvm_runtime::vm::template::lifecycle::template_artifacts_dispatched(env)
            .with_context(|| format!("Loading template '{env}'"))?;
    let snap_info = mvm_runtime::vm::template::lifecycle::template_snapshot_info_dispatched(env)
        .ok()
        .flatten();

    let backend = AnyBackend::auto_select();
    // Append the same nanosecond suffix transient_vm_name uses so
    // concurrent boots in the same session don't collide.
    let vm_name = format!("{}-{}", vm_name_prefix, transient_vm_name());

    let (verity_path, roothash) = mvm_runtime::microvm::probe_verity_sidecar(&rootfs);

    // Session VMs default to the legacy no-admission path. When `admit`
    // returns a substrate, the plan-bearing fields below and any config-drive
    // files it supplies are populated before `backend.start()`.
    let mut start_config = VmStartConfig {
        name: vm_name.clone(),
        rootfs_path: rootfs.clone(),
        kernel_path: Some(vmlinux),
        initrd_path: initrd,
        verity_path,
        roothash,
        revision_hash: rev,
        flake_ref: spec.flake_ref,
        profile: Some(spec.profile),
        cpus,
        memory_mib,
        // Session VMs are short-lived MCP-driven boots; balloon
        // elasticity isn't useful here, so leave commit at boot.
        mem_initial_mib: None,
        ports: vec![],
        volumes: vec![],
        config_files: vec![],
        secret_files: vec![],
        runner_dir: None,
        network_policy: network_policy.clone(),
        // Derive the userspace L3 egress tunnel from the resolved policy, exactly
        // as the transient argv path does: an admitted allow-list gets the smoltcp
        // forwarder whose gate enforces those flows; deny-all / unrestricted return
        // None (no forwarding tunnel), so plain session/MCP boots are unaffected.
        // The identity is minted here so the guest cmdline token and the host
        // worker's expected-session validate against identical values.
        network_tunnel: mvm_runtime::network_tunnel_for_launch(
            network_policy,
            mvm_runtime::TunnelLaunchIdentity {
                tenant_id: "local".to_string(),
                vm_id: vm_name.clone(),
                boot_id: uuid::Uuid::new_v4().to_string(),
                session_nonce: uuid::Uuid::new_v4().to_string(),
            },
        ),
        ..Default::default()
    };

    // Session VMs are always block-rooted template boots; resolve the overlay
    // policy the same way the transient runner does so the runtime overlay is
    // the single source of the guest agent + helpers here too (a missing
    // required overlay is built/acquired by attach_runtime_overlay_if_cached,
    // never silently replaced by a baked rootfs copy).
    start_config.runtime_source_policy = mvm_core::vm_backend::select_runtime_source_policy(
        mvm_core::vm_backend::RuntimeSourcePolicySelection {
            backend_name: Some(backend.name()),
            sealed: start_config.verity_path.is_some(),
            root_strategy: Some(mvm_core::vm_backend::RuntimeSourceRootStrategy::BlockExt4),
            launch_kind: mvm_core::vm_backend::RuntimeSourceLaunchKind::WorkloadImage,
        },
    );

    // Admit the workload's lowered secrets (the closure runs
    // synthesize→sign→verify with the now-known rootfs + vm_name) and thread the
    // signed plan into the config so `backend.start` spawns the substitution
    // endpoint. Force a cold boot when secrets are present: snapshot-restore
    // bypasses the endpoint-spawn path. `None` admit ⇒ unchanged legacy path.
    let mut admitted_workload = false;
    if let Some(admit_fn) = admit
        && let Some(sub) = admit_fn(std::path::Path::new(&rootfs), &vm_name)?
    {
        start_config.tenant_id = Some(sub.tenant_id);
        start_config.plan_json = Some(sub.plan_json);
        start_config.bundle_json = sub.bundle_json;
        start_config.config_files.extend(sub.config_files);
        admitted_workload = true;
        if mvm_runtime::catalog::descriptor(backend.kind()).is_workload {
            mvm_hostd::plan_admission::stash_plan_for_bridge(&start_config)
                .context("persisting admitted session plan before backend start")?;
        }
    }

    crate::commands::vm::up::attach_runtime_overlay_if_cached(&mut start_config, backend.name())?;

    // The tunnel worker spawns on the cold-boot path, not snapshot-restore, so an
    // egress-admitted session must cold-boot even when a snapshot exists.
    let use_snapshot = !admitted_workload
        && start_config.network_tunnel.is_none()
        && snap_info.is_some()
        && backend.capabilities().snapshots;
    drop_l3_tunnel_for_host_vsock_proxy(&mut start_config, &backend);
    let booted = if use_snapshot {
        let snap = snap_info.as_ref().expect("use_snapshot implies snap_info");
        match restore_via_snapshot(&vm_name, env, snap, &start_config) {
            Ok(()) => true,
            Err(e) => {
                ui::warn(&format!(
                    "Session VM snapshot restore failed: {e}; cold-booting."
                ));
                false
            }
        }
    } else {
        false
    };

    if !booted {
        ui::info(&format!(
            "Booting session VM '{vm_name}' for env '{env}'..."
        ));
        backend
            .start(&start_config)
            .with_context(|| format!("starting session microVM '{vm_name}'"))?;
    }

    Ok(SessionVm { vm_name })
}

/// Dispatch a single command into an already-booted session VM,
/// capturing stdout/stderr. Equivalent to the dispatch step of
/// [`run_captured`] without any boot/teardown.
pub fn dispatch_in_session(
    vm: &SessionVm,
    code: String,
    timeout_secs: Option<u64>,
) -> Result<ExecOutput> {
    if !wait_for_agent(&vm.vm_name, 30) {
        anyhow::bail!("guest agent did not become reachable within 30s");
    }
    // Reuse build_guest_wrapper by constructing a minimal ExecRequest
    // with no add_dirs (sessions don't take --add-dir). The wrapper
    // emits `set -e\n<env exports>\n<argv>\n`.
    let req = ExecRequest {
        name: None,
        warm_pool_size: 0,
        image: ImageSource::Template(String::new()),
        cpus: 0,
        memory_mib: 0,
        mem_initial_mib: None,
        add_dirs: vec![],
        env: vec![],
        target: ExecTarget::Inline {
            argv: vec!["bash".to_string(), "-c".to_string(), code],
        },
        timeout_secs,
        pty: false,
        // Wrapper-string construction only — the session VM is already
        // running, so this never reaches a backend boot.
        network_policy: mvm_core::network_policy::NetworkPolicy::deny_all(),
        stdin: Vec::new(),
        healthcheck: None,
        hypervisor: None,
    };
    let wrapper = build_guest_wrapper(&req, &[]);
    let transport = vsock_transport::for_vm(&vm.vm_name)?;
    let mut stream = transport.connect(mvm_agentd::vsock::GUEST_AGENT_PORT)?;
    // Inbound vsock RPC audit. Mirrors run_in_guest's emit; was lost when
    // this function migrated from send_request to send_exec_streaming.
    let verb = "exec";
    mvm_core::audit_emit!(
        NetworkPolicyAllow,
        vm: &vm.vm_name,
        "scope=rpc,direction=in,kind=vsock,verb={verb}",
        verb = verb,
    );

    let mut out = Vec::<u8>::new();
    let mut err = Vec::<u8>::new();
    let terminal = mvm_agentd::vsock::send_exec_streaming(
        &mut stream,
        &wrapper,
        None,
        timeout_secs,
        |event| match event {
            mvm_agentd::vsock::ExecEvent::Stdout { chunk } => out.extend_from_slice(chunk),
            mvm_agentd::vsock::ExecEvent::Stderr { chunk } => err.extend_from_slice(chunk),
            _ => {}
        },
    )?;
    let exit_code = match terminal {
        mvm_agentd::vsock::ExecEvent::Exit { code } => code,
        mvm_agentd::vsock::ExecEvent::TimedOut => {
            err.extend_from_slice(format!("{}\n", timeout_exit_message(timeout_secs)).as_bytes());
            EXEC_TIMEOUT_EXIT_CODE
        }
        other => anyhow::bail!("unexpected terminal exec event: {other:?}"),
    };
    Ok(ExecOutput {
        exit_code,
        stdout: String::from_utf8_lossy(&out).into_owned(),
        stderr: String::from_utf8_lossy(&err).into_owned(),
    })
}

/// Tear down a session VM. Best-effort — failures (already-stopped,
/// backend mismatch) are logged via `tracing::warn!` rather than
/// propagated, since the reaper calls this from a background thread
/// where there's nobody to receive an error.
pub fn tear_down_session_vm(vm: SessionVm) {
    let backend = AnyBackend::auto_select();
    if let Err(e) = backend.stop(&VmId(vm.vm_name.clone())) {
        tracing::warn!(vm = %vm.vm_name, err = %e, "session VM teardown failed");
    }
}

pub fn wait_for_agent(vm_name: &str, timeout_secs: u64) -> bool {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
    while std::time::Instant::now() < deadline {
        // Re-pick the transport on each iteration: a Firecracker VM
        // that's still booting may not show up in
        // resolve_running_vm_dir until the daemon registers it.
        // "agent reachable" means it speaks the protocol, not just that
        // the socket is open. We require a
        // successful hello (with at least the `Ping` capability) before
        // reporting ready, since under hard cutover a pre-hello agent
        // would only answer `ProtocolMismatch` to the next request and
        // that is *not* "reachable" from the caller's perspective.
        if let Ok(transport) = vsock_transport::for_vm(vm_name)
            && let Ok(mut stream) = transport.connect(mvm_agentd::vsock::GUEST_AGENT_PORT)
            && {
                // Bound each probe: a transport whose socket is bound but whose
                // guest agent hasn't replied yet (e.g. still booting, or an
                // hvf VMM whose relay isn't answering) must not block the
                // whole hello read forever — otherwise this loop never gets back
                // to the deadline check and hangs instead of timing out. A short
                // per-attempt read timeout lets `negotiate_protocol` fail fast so
                // the outer loop retries and ultimately honours `timeout_secs`.
                // The stream is a throwaway probe (dropped below), so the timeout
                // never touches a real agent-RPC data stream.
                let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(3)));
                mvm_agentd::vsock::negotiate_protocol(
                    &mut stream,
                    vec![mvm_agentd::vsock::GuestCapability::Ping],
                )
                .is_ok()
            }
        {
            return true;
        }
        // Tight poll: the guest agent comes up within ~1s, so a coarse
        // cadence would round readiness up to the next tick and add hundreds
        // of ms to perceived launch latency. The connect+hello attempts are
        // cheap and fail fast while the guest is still booting.
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_healthcheck_wraps_shell_command() {
        let hc = build_healthcheck(Some("curl -fsS localhost/health"), 10, 5, 3, 0)
            .expect("Some when a command is given");
        assert_eq!(
            hc.command,
            vec!["/bin/sh", "-lc", "curl -fsS localhost/health"]
        );
        assert_eq!(hc.interval_secs, 10);
        assert_eq!(build_healthcheck(None, 30, 5, 3, 0), None);
    }

    #[test]
    fn select_exec_backend_requested_flag_selects_backend() {
        let deny_all = mvm_core::network_policy::NetworkPolicy::deny_all();
        let backend = select_exec_backend(false, &deny_all, Some("libkrun"))
            .expect("libkrun resolves without probing availability (image not requested)");
        assert_eq!(backend.name(), "libkrun");

        let backend = select_exec_backend(false, &deny_all, Some("hvf"))
            .expect("hvf resolves without probing availability (image not requested)");
        assert_eq!(backend.name(), "hvf");
    }

    #[test]
    fn select_exec_backend_none_with_no_env_falls_to_auto_detect() {
        let saved_hv = std::env::var_os("MVM_HYPERVISOR");
        let saved_be = std::env::var_os("MVM_BACKEND");
        // SAFETY: test-local env mutation, restored before returning.
        unsafe {
            std::env::remove_var("MVM_HYPERVISOR");
            std::env::remove_var("MVM_BACKEND");
        }
        let deny_all = mvm_core::network_policy::NetworkPolicy::deny_all();
        let backend =
            select_exec_backend(false, &deny_all, None).expect("auto-detect always resolves");
        assert_eq!(backend.name(), AnyBackend::auto_select().name());
        // SAFETY: restore prior values.
        unsafe {
            match saved_hv {
                Some(v) => std::env::set_var("MVM_HYPERVISOR", v),
                None => std::env::remove_var("MVM_HYPERVISOR"),
            }
            match saved_be {
                Some(v) => std::env::set_var("MVM_BACKEND", v),
                None => std::env::remove_var("MVM_BACKEND"),
            }
        }
    }

    /// The CLI `--hypervisor` flag (the `requested` param) wins over a
    /// conflicting `MVM_HYPERVISOR` env override — the admit/build/boot call
    /// sites must all resolve to the same backend as what was requested.
    #[test]
    fn select_exec_backend_requested_flag_beats_conflicting_env() {
        let saved_hv = std::env::var_os("MVM_HYPERVISOR");
        let saved_be = std::env::var_os("MVM_BACKEND");
        // SAFETY: test-local env mutation, restored before returning.
        unsafe {
            std::env::remove_var("MVM_BACKEND");
            std::env::set_var("MVM_HYPERVISOR", "qemu");
        }
        let deny_all = mvm_core::network_policy::NetworkPolicy::deny_all();
        let backend = select_exec_backend(false, &deny_all, Some("libkrun"))
            .expect("libkrun resolves without probing availability (image not requested)");
        assert_eq!(
            backend.name(),
            "libkrun",
            "the requested flag must win over MVM_HYPERVISOR=qemu"
        );
        // SAFETY: restore prior values.
        unsafe {
            match saved_hv {
                Some(v) => std::env::set_var("MVM_HYPERVISOR", v),
                None => std::env::remove_var("MVM_HYPERVISOR"),
            }
            match saved_be {
                Some(v) => std::env::set_var("MVM_BACKEND", v),
                None => std::env::remove_var("MVM_BACKEND"),
            }
        }
    }

    fn fixture_network_tunnel() -> mvm_core::protocol::network_tunnel::TunnelRuntimeConfig {
        mvm_core::protocol::network_tunnel::TunnelRuntimeConfig {
            guest_port: mvm_core::protocol::network_tunnel::NETWORK_TUNNEL_GUEST_PORT,
            session: mvm_core::protocol::network_tunnel::TunnelSessionConfig {
                tenant_id: "local".to_string(),
                vm_id: "test-vm".to_string(),
                boot_id: "test-boot".to_string(),
                session_nonce: "test-nonce".to_string(),
                requested_features: Default::default(),
                maximum_frame_size: 65536,
            },
        }
    }

    #[test]
    fn drop_l3_tunnel_for_host_vsock_proxy_drops_it_on_libkrun() {
        let mut config = VmStartConfig {
            network_tunnel: Some(fixture_network_tunnel()),
            ..Default::default()
        };
        let backend = AnyBackend::from_hypervisor("libkrun");
        drop_l3_tunnel_for_host_vsock_proxy(&mut config, &backend);
        assert!(
            config.network_tunnel.is_none(),
            "libkrun carries all egress over its host-vsock proxy; the L3 tunnel is a redundant second data plane"
        );
    }

    #[test]
    fn drop_l3_tunnel_for_host_vsock_proxy_keeps_it_on_firecracker() {
        let mut config = VmStartConfig {
            network_tunnel: Some(fixture_network_tunnel()),
            ..Default::default()
        };
        let backend = AnyBackend::from_hypervisor("firecracker");
        drop_l3_tunnel_for_host_vsock_proxy(&mut config, &backend);
        assert!(
            config.network_tunnel.is_some(),
            "firecracker has no host-vsock proxy; the L3 tunnel is its only vsock-only egress path"
        );
    }

    #[test]
    fn validate_backend_for_egress_refuses_unavailable_hvf_before_boot_work() {
        let _guard = mvm_runtime::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let policy = mvm_core::network_policy::NetworkPolicy::allow_list(vec![
            mvm_core::network_policy::HostPort::new("example.com", 443),
        ]);
        // SAFETY: test-only env mutation.
        unsafe {
            std::env::set_var("MVM_HVF_SUPERVISOR_PATH", "/no/such/mvm-hvf-supervisor");
        }
        let err = validate_backend_for_egress(
            "hvf",
            true,
            &policy,
            "OCI --image runs with outbound egress enabled",
        )
        .expect_err("unavailable hvf must fail closed before OCI work");
        // SAFETY: test-only env mutation.
        unsafe {
            std::env::remove_var("MVM_HVF_SUPERVISOR_PATH");
        }
        let msg = err.to_string();
        assert!(msg.contains("NIC-less host-vsock-proxy backend"));
        assert!(msg.contains("backend hvf lacks ["));
        assert!(msg.contains("host_vsock_proxy"));
        assert!(msg.contains("no_routable_guest_nic"));
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn select_backend_name_for_egress_picks_hvf_when_proxy_support_is_available() {
        let _guard = mvm_runtime::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().expect("tempdir");
        let supervisor = dir.path().join("mvm-hvf-supervisor");
        std::fs::write(&supervisor, b"stub").expect("stub supervisor");
        let policy = mvm_core::network_policy::NetworkPolicy::allow_list(vec![
            mvm_core::network_policy::HostPort::new("example.com", 443),
        ]);

        // SAFETY: test-only env mutation.
        unsafe {
            std::env::set_var("MVM_HVF_SUPERVISOR_PATH", &supervisor);
        }
        let selected = select_backend_name_for_egress(
            None,
            true,
            &policy,
            "OCI --image runs with outbound egress enabled",
        )
        .expect("hvf should satisfy the proxy backend requirement");
        // SAFETY: test-only env mutation.
        unsafe {
            std::env::remove_var("MVM_HVF_SUPERVISOR_PATH");
        }

        assert_eq!(selected, "hvf");
    }

    #[test]
    fn add_dir_parse_happy_path() {
        let d = AddDir::parse("/tmp/src:/work").unwrap();
        assert_eq!(d.host_path, "/tmp/src");
        assert_eq!(d.guest_path, "/work");
    }

    #[test]
    fn add_dir_parse_rejects_missing_colon() {
        let err = AddDir::parse("/tmp/src").unwrap_err();
        assert!(err.to_string().contains("missing ':'"));
    }

    #[test]
    fn add_dir_parse_rejects_empty_host() {
        let err = AddDir::parse(":/work").unwrap_err();
        assert!(err.to_string().contains("host path"));
    }

    #[test]
    fn add_dir_parse_rejects_empty_guest() {
        let err = AddDir::parse("/tmp/src:").unwrap_err();
        assert!(err.to_string().contains("guest path"));
    }

    #[test]
    fn add_dir_parse_rejects_relative_guest() {
        let err = AddDir::parse("/tmp/src:relative/path").unwrap_err();
        assert!(err.to_string().contains("absolute"));
    }

    #[test]
    fn add_dir_expands_tilde_in_host_path() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.set("HOME", "/tmp/fakehome");
        let d = AddDir::parse("~/configs:/etc/configs").unwrap();
        assert_eq!(d.host_path, "/tmp/fakehome/configs");
        assert_eq!(d.guest_path, "/etc/configs");
    }

    #[test]
    fn add_dir_parse_default_is_read_only() {
        let d = AddDir::parse("/tmp/src:/work").unwrap();
        assert!(d.read_only, "default mode should be read-only");
    }

    #[test]
    fn add_dir_parse_explicit_ro() {
        let d = AddDir::parse("/tmp/src:/work:ro").unwrap();
        assert_eq!(d.host_path, "/tmp/src");
        assert_eq!(d.guest_path, "/work");
        assert!(d.read_only);
    }

    #[test]
    fn add_dir_parse_explicit_rw() {
        let d = AddDir::parse("/tmp/src:/work:rw").unwrap();
        assert_eq!(d.host_path, "/tmp/src");
        assert_eq!(d.guest_path, "/work");
        assert!(!d.read_only);
    }

    #[test]
    fn add_dir_parse_rejects_bogus_mode() {
        let err = AddDir::parse("/tmp/src:/work:bogus").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("unknown mode"), "got: {msg}");
        assert!(msg.contains("'bogus'"), "got: {msg}");
    }

    #[test]
    fn add_dir_extra_colons_belong_to_guest_path() {
        // A guest path that legitimately contains a colon: the trailing
        // component must be path-shaped (contains a slash) so we can
        // distinguish it from a mode token.
        let d = AddDir::parse("/host:/weird:path/file").unwrap();
        assert_eq!(d.host_path, "/host");
        assert_eq!(d.guest_path, "/weird:path/file");
        assert!(d.read_only);
    }

    #[test]
    fn shell_quote_basic() {
        assert_eq!(shell_quote("hello"), "'hello'");
        assert_eq!(shell_quote("hello world"), "'hello world'");
    }

    #[test]
    fn shell_quote_escapes_single_quotes() {
        assert_eq!(shell_quote("it's"), r"'it'\''s'");
    }

    #[test]
    fn target_command_inline_quotes_each_arg() {
        let req = ExecRequest {
            name: None,
            warm_pool_size: 0,
            image: ImageSource::Template("t".into()),
            cpus: 1,
            memory_mib: 256,
            mem_initial_mib: None,
            add_dirs: Vec::new(),
            env: Vec::new(),
            target: ExecTarget::Inline {
                argv: vec!["uname".into(), "-a".into()],
            },
            timeout_secs: Some(30),
            pty: false,
            network_policy: mvm_core::network_policy::NetworkPolicy::deny_all(),
            stdin: Vec::new(),
            healthcheck: None,
            hypervisor: None,
        };
        assert_eq!(req.target_command(), "exec 'uname' '-a'");
    }

    #[test]
    fn build_guest_wrapper_no_extras() {
        let req = ExecRequest {
            name: None,
            warm_pool_size: 0,
            image: ImageSource::Template("t".into()),
            cpus: 1,
            memory_mib: 256,
            mem_initial_mib: None,
            add_dirs: Vec::new(),
            env: Vec::new(),
            target: ExecTarget::Inline {
                argv: vec!["true".into()],
            },
            timeout_secs: Some(30),
            pty: false,
            network_policy: mvm_core::network_policy::NetworkPolicy::deny_all(),
            stdin: Vec::new(),
            healthcheck: None,
            hypervisor: None,
        };
        let script = build_guest_wrapper(&req, &[]);
        assert!(script.starts_with("set -e\n"));
        assert!(script.contains("exec 'true'"));
        assert!(!script.contains("mount"));
        assert!(!script.contains("export"));
    }

    #[test]
    fn build_guest_wrapper_mounts_and_env() {
        let req = ExecRequest {
            name: None,
            warm_pool_size: 0,
            image: ImageSource::Template("t".into()),
            cpus: 1,
            memory_mib: 256,
            mem_initial_mib: None,
            add_dirs: vec![AddDir {
                host_path: "/h".into(),
                guest_path: "/g".into(),
                read_only: true,
            }],
            env: vec![("FOO".into(), "bar baz".into())],
            target: ExecTarget::Inline {
                argv: vec!["echo".into(), "$FOO".into()],
            },
            timeout_secs: Some(30),
            pty: false,
            network_policy: mvm_core::network_policy::NetworkPolicy::deny_all(),
            stdin: Vec::new(),
            healthcheck: None,
            hypervisor: None,
        };
        let script = build_guest_wrapper(&req, &["mvm-extra-0".to_string()]);
        assert!(script.contains("mkdir -p '/g'"));
        assert!(script.contains("mount LABEL='mvm-extra-0' '/g' -o ro"));
        assert!(script.contains("export FOO='bar baz'"));
        assert!(script.contains("exec 'echo' '$FOO'"));
    }

    #[test]
    fn build_guest_wrapper_writable_mount_drops_ro_flag() {
        let req = ExecRequest {
            name: None,
            warm_pool_size: 0,
            image: ImageSource::Template("t".into()),
            cpus: 1,
            memory_mib: 256,
            mem_initial_mib: None,
            add_dirs: vec![AddDir {
                host_path: "/h".into(),
                guest_path: "/g".into(),
                read_only: false,
            }],
            env: Vec::new(),
            target: ExecTarget::Inline {
                argv: vec!["true".into()],
            },
            timeout_secs: Some(30),
            pty: false,
            network_policy: mvm_core::network_policy::NetworkPolicy::deny_all(),
            stdin: Vec::new(),
            healthcheck: None,
            hypervisor: None,
        };
        let script = build_guest_wrapper(&req, &["mvm-extra-0".to_string()]);
        // RW mount is unqualified — no `-o ro`.
        assert!(
            script.contains("mount LABEL='mvm-extra-0' '/g'\n"),
            "expected unqualified mount line, got: {script}"
        );
        assert!(!script.contains("-o ro"), "RW mount must not include -o ro");
    }

    #[test]
    fn pty_console_request_passes_inline_argv_directly() {
        let req = ExecRequest {
            name: None,
            warm_pool_size: 0,
            image: ImageSource::Template("t".into()),
            cpus: 1,
            memory_mib: 256,
            mem_initial_mib: None,
            add_dirs: Vec::new(),
            env: vec![("TERM".into(), "xterm-256color".into())],
            target: ExecTarget::Inline {
                argv: vec!["/bin/sh".into()],
            },
            timeout_secs: None,
            pty: true,
            network_policy: mvm_core::network_policy::NetworkPolicy::deny_all(),
            stdin: Vec::new(),
            healthcheck: None,
            hypervisor: None,
        };

        let pty = pty_console_request(&req, &[], "set -e\nexec '/bin/sh'\n".to_string());

        assert_eq!(pty.argv, vec!["/bin/sh"]);
        assert_eq!(pty.env, vec![("TERM".into(), "xterm-256color".into())]);
    }

    #[test]
    fn pty_console_request_uses_wrapper_when_mount_setup_is_required() {
        let req = ExecRequest {
            name: None,
            warm_pool_size: 0,
            image: ImageSource::Template("t".into()),
            cpus: 1,
            memory_mib: 256,
            mem_initial_mib: None,
            add_dirs: vec![AddDir {
                host_path: "/h".into(),
                guest_path: "/g".into(),
                read_only: true,
            }],
            env: vec![("FOO".into(), "bar".into())],
            target: ExecTarget::Inline {
                argv: vec!["/bin/sh".into()],
            },
            timeout_secs: None,
            pty: true,
            network_policy: mvm_core::network_policy::NetworkPolicy::deny_all(),
            stdin: Vec::new(),
            healthcheck: None,
            hypervisor: None,
        };
        let wrapper = build_guest_wrapper(&req, &["mvm-extra-0".to_string()]);

        let pty = pty_console_request(&req, &["mvm-extra-0".to_string()], wrapper.clone());

        assert_eq!(pty.argv, vec!["/bin/sh", "-lc", wrapper.as_str()]);
        assert!(pty.env.is_empty());
    }

    #[test]
    fn pty_console_request_keeps_relative_commands_on_shell_path_lookup() {
        let req = ExecRequest {
            name: None,
            warm_pool_size: 0,
            image: ImageSource::Template("t".into()),
            cpus: 1,
            memory_mib: 256,
            mem_initial_mib: None,
            add_dirs: Vec::new(),
            env: Vec::new(),
            target: ExecTarget::Inline {
                argv: vec!["htop".into()],
            },
            timeout_secs: None,
            pty: true,
            network_policy: mvm_core::network_policy::NetworkPolicy::deny_all(),
            stdin: Vec::new(),
            healthcheck: None,
            hypervisor: None,
        };
        let wrapper = build_guest_wrapper(&req, &[]);

        let pty = pty_console_request(&req, &[], wrapper.clone());

        assert_eq!(pty.argv, vec!["/bin/sh", "-lc", wrapper.as_str()]);
        assert!(pty.env.is_empty());
    }

    #[test]
    fn transient_vm_name_format() {
        let n = transient_vm_name();
        mvm_core::naming::validate_vm_name(&n)
            .unwrap_or_else(|e| panic!("transient name {n:?} invalid: {e}"));
        assert_eq!(n.split('-').count(), 3);
        assert!(!n.contains(' '));
        assert!(!n.contains('/'));
    }

    // -- launch.json parser --

    fn parse_str(json: &str) -> Result<LaunchEntrypoint> {
        let raw: RawLaunchPlan = serde_json::from_str(json).expect("valid json");
        parse_launch_plan(raw, "test")
    }

    #[test]
    fn launch_plan_minimal_app() {
        let plan = r#"{
            "apps": [
                { "entrypoint": { "command": ["python", "-m", "hello"] } }
            ]
        }"#;
        let ep = parse_str(plan).unwrap();
        assert_eq!(ep.command, vec!["python", "-m", "hello"]);
        assert!(ep.working_dir.is_none());
        assert!(ep.env.is_empty());
    }

    #[test]
    fn launch_plan_with_working_dir_and_env() {
        let plan = r#"{
            "apps": [
                {
                    "name": "hello",
                    "entrypoint": {
                        "command": ["python", "main.py"],
                        "working_dir": "/app",
                        "env": { "PORT": "8080" }
                    },
                    "env": { "LOG_LEVEL": "info" }
                }
            ]
        }"#;
        let ep = parse_str(plan).unwrap();
        assert_eq!(ep.command, vec!["python", "main.py"]);
        assert_eq!(ep.working_dir.as_deref(), Some("/app"));
        assert_eq!(ep.env.get("PORT").map(String::as_str), Some("8080"));
        // app.env merged in (under entrypoint.env precedence, but no conflict here).
        assert_eq!(ep.env.get("LOG_LEVEL").map(String::as_str), Some("info"));
    }

    #[test]
    fn launch_plan_entrypoint_env_overrides_app_env() {
        let plan = r#"{
            "apps": [
                {
                    "entrypoint": {
                        "command": ["true"],
                        "env": { "X": "from-entrypoint" }
                    },
                    "env": { "X": "from-app", "Y": "y" }
                }
            ]
        }"#;
        let ep = parse_str(plan).unwrap();
        assert_eq!(ep.env.get("X").map(String::as_str), Some("from-entrypoint"));
        assert_eq!(ep.env.get("Y").map(String::as_str), Some("y"));
    }

    #[test]
    fn launch_plan_ignores_unknown_top_level_fields() {
        // mvmforge ships `version`, `workload.id`, etc. — we don't care about them.
        let plan = r#"{
            "version": "v0",
            "workload": { "id": "hello" },
            "apps": [ { "entrypoint": { "command": ["true"] } } ],
            "future_field": 42
        }"#;
        assert!(parse_str(plan).is_ok());
    }

    #[test]
    fn launch_plan_rejects_no_apps() {
        let err = parse_str(r#"{ "apps": [] }"#).unwrap_err();
        assert!(err.to_string().contains("missing both"));
    }

    #[test]
    fn launch_plan_accepts_mvmforge_artifact_shape() {
        // The JSON `mvmforge compile` actually writes to launch.json: top-level
        // `entrypoint`, plus toolchain metadata fields we ignore.
        let plan = r#"{
            "artifact_format_version": "1.0",
            "flake_attribute": "mvmforge.workload",
            "flake_path": ".",
            "ir_hash": "deadbeef",
            "ir_schema_version": "0.1",
            "toolchain_version": "0.1.0",
            "workload_id": "hello",
            "image": { "kind": "nix_packages", "packages": ["python312"] },
            "entrypoint": {
                "command": ["python", "-m", "hello"],
                "working_dir": "/app",
                "env": { "PORT": "8080" }
            },
            "env": {},
            "mounts": [],
            "network": null,
            "source": { "kind": "local_path", "subdir": "src", "file_count": 0, "tree_hash": "0" }
        }"#;
        let ep = parse_str(plan).unwrap();
        assert_eq!(ep.command, vec!["python", "-m", "hello"]);
        assert_eq!(ep.working_dir.as_deref(), Some("/app"));
        assert_eq!(ep.env.get("PORT").map(String::as_str), Some("8080"));
    }

    #[test]
    fn launch_plan_artifact_top_env_merged_under_entrypoint_env() {
        let plan = r#"{
            "entrypoint": {
                "command": ["true"],
                "env": { "X": "from-entrypoint" }
            },
            "env": { "X": "from-top", "Y": "y" }
        }"#;
        let ep = parse_str(plan).unwrap();
        assert_eq!(ep.env.get("X").map(String::as_str), Some("from-entrypoint"));
        assert_eq!(ep.env.get("Y").map(String::as_str), Some("y"));
    }

    #[test]
    fn launch_plan_artifact_rejects_empty_command() {
        let plan = r#"{ "entrypoint": { "command": [] } }"#;
        let err = parse_str(plan).unwrap_err();
        assert!(err.to_string().contains("non-empty"));
    }

    #[test]
    fn launch_plan_rejects_both_shapes_present() {
        // Defensive: a JSON that simultaneously declares `apps[]` and a
        // top-level `entrypoint` is ambiguous — refuse rather than silently
        // pick one.
        let plan = r#"{
            "apps": [ { "entrypoint": { "command": ["x"] } } ],
            "entrypoint": { "command": ["y"] }
        }"#;
        let err = parse_str(plan).unwrap_err();
        assert!(err.to_string().contains("both"));
    }

    #[test]
    fn launch_plan_rejects_completely_empty_document() {
        let err = parse_str(r#"{}"#).unwrap_err();
        assert!(err.to_string().contains("missing both"));
    }

    #[test]
    fn launch_plan_rejects_multi_app() {
        let plan = r#"{
            "apps": [
                { "name": "a", "entrypoint": { "command": ["x"] } },
                { "name": "b", "entrypoint": { "command": ["y"] } }
            ]
        }"#;
        let err = parse_str(plan).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("single-app"), "got: {msg}");
        assert!(msg.contains("a, b"), "names should appear: {msg}");
    }

    #[test]
    fn launch_plan_rejects_empty_command() {
        let plan = r#"{
            "apps": [ { "entrypoint": { "command": [] } } ]
        }"#;
        let err = parse_str(plan).unwrap_err();
        assert!(err.to_string().contains("non-empty"));
    }

    #[test]
    fn load_launch_plan_reads_file() {
        let dir = std::env::temp_dir().join(format!("mvm-launch-plan-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("launch.json");
        std::fs::write(
            &path,
            r#"{ "apps": [ { "entrypoint": { "command": ["echo", "hi"] } } ] }"#,
        )
        .unwrap();
        let ep = load_launch_plan(&path).unwrap();
        assert_eq!(ep.command, vec!["echo", "hi"]);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn load_launch_plan_reports_missing_file() {
        let err = load_launch_plan(Path::new("/nonexistent/launch.json")).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("reading launch plan"));
    }

    #[test]
    fn target_command_launch_plan_quotes_argv() {
        let req = ExecRequest {
            name: None,
            warm_pool_size: 0,
            image: ImageSource::Template("t".into()),
            cpus: 1,
            memory_mib: 256,
            mem_initial_mib: None,
            add_dirs: Vec::new(),
            env: Vec::new(),
            target: ExecTarget::LaunchPlan {
                entrypoint: LaunchEntrypoint {
                    command: vec!["python".into(), "-m".into(), "x".into()],
                    working_dir: None,
                    env: BTreeMap::new(),
                },
            },
            timeout_secs: Some(30),
            pty: false,
            network_policy: mvm_core::network_policy::NetworkPolicy::deny_all(),
            stdin: Vec::new(),
            healthcheck: None,
            hypervisor: None,
        };
        assert_eq!(req.target_command(), "exec 'python' '-m' 'x'");
    }

    #[test]
    fn build_guest_wrapper_launch_plan_emits_cd_and_env() {
        let mut env = BTreeMap::new();
        env.insert("PORT".to_string(), "8080".to_string());
        env.insert("LOG".to_string(), "info".to_string());
        let req = ExecRequest {
            name: None,
            warm_pool_size: 0,
            image: ImageSource::Template("t".into()),
            cpus: 1,
            memory_mib: 256,
            mem_initial_mib: None,
            add_dirs: Vec::new(),
            env: vec![("CLI_OVER".to_string(), "wins".to_string())],
            target: ExecTarget::LaunchPlan {
                entrypoint: LaunchEntrypoint {
                    command: vec!["python".into(), "main.py".into()],
                    working_dir: Some("/app".into()),
                    env,
                },
            },
            timeout_secs: Some(30),
            pty: false,
            network_policy: mvm_core::network_policy::NetworkPolicy::deny_all(),
            stdin: Vec::new(),
            healthcheck: None,
            hypervisor: None,
        };
        let script = build_guest_wrapper(&req, &[]);
        // Env from entrypoint exported.
        assert!(script.contains("export PORT='8080'"));
        assert!(script.contains("export LOG='info'"));
        // CLI env exported AFTER entrypoint env, so it wins on conflict.
        let cli_pos = script
            .find("export CLI_OVER='wins'")
            .expect("CLI env exported");
        let port_pos = script.find("export PORT='8080'").expect("port exported");
        assert!(
            cli_pos > port_pos,
            "CLI env must appear after launch-plan env"
        );
        // cd into working_dir before exec.
        assert!(script.contains("cd '/app'"));
        let cd_pos = script.find("cd '/app'").unwrap();
        let exec_pos = script.find("exec 'python' 'main.py'").unwrap();
        assert!(cd_pos < exec_pos, "cd must precede the final exec");
    }

    #[test]
    fn build_guest_wrapper_inline_target_unchanged() {
        // Sanity: inline target wrapper still does not emit cd or extra env blocks.
        let req = ExecRequest {
            name: None,
            warm_pool_size: 0,
            image: ImageSource::Template("t".into()),
            cpus: 1,
            memory_mib: 256,
            mem_initial_mib: None,
            add_dirs: Vec::new(),
            env: Vec::new(),
            target: ExecTarget::Inline {
                argv: vec!["true".into()],
            },
            timeout_secs: Some(30),
            pty: false,
            network_policy: mvm_core::network_policy::NetworkPolicy::deny_all(),
            stdin: Vec::new(),
            healthcheck: None,
            hypervisor: None,
        };
        let script = build_guest_wrapper(&req, &[]);
        assert!(!script.contains("cd "));
        assert!(!script.contains("export "));
        assert!(script.contains("exec 'true'"));
    }

    // -- snapshot_eligible --

    fn template(name: &str) -> ImageSource {
        ImageSource::Template(name.into())
    }

    fn prebuilt() -> ImageSource {
        ImageSource::Prebuilt {
            kernel_path: "/k".into(),
            rootfs_path: "/r".into(),
            initrd_path: None,
            label: "lbl".into(),
            virtiofs_oci_root: None,
        }
    }

    #[test]
    fn virtiofs_gate_only_dev_capable_nonsealed_reaches_virtiofs() {
        let with = |prod| ImageSource::Prebuilt {
            kernel_path: "/k".into(),
            rootfs_path: "/r".into(),
            initrd_path: None,
            label: "l".into(),
            virtiofs_oci_root: Some(VirtiofsOciRoot {
                tree_dir: "/tree".into(),
                prod,
            }),
        };
        // The one cell that reaches virtiofs: OCI candidate, capable backend,
        // non-prod, non-sealed.
        assert_eq!(
            resolve_virtiofs_root(&with(false), true, false).as_deref(),
            Some("/tree")
        );
        // Every disqualifier keeps it on the block rootfs (claim 3):
        assert_eq!(
            resolve_virtiofs_root(&with(true), true, false),
            None,
            "prod"
        );
        assert_eq!(
            resolve_virtiofs_root(&with(false), true, true),
            None,
            "sealed"
        );
        assert_eq!(
            resolve_virtiofs_root(&with(false), false, false),
            None,
            "non-virtiofs backend (e.g. Firecracker)"
        );
        // A non-OCI image (flake/template/default) never reaches virtiofs.
        assert_eq!(resolve_virtiofs_root(&prebuilt(), true, false), None);
    }

    fn add_dir() -> AddDir {
        AddDir {
            host_path: "/h".into(),
            guest_path: "/g".into(),
            read_only: true,
        }
    }

    #[test]
    fn snapshot_eligible_true_for_template_no_extras_with_snapshot() {
        assert!(snapshot_eligible(&template("t"), &[], true, true));
    }

    #[test]
    fn snapshot_eligible_false_when_backend_lacks_support() {
        assert!(!snapshot_eligible(&template("t"), &[], true, false));
    }

    #[test]
    fn snapshot_eligible_false_when_no_snapshot_present() {
        assert!(!snapshot_eligible(&template("t"), &[], false, true));
    }

    #[test]
    fn snapshot_eligible_false_with_add_dirs() {
        // Adding extra drives changes the recorded layout; snapshot would fail.
        assert!(!snapshot_eligible(&template("t"), &[add_dir()], true, true));
    }

    #[test]
    fn snapshot_eligible_false_for_prebuilt_image() {
        // The bundled default image isn't a registered template — no snapshot exists.
        assert!(!snapshot_eligible(&prebuilt(), &[], true, true));
    }

    #[test]
    fn transient_oci_required_overlay_prefers_sibling_initrd() {
        let dir = tempfile::tempdir().unwrap();
        let rootfs = dir.path().join("rootfs.ext4");
        let initrd = dir.path().join("rootfs.initrd");
        std::fs::write(&rootfs, b"rootfs").unwrap();
        std::fs::write(&initrd, b"initrd").unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.set("MVM_RUNTIME_OVERLAY_ACQUIRE_MODE", "download");
        let image = ImageSource::Prebuilt {
            kernel_path: "/k".into(),
            rootfs_path: rootfs.display().to_string(),
            initrd_path: None,
            label: "oci".into(),
            virtiofs_oci_root: Some(VirtiofsOciRoot {
                tree_dir: "/tree".into(),
                prod: false,
            }),
        };

        let resolved = effective_transient_initrd(
            &image,
            None,
            &rootfs.display().to_string(),
            mvm_core::vm_backend::RuntimeSourcePolicy::RequiredOverlay,
            mvm_build::run_image::RootStrategy::BlockExt4,
        )
        .unwrap();

        assert_eq!(
            resolved.as_deref(),
            Some(initrd.to_str().expect("utf-8 initrd path"))
        );
    }

    #[test]
    fn transient_oci_required_overlay_falls_back_to_cached_verity_initrd() {
        let dir = tempfile::tempdir().unwrap();
        let rootfs = dir.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"rootfs").unwrap();
        let image = ImageSource::Prebuilt {
            kernel_path: "/k".into(),
            rootfs_path: rootfs.display().to_string(),
            initrd_path: None,
            label: "oci".into(),
            virtiofs_oci_root: Some(VirtiofsOciRoot {
                tree_dir: "/tree".into(),
                prod: false,
            }),
        };

        let cache = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.set("MVM_HOME", cache.path());
        env.set("MVM_RUNTIME_OVERLAY_ACQUIRE_MODE", "download");
        let initrd_dir = cache
            .path()
            .join("cache")
            .join("verity-initrd")
            .join(env!("CARGO_PKG_VERSION"))
            .join(if cfg!(target_arch = "aarch64") {
                "aarch64"
            } else {
                "x86_64"
            });
        std::fs::create_dir_all(&initrd_dir).unwrap();
        std::fs::write(initrd_dir.join("rootfs.initrd"), b"initrd").unwrap();

        let resolved = effective_transient_initrd(
            &image,
            None,
            &rootfs.display().to_string(),
            mvm_core::vm_backend::RuntimeSourcePolicy::RequiredOverlay,
            mvm_build::run_image::RootStrategy::BlockExt4,
        )
        .unwrap();

        assert_eq!(
            resolved.as_deref(),
            Some(
                initrd_dir
                    .join("rootfs.initrd")
                    .to_str()
                    .expect("utf-8 cached initrd path")
            )
        );
    }

    #[test]
    fn transient_non_oci_prebuilt_does_not_infer_initrd() {
        let dir = tempfile::tempdir().unwrap();
        let rootfs = dir.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"rootfs").unwrap();

        let resolved = effective_transient_initrd(
            &prebuilt(),
            None,
            &rootfs.display().to_string(),
            mvm_core::vm_backend::RuntimeSourcePolicy::RequiredOverlay,
            mvm_build::run_image::RootStrategy::BlockExt4,
        )
        .unwrap();

        assert!(resolved.is_none());
    }

    // --- transient_run_dev_console ---

    #[test]
    fn interactive_transient_run_sets_dev_console_when_not_sealed() {
        // PTY-mode run against a non-sealed image must pre-open console sockets
        // so the hvf backend can host-dial the guest's data port.
        assert!(transient_run_dev_console(true, false));
    }

    #[test]
    fn non_interactive_transient_run_leaves_dev_console_unset() {
        // A non-PTY run never needs the interactive console data sockets.
        assert!(!transient_run_dev_console(false, false));
    }

    #[test]
    fn interactive_sealed_run_leaves_dev_console_unset() {
        // A sealed image has no interactive agent; pre-opening sockets is
        // wasteful. enforce_accessible_gate refuses the attach separately.
        assert!(!transient_run_dev_console(true, true));
    }

    #[test]
    fn non_interactive_sealed_run_leaves_dev_console_unset() {
        assert!(!transient_run_dev_console(false, true));
    }

    #[test]
    fn interactive_verity_backed_oci_run_still_arms_dev_console() {
        let dir = tempfile::tempdir().unwrap();
        let rootfs = dir.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"x").unwrap();
        std::fs::write(dir.path().join("rootfs.verity"), b"verity").unwrap();
        std::fs::write(dir.path().join("rootfs.roothash"), b"roothash").unwrap();
        mvm_build::builder_vm::GuestSidecar::for_oci_run("oci:test", false, true)
            .write_to_dir(dir.path())
            .unwrap();

        let image_sealed = crate::commands::vm::image_is_sealed(&rootfs);
        assert!(
            transient_run_dev_console(true, image_sealed),
            "verity-backed accessible OCI images must keep the interactive console armed"
        );
    }

    #[test]
    fn remove_transient_state_dir_removes_the_host_dir() {
        // Every transient run (with or without --add-dir) creates its state dir
        // when the backend writes hvf.pid / console.log there, so teardown must
        // remove it host-side — not via run_in_vm, which targets the guest.
        let tmp = tempfile::tempdir().expect("tempdir");
        let dir = tmp.path().join("vms").join("throwaway-vm");
        std::fs::create_dir_all(&dir).expect("create state dir");
        std::fs::write(dir.join("hvf.pid"), b"1234").expect("write pid file");
        assert!(dir.exists());

        remove_transient_state_dir(&dir.to_string_lossy());

        assert!(!dir.exists(), "the host state dir must be removed");
    }

    #[test]
    fn remove_transient_state_dir_is_a_noop_on_a_missing_dir() {
        // Best-effort: an already-gone dir (or a boot that never created one) is
        // a clean no-op, never a panic.
        remove_transient_state_dir("/nonexistent/mvm/vms/never-created");
    }

    #[test]
    fn normalize_backend_override_trims_lowercases_and_drops_blank() {
        assert_eq!(
            normalize_backend_override("  LibKrun \n"),
            Some("libkrun".to_string())
        );
        assert_eq!(
            normalize_backend_override("firecracker"),
            Some("firecracker".to_string())
        );
        assert_eq!(normalize_backend_override("   "), None);
        assert_eq!(normalize_backend_override(""), None);
    }
}
