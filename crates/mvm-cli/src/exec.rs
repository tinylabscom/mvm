//! `mvmctl exec` — boot a transient microVM, run one command, tear down.
//!
//! Composes existing primitives: template artifact resolution → backend
//! start → vsock guest agent → backend stop. The "what to run" is modeled
//! as a tagged enum so future variants (mvmforge `launch.json`, baked-in
//! template entrypoint) can be added without churning the inline-command
//! surface.
//!
//! Dev-mode only: the guest agent's Exec handler is gated at compile time
//! by the `dev-shell` Cargo feature. Production guest binaries are built
//! without `dev-shell`, so the handler is not present and `exec` returns
//! "exec not available" regardless of any runtime configuration.

use anyhow::{Context, Result};
use mvm_core::vm_backend::{VmId, VmStartConfig, VmVolume};
use mvm_runtime::vm::backend::AnyBackend;
use mvm_runtime::vm::microvm;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::Path;

use crate::ui;

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
/// back to the host directory after the command exits — see ADR-002.
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
    },
}

/// All inputs to the orchestrator.
#[derive(Debug, Clone)]
pub struct ExecRequest {
    pub image: ImageSource,
    pub cpus: u32,
    pub memory_mib: u32,
    pub add_dirs: Vec<AddDir>,
    pub env: Vec<(String, String)>,
    pub target: ExecTarget,
    /// Timeout for the in-guest command in seconds.
    pub timeout_secs: u64,
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
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or_default();
    let pid = std::process::id();
    format!("exec-{pid:x}-{nanos:08x}")
}

/// Decide whether snapshot restore is safe for this request.
///
/// v2 (issue #7) only enables it for the trivial case: a registered template
/// (so the image has a snapshot at all), no `--add-dir` extras (so the drive
/// layout matches the snapshot's recorded layout), and a backend that
/// advertises snapshot support. Adding `--add-dir` would change the drive
/// count and break the snapshot — that case is tracked separately in #7's
/// "harder" branch and stays cold-boot for now.
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

/// Run the request: boot, run, tear down.
///
/// Returns the guest command's exit code. On orchestrator failure (boot,
/// agent unreachable, vsock error), returns an error; the VM is torn down
/// best-effort before returning.
pub fn run(req: ExecRequest) -> Result<i32> {
    let backend = AnyBackend::auto_select();

    // Resolve image artifacts: either a named template or a pre-built pair.
    // For templates, also probe for a pre-built snapshot so we can skip the
    // cold-boot cost when the request is snapshot-eligible.
    let (vmlinux, initrd, rootfs, revision, flake_ref, profile, snap_info, template_id) =
        match &req.image {
            ImageSource::Template(name) => {
                let (spec, vmlinux, initrd, rootfs, rev) =
                    mvm_runtime::vm::template::lifecycle::template_artifacts(name)
                        .with_context(|| format!("Loading template '{name}'"))?;
                let snap = mvm_runtime::vm::template::lifecycle::template_snapshot_info(name)
                    .ok()
                    .flatten();
                (
                    vmlinux,
                    initrd,
                    rootfs,
                    rev,
                    spec.flake_ref.clone(),
                    Some(spec.profile.clone()),
                    snap,
                    Some(name.clone()),
                )
            }
            ImageSource::Prebuilt {
                kernel_path,
                rootfs_path,
                initrd_path,
                label,
            } => (
                kernel_path.clone(),
                initrd_path.clone(),
                rootfs_path.clone(),
                String::new(),
                label.clone(),
                None,
                None,
                None,
            ),
        };

    // Build read-only ext4 images for each --add-dir, staged in a transient
    // VMS subdirectory so cleanup is straightforward.
    let vm_name = transient_vm_name();
    let staging_dir = format!("{}/{}/extras", mvm_runtime::config::VMS_DIR, vm_name);
    let mut volumes: Vec<mvm_runtime::vm::image::RuntimeVolume> = Vec::new();
    let mut add_dir_labels: Vec<String> = Vec::new();
    for (idx, dir) in req.add_dirs.iter().enumerate() {
        let label = format!("mvm-extra-{idx}");
        let image_path = format!("{staging_dir}/extra-{idx}.ext4");
        mvm_runtime::vm::image::build_dir_image_ro(&dir.host_path, &label, &image_path)
            .with_context(|| {
                format!(
                    "preparing --add-dir image for '{}' -> '{}'",
                    dir.host_path, dir.guest_path
                )
            })?;
        volumes.push(mvm_runtime::vm::image::RuntimeVolume {
            host: image_path,
            guest: dir.guest_path.clone(),
            size: String::new(),
            read_only: dir.read_only,
        });
        add_dir_labels.push(label);
    }

    // Snapshot path is taken when the request is eligible; otherwise cold boot.
    let use_snapshot = snapshot_eligible(
        &req.image,
        &req.add_dirs,
        snap_info.is_some(),
        backend.capabilities().snapshots,
    );

    let start_config = VmStartConfig {
        name: vm_name.clone(),
        rootfs_path: rootfs.clone(),
        kernel_path: Some(vmlinux.clone()),
        initrd_path: initrd.clone(),
        revision_hash: revision.clone(),
        flake_ref: flake_ref.clone(),
        profile: profile.clone(),
        cpus: req.cpus,
        memory_mib: req.memory_mib,
        ports: Vec::new(),
        volumes: volumes
            .iter()
            .map(|v| VmVolume {
                host: v.host.clone(),
                guest: v.guest.clone(),
                size: v.size.clone(),
                read_only: v.read_only,
            })
            .collect(),
        config_files: Vec::new(),
        secret_files: Vec::new(),
        runner_dir: None,
    };

    let booted = if use_snapshot {
        let tmpl = template_id
            .as_deref()
            .expect("snapshot_eligible only true for ImageSource::Template");
        let snap = snap_info
            .as_ref()
            .expect("snapshot_eligible requires snap_info.is_some()");
        ui::info(&format!(
            "Restoring transient VM '{vm_name}' from template '{tmpl}' snapshot..."
        ));
        match restore_via_snapshot(&vm_name, tmpl, snap, &start_config) {
            Ok(()) => true,
            Err(e) => {
                // macOS / Lima QEMU returns os error 95 (EOPNOTSUPP) on vsock
                // snapshots; cold boot still works there. Fall back rather
                // than failing the whole exec.
                ui::warn(&format!("Snapshot restore failed: {e}; cold-booting."));
                false
            }
        }
    } else {
        false
    };

    if !booted {
        ui::info(&format!("Booting transient VM '{vm_name}'..."));
        if let Err(e) = backend.start(&start_config) {
            let _ = mvm_runtime::shell::run_in_vm(&format!("rm -rf {staging_dir}"));
            return Err(e).context("starting transient microVM");
        }
    }

    // Install Ctrl-C handler that tears the VM down.
    let interrupted = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    {
        let interrupted = interrupted.clone();
        let vm_name = vm_name.clone();
        let _ = ctrlc::set_handler(move || {
            interrupted.store(true, std::sync::atomic::Ordering::SeqCst);
            let backend = AnyBackend::auto_select();
            let _ = backend.stop(&VmId(vm_name.clone()));
        });
    }

    // Run the command + always tear down.
    let result = run_in_guest(&vm_name, &req, &add_dir_labels);

    let _ = backend.stop(&VmId(vm_name.clone()));

    // ADR-002: writable --add-dir uses rsync-back. With the VM stopped the
    // ext4 image is no longer in use, so we mount it host-side and rsync
    // its contents over the host directory before nuking the staging dir.
    // Failures here are warned but do not override the guest exit code.
    for (idx, dir) in req.add_dirs.iter().enumerate() {
        if dir.read_only {
            continue;
        }
        let image_path = format!("{staging_dir}/extra-{idx}.ext4");
        if let Err(e) = mvm_runtime::vm::image::rsync_image_to_host(&image_path, &dir.host_path) {
            ui::warn(&format!(
                "writable --add-dir sync-back failed for '{}' -> '{}': {e:#}",
                dir.host_path, dir.guest_path,
            ));
        }
    }

    let _ = mvm_runtime::shell::run_in_vm(&format!("rm -rf {staging_dir}"));

    if interrupted.load(std::sync::atomic::Ordering::SeqCst) {
        anyhow::bail!("interrupted");
    }
    result
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
    let slot = mvm_runtime::vm::microvm::allocate_slot(vm_name)?;
    let run_config = mvm_runtime::vm::microvm::FlakeRunConfig {
        name: vm_name.to_string(),
        slot,
        vmlinux_path: start_config.kernel_path.clone().unwrap_or_default(),
        initrd_path: start_config.initrd_path.clone(),
        rootfs_path: start_config.rootfs_path.clone(),
        revision_hash: start_config.revision_hash.clone(),
        flake_ref: start_config.flake_ref.clone(),
        profile: start_config.profile.clone(),
        cpus: start_config.cpus,
        memory: start_config.memory_mib,
        // Snapshot-eligible callers have no extra volumes; if that ever
        // changes the snapshot layout will mismatch and Firecracker will
        // refuse to load — `snapshot_eligible` enforces this.
        volumes: Vec::new(),
        config_files: Vec::new(),
        secret_files: Vec::new(),
        ports: Vec::new(),
        network_policy: mvm_core::network_policy::NetworkPolicy::default(),
    };
    let rev = mvm_runtime::vm::template::lifecycle::current_revision_id(template_id)?;
    let snap_dir = mvm_core::template::template_snapshot_dir(template_id, &rev);
    mvm_runtime::vm::microvm::restore_from_template_snapshot(
        template_id,
        &run_config,
        &snap_dir,
        snap_info,
    )
}

/// Send the wrapped command to the guest agent and stream stdout/stderr.
fn run_in_guest(vm_name: &str, req: &ExecRequest, labels: &[String]) -> Result<i32> {
    if !wait_for_agent(vm_name, 30) {
        anyhow::bail!("guest agent did not become reachable within 30s");
    }
    let wrapper = build_guest_wrapper(req, labels);
    let resp = send_request(vm_name, &wrapper, req.timeout_secs)?;
    match resp {
        mvm_guest::vsock::GuestResponse::ExecResult {
            exit_code,
            stdout,
            stderr,
        } => {
            if !stdout.is_empty() {
                print!("{stdout}");
            }
            if !stderr.is_empty() {
                eprint!("{stderr}");
            }
            Ok(exit_code)
        }
        mvm_guest::vsock::GuestResponse::Error { message } => {
            anyhow::bail!("guest exec error: {message}")
        }
        other => anyhow::bail!("unexpected guest response: {other:?}"),
    }
}

fn wait_for_agent(vm_name: &str, timeout_secs: u64) -> bool {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
    while std::time::Instant::now() < deadline {
        if mvm_apple_container::vsock_connect(vm_name, mvm_guest::vsock::GUEST_AGENT_PORT).is_ok() {
            return true;
        }
        if let Ok(instance_dir) = microvm::resolve_running_vm_dir(vm_name) {
            let uds = mvm_guest::vsock::vsock_uds_path(&instance_dir);
            if mvm_guest::vsock::ping_at(&uds).unwrap_or(false) {
                return true;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    false
}

fn send_request(
    vm_name: &str,
    command: &str,
    timeout_secs: u64,
) -> Result<mvm_guest::vsock::GuestResponse> {
    if let Ok(mut stream) =
        mvm_apple_container::vsock_connect(vm_name, mvm_guest::vsock::GUEST_AGENT_PORT)
    {
        return mvm_guest::vsock::send_request(
            &mut stream,
            &mvm_guest::vsock::GuestRequest::Exec {
                command: command.to_string(),
                stdin: None,
                timeout_secs: Some(timeout_secs),
            },
        );
    }
    let instance_dir = microvm::resolve_running_vm_dir(vm_name)?;
    mvm_guest::vsock::exec_at(
        &mvm_guest::vsock::vsock_uds_path(&instance_dir),
        command,
        None,
        timeout_secs,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

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
        // SAFETY: test process is single-threaded for env access.
        unsafe {
            std::env::set_var("HOME", "/tmp/fakehome");
        }
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
            image: ImageSource::Template("t".into()),
            cpus: 1,
            memory_mib: 256,
            add_dirs: Vec::new(),
            env: Vec::new(),
            target: ExecTarget::Inline {
                argv: vec!["uname".into(), "-a".into()],
            },
            timeout_secs: 30,
        };
        assert_eq!(req.target_command(), "exec 'uname' '-a'");
    }

    #[test]
    fn build_guest_wrapper_no_extras() {
        let req = ExecRequest {
            image: ImageSource::Template("t".into()),
            cpus: 1,
            memory_mib: 256,
            add_dirs: Vec::new(),
            env: Vec::new(),
            target: ExecTarget::Inline {
                argv: vec!["true".into()],
            },
            timeout_secs: 30,
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
            image: ImageSource::Template("t".into()),
            cpus: 1,
            memory_mib: 256,
            add_dirs: vec![AddDir {
                host_path: "/h".into(),
                guest_path: "/g".into(),
                read_only: true,
            }],
            env: vec![("FOO".into(), "bar baz".into())],
            target: ExecTarget::Inline {
                argv: vec!["echo".into(), "$FOO".into()],
            },
            timeout_secs: 30,
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
            image: ImageSource::Template("t".into()),
            cpus: 1,
            memory_mib: 256,
            add_dirs: vec![AddDir {
                host_path: "/h".into(),
                guest_path: "/g".into(),
                read_only: false,
            }],
            env: Vec::new(),
            target: ExecTarget::Inline {
                argv: vec!["true".into()],
            },
            timeout_secs: 30,
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
    fn transient_vm_name_format() {
        let n = transient_vm_name();
        assert!(n.starts_with("exec-"));
        assert!(n.len() > "exec-".len());
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
            image: ImageSource::Template("t".into()),
            cpus: 1,
            memory_mib: 256,
            add_dirs: Vec::new(),
            env: Vec::new(),
            target: ExecTarget::LaunchPlan {
                entrypoint: LaunchEntrypoint {
                    command: vec!["python".into(), "-m".into(), "x".into()],
                    working_dir: None,
                    env: BTreeMap::new(),
                },
            },
            timeout_secs: 30,
        };
        assert_eq!(req.target_command(), "exec 'python' '-m' 'x'");
    }

    #[test]
    fn build_guest_wrapper_launch_plan_emits_cd_and_env() {
        let mut env = BTreeMap::new();
        env.insert("PORT".to_string(), "8080".to_string());
        env.insert("LOG".to_string(), "info".to_string());
        let req = ExecRequest {
            image: ImageSource::Template("t".into()),
            cpus: 1,
            memory_mib: 256,
            add_dirs: Vec::new(),
            env: vec![("CLI_OVER".to_string(), "wins".to_string())],
            target: ExecTarget::LaunchPlan {
                entrypoint: LaunchEntrypoint {
                    command: vec!["python".into(), "main.py".into()],
                    working_dir: Some("/app".into()),
                    env,
                },
            },
            timeout_secs: 30,
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
            image: ImageSource::Template("t".into()),
            cpus: 1,
            memory_mib: 256,
            add_dirs: Vec::new(),
            env: Vec::new(),
            target: ExecTarget::Inline {
                argv: vec!["true".into()],
            },
            timeout_secs: 30,
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
        }
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
}
