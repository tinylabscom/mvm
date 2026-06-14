//! Vz dev environment + bundled image fetching.
//!
//! The dev VM is a long-lived Vz builder guest (`/dev/vdb` nix-store
//! overlay + `/work` share wired internally) that runs `nix build`.
//! Both the auto-detect macOS tier and an explicit `--builder vz`
//! route here.

use anyhow::{Context, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};

#[cfg(feature = "builder-vm")]
use mvm::vsock_transport::{VsockTransport, VzTransport};

#[cfg(feature = "builder-vm")]
use super::super::vm::console::console_interactive;
use super::artifact_verify::{
    bump_verify_outcome, download_file, fetch_expected_hashes, url_exists, verify_artifact_hash,
};
use crate::ui;

// ============================================================================
// Dev environment (Vz supervisor)
// ============================================================================

pub(super) const DEV_VM_NAME: &str = "mvm-dev";

/// Stable session id for the long-lived dev builder VM. Fixed (not the
/// random per-build id the warm pool uses) so a separate `dev down`
/// process can locate the supervisor PID file under
/// `~/.cache/mvm/builder-vm/vms/mvm-persistent-builder-vz-dev/` and reap it.
#[cfg(feature = "builder-vm")]
const DEV_VM_SESSION_ID: &str = "dev";
const BUILDER_VM_SOURCE_FINGERPRINT_FILE: &str = ".mvm-source.sha256";
const BUILDER_VM_ARTIFACT_DIGEST_FILE: &str = ".mvm-artifacts.sha256";
const BUILDER_VM_PROVENANCE_FILE: &str = ".mvm-provenance.json";
/// Absolute path the builder-VM rootfs must carry for the steady-state
/// VM to boot (`init=/sbin/mvm-host-vm-init` on the kernel cmdline).
/// `verify_stage0_rootfs_has_init` looks this inode up directly via a
/// read-only ext4 walk after Stage 0 builds the image.
#[cfg(feature = "builder-vm")]
const HOST_VM_INIT_ROOTFS_PATH: &str = "/sbin/mvm-host-vm-init";

/// Host directory the dev VM binds at `/work` (the guest-side
/// workspace mount). This is the user's CWD at `dev up` time — the
/// same value the old daemon captured to choose the virtio-fs share —
/// so `dev_build` paths resolve identically on both sides of the VM
/// boundary.
#[cfg(feature = "builder-vm")]
fn dev_workspace_root() -> std::path::PathBuf {
    std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."))
}

/// Cmdline for the dev rootfs override. Reuses the builder image's
/// canonical cmdline (same flake / mkGuest shape) when the builder
/// cache is populated, falling back to the Vz builder default. Both
/// carry `root=/dev/vda`, `console=hvc0`, and `init=/init`; the guest
/// init then mounts `/dev/vdb` as the persistent nix store.
#[cfg(feature = "builder-vm")]
fn dev_image_cmdline() -> String {
    use mvm_build::libkrun_builder::BuilderVmImage;
    match mvm_build::libkrun_builder::ensure_builder_vm_image() {
        Ok(BuilderVmImage::Rootfs { cmdline, .. }) if !cmdline.trim().is_empty() => cmdline,
        _ => mvm_build::vz_builder::DEFAULT_VZ_BUILDER_CMDLINE.to_string(),
    }
}

/// Connect to the dev VM's guest agent over its Vz per-port vsock
/// socket. The dev VM is a persistent Vz builder; its socket lives in
/// the builder cache (not the data-dir path `VzTransport::for_vm`
/// resolves), so the transport is built directly from the session's
/// vsock dir.
#[cfg(feature = "builder-vm")]
fn dev_vm_guest_agent_connect() -> Result<std::os::unix::net::UnixStream> {
    let vsock_dir = mvm_build::vz_builder::persistent_vz_vsock_dir(DEV_VM_SESSION_ID);
    VzTransport::new(vsock_dir).connect(mvm_guest::vsock::GUEST_AGENT_PORT)
}

/// Check if the dev VM is running *and* reachable cross-process.
///
/// A live supervisor PID alone isn't enough — the guest may still be
/// booting, in which case other-process RPCs fail. Requiring the
/// guest-agent socket to connect keeps `dev status` honest with what
/// `dev shell` actually sees.
pub(in crate::commands) fn is_vz_dev_running() -> bool {
    #[cfg(feature = "builder-vm")]
    {
        let state_dir = mvm_build::vz_builder::persistent_vz_state_dir(DEV_VM_SESSION_ID);
        if !mvm_build::vz_builder::persistent_vz_supervisor_alive(&state_dir) {
            return false;
        }
        dev_vm_guest_agent_connect().is_ok()
    }
    #[cfg(not(feature = "builder-vm"))]
    {
        false
    }
}

/// Boot the dev VM via the Vz supervisor, optionally opening an
/// interactive console.
#[cfg(feature = "builder-vm")]
pub(super) fn cmd_dev_vz(cpus: u32, memory_gib: u32, open_shell: bool) -> Result<&'static str> {
    ui::progress("Starting dev environment via Vz (Virtualization.framework)...");

    if is_vz_dev_running() {
        if open_shell {
            ui::progress("Dev VM already running. Opening shell...");
            console_interactive(DEV_VM_NAME)?;
        } else {
            ui::progress("Dev VM already running.");
        }
        return Ok("already-running");
    }

    // Reap a dead-but-not-reaped supervisor from a prior session so the
    // fresh start binds a clean state dir.
    let state_dir = mvm_build::vz_builder::persistent_vz_state_dir(DEV_VM_SESSION_ID);
    mvm_build::vz_builder::stop_persistent_vz_by_pid_file(&state_dir);

    // Ensure dev image exists (build if needed — runs in this process).
    let (kernel, rootfs) = ensure_dev_image()?;

    // Lock ~/.mvm and ~/.cache/mvm to 0700 on every `dev up`. Idempotent.
    mvm_core::config::ensure_data_dir().with_context(|| "locking down data dir to mode 0700")?;
    mvm_core::config::ensure_cache_dir().with_context(|| "locking down cache dir to mode 0700")?;

    ui::info(&format!(
        "Booting dev VM ({cpus} vCPUs, {memory_gib} GiB memory)..."
    ));

    let memory_mib = memory_gib.saturating_mul(1024);
    let image = mvm_build::libkrun_builder::BuilderVmImage::Rootfs {
        kernel_path: std::path::PathBuf::from(&kernel),
        rootfs_path: std::path::PathBuf::from(&rootfs),
        cmdline: dev_image_cmdline(),
    };

    // The Vz supervisor detaches: `start()` spawns it as a background
    // child that writes `builder.pid` under the stable state dir and
    // outlives this CLI process. A later `dev down` reaps it via that
    // PID file. The persistent builder wires the `/dev/vdb` nix store
    // and the `/work` share internally and holds the nix-store flock
    // for the VM's lifetime.
    let handle = mvm_build::vz_builder::VzPersistentBuilderVm::new(dev_workspace_root())
        .with_session_id(DEV_VM_SESSION_ID)
        .with_guest_agent_port(true)
        .with_vcpus(cpus.clamp(1, u32::from(u8::MAX)) as u8)
        .with_memory_mib(memory_mib)
        .with_image_override(image)
        .start()
        .map_err(|e| anyhow::anyhow!("Failed to start dev VM: {e}"))?;
    let console_log = handle.vm_state_dir().join("console.log");
    // Drop the handle WITHOUT killing the supervisor — the dev VM must
    // survive this process exit. `VzPersistentVmHandle::Drop` leaves the
    // detached supervisor running (it only owns the `Child` for an
    // optional explicit kill, which we don't call).
    drop(handle);

    // Wait for the guest agent (≤60s), then point at the console log on
    // timeout.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    loop {
        if std::time::Instant::now() > deadline {
            anyhow::bail!(
                "Dev VM did not become ready within 60 seconds.\n\
                 Check the console log: {}",
                console_log.display()
            );
        }
        if dev_vm_guest_agent_connect().is_ok() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }

    ui::success("Dev VM ready.");
    ui::info("  Shell:      mvmctl dev shell");
    ui::info("  Stop VM:    mvmctl dev down");

    if open_shell {
        ui::info("");
        let _ = console_interactive(DEV_VM_NAME);
    }

    Ok("started")
}

#[cfg(not(feature = "builder-vm"))]
pub(super) fn cmd_dev_vz(_cpus: u32, _memory_gib: u32, _open_shell: bool) -> Result<&'static str> {
    anyhow::bail!(
        "the dev VM is built locally via the builder VM, but this mvmctl was \
         compiled without the `builder-vm` feature."
    )
}

/// Host-side path of the dev VM's guest-agent vsock socket. The console
/// picker checks this for existence before falling through to the other
/// backend probes; a present socket means the dev VM is the target.
pub(in crate::commands) fn dev_vsock_proxy_path() -> String {
    #[cfg(feature = "builder-vm")]
    {
        mvm_build::vz_builder::persistent_vz_vsock_dir(DEV_VM_SESSION_ID)
            .join(mvm_core::config::vsock_socket_filename(
                mvm_guest::vsock::GUEST_AGENT_PORT,
            ))
            .to_string_lossy()
            .into_owned()
    }
    #[cfg(not(feature = "builder-vm"))]
    {
        // No builder-vm feature → no dev VM; return a path that never
        // exists so the console picker skips the dev branch.
        String::new()
    }
}

/// Stop the dev VM by reaping its detached Vz supervisor via the PID
/// file under the stable state dir.
/// Stop the Vz dev VM. Returns whether a live VM was reaped. Prints the
/// human result line only when `!json` (the dispatch emits the JSON form).
pub(super) fn cmd_dev_vz_down(json: bool) -> Result<bool> {
    #[cfg(feature = "builder-vm")]
    {
        let state_dir = mvm_build::vz_builder::persistent_vz_state_dir(DEV_VM_SESSION_ID);
        let was_running = mvm_build::vz_builder::stop_persistent_vz_by_pid_file(&state_dir);
        // Drop the per-VM vsock dir so a stale socket can't fool the
        // liveness probe on the next `dev status`.
        let _ = std::fs::remove_dir_all(state_dir.join("vsock"));
        if !json {
            if was_running {
                ui::success("Dev VM stopped.");
            } else {
                ui::info("Dev VM is not running.");
            }
        }
        Ok(was_running)
    }
    #[cfg(not(feature = "builder-vm"))]
    {
        if !json {
            ui::info("Dev VM is not running.");
        }
        Ok(false)
    }
}

/// Show dev VM status.
pub(super) fn cmd_dev_vz_status(json: bool) -> Result<()> {
    let running = is_vz_dev_running();
    let state = if running { "running" } else { "stopped" };
    let kernel = if running { probe_dev_vm_kernel() } else { None };

    if json {
        return crate::json_out::emit_json(&build_dev_status_json("vz", state, kernel));
    }

    ui::info("Backend:  Vz (Apple Virtualization.framework)");
    ui::info(&format!("Dev VM:   {DEV_VM_NAME}"));
    ui::info(&format!("Status:   {state}"));
    if let Some(kernel) = &kernel {
        ui::info(&format!("  Kernel:  {kernel}"));
    }

    if let Some(image) = resolve_dev_status_image() {
        ui::info("  Image:   cached");
        if let Some(kernel_path) = image.kernel_path {
            ui::info(&format!("  Image kernel: {kernel_path}"));
        }
        ui::info(&format!("  Rootfs:  {}", image.rootfs_path));
    } else {
        ui::info("  Image:   not built");
    }

    let builder_cache = resolve_builder_vm_cache_status_summary();
    ui::info(&format!(
        "  Builder: {} cache {} (reason: {})",
        builder_cache.cache_kind,
        builder_cache.state.label(),
        builder_cache.reason_code
    ));

    Ok(())
}

/// Best-effort `uname -r` over the dev VM's guest agent. `None` when the
/// agent isn't reachable (VM down/booting) or the `builder-vm` feature
/// (which carries the guest-agent transport) is off.
#[cfg(feature = "builder-vm")]
fn probe_dev_vm_kernel() -> Option<String> {
    let mut stream = dev_vm_guest_agent_connect().ok()?;
    // Inbound vsock RPC audit.
    super::super::shared::emit_vsock_rpc_audit(
        DEV_VM_NAME,
        &mvm_guest::vsock::GuestRequest::Exec {
            command: "uname -r".to_string(),
            stdin: None,
            timeout_secs: Some(5),
        },
    );
    let mut out_buf: Vec<u8> = Vec::new();
    mvm_guest::vsock::send_exec_streaming(&mut stream, "uname -r", None, Some(5), |event| {
        if let mvm_guest::vsock::ExecEvent::Stdout { chunk } = event {
            out_buf.extend_from_slice(chunk);
        }
    })
    .ok()?;
    let kernel = String::from_utf8_lossy(&out_buf).trim().to_string();
    (!kernel.is_empty()).then_some(kernel)
}

#[cfg(not(feature = "builder-vm"))]
fn probe_dev_vm_kernel() -> Option<String> {
    None
}

/// Inspect dev caches without booting, rebuilding, or exposing local
/// artifact paths/digests.
pub(super) fn cmd_dev_cache_inspect(json: bool) -> Result<()> {
    let summary = resolve_dev_cache_inspect_summary();
    if json {
        println!("{}", dev_cache_inspect_json(&summary)?);
        return Ok(());
    }

    ui::info("Dev cache:");
    ui::info(&format!(
        "  Dev image: {} (kernel: {}, rootfs: {})",
        summary.dev_image.state, summary.dev_image.kernel, summary.dev_image.rootfs
    ));
    ui::info(&format!(
        "  Builder:   {} cache {} (reason: {})",
        summary.builder_cache.cache_kind,
        summary.builder_cache.state.label(),
        summary.builder_cache.reason_code
    ));
    Ok(())
}

#[derive(Debug, Eq, PartialEq)]
struct DevStatusImage {
    kernel_path: Option<String>,
    rootfs_path: String,
}

fn resolve_dev_status_image() -> Option<DevStatusImage> {
    let version = env!("CARGO_PKG_VERSION");
    for dir in [
        format!("{}/dev/current", mvm_core::config::mvm_data_dir()),
        format!(
            "{}/dev/prebuilt/v{version}",
            mvm_core::config::mvm_data_dir()
        ),
        format!("{}/dev", mvm_core::config::mvm_cache_dir()),
    ] {
        let rootfs_path = format!("{dir}/rootfs.ext4");
        if !std::path::Path::new(&rootfs_path).exists() {
            continue;
        }
        let kernel_path = format!("{dir}/vmlinux");
        return Some(DevStatusImage {
            kernel_path: std::path::Path::new(&kernel_path)
                .exists()
                .then_some(kernel_path),
            rootfs_path,
        });
    }

    None
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum BuilderVmCacheState {
    Ready,
    Stale,
}

impl BuilderVmCacheState {
    fn label(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Stale => "stale",
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
struct BuilderVmCacheStatusSummary {
    cache_kind: &'static str,
    state: BuilderVmCacheState,
    reason_code: &'static str,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
struct DevImageCacheSummary {
    state: &'static str,
    kernel: &'static str,
    rootfs: &'static str,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
struct DevCacheInspectSummary {
    dev_image: DevImageCacheSummary,
    builder_cache: BuilderVmCacheStatusSummary,
}

#[derive(Debug, Serialize)]
struct DevCacheInspectJson {
    schema_version: u8,
    dev_image: DevImageCacheJson,
    builder_cache: BuilderVmCacheJson,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub(super) struct DevImageCacheJson {
    state: &'static str,
    kernel: &'static str,
    rootfs: &'static str,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub(super) struct BuilderVmCacheJson {
    kind: &'static str,
    state: &'static str,
    reason_code: &'static str,
}

fn resolve_dev_cache_inspect_summary() -> DevCacheInspectSummary {
    DevCacheInspectSummary {
        dev_image: dev_image_cache_summary(resolve_dev_status_image().as_ref()),
        builder_cache: resolve_builder_vm_cache_status_summary(),
    }
}

fn dev_image_cache_summary(image: Option<&DevStatusImage>) -> DevImageCacheSummary {
    match image {
        Some(image) => DevImageCacheSummary {
            state: "cached",
            kernel: if image.kernel_path.is_some() {
                "present"
            } else {
                "missing"
            },
            rootfs: "present",
        },
        None => DevImageCacheSummary {
            state: "missing",
            kernel: "missing",
            rootfs: "missing",
        },
    }
}

fn dev_cache_inspect_json(summary: &DevCacheInspectSummary) -> Result<String> {
    let output = DevCacheInspectJson {
        schema_version: 1,
        dev_image: dev_image_cache_json(&summary.dev_image),
        builder_cache: builder_vm_cache_json(&summary.builder_cache),
    };
    serde_json::to_string_pretty(&output).context("serializing dev cache inspection JSON")
}

fn dev_image_cache_json(summary: &DevImageCacheSummary) -> DevImageCacheJson {
    DevImageCacheJson {
        state: summary.state,
        kernel: summary.kernel,
        rootfs: summary.rootfs,
    }
}

fn builder_vm_cache_json(summary: &BuilderVmCacheStatusSummary) -> BuilderVmCacheJson {
    BuilderVmCacheJson {
        kind: summary.cache_kind,
        state: summary.state.label(),
        reason_code: summary.reason_code,
    }
}

/// Machine-readable `mvmctl dev status --json` shape. Privacy-safe like
/// the cache-inspect report: cache fields say `present`/`missing`/`cached`,
/// never a local artifact path or digest. `guest_kernel` carries the
/// running guest's probed `uname -r` (a version string, not a path) only
/// when the VM answers — distinct from `dev_image.kernel`, which reports
/// whether the *cached image* ships a kernel artifact.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub(super) struct DevStatusJson {
    pub schema_version: u8,
    pub backend: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vm_name: Option<&'static str>,
    pub state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guest_kernel: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dev_image: Option<DevImageCacheJson>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub builder_cache: Option<BuilderVmCacheJson>,
}

/// Build the status report for a VM-backed dev backend (vz / libkrun):
/// resolves the backend-agnostic dev-image + builder-VM cache state and
/// attaches the caller-probed `kernel` (vz only; `None` elsewhere).
pub(super) fn build_dev_status_json(
    backend: &'static str,
    state: &'static str,
    guest_kernel: Option<String>,
) -> DevStatusJson {
    DevStatusJson {
        schema_version: 1,
        backend,
        vm_name: Some(DEV_VM_NAME),
        state,
        guest_kernel,
        dev_image: Some(dev_image_cache_json(&dev_image_cache_summary(
            resolve_dev_status_image().as_ref(),
        ))),
        builder_cache: Some(builder_vm_cache_json(
            &resolve_builder_vm_cache_status_summary(),
        )),
    }
}

/// Report for a backend with no managed dev VM (linux-native host shell,
/// or an unsupported host): no VM, no image/builder cache.
pub(super) fn build_dev_status_json_vmless(
    backend: &'static str,
    state: &'static str,
) -> DevStatusJson {
    DevStatusJson {
        schema_version: 1,
        backend,
        vm_name: None,
        state,
        guest_kernel: None,
        dev_image: None,
        builder_cache: None,
    }
}

/// Machine-readable result of a `dev down` (and, later, `dev up`)
/// lifecycle mutation, so scripts can branch on the outcome.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub(super) struct DevLifecycleJson {
    pub schema_version: u8,
    pub backend: &'static str,
    pub action: &'static str,
    /// `stopped` (a live VM was reaped) or `not-running` (nothing to stop).
    pub outcome: &'static str,
    /// `true` only when `dev down --reset` also dropped the Nix-store overlay.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub reset: bool,
}

pub(super) fn build_dev_up_json(backend: &'static str, outcome: &'static str) -> DevLifecycleJson {
    DevLifecycleJson {
        schema_version: 1,
        backend,
        action: "up",
        // `started` (booted + agent reachable), `already-running`, or
        // `host-native` (Linux KVM: the host shell is the dev env).
        outcome,
        reset: false,
    }
}

pub(super) fn build_dev_down_json(
    backend: &'static str,
    was_running: bool,
    reset: bool,
) -> DevLifecycleJson {
    DevLifecycleJson {
        schema_version: 1,
        backend,
        action: "down",
        outcome: if was_running {
            "stopped"
        } else {
            "not-running"
        },
        reset,
    }
}

fn resolve_builder_vm_cache_status_summary() -> BuilderVmCacheStatusSummary {
    builder_vm_cache_status_summary(
        find_builder_vm_flake(),
        std::path::Path::new(&mvm_core::config::mvm_cache_dir()),
        builder_vm_host_arch(),
    )
}

fn builder_vm_cache_status_summary(
    builder_flake: Result<String>,
    cache_root: &std::path::Path,
    arch: &str,
) -> BuilderVmCacheStatusSummary {
    let cache_dir = cache_root.join("builder-vm").join(arch);
    let Ok(flake_dir) = builder_flake else {
        return release_builder_vm_cache_status_summary(&cache_dir);
    };
    let Ok(fingerprint) = builder_vm_source_fingerprint(&flake_dir) else {
        return BuilderVmCacheStatusSummary {
            cache_kind: "source",
            state: BuilderVmCacheState::Stale,
            reason_code: "source_fingerprint_error",
        };
    };
    let status = builder_vm_source_cache_status(&cache_dir, &fingerprint);
    BuilderVmCacheStatusSummary {
        cache_kind: "source",
        state: if status.is_ready() {
            BuilderVmCacheState::Ready
        } else {
            BuilderVmCacheState::Stale
        },
        reason_code: status.reason_code(),
    }
}

fn release_builder_vm_cache_status_summary(
    cache_dir: &std::path::Path,
) -> BuilderVmCacheStatusSummary {
    if validate_builder_vm_stage0_artifacts(cache_dir).is_ok() {
        return BuilderVmCacheStatusSummary {
            cache_kind: "release",
            state: BuilderVmCacheState::Ready,
            reason_code: "hit",
        };
    }
    BuilderVmCacheStatusSummary {
        cache_kind: "release",
        state: BuilderVmCacheState::Stale,
        reason_code: "missing_or_invalid_artifacts",
    }
}

/// Prepare `~/.mvm/dev/current/` for a fresh dev-image build.
///
/// Replaces a stale symlink (the nix-darwin `linux-builder` legacy
/// pointed `current` at a root-owned `/nix/store/…-mvm-dev` path)
/// with a real, writable directory. `create_dir_all` is a no-op
/// against an existing symlink, so without this the libkrun
/// virtio-fs `/out` mount lands on the read-only Nix store path
/// and Apple Container fails with EACCES.
///
/// Only reachable under the libkrun-dispatch branch of `ensure_dev_image`,
/// which itself is gated on `builder-vm`.
#[cfg(feature = "builder-vm")]
fn prepare_dev_image_out_dir(out_dir: &str) -> Result<()> {
    if let Some(parent) = std::path::Path::new(out_dir).parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating dev-image out parent {}", parent.display()))?;
    }
    if std::path::Path::new(out_dir)
        .symlink_metadata()
        .is_ok_and(|m| m.file_type().is_symlink())
    {
        std::fs::remove_file(out_dir)
            .with_context(|| format!("removing stale dev-image symlink at {out_dir}"))?;
    }
    std::fs::create_dir_all(out_dir)
        .with_context(|| format!("creating dev-image out dir {out_dir}"))?;
    Ok(())
}

/// Resolve the dev image (kernel + rootfs) to absolute paths.
///
/// In a source checkout: uses the libkrun-backed builder VM
/// (`LibkrunBuilderVm` runs `nix build` against the dev-shell flake
/// from inside a microVM with a persistent 64 GiB `/nix` store).
/// Libkrun isn't installed → loud error pointing at the install
/// command; **no libkrun fallback for the dev-shell image** — the
/// dev-shell rustc closure overflows libkrun's 4 GiB overlay anyway,
/// so a fallback that would just disk-out is worse than an actionable
/// error.
///
/// Outside a source checkout: falls back to the GitHub-release
/// download of a pre-built image.
///
/// Failures of the local build are surfaced loudly — never silently
/// substituted with the prebuilt, since the prebuilt would mask local
/// rootfs changes.
pub(super) fn ensure_dev_image() -> Result<(String, String)> {
    // Source-checkout dispatch.
    //
    // The dev-shell image now comes from `packages.<sys>.dev` in
    // `nix/images/builder-vm/flake.nix` (the same flake as the
    // headless builder VM). The old separate `nix/images/builder/`
    // flake has been deleted. `find_builder_vm_flake()` detects a
    // source checkout; when present, `build_image_via_libkrun` is
    // invoked against the `dev` attr of the consolidated flake.
    #[cfg(feature = "builder-vm")]
    if let Ok(flake_dir) = find_builder_vm_flake() {
        let out_dir = format!("{}/dev/current", mvm_core::config::mvm_data_dir());
        let out_path = std::path::Path::new(&out_dir);

        // Fix A — fast-path: when the dev-image source fingerprint matches
        // the cached artifacts, the image the builder VM would produce is
        // byte-identical to what's on disk, so boot it without spinning a
        // builder VM. Without this, every `dev up` in a source checkout
        // re-enters nix to rebuild the custom kernel + full crate closure
        // (minutes) even when nothing changed. Same trust model as the
        // Layer-1 and published-prebuilt fast paths: fingerprint match ⇒
        // identical nix derivation ⇒ identical output. `prepare_dev_image_out_dir`
        // (which clears the dir) runs only on the rebuild path below, so a
        // hit never destroys the cache it's about to return.
        if let Ok(fingerprint) = builder_vm_source_fingerprint(&flake_dir) {
            let status = builder_vm_source_cache_status(out_path, &fingerprint);
            if status.is_ready() {
                ui::success(&format!(
                    "Dev image cache hit (fingerprint {}); skipping builder VM.",
                    stage0_fingerprint_prefix(&fingerprint),
                ));
                return Ok((
                    format!("{out_dir}/vmlinux"),
                    format!("{out_dir}/rootfs.ext4"),
                ));
            }
            ui::progress(&format!(
                "Dev image cache decision: {}",
                status.reason_code()
            ));
        }

        prepare_dev_image_out_dir(&out_dir)?;
        return build_image_via_libkrun(&out_dir);
    }

    // No local source checkout — download the published prebuilt.
    // Cache key = mvmctl's version: each version owns a sibling
    // directory under .../dev/prebuilt/, and bumping the binary
    // automatically invalidates older caches. We sweep older version
    // dirs on every miss so disk usage tracks the *current* version,
    // not the union of every version ever installed.
    ui::info("No local builder-vm flake found; downloading published prebuilt.");
    let version = env!("CARGO_PKG_VERSION");
    let prebuilt_root = format!("{}/dev/prebuilt", mvm_core::config::mvm_data_dir());
    let prebuilt_dir = format!("{prebuilt_root}/v{version}");
    std::fs::create_dir_all(&prebuilt_dir)
        .with_context(|| format!("creating prebuilt dir {prebuilt_dir}"))?;
    let kernel_path = format!("{prebuilt_dir}/vmlinux");
    let rootfs_path = format!("{prebuilt_dir}/rootfs.ext4");
    // Cache hit on the current version's dir — fast path. Validate
    // first; if either file is below the size floor or the rootfs
    // lacks the ext4 magic, treat the cache as poisoned and delete it
    // so the cascade below can re-populate from a healthy source. The
    // typical poisoning vector is an earlier copy from a stub or
    // half-downloaded source — the size floor catches the stub case
    // (~12 B vs. ~16 MiB minimum), and the magic check catches a
    // wrong-format file at the right size.
    if std::path::Path::new(&kernel_path).exists() && std::path::Path::new(&rootfs_path).exists() {
        match validate_dev_image_artifacts(&kernel_path, &rootfs_path) {
            Ok(()) => {
                prune_old_prebuilts(&prebuilt_root, version);
                return Ok((kernel_path, rootfs_path));
            }
            Err(e) => {
                ui::warn(&format!(
                    "Cached dev image at {prebuilt_dir} failed sanity check ({e}); \
                     deleting and rebuilding."
                ));
                let _ = std::fs::remove_file(&kernel_path);
                let _ = std::fs::remove_file(&rootfs_path);
            }
        }
    }
    // Source-checkout-first. When the binary was compiled out of an
    // mvm source tree that has `nix/images/dev-prebuilt/<arch>/`
    // populated, that's the authoritative dev image for this build —
    // skip GitHub entirely. The helper returns `None` for installed
    // binaries (their `CARGO_MANIFEST_DIR` resolves into
    // `~/.cargo/registry/` where the directory will never exist) and
    // for source checkouts that haven't vendored anything yet, in
    // which case we fall through to the published prebuilt as before.
    if let Some((src_kernel, src_rootfs, source_label)) = find_vendored_dev_image() {
        validate_dev_image_artifacts(&src_kernel, &src_rootfs).with_context(|| {
            format!(
                "vendored dev image at {source_label} failed sanity check — \
                 refusing to copy garbage into the prebuilt cache"
            )
        })?;
        ui::info(&format!(
            "Using vendored dev image from source checkout ({source_label})."
        ));
        std::fs::copy(&src_kernel, &kernel_path)
            .with_context(|| format!("copying vendored kernel {src_kernel:?} → {kernel_path}"))?;
        std::fs::copy(&src_rootfs, &rootfs_path)
            .with_context(|| format!("copying vendored rootfs {src_rootfs:?} → {rootfs_path}"))?;
        // No prune — vendored is the source of truth for this binary,
        // not a download; leaving older `v*/` dirs around lets
        // installed-binary users keep their offline-fallback cache.
        return Ok((kernel_path, rootfs_path));
    }
    // Try the published prebuilt. Defer the prune until *after* a
    // successful download — old `~/.mvm/dev/prebuilt/v*/` dirs and
    // historical `~/.mvm/dev/builds/<hash>/` artifacts are our last-
    // resort fallback when the release page lacks v{version} assets.
    match download_dev_image(&kernel_path, &rootfs_path) {
        Ok(result) => {
            prune_old_prebuilts(&prebuilt_root, version);
            Ok(result)
        }
        Err(download_err) => {
            ui::warn(&format!(
                "Could not download dev image for v{version}: {download_err}\n\
                 Searching for a local fallback under ~/.mvm/dev/."
            ));
            if let Some((src_kernel, src_rootfs, source_label)) = find_local_fallback_image() {
                ui::warn(&format!(
                    "Using local fallback from {source_label}. \
                     This is not the published v{version} image — boot it knowing the \
                     versions differ. Publish v{version} assets or restore the local \
                     builder flake to make this go away."
                ));
                std::fs::copy(&src_kernel, &kernel_path).with_context(|| {
                    format!("copying fallback kernel {src_kernel:?} → {kernel_path}")
                })?;
                std::fs::copy(&src_rootfs, &rootfs_path).with_context(|| {
                    format!("copying fallback rootfs {src_rootfs:?} → {rootfs_path}")
                })?;
                Ok((kernel_path, rootfs_path))
            } else {
                Err(download_err.context(
                    "no local fallback found under ~/.mvm/dev/current/, \
                     ~/.mvm/dev/prebuilt/v*/, or ~/.mvm/dev/builds/*/",
                ))
            }
        }
    }
}

/// Search for any locally-cached dev image as a fallback when the
/// published-prebuilt download fails or as a Stage 0 seed when the
/// builder VM cache is empty. Looks under, in order of precedence
/// when mtimes tie:
///
/// - `~/.mvm/dev/current/{vmlinux,rootfs.ext4}` — the canonical
///   "live" dev image written by `build_image_via_libkrun` and read
///   by `resolve_dev_status_image`. Present whenever `mvmctl dev up`
///   has succeeded at least once on this host; survives a manual
///   delete of `~/.cache/mvm/builder-vm/`. This is the load-bearing
///   Stage 0 seed — without it, a contributor who blew away the
///   builder VM cache would have no path back.
/// - `~/.mvm/dev/prebuilt/v*/{vmlinux,rootfs.ext4}` — previously
///   downloaded prebuilts for earlier versions.
/// - `~/.mvm/dev/builds/<hash>/{vmlinux,rootfs.ext4}` — historical
///   nix-darwin `linux-builder` outputs from the pre-libkrun era.
///
/// Returns the most-recently-modified pair so a user with a recent
/// successful build/download keeps booting, with a short label
/// (e.g. `current`, `prebuilt/v0.13.0`, or `builds/abcdef…`) for the
/// warning surface. `None` means nothing usable was found.
fn find_local_fallback_image() -> Option<(std::path::PathBuf, std::path::PathBuf, String)> {
    find_local_fallback_image_with(|_| true)
}

fn find_local_fallback_image_with(
    accepts_rootfs: impl Fn(&std::path::Path) -> bool,
) -> Option<(std::path::PathBuf, std::path::PathBuf, String)> {
    let dev_root = format!("{}/dev", mvm_core::config::mvm_data_dir());

    let mut candidates: Vec<(std::time::SystemTime, std::path::PathBuf, String)> = Vec::new();
    // Silently skip cache entries that look corrupt (stub bytes from
    // a botched earlier copy, half-written downloads, stale symlinks
    // from the legacy nix-darwin `current/` layout). The auto-discover
    // path is best-effort — surfacing every bad candidate as a warning
    // would spam the boot path; the cascade just falls through to a
    // healthier candidate or to the next layer.
    let mut consider = |dir: std::path::PathBuf, label: String| {
        let kernel = dir.join("vmlinux");
        let rootfs = dir.join("rootfs.ext4");
        if !kernel.is_file() || !rootfs.is_file() {
            return;
        }
        if validate_dev_image_artifacts(&kernel, &rootfs).is_err() {
            return;
        }
        if !accepts_rootfs(&rootfs) {
            return;
        }
        let mtime = std::fs::metadata(&rootfs)
            .and_then(|m| m.modified())
            .unwrap_or(std::time::UNIX_EPOCH);
        candidates.push((mtime, dir, label));
    };

    consider(
        std::path::Path::new(&dev_root).join("current"),
        "current".to_string(),
    );
    for sub in ["prebuilt", "builds"] {
        let parent = std::path::Path::new(&dev_root).join(sub);
        let Ok(entries) = std::fs::read_dir(&parent) else {
            continue;
        };
        for entry in entries.flatten() {
            let dir = entry.path();
            if !dir.is_dir() {
                continue;
            }
            let label = format!("{sub}/{}", entry.file_name().to_string_lossy());
            consider(dir, label);
        }
    }

    candidates.sort_by_key(|(mtime, ..)| *mtime);
    let (_, dir, label) = candidates.into_iter().next_back()?;
    Some((dir.join("vmlinux"), dir.join("rootfs.ext4"), label))
}

/// Verify the freshly-built Stage 0 rootfs actually carries
/// `/sbin/mvm-host-vm-init` by walking the ext4 image read-only and
/// looking the inode up by path — no mount, no root, no
/// raw-byte substring scan. Catches a builder-VM flake that built but
/// failed to install the init binary, before the artifacts are promoted
/// into the cache (where the next boot would `init=` into a missing
/// binary and panic).
///
/// A malformed / non-ext4 image surfaces as an `Err` (load failure)
/// rather than a false negative.
#[cfg(feature = "builder-vm")]
fn verify_stage0_rootfs_has_init(rootfs: &std::path::Path) -> Result<()> {
    let fs = ext4_view::Ext4::load_from_path(rootfs)
        .with_context(|| format!("opening {} as ext4", rootfs.display()))?;
    let present = fs.exists(HOST_VM_INIT_ROOTFS_PATH).with_context(|| {
        format!(
            "looking up {HOST_VM_INIT_ROOTFS_PATH} in {}",
            rootfs.display()
        )
    })?;
    if !present {
        anyhow::bail!(
            "Stage 0 builder VM rootfs {} is missing {HOST_VM_INIT_ROOTFS_PATH}",
            rootfs.display()
        );
    }
    Ok(())
}

/// Sanity-check that a `(vmlinux, rootfs.ext4)` pair looks like a real
/// dev image. Fast-fails before copying or returning the artifacts as
/// usable, so a stub or truncated file can't poison the prebuilt cache.
///
/// Two checks per file:
///
/// - **Size floor.** A real `vmlinux` is several MiB (typical ARM64
///   Image is 15–20 MiB); a real `rootfs.ext4` is ~700 MiB. Reject
///   anything under a conservative floor (1 MiB / 4 MiB respectively)
///   to catch the stub-file case (~12 B from a botched test, ~0 B
///   from a torn-down download).
/// - **Ext4 magic.** The ext4 superblock starts at byte 1024; the
///   `s_magic` field is at byte 1080 (offset 56 inside the
///   superblock) and equals `0xEF53` little-endian. Only the rootfs
///   gets this check — `vmlinux` formats vary by arch (ARM64
///   `Image`, x86 bzImage, etc.) so there's no portable magic to
///   match.
fn validate_dev_image_artifacts(
    kernel: impl AsRef<std::path::Path>,
    rootfs: impl AsRef<std::path::Path>,
) -> Result<()> {
    const KERNEL_MIN_BYTES: u64 = 1024 * 1024;
    const ROOTFS_MIN_BYTES: u64 = 4 * 1024 * 1024;
    const EXT4_MAGIC_OFFSET: u64 = 1024 + 56;
    const EXT4_MAGIC: [u8; 2] = [0x53, 0xEF];

    let kernel = kernel.as_ref();
    let rootfs = rootfs.as_ref();

    let kernel_size = std::fs::metadata(kernel)
        .with_context(|| format!("stat {}", kernel.display()))?
        .len();
    if kernel_size < KERNEL_MIN_BYTES {
        anyhow::bail!(
            "kernel at {} is only {} bytes (expected ≥ {})",
            kernel.display(),
            kernel_size,
            KERNEL_MIN_BYTES,
        );
    }

    let rootfs_size = std::fs::metadata(rootfs)
        .with_context(|| format!("stat {}", rootfs.display()))?
        .len();
    if rootfs_size < ROOTFS_MIN_BYTES {
        anyhow::bail!(
            "rootfs at {} is only {} bytes (expected ≥ {})",
            rootfs.display(),
            rootfs_size,
            ROOTFS_MIN_BYTES,
        );
    }

    use std::io::{Read, Seek, SeekFrom};
    let mut f =
        std::fs::File::open(rootfs).with_context(|| format!("open {}", rootfs.display()))?;
    f.seek(SeekFrom::Start(EXT4_MAGIC_OFFSET))
        .with_context(|| format!("seek to ext4 magic in {}", rootfs.display()))?;
    let mut magic = [0u8; 2];
    f.read_exact(&mut magic)
        .with_context(|| format!("read ext4 magic from {}", rootfs.display()))?;
    if magic != EXT4_MAGIC {
        anyhow::bail!(
            "rootfs at {} does not have ext4 magic at offset {} (got {magic:02x?})",
            rootfs.display(),
            EXT4_MAGIC_OFFSET,
        );
    }

    Ok(())
}

/// Look for a vendored dev image inside the source checkout the mvmctl
/// binary was compiled from: `{workspace_root}/nix/images/dev-prebuilt/
/// <arch>/{vmlinux, rootfs.ext4}`. The path is checked last in the
/// fallback cascade — it's the most predictable source ("what the
/// repo ships") but only useful when `mvmctl` runs out of its source
/// checkout: `CARGO_MANIFEST_DIR` is baked at compile time and points
/// into `~/.cargo/registry/` for `cargo install`-ed builds, where the
/// directory will reliably be missing. That's fine — for installed
/// binaries the `~/.mvm/dev/` auto-discover path covers the offline
/// case.
///
/// `arch` mirrors the matrix used by `download_dev_image`: `aarch64`
/// on Apple Silicon / aarch64-linux, `x86_64` everywhere else.
fn find_vendored_dev_image() -> Option<(std::path::PathBuf, std::path::PathBuf, String)> {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let workspace_root = std::path::Path::new(manifest_dir).parent()?.parent()?;
    let arch = if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else {
        "x86_64"
    };
    let dir = workspace_root
        .join("nix")
        .join("images")
        .join("dev-prebuilt")
        .join(arch);
    let kernel = dir.join("vmlinux");
    let rootfs = dir.join("rootfs.ext4");
    if !kernel.is_file() || !rootfs.is_file() {
        return None;
    }
    let label = format!("vendored {}", dir.display());
    Some((kernel, rootfs, label))
}

/// Drop every direct child of `prebuilt_root` except the one for the
/// currently-running version. Best-effort — failure is logged.
fn prune_old_prebuilts(prebuilt_root: &str, current_version: &str) {
    let current = format!("v{current_version}");
    let Ok(entries) = std::fs::read_dir(prebuilt_root) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if name_str == current {
            continue;
        }
        let path = entry.path();
        match std::fs::remove_dir_all(&path) {
            Ok(()) => ui::info(&format!("Pruned stale prebuilt cache: {name_str}")),
            Err(e) => tracing::warn!("Could not prune {}: {e}", path.display()),
        }
    }
}

/// Download a pre-built dev image (kernel + rootfs) from GitHub releases.
///
/// Trust chain:
///
/// 1. Try the cosign-keyless-signed manifest first
///    (`dev-image-{arch}.manifest.json` + `.bundle`). If present,
///    `mvm-security::image_verify::verify_manifest` validates the
///    Sigstore bundle against the project's release-workflow OIDC
///    identity, parses the manifest, and we use *its* artifact
///    digests as the source of truth.
///
/// 2. If the manifest is 404 (older release predating signing) or
///    its companion bundle is missing, fall back to the
///    unsigned-checksum path with a loud deprecation warning. This
///    keeps mvmctl pointing at older releases working through the
///    rollout, and the deprecation banner sets the stage for making
///    the manifest mandatory in a future major version.
///
/// 3. Either way, every downloaded artifact gets streaming SHA-256
///    verification against the expected digest.
///
/// Escape hatches (both print loud warnings):
///   - `MVM_SKIP_HASH_VERIFY=1` — skip SHA-256 step.
///   - `MVM_SKIP_COSIGN_VERIFY=1` — skip cosign signature check on
///     the manifest body but still parse and use it. Only for
///     emergency Sigstore-side rotation; SHA-256 still applies.
fn download_dev_image(kernel_path: &str, rootfs_path: &str) -> Result<(String, String)> {
    // Wrap the verification pipeline so every exit path — success or
    // failure — emits the verify_duration gauge and bumps the
    // appropriate outcome counter.
    let verify_start = std::time::Instant::now();
    let result = download_dev_image_inner(kernel_path, rootfs_path);
    let elapsed_ms = verify_start.elapsed().as_millis() as u64;
    let metrics = mvm_core::observability::metrics::global();
    metrics
        .dev_image_verify_duration_ms
        .store(elapsed_ms, std::sync::atomic::Ordering::Relaxed);
    if result.is_ok() {
        metrics
            .dev_image_verify_ok
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    result
}

fn download_dev_image_inner(kernel_path: &str, rootfs_path: &str) -> Result<(String, String)> {
    let version = env!("CARGO_PKG_VERSION");
    let base_url = format!("https://github.com/tinylabscom/mvm/releases/download/v{version}");
    // Detect host arch to download the right image.
    // Apple Silicon (aarch64-darwin) needs aarch64-linux image.
    // Intel Mac (x86_64-darwin) needs x86_64-linux image.
    let arch = if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else {
        "x86_64"
    };
    let kernel_name = format!("dev-vmlinux-{arch}");
    let rootfs_name = format!("dev-rootfs-{arch}.ext4");
    let kernel_url = format!("{base_url}/{kernel_name}");
    let rootfs_url = format!("{base_url}/{rootfs_name}");

    ui::info(&format!(
        "Downloading dev image (v{version}) — one-time setup. \
         Subsequent runs reuse the cached image and start in seconds."
    ));

    // Prefer the cosign-signed manifest. Falls back to the unsigned
    // checksum file when the manifest is 404 (older release).
    let expected = match try_fetch_signed_manifest(&base_url, version, arch, "dev")? {
        Some(manifest) => {
            ui::success(&format!(
                "  ✓ cosign-verified manifest for v{} (built {} UTC, valid until {} UTC)",
                manifest.version,
                manifest.built_at.format("%Y-%m-%d"),
                manifest.not_after.format("%Y-%m-%d"),
            ));
            manifest
                .artifacts
                .iter()
                .map(|a| (a.name.clone(), a.sha256.to_ascii_lowercase()))
                .collect::<std::collections::HashMap<_, _>>()
        }
        None => {
            ui::warn(&format!(
                "No cosign-signed manifest found for v{version}. Falling back to \
                 unsigned checksum file (legacy path predating plan 36 / ADR 005). \
                 Future releases will require the signed manifest."
            ));
            let checksums_name = format!("dev-image-{arch}-checksums-sha256.txt");
            let checksums_url = format!("{base_url}/{checksums_name}");
            fetch_expected_hashes(&checksums_url, &[&kernel_name, &rootfs_name])?
        }
    };

    ui::info("  Fetching kernel...");
    download_file(&kernel_url, kernel_path).map_err(|e| {
        bump_verify_outcome("network");
        e.context(format!("Failed to download kernel from {kernel_url}"))
    })?;
    verify_artifact_hash(
        kernel_path,
        &kernel_name,
        expected.get(kernel_name.as_str()),
    )?;

    ui::info("  Fetching rootfs...");
    download_file(&rootfs_url, rootfs_path).map_err(|e| {
        bump_verify_outcome("network");
        e.context(format!("Failed to download rootfs from {rootfs_url}"))
    })?;
    verify_artifact_hash(
        rootfs_path,
        &rootfs_name,
        expected.get(rootfs_name.as_str()),
    )?;

    ui::success("Dev image downloaded, hash-verified, and cached.");
    Ok((kernel_path.to_string(), rootfs_path.to_string()))
}

/// Probe for and verify the cosign-signed manifest at
/// `{base_url}/{variant}-image-{arch}.manifest.json{,.bundle}`.
///
/// Returns:
/// - `Ok(Some(manifest))` — manifest + bundle present, signature verified,
///   version pinned to runtime, max-age window not yet exceeded.
/// - `Ok(None)` — manifest URL 404. This is the legacy fallback for
///   older releases that predate signing; caller can fall back to the
///   unsigned-checksum path with a deprecation warning.
/// - `Err(_)` — manifest fetched but verification or parsing failed.
///   Hard error; never silently fall through. `MVM_SKIP_COSIGN_VERIFY=1`
///   downgrades signature failures to a parse-only path.
fn try_fetch_signed_manifest(
    base_url: &str,
    version: &str,
    arch: &str,
    variant: &str,
) -> Result<Option<mvm_core::crypto::image_verify::SignedManifest>> {
    use mvm_core::crypto::image_verify;

    let manifest_name = format!("{variant}-image-{arch}.manifest.json");
    let manifest_url = format!("{base_url}/{manifest_name}");
    let bundle_url = format!("{manifest_url}.bundle");

    // HEAD-probe the manifest URL. If absent (older release without
    // signing), fall back gracefully.
    if !url_exists(&manifest_url)? {
        return Ok(None);
    }

    let manifest_tmp = tempfile::NamedTempFile::new().context("creating manifest tempfile")?;
    let bundle_tmp = tempfile::NamedTempFile::new().context("creating bundle tempfile")?;
    let manifest_path = manifest_tmp.path().to_string_lossy().into_owned();
    let bundle_path = bundle_tmp.path().to_string_lossy().into_owned();

    download_file(&manifest_url, &manifest_path).map_err(|e| {
        bump_verify_outcome("network");
        e.context(format!(
            "Failed to download signed manifest from {manifest_url}"
        ))
    })?;
    download_file(&bundle_url, &bundle_path).map_err(|e| {
        bump_verify_outcome("network");
        e.context(format!(
            "Failed to download cosign bundle from {bundle_url}. The release \
             pipeline requires a manifest's signature to be present alongside \
             the manifest body — refusing to trust an unsigned manifest."
        ))
    })?;

    let manifest_bytes =
        std::fs::read(&manifest_path).context("reading downloaded manifest body")?;
    let bundle_bytes = std::fs::read(&bundle_path).context("reading downloaded cosign bundle")?;

    // GitHub Actions keyless OIDC: the SAN encodes the workflow URL
    // bound to the tag, and the issuer is GitHub's token endpoint.
    let expected_identity = format!(
        "https://github.com/tinylabscom/mvm/.github/workflows/release.yml@refs/tags/v{version}"
    );
    let expected_issuer = "https://token.actions.githubusercontent.com";

    let manifest = if std::env::var_os("MVM_SKIP_COSIGN_VERIFY").is_some() {
        tracing::warn!(
            "MVM_SKIP_COSIGN_VERIFY set — accepting unverified manifest body. \
             This is an emergency-rotation escape hatch only."
        );
        image_verify::parse_manifest(&manifest_bytes)
            .map_err(|e| anyhow::anyhow!("manifest parse failed: {e}"))?
    } else {
        image_verify::verify_manifest(
            &manifest_bytes,
            &bundle_bytes,
            &expected_identity,
            expected_issuer,
        )
        .map_err(|e| {
            bump_verify_outcome("sig_invalid");
            anyhow::anyhow!(
                "Cosign verification failed for {manifest_name}: {e}\n\
                 \n\
                 Plan 36 / ADR 005 requires every dev image manifest to be cosign-keyless\n\
                 signed against the release workflow's OIDC identity. Refusing to use this\n\
                 image. Possible causes:\n\
                 - account/CDN compromise (open a security issue);\n\
                 - the release was published without going through the signing job;\n\
                 - clock skew (manifest expired); check `date -u`.\n\
                 \n\
                 Emergency rotation: set MVM_SKIP_COSIGN_VERIFY=1 to bypass the signature\n\
                 check while keeping SHA-256 verification active."
            )
        })?
    };

    // Pin the manifest's claimed version to mvmctl's own version. A
    // mismatch means someone is feeding us a different release's
    // manifest — refuse.
    image_verify::check_version_pin(&manifest, version).map_err(|e| {
        bump_verify_outcome("version_skew");
        anyhow::anyhow!("manifest version pin failed: {e}")
    })?;

    // Enforce max-age (default 90d). mvmctl warns and proceeds; mvmd
    // refuses (different risk tolerance — handled in mvmd).
    let now = chrono::Utc::now();
    if let Err(e) = image_verify::check_not_after(&manifest, now) {
        bump_verify_outcome("expired");
        ui::warn(&format!(
            "Dev image manifest is past its max-age ({e}). Consider upgrading \
             mvmctl — older signed images are still cryptographically valid but \
             may carry unpatched vulnerabilities."
        ));
    }

    // Consult the cosign-signed revocation list. Cached up to 24h;
    // tolerated up to 7d offline. A signed
    // image whose version is on the list hard-fails — recall is the
    // primary mechanism for "we know this build is bad."
    if let Some(revocations) = try_fetch_revocation_list()? {
        image_verify::check_revocation(&manifest, &revocations).map_err(|e| {
            bump_verify_outcome("revoked");
            anyhow::anyhow!(
                "Dev image manifest is on the project's revocation list: {e}\n\
                 \n\
                 Plan 36 / ADR 005: a published `revocations` release entry has\n\
                 marked v{version} unsafe to run. Refusing to use this image.\n\
                 Upgrade mvmctl to a non-revoked release."
            )
        })?;
    }

    Ok(Some(manifest))
}

/// Fetch + verify the project's signed revocation list, caching it
/// under `~/.cache/mvm/revocations/`.
///
/// The revocation list lives at a stable `revocations` release tag
/// whose only assets are
/// `revoked-versions.json` and its cosign bundle. Append-only across
/// releases; updated by cutting a new entry on that tag.
///
/// Cache policy:
///   - Refresh from upstream if the cached file is >24h old.
///   - Tolerate up to 7d of cached staleness when the network is
///     unavailable; surface a warning rather than blocking.
///   - 404 on the upstream URL is treated as "no recalls today" —
///     bootstrap state until the project publishes its first
///     revocations entry. Returns Ok(None).
///
/// Returns Ok(None) when the list isn't available *and* we have no
/// cached copy — caller proceeds without revocation enforcement (with
/// a warning). Returns Err on signature verification failure.
fn try_fetch_revocation_list() -> Result<Option<mvm_core::crypto::image_verify::RevocationList>> {
    use mvm_core::crypto::image_verify;
    use std::time::{Duration, SystemTime};

    let cache_dir = format!("{}/revocations", mvm_core::config::mvm_cache_dir());
    std::fs::create_dir_all(&cache_dir)
        .with_context(|| format!("creating revocations cache dir {cache_dir}"))?;
    let cache_json = format!("{cache_dir}/revoked-versions.json");
    let cache_bundle = format!("{cache_dir}/revoked-versions.json.bundle");

    let cache_age = std::fs::metadata(&cache_json)
        .ok()
        .and_then(|m| m.modified().ok())
        .and_then(|t| SystemTime::now().duration_since(t).ok())
        .unwrap_or(Duration::from_secs(u64::MAX));

    let twenty_four_hours = Duration::from_secs(24 * 60 * 60);
    let seven_days = Duration::from_secs(7 * 24 * 60 * 60);

    // Refresh if cache is stale (or absent).
    if cache_age > twenty_four_hours {
        let base = "https://github.com/tinylabscom/mvm/releases/download/revocations";
        let json_url = format!("{base}/revoked-versions.json");
        let bundle_url = format!("{base}/revoked-versions.json.bundle");

        match url_exists(&json_url) {
            Ok(true) => {
                let tmp_json =
                    tempfile::NamedTempFile::new().context("creating revocations tempfile")?;
                let tmp_bundle = tempfile::NamedTempFile::new()
                    .context("creating revocations bundle tempfile")?;
                let tmp_json_path = tmp_json.path().to_string_lossy().into_owned();
                let tmp_bundle_path = tmp_bundle.path().to_string_lossy().into_owned();
                let download_result = download_file(&json_url, &tmp_json_path)
                    .and_then(|()| download_file(&bundle_url, &tmp_bundle_path));
                match download_result {
                    Ok(()) => {
                        std::fs::copy(&tmp_json_path, &cache_json)
                            .context("caching revoked-versions.json")?;
                        std::fs::copy(&tmp_bundle_path, &cache_bundle)
                            .context("caching revoked-versions.json.bundle")?;
                    }
                    Err(e) if cache_age <= seven_days => {
                        ui::warn(&format!(
                            "Could not refresh revocation list ({e}); using cached copy \
                             (last refreshed {} hours ago).",
                            cache_age.as_secs() / 3600
                        ));
                    }
                    Err(e) => {
                        ui::warn(&format!(
                            "Could not refresh revocation list ({e}) and no fresh cache \
                             is available; proceeding without recall enforcement."
                        ));
                        return Ok(None);
                    }
                }
            }
            Ok(false) => {
                // 404: the project hasn't published a revocations
                // release yet. Bootstrap state — no recalls means
                // nothing to enforce. Don't cache this; a future
                // refresh should pick up the first published list.
                return Ok(None);
            }
            Err(e) if cache_age <= seven_days => {
                ui::warn(&format!(
                    "Could not probe revocation list ({e}); using cached copy."
                ));
            }
            Err(e) => {
                ui::warn(&format!(
                    "Could not probe revocation list ({e}) and no fresh cache \
                     is available; proceeding without recall enforcement."
                ));
                return Ok(None);
            }
        }
    }

    // No cached file → nothing to enforce.
    if !std::path::Path::new(&cache_json).exists() {
        return Ok(None);
    }

    let json_bytes = std::fs::read(&cache_json).context("reading cached revocations.json")?;
    let bundle_bytes =
        std::fs::read(&cache_bundle).context("reading cached revocations.json.bundle")?;

    // The revocations tag is signed by a dedicated revocations
    // workflow's OIDC identity, not the per-release workflow. A
    // separate identity ensures a leaked image-signing cert can't
    // fabricate a permissive revocation list (and vice versa).
    let expected_identity = "https://github.com/tinylabscom/mvm/.github/workflows/revocations.yml@refs/tags/revocations";
    let expected_issuer = "https://token.actions.githubusercontent.com";

    if std::env::var_os("MVM_SKIP_COSIGN_VERIFY").is_some() {
        // The same MVM_SKIP_COSIGN_VERIFY emergency-rotation escape
        // hatch covers both the manifest and the revocation list.
        // SHA-256 of artifacts still applies separately at the
        // verify_artifact_hash callsite.
        let list: image_verify::RevocationList = serde_json::from_slice(&json_bytes)
            .context("parsing revocations JSON without signature verification")?;
        return Ok(Some(list));
    }

    image_verify::verify_signed_payload(
        &json_bytes,
        &bundle_bytes,
        expected_identity,
        expected_issuer,
    )
    .map_err(|e| {
        anyhow::anyhow!(
            "Revocation list signature verification failed: {e}. Refusing to \
             trust an unverified recall."
        )
    })?;
    let list: image_verify::RevocationList =
        serde_json::from_slice(&json_bytes).context("parsing verified revocations JSON")?;
    Ok(Some(list))
}

/// `mvmctl dev import-image` — sideload a verified dev image from local files.
///
/// Runs the same cosign + SHA-256 + version-pin + max-age +
/// revocation pipeline as `download_dev_image`, but against
/// operator-provided local
/// files instead of the GitHub Releases URL. On success the verified
/// artifacts are copied into the version-namespaced cache so the next
/// `mvmctl dev up` boots from them with no further verification or
/// network round-trip.
///
/// The intended user is anyone running mvmctl in a regulated /
/// gov / air-gapped environment that can't reach github.com but
/// that legitimately wants the supply-chain check. Without this
/// path the only option for these users was MVM_SKIP_HASH_VERIFY=1,
/// which disables verification entirely — exactly the unsafe escape
/// the signed-manifest path exists to discourage.
pub fn cmd_dev_import_image(
    manifest_path: &str,
    bundle_path: &str,
    vmlinux_path: &str,
    rootfs_path: &str,
) -> Result<()> {
    use mvm_core::crypto::image_verify;

    let version = env!("CARGO_PKG_VERSION");
    let arch = if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else {
        "x86_64"
    };

    ui::info(&format!(
        "Importing dev image (v{version}, {arch}) from local files..."
    ));

    let manifest_bytes = std::fs::read(manifest_path)
        .with_context(|| format!("reading manifest file at {manifest_path}"))?;
    let bundle_bytes = std::fs::read(bundle_path)
        .with_context(|| format!("reading cosign bundle at {bundle_path}"))?;

    let expected_identity = format!(
        "https://github.com/tinylabscom/mvm/.github/workflows/release.yml@refs/tags/v{version}"
    );
    let expected_issuer = "https://token.actions.githubusercontent.com";

    let manifest = if std::env::var_os("MVM_SKIP_COSIGN_VERIFY").is_some() {
        ui::warn(
            "MVM_SKIP_COSIGN_VERIFY set — accepting unverified manifest. \
             This is an emergency-rotation escape only.",
        );
        image_verify::parse_manifest(&manifest_bytes)
            .map_err(|e| anyhow::anyhow!("manifest parse failed: {e}"))?
    } else {
        image_verify::verify_manifest(
            &manifest_bytes,
            &bundle_bytes,
            &expected_identity,
            expected_issuer,
        )
        .map_err(|e| {
            bump_verify_outcome("sig_invalid");
            anyhow::anyhow!(
                "Cosign verification failed for the imported manifest: {e}\n\
                 \n\
                 Plan 36 / ADR 005: a sideloaded manifest must carry the\n\
                 same release-workflow OIDC signature as the network path.\n\
                 \n\
                 Common causes:\n\
                 - mismatched manifest + bundle pair (re-export both as a set);\n\
                 - manifest belongs to a different mvmctl version (check `mvmctl --version`);\n\
                 - clock skew (signature time-window).\n\
                 \n\
                 Emergency rotation: MVM_SKIP_COSIGN_VERIFY=1 keeps SHA-256\n\
                 verification active while bypassing the signature step."
            )
        })?
    };

    image_verify::check_version_pin(&manifest, version).map_err(|e| {
        bump_verify_outcome("version_skew");
        anyhow::anyhow!(
            "Imported manifest is for a different mvmctl version: {e}\n\
             \n\
             Plan 36 pins manifest.version == mvmctl version exactly. Re-export\n\
             the manifest from a release matching v{version}, or upgrade mvmctl."
        )
    })?;

    let now = chrono::Utc::now();
    if let Err(e) = image_verify::check_not_after(&manifest, now) {
        bump_verify_outcome("expired");
        ui::warn(&format!(
            "Imported manifest is past its max-age ({e}). Sideloaded images \
             from older releases remain cryptographically valid but may \
             carry unpatched vulnerabilities."
        ));
    }

    if let Some(revocations) = try_fetch_revocation_list()? {
        image_verify::check_revocation(&manifest, &revocations).map_err(|e| {
            bump_verify_outcome("revoked");
            anyhow::anyhow!(
                "Imported manifest is on the project's revocation list: {e}\n\
                 \n\
                 Plan 36: a `revocations` release entry has marked v{version} \
                 unsafe to run. Refusing to import."
            )
        })?;
    }

    if manifest.arch != arch {
        anyhow::bail!(
            "Manifest is for arch {} but this host is {arch}. Wrong-arch image \
             would not boot. Re-export the manifest for the correct arch.",
            manifest.arch
        );
    }

    let kernel_name = format!("dev-vmlinux-{arch}");
    let rootfs_name = format!("dev-rootfs-{arch}.{}", manifest.rootfs_format);

    let kernel_digest = manifest
        .artifact(&kernel_name)
        .ok_or_else(|| anyhow::anyhow!("manifest does not list {kernel_name}"))?;
    let rootfs_digest = manifest
        .artifact(&rootfs_name)
        .ok_or_else(|| anyhow::anyhow!("manifest does not list {rootfs_name}"))?;

    image_verify::verify_artifact(std::path::Path::new(vmlinux_path), kernel_digest).map_err(
        |e| {
            bump_verify_outcome("digest_mismatch");
            anyhow::anyhow!("kernel SHA-256 mismatch: {e}")
        },
    )?;
    image_verify::verify_artifact(std::path::Path::new(rootfs_path), rootfs_digest).map_err(
        |e| {
            bump_verify_outcome("digest_mismatch");
            anyhow::anyhow!("rootfs SHA-256 mismatch: {e}")
        },
    )?;

    // Copy the verified artifacts into the version-namespaced cache.
    // The next `mvmctl dev up` picks them up without re-running
    // verification (the cache hit precedes download_dev_image).
    let prebuilt_dir = format!(
        "{}/dev/prebuilt/v{version}",
        mvm_core::config::mvm_data_dir()
    );
    std::fs::create_dir_all(&prebuilt_dir)
        .with_context(|| format!("creating prebuilt dir {prebuilt_dir}"))?;
    let target_kernel = format!("{prebuilt_dir}/vmlinux");
    let target_rootfs = format!("{prebuilt_dir}/rootfs.ext4");
    std::fs::copy(vmlinux_path, &target_kernel)
        .with_context(|| format!("copying kernel to {target_kernel}"))?;
    std::fs::copy(rootfs_path, &target_rootfs)
        .with_context(|| format!("copying rootfs to {target_rootfs}"))?;

    mvm_core::observability::metrics::global()
        .dev_image_verify_ok
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

    ui::success(&format!(
        "Imported and verified dev image v{version} into {prebuilt_dir}. \
         Run `mvmctl dev up` to boot the dev VM from the cached artifacts."
    ));
    Ok(())
}

/// Locate the builder-VM flake at `nix/images/builder-vm/flake.nix`.
///
/// The consolidated flake produces both the headless builder VM
/// (`packages.<sys>.default`) and the interactive
/// dev-shell image (`packages.<sys>.dev`). Used by `ensure_dev_image`
/// to detect a source checkout, and by `bootstrap_builder_vm_image`
/// to locate Layer 1. Returns `Err` when not in a source checkout,
/// signalling the caller to fall back to the published prebuilt.
fn find_builder_vm_flake() -> Result<String> {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let workspace_root = std::path::Path::new(manifest_dir)
        .parent()
        .and_then(|p| p.parent())
        .ok_or_else(|| anyhow::anyhow!("Cannot find workspace root"))?;

    let candidate = workspace_root.join("nix").join("images").join("builder-vm");
    if candidate.join("flake.nix").exists() {
        return Ok(candidate.to_str().unwrap_or(".").to_string());
    }

    anyhow::bail!("Builder VM flake not found. Expected at nix/images/builder-vm/flake.nix.")
}

/// Ensure `~/.cache/mvm/builder-vm/<arch>/` contains `vmlinux` +
/// `rootfs.ext4` before launching the libkrun builder.
///
/// `LibkrunBuilderVm::run_build` reads from this cache; this
/// function is what fills it. The two-layer artifact rule in action:
///
/// - Layer 1 (this function): ensure the **builder VM image** is
///   available in the local cache.
/// - Layer 2: use the Layer 1 image plus libkrun to build the
///   **dev shell image** with the large rustc closure.
///
/// Acquisition policy:
///
/// - Source checkout: a cache hit is allowed, but a cache miss fails
///   closed. The builder VM image must come from the in-repo
///   `nix/images/builder-vm/flake.nix` path; downloading a published
///   artifact would hide local builder-image changes.
/// - Installed binary: a cache hit is allowed; a cache miss may fetch
///   the published artifact for the running release version.
///
/// `allow(dead_code)`: same justification as
/// [`find_builder_vm_flake`] — only called when
/// `builder-vm` is on.
#[allow(dead_code)]
pub(in crate::commands) fn bootstrap_builder_vm_image() -> Result<()> {
    let arch = builder_vm_host_arch();
    let out_dir = format!("{}/builder-vm/{arch}", mvm_core::config::mvm_cache_dir());
    let out_dir_path = std::path::Path::new(&out_dir);
    let builder_flake = find_builder_vm_flake();
    let source_fingerprint = builder_flake
        .as_ref()
        .ok()
        .map(|flake_dir| builder_vm_source_fingerprint(flake_dir))
        .transpose()?;
    let cache_ready = match source_fingerprint.as_deref() {
        Some(fingerprint) => {
            let status = builder_vm_source_cache_status(out_dir_path, fingerprint);
            ui::progress(&format!(
                "Builder VM source cache decision: {}",
                status.reason_code()
            ));
            status.is_ready()
        }
        None => validate_builder_vm_stage0_artifacts(out_dir_path).is_ok(),
    };

    match resolve_builder_vm_bootstrap_action(builder_flake, cache_ready)? {
        BuilderVmBootstrapAction::UseCached => {
            ui::info(&format!("Builder VM image already cached at {out_dir}."));
            Ok(())
        }
        BuilderVmBootstrapAction::BuildFromSource { flake_dir } => {
            #[cfg(feature = "builder-vm")]
            let source_fingerprint = source_fingerprint.ok_or_else(|| {
                anyhow::anyhow!("builder VM source fingerprint was not computed for {flake_dir}")
            })?;
            ui::info(&format!(
                "Builder VM image not in cache; building locally from {flake_dir}..."
            ));

            // The nix-seed root-dir Stage 0 is the only bootstrap
            // path. The dev-image Stage 0 path
            // (bootstrap_builder_vm_image_via_dev_image_stage0) has been
            // removed; `nix/images/builder/flake.nix` is deleted.
            #[cfg(feature = "builder-vm")]
            {
                bootstrap_builder_vm_image_via_root_dir_stage0(
                    &flake_dir,
                    &out_dir,
                    &source_fingerprint,
                )
                .context("building the source-checkout builder VM image via root-dir Stage 0")
            }

            #[cfg(not(feature = "builder-vm"))]
            {
                let _ = (&flake_dir, &out_dir, &source_fingerprint, arch);
                anyhow::bail!(
                    "Stage 0 needs the `builder-vm` cargo feature to be enabled \
                     for this `mvmctl` build."
                )
            }
        }
        BuilderVmBootstrapAction::DownloadPublished => {
            perform_builder_vm_download_published(arch, &out_dir)
        }
    }
}

fn builder_vm_host_arch() -> &'static str {
    if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else {
        "x86_64"
    }
}

/// The only call site that can invoke the published-prebuilt
/// download path. Gated behind `release-artifact-bootstrap`. Contributor
/// builds (the default) hit the `cfg(not(...))` arm and bail structurally
/// — even if the resolver routed here, the function refuses to touch the
/// network. End-user-binary release builds opt in at compile time.
///
/// Extracted from [`bootstrap_builder_vm_image`] specifically so the
/// fail-closed shape is unit-testable.
fn perform_builder_vm_download_published(arch: &str, out_dir: &str) -> Result<()> {
    #[cfg(feature = "release-artifact-bootstrap")]
    {
        ui::info(&format!(
            "Builder VM image not in cache; downloading published prebuilt for v{}...",
            env!("CARGO_PKG_VERSION")
        ));
        std::fs::create_dir_all(out_dir)
            .with_context(|| format!("creating builder-vm cache dir {out_dir}"))?;
        download_builder_vm_image(arch, out_dir).context("downloading the builder VM image")
    }
    #[cfg(not(feature = "release-artifact-bootstrap"))]
    {
        let _ = (arch, out_dir);
        anyhow::bail!(
            "Builder VM image is missing and no in-repo builder VM flake \
             was found. This `mvmctl` binary was built without the \
             `release-artifact-bootstrap` feature, so it cannot pull a \
             published prebuilt from GitHub releases (per Plan 77 W4 and \
             the AGENTS.md / CLAUDE.md invariant). \
             Run from a source checkout that has \
             `nix/images/builder-vm/flake.nix`, or rebuild `mvmctl` with \
             `--features release-artifact-bootstrap` (release-cut binaries only)."
        );
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
enum BuilderVmBootstrapAction {
    UseCached,
    BuildFromSource { flake_dir: String },
    DownloadPublished,
}

fn resolve_builder_vm_bootstrap_action(
    builder_flake: Result<String>,
    cache_ready: bool,
) -> Result<BuilderVmBootstrapAction> {
    if cache_ready {
        return Ok(BuilderVmBootstrapAction::UseCached);
    }

    match builder_flake {
        Ok(flake_dir) => Ok(BuilderVmBootstrapAction::BuildFromSource { flake_dir }),
        Err(_) => Ok(BuilderVmBootstrapAction::DownloadPublished),
    }
}

/// Stage 0 bootstrap via libkrun's `krun_set_root` mode — extract the
/// official Nix release tarball's `/nix/store` (hash-pinned) into
/// a host directory, layer the embedded `stage0-init` PID 1 on as `/init`,
/// and hand the directory to libkrun. libkrun mounts it as the guest root
/// via virtiofs against libkrunfw's bundled TSI-patched kernel. `stage0-init`
/// builds the in-repo `nix/images/builder-vm` flake against `/work` and
/// writes the steady-state artifacts (`vmlinux`, `rootfs.ext4`,
/// `cmdline.txt`) to `/out`, then powers off. One userland — busybox; no
/// Alpine, no apk, no pgp.
///
/// Replaces the previous initramfs-cpio dispatch shape: libkrunfw's
/// kernel ships with `CONFIG_BLK_DEV_INITRD=n`, so cpio initramfs
/// cannot unpack. `set_root` mode is libkrun's intended container
/// boot path and uses the same kernel without modification.
#[cfg(feature = "builder-vm")]
fn bootstrap_builder_vm_image_via_root_dir_stage0(
    builder_flake_dir: &str,
    out_dir: &str,
    source_fingerprint: &str,
) -> Result<()> {
    let _stage0_guard = acquire_stage0_lock(out_dir)?;

    // Time each host-visible Stage 0 step and print a one-line
    // `[mvm] <step> … <secs>s` so perceived speed matches the actual
    // per-step wall-clock.
    // The seed is the official Nix release tarball + the embedded
    // `stage0-init` PID 1 — one userland (busybox), no Alpine/apk/pgp.
    let fetch_started = std::time::Instant::now();
    let stage0_assets = mvm_build::stage0::assets_for_host_arch();
    let vendor_reports = mvm_build::stage0::prepare_assets(stage0_assets)
        .context("preparing Stage 0 bootstrap assets")?;
    ui::timed_step("Fetching Stage 0 bootstrap assets", fetch_started.elapsed());
    // One VendorBlobFetched audit entry per vendored blob (covers both
    // fresh fetch and cache revalidation), so every supply-chain trust
    // decision in the no-prebuilt-download path is auditable. The emit
    // lives here (the host caller) so `mvm-build` stays audit-free.
    for report in &vendor_reports {
        mvm_core::policy::audit::emit(
            mvm_core::policy::audit::LocalAuditKind::VendorBlobFetched,
            None,
            Some(&report.audit_detail()),
        );
    }

    // Materialize the guest root tree under a stable per-host location.
    // libkrun mounts this directory as the guest root via virtiofs.
    let root_dir = mvm_build::stage0::stage0_cache_dir().join("root");
    if root_dir.exists() {
        std::fs::remove_dir_all(&root_dir).with_context(|| {
            format!("clearing previous Stage 0 root dir {}", root_dir.display())
        })?;
    }
    let materialize_started = std::time::Instant::now();
    // The seed's PID 1 is the embedded `stage0-init` binary. Pull its bytes
    // from the embed table (refuse a zero-byte stub build).
    let stage0_init = crate::host_binaries::embedded::EMBEDDED
        .iter()
        .find(|b| b.name == "stage0-init")
        .ok_or_else(|| anyhow::anyhow!("stage0-init not in the embedded host binaries"))?;
    if stage0_init.bytes.is_empty() {
        anyhow::bail!(
            "embedded stage0-init is a zero-byte stub — this mvmctl was built with \
             MVM_SKIP_EMBED_BINARIES=1 and cannot seed Stage 0; rebuild without it"
        );
    }
    mvm_build::stage0::materialize_root_dir(&root_dir, stage0_init.bytes)
        .with_context(|| format!("materializing Stage 0 root at {}", root_dir.display()))?;
    ui::timed_step(
        "Materializing Stage 0 root dir",
        materialize_started.elapsed(),
    );

    // Workspace root = three dirs above the flake.nix
    // (nix/images/builder-vm/flake.nix → repo root).
    let workspace_root = std::path::Path::new(builder_flake_dir)
        .parent()
        .and_then(|p| p.parent())
        .and_then(|p| p.parent())
        .ok_or_else(|| anyhow::anyhow!("Cannot derive workspace root from {builder_flake_dir}"))?
        .to_path_buf();

    let out_dir_path = std::path::Path::new(out_dir);
    let staging_dir = unique_builder_vm_stage0_staging_dir(out_dir_path)?;
    std::fs::create_dir_all(&staging_dir)
        .with_context(|| format!("creating Stage 0 staging dir {}", staging_dir.display()))?;

    let started = std::time::Instant::now();
    let fingerprint_prefix = stage0_fingerprint_prefix(source_fingerprint);
    mvm_core::audit_emit!(
        Stage0Boot,
        "seed=root-dir fingerprint_prefix={fingerprint_prefix} flavor={flavor}",
        flavor = STAGE0_FLAVOR_CURRENT,
    );

    // Extract the embedded host-vm binaries so the Stage 0 nix build
    // can install them from /mvm-bins instead of building them with
    // the guest's nix. Same cache dir the steady-state job path uses.
    let host_bins_cache = format!("{}/host-bins", mvm_core::config::mvm_cache_dir());
    let host_bin_dir = crate::host_binaries::extract::ensure_extracted_for_boot(
        std::path::Path::new(&host_bins_cache),
    )
    .map_err(|e| anyhow::anyhow!("extract embedded host-vm binaries: {e}"))?;

    // Kernel acquisition override (MVM_KERNEL_SOURCE / --kernel-source).
    // `download` (and `auto` when a publish exists) boots the builder VM
    // on a published, hash-verified kernel — build only the rootfs and
    // pair the kernel in, skipping the in-image kernel compile. Unset or
    // `compile` → the normal `default` build (kernel compiled in-image;
    // also the cheaper single-boot path, so `dev up --kernel-source
    // compile` deliberately stays on it).
    let external_kernel: Option<std::path::PathBuf> = match resolve_kernel_source() {
        Some(KernelSource::Download) => {
            ui::info("Kernel source: download — fetching the published builder kernel.");
            Some(download_builder_kernel(builder_vm_host_arch())?)
        }
        Some(KernelSource::Auto) => match download_builder_kernel(builder_vm_host_arch()) {
            Ok(p) => {
                ui::info("Kernel source: auto — using the published builder kernel.");
                Some(p)
            }
            Err(e) => {
                ui::warn(&format!(
                    "no published builder kernel ({e}); compiling it in-image"
                ));
                None
            }
        },
        Some(KernelSource::Compile) | None => None,
    };

    let result = if let Some(kernel) = &external_kernel {
        run_stage0_rootfs_with_external_kernel(
            &staging_dir,
            &workspace_root,
            &root_dir,
            &host_bin_dir,
            kernel,
            source_fingerprint,
        )
    } else {
        run_stage0_root_dir(
            &staging_dir,
            &workspace_root,
            &root_dir,
            "/init",
            &host_bin_dir,
            source_fingerprint,
        )
    };
    let duration_ms = started.elapsed().as_millis() as u64;

    match result {
        Ok(()) => {
            promote_builder_vm_stage0_cache(&staging_dir, out_dir_path, source_fingerprint)
                .context("promoting Stage 0 artifacts into the builder VM cache")?;
            mvm_core::audit_emit!(
                Stage0CachePromoted,
                "cache={cache} fingerprint_prefix={fingerprint_prefix} duration_ms={duration_ms} flavor={flavor}",
                cache = out_dir_path.display(),
                flavor = STAGE0_FLAVOR_CURRENT,
            );
            Ok(())
        }
        Err((stage, e)) => {
            let _ = std::fs::remove_dir_all(&staging_dir);
            let reason = stage0_failure_reason_summary(&e);
            mvm_core::audit_emit!(
                Stage0Failed,
                "stage={stage} duration_ms={duration_ms} reason={reason}"
            );
            Err(e)
        }
    }
}

/// Which custom kernel `mvmctl kernel build` realizes. Each maps to a
/// flake attr on `nix/images/builder-vm` and a cache subdir.
#[cfg(feature = "builder-vm")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KernelVariant {
    /// Builder-VM kernel — shared base + virtio-fs / overlay / netfilter
    /// / nix-sandbox infra (`nix/images/builder-vm/kernel`).
    Builder,
    /// Workload-microVM kernel — the shared base alone (`workload-kernel`).
    Workload,
}

#[cfg(feature = "builder-vm")]
impl KernelVariant {
    /// Flake attr under `packages.<arch>-linux`.
    fn attr(self) -> &'static str {
        match self {
            Self::Builder => "builder-kernel",
            Self::Workload => "workload-kernel",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Builder => "builder",
            Self::Workload => "workload",
        }
    }
}

/// Where the builder VM's kernel comes from when bootstrapping its
/// image, from `MVM_KERNEL_SOURCE` (set by the global `--kernel-source`
/// flag). `download` boots the builder VM on a published, hash-verified
/// kernel — building only the rootfs locally and pairing the kernel in,
/// so a fresh `dev up` skips the multi-minute kernel compile. Unset →
/// the default `nix build default` path (kernel compiled in-image).
#[cfg(feature = "builder-vm")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KernelSource {
    Compile,
    Download,
    Auto,
}

#[cfg(feature = "builder-vm")]
fn resolve_kernel_source() -> Option<KernelSource> {
    let raw = std::env::var("MVM_KERNEL_SOURCE").ok()?;
    match raw.trim().to_ascii_lowercase().as_str() {
        "" => None,
        "compile" => Some(KernelSource::Compile),
        "download" => Some(KernelSource::Download),
        "auto" => Some(KernelSource::Auto),
        other => {
            ui::warn(&format!(
                "ignoring unrecognised MVM_KERNEL_SOURCE={other:?} \
                 (expected compile|download|auto)"
            ));
            None
        }
    }
}

/// Download + SHA-256-verify the published *builder* kernel for `arch`
/// into the per-arch kernel cache, returning its path.
#[cfg(feature = "builder-vm")]
fn download_builder_kernel(arch: &str) -> Result<std::path::PathBuf> {
    let dest = std::path::Path::new(&mvm_core::config::mvm_cache_dir())
        .join("builder-vm")
        .join(arch)
        .join("kernels")
        .join("builder")
        .join("vmlinux");
    crate::update::download_kernel(arch, "builder", &dest)?;
    Ok(dest)
}

/// Boot Stage 0 to build the builder rootfs *only* (`stage0-rootfs`
/// attr, kernel-less), then pair `external_kernel` as the image's
/// `vmlinux` and write the cache sidecars. This is the
/// `--kernel-source download` path: the builder VM boots on a published
/// kernel without compiling one inside the `default` image.
#[cfg(feature = "builder-vm")]
fn run_stage0_rootfs_with_external_kernel(
    staging_dir: &std::path::Path,
    workspace_root: &std::path::Path,
    guest_root_dir: &std::path::Path,
    host_bin_dir: &std::path::Path,
    external_kernel: &std::path::Path,
    source_fingerprint: &str,
) -> std::result::Result<(), (Stage0FailureStage, anyhow::Error)> {
    use mvm_build::builder_backend_select::resolve_stage0_backend;

    // Build only the rootfs (`stage0-rootfs`, no kernel in $out).
    std::fs::write(
        staging_dir.join("stage0-build.conf"),
        "MVM_STAGE0_BUILD_ATTR=stage0-rootfs\nMVM_STAGE0_OUTPUT_MODE=rootfs\n",
    )
    .map_err(|e| {
        (
            Stage0FailureStage::Build,
            anyhow::anyhow!("writing stage0-build.conf: {e}"),
        )
    })?;

    let backend = resolve_stage0_backend(false);
    backend
        .run_stage0(
            guest_root_dir,
            "/init",
            workspace_root,
            staging_dir,
            host_bin_dir,
        )
        .map_err(|e| {
            (
                Stage0FailureStage::Build,
                anyhow::anyhow!("Stage 0 rootfs build: {e}"),
            )
        })?;

    // Pair the externally-acquired kernel as the image's vmlinux. The
    // published builder kernel is the same flake derivation `default`
    // bundles, so the paired image is equivalent.
    std::fs::copy(external_kernel, staging_dir.join("vmlinux")).map_err(|e| {
        (
            Stage0FailureStage::Build,
            anyhow::anyhow!("pairing kernel {}: {e}", external_kernel.display()),
        )
    })?;

    verify_stage0_rootfs_has_init(&staging_dir.join("rootfs.ext4"))
        .map_err(|e| (Stage0FailureStage::Validate, e))?;
    write_builder_vm_cache_sidecars(staging_dir, source_fingerprint)
        .map_err(|e| (Stage0FailureStage::Validate, e))?;
    Ok(())
}

/// Render the compile heartbeat line. Pure (testable); the live
/// heartbeat thread routes it through `ui::info`.
#[cfg(feature = "builder-vm")]
fn format_compile_elapsed(elapsed: std::time::Duration) -> String {
    let secs = elapsed.as_secs();
    format!("still compiling… ({}m{:02}s elapsed)", secs / 60, secs % 60)
}

/// `mvmctl kernel build --source compile`: compile a single kernel attr
/// through the Stage 0 nix-seed bootstrap and land its `vmlinux` in the
/// per-arch builder-VM cache. Returns the cached kernel path.
///
/// Reuses the exact Stage 0 boot path `mvmctl dev up` uses, but writes a
/// `/out/stage0-build.conf` pointing `stage0-init` at the kernel attr in
/// kernel-only output mode (no rootfs). The persistent
/// `nix-store-stage0` image is shared — and locked — with the full
/// image build, so a freshly compiled kernel is *substituted*, not
/// rebuilt, by the next `dev up`.
///
/// Host-arch only: Stage 0 boots a host-arch VM under libkrun and can't
/// cross-compile. Cross-arch kernels come from the download arm (the
/// kernel-build GHA publishes both arches).
#[cfg(feature = "builder-vm")]
pub(crate) fn build_kernel_via_stage0(
    variant: KernelVariant,
    verbose: bool,
) -> Result<std::path::PathBuf> {
    let builder_flake_dir = find_builder_vm_flake().map_err(|_| {
        anyhow::anyhow!(
            "`mvmctl kernel build --source compile` needs a source checkout of mvm \
             (nix/images/builder-vm/flake.nix). From an installed binary, fetch a \
             published kernel with `--source download` instead."
        )
    })?;

    let arch = builder_vm_host_arch();
    // Per-arch, per-variant kernel cache, distinct from the image's
    // `builder-vm/<arch>/vmlinux` so the two never clobber each other.
    let out_dir = format!(
        "{}/builder-vm/{arch}/kernels/{}",
        mvm_core::config::mvm_cache_dir(),
        variant.label()
    );
    let out_dir_path = std::path::Path::new(&out_dir);
    std::fs::create_dir_all(out_dir_path)
        .with_context(|| format!("creating kernel cache dir {out_dir}"))?;

    // Shares the Stage 0 output lock with `dev up`; the deeper
    // nix-store-stage0 image lock (taken inside `run_stage0`) is the
    // real mutual exclusion against a concurrent image build.
    let _stage0_guard = acquire_stage0_lock(&out_dir)?;

    let stage0_assets = mvm_build::stage0::assets_for_host_arch();
    let vendor_reports = mvm_build::stage0::prepare_assets(stage0_assets)
        .context("preparing Stage 0 bootstrap assets (nix-tarball seed)")?;
    for report in &vendor_reports {
        mvm_core::policy::audit::emit(
            mvm_core::policy::audit::LocalAuditKind::VendorBlobFetched,
            None,
            Some(&report.audit_detail()),
        );
    }

    let root_dir = mvm_build::stage0::stage0_cache_dir().join("root");
    if root_dir.exists() {
        std::fs::remove_dir_all(&root_dir)
            .with_context(|| format!("clearing Stage 0 root dir {}", root_dir.display()))?;
    }
    // The seed's PID 1 is the embedded `stage0-init` binary (refuse a
    // zero-byte stub build that can't seed Stage 0).
    let stage0_init = crate::host_binaries::embedded::EMBEDDED
        .iter()
        .find(|b| b.name == "stage0-init")
        .ok_or_else(|| anyhow::anyhow!("stage0-init not in the embedded host binaries"))?;
    if stage0_init.bytes.is_empty() {
        anyhow::bail!(
            "embedded stage0-init is a zero-byte stub — this mvmctl was built with \
             MVM_SKIP_EMBED_BINARIES=1 and cannot seed Stage 0; rebuild without it"
        );
    }
    mvm_build::stage0::materialize_root_dir(&root_dir, stage0_init.bytes)
        .with_context(|| format!("materializing Stage 0 root at {}", root_dir.display()))?;

    // Workspace root = three dirs above the flake.nix
    // (nix/images/builder-vm/flake.nix → repo root).
    let workspace_root = std::path::Path::new(&builder_flake_dir)
        .parent()
        .and_then(|p| p.parent())
        .and_then(|p| p.parent())
        .ok_or_else(|| anyhow::anyhow!("cannot derive workspace root from {builder_flake_dir}"))?
        .to_path_buf();

    let staging_dir = unique_builder_vm_stage0_staging_dir(out_dir_path)?;
    std::fs::create_dir_all(&staging_dir)
        .with_context(|| format!("creating Stage 0 staging dir {}", staging_dir.display()))?;

    // Point stage0-init at the kernel attr + kernel-only output. Absent this
    // file (the `dev up` path), stage0-init builds the full image.
    let conf = format!(
        "MVM_STAGE0_BUILD_ATTR={}\nMVM_STAGE0_OUTPUT_MODE=kernel\n",
        variant.attr()
    );
    std::fs::write(staging_dir.join("stage0-build.conf"), conf)
        .with_context(|| format!("writing stage0-build.conf in {}", staging_dir.display()))?;

    // The Stage 0 nix build installs the embedded host-vm binaries
    // from /mvm-bins rather than building them in-guest.
    let host_bins_cache = format!("{}/host-bins", mvm_core::config::mvm_cache_dir());
    let host_bin_dir = crate::host_binaries::extract::ensure_extracted_for_boot(
        std::path::Path::new(&host_bins_cache),
    )
    .map_err(|e| anyhow::anyhow!("extract embedded host-vm binaries: {e}"))?;

    ui::info(&format!(
        "Compiling {} kernel ({arch}) via Stage 0 — first build is slow \
         (3-10 min); later runs hit the nix store cache.",
        variant.label()
    ));

    {
        use mvm_build::builder_backend_select::resolve_stage0_backend;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        // Host-side heartbeat so a quiet (non-verbose) compile is never
        // dead-silent. In verbose mode the streamed console output is
        // the liveness signal, so the heartbeat stays off.
        let stop = Arc::new(AtomicBool::new(false));
        let heartbeat = if verbose {
            None
        } else {
            let stop = Arc::clone(&stop);
            Some(std::thread::spawn(move || {
                let start = std::time::Instant::now();
                // Poll the stop flag every 500ms but only print every ~20s.
                let mut ticks: u64 = 0;
                while !stop.load(Ordering::Relaxed) {
                    std::thread::sleep(std::time::Duration::from_millis(500));
                    ticks += 1;
                    if ticks.is_multiple_of(40) {
                        ui::info(&format_compile_elapsed(start.elapsed()));
                    }
                }
            }))
        };

        let backend = resolve_stage0_backend(verbose);
        let result = backend.run_stage0(
            &root_dir,
            "/init",
            &workspace_root,
            &staging_dir,
            &host_bin_dir,
        );

        stop.store(true, Ordering::Relaxed);
        if let Some(handle) = heartbeat {
            let _ = handle.join();
        }

        result.map_err(|e| anyhow::anyhow!("Stage 0 kernel build: {e}"))?;
    }

    let built = staging_dir.join("vmlinux");
    if !built.is_file() {
        let _ = std::fs::remove_dir_all(&staging_dir);
        anyhow::bail!(
            "Stage 0 produced no kernel at {} (attr {})",
            built.display(),
            variant.attr()
        );
    }
    let dest = out_dir_path.join("vmlinux");
    std::fs::copy(&built, &dest)
        .with_context(|| format!("copying kernel to {}", dest.display()))?;
    let _ = std::fs::remove_dir_all(&staging_dir);

    Ok(dest)
}

/// Boot the Stage 0 VM with the supplied `RootDir` image, mounting
/// `workspace_root` as `/work` and `staging_dir` as `/out`. On
/// clean exit, write the cache-validation sidecars next to the
/// emitted artifacts so the outer caller can promote them into the
/// per-arch builder VM cache.
#[cfg(feature = "builder-vm")]
fn run_stage0_root_dir(
    staging_dir: &std::path::Path,
    workspace_root: &std::path::Path,
    guest_root_dir: &std::path::Path,
    entry_path: &str,
    host_bin_dir: &std::path::Path,
    source_fingerprint: &str,
) -> std::result::Result<(), (Stage0FailureStage, anyhow::Error)> {
    use mvm_build::builder_backend_select::resolve_stage0_backend;

    // Dispatch Stage 0 through the `BuilderVm` trait.
    // `resolve_stage0_backend` uses QEMU when explicitly chosen
    // (`MVM_BUILDER_BACKEND=qemu`) and **libkrun otherwise** — including the
    // Vz auto-detect default on macOS-26+, since Vz Stage 0 is still a gap.
    // That preserves the "Stage 0 is libkrun even on Vz-default hosts"
    // invariant while adding QEMU as the second implemented backend.
    let backend = resolve_stage0_backend(false);
    backend
        .run_stage0(
            guest_root_dir,
            entry_path,
            workspace_root,
            staging_dir,
            host_bin_dir,
        )
        .map_err(|e| {
            (
                Stage0FailureStage::Build,
                anyhow::anyhow!("Stage 0 root-dir build: {e}"),
            )
        })?;

    // Refuse to promote a rootfs the steady-state VM can't boot: walk the
    // freshly-built ext4 and confirm the `init=` target is present.
    verify_stage0_rootfs_has_init(&staging_dir.join("rootfs.ext4"))
        .map_err(|e| (Stage0FailureStage::Validate, e))?;

    write_builder_vm_cache_sidecars(staging_dir, source_fingerprint)
        .map_err(|e| (Stage0FailureStage::Validate, e))?;

    Ok(())
}

/// Which Stage 0 bootstrap variant this build runs.
///
/// The `flavor=` field on `Stage0Boot` / `Stage0CachePromoted` audit
/// detail strings carries this value so a future per-variant identifier
/// (e.g. an experimental seed image alongside the nix-tarball seed) only
/// needs to flip this single constant — not every emit site. Today
/// there is one variant, so the value is the literal `"current"`.
#[cfg(feature = "builder-vm")]
const STAGE0_FLAVOR_CURRENT: &str = "current";

/// Which phase of Stage 0 failed. Each variant maps to a
/// `stage=...` value in the `Stage0Failed` audit detail so a dashboard
/// can break down "Stage 0 reliability" by failure phase. String
/// representations are stable wire format.
#[cfg(feature = "builder-vm")]
#[derive(Debug, Clone, Copy)]
enum Stage0FailureStage {
    Build,
    Validate,
}

#[cfg(feature = "builder-vm")]
impl Stage0FailureStage {
    fn as_str(self) -> &'static str {
        match self {
            Self::Build => "build",
            Self::Validate => "validate",
        }
    }
}

#[cfg(feature = "builder-vm")]
impl std::fmt::Display for Stage0FailureStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Extract libkrunfw's bundled TSI-patched kernel into the host cache
/// and return the on-disk path. Only available when `libkrun-sys` is
/// compiled in (the default on macOS + Linux libkrun hosts) — without
/// that feature the FFI is dead code and the caller falls back.
///
/// Currently unused on the main path; reserved for wiring the
/// initramfs Stage 0 dispatch (the initramfs path needs a kernel and
/// libkrunfw is where we get it).
#[cfg(all(feature = "builder-vm", feature = "libkrun-sys"))]
#[allow(dead_code)]
fn extract_libkrunfw_kernel() -> Result<std::path::PathBuf> {
    let cache_dir =
        std::path::PathBuf::from(format!("{}/libkrunfw", mvm_core::config::mvm_cache_dir()));
    let target = cache_dir.join("vmlinux");
    let bundled = libkrun_sys::extract_bundled_kernel(&target)
        .map_err(|e| anyhow::anyhow!("libkrunfw kernel extraction: {e}"))?;
    ui::info(&format!(
        "Extracted libkrunfw kernel ({} bytes) to {}",
        bundled.size,
        bundled.path.display()
    ));
    Ok(bundled.path)
}

#[cfg(all(feature = "builder-vm", not(feature = "libkrun-sys")))]
#[allow(dead_code)]
fn extract_libkrunfw_kernel() -> Result<std::path::PathBuf> {
    anyhow::bail!(
        "libkrunfw kernel extraction requires the `libkrun-sys` feature; \
         rebuild `mvmctl` with `--features libkrun-sys` on a host with libkrun installed."
    )
}

/// Short prefix of the source fingerprint for audit
/// `fingerprint_prefix=` field. 8 hex chars are enough to disambiguate
/// against unrelated `dev up` runs without exposing the full digest.
#[cfg(feature = "builder-vm")]
fn stage0_fingerprint_prefix(source_fingerprint: &str) -> String {
    source_fingerprint.chars().take(8).collect::<String>()
}

/// Condense an `anyhow::Error` into the short single-line
/// `reason=` field for `Stage0Failed`. The full chain is on stderr
/// already; the audit field is for "what broke at a glance". Capped
/// at 160 chars and stripped of newlines / commas / spaces around
/// `=`-signs so the space-separated `key=value` detail format stays
/// parseable.
#[cfg(feature = "builder-vm")]
fn stage0_failure_reason_summary(err: &anyhow::Error) -> String {
    let raw = err.to_string();
    let cleaned: String = raw
        .chars()
        .map(|c| match c {
            '\n' | '\r' | '\t' => ' ',
            // Audit detail is space-separated `key=value` pairs; any
            // bare `=` in the reason text would confuse a downstream
            // parser, so map them to `~` (visibly distinct from `=`).
            '=' => '~',
            _ => c,
        })
        .collect();
    let truncated: String = cleaned.chars().take(160).collect();
    truncated
}

/// RAII advisory lock at
/// `~/.cache/mvm/builder-vm/stage0.lock` (one directory above the
/// per-arch cache). `try_acquire` is non-blocking, so a concurrent
/// invocation bails fast with a clear message instead of silently
/// queuing for minutes behind a libkrun-builder VM that's already
/// busy holding the shared `nix-store-<arch>.img` volume.
///
/// `out_dir` is the per-arch cache dir (e.g. `.../builder-vm/aarch64`);
/// the lock anchor is its sibling `stage0` (so `FileLock::try_acquire`
/// produces `stage0.lock`).
#[cfg(any(feature = "builder-vm", test))]
fn acquire_stage0_lock(out_dir: &str) -> Result<mvm_core::atomic_io::FileLock> {
    use mvm_core::atomic_io::FileLock;

    let parent = std::path::Path::new(out_dir)
        .parent()
        .ok_or_else(|| anyhow::anyhow!("builder VM cache path has no parent: {out_dir}"))?;
    std::fs::create_dir_all(parent)
        .with_context(|| format!("creating builder-vm cache parent {}", parent.display()))?;
    let lock_anchor = parent.join("stage0");

    match FileLock::try_acquire(&lock_anchor) {
        Ok(Some(guard)) => Ok(guard),
        Ok(None) => anyhow::bail!(
            "another `mvmctl dev up` (or any caller of Stage 0) is already bootstrapping the \
             builder VM image on this host (lock held at {}.lock). Wait for it to finish, or — \
             only if you are sure no other invocation is running, e.g. after a crash — delete the \
             lock file and retry.",
            lock_anchor.display()
        ),
        Err(e) => Err(e.context("acquiring Stage 0 advisory lock")),
    }
}

#[cfg(any(feature = "builder-vm", test))]
fn unique_builder_vm_stage0_staging_dir(final_dir: &std::path::Path) -> Result<std::path::PathBuf> {
    let parent = final_dir.parent().ok_or_else(|| {
        anyhow::anyhow!(
            "builder VM cache path has no parent: {}",
            final_dir.display()
        )
    })?;
    let name = final_dir
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "builder VM cache path has no UTF-8 basename: {}",
                final_dir.display()
            )
        })?;
    std::fs::create_dir_all(parent)
        .with_context(|| format!("creating builder-vm cache parent {}", parent.display()))?;
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    Ok(parent.join(format!(".{name}.stage0-{}-{nonce}", std::process::id())))
}

/// Structural validation of a cached `(vmlinux, rootfs.ext4)` pair —
/// size floor + ext4 superblock magic. Cheap and host-agnostic; used by
/// the cache-readiness and promotion paths. The deeper "does the rootfs
/// actually contain the init binary" check is `verify_stage0_rootfs_has_init`,
/// run once at build time (it needs to parse the full ext4 tree).
fn validate_builder_vm_stage0_artifacts(dir: &std::path::Path) -> Result<()> {
    validate_dev_image_artifacts(dir.join("vmlinux"), dir.join("rootfs.ext4")).with_context(|| {
        format!(
            "validating Stage 0 builder VM artifacts in {}",
            dir.display()
        )
    })
}

/// Outcome of [`sweep_orphaned_stage0_staging_dirs`]:
/// either the sweep ran (with counts) or the Stage 0 advisory lock was
/// already held so the sweep was skipped to avoid racing a live
/// bootstrap. The pruner uses the variant to decide what to print.
pub(in crate::commands) enum Stage0SweepOutcome {
    Swept { removed: u64, freed_bytes: u64 },
    SkippedLockHeld,
}

/// Remove staging directories from a crashed Stage 0
/// bootstrap. Only safe to run when no Stage 0 is currently in progress;
/// the function tries the same advisory lock the live bootstrap uses
/// and bails (returns `SkippedLockHeld`) on contention rather than
/// racing it. Called from `mvmctl cache prune` so the cleanup ships
/// with the existing "clean everything" verb.
///
/// "Orphan" means the staging dir was left behind by a crashed run;
/// successful Stage 0 runs `rename(2)` the staging dir into the live
/// cache, so any staging dir on disk is by definition orphaned. Format
/// matches [`unique_builder_vm_stage0_staging_dir`]
/// (`.<arch>.stage0-<pid>-<nonce>`); we also recognise the legacy
/// `<arch>-staging[-...]` shape from older builds on the same host.
pub(in crate::commands) fn sweep_orphaned_stage0_staging_dirs(
    dry_run: bool,
) -> Result<Stage0SweepOutcome> {
    let builder_vm_root =
        std::path::PathBuf::from(mvm_core::config::mvm_cache_dir()).join("builder-vm");
    sweep_orphaned_stage0_staging_dirs_at(&builder_vm_root, dry_run)
}

/// Inner form of [`sweep_orphaned_stage0_staging_dirs`] that takes an
/// explicit root path. Exists so unit tests can exercise the sweep
/// against a tempdir without mutating `MVM_CACHE_DIR` or any other
/// process-wide env var.
fn sweep_orphaned_stage0_staging_dirs_at(
    builder_vm_root: &std::path::Path,
    dry_run: bool,
) -> Result<Stage0SweepOutcome> {
    use mvm_core::atomic_io::FileLock;

    if !builder_vm_root.is_dir() {
        return Ok(Stage0SweepOutcome::Swept {
            removed: 0,
            freed_bytes: 0,
        });
    }

    // Try the Stage 0 advisory lock. The lock anchor is shared with the
    // live `acquire_stage0_lock` callsite — when a `dev up` is in
    // progress, we want the pruner to skip the staging sweep rather
    // than race it. RAII drop releases the lock when this function
    // returns.
    let lock_anchor = builder_vm_root.join("stage0");
    let _guard = match FileLock::try_acquire(&lock_anchor) {
        Ok(Some(guard)) => guard,
        Ok(None) => return Ok(Stage0SweepOutcome::SkippedLockHeld),
        Err(e) => {
            // I/O failure on the lock path is rare (e.g. parent disappeared
            // mid-prune). Treat it as "skip with a warning" rather than
            // failing the whole prune verb — the staging sweep is a best-
            // effort hygiene step.
            tracing::warn!(err = %e, "could not acquire Stage 0 lock for sweep; skipping");
            return Ok(Stage0SweepOutcome::SkippedLockHeld);
        }
    };

    let mut removed = 0u64;
    let mut freed_bytes = 0u64;
    let entries = match std::fs::read_dir(builder_vm_root) {
        Ok(e) => e,
        Err(_) => {
            return Ok(Stage0SweepOutcome::Swept {
                removed,
                freed_bytes,
            });
        }
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        if !is_orphan_stage0_staging_dir_name(&name) || !path.is_dir() {
            continue;
        }
        let size = stage0_dir_size_bytes(&path);
        if dry_run {
            println!(
                "Would remove orphan Stage 0 staging dir: {} ({} bytes)",
                path.display(),
                size,
            );
        } else if let Err(e) = std::fs::remove_dir_all(&path) {
            tracing::warn!(path = %path.display(), err = %e, "could not remove orphan staging dir");
            continue;
        }
        removed += 1;
        freed_bytes += size;
    }
    Ok(Stage0SweepOutcome::Swept {
        removed,
        freed_bytes,
    })
}

/// Outcome of [`reap_orphaned_vm_helpers`]. Counts
/// orphaned helper PIDs that were signalled and per-VM cache dirs
/// removed, plus the bytes freed by removing those dirs. Pruner-side
/// caller uses this to print a clean one-line summary.
pub(in crate::commands) struct ReapOutcome {
    pub killed: u64,
    pub removed_dirs: u64,
    pub freed_bytes: u64,
}

/// Reap orphaned per-VM helpers left behind by killed
/// `mvmctl dev up` runs. Covers both backends: libkrun (`mvm-libkrun-
/// supervisor` + `gvproxy`) and Vz (`mvm-vz-supervisor`).
///
/// mvmctl spawns the active backend's supervisor binary, which in turn
/// spawns its networking helper (gvproxy for libkrun). If mvmctl exits
/// abnormally (^C, SIGKILL, crash), supervisor + helpers are reparented
/// to launchd PID 1 and outlive mvmctl indefinitely. This is the
/// "clean up after the fact" side, distinct from the prevention path.
///
/// The dir traversal below is **prefix-agnostic**: it iterates every
/// subdirectory of `~/.cache/mvm/builder-vm/vms/`, so both
/// `mvm-builder-vm-<job_id>` (libkrun) and `mvm-builder-vz-<job_id>`
/// (Vz) state dirs are picked up by the same loop, and the sidecar PID
/// names (`builder.pid` / `stage0.pid`) are shared across backends. The
/// `reap_picks_up_orphaned_vz_builder_state_dir` test pins this — a
/// future refactor that narrows the traversal or renames the sidecar
/// must update that test.
///
/// Two scans per VM dir:
///
/// 1. **Sidecar PID scan.** Each dir carries a `{builder.pid,
///    stage0.pid}` sidecar with the supervisor's PID. (Earlier
///    versions of this function looked for the wrong names
///    (`supervisor.pid`/`gvproxy.pid`); the actual sidecar names
///    are `builder.pid` for steady-state and `stage0.pid` for
///    Stage 0 — fixed after smoke-testing on accumulated state
///    showed `0` PIDs killed despite live orphans.)
/// 2. **Argv scan.** `gvproxy` is the supervisor's GRANDCHILD and
///    writes no sidecar of its own — its argv references the VM
///    dir's `gvproxy.sock`. The argv scan catches those grandchildren
///    even after the supervisor is gone. Same for `tail -F` readers
///    of `console.log`.
///
/// For each PID found by either scan:
/// - dead → ignore
/// - alive with a non-launchd parent → in-flight dev up; mark dir
///   as "has a live owner", skip dir removal
/// - alive with launchd as parent → SIGTERM and count
///
/// Then if no helper in the dir had a live non-launchd parent, the
/// dir is removed. This avoids the over-aggressive `rm -rf $vm/` of an
/// earlier prototype, which during validation nuked a live mvmctl's
/// state dir.
pub(in crate::commands) fn reap_orphaned_vm_helpers(dry_run: bool) -> Result<ReapOutcome> {
    reap_orphaned_vm_helpers_both_roots(/* remove_builder_dirs = */ true, dry_run)
}

/// Best-effort orphan-helper sweep run at the *start* of `mvmctl dev
/// up` / `mvmctl up`. The next launch reaps the previous run's corpses
/// — startup is the robust trigger because an abnormal exit (^C,
/// SIGKILL, crash, the libkrun `krun_start_enter` `exit()` that skips
/// `GvproxyHandle::Drop`) is exactly when mvmctl can't self-clean and
/// reparents its helpers to launchd.
///
/// Kill-only: it signals provably-orphaned helpers but removes **no**
/// directories (so it never deletes host bytes and carries no audit
/// obligation — dir pruning stays the job of `mvmctl cache prune`).
/// Quiet on the happy path; one line only when it actually reaped
/// something. Swallows errors — a sweep failure must never block a
/// launch. Since [`free_loopback_port`](libkrun_sys::gvproxy::free_loopback_port)
/// gives every gvproxy a fresh port, a missed leak is now harmless
/// hygiene, not a boot blocker.
pub(in crate::commands) fn sweep_orphaned_vm_helpers_on_startup() {
    match reap_orphaned_vm_helpers_both_roots(/* remove_builder_dirs = */ false, false) {
        Ok(o) if o.killed > 0 => crate::ui::info(&format!(
            "Reaped {} orphaned VM helper(s) left by a prior run.",
            o.killed
        )),
        Ok(_) => {}
        Err(e) => {
            tracing::debug!(error = %e, "startup orphan-helper sweep failed (non-fatal)")
        }
    }
}

/// Sidecar PID file names a *builder* VM dir carries (libkrun + Vz).
const BUILDER_SIDECARS: &[&str] = &["builder.pid", "stage0.pid"];

/// Sidecar PID file names a *workload* VM dir under `~/.mvm/vms/<name>/`
/// carries: `libkrun.pid` (libkrun supervisor), `vz.pid` (Vz
/// supervisor), and the gvproxy sidecars (`gvproxy.pid` libkrun lane /
/// `host-gvproxy.pid` Vz lane). The argv scan backstops these, but
/// reading the sidecar directly is cheaper and catches a detached Vz
/// supervisor that the argv scan might miss.
const WORKLOAD_SIDECARS: &[&str] = &["libkrun.pid", "vz.pid", "gvproxy.pid", "host-gvproxy.pid"];

/// Scan both VM-state roots: the ephemeral builder cache
/// (`~/.cache/mvm/builder-vm/vms/`) and the workload VM tree
/// (`~/.mvm/vms/`). `remove_builder_dirs` deletes dead builder scratch
/// dirs (cache-prune semantics); workload dirs are **never** removed —
/// a stopped named VM's `~/.mvm/vms/<name>/` is persistent state the
/// user may restart, so we only reap its leaked helpers.
fn reap_orphaned_vm_helpers_both_roots(
    remove_builder_dirs: bool,
    dry_run: bool,
) -> Result<ReapOutcome> {
    let builder_root =
        std::path::PathBuf::from(mvm_core::config::mvm_cache_dir()).join("builder-vm/vms");
    let workload_root = std::path::PathBuf::from(mvm_core::config::mvm_data_dir()).join("vms");

    let mut out = reap_orphaned_vm_helpers_at(
        &builder_root,
        BUILDER_SIDECARS,
        remove_builder_dirs,
        dry_run,
    )?;
    let workload = reap_orphaned_vm_helpers_at(
        &workload_root,
        WORKLOAD_SIDECARS,
        /* remove_dead_dirs = */ false,
        dry_run,
    )?;
    out.killed += workload.killed;
    out.removed_dirs += workload.removed_dirs;
    out.freed_bytes += workload.freed_bytes;
    Ok(out)
}

/// Inner form taking an explicit `vms_root`, the sidecar names to look
/// for in each dir, and whether dead dirs may be removed. Exists for
/// tests against a tempdir without mutating `MVM_CACHE_DIR`.
fn reap_orphaned_vm_helpers_at(
    vms_root: &std::path::Path,
    sidecars: &[&str],
    remove_dead_dirs: bool,
    dry_run: bool,
) -> Result<ReapOutcome> {
    let mut outcome = ReapOutcome {
        killed: 0,
        removed_dirs: 0,
        freed_bytes: 0,
    };
    if !vms_root.is_dir() {
        return Ok(outcome);
    }

    // One process-table snapshot for the whole sweep. macOS has no
    // `/proc`, so the former code shelled out to `pgrep -f <basename>`
    // once per dir plus `ps -o ppid=` once per candidate PID. With a
    // cache of hundreds of builder scratch dirs that turned the `up`
    // hot path into a multi-second storm of subprocess spawns. One
    // `ps` up front collapses it to a single call.
    let snapshot = ProcSnapshot::capture();

    for entry in std::fs::read_dir(vms_root)?.flatten() {
        let dir = entry.path();
        if !dir.is_dir() {
            continue;
        }

        let mut dir_has_live_owner = false;
        let mut killed_in_dir = 0u64;
        let mut seen_pids: std::collections::HashSet<i32> = std::collections::HashSet::new();

        // Scan 1 — sidecar files. Builder dirs write `builder.pid` /
        // `stage0.pid`; workload dirs write `libkrun.pid` / `vz.pid` /
        // the gvproxy sidecars. `sidecars` is the per-root set; a
        // missing file is skipped.
        for sidecar in sidecars {
            let pid_file = dir.join(sidecar);
            let Some(pid) = read_pid_file(&pid_file) else {
                continue;
            };
            if !seen_pids.insert(pid) {
                continue;
            }
            match classify_pid(pid, &snapshot) {
                PidClassification::Dead => {}
                PidClassification::LiveOwned => dir_has_live_owner = true,
                PidClassification::Orphan => {
                    if !dry_run {
                        unsafe {
                            libc::kill(pid, libc::SIGTERM);
                        }
                    }
                    killed_in_dir += 1;
                }
            }
        }

        // Scan 2 — argv scan for grandchildren (gvproxy, tail -F …
        // console.log). They don't write sidecars but their argv
        // contains the VM dir basename (the `mvm-stage0-…` or
        // `mvm-builder-vm-…` id), which is unique on this host.
        let dir_basename = match dir.file_name().and_then(|s| s.to_str()) {
            Some(s) => s.to_string(),
            None => continue,
        };
        for pid in snapshot.pids_referencing(&dir_basename) {
            if !seen_pids.insert(pid) {
                continue;
            }
            match classify_pid(pid, &snapshot) {
                PidClassification::Dead => {}
                PidClassification::LiveOwned => dir_has_live_owner = true,
                PidClassification::Orphan => {
                    if !dry_run {
                        unsafe {
                            libc::kill(pid, libc::SIGTERM);
                        }
                    }
                    killed_in_dir += 1;
                }
            }
        }

        outcome.killed += killed_in_dir;
        if dir_has_live_owner || !remove_dead_dirs {
            continue;
        }

        let size = dir_size_bytes(&dir);
        if !dry_run {
            let _ = std::fs::remove_dir_all(&dir);
        }
        outcome.removed_dirs += 1;
        outcome.freed_bytes += size;
    }

    Ok(outcome)
}

enum PidClassification {
    Dead,
    LiveOwned, // alive, parent is something other than launchd → in-flight
    Orphan,    // alive, parent is launchd PID 1 → SIGTERM-able
}

fn classify_pid(pid: i32, snapshot: &ProcSnapshot) -> PidClassification {
    if !pid_is_alive(pid) {
        return PidClassification::Dead;
    }
    match snapshot.parent(pid) {
        Some(1) => PidClassification::Orphan,
        _ => PidClassification::LiveOwned,
    }
}

/// One-shot snapshot of the host process table, taken once per sweep.
/// macOS has no `/proc`, so the portable source for (pid, ppid, argv)
/// is `ps`. This replaces the former per-dir `pgrep -f` + per-PID
/// `ps -o ppid=` fan-out: with hundreds of cached builder scratch
/// dirs that fan-out cost seconds of serial subprocess spawns on the
/// `up` startup path. `ps -axww` (no column truncation) is a single
/// call serving both the argv-substring scan and the parent lookup.
struct ProcSnapshot {
    /// pid → ppid for every process visible to this user.
    parents: std::collections::HashMap<i32, i32>,
    /// (pid, full argv) for every real process (pid > 1), scanned for
    /// VM-dir-basename substrings.
    cmds: Vec<(i32, String)>,
}

impl ProcSnapshot {
    fn capture() -> Self {
        let mut parents = std::collections::HashMap::new();
        let mut cmds = Vec::new();
        let Ok(out) = std::process::Command::new("ps")
            .args(["-axww", "-o", "pid=,ppid=,command="])
            .output()
        else {
            return Self { parents, cmds };
        };
        if !out.status.success() {
            return Self { parents, cmds };
        }
        for line in String::from_utf8_lossy(&out.stdout).lines() {
            // `  501  1234 /path/to/cmd --flag` — leading pad, then
            // pid and ppid columns (variable width), then the full
            // command. Peel pid, then ppid, then keep the rest verbatim.
            let rest = line.trim_start();
            let Some((pid_s, rest)) = rest.split_once(char::is_whitespace) else {
                continue;
            };
            let Ok(pid) = pid_s.parse::<i32>() else {
                continue;
            };
            let rest = rest.trim_start();
            let Some((ppid_s, cmd)) = rest.split_once(char::is_whitespace) else {
                continue;
            };
            let Ok(ppid) = ppid_s.parse::<i32>() else {
                continue;
            };
            parents.insert(pid, ppid);
            if pid > 1 {
                cmds.push((pid, cmd.trim_start().to_string()));
            }
        }
        Self { parents, cmds }
    }

    /// Parent PID of `pid`, or `None` if it's not in the snapshot
    /// (exited, or spawned after the snapshot was taken).
    fn parent(&self, pid: i32) -> Option<i32> {
        self.parents.get(&pid).copied()
    }

    /// All real PIDs whose argv contains `needle` — the argv-substring
    /// match the old `pgrep -f <needle>` performed, served from the
    /// snapshot instead of a fresh subprocess per call.
    fn pids_referencing(&self, needle: &str) -> Vec<i32> {
        self.cmds
            .iter()
            .filter(|(_, cmd)| cmd.contains(needle))
            .map(|(pid, _)| *pid)
            .collect()
    }
}

fn read_pid_file(path: &std::path::Path) -> Option<i32> {
    std::fs::read_to_string(path)
        .ok()?
        .trim()
        .parse::<i32>()
        .ok()
        .filter(|&p| p > 1)
}

fn pid_is_alive(pid: i32) -> bool {
    // Signal 0 = existence check, doesn't deliver a signal.
    unsafe { libc::kill(pid, 0) == 0 }
}

fn dir_size_bytes(path: &std::path::Path) -> u64 {
    let mut total = 0u64;
    let Ok(entries) = std::fs::read_dir(path) else {
        return total;
    };
    for entry in entries.flatten() {
        let p = entry.path();
        if p.is_file() {
            total += p.metadata().map(|m| m.len()).unwrap_or(0);
        } else if p.is_dir() {
            total += dir_size_bytes(&p);
        }
    }
    total
}

/// Predicate matching the staging-dir basenames left by Stage 0.
/// Two shapes are recognised:
/// - Current: `.<arch>.stage0-<pid>-<nonce>` (hidden, see
///   [`unique_builder_vm_stage0_staging_dir`]).
/// - Legacy: `<arch>-staging` or `<arch>-staging-<suffix>`
///   left behind by earlier Stage 0 prototypes that were observed on
///   contributor hosts; harmless when they exist but the pruner is
///   the obvious place to clean them up.
fn is_orphan_stage0_staging_dir_name(name: &str) -> bool {
    let is_known_arch = |arch: &str| arch == "aarch64" || arch == "x86_64";

    // Current hidden form.
    if let Some(rest) = name.strip_prefix('.')
        && let Some((arch, tail)) = rest.split_once('.')
        && is_known_arch(arch)
        && tail.starts_with("stage0-")
    {
        return true;
    }
    // Legacy `<arch>-staging` / `<arch>-staging-<suffix>`.
    if let Some((arch, tail)) = name.split_once('-')
        && is_known_arch(arch)
        && (tail == "staging" || tail.starts_with("staging"))
    {
        return true;
    }
    false
}

/// Total byte size of a directory tree. Best-effort — failures stat-ing
/// individual entries are skipped silently because the caller only uses
/// this for the "bytes freed" UI counter, never for correctness.
fn stage0_dir_size_bytes(path: &std::path::Path) -> u64 {
    let mut total = 0u64;
    let mut stack = vec![path.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let entry_path = entry.path();
            match entry.file_type() {
                Ok(ft) if ft.is_dir() => stack.push(entry_path),
                Ok(_) => {
                    if let Ok(meta) = entry_path.metadata() {
                        total = total.saturating_add(meta.len());
                    }
                }
                Err(_) => {}
            }
        }
    }
    total
}

/// Fingerprint the full set of source inputs that determine the
/// builder-VM rootfs.
///
/// The builder-VM rootfs is built by `nix/images/builder-vm/flake.nix`
/// from these categories of source input:
///
/// 1. The flake itself (`flake.nix` + `flake.lock`) — controls
///    which `nixpkgs` rev, which `mkGuest` shape, which `microvm.nix`,
///    which packages get installed.
/// 2. The workspace `Cargo.lock` — the dep closure of every Rust
///    binary baked into the rootfs.
/// 3. The embedded host-binary bytes — `build.rs` cross-compiles the
///    in-VM PID-1 + egress-proxy binaries (`cargo build -p mvm-build
///    --bin <name>`) and embeds the bytes in mvmctl; injected into the
///    rootfs at boot. The byte hash captures the bin source, the
///    `mvm-build` lib, its deps, AND the cross-compile toolchain in one
///    shot — strictly more than the per-crate `src/` hash this replaced
///    (which also broke when the two former top-level `crates/<name>/`
///    crates were folded into `crates/mvm-build/src/bin/`).
/// 4. The shared Nix library (`nix/lib`) the flake imports.
///
/// Pre-2026-05 this function only hashed (1), so contributor edits to
/// the in-VM binaries silently reused the cached `rootfs.ext4`,
/// burning the dev loop. This version closes that hole — now via the
/// embedded-byte hash rather than a per-crate source walk.
///
/// ## Scope and tradeoffs
///
/// We don't hash the entire workspace. A change to `mvm-cli` doesn't
/// affect the rootfs and shouldn't invalidate the cache; only the
/// embedded binaries' bytes carry the in-VM binary identity.
///
/// ## Hash discipline
///
/// File layers use the original flake-only shape:
/// `{name}\0{u64-length-LE}\0{contents}\0`, repeated for each input.
/// The `name` is the relative path keyed off the workspace, so
/// renaming a file changes the fingerprint. Files within a directory
/// are visited in lexicographic order regardless of filesystem read
/// order so the hash is deterministic across HFS+, APFS, and ext4.
/// The embedded-binary layer folds `(name, sha256_hex)` under a
/// `host-bin\0` domain tag (see `fold_embedded_binary_identity`).
fn builder_vm_source_fingerprint(builder_flake_dir: &str) -> Result<String> {
    let flake_dir = std::path::Path::new(builder_flake_dir);
    let workspace_root = workspace_root_for_builder_flake(flake_dir)?;
    let mut hasher = Sha256::new();

    // Layer 1: flake-local inputs.
    for name in ["flake.nix", "flake.lock"] {
        let path = flake_dir.join(name);
        if !path.exists() {
            if name == "flake.nix" {
                anyhow::bail!("builder VM source fingerprint missing {}", path.display());
            }
            continue;
        }
        hash_named_file(&mut hasher, name, &path)?;
    }

    // Layer 2: the embedded host-binary identity — the authoritative
    // fingerprint of every Rust binary baked into the builder VM
    // (`mvm-host-vm-init`, `mvm-egress-proxy`). `build.rs` cross-compiles
    // them and embeds the bytes in mvmctl; Stage 0 installs those bytes into
    // the rootfs. The builder-VM flake forbids `rustPlatform.buildRustPackage`,
    // so no flake artifact consumes the workspace `Cargo.lock` — hashing the
    // embedded bytes already captures the bin source, the `mvm-build` lib,
    // its dep closure, AND the cross-compile toolchain (a gnu→musl switch
    // yields different bytes from identical source) in one shot. The
    // workspace `Cargo.lock` is therefore deliberately NOT hashed: it gates
    // nothing here, and folding it in busts this cache on unrelated
    // workspace-wide dep bumps. (`build.rs` reruns the cross-compile when its
    // real inputs change, so a rebuilt binary's bytes shift this layer.)
    for bin in crate::host_binaries::embedded::EMBEDDED.iter() {
        fold_embedded_binary_identity(&mut hasher, bin.name, bin.sha256_hex);
    }

    // Layer 3: the shared Nix library the flake imports. The builder-vm
    // flake pulls in `nix/lib` (mkGuest, the workspace filter, the
    // host-binaries manifest), so a change there — e.g. a new rootfs
    // mount-point dir — changes the built image. Hashing only the flake
    // dir misses it, which silently reuses a stale image.
    let nix_lib = workspace_root.join("nix").join("lib");
    if nix_lib.is_dir() {
        hash_dir_recursive(&mut hasher, "nix/lib", &nix_lib)?;
    }

    Ok(format!("{:x}", hasher.finalize()))
}

/// Fold one embedded host-binary's identity into the fingerprint.
/// Keyed on `(name, sha256_hex)` so a rebuilt binary's byte change —
/// the authoritative signal that the in-VM PID-1 / egress-proxy source
/// or toolchain shifted — busts the Stage 0 cache key. The `host-bin\0`
/// domain tag keeps these entries from colliding with the file-hash
/// layers above.
fn fold_embedded_binary_identity(hasher: &mut Sha256, name: &str, sha256_hex: &str) {
    hasher.update(b"host-bin\0");
    hasher.update(name.as_bytes());
    hasher.update(b"\0");
    hasher.update(sha256_hex.as_bytes());
}

/// Resolve the workspace root from the builder-VM flake dir.
///
/// `find_builder_vm_flake` computes the flake path as
/// `<workspace>/nix/images/builder-vm`, so walking three parents up
/// lands on the workspace. Splitting this out for the fingerprint
/// tests to call without going through `find_builder_vm_flake`'s
/// `CARGO_MANIFEST_DIR` lookup.
fn workspace_root_for_builder_flake(flake_dir: &std::path::Path) -> Result<std::path::PathBuf> {
    flake_dir
        .parent()
        .and_then(|p| p.parent())
        .and_then(|p| p.parent())
        .map(|p| p.to_path_buf())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "cannot resolve workspace root from builder-vm flake dir {} \
                 (expected <workspace>/nix/images/builder-vm)",
                flake_dir.display()
            )
        })
}

/// Feed a single named file into the hasher using the original
/// flake-fingerprint discipline: `{name}\0{u64-length-LE}\0{contents}\0`.
fn hash_named_file(hasher: &mut Sha256, name: &str, path: &std::path::Path) -> Result<()> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("reading builder VM source input {}", path.display()))?;
    hasher.update(name.as_bytes());
    hasher.update(b"\0");
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(b"\0");
    hasher.update(&bytes);
    hasher.update(b"\0");
    Ok(())
}

/// Hash every regular file under `dir` recursively, keyed by
/// `<prefix>/<relative-path>` so the fingerprint reflects directory
/// structure. Skips hidden entries and `target/` — neither is an
/// input to `rustPlatform.buildRustPackage`.
fn hash_dir_recursive(hasher: &mut Sha256, prefix: &str, dir: &std::path::Path) -> Result<()> {
    let files = walk_source_dir_sorted(dir)
        .with_context(|| format!("walking builder VM source dir {}", dir.display()))?;
    for path in &files {
        let rel = path.strip_prefix(dir).map_err(|e| {
            anyhow::anyhow!(
                "strip_prefix {} from {}: {e}",
                dir.display(),
                path.display()
            )
        })?;
        let key = format!("{prefix}/{}", rel.display());
        hash_named_file(hasher, &key, path)?;
    }
    Ok(())
}

/// Walk every regular file under `dir`, skipping hidden entries
/// (`.git/`, `.DS_Store`, …), editor swap files (`*.swp`), and
/// `target/` (cargo build output). Paths are returned
/// lexicographically sorted so the hash is deterministic regardless
/// of filesystem read order.
fn walk_source_dir_sorted(dir: &std::path::Path) -> Result<Vec<std::path::PathBuf>> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let entries = std::fs::read_dir(&d).with_context(|| format!("read_dir {}", d.display()))?;
        for e in entries {
            let e = e.with_context(|| format!("read_dir entry in {}", d.display()))?;
            let name = e.file_name();
            let name_str = name.to_string_lossy();
            if name_str.starts_with('.') || name_str == "target" || name_str.ends_with(".swp") {
                continue;
            }
            let path = e.path();
            let ft = e
                .file_type()
                .with_context(|| format!("file_type {}", path.display()))?;
            if ft.is_dir() {
                stack.push(path);
            } else if ft.is_file() {
                out.push(path);
            }
        }
    }
    out.sort();
    Ok(out)
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum BuilderVmSourceCacheStatus {
    Hit,
    MissingArtifact,
    InvalidStage0Artifacts,
    MissingFingerprint,
    FingerprintMismatch,
    MissingArtifactDigestManifest,
    ArtifactDigestMismatch,
    MissingProvenance,
    ProvenanceMismatch,
}

impl BuilderVmSourceCacheStatus {
    fn is_ready(self) -> bool {
        self == Self::Hit
    }

    fn reason_code(self) -> &'static str {
        match self {
            Self::Hit => "hit",
            Self::MissingArtifact => "missing_artifact",
            Self::InvalidStage0Artifacts => "invalid_stage0_artifacts",
            Self::MissingFingerprint => "missing_fingerprint",
            Self::FingerprintMismatch => "fingerprint_mismatch",
            Self::MissingArtifactDigestManifest => "missing_artifact_digest_manifest",
            Self::ArtifactDigestMismatch => "artifact_digest_mismatch",
            Self::MissingProvenance => "missing_provenance",
            Self::ProvenanceMismatch => "provenance_mismatch",
        }
    }
}

fn builder_vm_source_cache_status(
    dir: &std::path::Path,
    expected_fingerprint: &str,
) -> BuilderVmSourceCacheStatus {
    if !dir.join("vmlinux").exists() || !dir.join("rootfs.ext4").exists() {
        return BuilderVmSourceCacheStatus::MissingArtifact;
    }
    if validate_builder_vm_stage0_artifacts(dir).is_err() {
        return BuilderVmSourceCacheStatus::InvalidStage0Artifacts;
    }

    let fingerprint_path = dir.join(BUILDER_VM_SOURCE_FINGERPRINT_FILE);
    let Ok(actual_fingerprint) = std::fs::read_to_string(fingerprint_path) else {
        return BuilderVmSourceCacheStatus::MissingFingerprint;
    };
    if actual_fingerprint.trim() != expected_fingerprint {
        return BuilderVmSourceCacheStatus::FingerprintMismatch;
    }

    let digest_path = dir.join(BUILDER_VM_ARTIFACT_DIGEST_FILE);
    if !digest_path.exists() {
        return BuilderVmSourceCacheStatus::MissingArtifactDigestManifest;
    }
    if !builder_vm_artifact_digest_manifest_matches(dir) {
        return BuilderVmSourceCacheStatus::ArtifactDigestMismatch;
    }

    let provenance_path = dir.join(BUILDER_VM_PROVENANCE_FILE);
    if !provenance_path.exists() {
        return BuilderVmSourceCacheStatus::MissingProvenance;
    }
    if !builder_vm_source_cache_provenance_matches(dir, expected_fingerprint) {
        return BuilderVmSourceCacheStatus::ProvenanceMismatch;
    }

    BuilderVmSourceCacheStatus::Hit
}

#[cfg(any(feature = "builder-vm", test))]
fn builder_vm_source_cache_ready(dir: &std::path::Path, expected_fingerprint: &str) -> bool {
    builder_vm_source_cache_status(dir, expected_fingerprint).is_ready()
}

#[cfg(any(feature = "builder-vm", test))]
fn builder_vm_source_fingerprint_matches(
    dir: &std::path::Path,
    expected_fingerprint: &str,
) -> bool {
    std::fs::read_to_string(dir.join(BUILDER_VM_SOURCE_FINGERPRINT_FILE))
        .map(|actual| actual.trim() == expected_fingerprint)
        .unwrap_or(false)
}

#[cfg(any(feature = "builder-vm", test))]
fn write_builder_vm_source_fingerprint(
    dir: &std::path::Path,
    source_fingerprint: &str,
) -> Result<()> {
    std::fs::write(
        dir.join(BUILDER_VM_SOURCE_FINGERPRINT_FILE),
        format!("{source_fingerprint}\n"),
    )
    .with_context(|| format!("writing builder VM source fingerprint in {}", dir.display()))
}

fn builder_vm_artifact_digest_manifest(dir: &std::path::Path) -> Result<String> {
    let mut lines = Vec::new();
    for name in ["vmlinux", "rootfs.ext4", "cmdline.txt"] {
        let path = dir.join(name);
        if !path.exists() {
            if name == "cmdline.txt" {
                continue;
            }
            anyhow::bail!("builder VM artifact digest missing {}", path.display());
        }
        let bytes = std::fs::read(&path)
            .with_context(|| format!("reading builder VM artifact {}", path.display()))?;
        lines.push(format!("{:x}  {name}", Sha256::digest(&bytes)));
    }
    Ok(format!("{}\n", lines.join("\n")))
}

fn builder_vm_artifact_digest_manifest_matches(dir: &std::path::Path) -> bool {
    let expected = match builder_vm_artifact_digest_manifest(dir) {
        Ok(expected) => expected,
        Err(_) => return false,
    };
    std::fs::read_to_string(dir.join(BUILDER_VM_ARTIFACT_DIGEST_FILE))
        .map(|actual| actual == expected)
        .unwrap_or(false)
}

#[cfg(any(feature = "builder-vm", test))]
fn write_builder_vm_artifact_digest_manifest(dir: &std::path::Path) -> Result<()> {
    let manifest = builder_vm_artifact_digest_manifest(dir)?;
    std::fs::write(dir.join(BUILDER_VM_ARTIFACT_DIGEST_FILE), manifest)
        .with_context(|| format!("writing builder VM artifact digests in {}", dir.display()))
}

#[derive(Debug, Clone, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct BuilderVmSourceCacheProvenance {
    schema_version: u32,
    source_kind: String,
    source_fingerprint: String,
    artifacts: Vec<String>,
}

fn builder_vm_source_cache_provenance(
    dir: &std::path::Path,
    source_fingerprint: &str,
) -> Result<BuilderVmSourceCacheProvenance> {
    Ok(BuilderVmSourceCacheProvenance {
        schema_version: 1,
        source_kind: "source_checkout_stage0".to_string(),
        source_fingerprint: source_fingerprint.to_string(),
        artifacts: builder_vm_artifact_names_present(dir)?,
    })
}

fn builder_vm_artifact_names_present(dir: &std::path::Path) -> Result<Vec<String>> {
    let mut names = Vec::new();
    for name in ["vmlinux", "rootfs.ext4", "cmdline.txt"] {
        let path = dir.join(name);
        if !path.exists() {
            if name == "cmdline.txt" {
                continue;
            }
            anyhow::bail!("builder VM provenance missing artifact {}", path.display());
        }
        names.push(name.to_string());
    }
    Ok(names)
}

fn builder_vm_source_cache_provenance_matches(
    dir: &std::path::Path,
    expected_fingerprint: &str,
) -> bool {
    let expected = match builder_vm_source_cache_provenance(dir, expected_fingerprint) {
        Ok(expected) => expected,
        Err(_) => return false,
    };
    std::fs::read_to_string(dir.join(BUILDER_VM_PROVENANCE_FILE))
        .ok()
        .and_then(|actual| serde_json::from_str::<BuilderVmSourceCacheProvenance>(&actual).ok())
        .map(|actual| actual == expected)
        .unwrap_or(false)
}

#[cfg(any(feature = "builder-vm", test))]
fn write_builder_vm_source_cache_provenance(
    dir: &std::path::Path,
    source_fingerprint: &str,
) -> Result<()> {
    let provenance = builder_vm_source_cache_provenance(dir, source_fingerprint)?;
    let json = serde_json::to_string_pretty(&provenance)
        .context("serializing builder VM source cache provenance")?;
    std::fs::write(dir.join(BUILDER_VM_PROVENANCE_FILE), format!("{json}\n"))
        .with_context(|| format!("writing builder VM provenance in {}", dir.display()))
}

/// Write the full cache-sidecar set — source fingerprint, artifact-digest
/// manifest, and provenance — that [`builder_vm_source_cache_status`] reads
/// back to decide a hit. Shared by Stage 0 promotion and the dev-image
/// fast-path (Fix A) so both write the identical format; the order matters
/// only in that the digest manifest must be written after the artifacts are
/// final.
#[cfg(any(feature = "builder-vm", test))]
fn write_builder_vm_cache_sidecars(dir: &std::path::Path, source_fingerprint: &str) -> Result<()> {
    write_builder_vm_source_fingerprint(dir, source_fingerprint)?;
    write_builder_vm_artifact_digest_manifest(dir)?;
    write_builder_vm_source_cache_provenance(dir, source_fingerprint)
}

#[cfg(any(feature = "builder-vm", test))]
fn promote_builder_vm_stage0_cache(
    staging_dir: &std::path::Path,
    final_dir: &std::path::Path,
    source_fingerprint: &str,
) -> Result<()> {
    validate_builder_vm_stage0_artifacts(staging_dir)?;
    if !builder_vm_source_fingerprint_matches(staging_dir, source_fingerprint) {
        anyhow::bail!(
            "Stage 0 builder VM staging dir {} is missing the expected source fingerprint",
            staging_dir.display()
        );
    }
    if !builder_vm_artifact_digest_manifest_matches(staging_dir) {
        anyhow::bail!(
            "Stage 0 builder VM staging dir {} is missing matching artifact digests",
            staging_dir.display()
        );
    }
    if !builder_vm_source_cache_provenance_matches(staging_dir, source_fingerprint) {
        anyhow::bail!(
            "Stage 0 builder VM staging dir {} is missing matching provenance metadata",
            staging_dir.display()
        );
    }

    if final_dir.exists() {
        if builder_vm_source_cache_ready(final_dir, source_fingerprint) {
            std::fs::remove_dir_all(staging_dir).with_context(|| {
                format!(
                    "removing redundant Stage 0 staging dir {}",
                    staging_dir.display()
                )
            })?;
            return Ok(());
        }
        std::fs::remove_dir_all(final_dir).with_context(|| {
            format!("removing partial builder VM cache {}", final_dir.display())
        })?;
    }

    std::fs::rename(staging_dir, final_dir).with_context(|| {
        format!(
            "promoting Stage 0 builder VM cache {} to {}",
            staging_dir.display(),
            final_dir.display()
        )
    })?;
    if !builder_vm_source_cache_ready(final_dir, source_fingerprint) {
        anyhow::bail!(
            "promoted Stage 0 builder VM cache {} failed source-cache validation",
            final_dir.display()
        );
    }
    Ok(())
}

/// Download the per-arch Layer 1 builder VM artifacts published by the
/// `builder-vm-image` release-workflow job into the local cache dir,
/// SHA-256-verified.
///
/// Mirrors `download_dev_image_inner` for the dev-shell image, minus
/// cosign signing (the signed-manifest path extends to builder-vm
/// artifacts as a follow-up). The required artifacts are `vmlinux` +
/// `rootfs.ext4`; `cmdline.txt` and `manifest.json` sidecars are
/// best-effort downloads with a fallback at the `mvm-build` consumer
/// (`ensure_builder_vm_image` uses the canonical cmdline when
/// `cmdline.txt` is missing).
///
/// Gated behind `release-artifact-bootstrap`. Contributor
/// builds (default) never compile this in, so the "no flake + cache
/// miss" branch in [`bootstrap_builder_vm_image`] has no escape hatch
/// and surfaces a hard error. End-user-binary release builds opt in
/// at compile time via `--features release-artifact-bootstrap`.
#[cfg(feature = "release-artifact-bootstrap")]
fn download_builder_vm_image(arch: &str, cache_dir: &str) -> Result<()> {
    let version = env!("CARGO_PKG_VERSION");
    let names = builder_vm_artifact_names(arch);
    let base_url = format!("https://github.com/tinylabscom/mvm/releases/download/v{version}");
    let kernel_url = format!("{base_url}/{}", names.kernel);
    let rootfs_url = format!("{base_url}/{}", names.rootfs);
    let cmdline_url = format!("{base_url}/{}", names.cmdline);
    let manifest_url = format!("{base_url}/{}", names.manifest);
    let checksums_url = format!("{base_url}/{}", names.checksums);

    // Required artifacts only; sidecars get best-effort treatment
    // below. `fetch_expected_hashes` enforces that the checksum file
    // contains entries for everything in `wanted` before any download
    // starts.
    let expected = fetch_expected_hashes(&checksums_url, &[&names.kernel, &names.rootfs])?;

    ui::info("  Fetching kernel...");
    let kernel_path = format!("{cache_dir}/vmlinux");
    download_file(&kernel_url, &kernel_path).map_err(|e| {
        bump_verify_outcome("network");
        e.context(format!(
            "Failed to download builder VM kernel from {kernel_url}"
        ))
    })?;
    verify_artifact_hash(&kernel_path, &names.kernel, expected.get(&names.kernel))?;

    ui::info("  Fetching rootfs...");
    let rootfs_path = format!("{cache_dir}/rootfs.ext4");
    download_file(&rootfs_url, &rootfs_path).map_err(|e| {
        bump_verify_outcome("network");
        e.context(format!(
            "Failed to download builder VM rootfs from {rootfs_url}"
        ))
    })?;
    verify_artifact_hash(&rootfs_path, &names.rootfs, expected.get(&names.rootfs))?;

    // Sidecars — best-effort. `cmdline.txt` has a documented fallback
    // in `mvm-build::libkrun_builder::ensure_builder_vm_image`;
    // `manifest.json` is informational. A 404 on either is fine; a
    // hash mismatch when the file IS present is still a hard fail.
    if let Some(expected_cmdline) = expected.get(&names.cmdline) {
        let cmdline_path = format!("{cache_dir}/cmdline.txt");
        if download_file(&cmdline_url, &cmdline_path).is_ok() {
            verify_artifact_hash(&cmdline_path, &names.cmdline, Some(expected_cmdline))?;
        }
    }
    if let Some(expected_manifest) = expected.get(&names.manifest) {
        let manifest_path = format!("{cache_dir}/manifest.json");
        if download_file(&manifest_url, &manifest_path).is_ok() {
            verify_artifact_hash(&manifest_path, &names.manifest, Some(expected_manifest))?;
        }
    }

    ui::success(&format!(
        "Builder VM image downloaded, hash-verified, and cached at {cache_dir}."
    ));
    Ok(())
}

/// Per-arch artifact filenames the release workflow's
/// `builder-vm-image` job uploads. Pure function — no I/O, no
/// network — so the unit test can verify naming matches the
/// release.yml side without touching the network. Gated together
/// with [`download_builder_vm_image`].
#[cfg(any(feature = "release-artifact-bootstrap", test))]
struct BuilderVmArtifactNames {
    kernel: String,
    rootfs: String,
    cmdline: String,
    manifest: String,
    checksums: String,
}

#[cfg(any(feature = "release-artifact-bootstrap", test))]
fn builder_vm_artifact_names(arch: &str) -> BuilderVmArtifactNames {
    BuilderVmArtifactNames {
        kernel: format!("builder-vm-vmlinux-{arch}"),
        rootfs: format!("builder-vm-rootfs-{arch}.ext4"),
        cmdline: format!("builder-vm-{arch}.cmdline.txt"),
        manifest: format!("builder-vm-{arch}.manifest.json"),
        checksums: format!("builder-vm-{arch}-checksums-sha256.txt"),
    }
}

/// Build the dev-shell image via the libkrun-backed builder VM.
///
/// Layer 1 (the builder VM image at `~/.cache/mvm/builder-vm/<arch>/`)
/// is fetched via [`bootstrap_builder_vm_image`] on cache miss. The
/// dev-shell image the user boots into via `mvmctl dev up` is built by
/// `LibkrunBuilderVm::run_build` against the in-repo
/// `nix/images/builder/` flake, inside a libkrun guest that mounts the
/// workspace at `/work` and writes its artifacts back through a
/// virtio-fs `/out` share.
///
/// On success returns the host-side paths to the produced `vmlinux`
/// and `rootfs.ext4` in `out_dir`.
///
/// Caller is expected to have:
///   - confirmed `libkrun_sys::is_available()` true,
///   - confirmed `find_builder_vm_flake().is_ok()` (Layer 1 source is
///     present in the workspace),
///   - run [`prepare_dev_image_out_dir`] on `out_dir`.
// Gated only on `builder-vm`.
#[cfg(feature = "builder-vm")]
fn build_image_via_libkrun(out_dir: &str) -> Result<(String, String)> {
    use mvm_build::builder_backend_select::{
        resolve_builder_backend_with_override, resolve_choice, resolve_env_override,
    };
    use mvm_build::builder_vm::{BuilderJob, BuilderMounts, host_system_linux};

    // Ensure Layer 1 (the builder VM image) is in
    // `~/.cache/mvm/builder-vm/<arch>/`.
    bootstrap_builder_vm_image()
        .context("Stage 0 builder-VM image bootstrap (precondition for libkrun dispatch)")?;

    // Workspace root for the `/work` virtio-fs share. `find_builder_vm_flake()`
    // returns `<workspace>/nix/images/builder-vm`; the workspace itself is
    // three levels up. The consolidated flake reads `MVM_WORKSPACE_PATH=/work`
    // (set in the guest's `cmd.sh` by `LibkrunBuilderVm`) under
    // `--impure`, so the flake's `builtins.path` import lands on the
    // mount rather than the store-copied flake dir.
    // `nix/images/builder/` was collapsed into `nix/images/builder-vm/`;
    // the interactive dev-shell image is now `packages.<sys>.dev`.
    let builder_flake = find_builder_vm_flake().context(
        "builder-vm flake missing at nix/images/builder-vm/flake.nix; libkrun dispatch needs it as Layer 2 source",
    )?;
    let workspace_root = std::path::Path::new(&builder_flake)
        .parent()
        .and_then(|p| p.parent())
        .and_then(|p| p.parent())
        .ok_or_else(|| anyhow::anyhow!("Cannot derive workspace root from {builder_flake}"))?
        .to_path_buf();

    // Inside the guest, `/work` is the workspace mount. The builder-vm
    // flake lives at `/work/nix/images/builder-vm` from the cmd.sh's
    // perspective. `path:` forces Nix's filesystem flake fetcher (not
    // the git fetcher, which would discover `/work/.git` and trip on
    // worktree files whose `gitdir:` redirects point outside the
    // mount). `packages.<sys>.dev` is the interactive (dev-shell) attr.
    // Extract the embedded host-vm binaries to the host-bins cache dir
    // and mount them at /mvm-bins inside the builder VM.
    // The builder-vm flake's cmd.sh reads MVM_HOST_BIN_DIR=/mvm-bins to
    // install the correct cross-compiled binaries into the rootfs.
    let host_bins_cache = format!("{}/host-bins", mvm_core::config::mvm_cache_dir());
    let host_bin_dir = crate::host_binaries::extract::ensure_extracted_for_boot(
        std::path::Path::new(&host_bins_cache),
    )
    .map_err(|e| anyhow::anyhow!("extract embedded host-vm binaries: {e}"))?;

    let job = BuilderJob::Flake {
        flake_ref: "path:/work/nix/images/builder-vm".to_string(),
        attr_path: format!("packages.{}.dev", host_system_linux()),
    };
    let mounts = BuilderMounts {
        flake_src: workspace_root,
        // libkrun keeps `/nix` on a persistent virtio-blk; no host
        // bind-mount of `/nix/store` is used or wanted (would be a
        // Darwin-x-Linux closure mismatch on macOS anyway).
        host_nix_store: None,
        artifact_out: std::path::PathBuf::from(out_dir),
        host_bin_dir,
        // The dev-image build already builds the in-repo builder-vm flake
        // with the workspace mounted at /work; no user-flake override.
        staged_user_flake: None,
    };

    // Source-checkout dev-image builds route through the selected
    // builder backend. When Vz was chosen only
    // by auto-detect (no explicit `--builder` / env override), allow
    // a one-shot fallback to libkrun if Vz bring-up fails. This
    // keeps `mvmctl dev up` usable on hosts where the platform-level
    // Vz probe passes but the builder-VM path still trips a backend-
    // specific runtime issue. Explicit `vz` overrides still fail
    // loudly so operators can debug the backend they asked for.
    let selected = resolve_choice();
    let explicit_override = resolve_env_override().is_some();
    let attempt_order = builder_backend_attempt_order(selected, explicit_override);
    let mut used_backend = selected;
    let mut last_error = None;
    for (idx, choice) in attempt_order.iter().copied().enumerate() {
        let backend = resolve_builder_backend_with_override(Some(choice));
        match backend.run_build(&job, &mounts) {
            Ok(_) => {
                used_backend = choice;
                last_error = None;
                break;
            }
            Err(err) => {
                if idx + 1 < attempt_order.len() {
                    ui::warn(&format!(
                        "Auto-selected {} builder failed ({}); retrying with {}.",
                        choice.name(),
                        err,
                        attempt_order[idx + 1].name(),
                    ));
                    prepare_dev_image_out_dir(out_dir)?;
                }
                last_error = Some(anyhow::anyhow!("{} builder VM: {err}", choice.name()));
            }
        }
    }
    if let Some(err) = last_error {
        return Err(err);
    }

    // run_build wrote vmlinux + rootfs.ext4 into out_dir via the
    // virtio-fs `/out` mount; the same files mvm-cli is about to
    // hand back to the dev-up path.
    let kernel = format!("{out_dir}/vmlinux");
    let rootfs = format!("{out_dir}/rootfs.ext4");
    if !std::path::Path::new(&kernel).exists() {
        anyhow::bail!(
            "{} builder VM exited cleanly but did not produce {kernel}",
            used_backend.name()
        );
    }
    if !std::path::Path::new(&rootfs).exists() {
        anyhow::bail!(
            "{} builder VM exited cleanly but did not produce {rootfs}",
            used_backend.name()
        );
    }

    // Fix A — persist the source fingerprint + artifact-digest + provenance
    // sidecars so the next `dev up` fast-paths past the builder VM entirely
    // (see the cache check in `ensure_dev_image`). Best-effort: a failed
    // sidecar write must not fail an otherwise-good build — the next run
    // just rebuilds. The fingerprint is recomputed here from the same flake
    // dir the build read, so a fingerprint match later means an identical
    // nix derivation, hence an identical image.
    if let Ok(flake_dir) = find_builder_vm_flake()
        && let Ok(fingerprint) = builder_vm_source_fingerprint(&flake_dir)
        && let Err(e) = write_builder_vm_cache_sidecars(std::path::Path::new(out_dir), &fingerprint)
    {
        ui::warn(&format!(
            "Dev image built, but writing cache sidecars failed ({e}); \
             next `dev up` will rebuild instead of fast-pathing."
        ));
    }

    Ok((kernel, rootfs))
}

#[cfg(feature = "builder-vm")]
fn builder_backend_attempt_order(
    selected: mvm_build::builder_backend_select::BuilderBackendChoice,
    explicit_override: bool,
) -> Vec<mvm_build::builder_backend_select::BuilderBackendChoice> {
    use mvm_build::builder_backend_select::BuilderBackendChoice;

    match (selected, explicit_override) {
        (BuilderBackendChoice::Vz, false) => {
            vec![BuilderBackendChoice::Vz, BuilderBackendChoice::Libkrun]
        }
        _ => vec![selected],
    }
}

#[cfg(all(test, feature = "builder-vm"))]
mod builder_backend_attempt_order_tests {
    use super::builder_backend_attempt_order;
    use mvm_build::builder_backend_select::BuilderBackendChoice;

    #[test]
    fn auto_selected_vz_retries_with_libkrun() {
        assert_eq!(
            builder_backend_attempt_order(BuilderBackendChoice::Vz, false),
            vec![BuilderBackendChoice::Vz, BuilderBackendChoice::Libkrun]
        );
    }

    #[test]
    fn explicit_vz_override_does_not_fallback() {
        assert_eq!(
            builder_backend_attempt_order(BuilderBackendChoice::Vz, true),
            vec![BuilderBackendChoice::Vz]
        );
    }

    #[test]
    fn libkrun_selection_stays_single_backend() {
        assert_eq!(
            builder_backend_attempt_order(BuilderBackendChoice::Libkrun, false),
            vec![BuilderBackendChoice::Libkrun]
        );
        assert_eq!(
            builder_backend_attempt_order(BuilderBackendChoice::Libkrun, true),
            vec![BuilderBackendChoice::Libkrun]
        );
    }
}

/// Ensure the bundled default microVM image (kernel + rootfs) is in the cache,
/// keyed on `BuildMode`. Used by any image-taking command when no
/// `--flake`/`--template`/`--image` was supplied. Returns `(kernel, rootfs)`;
/// the verity + `mvm-meta.json` sidecars land alongside the rootfs.
///
/// - **Prod** downloads the published, verity-sealed prod image (the
///   `default-microvm-*` release assets), hash-verified.
/// - **Dev** builds the accessible dev variant locally from the in-repo flake
///   via the builder VM — dev images are never published.
pub(crate) fn ensure_default_microvm_image(
    mode: mvm_build::pipeline::BuildMode,
) -> Result<(String, String)> {
    use mvm_build::pipeline::BuildMode;
    let base = format!("{}/default-microvm", mvm_core::config::mvm_cache_dir());
    match mode {
        BuildMode::Prod => {
            let cache_dir = format!("{base}/prod");
            std::fs::create_dir_all(&cache_dir)?;
            let kernel_path = format!("{cache_dir}/vmlinux");
            let rootfs_path = format!("{cache_dir}/rootfs.ext4");
            // All five must be present before skipping the download — an older
            // cache has only vmlinux + rootfs.ext4 and would
            // fail admission (no overlay-aware sidecar, no verity).
            let required = [
                kernel_path.clone(),
                rootfs_path.clone(),
                format!("{cache_dir}/mvm-meta.json"),
                format!("{cache_dir}/rootfs.verity"),
                format!("{cache_dir}/rootfs.roothash"),
            ];
            if required.iter().all(|p| std::path::Path::new(p).exists()) {
                return Ok((kernel_path, rootfs_path));
            }
            download_default_microvm_image(&cache_dir, &kernel_path, &rootfs_path)
        }
        BuildMode::Dev => ensure_default_microvm_dev_image(&format!("{base}/dev")),
    }
}

/// Dev-mode default image: build the accessible `dev` variant locally from the
/// in-repo `nix/images/default-tenant` flake via the builder VM (not published).
#[cfg(feature = "builder-vm")]
fn ensure_default_microvm_dev_image(cache_dir: &str) -> Result<(String, String)> {
    std::fs::create_dir_all(cache_dir)?;
    let kernel_path = format!("{cache_dir}/vmlinux");
    let rootfs_path = format!("{cache_dir}/rootfs.ext4");
    let meta_path = format!("{cache_dir}/mvm-meta.json");
    if [&kernel_path, &rootfs_path, &meta_path]
        .iter()
        .all(|p| std::path::Path::new(p).exists())
    {
        return Ok((kernel_path, rootfs_path));
    }
    ui::info("Building the dev default microVM image locally (dev mode)...");
    build_default_microvm_dev_via_libkrun(cache_dir)
}

#[cfg(not(feature = "builder-vm"))]
fn ensure_default_microvm_dev_image(_cache_dir: &str) -> Result<(String, String)> {
    anyhow::bail!(
        "dev mode builds the default image locally via the builder VM, but this \
         mvmctl was built without the `builder-vm` feature. Use `--prod` (downloads \
         the published image), or pass a `--flake`."
    )
}

/// Build the bundled **dev** default microVM image via the libkrun builder VM:
/// `nix build nix/images/default-tenant#packages.<sys>.dev` inside the guest,
/// extracting `vmlinux` + `rootfs.ext4` + `mvm-meta.json` to `out_dir`. Mirrors
/// [`build_image_via_libkrun`] but targets the default-tenant flake.
#[cfg(feature = "builder-vm")]
fn build_default_microvm_dev_via_libkrun(out_dir: &str) -> Result<(String, String)> {
    use mvm_build::builder_backend_select::{
        resolve_builder_backend_with_override, resolve_choice, resolve_env_override,
    };
    use mvm_build::builder_vm::{BuilderJob, BuilderMounts, host_system_linux};

    bootstrap_builder_vm_image()
        .context("Stage 0 builder-VM image bootstrap (precondition for libkrun dispatch)")?;

    // The default-tenant flake reads the workspace via the `/work` mount the
    // builder VM sets (`MVM_WORKSPACE_PATH=/work`), same as the builder-vm flake.
    let builder_flake = find_builder_vm_flake().context(
        "builder-vm flake missing at nix/images/builder-vm/flake.nix; libkrun dispatch needs it",
    )?;
    let workspace_root = std::path::Path::new(&builder_flake)
        .parent()
        .and_then(|p| p.parent())
        .and_then(|p| p.parent())
        .ok_or_else(|| anyhow::anyhow!("Cannot derive workspace root from {builder_flake}"))?
        .to_path_buf();

    let host_bins_cache = format!("{}/host-bins", mvm_core::config::mvm_cache_dir());
    let host_bin_dir =
        crate::host_binaries::extract::ensure_extracted(std::path::Path::new(&host_bins_cache))
            .map_err(|e| anyhow::anyhow!("extract embedded host-vm binaries: {e}"))?;

    std::fs::create_dir_all(out_dir)
        .with_context(|| format!("creating default-microvm dev out dir {out_dir}"))?;

    let job = BuilderJob::Flake {
        flake_ref: "path:/work/nix/images/default-tenant".to_string(),
        attr_path: format!("packages.{}.dev", host_system_linux()),
    };
    let mounts = BuilderMounts {
        flake_src: workspace_root,
        host_nix_store: None,
        artifact_out: std::path::PathBuf::from(out_dir),
        host_bin_dir,
        staged_user_flake: None,
    };

    let selected = resolve_choice();
    let explicit_override = resolve_env_override().is_some();
    let attempt_order = builder_backend_attempt_order(selected, explicit_override);
    let mut last_error = None;
    for (idx, choice) in attempt_order.iter().copied().enumerate() {
        let backend = resolve_builder_backend_with_override(Some(choice));
        match backend.run_build(&job, &mounts) {
            Ok(_) => {
                last_error = None;
                break;
            }
            Err(err) => {
                if idx + 1 < attempt_order.len() {
                    ui::warn(&format!(
                        "Auto-selected {} builder failed ({}); retrying with {}.",
                        choice.name(),
                        err,
                        attempt_order[idx + 1].name(),
                    ));
                }
                last_error = Some(anyhow::anyhow!("{} builder VM: {err}", choice.name()));
            }
        }
    }
    if let Some(err) = last_error {
        return Err(err);
    }

    let kernel = format!("{out_dir}/vmlinux");
    let rootfs = format!("{out_dir}/rootfs.ext4");
    let meta = format!("{out_dir}/mvm-meta.json");
    for (label, p) in [
        ("vmlinux", &kernel),
        ("rootfs.ext4", &rootfs),
        ("mvm-meta.json", &meta),
    ] {
        if !std::path::Path::new(p).exists() {
            anyhow::bail!("builder VM exited cleanly but did not produce {label} at {p}");
        }
    }
    Ok((kernel, rootfs))
}

/// The (release asset name, local destination) contract for the prod default
/// microVM image. Release names match the `default-microvm` job in
/// `release.yml`; local names are the rootfs siblings the backend verity probe
/// (`microvm.rs::probe_verity_sidecar`) and `admit_overlay_aware` expect. Pure
/// — pinned by `default_microvm_assets_pins_the_five_asset_contract`.
fn default_microvm_assets(cache_dir: &str, arch: &str) -> [(String, String); 5] {
    [
        (
            format!("default-microvm-vmlinux-{arch}"),
            format!("{cache_dir}/vmlinux"),
        ),
        (
            format!("default-microvm-rootfs-{arch}.ext4"),
            format!("{cache_dir}/rootfs.ext4"),
        ),
        (
            format!("default-microvm-rootfs-{arch}.verity"),
            format!("{cache_dir}/rootfs.verity"),
        ),
        (
            format!("default-microvm-rootfs-{arch}.roothash"),
            format!("{cache_dir}/rootfs.roothash"),
        ),
        (
            format!("default-microvm-meta-{arch}.json"),
            format!("{cache_dir}/mvm-meta.json"),
        ),
    ]
}

#[cfg(test)]
mod default_microvm_tests {
    use super::default_microvm_assets;

    #[test]
    fn default_microvm_assets_pins_the_five_asset_contract() {
        let a = default_microvm_assets("/cache/dm", "aarch64");
        let names: Vec<&str> = a.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(
            names,
            vec![
                "default-microvm-vmlinux-aarch64",
                "default-microvm-rootfs-aarch64.ext4",
                "default-microvm-rootfs-aarch64.verity",
                "default-microvm-rootfs-aarch64.roothash",
                "default-microvm-meta-aarch64.json",
            ],
            "release asset names must match the default-microvm release job",
        );
        let dests: Vec<&str> = a.iter().map(|(_, d)| d.as_str()).collect();
        assert_eq!(
            dests,
            vec![
                "/cache/dm/vmlinux",
                "/cache/dm/rootfs.ext4",
                "/cache/dm/rootfs.verity",
                "/cache/dm/rootfs.roothash",
                "/cache/dm/mvm-meta.json",
            ],
            "local dests must be the rootfs siblings the backend + admit gate expect",
        );
    }
}

/// Download the pre-built **prod** default microVM image from the matching
/// GitHub release: kernel + verity-sealed rootfs + the `rootfs.verity` /
/// `rootfs.roothash` sidecars + the overlay-aware `mvm-meta.json`. Every file
/// is SHA-256-verified against the release checksums manifest.
/// The sidecars land alongside the rootfs so the backend verity probe +
/// `admit_overlay_aware` resolve them by path convention.
fn download_default_microvm_image(
    cache_dir: &str,
    kernel_path: &str,
    rootfs_path: &str,
) -> Result<(String, String)> {
    let version = env!("CARGO_PKG_VERSION");
    let base_url = format!("https://github.com/tinylabscom/mvm/releases/download/v{version}");
    let arch = if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else {
        "x86_64"
    };

    let assets = default_microvm_assets(cache_dir, arch);
    let checksums_name = format!("default-microvm-{arch}-checksums-sha256.txt");
    let checksums_url = format!("{base_url}/{checksums_name}");

    ui::info(&format!(
        "Downloading default microVM image (v{version})..."
    ));

    let asset_names: Vec<&str> = assets.iter().map(|(n, _)| n.as_str()).collect();
    let expected = fetch_expected_hashes(&checksums_url, &asset_names)?;

    for (name, dest) in &assets {
        ui::info(&format!("  Fetching {name}..."));
        let url = format!("{base_url}/{name}");
        download_file(&url, dest).with_context(|| format!("Failed to download {url}"))?;
        verify_artifact_hash(dest, name, expected.get(name.as_str()))?;
    }

    ui::success("Default microVM image downloaded, hash-verified, and cached.");
    Ok((kernel_path.to_string(), rootfs_path.to_string()))
}

#[cfg(test)]
mod dev_status_image_tests {
    use super::*;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    struct EnvGuard {
        _env: mvm_core::util::test_env::TestEnv,
    }

    impl EnvGuard {
        fn set(
            home: &std::path::Path,
            data_dir: &std::path::Path,
            cache_dir: &std::path::Path,
        ) -> Self {
            let mut env = mvm_core::util::test_env::TestEnv::new();
            env.set("HOME", home);
            env.set("MVM_DATA_DIR", data_dir);
            env.set("MVM_CACHE_DIR", cache_dir);
            Self { _env: env }
        }
    }

    fn touch(path: &std::path::Path) {
        std::fs::create_dir_all(path.parent().expect("test path must have parent")).unwrap();
        std::fs::write(path, b"test").unwrap();
    }

    fn write_valid_builder_cache_artifacts(dir: &std::path::Path) {
        // Satisfies `validate_builder_vm_stage0_artifacts` (size floor +
        // ext4 magic). The deeper inode check lives in
        // `verify_stage0_rootfs_has_init`, exercised against a real ext4
        // image by `verify_stage0_rootfs_has_init_*` below.
        const EXT4_MAGIC_OFFSET: usize = 1024 + 56;
        std::fs::create_dir_all(dir).expect("mkdir artifact dir");
        std::fs::write(dir.join("vmlinux"), vec![0x7f; 1024 * 1024 + 1]).expect("write kernel");
        let mut rootfs = vec![0u8; 4 * 1024 * 1024 + 1];
        rootfs[EXT4_MAGIC_OFFSET] = 0x53;
        rootfs[EXT4_MAGIC_OFFSET + 1] = 0xEF;
        std::fs::write(dir.join("rootfs.ext4"), rootfs).expect("write rootfs");
    }

    fn write_builder_vm_flake(dir: &std::path::Path) {
        std::fs::create_dir_all(dir).expect("mkdir flake dir");
        std::fs::write(dir.join("flake.nix"), "{ outputs = _: {}; }").expect("write flake");
        std::fs::write(dir.join("flake.lock"), "{\"nodes\":{}}").expect("write lock");
    }

    /// Stage the workspace prerequisites that `builder_vm_source_fingerprint`
    /// reads beyond the flake dir: a `Cargo.lock` at the workspace root.
    /// Without it, a test calling the fingerprint helper against a fresh
    /// tempdir-rooted flake at `<tmp>/nix/images/builder-vm` blows up with
    /// `builder VM source fingerprint missing <tmp>/Cargo.lock`. (The
    /// in-VM binary identity comes from the embedded host-binary bytes,
    /// not on-disk crate dirs, so no crate stubs are needed.)
    ///
    /// Matches `builder_vm_bootstrap_tests::write_builder_vm_workspace`
    /// in shape; lives here as well because the two test mods are
    /// independent and we don't want to plumb a cross-mod helper just
    /// for two callers.
    fn write_builder_vm_workspace_prereqs(workspace_root: &std::path::Path) {
        std::fs::write(workspace_root.join("Cargo.lock"), "# stub Cargo.lock\n")
            .expect("write Cargo.lock");
    }

    #[test]
    fn status_image_reports_current_data_dir_image() {
        let _lock = ENV_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let _env = EnvGuard::set(
            &tmp.path().join("home"),
            &tmp.path().join("data"),
            &tmp.path().join("cache"),
        );
        let kernel = tmp.path().join("data/dev/current/vmlinux");
        let rootfs = tmp.path().join("data/dev/current/rootfs.ext4");
        touch(&kernel);
        touch(&rootfs);

        assert_eq!(
            resolve_dev_status_image(),
            Some(DevStatusImage {
                kernel_path: Some(kernel.to_string_lossy().into_owned()),
                rootfs_path: rootfs.to_string_lossy().into_owned(),
            })
        );
    }

    #[test]
    fn status_image_reports_versioned_prebuilt_when_current_missing() {
        let _lock = ENV_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path().join("data");
        let _env = EnvGuard::set(
            &tmp.path().join("home"),
            &data_dir,
            &tmp.path().join("cache"),
        );
        let dir = data_dir
            .join("dev/prebuilt")
            .join(format!("v{}", env!("CARGO_PKG_VERSION")));
        let rootfs = dir.join("rootfs.ext4");
        touch(&rootfs);

        assert_eq!(
            resolve_dev_status_image(),
            Some(DevStatusImage {
                kernel_path: None,
                rootfs_path: rootfs.to_string_lossy().into_owned(),
            })
        );
    }

    #[test]
    fn status_image_falls_back_to_legacy_cache_dir() {
        let _lock = ENV_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let cache_dir = tmp.path().join("cache");
        let _env = EnvGuard::set(
            &tmp.path().join("home"),
            &tmp.path().join("data"),
            &cache_dir,
        );
        let rootfs = cache_dir.join("dev/rootfs.ext4");
        touch(&rootfs);

        assert_eq!(
            resolve_dev_status_image(),
            Some(DevStatusImage {
                kernel_path: None,
                rootfs_path: rootfs.to_string_lossy().into_owned(),
            })
        );
    }

    #[test]
    fn status_image_is_none_when_no_rootfs_exists() {
        let _lock = ENV_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let _env = EnvGuard::set(
            &tmp.path().join("home"),
            &tmp.path().join("data"),
            &tmp.path().join("cache"),
        );

        assert_eq!(resolve_dev_status_image(), None);
    }

    /// Write a `(vmlinux, rootfs.ext4)` pair that satisfies
    /// `validate_dev_image_artifacts` (size floor + ext4 magic).
    fn write_valid_dev_image(dir: &std::path::Path) {
        const EXT4_MAGIC_OFFSET: usize = 1024 + 56;
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join("vmlinux"), vec![0x7f; 1024 * 1024 + 1]).unwrap();
        let mut rootfs = vec![0u8; 4 * 1024 * 1024 + 1];
        rootfs[EXT4_MAGIC_OFFSET] = 0x53;
        rootfs[EXT4_MAGIC_OFFSET + 1] = 0xEF;
        std::fs::write(dir.join("rootfs.ext4"), rootfs).unwrap();
    }

    /// `~/.mvm/dev/current/` is the load-bearing seed for
    /// Stage 0 when the builder VM cache is empty but a dev image was
    /// previously built on this host. Closes the gap where a contributor
    /// who deleted `~/.cache/mvm/builder-vm/<arch>/` got a hard error
    /// even though a valid seed was sitting at `dev/current/`.
    #[test]
    fn fallback_image_finds_dev_current() {
        let _lock = ENV_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path().join("data");
        let _env = EnvGuard::set(
            &tmp.path().join("home"),
            &data_dir,
            &tmp.path().join("cache"),
        );

        let current = data_dir.join("dev/current");
        write_valid_dev_image(&current);

        let (kernel, rootfs, label) =
            find_local_fallback_image().expect("dev/current/ pair must be discovered");
        assert_eq!(kernel, current.join("vmlinux"));
        assert_eq!(rootfs, current.join("rootfs.ext4"));
        assert_eq!(label, "current");
    }

    /// When multiple candidates exist, the most-recently-modified one
    /// wins. Guards against a stale `prebuilt/` entry hiding a fresh
    /// `current/` image (or vice versa).
    #[test]
    fn fallback_image_prefers_most_recent_candidate() {
        let _lock = ENV_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path().join("data");
        let _env = EnvGuard::set(
            &tmp.path().join("home"),
            &data_dir,
            &tmp.path().join("cache"),
        );

        let prebuilt = data_dir.join("dev/prebuilt/v0.0.1");
        let current = data_dir.join("dev/current");
        write_valid_dev_image(&prebuilt);
        write_valid_dev_image(&current);
        // Force `current/` to be strictly newer than `prebuilt/` —
        // coarse-mtime filesystems (HFS+, some tmpfs) can otherwise
        // collide two writes into the same second.
        let later = std::time::SystemTime::now() + std::time::Duration::from_secs(2);
        std::fs::OpenOptions::new()
            .write(true)
            .open(current.join("rootfs.ext4"))
            .unwrap()
            .set_modified(later)
            .unwrap();

        let (_, _, label) = find_local_fallback_image().expect("a candidate must be discovered");
        assert_eq!(label, "current");
    }

    /// No candidates anywhere → `None`. Smoke-test for the empty case.
    #[test]
    fn fallback_image_is_none_when_no_pair_exists() {
        let _lock = ENV_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let _env = EnvGuard::set(
            &tmp.path().join("home"),
            &tmp.path().join("data"),
            &tmp.path().join("cache"),
        );

        assert!(find_local_fallback_image().is_none());
    }

    #[test]
    fn builder_cache_status_reports_source_cache_hit_without_paths() {
        let tmp = tempfile::tempdir().unwrap();
        let flake = tmp.path().join("nix/images/builder-vm");
        let cache_root = tmp.path().join("cache");
        let cache = cache_root.join("builder-vm/testarch");
        write_builder_vm_flake(&flake);
        write_builder_vm_workspace_prereqs(tmp.path());
        write_valid_builder_cache_artifacts(&cache);
        let fingerprint = builder_vm_source_fingerprint(flake.to_str().unwrap()).unwrap();
        write_builder_vm_source_fingerprint(&cache, &fingerprint).unwrap();
        write_builder_vm_artifact_digest_manifest(&cache).unwrap();
        write_builder_vm_source_cache_provenance(&cache, &fingerprint).unwrap();

        assert_eq!(
            builder_vm_cache_status_summary(
                Ok(flake.to_string_lossy().into_owned()),
                &cache_root,
                "testarch"
            ),
            BuilderVmCacheStatusSummary {
                cache_kind: "source",
                state: BuilderVmCacheState::Ready,
                reason_code: "hit",
            }
        );
    }

    #[test]
    fn builder_cache_status_reports_source_provenance_drift() {
        let tmp = tempfile::tempdir().unwrap();
        let flake = tmp.path().join("nix/images/builder-vm");
        let cache_root = tmp.path().join("cache");
        let cache = cache_root.join("builder-vm/testarch");
        write_builder_vm_flake(&flake);
        write_builder_vm_workspace_prereqs(tmp.path());
        write_valid_builder_cache_artifacts(&cache);
        let fingerprint = builder_vm_source_fingerprint(flake.to_str().unwrap()).unwrap();
        write_builder_vm_source_fingerprint(&cache, &fingerprint).unwrap();
        write_builder_vm_artifact_digest_manifest(&cache).unwrap();

        assert_eq!(
            builder_vm_cache_status_summary(
                Ok(flake.to_string_lossy().into_owned()),
                &cache_root,
                "testarch"
            ),
            BuilderVmCacheStatusSummary {
                cache_kind: "source",
                state: BuilderVmCacheState::Stale,
                reason_code: "missing_provenance",
            }
        );
    }

    #[test]
    fn builder_cache_status_reports_release_cache_without_source_flake() {
        let tmp = tempfile::tempdir().unwrap();
        let cache_root = tmp.path().join("cache");

        assert_eq!(
            builder_vm_cache_status_summary(
                Err(anyhow::anyhow!("missing source flake")),
                &cache_root,
                "testarch",
            ),
            BuilderVmCacheStatusSummary {
                cache_kind: "release",
                state: BuilderVmCacheState::Stale,
                reason_code: "missing_or_invalid_artifacts",
            }
        );

        write_valid_builder_cache_artifacts(&cache_root.join("builder-vm/testarch"));
        assert_eq!(
            builder_vm_cache_status_summary(
                Err(anyhow::anyhow!("missing source flake")),
                &cache_root,
                "testarch",
            ),
            BuilderVmCacheStatusSummary {
                cache_kind: "release",
                state: BuilderVmCacheState::Ready,
                reason_code: "hit",
            }
        );
    }

    #[test]
    fn dev_image_cache_summary_never_includes_paths() {
        let image = DevStatusImage {
            kernel_path: Some("/private/tmp/mvm/vmlinux".to_string()),
            rootfs_path: "/private/tmp/mvm/rootfs.ext4".to_string(),
        };

        assert_eq!(
            dev_image_cache_summary(Some(&image)),
            DevImageCacheSummary {
                state: "cached",
                kernel: "present",
                rootfs: "present",
            }
        );
        assert_eq!(
            dev_image_cache_summary(None),
            DevImageCacheSummary {
                state: "missing",
                kernel: "missing",
                rootfs: "missing",
            }
        );
    }

    #[test]
    fn dev_cache_inspect_json_omits_paths_and_digests() {
        let summary = DevCacheInspectSummary {
            dev_image: DevImageCacheSummary {
                state: "cached",
                kernel: "present",
                rootfs: "present",
            },
            builder_cache: BuilderVmCacheStatusSummary {
                cache_kind: "source",
                state: BuilderVmCacheState::Ready,
                reason_code: "hit",
            },
        };

        let json = dev_cache_inspect_json(&summary).expect("serialize JSON");
        assert!(json.contains("\"schema_version\": 1"));
        assert!(json.contains("\"builder_cache\""));
        assert!(json.contains("\"reason_code\": \"hit\""));
        assert!(!json.contains("/private/tmp"));
        assert!(!json.contains("sha256"));
        assert!(!json.contains("rootfs.ext4"));
        assert!(!json.contains("vmlinux"));
    }

    #[test]
    fn dev_status_json_is_versioned_and_privacy_safe() {
        // A VM-backed report carries the backend, the fixed dev VM name,
        // the state, and a guest-probed kernel version — but never a local
        // artifact path or digest (same privacy floor as cache-inspect).
        let report = build_dev_status_json("vz", "running", Some("6.1.0-mvm".to_string()));
        assert_eq!(report.schema_version, 1);
        assert_eq!(report.backend, "vz");
        assert_eq!(report.vm_name, Some(DEV_VM_NAME));
        assert_eq!(report.state, "running");
        assert_eq!(report.guest_kernel.as_deref(), Some("6.1.0-mvm"));
        assert!(report.dev_image.is_some());
        assert!(report.builder_cache.is_some());

        let json = crate::json_out::to_json_string(&report).expect("serialize");
        assert!(json.contains("\"backend\": \"vz\""));
        assert!(json.contains("\"state\": \"running\""));
        assert!(json.contains("\"guest_kernel\": \"6.1.0-mvm\""));
        // No absolute paths / image filenames / digests leak.
        assert!(!json.contains("/Users"));
        assert!(!json.contains("/private/tmp"));
        assert!(!json.contains("rootfs.ext4"));
        assert!(!json.contains("vmlinux"));
        assert!(!json.contains("sha256"));
    }

    #[test]
    fn dev_status_json_stopped_omits_kernel() {
        // A stopped VM has no guest to probe; `guest_kernel` is skipped, not null.
        let report = build_dev_status_json("vz", "stopped", None);
        assert_eq!(report.state, "stopped");
        assert!(report.guest_kernel.is_none());
        let json = crate::json_out::to_json_string(&report).expect("serialize");
        assert!(!json.contains("\"guest_kernel\""));
    }

    #[test]
    fn dev_status_json_vmless_omits_vm_and_caches() {
        // Host-native / unsupported hosts have no managed dev VM: vm_name,
        // dev_image, and builder_cache are absent (not null).
        let report = build_dev_status_json_vmless("linux-native", "ready");
        assert_eq!(report.backend, "linux-native");
        assert_eq!(report.state, "ready");
        assert!(report.vm_name.is_none());
        assert!(report.dev_image.is_none());
        assert!(report.builder_cache.is_none());
        let json = crate::json_out::to_json_string(&report).expect("serialize");
        assert!(json.contains("\"backend\": \"linux-native\""));
        assert!(!json.contains("\"vm_name\""));
        assert!(!json.contains("\"dev_image\""));
        assert!(!json.contains("\"builder_cache\""));
    }

    #[test]
    fn dev_down_json_reports_stopped_and_omits_reset_when_false() {
        let report = build_dev_down_json("vz", true, false);
        assert_eq!(report.schema_version, 1);
        assert_eq!(report.backend, "vz");
        assert_eq!(report.action, "down");
        assert_eq!(report.outcome, "stopped");
        let json = crate::json_out::to_json_string(&report).expect("serialize");
        assert!(json.contains("\"action\": \"down\""));
        assert!(json.contains("\"outcome\": \"stopped\""));
        // `reset` defaults false and is skipped, not serialized as false.
        assert!(!json.contains("\"reset\""));
    }

    #[test]
    fn dev_down_json_reports_not_running_and_reset() {
        let report = build_dev_down_json("libkrun", false, true);
        assert_eq!(report.outcome, "not-running");
        assert!(report.reset);
        let json = crate::json_out::to_json_string(&report).expect("serialize");
        assert!(json.contains("\"outcome\": \"not-running\""));
        assert!(json.contains("\"reset\": true"));
    }

    #[test]
    fn dev_up_json_reports_outcome_and_omits_reset() {
        let started = build_dev_up_json("vz", "started");
        assert_eq!(started.action, "up");
        assert_eq!(started.outcome, "started");
        assert_eq!(started.backend, "vz");
        let json = crate::json_out::to_json_string(&started).expect("serialize");
        assert!(json.contains("\"action\": \"up\""));
        assert!(json.contains("\"outcome\": \"started\""));
        // `reset` is down-only; the up shape never emits it.
        assert!(!json.contains("\"reset\""));

        let already = build_dev_up_json("libkrun", "already-running");
        assert_eq!(already.outcome, "already-running");
    }
}

#[cfg(test)]
mod reap_orphans_tests {
    use super::*;

    #[test]
    fn missing_vms_root_is_empty_outcome() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vms_root = dir.path().join("does-not-exist");
        let out =
            reap_orphaned_vm_helpers_at(&vms_root, BUILDER_SIDECARS, true, false).expect("reap");
        assert_eq!(out.killed, 0);
        assert_eq!(out.removed_dirs, 0);
        assert_eq!(out.freed_bytes, 0);
    }

    #[test]
    fn dead_pids_get_their_dirs_swept() {
        // A VM dir whose `builder.pid` references a long-dead PID
        // (we use `1` and skip it via read_pid_file's `> 1` guard, so
        // instead use a PID that's very unlikely to be alive). The
        // reaper should remove the dir and count `removed_dirs += 1`
        // without trying to kill anyone.
        let dir = tempfile::tempdir().expect("tempdir");
        let vms_root = dir.path().join("vms");
        let vm = vms_root.join("mvm-stage0-99999-1234567890");
        std::fs::create_dir_all(&vm).expect("mkdir");
        // pick a PID guaranteed not to exist: 2^31-2 (one less than i32::MAX,
        // outside normal kernel allocation range on macOS/Linux)
        std::fs::write(vm.join("builder.pid"), "2147483646\n").expect("write pid");
        std::fs::write(vm.join("payload"), vec![0u8; 1024]).expect("write payload");

        let out =
            reap_orphaned_vm_helpers_at(&vms_root, BUILDER_SIDECARS, true, false).expect("reap");
        assert_eq!(out.killed, 0, "no live PID, so nothing to kill");
        assert_eq!(out.removed_dirs, 1, "dir should be removed");
        assert!(out.freed_bytes >= 1024, "payload size counted");
        assert!(!vm.exists(), "dir should be gone");
    }

    #[test]
    fn live_owner_preserves_dir_in_dry_run_and_real() {
        // A VM dir whose `builder.pid` references THIS test's PID.
        // The test process's parent is cargo/test runner, not launchd
        // PID 1, so `pid_parent != Some(1)` → reaper marks the dir as
        // "has a live owner" and leaves it alone.
        let dir = tempfile::tempdir().expect("tempdir");
        let vms_root = dir.path().join("vms");
        let vm = vms_root.join("mvm-stage0-pid-of-self");
        std::fs::create_dir_all(&vm).expect("mkdir");
        let my_pid = std::process::id() as i32;
        std::fs::write(vm.join("builder.pid"), format!("{my_pid}\n")).expect("write pid");

        let out =
            reap_orphaned_vm_helpers_at(&vms_root, BUILDER_SIDECARS, true, false).expect("reap");
        assert_eq!(out.killed, 0, "live owner should not be killed");
        assert_eq!(out.removed_dirs, 0, "dir preserved while owner alive");
        assert!(vm.exists(), "dir should still be on disk");
    }

    #[test]
    fn workload_root_preserves_dir_with_dead_pid() {
        // Workload VM dirs (`~/.mvm/vms/<name>/`) are persistent state —
        // a stopped named VM the user may restart. The reaper must reap
        // their leaked helpers but NEVER delete the dir, even when its
        // supervisor PID is long dead. `remove_dead_dirs = false` is the
        // contract; this pins it against a regression that would `rm -rf`
        // a user's stopped-VM state.
        let dir = tempfile::tempdir().expect("tempdir");
        let vms_root = dir.path().join("vms");
        // Basename must not substring-match any live process — Scan 2
        // argv-scans the whole host via `pgrep -f <basename>`, so a
        // realistic VM name (e.g. "silly-experience") could match a real
        // leaked daemon and pollute the count. Use an unmistakable one.
        let vm = vms_root.join("mvm-workload-reaptest-7f3a9c-deadpid");
        std::fs::create_dir_all(&vm).expect("mkdir");
        std::fs::write(vm.join("libkrun.pid"), "2147483646\n").expect("write pid");
        std::fs::write(vm.join("config"), vec![0u8; 512]).expect("write state");

        let out = reap_orphaned_vm_helpers_at(&vms_root, WORKLOAD_SIDECARS, false, false)
            .expect("reap workload root");
        assert_eq!(out.killed, 0, "dead PID, nothing to kill");
        assert_eq!(out.removed_dirs, 0, "workload dir must never be removed");
        assert!(vm.exists(), "workload VM state dir must survive the sweep");
        assert!(vm.join("config").exists(), "persistent state untouched");
    }

    #[test]
    fn dry_run_does_not_mutate() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vms_root = dir.path().join("vms");
        let vm = vms_root.join("mvm-stage0-dryrun-test");
        std::fs::create_dir_all(&vm).expect("mkdir");
        std::fs::write(vm.join("builder.pid"), "2147483646\n").expect("write pid");
        std::fs::write(vm.join("payload"), vec![0u8; 256]).expect("write payload");

        let out = reap_orphaned_vm_helpers_at(&vms_root, BUILDER_SIDECARS, true, true)
            .expect("dry-run reap");
        // Dry-run still *counts* what it would do, but doesn't mutate.
        assert_eq!(out.removed_dirs, 1);
        assert!(vm.exists(), "dry-run must not remove the dir");
        assert!(vm.join("builder.pid").exists(), "pid file untouched");
    }
}

#[cfg(test)]
mod builder_vm_bootstrap_tests {
    //! `find_builder_vm_flake` + `bootstrap_builder_vm_image`.
    use super::*;
    use std::io::Write;

    #[test]
    fn find_builder_vm_flake_resolves_to_in_repo_path() {
        // From a source checkout, the helper must find the
        // flake at <workspace>/nix/images/builder-vm/flake.nix.
        // `env!("CARGO_MANIFEST_DIR")` is baked at compile time
        // and points at the workspace's mvm-cli crate dir, so
        // this assertion is robust across `cargo test` and
        // `cargo nextest`.
        let path = find_builder_vm_flake().expect("expected builder-vm flake present in repo");
        assert!(
            path.ends_with("nix/images/builder-vm"),
            "unexpected flake path: {path}"
        );
        // The flake file itself must be readable.
        assert!(
            std::path::Path::new(&path).join("flake.nix").is_file(),
            "flake.nix missing under {path}"
        );
    }

    /// Per-arch artifact filenames must match what the release
    /// workflow's `builder-vm-image` job uploads. Pure function —
    /// asserts the contract between `builder_vm_artifact_names()`
    /// (the consumer side that constructs download URLs) and the
    /// `cp "$STORE_PATH/..." "staging/builder-vm-..."` lines in
    /// `.github/workflows/release.yml` (the producer side).
    #[test]
    fn builder_vm_artifact_names_match_release_workflow() {
        let n = builder_vm_artifact_names("aarch64");
        assert_eq!(n.kernel, "builder-vm-vmlinux-aarch64");
        assert_eq!(n.rootfs, "builder-vm-rootfs-aarch64.ext4");
        assert_eq!(n.cmdline, "builder-vm-aarch64.cmdline.txt");
        assert_eq!(n.manifest, "builder-vm-aarch64.manifest.json");
        assert_eq!(n.checksums, "builder-vm-aarch64-checksums-sha256.txt");

        let n = builder_vm_artifact_names("x86_64");
        assert_eq!(n.kernel, "builder-vm-vmlinux-x86_64");
        assert_eq!(n.rootfs, "builder-vm-rootfs-x86_64.ext4");
        assert_eq!(n.cmdline, "builder-vm-x86_64.cmdline.txt");
        assert_eq!(n.manifest, "builder-vm-x86_64.manifest.json");
        assert_eq!(n.checksums, "builder-vm-x86_64-checksums-sha256.txt");
    }

    #[test]
    fn builder_vm_bootstrap_uses_cache_even_in_source_checkout() {
        let action = resolve_builder_vm_bootstrap_action(
            Ok("/repo/nix/images/builder-vm".to_string()),
            true,
        )
        .expect("cache hit should be usable in a source checkout");

        assert_eq!(action, BuilderVmBootstrapAction::UseCached);
    }

    #[test]
    fn builder_vm_bootstrap_source_checkout_builds_from_source_on_cache_miss() {
        let action = resolve_builder_vm_bootstrap_action(
            Ok("/repo/nix/images/builder-vm".to_string()),
            false,
        )
        .expect("source checkout cache miss should route to local source build");

        assert_eq!(
            action,
            BuilderVmBootstrapAction::BuildFromSource {
                flake_dir: "/repo/nix/images/builder-vm".to_string()
            }
        );
    }

    #[test]
    fn builder_vm_bootstrap_installed_binary_may_download_on_cache_miss() {
        let action =
            resolve_builder_vm_bootstrap_action(Err(anyhow::anyhow!("no source flake")), false)
                .expect("installed binaries may use published prebuilts");

        assert_eq!(action, BuilderVmBootstrapAction::DownloadPublished);
    }

    /// Even when the resolver routes to `DownloadPublished`,
    /// a contributor build (no `release-artifact-bootstrap` feature) must
    /// refuse to invoke the download path and surface a clear structural
    /// error. This locks the AGENTS.md / CLAUDE.md "no prebuilt builder
    /// VM artifact" invariant into the type system rather than runtime
    /// branch order. The companion sibling under
    /// `#[cfg(feature = "release-artifact-bootstrap")]` would need a
    /// network mock; we cover the structural-failure side here because
    /// it's the one contributors hit.
    #[cfg(not(feature = "release-artifact-bootstrap"))]
    #[test]
    fn perform_builder_vm_download_published_bails_without_feature() {
        let err = perform_builder_vm_download_published("aarch64", "/tmp/mvm-w4-test-out")
            .expect_err("download must refuse without release-artifact-bootstrap");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("release-artifact-bootstrap"),
            "error must name the feature flag: {msg}"
        );
        assert!(
            msg.contains("nix/images/builder-vm/flake.nix"),
            "error must point at the source-checkout remediation: {msg}"
        );
        // Critically: the bail must happen before any directory creation.
        // Otherwise a contributor running on a shared host could pollute
        // `/tmp/...` even when the gate is "closed".
        assert!(
            !std::path::Path::new("/tmp/mvm-w4-test-out").exists(),
            "structural failure must not touch the filesystem"
        );
    }

    fn write_valid_builder_vm_artifacts(dir: &std::path::Path) {
        const EXT4_MAGIC_OFFSET: usize = 1024 + 56;
        std::fs::create_dir_all(dir).expect("mkdir artifact dir");
        std::fs::write(dir.join("vmlinux"), vec![0x7f; 1024 * 1024 + 1]).expect("write kernel");
        let mut rootfs = vec![0u8; 4 * 1024 * 1024 + 1];
        rootfs[EXT4_MAGIC_OFFSET] = 0x53;
        rootfs[EXT4_MAGIC_OFFSET + 1] = 0xEF;
        std::fs::write(dir.join("rootfs.ext4"), rootfs).expect("write rootfs");
    }

    fn write_builder_vm_flake(dir: &std::path::Path, flake: &str, lock: Option<&str>) {
        std::fs::create_dir_all(dir).expect("mkdir flake dir");
        std::fs::write(dir.join("flake.nix"), flake).expect("write flake");
        if let Some(lock) = lock {
            std::fs::write(dir.join("flake.lock"), lock).expect("write lock");
        }
    }

    fn write_builder_vm_source_cache_metadata(dir: &std::path::Path, fingerprint: &str) {
        write_builder_vm_source_fingerprint(dir, fingerprint).expect("write fingerprint");
        write_builder_vm_artifact_digest_manifest(dir).expect("write artifact digest manifest");
        write_builder_vm_source_cache_provenance(dir, fingerprint).expect("write provenance");
    }

    /// `acquire_stage0_lock` is an advisory `flock(2)`
    /// guard at `<cache_parent>/stage0.lock`. The first acquisition
    /// succeeds; a second concurrent attempt while the first guard is
    /// still in scope fails fast with a recognizable message; once the
    /// first guard drops, the lock becomes available again.
    #[test]
    fn stage0_lock_refuses_concurrent_acquisition() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let out_dir = tmp.path().join("aarch64");
        let out_dir_str = out_dir.to_str().expect("utf-8 out_dir");

        let first = acquire_stage0_lock_uncontended(out_dir_str);
        // Lock file lives one directory above out_dir, named `stage0.lock`.
        assert!(
            tmp.path().join("stage0.lock").exists(),
            "stage0.lock should be created on first acquisition"
        );

        let err = match acquire_stage0_lock(out_dir_str) {
            Err(e) => e,
            Ok(_) => panic!("second acquisition must refuse while first is held"),
        };
        let msg = format!("{err:#}");
        assert!(
            msg.contains("already bootstrapping the builder VM image"),
            "unexpected error: {msg}"
        );
        assert!(
            msg.contains("stage0.lock"),
            "error should name the lock file path: {msg}"
        );

        drop(first);

        // Now reachable again — guards must not leak past their scope.
        let _second = acquire_stage0_lock_uncontended(out_dir_str);
    }

    /// Lock setup must not fail when the parent cache directory does
    /// not yet exist on disk (fresh contributor host). `acquire_stage0_lock`
    /// is responsible for creating it.
    #[test]
    fn stage0_lock_creates_missing_cache_parent() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let nested = tmp.path().join("nested/builder-vm/aarch64");
        let nested_str = nested.to_str().expect("utf-8 nested");

        let _guard = acquire_stage0_lock_uncontended(nested_str);
        assert!(
            tmp.path().join("nested/builder-vm/stage0.lock").exists(),
            "lock file must be created at the constructed parent path"
        );
    }

    /// Name predicate must match both the current hidden
    /// `.<arch>.stage0-<pid>-<nonce>` form and the legacy
    /// `<arch>-staging[-...]` form, and reject everything else that
    /// lives alongside under `~/.cache/mvm/builder-vm/` (live cache
    /// dirs `aarch64/` / `x86_64/`, the `nix-store-<arch>.img` blob,
    /// `jobs/`, `vms/`, `stage0.lock`, sundry dotfiles).
    #[test]
    fn is_orphan_stage0_staging_dir_name_matches_known_shapes() {
        // Current hidden form (matches `unique_builder_vm_stage0_staging_dir`).
        assert!(is_orphan_stage0_staging_dir_name(
            ".aarch64.stage0-12345-1700000000000000000"
        ));
        assert!(is_orphan_stage0_staging_dir_name(
            ".x86_64.stage0-99999-1700000000000000000"
        ));
        // Legacy plain form.
        assert!(is_orphan_stage0_staging_dir_name("aarch64-staging"));
        assert!(is_orphan_stage0_staging_dir_name("x86_64-staging-foo"));

        // Negatives: everything that legitimately lives next to
        // staging dirs must be left alone.
        assert!(!is_orphan_stage0_staging_dir_name("aarch64"));
        assert!(!is_orphan_stage0_staging_dir_name("x86_64"));
        assert!(!is_orphan_stage0_staging_dir_name("jobs"));
        assert!(!is_orphan_stage0_staging_dir_name("vms"));
        assert!(!is_orphan_stage0_staging_dir_name("stage0.lock"));
        assert!(!is_orphan_stage0_staging_dir_name("nix-store-aarch64.img"));
        assert!(!is_orphan_stage0_staging_dir_name("nix-store-x86_64.img"));
        // Dotfile that isn't a staging dir.
        assert!(!is_orphan_stage0_staging_dir_name(".DS_Store"));
        // Unknown arch suffixes are conservative-deny.
        assert!(!is_orphan_stage0_staging_dir_name(".riscv64.stage0-1-2"));
        assert!(!is_orphan_stage0_staging_dir_name("riscv64-staging"));
    }

    /// `flock(2)` can spuriously report `EWOULDBLOCK` on a brand-new,
    /// uncontended lock path when hundreds of test threads hammer the
    /// syscall in parallel (seen as `acquire_stage0_lock` → `Err` /
    /// `sweep` → `SkippedLockHeld` on paths no other test can possibly
    /// hold). These helpers retry the *uncontended* acquisitions a bounded
    /// number of times: the test owns the only would-be holder, so a
    /// reported block here is always spurious. Tests that deliberately
    /// contend the lock (`sweep_skips_when_stage0_lock_is_held`) do not use
    /// these — they want the real "held" outcome.
    fn acquire_stage0_lock_uncontended(out_dir: &str) -> mvm_core::atomic_io::FileLock {
        for attempt in 0..200u32 {
            match acquire_stage0_lock(out_dir) {
                Ok(guard) => return guard,
                Err(e) => {
                    assert!(
                        attempt < 199,
                        "stage0 lock stayed spuriously blocked: {e:#}"
                    );
                    std::thread::sleep(std::time::Duration::from_millis(2));
                }
            }
        }
        unreachable!()
    }

    fn try_acquire_filelock_uncontended(anchor: &std::path::Path) -> mvm_core::atomic_io::FileLock {
        use mvm_core::atomic_io::FileLock;
        for attempt in 0..200u32 {
            match FileLock::try_acquire(anchor) {
                Ok(Some(guard)) => return guard,
                Ok(None) => {
                    assert!(attempt < 199, "flock stayed spuriously blocked");
                    std::thread::sleep(std::time::Duration::from_millis(2));
                }
                Err(e) => panic!("flock error: {e:#}"),
            }
        }
        unreachable!()
    }

    fn sweep_uncontended(root: &std::path::Path, dry_run: bool) -> Stage0SweepOutcome {
        for attempt in 0..200u32 {
            match sweep_orphaned_stage0_staging_dirs_at(root, dry_run)
                .expect("sweep should succeed")
            {
                Stage0SweepOutcome::SkippedLockHeld => {
                    assert!(attempt < 199, "sweep stayed spuriously lock-blocked");
                    std::thread::sleep(std::time::Duration::from_millis(2));
                }
                swept => return swept,
            }
        }
        unreachable!()
    }

    /// Build the representative sweep layout under `root`: one orphan
    /// staging dir (18 bytes across two files), a live cache dir, and an
    /// unrelated nix-store image sibling. Returns the three paths.
    fn stage_sweep_layout(
        root: &std::path::Path,
    ) -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
        let orphan = root.join(".aarch64.stage0-12345-1700000000000000000");
        std::fs::create_dir_all(orphan.join("nested")).unwrap();
        std::fs::write(orphan.join("a"), b"hello world").unwrap(); // 11 bytes
        std::fs::write(orphan.join("nested/b"), vec![0u8; 7]).unwrap();

        let live_cache = root.join("aarch64");
        std::fs::create_dir_all(&live_cache).unwrap();
        std::fs::write(live_cache.join("rootfs.ext4"), b"do-not-delete").unwrap();

        let nix_store = root.join("nix-store-aarch64.img");
        std::fs::write(&nix_store, b"sparse").unwrap();
        (orphan, live_cache, nix_store)
    }

    // NOTE: the dry-run and real-run sweeps are split into two tests on
    // purpose. A single test that swept twice took the Stage 0 `flock`,
    // released it, then re-took it on the *same* path microseconds later;
    // under parallel test load the close()-release / flock()-reacquire
    // window intermittently surfaced `EWOULDBLOCK` (a `SkippedLockHeld`
    // false positive). One acquire per test removes the self-race; the
    // unique tempdir per test keeps them independent.

    /// The dry-run sweep is purely observational: it reports
    /// the orphan + byte count but mutates nothing.
    #[test]
    fn sweep_dry_run_reports_orphan_without_removing() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = tmp.path().to_path_buf();
        let (orphan, live_cache, _nix_store) = stage_sweep_layout(&root);

        match sweep_uncontended(&root, true) {
            Stage0SweepOutcome::Swept {
                removed,
                freed_bytes,
            } => {
                assert_eq!(removed, 1, "dry-run reports the orphan");
                assert_eq!(freed_bytes, 18, "dry-run reports the orphan's byte total");
            }
            Stage0SweepOutcome::SkippedLockHeld => panic!("dry-run must not skip"),
        }
        assert!(orphan.is_dir(), "dry-run must not remove the orphan");
        assert!(live_cache.is_dir(), "dry-run must not touch the live cache");
    }

    /// The real sweep removes the orphan staging dir, reports
    /// its byte count, and leaves the live cache and unrelated siblings
    /// intact.
    #[test]
    fn sweep_real_run_removes_orphan_and_leaves_siblings() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = tmp.path().to_path_buf();
        let (orphan, live_cache, nix_store) = stage_sweep_layout(&root);

        match sweep_uncontended(&root, false) {
            Stage0SweepOutcome::Swept {
                removed,
                freed_bytes,
            } => {
                assert_eq!(removed, 1);
                assert_eq!(freed_bytes, 18);
            }
            Stage0SweepOutcome::SkippedLockHeld => panic!("must not skip on uncontended lock"),
        }
        assert!(!orphan.exists(), "orphan must be removed");
        assert!(
            live_cache.join("rootfs.ext4").is_file(),
            "live cache must be untouched"
        );
        assert!(nix_store.is_file(), "nix-store image must be untouched");
    }

    /// When a live Stage 0 is in progress and holds the
    /// advisory lock, the sweep must skip rather than race the
    /// staging dir the live run is about to promote.
    #[test]
    fn sweep_skips_when_stage0_lock_is_held() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = tmp.path().to_path_buf();
        std::fs::create_dir_all(&root).unwrap();

        // Hold the lock as a "live" Stage 0 would.
        let _live = try_acquire_filelock_uncontended(&root.join("stage0"));

        // Stage an orphan to confirm the sweep would have something to do.
        let orphan = root.join(".aarch64.stage0-12345-1700000000000000000");
        std::fs::create_dir_all(&orphan).unwrap();

        match sweep_orphaned_stage0_staging_dirs_at(&root, false)
            .expect("sweep should succeed even when skipping")
        {
            Stage0SweepOutcome::SkippedLockHeld => {}
            Stage0SweepOutcome::Swept { .. } => {
                panic!("sweep must skip while the Stage 0 lock is held")
            }
        }
        assert!(
            orphan.is_dir(),
            "skipped sweep must not touch the would-be orphan"
        );
    }

    /// Sweep on a non-existent root is a no-op. Exercises
    /// the early-return for fresh hosts that have never run `dev up`.
    #[test]
    fn sweep_is_noop_when_root_missing() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let missing = tmp.path().join("never-existed");

        match sweep_orphaned_stage0_staging_dirs_at(&missing, false)
            .expect("sweep on missing root should succeed")
        {
            Stage0SweepOutcome::Swept {
                removed,
                freed_bytes,
            } => {
                assert_eq!(removed, 0);
                assert_eq!(freed_bytes, 0);
            }
            Stage0SweepOutcome::SkippedLockHeld => {
                panic!("missing root must not look like lock contention")
            }
        }
    }

    /// Pin that the orphan reaper covers `mvm-builder-vz-<job_id>`
    /// dirs the same way it covers
    /// `mvm-builder-vm-<job_id>`. The traversal in
    /// `reap_orphaned_vm_helpers_at` is prefix-agnostic and
    /// `VzBuilderVm` writes a `builder.pid` sidecar under the shared
    /// `~/.cache/mvm/builder-vm/vms/` tree; this test guards against
    /// a future refactor narrowing either invariant.
    #[test]
    fn reap_picks_up_orphaned_vz_builder_state_dir() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let vms = tmp.path();
        let vz_dir = vms.join("mvm-builder-vz-abc12345");
        std::fs::create_dir_all(&vz_dir).unwrap();
        // `i32::MAX` is guaranteed not to be a live process on any
        // supported host — classify_pid → Dead, so the dir has no
        // live owner and is eligible for removal.
        std::fs::write(vz_dir.join("builder.pid"), format!("{}\n", i32::MAX)).unwrap();

        let outcome =
            reap_orphaned_vm_helpers_at(vms, BUILDER_SIDECARS, true, /* dry_run = */ false)
                .expect("reap should succeed");

        assert_eq!(
            outcome.removed_dirs, 1,
            "vz builder state dir should be reaped"
        );
        assert!(
            !vz_dir.exists(),
            "vz builder state dir should be gone on disk"
        );
    }

    #[test]
    fn builder_vm_stage0_staging_dir_is_hidden_sibling() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let final_dir = tmp.path().join("builder-vm").join("aarch64");
        let staging = unique_builder_vm_stage0_staging_dir(&final_dir)
            .expect("valid final dir should produce staging dir");

        assert_eq!(staging.parent(), final_dir.parent());
        let name = staging
            .file_name()
            .and_then(|s| s.to_str())
            .expect("staging basename should be utf-8");
        assert!(
            name.starts_with(".aarch64.stage0-"),
            "unexpected staging dir name: {name}"
        );
    }

    #[test]
    fn builder_vm_stage0_promotion_rejects_invalid_artifacts_without_live_cache() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let staging = tmp.path().join(".aarch64.stage0-test");
        std::fs::create_dir_all(&staging).expect("mkdir staging");
        std::fs::write(staging.join("vmlinux"), b"stub").expect("write stub kernel");
        std::fs::write(staging.join("rootfs.ext4"), b"stub").expect("write stub rootfs");
        write_builder_vm_source_cache_metadata(&staging, "fingerprint");
        let final_dir = tmp.path().join("aarch64");

        let err = promote_builder_vm_stage0_cache(&staging, &final_dir, "fingerprint")
            .expect_err("stub artifacts must not be promoted");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("validating Stage 0 builder VM artifacts"),
            "{msg}"
        );
        assert!(!final_dir.exists(), "invalid cache must not go live");
    }

    #[test]
    fn builder_vm_stage0_promotion_validates_then_promotes() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let staging = tmp.path().join(".aarch64.stage0-test");
        let final_dir = tmp.path().join("aarch64");
        write_valid_builder_vm_artifacts(&staging);
        write_builder_vm_source_cache_metadata(&staging, "fingerprint");

        promote_builder_vm_stage0_cache(&staging, &final_dir, "fingerprint")
            .expect("valid artifacts should promote");

        assert!(!staging.exists(), "staging dir should be moved away");
        validate_builder_vm_stage0_artifacts(&final_dir).expect("final cache should validate");
        assert!(builder_vm_source_cache_ready(&final_dir, "fingerprint"));
    }

    #[test]
    fn builder_vm_stage0_promotion_keeps_existing_valid_cache() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let staging = tmp.path().join(".aarch64.stage0-test");
        let final_dir = tmp.path().join("aarch64");
        write_valid_builder_vm_artifacts(&staging);
        write_builder_vm_source_cache_metadata(&staging, "fingerprint");
        write_valid_builder_vm_artifacts(&final_dir);
        write_builder_vm_source_cache_metadata(&final_dir, "fingerprint");

        promote_builder_vm_stage0_cache(&staging, &final_dir, "fingerprint")
            .expect("existing valid cache should win the race");

        assert!(!staging.exists(), "redundant staging dir should be removed");
        validate_builder_vm_stage0_artifacts(&final_dir)
            .expect("existing cache should remain valid");
    }

    /// Lay out a synthetic mvm workspace under `tmp` that the
    /// `builder_vm_source_fingerprint` will accept:
    ///
    /// ```text
    /// tmp/
    ///   Cargo.lock
    ///   nix/lib/mkguest.nix
    ///   nix/images/builder-vm/{flake.nix,flake.lock}
    /// ```
    ///
    /// In-VM binary identity now rides on the embedded host-binary
    /// bytes (see `fold_embedded_binary_identity`), so the old per-crate
    /// `crates/<name>/{Cargo.toml,src}` stubs are gone. `nix/lib` is
    /// present because the flake imports it (Layer 5) and the dir-walker
    /// skip tests exercise it.
    ///
    /// Returns the path of the `nix/images/builder-vm/` dir — the
    /// argument the fingerprint function expects.
    fn write_builder_vm_workspace(tmp: &std::path::Path) -> std::path::PathBuf {
        std::fs::write(tmp.join("Cargo.lock"), "# stub Cargo.lock\n").expect("write Cargo.lock");

        let nix_lib = tmp.join("nix/lib");
        std::fs::create_dir_all(&nix_lib).expect("mkdir nix/lib");
        std::fs::write(nix_lib.join("mkguest.nix"), "{ }\n").expect("write nix/lib");

        let flake = tmp.join("nix/images/builder-vm");
        write_builder_vm_flake(&flake, "{ outputs = _: {}; }", Some("{\"nodes\":{}}"));
        flake
    }

    #[test]
    fn builder_vm_source_fingerprint_changes_with_flake_inputs() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let flake = write_builder_vm_workspace(tmp.path());
        let first = builder_vm_source_fingerprint(flake.to_str().unwrap()).expect("fingerprint");

        write_builder_vm_flake(
            &flake,
            "{ outputs = _: { changed = true; }; }",
            Some("{\"nodes\":{}}"),
        );
        let second = builder_vm_source_fingerprint(flake.to_str().unwrap()).expect("fingerprint");

        assert_ne!(first, second);
    }

    #[test]
    fn builder_vm_source_fingerprint_is_unaffected_by_cargo_lock() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let flake = write_builder_vm_workspace(tmp.path());
        let first = builder_vm_source_fingerprint(flake.to_str().unwrap()).expect("fingerprint");

        // The builder-VM flake forbids `buildRustPackage`; no flake artifact
        // consumes the workspace lockfile. The only baked Rust is the
        // embedded host binaries, whose identity rides on the byte-hash layer
        // (a rebuilt binary changes its sha256). A `cargo update` therefore
        // must NOT invalidate the builder-VM cache key.
        std::fs::write(
            tmp.path().join("Cargo.lock"),
            "# stub Cargo.lock — updated\n",
        )
        .expect("rewrite Cargo.lock");
        let second = builder_vm_source_fingerprint(flake.to_str().unwrap()).expect("fingerprint");

        assert_eq!(
            first, second,
            "a workspace Cargo.lock edit must not invalidate the builder-vm cache key"
        );
    }

    #[test]
    fn fold_embedded_binary_identity_distinguishes_inputs() {
        // The new contract: in-VM binary identity rides on the embedded
        // bytes, not a per-crate source walk. A rebuilt binary (changed
        // name OR changed sha256) must fold to a different digest so the
        // Stage 0 cache key busts.
        let base = {
            let mut h = Sha256::new();
            fold_embedded_binary_identity(&mut h, "mvm-host-vm-init", "aa");
            format!("{:x}", h.finalize())
        };
        let changed_hash = {
            let mut h = Sha256::new();
            fold_embedded_binary_identity(&mut h, "mvm-host-vm-init", "bb");
            format!("{:x}", h.finalize())
        };
        let changed_name = {
            let mut h = Sha256::new();
            fold_embedded_binary_identity(&mut h, "mvm-egress-proxy", "aa");
            format!("{:x}", h.finalize())
        };

        assert_ne!(
            base, changed_hash,
            "a rebuilt binary (new sha256) must bust the cache key"
        );
        assert_ne!(
            base, changed_name,
            "a renamed embedded binary must bust the cache key"
        );
        // The `\0` separator prevents (name+hash) concatenation
        // collisions, e.g. ("ab","") vs ("a","b").
        let glued = {
            let mut h = Sha256::new();
            fold_embedded_binary_identity(&mut h, "mvm-host-vm-initaa", "");
            format!("{:x}", h.finalize())
        };
        assert_ne!(base, glued, "name/hash boundary must be unambiguous");
    }

    #[test]
    fn builder_vm_source_fingerprint_is_deterministic_for_identical_workspace() {
        let tmp1 = tempfile::tempdir().expect("tempdir 1");
        let tmp2 = tempfile::tempdir().expect("tempdir 2");
        let flake1 = write_builder_vm_workspace(tmp1.path());
        let flake2 = write_builder_vm_workspace(tmp2.path());

        let a = builder_vm_source_fingerprint(flake1.to_str().unwrap()).expect("fingerprint 1");
        let b = builder_vm_source_fingerprint(flake2.to_str().unwrap()).expect("fingerprint 2");

        // Same inputs → same fingerprint regardless of where they
        // live on disk. (The hash discipline keys off relative
        // paths, never absolute, so this must hold.)
        assert_eq!(
            a, b,
            "identical workspace layouts must produce identical fingerprints"
        );
    }

    #[test]
    fn builder_vm_source_fingerprint_ignores_target_dir() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let flake = write_builder_vm_workspace(tmp.path());
        let baseline =
            builder_vm_source_fingerprint(flake.to_str().unwrap()).expect("baseline fingerprint");

        // The `nix/lib` walk (Layer 5) skips `target/`. Drop junk in a
        // `target/` under the walked dir; the fingerprint must ignore it.
        let lib_target = tmp.path().join("nix/lib/target/debug");
        std::fs::create_dir_all(&lib_target).expect("mkdir nix/lib/target");
        std::fs::write(lib_target.join("junk.rlib"), vec![0u8; 4096])
            .expect("write target garbage");

        let after =
            builder_vm_source_fingerprint(flake.to_str().unwrap()).expect("after fingerprint");

        assert_eq!(
            baseline, after,
            "target/ contents must not affect the builder-vm cache key"
        );
    }

    #[test]
    fn builder_vm_source_fingerprint_ignores_hidden_files() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let flake = write_builder_vm_workspace(tmp.path());
        let baseline =
            builder_vm_source_fingerprint(flake.to_str().unwrap()).expect("baseline fingerprint");

        // `.git/HEAD`, editor swap files (`.swp`, `foo.rs.swp`),
        // `.DS_Store`, etc. — none are flake inputs and editing them
        // shouldn't bust the cache. Drop each inside the walked `nix/lib`
        // dir, exercising the explicit skip in `walk_source_dir_sorted`.
        for path in [
            "nix/lib/.DS_Store",
            "nix/lib/.swp",
            "nix/lib/mkguest.nix.swp",
        ] {
            std::fs::write(tmp.path().join(path), b"junk").expect("write hidden");
        }

        let after =
            builder_vm_source_fingerprint(flake.to_str().unwrap()).expect("after fingerprint");

        assert_eq!(
            baseline, after,
            "hidden entries / swap files must not affect the cache key"
        );
    }

    #[test]
    fn builder_vm_source_cache_requires_matching_fingerprint() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let cache = tmp.path().join("builder-vm").join("aarch64");
        write_valid_builder_vm_artifacts(&cache);

        assert!(
            !builder_vm_source_cache_ready(&cache, "fingerprint"),
            "valid artifacts without a source marker must not satisfy source checkout cache"
        );
        write_builder_vm_source_cache_metadata(&cache, "other");
        assert!(
            !builder_vm_source_cache_ready(&cache, "fingerprint"),
            "stale source marker must not satisfy source checkout cache"
        );
        write_builder_vm_source_cache_metadata(&cache, "fingerprint");
        assert!(builder_vm_source_cache_ready(&cache, "fingerprint"));
    }

    #[test]
    fn builder_vm_source_cache_status_reports_safe_reason_codes() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let cache = tmp.path().join("builder-vm").join("aarch64");

        assert_eq!(
            builder_vm_source_cache_status(&cache, "fingerprint").reason_code(),
            "missing_artifact"
        );

        std::fs::create_dir_all(&cache).expect("mkdir cache");
        std::fs::write(cache.join("vmlinux"), b"stub").expect("write stub kernel");
        std::fs::write(cache.join("rootfs.ext4"), b"stub").expect("write stub rootfs");
        assert_eq!(
            builder_vm_source_cache_status(&cache, "fingerprint").reason_code(),
            "invalid_stage0_artifacts"
        );

        write_valid_builder_vm_artifacts(&cache);
        assert_eq!(
            builder_vm_source_cache_status(&cache, "fingerprint").reason_code(),
            "missing_fingerprint"
        );

        write_builder_vm_source_fingerprint(&cache, "other").expect("write fingerprint");
        assert_eq!(
            builder_vm_source_cache_status(&cache, "fingerprint").reason_code(),
            "fingerprint_mismatch"
        );

        write_builder_vm_source_fingerprint(&cache, "fingerprint").expect("write fingerprint");
        assert_eq!(
            builder_vm_source_cache_status(&cache, "fingerprint").reason_code(),
            "missing_artifact_digest_manifest"
        );

        write_builder_vm_artifact_digest_manifest(&cache).expect("write digest manifest");
        assert_eq!(
            builder_vm_source_cache_status(&cache, "fingerprint").reason_code(),
            "missing_provenance"
        );

        write_builder_vm_source_cache_provenance(&cache, "other").expect("write provenance");
        assert_eq!(
            builder_vm_source_cache_status(&cache, "fingerprint").reason_code(),
            "provenance_mismatch"
        );

        write_builder_vm_source_cache_provenance(&cache, "fingerprint").expect("write provenance");
        assert_eq!(
            builder_vm_source_cache_status(&cache, "fingerprint").reason_code(),
            "hit"
        );

        write_builder_vm_artifact_digest_manifest(&cache).expect("rewrite digest manifest");
        std::fs::OpenOptions::new()
            .append(true)
            .open(cache.join("vmlinux"))
            .expect("open kernel")
            .write_all(b"tamper")
            .expect("tamper kernel");
        assert_eq!(
            builder_vm_source_cache_status(&cache, "fingerprint").reason_code(),
            "artifact_digest_mismatch"
        );

        write_valid_builder_vm_artifacts(&cache);
        write_builder_vm_source_cache_metadata(&cache, "fingerprint");
        assert_eq!(
            builder_vm_source_cache_status(&cache, "fingerprint").reason_code(),
            "hit"
        );
    }

    // Fix A — `build_image_via_libkrun` writes the same fingerprint +
    // artifact-digest + provenance sidecars the Layer-1 cache uses, so the
    // next `dev up` fast-paths past the builder VM. Round-trip: a sidecar
    // write for a fingerprint reads back as a hit for that fingerprint and a
    // miss for any other — which is exactly the gate `ensure_dev_image`
    // consults before deciding to rebuild.
    #[test]
    fn dev_image_cache_sidecars_enable_hit_and_reject_changed_source() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let out = tmp.path().join("dev").join("current");
        write_valid_builder_vm_artifacts(&out);

        write_builder_vm_cache_sidecars(&out, "devfp").expect("write sidecars");
        assert!(
            builder_vm_source_cache_status(&out, "devfp").is_ready(),
            "matching fingerprint must be a cache hit"
        );
        assert_eq!(
            builder_vm_source_cache_status(&out, "changed").reason_code(),
            "fingerprint_mismatch",
            "a changed source fingerprint must miss so the dev image rebuilds"
        );
    }

    #[test]
    fn builder_vm_source_cache_provenance_omits_local_paths_and_artifact_digests() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let cache = tmp.path().join("builder-vm").join("aarch64");
        write_valid_builder_vm_artifacts(&cache);
        write_builder_vm_source_cache_metadata(&cache, "fingerprint");

        let json = std::fs::read_to_string(cache.join(BUILDER_VM_PROVENANCE_FILE))
            .expect("read provenance");
        assert!(json.contains("\"source_kind\": \"source_checkout_stage0\""));
        assert!(json.contains("\"source_fingerprint\": \"fingerprint\""));
        assert!(json.contains("\"vmlinux\""));
        assert!(json.contains("\"rootfs.ext4\""));
        assert!(
            !json.contains(&cache.display().to_string()),
            "provenance must not store local cache paths: {json}"
        );
        assert!(
            !json.contains("sha256"),
            "artifact digests belong in the separate digest manifest, not provenance: {json}"
        );
    }

    #[test]
    fn builder_vm_source_cache_rejects_tampered_provenance() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let cache = tmp.path().join("builder-vm").join("aarch64");
        write_valid_builder_vm_artifacts(&cache);
        write_builder_vm_source_cache_metadata(&cache, "fingerprint");

        let tampered = serde_json::json!({
            "schema_version": 1,
            "source_kind": "source_checkout_stage0",
            "source_fingerprint": "other",
            "artifacts": ["vmlinux", "rootfs.ext4"]
        });
        std::fs::write(
            cache.join(BUILDER_VM_PROVENANCE_FILE),
            serde_json::to_string_pretty(&tampered).expect("json"),
        )
        .expect("write tampered provenance");

        assert_eq!(
            builder_vm_source_cache_status(&cache, "fingerprint").reason_code(),
            "provenance_mismatch"
        );
        assert!(
            !builder_vm_source_cache_ready(&cache, "fingerprint"),
            "provenance drift must force a source-checkout rebuild"
        );
    }

    #[test]
    fn builder_vm_source_cache_rejects_tampered_artifact_after_metadata() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let cache = tmp.path().join("builder-vm").join("aarch64");
        write_valid_builder_vm_artifacts(&cache);
        write_builder_vm_source_cache_metadata(&cache, "fingerprint");

        std::fs::OpenOptions::new()
            .append(true)
            .open(cache.join("vmlinux"))
            .expect("open kernel")
            .write_all(b"tamper")
            .expect("tamper kernel");

        assert!(
            !builder_vm_source_cache_ready(&cache, "fingerprint"),
            "artifact digest drift must force a source-checkout rebuild"
        );
    }

    #[test]
    fn builder_vm_stage0_promotion_replaces_stale_valid_cache() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let staging = tmp.path().join(".aarch64.stage0-test");
        let final_dir = tmp.path().join("aarch64");
        write_valid_builder_vm_artifacts(&staging);
        write_builder_vm_source_cache_metadata(&staging, "new");
        write_valid_builder_vm_artifacts(&final_dir);
        write_builder_vm_source_cache_metadata(&final_dir, "old");

        promote_builder_vm_stage0_cache(&staging, &final_dir, "new")
            .expect("stale valid cache should be replaced");

        assert!(!staging.exists(), "staging dir should be moved away");
        assert!(builder_vm_source_cache_ready(&final_dir, "new"));
    }

    // -------------------------------------------------------------------
    // Stage 0 audit-emit helpers.
    //
    // Tests below pin the *details* of the audit emits (which strings
    // the macro will write into `kind`, `detail`) so that the
    // downstream log shippers don't break on a typo, plus a structural
    // test for the failure-summary truncation rule.
    // -------------------------------------------------------------------

    #[test]
    fn stage0_fingerprint_prefix_truncates_to_eight_chars() {
        let full = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let prefix = stage0_fingerprint_prefix(full);
        assert_eq!(prefix, "01234567");
        assert_eq!(prefix.len(), 8);
    }

    #[test]
    fn stage0_fingerprint_prefix_handles_short_input() {
        // Defensive: source_fingerprint should always be 64 hex chars,
        // but if a future caller hands us a short string the helper
        // must not panic.
        let prefix = stage0_fingerprint_prefix("abc");
        assert_eq!(prefix, "abc");
    }

    #[test]
    fn stage0_failure_reason_summary_strips_newlines_and_caps_length() {
        let err = anyhow::anyhow!("first line\nsecond line\twith tab");
        let summary = stage0_failure_reason_summary(&err);
        assert!(!summary.contains('\n'));
        assert!(!summary.contains('\r'));
        assert!(!summary.contains('\t'));

        // 200-char input → 160-char output.
        let long_err = anyhow::anyhow!("{}", "x".repeat(200));
        let summary = stage0_failure_reason_summary(&long_err);
        assert_eq!(summary.chars().count(), 160);
    }

    #[test]
    fn stage0_failure_reason_summary_escapes_equals() {
        // The audit detail format is space-separated `key=value` pairs.
        // A bare `=` in the reason text would confuse downstream
        // parsers; the helper maps them to `~`.
        let err = anyhow::anyhow!("expected x=1 got y=2");
        let summary = stage0_failure_reason_summary(&err);
        assert!(!summary.contains('='), "got {summary}");
        assert!(summary.contains('~'));
    }

    #[test]
    fn stage0_failure_stage_wire_format_is_stable() {
        // The `stage=` value lands in audit details that downstream
        // dashboards filter on. Pinning the casing here keeps a future
        // refactor from accidentally renaming the variant.
        assert_eq!(Stage0FailureStage::Build.as_str(), "build");
        assert_eq!(Stage0FailureStage::Validate.as_str(), "validate");
        assert_eq!(format!("{}", Stage0FailureStage::Build), "build");
    }

    #[test]
    fn stage0_flavor_current_wire_format_is_stable() {
        // The `flavor=` value emitted on every
        // `Stage0Boot` / `Stage0CachePromoted` audit line. Today there
        // is one variant (`"current"` — the nix-tarball seed); a future
        // change may introduce additional variants. Pinning the current
        // literal here so a rename surfaces immediately.
        assert_eq!(STAGE0_FLAVOR_CURRENT, "current");
    }

    /// A non-ext4 blob (here: zeros, no valid superblock) must surface
    /// as an `Err` from the load, not a silent "init present / absent".
    /// Cross-platform — no `mke2fs` needed to produce a bad image.
    #[cfg(feature = "builder-vm")]
    #[test]
    fn verify_stage0_rootfs_has_init_rejects_non_ext4() {
        let tmp = tempfile::tempdir().unwrap();
        let rootfs = tmp.path().join("rootfs.ext4");
        std::fs::write(&rootfs, vec![0u8; 1024 * 1024]).unwrap();
        let err = verify_stage0_rootfs_has_init(&rootfs)
            .expect_err("a zero-filled blob is not a loadable ext4");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("as ext4"),
            "error names the load failure: {msg}"
        );
    }

    /// Build a tiny real ext4 from `staged_dir` at `image`, returning
    /// `false` if `mke2fs` isn't installed (so the test skips rather than
    /// fails on a host without e2fsprogs). Mirrors the preallocate-then-
    /// `mke2fs -d` shape `mvm_build::oci_to_rootfs::ext4` uses.
    #[cfg(all(feature = "builder-vm", target_os = "linux"))]
    fn mke2fs_from_dir(staged_dir: &std::path::Path, image: &std::path::Path) -> bool {
        {
            let f = std::fs::File::create(image).expect("create image file");
            f.set_len(16 * 1024 * 1024).expect("preallocate image");
        }
        match std::process::Command::new("mke2fs")
            .args(["-q", "-F", "-t", "ext4", "-b", "4096", "-d"])
            .arg(staged_dir)
            .arg(image)
            .output()
        {
            Ok(out) if out.status.success() => true,
            Ok(out) => panic!("mke2fs failed: {}", String::from_utf8_lossy(&out.stderr)),
            Err(_) => false, // e2fsprogs absent on this host — skip.
        }
    }

    /// Real ext4 round-trip: an image carrying `/sbin/mvm-host-vm-init`
    /// passes; an otherwise-identical image without it fails. Linux-only
    /// because `mke2fs` is the only ext4 writer available (matches the
    /// `oci_to_rootfs` ext4 tests' gating).
    #[cfg(all(feature = "builder-vm", target_os = "linux"))]
    #[test]
    fn verify_stage0_rootfs_has_init_round_trips_real_ext4() {
        let tmp = tempfile::tempdir().unwrap();

        let with_dir = tmp.path().join("with/sbin");
        std::fs::create_dir_all(&with_dir).unwrap();
        std::fs::write(with_dir.join("mvm-host-vm-init"), b"#!/bin/true\n").unwrap();
        let with_img = tmp.path().join("with.ext4");
        if !mke2fs_from_dir(&tmp.path().join("with"), &with_img) {
            eprintln!("skipping: mke2fs not installed");
            return;
        }
        verify_stage0_rootfs_has_init(&with_img)
            .expect("rootfs carrying /sbin/mvm-host-vm-init must validate");

        let without_dir = tmp.path().join("without/sbin");
        std::fs::create_dir_all(&without_dir).unwrap();
        std::fs::write(without_dir.join("something-else"), b"x").unwrap();
        let without_img = tmp.path().join("without.ext4");
        assert!(mke2fs_from_dir(&tmp.path().join("without"), &without_img));
        let err = verify_stage0_rootfs_has_init(&without_img)
            .expect_err("rootfs missing the init binary must be rejected");
        assert!(
            format!("{err:#}").contains("missing /sbin/mvm-host-vm-init"),
            "error names the missing binary"
        );
    }
}

#[cfg(all(test, feature = "builder-vm"))]
mod heartbeat_tests {
    use super::format_compile_elapsed;
    use std::time::Duration;

    #[test]
    fn format_compile_elapsed_renders_minutes_and_seconds() {
        assert_eq!(
            format_compile_elapsed(Duration::from_secs(5)),
            "still compiling… (0m05s elapsed)"
        );
        assert_eq!(
            format_compile_elapsed(Duration::from_secs(130)),
            "still compiling… (2m10s elapsed)"
        );
    }
}
