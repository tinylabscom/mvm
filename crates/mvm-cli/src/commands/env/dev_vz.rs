//! Vz dev environment + bundled image fetching.
//!
//! The dev VM is a long-lived Vz builder guest (`/dev/vdb` nix-store
//! overlay + `/work` share wired internally) that runs `nix build`.
//! Both the auto-detect macOS tier and an explicit `--builder vz`
//! route here.

mod base;
mod bootstrap;
#[cfg(test)]
mod bootstrap_tests;
#[cfg(test)]
mod builder_vm_bootstrap_tests;
mod default_microvm;
mod image_ops;
mod kernel;
mod residency;
mod stage0_cache;
mod status;
#[cfg(test)]
mod tests;
mod vm_helpers;

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
use base::read_dev_base_provenance;
#[cfg(test)]
use base::{
    DevBaseProvenance, ResolvedDevBaseImage, dev_base_artifacts_from_revision_dir,
    dev_base_provenance_path,
};
pub(super) use base::{DevBaseRef, DevBaseStatusJson};
#[cfg(any(feature = "builder-vm", test))]
use base::{remove_dev_base_provenance, resolve_dev_base_image, write_dev_base_provenance};
#[cfg(all(test, feature = "builder-vm"))]
use bootstrap::BuildHeartbeat;
pub(in crate::commands) use bootstrap::bootstrap_builder_vm_image;
#[cfg(test)]
use bootstrap::{
    BuilderVmBootstrapAction, STAGE0_FLAVOR_CURRENT, perform_builder_vm_download_published,
    resolve_builder_vm_bootstrap_action,
};
#[cfg(all(test, feature = "builder-vm"))]
use default_microvm::DefaultMicrovmVariant;
#[cfg(test)]
use default_microvm::{
    WorkloadKernelBootstrap, default_microvm_assets, find_cached_workload_kernel,
    find_reusable_builder_kernel, resolve_workload_kernel_bootstrap,
};
pub(crate) use default_microvm::{ensure_default_microvm_image, ensure_workload_kernel};
pub use image_ops::cmd_dev_import_image;
pub(in crate::commands) use image_ops::ensure_dev_image;
#[cfg(test)]
use image_ops::find_local_fallback_image;
use image_ops::validate_dev_image_artifacts;
use image_ops::{
    BuilderVmCacheState, BuilderVmCacheStatusSummary, DevCacheInspectSummary, DevImageCacheSummary,
    DevStatusImage, resolve_dev_status_image,
};
#[cfg(feature = "builder-vm")]
use image_ops::{prepare_dev_image_out_dir, verify_stage0_rootfs_has_init};
#[cfg(all(test, feature = "builder-vm"))]
use kernel::format_compile_elapsed;
#[cfg(feature = "builder-vm")]
pub(crate) use kernel::{KernelVariant, build_kernel_via_stage0};
#[cfg(feature = "builder-vm")]
use residency::VzDevResidencyDecision;
use residency::dev_vz_snapshot_exists;
#[cfg(feature = "builder-vm")]
pub(in crate::commands) use residency::touch_dev_vz_activity_now;
#[cfg(all(test, feature = "builder-vm"))]
use residency::{decide_vz_dev_residency, read_dev_vz_last_activity, touch_dev_vz_activity_at};
#[cfg(feature = "builder-vm")]
use residency::{
    enforce_dev_vz_cold_policy_on_entry, enforce_dev_vz_residency_policy,
    remove_dev_vz_snapshot_markers, should_park, should_resume, wait_for_dev_vm_ready,
};
#[cfg(feature = "builder-vm")]
use stage0_cache::Stage0FailureStage;
pub(in crate::commands) use stage0_cache::{
    Stage0SweepOutcome, stage0_bootstrap_in_flight, sweep_orphaned_stage0_staging_dirs,
};
#[cfg(any(feature = "builder-vm", test))]
use stage0_cache::{
    acquire_stage0_lock, build_image_via_libkrun, builder_vm_source_cache_status,
    builder_vm_source_fingerprint, stage0_fingerprint_prefix, unique_builder_vm_stage0_staging_dir,
};
#[cfg(test)]
use stage0_cache::{
    builder_vm_artifact_names, builder_vm_source_cache_ready, fold_embedded_binary_identity,
    is_orphan_stage0_staging_dir_name, stage0_bootstrap_in_flight_at,
    sweep_orphaned_stage0_staging_dirs_at, write_builder_vm_artifact_digest_manifest,
    write_builder_vm_source_cache_provenance, write_builder_vm_source_fingerprint,
};
pub(in crate::commands) use status::{
    build_dev_down_json, build_dev_park_json, build_dev_status_json,
    build_dev_status_json_linux_native, build_dev_status_json_vmless, build_dev_up_json,
};
#[cfg(test)]
use status::{builder_vm_cache_status_summary, dev_image_cache_summary};
use status::{resolve_builder_vm_cache_status_summary, resolve_dev_cache_inspect_summary};
pub(in crate::commands) use vm_helpers::sweep_orphaned_vm_helpers_on_startup;
#[cfg(test)]
use vm_helpers::{
    BUILDER_SIDECARS, ProcSnapshot, WORKLOAD_SIDECARS, pid_is_alive, reap_orphaned_vm_helpers_at,
    reap_orphaned_vm_helpers_at_with_snapshot,
};

#[cfg(feature = "builder-vm")]
pub(in crate::commands) use vm_helpers::reap_orphaned_vm_helpers;

#[cfg(not(feature = "builder-vm"))]
pub(in crate::commands) fn reap_orphaned_vm_helpers(
    _dry_run: bool,
) -> Result<vm_helpers::ReapOutcome> {
    anyhow::bail!("builder helper reaping requires the `builder-vm` cargo feature")
}

// ============================================================================
// Dev environment (Vz supervisor)
// ============================================================================

pub(in crate::commands) const DEV_VM_NAME: &str = "mvm-dev";

pub(super) fn builder_vm_host_arch() -> &'static str {
    bootstrap::builder_vm_host_arch()
}

#[cfg(feature = "builder-vm")]
pub(super) fn builder_backend_attempt_order(
    selected: mvm_build::builder_backend_select::BuilderBackendChoice,
    explicit: bool,
) -> Vec<mvm_build::builder_backend_select::BuilderBackendChoice> {
    stage0_cache::builder_backend_attempt_order(selected, explicit)
}

#[cfg(feature = "builder-vm")]
pub(super) fn write_builder_vm_cache_sidecars(
    dir: &std::path::Path,
    source_fingerprint: &str,
) -> Result<()> {
    stage0_cache::write_builder_vm_cache_sidecars(dir, source_fingerprint)
}

#[cfg(test)]
fn promote_builder_vm_stage0_cache(
    staging_dir: &std::path::Path,
    final_dir: &std::path::Path,
    source_fingerprint: &str,
) -> Result<()> {
    stage0_cache::promote_builder_vm_stage0_cache(staging_dir, final_dir, source_fingerprint)
}

#[cfg(test)]
fn stage0_failure_reason_summary(err: &anyhow::Error) -> String {
    stage0_cache::stage0_failure_reason_summary(err)
}

fn dev_cache_inspect_json(summary: &DevCacheInspectSummary) -> Result<String> {
    status::dev_cache_inspect_json(summary)
}

/// Stable session id for the long-lived dev builder VM. Fixed (not the
/// random per-build id the warm pool uses) so a separate `dev down`
/// process can locate the supervisor PID file under
/// `~/.cache/mvm/builder-vm/vms/mvm-persistent-builder-vz-dev/` and reap it.
#[cfg(feature = "builder-vm")]
const DEV_VM_SESSION_ID: &str = mvm_build::vz_builder::DEV_SESSION_ID;
#[cfg(feature = "builder-vm")]
const DEV_VZ_ACTIVITY_FILE: &str = "last-activity-unix-secs";
const BUILDER_VM_SOURCE_FINGERPRINT_FILE: &str = ".mvm-source.sha256";
const BUILDER_VM_ARTIFACT_DIGEST_FILE: &str = ".mvm-artifacts.sha256";
const BUILDER_VM_PROVENANCE_FILE: &str = ".mvm-provenance.json";
/// Env var opting an installed binary into the attested-pack acceleration path:
/// place a verified builder-image pack into the cache in lieu of the plain
/// checksum download. Truthy: `1`, `true`, `yes`, `on`. Off/unset ⇒ the download
/// path is byte-identical to today. Ignored on a source checkout (which builds
/// the builder image locally and never fetches published artifacts).
#[cfg(any(
    all(feature = "release-artifact-bootstrap", feature = "builder-vm"),
    test
))]
const MVM_BUILDER_PACK_ENV: &str = "MVM_BUILDER_PACK";
#[cfg(feature = "builder-vm")]
const DEV_BASE_PROVENANCE_FILE: &str = "dev-base.json";
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
pub(super) fn cmd_dev_vz(
    cpus: u32,
    memory_gib: u32,
    open_shell: bool,
    base_ref: Option<&DevBaseRef>,
) -> Result<&'static str> {
    ui::progress("Starting dev environment via Vz (Virtualization.framework)...");

    let state_dir = mvm_build::vz_builder::persistent_vz_state_dir(DEV_VM_SESSION_ID);
    if enforce_dev_vz_cold_policy_on_entry(&state_dir) {
        ui::info("Stopped existing dev VM because MVM_RESIDENCY=cold; cold-booting.");
    }

    if is_vz_dev_running() {
        if base_ref.is_some() {
            anyhow::bail!(
                "`mvmctl dev up --base` cannot change the base of an already-running dev VM; \
                 run `mvmctl dev down` first"
            );
        }
        touch_dev_vz_activity_now();
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
    mvm_build::vz_builder::stop_persistent_vz_by_pid_file(&state_dir);
    let console_log = state_dir.join("console.log");
    let allows_persistent = mvm_core::residency::resolve_residency()
        .0
        .allows_persistent_builder();
    let snapshot_present = dev_vz_snapshot_exists();
    if snapshot_present && base_ref.is_some() {
        anyhow::bail!(
            "`mvmctl dev up --base` cannot change the base of a parked dev VM; \
             run `mvmctl dev down` first"
        );
    }
    if should_resume(allows_persistent, snapshot_present) {
        match mvm_build::vz_builder::restore_persistent_vz_builder_from_snapshot(&state_dir) {
            Ok(_) => {
                wait_for_dev_vm_ready(&console_log)?;
                touch_dev_vz_activity_now();
                ui::success("Dev VM restored from parked snapshot.");
                if open_shell {
                    ui::info("");
                    let _ = console_interactive(DEV_VM_NAME);
                }
                return Ok("restored");
            }
            Err(e) => {
                // The snapshot is unusable; discard it so the next `dev up`
                // cold-boots cleanly instead of retrying the same failed restore.
                remove_dev_vz_snapshot_markers(&state_dir);
                ui::warn(&format!(
                    "parked dev VM restore failed; discarded snapshot, cold-booting: {e}"
                ));
            }
        }
    } else if dev_vz_snapshot_exists() {
        // Residency no longer keeps a resident builder (cold): drop the stale
        // snapshot so we cold-boot cleanly rather than waking an unwanted VM.
        remove_dev_vz_snapshot_markers(&state_dir);
    }

    // Ensure the boot image exists before launching. `--base` resolves
    // through the same template/slot/bundle artifact registry as `mvmctl up`;
    // the default path keeps the source-checkout dev-image fast path.
    let image = match base_ref {
        Some(base) => {
            let resolved = resolve_dev_base_image(base)?;
            write_dev_base_provenance(&state_dir, &resolved)?;
            ui::info(&format!(
                "Using pinned dev base {}@{}",
                resolved.id, resolved.revision
            ));
            mvm_build::libkrun_builder::BuilderVmImage::Rootfs {
                kernel_path: resolved.kernel_path,
                rootfs_path: resolved.rootfs_path,
                cmdline: dev_image_cmdline(),
            }
        }
        None => {
            remove_dev_base_provenance(&state_dir);
            let (kernel, rootfs) = ensure_dev_image()?;
            mvm_build::libkrun_builder::BuilderVmImage::Rootfs {
                kernel_path: std::path::PathBuf::from(&kernel),
                rootfs_path: std::path::PathBuf::from(&rootfs),
                cmdline: dev_image_cmdline(),
            }
        }
    };

    // Lock ~/.mvm and ~/.cache/mvm to 0700 on every `dev up`. Idempotent.
    mvm_core::config::ensure_data_dir().with_context(|| "locking down data dir to mode 0700")?;
    mvm_core::config::ensure_cache_dir().with_context(|| "locking down cache dir to mode 0700")?;

    ui::info(&format!(
        "Booting dev VM ({cpus} vCPUs, {memory_gib} GiB memory)..."
    ));

    let memory_mib = memory_gib.saturating_mul(1024);

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

    wait_for_dev_vm_ready(&console_log)?;
    touch_dev_vz_activity_now();

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
pub(super) fn cmd_dev_vz(
    _cpus: u32,
    _memory_gib: u32,
    _open_shell: bool,
    _base_ref: Option<&DevBaseRef>,
) -> Result<&'static str> {
    anyhow::bail!(
        "the dev VM is built locally via the builder VM, but this mvmctl was \
         compiled without the `builder-vm` feature."
    )
}

pub(in crate::commands) fn cmd_dev_vz_park(json: bool) -> Result<bool> {
    #[cfg(feature = "builder-vm")]
    {
        let state_dir = mvm_build::vz_builder::persistent_vz_state_dir(DEV_VM_SESSION_ID);
        if !mvm_build::vz_builder::persistent_vz_supervisor_alive(&state_dir) {
            if !json {
                ui::info("Dev VM is not running.");
            }
            return Ok(false);
        }
        let parked = mvm_build::vz_builder::park_persistent_vz_builder(&state_dir)
            .map_err(|e| anyhow::anyhow!("Failed to park dev VM: {e}"))?;
        let _ = std::fs::remove_dir_all(state_dir.join("vsock"));
        if !json {
            ui::success("Dev VM parked.");
            ui::info(&format!("  Snapshot: {}", parked.snapshot_path.display()));
        }
        Ok(true)
    }
    #[cfg(not(feature = "builder-vm"))]
    {
        if !json {
            ui::info("Dev VM is not running.");
        }
        Ok(false)
    }
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
pub(in crate::commands) fn cmd_dev_vz_down(json: bool, reset: bool) -> Result<bool> {
    #[cfg(feature = "builder-vm")]
    {
        let state_dir = mvm_build::vz_builder::persistent_vz_state_dir(DEV_VM_SESSION_ID);
        let allows_persistent = mvm_core::residency::resolve_residency()
            .0
            .allows_persistent_builder();
        let alive = mvm_build::vz_builder::persistent_vz_supervisor_alive(&state_dir);

        if should_park(allows_persistent, alive, reset) {
            match mvm_build::vz_builder::park_persistent_vz_builder(&state_dir) {
                Ok(_) => {
                    // park_persistent_vz_builder already stopped the supervisor.
                    let _ = std::fs::remove_dir_all(state_dir.join("vsock"));
                    if !json {
                        ui::success("Parked dev VM — next `dev up` resumes from snapshot.");
                    }
                    return Ok(true);
                }
                Err(e) => {
                    // Park failed: fall through to a normal stop so we never
                    // leave a half-parked, still-running VM.
                    if !json {
                        ui::warn(&format!("Park failed ({e}); stopping normally."));
                    }
                }
            }
        }

        let was_running = mvm_build::vz_builder::stop_persistent_vz_by_pid_file(&state_dir);
        // Drop the per-VM vsock dir so a stale socket can't fool the
        // liveness probe on the next `dev status`.
        let _ = std::fs::remove_dir_all(state_dir.join("vsock"));
        // Not parking (cold residency or `--reset`): discard any stale snapshot
        // so a later `dev up` cold-boots instead of resuming an old builder.
        remove_dev_vz_snapshot_markers(&state_dir);
        remove_dev_base_provenance(&state_dir);
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
        let _ = reset;
        if !json {
            ui::info("Dev VM is not running.");
        }
        Ok(false)
    }
}

/// Show dev VM status.
pub(super) fn cmd_dev_vz_status(json: bool) -> Result<()> {
    #[cfg(feature = "builder-vm")]
    {
        match enforce_dev_vz_residency_policy() {
            Ok(Some(decision)) if !json => match decision {
                VzDevResidencyDecision::Park => {
                    ui::info("Dev VM parked by residency policy.");
                }
                VzDevResidencyDecision::Teardown => {
                    ui::info("Dev VM stopped by cold residency policy.");
                }
                VzDevResidencyDecision::Keep => {}
            },
            Ok(_) => {}
            Err(e) if !json => {
                ui::warn(&format!("Dev VM residency policy enforcement failed: {e}"));
            }
            Err(e) => return Err(e),
        }
    }
    let running = is_vz_dev_running();
    let state = if running {
        "running"
    } else if cfg!(feature = "builder-vm") && dev_vz_snapshot_exists() {
        "parked"
    } else {
        "stopped"
    };
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

/// Returns `true` when the running `mvmctl` is a source-checkout build
/// (the in-repo builder-VM flake is present). The local-build invariant
/// applies when this is true: source checkouts must build kernels
/// locally and never fetch pre-built artifacts.
pub(in crate::commands) fn find_builder_vm_flake_is_source_checkout() -> bool {
    find_builder_vm_flake().is_ok()
}
