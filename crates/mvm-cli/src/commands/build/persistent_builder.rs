//! `mvmctl persistent-builder` CLI verb.
//!
//! Wires the host-side `LibkrunPersistentHostVm` +
//! `PersistentBuilderSupervisor` + the in-guest dispatch loop into
//! a user-facing command. Three subcommands:
//!
//! - **`start --workspace <path>`** — spawns the long-lived
//!   builder VM and records the dispatch socket path so
//!   subsequent `submit` / `stop` calls find it.
//! - **`submit --flake <path>`** — dispatches one
//!   `BuilderJob::Flake` into the running VM, blocks for the
//!   `HostVmResponse::Result`, prints the outcome. Re-stages
//!   `cmd.sh` under the running VM's job dir per-call.
//! - **`stop`** — sends `HostVmRequest::Shutdown` to the dispatch
//!   loop, waits for the supervisor child to exit cleanly.
//!
//! This is deliberately separate from the builder VM bootstrap. The
//! lifecycle binding (the bootstrap auto-starting the persistent
//! supervisor) lands in a follow-up. Once it does, the bootstrap
//! becomes a thin caller of the same
//! `LibkrunPersistentHostVm::start()` this verb invokes.
//!
//! ## Session state
//!
//! The running VM's dispatch-socket path + supervisor PID get
//! recorded at `~/.mvm/run/persistent-builder.json` so `submit` /
//! `stop` find them across process invocations. The file is mode
//! 0600 to match the security contract for `~/.mvm/run/`.
//!
//! ## What's deferred
//!
//! - Auto-start from the builder VM bootstrap (post-merge follow-up).
//! - `mvmctl build` routing into the persistent supervisor when a
//!   session is active (`submit` now produces real artifacts, so
//!   the routing target exists).
//! - Install variant dispatch.
//! - Stderr streaming.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::{Args as ClapArgs, Subcommand};
use serde::{Deserialize, Serialize};

use mvm_build::builder_backend_select::{BuilderBackendChoice, resolve_env_override};
use mvm_build::builder_protocol::HostVmResponseRead;
use mvm_build::builder_vm::BuilderJob;
use mvm_build::libkrun_builder::{
    DISPATCH_SOCK_MARKER, LibkrunPersistentHostVm, PersistentVmHandle,
};
use mvm_build::persistent_builder::{
    DispatchOutcome, PersistentBuilderSupervisor, SessionDiskTransport, current_unix_secs,
    guest_artifact_dir, read_dispatch_artifacts, repack_dispatch_input,
};

use crate::commands::Cli;

#[derive(ClapArgs, Debug, Clone)]
pub struct Args {
    #[command(subcommand)]
    pub command: Sub,
}

#[derive(Subcommand, Debug, Clone)]
pub enum Sub {
    /// Spawn the persistent builder VM and record the session.
    /// The VM keeps running after this command returns; `submit`
    /// dispatches jobs into it and `stop` brings it down.
    Start(StartArgs),
    /// Dispatch one flake build into the running persistent VM
    /// and print the outcome.
    Submit(SubmitArgs),
    /// Send `HostVmRequest::Shutdown` to the persistent VM and
    /// wait for it to power off cleanly.
    Stop(StopArgs),
    /// Print the current session record (if any).
    Status,
}

#[derive(ClapArgs, Debug, Clone)]
pub struct StartArgs {
    /// Host directory bound at `/work` inside the persistent VM.
    /// Defaults to the current working directory.
    #[arg(long)]
    pub workspace: Option<PathBuf>,
    /// Guest memory in MiB for the persistent Nix builder.
    #[arg(long, default_value_t = DEFAULT_MEMORY_MIB)]
    pub memory_mib: u32,
}

/// Guest memory for a persistent builder when nobody names one. Shared by the
/// `--memory-mib` default and the auto-start path, so a build that starts a
/// session on contention gets the same builder an explicit `start` would.
const DEFAULT_MEMORY_MIB: u32 = 4096;

#[derive(ClapArgs, Debug, Clone)]
pub struct SubmitArgs {
    /// Flake reference to build (e.g. `path:/work#packages.default`).
    #[arg(long)]
    pub flake: String,
    /// Flake attribute path. Defaults to `packages.<host_arch>-linux.default`.
    #[arg(long)]
    pub attr: Option<String>,
}

#[derive(ClapArgs, Debug, Clone)]
pub struct StopArgs {}

/// Persisted at `~/.mvm/run/persistent-builder.json` — single
/// source of truth for `submit` / `stop` to locate a running
/// session.
#[derive(Debug, Serialize, Deserialize)]
struct SessionRecord {
    /// Opaque session ID from `PersistentVmHandle::session_id`.
    session_id: String,
    /// Path libkrun exposes for AF_VSOCK port 21471 proxy. The
    /// supervisor connects here.
    dispatch_socket_path: PathBuf,
    /// Per-VM job dir. `submit` stages each call's cmd.sh under a fresh
    /// `<job_dir_relpath>` here and reads that dispatch's artifacts back here.
    /// Reaches the guest as a `/job` share, or — when `disk_transport` is set —
    /// over the transport disks, in which case the guest never sees this path.
    job_dir: PathBuf,
    /// Set when this session exchanges jobs over raw disks rather than shares.
    /// Absent means shares, which is what the libkrun backend uses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    disk_transport: Option<SessionDiskTransport>,
    /// Workspace bound at `/work` in the guest. Recorded for
    /// `status` output; not load-bearing.
    workspace_root: PathBuf,
    /// PID of the libkrun supervisor child. `stop` uses
    /// `libc::kill(pid, 0)` to check liveness before attempting
    /// shutdown.
    supervisor_pid: u32,
    /// Last successful host-side activity. Optional for backward compatibility
    /// with older session records.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_activity_unix_secs: Option<u64>,
}

fn session_record_path() -> PathBuf {
    PathBuf::from(mvm_core::config::mvm_runtime_dir()).join("persistent-builder.json")
}

fn write_session_record(record: &SessionRecord) -> Result<()> {
    let path = session_record_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let body = serde_json::to_vec_pretty(record).context("serializing session record")?;
    std::fs::write(&path, body).with_context(|| format!("writing {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

fn read_session_record() -> Result<SessionRecord> {
    let path = session_record_path();
    let body = std::fs::read(&path).with_context(|| {
        format!(
            "no persistent-builder session record at {} \
             (start one with `mvmctl persistent-builder start`)",
            path.display()
        )
    })?;
    serde_json::from_slice(&body)
        .with_context(|| format!("parsing session record at {}", path.display()))
}

fn remove_session_record() -> Result<()> {
    let path = session_record_path();
    if path.exists() {
        std::fs::remove_file(&path).with_context(|| format!("removing {}", path.display()))?;
    }
    Ok(())
}

pub fn run(_cli: &Cli, args: Args) -> Result<()> {
    match args.command {
        Sub::Start(a) => run_start(a),
        Sub::Submit(a) => run_submit(a),
        Sub::Stop(_) => run_stop(),
        Sub::Status => run_status(),
    }
}

/// Which persistent builder backend `start` brings up. Both expose the same
/// dispatch contract (`HostVmRequest` over the per-VM dispatch socket), which
/// is what keeps the session record and `submit` / `stop` backend-agnostic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PersistentBackend {
    Libkrun,
    Hvf,
}

/// Resolve the explicit backend selection (`--builder`, folded into
/// `MVM_BUILDER_BACKEND` at startup, or the env var directly) to the persistent
/// host VM to spawn. An unset selection keeps libkrun — the verb's default,
/// independent of the platform auto-detect. QEMU has no persistent host VM, so
/// it fails closed with guidance.
fn persistent_backend(explicit: Option<BuilderBackendChoice>) -> Result<PersistentBackend> {
    match explicit {
        None | Some(BuilderBackendChoice::Libkrun) => Ok(PersistentBackend::Libkrun),
        Some(BuilderBackendChoice::Hvf) => Ok(PersistentBackend::Hvf),
        Some(BuilderBackendChoice::Qemu) => bail!(
            "`mvmctl persistent-builder start` has no QEMU persistent builder \
             (QEMU is a one-shot dev/test backend). Use `--builder libkrun` \
             (or omit `--builder` for libkrun)."
        ),
        Some(BuilderBackendChoice::WebLinux) => bail!(
            "`mvmctl persistent-builder start` has no WebLinux persistent builder \
             (WebLinux is browser-only). Use `--builder libkrun` or `--builder hvf`."
        ),
    }
}

fn run_start(args: StartArgs) -> Result<()> {
    // Resolve the backend from the explicit selection (the `--builder` flag is
    // folded into `MVM_BUILDER_BACKEND` at startup, so the env reflects it).
    let backend = persistent_backend(resolve_env_override())?;

    if read_session_record().is_ok() {
        bail!(
            "a persistent-builder session is already running. \
             Stop it with `mvmctl persistent-builder stop` before starting a new one."
        );
    }

    let workspace = match args.workspace {
        Some(p) => p,
        None => std::env::current_dir().context("resolving current dir for --workspace")?,
    };

    let record = match backend {
        PersistentBackend::Libkrun => start_libkrun_persistent(workspace, args.memory_mib)?,
        PersistentBackend::Hvf => start_hvf_persistent(workspace, args.memory_mib)?,
    };
    write_session_record(&record)?;

    println!("session_id: {}", record.session_id);
    println!("dispatch_socket: {}", record.dispatch_socket_path.display());
    println!("supervisor_pid: {}", record.supervisor_pid);
    Ok(())
}

/// Start a session on behalf of a build that found the store image busy.
///
/// Registered into `mvm-build`, which decides *when* a session is worth
/// starting but cannot start one: extracting host binaries, resolving a
/// builder image and writing the session record all live above it in the
/// dependency graph.
///
/// The workspace is the build's own working directory — the tree it would have
/// handed a single-shot builder — so the session serves `/work` from where the
/// build expects it.
pub(crate) fn start_session_for_contended_build()
-> Result<mvm_build::persistent_builder::SessionRecord> {
    // Another process may have published a record between `mvm-build`'s check
    // and this call.
    if let Ok(existing) = read_session_record() {
        return Ok(as_build_record(&existing));
    }

    let backend = persistent_backend(resolve_env_override())?;
    let workspace = std::env::current_dir()
        .context("resolving the working directory for the builder session")?;
    let record = match backend {
        PersistentBackend::Libkrun => start_libkrun_persistent(workspace, DEFAULT_MEMORY_MIB)?,
        PersistentBackend::Hvf => start_hvf_persistent(workspace, DEFAULT_MEMORY_MIB)?,
    };
    write_session_record(&record)?;
    Ok(as_build_record(&record))
}

/// Project the CLI's session record onto `mvm-build`'s copy of the shape. The
/// two are deliberately separate types — `mvm-build` sits below this crate —
/// and `session_record_serde_matches_mvm_cli` pins them together.
fn as_build_record(record: &SessionRecord) -> mvm_build::persistent_builder::SessionRecord {
    mvm_build::persistent_builder::SessionRecord {
        session_id: record.session_id.clone(),
        dispatch_socket_path: record.dispatch_socket_path.clone(),
        job_dir: record.job_dir.clone(),
        workspace_root: record.workspace_root.clone(),
        disk_transport: record.disk_transport.clone(),
        supervisor_pid: record.supervisor_pid,
        last_activity_unix_secs: record.last_activity_unix_secs,
    }
}

/// Extract the host-vm binaries a persistent builder serves at `/mvm-bins`,
/// and make the directory traversable by the guest's virtio-fs view of it.
/// Shared by both backends: the payload and the mode requirement are the same
/// whichever VMM serves the share.
fn ensure_persistent_host_bins() -> Result<PathBuf> {
    let host_bin_cache = PathBuf::from(mvm_core::config::mvm_cache_dir()).join("host-bins");
    let host_bin_dir = crate::host_binaries::extract::ensure_extracted(&host_bin_cache)
        .context("extracting host-vm binaries for persistent builder")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&host_bin_dir, std::fs::Permissions::from_mode(0o755))
            .with_context(|| {
                format!(
                    "making persistent builder host binaries readable: {}",
                    host_bin_dir.display()
                )
            })?;
    }
    Ok(host_bin_dir)
}

/// Spawn the HVF persistent builder and build its session record.
///
/// Same store-lock caveat as [`leak_handle`]: this process exits so the VM
/// outlives it, and the flock goes with it. The session record is the soft
/// mutex until the lock moves into the supervisor, which is the only place it
/// can outlive this command.
fn start_hvf_persistent(workspace: PathBuf, memory_mib: u32) -> Result<SessionRecord> {
    let host_bin_dir = ensure_persistent_host_bins()?;
    let (kernel, rootfs, closure_nar) =
        crate::commands::build::hvf_builder_image::resolve_hvf_builder_image()
            .map_err(|e| anyhow::anyhow!(e))
            .context("resolving the hvf builder image for the persistent builder")?;

    let session_id = format!("{:x}", current_unix_secs());
    let mut vm = mvm_runtime::builder_runner::HvfPersistentHostVm::new(
        kernel,
        rootfs,
        &workspace,
        host_bin_dir,
    )
    .with_resources(DEFAULT_PERSISTENT_VCPUS, memory_mib);
    // A builder pack may ship a pre-fetched toolchain closure. It rides the
    // input disk, so it has to be known before the disk is packed.
    if let Some(nar) = closure_nar {
        vm = vm.with_closure_nar(nar);
    }
    let session = vm
        .start(&session_id)
        .context("spawning persistent builder VM (HvfPersistentHostVm::start)")?;

    let record = SessionRecord {
        session_id: session.session_id().to_string(),
        dispatch_socket_path: session.dispatch_socket_path(),
        job_dir: session.job_dir().to_path_buf(),
        // HVF has no virtio-fs: every job and every artifact crosses on a disk.
        disk_transport: Some(SessionDiskTransport {
            input_disk: session.input_disk().to_path_buf(),
            output_disk: session.output_disk().to_path_buf(),
        }),
        workspace_root: workspace,
        supervisor_pid: session
            .supervisor_pid()
            .unwrap_or_else(|| read_supervisor_pid(session.state_dir())),
        last_activity_unix_secs: Some(current_unix_secs()),
    };
    // Same reason as the libkrun path: the supervisor must outlive this
    // command, so the handle is leaked rather than dropped.
    std::mem::forget(session);
    Ok(record)
}

/// vCPUs for a persistent builder session. Matches the one-shot builder's
/// default; `nix build` parallelizes at the derivation level.
const DEFAULT_PERSISTENT_VCPUS: u32 = 4;

/// Spawn the libkrun persistent builder and build its session record.
fn start_libkrun_persistent(workspace: PathBuf, memory_mib: u32) -> Result<SessionRecord> {
    let host_bin_dir = ensure_persistent_host_bins()?;
    let vm = LibkrunPersistentHostVm::new(&workspace)
        .with_memory_mib(memory_mib)
        .with_host_bin_dir(host_bin_dir);
    let handle = vm
        .start()
        .context("spawning persistent builder VM (LibkrunPersistentHostVm::start)")?;
    let record = SessionRecord {
        session_id: handle.session_id().to_string(),
        dispatch_socket_path: handle.dispatch_socket_path(),
        job_dir: handle.job_dir().to_path_buf(),
        // libkrun serves `/job` and `/out` as virtio-fs shares, so the host
        // already sees what the guest writes and needs no transport disks.
        disk_transport: None,
        workspace_root: workspace,
        supervisor_pid: read_supervisor_pid(handle.vm_state_dir()),
        last_activity_unix_secs: Some(current_unix_secs()),
    };
    leak_handle(handle);
    Ok(record)
}

/// Intentionally LEAK the libkrun handle so the supervisor child stays running
/// after this process exits. `stop` reattaches via the PID in the session
/// record.
///
/// The handle carries no store lock to lose: the supervisor takes that lock
/// itself and holds it for as long as it runs, which is as long as the VM. An
/// earlier arrangement locked the image here, and the kernel released it the
/// moment this process exited — leaving a live VM writing an image any other
/// builder was free to attach.
fn leak_handle(handle: PersistentVmHandle) {
    std::mem::forget(handle);
}

fn run_submit(args: SubmitArgs) -> Result<()> {
    let record = read_session_record()?;
    if !supervisor_alive(record.supervisor_pid) {
        let _ = remove_session_record();
        bail!(
            "recorded supervisor PID {} is not alive — session record cleared. \
             Start a new session with `mvmctl persistent-builder start`.",
            record.supervisor_pid
        );
    }

    let attr = args
        .attr
        .unwrap_or_else(|| format!("packages.{}-linux.default", host_arch_for_attr()));
    let _ = mvm_build::persistent_builder::touch_active_session(current_unix_secs());
    let transport = record.disk_transport.as_ref();
    let job_dir_relpath = stage_flake_cmd_sh(&record.job_dir, &args.flake, &attr, transport)?;

    // Disk-backed session: the job has to be on the input disk before the
    // guest is told to run it. `submit` below is what sends the frame, so
    // finishing here is what makes the ordering safe.
    if let Some(t) = transport {
        repack_dispatch_input(t, &record.job_dir, &job_dir_relpath)
            .context("packing the dispatch input disk")?;
    }

    let supervisor = PersistentBuilderSupervisor::new(&record.dispatch_socket_path)
        // Nix can spend a long time in a quiet compiler phase while the
        // staged script keeps the complete diagnostic in a host-visible log.
        // Keep the transport alive for that bounded quiet period; the
        // one-hour dispatch deadline remains the overall build cap.
        .with_frame_read_timeout(Duration::from_secs(30 * 60));

    let outcome = supervisor
        .submit(
            BuilderJob::Flake {
                flake_ref: args.flake.clone(),
                attr_path: attr.clone(),
            },
            job_dir_relpath.clone(),
        )
        .context("PersistentBuilderSupervisor::submit")?;
    let _ = mvm_build::persistent_builder::touch_active_session(current_unix_secs());

    print_outcome(&outcome);

    // The guest wrote its artifact tar before answering, so reading now cannot
    // race it. This lands them where `artifact_dir_for` looks, which is what
    // keeps the reporting below identical across both transports.
    if let Some(t) = transport
        && let Err(e) = read_dispatch_artifacts(t, &record.job_dir, &job_dir_relpath)
    {
        // Best-effort on a failed dispatch: the guest still collects after
        // every job, so this usually carries the Nix log even when the build
        // did not produce artifacts. A hard error here would replace the
        // build's own diagnosis with a transport one.
        eprintln!("warning: reading the dispatch output disk failed: {e}");
    }

    if outcome.exit_code == 0 {
        let artifact_dir = artifact_dir_for(&record.job_dir, &job_dir_relpath);
        match summarize_artifacts(&artifact_dir) {
            Ok(summary) => {
                println!("artifact_dir: {}", artifact_dir.display());
                println!(
                    "vmlinux: {} ({} bytes)",
                    summary.vmlinux.display(),
                    summary.vmlinux_bytes
                );
                println!(
                    "rootfs.ext4: {} ({} bytes)",
                    summary.rootfs.display(),
                    summary.rootfs_bytes
                );
                if let Some(manifest) = &summary.manifest {
                    println!("manifest.json: {}", manifest.display());
                }
            }
            Err(e) => {
                eprintln!(
                    "warning: dispatch succeeded but artifact dir at {} is incomplete: {e}",
                    artifact_dir.display()
                );
            }
        }
    }

    Ok(())
}

/// On-disk summary of what `stage_flake_cmd_sh`'s cmd.sh
/// produced. Both `vmlinux` and `rootfs.ext4` are required;
/// `manifest.json` is an optional sidecar (some flakes emit it,
/// some don't — see `nix/images/builder/flake.nix` for the
/// shape).
#[derive(Debug)]
struct ArtifactSummary {
    vmlinux: std::path::PathBuf,
    vmlinux_bytes: u64,
    rootfs: std::path::PathBuf,
    rootfs_bytes: u64,
    manifest: Option<std::path::PathBuf>,
}

fn summarize_artifacts(dir: &std::path::Path) -> Result<ArtifactSummary> {
    if !dir.is_dir() {
        bail!("missing artifact dir {}", dir.display());
    }
    let vmlinux = dir.join("vmlinux");
    let vmlinux_meta =
        std::fs::metadata(&vmlinux).with_context(|| format!("missing {}", vmlinux.display()))?;
    let rootfs = dir.join("rootfs.ext4");
    let rootfs_meta =
        std::fs::metadata(&rootfs).with_context(|| format!("missing {}", rootfs.display()))?;
    let manifest_path = dir.join("manifest.json");
    let manifest = if manifest_path.is_file() {
        Some(manifest_path)
    } else {
        None
    };
    Ok(ArtifactSummary {
        vmlinux,
        vmlinux_bytes: vmlinux_meta.len(),
        rootfs,
        rootfs_bytes: rootfs_meta.len(),
        manifest,
    })
}

fn run_stop() -> Result<()> {
    let record = read_session_record()?;
    if !supervisor_alive(record.supervisor_pid) {
        eprintln!(
            "supervisor PID {} not alive — clearing stale session record",
            record.supervisor_pid
        );
        remove_session_record()?;
        return Ok(());
    }

    let supervisor = PersistentBuilderSupervisor::new(&record.dispatch_socket_path);
    supervisor
        .shutdown()
        .context("PersistentBuilderSupervisor::shutdown")?;

    // Wait briefly for the supervisor child to exit on its own
    // (the guest reboots after sending Bye, then libkrun returns,
    // then the supervisor's main exits). If it doesn't exit within
    // the deadline, fall through to a kill. We don't own the
    // process anymore — start() leaked the handle — so we poll the
    // PID via kill(pid, 0).
    let stop_deadline = std::time::Instant::now() + Duration::from_secs(30);
    while std::time::Instant::now() < stop_deadline {
        if !supervisor_alive(record.supervisor_pid) {
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    if supervisor_alive(record.supervisor_pid) {
        eprintln!(
            "supervisor PID {} did not exit within 30s; sending SIGTERM",
            record.supervisor_pid
        );
        send_sigterm(record.supervisor_pid);
    }

    remove_session_record()?;
    Ok(())
}

fn run_status() -> Result<()> {
    match read_session_record() {
        Ok(record) => {
            let alive = supervisor_alive(record.supervisor_pid);
            println!("session_id: {}", record.session_id);
            println!("workspace_root: {}", record.workspace_root.display());
            println!("dispatch_socket: {}", record.dispatch_socket_path.display());
            println!(
                "supervisor_pid: {} ({})",
                record.supervisor_pid,
                if alive { "alive" } else { "stale" }
            );
            if let Some(last) = record.last_activity_unix_secs {
                println!("last_activity_unix_secs: {last}");
            }
        }
        Err(e) => {
            println!("no persistent-builder session ({e})");
        }
    }
    Ok(())
}

/// Subdir name inside a dispatch's job dir where the cmd.sh
/// copies `vmlinux` + `rootfs.ext4`. Mirrors mkGuest's output
/// layout. The host reads from `<job_dir>/<job_id>/out/` after
/// the dispatch completes.
const ARTIFACT_SUBDIR: &str = "out";

/// Stage a fresh cmd.sh under `<job_dir>/<uuid>/cmd.sh`, return
/// the relative path the guest's dispatch loop resolves under
/// `/job/`. The cmd.sh:
///
/// 1. Runs `nix build` against `<flake_ref>#<attr>` and prints
///    the store path.
/// 2. Copies the result's `vmlinux` and `rootfs.ext4` into
///    `/job/<job_id>/<ARTIFACT_SUBDIR>/` so the host can read
///    them back after the dispatch completes (the same dir is
///    bound at `/out` in the guest — both views see identical
///    bytes).
///
/// Matches the shape `LibkrunBuilderVm::run_build` produces for
/// the single-shot path so the guest's `run_job` helper accepts
/// the input unchanged.
fn stage_flake_cmd_sh(
    job_dir: &std::path::Path,
    flake_ref: &str,
    attr: &str,
    transport: Option<&SessionDiskTransport>,
) -> Result<String> {
    let job_id = uuid::Uuid::new_v4().to_string();
    let sub = job_dir.join(&job_id);
    let artifact_dir = sub.join(ARTIFACT_SUBDIR);
    std::fs::create_dir_all(&artifact_dir)
        .with_context(|| format!("creating {}", artifact_dir.display()))?;
    // The guest runs the staged script as the unprivileged builder uid while
    // the host creates this share as the invoking user. Make only this
    // per-dispatch subtree guest-writable so Nix diagnostics and copied
    // artifacts can cross the virtio-fs boundary without widening the parent
    // builder cache permissions.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let guest_writable = std::fs::Permissions::from_mode(0o777);
        std::fs::set_permissions(&sub, guest_writable.clone())
            .with_context(|| format!("making {} guest-writable", sub.display()))?;
        std::fs::set_permissions(&artifact_dir, guest_writable)
            .with_context(|| format!("making {} guest-writable", artifact_dir.display()))?;
    }
    let script = format!(
        "#!/bin/sh\n\
         set -eu\n\
         # The builder rootfs is read-only and the dispatched command runs\n\
         # under the unprivileged builder uid. Keep Nix's user caches on the\n\
         # writable tmpfs / persistent store locations.\n\
         export HOME=/tmp\n\
         export MVM_WORKSPACE_PATH=/work\n\
         export MVM_HOST_BIN_DIR=/mvm-bins\n\
         export XDG_CACHE_HOME=/tmp/.cache\n\
         export XDG_STATE_HOME=/tmp/.local/state\n\
         # Keep persistent jobs on the builder's host-mediated egress path\n\
         # even when the cached builder image predates the matching init\n\
         # binary. Nix and its fetchers inherit these loopback proxy vars.\n\
         export ALL_PROXY='{egress_proxy_url}'\n\
         export HTTP_PROXY='{egress_proxy_url}'\n\
         export HTTPS_PROXY='{egress_proxy_url}'\n\
         export all_proxy='{egress_proxy_url}'\n\
         export http_proxy='{egress_proxy_url}'\n\
         export https_proxy='{egress_proxy_url}'\n\
         export NO_PROXY='{no_proxy_loopback}'\n\
         export no_proxy='{no_proxy_loopback}'\n\
         # Older cached builder images may not have loaded the read-only\n\
         # rootfs closure into the writable Nix database at boot. Register\n\
         # it here before Nix decides to substitute paths that are local.\n\
         if [ -r /nix-path-registration ]; then\n\
             /sbin/nix-store --load-db < /nix-path-registration 2>/tmp/nix-db-load.log ||\n\
                 cat /tmp/nix-db-load.log >&2\n\
         fi\n\
         export NIX_CONFIG='experimental-features = nix-command flakes\n\
         sandbox = false\n\
         build-users-group =\n\
         max-jobs = 1\n\
         cores = 1\n\
         auto-optimise-store = false\n\
         substituters = https://cache.nixos.org/\n\
         trusted-public-keys = cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY=\n\
         fallback = true\n\
         download-attempts = 8\n\
         http-connections = 2\n\
         connect-timeout = 60\n\
         stalled-download-timeout = 300'\n\
         mkdir -p \"$XDG_CACHE_HOME\" \"$XDG_STATE_HOME\"\n\
         nix() {{ env HOME=\"$HOME\" XDG_CACHE_HOME=\"$XDG_CACHE_HOME\" XDG_STATE_HOME=\"$XDG_STATE_HOME\" /sbin/nix \"$@\"; }}\n\
         OUT_DIR='{out_dir}'\n\
         NIX_LOG=\"$OUT_DIR/nix-stderr.log\"\n\
         NIX_STATUS=\"$OUT_DIR/nix-exit-status\"\n\
         mkdir -p \"$OUT_DIR\"\n\
         # Keep the complete Nix diagnostic beside the artifacts, which is\n\
         # the one directory the host reads back on either transport. A build\n\
         # can terminate before the terminal Result frame is written; this\n\
         # file remains available for post-mortem inspection.\n\
         set +e\n\
         STORE_PATH=$(nix --extra-experimental-features 'nix-command flakes' \\\n\
             build --no-link --print-out-paths \\\n\
            --impure --no-write-lock-file \\\n\
             {flake_ref}#{attr} 2>\"$NIX_LOG\")\n\
         nix_status=$?\n\
         set -e\n\
         printf '%s\\n' \"$nix_status\" > \"$NIX_STATUS\"\n\
         cat \"$NIX_LOG\" >&2\n\
         if [ \"$nix_status\" -ne 0 ]; then\n\
             echo \"mvm-host-vm-init: nix build exited $nix_status\" >&2\n\
             exit \"$nix_status\"\n\
         fi\n\
         echo \"store-path=$STORE_PATH\"\n\
         # mkGuest layout: $STORE_PATH/{{vmlinux,rootfs.ext4}}.\n\
         # Copy via `cp -L` so the host gets real bytes, not\n\
         # store-path symlinks (those point into the in-guest\n\
         # /nix/store and don't resolve on the host).\n\
         if [ ! -f \"$STORE_PATH/vmlinux\" ]; then\n\
             echo 'mvm-host-vm-init: nix output missing vmlinux' >&2\n\
             exit 4\n\
         fi\n\
         if [ ! -f \"$STORE_PATH/rootfs.ext4\" ]; then\n\
             echo 'mvm-host-vm-init: nix output missing rootfs.ext4' >&2\n\
             exit 4\n\
         fi\n\
         cp -L \"$STORE_PATH/vmlinux\" \"$OUT_DIR/vmlinux\"\n\
         cp -L \"$STORE_PATH/rootfs.ext4\" \"$OUT_DIR/rootfs.ext4\"\n\
         # Manifest sidecar — copy if present, but don't fail\n\
         # for flakes that don't emit it.\n\
         if [ -f \"$STORE_PATH/manifest.json\" ]; then\n\
             cp -L \"$STORE_PATH/manifest.json\" \"$OUT_DIR/manifest.json\"\n\
         fi\n\
         # Production image sidecars — retain the dm-verity payload and\n\
         # admission metadata emitted by the Nix image flake.\n\
         for sidecar in rootfs.verity rootfs.roothash rootfs-closure-paths mvm-meta.json; do\n\
             if [ -f \"$STORE_PATH/$sidecar\" ]; then\n\
                 cp -L \"$STORE_PATH/$sidecar\" \"$OUT_DIR/$sidecar\"\n\
             fi\n\
         done\n",
        out_dir = guest_artifact_dir(transport, &job_id),
        flake_ref = shell_escape(flake_ref),
        attr = shell_escape(attr),
        egress_proxy_url = mvm_core::guest_netd::DEFAULT_EGRESS_PROXY_URL,
        no_proxy_loopback = mvm_core::guest_netd::NO_PROXY_LOOPBACK,
    );
    let cmd_path = sub.join("cmd.sh");
    std::fs::write(&cmd_path, script).with_context(|| format!("writing {}", cmd_path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&cmd_path, std::fs::Permissions::from_mode(0o755));
    }
    Ok(job_id)
}

/// Path on the host where the cmd.sh for `job_id` will have
/// copied the build artifacts. Caller checks for the presence of
/// `vmlinux` and `rootfs.ext4` after a successful dispatch.
fn artifact_dir_for(job_dir: &std::path::Path, job_id: &str) -> std::path::PathBuf {
    job_dir.join(job_id).join(ARTIFACT_SUBDIR)
}

/// Minimal POSIX-shell single-quote escape. Sufficient for the
/// closed flake_ref + attr_path shapes the supervisor accepts;
/// stricter validation belongs upstream in the IR.
fn shell_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for c in s.chars() {
        if c == '\'' {
            out.push_str(r"'\''");
        } else {
            out.push(c);
        }
    }
    out.push('\'');
    out
}

fn host_arch_for_attr() -> &'static str {
    if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else {
        "x86_64"
    }
}

fn print_outcome(outcome: &DispatchOutcome) {
    println!("job_id: {}", outcome.job_id);
    println!("exit_code: {}", outcome.exit_code);
    println!("build_ms: {}", outcome.job_timings.build_ms);
    if !outcome.stderr_chunks.is_empty() {
        println!("stderr_chunks ({}):", outcome.stderr_chunks.len());
        for line in &outcome.stderr_chunks {
            println!("  {line}");
        }
    }
    if !outcome.stderr_tail.is_empty() {
        println!("stderr_tail:");
        println!("{}", outcome.stderr_tail);
    }
}

/// `kill(pid, 0)` — checks that the process exists and we can
/// signal it without actually signalling. Returns `false` on
/// `ESRCH` / `EPERM`.
fn supervisor_alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        let rc = unsafe { libc::kill(pid as libc::pid_t, 0) };
        rc == 0
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        false
    }
}

fn send_sigterm(pid: u32) {
    #[cfg(unix)]
    {
        unsafe {
            let _ = libc::kill(pid as libc::pid_t, libc::SIGTERM);
        }
    }
}

/// Extract the supervisor PID. `PersistentVmHandle` doesn't expose
/// it publicly (the supervisor is internal); we reach in via the
/// process id of `std::process::Child` by going through `id()`
/// when available. Returns 0 if the handle's child has already
/// been consumed.
fn read_supervisor_pid(vm_state_dir: &Path) -> u32 {
    // The handle's `Child` is private, so read the PID from the
    // supervisor's PID file at <vm_state_dir>/builder.pid.
    let pid_path = vm_state_dir.join("builder.pid");
    // The PID file may not exist immediately — the supervisor
    // writes it after init. Brief retry.
    for _ in 0..50 {
        if let Ok(body) = std::fs::read_to_string(&pid_path)
            && let Ok(pid) = body.trim().parse::<u32>()
        {
            return pid;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    0
}

// Used in the `start` doc string; pulled in here just so the
// unused-import lint stays silent in the cfg-feature-gated
// signatures.
#[allow(dead_code)]
const _MARKER_CONST: &str = DISPATCH_SOCK_MARKER;
#[allow(dead_code)]
fn _force_read_use(r: HostVmResponseRead) -> HostVmResponseRead {
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persistent_backend_unset_and_libkrun_select_libkrun() {
        // No explicit selection → libkrun default, regardless of platform auto-detect.
        assert_eq!(
            persistent_backend(None).unwrap(),
            PersistentBackend::Libkrun
        );
        assert_eq!(
            persistent_backend(Some(BuilderBackendChoice::Libkrun)).unwrap(),
            PersistentBackend::Libkrun
        );
    }

    #[test]
    fn persistent_backend_selects_hvf_when_asked_for_it() {
        // hvf is the macOS 26+ auto-detect default, so refusing it here left
        // the whole persistent-builder path unreachable on that tier.
        assert_eq!(
            persistent_backend(Some(BuilderBackendChoice::Hvf)).unwrap(),
            PersistentBackend::Hvf
        );
    }

    #[test]
    fn persistent_backend_rejects_qemu_with_guidance() {
        let err = persistent_backend(Some(BuilderBackendChoice::Qemu)).unwrap_err();
        let msg = format!("{err}");
        // Names QEMU's absence and points at the supported backend.
        assert!(msg.contains("QEMU"), "{msg}");
        assert!(msg.contains("libkrun"), "{msg}");
    }

    #[test]
    fn shell_escape_wraps_value_in_single_quotes() {
        assert_eq!(shell_escape("simple"), "'simple'");
        assert_eq!(shell_escape("path:/work"), "'path:/work'");
    }

    #[test]
    fn shell_escape_handles_embedded_single_quote() {
        // The classic posix workaround: close quote, escaped
        // literal quote, re-open quote.
        assert_eq!(shell_escape("don't"), r"'don'\''t'");
    }

    #[test]
    fn host_arch_for_attr_returns_a_known_arch() {
        let a = host_arch_for_attr();
        assert!(a == "aarch64" || a == "x86_64", "got {a}");
    }

    #[test]
    fn stage_flake_cmd_sh_writes_valid_shell_under_per_job_subdir() {
        let scratch = tempfile::tempdir().expect("tempdir");
        let job_dir = scratch.path().to_path_buf();
        let relpath = stage_flake_cmd_sh(
            &job_dir,
            "path:/work",
            "packages.aarch64-linux.default",
            None,
        )
        .expect("stage");
        let cmd_path = job_dir.join(&relpath).join("cmd.sh");
        assert!(cmd_path.is_file(), "{}", cmd_path.display());
        let body = std::fs::read_to_string(&cmd_path).expect("read");
        // The shell script must reference the flake_ref + attr
        // (both escaped) and use the `nix build` invocation the
        // single-shot path also uses.
        assert!(body.contains("'path:/work'"), "{body}");
        assert!(body.contains("'packages.aarch64-linux.default'"), "{body}");
        assert!(body.contains("nix"), "{body}");
        assert!(body.starts_with("#!/bin/sh"), "{body}");
    }

    #[test]
    fn stage_flake_cmd_sh_uses_canonical_egress_proxy_contract() {
        let scratch = tempfile::tempdir().expect("tempdir");
        let relpath = stage_flake_cmd_sh(
            scratch.path(),
            "path:/work",
            "packages.aarch64-linux.default",
            None,
        )
        .expect("stage");
        let body =
            std::fs::read_to_string(scratch.path().join(relpath).join("cmd.sh")).expect("read");

        for key in [
            "ALL_PROXY",
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "all_proxy",
            "http_proxy",
            "https_proxy",
        ] {
            assert!(
                body.contains(&format!(
                    "export {key}='{}'",
                    mvm_core::guest_netd::DEFAULT_EGRESS_PROXY_URL
                )),
                "{body}"
            );
        }
        for key in ["NO_PROXY", "no_proxy"] {
            assert!(
                body.contains(&format!(
                    "export {key}='{}'",
                    mvm_core::guest_netd::NO_PROXY_LOOPBACK
                )),
                "{body}"
            );
        }
    }

    #[test]
    fn stage_flake_cmd_sh_creates_artifact_output_subdir() {
        // The cmd.sh dispatches `nix build` and then copies
        // vmlinux + rootfs.ext4 to a per-dispatch
        // out/ subdir. The host stages the empty subdir up-front
        // so the cmd.sh's `mkdir -p` is a no-op on success path
        // (and so the host can read from a known path without
        // racing the guest's mkdir).
        let scratch = tempfile::tempdir().expect("tempdir");
        let job_dir = scratch.path().to_path_buf();
        let relpath = stage_flake_cmd_sh(
            &job_dir,
            "path:/work",
            "packages.aarch64-linux.default",
            None,
        )
        .expect("stage");
        let artifact_dir = artifact_dir_for(&job_dir, &relpath);
        assert!(
            artifact_dir.is_dir(),
            "expected pre-staged artifact dir at {}",
            artifact_dir.display()
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(job_dir.join(&relpath))
                    .expect("staged job metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o777
            );
            assert_eq!(
                std::fs::metadata(&artifact_dir)
                    .expect("staged artifact metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o777
            );
        }
        // The cmd.sh body must reference the same in-guest path
        // (`/job/<relpath>/out`) so the bytes the guest writes are
        // visible at the host's `artifact_dir_for` path.
        let body = std::fs::read_to_string(job_dir.join(&relpath).join("cmd.sh")).expect("read");
        assert!(body.contains("export HOME=/tmp"));
        assert!(body.contains("export MVM_WORKSPACE_PATH=/work"));
        assert!(body.contains("export MVM_HOST_BIN_DIR=/mvm-bins"));
        assert!(body.contains("export XDG_CACHE_HOME=/tmp/.cache"));
        assert!(body.contains("export NIX_CONFIG="));
        assert!(body.contains("export HTTPS_PROXY='socks5h://127.0.0.1:1080'"));
        assert!(body.contains("export no_proxy='localhost,127.0.0.1,::1'"));
        assert!(body.contains("/sbin/nix-store --load-db < /nix-path-registration"));
        assert!(body.contains("fallback = true"));
        assert!(body.contains("download-attempts = 8"));
        assert!(body.contains("http-connections = 2"));
        assert!(body.contains("connect-timeout = 60"));
        assert!(body.contains("stalled-download-timeout = 300"));
        assert!(body.contains("export XDG_STATE_HOME=/tmp/.local/state"));
        assert!(body.contains("nix() { env HOME=\"$HOME\""));
        // Beside the artifacts, not in the job dir: `$OUT_DIR` is the one
        // directory the host reads back on either transport.
        assert!(body.contains("NIX_LOG=\"$OUT_DIR/nix-stderr.log\""));
        assert!(body.contains("NIX_STATUS=\"$OUT_DIR/nix-exit-status\""));
        assert!(body.contains("cat \"$NIX_LOG\" >&2"));
        assert!(body.contains("--impure --no-write-lock-file"));
        let expected_guest_path = format!("/job/{relpath}/out");
        assert!(
            body.contains(&expected_guest_path),
            "cmd.sh must write to {expected_guest_path}\n--- body ---\n{body}"
        );
        assert!(body.contains("vmlinux"), "{body}");
        assert!(body.contains("rootfs.ext4"), "{body}");
        assert!(body.contains("rootfs.verity"), "{body}");
        assert!(body.contains("rootfs.roothash"), "{body}");
        assert!(body.contains("rootfs-closure-paths"), "{body}");
        assert!(body.contains("mvm-meta.json"), "{body}");
        // `cp -L` (not just `cp`) so the host gets real bytes,
        // not store-path symlinks that don't resolve.
        assert!(body.contains("cp -L"), "must use cp -L: {body}");
    }

    #[test]
    fn a_disk_backed_dispatch_writes_artifacts_to_the_collected_directory() {
        // The trap this pins: the guest tars `/out` — and only `/out` — onto
        // the output disk. Under the disk transport `/job` is a bind onto the
        // guest's own input stage, so a cmd.sh still pointing at
        // `/job/<id>/out` runs clean and produces nothing the host can read.
        let scratch = tempfile::tempdir().expect("tempdir");
        let transport = SessionDiskTransport {
            input_disk: scratch.path().join("input.img"),
            output_disk: scratch.path().join("output.img"),
        };
        let relpath = stage_flake_cmd_sh(
            scratch.path(),
            "path:/work",
            "packages.aarch64-linux.default",
            Some(&transport),
        )
        .expect("stage");
        let body =
            std::fs::read_to_string(scratch.path().join(&relpath).join("cmd.sh")).expect("read");

        assert!(body.contains("OUT_DIR='/out'"), "{body}");
        assert!(
            !body.contains(&format!("/job/{relpath}/out")),
            "a disk-backed dispatch must not target the uncollected job dir: {body}"
        );
    }

    #[test]
    fn a_share_backed_dispatch_still_writes_into_the_shared_job_dir() {
        // The other half of the same contract: with shares, `/job` and `/out`
        // are the same host directory, and `artifact_dir_for` looks under the
        // job dir. Retargeting this one at `/out` would write to the wrong
        // place on libkrun.
        let scratch = tempfile::tempdir().expect("tempdir");
        let relpath = stage_flake_cmd_sh(
            scratch.path(),
            "path:/work",
            "packages.aarch64-linux.default",
            None,
        )
        .expect("stage");
        let body =
            std::fs::read_to_string(scratch.path().join(&relpath).join("cmd.sh")).expect("read");

        assert!(
            body.contains(&format!("OUT_DIR='/job/{relpath}/out'")),
            "{body}"
        );
    }

    #[test]
    fn summarize_artifacts_requires_vmlinux_and_rootfs() {
        let scratch = tempfile::tempdir().expect("tempdir");
        let dir = scratch.path().join("out");
        std::fs::create_dir_all(&dir).unwrap();
        assert!(summarize_artifacts(&dir).is_err(), "empty dir must fail");

        std::fs::write(dir.join("vmlinux"), b"fake-kernel").unwrap();
        assert!(
            summarize_artifacts(&dir).is_err(),
            "missing rootfs must fail"
        );

        std::fs::write(dir.join("rootfs.ext4"), b"fake-rootfs").unwrap();
        let summary = summarize_artifacts(&dir).expect("now complete");
        assert_eq!(summary.vmlinux_bytes, 11);
        assert_eq!(summary.rootfs_bytes, 11);
        assert!(summary.manifest.is_none(), "no manifest staged");

        std::fs::write(dir.join("manifest.json"), b"{}").unwrap();
        let summary = summarize_artifacts(&dir).expect("with manifest");
        assert!(summary.manifest.is_some());
    }

    #[test]
    fn summarize_artifacts_rejects_missing_dir() {
        let scratch = tempfile::tempdir().expect("tempdir");
        let dir = scratch.path().join("does-not-exist");
        let err = summarize_artifacts(&dir).expect_err("missing dir");
        let msg = format!("{err:#}");
        assert!(msg.contains("missing artifact dir"), "{msg}");
    }

    #[test]
    fn session_record_roundtrips_through_json() {
        let record = SessionRecord {
            session_id: "abc123".to_string(),
            dispatch_socket_path: PathBuf::from("/tmp/sock"),
            disk_transport: None,
            job_dir: PathBuf::from("/tmp/jobs"),
            workspace_root: PathBuf::from("/work"),
            supervisor_pid: 4242,
            last_activity_unix_secs: Some(1234567890),
        };
        let json = serde_json::to_vec(&record).expect("serialize");
        let back: SessionRecord = serde_json::from_slice(&json).expect("deserialize");
        assert_eq!(back.session_id, "abc123");
        assert_eq!(back.dispatch_socket_path, PathBuf::from("/tmp/sock"));
        assert_eq!(back.supervisor_pid, 4242);
    }
}
