//! Persistent builder lifecycle and dispatch, independent of command presentation.
//!
//! Start owns its VM until the shared session record is atomically published.
//! All record transactions use the build layer's stable record lock; backend
//! handles and disk transport remain private to this implementation.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};

use mvm_build::builder_backend_select::{
    BuilderBackendChoice, auto_detect_default, resolve_env_override,
};
use mvm_build::builder_vm::BuilderJob;
use mvm_build::libkrun_builder::{LibkrunPersistentHostVm, PersistentVmHandle};
use mvm_build::persistent_builder::{
    PersistentBuilderSupervisor, SessionDiskTransport, current_unix_secs, guest_artifact_dir,
    read_dispatch_artifacts, repack_dispatch_input,
};

#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct PersistentBuilderError(#[from] anyhow::Error);

#[derive(Debug, Clone)]
pub struct PersistentBuilderStart {
    /// Host directory bound at `/work` inside the persistent VM.
    /// Defaults to the current working directory.
    pub workspace: Option<PathBuf>,
    /// Guest memory in MiB for the persistent Nix builder.
    pub memory_mib: u32,
}

/// Guest memory for a persistent builder when nobody names one. Shared by the
/// `--memory-mib` default and the auto-start path, so a build that starts a
/// session on contention gets the same builder an explicit `start` would.
const DEFAULT_MEMORY_MIB: u32 = 4096;

impl Default for PersistentBuilderStart {
    fn default() -> Self {
        Self {
            workspace: None,
            memory_mib: DEFAULT_MEMORY_MIB,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PersistentBuilderSubmit {
    /// Flake reference to build (e.g. `path:/work#packages.default`).
    pub flake: String,
    /// Flake attribute path. Defaults to `packages.<host_arch>-linux.default`.
    pub attr: Option<String>,
}

/// Snapshot only; no runtime handle or backend escapes the service.
#[derive(Debug, Clone)]
pub struct PersistentBuilderStatus {
    pub session_id: String,
    pub workspace_root: PathBuf,
    pub dispatch_socket_path: PathBuf,
    pub supervisor_pid: u32,
    pub alive: bool,
    pub last_activity_unix_secs: Option<u64>,
}

use mvm_build::persistent_builder::{SessionRecord, SessionRecordGuard};

impl From<&SessionRecord> for PersistentBuilderStatus {
    fn from(record: &SessionRecord) -> Self {
        Self {
            session_id: record.session_id.clone(),
            workspace_root: record.workspace_root.clone(),
            dispatch_socket_path: record.dispatch_socket_path.clone(),
            supervisor_pid: record.supervisor_pid,
            alive: supervisor_alive(record.supervisor_pid),
            last_activity_unix_secs: record.last_activity_unix_secs,
        }
    }
}

fn session_record_path() -> PathBuf {
    PathBuf::from(mvm_core::config::mvm_runtime_dir()).join("persistent-builder.json")
}

#[cfg(test)]
fn write_session_record(record: &SessionRecord) -> Result<()> {
    SessionRecordGuard::acquire()?.write(record)?;
    Ok(())
}

fn read_session_record(guard: &SessionRecordGuard) -> Result<SessionRecord> {
    let path = session_record_path();
    guard.read().with_context(|| {
        format!(
            "no persistent-builder session record at {} \
             (start one with `mvmctl persistent-builder start`)",
            path.display()
        )
    })
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
/// host VM to spawn. An unset selection uses the platform default, so a
/// supported Mac stays on native HVF rather than silently requiring libkrun.
/// QEMU has no persistent host VM, so it fails closed with guidance.
fn persistent_backend(explicit: Option<BuilderBackendChoice>) -> Result<PersistentBackend> {
    persistent_backend_for(explicit.unwrap_or_else(auto_detect_default))
}

fn persistent_backend_for(choice: BuilderBackendChoice) -> Result<PersistentBackend> {
    match choice {
        BuilderBackendChoice::Libkrun => Ok(PersistentBackend::Libkrun),
        BuilderBackendChoice::Hvf => Ok(PersistentBackend::Hvf),
        BuilderBackendChoice::Qemu => bail!(
            "`mvmctl persistent-builder start` has no QEMU persistent builder \
             (QEMU is a one-shot builder). On supported Apple Silicon macOS, \
             use the automatic HVF selection; libkrun remains an explicit \
             contributor integration."
        ),
        BuilderBackendChoice::Firecracker => bail!(
            "`mvmctl persistent-builder start` has no Firecracker persistent builder \
             yet (Firecracker serves one-shot builder jobs and Stage 0). Use \
             `--builder hvf` on a supported Mac, or `--builder libkrun`."
        ),
        BuilderBackendChoice::WebLinux => bail!(
            "`mvmctl persistent-builder start` has no WebLinux persistent builder \
             (WebLinux is browser-only). Use the native HVF path on a supported Mac."
        ),
    }
}

pub fn start_persistent_builder(
    args: PersistentBuilderStart,
) -> Result<PersistentBuilderStatus, PersistentBuilderError> {
    start(args).map_err(Into::into)
}

fn start(args: PersistentBuilderStart) -> Result<PersistentBuilderStatus> {
    let guard = SessionRecordGuard::acquire()?;
    // Resolve the backend from the explicit selection (the `--builder` flag is
    // folded into `MVM_BUILDER_BACKEND` at startup, so the env reflects it).
    let backend = persistent_backend(resolve_env_override())?;

    if current_session_record(&guard)?.is_some() {
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
        PersistentBackend::Libkrun => start_libkrun_persistent(&guard, workspace, args.memory_mib)?,
        PersistentBackend::Hvf => start_hvf_persistent(&guard, workspace, args.memory_mib)?,
    };
    Ok(PersistentBuilderStatus::from(&record))
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
pub fn start_session_for_contended_build() -> Result<mvm_build::persistent_builder::SessionRecord> {
    let guard = SessionRecordGuard::acquire()?;
    // Another process may have published a record between `mvm-build`'s check
    // and this call.
    if let Some(existing) = current_session_record(&guard)? {
        return Ok(existing);
    }

    let backend = persistent_backend(resolve_env_override())?;
    let workspace = std::env::current_dir()
        .context("resolving the working directory for the builder session")?;
    let record = match backend {
        PersistentBackend::Libkrun => {
            start_libkrun_persistent(&guard, workspace, DEFAULT_MEMORY_MIB)?
        }
        PersistentBackend::Hvf => start_hvf_persistent(&guard, workspace, DEFAULT_MEMORY_MIB)?,
    };
    Ok(record)
}

/// The session this command may use, if there is one. A session left by an
/// `mvmctl` with other builder binaries is stopped rather than reused: it would
/// keep running the binaries it booted with.
fn current_session_record(guard: &SessionRecordGuard) -> Result<Option<SessionRecord>> {
    let current = mvm_build::builder_boot::current_payload_digest();
    current_session_record_with_current(guard, current.as_ref().map(|digest| digest.as_str()))
}

fn current_session_record_with_current(
    guard: &SessionRecordGuard,
    current: Option<&str>,
) -> Result<Option<SessionRecord>> {
    let record = match guard.read() {
        Ok(record) => record,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if !supervisor_alive(record.supervisor_pid) {
        let _ = guard.remove();
        return Ok(None);
    }
    if mvm_build::persistent_builder::session_payload_is_current(
        record.boot_payload_digest.as_deref(),
        current,
    ) {
        return Ok(Some(record));
    }
    stop_stale_session_record(guard, &record)?;
    Ok(None)
}

fn checked_current_session_record(guard: &SessionRecordGuard) -> Result<SessionRecord> {
    let current = mvm_build::builder_boot::current_payload_digest();
    checked_current_session_record_locked(guard, current.as_ref().map(|digest| digest.as_str()))
}

#[cfg(test)]
fn checked_current_session_record_with_current(current: Option<&str>) -> Result<SessionRecord> {
    checked_current_session_record_locked(&SessionRecordGuard::acquire()?, current)
}

fn checked_current_session_record_locked(
    guard: &SessionRecordGuard,
    current: Option<&str>,
) -> Result<SessionRecord> {
    let record = read_session_record(guard)?;
    if mvm_build::persistent_builder::session_payload_is_current(
        record.boot_payload_digest.as_deref(),
        current,
    ) {
        return Ok(record);
    }
    stop_stale_session_record(guard, &record)?;
    read_session_record(guard)
}

fn stop_stale_session_record(guard: &SessionRecordGuard, record: &SessionRecord) -> Result<()> {
    tracing::info!(
        "stopping persistent builder {}: it runs other builder binaries than this mvmctl",
        record.session_id
    );
    guard.stop(record);
    if guard.read().is_ok() {
        bail!("persistent builder shutdown could not be confirmed; session record retained");
    }
    Ok(())
}

/// Extract the host-vm binaries a persistent builder receives at `/mvm-bins`,
/// and make the tree traversable while the raw input tar is packed.
fn ensure_persistent_host_bins() -> Result<PathBuf> {
    let host_bin_dir = mvm_build::builder_boot::registered_host_bin_dir()
        .context("extracting host-vm binaries for persistent builder")?
        .context("the registered builder payload source does not provide host binaries")?;
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
/// The HVF driver hands the store lock path to its supervisor, so the lock
/// outlives this caller along with the VM.
fn start_hvf_persistent(
    guard: &SessionRecordGuard,
    workspace: PathBuf,
    memory_mib: u32,
) -> Result<SessionRecord> {
    let host_bin_dir = ensure_persistent_host_bins()?;
    let image = mvm_runtime::builder_runner::resolve_driver_builder_image()
        .map_err(|e| anyhow::anyhow!(e))
        .context("resolving the hvf builder image for the persistent builder")?;
    let (kernel, rootfs, closure_nar) = (image.kernel, image.rootfs, image.closure_nar);

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
        boot_payload_digest: session.boot_payload_digest().map(str::to_string),
    };
    // Same reason as the libkrun path: the supervisor must outlive this
    // command, so the handle is leaked rather than dropped.
    publish_started_session(guard, &record, session)?;
    Ok(record)
}

/// vCPUs for a persistent builder session. Matches the one-shot builder's
/// default; `nix build` parallelizes at the derivation level.
const DEFAULT_PERSISTENT_VCPUS: u32 = 4;

/// Spawn the libkrun persistent builder and build its session record.
fn start_libkrun_persistent(
    guard: &SessionRecordGuard,
    workspace: PathBuf,
    memory_mib: u32,
) -> Result<SessionRecord> {
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
        disk_transport: Some(SessionDiskTransport {
            input_disk: handle.input_disk().to_path_buf(),
            output_disk: handle.output_disk().to_path_buf(),
        }),
        workspace_root: workspace,
        supervisor_pid: read_supervisor_pid(handle.vm_state_dir()),
        last_activity_unix_secs: Some(current_unix_secs()),
        boot_payload_digest: handle.boot_payload_digest().map(str::to_string),
    };
    publish_started_session(guard, &record, handle)?;
    Ok(record)
}

/// Private ownership boundary. Runtime handles do not reliably clean up on
/// Drop, so publication failure explicitly kills the still-owned VM.
trait StartedSession: Sized {
    fn terminate(self) -> Result<()>;

    fn detach(self) {
        // The supervisor holds its own store lock and must outlive this caller.
        std::mem::forget(self);
    }
}

impl StartedSession for PersistentVmHandle {
    fn terminate(mut self) -> Result<()> {
        self.kill()
            .context("terminating the libkrun builder supervisor")
    }
}

impl StartedSession for mvm_runtime::builder_runner::hvf_persistent::PersistentHvfSession {
    fn terminate(self) -> Result<()> {
        // Unlike the libkrun handle, HVF retains a PID, not an owned Child.
        // Do not delegate to its PID-only kill path after publication fails.
        let state_dir = self.state_dir();
        let pid = self.supervisor_pid().with_context(|| {
            format!(
                "HVF builder has no supervisor PID; inspect {} for cleanup",
                state_dir.display()
            )
        })?;
        mvm_build::persistent_builder::terminate_supervisor(pid).with_context(|| {
            format!(
                "HVF builder cleanup uncertain: PID {pid}, state {}",
                state_dir.display()
            )
        })?;
        if supervisor_alive(pid) {
            bail!(
                "HVF builder SIGTERM sent but exit is unconfirmed; inspect PID {pid} and {} for cleanup",
                state_dir.display()
            );
        }
        Ok(())
    }
}

fn publish_started_session(
    guard: &SessionRecordGuard,
    record: &SessionRecord,
    session: impl StartedSession,
) -> Result<()> {
    let publication = if record.supervisor_pid == 0 || record.supervisor_pid > i32::MAX as u32 {
        Err(std::io::Error::other(
            "persistent builder has no valid supervisor PID",
        ))
    } else {
        guard.write(record)
    };
    if let Err(error) = publication {
        session.terminate().with_context(|| {
            format!("publishing persistent builder failed: {error}; cleanup also failed")
        })?;
        return Err(error.into());
    }
    session.detach();
    Ok(())
}

/// Completed dispatch, including best-effort artifact diagnostics.
#[derive(Debug)]
pub struct PersistentBuilderResult {
    pub job_id: String,
    pub exit_code: i32,
    pub build_ms: u64,
    pub stderr_chunks: Vec<String>,
    pub stderr_tail: String,
    pub artifact_dir: Option<PathBuf>,
    /// The dm-verity root hash the host computed over the returned rootfs,
    /// when the build declared one.
    pub rootfs_roothash: Option<String>,
    pub artifacts: Option<PersistentBuilderArtifacts>,
    pub warnings: Vec<String>,
}

pub fn submit_persistent_builder(
    args: PersistentBuilderSubmit,
) -> Result<PersistentBuilderResult, PersistentBuilderError> {
    submit(args).map_err(Into::into)
}

fn submit(args: PersistentBuilderSubmit) -> Result<PersistentBuilderResult> {
    let guard = SessionRecordGuard::acquire()?;
    let record = checked_current_session_record(&guard)?;
    if !supervisor_alive(record.supervisor_pid) {
        let _ = guard.remove();
        bail!(
            "recorded supervisor PID {} is not alive — session record cleared. \
             Start a new session with `mvmctl persistent-builder start`.",
            record.supervisor_pid
        );
    }

    let attr = args
        .attr
        .unwrap_or_else(|| format!("packages.{}-linux.default", host_arch_for_attr()));
    let _ = guard.touch(current_unix_secs());
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
    let _ = guard.touch(current_unix_secs());

    let mut warnings = Vec::new();

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
        warnings.push(format!("reading the dispatch output disk failed: {e}"));
    }

    let mut artifacts = None;
    let mut result_artifact_dir = None;
    let mut rootfs_roothash = None;
    if outcome.exit_code == 0 {
        let artifact_dir = artifact_dir_for(&record.job_dir, &job_dir_relpath);
        rootfs_roothash = mvm_build::builder_output::seal_declared_rootfs(&artifact_dir)
            .context("sealing the dispatch's rootfs")?;
        match summarize_artifacts(&artifact_dir) {
            Ok(summary) => {
                result_artifact_dir = Some(artifact_dir);
                artifacts = Some(summary);
            }
            Err(e) => {
                warnings.push(format!(
                    "dispatch succeeded but artifact dir at {} is incomplete: {e}",
                    artifact_dir.display()
                ));
            }
        }
    }

    Ok(PersistentBuilderResult {
        job_id: outcome.job_id.to_string(),
        exit_code: outcome.exit_code,
        build_ms: outcome.job_timings.build_ms,
        stderr_chunks: outcome.stderr_chunks,
        stderr_tail: outcome.stderr_tail,
        artifact_dir: result_artifact_dir,
        rootfs_roothash,
        artifacts,
        warnings,
    })
}

/// On-disk summary of what `stage_flake_cmd_sh`'s cmd.sh
/// produced. Both `vmlinux` and `rootfs.ext4` are required;
/// `manifest.json` is an optional sidecar (some flakes emit it,
/// some don't).
#[derive(Debug)]
pub struct PersistentBuilderArtifacts {
    pub vmlinux: std::path::PathBuf,
    pub vmlinux_bytes: u64,
    pub rootfs: std::path::PathBuf,
    pub rootfs_bytes: u64,
    pub manifest: Option<std::path::PathBuf>,
}

fn summarize_artifacts(dir: &std::path::Path) -> Result<PersistentBuilderArtifacts> {
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
    Ok(PersistentBuilderArtifacts {
        vmlinux,
        vmlinux_bytes: vmlinux_meta.len(),
        rootfs,
        rootfs_bytes: rootfs_meta.len(),
        manifest,
    })
}

pub fn stop_persistent_builder() -> Result<Vec<String>, PersistentBuilderError> {
    stop().map_err(Into::into)
}

fn stop() -> Result<Vec<String>> {
    let guard = SessionRecordGuard::acquire()?;
    let record = read_session_record(&guard)?;
    let mut warnings = Vec::new();
    if !supervisor_alive(record.supervisor_pid) {
        warnings.push(format!(
            "supervisor PID {} not alive — clearing stale session record",
            record.supervisor_pid
        ));
        guard.remove()?;
        return Ok(warnings);
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
        warnings.push(format!(
            "supervisor PID {} did not exit within 30s; sending SIGTERM",
            record.supervisor_pid
        ));
        mvm_build::persistent_builder::terminate_supervisor(record.supervisor_pid)
            .context("persistent builder force-stop failed; session record retained")?;
    }

    if !guard.clear_stopped(&record)? {
        bail!("persistent builder shutdown could not be confirmed; session record retained");
    }
    Ok(warnings)
}

pub fn persistent_builder_status() -> Result<PersistentBuilderStatus, PersistentBuilderError> {
    status().map_err(Into::into)
}

fn status() -> Result<PersistentBuilderStatus> {
    let guard = SessionRecordGuard::acquire()?;
    read_session_record(&guard).map(|record| PersistentBuilderStatus::from(&record))
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
    let job_id = mvm_build::builder_protocol::JobId::new().to_string();
    let sub = job_dir.join(&job_id);
    let artifact_dir = sub.join(ARTIFACT_SUBDIR);
    std::fs::create_dir_all(&artifact_dir)
        .with_context(|| format!("creating {}", artifact_dir.display()))?;
    mvm_build::builder_job_contract::write_marker(&sub)
        .with_context(|| format!("stamping {} with its job contract", sub.display()))?;
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
         # The guest sidecar, when the image publishes one.\n\
         if [ -f \"$STORE_PATH/mvm-meta.json\" ]; then\n\
             cp -L \"$STORE_PATH/mvm-meta.json\" \"$OUT_DIR/mvm-meta.json\"\n\
         fi\n\
         # Every other member a build returns. The dm-verity pair is not\n\
         # one: the host computes it over the rootfs it receives.\n\
         {copy_members_sh}",
        copy_members_sh = mvm_build::builder_output::copy_nix_output_members_sh(
            "\"$STORE_PATH\"",
            "\"$OUT_DIR\""
        ),
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

/// Signal zero checks existence. Only ESRCH proves exit; permission errors
/// retain the record rather than allow another VM to replace it.
fn supervisor_alive(pid: u32) -> bool {
    mvm_build::persistent_builder::supervisor_alive(pid)
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

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::util::test_env::TestEnv;

    struct TestSession<'a> {
        terminated: &'a std::cell::Cell<bool>,
        detached: &'a std::cell::Cell<bool>,
        cleanup_fails: bool,
    }

    impl StartedSession for TestSession<'_> {
        fn terminate(self) -> Result<()> {
            self.terminated.set(true);
            if self.cleanup_fails {
                bail!("injected cleanup failure");
            }
            Ok(())
        }

        fn detach(self) {
            self.detached.set(true);
        }
    }

    #[test]
    fn publication_failure_terminates_owned_session_without_detaching() {
        let scratch = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(scratch.path());
        let guard = SessionRecordGuard::acquire().unwrap();
        // Rename cannot replace a directory; this exercises the final atomic
        // publication failure after the temporary record has been written.
        std::fs::create_dir(session_record_path()).unwrap();
        let terminated = std::cell::Cell::new(false);
        let detached = std::cell::Cell::new(false);
        let result = publish_started_session(
            &guard,
            &session_record_fixture(None),
            TestSession {
                terminated: &terminated,
                detached: &detached,
                cleanup_fails: false,
            },
        );
        assert!(result.is_err());
        assert!(terminated.get());
        assert!(!detached.get());
        assert!(session_record_path().is_dir());
    }

    #[test]
    fn cleanup_failure_keeps_publication_error_context() {
        let scratch = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(scratch.path());
        let guard = SessionRecordGuard::acquire().unwrap();
        let mut record = session_record_fixture(None);
        record.supervisor_pid = 0;
        let terminated = std::cell::Cell::new(false);
        let detached = std::cell::Cell::new(false);
        let error = publish_started_session(
            &guard,
            &record,
            TestSession {
                terminated: &terminated,
                detached: &detached,
                cleanup_fails: true,
            },
        )
        .unwrap_err();
        let detail = format!("{error:#}");
        assert!(detail.contains("no valid supervisor PID"));
        assert!(detail.contains("injected cleanup failure"));
        assert!(terminated.get());
        assert!(!detached.get());
        assert!(!session_record_path().exists());
    }

    #[test]
    fn successful_publication_detaches_only_after_record_exists() {
        let scratch = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(scratch.path());
        let guard = SessionRecordGuard::acquire().unwrap();
        let record = session_record_fixture(None);
        let terminated = std::cell::Cell::new(false);
        let detached = std::cell::Cell::new(false);
        publish_started_session(
            &guard,
            &record,
            TestSession {
                terminated: &terminated,
                detached: &detached,
                cleanup_fails: false,
            },
        )
        .unwrap();
        assert_eq!(guard.read().unwrap().session_id, record.session_id);
        assert!(detached.get());
        assert!(!terminated.get());
    }

    fn session_record_fixture(boot_payload_digest: Option<&str>) -> SessionRecord {
        SessionRecord {
            session_id: "session-123".to_string(),
            dispatch_socket_path: PathBuf::from("/tmp/does-not-exist.sock"),
            disk_transport: None,
            job_dir: PathBuf::from("/tmp/jobs"),
            workspace_root: PathBuf::from("/tmp/work"),
            supervisor_pid: 2_000_000_000,
            last_activity_unix_secs: Some(1234567890),
            boot_payload_digest: boot_payload_digest.map(str::to_string),
        }
    }

    #[test]
    fn persistent_backend_keeps_libkrun_explicit_only() {
        assert_eq!(
            persistent_backend_for(BuilderBackendChoice::Libkrun).unwrap(),
            PersistentBackend::Libkrun
        );
    }

    #[test]
    fn persistent_backend_uses_hvf_for_the_standard_macos_choice() {
        assert_eq!(
            persistent_backend_for(BuilderBackendChoice::Hvf).unwrap(),
            PersistentBackend::Hvf
        );
    }

    #[test]
    fn persistent_backend_rejects_qemu_with_guidance() {
        let err = persistent_backend_for(BuilderBackendChoice::Qemu).unwrap_err();
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
        mvm_build::builder_job_contract::check_job_dir(&job_dir.join(&relpath))
            .expect("a dispatch job dir carries the job contract marker");
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
        assert!(body.contains("mvm-meta.json"), "{body}");
        // The member set every one-shot build returns, and no verity pair:
        // the host seals the rootfs it receives.
        assert!(
            body.contains(&mvm_build::builder_output::copy_nix_output_members_sh(
                "\"$STORE_PATH\"",
                "\"$OUT_DIR\""
            )),
            "{body}"
        );
        assert!(body.contains("initrd"), "{body}");
        assert!(body.contains("rootfs-closure-paths"), "{body}");
        assert!(!body.contains("rootfs.verity"), "{body}");
        assert!(!body.contains("rootfs.roothash"), "{body}");
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
            boot_payload_digest: Some("a".repeat(64)),
        };
        let json = serde_json::to_vec(&record).expect("serialize");
        let back: SessionRecord = serde_json::from_slice(&json).expect("deserialize");
        assert_eq!(back.session_id, "abc123");
        assert_eq!(back.dispatch_socket_path, PathBuf::from("/tmp/sock"));
        assert_eq!(back.supervisor_pid, 4242);
        // The digest survives into the copy `mvm-build` reads, which is the
        // one that decides whether a build may dispatch into the session.
        assert_eq!(back.boot_payload_digest, Some("a".repeat(64)));
    }

    #[test]
    fn checked_current_session_record_keeps_matching_payload() {
        let scratch = tempfile::tempdir().expect("tempdir");
        let mut env = TestEnv::new();
        env.isolate_mvm_home(scratch.path().join("mvm-home"));
        write_session_record(&session_record_fixture(Some("current-digest"))).expect("record");

        let record = checked_current_session_record_with_current(Some("current-digest"))
            .expect("current session");
        assert_eq!(record.session_id, "session-123");
    }

    #[test]
    fn checked_current_session_record_preserves_missing_record_error() {
        let scratch = tempfile::tempdir().expect("tempdir");
        let mut env = TestEnv::new();
        env.isolate_mvm_home(scratch.path().join("mvm-home"));

        let err = checked_current_session_record_with_current(Some("current-digest"))
            .expect_err("missing record must fail");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("no persistent-builder session record"),
            "{msg}"
        );
    }

    #[test]
    fn checked_current_session_record_rejects_stale_payload_and_clears_record() {
        let scratch = tempfile::tempdir().expect("tempdir");
        let mvm_home = scratch.path().join("mvm-home");
        let mut env = TestEnv::new();
        env.isolate_mvm_home(&mvm_home);
        write_session_record(&session_record_fixture(Some("stale-digest"))).expect("record");

        let err = checked_current_session_record_with_current(Some("current-digest"))
            .expect_err("stale record must fail");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("no persistent-builder session record"),
            "{msg}"
        );
        assert!(
            !session_record_path().exists(),
            "stale session record should be cleared after stop"
        );
    }
}
