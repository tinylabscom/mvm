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
//! This is deliberately separate from `mvmctl dev up`. The
//! lifecycle binding (`mvmctl dev up` auto-starts the persistent
//! supervisor) lands in a follow-up. Once it does, `mvmctl dev up`
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
//! - Auto-start from `mvmctl dev up` (post-merge follow-up).
//! - `mvmctl build` routing into the persistent supervisor when a
//!   session is active (`submit` now produces real artifacts, so
//!   the routing target exists).
//! - Install variant dispatch.
//! - Stderr streaming.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::{Args as ClapArgs, Subcommand};
use serde::{Deserialize, Serialize};

use mvm_build::builder_protocol::HostVmResponseRead;
use mvm_build::builder_vm::BuilderJob;
use mvm_build::libkrun_builder::{
    DISPATCH_SOCK_MARKER, LibkrunPersistentHostVm, PersistentVmHandle,
};
use mvm_build::persistent_builder::{
    DispatchOutcome, PersistentBuilderSupervisor, current_unix_secs,
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
}

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
    /// Per-VM job dir (bound at `/job` in the guest). `submit`
    /// stages each call's cmd.sh under a fresh
    /// `<job_dir_relpath>` here.
    job_dir: PathBuf,
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
    mvm_core::config::mvm_data_dir_strict()
        .unwrap_or_else(|_| {
            std::env::var_os("HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("/tmp"))
                .join(".mvm")
        })
        .join("run")
        .join("persistent-builder.json")
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

fn run_start(args: StartArgs) -> Result<()> {
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

    let vm = LibkrunPersistentHostVm::new(&workspace);
    let handle = vm
        .start()
        .context("spawning persistent builder VM (LibkrunPersistentHostVm::start)")?;

    let supervisor_pid = handle_pid(&handle);
    let record = SessionRecord {
        session_id: handle.session_id().to_string(),
        dispatch_socket_path: handle.dispatch_socket_path(),
        job_dir: handle.job_dir().to_path_buf(),
        workspace_root: workspace,
        supervisor_pid,
        last_activity_unix_secs: Some(current_unix_secs()),
    };
    write_session_record(&record)?;

    // We intentionally LEAK the handle here — the supervisor
    // child stays running after this process exits. `stop`
    // reattaches via the PID in the session record. The held
    // `_nix_store_lock` inside the handle goes away when this
    // process exits but the kernel-level flock follows the fd,
    // which the supervisor's parent (now PID 1 after we exit)
    // doesn't own — so the lock is released on our exit. That's
    // a known gap: between this exit and the supervisor exit,
    // another `mvmctl deps install` can take the lock. The
    // mvmctl-side session record acts as a soft mutex (start
    // refuses if one exists). Hardening to keep the kernel lock
    // alive across CLI invocations is a follow-up.
    std::mem::forget(handle);

    println!("session_id: {}", record.session_id);
    println!("dispatch_socket: {}", record.dispatch_socket_path.display());
    println!("supervisor_pid: {}", record.supervisor_pid);
    Ok(())
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
    let job_dir_relpath = stage_flake_cmd_sh(&record.job_dir, &args.flake, &attr)?;

    let supervisor = PersistentBuilderSupervisor::new(&record.dispatch_socket_path)
        .with_frame_read_timeout(Duration::from_secs(60));

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
fn stage_flake_cmd_sh(job_dir: &std::path::Path, flake_ref: &str, attr: &str) -> Result<String> {
    let job_id = uuid::Uuid::new_v4().to_string();
    let sub = job_dir.join(&job_id);
    let artifact_dir = sub.join(ARTIFACT_SUBDIR);
    std::fs::create_dir_all(&artifact_dir)
        .with_context(|| format!("creating {}", artifact_dir.display()))?;
    let script = format!(
        "#!/bin/sh\n\
         set -eu\n\
         OUT_DIR='/job/{job_id}/{artifact_subdir}'\n\
         mkdir -p \"$OUT_DIR\"\n\
         STORE_PATH=$(nix --extra-experimental-features 'nix-command flakes' \\\n\
             build --no-link --print-out-paths \\\n\
             {flake_ref}#{attr})\n\
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
         fi\n",
        artifact_subdir = ARTIFACT_SUBDIR,
        flake_ref = shell_escape(flake_ref),
        attr = shell_escape(attr),
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
fn handle_pid(handle: &PersistentVmHandle) -> u32 {
    // PersistentVmHandle's `Child` is private. We can't read its
    // PID directly. For now read it from the supervisor's PID
    // file at <vm_state_dir>/builder.pid which the libkrun
    // supervisor writes (see SupervisorConfig::pid_file_name).
    let pid_path = handle.vm_state_dir().join("builder.pid");
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
        let relpath = stage_flake_cmd_sh(&job_dir, "path:/work", "packages.aarch64-linux.default")
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
    fn stage_flake_cmd_sh_creates_artifact_output_subdir() {
        // The cmd.sh dispatches `nix build` and then copies
        // vmlinux + rootfs.ext4 to a per-dispatch
        // out/ subdir. The host stages the empty subdir up-front
        // so the cmd.sh's `mkdir -p` is a no-op on success path
        // (and so the host can read from a known path without
        // racing the guest's mkdir).
        let scratch = tempfile::tempdir().expect("tempdir");
        let job_dir = scratch.path().to_path_buf();
        let relpath = stage_flake_cmd_sh(&job_dir, "path:/work", "packages.aarch64-linux.default")
            .expect("stage");
        let artifact_dir = artifact_dir_for(&job_dir, &relpath);
        assert!(
            artifact_dir.is_dir(),
            "expected pre-staged artifact dir at {}",
            artifact_dir.display()
        );
        // The cmd.sh body must reference the same in-guest path
        // (`/job/<relpath>/out`) so the bytes the guest writes are
        // visible at the host's `artifact_dir_for` path.
        let body = std::fs::read_to_string(job_dir.join(&relpath).join("cmd.sh")).expect("read");
        let expected_guest_path = format!("/job/{relpath}/out");
        assert!(
            body.contains(&expected_guest_path),
            "cmd.sh must write to {expected_guest_path}\n--- body ---\n{body}"
        );
        assert!(body.contains("vmlinux"), "{body}");
        assert!(body.contains("rootfs.ext4"), "{body}");
        // `cp -L` (not just `cp`) so the host gets real bytes,
        // not store-path symlinks that don't resolve.
        assert!(body.contains("cp -L"), "must use cp -L: {body}");
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
