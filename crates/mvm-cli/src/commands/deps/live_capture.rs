//! Capture dependency artifacts from a running development VM.
//!
//! The guest is read through the agent filesystem RPC rather than through a
//! host share or a guest shell. The export is bounded, rejects symlinks and
//! special files, and is staged under a temporary host directory before the
//! existing capture path verifies and reseals it.

use anyhow::{Context, Result, bail};
use clap::Args as ClapArgs;
use serde::Serialize;
use std::collections::HashSet;
use std::fs;
use std::path::{Component, Path, PathBuf};

use mvm_agentd::vsock::{FsEntryKind, FsResult, GuestRequest};
use mvm_client::LocalBackend;
use mvm_client::inventory::{WorkloadPosture, list_local_inventory};
use mvm_core::client::dto::MachineStatus;

use super::capture::{CaptureOutcome, CaptureRequest, capture_volume};

const DEFAULT_MAX_BYTES: u64 = 512 * 1024 * 1024;
const DEFAULT_MAX_FILES: u64 = 100_000;
const MAX_DIRECTORY_DEPTH: usize = 256;

/// Arguments for importing dependency artifacts from a running development VM.
#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// Existing sealed dependency volume to replace.
    #[arg(value_name = "VOLUME_HASH")]
    pub volume_hash: String,

    /// Running development VM containing the installed dependency tree.
    #[arg(long, value_name = "VM")]
    pub vm: String,

    /// Absolute guest directory containing the installed dependency tree.
    #[arg(long, value_name = "PATH")]
    pub guest_content: String,

    /// Absolute guest path to the fresh CycloneDX SBOM.
    #[arg(long, value_name = "PATH")]
    pub guest_sbom: String,

    /// Absolute guest path to the install fetch log.
    #[arg(long, value_name = "PATH")]
    pub guest_fetch_log: String,

    /// Absolute guest path to the fresh CVE result.
    #[arg(long, value_name = "PATH")]
    pub guest_cve: String,

    /// Override the sealed dependency-volume cache root.
    #[arg(long)]
    pub cache_root: Option<PathBuf>,

    /// Emit a machine-readable JSON result on stdout.
    #[arg(long)]
    pub json: bool,

    /// Write the captured dependency declaration as the canonical SDK/IR
    /// dependency object.
    #[arg(long, value_name = "PATH", requires = "lockfile")]
    pub declaration: Option<PathBuf>,

    /// Local lockfile whose bytes must match the sealed volume pin.
    #[arg(long, value_name = "PATH", requires = "declaration")]
    pub lockfile: Option<PathBuf>,

    /// Maximum combined bytes exported from the guest.
    #[arg(long, default_value_t = DEFAULT_MAX_BYTES)]
    pub max_bytes: u64,

    /// Maximum number of regular files exported from the guest.
    #[arg(long, default_value_t = DEFAULT_MAX_FILES)]
    pub max_files: u64,
}

#[derive(Debug, Serialize)]
struct LiveCaptureOutcome {
    #[serde(flatten)]
    capture: CaptureOutcome,
    vm: String,
    guest_content: String,
    files_exported: u64,
    bytes_exported: u64,
}

#[derive(Debug)]
struct ExportState {
    files: u64,
    bytes: u64,
    max_files: u64,
    max_bytes: u64,
}

pub(super) fn run(args: Args) -> Result<()> {
    ensure_dev_vm(&args.vm)?;
    validate_guest_path(&args.guest_content, "guest content")?;
    validate_guest_path(&args.guest_sbom, "guest SBOM")?;
    validate_guest_path(&args.guest_fetch_log, "guest fetch log")?;
    validate_guest_path(&args.guest_cve, "guest CVE")?;
    if args.max_bytes == 0 || args.max_files == 0 {
        bail!("--max-bytes and --max-files must be greater than zero");
    }

    let staging = tempfile::tempdir().context("creating live dependency capture staging")?;
    let content = staging.path().join("content");
    fs::create_dir_all(&content).context("creating live capture content directory")?;
    let mut state = ExportState {
        files: 0,
        bytes: 0,
        max_files: args.max_files,
        max_bytes: args.max_bytes,
    };
    export_tree(&args.vm, &args.guest_content, &content, &mut state, 0)?;
    let sbom = export_file(
        &args.vm,
        &args.guest_sbom,
        &staging.path().join("sbom.cdx.json"),
        &mut state,
    )?;
    let fetch_log = export_file(
        &args.vm,
        &args.guest_fetch_log,
        &staging.path().join("fetch.log"),
        &mut state,
    )?;
    let cve = export_file(
        &args.vm,
        &args.guest_cve,
        &staging.path().join("cve.json"),
        &mut state,
    )?;

    let cache_root = mvm_build::app_deps::resolve_cache_root(args.cache_root.as_deref());
    let request = CaptureRequest::builder()
        .cache_root(&cache_root)
        .prior_hash(&args.volume_hash)
        .captured_content(&content)
        .sbom(&sbom)
        .fetch_log(&fetch_log)
        .cve(&cve)
        .declaration_path(args.declaration.as_deref())
        .lockfile_path(args.lockfile.as_deref())
        .build()?;
    let capture = capture_volume(request)?;
    let outcome = LiveCaptureOutcome {
        capture,
        vm: args.vm,
        guest_content: args.guest_content,
        files_exported: state.files,
        bytes_exported: state.bytes,
    };
    mvm_core::audit_emit!(
        DepsAudit,
        "operation=capture-live,prior={},new={},files={},bytes={}",
        outcome.capture.prior_volume_hash,
        outcome.capture.volume_hash,
        outcome.files_exported,
        outcome.bytes_exported,
    );
    if args.json {
        println!("{}", serde_json::to_string_pretty(&outcome)?);
    } else {
        eprintln!(
            "captured dependency volume {} -> {} from {} ({} files, {} bytes)",
            outcome.capture.prior_volume_hash,
            outcome.capture.volume_hash,
            outcome.vm,
            outcome.files_exported,
            outcome.bytes_exported,
        );
    }
    Ok(())
}

fn ensure_dev_vm(vm: &str) -> Result<()> {
    let client = LocalBackend::new();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("building runtime for live capture posture check")?;
    let records = runtime
        .block_on(list_local_inventory(&client))
        .map_err(|error| anyhow::anyhow!(error.to_string()))
        .context("listing machines for live capture")?;
    let record = records
        .into_iter()
        .find(|record| record.name == vm)
        .ok_or_else(|| anyhow::anyhow!("no machine named `{vm}` is present"))?;
    require_running_dev_posture(record.status, record.build_mode)
}

fn require_dev_posture(posture: WorkloadPosture) -> Result<()> {
    if !posture.is_dev() {
        bail!("live dependency capture requires a development VM; production posture refused");
    }
    Ok(())
}

fn require_running_dev_posture(status: MachineStatus, posture: WorkloadPosture) -> Result<()> {
    if status != MachineStatus::Running {
        bail!(
            "live dependency capture requires a running development VM; current status is {}",
            status.wire_label()
        );
    }
    require_dev_posture(posture)
}

fn export_tree(
    vm: &str,
    guest_path: &str,
    host_path: &Path,
    state: &mut ExportState,
    depth: usize,
) -> Result<()> {
    ensure_directory_depth(depth, guest_path)?;
    let stat = stat_guest(vm, guest_path)?;
    if stat.kind != FsEntryKind::Dir {
        bail!("guest dependency root `{guest_path}` is not a directory");
    }
    let entries = list_guest(vm, guest_path)?;
    fs::create_dir_all(host_path)
        .with_context(|| format!("creating exported directory {}", host_path.display()))?;
    let mut names = HashSet::with_capacity(entries.len());
    for entry in entries {
        validate_entry_name(&entry.name)?;
        if !names.insert(entry.name.clone()) {
            bail!(
                "guest directory returned duplicate entry `{guest_path}/{}`",
                entry.name
            );
        }
        let guest_child = join_guest_path(guest_path, &entry.name);
        let host_child = host_path.join(&entry.name);
        match entry.kind {
            FsEntryKind::Dir => export_tree(vm, &guest_child, &host_child, state, depth + 1)?,
            FsEntryKind::File => {
                export_file(vm, &guest_child, &host_child, state)?;
            }
            FsEntryKind::Symlink | FsEntryKind::Other => {
                bail!("live dependency capture refuses non-regular guest entry `{guest_child}`")
            }
        }
    }
    Ok(())
}

fn export_file(
    vm: &str,
    guest_path: &str,
    host_path: &Path,
    state: &mut ExportState,
) -> Result<PathBuf> {
    let stat = stat_guest(vm, guest_path)?;
    if stat.kind != FsEntryKind::File {
        bail!("live dependency capture source `{guest_path}` is not a regular file");
    }
    reserve(state, stat.size, guest_path)?;
    let bytes = crate::commands::vm::fs::read_guest_chunks_with_symlink_policy(
        vm, guest_path, 0, stat.size, false,
    )?;
    let actual = u64::try_from(bytes.len()).expect("host buffer length fits u64");
    if actual != stat.size {
        bail!(
            "guest file `{guest_path}` changed during capture: expected {}, read {}",
            stat.size,
            actual
        );
    }
    let after = stat_guest(vm, guest_path)?;
    if after != stat {
        bail!("guest file `{guest_path}` changed during capture");
    }
    if let Some(parent) = host_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("creating export parent {}", parent.display()))?;
    }
    fs::write(host_path, bytes)
        .with_context(|| format!("writing exported file {}", host_path.display()))?;
    Ok(host_path.to_path_buf())
}

fn reserve(state: &mut ExportState, bytes: u64, guest_path: &str) -> Result<()> {
    let next_files = state
        .files
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("captured file count overflow"))?;
    if next_files > state.max_files {
        bail!(
            "live dependency capture exceeded --max-files {} at `{guest_path}`",
            state.max_files
        );
    }
    let next_bytes = state
        .bytes
        .checked_add(bytes)
        .ok_or_else(|| anyhow::anyhow!("captured byte count overflow"))?;
    if next_bytes > state.max_bytes {
        bail!(
            "live dependency capture exceeded --max-bytes {} at `{guest_path}`",
            state.max_bytes
        );
    }
    state.files = next_files;
    state.bytes = next_bytes;
    Ok(())
}

fn ensure_directory_depth(depth: usize, guest_path: &str) -> Result<()> {
    if depth > MAX_DIRECTORY_DEPTH {
        bail!(
            "guest dependency tree exceeded the directory depth limit of {} at `{guest_path}`",
            MAX_DIRECTORY_DEPTH
        );
    }
    Ok(())
}

fn list_guest(vm: &str, path: &str) -> Result<Vec<mvm_agentd::vsock::FsEntry>> {
    let request = GuestRequest::FsList {
        path: path.to_string(),
        follow_symlinks: false,
    };
    crate::commands::shared::emit_vsock_rpc_audit(vm, &request);
    match crate::commands::vm::fs::fs_request(vm, request)? {
        FsResult::List { entries, truncated } if !truncated => Ok(entries),
        FsResult::List {
            truncated: true, ..
        } => {
            bail!("guest directory `{path}` exceeded the agent listing cap")
        }
        FsResult::Error { kind, message } => {
            bail!("guest FS list failed for `{path}` ({kind:?}): {message}")
        }
        other => bail!("unexpected guest FS list result for `{path}`: {other:?}"),
    }
}

fn stat_guest(vm: &str, path: &str) -> Result<mvm_agentd::vsock::FsStat> {
    let request = GuestRequest::FsStat {
        path: path.to_string(),
        follow_symlinks: false,
    };
    crate::commands::shared::emit_vsock_rpc_audit(vm, &request);
    match crate::commands::vm::fs::fs_request(vm, request)? {
        FsResult::Stat(stat) => Ok(stat),
        FsResult::Error { kind, message } => {
            bail!("guest FS stat failed for `{path}` ({kind:?}): {message}")
        }
        other => bail!("unexpected guest FS stat result for `{path}`: {other:?}"),
    }
}

fn validate_guest_path(path: &str, label: &str) -> Result<()> {
    let parsed = Path::new(path);
    if !parsed.is_absolute()
        || parsed
            .components()
            .any(|component| matches!(component, Component::ParentDir))
    {
        bail!("{label} path must be absolute and must not contain `..`: `{path}`");
    }
    Ok(())
}

fn validate_entry_name(name: &str) -> Result<()> {
    let path = Path::new(name);
    if name.is_empty()
        || name.contains('/')
        || name.contains('\\')
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        bail!("guest directory returned an unsafe entry name: `{name}`");
    }
    Ok(())
}

fn join_guest_path(parent: &str, name: &str) -> String {
    format!("{}/{}", parent.trim_end_matches('/'), name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guest_paths_must_be_absolute_without_parent_components() {
        assert!(validate_guest_path("/app/deps", "content").is_ok());
        assert!(validate_guest_path("app/deps", "content").is_err());
        assert!(validate_guest_path("/app/../etc", "content").is_err());
    }

    #[test]
    fn entry_names_cannot_escape_the_export_root() {
        assert!(validate_entry_name("package.py").is_ok());
        assert!(validate_entry_name("../package.py").is_err());
        assert!(validate_entry_name("nested/package.py").is_err());
        assert!(validate_entry_name("/package.py").is_err());
    }

    #[test]
    fn export_limits_are_accounted_before_reading() {
        let mut state = ExportState {
            files: 0,
            bytes: 0,
            max_files: 1,
            max_bytes: 4,
        };
        reserve(&mut state, 4, "/deps/a").unwrap();
        assert_eq!(state.files, 1);
        assert_eq!(state.bytes, 4);
        assert!(reserve(&mut state, 0, "/deps/b").is_err());
        assert!(reserve(&mut state, 1, "/deps/c").is_err());
    }

    #[test]
    fn directory_depth_is_bounded() {
        assert!(ensure_directory_depth(MAX_DIRECTORY_DEPTH, "/deps").is_ok());
        assert!(ensure_directory_depth(MAX_DIRECTORY_DEPTH + 1, "/deps/deep").is_err());
    }

    #[test]
    fn guest_path_join_does_not_duplicate_root_separator() {
        assert_eq!(join_guest_path("/", "deps"), "/deps");
        assert_eq!(join_guest_path("/app/", "deps"), "/app/deps");
    }

    #[test]
    fn production_posture_is_refused() {
        assert!(require_dev_posture(WorkloadPosture::Prod).is_err());
        assert!(require_dev_posture(WorkloadPosture::Dev).is_ok());
    }

    #[test]
    fn non_running_development_vm_is_refused() {
        assert!(require_running_dev_posture(MachineStatus::Stopped, WorkloadPosture::Dev).is_err());
        assert!(require_running_dev_posture(MachineStatus::Paused, WorkloadPosture::Dev).is_err());
        assert!(
            require_running_dev_posture(MachineStatus::Running, WorkloadPosture::Prod).is_err()
        );
        assert!(require_running_dev_posture(MachineStatus::Running, WorkloadPosture::Dev).is_ok());
    }
}
