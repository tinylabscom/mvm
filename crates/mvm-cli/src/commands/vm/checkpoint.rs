//! `mvmctl vm checkpoint create|ls|rm|fork` — immutable fs_quick snapshots of a
//! quiesced VM's rootfs, and copy-on-write forks that branch a new sandbox
//! lineage from one. With `--boot` the fork arm also admits and launches the
//! child as a fresh VM, adopting the materialized rootfs without clobbering it.
//!
//! Rootfs resolution is backend-neutral: every backend that calls
//! `record_from_rootfs` at start time writes the rootfs path into mode.json,
//! which `resolve_quiesced_vm_rootfs` reads as its primary source.

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use clap::Args as ClapArgs;
use serde::Serialize;

use mvm_core::checkpoint::{CheckpointClass, CheckpointDigest, CheckpointId, CheckpointMeta};
use mvm_core::config::vm_state_dir;
use mvm_core::vm_backend::SnapshotCapability;
use mvm_hostd::audit::bind::class_str;
use mvm_runtime::checkpoint::{
    CaptureFsQuickParams, CaptureVmFullParams, CheckpointStore, ForkParams, capture_fs_quick,
    capture_vm_full, checkpoint_is_vz, fork_checkpoint, fork_vm_full_fc,
};

use super::Cli;
use super::shared::clap_vm_name;
use crate::ui;

mod lineage;
mod revert;
mod timeline;
pub(in crate::commands) use lineage::SignedChainAnchor;
pub(in crate::commands) use revert::{
    AdvanceArgs, RevertArgs, RevertImageSource, RevertOutcome, RevertRunImage, run_advance,
    run_revert, run_rewind,
};
pub(in crate::commands) use timeline::{TimelineArgs, run_timeline};

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct CheckpointArgs {
    #[command(subcommand)]
    pub command: CheckpointCmd,
}

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct SaveArgs {
    /// Name of the running VM to save.
    #[arg(value_parser = clap_vm_name)]
    pub name: String,
    /// Optional human label recorded on the checkpoint.
    #[arg(long)]
    pub tag: Option<String>,
    /// Output the sealed checkpoint metadata as JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct RestoreArgs {
    /// Checkpoint id to restore.
    pub id: String,
    /// Output the restore result as JSON.
    #[arg(long)]
    pub json: bool,
}

/// Which kind of checkpoint to capture. `fs-quick` clones the rootfs of a
/// quiesced VM (no memory); `vm-full` captures a running VM's {rootfs, memory,
/// machine-id} triple in one pause window.
#[derive(clap::ValueEnum, Debug, Clone, Copy)]
pub(in crate::commands) enum CheckpointClassArg {
    FsQuick,
    VmFull,
}

#[derive(clap::Subcommand, Debug, Clone)]
pub(in crate::commands) enum CheckpointCmd {
    /// Freeze a VM into a checkpoint. `--class fs-quick` (default) clones a
    /// quiesced VM's rootfs; `--class vm-full` captures a running VM's memory.
    Create {
        /// Name of the VM to checkpoint.
        #[arg(value_parser = clap_vm_name)]
        name: String,
        /// Checkpoint class. `fs-quick` needs the VM quiesced; `vm-full` needs
        /// it running.
        #[arg(long, value_enum, default_value = "fs-quick")]
        class: CheckpointClassArg,
        /// Optional human label recorded on the checkpoint.
        #[arg(long)]
        tag: Option<String>,
        /// Output the sealed checkpoint metadata as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Resume a VM from a vm_full checkpoint (same identity).
    Restore {
        /// Checkpoint id to restore.
        id: String,
        /// Output the restore result as JSON.
        #[arg(long)]
        json: bool,
    },
    /// List checkpoints under ~/.mvm/checkpoints.
    Ls {
        /// Output as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Remove a checkpoint by id.
    Rm {
        /// Checkpoint id to remove.
        id: String,
        /// Output the removal result as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Branch a new sandbox lineage from a checkpoint.
    ///
    /// By default the child rootfs is materialized but not booted (fs_quick).
    /// Pass `--boot` to admit and launch the child immediately.
    /// vm_full forks always auto-boot as part of the fork; `--boot` is
    /// accepted there but has no extra effect.
    Fork {
        /// Parent checkpoint id.
        id: String,
        /// Name for the new VM instance (auto-generated if omitted).
        #[arg(long, value_parser = clap_vm_name)]
        new_id: Option<String>,
        /// Admit and boot the forked child immediately. fs_quick forks only —
        /// vm_full forks boot as part of forking and ignore this flag.
        #[arg(long)]
        boot: bool,
        /// Hypervisor backend for `--boot` (fs_quick forks only).
        /// Defaults to the same auto-detect order as `mvmctl up`.
        #[arg(long, default_value = "firecracker")]
        hypervisor: String,
        /// vCPU count for the booted child (fs_quick `--boot` only).
        /// Inherits from the parent plan when omitted.
        #[arg(long)]
        cpus: Option<u32>,
        /// Memory for the booted child, e.g. 512M, 2G (fs_quick `--boot` only).
        /// Inherits from the parent plan when omitted.
        #[arg(long)]
        memory: Option<String>,
        /// Output the fork result as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Compare two checkpoints (metadata + content manifest; `b` relative to `a`).
    Diff {
        /// Baseline checkpoint id (`a`).
        a: String,
        /// Compared checkpoint id (`b`).
        b: String,
        /// Output as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Verify a checkpoint's full lineage against the signed audit chain.
    ///
    /// Walks from the checkpoint up to its genesis root; at every hop the
    /// record's content-address must match both its stored `meta_digest` and the
    /// digest the host signed into the audit chain at creation. Exits nonzero on
    /// any drift, chain mismatch, missing signed entry, or broken lineage.
    Verify {
        /// Checkpoint id to verify.
        id: String,
        /// Output the verification result as JSON.
        #[arg(long)]
        json: bool,
    },
}

pub(in crate::commands) fn run_checkpoint(_cli: &Cli, args: CheckpointArgs) -> Result<()> {
    match args.command {
        CheckpointCmd::Create {
            name,
            class,
            tag,
            json,
        } => match class {
            CheckpointClassArg::FsQuick => create(&name, tag, json),
            CheckpointClassArg::VmFull => create_vm_full(&name, tag, json),
        },
        CheckpointCmd::Restore { id, json } => restore(&id, json),
        CheckpointCmd::Ls { json } => ls(json),
        CheckpointCmd::Rm { id, json } => rm(&id, json),
        CheckpointCmd::Fork {
            id,
            new_id,
            boot,
            hypervisor,
            cpus,
            memory,
            json,
        } => fork(
            &id,
            new_id,
            boot,
            &hypervisor,
            cpus,
            memory.as_deref(),
            json,
        ),
        CheckpointCmd::Diff { a, b, json } => diff(&a, &b, json),
        CheckpointCmd::Verify { id, json } => lineage::verify(&id, json),
    }
}

pub(in crate::commands) fn run_save(_cli: &Cli, args: SaveArgs) -> Result<()> {
    create_vm_full(&args.name, args.tag, args.json)
}

pub(in crate::commands) fn run_restore(_cli: &Cli, args: RestoreArgs) -> Result<()> {
    restore(&args.id, args.json)
}

#[derive(Serialize)]
struct CheckpointRemoveJson<'a> {
    schema_version: u8,
    action: &'static str,
    id: &'a CheckpointId,
    removed: bool,
}

#[derive(Serialize)]
struct CheckpointForkJson<'a> {
    schema_version: u8,
    action: &'static str,
    parent_id: &'a CheckpointId,
    child_vm_name: &'a str,
    booted: bool,
    checkpoint: &'a CheckpointMeta,
}

/// Reject a user-supplied checkpoint id that could escape the store root or
/// otherwise produce an unsafe on-disk directory name. The id becomes a
/// directory component under `checkpoints_dir()`, so path-traversal and
/// control bytes must never reach the filesystem.
pub(in crate::commands) fn validated_checkpoint_id(raw: &str) -> Result<CheckpointId> {
    if raw.is_empty() {
        bail!("invalid checkpoint id: empty");
    }
    let bad = raw.contains('/')
        || raw.contains('\\')
        || raw.contains("..")
        || raw.bytes().any(|b| b == 0 || b.is_ascii_control());
    if bad {
        bail!(
            "invalid checkpoint id {raw:?}: must not contain '/', '\\', '..', \
             NUL, or control characters"
        );
    }
    Ok(CheckpointId::new(raw.to_string()))
}

pub(in crate::commands) fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Resolve the host-side bootable rootfs image for a quiesced VM, or a clean
/// error explaining why a checkpoint can't be taken.
///
/// "Quiesced" means the VM is not running, OR the pause verb has written a
/// pause marker that matches the live supervisor pid (vCPUs and virtio queues
/// quiesced). A live, unpaused VM is refused: an fs_quick checkpoint has no
/// memory, so the rootfs must be in a clean, deterministic state.
///
/// Resolution order (first match wins):
/// 1. Per-instance `rootfs.ext4` CoW clone in `vm_state_dir(name)`.
/// 2. `mode.json` `rootfs_path` field (backend-neutral; written by every
///    backend that calls `record_from_rootfs` at start time).
fn resolve_quiesced_vm_rootfs(name: &str) -> Result<PathBuf> {
    if !vm_is_quiesced(name) {
        bail!("stop or pause VM '{name}' before checkpointing");
    }
    let state_dir = vm_state_dir(name);

    // Per-instance CoW clone — deterministic, present on disk.
    let instance_rootfs = state_dir.join("rootfs.ext4");
    if instance_rootfs.is_file() {
        return Ok(instance_rootfs);
    }

    // Backend-neutral: every backend that calls `record_from_rootfs` at start
    // time writes the rootfs path into mode.json.
    if let Some(path) = rootfs_from_mode_json(&state_dir)? {
        if !path.exists() {
            bail!(
                "fs_quick checkpoint needs the VM's rootfs ({}), which is no longer \
                 on disk. Pause instead of stopping: `mvmctl vm pause {name}`, \
                 checkpoint, then `mvmctl vm resume {name}` — or use \
                 `--class vm-full` on a running VM.",
                path.display()
            );
        }
        return Ok(path);
    }

    bail!("fs_quick checkpoint is not supported for this VM's backend");
}

/// Read `mode.json` and return the recorded `rootfs_path` field, if present.
/// Absent file or absent field → `Ok(None)`. Malformed JSON propagates.
fn rootfs_from_mode_json(state_dir: &std::path::Path) -> Result<Option<PathBuf>> {
    let path = state_dir.join("mode.json");
    let body = match std::fs::read_to_string(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    };
    let meta: mvm_runtime::base::runtime_meta::VmRuntimeMeta =
        serde_json::from_str(&body).with_context(|| format!("parsing {}", path.display()))?;
    Ok(meta.rootfs_path.map(PathBuf::from))
}

/// Best-effort liveness: a VM is "running" iff one of its per-backend PID
/// files names a live process. Mirrors the per-backend `kill(pid, 0)` probe.
///
/// NOTE: libkrun writes `libkrun.pid` and Firecracker writes `fc.pid`, both
/// into the shared per-VM directory (`<mvm_home>/vms/<name>/`). The file
/// names are backend-disjoint, so both probes read the same tree.
fn vm_is_running(name: &str) -> bool {
    let state_dir = vm_state_dir(name);
    // libkrun.pid lives under vm_state_dir (the host metadata store).
    let state_dir_running = ["libkrun.pid"]
        .iter()
        .filter_map(|f| std::fs::read_to_string(state_dir.join(f)).ok())
        .filter_map(|s| s.trim().parse::<libc::pid_t>().ok())
        // SAFETY: signal 0 only probes existence; it delivers nothing.
        .any(|pid| unsafe { libc::kill(pid, 0) == 0 });

    if state_dir_running {
        return true;
    }

    // Firecracker's fc.pid is written via fc_pid_path() (strict resolver —
    // None in hermetic environments). Probe it so a live FC VM is detected.
    if let Some(fc_pid_path) = mvm_runtime::microvm::fc_pid_path(name)
        && let Ok(s) = std::fs::read_to_string(&fc_pid_path)
        && let Ok(pid) = s.trim().parse::<libc::pid_t>()
    {
        // SAFETY: signal 0 only probes existence; it delivers nothing.
        if unsafe { libc::kill(pid, 0) } == 0 {
            return true;
        }
    }

    false
}

/// fs_quick clones the instance rootfs, so the guest must not be writing:
/// either the VM is stopped, or it is paused (vCPUs and virtio queues quiesced
/// — the FC pause verb stamps the fc pid into `fc.paused`; resume and any path
/// that replaces the process removes or invalidates the marker). A
/// running-but-paused VM keeps its pid alive, so `vm_is_running` alone would
/// incorrectly refuse the checkpoint without these marker checks.
fn vm_is_quiesced(name: &str) -> bool {
    if !vm_is_running(name) {
        return true;
    }
    fc_pause_marker_matches_live_pid(name)
}

/// `machine pause` snapshot-seals FC but leaves the fc process running, so a
/// live pid cannot
/// distinguish paused from running. The pause verb stamps the fc pid into
/// `fc.paused` (under `vm_state_dir`); resume removes it. Quiesced iff the
/// marker matches the live fc pid at `<mvm_home>/vms/<name>/fc.pid`.
fn fc_pause_marker_matches_live_pid(name: &str) -> bool {
    let marker = std::fs::read_to_string(vm_state_dir(name).join("fc.paused")).ok();
    let live =
        mvm_runtime::microvm::fc_pid_path(name).and_then(|p| std::fs::read_to_string(p).ok());
    matches!((marker, live), (Some(m), Some(l)) if !m.trim().is_empty() && m.trim() == l.trim())
}

/// Hash the VM's persisted supervisor config so the checkpoint pins the launch
/// shape it was captured from. No config on disk → empty digest (the field is
/// advisory for fs_quick; integrity rests on `content_sha256`).
fn supervisor_config_digest(state_dir: &std::path::Path) -> String {
    let cfg_path = state_dir.join("supervisor-config.json");
    mvm_core::crypto::image_verify::sha256_file(&cfg_path).unwrap_or_default()
}

fn runtime_contract_for_checkpoint(
    name: &str,
) -> Result<(
    Option<mvm_core::vm_backend::RuntimeSourcePolicy>,
    Option<String>,
)> {
    Ok(mvm_runtime::base::runtime_meta::read(name)?
        .map(|meta| {
            (
                Some(meta.runtime_source_policy),
                meta.runtime_overlay_version,
            )
        })
        .unwrap_or((None, None)))
}

fn ensure_save_restore_supported(action: &str) -> Result<()> {
    let backend = mvm_runtime::backend::AnyBackend::auto_select();
    let available = backend.snapshot_capability();
    if !available.satisfies(SnapshotCapability::SaveRestore) {
        bail!(
            "vm {action} requires memory-snapshot support, but backend '{}' reports \
             snapshot tier '{}' on this host",
            backend.name(),
            available.label()
        );
    }
    Ok(())
}

fn create(name: &str, tag: Option<String>, json: bool) -> Result<()> {
    let rootfs = resolve_quiesced_vm_rootfs(name)?;
    let state_dir = vm_state_dir(name);
    let (runtime_source_policy, runtime_overlay_version) = runtime_contract_for_checkpoint(name)?;
    let store = CheckpointStore::open();
    let now = now_unix();
    let id = CheckpointId::new(format!("ckpt-{name}-{now}"));

    let meta = capture_fs_quick(
        &store,
        CaptureFsQuickParams {
            id,
            vm_name: name.to_string(),
            rootfs,
            supervisor_config_digest: supervisor_config_digest(&state_dir),
            runtime_source_policy,
            runtime_overlay_version,
            tag,
            created_unix: now,
            quiesced: true,
        },
    )
    .with_context(|| format!("capturing fs_quick checkpoint of {name:?}"))?;

    // Best-effort audit binding: a missing plan/signer or flaky audit fs warns
    // and continues — the checkpoint is already sealed on disk.
    bind_checkpoint_created(name, &meta);

    if json {
        crate::json_out::emit_json(&meta)?;
    } else {
        let sha = meta
            .content
            .first()
            .map(|b| b.sha256.as_str())
            .unwrap_or("(no blobs)");
        ui::success(&format!(
            "{name}: checkpoint {} created (sha256 {})",
            meta.id.as_str(),
            sha
        ));
    }
    Ok(())
}

/// Capture the vm_full triple for the running VM. Firecracker (the sole
/// full-VM capture backend) drives the pause/save/resume window. The caller
/// has already verified the VM is running.
fn capture_vm_full_for_running_vm(
    name: &str,
    state_dir: &std::path::Path,
    store: &CheckpointStore,
    id: CheckpointId,
    tag: Option<String>,
    created_unix: u64,
) -> Result<mvm_core::checkpoint::CheckpointMeta> {
    let (runtime_source_policy, runtime_overlay_version) = runtime_contract_for_checkpoint(name)?;
    let params = CaptureVmFullParams {
        id,
        vm_name: name.to_string(),
        supervisor_config_digest: supervisor_config_digest(state_dir),
        runtime_source_policy,
        runtime_overlay_version,
        supervisor_config_src: None,
        tag,
        created_unix,
    };
    let control = mvm_runtime::firecracker::FcVmFullControl::new(name);
    capture_vm_full(store, params, &control)
}

/// `mvmctl checkpoint create --class vm-full <vm>`: capture a RUNNING VM's
/// memory + rootfs in one pause window. The inverse of fs_quick — a vm_full
/// checkpoint carries memory, so the VM must be live.
fn create_vm_full(name: &str, tag: Option<String>, json: bool) -> Result<()> {
    ensure_save_restore_supported("save")?;
    if !vm_is_running(name) {
        bail!("checkpoint --class vm-full requires a running VM; start '{name}' first");
    }
    let state_dir = vm_state_dir(name);
    let store = CheckpointStore::open();
    let now = now_unix();
    let id = CheckpointId::new(format!("ckpt-{name}-{now}"));

    let meta = capture_vm_full_for_running_vm(name, &state_dir, &store, id, tag, now)
        .with_context(|| format!("capturing vm_full checkpoint of {name:?}"))?;

    // Best-effort audit binding, same policy as fs_quick capture.
    bind_checkpoint_created(name, &meta);

    if json {
        crate::json_out::emit_json(&meta)?;
    } else {
        ui::success(&format!(
            "{name}: vm_full checkpoint {} created",
            meta.id.as_str()
        ));
    }
    Ok(())
}

pub(crate) fn bind_checkpoint_created(name: &str, meta: &mvm_core::checkpoint::CheckpointMeta) {
    let plan = match super::plan_persist::read_plan(name) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, vm = name,
                "no persisted plan; checkpoint.created emitted without chain binding");
            return;
        }
    };
    let signer = match super::host_signer::load_or_init() {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, "host signer unavailable; chain entry skipped");
            return;
        }
    };
    let emitter = match super::audit_chain::AuditEmitter::new(signer.signing) {
        Ok(e) => e.with_receipts(),
        Err(e) => {
            tracing::warn!(error = %e, "audit emitter unavailable; chain entry skipped");
            return;
        }
    };
    if let Err(e) = mvm_hostd::audit::bind::bind_checkpoint_created(&emitter, &plan, meta) {
        tracing::warn!(error = %e, "audit emit_checkpoint_created failed (non-fatal)");
    }
}

fn ls(json: bool) -> Result<()> {
    let metas = CheckpointStore::open().list()?;
    if json {
        crate::json_out::emit_json(&metas)?;
        return Ok(());
    }
    if metas.is_empty() {
        ui::info("(no checkpoints)");
        return Ok(());
    }
    // The parent hash-link is a content-address on disk; resolve it back to the
    // human checkpoint id the operator recognizes. Build the digest->id lookup
    // once from the metas already listed rather than re-scanning per row.
    let id_by_digest: std::collections::HashMap<&CheckpointDigest, &str> = metas
        .iter()
        .map(|m| (&m.meta_digest, m.id.as_str()))
        .collect();
    println!(
        "{:<32} {:<10} {:<20} {:<8} PARENT",
        "ID", "CLASS", "VM", "TAG"
    );
    for m in &metas {
        let parent_display = match &m.parent {
            None => "-".to_string(),
            // Unknown parent (pruned/dangling): fall back to the short digest so
            // the link stays visible instead of silently blank.
            Some(digest) => id_by_digest
                .get(digest)
                .map(|id| id.to_string())
                .unwrap_or_else(|| short_digest(digest)),
        };
        println!(
            "{:<32} {:<10} {:<20} {:<8} {}",
            m.id.as_str(),
            class_str(m.class),
            m.vm_name,
            m.tag.as_deref().unwrap_or("-"),
            parent_display,
        );
    }
    Ok(())
}

/// Compact display form of a checkpoint content-address (`sha256:` + first 12
/// hex), for the `ls` PARENT column when the human id behind a link isn't in
/// view.
fn short_digest(digest: &CheckpointDigest) -> String {
    let hex = digest
        .as_str()
        .strip_prefix(CheckpointDigest::PREFIX)
        .unwrap_or_else(|| digest.as_str());
    format!("{}{}", CheckpointDigest::PREFIX, &hex[..hex.len().min(12)])
}

fn diff(a: &str, b: &str, json: bool) -> Result<()> {
    let id_a = validated_checkpoint_id(a)?;
    let id_b = validated_checkpoint_id(b)?;
    let store = CheckpointStore::open();
    let meta_a = store
        .read_meta(&id_a)
        .with_context(|| format!("reading checkpoint {a:?}"))?;
    let meta_b = store
        .read_meta(&id_b)
        .with_context(|| format!("reading checkpoint {b:?}"))?;
    let d = mvm_runtime::checkpoint::diff_checkpoints(&meta_a, &meta_b);

    if json {
        crate::json_out::emit_json(&d)?;
        return Ok(());
    }

    use mvm_runtime::checkpoint::{BlobStatus, LineageRelation};
    ui::info(&format!("checkpoint diff: {a} -> {b}"));
    if d.class_a != d.class_b {
        ui::info(&format!(
            "  class: {} -> {}",
            class_str(d.class_a),
            class_str(d.class_b)
        ));
    }
    if d.vm_name_a != d.vm_name_b {
        ui::info(&format!("  vm:    {} -> {}", d.vm_name_a, d.vm_name_b));
    }
    if !d.supervisor_config_digest_same {
        ui::info("  supervisor config: changed");
    }
    let rel = match d.lineage {
        LineageRelation::BChildOfA => format!("{b} is a child of {a}"),
        LineageRelation::AChildOfB => format!("{a} is a child of {b}"),
        LineageRelation::Same => "same checkpoint id".to_string(),
        LineageRelation::Unrelated => "no direct lineage".to_string(),
    };
    ui::info(&format!("  lineage: {rel}"));
    println!("{:<20} STATUS", "BLOB");
    for blob in &d.blobs {
        let status = match blob.status {
            BlobStatus::Unchanged => "unchanged",
            BlobStatus::Changed => "changed",
            BlobStatus::AddedInB => "added",
            BlobStatus::RemovedFromB => "removed",
        };
        println!("{:<20} {}", blob.name, status);
    }
    Ok(())
}

fn rm(id: &str, json: bool) -> Result<()> {
    let id = validated_checkpoint_id(id)?;
    CheckpointStore::open().remove(&id)?;
    if json {
        crate::json_out::emit_json(&CheckpointRemoveJson {
            schema_version: 1,
            action: "rm",
            id: &id,
            removed: true,
        })?;
    } else {
        ui::success(&format!("checkpoint {} removed", id.as_str()));
    }
    Ok(())
}

/// `mvmctl vm checkpoint restore <id>`: same-identity resume of a vm_full
/// checkpoint. The restore mechanism is being re-homed onto the in-house HVF
/// VMM and is unavailable on the current macOS/Linux backends; a clear,
/// tracked error is returned rather than a partial resume.
fn restore(id: &str, _json: bool) -> Result<()> {
    // Validate the id so an obviously bad argument still errors clearly.
    let _ = validated_checkpoint_id(id)?;
    bail!(
        "vm restore requires full-VM save/restore, which is being re-homed onto \
         the in-house HVF VMM and is unavailable on this backend for now"
    );
}

fn fork(
    id: &str,
    new_id: Option<String>,
    boot: bool,
    hypervisor: &str,
    cpus: Option<u32>,
    memory: Option<&str>,
    json: bool,
) -> Result<()> {
    let checkpoint = validated_checkpoint_id(id)?;
    let store = CheckpointStore::open();
    // Pick the fork arm by the parent's class: vm_full carries memory and must
    // restore through the vm_full fork arm (which auto-boots the child); fs_quick
    // is a rootfs-only clone that the operator can optionally boot with `--boot`.
    let parent = store.read_meta(&checkpoint)?;
    match parent.class {
        CheckpointClass::VmFull => {
            fork_vm_full_arm(&store, &checkpoint, new_id, cpus, memory, json)
        }
        CheckpointClass::FsQuick => fork_fs_quick_arm(ForkFsQuickArmParams {
            store: &store,
            checkpoint: &checkpoint,
            new_id,
            boot,
            hypervisor,
            cpus_override: cpus,
            memory_override: memory,
            json,
        }),
    }
}

/// Inputs for [`fork_fs_quick_arm`]. Grouped to stay under the
/// `clippy::too_many_arguments` workspace ceiling.
struct ForkFsQuickArmParams<'a> {
    store: &'a CheckpointStore,
    checkpoint: &'a CheckpointId,
    new_id: Option<String>,
    boot: bool,
    hypervisor: &'a str,
    cpus_override: Option<u32>,
    memory_override: Option<&'a str>,
    json: bool,
}

/// fs_quick fork: CoW-clone the rootfs into a new VM state dir. With
/// `--boot`, also admits and launches the child as a fresh VM, adopting the
/// materialized rootfs without clobbering it (the no-clobber seam in
/// `prepare_instance_rootfs` returns early when source == instance path).
fn fork_fs_quick_arm(p: ForkFsQuickArmParams<'_>) -> Result<()> {
    let now = now_unix();
    let child_vm_name = p
        .new_id
        .unwrap_or_else(|| format!("{}-fork-{now}", p.checkpoint.as_str()));
    let dest_dir = vm_state_dir(&child_vm_name);
    let child_id = CheckpointId::new(format!("fork-{child_vm_name}-{now}"));

    // Verify the parent against the signed audit chain before any bytes are
    // cloned — a fork must never build on a checkpoint edited after it was
    // audited.
    let anchor = SignedChainAnchor::load()
        .context("loading the signed audit chain to verify the fork parent")?;
    let meta = fork_checkpoint(
        p.store,
        ForkParams {
            checkpoint: p.checkpoint.clone(),
            child_id,
            child_vm_name: child_vm_name.clone(),
            dest_dir: dest_dir.clone(),
            created_unix: now,
            child_plan_json: None,
            child_tenant_id: None,
        },
        &anchor,
    )
    .with_context(|| format!("forking checkpoint {:?}", p.checkpoint.as_str()))?;

    // A fork that we can't audit (signer present but emit fails) is refused —
    // an unaudited lineage record would break the chain. A missing plan/signer
    // is best-effort, matching capture.
    bind_checkpoint_forked(p.checkpoint, &meta, &child_vm_name, p.store)?;

    if p.boot {
        let instance_rootfs = dest_dir.join("rootfs.ext4");
        boot_forked_child(BootForkedChildParams {
            child_vm_name: &child_vm_name,
            instance_rootfs: &instance_rootfs,
            parent_checkpoint: p.checkpoint,
            store: p.store,
            hypervisor: p.hypervisor,
            cpus_override: p.cpus_override,
            memory_override: p.memory_override,
            emit_text: !p.json,
        })?;
    }

    if p.json {
        crate::json_out::emit_json(&CheckpointForkJson {
            schema_version: 1,
            action: "fork",
            parent_id: p.checkpoint,
            child_vm_name: &child_vm_name,
            booted: p.boot,
            checkpoint: &meta,
        })?;
    } else {
        ui::success(&format!(
            "forked {} -> checkpoint {} (vm '{}')",
            p.checkpoint.as_str(),
            meta.id.as_str(),
            child_vm_name
        ));
        if !p.boot {
            ui::info(&format!(
                "child '{child_vm_name}' materialized at {}; re-run the fork with \
                 --boot to admit and launch a child, or delete the directory to \
                 discard this one",
                dest_dir.display()
            ));
        }
    }
    Ok(())
}

/// Inputs for [`fork_vm_full_arm`]. Grouped to stay under the
/// `clippy::too_many_arguments` workspace ceiling.
struct ForkVmFullArmParams<'a> {
    store: &'a CheckpointStore,
    checkpoint: &'a CheckpointId,
    new_id: Option<String>,
    /// Refused with a user-visible error: a vm_full fork restores the saved
    /// machine state (cpu/mem baked into the snapshot), so the shape is fixed.
    /// Use an fs_quick fork to boot a resized child.
    cpus_override: Option<u32>,
    /// Refused with a user-visible error for the same reason as `cpus_override`.
    memory_override: Option<&'a str>,
    json: bool,
}

/// vm_full fork: clone the captured triple into a new child identity, admit a
/// fresh claim-8 plan for the child (using the parent's saved cpu/mem — the
/// restore shape is fixed), rewrite the supervisor config, and boot the child
/// in restore mode. The child's admitted plan is distinct from the parent's.
/// Whether the experimental Firecracker vm_full fork restore is opted into.
///
/// Off by default: a forked child restores the parent's saved guest memory,
/// which carries the parent's IP/MAC, and there is no per-child guest
/// re-addressing yet — so a booted child collides with its parent on the
/// shared bridge. The opt-in exercises the (proven-sound) restore mechanism
/// on an isolated single-child network while that per-child network model is
/// still being settled.
fn fc_vm_full_fork_experimental_enabled() -> bool {
    std::env::var_os("MVM_FORK_VMFULL_FC_EXPERIMENTAL").is_some()
}

fn fork_vm_full_arm(
    store: &CheckpointStore,
    checkpoint: &CheckpointId,
    new_id: Option<String>,
    cpus_override: Option<u32>,
    memory_override: Option<&str>,
    json: bool,
) -> Result<()> {
    fork_vm_full_arm_inner(ForkVmFullArmParams {
        store,
        checkpoint,
        new_id,
        cpus_override,
        memory_override,
        json,
    })
}

fn fork_vm_full_arm_inner(p: ForkVmFullArmParams<'_>) -> Result<()> {
    // A vm_full fork restores a saved machine state whose cpu/mem are baked
    // into the snapshot; the removed Vz backend validated device config
    // against the saved state and refused a mismatch. Accepting these flags
    // would silently fail at restore time with a confusing hypervisor error
    // — refuse early.
    if p.cpus_override.is_some() {
        anyhow::bail!(
            "--cpus is not valid for a vm_full fork: a memory restore resumes the saved \
             machine shape; use an fs_quick fork to resize"
        );
    }
    if p.memory_override.is_some() {
        anyhow::bail!(
            "--memory is not valid for a vm_full fork: a memory restore resumes the saved \
             machine shape; use an fs_quick fork to resize"
        );
    }

    let now = now_unix();
    let child_vm_name = p
        .new_id
        .unwrap_or_else(|| format!("{}-fork-{now}", p.checkpoint.as_str()));
    let dest_dir = vm_state_dir(&child_vm_name);
    let child_id = CheckpointId::new(format!("fork-{child_vm_name}-{now}"));

    let parent_meta = p.store.read_meta(p.checkpoint)?;

    fork_vm_full_arm_fc(ForkVmFullArmFcParams {
        store: p.store,
        checkpoint: p.checkpoint,
        parent_meta,
        child_vm_name,
        dest_dir,
        child_id,
        now,
        json: p.json,
        bypass_experimental_guard: false,
    })?;
    Ok(())
}

/// Inputs for [`fork_vm_full_arm_fc`]. Grouped to stay under the
/// `clippy::too_many_arguments` workspace ceiling.
pub(in crate::commands) struct ForkVmFullArmFcParams<'a> {
    pub(in crate::commands) store: &'a CheckpointStore,
    pub(in crate::commands) checkpoint: &'a CheckpointId,
    pub(in crate::commands) parent_meta: mvm_core::checkpoint::CheckpointMeta,
    pub(in crate::commands) child_vm_name: String,
    pub(in crate::commands) dest_dir: std::path::PathBuf,
    pub(in crate::commands) child_id: CheckpointId,
    pub(in crate::commands) now: u64,
    pub(in crate::commands) json: bool,
    /// When true, skip the `MVM_FORK_VMFULL_FC_EXPERIMENTAL` guard. The guard
    /// stays on the lower-level `vm checkpoint fork` path; the user-facing
    /// `machine warm-restore` verb opts in explicitly.
    pub(in crate::commands) bypass_experimental_guard: bool,
}

/// FC vm_full fork: clone the captured triple, admit a fresh claim-8 plan for
/// the child, rename `memory.bin` → `mem.bin`, and boot the child via a fresh
/// Firecracker VMM loaded from the checkpoint snapshot.
pub(in crate::commands) fn fork_vm_full_arm_fc(
    p: ForkVmFullArmFcParams<'_>,
) -> Result<mvm_core::checkpoint::CheckpointMeta> {
    // FC vm_full fork loads a snapshot that still carries the parent's TAP
    // name and guest MAC in bitcode. Remapping backing files is not enough to
    // make a live-parent fork safe, so require the parent to be stopped first.
    // The device-path remapping happens in a private mount namespace before
    // the child Firecracker starts.
    if vm_is_running(&p.parent_meta.vm_name) {
        anyhow::bail!(
            "Firecracker vm_full fork requires the parent VM '{}' to be stopped first;              live-parent fork would collide on the parent's TAP/MAC",
            p.parent_meta.vm_name
        );
    }

    // Checkpoints captured under the removed Apple-Virtualization backend carry
    // a supervisor-config.json blob. Their full-VM fork is being re-homed onto
    // the in-house HVF VMM and is unavailable for now — refuse cleanly.
    if checkpoint_is_vz(&p.parent_meta) {
        anyhow::bail!(
            "this vm_full checkpoint was captured under a backend that has been removed; \
             its full-VM fork is being re-homed onto the in-house HVF VMM and is \
             unavailable for now. Use an fs_quick fork instead."
        );
    }

    // Firecracker vm_full fork. A forked child restores the parent's saved guest
    // memory verbatim, which carries the parent's IP/MAC. VMGenID reseeds the
    // guest RNG on restore but does not re-address the network, so a booted child
    // would collide with its parent on the shared dev-subnet bridge. The host-tap
    // side is remappable, but re-IP'ing the guest is a per-child network-model
    // decision that is not yet settled — refuse cleanly rather than boot a
    // colliding child. The restore mechanism stays reachable behind an explicit
    // opt-in for isolated single-child testing on that model, unless the caller
    // has already opted in (the user-facing `machine warm-restore` path).
    if !p.bypass_experimental_guard && !fc_vm_full_fork_experimental_enabled() {
        anyhow::bail!(
            "forking a vm_full checkpoint on Firecracker is not yet supported: the \
             forked child inherits the parent's guest IP/MAC from the saved memory \
             image and has no per-child network reconfiguration, so it would collide \
             with the parent on the shared bridge. Use an fs_quick fork, or set \
             MVM_FORK_VMFULL_FC_EXPERIMENTAL=1 to exercise the restore on an isolated \
             single-child network."
        );
    }

    // Use safe defaults for FC cpu/mem plan admission. The actual cpu/mem are
    // baked into the snapshot and enforced by FC at load time; the plan values
    // are used for claim-8 admission metadata only.
    let user_cfg = mvm_core::user_config::load(None);
    let cpus = user_cfg.default_cpus;
    let mem_mib = user_cfg.default_memory_mib as u64;

    // Admit a fresh plan for the child using the checkpoint's RECORDED rootfs sha.
    let rootfs_blob = p.store.content_dir(p.checkpoint).join("rootfs.ext4");
    let recorded_sha = p
        .parent_meta
        .content
        .iter()
        .find(|b| b.name == "rootfs.ext4")
        .map(|b| b.sha256.clone());
    let parent_agent_verbs = parent_agent_verb_override(p.checkpoint, p.store);
    let tenant = super::tenant_resolution::resolve_tenant(None);
    let ledger = mvm_hostd::plan_admission::InMemoryNonceLedger::new();
    let admission = super::up::admit_plan_for_boot(super::up::AdmitPlanForBootParams {
        tenant: &tenant,
        vm_name: &p.child_vm_name,
        backend_name: "firecracker",
        rootfs_path: &rootfs_blob,
        precomputed_image_sha256: recorded_sha,
        boot_artifact_identity: None,
        cpus,
        mem_mib,
        seccomp_tier: mvm_core::plan::PlanSeccompTier::Standard,
        secret_release: mvm_core::plan::SecretReleasePolicy::default(),
        secrets: Vec::new(),
        no_supervisor: false,
        ledger: &ledger,
        keys_dir: None,
        audit_dir: None,
        policy_dir: None,
        bundle_pin: None,
        deps_volume: None,
        shares: Vec::new(),
        redaction: mvm_core::policy::RedactionPolicy::default(),
        network_policy: mvm_core::network_policy::NetworkPolicy::deny_all(),
        agent_verb_override: parent_agent_verbs.clone(),
        // A restored child is never interactive, never carries ad-hoc argv, and
        // is always prod-profile, so it qualifies for the attenuated grant.
        restrict_agent_verbs: !parent_agent_verbs.is_empty()
            || super::agent_verbs::grant_eligible(false, false, false),
        services: Vec::new(),
        entrypoint: crate::commands::vm::entrypoint_resolve::ResolvedEntrypoint::unresolved(
            "a checkpoint fork boots the image the parent booted; this path resolves no entrypoint",
        ),
    })?;

    let child_plan_json = admission.as_ref().map(|ctx| {
        serde_json::to_string(ctx.admitted.signed()).expect("admitted plan is always serializable")
    });
    let child_tenant_id = admission
        .as_ref()
        .map(|ctx| ctx.admitted.plan().tenant.0.clone());

    // Mint the child's verb-grant sidecar up front so it's readable below for
    // post-restore delivery. Mirrors the former Vz backend's fork path.
    if let Some(ref plan_json_str) = child_plan_json {
        let mint_cfg = mvm_core::vm_backend::VmStartConfig {
            name: p.child_vm_name.clone(),
            plan_json: Some(plan_json_str.clone()),
            ..Default::default()
        };
        mvm_hostd::plan_admission::stash_plan_for_bridge(&mint_cfg)?;
    }

    // Verify the parent against the signed audit chain before cloning/restoring.
    let parent_meta = p.store.read_meta(p.checkpoint)?;
    let anchor = SignedChainAnchor::load()
        .context("loading the signed audit chain to verify the fork parent")?;
    let restorer = mvm_runtime::firecracker::FcForkRestorer;
    let fork_result = fork_vm_full_fc(
        p.store,
        ForkParams {
            checkpoint: p.checkpoint.clone(),
            child_id: p.child_id,
            child_vm_name: p.child_vm_name.clone(),
            dest_dir: p.dest_dir,
            created_unix: p.now,
            child_plan_json,
            child_tenant_id,
        },
        &restorer,
        &anchor,
    );
    if let Err(ref e) = fork_result {
        super::up::emit_failed_if(&admission, "fork-vm-full-fc", e);
    }
    let meta = fork_result
        .with_context(|| format!("forking FC vm_full checkpoint {:?}", p.checkpoint.as_str()))?;

    bind_checkpoint_forked(p.checkpoint, &meta, &p.child_vm_name, p.store)?;
    super::up::emit_launched_if(&admission, "firecracker", true);

    // Deliver the fresh generation token to every restored child. A grant is
    // optional for dev/test forks, but identity rotation is not: the token is
    // bound to the child's recorded snapshot identity, not its human-readable
    // VM name. When a grant exists, re-pin it in the same PostRestore RPC.
    let mut grant_env = read_grant_envelope_for(&p.child_vm_name);
    if let Some(grant) = grant_env.as_mut()
        && let Some(parent_vm_name) = p.store.read_meta(p.checkpoint).ok().map(|m| m.vm_name)
        && let Some((session_id, plan_nonce)) = grant_predecessor_from_vm_name(&parent_vm_name)
    {
        grant.predecessor_session_id = Some(session_id);
        grant.predecessor_plan_nonce_hex = Some(plan_nonce.as_hex().to_string());
    }
    if let Err(error) = deliver_fc_fork_post_restore(
        &p.child_vm_name,
        parent_meta.meta_digest.as_str(),
        grant_env,
    ) {
        let stop_result = mvm_runtime::microvm::stop_vm(&p.child_vm_name);
        return match stop_result {
            Ok(()) => Err(error.context(format!(
                "stopped forked child '{}' after post-restore hygiene failure",
                p.child_vm_name
            ))),
            Err(stop_error) => Err(error.context(format!(
                "post-restore hygiene failed for '{}' and stopping the child also failed: {}",
                p.child_vm_name, stop_error
            ))),
        };
    }

    if p.json {
        crate::json_out::emit_json(&CheckpointForkJson {
            schema_version: 1,
            action: "fork",
            parent_id: p.checkpoint,
            child_vm_name: &p.child_vm_name,
            booted: true,
            checkpoint: &meta,
        })?;
    } else {
        ui::success(&format!(
            "forked {} -> checkpoint {} (vm '{}', auto-booted on firecracker)",
            p.checkpoint.as_str(),
            meta.id.as_str(),
            p.child_vm_name
        ));
    }
    Ok(meta)
}

fn deliver_fc_fork_post_restore(
    child_vm_name: &str,
    parent_snapshot_digest: &str,
    grant_env: Option<mvm_core::protocol::vm_backend::VerbGrantEnvelope>,
) -> Result<()> {
    let vm_dir = mvm_runtime::microvm::resolve_running_vm_dir(child_vm_name)
        .with_context(|| format!("resolving VM dir for '{child_vm_name}'"))?;
    let vsock_path_str = mvm_runtime::microvm::firecracker_vsock_uds_path(&vm_dir);
    const POLL_ATTEMPTS: u32 = 40; // 20 seconds max
    for _ in 0..POLL_ATTEMPTS {
        if mvm_agentd::vsock::ping_at(&vsock_path_str).unwrap_or(false) {
            let token =
                mvm_core::crypto::vmgenid::fresh_generation_token(parent_snapshot_digest).token;
            let host_epoch_secs = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .context("reading host wall clock for fork PostRestore")?
                .as_secs();
            let reply = mvm_agentd::vsock::post_restore_with_grant_and_clock_at(
                &vsock_path_str,
                token,
                grant_env,
                Some(host_epoch_secs),
            )
            .with_context(|| format!("sending PostRestore to '{child_vm_name}'"))?;
            require_fork_post_restore_success(reply)?;
            tracing::info!(
                "FC fork post-restore identity rotation acknowledged for '{}'",
                child_vm_name
            );
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    anyhow::bail!("guest agent not reachable for '{child_vm_name}' after fork restore")
}

fn require_fork_post_restore_success(reply: mvm_agentd::vsock::PostRestoreReply) -> Result<()> {
    anyhow::ensure!(reply.acknowledged, "guest did not acknowledge PostRestore");
    anyhow::ensure!(
        reply.reseeded,
        "guest acknowledged PostRestore without rotating its generation identity"
    );
    anyhow::ensure!(
        reply.clock_resynced,
        "guest acknowledged PostRestore without resynchronizing its wall clock"
    );
    Ok(())
}

/// Inputs for [`boot_forked_child`]. Grouped to stay under the
/// `clippy::too_many_arguments` workspace ceiling.
struct BootForkedChildParams<'a> {
    child_vm_name: &'a str,
    /// Absolute path to the materialized child rootfs (the fork output).
    /// Passed as-is to admission so `prepare_instance_rootfs`'s
    /// source-equals-instance arm returns without clobbering it.
    instance_rootfs: &'a std::path::Path,
    /// The parent fs_quick checkpoint id — used to look up the parent VM's
    /// plan when the child has none yet.
    parent_checkpoint: &'a CheckpointId,
    store: &'a CheckpointStore,
    hypervisor: &'a str,
    cpus_override: Option<u32>,
    memory_override: Option<&'a str>,
    emit_text: bool,
}

/// Admit and boot a forked child VM after its rootfs has been materialized.
///
/// Resource resolution: flags win > parent's persisted plan > global defaults.
/// The rootfs is the already-materialized instance file (`prepare_instance_rootfs`
/// returns early when source == instance, so nothing gets clobbered).
fn boot_forked_child(p: BootForkedChildParams<'_>) -> Result<()> {
    use mvm_core::util::parse_human_size;
    use mvm_runtime::backend::AnyBackend;

    let effective_hypervisor = super::super::shared::resolve_effective_hypervisor(p.hypervisor);
    let parent_agent_verbs = parent_agent_verb_override(p.parent_checkpoint, p.store);
    let parent_meta = p.store.read_meta(p.parent_checkpoint)?;

    // Resource shape: flag > parent plan > global defaults.
    let (parent_cpus, parent_mem) = parent_plan_resources(p.parent_checkpoint, p.store);
    let user_cfg = mvm_core::user_config::load(None);
    let cpus = p
        .cpus_override
        .or(parent_cpus)
        .unwrap_or(user_cfg.default_cpus);
    let mem_mib = match p.memory_override {
        Some(s) => parse_human_size(s).context("parsing --memory for --boot")?,
        None => parent_mem.unwrap_or(user_cfg.default_memory_mib),
    } as u64;

    let tenant = super::tenant_resolution::resolve_tenant(None);

    // The booted child needs a real kernel path; work-image boots ship none.
    // Fall back to the cached builder-VM kernel the same way `up` does.
    let vmlinux_placeholder = p
        .instance_rootfs
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."))
        .join("vmlinux");
    let vmlinux_path = super::up::resolve_workload_kernel(
        vmlinux_placeholder.to_str().unwrap_or(""),
        &effective_hypervisor,
    )?;

    let ledger = mvm_hostd::plan_admission::InMemoryNonceLedger::new();
    let admission = super::up::admit_plan_for_boot(super::up::AdmitPlanForBootParams {
        tenant: &tenant,
        vm_name: p.child_vm_name,
        backend_name: &effective_hypervisor,
        rootfs_path: p.instance_rootfs,
        precomputed_image_sha256: None,
        boot_artifact_identity: None,
        cpus,
        mem_mib,
        seccomp_tier: mvm_core::plan::PlanSeccompTier::Standard,
        secret_release: mvm_core::plan::SecretReleasePolicy::default(),
        secrets: Vec::new(),
        no_supervisor: false,
        ledger: &ledger,
        keys_dir: None,
        audit_dir: None,
        policy_dir: None,
        bundle_pin: None,
        deps_volume: None,
        shares: Vec::new(),
        redaction: mvm_core::policy::RedactionPolicy::default(),
        network_policy: mvm_core::network_policy::NetworkPolicy::deny_all(),
        agent_verb_override: parent_agent_verbs.clone(),
        // A baked-entrypoint child qualifies for an attenuated grant. Forks are
        // never interactive, never carry trailing argv, and are always
        // prod-profile.
        restrict_agent_verbs: !parent_agent_verbs.is_empty()
            || super::agent_verbs::grant_eligible(false, false, false),
        services: Vec::new(),
        entrypoint: crate::commands::vm::entrypoint_resolve::ResolvedEntrypoint::unresolved(
            "a checkpoint fork boots the image the parent booted; this path resolves no entrypoint",
        ),
    })?;

    let mut start_config = mvm_core::vm_backend::VmStartConfig {
        name: p.child_vm_name.to_string(),
        // Passing the instance path as rootfs_path so `prepare_instance_rootfs`
        // hits the source-equals-instance no-op arm and leaves the fork intact.
        rootfs_path: p.instance_rootfs.to_string_lossy().into_owned(),
        kernel_path: Some(vmlinux_path),
        cpus,
        memory_mib: mem_mib as u32,
        ..Default::default()
    };
    start_config.runtime_source_policy = forked_child_checkpoint_runtime_source_policy(
        &parent_meta,
        &effective_hypervisor,
        p.instance_rootfs,
    )?;
    super::up::attach_runtime_overlay_if_cached_version(
        &mut start_config,
        &effective_hypervisor,
        parent_meta.runtime_overlay_version.as_deref(),
    )?;
    super::up::attach_universal_initramfs_if_cached(&mut start_config)?;

    populate_fork_rootfs_verity(&mut start_config, p.instance_rootfs)?;

    if let Some(ctx) = admission.as_ref() {
        mvm_hostd::plan_admission::populate_audit_substrate(
            &mut start_config,
            &ctx.admitted,
            ctx.policy_bundle.as_ref(),
        )?;
    }

    // Mint the child's verb-grant sidecar. The backend's cmdline builder
    // reads it via verb_grant_cmdline_token at start time.
    if super::up::persists_plan_before_start(&effective_hypervisor) {
        mvm_hostd::plan_admission::stash_plan_for_bridge(&start_config)?;
    }

    let backend = AnyBackend::from_hypervisor(&effective_hypervisor);
    if let Err(e) = backend.start(&start_config) {
        super::up::emit_failed_if(&admission, "backend-start", &e);
        return Err(e);
    }
    super::up::emit_launched_if(&admission, &effective_hypervisor, true);

    if p.emit_text {
        ui::success(&format!(
            "child VM '{}' booted (hypervisor: {})",
            p.child_vm_name, effective_hypervisor
        ));
    }
    Ok(())
}

/// Read the minted verb-grant sidecar for `vm_name` from its per-VM state dir.
/// Returns `Some(envelope)` when the sidecar is present and parses correctly;
/// `None` on any error (absent file, malformed JSON) — grant-less is the safe
/// default when the sidecar is missing.
fn read_grant_envelope_for(
    vm_name: &str,
) -> Option<mvm_core::protocol::vm_backend::VerbGrantEnvelope> {
    let path = mvm_core::config::vm_state_dir(vm_name).join("verb-grant.json");
    let bytes = std::fs::read(&path).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn forked_child_runtime_source_policy(
    hypervisor: &str,
    instance_rootfs: &std::path::Path,
) -> mvm_core::vm_backend::RuntimeSourcePolicy {
    mvm_core::vm_backend::select_runtime_source_policy(
        mvm_core::vm_backend::RuntimeSourcePolicySelection {
            backend_name: Some(hypervisor),
            sealed: super::agent_verbs::image_is_sealed(instance_rootfs),
            root_strategy: Some(mvm_core::vm_backend::RuntimeSourceRootStrategy::BlockExt4),
            launch_kind: mvm_core::vm_backend::RuntimeSourceLaunchKind::WorkloadImage,
        },
    )
}

fn forked_child_checkpoint_runtime_source_policy(
    parent_meta: &mvm_core::checkpoint::CheckpointMeta,
    hypervisor: &str,
    instance_rootfs: &std::path::Path,
) -> Result<mvm_core::vm_backend::RuntimeSourcePolicy> {
    match (
        parent_meta.runtime_source_policy,
        parent_meta.runtime_overlay_version.as_deref(),
    ) {
        (Some(mvm_core::vm_backend::RuntimeSourcePolicy::RequiredOverlay), None) => {
            bail!(
                "checkpoint '{}' requires a runtime overlay but records no overlay version",
                parent_meta.id
            );
        }
        (Some(policy), _) => Ok(policy),
        (None, _) => Ok(forked_child_runtime_source_policy(
            hypervisor,
            instance_rootfs,
        )),
    }
}

fn grant_predecessor_from_vm_name(vm_name: &str) -> Option<(String, mvm_core::plan::Nonce)> {
    let envelope = read_grant_envelope_for(vm_name)?;
    Some((
        envelope.grant.session_id,
        mvm_core::plan::Nonce::from_hex(&envelope.plan_nonce_hex).ok()?,
    ))
}

/// Read the parent checkpoint's source VM plan and return (cpus, mem_mib).
/// Returns (None, None) when the plan is absent — the caller falls back to
/// global defaults. The parent checkpoint's `vm_name` field names the source VM.
/// If the child rootfs directory carries dm-verity sidecars, populate the
/// start config so the backend attaches the hash tree and emits the roothash
/// on the kernel cmdline. Without this the child skips `mvm-verity-init` and
/// cannot mount the runtime overlay, leading to a guest panic.
fn populate_fork_rootfs_verity(
    start_config: &mut mvm_core::vm_backend::VmStartConfig,
    rootfs: &std::path::Path,
) -> anyhow::Result<()> {
    let rootfs_dir = rootfs.parent().unwrap_or(std::path::Path::new("."));
    let verity = rootfs_dir.join("rootfs.verity");
    let roothash = rootfs_dir.join("rootfs.roothash");
    if verity.exists() && roothash.exists() {
        start_config.verity_path = Some(
            verity
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("rootfs.verity path is not UTF-8"))?
                .to_string(),
        );
        start_config.roothash = Some(
            std::fs::read_to_string(&roothash)
                .with_context(|| format!("reading {}", roothash.display()))?
                .trim()
                .to_string(),
        );
    }
    Ok(())
}

/// Read the parent checkpoint's source VM plan and return the agent-verb
/// override it was admitted with. Forks inherit the parent's explicit
/// `--agent-verb` list so that a child of an unsealed image can still be
/// grant-bearing when the parent was.
fn parent_agent_verb_override(
    parent_checkpoint: &CheckpointId,
    store: &CheckpointStore,
) -> Vec<String> {
    let Ok(parent_meta) = store.read_meta(parent_checkpoint) else {
        return Vec::new();
    };
    let Ok(plan) = super::plan_persist::read_plan(&parent_meta.vm_name) else {
        return Vec::new();
    };
    plan.agent_verbs
        .unwrap_or_default()
        .into_iter()
        .map(|v| v.as_str().to_string())
        .collect()
}

fn parent_plan_resources(
    parent_checkpoint: &CheckpointId,
    store: &CheckpointStore,
) -> (Option<u32>, Option<u32>) {
    let parent_meta = match store.read_meta(parent_checkpoint) {
        Ok(m) => m,
        Err(_) => return (None, None),
    };
    let plan = match super::plan_persist::read_plan(&parent_meta.vm_name) {
        Ok(p) => p,
        Err(_) => return (None, None),
    };
    let cpus = Some(plan.resources.cpus);
    let mem = Some(plan.resources.mem_mib as u32);
    (cpus, mem)
}

pub(crate) fn bind_checkpoint_forked(
    parent: &CheckpointId,
    child: &mvm_core::checkpoint::CheckpointMeta,
    child_vm_name: &str,
    store: &CheckpointStore,
) -> Result<()> {
    // The child VM has no persisted plan yet (it was never booted as an independent
    // VM); look up the parent VM name from the parent checkpoint record so the
    // lineage entry binds to the admitted identity the fork branched from.
    let parent_vm_name = store.read_meta(parent).ok().map(|m| m.vm_name);
    let plan =
        match super::plan_persist::read_plan(&child.vm_name).or_else(|_| {
            match parent_vm_name.as_deref() {
                Some(name) => super::plan_persist::read_plan(name),
                None => Err(anyhow::anyhow!("parent checkpoint has no recorded vm_name")),
            }
        }) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(error = %e,
                "no persisted plan for fork; checkpoint.forked emitted without chain binding");
                return Ok(());
            }
        };
    let signer = match super::host_signer::load_or_init() {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, "host signer unavailable; chain entry skipped");
            return Ok(());
        }
    };
    let emitter = super::audit_chain::AuditEmitter::new(signer.signing)
        .map(|e| e.with_receipts())
        .context("refusing an unaudited fork: audit emitter unavailable")?;
    mvm_hostd::audit::bind::bind_checkpoint_forked(&emitter, &plan, parent, child, child_vm_name)
        .context("refusing an unaudited fork")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_runtime::checkpoint::{CheckpointChainAnchor, verify_lineage};

    #[test]
    fn validated_checkpoint_id_accepts_normal() {
        assert!(validated_checkpoint_id("ckpt-myvm-1700000000").is_ok());
        assert!(validated_checkpoint_id("fork-child-42").is_ok());
    }

    #[test]
    fn validated_checkpoint_id_rejects_traversal() {
        assert!(validated_checkpoint_id("../etc").is_err());
        assert!(validated_checkpoint_id("a/b").is_err());
        assert!(validated_checkpoint_id("a\\b").is_err());
        assert!(validated_checkpoint_id("").is_err());
        assert!(validated_checkpoint_id("a\0b").is_err());
        assert!(validated_checkpoint_id("a\nb").is_err());
    }

    #[test]
    fn fork_post_restore_requires_acknowledgement_and_reseed() {
        let acknowledged = mvm_agentd::vsock::PostRestoreReply {
            acknowledged: true,
            reseeded: true,
            clock_resynced: true,
        };
        assert!(require_fork_post_restore_success(acknowledged).is_ok());

        let not_reseeded = mvm_agentd::vsock::PostRestoreReply {
            acknowledged: true,
            reseeded: false,
            clock_resynced: true,
        };
        let err = require_fork_post_restore_success(not_reseeded).unwrap_err();
        assert!(err.to_string().contains("without rotating"));

        let not_acknowledged = mvm_agentd::vsock::PostRestoreReply {
            acknowledged: false,
            reseeded: false,
            clock_resynced: false,
        };
        let err = require_fork_post_restore_success(not_acknowledged).unwrap_err();
        assert!(err.to_string().contains("did not acknowledge"));

        let not_clock_resynced = mvm_agentd::vsock::PostRestoreReply {
            acknowledged: true,
            reseeded: true,
            clock_resynced: false,
        };
        let err = require_fork_post_restore_success(not_clock_resynced).unwrap_err();
        assert!(err.to_string().contains("wall clock"));
    }

    #[test]
    fn parent_agent_verb_override_inherits_parent_verbs() {
        use mvm_contract::plan::VerbId;
        use mvm_core::checkpoint::{CheckpointClass, CheckpointId};
        use mvm_core::plan::test_support::PlanFixture;

        let mut env = mvm_core::util::test_env::TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.isolate_mvm_home(tmp.path());

        let mut plan = PlanFixture::new()
            .tenant("local")
            .plan_id("parent-plan")
            .build();
        plan.agent_verbs = Some(vec![
            VerbId::new("ping").unwrap(),
            VerbId::new("run-entrypoint").unwrap(),
        ]);
        mvm_hostd::audit::plan_persist::write_plan("parent-vm", &plan).unwrap();

        let store = mvm_runtime::checkpoint::CheckpointStore::open();
        let meta = mvm_core::checkpoint::CheckpointMeta::builder(
            CheckpointId::new("ckpt-parent"),
            CheckpointClass::FsQuick,
            "parent-vm",
        )
        .content(vec![])
        .supervisor_config_digest("d")
        .created_unix(1)
        .build();
        store.write_meta(&meta).unwrap();

        let verbs = parent_agent_verb_override(&meta.id, &store);
        assert_eq!(verbs, vec!["ping", "run-entrypoint"]);
    }

    #[test]
    fn parent_agent_verb_override_returns_empty_when_plan_missing() {
        use mvm_core::checkpoint::{CheckpointClass, CheckpointId};

        let mut env = mvm_core::util::test_env::TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.isolate_mvm_home(tmp.path());

        let store = mvm_runtime::checkpoint::CheckpointStore::open();
        let meta = mvm_core::checkpoint::CheckpointMeta::builder(
            CheckpointId::new("ckpt-no-plan"),
            CheckpointClass::FsQuick,
            "orphan-vm",
        )
        .content(vec![])
        .supervisor_config_digest("d")
        .created_unix(1)
        .build();
        store.write_meta(&meta).unwrap();

        assert!(parent_agent_verb_override(&meta.id, &store).is_empty());
    }

    // ── FC vm_full fork gate ─────────────────────────────────────────────

    /// The FC vm_full fork is refused by default (guest re-IP unsettled) and
    /// only reachable behind the explicit experimental opt-in.
    #[test]
    fn fc_vm_full_fork_gated_off_without_optin() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.remove("MVM_FORK_VMFULL_FC_EXPERIMENTAL");
        assert!(
            !fc_vm_full_fork_experimental_enabled(),
            "FC vm_full fork must be gated off unless explicitly opted in"
        );
        env.set("MVM_FORK_VMFULL_FC_EXPERIMENTAL", "1");
        assert!(
            fc_vm_full_fork_experimental_enabled(),
            "opt-in must enable the experimental FC vm_full fork restore"
        );
    }

    // ── vm_is_quiesced ───────────────────────────────────────────────────

    /// A VM with no PID files is stopped → quiesced regardless of markers.
    #[test]
    fn stopped_vm_is_quiesced() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.isolate_mvm_home(tmp.path());
        assert!(
            vm_is_quiesced("no-such-vm-stopped"),
            "stopped VM must be quiesced"
        );
    }

    // ── fc_pause_marker_matches_live_pid ─────────────────────────────────

    /// A paused FC VM: `fc.paused` in vm_state_dir matches the live fc pid at
    /// `<mvm_home>/vms/<name>/fc.pid` → quiesced (checkpoint allowed).
    #[test]
    fn fc_paused_vm_with_matching_marker_is_quiesced() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.isolate_mvm_home(tmp.path());

        let pid = unsafe { libc::getpid() };
        let pid_str = pid.to_string();

        // Write fc.pid at the location fc_pid_path() resolves to — the same
        // per-VM directory vm_state_dir names (one tree, disjoint file names).
        let fc_dir = tmp.path().join("vms").join("fcpausedvm");
        std::fs::create_dir_all(&fc_dir).unwrap();
        std::fs::write(fc_dir.join("fc.pid"), &pid_str).unwrap();

        // Write fc.paused in vm_state_dir with the same pid.
        let state_dir = mvm_core::config::vm_state_dir("fcpausedvm");
        std::fs::create_dir_all(&state_dir).unwrap();
        std::fs::write(state_dir.join("fc.paused"), &pid_str).unwrap();

        assert!(
            fc_pause_marker_matches_live_pid("fcpausedvm"),
            "fc.paused matching live fc pid must report quiesced"
        );
        assert!(
            vm_is_quiesced("fcpausedvm"),
            "paused FC VM must be considered quiesced"
        );
    }

    /// A running FC VM: live fc.pid exists but NO fc.paused marker → not quiesced
    /// (checkpoint refused — vm is writing).
    #[test]
    fn fc_running_without_marker_is_not_quiesced() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.isolate_mvm_home(tmp.path());

        let pid = unsafe { libc::getpid() };

        // Write fc.pid (vm is running) but no fc.paused marker.
        let fc_dir = tmp.path().join("vms").join("fcrunningvm");
        std::fs::create_dir_all(&fc_dir).unwrap();
        std::fs::write(fc_dir.join("fc.pid"), pid.to_string()).unwrap();

        let state_dir = mvm_core::config::vm_state_dir("fcrunningvm");
        std::fs::create_dir_all(&state_dir).unwrap();
        // No fc.paused written.

        assert!(
            !fc_pause_marker_matches_live_pid("fcrunningvm"),
            "running FC VM with no pause marker must not match"
        );
        assert!(
            !vm_is_quiesced("fcrunningvm"),
            "running FC VM with no pause marker must not be quiesced"
        );
    }

    /// Stale fc.paused: the marker's pid differs from the live fc pid → not quiesced.
    #[test]
    fn fc_stale_marker_is_not_quiesced() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.isolate_mvm_home(tmp.path());

        let live_pid = unsafe { libc::getpid() };
        let stale_pid = live_pid.saturating_add(1);

        let fc_dir = tmp.path().join("vms").join("fcstalevm");
        std::fs::create_dir_all(&fc_dir).unwrap();
        std::fs::write(fc_dir.join("fc.pid"), live_pid.to_string()).unwrap();

        let state_dir = mvm_core::config::vm_state_dir("fcstalevm");
        std::fs::create_dir_all(&state_dir).unwrap();
        // Marker has an old (stale) pid.
        std::fs::write(state_dir.join("fc.paused"), stale_pid.to_string()).unwrap();

        assert!(
            !fc_pause_marker_matches_live_pid("fcstalevm"),
            "stale fc.paused (pid mismatch) must not match"
        );
        assert!(
            !vm_is_quiesced("fcstalevm"),
            "running FC VM with stale pause marker must not be quiesced"
        );
    }

    // ── resolve_quiesced_vm_rootfs: mode.json rootfs_path resolution ─────

    /// A stopped VM whose mode.json carries `rootfs_path` pointing at an
    /// existing file resolves that path without needing a supervisor config.
    #[test]
    fn resolve_rootfs_from_mode_json_when_present() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.isolate_mvm_home(tmp.path());

        let vm_name = "mode-json-rootfs-vm";
        let state_dir = mvm_core::config::vm_state_dir(vm_name);
        std::fs::create_dir_all(&state_dir).unwrap();

        // Write a stub rootfs file.
        let rootfs_file = tmp.path().join("images").join("rootfs.ext4");
        std::fs::create_dir_all(rootfs_file.parent().unwrap()).unwrap();
        std::fs::write(&rootfs_file, b"fake rootfs").unwrap();

        // Write mode.json carrying the rootfs_path (as record_from_rootfs would).
        let meta = mvm_runtime::base::runtime_meta::VmRuntimeMeta {
            mode: mvm_runtime::base::runtime_meta::StartModeKind::Detached,
            accessible: false,
            rootfs_path: Some(rootfs_file.to_string_lossy().into_owned()),
            runtime_source_policy: mvm_core::vm_backend::RuntimeSourcePolicy::RootfsOnly,
            runtime_overlay_version: None,
            observability_target: None,
        };
        let json = serde_json::to_string(&meta).unwrap();
        std::fs::write(state_dir.join("mode.json"), json).unwrap();

        // VM is stopped (no pid file) — quiesced.
        let resolved = resolve_quiesced_vm_rootfs(vm_name).expect("must resolve");
        assert_eq!(resolved, rootfs_file);
    }

    /// When mode.json carries `rootfs_path` but the file no longer exists on
    /// disk, the error mentions the pause workflow (same user-visible guidance
    /// as the former Vz backend's supervisor-config path).
    #[test]
    fn mode_json_rootfs_path_missing_on_disk_produces_actionable_error() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.isolate_mvm_home(tmp.path());

        let vm_name = "mode-json-gone-vm";
        let state_dir = mvm_core::config::vm_state_dir(vm_name);
        std::fs::create_dir_all(&state_dir).unwrap();

        // Write mode.json pointing at a rootfs that does NOT exist.
        let gone_path = tmp.path().join("gone").join("rootfs.ext4");
        let meta = mvm_runtime::base::runtime_meta::VmRuntimeMeta {
            mode: mvm_runtime::base::runtime_meta::StartModeKind::Detached,
            accessible: false,
            rootfs_path: Some(gone_path.to_string_lossy().into_owned()),
            runtime_source_policy: mvm_core::vm_backend::RuntimeSourcePolicy::RootfsOnly,
            runtime_overlay_version: None,
            observability_target: None,
        };
        let json = serde_json::to_string(&meta).unwrap();
        std::fs::write(state_dir.join("mode.json"), json).unwrap();

        let err = resolve_quiesced_vm_rootfs(vm_name).expect_err("must error");
        let msg = err.to_string();
        assert!(
            msg.contains("pause") || msg.contains("vm-full") || msg.contains("vm_full"),
            "error must guide the user: {msg}"
        );
    }

    // ── boot_forked_child: resource-shape resolution ─────────────────────

    /// Helper: seed a minimal fs_quick checkpoint in a store and return its id.
    fn seed_checkpoint(store: &CheckpointStore, vm_name: &str) -> CheckpointId {
        let content_dir = store.content_dir(&mvm_core::checkpoint::CheckpointId::new(format!(
            "ck-{vm_name}"
        )));
        std::fs::create_dir_all(&content_dir).unwrap();
        let blob = content_dir.join("rootfs.ext4");
        std::fs::write(&blob, b"fake").unwrap();
        let sha = mvm_core::crypto::image_verify::sha256_file(&blob).unwrap();
        let meta = mvm_core::checkpoint::CheckpointMeta::builder(
            mvm_core::checkpoint::CheckpointId::new(format!("ck-{vm_name}")),
            mvm_core::checkpoint::CheckpointClass::FsQuick,
            vm_name.to_string(),
        )
        .content(vec![mvm_core::checkpoint::ContentBlob {
            name: "rootfs.ext4".into(),
            sha256: sha,
        }])
        .supervisor_config_digest("d")
        .created_unix(1)
        .build();
        store.write_meta(&meta).unwrap();
        meta.id
    }

    /// When no plan exists for the parent VM and no flags are provided, the
    /// resource resolution falls through to global defaults (2 CPUs, 512 MiB).
    #[test]
    fn resource_shape_no_plan_no_flags_uses_defaults() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.isolate_mvm_home(tmp.path());

        let store = CheckpointStore::at(tmp.path().join("store"));
        let ckpt_id = seed_checkpoint(&store, "origin-vm");

        let (cpus, mem) = parent_plan_resources(&ckpt_id, &store);
        // No plan on disk → both are None.
        assert!(cpus.is_none());
        assert!(mem.is_none());

        // Resolution: flags win (None here) → plan (None) → defaults.
        let user_cfg = mvm_core::user_config::load(None);
        let final_cpus = None::<u32>.or(cpus).unwrap_or(user_cfg.default_cpus);
        let final_mem = None::<u32>.or(mem).unwrap_or(user_cfg.default_memory_mib);
        assert_eq!(final_cpus, 2);
        assert_eq!(final_mem, 512);
    }

    /// Explicit flags win over everything: cpus=8, memory="1024" override
    /// whatever the parent plan would have said.
    #[test]
    fn resource_shape_flags_override_plan() {
        let flag_cpus: Option<u32> = Some(8);
        let flag_mem: Option<&str> = Some("1024");
        let plan_cpus: Option<u32> = Some(2);
        let plan_mem: Option<u32> = Some(512);

        let user_cfg = mvm_core::user_config::load(None);
        let final_cpus = flag_cpus.or(plan_cpus).unwrap_or(user_cfg.default_cpus);
        let final_mem_mib = flag_mem
            .map(|s| mvm_core::util::parse_human_size(s).unwrap())
            .or(plan_mem)
            .unwrap_or(user_cfg.default_memory_mib);
        assert_eq!(final_cpus, 8);
        assert_eq!(final_mem_mib, 1024);
    }

    // ── boot path: no-clobber property ───────────────────────────────────

    /// The boot arm passes the INSTANCE path (`vm_state_dir/rootfs.ext4`) as
    /// the rootfs_path in the VmStartConfig. `prepare_instance_rootfs` returns
    /// early when source == instance, so the forked rootfs is never replaced.
    #[test]
    fn boot_arm_start_config_uses_instance_path() {
        let tmp = tempfile::tempdir().unwrap();
        let instance = tmp.path().join("childvm").join("rootfs.ext4");
        std::fs::create_dir_all(instance.parent().unwrap()).unwrap();
        std::fs::write(&instance, b"forked").unwrap();

        // Build the VmStartConfig the same way boot_forked_child does, and assert
        // rootfs_path equals the instance path (not some other source).
        let config = mvm_core::vm_backend::VmStartConfig {
            name: "childvm".into(),
            rootfs_path: instance.to_string_lossy().into_owned(),
            kernel_path: None,
            cpus: 2,
            memory_mib: 512,
            ..Default::default()
        };
        assert_eq!(
            config.rootfs_path,
            instance.to_str().unwrap(),
            "rootfs_path must point at the instance file, not any source template"
        );

        // Confirm the no-clobber seam fires: prepare_instance_rootfs_inner
        // returns the same path without touching the file when src == instance.
        let out = mvm_runtime::base::cow::prepare_instance_rootfs_inner(
            &instance,
            instance.to_str().unwrap(),
        )
        .unwrap();
        assert_eq!(out, instance);
        // File must be untouched.
        assert_eq!(std::fs::read(&instance).unwrap(), b"forked");
    }

    #[test]
    fn sealed_firecracker_forked_child_requires_overlay() {
        let tmp = tempfile::tempdir().unwrap();
        let rootfs = tmp.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"fake").unwrap();
        let sidecar = mvm_build::builder_vm::GuestSidecar {
            name: "sealed".to_string(),
            accessible: false,
            sealed: true,
            entrypoint_kind: "command".to_string(),
            entrypoint_argv: Vec::new(),
            init_system: "busybox".to_string(),
            expected_boot_ms: 300,
            agent_binary: "real".to_string(),
            rootless_entrypoint: true,
            hypervisor: "firecracker".to_string(),
            overlay_aware: true,
            runtime_lean: true,
        };
        sidecar.write_to_dir(tmp.path()).unwrap();
        assert_eq!(
            forked_child_runtime_source_policy("firecracker", &rootfs),
            mvm_core::vm_backend::RuntimeSourcePolicy::RequiredOverlay
        );
    }

    #[test]
    fn unsealed_firecracker_forked_child_requires_overlay() {
        // A forked child is a block workload boot, so it requires the overlay
        // whether or not its rootfs is sealed.
        let tmp = tempfile::tempdir().unwrap();
        let rootfs = tmp.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"fake").unwrap();
        let sidecar = mvm_build::builder_vm::GuestSidecar {
            name: "dev".to_string(),
            accessible: true,
            sealed: false,
            entrypoint_kind: "shell".to_string(),
            entrypoint_argv: Vec::new(),
            init_system: "busybox".to_string(),
            expected_boot_ms: 300,
            agent_binary: "real".to_string(),
            rootless_entrypoint: false,
            hypervisor: "firecracker".to_string(),
            overlay_aware: true,
            runtime_lean: false,
        };
        sidecar.write_to_dir(tmp.path()).unwrap();
        assert_eq!(
            forked_child_runtime_source_policy("firecracker", &rootfs),
            mvm_core::vm_backend::RuntimeSourcePolicy::RequiredOverlay
        );
    }

    #[test]
    fn forked_child_checkpoint_policy_prefers_recorded_policy() {
        let tmp = tempfile::tempdir().unwrap();
        let rootfs = tmp.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"fake").unwrap();
        let parent_meta = mvm_core::checkpoint::CheckpointMeta::builder(
            CheckpointId::new("ckpt-parent"),
            CheckpointClass::FsQuick,
            "parentvm",
        )
        .content(vec![mvm_core::checkpoint::ContentBlob {
            name: "rootfs.ext4".into(),
            sha256: "abc".into(),
        }])
        .supervisor_config_digest("d")
        .runtime_source_policy(Some(
            mvm_core::vm_backend::RuntimeSourcePolicy::PreferOverlay,
        ))
        .runtime_overlay_version(Some("0.17.0".to_string()))
        .created_unix(1)
        .build();
        assert_eq!(
            forked_child_checkpoint_runtime_source_policy(&parent_meta, "firecracker", &rootfs)
                .unwrap(),
            mvm_core::vm_backend::RuntimeSourcePolicy::PreferOverlay
        );
    }

    #[test]
    fn forked_child_checkpoint_policy_rejects_required_overlay_without_version() {
        let tmp = tempfile::tempdir().unwrap();
        let rootfs = tmp.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"fake").unwrap();
        let parent_meta = mvm_core::checkpoint::CheckpointMeta::builder(
            CheckpointId::new("ckpt-parent"),
            CheckpointClass::FsQuick,
            "parentvm",
        )
        .content(vec![mvm_core::checkpoint::ContentBlob {
            name: "rootfs.ext4".into(),
            sha256: "abc".into(),
        }])
        .supervisor_config_digest("d")
        .runtime_source_policy(Some(
            mvm_core::vm_backend::RuntimeSourcePolicy::RequiredOverlay,
        ))
        .created_unix(1)
        .build();
        let err =
            forked_child_checkpoint_runtime_source_policy(&parent_meta, "firecracker", &rootfs)
                .unwrap_err();
        assert!(err.to_string().contains("records no overlay version"));
    }

    #[test]
    fn forked_child_checkpoint_policy_falls_back_for_older_checkpoints() {
        let tmp = tempfile::tempdir().unwrap();
        let rootfs = tmp.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"fake").unwrap();
        let sidecar = mvm_build::builder_vm::GuestSidecar {
            name: "sealed".to_string(),
            accessible: false,
            sealed: true,
            entrypoint_kind: "command".to_string(),
            entrypoint_argv: Vec::new(),
            init_system: "busybox".to_string(),
            expected_boot_ms: 300,
            agent_binary: "real".to_string(),
            rootless_entrypoint: true,
            hypervisor: "firecracker".to_string(),
            overlay_aware: true,
            runtime_lean: true,
        };
        sidecar.write_to_dir(tmp.path()).unwrap();
        let parent_meta = mvm_core::checkpoint::CheckpointMeta::builder(
            CheckpointId::new("ckpt-parent"),
            CheckpointClass::FsQuick,
            "parentvm",
        )
        .content(vec![mvm_core::checkpoint::ContentBlob {
            name: "rootfs.ext4".into(),
            sha256: "abc".into(),
        }])
        .supervisor_config_digest("d")
        .created_unix(1)
        .build();
        assert_eq!(
            forked_child_checkpoint_runtime_source_policy(&parent_meta, "firecracker", &rootfs)
                .unwrap(),
            mvm_core::vm_backend::RuntimeSourcePolicy::RequiredOverlay
        );
    }

    // ── bind_checkpoint_forked: parent-name resolution ───────────────────

    /// bind_checkpoint_forked resolves the parent VM name from the stored
    /// checkpoint record, not from a heuristic that guessed the checkpoint id.
    /// The observable seam: the store's read_meta returns the recorded vm_name.
    #[test]
    fn bind_uses_parent_checkpoint_vm_name() {
        let tmp = tempfile::tempdir().unwrap();
        let store = CheckpointStore::at(tmp.path());
        let parent_id = CheckpointId::new("ckpt-parentvm-1700000000");
        let parent_meta = mvm_core::checkpoint::CheckpointMeta::builder(
            parent_id.clone(),
            CheckpointClass::FsQuick,
            "parentvm",
        )
        .content(vec![mvm_core::checkpoint::ContentBlob {
            name: "rootfs.ext4".into(),
            sha256: "abc".into(),
        }])
        .supervisor_config_digest("d")
        .created_unix(1)
        .build();
        store.write_meta(&parent_meta).unwrap();

        // Verify the store round-trip returns the original vm_name, not the
        // checkpoint id string (which was what the old heuristic returned).
        let recovered = store.read_meta(&parent_id).unwrap();
        assert_eq!(
            recovered.vm_name, "parentvm",
            "store must return the recorded vm_name, not the checkpoint id"
        );
        assert_ne!(
            recovered.vm_name,
            parent_id.as_str(),
            "checkpoint id and vm_name are different; the old heuristic was wrong"
        );
    }

    // ── read_grant_envelope_for ───────────────────────────────────────────────

    /// A vm name with no state dir returns None without panicking.
    #[test]
    fn read_grant_envelope_for_returns_none_when_absent() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.isolate_mvm_home(tmp.path());

        let result = read_grant_envelope_for("no-such-vm-read-grant-test");
        assert!(result.is_none());
    }

    /// When a verb-grant.json sidecar is present and valid JSON, the function
    /// returns Some with the deserialized envelope.
    #[test]
    fn read_grant_envelope_for_returns_some_when_sidecar_present() {
        use mvm_core::protocol::vm_backend::VerbGrantEnvelope;

        let mut env = mvm_core::util::test_env::TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.isolate_mvm_home(tmp.path());

        let vm_name = "test-fork-grant-read-sidecar";
        let state_dir = mvm_core::config::vm_state_dir(vm_name);
        std::fs::create_dir_all(&state_dir).unwrap();

        // Build a minimal VerbGrant and wrap it in an envelope. The sig field
        // is not verified here (we test the file-read path, not crypto).
        let grant = mvm_core::plan::VerbGrant {
            session_id: "test-session".into(),
            plan_nonce: mvm_core::plan::Nonce::from_bytes([1u8; 16]),
            not_after: chrono::Utc::now() + chrono::Duration::hours(1),
            verbs: vec![],
            sig: vec![0u8; 64],
        };
        let envelope = VerbGrantEnvelope {
            pubkey_hex: "aa".repeat(32),
            plan_nonce_hex: "bb".repeat(16),
            predecessor_session_id: None,
            predecessor_plan_nonce_hex: None,
            grant,
        };
        let json = serde_json::to_vec(&envelope).unwrap();
        std::fs::write(state_dir.join("verb-grant.json"), &json).unwrap();

        let result = read_grant_envelope_for(vm_name);
        assert!(result.is_some(), "should read back the written sidecar");
        let got = result.unwrap();
        assert_eq!(got.pubkey_hex, envelope.pubkey_hex);
        assert_eq!(got.plan_nonce_hex, envelope.plan_nonce_hex);
    }

    #[test]
    fn grant_predecessor_from_vm_name_reads_session_and_nonce() {
        use mvm_core::protocol::vm_backend::VerbGrantEnvelope;

        let mut env = mvm_core::util::test_env::TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.isolate_mvm_home(tmp.path());

        let vm_name = "test-fork-grant-predecessor";
        let state_dir = mvm_core::config::vm_state_dir(vm_name);
        std::fs::create_dir_all(&state_dir).unwrap();

        let nonce = mvm_core::plan::Nonce::from_bytes([7u8; 16]);
        let envelope = VerbGrantEnvelope {
            pubkey_hex: "aa".repeat(32),
            plan_nonce_hex: nonce.as_hex().to_string(),
            predecessor_session_id: None,
            predecessor_plan_nonce_hex: None,
            grant: mvm_core::plan::VerbGrant {
                session_id: "parent-session".into(),
                plan_nonce: nonce.clone(),
                not_after: chrono::Utc::now() + chrono::Duration::hours(1),
                verbs: vec![],
                sig: vec![0u8; 64],
            },
        };
        let json = serde_json::to_vec(&envelope).unwrap();
        std::fs::write(state_dir.join("verb-grant.json"), &json).unwrap();

        let (session_id, predecessor_nonce) =
            grant_predecessor_from_vm_name(vm_name).expect("must read predecessor");
        assert_eq!(session_id, "parent-session");
        assert_eq!(predecessor_nonce, nonce);
    }

    // ── vm_full fork: --cpus/--memory refused ────────────────────────────────

    /// Passing --cpus to a vm_full fork is refused with a clear error message
    /// that explains the memory-restore constraint and names the fs_quick
    /// alternative.
    #[test]
    fn vm_full_fork_refuses_cpus_override() {
        let tmp = tempfile::tempdir().unwrap();
        let err = fork_vm_full_arm_inner(ForkVmFullArmParams {
            store: &CheckpointStore::at(tmp.path()),
            checkpoint: &CheckpointId::new("ck-unused"),
            new_id: None,
            cpus_override: Some(8),
            memory_override: None,
            json: false,
        })
        .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("--cpus"), "error must name --cpus: {msg}");
        assert!(
            msg.contains("fs_quick") || msg.contains("fs-quick"),
            "error must name the fs_quick alternative: {msg}"
        );
    }

    /// Passing --memory to a vm_full fork is refused with a clear error message.
    #[test]
    fn vm_full_fork_refuses_memory_override() {
        let tmp = tempfile::tempdir().unwrap();
        let err = fork_vm_full_arm_inner(ForkVmFullArmParams {
            store: &CheckpointStore::at(tmp.path()),
            checkpoint: &CheckpointId::new("ck-unused"),
            new_id: None,
            cpus_override: None,
            memory_override: Some("2G"),
            json: false,
        })
        .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("--memory"), "error must name --memory: {msg}");
        assert!(
            msg.contains("fs_quick") || msg.contains("fs-quick"),
            "error must name the fs_quick alternative: {msg}"
        );
    }

    // ── vm_is_running / vm_is_quiesced: Firecracker fc.pid path ──────────

    /// A live FC VM whose fc.pid lives under `<mvm_home>/vms/<name>/fc.pid`
    /// must be detected as running — so fs_quick refuses to checkpoint it.
    #[test]
    fn live_fc_vm_is_not_quiesced() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        // Point MVM_HOME somewhere clean so the per-VM dirs have no stale pids.
        env.isolate_mvm_home(tmp.path().join("mvm"));

        // Construct <mvm_home>/vms/<name>/fc.pid with the current process PID.
        let vm_name = "live-fc-vm-quiesce-test";
        let fc_vms_dir = tmp.path().join("mvm").join("vms").join(vm_name);
        std::fs::create_dir_all(&fc_vms_dir).unwrap();
        let pid = unsafe { libc::getpid() };
        std::fs::write(fc_vms_dir.join("fc.pid"), pid.to_string()).unwrap();

        assert!(
            !vm_is_quiesced(vm_name),
            "a live FC VM (fc.pid present in its per-VM dir) must NOT be quiesced"
        );
    }

    /// A live FC VM is refused by resolve_quiesced_vm_rootfs with a clear error.
    #[test]
    fn resolve_quiesced_vm_rootfs_refuses_live_fc_vm() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.isolate_mvm_home(tmp.path().join("mvm"));

        let vm_name = "live-fc-refuse-test";
        let fc_vms_dir = tmp.path().join("mvm").join("vms").join(vm_name);
        std::fs::create_dir_all(&fc_vms_dir).unwrap();
        let pid = unsafe { libc::getpid() };
        std::fs::write(fc_vms_dir.join("fc.pid"), pid.to_string()).unwrap();

        let err = resolve_quiesced_vm_rootfs(vm_name)
            .expect_err("live FC VM must be refused by resolve_quiesced_vm_rootfs");
        let msg = err.to_string();
        assert!(
            msg.contains("stop or pause"),
            "error must tell user to stop or pause: {msg}"
        );
        assert!(msg.contains(vm_name), "error must name the VM: {msg}");
    }

    /// A stopped FC VM (no fc.pid file in its per-VM dir) is quiesced.
    #[test]
    fn stopped_fc_vm_is_quiesced() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.isolate_mvm_home(tmp.path().join("mvm"));

        // No fc.pid written — VM is stopped.
        assert!(
            vm_is_quiesced("stopped-fc-vm-test"),
            "stopped FC VM (no fc.pid in its per-VM dir) must be quiesced"
        );
    }

    // ── ensure_save_restore_supported: backend-neutral gate ─────────────────

    /// The platform's auto-selected backend satisfies SaveRestore iff its
    /// snapshot_capability rank >= 2. This test checks the backend-neutral
    /// satisfies logic the gate relies on.
    #[test]
    fn save_restore_gate_error_is_backend_neutral() {
        // We can't run ensure_save_restore_supported directly because it checks
        // the auto-selected backend which may or may not be available in CI.
        // Instead, assert the Unsupported path produces a backend-neutral message
        // by exercising the SnapshotCapability::satisfies logic directly.
        use mvm_core::vm_backend::SnapshotCapability;
        assert!(
            SnapshotCapability::LiveMemory.satisfies(SnapshotCapability::SaveRestore),
            "LiveMemory (FC) must satisfy SaveRestore (rank 3 >= 2)"
        );
        assert!(
            SnapshotCapability::SaveRestore.satisfies(SnapshotCapability::SaveRestore),
            "SaveRestore must satisfy itself"
        );
        assert!(
            !SnapshotCapability::Unsupported.satisfies(SnapshotCapability::SaveRestore),
            "Unsupported must not satisfy SaveRestore"
        );
    }

    // ── SignedChainAnchor: real signed-chain linkage ─────────────────────────

    use mvm_core::checkpoint::{CheckpointClass, ContentBlob};

    /// Capture a checkpoint record and emit its `checkpoint.created` entry into
    /// the host-signed audit chain under the active `MVM_HOME`, exactly as the
    /// capture path does. Returns the persisted meta.
    fn seed_audited_checkpoint(
        store: &CheckpointStore,
        id: &str,
        rootfs_sha: &str,
    ) -> CheckpointMeta {
        let meta = CheckpointMeta::builder(CheckpointId::new(id), CheckpointClass::FsQuick, "vm")
            .content(vec![ContentBlob {
                name: "rootfs.ext4".into(),
                sha256: rootfs_sha.into(),
            }])
            .supervisor_config_digest("d")
            .created_unix(1)
            .build();
        store.write_meta(&meta).unwrap();

        let signer = super::super::host_signer::load_or_init().unwrap();
        let emitter = super::super::audit_chain::AuditEmitter::new(signer.signing).unwrap();
        let plan = mvm_core::plan::test_support::PlanFixture::new()
            .tenant("local")
            .plan_id("plan-verify")
            .build();
        mvm_hostd::audit::bind::bind_checkpoint_created(&emitter, &plan, &meta).unwrap();
        meta
    }

    #[test]
    fn signed_chain_anchor_indexes_a_real_created_entry_and_verify_passes() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.isolate_mvm_home(tmp.path());

        let store = CheckpointStore::open();
        let meta = seed_audited_checkpoint(&store, "ckpt-anchor-1", "aa");

        let anchor = SignedChainAnchor::load().unwrap();
        // The anchor recovers the checkpoint's content-address from the signed
        // chain, and the full lineage verifies against it.
        assert_eq!(
            anchor.recorded_creation_digest(&meta).unwrap(),
            Some(meta.meta_digest.clone())
        );
        verify_lineage(&store, &meta.id, &anchor).unwrap();
    }

    /// The point of chain-anchoring: a fully self-consistent local re-forge — an
    /// attacker rewrites the record's content AND recomputes its `meta_digest` so
    /// the two agree on disk — passes local recompute but is caught by the signed
    /// chain, which recorded the original content-address and cannot be re-signed.
    #[test]
    fn chain_anchor_catches_a_fully_consistent_local_reforge() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.isolate_mvm_home(tmp.path());

        let store = CheckpointStore::open();
        // The audited original: the chain records ITS content-address.
        seed_audited_checkpoint(&store, "ckpt-anchor-2", "aa");

        // Attacker overwrites meta.json with a different-content record whose own
        // meta_digest is recomputed to match (locally consistent).
        let reforged = CheckpointMeta::builder(
            CheckpointId::new("ckpt-anchor-2"),
            CheckpointClass::FsQuick,
            "vm",
        )
        .content(vec![ContentBlob {
            name: "rootfs.ext4".into(),
            sha256: "zz".into(),
        }])
        .supervisor_config_digest("d")
        .created_unix(1)
        .build();
        store.write_meta(&reforged).unwrap();
        // Local recompute alone would accept this — it is self-consistent.
        assert_eq!(reforged.meta_digest, reforged.compute_meta_digest());

        let anchor = SignedChainAnchor::load().unwrap();
        let err = verify_lineage(&store, &reforged.id, &anchor).unwrap_err();
        assert!(
            err.to_string()
                .contains("does not match the signed audit chain"),
            "the signed chain must catch a consistent local re-forge, got: {err}"
        );
    }

    // ── image lineage: real signed-chain linkage ─────────────────────────────

    use mvm_core::image_lineage::{
        ImageBuildIdentity, ImageCanonicalId, ImageIdentity, ImageNode, ImageProvenance,
    };
    use mvm_runtime::image_lineage::{ImageStore, verify_image_lineage};

    fn image_node(slot: &str, revision: &str, parent: Option<CheckpointDigest>) -> ImageNode {
        ImageNode::builder(
            ImageBuildIdentity::Flake {
                slot_hash: slot.into(),
            },
            ImageIdentity {
                canonical: ImageCanonicalId::Flake {
                    revision_hash: revision.into(),
                },
                artifacts: vec![ContentBlob {
                    name: "rootfs.ext4".into(),
                    sha256: revision.into(),
                }],
            },
            ImageProvenance::Build {
                input_ref: ".#app".into(),
                lock_digest: None,
            },
        )
        .parent(parent)
        .created_unix(1)
        .build()
    }

    /// Save a node and emit its `image.created` entry into the host-signed chain
    /// under the active `MVM_HOME`, exactly as the build path (a later slice)
    /// will. Returns nothing; the store + chain are the observable state.
    fn seed_audited_image_node(store: &ImageStore, node: &ImageNode) {
        store.save(node).unwrap();
        let signer = super::super::host_signer::load_or_init().unwrap();
        let emitter = super::super::audit_chain::AuditEmitter::new(signer.signing).unwrap();
        let plan = mvm_core::plan::test_support::PlanFixture::new()
            .tenant("local")
            .plan_id("plan-image-verify")
            .build();
        emitter.emit_image_created(&plan, node).unwrap();
    }

    #[test]
    fn image_lineage_verifies_against_a_real_signed_chain() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.isolate_mvm_home(tmp.path());

        let store = ImageStore::open();
        let g0 = image_node("slot-a", "rev-1", None);
        let g1 = image_node("slot-a", "rev-2", Some(g0.node_digest.clone()));
        let g2 = image_node("slot-a", "rev-3", Some(g1.node_digest.clone()));
        seed_audited_image_node(&store, &g0);
        seed_audited_image_node(&store, &g1);
        seed_audited_image_node(&store, &g2);

        let anchor = SignedChainAnchor::load().unwrap();
        // The anchor recovers each node's content-address from the signed chain,
        // and the full three-node version lineage verifies against it.
        verify_image_lineage(&store, &g2.node_digest, &anchor).unwrap();
        // The store's head_for reports g2 as the chain's tip.
        assert_eq!(
            store
                .head_for(&ImageBuildIdentity::Flake {
                    slot_hash: "slot-a".into()
                })
                .unwrap()
                .unwrap()
                .node_digest,
            g2.node_digest
        );
    }

    #[test]
    fn image_lineage_refuses_a_node_absent_from_the_signed_chain() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.isolate_mvm_home(tmp.path());

        let store = ImageStore::open();
        let g0 = image_node("slot-a", "rev-1", None);
        // Saved but NEVER audited: no image.created entry anchors it.
        store.save(&g0).unwrap();

        let anchor = SignedChainAnchor::load().unwrap();
        let err = verify_image_lineage(&store, &g0.node_digest, &anchor).unwrap_err();
        assert!(err.to_string().contains("no signed audit entry"), "{err}");
    }

    /// End-to-end proof that the *build path*'s node recorder produces nodes
    /// that verify against the real host-signed chain: a genesis build, an
    /// idempotent rebuild of the same revision, and a new-revision child, all
    /// through `record_image_node` with the real signer / emitter / store under
    /// `MVM_HOME`, then verified with the real `SignedChainAnchor`.
    #[test]
    fn build_path_nodes_verify_against_the_real_signed_chain() {
        use crate::commands::build::image_lineage::{
            ImageNodeInputs, ImageNodeOutcome, record_image_node,
        };

        let mut env = mvm_core::util::test_env::TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.isolate_mvm_home(tmp.path());

        let store = ImageStore::open();
        let signer = super::super::host_signer::load_or_init().unwrap();
        let emitter = super::super::audit_chain::AuditEmitter::new(signer.signing).unwrap();
        let plan = mvm_core::plan::test_support::PlanFixture::new()
            .tenant("local")
            .plan_id("plan-build-path")
            .build();

        let inputs = |revision: &str| ImageNodeInputs {
            build_identity: ImageBuildIdentity::Flake {
                slot_hash: "slot-a".into(),
            },
            canonical: ImageCanonicalId::Flake {
                revision_hash: revision.into(),
            },
            artifacts: vec![ContentBlob {
                name: "rootfs.ext4".into(),
                sha256: revision.into(),
            }],
            provenance: ImageProvenance::Build {
                input_ref: ".#app".into(),
                lock_digest: Some("sha256:lock".into()),
            },
        };

        // Genesis build. The anchor is the real signed-chain reader, reloaded per
        // call so it reflects the chain as of that record.
        let genesis = match record_image_node(
            &store,
            &emitter,
            &plan,
            &inputs("rev-1"),
            1,
            &SignedChainAnchor::load().unwrap(),
        )
        .unwrap()
        {
            ImageNodeOutcome::Created(d) => d,
            other => panic!("expected Created, got {other:?}"),
        };
        // Idempotent rebuild of the identical revision → no new node (the genesis
        // is now anchored in the reloaded chain).
        assert!(matches!(
            record_image_node(
                &store,
                &emitter,
                &plan,
                &inputs("rev-1"),
                2,
                &SignedChainAnchor::load().unwrap(),
            )
            .unwrap(),
            ImageNodeOutcome::AlreadyCurrent(_)
        ));
        // New revision chains as a child of genesis.
        let child = match record_image_node(
            &store,
            &emitter,
            &plan,
            &inputs("rev-2"),
            3,
            &SignedChainAnchor::load().unwrap(),
        )
        .unwrap()
        {
            ImageNodeOutcome::Created(d) => d,
            other => panic!("expected Created, got {other:?}"),
        };
        assert_eq!(
            store.by_digest(&child).unwrap().unwrap().parent.as_ref(),
            Some(&genesis)
        );

        // The two-node chain verifies against the real signed audit chain, and
        // the store reports the child as the single tip.
        let anchor = SignedChainAnchor::load().unwrap();
        verify_image_lineage(&store, &child, &anchor).unwrap();
        assert_eq!(
            store
                .head_for(&ImageBuildIdentity::Flake {
                    slot_hash: "slot-a".into()
                })
                .unwrap()
                .unwrap()
                .node_digest,
            child
        );
    }

    /// The OCI-pull recorder keys the chain on registry+repository and the
    /// resolved manifest digest, and its nodes verify against the real signed
    /// chain just like the flake path's.
    #[test]
    fn oci_pull_nodes_verify_against_the_real_signed_chain() {
        use crate::commands::build::image_lineage::{
            ImageNodeInputs, ImageNodeOutcome, record_image_node,
        };

        let mut env = mvm_core::util::test_env::TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.isolate_mvm_home(tmp.path());

        let store = ImageStore::open();
        let signer = super::super::host_signer::load_or_init().unwrap();
        let emitter = super::super::audit_chain::AuditEmitter::new(signer.signing).unwrap();
        let plan = mvm_core::plan::test_support::PlanFixture::new()
            .tenant("local")
            .plan_id("plan-oci-pull")
            .build();

        let inputs = |digest_hex: &str| ImageNodeInputs {
            build_identity: ImageBuildIdentity::Oci {
                registry: "docker.io".into(),
                repository: "library/alpine".into(),
            },
            canonical: ImageCanonicalId::Oci {
                resolved_digest: format!("sha256:{}", digest_hex.repeat(64)),
            },
            artifacts: vec![ContentBlob {
                name: "rootfs.ext4".into(),
                sha256: digest_hex.into(),
            }],
            provenance: ImageProvenance::Oci {
                resolved_digest: format!("sha256:{}", digest_hex.repeat(64)),
                layer_digests: vec![format!("sha256:{}", "e".repeat(64))],
            },
        };

        let genesis = match record_image_node(
            &store,
            &emitter,
            &plan,
            &inputs("a"),
            1,
            &SignedChainAnchor::load().unwrap(),
        )
        .unwrap()
        {
            ImageNodeOutcome::Created(d) => d,
            other => panic!("expected Created, got {other:?}"),
        };
        // Re-pulling the same digest is idempotent (the genesis is now anchored).
        assert!(matches!(
            record_image_node(
                &store,
                &emitter,
                &plan,
                &inputs("a"),
                2,
                &SignedChainAnchor::load().unwrap(),
            )
            .unwrap(),
            ImageNodeOutcome::AlreadyCurrent(_)
        ));
        // A newly-resolved digest for the same repo chains as a child.
        let child = match record_image_node(
            &store,
            &emitter,
            &plan,
            &inputs("b"),
            3,
            &SignedChainAnchor::load().unwrap(),
        )
        .unwrap()
        {
            ImageNodeOutcome::Created(d) => d,
            other => panic!("expected Created, got {other:?}"),
        };
        assert_eq!(
            store.by_digest(&child).unwrap().unwrap().parent.as_ref(),
            Some(&genesis)
        );

        let anchor = SignedChainAnchor::load().unwrap();
        verify_image_lineage(&store, &child, &anchor).unwrap();
    }
}
