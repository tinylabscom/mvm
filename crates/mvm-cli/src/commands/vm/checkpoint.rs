//! `mvmctl checkpoint create|ls|rm|fork` — immutable fs_quick snapshots of a
//! quiesced VM's rootfs, and copy-on-write forks that branch a new sandbox
//! lineage from one. With `--boot` the fork arm also admits and launches the
//! child as a fresh VM, adopting the materialized rootfs without clobbering it.
//!
//! Only the macOS Vz workload backend materializes a host-side rootfs image,
//! so checkpointing is gated to a VM that has one.

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use clap::Args as ClapArgs;

use mvm_backend::checkpoint::{
    CaptureFsQuickParams, CaptureVmFullParams, CheckpointStore, ForkParams, RestoreParams,
    capture_fs_quick, capture_vm_full, fork_checkpoint, fork_vm_full, restore_checkpoint,
};
use mvm_backend::vz::supervisor_config_path;
use mvm_core::checkpoint::{CheckpointClass, CheckpointId};
use mvm_core::config::vm_state_dir;
use mvm_hostd::audit::bind::class_str;

use super::Cli;
use super::shared::clap_vm_name;
use crate::ui;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct CheckpointArgs {
    #[command(subcommand)]
    pub command: CheckpointCmd,
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
        CheckpointCmd::Restore { id } => restore(&id),
        CheckpointCmd::Ls { json } => ls(json),
        CheckpointCmd::Rm { id } => rm(&id),
        CheckpointCmd::Fork {
            id,
            new_id,
            boot,
            hypervisor,
            cpus,
            memory,
        } => fork(&id, new_id, boot, &hypervisor, cpus, memory.as_deref()),
        CheckpointCmd::Diff { a, b, json } => diff(&a, &b, json),
    }
}

/// Reject a user-supplied checkpoint id that could escape the store root or
/// otherwise produce an unsafe on-disk directory name. The id becomes a
/// directory component under `checkpoints_dir()`, so path-traversal and
/// control bytes must never reach the filesystem.
fn validated_checkpoint_id(raw: &str) -> Result<CheckpointId> {
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

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Resolve the host-side bootable rootfs image for a quiesced VM, or a clean
/// error explaining why a checkpoint can't be taken.
///
/// "Quiesced" means the VM is not running, OR the pause verb has written a
/// `vz.paused` marker that matches the live supervisor pid (vCPUs and virtio
/// queues quiesced). A live, unpaused VM is refused: an fs_quick checkpoint has
/// no memory, so the rootfs must be in a clean, deterministic state.
///
/// Rootfs location is backend-specific but the macOS Vz workload backend keeps
/// the image under `vm_state_dir(name)`:
///   - a per-instance `rootfs.ext4` CoW clone lands there;
///   - Vz boots from a supplied path but persists the launch config, whose
///     `rootfs` disk records that path.
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

    // Vz persists its full supervisor config at launch; the rootfs disk's
    // path points at the bootable image.
    if let Some(path) = vz_rootfs_from_supervisor_config(&state_dir)? {
        if !path.exists() {
            bail!(
                "fs_quick checkpoint needs the VM's instance rootfs ({}), which is \
                 removed when the VM is stopped on this backend. Pause instead: \
                 `mvmctl vm pause {name}`, checkpoint, then `mvmctl vm resume {name}` \
                 — or use `--class vm-full` on a running VM.",
                path.display()
            );
        }
        return Ok(path);
    }

    bail!("fs_quick checkpoint is not supported for this VM's backend");
}

/// Read the persisted Vz supervisor config and return the `rootfs` disk path,
/// if the config exists and names one. Absent config → `Ok(None)` (let the
/// caller fall through to the unsupported-backend error).
fn vz_rootfs_from_supervisor_config(state_dir: &std::path::Path) -> Result<Option<PathBuf>> {
    let cfg_path = state_dir.join("supervisor-config.json");
    let bytes = match std::fs::read(&cfg_path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("reading {}", cfg_path.display())),
    };
    let cfg: mvm_build::vz::SupervisorConfig = serde_json::from_slice(&bytes)
        .with_context(|| format!("parsing {}", cfg_path.display()))?;
    let rootfs = cfg
        .disks
        .iter()
        .find(|d| d.id == "rootfs")
        .map(|d| PathBuf::from(&d.path));
    Ok(rootfs)
}

/// Best-effort liveness: a VM is "running" iff one of its per-backend PID
/// files names a live process. Mirrors the per-backend `kill(pid, 0)` probe.
fn vm_is_running(name: &str) -> bool {
    let state_dir = vm_state_dir(name);
    ["vz.pid", "libkrun.pid"]
        .iter()
        .filter_map(|f| std::fs::read_to_string(state_dir.join(f)).ok())
        .filter_map(|s| s.trim().parse::<libc::pid_t>().ok())
        // SAFETY: signal 0 only probes existence; it delivers nothing.
        .any(|pid| unsafe { libc::kill(pid, 0) == 0 })
}

/// fs_quick clones the instance rootfs, so the guest must not be writing:
/// either the VM is stopped, or it is paused (vCPUs and virtio queues quiesced
/// — the Vz pause verb stamps the supervisor pid into `vz.paused`; resume and
/// any path that replaces the supervisor removes or invalidates it). A
/// running-but-paused Vz supervisor keeps its pid alive, so `vm_is_running`
/// alone would incorrectly refuse the checkpoint without this marker check.
fn vm_is_quiesced(name: &str) -> bool {
    if !vm_is_running(name) {
        return true;
    }
    vz_pause_marker_matches_live_pid(name)
}

/// A paused Vz VM keeps its supervisor pid alive, so pid-liveness
/// alone reads as "running". The pause verb stamps the supervisor's
/// pid into a marker; the marker only counts if it matches the live
/// pid — a marker left behind by a crash or a re-launched VM names a
/// dead or different supervisor and is ignored.
fn vz_pause_marker_matches_live_pid(name: &str) -> bool {
    let dir = vm_state_dir(name);
    let (Ok(marker), Ok(pid)) = (
        std::fs::read_to_string(dir.join("vz.paused")),
        std::fs::read_to_string(dir.join("vz.pid")),
    ) else {
        return false;
    };
    !marker.trim().is_empty() && marker.trim() == pid.trim()
}

/// Hash the VM's persisted supervisor config so the checkpoint pins the launch
/// shape it was captured from. No config on disk → empty digest (the field is
/// advisory for fs_quick; integrity rests on `content_sha256`).
fn supervisor_config_digest(state_dir: &std::path::Path) -> String {
    let cfg_path = state_dir.join("supervisor-config.json");
    mvm_core::crypto::image_verify::sha256_file(&cfg_path).unwrap_or_default()
}

fn create(name: &str, tag: Option<String>, json: bool) -> Result<()> {
    let rootfs = resolve_quiesced_vm_rootfs(name)?;
    let state_dir = vm_state_dir(name);
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

/// `mvmctl checkpoint create --class vm-full <vm>`: capture a RUNNING VM's
/// {rootfs, memory, machine-id} triple in one pause window. The inverse of
/// fs_quick — a vm_full checkpoint carries memory, so the VM must be live (the
/// library's `VzVmFullControl` pauses/saves/resumes it).
fn create_vm_full(name: &str, tag: Option<String>, json: bool) -> Result<()> {
    if !vm_is_running(name) {
        bail!("checkpoint --class vm-full requires a running VM; start '{name}' first");
    }
    let state_dir = vm_state_dir(name);
    let store = CheckpointStore::open();
    let now = now_unix();
    let id = CheckpointId::new(format!("ckpt-{name}-{now}"));

    let control = mvm_backend::vz::VzVmFullControl::new(name);
    let meta = capture_vm_full(
        &store,
        CaptureVmFullParams {
            id,
            vm_name: name.to_string(),
            supervisor_config_digest: supervisor_config_digest(&state_dir),
            tag,
            created_unix: now,
        },
        &control,
    )
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
        Ok(e) => e,
        Err(e) => {
            tracing::warn!(error = %e, "audit emitter unavailable; chain entry skipped");
            return;
        }
    };
    if let Err(e) = mvm_hostd::audit::bind::bind_checkpoint_created(&emitter, &plan, meta) {
        tracing::warn!(error = %e, "audit emit_checkpoint_created failed (non-fatal)");
    }
}

/// Best-effort: loads the persisted plan for `vm_name` and emits
/// `checkpoint.restored` into the chain-signed audit log. Non-fatal —
/// a restored checkpoint is already live; missing plan/signer/emitter
/// is warned and skipped.
pub(crate) fn bind_checkpoint_restored(vm_name: &str, meta: &mvm_core::checkpoint::CheckpointMeta) {
    let plan = match super::plan_persist::read_plan(vm_name) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, vm = vm_name,
                "no persisted plan; checkpoint.restored emitted without chain binding");
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
        Ok(e) => e,
        Err(e) => {
            tracing::warn!(error = %e, "audit emitter unavailable; chain entry skipped");
            return;
        }
    };
    if let Err(e) = mvm_hostd::audit::bind::bind_checkpoint_restored(&emitter, &plan, meta) {
        tracing::warn!(error = %e, "audit emit_checkpoint_restored failed (non-fatal)");
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
    println!(
        "{:<32} {:<10} {:<20} {:<8} PARENT",
        "ID", "CLASS", "VM", "TAG"
    );
    for m in &metas {
        let class = class_str(m.class);
        println!(
            "{:<32} {:<10} {:<20} {:<8} {}",
            m.id.as_str(),
            class,
            m.vm_name,
            m.tag.as_deref().unwrap_or("-"),
            m.parent.as_ref().map(|p| p.as_str()).unwrap_or("-"),
        );
    }
    Ok(())
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
    let d = mvm_backend::checkpoint::diff_checkpoints(&meta_a, &meta_b);

    if json {
        crate::json_out::emit_json(&d)?;
        return Ok(());
    }

    use mvm_backend::checkpoint::{BlobStatus, LineageRelation};
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

fn rm(id: &str) -> Result<()> {
    let id = validated_checkpoint_id(id)?;
    CheckpointStore::open().remove(&id)?;
    ui::success(&format!("checkpoint {} removed", id.as_str()));
    Ok(())
}

/// `mvmctl checkpoint restore <id>`: same-identity resume of a vm_full
/// checkpoint. The library verifies the manifest, then materializes the saved
/// {rootfs, memory, machine-id} back into the original VM and resumes it.
fn restore(id: &str) -> Result<()> {
    let checkpoint = validated_checkpoint_id(id)?;
    let store = CheckpointStore::open();
    let meta = store.read_meta(&checkpoint)?;

    let backend = mvm_backend::vz::VzBackend;
    restore_checkpoint(
        &store,
        RestoreParams {
            checkpoint: checkpoint.clone(),
            target_vm: meta.vm_name.clone(),
        },
        &backend,
    )
    .with_context(|| format!("restoring checkpoint {id:?}"))?;

    bind_checkpoint_restored(&meta.vm_name, &meta);
    ui::success(&format!(
        "restored {} into vm '{}'",
        checkpoint.as_str(),
        meta.vm_name
    ));
    Ok(())
}

fn fork(
    id: &str,
    new_id: Option<String>,
    boot: bool,
    hypervisor: &str,
    cpus: Option<u32>,
    memory: Option<&str>,
) -> Result<()> {
    let checkpoint = validated_checkpoint_id(id)?;
    let store = CheckpointStore::open();
    // Pick the fork arm by the parent's class: vm_full carries memory and must
    // restore through `fork_vm_full` (which auto-boots the child); fs_quick is
    // a rootfs-only clone that the operator can optionally boot with `--boot`.
    let parent = store.read_meta(&checkpoint)?;
    match parent.class {
        CheckpointClass::VmFull => fork_vm_full_arm(&store, &checkpoint, new_id, cpus, memory),
        CheckpointClass::FsQuick => {
            fork_fs_quick_arm(&store, &checkpoint, new_id, boot, hypervisor, cpus, memory)
        }
    }
}

/// fs_quick fork: CoW-clone the rootfs into a new VM state dir. With
/// `--boot`, also admits and launches the child as a fresh VM, adopting the
/// materialized rootfs without clobbering it (the no-clobber seam in
/// `prepare_instance_rootfs` returns early when source == instance path).
fn fork_fs_quick_arm(
    store: &CheckpointStore,
    checkpoint: &CheckpointId,
    new_id: Option<String>,
    boot: bool,
    hypervisor: &str,
    cpus: Option<u32>,
    memory: Option<&str>,
) -> Result<()> {
    let now = now_unix();
    let child_vm_name = new_id.unwrap_or_else(|| format!("{}-fork-{now}", checkpoint.as_str()));
    let dest_dir = vm_state_dir(&child_vm_name);
    let child_id = CheckpointId::new(format!("fork-{child_vm_name}-{now}"));

    let meta = fork_checkpoint(
        store,
        ForkParams {
            checkpoint: checkpoint.clone(),
            child_id,
            child_vm_name: child_vm_name.clone(),
            dest_dir: dest_dir.clone(),
            created_unix: now,
            child_plan_json: None,
            child_tenant_id: None,
        },
    )
    .with_context(|| format!("forking checkpoint {:?}", checkpoint.as_str()))?;

    // A fork that we can't audit (signer present but emit fails) is refused —
    // an unaudited lineage record would break the chain. A missing plan/signer
    // is best-effort, matching capture.
    bind_checkpoint_forked(checkpoint, &meta, &child_vm_name, store)?;

    ui::success(&format!(
        "forked {} -> checkpoint {} (vm '{}')",
        checkpoint.as_str(),
        meta.id.as_str(),
        child_vm_name
    ));

    if boot {
        let instance_rootfs = dest_dir.join("rootfs.ext4");
        boot_forked_child(BootForkedChildParams {
            child_vm_name: &child_vm_name,
            instance_rootfs: &instance_rootfs,
            parent_checkpoint: checkpoint,
            store,
            hypervisor,
            cpus_override: cpus,
            memory_override: memory,
        })?;
    } else {
        ui::info(&format!(
            "child '{child_vm_name}' materialized at {}; re-run the fork with \
             --boot to admit and launch a child, or delete the directory to \
             discard this one",
            dest_dir.display()
        ));
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
}

/// vm_full fork: clone the captured triple into a new child identity, admit a
/// fresh claim-8 plan for the child (using the parent's saved cpu/mem — the
/// restore shape is fixed), rewrite the supervisor config, and boot the child
/// in restore mode. The child's admitted plan is distinct from the parent's.
fn fork_vm_full_arm(
    store: &CheckpointStore,
    checkpoint: &CheckpointId,
    new_id: Option<String>,
    cpus_override: Option<u32>,
    memory_override: Option<&str>,
) -> Result<()> {
    fork_vm_full_arm_inner(ForkVmFullArmParams {
        store,
        checkpoint,
        new_id,
        cpus_override,
        memory_override,
    })
}

fn fork_vm_full_arm_inner(p: ForkVmFullArmParams<'_>) -> Result<()> {
    // A vm_full fork restores a saved machine state whose cpu/mem are baked
    // into the snapshot; Vz validates device config against the saved state
    // and refuses a mismatch. Accepting these flags would silently fail at
    // restore time with a confusing hypervisor error — refuse early.
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

    // Read the parent supervisor config to extract the saved machine shape
    // (cpu_count / memory_mib). The restore must match these exactly.
    let parent_meta = p.store.read_meta(p.checkpoint)?;
    let parent_cfg_path =
        supervisor_config_path(&mvm_core::config::vm_state_dir(&parent_meta.vm_name));
    let parent_cfg_bytes = std::fs::read(&parent_cfg_path).with_context(|| {
        format!(
            "reading parent supervisor config {}",
            parent_cfg_path.display()
        )
    })?;
    let parent_cfg: mvm_build::vz::SupervisorConfig = serde_json::from_slice(&parent_cfg_bytes)
        .with_context(|| {
            format!(
                "parsing parent supervisor config {}",
                parent_cfg_path.display()
            )
        })?;
    let cpus = parent_cfg.resources.cpu_count;
    let mem_mib = parent_cfg.resources.memory_mib;

    // Admit a fresh plan for the child under the child's identity using the
    // checkpoint's RECORDED rootfs sha (the child's materialized rootfs is a
    // clone of that blob — same bytes). Re-hashing the multi-hundred-MB image
    // here would double the fork latency for nothing: `fork_vm_full` runs
    // `verify_content` over the same blob fail-closed before any supervisor
    // spawns, so a tampered blob aborts the launch instead of booting
    // mis-admitted.
    let rootfs_blob = p.store.content_dir(p.checkpoint).join("rootfs.ext4");
    let recorded_sha = parent_meta
        .content
        .iter()
        .find(|b| b.name == "rootfs.ext4")
        .map(|b| b.sha256.clone());
    let tenant = super::tenant_resolution::resolve_tenant(None);
    let ledger = super::plan_admission::InMemoryNonceLedger::new();
    let admission = super::up::admit_plan_for_boot(super::up::AdmitPlanForBootParams {
        tenant: &tenant,
        vm_name: &child_vm_name,
        backend_name: "vz",
        rootfs_path: &rootfs_blob,
        precomputed_image_sha256: recorded_sha,
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
    })?;

    // Serialize the admitted plan envelope so the backend can inject it into
    // the child's SupervisorConfig before spawning.
    let child_plan_json = admission.as_ref().map(|ctx| {
        serde_json::to_string(&ctx.admitted.signed).expect("admitted plan is always serializable")
    });
    let child_tenant_id = admission
        .as_ref()
        .map(|ctx| ctx.admitted.plan.tenant.0.clone());

    let spawner = mvm_backend::vz::VzChildSupervisorSpawner;
    let fork_result = fork_vm_full(
        p.store,
        ForkParams {
            checkpoint: p.checkpoint.clone(),
            child_id,
            child_vm_name: child_vm_name.clone(),
            dest_dir,
            created_unix: now,
            child_plan_json,
            child_tenant_id,
        },
        &spawner,
    );
    if let Err(ref e) = fork_result {
        super::up::emit_failed_if(&admission, "fork-vm-full", e);
    }
    let meta = fork_result
        .with_context(|| format!("forking vm_full checkpoint {:?}", p.checkpoint.as_str()))?;

    bind_checkpoint_forked(p.checkpoint, &meta, &child_vm_name, p.store)?;
    super::up::emit_launched_if(&admission, "vz");

    ui::success(&format!(
        "forked {} -> checkpoint {} (vm '{}', auto-booted)",
        p.checkpoint.as_str(),
        meta.id.as_str(),
        child_vm_name
    ));
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
}

/// Admit and boot a forked child VM after its rootfs has been materialized.
///
/// Resource resolution: flags win > parent's persisted plan > global defaults.
/// The rootfs is the already-materialized instance file (`prepare_instance_rootfs`
/// returns early when source == instance, so nothing gets clobbered).
fn boot_forked_child(p: BootForkedChildParams<'_>) -> Result<()> {
    use mvm_backend::backend::AnyBackend;
    use mvm_core::util::parse_human_size;

    let effective_hypervisor = super::super::shared::resolve_effective_hypervisor(p.hypervisor);

    // The fork was captured from a VZ-family VM and the no-clobber rootfs
    // adoption relies on the VZ backend's instance-path early-return; other
    // backends would mutate the forked copy in place or mismatch the kernel.
    if !matches!(
        effective_hypervisor.as_str(),
        "vz" | "virtualization" | "apple-container"
    ) {
        anyhow::bail!(
            "checkpoint fork --boot supports the VZ-family backends only \
             (resolved hypervisor: {effective_hypervisor}); omit --hypervisor \
             to use the platform default"
        );
    }

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

    // The Vz backend needs a real kernel path; work-image boots ship none.
    // Fall back to the cached builder-VM kernel the same way `up` does.
    let vmlinux_placeholder = p
        .instance_rootfs
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."))
        .join("vmlinux");
    let vmlinux_path = super::up::resolve_vz_workload_kernel(
        vmlinux_placeholder.to_str().unwrap_or(""),
        &effective_hypervisor,
    )?;

    let ledger = super::plan_admission::InMemoryNonceLedger::new();
    let admission = super::up::admit_plan_for_boot(super::up::AdmitPlanForBootParams {
        tenant: &tenant,
        vm_name: p.child_vm_name,
        backend_name: &effective_hypervisor,
        rootfs_path: p.instance_rootfs,
        precomputed_image_sha256: None,
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

    if let Some(ctx) = admission.as_ref() {
        super::plan_admission::populate_audit_substrate(
            &mut start_config,
            &ctx.admitted,
            ctx.policy_bundle.as_ref(),
        )?;
    }

    let backend = AnyBackend::from_hypervisor(&effective_hypervisor);
    if let Err(e) = backend.start(&start_config) {
        super::up::emit_failed_if(&admission, "backend-start", &e);
        return Err(e);
    }
    super::up::emit_launched_if(&admission, &effective_hypervisor);

    ui::success(&format!(
        "child VM '{}' booted (hypervisor: {})",
        p.child_vm_name, effective_hypervisor
    ));
    Ok(())
}

/// Read the parent checkpoint's source VM plan and return (cpus, mem_mib).
/// Returns (None, None) when the plan is absent — the caller falls back to
/// global defaults. The parent checkpoint's `vm_name` field names the source VM.
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
        .context("refusing an unaudited fork: audit emitter unavailable")?;
    mvm_hostd::audit::bind::bind_checkpoint_forked(&emitter, &plan, parent, child, child_vm_name)
        .context("refusing an unaudited fork")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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

    // ── vm_is_quiesced / vz_pause_marker_matches_live_pid ────────────────

    /// A VM with no PID files is stopped → quiesced regardless of markers.
    #[test]
    fn stopped_vm_is_quiesced() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.set("MVM_DATA_DIR", tmp.path());
        assert!(
            vm_is_quiesced("no-such-vm-stopped"),
            "stopped VM must be quiesced"
        );
    }

    /// Running VM + matching `vz.paused` marker (pid matches `vz.pid`) → quiesced.
    #[test]
    fn running_with_matching_marker_is_quiesced() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.set("MVM_DATA_DIR", tmp.path());

        let state_dir = mvm_core::config::vm_state_dir("pausedvm");
        std::fs::create_dir_all(&state_dir).unwrap();
        let pid = unsafe { libc::getpid() };
        let pid_str = pid.to_string();
        // Both files carry the same pid — the pause verb writes it this way.
        std::fs::write(state_dir.join("vz.pid"), &pid_str).unwrap();
        std::fs::write(state_dir.join("vz.paused"), &pid_str).unwrap();

        assert!(
            vm_is_quiesced("pausedvm"),
            "running VM with matching pause marker must be quiesced"
        );
    }

    /// Running VM + no `vz.paused` marker → not quiesced.
    #[test]
    fn running_without_marker_is_not_quiesced() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.set("MVM_DATA_DIR", tmp.path());

        let state_dir = mvm_core::config::vm_state_dir("livevm");
        std::fs::create_dir_all(&state_dir).unwrap();
        let pid = unsafe { libc::getpid() };
        std::fs::write(state_dir.join("vz.pid"), pid.to_string()).unwrap();
        // No vz.paused written.

        assert!(
            !vm_is_quiesced("livevm"),
            "running VM with no pause marker must not be quiesced"
        );
    }

    /// Stale marker: `vz.paused` contains a pid that differs from `vz.pid`
    /// (left behind by a crash or a re-launched supervisor) → not quiesced.
    #[test]
    fn running_with_stale_marker_is_not_quiesced() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.set("MVM_DATA_DIR", tmp.path());

        let state_dir = mvm_core::config::vm_state_dir("relaunchedvm");
        std::fs::create_dir_all(&state_dir).unwrap();
        let live_pid = unsafe { libc::getpid() };
        // The marker was stamped with a different (old) pid.
        let old_pid = live_pid.saturating_add(1);
        std::fs::write(state_dir.join("vz.pid"), live_pid.to_string()).unwrap();
        std::fs::write(state_dir.join("vz.paused"), old_pid.to_string()).unwrap();

        assert!(
            !vm_is_quiesced("relaunchedvm"),
            "running VM with a stale pause marker (pid mismatch) must not be quiesced"
        );
    }

    // ── resolve_quiesced_vm_rootfs: missing-rootfs error ─────────────────

    /// When the supervisor-config rootfs path does not exist on disk after the VM
    /// was stopped (Vz/apple_container teardown), the error explains the
    /// pause-based workflow rather than cryptically failing on the path.
    #[test]
    fn missing_rootfs_produces_actionable_error() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.set("MVM_DATA_DIR", tmp.path());
        env.set("MVM_SHARE_DIR", tmp.path());

        let state_dir = mvm_core::config::vm_state_dir("gone-vm");
        std::fs::create_dir_all(&state_dir).unwrap();

        // Write a supervisor config pointing at a rootfs that does NOT exist.
        let cfg = mvm_build::vz::SupervisorConfig {
            name: "gone-vm".into(),
            vm_state_dir: state_dir.to_string_lossy().into_owned(),
            pid_file_name: None,
            kernel: mvm_build::vz::KernelConfig {
                path: "/abs/vmlinux".into(),
                cmdline: "root=/dev/vda".into(),
                initrd_path: None,
            },
            resources: mvm_build::vz::ResourceConfig {
                cpu_count: 1,
                memory_mib: 512,
            },
            disks: vec![mvm_build::vz::DiskConfig {
                id: "rootfs".into(),
                // Points at a path that was deleted on `mvmctl down`.
                path: state_dir.join("rootfs.ext4").to_string_lossy().into_owned(),
                read_only: true,
            }],
            virtio_fs: vec![],
            vsock: mvm_build::vz::VsockConfig {
                ports: vec![],
                socket_dir: state_dir.to_string_lossy().into_owned(),
                host_listen_ports: vec![],
            },
            console_output_path: None,
            network: None,
            balloon: None,
            control_socket_path: None,
            startup_mode: mvm_build::vz::StartupMode::Boot,
            tenant_id: None,
            plan: None,
            bundle: None,
            audit_dir: None,
            gateway_audit_socket: None,
            signing_key_path: None,
        };
        let json = cfg.to_json().unwrap();
        std::fs::write(state_dir.join("supervisor-config.json"), json).unwrap();

        // VM is stopped (no pid file).
        let err = resolve_quiesced_vm_rootfs("gone-vm").expect_err("missing rootfs must error");
        let msg = err.to_string();
        assert!(
            msg.contains("pause") && msg.contains("gone-vm"),
            "error should mention pause workflow and VM name: {msg}"
        );
        assert!(
            msg.contains("vm-full") || msg.contains("vm_full"),
            "error should mention vm-full alternative: {msg}"
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
        env.set("MVM_DATA_DIR", tmp.path());

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
        let out = mvm_backend::base::cow::prepare_instance_rootfs_inner(
            &instance,
            instance.to_str().unwrap(),
        )
        .unwrap();
        assert_eq!(out, instance);
        // File must be untouched.
        assert_eq!(std::fs::read(&instance).unwrap(), b"forked");
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
        })
        .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("--memory"), "error must name --memory: {msg}");
        assert!(
            msg.contains("fs_quick") || msg.contains("fs-quick"),
            "error must name the fs_quick alternative: {msg}"
        );
    }
}
