//! `mvmctl checkpoint create|ls|rm|fork` — immutable fs_quick snapshots of a
//! quiesced VM's rootfs, and copy-on-write forks that branch a new sandbox
//! lineage from one. Capture and fork are filesystem-only here; booting a
//! forked child is a separate `mvmctl up` step.
//!
//! Only the macOS workload backends (Vz / apple_container) materialize a
//! host-side rootfs image, so checkpointing is gated to a VM that has one.

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use clap::Args as ClapArgs;

use mvm_backend::checkpoint::{
    CaptureFsQuickParams, CheckpointStore, ForkParams, capture_fs_quick, fork_checkpoint,
};
use mvm_core::checkpoint::CheckpointId;
use mvm_core::config::vm_state_dir;

use super::Cli;
use super::shared::clap_vm_name;
use crate::ui;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct CheckpointArgs {
    #[command(subcommand)]
    pub command: CheckpointCmd,
}

#[derive(clap::Subcommand, Debug, Clone)]
pub(in crate::commands) enum CheckpointCmd {
    /// Freeze a quiesced VM's rootfs into an immutable fs_quick checkpoint.
    Create {
        /// Name of the VM to checkpoint (must be stopped or paused).
        #[arg(value_parser = clap_vm_name)]
        name: String,
        /// Optional human label recorded on the checkpoint.
        #[arg(long)]
        tag: Option<String>,
        /// Output the sealed checkpoint metadata as JSON.
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
    },
    /// Branch a new sandbox lineage from a checkpoint (materialize only).
    Fork {
        /// Parent checkpoint id.
        id: String,
        /// VM name for the forked child. Defaults to `<id>-fork-<unix>`.
        #[arg(long)]
        new_id: Option<String>,
    },
}

pub(in crate::commands) fn run_checkpoint(_cli: &Cli, args: CheckpointArgs) -> Result<()> {
    match args.command {
        CheckpointCmd::Create { name, tag, json } => create(&name, tag, json),
        CheckpointCmd::Ls { json } => ls(json),
        CheckpointCmd::Rm { id } => rm(&id),
        CheckpointCmd::Fork { id, new_id } => fork(&id, new_id),
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
/// "Quiesced" means the VM is not running, OR it's marked paused in the name
/// registry (a sealed instance snapshot exists). A live VM is refused: an
/// fs_quick checkpoint has no memory, so the rootfs must be in a clean,
/// deterministic state.
///
/// Rootfs location is backend-specific but both macOS workload backends keep
/// the image under `vm_state_dir(name)`:
///   - apple_container clones a per-instance `rootfs.ext4` there;
///   - Vz boots from a supplied path but persists the launch config, whose
///     `rootfs` disk records that path.
fn resolve_quiesced_vm_rootfs(name: &str) -> Result<PathBuf> {
    if vm_is_running(name) {
        bail!("stop or pause VM '{name}' before checkpointing");
    }
    let state_dir = vm_state_dir(name);

    // apple_container per-instance clone — deterministic, present on disk.
    let instance_rootfs = state_dir.join("rootfs.ext4");
    if instance_rootfs.is_file() {
        return Ok(instance_rootfs);
    }

    // Vz persists its full supervisor config at launch; the rootfs disk's
    // path points at the bootable image.
    if let Some(path) = vz_rootfs_from_supervisor_config(&state_dir)? {
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
        ui::success(&format!(
            "{name}: checkpoint {} created (sha256 {})",
            meta.id.as_str(),
            meta.content_sha256
        ));
    }
    Ok(())
}

fn bind_checkpoint_created(name: &str, meta: &mvm_core::checkpoint::CheckpointMeta) {
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
    if let Err(e) = emitter.emit_checkpoint_created(
        &plan,
        meta.id.as_str(),
        "fs_quick",
        &meta.content_sha256,
        name,
    ) {
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
    println!(
        "{:<32} {:<10} {:<20} {:<8} PARENT",
        "ID", "CLASS", "VM", "TAG"
    );
    for m in &metas {
        let class = match m.class {
            mvm_core::checkpoint::CheckpointClass::FsQuick => "fs_quick",
            mvm_core::checkpoint::CheckpointClass::VmFull => "vm_full",
        };
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

fn rm(id: &str) -> Result<()> {
    let id = validated_checkpoint_id(id)?;
    CheckpointStore::open().remove(&id)?;
    ui::success(&format!("checkpoint {} removed", id.as_str()));
    Ok(())
}

fn fork(id: &str, new_id: Option<String>) -> Result<()> {
    let checkpoint = validated_checkpoint_id(id)?;
    let now = now_unix();
    let child_vm_name = new_id.unwrap_or_else(|| format!("{id}-fork-{now}"));
    let dest_dir = vm_state_dir(&child_vm_name);
    let child_id = CheckpointId::new(format!("fork-{child_vm_name}-{now}"));

    let meta = fork_checkpoint(
        &CheckpointStore::open(),
        ForkParams {
            checkpoint: checkpoint.clone(),
            child_id,
            child_vm_name: child_vm_name.clone(),
            dest_dir,
            created_unix: now,
        },
    )
    .with_context(|| format!("forking checkpoint {:?}", checkpoint.as_str()))?;

    // A fork that we can't audit (signer present but emit fails) is refused —
    // an unaudited lineage record would break the chain. A missing plan/signer
    // is best-effort, matching capture.
    bind_checkpoint_forked(&checkpoint, &meta, &child_vm_name)?;

    ui::success(&format!(
        "forked {} -> checkpoint {} (vm '{}')",
        checkpoint.as_str(),
        meta.id.as_str(),
        child_vm_name
    ));
    ui::info(&format!(
        "boot the child with: mvmctl up <flake> --name {child_vm_name}"
    ));
    Ok(())
}

fn bind_checkpoint_forked(
    parent: &CheckpointId,
    child: &mvm_core::checkpoint::CheckpointMeta,
    child_vm_name: &str,
) -> Result<()> {
    let plan = match super::plan_persist::read_plan(&child.vm_name).or_else(|_| {
        // The child VM has no plan yet (not booted); fall back to the parent
        // VM's plan so the lineage entry binds to *some* admitted identity.
        super::plan_persist::read_plan(parent_vm_name_hint(parent))
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
    emitter
        .emit_checkpoint_forked(&plan, parent.as_str(), child.id.as_str(), child_vm_name)
        .context("refusing an unaudited fork")?;
    Ok(())
}

/// The parent checkpoint id has no embedded VM name we can recover cheaply, so
/// this best-effort hint just reuses the checkpoint id as a plan-lookup key.
/// A miss degrades to the no-plan warn path above.
fn parent_vm_name_hint(parent: &CheckpointId) -> &str {
    parent.as_str()
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
}
