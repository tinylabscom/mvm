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
use mvm_runtime::backend::AnyBackend;
use mvm_runtime::checkpoint::{
    CaptureFsQuickParams, CaptureVmFullParams, CheckpointStore, ForkParams, capture_fs_quick,
    capture_vm_full, fork_checkpoint,
};

use super::Cli;
use super::shared::clap_vm_name;
use crate::ui;

mod fork_vm_full;
mod lineage;
mod revert;
mod timeline;
mod vm_state;
use fork_vm_full::fork_vm_full_arm;
pub(in crate::commands) use fork_vm_full::{ForkVmFullArmFcParams, fork_vm_full_arm_fc};
pub(in crate::commands) use lineage::SignedChainAnchor;
pub(in crate::commands) use revert::{
    AdvanceArgs, RevertArgs, RevertImageSource, RevertOutcome, RevertRunImage, run_advance,
    run_revert, run_rewind,
};
pub(in crate::commands) use timeline::{TimelineArgs, run_timeline};
use vm_state::{
    backend_for_vm, ensure_save_restore_supported, resolve_quiesced_vm_rootfs,
    runtime_contract_for_checkpoint, supervisor_config_digest, vm_is_running,
};

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
        /// Declare a secret binding for the forked child (format: `VAR` or
        /// `VAR=ADDRESS`). `VAR` is the name the workload sees; `ADDRESS` is the
        /// keystore address it resolves from, defaulting to `VAR`.
        ///
        /// Declared, never inherited: a fork child carries only what is named
        /// here, so its capability is readable from its own plan. The
        /// destination allow-list lives in the operator's binding
        /// (`mvmctl secret set`), so naming a secret the operator has not bound
        /// grants nothing. Repeatable.
        ///
        /// A vm_full fork always admits a plan, so bindings always apply. An
        /// fs_quick fork admits one only with `--boot`; without it the fork is
        /// a rootfs clone carrying no plan, and there is nothing for a binding
        /// to ride on.
        #[arg(long = "secret")]
        secret: Vec<String>,
        /// Permit the child to omit secret bindings declared by the parent.
        /// Without this flag, every parent binding must be redeclared with
        /// `--secret`, making capability attenuation explicit and reviewable.
        #[arg(long)]
        allow_secret_drop: bool,
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
            secret,
            allow_secret_drop,
            json,
        } => fork(ForkCmdParams {
            id: &id,
            new_id,
            boot,
            hypervisor: &hypervisor,
            cpus,
            memory: memory.as_deref(),
            declared_secrets: &parse_declared_secrets(&secret)?,
            allow_secret_drop,
            json,
        }),
        CheckpointCmd::Diff { a, b, json } => diff(&a, &b, json),
        CheckpointCmd::Verify { id, json } => lineage::verify(&id, json),
    }
}

pub(in crate::commands) fn run_save(_cli: &Cli, args: SaveArgs) -> Result<()> {
    create_vm_full(&args.name, args.tag, args.json)
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
            grants: admitted_grants_for(name)?,
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

/// Inputs for [`capture_vm_full_for_running_vm`]. Grouped so the call site
/// reads as one value rather than a positional list.
struct CaptureVmFullArgs<'a> {
    name: &'a str,
    state_dir: &'a std::path::Path,
    store: &'a CheckpointStore,
    backend: &'a AnyBackend,
    id: CheckpointId,
    tag: Option<String>,
    created_unix: u64,
}

/// Capture the vm_full triple for the running VM through the pause/save/resume
/// control of the backend that owns it. The caller has already verified the VM
/// is running and that the backend advertises save/restore.
fn capture_vm_full_for_running_vm(
    args: CaptureVmFullArgs<'_>,
) -> Result<mvm_core::checkpoint::CheckpointMeta> {
    let (runtime_source_policy, runtime_overlay_version) =
        runtime_contract_for_checkpoint(args.name)?;
    let control = args.backend.vm_full_control(args.name).ok_or_else(|| {
        anyhow::anyhow!(
            "backend '{}' has no full-VM capture control for '{}'",
            args.backend.name(),
            args.name
        )
    })?;
    let params = CaptureVmFullParams {
        id: args.id,
        vm_name: args.name.to_string(),
        supervisor_config_digest: supervisor_config_digest(args.state_dir),
        runtime_source_policy,
        runtime_overlay_version,
        // Backends that drive their VMM through a supervisor config (HVF) carry
        // it into the checkpoint: a restore has to rebuild the launch shape the
        // capture froze, and every stop reaps the live copy. Firecracker returns
        // None and the blob is simply absent.
        supervisor_config_src: control.supervisor_config_path()?,
        tag: args.tag,
        created_unix: args.created_unix,
        retain_paused: false,
        grants: admitted_grants_for(args.name)?,
    };
    capture_vm_full(args.store, params, control.as_ref())
}

/// `mvmctl checkpoint create --class vm-full <vm>`: capture a RUNNING VM's
/// memory + rootfs in one pause window. The inverse of fs_quick — a vm_full
/// checkpoint carries memory, so the VM must be live.
fn create_vm_full(name: &str, tag: Option<String>, json: bool) -> Result<()> {
    let backend = backend_for_vm(name);
    ensure_save_restore_supported("save", &backend)?;
    if !vm_is_running(name) {
        bail!("checkpoint --class vm-full requires a running VM; start '{name}' first");
    }
    let state_dir = vm_state_dir(name);
    let store = CheckpointStore::open();
    let now = now_unix();
    let id = CheckpointId::new(format!("ckpt-{name}-{now}"));

    let meta = capture_vm_full_for_running_vm(CaptureVmFullArgs {
        name,
        state_dir: &state_dir,
        store: &store,
        backend: &backend,
        id,
        tag,
        created_unix: now,
    })
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

/// Capture a vm_full checkpoint of a running machine and return its id, without
/// emitting human output. Used by `mvmctl machine fork` so the intermediate
/// checkpoint can be created, branched, and (optionally) cleaned up by the caller.
pub(in crate::commands) fn capture_vm_full_for_machine(
    name: &str,
    tag: Option<String>,
) -> Result<CheckpointId> {
    let backend = backend_for_vm(name);
    ensure_save_restore_supported("fork", &backend)?;
    if !vm_is_running(name) {
        bail!("machine fork requires a running VM; start '{name}' first");
    }
    let state_dir = vm_state_dir(name);
    let store = CheckpointStore::open();
    let now = now_unix();
    let id = CheckpointId::new(format!("ckpt-{name}-{now}"));

    let meta = capture_vm_full_for_running_vm(CaptureVmFullArgs {
        name,
        state_dir: &state_dir,
        store: &store,
        backend: &backend,
        id: id.clone(),
        tag,
        created_unix: now,
    })
    .with_context(|| format!("capturing vm_full checkpoint of {name:?}"))?;

    bind_checkpoint_created(name, &meta);
    Ok(id)
}

/// The permission set `name` was admitted under, read off its persisted plan so
/// the checkpoint can seal it and a later restore can bound a child against it.
///
/// Degrades the same way [`bind_checkpoint_created`] does, and safely for the
/// same reason: a VM with no readable plan also gets no chain-signed
/// `checkpoint.created` entry, so the record it produces has nothing to anchor
/// its content-address and every fork of it is refused before the grants are
/// consulted at all.
fn admitted_grants_for(name: &str) -> Result<Option<mvm_contract::grants::Grants>> {
    let path = super::plan_persist::plan_path(name)?;
    // A VM that never had a plan legitimately has no grant to seal, and that is
    // the only tolerated absence. Every other failure — a corrupt plan, one at
    // loose permissions, one that will not parse — is refused rather than
    // resolved to `None`, because `None` is not "unknown" here: for CPU and wall
    // clock it means *unbounded*, so swallowing the error would widen the record
    // silently and hand every child restored from it that widening.
    if !path.exists() {
        return Ok(None);
    }
    let plan = super::plan_persist::read_plan_at(&path).with_context(|| {
        format!(
            "reading {name}'s admitted plan to seal its grants into the checkpoint; \
             refusing to seal a checkpoint whose permission set cannot be determined"
        )
    })?;
    Ok(plan.grants)
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
    let emitter = match super::audit_chain::AuditEmitter::new(signer.signing)
        .map(|e| e.with_receipts().with_decisions())
    {
        Ok(Ok(e)) => e,
        Ok(Err(e)) | Err(e) => {
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

/// The id of a live or hibernated session whose resume point is `digest`, if
/// any. Delegates the pin rule to `mvm_runtime::agent_session::pinning_session`
/// — the one place that decides whether a session's resume point still needs
/// holding — so `rm` can tell the operator what is holding the checkpoint it
/// refused to remove without re-deriving that rule here.
fn session_pinning_checkpoint(
    digest: &CheckpointDigest,
) -> Result<Option<mvm_contract::protocol::agent_session::AgentSessionId>> {
    let sessions = mvm_runtime::agent_session::AgentSessionStore::open();
    mvm_runtime::agent_session::pinning_session(&sessions, digest).context("listing agent sessions")
}

/// `mvmctl vm checkpoint rm <id>`: delete a checkpoint by id.
///
/// Refuses when the checkpoint is still the resume point of a live or
/// hibernated agent session — the same guard the automated sweep in
/// `mvmctl cache prune` applies, closing the manual door to the identical
/// data-loss class: an operator deleting by hand can otherwise make a parked
/// session permanently unresumable exactly as an unguarded sweep could.
/// `rm` has no force/override flag, so this refusal is unconditional; the
/// operator must close the session first.
fn rm(id: &str, json: bool) -> Result<()> {
    let id = validated_checkpoint_id(id)?;
    let store = CheckpointStore::open();
    if let Ok(meta) = store.read_meta(&id)
        && let Some(session_id) = session_pinning_checkpoint(&meta.meta_digest)?
    {
        bail!(
            "cannot remove checkpoint '{}': it is the resume point for agent session '{}'; \
             close that session before removing the checkpoint",
            id.as_str(),
            session_id.as_str()
        );
    }
    store.remove(&id)?;
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

/// JSON shape of a completed same-identity restore.
#[derive(Serialize)]
struct CheckpointRestoreJson<'a> {
    schema_version: u8,
    action: &'static str,
    id: &'a CheckpointId,
    vm_name: &'a str,
}

/// `mvmctl vm checkpoint restore <id>`: same-identity resume of a vm_full
/// checkpoint.
///
/// The checkpoint is verified against the signed audit chain before a single
/// byte is cloned, so a restore can never bring back a record that was edited
/// after it was audited. The VM comes back under its own name from its own
/// clone of the sealed content — the immutable checkpoint bytes are never
/// booted against, because a resumed guest writes through to its rootfs.
fn restore(id: &str, json: bool) -> Result<()> {
    let id = validated_checkpoint_id(id)?;
    let store = CheckpointStore::open();
    let meta = store
        .read_meta(&id)
        .with_context(|| format!("reading checkpoint {}", id.as_str()))?;
    if meta.class != CheckpointClass::VmFull {
        bail!(
            "checkpoint '{}' is class fs_quick; restore applies to vm_full checkpoints \
             (fork an fs_quick checkpoint instead)",
            id.as_str()
        );
    }
    if vm_is_running(&meta.vm_name) {
        bail!(
            "cannot restore into '{}': it is still running; stop it first",
            meta.vm_name
        );
    }
    let restorer = mvm_runtime::checkpoint::vm_full_restorer_for(&meta)?;
    let anchor = SignedChainAnchor::load()
        .context("loading the signed audit chain to verify the restore source")?;
    mvm_runtime::checkpoint::restore_checkpoint(
        &store,
        mvm_runtime::checkpoint::RestoreParams {
            checkpoint: id.clone(),
            target_vm: meta.vm_name.clone(),
        },
        restorer.as_ref(),
        &anchor,
    )
    .with_context(|| format!("restoring checkpoint {}", id.as_str()))?;

    if json {
        crate::json_out::emit_json(&CheckpointRestoreJson {
            schema_version: 1,
            action: "restore",
            id: &id,
            vm_name: &meta.vm_name,
        })?;
    } else {
        ui::success(&format!(
            "restored {} into vm '{}'",
            id.as_str(),
            meta.vm_name
        ));
    }
    Ok(())
}

/// Inputs for [`fork`].
struct ForkCmdParams<'a> {
    id: &'a str,
    new_id: Option<String>,
    boot: bool,
    hypervisor: &'a str,
    cpus: Option<u32>,
    memory: Option<&'a str>,
    declared_secrets: &'a [mvm_core::plan::SecretBinding],
    allow_secret_drop: bool,
    json: bool,
}

/// Parse `--secret` values into plan bindings.
///
/// `VAR` binds the workload-visible name to the keystore address of the same
/// name; `VAR=ADDRESS` separates them. Nothing here contacts the keystore or
/// resolves a value — a binding is a reference, and an address that names no
/// secret simply fails to resolve later rather than granting anything.
pub(in crate::commands) fn parse_declared_secrets(
    values: &[String],
) -> Result<Vec<mvm_core::plan::SecretBinding>> {
    values
        .iter()
        .map(|raw| {
            let (var, address) = match raw.split_once('=') {
                Some((var, address)) => (var.trim(), address.trim()),
                None => (raw.trim(), raw.trim()),
            };
            if var.is_empty() || address.is_empty() {
                anyhow::bail!(
                    "invalid --secret {raw:?}: expected VAR or VAR=ADDRESS with both non-empty"
                );
            }
            Ok(mvm_core::plan::SecretBinding {
                name: var.to_string(),
                source: mvm_core::plan::SecretSource::Keystore {
                    address: address.to_string(),
                },
            })
        })
        .collect()
}

fn fork(p: ForkCmdParams<'_>) -> Result<()> {
    let ForkCmdParams {
        id,
        new_id,
        boot,
        hypervisor,
        cpus,
        memory,
        declared_secrets,
        allow_secret_drop,
        json,
    } = p;
    let checkpoint = validated_checkpoint_id(id)?;
    let store = CheckpointStore::open();
    // Pick the fork arm by the parent's class: vm_full carries memory and must
    // restore through the vm_full fork arm (which auto-boots the child); fs_quick
    // is a rootfs-only clone that the operator can optionally boot with `--boot`.
    let parent = store.read_meta(&checkpoint)?;
    match parent.class {
        CheckpointClass::VmFull => {
            fork_vm_full_arm(fork_vm_full::ForkVmFullArmParams {
                store: &store,
                checkpoint: &checkpoint,
                new_id,
                cpus_override: cpus,
                memory_override: memory,
                json,
                // No CLI surface declares bindings yet, so a fork declares
                // none — exactly the prior behaviour.
                declared_secrets,
                allow_secret_drop,
            })
        }
        CheckpointClass::FsQuick => fork_fs_quick_arm(ForkFsQuickArmParams {
            store: &store,
            checkpoint: &checkpoint,
            new_id,
            boot,
            hypervisor,
            cpus_override: cpus,
            memory_override: memory,
            declared_secrets,
            allow_secret_drop,
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
    /// Declared for the child when `--boot` admits one. A fs_quick fork without
    /// `--boot` admits no plan, so there is nothing for these to ride on.
    declared_secrets: &'a [mvm_core::plan::SecretBinding],
    allow_secret_drop: bool,
    json: bool,
}

/// fs_quick fork: CoW-clone the rootfs into a new VM state dir. With
/// `--boot`, also admits and launches the child as a fresh VM, adopting the
/// materialized rootfs without clobbering it (the no-clobber seam in
/// `prepare_instance_rootfs` returns early when source == instance path).
fn fork_fs_quick_arm(p: ForkFsQuickArmParams<'_>) -> Result<()> {
    if !p.boot && !p.declared_secrets.is_empty() {
        bail!(
            "--secret requires --boot for an fs_quick fork because an unbooted clone has no child plan"
        );
    }
    let child_tenant = super::tenant_resolution::resolve_tenant(None);
    if p.boot {
        validate_fork_secret_policy(
            p.checkpoint,
            p.store,
            &child_tenant,
            p.declared_secrets,
            p.allow_secret_drop,
        )?;
    }
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
    bind_checkpoint_forked(
        p.checkpoint,
        &meta,
        &child_vm_name,
        p.store,
        p.declared_secrets,
        &child_tenant,
    )?;

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
            declared_secrets: p.declared_secrets,
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
    /// Declared for this child's plan. A fs_quick fork admits a plan only under
    /// `--boot`, which is this function, so this is where they land.
    declared_secrets: &'a [mvm_core::plan::SecretBinding],
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
    AnyBackend::require_hypervisor_selectable(&effective_hypervisor)?;
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
        network_mode: parent_network_mode(p.parent_checkpoint, p.store),
        tenant: &tenant,
        vm_name: p.child_vm_name,
        backend_name: &effective_hypervisor,
        rootfs_path: p.instance_rootfs,
        precomputed_image_sha256: None,
        boot_artifact_identity: None,
        cpus,
        mem_mib,
        seccomp_tier: mvm_core::plan::PlanSeccompTier::Standard,
        secret_release: crate::commands::vm::managed_secrets::secret_release_for_bindings(
            p.declared_secrets,
        ),
        secrets: p.declared_secrets.to_vec(),
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
        grants: None,
        backend_kind: None,
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

/// The transport a forked or restored child is admitted with.
///
/// Inherits the parent's, because a child that boots from a parent's memory
/// and rootfs is continuing that workload rather than starting a new one: if
/// the parent was admitted onto the raw-IP tunnel, its child is on it too.
/// Falls back to what a fresh launch of the same shape would derive when the
/// parent's plan cannot be read, which is the same shape `parent_plan_resources`
/// already takes for cpus and memory.
///
/// Not `NetworkMode::None` on the fallback: that value means the guest has no
/// broker at all, and claiming it for a child that is about to be given one is
/// the defect this function exists to avoid rather than a safe default.
fn parent_network_mode(
    parent_checkpoint: &CheckpointId,
    store: &CheckpointStore,
) -> mvm_contract::plan::NetworkMode {
    let fallback = crate::commands::machine::preflight_network();
    let Ok(parent_meta) = store.read_meta(parent_checkpoint) else {
        return fallback;
    };
    let Ok(plan) = super::plan_persist::read_plan(&parent_meta.vm_name) else {
        return fallback;
    };
    plan.network_mode
}

/// The secret binding *names* the parent was admitted with, for diagnostics.
///
/// A fork child is admitted with no secrets, so every binding the parent held
/// is dropped. Without a diagnostic that presents as an upstream that stopped
/// answering rather than as a capability the child never got.
///
/// Names only: `SecretBinding` carries a name and a source reference, never a
/// value, and only the name is echoed.
///
/// An unreadable parent plan yields an empty set, matching the sibling
/// inheritance helpers. Absence of a plan file is not evidence the parent held
/// no secrets, so silence here means "unknown", not "none".
fn parent_secret_names(parent_checkpoint: &CheckpointId, store: &CheckpointStore) -> Vec<String> {
    let Ok(parent_meta) = store.read_meta(parent_checkpoint) else {
        return Vec::new();
    };
    let Ok(plan) = super::plan_persist::read_plan(&parent_meta.vm_name) else {
        return Vec::new();
    };
    plan.secrets.into_iter().map(|b| b.name).collect()
}

fn dropped_parent_secret_names(
    parent_names: &[String],
    declared: &[mvm_core::plan::SecretBinding],
) -> Vec<String> {
    let declared_names = declared
        .iter()
        .map(|binding| binding.name.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    parent_names
        .iter()
        .filter(|name| !declared_names.contains(name.as_str()))
        .cloned()
        .collect()
}

fn enforce_secret_attenuation(dropped: &[String], allow_secret_drop: bool) -> Result<()> {
    if dropped.is_empty() {
        return Ok(());
    }
    if !allow_secret_drop {
        bail!(
            "fork child would drop parent secret bindings: {}. Redeclare each required binding with --secret NAME, or pass --allow-secret-drop to attenuate them intentionally",
            dropped.join(", ")
        );
    }
    Ok(())
}

/// Validate a fork child's complete secret capability before any child boots.
///
/// Every declared keystore address must exist in the child's tenant. Parent
/// bindings are never inherited; omitting one is an explicit attenuation and
/// therefore requires `--allow-secret-drop`.
pub(super) fn validate_fork_secret_policy(
    parent_checkpoint: &CheckpointId,
    store: &CheckpointStore,
    tenant: &str,
    declared: &[mvm_core::plan::SecretBinding],
    allow_secret_drop: bool,
) -> Result<()> {
    let binding_store = mvm_hostd::keyholder::FileBindingStore::default_location()
        .context("opening the child tenant's secret-binding store")?;
    resolve_fork_secret_audit(tenant, declared, &binding_store)?;

    let dropped =
        dropped_parent_secret_names(&parent_secret_names(parent_checkpoint, store), declared);
    enforce_secret_attenuation(&dropped, allow_secret_drop)?;
    if !dropped.is_empty() {
        tracing::warn!(
            secrets = %dropped.join(", "),
            count = dropped.len(),
            "fork child intentionally drops parent secret bindings"
        );
    }
    Ok(())
}

fn resolve_fork_secret_audit(
    tenant: &str,
    declared: &[mvm_core::plan::SecretBinding],
    bindings: &dyn mvm_hostd::keyholder::BindingStore,
) -> Result<Vec<mvm_hostd::audit::bind::CheckpointForkSecretBinding>> {
    use mvm_core::plan::SecretSource;

    declared
        .iter()
        .filter_map(|binding| match &binding.source {
            SecretSource::Keystore { address } => Some((binding, address)),
            SecretSource::External { .. } => None,
        })
        .map(|(binding, address)| {
            let metadata = bindings
                .get(tenant, address)
                .with_context(|| format!("reading binding {address:?} for tenant {tenant:?}"))?
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "secret {address:?} has no binding in child tenant {tenant:?}; bind it for that tenant before forking"
                    )
                })?;
            Ok(mvm_hostd::audit::bind::CheckpointForkSecretBinding {
                name: binding.name.clone(),
                allowed_hosts: metadata.allowed_hosts,
            })
        })
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
    declared_secrets: &[mvm_core::plan::SecretBinding],
    child_tenant: &str,
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
    let binding_store = mvm_hostd::keyholder::FileBindingStore::default_location()
        .context("opening the child tenant's secret-binding store for fork audit")?;
    let secret_bindings =
        resolve_fork_secret_audit(child_tenant, declared_secrets, &binding_store)?;
    mvm_hostd::audit::bind::bind_checkpoint_forked(
        &emitter,
        &plan,
        parent,
        child,
        child_vm_name,
        &secret_bindings,
    )
    .context("refusing an unaudited fork")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::vm_state::{fc_pause_marker_matches_live_pid, vm_is_quiesced};
    use super::*;
    use mvm_contract::ir::AuthType;
    use mvm_core::plan::{SecretBinding, SecretSource};
    use mvm_hostd::keyholder::{BindingStore, FileBindingStore, SecretBindingMeta};
    use mvm_runtime::checkpoint::{CheckpointChainAnchor, verify_lineage};

    fn secret_binding(name: &str, address: &str) -> SecretBinding {
        SecretBinding {
            name: name.into(),
            source: SecretSource::Keystore {
                address: address.into(),
            },
        }
    }

    #[test]
    fn dropped_parent_secrets_excludes_explicit_redeclarations() {
        let parent = vec!["API_KEY".to_string(), "DB_KEY".to_string()];
        let declared = vec![secret_binding("API_KEY", "child-api")];

        assert_eq!(
            dropped_parent_secret_names(&parent, &declared),
            vec!["DB_KEY"]
        );
    }

    #[test]
    fn secret_attenuation_requires_explicit_drop_permission() {
        let dropped = vec!["DB_KEY".to_string()];

        let error = enforce_secret_attenuation(&dropped, false).unwrap_err();
        assert!(error.to_string().contains("--allow-secret-drop"));
        assert!(enforce_secret_attenuation(&dropped, true).is_ok());
        assert!(enforce_secret_attenuation(&[], false).is_ok());
    }

    #[test]
    fn fork_secret_audit_resolves_only_child_tenant_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let store = FileBindingStore::with_dir(dir.path());
        store
            .put(
                "child-tenant",
                "api-address",
                &SecretBindingMeta {
                    auth_type: AuthType::Bearer,
                    allowed_hosts: vec!["api.example.com".into()],
                    sigv4: None,
                    provider: Some("catalog-provider".into()),
                },
            )
            .unwrap();
        let declared = vec![secret_binding("API_KEY", "api-address")];

        let audit = resolve_fork_secret_audit("child-tenant", &declared, &store).unwrap();
        assert_eq!(audit.len(), 1);
        assert_eq!(audit[0].name, "API_KEY");
        assert_eq!(audit[0].allowed_hosts, vec!["api.example.com"]);
        assert!(resolve_fork_secret_audit("other-tenant", &declared, &store).is_err());
    }

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
    fn bare_secret_name_binds_var_and_address_alike() {
        let got = parse_declared_secrets(&["STRIPE_KEY".to_string()]).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].name, "STRIPE_KEY");
        assert_eq!(
            got[0].source,
            mvm_core::plan::SecretSource::Keystore {
                address: "STRIPE_KEY".to_string()
            }
        );
    }

    #[test]
    fn var_equals_address_separates_the_two() {
        let got = parse_declared_secrets(&["DB_PASSWORD=prod/db/password".to_string()]).unwrap();
        assert_eq!(got[0].name, "DB_PASSWORD");
        assert_eq!(
            got[0].source,
            mvm_core::plan::SecretSource::Keystore {
                address: "prod/db/password".to_string()
            }
        );
    }

    /// An empty half is a typo, not an empty binding: `=addr` names no variable
    /// and `VAR=` names no address, and either would admit a binding that can
    /// never resolve.
    #[test]
    fn an_empty_half_is_refused() {
        for bad in ["", "=addr", "VAR=", "  =  "] {
            assert!(
                parse_declared_secrets(&[bad.to_string()]).is_err(),
                "{bad:?} must be refused"
            );
        }
    }

    #[test]
    fn declaring_nothing_parses_to_nothing() {
        assert!(parse_declared_secrets(&[]).unwrap().is_empty());
    }

    /// The release policy is derived from the set, not defaulted. A plan that
    /// listed bindings under the default `None` would declare capability it
    /// could never release.
    #[test]
    fn declared_bindings_make_the_release_policy_plan_bound() {
        use crate::commands::vm::managed_secrets::secret_release_for_bindings;

        let none = secret_release_for_bindings(&[]);
        assert_eq!(none, mvm_core::plan::SecretReleasePolicy::None);

        let declared = parse_declared_secrets(&["TOKEN".to_string()]).unwrap();
        assert_eq!(
            secret_release_for_bindings(&declared),
            mvm_core::plan::SecretReleasePolicy::PlanBound
        );
    }

    #[test]
    fn parent_secret_names_lists_the_parent_bindings_by_name() {
        use mvm_contract::plan::{SecretBinding, SecretSource};
        use mvm_core::checkpoint::{CheckpointClass, CheckpointId};
        use mvm_core::plan::test_support::PlanFixture;

        let mut env = mvm_core::util::test_env::TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.isolate_mvm_home(tmp.path());

        let mut plan = PlanFixture::new()
            .tenant("local")
            .plan_id("parent-plan")
            .build();
        plan.secrets = vec![
            SecretBinding {
                name: "STRIPE_KEY".to_string(),
                source: SecretSource::Keystore {
                    address: "kv/stripe".to_string(),
                },
            },
            SecretBinding {
                name: "DB_PASSWORD".to_string(),
                source: SecretSource::External {
                    provider: "vault".to_string(),
                    path: "secret/db".to_string(),
                },
            },
        ];
        mvm_hostd::audit::plan_persist::write_plan("secretful-parent", &plan).unwrap();

        let store = mvm_runtime::checkpoint::CheckpointStore::open();
        let meta = mvm_core::checkpoint::CheckpointMeta::builder(
            CheckpointId::new("ckpt-secretful"),
            CheckpointClass::FsQuick,
            "secretful-parent",
        )
        .content(vec![])
        .supervisor_config_digest("d")
        .created_unix(1)
        .build();
        store.write_meta(&meta).unwrap();

        assert_eq!(
            parent_secret_names(&meta.id, &store),
            vec!["STRIPE_KEY".to_string(), "DB_PASSWORD".to_string()],
        );
    }

    /// The source half of a binding names a provider and an address. Neither is
    /// a secret value, but neither is echoed either: the diagnostic is names.
    #[test]
    fn parent_secret_names_echoes_no_source_addresses() {
        use mvm_contract::plan::{SecretBinding, SecretSource};
        use mvm_core::checkpoint::{CheckpointClass, CheckpointId};
        use mvm_core::plan::test_support::PlanFixture;

        let mut env = mvm_core::util::test_env::TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.isolate_mvm_home(tmp.path());

        let mut plan = PlanFixture::new().tenant("local").plan_id("p").build();
        plan.secrets = vec![SecretBinding {
            name: "TOKEN".to_string(),
            source: SecretSource::External {
                provider: "vault".to_string(),
                path: "secret/very/specific/path".to_string(),
            },
        }];
        mvm_hostd::audit::plan_persist::write_plan("p-vm", &plan).unwrap();

        let store = mvm_runtime::checkpoint::CheckpointStore::open();
        let meta = mvm_core::checkpoint::CheckpointMeta::builder(
            CheckpointId::new("ckpt-src"),
            CheckpointClass::FsQuick,
            "p-vm",
        )
        .content(vec![])
        .supervisor_config_digest("d")
        .created_unix(1)
        .build();
        store.write_meta(&meta).unwrap();

        let names = parent_secret_names(&meta.id, &store);
        assert_eq!(names, vec!["TOKEN".to_string()]);
        let joined = names.join(", ");
        assert!(!joined.contains("vault"), "provider leaked: {joined}");
        assert!(!joined.contains("secret/"), "address leaked: {joined}");
    }

    /// A parent whose plan cannot be read is "unknown", not "held none" — the
    /// helper stays quiet rather than asserting the parent was secretless.
    #[test]
    fn parent_secret_names_is_empty_when_the_parent_plan_is_unreadable() {
        use mvm_core::checkpoint::{CheckpointClass, CheckpointId};

        let mut env = mvm_core::util::test_env::TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.isolate_mvm_home(tmp.path());

        let store = mvm_runtime::checkpoint::CheckpointStore::open();
        let meta = mvm_core::checkpoint::CheckpointMeta::builder(
            CheckpointId::new("ckpt-planless"),
            CheckpointClass::FsQuick,
            "planless-vm",
        )
        .content(vec![])
        .supervisor_config_digest("d")
        .created_unix(1)
        .build();
        store.write_meta(&meta).unwrap();

        assert!(parent_secret_names(&meta.id, &store).is_empty());
    }

    /// The manual deletion door (`checkpoint rm`) is a second place the same
    /// data-loss class Task 1 closed for the automated sweep can happen: an
    /// operator removing by id, with no pin check, can make a parked session
    /// permanently unresumable. `rm` must refuse and name the session.
    #[test]
    fn rm_refuses_a_checkpoint_pinned_by_a_parked_session() {
        use mvm_contract::protocol::agent_session::AgentSessionId;
        use mvm_core::checkpoint::{CheckpointClass, CheckpointId};
        use mvm_runtime::agent_session::{AgentSessionRecord, AgentSessionStore, SandboxResidency};

        let mut env = mvm_core::util::test_env::TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.isolate_mvm_home(tmp.path());

        let store = mvm_runtime::checkpoint::CheckpointStore::open();
        let meta = mvm_core::checkpoint::CheckpointMeta::builder(
            CheckpointId::new("ckpt-pinned"),
            CheckpointClass::FsQuick,
            "vm-alpha",
        )
        .content(vec![])
        .supervisor_config_digest("d")
        .created_unix(1)
        .build();
        store.write_meta(&meta).unwrap();

        let sessions = AgentSessionStore::open();
        sessions
            .write(&AgentSessionRecord {
                session_id: AgentSessionId::parse("sess-parked").unwrap(),
                generation: 1,
                state: SandboxResidency::Hibernated,
                members: vec!["vm-alpha".to_string()],
                parent_checkpoint: Some(meta.meta_digest.clone()),
                created_unix: 0,
                updated_unix: 0,
                journal_cursor: 0,
                approval_head: None,
                storage_tier: None,
                park_reason: None,
            })
            .unwrap();

        let err = rm("ckpt-pinned", false).unwrap_err();
        assert!(
            err.to_string().contains("sess-parked"),
            "refusal must name the session holding the checkpoint: {err}"
        );
        assert!(
            store.read_meta(&CheckpointId::new("ckpt-pinned")).is_ok(),
            "the checkpoint must still be on disk after the refusal"
        );
    }

    #[test]
    fn rm_removes_a_checkpoint_no_session_pins() {
        use mvm_core::checkpoint::{CheckpointClass, CheckpointId};

        let mut env = mvm_core::util::test_env::TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.isolate_mvm_home(tmp.path());

        let store = mvm_runtime::checkpoint::CheckpointStore::open();
        let meta = mvm_core::checkpoint::CheckpointMeta::builder(
            CheckpointId::new("ckpt-unpinned"),
            CheckpointClass::FsQuick,
            "vm-alpha",
        )
        .content(vec![])
        .supervisor_config_digest("d")
        .created_unix(1)
        .build();
        store.write_meta(&meta).unwrap();

        rm("ckpt-unpinned", false).unwrap();
        assert!(
            store
                .read_meta(&CheckpointId::new("ckpt-unpinned"))
                .is_err(),
            "a checkpoint no session pins must still be removable"
        );
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
    /// as a supervisor-config-bearing capture).
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
            image_tag: String::new(),
            source: String::new(),
            built_at: String::new(),
            protocol_version: 0,
            generator_rev: String::new(),
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
            image_tag: String::new(),
            source: String::new(),
            built_at: String::new(),
            protocol_version: 0,
            generator_rev: String::new(),
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
            image_tag: String::new(),
            source: String::new(),
            built_at: String::new(),
            protocol_version: 0,
            generator_rev: String::new(),
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
