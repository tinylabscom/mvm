//! Checkpoint command arguments and rendering.
//!
//! Capture, catalog, restore, and fork operations are owned by the client.

use anyhow::Result;
use clap::Args as ClapArgs;
use serde::Serialize;

use mvm_client::checkpoint::{CaptureRequest, Checkpoints, ForkRequest, RestoreRequest};
use mvm_core::checkpoint::{CheckpointClass, CheckpointDigest, CheckpointId};

use super::Cli;
use super::shared::clap_vm_name;
use crate::ui;

mod lineage;
mod revert;
mod timeline;

pub(in crate::commands) use mvm_client::checkpoint::{ForkIntent, VmFullStepCheckpointer};
pub(in crate::commands) use revert::{
    AdvanceArgs, RevertArgs, RevertImageSource, RevertOutcome, RevertRunImage, run_advance,
    run_revert, run_rewind,
};
pub(in crate::commands) use timeline::{TimelineArgs, run_timeline};

#[cfg(test)]
#[path = "checkpoint_regression.rs"]
mod checkpoint_regression;

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
        /// Defaults to the same auto-detect order as `machine run`.
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
            intent: ForkIntent::Ordinary,
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

/// Validate the id at the client boundary before it becomes a store path.
pub(in crate::commands) fn validated_checkpoint_id(raw: &str) -> Result<CheckpointId> {
    mvm_client::checkpoint::validated_id(raw)
}

fn class_str(class: CheckpointClass) -> &'static str {
    match class {
        CheckpointClass::FsQuick => "fs_quick",
        CheckpointClass::VmFull => "vm_full",
    }
}

fn create(name: &str, tag: Option<String>, json: bool) -> Result<()> {
    let meta = Checkpoints::open().capture(&CaptureRequest {
        name: name.to_string(),
        class: CheckpointClass::FsQuick,
        tag,
    })?;
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

fn create_vm_full(name: &str, tag: Option<String>, json: bool) -> Result<()> {
    let meta = Checkpoints::open().capture(&CaptureRequest {
        name: name.to_string(),
        class: CheckpointClass::VmFull,
        tag,
    })?;
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

/// Capture without rendering an intermediate checkpoint for command workflows.
pub(in crate::commands) fn capture_vm_full_for_machine(
    name: &str,
    tag: Option<String>,
) -> Result<CheckpointId> {
    Checkpoints::open().capture_for_fork(name, tag)
}

fn ls(json: bool) -> Result<()> {
    let metas = Checkpoints::open().list()?;
    if json {
        crate::json_out::emit_json(&metas)?;
        return Ok(());
    }
    if metas.is_empty() {
        ui::info("(no checkpoints)");
        return Ok(());
    }
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
    let d = Checkpoints::open().diff(&id_a, &id_b)?;
    if json {
        crate::json_out::emit_json(&d)?;
        return Ok(());
    }
    use mvm_client::checkpoint::{BlobStatus, LineageRelation};
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
    Checkpoints::open().remove(&id)?;
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

fn restore(id: &str, json: bool) -> Result<()> {
    let report = Checkpoints::open().restore(&RestoreRequest {
        id: validated_checkpoint_id(id)?,
        tenant: super::tenant_resolution::resolve_tenant(None),
    })?;
    if json {
        crate::json_out::emit_json(&report)?;
    } else {
        ui::success(&format!(
            "restored {} into vm '{}'",
            report.id.as_str(),
            report.vm_name
        ));
    }
    Ok(())
}

/// Inputs for [`fork`].
pub(in crate::commands) struct ForkCmdParams<'a> {
    pub id: &'a str,
    pub new_id: Option<String>,
    pub boot: bool,
    pub hypervisor: &'a str,
    pub cpus: Option<u32>,
    pub memory: Option<&'a str>,
    pub declared_secrets: &'a [mvm_core::plan::SecretBinding],
    pub allow_secret_drop: bool,
    pub json: bool,
    pub intent: ForkIntent,
}

/// Parse references, never secret values or release policy.
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
                destinations: Vec::new(),
                approval_required: false,
            })
        })
        .collect()
}

pub(in crate::commands) fn fork(p: ForkCmdParams<'_>) -> Result<()> {
    let report = Checkpoints::open().fork(
        &ForkRequest {
            id: validated_checkpoint_id(p.id)?,
            new_id: p.new_id,
            boot: p.boot,
            hypervisor: p.hypervisor.to_owned(),
            cpus: p.cpus,
            memory: p.memory.map(str::to_owned),
            declared_secrets: p.declared_secrets.to_vec(),
            allow_secret_drop: p.allow_secret_drop,
            intent: p.intent,
            tenant: super::tenant_resolution::resolve_tenant(None),
        },
        &mut mvm_client::entrypoint::CapturedOutput::default(),
    )?;
    if p.json {
        crate::json_out::emit_json(&report)?;
    } else {
        match report.checkpoint.class {
            CheckpointClass::VmFull => {
                let backend = if matches!(
                    mvm_core::checkpoint::vm_full_origin(&report.checkpoint),
                    Some(mvm_core::checkpoint::VmFullOrigin::Hvf)
                ) {
                    "hvf"
                } else {
                    "firecracker"
                };
                ui::success(&format!(
                    "forked {} -> checkpoint {} (vm '{}', auto-booted on {backend})",
                    report.parent_id.as_str(),
                    report.checkpoint.id.as_str(),
                    report.child_vm_name
                ));
            }
            CheckpointClass::FsQuick => {
                if report.booted {
                    ui::success(&format!(
                        "child VM '{}' booted (hypervisor: {})",
                        report.child_vm_name,
                        mvm_client::launch::machine_start::resolve_effective_hypervisor(
                            p.hypervisor
                        )
                    ));
                }
                ui::success(&format!(
                    "forked {} -> checkpoint {} (vm '{}')",
                    report.parent_id.as_str(),
                    report.checkpoint.id.as_str(),
                    report.child_vm_name
                ));
                if !report.booted {
                    ui::info(&format!(
                        "child '{}' materialized at {}; re-run the fork with \
                         --boot to admit and launch a child, or delete the directory to \
                         discard this one",
                        report.child_vm_name,
                        mvm_core::config::vm_state_dir(&report.child_vm_name).display()
                    ));
                }
            }
        }
    }
    Ok(())
}
