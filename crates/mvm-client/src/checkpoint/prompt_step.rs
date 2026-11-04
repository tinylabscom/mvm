//! Full-VM checkpoint capture for an agent prompt step.

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use mvm_core::checkpoint::{CheckpointId, CheckpointMeta};
use mvm_core::config::{machine_state_dir, vm_state_dir};
use mvm_core::vm_backend::SnapshotCapability;
use mvm_hostd::audit::{emitter::AuditEmitter, host_keypair, plan_persist};
use mvm_runtime::backend::AnyBackend;

use crate::agent_prompt::{StepCapture, StepCheckpointer};
use crate::checkpoint::{CaptureVmFullParams, CheckpointStore, WorkspaceVolume, capture_vm_full};
use crate::volume::{AccessMode, LocalVolumeService, VolumeService};

/// Captures a prompt step using the running machine's backend.
pub struct VmFullStepCheckpointer;

impl StepCheckpointer for VmFullStepCheckpointer {
    fn capture(&self, step: StepCapture<'_>) -> Result<CheckpointMeta> {
        let name = step.vm_name;
        let backend = AnyBackend::for_started_vm(name).unwrap_or_else(AnyBackend::auto_select);
        let available = backend.snapshot_capability();
        if !available.satisfies(SnapshotCapability::SaveRestore) {
            bail!(
                "vm checkpoint a prompt step requires memory-snapshot support, but backend '{}' reports snapshot tier '{}' on this host",
                backend.name(),
                available.label()
            );
        }
        if !mvm_runtime::checkpoint::vm_is_running(name) {
            bail!("a prompt step checkpoint requires a running VM; '{name}' is not running");
        }
        let machine_dir = machine_state_dir(name);
        let _input_lock = crate::input_journal::lock(&machine_dir)?;
        let input_cursor = crate::input_journal::cursor(&machine_dir)?;
        let store = CheckpointStore::open();
        let state_dir = vm_state_dir(name);
        let runtime = super::read_runtime_meta(name)?;
        let control = backend.vm_full_control(name).ok_or_else(|| {
            anyhow::anyhow!(
                "backend '{}' has no full-VM capture control for '{}'",
                backend.name(),
                name
            )
        })?;
        let admitted = super::admitted::admitted_capture_for(name)?;
        let mut workspaces: Vec<_> = LocalVolumeService::new()
            .list_attachments(name)
            .with_context(|| format!("listing the volumes registered for {name:?}"))?
            .into_iter()
            .filter(|attachment| {
                attachment.access == AccessMode::ReadWrite && attachment.host_snapshot.is_some()
            })
            .filter_map(|attachment| {
                let image = PathBuf::from(attachment.host_path);
                image.is_file().then_some(WorkspaceVolume {
                    name: attachment.volume,
                    image,
                })
            })
            .collect();
        workspaces.sort_by(|a, b| a.name.cmp(&b.name));
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let cursor = step.session.journal_cursor;
        let meta = capture_vm_full(
            &store,
            CaptureVmFullParams {
                id: CheckpointId::new(format!("ckpt-{name}-prompt-{cursor}-{now}")),
                vm_name: name.to_string(),
                supervisor_config_digest: mvm_core::crypto::image_verify::sha256_file(
                    &state_dir.join("supervisor-config.json"),
                )
                .unwrap_or_default(),
                runtime_overlay_version: runtime
                    .as_ref()
                    .and_then(|meta| meta.runtime_overlay_version.clone()),
                runtime_launch_binding: runtime.and_then(|meta| meta.runtime_launch_binding),
                supervisor_config_src: control.supervisor_config_path()?,
                tag: Some(format!("prompt-step-{cursor}")),
                created_unix: now,
                retain_paused: false,
                grants: admitted.grants,
                parent: step.parent,
                session: Some(step.session),
                workspace_volumes: workspaces,
                key_domain: admitted.key_domain,
            },
            control.as_ref(),
        )
        .with_context(|| format!("capturing the prompt step checkpoint of {name:?}"))?;
        let meta = meta.with_machine_input_cursor(input_cursor);
        store
            .write_meta(&meta)
            .context("sealing the machine input cursor into checkpoint metadata")?;
        bind_created(name, &meta);
        Ok(meta)
    }
}

fn bind_created(name: &str, meta: &CheckpointMeta) {
    let result = (|| -> Result<()> {
        let plan = plan_persist::read_plan(name)?;
        let signer = host_keypair::load_or_init()?;
        let emitter = AuditEmitter::new(signer.signing)?
            .with_receipts()
            .with_decisions()?;
        super::bind_checkpoint_created(&emitter, &plan, meta)?;
        Ok(())
    })();
    if let Err(error) = result {
        tracing::warn!(%error, vm = name, "checkpoint audit binding failed");
    }
}
