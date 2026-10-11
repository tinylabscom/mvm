//! Capture orchestration, including journal serialization and admitted key domains.

use anyhow::{Context, Result, bail};
use mvm_core::checkpoint::{CheckpointClass, CheckpointDigest, CheckpointId, CheckpointMeta};
use mvm_core::config::{machine_state_dir, vm_state_dir};
use mvm_runtime::backend::AnyBackend;
use mvm_runtime::checkpoint::{
    CaptureFsQuickParams, CaptureVmFullParams, CheckpointStore, capture_fs_quick, capture_vm_full,
};

use super::Checkpoints;
use super::admitted::admitted_capture_for;
use super::vm_state::{
    backend_for_vm, ensure_save_restore_supported, resolve_quiesced_vm_rootfs,
    runtime_contract_for_checkpoint, supervisor_config_digest, vm_is_running,
};
use crate::replay::input_journal;

/// Capture the current machine state without exposing stores, drivers, or keys.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct CaptureRequest {
    pub name: String,
    pub class: CheckpointClass,
    #[serde(default)]
    pub tag: Option<String>,
}

impl Checkpoints {
    pub fn capture(&self, request: &CaptureRequest) -> Result<CheckpointMeta> {
        crate::validate_vm_name(&request.name)?;
        match request.class {
            CheckpointClass::FsQuick => self.capture_fs_quick(&request.name, request.tag.clone()),
            CheckpointClass::VmFull => {
                self.capture_running(&request.name, request.tag.clone(), false)
            }
        }
    }

    /// Freeze a running source machine for a subsequent admitted fork.
    pub fn capture_for_fork(&self, name: &str, tag: Option<String>) -> Result<CheckpointId> {
        crate::validate_vm_name(name)?;
        Ok(self.capture_running(name, tag, true)?.id)
    }

    fn capture_fs_quick(&self, name: &str, tag: Option<String>) -> Result<CheckpointMeta> {
        let rootfs = resolve_quiesced_vm_rootfs(name)?;
        let state_dir = vm_state_dir(name);
        let (_input_lock, input_cursor) = lock_machine_input_cursor(name)?;
        let runtime_overlay_version = runtime_contract_for_checkpoint(name)?;
        let now = now_unix();
        let id = CheckpointId::new(format!("ckpt-{name}-{now}"));
        let admitted = admitted_capture_for(name)?;
        let meta = capture_fs_quick(
            &self.store,
            CaptureFsQuickParams {
                id,
                vm_name: name.to_string(),
                rootfs,
                supervisor_config_digest: supervisor_config_digest(&state_dir),
                runtime_overlay_version,
                tag,
                created_unix: now,
                quiesced: true,
                grants: admitted.grants,
                key_domain: admitted.key_domain,
            },
        )
        .with_context(|| format!("capturing fs_quick checkpoint of {name:?}"))?;
        let meta = seal_machine_input_cursor(&self.store, &meta, input_cursor)?;
        bind_checkpoint_created(name, &meta);
        Ok(meta)
    }

    fn capture_running(
        &self,
        name: &str,
        tag: Option<String>,
        for_fork: bool,
    ) -> Result<CheckpointMeta> {
        let backend = backend_for_vm(name);
        ensure_save_restore_supported(if for_fork { "fork" } else { "save" }, &backend)?;
        if !vm_is_running(name) {
            if for_fork {
                bail!("machine fork requires a running VM; start '{name}' first");
            }
            bail!("checkpoint --class vm-full requires a running VM; start '{name}' first");
        }
        let state_dir = vm_state_dir(name);
        let (_input_lock, input_cursor) = lock_machine_input_cursor(name)?;
        let now = now_unix();
        let meta = capture_vm_full_for_running_vm(CaptureVmFullArgs {
            name,
            state_dir: &state_dir,
            store: &self.store,
            backend: &backend,
            id: CheckpointId::new(format!("ckpt-{name}-{now}")),
            tag,
            created_unix: now,
            step: None,
        })
        .with_context(|| format!("capturing vm_full checkpoint of {name:?}"))?;
        let meta = seal_machine_input_cursor(&self.store, &meta, input_cursor)?;
        bind_checkpoint_created(name, &meta);
        Ok(meta)
    }
}

pub(super) fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

pub(super) fn lock_machine_input_cursor(
    name: &str,
) -> Result<(mvm_core::util::atomic_io::FileLock, u64)> {
    let dir = machine_state_dir(name);
    let lock = input_journal::lock(&dir)?;
    let cursor = input_journal::cursor(&dir)?;
    Ok((lock, cursor))
}

pub(super) struct CaptureVmFullArgs<'a> {
    pub name: &'a str,
    pub state_dir: &'a std::path::Path,
    pub store: &'a CheckpointStore,
    pub backend: &'a AnyBackend,
    pub id: CheckpointId,
    pub tag: Option<String>,
    pub created_unix: u64,
    pub step: Option<SessionStep>,
}

pub(super) struct SessionStep {
    pub parent: Option<CheckpointDigest>,
    pub session: mvm_core::checkpoint::SessionBinding,
}

pub(super) fn capture_vm_full_for_running_vm(
    args: CaptureVmFullArgs<'_>,
) -> Result<CheckpointMeta> {
    let runtime_overlay_version = runtime_contract_for_checkpoint(args.name)?;
    let control = args.backend.vm_full_control(args.name).ok_or_else(|| {
        anyhow::anyhow!(
            "backend '{}' has no full-VM capture control for '{}'",
            args.backend.name(),
            args.name
        )
    })?;
    let admitted = admitted_capture_for(args.name)?;
    let (parent, session) = match args.step {
        Some(step) => (step.parent, Some(step.session)),
        None => (None, None),
    };
    let params = CaptureVmFullParams {
        id: args.id,
        vm_name: args.name.to_string(),
        supervisor_config_digest: supervisor_config_digest(args.state_dir),
        runtime_overlay_version,
        supervisor_config_src: control.supervisor_config_path()?,
        tag: args.tag,
        created_unix: args.created_unix,
        retain_paused: false,
        grants: admitted.grants,
        parent,
        session,
        workspace_volumes: crate::workspace_apply::capture_set(
            &crate::workspace_apply::workspaces_of(args.name)?,
        )
        .into_iter()
        .map(Into::into)
        .collect(),
        key_domain: admitted.key_domain,
    };
    capture_vm_full(args.store, params, control.as_ref())
}

pub(super) fn seal_machine_input_cursor(
    store: &CheckpointStore,
    meta: &CheckpointMeta,
    cursor: u64,
) -> Result<CheckpointMeta> {
    let sealed = meta.with_machine_input_cursor(cursor);
    store
        .write_meta(&sealed)
        .context("sealing the machine input cursor into checkpoint metadata")?;
    Ok(sealed)
}

pub(super) fn bind_checkpoint_created(name: &str, meta: &CheckpointMeta) {
    let plan = match mvm_hostd::audit::plan_persist::read_plan(name) {
        Ok(plan) => plan,
        Err(error) => {
            tracing::warn!(error = %error, vm = name,
                "no persisted plan; checkpoint.created emitted without chain binding");
            return;
        }
    };
    let signer = match mvm_hostd::audit::host_keypair::load_or_init() {
        Ok(signer) => signer,
        Err(error) => {
            tracing::warn!(error = %error, "host signer unavailable; chain entry skipped");
            return;
        }
    };
    let emitter = match mvm_hostd::audit::emitter::AuditEmitter::new(signer.signing)
        .map(|emitter| emitter.with_receipts().with_decisions())
    {
        Ok(Ok(emitter)) => emitter,
        Ok(Err(error)) | Err(error) => {
            tracing::warn!(error = %error, "audit emitter unavailable; chain entry skipped");
            return;
        }
    };
    if let Err(error) = mvm_hostd::audit::bind::bind_checkpoint_created(&emitter, &plan, meta) {
        tracing::warn!(error = %error, "audit emit_checkpoint_created failed (non-fatal)");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frozen_machine(name: &str) {
        let dir = vm_state_dir(name);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("rootfs.ext4"), b"frozen-rootfs-fixture").unwrap();
    }

    fn request(name: &str) -> CaptureRequest {
        CaptureRequest {
            name: name.into(),
            class: CheckpointClass::FsQuick,
            tag: Some("fixture".into()),
        }
    }

    #[test]
    fn frozen_capture_seals_committed_input_cursor_and_encrypted_content() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.isolate_mvm_home(tmp.path());
        frozen_machine("captured");
        let dir = machine_state_dir("captured");
        {
            let _lock = input_journal::lock(&dir).unwrap();
            let pending = input_journal::begin_exec(&dir, &["/bin/true".into()]).unwrap();
            input_journal::finish_exec(&dir, pending, true).unwrap();
        }
        let checkpoints = Checkpoints::at(tmp.path().join("catalog"));
        let meta = checkpoints.capture(&request("captured")).unwrap();
        assert_eq!(meta.machine_input_cursor, Some(1));
        assert_eq!(meta.tag.as_deref(), Some("fixture"));
        assert_eq!(checkpoints.read(&meta.id).unwrap(), meta);
        assert_eq!(meta.meta_digest, meta.compute_meta_digest());
        assert!(
            !checkpoints
                .store
                .content_dir(&meta.id)
                .join("rootfs.ext4")
                .exists()
        );
        mvm_runtime::checkpoint::verify_content(&checkpoints.store, &meta).unwrap();
    }

    #[test]
    fn unfinished_execution_refuses_capture_before_publishing_a_checkpoint() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.isolate_mvm_home(tmp.path());
        frozen_machine("pending");
        let dir = machine_state_dir("pending");
        input_journal::begin_exec(&dir, &["/bin/true".into()]).unwrap();
        let checkpoints = Checkpoints::at(tmp.path().join("catalog"));
        let error = checkpoints.capture(&request("pending")).unwrap_err();
        assert!(
            format!("{error:#}").contains("no durable finish"),
            "{error:#}"
        );
        assert!(checkpoints.list().unwrap().is_empty());
    }

    #[test]
    fn corrupt_admitted_plan_refuses_capture_without_widening_to_host_keys() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.isolate_mvm_home(tmp.path());
        frozen_machine("corrupt");
        let path = mvm_hostd::audit::plan_persist::plan_path("corrupt").unwrap();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, b"not an admitted plan").unwrap();
        let checkpoints = Checkpoints::at(tmp.path().join("catalog"));
        let error = checkpoints.capture(&request("corrupt")).unwrap_err();
        assert!(
            format!("{error:#}").contains("permission set cannot be determined"),
            "{error:#}"
        );
        assert!(checkpoints.list().unwrap().is_empty());
    }

    #[test]
    fn live_unpaused_machine_is_refused_before_capture() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.isolate_mvm_home(tmp.path());
        frozen_machine("live");
        std::fs::write(
            vm_state_dir("live").join("fc.pid"),
            std::process::id().to_string(),
        )
        .unwrap();
        let checkpoints = Checkpoints::at(tmp.path().join("catalog"));
        let error = checkpoints.capture(&request("live")).unwrap_err();
        assert!(error.to_string().contains("stop or pause"), "{error:#}");
        assert!(checkpoints.list().unwrap().is_empty());
    }

    #[test]
    fn capture_request_round_trips_and_rejects_escaping_names() {
        let tmp = tempfile::tempdir().unwrap();
        let checkpoints = Checkpoints::at(tmp.path());
        let request = request("../escape");
        let encoded = serde_json::to_string(&request).unwrap();
        let decoded: CaptureRequest = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded.name, request.name);
        assert_eq!(decoded.class, request.class);
        assert_eq!(decoded.tag, request.tag);
        assert!(checkpoints.capture(&decoded).is_err());
        assert!(checkpoints.capture_for_fork("../escape", None).is_err());
    }
}
