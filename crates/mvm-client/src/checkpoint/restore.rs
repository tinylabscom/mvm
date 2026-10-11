//! Same-identity restore, serialized against stop and reconciliation.

use anyhow::{Context, Result, bail};
use mvm_core::checkpoint::{CheckpointClass, CheckpointId};

use super::{Checkpoints, SignedChainAnchor, vm_is_running};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct RestoreRequest {
    pub id: CheckpointId,
    pub tenant: String,
}

#[derive(Debug, Clone, serde::Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct RestoreReport {
    pub schema_version: u8,
    pub action: &'static str,
    pub id: CheckpointId,
    pub vm_name: String,
}

impl Checkpoints {
    pub fn restore(&self, request: &RestoreRequest) -> Result<RestoreReport> {
        let meta = self.read(&request.id)?;
        crate::validate_vm_name(&meta.vm_name)?;
        if meta.class != CheckpointClass::VmFull {
            bail!(
                "checkpoint '{}' is class fs_quick; restore applies to vm_full checkpoints \
                 (fork an fs_quick checkpoint instead)",
                request.id.as_str()
            );
        }
        // The lifecycle guard must outlive materialization and supervisor startup.
        let _lifecycle = mvm_runtime::vm::instance_snapshot::lock_resume(&meta.vm_name)?;
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
            &self.store,
            mvm_runtime::checkpoint::RestoreParams {
                checkpoint: request.id.clone(),
                target_vm: meta.vm_name.clone(),
                tenant: request.tenant.clone(),
            },
            restorer.as_ref(),
            &anchor,
        )
        .with_context(|| format!("restoring checkpoint {}", request.id.as_str()))?;
        Ok(RestoreReport {
            schema_version: 1,
            action: "restore",
            id: request.id.clone(),
            vm_name: meta.vm_name,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::checkpoint::CheckpointMeta;

    #[test]
    fn fs_quick_restore_is_refused_before_backend_access() {
        let tmp = tempfile::tempdir().unwrap();
        let checkpoints = Checkpoints::at(tmp.path());
        let meta = CheckpointMeta::builder(
            CheckpointId::new("fs"),
            CheckpointClass::FsQuick,
            "test-machine",
        )
        .build();
        checkpoints.store.write_meta(&meta).unwrap();
        let error = checkpoints
            .restore(&RestoreRequest {
                id: meta.id,
                tenant: "local".into(),
            })
            .unwrap_err();
        assert!(error.to_string().contains("fork an fs_quick"), "{error:#}");
    }
}
