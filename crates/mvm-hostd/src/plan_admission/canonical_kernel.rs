//! Private admission guard minted from the actual verified plan and owner.

use super::{AdmittedPlan, ExecutionPlan, RunPosture, VmStartConfig};
use anyhow::{Context, Result, ensure};
use mvm_core::canonical_linux::PreparedCanonicalLinux;
use mvm_core::vm_backend::BackendKind;
use std::sync::Arc;

#[derive(Debug)]
pub(super) struct AdmittedKernel {
    owner: Arc<PreparedCanonicalLinux>,
    backend: BackendKind,
    image_sha256: String,
}

impl AdmittedKernel {
    pub(super) fn capture(
        posture: RunPosture<'_>,
        plan: &ExecutionPlan,
    ) -> Result<Option<Arc<Self>>> {
        let Some(config) = posture.runtime_config else {
            return Ok(None);
        };
        let Some(owner) = &config.canonical_kernel else {
            return Ok(None);
        };
        let backend = posture
            .backend
            .context("canonical kernel requires actual backend at admission")?;
        ensure!(
            mvm_core::canonical_linux::supports_lifetime_custody(backend),
            "this backend has no canonical kernel lifetime release mechanism"
        );
        ensure!(
            plan.bundle.as_ref() == Some(owner.pin()),
            "canonical kernel owner differs from actual admitted bundle pin"
        );
        let guard = Arc::new(Self {
            owner: Arc::clone(owner),
            backend,
            image_sha256: plan.image.sha256.clone(),
        });
        guard.verify_launch(config, backend)?;
        Ok(Some(guard))
    }
}

impl AdmittedKernel {
    fn verify_launch(&self, config: &VmStartConfig, backend: BackendKind) -> Result<()> {
        ensure!(
            backend == self.backend,
            "launch backend differs from canonical kernel admission"
        );
        self.owner.verify_config(
            config,
            backend,
            &mvm_build::stage0_kernel::current_image_set_protocol_support(),
        )?;
        ensure!(
            mvm_core::crypto::image_verify::sha256_file(std::path::Path::new(&config.rootfs_path))?
                == self.image_sha256,
            "launch rootfs differs from the actual admitted image"
        );
        Ok(())
    }
}

impl AdmittedPlan {
    pub(super) fn bind_canonical_kernel(&self, config: &mut VmStartConfig) -> Result<()> {
        match &self.canonical_kernel {
            Some(guard) => {
                guard.verify_launch(config, guard.backend)?;
            }
            None => {
                ensure!(
                    config.canonical_kernel.is_none(),
                    "admission never verified this canonical kernel owner"
                );
            }
        }
        Ok(())
    }
}
