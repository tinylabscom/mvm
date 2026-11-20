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

#[cfg(test)]
#[path = "../../../mvm-core/src/image_set/fixtures/prepared_owner.rs"]
mod prepared_owner;

#[cfg(test)]
mod tests {
    use super::prepared_owner::prepared_owner;
    use super::*;
    use mvm_core::util::test_env::TestEnv;

    /// The two backends that hold the canonical kernel by descriptor.
    fn custody_backend() -> BackendKind {
        if cfg!(target_os = "linux") {
            BackendKind::Firecracker
        } else {
            BackendKind::Hvf
        }
    }

    /// An admitted plan carrying a guard minted over `owner`, and a config
    /// bound to that owner with a real rootfs whose digest the guard records.
    struct Fixture {
        admitted: AdmittedPlan,
        config: VmStartConfig,
        _home: tempfile::TempDir,
        _rootfs: tempfile::TempDir,
        _env: TestEnv,
    }

    fn fixture() -> Fixture {
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(home.path());
        let owner = prepared_owner(custody_backend());
        let rootfs_dir = tempfile::tempdir().unwrap();
        let rootfs = rootfs_dir.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"admitted rootfs").unwrap();
        let mut config = VmStartConfig {
            name: "canonical-neg".into(),
            rootfs_path: rootfs.display().to_string(),
            ..Default::default()
        };
        owner.bind_to_config(&mut config).unwrap();
        let mut plan = mvm_core::plan::test_support::PlanFixture::new().build();
        plan.plan_id = mvm_core::plan::compute_plan_id(&plan);
        let signer = "host:test".to_string();
        let signed = mvm_core::plan::sign_plan(
            &plan,
            &ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
            &signer,
        );
        let mut admitted = AdmittedPlan::for_test(plan, signer, signed);
        admitted.canonical_kernel = Some(Arc::new(AdmittedKernel {
            owner,
            backend: custody_backend(),
            image_sha256: mvm_core::crypto::image_verify::sha256_file(&rootfs).unwrap(),
        }));
        Fixture {
            admitted,
            config,
            _home: home,
            _rootfs: rootfs_dir,
            _env: env,
        }
    }

    fn refusal(f: &mut Fixture) -> String {
        f.admitted
            .bind_canonical_kernel(&mut f.config)
            .unwrap_err()
            .to_string()
    }

    #[test]
    #[ignore = "requires the actual pinned public kernel in MVM_TEST_CANONICAL_KERNEL; no download"]
    fn the_exact_admitted_owner_and_rootfs_bind() {
        let mut f = fixture();
        f.admitted.bind_canonical_kernel(&mut f.config).unwrap();
    }

    #[test]
    #[ignore = "requires the actual pinned public kernel in MVM_TEST_CANONICAL_KERNEL; no download"]
    fn an_owner_admission_never_verified_is_refused() {
        let mut f = fixture();
        f.admitted.canonical_kernel = None;
        assert_eq!(
            refusal(&mut f),
            "admission never verified this canonical kernel owner"
        );
    }

    #[test]
    #[ignore = "requires the actual pinned public kernel in MVM_TEST_CANONICAL_KERNEL; no download"]
    fn a_rootfs_changed_after_admission_is_refused() {
        let mut f = fixture();
        std::fs::write(&f.config.rootfs_path, b"swapped rootfs").unwrap();
        assert_eq!(
            refusal(&mut f),
            "launch rootfs differs from the actual admitted image"
        );
    }

    #[test]
    #[ignore = "requires the actual pinned public kernel in MVM_TEST_CANONICAL_KERNEL; no download"]
    fn a_config_that_dropped_the_owner_is_refused() {
        let mut f = fixture();
        f.config.canonical_kernel = None;
        assert_eq!(
            refusal(&mut f),
            "launch substituted the canonical kernel owner"
        );
    }

    #[test]
    #[ignore = "requires the actual pinned public kernel in MVM_TEST_CANONICAL_KERNEL; no download"]
    fn a_config_renamed_after_binding_is_refused() {
        let mut f = fixture();
        f.config.name = "another-vm".into();
        assert_eq!(refusal(&mut f), "kernel owner VM binding differs");
    }

    #[test]
    #[ignore = "requires the actual pinned public kernel in MVM_TEST_CANONICAL_KERNEL; no download"]
    fn a_substituted_kernel_path_is_refused() {
        let mut f = fixture();
        f.config.kernel_path = Some("/tmp/not-the-owned-kernel".into());
        assert_eq!(
            refusal(&mut f),
            "launch substituted the selected kernel path"
        );
    }
}
