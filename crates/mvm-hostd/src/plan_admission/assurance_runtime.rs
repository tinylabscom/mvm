//! Verification and binding of the actual runtime selected for admission.

use super::{AdmittedPlan, ExecutionPlan, RunPosture, VmStartConfig};
use anyhow::{Context, Result};

/// Private evidence that admission checked an assurance-compatible runtime
/// against the actual image and artifact bytes selected for this launch.
#[derive(Debug, PartialEq)]
pub(super) struct AssuranceRuntimeBinding {
    vm_name: String,
    selection: serde_json::Value,
}

impl AssuranceRuntimeBinding {
    pub(super) fn verify(
        config: &VmStartConfig,
        plan: &ExecutionPlan,
        runtime: Option<&mvm_runtime::runtime_evidence::VerifiedRuntimeSet>,
    ) -> Result<Self> {
        let checked_release = if let Some(runtime) = runtime {
            runtime.verify_config(config)?;
            plan.require_runtime_identity(runtime.identity())?;
            None
        } else {
            crate::operator_admitted_trial_booter::verify_assurance_guest_protocol(config)?
        };
        let declaration = runtime
            .map(|runtime| runtime.release().manifest())
            .or(checked_release.as_ref())
            .map(|release| release.declaration(mvm_core::arch::GuestArch::host()))
            .transpose()?;
        let mut files = Vec::new();
        for (role, path) in [
            ("rootfs", Some(config.rootfs_path.as_str())),
            ("kernel", config.kernel_path.as_deref()),
            ("verity", config.verity_path.as_deref()),
            ("overlay", config.runtime_overlay_path.as_deref()),
            (
                "overlay_verity",
                config.runtime_overlay_verity_path.as_deref(),
            ),
            ("initramfs", config.initrd_path.as_deref()),
        ] {
            if let Some(path) = path {
                let digest =
                    mvm_core::crypto::image_verify::sha256_file(std::path::Path::new(path))
                        .with_context(|| format!("hashing assurance {role}"))?;
                if role == "rootfs" && digest != plan.image.sha256 {
                    anyhow::bail!("assurance rootfs differs from the admitted image");
                }
                if let Some(declaration) = declaration {
                    verify_declared_runtime_digest(role, &digest, declaration)?;
                }
                files.push((role, path, digest));
            }
        }
        Ok(Self {
            vm_name: config.name.clone(),
            selection: serde_json::json!({
                "files": files,
                "roothash": config.roothash,
                "runtime_roothash": config.runtime_overlay_roothash,
                "runtime_version": config.runtime_overlay_version,
                "release_proof": config.runtime_release_proof,
                "legacy_bundle_runtime": config.legacy_bundle_runtime,
                "legacy_portable_runtime": config.legacy_portable_runtime,
            }),
        })
    }
}

fn verify_declared_runtime_digest(
    role: &str,
    digest: &str,
    declaration: &mvm_build::guest_bins::assembly::RuntimeAssembly,
) -> Result<()> {
    let expected = match role {
        "overlay" => Some(declaration.overlay_sha256.as_str()),
        "overlay_verity" => Some(declaration.overlay_verity_sha256.as_str()),
        "initramfs" => Some(declaration.initramfs_sha256.as_str()),
        _ => None,
    };
    if expected.is_some_and(|expected| digest != expected) {
        anyhow::bail!("assurance {role} bytes differ from the authenticated runtime declaration");
    }
    Ok(())
}

impl AdmittedPlan {
    /// Session-only fixtures do not boot or claim runtime authentication.
    #[cfg(test)]
    pub(crate) fn with_mock_assurance_runtime_for_test(mut self, vm: &str) -> Self {
        self.assurance_runtime = Some(AssuranceRuntimeBinding {
            vm_name: vm.to_string(),
            selection: serde_json::Value::Null,
        });
        self
    }

    /// Bind the selected runtime only for a declared campaign, before boot.
    /// Ordinary admission never carries an assurance capability forward.
    pub(crate) fn bind_assurance_runtime(
        &mut self,
        config: &VmStartConfig,
        runtime: Option<&mvm_runtime::runtime_evidence::VerifiedRuntimeSet>,
    ) -> Result<()> {
        self.assurance_runtime = None;
        self.assurance_runtime = Some(AssuranceRuntimeBinding::verify(
            config, &self.plan, runtime,
        )?);
        Ok(())
    }

    /// Assurance cannot be added to an admission without a campaign-time
    /// check of its actual runtime, or one checked only as contributor source.
    pub(crate) fn require_assurance_runtime(&self, vm: &str) -> Result<()> {
        let binding = self
            .assurance_runtime
            .as_ref()
            .context("admission has no verified assurance runtime binding")?;
        if binding.vm_name != vm {
            anyhow::bail!("assurance session VM differs from the runtime-bound launch identity");
        }
        Ok(())
    }

    pub(super) fn verify_assurance_launch(
        &self,
        config: &VmStartConfig,
        runtime: Option<&mvm_runtime::runtime_evidence::VerifiedRuntimeSet>,
    ) -> Result<()> {
        self.require_assurance_runtime(&config.name)?;
        let actual = AssuranceRuntimeBinding::verify(config, &self.plan, runtime)?;
        if self.assurance_runtime.as_ref() != Some(&actual) {
            anyhow::bail!("assurance launch runtime differs from its admitted selection");
        }
        Ok(())
    }
}

impl RunPosture<'_> {
    pub(super) fn verify_runtime(&self) -> Result<()> {
        let Some(config) = self.runtime_config else {
            return Ok(());
        };
        verify_selected_runtime(config)
    }

    pub(super) fn assurance_runtime(
        &self,
        _plan: &ExecutionPlan,
    ) -> Result<Option<AssuranceRuntimeBinding>> {
        // Admission of an ordinary launch does not pre-authorize a future
        // campaign. The declared campaign checks and binds at boot instead.
        Ok(None)
    }
}

#[tracing::instrument(skip_all)]
pub(super) fn verify_selected_runtime(config: &VmStartConfig) -> Result<()> {
    mvm_runtime::runtime_evidence::verify_runtime_for_launch(
        config,
        mvm_runtime::runtime_evidence::MIN_GUEST_RPC_PROTOCOL_VERSION,
    )
    .context("verifying selected guest runtime at admission")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::{BackendKind, Variant};
    use super::*;

    #[test]
    fn ordinary_admission_does_not_check_or_prebind_assurance_runtime() {
        let config = VmStartConfig {
            name: "ordinary".into(),
            rootfs_path: "/missing/selected-rootfs".into(),
            runtime_release_proof: Some(mvm_core::protocol::runtime_release::RuntimeReleaseProof {
                archive: "/missing/release.tar.gz".into(),
                checksum: "/missing/release.tar.gz.sha256".into(),
                signature_bundle: "/missing/release.tar.gz.bundle".into(),
                archive_sha256: "a".repeat(64),
                version: "1.2.3".into(),
                arch: mvm_core::arch::GuestArch::host(),
            }),
            ..Default::default()
        };
        let plan = mvm_core::plan::test_support::PlanFixture::new().build();
        let posture =
            RunPosture::on_backend(Variant::Prod, BackendKind::Hvf).with_runtime(Some(&config));
        assert!(posture.assurance_runtime(&plan).unwrap().is_none());

        let signer_id = "host:test".to_string();
        let signed = mvm_core::plan::signing::sign_plan(
            &plan,
            &ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
            &signer_id,
        );
        let mut admitted = AdmittedPlan::for_test(plan, signer_id, signed);
        assert!(admitted.require_assurance_runtime(&config.name).is_err());
        assert!(admitted.bind_assurance_runtime(&config, None).is_err());
        assert!(admitted.require_assurance_runtime(&config.name).is_err());
    }

    #[test]
    fn campaign_binding_checks_selected_bytes_and_vm_before_promotion() {
        let directory = tempfile::tempdir().unwrap();
        let mut config = mvm_runtime::signed_legacy_portable_runtime_fixture(directory.path());
        config.name = "campaign".into();
        let mut plan = mvm_core::plan::test_support::PlanFixture::new().build();
        plan.image.sha256 =
            mvm_core::crypto::image_verify::sha256_file(std::path::Path::new(&config.rootfs_path))
                .unwrap();
        let signer_id = "host:test".to_string();
        let signed = mvm_core::plan::signing::sign_plan(
            &plan,
            &ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
            &signer_id,
        );
        let mut admitted = AdmittedPlan::for_test(plan, signer_id, signed);
        admitted.bind_assurance_runtime(&config, None).unwrap();
        admitted.verify_assurance_launch(&config, None).unwrap();
        assert!(admitted.require_assurance_runtime("another-vm").is_err());

        std::fs::write(&config.rootfs_path, b"substituted rootfs").unwrap();
        assert!(admitted.verify_assurance_launch(&config, None).is_err());
        assert!(admitted.bind_assurance_runtime(&config, None).is_err());
        // A failed rebind cannot leave a previous campaign's capability usable.
        assert!(admitted.require_assurance_runtime(&config.name).is_err());
    }

    #[test]
    fn runtime_gate_refuses_unverified_unsigned_request_with_forged_plan() {
        let config = VmStartConfig {
            unsigned_runtime_development: true,
            plan_json: Some(r#"{"build_mode":"dev","verified":true}"#.to_string()),
            ..Default::default()
        };
        for variant in [Variant::Dev, Variant::Prod] {
            RunPosture::on_backend(variant, BackendKind::Hvf)
                .with_runtime(Some(&config))
                .verify_runtime()
                .expect_err("request and plan JSON cannot grant source runtime authority");
        }
    }

    #[test]
    fn runtime_gate_refuses_selected_overlay_without_proof() {
        let config = VmStartConfig {
            runtime_overlay_path: Some("/untrusted/runtime.ext4".to_string()),
            ..Default::default()
        };
        for variant in [Variant::Dev, Variant::Prod] {
            RunPosture::on_backend(variant, BackendKind::Hvf)
                .with_runtime(Some(&config))
                .verify_runtime()
                .expect_err("dev posture alone does not bypass signed runtime verification");
        }
    }

    #[test]
    fn every_runtime_artifact_must_match_the_authenticated_declaration() {
        // Exercises the comparison used after verification, not a successful
        // signature verification. No trusted runtime handle is fabricated.
        let declaration = mvm_build::guest_bins::assembly::RuntimeAssembly {
            assembly_format: mvm_build::guest_bins::assembly::RUNTIME_ASSEMBLY_FORMAT,
            arch: mvm_core::arch::GuestArch::host(),
            protocol_version: mvm_runtime::runtime_evidence::GUEST_RPC_PROTOCOL_VERSION,
            min_supported_protocol_version:
                mvm_runtime::runtime_evidence::MIN_GUEST_RPC_PROTOCOL_VERSION,
            overlay_sha256: "a".repeat(64),
            overlay_verity_sha256: "b".repeat(64),
            overlay_roothash: "c".repeat(64),
            initramfs_sha256: "d".repeat(64),
        };
        for (role, expected) in [
            ("overlay", &declaration.overlay_sha256),
            ("overlay_verity", &declaration.overlay_verity_sha256),
            ("initramfs", &declaration.initramfs_sha256),
        ] {
            verify_declared_runtime_digest(role, expected, &declaration).unwrap();
            assert!(
                verify_declared_runtime_digest(role, &"e".repeat(64), &declaration).is_err(),
                "{role} substitution must not mint an assurance capability"
            );
        }
    }
}
