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
    pub(super) fn verify(config: &VmStartConfig, plan: &ExecutionPlan) -> Result<Self> {
        let release =
            crate::operator_admitted_trial_booter::verify_assurance_guest_protocol(config)?;
        let declaration = release
            .as_ref()
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

    /// Assurance cannot be added to an admission that never checked its
    /// actual runtime, or that checked only contributor-source artifacts.
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

    pub(super) fn verify_assurance_launch(&self, config: &VmStartConfig) -> Result<()> {
        self.require_assurance_runtime(&config.name)?;
        let actual = AssuranceRuntimeBinding::verify(config, &self.plan)?;
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
        plan: &ExecutionPlan,
    ) -> Result<Option<AssuranceRuntimeBinding>> {
        let Some(config) = self.runtime_config else {
            return Ok(None);
        };
        if crate::operator_admitted_trial_booter::verify_assurance_guest_protocol(config).is_err() {
            return Ok(None);
        }
        AssuranceRuntimeBinding::verify(config, plan).map(Some)
    }
}

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
