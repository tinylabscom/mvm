//! Resolve registered artifacts, then delegate sealing to the shared exporter.

use super::*;
use std::path::PathBuf;

use mvm_core::plan::BundleResources;
use mvm_core::plan::types::{BuildProvenance, InputKind};
use mvm_core::security::AgentProfile;
use mvm_runtime::vm::template::lifecycle as tmpl;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct ExportRequest {
    pub template: String,
    pub out: PathBuf,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub cmdline: Option<PathBuf>,
    #[serde(default)]
    pub posture: Option<ExportPosture>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct ExportPosture {
    pub profile: AgentProfile,
    #[serde(default)]
    pub allow_egress: bool,
    #[serde(default)]
    pub allow_volumes: bool,
    #[serde(default)]
    pub allow_unauthenticated: bool,
}

impl From<PostureInputs> for ExportPosture {
    fn from(inputs: PostureInputs) -> Self {
        Self {
            profile: inputs.profile,
            allow_egress: inputs.allows_egress,
            allow_volumes: inputs.allows_volumes,
            allow_unauthenticated: !inputs.requires_auth,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ExportReport {
    pub path: PathBuf,
    pub size_bytes: u64,
    pub key_id: String,
}

/// Export under the host signer. Signing failure never falls back to unsigned
/// output, and neither request nor report carries private key material.
pub fn export(request: &ExportRequest) -> Result<ExportReport> {
    export_signed_by(request, None)
}

/// Export under `signer`, or under the host signer when none is given.
pub fn export_signed_by(
    request: &ExportRequest,
    signer: Option<&dyn BundleSigner>,
) -> Result<ExportReport> {
    let key = crate::manifest::resolve_artifact_key(&request.template)?;
    let (spec, vmlinux, initrd, rootfs, _) = tmpl::template_artifacts_dispatched(&key)
        .with_context(|| {
            format!(
                "loading template {:?} — does it exist? Try `mvmctl manifest ls`",
                request.template
            )
        })?;
    anyhow::ensure!(
        spec.template_id == key,
        "template records mismatched identity"
    );
    crate::manifest::checked_artifact(&key, Path::new(&vmlinux))?;
    crate::manifest::checked_artifact(&key, Path::new(&rootfs))?;
    if let Some(initrd) = &initrd {
        crate::manifest::checked_artifact(&key, Path::new(initrd))?;
    }
    let root = Path::new(&rootfs)
        .parent()
        .context("rootfs has no parent")?;
    crate::manifest::checked_artifact(&key, &root.join(mvm_core::guest_sidecar::SIDECAR_FILENAME))?;
    let installed_arch = tmpl::installed_bundle_arch(&key)?;
    let provenance = template_provenance(&spec.flake_ref, installed_arch.is_some());
    let source_arch =
        installed_arch.unwrap_or_else(|| mvm_core::arch::GuestArch::host().to_string());
    let (verity_path, roothash) = mvm_runtime::microvm::probe_verity_sidecar(&rootfs);
    // The boot probe permits unverified boot. Export must not silently strip a
    // malformed or half-present binding from the signed artifact.
    for name in ["rootfs.verity", "rootfs.roothash"] {
        let path = root.join(name);
        if std::fs::symlink_metadata(&path).is_ok() {
            crate::manifest::checked_artifact(&key, &path)?;
            anyhow::ensure!(
                verity_path.is_some() && roothash.is_some(),
                "template carries an incomplete or invalid dm-verity binding; rebuild before exporting"
            );
        }
    }
    let verity_bytes = verity_path
        .as_deref()
        .map(|path| {
            std::fs::read(path).with_context(|| format!("reading verity sidecar at {path}"))
        })
        .transpose()?;
    let cmdline = request
        .cmdline
        .as_deref()
        .map(|path| {
            std::fs::read_to_string(path)
                .with_context(|| format!("reading kernel command line at {}", path.display()))
        })
        .transpose()?;
    crate::manifest::check_export_destination(&request.out)?;
    let posture = request.posture.as_ref().map(|posture| {
        PostureInputs::new(posture.profile)
            .requires_auth(!posture.allow_unauthenticated)
            .allows_volumes(posture.allow_volumes)
            .allows_egress(posture.allow_egress)
    });
    let host_signer;
    let signer = match signer {
        Some(signer) => signer,
        None => {
            host_signer = HostBundleSigner::load()?;
            &host_signer
        }
    };
    // Signer initialization may create a previously absent protected root.
    crate::manifest::check_export_destination(&request.out)?;
    let exported = export_bundle_with_signer(
        &BundleExportInputs {
            vmlinux: &vmlinux,
            initrd: initrd.as_deref(),
            rootfs: &rootfs,
            verity_bytes: verity_bytes.as_deref(),
            roothash: roothash.as_deref(),
            profile: Some(&spec.profile),
            resources: Some(BundleResources {
                vcpus: u32::from(spec.vcpus),
                mem_mib: spec.mem_mib,
            }),
            arch_label: &source_arch,
            label: request.label.clone(),
            cmdline: cmdline.as_deref(),
            posture,
            provenance,
            boot_assets: None,
            out: &request.out,
            debug_out: None,
        },
        signer,
    )?;
    Ok(ExportReport {
        path: exported.path,
        size_bytes: exported.size_bytes,
        key_id: exported.key_id.0,
    })
}

fn template_provenance(flake_ref: &str, is_installed_bundle: bool) -> Option<BuildProvenance> {
    if is_installed_bundle || flake_ref.trim().is_empty() {
        return None;
    }
    Some(BuildProvenance {
        input_kind: InputKind::NixFlake,
        input_ref: flake_ref.to_string(),
        lock_digest: None,
        builder_id: None,
        artifacts: Default::default(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provenance_is_recorded_only_for_a_locally_built_template() {
        let local = template_provenance("github:org/app#default", false).unwrap();
        assert_eq!(local.input_kind, InputKind::NixFlake);
        assert_eq!(local.input_ref, "github:org/app#default");
        assert!(template_provenance("github:org/app#default", true).is_none());
        assert!(template_provenance("  ", false).is_none());
    }

    #[test]
    fn posture_defaults_closed_and_requests_roundtrip() {
        let request: ExportRequest = serde_json::from_str(
            r#"{"template":"slot","out":"a.mvmpkg","posture":{"profile":"sealed-prod"}}"#,
        )
        .unwrap();
        let posture = request.posture.as_ref().unwrap();
        assert!(!posture.allow_egress && !posture.allow_volumes && !posture.allow_unauthenticated);
        let encoded = serde_json::to_value(&request).unwrap();
        assert!(serde_json::from_value::<ExportRequest>(encoded).is_ok());
        assert!(
            serde_json::from_str::<ExportRequest>(
                r#"{"template":"slot","out":"a.mvmpkg","unsigned":true}"#
            )
            .is_err()
        );
    }
}
