//! `machine check-artifact <app.mvmpkg>`: verify a signed bundle, confirm it
//! can run on this host, and show what it declares about any launch of it.
//!
//! Read-only: no install, no extraction, no boot, no audit-chain emission.
//! The run path (`machine run --manifest <app.mvmpkg>`) verifies the same
//! archive through the same streaming verifier.

use anyhow::Result;
use mvm_core::arch::GuestArch;
use mvm_core::image_set::BackendImageSupport;
use mvm_core::plan::bundle::verify_bundle_file;
use mvm_core::plan::{BundleManifest, FsTrustStore, check_embedded_image_set_for_backend};
use std::path::PathBuf;

#[derive(clap::Args, Debug, Clone)]
pub(in crate::commands) struct CheckArtifactArgs {
    /// Path to the signed `.mvmpkg` bundle to verify and preview.
    pub path: PathBuf,
    /// Publisher trust-store directory. Defaults to
    /// `~/.mvm/trusted-publishers/`.
    #[arg(long, value_name = "DIR")]
    pub trust_store: Option<PathBuf>,
    /// Also prove an embedded image set is usable by this backend before boot.
    /// Supported values: firecracker, hvf, libkrun, qemu.
    #[arg(long, value_name = "BACKEND")]
    pub backend: Option<String>,
    /// Emit the verdict as JSON.
    #[arg(long)]
    pub json: bool,
}

pub(in crate::commands) fn run_check_artifact(args: CheckArtifactArgs) -> Result<()> {
    if !mvm_client::launch::manifest_ref::is_bundle_archive(&args.path) {
        anyhow::bail!(
            "{} is not a .mvmpkg bundle; seal one with `mvmctl bundle export`",
            args.path.display()
        );
    }
    let trust = match &args.trust_store {
        Some(path) => FsTrustStore::new(path),
        None => FsTrustStore::default_path()?,
    };
    let verified = verify_bundle_file(&args.path, &trust)
        .map_err(|error| anyhow::anyhow!("{}: {error}", args.path.display()))?;
    let host_arch = GuestArch::require_host(&verified.manifest.arch)
        .map_err(|error| anyhow::anyhow!("{}: not runnable here: {error}", args.path.display()))?;

    if let Some(name) = args.backend.as_deref() {
        let support = backend_image_support(name)?;
        let host_protocols = mvm_build::stage0_kernel::current_image_set_protocol_support();
        for embedded in &verified.embedded_image_sets {
            check_embedded_image_set_for_backend(embedded, host_arch, &support, &host_protocols)
                .map_err(|error| {
                    anyhow::anyhow!("backend {name} refuses embedded image set: {error}")
                })?;
        }
    }

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "path": args.path.display().to_string(),
                "bundle_sha256": verified.bundle_sha256,
                "arch": verified.manifest.arch,
                "runnable_here": true,
                "artifact_count": verified.manifest.artifacts.len(),
                "embedded_image_sets": verified.embedded_image_sets.iter().map(|set| {
                    set.manifest_sha256.as_str()
                }).collect::<Vec<_>>(),
                "backend": args.backend,
                "posture": posture_preview(&verified.manifest),
                "kernel_cmdline": verified.manifest.kernel_cmdline(),
                "built_from": verified.manifest.build_provenance().map(|p| p.input_ref.as_str()),
                "verified": true,
            }))?
        );
    } else {
        crate::ui::success(&format!(
            "{}: verified, runnable on {host_arch} ({} artifacts, {} embedded image set{}){}",
            args.path.display(),
            verified.manifest.artifacts.len(),
            verified.embedded_image_sets.len(),
            if verified.embedded_image_sets.len() == 1 {
                ""
            } else {
                "s"
            },
            args.backend
                .as_deref()
                .map(|backend| format!(", backend {backend} compatible"))
                .unwrap_or_default(),
        ));
        println!("  posture: {}", posture_line(&verified.manifest));
        if let Some(cmdline) = verified.manifest.kernel_cmdline() {
            println!("  kernel cmdline: {cmdline}");
        }
        if let Some(provenance) = verified.manifest.build_provenance() {
            println!("  built from: {}", provenance.input_ref);
        }
    }
    Ok(())
}

/// The ceilings a bundle places on any launch of it, as the JSON verdict
/// reports them. `null` when the bundle declares no posture, which leaves the
/// launch's own policy as the only limit.
fn posture_preview(manifest: &BundleManifest) -> serde_json::Value {
    let Some(posture) = manifest.security_posture() else {
        return serde_json::Value::Null;
    };
    serde_json::json!({
        "profile": posture.profile,
        "verity_protected": posture.verity_protected,
        "requires_auth": posture.requires_auth,
        "egress": if posture.allows_egress { "allowed" } else { "deny-all" },
        "volumes": posture.allows_volumes,
    })
}

fn posture_line(manifest: &BundleManifest) -> String {
    let Some(posture) = manifest.security_posture() else {
        return "none declared; the launch's own policy applies".to_string();
    };
    let profile = serde_json::to_value(posture.profile)
        .ok()
        .and_then(|value| value.as_str().map(str::to_string))
        .unwrap_or_default();
    let allowed = |yes: bool| if yes { "allowed" } else { "refused" };
    format!(
        "{profile} (egress={}, volumes={}, verity={}, auth={})",
        allowed(posture.allows_egress),
        allowed(posture.allows_volumes),
        posture.verity_protected,
        if posture.requires_auth {
            "required"
        } else {
            "not required"
        },
    )
}

fn backend_image_support(name: &str) -> Result<BackendImageSupport> {
    let kind = mvm_core::vm_backend::BackendKind::from_label(name)
        .ok_or_else(|| anyhow::anyhow!("unknown backend {name:?}"))?;
    BackendImageSupport::for_backend(kind).ok_or_else(|| {
        anyhow::anyhow!(
            "backend {name:?} has no Linux-direct embedded image-set contract; expected firecracker, hvf, libkrun, or qemu"
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::plan::{BundleMember, BundleSecurityPosture, KeyId};
    use mvm_core::security::AgentProfile;

    fn manifest(members: Vec<BundleMember>) -> BundleManifest {
        BundleManifest {
            schema_version: mvm_core::plan::BUNDLE_SCHEMA_VERSION,
            publisher: "p".to_string(),
            key_id: KeyId("0".repeat(32)),
            arch: "x86_64".to_string(),
            kernel_version: None,
            profile: None,
            workload_label: None,
            created_at: "2026-01-01T00:00:00Z".to_string(),
            labels: Default::default(),
            artifacts: Vec::new(),
            members,
            verity: None,
            resources: None,
        }
    }

    #[test]
    fn a_bundle_without_a_posture_previews_no_ceiling() {
        let m = manifest(Vec::new());
        assert_eq!(posture_preview(&m), serde_json::Value::Null);
        assert!(posture_line(&m).starts_with("none declared"));
    }

    #[test]
    fn a_declared_posture_previews_each_ceiling() {
        let m = manifest(vec![BundleMember::SecurityPosture(BundleSecurityPosture {
            profile: AgentProfile::Dev,
            verity_protected: false,
            requires_auth: true,
            allows_volumes: false,
            allows_egress: true,
        })]);
        let preview = posture_preview(&m);
        assert_eq!(preview["profile"], "dev");
        assert_eq!(preview["egress"], "allowed");
        assert_eq!(preview["volumes"], false);
        assert_eq!(
            posture_line(&m),
            "dev (egress=allowed, volumes=refused, verity=false, auth=required)"
        );
    }
}
