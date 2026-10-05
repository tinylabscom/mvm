//! The instruction-file provenance gate, as admission runs it.
//!
//! Two halves, because the audit entries need a plan to bind to and the plan
//! does not exist until admission has signed it. [`evaluate`] runs before
//! signing — it reads the policy and verifies every instruction file the boot
//! is about to copy into the guest, failing admission early on a broken
//! policy or an unreadable input. [`record_and_enforce`] runs once the plan
//! and its audit emitter exist, before the boot is recorded as admitted: it
//! writes one chain-signed entry per file and then applies the enforcement
//! mode.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use mvm_core::plan::{ExecutionPlan, HostShareGrant, ShareKind};
use mvm_core::vm_backend::VmVolume;
use mvm_hostd::audit::emitter::AuditEmitter;

use super::AssetSpec;
use crate::instruction_trust::gate::{BootInputs, Decision, ScanReport, evaluate_boot_inputs};

/// Where a boot's instruction-file policy comes from, beyond its mounts and
/// assets.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct InstructionSources<'a> {
    /// The workload's source directory on this host, when it has one. It is
    /// scanned like a mount, and a project policy is looked for inside it.
    pub workload_dir: Option<&'a Path>,
    /// The exact roots copied into the guest for directory mounts, when the
    /// caller has already materialized them. When absent, the scan falls back
    /// to the admitted directory-share host paths.
    pub mount_roots: Option<&'a [PathBuf]>,
    /// Materialized host-directory images attached to the guest.
    pub mount_images: Option<&'a [PathBuf]>,
    /// Override for the user policy path. `None` reads
    /// `mvm_core::config::instruction_trust_policy_path()`; tests inject a
    /// tempdir so they never read the real user's policy.
    pub user_policy: Option<&'a Path>,
}

impl<'a> InstructionSources<'a> {
    /// Sources for a boot whose workload lives in `workload_dir`.
    #[must_use]
    pub fn for_workload(workload_dir: Option<&'a Path>) -> Self {
        Self {
            workload_dir,
            mount_roots: None,
            mount_images: None,
            user_policy: None,
        }
    }

    /// Use the exact roots the boot will copy into the guest for directory
    /// mounts, rather than re-reading the admitted source paths.
    #[must_use]
    pub fn with_mount_roots(mut self, mount_roots: &'a [PathBuf]) -> Self {
        self.mount_roots = Some(mount_roots);
        self
    }

    /// Inspect the actual image contents attached for host-directory mounts.
    #[must_use]
    pub fn with_mount_images(mut self, images: &'a [PathBuf]) -> Self {
        self.mount_images = Some(images);
        self
    }
}

/// The ext4 images a boot attaches in place of host directories.
///
/// A `--mount` reaches the guest as a materialized image, not as the directory
/// it was built from, so these are what the provenance scan has to read. Pass
/// them to [`InstructionSources::with_mount_images`]: handed to
/// [`InstructionSources::with_mount_roots`] instead, an image is a file root
/// matched by its own name, which is never an instruction file's name, and the
/// scan finds nothing in it.
#[must_use]
pub fn materialized_mount_images(volumes: &[VmVolume]) -> Vec<PathBuf> {
    volumes
        .iter()
        .filter_map(|volume| volume.materialized_image.as_deref().map(PathBuf::from))
        .collect()
}

/// The host paths this boot copies into the guest.
///
/// Directory shares and materialized host-directory images are scanned.
/// Managed block volumes remain guest-owned and are not host inputs.
fn boot_inputs(
    shares: &[HostShareGrant],
    assets: &[AssetSpec],
    sources: InstructionSources<'_>,
) -> BootInputs {
    BootInputs {
        mounts: sources.mount_roots.map_or_else(
            || {
                shares
                    .iter()
                    .filter(|grant| grant.kind == ShareKind::DirShare)
                    .map(|grant| PathBuf::from(&grant.host_path))
                    .collect()
            },
            <[PathBuf]>::to_vec,
        ),
        mount_images: sources
            .mount_images
            .map_or_else(Vec::new, <[PathBuf]>::to_vec),
        assets: assets
            .iter()
            .filter_map(|asset| match asset {
                AssetSpec::File { host_path, .. } => Some(PathBuf::from(host_path)),
                AssetSpec::RegistryPack(_) => None,
            })
            .collect(),
        workload_dir: sources.workload_dir.map(Path::to_path_buf),
    }
}

/// Load the policy and verify every instruction file under the boot's inputs.
///
/// `Ok(None)` when the boot copies nothing from the host.
pub(super) fn evaluate(
    shares: &[HostShareGrant],
    assets: &[AssetSpec],
    sources: InstructionSources<'_>,
) -> Result<Option<ScanReport>> {
    evaluate_boot_inputs(&boot_inputs(shares, assets, sources), sources.user_policy)
        .context("checking the provenance of instruction files copied into the guest")
}

/// Record every verdict under `plan`, then apply the enforcement mode.
///
/// Under an operator-written policy a verdict that cannot be recorded fails
/// the boot: the audit trail is part of what the operator asked for. With no
/// policy at all the records are informational and a write failure is only
/// logged.
pub(super) fn record_and_enforce(
    emitter: &AuditEmitter,
    plan: &ExecutionPlan,
    report: &ScanReport,
) -> Result<()> {
    for note in &report.notes {
        mvm_runtime::ui::warn(&format!("instruction trust: {note}"));
    }
    let recorded = emitter.batched(|| {
        for (event, labels) in report.audit_records() {
            emitter.emit_instruction_trust(plan, event, labels)?;
        }
        Ok(())
    });
    if let Err(error) = recorded {
        if report.origin.is_configured() {
            return Err(error.context("recording instruction-file provenance verdicts"));
        }
        tracing::warn!(error = %error, "recording instruction-file verdicts failed (non-fatal)");
    }
    match report.decision() {
        Decision::Admit => Ok(()),
        Decision::Warn(lines) => {
            for line in lines {
                mvm_runtime::ui::warn(&format!("instruction file {line}"));
            }
            Ok(())
        }
        Decision::Refuse(message) => {
            emitter
                .emit_refused(plan, "instruction_provenance", &message)
                .with_context(|| {
                    format!(
                        "recording the instruction-provenance refusal in the audit chain \
                         for: {message}"
                    )
                })?;
            anyhow::bail!(message)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn share(host: &str, kind: ShareKind) -> HostShareGrant {
        HostShareGrant {
            tag: "t".to_string(),
            host_path: host.to_string(),
            guest_path: "/work".to_string(),
            kind,
            read_only: true,
            encrypted: false,
            content_sha256: None,
        }
    }

    #[test]
    fn directory_shares_assets_and_the_workload_are_scanned_and_disks_are_not() {
        let assets = vec![AssetSpec::File {
            kind: mvm_contract::plan::AssetKind::Prompt,
            host_path: "/assets/prompt".to_string(),
        }];
        let inputs = boot_inputs(
            &[
                share("/src/tree", ShareKind::DirShare),
                share("/images/disk.ext4", ShareKind::Disk),
            ],
            &assets,
            InstructionSources::for_workload(Some(Path::new("/project"))),
        );
        assert_eq!(inputs.mounts, vec![PathBuf::from("/src/tree")]);
        assert_eq!(inputs.assets, vec![PathBuf::from("/assets/prompt")]);
        assert_eq!(inputs.workload_dir, Some(PathBuf::from("/project")));
    }

    #[test]
    fn a_boot_with_nothing_from_the_host_is_not_scanned() {
        assert!(
            evaluate(&[], &[], InstructionSources::default())
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn a_pack_identity_is_not_mistaken_for_a_host_file_to_scan() {
        let pin = mvm_core::registry_pack::PackPin::new(
            "runtime/python@1.0.0".parse().expect("pack reference"),
            mvm_core::packs::Sha256Hex::from_bytes(b"signed manifest"),
        )
        .expect("versioned pin");
        let assets = vec![AssetSpec::RegistryPack(pin)];
        let inputs = boot_inputs(&[], &assets, InstructionSources::default());
        assert!(inputs.assets.is_empty());
    }

    #[test]
    fn explicit_mount_roots_override_admitted_share_paths() {
        let assets = vec![AssetSpec::File {
            kind: mvm_contract::plan::AssetKind::Prompt,
            host_path: "/assets/prompt".to_string(),
        }];
        let materialized = vec![PathBuf::from("/state/mount-0")];
        let inputs = boot_inputs(
            &[share("/src/tree", ShareKind::DirShare)],
            &assets,
            InstructionSources::for_workload(None).with_mount_roots(&materialized),
        );
        assert_eq!(inputs.mounts, materialized);
        assert_eq!(inputs.assets, vec![PathBuf::from("/assets/prompt")]);
    }

    #[test]
    fn materialized_mount_images_are_the_attached_images_only() {
        let volumes = vec![
            VmVolume {
                host: "/src/tree".to_string(),
                guest: "/work".to_string(),
                materialized_image: Some("/cache/mounts/key.ext4".to_string()),
                ..Default::default()
            },
            VmVolume {
                host: "/images/disk.ext4".to_string(),
                guest: "/data".to_string(),
                ..Default::default()
            },
        ];
        assert_eq!(
            materialized_mount_images(&volumes),
            vec![PathBuf::from("/cache/mounts/key.ext4")]
        );
    }
}
