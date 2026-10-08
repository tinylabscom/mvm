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
    /// Explicit host-source to frozen-image identities for materialized
    /// directory grants.
    pub materialized_mounts: Option<&'a [MaterializedMount]>,
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
            materialized_mounts: None,
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

    #[must_use]
    pub fn with_materialized_mounts(mut self, mounts: &'a [MaterializedMount]) -> Self {
        self.materialized_mounts = Some(mounts);
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaterializedMount {
    pub host_path: PathBuf,
    pub image_path: PathBuf,
}

#[must_use]
pub fn materialized_mounts(volumes: &[VmVolume]) -> Vec<MaterializedMount> {
    volumes
        .iter()
        .filter_map(|volume| {
            volume
                .materialized_image
                .as_deref()
                .map(|image| MaterializedMount {
                    host_path: PathBuf::from(&volume.host),
                    image_path: PathBuf::from(image),
                })
        })
        .collect()
}

/// Refuse host-directory snapshots on Wasm, which cannot mount the verified
/// ext4 bytes and must never substitute the live host source.
pub fn refuse_wasm_host_snapshots(
    backend: mvm_contract::protocol::vm_backend::BackendKind,
    mounts: &[MaterializedMount],
) -> Result<()> {
    if backend == mvm_contract::protocol::vm_backend::BackendKind::Wasm && !mounts.is_empty() {
        anyhow::bail!(
            "the Wasm backend cannot safely expose a verified materialized \
             host-directory snapshot; use a managed block volume or another backend"
        );
    }
    Ok(())
}

/// Harden instruction-bearing host snapshots to read-only using the same
/// effective policy and ext4 scanner admission uses.
///
/// Classification reads the frozen image, never the live source directory.
/// An unreadable or malformed image is therefore an error rather than a clean
/// classification.
struct Evaluation {
    report: ScanReport,
    instruction_images: std::collections::BTreeSet<PathBuf>,
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
        mount_images: sources.materialized_mounts.map_or_else(Vec::new, |mounts| {
            mounts
                .iter()
                .map(|mount| mount.image_path.clone())
                .collect()
        }),
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
fn evaluate(
    shares: &[HostShareGrant],
    assets: &[AssetSpec],
    sources: InstructionSources<'_>,
) -> Result<Option<Evaluation>> {
    let Some(report) =
        evaluate_boot_inputs(&boot_inputs(shares, assets, sources), sources.user_policy)
            .context("checking the provenance of instruction files copied into the guest")?
    else {
        return Ok(None);
    };
    let instruction_images = report
        .files
        .iter()
        .map(|file| file.file.root.clone())
        .collect();
    Ok(Some(Evaluation {
        report,
        instruction_images,
    }))
}

fn validate_legacy_mount_roots(
    shares: &[HostShareGrant],
    mount_roots: &[PathBuf],
) -> Result<std::collections::BTreeMap<PathBuf, PathBuf>> {
    let directory_shares = shares
        .iter()
        .filter(|share| share.kind == ShareKind::DirShare)
        .collect::<Vec<_>>();
    anyhow::ensure!(
        mount_roots.len() == directory_shares.len(),
        "legacy directory scan roots must match admitted directory shares one-to-one"
    );

    let mut roots_by_identity = std::collections::BTreeMap::new();
    for root in mount_roots {
        let identity = root.canonicalize().with_context(|| {
            format!(
                "canonicalizing legacy directory scan root {}",
                root.display()
            )
        })?;
        anyhow::ensure!(
            identity.is_dir(),
            "legacy directory scan root is not a directory: {}",
            root.display()
        );
        anyhow::ensure!(
            roots_by_identity.insert(identity, root.clone()).is_none(),
            "duplicate legacy directory scan root identity: {}",
            root.display()
        );
    }

    let mut share_identities = std::collections::BTreeSet::new();
    for share in directory_shares {
        let host_path = Path::new(&share.host_path);
        let identity = host_path.canonicalize().with_context(|| {
            format!(
                "canonicalizing admitted directory share {}",
                host_path.display()
            )
        })?;
        anyhow::ensure!(
            identity.is_dir(),
            "admitted directory share is not a directory: {}",
            host_path.display()
        );
        anyhow::ensure!(
            share_identities.insert(identity.clone()),
            "duplicate admitted directory share identity: {}",
            host_path.display()
        );
        anyhow::ensure!(
            roots_by_identity.contains_key(&identity),
            "legacy directory scan roots do not identify admitted directory share {}",
            host_path.display()
        );
    }
    Ok(roots_by_identity)
}

pub(super) fn evaluate_and_harden(
    shares: &mut [HostShareGrant],
    assets: &[AssetSpec],
    sources: InstructionSources<'_>,
) -> Result<Option<ScanReport>> {
    let legacy_roots = match (sources.mount_roots, sources.materialized_mounts) {
        (Some(roots), None) => Some(validate_legacy_mount_roots(shares, roots)?),
        _ => None,
    };
    anyhow::ensure!(
        !(sources.mount_roots.is_some_and(<[PathBuf]>::is_empty)
            && sources.materialized_mounts.is_none()
            && shares.iter().any(|share| share.kind == ShareKind::DirShare)),
        "directory share has no materialized-image identity"
    );
    if let Some(mounts) = sources.materialized_mounts {
        anyhow::ensure!(
            !mounts.is_empty() || !shares.iter().any(|share| share.kind == ShareKind::DirShare),
            "directory share has no materialized-image identity"
        );
    }
    let Some(evaluation) = evaluate(shares, assets, sources)? else {
        return Ok(None);
    };
    if let Some(mounts) = sources.materialized_mounts {
        let mut by_host = std::collections::BTreeMap::new();
        let mut images = std::collections::BTreeSet::new();
        for mount in mounts {
            anyhow::ensure!(
                by_host
                    .insert(mount.host_path.clone(), mount.image_path.clone())
                    .is_none(),
                "duplicate materialized host-directory source {}",
                mount.host_path.display()
            );
            anyhow::ensure!(
                images.insert(mount.image_path.clone()),
                "duplicate materialized host-directory image {}",
                mount.image_path.display()
            );
        }
        for share in shares
            .iter_mut()
            .filter(|share| share.kind == ShareKind::DirShare)
        {
            let image = by_host
                .remove(Path::new(&share.host_path))
                .with_context(|| {
                    format!(
                        "directory share {} has no materialized-image identity",
                        share.host_path
                    )
                })?;
            if evaluation.instruction_images.contains(&image) {
                share.read_only = true;
            }
        }
        anyhow::ensure!(
            by_host.is_empty(),
            "materialized-image identity has no admitted directory share: {}",
            by_host
                .keys()
                .map(|path| path.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );
    } else {
        for share in shares {
            let scan_root = if let Some(roots) = &legacy_roots {
                if share.kind != ShareKind::DirShare {
                    continue;
                }
                let identity = Path::new(&share.host_path)
                    .canonicalize()
                    .with_context(|| {
                        format!(
                            "canonicalizing admitted directory share {}",
                            share.host_path
                        )
                    })?;
                roots.get(&identity).map(PathBuf::as_path)
            } else {
                Some(Path::new(&share.host_path))
            };
            if scan_root.is_some_and(|root| evaluation.instruction_images.contains(root)) {
                share.read_only = true;
            }
        }
    }
    Ok(Some(evaluation.report))
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
    use mvm_core::util::test_env::TestEnv;

    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

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
    fn materialized_mounts_are_the_attached_host_image_identities_only() {
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
            materialized_mounts(&volumes),
            vec![MaterializedMount {
                host_path: PathBuf::from("/src/tree"),
                image_path: PathBuf::from("/cache/mounts/key.ext4"),
            }]
        );
    }

    fn image_with(path: &Path, guest_path: &str) {
        use mvm_fs::ext4::{Node, Owner, build_image};
        let bytes = build_image(
            vec![Node::File {
                path: guest_path.to_string(),
                mode: 0o644,
                data: b"content\n".to_vec(),
                xattrs: Vec::new(),
                owner: Owner::ROOT,
            }],
            &Default::default(),
        )
        .unwrap();
        std::fs::write(path, bytes).unwrap();
    }

    fn explicit_policy(dir: &Path) -> PathBuf {
        let policy = dir.join("instruction-trust.toml");
        std::fs::write(
            &policy,
            "enforcement = \"audit\"\nincludes = [\"AGENTS.md\", \"CLAUDE.md\"]\n",
        )
        .unwrap();
        policy
    }

    #[test]
    fn hardening_depends_on_the_frozen_images_instruction_contents() {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let ambient_home = dir.path().join("ambient-home");
        std::fs::create_dir_all(&ambient_home).unwrap();
        std::fs::write(
            ambient_home.join("instruction-trust.toml"),
            "enforcement = \"audit\"\nincludes = []\n",
        )
        .unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(&ambient_home);
        let instruction = dir.path().join("instruction.ext4");
        let ordinary = dir.path().join("ordinary.ext4");
        let policy = explicit_policy(dir.path());
        image_with(&instruction, "/AGENTS.md");
        image_with(&ordinary, "/app.txt");
        let volumes = vec![
            VmVolume {
                host: "/host/instruction".into(),
                materialized_image: Some(instruction.display().to_string()),
                read_only: false,
                ..Default::default()
            },
            VmVolume {
                host: "/host/ordinary".into(),
                materialized_image: Some(ordinary.display().to_string()),
                read_only: false,
                ..Default::default()
            },
            VmVolume {
                host: "/managed.ext4".to_string(),
                read_only: false,
                ..Default::default()
            },
        ];
        let mounts = materialized_mounts(&volumes);
        let mut shares = mvm_hostd::run::shares_from_vm_volumes(&volumes);
        shares.swap(0, 1);
        evaluate_and_harden(
            &mut shares,
            &[],
            InstructionSources {
                user_policy: Some(&policy),
                ..InstructionSources::default()
                    .with_mount_roots(&[])
                    .with_materialized_mounts(&mounts)
            },
        )
        .unwrap();
        assert!(!shares[0].read_only, "ordinary rw remains rw after reorder");
        assert!(shares[1].read_only, "instruction-bearing rw becomes ro");
        assert!(!shares[2].read_only, "managed block rw remains rw");
    }

    #[test]
    fn unreadable_snapshot_classification_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let image = dir.path().join("tampered.ext4");
        let policy = explicit_policy(dir.path());
        std::fs::write(&image, b"not ext4").unwrap();
        let volumes = vec![VmVolume {
            materialized_image: Some(image.display().to_string()),
            ..Default::default()
        }];
        let mounts = materialized_mounts(&volumes);
        let mut shares = mvm_hostd::run::shares_from_vm_volumes(&volumes);
        assert!(
            evaluate_and_harden(
                &mut shares,
                &[],
                InstructionSources {
                    user_policy: Some(&policy),
                    ..InstructionSources::default()
                        .with_mount_roots(&[])
                        .with_materialized_mounts(&mounts)
                }
            )
            .is_err()
        );
    }

    #[test]
    fn materialized_identity_mapping_rejects_missing_duplicate_and_unmatched_entries() {
        let dir = tempfile::tempdir().unwrap();
        let image = dir.path().join("ordinary.ext4");
        let policy = explicit_policy(dir.path());
        image_with(&image, "/ordinary.txt");
        let volume = VmVolume {
            host: "/host/source".into(),
            materialized_image: Some(image.display().to_string()),
            ..Default::default()
        };
        let mut shares = mvm_hostd::run::shares_from_vm_volumes(std::slice::from_ref(&volume));
        let run = |shares: &mut [HostShareGrant], mounts: &[MaterializedMount]| {
            evaluate_and_harden(
                shares,
                &[],
                InstructionSources {
                    user_policy: Some(&policy),
                    ..InstructionSources::default()
                        .with_mount_roots(&[])
                        .with_materialized_mounts(mounts)
                },
            )
        };
        assert!(run(&mut shares.clone(), &[]).is_err());
        let mapping = materialized_mounts(&[volume]);
        assert!(
            run(
                &mut shares.clone(),
                &[mapping[0].clone(), mapping[0].clone()]
            )
            .is_err()
        );
        let unmatched = MaterializedMount {
            host_path: "/host/other".into(),
            image_path: image,
        };
        assert!(run(&mut shares, &[unmatched]).is_err());
    }

    #[test]
    fn prepared_result_cannot_disagree_after_policy_changes_to_empty_includes() {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(dir.path());
        let image = dir.path().join("source.ext4");
        image_with(&image, "/AGENTS.md");
        let policy = dir.path().join("instruction-trust.toml");
        std::fs::write(
            &policy,
            "enforcement = \"audit\"\nincludes = [\"AGENTS.md\"]\n",
        )
        .unwrap();
        let volume = VmVolume {
            host: "/host/source".into(),
            materialized_image: Some(image.display().to_string()),
            ..Default::default()
        };
        let mounts = materialized_mounts(std::slice::from_ref(&volume));
        let mut shares = mvm_hostd::run::shares_from_vm_volumes(&[volume]);
        let report = evaluate_and_harden(
            &mut shares,
            &[],
            InstructionSources {
                user_policy: Some(&policy),
                ..InstructionSources::default()
                    .with_mount_roots(&[])
                    .with_materialized_mounts(&mounts)
            },
        )
        .unwrap()
        .unwrap();
        std::fs::write(&policy, "enforcement = \"deny\"\nincludes = []\n").unwrap();
        assert!(shares[0].read_only);
        assert_eq!(report.files.len(), 1);
    }

    #[test]
    fn wasm_refuses_every_host_snapshot_mode_but_not_managed_blocks() {
        use mvm_contract::protocol::vm_backend::BackendKind;
        for read_only in [false, true] {
            let volume = VmVolume {
                read_only,
                materialized_image: Some("/frozen/snapshot.ext4".to_string()),
                ..Default::default()
            };
            let mounts = materialized_mounts(&[volume]);
            let error = refuse_wasm_host_snapshots(BackendKind::Wasm, &mounts)
                .expect_err("Wasm must refuse both rw and ro host snapshots");
            assert!(error.to_string().contains("cannot safely expose"));
        }
        assert!(refuse_wasm_host_snapshots(BackendKind::Wasm, &[]).is_ok());
        assert!(
            refuse_wasm_host_snapshots(
                BackendKind::Firecracker,
                &[MaterializedMount {
                    host_path: PathBuf::from("/host/source"),
                    image_path: PathBuf::from("/frozen/snapshot.ext4"),
                }]
            )
            .is_ok()
        );
    }
}
