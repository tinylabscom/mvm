//! Registered writable host snapshots, independent of the command-line UI.

use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::volume::{AccessMode, AttachmentRecord, LocalVolumeService, VolumeService};

/// A writable snapshot and the identity of its verified baseline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct Workspace {
    pub volume: String,
    pub guest_path: String,
    pub source_dir: PathBuf,
    pub baseline_key: String,
    pub image: PathBuf,
}

/// A workspace image included in a checkpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct WorkspaceImage {
    pub name: String,
    pub image: PathBuf,
}

impl From<WorkspaceImage> for mvm_runtime::checkpoint::WorkspaceVolume {
    fn from(value: WorkspaceImage) -> Self {
        Self {
            name: value.name,
            image: value.image,
        }
    }
}

/// Classify registered volumes; only writable host-directory snapshots qualify.
pub fn workspaces_in(attachments: Vec<AttachmentRecord>) -> Vec<Workspace> {
    let mut workspaces: Vec<_> = attachments
        .into_iter()
        .filter(|attachment| attachment.access == AccessMode::ReadWrite)
        .filter_map(|attachment| {
            let snapshot = attachment.host_snapshot?;
            Some(Workspace {
                volume: attachment.volume,
                guest_path: attachment.guest_path,
                source_dir: PathBuf::from(snapshot.source_path),
                baseline_key: snapshot.fingerprint,
                image: PathBuf::from(attachment.host_path),
            })
        })
        .collect();
    workspaces.sort_by(|a, b| a.volume.cmp(&b.volume));
    workspaces
}

/// Every workspace registered for a validated machine name.
pub fn workspaces_of(vm: &str) -> Result<Vec<Workspace>> {
    crate::validate_vm_name(vm)?;
    let attachments = LocalVolumeService::new()
        .list_attachments(vm)
        .with_context(|| format!("listing the volumes registered for {vm:?}"))?;
    Ok(workspaces_in(attachments))
}

/// Existing images to freeze with the machine.
pub fn capture_set(workspaces: &[Workspace]) -> Vec<WorkspaceImage> {
    workspaces
        .iter()
        .filter(|workspace| workspace.image.is_file())
        .map(|workspace| WorkspaceImage {
            name: workspace.volume.clone(),
            image: workspace.image.clone(),
        })
        .collect()
}

/// Flush a running guest before reading its workspace images.
pub fn flush_running_guest(vm: &str) -> Result<()> {
    crate::validate_vm_name(vm)?;
    crate::guest::sync_filesystems_if_running(vm)
}

/// Find a published baseline, checking its backing encryption and digest.
pub fn baseline_image(workspace: &Workspace) -> Result<PathBuf> {
    super::cache::MountImageCache::new()?
        .published_image(&workspace.baseline_key)?
        .with_context(|| {
            format!(
                "the baseline image volume {:?} was copied from is no longer cached, or no \
                 longer matches its recorded digest; it cannot be compared against",
                workspace.volume
            )
        })
}

/// Select a registered workspace; callers cannot supply arbitrary host paths.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct WorkspaceRequest {
    pub vm: String,
    #[serde(default)]
    pub volume: Option<String>,
    #[serde(default)]
    pub exclude: Vec<String>,
    #[serde(default)]
    pub protected_paths: Vec<String>,
}

/// A selected workspace, with mutation policy and registration identity pinned.
pub struct RegisteredWorkspace {
    request: WorkspaceRequest,
    workspace: Workspace,
    audit: super::SignedWorkspaceAudit,
}

impl RegisteredWorkspace {
    /// Recover interrupted work before planning, matching imperative apply.
    pub fn open(request: WorkspaceRequest) -> Result<(Self, Vec<super::Recovered>)> {
        let workspace = select_workspace(&request.vm, request.volume.as_deref())?;
        let session = Self {
            request,
            workspace,
            audit: super::SignedWorkspaceAudit::new(),
        };
        let (_, recovered) = super::WorkspaceApplier::open(session.target(), &session.audit)?;
        Ok((session, recovered))
    }

    pub fn workspace(&self) -> &Workspace {
        &self.workspace
    }

    fn target(&self) -> super::WorkspaceTarget<'_> {
        super::WorkspaceTarget {
            vm: &self.request.vm,
            volume: &self.workspace.volume,
            source_dir: &self.workspace.source_dir,
        }
    }

    fn revalidate_registration(&self) -> Result<()> {
        let current = select_workspace(&self.request.vm, Some(&self.workspace.volume))?;
        ensure_registration_matches(&self.workspace, &current)
    }

    pub fn review(&self) -> Result<super::Review> {
        self.revalidate_registration()?;
        flush_running_guest(&self.request.vm)?;
        let baseline = baseline_image(&self.workspace)?;
        let mut reviewed = super::review(
            self.target(),
            &super::ReviewRequest {
                baseline_image: &baseline,
                live_image: &self.workspace.image,
                exclude: &self.request.exclude,
                protected_paths: &self.request.protected_paths,
            },
        )?;
        if let super::Review::Ready(pending) = &mut reviewed {
            pending.registration = Some(self.workspace.clone());
        }
        Ok(reviewed)
    }

    /// Commit only explicit approval; the engine re-plans before staging.
    pub fn apply(&self, pending: super::PendingApply, approved: bool) -> Result<super::Applied> {
        anyhow::ensure!(approved, "workspace apply requires explicit approval");
        ensure_review_policy(&pending, &self.request)?;
        anyhow::ensure!(
            pending.registration.as_ref() == Some(&self.workspace),
            "reviewed workspace registration does not match the apply target"
        );
        self.revalidate_registration()?;
        flush_running_guest(&self.request.vm)?;
        baseline_image(&self.workspace)?;
        let (applier, _) = super::WorkspaceApplier::open(self.target(), &self.audit)?;
        applier.apply(pending)
    }

    /// Stateless commit: compare the caller-approved digest with a new review,
    /// then repeat the normal immediate pre-stage revalidation.
    pub fn apply_reviewed(&self, fingerprint: &str, approved: bool) -> Result<super::Applied> {
        anyhow::ensure!(approved, "workspace apply requires explicit approval");
        let super::Review::Ready(pending) = self.review()? else {
            anyhow::bail!("workspace changed after review; review again before applying");
        };
        anyhow::ensure!(
            pending.fingerprint()? == fingerprint,
            "workspace changed after review; review again before applying"
        );
        self.apply(*pending, approved)
    }

    pub fn undo(&self) -> Result<Option<super::AppliedRelation>> {
        self.revalidate_registration()?;
        let (applier, _) = super::WorkspaceApplier::open(self.target(), &self.audit)?;
        applier.undo()
    }

    pub fn redo(&self) -> Result<Option<super::AppliedRelation>> {
        self.revalidate_registration()?;
        let (applier, _) = super::WorkspaceApplier::open(self.target(), &self.audit)?;
        applier.redo()
    }
}

fn ensure_registration_matches(expected: &Workspace, current: &Workspace) -> Result<()> {
    anyhow::ensure!(
        expected == current,
        "workspace registration changed after review"
    );
    Ok(())
}

pub(super) fn ensure_review_policy(
    pending: &super::PendingApply,
    request: &WorkspaceRequest,
) -> Result<()> {
    anyhow::ensure!(
        pending.protected_paths == request.protected_paths
            && pending.plan.exclusion_patterns == request.exclude,
        "reviewed workspace policy does not match the apply request"
    );
    Ok(())
}

pub fn select_workspace(vm: &str, volume: Option<&str>) -> Result<Workspace> {
    if let Some(volume) = volume {
        mvm_core::domain::volume::VolumeName::new(volume)?;
    }
    let all = workspaces_of(vm)?;
    if all.is_empty() {
        anyhow::bail!(
            "machine {vm:?} has no workspace volume; attach a host directory read-write with \
             `mvmctl machine volume mount {vm} --volume NAME --host DIR --guest PATH --rw`"
        );
    }
    match volume {
        Some(name) => all
            .into_iter()
            .find(|w| w.volume == name)
            .with_context(|| format!("machine {vm:?} has no workspace volume {name:?}")),
        None => {
            if all.len() > 1 {
                let names: Vec<_> = all.iter().map(|w| w.volume.as_str()).collect();
                anyhow::bail!(
                    "machine {vm:?} has several workspace volumes ({}); pass --volume",
                    names.join(", ")
                );
            }
            all.into_iter().next().context("no workspace")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registration_drift_refuses_changed_source_image_or_baseline() {
        let expected = Workspace {
            volume: "source".into(),
            guest_path: "/work".into(),
            source_dir: "/host/source".into(),
            baseline_key: "a".repeat(64),
            image: "/state/source.ext4".into(),
        };
        assert!(ensure_registration_matches(&expected, &expected).is_ok());
        for changed in [
            Workspace {
                source_dir: "/other".into(),
                ..expected.clone()
            },
            Workspace {
                baseline_key: "b".repeat(64),
                ..expected.clone()
            },
            Workspace {
                image: "/state/other.ext4".into(),
                ..expected.clone()
            },
            Workspace {
                guest_path: "/data".into(),
                ..expected.clone()
            },
        ] {
            assert!(ensure_registration_matches(&expected, &changed).is_err());
        }
    }

    #[test]
    fn workspace_image_conversion_preserves_authoritative_identity() {
        let image = WorkspaceImage {
            name: "source".into(),
            image: PathBuf::from("/state/source.ext4"),
        };
        let runtime: mvm_runtime::checkpoint::WorkspaceVolume = image.clone().into();
        assert_eq!(runtime.name, image.name);
        assert_eq!(runtime.image, image.image);
        assert_eq!(
            serde_json::from_str::<WorkspaceImage>(&serde_json::to_string(&image).unwrap())
                .unwrap(),
            image
        );
    }

    #[test]
    fn workspace_request_defaults_are_read_only_policy_inputs() {
        let request: WorkspaceRequest = serde_json::from_str(r#"{"vm":"test"}"#).unwrap();
        assert!(request.volume.is_none());
        assert!(request.exclude.is_empty());
        assert!(request.protected_paths.is_empty());
        assert!(
            serde_json::from_str::<WorkspaceRequest>(r#"{"vm":"test","approved":true}"#).is_err()
        );
        assert_eq!(
            serde_json::from_str::<WorkspaceRequest>(&serde_json::to_string(&request).unwrap())
                .unwrap(),
            request
        );
    }

    #[test]
    fn workspace_selection_refuses_escaping_names_before_disk_access() {
        assert!(select_workspace("../outside", None).is_err());
        assert!(select_workspace("valid", Some("../outside")).is_err());
    }
}
