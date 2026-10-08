//! `mvmctl machine vm diff` — what a machine changed in its workspaces, with
//! content.
//!
//! A workspace is a writable volume that began as a snapshot of a host
//! directory (see [`super::workspace`]). Both sides of the diff are ext4
//! images read on the host: the baseline the copy began as, or a checkpoint's
//! frozen copy, against the live copy or another checkpoint's. No file content
//! crosses the guest channel to produce it. Against a running machine the
//! guest is first asked to flush its writes (`SyncFilesystems`, gated with the
//! filesystem RPC it serves); a guest that refuses is reported and the diff
//! shows what has reached the disk.

mod render;

use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::Args as ClapArgs;
use mvm_core::naming::validate_vm_name;
use mvm_core::user_config::MvmConfig;
use mvm_fs::tree_diff::{DiffLimits, TreeDiff, diff_images};
use serde::Serialize;

use super::Cli;
use super::shared::clap_vm_name;
use super::workspace::{Workspace, baseline_image, workspaces_of};
use render::VolumeDiff;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// Name of the VM
    #[arg(value_parser = clap_vm_name)]
    pub name: String,
    /// Compare from this checkpoint instead of the workspace's starting point
    #[arg(long, value_name = "CKPT")]
    pub from: Option<String>,
    /// Compare to this checkpoint instead of the live workspace
    #[arg(long, value_name = "CKPT")]
    pub to: Option<String>,
    /// Only this workspace volume
    #[arg(long)]
    pub volume: Option<String>,
    /// One line per changed entry, with line counts
    #[arg(long, conflicts_with_all = ["side_by_side", "json"])]
    pub stat: bool,
    /// Old and new text in two columns
    #[arg(long, conflicts_with = "json")]
    pub side_by_side: bool,
    /// Output as JSON
    #[arg(long)]
    pub json: bool,
    /// Unchanged lines shown around each change
    #[arg(long, default_value_t = 3)]
    pub context: usize,
    /// Changed entries listed before the rest are only counted
    #[arg(long, default_value_t = DiffLimits::default().max_files)]
    pub max_files: u64,
    /// Largest file whose text is shown; larger files are compared by digest
    #[arg(long, default_value_t = DiffLimits::default().max_file_bytes)]
    pub max_file_bytes: u64,
    /// Diff text shown before later files are listed without it
    #[arg(long, default_value_t = DiffLimits::default().max_output_bytes)]
    pub max_output_bytes: u64,
}

impl Args {
    fn limits(&self) -> DiffLimits {
        DiffLimits::default()
            .with_context_lines(self.context)
            .with_max_files(self.max_files)
            .with_max_file_bytes(self.max_file_bytes)
            .with_max_output_bytes(self.max_output_bytes)
    }
}

/// Where one side of the diff comes from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Side {
    /// The image the workspace was copied from.
    Baseline,
    /// The image the guest writes now.
    Live,
    /// A checkpoint's frozen copy.
    Checkpoint { id: String },
}

/// One volume's diff, as `--json` reports it.
#[derive(Debug, Serialize)]
struct VolumeReport {
    volume: String,
    guest_path: String,
    source_dir: PathBuf,
    diff: TreeDiff,
}

#[derive(Debug, Serialize)]
struct DiffReport {
    schema_version: u32,
    vm: String,
    from: Side,
    to: Side,
    /// Why the live side may lag the guest, when it does.
    #[serde(skip_serializing_if = "Option::is_none")]
    unsynced: Option<String>,
    volumes: Vec<VolumeReport>,
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    validate_vm_name(&args.name).with_context(|| format!("Invalid VM name: {:?}", args.name))?;
    let workspaces = selected_workspaces(&args)?;
    let from = side_for(args.from.as_deref(), Side::Baseline)?;
    let to = side_for(args.to.as_deref(), Side::Live)?;
    let unsynced = (to == Side::Live)
        .then(|| mvm_client::guest::sync_filesystems_if_running(&args.name).err())
        .flatten()
        .map(|error| format!("{error:#}"));

    let checkpoints = mvm_client::checkpoint::Checkpoints::open();
    let limits = args.limits();
    let mut volumes = Vec::with_capacity(workspaces.len());
    for workspace in &workspaces {
        let old = image_for(&checkpoints, workspace, &from)?;
        let new = image_for(&checkpoints, workspace, &to)?;
        let diff = diff_images(&old, &new, limits)
            .with_context(|| format!("diffing workspace volume {:?}", workspace.volume))?;
        volumes.push(VolumeReport {
            volume: workspace.volume.clone(),
            guest_path: workspace.guest_path.clone(),
            source_dir: workspace.source_dir.clone(),
            diff,
        });
    }
    let report = DiffReport {
        schema_version: 1,
        vm: args.name.clone(),
        from,
        to,
        unsynced,
        volumes,
    };
    print_report(&args, &report)
}

fn print_report(args: &Args, report: &DiffReport) -> Result<()> {
    if args.json {
        return crate::json_out::emit_json(report);
    }
    if let Some(reason) = &report.unsynced {
        crate::ui::warn(&format!(
            "the guest did not flush its writes ({reason}); showing what has reached the disk"
        ));
    }
    let several = report.volumes.len() > 1;
    let views: Vec<VolumeDiff<'_>> = report
        .volumes
        .iter()
        .map(|volume| VolumeDiff {
            prefix: if several { volume.volume.as_str() } else { "" },
            diff: &volume.diff,
        })
        .collect();
    if views.iter().all(|view| view.diff.stats.changed() == 0) {
        crate::ui::notice("no changes");
        return Ok(());
    }
    let text = if args.stat {
        render::stat(&views)
    } else if args.side_by_side {
        render::side_by_side(&views, terminal_width())
    } else {
        render::unified(&views)
    };
    print!("{text}");
    if let Some(notice) = render::truncation_notice(&views) {
        crate::ui::warn(&notice);
    }
    Ok(())
}

/// The workspaces the diff covers: all of them, or the one `--volume` names.
fn selected_workspaces(args: &Args) -> Result<Vec<Workspace>> {
    let all = workspaces_of(&args.name)?;
    if all.is_empty() {
        bail!(
            "machine {:?} has no workspace volume to diff; attach a host directory \
             read-write with `mvmctl machine volume mount {} --volume NAME --host DIR \
             --guest PATH --rw`",
            args.name,
            args.name
        );
    }
    match &args.volume {
        None => Ok(all),
        Some(name) => {
            let chosen: Vec<Workspace> = all.into_iter().filter(|w| &w.volume == name).collect();
            if chosen.is_empty() {
                bail!("machine {:?} has no workspace volume {name:?}", args.name);
            }
            Ok(chosen)
        }
    }
}

fn side_for(checkpoint: Option<&str>, default: Side) -> Result<Side> {
    Ok(match checkpoint {
        None => default,
        Some(raw) => Side::Checkpoint {
            id: super::checkpoint::validated_checkpoint_id(raw)?
                .as_str()
                .to_string(),
        },
    })
}

fn image_for(
    checkpoints: &mvm_client::checkpoint::Checkpoints,
    workspace: &Workspace,
    side: &Side,
) -> Result<PathBuf> {
    match side {
        Side::Baseline => baseline_image(workspace),
        Side::Live => Ok(workspace.image.clone()),
        Side::Checkpoint { id } => {
            let id = mvm_core::checkpoint::CheckpointId::new(id.clone());
            checkpoints.workspace_image(&id, &workspace.volume)
        }
    }
}

/// What the guest changed in `workspace` since it began, rendered the way
/// `machine diff` prints it. `None` when nothing changed.
pub(in crate::commands) fn workspace_changes_text(workspace: &Workspace) -> Result<Option<String>> {
    let diff = diff_images(
        &baseline_image(workspace)?,
        &workspace.image,
        DiffLimits::default(),
    )
    .with_context(|| format!("diffing workspace volume {:?}", workspace.volume))?;
    if diff.stats.changed() == 0 {
        return Ok(None);
    }
    let views = [VolumeDiff {
        prefix: "",
        diff: &diff,
    }];
    let mut text = render::unified(&views);
    if let Some(notice) = render::truncation_notice(&views) {
        text.push_str(&notice);
        text.push('\n');
    }
    Ok(Some(text))
}

/// Ask the running guest to flush its writes before its volume image is read.
pub(in crate::commands) fn flush_guest(name: &str) -> Result<()> {
    mvm_client::guest::sync_filesystems(name)
}

fn terminal_width() -> usize {
    // SAFETY: TIOCGWINSZ on stdout writes only into the zeroed struct.
    unsafe {
        let mut ws: libc::winsize = std::mem::zeroed();
        if libc::ioctl(1, libc::TIOCGWINSZ, &mut ws) == 0 && ws.ws_col > 0 {
            usize::from(ws.ws_col)
        } else {
            160
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unnamed_side_is_the_default_and_a_named_one_is_a_checkpoint() {
        assert_eq!(side_for(None, Side::Baseline).unwrap(), Side::Baseline);
        assert_eq!(
            side_for(Some("ckpt-a"), Side::Live).unwrap(),
            Side::Checkpoint {
                id: "ckpt-a".into()
            }
        );
        assert!(side_for(Some("../escape"), Side::Live).is_err());
    }

    #[test]
    fn the_report_names_both_sides_in_json() {
        let report = DiffReport {
            schema_version: 1,
            vm: "vm".into(),
            from: Side::Baseline,
            to: Side::Checkpoint {
                id: "ckpt-b".into(),
            },
            unsynced: None,
            volumes: Vec::new(),
        };
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["from"], serde_json::json!({"kind": "baseline"}));
        assert_eq!(
            json["to"],
            serde_json::json!({"kind": "checkpoint", "id": "ckpt-b"})
        );
        assert!(json.get("unsynced").is_none());
    }
}
