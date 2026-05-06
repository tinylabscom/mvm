//! `mvmctl manifest prune` — sweep orphaned slots.

use anyhow::Result;
use clap::Args as ClapArgs;

use mvm_core::user_config::MvmConfig;
use mvm_runtime::vm::template::lifecycle as tmpl;

use super::super::Cli;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// Remove slots whose source manifest file is missing on disk.
    /// (Today this is the only prune mode; the flag is required so
    /// the verb is explicit and future modes — `--all`, `--legacy`,
    /// `--keep <N>` — slot in cleanly.)
    #[arg(long)]
    pub orphans: bool,
    /// Show what would be removed without actually deleting.
    #[arg(long)]
    pub dry_run: bool,
    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    if !args.orphans {
        anyhow::bail!(
            "no prune mode specified. Pass `--orphans` to remove slots whose manifest file is gone."
        );
    }

    if args.dry_run {
        return run_dry(args.json);
    }

    let (count, removed) = tmpl::template_prune_orphan_slots()?;

    mvm_core::audit::emit(
        mvm_core::audit::LocalAuditKind::SlotPrune,
        None,
        Some(&format!("source=manifest_prune count={count}")),
    );

    if args.json {
        #[derive(serde::Serialize)]
        struct Out {
            removed_count: usize,
            removed: Vec<String>,
        }
        println!(
            "{}",
            serde_json::to_string_pretty(&Out {
                removed_count: count,
                removed,
            })?
        );
        return Ok(());
    }

    if count == 0 {
        println!("No orphaned slots.");
    } else {
        println!("Removed {} orphaned slot(s):", count);
        for h in removed {
            println!("  {}", &h[..h.len().min(12)]);
        }
    }
    Ok(())
}

fn run_dry(json: bool) -> Result<()> {
    // Re-walk slots and predict orphans without deleting. We use the
    // same classification as `template_prune_orphan_slots` but skip
    // the delete step.
    use mvm_core::manifest::PersistedManifest;

    let mut would_remove: Vec<(String, String)> = Vec::new(); // (slot_hash, reason)
    for slot_hash in tmpl::template_list_slot_hashes()? {
        let dir = mvm_core::manifest::slot_dir(&slot_hash);
        let persisted = PersistedManifest::read_from_slot(std::path::Path::new(&dir));
        match persisted {
            Ok(p) if !std::path::Path::new(&p.manifest_path).exists() => {
                would_remove.push((slot_hash, format!("manifest gone: {}", p.manifest_path)));
            }
            Err(e) => {
                would_remove.push((slot_hash, format!("unreadable manifest.json: {e}")));
            }
            Ok(_) => {}
        }
    }

    if json {
        #[derive(serde::Serialize)]
        struct Row {
            slot_hash: String,
            reason: String,
        }
        let rows: Vec<Row> = would_remove
            .into_iter()
            .map(|(slot_hash, reason)| Row { slot_hash, reason })
            .collect();
        println!("{}", serde_json::to_string_pretty(&rows)?);
        return Ok(());
    }

    if would_remove.is_empty() {
        println!("(dry-run) No orphaned slots.");
    } else {
        println!(
            "(dry-run) Would remove {} orphaned slot(s):",
            would_remove.len()
        );
        for (h, reason) in would_remove {
            println!("  {}  ({})", &h[..h.len().min(12)], reason);
        }
    }
    Ok(())
}
