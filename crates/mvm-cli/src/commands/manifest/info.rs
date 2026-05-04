//! `mvmctl manifest info` — show details for one slot.

use anyhow::{Context, Result};
use clap::Args as ClapArgs;

use mvm_core::manifest::{canonical_key_for_path, resolve_manifest_config_path};
use mvm_core::user_config::MvmConfig;
use mvm_runtime::vm::template::lifecycle as tmpl;

use super::super::Cli;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// Manifest path (file or directory). Defaults to walking up from cwd.
    #[arg(value_name = "PATH")]
    pub path: Option<String>,
    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    let manifest_path = match args.path.as_deref() {
        Some(p) => resolve_manifest_config_path(std::path::Path::new(p))?,
        None => {
            let cwd = std::env::current_dir().context("Failed to read cwd")?;
            mvm_core::manifest::discover_manifest_from_dir(&cwd)?
                .ok_or_else(|| anyhow::anyhow!(
                    "No manifest found from cwd. Run `mvmctl init` to create one, or pass a path explicitly."
                ))?
        }
    };

    let canonical = std::fs::canonicalize(&manifest_path).with_context(|| {
        format!(
            "Failed to canonicalize manifest path {}",
            manifest_path.display()
        )
    })?;
    let slot_hash = canonical_key_for_path(&canonical)?;
    let persisted = tmpl::template_load_slot(&slot_hash).with_context(|| {
        format!(
            "Manifest at {} has no built slot — run `mvmctl build {}` first",
            canonical.display(),
            canonical.display()
        )
    })?;

    let revision = tmpl::template_snapshot_info_for_slot(&slot_hash).ok().flatten();

    if args.json {
        #[derive(serde::Serialize)]
        struct Out {
            slot_hash: String,
            persisted: mvm_core::manifest::PersistedManifest,
            snapshot: Option<mvm_core::template::SnapshotInfo>,
        }
        println!(
            "{}",
            serde_json::to_string_pretty(&Out {
                slot_hash,
                persisted,
                snapshot: revision,
            })?
        );
        return Ok(());
    }

    let label = persisted.name.as_deref().unwrap_or("(unnamed)");
    println!("Manifest: {}", persisted.manifest_path);
    println!("  Slot:       {}", persisted.manifest_hash);
    println!("  Name:       {}", label);
    println!("  Flake:      {}", persisted.flake_ref);
    println!("  Profile:    {}", persisted.profile);
    println!("  vCPUs:      {}", persisted.vcpus);
    println!("  Mem (MiB):  {}", persisted.mem_mib);
    println!("  Disk (MiB): {}", persisted.data_disk_mib);
    println!("  Backend:    {}", persisted.backend);
    println!("  Built at:   {}", persisted.updated_at);
    println!("  Toolchain:  {}", persisted.provenance.toolchain_version);
    println!("  Host arch:  {}", persisted.provenance.host_arch);
    if let Some(ir) = &persisted.provenance.ir_hash {
        println!("  IR hash:    {}", ir);
    }
    if let Some(snap) = revision {
        println!("\nSnapshot: yes (created {})", snap.created_at);
    } else {
        println!("\nSnapshot: none — `mvmctl build --snapshot` to create one");
    }

    Ok(())
}
