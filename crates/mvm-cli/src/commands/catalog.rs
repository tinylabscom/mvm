//! `mvmctl catalog` — browse the bundled image catalog. Plan 40
//! folded the old top-level `image` namespace down to this metadata
//! browser; project scaffolding from a catalog entry now goes through
//! `mvmctl init <DIR> --catalog <name>`.

use anyhow::Result;
use clap::{Args as ClapArgs, Subcommand};

use crate::ui;
use mvm_core::user_config::MvmConfig;

use super::Cli;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    #[command(subcommand)]
    pub action: CatalogAction,
}

#[derive(Subcommand, Debug, Clone)]
pub(in crate::commands) enum CatalogAction {
    /// List bundled catalog entries
    List,
    /// Search entries by name or tag
    Search {
        /// Search query
        query: String,
    },
    /// Print full details of one catalog entry as JSON
    Info {
        /// Entry name
        name: String,
    },
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    let catalog = load_bundled_catalog();

    match args.action {
        CatalogAction::List => {
            if catalog.entries.is_empty() {
                ui::info("No entries in catalog.");
            } else {
                println!(
                    "{:<20} {:<40} {:<6} {:<8}",
                    "NAME", "DESCRIPTION", "CPUS", "MEM"
                );
                for entry in &catalog.entries {
                    println!(
                        "{:<20} {:<40} {:<6} {:<8}",
                        entry.name,
                        entry.description,
                        entry.default_cpus,
                        format!("{}M", entry.default_memory_mib),
                    );
                }
            }
            Ok(())
        }
        CatalogAction::Search { query } => {
            let results = catalog.search(&query);
            if results.is_empty() {
                ui::info(&format!("No entries matching {:?}", query));
            } else {
                println!("{:<20} {:<40} {:<30}", "NAME", "DESCRIPTION", "TAGS");
                for entry in results {
                    println!(
                        "{:<20} {:<40} {:<30}",
                        entry.name,
                        entry.description,
                        entry.tags.join(", "),
                    );
                }
            }
            Ok(())
        }
        CatalogAction::Info { name } => {
            let entry = catalog
                .find(&name)
                .ok_or_else(|| anyhow::anyhow!("Catalog entry {:?} not found", name))?;
            println!("{}", serde_json::to_string_pretty(entry)?);
            Ok(())
        }
    }
}

/// Load the bundled image catalog with built-in presets.
pub(in crate::commands) fn load_bundled_catalog() -> mvm_core::catalog::Catalog {
    mvm_core::catalog::Catalog {
        schema_version: 1,
        entries: vec![
            mvm_core::catalog::CatalogEntry {
                name: "minimal".to_string(),
                description: "Bare-bones microVM with init only".to_string(),
                flake_ref: ".".to_string(),
                profile: "minimal".to_string(),
                default_cpus: 1,
                default_memory_mib: 256,
                tags: vec!["base".to_string(), "minimal".to_string()],
            },
            mvm_core::catalog::CatalogEntry {
                name: "http".to_string(),
                description: "HTTP server (Nginx or custom)".to_string(),
                flake_ref: ".".to_string(),
                profile: "http".to_string(),
                default_cpus: 2,
                default_memory_mib: 512,
                tags: vec!["web".to_string(), "http".to_string(), "nginx".to_string()],
            },
            mvm_core::catalog::CatalogEntry {
                name: "postgres".to_string(),
                description: "PostgreSQL database server".to_string(),
                flake_ref: ".".to_string(),
                profile: "postgres".to_string(),
                default_cpus: 2,
                default_memory_mib: 1024,
                tags: vec![
                    "database".to_string(),
                    "sql".to_string(),
                    "postgres".to_string(),
                ],
            },
            mvm_core::catalog::CatalogEntry {
                name: "worker".to_string(),
                description: "Background job worker".to_string(),
                flake_ref: ".".to_string(),
                profile: "worker".to_string(),
                default_cpus: 2,
                default_memory_mib: 512,
                tags: vec!["worker".to_string(), "background".to_string()],
            },
            mvm_core::catalog::CatalogEntry {
                name: "python".to_string(),
                description: "Python runtime environment".to_string(),
                flake_ref: ".".to_string(),
                profile: "python".to_string(),
                default_cpus: 2,
                default_memory_mib: 512,
                tags: vec!["python".to_string(), "runtime".to_string()],
            },
        ],
    }
}
