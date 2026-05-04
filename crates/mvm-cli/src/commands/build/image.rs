//! `mvmctl image` subcommand handlers.

use anyhow::Result;
use clap::{Args as ClapArgs, Subcommand};

use crate::ui;
use mvm_core::user_config::MvmConfig;

use super::Cli;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    #[command(subcommand)]
    pub action: ImageAction,
}

#[derive(Subcommand, Debug, Clone)]
pub(in crate::commands) enum ImageAction {
    /// List available images in the catalog
    #[command(alias = "ls")]
    List,
    /// Search images by name or tag
    Search {
        /// Search query
        query: String,
    },
    /// Fetch (build) an image from the catalog
    Fetch {
        /// Image name from the catalog
        name: String,
    },
    /// Show details of a catalog image
    Info {
        /// Image name from the catalog
        name: String,
    },
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    let catalog = load_bundled_catalog();

    match args.action {
        ImageAction::List => {
            if catalog.entries.is_empty() {
                ui::info("No images in catalog.");
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
        ImageAction::Search { query } => {
            let results = catalog.search(&query);
            if results.is_empty() {
                ui::info(&format!("No images matching {:?}", query));
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
        ImageAction::Fetch { name } => {
            // Plan 38 §4 (slice 7b): the `template *` namespace is gone.
            // `image fetch` previously synthesised a name-keyed template
            // and ran `template build`; with manifest-keyed slots the
            // equivalent flow is to scaffold an `mvm.toml` directory and
            // run `mvmctl build` against it. Slice 7c rewires this path
            // around the new verbs; for now we surface a copy-pasteable
            // recipe so the catalog stays useful.
            let entry = catalog
                .find(&name)
                .ok_or_else(|| anyhow::anyhow!("Image {:?} not found in catalog", name))?;

            mvm_core::audit::emit(
                mvm_core::audit::LocalAuditKind::ImageFetch,
                None,
                Some(&name),
            );

            ui::info(&format!("Catalog entry: {:?}", entry.name));
            ui::info(&format!("  flake:   {}", entry.flake_ref));
            ui::info(&format!("  profile: {}", entry.profile));
            ui::info(&format!(
                "  vcpus:   {}, mem: {} MiB",
                entry.default_cpus, entry.default_memory_mib
            ));
            ui::info("");
            ui::info("To materialise this catalog entry as a buildable manifest:");
            ui::info(&format!("  mkdir -p ./{}", entry.name));
            ui::info(&format!("  cat > ./{}/mvm.toml <<EOF", entry.name));
            ui::info(&format!("  flake = \"{}\"", entry.flake_ref));
            ui::info(&format!("  profile = \"{}\"", entry.profile));
            ui::info(&format!("  vcpus = {}", entry.default_cpus));
            ui::info(&format!(
                "  mem = \"{}M\"",
                entry.default_memory_mib
            ));
            ui::info("  data_disk = \"0\"");
            ui::info(&format!("  name = \"{}\"", entry.name));
            ui::info("  EOF");
            ui::info(&format!("  mvmctl build ./{}", entry.name));
            ui::info(&format!("  mvmctl up ./{}", entry.name));
            Ok(())
        }
        ImageAction::Info { name } => {
            let entry = catalog
                .find(&name)
                .ok_or_else(|| anyhow::anyhow!("Image {:?} not found in catalog", name))?;
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
