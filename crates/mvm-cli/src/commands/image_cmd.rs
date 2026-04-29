//! `mvmctl image` subcommand handlers.

use anyhow::Result;
use clap::Subcommand;

use crate::template_cmd;
use crate::ui;

#[derive(Subcommand)]
pub(crate) enum ImageCmd {
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

pub(super) fn cmd_image(action: ImageCmd) -> Result<()> {
    let catalog = load_bundled_catalog();

    match action {
        ImageCmd::List => {
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
        ImageCmd::Search { query } => {
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
        ImageCmd::Fetch { name } => {
            let entry = catalog
                .find(&name)
                .ok_or_else(|| anyhow::anyhow!("Image {:?} not found in catalog", name))?;

            ui::info(&format!(
                "Fetching image {:?} from {}...",
                entry.name, entry.flake_ref
            ));
            ui::info("This will create a template and build it via Nix.");
            ui::info(&format!(
                "Equivalent to: mvmctl template create {} --flake {} --profile {} && mvmctl template build {}",
                entry.name, entry.flake_ref, entry.profile, entry.name
            ));

            mvm_core::audit::emit(
                mvm_core::audit::LocalAuditKind::ImageFetch,
                None,
                Some(&name),
            );

            // Create a template from the catalog entry, then build it
            template_cmd::create_single(
                &entry.name,
                &entry.flake_ref,
                &entry.profile,
                "worker",
                entry.default_cpus,
                entry.default_memory_mib,
                0, // no data disk
            )?;
            ui::success(&format!("Created template {:?} from catalog.", entry.name));

            ui::info(&format!("Building template {:?}...", entry.name));
            template_cmd::build(&entry.name, false, false, None, false)?;
            ui::success(&format!(
                "Image {:?} is ready. Run with: mvmctl up --template {}",
                entry.name, entry.name
            ));
            Ok(())
        }
        ImageCmd::Info { name } => {
            let entry = catalog
                .find(&name)
                .ok_or_else(|| anyhow::anyhow!("Image {:?} not found in catalog", name))?;
            println!("{}", serde_json::to_string_pretty(entry)?);
            Ok(())
        }
    }
}

/// Load the bundled image catalog with built-in presets.
pub(super) fn load_bundled_catalog() -> mvm_core::catalog::Catalog {
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
