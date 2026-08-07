//! `mvmctl template` — browse bundled and remote microVM templates.
//!
//! Templates are parameterized project scaffolds. The bundled core set
//! ships offline with `mvmctl`; additional templates live in a separate
//! registry repository and are fetched on demand.

use anyhow::Result;
use clap::{Args as ClapArgs, Subcommand};

use mvm_core::user_config::MvmConfig;

use super::Cli;
use crate::template_registry::{RegistryConfig, list_available, search_remote};

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    #[command(subcommand)]
    pub action: TemplateAction,
}

#[derive(Subcommand, Debug, Clone)]
pub(in crate::commands) enum TemplateAction {
    /// List available templates (bundled + cached remote).
    List,
    /// Search the remote registry for templates matching a query.
    Search {
        /// Search query.
        query: String,
    },
    /// Show details for one template (bundled or remote).
    Info {
        /// Template name.
        name: String,
    },
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    // Synchronous entry point; network paths spawn a temporary runtime.
    let cfg = RegistryConfig::load();
    match args.action {
        TemplateAction::List => run_list(&cfg),
        TemplateAction::Search { query } => run_search(&cfg, &query),
        TemplateAction::Info { name } => run_info(&cfg, &name),
    }
}

fn run_list(cfg: &RegistryConfig) -> Result<()> {
    let entries = list_available(cfg);
    if entries.is_empty() {
        println!("No templates available.");
        return Ok(());
    }
    print_table(&entries);
    Ok(())
}

fn run_search(cfg: &RegistryConfig, query: &str) -> Result<()> {
    let entries = tokio_block(search_remote(cfg, query))?;
    if entries.is_empty() {
        println!("No remote templates matched {:?}.", query);
        return Ok(());
    }
    print_table(&entries);
    Ok(())
}

fn run_info(cfg: &RegistryConfig, name: &str) -> Result<()> {
    let entry: crate::template_registry::TemplateEntry =
        tokio_block(crate::template_registry::resolve(cfg, name))?;
    println!("name:        {}", entry.name);
    println!("description: {}", entry.description);
    println!("cpus:        {}", entry.default_cpus);
    println!("memory:      {}M", entry.default_memory_mib);
    if !entry.tags.is_empty() {
        println!("tags:        {}", entry.tags.join(", "));
    }
    match entry.source {
        crate::template_registry::TemplateSource::Bundled { .. } => {
            println!("source:      bundled");
        }
        crate::template_registry::TemplateSource::Remote { cache_dir } => {
            println!("source:      remote");
            println!("cache:       {}", cache_dir.display());
        }
    }
    Ok(())
}

fn print_table(entries: &[crate::template_registry::TemplateEntry]) {
    println!(
        "{:<20} {:<50} {:<6} {:<8}",
        "NAME", "DESCRIPTION", "CPUS", "MEM"
    );
    for entry in entries {
        println!(
            "{:<20} {:<50} {:<6} {:<8}",
            entry.name,
            truncate(&entry.description, 49),
            entry.default_cpus,
            format!("{}M", entry.default_memory_mib),
        );
    }
}

fn truncate(s: &str, max_len: usize) -> String {
    if s.chars().count() <= max_len {
        s.to_string()
    } else {
        format!(
            "{}…",
            s.chars()
                .take(max_len.saturating_sub(1))
                .collect::<String>()
        )
    }
}

fn tokio_block<F, T>(future: F) -> Result<T>
where
    F: std::future::Future<Output = Result<T>>,
{
    tokio::runtime::Runtime::new()?.block_on(future)
}
