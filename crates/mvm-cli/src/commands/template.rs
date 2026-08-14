//! `mvmctl template` — browse, build, and inspect microVM templates.
//!
//! Templates are reusable workload bases. The bundled core set ships offline
//! with `mvmctl`; built-in image templates provide pinned OCI runtimes for
//! common languages; user-built image templates are created with
//! `mvmctl template build --image <ref>`; and additional templates live in a
//! separate registry repository fetched on demand.

use anyhow::{Context, Result};
use clap::{Args as ClapArgs, Subcommand};

use mvm_core::user_config::MvmConfig;

use super::Cli;
use crate::template_registry::{
    RegistryConfig, list_available, persist_built_image_template, search_remote,
};

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    #[command(subcommand)]
    pub action: TemplateAction,
}

#[derive(Subcommand, Debug, Clone)]
pub(in crate::commands) enum TemplateAction {
    /// List available templates (built + built-in image + bundled + cached remote).
    List,
    /// Build a reusable image-backed template from an OCI reference.
    Build {
        /// OCI image reference (e.g. `python:3.12-alpine`).
        #[arg(long, value_name = "REF")]
        image: String,
        /// Name for the template. Defaults to the image repository basename.
        #[arg(long, value_name = "NAME")]
        name: Option<String>,
        /// Human-readable description.
        #[arg(long, value_name = "TEXT")]
        description: Option<String>,
        /// Default vCPUs for runs using this template.
        #[arg(long, value_name = "N")]
        cpus: Option<u8>,
        /// Default memory in MiB for runs using this template.
        #[arg(long, value_name = "MIB")]
        memory: Option<u32>,
    },
    /// Search the remote registry for templates matching a query.
    Search {
        /// Search query.
        query: String,
    },
    /// Show details for one template (built, bundled, or remote).
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
        TemplateAction::Build {
            image,
            name,
            description,
            cpus,
            memory,
        } => run_build(
            &image,
            name.as_deref(),
            description.as_deref(),
            cpus,
            memory,
        ),
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

fn run_build(
    image_ref: &str,
    name: Option<&str>,
    description: Option<&str>,
    cpus: Option<u8>,
    memory: Option<u32>,
) -> Result<()> {
    let name = name
        .map(ToString::to_string)
        .unwrap_or_else(|| default_name_from_image_ref(image_ref));

    persist_built_image_template(&name, image_ref, description, cpus, memory)
        .with_context(|| format!("persisting built template {name}"))?;

    println!("Built image template '{name}' from {image_ref}");
    println!("Use it with: mvmctl run --template {name} -- <cmd>...");
    Ok(())
}

fn default_name_from_image_ref(image_ref: &str) -> String {
    // Strip tag/digest and repository prefix; keep the last path component.
    let without_digest = image_ref
        .split_once('@')
        .map(|(l, _)| l)
        .unwrap_or(image_ref);
    let without_tag = without_digest
        .split_once(':')
        .map(|(l, _)| l)
        .unwrap_or(without_digest);
    without_tag
        .split('/')
        .next_back()
        .unwrap_or(without_tag)
        .to_string()
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
        crate::template_registry::TemplateSource::Image { image_ref } => {
            println!("source:      image");
            println!("image:       {image_ref}");
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
