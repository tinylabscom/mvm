//! `mvmctl manifest tag <template> {add,rm,ls}` — manage the
//! free-form tag set on a built template / manifest.
//!
//! Tags are persisted at `~/.mvm/templates/<template>/tags.json`
//! via `mvm_core::domain::template_tags`. They're tenant-controlled
//! so the same charset/length validation runs on every input.

use anyhow::{Context, Result, bail};
use clap::{Args as ClapArgs, Subcommand};

use mvm_core::domain::template_tags::TemplateTags;
use mvm_core::naming::validate_template_name;
use mvm_core::user_config::MvmConfig;

use super::super::Cli;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    #[command(subcommand)]
    pub action: TagAction,
}

#[derive(Subcommand, Debug, Clone)]
pub(in crate::commands) enum TagAction {
    /// Add a tag to the template
    Add {
        /// Template name (manifest slot)
        template: String,
        /// Tag value
        tag: String,
    },
    /// Remove a tag from the template
    Rm { template: String, tag: String },
    /// List the template's tags
    Ls {
        template: String,
        #[arg(long)]
        json: bool,
    },
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    match args.action {
        TagAction::Add { template, tag } => add(&template, &tag),
        TagAction::Rm { template, tag } => rm(&template, &tag),
        TagAction::Ls { template, json } => ls(&template, json),
    }
}

fn add(template: &str, tag: &str) -> Result<()> {
    validate_template_name(template)
        .with_context(|| format!("invalid template name {:?}", template))?;
    let mut catalog = TemplateTags::load(template)
        .with_context(|| format!("loading tags catalog for {:?}", template))?;
    catalog.add_tag(tag).context("adding tag")?;
    catalog
        .save(template)
        .with_context(|| format!("saving tags catalog for {:?}", template))?;
    println!("{template}: added tag {tag:?}");
    mvm_core::audit_emit!(ManifestTagAdd, "template={template} tag={tag}");
    Ok(())
}

fn rm(template: &str, tag: &str) -> Result<()> {
    validate_template_name(template)
        .with_context(|| format!("invalid template name {:?}", template))?;
    let mut catalog = TemplateTags::load(template)?;
    if !catalog.remove_tag(tag) {
        bail!("template {template:?} has no tag {tag:?}");
    }
    catalog.save(template)?;
    println!("{template}: removed tag {tag:?}");
    mvm_core::audit_emit!(ManifestTagRemove, "template={template} tag={tag}");
    Ok(())
}

fn ls(template: &str, json: bool) -> Result<()> {
    validate_template_name(template)
        .with_context(|| format!("invalid template name {:?}", template))?;
    let catalog = TemplateTags::load(template)?;
    if json {
        // Render as a sorted array; BTreeSet iteration is already
        // sorted but explicitly Vec'ing keeps the wire shape stable
        // for SDK callers.
        let arr: Vec<&String> = catalog.tags.iter().collect();
        println!("{}", serde_json::to_string_pretty(&arr)?);
        return Ok(());
    }
    if catalog.tags.is_empty() {
        println!("(no tags)");
        return Ok(());
    }
    for tag in &catalog.tags {
        println!("{tag}");
    }
    Ok(())
}
