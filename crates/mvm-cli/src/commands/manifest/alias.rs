//! `mvmctl manifest alias <template> {set,rm,ls}` — manage movable
//! `alias → revision_hash` pointers on a built template. W1 / A6
//! of the filesystem-volumes plan.
//!
//! Aliases let `mvmctl machine run --manifest <template>@<alias>` resolve
//! to the revision the alias currently points at. `set` is
//! force-shaped (overwrites silently), mirroring `git tag -f`.
//!
//! Persisted alongside tags in
//! `~/.mvm/templates/<template>/tags.json`.

use anyhow::{Context, Result, bail};
use clap::{Args as ClapArgs, Subcommand};

use mvm_core::domain::template_tags::TemplateTags;
use mvm_core::naming::validate_template_name;
use mvm_core::user_config::MvmConfig;

use super::super::Cli;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    #[command(subcommand)]
    pub action: AliasAction,
}

#[derive(Subcommand, Debug, Clone)]
pub(in crate::commands) enum AliasAction {
    /// Set or move an alias to point at a revision hash
    Set {
        /// Template name (manifest slot)
        template: String,
        /// Alias name (e.g. `latest`, `stable`, `v1`)
        alias: String,
        /// Revision hash the alias points to
        revision_hash: String,
    },
    /// Remove an alias
    Rm { template: String, alias: String },
    /// List the template's aliases
    Ls {
        template: String,
        #[arg(long)]
        json: bool,
    },
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    match args.action {
        AliasAction::Set {
            template,
            alias,
            revision_hash,
        } => set(&template, &alias, &revision_hash),
        AliasAction::Rm { template, alias } => rm(&template, &alias),
        AliasAction::Ls { template, json } => ls(&template, json),
    }
}

fn set(template: &str, alias: &str, revision_hash: &str) -> Result<()> {
    validate_template_name(template)
        .with_context(|| format!("invalid template name {:?}", template))?;
    let mut catalog = TemplateTags::load(template)?;
    catalog
        .set_alias(alias, revision_hash)
        .with_context(|| format!("setting alias {alias:?} → {revision_hash:?}"))?;
    catalog.save(template)?;
    println!("{template}: alias {alias:?} → {revision_hash}");
    mvm_core::audit_emit!(
        ManifestAliasSet,
        "template={template} alias={alias} rev={revision_hash}"
    );
    Ok(())
}

fn rm(template: &str, alias: &str) -> Result<()> {
    validate_template_name(template)
        .with_context(|| format!("invalid template name {:?}", template))?;
    let mut catalog = TemplateTags::load(template)?;
    if !catalog.remove_alias(alias) {
        bail!("template {template:?} has no alias {alias:?}");
    }
    catalog.save(template)?;
    println!("{template}: removed alias {alias:?}");
    mvm_core::audit_emit!(ManifestAliasRemove, "template={template} alias={alias}");
    Ok(())
}

fn ls(template: &str, json: bool) -> Result<()> {
    validate_template_name(template)
        .with_context(|| format!("invalid template name {:?}", template))?;
    let catalog = TemplateTags::load(template)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&catalog.aliases)?);
        return Ok(());
    }
    if catalog.aliases.is_empty() {
        println!("(no aliases)");
        return Ok(());
    }
    for (alias, revision_hash) in &catalog.aliases {
        println!("{alias} → {revision_hash}");
    }
    Ok(())
}
