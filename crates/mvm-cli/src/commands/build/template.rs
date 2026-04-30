//! `mvmctl template` subcommand handlers.

use anyhow::{Context, Result};
use clap::{Args as ClapArgs, Subcommand};

use mvm_core::naming::{validate_flake_ref, validate_template_name};
use mvm_core::user_config::MvmConfig;
use mvm_core::util::parse_human_size;

use crate::template_cmd;

use super::Cli;
use super::shared::clap_flake_ref;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    #[command(subcommand)]
    pub action: TemplateAction,
}

#[derive(Subcommand, Debug, Clone)]
pub(in crate::commands) enum TemplateAction {
    /// Create a new template (single role/profile)
    #[command(alias = "new")]
    Create {
        /// Template name (e.g. "base", "openclaw")
        name: String,
        /// Nix flake reference for the template source
        #[arg(long, default_value = ".", value_parser = clap_flake_ref)]
        flake: String,
        /// Flake package variant
        #[arg(long, default_value = "default")]
        profile: String,
        /// VM role (worker or gateway)
        #[arg(long, default_value = "worker")]
        role: String,
        /// Default vCPU count for VMs using this template
        #[arg(long, default_value = "2")]
        cpus: u8,
        /// Default memory (supports human-readable sizes: 512M, 4G, or plain MB)
        #[arg(long, default_value = "1024")]
        mem: String,
        /// Data disk size (supports human-readable sizes: 10G, 512M, or plain MB; 0 = no disk)
        #[arg(long, default_value = "0")]
        data_disk: String,
    },
    /// Create multiple role-specific templates (name-role)
    CreateMulti {
        /// Base template name (each role becomes <base>-<role>)
        base: String,
        /// Nix flake reference for the template source
        #[arg(long, default_value = ".", value_parser = clap_flake_ref)]
        flake: String,
        /// Flake package variant
        #[arg(long, default_value = "default")]
        profile: String,
        /// Comma-separated roles, e.g. gateway,agent
        #[arg(long)]
        roles: String,
        /// Default vCPU count for VMs using this template
        #[arg(long, default_value = "2")]
        cpus: u8,
        /// Default memory (supports human-readable sizes: 512M, 4G, or plain MB)
        #[arg(long, default_value = "1024")]
        mem: String,
        /// Data disk size (supports human-readable sizes: 10G, 512M, or plain MB; 0 = no disk)
        #[arg(long, default_value = "0")]
        data_disk: String,
    },
    /// Build a template (shared image via nix build)
    #[command(alias = "b")]
    Build {
        /// Template name to build
        name: String,
        /// Rebuild even if a cached revision exists
        #[arg(long)]
        force: bool,
        /// After build, boot VM, wait for healthy, and create a snapshot for instant starts
        #[arg(long)]
        snapshot: bool,
        /// Optional template config TOML to build multiple variants
        #[arg(long)]
        config: Option<String>,
        /// Recompute the Nix fixed-output derivation hash (use after version bump)
        #[arg(long)]
        update_hash: bool,
    },
    /// Push a built template revision to the object storage registry
    Push {
        /// Template name to push
        name: String,
        /// Revision hash to push (defaults to current)
        #[arg(long)]
        revision: Option<String>,
    },
    /// Pull a template revision from the object storage registry
    Pull {
        /// Template name to pull
        name: String,
        /// Revision hash to pull (defaults to registry current)
        #[arg(long)]
        revision: Option<String>,
    },
    /// Verify a locally installed template revision against checksums.json
    Verify {
        /// Template name to verify
        name: String,
        /// Revision hash to verify (defaults to current)
        #[arg(long)]
        revision: Option<String>,
    },
    /// List all templates
    #[command(alias = "ls")]
    List {
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Show template details (spec, revisions, cache key)
    #[command(alias = "show")]
    Info {
        /// Template name
        name: String,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Edit an existing template's configuration
    Edit {
        /// Template name to edit
        name: String,
        /// Update Nix flake reference
        #[arg(long)]
        flake: Option<String>,
        /// Update flake package variant
        #[arg(long)]
        profile: Option<String>,
        /// Update VM role
        #[arg(long)]
        role: Option<String>,
        /// Update vCPU count
        #[arg(long)]
        cpus: Option<u8>,
        /// Update memory (supports human-readable sizes: 512M, 4G, or plain MB)
        #[arg(long)]
        mem: Option<String>,
        /// Update data disk size (supports human-readable sizes: 10G, 512M, or plain MB)
        #[arg(long)]
        data_disk: Option<String>,
    },
    /// Delete a template and its artifacts
    Delete {
        /// Template name to delete
        name: String,
        /// Skip confirmation prompt
        #[arg(long)]
        force: bool,
    },
    /// Initialize on-disk template layout (idempotent)
    Init {
        /// Template name to initialize
        name: String,
        /// Create locally instead of in ~/.mvm/templates
        #[arg(long)]
        local: bool,
        /// Create inside the Lima VM (overrides --local)
        #[arg(long)]
        vm: bool,
        /// Base directory for local init (default: current dir)
        #[arg(long, default_value = ".")]
        dir: String,
        /// Scaffold preset: minimal, http, postgres, worker, python (default: minimal)
        #[arg(long)]
        preset: Option<String>,
        /// Natural-language prompt used to generate a local scaffold and metadata (uses OpenAI when OPENAI_API_KEY is set)
        #[arg(long)]
        prompt: Option<String>,
    },
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    match args.action {
        TemplateAction::Create {
            name,
            flake,
            profile,
            role,
            cpus,
            mem,
            data_disk,
        } => {
            validate_template_name(&name)
                .with_context(|| format!("Invalid template name: {:?}", name))?;
            validate_flake_ref(&flake)
                .with_context(|| format!("Invalid flake reference: {:?}", flake))?;
            let mem_mb = parse_human_size(&mem).context("Invalid memory size")?;
            let data_disk_mb = parse_human_size(&data_disk).context("Invalid data disk size")?;
            template_cmd::create_single(&name, &flake, &profile, &role, cpus, mem_mb, data_disk_mb)
        }
        TemplateAction::CreateMulti {
            base,
            flake,
            profile,
            roles,
            cpus,
            mem,
            data_disk,
        } => {
            validate_template_name(&base)
                .with_context(|| format!("Invalid template base name: {:?}", base))?;
            validate_flake_ref(&flake)
                .with_context(|| format!("Invalid flake reference: {:?}", flake))?;
            let mem_mb = parse_human_size(&mem).context("Invalid memory size")?;
            let data_disk_mb = parse_human_size(&data_disk).context("Invalid data disk size")?;
            let role_list: Vec<String> = roles.split(',').map(|s| s.trim().to_string()).collect();
            template_cmd::create_multi(
                &base,
                &flake,
                &profile,
                &role_list,
                cpus,
                mem_mb,
                data_disk_mb,
            )
        }
        TemplateAction::Build {
            name,
            force,
            snapshot,
            config,
            update_hash,
        } => {
            validate_template_name(&name)
                .with_context(|| format!("Invalid template name: {:?}", name))?;
            template_cmd::build(&name, force, snapshot, config.as_deref(), update_hash)
        }
        TemplateAction::Push { name, revision } => {
            validate_template_name(&name)
                .with_context(|| format!("Invalid template name: {:?}", name))?;
            template_cmd::push(&name, revision.as_deref())
        }
        TemplateAction::Pull { name, revision } => {
            validate_template_name(&name)
                .with_context(|| format!("Invalid template name: {:?}", name))?;
            template_cmd::pull(&name, revision.as_deref())
        }
        TemplateAction::Verify { name, revision } => {
            validate_template_name(&name)
                .with_context(|| format!("Invalid template name: {:?}", name))?;
            template_cmd::verify(&name, revision.as_deref())
        }
        TemplateAction::List { json } => template_cmd::list(json),
        TemplateAction::Info { name, json } => {
            validate_template_name(&name)
                .with_context(|| format!("Invalid template name: {:?}", name))?;
            template_cmd::info(&name, json)
        }
        TemplateAction::Edit {
            name,
            flake,
            profile,
            role,
            cpus,
            mem,
            data_disk,
        } => {
            validate_template_name(&name)
                .with_context(|| format!("Invalid template name: {:?}", name))?;
            if let Some(ref f) = flake {
                validate_flake_ref(f)
                    .with_context(|| format!("Invalid flake reference: {:?}", f))?;
            }
            let mem_mb = mem
                .as_ref()
                .map(|s| parse_human_size(s))
                .transpose()
                .context("Invalid memory size")?;
            let data_disk_mb = data_disk
                .as_ref()
                .map(|s| parse_human_size(s))
                .transpose()
                .context("Invalid data disk size")?;
            template_cmd::edit(
                &name,
                flake.as_deref(),
                profile.as_deref(),
                role.as_deref(),
                cpus,
                mem_mb,
                data_disk_mb,
            )
        }
        TemplateAction::Delete { name, force } => {
            validate_template_name(&name)
                .with_context(|| format!("Invalid template name: {:?}", name))?;
            template_cmd::delete(&name, force)
        }
        TemplateAction::Init {
            name,
            local,
            vm,
            dir,
            preset,
            prompt,
        } => {
            validate_template_name(&name)
                .with_context(|| format!("Invalid template name: {:?}", name))?;
            let use_local = local && !vm;
            template_cmd::init(&name, use_local, &dir, preset.as_deref(), prompt.as_deref())
        }
    }
}
