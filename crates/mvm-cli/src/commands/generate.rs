//! `mvmctl generate` — unified project-generation entry point.
//!
//! This verb wraps the existing generation paths so users don't have to
//! remember whether a workload starts from an SDK source file, a catalog
//! preset, or a natural-language prompt:
//!
//!   - `mvmctl generate sdk app.py -o ./my-app`      → `build compile`
//!   - `mvmctl generate template python ./my-app`    → `init --catalog python`
//!   - `mvmctl generate prompt "python api" ./my-app` → `init --prompt "..."`
//!
//! The generated directory contains a runnable mvm project: `flake.nix`,
//! `mvm.toml`, and any baseline/source files the chosen generator needs.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Args as ClapArgs, Subcommand};

use mvm_core::user_config::MvmConfig;

use super::Cli;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    #[command(subcommand)]
    pub action: GenerateAction,
}

#[derive(Subcommand, Debug, Clone)]
pub(in crate::commands) enum GenerateAction {
    /// Generate from an SDK-decorated `.py` or `.ts` source file.
    ///
    /// Runs the same pipeline as `mvmctl build compile`: parses the
    /// decorator, emits `flake.nix` + `launch.json`, and bundles the
    /// source tree into `--out <dir>`.
    Sdk {
        /// Path to the `.py`/`.ts` script carrying `@mvm.app(...)`.
        script: PathBuf,

        /// Output directory for the generated project.
        #[arg(short = 'o', long = "out", value_name = "DIR", default_value = "./out")]
        out: PathBuf,
    },

    /// Generate from a bundled catalog entry or scaffold preset.
    ///
    /// Names are matched first against `mvmctl catalog list`; if no
    /// catalog entry matches, the known presets (`minimal`, `http`,
    /// `postgres`, `worker`, `python`) are tried.
    Template {
        /// Catalog entry or preset name.
        name: String,

        /// Directory to scaffold.
        dir: String,
    },

    /// Generate from a natural-language description.
    ///
    /// Routes through the same planner as `mvmctl init --prompt`. If a
    /// hosted or local LLM provider is configured, the prompt is sent to
    /// it; otherwise a heuristic planner picks a preset and fills in the
    /// details.
    Prompt {
        /// Natural-language description of the workload.
        description: String,

        /// Directory to scaffold.
        dir: String,
    },
}

pub(in crate::commands) fn run(cli: &Cli, args: Args, cfg: &MvmConfig) -> Result<()> {
    match args.action {
        GenerateAction::Sdk { script, out } => generate_sdk(cli, script, out, cfg),
        GenerateAction::Template { name, dir } => generate_template(&name, &dir),
        GenerateAction::Prompt { description, dir } => generate_prompt(&description, &dir),
    }
}

fn generate_sdk(cli: &Cli, script: PathBuf, out: PathBuf, cfg: &MvmConfig) -> Result<()> {
    let script = script
        .canonicalize()
        .with_context(|| format!("failed to resolve script path: {}", script.display()))?;

    let compile_args = super::build::compile::Args {
        entry: Some(script.to_string_lossy().into_owned()),
        from_ir: None,
        from_recording: None,
        recording_sha256: None,
        out,
        mode: None,
        prod: false,
        dev: false,
    };
    super::build::compile::run(cli, compile_args, cfg)
}

fn generate_template(name: &str, dir: &str) -> Result<()> {
    let catalog = super::catalog::load_bundled_catalog();
    let preset = catalog
        .find(name)
        .map(|entry| entry.profile.as_str())
        .unwrap_or(name);

    crate::template_cmd::init(dir, true, ".", Some(preset), None)
}

fn generate_prompt(description: &str, dir: &str) -> Result<()> {
    crate::template_cmd::init(dir, true, ".", None, Some(description))
}
