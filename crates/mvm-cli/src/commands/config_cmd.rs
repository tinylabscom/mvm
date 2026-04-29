//! `mvmctl config` subcommand handlers.

use anyhow::{Context, Result};
use clap::Subcommand;

#[derive(Subcommand)]
pub(crate) enum ConfigAction {
    /// Print current config as TOML
    Show,
    /// Open the config file in $EDITOR (falls back to nano)
    Edit,
    /// Set a single config key
    Set {
        /// Config key (e.g. lima_cpus)
        key: String,
        /// New value
        value: String,
    },
}

pub(super) fn cmd_config(action: ConfigAction) -> Result<()> {
    match action {
        ConfigAction::Show => cmd_config_show(),
        ConfigAction::Edit => cmd_config_edit(),
        ConfigAction::Set { key, value } => cmd_config_set(&key, &value),
    }
}

fn cmd_config_show() -> Result<()> {
    let cfg = mvm_core::user_config::load(None);
    let text = toml::to_string_pretty(&cfg).context("Failed to serialize config")?;
    print!("{}", text);
    Ok(())
}

fn cmd_config_edit() -> Result<()> {
    // Ensure config file exists (load creates it with defaults if absent).
    let _ = mvm_core::user_config::load(None);
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    let config_path = std::path::PathBuf::from(home)
        .join(".mvm")
        .join("config.toml");
    let editor = std::env::var("EDITOR").unwrap_or_else(|_| "nano".to_string());
    let status = std::process::Command::new(&editor)
        .arg(&config_path)
        .status()
        .with_context(|| format!("Failed to launch editor {:?}", editor))?;
    if !status.success() {
        anyhow::bail!("Editor exited with status {}", status);
    }
    Ok(())
}

fn cmd_config_set(key: &str, value: &str) -> Result<()> {
    let mut cfg = mvm_core::user_config::load(None);
    mvm_core::user_config::set_key(&mut cfg, key, value)?;
    mvm_core::user_config::save(&cfg, None)?;
    println!("Set {} = {}", key, value);
    Ok(())
}
