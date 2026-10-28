//! `mvmctl config` subcommand handlers.

use anyhow::{Context, Result};
use clap::{Args as ClapArgs, Subcommand};

use mvm_core::user_config::MvmConfig;

use super::Cli;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    #[command(subcommand)]
    pub action: ConfigAction,
}

#[derive(Subcommand, Debug, Clone)]
pub(in crate::commands) enum ConfigAction {
    /// Print current config as TOML
    Show,
    /// Open the config file in $EDITOR (falls back to nano)
    Edit,
    /// Set a single config key
    Set {
        /// Config key (e.g. dev_vm_cpus)
        key: String,
        /// New value
        value: String,
    },
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    match args.action {
        ConfigAction::Show => config_show(),
        ConfigAction::Edit => config_edit(),
        ConfigAction::Set { key, value } => config_set(&key, &value),
    }
}

fn config_show() -> Result<()> {
    config_show_to(&mut std::io::stdout())
}

fn config_show_to(out: &mut impl std::io::Write) -> Result<()> {
    let mut cfg = mvm_core::user_config::load(None);
    // Redact only this display copy, never the persisted or endpoint wire config.
    if let Some(proxy) = cfg.egress_proxy.as_mut() {
        for value in [&mut proxy.https, &mut proxy.http, &mut proxy.no_proxy] {
            if value.is_some() {
                *value = Some("<redacted>".to_string());
            }
        }
    }
    let text = toml::to_string_pretty(&cfg).context("Failed to serialize config")?;
    out.write_all(text.as_bytes())?;
    Ok(())
}

fn config_edit() -> Result<()> {
    // Ensure config file exists (load creates it with defaults if absent).
    let _ = mvm_core::user_config::load(None);
    let config_path = mvm_core::user_config::config_path();
    let editor = std::env::var("EDITOR").unwrap_or_else(|_| "nano".to_string());
    let status = mvm_core::env_hygiene::helper_command(&editor)
        .arg(&config_path)
        .status()
        .with_context(|| format!("Failed to launch editor {:?}", editor))?;
    if !status.success() {
        anyhow::bail!("Editor exited with status {}", status);
    }
    Ok(())
}

fn config_set(key: &str, value: &str) -> Result<()> {
    let mut cfg = mvm_core::user_config::load(None);
    mvm_core::user_config::set_key(&mut cfg, key, value)?;
    mvm_core::user_config::save(&cfg, None)?;
    println!("Set {} = {}", key, value);
    // Every mutation of the user config file is audit-worthy. The value
    // is included in `detail` because
    // configs hold operationally-significant settings (default backend,
    // network policy, etc.) and the audit chain is the only after-the-
    // fact record of what changed.
    mvm_core::audit_emit!(ConfigChange, "key={key} value={value}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn show_output_redacts_proxy_without_changing_persistence() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let home = tempfile::tempdir().unwrap();
        env.isolate_mvm_home(home.path());
        let path = mvm_core::user_config::config_path();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let raw = "[egress_proxy]\nhttps = 'http://username-token:password-token@proxy.corp:3128'\nhttp = 'malformed username-token:password-token'\nno_proxy = 'internal.example'\n";
        std::fs::write(&path, raw).unwrap();
        let mut output = Vec::new();
        config_show_to(&mut output).unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(!output.contains("username-token"));
        assert!(!output.contains("password-token"));
        let shown: MvmConfig = toml::from_str(&output).unwrap();
        assert_eq!(
            shown.egress_proxy.unwrap().https.as_deref(),
            Some("<redacted>")
        );
        assert_eq!(std::fs::read_to_string(path).unwrap(), raw);
        assert!(
            toml::to_string(&mvm_core::user_config::load(None))
                .unwrap()
                .contains("password-token")
        );
    }
}
