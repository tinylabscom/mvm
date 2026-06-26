//! `mvmctl bootstrap` — full environment setup from scratch.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Args as ClapArgs;

use crate::bootstrap;
use crate::ui;

use mvm_core::user_config::MvmConfig;

use super::Cli;
use super::setup::run_setup_steps;
use crate::commands::ops::cache::{
    InstallPackFromSourceArgs, PackArchiveSource, PackBackendArg, PackPolicyArgs,
    PackPolicyModeArg, PackRevocationSource, install_pack_from_source, pack_kind_name,
};

const SKIP_PACK_PREFETCH_ENV: &str = "MVM_SKIP_PACK_PREFETCH";
const RUNTIME_PACK_SOURCE_ENV: &str = "MVM_BOOTSTRAP_RUNTIME_PACK_SOURCE";
const BUILDER_PACK_SOURCE_ENV: &str = "MVM_BOOTSTRAP_BUILDER_PACK_SOURCE";
const PACK_POLICY_HASH_ENV: &str = "MVM_BOOTSTRAP_PACK_POLICY_HASH";
const PACK_BACKEND_ENV: &str = "MVM_BOOTSTRAP_PACK_BACKEND";
const PACK_CHANNELS_ENV: &str = "MVM_BOOTSTRAP_PACK_CHANNELS";
const PACK_HOST_CAPABILITIES_ENV: &str = "MVM_BOOTSTRAP_PACK_HOST_CAPABILITIES";
const PACK_POLICY_MODE_ENV: &str = "MVM_BOOTSTRAP_PACK_POLICY_MODE";
const PACK_CHANNEL_SIGNING_KEYS_ENV: &str = "MVM_BOOTSTRAP_PACK_CHANNEL_SIGNING_KEYS";
const PACK_MIRROR_IDENTITY_ENV: &str = "MVM_BOOTSTRAP_PACK_MIRROR_IDENTITY";
const PACK_TRUST_STORE_ENV: &str = "MVM_BOOTSTRAP_PACK_TRUST_STORE";
const PACK_REVOCATIONS_ENV: &str = "MVM_BOOTSTRAP_PACK_REVOCATIONS";
const PACK_REVOCATIONS_SOURCE_ENV: &str = "MVM_BOOTSTRAP_PACK_REVOCATIONS_SOURCE";
const PACK_ALLOW_HTTP_ENV: &str = "MVM_BOOTSTRAP_PACK_ALLOW_HTTP";

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// Production mode (skip Homebrew, assume Linux with apt)
    #[arg(long)]
    pub production: bool,
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    bootstrap_environment(args.production)
}

/// Full environment bootstrap: host-tooling setup **plus** pre-acquiring the
/// builder VM image so the first `mvmctl dev up` is fast (no first-run
/// download/build on the hot path). Shared by the top-level `mvmctl bootstrap`
/// and `mvmctl env bootstrap`.
pub(in crate::commands) fn bootstrap_environment(production: bool) -> Result<()> {
    run_steps(production)?;
    // Pre-fetch the builder VM image. On a release install this downloads the
    // published, SHA-256-verified image; on a source checkout it builds it
    // locally (a source checkout never downloads mvm-release artifacts).
    // Cache-gated, so it is a fast no-op when the image is already present.
    super::dev_vz::bootstrap_builder_vm_image()?;
    bootstrap_default_packs_from_env()?;
    ui::success("\nBootstrap complete! Run 'mvmctl dev' to enter the development environment.");
    Ok(())
}

fn bootstrap_default_packs_from_env() -> Result<()> {
    let Some(config) = BootstrapPackConfig::from_env()? else {
        return Ok(());
    };
    for (label, source) in config.sources() {
        ui::info(&format!(
            "Installing default {label} pack into the attested cache..."
        ));
        let cached = install_pack_from_source(InstallPackFromSourceArgs {
            source: PackArchiveSource::parse(source),
            policy: PackPolicyArgs {
                backend: config.backend,
                policy_hash: config.policy_hash.clone(),
                channels: config.channels.clone(),
                host_capabilities: config.host_capabilities.clone(),
                policy_mode: config.policy_mode,
                channel_signing_keys: config.channel_signing_keys.clone(),
                mirror_identity: config.mirror_identity.clone(),
            },
            trust_store: config.trust_store.clone(),
            revocations: config.revocations.clone(),
            revocations_source: config
                .revocations_source
                .as_deref()
                .map(PackRevocationSource::parse),
            allow_http: config.allow_http,
        })
        .with_context(|| format!("installing default {label} pack during bootstrap"))?;
        mvm_core::audit_emit!(
            CachePackInstall,
            "pack_hash={} kind={} channel={} source_kind=bootstrap cache_root={}",
            cached.verified.pack_hash.as_str(),
            pack_kind_name(&cached.manifest.kind),
            cached.manifest.trust.channel_identity,
            cached.root.display()
        );
        ui::success(&format!(
            "Default {label} pack ready: {}",
            cached.verified.pack_hash.as_str()
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BootstrapPackConfig {
    runtime_source: Option<String>,
    builder_source: Option<String>,
    policy_hash: String,
    backend: PackBackendArg,
    channels: Vec<String>,
    host_capabilities: Vec<String>,
    policy_mode: PackPolicyModeArg,
    channel_signing_keys: Vec<String>,
    mirror_identity: Option<String>,
    trust_store: Option<PathBuf>,
    revocations: Option<PathBuf>,
    revocations_source: Option<String>,
    allow_http: bool,
}

impl BootstrapPackConfig {
    fn from_env() -> Result<Option<Self>> {
        Self::from_lookup(|key| std::env::var(key).ok())
    }

    fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Option<Self>> {
        if get(SKIP_PACK_PREFETCH_ENV).as_deref() == Some("1") {
            return Ok(None);
        }
        let runtime_source = non_empty_env(&get, RUNTIME_PACK_SOURCE_ENV);
        let builder_source = non_empty_env(&get, BUILDER_PACK_SOURCE_ENV);
        if runtime_source.is_none() && builder_source.is_none() {
            return Ok(None);
        }
        let policy_hash = required_env(&get, PACK_POLICY_HASH_ENV)?;
        let backend = parse_bootstrap_pack_backend(&required_env(&get, PACK_BACKEND_ENV)?)?;
        let channels = split_env_list(&required_env(&get, PACK_CHANNELS_ENV)?);
        if channels.is_empty() {
            anyhow::bail!("{PACK_CHANNELS_ENV} must contain at least one channel");
        }
        let revocations = non_empty_env(&get, PACK_REVOCATIONS_ENV).map(PathBuf::from);
        let revocations_source = non_empty_env(&get, PACK_REVOCATIONS_SOURCE_ENV);
        if revocations.is_some() && revocations_source.is_some() {
            anyhow::bail!(
                "{PACK_REVOCATIONS_ENV} and {PACK_REVOCATIONS_SOURCE_ENV} cannot both be set"
            );
        }
        Ok(Some(Self {
            runtime_source,
            builder_source,
            policy_hash,
            backend,
            channels,
            host_capabilities: non_empty_env(&get, PACK_HOST_CAPABILITIES_ENV)
                .map(|value| split_env_list(&value))
                .unwrap_or_default(),
            policy_mode: non_empty_env(&get, PACK_POLICY_MODE_ENV)
                .map(|value| parse_bootstrap_pack_policy_mode(&value))
                .transpose()?
                .unwrap_or(PackPolicyModeArg::OnlineDefault),
            channel_signing_keys: non_empty_env(&get, PACK_CHANNEL_SIGNING_KEYS_ENV)
                .map(|value| split_env_list(&value))
                .unwrap_or_default(),
            mirror_identity: non_empty_env(&get, PACK_MIRROR_IDENTITY_ENV),
            trust_store: non_empty_env(&get, PACK_TRUST_STORE_ENV).map(PathBuf::from),
            revocations,
            revocations_source,
            allow_http: get(PACK_ALLOW_HTTP_ENV).as_deref() == Some("1"),
        }))
    }

    fn sources(&self) -> Vec<(&'static str, &str)> {
        let mut sources = Vec::new();
        if let Some(source) = self.runtime_source.as_deref() {
            sources.push(("runtime", source));
        }
        if let Some(source) = self.builder_source.as_deref() {
            sources.push(("builder", source));
        }
        sources
    }
}

fn non_empty_env(get: &impl Fn(&str) -> Option<String>, key: &str) -> Option<String> {
    get(key).and_then(|value| {
        let trimmed = value.trim();
        (!trimmed.is_empty()).then(|| trimmed.to_string())
    })
}

fn required_env(get: &impl Fn(&str) -> Option<String>, key: &str) -> Result<String> {
    non_empty_env(get, key)
        .with_context(|| format!("{key} is required when bootstrap pack sources are set"))
}

fn split_env_list(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(ToString::to_string)
        .collect()
}

fn parse_bootstrap_pack_backend(value: &str) -> Result<PackBackendArg> {
    match value {
        "firecracker" => Ok(PackBackendArg::Firecracker),
        "libkrun" => Ok(PackBackendArg::Libkrun),
        "vz" => Ok(PackBackendArg::Vz),
        "qemu" => Ok(PackBackendArg::Qemu),
        "docker" => Ok(PackBackendArg::Docker),
        other => anyhow::bail!(
            "{PACK_BACKEND_ENV} must be one of firecracker, libkrun, vz, qemu, docker; got {other:?}"
        ),
    }
}

fn parse_bootstrap_pack_policy_mode(value: &str) -> Result<PackPolicyModeArg> {
    match value {
        "online-default" => Ok(PackPolicyModeArg::OnlineDefault),
        "offline-pinned" => Ok(PackPolicyModeArg::OfflinePinned),
        "mirror-only" => Ok(PackPolicyModeArg::MirrorOnly),
        "local-rebuild-required" => Ok(PackPolicyModeArg::LocalRebuildRequired),
        other => anyhow::bail!(
            "{PACK_POLICY_MODE_ENV} must be one of online-default, offline-pinned, mirror-only, local-rebuild-required; got {other:?}"
        ),
    }
}

/// Run the host-tooling bootstrap steps only (no builder-image prefetch) —
/// exposed so `dev` can re-bootstrap without going through the dispatcher.
pub(super) fn run_steps(production: bool) -> Result<()> {
    ui::info("Bootstrapping full environment...\n");

    if !production {
        bootstrap::check_package_manager()?;
    }

    // Dev mode is libkrun/Apple-Container on Apple Silicon macOS or
    // native Firecracker on Linux KVM. There is no Lima VM to provision
    // here; setup_steps below handles the remaining assets.
    bootstrap::hint_libkrun_if_useful();

    // Default sizing for the builder VM; CLI-level overrides ride the
    // setup path.
    run_setup_steps(false, 8, 16)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn lookup(vars: BTreeMap<&'static str, &'static str>) -> impl Fn(&str) -> Option<String> {
        move |key| vars.get(key).map(|value| (*value).to_string())
    }

    #[test]
    fn bootstrap_pack_config_absent_is_noop() {
        let config = BootstrapPackConfig::from_lookup(lookup(BTreeMap::new())).expect("config");
        assert!(config.is_none());
    }

    #[test]
    fn bootstrap_pack_config_honors_skip_env() {
        let config = BootstrapPackConfig::from_lookup(lookup(BTreeMap::from([
            (SKIP_PACK_PREFETCH_ENV, "1"),
            (
                RUNTIME_PACK_SOURCE_ENV,
                "https://example.test/runtime.tar.gz",
            ),
        ])))
        .expect("config");
        assert!(config.is_none());
    }

    #[test]
    fn bootstrap_pack_config_requires_policy_when_sources_set() {
        let err = BootstrapPackConfig::from_lookup(lookup(BTreeMap::from([(
            RUNTIME_PACK_SOURCE_ENV,
            "https://example.test/runtime.tar.gz",
        )])))
        .expect_err("policy required");
        assert!(err.to_string().contains(PACK_POLICY_HASH_ENV));
    }

    #[test]
    fn bootstrap_pack_config_parses_sources_and_policy() {
        let config = BootstrapPackConfig::from_lookup(lookup(BTreeMap::from([
            (
                RUNTIME_PACK_SOURCE_ENV,
                "https://example.test/runtime.tar.gz",
            ),
            (BUILDER_PACK_SOURCE_ENV, "/tmp/builder.tar.gz"),
            (
                PACK_POLICY_HASH_ENV,
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            ),
            (PACK_BACKEND_ENV, "vz"),
            (PACK_CHANNELS_ENV, "stable, enterprise "),
            (PACK_HOST_CAPABILITIES_ENV, "vsock, hvf "),
            (PACK_POLICY_MODE_ENV, "mirror-only"),
            (
                PACK_CHANNEL_SIGNING_KEYS_ENV,
                "stable=0123456789abcdef0123456789abcdef",
            ),
            (PACK_MIRROR_IDENTITY_ENV, "enterprise-mirror"),
            (PACK_TRUST_STORE_ENV, "/tmp/trust"),
            (PACK_REVOCATIONS_ENV, "/tmp/revocations.json"),
            (PACK_ALLOW_HTTP_ENV, "1"),
        ])))
        .expect("config")
        .expect("present");

        assert_eq!(
            config.runtime_source.as_deref(),
            Some("https://example.test/runtime.tar.gz")
        );
        assert_eq!(
            config.builder_source.as_deref(),
            Some("/tmp/builder.tar.gz")
        );
        assert_eq!(config.backend, PackBackendArg::Vz);
        assert_eq!(config.channels, vec!["stable", "enterprise"]);
        assert_eq!(config.host_capabilities, vec!["vsock", "hvf"]);
        assert_eq!(config.policy_mode, PackPolicyModeArg::MirrorOnly);
        assert_eq!(
            config.channel_signing_keys,
            vec!["stable=0123456789abcdef0123456789abcdef"]
        );
        assert_eq!(config.mirror_identity.as_deref(), Some("enterprise-mirror"));
        assert_eq!(config.trust_store, Some(PathBuf::from("/tmp/trust")));
        assert_eq!(
            config.revocations,
            Some(PathBuf::from("/tmp/revocations.json"))
        );
        assert_eq!(config.revocations_source, None);
        assert!(config.allow_http);
        assert_eq!(
            config.sources(),
            vec![
                ("runtime", "https://example.test/runtime.tar.gz"),
                ("builder", "/tmp/builder.tar.gz")
            ]
        );
    }

    #[test]
    fn bootstrap_pack_config_parses_revocation_source() {
        let config = BootstrapPackConfig::from_lookup(lookup(BTreeMap::from([
            (
                RUNTIME_PACK_SOURCE_ENV,
                "https://example.test/runtime.tar.gz",
            ),
            (
                PACK_POLICY_HASH_ENV,
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            ),
            (PACK_BACKEND_ENV, "libkrun"),
            (PACK_CHANNELS_ENV, "stable"),
            (
                PACK_REVOCATIONS_SOURCE_ENV,
                "https://example.test/revocations.json",
            ),
        ])))
        .expect("config")
        .expect("present");

        assert!(config.revocations.is_none());
        assert_eq!(
            config.revocations_source.as_deref(),
            Some("https://example.test/revocations.json")
        );
    }

    #[test]
    fn bootstrap_pack_config_rejects_revocation_file_and_source_together() {
        let err = BootstrapPackConfig::from_lookup(lookup(BTreeMap::from([
            (
                RUNTIME_PACK_SOURCE_ENV,
                "https://example.test/runtime.tar.gz",
            ),
            (
                PACK_POLICY_HASH_ENV,
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            ),
            (PACK_BACKEND_ENV, "libkrun"),
            (PACK_CHANNELS_ENV, "stable"),
            (PACK_REVOCATIONS_ENV, "/tmp/revocations.json"),
            (
                PACK_REVOCATIONS_SOURCE_ENV,
                "https://example.test/revocations.json",
            ),
        ])))
        .expect_err("conflicting revocation metadata inputs rejected");

        assert!(err.to_string().contains(PACK_REVOCATIONS_SOURCE_ENV));
    }

    #[test]
    fn bootstrap_pack_config_rejects_unknown_backend() {
        let err = BootstrapPackConfig::from_lookup(lookup(BTreeMap::from([
            (
                RUNTIME_PACK_SOURCE_ENV,
                "https://example.test/runtime.tar.gz",
            ),
            (
                PACK_POLICY_HASH_ENV,
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            ),
            (PACK_BACKEND_ENV, "unknown"),
            (PACK_CHANNELS_ENV, "stable"),
        ])))
        .expect_err("bad backend rejected");
        assert!(err.to_string().contains(PACK_BACKEND_ENV));
    }

    #[test]
    fn bootstrap_pack_config_rejects_unknown_policy_mode() {
        let err = BootstrapPackConfig::from_lookup(lookup(BTreeMap::from([
            (
                RUNTIME_PACK_SOURCE_ENV,
                "https://example.test/runtime.tar.gz",
            ),
            (
                PACK_POLICY_HASH_ENV,
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            ),
            (PACK_BACKEND_ENV, "vz"),
            (PACK_CHANNELS_ENV, "stable"),
            (PACK_POLICY_MODE_ENV, "unknown"),
        ])))
        .expect_err("bad policy mode rejected");
        assert!(err.to_string().contains(PACK_POLICY_MODE_ENV));
    }
}
