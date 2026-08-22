//! Generic bounded MVEX process boundary for an admitted extension provider.
//!
//! This binary deliberately has no generic command runner, host-path
//! discovery, credential loading, or ambient configuration. Operator session
//! declarations arrive in a bounded typed `OpenSession` frame and are joined
//! to the provider request before the runner is called. The current
//! executable loads one strict fixed boot configuration beneath that state
//! root, injects the concrete admitted lifecycle, and otherwise fails before
//! serving a frame. It never accepts a command, image, pack, policy, backend,
//! destination, credential, or host path from the provider request.

use std::path::PathBuf;

use anyhow::{Context, Result};
use mvm_contract::assurance::AssuranceId;
use mvm_hostd::admitted_campaign_runner::LifecycleAdmittedCampaignRunner;
use mvm_hostd::assurance_agent_adapter::GuestAssuranceExecutor;
use mvm_hostd::assurance_provider::{prepare_provider_state_root, serve_provider};
use mvm_hostd::operator_admitted_trial_booter::OperatorConfiguredTrialBooter;

const DEFAULT_PROVIDER_ID: &str = "org.tinylabs.mvm-extension-provider";
const DEFAULT_PROVIDER_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug)]
struct ProviderOptions {
    provider_id: AssuranceId,
    version: String,
    journal_root: PathBuf,
}

impl ProviderOptions {
    fn parse(args: impl IntoIterator<Item = String>) -> Result<Self> {
        let mut provider_id = DEFAULT_PROVIDER_ID.to_string();
        let mut version = DEFAULT_PROVIDER_VERSION.to_string();
        let mut journal_root = None;
        let mut args = args.into_iter();
        while let Some(argument) = args.next() {
            match argument.as_str() {
                "--provider-id" => provider_id = next_value(&mut args, "--provider-id")?,
                "--version" => version = next_value(&mut args, "--version")?,
                "--state-root" => {
                    journal_root = Some(PathBuf::from(next_value(&mut args, "--state-root")?));
                }
                "--help" => anyhow::bail!("{}", usage()),
                other => anyhow::bail!("unknown argument {other:?}; expected --state-root"),
            }
        }
        let provider_id = AssuranceId::parse(provider_id).context("invalid provider id")?;
        if version.is_empty() || version.len() > 128 || version.chars().any(char::is_control) {
            anyhow::bail!("provider version is outside its bound");
        }
        let journal_root = journal_root.context("--state-root is required")?;
        if journal_root.as_os_str().is_empty() {
            anyhow::bail!("--state-root must not be empty");
        }
        if !journal_root.is_absolute() {
            anyhow::bail!("--state-root must be an absolute path");
        }
        Ok(Self {
            provider_id,
            version,
            journal_root,
        })
    }
}

fn next_value(args: &mut impl Iterator<Item = String>, name: &str) -> Result<String> {
    args.next()
        .with_context(|| format!("{name} requires an explicit value"))
}

fn usage() -> &'static str {
    "usage: mvm-extension-provider --state-root PATH [--provider-id ID] [--version VERSION]"
}

fn main() -> Result<()> {
    mvm_hostd::panic_hook::install("extension-provider");
    let options = ProviderOptions::parse(std::env::args().skip(1))?;
    prepare_provider_state_root(&options.journal_root)?;
    let booter = OperatorConfiguredTrialBooter::load(&options.journal_root)
        .context("loading operator-configured admitted trial booter")?;
    let runner = LifecycleAdmittedCampaignRunner::new(
        &options.journal_root,
        booter,
        GuestAssuranceExecutor,
    )?;
    serve_provider(
        options.provider_id,
        options.version,
        options.journal_root,
        runner,
        &mut std::io::stdin().lock(),
        &mut std::io::stdout().lock(),
    )
    .context("extension provider MVEX loop failed")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requires_an_explicit_private_journal_root() {
        let error = ProviderOptions::parse(Vec::<String>::new()).expect_err("root is required");
        assert!(error.to_string().contains("--state-root"));
    }

    #[test]
    fn rejects_unknown_configuration_instead_of_consulting_the_environment() {
        let error = ProviderOptions::parse([
            "--state-root".to_string(),
            "/private/tmp/provider".to_string(),
            "--command".to_string(),
            "sh".to_string(),
        ])
        .expect_err("arbitrary command configuration is forbidden");
        assert!(error.to_string().contains("unknown argument"));
    }

    #[test]
    fn rejects_a_current_directory_relative_state_root() {
        let error =
            ProviderOptions::parse(["--state-root".to_string(), "provider-state".to_string()])
                .expect_err("relative state is ambient process state");
        assert!(error.to_string().contains("absolute path"));
    }
}
