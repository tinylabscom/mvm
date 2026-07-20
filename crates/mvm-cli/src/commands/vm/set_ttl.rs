//! `mvmctl set-ttl <vm> <duration>` — set or clear a sandbox's TTL.
//!
//! Updates the `expires_at` field on the persistent name-registry
//! record. The supervisor reaper (separate workstream) walks the
//! registry every ~30s with jitter and tears down expired VMs.
//!
//! Pass `--clear` to remove an existing TTL without specifying a new
//! one. Otherwise `<duration>` parses through
//! `mvm_core::crypto::policy::parse_ttl` (`30s`, `5m`, `2h`, `7d`, or bare
//! seconds) and the `expires_at` is set to `now() + duration`.

use anyhow::{Context, Result, bail};
use clap::Args as ClapArgs;

use mvm_client::{LocalBackend, MachineId, MvmClient, MvmError};
use mvm_core::user_config::MvmConfig;

use super::Cli;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// Name of the VM to update.
    pub name: String,
    /// New TTL (e.g. `30s`, `5m`, `2h`). Omit when using `--clear`.
    pub duration: Option<String>,
    /// Remove the existing TTL.
    #[arg(long, conflicts_with = "duration")]
    pub clear: bool,
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    // Duration parsing is a CLI concern; the facade takes the resolved
    // `expires_at` timestamp (or `None` to clear) and applies it to the registry.
    let new_expires_at: Option<String> = match (args.clear, args.duration.as_deref()) {
        (true, _) => None,
        (false, Some(d)) => {
            let dur = mvm_core::crypto::policy::parse_ttl(d).context("Invalid duration")?;
            Some(mvm_core::util::time::utc_plus_duration(dur))
        }
        (false, None) => bail!("Provide a duration (e.g. `30m`) or pass `--clear`"),
    };

    let client = LocalBackend::new();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("build runtime for set-ttl")?;
    match runtime.block_on(client.set_ttl(&MachineId(args.name.clone()), new_expires_at.clone())) {
        Ok(()) => {}
        Err(MvmError::NotFound { .. }) => bail!("VM {:?} is not registered", args.name),
        Err(e) => return Err(anyhow::anyhow!("{e}")).context("Failed to update TTL"),
    }

    let detail = match &new_expires_at {
        Some(ts) => {
            println!("{}: TTL set, expires at {ts}", args.name);
            format!("expires_at={ts}")
        }
        None => {
            println!("{}: TTL cleared", args.name);
            "expires_at=cleared".to_string()
        }
    };
    mvm_core::audit_emit!(VmTtlSet, vm: &args.name, "{detail}");
    Ok(())
}
