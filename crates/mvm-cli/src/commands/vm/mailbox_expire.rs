//! `mvmctl machine mailbox-expire <vm>` — expire a quarantined workload's
//! mailbox after its VM is stopped.
//!
//! A quarantined workload never launches again, so no mailbox helper will
//! expire what its store still holds. This runs the expiry without a VM. It
//! expires only what is due now; run it again after later deadlines pass.

use anyhow::{Context, Result};
use clap::Args as ClapArgs;

use mvm_client::{LocalBackend, MachineId, MvmClient};
use mvm_core::user_config::MvmConfig;

use super::Cli;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// Name of the stopped VM whose workload is quarantined.
    pub name: String,
    /// Print the result as JSON.
    #[arg(long)]
    pub json: bool,
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("build runtime for mailbox-expire")?;
    let done = runtime
        .block_on(LocalBackend::new().expire_quarantined_mailbox(&MachineId(args.name.clone())))
        .map_err(|e| anyhow::anyhow!("{e}"))
        .context("Failed to expire the mailbox")?;
    if args.json {
        println!("{}", serde_json::to_string(&done)?);
        return Ok(());
    }
    println!(
        "{}: expired {} message(s), {} compaction(s){}",
        args.name,
        done.expired,
        done.compactions,
        if done.complete {
            ""
        } else {
            "; more is due, run again"
        }
    );
    Ok(())
}
