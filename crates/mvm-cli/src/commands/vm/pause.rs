//! `mvmctl pause <vm>` / `mvmctl resume <vm>` — instance snapshot lifecycle.
//!
//! Thin CLI wrappers over the mvm-client facade: they validate the name, build a
//! `LocalBackend` from `--hypervisor`, and drive `pause_machine` /
//! `resume_machine`. The facade owns the snapshot machinery — the seal/verify
//! round-trip (including the replay refusal that gates every resume), the
//! `fc.paused` marker, the name-registry flags, and the guest PostRestore signal.
//! The CLI keeps only the cross-cutting wrappers: the success line and the
//! `WorkloadSleep` / `WorkloadWake` audit entries.

use anyhow::{Context, Result};
use clap::Args as ClapArgs;

use mvm_client::{
    LocalBackend, MachineId, MvmClient, PauseOpts, ResumeOpts, require_hypervisor_selectable,
};
use mvm_core::naming::validate_vm_name;
use mvm_core::user_config::MvmConfig;

use super::Cli;
use super::shared::clap_vm_name;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct PauseArgs {
    /// Name of the VM to pause
    #[arg(value_parser = clap_vm_name)]
    pub name: String,
    /// Hypervisor to drive the snapshot through. Defaults to the one that
    /// started the machine.
    /// `--hypervisor mock` selects the hermetic in-memory backend (canned
    /// snapshot bytes, no guest agent) so the audited seal path runs in tests
    /// without a live Firecracker socket.
    #[arg(long, default_value = "auto")]
    pub hypervisor: String,
    /// Before sealing, wait for the workload to signal "primed" (it created
    /// `/run/mvm/primed`) so the warm base is deterministic and fully-warmed.
    /// Fails closed: if the workload does not signal within `--primed-timeout`,
    /// the pause refuses rather than sealing a half-warmed snapshot.
    #[arg(long)]
    pub primed_barrier: bool,
    /// Seconds to wait for the primed signal when `--primed-barrier` is set.
    #[arg(long, default_value_t = 120)]
    pub primed_timeout: u64,
}

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct ResumeArgs {
    /// Name of the VM to resume
    #[arg(value_parser = clap_vm_name)]
    pub name: String,
    /// Hypervisor to drive the restore through. Defaults to `firecracker`.
    /// See `pause --help` for the `mock` variant.
    #[arg(long, default_value = "auto")]
    pub hypervisor: String,
    /// Drive the resume through the backend's live-memory warm-start path
    /// instead of the plain verify-and-resume. Fails closed with a typed
    /// recovery hint on a backend that can't warm-start at the live-memory tier
    /// (e.g. a backend may expose no selectable snapshot tier).
    #[arg(long)]
    pub warm: bool,
}

pub(in crate::commands) fn run_pause(_cli: &Cli, args: PauseArgs, _cfg: &MvmConfig) -> Result<()> {
    validate_vm_name(&args.name).with_context(|| format!("Invalid VM name: {:?}", args.name))?;
    // `auto` means "whichever VMM started this machine". Resolving from the
    // machine's own state marker rather than a flag default is what keeps
    // `pause` from reaching for Firecracker on a guest running under HVF.
    let client = if args.hypervisor == "auto" {
        LocalBackend::for_started_vm(&args.name)
    } else {
        require_hypervisor_selectable(&args.hypervisor)?;
        LocalBackend::with_hypervisor(&args.hypervisor)
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("build runtime for pausing")?;
    let outcome = runtime
        .block_on(client.pause_machine(
            &MachineId(args.name.clone()),
            PauseOpts {
                primed_barrier: args.primed_barrier,
                primed_timeout_secs: args.primed_timeout,
            },
        ))
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    println!(
        "{}: paused (epoch {}, vmstate {} B, mem {} B)",
        args.name, outcome.epoch, outcome.vmstate_len, outcome.mem_len
    );
    mvm_core::audit_emit!(WorkloadSleep, vm: &args.name, "epoch={} vmstate={} mem={}",
        outcome.epoch, outcome.vmstate_len, outcome.mem_len
    );
    Ok(())
}

pub(in crate::commands) fn run_resume(
    _cli: &Cli,
    args: ResumeArgs,
    _cfg: &MvmConfig,
) -> Result<()> {
    validate_vm_name(&args.name).with_context(|| format!("Invalid VM name: {:?}", args.name))?;

    // Same resolution as `pause`: a resume must reach the VMM that owns the
    // sealed instance, not whatever a flag defaults to.
    let client = if args.hypervisor == "auto" {
        LocalBackend::for_started_vm(&args.name)
    } else {
        require_hypervisor_selectable(&args.hypervisor)?;
        LocalBackend::with_hypervisor(&args.hypervisor)
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("build runtime for resuming")?;
    let outcome = runtime
        .block_on(client.resume_machine(
            &MachineId(args.name.clone()),
            ResumeOpts { warm: args.warm },
        ))
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    if args.warm {
        // A warm resume restores live memory (no sealed snapshot), so the detail
        // is the reseed summary rather than epoch/lengths.
        let reseed = outcome.reseed.as_deref().unwrap_or("no reseed reported");
        println!("{}: warm-started (live-memory resume, {reseed})", args.name);
        mvm_core::audit_emit!(WorkloadWake, vm: &args.name, "warm_start backend={} {reseed}", args.hypervisor);
    } else {
        // Plain resume — carry the verified snapshot's epoch + artifact lengths
        // into the WorkloadWake entry, at parity with the pause's WorkloadSleep.
        println!(
            "{}: resumed (epoch {}, vmstate {} B, mem {} B)",
            args.name, outcome.epoch, outcome.vmstate_len, outcome.mem_len
        );
        mvm_core::audit_emit!(WorkloadWake, vm: &args.name, "epoch={} vmstate={} mem={}",
            outcome.epoch, outcome.vmstate_len, outcome.mem_len);
    }
    Ok(())
}
