//! `mvmctl vm rekernel` — relaunch a VM on a chosen/updated workload kernel.
//!
//! A thin composition over the canonical `machine run` boot path: the running
//! VM is stopped (non-fatal if it isn't running), then rebooted on the new
//! kernel. With `--flake` the source is rebuilt and the spec recreated; without
//! it the stored spec is rebooted as-is on the (optionally pinned) kernel,
//! preserving its volumes/config. Use after `mvmctl build kernel build --which
//! workload` lands a patched kernel in the cache.

use anyhow::Result;
use clap::Args as ClapArgs;

use mvm_core::user_config::MvmConfig;

use super::super::machine;
use super::Cli;
use super::down;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// Name of the VM to relaunch
    pub name: String,
    /// Nix flake reference passed to the new boot (rebuilds the source)
    #[arg(long)]
    pub flake: Option<String>,
    /// Use the locally-built workload kernel from the mvm cache instead of
    /// whatever the image ships
    #[arg(long = "kernel-pin")]
    pub kernel_pin: Option<String>,
    /// Hypervisor backend for the new boot (firecracker, libkrun, qemu, vz)
    #[arg(long, default_value = "libkrun")]
    pub hypervisor: String,
}

pub(in crate::commands) fn run(cli: &Cli, args: Args, cfg: &MvmConfig) -> Result<()> {
    // Stop the running VM. Treat "not running" as non-fatal so a caller that is
    // unsure of the VM's current state can still use `rekernel` safely. Any real
    // stop error (backend dispatch failure, etc.) is still propagated.
    let stop_result = down::run(
        cli,
        down::Args {
            name: Some(args.name.clone()),
        },
        cfg,
    );
    if let Err(ref e) = stop_result {
        let msg = e.to_string();
        // A VM that was never started produces a "not found" / "no such" style
        // error from the backend registry. Surface it as a warning and continue
        // so the reboot leg still runs.
        if msg.contains("not found")
            || msg.contains("no such")
            || msg.contains("not running")
            || msg.contains("No such")
        {
            crate::ui::warn(&format!(
                "rekernel: stop returned '{msg}' — VM may not have been running; continuing"
            ));
        } else {
            return stop_result;
        }
    }

    // Capture the kernel-swap detail before the fields move into the boot args.
    let vm_name = args.name.clone();
    let rekernel_detail = format!(
        "hypervisor={} kernel_pin={} flake={}",
        args.hypervisor,
        args.kernel_pin.as_deref().unwrap_or("-"),
        args.flake.as_deref().unwrap_or("-"),
    );

    // Reboot through the canonical `machine run` persistent boot path. With a
    // flake the source is rebuilt and the spec recreated; without one the stored
    // spec is rebooted as-is on the (optionally pinned) kernel.
    machine::boot_persistent_by_name(
        cli,
        cfg,
        args.name,
        args.flake,
        args.kernel_pin,
        Some(args.hypervisor),
    )?;

    // Record the kernel swap as a distinct audit entry. The stop + boot legs
    // above already emitted their own VmStop / plan.* + VmStart entries; this
    // makes the kernel change itself forensically visible.
    mvm_core::audit_emit!(VmRekernel, vm: &vm_name, "{rekernel_detail}");
    Ok(())
}
