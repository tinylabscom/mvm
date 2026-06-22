//! `mvmctl vm rekernel` — relaunch a VM on a chosen/updated workload kernel.
//!
//! This is a thin composition of `down` + `up`: the running VM is stopped
//! (non-fatal if it isn't running), then rebooted with the same name so the
//! caller gets a fresh boot on the new kernel without changing any other
//! parameters. Use after `mvmctl build kernel build --which workload` lands a
//! patched kernel in the cache.

use anyhow::Result;
use clap::Args as ClapArgs;

use mvm_core::user_config::MvmConfig;

use super::Cli;
use super::{down, up};

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// Name of the VM to relaunch
    pub name: String,
    /// Nix flake reference passed to the new boot (same semantics as `up --flake`)
    #[arg(long)]
    pub flake: Option<String>,
    /// Use the locally-built workload kernel from the mvm cache instead of
    /// whatever the image ships (same semantics as `up --kernel-pin`)
    #[arg(long = "kernel-pin")]
    pub kernel_pin: Option<String>,
    /// Hypervisor backend for the new boot (firecracker, libkrun, qemu, vz)
    #[arg(long, default_value = "libkrun")]
    pub hypervisor: String,
}

pub(in crate::commands) fn run(cli: &Cli, args: Args, cfg: &MvmConfig) -> Result<()> {
    // Stop the running VM. Treat "not running" as non-fatal so a caller
    // that is unsure of the VM's current state can still use `rekernel`
    // safely. Any real stop error (backend dispatch failure, etc.) is
    // still propagated.
    let stop_result = down::run(
        cli,
        down::Args {
            name: Some(args.name.clone()),
        },
        cfg,
    );
    if let Err(ref e) = stop_result {
        let msg = e.to_string();
        // A VM that was never started produces a "not found" / "no such"
        // style error from the backend registry. Surface it as a warning
        // and continue so the up leg still runs.
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

    // Capture the kernel-swap detail before these fields move into `up::Args`.
    let vm_name = args.name.clone();
    let rekernel_detail = format!(
        "hypervisor={} kernel_pin={} flake={}",
        args.hypervisor,
        args.kernel_pin.as_deref().unwrap_or("-"),
        args.flake.as_deref().unwrap_or("-"),
    );

    // Reboot on the (potentially new) kernel. All parameters not exposed on
    // the `rekernel` surface take their `up` defaults so the semantics are
    // exactly those of a plain `mvmctl up --name <name> [flags...]`.
    up::run(
        cli,
        up::Args {
            name: Some(args.name),
            flake: args.flake,
            kernel_pin: args.kernel_pin,
            hypervisor: args.hypervisor,
            // Everything below: up defaults (no flake build, no volume
            // overrides, no port/env/secret injection, standard security
            // posture, no TTL, no detach/wait/console modes).
            manifest: None,
            profile: None,
            cpus: None,
            memory: None,
            config: None,
            volume: vec![],
            port: vec![],
            env: vec![],
            secret: vec![],
            forward: false,
            metrics_port: 0,
            warm_pool_size: None,
            watch_config: false,
            watch: false,
            detach: false,
            wait: false,
            console: false,
            network_preset: None,
            network_allow: vec![],
            security_profile: None,
            seccomp: None,
            network: "default".to_string(),
            tags: vec![],
            ttl: None,
            no_auto_resume: false,
            tenant: None,
            no_supervisor: false,
            bundle_pin: None,
            build_mode: super::super::shared::BuildModeFlags::default(),
            from_workload_ir: None,
            accept_tier2_isolation: false,
            up_json: false,
            redact: vec![],
        },
        cfg,
    )?;

    // Record the kernel swap as a distinct audit entry. The down/up legs
    // above already emitted their own VmStop / plan.* + VmStart entries;
    // this makes the kernel change itself forensically visible.
    mvm_core::audit_emit!(VmRekernel, vm: &vm_name, "{rekernel_detail}");
    Ok(())
}
