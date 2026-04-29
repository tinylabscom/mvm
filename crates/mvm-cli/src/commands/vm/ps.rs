//! `mvmctl ls` / `mvmctl ps` — list running VMs.

use anyhow::Result;
use clap::Args as ClapArgs;

use crate::bootstrap;

use mvm_core::user_config::MvmConfig;
use mvm_runtime::vm::backend::AnyBackend;
use mvm_runtime::vm::lima;

use super::Cli;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// Show all VMs (including stopped)
    #[arg(short, long)]
    pub all: bool,
    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    use mvm_core::vm_backend::VmInfo;

    let mut all_vms: Vec<VmInfo> = Vec::new();

    // Collect from Apple Container backend
    let ac_backend = AnyBackend::from_hypervisor("apple-container");
    if let Ok(vms) = ac_backend.list() {
        all_vms.extend(vms);
    }

    // Collect from Docker backend
    let docker_backend = AnyBackend::from_hypervisor("docker");
    if let Ok(vms) = docker_backend.list() {
        all_vms.extend(vms);
    }

    // Collect from Firecracker backend (if Lima is running)
    if bootstrap::is_lima_required() {
        if let Ok(lima::LimaStatus::Running) = lima::get_status() {
            let fc_backend = AnyBackend::from_hypervisor("firecracker");
            if let Ok(vms) = fc_backend.list() {
                all_vms.extend(vms);
            }
        }
    } else {
        // Native Linux — Firecracker runs directly
        let fc_backend = AnyBackend::from_hypervisor("firecracker");
        if let Ok(vms) = fc_backend.list() {
            all_vms.extend(vms);
        }
    }

    let _ = args.all;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&all_vms)?);
        return Ok(());
    }

    if all_vms.is_empty() {
        println!("No running VMs.");
        return Ok(());
    }

    // Docker-style table output
    println!(
        "{:<20} {:<18} {:<10} {:<8} {:<10} {:<20} IMAGE",
        "NAME", "BACKEND", "STATUS", "CPUS", "MEMORY", "PORTS"
    );
    for vm in &all_vms {
        let backend_name = if vm.flake_ref.as_deref().is_some() {
            // Determine backend from context
            if mvm_core::platform::current().has_apple_containers() {
                "apple-container"
            } else {
                "firecracker"
            }
        } else {
            "unknown"
        };
        let status = format!("{:?}", vm.status);
        let mem = if vm.memory_mib > 0 {
            format!("{}Mi", vm.memory_mib)
        } else {
            "-".to_string()
        };
        let image = vm
            .flake_ref
            .as_deref()
            .or(vm.profile.as_deref())
            .unwrap_or("-");
        let ports = if vm.ports.is_empty() {
            "-".to_string()
        } else {
            vm.ports
                .iter()
                .map(|p| format!("{}→{}", p.host, p.guest))
                .collect::<Vec<_>>()
                .join(", ")
        };
        println!(
            "{:<20} {:<18} {:<10} {:<8} {:<10} {:<20} {}",
            vm.name,
            backend_name,
            status,
            if vm.cpus > 0 {
                vm.cpus.to_string()
            } else {
                "-".to_string()
            },
            mem,
            ports,
            image,
        );
    }

    Ok(())
}
