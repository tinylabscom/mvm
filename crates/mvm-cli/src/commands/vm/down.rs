//! `mvmctl down` — stop one or more running VMs.

use anyhow::{Context, Result};
use clap::Args as ClapArgs;

use crate::fleet;
use crate::ui;

use mvm_core::user_config::MvmConfig;
use mvm_core::vm_backend::VmId;
use mvm_runtime::vm::backend::AnyBackend;

use super::Cli;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// VM name to stop (or all VMs if omitted)
    pub name: Option<String>,
    /// Path to fleet config (stops only VMs defined in config)
    #[arg(short = 'f', long)]
    pub config: Option<String>,
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    // Use Apple Container backend on macOS 26+, otherwise default (Firecracker).
    let backend = if mvm_core::platform::current().has_apple_containers() {
        AnyBackend::from_hypervisor("apple-container")
    } else {
        AnyBackend::default_backend()
    };
    match args.name.as_deref() {
        Some(n) => {
            let result = backend.stop(&VmId::from(n));
            // Deregister from the name registry (best-effort)
            let registry_path = mvm_runtime::vm::name_registry::registry_path();
            if let Ok(mut registry) =
                mvm_runtime::vm::name_registry::VmNameRegistry::load(&registry_path)
            {
                registry.deregister(n);
                let _ = registry.save(&registry_path);
            }
            result
        }
        None => {
            let found = load_fleet_config(args.config.as_deref())?;
            if let Some((fleet_config, _base_dir)) = found {
                let mut stopped = 0;
                for vm_name in fleet_config.vms.keys() {
                    if backend.stop(&VmId::from(vm_name.as_str())).is_ok() {
                        stopped += 1;
                    }
                }

                // Clean up bridge if no VMs remain
                let remaining = backend.list().unwrap_or_default();
                if remaining.is_empty() {
                    let _ = mvm_runtime::vm::network::bridge_teardown();
                }

                ui::success(&format!("Stopped {} VMs", stopped));
                Ok(())
            } else {
                backend.stop_all()
            }
        }
    }
}

/// Load fleet config from an explicit path or auto-discover mvm.toml.
pub(super) fn load_fleet_config(
    config_path: Option<&str>,
) -> Result<Option<(fleet::FleetConfig, std::path::PathBuf)>> {
    match config_path {
        Some(path) => {
            let content = std::fs::read_to_string(path)
                .with_context(|| format!("Failed to read {}", path))?;
            let config: fleet::FleetConfig =
                toml::from_str(&content).with_context(|| format!("Failed to parse {}", path))?;
            let dir = std::path::Path::new(path)
                .parent()
                .unwrap_or(std::path::Path::new("."))
                .to_path_buf();
            Ok(Some((config, dir)))
        }
        None => fleet::find_fleet_config(),
    }
}
