//! `mvmctl init` first-time setup wizard.

use anyhow::Result;
use clap::Args as ClapArgs;

use crate::bootstrap;
use crate::ui;
use mvm_core::user_config::MvmConfig;

use super::super::build::image::load_bundled_catalog;
use super::Cli;
use super::setup::run_setup_steps;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// Skip interactive prompts, use defaults
    #[arg(long)]
    pub non_interactive: bool,
    /// Number of vCPUs for the Lima VM
    #[arg(long, default_value = "8")]
    pub lima_cpus: u32,
    /// Memory (GiB) for the Lima VM
    #[arg(long, default_value = "16")]
    pub lima_mem: u32,
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    use mvm_core::dev_network::{DevNetwork, network_path, networks_dir};

    ui::info("Welcome to mvmctl! Running first-time setup...\n");

    // Step 1: Platform detection
    let plat = mvm_core::platform::current();
    ui::info(&format!("Platform: {}", platform_label(plat)));

    if plat.has_apple_containers() {
        ui::info("Apple Container support detected (macOS 26+).");
    }

    // Step 2: Check and install dependencies
    ui::info("\nChecking dependencies...");
    match bootstrap::check_package_manager() {
        Ok(()) => {}
        Err(e) => {
            if args.non_interactive {
                return Err(e);
            }
            ui::warn(&format!("Package manager issue: {e}"));
            ui::info("Please install a package manager and retry.");
            return Err(e);
        }
    }

    if plat.needs_lima() {
        ui::info("Ensuring Lima is installed...");
        bootstrap::ensure_lima()?;
    }

    // Step 3: Run setup steps (create Lima VM, install Firecracker, Nix)
    ui::info("\nSetting up development environment...");
    run_setup_steps(false, args.lima_cpus, args.lima_mem)?;

    // Step 4: Create default network if it doesn't exist
    let dir = networks_dir();
    let default_path = network_path("default");
    if !std::path::Path::new(&default_path).exists() {
        ui::info("\nCreating default network...");
        std::fs::create_dir_all(&dir)?;
        let net = DevNetwork::default_network();
        let json = serde_json::to_string_pretty(&net)?;
        std::fs::write(&default_path, json)?;
        ui::success(&format!(
            "Created default network (bridge={}, subnet={})",
            net.bridge_name, net.subnet
        ));
    } else {
        ui::info("\nDefault network already configured.");
    }

    // Step 5: Create XDG directories
    ui::info("\nCreating data directories...");
    let dirs = [
        mvm_core::config::mvm_cache_dir(),
        mvm_core::config::mvm_config_dir(),
        mvm_core::config::mvm_state_dir(),
        mvm_core::config::mvm_share_dir(),
    ];
    for d in &dirs {
        std::fs::create_dir_all(d)?;
    }

    // Step 6: Show available images
    ui::info("\nAvailable images in catalog:");
    let catalog = load_bundled_catalog();
    for entry in &catalog.entries {
        ui::info(&format!("  {} — {}", entry.name, entry.description));
    }

    ui::success("\nSetup complete!");
    ui::info("Next steps:");
    ui::info("  mvmctl dev              # Enter development environment");
    ui::info("  mvmctl image list       # Browse available images");
    ui::info("  mvmctl doctor           # Verify everything is working");
    ui::info("  mvmctl up --flake .     # Build and run a VM from a Nix flake");

    Ok(())
}

fn platform_label(plat: mvm_core::platform::Platform) -> &'static str {
    match plat {
        mvm_core::platform::Platform::MacOS => "macOS (Lima + Firecracker)",
        mvm_core::platform::Platform::LinuxNative => "Linux (native KVM)",
        mvm_core::platform::Platform::LinuxNoKvm => "Linux (no KVM — limited)",
        mvm_core::platform::Platform::Wsl2 => "WSL2 (Linux via Windows)",
        mvm_core::platform::Platform::Windows => "Windows (experimental)",
    }
}
