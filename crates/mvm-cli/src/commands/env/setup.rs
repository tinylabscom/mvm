//! Presentation adapters used by bootstrap for host provisioning.

use anyhow::Result;
use mvm_client::maintenance::environment::{
    SetupAction, SetupEvent, SetupRequest, SetupScope, setup,
};

use crate::ui;

pub(super) fn run_setup_steps(force: bool, _builder_cpus: u32, _builder_mem: u32) -> Result<()> {
    setup(&setup_request(force), &mut render)?;
    Ok(())
}

fn setup_request(force: bool) -> SetupRequest {
    SetupRequest {
        apply: true,
        force,
        scope: SetupScope::Full,
    }
}

fn render(event: SetupEvent) {
    match event {
        SetupEvent::Unsupported => {
            ui::info("Firecracker runs on Linux only — skipping Firecracker asset provisioning.")
        }
        SetupEvent::FirecrackerPresent => {
            ui::step(1, 4, "Firecracker already installed — skipping.");
        }
        SetupEvent::AssetsPresent => {
            ui::step(2, 4, "Kernel and rootfs already present — skipping.");
        }
        SetupEvent::Starting(action) => match action {
            SetupAction::InstallFirecracker => ui::step(1, 4, "Installing Firecracker..."),
            SetupAction::DownloadAssets => ui::step(2, 4, "Downloading kernel and rootfs..."),
            SetupAction::RepairRootfsDownload => {
                ui::warn("Downloaded rootfs is corrupted. Re-downloading...");
            }
            SetupAction::PrepareRootfs => ui::step(3, 4, "Preparing root filesystem..."),
            SetupAction::DeployStrictSeccomp => ui::step(4, 4, "Setting up security baseline..."),
            SetupAction::WriteState | SetupAction::CreateAuditDirectory => {}
        },
        SetupEvent::Completed(action) => match action {
            SetupAction::DeployStrictSeccomp => ui::info("  Seccomp strict profile deployed."),
            SetupAction::CreateAuditDirectory => ui::info("  Audit log directory created."),
            SetupAction::InstallFirecracker
            | SetupAction::DownloadAssets
            | SetupAction::RepairRootfsDownload
            | SetupAction::PrepareRootfs
            | SetupAction::WriteState => {}
        },
        SetupEvent::JailerAvailable(true) => ui::info("  Jailer binary available."),
        SetupEvent::JailerAvailable(false) => {
            ui::warn("  Jailer binary not found (may not be in this Firecracker release).");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bootstrap_preserves_apply_intent_and_force_argument() {
        for force in [false, true] {
            let request = setup_request(force);
            assert!(request.apply);
            assert_eq!(request.force, force);
            assert_eq!(request.scope, SetupScope::Full);
        }
        assert!(!SetupRequest::default().apply);
    }
}
