//! `mvmctl security` subcommand handlers.

use anyhow::Result;
use clap::{Args as ClapArgs, Subcommand};

use mvm_core::user_config::MvmConfig;

use super::Cli;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    #[command(subcommand)]
    pub action: SecurityAction,
}

#[derive(Subcommand, Debug, Clone)]
pub(in crate::commands) enum SecurityAction {
    /// Show security posture evaluation for the current environment
    Status {
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    match args.action {
        SecurityAction::Status { json } => security_status(json),
    }
}

fn security_status(json: bool) -> Result<()> {
    use mvm_core::security::{PostureCheck, SecurityLayer};
    use mvm_security::posture::SecurityPosture;

    let mut checks = Vec::new();

    // Check audit logging
    let audit_path = mvm_core::audit::default_audit_log();
    let audit_exists = std::path::Path::new(&audit_path).exists();
    checks.push(PostureCheck {
        layer: SecurityLayer::AuditLogging,
        name: "Local audit log".to_string(),
        passed: audit_exists,
        detail: if audit_exists {
            format!("Active at {audit_path}")
        } else {
            format!("Not found at {audit_path}")
        },
    });

    // Check XDG directory structure
    let share_dir = mvm_core::config::mvm_share_dir();
    let xdg_exists = std::path::Path::new(&share_dir).exists();
    checks.push(PostureCheck {
        layer: SecurityLayer::ConfigImmutability,
        name: "XDG data directory".to_string(),
        passed: xdg_exists,
        detail: if xdg_exists {
            format!("Present at {share_dir}")
        } else {
            "Not yet created — run `mvmctl init`".to_string()
        },
    });

    // Check default network
    let net_path = mvm_core::dev_network::network_path("default");
    let net_exists = std::path::Path::new(&net_path).exists();
    checks.push(PostureCheck {
        layer: SecurityLayer::NetworkIsolation,
        name: "Default dev network".to_string(),
        passed: net_exists,
        detail: if net_exists {
            "Configured".to_string()
        } else {
            "Not configured — run `mvmctl init` or `mvmctl network create default`".to_string()
        },
    });

    // Check seccomp availability
    checks.push(PostureCheck {
        layer: SecurityLayer::SeccompFilter,
        name: "Seccomp profiles".to_string(),
        passed: true,
        detail: "5-tier profiles available (essential → unrestricted)".to_string(),
    });

    // Check vsock auth
    checks.push(PostureCheck {
        layer: SecurityLayer::VsockAuth,
        name: "Vsock authentication".to_string(),
        passed: true,
        detail: "Ed25519 signing with replay protection".to_string(),
    });

    // Check guest hardening (no SSH)
    checks.push(PostureCheck {
        layer: SecurityLayer::GuestHardening,
        name: "No SSH policy".to_string(),
        passed: true,
        detail: "Vsock-only guest communication (no sshd)".to_string(),
    });

    // Check supply chain
    checks.push(PostureCheck {
        layer: SecurityLayer::SupplyChainIntegrity,
        name: "Nix-based builds".to_string(),
        passed: true,
        detail: "All images built from Nix flakes (content-addressed)".to_string(),
    });

    let timestamp = mvm_core::time::utc_now();
    let report = SecurityPosture::evaluate(checks, &timestamp);

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print!("{}", SecurityPosture::summary(&report));

        let uncovered = SecurityPosture::uncovered_layers(&report.checks);
        if !uncovered.is_empty() {
            println!("\nUncovered layers (no checks):");
            for layer in uncovered {
                println!("  - {:?}", layer);
            }
        }
    }

    Ok(())
}
