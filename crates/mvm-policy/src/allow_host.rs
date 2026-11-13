//! The common parser for workload egress allow-host requests.

use anyhow::{Context, Result};
use mvm_core::network_policy::{HostPort, is_banned_ssh_port};

/// Parse one `--allow-host` entry, defaulting a bare host to HTTPS.
///
/// # Errors
///
/// Empty hosts, malformed explicit ports, and SSH destinations are refused.
pub fn parse_allow_host(entry: &str) -> Result<HostPort> {
    let parsed = match entry.rsplit_once(':') {
        Some(_) => entry
            .parse()
            .with_context(|| format!("invalid --allow-host {entry:?}")),
        None if entry.is_empty() => anyhow::bail!("--allow-host cannot be empty"),
        None => Ok(HostPort::new(entry, 443)),
    }?;
    if is_banned_ssh_port(parsed.port) {
        anyhow::bail!(
            "--allow-host {entry:?} requests TCP/22, but SSH sessions are banned in microVMs"
        );
    }
    Ok(parsed)
}
