//! In-guest DNS resolver binary for local addons.
//!
//! Listens on `127.0.0.1:53` and `::1:53`, serves exact configured
//! hostnames from a config-disk zone, forwards everything else upstream.
//!
//! SIGHUP reloads `/run/mvm/addon_dns_zone.json` (or the env-overridden
//! path) into the shared zone without re-binding sockets, so in-flight
//! UDP queries are never dropped during a config-disk refresh. A reload
//! that fails to read or parse leaves the previous zone in place.

use anyhow::{Context, Result};
use mvm_guest_helpers::addon_dns::{
    DnsServerConfig, SharedZone, Zone, load_upstreams_from_resolv_conf, load_zone,
    reload_zone_from_path, run_udp_server, shared_zone,
};
use std::env;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use tokio::signal::unix::{SignalKind, signal};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    // The config disk mounts addon_dns_zone at a well-known path. The binary
    // accepts an env-var override for testability; the production
    // path is fixed by mvm's init scripts.
    let zone_path: PathBuf = env::var_os("MVM_ADDON_DNS_ZONE_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/run/mvm/addon_dns_zone.json"));
    let upstream_resolv_path: PathBuf = env::var_os("MVM_ADDON_DNS_UPSTREAM_RESOLV_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/run/mvm/upstream-resolv.conf"));

    let records = if zone_path.exists() {
        load_zone(&zone_path).with_context(|| {
            format!("failed to load addon DNS zone from {}", zone_path.display())
        })?
    } else {
        // No zone file at startup. The binary stays installed and idle
        // so a SIGHUP after a later config-disk refresh can promote it
        // into authoritative mode without a respawn. Mirrors the
        // "always-install + no-op when zone empty" pattern declared in
        // `specs/contracts/local-addon-dns.md`.
        tracing::info!(
            zone_path = %zone_path.display(),
            "no zone file present; starting with empty zone"
        );
        vec![]
    };

    let zone = shared_zone(Zone::new(records));
    tracing::info!(records = zone.read().await.len(), "loaded addon DNS zone");

    let mut config = DnsServerConfig::production_default();
    if let Some(bind_addrs) = env::var_os("MVM_ADDON_DNS_BIND_ADDRS") {
        config.bind_addrs = parse_socket_addr_list(&bind_addrs.to_string_lossy())
            .context("failed to parse MVM_ADDON_DNS_BIND_ADDRS")?;
    }
    if let Some(upstream_addrs) = env::var_os("MVM_ADDON_DNS_UPSTREAM_ADDRS") {
        config.upstream_addrs = parse_socket_addr_list(&upstream_addrs.to_string_lossy())
            .context("failed to parse MVM_ADDON_DNS_UPSTREAM_ADDRS")?;
    } else if upstream_resolv_path.exists() {
        config.upstream_addrs = load_upstreams_from_resolv_conf(&upstream_resolv_path)
            .with_context(|| {
                format!(
                    "failed to load addon DNS upstream resolvers from {}",
                    upstream_resolv_path.display()
                )
            })?;
    }

    spawn_sighup_reloader(zone.clone(), zone_path.clone())?;

    run_udp_server(zone, config)
        .await
        .context("addon DNS UDP server failed")
}

fn spawn_sighup_reloader(zone: SharedZone, zone_path: PathBuf) -> Result<()> {
    let mut sighup =
        signal(SignalKind::hangup()).context("failed to install SIGHUP handler for zone reload")?;
    tokio::spawn(async move {
        while sighup.recv().await.is_some() {
            reload_once(&zone, &zone_path).await;
        }
        tracing::warn!("SIGHUP stream ended; addon DNS reloads disabled");
    });
    Ok(())
}

async fn reload_once(zone: &SharedZone, zone_path: &Path) {
    if !zone_path.exists() {
        // Treat a missing file the same as the no-op contract: clear
        // the in-memory zone so the supervisor can stop being
        // authoritative without restarting the binary. Mirrors the
        // "empty zone = forward everything upstream" semantics the
        // server already implements.
        let mut guard = zone.write().await;
        guard.set_records(vec![]);
        tracing::info!(
            zone_path = %zone_path.display(),
            "SIGHUP received; zone file absent — cleared in-memory records"
        );
        return;
    }
    match reload_zone_from_path(zone, zone_path).await {
        Ok(count) => tracing::info!(
            records = count,
            zone_path = %zone_path.display(),
            "addon DNS zone reloaded on SIGHUP"
        ),
        Err(err) => tracing::warn!(
            error = %err,
            zone_path = %zone_path.display(),
            "addon DNS zone reload failed; keeping previous zone"
        ),
    }
}

fn parse_socket_addr_list(value: &str) -> Result<Vec<SocketAddr>> {
    value
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(|part| {
            part.parse::<SocketAddr>()
                .with_context(|| format!("invalid socket address {part:?}"))
        })
        .collect()
}
