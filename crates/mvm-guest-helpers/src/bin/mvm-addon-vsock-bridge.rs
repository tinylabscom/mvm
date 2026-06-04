//! In-guest TCP↔vsock bridge binary for local addons.
//!
//! Loads `addon_loopback_bindings` from the config disk, binds a TCP
//! listener per binding, and (for each accepted TCP connection) opens
//! a vsock stream to the host addon proxy, writes the
//! length-prefixed peer header, then proxies bytes both ways.
//!
use anyhow::{Context, Result};
use mvm_guest_helpers::addon_vsock_bridge::{load_bindings, run_bridge};
use std::env;
use std::path::PathBuf;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let bindings_path: PathBuf = env::var_os("MVM_ADDON_LOOPBACK_BINDINGS_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/run/mvm/addon_loopback_bindings.json"));

    let bindings = if bindings_path.exists() {
        load_bindings(&bindings_path).with_context(|| {
            format!(
                "failed to load addon loopback bindings from {}",
                bindings_path.display()
            )
        })?
    } else {
        // No-op mode: launch.json declared no addons. Idle and let
        // the supervisor's respawn loop manage us. Matches the
        // "always-install + no-op when bindings empty" pattern from
        // `specs/contracts/local-addon-dns.md`.
        tracing::info!(
            bindings_path = %bindings_path.display(),
            "no bindings file present; idling (no-op mode)"
        );
        loop {
            std::thread::park();
        }
    };

    tracing::info!(bindings = bindings.len(), "loaded addon loopback bindings");

    if bindings.is_empty() {
        loop {
            std::thread::park();
        }
    }

    run_bridge(bindings)
        .await
        .context("addon vsock bridge failed")
}
