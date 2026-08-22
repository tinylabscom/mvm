//! Load the per-boot FlowMux identity material used by the guest-side
//! loopback adapters.

#![warn(missing_docs)]

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use ed25519_dalek::{SigningKey, VerifyingKey};

/// Default path to the guest's ephemeral FlowMux signing key.
pub const DEFAULT_GUEST_SIGNING_KEY_PATH: &str = "/run/mvm/flowmux-guest-signing-key";

// The identity drive's own names live in `crate::flowmux_drive`, which is not
// gated behind `addons` — the guest inits that mount the drive must reach them
// without pulling this module's tokio-backed loader in.
pub use crate::flowmux_drive::{
    GUEST_SIGNING_KEY_FILE, GuestIngressTarget, HOST_SIGNER_PUB_FILE, IDENTITY_DRIVE_LABEL,
    INGRESS_TARGETS_FILE,
};

/// Default path to the signed-plan-derived guest ingress target map.
pub const DEFAULT_INGRESS_TARGETS_PATH: &str = "/run/mvm/flowmux-ingress.json";

/// Default path to the boot-pinned host-signer Ed25519 public key.
pub const DEFAULT_HOST_SIGNER_PUBKEY_PATH: &str = "/run/mvm/host-signer.pub";

/// Read the guest signing key from [`DEFAULT_GUEST_SIGNING_KEY_PATH`] or from
/// `MVM_FLOWMUX_GUEST_SIGNING_KEY_PATH` when set.
pub async fn load_guest_signing_key() -> Result<SigningKey> {
    let path = std::env::var("MVM_FLOWMUX_GUEST_SIGNING_KEY_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_GUEST_SIGNING_KEY_PATH));
    let path_for_error = path.clone();
    let raw = tokio::task::spawn_blocking(move || std::fs::read(&path))
        .await
        .context("failed to read guest signing key")?
        .with_context(|| {
            format!(
                "failed to read guest signing key from {}",
                path_for_error.display()
            )
        })?;
    let bytes: [u8; 32] = raw.try_into().map_err(|v: Vec<u8>| {
        anyhow::anyhow!(
            "guest signing key must be exactly 32 bytes, got {}",
            v.len()
        )
    })?;
    Ok(SigningKey::from_bytes(&bytes))
}

/// Load the signed-plan-derived ingress targets provisioned with this boot.
pub async fn load_ingress_targets() -> Result<Vec<GuestIngressTarget>> {
    let path = std::env::var("MVM_FLOWMUX_INGRESS_TARGETS_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_INGRESS_TARGETS_PATH));
    let path_for_error = path.clone();
    let raw = tokio::task::spawn_blocking(move || std::fs::read(&path))
        .await
        .context("failed to read FlowMux ingress targets")?
        .with_context(|| {
            format!(
                "failed to read FlowMux ingress targets from {}",
                path_for_error.display()
            )
        })?;
    serde_json::from_slice(&raw).context("failed to parse FlowMux ingress targets")
}

/// Load the host-signer verifying key from `path`.
pub fn load_host_signer_verifying_key(path: &Path) -> Result<Option<VerifyingKey>> {
    crate::vsock::load_host_signer_verifying_key(path)
}
