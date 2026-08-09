//! Retired single-VM Firecracker lifecycle entry points.

use anyhow::Result;
use tracing::instrument;

/// Refuse the legacy raw lifecycle. Workloads must use the runner-backed
/// Firecracker driver, which configures vsock and never exposes a guest NIC.
#[instrument]
pub fn start() -> Result<()> {
    anyhow::bail!("legacy raw Firecracker lifecycle is disabled; use the vsock workload runner")
}

/// The legacy lifecycle has no independent stop owner. Use the backend control
/// surface so the runner's endpoint and broker guards are handled together.
#[instrument]
pub fn stop() -> Result<()> {
    anyhow::bail!("legacy raw Firecracker lifecycle is disabled; use the vsock workload runner")
}
