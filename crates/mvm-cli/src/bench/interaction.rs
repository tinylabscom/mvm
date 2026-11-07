//! Interaction round-trip latency: cold RPC (fresh dial + handshake + one
//! Ping) vs warm RPC (N Pings over one held session). The steady warm p50 is
//! the number the "feels instant" budget is set against.

/// Sample counts for one interaction measurement.
#[cfg(feature = "libkrun-live")]
#[derive(Debug, Clone, Copy)]
pub struct InteractionRunCfg {
    /// Fresh dial+handshake+Ping sessions (cold RPC); median reported.
    pub cold_samples: u32,
    /// Warm Pings discarded before measuring, to settle the held session.
    pub warmup: u32,
    /// Measured warm Pings over the held session.
    pub samples: u32,
}

#[cfg(feature = "libkrun-live")]
impl Default for InteractionRunCfg {
    fn default() -> Self {
        Self {
            cold_samples: 10,
            warmup: 20,
            samples: 200,
        }
    }
}

/// Open a fresh authenticated session, issue one Ping, and confirm Pong.
/// Used both as the cold-RPC sample and to seed the warm loop.
#[cfg(feature = "libkrun-live")]
fn ping_once_cold(vm_name: &str) -> anyhow::Result<f64> {
    use std::time::Instant;

    use mvm_agentd::vsock::{ControlSession, GUEST_AGENT_PORT, GuestRequest, GuestResponse};

    let t = Instant::now();
    // Mirror the backend-agnostic dial used by `mvmctl fs`/`proc`/`diff`:
    // `mvm_runtime::vsock_transport::for_vm(name)?.connect(GUEST_AGENT_PORT)?`.
    let mut stream = mvm_runtime::vsock_transport::for_vm(vm_name)?.connect(GUEST_AGENT_PORT)?;
    let mut session = ControlSession::open(&mut stream)?;
    let resp = session.call_unary(&mut stream, &GuestRequest::Ping)?;
    anyhow::ensure!(
        matches!(resp, GuestResponse::Pong),
        "cold ping: expected Pong"
    );
    Ok(t.elapsed().as_secs_f64() * 1000.0)
}

#[cfg(test)]
mod tests {}
