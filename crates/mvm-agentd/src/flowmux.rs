//! Guest-side FlowMux client for the converged workload networking path.
//!
//! This module implements the in-guest half of Plan 316 Phase 3: one
//! authenticated FlowMux session to the host `GuestService::NetworkFlow` port,
//! shared by SOCKS5/HTTP/DNS loopback adapters. See
//! `specs/notes/316-guest-flowmux-adapter.md` for the full design.
//!
//! TODO: frame pump, stream handles, reconnect owner, and adapter integration.

#![warn(missing_docs)]

use ed25519_dalek::{SigningKey, VerifyingKey};

/// A FlowMux client handle.
///
/// Owns the authenticated session (in a background task) and exposes async
/// methods to open TCP/UDP flows and resolve DNS names. Clones of the handle
/// share the same session and reconnect state.
#[derive(Debug, Clone)]
pub struct FlowMuxClient;

impl FlowMuxClient {
    /// Connect to the host NetworkFlow channel and complete the FlowMux
    /// handshake (`Hello` / `HelloAck`).
    ///
    /// The cryptographic session handshake is performed as the guest using
    /// `guest_signing_key` and the pinned host anchor.
    pub async fn connect<S>(
        _stream: S,
        _guest_signing_key: SigningKey,
        _host_anchor: VerifyingKey,
    ) -> anyhow::Result<Self>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        // TODO: implement handshake + Hello/Ack.
        Ok(Self)
    }

    /// Open a TCP flow to `target` (`host:port`).
    pub async fn open_tcp(&self, _target: &str) -> anyhow::Result<FlowMuxStream> {
        // TODO: implement OpenTcp/Opened/Refused exchange.
        Err(anyhow::anyhow!("not yet implemented"))
    }

    /// Open a UDP association.
    pub async fn open_udp(&self) -> anyhow::Result<FlowMuxUdpSocket> {
        // TODO: implement OpenUdp/UdpOpened/Refused exchange.
        Err(anyhow::anyhow!("not yet implemented"))
    }

    /// Resolve a DNS name. Returns the raw DNS response bytes.
    pub async fn resolve(&self, _name: &str, _qtype: u16) -> anyhow::Result<Vec<u8>> {
        // TODO: implement Resolve/Resolved/ResolveRefused exchange.
        Err(anyhow::anyhow!("not yet implemented"))
    }
}

/// An async TCP-like stream over a FlowMux session.
pub struct FlowMuxStream;

/// An async UDP-like socket over a FlowMux session.
pub struct FlowMuxUdpSocket;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_stub_compiles() {
        // Smoke test until the async frame pump lands.
        let _ = FlowMuxClient;
    }
}
