//! Reconnecting ownership for FlowMux client sessions.

use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::{SigningKey, VerifyingKey};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::watch;
use tracing::warn;

use crate::flowmux_drive::GuestIngressTarget;

use super::{FlowMuxClient, FlowMuxError, FlowMuxStream, FlowMuxUdpSocket, SessionState};

/// Default timeout for an individual call that waits through reconnect.
const CALL_TIMEOUT: Duration = Duration::from_secs(30);

/// Reconnect policy: bounded exponential backoff with a small absolute cap.
#[derive(Debug, Clone, Copy)]
pub struct ReconnectPolicy {
    /// Initial delay before the first reconnect attempt.
    pub initial_delay: Duration,
    /// Maximum delay between attempts.
    pub max_delay: Duration,
    /// Maximum number of reconnect attempts before giving up.
    pub max_attempts: u32,
}

impl Default for ReconnectPolicy {
    fn default() -> Self {
        Self {
            initial_delay: Duration::from_millis(250),
            max_delay: Duration::from_secs(16),
            max_attempts: 10,
        }
    }
}

/// A reconnecting FlowMux client.
///
/// Wraps one active [`FlowMuxClient`] session and transparently re-creates it
/// on transport failure. Live handles from a lost session fail promptly; new
/// requests block until a fresh session is established or reconnect is
/// exhausted. No request body, datagram, or `Open` frame is replayed across
/// sessions.
#[derive(Debug, Clone)]
pub struct FlowMuxReconnectClient {
    current: watch::Receiver<Option<Arc<FlowMuxClient>>>,
}

impl FlowMuxReconnectClient {
    /// Connect to the host and start the reconnect owner.
    ///
    /// `connector` is called to obtain a new transport each time the current
    /// session dies. The initial connection uses `connector()`; subsequent
    /// attempts use the same factory under bounded exponential backoff.
    pub async fn connect<S, F, Fut>(
        connector: F,
        guest_signing_key: SigningKey,
        host_anchor: VerifyingKey,
    ) -> Result<Self, FlowMuxError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = Result<S, FlowMuxError>> + Send,
    {
        Self::connect_with_ingress(connector, guest_signing_key, host_anchor, Vec::new()).await
    }

    /// Connect and retain the signed ingress target set across reconnects.
    pub async fn connect_with_ingress<S, F, Fut>(
        connector: F,
        guest_signing_key: SigningKey,
        host_anchor: VerifyingKey,
        ingress_targets: Vec<GuestIngressTarget>,
    ) -> Result<Self, FlowMuxError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = Result<S, FlowMuxError>> + Send,
    {
        let ingress_targets = Arc::new(ingress_targets);
        let initial = connector().await?;
        let client = Arc::new(
            FlowMuxClient::connect_with_ingress(
                initial,
                guest_signing_key.clone(),
                host_anchor,
                ingress_targets.as_ref().clone(),
            )
            .await?,
        );
        let (current_tx, current_rx) = watch::channel(Some(Arc::clone(&client)));

        tokio::spawn(async move {
            let mut state_rx = client.state();
            reconnect_loop(
                connector,
                guest_signing_key,
                host_anchor,
                ingress_targets,
                current_tx,
                &mut state_rx,
                ReconnectPolicy::default(),
            )
            .await;
        });

        Ok(Self {
            current: current_rx,
        })
    }

    /// Wait until there is a ready session and return a clone of it.
    ///
    /// Two watches move independently here: `current` names which client the
    /// reconnect loop owns, and the client's own state says whether that one
    /// has finished its handshake. Waiting on only the first parks forever on
    /// a client that is still connecting, since nothing replaces it.
    async fn active_client(&self) -> Result<Arc<FlowMuxClient>, FlowMuxError> {
        let mut current = self.current.clone();
        loop {
            let snapshot = current.borrow().clone();
            let Some(client) = snapshot else {
                if current.changed().await.is_err() {
                    return Err(FlowMuxError::SessionClosed("reconnect owner gone".into()));
                }
                continue;
            };

            let mut state = client.state();
            let settled = loop {
                match state.borrow().clone() {
                    SessionState::Ready => break Some(client),
                    // Dead is the reconnect loop's cue; wait for the client it
                    // puts in place rather than re-reading this one.
                    SessionState::Dead(_) => break None,
                    SessionState::Connecting | SessionState::Reconnecting => {}
                }
                tokio::select! {
                    changed = state.changed() => {
                        if changed.is_err() {
                            break None;
                        }
                    }
                    changed = current.changed() => {
                        if changed.is_err() {
                            return Err(FlowMuxError::SessionClosed("reconnect owner gone".into()));
                        }
                        break None;
                    }
                }
            };
            if let Some(client) = settled {
                return Ok(client);
            }
            if current.has_changed().unwrap_or(false) {
                continue;
            }
            if current.changed().await.is_err() {
                return Err(FlowMuxError::SessionClosed("reconnect owner gone".into()));
            }
        }
    }

    /// Open a TCP flow to `target` (`host:port`).
    pub async fn open_tcp(&self, target: &str) -> Result<FlowMuxStream, FlowMuxError> {
        let client = tokio::time::timeout(CALL_TIMEOUT, self.active_client())
            .await
            .map_err(|_| FlowMuxError::SessionClosed("reconnect timed out".into()))??;
        client.open_tcp(target).await
    }

    /// Open a UDP association.
    pub async fn open_udp(&self) -> Result<FlowMuxUdpSocket, FlowMuxError> {
        let client = tokio::time::timeout(CALL_TIMEOUT, self.active_client())
            .await
            .map_err(|_| FlowMuxError::SessionClosed("reconnect timed out".into()))??;
        client.open_udp().await
    }

    /// Resolve a DNS name. Returns the raw DNS response bytes.
    pub async fn resolve(&self, name: &str, qtype: u16) -> Result<Vec<u8>, FlowMuxError> {
        let client = tokio::time::timeout(CALL_TIMEOUT, self.active_client())
            .await
            .map_err(|_| FlowMuxError::SessionClosed("reconnect timed out".into()))??;
        client.resolve(name, qtype).await
    }

    /// Build a reconnect client from an existing watch receiver.
    ///
    /// Test-only: lets in-crate tests stand up a client that is already
    /// connected to a mock host without going through the reconnect factory.
    #[cfg(all(test, feature = "addons"))]
    pub(crate) fn from_receiver(current: watch::Receiver<Option<Arc<FlowMuxClient>>>) -> Self {
        Self { current }
    }
}

async fn reconnect_loop<S, F, Fut>(
    connector: F,
    guest_signing_key: SigningKey,
    host_anchor: VerifyingKey,
    ingress_targets: Arc<Vec<GuestIngressTarget>>,
    current_tx: watch::Sender<Option<Arc<FlowMuxClient>>>,
    state_rx: &mut watch::Receiver<SessionState>,
    policy: ReconnectPolicy,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    F: Fn() -> Fut + Send + Sync,
    Fut: std::future::Future<Output = Result<S, FlowMuxError>> + Send,
{
    let mut delay = policy.initial_delay;
    let mut attempts = 0_u32;

    loop {
        // Wait for the current session to die.
        loop {
            if matches!(*state_rx.borrow(), SessionState::Dead(_)) {
                break;
            }
            if state_rx.changed().await.is_err() {
                // The session task dropped its state sender. That is the
                // strongest evidence the session is gone, not a signal to stop
                // watching — a session can end without ever publishing `Dead`.
                // Returning here drops `current_tx`, so every waiter fails with
                // "reconnect owner gone" and the guest never gets a second
                // session, which is indistinguishable from having no network.
                break;
            }
        }

        attempts += 1;
        if attempts > policy.max_attempts {
            warn!("FlowMux reconnect exhausted; entering dead state");
            let _ = current_tx.send(None);
            return;
        }

        let jitter = Duration::from_millis(u64::from(rand::random::<u16>()) % 100);
        tokio::time::sleep(delay + jitter).await;
        delay = (delay * 2).min(policy.max_delay);

        match connector().await {
            Ok(stream) => {
                match FlowMuxClient::connect_with_ingress(
                    stream,
                    guest_signing_key.clone(),
                    host_anchor,
                    ingress_targets.as_ref().clone(),
                )
                .await
                {
                    Ok(client) => {
                        let new_client = Arc::new(client);
                        let state = new_client.state();
                        if current_tx.send(Some(new_client)).is_err() {
                            return;
                        }
                        *state_rx = state;
                        attempts = 0;
                        delay = policy.initial_delay;
                    }
                    Err(e) => {
                        warn!(error = %e, "FlowMux reconnect handshake failed");
                    }
                }
            }
            Err(e) => {
                warn!(error = %e, "FlowMux reconnect transport failed");
            }
        }
    }
}
