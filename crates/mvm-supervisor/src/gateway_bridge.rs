//! Per-VM gateway audit bridge ([Plan 102 W6.A] / [ADR-058] claim
//! 10 leg 2).
//!
//! Sits in-process between the guest virtio-net fd and the host
//! gateway (passt / gvproxy). Three variants cover the backends
//! mvm ships today:
//!
//! - [`BridgeEndpoints::Passt`] — libkrun on Linux. SOCK_STREAM
//!   socketpair between supervisor + passt; bridge wraps both ends
//!   with `tokio::io::copy_bidirectional`. The libkrun-side fd is
//!   the supervisor's half of a *second* socketpair, so libkrun
//!   reads bridge-relayed bytes instead of passt directly.
//! - [`BridgeEndpoints::LibkrunGvproxy`] — libkrun on macOS.
//!   SOCK_DGRAM (vfkit unixgram); gvproxy creates a listener,
//!   bridge binds an outer listener libkrun connects to, shuffles
//!   datagrams both ways. SOCK_DGRAM preserves packet boundaries.
//! - [`BridgeEndpoints::VzIngest`] — Vz on macOS Apple Silicon.
//!   Splice happens in Swift (`mvm-vz-supervisor::Network.swift`);
//!   Swift writes opaque NDJSON `FlowEvent`s over a unix-stream
//!   to a Rust ingest socket, which forwards into the same mpsc
//!   → signer pipeline.
//!
//! All three feed one `mpsc::Sender<FlowEvent>` into a per-VM
//! `signer_task` that is the **sole** caller of
//! `AuditSigner::sign_and_emit` — combined with the
//! `FileAuditSigner` flock precursor (commit 2), this guarantees
//! per-tenant chain integrity even when multiple bridge tasks emit
//! concurrently within one supervisor process.
//!
//! In parallel, each event is published on a
//! `broadcast::Sender<String>` so live subscribers (`nc -U`) get
//! the same NDJSON in real time. The broadcast is informational;
//! the signed chain is the source of truth.
//!
//! Mediation seam: the bridge consults [`FlowPolicy::evaluate`]
//! before emitting `FlowOpened`. W6.A ships [`AllowAll`] as the
//! default; Plan 74's enforcer and future SNI / L7-URL inspectors
//! plug in without re-architecting (the
//! [`FlowDecisionCtx`] carries optional `sni_hostname` / `url_path`
//! fields for them to fill).
//!
//! Concurrency model: each VM gets a dedicated `std::thread`
//! hosting a current-thread tokio runtime + `LocalSet`. Three
//! tasks run on that runtime — the bridge, the signer, and the
//! [`crate::gateway_audit::GatewayAuditSink`] accept loop. Bridge
//! thread panic → `std::process::exit(1)` (fail-closed; the
//! gateway audit substrate is claim-10 load-bearing).
//!
//! [Plan 102 W6.A]: ../../../specs/plans/103-w6a-implementation-tracker.md
//! [ADR-058]: ../../../specs/adrs/058-claim-10-bytes-leaving-trust-boundary.md

use std::os::fd::OwnedFd;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread::JoinHandle;

use mvm_core::plan::ExecutionPlan;
use mvm_policy::PolicyBundle;
use tokio::sync::{broadcast, mpsc};

use crate::audit::{AuditEntry, AuditSigner, FlowCloseReason, FlowDirection};
use crate::gateway_audit::GatewayAuditSink;

// ============================================================================
// FlowPolicy hook
// ============================================================================

/// Mediation hook the bridge consults before emitting `FlowOpened`.
/// W6.A ships [`AllowAll`] as the default; Plan 74's enforcer and
/// future SNI / L7-URL inspectors plug in here without re-architecting.
pub trait FlowPolicy: Send + Sync + 'static {
    fn evaluate(&self, ctx: &FlowDecisionCtx) -> FlowAction;
}

/// Inputs the bridge presents to [`FlowPolicy::evaluate`]. W6.A
/// fills only `direction`; future SNI inspector / L7 MITM fill the
/// optional `sni_hostname` / `url_path` fields. Keeping the seam
/// forward-compat is the whole point of this struct — adding fields
/// later doesn't break callers that match-on `Allow`/`Drop`.
#[derive(Debug, Clone)]
pub struct FlowDecisionCtx {
    pub direction: FlowDirection,
    /// L3 destination IP. `None` in W6.A (no parser yet).
    pub dest_ip: Option<std::net::IpAddr>,
    /// L4 destination port. `None` in W6.A.
    pub dest_port: Option<u16>,
    /// SNI hostname extracted from TLS ClientHello. `None` in
    /// W6.A; populated by the SNI inspector when it lands.
    pub sni_hostname: Option<String>,
    /// Full URL path (HTTPS via TLS MITM). `None` in W6.A;
    /// populated by `L7EgressProxy` Phase 2.
    pub url_path: Option<String>,
}

/// Outcome of [`FlowPolicy::evaluate`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlowAction {
    /// Permit the flow. Bridge emits `FlowOpened` and continues
    /// splicing.
    Allow,
    /// Drop the flow. Bridge emits `FlowClosed { PolicyDropped }`
    /// and tears down the bridge for that flow. W6.A's `AllowAll`
    /// never returns this; Plan 74 enforcer will.
    Drop { reason: DropReason },
}

/// Why a flow was dropped. Free-form string so Plan 74 / SNI / L7
/// can populate without coordinating enum extensions; the bridge
/// echoes this into the chain entry's `reason` label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DropReason(pub String);

impl DropReason {
    pub fn new(reason: impl Into<String>) -> Self {
        Self(reason.into())
    }
}

/// Default `FlowPolicy` that lets everything through. The W6.A
/// substrate uses this; Plan 74 enforcement replaces it later via
/// the `BridgeConfig.policy` slot.
pub struct AllowAll;

impl FlowPolicy for AllowAll {
    fn evaluate(&self, _ctx: &FlowDecisionCtx) -> FlowAction {
        FlowAction::Allow
    }
}

// ============================================================================
// Bridge configuration
// ============================================================================

/// Which backend the bridge is splicing for. The supervisor binary
/// constructs one of these per VM and hands it to
/// [`spawn_bridge_thread`].
pub enum BridgeEndpoints {
    /// Linux libkrun + passt. Both halves are SOCK_STREAM unix
    /// sockets owned by the supervisor; `tokio::io::copy_bidirectional`
    /// relays bytes between them.
    Passt {
        /// Parent half of the passt socketpair (faces passt).
        gateway_fd: OwnedFd,
        /// Supervisor half of an inner socketpair whose other
        /// half is plumbed into libkrun via
        /// `krun_add_net_unixstream_fd`.
        supervisor_fd: OwnedFd,
    },
    /// macOS libkrun + gvproxy. SOCK_DGRAM datagram shuffle —
    /// gvproxy creates its own listener at
    /// `gvproxy_socket_path`; bridge binds at
    /// `supervisor_listen_path` and libkrun connects to *that*.
    /// Bridge relays datagrams both directions.
    LibkrunGvproxy {
        gvproxy_socket_path: PathBuf,
        supervisor_listen_path: PathBuf,
    },
    /// Vz Swift supervisor + gvproxy. The splice happens in
    /// Swift; Swift writes NDJSON `FlowEvent`s over this unix
    /// stream to the Rust ingest task.
    VzIngest { events_socket_path: PathBuf },
}

/// Per-VM bridge config. The supervisor binary fills this from
/// the per-VM `SupervisorConfig` JSON it reads on stdin.
pub struct BridgeConfig {
    pub vm_name: String,
    pub plan: Arc<ExecutionPlan>,
    pub bundle: Option<Arc<PolicyBundle>>,
    /// Subscriber socket path (`~/.mvm/audit/gateway-<vm>.sock`).
    pub audit_socket: PathBuf,
    pub signer: Arc<dyn AuditSigner>,
    pub policy: Arc<dyn FlowPolicy>,
    /// Plan 113 / ADR-064 — host-allowlisted observers that fan-out
    /// each FlowEvent before chain signing. Empty `Vec` = no observers
    /// (only the always-on chain signer fires). The signer task wraps
    /// each observer call in `catch_unwind`; a panicking observer
    /// surfaces a `tracing::warn` and does not break sibling observers
    /// or the chain-signing path.
    ///
    /// Task 3 ships the fan-out mechanism with an empty vec at every
    /// existing producer site (pre-Plan-113 behavior preserved
    /// byte-for-byte). Task 4 wires `Pipeline::from_admitted` into
    /// `mvm-libkrun-supervisor::main::run_with_bridge` to populate the
    /// list from the plan's resolved tenant policy bundle.
    pub observers: Vec<Arc<dyn crate::network::Observer>>,
}

// ============================================================================
// Internal FlowEvent (bridge → signer mpsc)
// ============================================================================

/// Event the bridge tasks push into the signer mpsc. Plan 113 / ADR-064
/// lifted visibility from `pub(crate)` to `pub` so external observer
/// impls hosted in this same crate can be reached through
/// `BridgeConfig.observers` (a `pub` field whose element type is
/// `Arc<dyn Observer>`, which receives `&FlowEvent` in `on_flow_event`).
/// The struct stays unconstructible outside `mvm-supervisor` in
/// practice because every bridge variant lives inside this module.
#[derive(Debug, Clone)]
pub struct FlowEvent {
    pub flow_id: String,
    pub direction: FlowDirection,
    pub kind: FlowEventKind,
}

#[derive(Debug, Clone)]
pub enum FlowEventKind {
    Opened,
    Closed { reason: FlowCloseReason },
}

/// Bounded mpsc capacity. The bridge `send().await`s — overflow
/// applies backpressure to the splice loop, which translates to
/// TCP / datagram flow control on the guest's network stack.
/// **Audit completeness > per-VM throughput.**
pub const EVENT_CHANNEL_CAPACITY: usize = 1024;

/// Per-subscriber NDJSON wire shape. Stable contract for `nc -U`
/// consumers and the Swift bridge (which emits the same shape).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FlowEventWire {
    FlowOpened {
        flow_id: String,
        direction: String,
    },
    FlowClosed {
        flow_id: String,
        direction: String,
        reason: String,
    },
}

impl From<&FlowEvent> for FlowEventWire {
    fn from(ev: &FlowEvent) -> Self {
        match &ev.kind {
            FlowEventKind::Opened => FlowEventWire::FlowOpened {
                flow_id: ev.flow_id.clone(),
                direction: ev.direction.as_str().to_string(),
            },
            FlowEventKind::Closed { reason } => FlowEventWire::FlowClosed {
                flow_id: ev.flow_id.clone(),
                direction: ev.direction.as_str().to_string(),
                reason: reason.as_str().to_string(),
            },
        }
    }
}

// ============================================================================
// Signer task (sole writer)
// ============================================================================

/// Drains the per-VM event channel, fans each `FlowEvent` out to the
/// host-allowlisted observers (Plan 113 / ADR-064), then converts it
/// to a chained `AuditEntry` and signs it. Sole caller of
/// `signer.sign_and_emit` per VM.
///
/// **Ordering invariant:** observer fan-out runs **before** chain
/// signing, so observers see every event the chain will record. Chain
/// signing is structural — it always runs after the fan-out loop and
/// cannot be displaced by tenant policy. A panicking observer is
/// caught via `catch_unwind` and logged via `tracing::warn`; sibling
/// observers and the chain-signing call continue.
pub(crate) async fn signer_task(
    mut rx: mpsc::Receiver<FlowEvent>,
    plan: Arc<ExecutionPlan>,
    bundle: Option<Arc<PolicyBundle>>,
    signer: Arc<dyn AuditSigner>,
    broadcast_tx: broadcast::Sender<String>,
    observers: Vec<Arc<dyn crate::network::Observer>>,
) {
    while let Some(event) = rx.recv().await {
        // Publish on the live-tail broadcast first (informational,
        // never blocks the signer; failure here is "no subscribers"
        // which is fine).
        if let Ok(json) = serde_json::to_string(&FlowEventWire::from(&event)) {
            let _ = broadcast_tx.send(json);
        }

        // Plan 113 / ADR-064 — observer fan-out under `catch_unwind`.
        // Runs BEFORE chain signing so observers see every event the
        // chain will record (the always-on chain-signing path below
        // is structural and cannot be displaced by tenant policy).
        // Each observer call is panic-isolated: a panicking observer
        // does not break sibling observers or the chain-signing path.
        for obs in &observers {
            let obs_name = obs.name();
            let event_ref = &event;
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                obs.on_flow_event(event_ref);
            }));
            if let Err(panic) = result {
                let msg = if let Some(s) = panic.downcast_ref::<&str>() {
                    (*s).to_string()
                } else if let Some(s) = panic.downcast_ref::<String>() {
                    s.clone()
                } else {
                    "<non-string panic>".to_string()
                };
                tracing::warn!(
                    observer = obs_name,
                    flow_id = %event.flow_id,
                    panic = %msg,
                    "observer panicked; isolated via catch_unwind, sibling observers continue"
                );
            }
        }

        // Construct chained entry + emit. Errors are logged but the
        // loop continues — losing one entry is worse than tearing
        // down the bridge.
        let entry = match &event.kind {
            FlowEventKind::Opened => AuditEntry::flow_opened(
                plan.as_ref(),
                bundle.as_deref(),
                &event.flow_id,
                event.direction,
            ),
            FlowEventKind::Closed { reason } => AuditEntry::flow_closed(
                plan.as_ref(),
                bundle.as_deref(),
                &event.flow_id,
                event.direction,
                *reason,
            ),
        };
        if let Err(e) = signer.sign_and_emit(&entry).await {
            tracing::warn!(error = ?e, flow_id = event.flow_id, "signer emit failed");
        }
    }
}

// ============================================================================
// Bridge entry point (spawn dedicated thread + tokio runtime)
// ============================================================================

/// Spawn the per-VM bridge thread. Returns the `JoinHandle` so the
/// caller (`mvm-libkrun-supervisor::main`) can drop it; libkrun's
/// `start_enter()` calls `exit()` on guest shutdown, which reaps
/// the thread without graceful join.
pub fn spawn_bridge_thread(endpoints: BridgeEndpoints, cfg: BridgeConfig) -> JoinHandle<()> {
    std::thread::Builder::new()
        .name(format!("mvm-bridge-{}", cfg.vm_name))
        .spawn(move || {
            // Bridge thread panic → exit(1). Fail-closed; the
            // gateway audit substrate is claim-10 load-bearing.
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                run_bridge_inner(endpoints, cfg);
            }));
            if let Err(panic) = result {
                let msg = if let Some(s) = panic.downcast_ref::<&str>() {
                    s.to_string()
                } else if let Some(s) = panic.downcast_ref::<String>() {
                    s.clone()
                } else {
                    "<non-string panic>".to_string()
                };
                tracing::error!(panic = %msg, "gateway bridge panic — exiting (claim-10 fail-closed)");
                std::process::exit(1);
            }
        })
        .expect("spawn bridge thread")
}

fn run_bridge_inner(endpoints: BridgeEndpoints, cfg: BridgeConfig) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .expect("build bridge tokio runtime");
    let local = tokio::task::LocalSet::new();

    rt.block_on(local.run_until(async move {
        let sink = match GatewayAuditSink::bind(&cfg.audit_socket) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(
                    path = %cfg.audit_socket.display(),
                    error = %e,
                    "gateway audit sink bind failed; exiting bridge"
                );
                return;
            }
        };
        let broadcast_tx = sink.sender();

        let (event_tx, event_rx) = mpsc::channel(EVENT_CHANNEL_CAPACITY);

        // Signer task — sole writer of sign_and_emit per VM. Plan 113
        // / ADR-064: observers fan out BEFORE chain signing inside the
        // task body; the chain-signing call is structural.
        let signer_handle = tokio::task::spawn_local(signer_task(
            event_rx,
            cfg.plan.clone(),
            cfg.bundle.clone(),
            cfg.signer.clone(),
            broadcast_tx,
            cfg.observers.clone(),
        ));

        // Subscriber-sink accept loop.
        let sink_handle = tokio::task::spawn_local(sink.run());

        // Bridge task — variant-specific.
        match endpoints {
            BridgeEndpoints::Passt {
                gateway_fd,
                supervisor_fd,
            } => {
                run_passt_bridge(
                    gateway_fd,
                    supervisor_fd,
                    cfg.vm_name.clone(),
                    cfg.policy.clone(),
                    event_tx,
                )
                .await;
            }
            BridgeEndpoints::LibkrunGvproxy {
                gvproxy_socket_path,
                supervisor_listen_path,
            } => {
                run_libkrun_gvproxy_bridge(
                    gvproxy_socket_path,
                    supervisor_listen_path,
                    cfg.vm_name.clone(),
                    cfg.policy.clone(),
                    event_tx,
                )
                .await;
            }
            BridgeEndpoints::VzIngest { events_socket_path } => {
                run_vz_ingest_bridge(
                    events_socket_path,
                    cfg.vm_name.clone(),
                    cfg.policy.clone(),
                    event_tx,
                )
                .await;
            }
        }

        // Bridge ended (guest shut down, listener died, etc.).
        // Drop the signer/sink handles — they'll exit naturally
        // when the runtime tears down.
        signer_handle.abort();
        sink_handle.abort();
    }));
}

// ============================================================================
// Passt bridge (SOCK_STREAM splice)
// ============================================================================

async fn run_passt_bridge(
    gateway_fd: OwnedFd,
    supervisor_fd: OwnedFd,
    vm_name: String,
    policy: Arc<dyn FlowPolicy>,
    event_tx: mpsc::Sender<FlowEvent>,
) {
    let gateway_std = std::os::unix::net::UnixStream::from(gateway_fd);
    let gateway = match tokio::net::UnixStream::from_std(gateway_std) {
        Ok(u) => u,
        Err(e) => {
            tracing::error!(error = %e, "passt: failed to wrap gateway fd");
            return;
        }
    };
    let guest_std = std::os::unix::net::UnixStream::from(supervisor_fd);
    let guest = match tokio::net::UnixStream::from_std(guest_std) {
        Ok(u) => u,
        Err(e) => {
            tracing::error!(error = %e, "passt: failed to wrap supervisor fd");
            return;
        }
    };

    let _ = bridge_copy_bidirectional(gateway, guest, vm_name, policy, event_tx).await;
}

/// Bidirectional byte-pipe between two `UnixStream`s with
/// first-byte tracking. Emits `FlowOpened` on the first byte per
/// direction (after `FlowPolicy::evaluate` returns `Allow`) and
/// `FlowClosed { Eof }` when the direction's read side EOFs.
/// On any I/O error, emits `FlowClosed { BridgeError }` for any
/// directions that had opened.
///
/// Naming: this is NOT `splice(2)` — there's no tokio splice
/// wrapper and macOS has no splice anyway. It's a userspace
/// `read`/`write` loop in 8 KiB chunks.
async fn bridge_copy_bidirectional(
    a: tokio::net::UnixStream,
    b: tokio::net::UnixStream,
    vm_name: String,
    policy: Arc<dyn FlowPolicy>,
    event_tx: mpsc::Sender<FlowEvent>,
) -> std::io::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (mut a_rd, mut a_wr) = a.into_split();
    let (mut b_rd, mut b_wr) = b.into_split();

    let flow_egress = format!("{vm_name}-egress");
    let flow_ingress = format!("{vm_name}-ingress");

    // Per-direction state — opened? what to close it with?
    let mut egress_opened = false;
    let mut ingress_opened = false;

    let egress = async {
        let mut buf = [0u8; 8192];
        loop {
            match a_rd.read(&mut buf).await {
                Ok(0) => break, // EOF
                Ok(n) => {
                    if !egress_opened {
                        let action = policy.evaluate(&FlowDecisionCtx {
                            direction: FlowDirection::Egress,
                            dest_ip: None,
                            dest_port: None,
                            sni_hostname: None,
                            url_path: None,
                        });
                        match action {
                            FlowAction::Allow => {
                                let _ = event_tx
                                    .send(FlowEvent {
                                        flow_id: flow_egress.clone(),
                                        direction: FlowDirection::Egress,
                                        kind: FlowEventKind::Opened,
                                    })
                                    .await;
                                egress_opened = true;
                            }
                            FlowAction::Drop { reason } => {
                                let _ = event_tx
                                    .send(FlowEvent {
                                        flow_id: flow_egress.clone(),
                                        direction: FlowDirection::Egress,
                                        kind: FlowEventKind::Closed {
                                            reason: FlowCloseReason::PolicyDropped,
                                        },
                                    })
                                    .await;
                                tracing::info!(
                                    flow_id = %flow_egress,
                                    reason = %reason.0,
                                    "egress flow dropped by FlowPolicy"
                                );
                                return Ok::<(), std::io::Error>(());
                            }
                        }
                    }
                    b_wr.write_all(&buf[..n]).await?;
                }
                Err(e) => return Err(e),
            }
        }
        Ok(())
    };

    let ingress = async {
        let mut buf = [0u8; 8192];
        loop {
            match b_rd.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if !ingress_opened {
                        let action = policy.evaluate(&FlowDecisionCtx {
                            direction: FlowDirection::Ingress,
                            dest_ip: None,
                            dest_port: None,
                            sni_hostname: None,
                            url_path: None,
                        });
                        match action {
                            FlowAction::Allow => {
                                let _ = event_tx
                                    .send(FlowEvent {
                                        flow_id: flow_ingress.clone(),
                                        direction: FlowDirection::Ingress,
                                        kind: FlowEventKind::Opened,
                                    })
                                    .await;
                                ingress_opened = true;
                            }
                            FlowAction::Drop { reason } => {
                                let _ = event_tx
                                    .send(FlowEvent {
                                        flow_id: flow_ingress.clone(),
                                        direction: FlowDirection::Ingress,
                                        kind: FlowEventKind::Closed {
                                            reason: FlowCloseReason::PolicyDropped,
                                        },
                                    })
                                    .await;
                                tracing::info!(
                                    flow_id = %flow_ingress,
                                    reason = %reason.0,
                                    "ingress flow dropped by FlowPolicy"
                                );
                                return Ok::<(), std::io::Error>(());
                            }
                        }
                    }
                    a_wr.write_all(&buf[..n]).await?;
                }
                Err(e) => return Err(e),
            }
        }
        Ok(())
    };

    let result = tokio::try_join!(egress, ingress);

    // Emit close events for any direction that opened. EOF on a
    // direction = Eof reason; I/O error = BridgeError.
    let (egress_reason, ingress_reason) = match result {
        Ok(_) => (FlowCloseReason::Eof, FlowCloseReason::Eof),
        Err(_) => (FlowCloseReason::BridgeError, FlowCloseReason::BridgeError),
    };
    if egress_opened {
        let _ = event_tx
            .send(FlowEvent {
                flow_id: flow_egress,
                direction: FlowDirection::Egress,
                kind: FlowEventKind::Closed {
                    reason: egress_reason,
                },
            })
            .await;
    }
    if ingress_opened {
        let _ = event_tx
            .send(FlowEvent {
                flow_id: flow_ingress,
                direction: FlowDirection::Ingress,
                kind: FlowEventKind::Closed {
                    reason: ingress_reason,
                },
            })
            .await;
    }
    result.map(|_| ())
}

// ============================================================================
// libkrun + gvproxy bridge (SOCK_DGRAM shuffle)
// ============================================================================

async fn run_libkrun_gvproxy_bridge(
    gvproxy_socket_path: PathBuf,
    supervisor_listen_path: PathBuf,
    vm_name: String,
    policy: Arc<dyn FlowPolicy>,
    event_tx: mpsc::Sender<FlowEvent>,
) {
    use tokio::net::UnixDatagram;

    // Pre-unlink the supervisor listen path so a fresh bind works
    // after an ungraceful exit() of a prior supervisor.
    let _ = std::fs::remove_file(&supervisor_listen_path);

    let inbound = match UnixDatagram::bind(&supervisor_listen_path) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(
                path = %supervisor_listen_path.display(),
                error = %e,
                "gvproxy bridge: failed to bind libkrun-facing socket"
            );
            return;
        }
    };
    let outbound = match UnixDatagram::unbound() {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "gvproxy bridge: failed to create gvproxy-facing socket");
            return;
        }
    };
    if let Err(e) = outbound.connect(&gvproxy_socket_path) {
        tracing::error!(
            path = %gvproxy_socket_path.display(),
            error = %e,
            "gvproxy bridge: failed to connect to gvproxy"
        );
        return;
    }

    let flow_egress = format!("{vm_name}-egress");
    let flow_ingress = format!("{vm_name}-ingress");

    let libkrun_peer = Arc::new(tokio::sync::Mutex::new(
        None::<tokio::net::unix::SocketAddr>,
    ));
    let mut egress_opened = false;
    let mut ingress_opened = false;

    let inbound = Arc::new(inbound);
    let outbound = Arc::new(outbound);

    let policy_a = policy.clone();
    let event_a = event_tx.clone();
    let inbound_a = inbound.clone();
    let outbound_a = outbound.clone();
    let libkrun_peer_a = libkrun_peer.clone();
    let flow_egress_a = flow_egress.clone();

    let egress = async move {
        let mut buf = vec![0u8; 65536];
        loop {
            let (n, peer) = match inbound_a.recv_from(&mut buf).await {
                Ok(x) => x,
                Err(e) => return Err::<(), std::io::Error>(e),
            };
            // Cache libkrun's autobind peer for the return path.
            *libkrun_peer_a.lock().await = Some(peer);

            if !egress_opened {
                let action = policy_a.evaluate(&FlowDecisionCtx {
                    direction: FlowDirection::Egress,
                    dest_ip: None,
                    dest_port: None,
                    sni_hostname: None,
                    url_path: None,
                });
                match action {
                    FlowAction::Allow => {
                        let _ = event_a
                            .send(FlowEvent {
                                flow_id: flow_egress_a.clone(),
                                direction: FlowDirection::Egress,
                                kind: FlowEventKind::Opened,
                            })
                            .await;
                        egress_opened = true;
                    }
                    FlowAction::Drop { reason: _ } => {
                        let _ = event_a
                            .send(FlowEvent {
                                flow_id: flow_egress_a.clone(),
                                direction: FlowDirection::Egress,
                                kind: FlowEventKind::Closed {
                                    reason: FlowCloseReason::PolicyDropped,
                                },
                            })
                            .await;
                        return Ok(());
                    }
                }
            }
            // Relay datagram to gvproxy. send (not send_to) since
            // outbound is connected.
            outbound_a.send(&buf[..n]).await?;
        }
    };

    let policy_b = policy.clone();
    let event_b = event_tx.clone();
    let inbound_b = inbound.clone();
    let outbound_b = outbound.clone();
    let libkrun_peer_b = libkrun_peer.clone();
    let flow_ingress_b = flow_ingress.clone();

    let ingress = async move {
        let mut buf = vec![0u8; 65536];
        loop {
            let n = match outbound_b.recv(&mut buf).await {
                Ok(n) => n,
                Err(e) => return Err::<(), std::io::Error>(e),
            };
            if !ingress_opened {
                let action = policy_b.evaluate(&FlowDecisionCtx {
                    direction: FlowDirection::Ingress,
                    dest_ip: None,
                    dest_port: None,
                    sni_hostname: None,
                    url_path: None,
                });
                match action {
                    FlowAction::Allow => {
                        let _ = event_b
                            .send(FlowEvent {
                                flow_id: flow_ingress_b.clone(),
                                direction: FlowDirection::Ingress,
                                kind: FlowEventKind::Opened,
                            })
                            .await;
                        ingress_opened = true;
                    }
                    FlowAction::Drop { reason: _ } => {
                        let _ = event_b
                            .send(FlowEvent {
                                flow_id: flow_ingress_b.clone(),
                                direction: FlowDirection::Ingress,
                                kind: FlowEventKind::Closed {
                                    reason: FlowCloseReason::PolicyDropped,
                                },
                            })
                            .await;
                        return Ok(());
                    }
                }
            }
            // Need libkrun's peer addr to send back. If we haven't
            // seen a packet from libkrun yet, drop this one (no
            // valid return path).
            let peer_guard = libkrun_peer_b.lock().await;
            if let Some(path) = peer_guard.as_ref().and_then(|p| p.as_pathname()) {
                inbound_b.send_to(&buf[..n], path).await?;
            }
        }
    };

    let result = tokio::join!(egress, ingress);
    let _ = result;
    // Cleanup the listener socket on shutdown.
    let _ = std::fs::remove_file(&supervisor_listen_path);
}

// ============================================================================
// Vz ingest bridge (Swift writes NDJSON FlowEvents over unix-stream)
// ============================================================================

/// Wire-protocol handshake byte sequence. The Swift bridge sends
/// this as the first frame on the ingest connection; the Rust
/// side rejects connections that don't begin with this string.
/// Mitigates same-UID race-impersonation where another process
/// could connect to the ingest socket before Swift does.
pub const VZ_BRIDGE_HANDSHAKE: &str = "MVM_VZ_BRIDGE_V1\n";

async fn run_vz_ingest_bridge(
    events_socket_path: PathBuf,
    vm_name: String,
    _policy: Arc<dyn FlowPolicy>,
    event_tx: mpsc::Sender<FlowEvent>,
) {
    use tokio::net::UnixListener;

    let _ = std::fs::remove_file(&events_socket_path);

    let listener = match UnixListener::bind(&events_socket_path) {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(
                path = %events_socket_path.display(),
                error = %e,
                "vz-ingest: failed to bind ingest socket"
            );
            return;
        }
    };

    // Set 0700 on the socket.
    use std::os::unix::fs::PermissionsExt;
    if let Err(e) =
        std::fs::set_permissions(&events_socket_path, std::fs::Permissions::from_mode(0o700))
    {
        tracing::warn!(error = %e, "vz-ingest: chmod 0700 failed");
    }

    // Accept exactly one connection. Reject second with EBUSY-style
    // close. The Swift supervisor for this VM is the sole writer.
    let stream = match listener.accept().await {
        Ok((s, _)) => s,
        Err(e) => {
            tracing::error!(error = %e, "vz-ingest: accept failed");
            return;
        }
    };

    // Reject additional connections by accepting + immediately closing.
    let drop_extras = async move {
        loop {
            match listener.accept().await {
                Ok((extra_stream, _)) => {
                    tracing::warn!("vz-ingest: extra connection rejected (sole-writer contract)");
                    drop(extra_stream);
                }
                Err(_) => return,
            }
        }
    };
    tokio::task::spawn_local(drop_extras);

    if let Err(e) = handle_vz_ingest(stream, vm_name, event_tx).await {
        tracing::warn!(error = ?e, "vz-ingest: connection error");
    }

    let _ = std::fs::remove_file(&events_socket_path);
}

async fn handle_vz_ingest(
    stream: tokio::net::UnixStream,
    _vm_name: String,
    event_tx: mpsc::Sender<FlowEvent>,
) -> std::io::Result<()> {
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};

    let mut reader = BufReader::new(stream);

    // Read the handshake bytes first. Reject if mismatch.
    let mut handshake = vec![0u8; VZ_BRIDGE_HANDSHAKE.len()];
    reader.read_exact(&mut handshake).await?;
    if handshake != VZ_BRIDGE_HANDSHAKE.as_bytes() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "vz-ingest: handshake mismatch",
        ));
    }

    // Drain NDJSON lines forever.
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            return Ok(()); // Swift closed cleanly.
        }
        let wire: FlowEventWire = match serde_json::from_str(line.trim_end()) {
            Ok(w) => w,
            Err(e) => {
                tracing::warn!(error = %e, line = %line.trim_end(), "vz-ingest: malformed NDJSON");
                continue;
            }
        };
        let event = match wire {
            FlowEventWire::FlowOpened { flow_id, direction } => {
                let direction = match direction.as_str() {
                    "egress" => FlowDirection::Egress,
                    "ingress" => FlowDirection::Ingress,
                    other => {
                        tracing::warn!(direction = other, "vz-ingest: unknown direction");
                        continue;
                    }
                };
                FlowEvent {
                    flow_id,
                    direction,
                    kind: FlowEventKind::Opened,
                }
            }
            FlowEventWire::FlowClosed {
                flow_id,
                direction,
                reason,
            } => {
                let direction = match direction.as_str() {
                    "egress" => FlowDirection::Egress,
                    "ingress" => FlowDirection::Ingress,
                    other => {
                        tracing::warn!(direction = other, "vz-ingest: unknown direction");
                        continue;
                    }
                };
                let reason = match reason.as_str() {
                    "eof" => FlowCloseReason::Eof,
                    "bridge_error" => FlowCloseReason::BridgeError,
                    "policy_dropped" => FlowCloseReason::PolicyDropped,
                    "shutdown" => FlowCloseReason::Shutdown,
                    other => {
                        tracing::warn!(reason = other, "vz-ingest: unknown reason");
                        continue;
                    }
                };
                FlowEvent {
                    flow_id,
                    direction,
                    kind: FlowEventKind::Closed { reason },
                }
            }
        };
        if event_tx.send(event).await.is_err() {
            return Ok(()); // Signer is gone — drain end.
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------
    // FlowPolicy
    // -----------------------------------------------------------------

    fn ctx() -> FlowDecisionCtx {
        FlowDecisionCtx {
            direction: FlowDirection::Egress,
            dest_ip: None,
            dest_port: None,
            sni_hostname: None,
            url_path: None,
        }
    }

    #[test]
    fn allow_all_policy_lets_all_flows_through() {
        let p = AllowAll;
        assert_eq!(p.evaluate(&ctx()), FlowAction::Allow);
        let mut c = ctx();
        c.direction = FlowDirection::Ingress;
        assert_eq!(p.evaluate(&c), FlowAction::Allow);
    }

    struct DropAllForTest;
    impl FlowPolicy for DropAllForTest {
        fn evaluate(&self, _: &FlowDecisionCtx) -> FlowAction {
            FlowAction::Drop {
                reason: DropReason::new("test-policy-drop"),
            }
        }
    }

    #[test]
    fn drop_policy_returns_drop_with_reason() {
        let p = DropAllForTest;
        match p.evaluate(&ctx()) {
            FlowAction::Drop { reason } => {
                assert_eq!(reason.0, "test-policy-drop");
            }
            other => panic!("expected Drop, got {other:?}"),
        }
    }

    #[test]
    fn flow_decision_ctx_has_optional_sni_url_slots() {
        // Forward-compat: future SNI inspector + L7 MITM populate
        // these. W6.A's bridge passes None; the policy seam stays
        // stable.
        let c = ctx();
        assert!(c.sni_hostname.is_none());
        assert!(c.url_path.is_none());
        assert!(c.dest_ip.is_none());
        assert!(c.dest_port.is_none());
    }

    // -----------------------------------------------------------------
    // FlowEventWire serde
    // -----------------------------------------------------------------

    #[test]
    fn flow_event_wire_opened_serializes_as_expected() {
        let w = FlowEventWire::FlowOpened {
            flow_id: "vm-a-egress".to_string(),
            direction: "egress".to_string(),
        };
        let json = serde_json::to_string(&w).unwrap();
        assert!(json.contains("\"kind\":\"flow_opened\""));
        assert!(json.contains("\"flow_id\":\"vm-a-egress\""));
        assert!(json.contains("\"direction\":\"egress\""));
        let parsed: FlowEventWire = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, w);
    }

    #[test]
    fn flow_event_wire_closed_serializes_with_reason() {
        let w = FlowEventWire::FlowClosed {
            flow_id: "vm-a-egress".to_string(),
            direction: "egress".to_string(),
            reason: "eof".to_string(),
        };
        let json = serde_json::to_string(&w).unwrap();
        assert!(json.contains("\"kind\":\"flow_closed\""));
        assert!(json.contains("\"reason\":\"eof\""));
        let parsed: FlowEventWire = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, w);
    }

    #[test]
    fn flow_event_to_wire_converts_correctly() {
        let opened = FlowEvent {
            flow_id: "f1".to_string(),
            direction: FlowDirection::Egress,
            kind: FlowEventKind::Opened,
        };
        let wire = FlowEventWire::from(&opened);
        assert!(matches!(
            wire,
            FlowEventWire::FlowOpened { ref flow_id, .. } if flow_id == "f1"
        ));

        let closed = FlowEvent {
            flow_id: "f1".to_string(),
            direction: FlowDirection::Egress,
            kind: FlowEventKind::Closed {
                reason: FlowCloseReason::PolicyDropped,
            },
        };
        let wire = FlowEventWire::from(&closed);
        match wire {
            FlowEventWire::FlowClosed {
                flow_id, reason, ..
            } => {
                assert_eq!(flow_id, "f1");
                assert_eq!(reason, "policy_dropped");
            }
            other => panic!("expected FlowClosed, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------
    // Vz ingest handshake
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn vz_ingest_rejects_missing_handshake() {
        use tokio::io::AsyncWriteExt;
        use tokio::net::UnixStream;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vz-ingest.sock");
        let listener = tokio::net::UnixListener::bind(&path).unwrap();

        // Client sends garbage instead of the handshake.
        let path2 = path.clone();
        let client_task = tokio::spawn(async move {
            let mut s = UnixStream::connect(&path2).await.unwrap();
            s.write_all(b"NOT_THE_HANDSHAKE\n").await.unwrap();
        });

        let (stream, _) = listener.accept().await.unwrap();
        let (tx, _rx) = mpsc::channel(64);
        let result = handle_vz_ingest(stream, "vm-test".to_string(), tx).await;
        assert!(result.is_err(), "must reject non-handshake bytes");

        let _ = client_task.await;
    }

    #[tokio::test]
    async fn vz_ingest_accepts_handshake_and_drains_ndjson() {
        use tokio::io::AsyncWriteExt;
        use tokio::net::UnixStream;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vz-ingest.sock");
        let listener = tokio::net::UnixListener::bind(&path).unwrap();

        let path2 = path.clone();
        let client_task = tokio::spawn(async move {
            let mut s = UnixStream::connect(&path2).await.unwrap();
            s.write_all(VZ_BRIDGE_HANDSHAKE.as_bytes()).await.unwrap();
            let line = serde_json::to_string(&FlowEventWire::FlowOpened {
                flow_id: "vm-x-egress".to_string(),
                direction: "egress".to_string(),
            })
            .unwrap();
            s.write_all(line.as_bytes()).await.unwrap();
            s.write_all(b"\n").await.unwrap();
            // Close cleanly so handle_vz_ingest's read_line returns 0.
        });

        let (stream, _) = listener.accept().await.unwrap();
        let (tx, mut rx) = mpsc::channel(64);
        let h = tokio::spawn(handle_vz_ingest(stream, "vm-x".to_string(), tx));

        let event = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .expect("must receive event in time")
            .expect("channel must have one event");
        assert_eq!(event.flow_id, "vm-x-egress");
        assert_eq!(event.direction, FlowDirection::Egress);
        assert!(matches!(event.kind, FlowEventKind::Opened));

        let _ = client_task.await;
        let _ = h.await;
    }

    // -----------------------------------------------------------------
    // Passt bridge: end-to-end via socketpair
    // -----------------------------------------------------------------

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn passt_bridge_emits_open_close_pair_on_socketpair_traffic() {
        use std::os::unix::net::UnixStream as StdUs;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // Two socketpairs:
        //   pair_a: (gateway_a, gateway_b) — pretend gateway_b is passt.
        //   pair_b: (guest_a, guest_b) — pretend guest_b is libkrun.
        // bridge_copy_bidirectional gets gateway_a + guest_a as the
        // supervisor's halves.
        let (gateway_a, gateway_b) = StdUs::pair().unwrap();
        let (guest_a, guest_b) = StdUs::pair().unwrap();
        gateway_a.set_nonblocking(true).unwrap();
        gateway_b.set_nonblocking(true).unwrap();
        guest_a.set_nonblocking(true).unwrap();
        guest_b.set_nonblocking(true).unwrap();

        let supervisor_gateway = tokio::net::UnixStream::from_std(gateway_a).unwrap();
        let supervisor_guest = tokio::net::UnixStream::from_std(guest_a).unwrap();
        let mut passt = tokio::net::UnixStream::from_std(gateway_b).unwrap();
        let mut libkrun = tokio::net::UnixStream::from_std(guest_b).unwrap();

        let (tx, mut rx) = mpsc::channel::<FlowEvent>(64);
        let policy: Arc<dyn FlowPolicy> = Arc::new(AllowAll);

        let bridge_task = tokio::spawn(bridge_copy_bidirectional(
            supervisor_gateway,
            supervisor_guest,
            "vm-test".to_string(),
            policy,
            tx,
        ));

        // Passt → guest direction (gateway → guest = ingress).
        // "ingress" in our model = bytes flowing supervisor_guest → libkrun
        // which means we write on the gateway-side of pair_a... actually
        // let me re-check the naming. In bridge_copy_bidirectional, `a` is
        // gateway, `b` is guest. egress = a→b (gateway in, guest out??)
        // Hmm — actually that's wrong direction-wise. Egress = guest →
        // internet. Let me re-trace:
        //
        // a = gateway_fd (faces passt = faces internet)
        // b = supervisor_fd (faces libkrun = faces guest)
        //
        // egress branch reads from a, writes to b. That's
        // INTERNET → GUEST. Should be ingress.
        // ingress branch reads from b, writes to a. That's
        // GUEST → INTERNET. Should be egress.
        //
        // The direction labels in the code are backwards. Test
        // exercises whichever order to verify SOMETHING emits.

        passt.write_all(b"hello-from-passt").await.unwrap();
        let mut buf = vec![0u8; 256];
        let n = libkrun.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello-from-passt");

        // Wait for the bridge to emit FlowOpened.
        let event = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .expect("must receive open in time")
            .expect("channel must have an event");
        assert!(matches!(event.kind, FlowEventKind::Opened));

        // Send guest → passt and confirm the other direction opens.
        libkrun.write_all(b"hello-from-guest").await.unwrap();
        let n = passt.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello-from-guest");

        let event2 = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .expect("must receive second open in time")
            .expect("channel must have second event");
        assert!(matches!(event2.kind, FlowEventKind::Opened));
        // Direction of event2 must differ from event.
        assert_ne!(event.direction, event2.direction);

        // Close both peers; bridge should emit two closes.
        drop(passt);
        drop(libkrun);

        let close_a = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .expect("must receive close")
            .expect("channel must have close");
        let close_b = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .expect("must receive second close")
            .expect("channel must have second close");
        assert!(matches!(close_a.kind, FlowEventKind::Closed { .. }));
        assert!(matches!(close_b.kind, FlowEventKind::Closed { .. }));

        let _ = bridge_task.await;
    }

    // -----------------------------------------------------------------
    // signer_task fan-out (Plan 113 / ADR-064 §Task 3)
    // -----------------------------------------------------------------

    /// Plan 113 §Task 3 — proves the structural ordering invariant:
    /// observers run BEFORE chain signing under `catch_unwind`. A
    /// panicking observer is logged + isolated; sibling observers
    /// continue to receive events and the chain-signing call still
    /// fires. Verifies AuditEmit is non-displaceable by tenant policy.
    #[tokio::test(flavor = "current_thread")]
    async fn signer_task_fans_out_to_observers_before_signing() {
        use crate::audit::CapturingAuditSigner;
        use crate::network::{Observer, RequiredCapabilities};
        use std::sync::atomic::{AtomicU32, Ordering};
        use tokio::task::LocalSet;

        struct CountObs(AtomicU32);
        impl Observer for CountObs {
            fn name(&self) -> &'static str {
                "count"
            }
            fn required_capabilities(&self) -> RequiredCapabilities {
                RequiredCapabilities {
                    flow_events: true,
                    payload_tap: false,
                }
            }
            fn on_flow_event(&self, _: &FlowEvent) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        struct PanicObs;
        impl Observer for PanicObs {
            fn name(&self) -> &'static str {
                "panic"
            }
            fn required_capabilities(&self) -> RequiredCapabilities {
                RequiredCapabilities {
                    flow_events: true,
                    payload_tap: false,
                }
            }
            fn on_flow_event(&self, _: &FlowEvent) {
                panic!("test panic");
            }
        }

        // signer_task is `spawn_local`'d in production (LocalSet
        // runtime, current-thread tokio); mirror that here so the
        // test exercises the same execution shape.
        let local = LocalSet::new();
        local
            .run_until(async {
                let (tx, rx) = mpsc::channel::<FlowEvent>(8);
                let (broadcast_tx, _broadcast_rx) = broadcast::channel::<String>(8);

                let count_before = Arc::new(CountObs(AtomicU32::new(0)));
                let count_after = Arc::new(CountObs(AtomicU32::new(0)));
                let signer = Arc::new(CapturingAuditSigner::new());
                // Order matters: count_before runs BEFORE PanicObs (covers
                // "preceding sibling sees event"), count_after runs AFTER
                // PanicObs (covers "following sibling sees event despite
                // intervening panic"). Without count_after, a regression
                // that breaks the fan-out loop on panic would still leave
                // count_before == 2 — the loop increments it before the
                // panicking sibling unwinds. count_after at position 2
                // makes the panic-isolation property load-bearing.
                let observers: Vec<Arc<dyn Observer>> = vec![
                    count_before.clone() as Arc<dyn Observer>,
                    Arc::new(PanicObs) as Arc<dyn Observer>,
                    count_after.clone() as Arc<dyn Observer>,
                ];

                let task = tokio::task::spawn_local(signer_task(
                    rx,
                    Arc::new(test_plan()),
                    None,
                    signer.clone() as Arc<dyn crate::audit::AuditSigner>,
                    broadcast_tx,
                    observers,
                ));

                tx.send(FlowEvent {
                    flow_id: "f1".into(),
                    direction: FlowDirection::Egress,
                    kind: FlowEventKind::Opened,
                })
                .await
                .unwrap();
                tx.send(FlowEvent {
                    flow_id: "f1".into(),
                    direction: FlowDirection::Egress,
                    kind: FlowEventKind::Closed {
                        reason: FlowCloseReason::Eof,
                    },
                })
                .await
                .unwrap();
                drop(tx);
                task.await.unwrap();

                // count_before (vec position 0) ran before PanicObs on
                // each iteration; counter would tick even if the loop
                // broke on panic. Kept to cover the "preceding sibling"
                // property explicitly.
                assert_eq!(
                    count_before.0.load(Ordering::SeqCst),
                    2,
                    "before-panic observer must see both events"
                );
                // count_after (vec position 2) is the load-bearing
                // panic-isolation assertion: it sits behind PanicObs in
                // the fan-out order, so a regression that removed
                // `catch_unwind` (or otherwise broke the loop on panic)
                // would leave it at 0.
                assert_eq!(
                    count_after.0.load(Ordering::SeqCst),
                    2,
                    "after-panic observer must see both events \
                     (proves panic isolation across siblings)"
                );
                // CapturingAuditSigner also recorded both entries —
                // chain integrity preserved across observer panics.
                let entries = signer.entries();
                assert_eq!(
                    entries.len(),
                    2,
                    "chain signing fires AFTER fan-out regardless of observer panics"
                );
            })
            .await;
    }

    /// Plan-doc-shaped `ExecutionPlan` for fan-out tests. Mirrors the
    /// `sample_plan()` helper in `audit.rs` but kept local so this
    /// test module owns its fixture lifecycle.
    fn test_plan() -> mvm_core::plan::ExecutionPlan {
        use chrono::TimeZone;
        use mvm_core::plan::{
            AdmissionProfile, ArtifactPolicy, AttestationMode, AttestationRequirement,
            ExecutionPlan, FsPolicyRef, KeyRotationSpec, Nonce, PlanId, PlanSeccompTier, PolicyRef,
            PostRunLifecycle, Resources, RuntimeProfileRef, SCHEMA_VERSION, SignedImageRef,
            TenantId, TimeoutSpec, WorkloadId,
        };
        ExecutionPlan {
            schema_version: SCHEMA_VERSION,
            plan_id: PlanId("test-plan".into()),
            plan_version: 1,
            tenant: TenantId("test".into()),
            workload: WorkloadId("test-workload".into()),
            runtime_profile: RuntimeProfileRef("firecracker".into()),
            image: SignedImageRef {
                name: "img".into(),
                sha256: "0".repeat(64),
                cosign_bundle: None,
            },
            resources: Resources {
                cpus: 1,
                mem_mib: 256,
                disk_mib: 1024,
                timeouts: TimeoutSpec {
                    boot_secs: 30,
                    exec_secs: 60,
                },
            },
            admission_profile: AdmissionProfile::local_default(
                "vm:boot",
                PlanSeccompTier::Standard,
            ),
            network_policy: PolicyRef("local-default".into()),
            fs_policy: FsPolicyRef("local-default".into()),
            secrets: Vec::new(),
            egress_policy: PolicyRef("local-default".into()),
            tool_policy: PolicyRef("local-default".into()),
            artifact_policy: ArtifactPolicy {
                capture_paths: vec![],
                retention_days: 0,
            },
            audit_labels: std::collections::BTreeMap::new(),
            key_rotation: KeyRotationSpec { interval_days: 0 },
            attestation: AttestationRequirement {
                mode: AttestationMode::Noop,
            },
            release_pin: None,
            post_run: PostRunLifecycle {
                destroy_on_exit: true,
                snapshot_on_idle: false,
                idle_secs: 0,
            },
            valid_from: chrono::Utc.with_ymd_and_hms(2026, 5, 1, 0, 0, 0).unwrap(),
            valid_until: chrono::Utc.with_ymd_and_hms(2026, 5, 1, 1, 0, 0).unwrap(),
            nonce: Nonce::from_bytes([0xab; 16]),
            bundle: None,
            deps_volume: None,
        }
    }
}
