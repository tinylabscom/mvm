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
//! [`crate::supervisor::gateway_audit::GatewayAuditSink`] accept loop. Bridge
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
use mvm_core::policy::{EmergencyDeny, PolicyBundle};
use tokio::sync::{broadcast, mpsc};

use crate::supervisor::audit::{AuditEntry, AuditSigner, FlowCloseReason, FlowDirection};
use crate::supervisor::gateway_audit::GatewayAuditSink;
// Plan 141 / ADR-064 — packet-observer pipeline wiring.
use crate::supervisor::network::Observer;
use crate::supervisor::network::PacketCtx;
use crate::supervisor::network::latency::ObserverLatency;
use crate::supervisor::network::packet::{self, FlowKey};
use crate::supervisor::network::pipeline::{PacketDecision, run_packet_pipeline};
// plan 123 A3.2/A3.3: egress stages wired into the live pipeline, carried on
// ObserverWiring (default no-op) so plan 129 sets them without touching the
// call sites.
use crate::supervisor::network::stages::{
    NoopSubstitution, ScanStage, SubstitutionStage, build_egress_scan,
};
use crate::supervisor::proxy::l4::LiveL4Gate;
use std::collections::HashSet;

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
    pub observers: Vec<Arc<dyn crate::supervisor::network::Observer>>,
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
    Closed {
        reason: FlowCloseReason,
    },
    /// Plan 141 / ADR-064 — a host-allowlisted observer's `on_packet`
    /// forced a fail-closed flow kill. `reason` ∈ {`drop`,
    /// `modify_over_mtu`, `modify_unserializable`}.
    ObserverFault {
        observer: String,
        reason: String,
    },
}

/// Bounded mpsc capacity. The bridge `send().await`s — overflow
/// applies backpressure to the splice loop, which translates to
/// TCP / datagram flow control on the guest's network stack.
/// **Audit completeness > per-VM throughput.**
pub const EVENT_CHANNEL_CAPACITY: usize = 1024;

/// Frame-size ceiling for `Verdict::Modify` rebuilds (Plan 141). A
/// rebuilt frame larger than this cannot traverse the unixgram /
/// length-prefixed datagram path, so the flow is killed (fail-closed,
/// Q8). Set to the practical datagram max rather than the 1500 link MTU
/// so a legitimately large (e.g. TSO) original frame isn't spuriously
/// killed when an observer shrinks or keeps its payload size.
pub const BRIDGE_MTU: usize = 65_535;

/// Per-VM packet-observer wiring threaded into the bridge variants
/// (Plan 141 / ADR-064). Bundled into one struct so the variant fns stay
/// under the `too_many_arguments` lint. `observers` mirrors the set
/// `signer_task` fans flow-events to; the same observer may implement both
/// `on_flow_event` and `on_packet`. `killed_flows` is shared across both
/// directions so a kill on one is honoured everywhere.
pub struct ObserverWiring {
    pub observers: Vec<Arc<dyn Observer>>,
    pub latency: Arc<ObserverLatency>,
    pub killed_flows: Arc<tokio::sync::Mutex<HashSet<FlowKey>>>,
    pub mtu: usize,
    /// Plan 129 egress stages (A3.3). Default no-op; Plan 129 sets these so its
    /// substitution/leak-scan run on the live egress path without a code edit.
    pub substitution: Arc<dyn SubstitutionStage>,
    pub scan: Arc<dyn ScanStage>,
}

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
    FlowObserverFault {
        flow_id: String,
        direction: String,
        observer: String,
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
            FlowEventKind::ObserverFault { observer, reason } => FlowEventWire::FlowObserverFault {
                flow_id: ev.flow_id.clone(),
                direction: ev.direction.as_str().to_string(),
                observer: observer.clone(),
                reason: reason.clone(),
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
    observers: Vec<Arc<dyn crate::supervisor::network::Observer>>,
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
            FlowEventKind::ObserverFault { observer, reason } => AuditEntry::flow_observer_fault(
                plan.as_ref(),
                bundle.as_deref(),
                &event.flow_id,
                event.direction,
                observer,
                reason,
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

        // Plan 123 Slice 3 — resolve the tenant's L4 egress policy from the
        // admitted policy bundle, if one reached the bridge, so the per-tenant
        // filter composes under mandatory-deny. No bundle (the common case
        // today: bundle_json carries a PlanArtifact pin, not resolved content)
        // → None → mandatory-deny only, the prior live default. A bundle whose
        // L4 specs fail to translate (admission should have rejected it) fails
        // CLOSED to deny-all, never open. Emergency/now only gate the tool
        // policy, so the network resolution is stable.
        let egress_policy = cfg.bundle.as_deref().map(|bundle| {
            let net = mvm_core::policy::resolve(
                bundle,
                &cfg.plan.tenant,
                chrono::Utc::now(),
                &EmergencyDeny::default(),
            )
            .network;
            LiveL4Gate::from_specs(&net.l4)
                .map(|gate| gate.policy)
                .unwrap_or_else(|_| crate::supervisor::proxy::l4::L4Policy::deny_all())
        });
        // Plan 141 — packet-observer wiring shared across both directions.
        let wiring = ObserverWiring {
            observers: cfg.observers.clone(),
            latency: Arc::new(ObserverLatency::new(
                cfg.vm_name.clone(),
                cfg.plan.tenant.0.clone(),
            )),
            killed_flows: Arc::new(tokio::sync::Mutex::new(HashSet::new())),
            mtu: BRIDGE_MTU,
            substitution: Arc::new(NoopSubstitution),
            // Host-side mandatory-deny (link-local + cloud metadata), always on
            // and unbypassable from inside a compromised guest; the per-tenant
            // L4 filter composes under it when a bundle is present.
            scan: build_egress_scan(egress_policy),
        };

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
                    cfg.plan.tenant.0.clone(),
                    cfg.policy.clone(),
                    event_tx,
                    wiring,
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
                    cfg.plan.tenant.0.clone(),
                    cfg.policy.clone(),
                    event_tx,
                    wiring,
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
    tenant: String,
    policy: Arc<dyn FlowPolicy>,
    event_tx: mpsc::Sender<FlowEvent>,
    wiring: ObserverWiring,
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

    let _ =
        bridge_copy_bidirectional(gateway, guest, vm_name, tenant, policy, event_tx, wiring).await;
}

/// Read one length-prefixed frame from a passt/qemu stream socket. passt's
/// `--fd` backend (which libkrun's `krun_add_net_unixstream_fd` path
/// speaks) uses the qemu socket protocol: each ethernet frame is prefixed
/// with a 4-byte big-endian length. Returns `Ok(None)` on a clean EOF at a
/// frame boundary. Caps the frame at 65535 — a bogus length fails closed
/// instead of allocating gigabytes.
///
/// NOTE: the 4-byte-BE qemu-socket framing is the documented passt wire
/// format, but the live Passt path is Linux-only and is validated on
/// Linux/KVM CI (this host cannot exercise it). The reframing logic itself
/// is unit-tested via an in-memory duplex.
async fn read_one_frame<R>(r: &mut R) -> std::io::Result<Option<Vec<u8>>>
where
    R: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;
    let mut lenbuf = [0u8; 4];
    match r.read_exact(&mut lenbuf).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_be_bytes(lenbuf) as usize;
    if len > 65_535 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "passt frame length-prefix exceeds 65535",
        ));
    }
    let mut frame = vec![0u8; len];
    r.read_exact(&mut frame).await?;
    Ok(Some(frame))
}

/// Write one length-prefixed frame (inverse of [`read_one_frame`]).
async fn write_one_frame<W>(w: &mut W, frame: &[u8]) -> std::io::Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;
    let len = u32::try_from(frame.len()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "frame too large for 4-byte length prefix",
        )
    })?;
    w.write_all(&len.to_be_bytes()).await?;
    w.write_all(frame).await?;
    Ok(())
}

/// Frame-aware bidirectional bridge between two passt/qemu stream sockets.
/// Reads one length-prefixed ethernet frame at a time, runs the
/// packet-observer pipeline (Plan 141), and re-emits the (possibly
/// rebuilt) frame with a corrected length prefix. Emits `FlowOpened` on
/// the first frame per direction (after `FlowPolicy::evaluate` returns
/// `Allow`) and `FlowClosed { Eof }` on a clean EOF; `BridgeError` on I/O
/// error.
///
/// Direction semantics (the pre-Plan-141 opaque-copy code had the labels
/// reversed, which didn't matter for a byte pump but does for observers):
/// `a` faces passt/internet, `b` faces libkrun/guest. **Egress** = guest →
/// internet (read `b`, write `a`); **ingress** = internet → guest (read
/// `a`, write `b`).
async fn bridge_copy_bidirectional(
    a: tokio::net::UnixStream,
    b: tokio::net::UnixStream,
    vm_name: String,
    tenant: String,
    policy: Arc<dyn FlowPolicy>,
    event_tx: mpsc::Sender<FlowEvent>,
    wiring: ObserverWiring,
) -> std::io::Result<()> {
    let (mut a_rd, mut a_wr) = a.into_split();
    let (mut b_rd, mut b_wr) = b.into_split();

    let flow_egress = format!("{vm_name}-egress");
    let flow_ingress = format!("{vm_name}-ingress");

    let mut egress_opened = false;
    let mut ingress_opened = false;

    let observers = wiring.observers;
    let latency = wiring.latency;
    let killed_flows = wiring.killed_flows;
    let mtu = wiring.mtu;
    let substitution = wiring.substitution;
    let scan = wiring.scan;

    // Egress: guest → internet. Read framed from b, observe, write to a.
    let egress = async {
        loop {
            let frame = match read_one_frame(&mut b_rd).await {
                Ok(Some(f)) => f,
                Ok(None) => break,
                Err(e) => return Err::<(), std::io::Error>(e),
            };
            if !egress_opened {
                match policy.evaluate(&FlowDecisionCtx {
                    direction: FlowDirection::Egress,
                    dest_ip: None,
                    dest_port: None,
                    sni_hostname: None,
                    url_path: None,
                }) {
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
                        tracing::info!(flow_id = %flow_egress, reason = %reason.0, "egress flow dropped by FlowPolicy");
                        return Ok(());
                    }
                }
            }
            if flow_is_killed(&killed_flows, &frame).await {
                continue;
            }
            let ctx = PacketCtx {
                vm_name: &vm_name,
                tenant: &tenant,
                direction: FlowDirection::Egress,
                flow_id: &flow_egress,
            };
            match run_packet_pipeline(
                &observers,
                substitution.as_ref(),
                scan.as_ref(),
                ctx,
                &frame,
                mtu,
                &latency,
            ) {
                PacketDecision::Forward { frame: out, .. } => {
                    write_one_frame(&mut a_wr, &out).await?;
                }
                PacketDecision::Kill {
                    observer,
                    reason,
                    flow_key,
                } => {
                    if let Some(k) = flow_key {
                        killed_flows.lock().await.insert(k);
                    }
                    let _ = event_tx
                        .send(FlowEvent {
                            flow_id: flow_egress.clone(),
                            direction: FlowDirection::Egress,
                            kind: FlowEventKind::ObserverFault {
                                observer: observer.to_string(),
                                reason: reason.as_str().to_string(),
                            },
                        })
                        .await;
                }
            }
            latency.write_scrape_file();
        }
        Ok(())
    };

    // Ingress: internet → guest. Read framed from a, observe, write to b.
    let ingress = async {
        loop {
            let frame = match read_one_frame(&mut a_rd).await {
                Ok(Some(f)) => f,
                Ok(None) => break,
                Err(e) => return Err::<(), std::io::Error>(e),
            };
            if !ingress_opened {
                match policy.evaluate(&FlowDecisionCtx {
                    direction: FlowDirection::Ingress,
                    dest_ip: None,
                    dest_port: None,
                    sni_hostname: None,
                    url_path: None,
                }) {
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
                        tracing::info!(flow_id = %flow_ingress, reason = %reason.0, "ingress flow dropped by FlowPolicy");
                        return Ok(());
                    }
                }
            }
            if flow_is_killed(&killed_flows, &frame).await {
                continue;
            }
            let ctx = PacketCtx {
                vm_name: &vm_name,
                tenant: &tenant,
                direction: FlowDirection::Ingress,
                flow_id: &flow_ingress,
            };
            match run_packet_pipeline(
                &observers,
                substitution.as_ref(),
                scan.as_ref(),
                ctx,
                &frame,
                mtu,
                &latency,
            ) {
                PacketDecision::Forward { frame: out, .. } => {
                    write_one_frame(&mut b_wr, &out).await?;
                }
                PacketDecision::Kill {
                    observer,
                    reason,
                    flow_key,
                } => {
                    if let Some(k) = flow_key {
                        killed_flows.lock().await.insert(k);
                    }
                    let _ = event_tx
                        .send(FlowEvent {
                            flow_id: flow_ingress.clone(),
                            direction: FlowDirection::Ingress,
                            kind: FlowEventKind::ObserverFault {
                                observer: observer.to_string(),
                                reason: reason.as_str().to_string(),
                            },
                        })
                        .await;
                }
            }
            latency.write_scrape_file();
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

/// Plan 141 — true if `raw` parses to a flow already in `killed`. Cheap:
/// only parses when at least one flow has been killed. The async-mutex
/// guard is held across the synchronous parse (no await in between).
async fn flow_is_killed(killed: &tokio::sync::Mutex<HashSet<FlowKey>>, raw: &[u8]) -> bool {
    let guard = killed.lock().await;
    if guard.is_empty() {
        return false;
    }
    match packet::parse(raw) {
        Some(p) => guard.contains(&p.five_tuple.flow_key()),
        None => false,
    }
}

async fn run_libkrun_gvproxy_bridge(
    gvproxy_socket_path: PathBuf,
    supervisor_listen_path: PathBuf,
    vm_name: String,
    tenant: String,
    policy: Arc<dyn FlowPolicy>,
    event_tx: mpsc::Sender<FlowEvent>,
    wiring: ObserverWiring,
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
    // The gvproxy-facing socket MUST be bound to a pathname, not left
    // unbound/autobind: gvproxy refuses datagrams from an empty-address
    // peer ("vfkit accept error: vfkit socket address is empty") and needs
    // a concrete address to send replies back to. macOS additionally never
    // autobinds AF_UNIX datagram sockets, so an unbound socket here has no
    // address at all and the gateway can neither accept our frames nor
    // reply. Bind a sibling path next to the libkrun-facing listener.
    let outbound_bind_path = gvproxy_outbound_bind_path(&supervisor_listen_path);
    let _ = std::fs::remove_file(&outbound_bind_path);
    let outbound = match UnixDatagram::bind(&outbound_bind_path) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(
                path = %outbound_bind_path.display(),
                error = %e,
                "gvproxy bridge: failed to bind gvproxy-facing socket"
            );
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

    // Plan 141 — per-direction clones of the packet-observer wiring.
    let mtu = wiring.mtu;
    let policy_a = policy.clone();
    let event_a = event_tx.clone();
    let inbound_a = inbound.clone();
    let outbound_a = outbound.clone();
    let libkrun_peer_a = libkrun_peer.clone();
    let flow_egress_a = flow_egress.clone();
    let observers_a = wiring.observers.clone();
    let latency_a = wiring.latency.clone();
    let killed_flows_a = wiring.killed_flows.clone();
    let substitution_a = wiring.substitution.clone();
    let scan_a = wiring.scan.clone();
    let vm_name_a = vm_name.clone();
    let tenant_a = tenant.clone();

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

            // Plan 141 — packet-observer pipeline. Short-circuit packets on
            // an already-killed flow, then fan out; `Forward` relays the
            // (possibly rebuilt) frame, `Kill` records the flow + emits a
            // fault and drops (fail-closed).
            let raw = &buf[..n];
            if flow_is_killed(&killed_flows_a, raw).await {
                continue;
            }
            let ctx = PacketCtx {
                vm_name: &vm_name_a,
                tenant: &tenant_a,
                direction: FlowDirection::Egress,
                flow_id: &flow_egress_a,
            };
            match run_packet_pipeline(
                &observers_a,
                substitution_a.as_ref(),
                scan_a.as_ref(),
                ctx,
                raw,
                mtu,
                &latency_a,
            ) {
                PacketDecision::Forward { frame, .. } => {
                    // send (not send_to) — outbound is connected to gvproxy.
                    outbound_a.send(&frame).await?;
                }
                PacketDecision::Kill {
                    observer,
                    reason,
                    flow_key,
                } => {
                    if let Some(k) = flow_key {
                        killed_flows_a.lock().await.insert(k);
                    }
                    let _ = event_a
                        .send(FlowEvent {
                            flow_id: flow_egress_a.clone(),
                            direction: FlowDirection::Egress,
                            kind: FlowEventKind::ObserverFault {
                                observer: observer.to_string(),
                                reason: reason.as_str().to_string(),
                            },
                        })
                        .await;
                }
            }
            latency_a.write_scrape_file();
        }
    };

    let policy_b = policy.clone();
    let event_b = event_tx.clone();
    let inbound_b = inbound.clone();
    let outbound_b = outbound.clone();
    let libkrun_peer_b = libkrun_peer.clone();
    let flow_ingress_b = flow_ingress.clone();
    let observers_b = wiring.observers.clone();
    let latency_b = wiring.latency.clone();
    let killed_flows_b = wiring.killed_flows.clone();
    let substitution_b = wiring.substitution.clone();
    let scan_b = wiring.scan.clone();
    let vm_name_b = vm_name.clone();
    let tenant_b = tenant.clone();

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

            // Plan 141 — packet-observer pipeline (ingress direction).
            let raw = &buf[..n];
            if flow_is_killed(&killed_flows_b, raw).await {
                continue;
            }
            let ctx = PacketCtx {
                vm_name: &vm_name_b,
                tenant: &tenant_b,
                direction: FlowDirection::Ingress,
                flow_id: &flow_ingress_b,
            };
            match run_packet_pipeline(
                &observers_b,
                substitution_b.as_ref(),
                scan_b.as_ref(),
                ctx,
                raw,
                mtu,
                &latency_b,
            ) {
                PacketDecision::Forward { frame, .. } => {
                    // Need libkrun's peer addr to send back. If we haven't
                    // seen a packet from libkrun yet, drop this one.
                    let peer_guard = libkrun_peer_b.lock().await;
                    if let Some(path) = peer_guard.as_ref().and_then(|p| p.as_pathname()) {
                        inbound_b.send_to(&frame, path).await?;
                    }
                }
                PacketDecision::Kill {
                    observer,
                    reason,
                    flow_key,
                } => {
                    if let Some(k) = flow_key {
                        killed_flows_b.lock().await.insert(k);
                    }
                    let _ = event_b
                        .send(FlowEvent {
                            flow_id: flow_ingress_b.clone(),
                            direction: FlowDirection::Ingress,
                            kind: FlowEventKind::ObserverFault {
                                observer: observer.to_string(),
                                reason: reason.as_str().to_string(),
                            },
                        })
                        .await;
                }
            }
            latency_b.write_scrape_file();
        }
    };

    let result = tokio::join!(egress, ingress);
    let _ = result;
    // Cleanup both bound sockets on shutdown.
    let _ = std::fs::remove_file(&supervisor_listen_path);
    let _ = std::fs::remove_file(&outbound_bind_path);
}

/// Bind path for the bridge's gvproxy-facing datagram socket — a sibling
/// of the libkrun-facing listener (`<listen>.gw-out`). Must be a real
/// pathname: gvproxy rejects empty-address peers and macOS never
/// autobinds AF_UNIX datagram sockets.
fn gvproxy_outbound_bind_path(supervisor_listen_path: &std::path::Path) -> PathBuf {
    let mut s = supervisor_listen_path.as_os_str().to_os_string();
    s.push(".gw-out");
    PathBuf::from(s)
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
            // Plan 141 — the Vz NDJSON ingest path (Plan 152 territory) does
            // not produce observer faults; Rust owns the packet pipeline on
            // the in-scope backends. Accept the variant for exhaustiveness
            // and forward it verbatim if a future Swift sender emits it.
            FlowEventWire::FlowObserverFault {
                flow_id,
                direction,
                observer,
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
                FlowEvent {
                    flow_id,
                    direction,
                    kind: FlowEventKind::ObserverFault { observer, reason },
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
    // The live default scan is MandatoryDenyEgressScan; the bridge tests want a
    // pass-through default, so wiring_with keeps NoopScan (test-scoped import).
    use crate::supervisor::network::stages::NoopScan;

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

    #[tokio::test]
    async fn read_write_one_frame_roundtrips_through_duplex() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let frame = tcp_egress_frame(b"payload-bytes");
        write_one_frame(&mut client, &frame).await.unwrap();
        let got = read_one_frame(&mut server).await.unwrap().unwrap();
        assert_eq!(got, frame);
        // Clean EOF at a frame boundary returns None.
        drop(client);
        assert!(read_one_frame(&mut server).await.unwrap().is_none());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn passt_bridge_emits_open_close_pair_on_framed_traffic() {
        use std::os::unix::net::UnixStream as StdUs;

        // pair_a: (gateway_a, gateway_b=passt); pair_b: (guest_a, guest_b=libkrun).
        // The bridge holds gateway_a (a, faces passt) + guest_a (b, faces guest).
        let (gateway_a, gateway_b) = StdUs::pair().unwrap();
        let (guest_a, guest_b) = StdUs::pair().unwrap();
        for s in [&gateway_a, &gateway_b, &guest_a, &guest_b] {
            s.set_nonblocking(true).unwrap();
        }
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
            "t".to_string(),
            policy,
            tx,
            wiring_with(vec![]),
        ));

        // passt → guest = ingress. Frame must round-trip byte-identically.
        let f1 = tcp_egress_frame(b"from-passt");
        write_one_frame(&mut passt, &f1).await.unwrap();
        let got = read_one_frame(&mut libkrun).await.unwrap().unwrap();
        assert_eq!(got, f1);
        let ev1 = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .expect("open in time")
            .expect("event");
        assert!(matches!(ev1.kind, FlowEventKind::Opened));
        assert_eq!(ev1.direction, FlowDirection::Ingress);

        // guest → passt = egress.
        let f2 = tcp_egress_frame(b"from-guest");
        write_one_frame(&mut libkrun, &f2).await.unwrap();
        let got = read_one_frame(&mut passt).await.unwrap().unwrap();
        assert_eq!(got, f2);
        let ev2 = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .expect("second open in time")
            .expect("event");
        assert!(matches!(ev2.kind, FlowEventKind::Opened));
        assert_ne!(ev1.direction, ev2.direction);

        drop(passt);
        drop(libkrun);
        let c1 = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .expect("close")
            .expect("event");
        let c2 = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .expect("second close")
            .expect("event");
        assert!(matches!(c1.kind, FlowEventKind::Closed { .. }));
        assert!(matches!(c2.kind, FlowEventKind::Closed { .. }));
        let _ = bridge_task.await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn passt_bridge_redacts_egress_frame() {
        use std::os::unix::net::UnixStream as StdUs;

        let (gateway_a, gateway_b) = StdUs::pair().unwrap();
        let (guest_a, guest_b) = StdUs::pair().unwrap();
        for s in [&gateway_a, &gateway_b, &guest_a, &guest_b] {
            s.set_nonblocking(true).unwrap();
        }
        let supervisor_gateway = tokio::net::UnixStream::from_std(gateway_a).unwrap();
        let supervisor_guest = tokio::net::UnixStream::from_std(guest_a).unwrap();
        let mut passt = tokio::net::UnixStream::from_std(gateway_b).unwrap();
        let mut libkrun = tokio::net::UnixStream::from_std(guest_b).unwrap();

        let (tx, _rx) = mpsc::channel::<FlowEvent>(64);
        let policy: Arc<dyn FlowPolicy> = Arc::new(AllowAll);
        let bridge_task = tokio::spawn(bridge_copy_bidirectional(
            supervisor_gateway,
            supervisor_guest,
            "vm-test".to_string(),
            "t".to_string(),
            policy,
            tx,
            wiring_with(vec![Arc::new(RedactorObs)]),
        ));

        // guest → internet = egress; RedactorObs redacts SECRET on this path.
        write_one_frame(&mut libkrun, &tcp_egress_frame(b"hello-SECRET-bye"))
            .await
            .unwrap();
        let out = read_one_frame(&mut passt).await.unwrap().unwrap();
        let parsed = crate::supervisor::network::packet::parse(&out).expect("re-parses");
        assert!(parsed.l4_payload.windows(6).any(|w| w == b"XXXXXX"));
        assert!(!parsed.l4_payload.windows(6).any(|w| w == b"SECRET"));
        bridge_task.abort();
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
        use crate::supervisor::audit::CapturingAuditSigner;
        use crate::supervisor::network::{Observer, RequiredCapabilities};
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
                    signer.clone() as Arc<dyn crate::supervisor::audit::AuditSigner>,
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

    #[test]
    fn flow_event_observer_fault_wire_roundtrips() {
        let ev = FlowEvent {
            flow_id: "vm-egress".to_string(),
            direction: FlowDirection::Egress,
            kind: FlowEventKind::ObserverFault {
                observer: "test-redactor".to_string(),
                reason: "modify_over_mtu".to_string(),
            },
        };
        let wire = FlowEventWire::from(&ev);
        let json = serde_json::to_string(&wire).unwrap();
        assert!(json.contains("\"kind\":\"flow_observer_fault\""));
        assert!(json.contains("\"observer\":\"test-redactor\""));
        assert!(json.contains("\"reason\":\"modify_over_mtu\""));
        let parsed: FlowEventWire = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, wire);
    }

    // -----------------------------------------------------------------
    // Plan 141 — gvproxy packet-observer pipeline wiring
    // -----------------------------------------------------------------

    use crate::supervisor::network::latency::ObserverLatency;
    use crate::supervisor::network::packet::ParsedPacket;
    use crate::supervisor::network::{
        Directions, Observer, PacketCtx, RequiredCapabilities, Verdict,
    };

    fn payload_tap_caps() -> RequiredCapabilities {
        RequiredCapabilities {
            flow_events: true,
            payload_tap: true,
        }
    }

    /// Egress observer that redacts "SECRET" → "XXXXXX" (same length).
    struct RedactorObs;
    impl Observer for RedactorObs {
        fn name(&self) -> &'static str {
            "test-redactor"
        }
        fn required_capabilities(&self) -> RequiredCapabilities {
            payload_tap_caps()
        }
        fn on_flow_event(&self, _: &FlowEvent) {}
        fn directions(&self) -> Directions {
            Directions::Egress
        }
        fn on_packet(&self, _c: &PacketCtx<'_>, p: &ParsedPacket<'_>) -> Verdict {
            let s = String::from_utf8_lossy(p.l4_payload).replace("SECRET", "XXXXXX");
            Verdict::Modify(s.into_bytes())
        }
    }

    /// Egress observer that drops everything.
    struct DropObs;
    impl Observer for DropObs {
        fn name(&self) -> &'static str {
            "test-drop"
        }
        fn required_capabilities(&self) -> RequiredCapabilities {
            payload_tap_caps()
        }
        fn on_flow_event(&self, _: &FlowEvent) {}
        fn directions(&self) -> Directions {
            Directions::Egress
        }
        fn on_packet(&self, _c: &PacketCtx<'_>, _p: &ParsedPacket<'_>) -> Verdict {
            Verdict::Drop
        }
    }

    fn tcp_egress_frame(payload: &[u8]) -> Vec<u8> {
        use etherparse::PacketBuilder;
        let b = PacketBuilder::ethernet2([1; 6], [2; 6])
            .ipv4([10, 0, 0, 2], [93, 184, 216, 34], 64)
            .tcp(40000, 443, 1, 64000);
        let mut o = Vec::new();
        b.write(&mut o, payload).unwrap();
        o
    }

    fn wiring_with(observers: Vec<Arc<dyn Observer>>) -> ObserverWiring {
        ObserverWiring {
            observers,
            latency: Arc::new(ObserverLatency::new("vm-test", "t")),
            killed_flows: Arc::new(tokio::sync::Mutex::new(HashSet::new())),
            mtu: BRIDGE_MTU,
            substitution: Arc::new(NoopSubstitution),
            scan: Arc::new(NoopScan),
        }
    }

    #[test]
    fn observer_wiring_defaults_to_noop_stages() {
        // A3.3: the bridge wiring carries the egress stages; the default is
        // no-op, so Plan 129 opts in by setting them — never the reverse.
        let w = wiring_with(vec![]);
        assert_eq!(w.substitution.name(), "noop-substitution");
        assert_eq!(w.scan.name(), "noop-scan");
    }

    /// Connect a libkrun-side datagram socket to the bridge's listener,
    /// retrying until the bridge has bound it.
    async fn connect_libkrun(path: &std::path::Path) -> tokio::net::UnixDatagram {
        let sock = tokio::net::UnixDatagram::unbound().unwrap();
        for _ in 0..100 {
            if sock.connect(path).is_ok() {
                return sock;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("bridge never bound {}", path.display());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn gvproxy_pipeline_forwards_modified_frame() {
        let dir = tempfile::tempdir().unwrap();
        let gvproxy_path = dir.path().join("gvproxy.sock");
        let sup_listen = dir.path().join("sup.sock");
        let gvproxy = tokio::net::UnixDatagram::bind(&gvproxy_path).unwrap();

        let (tx, _rx) = mpsc::channel::<FlowEvent>(64);
        let policy: Arc<dyn FlowPolicy> = Arc::new(AllowAll);
        let bridge = tokio::spawn(run_libkrun_gvproxy_bridge(
            gvproxy_path.clone(),
            sup_listen.clone(),
            "vm-test".to_string(),
            "t".to_string(),
            policy,
            tx,
            wiring_with(vec![Arc::new(RedactorObs)]),
        ));

        let libkrun = connect_libkrun(&sup_listen).await;
        libkrun
            .send(&tcp_egress_frame(b"hello-SECRET-bye"))
            .await
            .unwrap();

        let mut buf = vec![0u8; 65536];
        let n = tokio::time::timeout(std::time::Duration::from_secs(3), gvproxy.recv(&mut buf))
            .await
            .expect("gvproxy must receive the forwarded frame in time")
            .expect("recv ok");
        let parsed = crate::supervisor::network::packet::parse(&buf[..n])
            .expect("forwarded frame re-parses");
        assert!(
            parsed.l4_payload.windows(6).any(|w| w == b"XXXXXX"),
            "gvproxy must see the redacted payload"
        );
        assert!(
            !parsed.l4_payload.windows(6).any(|w| w == b"SECRET"),
            "the secret must not reach gvproxy"
        );
        bridge.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn gvproxy_pipeline_drop_kills_flow_and_emits_fault() {
        let dir = tempfile::tempdir().unwrap();
        let gvproxy_path = dir.path().join("gvproxy.sock");
        let sup_listen = dir.path().join("sup.sock");
        let gvproxy = tokio::net::UnixDatagram::bind(&gvproxy_path).unwrap();

        let (tx, mut rx) = mpsc::channel::<FlowEvent>(64);
        let policy: Arc<dyn FlowPolicy> = Arc::new(AllowAll);
        let bridge = tokio::spawn(run_libkrun_gvproxy_bridge(
            gvproxy_path.clone(),
            sup_listen.clone(),
            "vm-test".to_string(),
            "t".to_string(),
            policy,
            tx,
            wiring_with(vec![Arc::new(DropObs)]),
        ));

        let libkrun = connect_libkrun(&sup_listen).await;
        libkrun.send(&tcp_egress_frame(b"anything")).await.unwrap();

        // The dropped packet must NOT reach gvproxy.
        let mut buf = vec![0u8; 65536];
        let got = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            gvproxy.recv(&mut buf),
        )
        .await;
        assert!(got.is_err(), "dropped packet must not reach gvproxy");

        // A FlowOpened then an ObserverFault must arrive on the event stream.
        let mut saw_fault = false;
        for _ in 0..4 {
            match tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv()).await {
                Ok(Some(ev)) => {
                    if let FlowEventKind::ObserverFault { observer, reason } = ev.kind {
                        assert_eq!(observer, "test-drop");
                        assert_eq!(reason, "drop");
                        saw_fault = true;
                        break;
                    }
                }
                _ => break,
            }
        }
        assert!(saw_fault, "an ObserverFault event must be emitted on drop");
        bridge.abort();
    }

    // -----------------------------------------------------------------
    // Plan 141 follow-up — live DHCP handshake through a REAL gateway
    // (gvproxy / rvproxy). Opt-in (MVM_GATEWAY_DHCP_E2E=1); skips when
    // unset or when the gateway binary is absent. Validates the macOS
    // gvproxy datagram arm end-to-end against a real userspace gateway:
    // no microVM, no KVM. Doubles as an rvproxy drop-in conformance check
    // (point MVM_GATEWAY_BIN at it once it speaks the gvproxy `-listen-vfkit`
    // CLI + vfkit/DHCP contract — see rvproxy's GVPROXY_CONFORMANCE.md).
    // -----------------------------------------------------------------

    fn free_tcp_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    /// A minimal BOOTP/DHCP DISCOVER wrapped in UDP/IPv4/Ethernet. `src`
    /// MAC is the pretend-guest; destination is L2 broadcast, IP
    /// 0.0.0.0 → 255.255.255.255, UDP 68 → 67. Option 53 = 1 (DISCOVER).
    fn build_dhcp_discover(mac: [u8; 6]) -> Vec<u8> {
        // op = BOOTREQUEST, htype = Ethernet, hlen = 6, hops = 0.
        let mut dhcp = vec![1u8, 1, 6, 0];
        dhcp.extend_from_slice(&0x1234_5678u32.to_be_bytes()); // xid
        dhcp.extend_from_slice(&0u16.to_be_bytes()); // secs
        dhcp.extend_from_slice(&0u16.to_be_bytes()); // flags (unicast)
        dhcp.extend_from_slice(&[0u8; 4]); // ciaddr
        dhcp.extend_from_slice(&[0u8; 4]); // yiaddr
        dhcp.extend_from_slice(&[0u8; 4]); // siaddr
        dhcp.extend_from_slice(&[0u8; 4]); // giaddr
        let mut chaddr = [0u8; 16];
        chaddr[..6].copy_from_slice(&mac);
        dhcp.extend_from_slice(&chaddr); // chaddr (16)
        dhcp.extend_from_slice(&[0u8; 64]); // sname
        dhcp.extend_from_slice(&[0u8; 128]); // file
        dhcp.extend_from_slice(&[0x63, 0x82, 0x53, 0x63]); // DHCP magic cookie
        dhcp.extend_from_slice(&[53, 1, 1]); // option 53 = DISCOVER
        dhcp.push(255); // end
        while dhcp.len() < 300 {
            dhcp.push(0); // pad to a conventional minimum BOOTP size
        }
        let builder = etherparse::PacketBuilder::ethernet2(mac, [0xff; 6])
            .ipv4([0, 0, 0, 0], [255, 255, 255, 255], 64)
            .udp(68, 67);
        let mut out = Vec::with_capacity(builder.size(dhcp.len()));
        builder.write(&mut out, &dhcp).unwrap();
        out
    }

    /// Extract the DHCP message-type (option 53) from an ethernet frame,
    /// or `None` if it isn't a well-formed DHCP packet. 2 = OFFER.
    fn dhcp_msg_type(frame: &[u8]) -> Option<u8> {
        let sliced = etherparse::SlicedPacket::from_ethernet(frame).ok()?;
        let payload = match sliced.transport? {
            etherparse::TransportSlice::Udp(u) => u.payload(),
            _ => return None,
        };
        if payload.len() < 240 || payload[236..240] != [0x63, 0x82, 0x53, 0x63] {
            return None;
        }
        let mut i = 240;
        while i < payload.len() {
            match payload[i] {
                255 => break, // end
                0 => i += 1,  // pad
                code => {
                    let len = *payload.get(i + 1)? as usize;
                    if code == 53 && len >= 1 {
                        return payload.get(i + 2).copied();
                    }
                    i += 2 + len;
                }
            }
        }
        None
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn gvproxy_dhcp_offer_roundtrips_through_bridge() {
        if std::env::var("MVM_GATEWAY_DHCP_E2E").is_err() {
            eprintln!("skip: set MVM_GATEWAY_DHCP_E2E=1 to run the live gateway DHCP test");
            return;
        }
        let gw_bin = std::env::var("MVM_GATEWAY_BIN").unwrap_or_else(|_| "gvproxy".to_string());
        let tmp = tempfile::tempdir().unwrap();
        let gw_sock = tmp.path().join("gw.sock");
        let gw_log = tmp.path().join("gw.log");
        let stdio = std::fs::File::create(tmp.path().join("gw-stdio.log")).unwrap();

        // Real gateway: `-listen-vfkit unixgram://<sock>` is the contract
        // (gvproxy's, and what rvproxy must match). `-ssh-port` is
        // gvproxy-specific (it always binds an SSH-forward listener); only
        // pass it for gvproxy so other gateways aren't tripped by an
        // unknown flag.
        let mut cmd = std::process::Command::new(&gw_bin);
        cmd.arg("-listen-vfkit")
            .arg(format!("unixgram://{}", gw_sock.display()))
            .arg("-log-file")
            .arg(&gw_log)
            .stdout(stdio.try_clone().unwrap())
            .stderr(stdio);
        let is_gvproxy = std::path::Path::new(&gw_bin)
            .file_name()
            .is_none_or(|n| n == "gvproxy");
        if is_gvproxy {
            cmd.arg("-ssh-port").arg(free_tcp_port().to_string());
        }
        let mut gateway = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                eprintln!("skip: cannot spawn gateway {gw_bin:?}: {e}");
                return;
            }
        };

        // Wait for the gateway to create its listener socket.
        let mut ready = false;
        for _ in 0..100 {
            if gw_sock.exists() {
                ready = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        if !ready {
            let _ = gateway.kill();
            let log = std::fs::read_to_string(tmp.path().join("gw-stdio.log")).unwrap_or_default();
            panic!(
                "gateway {gw_bin:?} never created {} (stdio: {log})",
                gw_sock.display()
            );
        }

        // Bridge: gvproxy-facing = the gateway's socket; libkrun-facing =
        // a listener the harness connects to.
        let sup_listen = tmp.path().join("sup.sock");
        let (tx, mut rx) = mpsc::channel::<FlowEvent>(64);
        let policy: Arc<dyn FlowPolicy> = Arc::new(AllowAll);
        let bridge = tokio::spawn(run_libkrun_gvproxy_bridge(
            gw_sock.clone(),
            sup_listen.clone(),
            "vm-dhcp".to_string(),
            "t".to_string(),
            policy,
            tx,
            wiring_with(vec![]),
        ));

        // Harness plays the VMM (vfkit/libkrun). It MUST be bound to a
        // pathname so the gateway can address its DHCP reply back.
        let harness_path = tmp.path().join("harness.sock");
        let harness = tokio::net::UnixDatagram::bind(&harness_path).unwrap();
        let mut connected = false;
        for _ in 0..100 {
            if harness.connect(&sup_listen).is_ok() {
                connected = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert!(connected, "bridge never bound {}", sup_listen.display());

        // vfkit announces itself with a 4-byte "VFKT" handshake datagram,
        // then sends ethernet frames. (Bridge forwards both verbatim.)
        let mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x42];
        harness.send(b"VFKT").await.unwrap();
        harness.send(&build_dhcp_discover(mac)).await.unwrap();

        // Read until we see a DHCP OFFER or time out. The gateway may emit
        // other frames (ARP, etc.) first.
        let mut buf = vec![0u8; 65536];
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(8);
        let mut got_offer = false;
        while tokio::time::Instant::now() < deadline {
            match tokio::time::timeout(
                std::time::Duration::from_millis(500),
                harness.recv(&mut buf),
            )
            .await
            {
                Ok(Ok(n)) if dhcp_msg_type(&buf[..n]) == Some(2) => {
                    got_offer = true;
                    break;
                }
                _ => {}
            }
        }

        // A FlowOpened must have been emitted (observer pipeline fired on
        // the real-gateway path).
        let mut saw_open = false;
        while let Ok(ev) = rx.try_recv() {
            if matches!(ev.kind, FlowEventKind::Opened) {
                saw_open = true;
            }
        }

        let _ = gateway.kill();
        let _ = gateway.wait();
        bridge.abort();

        let log = std::fs::read_to_string(tmp.path().join("gw-stdio.log")).unwrap_or_default();
        assert!(
            got_offer,
            "no DHCP OFFER returned through the bridge from {gw_bin:?} (gateway stdio: {log})"
        );
        assert!(saw_open, "bridge must emit a FlowOpened for the exchange");
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
                entrypoint_present: true,
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
            shares: Vec::new(),
        }
    }
}
