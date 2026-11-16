//! Host-initiated ingress flows carried by one authenticated FlowMux session.

use std::collections::BTreeMap;
use std::net::TcpStream;
use std::os::unix::net::UnixStream;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

use mvm_contract::protocol::network_flow::{Direction, Opcode, SessionValidator};
use mvm_core::{audit_sink::AuditSink, net::session::Session};

use super::decision_audit::{self, UdpDenials};
use super::registry::{self, StreamRegistry};
use super::socket::FlowSocket;
use super::tcp_relay::{TcpRelayParams, run_tcp_relay};
use super::udp_relay::{
    UdpAssociationHandle, UdpPeerAdmission, UdpRelayParams, run_udp_relay, udp_event_sources,
};
use super::wire::{lock_registry, lock_validator, write_frame_to};
use super::{FlowMuxError, TcpStreamHandle};

pub(super) type IngressOpenResult = Result<(), String>;
pub(super) type IngressOpenWaiters = BTreeMap<u32, std::sync::mpsc::SyncSender<IngressOpenResult>>;
pub(super) type SharedIngressOpenWaiters = Arc<Mutex<IngressOpenWaiters>>;
pub(super) type SharedUdpAssociations = Arc<Mutex<BTreeMap<u32, UdpAssociationHandle>>>;

/// Cloneable host-initiated ingress side of one authenticated session.
#[derive(Clone)]
pub struct FlowMuxIngressHandle {
    pub(super) session: Arc<Mutex<Session>>,
    pub(super) writer: Arc<Mutex<UnixStream>>,
    pub(super) validator: Arc<Mutex<SessionValidator>>,
    pub(super) registry: Arc<Mutex<StreamRegistry>>,
    pub(super) streams: Arc<Mutex<BTreeMap<u32, TcpStreamHandle>>>,
    pub(super) pending: SharedIngressOpenWaiters,
    pub(super) activity: Arc<Mutex<()>>,
    pub(super) session_closed: Arc<AtomicBool>,
    pub(super) credit_wait: Duration,
    pub(super) audit_sink: Arc<dyn AuditSink>,
    pub(super) udp_associations: SharedUdpAssociations,
    pub(super) udp_idle_timeout: Duration,
    pub(super) max_udp_peers: usize,
}

impl FlowMuxIngressHandle {
    /// Open one accepted opaque TCP connection on an admitted mapping.
    pub fn open_tcp(&self, mapping_id: u16, external: TcpStream) -> Result<(), FlowMuxError> {
        let _activity = self.activity.lock().expect("ingress owner poisoned");
        self.require_live_session()?;
        let result = self.open_tcp_inner(mapping_id, external);
        if result.is_err() && !matches!(result, Err(FlowMuxError::Audit(_))) {
            self.audit_ingress_denial(mapping_id, "tcp_ingress");
        }
        result
    }

    fn open_tcp_inner(&self, mapping_id: u16, external: TcpStream) -> Result<(), FlowMuxError> {
        let stream_id = lock_registry(&self.registry)
            .alloc_host(registry::FlowClass::Tcp)
            .map_err(|error| FlowMuxError::FrameRefused(error.to_string()))?;
        let tracked = match external.try_clone() {
            Ok(stream) => stream,
            Err(error) => {
                let _ = lock_registry(&self.registry).retire(stream_id);
                return Err(FlowMuxError::Transport(error));
            }
        };
        lock_tcp_streams(&self.streams).insert(
            stream_id,
            TcpStreamHandle {
                upstream: FlowSocket::from(tracked),
                host_half_closed: Arc::new(AtomicBool::new(false)),
                retired: Arc::new(AtomicBool::new(false)),
            },
        );
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        lock_pending_ingress(&self.pending).insert(stream_id, sender);

        let payload = mapping_id.to_be_bytes();
        if let Err(error) = lock_validator(&self.validator).admit(
            &mvm_contract::protocol::network_flow::FrameFacts::new(
                Direction::HostToGuest,
                Opcode::InboundOpen,
                stream_id,
            )
            .with_payload(payload.len() as u32)
            .with_ingress_mapping(mapping_id),
        ) {
            lock_pending_ingress(&self.pending).remove(&stream_id);
            if let Some(handle) = lock_tcp_streams(&self.streams).remove(&stream_id) {
                let _ = handle.upstream.shutdown(std::net::Shutdown::Both);
            }
            let _ = lock_registry(&self.registry).retire(stream_id);
            return Err(FlowMuxError::FrameRefused(error.to_string()));
        }
        if let Err(error) = self
            .audit_ingress(mapping_id, "tcp_ingress", true)
            .and_then(|()| {
                write_frame_to(
                    &self.session,
                    &self.writer,
                    Opcode::InboundOpen,
                    stream_id,
                    &payload,
                )
            })
        {
            lock_pending_ingress(&self.pending).remove(&stream_id);
            if let Some(handle) = lock_tcp_streams(&self.streams).remove(&stream_id) {
                let _ = handle.upstream.shutdown(std::net::Shutdown::Both);
            }
            self.retire_unopened(stream_id);
            return Err(error);
        }

        match receiver.recv_timeout(Duration::from_secs(5)) {
            Ok(Ok(())) => self.spawn_tcp_relay(stream_id, FlowSocket::from(external)),
            Ok(Err(reason)) => {
                if let Some(handle) = lock_tcp_streams(&self.streams).remove(&stream_id) {
                    let _ = handle.upstream.shutdown(std::net::Shutdown::Both);
                }
                Err(FlowMuxError::FrameRefused(format!(
                    "guest refused ingress mapping {mapping_id}: {reason}"
                )))
            }
            Err(error) => {
                lock_pending_ingress(&self.pending).remove(&stream_id);
                if let Some(handle) = lock_tcp_streams(&self.streams).remove(&stream_id) {
                    let _ = handle.upstream.shutdown(std::net::Shutdown::Both);
                }
                let _ = lock_registry(&self.registry).retire(stream_id);
                Err(FlowMuxError::FrameRefused(format!(
                    "guest ingress response timed out: {error}"
                )))
            }
        }
    }

    /// Start one admitted UDP listener mapping for this authenticated session.
    pub fn open_udp(
        &self,
        mapping_id: u16,
        socket: std::net::UdpSocket,
    ) -> Result<(), FlowMuxError> {
        let _activity = self.activity.lock().expect("ingress owner poisoned");
        self.require_live_session()?;
        let result = self.open_udp_inner(mapping_id, socket);
        if result.is_err() && !matches!(result, Err(FlowMuxError::Audit(_))) {
            self.audit_ingress_denial(mapping_id, "udp_ingress");
        }
        result
    }

    fn open_udp_inner(
        &self,
        mapping_id: u16,
        socket: std::net::UdpSocket,
    ) -> Result<(), FlowMuxError> {
        super::udp_relay::reap_associations(&self.udp_associations, &self.registry);
        let stream_id = lock_registry(&self.registry)
            .alloc_host(registry::FlowClass::Udp)
            .map_err(|error| FlowMuxError::FrameRefused(error.to_string()))?;
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        lock_pending_ingress(&self.pending).insert(stream_id, sender);
        let payload = mapping_id.to_be_bytes();
        if let Err(error) = lock_validator(&self.validator).admit(
            &mvm_contract::protocol::network_flow::FrameFacts::new(
                Direction::HostToGuest,
                Opcode::InboundOpen,
                stream_id,
            )
            .with_payload(payload.len() as u32)
            .with_ingress_mapping(mapping_id),
        ) {
            lock_pending_ingress(&self.pending).remove(&stream_id);
            let _ = lock_registry(&self.registry).retire(stream_id);
            return Err(FlowMuxError::FrameRefused(error.to_string()));
        }
        if let Err(error) = self
            .audit_ingress(mapping_id, "udp_ingress", true)
            .and_then(|()| {
                write_frame_to(
                    &self.session,
                    &self.writer,
                    Opcode::InboundOpen,
                    stream_id,
                    &payload,
                )
            })
        {
            lock_pending_ingress(&self.pending).remove(&stream_id);
            self.retire_unopened(stream_id);
            return Err(error);
        }
        match receiver.recv_timeout(Duration::from_secs(5)) {
            Ok(Ok(())) => {}
            Ok(Err(reason)) => {
                return Err(FlowMuxError::FrameRefused(format!(
                    "guest refused UDP ingress mapping {mapping_id}: {reason}"
                )));
            }
            Err(error) => {
                lock_pending_ingress(&self.pending).remove(&stream_id);
                let _ = lock_registry(&self.registry).retire(stream_id);
                return Err(FlowMuxError::FrameRefused(format!(
                    "guest UDP ingress response timed out: {error}"
                )));
            }
        }

        let (poll, waker) = match udp_event_sources(&socket) {
            Ok(sources) => sources,
            Err(error) => {
                self.abort_udp_ingress(mapping_id, stream_id, b"UDP relay setup failed");
                return Err(FlowMuxError::Transport(error));
            }
        };
        let (tx, rx) = std::sync::mpsc::channel();
        let audited_denials = Arc::new(UdpDenials::default());
        let association = UdpAssociationHandle::new(
            tx,
            Arc::clone(&waker),
            UdpPeerAdmission::ObservedOnly,
            Arc::clone(&audited_denials),
        );
        let cancelled = Arc::clone(&association.cancelled);
        {
            let mut associations = lock_udp_associations(&self.udp_associations);
            if lock_registry(&self.registry).get(stream_id).is_none() {
                return Err(FlowMuxError::FrameRefused(
                    "UDP ingress closed before relay start".into(),
                ));
            }
            associations.insert(stream_id, association);
        }
        let session = Arc::clone(&self.session);
        let writer = Arc::clone(&self.writer);
        let registry = Arc::clone(&self.registry);
        let idle_timeout = self.udp_idle_timeout;
        let max_peers = self.max_udp_peers;
        let audit_sink = Arc::clone(&self.audit_sink);
        let relay = std::thread::Builder::new()
            .name(format!("flowmux-ingress-udp-{stream_id}"))
            .spawn(move || {
                run_udp_relay(UdpRelayParams {
                    stream_id,
                    socket,
                    poll,
                    session,
                    writer,
                    idle_timeout,
                    max_peers,
                    peer_admission: UdpPeerAdmission::ObservedOnly,
                    rx,
                    registry,
                    audit_sink,
                    audited_denials,
                    cancelled,
                });
            });
        match relay {
            Ok(relay) => {
                if let Some(association) =
                    lock_udp_associations(&self.udp_associations).get_mut(&stream_id)
                {
                    association.relay = Some(relay);
                } else {
                    let _ = waker.wake();
                    if relay.join().is_err() {
                        tracing::warn!(stream_id, "UDP ingress relay panicked during cleanup");
                    }
                }
            }
            Err(error) => {
                lock_udp_associations(&self.udp_associations).remove(&stream_id);
                self.abort_udp_ingress(mapping_id, stream_id, b"UDP relay unavailable");
                return Err(FlowMuxError::Transport(error));
            }
        }
        Ok(())
    }

    fn abort_udp_ingress(&self, mapping_id: u16, stream_id: u32, reason: &[u8]) {
        self.audit_ingress_denial(mapping_id, "udp_ingress");
        lock_pending_ingress(&self.pending).remove(&stream_id);
        lock_udp_associations(&self.udp_associations).remove(&stream_id);
        if lock_validator(&self.validator)
            .admit(
                &mvm_contract::protocol::network_flow::FrameFacts::new(
                    Direction::HostToGuest,
                    Opcode::Reset,
                    stream_id,
                )
                .with_payload(u32::try_from(reason.len()).unwrap_or(u32::MAX)),
            )
            .is_ok()
        {
            let _ = write_frame_to(
                &self.session,
                &self.writer,
                Opcode::Reset,
                stream_id,
                reason,
            );
        }
        let _ = lock_registry(&self.registry).retire(stream_id);
    }

    fn require_live_session(&self) -> Result<(), FlowMuxError> {
        if self.session_closed.load(Ordering::Acquire) {
            return Err(FlowMuxError::FrameRefused("session closed".into()));
        }
        Ok(())
    }

    fn retire_unopened(&self, stream_id: u32) {
        let _ = lock_validator(&self.validator).admit(
            &mvm_contract::protocol::network_flow::FrameFacts::new(
                Direction::HostToGuest,
                Opcode::Reset,
                stream_id,
            ),
        );
        let _ = lock_registry(&self.registry).retire(stream_id);
    }

    fn audit_ingress(
        &self,
        mapping_id: u16,
        class: &str,
        allowed: bool,
    ) -> Result<(), FlowMuxError> {
        let (event, verdict) = if allowed {
            ("host.ingress.allowed", "allowed")
        } else {
            ("host.ingress.denied", "denied")
        };
        decision_audit::record(
            self.audit_sink.as_ref(),
            event,
            BTreeMap::from([
                ("mapping_id".into(), mapping_id.to_string()),
                ("class".into(), class.into()),
                ("verdict".into(), verdict.into()),
            ]),
        )
        .map_err(FlowMuxError::Audit)
    }

    fn audit_ingress_denial(&self, mapping_id: u16, class: &str) {
        if self.audit_ingress(mapping_id, class, false).is_err() {
            tracing::debug!("FlowMux ingress remains refused after audit failure");
        }
    }

    pub(super) fn spawn_tcp_relay(
        &self,
        stream_id: u32,
        upstream: FlowSocket,
    ) -> Result<(), FlowMuxError> {
        let upstream_read = upstream.try_clone()?;
        let host_half_closed = Arc::new(AtomicBool::new(false));
        let relay_flag = Arc::clone(&host_half_closed);
        let retired = Arc::new(AtomicBool::new(false));
        let retired_flag = Arc::clone(&retired);
        let session = Arc::clone(&self.session);
        let writer = Arc::clone(&self.writer);
        let registry = Arc::clone(&self.registry);
        let validator = Arc::clone(&self.validator);
        let credit_wait = self.credit_wait;

        std::thread::Builder::new()
            .name(format!("flowmux-ingress-tcp-{stream_id}"))
            .spawn(move || {
                run_tcp_relay(TcpRelayParams {
                    stream_id,
                    upstream: upstream_read,
                    session,
                    writer,
                    registry,
                    validator,
                    host_half_closed: relay_flag,
                    retired: retired_flag,
                    credit_wait,
                })
            })
            .map_err(FlowMuxError::Transport)?;

        lock_tcp_streams(&self.streams).insert(
            stream_id,
            TcpStreamHandle {
                upstream,
                host_half_closed,
                retired,
            },
        );
        Ok(())
    }
}

pub(super) fn lock_tcp_streams(
    streams: &Mutex<BTreeMap<u32, TcpStreamHandle>>,
) -> std::sync::MutexGuard<'_, BTreeMap<u32, TcpStreamHandle>> {
    streams.lock().unwrap_or_else(|error| error.into_inner())
}

pub(super) fn lock_pending_ingress(
    pending: &Mutex<IngressOpenWaiters>,
) -> std::sync::MutexGuard<'_, IngressOpenWaiters> {
    pending.lock().unwrap_or_else(|error| error.into_inner())
}

pub(super) fn lock_udp_associations(
    associations: &Mutex<BTreeMap<u32, UdpAssociationHandle>>,
) -> std::sync::MutexGuard<'_, BTreeMap<u32, UdpAssociationHandle>> {
    associations
        .lock()
        .unwrap_or_else(|error| error.into_inner())
}
