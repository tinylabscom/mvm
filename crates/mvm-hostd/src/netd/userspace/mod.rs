//! The userspace socket datapath.
//!
//! Terminates guest TCP/UDP inside a smoltcp stack driven by
//! [`device::GuestDevice`], then re-originates each admitted flow on a host
//! socket. No `utun`, no routes, no PF anchor, and no privilege of any kind
//! — the whole point of this backend is that it needs none.
//!
//! Per-flow cost here is a file descriptor, not a flow-table entry, so its
//! socket cap comes from [`socket_budget`], derived from the process's own
//! `RLIMIT_NOFILE`, rather than from `mvm_net::l3::flow::DEFAULT_MAX_FLOWS`.
//! See `limits` for why a guest's admitted allowance and this process's
//! descriptor budget are different numbers.

pub mod device;
pub mod ingress;
pub mod limits;
pub mod readiness;
pub mod tcp;
pub mod udp;

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::RawFd;

use mvm_contract::l3::ip::{self, ParsedIpPacket, proto};
use mvm_contract::l3::limits::MTU_V1;
use mvm_net::l3::AdmittedPacket;
use mvm_net::l3::admit::DenyCode;
use mvm_net::l3::config::DEFAULT_QUEUE_DEPTH;
use mvm_net::l3::flow::FlowKey;
use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr};

use self::device::{GuestDevice, PushOutcome, QueueDepths};
use self::ingress::{DatagramIngress, IngressBounds, ReplyOutcome};
use self::limits::{
    DEFAULT_MAX_HALF_OPEN, DEFAULT_MAX_HOST_SOCKETS, DEFAULT_MAX_UDP_ASSOCIATIONS,
    DEFAULT_MAX_UDP_INGRESS_LISTENERS, FD_RESERVE, PEERS_PER_INGRESS_LISTENER,
};
use self::readiness::ReadinessSet;
use self::tcp::{EstablishedFlow, HalfOpenTable, SynOutcome};
use self::udp::UdpAssociations;
use super::datapath::{
    DatapathError, DatapathHandle, DatapathRequest, ForwardingCapabilities, InboundDrain,
    L3Datapath,
};
use super::metrics::GatewayMetrics;

/// The addresses this session leased the guest, one per family.
///
/// A host-originated packet — a reset, a synthesized datagram — is addressed
/// from this and never from the source field of whatever the guest last
/// sent. Carrying both families in one value rather than one address per
/// table is what lets a v6 flow's reply be addressed at all: the reply's
/// family is the flow's, not the session's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuestAddressing {
    v4: Ipv4Addr,
    /// `None` when the session was issued no IPv6 address. Admission
    /// refuses the family in that case, so nothing should reach here asking
    /// for one — and if something does, it is counted as unaddressable
    /// rather than sent somewhere invented.
    v6: Option<Ipv6Addr>,
}

impl GuestAddressing {
    pub fn new(v4: Ipv4Addr, v6: Option<Ipv6Addr>) -> Self {
        Self { v4, v6 }
    }

    /// The leased address in `remote`'s family.
    pub fn matching(&self, remote: IpAddr) -> Option<IpAddr> {
        match remote {
            IpAddr::V4(_) => Some(IpAddr::V4(self.v4)),
            IpAddr::V6(_) => self.v6.map(IpAddr::V6),
        }
    }
}

/// Concurrent host sockets this process can afford.
///
/// The soft limit is raised toward the hard limit first, which an
/// unprivileged process is permitted to do, then a fixed reserve is held
/// back for the process's own descriptors.
pub fn socket_budget(rlimit_soft: u64, rlimit_hard: u64) -> usize {
    let usable = rlimit_soft.max(rlimit_hard) as usize;
    usable
        .saturating_sub(FD_RESERVE)
        .min(DEFAULT_MAX_HOST_SOCKETS)
}

/// Reject a packet before it reaches [`GuestDevice`], which bounds queue
/// *count* but not per-packet *size* and would queue an oversized slice
/// as-is.
///
/// Factored out of [`UserspaceHandle::send_to_network`] rather than inlined
/// there: that method only ever receives an `AdmittedPacket`, and that type
/// is constructible solely by `mvm_net::l3`'s admitter, so a unit test in
/// this crate has no way to build one to drive the check through the trait
/// method. Testing this function directly exercises the real guard; a test
/// that could not construct its own input would not.
fn accept_packet_size(len: usize) -> Result<(), DatapathError> {
    if len > MTU_V1 as usize {
        return Err(DatapathError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{len} byte packet exceeds the {MTU_V1} byte MTU"),
        )));
    }
    Ok(())
}

/// Refuse a configured MTU above [`MTU_V1`], rather than accommodating it.
///
/// The per-machine memory ceiling is computed from `MTU_V1`, because a
/// device queue entry is bounded by the link's MTU. Take the configured
/// value instead and the ceiling becomes a runtime number that no
/// compile-time assertion can pin — at an MTU of 9000 the true figure is
/// some multiple of the asserted one, and the constant silently stops
/// describing reality. That has already happened once here by a different
/// route, which is the argument for closing the route rather than widening
/// the formula.
///
/// Failing closed is the right direction because `MTU_V1` is *fixed and
/// not negotiated* — deliberately, so that nothing outside this process
/// gets to choose the host's buffer sizes. Nothing on this datapath needs
/// jumbo frames, and a ceiling a configuration can raise is not a ceiling.
fn accept_mtu(mtu: usize) -> Result<usize, DatapathError> {
    if mtu > MTU_V1 as usize {
        return Err(DatapathError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "configured MTU {mtu} exceeds the fixed {MTU_V1} byte MTU this datapath \
                 sizes its buffers for"
            ),
        )));
    }
    Ok(mtu)
}

/// Read `RLIMIT_NOFILE` and raise the soft limit toward the hard limit.
///
/// An unprivileged process may always raise its own soft limit up to the
/// hard limit — no capability is required for that direction. If the raise
/// itself fails (a sandboxed or already-tightened host), the open must not
/// fail with it: [`socket_budget`] is computed from the hard limit either
/// way, so a process that cannot actually reach that many open descriptors
/// fails later, at the individual `socket()` call, which is where a real
/// resource exhaustion belongs rather than at datapath setup.
fn read_and_raise_nofile_limit() -> libc::rlimit {
    let mut lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `lim` is a valid, writable `rlimit` for the call's duration.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) } != 0 {
        // Could not even read the limit; 0/0 makes `socket_budget` fail
        // closed rather than assume a number nobody confirmed.
        return lim;
    }
    if lim.rlim_cur < lim.rlim_max {
        let raised = libc::rlimit {
            rlim_cur: lim.rlim_max,
            rlim_max: lim.rlim_max,
        };
        // SAFETY: same resource id, a valid rlimit read just above. A
        // failed raise is not fatal — see the doc comment above.
        unsafe {
            libc::setrlimit(libc::RLIMIT_NOFILE, &raised);
        }
    }
    lim
}

/// Opens userspace socket datapaths.
///
/// Needs no privileges at all — no `utun`, no routes, no PF anchor — which
/// is its entire reason for existing, and why it is what every host without
/// a usable tunnel device forwards through.
#[derive(Debug, Default)]
pub struct UserspaceSocketDatapath;

impl UserspaceSocketDatapath {
    pub fn new() -> Self {
        Self
    }

    /// Build the concrete handle.
    ///
    /// Kept separate from [`L3Datapath::open`], which just boxes this, so
    /// tests and the fuzz harness can reach handle-only methods (`service`,
    /// `open_socket_count`) without downcasting a trait object. It opens no
    /// door a caller does not already have: [`DatapathHandle::send_to_network`]
    /// still takes an `AdmittedPacket`, so a concrete handle carries no more
    /// authority than a boxed one.
    pub fn open_handle(&self, req: &DatapathRequest) -> Result<UserspaceHandle, DatapathError> {
        let lim = read_and_raise_nofile_limit();
        // `libc::rlim_t` is `u64` on every target this crate builds for, so
        // this is a direct pass-through rather than a conversion.
        let budget = socket_budget(lim.rlim_cur, lim.rlim_max);

        let readiness = ReadinessSet::new().map_err(|source| DatapathError::SetupFailed {
            what: "userspace datapath poll set",
            machine_id: req.machine_id.clone(),
            source,
        })?;
        let watch = readiness.watch();

        // Symmetric, and at the machine-wide default: this is the one
        // device a machine has, so its depth does not multiply by the
        // socket cap the way a flow's does. The asymmetric per-flow
        // derivation exists to keep 256 copies affordable; against a
        // single queue there is no such pressure, in either direction.
        // (Not "because its stack emits nothing" — an interface answers
        // unmatched ingress with a reset or an unreachable whether or not
        // its socket set is empty.)
        let mut device = GuestDevice::new(
            accept_mtu(req.mtu as usize)?,
            QueueDepths::symmetric(DEFAULT_QUEUE_DEPTH),
        );
        let mut config = Config::new(HardwareAddress::Ip);
        // Recommended by smoltcp's own doc on `Config::random_seed`: a
        // predictable seed makes the ISNs and IPv4 identification field
        // this interface generates for the guest predictable too.
        config.random_seed = rand::random();
        let now = SmolInstant::from_millis(0i64);
        let mut interface = Interface::new(config, &mut device, now);
        interface.update_ip_addrs(|addrs| {
            addrs
                .push(IpCidr::new(IpAddress::Ipv4(req.gateway), req.prefix_len))
                .expect("a freshly created address list has room for its first entry");
            // The lease's own prefix length, not a second copy of it: the
            // IPv6 analogue of the IPv4 /30, leaving the guest on-link and
            // nothing else.
            if let Some(v6) = req.v6 {
                addrs
                    .push(IpCidr::new(IpAddress::Ipv6(v6.gateway), v6.prefix_len))
                    .expect("smoltcp's address list holds four");
            }
        });

        // Empty, and it stays empty: an established flow terminates the
        // guest's TCP in its own stack, addressed at its own destination,
        // rather than as one socket in a set shared across destinations.
        // This set is here for the interface `poll` below, which takes one
        // whether or not anything is in it.
        let sockets = SocketSet::new(Vec::new());

        let guest = GuestAddressing::new(req.guest, req.v6.map(|v6| v6.guest));

        // Bound before the handle exists, so a machine whose declared
        // mappings cannot all be served does not start. A listener silently
        // skipped is a workload told it is reachable on a port nothing
        // answers, which is the failure a declaration exists to prevent.
        let mut ingress = DatagramIngress::new(
            IngressBounds {
                // Against the same descriptor budget, for the same reason
                // as the tables above — and more strictly, since a listener
                // holds its descriptor for the machine's whole life.
                listeners: DEFAULT_MAX_UDP_INGRESS_LISTENERS.min(budget),
                peers_per_listener: PEERS_PER_INGRESS_LISTENER,
            },
            guest,
            watch.clone(),
        );
        for mapping in &req.ingress {
            // TCP ingress is declarable and is not served here: it would
            // need a listener whose accepted connections are originated
            // *toward* the guest, which this datapath does not build. It is
            // skipped rather than refused so a plan carrying one still runs
            // its outbound traffic; the gap is recorded in the capability
            // seam rather than hidden behind a bound socket.
            if mapping.proto != mvm_core::policy::projection::Proto::Udp {
                continue;
            }
            ingress.declare(*mapping)?;
        }

        Ok(UserspaceHandle {
            machine_id: req.machine_id.clone(),
            readiness: Some(readiness),
            device,
            interface,
            sockets,
            guest,
            mtu: accept_mtu(req.mtu as usize)?,
            budget,
            // Whichever is tighter. The half-open figure is sized against
            // real connect demand, but a process whose descriptor budget is
            // smaller than that demand cannot honour it, and a table
            // allowed to hold more entries than the process has descriptors
            // would refuse at `socket()` rather than at its own bound.
            half_open: HalfOpenTable::new(DEFAULT_MAX_HALF_OPEN.min(budget), guest, watch.clone()),
            // Bounded against the same budget, and for the same reason: an
            // association parks a descriptor drawn from the one pool TCP is
            // also drawing on.
            udp: UdpAssociations::new(
                DEFAULT_MAX_UDP_ASSOCIATIONS.min(budget),
                guest,
                watch.clone(),
            ),
            ingress,
            flows: BTreeMap::new(),
            metrics: GatewayMetrics::default(),
            now_millis: 0,
            closed: false,
        })
    }
}

impl L3Datapath for UserspaceSocketDatapath {
    fn open(&self, req: &DatapathRequest) -> Result<Box<dyn DatapathHandle>, DatapathError> {
        Ok(Box::new(self.open_handle(req)?))
    }

    fn is_available(&self) -> Result<(), DatapathError> {
        // No utun, no routes, no PF anchor: nothing here needs a
        // privilege check, which is the point of this backend.
        Ok(())
    }

    fn capabilities(&self) -> ForwardingCapabilities {
        ForwardingCapabilities::USERSPACE_SOCKETS
    }
}

/// One machine's open userspace datapath.
pub struct UserspaceHandle {
    machine_id: String,
    /// Backs [`DatapathHandle::readiness_fd`]. Every host socket this
    /// datapath opens is registered here, so a connect the kernel has
    /// decided or a peer that has sent wakes the drive loop instead of
    /// waiting out its tick.
    ///
    /// `Option` because `close` must drop it: the readiness contract
    /// promises that closing releases the descriptor number for reuse, and
    /// a set still alive inside a handle that merely says it is closed
    /// would keep holding it.
    readiness: Option<ReadinessSet>,
    /// The machine-wide guest-facing device.
    ///
    /// Carries no flow traffic — each flow terminates in its own stack over
    /// its own device — but it is where a packet the *host* originates for
    /// a guest goes when there is no flow to put it on: the resets owed to
    /// a connect that failed or timed out before any stack existed. Its
    /// queue is already bounded and already counted, which is why those
    /// resets do not get a second queue of their own.
    device: GuestDevice,
    interface: Interface,
    sockets: SocketSet<'static>,
    /// The addresses this session leased the guest. The authority on where
    /// a host-originated packet is addressed — never the source field of
    /// whatever the guest last sent.
    guest: GuestAddressing,
    /// Link MTU, checked once at open and reused for every flow's device so
    /// no flow can be built with buffers the ceiling has not budgeted for.
    mtu: usize,
    /// Ceiling on concurrent host sockets, computed once at open time from
    /// the process's actual descriptor budget.
    budget: usize,
    half_open: HalfOpenTable,
    /// Guest datagram conversations, each on its own connected host socket.
    udp: UdpAssociations,
    /// Host listeners for the declared inbound datagram mappings. Nothing
    /// is ever added here after open: a mapping exists because the plan
    /// declared it, never because traffic arrived.
    ingress: DatagramIngress,
    flows: BTreeMap<FlowKey, EstablishedFlow>,
    metrics: GatewayMetrics,
    /// The clock the last [`Self::service`] ran at.
    ///
    /// [`DatapathHandle::send_to_network`] carries no timestamp and this
    /// datapath deliberately reads no clock of its own — every time it uses
    /// comes from its driver, so a test drives it deterministically. A SYN
    /// arriving between two service passes is therefore timed as of the
    /// last one, which is one tick of skew against a half-open timeout of
    /// [`limits::HALF_OPEN_TIMEOUT_MILLIS`].
    now_millis: u64,
    closed: bool,
}

impl UserspaceHandle {
    /// Host sockets currently open for this machine.
    ///
    /// Half-open entries, established flows, and datagram associations are
    /// counted **together** because each one parks a real descriptor and
    /// they compete for the same budget. Three separate counters whose sum
    /// can exceed what the process was granted would not be a budget.
    ///
    /// A flow that released its socket early — a host error resets and
    /// closes in the same step — still counts here until the next service
    /// pass reaps it. That over-counts by at most one pass's worth, in the
    /// direction of refusing a newcomer rather than over-subscribing the
    /// process's descriptors.
    ///
    /// `pub`, like [`Self::metrics`]: the budget is the observable that says
    /// a reclaimed flow actually gave its descriptor back, and the end-to-end
    /// suite that asserts it lives outside this crate's netd module tree.
    pub fn open_socket_count(&self) -> usize {
        self.flows.len() + self.half_open.len() + self.udp.len() + self.ingress.len()
    }

    /// This machine's counters.
    ///
    /// `pub`, like [`Self::service`], because the driver that folds these
    /// into the gateway's own record lives outside this crate's netd
    /// module tree — and because a `pub(crate)` accessor with only a test
    /// caller trips `dead_code` under `-D warnings`.
    pub fn metrics(&self) -> &GatewayMetrics {
        &self.metrics
    }

    /// Drive the datapath: resolve completed connects, promote them into
    /// flows, expire what has timed out, pump every established flow, and
    /// poll the machine-wide interface.
    ///
    /// Reports [`InboundDrain::Backlogged`] when any flow's host-to-guest
    /// half stopped at its per-pass bound. The readiness this pass was woken
    /// by is spent at the top, before a socket is read, so a peer's
    /// remainder sitting in a host socket has no edge left to announce it —
    /// the driver has to be told, or it waits out the tick with the bytes
    /// already in hand.
    pub fn service(&mut self, now_millis: u64) -> Result<InboundDrain, DatapathError> {
        if self.closed {
            return Err(DatapathError::Io(std::io::Error::from(
                std::io::ErrorKind::BrokenPipe,
            )));
        }
        self.now_millis = now_millis;
        // Spend the readiness this pass was woken by before reading a single
        // socket. An edge cleared afterwards would be one for bytes that
        // landed between the two, and nothing would go back for them until
        // the tick — which is the wait this whole mechanism removes.
        if let Some(readiness) = self.readiness.as_mut() {
            readiness.drain();
        }
        self.resolve_connects(now_millis);
        self.expire_half_open();
        // Polled before expiring, so a reply that arrived inside an
        // association's lifetime still reaches the guest on the pass that
        // ends it.
        self.poll_associations(now_millis);
        self.expire_associations(now_millis);
        // Same order, for the same reason: a datagram that arrived inside a
        // peer's lifetime still reaches the guest on the pass that ends it.
        self.poll_ingress(now_millis);
        self.expire_ingress(now_millis);
        let drain = self.pump_flows(now_millis);
        let now = SmolInstant::from_millis(now_millis as i64);
        self.interface
            .poll(now, &mut self.device, &mut self.sockets);
        Ok(drain)
    }

    /// Take out every connect the kernel has decided: successes become
    /// flows, failures become the resets their guests are owed.
    fn resolve_connects(&mut self, now_millis: u64) {
        let resolved = self.half_open.resolve(&mut self.metrics);
        for reset in resolved.resets {
            self.queue_for_guest(reset);
        }
        for entry in resolved.established {
            let key = entry.key();
            match EstablishedFlow::from_half_open(entry, self.guest, self.mtu, now_millis) {
                Ok(flow) => {
                    self.flows.insert(key, flow);
                }
                // The connect succeeded but the flow could not be built.
                // Counted rather than dropped: the guest is left waiting on
                // a SYN-ACK that is not coming, which is the one outcome
                // the deferred handshake exists to make impossible.
                Err(_) => self.metrics.datapath_errors += 1,
            }
        }
        // `resolved.failed` drops here, and each entry's host descriptor
        // closes with it. The reset each one owed was built above, before
        // the socket went away.
    }

    /// Drop half-open entries whose destination never answered, telling
    /// each guest so.
    fn expire_half_open(&mut self) {
        let guest = self.guest;
        for entry in self.half_open.expire(self.now_millis) {
            match entry.reset_for_guest(guest) {
                Some(reset) => self.queue_for_guest(reset),
                None => self.metrics.datapath_errors += 1,
            }
            self.metrics.flows_expired += 1;
        }
    }

    /// Put what every association's peer sent in front of the guest.
    fn poll_associations(&mut self, now_millis: u64) {
        for packet in self.udp.poll(now_millis) {
            self.queue_for_guest(packet);
        }
        let drops = self.udp.take_drops();
        // A datagram from a source this guest never addressed is an
        // injection attempt the kernel's own filter should have stopped.
        self.metrics
            .record_denies(DenyCode::UnsolicitedInbound, drops.off_path);
        self.metrics
            .record_denies(DenyCode::OversizedPacket, drops.oversized);
        self.metrics.datapath_errors = self
            .metrics
            .datapath_errors
            .saturating_add(drops.unaddressable);
    }

    /// Put what every declared mapping's peers sent in front of the guest.
    ///
    /// Queued, not delivered: these packets leave through the handle's read
    /// path and go back through `mvm_net::l3::admit`, which refuses any
    /// whose guest port has no declared mapping there. This side opens the
    /// socket; admission decides what reaches the guest.
    fn poll_ingress(&mut self, now_millis: u64) {
        for packet in self.ingress.poll(now_millis) {
            self.queue_for_guest(packet);
        }
        let drops = self.ingress.take_drops();
        // A peer the listener had no room to remember is refused for the
        // same reason a flow past the table's cap is.
        self.metrics
            .record_denies(DenyCode::FlowTableFull, drops.peers_full);
        self.metrics
            .record_denies(DenyCode::OversizedPacket, drops.oversized);
        self.metrics.datapath_errors = self
            .metrics
            .datapath_errors
            .saturating_add(drops.unaddressable)
            .saturating_add(drops.read_errors);
    }

    /// Reclaim ingress peers that have reached their deadline. The
    /// listeners themselves stay: they are declared.
    fn expire_ingress(&mut self, now_millis: u64) {
        let expired = self.ingress.expire(now_millis) as u64;
        self.metrics.flows_expired = self.metrics.flows_expired.saturating_add(expired);
    }

    /// Reclaim associations that have reached their deadline.
    fn expire_associations(&mut self, now_millis: u64) {
        let expired = self.udp.expire(now_millis) as u64;
        self.metrics.flows_expired = self.metrics.flows_expired.saturating_add(expired);
    }

    /// Move both directions of every established flow, and reap the ones
    /// that have finished.
    ///
    /// Finished means the connection ended, never that it was quiet: see
    /// the body, and [`limits::KEEPALIVE_IDLE_SECS`] for what reclaims a
    /// flow whose peer is gone.
    ///
    /// Reports whether *any* flow's host-to-guest half stopped at its bound.
    /// One flag for the machine rather than a set of flow keys: the driver's
    /// only decision is whether to come straight back, and it comes back to
    /// all of them at once.
    fn pump_flows(&mut self, now_millis: u64) -> InboundDrain {
        let Self { flows, metrics, .. } = self;
        let mut backlogged = false;
        flows.retain(|_, flow| {
            let stats = flow.pump(now_millis, metrics);
            fold_throughput(metrics, &stats);
            backlogged |= stats.backlogged;
            // Nothing here ages a flow for being quiet. An established flow
            // is reclaimed when its *peer* is gone — the host socket's
            // keepalive surfaces that as an error, and the error path
            // resets the guest and releases the descriptor — never for
            // having nothing to say. This datapath carries protocols that
            // are idle by design, and a quiet stream is a working stream.
            //
            // A finished flow is kept while it still holds packets for the
            // guest — the reset explaining why it finished, above all.
            // Reaping it with those undelivered would put the guest back at
            // the silent hang the reset exists to prevent.
            flow.is_active() || flow.pending_to_guest() > 0
        });
        if backlogged {
            InboundDrain::Backlogged
        } else {
            InboundDrain::Idle
        }
    }

    /// Put a host-originated packet on the machine-wide guest-bound queue.
    fn queue_for_guest(&mut self, packet: Vec<u8>) {
        if self.device.push_to_guest(packet) != PushOutcome::Queued {
            // The device counts this for a debugger holding the handle;
            // this is the same drop in the counter an operator reads.
            self.metrics.queue_drops_egress = self.metrics.queue_drops_egress.saturating_add(1);
        }
    }

    /// Forward one admitted guest packet, given what admission already
    /// parsed out of it.
    ///
    /// Split out of [`DatapathHandle::send_to_network`] for the reason
    /// [`accept_packet_size`] is: an `AdmittedPacket` is constructible only
    /// by `mvm_net::l3`'s admitter, so a unit test in this crate cannot
    /// build one, and a wiring that could only be driven through the trait
    /// method could not be tested at all.
    fn forward(
        &mut self,
        flow: FlowKey,
        meta: &ParsedIpPacket,
        bytes: &[u8],
    ) -> Result<(), DatapathError> {
        if self.closed {
            return Err(DatapathError::Io(std::io::Error::from(
                std::io::ErrorKind::BrokenPipe,
            )));
        }
        accept_packet_size(bytes.len())?;
        match meta.protocol {
            proto::TCP => self.forward_segment(flow, meta, bytes),
            proto::UDP => self.forward_datagram(flow, meta, bytes),
            other => Err(self.refuse_protocol(other)),
        }
    }

    /// Re-originate one guest datagram on a host socket.
    ///
    /// DNS never arrives here: it is answered above this seam by the
    /// host-terminated resolver, so no query reaches a nameserver through a
    /// socket this datapath opened.
    fn forward_datagram(
        &mut self,
        flow: FlowKey,
        meta: &ParsedIpPacket,
        bytes: &[u8],
    ) -> Result<(), DatapathError> {
        let payload = ip::udp_payload(bytes, meta).ok_or_else(|| {
            DatapathError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "a UDP packet whose declared length names no readable payload",
            ))
        })?;
        // The ingress path first. A conversation a declared mapping started
        // is answered on the listener it arrived on, so the peer sees the
        // reply come from the address it dialled — an ephemeral source port
        // from a fresh association would be a different 4-tuple, and the
        // peer would discard it as belonging to nothing.
        match self.ingress.reply(&flow, payload, self.now_millis) {
            ReplyOutcome::Sent => {
                self.metrics.packets_egress = self.metrics.packets_egress.saturating_add(1);
                return Ok(());
            }
            ReplyOutcome::Failed(e) => {
                self.metrics.datapath_errors += 1;
                return Err(e);
            }
            // Not an ingress conversation. Falls through to the association
            // path, whose socket is connected to an admitted destination.
            ReplyOutcome::NotIngress => {}
        }
        if !self.udp.holds(&flow) && (self.open_socket_count() >= self.budget || self.udp.is_full())
        {
            // Drop the newcomer, never a live association — the posture the
            // rest of this subsystem takes at capacity.
            self.metrics.record_deny(DenyCode::FlowTableFull);
            return Err(DatapathError::Io(std::io::Error::new(
                std::io::ErrorKind::OutOfMemory,
                format!("{} host sockets already open for this machine", self.budget),
            )));
        }
        match self.udp.send(flow, payload, self.now_millis) {
            Ok(()) => {
                self.metrics.packets_egress = self.metrics.packets_egress.saturating_add(1);
                Ok(())
            }
            Err(e) => {
                self.metrics.datapath_errors += 1;
                Err(e)
            }
        }
    }

    /// Carry one guest TCP segment into the flow that owns it, opening one
    /// if this is a SYN.
    fn forward_segment(
        &mut self,
        flow: FlowKey,
        meta: &ParsedIpPacket,
        bytes: &[u8],
    ) -> Result<(), DatapathError> {
        // Established first, so a SYN retransmitted after the handshake
        // completed reaches the flow that owns it instead of opening a
        // second host socket for a connection that already exists.
        if let Some(established) = self.flows.get_mut(&flow) {
            return match established.deliver_from_guest(bytes) {
                PushOutcome::Queued => {
                    self.metrics.packets_egress = self.metrics.packets_egress.saturating_add(1);
                    Ok(())
                }
                PushOutcome::DroppedQueueFull => Err(DatapathError::Io(std::io::Error::from(
                    std::io::ErrorKind::WouldBlock,
                ))),
                PushOutcome::DroppedOversized => Err(DatapathError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "packet exceeds the link MTU",
                ))),
            };
        }
        let flags = ip::tcp_flags(bytes, meta).ok_or_else(|| {
            DatapathError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "a TCP packet with no readable flag byte",
            ))
        })?;
        if !meta.is_tcp_syn_only(flags) {
            // A segment for a connection this datapath has no record of:
            // most often the guest's last ACK arriving after its flow was
            // reaped, which is routine and must not be reported as an
            // error. Counted under its own name so it also cannot hide.
            self.metrics.segments_without_flow += 1;
            return Ok(());
        }
        self.open_flow(flow, bytes)
    }

    /// Start a host connect for a guest SYN, if the budget allows.
    fn open_flow(&mut self, flow: FlowKey, syn: &[u8]) -> Result<(), DatapathError> {
        if self.open_socket_count() >= self.budget {
            // Drop the newcomer, never a live entry — the posture the rest
            // of this subsystem takes at capacity.
            self.metrics.record_deny(DenyCode::FlowTableFull);
            return Err(DatapathError::Io(std::io::Error::new(
                std::io::ErrorKind::OutOfMemory,
                format!("{} host sockets already open for this machine", self.budget),
            )));
        }
        // The destination comes from the admitted flow key, never from a
        // re-read of the guest's bytes: re-deriving it here would put a
        // second parse below the policy seam that checked the first.
        let dst = SocketAddr::new(flow.remote, flow.remote_port);
        match self
            .half_open
            .on_syn(flow, syn.to_vec(), dst, self.now_millis)
        {
            SynOutcome::Started | SynOutcome::Folded => {
                self.metrics.packets_egress = self.metrics.packets_egress.saturating_add(1);
                Ok(())
            }
            SynOutcome::Refused(code) => {
                self.metrics.record_deny(code);
                Err(DatapathError::Io(std::io::Error::new(
                    std::io::ErrorKind::ConnectionRefused,
                    format!(
                        "the host refused a connect for this flow: {}",
                        code.as_str()
                    ),
                )))
            }
        }
    }

    /// Refuse a transport this datapath cannot translate.
    ///
    /// Refused rather than dropped. A silently discarded packet is a guest
    /// that hangs with nothing anywhere to say why; an error reaches the
    /// caller's `datapath_errors` counter on the very first packet.
    fn refuse_protocol(&mut self, protocol: u8) -> DatapathError {
        self.metrics.record_deny(DenyCode::ProtocolDenied);
        DatapathError::Unsupported {
            platform: "the userspace socket datapath",
            detail: format!("IP protocol {protocol} is not translated to a host socket"),
        }
    }

    /// The next packet waiting for the guest, from anywhere this handle
    /// holds one.
    fn next_guest_packet(&mut self) -> Option<Vec<u8>> {
        // Host-originated packets first. They are the resets owed to a
        // guest whose connect failed, and that guest is blocked on nothing
        // else; a flow with data to move is, by definition, one whose
        // connect worked.
        let packet = self.device.pop_for_guest().or_else(|| {
            self.flows
                .values_mut()
                .find_map(EstablishedFlow::next_guest_packet)
        })?;
        self.metrics.packets_ingress = self.metrics.packets_ingress.saturating_add(1);
        Some(packet)
    }
}

impl DatapathHandle for UserspaceHandle {
    fn send_to_network(&mut self, packet: &AdmittedPacket<'_>) -> Result<(), DatapathError> {
        self.forward(packet.flow(), packet.meta(), packet.bytes())
    }

    /// The driver holds a trait object, so this is the only `service` it can
    /// reach. Everything a pending connect needs is behind it.
    fn service(&mut self, now_millis: u64) -> Result<InboundDrain, DatapathError> {
        UserspaceHandle::service(self, now_millis)
    }

    fn recv_from_network(&mut self, buf: &mut [u8]) -> Result<usize, DatapathError> {
        if self.closed {
            return Err(DatapathError::Io(std::io::Error::from(
                std::io::ErrorKind::BrokenPipe,
            )));
        }
        match self.next_guest_packet() {
            Some(packet) => {
                let n = packet.len().min(buf.len());
                buf[..n].copy_from_slice(&packet[..n]);
                Ok(n)
            }
            None => Err(DatapathError::Io(std::io::Error::from(
                std::io::ErrorKind::WouldBlock,
            ))),
        }
    }

    fn close(&mut self) -> Result<(), DatapathError> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        // Every entry in every table parks a host descriptor, so dropping
        // them here is what actually closes those. Deferring to the
        // handle's own drop would leak them for as long as anything still
        // holds the handle — and this runs on the failed-startup path too,
        // where the tables may never have held anything at all.
        self.flows.clear();
        self.half_open.clear();
        self.udp.clear();
        self.ingress.clear();
        // Dropped after the tables above, so every socket deregisters
        // itself while the set is still there to deregister from. Dropped
        // now rather than whenever the handle happens to: the readiness
        // contract promises that closing frees the descriptor number
        // `readiness_fd` reported, for the next `open` anywhere in the
        // process to reuse.
        //
        // The set's second descriptor — the owned reference the tables
        // register through — goes when the handle itself drops, because the
        // tables outlive this call. It names the same kernel object, nothing
        // waits on it, and there is nothing left registered on it by the
        // time this returns.
        self.readiness = None;
        Ok(())
    }

    fn description(&self) -> String {
        format!(
            "userspace socket datapath for {} (budget {} sockets, {} open)",
            self.machine_id,
            self.budget,
            self.open_socket_count()
        )
    }

    fn readiness_fd(&self) -> Option<RawFd> {
        self.readiness.as_ref().map(ReadinessSet::readiness_fd)
    }
}

impl Drop for UserspaceHandle {
    /// Teardown must not depend on anyone remembering to call `close`. A
    /// panic, an early return, or a dropped supervisor would otherwise
    /// leave the poll set's descriptor open under a handle nothing can
    /// reach anymore.
    fn drop(&mut self) {
        let _ = self.close();
    }
}

/// Fold one pump pass's byte movement into the machine's counters.
///
/// Without this the datapath is unobservable for throughput: nothing else
/// records whether it is carrying traffic at all. The same argument that
/// made a queue drop countable rather than silent applies to the traffic
/// the drop is measured against.
///
/// **Packets are counted at the guest seam and bytes at the host seam**, and
/// on a datapath that translates flows into host sockets those are honestly
/// different quantities: a guest packet includes framing and may be a pure
/// ACK carrying nothing, while a host byte is payload that actually crossed
/// the network. Counting bytes at the guest seam as well would put two
/// meanings behind one counter, so `bytes_egress` is payload written to the
/// host socket and `packets_egress` is packets accepted from the guest.
fn fold_throughput(metrics: &mut GatewayMetrics, stats: &tcp::PumpStats) {
    metrics.bytes_egress = metrics.bytes_egress.saturating_add(stats.to_host as u64);
    metrics.bytes_ingress = metrics.bytes_ingress.saturating_add(stats.to_guest as u64);
}

#[cfg(test)]
mod tests {
    use super::super::datapath::V6Link;
    use super::limits::{
        ASSOCIATION_LIFETIME_MILLIS, HALF_CLOSED_TIMEOUT_MILLIS,
        HANDSHAKE_COMPLETION_TIMEOUT_MILLIS, RESET_DELIVERY_TIMEOUT_MILLIS,
    };
    use super::*;
    use crate::netd::test_packets::v4_packet;
    use mvm_net::l3::flow::DEFAULT_TCP_IDLE_MILLIS;
    use smoltcp::wire::{TcpControl, TcpRepr, TcpSeqNumber};
    use std::io::{Read, Write};
    use std::net::{Ipv4Addr, TcpListener};
    use std::time::Duration;

    use super::tcp::{emit_v4_segment, emit_v6_segment, max_bytes_per_pass};
    use mvm_net::l3::IngressMapping;

    const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

    /// Service passes a fixture will wait through for a loopback connect to
    /// resolve. Bounded, so a fixture that never resolves fails an
    /// assertion instead of hanging the suite.
    const SERVICE_ATTEMPTS: usize = 200;

    /// How long a fixture gives a completed loopback write to reach the
    /// far socket's receive queue. `write` returning means the kernel took
    /// the bytes, not that the reader can see them yet — loopback delivery
    /// finishes in a softirq. Only ever a precondition, never an assertion.
    const LOOPBACK_SETTLE: Duration = Duration::from_millis(50);

    /// The fixture session is dual-stack, so the v4 assertions below run
    /// against exactly the handle shape a v6 flow also runs against.
    const FIXTURE_GATEWAY_V6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0xc9, 0, 0, 0, 0, 0, 1);
    const FIXTURE_GUEST_V6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0xc9, 0, 0, 0, 0, 0, 2);

    fn request() -> DatapathRequest {
        DatapathRequest {
            machine_id: "vm-a".into(),
            gateway: std::net::Ipv4Addr::new(10, 201, 0, 5),
            guest: std::net::Ipv4Addr::new(10, 201, 0, 6),
            prefix_len: 30,
            v6: Some(V6Link {
                gateway: FIXTURE_GATEWAY_V6,
                guest: FIXTURE_GUEST_V6,
                prefix_len: 126,
            }),
            mtu: MTU_V1,
            ingress: Vec::new(),
        }
    }

    fn open_test_handle() -> UserspaceHandle {
        UserspaceSocketDatapath::new()
            .open_handle(&request())
            .expect("opening a userspace handle needs no privileges")
    }

    /// macOS ships a soft RLIMIT_NOFILE of 256. Inheriting the flow cap of
    /// 4096 would exhaust the process's descriptors — which does not
    /// merely break the tunnel, it breaks the supervisor's ability to open
    /// its audit log.
    #[test]
    fn the_socket_budget_respects_a_small_descriptor_limit() {
        assert_eq!(socket_budget(256, 256), 256 - FD_RESERVE);
    }

    #[test]
    fn the_socket_budget_never_exceeds_the_ceiling() {
        assert_eq!(
            socket_budget(1_048_576, 1_048_576),
            DEFAULT_MAX_HOST_SOCKETS
        );
    }

    #[test]
    fn a_descriptor_limit_below_the_reserve_yields_no_sockets() {
        assert_eq!(socket_budget(32, 32), 0);
    }

    #[test]
    fn the_socket_budget_uses_the_larger_of_soft_and_hard() {
        // The hard limit is what an unprivileged process can always reach
        // by raising its soft limit; a soft limit reported larger than the
        // hard limit should not happen, but the budget must not
        // under-count if it somehow does.
        assert_eq!(socket_budget(300, 200), 300 - FD_RESERVE);
    }

    #[test]
    fn the_userspace_datapath_reports_socket_translation_capabilities() {
        let dp = UserspaceSocketDatapath::new();
        assert_eq!(dp.capabilities(), ForwardingCapabilities::USERSPACE_SOCKETS);
        assert!(
            dp.is_available().is_ok(),
            "it needs no privileges, so it is always available"
        );
    }

    #[test]
    fn an_oversized_packet_is_refused_before_it_reaches_the_device() {
        assert!(accept_packet_size(MTU_V1 as usize + 1).is_err());
    }

    #[test]
    fn a_packet_at_exactly_the_mtu_is_accepted() {
        assert!(accept_packet_size(MTU_V1 as usize).is_ok());
    }

    /// The memory ceiling is computed from `MTU_V1`. A configured MTU above
    /// it would make that constant describe something other than reality —
    /// the same class of silent drift that the per-flow device queues
    /// caused, reached by configuration instead of by code.
    #[test]
    fn an_mtu_above_the_fixed_one_is_refused_rather_than_accommodated() {
        assert!(accept_mtu(MTU_V1 as usize).is_ok());
        assert!(accept_mtu(MTU_V1 as usize - 1).is_ok());
        assert!(
            accept_mtu(9000).is_err(),
            "a jumbo MTU would silently multiply the per-machine ceiling"
        );
    }

    #[test]
    fn opening_a_handle_refuses_an_mtu_above_the_fixed_one() {
        let mut req = request();
        req.mtu = 9000;
        assert!(
            UserspaceSocketDatapath::new().open_handle(&req).is_err(),
            "the datapath must not open with buffers it has not budgeted for"
        );
    }

    #[test]
    fn opening_a_handle_exposes_a_readiness_descriptor() {
        let handle = open_test_handle();
        assert!(
            handle.readiness_fd().is_some(),
            "the handle owns a poll set even before any socket is registered on it"
        );
    }

    /// How long a readiness assertion waits before calling it a failure.
    ///
    /// A ceiling on a wait, not a latency budget: a registered descriptor
    /// reports a resolved loopback connect in microseconds, and the margin
    /// is here so a loaded test host cannot fail the assertion. What makes
    /// this a witness is that it asserts on *readiness*, not on elapsed
    /// time — an unregistered descriptor waits this out and reports nothing,
    /// however fast the machine is.
    const READINESS_DEADLINE: Duration = Duration::from_secs(10);

    /// Wait for the handle's readiness descriptor to report something.
    ///
    /// Driven from an outer poll set, because that is what `mvm-netd` does
    /// with `readiness_fd`: a test that polled the datapath's own set would
    /// be exercising a nesting production never performs.
    fn readiness_fires(handle: &UserspaceHandle) -> bool {
        let fd = handle
            .readiness_fd()
            .expect("an open handle exposes its readiness descriptor");
        let mut outer = mio::Poll::new().expect("outer poll set");
        outer
            .registry()
            .register(
                &mut mio::unix::SourceFd(&fd),
                mio::Token(0),
                mio::Interest::READABLE,
            )
            .expect("registering the datapath's readiness descriptor");
        let mut events = mio::Events::with_capacity(8);
        let deadline = std::time::Instant::now() + READINESS_DEADLINE;
        loop {
            let Some(left) = deadline.checked_duration_since(std::time::Instant::now()) else {
                return false;
            };
            outer.poll(&mut events, Some(left)).expect("outer poll");
            if !events.is_empty() {
                return true;
            }
        }
    }

    /// The defect this pins: `readiness_fd` handed the drive loop a poll set
    /// with nothing registered behind it, so a connect the kernel had
    /// already decided woke nobody and the guest waited out the loop's tick
    /// instead. Registering the host sockets this datapath owns is what
    /// turns that descriptor from decorative into the thing that drives the
    /// loop.
    #[test]
    fn a_resolved_connect_reports_on_the_readiness_descriptor() {
        let held = listener();
        let dst = held.local_addr().expect("local addr");
        let mut handle = open_test_handle();
        let syn = guest_segment(50_000, dst, TcpControl::Syn, &[]);
        deliver(&mut handle, &syn).expect("a SYN toward a live listener is accepted");

        assert!(
            readiness_fires(&handle),
            "the host socket this datapath opened for the guest's connect must \
             be registered on the descriptor the drive loop waits on"
        );
        handle.service(0).expect("service");
        assert_eq!(
            handle.flows.len(),
            1,
            "the wake must mean the connect is resolvable, not merely that \
             something fired"
        );
    }

    #[test]
    fn close_is_idempotent_and_releases_the_readiness_descriptor() {
        let mut handle = open_test_handle();
        handle.close().expect("first close");
        handle
            .close()
            .expect("second close is a no-op, not an error");
        assert!(handle.readiness_fd().is_none());
    }

    #[test]
    fn a_closed_handle_refuses_further_reads_and_writes() {
        let mut handle = open_test_handle();
        handle.close().expect("close");
        let mut buf = [0u8; 64];
        assert!(handle.recv_from_network(&mut buf).is_err());
    }

    #[test]
    fn recv_from_network_reports_would_block_when_idle() {
        let mut handle = open_test_handle();
        let mut buf = [0u8; 64];
        let err = handle.recv_from_network(&mut buf).unwrap_err();
        assert!(matches!(
            err,
            DatapathError::Io(ref e) if e.kind() == std::io::ErrorKind::WouldBlock
        ));
    }

    #[test]
    fn service_polls_smoltcp_with_no_flows_and_does_not_error() {
        let mut handle = open_test_handle();
        assert!(handle.service(0).is_ok());
        assert!(handle.service(1_000).is_ok());
        assert_eq!(handle.open_socket_count(), 0);
    }

    #[test]
    fn service_on_a_closed_handle_is_an_error_not_a_panic() {
        let mut handle = open_test_handle();
        handle.close().expect("close");
        assert!(handle.service(0).is_err());
    }

    /// The driver holds a `Box<dyn DatapathHandle>`, so the inherent
    /// `service` above is not the one production reaches: the trait method
    /// is. A trait impl left on the no-op default would leave every connect
    /// pending forever while every test that calls the inherent method
    /// stayed green.
    #[test]
    fn servicing_through_the_trait_object_resolves_a_pending_connect() {
        let held = listener();
        let dst = held.local_addr().expect("local addr");
        let mut handle = open_test_handle();
        let syn = guest_segment(50_000, dst, TcpControl::Syn, &[]);
        deliver(&mut handle, &syn).expect("a SYN toward a live listener is accepted");

        let mut boxed: Box<dyn DatapathHandle> = Box::new(handle);
        let mut buf = [0u8; MTU_V1 as usize];
        let mut answered = false;
        for pass in 0..SERVICE_ATTEMPTS {
            boxed.service(pass as u64).expect("service");
            if let Ok(n) = boxed.recv_from_network(&mut buf)
                && syn_ack_isn(&buf[..n], 50_000).is_some()
            {
                answered = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        assert!(
            answered,
            "servicing through the trait object must resolve the connect and \
             answer the guest's SYN"
        );
    }

    fn v4_of(addr: SocketAddr) -> Ipv4Addr {
        match addr.ip() {
            IpAddr::V4(a) => a,
            IpAddr::V6(_) => unreachable!("the fixture destinations are IPv4"),
        }
    }

    /// The guest's initial sequence number. Any value works; a fixed one
    /// makes a desynchronised fixture obvious in a packet dump.
    const GUEST_ISN: u32 = 1_000;

    /// One guest segment toward `dst`, paired with the flow key admission
    /// would have derived from it.
    ///
    /// The pair is built together because the datapath trusts the *key* for
    /// the destination it connects to and the *bytes* for what it replays
    /// into the stack; a fixture that let the two disagree would be testing
    /// a state admission cannot produce.
    ///
    /// Emitted through the same builder the datapath's own resets go
    /// through, rather than a hand-laid header: a segment with a zero
    /// checksum is dropped by the flow's stack before it reaches any of the
    /// state under test, and the test would then be asserting against a
    /// packet nothing ever saw.
    fn guest_segment(
        guest_port: u16,
        dst: SocketAddr,
        control: TcpControl,
        payload: &[u8],
    ) -> (FlowKey, Vec<u8>) {
        GuestSegment {
            guest_port,
            dst,
            control,
            seq: GUEST_ISN,
            ack: (!matches!(control, TcpControl::Syn)).then_some(1),
            payload,
        }
        .emit()
    }

    /// A guest segment described by every field that matters, rather than
    /// by a row of positional arguments: once the sequence and the
    /// acknowledgement are both callers' business, two adjacent `u32`s in a
    /// signature are a transposition waiting to happen.
    struct GuestSegment<'a> {
        guest_port: u16,
        dst: SocketAddr,
        control: TcpControl,
        seq: u32,
        ack: Option<u32>,
        payload: &'a [u8],
    }

    impl GuestSegment<'_> {
        fn emit(&self) -> (FlowKey, Vec<u8>) {
            let segment = TcpRepr {
                src_port: self.guest_port,
                dst_port: self.dst.port(),
                control: self.control,
                seq_number: TcpSeqNumber(self.seq as i32),
                ack_number: self.ack.map(|a| TcpSeqNumber(a as i32)),
                window_len: u16::MAX,
                window_scale: None,
                max_seg_size: matches!(self.control, TcpControl::Syn).then_some(1_400),
                sack_permitted: false,
                sack_ranges: [None; 3],
                timestamp: None,
                payload: self.payload,
            };
            let bytes = match self.dst.ip() {
                IpAddr::V4(dst) => emit_v4_segment(request().guest, dst, &segment),
                IpAddr::V6(dst) => emit_v6_segment(
                    request().v6.expect("the fixture session holds one").guest,
                    dst,
                    &segment,
                ),
            };
            let key = FlowKey {
                protocol: proto::TCP,
                guest_port: self.guest_port,
                remote: self.dst.ip(),
                remote_port: self.dst.port(),
            };
            (key, bytes)
        }
    }

    /// The transport header of a packet of either family.
    ///
    /// The fixtures emit no IPv6 extension headers, so the payload of a v6
    /// packet is at the fixed header length; a v4 packet's is at its IHL.
    fn transport_payload(packet: &[u8]) -> Option<&[u8]> {
        match packet.first()? >> 4 {
            4 => packet.get(((packet[0] & 0x0f) as usize) * 4..),
            6 => packet.get(40..),
            _ => None,
        }
    }

    /// The stack's initial sequence number, read out of the SYN-ACK it
    /// produced for `guest_port`.
    fn syn_ack_isn(packet: &[u8], guest_port: u16) -> Option<u32> {
        let seg = smoltcp::wire::TcpPacket::new_checked(transport_payload(packet)?).ok()?;
        (seg.syn() && seg.ack() && seg.dst_port() == guest_port).then(|| seg.seq_number().0 as u32)
    }

    /// Answer the SYN-ACK, so the guest side reaches ESTABLISHED.
    ///
    /// Without this a handle's flows sit in SYN-RECEIVED, where smoltcp
    /// will neither deliver a payload to the host nor accept one for the
    /// guest — so every throughput assertion over such a flow would be
    /// vacuous. Returns the acknowledgement number the guest must carry
    /// from here on.
    fn complete_handshake(handle: &mut UserspaceHandle, guest_port: u16, dst: SocketAddr) -> u32 {
        let mut buf = [0u8; MTU_V1 as usize];
        for _ in 0..SERVICE_ATTEMPTS {
            let Ok(n) = handle.recv_from_network(&mut buf) else {
                break;
            };
            let Some(isn) = syn_ack_isn(&buf[..n], guest_port) else {
                continue;
            };
            let ack = isn.wrapping_add(1);
            let reply = GuestSegment {
                guest_port,
                dst,
                control: TcpControl::None,
                seq: GUEST_ISN.wrapping_add(1),
                ack: Some(ack),
                payload: &[],
            }
            .emit();
            deliver(handle, &reply).expect("the guest's handshake ACK is accepted");
            handle.service(0).expect("service");
            return ack;
        }
        panic!("the flow's stack must answer the replayed SYN with a SYN-ACK");
    }

    /// A handle carrying one flow whose guest has completed its handshake,
    /// with the accepted peer at the far end so a test can see what
    /// actually crossed the host socket.
    fn handle_with_an_established_conversation()
    -> (UserspaceHandle, SocketAddr, std::net::TcpStream, u32) {
        let held = listener();
        let dst = held.local_addr().expect("local addr");
        let mut handle = open_test_handle();
        let syn = guest_segment(50_000, dst, TcpControl::Syn, &[]);
        deliver(&mut handle, &syn).expect("a SYN toward a live listener is accepted");
        assert!(
            drive_until(&mut handle, |h| h.flows.len() == 1),
            "the fixture's loopback connect must resolve"
        );
        let (peer, _) = held.accept().expect("accept the flow's host socket");
        let ack = complete_handshake(&mut handle, 50_000, dst);
        (handle, dst, peer, ack)
    }

    fn udp_segment(guest_port: u16, dst: SocketAddr, payload: &[u8]) -> (FlowKey, Vec<u8>) {
        let mut datagram = vec![0u8; 8];
        datagram[0..2].copy_from_slice(&guest_port.to_be_bytes());
        datagram[2..4].copy_from_slice(&dst.port().to_be_bytes());
        datagram[4..6].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        datagram.extend_from_slice(payload);
        let bytes = v4_packet(proto::UDP, request().guest, v4_of(dst), &datagram);
        let key = FlowKey {
            protocol: proto::UDP,
            guest_port,
            remote: dst.ip(),
            remote_port: dst.port(),
        };
        (key, bytes)
    }

    /// Hand a fixture packet to the handle exactly as `send_to_network`
    /// would, with the metadata admission would have attached.
    fn deliver(
        handle: &mut UserspaceHandle,
        packet: &(FlowKey, Vec<u8>),
    ) -> Result<(), DatapathError> {
        let meta = ip::parse(&packet.1).expect("the fixture packet parses");
        handle.forward(packet.0, &meta, &packet.1)
    }

    fn listener() -> TcpListener {
        TcpListener::bind("127.0.0.1:0").expect("bind a loopback listener")
    }

    /// An address nothing is listening on, so a connect to it is refused
    /// rather than left pending.
    fn dead_destination() -> SocketAddr {
        let l = listener();
        let addr = l.local_addr().expect("local addr");
        drop(l);
        addr
    }

    /// Drive `handle` until `ready` holds, or fail. Bounded on both counts:
    /// a condition that never comes true must produce an assertion, never a
    /// hang.
    fn drive_until(handle: &mut UserspaceHandle, ready: impl Fn(&UserspaceHandle) -> bool) -> bool {
        for pass in 0..SERVICE_ATTEMPTS {
            handle.service(pass as u64).expect("service");
            if ready(handle) {
                return true;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        false
    }

    /// A handle carrying `count` established flows over real host sockets.
    ///
    /// The listener is returned rather than dropped: dropping it would
    /// reset every connection and the flows would stop being open sockets.
    fn handle_with_open_flows(count: usize) -> (UserspaceHandle, TcpListener) {
        let held = listener();
        let dst = held.local_addr().expect("local addr");
        let mut handle = open_test_handle();
        for i in 0..count {
            let syn = guest_segment(50_000 + i as u16, dst, TcpControl::Syn, &[]);
            deliver(&mut handle, &syn).expect("a SYN toward a live listener is accepted");
        }
        assert!(
            drive_until(&mut handle, |h| h.flows.len() == count),
            "the fixture's {count} loopback connects must resolve"
        );
        (handle, held)
    }

    #[test]
    fn a_guest_syn_becomes_a_flow_over_a_real_host_socket() {
        let (handle, _held) = handle_with_open_flows(1);
        assert_eq!(handle.open_socket_count(), 1);
        assert!(
            handle.half_open.is_empty(),
            "a resolved entry must leave the half-open table"
        );
    }

    /// The handshake the flow's stack produced has to be reachable through
    /// the datapath's own read path, or the guest never reaches ESTABLISHED
    /// however well the tables behave.
    #[test]
    fn the_stacks_reply_reaches_the_guest_through_recv() {
        let (mut handle, _held) = handle_with_open_flows(1);
        let mut buf = [0u8; MTU_V1 as usize];
        let n = handle
            .recv_from_network(&mut buf)
            .expect("the flow's stack answered the replayed SYN");
        let ip = smoltcp::wire::Ipv4Packet::new_checked(&buf[..n]).expect("ipv4");
        let seg = smoltcp::wire::TcpPacket::new_checked(ip.payload()).expect("tcp");
        assert!(
            seg.syn() && seg.ack(),
            "the guest is owed the SYN-ACK its deferred handshake earned"
        );
    }

    /// A packet for an established flow must reach that flow's stack, not
    /// the machine-wide device, which has no socket for it.
    #[test]
    fn guest_data_reaches_the_flow_that_owns_it() {
        let (mut handle, held) = handle_with_open_flows(1);
        let dst = held.local_addr().expect("local addr");
        let data = guest_segment(50_000, dst, TcpControl::None, b"hello");
        deliver(&mut handle, &data).expect("an established flow takes its guest's bytes");
        assert!(
            handle.flows.values().any(|f| f.bytes_buffered() > 0),
            "the flow's own device must hold what the guest sent"
        );
    }

    // ---- IPv6 --------------------------------------------------------

    fn v6_listener() -> TcpListener {
        TcpListener::bind("[::1]:0").expect("bind a v6 loopback listener")
    }

    /// A v6 flow, end to end: the guest's SYN opens a real host socket, the
    /// handshake completes over v6, and bytes cross in both directions.
    ///
    /// The datapath was never IPv4-only in shape — its emitters carry both
    /// families — but nothing addressed a host-originated packet in the
    /// flow's family until the session could hold a v6 address.
    #[test]
    fn a_v6_flow_is_carried_end_to_end_over_a_host_socket() {
        let held = v6_listener();
        let dst = held.local_addr().expect("local addr");
        assert!(dst.is_ipv6(), "the fixture destination must be IPv6");
        let mut handle = open_test_handle();

        let syn = guest_segment(50_000, dst, TcpControl::Syn, &[]);
        deliver(&mut handle, &syn).expect("a v6 SYN toward a live listener is accepted");
        assert!(
            drive_until(&mut handle, |h| h.flows.len() == 1),
            "the v6 loopback connect must resolve into a flow"
        );
        let (mut peer, _) = held.accept().expect("accept the flow's host socket");

        // The handshake is completed inline rather than through
        // `complete_handshake`, which discards the SYN-ACK: the addressing
        // of that packet is half of what this test is checking. It comes
        // back as IPv6, addressed to the leased v6 address and not the v4
        // one.
        let mut buf = [0u8; MTU_V1 as usize];
        let n = handle
            .recv_from_network(&mut buf)
            .expect("the flow's stack answers the replayed SYN");
        let reply = smoltcp::wire::Ipv6Packet::new_checked(&buf[..n]).expect("an IPv6 reply");
        assert_eq!(reply.dst_addr(), FIXTURE_GUEST_V6);
        assert_eq!(reply.src_addr(), Ipv6Addr::LOCALHOST);
        let ack = syn_ack_isn(&buf[..n], 50_000)
            .expect("the reply is the SYN-ACK for the guest's port")
            .wrapping_add(1);
        let handshake = GuestSegment {
            guest_port: 50_000,
            dst,
            control: TcpControl::None,
            seq: GUEST_ISN.wrapping_add(1),
            ack: Some(ack),
            payload: &[],
        }
        .emit();
        deliver(&mut handle, &handshake).expect("the guest's handshake ACK is accepted");
        handle.service(0).expect("service");
        let data = GuestSegment {
            guest_port: 50_000,
            dst,
            control: TcpControl::None,
            seq: GUEST_ISN + 1,
            ack: Some(ack),
            payload: b"over v6",
        }
        .emit();
        deliver(&mut handle, &data).expect("an established v6 flow takes its guest's bytes");
        assert!(
            drive_until(&mut handle, |h| h
                .flows
                .values()
                .all(|f| f.bytes_buffered() == 0)),
            "the guest's bytes must reach the host socket"
        );

        std::thread::sleep(LOOPBACK_SETTLE);
        peer.set_read_timeout(Some(Duration::from_secs(5)))
            .expect("read timeout");
        let mut got = [0u8; 7];
        peer.read_exact(&mut got).expect("the peer reads the bytes");
        assert_eq!(&got, b"over v6");

        peer.write_all(b"back").expect("the peer answers");
        std::thread::sleep(LOOPBACK_SETTLE);
        assert!(
            drive_until(&mut handle, |h| h
                .flows
                .values()
                .any(|f| f.pending_to_guest() > 0)),
            "the peer's answer must be queued for the guest"
        );
    }

    /// A session holding no v6 address can address nothing to its guest in
    /// that family, and says so rather than inventing a destination.
    #[test]
    fn a_session_without_a_v6_address_can_address_nothing_to_its_guest_in_v6() {
        let dual = GuestAddressing::new(request().guest, Some(FIXTURE_GUEST_V6));
        let v4_only = GuestAddressing::new(request().guest, None);
        let v6_remote = IpAddr::V6(Ipv6Addr::LOCALHOST);

        assert_eq!(dual.matching(v6_remote), Some(IpAddr::V6(FIXTURE_GUEST_V6)));
        assert_eq!(v4_only.matching(v6_remote), None);
        assert_eq!(
            v4_only.matching(LOOPBACK),
            Some(IpAddr::V4(request().guest))
        );
    }

    /// A v6 connect that never completes owes its guest a reset addressed in
    /// v6, for the reason the v4 one does: without it the guest waits out
    /// its own connect timeout with nothing to explain the silence.
    #[test]
    fn a_failed_v6_connect_resets_the_guest_over_v6() {
        let dead = {
            let l = v6_listener();
            let addr = l.local_addr().expect("local addr");
            drop(l);
            addr
        };
        let mut handle = open_test_handle();
        let syn = guest_segment(50_000, dead, TcpControl::Syn, &[]);
        // The connect may be refused synchronously; either way the reset is
        // owed and comes out of the read path.
        let _ = deliver(&mut handle, &syn);

        let mut buf = [0u8; MTU_V1 as usize];
        let mut reset = None;
        for pass in 0..SERVICE_ATTEMPTS {
            handle.service(pass as u64).expect("service");
            if let Ok(n) = handle.recv_from_network(&mut buf) {
                reset = Some(buf[..n].to_vec());
                break;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        let reset = reset.expect("a failed connect owes the guest a reset");
        let ip = smoltcp::wire::Ipv6Packet::new_checked(&reset[..]).expect("an IPv6 reset");
        assert_eq!(ip.dst_addr(), FIXTURE_GUEST_V6);
        let seg = smoltcp::wire::TcpPacket::new_checked(ip.payload()).expect("tcp");
        assert!(seg.rst(), "the guest is owed a reset, not a silence");
    }

    /// Half-open and established entries compete for one descriptor budget.
    /// Two independent bounds whose sum can exceed it would not be a bound.
    #[test]
    fn the_budget_counts_half_open_and_established_together() {
        let held = listener();
        let dst = held.local_addr().expect("local addr");
        let mut handle = open_test_handle();
        handle.budget = 2;

        for i in 0..2 {
            let syn = guest_segment(50_000 + i, dst, TcpControl::Syn, &[]);
            deliver(&mut handle, &syn).expect("inside the budget");
        }
        let third = guest_segment(50_002, dst, TcpControl::Syn, &[]);
        assert!(
            deliver(&mut handle, &third).is_err(),
            "the newcomer is refused at the budget, never by evicting a live entry"
        );
        assert_eq!(handle.open_socket_count(), 2);
        assert_eq!(handle.metrics().denies_for(DenyCode::FlowTableFull), 1);

        // And the two that were admitted are still the ones that survive
        // once they become established.
        assert!(drive_until(&mut handle, |h| h.flows.len() == 2));
        assert_eq!(handle.open_socket_count(), 2);
    }

    /// A connect that fails owes its guest a reset, and that reset has to
    /// come out of the read path — otherwise the guest waits on a SYN-ACK
    /// that is never coming, for as long as its own connect timeout.
    #[test]
    fn a_failed_connect_reaches_the_guest_as_a_reset() {
        let mut handle = open_test_handle();
        let syn = guest_segment(50_000, dead_destination(), TcpControl::Syn, &[]);
        deliver(&mut handle, &syn).expect("the SYN is taken; the connect is what fails");

        let mut buf = [0u8; MTU_V1 as usize];
        assert!(
            drive_until(&mut handle, |h| h.device.pending_to_guest() > 0),
            "a refused connect must produce the reset the guest is owed"
        );
        let n = handle.recv_from_network(&mut buf).expect("the reset");
        let ip = smoltcp::wire::Ipv4Packet::new_checked(&buf[..n]).expect("ipv4");
        let seg = smoltcp::wire::TcpPacket::new_checked(ip.payload()).expect("tcp");
        assert!(seg.rst(), "the guest must be told, not left to time out");
        assert_eq!(
            ip.dst_addr(),
            request().guest,
            "the reset is addressed from the lease, not from the guest's own SYN"
        );
        assert_eq!(handle.open_socket_count(), 0, "and the descriptor is gone");
    }

    /// A flow that has just been reset still owes the guest that reset.
    /// Reaping it on the pass that ended it would discard the one packet
    /// explaining why — putting the guest back at the silent hang the reset
    /// exists to prevent.
    #[test]
    fn a_reset_flow_is_not_reaped_before_the_guest_has_its_reset() {
        let (mut handle, _held) = handle_with_open_flows(1);
        let mut buf = [0u8; MTU_V1 as usize];
        // Drain the handshake, so the only thing left to read is the reset.
        // Bounded: a read path that never reports `WouldBlock` must fail an
        // assertion below rather than spin here.
        for _ in 0..SERVICE_ATTEMPTS {
            if handle.recv_from_network(&mut buf).is_err() {
                break;
            }
        }
        handle
            .flows
            .values_mut()
            .next()
            .expect("the fixture flow")
            .on_host_error(std::io::ErrorKind::ConnectionReset);

        handle.service(1).expect("service");

        let n = handle
            .recv_from_network(&mut buf)
            .expect("the reset must outlive the pass that produced it");
        let ip = smoltcp::wire::Ipv4Packet::new_checked(&buf[..n]).expect("ipv4");
        let seg = smoltcp::wire::TcpPacket::new_checked(ip.payload()).expect("tcp");
        assert!(seg.rst(), "the packet held back must be the reset itself");
    }

    /// **Scenario A at the handle.** The descriptor was never the whole
    /// cost: a flow entry holds ~176 KB of buffers and a slot in the socket
    /// budget. A guest that opens its budget in handshakes it never
    /// completes would take the datapath out of service permanently, and
    /// every one of those flows is in a state where no host error can ever
    /// arrive to end it.
    ///
    /// The fixture's flows are exactly that state: `handle_with_open_flows`
    /// replays each SYN but never answers the SYN-ACK.
    #[test]
    fn handshakes_the_guest_never_completes_do_not_pin_the_budget() {
        let (mut handle, _held) = handle_with_open_flows(3);
        assert_eq!(handle.open_socket_count(), 3);

        // Past the bound by the fixture's own drive window, since which
        // pass a loopback connect resolves on is the kernel's business.
        let past = HANDSHAKE_COMPLETION_TIMEOUT_MILLIS + SERVICE_ATTEMPTS as u64;
        handle.service(past).expect("past the handshake bound");

        let mut buf = [0u8; MTU_V1 as usize];
        assert!(
            drain_carries_a_reset(&mut handle, &mut buf),
            "each guest is told, not left waiting on a handshake nobody will finish"
        );
        handle.service(past + 1).expect("service");
        assert_eq!(
            handle.open_socket_count(),
            0,
            "the budget slots must come back, not just the descriptors"
        );
        assert!(handle.flows.is_empty());
    }

    /// **Scenario B at the handle.** Once the peer stops sending, the flow
    /// stops reading that socket, so the keepalive can never fire on it.
    #[test]
    fn a_half_closed_flow_the_guest_never_finishes_does_not_pin_the_budget() {
        let (mut handle, _dst, peer, _ack) = handle_with_an_established_conversation();
        peer.shutdown(std::net::Shutdown::Write)
            .expect("the peer closes its sending half");
        assert!(
            drive_until(&mut handle, |h| h
                .flows
                .values()
                .all(EstablishedFlow::peer_finished_sending)),
            "the fixture must reach the half-closed state it is testing"
        );
        assert_eq!(handle.open_socket_count(), 1);

        let past = HALF_CLOSED_TIMEOUT_MILLIS + SERVICE_ATTEMPTS as u64;
        handle.service(past).expect("past the half-closed bound");
        let mut buf = [0u8; MTU_V1 as usize];
        for _ in 0..SERVICE_ATTEMPTS {
            if handle.recv_from_network(&mut buf).is_err() {
                break;
            }
        }
        handle.service(past + 1).expect("service");
        assert_eq!(
            handle.open_socket_count(),
            0,
            "a half-closed flow the guest never finishes must not be permanent"
        );
        assert!(handle.flows.is_empty());
    }

    /// **The streaming case.** A Server-Sent Events stream between events,
    /// or a WebSocket between messages, is idle by design and may stay that
    /// way for hours. Reclaiming it would look to the guest like a
    /// connection that dropped for no reason, with nothing in any log to
    /// say why. Quietness is not a fault, and nothing here may treat it as
    /// one.
    #[test]
    fn a_quiet_flow_whose_peer_is_alive_is_never_reclaimed() {
        let (mut handle, _dst, _peer, _ack) = handle_with_an_established_conversation();
        // Well past any idle bound the rest of the system uses for a flow
        // *table* entry, whose cost is a row rather than a live socket.
        for step in 1..=4u64 {
            let now = step * DEFAULT_TCP_IDLE_MILLIS;
            handle.service(now).expect("service");
            assert_eq!(
                handle.flows.len(),
                1,
                "a quiet connection with a live peer was reclaimed at {now} ms"
            );
        }
        assert_eq!(handle.open_socket_count(), 1);
    }

    /// The fold that carries a flow's own report out to the driver. The
    /// pass spends its readiness before it reads a socket, so a flow that
    /// stopped at its bound has nothing left to announce the remainder —
    /// and the driver's only way to learn of it is this return value.
    #[test]
    fn a_flow_that_stopped_at_its_budget_makes_the_service_pass_say_so() {
        let (mut handle, _dst, mut peer, _ack) = handle_with_an_established_conversation();
        let body = vec![0x5Au8; max_bytes_per_pass() * 2];
        let writer = std::thread::spawn(move || {
            peer.write_all(&body).expect("the peer's whole answer");
            peer.flush().expect("flush");
            peer
        });
        let _peer = writer.join().expect("the peer's writer thread");
        // The fixture's precondition, asserted below rather than assumed: a
        // pass can only stop at the bound with more than the bound already
        // waiting. This guest acknowledges nothing, so the stack's send
        // buffer fills on the first pass and no later one could reach it.
        std::thread::sleep(LOOPBACK_SETTLE);

        let drain = handle.service(0).expect("service");

        assert!(
            handle.metrics().bytes_ingress >= max_bytes_per_pass() as u64,
            "the fixture must really have had a pass's worth waiting, or this \
             asserts nothing"
        );
        assert_eq!(
            drain,
            InboundDrain::Backlogged,
            "a flow whose pump stopped at its bound must reach the driver as a \
             backlog, or its tail waits out the tick"
        );
    }

    /// The budget slot, not just the descriptor. A flow holding an
    /// undelivered reset keeps roughly 176 KB of buffers and a place in
    /// `open_socket_count`; a guest that simply stops acknowledging must
    /// not be able to hold those for the machine's lifetime, which is what
    /// an unbounded deferral would allow — 256 times over, after which no
    /// connect for this machine could ever succeed again.
    #[test]
    fn a_guest_that_stops_acknowledging_does_not_pin_its_budget_slot() {
        let (mut handle, _dst, mut peer, _ack) = handle_with_an_established_conversation();
        let body = b"an-answer-the-guest-never-acknowledges";
        peer.write_all(body).expect("peer write");
        peer.flush().expect("flush");
        assert!(
            drive_until(&mut handle, |h| h.metrics().bytes_ingress > 0),
            "the peer's answer must reach the stack before its socket dies"
        );

        // The peer dies abortively; the fixture guest acknowledges nothing
        // from here on, which is the state under test.
        socket2::SockRef::from(&peer)
            .set_linger(Some(Duration::ZERO))
            .expect("an abortive close");
        drop(peer);
        assert!(
            drive_until(&mut handle, |h| h
                .flows
                .values()
                .all(EstablishedFlow::host_socket_closed)),
            "the dead peer's descriptor must come back straight away"
        );

        let mut buf = [0u8; MTU_V1 as usize];
        assert!(
            !drain_carries_a_reset(&mut handle, &mut buf),
            "while the deadline holds, the guest still gets its chance at the data"
        );
        assert_eq!(
            handle.open_socket_count(),
            1,
            "and the flow is held open for it"
        );

        handle
            .service(RESET_DELIVERY_TIMEOUT_MILLIS + 1)
            .expect("past the reset deadline");

        assert!(
            drain_carries_a_reset(&mut handle, &mut buf),
            "past the deadline the guest is reset rather than waited on"
        );
        handle
            .service(RESET_DELIVERY_TIMEOUT_MILLIS + 2)
            .expect("service");
        assert_eq!(
            handle.open_socket_count(),
            0,
            "and the budget slot comes back with it"
        );
        assert!(handle.flows.is_empty());
    }

    /// Drain everything waiting for the guest, reporting whether a reset
    /// was among it. Bounded: a read path that never reports `WouldBlock`
    /// fails its caller's assertion rather than spinning here.
    fn drain_carries_a_reset(handle: &mut UserspaceHandle, buf: &mut [u8]) -> bool {
        let mut saw_reset = false;
        for _ in 0..SERVICE_ATTEMPTS {
            let Ok(n) = handle.recv_from_network(buf) else {
                break;
            };
            let Ok(ip) = smoltcp::wire::Ipv4Packet::new_checked(&buf[..n]) else {
                continue;
            };
            if let Ok(seg) = smoltcp::wire::TcpPacket::new_checked(ip.payload()) {
                saw_reset |= seg.rst();
            }
        }
        saw_reset
    }

    /// And the resource hole that closes: a peer that goes away takes its
    /// descriptor with it, without the guest having to do anything.
    #[test]
    fn a_flow_whose_peer_is_gone_is_reclaimed() {
        let (mut handle, _dst, peer, _ack) = handle_with_an_established_conversation();
        assert_eq!(handle.open_socket_count(), 1);

        // An abortive close, which is what a peer that crashed or was
        // killed looks like on the wire. The graceful path is a FIN and is
        // covered by the half-close tests; this is the one that has to
        // surface as an error on the host socket.
        let sock = socket2::SockRef::from(&peer);
        sock.set_linger(Some(Duration::ZERO))
            .expect("an abortive close");
        drop(peer);

        assert!(
            drive_until(&mut handle, |h| h
                .flows
                .values()
                .all(EstablishedFlow::host_socket_closed)),
            "a flow whose peer is gone must give the descriptor back"
        );

        // The guest is told, and only once it has been told is the flow
        // reaped — the reset is the last thing this flow owes anyone.
        let mut buf = [0u8; MTU_V1 as usize];
        assert!(
            drain_carries_a_reset(&mut handle, &mut buf),
            "the guest must learn that its peer is gone"
        );

        handle.service(1).expect("service");
        assert!(handle.flows.is_empty());
        assert_eq!(handle.open_socket_count(), 0);
    }

    /// A datapath nobody can see the throughput of cannot be told from one
    /// carrying nothing at all — and this is also the end-to-end witness
    /// that the wiring works: a guest packet in at the trait method, the
    /// same bytes out of a host socket a real peer is reading.
    #[test]
    fn the_traffic_it_carries_crosses_the_host_socket_and_is_counted() {
        let (mut handle, dst, mut peer, ack) = handle_with_an_established_conversation();
        let accepted = handle.metrics().packets_egress;
        let ingress = handle.metrics().packets_ingress;
        assert!(accepted >= 1, "the SYN that opened the flow was counted");
        assert!(ingress >= 1, "the SYN-ACK handed back was counted");

        let body = b"payload-that-crosses";
        let data = GuestSegment {
            guest_port: 50_000,
            dst,
            control: TcpControl::None,
            seq: GUEST_ISN.wrapping_add(1),
            ack: Some(ack),
            payload: body,
        }
        .emit();
        deliver(&mut handle, &data).expect("an established flow takes its guest's bytes");
        assert_eq!(handle.metrics().packets_egress, accepted + 1);

        handle.service(1).expect("service");

        assert_eq!(
            handle.metrics().bytes_egress,
            body.len() as u64,
            "the bytes a pass moved onto the host socket must be counted, not discarded"
        );
        peer.set_read_timeout(Some(Duration::from_secs(5)))
            .expect("a bounded read");
        let mut got = vec![0u8; body.len()];
        peer.read_exact(&mut got)
            .expect("the peer reads what the guest sent");
        assert_eq!(
            got.as_slice(),
            body,
            "and the bytes counted must be the bytes that crossed"
        );
    }

    /// The other direction, at the same seam.
    #[test]
    fn bytes_arriving_from_the_peer_are_counted_too() {
        let (mut handle, _dst, mut peer, _ack) = handle_with_an_established_conversation();
        peer.write_all(b"a-response").expect("peer write");
        peer.flush().expect("flush");
        assert!(
            drive_until(&mut handle, |h| h.metrics().bytes_ingress > 0),
            "bytes read off a host socket must reach the counters"
        );
        assert_eq!(handle.metrics().bytes_ingress, b"a-response".len() as u64);
    }

    /// A loopback UDP echo server, bounded in datagram count and read
    /// timeout so its thread cannot outlive the test that started it.
    fn udp_echo_server() -> SocketAddr {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind an echo server");
        let addr = socket.local_addr().expect("local addr");
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("a bounded read");
        std::thread::spawn(move || {
            let mut buf = [0u8; 2048];
            for _ in 0..16 {
                let Ok((n, from)) = socket.recv_from(&mut buf) else {
                    return;
                };
                if socket.send_to(&buf[..n], from).is_err() {
                    return;
                }
            }
        });
        addr
    }

    /// The end-to-end datagram witness at the trait seam: a guest datagram
    /// in, the same bytes out of a host socket a real peer answered, and
    /// the answer back through the datapath's own read path.
    #[test]
    fn a_guest_datagram_crosses_a_host_socket_and_the_reply_reaches_the_guest() {
        let echo = udp_echo_server();
        let mut handle = open_test_handle();
        let datagram = udp_segment(50_000, echo, b"ping");
        deliver(&mut handle, &datagram).expect("a datagram toward a live peer is carried");
        assert_eq!(
            handle.open_socket_count(),
            1,
            "an association parks a descriptor drawn from the same budget TCP uses"
        );

        assert!(
            drive_until(&mut handle, |h| h.device.pending_to_guest() > 0),
            "the peer's answer must reach the guest-bound queue"
        );
        let mut buf = [0u8; MTU_V1 as usize];
        let n = handle.recv_from_network(&mut buf).expect("the reply");
        let meta = ip::parse(&buf[..n]).expect("the reply parses");
        assert_eq!(meta.protocol, proto::UDP);
        assert_eq!(
            meta.src,
            echo.ip(),
            "addressed from the destination policy admitted"
        );
        assert_eq!(
            meta.dst,
            IpAddr::V4(request().guest),
            "and to the address the session leased, not to anything the guest wrote"
        );
        assert_eq!(meta.dst_port, Some(50_000));
        assert_eq!(
            ip::udp_payload(&buf[..n], &meta),
            Some(&b"ping"[..]),
            "and it carries what the peer sent"
        );
    }

    /// Associations age out on their own deadline, and the descriptor and
    /// the budget slot come back with them.
    #[test]
    fn an_association_the_guest_stops_using_does_not_pin_the_budget() {
        let echo = udp_echo_server();
        let mut handle = open_test_handle();
        deliver(&mut handle, &udp_segment(50_000, echo, b"ping")).expect("carried");
        assert_eq!(handle.open_socket_count(), 1);

        handle
            .service(ASSOCIATION_LIFETIME_MILLIS)
            .expect("past the association's deadline");
        assert_eq!(
            handle.open_socket_count(),
            0,
            "an association must not outlive the lifetime it was given"
        );
        assert_eq!(handle.metrics().flows_expired, 1);
    }

    /// Datagram associations compete with flows for one descriptor budget.
    #[test]
    fn associations_and_flows_share_one_socket_budget() {
        let echo = udp_echo_server();
        let mut handle = open_test_handle();
        handle.budget = 1;
        deliver(&mut handle, &udp_segment(50_000, echo, b"x")).expect("inside the budget");

        let held = listener();
        let syn = guest_segment(
            50_001,
            held.local_addr().expect("addr"),
            TcpControl::Syn,
            &[],
        );
        assert!(
            deliver(&mut handle, &syn).is_err(),
            "a connect must not be able to overdraw the budget an association is holding"
        );
        assert_eq!(handle.metrics().denies_for(DenyCode::FlowTableFull), 1);
        assert_eq!(handle.open_socket_count(), 1);
    }

    /// At capacity the newcomer is refused where the caller can see it.
    /// UDP gives the guest no reset to read, so an error at the seam is the
    /// only signal there is.
    #[test]
    fn a_datagram_past_the_budget_is_refused_rather_than_evicting_one() {
        let echo = udp_echo_server();
        let mut handle = open_test_handle();
        handle.budget = 1;
        deliver(&mut handle, &udp_segment(50_000, echo, b"x")).expect("inside the budget");
        assert!(deliver(&mut handle, &udp_segment(50_001, echo, b"x")).is_err());
        assert_eq!(handle.metrics().denies_for(DenyCode::FlowTableFull), 1);
        assert_eq!(handle.open_socket_count(), 1);
        assert!(
            handle.udp.holds(&udp_segment(50_000, echo, b"x").0),
            "the association that was already open is the one that survives"
        );
    }

    /// An association parks a descriptor exactly as a flow does, so a close
    /// that only cleared the flow tables would leak one per machine.
    #[test]
    fn close_releases_datagram_associations_too() {
        let echo = udp_echo_server();
        let mut handle = open_test_handle();
        for i in 0..4 {
            deliver(&mut handle, &udp_segment(50_000 + i, echo, b"x")).expect("carried");
        }
        assert_eq!(handle.open_socket_count(), 4);
        handle.close().expect("close");
        assert_eq!(handle.open_socket_count(), 0);
    }

    #[test]
    fn a_closed_handle_opens_no_association() {
        let echo = udp_echo_server();
        let mut handle = open_test_handle();
        handle.close().expect("close");
        assert!(deliver(&mut handle, &udp_segment(50_000, echo, b"x")).is_err());
        assert_eq!(handle.open_socket_count(), 0);
    }

    /// A transport with no socket translation is still refused where the
    /// caller can see it — the property the UDP arm used to carry, now
    /// witnessed by a protocol that really has no translation.
    #[test]
    fn a_transport_without_a_translation_is_refused_rather_than_dropped() {
        let mut handle = open_test_handle();
        let bytes = v4_packet(
            proto::ICMP,
            request().guest,
            v4_of(dead_destination()),
            &[8, 0, 0, 0],
        );
        let meta = ip::parse(&bytes).expect("the fixture packet parses");
        let key = FlowKey {
            protocol: proto::ICMP,
            guest_port: 0,
            remote: meta.dst,
            remote_port: 0,
        };
        let err = handle
            .forward(key, &meta, &bytes)
            .expect_err("ICMP has no socket translation");
        assert!(matches!(err, DatapathError::Unsupported { .. }));
        assert_eq!(handle.metrics().denies_for(DenyCode::ProtocolDenied), 1);
        assert_eq!(handle.open_socket_count(), 0);
    }

    /// The capability advertisement is a promise admission enforces. A
    /// backend that claims `udp` and refuses datagrams would have a plan
    /// admitted against a datapath that cannot serve it.
    #[test]
    fn advertising_udp_means_a_datagram_is_actually_carried() {
        // Compile-time: withdrawing the advertisement has to break the
        // build here, so the promise and the datagram below cannot drift
        // apart silently.
        const { assert!(ForwardingCapabilities::USERSPACE_SOCKETS.udp) };
        let echo = udp_echo_server();
        let mut handle = open_test_handle();
        deliver(&mut handle, &udp_segment(50_000, echo, b"x"))
            .expect("the advertised capability has to be true of the datapath behind it");
    }

    // ---- declared inbound datagram mappings -------------------------

    /// A host port nothing is bound to, for a mapping to declare. Probed
    /// rather than fixed, for the reason the `ingress` module's own fixture
    /// gives: a hard-coded port collides with whatever else this
    /// process-parallel suite is running.
    fn free_host_port() -> u16 {
        std::net::UdpSocket::bind("127.0.0.1:0")
            .expect("probe a free port")
            .local_addr()
            .expect("local addr")
            .port()
    }

    fn handle_serving(mappings: Vec<IngressMapping>) -> UserspaceHandle {
        let mut req = request();
        req.ingress = mappings;
        UserspaceSocketDatapath::new()
            .open_handle(&req)
            .expect("opening a userspace handle needs no privileges")
    }

    /// A peer that will talk to a declared mapping, with a bounded read so
    /// an answer that never comes fails an assertion rather than hanging.
    fn ingress_peer() -> std::net::UdpSocket {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind a peer");
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("a bounded read");
        socket
    }

    /// The end-to-end ingress witness at the handle: a peer's datagram in
    /// on a declared listener, the same bytes out of the read path,
    /// addressed to the guest port the *declaration* named.
    #[test]
    fn a_declared_mapping_puts_a_peers_datagram_in_front_of_the_guest() {
        let host_port = free_host_port();
        let mut handle = handle_serving(vec![IngressMapping::udp(LOOPBACK, host_port, 5140)]);
        assert_eq!(
            handle.open_socket_count(),
            1,
            "a listener parks a descriptor from the same budget TCP uses"
        );

        let peer = ingress_peer();
        peer.send_to(b"probe", (Ipv4Addr::LOCALHOST, host_port))
            .expect("a peer datagram toward the declared mapping");
        assert!(
            drive_until(&mut handle, |h| h.device.pending_to_guest() > 0),
            "the declared mapping must put the datagram in front of the guest"
        );

        let mut buf = [0u8; MTU_V1 as usize];
        let n = handle.recv_from_network(&mut buf).expect("the datagram");
        let meta = ip::parse(&buf[..n]).expect("the packet parses");
        assert_eq!(meta.protocol, proto::UDP);
        assert_eq!(
            meta.dst,
            IpAddr::V4(request().guest),
            "addressed to the address the session leased"
        );
        assert_eq!(
            meta.dst_port,
            Some(5140),
            "and to the guest port the declaration named, not the host port"
        );
        assert_eq!(meta.src, LOOPBACK);
        assert_eq!(meta.src_port, Some(peer.local_addr().expect("addr").port()));
        assert_eq!(ip::udp_payload(&buf[..n], &meta), Some(&b"probe"[..]));
    }

    /// The guest's answer must reach the peer from the address it dialled,
    /// and must not cost a second descriptor: an answer sent from a fresh
    /// association's ephemeral port is a different 4-tuple, which the peer
    /// discards as belonging to no conversation of its own.
    #[test]
    fn an_ingress_answer_leaves_by_the_listener_rather_than_a_new_socket() {
        let host_port = free_host_port();
        let mut handle = handle_serving(vec![IngressMapping::udp(LOOPBACK, host_port, 5140)]);
        let peer = ingress_peer();
        let peer_addr = peer.local_addr().expect("addr");
        peer.send_to(b"probe", (Ipv4Addr::LOCALHOST, host_port))
            .expect("send");
        assert!(
            drive_until(&mut handle, |h| h.device.pending_to_guest() > 0),
            "the peer's datagram must arrive, or the answer proves nothing"
        );

        let before = handle.open_socket_count();
        deliver(&mut handle, &udp_segment(5140, peer_addr, b"answer"))
            .expect("the guest's answer to a declared conversation");
        assert_eq!(
            handle.open_socket_count(),
            before,
            "answering on the listener must not open an association as well"
        );

        let mut buf = [0u8; 64];
        let (n, from) = peer.recv_from(&mut buf).expect("the guest's answer");
        assert_eq!(&buf[..n], b"answer");
        assert_eq!(
            from,
            SocketAddr::new(LOOPBACK, host_port),
            "the answer must come from the address the peer dialled"
        );
    }

    /// A guest datagram toward somewhere the mapping never heard from is
    /// not the listener's to send. It takes the ordinary outbound path,
    /// whose socket is connected to the admitted destination.
    #[test]
    fn a_guest_datagram_for_an_unheard_destination_opens_an_association_instead() {
        let host_port = free_host_port();
        let mut handle = handle_serving(vec![IngressMapping::udp(LOOPBACK, host_port, 5140)]);
        assert_eq!(handle.open_socket_count(), 1);

        let echo = udp_echo_server();
        deliver(&mut handle, &udp_segment(5140, echo, b"x")).expect("carried");
        assert_eq!(
            handle.open_socket_count(),
            2,
            "the listener, plus the association the outbound path opened"
        );
    }

    /// A listener parks a descriptor exactly as an association does, so a
    /// close that only cleared the other tables would leak one per machine.
    #[test]
    fn close_releases_ingress_listeners_too() {
        let mut handle = handle_serving(vec![
            IngressMapping::udp(LOOPBACK, free_host_port(), 5140),
            IngressMapping::udp(LOOPBACK, free_host_port(), 5141),
        ]);
        assert_eq!(handle.open_socket_count(), 2);
        handle.close().expect("close");
        assert_eq!(handle.open_socket_count(), 0);
    }

    /// The capability advertisement is a promise admission enforces. A
    /// backend that claims `declared_ingress` and binds nothing would have
    /// a plan admitted against a datapath that cannot serve it — which is
    /// exactly what this backend used to do.
    #[test]
    fn advertising_declared_ingress_means_a_datagram_mapping_is_actually_bound() {
        // Compile-time: withdrawing the advertisement has to break the
        // build here, so the promise and the listener below cannot drift
        // apart silently.
        const { assert!(ForwardingCapabilities::USERSPACE_SOCKETS.declared_ingress) };
        let host_port = free_host_port();
        let handle = handle_serving(vec![IngressMapping::udp(LOOPBACK, host_port, 5140)]);
        assert_eq!(
            handle.open_socket_count(),
            1,
            "the advertised capability has to be true of the datapath behind it"
        );
    }

    /// **The part of the advertisement that is still not true.** A declared
    /// TCP mapping needs a listener whose accepted connections are
    /// originated *toward* the guest, and this datapath does not build one.
    /// It is skipped rather than refused, so a plan carrying one still runs
    /// its outbound traffic — and it opens no socket, so nothing here can
    /// be mistaken for serving it.
    #[test]
    fn a_declared_tcp_mapping_binds_nothing_here_and_does_not_stop_the_machine() {
        let handle = handle_serving(vec![IngressMapping::tcp(LOOPBACK, free_host_port(), 80)]);
        assert_eq!(
            handle.open_socket_count(),
            0,
            "stream ingress is not served by this backend"
        );
    }

    /// A segment for a connection the datapath has no state for — most
    /// often a guest's last ACK arriving after its flow was reaped — is
    /// routine, and must neither open a host socket nor be reported as an
    /// error. It is still counted.
    #[test]
    fn a_segment_for_no_flow_opens_nothing_and_is_counted() {
        let mut handle = open_test_handle();
        let stray = guest_segment(50_000, dead_destination(), TcpControl::None, b"stray");
        deliver(&mut handle, &stray).expect("a stray segment is not an error");
        assert_eq!(handle.open_socket_count(), 0);
        assert_eq!(handle.metrics().segments_without_flow, 1);
    }

    /// A retransmitted SYN must not cost a second descriptor, whether the
    /// first one is still connecting or has already become a flow.
    #[test]
    fn a_retransmitted_syn_costs_no_second_socket() {
        let held = listener();
        let dst = held.local_addr().expect("local addr");
        let mut handle = open_test_handle();
        let syn = guest_segment(50_000, dst, TcpControl::Syn, &[]);

        deliver(&mut handle, &syn).expect("first SYN");
        deliver(&mut handle, &syn).expect("a retransmit folds into the entry");
        assert_eq!(handle.open_socket_count(), 1);

        assert!(drive_until(&mut handle, |h| h.flows.len() == 1));
        deliver(&mut handle, &syn).expect("and a retransmit after establishment");
        assert_eq!(
            handle.open_socket_count(),
            1,
            "a SYN for an established flow belongs to that flow, not to a new connect"
        );
    }

    /// Per-flow cost here is a descriptor, so a close that leaked one would
    /// accumulate across machine restarts until the process could not open
    /// its own audit log.
    #[test]
    fn close_shuts_every_host_socket_and_is_idempotent() {
        let (mut handle, _held) = handle_with_open_flows(8);
        assert_eq!(handle.open_socket_count(), 8);
        handle.close().expect("close");
        assert_eq!(handle.open_socket_count(), 0);
        handle.close().expect("close must be safe to call twice");
        assert_eq!(handle.open_socket_count(), 0);
    }

    /// The failed-startup path: nothing was ever populated, and close must
    /// not care.
    #[test]
    fn close_on_a_handle_that_never_opened_a_socket_is_a_no_op() {
        let mut handle = open_test_handle();
        assert_eq!(handle.open_socket_count(), 0);
        handle.close().expect("close");
        handle.close().expect("close again");
        assert_eq!(handle.open_socket_count(), 0);
    }

    /// Half-open entries hold descriptors too, and a close that only
    /// cleared the established table would leak every connect in flight.
    #[test]
    fn close_releases_connects_that_are_still_in_flight() {
        let held = listener();
        let dst = held.local_addr().expect("local addr");
        let mut handle = open_test_handle();
        for i in 0..4 {
            let syn = guest_segment(50_000 + i, dst, TcpControl::Syn, &[]);
            deliver(&mut handle, &syn).expect("SYN");
        }
        assert_eq!(handle.open_socket_count(), 4);
        handle.close().expect("close");
        assert_eq!(handle.open_socket_count(), 0);
    }

    /// A closed handle must not keep taking guest packets, or a machine
    /// that has been torn down goes on opening host sockets.
    #[test]
    fn a_closed_handle_refuses_to_open_new_flows() {
        let held = listener();
        let dst = held.local_addr().expect("local addr");
        let mut handle = open_test_handle();
        handle.close().expect("close");
        let syn = guest_segment(50_000, dst, TcpControl::Syn, &[]);
        assert!(deliver(&mut handle, &syn).is_err());
        assert_eq!(handle.open_socket_count(), 0);
    }
}
