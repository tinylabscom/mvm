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
pub mod limits;

use std::os::fd::{AsRawFd, RawFd};

use mio::Poll;
use mvm_net::l3::AdmittedPacket;
use mvm_net::l3::config::DEFAULT_QUEUE_DEPTH;
use mvm_protocol::l3::limits::MTU_V1;
use smoltcp::iface::{Config, Interface, SocketSet, SocketStorage};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr};

use self::device::{GuestDevice, PushOutcome};
use self::limits::{DEFAULT_MAX_HOST_SOCKETS, FD_RESERVE};
use super::datapath::{
    DatapathError, DatapathHandle, DatapathRequest, ForwardingCapabilities, L3Datapath,
};

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
/// is its entire reason for existing: [`super::MacosUserspaceGateway`] is
/// the capability declaration this type makes real.
#[derive(Debug, Default)]
pub struct UserspaceSocketDatapath;

impl UserspaceSocketDatapath {
    pub fn new() -> Self {
        Self
    }

    /// Build the concrete handle.
    ///
    /// Kept separate from [`L3Datapath::open`], which just boxes this, so
    /// tests can reach handle-only methods (`service`,
    /// `open_socket_count`) without downcasting a trait object.
    fn open_handle(&self, req: &DatapathRequest) -> Result<UserspaceHandle, DatapathError> {
        let lim = read_and_raise_nofile_limit();
        // `libc::rlim_t` is `u64` on every target this crate builds for, so
        // this is a direct pass-through rather than a conversion.
        let budget = socket_budget(lim.rlim_cur, lim.rlim_max);

        let poll = Poll::new().map_err(|source| DatapathError::SetupFailed {
            what: "userspace datapath poll set",
            machine_id: req.machine_id.clone(),
            source,
        })?;

        let mut device = GuestDevice::new(req.mtu as usize, DEFAULT_QUEUE_DEPTH);
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
        });

        // No sockets exist yet — nothing opens a host socket per flow until
        // a later task wires that up — so the set's backing storage is
        // genuinely empty rather than pre-sized and unused. Without
        // smoltcp's `alloc` feature (deliberately not enabled — see the
        // crate-level note on this workspace's smoltcp feature set) an
        // owned `SocketSet` needs borrowed storage; a `'static` empty
        // slice costs nothing to hold and there is nothing yet to put in
        // it.
        let storage: &'static mut [SocketStorage<'static>] = &mut [];
        let sockets = SocketSet::new(storage);

        Ok(UserspaceHandle {
            machine_id: req.machine_id.clone(),
            poll: Some(poll),
            device,
            interface,
            sockets,
            budget,
            open_sockets: 0,
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
    /// Backs [`DatapathHandle::readiness_fd`]. `Option` because `close`
    /// must drop it: the readiness contract promises that closing releases
    /// the descriptor number for reuse, and a `Poll` still alive inside a
    /// handle that merely says it is closed would keep holding it.
    ///
    /// Nothing is registered on it yet — a later task registers each host
    /// socket here as it opens — so today it never reports readiness. The
    /// outer driver still services this handle on its timer tick
    /// regardless of readiness (see `netd/mod.rs`'s pump loop, which does
    /// not gate the datapath call on a datapath event).
    poll: Option<Poll>,
    device: GuestDevice,
    interface: Interface,
    sockets: SocketSet<'static>,
    /// Ceiling on concurrent host sockets, computed once at open time from
    /// the process's actual descriptor budget.
    budget: usize,
    open_sockets: usize,
    closed: bool,
}

impl UserspaceHandle {
    /// Host sockets currently open for this machine. Always zero until a
    /// later task starts opening one per admitted flow.
    pub(crate) fn open_socket_count(&self) -> usize {
        self.open_sockets
    }

    /// Drive the datapath: poll smoltcp, resolve completed connects, pump
    /// established flows, expire timed-out state.
    ///
    /// No flows exist yet, so today this is exactly the smoltcp poll and
    /// nothing else — correct, not a placeholder. An interface with an
    /// empty socket set legitimately has no ingress or egress work beyond
    /// that poll; later tasks add work here as they add state to expire
    /// and connects to resolve.
    pub fn service(&mut self, now_millis: u64) -> Result<(), DatapathError> {
        if self.closed {
            return Err(DatapathError::Io(std::io::Error::from(
                std::io::ErrorKind::BrokenPipe,
            )));
        }
        let now = SmolInstant::from_millis(now_millis as i64);
        self.interface
            .poll(now, &mut self.device, &mut self.sockets);
        Ok(())
    }
}

impl DatapathHandle for UserspaceHandle {
    fn send_to_network(&mut self, packet: &AdmittedPacket<'_>) -> Result<(), DatapathError> {
        if self.closed {
            return Err(DatapathError::Io(std::io::Error::from(
                std::io::ErrorKind::BrokenPipe,
            )));
        }
        accept_packet_size(packet.bytes().len())?;
        match self.device.push_from_guest(packet.bytes()) {
            PushOutcome::Queued => Ok(()),
            // The guest-to-stack queue is full. This is congestion, not a
            // hard failure — the same condition a nonblocking write hitting
            // a full socket buffer reports — so it is surfaced the same
            // way a caller already knows how to interpret.
            PushOutcome::DroppedQueueFull => Err(DatapathError::Io(std::io::Error::from(
                std::io::ErrorKind::WouldBlock,
            ))),
        }
    }

    fn recv_from_network(&mut self, buf: &mut [u8]) -> Result<usize, DatapathError> {
        if self.closed {
            return Err(DatapathError::Io(std::io::Error::from(
                std::io::ErrorKind::BrokenPipe,
            )));
        }
        match self.device.pop_for_guest() {
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
        // Drop now, not whenever the handle itself happens to drop: the
        // readiness contract promises that closing frees the descriptor
        // number for the next `open` anywhere in the process to reuse.
        self.poll = None;
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
        self.poll.as_ref().map(Poll::as_raw_fd)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> DatapathRequest {
        DatapathRequest {
            machine_id: "vm-a".into(),
            gateway: std::net::Ipv4Addr::new(10, 201, 0, 5),
            guest: std::net::Ipv4Addr::new(10, 201, 0, 6),
            prefix_len: 30,
            mtu: MTU_V1,
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

    #[test]
    fn opening_a_handle_exposes_a_readiness_descriptor() {
        let handle = open_test_handle();
        assert!(
            handle.readiness_fd().is_some(),
            "the handle owns a poll set even before any socket is registered on it"
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
}
