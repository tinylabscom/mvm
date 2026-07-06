//! The dedicated host-I/O thread for the hvf VMM's virtio-vsock device.
//!
//! Host→guest vsock delivery used to run only from the vCPU run loop's
//! `poll()` — serviced on `VTimer`/`Canceled` exits. On HVF a busy guest produces
//! a torrent of `Mmio` exits and almost no timer/cancel exits, so `poll()` (and
//! thus accepting the host agent connection + delivering rx packets) was starved
//! to a handful of calls over tens of seconds — the host could never reach the
//! guest agent.
//!
//! This module moves that servicing onto its own OS thread driven by a
//! `mio::Poll` (kqueue/epoll) event loop, so it runs on wall-clock time regardless
//! of what the guest's vCPU is doing. The thread:
//!
//! - registers the agent Unix listener for readiness (so a host connection is
//!   accepted promptly) plus a `Waker` (for a prompt stop),
//! - wakes on that readiness, on the waker, or on a short backstop timeout, and on
//!   each wake takes the device lock and runs [`VsockShared::service_host_io`]
//!   (accept + drain the agent/egress sockets, frame rx packets into the guest's
//!   rx queue),
//! - raises the device IRQ via the injected [`IrqLine`] when it delivered — which
//!   also wakes a guest blocked in WFI to consume the packet — **independent of
//!   any vCPU exit**.
//!
//! Guest RAM and the virtqueues are only ever touched under the device lock, and
//! the thread is joined (via [`IoHandle::stop`]) before the guest RAM is freed, so
//! it never races the vCPU thread or dereferences unmapped memory.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use mio::unix::SourceFd;
use mio::{Events, Interest, Poll, Token, Waker};

use super::vsock::{IrqLine, VsockShared};

/// The agent listener readiness source.
const LISTENER: Token = Token(0);
/// The waker used to break the poll for a prompt stop.
const WAKER: Token = Token(1);
/// Backstop poll timeout. The listener wakes us on a new connection; this bounds
/// the latency of draining already-open agent/egress sockets (whose per-fd
/// readiness we deliberately don't register — see the module note on fd lifetime)
/// so a guest→host reply or egress response is delivered within a few ms even
/// with no new connection event.
const BACKSTOP: Duration = Duration::from_millis(5);

/// Handle to a running host-I/O thread. Dropping it (or calling [`Self::stop`])
/// stops and joins the thread.
pub(super) struct IoHandle {
    stop: Arc<AtomicBool>,
    waker: Arc<Waker>,
    join: Option<JoinHandle<()>>,
}

impl IoHandle {
    /// Signal the thread to stop and join it. Blocks until the thread has exited,
    /// guaranteeing it no longer touches the shared state / guest RAM.
    pub(super) fn stop(mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let _ = self.waker.wake();
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

impl Drop for IoHandle {
    fn drop(&mut self) {
        // If stopped via `stop()` the join already happened; otherwise ensure the
        // thread is torn down here too.
        self.stop.store(true, Ordering::Relaxed);
        let _ = self.waker.wake();
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

/// Spawn the host-I/O thread for `shared`, raising `spi` via `irq` on delivery.
pub(super) fn spawn(shared: Arc<Mutex<VsockShared>>, irq: Arc<dyn IrqLine>, spi: u32) -> IoHandle {
    let poll = Poll::new().expect("mvm-vsock-io: mio::Poll");
    let waker = Arc::new(Waker::new(poll.registry(), WAKER).expect("mvm-vsock-io: mio::Waker"));
    // Register the agent listener for readiness so a host connection is accepted
    // promptly. The fd lives inside the lock for the whole run, so it stays valid
    // while registered (the thread is joined before the device drops). Egress has
    // no listener; without an agent socket bound we run purely on the backstop.
    if let Some(fd) = shared
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .agent_listener_fd()
    {
        let mut src = SourceFd(&fd);
        let _ = poll
            .registry()
            .register(&mut src, LISTENER, Interest::READABLE);
    }
    let stop = Arc::new(AtomicBool::new(false));
    let stop_t = Arc::clone(&stop);
    let join = std::thread::Builder::new()
        .name("mvm-vsock-io".into())
        .spawn(move || io_loop(poll, shared, irq, spi, stop_t))
        .expect("mvm-vsock-io: spawn");
    IoHandle {
        stop,
        waker,
        join: Some(join),
    }
}

/// The event loop: wake on listener readiness / waker / backstop, service host
/// I/O under the lock, and raise the IRQ on delivery.
fn io_loop(
    mut poll: Poll,
    shared: Arc<Mutex<VsockShared>>,
    irq: Arc<dyn IrqLine>,
    spi: u32,
    stop: Arc<AtomicBool>,
) {
    let mut events = Events::with_capacity(16);
    while !stop.load(Ordering::Relaxed) {
        // A backstop timeout bounds latency for already-open sockets; a new host
        // connection or the stop-waker breaks the wait sooner. `EINTR` surfaces as
        // `Err` — just loop and re-check `stop`.
        let _ = poll.poll(&mut events, Some(BACKSTOP));
        if stop.load(Ordering::Relaxed) {
            break;
        }
        // On any wake (listener readable, waker, or backstop) do one servicing
        // pass. `accept_new` drains the listener to `WouldBlock`, so its readiness
        // clears and we don't spin.
        let delivered = shared
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .service_host_io();
        if delivered {
            irq.signal(spi);
        }
    }
}
