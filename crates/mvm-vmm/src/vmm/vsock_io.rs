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
//! - registers the current bridge listeners/streams plus a `Waker` (for prompt
//!   stop and topology-change resync),
//! - wakes on readiness or the waker, then takes the device lock and runs
//!   [`VsockShared::service_host_io`] (accept + drain the agent/console/egress/
//!   broker sockets, frame rx packets into the guest's rx queue),
//! - raises the device IRQ via the injected [`IrqLine`] when it delivered — which
//!   also wakes a guest blocked in WFI to consume the packet — **independent of
//!   any vCPU exit**.
//!
//! Guest RAM and the virtqueues are only ever touched under the device lock, and
//! the thread is joined (via [`IoHandle::stop`]) before the guest RAM is freed, so
//! it never races the vCPU thread or dereferences unmapped memory.

use std::collections::HashSet;
use std::os::fd::RawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use mio::unix::SourceFd;
use mio::{Events, Interest, Poll, Token, Waker};

use super::vsock::{IrqLine, VsockShared};

/// The waker used to break the poll for a prompt stop or a readiness-set resync.
const WAKER: Token = Token(0);

/// Handle to a running host-I/O thread. Dropping it (or calling [`Self::stop`])
/// stops and joins the thread.
pub(super) struct IoHandle {
    stop: Arc<AtomicBool>,
    waker: Arc<Waker>,
    join: Option<JoinHandle<()>>,
}

impl IoHandle {
    pub(super) fn wake(&self) {
        let _ = self.waker.wake();
    }

    /// Signal the thread to stop and join it. Blocks until the thread has exited,
    /// guaranteeing it no longer touches the shared state / guest RAM.
    pub(super) fn stop(mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.wake();
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
        self.wake();
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

/// Spawn the host-I/O thread for `shared`, raising `spi` via `irq` on delivery.
pub(super) fn spawn(shared: Arc<Mutex<VsockShared>>, irq: Arc<dyn IrqLine>, spi: u32) -> IoHandle {
    let poll = Poll::new().expect("mvm-vsock-io: mio::Poll");
    let waker = Arc::new(Waker::new(poll.registry(), WAKER).expect("mvm-vsock-io: mio::Waker"));
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

/// The event loop: keep the registered fd set aligned with the bridge topology,
/// then block on readiness / the resync waker, service host I/O under the lock,
/// and raise the IRQ on delivery.
fn io_loop(
    mut poll: Poll,
    shared: Arc<Mutex<VsockShared>>,
    irq: Arc<dyn IrqLine>,
    spi: u32,
    stop: Arc<AtomicBool>,
) {
    let mut events = Events::with_capacity(16);
    let mut registered = HashSet::new();
    while !stop.load(Ordering::Relaxed) {
        let current = shared
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .poll_fds()
            .into_iter()
            .collect::<HashSet<_>>();
        sync_ready_fds(&poll, &mut registered, &current);
        // `EINTR` surfaces as `Err` — just loop and re-check `stop`.
        let _ = poll.poll(&mut events, None);
        if stop.load(Ordering::Relaxed) {
            break;
        }
        let delivered = shared
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .service_host_io();
        if delivered {
            irq.signal(spi);
        }
    }
}

fn sync_ready_fds(poll: &Poll, registered: &mut HashSet<RawFd>, current: &HashSet<RawFd>) {
    let removed: Vec<_> = registered.difference(current).copied().collect();
    for fd in removed {
        let mut src = SourceFd(&fd);
        let _ = poll.registry().deregister(&mut src);
        registered.remove(&fd);
    }

    let added: Vec<_> = current.difference(registered).copied().collect();
    for fd in added {
        let mut src = SourceFd(&fd);
        if poll
            .registry()
            .register(&mut src, fd_token(fd), Interest::READABLE)
            .is_ok()
        {
            registered.insert(fd);
        }
    }
}

fn fd_token(fd: RawFd) -> Token {
    Token(fd as usize + 1)
}
