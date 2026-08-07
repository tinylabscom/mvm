//! What the drive loop waits on, and the registration that keeps it honest.
//!
//! This datapath translates each admitted flow into a host socket, so the
//! events that matter to it — a connect the kernel has decided, a peer that
//! sent — arrive on descriptors nothing outside this module tree knows
//! about. The loop cannot wait on them individually, so they are gathered
//! onto one poll set and the loop waits on *that* descriptor.
//!
//! # Why registration has to be an ownership fact
//!
//! Sockets come and go with flows, and most of them go by being dropped:
//! out of a `retain`, out of a `clear`, out of a table entry replaced. A
//! descriptor that closes while the set still names it frees its *number*
//! for the next `open` anywhere in this process, and readiness reported for
//! that number would then be attributed to a resource nothing here opened.
//! Deregistering at each of the dozen places a socket can go would work
//! until somebody adds the thirteenth.
//!
//! So [`Watched`] owns the socket and its registration together, and drops
//! them in that order. A socket that exists is registered, and one that has
//! gone is not, with no bookkeeping in between to fall out of step.

use std::io;
use std::ops::{Deref, DerefMut};
use std::os::fd::{AsRawFd, RawFd};
use std::sync::Arc;
use std::time::Duration;

use mio::unix::SourceFd;
use mio::{Events, Interest, Poll, Registry, Token};

/// Events one drain takes before making another pass.
const DRAIN_CAPACITY: usize = 128;

/// Passes one drain makes before giving up on emptying the set.
///
/// A fail-safe rather than a budget, and sized so it cannot bind: at
/// `DRAIN_CAPACITY` each, this takes 1024 events, against a ceiling of two
/// for every one of the [`DEFAULT_MAX_HOST_SOCKETS`] sockets a machine may
/// hold — two because kqueue reports a socket's readable and writable halves
/// as separate events. It is here because a loop with no bound at all is a
/// loop a future change can wedge, not because leftovers are expected.
///
/// They would not be lost if there were any, but only because the next pass
/// drains unconditionally. An outer poll set is woken by this one
/// *transitioning* into having events, and a set already holding some never
/// transitions again — measured, not assumed: an outer kqueue watching a
/// dirty inner one stays silent even as further events land on it. So a set
/// left non-empty stops waking the drive loop entirely, and what recovers it
/// is the tick's own service pass emptying it. That is why the drain is not
/// conditional on having been woken by readiness: the unconditional call is
/// also the repair.
///
/// [`DEFAULT_MAX_HOST_SOCKETS`]: super::limits::DEFAULT_MAX_HOST_SOCKETS
const DRAIN_PASSES: usize = 8;

/// What the guest's host sockets report their readiness on.
///
/// Costs two descriptors rather than one: [`Self::readiness_fd`] hands the
/// drive loop the poll set's own, and a second, owned reference to the same
/// kernel object goes to every socket so each can unregister itself when it
/// closes. mio's registry is borrowed from the poll set, and a borrow cannot
/// outlive it into a socket's `Drop`.
pub struct ReadinessSet {
    poll: Poll,
    registry: Arc<Registry>,
    events: Events,
    /// Polls this set has issued, so a drain can be witnessed by the syscall
    /// count it costs rather than by how long it took. Only a test reads it,
    /// and a latency fix asserted on wall-clock is a flake, so it is the one
    /// observable that makes the property checkable at all.
    #[cfg(test)]
    polls: usize,
}

impl ReadinessSet {
    pub fn new() -> io::Result<Self> {
        Self::with_drain_capacity(DRAIN_CAPACITY)
    }

    fn with_drain_capacity(capacity: usize) -> io::Result<Self> {
        let poll = Poll::new()?;
        let registry = Arc::new(poll.registry().try_clone()?);
        Ok(Self {
            poll,
            registry,
            events: Events::with_capacity(capacity),
            #[cfg(test)]
            polls: 0,
        })
    }

    /// The descriptor the drive loop waits on.
    pub fn readiness_fd(&self) -> RawFd {
        self.poll.as_raw_fd()
    }

    /// The means to register a socket here, cheap to clone and safe to hold.
    pub fn watch(&self) -> Watch {
        Watch(Arc::clone(&self.registry))
    }

    /// Consume the readiness that has accumulated, reporting how much.
    ///
    /// Nothing is demultiplexed. The caller services every socket it holds
    /// on the pass this wakes, so which one fired carries no information it
    /// needs. What the drain is for is the *edge*: an outer poll set waiting
    /// on this one wakes when it transitions into having events pending, and
    /// a set nobody empties never transitions again — it would either wake
    /// the loop continuously or, once its edge was spent, never again.
    ///
    /// Called before the sockets are read rather than after. An edge cleared
    /// after a read is an edge for bytes that arrived between the two, which
    /// nothing would then go back for until the tick.
    pub fn drain(&mut self) -> usize {
        self.drain_for(Duration::ZERO)
    }

    /// [`Self::drain`], but willing to wait for the first report.
    ///
    /// The service pass never waits — the drive loop owns the waiting — so
    /// production always passes zero. A test asserting that something does
    /// *not* report needs a window in which it could have.
    fn drain_for(&mut self, first_wait: Duration) -> usize {
        let mut taken = 0;
        for pass in 0..DRAIN_PASSES {
            let wait = if pass == 0 {
                first_wait
            } else {
                Duration::ZERO
            };
            match self.poll.poll(&mut self.events, Some(wait)) {
                Ok(()) => {}
                Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                // A poll set that cannot be polled reports no readiness; the
                // drive loop's tick still advances everything this datapath
                // owns, so this degrades to the pre-readiness behaviour
                // rather than to a stall.
                Err(_) => break,
            }
            #[cfg(test)]
            {
                self.polls += 1;
            }
            let n = self.events.iter().count();
            taken += n;
            // A poll that filled fewer slots than it offered has emptied
            // the set: both kqueue and epoll copy out ready events until
            // the ready list runs out or the caller's buffer does, so a
            // short return *is* the "nothing left" report and asking again
            // can only repeat it. Stopping here is not one syscall saved
            // out of thriftiness — on macOS a `kevent` that returns zero
            // events costs ~12 µs against a few hundred nanoseconds for one
            // that returns an event, and a drain that stopped only on an
            // empty return always ended with the expensive shape.
            //
            // It drops no edge. Readiness that arrives after this stops is
            // queued behind a set the kernel has just emptied, so it is a
            // transition into non-empty — exactly what the outer poll set
            // watching this descriptor wakes on.
            if n < self.events.capacity() {
                break;
            }
        }
        taken
    }
}

/// The means to put a socket on a [`ReadinessSet`].
///
/// Holds the set's kernel object alive, so a table handed one can register
/// for as long as it lives without a lifetime threaded through every entry.
#[derive(Clone)]
pub struct Watch(Arc<Registry>);

impl std::fmt::Debug for Watch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Watch")
    }
}

/// One descriptor's place on the readiness set, released when this drops.
///
/// Separate from the socket it describes so it can be tested against a
/// descriptor the test still owns: a guard that also owned the socket could
/// only be observed by closing the thing whose registration is under test,
/// which would pass whether or not it deregistered anything.
pub struct Registration {
    registry: Arc<Registry>,
    fd: RawFd,
}

impl Registration {
    /// Register `fd` for both directions.
    ///
    /// One interest for every socket, rather than writable for a connect in
    /// flight and readable for an established flow. The service pass drives
    /// everything this datapath holds whatever woke it, so a narrower
    /// interest would buy nothing but a re-registration at the moment a
    /// half-open entry becomes a flow — a second place for the registration
    /// to be wrong.
    pub fn new(watch: &Watch, fd: RawFd) -> io::Result<Self> {
        let registry = Arc::clone(&watch.0);
        registry.register(
            &mut SourceFd(&fd),
            Token(fd as usize),
            Interest::READABLE | Interest::WRITABLE,
        )?;
        Ok(Self { registry, fd })
    }
}

impl Drop for Registration {
    fn drop(&mut self) {
        // Nothing to do about a failure here: the descriptor is on its way
        // out either way, and the kernel drops a closed descriptor's
        // registration with it.
        let _ = self.registry.deregister(&mut SourceFd(&self.fd));
    }
}

impl std::fmt::Debug for Registration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Registration")
            .field("fd", &self.fd)
            .finish()
    }
}

/// A host socket and its registration, with one lifetime between them.
pub struct Watched<S: AsRawFd> {
    /// Declared before the socket so it drops first. Field drop order is
    /// declaration order, and the other way round would hand the poll set a
    /// descriptor number the kernel had already freed.
    registration: Registration,
    socket: S,
}

impl<S: AsRawFd> Watched<S> {
    pub fn new(watch: &Watch, socket: S) -> io::Result<Self> {
        let registration = Registration::new(watch, socket.as_raw_fd())?;
        Ok(Self {
            registration,
            socket,
        })
    }
}

impl<S: AsRawFd> Deref for Watched<S> {
    type Target = S;

    fn deref(&self) -> &S {
        &self.socket
    }
}

impl<S: AsRawFd> DerefMut for Watched<S> {
    fn deref_mut(&mut self) -> &mut S {
        &mut self.socket
    }
}

impl<S: AsRawFd> std::fmt::Debug for Watched<S> {
    /// Hand-written because `S` is a socket carrying guest-controlled
    /// traffic, and the tables that hold these format themselves into logs.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Watched")
            .field("registration", &self.registration)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::net::UnixStream;

    /// How long the negative half of the deregistration witness waits for a
    /// report that must not come.
    ///
    /// Wide on purpose. A live registration reports a written byte in
    /// microseconds on both kqueue and epoll — this is three orders of
    /// magnitude past that, so a pass here is a deregistration rather than a
    /// slow machine.
    const SILENCE_WINDOW: Duration = Duration::from_millis(500);

    fn pair() -> (UnixStream, UnixStream) {
        UnixStream::pair().expect("a socket pair")
    }

    #[test]
    fn a_registered_descriptor_reports_what_its_peer_sent() {
        let mut set = ReadinessSet::new().expect("readiness set");
        let (host, mut peer) = pair();
        let _registration =
            Registration::new(&set.watch(), host.as_raw_fd()).expect("registration");

        peer.write_all(b"x").expect("write");
        assert!(
            set.drain_for(SILENCE_WINDOW) > 0,
            "a registered descriptor must report"
        );
    }

    /// The hazard this pins: a descriptor that closes while the set still
    /// names it frees its number for the next open in this process, and the
    /// set would then report an unrelated resource as this flow. The
    /// registration is dropped here while the socket stays open, which is
    /// the only arrangement in which "it stopped reporting" means
    /// deregistration rather than the descriptor simply being gone.
    #[test]
    fn a_dropped_registration_stops_reporting() {
        let mut set = ReadinessSet::new().expect("readiness set");
        let (host, mut peer) = pair();
        let registration = Registration::new(&set.watch(), host.as_raw_fd()).expect("registration");

        peer.write_all(b"first").expect("write");
        assert!(
            set.drain() > 0,
            "the registration must report while it lives"
        );

        drop(registration);
        peer.write_all(b"second").expect("write");
        assert_eq!(
            set.drain_for(SILENCE_WINDOW),
            0,
            "a descriptor whose registration has gone must not report, even \
             though the descriptor itself is still open"
        );
    }

    /// A sanity check on the composition, and **not** a witness for
    /// deregistration: dropping a `Watched` closes the socket too, and the
    /// kernel takes a closed descriptor's registration with it, so this
    /// stays green with [`Registration`]'s `Drop` gutted. Verified by doing
    /// exactly that. The witness is
    /// [`a_dropped_registration_stops_reporting`], which is why
    /// `Registration` is a type of its own.
    #[test]
    fn a_watched_socket_carries_its_own_registration() {
        let mut set = ReadinessSet::new().expect("readiness set");
        let (host, mut peer) = pair();
        let watched = Watched::new(&set.watch(), host).expect("watched socket");

        peer.write_all(b"first").expect("write");
        assert!(set.drain() > 0, "a watched socket reports while it lives");

        drop(watched);
        // The peer's write has nowhere to land now; what matters is that the
        // set has nothing left to report either way.
        let _ = peer.write_all(b"second");
        assert_eq!(
            set.drain_for(SILENCE_WINDOW),
            0,
            "a socket that has gone leaves nothing behind on the set"
        );
    }

    /// The claim on [`DRAIN_PASSES`] is arithmetic, so it is checked rather
    /// than asserted in prose: a later change to either constant, or to the
    /// socket ceiling, must not quietly make the fail-safe a real budget.
    #[test]
    fn one_drain_can_empty_a_full_set() {
        const {
            assert!(
                DRAIN_PASSES * DRAIN_CAPACITY >= 2 * super::super::limits::DEFAULT_MAX_HOST_SOCKETS
            )
        };
    }

    /// The defect this pins: a drain that stops only on a poll reporting
    /// nothing always ends with one, and on macOS that call is the expensive
    /// shape — a `kevent` returning zero events measures ~12 µs against a
    /// few hundred nanoseconds for one returning an event, which is most of
    /// what a single-flow service pass costs. A poll that fills fewer slots
    /// than it offered has already emptied the set, so the terminating call
    /// buys nothing.
    ///
    /// Asserts on the poll count rather than on elapsed time: this is a
    /// latency fix, and a latency fix witnessed by a stopwatch is a flake.
    #[test]
    fn a_drain_that_empties_the_set_stops_without_a_further_poll() {
        let mut set = ReadinessSet::new().expect("readiness set");
        let (host, mut peer) = pair();
        let _registration =
            Registration::new(&set.watch(), host.as_raw_fd()).expect("registration");

        peer.write_all(b"x").expect("write");
        assert!(
            set.drain_for(SILENCE_WINDOW) > 0,
            "a registered descriptor must report"
        );
        assert_eq!(
            set.polls, 1,
            "one poll returned fewer events than it had room for, which \
             means the set was empty; a second poll can only report nothing"
        );
    }

    /// The other half of the same property, and the reason it is a *short*
    /// return rather than "stop after the first poll": a set holding more
    /// than one poll's worth must still be emptied, or the leftovers wait
    /// out the drive loop's tick.
    #[test]
    fn a_drain_keeps_going_while_each_poll_fills_the_buffer() {
        // Small on purpose. Overflowing the production buffer would need
        // hundreds of descriptors, and the loop under test does not care
        // how big the buffer is — only whether a poll filled it.
        const CAPACITY: usize = 2;
        let mut set = ReadinessSet::with_drain_capacity(CAPACITY).expect("readiness set");
        let mut held = Vec::new();
        for _ in 0..(CAPACITY * 2) {
            let (host, mut peer) = pair();
            let registration =
                Registration::new(&set.watch(), host.as_raw_fd()).expect("registration");
            peer.write_all(b"x").expect("write");
            held.push((host, peer, registration));
        }

        let taken = set.drain_for(SILENCE_WINDOW);
        assert!(
            taken >= held.len(),
            "every registered descriptor has something to report: took {taken} \
             of at least {}",
            held.len()
        );
        assert!(
            set.polls > 1,
            "a set holding more than one poll's worth needs more than one poll"
        );
    }

    #[test]
    fn draining_an_idle_set_takes_nothing() {
        let mut set = ReadinessSet::new().expect("readiness set");
        assert_eq!(set.drain(), 0);
    }

    #[test]
    fn a_set_exposes_the_descriptor_the_drive_loop_waits_on() {
        let set = ReadinessSet::new().expect("readiness set");
        assert!(set.readiness_fd() >= 0);
    }
}
