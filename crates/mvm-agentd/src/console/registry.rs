//! Console session bookkeeping: who is attached, what they missed, and whether
//! the shell is still alive.
//!
//! Pure state, no I/O of its own. The PTY pump and the per-attach data
//! channels in the parent module drive it, always under one mutex, so every
//! transition here is atomic with respect to the others. In particular a
//! session's exit is recorded before its client is hung up, so a host that
//! sees its data stream end can always ask how the session finished.
//!
//! One session per VM. A console is a dev convenience; several concurrent
//! shells behind one verb would add a naming surface and a fan-out of
//! scrollback memory for no capability `machine exec` does not already give.

use std::fs::File;
use std::os::fd::{AsRawFd, RawFd};
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::scrollback::ScrollbackRing;
use crate::vsock::CONSOLE_PORT_BASE;

/// Where a console client's output goes. The production sink is the vsock
/// data stream; tests substitute a recorder.
pub trait ConsoleSink: Send {
    /// Deliver `bytes` to the client. An error means the client is gone.
    fn send(&mut self, bytes: &[u8]) -> std::io::Result<()>;
    /// End the client's data stream. The session itself is untouched.
    fn hang_up(&mut self);
}

/// Permission to complete one attach: the data port the host dials next, and
/// the identity that ties the connection back to this attach and no later one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttachTicket {
    pub session_id: u32,
    pub attach_id: u32,
    pub data_port: u32,
    /// Scrollback bytes the client will receive before live output.
    pub replay_bytes: u64,
}

/// Why an attach was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachRefusal {
    /// No session with that id exists on this agent.
    NoSuchSession(u32),
    /// Another client is attached, and the request did not ask to take over.
    Busy(u32),
}

impl std::fmt::Display for AttachRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoSuchSession(id) => write!(f, "no console session {id}"),
            Self::Busy(id) => write!(f, "console session {id} already has an attached client"),
        }
    }
}

impl std::error::Error for AttachRefusal {}

/// What happened when a data connection arrived for an attach.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachOutcome {
    /// The client has its replay and now receives live output.
    Live,
    /// The session had already ended: the client got the final scrollback and
    /// its stream was closed.
    Ended,
    /// A later attach replaced this one before it connected.
    Superseded,
    /// The replay could not be delivered; the client is gone.
    Failed,
}

/// Point-in-time description of a session, for listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionSummary {
    pub session_id: u32,
    /// The program the session runs (argv\[0\] only: arguments can carry
    /// values the operator typed, and a listing is no place to echo them).
    pub command: String,
    pub attached: bool,
    pub exit_code: Option<i32>,
    pub scrollback_bytes: u64,
    /// How long the session has had no client, while it is running.
    pub detached_for: Option<Duration>,
    pub detach_timeout: Option<Duration>,
}

/// A freshly forked shell, ready to be recorded.
pub struct SpawnedSession {
    pub child_pid: i32,
    pub master: Option<Arc<File>>,
    pub command: String,
    pub detach_timeout: Option<Duration>,
}

enum Liveness {
    Running { child_pid: i32 },
    Exited { exit_code: i32 },
}

struct Attachment {
    attach_id: u32,
    /// `None` between the attach request and the host's data connection.
    sink: Option<Box<dyn ConsoleSink>>,
}

impl Attachment {
    fn hang_up(self) {
        if let Some(mut sink) = self.sink {
            sink.hang_up();
        }
    }
}

struct Session {
    id: u32,
    command: String,
    liveness: Liveness,
    master: Option<Arc<File>>,
    ring: ScrollbackRing,
    attachment: Option<Attachment>,
    detached_since: Option<Instant>,
    detach_timeout: Option<Duration>,
}

impl Session {
    fn is_running(&self) -> bool {
        matches!(self.liveness, Liveness::Running { .. })
    }

    /// Drop the current client, if any, and start the detached clock.
    fn drop_client(&mut self, now: Instant) {
        if let Some(attachment) = self.attachment.take() {
            attachment.hang_up();
        }
        if self.is_running() {
            self.detached_since = Some(now);
        }
    }
}

/// The agent's console sessions. See the module docs for the invariants.
pub struct Registry {
    session: Option<Session>,
    next_session_id: u32,
    next_attach_id: u32,
    scrollback_cap: usize,
}

impl Registry {
    pub const fn new(scrollback_cap: usize) -> Self {
        Self {
            session: None,
            next_session_id: 0,
            next_attach_id: 0,
            scrollback_cap,
        }
    }

    /// Refuse to start a second shell while one is still running. A session
    /// that has exited is replaced, taking its scrollback with it.
    pub fn ensure_can_open(&self) -> Result<(), super::ConsoleError> {
        match &self.session {
            Some(session) if session.is_running() => {
                Err(super::ConsoleError::AlreadyActive(session.id))
            }
            _ => Ok(()),
        }
    }

    /// Allocate the id — and so the data port — for the next attach.
    ///
    /// Every attach gets a fresh port rather than reusing its session's: a
    /// host-side bridge that still holds the previous connection must never be
    /// handed the next one.
    pub fn allocate_attach(&mut self) -> (u32, u32) {
        self.next_attach_id += 1;
        let attach_id = self.next_attach_id;
        (attach_id, CONSOLE_PORT_BASE + attach_id)
    }

    /// Record a newly spawned shell with a pending first attach.
    pub fn insert(&mut self, spawned: SpawnedSession, attach_id: u32) -> AttachTicket {
        self.next_session_id += 1;
        let id = self.next_session_id;
        self.session = Some(Session {
            id,
            command: spawned.command,
            liveness: Liveness::Running {
                child_pid: spawned.child_pid,
            },
            master: spawned.master,
            ring: ScrollbackRing::new(self.scrollback_cap),
            attachment: Some(Attachment {
                attach_id,
                sink: None,
            }),
            detached_since: None,
            detach_timeout: spawned.detach_timeout,
        });
        AttachTicket {
            session_id: id,
            attach_id,
            data_port: CONSOLE_PORT_BASE + attach_id,
            replay_bytes: 0,
        }
    }

    fn session_mut(&mut self, session_id: u32) -> Option<&mut Session> {
        self.session.as_mut().filter(|s| s.id == session_id)
    }

    fn session(&self, session_id: u32) -> Option<&Session> {
        self.session.as_ref().filter(|s| s.id == session_id)
    }

    /// Reserve `session_id` for a new client. With `take_over`, a client
    /// already attached is hung up first; without it, it is a [`AttachRefusal::Busy`].
    pub fn attach(
        &mut self,
        session_id: u32,
        take_over: bool,
    ) -> Result<AttachTicket, AttachRefusal> {
        let Some(session) = self.session.as_ref().filter(|s| s.id == session_id) else {
            return Err(AttachRefusal::NoSuchSession(session_id));
        };
        if session.attachment.is_some() && !take_over {
            return Err(AttachRefusal::Busy(session_id));
        }
        let (attach_id, data_port) = self.allocate_attach();
        let session = self
            .session_mut(session_id)
            .expect("session was found above under the same borrow of self");
        if let Some(previous) = session.attachment.take() {
            previous.hang_up();
        }
        session.attachment = Some(Attachment {
            attach_id,
            sink: None,
        });
        session.detached_since = None;
        Ok(AttachTicket {
            session_id,
            attach_id,
            data_port,
            replay_bytes: session.ring.len() as u64,
        })
    }

    /// Hand the data connection for `attach_id` its replay and, if the shell
    /// is still running, make it the live client.
    pub fn complete_attach(
        &mut self,
        attach_id: u32,
        mut sink: Box<dyn ConsoleSink>,
        now: Instant,
    ) -> AttachOutcome {
        let Some(session) = self.session.as_mut().filter(|s| {
            s.attachment
                .as_ref()
                .is_some_and(|a| a.attach_id == attach_id && a.sink.is_none())
        }) else {
            sink.hang_up();
            return AttachOutcome::Superseded;
        };
        let replay = session.ring.replay();
        if !replay.is_empty() && sink.send(&replay).is_err() {
            sink.hang_up();
            session.attachment = None;
            if session.is_running() {
                session.detached_since = Some(now);
            }
            return AttachOutcome::Failed;
        }
        if !session.is_running() {
            sink.hang_up();
            session.attachment = None;
            return AttachOutcome::Ended;
        }
        session.attachment = Some(Attachment {
            attach_id,
            sink: Some(sink),
        });
        AttachOutcome::Live
    }

    /// The client of `attach_id` is gone (its input closed, or its data
    /// connection never arrived). A later attach is left alone.
    pub fn release(&mut self, attach_id: u32, now: Instant) {
        if let Some(session) = self.session.as_mut().filter(|s| {
            s.attachment
                .as_ref()
                .is_some_and(|a| a.attach_id == attach_id)
        }) {
            session.drop_client(now);
        }
    }

    /// Hang up whichever client is attached to `session_id`. Returns whether
    /// one was.
    pub fn detach(&mut self, session_id: u32, now: Instant) -> Result<bool, AttachRefusal> {
        let session = self
            .session_mut(session_id)
            .ok_or(AttachRefusal::NoSuchSession(session_id))?;
        let was_attached = session.attachment.is_some();
        session.drop_client(now);
        Ok(was_attached)
    }

    /// Shell output: keep it for replay and forward it to the live client. A
    /// client that cannot take it is dropped rather than allowed to stall the
    /// shell.
    pub fn record_output(&mut self, session_id: u32, bytes: &[u8], now: Instant) {
        let Some(session) = self.session_mut(session_id) else {
            return;
        };
        session.ring.push(bytes);
        let delivered = match session.attachment.as_mut().and_then(|a| a.sink.as_mut()) {
            Some(sink) => sink.send(bytes).is_ok(),
            None => true,
        };
        if !delivered {
            session.drop_client(now);
        }
    }

    /// The shell exited. Recorded before the client is hung up, so the host
    /// that sees its stream end finds the exit code already here.
    pub fn record_exit(&mut self, session_id: u32, exit_code: i32) {
        let Some(session) = self.session_mut(session_id) else {
            return;
        };
        session.liveness = Liveness::Exited { exit_code };
        session.master = None;
        session.detached_since = None;
        // A pending attach keeps its reservation: its client still gets the
        // final scrollback and a clean end when it connects.
        let connected = session
            .attachment
            .as_ref()
            .is_some_and(|a| a.sink.is_some());
        if connected && let Some(attachment) = session.attachment.take() {
            attachment.hang_up();
        }
    }

    /// The exit code of `session_id`, once it has exited.
    pub fn exit_code(&self, session_id: u32) -> Option<i32> {
        match self.session(session_id)?.liveness {
            Liveness::Exited { exit_code } => Some(exit_code),
            Liveness::Running { .. } => None,
        }
    }

    /// The shell pid of `session_id`, while it runs.
    pub fn running_child(&self, session_id: u32) -> Option<i32> {
        match self.session(session_id)?.liveness {
            Liveness::Running { child_pid } => Some(child_pid),
            Liveness::Exited { .. } => None,
        }
    }

    /// Whether `session_id` names the current session.
    pub fn contains(&self, session_id: u32) -> bool {
        self.session(session_id).is_some()
    }

    /// The PTY master of `session_id`, while it runs.
    pub fn master(&self, session_id: u32) -> Option<Arc<File>> {
        self.session(session_id)?.master.clone()
    }

    /// The raw PTY master fd of `session_id`, for a window-size change.
    pub fn master_fd(&self, session_id: u32) -> Option<RawFd> {
        self.session(session_id)?
            .master
            .as_ref()
            .map(|master| master.as_raw_fd())
    }

    /// The shell to hang up because its session has sat detached past its
    /// timeout, if any.
    pub fn expired_child(&self, now: Instant) -> Option<i32> {
        let session = self.session.as_ref()?;
        let Liveness::Running { child_pid } = session.liveness else {
            return None;
        };
        let timeout = session.detach_timeout?;
        let since = session.detached_since?;
        (session.attachment.is_none() && now.saturating_duration_since(since) >= timeout)
            .then_some(child_pid)
    }

    /// Every session this agent knows about: the running one, or the last one
    /// to exit until the next is opened.
    pub fn summaries(&self, now: Instant) -> Vec<SessionSummary> {
        self.session
            .iter()
            .map(|session| SessionSummary {
                session_id: session.id,
                command: session.command.clone(),
                attached: session
                    .attachment
                    .as_ref()
                    .is_some_and(|a| a.sink.is_some()),
                exit_code: match session.liveness {
                    Liveness::Exited { exit_code } => Some(exit_code),
                    Liveness::Running { .. } => None,
                },
                scrollback_bytes: session.ring.len() as u64,
                detached_for: session
                    .detached_since
                    .map(|since| now.saturating_duration_since(since)),
                detach_timeout: session.detach_timeout,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, Ordering};

    /// A client that records what it was sent and whether it was hung up.
    #[derive(Clone, Default)]
    struct Recorder {
        bytes: Arc<Mutex<Vec<u8>>>,
        hung_up: Arc<AtomicBool>,
        broken: Arc<AtomicBool>,
    }

    impl Recorder {
        fn received(&self) -> Vec<u8> {
            self.bytes.lock().unwrap().clone()
        }
        fn was_hung_up(&self) -> bool {
            self.hung_up.load(Ordering::SeqCst)
        }
        fn sink(&self) -> Box<dyn ConsoleSink> {
            Box::new(self.clone())
        }
    }

    impl ConsoleSink for Recorder {
        fn send(&mut self, bytes: &[u8]) -> std::io::Result<()> {
            if self.broken.load(Ordering::SeqCst) {
                return Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe));
            }
            self.bytes.lock().unwrap().extend_from_slice(bytes);
            Ok(())
        }
        fn hang_up(&mut self) {
            self.hung_up.store(true, Ordering::SeqCst);
        }
    }

    fn spawned(detach_timeout: Option<Duration>) -> SpawnedSession {
        SpawnedSession {
            child_pid: 4242,
            master: None,
            command: "/bin/sh".to_string(),
            detach_timeout,
        }
    }

    /// A registry holding one running session whose first client is live.
    fn live_session() -> (Registry, AttachTicket, Recorder) {
        let mut reg = Registry::new(64);
        let (attach_id, _) = reg.allocate_attach();
        let ticket = reg.insert(spawned(None), attach_id);
        let client = Recorder::default();
        let outcome = reg.complete_attach(ticket.attach_id, client.sink(), Instant::now());
        assert_eq!(outcome, AttachOutcome::Live);
        (reg, ticket, client)
    }

    #[test]
    fn output_produced_before_the_first_client_connects_is_replayed_to_it() {
        let mut reg = Registry::new(64);
        let (attach_id, port) = reg.allocate_attach();
        let ticket = reg.insert(spawned(None), attach_id);
        assert_eq!(ticket.data_port, port);
        reg.record_output(ticket.session_id, b"$ ", Instant::now());

        let client = Recorder::default();
        assert_eq!(
            reg.complete_attach(ticket.attach_id, client.sink(), Instant::now()),
            AttachOutcome::Live
        );
        reg.record_output(ticket.session_id, b"ls\n", Instant::now());
        assert_eq!(client.received(), b"$ ls\n");
    }

    #[test]
    fn a_second_client_is_refused_as_busy() {
        let (mut reg, ticket, _client) = live_session();
        assert_eq!(
            reg.attach(ticket.session_id, false),
            Err(AttachRefusal::Busy(ticket.session_id))
        );
    }

    #[test]
    fn a_pending_attach_also_holds_the_session() {
        // Between the attach request and its data connection the session is
        // spoken for; a racing second client must not slip in.
        let mut reg = Registry::new(64);
        let (attach_id, _) = reg.allocate_attach();
        let ticket = reg.insert(spawned(None), attach_id);
        assert_eq!(
            reg.attach(ticket.session_id, false),
            Err(AttachRefusal::Busy(ticket.session_id))
        );
    }

    #[test]
    fn detach_keeps_the_shell_and_buffers_its_output_for_reattach() {
        let (mut reg, ticket, client) = live_session();
        reg.record_output(ticket.session_id, b"before\n", Instant::now());
        assert_eq!(reg.detach(ticket.session_id, Instant::now()), Ok(true));
        assert!(client.was_hung_up());
        assert_eq!(reg.running_child(ticket.session_id), Some(4242));

        reg.record_output(ticket.session_id, b"while away\n", Instant::now());
        let again = reg
            .attach(ticket.session_id, false)
            .expect("a detached session accepts a new client");
        assert_ne!(again.attach_id, ticket.attach_id);
        assert_ne!(
            again.data_port, ticket.data_port,
            "every attach gets a fresh port"
        );
        assert_eq!(again.replay_bytes, 18);

        let second = Recorder::default();
        assert_eq!(
            reg.complete_attach(again.attach_id, second.sink(), Instant::now()),
            AttachOutcome::Live
        );
        assert_eq!(second.received(), b"before\nwhile away\n");
        assert!(
            !client.received().ends_with(b"while away\n"),
            "a detached client receives nothing more"
        );
    }

    #[test]
    fn a_lost_connection_detaches_without_ending_the_session() {
        let (mut reg, ticket, client) = live_session();
        reg.release(ticket.attach_id, Instant::now());
        assert!(client.was_hung_up());
        assert!(reg.attach(ticket.session_id, false).is_ok());
        assert_eq!(reg.exit_code(ticket.session_id), None);
    }

    #[test]
    fn a_client_that_cannot_take_output_is_dropped_not_waited_on() {
        let (mut reg, ticket, client) = live_session();
        client.broken.store(true, Ordering::SeqCst);
        reg.record_output(ticket.session_id, b"x", Instant::now());
        assert!(client.was_hung_up());
        let summary = &reg.summaries(Instant::now())[0];
        assert!(!summary.attached);
        assert_eq!(summary.scrollback_bytes, 1, "the output is still retained");
    }

    #[test]
    fn take_over_hangs_up_the_attached_client_and_admits_the_new_one() {
        let (mut reg, ticket, first) = live_session();
        let stolen = reg
            .attach(ticket.session_id, true)
            .expect("take-over is admitted");
        assert!(first.was_hung_up());

        // The displaced client's own release must not detach its successor.
        reg.release(ticket.attach_id, Instant::now());
        let second = Recorder::default();
        assert_eq!(
            reg.complete_attach(stolen.attach_id, second.sink(), Instant::now()),
            AttachOutcome::Live
        );
        reg.record_output(ticket.session_id, b"ok", Instant::now());
        assert_eq!(second.received(), b"ok");
    }

    #[test]
    fn a_superseded_connection_is_hung_up_on_arrival() {
        let mut reg = Registry::new(64);
        let (attach_id, _) = reg.allocate_attach();
        let ticket = reg.insert(spawned(None), attach_id);
        let _later = reg.attach(ticket.session_id, true).unwrap();
        let late = Recorder::default();
        assert_eq!(
            reg.complete_attach(ticket.attach_id, late.sink(), Instant::now()),
            AttachOutcome::Superseded
        );
        assert!(late.was_hung_up());
    }

    #[test]
    fn exit_is_recorded_before_the_client_is_hung_up() {
        let (mut reg, ticket, client) = live_session();
        reg.record_exit(ticket.session_id, 3);
        assert!(client.was_hung_up());
        assert_eq!(reg.exit_code(ticket.session_id), Some(3));
        assert_eq!(reg.running_child(ticket.session_id), None);
        assert_eq!(reg.summaries(Instant::now())[0].exit_code, Some(3));
    }

    #[test]
    fn a_client_attaching_after_exit_gets_the_final_output_and_an_end() {
        let mut reg = Registry::new(64);
        let (attach_id, _) = reg.allocate_attach();
        let ticket = reg.insert(spawned(None), attach_id);
        reg.record_output(ticket.session_id, b"done\n", Instant::now());
        reg.record_exit(ticket.session_id, 0);

        let client = Recorder::default();
        assert_eq!(
            reg.complete_attach(ticket.attach_id, client.sink(), Instant::now()),
            AttachOutcome::Ended
        );
        assert_eq!(client.received(), b"done\n");
        assert!(client.was_hung_up());
    }

    #[test]
    fn a_running_session_blocks_a_second_open_and_an_exited_one_does_not() {
        let (mut reg, ticket, _client) = live_session();
        assert!(matches!(
            reg.ensure_can_open(),
            Err(super::super::ConsoleError::AlreadyActive(id)) if id == ticket.session_id
        ));
        reg.record_exit(ticket.session_id, 0);
        assert!(reg.ensure_can_open().is_ok());
    }

    #[test]
    fn an_unknown_session_is_refused_by_every_operation() {
        let (mut reg, ticket, _client) = live_session();
        let other = ticket.session_id + 1;
        assert_eq!(
            reg.attach(other, true),
            Err(AttachRefusal::NoSuchSession(other))
        );
        assert_eq!(
            reg.detach(other, Instant::now()),
            Err(AttachRefusal::NoSuchSession(other))
        );
        assert!(!reg.contains(other));
        assert_eq!(reg.master_fd(other), None);
    }

    #[test]
    fn the_detach_timeout_runs_only_while_no_client_is_attached() {
        let start = Instant::now();
        let mut reg = Registry::new(64);
        let (attach_id, _) = reg.allocate_attach();
        let ticket = reg.insert(spawned(Some(Duration::from_secs(10))), attach_id);
        let client = Recorder::default();
        reg.complete_attach(ticket.attach_id, client.sink(), start);
        assert_eq!(
            reg.expired_child(start + Duration::from_secs(60)),
            None,
            "an attached session never idles out"
        );

        reg.detach(ticket.session_id, start).unwrap();
        assert_eq!(reg.expired_child(start + Duration::from_secs(9)), None);
        assert_eq!(
            reg.expired_child(start + Duration::from_secs(10)),
            Some(4242)
        );

        // Reattaching stops the clock.
        reg.attach(ticket.session_id, false).unwrap();
        assert_eq!(reg.expired_child(start + Duration::from_secs(60)), None);
    }

    #[test]
    fn without_a_timeout_a_detached_session_lives_until_the_vm_stops() {
        let (mut reg, ticket, _client) = live_session();
        let now = Instant::now();
        reg.detach(ticket.session_id, now).unwrap();
        assert_eq!(reg.expired_child(now + Duration::from_secs(86_400)), None);
    }

    #[test]
    fn a_summary_names_the_program_and_its_state() {
        let (mut reg, ticket, _client) = live_session();
        let now = Instant::now();
        let summary = &reg.summaries(now)[0];
        assert_eq!(summary.session_id, ticket.session_id);
        assert_eq!(summary.command, "/bin/sh");
        assert!(summary.attached);
        assert_eq!(summary.detached_for, None);

        reg.detach(ticket.session_id, now).unwrap();
        let summary = &reg.summaries(now + Duration::from_secs(5))[0];
        assert!(!summary.attached);
        assert_eq!(summary.detached_for, Some(Duration::from_secs(5)));
    }
}
