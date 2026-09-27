//! Local controller for the grant-gated production drive surface.
//!
//! The controller binds once to a running machine's verified drive authority.
//! MCP and the in-process language bindings share this type, so discovery,
//! filesystem calls, input delivery, and streamed events cannot drift into
//! separate implementations.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread::JoinHandle;

use mvm_agentd::vsock::RunEntrypointError;
pub use mvm_agentd::vsock::{DriveFileOperation, EntrypointEvent, FsResult};
use mvm_contract::stream::StreamKind;
pub use mvm_contract::stream::input::InputFrame;
use mvm_hostd::drive::{DriveAuthority, DriveInputSession, DriveSessionError};

/// A local drive-controller failure.
#[derive(Debug, thiserror::Error)]
pub enum DriveError {
    #[error(transparent)]
    Session(#[from] DriveSessionError),
    #[error("this MCP server is not bound to a drive grant")]
    NotGranted,
    #[error("a driven program is already in flight")]
    AlreadyOpen,
    #[error("no driven program is open")]
    NotOpen,
    #[error("the drive worker panicked")]
    WorkerPanicked,
}

impl DriveError {
    /// Stable machine-readable code from the shared error-code registry, so
    /// an SDK or MCP caller branches on the same codes every other surface
    /// reports.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        use mvm_core::error_codes::{BACKEND_ERROR, CONFLICT, INTERNAL, REJECTED, UNAUTHORIZED};
        match self {
            Self::Session(DriveSessionError::Refused(_)) => REJECTED,
            Self::Session(_) => BACKEND_ERROR,
            Self::NotGranted => UNAUTHORIZED,
            Self::AlreadyOpen | Self::NotOpen => CONFLICT,
            Self::WorkerPanicked => INTERNAL,
        }
    }

    /// Whether retrying the identical request may succeed. None of these can:
    /// each is a property of the request or of the controller's state, and
    /// only a transient backend condition is retryable in the shared registry.
    #[must_use]
    pub const fn retryable(&self) -> bool {
        false
    }
}

/// One MCP/SDK process bound to one machine's admitted drive authority.
pub struct LocalDrive {
    vm: String,
    authority: DriveAuthority,
    state: Mutex<DriveState>,
    events: Arc<Mutex<VecDeque<EntrypointEvent>>>,
}

#[derive(Default)]
struct DriveState {
    input: Option<DriveInputSession>,
    worker: Option<JoinHandle<()>>,
}

impl LocalDrive {
    /// Bind to `vm` only when its current admitted plan carries a valid,
    /// unexpired drive grant. `Ok(None)` is the ordinary no-grant discovery
    /// result.
    pub fn bind(vm: &str) -> Result<Option<Self>, DriveError> {
        let Some(authority) = DriveAuthority::load(vm)? else {
            return Ok(None);
        };
        Ok(Some(Self {
            vm: vm.to_string(),
            authority,
            state: Mutex::new(DriveState::default()),
            events: Arc::new(Mutex::new(VecDeque::new())),
        }))
    }

    /// Start the program selected by the signed grant.
    ///
    /// Output events are queued without blocking the guest pump and are also
    /// handed to the host stream capture when this process owns one.
    pub fn open(&self, cwd: &str) -> Result<String, DriveError> {
        let mut state = self.state();
        self.reap_finished(&mut state)?;
        if state.worker.is_some() || state.input.is_some() {
            return Err(DriveError::AlreadyOpen);
        }
        self.authority.prepare_open(cwd)?;
        let input = DriveInputSession::open_existing(&self.authority)?;
        let holder = input.holder().to_string();
        lock_events(&self.events).clear();
        let authority = self.authority.clone();
        let vm = self.vm.clone();
        let cwd = cwd.to_string();
        let events = Arc::clone(&self.events);
        let worker = std::thread::spawn(move || {
            let mut capture = mvm_hostd::stream::EntrypointSink::for_vm(&vm);
            let terminal = authority.open_program(&cwd, |event| {
                capture_event(&mut capture, event);
                lock_events(&events).push_back(event.clone());
            });
            let terminal = terminal.unwrap_or_else(|error| EntrypointEvent::Error {
                kind: RunEntrypointError::InternalError,
                message: error.to_string(),
            });
            lock_events(&events).push_back(terminal);
        });
        state.input = Some(input);
        state.worker = Some(worker);
        Ok(holder)
    }

    /// Deliver one ordered input frame. When `eof` is true, close the input
    /// route after the frame has been delivered.
    pub fn write(&self, frame: InputFrame, eof: bool) -> Result<usize, DriveError> {
        let accepted = frame.payload.len();
        let mut state = self.state();
        let input = state.input.as_mut().ok_or(DriveError::NotOpen)?;
        input.write(frame)?;
        if eof {
            let input = state.input.take().ok_or(DriveError::NotOpen)?;
            input.close()?;
        }
        Ok(accepted)
    }

    /// Return the next queued drive event without waiting. A caller polls this
    /// method; the bounded guest handoff remains independent of MCP pacing.
    pub fn next_event(&self) -> Result<Option<EntrypointEvent>, DriveError> {
        let event = lock_events(&self.events).pop_front();
        if event.as_ref().is_some_and(EntrypointEvent::is_terminal) {
            let mut state = self.state();
            if let Some(worker) = state.worker.take() {
                worker.join().map_err(|_| DriveError::WorkerPanicked)?;
            }
            state.input.take();
        }
        Ok(event)
    }

    /// Execute one grant-bounded file operation.
    pub fn file(&self, operation: DriveFileOperation) -> Result<FsResult, DriveError> {
        self.authority.file(operation).map_err(DriveError::from)
    }

    fn state(&self) -> MutexGuard<'_, DriveState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn reap_finished(&self, state: &mut DriveState) -> Result<(), DriveError> {
        if !state.worker.as_ref().is_some_and(JoinHandle::is_finished) {
            return Ok(());
        }
        if let Some(worker) = state.worker.take() {
            worker.join().map_err(|_| DriveError::WorkerPanicked)?;
        }
        state.input.take();
        Ok(())
    }
}

fn lock_events(
    events: &Mutex<VecDeque<EntrypointEvent>>,
) -> MutexGuard<'_, VecDeque<EntrypointEvent>> {
    events.lock().unwrap_or_else(PoisonError::into_inner)
}

fn capture_event(capture: &mut mvm_hostd::stream::EntrypointSink, event: &EntrypointEvent) {
    match event {
        EntrypointEvent::Stdout { chunk } => {
            capture.ingest(StreamKind::Stdout, chunk);
        }
        EntrypointEvent::Stderr { chunk } => {
            capture.ingest(StreamKind::Stderr, chunk);
        }
        EntrypointEvent::Control { header_json, .. } => {
            capture.ingest(StreamKind::Trace, header_json.as_bytes());
        }
        EntrypointEvent::Exit { .. } | EntrypointEvent::Error { .. } => {}
    }
}

#[cfg(test)]
mod tests {
    use mvm_core::util::test_env::TestEnv;

    use super::*;

    #[test]
    fn a_machine_without_a_drive_grant_does_not_bind_a_controller() {
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(home.path());
        let plan = mvm_core::plan::test_support::PlanFixture::new()
            .workload("mcp-no-drive")
            .build();
        mvm_hostd::audit::plan_persist::write_plan("mcp-no-drive", &plan).unwrap();

        assert!(LocalDrive::bind("mcp-no-drive").unwrap().is_none());
    }

    #[test]
    fn drive_error_codes_come_from_the_shared_registry_and_none_is_retryable() {
        use mvm_agentd::vsock::DriveRefusal;
        use mvm_core::error_codes::{BACKEND_ERROR, CONFLICT, INTERNAL, REJECTED, UNAUTHORIZED};

        let cases = [
            (
                DriveError::Session(DriveSessionError::Refused(
                    DriveRefusal::OutsideWorkspaceRoots,
                )),
                REJECTED,
            ),
            (
                DriveError::Session(DriveSessionError::Rpc(anyhow::anyhow!("gone"))),
                BACKEND_ERROR,
            ),
            (DriveError::NotGranted, UNAUTHORIZED),
            (DriveError::AlreadyOpen, CONFLICT),
            (DriveError::NotOpen, CONFLICT),
            (DriveError::WorkerPanicked, INTERNAL),
        ];
        for (error, code) in cases {
            assert_eq!(error.code(), code, "{error}");
            assert!(!error.retryable(), "{error}");
        }
    }
}
