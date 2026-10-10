use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, OnceLock, mpsc};
use std::time::Instant;

use ed25519_dalek::SigningKey;
use rand::Rng as _;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::{CallerCredential, EnrolledIdentity, IdentityError, Result, Store};

/// A handle to the process's single bounded native credential worker.
#[derive(Clone)]
pub struct IdentityClient {
    requests: mpsc::SyncSender<Request>,
    busy: Arc<AtomicBool>,
    stopped: Arc<AtomicBool>,
    owner_pid: u32,
}

struct ClientFactory {
    owner_pid: AtomicU32,
    client: OnceLock<Result<IdentityClient>>,
}

impl ClientFactory {
    const fn new() -> Self {
        Self {
            owner_pid: AtomicU32::new(0),
            client: OnceLock::new(),
        }
    }

    fn get(&self, store: impl FnOnce() -> Result<Box<dyn Store>>) -> Result<IdentityClient> {
        let pid = std::process::id();
        if let Err(owner) =
            self.owner_pid
                .compare_exchange(0, pid, Ordering::AcqRel, Ordering::Acquire)
            && owner != pid
        {
            // Check before touching OnceLock: a fork can inherit it while a
            // vanished parent thread is still initializing the worker.
            return Err(IdentityError::Unavailable);
        }
        let client = self
            .client
            .get_or_init(|| IdentityClient::start(store()?))
            .clone()?;
        client.check_process()?;
        Ok(client)
    }
}

struct WorkerLiveness(Arc<AtomicBool>);
impl Drop for WorkerLiveness {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

#[cfg(test)]
#[path = "worker_tests.rs"]
mod tests;

/// Dropping a pending operation cancels result delivery, not the native syscall.
pub struct PendingCredential {
    result: mpsc::Receiver<Result<CallerCredential>>,
    canceled: Arc<AtomicBool>,
    deadline: Instant,
}

struct Request {
    installation: Uuid,
    expected: Option<[u8; 32]>,
    account: String,
    deadline: Instant,
    canceled: Arc<AtomicBool>,
    result: mpsc::SyncSender<Result<CallerCredential>>,
}

impl IdentityClient {
    /// Select only the dedicated native adapter, never a default/mock/file store.
    /// Repeated construction shares one lane, including after canceled calls.
    /// Inherited post-fork handles are refused; exec a fresh host process first.
    pub fn native() -> Result<Self> {
        static CLIENT: ClientFactory = ClientFactory::new();
        CLIENT.get(super::native_store)
    }

    #[cfg(all(
        test,
        feature = "native-caller-identity",
        any(target_os = "macos", target_os = "linux")
    ))]
    pub(super) fn shares_worker_with(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.busy, &other.busy)
    }

    pub(super) fn start(store: Box<dyn Store>) -> Result<Self> {
        // The atomic lane excludes a second request even while the worker is
        // blocked in the OS. One channel slot avoids a startup scheduling race.
        let (requests, work) = mpsc::sync_channel::<Request>(1);
        let busy = Arc::new(AtomicBool::new(false));
        let occupied = Arc::clone(&busy);
        let stopped = Arc::new(AtomicBool::new(false));
        let liveness = WorkerLiveness(Arc::clone(&stopped));
        std::thread::Builder::new()
            .name("mvm-caller-identity".into())
            .spawn(move || {
                let _liveness = liveness;
                while let Ok(request) = work.recv() {
                    let credential = execute(store.as_ref(), &request);
                    occupied.store(false, Ordering::Release);
                    // A disconnected receiver drops and zeroizes a late key.
                    let _ = request.result.send(credential);
                    #[cfg(test)]
                    store.completed();
                }
            })
            .map_err(|_| IdentityError::Unavailable)?;
        Ok(Self {
            requests,
            busy,
            stopped,
            owner_pid: std::process::id(),
        })
    }

    fn check_process(&self) -> Result<()> {
        if self.owner_pid != std::process::id() || self.stopped.load(Ordering::Acquire) {
            return Err(IdentityError::Unavailable);
        }
        Ok(())
    }

    /// Explicit first enrollment. Existing unpinned namespaces are conflicts;
    /// idempotent reuse requires `load` with the saved public enrollment pin.
    /// A timeout may leave the requested entry in the OS store: retain the
    /// installation identifier for explicit operator recovery, never overwrite.
    pub fn enroll(&self, installation: Uuid, deadline: Instant) -> Result<PendingCredential> {
        self.request(installation, None, deadline)
    }

    /// Load only the enrolled key. Missing keys are never regenerated.
    pub fn load(
        &self,
        identity: &EnrolledIdentity,
        deadline: Instant,
    ) -> Result<PendingCredential> {
        self.request(identity.installation, Some(identity.public_key), deadline)
    }

    fn request(
        &self,
        installation: Uuid,
        expected: Option<[u8; 32]>,
        deadline: Instant,
    ) -> Result<PendingCredential> {
        self.check_process()?;
        if Instant::now() >= deadline {
            return Err(IdentityError::Deadline);
        }
        let account = super::account(installation)?;
        let canceled = Arc::new(AtomicBool::new(false));
        let (reply, result) = mpsc::sync_channel(1);
        let request = Request {
            installation,
            expected,
            account,
            deadline,
            canceled: Arc::clone(&canceled),
            result: reply,
        };
        self.busy
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| IdentityError::Busy)?;
        if let Err(error) = self.requests.try_send(request) {
            self.busy.store(false, Ordering::Release);
            return Err(match error {
                mpsc::TrySendError::Full(_) => IdentityError::Busy,
                mpsc::TrySendError::Disconnected(_) => IdentityError::Unavailable,
            });
        }
        Ok(PendingCredential {
            result,
            canceled,
            deadline,
        })
    }
}

impl PendingCredential {
    pub fn wait(self) -> Result<CallerCredential> {
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        let result = self
            .result
            .recv_timeout(remaining)
            .map_err(|error| match error {
                mpsc::RecvTimeoutError::Timeout => IdentityError::Deadline,
                mpsc::RecvTimeoutError::Disconnected => IdentityError::Unavailable,
            })?;
        // A queued success cannot authorize a launch after its deadline.
        if Instant::now() >= self.deadline {
            return Err(IdentityError::Deadline);
        }
        result
    }
}

impl Drop for PendingCredential {
    fn drop(&mut self) {
        self.canceled.store(true, Ordering::Release);
    }
}

fn active(request: &Request) -> Result<()> {
    if request.canceled.load(Ordering::Acquire) {
        return Err(IdentityError::Canceled);
    }
    if Instant::now() >= request.deadline {
        return Err(IdentityError::Deadline);
    }
    Ok(())
}

fn execute(store: &dyn Store, request: &Request) -> Result<CallerCredential> {
    active(request)?;
    let seed = match (store.read(&request.account), request.expected) {
        (Ok(seed), Some(_)) => seed,
        (Ok(_), None) => return Err(IdentityError::Conflict),
        (Err(IdentityError::Missing), None) => {
            active(request)?;
            let mut seed = Zeroizing::new([0u8; 32]);
            rand::rng().fill_bytes(seed.as_mut());
            store.create(&request.account, seed.as_ref())?;
            active(request)?;
            let stored = store.read(&request.account)?;
            if !mvm_core::crypto::constant_time::constant_time_eq(stored.as_slice(), seed.as_ref())
            {
                return Err(IdentityError::Conflict);
            }
            stored
        }
        (Err(error), _) => return Err(error),
    };
    active(request)?;
    let exact: &[u8; 32] = seed
        .as_slice()
        .try_into()
        .map_err(|_| IdentityError::Conflict)?;
    let credential = CallerCredential {
        installation: request.installation,
        key: SigningKey::from_bytes(exact),
    };
    if request
        .expected
        .is_some_and(|key| key != credential.identity().public_key)
    {
        return Err(IdentityError::Conflict);
    }
    active(request)?;
    Ok(credential)
}
