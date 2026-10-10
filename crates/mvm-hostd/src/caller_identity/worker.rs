use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::time::Instant;

use ed25519_dalek::SigningKey;
use rand::Rng as _;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::{CallerCredential, EnrolledIdentity, IdentityError, Result, Store};

/// One bounded worker per client; clone the client to share its single lane.
#[derive(Clone)]
pub struct IdentityClient {
    requests: mpsc::SyncSender<Request>,
    busy: Arc<AtomicBool>,
}

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
    pub fn native() -> Result<Self> {
        Self::start(super::native_store()?)
    }

    pub(super) fn start(store: Box<dyn Store>) -> Result<Self> {
        // The atomic lane excludes a second request even while the worker is
        // blocked in the OS. One channel slot avoids a startup scheduling race.
        let (requests, work) = mpsc::sync_channel::<Request>(1);
        let busy = Arc::new(AtomicBool::new(false));
        let occupied = Arc::clone(&busy);
        std::thread::Builder::new()
            .name("mvm-caller-identity".into())
            .spawn(move || {
                while let Ok(request) = work.recv() {
                    let credential = execute(store.as_ref(), &request);
                    occupied.store(false, Ordering::Release);
                    // A disconnected receiver drops and zeroizes a late key.
                    let _ = request.result.send(credential);
                }
            })
            .map_err(|_| IdentityError::Unavailable)?;
        Ok(Self { requests, busy })
    }

    /// Explicit first enrollment. Existing unpinned namespaces are conflicts;
    /// idempotent reuse requires `load` with the saved public enrollment pin.
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
