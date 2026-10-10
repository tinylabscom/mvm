use super::*;
use std::sync::atomic::AtomicUsize;
use std::time::Duration;

struct PausedOnce {
    first_account: String,
    entered: mpsc::SyncSender<()>,
    release: mpsc::Receiver<()>,
    completed: mpsc::SyncSender<()>,
    reads: AtomicUsize,
}

impl Store for PausedOnce {
    fn read(&self, account: &str) -> Result<Zeroizing<Vec<u8>>> {
        if self.reads.fetch_add(1, Ordering::SeqCst) == 0 {
            self.entered.send(()).unwrap();
            self.release.recv().unwrap();
        }
        let seed = if account == self.first_account { 7 } else { 8 };
        Ok(Zeroizing::new(vec![seed; 32]))
    }
    fn create(&self, _: &str, _: &[u8]) -> Result<()> {
        panic!("pinned lookup cannot create")
    }
    fn completed(&self) {
        self.completed.send(()).unwrap();
    }
}

fn identity() -> EnrolledIdentity {
    EnrolledIdentity {
        installation: Uuid::new_v4(),
        public_key: SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes(),
    }
}

#[test]
fn factory_reconstruction_cannot_escape_a_timed_out_lane_and_recovers_after_release() {
    let factory = ClientFactory::new();
    let created = AtomicUsize::new(0);
    let (entered, observed) = mpsc::sync_channel(1);
    let (release, released) = mpsc::sync_channel(1);
    let (completed, processed) = mpsc::sync_channel(1);
    let pin = identity();
    let client = factory
        .get(|| {
            created.fetch_add(1, Ordering::SeqCst);
            Ok(Box::new(PausedOnce {
                first_account: super::super::account(pin.installation).unwrap(),
                entered,
                release: released,
                completed,
                reads: AtomicUsize::new(0),
            }))
        })
        .unwrap();
    let pending = client
        .load(&pin, Instant::now() + Duration::from_secs(5))
        .unwrap();
    observed.recv_timeout(Duration::from_secs(5)).unwrap();
    assert!(matches!(pending.wait(), Err(IdentityError::Deadline)));
    for _ in 0..64 {
        let repeated = factory
            .get(|| panic!("must not spawn another worker"))
            .unwrap();
        assert!(matches!(
            repeated
                .clone()
                .load(&pin, Instant::now() + Duration::from_secs(5)),
            Err(IdentityError::Busy)
        ));
    }
    assert_eq!(created.load(Ordering::SeqCst), 1);
    release.send(()).unwrap();
    processed.recv_timeout(Duration::from_secs(5)).unwrap();
    let reused = factory
        .get(|| panic!("must reuse recovered worker"))
        .unwrap();
    let key = reused
        .load(&pin, Instant::now() + Duration::from_secs(5))
        .unwrap()
        .wait()
        .unwrap();
    assert_eq!(key.identity(), pin);
    processed.recv_timeout(Duration::from_secs(5)).unwrap();
    let mut other = identity();
    other.public_key = SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes();
    let key = reused
        .load(&other, Instant::now() + Duration::from_secs(5))
        .unwrap()
        .wait()
        .unwrap();
    assert_eq!(key.identity(), other);
    processed.recv_timeout(Duration::from_secs(5)).unwrap();
}

struct Panics(mpsc::SyncSender<()>);
impl Store for Panics {
    fn read(&self, _: &str) -> Result<Zeroizing<Vec<u8>>> {
        panic!("synthetic native failure")
    }
    fn create(&self, _: &str, _: &[u8]) -> Result<()> {
        panic!("no enrollment")
    }
}
impl Drop for Panics {
    fn drop(&mut self) {
        let _ = self.0.send(());
    }
}

#[test]
fn a_dead_worker_is_not_respawned_and_post_fork_handles_are_refused() {
    let factory = ClientFactory::new();
    let (exited, observed) = mpsc::sync_channel(1);
    let client = factory.get(|| Ok(Box::new(Panics(exited)))).unwrap();
    let mut inherited = client.clone();
    inherited.owner_pid = inherited.owner_pid.wrapping_add(1);
    assert!(matches!(
        inherited.load(&identity(), Instant::now() + Duration::from_secs(5)),
        Err(IdentityError::Unavailable)
    ));
    let pending = client
        .load(&identity(), Instant::now() + Duration::from_secs(5))
        .unwrap();
    assert!(matches!(pending.wait(), Err(IdentityError::Unavailable)));
    observed.recv_timeout(Duration::from_secs(5)).unwrap();
    assert!(matches!(
        factory.get(|| panic!("dead worker must not respawn")),
        Err(IdentityError::Unavailable)
    ));
}
