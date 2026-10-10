use super::*;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

#[derive(Clone, Default)]
struct MemoryStore(Arc<Mutex<HashMap<String, Zeroizing<Vec<u8>>>>>);
impl Store for MemoryStore {
    fn read(&self, account: &str) -> Result<Zeroizing<Vec<u8>>> {
        self.0
            .lock()
            .unwrap()
            .get(account)
            .cloned()
            .ok_or(IdentityError::Missing)
    }
    fn create(&self, account: &str, seed: &[u8]) -> Result<()> {
        let mut values = self.0.lock().unwrap();
        if values.contains_key(account) {
            return Err(IdentityError::Conflict);
        }
        values.insert(account.into(), Zeroizing::new(seed.to_vec()));
        Ok(())
    }
}

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(5)
}
fn enrolled(client: &IdentityClient) -> EnrolledIdentity {
    client
        .enroll(Uuid::new_v4(), deadline())
        .unwrap()
        .wait()
        .unwrap()
        .identity()
}

#[test]
fn enrollment_loads_exact_pin_and_does_not_replace_an_existing_key() {
    let store = MemoryStore::default();
    let client = IdentityClient::start(Box::new(store.clone())).unwrap();
    let identity = enrolled(&client);
    assert_eq!(
        client
            .load(&identity, deadline())
            .unwrap()
            .wait()
            .unwrap()
            .identity(),
        identity
    );
    assert!(matches!(
        client
            .enroll(identity.installation, deadline())
            .unwrap()
            .wait(),
        Err(IdentityError::Conflict)
    ));
    assert_eq!(store.0.lock().unwrap().len(), 1);
    assert_eq!(
        client
            .load(&identity, deadline())
            .unwrap()
            .wait()
            .unwrap()
            .identity(),
        identity
    );
}

#[test]
fn missing_wrong_namespace_wrong_key_and_malformed_seed_refuse_without_repair() {
    let store = MemoryStore::default();
    let client = IdentityClient::start(Box::new(store.clone())).unwrap();
    let identity = enrolled(&client);
    let mut changed = identity.clone();
    changed.public_key[0] ^= 1;
    assert!(matches!(
        client.load(&changed, deadline()).unwrap().wait(),
        Err(IdentityError::Conflict)
    ));
    changed = identity.clone();
    changed.installation = Uuid::new_v4();
    assert!(matches!(
        client.load(&changed, deadline()).unwrap().wait(),
        Err(IdentityError::Missing)
    ));
    store.0.lock().unwrap().insert(
        account(identity.installation).unwrap(),
        Zeroizing::new(vec![0; 31]),
    );
    assert!(matches!(
        client.load(&identity, deadline()).unwrap().wait(),
        Err(IdentityError::Conflict)
    ));
    store.0.lock().unwrap().clear();
    assert!(matches!(
        client.load(&identity, deadline()).unwrap().wait(),
        Err(IdentityError::Missing)
    ));
    assert!(store.0.lock().unwrap().is_empty());
}

#[test]
fn public_record_roundtrips_and_namespace_is_not_a_path() {
    let client = IdentityClient::start(Box::new(MemoryStore::default())).unwrap();
    let identity = enrolled(&client);
    let json = serde_json::to_vec(&identity).unwrap();
    assert_eq!(
        serde_json::from_slice::<EnrolledIdentity>(&json).unwrap(),
        identity
    );
    assert!(
        account(identity.installation)
            .unwrap()
            .ends_with(":entrypoint-caller:ed25519:v1")
    );
    assert!(matches!(account(Uuid::nil()), Err(IdentityError::Conflict)));
    assert!(serde_json::from_value::<EnrolledIdentity>(serde_json::json!({
        "installation": identity.installation, "public_key": identity.public_key, "backend": "mock"
    })).is_err());
}

struct Unavailable;
impl Store for Unavailable {
    fn read(&self, _: &str) -> Result<Zeroizing<Vec<u8>>> {
        Err(IdentityError::Unavailable)
    }
    fn create(&self, _: &str, _: &[u8]) -> Result<()> {
        panic!("unavailability must not create a fallback")
    }
}

#[test]
fn unavailable_refuses_without_fallback() {
    let client = IdentityClient::start(Box::new(Unavailable)).unwrap();
    assert!(matches!(
        client.enroll(Uuid::new_v4(), deadline()).unwrap().wait(),
        Err(IdentityError::Unavailable)
    ));
}

struct BlockedStore {
    entered: mpsc::SyncSender<()>,
    release: mpsc::Receiver<()>,
    finished: mpsc::SyncSender<()>,
}
impl Store for BlockedStore {
    fn read(&self, _: &str) -> Result<Zeroizing<Vec<u8>>> {
        self.entered.send(()).unwrap();
        self.release.recv().unwrap();
        Ok(Zeroizing::new(vec![9; 32]))
    }
    fn create(&self, _: &str, _: &[u8]) -> Result<()> {
        panic!("load may not enroll")
    }
}
impl Drop for BlockedStore {
    fn drop(&mut self) {
        let _ = self.finished.send(());
    }
}
fn blocked() -> (
    IdentityClient,
    mpsc::Receiver<()>,
    mpsc::SyncSender<()>,
    mpsc::Receiver<()>,
) {
    let (entered, observed) = mpsc::sync_channel(1);
    let (release, released) = mpsc::sync_channel(1);
    let (finished, exited) = mpsc::sync_channel(1);
    let client = IdentityClient::start(Box::new(BlockedStore {
        entered,
        release: released,
        finished,
    }))
    .unwrap();
    (client, observed, release, exited)
}
fn pinned() -> EnrolledIdentity {
    EnrolledIdentity {
        installation: Uuid::new_v4(),
        public_key: SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes(),
    }
}

#[test]
fn a_blocked_native_call_keeps_one_lane_even_after_cancel() {
    let (client, entered, release, exited) = blocked();
    let identity = pinned();
    let pending = client.load(&identity, deadline()).unwrap();
    entered.recv_timeout(Duration::from_secs(5)).unwrap();
    drop(pending);
    for _ in 0..64 {
        assert!(matches!(
            client.clone().load(&identity, deadline()),
            Err(IdentityError::Busy)
        ));
    }
    drop(client);
    release.send(()).unwrap();
    exited.recv_timeout(Duration::from_secs(5)).unwrap();
}

#[test]
fn a_deadline_does_not_cancel_the_os_call_or_allow_a_late_key() {
    let (client, entered, release, exited) = blocked();
    let identity = pinned();
    let pending = client.load(&identity, deadline()).unwrap();
    entered.recv_timeout(Duration::from_secs(5)).unwrap();
    assert!(matches!(pending.wait(), Err(IdentityError::Deadline)));
    assert!(matches!(
        client.load(&identity, deadline()),
        Err(IdentityError::Busy)
    ));
    drop(client);
    release.send(()).unwrap();
    exited.recv_timeout(Duration::from_secs(5)).unwrap();
}

#[test]
fn an_expired_request_never_reaches_the_store() {
    let client = IdentityClient::start(Box::new(Unavailable)).unwrap();
    assert!(matches!(
        client.enroll(Uuid::new_v4(), Instant::now()),
        Err(IdentityError::Deadline)
    ));
}

#[test]
fn loaded_and_late_key_types_have_zeroizing_drop_contracts() {
    fn zeroizes_on_drop<T: zeroize::ZeroizeOnDrop>() {}
    zeroizes_on_drop::<SigningKey>();
    zeroizes_on_drop::<Zeroizing<Vec<u8>>>();
}

#[test]
fn dedicated_native_feature_does_not_flip_the_legacy_keyring_factory() {
    let entry = keyring::Entry::new_with_target(
        "mvm-tenant-secrets",
        "com.tinylabs.mvm.test.factory-selection",
        "no-store-operation",
    )
    .unwrap();
    assert!(entry.get_credential().is::<keyring::mock::MockCredential>());
}

#[test]
fn competing_enrollment_never_overwrites_the_winner() {
    let store = MemoryStore::default();
    let first = IdentityClient::start(Box::new(store.clone())).unwrap();
    let second = IdentityClient::start(Box::new(store.clone())).unwrap();
    let installation = Uuid::new_v4();
    let a = first.enroll(installation, deadline()).unwrap();
    let b = second.enroll(installation, deadline()).unwrap();
    let winner = match (a.wait(), b.wait()) {
        (Ok(key), Err(IdentityError::Conflict)) | (Err(IdentityError::Conflict), Ok(key)) => key,
        _ => panic!("enrollment must select exactly one immutable key"),
    };
    let pin = winner.identity();
    assert_eq!(store.0.lock().unwrap().len(), 1);
    assert_eq!(
        first
            .load(&pin, deadline())
            .unwrap()
            .wait()
            .unwrap()
            .identity(),
        pin
    );
}

#[test]
fn a_pinned_worker_result_proves_only_its_exact_registration_identity() {
    use mvm_core::crypto::entrypoint_delegation::{
        DelegationError, RegistrationBinding, RegistrationChallenge,
    };
    let client = IdentityClient::start(Box::new(MemoryStore::default())).unwrap();
    let identity = enrolled(&client);
    let credential = client.load(&identity, deadline()).unwrap().wait().unwrap();
    let challenge = RegistrationChallenge::fresh(
        RegistrationBinding {
            tenant: "test-tenant".into(),
            instance: Uuid::new_v4().to_string(),
            plan_id: "test-plan".into(),
            plan_nonce: mvm_core::plan::Nonce::from_bytes([4; 16]),
            run: Uuid::new_v4(),
            producer: Uuid::new_v4(),
            session: Uuid::new_v4(),
            not_before: 100,
            not_after: 200,
        },
        identity,
        100,
    )
    .unwrap();
    let proof = credential.prove_registration(&challenge, 100).unwrap();
    assert_eq!(
        proof.verify(&challenge, 100).unwrap().challenge(),
        &challenge
    );
    let mut swapped = challenge;
    swapped.identity.installation = Uuid::new_v4();
    assert!(matches!(
        credential.prove_registration(&swapped, 100),
        Err(DelegationError::Binding)
    ));
}

#[cfg(not(all(
    feature = "native-caller-identity",
    any(target_os = "macos", target_os = "linux")
)))]
#[test]
fn no_native_build_refuses_instead_of_selecting_mock() {
    assert!(matches!(
        IdentityClient::native(),
        Err(IdentityError::Unsupported)
    ));
}
