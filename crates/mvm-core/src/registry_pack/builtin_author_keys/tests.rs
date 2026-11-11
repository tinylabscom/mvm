use super::*;
use crate::plan::bundle::FsTrustStore;
use ed25519_dalek::SigningKey;

const OFFICIAL_KEY_ID: &str = "b29ae91c7cbf09b08c3e9291d0a6655b";

fn empty_store() -> (tempfile::TempDir, FsTrustStore) {
    let dir = tempfile::tempdir().unwrap();
    let store = FsTrustStore::new(dir.path().join("trust"));
    (dir, store)
}

fn id(text: &str) -> KeyId {
    KeyId(text.to_string())
}

#[test]
fn the_embedded_key_matches_its_published_key_id() {
    let key = VerifyingKey::from_bytes(&OFFICIAL_BUNDLE_AUTHOR_KEYS[0]).unwrap();
    assert_eq!(key_id_from_pubkey(&key).0, OFFICIAL_KEY_ID);
}

#[test]
fn python_authority_is_separate_from_claude_and_operator_enrollment() {
    let claude = id(OFFICIAL_KEY_ID);
    assert!(!is_official_python_bundle_author_key(&claude));
    let operator = SigningKey::from_bytes(&[7; 32]).verifying_key();
    let key_id = key_id_from_pubkey(&operator);
    assert!(!is_official_python_bundle_author_key(&key_id));
    assert!(python_author_key_in(&key_id, &[operator.to_bytes()], &[]));
    assert!(!python_author_key_in(
        &key_id,
        &[operator.to_bytes()],
        &[key_id.0.as_str()],
    ));
}

#[test]
fn a_builtin_key_resolves_without_enrollment_and_writes_nothing() {
    let (_dir, store) = empty_store();
    let trust = BuiltinAuthorTrust::with_lists(&store, OFFICIAL_BUNDLE_AUTHOR_KEYS.to_vec(), &[]);
    let key = trust.lookup(&id(OFFICIAL_KEY_ID)).unwrap();
    assert_eq!(key.as_bytes(), &OFFICIAL_BUNDLE_AUTHOR_KEYS[0]);
    assert!(!store.root().exists());
}

#[test]
fn an_unknown_key_id_is_not_trusted() {
    let (_dir, store) = empty_store();
    let trust = BuiltinAuthorTrust::with_lists(&store, OFFICIAL_BUNDLE_AUTHOR_KEYS.to_vec(), &[]);
    assert!(trust.lookup(&id(&"0".repeat(32))).is_none());
}

#[test]
fn a_revoked_builtin_key_is_dropped_before_trust() {
    static REVOKED: &[&str] = &[OFFICIAL_KEY_ID];
    let (_dir, store) = empty_store();
    let trust =
        BuiltinAuthorTrust::with_lists(&store, OFFICIAL_BUNDLE_AUTHOR_KEYS.to_vec(), REVOKED);
    assert!(trust.lookup(&id(OFFICIAL_KEY_ID)).is_none());
    assert!(REVOKED_OFFICIAL_BUNDLE_AUTHOR_KEY_IDS.is_empty());
}

#[test]
fn operator_enrollment_stays_additive() {
    let (_dir, store) = empty_store();
    std::fs::create_dir(store.root()).unwrap();
    let key = SigningKey::from_bytes(&[7; 32]).verifying_key();
    let key_id = key_id_from_pubkey(&key);
    std::fs::write(
        store.root().join(format!("{}.pub", key_id.0)),
        key.as_bytes(),
    )
    .unwrap();
    let trust = BuiltinAuthorTrust::with_lists(&store, OFFICIAL_BUNDLE_AUTHOR_KEYS.to_vec(), &[]);
    assert_eq!(trust.lookup(&key_id).unwrap(), key);
    assert!(trust.lookup(&id(OFFICIAL_KEY_ID)).is_some());
}

#[test]
fn an_operator_policy_replaces_the_builtin_keys_wholesale() {
    use crate::registry_pack_store::load_publisher_policy_or_official_default;
    let dir = tempfile::tempdir().unwrap();
    let (_d, store) = empty_store();
    let official = load_publisher_policy_or_official_default(&dir.path().join("none")).unwrap();
    assert!(
        BuiltinAuthorTrust::for_policy(&store, &official)
            .lookup(&id(OFFICIAL_KEY_ID))
            .is_some()
    );
    let mut operator = official.clone();
    operator.source = PublisherPolicySource::OperatorFile;
    assert!(
        BuiltinAuthorTrust::for_policy(&store, &operator)
            .lookup(&id(OFFICIAL_KEY_ID))
            .is_none()
    );
}

#[test]
fn a_revoked_key_is_refused_even_when_an_operator_enrolled_it() {
    static REVOKED: &[&str] = &[OFFICIAL_KEY_ID];
    let (_dir, store) = empty_store();
    std::fs::create_dir(store.root()).unwrap();
    std::fs::write(
        store.root().join(format!("{OFFICIAL_KEY_ID}.pub")),
        OFFICIAL_BUNDLE_AUTHOR_KEYS[0],
    )
    .unwrap();
    assert!(store.lookup(&id(OFFICIAL_KEY_ID)).is_some());
    let trust = BuiltinAuthorTrust::with_lists(&store, Vec::new(), REVOKED);
    assert!(trust.lookup(&id(OFFICIAL_KEY_ID)).is_none());
}
