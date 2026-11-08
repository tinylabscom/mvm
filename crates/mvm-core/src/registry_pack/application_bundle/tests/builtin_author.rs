use super::*;
use crate::registry_pack::BuiltinAuthorTrust;

/// A bundle signed by a fresh key that this test declares "built in".
fn builtin_fixture() -> (tempfile::TempDir, Vec<u8>, &'static [[u8; 32]], String) {
    let (directory, bytes, trust, key_id) = fixture();
    let raw = std::fs::read(trust.root().join(format!("{key_id}.pub"))).unwrap();
    let keys: &'static [[u8; 32]] =
        Box::leak(vec![<[u8; 32]>::try_from(raw.as_slice()).unwrap()].into_boxed_slice());
    (directory, bytes, keys, key_id)
}

fn verify(
    directory: &tempfile::TempDir,
    bytes: &[u8],
    key_id: &str,
    keys: &'static [[u8; 32]],
    revoked: &'static [&'static str],
) -> Result<VerifiedApplicationBundle, ApplicationBundleError> {
    let source = directory.path().join("builtin.mvmpkg");
    std::fs::write(&source, bytes).unwrap();
    let none = FsTrustStore::new(directory.path().join("no-keys"));
    let trust = BuiltinAuthorTrust::with_lists(&none, keys, revoked);
    let application = descriptor(bytes, key_id, |_| {});
    let held = verify_application_bundle(&application, &source, &trust)?;
    assert!(!none.root().exists(), "nothing is enrolled");
    held.reverify(&trust)?;
    Ok(held)
}

#[test]
fn a_builtin_author_key_verifies_with_no_enrollment() {
    let (d, bytes, keys, key_id) = builtin_fixture();
    verify(&d, &bytes, &key_id, keys, &[]).unwrap();
}

#[test]
fn a_key_id_outside_the_builtin_list_is_refused() {
    let (d, bytes, _keys, key_id) = builtin_fixture();
    assert!(verify(&d, &bytes, &key_id, &[], &[]).is_err());
}

#[test]
fn a_host_signed_bundle_is_not_in_the_builtin_list_and_is_refused() {
    let (d, bytes, _keys, key_id) = builtin_fixture();
    let (_d2, _b2, other_keys, _other_id) = builtin_fixture();
    assert!(verify(&d, &bytes, &key_id, other_keys, &[]).is_err());
}

#[test]
fn a_builtin_key_id_with_a_signature_by_another_key_is_refused() {
    let (d, bytes, _keys, _id) = builtin_fixture();
    let (_d2, _b2, other_keys, other_id) = builtin_fixture();
    // The list names `other_id`, but `bytes` was signed by a different key.
    assert!(verify(&d, &bytes, &other_id, other_keys, &[]).is_err());
}

#[test]
fn a_revoked_builtin_key_is_refused() {
    let (d, bytes, keys, key_id) = builtin_fixture();
    let leaked: &'static str = Box::leak(key_id.clone().into_boxed_str());
    let revoked: &'static [&'static str] = Box::leak(vec![leaked].into_boxed_slice());
    assert!(verify(&d, &bytes, &key_id, keys, revoked).is_err());
}

#[test]
fn a_descriptor_naming_another_key_id_is_a_key_mismatch() {
    let (d, bytes, keys, _key_id) = builtin_fixture();
    let error = verify(&d, &bytes, &"0".repeat(32), keys, &[]).unwrap_err();
    assert!(!matches!(error, ApplicationBundleError::Digest));
}

#[test]
fn a_tampered_archive_is_refused_even_under_a_builtin_key() {
    let (d, mut bytes, keys, key_id) = builtin_fixture();
    let source = d.path().join("t.mvmpkg");
    let application = descriptor(&bytes, &key_id, |_| {});
    let middle = bytes.len() / 2;
    bytes[middle] ^= 1;
    std::fs::write(&source, &bytes).unwrap();
    let none = FsTrustStore::new(d.path().join("no-keys"));
    let trust = BuiltinAuthorTrust::with_lists(&none, keys, &[]);
    assert!(matches!(
        verify_application_bundle(&application, &source, &trust),
        Err(ApplicationBundleError::Digest)
    ));
}
