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
    let trust = BuiltinAuthorTrust::with_lists(&none, keys.to_vec(), revoked);
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
    let trust = BuiltinAuthorTrust::with_lists(&none, keys.to_vec(), &[]);
    assert!(matches!(
        verify_application_bundle(&application, &source, &trust),
        Err(ApplicationBundleError::Digest)
    ));
}

mod installed_flow {
    use super::*;
    use crate::registry_pack_store::{LoadedPublisherPolicy, PublisherPolicySource};

    struct Flow {
        _directory: tempfile::TempDir,
        _environment: crate::util::test_env::TestEnv,
        store: ApplicationInstallStore,
        empty: FsTrustStore,
        key_id: String,
        bundle_sha256: String,
    }

    fn loaded(source: PublisherPolicySource) -> LoadedPublisherPolicy {
        LoadedPublisherPolicy {
            policy: publisher_policy(),
            source,
        }
    }

    /// Install an application signed by a throwaway "pinned" key with an empty
    /// consumer trust store: the only trust is the pinned list.
    fn install_without_enrollment() -> Flow {
        let (directory, bytes, enrolled, key_id) = fixture();
        let raw = std::fs::read(enrolled.root().join(format!("{key_id}.pub"))).unwrap();
        crate::registry_pack::register_test_author_key(raw.as_slice().try_into().unwrap());
        let mut environment = crate::util::test_env::TestEnv::new();
        environment.isolate_mvm_home(directory.path().join("home"));
        application_test_feed::configure();
        let empty = FsTrustStore::new(directory.path().join("no-keys"));
        let trust =
            BuiltinAuthorTrust::for_policy(&empty, &loaded(PublisherPolicySource::OfficialDefault));
        let source = directory.path().join("input.mvmpkg");
        std::fs::write(&source, &bytes).unwrap();
        let application = descriptor(&bytes, &key_id, |_| {});
        let verified = verify_application_bundle(&application, &source, &trust).unwrap();
        let store = ApplicationInstallStore::new(
            directory.path().join("descriptors"),
            directory.path().join("packs.lock.toml"),
            directory.path().join("bundles"),
        );
        install_with(
            &verified,
            &store,
            &publisher_policy(),
            &trust,
            accept_signature,
            crate::registry_pack_store::RegistryPackStoreLease::commit_application_pin,
        )
        .unwrap();
        assert!(!empty.root().exists(), "nothing was enrolled");
        Flow {
            bundle_sha256: sha256_hex(&bytes),
            _directory: directory,
            _environment: environment,
            store,
            empty,
            key_id,
        }
    }

    fn trust_for<'a>(
        flow: &'a Flow,
        sha: &str,
        source: PublisherPolicySource,
    ) -> BuiltinAuthorTrust<&'a FsTrustStore> {
        launch::trust_for_installed_bundle_with(
            &flow.empty,
            sha,
            &flow.store,
            Ok(loaded(source)),
            accept_signature,
        )
    }

    fn id(flow: &Flow) -> crate::plan::bundle::KeyId {
        crate::plan::bundle::KeyId(flow.key_id.clone())
    }

    #[test]
    fn an_application_installed_under_a_pinned_key_launches_without_enrollment() {
        use crate::plan::bundle::TrustStore;
        let flow = install_without_enrollment();
        let trust = trust_for(
            &flow,
            &flow.bundle_sha256,
            PublisherPolicySource::OfficialDefault,
        );
        assert!(trust.lookup(&id(&flow)).is_some());
        // The launch resolver and the canonical-plan/admission verifiers all
        // reach the archive through this one view.
        let archive =
            BundleRegistry::new(&flow.store.bundle_root).archive_path(&flow.bundle_sha256);
        crate::plan::bundle::verify_bundle_file(&archive, &trust).unwrap();
        launch::resolve_with_checks(
            &"runtime/python@1.2.3".parse().unwrap(),
            &flow.store,
            &publisher_policy(),
            &trust,
            accept_signature,
            application_test_feed::check,
        )
        .unwrap();
    }

    #[test]
    fn an_operator_policy_refuses_the_same_install_at_launch() {
        use crate::plan::bundle::TrustStore;
        let flow = install_without_enrollment();
        let trust = trust_for(
            &flow,
            &flow.bundle_sha256,
            PublisherPolicySource::OperatorFile,
        );
        assert!(trust.lookup(&id(&flow)).is_none());
        let archive =
            BundleRegistry::new(&flow.store.bundle_root).archive_path(&flow.bundle_sha256);
        assert!(crate::plan::bundle::verify_bundle_file(&archive, &trust).is_err());
    }

    #[test]
    fn a_bundle_that_is_not_an_installed_application_gets_no_pinned_keys() {
        use crate::plan::bundle::TrustStore;
        let flow = install_without_enrollment();
        let trust = trust_for(
            &flow,
            &"0".repeat(64),
            PublisherPolicySource::OfficialDefault,
        );
        assert!(trust.lookup(&id(&flow)).is_none());
    }

    #[test]
    fn a_failed_descriptor_authentication_gets_no_pinned_keys() {
        use crate::plan::bundle::TrustStore;
        let flow = install_without_enrollment();
        let trust = launch::trust_for_installed_bundle_with(
            &flow.empty,
            &flow.bundle_sha256,
            &flow.store,
            Ok(loaded(PublisherPolicySource::OfficialDefault)),
            crate::registry_pack::tests::reject_signature,
        );
        assert!(trust.lookup(&id(&flow)).is_none());
    }
}
