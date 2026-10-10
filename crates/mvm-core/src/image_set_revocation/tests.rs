use std::fs;

use chrono::TimeZone;

use super::*;
use crate::pack_trust::RevokedPack;
use crate::plan::bundle::key_id_from_identity;
use crate::release_trust::{
    accepted_image_set_identities, image_set_revocation_identity, revocation_keyless_trust,
};

/// A stand-in bundle: the fake signer "verifies" a bundle that names its
/// identity and refuses anything else, so the stages after the signature check
/// are reachable without the producer's signing certificate.
fn bundle_for(identity: &str) -> Vec<u8> {
    format!("signed-by:{identity}").into_bytes()
}

fn bundle_for_publication(publication: u64) -> Vec<u8> {
    bundle_for(&image_set_revocation_identity(publication))
}

fn fake_signer(_document: &[u8], bundle: &[u8]) -> Result<VerifiedSigner, String> {
    let bundle = std::str::from_utf8(bundle).map_err(|error| error.to_string())?;
    let identity = bundle
        .strip_prefix("signed-by:")
        .ok_or_else(|| "test signature rejected".to_string())?;
    Ok(VerifiedSigner {
        identity: identity.to_string(),
        issuer: RELEASE_OIDC_ISSUER.to_string(),
    })
}

fn at(day: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 10, day, 0, 0, 0)
        .single()
        .expect("valid date")
}

fn list(issued_at: DateTime<Utc>, not_after: DateTime<Utc>) -> PackRevocationList {
    PackRevocationList {
        schema_version: PACK_REVOCATION_SCHEMA_VERSION,
        revocations: Vec::new(),
        issued_at,
        not_after,
    }
}

fn document(list: &PackRevocationList) -> Vec<u8> {
    serde_json::to_vec(list).expect("serialize list")
}

fn verify(
    document: &[u8],
    bundle: &[u8],
    now: DateTime<Utc>,
    previous: Option<&ImageSetRevocationCheckpoint>,
) -> Result<VerifiedImageSetRevocations, ImageSetRevocationError> {
    verify_image_set_revocations_with(document, bundle, now, previous, fake_signer)
}

fn accepted(
    publication: u64,
    issued_at: DateTime<Utc>,
    entries: Vec<RevokedPack>,
) -> (Vec<u8>, ImageSetRevocationCheckpoint) {
    let mut body = list(issued_at, issued_at + Duration::days(30));
    body.revocations = entries;
    let bytes = document(&body);
    let verified = verify(
        &bytes,
        &bundle_for_publication(publication),
        issued_at,
        None,
    )
    .expect("baseline list verifies");
    (bytes, verified.checkpoint().clone())
}

fn image_set_signer_key_id() -> KeyId {
    let identity = accepted_image_set_identities("0.1.0")
        .pop()
        .expect("image-set identity");
    key_id_from_identity(&identity)
}

// --- authority ---------------------------------------------------------------

#[test]
fn a_list_from_the_revocation_workflow_tag_is_accepted() {
    let bytes = document(&list(at(1), at(20)));
    let verified = verify(&bytes, &bundle_for_publication(3), at(2), None).expect("accepted");
    assert_eq!(
        verified.checkpoint(),
        &ImageSetRevocationCheckpoint {
            publication: 3,
            issued_at: at(1),
            sha256: Sha256Hex::from_bytes(&bytes),
        }
    );
    assert_eq!(verified.signer_identity(), image_set_revocation_identity(3));
    assert_eq!(verified.not_after(), at(20));
    assert_eq!(verified.entry_count(), 0);
}

#[test]
fn every_other_signer_is_refused_even_with_a_valid_signature() {
    let bytes = document(&list(at(1), at(20)));
    let others = revocation_keyless_trust()
        .accepted_identities
        .into_iter()
        .chain(accepted_image_set_identities("0.1.0"))
        .chain([
            "https://github.com/tinylabscom/mvm-images/.github/workflows/revocations.yml@refs/heads/main"
                .to_string(),
        ]);
    for identity in others {
        let err = verify(&bytes, &bundle_for(&identity), at(2), None)
            .expect_err("a foreign signer must be refused");
        assert!(
            matches!(err, ImageSetRevocationError::UntrustedSigner { .. }),
            "{identity}: {err}"
        );
    }
}

#[test]
fn the_right_identity_under_another_issuer_is_refused() {
    let bytes = document(&list(at(1), at(20)));
    let err = verify_image_set_revocations_with(&bytes, b"", at(2), None, |_, _| {
        Ok(VerifiedSigner {
            identity: image_set_revocation_identity(1),
            issuer: "https://issuer.invalid".to_string(),
        })
    })
    .expect_err("issuer is part of the authority");
    assert!(matches!(
        err,
        ImageSetRevocationError::UntrustedSigner { .. }
    ));
}

#[test]
fn a_bad_signature_is_refused_before_the_document_is_parsed() {
    let err = verify(b"not json at all", b"forged", at(2), None).expect_err("refused");
    assert!(matches!(err, ImageSetRevocationError::SignatureInvalid(_)));
}

#[test]
fn oversized_inputs_are_refused_before_signature_verification() {
    let huge = vec![b' '; MAX_DOCUMENT_BYTES + 1];
    let err = verify_image_set_revocations_with(&huge, b"", at(2), None, |_, _| {
        panic!("the signer must not see an oversized document")
    })
    .expect_err("refused");
    assert_eq!(err, ImageSetRevocationError::TooLarge);
}

#[test]
fn a_registry_pack_revocation_document_is_not_an_image_set_list() {
    let registry_document = serde_json::json!({
        "schema_version": 1,
        "sequence": 1,
        "issued_at": at(1),
        "not_after": at(2),
        "revoked_identities": [],
        "revoked_manifests": []
    })
    .to_string();
    let err = verify(
        registry_document.as_bytes(),
        &bundle_for_publication(1),
        at(1) + Duration::hours(1),
        None,
    )
    .expect_err("a different feed's format is refused");
    assert!(matches!(err, ImageSetRevocationError::Parse(_)), "{err}");
}

// --- freshness ---------------------------------------------------------------

#[test]
fn an_unsupported_schema_is_refused() {
    let mut body = list(at(1), at(20));
    body.schema_version = PACK_REVOCATION_SCHEMA_VERSION + 1;
    let err =
        verify(&document(&body), &bundle_for_publication(1), at(2), None).expect_err("refused");
    assert!(matches!(
        err,
        ImageSetRevocationError::UnsupportedSchema { .. }
    ));
}

#[test]
fn a_list_is_usable_only_inside_its_own_window() {
    let bytes = document(&list(at(5), at(10)));
    let bundle = bundle_for_publication(1);
    assert!(matches!(
        verify(&bytes, &bundle, at(4), None),
        Err(ImageSetRevocationError::IssuedInFuture { .. })
    ));
    assert!(verify(&bytes, &bundle, at(5), None).is_ok());
    assert!(verify(&bytes, &bundle, at(10) - Duration::seconds(1), None).is_ok());
    let err = verify(&bytes, &bundle, at(10), None).expect_err("expired at not_after");
    assert!(matches!(err, ImageSetRevocationError::Expired { .. }));
    assert!(
        err.to_string().contains(IMAGE_SET_REVOCATION_CHANNEL),
        "an expiry says where the current list is: {err}"
    );
}

#[test]
fn an_inverted_or_overlong_window_is_refused() {
    let bundle = bundle_for_publication(1);
    assert_eq!(
        verify(&document(&list(at(5), at(5))), &bundle, at(5), None).expect_err("empty window"),
        ImageSetRevocationError::InvalidValidityWindow
    );
    let overlong = list(
        at(1),
        at(1) + MAX_IMAGE_SET_REVOCATION_VALIDITY + Duration::seconds(1),
    );
    assert_eq!(
        verify(&document(&overlong), &bundle, at(2), None).expect_err("overlong"),
        ImageSetRevocationError::ValidityTooLong
    );
    let longest = list(at(1), at(1) + MAX_IMAGE_SET_REVOCATION_VALIDITY);
    assert!(verify(&document(&longest), &bundle, at(2), None).is_ok());
}

// --- monotonicity ------------------------------------------------------------

#[test]
fn the_same_bytes_are_accepted_again() {
    let (bytes, checkpoint) = accepted(2, at(3), Vec::new());
    let again =
        verify(&bytes, &bundle_for_publication(2), at(4), Some(&checkpoint)).expect("idempotent");
    assert_eq!(again.checkpoint(), &checkpoint);
}

#[test]
fn a_later_publication_advances_the_checkpoint() {
    let (_, checkpoint) = accepted(2, at(3), Vec::new());
    let next = document(&list(at(4), at(20)));
    let verified =
        verify(&next, &bundle_for_publication(3), at(5), Some(&checkpoint)).expect("advance");
    assert!(verified.checkpoint().supersedes(&checkpoint));
    assert!(!checkpoint.supersedes(verified.checkpoint()));
}

#[test]
fn a_contradicting_checkpoint_never_supersedes() {
    let (_, checkpoint) = accepted(5, at(10), Vec::new());
    let same_publication = ImageSetRevocationCheckpoint {
        issued_at: at(11),
        sha256: Sha256Hex::from_bytes(b"different list"),
        ..checkpoint.clone()
    };
    assert!(!same_publication.supersedes(&checkpoint));
    assert!(!checkpoint.supersedes(&checkpoint));
}

#[test]
fn an_older_publication_or_issue_time_is_rollback() {
    let (_, checkpoint) = accepted(5, at(10), Vec::new());
    let older_time = document(&list(at(9), at(20)));
    assert!(matches!(
        verify(
            &older_time,
            &bundle_for_publication(6),
            at(11),
            Some(&checkpoint)
        ),
        Err(ImageSetRevocationError::Rollback { .. })
    ));
    let newer_time = document(&list(at(11), at(20)));
    assert!(matches!(
        verify(
            &newer_time,
            &bundle_for_publication(4),
            at(12),
            Some(&checkpoint)
        ),
        Err(ImageSetRevocationError::Rollback { .. })
    ));
}

#[test]
fn a_second_list_at_the_same_publication_or_time_is_equivocation() {
    let (_, checkpoint) = accepted(5, at(10), Vec::new());
    let same_publication = document(&list(at(11), at(20)));
    assert!(matches!(
        verify(
            &same_publication,
            &bundle_for_publication(5),
            at(12),
            Some(&checkpoint)
        ),
        Err(ImageSetRevocationError::Equivocation { .. })
    ));
    let mut same_time = list(at(10), at(21));
    same_time.revocations.push(RevokedPack {
        key_id: image_set_signer_key_id(),
        pack_hash: None,
        reason: "withdrawn".to_string(),
    });
    assert!(matches!(
        verify(
            &document(&same_time),
            &bundle_for_publication(6),
            at(12),
            Some(&checkpoint)
        ),
        Err(ImageSetRevocationError::Equivocation { .. })
    ));
}

// --- what a verified list revokes ---------------------------------------------

#[test]
fn a_whole_key_entry_revokes_the_set_and_every_member() {
    let signer = image_set_signer_key_id();
    let (bytes, _) = accepted(
        1,
        at(1),
        vec![RevokedPack {
            key_id: signer.clone(),
            pack_hash: None,
            reason: "signing workflow compromised".to_string(),
        }],
    );
    let verified = verify(&bytes, &bundle_for_publication(1), at(2), None).expect("verified");
    for digest in [b"set manifest".as_slice(), b"kernel member"] {
        assert_eq!(
            verified.status(&signer, &Sha256Hex::from_bytes(digest)),
            RevocationStatus::Revoked {
                reason: "signing workflow compromised".to_string()
            }
        );
    }
}

#[test]
fn a_member_entry_revokes_only_that_member() {
    let signer = image_set_signer_key_id();
    let bad = Sha256Hex::from_bytes(b"bad member");
    let (bytes, _) = accepted(
        1,
        at(1),
        vec![RevokedPack {
            key_id: signer.clone(),
            pack_hash: Some(bad.clone()),
            reason: "bad kernel".to_string(),
        }],
    );
    let verified = verify(&bytes, &bundle_for_publication(1), at(2), None).expect("verified");
    assert!(matches!(
        verified.status(&signer, &bad),
        RevocationStatus::Revoked { .. }
    ));
    assert_eq!(
        verified.status(&signer, &Sha256Hex::from_bytes(b"other member")),
        RevocationStatus::Good
    );
    let other_signer = key_id_from_identity(&accepted_image_set_identities("0.2.0")[0]);
    assert_eq!(verified.status(&other_signer, &bad), RevocationStatus::Good);
}

/// The producer documents the key id its revocation entries use for the first
/// image-set release. Revocation keys on the lock's signer through the same
/// derivation, so a mismatch here would make every published entry inert.
#[test]
fn the_producer_documented_key_id_is_the_one_admission_derives() {
    assert_eq!(
        image_set_signer_key_id().0,
        "6996feb9248dd8eee1e335470cbff52a"
    );
}

// --- the prepared store ----------------------------------------------------------

fn store_in(dir: &tempfile::TempDir) -> ImageSetRevocationStore {
    ImageSetRevocationStore::new(dir.path().join("image-set-revocations"))
        .with_signer_check(fake_signer)
}

#[test]
fn an_unprepared_store_is_missing_not_empty() {
    let dir = tempfile::tempdir().expect("tempdir");
    let err = store_in(&dir).load(at(2)).expect_err("missing");
    assert!(matches!(err, ImageSetRevocationStoreError::Missing));
    let message = err.to_string();
    assert!(
        message.contains("mvmctl image revocations update"),
        "{message}"
    );
    assert!(message.contains(IMAGE_SET_REVOCATION_CHANNEL), "{message}");
}

#[test]
fn an_applied_list_loads_back_with_private_files() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = store_in(&dir);
    let bytes = document(&list(at(1), at(20)));
    let checkpoint = store
        .update(&bytes, &bundle_for_publication(1), at(2))
        .expect("update");
    let loaded = store.load(at(3)).expect("load");
    assert_eq!(loaded.checkpoint(), &checkpoint);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        for path in [store.checkpoint_path(), store.state_path()] {
            let mode = fs::metadata(path).expect("metadata").permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }
}

#[test]
fn an_applied_list_goes_stale_at_load() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = store_in(&dir);
    store
        .update(
            &document(&list(at(1), at(5))),
            &bundle_for_publication(1),
            at(2),
        )
        .expect("update");
    assert!(matches!(
        store.load(at(5)),
        Err(ImageSetRevocationStoreError::Verification(
            ImageSetRevocationError::Expired { .. }
        ))
    ));
}

#[test]
fn rollback_and_wrong_signer_leave_the_store_untouched() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = store_in(&dir);
    store
        .update(
            &document(&list(at(5), at(20))),
            &bundle_for_publication(4),
            at(6),
        )
        .expect("update");
    let before = fs::read(store.state_path()).expect("state");
    let older = document(&list(at(4), at(20)));
    assert!(matches!(
        store.update(&older, &bundle_for_publication(3), at(6)),
        Err(ImageSetRevocationStoreError::Verification(
            ImageSetRevocationError::Rollback { .. }
        ))
    ));
    let foreign = bundle_for(&revocation_keyless_trust().accepted_identities[0]);
    assert!(matches!(
        store.update(&document(&list(at(6), at(20))), &foreign, at(7)),
        Err(ImageSetRevocationStoreError::Verification(
            ImageSetRevocationError::UntrustedSigner { .. }
        ))
    ));
    assert_eq!(fs::read(store.state_path()).expect("state"), before);
}

#[test]
fn deleting_the_checkpoint_does_not_reopen_rollback() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = store_in(&dir);
    store
        .update(
            &document(&list(at(5), at(20))),
            &bundle_for_publication(4),
            at(6),
        )
        .expect("update");
    fs::remove_file(store.checkpoint_path()).expect("remove checkpoint");
    assert!(matches!(
        store.load(at(6)),
        Err(ImageSetRevocationStoreError::Incomplete)
    ));
    assert!(matches!(
        store.update(
            &document(&list(at(1), at(20))),
            &bundle_for_publication(1),
            at(6)
        ),
        Err(ImageSetRevocationStoreError::Incomplete)
    ));
}

#[test]
fn a_modified_cache_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = store_in(&dir);
    store
        .update(
            &document(&list(at(5), at(20))),
            &bundle_for_publication(4),
            at(6),
        )
        .expect("update");
    let mut state: crate::signed_feed_store::StoredFeed<ImageSetRevocationCheckpoint> =
        serde_json::from_slice(&fs::read(store.state_path()).expect("read")).expect("parse");
    state.document_base64 = {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(document(&list(at(5), at(19))))
    };
    fs::write(
        store.state_path(),
        serde_json::to_vec(&state).expect("serialize"),
    )
    .expect("tamper");
    assert!(matches!(
        store.load(at(6)),
        Err(ImageSetRevocationStoreError::Corrupt)
    ));
}

#[test]
fn an_interrupted_update_is_repaired_only_by_a_verified_refresh() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = store_in(&dir);
    store
        .update(
            &document(&list(at(5), at(20))),
            &bundle_for_publication(1),
            at(6),
        )
        .expect("first");
    let next = document(&list(at(6), at(20)));
    let next_checkpoint = verify(&next, &bundle_for_publication(2), at(7), None)
        .expect("verified")
        .checkpoint()
        .clone();
    crate::util::atomic_io::write_private(
        &store.checkpoint_path(),
        &serde_json::to_vec(&next_checkpoint).expect("serialize"),
    )
    .expect("simulate a crash after the checkpoint write");
    assert!(matches!(
        store.load(at(7)),
        Err(ImageSetRevocationStoreError::Incomplete)
    ));
    store
        .update(&next, &bundle_for_publication(2), at(7))
        .expect("verified refresh");
    assert_eq!(
        store.load(at(7)).expect("repaired").checkpoint(),
        &next_checkpoint
    );
}

#[test]
fn image_set_and_registry_pack_feeds_never_share_a_directory() {
    assert_ne!(
        crate::config::image_set_revocation_store_dir(),
        crate::config::registry_pack_revocation_store_dir()
    );
    assert!(
        !crate::config::image_set_revocation_store_dir()
            .starts_with(crate::config::registry_pack_revocation_store_dir())
    );
}

// --- the published list ------------------------------------------------------------

#[cfg(feature = "manifest-verify")]
mod published {
    use super::*;

    const DOCUMENT: &[u8] = include_bytes!(
        "../../tests/fixtures/image-set-revocations/revocation-list-v1/revocations.json"
    );
    const BUNDLE: &[u8] = include_bytes!(
        "../../tests/fixtures/image-set-revocations/revocation-list-v1/revocations.json.bundle"
    );

    /// Inside the published list's window (2026-09-24 to 2026-11-08).
    fn inside_window() -> DateTime<Utc> {
        at(1)
    }

    #[test]
    fn the_published_list_verifies_under_the_producer_identity() {
        let verified = verify_image_set_revocations(DOCUMENT, BUNDLE, inside_window(), None)
            .expect("the published revocation-list/v1 signature must verify");
        assert_eq!(verified.checkpoint().publication, 1);
        assert_eq!(verified.signer_identity(), image_set_revocation_identity(1));
        assert_eq!(verified.entry_count(), 0);
    }

    #[test]
    fn a_byte_flip_in_the_published_list_fails_its_signature() {
        let mut tampered = DOCUMENT.to_vec();
        let last = tampered.len() - 2;
        tampered[last] ^= 0x01;
        assert!(matches!(
            verify_image_set_revocations(&tampered, BUNDLE, inside_window(), None),
            Err(ImageSetRevocationError::SignatureInvalid(_))
        ));
    }

    #[test]
    fn the_published_bundle_does_not_vouch_for_another_feed() {
        let err = crate::registry_pack_revocation::verify_registry_pack_revocations(
            DOCUMENT,
            BUNDLE,
            &revocation_keyless_trust(),
            inside_window(),
            None,
        )
        .expect_err("an image-set revocation signature is not a registry-pack one");
        assert!(matches!(
            err,
            crate::registry_pack_revocation::RegistryPackRevocationError::SignatureInvalid(_)
        ));
    }

    #[test]
    fn the_published_list_is_refused_once_stale_or_rolled_back() {
        let after = Utc
            .with_ymd_and_hms(2026, 11, 8, 14, 35, 3)
            .single()
            .expect("date");
        assert!(matches!(
            verify_image_set_revocations(DOCUMENT, BUNDLE, after, None),
            Err(ImageSetRevocationError::Expired { .. })
        ));
        let later = ImageSetRevocationCheckpoint {
            publication: 2,
            issued_at: inside_window(),
            sha256: Sha256Hex::from_bytes(b"a later list"),
        };
        assert!(matches!(
            verify_image_set_revocations(DOCUMENT, BUNDLE, inside_window(), Some(&later)),
            Err(ImageSetRevocationError::Rollback { .. })
        ));
    }

    #[test]
    fn the_published_list_round_trips_through_the_store() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = ImageSetRevocationStore::new(dir.path().join("image-set-revocations"));
        let checkpoint = store
            .update(DOCUMENT, BUNDLE, inside_window())
            .expect("apply the published list");
        assert_eq!(
            store.load(inside_window()).expect("load").checkpoint(),
            &checkpoint
        );
    }
}
