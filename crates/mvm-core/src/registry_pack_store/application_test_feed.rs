//! Explicit independent operator trust for isolated Core unit fixtures only.
//!
//! Descriptor authentication and feed signatures use private test seams. The
//! feed still passes the canonical parser, time/checkpoint checks and sealed
//! subject check. This is not a Sigstore or public-registry positive witness.

use chrono::{Duration, Utc};
use ed25519_dalek::{Signer, SigningKey};

use super::{RegistryPackStoreError, check_application_revocations_with};
use crate::packs::KeylessTrust;
use crate::registry_pack::VerifiedRegistryApplication;
use crate::registry_pack_revocation::verify_registry_pack_revocations_with;

const IDENTITY: &str = "independent-unit-feed";
const ISSUER: &str = "private-unit-Ed25519";

/// Called explicitly after the fixture has isolated its MVM_HOME.
pub(crate) fn configure() {
    let path = crate::config::registry_pack_revocation_trust_path();
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    crate::private_fs::set_mode(path.parent().unwrap(), 0o700).unwrap();
    std::fs::write(
        &path,
        format!("schema_version = 1\nissuer = '{ISSUER}'\naccepted_identities = ['{IDENTITY}']\n"),
    )
    .unwrap();
    crate::private_fs::set_mode(&path, 0o600).unwrap();
}

/// Inject only at a private per-call unit seam; production never calls this.
pub(crate) fn check(
    application: &VerifiedRegistryApplication,
) -> Result<(), RegistryPackStoreError> {
    let now = Utc::now();
    let key = SigningKey::from_bytes(&[73; 32]);
    let document = serde_json::to_vec(&serde_json::json!({
        "schema_version": 1,
        "sequence": 1,
        "issued_at": now - Duration::minutes(1),
        "not_after": now + Duration::hours(1),
        "revoked_identities": [],
        "revoked_manifests": [],
    }))
    .unwrap();
    let signature = key.sign(&document).to_bytes();
    check_application_revocations_with(
        application,
        &crate::config::registry_pack_revocation_trust_path(),
        now,
        |trust: &KeylessTrust, at| {
            verify_registry_pack_revocations_with(
                &document,
                &signature,
                trust,
                at,
                None,
                |bytes, signature, trust| {
                    if trust.issuer != ISSUER || trust.accepted_identities != [IDENTITY] {
                        return Err(
                            "unit feed trust differs from its explicitly configured identity"
                                .into(),
                        );
                    }
                    let signature = ed25519_dalek::Signature::from_slice(signature)
                        .map_err(|error| error.to_string())?;
                    key.verifying_key()
                        .verify_strict(bytes, &signature)
                        .map_err(|error| error.to_string())
                },
            )
            .map_err(RegistryPackStoreError::Revoked)
        },
    )
}
