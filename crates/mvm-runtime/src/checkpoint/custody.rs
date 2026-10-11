//! Key custody for protected checkpoints.
//!
//! A protected checkpoint is sealed under the keys of its key domain
//! ([`DomainKeys`]). Custody decides where those keys come from; the object
//! envelope and the storage layer never fetch, derive, or hold one.
//!
//! The host's custody ([`HostKeyCustody`]) resolves a 32-byte root per domain
//! through the same ordered sources instance snapshots use
//! ([`SnapshotKeyResolver`]), and keeps the two kinds of domain apart:
//!
//! * the **host** domain — factory parents, warm-pool standbys, and every
//!   checkpoint of a VM admitted under no tenant — uses the host's snapshot
//!   key, the root `machine pause` already requires;
//! * a **tenant** domain uses that tenant's own key, looked up under the
//!   tenant's id (`MVM_TENANT_KEY_<TENANT>`, the keystore entry
//!   `mvm/<tenant>`, or `/var/lib/mvm/keys/<tenant>.key`), and never falls
//!   back to the host's key.
//!
//! The wrapping and reference keys are derived from the root with HMAC-SHA256
//! under distinct labels and the domain's name, so two domains never share a
//! key even if an operator provisions both from the same root, and a domain's
//! two keys are never the same bytes.
//!
//! Every refusal names the domain and what to provision, and never carries
//! key material or a provider's own error text.

use std::fmt;
use std::sync::Arc;

use anyhow::Context as _;

use hmac::{Hmac, KeyInit, Mac};
use mvm_core::checkpoint::{CheckpointKeyDomain, CheckpointMeta};
use mvm_core::crypto::aead;
use mvm_core::crypto::checkpoint_object::{DomainKeys, REFERENCE_LEN, ReferenceKey};
use mvm_core::crypto::keystore::{DEFAULT_KEYS_DIR, EnvKeyProvider};
use sha2::Sha256;
use zeroize::Zeroizing;

use super::CheckpointStore;
use crate::vm::snapshot_key::{
    SNAPSHOT_TENANT_ID, SnapshotKey, SnapshotKeyError, SnapshotKeyResolver, SnapshotKeySource,
};

const WRAPPING_LABEL: &[u8] = b"mvm.checkpoint.custody.wrapping.v1\0";
const REFERENCE_LABEL: &[u8] = b"mvm.checkpoint.custody.reference.v1\0";

/// Supplies the keys a protected checkpoint is sealed and opened under.
///
/// Implemented by the host ([`HostKeyCustody`]) and by an embedder that
/// holds keys elsewhere. An implementation must refuse rather than substitute
/// another domain's keys.
pub trait CheckpointKeyCustody: Send + Sync {
    /// The keys of `domain`, or why none can be admitted.
    fn domain_keys(&self, domain: &CheckpointKeyDomain) -> Result<DomainKeys, CheckpointKeyError>;
}

/// Why a checkpoint key domain has no admissible keys. Secret-free.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CheckpointKeyError {
    /// The host domain's root, which is the instance-snapshot key.
    #[error(
        "protected checkpoints in the host key domain are sealed under the host snapshot key: \
         {0}"
    )]
    Host(SnapshotKeyError),
    /// A tenant domain's own root.
    #[error(
        "protected checkpoints in key domain tenant:{tenant} {}",
        .failure.describe(.tenant)
    )]
    Tenant {
        tenant: String,
        failure: TenantKeyFailure,
    },
    /// The domain cannot be framed or derived under.
    #[error("checkpoint key domain {domain} cannot hold keys: {reason}")]
    Domain { domain: String, reason: String },
    /// The store was opened without key custody, so it cannot open a
    /// protected record or seal a new one.
    #[error(
        "checkpoint {checkpoint} is protected, and this checkpoint store has no key custody; \
         open the store with key custody to read it"
    )]
    NoCustody { checkpoint: String },
}

/// What went wrong with a tenant's own key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TenantKeyFailure {
    /// No source holds one.
    Missing,
    /// A source exists but could not be read.
    Unavailable(SnapshotKeySource),
    /// A source holds something that is not a 32-byte key.
    Invalid(SnapshotKeySource),
}

/// Renders a tenant failure with the tenant's own source names, which differ
/// from the host's: the explicit variable and the key file carry the tenant id.
struct TenantSource<'a>(&'a str, SnapshotKeySource);

impl fmt::Display for TenantSource<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let tenant = self.0;
        match self.1 {
            SnapshotKeySource::Explicit => f.write_str(&EnvKeyProvider::variable_for(tenant)),
            SnapshotKeySource::Keystore => write!(f, "the OS keystore entry mvm/{tenant}"),
            SnapshotKeySource::KeyFile => write!(f, "{DEFAULT_KEYS_DIR}/{tenant}.key"),
        }
    }
}

impl TenantKeyFailure {
    fn describe(&self, tenant: &str) -> String {
        let setup = format!(
            "Provision the tenant's 32-byte key: set {} to 64 hex characters, or write the 32 \
             raw bytes to {DEFAULT_KEYS_DIR}/{tenant}.key with mode 0600. The host snapshot key \
             is never used in its place.",
            EnvKeyProvider::variable_for(tenant)
        );
        match self {
            Self::Missing => format!("need the tenant's own key, and none is configured. {setup}"),
            Self::Unavailable(source) => format!(
                "need the tenant's own key, and {} could not be read; refusing to continue \
                 without it",
                TenantSource(tenant, *source)
            ),
            Self::Invalid(source) => format!(
                "need the tenant's own key, and {} is not a usable 32-byte key. {setup}",
                TenantSource(tenant, *source)
            ),
        }
    }
}

impl From<SnapshotKeyError> for TenantKeyFailure {
    fn from(error: SnapshotKeyError) -> Self {
        match error {
            SnapshotKeyError::Missing => Self::Missing,
            SnapshotKeyError::Unavailable { origin } => Self::Unavailable(origin),
            SnapshotKeyError::Invalid { origin } => Self::Invalid(origin),
        }
    }
}

/// The host's own custody: the snapshot key for the host domain, each
/// tenant's own key for its domain.
#[derive(Debug, Clone, Copy, Default)]
pub struct HostKeyCustody;

impl CheckpointKeyCustody for HostKeyCustody {
    fn domain_keys(&self, domain: &CheckpointKeyDomain) -> Result<DomainKeys, CheckpointKeyError> {
        let root = match tenant_of(domain) {
            None => SnapshotKeyResolver::host_for(SNAPSHOT_TENANT_ID)
                .admit_for(SNAPSHOT_TENANT_ID)
                .map_err(CheckpointKeyError::Host)?,
            Some(tenant) => SnapshotKeyResolver::host_for(tenant)
                .admit_for(tenant)
                .map_err(|error| tenant_error(tenant, error))?,
        };
        derive_domain_keys(domain, &root)
    }
}

/// The tenant a domain belongs to, or `None` for the host domain.
#[must_use]
pub fn tenant_of(domain: &CheckpointKeyDomain) -> Option<&str> {
    if domain.is_host() {
        return None;
    }
    domain.as_str().strip_prefix("tenant:")
}

fn tenant_error(tenant: &str, error: SnapshotKeyError) -> CheckpointKeyError {
    CheckpointKeyError::Tenant {
        tenant: tenant.to_string(),
        failure: error.into(),
    }
}

/// Derive `domain`'s wrapping and reference keys from a custody root.
///
/// Public so an embedder holding roots elsewhere derives exactly what the
/// host does; the derivation is part of the protected-checkpoint format.
pub fn derive_domain_keys(
    domain: &CheckpointKeyDomain,
    root: &SnapshotKey,
) -> Result<DomainKeys, CheckpointKeyError> {
    let wrapping = derive(root.expose(), WRAPPING_LABEL, domain);
    let reference = derive(root.expose(), REFERENCE_LABEL, domain);
    DomainKeys::new(
        domain.clone(),
        aead::Key::from_bytes(*wrapping),
        ReferenceKey::from_bytes(*reference),
    )
    .map_err(|error| CheckpointKeyError::Domain {
        domain: domain.as_str().to_string(),
        reason: error.to_string(),
    })
}

fn derive(
    root: &[u8],
    label: &[u8],
    domain: &CheckpointKeyDomain,
) -> Zeroizing<[u8; REFERENCE_LEN]> {
    let name = domain.as_str().as_bytes();
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(root)
        .expect("HMAC-SHA256 accepts a key of any length");
    mac.update(label);
    mac.update(&(name.len() as u64).to_be_bytes());
    mac.update(name);
    Zeroizing::new(mac.finalize().into_bytes().into())
}

impl CheckpointStore {
    /// Seal captures, and open protected records, under `custody`.
    #[must_use]
    pub fn with_key_custody(mut self, custody: Arc<dyn CheckpointKeyCustody>) -> Self {
        self.custody = Some(custody);
        self
    }

    /// Whether captures into this store are sealed.
    pub fn protects_captures(&self) -> bool {
        self.custody.is_some()
    }

    pub(super) fn custody(&self) -> Option<&dyn CheckpointKeyCustody> {
        self.custody.as_deref()
    }

    /// The keys a protected record opens under; `None` for a legacy record.
    pub(super) fn keys_for(&self, meta: &CheckpointMeta) -> anyhow::Result<Option<DomainKeys>> {
        if meta.protection.is_unprotected() {
            return Ok(None);
        }
        let custody = self
            .custody()
            .ok_or_else(|| CheckpointKeyError::NoCustody {
                checkpoint: meta.id.to_string(),
            })?;
        Ok(Some(custody.domain_keys(&meta.key_domain).with_context(
            || format!("opening protected checkpoint '{}'", meta.id),
        )?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::crypto::checkpoint_object::{ObjectExpectation, ObjectKind, open, seal};

    fn root(byte: u8) -> SnapshotKey {
        SnapshotKey::from_bytes(vec![byte; 32]).unwrap()
    }

    fn tenant(name: &str) -> CheckpointKeyDomain {
        CheckpointKeyDomain::tenant(name).unwrap()
    }

    #[test]
    fn one_root_derives_distinct_keys_for_every_domain() {
        let host = derive_domain_keys(&CheckpointKeyDomain::host(), &root(7)).unwrap();
        let a = derive_domain_keys(&tenant("a"), &root(7)).unwrap();
        let sealed = seal(&host, ObjectKind::Chunk, b"payload").unwrap();
        // The tenant's keys are not the host's even from the same root: its
        // reference differs, and the host's object does not open under it.
        assert_ne!(
            a.reference_for(ObjectKind::Chunk, b"payload").unwrap(),
            sealed.reference
        );
        let expect = ObjectExpectation::new(ObjectKind::Chunk, sealed.reference);
        assert!(open(&a, &expect, &sealed.bytes).is_err());
        assert_eq!(open(&host, &expect, &sealed.bytes).unwrap(), b"payload");
    }

    #[test]
    fn derivation_is_deterministic_and_root_bound() {
        let domain = tenant("a");
        let first = derive_domain_keys(&domain, &root(1)).unwrap();
        let again = derive_domain_keys(&domain, &root(1)).unwrap();
        let other = derive_domain_keys(&domain, &root(2)).unwrap();
        let sealed = seal(&first, ObjectKind::Chunk, b"x").unwrap();
        let expect = ObjectExpectation::new(ObjectKind::Chunk, sealed.reference);
        assert_eq!(open(&again, &expect, &sealed.bytes).unwrap(), b"x");
        assert!(open(&other, &expect, &sealed.bytes).is_err());
    }

    #[test]
    fn a_tenant_failure_names_the_tenants_own_sources_and_no_secret() {
        let error = tenant_error(
            "acme-1",
            SnapshotKeyError::Invalid {
                origin: SnapshotKeySource::Explicit,
            },
        );
        let rendered = error.to_string();
        assert!(rendered.contains("MVM_TENANT_KEY_ACME_1"), "{rendered}");
        assert!(rendered.contains("tenant:acme-1"), "{rendered}");
        assert!(rendered.contains("never used in its place"), "{rendered}");
        let missing = tenant_error("acme", SnapshotKeyError::Missing).to_string();
        assert!(missing.contains("/var/lib/mvm/keys/acme.key"), "{missing}");
    }

    #[test]
    fn host_and_tenant_domains_are_told_apart() {
        assert_eq!(tenant_of(&CheckpointKeyDomain::host()), None);
        assert_eq!(tenant_of(&tenant("acme")), Some("acme"));
    }

    #[test]
    fn host_custody_refuses_a_tenant_with_no_key_of_its_own() {
        // Unit builds consult no keystore or key directory, and the tenant's
        // variable is unset, so the tenant has no key — even when the host's
        // snapshot key is configured.
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.set(
            crate::vm::snapshot_key::SNAPSHOT_TENANT_KEY_ENV,
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
        );
        env.remove("MVM_TENANT_KEY_NOKEY_TENANT");
        let error = HostKeyCustody
            .domain_keys(&tenant("nokey-tenant"))
            .err()
            .expect("a tenant without its own key is refused");
        assert_eq!(
            error,
            CheckpointKeyError::Tenant {
                tenant: "nokey-tenant".into(),
                failure: TenantKeyFailure::Missing,
            }
        );
        assert!(
            HostKeyCustody
                .domain_keys(&CheckpointKeyDomain::host())
                .is_ok()
        );
    }
}
