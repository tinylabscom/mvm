use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

use super::error::Denial;

/// Strength of evidence behind a node. Software evidence is never reported as
/// hardware.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Assurance {
    None,
    Software,
    Hardware,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssuranceRequirement {
    pub required: bool,
    /// Minimum level when `required`; ignored otherwise.
    pub minimum: Assurance,
}

impl Default for AssuranceRequirement {
    /// `attestation: { required: false }`.
    fn default() -> Self {
        Self {
            required: false,
            minimum: Assurance::Hardware,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VolumeMode {
    ReadOnly,
    ReadWrite,
}

/// A trusted host location exposed to a guest as a named, policy-authorized
/// grant. Always node-local.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamedVolumeGrant {
    pub id: String,
    pub source: String,
    pub guest_target: String,
    pub mode: VolumeMode,
    /// Read-write needs this explicit opt-in on the grant itself.
    #[serde(default)]
    pub read_write_authorized: bool,
    #[serde(default)]
    pub quota_bytes: Option<u64>,
}

impl NamedVolumeGrant {
    /// Lexical checks only; symlink/device/ownership checks happen against the
    /// real filesystem at mount time.
    pub fn validate(&self) -> Result<(), Denial> {
        let bad = |why: &str| Err(Denial::VolumeGrant(format!("{}: {why}", self.id)));
        if self.id.is_empty() {
            return bad("empty id");
        }
        for p in [&self.source, &self.guest_target] {
            if !p.starts_with('/') || p.split('/').any(|s| s == "..") || p.contains('\0') {
                return bad("path must be absolute with no `..`");
            }
        }
        if self.source == "/" {
            return bad("source may not be the filesystem root");
        }
        if self.mode == VolumeMode::ReadWrite && !self.read_write_authorized {
            return bad("read-write requires explicit authorization");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostPolicy {
    pub version: u64,
    /// Unix seconds; `None` means the policy does not expire (local default).
    pub not_after: Option<u64>,
    /// Node ids covered; empty means every node (local default).
    #[serde(default)]
    pub scope: Vec<String>,
    #[serde(default)]
    pub attestation: AssuranceRequirement,
    #[serde(default)]
    pub volumes: Vec<NamedVolumeGrant>,
    /// Admitted image digests; empty means any digest (local default).
    #[serde(default)]
    pub image_digests: Vec<String>,
}

impl HostPolicy {
    pub fn check_launch_scope(&self, node_id: &str, now: u64) -> Result<(), Denial> {
        if self.not_after.is_some_and(|t| now >= t) {
            return Err(Denial::PolicyExpired);
        }
        if !self.scope.is_empty() && !self.scope.iter().any(|s| s == node_id) {
            return Err(Denial::PolicyScope);
        }
        self.volumes.iter().try_for_each(NamedVolumeGrant::validate)
    }

    pub fn check_assurance(&self, have: Assurance) -> Result<(), Denial> {
        if self.attestation.required && have < self.attestation.minimum {
            return Err(Denial::AttestationRequired(have));
        }
        Ok(())
    }

    pub fn check_image(&self, digest: &str) -> Result<(), Denial> {
        if self.image_digests.is_empty() || self.image_digests.iter().any(|d| d == digest) {
            Ok(())
        } else {
            Err(Denial::ImageDigest)
        }
    }
}

/// A policy plus the issuer's detached signature over its JCS bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedHostPolicy {
    pub policy: HostPolicy,
    pub issuer: String,
    pub signature: Vec<u8>,
}

impl SignedHostPolicy {
    pub fn sign(
        policy: HostPolicy,
        issuer: &str,
        key: &ed25519_dalek::SigningKey,
    ) -> Result<Self, serde_json::Error> {
        use ed25519_dalek::Signer;
        let bytes = serde_jcs::to_vec(&policy)?;
        Ok(Self {
            policy,
            issuer: issuer.to_owned(),
            signature: key.sign(&bytes).to_bytes().to_vec(),
        })
    }

    /// Verify issuer, signature, expiry and rollback; only then yield the policy.
    pub fn verify(
        self,
        trusted: &[(String, VerifyingKey)],
        now: u64,
        min_version: u64,
    ) -> Result<HostPolicy, Denial> {
        let (_, key) = trusted
            .iter()
            .find(|(id, _)| *id == self.issuer)
            .ok_or(Denial::PolicyIssuer)?;
        let sig = Signature::from_slice(&self.signature).map_err(|_| Denial::PolicySignature)?;
        let bytes = serde_jcs::to_vec(&self.policy).map_err(|_| Denial::PolicySignature)?;
        key.verify_strict(&bytes, &sig)
            .map_err(|_| Denial::PolicySignature)?;
        if self.policy.not_after.is_some_and(|t| now >= t) {
            return Err(Denial::PolicyExpired);
        }
        if self.policy.version < min_version {
            return Err(Denial::PolicyRollback {
                got: self.policy.version,
                min: min_version,
            });
        }
        Ok(self.policy)
    }
}
