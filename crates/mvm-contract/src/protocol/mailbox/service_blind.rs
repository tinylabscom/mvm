//! Signed selection of service-blind launch requirements, not permission to execute them.

use serde::{Deserialize, Serialize};

/// Requested V3 bindings, not provisioning, custody, Ready, or release authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "LaunchProfileWire", into = "LaunchProfileWire")]
pub struct LaunchProfile {
    descriptor_commitment: [u8; 32],
    owner_policy_commitment: [u8; 32],
}

/// A selector has an unsupported version or an absent commitment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("service-blind launch selection requires version 3 and nonzero commitments")]
pub struct InvalidLaunchProfile;

impl LaunchProfile {
    /// Bind requested intent to exact public objects without asserting their approval.
    ///
    /// # Errors
    /// Refuses a zero descriptor or owner-policy commitment.
    pub fn new(
        descriptor_commitment: [u8; 32],
        owner_policy_commitment: [u8; 32],
    ) -> Result<Self, InvalidLaunchProfile> {
        if descriptor_commitment == [0; 32] || owner_policy_commitment == [0; 32] {
            return Err(InvalidLaunchProfile);
        }
        Ok(Self {
            descriptor_commitment,
            owner_policy_commitment,
        })
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LaunchProfileWire {
    version: u16,
    descriptor_commitment: [u8; 32],
    owner_policy_commitment: [u8; 32],
}

impl TryFrom<LaunchProfileWire> for LaunchProfile {
    type Error = InvalidLaunchProfile;

    fn try_from(value: LaunchProfileWire) -> Result<Self, Self::Error> {
        if value.version != 3 {
            return Err(InvalidLaunchProfile);
        }
        Self::new(value.descriptor_commitment, value.owner_policy_commitment)
    }
}

impl From<LaunchProfile> for LaunchProfileWire {
    fn from(value: LaunchProfile) -> Self {
        Self {
            version: 3,
            descriptor_commitment: value.descriptor_commitment,
            owner_policy_commitment: value.owner_policy_commitment,
        }
    }
}
