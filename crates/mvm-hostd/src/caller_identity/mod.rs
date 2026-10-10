//! Dedicated macOS native custody for an entrypoint caller's reusable identity.
//!
//! Enrollment is explicit preparation, never a side effect of loading a key.
//! Native custody proves possession only; it does not authorize a producer.
//! Linux and other platforms refuse this opt-in rather than selecting an
//! unvalidated backend or falling back to mock/file storage.

use ed25519_dalek::SigningKey;
use mvm_core::crypto::entrypoint_delegation::{
    DelegationError, RegistrationChallenge, RegistrationProof,
};
pub use mvm_core::crypto::entrypoint_identity::EnrolledIdentity;
use uuid::Uuid;
use zeroize::Zeroizing;

mod worker;
pub use worker::{IdentityClient, PendingCredential};
#[cfg(all(feature = "native-caller-identity", target_os = "macos"))]
mod macos;
#[cfg(all(test, feature = "native-caller-identity", target_os = "macos"))]
mod native_tests;
#[cfg(all(test, feature = "native-caller-identity", target_os = "macos"))]
mod production_fixture;
#[cfg(test)]
mod tests;

#[cfg(all(feature = "native-caller-identity", target_os = "macos"))]
const SERVICE: &str = "com.tinylabs.mvm.entrypoint-caller.v1";

/// Loaded dedicated key, zeroized on drop; neither cloneable nor printable.
pub struct CallerCredential {
    installation: Uuid,
    key: SigningKey,
}

impl CallerCredential {
    pub fn identity(&self) -> EnrolledIdentity {
        EnrolledIdentity {
            installation: self.installation,
            public_key: self.key.verifying_key().to_bytes(),
        }
    }

    /// Possession only. The verifier separately establishes admission authority.
    pub fn prove_registration(
        &self,
        challenge: &RegistrationChallenge,
        now: u64,
    ) -> std::result::Result<RegistrationProof, DelegationError> {
        RegistrationProof::sign(&self.key, &self.identity(), challenge, now)
    }
}

/// Payload-free failures: native error text never enters diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum IdentityError {
    #[error(
        "native caller custody requires a macOS host build with native-caller-identity; Linux and other platforms do not support this opt-in"
    )]
    Unsupported,
    #[error(
        "native caller custody unavailable or locked; configure and unlock the user's macOS login keychain before enrollment"
    )]
    Unavailable,
    #[error("caller identity is not enrolled; explicitly enroll before launching")]
    Missing,
    #[error(
        "caller identity is invalid or differs from its enrollment pin; do not replace it silently"
    )]
    Conflict,
    #[error("the caller credential worker is busy; no additional worker was started")]
    Busy,
    #[error("caller credential deadline expired; the native operation may still be running")]
    Deadline,
    #[error("caller credential request canceled")]
    Canceled,
}

type Result<T> = std::result::Result<T, IdentityError>;

/// Private seam for the native implementation and deterministic tests.
trait Store: Send + 'static {
    fn read(&self, account: &str) -> Result<Zeroizing<Vec<u8>>>;
    /// Create only. Existing items must never be replaced.
    fn create(&self, account: &str, seed: &[u8]) -> Result<()>;
    #[cfg(test)]
    fn completed(&self) {}
}

fn account(installation: Uuid) -> Result<String> {
    if installation.is_nil() {
        return Err(IdentityError::Conflict);
    }
    Ok(format!(
        "installation:{installation}:entrypoint-caller:ed25519:v1"
    ))
}

fn native_store() -> Result<Box<dyn Store>> {
    #[cfg(all(feature = "native-caller-identity", target_os = "macos"))]
    {
        Ok(Box::new(macos::NativeStore))
    }
    #[cfg(not(all(feature = "native-caller-identity", target_os = "macos")))]
    {
        Err(IdentityError::Unsupported)
    }
}
