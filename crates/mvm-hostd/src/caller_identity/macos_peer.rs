//! Compatibility exports for the low-level macOS peer verifier.

pub use mvm_commissioning_auth::macos_peer::{
    AUDIT_TOKEN_BYTES, DesignatedRequirement, MAX_DESIGNATED_REQUIREMENT_BYTES, MacAuditToken,
    MacPeerVerificationError, VerifiedMacPeer,
};
