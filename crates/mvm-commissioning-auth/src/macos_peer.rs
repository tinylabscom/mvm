//! Audit-token-bound dynamic code identity verification for macOS peers.
//!
//! This module verifies an already-captured kernel audit token. It does not
//! open a transport, discover a path, authorize an operation, or provide a
//! weaker UID-only success mode.

use std::fmt;

/// Byte length of Darwin's `audit_token_t`.
pub const AUDIT_TOKEN_BYTES: usize = 32;
/// Maximum accepted designated-requirement source length.
pub const MAX_DESIGNATED_REQUIREMENT_BYTES: usize = 4096;

#[cfg(test)]
const AUDIT_TOKEN_WORDS: usize = 8;
const EUID_WORD: usize = 1;
const PID_WORD: usize = 5;
const PIDVERSION_WORD: usize = 7;

/// One exact kernel audit token captured from the peer connection.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MacAuditToken {
    bytes: [u8; AUDIT_TOKEN_BYTES],
}

impl MacAuditToken {
    /// Retains one exact `audit_token_t` byte representation.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; AUDIT_TOKEN_BYTES]) -> Self {
        Self { bytes }
    }

    fn word(&self, index: usize) -> u32 {
        let offset = index * size_of::<u32>();
        u32::from_ne_bytes(
            self.bytes[offset..offset + size_of::<u32>()]
                .try_into()
                .expect("audit token word is exactly four bytes"),
        )
    }

    fn euid(&self) -> u32 {
        self.word(EUID_WORD)
    }

    fn pid(&self) -> u32 {
        self.word(PID_WORD)
    }

    fn pidversion(&self) -> u32 {
        self.word(PIDVERSION_WORD)
    }
}

impl TryFrom<&[u8]> for MacAuditToken {
    type Error = MacPeerVerificationError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let bytes: [u8; AUDIT_TOKEN_BYTES] = bytes
            .try_into()
            .map_err(|_| MacPeerVerificationError::InvalidAuditToken)?;
        Ok(Self::from_bytes(bytes))
    }
}

impl fmt::Debug for MacAuditToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MacAuditToken([REDACTED])")
    }
}

/// An exact, bounded designated-requirement source supplied by trusted code.
pub struct DesignatedRequirement {
    #[cfg(all(feature = "native-caller-identity", target_os = "macos"))]
    source: String,
    #[cfg(not(all(feature = "native-caller-identity", target_os = "macos")))]
    _validated: (),
}

impl DesignatedRequirement {
    /// Validates and retains one exact requirement source.
    ///
    /// This type does not derive or broaden a requirement from a path or Team
    /// ID. The trusted commissioning code must supply the complete pin.
    ///
    /// # Errors
    ///
    /// Refuses empty, oversized, or NUL-containing source.
    pub fn new(source: &str) -> Result<Self, MacPeerVerificationError> {
        if source.is_empty()
            || source.len() > MAX_DESIGNATED_REQUIREMENT_BYTES
            || source.as_bytes().contains(&0)
        {
            return Err(MacPeerVerificationError::InvalidRequirement);
        }
        Ok(Self {
            #[cfg(all(feature = "native-caller-identity", target_os = "macos"))]
            source: source.to_owned(),
            #[cfg(not(all(feature = "native-caller-identity", target_os = "macos")))]
            _validated: (),
        })
    }
}

impl fmt::Debug for DesignatedRequirement {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DesignatedRequirement([REDACTED])")
    }
}

/// Redacted peer-verification refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum MacPeerVerificationError {
    /// The feature was built on a platform without the macOS primitive.
    #[error("macOS audit-token code identity verification is unsupported on this platform")]
    Unsupported,
    /// The supplied bytes cannot represent the required token.
    #[error("peer audit token is invalid")]
    InvalidAuditToken,
    /// The trusted requirement pin violates the source bound.
    #[error("designated requirement source is invalid")]
    InvalidRequirement,
    /// Security.framework rejected the requirement source.
    #[error("designated requirement could not be compiled")]
    RequirementCompilation,
    /// The kernel could not resolve a live dynamic code object for the token.
    #[error("peer dynamic code identity is unavailable")]
    CodeUnavailable,
    /// The token did not name the expected effective UID or stable process.
    #[error("peer audit identity does not match the verified observation")]
    IdentityMismatch,
    /// The live code object did not satisfy the exact requirement.
    #[error("peer code identity does not satisfy the designated requirement")]
    RequirementMismatch,
    /// The transport-specific recapture failed immediately before use.
    #[error("peer audit token could not be recaptured")]
    RecaptureUnavailable,
}

/// A verified observation whose live identity can be rechecked before mutation.
///
/// The value is intentionally non-cloneable and its fields are private. A
/// trusted transport adapter must supply connection-derived token bytes and a
/// fresh recapture callback; this type does not itself prove that provenance.
///
/// ```compile_fail
/// use mvm_commissioning_auth::macos_peer::VerifiedMacPeer;
///
/// fn duplicate(peer: VerifiedMacPeer) {
///     let _copy = peer.clone();
/// }
/// ```
///
/// ```compile_fail
/// use mvm_commissioning_auth::macos_peer::VerifiedMacPeer;
///
/// fn forge() -> VerifiedMacPeer {
///     VerifiedMacPeer { pid: 1 }
/// }
/// ```
pub struct VerifiedMacPeer {
    pid: u32,
    pidversion: u32,
    euid: u32,
    expected_euid: u32,
    requirement: DesignatedRequirement,
    recapture: Box<dyn Fn() -> Option<MacAuditToken> + Send + Sync>,
}

impl fmt::Debug for VerifiedMacPeer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedMacPeer")
            .field("pid", &self.pid)
            .field("pidversion", &self.pidversion)
            .field("euid", &self.euid)
            .field("requirement", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl VerifiedMacPeer {
    /// Verifies an initial token and binds a live recapture operation.
    ///
    /// `recapture` must read a fresh kernel token from the same peer connection.
    /// It is invoked by [`Self::revalidate`] immediately before a mutation.
    ///
    /// # Errors
    ///
    /// Refuses unsupported platforms, invalid observations, unavailable dynamic
    /// code, or code that does not satisfy the exact requirement.
    pub fn verify(
        token: MacAuditToken,
        expected_euid: u32,
        requirement: DesignatedRequirement,
        recapture: impl Fn() -> Option<MacAuditToken> + Send + Sync + 'static,
    ) -> Result<Self, MacPeerVerificationError> {
        verify_observation(&token, expected_euid, &requirement)?;
        Ok(Self {
            pid: token.pid(),
            pidversion: token.pidversion(),
            euid: token.euid(),
            expected_euid,
            requirement,
            recapture: Box::new(recapture),
        })
    }

    /// Re-captures and verifies the same live peer immediately before mutation.
    ///
    /// # Errors
    ///
    /// Refuses recapture failure, UID/process replacement, unavailable dynamic
    /// code, or a requirement mismatch. No weaker success is returned.
    pub fn revalidate(&self) -> Result<(), MacPeerVerificationError> {
        let token = (self.recapture)().ok_or(MacPeerVerificationError::RecaptureUnavailable)?;
        if token.pid() != self.pid || token.pidversion() != self.pidversion {
            return Err(MacPeerVerificationError::IdentityMismatch);
        }
        verify_observation(&token, self.expected_euid, &self.requirement)
    }

    /// Kernel-observed process identifier.
    #[must_use]
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Kernel-observed process incarnation.
    #[must_use]
    pub fn pidversion(&self) -> u32 {
        self.pidversion
    }

    /// Kernel-observed effective UID.
    #[must_use]
    pub fn euid(&self) -> u32 {
        self.euid
    }
}

#[cfg(all(feature = "native-caller-identity", target_os = "macos"))]
fn verify_observation(
    token: &MacAuditToken,
    expected_euid: u32,
    requirement: &DesignatedRequirement,
) -> Result<(), MacPeerVerificationError> {
    use core_foundation::{base::TCFType as _, data::CFData};
    use security_framework::os::macos::code_signing::{
        Flags, GuestAttributes, SecCode, SecRequirement,
    };

    if token.euid() != expected_euid || token.pid() == 0 {
        return Err(MacPeerVerificationError::IdentityMismatch);
    }

    let requirement: SecRequirement = requirement
        .source
        .parse()
        .map_err(|_| MacPeerVerificationError::RequirementCompilation)?;
    let data = CFData::from_buffer(&token.bytes);
    let mut attributes = GuestAttributes::new();
    attributes.set_audit_token(data.as_concrete_TypeRef());
    let code = SecCode::copy_guest_with_attribues(None, &attributes, Flags::NONE)
        .map_err(|_| MacPeerVerificationError::CodeUnavailable)?;
    code.check_validity(Flags::NONE, &requirement)
        .map_err(|_| MacPeerVerificationError::RequirementMismatch)
}

#[cfg(not(all(feature = "native-caller-identity", target_os = "macos")))]
fn verify_observation(
    _token: &MacAuditToken,
    _expected_euid: u32,
    _requirement: &DesignatedRequirement,
) -> Result<(), MacPeerVerificationError> {
    Err(MacPeerVerificationError::Unsupported)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(all(feature = "native-caller-identity", target_os = "macos")))]
    fn token(euid: u32, pid: u32, pidversion: u32) -> MacAuditToken {
        let mut words = [0_u32; AUDIT_TOKEN_WORDS];
        words[EUID_WORD] = euid;
        words[PID_WORD] = pid;
        words[PIDVERSION_WORD] = pidversion;
        let mut bytes = [0_u8; AUDIT_TOKEN_BYTES];
        for (index, word) in words.into_iter().enumerate() {
            let offset = index * size_of::<u32>();
            bytes[offset..offset + size_of::<u32>()].copy_from_slice(&word.to_ne_bytes());
        }
        MacAuditToken::from_bytes(bytes)
    }

    #[test]
    fn audit_token_requires_exact_kernel_size() {
        assert_eq!(
            MacAuditToken::try_from(&[0_u8; AUDIT_TOKEN_BYTES - 1][..]),
            Err(MacPeerVerificationError::InvalidAuditToken)
        );
        assert_eq!(
            MacAuditToken::try_from(&[0_u8; AUDIT_TOKEN_BYTES + 1][..]),
            Err(MacPeerVerificationError::InvalidAuditToken)
        );
    }

    #[test]
    fn requirement_source_is_exact_and_bounded() {
        assert_eq!(
            DesignatedRequirement::new("").expect_err("empty source must refuse"),
            MacPeerVerificationError::InvalidRequirement
        );
        assert_eq!(
            DesignatedRequirement::new(&"x".repeat(MAX_DESIGNATED_REQUIREMENT_BYTES + 1))
                .expect_err("oversized source must refuse"),
            MacPeerVerificationError::InvalidRequirement
        );
        assert_eq!(
            DesignatedRequirement::new("identifier \"dev.mvm.owner\"\0")
                .expect_err("NUL-containing source must refuse"),
            MacPeerVerificationError::InvalidRequirement
        );
    }

    #[test]
    fn token_and_requirement_debug_are_redacted() {
        let token = MacAuditToken::from_bytes([7; AUDIT_TOKEN_BYTES]);
        let requirement =
            DesignatedRequirement::new("identifier \"secret.example\"").expect("valid source");
        assert!(!format!("{token:?}").contains("7, 7"));
        assert!(!format!("{requirement:?}").contains("secret.example"));
    }

    #[cfg(not(all(feature = "native-caller-identity", target_os = "macos")))]
    #[test]
    fn unsupported_platform_never_returns_success() {
        let error = VerifiedMacPeer::verify(
            token(501, 42, 7),
            501,
            DesignatedRequirement::new("identifier \"dev.mvm.owner\"")
                .expect("bounded requirement"),
            || Some(token(501, 42, 7)),
        )
        .expect_err("non-macOS must refuse");
        assert_eq!(error, MacPeerVerificationError::Unsupported);
    }

    #[cfg(all(feature = "native-caller-identity", target_os = "macos"))]
    mod native {
        use std::ffi::c_void;

        use core_foundation::{base::TCFType as _, string::CFString};
        use security_framework::os::macos::code_signing::{Flags, SecCode, SecRequirement};

        use super::*;

        unsafe extern "C" {
            fn SecCodeCopyDesignatedRequirement(
                code: *const c_void,
                flags: u32,
                requirement: *mut *const c_void,
            ) -> i32;
            fn SecRequirementCopyString(
                requirement: *const c_void,
                flags: u32,
                text: *mut *const c_void,
            ) -> i32;
        }

        const TASK_AUDIT_TOKEN: u32 = 15;

        #[allow(deprecated)] // libc preserves the exact Darwin mach_port_t ABI used by this probe.
        fn current_token() -> Option<MacAuditToken> {
            let mut words = [0_u32; AUDIT_TOKEN_WORDS];
            let mut count = AUDIT_TOKEN_WORDS as u32;
            // SAFETY: `words` is writable for the eight natural words requested
            // by TASK_AUDIT_TOKEN, and both pointers remain live for the call.
            let result = unsafe {
                libc::task_info(
                    libc::mach_task_self(),
                    TASK_AUDIT_TOKEN,
                    words.as_mut_ptr().cast(),
                    &mut count,
                )
            };
            (result == 0 && count as usize == AUDIT_TOKEN_WORDS).then(|| {
                let mut bytes = [0_u8; AUDIT_TOKEN_BYTES];
                for (chunk, word) in bytes.chunks_exact_mut(4).zip(words) {
                    chunk.copy_from_slice(&word.to_ne_bytes());
                }
                MacAuditToken::from_bytes(bytes)
            })
        }

        fn self_designated_requirement() -> DesignatedRequirement {
            let code = SecCode::for_self(Flags::NONE).expect("current dynamic code is available");
            let mut requirement = std::ptr::null();
            // SAFETY: Security.framework receives a valid retained SecCode and
            // initializes the create-rule output on success.
            let status = unsafe {
                SecCodeCopyDesignatedRequirement(
                    code.as_concrete_TypeRef().cast(),
                    0,
                    &mut requirement,
                )
            };
            assert_eq!(status, 0, "current code has a designated requirement");
            assert!(!requirement.is_null(), "requirement output is non-null");

            let mut text = std::ptr::null();
            // SAFETY: `requirement` is the live create-rule object returned
            // above and Security.framework initializes `text` on success.
            let status = unsafe { SecRequirementCopyString(requirement, 0, &mut text) };
            // SAFETY: transfer the create-rule requirement to the Rust wrapper
            // so it is released after conversion.
            let _requirement =
                unsafe { SecRequirement::wrap_under_create_rule(requirement.cast_mut().cast()) };
            assert_eq!(status, 0, "designated requirement converts to source");
            assert!(!text.is_null(), "requirement source output is non-null");
            // SAFETY: transfer the create-rule string to the Rust wrapper.
            let text = unsafe { CFString::wrap_under_create_rule(text.cast_mut().cast()) };
            DesignatedRequirement::new(&text.to_string()).expect("native source satisfies bound")
        }

        #[test]
        fn current_process_verifies_and_revalidates() {
            let token = current_token().expect("host supports TASK_AUDIT_TOKEN");
            let peer = VerifiedMacPeer::verify(
                token,
                token.euid(),
                self_designated_requirement(),
                current_token,
            )
            .expect("current code satisfies its designated requirement");
            assert_eq!(peer.pid(), std::process::id(), "audit token pid");
            assert_eq!(peer.euid(), token.euid(), "audit token euid");
            peer.revalidate()
                .expect("same live process revalidates immediately");
        }

        #[test]
        fn changed_pidversion_refuses_before_second_code_lookup() {
            let initial = current_token().expect("host supports TASK_AUDIT_TOKEN");
            let mut changed = initial.bytes;
            let offset = PIDVERSION_WORD * size_of::<u32>();
            let next = initial.pidversion().wrapping_add(1).to_ne_bytes();
            changed[offset..offset + size_of::<u32>()].copy_from_slice(&next);
            let peer = VerifiedMacPeer::verify(
                initial,
                initial.euid(),
                self_designated_requirement(),
                move || Some(MacAuditToken::from_bytes(changed)),
            )
            .expect("initial current code satisfies its requirement");
            assert_eq!(
                peer.revalidate()
                    .expect_err("changed process incarnation must refuse"),
                MacPeerVerificationError::IdentityMismatch
            );
        }

        #[test]
        fn wrong_expected_uid_refuses_before_code_lookup() {
            let token = current_token().expect("host supports TASK_AUDIT_TOKEN");
            let wrong_uid = token.euid().wrapping_add(1);
            let error = VerifiedMacPeer::verify(
                token,
                wrong_uid,
                DesignatedRequirement::new("invalid requirement is not reached")
                    .expect("bounded requirement"),
                current_token,
            )
            .expect_err("wrong uid must refuse");
            assert_eq!(error, MacPeerVerificationError::IdentityMismatch);
        }

        #[test]
        fn invalid_requirement_is_redacted() {
            let token = current_token().expect("host supports TASK_AUDIT_TOKEN");
            let error = VerifiedMacPeer::verify(
                token,
                token.euid(),
                DesignatedRequirement::new("not valid requirement syntax $$$")
                    .expect("bounded requirement"),
                current_token,
            )
            .expect_err("invalid requirement must refuse");
            assert_eq!(error, MacPeerVerificationError::RequirementCompilation);
            assert!(!error.to_string().contains("$$$"), "native text leaked");
        }

        #[test]
        fn valid_unsatisfied_requirement_and_unavailable_code_refuse() {
            let token = current_token().expect("host supports TASK_AUDIT_TOKEN");
            let error = VerifiedMacPeer::verify(
                token,
                token.euid(),
                DesignatedRequirement::new("identifier \"invalid.example.never\"")
                    .expect("valid requirement syntax"),
                current_token,
            )
            .expect_err("unmatched requirement must refuse");
            assert_eq!(error, MacPeerVerificationError::RequirementMismatch);

            let mut unavailable = token.bytes;
            let offset = PID_WORD * size_of::<u32>();
            unavailable[offset..offset + size_of::<u32>()].copy_from_slice(&u32::MAX.to_ne_bytes());
            let error = VerifiedMacPeer::verify(
                MacAuditToken::from_bytes(unavailable),
                token.euid(),
                self_designated_requirement(),
                current_token,
            )
            .expect_err("unknown process token must refuse");
            assert_eq!(error, MacPeerVerificationError::CodeUnavailable);
        }

        #[test]
        fn recapture_pid_and_euid_changes_refuse() {
            let initial = current_token().expect("host supports TASK_AUDIT_TOKEN");
            let peer = VerifiedMacPeer::verify(
                initial,
                initial.euid(),
                self_designated_requirement(),
                || None,
            )
            .expect("initial identity verifies");
            assert_eq!(
                peer.revalidate().unwrap_err(),
                MacPeerVerificationError::RecaptureUnavailable
            );

            for word in [PID_WORD, EUID_WORD] {
                let mut changed = initial.bytes;
                let offset = word * size_of::<u32>();
                changed[offset..offset + size_of::<u32>()].copy_from_slice(&u32::MAX.to_ne_bytes());
                let peer = VerifiedMacPeer::verify(
                    initial,
                    initial.euid(),
                    self_designated_requirement(),
                    move || Some(MacAuditToken::from_bytes(changed)),
                )
                .expect("initial identity verifies");
                assert_eq!(
                    peer.revalidate().unwrap_err(),
                    MacPeerVerificationError::IdentityMismatch
                );
            }
        }
    }
}
