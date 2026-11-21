//! In-memory, one-use commissioning-bootstrap authorization.
//!
//! A session owns one [`VerifiedMacPeer`], binds it to one short-lived exchange,
//! and can move it into one permit. It opens no endpoint and performs no durable
//! or VM effect.

use std::{
    fmt,
    sync::Mutex,
    time::{Duration, Instant},
};

#[cfg(test)]
use std::sync::Arc;

use mvm_contract::protocol::commissioning_bootstrap::{
    CONFIRM_SEQUENCE, CodecError, MAX_CHALLENGE_EXPIRES_AFTER_MS, Request, Response, VERSION,
};
#[cfg(not(test))]
use rand::TryRng as _;

use crate::caller_identity::macos_peer::VerifiedMacPeer;

const CHALLENGE_LIFETIME: Duration = Duration::from_millis(MAX_CHALLENGE_EXPIRES_AFTER_MS as u64);

/// Payload-free refusal from a commissioning-bootstrap session transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SessionError {
    /// The typed message violates the protocol vocabulary.
    #[error("commissioning-bootstrap message is invalid")]
    InvalidMessage,
    /// The requested transition is unavailable in the current state.
    #[error("commissioning-bootstrap session is in the wrong state")]
    WrongState,
    /// Confirmation did not exactly repeat the issued bindings.
    #[error("commissioning-bootstrap confirmation binding does not match")]
    BindingMismatch,
    /// The accepted begin request reached its monotonic deadline.
    #[error("commissioning-bootstrap session expired")]
    Expired,
    /// Fresh OS randomness was unavailable.
    #[error("commissioning-bootstrap server nonce is unavailable")]
    EntropyUnavailable,
    /// The live macOS peer no longer satisfies its verified observation.
    #[error("commissioning-bootstrap peer revalidation failed")]
    PeerRevalidation,
}

impl From<CodecError> for SessionError {
    fn from(_error: CodecError) -> Self {
        Self::InvalidMessage
    }
}

/// One in-memory commissioning-bootstrap exchange.
///
/// The session is intentionally not serializable. It retains the verified peer
/// and uses one mutex to linearize validation, live revalidation, and terminal
/// consumption.
pub struct CommissioningBootstrapSession {
    state: Mutex<State>,
    #[cfg(test)]
    clock: Arc<dyn Fn() -> Instant + Send + Sync>,
    #[cfg(test)]
    nonce: [u8; 32],
}

impl fmt::Debug for CommissioningBootstrapSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CommissioningBootstrapSession")
            .finish_non_exhaustive()
    }
}

enum State {
    Fresh {
        peer: VerifiedMacPeer,
        intent_digest: [u8; 32],
    },
    Challenged {
        peer: VerifiedMacPeer,
        intent_digest: [u8; 32],
        client_nonce: [u8; 32],
        server_nonce: [u8; 32],
        deadline: Instant,
    },
    Consumed,
}

impl CommissioningBootstrapSession {
    /// Creates a fresh session for one independently selected intent digest.
    ///
    /// # Errors
    ///
    /// Refuses the all-zero digest reserved by the protocol.
    pub fn new(peer: VerifiedMacPeer, intent_digest: [u8; 32]) -> Result<Self, SessionError> {
        Request::Begin {
            version: VERSION,
            intent_digest,
            client_nonce: [1; 32],
        }
        .validate()?;
        Ok(Self {
            state: Mutex::new(State::Fresh {
                peer,
                intent_digest,
            }),
            #[cfg(test)]
            clock: Arc::new(Instant::now),
            #[cfg(test)]
            nonce: [1; 32],
        })
    }

    #[cfg(test)]
    fn new_for_test(
        peer: VerifiedMacPeer,
        intent_digest: [u8; 32],
        clock: Arc<dyn Fn() -> Instant + Send + Sync>,
        nonce: [u8; 32],
    ) -> Self {
        Self {
            state: Mutex::new(State::Fresh {
                peer,
                intent_digest,
            }),
            clock,
            nonce,
        }
    }

    /// Accepts exactly one valid begin request and issues its bound challenge.
    ///
    /// The monotonic 30-second lifetime starts while the state mutex is held.
    ///
    /// # Errors
    ///
    /// Refuses invalid messages, duplicate or out-of-order transitions, and OS
    /// entropy failure without issuing a challenge.
    pub fn begin(&self, request: &Request) -> Result<Response, SessionError> {
        request.validate()?;
        let Request::Begin {
            version,
            intent_digest,
            client_nonce,
        } = request
        else {
            return Err(SessionError::WrongState);
        };

        let mut state = self
            .state
            .lock()
            .expect("session state lock is not poisoned");
        let State::Fresh {
            intent_digest: expected_digest,
            ..
        } = &*state
        else {
            return Err(SessionError::WrongState);
        };
        if intent_digest != expected_digest {
            return Err(SessionError::BindingMismatch);
        }

        let now = self.now();
        let deadline = now
            .checked_add(CHALLENGE_LIFETIME)
            .ok_or(SessionError::Expired)?;
        let server_nonce = self.server_nonce()?;
        let State::Fresh { peer, .. } = std::mem::replace(&mut *state, State::Consumed) else {
            unreachable!("fresh state was checked while holding the same mutex");
        };
        *state = State::Challenged {
            peer,
            intent_digest: *intent_digest,
            client_nonce: *client_nonce,
            server_nonce,
            deadline,
        };

        Ok(Response::Challenge {
            version: *version,
            intent_digest: *intent_digest,
            client_nonce: *client_nonce,
            server_nonce,
            expires_after_ms: MAX_CHALLENGE_EXPIRES_AFTER_MS,
        })
    }

    /// Revalidates and consumes the exact issued challenge into one permit.
    ///
    /// The state mutex remains held across binding validation, live peer
    /// revalidation, deadline checks, and the terminal transition.
    ///
    /// # Errors
    ///
    /// Refuses invalid, out-of-order, mismatched, expired, or no-longer-valid
    /// peer confirmations. Binding and revalidation refusals preserve the
    /// challenge unless its deadline has elapsed; expiry is terminal.
    pub fn confirm(
        &self,
        request: &Request,
    ) -> Result<(Response, CommissioningBootstrapPermit), SessionError> {
        let mut state = self
            .state
            .lock()
            .expect("session state lock is not poisoned");
        let State::Challenged {
            peer,
            intent_digest,
            client_nonce,
            server_nonce,
            deadline,
        } = &*state
        else {
            return Err(SessionError::WrongState);
        };

        if self.now() >= *deadline {
            *state = State::Consumed;
            return Err(SessionError::Expired);
        }

        request.validate()?;
        let Request::Confirm {
            version,
            intent_digest: confirmed_digest,
            client_nonce: confirmed_client_nonce,
            server_nonce: confirmed_server_nonce,
            sequence,
        } = request
        else {
            return Err(SessionError::WrongState);
        };
        if *version != VERSION
            || confirmed_digest != intent_digest
            || confirmed_client_nonce != client_nonce
            || confirmed_server_nonce != server_nonce
            || *sequence != CONFIRM_SEQUENCE
        {
            return Err(SessionError::BindingMismatch);
        }

        if peer.revalidate().is_err() {
            if self.now() >= *deadline {
                *state = State::Consumed;
                return Err(SessionError::Expired);
            }
            return Err(SessionError::PeerRevalidation);
        }
        if self.now() >= *deadline {
            *state = State::Consumed;
            return Err(SessionError::Expired);
        }

        let State::Challenged {
            peer,
            intent_digest,
            client_nonce,
            server_nonce,
            ..
        } = std::mem::replace(&mut *state, State::Consumed)
        else {
            unreachable!("challenged state was retained while holding the same mutex");
        };
        let response = Response::Accepted {
            version: VERSION,
            intent_digest,
            client_nonce,
            server_nonce,
            sequence: CONFIRM_SEQUENCE,
        };
        let permit = CommissioningBootstrapPermit {
            intent_digest,
            peer,
        };
        Ok((response, permit))
    }

    fn now(&self) -> Instant {
        #[cfg(test)]
        {
            (self.clock)()
        }
        #[cfg(not(test))]
        {
            Instant::now()
        }
    }

    fn server_nonce(&self) -> Result<[u8; 32], SessionError> {
        #[cfg(test)]
        {
            if self.nonce.iter().all(|byte| *byte == 0) {
                return Err(SessionError::EntropyUnavailable);
            }
            Ok(self.nonce)
        }
        #[cfg(not(test))]
        {
            let mut nonce = [0_u8; 32];
            rand::rngs::SysRng
                .try_fill_bytes(&mut nonce)
                .map_err(|_| SessionError::EntropyUnavailable)?;
            if nonce.iter().all(|byte| *byte == 0) {
                return Err(SessionError::EntropyUnavailable);
            }
            Ok(nonce)
        }
    }
}

/// One-use authority to continue commissioning for one exact intent and peer.
///
/// Fields are private and this unique resource implements neither cloning nor
/// serialization. The permit itself performs no commissioning effect.
///
/// ```compile_fail
/// use mvm_hostd::commissioning_bootstrap_session::CommissioningBootstrapPermit;
///
/// fn duplicate(permit: CommissioningBootstrapPermit) {
///     let _copy = permit.clone();
/// }
/// ```
///
/// ```compile_fail
/// use mvm_hostd::{
///     caller_identity::macos_peer::VerifiedMacPeer,
///     commissioning_bootstrap_session::CommissioningBootstrapPermit,
/// };
///
/// fn forge(peer: VerifiedMacPeer) -> CommissioningBootstrapPermit {
///     CommissioningBootstrapPermit {
///         intent_digest: [1; 32],
///         peer,
///     }
/// }
/// ```
///
/// ```compile_fail
/// use mvm_hostd::commissioning_bootstrap_session::CommissioningBootstrapPermit;
///
/// fn serialize(permit: &CommissioningBootstrapPermit) {
///     let _bytes = serde_json::to_vec(permit).unwrap();
/// }
/// ```
pub struct CommissioningBootstrapPermit {
    intent_digest: [u8; 32],
    peer: VerifiedMacPeer,
}

impl fmt::Debug for CommissioningBootstrapPermit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CommissioningBootstrapPermit")
            .field("intent_digest", &"[REDACTED]")
            .field("peer", &self.peer)
            .finish()
    }
}

impl CommissioningBootstrapPermit {
    /// Returns the exact commissioning-intent digest bound by the exchange.
    #[must_use]
    pub fn intent_digest(&self) -> &[u8; 32] {
        &self.intent_digest
    }

    /// Revalidates the retained live peer immediately before a later effect.
    ///
    /// # Errors
    ///
    /// Refuses every failure from the original macOS peer verifier without a
    /// weaker UID-only success path.
    pub fn revalidate(
        &self,
    ) -> Result<(), crate::caller_identity::macos_peer::MacPeerVerificationError> {
        self.peer.revalidate()
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use std::{
        ffi::c_void,
        sync::{
            Arc, Barrier, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
        thread,
    };

    use core_foundation::{base::TCFType as _, string::CFString};
    use security_framework::os::macos::code_signing::{Flags, SecCode, SecRequirement};

    use super::*;
    use crate::caller_identity::macos_peer::{
        AUDIT_TOKEN_BYTES, DesignatedRequirement, MacAuditToken,
    };

    const AUDIT_TOKEN_WORDS: usize = 8;
    const TASK_AUDIT_TOKEN: u32 = 15;

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

    #[allow(deprecated)] // libc preserves the Darwin mach_port_t ABI used by this native test.
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
            SecCodeCopyDesignatedRequirement(code.as_concrete_TypeRef().cast(), 0, &mut requirement)
        };
        assert_eq!(status, 0, "current code has a designated requirement");
        assert!(!requirement.is_null(), "requirement output is non-null");

        let mut text = std::ptr::null();
        // SAFETY: `requirement` is the live create-rule object returned above.
        let status = unsafe { SecRequirementCopyString(requirement, 0, &mut text) };
        // SAFETY: transfer the create-rule requirement to the Rust wrapper.
        let _requirement =
            unsafe { SecRequirement::wrap_under_create_rule(requirement.cast_mut().cast()) };
        assert_eq!(status, 0, "designated requirement converts to source");
        assert!(!text.is_null(), "requirement source output is non-null");
        // SAFETY: transfer the create-rule string to the Rust wrapper.
        let text = unsafe { CFString::wrap_under_create_rule(text.cast_mut().cast()) };
        DesignatedRequirement::new(&text.to_string()).expect("native source satisfies bound")
    }

    fn live_peer(
        recapture: impl Fn() -> Option<MacAuditToken> + Send + Sync + 'static,
    ) -> VerifiedMacPeer {
        let token = current_token().expect("host supports TASK_AUDIT_TOKEN");
        // SAFETY: `geteuid` takes no pointers and has no caller preconditions.
        let expected_euid = unsafe { libc::geteuid() };
        VerifiedMacPeer::verify(
            token,
            expected_euid,
            self_designated_requirement(),
            recapture,
        )
        .expect("current process satisfies its live designated requirement")
    }

    #[derive(Clone)]
    struct TestClock {
        now: Arc<Mutex<Instant>>,
    }

    impl TestClock {
        fn new() -> Self {
            Self {
                now: Arc::new(Mutex::new(Instant::now())),
            }
        }

        fn callback(&self) -> Arc<dyn Fn() -> Instant + Send + Sync> {
            let now = Arc::clone(&self.now);
            Arc::new(move || *now.lock().expect("test clock lock is not poisoned"))
        }

        fn advance(&self, duration: Duration) {
            let mut now = self.now.lock().expect("test clock lock is not poisoned");
            *now += duration;
        }
    }

    fn begin_request() -> Request {
        Request::Begin {
            version: VERSION,
            intent_digest: [7; 32],
            client_nonce: [8; 32],
        }
    }

    fn session_with(peer: VerifiedMacPeer) -> (CommissioningBootstrapSession, TestClock, [u8; 32]) {
        let clock = TestClock::new();
        let server_nonce = [9; 32];
        (
            CommissioningBootstrapSession::new_for_test(
                peer,
                [7; 32],
                clock.callback(),
                server_nonce,
            ),
            clock,
            server_nonce,
        )
    }

    fn confirm_request(server_nonce: [u8; 32]) -> Request {
        Request::Confirm {
            version: VERSION,
            intent_digest: [7; 32],
            client_nonce: [8; 32],
            server_nonce,
            sequence: CONFIRM_SEQUENCE,
        }
    }

    #[test]
    fn live_peer_happy_path_yields_one_bound_permit() {
        let (session, _clock, server_nonce) = session_with(live_peer(current_token));
        let challenge = session.begin(&begin_request()).expect("begin succeeds");
        assert_eq!(
            challenge,
            Response::Challenge {
                version: VERSION,
                intent_digest: [7; 32],
                client_nonce: [8; 32],
                server_nonce,
                expires_after_ms: MAX_CHALLENGE_EXPIRES_AFTER_MS,
            }
        );

        let (accepted, permit) = session
            .confirm(&confirm_request(server_nonce))
            .expect("exact live confirmation succeeds");
        assert_eq!(
            accepted,
            Response::Accepted {
                version: VERSION,
                intent_digest: [7; 32],
                client_nonce: [8; 32],
                server_nonce,
                sequence: CONFIRM_SEQUENCE,
            }
        );
        assert_eq!(permit.intent_digest(), &[7; 32]);
        permit
            .revalidate()
            .expect("permit retains the same live verifier");
    }

    #[test]
    fn confirm_before_begin_and_duplicate_begin_refuse() {
        let (session, _clock, server_nonce) = session_with(live_peer(current_token));
        assert!(matches!(
            session.confirm(&confirm_request(server_nonce)),
            Err(SessionError::WrongState)
        ));
        session
            .begin(&begin_request())
            .expect("first begin succeeds");
        assert_eq!(
            session.begin(&begin_request()),
            Err(SessionError::WrongState)
        );
        assert!(
            session.confirm(&confirm_request(server_nonce)).is_ok(),
            "duplicate begin must preserve the issued challenge"
        );
    }

    #[test]
    fn begin_must_match_the_independently_selected_intent() {
        let (session, _clock, server_nonce) = session_with(live_peer(current_token));
        let mismatched = Request::Begin {
            version: VERSION,
            intent_digest: [6; 32],
            client_nonce: [8; 32],
        };
        assert_eq!(
            session.begin(&mismatched),
            Err(SessionError::BindingMismatch)
        );
        session
            .begin(&begin_request())
            .expect("mismatch preserves the fresh session");
        assert!(
            session.confirm(&confirm_request(server_nonce)).is_ok(),
            "the selected intent remains usable"
        );
    }

    #[test]
    fn every_confirmation_binding_mismatch_preserves_the_challenge() {
        let (session, _clock, server_nonce) = session_with(live_peer(current_token));
        session.begin(&begin_request()).expect("begin succeeds");

        let mismatches = [
            Request::Confirm {
                version: VERSION,
                intent_digest: [6; 32],
                client_nonce: [8; 32],
                server_nonce,
                sequence: CONFIRM_SEQUENCE,
            },
            Request::Confirm {
                version: VERSION,
                intent_digest: [7; 32],
                client_nonce: [6; 32],
                server_nonce,
                sequence: CONFIRM_SEQUENCE,
            },
            Request::Confirm {
                version: VERSION,
                intent_digest: [7; 32],
                client_nonce: [8; 32],
                server_nonce: [6; 32],
                sequence: CONFIRM_SEQUENCE,
            },
        ];
        for mismatch in mismatches {
            assert!(matches!(
                session.confirm(&mismatch),
                Err(SessionError::BindingMismatch)
            ));
        }
        assert!(
            session.confirm(&confirm_request(server_nonce)).is_ok(),
            "mismatches must not consume the challenge"
        );
    }

    #[test]
    fn replay_refuses_after_success() {
        let (session, _clock, server_nonce) = session_with(live_peer(current_token));
        session.begin(&begin_request()).expect("begin succeeds");
        let confirm = confirm_request(server_nonce);
        let _permit = session.confirm(&confirm).expect("first confirm succeeds").1;
        assert!(matches!(
            session.confirm(&confirm),
            Err(SessionError::WrongState)
        ));
    }

    #[test]
    fn expiry_is_terminal_and_precedes_peer_revalidation() {
        let recaptures = Arc::new(AtomicUsize::new(0));
        let recapture_count = Arc::clone(&recaptures);
        let peer = live_peer(move || {
            recapture_count.fetch_add(1, Ordering::SeqCst);
            current_token()
        });
        let (session, clock, server_nonce) = session_with(peer);
        session.begin(&begin_request()).expect("begin succeeds");
        clock.advance(CHALLENGE_LIFETIME);

        assert!(matches!(
            session.confirm(&confirm_request(server_nonce)),
            Err(SessionError::Expired)
        ));
        assert_eq!(recaptures.load(Ordering::SeqCst), 0);
        assert!(matches!(
            session.confirm(&confirm_request(server_nonce)),
            Err(SessionError::WrongState)
        ));
    }

    #[test]
    fn failed_revalidation_does_not_consume_an_unexpired_challenge() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let attempt_count = Arc::clone(&attempts);
        let peer = live_peer(move || {
            (attempt_count.fetch_add(1, Ordering::SeqCst) > 0)
                .then(current_token)
                .flatten()
        });
        let (session, _clock, server_nonce) = session_with(peer);
        session.begin(&begin_request()).expect("begin succeeds");
        let confirm = confirm_request(server_nonce);

        assert!(matches!(
            session.confirm(&confirm),
            Err(SessionError::PeerRevalidation)
        ));
        assert!(
            session.confirm(&confirm).is_ok(),
            "a later successful revalidation can consume the same challenge"
        );
    }

    #[test]
    fn two_simultaneous_confirms_yield_exactly_one_permit() {
        let (session, _clock, server_nonce) = session_with(live_peer(current_token));
        session.begin(&begin_request()).expect("begin succeeds");
        let session = Arc::new(session);
        let barrier = Arc::new(Barrier::new(3));

        let handles: Vec<_> = (0..2)
            .map(|_| {
                let session = Arc::clone(&session);
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    session.confirm(&confirm_request(server_nonce))
                })
            })
            .collect();
        barrier.wait();
        let results: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().expect("confirm thread does not panic"))
            .collect();

        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Err(SessionError::WrongState)))
                .count(),
            1
        );
    }
}
