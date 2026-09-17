//! Guest-side reseed on a generation-token change.
//!
//! On a snapshot resume the host delivers a fresh generation token (see
//! [`mvm_core::crypto::vmgenid`]). When the token **changes** — meaning this
//! guest is a clone of a snapshot, not a normal wake of the same VM — the
//! guest must reseed the kernel's random generator so two clones don't
//! generate identical nonces or keys, and drop its vsock session so a fresh
//! Ed25519 handshake runs.
//!
//! Mixing the token into the kernel's input pool is not enough on its own: the
//! generator behind `getrandom` keeps its current key until the kernel's own
//! reseed schedule folds the pool in, so clones would keep producing identical
//! output until then. The reseed this module drives therefore has to force the
//! generator to rekey at once; [`crate::crng_reseed`] does that.
//!
//! The pure change-detection lives in `GenIdState`. The reseed itself is
//! injected, so a failed reseed is observable in tests and is never reported
//! as a rotation.

use mvm_core::crypto::vmgenid::{GENID_BYTES, GenIdState};

use crate::vsock::ReseedShortfall;

/// A reseed that did not happen, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReseedFailure {
    /// Whether the guest cannot reseed at all or tried and failed.
    pub shortfall: ReseedShortfall,
    /// The reason, for the operator.
    pub reason: String,
}

impl std::fmt::Display for ReseedFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.reason)
    }
}

/// What [`GenIdReseeder::on_genid`] did with a delivered token.
#[derive(Debug, PartialEq, Eq)]
pub enum GenIdAction {
    /// Token unchanged — a normal wake of the same VM. Nothing to do.
    Unchanged,
    /// Token changed and the kernel generator was rekeyed from it; the caller
    /// must drop the vsock session so a fresh handshake runs (new session
    /// keys, no carried sequence numbers).
    Reseeded,
    /// Token changed but the reseed did not happen. The guest is still drawing
    /// on the random state it was restored with, so it must not claim a fresh
    /// identity.
    ReseedFailed(ReseedFailure),
}

impl GenIdAction {
    /// Whether the guest may report that it rotated its random state.
    pub fn reseeded(&self) -> bool {
        matches!(self, GenIdAction::Reseeded)
    }
}

/// Wraps the pure [`GenIdState`] change-detector with the guest-side reseed
/// action.
pub struct GenIdReseeder {
    state: GenIdState,
}

impl GenIdReseeder {
    /// Seed with the generation token present at first boot/resume.
    pub const fn new(initial: [u8; GENID_BYTES]) -> Self {
        Self {
            state: GenIdState::new(initial),
        }
    }

    /// Process a delivered generation token. On a change, run `reseed` and
    /// report [`GenIdAction::Reseeded`] only if it succeeded; an unchanged token
    /// is a no-op.
    ///
    /// A failed reseed leaves the recorded token where it was. Advancing it
    /// would turn the host's retry with the same token into `Unchanged`, and
    /// the guest would never get a second chance to rotate.
    pub fn on_genid(
        &mut self,
        token: [u8; GENID_BYTES],
        reseed: impl FnOnce(&[u8; GENID_BYTES]) -> Result<(), ReseedFailure>,
    ) -> GenIdAction {
        if token == self.state.current() {
            return GenIdAction::Unchanged;
        }
        match reseed(&token) {
            Ok(()) => {
                self.state.on_genid(token);
                GenIdAction::Reseeded
            }
            Err(failure) => GenIdAction::ReseedFailed(failure),
        }
    }

    /// Dispatch a token delivered on the `PostRestore` resume RPC. An all-zero
    /// token means "no rotation requested" — the resume carried no fresh
    /// generation (e.g. a template restore that just remounts drives), so the
    /// change-detector is left untouched and a later real token still rotates.
    /// Any non-zero token runs the normal change-detect-and-reseed path.
    pub fn on_post_restore_token(
        &mut self,
        token: [u8; GENID_BYTES],
        reseed: impl FnOnce(&[u8; GENID_BYTES]) -> Result<(), ReseedFailure>,
    ) -> GenIdAction {
        if token == [0u8; GENID_BYTES] {
            return GenIdAction::Unchanged;
        }
        self.on_genid(token, reseed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn succeeds(_: &[u8; GENID_BYTES]) -> Result<(), ReseedFailure> {
        Ok(())
    }

    fn fails(_: &[u8; GENID_BYTES]) -> Result<(), ReseedFailure> {
        Err(ReseedFailure {
            shortfall: ReseedShortfall::Failed,
            reason: "RNDRESEEDCRNG: Operation not permitted".to_string(),
        })
    }

    #[test]
    fn changed_genid_forces_reseed_and_session_reset() {
        let mut r = GenIdReseeder::new([1u8; GENID_BYTES]);
        assert_eq!(
            r.on_genid([1u8; GENID_BYTES], succeeds),
            GenIdAction::Unchanged
        );
        assert_eq!(
            r.on_genid([2u8; GENID_BYTES], succeeds),
            GenIdAction::Reseeded
        );
        // Same token again is a no-op (normal wake, not a fresh clone).
        assert_eq!(
            r.on_genid([2u8; GENID_BYTES], succeeds),
            GenIdAction::Unchanged
        );
    }

    #[test]
    fn a_failed_reseed_is_never_reported_as_a_rotation() {
        let mut r = GenIdReseeder::new([1u8; GENID_BYTES]);
        let action = r.on_genid([2u8; GENID_BYTES], fails);
        assert!(
            matches!(&action, GenIdAction::ReseedFailed(f) if f.reason.contains("RNDRESEEDCRNG")),
            "the failure and its reason must be surfaced: {action:?}"
        );
        assert!(!action.reseeded());
    }

    #[test]
    fn a_failed_reseed_can_be_retried_with_the_same_token() {
        let mut r = GenIdReseeder::new([1u8; GENID_BYTES]);
        assert!(!r.on_genid([2u8; GENID_BYTES], fails).reseeded());
        assert_eq!(
            r.on_genid([2u8; GENID_BYTES], succeeds),
            GenIdAction::Reseeded,
            "a retry with the token that failed must reseed, not read as unchanged"
        );
    }

    #[test]
    fn an_unchanged_token_never_runs_the_reseed() {
        let mut r = GenIdReseeder::new([4u8; GENID_BYTES]);
        let action = r.on_genid([4u8; GENID_BYTES], |_| -> Result<(), ReseedFailure> {
            panic!("an unchanged token must not reseed")
        });
        assert_eq!(action, GenIdAction::Unchanged);
    }

    #[test]
    fn post_restore_zero_token_is_no_rotation() {
        // Baseline-zero seed mirrors the agent's static reseeder before any
        // real token has been delivered.
        let mut r = GenIdReseeder::new([0u8; GENID_BYTES]);
        // A no-rotation resume (zero token) must not advance the detector...
        assert_eq!(
            r.on_post_restore_token([0u8; GENID_BYTES], succeeds),
            GenIdAction::Unchanged
        );
        // ...so a later real token still counts as a fresh clone and rotates.
        assert_eq!(
            r.on_post_restore_token([7u8; GENID_BYTES], succeeds),
            GenIdAction::Reseeded
        );
        // Re-sending the same token (idempotent PostRestore) is a no-op.
        assert_eq!(
            r.on_post_restore_token([7u8; GENID_BYTES], succeeds),
            GenIdAction::Unchanged
        );
    }

    #[test]
    fn two_clones_of_one_snapshot_rotate_to_distinct_state() {
        // Both clones restore from the same snapshot-captured reseeder state.
        let snapshot_state = GenIdReseeder::new([3u8; GENID_BYTES]);
        let mut clone_a = GenIdReseeder {
            state: snapshot_state.state.clone(),
        };
        let mut clone_b = GenIdReseeder {
            state: snapshot_state.state,
        };
        // The host delivers a distinct fresh token to each clone, and each
        // clone reseeds from its own token.
        let mut mixed = Vec::new();
        assert_eq!(
            clone_a.on_post_restore_token([10u8; GENID_BYTES], |t| {
                mixed.push(*t);
                Ok::<(), ReseedFailure>(())
            }),
            GenIdAction::Reseeded
        );
        assert_eq!(
            clone_b.on_post_restore_token([20u8; GENID_BYTES], |t| {
                mixed.push(*t);
                Ok::<(), ReseedFailure>(())
            }),
            GenIdAction::Reseeded
        );
        assert_eq!(mixed, vec![[10u8; GENID_BYTES], [20u8; GENID_BYTES]]);
    }
}
