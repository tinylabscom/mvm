//! Guest-side VMGenID reseed.
//!
//! On a snapshot resume the host delivers a fresh generation token (see
//! [`mvm_core::crypto::vmgenid`]). When the token **changes** — meaning this
//! guest is a clone of a snapshot, not a normal wake of the same VM — the
//! guest must reseed its CSPRNG so two clones don't generate identical
//! nonces/keys (a real key-reuse break), and drop its vsock session so a
//! fresh Ed25519 handshake runs.
//!
//! The pure change-detection lives in `GenIdState`; this wraps it with the
//! guest-side reseed I/O. Delivery (the host sending the token over the
//! resume RPC) is the remaining wiring.

use std::io::Write;

use mvm_core::crypto::vmgenid::{GENID_BYTES, GenIdState};

/// What [`GenIdReseeder::on_genid`] did with a delivered token.
#[derive(Debug, PartialEq, Eq)]
pub enum GenIdAction {
    /// Token unchanged — a normal wake of the same VM. Nothing to do.
    Unchanged,
    /// Token changed — CSPRNG reseeded; the caller must drop the vsock
    /// session so a fresh handshake runs (new session keys, no carried
    /// sequence numbers).
    Reseeded,
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

    /// Process a delivered generation token. On a change, reseed the kernel
    /// CSPRNG and report [`GenIdAction::Reseeded`]; an unchanged token is a
    /// no-op. The reseed is best-effort — a failure to stir the pool is
    /// logged by the caller, never fatal (the token mismatch is still
    /// recorded so a retry on the next delivery converges).
    pub fn on_genid(&mut self, token: [u8; GENID_BYTES]) -> GenIdAction {
        if !self.state.on_genid(token) {
            return GenIdAction::Unchanged;
        }
        if let Err(e) = reseed_kernel_csprng(&token) {
            // Non-fatal: divergence via the write is best-effort, and the
            // state has already advanced so we don't loop on the same token.
            tracing::warn!("genid reseed: stirring /dev/urandom failed: {e}");
        }
        GenIdAction::Reseeded
    }

    /// Dispatch a token delivered on the `PostRestore` resume RPC. An all-zero
    /// token means "no rotation requested" — the resume carried no fresh
    /// generation (e.g. a template restore that just remounts drives), so the
    /// change-detector is left untouched and a later real token still rotates.
    /// Any non-zero token runs the normal change-detect-and-reseed path.
    pub fn on_post_restore_token(&mut self, token: [u8; GENID_BYTES]) -> GenIdAction {
        if token == [0u8; GENID_BYTES] {
            return GenIdAction::Unchanged;
        }
        self.on_genid(token)
    }
}

/// Mix `token` into the kernel CSPRNG by writing it to `/dev/urandom`.
///
/// On Linux a plain write to `/dev/urandom` stirs the pool (no
/// `CAP_SYS_ADMIN` needed — that's only for *crediting* entropy via
/// `RNDADDENTROPY`, which divergence doesn't require). Two clones writing
/// two distinct tokens end up with distinct pool state, so their subsequent
/// `getrandom` output diverges — which is the whole point.
pub fn reseed_kernel_csprng(token: &[u8; GENID_BYTES]) -> std::io::Result<()> {
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/urandom")?;
    f.write_all(token)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn changed_genid_forces_reseed_and_session_reset() {
        let mut r = GenIdReseeder::new([1u8; GENID_BYTES]);
        assert_eq!(r.on_genid([1u8; GENID_BYTES]), GenIdAction::Unchanged);
        assert_eq!(r.on_genid([2u8; GENID_BYTES]), GenIdAction::Reseeded);
        // Same token again is a no-op (normal wake, not a fresh clone).
        assert_eq!(r.on_genid([2u8; GENID_BYTES]), GenIdAction::Unchanged);
    }

    #[test]
    fn post_restore_zero_token_is_no_rotation() {
        // Baseline-zero seed mirrors the agent's static reseeder before any
        // real token has been delivered.
        let mut r = GenIdReseeder::new([0u8; GENID_BYTES]);
        // A no-rotation resume (zero token) must not advance the detector...
        assert_eq!(
            r.on_post_restore_token([0u8; GENID_BYTES]),
            GenIdAction::Unchanged
        );
        // ...so a later real token still counts as a fresh clone and rotates.
        assert_eq!(
            r.on_post_restore_token([7u8; GENID_BYTES]),
            GenIdAction::Reseeded
        );
        // Re-sending the same token (idempotent PostRestore) is a no-op.
        assert_eq!(
            r.on_post_restore_token([7u8; GENID_BYTES]),
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
        // The host delivers a distinct fresh token to each clone; both rotate.
        assert_eq!(
            clone_a.on_post_restore_token([10u8; GENID_BYTES]),
            GenIdAction::Reseeded
        );
        assert_eq!(
            clone_b.on_post_restore_token([20u8; GENID_BYTES]),
            GenIdAction::Reseeded
        );
    }
}
