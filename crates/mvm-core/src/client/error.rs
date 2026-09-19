//! The facade's error type. Deliberately transport-agnostic: a `LocalBackend`
//! and a `GatewayBackend` surface the same variants so callers branch on the
//! failure, not on which backend produced it.

use thiserror::Error;

pub type Result<T> = std::result::Result<T, MvmError>;

#[derive(Debug, Clone, Error)]
pub enum MvmError {
    #[error("machine not found: {id}")]
    NotFound { id: String },
    #[error("invalid machine spec: {reason}")]
    InvalidSpec { reason: String },
    #[error("backend error: {reason}")]
    Backend { reason: String },
    #[error("unauthorized: {reason}")]
    Unauthorized { reason: String },
    #[error("conflict: {reason}")]
    Conflict { reason: String },
    #[error("request rejected: {reason}")]
    Rejected { reason: String },
    #[error("service unavailable: {reason}")]
    Unavailable { reason: String },
}

impl MvmError {
    /// A stable, machine-readable identifier for this variant. Every surface
    /// that reports an `MvmError` to a programmatic caller (currently the MCP
    /// tool server's `_meta`) derives its error code from here, so the
    /// mapping has exactly one source of truth instead of drifting copies.
    pub fn code(&self) -> &'static str {
        match self {
            Self::NotFound { .. } => "NOT_FOUND",
            Self::InvalidSpec { .. } => "INVALID_SPEC",
            Self::Backend { .. } => "BACKEND_ERROR",
            Self::Unauthorized { .. } => "UNAUTHORIZED",
            Self::Conflict { .. } => "CONFLICT",
            Self::Rejected { .. } => "REJECTED",
            Self::Unavailable { .. } => "UNAVAILABLE",
        }
    }

    /// Whether a caller may reasonably retry the exact same request and
    /// expect a different outcome. Only `Unavailable` describes a transient
    /// backend condition; every other variant is a property of the request
    /// itself and retrying it unchanged would fail the same way.
    pub fn retryable(&self) -> bool {
        matches!(self, Self::Unavailable { .. })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn not_found_displays_the_id() {
        let e = MvmError::NotFound { id: "m1".into() };
        assert_eq!(e.to_string(), "machine not found: m1");
    }

    /// How many arms `pinned` has. This is a hand-written literal: the
    /// compiler does not tie it to the `match`, so a new variant must bump it
    /// by hand. When it is bumped, a walk that stops short of the new variant
    /// fails below; when it is not, the new variant can go unwalked.
    const PINNED_VARIANTS: usize = 7;

    /// The code and retryability each variant is documented to carry,
    /// written as literals in a `match` with no wildcard arm and kept apart
    /// from `MvmError::code`/`retryable` themselves: a new variant does not
    /// compile until its strings are written down here, rather than
    /// inheriting whatever `code()` happens to return for it.
    fn pinned(error: &MvmError) -> (&'static str, bool) {
        match error {
            MvmError::NotFound { .. } => ("NOT_FOUND", false),
            MvmError::InvalidSpec { .. } => ("INVALID_SPEC", false),
            MvmError::Backend { .. } => ("BACKEND_ERROR", false),
            MvmError::Unauthorized { .. } => ("UNAUTHORIZED", false),
            MvmError::Conflict { .. } => ("CONFLICT", false),
            MvmError::Rejected { .. } => ("REJECTED", false),
            MvmError::Unavailable { .. } => ("UNAVAILABLE", true),
        }
    }

    /// The variant after `error` in a fixed walk, `None` after the last.
    ///
    /// The list the tests iterate is produced by this `match`, not written
    /// beside it, so a new variant does not compile until it has an arm
    /// here naming its successor. It joins the walk when the arm before it
    /// names it in turn. The one way to leave a variant out is an arm that
    /// no other arm points to, which is visible in this function alone.
    fn successor(error: &MvmError) -> Option<MvmError> {
        let reason = || "r".to_string();
        match error {
            MvmError::NotFound { .. } => Some(MvmError::InvalidSpec { reason: reason() }),
            MvmError::InvalidSpec { .. } => Some(MvmError::Backend { reason: reason() }),
            MvmError::Backend { .. } => Some(MvmError::Unauthorized { reason: reason() }),
            MvmError::Unauthorized { .. } => Some(MvmError::Conflict { reason: reason() }),
            MvmError::Conflict { .. } => Some(MvmError::Rejected { reason: reason() }),
            MvmError::Rejected { .. } => Some(MvmError::Unavailable { reason: reason() }),
            MvmError::Unavailable { .. } => None,
        }
    }

    fn every_variant() -> Vec<MvmError> {
        let mut all = Vec::new();
        let mut next = Some(MvmError::NotFound { id: "m1".into() });
        while let Some(error) = next {
            next = successor(&error);
            all.push(error);
            assert!(all.len() <= 64, "`successor` loops: {all:?}");
        }
        all
    }

    /// The walk visits each variant once and reaches all of them: an arm of
    /// `successor` pointing back would repeat a code, and one ending the walk
    /// early would fall short of `PINNED_VARIANTS` and could drop the
    /// retryable variant, which the walk must contain.
    #[test]
    fn the_variant_walk_visits_each_variant_once() {
        let all = every_variant();
        let codes: Vec<&str> = all.iter().map(|e| pinned(e).0).collect();
        let mut distinct = codes.clone();
        distinct.sort_unstable();
        distinct.dedup();
        assert_eq!(codes.len(), distinct.len(), "{codes:?}");
        assert_eq!(codes.len(), PINNED_VARIANTS, "{codes:?}");
        assert!(
            all.iter()
                .any(|e| matches!(e, MvmError::Unavailable { .. })),
            "{codes:?}"
        );
    }

    #[test]
    fn only_unavailable_is_retryable() {
        for error in &every_variant() {
            assert_eq!(
                error.retryable(),
                pinned(error).1,
                "{error:?} retryable mismatch"
            );
        }
    }

    #[test]
    fn every_variant_has_the_documented_stable_code() {
        for error in &every_variant() {
            assert_eq!(error.code(), pinned(error).0, "{error:?} code mismatch");
        }
    }
}
