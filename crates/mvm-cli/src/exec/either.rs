//! A two-shape return value, and nothing else.
//!
//! `run` and `run_captured` differ only in what they hand back, and the
//! function they share has to return both. That is a generic utility with no
//! launch semantics in it, so it sits here rather than in the orchestrator it
//! happens to serve.

/// Tagged union for the two return shapes `run` and `run_captured` share.
/// Internal — the public API exposes the unboxed variants.
pub(super) enum Either<L, R> {
    Left(L),
    Right(R),
}

impl<L, R> Either<L, R> {
    pub(super) fn left(self) -> Option<L> {
        match self {
            Either::Left(l) => Some(l),
            Either::Right(_) => None,
        }
    }

    pub(super) fn right(self) -> Option<R> {
        match self {
            Either::Right(r) => Some(r),
            Either::Left(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each accessor answers for its own variant and refuses the other, which
    /// is the whole contract: the callers `.expect()` on these, so a wrong
    /// answer would surface as a panic far from here.
    #[test]
    fn each_side_answers_only_for_itself() {
        assert_eq!(Either::<i32, &str>::Left(7).left(), Some(7));
        assert_eq!(Either::<i32, &str>::Left(7).right(), None);
        assert_eq!(Either::<i32, &str>::Right("x").right(), Some("x"));
        assert_eq!(Either::<i32, &str>::Right("x").left(), None);
    }
}
