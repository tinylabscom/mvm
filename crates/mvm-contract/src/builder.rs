//! The single failure a builder can report: a required field was never set.
//!
//! Every input-parameter struct in the workspace is constructed through a
//! generated builder so a call site names each value instead of ordering it.
//! A builder starts empty, so `build()` has to distinguish "the caller left
//! this out" from "the caller chose the empty value" — a defaulted required
//! field is exactly the silent-wrong-value bug the builder exists to prevent.
//! One shared error keeps that check uniform without each module minting its
//! own near-identical enum.

use thiserror::Error;

/// A required field of `type_name` was still unset when `build()` ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Error)]
#[error("{type_name}::builder() is missing required field `{field}`")]
pub struct BuilderError {
    /// The type whose builder refused to finish.
    pub type_name: &'static str,
    /// The field the caller never set.
    pub field: &'static str,
}

impl BuilderError {
    /// The error a generated `build()` returns for an unset `field`.
    #[must_use]
    pub const fn missing(type_name: &'static str, field: &'static str) -> Self {
        Self { type_name, field }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    #[test]
    fn the_message_names_the_type_and_the_field() {
        let err = BuilderError::missing("ForkParams", "child_name");
        assert_eq!(
            err.to_string(),
            "ForkParams::builder() is missing required field `child_name`"
        );
    }

    #[test]
    fn two_errors_for_the_same_field_compare_equal() {
        assert_eq!(
            BuilderError::missing("A", "b"),
            BuilderError::missing("A", "b")
        );
        assert_ne!(
            BuilderError::missing("A", "b"),
            BuilderError::missing("A", "c")
        );
    }
}
