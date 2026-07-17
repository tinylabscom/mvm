//! Policy DTO leaves — the pure serde types describing session/frame
//! security posture, sub-policy shapes referenced by `PolicyBundle`,
//! per-destination egress redaction, and per-destination reversible-
//! replacement rules. Resolution, signing, and enforcement logic stays in
//! `mvm-core::policy`, which re-exports these modules at their existing
//! paths.

pub mod bundle;
pub mod policies;
pub mod redaction;
pub mod reversible_replacement;
pub mod security;
