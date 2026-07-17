//! Policy DTO leaves — the pure serde types describing session/frame
//! security posture and per-destination reversible-replacement rules.
//! Resolution, signing, and enforcement logic stays in
//! `mvm-core::policy`, which re-exports these modules at their existing
//! paths.

pub mod reversible_replacement;
pub mod security;
