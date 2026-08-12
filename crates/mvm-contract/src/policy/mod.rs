//! Policy DTO leaves — the pure serde types describing session/frame
//! security posture, sub-policy shapes referenced by `PolicyBundle`,
//! per-destination egress redaction, per-destination reversible-
//! replacement rules, admission-time DNS pins, and CLI secret bindings —
//! plus the egress-projection decision core, which is pure decision logic
//! over those DTOs with no I/O and no resolver. Signing and
//! clock-/env-/fs-dependent logic stays in `mvm-core::policy`, which
//! re-exports these modules at their existing paths.

pub mod approval;
pub mod audit;
pub mod bundle;
pub mod dns_pin;
pub mod network_policy;
pub mod policies;
pub mod projection;
pub mod redaction;
pub mod resolver;
pub mod reversible_replacement;
pub mod secret_binding;
pub mod security;
