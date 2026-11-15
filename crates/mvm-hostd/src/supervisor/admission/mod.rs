//! Admission-adjacent supervisor code: cold-start caller registration, and the verification and arming of plans a restored or warm-claimed child inherits.

pub mod caller_registration;
/// Arming a warm-claimed child's bounds in the standby supervisor it inherits.
pub mod claimed_child;
pub mod protected_handoff;
/// Verification of the plan a restored child's supervisor takes as authority.
pub mod restored_plan;
