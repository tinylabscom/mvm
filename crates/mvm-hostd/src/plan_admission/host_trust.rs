//! Host-owned trust roots and grant ceiling for plan admission.

use anyhow::Result;
use ed25519_dalek::VerifyingKey;
use mvm_contract::grants::ceiling::GrantCeiling;

/// The external plan signers this host trusts, from operator config.
///
/// Read from config rather than taken as a parameter for the same reason as
/// the grant ceiling: admission's trust root must not be widen-able by the
/// caller asking for admission. A malformed pin fails the whole read, so the
/// set in force is exactly the set the operator wrote.
pub(super) fn host_trusted_plan_signers() -> Result<Vec<(String, VerifyingKey)>> {
    mvm_core::user_config::load(None).trusted_plan_signer_keys()
}

/// The bound this host puts on what any workload may be granted.
///
/// Read from the operator's config, never from the plan under admission. The
/// two have different trust roots: whoever authors a plan also authors its
/// grants, so a ceiling the plan could carry would be a bound the bounded party
/// writes. There is no parameter for it here for the same reason — a caller
/// cannot hand admission a wider ceiling than the host configured.
pub(super) fn host_grant_ceiling() -> GrantCeiling {
    mvm_core::user_config::load(None).grant_ceiling()
}
