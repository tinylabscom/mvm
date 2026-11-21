//! Lifecycle-chain appends on behalf of a keyless broker.
//!
//! The signer helper and the per-VM audit signer each serve exactly one
//! tenant, fixed in their spawn config. A lifecycle entry is appended to that
//! tenant's chain, `<audit_dir>/<tenant>.jsonl`, through the same writer
//! [`AuditEmitter`] uses, so it takes the chain's `.lock` and interleaves with
//! every other writer of that file. An entry naming any other tenant is
//! refused, as is one whose labels the event does not carry.

use std::path::Path;

use mvm_core::plan::TenantId;
use mvm_core::protocol::audit_signer::AuditSignerErrorCode;
use mvm_core::protocol::lifecycle_audit::LifecycleEntry;
use tracing::warn;

use crate::audit::emitter::AuditEmitter;

/// Append `entry` to the chain of `served_tenant`, signed with the key at
/// `key_path`.
///
/// # Errors
///
/// `InvalidRequest` for an entry that names another tenant or carries a label
/// its event does not; `NotReady` for a signer with no key file, since an
/// entry under a key generated at boot would not verify; `InternalError` for
/// a failed write.
pub fn append(
    served_tenant: &str,
    key_path: Option<&Path>,
    entry: &LifecycleEntry,
) -> Result<(), AuditSignerErrorCode> {
    if entry.tenant_id != served_tenant || entry.validate().is_err() {
        return Err(AuditSignerErrorCode::InvalidRequest);
    }
    let Some(key_path) = key_path else {
        return Err(AuditSignerErrorCode::NotReady);
    };
    let written = crate::audit_signer::chain::read_chain_key(key_path)
        .and_then(AuditEmitter::new)
        .and_then(|emitter| {
            emitter.emit_topology_decision(
                &TenantId(served_tenant.to_string()),
                entry.event.as_str(),
                entry
                    .labels
                    .iter()
                    .map(|(k, v)| (k.as_str().to_string(), v.clone())),
            )
        });
    written.map_err(|e| {
        warn!(error = %format!("{e:#}"), event = entry.event.as_str(), "lifecycle append failed");
        AuditSignerErrorCode::InternalError
    })
}

#[cfg(test)]
#[path = "lifecycle_tests.rs"]
mod tests;
