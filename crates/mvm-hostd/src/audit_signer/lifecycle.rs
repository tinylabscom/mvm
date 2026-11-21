//! Lifecycle-chain appends on behalf of a keyless broker.
//!
//! The signer helper and the per-VM audit signer each serve exactly one
//! tenant, fixed in their spawn config. A lifecycle entry is appended to that
//! tenant's chain, `<audit_dir>/<tenant>.jsonl`, through the same writer
//! [`AuditEmitter`] uses, so it takes the chain's `.lock` and interleaves with
//! every other writer of that file. An entry naming any other tenant is
//! refused, as is one whose labels the event does not carry.
//!
//! The unit and epoch an entry is recorded under are the signer's: the ones
//! the VM was registered with, not the caller's. An entry naming another unit
//! or epoch is refused, and a VM registered without them cannot append.

use std::path::Path;

use mvm_core::plan::TenantId;
use mvm_core::protocol::audit_signer::{AuditSignerErrorCode, RegisteredUnit};
use mvm_core::protocol::lifecycle_audit::{LifecycleEntry, LifecycleLabel};
use tracing::warn;

use crate::audit::emitter::AuditEmitter;

/// Append `entry` to the chain of `served_tenant`, signed with the key at
/// `key_path`.
///
/// # Errors
///
/// `InvalidRequest` for an entry that names another tenant, another unit or
/// epoch than `registered`, or carries a label its event does not; `NotReady`
/// for a VM registered without a unit and epoch; `NotReady` for a signer with no key file, since an
/// entry under a key generated at boot would not verify; `InternalError` for
/// a failed write.
pub fn append(
    served_tenant: &str,
    registered: Option<&RegisteredUnit>,
    key_path: Option<&Path>,
    entry: &LifecycleEntry,
) -> Result<(), AuditSignerErrorCode> {
    if entry.tenant_id != served_tenant || entry.validate().is_err() {
        return Err(AuditSignerErrorCode::InvalidRequest);
    }
    let entry = attributed(entry, registered)?;
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

/// `entry` with the unit and epoch set to the registered ones. An entry that
/// names others is refused rather than rewritten, since the caller that sent
/// it is not the one it claims to speak for.
fn attributed(
    entry: &LifecycleEntry,
    registered: Option<&RegisteredUnit>,
) -> Result<LifecycleEntry, AuditSignerErrorCode> {
    let Some(registered) = registered else {
        return Err(AuditSignerErrorCode::NotReady);
    };
    let epoch = registered.epoch.get().to_string();
    let matches = |label, value: &str| entry.labels.get(&label).is_none_or(|v| v == value);
    if !matches(LifecycleLabel::Unit, &registered.unit) || !matches(LifecycleLabel::Epoch, &epoch) {
        return Err(AuditSignerErrorCode::InvalidRequest);
    }
    let mut entry = entry.clone();
    entry
        .labels
        .insert(LifecycleLabel::Unit, registered.unit.clone());
    entry.labels.insert(LifecycleLabel::Epoch, epoch);
    Ok(entry)
}

#[cfg(test)]
#[path = "lifecycle_tests.rs"]
mod tests;
