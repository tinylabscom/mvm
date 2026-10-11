//! Shared audit-prune operation. Frontends render outcomes, never own admission.
use std::path::Path;

use anyhow::{Context, Result};
use mvm_core::plan::TenantId;
use mvm_hostd::audit::{host_keypair, validate_prune_tenant};
use mvm_hostd::supervisor::{FileAuditSigner, verify_segment_set};

/// Removal requires an explicit commit request; the default only previews.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum AuditPruneMode {
    #[default]
    Preview,
    Commit,
}

/// Payload-free outcome for CLI, library and other client consumers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditPruneOutcome {
    NothingToPrune {
        floor: u64,
        through: u64,
    },
    WouldPrune {
        floor: u64,
        through: u64,
        segments: usize,
        entries: usize,
    },
    Pruned {
        through: u64,
        entries: u64,
    },
}

/// Preview or commit pruning using existing local audit authority.
///
/// A preview is advisory, not authorization for a later commit. Every commit
/// passes mandatory evidence admission inside the signer's tenant-locked
/// transaction. Missing keys never initialize replacement authority.
pub fn prune_audit(tenant: &str, through: u64, mode: AuditPruneMode) -> Result<AuditPruneOutcome> {
    validate_prune_tenant(tenant)?;
    let audit_dir = mvm_hostd::audit::emitter::default_audit_dir()?;
    let keys_dir = host_keypair::default_keys_dir()?;
    prune_at(&audit_dir, &keys_dir, tenant, through, mode)
}

fn prune_at(
    audit_dir: &Path,
    keys_dir: &Path,
    tenant: &str,
    through: u64,
    mode: AuditPruneMode,
) -> Result<AuditPruneOutcome> {
    validate_prune_tenant(tenant)?;
    let (signing, verifying) = mvm_core::crypto::ed25519_keypair::load_existing(
        &keys_dir.join(host_keypair::SECRET_FILENAME),
        &keys_dir.join(host_keypair::PUBLIC_FILENAME),
    )
    .map_err(|_| anyhow::anyhow!("existing audit authority is unavailable; refusing prune"))?;
    let verified = verify_segment_set(audit_dir, tenant, &verifying)
        .map_err(|_| anyhow::anyhow!("refusing to prune: the audit chain does not verify"))?;
    let floor = verified.pruned.map_or(1, |p| p.through + 1);
    let doomed: Vec<_> = verified
        .segments
        .iter()
        .filter(|s| !s.active && s.seq >= floor && s.seq <= through)
        .collect();
    if doomed.is_empty() {
        return Ok(AuditPruneOutcome::NothingToPrune { floor, through });
    }
    let signer = FileAuditSigner::open(signing, audit_dir)
        .context("opening the audit signer to assess the prune")?;
    match mode {
        AuditPruneMode::Preview => {
            signer
                .check_prune_pins(&TenantId(tenant.to_owned()), through)
                .context("dry-run blocked; no audit or payload evidence removed")?;
            Ok(AuditPruneOutcome::WouldPrune {
                floor,
                through,
                segments: doomed.len(),
                entries: doomed.iter().filter_map(|s| s.entries).sum(),
            })
        }
        AuditPruneMode::Commit => {
            let pruned = signer
                .prune_through(&TenantId(tenant.to_owned()), through)
                .context("pruning audit segments")?;
            Ok(AuditPruneOutcome::Pruned {
                through: pruned.through,
                entries: pruned.entries,
            })
        }
    }
}

#[cfg(test)]
#[path = "prune_tests.rs"]
mod tests;
