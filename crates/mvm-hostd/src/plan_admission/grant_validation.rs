//! Cross-field and host-ceiling checks before signing or dispatching a plan.

use anyhow::{Context as _, Result};
use mvm_contract::grants::Grants;
use mvm_contract::protocol::mailbox::{MailboxGrant, MailboxRetentionPolicy};
use mvm_core::plan::ExecutionPlan;

pub(super) fn enforce_mailbox_retention(
    mailbox: Option<&MailboxGrant>,
    max_ms: Option<u64>,
) -> Result<()> {
    let Some(requested) = mailbox.and_then(|grant| grant.retention) else {
        return Ok(());
    };
    let max_ms = max_ms
        .context("local mailbox retention requires max_mailbox_retention_ms in host config.toml")?;
    let ceiling = MailboxRetentionPolicy::new(max_ms)
        .context("host max_mailbox_retention_ms must be a finite, nonzero duration")?;
    anyhow::ensure!(
        requested.retention_ms() <= ceiling.retention_ms(),
        "local mailbox retention {} ms exceeds this host's {} ms ceiling",
        requested.retention_ms(),
        ceiling.retention_ms(),
    );
    Ok(())
}

/// A grant cannot carry a wall-clock bound that contradicts its projection.
pub(super) fn enforce_wall_clock_projection(plan: &ExecutionPlan, grants: &Grants) -> Result<()> {
    let projected = mvm_contract::grants::projection::exec_secs_from_grants(grants);
    let carried = plan.resources.timeouts.exec_secs;
    if projected != carried {
        anyhow::bail!(
            "plan carries exec_secs {carried} but its wall-clock grant projects to \
             {projected}; refusing to choose between two encodings of one bound"
        );
    }
    Ok(())
}
