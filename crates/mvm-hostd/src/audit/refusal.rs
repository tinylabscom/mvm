//! Where the cell store and the liveness signal record a refusal.
//!
//! Both record on the tenant's lifecycle chain. A process that holds the host
//! key writes it directly through [`AuditEmitter`]; a keyless broker sends the
//! entry to the signer it already uses, through [`AuditClient`], which appends
//! it to the same chain under the same lock.

use anyhow::{Context, Result, bail};
use mvm_core::plan::TenantId;
use mvm_core::protocol::audit_signer::{AppendEntryRequest, AppendEntryResponse};
use mvm_core::protocol::lifecycle_audit::{LifecycleEntry, LifecycleEvent, LifecycleLabels};

use crate::audit::audit_client::AuditClient;
use crate::audit::emitter::AuditEmitter;

/// Records one refusal on `tenant`'s lifecycle chain.
pub trait RefusalAudit: Send + Sync {
    /// # Errors
    ///
    /// The entry was not written.
    fn record_refusal(
        &self,
        tenant: &TenantId,
        event: LifecycleEvent,
        labels: LifecycleLabels,
    ) -> Result<()>;
}

impl RefusalAudit for AuditEmitter {
    fn record_refusal(
        &self,
        tenant: &TenantId,
        event: LifecycleEvent,
        labels: LifecycleLabels,
    ) -> Result<()> {
        self.emit_topology_decision(
            tenant,
            event.as_str(),
            labels.into_iter().map(|(k, v)| (k.as_str().to_string(), v)),
        )
    }
}

/// Blocks on the signer's answer, so it must be called off the async
/// executor, as the cell service calls it from a blocking task.
impl RefusalAudit for AuditClient {
    fn record_refusal(
        &self,
        tenant: &TenantId,
        event: LifecycleEvent,
        labels: LifecycleLabels,
    ) -> Result<()> {
        let request = AppendEntryRequest::AppendLifecycleEntry {
            request_id: format!("lifecycle-{}", event.as_str()),
            entry: LifecycleEntry {
                tenant_id: tenant.0.clone(),
                event,
                labels,
            },
        };
        let response = tokio::runtime::Handle::try_current()
            .context("recording a refusal needs the broker's runtime")?
            .block_on(self.append(&request))
            .context("sending the refusal to the audit signer")?;
        match response {
            AppendEntryResponse::LifecycleAppended { .. } => Ok(()),
            AppendEntryResponse::Err { code, message, .. } => {
                bail!("the audit signer refused the entry ({code:?}): {message}")
            }
            other => bail!("the audit signer answered a lifecycle entry with {other:?}"),
        }
    }
}
