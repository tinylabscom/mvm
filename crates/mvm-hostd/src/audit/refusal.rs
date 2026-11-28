//! Where the cell store and the liveness signal record a refusal.
//!
//! Both record on the tenant's lifecycle chain. A process that holds the host
//! key writes it directly through [`AuditEmitter`]; a keyless broker sends the
//! entry to the signer it already uses, through [`AuditClient`], which appends
//! it to the same chain under the same lock.
//!
//! A guest can repeat a refused call as often as it likes, and each refusal
//! would otherwise be a signed, synced entry on a chain that is never deleted.
//! [`ThrottledRefusals`] stands between a broker and its signer and bounds
//! that: the guest is still refused every time, but each kind of refusal is
//! recorded at once the first time and then at most once per
//! [`REFUSAL_AUDIT_INTERVAL`], with the number left unrecorded in between.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, bail};
use mvm_contract::timestamp::UtcTimestamp;
use mvm_core::plan::TenantId;
use mvm_core::protocol::audit_signer::{AppendEntryRequest, AppendEntryResponse};
use mvm_core::protocol::lifecycle_audit::{
    LifecycleEntry, LifecycleEvent, LifecycleLabel, LifecycleLabels,
};
use mvm_core::time::Clock;

use crate::audit::audit_client::AuditClient;
use crate::audit::emitter::AuditEmitter;

/// Records one refusal on `tenant`'s lifecycle chain.
pub trait RefusalAudit: Send + Sync {
    /// `kind` names the refusal's variant, so repeats can be told apart from
    /// distinct refusals without parsing the reason.
    ///
    /// # Errors
    ///
    /// The entry was not written.
    fn record_refusal(
        &self,
        tenant: &TenantId,
        event: LifecycleEvent,
        kind: &'static str,
        labels: LifecycleLabels,
    ) -> Result<()>;
}

impl RefusalAudit for AuditEmitter {
    fn record_refusal(
        &self,
        tenant: &TenantId,
        event: LifecycleEvent,
        _kind: &'static str,
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
        _kind: &'static str,
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

/// The longest one kind of refusal goes unrecorded while it repeats.
pub const REFUSAL_AUDIT_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);

/// The most kinds one registration tracks apart. Cell names are the guest's
/// to choose, so every kind past these is counted as one.
pub const MAX_TRACKED_REFUSAL_KINDS: usize = 8;

/// One kind of refusal: the event, the variant, and for a cell the operation
/// and the cell. `None` is the kind every untracked refusal folds into.
type Kind = Option<(LifecycleEvent, &'static str, Option<String>, Option<String>)>;

struct Recorded {
    at: UtcTimestamp,
    suppressed: u64,
}

/// Records refusals for one registered VM through `inner`, at a bounded rate.
pub struct ThrottledRefusals {
    inner: Arc<dyn RefusalAudit>,
    clock: Arc<dyn Clock>,
    kinds: Mutex<HashMap<Kind, Recorded>>,
}

impl ThrottledRefusals {
    #[must_use]
    pub fn new(inner: Arc<dyn RefusalAudit>, clock: Arc<dyn Clock>) -> Self {
        Self {
            inner,
            clock,
            kinds: Mutex::new(HashMap::new()),
        }
    }
}

impl RefusalAudit for ThrottledRefusals {
    fn record_refusal(
        &self,
        tenant: &TenantId,
        event: LifecycleEvent,
        kind: &'static str,
        mut labels: LifecycleLabels,
    ) -> Result<()> {
        let now = self.clock.now();
        let mut kinds = self
            .kinds
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let key = Some((
            event,
            kind,
            labels.get(&LifecycleLabel::Operation).cloned(),
            labels.get(&LifecycleLabel::Cell).cloned(),
        ));
        let key = if kinds.contains_key(&key) || kinds.len() < MAX_TRACKED_REFUSAL_KINDS {
            key
        } else {
            None
        };
        let suppressed = match kinds.get_mut(&key) {
            // A clock found behind the last entry records rather than waits.
            Some(seen)
                if now
                    .duration_since(seen.at)
                    .is_some_and(|since| since < REFUSAL_AUDIT_INTERVAL) =>
            {
                seen.suppressed += 1;
                return Ok(());
            }
            Some(seen) => seen.suppressed,
            None => 0,
        };
        if suppressed > 0 {
            labels.insert(LifecycleLabel::Suppressed, suppressed.to_string());
        }
        drop(kinds);
        // Only a written entry restarts the interval; a failed one is tried
        // again by the next refusal of its kind.
        self.inner.record_refusal(tenant, event, kind, labels)?;
        self.kinds
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(
                key,
                Recorded {
                    at: now,
                    suppressed: 0,
                },
            );
        Ok(())
    }
}

#[cfg(test)]
#[path = "refusal_tests.rs"]
mod tests;
