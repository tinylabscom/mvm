//! Bind already-assembled asynchronous endpoint consumers to the same decision sink.

use std::collections::BTreeMap;
use std::io;
use std::sync::Arc;

use mvm_core::audit_sink::{AuditContext, AuditSink};

use super::{
    EventCategory, Recorder, RecorderError, audit_mirror, for_plan, merge_extras,
    validate_event_prefix,
};

impl Recorder {
    /// Late binding keeps the endpoint's already-assembled services on one
    /// identity and failure counter. A weak reference avoids a recorder cycle.
    pub(crate) fn bind_audit_sink(&self, sink: &Arc<dyn AuditSink>) -> io::Result<()> {
        self.bound_sink
            .set(Arc::downgrade(sink))
            .map_err(|_| io::Error::other("recorder already has an endpoint audit binding"))
    }

    /// An expired installed binding is a refusal, never an unbound fallback.
    pub(crate) fn bound_audit_sink(&self) -> io::Result<Option<Arc<dyn AuditSink>>> {
        self.bound_sink
            .get()
            .map(|sink| {
                sink.upgrade()
                    .ok_or_else(|| io::Error::other("bound endpoint audit sink is unavailable"))
            })
            .transpose()
    }

    pub(super) async fn record_through_bound_sink(
        &self,
        category: EventCategory,
        event: String,
        extras: impl IntoIterator<Item = (String, String)>,
    ) -> Result<(), RecorderError> {
        validate_event_prefix(category, &event)?;
        let sink = self
            .bound_audit_sink()?
            .ok_or_else(|| io::Error::other("bound endpoint audit sink is unavailable"))?;
        let labels = merge_extras(category, extras);
        // Services run on async workers; the synchronous sink drives its signer
        // on a blocking worker instead of nesting Handle::block_on on this one.
        tokio::task::spawn_blocking(move || sink.record(&event, labels))
            .await
            .map_err(|_| io::Error::other("bound audit worker failed"))??;
        Ok(())
    }

    /// The bound sink's underlying journal leg, bypassing only the delegation
    /// back to itself, never signing, validation, or durability.
    pub(in crate::audit) async fn record_audit_context_direct(
        &self,
        context: &AuditContext,
        category: EventCategory,
        event: &str,
        extras: BTreeMap<String, String>,
    ) -> Result<(), RecorderError> {
        validate_event_prefix(category, event)?;
        if context.plan().is_none() && category.requires_plan_context() {
            return Err(RecorderError::MissingPlanContext { category });
        }
        let extras = merge_extras(category, extras);
        let mut entry = match context {
            AuditContext::Workload { plan, .. } => for_plan(plan, event, extras),
            AuditContext::Builder { .. } => self.unbound_entry(category, event.into(), extras),
        };
        // Sanitize after the plan's author labels and event extras have merged.
        for alias in ["plan_id", "plan_version", "tenant", "tenant_id", "vm_name"] {
            entry.labels.remove(alias);
        }
        if let Some(name) = &self.vm_name {
            entry.labels.insert("vm_name".into(), name.clone());
        }
        entry
            .labels
            .insert("category".into(), category.as_str().into());
        match context {
            AuditContext::Workload { plan, .. } => {
                entry.labels.remove("builder");
                entry.labels.insert("audit_scope".into(), "workload".into());
                entry
                    .labels
                    .insert("workload".into(), plan.workload.0.clone());
                entry
                    .labels
                    .insert("execution_epoch".into(), plan.execution_epoch.to_string());
            }
            AuditContext::Builder { name, .. } => {
                entry.labels.remove("workload");
                entry.labels.remove("execution_epoch");
                entry.labels.insert("audit_scope".into(), "builder".into());
                entry.labels.insert("builder".into(), name.clone());
            }
        }
        self.signer.sign_and_emit(&entry).await?;
        if context.plan().is_some() {
            audit_mirror::emit_mirror_event(&entry);
        }
        self.bump_metric(category);
        Ok(())
    }
}
