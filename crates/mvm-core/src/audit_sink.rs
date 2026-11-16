//! Bound host-decision recording without a dependency on a recorder or executor.

use std::collections::BTreeMap;
use std::io;

use serde::{Deserialize, Serialize};

use crate::plan::{ExecutionPlan, TenantId};

/// The host's explicit audit identity for an endpoint.
///
/// This is launch configuration, not a new authorization source. Workload
/// callers construct it only from their admitted plan.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AuditContext {
    Workload { plan: Box<ExecutionPlan> },
    Builder { tenant: TenantId, name: String },
}

impl std::fmt::Debug for AuditContext {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Workload { plan } => formatter
                .debug_struct("WorkloadAudit")
                .field("plan_id", &plan.plan_id)
                .finish_non_exhaustive(),
            Self::Builder { tenant, name } => formatter
                .debug_struct("BuilderAudit")
                .field("tenant", tenant)
                .field("name", name)
                .finish(),
        }
    }
}

impl AuditContext {
    #[must_use]
    pub fn plan(&self) -> Option<&ExecutionPlan> {
        match self {
            Self::Workload { plan } => Some(plan),
            Self::Builder { .. } => None,
        }
    }

    /// Refuse missing or cross-workload identity before an endpoint reports ready.
    ///
    /// # Errors
    ///
    /// A context for another tenant or workload, an empty identity, or a zero
    /// execution epoch is not a binding for this endpoint.
    pub fn validate_for(&self, tenant: &str, name: &str) -> io::Result<()> {
        let matches = match self {
            Self::Workload { plan } => {
                plan.tenant.0 == tenant
                    && plan.workload.0 == name
                    && !plan.plan_id.0.is_empty()
                    && plan.execution_epoch != 0
            }
            Self::Builder {
                tenant: bound_tenant,
                name: bound_name,
            } => bound_tenant.0 == tenant && bound_name == name,
        };
        if tenant.is_empty() || name.is_empty() || !matches {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "audit identity does not bind this endpoint",
            ));
        }
        Ok(())
    }
}

/// Records decisions under the identity fixed when the sink was constructed.
///
/// Workload implementations own their admitted plan and execution epoch.
/// Builder implementations identify the builder explicitly; they are never a
/// fallback for a workload whose plan is missing.
pub trait AuditSink: Send + Sync {
    /// Append a metadata-only decision before its response or authorized effect.
    ///
    /// # Errors
    ///
    /// Failure means the caller must refuse an allow. The implementation marks
    /// its bound epoch incomplete before returning the error. Workload lifetime
    /// is outside this interface.
    fn record(&self, event: &str, labels: BTreeMap<String, String>) -> io::Result<()>;

    /// Count an enforced denial whose repeated record was suppressed.
    ///
    /// Suppression does not count as a successful or failed journal write.
    fn suppress_denial(&self);

    /// Persist accumulated health and suppression counts at session completion.
    ///
    /// # Errors
    ///
    /// The caller must report a persistence failure rather than claim a clean
    /// session. This explicit operation avoids blocking or failing in `Drop`.
    fn flush_health(&self) -> io::Result<()>;
}

/// Loss accounting shared by every session of one bound execution epoch.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditHealth {
    pub consecutive_write_failures: u64,
    pub write_failures: u64,
    pub denials_suppressed: u64,
}

impl AuditHealth {
    /// A successful append resets the streak, not the epoch's missing records.
    pub fn record_success(&mut self) {
        self.consecutive_write_failures = 0;
    }

    /// Record a missing decision without allowing counters to wrap to healthy.
    pub fn record_failure(&mut self) {
        self.consecutive_write_failures = self.consecutive_write_failures.saturating_add(1);
        self.write_failures = self.write_failures.saturating_add(1);
    }

    /// Count a repeated denial without changing the journal-failure streak.
    pub fn suppress_denial(&mut self) {
        self.denials_suppressed = self.denials_suppressed.saturating_add(1);
    }

    #[must_use]
    pub fn host_record_incomplete(&self) -> bool {
        self.write_failures != 0
    }
}

#[cfg(test)]
mod tests;
