//! Plan-bound decision recording and epoch-local audit failure accounting.

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use mvm_core::atomic_io;
use mvm_core::audit_sink::{AuditContext, AuditHealth, AuditSink};
use mvm_core::private_fs::{OpenOptionsModeExt as _, PRIVATE_FILE_MODE};
use serde::Serialize;
use sha2::{Digest, Sha256};

use super::audit_recorder::{EventCategory, Recorder};

#[derive(Debug, Serialize)]
#[serde(tag = "scope", rename_all = "snake_case")]
enum Binding {
    Workload {
        tenant: String,
        workload: String,
        plan_id: String,
        execution_epoch: u64,
    },
    Builder {
        tenant: String,
        builder: String,
    },
}

impl Binding {
    fn from_context(context: &AuditContext) -> Self {
        match context {
            AuditContext::Workload { plan, .. } => Self::Workload {
                tenant: plan.tenant.0.clone(),
                workload: plan.workload.0.clone(),
                plan_id: plan.plan_id.0.clone(),
                execution_epoch: plan.execution_epoch,
            },
            AuditContext::Builder { tenant, name } => Self::Builder {
                tenant: tenant.0.clone(),
                builder: name.clone(),
            },
        }
    }
}

#[derive(Serialize)]
struct HealthRecord<'a> {
    binding: &'a Binding,
    completeness: &'static str,
    health: AuditHealth,
}

/// One identity, journal and failure streak shared across an endpoint's sessions.
pub struct BoundRecorder {
    recorder: Arc<Recorder>,
    runtime: tokio::runtime::Handle,
    context: AuditContext,
    binding: Binding,
    health_file: PathBuf,
    state: Mutex<AuditHealth>,
}

impl std::fmt::Debug for BoundRecorder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BoundRecorder")
            .field("binding", &self.binding)
            .finish_non_exhaustive()
    }
}

/// Configures the persistent health record.
pub struct BoundRecorderBuilder {
    recorder: Arc<Recorder>,
    runtime: tokio::runtime::Handle,
    context: AuditContext,
    health_file: Option<PathBuf>,
}

impl BoundRecorder {
    #[must_use]
    pub fn builder(
        recorder: Arc<Recorder>,
        runtime: tokio::runtime::Handle,
        context: AuditContext,
    ) -> BoundRecorderBuilder {
        BoundRecorderBuilder {
            recorder,
            runtime,
            context,
            health_file: None,
        }
    }

    /// A content-keyed health sidecar alongside the journal, never in VM state.
    ///
    /// # Errors
    ///
    /// Returns an error if the binding cannot be serialized.
    pub fn health_path(audit_dir: &Path, context: &AuditContext) -> io::Result<PathBuf> {
        let bytes = serde_json::to_vec(&Binding::from_context(context))?;
        let digest = hex::encode(Sha256::digest(bytes));
        let name = match context {
            AuditContext::Workload { .. } => format!("flow-health-{digest}.json"),
            // Builders have no execution epoch. Keep each endpoint lifetime's
            // evidence instead of resetting the previous boot's health.
            AuditContext::Builder { .. } => {
                format!("flow-health-{digest}-{:032x}.json", rand::random::<u128>())
            }
        };
        Ok(audit_dir.join(name))
    }

    /// Current accounting, including repeats not yet flushed to the sidecar.
    #[must_use]
    pub fn health(&self) -> AuditHealth {
        *self.state.lock().expect("bound audit state poisoned")
    }

    fn health_bytes(&self, state: &AuditHealth) -> io::Result<Vec<u8>> {
        serde_json::to_vec(&HealthRecord {
            binding: &self.binding,
            // An active endpoint is not a sealed epoch. A crash or failed
            // health write leaves this explicit unknown, never "complete".
            completeness: if state.host_record_incomplete() {
                "host_record_incomplete"
            } else {
                "active"
            },
            health: *state,
        })
        .map_err(io::Error::other)
    }

    fn persist(&self, state: &AuditHealth) -> io::Result<()> {
        // NamedTempFile starts owner-only on Unix; the umask can only narrow
        // that mode. No permission-changing syscall is needed under confinement.
        atomic_io::atomic_write_durable(&self.health_file, &self.health_bytes(state)?)
            .map_err(io::Error::other)
    }

    fn failed(
        &self,
        mut state: std::sync::MutexGuard<'_, AuditHealth>,
        error: io::Error,
    ) -> io::Error {
        state.record_failure();
        if let Err(health_error) = self.persist(&state) {
            tracing::error!(
                binding = ?self.binding,
                error = %health_error,
                "audit health persistence failed; the active record cannot prove completeness"
            );
        }
        tracing::error!(
            binding = ?self.binding,
            consecutive = state.consecutive_write_failures,
            error = %error,
            "host_record_incomplete"
        );
        error
    }
}

impl BoundRecorderBuilder {
    #[must_use]
    pub fn health_file(mut self, path: PathBuf) -> Self {
        self.health_file = Some(path);
        self
    }

    /// Bind and probe the real journal before reporting an endpoint ready.
    ///
    /// # Errors
    ///
    /// Refuses missing health storage, invalid identity, an existing health
    /// record, or a journal that cannot append.
    pub fn build(self) -> io::Result<BoundRecorder> {
        match &self.context {
            AuditContext::Workload { plan, .. } => {
                self.context
                    .validate_for(&plan.tenant.0, &plan.workload.0)?;
            }
            AuditContext::Builder { tenant, name } => {
                self.context.validate_for(&tenant.0, name)?;
            }
        }
        let sink = BoundRecorder {
            binding: Binding::from_context(&self.context),
            recorder: self.recorder,
            runtime: self.runtime,
            context: self.context,
            health_file: self
                .health_file
                .ok_or_else(|| io::Error::other("audit sink has no health file"))?,
            state: Mutex::new(AuditHealth::default()),
        };
        // Reserve the epoch exclusively before publishing its initial health.
        // A crash can leave an empty reservation: it still refuses a restart,
        // never resets evidence or claims a complete epoch.
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open_with_mode(PRIVATE_FILE_MODE, &sink.health_file)
            .map_err(|error| {
                if error.kind() == io::ErrorKind::AlreadyExists {
                    io::Error::new(
                        error.kind(),
                        "audit binding already has a health record; refusing to reset epoch evidence",
                    )
                } else {
                    error
                }
            })?;
        sink.persist(&AuditHealth::default())?;
        mvm_core::host_interface::preflight::audit::check(Some(&sink)).map_err(io::Error::other)?;
        Ok(sink)
    }
}

fn category(event: &str) -> io::Result<EventCategory> {
    match event.split_once('.').map(|(prefix, _)| prefix) {
        Some("host") => Ok(EventCategory::Host),
        Some("dns") => Ok(EventCategory::Dns),
        Some("icmp") => Ok(EventCategory::Icmp),
        Some("secret") => Ok(EventCategory::Secret),
        Some("approval") => Ok(EventCategory::Approval),
        Some("flow") => Ok(EventCategory::Flow),
        Some("policy") => Ok(EventCategory::Policy),
        Some("key") => Ok(EventCategory::Key),
        Some("audit") => Ok(EventCategory::Audit),
        Some("workload_audit") => Ok(EventCategory::WorkloadAudit),
        Some("lifecycle") => Ok(EventCategory::Lifecycle),
        Some("cmd") => Ok(EventCategory::Cmd),
        Some("plan") => Ok(EventCategory::Plan),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "unsupported flow audit event",
        )),
    }
}

impl AuditSink for BoundRecorder {
    fn record(&self, event: &str, labels: BTreeMap<String, String>) -> io::Result<()> {
        let mut state = self.state.lock().expect("bound audit state poisoned");
        let result = category(event).and_then(|category| {
            self.runtime
                .block_on(self.recorder.record_audit_context_direct(
                    &self.context,
                    category,
                    event,
                    labels,
                ))
                .map_err(io::Error::other)
        });
        match result {
            Ok(()) => {
                state.record_success();
                Ok(())
            }
            Err(error) => Err(self.failed(state, error)),
        }
    }

    fn suppress_denial(&self) {
        self.state
            .lock()
            .expect("bound audit state poisoned")
            .suppress_denial();
    }

    fn flush_health(&self) -> io::Result<()> {
        let state = self.state.lock().expect("bound audit state poisoned");
        match self.persist(&state) {
            Ok(()) => Ok(()),
            Err(error) => Err(self.failed(state, error)),
        }
    }
}

#[cfg(test)]
mod tests;
