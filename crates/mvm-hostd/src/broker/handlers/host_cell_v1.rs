//! `host.cell.v1` — host-held state cells and the liveness signal, served
//! over the broker.
//!
//! The verbs are `write`, `read` and `signal`. The guest names only the cell.
//! The tenant is the one the broker serves and the unit and epoch are the
//! ones the VM registered with, both from the call context; a registration
//! that names no unit and epoch is refused, since a cell has no meaning
//! without them. Whether the unit writes or reads the cell is the admitted
//! topology's answer and whether the epoch may act is the epoch gate's, both
//! asked by the store, so this handler decides neither.
//!
//! A write the store accepts also resets the unit's liveness deadline, if its
//! topology declares one.

use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use mvm_core::plan::{TenantId, WorkloadId};
use mvm_core::policy::security::AgentProfile;
use mvm_core::protocol::broker::{AuditDurability, Idempotency, ServiceErrorCode, ServiceId};
use mvm_core::protocol::handler::{
    ServiceCallCtx, ServiceDispatchResult, ServiceError, ServiceHandler,
};
use mvm_core::protocol::host_cell::{
    CellReadRequest, CellReadResponse, CellWriteRequest, CellWriteResponse, HOST_CELL_SERVICE,
    MAX_CELL_NAME_LEN,
};
use mvm_core::time::Clock;

use crate::audit::emitter::AuditEmitter;
use crate::liveness::{LivenessCaller, LivenessDeadlines, LivenessRefusal};
use crate::state_cells::{CellCaller, CellRefusal, MAX_CELL_BYTES, StateCells};

/// Handler for the `host.cell.v1` service.
pub struct HostCellV1Handler {
    /// Signs refusals onto the tenant's chain, so it holds the host key.
    emitter: Arc<AuditEmitter>,
    clock: Arc<dyn Clock>,
}

/// The caller as the registration names it.
struct Caller {
    tenant: TenantId,
    unit: WorkloadId,
    epoch: mvm_contract::protocol::mailbox::ExecutionEpoch,
}

impl Caller {
    fn from_ctx(ctx: &ServiceCallCtx) -> Result<Self, ServiceError> {
        let Some(call) = &ctx.epoch else {
            return Err(ServiceError::new(
                ServiceErrorCode::CapabilityDenied,
                format!(
                    "{HOST_CELL_SERVICE} needs a registration that names its unit and execution \
                     epoch"
                ),
            ));
        };
        Ok(Self {
            tenant: TenantId(ctx.tenant_id.clone()),
            unit: WorkloadId(call.unit.clone()),
            epoch: call.epoch,
        })
    }

    fn cell<'a>(&'a self, cell: &'a str) -> CellCaller<'a> {
        CellCaller {
            tenant: &self.tenant,
            unit: &self.unit,
            epoch: self.epoch,
            cell,
        }
    }

    fn liveness(&self) -> LivenessCaller<'_> {
        LivenessCaller {
            tenant: &self.tenant,
            unit: &self.unit,
            epoch: self.epoch,
        }
    }
}

/// A parsed and bounded call.
enum Operation {
    Write(CellWriteRequest),
    Read(CellReadRequest),
    Signal,
}

impl Operation {
    fn parse(verb: &str, payload: serde_json::Value) -> Result<Self, ServiceError> {
        let op = match verb {
            "write" => Self::Write(parse(verb, payload)?),
            "read" => Self::Read(parse(verb, payload)?),
            "signal" if payload.as_object().is_some_and(serde_json::Map::is_empty) => Self::Signal,
            "signal" => return Err(bad_request("signal payload must be an empty object".into())),
            other => {
                return Err(ServiceError::new(
                    ServiceErrorCode::NotImplemented,
                    format!("{HOST_CELL_SERVICE}: unknown verb `{other}`"),
                ));
            }
        };
        match &op {
            Self::Write(request) => {
                check_name(&request.cell)?;
                if request.value.len() as u64 > MAX_CELL_BYTES {
                    return Err(bad_request(format!(
                        "value is {} bytes, over the {MAX_CELL_BYTES}-byte limit",
                        request.value.len()
                    )));
                }
            }
            Self::Read(request) => check_name(&request.cell)?,
            Self::Signal => {}
        }
        Ok(op)
    }
}

fn parse<T: serde::de::DeserializeOwned>(
    verb: &str,
    payload: serde_json::Value,
) -> Result<T, ServiceError> {
    serde_json::from_value(payload)
        .map_err(|error| bad_request(format!("{verb} payload rejected: {error}")))
}

fn check_name(cell: &str) -> Result<(), ServiceError> {
    if cell.is_empty() || cell.len() > MAX_CELL_NAME_LEN {
        return Err(bad_request(format!(
            "a cell name is 1 to {MAX_CELL_NAME_LEN} bytes"
        )));
    }
    Ok(())
}

fn bad_request(detail: String) -> ServiceError {
    ServiceError::new(
        ServiceErrorCode::BadRequest,
        format!("{HOST_CELL_SERVICE}: {detail}"),
    )
}

fn encode<T: serde::Serialize>(value: T) -> ServiceDispatchResult {
    serde_json::to_value(value).map_err(|error| {
        ServiceError::new(
            ServiceErrorCode::InternalError,
            format!("{HOST_CELL_SERVICE} response encode failed: {error}"),
        )
    })
}

/// A host-side failure. The detail names host paths, so it stays in the log.
fn unavailable(error: &anyhow::Error) -> ServiceError {
    tracing::warn!(target: "mvm::broker::host_cell", error = %format!("{error:#}"), "host.cell.v1 failed");
    ServiceError::new(
        ServiceErrorCode::Unavailable,
        format!("{HOST_CELL_SERVICE}: store unavailable"),
    )
}

fn cell_error(error: anyhow::Error) -> ServiceError {
    let Some(refusal) = error.downcast_ref::<CellRefusal>() else {
        return unavailable(&error);
    };
    let code = match refusal {
        CellRefusal::Epoch { .. } => ServiceErrorCode::SessionRevoked,
        CellRefusal::VersionNotIncreasing { .. } | CellRefusal::TooLarge { .. } => {
            ServiceErrorCode::BadRequest
        }
        CellRefusal::UnknownCell { .. }
        | CellRefusal::NotWriter { .. }
        | CellRefusal::NotReader { .. } => ServiceErrorCode::CapabilityDenied,
    };
    ServiceError::new(code, format!("{HOST_CELL_SERVICE}: {refusal}"))
}

fn liveness_error(error: anyhow::Error) -> ServiceError {
    let Some(refusal) = error.downcast_ref::<LivenessRefusal>() else {
        return unavailable(&error);
    };
    let code = match refusal {
        LivenessRefusal::NoPeriod { .. } => ServiceErrorCode::CapabilityDenied,
        LivenessRefusal::Epoch { .. } | LivenessRefusal::DeadlinePassed { .. } => {
            ServiceErrorCode::SessionRevoked
        }
    };
    ServiceError::new(code, format!("{HOST_CELL_SERVICE}: {refusal}"))
}

impl HostCellV1Handler {
    #[must_use]
    pub fn new(emitter: Arc<AuditEmitter>, clock: Arc<dyn Clock>) -> Self {
        Self { emitter, clock }
    }

    /// Run one call. Blocking: the store takes file locks and syncs.
    fn run(
        emitter: &AuditEmitter,
        clock: &dyn Clock,
        caller: &Caller,
        op: Operation,
    ) -> ServiceDispatchResult {
        let cells = StateCells {
            host_signer_keys_dir: None,
            emitter,
        };
        let deadlines = LivenessDeadlines {
            host_signer_keys_dir: None,
            emitter,
            clock,
        };
        match op {
            Operation::Write(request) => {
                cells
                    .write(&caller.cell(&request.cell), request.version, &request.value)
                    .map_err(cell_error)?;
                // The write is committed whatever happens here; a refused
                // reset is on the chain already.
                if let Err(error) = deadlines.reset_after_write(&caller.liveness()) {
                    tracing::warn!(target: "mvm::broker::host_cell", error = %format!("{error:#}"), "a cell write did not reset the liveness deadline");
                }
                encode(CellWriteResponse {
                    version: request.version,
                })
            }
            Operation::Read(request) => {
                let value = cells
                    .read(&caller.cell(&request.cell))
                    .map_err(cell_error)?;
                encode(CellReadResponse {
                    version: value.version,
                    value: value.value,
                })
            }
            Operation::Signal => {
                deadlines
                    .signal(&caller.liveness())
                    .map_err(liveness_error)?;
                Ok(serde_json::json!({}))
            }
        }
    }
}

impl ServiceHandler for HostCellV1Handler {
    fn id(&self) -> ServiceId {
        ServiceId::parse(HOST_CELL_SERVICE).expect("host.cell.v1 is a valid ServiceId")
    }

    fn profiles(&self) -> &[AgentProfile] {
        &[AgentProfile::SealedProd, AgentProfile::Dev]
    }

    fn audit_durability(&self) -> AuditDurability {
        AuditDurability::default_batched()
    }

    fn idempotency(&self) -> Idempotency {
        Idempotency::MintFresh
    }

    fn call_timeout(&self) -> Duration {
        Duration::from_secs(5)
    }

    fn dispatch<'a>(
        &'a self,
        ctx: &'a ServiceCallCtx,
        verb: &'a str,
        payload: serde_json::Value,
    ) -> Pin<Box<dyn std::future::Future<Output = ServiceDispatchResult> + Send + 'a>> {
        Box::pin(async move {
            let caller = Caller::from_ctx(ctx)?;
            let op = Operation::parse(verb, payload)?;
            let emitter = Arc::clone(&self.emitter);
            let clock = Arc::clone(&self.clock);
            tokio::task::spawn_blocking(move || Self::run(&emitter, &*clock, &caller, op))
                .await
                .map_err(|error| unavailable(&anyhow::Error::new(error)))?
        })
    }
}

#[cfg(test)]
#[path = "host_cell_v1_tests.rs"]
mod tests;
