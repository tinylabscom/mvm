//! Host-side composition for the grant-gated drive plane.
//!
//! A session is exactly the existing input gate, the existing verified output
//! reader, and the signed grant. It creates no transport, port, or journal.

use mvm_agentd::vsock::{DriveFileOperation, DriveOpenCall, DriveRefusal};
use mvm_contract::grants::{DriveGrant, WorkspaceRoot};
use mvm_core::stream_client::{StreamOpts, StreamReader, connect_stream};
use std::sync::Arc;

use crate::audit::emitter::AuditEmitter;
use crate::plan_admission::AdmittedPlan;
use crate::stream::{InputGate, InputRefusal, InputSession};

/// Failure to establish or prepare a driven operation.
#[derive(Debug, thiserror::Error)]
pub enum DriveSessionError {
    #[error("drive request refused: {0:?}")]
    Refused(DriveRefusal),
    #[error("drive refusal could not be recorded in the audit chain: {0}")]
    Unauditable(#[source] anyhow::Error),
    #[error("drive input gate refused: {0}")]
    Input(#[from] InputRefusal),
    #[error("opening the existing workload output stream: {0}")]
    Output(#[from] mvm_core::stream_client::StreamError),
    #[error("opening the host audit chain: {0}")]
    Audit(#[source] anyhow::Error),
}

/// The existing stream-plane pieces bound to one admitted drive authority.
pub struct DriveSession {
    vm: String,
    plan: mvm_contract::plan::ExecutionPlan,
    grant: DriveGrant,
    input: DriveInputSession,
    output: Box<dyn StreamReader>,
    audit: Arc<AuditEmitter>,
}

/// The existing [`InputSession`] plus the drive grant's cumulative input cap.
pub struct DriveInputSession {
    inner: InputSession,
    max_bytes: u64,
    accepted_bytes: u64,
    vm: String,
    plan: mvm_contract::plan::ExecutionPlan,
    audit: Arc<AuditEmitter>,
}

impl DriveSession {
    /// Open a driven session from a verified admitted plan.
    pub fn open(vm: &str, admitted: &AdmittedPlan) -> Result<Self, DriveSessionError> {
        let signer =
            crate::audit::host_keypair::load_or_init().map_err(DriveSessionError::Audit)?;
        let audit = Arc::new(AuditEmitter::new(signer.signing).map_err(DriveSessionError::Audit)?);
        let plan = admitted.plan();
        let Some(grant) = plan
            .grants
            .as_ref()
            .and_then(|grants| grants.drive.as_ref())
            .cloned()
        else {
            record_refusal(&audit, plan, vm, DriveRefusal::NotGranted)?;
            return Err(DriveSessionError::Refused(DriveRefusal::NotGranted));
        };
        let input = DriveInputSession {
            inner: InputGate::open_drive(vm, admitted)?,
            max_bytes: grant.max_bytes_in.get(),
            accepted_bytes: 0,
            vm: vm.to_string(),
            plan: plan.clone(),
            audit: Arc::clone(&audit),
        };
        let output = connect_stream(vm, StreamOpts::builder().follow(true).build())?;
        Ok(Self {
            vm: vm.to_string(),
            plan: plan.clone(),
            grant,
            input,
            output,
            audit,
        })
    }

    /// Prepare a drive-open request without exposing program selection.
    pub fn prepare_open(&self, cwd: &str) -> Result<DriveOpenCall, DriveSessionError> {
        if !path_is_granted(&self.grant, cwd) {
            return self.refuse(DriveRefusal::OutsideWorkspaceRoots);
        }
        Ok(DriveOpenCall {
            cwd: cwd.to_string(),
            env: crate::workload_env::workload_egress_env(&self.vm),
        })
    }

    /// Validate a file operation at the host boundary before it can be sent.
    pub fn prepare_file(
        &self,
        operation: DriveFileOperation,
    ) -> Result<DriveFileOperation, DriveSessionError> {
        let refusal = if !path_is_granted(&self.grant, operation.path()) {
            Some(DriveRefusal::OutsideWorkspaceRoots)
        } else if operation.input_len() > self.grant.max_bytes_in.get() {
            Some(DriveRefusal::InputLimitExceeded)
        } else if operation.requested_output_len() > self.grant.max_bytes_out.get() {
            Some(DriveRefusal::OutputLimitExceeded)
        } else {
            None
        };
        match refusal {
            Some(reason) => self.refuse(reason),
            None => Ok(operation),
        }
    }

    /// The one secret-scanned writer lease for this driven program.
    pub fn input(&mut self) -> &mut DriveInputSession {
        &mut self.input
    }

    /// The existing verified workload output stream.
    pub fn output(&mut self) -> &mut dyn StreamReader {
        &mut *self.output
    }

    /// The signed authority callers pass to the existing drive RPC helpers.
    #[must_use]
    pub fn grant(&self) -> &DriveGrant {
        &self.grant
    }

    fn refuse<T>(&self, reason: DriveRefusal) -> Result<T, DriveSessionError> {
        record_refusal(&self.audit, &self.plan, &self.vm, reason)?;
        Err(DriveSessionError::Refused(reason))
    }
}

impl DriveInputSession {
    /// Offer one frame to the existing secret scanner and single-writer lease.
    pub fn write(
        &mut self,
        frame: mvm_contract::stream::input::InputFrame,
    ) -> Result<(), DriveSessionError> {
        let bytes = u64::try_from(frame.payload.len()).unwrap_or(u64::MAX);
        if self.accepted_bytes.saturating_add(bytes) > self.max_bytes {
            record_refusal(
                &self.audit,
                &self.plan,
                &self.vm,
                DriveRefusal::InputLimitExceeded,
            )?;
            return Err(DriveSessionError::Refused(DriveRefusal::InputLimitExceeded));
        }
        self.inner.write(frame)?;
        self.accepted_bytes = self.accepted_bytes.saturating_add(bytes);
        Ok(())
    }

    /// Refresh the existing lease and release any content-blind idle tail.
    pub fn refresh(&mut self) -> Result<(), DriveSessionError> {
        self.inner.refresh().map_err(DriveSessionError::Input)
    }

    /// Drain bytes the existing scanner has admitted for delivery.
    pub fn take_admitted(&mut self) -> Result<Vec<u8>, DriveSessionError> {
        self.inner.take_admitted().map_err(DriveSessionError::Input)
    }

    /// Close this writer through the existing input-session ordering rule.
    pub fn close(self) -> Result<mvm_contract::stream::input::CloseInput, DriveSessionError> {
        self.inner.close().map_err(DriveSessionError::Input)
    }

    /// Lease holder recorded in the stream-input audit chain.
    #[must_use]
    pub fn holder(&self) -> &str {
        self.inner.holder()
    }
}

fn record_refusal(
    audit: &AuditEmitter,
    plan: &mvm_contract::plan::ExecutionPlan,
    vm: &str,
    reason: DriveRefusal,
) -> Result<(), DriveSessionError> {
    audit
        .emit_drive_refused(plan, vm, reason)
        .map_err(DriveSessionError::Unauditable)
}

fn path_is_granted(grant: &DriveGrant, path: &str) -> bool {
    WorkspaceRoot::parse(path).ok().is_some_and(|path| {
        grant
            .workspace_roots
            .iter()
            .any(|root| path.is_within(root))
    })
}

#[cfg(test)]
mod tests {
    use std::num::{NonZeroU32, NonZeroU64};

    use mvm_contract::grants::{DriveGrant, DriveProgramId};

    use super::*;

    fn grant() -> DriveGrant {
        DriveGrant::builder()
            .workspace_root(WorkspaceRoot::parse("/workspace").unwrap())
            .program_id(DriveProgramId::parse("agent").unwrap())
            .max_bytes_in(NonZeroU64::new(32).unwrap())
            .max_bytes_out(NonZeroU64::new(64).unwrap())
            .ttl(NonZeroU32::new(30).unwrap())
            .build()
            .unwrap()
    }

    #[test]
    fn host_workspace_check_is_component_aware() {
        let grant = grant();
        assert!(path_is_granted(&grant, "/workspace/project/file"));
        assert!(!path_is_granted(&grant, "/workspace-escape/file"));
        assert!(!path_is_granted(&grant, "/workspace/../etc/passwd"));
    }
}
