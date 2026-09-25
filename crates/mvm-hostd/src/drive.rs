//! Host-side composition for the grant-gated drive plane.
//!
//! A session is exactly the existing input gate, the existing verified output
//! reader, and the signed grant. It creates no transport, port, or journal.

use mvm_agentd::vsock::{
    DriveFileOperation, DriveOpenCall, DriveRefusal, EntrypointEvent, FsResult, RpcError,
};
use mvm_contract::grants::{DriveGrant, WorkspaceRoot};
use mvm_core::stream_client::{StreamOpts, StreamReader, connect_stream};
use std::sync::Arc;

use crate::audit::emitter::AuditEmitter;
use crate::plan_admission::AdmittedPlan;
use crate::stream::{InputRefusal, InputRoute, InputRouteError, VsockInput, WireSequence};

/// Failure to establish or prepare a driven operation.
#[derive(Debug, thiserror::Error)]
pub enum DriveSessionError {
    #[error("drive request refused: {0:?}")]
    Refused(DriveRefusal),
    #[error("drive refusal could not be recorded in the audit chain: {0}")]
    Unauditable(#[source] anyhow::Error),
    #[error("drive input gate refused: {0}")]
    Input(#[from] InputRefusal),
    #[error("drive input delivery failed: {0}")]
    InputRoute(#[from] InputRouteError),
    #[error("opening the existing workload output stream: {0}")]
    Output(#[from] mvm_core::stream_client::StreamError),
    #[error("opening the host audit chain: {0}")]
    Audit(#[source] anyhow::Error),
    #[error("loading the admitted drive authority: {0}")]
    Authority(#[source] anyhow::Error),
    #[error("drive guest RPC failed: {0}")]
    Rpc(#[source] anyhow::Error),
}

/// A drive grant reloaded from the host's admitted-plan state and verified
/// against the host-signed verb-grant envelope for the running machine.
///
/// The fields stay private so an out-of-process controller cannot turn a bare
/// deserialized plan into authority. [`load`](Self::load) is the only
/// constructor outside tests.
#[derive(Clone)]
pub struct DriveAuthority {
    vm: String,
    plan: mvm_contract::plan::ExecutionPlan,
    grant: DriveGrant,
    audit: Arc<AuditEmitter>,
}

/// The existing stream-plane pieces bound to one admitted drive authority.
pub struct DriveSession {
    authority: DriveAuthority,
    input: DriveInputSession,
    output: Box<dyn StreamReader>,
}

impl DriveAuthority {
    /// Reload the current machine's drive authority.
    ///
    /// `Ok(None)` is the ordinary no-grant case used by discovery to omit the
    /// drive tools. A plan that claims a drive grant but has no matching,
    /// valid host-signed sidecar is an error rather than an absent grant.
    pub fn load(vm: &str) -> Result<Option<Self>, DriveSessionError> {
        mvm_core::naming::validate_vm_name(vm).map_err(|error| {
            DriveSessionError::Authority(anyhow::anyhow!("invalid machine name: {error}"))
        })?;
        let plan =
            crate::audit::plan_persist::read_plan(vm).map_err(DriveSessionError::Authority)?;
        let Some(plan_grant) = plan
            .grants
            .as_ref()
            .and_then(|grants| grants.drive.as_ref())
            .cloned()
        else {
            return Ok(None);
        };
        let envelope = mvm_runtime::microvm::read_verb_grant_envelope(vm)
            .map_err(DriveSessionError::Authority)?
            .ok_or_else(|| {
                DriveSessionError::Authority(anyhow::anyhow!(
                    "the admitted plan grants drive access but verb-grant.json is absent"
                ))
            })?;
        if envelope.plan_nonce_hex != plan.nonce.as_hex() {
            return Err(DriveSessionError::Authority(anyhow::anyhow!(
                "the drive grant nonce does not match the admitted plan"
            )));
        }
        let signer =
            crate::audit::host_keypair::load_or_init().map_err(DriveSessionError::Authority)?;
        envelope
            .grant
            .verify(&signer.verifying, vm, &plan.nonce, chrono::Utc::now())
            .map_err(|error| {
                DriveSessionError::Authority(anyhow::anyhow!(
                    "host-signed drive grant verification failed: {error}"
                ))
            })?;
        let signed_grant = envelope.grant.drive.ok_or_else(|| {
            DriveSessionError::Authority(anyhow::anyhow!(
                "the admitted plan grants drive access but the host-signed grant does not"
            ))
        })?;
        if signed_grant != plan_grant {
            return Err(DriveSessionError::Authority(anyhow::anyhow!(
                "the host-signed drive grant differs from the admitted plan"
            )));
        }
        let audit =
            Arc::new(AuditEmitter::new(signer.signing).map_err(DriveSessionError::Authority)?);
        Ok(Some(Self {
            vm: vm.to_string(),
            plan,
            grant: signed_grant,
            audit,
        }))
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

    /// Validate a file operation at the host boundary before transport.
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
        refusal.map_or(Ok(operation), |reason| self.refuse(reason))
    }

    /// The verified plan used for audit binding and the input gate.
    #[must_use]
    pub(crate) fn plan(&self) -> &mvm_contract::plan::ExecutionPlan {
        &self.plan
    }

    /// Machine identity covered by this authority.
    #[must_use]
    pub(crate) fn vm(&self) -> &str {
        &self.vm
    }

    /// The signed authority passed to the guest RPC helpers.
    #[must_use]
    pub fn grant(&self) -> &DriveGrant {
        &self.grant
    }

    /// Start the grant-selected program and hand over each non-terminal event
    /// as it arrives. The returned event is the single terminal outcome.
    pub fn open_program<F>(
        &self,
        cwd: &str,
        on_event: F,
    ) -> Result<EntrypointEvent, DriveSessionError>
    where
        F: FnMut(&EntrypointEvent),
    {
        let call = self.prepare_open(cwd)?;
        let transport =
            mvm_runtime::vsock_transport::for_vm(&self.vm).map_err(DriveSessionError::Rpc)?;
        let mut stream = transport
            .connect(mvm_agentd::vsock::GUEST_AGENT_PORT)
            .map_err(DriveSessionError::Rpc)?;
        mvm_agentd::vsock::send_drive_open(&mut stream, &self.grant, call, on_event)
            .map_err(|error| self.rpc_failure(error))
    }

    /// Execute one grant-bounded filesystem operation.
    pub fn file(&self, operation: DriveFileOperation) -> Result<FsResult, DriveSessionError> {
        let operation = self.prepare_file(operation)?;
        let transport =
            mvm_runtime::vsock_transport::for_vm(&self.vm).map_err(DriveSessionError::Rpc)?;
        let mut stream = transport
            .connect(mvm_agentd::vsock::GUEST_AGENT_PORT)
            .map_err(DriveSessionError::Rpc)?;
        mvm_agentd::vsock::send_drive_file(&mut stream, &self.grant, operation)
            .map_err(|error| self.rpc_failure(error))
    }

    fn rpc_failure(&self, error: anyhow::Error) -> DriveSessionError {
        if let Some(RpcError::DriveRefused { reason }) = error.downcast_ref::<RpcError>() {
            return match record_refusal(&self.audit, &self.plan, &self.vm, *reason) {
                Ok(()) => DriveSessionError::Refused(*reason),
                Err(error) => error,
            };
        }
        DriveSessionError::Rpc(error)
    }

    fn refuse<T>(&self, reason: DriveRefusal) -> Result<T, DriveSessionError> {
        record_refusal(&self.audit, &self.plan, &self.vm, reason)?;
        Err(DriveSessionError::Refused(reason))
    }
}

/// The existing [`InputSession`] plus the drive grant's cumulative input cap.
pub struct DriveInputSession {
    inner: InputRoute,
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
        let authority = DriveAuthority {
            vm: vm.to_string(),
            plan: plan.clone(),
            grant: grant.clone(),
            audit: Arc::clone(&audit),
        };
        let input = DriveInputSession {
            inner: InputRoute::open_drive(
                vm,
                admitted,
                Box::new(VsockInput::new(vm)),
                WireSequence::default(),
            )?,
            max_bytes: grant.max_bytes_in.get(),
            accepted_bytes: 0,
            vm: vm.to_string(),
            plan: plan.clone(),
            audit: Arc::clone(&audit),
        };
        let output = connect_stream(vm, StreamOpts::builder().follow(true).build())?;
        Ok(Self {
            authority,
            input,
            output,
        })
    }

    /// Open a driven session for an already-running machine by reloading and
    /// verifying the authority admission persisted for it.
    pub fn open_existing(vm: &str) -> Result<Self, DriveSessionError> {
        let Some(authority) = DriveAuthority::load(vm)? else {
            return Err(DriveSessionError::Refused(DriveRefusal::NotGranted));
        };
        let input = DriveInputSession::open_existing(&authority)?;
        let output = connect_stream(vm, StreamOpts::builder().follow(true).build())?;
        Ok(Self {
            authority,
            input,
            output,
        })
    }

    /// Prepare a drive-open request without exposing program selection.
    pub fn prepare_open(&self, cwd: &str) -> Result<DriveOpenCall, DriveSessionError> {
        self.authority.prepare_open(cwd)
    }

    /// Validate a file operation at the host boundary before it can be sent.
    pub fn prepare_file(
        &self,
        operation: DriveFileOperation,
    ) -> Result<DriveFileOperation, DriveSessionError> {
        self.authority.prepare_file(operation)
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
        self.authority.grant()
    }

    /// Start the grant-selected program through this session's verified
    /// authority.
    pub fn open_program<F>(
        &self,
        cwd: &str,
        on_event: F,
    ) -> Result<EntrypointEvent, DriveSessionError>
    where
        F: FnMut(&EntrypointEvent),
    {
        self.authority.open_program(cwd, on_event)
    }

    /// Execute one grant-bounded filesystem operation.
    pub fn file(&self, operation: DriveFileOperation) -> Result<FsResult, DriveSessionError> {
        self.authority.file(operation)
    }
}

impl DriveInputSession {
    /// Open the ordered, secret-scanned input route for an already-running
    /// machine under its re-verified drive authority.
    pub fn open_existing(authority: &DriveAuthority) -> Result<Self, DriveSessionError> {
        let vm = authority.vm();
        Ok(Self {
            inner: InputRoute::open_drive_authority(
                authority,
                Box::new(VsockInput::new(vm)),
                WireSequence::default(),
            )?,
            max_bytes: authority.grant.max_bytes_in.get(),
            accepted_bytes: 0,
            vm: vm.to_string(),
            plan: authority.plan.clone(),
            audit: Arc::clone(&authority.audit),
        })
    }

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
        self.inner.refresh().map_err(DriveSessionError::InputRoute)
    }

    /// Close this writer through the existing input-session ordering rule.
    pub fn close(self) -> Result<(), DriveSessionError> {
        self.inner.close().map_err(DriveSessionError::InputRoute)
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
    use std::os::unix::fs::PermissionsExt;

    use mvm_contract::grants::{DriveGrant, DriveProgramId, Grants};
    use mvm_core::protocol::vm_backend::VerbGrantEnvelope;
    use mvm_core::util::test_env::TestEnv;

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

    fn write_signed_authority(vm: &str, plan: &mvm_contract::plan::ExecutionPlan) {
        crate::audit::plan_persist::write_plan(vm, plan).unwrap();
        let signer = crate::audit::host_keypair::load_or_init().unwrap();
        let keystore =
            crate::host_signer::keystore::Keystore::load_from_file(&signer.secret_path).unwrap();
        let verb_grant = crate::host_signer::mint_verb_grant(
            &keystore,
            vm,
            &plan.nonce,
            plan.valid_until,
            Vec::new(),
            plan.grants.as_ref().and_then(|grants| grants.drive.clone()),
        )
        .unwrap();
        let envelope = VerbGrantEnvelope {
            pubkey_hex: signer
                .verifying
                .to_bytes()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
            plan_nonce_hex: plan.nonce.as_hex().to_string(),
            predecessor_session_id: None,
            predecessor_plan_nonce_hex: None,
            grant: verb_grant,
        };
        let path = mvm_core::config::vm_state_dir(vm).join("verb-grant.json");
        std::fs::write(&path, serde_json::to_vec(&envelope).unwrap()).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[test]
    fn existing_drive_authority_requires_the_matching_host_signed_grant() {
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(home.path());
        let drive = grant();
        let plan = mvm_core::plan::test_support::PlanFixture::new()
            .workload("drive-authority")
            .nonce([7; 16])
            .grants(Some(Grants {
                drive: Some(drive.clone()),
                ..Grants::default()
            }))
            .build();
        write_signed_authority("drive-authority", &plan);

        let loaded = DriveAuthority::load("drive-authority")
            .unwrap()
            .expect("drive grant is present");
        assert_eq!(loaded.grant(), &drive);
        assert_eq!(loaded.plan().nonce, plan.nonce);
    }

    #[test]
    fn existing_drive_authority_fails_closed_when_the_sidecar_is_missing() {
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(home.path());
        let plan = mvm_core::plan::test_support::PlanFixture::new()
            .workload("drive-missing-sidecar")
            .grants(Some(Grants {
                drive: Some(grant()),
                ..Grants::default()
            }))
            .build();
        crate::audit::plan_persist::write_plan("drive-missing-sidecar", &plan).unwrap();

        let Err(error) = DriveAuthority::load("drive-missing-sidecar") else {
            panic!("a missing signed sidecar must fail closed");
        };
        assert!(error.to_string().contains("verb-grant.json is absent"));
    }

    #[test]
    fn a_plan_without_a_drive_grant_exposes_no_drive_authority() {
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(home.path());
        let plan = mvm_core::plan::test_support::PlanFixture::new()
            .workload("drive-not-granted")
            .build();
        crate::audit::plan_persist::write_plan("drive-not-granted", &plan).unwrap();

        assert!(DriveAuthority::load("drive-not-granted").unwrap().is_none());
    }
}
