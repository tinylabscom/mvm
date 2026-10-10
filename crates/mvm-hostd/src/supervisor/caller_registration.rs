//! Cold-start caller registration at the trusted launcher/supervisor boundary.
//!
//! The startup transport is trusted under the host's authorized-launcher policy.
//! A generic signed plan is not registration authority. No producer endpoint or
//! warm handoff may call this installation path with producer-selected bytes.

use std::io::Read as _;

use anyhow::{Context, Result};
use ed25519_dalek::VerifyingKey;
use mvm_core::crypto::entrypoint_delegation::{RegistrationChallenge, VerifiedCallerProof};
use mvm_core::plan::{ExecutionPlan, SignedExecutionPlan};
use mvm_core::vm_backend::caller_registration::CallerRegistration;
use mvm_core::{atomic_io, config};

use crate::audit::host_keypair;
use crate::plan_admission::AdmittedPlan;

/// Immutable verified registration, owned by exactly one capture owner.
/// Deliberately not deserializable, cloneable, or constructible by a producer.
pub struct RegisteredCaller {
    proof: VerifiedCallerProof,
}

impl RegisteredCaller {
    pub fn challenge(&self) -> &RegistrationChallenge {
        self.proof.challenge()
    }
}

/// Verified cold-start state. This still must consume its one-shot startup slot.
pub struct VerifiedCallerLaunch {
    plan: ExecutionPlan,
    caller: RegisteredCaller,
    vm: String,
}

/// Validate opt-in before the supervisor publishes startup state, opens disks,
/// arms workload timers, publishes a PID, or enters the guest.
pub fn verify_startup(
    cfg: &mvm_vmm::host::hvf_supervisor::HvfSupervisorConfig,
) -> Result<Option<VerifiedCallerLaunch>> {
    let Some(registration) = cfg.caller_registration.as_ref() else {
        return Ok(None);
    };
    anyhow::ensure!(
        !cfg.trusted_builder_egress
            && cfg.handoff_socket.is_none()
            && cfg.restore_ram.is_none()
            && cfg.restore_frame.is_none()
            && cfg.restore_fds.is_none(),
        "caller registration currently requires a cold workload launch"
    );
    mvm_core::naming::validate_vm_name(&cfg.vm_name)?;
    anyhow::ensure!(
        cfg.pid_file.parent() == Some(config::vm_state_dir(&cfg.vm_name).as_path()),
        "caller startup state does not match its instance"
    );
    let signed = serde_json::from_value(
        cfg.plan
            .clone()
            .context("caller registration requires a signed plan")?,
    )
    .map_err(|_| anyhow::anyhow!("caller registration requires a signed plan"))?;
    verify_cold_start(&cfg.vm_name, &signed, registration).map(Some)
}

/// Mint only after actual plan admission and possession of the pinned native key.
/// The result is launch data, not a reusable authorization token.
pub fn admit_caller(
    admitted: &AdmittedPlan,
    vm: &str,
    expected: RegistrationChallenge,
    proof: VerifiedCallerProof,
) -> Result<CallerRegistration> {
    let now = unix_now()?;
    let registration = CallerRegistration {
        vm: vm.into(),
        expected,
        proof: proof.proof().clone(),
    };
    registration.verify_context(vm, admitted.plan(), now)?;
    Ok(registration)
}

/// Verify only a trusted cold-launch record, never a later producer request.
/// The root comes from the canonical host public-key location, not the config's
/// audit signing-key path or any root supplied alongside the signed plan.
pub fn verify_cold_start(
    vm: &str,
    signed: &SignedExecutionPlan,
    registration: &CallerRegistration,
) -> Result<VerifiedCallerLaunch> {
    let now = unix_now()?;
    let key = canonical_public_key()?;
    let plan =
        mvm_core::plan::verify_plan(signed, &[(host_keypair::host_signer_id().as_str(), &key)])
            .map_err(|_| anyhow::anyhow!("caller launch plan signature rejected"))?;
    mvm_core::plan::content_id::verify_plan_id(&plan)
        .map_err(|_| anyhow::anyhow!("caller launch plan content rejected"))?;
    mvm_core::plan::validity::check_window(&plan, chrono::Utc::now())
        .map_err(|_| anyhow::anyhow!("caller launch plan validity rejected"))?;
    let proof = registration
        .verify_context(vm, &plan, now)
        .map_err(|_| anyhow::anyhow!("caller launch possession or binding rejected"))?;
    Ok(VerifiedCallerLaunch {
        plan,
        caller: RegisteredCaller { proof },
        vm: vm.into(),
    })
}

impl VerifiedCallerLaunch {
    pub(crate) fn consume(self, vm: &str) -> Result<(ExecutionPlan, RegisteredCaller)> {
        anyhow::ensure!(self.vm == vm, "caller launch owner mismatch");
        mvm_core::plan::validity::check_window(&self.plan, chrono::Utc::now())
            .map_err(|_| anyhow::anyhow!("caller launch expired before installation"))?;
        self.caller
            .proof
            .proof()
            .verify(self.caller.challenge(), unix_now()?)
            .map_err(|_| anyhow::anyhow!("caller launch expired before installation"))?;
        mvm_core::naming::validate_vm_name(vm)?;
        let state = config::vm_state_dir(vm);
        match std::fs::symlink_metadata(&state) {
            Ok(metadata) => anyhow::ensure!(
                metadata.file_type().is_dir(),
                "caller launch state must be a real directory"
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        config::create_private_dir(&state)?;
        let parent = state
            .parent()
            .context("caller launch state has no parent")?;
        anyhow::ensure!(
            std::fs::canonicalize(&state)? == std::fs::canonicalize(parent)?.join(vm),
            "caller launch state is not contained"
        );
        // One fixed private replay slot per managed VM, not attacker-selected
        // filenames or an unbounded nonce directory. Failed setup stays spent:
        // retrying those same launch bytes must never restore authority. Normal
        // instance teardown removes the slot with the rest of managed VM state.
        // This marker is replay bookkeeping, never registration authority.
        let marker = state.join("caller-registration.used");
        let run = self.caller.challenge().binding.run.to_string();
        anyhow::ensure!(
            matches!(
                atomic_io::write_private_new(&marker, run.as_bytes())?,
                atomic_io::NewFile::Created
            ),
            "caller launch was already consumed; tear down the failed instance and obtain fresh admission"
        );
        Ok((self.plan, self.caller))
    }
}

fn canonical_public_key() -> Result<VerifyingKey> {
    let path = config::mvm_keys_dir().join(host_keypair::PUBLIC_FILENAME);
    let metadata = std::fs::symlink_metadata(&path)?;
    anyhow::ensure!(
        metadata.file_type().is_file() && metadata.len() == 32,
        "canonical host public key is invalid"
    );
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options.open(path)?;
    let mut bytes = [0; 32];
    file.read_exact(&mut bytes)?;
    anyhow::ensure!(
        file.read(&mut [0; 1])? == 0,
        "canonical host public key is invalid"
    );
    VerifyingKey::from_bytes(&bytes).context("canonical host public key is invalid")
}

fn unix_now() -> Result<u64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs())
}

#[cfg(test)]
#[path = "caller_registration_tests.rs"]
mod tests;
