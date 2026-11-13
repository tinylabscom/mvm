//! Original admitted invocation custody. Public registration bytes cannot
//! construct this credential-bearing value, and no credential enters the VMM.

use anyhow::{Context, Result, ensure};
use mvm_core::protocol::hvf_startup::{FrozenConfig, StartupEnvelope};
use mvm_core::vm_backend::caller_registration::CallerRegistration;
use std::sync::{Arc, OnceLock};
use uuid::Uuid;

pub(crate) struct CaptureInvocation {
    credential: mvm_hostd::caller_identity::CallerCredential,
    startup: StartupBinding,
}

impl CaptureInvocation {
    /// Called only while the original admission retains its loaded credential.
    pub(super) fn admitted(
        credential: mvm_hostd::caller_identity::CallerCredential,
        registration: &CallerRegistration,
        admitted: &mvm_hostd::plan_admission::AdmittedPlan,
        now: u64,
    ) -> Result<Self> {
        ensure!(
            credential.identity() == registration.expected.identity,
            "capture credential differs from admitted caller"
        );
        registration.verify_context(&registration.vm, admitted.plan(), now)?;
        Ok(Self {
            credential,
            startup: StartupBinding::new(registration.clone()),
        })
    }

    pub(super) fn take_emitter(
        &mut self,
    ) -> Result<impl FnOnce(FrozenConfig) -> Result<StartupEnvelope> + Send + 'static> {
        self.startup.take_emitter()
    }

    pub(super) fn before_dispatch(&self) -> Result<()> {
        ensure!(
            self.credential.identity() == self.startup.expected.expected.identity,
            "original capture credential differs"
        );
        self.startup.prepared()?;
        Ok(())
    }
}

struct StartupBinding {
    expected: CallerRegistration,
    call: Uuid,
    config: Arc<OnceLock<FrozenConfig>>,
    issued: bool,
}

impl StartupBinding {
    fn new(expected: CallerRegistration) -> Self {
        Self {
            expected,
            call: Uuid::new_v4(),
            config: Arc::new(OnceLock::new()),
            issued: false,
        }
    }

    fn prepared(&self) -> Result<&FrozenConfig> {
        self.config
            .get()
            .context("original capture startup was not bound")
    }

    fn take_emitter(
        &mut self,
    ) -> Result<impl FnOnce(FrozenConfig) -> Result<StartupEnvelope> + Send + 'static> {
        ensure!(!self.issued, "capture startup emitter was already issued");
        self.issued = true;
        let expected = self.expected.clone();
        let retained = Arc::clone(&self.config);
        let call = self.call;
        Ok(move |config: FrozenConfig| {
            let cfg: mvm_vmm::host::hvf_supervisor::HvfSupervisorConfig =
                serde_json::from_slice(config.as_bytes())
                    .map_err(|_| anyhow::anyhow!("invalid original capture configuration"))?;
            ensure!(
                cfg.vm_name == expected.vm
                    && cfg.caller_registration.as_ref() == Some(&expected)
                    && cfg.kernel_fd.is_some()
                    && cfg.boot_image_fds.is_some(),
                "final capture configuration differs from original checked caller"
            );
            let envelope = config.for_call(call)?;
            retained
                .set(envelope.config().clone())
                .map_err(|_| anyhow::anyhow!("original capture configuration already bound"))?;
            Ok(envelope)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::crypto::entrypoint_delegation::{
        RegistrationBinding, RegistrationChallenge, RegistrationProof,
    };
    use mvm_core::crypto::entrypoint_identity::EnrolledIdentity;
    use mvm_core::plan::Nonce;
    use mvm_core::vm_backend::caller_registration::CallerRegistration;
    use uuid::Uuid;

    // Public registration data only; no admission, credential or native custody.
    fn registration() -> CallerRegistration {
        let expected = RegistrationChallenge::fresh(
            RegistrationBinding {
                tenant: "tenant".into(),
                instance: format!("capture-fixture/{}", Uuid::from_u128(1)),
                plan_id: "sha256:".to_owned() + &"01".repeat(32),
                plan_nonce: Nonce::from_bytes([1; 16]),
                run: Uuid::from_u128(2),
                producer: Uuid::from_u128(3),
                session: Uuid::from_u128(4),
                not_before: 100,
                not_after: 200,
            },
            EnrolledIdentity {
                installation: Uuid::from_u128(5),
                public_key: [1; 32],
            },
            100,
        )
        .unwrap();
        CallerRegistration {
            vm: "capture-fixture".into(),
            proof: RegistrationProof {
                challenge: expected.clone(),
                signature: vec![0; 64],
            },
            expected,
        }
    }

    fn config(registration: &CallerRegistration) -> FrozenConfig {
        let mut config: mvm_vmm::host::hvf_supervisor::HvfSupervisorConfig =
            serde_json::from_value(serde_json::json!({
                "vm_name": "capture-fixture", "kernel": "/unused",
                "console_log": "/unused/console", "pid_file": "/unused/pid",
                "workload_exit": "/unused/exit", "timeout_secs": 0,
                "console_capture": "encrypted"
            }))
            .unwrap();
        config.caller_registration = Some(registration.clone());
        config.kernel_fd = Some(100);
        config.boot_image_fds = Some(mvm_vmm::host::hvf_supervisor::BootImageFds {
            rootfs: 101,
            verity: 102,
            metadata: 103,
            root_hash: 104,
        });
        FrozenConfig::serialize(&config).unwrap()
    }

    #[test]
    fn original_startup_is_shared_and_issued_only_once() {
        let registration = registration();
        let mut binding = StartupBinding::new(registration.clone());
        assert_ne!(binding.call, StartupBinding::new(registration.clone()).call);
        assert!(binding.prepared().is_err());
        let config = config(&registration);
        let emit = binding.take_emitter().unwrap();
        assert!(binding.take_emitter().is_err());
        let envelope = emit(config.clone()).unwrap();
        assert_eq!(envelope.call(), binding.call);
        assert!(std::ptr::eq(
            binding.prepared().unwrap().as_bytes(),
            config.as_bytes()
        ));
        assert_eq!(
            envelope.config().digest(),
            binding.prepared().unwrap().digest()
        );
    }

    #[test]
    fn changed_registration_or_vm_never_binds_original_call() {
        for change_vm in [false, true] {
            let registration = registration();
            let mut changed = registration.clone();
            if change_vm {
                changed.vm.push('x');
            } else {
                changed.expected.nonce[0] ^= 1;
            }
            let mut binding = StartupBinding::new(registration);
            assert!(binding.take_emitter().unwrap()(config(&changed)).is_err());
            assert!(binding.prepared().is_err());
            assert!(binding.take_emitter().is_err());
        }
    }

    #[test]
    fn schema_errors_do_not_repeat_private_configuration_values() {
        let mut binding = StartupBinding::new(registration());
        let bad = FrozenConfig::from_json(br#"{"console_capture":"private-input-value"}"#.to_vec())
            .unwrap();
        let error = binding.take_emitter().unwrap()(bad).unwrap_err();
        assert!(!format!("{error:?}").contains("private-input-value"));
        assert!(binding.prepared().is_err());
    }
}
