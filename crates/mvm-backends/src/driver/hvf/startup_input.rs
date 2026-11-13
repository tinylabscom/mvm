use anyhow::Result;
use mvm_core::protocol::hvf_startup::FrozenConfig;
use std::path::PathBuf;

pub(super) struct SupervisorLaunchPolicy {
    pub(super) validate_config: fn(&super::HvfSupervisorConfig) -> Result<()>,
    pub(super) configure_environment: fn(&mut std::process::Command),
    #[cfg(feature = "experimental-owned-capture")]
    pub(super) capture_startup: Option<CaptureStartup>,
}

impl SupervisorLaunchPolicy {
    pub(super) fn legacy() -> Self {
        Self {
            validate_config: |_| Ok(()),
            configure_environment: |command| {
                command.env_remove("MVM_HVF_LEGACY_CONFIG_REPLAY");
            },
            #[cfg(feature = "experimental-owned-capture")]
            capture_startup: None,
        }
    }

    pub(super) fn cold() -> Self {
        Self {
            validate_config: super::require_cold_config,
            configure_environment: |command| {
                // Bind projected boot arguments, not ambient debug overrides.
                // Remove both from the actual child environment before scope
                // binding seals the launch command.
                command.env_remove("MVM_HVF_BOOTARGS");
                command.env_remove("MVM_HVF_BOOTARGS_EXTRA");
                command.env_remove("MVM_HVF_LEGACY_CONFIG_REPLAY");
            },
            #[cfg(feature = "experimental-owned-capture")]
            capture_startup: None,
        }
    }
}

#[cfg(feature = "experimental-owned-capture")]
impl super::HvfDriver {
    /// Experimental startup under original cold custody; no capture transport.
    pub fn boot_cold_owned_with_capture(
        &self,
        spec: &super::VmmSpec,
        kernel: Option<&mvm_vmm::host::restore_image::VerifiedRestoreFile>,
        images: &mvm_vmm::host::boot_images::FrozenBootImageBytes,
        startup: CaptureStartup,
    ) -> std::result::Result<super::ColdHvfOwner, super::ColdHvfBootFailure> {
        let mut policy = SupervisorLaunchPolicy::cold();
        policy.capture_startup = Some(startup);
        super::boot_with_custody(
            spec,
            None,
            None,
            policy,
            super::BootInputFiles {
                kernel,
                images: Some(images),
                writable: None,
                data: None,
            },
        )
        .map(super::ColdHvfOwner::from_fresh)
    }
}

/// One-shot binding of final bytes by the original higher-layer invocation.
/// This callback carries no credential or receiver-side write authorization.
#[cfg(feature = "experimental-owned-capture")]
pub type CaptureStartup = Box<
    dyn FnOnce(FrozenConfig) -> Result<mvm_core::protocol::hvf_startup::StartupEnvelope> + Send,
>;

pub(super) struct SupervisorInput {
    config: FrozenConfig,
    #[cfg(feature = "experimental-owned-capture")]
    owned: Option<OwnedInput>,
}

#[cfg(feature = "experimental-owned-capture")]
struct OwnedInput {
    supervisor: PathBuf,
    bytes: zeroize::Zeroizing<Vec<u8>>,
}

impl SupervisorInput {
    pub(super) fn legacy(config: FrozenConfig) -> Self {
        Self {
            config,
            #[cfg(feature = "experimental-owned-capture")]
            owned: None,
        }
    }

    #[cfg(feature = "experimental-owned-capture")]
    pub(super) fn owned(
        resolve: impl FnOnce() -> Result<PathBuf>,
        bind: impl FnOnce() -> Result<mvm_core::protocol::hvf_startup::StartupEnvelope>,
    ) -> Result<Self> {
        let supervisor = resolve()?;
        let envelope = bind()?;
        let bytes = envelope.encode()?;
        Ok(Self {
            config: envelope.config().clone(),
            owned: Some(OwnedInput { supervisor, bytes }),
        })
    }

    pub(super) fn config(&self) -> &FrozenConfig {
        &self.config
    }

    pub(super) fn bytes(&self) -> &[u8] {
        #[cfg(feature = "experimental-owned-capture")]
        if let Some(owned) = &self.owned {
            return &owned.bytes;
        }
        self.config.as_bytes()
    }

    pub(super) fn supervisor(&self) -> Result<PathBuf> {
        #[cfg(feature = "experimental-owned-capture")]
        if let Some(owned) = &self.owned {
            return Ok(owned.supervisor.clone());
        }
        super::resolve_supervisor_path_verified()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "experimental-owned-capture")]
    use std::cell::Cell;

    #[test]
    fn legacy_input_keeps_the_exact_held_configuration() {
        let json = mvm_core::protocol::hvf_startup::FrozenConfig::from_json(
            b" { \"vm_name\": \"fixture\" }\n".to_vec(),
        )
        .unwrap();
        let input = SupervisorInput::legacy(json.clone());
        assert!(std::ptr::eq(input.bytes(), json.as_bytes()));
    }

    #[cfg(feature = "experimental-owned-capture")]
    #[test]
    fn compatibility_refusal_precedes_binding_or_workload_input() {
        let bound = Cell::new(false);
        let result = SupervisorInput::owned(
            || anyhow::bail!("unsupported helper"),
            || {
                bound.set(true);
                anyhow::bail!("must not bind input")
            },
        );
        assert!(result.is_err());
        assert!(!bound.get());
    }

    #[cfg(feature = "experimental-owned-capture")]
    #[test]
    fn owned_input_preserves_inner_bytes_call_and_original_storage() {
        use mvm_core::protocol::hvf_startup::{FrozenConfig, StartupEnvelope};
        let config = FrozenConfig::from_json(b" { \"tenant\": \"\xc3\xa9\" }\n".to_vec()).unwrap();
        let call = "cbe0cdfa-2a42-4497-bce2-593c80c4ceef".parse().unwrap();
        let input = SupervisorInput::owned(
            || Ok(std::path::PathBuf::from("/not-executed")),
            || config.clone().for_call(call).map_err(Into::into),
        )
        .unwrap();
        assert!(std::ptr::eq(input.config().as_bytes(), config.as_bytes()));
        let decoded = StartupEnvelope::decode(input.bytes()).unwrap();
        assert_eq!(decoded.call(), call);
        assert_eq!(decoded.config().as_bytes(), config.as_bytes());
        assert_eq!(decoded.config().digest(), config.digest());
    }
}
