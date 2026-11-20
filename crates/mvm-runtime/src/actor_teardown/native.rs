use super::*;
use mvm_core::protocol::hvf_control::HvfInstance;

/// The backend's original generation. Test identities never assert a native VM exit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum ActorInstance {
    /// Authenticated HVF supervisor generation.
    Hvf(HvfInstance),
    /// In-memory test backend generation, available only in test-support builds.
    #[cfg(feature = "test-support")]
    Mock {
        /// Host-private mock VM name.
        vm_id: VmId,
        /// Exact registry generation.
        generation: uuid::Uuid,
    },
}

pub(super) enum OriginalVm {
    Hvf(Box<dyn RunningVm>),
    #[cfg(feature = "test-support")]
    Mock {
        backend: crate::mock::MockBackend,
        id: VmId,
        generation: uuid::Uuid,
    },
}

pub(super) enum OriginalExit {
    Hvf(mvm_vmm::host::hvf_stop::ConfirmedExit),
    #[cfg(feature = "test-support")]
    Mock(crate::mock::MockActorExit),
}

impl OriginalVm {
    pub(super) fn open_agent_bridge(
        &self,
        stream: &mut Option<std::os::unix::net::UnixStream>,
    ) -> Result<()> {
        match self {
            Self::Hvf(vm) => vm.open_owned_agent_bridge(stream),
            #[cfg(feature = "test-support")]
            Self::Mock {
                backend,
                id,
                generation,
            } => {
                ensure!(
                    stream.is_none(),
                    "original mock bridge must not be replaced"
                );
                ensure!(
                    backend.actor_generation(id)? == *generation,
                    "mock actor generation changed"
                );
                let path = crate::mock::MockBackend::vm_dir(&id.0).join("runtime/v.sock");
                *stream = Some(mvm_agentd::vsock::connect_to_port_once(
                    &path.to_string_lossy(),
                    mvm_agentd::vsock::GUEST_AGENT_PORT,
                    5,
                )?);
                ensure!(
                    backend.actor_generation(id)? == *generation,
                    "mock actor generation changed"
                );
                Ok(())
            }
        }
    }

    pub(super) fn validate_agent_bridge(
        &self,
        stream: &std::os::unix::net::UnixStream,
    ) -> Result<()> {
        match self {
            Self::Hvf(vm) => vm.validate_owned_agent_bridge(stream),
            #[cfg(feature = "test-support")]
            Self::Mock {
                backend,
                id,
                generation,
            } => {
                let _ = stream;
                ensure!(
                    backend.actor_generation(id)? == *generation,
                    "mock actor generation changed"
                );
                Ok(())
            }
        }
    }

    pub(super) fn retained_process_descriptor_count(&self) -> Result<u64> {
        match self {
            Self::Hvf(vm) => vm.retained_process_descriptor_count(),
            #[cfg(feature = "test-support")]
            Self::Mock { .. } => Ok(0),
        }
    }

    pub(super) fn exit_observer(&self) -> Result<mvm_vmm::host::process_exit::ProcessExitObserver> {
        match self {
            Self::Hvf(vm) => vm.exit_observer(),
            #[cfg(feature = "test-support")]
            Self::Mock { .. } => anyhow::bail!("mock actors have no native process exit observer"),
        }
    }

    pub(super) fn id(&self) -> &VmId {
        match self {
            Self::Hvf(vm) => vm.id(),
            #[cfg(feature = "test-support")]
            Self::Mock { id, .. } => id,
        }
    }

    pub(super) fn identity(&self) -> Result<ActorInstance> {
        match self {
            Self::Hvf(vm) => Ok(ActorInstance::Hvf(
                vm.authenticated_hvf_instance()?
                    .context("original native identity missing")?,
            )),
            #[cfg(feature = "test-support")]
            Self::Mock { id, generation, .. } => Ok(ActorInstance::Mock {
                vm_id: id.clone(),
                generation: *generation,
            }),
        }
    }

    pub(super) fn status(&self) -> Result<mvm_core::vm_backend::VmStatus> {
        match self {
            Self::Hvf(vm) => vm.status(),
            #[cfg(feature = "test-support")]
            Self::Mock {
                backend,
                id,
                generation,
            } => {
                use mvm_core::vm_backend::VmBackend;
                ensure!(
                    backend.actor_generation(id)? == *generation,
                    "mock actor generation changed"
                );
                backend.status(id)
            }
        }
    }

    pub(super) fn wait(&self) -> Result<mvm_core::vm_backend::VmExitStatus> {
        match self {
            Self::Hvf(vm) => vm.wait(),
            #[cfg(feature = "test-support")]
            Self::Mock { backend, id, .. } => {
                use mvm_core::vm_backend::VmBackend;
                backend.wait(id)
            }
        }
    }

    pub(super) fn stop(&self) -> Result<OriginalExit> {
        match self {
            Self::Hvf(vm) => Ok(OriginalExit::Hvf(
                vm.terminate_with_kernel_exit()?
                    .hvf_exit
                    .context("original native exit is unconfirmed")?,
            )),
            #[cfg(feature = "test-support")]
            Self::Mock {
                backend,
                id,
                generation,
            } => backend.stop_actor(id, *generation).map(OriginalExit::Mock),
        }
    }
}

impl OriginalExit {
    pub(super) fn identity(&self) -> ActorInstance {
        match self {
            Self::Hvf(exit) => ActorInstance::Hvf(exit.instance().clone()),
            #[cfg(feature = "test-support")]
            Self::Mock(exit) => ActorInstance::Mock {
                vm_id: exit.id.clone(),
                generation: exit.generation,
            },
        }
    }

    pub(super) fn release_kernel(&self, lifecycle: &RuntimeLifecycleLease) -> Result<()> {
        match self {
            Self::Hvf(proof) => {
                proof.verify_current()?;
                if crate::kernel_custody::has_retained_kernel(lifecycle)? {
                    crate::kernel_custody::release_after_confirmed_exit(lifecycle, proof)?;
                }
                Ok(())
            }
            #[cfg(feature = "test-support")]
            Self::Mock(_) => Ok(()),
        }
    }
}

#[cfg(feature = "test-support")]
pub(super) fn start_mock(
    backend: &crate::mock::MockBackend,
    config: &VmStartConfig,
) -> Result<ActorOwner> {
    use mvm_core::vm_backend::VmBackend;
    config.wait_for_admission_durability()?;
    let lifecycle = RuntimeLifecycleLease::acquire(&config.name)?;
    let id = backend.start(config)?;
    let generation = backend.actor_generation(&id)?;
    let vm = OriginalVm::Mock {
        backend: backend.clone(),
        id,
        generation,
    };
    let state = ResourceIdentity::capture(&crate::mock::MockBackend::vm_dir(&config.name))?;
    let journal = ActorTeardownJournal {
        instance: vm.identity()?,
        state: state.clone(),
        socket_directory: None,
        helpers: Vec::new(),
        unverified_helpers: Vec::new(),
    };
    Ok(ActorOwner {
        vm: Some(vm),
        journal,
        helpers: Vec::new(),
        quarantined: Vec::new(),
        native_exit: None,
        lifecycle: Some(lifecycle),
        state,
        socket_directory: None,
        terminal: false,
        startup_failure: None,
        entrypoint: entrypoint::DispatchState::Ready,
        failed_entrypoint_stream: None,
    })
}
