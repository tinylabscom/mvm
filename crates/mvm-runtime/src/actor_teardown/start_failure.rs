use super::*;

pub(super) struct PendingStart {
    pub(super) vm: Option<OriginalVm>,
    pub(super) helpers: Helpers,
    pub(super) state: ResourceIdentity,
    pub(super) socket_directory: Option<ResourceIdentity>,
    pub(super) name: String,
    pub(super) no_dispatch: Option<ActorNoDispatchProof>,
}

impl PendingStart {
    fn owner(&mut self, cause: &mut Option<anyhow::Error>) -> Result<Option<ActorOwner>> {
        let Some(vm) = self.vm.as_ref() else {
            return Ok(None);
        };
        // All fallible initialization precedes moving any original custody.
        let instance = vm.identity()?;
        let lifecycle = RuntimeLifecycleLease::acquire(&self.name)?;
        let helpers =
            std::mem::take(&mut *self.helpers.lock().expect("actor helper custody poisoned"));
        let unverified_helpers = if cause.as_ref().is_some_and(|error| {
            error
                .downcast_ref::<mvm_vmm::host::retained_spawn::RetainedSpawnFailure>()
                .is_some()
        }) {
            vec![UnverifiedHelperIdentity {
                role: "startup-helper".into(),
                pid: None,
            }]
        } else {
            Vec::new()
        };
        let journal = ActorTeardownJournal {
            instance,
            state: self.state.clone(),
            socket_directory: self.socket_directory.clone(),
            helpers: helpers
                .iter()
                .map(|helper| helper.identity.clone())
                .collect(),
            unverified_helpers,
        };
        Ok(Some(ActorOwner {
            vm: self.vm.take(),
            journal,
            helpers,
            quarantined: Vec::new(),
            native_exit: None,
            lifecycle: Some(lifecycle),
            state: self.state.clone(),
            socket_directory: self.socket_directory.clone(),
            terminal: false,
            startup_failure: cause.take(),
            entrypoint: entrypoint::DispatchState::Ready,
            failed_entrypoint_stream: None,
        }))
    }
}

struct FailureState {
    pending: PendingStart,
    cause: Option<anyhow::Error>,
    owner: Option<ActorOwner>,
}

/// A failed actor start retaining every original native and helper owner.
///
/// Downcast the runtime error to this type. `take_owner` transfers a booted
/// original into the host lifecycle's Unknown slot; it is never reconstructed
/// from journal data. Preboot failures retain their helper/native spawn errors.
pub struct ActorStartFailure {
    message: String,
    state: Mutex<Option<FailureState>>,
    no_dispatch: Option<ActorNoDispatchProof>,
}

impl std::fmt::Debug for ActorStartFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ActorStartFailure")
            .field("message", &self.message)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Display for ActorStartFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "actor start failed with retained original custody: {}",
            self.message
        )
    }
}

impl std::error::Error for ActorStartFailure {}

impl ActorStartFailure {
    pub(super) fn before_dispatch(
        cause: anyhow::Error,
        no_dispatch: Option<ActorNoDispatchProof>,
    ) -> Self {
        Self {
            message: format!("{cause:#}"),
            state: Mutex::new(None),
            no_dispatch,
        }
    }

    pub(super) fn new(cause: anyhow::Error, mut pending: PendingStart) -> Self {
        Self {
            message: format!("{cause:#}"),
            no_dispatch: pending.no_dispatch.take(),
            state: Mutex::new(Some(FailureState {
                pending,
                cause: Some(cause),
                owner: None,
            })),
        }
    }

    /// Original runtime evidence, never inferred from successful rollback or absent owners.
    pub fn no_dispatch_proof(&self) -> Option<&ActorNoDispatchProof> {
        self.no_dispatch.as_ref()
    }

    /// Transfer a successfully booted original into the caller's retained owner slot.
    /// Initialization failure leaves all custody in this error for another retry.
    pub fn take_owner(&self) -> Result<Option<ActorOwner>> {
        let mut state = self.state.lock().expect("actor failed start poisoned");
        let Some(state) = state.as_mut() else {
            return Ok(None);
        };
        if state.owner.is_some() {
            return Ok(state.owner.take());
        }
        state.pending.owner(&mut state.cause)
    }

    /// Retry original rollback. This result alone is not reservation-release evidence.
    /// A booted owner remains available through `take_owner` after this call.
    pub fn retry_stop(&self) -> Result<()> {
        let mut state = self.state.lock().expect("actor failed start poisoned");
        let Some(state) = state.as_mut() else {
            return Ok(());
        };
        if state.owner.is_none() {
            state.owner = state.pending.owner(&mut state.cause)?;
        }
        if let Some(owner) = state.owner.as_mut() {
            return owner.stop_and_reap().map(drop);
        }
        if let Some(cause) = state.cause.as_mut() {
            if let Some(failure) =
                cause.downcast_mut::<mvm_backends::driver::hvf::ColdHvfBootFailure>()
            {
                failure.retry_stop()?;
            }
            if let Some(failure) =
                cause.downcast_ref::<mvm_vmm::host::retained_spawn::RetainedSpawnFailure>()
            {
                failure.retry_stop()?;
            }
        }
        reap_helpers(
            &mut state
                .pending
                .helpers
                .lock()
                .expect("actor helper custody poisoned"),
        )?;
        Ok(())
    }
}

impl Drop for ActorStartFailure {
    fn drop(&mut self) {
        // The host must keep this error or transfer its owner. Formatting an
        // uncertain error must never discard the sole original native handle.
        std::mem::forget(
            self.state
                .get_mut()
                .expect("actor failed start poisoned")
                .take(),
        );
    }
}

pub(super) fn finish(mut pending: PendingStart, result: Result<()>) -> Result<ActorOwner> {
    if let Err(error) = result {
        return Err(anyhow::Error::new(ActorStartFailure::new(error, pending)));
    }
    pending.no_dispatch = None;
    match pending.owner(&mut None) {
        Ok(Some(owner)) => Ok(owner),
        Ok(None) => Err(anyhow::Error::new(ActorStartFailure::new(
            anyhow::anyhow!("actor launch returned without original VM custody"),
            pending,
        ))),
        Err(error) => Err(anyhow::Error::new(ActorStartFailure::new(error, pending))),
    }
}
