//! Consume audit failure notifications in the existing VM lifetime owner.

use anyhow::Result;
use mvm_core::protocol::hvf_control::HvfInstance;
use mvm_runtime::driver::fc::FirecrackerStop;
use mvm_vmm::host::audit_control::{KeeperControl, ShutdownTarget};
use mvm_vmm::host::hvf_stop::ConnectedInstance;

enum PreparedTarget {
    Hvf(HvfInstance),
    Firecracker(FirecrackerStop),
}

impl PreparedTarget {
    fn connect(target: ShutdownTarget) -> Result<Self> {
        match target {
            ShutdownTarget::Hvf(instance) => {
                // Prove stop authority before publishing readiness; reconnect
                // with this exact generation when a failure actually arrives.
                ConnectedInstance::connect_instance(instance.clone())?;
                Ok(Self::Hvf(instance))
            }
            ShutdownTarget::Firecracker {
                process,
                api_socket,
            } => Ok(Self::Firecracker(FirecrackerStop::connect(
                &process,
                &api_socket,
            )?)),
        }
    }

    fn stop(self) -> Result<()> {
        match self {
            Self::Hvf(instance) => ConnectedInstance::connect_instance(instance)?
                .stop()?
                .verify_current(),
            Self::Firecracker(target) => target.stop(),
        }
    }
}

pub(super) fn serve(control: KeeperControl) -> Result<()> {
    control.serve(PreparedTarget::connect, PreparedTarget::stop)
}
