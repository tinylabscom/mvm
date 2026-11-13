//! Owned cold-start capture binding. Parsed bytes and possession are not authority.
//! Only consumed admission with checked boot inputs can reach the native owner.
//! Constructors belong to the existing authorized-launcher startup boundary,
//! never a producer-request, recovery or handoff endpoint.

use std::time::Instant;

use anyhow::{Context, Result, ensure};
use mvm_core::crypto::entrypoint_delegation::RegistrationChallenge;
use mvm_core::crypto::owned_capture::CaptureBinding;
use mvm_core::plan::ExecutionPlan;
use mvm_core::protocol::hvf_control::HvfInstance;
use mvm_core::protocol::hvf_startup::StartupEnvelope;
use mvm_vmm::host::hvf_supervisor::HvfSupervisorConfig;
use mvm_vmm::host::process_exit::{ProcessExitObserver, ProcessExitWait};

use super::caller_registration::{self, ConsumedCallerLaunch, RegisteredCaller};
use super::hvf_stop::StopAuthority;

/// Non-cloneable pending input under observed original-parent custody.
/// No permit is installed merely by constructing this value.
pub struct PendingCaptureStartup {
    input: StartupEnvelope,
    vm: String,
    expected: RegistrationChallenge,
    parent: OriginalParent,
}

/// Constructor-sealed authority for the existing protected owner only.
pub struct OwnedCaptureAuthority {
    plan: ExecutionPlan,
    caller: RegisteredCaller,
    permit: OwnedCapturePermit,
}

pub(crate) struct BoundCaptureOwnerParts {
    pub(crate) plan: ExecutionPlan,
    pub(crate) caller: RegisteredCaller,
    pub(crate) permit: OwnedCapturePermit,
}

pub(crate) struct OwnedCapturePermit {
    binding: CaptureBinding,
    instance: HvfInstance,
    parent: OriginalParent,
    native: StopAuthority,
    retired: bool,
}

impl PendingCaptureStartup {
    /// Observe before descriptor adoption, helpers or other startup effects.
    pub fn observe(input: StartupEnvelope) -> Result<Self> {
        let cfg: HvfSupervisorConfig = serde_json::from_slice(input.config().as_bytes())
            .map_err(|_| anyhow::anyhow!("invalid owned capture startup configuration"))?;
        ensure!(
            cfg.kernel_fd.is_some()
                && cfg.boot_image_fds.is_some()
                && cfg.caller_registration.is_some(),
            "owned capture requires complete checked startup"
        );
        caller_registration::require_cold_caller_mode(&cfg)
            .map_err(|_| anyhow::anyhow!("owned capture startup mode is invalid"))?;
        let expected = cfg
            .caller_registration
            .context("owned capture registration missing")?
            .expected;
        let parent = OriginalParent::observe(input.launcher_pid())?;
        Ok(Self {
            input,
            vm: cfg.vm_name,
            expected,
            parent,
        })
    }

    /// Bind only through actual consumed admission, checked inputs and the original
    /// native gate. This installs context, not a spent permit or append permission.
    pub fn bind_to_owner(
        self,
        launch: Box<ConsumedCallerLaunch>,
        native: StopAuthority,
    ) -> Result<Box<OwnedCaptureAuthority>> {
        let (plan, caller) = launch.into_capture_owner(&self.vm)?;
        ensure!(
            caller.challenge() == &self.expected,
            "owned capture caller binding differs"
        );
        let gate = native.clone();
        gate.with_capture_instance(&self.vm, |instance| {
            let mut parent = self.parent;
            parent.recheck()?;
            let binding = CaptureBinding::builder(
                caller.challenge().identity.clone(),
                caller.challenge().binding.clone(),
                &self.vm,
            )
            .with_startup(self.input.config().digest())
            .with_call(self.input.call())
            .with_boot(instance.boot_nonce)
            .with_capture_run(caller.capture_run())
            .with_peer_pids(parent.pid, std::process::id())
            .build()?;
            Ok(Box::new(OwnedCaptureAuthority {
                plan,
                caller,
                permit: OwnedCapturePermit {
                    binding,
                    instance: instance.clone(),
                    parent,
                    native,
                    retired: false,
                },
            }))
        })
    }
}

impl OwnedCapturePermit {
    /// Current binding data only. A later receiver must separately serialize
    /// authentication, one-call spend and append against retirement.
    pub(crate) fn current_binding(&mut self) -> Result<&CaptureBinding> {
        ensure!(!self.retired, "owned capture permit is retired");
        let result = self
            .native
            .with_capture_instance(&self.instance.vm_id, |instance| {
                ensure!(
                    instance == &self.instance,
                    "owned capture generation changed"
                );
                self.parent.recheck()
            });
        if let Err(error) = result {
            self.retire();
            return Err(error);
        }
        Ok(&self.binding)
    }

    pub(crate) fn retire(&mut self) {
        self.retired = true;
    }
}

impl OwnedCaptureAuthority {
    pub(crate) fn current_binding(&mut self) -> Result<&CaptureBinding> {
        self.permit.current_binding()
    }

    pub(crate) fn into_parts_for_vm(
        mut self: Box<Self>,
        vm: &str,
    ) -> Result<BoundCaptureOwnerParts> {
        ensure!(
            self.permit.instance.vm_id == vm,
            "owned capture owner differs"
        );
        self.current_binding()?;
        Ok(BoundCaptureOwnerParts {
            plan: self.plan,
            caller: self.caller,
            permit: self.permit,
        })
    }
}

struct OriginalParent {
    pid: u32,
    observer: ProcessExitObserver,
    retired: bool,
}

impl OriginalParent {
    fn observe(expected: u32) -> Result<Self> {
        // SAFETY: getppid only observes the current process's actual kernel parent.
        let pid = unsafe { libc::getppid() };
        ensure!(
            u32::try_from(pid).ok() == Some(expected),
            "capture launcher is not original parent"
        );
        let observer = ProcessExitObserver::arm(pid)?;
        let mut parent = Self {
            pid: expected,
            observer,
            retired: false,
        };
        parent.recheck()?;
        Ok(parent)
    }

    fn recheck(&mut self) -> Result<()> {
        // SAFETY: getppid is an observation, not a signal or ownership conversion.
        self.check(unsafe { libc::getppid() })
    }

    fn check(&mut self, actual: libc::pid_t) -> Result<()> {
        ensure!(!self.retired, "capture original parent is retired");
        let current = u32::try_from(actual).ok() == Some(self.pid);
        let event = self.observer.wait_event(Instant::now());
        if !current || !matches!(event, Ok(ProcessExitWait::TimedOut)) {
            self.retired = true;
            anyhow::bail!("capture original parent is unavailable");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    #[test]
    fn invalid_startup_schema_does_not_repeat_input_values() {
        let input = mvm_core::protocol::hvf_startup::FrozenConfig::from_json(
            br#"{"console_capture":"private-input-value"}"#.to_vec(),
        )
        .unwrap()
        .for_call(uuid::Uuid::new_v4())
        .unwrap();
        let error = PendingCaptureStartup::observe(input).err().unwrap();
        assert!(!format!("{error:?}").contains("private-input-value"));
    }

    struct ChildGuard(std::process::Child);

    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    #[test]
    fn original_parent_mismatch_is_absorbing() {
        // SAFETY: read-only process metadata; this test never signals its parent.
        let pid = u32::try_from(unsafe { libc::getppid() }).unwrap();
        let mut parent = OriginalParent::observe(pid).unwrap();
        assert!(parent.check(1).is_err());
        assert!(parent.recheck().is_err());
    }

    #[test]
    fn actual_observed_process_exit_cannot_be_reopened_by_a_reported_pid() {
        let mut child = ChildGuard(
            Command::new("/bin/sh")
                .args(["-c", "exec sleep 30"])
                .spawn()
                .unwrap(),
        );
        let pid = child.0.id();
        // The reported-parent value below is a fixture. Only the exit event is real.
        let mut parent = OriginalParent {
            pid,
            observer: ProcessExitObserver::arm(i32::try_from(pid).unwrap()).unwrap(),
            retired: false,
        };
        assert!(parent.check(i32::try_from(pid).unwrap()).is_ok());
        child.0.kill().unwrap();
        child.0.wait().unwrap();
        assert!(parent.check(i32::try_from(pid).unwrap()).is_err());
        assert!(parent.check(i32::try_from(pid).unwrap()).is_err());
    }
}
