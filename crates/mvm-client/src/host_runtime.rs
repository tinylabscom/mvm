//! Process integration for host-side frontends of the local client.
//!
//! Register shared runtime services once. Frontends still own signal handlers,
//! terminal interaction, tracing subscribers, and their own process exit.

use std::sync::Once;

static INITIALIZE: Once = Once::new();

/// Install the driver-backed builders and authenticated output-stream plane.
/// Registration does not start a VM or perform a build.
pub fn initialize() {
    INITIALIZE.call_once(|| {
        mvm_runtime::builder_runner::register_driver_backed_builders();
        crate::entrypoint::install_output_capture();
    });
}

/// The frontend's process-wide output contract for local runtime diagnostics.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OutputPolicy {
    pub verbose: bool,
    pub machine_readable_stdout: bool,
}

/// Keep runtime diagnostics out of a machine-readable stdout channel.
pub fn configure_output(policy: OutputPolicy) {
    mvm_runtime::ui::set_verbose(policy.verbose);
    mvm_runtime::ui::set_chrome_to_stderr(policy.machine_readable_stdout);
}

/// Settle armed client operations before a frontend exits on an interrupt.
/// The returned labels identify attempted cleanups, not successful outcomes.
pub fn run_interrupt_cleanups() -> Vec<String> {
    mvm_runtime::interrupt_cleanup::run_all()
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::util::test_env::TestEnv;

    #[test]
    fn repeated_initialization_does_not_create_machine_state() {
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(home.path());
        initialize();
        initialize();
        assert_eq!(std::fs::read_dir(home.path()).unwrap().count(), 0);
    }

    #[test]
    fn output_policy_keeps_verbose_independent_of_stdout_routing() {
        let _env = TestEnv::new();
        let original = OutputPolicy {
            verbose: mvm_runtime::ui::is_verbose(),
            machine_readable_stdout: mvm_runtime::ui::is_chrome_routed_to_stderr(),
        };
        for verbose in [false, true] {
            for machine_readable_stdout in [false, true] {
                configure_output(OutputPolicy {
                    verbose,
                    machine_readable_stdout,
                });
                assert_eq!(mvm_runtime::ui::is_verbose(), verbose);
                assert_eq!(
                    mvm_runtime::ui::is_chrome_routed_to_stderr(),
                    machine_readable_stdout
                );
            }
        }
        configure_output(original);
    }
}
