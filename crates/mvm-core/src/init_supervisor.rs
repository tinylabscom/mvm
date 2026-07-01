//! `mvm-init` supervisor core logic (pure).
//!
//! The decisions the static guest PID-1 supervisor makes, factored out of the
//! syscall/boot path so they are unit-testable without a VM: turning validated
//! flat [`LaunchMetadata`] into the workload's exec spec (fail-closed on empty
//! argv), and the normal marker progression `mvm-init` reports. The actual
//! mount/fork/exec/vsock plumbing wraps this and is exercised on the live box.

use crate::launch_metadata::LaunchMetadata;
use crate::lifecycle::LifecycleMarker;

/// The validated command `mvm-init` will exec as the workload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChildSpec {
    pub program: String,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
    pub workdir: Option<String>,
    pub user: Option<String>,
}

/// Why the supervisor could not prepare the workload. A fatal setup error here
/// makes `mvm-init` emit [`LifecycleMarker::FailedInspectable`] and hold the VM
/// alive, rather than exiting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InitError {
    /// No command to run — argv was empty.
    EmptyArgv,
}

impl core::fmt::Display for InitError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            InitError::EmptyArgv => write!(f, "launch metadata has no command (empty argv)"),
        }
    }
}

impl std::error::Error for InitError {}

/// Turn validated launch metadata into the workload exec spec: argv[0] is the
/// program, the rest are arguments. Fails closed if argv is empty.
pub fn child_spec_from(meta: &LaunchMetadata) -> Result<ChildSpec, InitError> {
    let (program, args) = meta.argv.split_first().ok_or(InitError::EmptyArgv)?;
    Ok(ChildSpec {
        program: program.clone(),
        args: args.to_vec(),
        env: meta.env.clone(),
        workdir: meta.workdir.clone(),
        user: meta.user.clone(),
    })
}

/// The normal marker progression `mvm-init` reports on a healthy boot, in order
/// and ending at [`LifecycleMarker::WorkloadExited`].
/// [`LifecycleMarker::FailedInspectable`] is not part of it — it is the
/// off-ramp taken on a fatal setup error.
pub const HAPPY_PATH: [LifecycleMarker; 8] = [
    LifecycleMarker::Booted,
    LifecycleMarker::MountsReady,
    LifecycleMarker::MetadataReady,
    LifecycleMarker::SecretsReady,
    LifecycleMarker::PreExec,
    LifecycleMarker::WorkloadStarted,
    LifecycleMarker::Ready,
    LifecycleMarker::WorkloadExited,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn child_spec_splits_program_and_args() {
        let meta = LaunchMetadata {
            argv: vec!["/bin/sh".into(), "-c".into(), "echo hi".into()],
            ..Default::default()
        };
        let spec = child_spec_from(&meta).unwrap();
        assert_eq!(spec.program, "/bin/sh");
        assert_eq!(spec.args, vec!["-c".to_string(), "echo hi".to_string()]);
    }

    #[test]
    fn child_spec_carries_env_workdir_user() {
        let meta = LaunchMetadata {
            argv: vec!["/app".into()],
            env: vec![("K".into(), "v".into())],
            workdir: Some("/work".into()),
            user: Some("901".into()),
        };
        let spec = child_spec_from(&meta).unwrap();
        assert!(spec.args.is_empty());
        assert_eq!(spec.env, vec![("K".to_string(), "v".to_string())]);
        assert_eq!(spec.workdir.as_deref(), Some("/work"));
        assert_eq!(spec.user.as_deref(), Some("901"));
    }

    #[test]
    fn empty_argv_is_a_fatal_setup_error() {
        let meta = LaunchMetadata::default();
        assert_eq!(child_spec_from(&meta).unwrap_err(), InitError::EmptyArgv);
    }

    #[test]
    fn happy_path_is_ordered_and_excludes_failure() {
        assert_eq!(*HAPPY_PATH.first().unwrap(), LifecycleMarker::Booted);
        assert_eq!(*HAPPY_PATH.last().unwrap(), LifecycleMarker::WorkloadExited);
        assert!(!HAPPY_PATH.contains(&LifecycleMarker::FailedInspectable));
    }
}
