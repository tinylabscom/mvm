//! Supervisor launch gating for the HVF driver: the launch policy that seals
//! the supervisor command, the exclusive per-instance launch lock, and the
//! runtime-evidence probes that decide whether an instance name is absent.

use std::path::{Path, PathBuf};

use crate::host::hvf_control_transport as stop_wire;
use anyhow::{Context, Result, bail};

use super::HvfSupervisorConfig;
use super::require_cold_config;
#[cfg(test)]
use super::tests::spec_with;
use crate::driver::hvf_process::PID_FILE_NAME;
#[cfg(test)]
use crate::driver::spec::KernelImage;

pub(super) struct SupervisorLaunchPolicy {
    pub(super) validate_config: fn(&HvfSupervisorConfig) -> Result<()>,
    pub(super) configure_environment: fn(&mut std::process::Command),
}

impl SupervisorLaunchPolicy {
    pub(super) fn legacy() -> Self {
        Self {
            validate_config: |_| Ok(()),
            configure_environment: |command| {
                command.env_remove("MVM_HVF_LEGACY_CONFIG_REPLAY");
            },
        }
    }

    pub(super) fn cold() -> Self {
        Self {
            validate_config: require_cold_config,
            configure_environment: |command| {
                // Bind projected boot arguments, not ambient debug overrides.
                // Remove both from the actual child environment before scope
                // binding seals the launch command.
                command.env_remove("MVM_HVF_BOOTARGS");
                command.env_remove("MVM_HVF_BOOTARGS_EXTRA");
                command.env_remove("MVM_HVF_LEGACY_CONFIG_REPLAY");
            },
        }
    }
}

/// The exclusive per-instance launch lock. A `flock` belongs to the open file
/// description, which a concurrently forking thread's child shares until it
/// execs, so closing the descriptor alone can leave the lock held. Dropping
/// unlocks explicitly, releasing it for every copy.
pub(super) struct HvfLaunchLock(std::fs::File);

impl Drop for HvfLaunchLock {
    fn drop(&mut self) {
        use std::os::fd::AsRawFd;
        // SAFETY: the owned file is open; unlocking cannot invalidate it.
        unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) };
    }
}

pub(super) fn claim_hvf_launch(state_dir: &Path) -> Result<HvfLaunchLock> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::OpenOptionsExt;
    let launch_lock = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(state_dir.join("hvf-launch.lock"))?;
    // SAFETY: the owned file holds this nonblocking launch lock until return.
    if unsafe { libc::flock(launch_lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        bail!("another HVF launch owns this instance name");
    }
    let launch_lock = HvfLaunchLock(launch_lock);
    if any_path_exists(hvf_runtime_evidence(state_dir))? {
        bail!("existing HVF runtime evidence requires confirmed cleanup before reuse");
    }
    Ok(launch_lock)
}

/// Files a supervisor launch, or its outcome, leaves under an instance's
/// state directory.
pub(super) fn hvf_runtime_evidence(state_dir: &Path) -> impl Iterator<Item = PathBuf> {
    [
        stop_wire::INSTANCE_FILE,
        stop_wire::SOCKET_FILE,
        stop_wire::FINALIZED_FILE,
        PID_FILE_NAME,
        "supervisor.json",
        "supervisor-status.json",
        "workload.exit",
    ]
    .map(|name| state_dir.join(name))
    .into_iter()
    .chain([
        mvm_core::config::vm_socket_dir_at(state_dir).join(stop_wire::SOCKET_FILE),
        mvm_core::config::vm_hvf_agent_socket_at(state_dir),
    ])
}

/// Whether no HVF launch was ever attempted under `state_dir`: no launch lock
/// and no runtime evidence. A launch takes the lock before it spawns a
/// supervisor, and cleanup removes the directory only after a confirmed exit.
pub(super) fn hvf_instance_absent(state_dir: &Path) -> Result<bool> {
    let lock = std::iter::once(state_dir.join("hvf-launch.lock"));
    Ok(!any_path_exists(
        lock.chain(hvf_runtime_evidence(state_dir)),
    )?)
}

pub(super) fn any_path_exists(paths: impl IntoIterator<Item = PathBuf>) -> Result<bool> {
    for path in paths {
        match std::fs::symlink_metadata(&path) {
            Ok(_) => return Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("inspect prior HVF runtime evidence"),
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::super::bounded_supervisor_command;
    use super::*;

    #[test]
    fn cold_actual_child_command_removes_both_bootarg_overrides_before_sealing() {
        let directory = tempfile::tempdir().unwrap();
        let spec = spec_with(KernelImage::Path("/test-kernel".into()), vec![], vec![]);
        let command = bounded_supervisor_command(
            Path::new("/native-supervisor-not-executed"),
            &spec,
            directory.path(),
            None,
            &SupervisorLaunchPolicy::cold(),
        );
        for name in ["MVM_HVF_BOOTARGS", "MVM_HVF_BOOTARGS_EXTRA"] {
            assert!(
                command
                    .as_command()
                    .get_envs()
                    .any(|(key, value)| key == name && value.is_none())
            );
        }
    }

    #[test]
    fn same_name_launch_is_exclusive_and_prior_outcome_is_not_absence_proof() {
        mvm_core::util::test_env::isolated_lock_probe(|| {
            let _env = mvm_core::util::test_env::TestEnv::new();
            let directory = tempfile::tempdir().unwrap();
            let first = claim_hvf_launch(directory.path()).unwrap();
            assert!(claim_hvf_launch(directory.path()).is_err());
            drop(first);
            drop(claim_hvf_launch(directory.path()).unwrap());
            std::fs::write(directory.path().join("workload.exit"), "124").unwrap();
            assert!(claim_hvf_launch(directory.path()).is_err());
            assert_eq!(
                std::fs::read_to_string(directory.path().join("workload.exit")).unwrap(),
                "124"
            );
        });
    }

    /// A forked child shares the lock's open file description until it execs.
    /// A clone stands in for it: dropping the lock must still release it.
    #[test]
    fn dropping_the_launch_lock_releases_it_while_another_descriptor_shares_it() {
        let directory = tempfile::tempdir().unwrap();
        let first = claim_hvf_launch(directory.path()).unwrap();
        let _forked_copy = first.0.try_clone().unwrap();
        drop(first);
        drop(claim_hvf_launch(directory.path()).unwrap());
    }

    #[test]
    fn a_granted_share_wraps_the_supervisor_spawn() {
        let scratch = tempfile::tempdir().expect("scratch");
        let mut env = mvm_core::util::test_env::TestEnv::new();
        mvm_core::spawn_scope::pretend_mechanism_present(&mut env, scratch.path())
            .expect("fake mechanism");

        let mut spec = spec_with(KernelImage::Bundled, vec![], vec![]);
        spec.cpu_grant = Some(mvm_contract::grants::CpuGrant::Share { millicores: 500 });
        let cmd = bounded_supervisor_command(
            Path::new("/usr/bin/mvm-hvf-supervisor"),
            &spec,
            scratch.path(),
            None,
            &SupervisorLaunchPolicy::legacy(),
        );
        let argv = mvm_core::spawn_scope::rendered_argv(cmd.as_command());

        assert_eq!(
            Path::new(&argv[0])
                .file_name()
                .and_then(|name| name.to_str()),
            Some("systemd-run")
        );
        assert!(argv.contains(&"CPUQuota=50%".to_string()), "{argv:?}");
        assert!(
            argv.contains(&format!(
                "MemoryMax={}M",
                u64::from(spec.memory_mib) + mvm_core::spawn_scope::VMM_MEMORY_OVERHEAD_MIB
            )),
            "{argv:?}"
        );
        assert_eq!(argv.last().expect("payload"), "/usr/bin/mvm-hvf-supervisor");
    }
}
