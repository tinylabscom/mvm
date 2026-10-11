use mvm_build::builder_backend_select::{
    BuilderBackendChoice, BuilderFactoryOptions, resolve_choice,
    try_resolve_builder_backend_with_options,
};
use mvm_build::builder_vm::{BuilderShellJob, BuilderShellResult, BuilderVm, BuilderVmError};

#[derive(Debug, thiserror::Error)]
pub enum ShellJobError {
    #[error("builder shell script is empty")]
    EmptyScript,
    #[error("builder shell job work_dir must be a directory")]
    MissingWorkDirectory,
    #[error("builder shell job contains an invalid extra disk")]
    InvalidDisk,
    #[error("builder shell jobs are not available for {0}; use hvf, firecracker, or libkrun")]
    UnsupportedBackend(&'static str),
    #[error("builder VM shell job failed: {0}")]
    Builder(#[from] BuilderVmError),
}

/// Validate and execute a shell job using the authoritative registered factory.
/// No fallback changes an explicitly selected execution boundary.
pub fn run_shell_job(
    job: &BuilderShellJob,
    backend: Option<BuilderBackendChoice>,
) -> Result<BuilderShellResult, ShellJobError> {
    run_shell_job_with_options(job, backend, BuilderFactoryOptions::default())
}

/// Run a shell job with explicit factory presentation settings.
pub fn run_shell_job_with_options(
    job: &BuilderShellJob,
    backend: Option<BuilderBackendChoice>,
    options: BuilderFactoryOptions,
) -> Result<BuilderShellResult, ShellJobError> {
    run_with_factory(job, resolve_choice(backend), |choice| {
        crate::host_runtime::initialize();
        try_resolve_builder_backend_with_options(choice, options)
    })
}

fn run_with_factory(
    job: &BuilderShellJob,
    choice: BuilderBackendChoice,
    factory: impl FnOnce(BuilderBackendChoice) -> Result<Box<dyn BuilderVm>, BuilderVmError>,
) -> Result<BuilderShellResult, ShellJobError> {
    validate(job)?;
    require_shell_backend(choice)?;
    let builder = factory(choice)?;
    run_shell_job_on(job, builder.as_ref())
}

/// Execute with a configured builder implementing the shared build contract.
/// This also supports embedders supplying a builder and hermetic test builders.
pub fn run_shell_job_on(
    job: &BuilderShellJob,
    builder: &dyn BuilderVm,
) -> Result<BuilderShellResult, ShellJobError> {
    validate(job)?;
    Ok(builder.run_shell_script(job)?)
}

fn require_shell_backend(choice: BuilderBackendChoice) -> Result<(), ShellJobError> {
    match choice {
        BuilderBackendChoice::Hvf
        | BuilderBackendChoice::Firecracker
        | BuilderBackendChoice::Libkrun => Ok(()),
        BuilderBackendChoice::Qemu | BuilderBackendChoice::WebLinux => {
            Err(ShellJobError::UnsupportedBackend(choice.name()))
        }
    }
}

fn validate(job: &BuilderShellJob) -> Result<(), ShellJobError> {
    if job.script.trim().is_empty() {
        return Err(ShellJobError::EmptyScript);
    }
    if !job.work_dir.is_dir() {
        return Err(ShellJobError::MissingWorkDirectory);
    }
    if job
        .extra_disks
        .iter()
        .any(|disk| disk.id.trim().is_empty() || !disk.path.is_file())
    {
        return Err(ShellJobError::InvalidDisk);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use mvm_build::builder_vm::{BuilderArtifacts, BuilderCapabilities, BuilderJob, BuilderMounts};

    use super::*;

    struct Builder {
        calls: AtomicUsize,
        refuse: bool,
    }

    impl BuilderVm for Builder {
        fn run_build(
            &self,
            _: &BuilderJob,
            _: &BuilderMounts,
        ) -> Result<BuilderArtifacts, BuilderVmError> {
            panic!("shell jobs must not dispatch a template build")
        }
        fn run_stage0(
            &self,
            _: &Path,
            _: &str,
            _: &Path,
            _: &Path,
            _: &Path,
        ) -> Result<(), BuilderVmError> {
            panic!("shell jobs must not run stage zero")
        }
        fn capabilities(&self) -> BuilderCapabilities {
            BuilderCapabilities::default()
        }
        fn run_shell_script(
            &self,
            job: &BuilderShellJob,
        ) -> Result<BuilderShellResult, BuilderVmError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.refuse {
                return Err(BuilderVmError::NotYetImplemented);
            }
            Ok(BuilderShellResult {
                job_dir: job.artifact_out.clone(),
                vm_state_dir: job.work_dir.clone(),
            })
        }
    }

    #[test]
    fn shell_execution_and_refusal_use_the_same_contract() {
        let directory = tempfile::tempdir().unwrap();
        let job = BuilderShellJob {
            work_dir: directory.path().into(),
            artifact_out: directory.path().join("out"),
            script: "true".into(),
            extra_disks: vec![],
        };
        for refuse in [false, true] {
            let builder = Builder {
                calls: AtomicUsize::new(0),
                refuse,
            };
            assert_eq!(run_shell_job_on(&job, &builder).is_err(), refuse);
            assert_eq!(builder.calls.load(Ordering::SeqCst), 1);
        }
    }

    #[test]
    fn invalid_jobs_are_refused_before_builder_execution() {
        let directory = tempfile::tempdir().unwrap();
        let mut job = BuilderShellJob {
            work_dir: directory.path().into(),
            artifact_out: directory.path().join("out"),
            script: " ".into(),
            extra_disks: vec![],
        };
        let builder = Builder {
            calls: AtomicUsize::new(0),
            refuse: false,
        };
        assert!(matches!(
            run_shell_job_on(&job, &builder),
            Err(ShellJobError::EmptyScript)
        ));
        job.script = "true".into();
        job.work_dir = directory.path().join("missing");
        assert!(matches!(
            run_shell_job_on(&job, &builder),
            Err(ShellJobError::MissingWorkDirectory)
        ));
        assert_eq!(builder.calls.load(Ordering::SeqCst), 0);
        assert!(!job.artifact_out.exists());
    }

    #[test]
    fn unsupported_backends_are_refused_without_resolving_an_image() {
        let directory = tempfile::tempdir().unwrap();
        let job = BuilderShellJob {
            work_dir: directory.path().into(),
            artifact_out: directory.path().join("out"),
            script: "true".into(),
            extra_disks: vec![],
        };
        for backend in [BuilderBackendChoice::Qemu, BuilderBackendChoice::WebLinux] {
            assert!(matches!(
                run_with_factory(&job, backend, |_| panic!(
                    "must not resolve a refused backend"
                )),
                Err(ShellJobError::UnsupportedBackend(_))
            ));
        }
    }

    #[test]
    fn factory_receives_the_selected_backend_without_fallback() {
        let directory = tempfile::tempdir().unwrap();
        let job = BuilderShellJob {
            work_dir: directory.path().into(),
            artifact_out: directory.path().join("out"),
            script: "true".into(),
            extra_disks: vec![],
        };
        for selected in [BuilderBackendChoice::Hvf, BuilderBackendChoice::Firecracker] {
            let result = run_with_factory(&job, selected, |choice| {
                assert_eq!(choice, selected);
                Ok(Box::new(Builder {
                    calls: AtomicUsize::new(0),
                    refuse: false,
                }))
            })
            .unwrap();
            assert_eq!(result.job_dir, job.artifact_out);
        }
    }
}
