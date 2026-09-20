//! The builders that run a builder shell job in their own image.
//!
//! HVF and Firecracker boot the builder image and run a caller's `cmd.sh`
//! against a `/work` tree, writing into `/out`. libkrun, QEMU and WebLinux
//! have no such path; a caller that needs one says so by name rather than
//! lowering onto another backend.

use anyhow::Result;
use mvm_build::builder_backend_select::BuilderBackendChoice;

/// A builder backend with a shell-job path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ShellJobBuilder {
    Hvf,
    Firecracker,
}

impl ShellJobBuilder {
    /// The shell-job builder for `choice`, when it has one.
    pub(crate) fn for_choice(choice: BuilderBackendChoice) -> Option<Self> {
        match choice {
            BuilderBackendChoice::Hvf => Some(Self::Hvf),
            BuilderBackendChoice::Firecracker => Some(Self::Firecracker),
            BuilderBackendChoice::Libkrun
            | BuilderBackendChoice::Qemu
            | BuilderBackendChoice::WebLinux => None,
        }
    }

    /// Boot this backend's builder image and run `job` in it.
    pub(crate) fn run(self, job: &mvm_build::libkrun_builder::BuilderShellJob) -> Result<()> {
        match self {
            Self::Hvf => {
                let (kernel, rootfs, closure_nar) =
                    crate::commands::build::hvf_builder_image::resolve_hvf_builder_image()
                        .map_err(|error| anyhow::anyhow!("resolving HVF builder image: {error}"))?;
                mvm_runtime::builder_runner::DriverBuilderVm::new(
                    mvm_backends::driver::hvf::HvfDriver::new(),
                    kernel,
                    rootfs,
                )
                .with_closure_nar(closure_nar)
                .run_shell_script(job)
                .map_err(|error| anyhow::anyhow!("HVF builder shell job: {error}"))?;
            }
            Self::Firecracker => {
                let image = crate::commands::build::fc_builder_image::resolve_fc_builder_image()
                    .map_err(|error| {
                        anyhow::anyhow!("resolving Firecracker builder image: {error}")
                    })?;
                mvm_runtime::builder_runner::DriverBuilderVm::new(
                    mvm_backends::driver::fc::FcDriver::new(),
                    image.kernel,
                    image.rootfs,
                )
                .with_closure_nar(image.closure_nar)
                .run_shell_script(job)
                .map_err(|error| anyhow::anyhow!("Firecracker builder shell job: {error}"))?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_hvf_and_firecracker_run_shell_jobs() {
        for (choice, builder) in [
            (BuilderBackendChoice::Hvf, Some(ShellJobBuilder::Hvf)),
            (
                BuilderBackendChoice::Firecracker,
                Some(ShellJobBuilder::Firecracker),
            ),
            (BuilderBackendChoice::Libkrun, None),
            (BuilderBackendChoice::Qemu, None),
            (BuilderBackendChoice::WebLinux, None),
        ] {
            assert_eq!(ShellJobBuilder::for_choice(choice), builder, "{choice:?}");
        }
    }
}
