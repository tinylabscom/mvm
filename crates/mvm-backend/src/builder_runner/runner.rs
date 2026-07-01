//! Boots a builder VM over the `VmmDriver` seam and moves the job in / artifacts
//! out over raw disks. The trusted, disk-only sibling of `WorkloadRunner`: no
//! egress endpoint (the builder carries no untrusted workload), no virtio-fs.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};

use mvm_build::builder_disk_transport::{
    InputTree, create_output_disk, pack_input_disk, read_output_disk,
};
use mvm_core::config::vm_state_dir;
use mvm_core::vm_backend::VmStatus;

use super::spec::{BuilderSpecInputs, builder_spec};
use crate::driver::VmmDriver;

/// The minimum input-disk size; the disk grows past this to hold the packed
/// `{job, work, mvm-bins}` tar (a few MiB of scripts + cross-compiled binaries).
const INPUT_DISK_MIN: u64 = 16 << 20;

/// Host-side backstop while waiting for the builder VM to power off. The VM's own
/// run budget (`MVM_HVF_TIMEOUT`) is the real bound — this only guards against a
/// supervisor that never drops its PID file. A `nix build` can take many minutes.
const BUILD_WAIT_TIMEOUT: Duration = Duration::from_secs(30 * 60);

/// Resolved inputs for one builder run. The caller (the builder-selection layer)
/// resolves the builder VM image + the persistent nix-store disk and stages the
/// job dir (`cmd.sh`); this runner owns the disk transport + the VM lifecycle.
pub struct BuilderBuild<'a> {
    pub name: &'a str,
    /// arm64 boot `Image` for the builder VM.
    pub kernel: &'a Path,
    /// Builder rootfs (booted read-only).
    pub rootfs: &'a Path,
    /// Persistent nix-store disk (writable; survives across builds).
    pub nix_store: &'a Path,
    /// Staged job dir (`cmd.sh`, …) → the guest's `/job`.
    pub job_dir: &'a Path,
    /// Flake source → the guest's `/work`.
    pub work_src: &'a Path,
    /// Host mvm binaries → the guest's `/mvm-bins`.
    pub host_bin_dir: &'a Path,
    /// Output disk size in bytes; must exceed the artifact tar (rootfs + sidecars).
    pub output_size: u64,
    pub vcpus: u32,
    pub memory_mib: u32,
}

/// What a builder run produced.
pub struct BuilderOutcome {
    /// True if the builder VM powered off on its own; false if the host-side
    /// backstop fired first. The authoritative build exit code lives in the
    /// output dir's `result` sidecar (the caller finalizes it).
    pub stopped: bool,
    /// Directory the guest's output tar was extracted into (`rootfs.ext4`,
    /// `result`, `boot-timings.json`). The caller finalizes it into a
    /// `BuilderArtifacts`.
    pub output_dir: PathBuf,
}

/// Boots builder VMs over the `VmmDriver` seam. Stateless: each build resolves
/// its own per-VM state dir from the name.
pub struct BuilderRunner<D: VmmDriver> {
    driver: D,
}

impl<D: VmmDriver + 'static> BuilderRunner<D> {
    pub fn new(driver: D) -> Self {
        Self { driver }
    }

    /// Pack the inputs onto the input disk, boot the builder VM, wait for it to
    /// finish, and extract the artifact tar off the output disk.
    pub fn build(&self, b: &BuilderBuild<'_>) -> Result<BuilderOutcome> {
        let state_dir = vm_state_dir(b.name);
        std::fs::create_dir_all(&state_dir)
            .with_context(|| format!("create builder state dir {}", state_dir.display()))?;

        let input_disk = state_dir.join("input.img");
        let output_disk = state_dir.join("output.img");
        let output_dir = state_dir.join("out");

        // Pack {job, work, mvm-bins} onto the input disk; the guest extracts it.
        pack_input_disk(
            &[
                InputTree {
                    name: "job",
                    src: b.job_dir,
                },
                InputTree {
                    name: "work",
                    src: b.work_src,
                },
                InputTree {
                    name: "mvm-bins",
                    src: b.host_bin_dir,
                },
            ],
            &input_disk,
            INPUT_DISK_MIN,
        )?;
        create_output_disk(&output_disk, b.output_size)?;

        let spec = builder_spec(&BuilderSpecInputs {
            name: b.name,
            kernel: b.kernel,
            rootfs: b.rootfs,
            nix_store: b.nix_store,
            input_disk: &input_disk,
            output_disk: &output_disk,
            console_log: state_dir.join("console.log"),
            agent_socket: Some(state_dir.join("agent.sock")),
            vcpus: b.vcpus,
            memory_mib: b.memory_mib,
        });

        let vm = self.driver.boot(&spec)?;
        // A builder is run-to-completion: the guest powers off after the job, and
        // `status()` flips to Stopped/Failed when the supervisor drops its PID
        // file. (Unlike a workload, it reports no exit code over vsock — its result
        // is the output tar's `result` sidecar.)
        let deadline = Instant::now() + BUILD_WAIT_TIMEOUT;
        let mut stopped = false;
        while Instant::now() < deadline {
            if !matches!(vm.status()?, VmStatus::Running) {
                stopped = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(500));
        }

        // The guest wrote a tar onto the output disk; extract it host-side.
        read_output_disk(&output_disk, &output_dir)?;
        Ok(BuilderOutcome {
            stopped,
            output_dir,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver::mock::MockDriver;

    #[test]
    fn build_packs_inputs_boots_the_builder_spec_and_extracts_the_output() {
        let tmp = tempfile::tempdir().unwrap();
        // Isolate per-VM state to the tempdir. nextest runs each test in its own
        // process, so this env override doesn't leak to sibling tests.
        // SAFETY: single-threaded test setup, before any VM state is resolved.
        unsafe { std::env::set_var("MVM_DATA_DIR", tmp.path()) };

        // Real input trees + placeholder image files on disk.
        let job = tmp.path().join("job");
        let work = tmp.path().join("work");
        let bins = tmp.path().join("bins");
        for d in [&job, &work, &bins] {
            std::fs::create_dir_all(d).unwrap();
        }
        std::fs::write(job.join("cmd.sh"), b"#!/bin/sh\nnix build\n").unwrap();
        std::fs::write(work.join("flake.nix"), b"{}").unwrap();
        std::fs::write(bins.join("mvm-host-vm-init"), b"ELF").unwrap();
        let kernel = tmp.path().join("Image");
        let rootfs = tmp.path().join("rootfs.ext4");
        let nix_store = tmp.path().join("nix-store.img");
        for f in [&kernel, &rootfs, &nix_store] {
            std::fs::write(f, b"x").unwrap();
        }

        // A run-to-completion builder: the mock VM reports Stopped so the
        // poll-until-off loop returns at once.
        let runner = BuilderRunner::new(MockDriver::default().reporting_status(VmStatus::Stopped));
        let outcome = runner
            .build(&BuilderBuild {
                name: "bld-unit",
                kernel: &kernel,
                rootfs: &rootfs,
                nix_store: &nix_store,
                job_dir: &job,
                work_src: &work,
                host_bin_dir: &bins,
                output_size: 1 << 20,
                vcpus: 2,
                memory_mib: 1024,
            })
            .expect("build orchestrates against the mock driver");

        assert!(outcome.stopped);
        // A single builder spec was booted: 4 disks, trusted, builder cmdline.
        let specs = runner.driver.booted_specs();
        assert_eq!(specs.len(), 1);
        assert!(specs[0].trusted_builder);
        assert_eq!(specs[0].blocks.len(), 4);
        assert!(specs[0].cmdline.contains("init=/sbin/mvm-host-vm-init"));
        // The input disk was packed and the output extracted (empty tar from the
        // mock guest, which writes nothing).
        assert!(tmp.path().join("vms/bld-unit/input.img").exists());
        assert!(outcome.output_dir.exists());
    }
}
