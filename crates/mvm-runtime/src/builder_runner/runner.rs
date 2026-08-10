//! Boots a builder VM over the `VmmDriver` seam and moves the job in / artifacts
//! out over raw disks. The trusted, disk-only sibling of `WorkloadRunner`: no
//! egress endpoint (the builder carries no untrusted workload), no virtio-fs.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};

use mvm_agentd::vsock::EGRESS_PORT;
use mvm_build::builder_disk_transport::{
    InputTree, create_output_disk, pack_input_disk, read_output_disk,
};
use mvm_core::config::{vm_state_dir, vm_vsock_port_socket_at};
use mvm_core::policy::RedactionPolicy;
use mvm_core::policy::network_policy::NetworkPolicy;
use mvm_core::vm_backend::VmStatus;

use super::spec::{BuilderSpecInputs, builder_spec};
use crate::driver::VmmDriver;
use crate::substitution_spawn::{
    EndpointGuard, EndpointTransport, SubstitutionSpawnParams, spawn_substitution_endpoint,
};

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
    /// Optional read-only runtime overlay ext4 for the builder guest.
    pub runtime_overlay: Option<&'a Path>,
    /// Optional seeded Nix store closure NAR, resolved from the builder
    /// image when it carries one → the guest's `/closure-seed/<file>`. `None`
    /// (the common case today) adds no share at all.
    pub closure_nar: Option<&'a Path>,
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
        let egress_socket = vm_vsock_port_socket_at(&state_dir, EGRESS_PORT);

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
            b.closure_nar,
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
            runtime_overlay: b.runtime_overlay,
            console_log: state_dir.join("console.log"),
            agent_socket: Some(state_dir.join("agent.sock")),
            egress_socket: egress_socket.clone(),
            vcpus: b.vcpus,
            memory_mib: b.memory_mib,
        });

        let builder_policy = NetworkPolicy::trusted_build_egress();
        spawn_substitution_endpoint(SubstitutionSpawnParams {
            vm_name: b.name,
            state_dir: &state_dir,
            tenant: "builder",
            secrets: &[],
            redaction: &RedactionPolicy::default(),
            transport: EndpointTransport::Uds {
                path: egress_socket,
            },
            terminator_listen: None,
            tls_intermediate: None,
            network_policy: Some(&builder_policy),
            raw_egress: true,
            resolver_remote: None,
            binding_store_dir: None,
        })?;
        let mut endpoint_guard = EndpointGuard::new(b.name);

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
        endpoint_guard.defuse();
        Ok(BuilderOutcome {
            stopped,
            output_dir,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver::MockDriver;
    use mvm_core::util::test_env::TestEnv;

    /// The on-disk inputs a builder run reads, materialized under one
    /// tempdir.
    struct BuilderFixture {
        tmp: tempfile::TempDir,
        job: PathBuf,
        work: PathBuf,
        bins: PathBuf,
        kernel: PathBuf,
        rootfs: PathBuf,
        nix_store: PathBuf,
    }

    /// Materialize those inputs and point the substitution endpoint at a
    /// shell stub.
    ///
    /// The stub is not a convenience: without it the run spawns the real
    /// `mvm-substitution-endpoint`, which is an `mvm-hostd` binary. A
    /// package-scoped `cargo nextest run -p mvm-runtime` never builds it,
    /// so a test that omits the stub passes only when something else in
    /// the same target dir happened to build another package's binary.
    fn builder_fixture(env: &mut TestEnv) -> BuilderFixture {
        let tmp = tempfile::tempdir().unwrap();
        env.set("MVM_HOME", tmp.path());

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

        // A well-formed ready handshake: the spawner parses this line and
        // fails closed on anything else, so a stub that printed prose would be
        // testing a shape production never produces.
        let stub = tmp.path().join("stub-endpoint.sh");
        std::fs::write(
            &stub,
            "#!/bin/sh\ncat >/dev/null\necho '{\"env\":[],\"input_fingerprints\":[]}'\nsleep 30\n",
        )
        .unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        env.set("MVM_SUBSTITUTION_ENDPOINT_PATH", &stub);

        BuilderFixture {
            tmp,
            job,
            work,
            bins,
            kernel,
            rootfs,
            nix_store,
        }
    }

    #[test]
    fn build_packs_inputs_boots_the_builder_spec_and_extracts_the_output() {
        let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut env = TestEnv::new();
        let fx = builder_fixture(&mut env);
        let tmp = &fx.tmp;

        // Reap the endpoint this test spawns. `build` defuses its own guard on
        // success, because in production the endpoint outlives the build and is
        // reaped by the stop path — but a test has no stop path, so without a
        // guard of its own the stub survives the run. It does not even reach its
        // `sleep 30`: it blocks in `cat >/dev/null` waiting for an stdin EOF
        // that never comes, so the leak is permanent rather than brief. Held as
        // a guard rather than reaped at the end of the test so a panicking
        // assertion cannot skip it.
        let _endpoint = EndpointGuard::new("bld-unit");

        // A run-to-completion builder: the mock VM reports Stopped so the
        // poll-until-off loop returns at once.
        let runner = BuilderRunner::new(MockDriver::default().reporting_status(VmStatus::Stopped));
        let outcome = runner
            .build(&BuilderBuild {
                name: "bld-unit",
                kernel: &fx.kernel,
                rootfs: &fx.rootfs,
                nix_store: &fx.nix_store,
                job_dir: &fx.job,
                work_src: &fx.work,
                host_bin_dir: &fx.bins,
                runtime_overlay: None,
                closure_nar: None,
                output_size: 1 << 20,
                vcpus: 2,
                memory_mib: 1024,
            })
            .expect("build orchestrates against the mock driver");

        assert!(outcome.stopped);
        // A single builder spec was booted: 4 disks and the builder cmdline.
        let specs = runner.driver.booted_specs();
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].blocks.len(), 4);
        assert!(specs[0].cmdline.contains("init=/sbin/mvm-host-vm-init"));
        // The input disk was packed and the output extracted (empty tar from the
        // mock guest, which writes nothing).
        assert!(tmp.path().join("vms/bld-unit/input.img").exists());
        assert!(outcome.output_dir.exists());
    }

    #[test]
    fn build_rides_the_closure_nar_on_the_same_input_disk_when_present() {
        // Attaching a seeded closure must never grow the disk layout — it
        // rides inside the existing input.img tar, so the builder spec still
        // boots exactly 4 disks.
        let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut env = TestEnv::new();
        let fx = builder_fixture(&mut env);
        let tmp = &fx.tmp;
        let closure = tmp.path().join("nix-closure.nar");
        std::fs::write(&closure, b"pretend-nar-bytes").unwrap();

        // See the sibling test: `build` defuses its own guard on success, so
        // without one here the stub endpoint outlives the run permanently.
        let _endpoint = EndpointGuard::new("bld-closure");

        let runner = BuilderRunner::new(MockDriver::default().reporting_status(VmStatus::Stopped));
        let outcome = runner
            .build(&BuilderBuild {
                name: "bld-closure",
                kernel: &fx.kernel,
                rootfs: &fx.rootfs,
                nix_store: &fx.nix_store,
                job_dir: &fx.job,
                work_src: &fx.work,
                host_bin_dir: &fx.bins,
                runtime_overlay: None,
                closure_nar: Some(&closure),
                output_size: 1 << 20,
                vcpus: 2,
                memory_mib: 1024,
            })
            .expect("build orchestrates against the mock driver");

        assert!(outcome.stopped);
        assert_eq!(runner.driver.booted_specs()[0].blocks.len(), 4);

        // Extract the packed input disk directly to confirm the closure NAR
        // landed under closure-seed/ alongside job/work/mvm-bins.
        let extracted = tmp.path().join("extracted-input");
        mvm_build::builder_disk_transport::read_output_disk(
            &tmp.path().join("vms/bld-closure/input.img"),
            &extracted,
        )
        .unwrap();
        assert_eq!(
            std::fs::read(extracted.join("closure-seed/nix-closure.nar")).unwrap(),
            b"pretend-nar-bytes"
        );
    }
}
