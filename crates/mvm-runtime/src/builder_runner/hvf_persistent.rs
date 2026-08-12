//! The HVF persistent builder VM: one long-lived guest that serves many builds
//! over vsock, instead of a fresh VM per `nix build`.
//!
//! This is the backend half of what makes concurrent builds possible. The Nix
//! store image is a genuinely exclusive resource — every backend attaches it
//! read-write and two guests mounting one ext4 corrupts it — so a second
//! `mvmctl build` can either queue for the image or dispatch into a VM that
//! already holds it. This type is that VM. Nix inside the guest parallelizes
//! derivations on its own, so one session serves several builds at once off a
//! single warm store.
//!
//! The store lock is held for the session's lifetime and released when the
//! handle is killed or waited on, which is what keeps the "one writer" rule
//! intact while the VM is up.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use mvm_build::builder_vm::{BuilderVmError, builder_vm_cache_dir};
use mvm_build::builder_vm_runtime::{
    DISPATCH_READY_MARKER, NixStoreImageLock, PERSISTENT_BUILDER_READY_TIMEOUT,
    acquire_nix_store_image_lock, stage_persistent_job_dir,
};
use mvm_core::config::{vm_hvf_vsock_port_socket_at, vm_state_dir};
use mvm_net::channel::GuestService;

use super::spec::{PersistentBuilderSpecInputs, persistent_builder_spec};
use crate::driver::traits::{RunningVm, VmmDriver};
use mvm_backends::driver::hvf::HvfDriver;

/// Default persistent nix-store disk size (MiB), matching the one-shot builder.
const DEFAULT_NIX_STORE_MIB: u32 = 64 * 1024;
const DEFAULT_VCPUS: u32 = 4;
const DEFAULT_MEMORY_MIB: u32 = 8 * 1024;

/// Poll interval while waiting for the guest to publish its dispatch listener.
const READY_POLL: Duration = Duration::from_millis(50);

/// Builder for a persistent HVF builder session.
///
/// The image (an HVF-bootable kernel plus a rootfs whose baked
/// `mvm-host-vm-init` speaks the dispatch protocol) is supplied by the caller,
/// same as [`HvfBuilderVm`](super::HvfBuilderVm).
pub struct HvfPersistentHostVm {
    kernel: PathBuf,
    rootfs: PathBuf,
    runtime_overlay: Option<PathBuf>,
    workspace_root: PathBuf,
    host_bin_dir: PathBuf,
    nix_store_mib: u32,
    vcpus: u32,
    memory_mib: u32,
}

impl HvfPersistentHostVm {
    /// A session rooted at `workspace_root`, which the guest sees at `/work`
    /// for the VM's lifetime, and `host_bin_dir`, which it sees at
    /// `/mvm-bins`.
    pub fn new(
        kernel: impl Into<PathBuf>,
        rootfs: impl Into<PathBuf>,
        workspace_root: impl Into<PathBuf>,
        host_bin_dir: impl Into<PathBuf>,
    ) -> Self {
        Self {
            kernel: kernel.into(),
            rootfs: rootfs.into(),
            runtime_overlay: None,
            workspace_root: workspace_root.into(),
            host_bin_dir: host_bin_dir.into(),
            nix_store_mib: DEFAULT_NIX_STORE_MIB,
            vcpus: DEFAULT_VCPUS,
            memory_mib: DEFAULT_MEMORY_MIB,
        }
    }

    pub fn with_runtime_overlay(mut self, overlay: impl Into<PathBuf>) -> Self {
        self.runtime_overlay = Some(overlay.into());
        self
    }

    pub fn with_resources(mut self, vcpus: u32, memory_mib: u32) -> Self {
        self.vcpus = vcpus;
        self.memory_mib = memory_mib;
        self
    }

    pub fn with_nix_store_mib(mut self, nix_store_mib: u32) -> Self {
        self.nix_store_mib = nix_store_mib;
        self
    }

    /// Boot the session and return once its dispatch loop is listening.
    ///
    /// `session_id` names the VM and its state dir. The caller owns id
    /// generation so the session record and the VM agree on it.
    pub fn start(&self, session_id: &str) -> Result<PersistentHvfSession> {
        if !self.workspace_root.is_dir() {
            bail!(
                "workspace_root {} is not a directory",
                self.workspace_root.display()
            );
        }
        if !self.host_bin_dir.is_dir() {
            bail!(
                "persistent builder host binary directory does not exist: {}",
                self.host_bin_dir.display()
            );
        }

        // Hold the store lock for the whole session: this VM is the one writer
        // for as long as it is up, which is exactly what lets other builds
        // dispatch into it rather than fight it for the image.
        let nix_store_lock = acquire_nix_store_image_lock(
            &builder_vm_cache_dir(),
            std::env::consts::ARCH,
            u64::from(self.nix_store_mib),
        )
        .map_err(|e: BuilderVmError| anyhow::anyhow!(e))
        .context("acquiring the nix-store image lock for the persistent builder")?;

        let vm_name = format!("mvm-persistent-builder-hvf-{session_id}");
        let state_dir = vm_state_dir(&vm_name);
        std::fs::create_dir_all(&state_dir)
            .with_context(|| format!("creating builder state dir {}", state_dir.display()))?;

        let job_dir = builder_vm_cache_dir().join("jobs").join(session_id);
        stage_persistent_job_dir(&job_dir)
            .map_err(|e: BuilderVmError| anyhow::anyhow!(e))
            .context("staging the dispatch marker")?;

        let spec = persistent_builder_spec(&PersistentBuilderSpecInputs {
            name: &vm_name,
            kernel: &self.kernel,
            rootfs: &self.rootfs,
            nix_store: nix_store_lock.path(),
            job_dir: &job_dir,
            workspace_root: &self.workspace_root,
            host_bin_dir: &self.host_bin_dir,
            runtime_overlay: self.runtime_overlay.as_deref(),
            console_log: state_dir.join("console.log"),
            egress_socket: socket_for(&state_dir, GuestService::Substitution),
            dispatch_socket: socket_for(&state_dir, GuestService::BuilderDispatch),
            builderd_socket: socket_for(&state_dir, GuestService::BuilderdControl),
            vcpus: self.vcpus,
            memory_mib: self.memory_mib,
        });

        let vm = HvfDriver::new()
            .boot(&spec)
            .context("booting the persistent HVF builder VM")?;

        let session = PersistentHvfSession {
            session_id: session_id.to_string(),
            state_dir,
            job_dir,
            vm,
            _nix_store_lock: nix_store_lock,
        };
        session.wait_until_dispatch_ready(PERSISTENT_BUILDER_READY_TIMEOUT)?;
        Ok(session)
    }
}

/// The host-side socket for one of the session's guest-listening ports.
fn socket_for(state_dir: &Path, service: GuestService) -> PathBuf {
    vm_hvf_vsock_port_socket_at(state_dir, service.port())
}

/// A live persistent builder session.
///
/// Holds the Nix store lock for as long as it exists: dropping, killing, or
/// waiting on the session releases it, and only then may another builder VM
/// attach the image.
pub struct PersistentHvfSession {
    session_id: String,
    state_dir: PathBuf,
    job_dir: PathBuf,
    vm: Box<dyn RunningVm>,
    /// Load-bearing despite the underscore: the guard's `Drop` releases the
    /// cross-process flock on the shared store image.
    _nix_store_lock: NixStoreImageLock,
}

impl PersistentHvfSession {
    /// Opaque session identifier, stable for the VM's lifetime.
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Per-VM state dir (vsock sockets, console log, pid file).
    pub fn state_dir(&self) -> &Path {
        &self.state_dir
    }

    /// Host dir bound at `/job`: where each dispatch is staged and its
    /// artifacts read back.
    pub fn job_dir(&self) -> &Path {
        &self.job_dir
    }

    /// Host socket the dispatch client dials to reach the guest's job loop.
    pub fn dispatch_socket_path(&self) -> PathBuf {
        socket_for(&self.state_dir, GuestService::BuilderDispatch)
    }

    /// Host socket for the resident builder daemon's typed control plane.
    pub fn builderd_socket_path(&self) -> PathBuf {
        socket_for(&self.state_dir, GuestService::BuilderdControl)
    }

    /// The supervisor process owning the VM, when the driver can name it.
    /// Recorded in the session record so a later `stop` can find it.
    pub fn supervisor_pid(&self) -> Option<u32> {
        self.vm.host_process_id()
    }

    /// Force-terminate the session. Releases the store lock with it.
    pub fn kill(self) -> Result<()> {
        self.vm.kill().context("killing the persistent builder VM")
    }

    /// Block until the VM exits.
    pub fn wait(&self) -> Result<()> {
        self.vm
            .wait()
            .map(|_| ())
            .context("waiting on the persistent builder VM")
    }

    /// Wait for the guest to publish `<job_dir>/dispatch.ready`.
    ///
    /// Fails fast if the VM dies first: without this the caller would wait the
    /// full readiness window on a guest that panicked seconds in, and then
    /// report a timeout rather than the boot failure that actually happened.
    fn wait_until_dispatch_ready(&self, timeout: Duration) -> Result<()> {
        let ready = self.job_dir.join(DISPATCH_READY_MARKER);
        let deadline = Instant::now() + timeout;
        while !ready.exists() {
            if !matches!(
                self.vm.status(),
                Ok(mvm_core::vm_backend::VmStatus::Running)
            ) {
                bail!(
                    "the persistent builder VM exited before its dispatch loop came up; \
                     see {}",
                    self.state_dir.join("console.log").display()
                );
            }
            if Instant::now() >= deadline {
                let _ = self.vm.kill();
                bail!(
                    "the persistent builder VM did not publish {} within {timeout:?}; killed. \
                     See {}",
                    ready.display(),
                    self.state_dir.join("console.log").display()
                );
            }
            std::thread::sleep(READY_POLL);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::util::test_env::TestEnv;

    #[test]
    fn control_sockets_follow_the_hvf_per_port_convention() {
        let state = Path::new("/state/mvm-persistent-builder-hvf-abc");
        assert_eq!(
            socket_for(state, GuestService::BuilderDispatch),
            mvm_core::config::vm_hvf_vsock_port_socket_at(
                state,
                GuestService::BuilderDispatch.port()
            )
        );
        // Dispatch and daemon control must not collapse onto one socket.
        assert_ne!(
            socket_for(state, GuestService::BuilderDispatch),
            socket_for(state, GuestService::BuilderdControl)
        );
    }

    #[test]
    fn start_refuses_a_workspace_that_is_not_a_directory() {
        let scratch = tempfile::tempdir().expect("scratch");
        let mut env = TestEnv::new();
        env.isolate_mvm_home(scratch.path());

        let missing = scratch.path().join("nope");
        let err = HvfPersistentHostVm::new(
            scratch.path().join("Image"),
            scratch.path().join("rootfs.ext4"),
            &missing,
            scratch.path(),
        )
        .start("s1")
        .map(|_| ())
        .expect_err("a missing workspace must fail before any VM is created");
        assert!(
            format!("{err}").contains("is not a directory"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn start_refuses_a_missing_host_binary_dir_before_taking_the_store_lock() {
        // Ordering matters: a validation failure must not leave the shared
        // store image locked by a process that then gives up.
        let scratch = tempfile::tempdir().expect("scratch");
        let mut env = TestEnv::new();
        env.isolate_mvm_home(scratch.path());

        let err = HvfPersistentHostVm::new(
            scratch.path().join("Image"),
            scratch.path().join("rootfs.ext4"),
            scratch.path(),
            scratch.path().join("no-bins"),
        )
        .start("s1")
        .map(|_| ())
        .expect_err("a missing host-bin dir must fail");
        assert!(
            format!("{err}").contains("host binary directory does not exist"),
            "unexpected error: {err}"
        );

        // The claim in this test's name: no store image, and so no lock, was
        // created on the way to that refusal. A validation failure that left
        // the shared image locked would block every other builder on the host.
        let cache = builder_vm_cache_dir();
        assert!(
            cache.starts_with(scratch.path()),
            "the cache dir must resolve inside the isolated home, or the \
             assertion below is vacuous: {}",
            cache.display()
        );
        let locks: Vec<_> = std::fs::read_dir(&cache)
            .map(|entries| {
                entries
                    .flatten()
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .filter(|name| name.ends_with(".lock"))
                    .collect()
            })
            .unwrap_or_default();
        assert!(
            locks.is_empty(),
            "refusal left lock files behind in {}: {locks:?}",
            cache.display()
        );
    }
}
