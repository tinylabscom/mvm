//! libkrun-backed builder VM — Plan 71 W1.
//!
//! Replaces `MicrosandboxBuilderVm` on the user-facing path. Same
//! `BuilderVm` trait, same `BuilderJob` / `BuilderMounts` /
//! `BuilderArtifacts` shape, so call sites in `mvm-cli` keep working
//! once W5's cutover flips the polarity. v1 of this skeleton is
//! "compiles + unit-tests cleanly behind the `backends-builder-vm-libkrun`
//! feature flag; not yet a default backend." End-to-end smoke (W4
//! networking, W5 cutover) lands on a macOS Apple Silicon host where
//! libkrun can actually boot.
//!
//! ## Inner shape (per plan 71 §W1)
//!
//! `run_build`:
//!   1. Resolve the builder VM image (kernel + rootfs.ext4) via the
//!      `mvm-cli`-owned `ensure_builder_vm_image()` (lands with W5).
//!      For W1 we trust the caller to supply a path or `BuilderVmError::
//!      ImagePullFailed` out cleanly when missing.
//!   2. Allocate / locate the persistent `/nix` store image at
//!      `~/.cache/mvm/builder-vm/nix-store-<arch>.img` (sparse, default
//!      64 GiB). First-build cost: format ext4; subsequent reuse.
//!   3. Stage the job dir at `~/.cache/mvm/builder-vm/jobs/<job-id>/`
//!      with `cmd.sh`, `env`, and an empty `result` file.
//!   4. Launch via `mvm_providers::libkrun::start_with_config(...)`
//!      with the workspace mounted at `/work` (RO), the artifact dir
//!      at `/out` (RW), the job dir at `/job` (RW), and the persistent
//!      `/nix` virtio-blk.
//!   5. Poll for power-off; time out at 30 min wall clock.
//!   6. Read `/job/result` for the exit code; validate the artifact
//!      dir contains the expected `vmlinux` + `rootfs.ext4`.
//!
//! W1 ships only the structural skeleton. The `run_build` body
//! intentionally bottoms out in `BuilderVmError::NotYetImplemented`
//! with a tracking pointer to plan 71 W4 (networking) / W5 (cutover)
//! — *not* `NotYetWired`, which is reserved for plan-57-territory
//! libkrun gaps. Per W1 acceptance: "no NotYetWired returns from any
//! path that this plan exercises" (anything the *libkrun crate*
//! returns is plan-57 territory and bubbles up).

#![cfg(feature = "backends-builder-vm-libkrun")]

use std::path::PathBuf;

use super::builder_vm::{
    BuilderArtifacts, BuilderJob, BuilderMounts, BuilderVm, BuilderVmError,
};

/// Default vCPU count for the libkrun builder VM. Tuned for "fast
/// enough to feel native on a developer laptop" without saturating
/// the host. Override via [`LibkrunBuilderVm::with_resources`].
pub const LIBKRUN_BUILDER_DEFAULT_CPUS: u8 = 4;

/// Default RAM for the libkrun builder VM, in MiB. Per plan 71 §W1.
pub const LIBKRUN_BUILDER_DEFAULT_MEMORY_MIB: u32 = 4096;

/// Default size of the persistent `/nix` store virtio-blk image, in
/// MiB. 64 GiB sparse — actual disk usage grows with the dev-image
/// closure. Per plan 71 §W1.
pub const LIBKRUN_BUILDER_DEFAULT_NIX_STORE_MIB: u32 = 65_536;

/// Sandbox-guest path the user's workspace is bind-mounted into.
/// Mirrors `BUILDER_GUEST_WORK_DIR` so flake refs constructed by
/// the call site (`path:/work/...`) resolve identically across both
/// builder backends.
pub use super::builder_vm::BUILDER_GUEST_WORK_DIR;

/// Sandbox-guest path artifacts get written into.
pub use super::builder_vm::BUILDER_GUEST_OUT_DIR;

/// Sandbox-guest path the per-job staging dir is mounted at. New for
/// the libkrun builder — microsandbox carried the job script inline
/// via `sandbox.shell()`. libkrun needs the script on disk in the
/// staged job dir.
pub const LIBKRUN_BUILDER_GUEST_JOB_DIR: &str = "/job";

/// Sandbox-guest path the persistent `/nix` virtio-blk is mounted at.
/// `mvm-builder-init` (W3) handles the bind from `/nix-store` to
/// `/nix` once the rootfs is up; this constant names the underlying
/// mount point.
pub const LIBKRUN_BUILDER_GUEST_NIX_STORE_DIR: &str = "/nix-store";

/// libkrun-backed builder VM.
///
/// Configuration only — `host_can_build` and `run_build` do the
/// actual work. v1 stores resource caps + a job-staging root; W5
/// adds image-cache lookup paths.
#[derive(Debug, Clone)]
pub struct LibkrunBuilderVm {
    pub vcpus: u8,
    pub memory_mib: u32,
    pub nix_store_mib: u32,
    /// Override for the per-job staging root. `None` means
    /// `~/.cache/mvm/builder-vm/jobs/`; tests use a tempdir.
    pub job_root: Option<PathBuf>,
}

impl Default for LibkrunBuilderVm {
    fn default() -> Self {
        Self {
            vcpus: LIBKRUN_BUILDER_DEFAULT_CPUS,
            memory_mib: LIBKRUN_BUILDER_DEFAULT_MEMORY_MIB,
            nix_store_mib: LIBKRUN_BUILDER_DEFAULT_NIX_STORE_MIB,
            job_root: None,
        }
    }
}

impl LibkrunBuilderVm {
    /// Override the default vCPU / memory pair.
    pub fn with_resources(mut self, vcpus: u8, memory_mib: u32) -> Self {
        self.vcpus = vcpus;
        self.memory_mib = memory_mib;
        self
    }

    /// Override the default persistent-nix-store size (MiB).
    pub fn with_nix_store_mib(mut self, mib: u32) -> Self {
        self.nix_store_mib = mib;
        self
    }

    /// Override the per-job staging root. Tests pass a tempdir; in
    /// production this stays `None` so the default
    /// `~/.cache/mvm/builder-vm/jobs/` applies.
    pub fn with_job_root(mut self, dir: impl Into<PathBuf>) -> Self {
        self.job_root = Some(dir.into());
        self
    }

    /// Resolve the directory the per-job staging trees live under.
    fn resolve_job_root(&self) -> Result<PathBuf, BuilderVmError> {
        if let Some(dir) = &self.job_root {
            return Ok(dir.clone());
        }
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .ok_or_else(|| BuilderVmError::ExtractionFailed(
                "HOME unset — cannot resolve default ~/.cache/mvm/builder-vm/jobs root".into(),
            ))?;
        Ok(home.join(".cache").join("mvm").join("builder-vm").join("jobs"))
    }
}

impl BuilderVm for LibkrunBuilderVm {
    /// libkrun is *the* builder backend for hosts without host Nix —
    /// the design assumes host_can_build returns `false` so callers
    /// always use the builder VM. Honoring a host Nix install is
    /// explicitly forbidden per `CLAUDE.md §"Host Nix is never used by
    /// mvmctl"`. Returning false unconditionally keeps that invariant
    /// from the trait level.
    fn host_can_build(&self) -> Result<bool, BuilderVmError> {
        Ok(false)
    }

    fn run_build(
        &self,
        job: &BuilderJob,
        mounts: &BuilderMounts,
    ) -> Result<BuilderArtifacts, BuilderVmError> {
        validate_mounts(mounts)?;
        let _job_id = job_id_for(job);
        let _job_root = self.resolve_job_root()?;
        // Plan 71 W1 ships only the trait skeleton + validation
        // helpers. The launch path (stage cmd.sh → libkrun
        // start_with_config → poll for poweroff → extract artifacts)
        // lands with W4 (network/vsock plumbing) and W5 (cutover).
        // Returning a typed error rather than a panic gives callers a
        // single grep target for the migration cutover. Once
        // `mvm_providers::libkrun::start` returns Ok, this body
        // becomes the real launch path.
        Err(BuilderVmError::NotYetImplemented)
    }
}

/// Validate `BuilderMounts` for the libkrun builder. Same checks the
/// microsandbox impl performs at call time; lifted into a free
/// function so tests can hit them without spinning up a VM.
///
/// Rules (mirrored from `microsandbox::run_build`'s preamble):
///   - `flake_src` must exist and be a directory.
///   - `artifact_out` must be a writable directory (or creatable —
///     callers are allowed to pass a not-yet-existing path; the
///     builder creates it before launch).
///   - Both paths must be UTF-8 (libkrun's C API takes `*const c_char`;
///     a non-UTF-8 path fails at the FFI boundary).
///   - `host_nix_store` is ignored: the libkrun builder uses its own
///     persistent virtio-blk for `/nix`, never the host's. Passing
///     `Some(...)` is a callee-level mistake; we reject loudly so the
///     caller fixes it rather than silently mismounting.
pub fn validate_mounts(mounts: &BuilderMounts) -> Result<(), BuilderVmError> {
    if !mounts.flake_src.exists() {
        return Err(BuilderVmError::ExtractionFailed(format!(
            "flake_src does not exist: {}",
            mounts.flake_src.display()
        )));
    }
    if !mounts.flake_src.is_dir() {
        return Err(BuilderVmError::ExtractionFailed(format!(
            "flake_src is not a directory: {}",
            mounts.flake_src.display()
        )));
    }
    if mounts.flake_src.to_str().is_none() {
        return Err(BuilderVmError::ExtractionFailed(format!(
            "flake_src contains non-UTF-8 bytes: {}",
            mounts.flake_src.display()
        )));
    }
    if mounts.artifact_out.to_str().is_none() {
        return Err(BuilderVmError::ExtractionFailed(format!(
            "artifact_out contains non-UTF-8 bytes: {}",
            mounts.artifact_out.display()
        )));
    }
    if mounts.host_nix_store.is_some() {
        return Err(BuilderVmError::ExtractionFailed(
            "BuilderMounts.host_nix_store is ignored by the libkrun builder \
             (the builder VM has its own persistent /nix virtio-blk per plan 71 §W1). \
             Pass `None`."
                .into(),
        ));
    }
    Ok(())
}

/// Compute a deterministic-within-process job id. Different from the
/// microsandbox sandbox-name helper: we don't include a timestamp,
/// because the job dir is rebuilt each run anyway — a stable id keeps
/// the cache structure inspectable from a shell.
pub fn job_id_for(job: &BuilderJob) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    job.flake_ref.hash(&mut h);
    job.attr_path.hash(&mut h);
    format!("mvm-libkrun-{:x}", h.finish())
}

/// Format the kernel cmdline the W2 builder VM image expects.
/// Returned as a single string per libkrun's C-API requirement.
/// Centralized here so W4 (network) and W5 (cutover) reference the
/// same value.
pub fn builder_kernel_cmdline() -> &'static str {
    // Mirrors plan 71 §W2 kernel cmdline. `console=hvc0` is the
    // libkrun virtio-console name (vs. firecracker's `ttyS0`); we
    // can't share with the firecracker dev-VM cmdline.
    "console=hvc0 root=/dev/vda ro rootfstype=ext4 init=/sbin/mvm-builder-init"
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn valid_job() -> BuilderJob {
        BuilderJob {
            flake_ref: "path:/work?dir=nix/images/builder-vm".into(),
            attr_path: "packages.aarch64-linux.default".into(),
        }
    }

    fn valid_mounts(tmp: &TempDir) -> BuilderMounts {
        let flake_src = tmp.path().join("workspace");
        let artifact_out = tmp.path().join("out");
        fs::create_dir_all(&flake_src).unwrap();
        // artifact_out can be created lazily by the builder; the
        // validator only checks UTF-8 on the path, not existence.
        BuilderMounts {
            flake_src,
            host_nix_store: None,
            artifact_out,
        }
    }

    #[test]
    fn default_resources_match_plan_71_w1() {
        let vm = LibkrunBuilderVm::default();
        assert_eq!(vm.vcpus, LIBKRUN_BUILDER_DEFAULT_CPUS);
        assert_eq!(vm.memory_mib, LIBKRUN_BUILDER_DEFAULT_MEMORY_MIB);
        assert_eq!(vm.nix_store_mib, LIBKRUN_BUILDER_DEFAULT_NIX_STORE_MIB);
    }

    #[test]
    fn with_resources_overrides_defaults() {
        let vm = LibkrunBuilderVm::default().with_resources(2, 2048);
        assert_eq!(vm.vcpus, 2);
        assert_eq!(vm.memory_mib, 2048);
    }

    #[test]
    fn with_nix_store_mib_overrides_default() {
        let vm = LibkrunBuilderVm::default().with_nix_store_mib(8192);
        assert_eq!(vm.nix_store_mib, 8192);
    }

    #[test]
    fn host_can_build_returns_false_unconditionally() {
        // CLAUDE.md §"Host Nix is never used by mvmctl": the libkrun
        // builder must never short-circuit to the host. The trait
        // method returns false even on a host that has nix on PATH.
        let vm = LibkrunBuilderVm::default();
        assert!(!vm.host_can_build().unwrap());
    }

    #[test]
    fn validate_mounts_rejects_missing_flake_src() {
        let tmp = TempDir::new().unwrap();
        let mounts = BuilderMounts {
            flake_src: tmp.path().join("nope-does-not-exist"),
            host_nix_store: None,
            artifact_out: tmp.path().join("out"),
        };
        let err = validate_mounts(&mounts).unwrap_err();
        assert!(
            err.to_string().contains("does not exist"),
            "got: {err}"
        );
    }

    #[test]
    fn validate_mounts_rejects_flake_src_that_is_a_file() {
        let tmp = TempDir::new().unwrap();
        let file = tmp.path().join("not-a-dir");
        fs::write(&file, b"").unwrap();
        let mounts = BuilderMounts {
            flake_src: file,
            host_nix_store: None,
            artifact_out: tmp.path().join("out"),
        };
        let err = validate_mounts(&mounts).unwrap_err();
        assert!(err.to_string().contains("not a directory"), "got: {err}");
    }

    #[test]
    fn validate_mounts_rejects_host_nix_store_set() {
        let tmp = TempDir::new().unwrap();
        let mut mounts = valid_mounts(&tmp);
        mounts.host_nix_store = Some(tmp.path().join("nix-store"));
        let err = validate_mounts(&mounts).unwrap_err();
        assert!(
            err.to_string().contains("host_nix_store is ignored"),
            "got: {err}"
        );
    }

    #[test]
    fn validate_mounts_accepts_valid_layout() {
        let tmp = TempDir::new().unwrap();
        let mounts = valid_mounts(&tmp);
        validate_mounts(&mounts).expect("valid layout");
    }

    #[test]
    fn job_id_is_deterministic_for_same_inputs() {
        let job = valid_job();
        let a = job_id_for(&job);
        let b = job_id_for(&job);
        assert_eq!(a, b);
        assert!(a.starts_with("mvm-libkrun-"));
    }

    #[test]
    fn job_id_differs_when_inputs_differ() {
        let mut a = valid_job();
        let mut b = valid_job();
        b.attr_path = "packages.x86_64-linux.default".into();
        assert_ne!(job_id_for(&a), job_id_for(&b));
        a.flake_ref = "path:/other".into();
        assert_ne!(job_id_for(&a), job_id_for(&b));
    }

    #[test]
    fn run_build_returns_not_yet_implemented_on_valid_input() {
        // W1 acceptance: the body bottoms out in NotYetImplemented
        // until W4 + W5 wire the launch path. Tests pin this so the
        // first PR that swaps the body in remembers to update the test.
        let tmp = TempDir::new().unwrap();
        let vm = LibkrunBuilderVm::default().with_job_root(tmp.path());
        let job = valid_job();
        let mounts = valid_mounts(&tmp);
        let err = vm.run_build(&job, &mounts).unwrap_err();
        assert!(matches!(err, BuilderVmError::NotYetImplemented));
    }

    #[test]
    fn run_build_propagates_mount_validation_failures() {
        let tmp = TempDir::new().unwrap();
        let vm = LibkrunBuilderVm::default().with_job_root(tmp.path());
        let job = valid_job();
        let mut mounts = valid_mounts(&tmp);
        // Make flake_src invalid post-construction.
        mounts.flake_src = tmp.path().join("does-not-exist");
        let err = vm.run_build(&job, &mounts).unwrap_err();
        assert!(matches!(err, BuilderVmError::ExtractionFailed(_)));
    }

    #[test]
    fn builder_kernel_cmdline_uses_libkrun_console() {
        let cmdline = builder_kernel_cmdline();
        // libkrun's macOS-Apple-Silicon console is hvc0, not ttyS0 —
        // sharing the firecracker dev-VM cmdline would land no console
        // output. Pin this so a future cmdline edit can't regress it.
        assert!(cmdline.contains("console=hvc0"));
        assert!(cmdline.contains("init=/sbin/mvm-builder-init"));
    }
}
