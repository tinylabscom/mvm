//! Linux builder VM bootstrap (libkrun-backed).
//!
//! Implements the contract documented in ADR-013 §"Linux builder via
//! libkrun (no Lima)": on hosts that can't `nix build` Linux
//! derivations natively (macOS, Windows-via-WSL2, or Linux without the
//! project builder boundary), `mvmctl build` bootstraps a small Linux builder microVM from
//! a pinned OCI image, runs `nix build` inside it, and extracts the
//! resulting rootfs back to the host.
//!
//! ## Status
//!
//! **Scaffolding.** The contract types and the 6-step flow are
//! locked; the actual bootstrap (OCI pull + sandbox spawn + bind-mount
//! wiring + artifact extraction) lands in a follow-up wave. Today
//! every method returns [`BuilderVmError::NotYetImplemented`] with a
//! pointer to the ADR section. Callers can wire the dispatch and
//! cover the error path in tests; the data-plane fills in
//! incrementally.
//!
//! ## Trust boundary
//!
//! The builder VM lives in a different trust zone than runtime VMs.
//! It pulls from network, runs arbitrary Nix derivations, and bind-
//! mounts the host's `/nix/store` for cache reuse. ADR-013's
//! "non-goal: OCI" applies to the **runtime** path; OCI is
//! deliberately *acceptable* for the builder. See
//! ADR-013 §"Linux builder via libkrun (no Lima)" for the
//! rationale.

use std::path::{Path, PathBuf};

use mvm_core::build_env::ShellEnvironment;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Pinned Nix-bearing OCI image. Bumped deliberately; the per-bump
/// audit (`xtask audit-flake` for flake inputs has a sister
/// `xtask audit-builder-image` that lands with the bootstrap impl)
/// re-checks the image's CVE surface.
///
/// `nixos/nix` is the upstream Nix project's image; we may switch to
/// a self-published image once we want to pin an exact substituter
/// configuration into the image rather than configure it at spawn
/// time.
pub const BUILDER_OCI_IMAGE: &str = "docker.io/nixos/nix:2.24.10";

/// SHA-256 digest the bootstrap verifies against after pull.
/// Empty until the bootstrap impl pins the digest in CI; an empty
/// expected-digest means "skip verification" (dev-only).
pub const BUILDER_OCI_DIGEST_SHA256: &str = "";

/// Cache directory for the pulled builder image, relative to the
/// user's cache root. Matches ADR-013 §"Linux builder…" step 2.
pub const BUILDER_IMAGE_CACHE_SUBDIR: &str = "builder-image";

/// Mount layout for a builder sandbox. ADR-013 step 3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuilderMounts {
    /// User's flake source. Bind-mounted read-only at `/work`.
    pub flake_src: PathBuf,
    /// Host's `/nix/store`. Bind-mounted read-write at `/nix` so
    /// builds populate the cache and subsequent builds reuse it.
    /// `None` means "use a fresh in-sandbox store" (slower; first
    /// build pulls everything from substituters).
    pub host_nix_store: Option<PathBuf>,
    /// Writable artifact extraction directory. Bind-mounted at
    /// `/out`; the builder writes the rootfs + metadata sidecar
    /// here. ADR-013 step 5 extracts from this path back to the
    /// host's per-build artifact directory.
    pub artifact_out: PathBuf,
    /// Plan 115 / ADR-065: dir containing the mvm host-vm binaries
    /// extracted from mvmctl's embedded payload, mounted read-only at
    /// `/mvm-bins` inside the builder VM and exposed via
    /// `MVM_HOST_BIN_DIR=/mvm-bins` to the flake's `cmd.sh`.
    pub host_bin_dir: PathBuf,
}

/// What the builder is asked to produce.
///
/// Plan 73 Followup B.2.0 generalised this from a single nix-build
/// shape into an enum so the same trait can dispatch both the
/// existing flake builds (`Flake`) and the application-dependency
/// install pipeline (`Install`) that Followup B.2 will wire. Each
/// variant pairs 1:1 with a [`BuilderArtifacts`] variant — see the
/// per-variant docs there for the expected outputs.
///
/// This is plumbing only: the `Install` variant is reserved here so
/// B.2 can land behavior changes against a stable shape, and today
/// every backend errors with [`BuilderVmError::NotYetImplemented`]
/// when it sees an `Install` job.
///
/// `Serialize`/`Deserialize` + `#[serde(deny_unknown_fields)]` were
/// added by Plan 89 W2 so `BuilderJob` can ride inside
/// [`crate::builder_protocol::HostVmRequest::Run`] over the
/// vsock-framed dispatch channel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum BuilderJob {
    /// Build a Nix flake attribute. The flake attribute path is
    /// system-specific; callers map host architecture to the
    /// matching Linux system (`aarch64-linux` on Apple Silicon,
    /// `x86_64-linux` on Intel/AMD).
    Flake {
        /// Flake reference (e.g. `git+file:///work?dir=.`, `.#default`,
        /// `path:./.`).
        flake_ref: String,
        /// Attribute path under the flake (e.g.
        /// `packages.x86_64-linux.tenant-worker`). Resolved by callers
        /// before invoking the builder.
        attr_path: String,
    },

    /// Application-dependency install pipeline (ADR-047, Followup
    /// B.2). The builder VM reads a serialised install spec from
    /// `spec_path` (lockfile + source-root + ecosystem + gate),
    /// runs the corresponding package manager (`uv pip install
    /// --no-deps`, `pnpm install --frozen-lockfile`, …) inside the
    /// VM, seals the resulting volume with SBOM + fetch log + CVE +
    /// attestations, and emits a `result.json` next to the volume.
    ///
    /// **Today every backend errors with
    /// [`BuilderVmError::NotYetImplemented`] for this variant.**
    /// Plan 73 Followup B.2 wires the libkrun backend; the
    /// libkrun backend never gets this variant.
    Install {
        /// Absolute host path to the install-spec JSON the builder
        /// VM reads at start-up. Followup B.2 defines the shape;
        /// today the orchestrator does not produce one.
        spec_path: PathBuf,
    },
}

/// Result of a successful build. The variant returned matches the
/// [`BuilderJob`] variant the caller passed: a `Flake` job yields
/// [`BuilderArtifacts::Image`]; an `Install` job yields
/// [`BuilderArtifacts::InstallVolume`].
///
/// Mirrors the host-backend's `BackendBuildResult` shape so the
/// runtime path can consume both transparently.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuilderArtifacts {
    /// Output of a [`BuilderJob::Flake`] build — a kernel +
    /// rootfs pair ready for boot, plus revision metadata.
    Image {
        /// Absolute host path to the extracted rootfs (typically
        /// `~/.mvm/dev/builds/<rev>/rootfs.ext4`).
        rootfs_path: PathBuf,
        /// Optional kernel image path (some flakes emit one; verity
        /// initramfs is paired with the kernel).
        kernel_path: Option<PathBuf>,
        /// Nix store revision hash (the leading `<hash>` segment of
        /// the derivation's output store path). Used as the artifact
        /// dir name and for cache lookups.
        revision_hash: String,
        /// `flake.lock` SHA-256, recorded for cache tracking.
        lock_hash: Option<String>,
        /// `passthru.mvm.accessible` — wires through to
        /// `runtime_meta.accessible`, populating the W6.2 console
        /// gate. `None` means the flake didn't surface the field;
        /// callers default to `true` for backward compatibility
        /// (W6.2's same default).
        accessible: Option<bool>,
    },

    /// Output of a [`BuilderJob::Install`] run — a sealed deps
    /// volume on the host filesystem plus a structured result
    /// document. Followup B.2 will fill this in; today no backend
    /// constructs this variant.
    InstallVolume {
        /// Directory the builder VM sealed the application-deps
        /// volume into (content + SBOM + fetch log + CVE scan +
        /// attestations + meta). Caller hashes this with
        /// `mvm_sdk::compile::deps_audit::verify_sealed_volume` to
        /// derive the canonical `volume_hash`.
        volume_dir: PathBuf,
        /// JSON sidecar emitted by `mvm-host-vm-init` next to the
        /// volume describing the install outcome (exit code,
        /// installer stderr tail, timings). Shape pinned by
        /// Followup B.2.
        result_json_path: PathBuf,
    },
}

/// Filename for the sidecar manifest written next to a built
/// rootfs. Mirrors `passthru.mvm` from `mkGuest` so the runtime
/// path can populate `runtime_meta` (W6.2) without re-running
/// `nix eval`. Living next to the rootfs keeps the sidecar
/// atomic with the artifact — a stale sidecar on the filesystem
/// without a matching rootfs is impossible.
pub const SIDECAR_FILENAME: &str = "mvm-meta.json";

/// mkGuest runtime sidecar (`mvm-meta.json`). Wire-format mirror of
/// `mkGuest`'s `passthru.mvm`. Build paths emit this; runtime paths
/// consume it.
///
/// Field names are camelCase to match the Nix passthru shape
/// directly — a future `nix eval --json` path can dump straight
/// into this struct.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GuestSidecar {
    /// Name from `mkGuest { name = …; }`.
    pub name: String,
    /// Whether `mvmctl console` may attach. Drives the W6.2 gate.
    pub accessible: bool,
    /// Inverse of `accessible` — sealed images refuse exec/console.
    pub sealed: bool,
    /// Form of the entrypoint declaration: "shell", "command", or
    /// "services". Information; not load-bearing for runtime gates.
    pub entrypoint_kind: String,
    /// Init system in use; "busybox" today (W5.1).
    pub init_system: String,
    /// Per-backend boot floor in milliseconds (ADR-013 §"Per-backend
    /// boot budgets"). Used by perf gates to flag regressions.
    pub expected_boot_ms: u32,
    /// Agent binary kind: "stub" (W6.1.1 placeholder) or "real"
    /// (W6.1.2 cross-compiled Rust). Production policies should
    /// require "real".
    pub agent_binary: String,
    /// Whether the entrypoint runs as a non-root uid.
    pub rootless_entrypoint: bool,
    /// Active hypervisor declaration.
    pub hypervisor: String,
    /// Plan 74 W2 / ADR-051 — whether the rootfs carries the
    /// `/mvm/runtime` bind-mount target and a mkGuest `/init` that
    /// prefers the overlay-resident agent/seccomp-apply/netinit.
    ///
    /// Set by mkGuest's `passthru.mvm.overlayAware = true` since
    /// W1.4b.3c. Sidecars written *before* the field existed
    /// deserialize as `false` (via `serde(default)`), which the
    /// [`admit_overlay_aware`] gate refuses — pre-W1.4b cached
    /// templates have no `/mvm/runtime` mount point, so attaching
    /// the overlay disk to them would either fail or silently
    /// degrade.
    #[serde(default)]
    pub overlay_aware: bool,
}

impl GuestSidecar {
    /// Path the sidecar lives at, given a directory containing the
    /// rootfs. Single source of truth for both writers and readers.
    pub fn path_in(dir: &Path) -> PathBuf {
        dir.join(SIDECAR_FILENAME)
    }

    /// Write the sidecar JSON to `dir/mvm-meta.json`. Creates the
    /// directory if missing. Errors propagate — sidecar writes are
    /// load-bearing for the W6.2 gate, unlike `runtime_meta::write`
    /// which is best-effort.
    pub fn write_to_dir(&self, dir: &Path) -> Result<PathBuf, std::io::Error> {
        std::fs::create_dir_all(dir)?;
        let path = Self::path_in(dir);
        let body = serde_json::to_string_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        std::fs::write(&path, format!("{body}\n"))?;
        Ok(path)
    }

    /// Whether the rootfs is overlay-aware (carries `/mvm/runtime` +
    /// uses mkGuest's overlay-preferring `/init`). Plan 74 W2
    /// admission gate consults this; see [`admit_overlay_aware`].
    pub fn is_overlay_aware(&self) -> bool {
        self.overlay_aware
    }

    /// Read the sidecar from a directory. Returns `Ok(None)` if the
    /// sidecar doesn't exist (pre-W7.x.1 build artifacts; runtime
    /// path falls through to the W6.2 default-accessible behavior).
    /// Errors only on malformed JSON.
    pub fn read_from_dir(dir: &Path) -> Result<Option<Self>, anyhow::Error> {
        let path = Self::path_in(dir);
        let body = match std::fs::read_to_string(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(anyhow::Error::new(e)),
        };
        let sidecar: Self = serde_json::from_str(&body)
            .map_err(|e| anyhow::anyhow!("parsing {}: {e}", path.display()))?;
        Ok(Some(sidecar))
    }
}

/// Builder VM driver. Today this is a marker trait shape — the
/// concrete impl arrives with the bootstrap wave. Defining it now
/// lets call sites be wired against the future API and lets tests
/// cover the error path.
pub trait BuilderVm {
    /// Steps 2-5 (ADR-013): pull the OCI image (if not cached),
    /// spawn a sandbox with the given mounts, run `nix build` for
    /// the job, and extract artifacts to `mounts.artifact_out`.
    /// Idempotent w.r.t. the image cache; not idempotent w.r.t. the
    /// artifact dir (caller cleans up).
    ///
    /// There is no host-Nix fallback. The CLAUDE.md invariant —
    /// *"Host Nix is never used by mvmctl, even when present"* —
    /// rules out a `host_can_build`-style probe: every Nix evaluation
    /// must go through a VM we launched, so we always take the
    /// builder-VM path.
    fn run_build(
        &self,
        job: &BuilderJob,
        mounts: &BuilderMounts,
    ) -> Result<BuilderArtifacts, BuilderVmError>;

    /// Stage 0 bootstrap (Plan 91 / ADR-068). Boot a self-contained
    /// `RootDir` guest whose `entry_path` init reads `workspace_dir`
    /// (mounted `/work`), installs Nix, builds the steady-state builder
    /// VM kernel + `rootfs.ext4` into `artifact_out` (mounted `/out`)
    /// using the embedded host-vm binaries from `host_bin_dir` (mounted
    /// `/mvm-bins`), then powers off cleanly. On `Ok`, the caller
    /// validates + promotes the artifacts; this only asserts the
    /// supervisor exited 0.
    ///
    /// Lives on the trait — rather than as a libkrun-inherent method —
    /// so the orchestration dispatches Stage 0 through `&dyn BuilderVm`,
    /// the same seam `run_build` uses. The default impl is a *fail-closed
    /// gap*: Stage 0 is implemented for the libkrun backend only today.
    /// Vz and Firecracker Stage 0 are tracked in ADR-068 §"Backend gaps"
    /// — a backend without an impl returns a clear error rather than
    /// silently doing nothing.
    fn run_stage0(
        &self,
        guest_root_dir: &Path,
        entry_path: &str,
        workspace_dir: &Path,
        artifact_out: &Path,
        host_bin_dir: &Path,
    ) -> Result<(), BuilderVmError> {
        let _ = (
            guest_root_dir,
            entry_path,
            workspace_dir,
            artifact_out,
            host_bin_dir,
        );
        Err(BuilderVmError::VmmUnavailable {
            requested: "stage0-bootstrap".to_string(),
            reason: "Stage 0 builder-VM bootstrap is implemented for the libkrun \
                     backend only; Vz and Firecracker Stage 0 are tracked in \
                     ADR-068 §\"Backend gaps\". Bootstrap with the libkrun builder \
                     backend."
                .to_string(),
        })
    }

    /// Tear down any persistent state (warm builder pool entries,
    /// pulled images older than N days, etc.). No-op for stateless
    /// implementations.
    fn cleanup(&self) -> Result<(), BuilderVmError> {
        Ok(())
    }
}

/// Errors from the builder VM.
#[derive(Debug, Error)]
pub enum BuilderVmError {
    /// Bootstrap is not implemented yet. Returned by the stub impl
    /// until the follow-up wave fills in the data plane.
    #[error(
        "libkrun-as-Linux-builder bootstrap is in flight; \
         the libkrun builder path does not use host Nix; \
         see ADR-013 §\"Linux builder via libkrun (no Lima)\" \
         for the design and Sprint 50 for the schedule. \
         Rebuild or restart the project builder VM before retrying."
    )]
    NotYetImplemented,

    /// Libkrun isn't installed or isn't on PATH.
    #[error("libkrun not available: {0}")]
    LibkrunUnavailable(String),

    /// Plan 100 W1 / Plan 105 — a host VMM the operator explicitly
    /// asked for isn't available on this platform. Carries the
    /// requested label (e.g. `"linux-builder-vm"`, `"vz"`) and an
    /// actionable hint pointing at the kernel-module parameter,
    /// platform-version gap, or install step the operator needs.
    #[error("{requested} is not available on this host: {reason}")]
    VmmUnavailable {
        /// Short tag identifying the VMM the operator requested
        /// (typically the env-var value or `--builder` flag value).
        requested: String,
        /// Operator-actionable explanation including the fix
        /// command or kernel parameter to enable.
        reason: String,
    },

    /// OCI image pull failed (network, registry auth, digest
    /// mismatch). Wraps the underlying error.
    #[error("OCI image pull failed: {0}")]
    ImagePullFailed(String),

    /// `nix build` returned non-zero inside the sandbox.
    #[error("nix build failed inside builder sandbox: {0}")]
    NixBuildFailed(String),

    /// Artifact extraction failed (missing rootfs, permissions,
    /// extraction-dir issue).
    #[error("extracting artifacts from builder sandbox: {0}")]
    ExtractionFailed(String),

    /// Plan 77 W6 — kernel-panic detected on the supervisor's console
    /// log. `Child::wait()` would otherwise block forever (libkrun's
    /// `krun_start_enter` doesn't notice a panicked guest), so a
    /// host-side watcher kills the supervisor and surfaces the
    /// captured banner line for diagnosis.
    #[error(
        "Stage 0 seed VM kernel-panicked during boot ({panic_line}); see {console_log_path} for the full kernel log"
    )]
    SeedKernelPanic {
        /// First matched line of the kernel panic (the `Kernel panic -
        /// not syncing: ...` banner). Captured verbatim minus the
        /// trailing newline.
        panic_line: String,
        /// Host-side path to the supervisor's console log, where the
        /// full pre- and post-panic kernel output is preserved.
        console_log_path: String,
    },
}

/// Stub implementation. Every method returns
/// [`BuilderVmError::NotYetImplemented`]. Kept around for tests that
/// want a `BuilderVm` impl with deterministic error behavior;
/// production code uses [`LibkrunBuilderVm`].
#[derive(Debug, Default, Clone, Copy)]
pub struct StubBuilderVm;

impl BuilderVm for StubBuilderVm {
    fn run_build(
        &self,
        _job: &BuilderJob,
        _mounts: &BuilderMounts,
    ) -> Result<BuilderArtifacts, BuilderVmError> {
        Err(BuilderVmError::NotYetImplemented)
    }
}

// ============================================================================
// VmBackendForBuilder — hypervisor-agnostic seam for the builder-VM helper.
//
// Plan 97 §"Phase C seam design". This trait is the smaller-than-VmBackend
// surface that a future `BuilderVmRuntime` helper builds on top of:
// today `LibkrunBuilderVm` does both the substrate orchestration (cmd.sh
// emission, /job/result parsing, panic detection, NixStoreImageLock,
// stderr-tail capture) and the hypervisor-specific spawn/wait. Lifting
// the substrate out behind this trait lets a future `VzBuilderVm`
// reuse ~850 lines of orchestration code with only a Vz-side mount
// glue (~600 lines).
//
// This commit lands the trait + supporting types only — no impls yet.
// Subsequent slices wire it for libkrun (port LibkrunBuilderVm) and
// Vz (new VzBuilderVm).
// ============================================================================

/// Per-run configuration the builder helper passes to the underlying
/// hypervisor. Hypervisor-agnostic — both libkrun and Vz consume it
/// identically. Plan 97 Phase C seam design §1.
///
/// Resources (`vcpus`, `memory_mib`) are caller-supplied; the
/// backend's resource-cap check enforces a host-side ceiling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuilderVmRunConfig {
    /// Human-readable VM name. Surfaces in logs + the per-VM state
    /// dir. Must be a valid mvm VM name (see `mvm_core::naming`).
    pub name: String,
    /// Absolute host path to the uncompressed Linux kernel.
    pub kernel_path: PathBuf,
    /// Kernel command line. Backend impls thread it onto their
    /// supervisor's boot loader unchanged.
    pub kernel_cmdline: String,
    /// Optional initrd path.
    pub initrd_path: Option<PathBuf>,
    /// vCPU count. The libkrun + Vz backends both refuse values
    /// above their host-determined caps.
    pub vcpus: u8,
    /// Guest memory in MiB.
    pub memory_mib: u32,
    /// Vsock ports the host wants to dial. Each becomes a per-port
    /// unix socket under `<vm_state_dir>/vsock/`.
    pub vsock_ports: Vec<u32>,
    /// Per-VM state directory. The backend creates it mode 0700 and
    /// writes its `<backend>.pid`, `console.log`, and vsock socket
    /// dir inside.
    pub vm_state_dir: PathBuf,
}

/// virtio-fs share to attach for the builder run. Maps onto
/// `libkrun_add_virtiofs` (libkrun) or
/// `VZVirtioFileSystemDeviceConfiguration` (Vz).
///
/// Builder mode is the *only* path that attaches virtio-fs shares
/// today; workload microVMs default to zero shares per Plan 97
/// §"Host-path mounts" and refuse unauthorised shares.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuilderVmMount {
    /// Symbolic mount tag the guest uses in `mount -t virtiofs <tag>
    /// <target>`. Convention: `/work`, `/out`, `/job`.
    pub tag: String,
    /// Host directory exported into the guest.
    pub host_path: PathBuf,
    /// Whether the share is mounted read-only inside the guest.
    pub read_only: bool,
}

/// Additional virtio-blk device beyond the rootfs (e.g. the
/// persistent Nix store image at `/dev/vdb`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuilderVmDisk {
    /// Stable identifier; surfaces in logs only.
    pub id: String,
    /// Host path to the raw disk image.
    pub host_path: PathBuf,
    /// Whether the device is read-only.
    pub read_only: bool,
}

/// Outcome of a single builder-VM run from the perspective of the
/// hypervisor-agnostic helper. The helper interprets this against
/// the job's expectations (`exit_code == 0` + no panic = success).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuilderVmExitInfo {
    /// Guest exit code (Some when the supervisor cleanly returned a
    /// status; None when the supervisor died before observing the
    /// guest exit — kernel panic, SIGKILL, etc.).
    pub exit_code: Option<i32>,
    /// First matched line of a kernel-panic banner if the host-side
    /// console-log watcher caught one. None on a clean run. Plan 77
    /// W6's panic-detector contract — `Child::wait()` cannot detect
    /// a panicked libkrun guest, so the watcher tails the console
    /// log and kills the supervisor when it sees the banner.
    pub panic_line: Option<String>,
}

/// Hypervisor-agnostic primitive that a `BuilderVmRuntime` helper
/// builds on top of. Plan 97 §"Phase C seam design".
///
/// Both `LibkrunBuilderVm` (today, via the libkrun supervisor) and
/// the future `VzBuilderVm` (via the `mvm-vz-supervisor`) implement
/// this trait. The shared orchestration logic — cmd.sh emission,
/// `/job/result` JSON parsing, `NixStoreImageLock`, kernel-panic
/// detection on the console log, stderr-tail capture — lives in the
/// helper and works against `&dyn VmBackendForBuilder` so it doesn't
/// know which VMM is on the other end.
///
/// ## Design rationale
///
/// `VmBackend` (in `mvm-core::vm_backend`) is the *workload* runtime
/// trait — single-shot `start` returning a `VmId`, async stop, etc.
/// The builder path needs a different shape: foreground spawn, block
/// until guest exits, return the exit info + panic line. Reusing
/// `VmBackend` would either bloat its surface or shoehorn the
/// builder semantics into ill-fitting methods. A dedicated trait
/// keeps both clean.
///
/// ## Implementations (planned)
///
/// - `LibkrunBuilderBackend` — `mvm-build/src/libkrun_builder.rs`,
///   wraps `spawn_supervisor_and_wait` + `wait_with_panic_detector`.
///   Lands in the next slice (PR-B).
/// - `VzBuilderBackend` — wraps `VzBackend::run_attached` with
///   builder-side virtio-fs share configuration. Lands in PR-C.
pub trait VmBackendForBuilder: Send + Sync {
    /// Spawn the supervisor for a builder run, attach the given
    /// virtio-fs shares + extra virtio-blk disks, and block until
    /// the guest exits. Returns the exit info — exit code plus
    /// optional panic line captured by the host-side console-log
    /// watcher.
    ///
    /// The supervisor must be killed if `timeout` elapses. Callers
    /// that want unbounded waits pass `Duration::MAX`.
    fn run_attached_with_mounts(
        &self,
        config: &BuilderVmRunConfig,
        mounts: &[BuilderVmMount],
        extra_disks: &[BuilderVmDisk],
        timeout: std::time::Duration,
    ) -> Result<BuilderVmExitInfo, BuilderVmError>;

    /// Host-side path of the supervisor's console capture file
    /// inside `vm_state_dir`. The panic-detector watcher in the
    /// helper tails this in real time. Returning a path that
    /// doesn't yet exist is fine — the supervisor creates it ~100 ms
    /// after spawn, and the watcher's poll loop retries
    /// `File::open()` until the file appears (Plan 77 W6).
    fn console_log_path(&self, vm_state_dir: &Path) -> PathBuf;
}

#[cfg(test)]
mod vm_backend_for_builder_tests {
    use super::*;
    use std::sync::Mutex;
    use std::time::Duration;

    /// Recorded args from a single `run_attached_with_mounts` call.
    /// Named so the mock's `invocations` Vec stays under the
    /// clippy::type_complexity threshold.
    type RecordedInvocation = (BuilderVmRunConfig, Vec<BuilderVmMount>, Vec<BuilderVmDisk>);

    /// Test mock — records every `run_attached_with_mounts` call and
    /// returns a programmable `BuilderVmExitInfo`. Exists in this
    /// module rather than as a workspace-level fixture so the trait
    /// is exercised at the point of definition. A future
    /// `BuilderVmRuntime` test suite (PR-B) can move this into a
    /// `pub(crate)` helper if reused.
    #[derive(Default)]
    struct MockBackend {
        scripted_exit: Option<BuilderVmExitInfo>,
        scripted_err: Option<BuilderVmError>,
        invocations: Mutex<Vec<RecordedInvocation>>,
    }

    impl VmBackendForBuilder for MockBackend {
        fn run_attached_with_mounts(
            &self,
            config: &BuilderVmRunConfig,
            mounts: &[BuilderVmMount],
            extra_disks: &[BuilderVmDisk],
            _timeout: Duration,
        ) -> Result<BuilderVmExitInfo, BuilderVmError> {
            self.invocations.lock().unwrap().push((
                config.clone(),
                mounts.to_vec(),
                extra_disks.to_vec(),
            ));
            if let Some(err) = &self.scripted_err {
                // Errors don't have an obvious Clone, so reconstruct
                // the specific cases the trait emits.
                return Err(match err {
                    BuilderVmError::NotYetImplemented => BuilderVmError::NotYetImplemented,
                    BuilderVmError::SeedKernelPanic {
                        panic_line,
                        console_log_path,
                    } => BuilderVmError::SeedKernelPanic {
                        panic_line: panic_line.clone(),
                        console_log_path: console_log_path.clone(),
                    },
                    other => BuilderVmError::ExtractionFailed(format!("mock: {other}")),
                });
            }
            Ok(self.scripted_exit.clone().unwrap_or(BuilderVmExitInfo {
                exit_code: Some(0),
                panic_line: None,
            }))
        }

        fn console_log_path(&self, vm_state_dir: &Path) -> PathBuf {
            vm_state_dir.join("console.log")
        }
    }

    fn fixture_config() -> BuilderVmRunConfig {
        BuilderVmRunConfig {
            name: "builder-test".to_string(),
            kernel_path: PathBuf::from("/tmp/vmlinux"),
            kernel_cmdline: "console=hvc0".to_string(),
            initrd_path: None,
            vcpus: 2,
            memory_mib: 1024,
            vsock_ports: vec![5252],
            vm_state_dir: PathBuf::from("/tmp/mvm-test/builder-test"),
        }
    }

    #[test]
    fn run_attached_records_config_mounts_and_disks() {
        let backend = MockBackend::default();
        let cfg = fixture_config();
        let mount = BuilderVmMount {
            tag: "/work".to_string(),
            host_path: PathBuf::from("/host/work"),
            read_only: true,
        };
        let disk = BuilderVmDisk {
            id: "nix-store".to_string(),
            host_path: PathBuf::from("/host/nix-store.img"),
            read_only: false,
        };

        let info = backend
            .run_attached_with_mounts(
                &cfg,
                std::slice::from_ref(&mount),
                std::slice::from_ref(&disk),
                Duration::from_secs(1),
            )
            .expect("default mock returns clean exit");
        assert_eq!(info.exit_code, Some(0));
        assert!(info.panic_line.is_none());

        let invocations = backend.invocations.lock().unwrap();
        assert_eq!(invocations.len(), 1);
        let (recorded_cfg, recorded_mounts, recorded_disks) = &invocations[0];
        assert_eq!(recorded_cfg, &cfg);
        assert_eq!(recorded_mounts.as_slice(), std::slice::from_ref(&mount));
        assert_eq!(recorded_disks.as_slice(), std::slice::from_ref(&disk));
    }

    #[test]
    fn console_log_path_lives_inside_state_dir() {
        let backend = MockBackend::default();
        let dir = PathBuf::from("/tmp/example/vms/foo");
        let p = backend.console_log_path(&dir);
        assert_eq!(p, dir.join("console.log"));
    }

    #[test]
    fn exit_info_carries_panic_line() {
        let backend = MockBackend {
            scripted_exit: Some(BuilderVmExitInfo {
                exit_code: None,
                panic_line: Some("Kernel panic - not syncing: VFS: Unable to mount root fs".into()),
            }),
            ..Default::default()
        };
        let info = backend
            .run_attached_with_mounts(&fixture_config(), &[], &[], Duration::from_secs(1))
            .expect("panic surfaces through the exit info, not an Err");
        assert_eq!(info.exit_code, None);
        assert!(info.panic_line.as_deref().unwrap().contains("Kernel panic"));
    }

    #[test]
    fn errors_propagate_through_the_trait() {
        let backend = MockBackend {
            scripted_err: Some(BuilderVmError::NotYetImplemented),
            ..Default::default()
        };
        let err = backend
            .run_attached_with_mounts(&fixture_config(), &[], &[], Duration::from_secs(1))
            .expect_err("scripted error propagates");
        assert!(matches!(err, BuilderVmError::NotYetImplemented));
    }

    #[test]
    fn mock_works_through_dyn_trait_object() {
        // The helper (PR-B) holds `&dyn VmBackendForBuilder`, so the
        // trait must be object-safe. This compiles only if it is.
        let backend: Box<dyn VmBackendForBuilder> = Box::new(MockBackend::default());
        let info = backend
            .run_attached_with_mounts(&fixture_config(), &[], &[], Duration::from_secs(1))
            .unwrap();
        assert_eq!(info.exit_code, Some(0));
    }
}

/// Resolve the host architecture's matching Linux system for flake
/// attribute construction. Mirrors `mvm-build/src/backend/host.rs`'s
/// `resolve_build_attribute_host`'s system selection.
pub fn host_system_linux() -> &'static str {
    if cfg!(target_arch = "aarch64") {
        "aarch64-linux"
    } else {
        "x86_64-linux"
    }
}

fn shell_quote(input: &str) -> String {
    format!("'{}'", input.replace('\'', "'\\''"))
}

/// Best-effort sidecar emission: query `passthru.mvm` against the
/// already-built flake/attr and write it to
/// `<build_dir>/mvm-meta.json` so the consumer in
/// `mvm::vm::runtime_meta::from_sidecar` can populate
/// `accessible` for the W6.2 console gate.
///
/// Failure modes (all log+continue, never fail the build):
/// - Flake doesn't surface `passthru.mvm` (older mkGuest, third-
///   party flakes): query returns non-zero → log warning
/// - `nix` not on PATH: query errors → log warning
/// - JSON shape doesn't match `GuestSidecar` (drift between
///   mkGuest and our wire type): parse error → log warning
/// - Disk write fails: log warning
///
/// The consumer side (W6.2) defaults `accessible: true` when the
/// sidecar is missing, so a logged warning here is the only
/// user-visible signal — the build still succeeds.
///
/// `dev_override` and `impure_flag` are passed through verbatim to
/// the underlying invocation so the dev path's `mvm` flake
/// override (which requires `--impure`) is honored. The mvmd /
/// orchestrated path passes empty strings.
pub fn emit_sidecar_via_passthru_query(
    env: &dyn ShellEnvironment,
    attr: &str,
    build_dir: &str,
    dev_override: &str,
    impure_flag: &str,
) {
    let passthru_attr = format!("{}.passthru.mvm", attr);
    let cmd = format!(
        "nix eval --json {}{}{}",
        shell_quote(&passthru_attr),
        impure_flag,
        dev_override,
    );
    let json = match env.shell_exec_stdout(&cmd) {
        Ok(s) => s,
        Err(e) => {
            env.log_warn(&format!(
                "sidecar: nix eval passthru.mvm failed (console gate stays accessible-by-default): {e}"
            ));
            return;
        }
    };
    let sidecar: GuestSidecar = match serde_json::from_str(json.trim()) {
        Ok(s) => s,
        Err(e) => {
            env.log_warn(&format!(
                "sidecar: passthru.mvm shape doesn't match GuestSidecar (mkGuest drift?): {e}"
            ));
            return;
        }
    };
    match sidecar.write_to_dir(Path::new(build_dir)) {
        Ok(path) => env.log_info(&format!("Wrote sidecar: {}", path.display())),
        Err(e) => env.log_warn(&format!("sidecar: write failed: {e}")),
    }
}

/// Plan 74 W2 / ADR-051 admission gate — refuse to start a VM whose
/// rootfs is not overlay-aware.
///
/// Reads `mvm-meta.json` from `rootfs_dir` and inspects
/// `overlay_aware`. The rootfs is overlay-aware when the sidecar
/// exists and reports `overlay_aware: true`. Anything else fails:
///
/// - **Sidecar missing** → refuse. Either the build pipeline that
///   produced the rootfs predates the sidecar emit (W6.2), or the
///   sidecar was deleted out from under us. Either way, attaching
///   a runtime overlay to an unknown rootfs is unsafe.
/// - **Sidecar present, `overlay_aware: false`** → refuse. This is
///   the pre-W1.4b cached-template case: the rootfs has no
///   `/mvm/runtime` mount point, so the overlay disk has nowhere
///   to land. mkGuest's `/init` would either fail or silently
///   degrade to the baked-in agent path.
/// - **Sidecar malformed** → propagate. Same posture as
///   [`GuestSidecar::read_from_dir`].
///
/// The error message is wordy on purpose: an operator hitting this
/// gate needs the recovery path (rebuild with current mkGuest, or
/// drop the cached template) in one glance.
pub fn admit_overlay_aware(rootfs_dir: &Path) -> Result<(), anyhow::Error> {
    let sidecar = GuestSidecar::read_from_dir(rootfs_dir)?;
    match sidecar {
        None => Err(anyhow::anyhow!(
            "refusing to start VM: rootfs at {} has no `mvm-meta.json` sidecar. \
             The build pipeline that produced this rootfs predates the W6.2 \
             sidecar emit, which means it also predates W1.4b runtime overlay \
             (no `/mvm/runtime` mount point in the rootfs). Rebuild the image \
             with current mkGuest, or drop the cached template.",
            rootfs_dir.display()
        )),
        Some(s) if !s.is_overlay_aware() => Err(anyhow::anyhow!(
            "refusing to start VM: rootfs at {} has `overlay_aware: false` \
             in its `mvm-meta.json` sidecar. Pre-W1.4b cached templates have \
             no `/mvm/runtime` mount point; attaching the runtime overlay disk \
             to them would either fail or silently degrade to the baked-in \
             agent. Rebuild the image with current mkGuest \
             (`passthru.mvm.overlayAware = true`).",
            rootfs_dir.display()
        )),
        Some(_) => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pinned_image_is_namespaced() {
        // Sanity: pinning a top-level image like `nix:2.24.10` is
        // ambiguous across registries. The constant must include the
        // registry + namespace.
        assert!(
            BUILDER_OCI_IMAGE.starts_with("docker.io/")
                || BUILDER_OCI_IMAGE.starts_with("ghcr.io/")
                || BUILDER_OCI_IMAGE.starts_with("registry."),
            "image must be fully qualified: {BUILDER_OCI_IMAGE}"
        );
        assert!(
            BUILDER_OCI_IMAGE.contains(':'),
            "image must carry a tag: {BUILDER_OCI_IMAGE}"
        );
    }

    #[test]
    fn host_system_is_linux() {
        let s = host_system_linux();
        assert!(s.ends_with("-linux"), "got {s}");
    }

    #[test]
    fn stub_returns_not_yet_implemented_for_run_build() {
        let stub = StubBuilderVm;
        let job = BuilderJob::Flake {
            flake_ref: ".".to_string(),
            attr_path: "packages.x86_64-linux.default".to_string(),
        };
        let mounts = BuilderMounts {
            flake_src: PathBuf::from("/tmp/flake"),
            host_nix_store: None,
            artifact_out: PathBuf::from("/tmp/out"),
            host_bin_dir: PathBuf::from("/tmp/host-bins"),
        };
        let err = stub.run_build(&job, &mounts).expect_err("stub returns err");
        assert!(matches!(err, BuilderVmError::NotYetImplemented));
    }

    #[test]
    fn stub_returns_not_yet_implemented_for_install_job() {
        // The B.2.0 plumbing reserves the Install variant; until B.2
        // wires behavior, every backend (including the stub) must
        // surface NotYetImplemented for it.
        let stub = StubBuilderVm;
        let job = BuilderJob::Install {
            spec_path: PathBuf::from("/tmp/spec.json"),
        };
        let mounts = BuilderMounts {
            flake_src: PathBuf::from("/tmp/flake"),
            host_nix_store: None,
            artifact_out: PathBuf::from("/tmp/out"),
            host_bin_dir: PathBuf::from("/tmp/host-bins"),
        };
        let err = stub.run_build(&job, &mounts).expect_err("stub returns err");
        assert!(matches!(err, BuilderVmError::NotYetImplemented));
    }

    #[test]
    fn cleanup_default_is_ok() {
        // Stateless implementations get a free no-op cleanup.
        assert!(StubBuilderVm.cleanup().is_ok());
    }

    #[test]
    fn run_stage0_default_is_a_documented_backend_gap() {
        // ADR-068: backends without a Stage 0 impl (Stub, and Vz until a
        // future slice) inherit the trait default — a fail-closed error
        // that names the gap and the recovery path, never a silent no-op
        // or a todo!() panic.
        let stub = StubBuilderVm;
        let err = stub
            .run_stage0(
                Path::new("/tmp/root"),
                "/init",
                Path::new("/tmp/work"),
                Path::new("/tmp/out"),
                Path::new("/tmp/mvm-bins"),
            )
            .expect_err("default Stage 0 impl must fail closed");
        match err {
            BuilderVmError::VmmUnavailable { requested, reason } => {
                assert_eq!(requested, "stage0-bootstrap");
                assert!(reason.contains("libkrun"), "names the supported backend");
                assert!(reason.contains("ADR-068"), "points at the tracking ADR");
            }
            other => panic!("unexpected error variant: {other}"),
        }
    }

    #[test]
    fn error_message_points_at_recovery_path() {
        let err = BuilderVmError::NotYetImplemented;
        let msg = err.to_string();
        assert!(msg.contains("libkrun builder") && msg.contains("does not use host Nix"));
    }

    fn fixture_sidecar() -> GuestSidecar {
        GuestSidecar {
            name: "test-vm".to_string(),
            accessible: true,
            sealed: false,
            entrypoint_kind: "shell".to_string(),
            init_system: "busybox".to_string(),
            expected_boot_ms: 300,
            agent_binary: "stub".to_string(),
            rootless_entrypoint: false,
            hypervisor: "libkrun".to_string(),
            overlay_aware: true,
        }
    }

    #[test]
    fn sidecar_write_then_read_round_trips() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let sidecar = fixture_sidecar();
        let path = sidecar.write_to_dir(tmp.path()).expect("write");
        assert_eq!(path, tmp.path().join(SIDECAR_FILENAME));
        let read = GuestSidecar::read_from_dir(tmp.path())
            .expect("read")
            .expect("present");
        assert_eq!(read, sidecar);
    }

    #[test]
    fn sidecar_read_missing_returns_none() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let result = GuestSidecar::read_from_dir(tmp.path()).expect("ok");
        assert!(result.is_none());
    }

    #[test]
    fn sidecar_read_malformed_errors() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(tmp.path().join(SIDECAR_FILENAME), "{not valid json")
            .expect("write malformed");
        let result = GuestSidecar::read_from_dir(tmp.path());
        assert!(result.is_err(), "malformed sidecar should error");
    }

    #[test]
    fn sidecar_overlay_aware_round_trips_camel_case() {
        // Field maps to `overlayAware` on disk (matches the
        // `passthru.mvm.overlayAware` Nix key one-to-one) so a
        // future `nix eval --json passthru.mvm` lands straight
        // into the struct.
        let tmp = tempfile::tempdir().expect("tempdir");
        fixture_sidecar().write_to_dir(tmp.path()).expect("write");
        let body = std::fs::read_to_string(tmp.path().join(SIDECAR_FILENAME)).expect("read raw");
        assert!(body.contains("\"overlayAware\""), "got: {body}");
        let read = GuestSidecar::read_from_dir(tmp.path())
            .expect("read")
            .expect("present");
        assert!(read.is_overlay_aware());
    }

    #[test]
    fn sidecar_missing_overlay_aware_field_deserializes_as_false() {
        // Pre-W1.4b sidecars on disk don't carry `overlayAware`.
        // `#[serde(default)]` must read them as `false` so the
        // admission gate refuses them rather than silently
        // boot-attempting a non-overlay-aware rootfs.
        let tmp = tempfile::tempdir().expect("tempdir");
        let legacy_json = r#"{
            "name": "legacy",
            "accessible": true,
            "sealed": false,
            "entrypointKind": "shell",
            "initSystem": "busybox",
            "expectedBootMs": 300,
            "agentBinary": "real",
            "rootlessEntrypoint": false,
            "hypervisor": "libkrun"
        }"#;
        std::fs::write(tmp.path().join(SIDECAR_FILENAME), legacy_json).expect("write legacy");
        let read = GuestSidecar::read_from_dir(tmp.path())
            .expect("legacy must parse")
            .expect("present");
        assert!(
            !read.is_overlay_aware(),
            "missing overlayAware field must default to false"
        );
    }

    #[test]
    fn admit_overlay_aware_accepts_w14b_sidecar() {
        let tmp = tempfile::tempdir().expect("tempdir");
        fixture_sidecar().write_to_dir(tmp.path()).expect("write");
        admit_overlay_aware(tmp.path()).expect("overlay_aware: true must admit");
    }

    #[test]
    fn admit_overlay_aware_refuses_missing_sidecar() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let err = admit_overlay_aware(tmp.path()).expect_err("missing sidecar must refuse");
        let msg = err.to_string();
        assert!(msg.contains("no `mvm-meta.json` sidecar"), "got: {msg}");
        assert!(msg.contains("predates W1.4b"), "got: {msg}");
    }

    #[test]
    fn admit_overlay_aware_refuses_pre_w14b_sidecar() {
        let tmp = tempfile::tempdir().expect("tempdir");
        // Write a sidecar with overlay_aware=false (mirrors a
        // pre-W1.4b cached template or a sidecar that lost the
        // field).
        let mut stale = fixture_sidecar();
        stale.overlay_aware = false;
        stale.write_to_dir(tmp.path()).expect("write stale");
        let err = admit_overlay_aware(tmp.path()).expect_err("overlay_aware: false must refuse");
        let msg = err.to_string();
        assert!(msg.contains("overlay_aware: false"), "got: {msg}");
        assert!(msg.contains("Rebuild the image"), "got: {msg}");
    }

    #[test]
    fn admit_overlay_aware_propagates_malformed_sidecar() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(tmp.path().join(SIDECAR_FILENAME), "{not valid json")
            .expect("write malformed");
        let err = admit_overlay_aware(tmp.path()).expect_err("malformed sidecar must error");
        // Error chain bubbles up from `read_from_dir`'s parse error;
        // we just assert it surfaces *some* parse-shaped message so
        // an operator can debug without guessing.
        assert!(format!("{err:#}").contains("parsing"), "got: {err:#}");
    }

    #[test]
    fn sidecar_uses_camel_case_on_disk() {
        // The on-disk format mirrors `passthru.mvm` so a future
        // `nix eval --json` path can dump straight into this struct.
        // Asserting the field names guards against accidental rename.
        let tmp = tempfile::tempdir().expect("tempdir");
        fixture_sidecar().write_to_dir(tmp.path()).expect("write");
        let body = std::fs::read_to_string(tmp.path().join(SIDECAR_FILENAME)).expect("read raw");
        assert!(body.contains("\"entrypointKind\""), "got: {body}");
        assert!(body.contains("\"expectedBootMs\""), "got: {body}");
        assert!(body.contains("\"agentBinary\""), "got: {body}");
        assert!(body.contains("\"rootlessEntrypoint\""), "got: {body}");
        // The accessible field is the W6.2 wire — check it's present.
        assert!(body.contains("\"accessible\""), "got: {body}");
    }
}
