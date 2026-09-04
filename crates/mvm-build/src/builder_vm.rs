//! Linux builder VM bootstrap (libkrun-backed).
//!
//! On hosts that can't `nix build` Linux derivations natively (macOS,
//! Windows-via-WSL2, or Linux without the project builder boundary),
//! `mvmctl build` bootstraps a small Linux builder microVM from a
//! pinned OCI image, runs `nix build` inside it, and extracts the
//! resulting rootfs back to the host.
//!
//! ## Status
//!
//! **Scaffolding.** The contract types and the 6-step flow are
//! locked; the actual bootstrap (OCI pull + sandbox spawn + bind-mount
//! wiring + artifact extraction) lands in a follow-up wave. Today
//! every method returns [`BuilderVmError::NotYetImplemented`].
//! Callers can wire the dispatch and cover the error path in tests;
//! the data-plane fills in incrementally.
//!
//! ## Trust boundary
//!
//! The builder VM lives in a different trust zone than runtime VMs.
//! It pulls from network, runs arbitrary Nix derivations, and bind-
//! mounts the host's `/nix/store` for cache reuse. The runtime path's
//! "no OCI" non-goal does not apply to the builder: OCI is
//! deliberately acceptable here.

use std::path::{Path, PathBuf};

use mvm_core::build_env::ShellEnvironment;
use serde::{Deserialize, Serialize};

use crate::guest_libc::GuestLibc;
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
/// user's cache root.
pub const BUILDER_IMAGE_CACHE_SUBDIR: &str = "builder-image";

/// Mount layout for a builder sandbox.
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
    /// here. Extraction copies from this path back to the host's
    /// per-build artifact directory.
    pub artifact_out: PathBuf,
    /// Dir containing the mvm host-vm binaries extracted from
    /// mvmctl's embedded payload, mounted read-only at `/mvm-bins`
    /// inside the builder VM and exposed via
    /// `MVM_HOST_BIN_DIR=/mvm-bins` to the flake's `cmd.sh`.
    pub host_bin_dir: PathBuf,
    /// Source-checkout invariant. When `Some`, the build runs in
    /// "local-mvm override" mode: `flake_src` (mounted at
    /// `/work`) is the **mvm workspace**, this user flake is staged into
    /// the job dir, and `cmd.sh` builds it with `--override-input mvm
    /// path:/work/nix` so the workload resolves `mvm` from the in-repo
    /// checkout rather than GitHub. `None` keeps the legacy behavior:
    /// `flake_src` is the user flake and `mvm` resolves from its lock.
    pub staged_user_flake: Option<PathBuf>,
}

/// What the builder is asked to produce.
///
/// An enum so the same trait can dispatch both flake builds (`Flake`)
/// and the application-dependency install pipeline (`Install`). Each
/// variant pairs 1:1 with a [`BuilderArtifacts`] variant — see the
/// per-variant docs there for the expected outputs.
///
/// The `Install` variant is plumbing only: it's reserved here so the
/// install pipeline can land behavior changes against a stable shape,
/// and today every backend errors with
/// [`BuilderVmError::NotYetImplemented`] when it sees an `Install`
/// job.
///
/// `Serialize`/`Deserialize` + `#[serde(deny_unknown_fields)]` let
/// `BuilderJob` ride inside
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

    /// Application-dependency install pipeline. The builder VM reads a
    /// serialised install spec from `spec_path` (lockfile +
    /// source-root + ecosystem + gate), runs the corresponding package
    /// manager (`uv pip install --no-deps`, `pnpm install
    /// --frozen-lockfile`, …) inside the VM, seals the resulting volume
    /// with SBOM + fetch log + CVE + attestations, and emits a
    /// `result.json` next to the volume.
    ///
    /// **Today every backend errors with
    /// [`BuilderVmError::NotYetImplemented`] for this variant.**
    Install {
        /// Absolute host path to the install-spec JSON the builder
        /// VM reads at start-up. Today the orchestrator does not
        /// produce one.
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
        /// `runtime_meta.accessible`, populating the console gate.
        /// `None` means the flake didn't surface the field; callers
        /// default to `true` for backward compatibility (matching the
        /// console gate's own default).
        accessible: Option<bool>,
    },

    /// Output of a [`BuilderJob::Install`] run — a sealed deps
    /// volume on the host filesystem plus a structured result
    /// document. Today no backend constructs this variant.
    InstallVolume {
        /// Directory the builder VM sealed the application-deps
        /// volume into (content + SBOM + fetch log + CVE scan +
        /// attestations + meta). Caller hashes this with
        /// `mvm_sdk::compile::deps_audit::verify_sealed_volume` to
        /// derive the canonical `volume_hash`.
        volume_dir: PathBuf,
        /// JSON sidecar emitted by `mvm-host-vm-init` next to the
        /// volume describing the install outcome (exit code,
        /// installer stderr tail, timings).
        result_json_path: PathBuf,
    },
}

/// Filename for the sidecar manifest written next to a built
/// rootfs. Mirrors `passthru.mvm` from `mkGuest` so the runtime
/// path can populate `runtime_meta` without re-running
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
    /// Whether `mvmctl console` may attach. Drives the console gate.
    pub accessible: bool,
    /// Inverse of `accessible` — sealed images refuse exec/console.
    pub sealed: bool,
    /// Form of the entrypoint declaration: "shell", "command", or
    /// "services". Information; not load-bearing for runtime gates.
    pub entrypoint_kind: String,
    /// The argv PID 1 actually execs for this image, as the build path
    /// resolved it: `entrypoint.command` for a command-form mkGuest image,
    /// the interactive shell for the shell form, the image's own
    /// Entrypoint/Cmd for an OCI rootfs.
    ///
    /// Load-bearing, unlike [`Self::entrypoint_kind`]: the host has no way to
    /// read inside a materialized ext4, so this is the only place admission
    /// can learn what a workload will run before it runs it. Empty means the
    /// build path did not record one — an image built before the field
    /// existed, or one whose shape the builder could not resolve — and a
    /// caller gating on it must treat empty as *unknown*, never as safe.
    #[serde(default)]
    pub entrypoint_argv: Vec<String>,
    /// Init system in use; "busybox" today.
    pub init_system: String,
    /// Per-backend boot floor in milliseconds. Used by perf gates to
    /// flag regressions.
    pub expected_boot_ms: u32,
    /// Agent binary kind: "stub" (placeholder) or "real"
    /// (cross-compiled Rust). Production policies should require
    /// "real".
    pub agent_binary: String,
    /// Whether the entrypoint runs as a non-root uid.
    pub rootless_entrypoint: bool,
    /// Active hypervisor declaration.
    pub hypervisor: String,
    /// Whether the rootfs carries the `/mvm/runtime` bind-mount target
    /// and a mkGuest `/init` that prefers the overlay-resident
    /// agent/seccomp-apply/netinit.
    ///
    /// Set by mkGuest's `passthru.mvm.overlayAware = true`. Sidecars
    /// written *before* the field existed deserialize as `false` (via
    /// `serde(default)`), which the [`admit_runtime_overlay_contract`] gate
    /// refuses — those older cached templates have no `/mvm/runtime`
    /// mount point, so attaching the overlay disk to them would either
    /// fail or silently degrade.
    #[serde(default)]
    pub overlay_aware: bool,
    /// Whether the rootfs intentionally omits the baked
    /// `/usr/local/bin/mvm-guest-agent` + `mvm-guest-netinit` fallback and
    /// therefore depends on the runtime overlay contract for those binaries.
    #[serde(default)]
    pub runtime_lean: bool,
    /// Release line and version this image came from, e.g.
    /// `boot-image/v0.1.0`. Empty means the producer recorded none — an image
    /// built before the field existed, or a local build of a working tree that
    /// belongs to no published line.
    #[serde(default)]
    pub image_tag: String,
    /// How the bytes on disk were acquired: `built-local` or `fetched`.
    ///
    /// Written by whoever put the image in the cache, not by whoever built it
    /// originally — a published image is built by a Nix build somewhere, but
    /// from this host's point of view it arrived over the network, and that is
    /// the fact a misfiring build/fetch split needs to be readable from.
    /// Empty means unrecorded; never read it as either arm.
    #[serde(default)]
    pub source: String,
    /// RFC 3339 timestamp for when this cache entry was produced or acquired.
    /// Orders two otherwise-identical local builds. Empty when the producer
    /// had no clock — a hermetic Nix build deliberately has none.
    #[serde(default)]
    pub built_at: String,
    /// Host↔guest contract version this rootfs speaks. Zero means unrecorded,
    /// which is distinct from any real version and must not be read as one.
    #[serde(default)]
    pub protocol_version: u8,
    /// Commit whose `mk-guest.nix` produced this rootfs. Empty when the build
    /// ran from a source tree with no resolvable revision (a dirty or
    /// non-git flake input), which a Nix build cannot invent.
    #[serde(default)]
    pub generator_rev: String,
    /// The C library this rootfs is built against, read off its dynamic loader
    /// while the tree was still a directory.
    ///
    /// Load-bearing for the same reason as [`Self::entrypoint_argv`]: nothing
    /// on the host opens the ext4 once it exists, so a host-side decision that
    /// depends on the guest's libc can only be made from what was recorded
    /// here. The SDK host-services cdylib is such a decision — it is built for
    /// one libc, and a process under the other cannot load it at all.
    ///
    /// [`GuestLibc::Unknown`] covers both a sidecar written before this field
    /// existed and a tree whose loader was unrecognisable. Neither is a
    /// permissive default: a caller gating on this must refuse, not guess.
    #[serde(default)]
    pub libc: GuestLibc,
}

impl GuestSidecar {
    /// Path the sidecar lives at, given a directory containing the
    /// rootfs. Single source of truth for both writers and readers.
    pub fn path_in(dir: &Path) -> PathBuf {
        dir.join(SIDECAR_FILENAME)
    }

    /// Write the sidecar JSON to `dir/mvm-meta.json`. Creates the
    /// directory if missing. Errors propagate — sidecar writes are
    /// load-bearing for the console gate, unlike `runtime_meta::write`
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
    /// uses mkGuest's overlay-preferring `/init`). The admission gate
    /// consults this; see [`admit_runtime_overlay_contract`].
    pub fn is_overlay_aware(&self) -> bool {
        self.overlay_aware
    }

    /// Whether the rootfs intentionally depends on the runtime overlay for the
    /// agent/netinit pair instead of carrying a baked fallback.
    pub fn is_runtime_lean(&self) -> bool {
        self.runtime_lean
    }

    /// Sidecar for a rootfs materialized from an OCI image and made
    /// bootable by the mvm runtime injection (baked agent + netinit +
    /// `/mvm/runtime` mount point + overlay-preferring `/init`).
    ///
    /// An arbitrary OCI image ships none of the mvm runtime. The
    /// materialize path injects it, so the resulting rootfs is
    /// genuinely overlay-aware: the `/mvm/runtime` mount point exists
    /// and the injected `/init` prefers an overlay-resident agent when
    /// one is attached (Firecracker) and falls back to the baked agent
    /// otherwise (libkrun/HVF). `overlay_aware: true` is therefore an
    /// honest claim, not a gate bypass — only emit this sidecar once
    /// the injection has actually run.
    ///
    /// Posture: `sealed` selects the tier. A plain `run --image` guest is
    /// a dev/interactive surface, so it is `accessible` (console may attach)
    /// and not `sealed`. A `--prod` run boots a dm-verity-sealed rootfs, so
    /// it is `sealed` and **not** `accessible` — the console/exec gate and
    /// the agent-verb grant both read these fields and must see a sealed
    /// image refuse interactive access. The baked agent is the real
    /// cross-compiled binary, not the stub. `hypervisor` is left
    /// backend-neutral ("oci"): the materialized rootfs is cached and
    /// boots on any backend, so it can't honestly name one — and no
    /// gate reads this field (it is informational; only `accessible`
    /// drives a runtime decision).
    pub fn for_oci_run(name: &str, sealed: bool, runtime_lean: bool) -> Self {
        Self {
            name: name.to_string(),
            accessible: !sealed,
            sealed,
            entrypoint_kind: "command".to_string(),
            // The caller knows the image's resolved Entrypoint/Cmd, not this
            // constructor; `with_entrypoint_argv` is how it gets recorded.
            entrypoint_argv: Vec::new(),
            init_system: "busybox".to_string(),
            // Unknown for an arbitrary OCI image; not load-bearing
            // (perf gates only apply to the curated image set).
            expected_boot_ms: 0,
            agent_binary: "real".to_string(),
            // OCI images default to running as root unless the image
            // config says otherwise; the entrypoint runs under the
            // agent, which applies the configured uid.
            rootless_entrypoint: false,
            hypervisor: "oci".to_string(),
            overlay_aware: true,
            runtime_lean,
            // An arbitrary OCI image belongs to no mvm image line and carries
            // no mvm build provenance. Leave every provenance field
            // unrecorded rather than inventing one.
            image_tag: String::new(),
            source: String::new(),
            built_at: String::new(),
            protocol_version: 0,
            generator_rev: String::new(),
            // Read off the unpacked tree by the caller that still has it;
            // this constructor has only a name. `with_libc` records it.
            libc: GuestLibc::Unknown,
        }
    }

    /// Record the argv PID 1 will exec, so a host-side gate can see what the
    /// image runs without opening the ext4.
    #[must_use]
    pub fn with_entrypoint_argv(mut self, argv: Vec<String>) -> Self {
        self.entrypoint_argv = argv;
        self
    }

    /// Record the libc detected on the unpacked rootfs, for the same reason as
    /// [`Self::with_entrypoint_argv`]: it is observable only while the tree is
    /// a directory, and needed after it is not.
    #[must_use]
    pub fn with_libc(mut self, libc: GuestLibc) -> Self {
        self.libc = libc;
        self
    }

    /// Read the sidecar from a directory. Returns `Ok(None)` if the
    /// sidecar doesn't exist (older build artifacts; runtime path
    /// falls through to the default-accessible behavior). Errors only
    /// on malformed JSON.
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

/// What a builder backend can do on this host.
///
/// Deliberately declared rather than probed: probing Stage 0 means attempting
/// Stage 0, which is the twenty-minute operation the caller is trying to
/// decide about. Mirrors `VmCapabilities` on the workload seam.
///
/// Every field defaults to `false`, so a capability is opt-in and a backend
/// that forgets one under-promises rather than over-promises.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BuilderCapabilities {
    /// Whether [`BuilderVm::run_stage0`] is wired on this backend.
    ///
    /// `false` means Stage 0 refuses — the backend cannot bootstrap the
    /// steady-state builder VM from nothing. It says nothing about
    /// [`BuilderVm::run_build`], which a backend can serve perfectly well
    /// against an already-bootstrapped builder.
    pub stage0_bootstrap: bool,
    /// Whether [`BuilderVm::run_build`] serves [`BuilderJob::Install`] — the
    /// arm that installs a hash-pinned lockfile into a sealed dependency
    /// volume.
    ///
    /// Separate from `stage0_bootstrap` because the two gaps are independent
    /// and were being described by two different stale sentences: one said
    /// Stage 0 was "implemented for the libkrun backend only" after qemu had
    /// grown one, the other said the install pipeline "isn't wired for any
    /// backend yet" while libkrun and qemu both served it.
    pub dependency_install: bool,
}

/// Builder VM driver. Today this is a marker trait shape — the
/// concrete impl arrives with the bootstrap wave. Defining it now
/// lets call sites be wired against the future API and lets tests
/// cover the error path.
pub trait BuilderVm {
    /// Pull the OCI image (if not cached), spawn a sandbox with the
    /// given mounts, run `nix build` for the job, and extract
    /// artifacts to `mounts.artifact_out`.
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

    /// Stage 0 bootstrap. Boot a self-contained `RootDir` guest whose
    /// `entry_path` init reads `workspace_dir` (mounted `/work`),
    /// installs Nix, builds the steady-state builder VM kernel +
    /// `rootfs.ext4` into `artifact_out` (mounted `/out`) using the
    /// embedded host-vm binaries from `host_bin_dir` (mounted
    /// `/mvm-bins`), then powers off cleanly. On `Ok`, the caller
    /// validates + promotes the artifacts; this only asserts the
    /// supervisor exited 0.
    ///
    /// Lives on the trait — rather than as a libkrun-inherent method —
    /// so the orchestration dispatches Stage 0 through `&dyn BuilderVm`,
    /// the same seam `run_build` uses.
    ///
    /// Required, deliberately. This carried a default impl that returned
    /// "implemented for the libkrun backend only", and by the time anyone
    /// read it that was already false — qemu had grown a Stage 0 and the
    /// sentence had not been revisited. A default is what let that rot: a
    /// backend inherits it by saying nothing, so nothing forces the text to
    /// stay true and nothing forces a new backend's author to decide.
    ///
    /// With no default, adding a backend does not compile until it answers
    /// this question, and a backend that cannot Stage 0 refuses in its own
    /// impl, naming itself. Pair the refusal with
    /// [`BuilderCapabilities::stage0_bootstrap`] = `false` so callers can ask
    /// before they spend the boot finding out.
    fn run_stage0(
        &self,
        guest_root_dir: &Path,
        entry_path: &str,
        workspace_dir: &Path,
        artifact_out: &Path,
        host_bin_dir: &Path,
    ) -> Result<(), BuilderVmError>;

    /// What this backend can actually do on this host.
    ///
    /// The builder-side counterpart of `VmBackend::capabilities`, and required
    /// for the same reason: a caller has to be able to ask before it commits
    /// to a boot, and the builder auto-fallback needs a question it can answer
    /// without provoking the failure it is trying to avoid.
    fn capabilities(&self) -> BuilderCapabilities;

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
         builds run inside a builder VM the CLI launches directly. \
         Rebuild or restart the project builder VM before retrying."
    )]
    NotYetImplemented,

    /// Libkrun isn't installed or isn't on PATH.
    #[error("libkrun not available: {0}")]
    LibkrunUnavailable(String),

    /// A host VMM the operator explicitly asked for isn't available on
    /// this platform. Carries the requested label (e.g.
    /// `"linux-builder-vm"`, `"hvf"`) and an
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

    /// The builder-VM supervisor exited non-zero — the VM/VMM itself could not
    /// run the build (e.g. libkrun failing `KVM_SET_USER_MEMORY_REGION` on a
    /// host that can't map the guest's high-memory region). Distinct from
    /// [`NixBuildFailed`](Self::NixBuildFailed) — where the build *ran* and
    /// failed — so the builder dispatch can transparently fall back to another
    /// backend on a VMM-level failure without masking a genuine build error.
    #[error("supervisor exited with non-zero status ({exit_code}); guest stderr at {vm_state_dir}")]
    SupervisorExited {
        /// The supervisor process's non-zero exit code.
        exit_code: i32,
        /// Host path to the per-VM state dir holding the guest console/stderr.
        vm_state_dir: String,
    },

    /// The hvf builder VM could not run the build (boot / disk-transport /
    /// power-off-timeout failure) — a VMM-level failure that triggers the
    /// builder-backend fallback, distinct from a genuine `nix build` error.
    #[error("hvf builder VMM-level failure: {detail}")]
    HvfVmmFailed { detail: String },

    /// The persistent builder Nix store has a dangling/GC'd path — every build
    /// re-evals to the same missing path and fails identically, so builds
    /// appear to "loop". Distinguished from a generic build failure so
    /// the user gets the one-line recovery instead of an opaque nix error.
    #[error(
        "the builder VM's Nix store has a dangling/garbage-collected path — \
         a previous `nix-collect-garbage` removed a store path the cached builder \
         image still references, so every `mvmctl bootstrap` fails identically.\n\
         Recover with:\n    mvmctl cache repair\n\
         (or `rm -rf {cache_dir}`), then re-run `mvmctl bootstrap` — the builder \
         image rebuilds from scratch.\n\
         Inner nix error: {detail}\nFull log: {log_path}"
    )]
    DegradedBuilderStore {
        cache_dir: String,
        log_path: String,
        detail: String,
    },

    /// Artifact extraction failed (missing rootfs, permissions,
    /// extraction-dir issue).
    #[error("extracting artifacts from builder sandbox: {0}")]
    ExtractionFailed(String),

    /// Kernel-panic detected on the supervisor's console log.
    /// `Child::wait()` would otherwise block forever (libkrun's
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

    /// A lean (`runtimeLean`) builder VM requires the runtime overlay for its
    /// guest binaries — it bakes none — but the overlay could not be resolved
    /// or built. Booting without it silently strands the guest agent, so this
    /// fails closed. Distinct from a VMM-level failure: it is not
    /// backend-specific, so it surfaces unchanged with no auto-fallback.
    #[error("builder VM runtime overlay unavailable: {0}")]
    RuntimeOverlayUnavailable(String),

    /// The guest shut down via a halt instead of a clean power-off. The
    /// rootfs-backed builder kernel has no power-off method, so the guest's
    /// end-of-job `reboot(RB_POWER_OFF)` falls back to a halt (the console
    /// shows `Power off not available: System halted instead`). This is not a
    /// build failure on its own — the single-shot build paths treat it like a
    /// clean exit and defer to their fail-closed on-disk result. It surfaces as
    /// an error only for callers that gate completion on a separate console
    /// marker, where a halt without that marker does mean the build failed.
    #[error(
        "builder VM build failed — the guest halted ({halt_line}). Full console log: {console_log_path}"
    )]
    GuestHalted {
        /// The console line that classified the shutdown as a halt (the
        /// kernel's power-off-unavailable fallback banner). Captured verbatim
        /// minus the trailing newline.
        halt_line: String,
        /// Host-side path to the supervisor's console log, where the full guest
        /// output — including the build error above the halt banner — is
        /// preserved.
        console_log_path: String,
    },
}

/// `~/.mvm/cache/builder-vm/` (honors `MVM_HOME`) — the directory to clear
/// to recover a degraded builder store. Lives here (ungated) so the build
/// error path can name the recovery dir; the `builder-vm`-gated builder modules
/// delegate to this for a single source of truth.
pub fn builder_vm_cache_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(mvm_core::config::mvm_cache_dir()).join("builder-vm")
}

/// Detect nix's dangling-store-path signature in a build's stderr: a
/// `/nix/store/...` path the build references was garbage-collected, so the eval
/// fails with `error: path '/nix/store/<hash>...' does not exist`. Matched
/// precisely — a quoted `/nix/store/` path **and** "does not exist" on the same
/// line — so an unrelated "does not exist" (a user's missing source file) does
/// not trip the degraded-store recovery hint. Returns the matched line for the
/// error `detail`.
pub fn dangling_store_path_line(stderr: &str) -> Option<&str> {
    stderr.lines().find(|line| {
        line.contains("does not exist")
            && line.contains("/nix/store/")
            && (line.contains("path '") || line.contains("path \""))
    })
}

/// Outcome of a builder-store repair.
#[derive(Debug, Clone, serde::Serialize)]
pub struct BuilderStoreRepair {
    /// The builder-VM cache dir that was (or would be) cleared.
    pub path: String,
    /// Whether the dir existed (a fresh host has nothing to repair).
    pub existed: bool,
    /// Bytes that were (or, under `dry_run`, would be) freed.
    pub bytes_freed: u64,
    /// `true` when only reporting — nothing was removed.
    pub dry_run: bool,
}

/// Recover a degraded builder Nix store by removing the builder-VM cache
/// dir so the next `mvmctl bootstrap` / `build` cold-rebuilds it clean — the documented
/// `rm -rf ~/.mvm/cache/builder-vm` recovery as a first-class operation. The
/// whole dir goes (store image + per-VM dirs + job dirs): the store image is the
/// degraded piece, and the kernel/rootfs/jobs are all rebuildable. `dry_run`
/// reports what would be freed without deleting.
///
/// Intended to run when builds are FAILING on a dangling-store error, so there
/// is no healthy in-flight build to disturb — callers that auto-repair should
/// only do so after a [`BuilderVmError::DegradedBuilderStore`].
pub fn clear_builder_store(dry_run: bool) -> std::io::Result<BuilderStoreRepair> {
    clear_builder_store_at(&builder_vm_cache_dir(), dry_run)
}

/// The architecture tag used in cached builder artifact filenames
/// (`nix-store-<arch>.img`).
///
/// Lives here rather than in `libkrun_builder` because that module is gated
/// behind the `builder-vm` feature, and store recovery must work without it.
pub fn host_arch_tag() -> &'static str {
    if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else {
        "x86_64"
    }
}

/// Remove only the persistent Nix store image for `arch`, leaving the builder
/// kernel/rootfs, the Stage 0 seed, and the job dirs in place.
///
/// The narrow counterpart to [`clear_builder_store`]. When the store image
/// itself is the damaged piece — the kernel recorded ext4 errors on it — there
/// is no reason to also discard tens of gigabytes of intact, expensive-to-
/// rebuild builder images. The next build recreates the store from the seed.
pub fn clear_builder_store_image(dry_run: bool) -> std::io::Result<BuilderStoreRepair> {
    clear_builder_store_image_at(&builder_vm_cache_dir(), host_arch_tag(), dry_run)
}

/// [`clear_builder_store_image`] with an explicit dir — the unit-testable core.
pub fn clear_builder_store_image_at(
    dir: &std::path::Path,
    arch: &str,
    dry_run: bool,
) -> std::io::Result<BuilderStoreRepair> {
    let image = dir.join(format!("nix-store-{arch}.img"));
    let existed = image.exists();
    let bytes_freed = if existed {
        std::fs::metadata(&image).map(|m| m.len()).unwrap_or(0)
    } else {
        0
    };
    if existed && !dry_run {
        std::fs::remove_file(&image)?;
    }
    Ok(BuilderStoreRepair {
        path: image.display().to_string(),
        existed,
        bytes_freed,
        dry_run,
    })
}

/// [`clear_builder_store`] with an explicit dir — the unit-testable core.
pub fn clear_builder_store_at(
    dir: &std::path::Path,
    dry_run: bool,
) -> std::io::Result<BuilderStoreRepair> {
    let existed = dir.exists();
    let bytes_freed = if existed { dir_size_bytes(dir) } else { 0 };
    if existed && !dry_run {
        std::fs::remove_dir_all(dir)?;
    }
    Ok(BuilderStoreRepair {
        path: dir.display().to_string(),
        existed,
        bytes_freed,
        dry_run,
    })
}

/// Disk clearing the builder store would return. Shared with the CLI's cache
/// counters so repair and prune quote the same number for the same tree.
fn dir_size_bytes(dir: &std::path::Path) -> u64 {
    mvm_core::disk_usage::tree_bytes(dir)
}

/// Stub implementation. Every method returns
/// [`BuilderVmError::NotYetImplemented`]. Kept around for tests that
/// want a `BuilderVm` impl with deterministic error behavior;
/// production code uses [`crate::libkrun_builder::LibkrunBuilderVm`].
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

    fn run_stage0(
        &self,
        _guest_root_dir: &Path,
        _entry_path: &str,
        _workspace_dir: &Path,
        _artifact_out: &Path,
        _host_bin_dir: &Path,
    ) -> Result<(), BuilderVmError> {
        Err(BuilderVmError::VmmUnavailable {
            requested: "stage0-bootstrap".to_string(),
            reason: "the stub builder runs no VM; it exists so tests can hold a \
                     `BuilderVm` with deterministic errors."
                .to_string(),
        })
    }

    fn capabilities(&self) -> BuilderCapabilities {
        BuilderCapabilities::default()
    }
}

// ============================================================================
// VmBackendForBuilder — hypervisor-agnostic seam for the builder-VM helper.
//
// The smaller-than-VmBackend surface that a future `BuilderVmRuntime`
// helper builds on top of: today `LibkrunBuilderVm` does both the
// substrate orchestration (cmd.sh emission, /job/result parsing, panic
// detection, NixStoreImageLock, stderr-tail capture) and the
// hypervisor-specific spawn/wait. Lifting the substrate out behind this
// trait lets an additional backend reuse ~850 lines of orchestration
// code with only backend-side mount glue.
// ============================================================================

/// Per-run configuration the builder helper passes to the underlying
/// hypervisor. Hypervisor-agnostic — every builder backend consumes it
/// identically.
///
/// Resources (`vcpus`, `memory_mib`) are caller-supplied; the
/// backend's resource-cap check enforces a host-side ceiling.
/// The host's current wall clock as an `mvm.hostepoch=<unix_seconds>` cmdline
/// token. The libkrun + hvf builder VMMs expose no RTC, so the guest boots with a
/// ~1970 clock; PID 1 (`mvm-host-vm-init`) reads this token and seeds the wall
/// clock from it, otherwise a cold Nix store's HTTPS fetch fails cert validation
/// ("certificate is not yet valid"). Appended fresh at each launch so the clock
/// tracks real time, not a stale image constant.
pub use mvm_vmm::host::boot_config::builder_hostepoch_cmdline_token;

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
    /// vCPU count. The libkrun + HVF backends both refuse values
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

/// Legacy directory-mount request for a builder run. Current builders exchange
/// directory trees through the raw-tar disk transport and refuse this shape;
/// the type remains while the generic trait still carries the compatibility
/// parameter.
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
    /// console-log watcher caught one. None on a clean run.
    /// `Child::wait()` cannot detect a panicked libkrun guest, so the
    /// watcher tails the console log and kills the supervisor when it
    /// sees the banner.
    pub panic_line: Option<String>,
}

/// Hypervisor-agnostic primitive that a `BuilderVmRuntime` helper
/// builds on top of.
///
/// `LibkrunBuilderVm` (via the libkrun supervisor) implements this
/// trait; the shape stays hypervisor-agnostic so a future backend can
/// reuse it. The shared orchestration logic — cmd.sh emission,
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
/// ## Implementations
///
/// - `LibkrunBuilderBackend` — `mvm-build/src/libkrun_builder.rs`,
///   wraps `spawn_supervisor_and_wait` + `wait_with_panic_detector`.
pub trait VmBackendForBuilder: Send + Sync {
    /// Spawn the supervisor for a builder run, attach the given disks, and
    /// block until the guest exits. `mounts` is a compatibility seam that
    /// block-only backends refuse. Returns the exit info — exit code plus
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
    /// `File::open()` until the file appears.
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
    /// `BuilderVmRuntime` test suite can move this into a
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
        // The helper holds `&dyn VmBackendForBuilder`, so the trait
        // must be object-safe. This compiles only if it is.
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
/// `mvm_runtime::vm::runtime_meta::from_sidecar` can populate
/// `accessible` for the console gate.
///
/// Failure modes (all log+continue, never fail the build):
/// - Flake doesn't surface `passthru.mvm` (older mkGuest, third-
///   party flakes): query returns non-zero → log warning
/// - `nix` not on PATH: query errors → log warning
/// - JSON shape doesn't match `GuestSidecar` (drift between
///   mkGuest and our wire type): parse error → log warning
/// - Disk write fails: log warning
///
/// The consumer side defaults `accessible: true` when the
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

/// Admission gate — refuse to start a VM whose rootfs is not
/// overlay-aware.
///
/// Reads `mvm-meta.json` from `rootfs_dir` and inspects
/// `overlay_aware`. The rootfs is overlay-aware when the sidecar
/// exists and reports `overlay_aware: true`. Anything else fails:
///
/// - **Sidecar missing** → refuse. Either the build pipeline that
///   produced the rootfs predates the sidecar emit, or the
///   sidecar was deleted out from under us. Either way, attaching
///   a runtime overlay to an unknown rootfs is unsafe.
/// - **Sidecar present, `overlay_aware: false`** → refuse. This is
///   the older cached-template case: the rootfs has no
///   `/mvm/runtime` mount point, so the overlay disk has nowhere
///   to land. mkGuest's `/init` would either fail or silently
///   degrade to the baked-in agent path.
/// - **Sidecar malformed** → propagate. Same posture as
///   [`GuestSidecar::read_from_dir`].
///
/// The error message is wordy on purpose: an operator hitting this
/// gate needs the recovery path (rebuild with current mkGuest, or
/// drop the cached template) in one glance.
/// Admission gate for the runtime-overlay contract.
///
/// Requires both an overlay-aware and a runtime-lean rootfs: the overlay is the
/// single source of the guest binaries, so a rootfs still carrying a baked
/// agent/netinit pair could silently degrade back to it.
pub use mvm_vmm::host::runtime_meta::admit_runtime_overlay_contract;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dangling_store_line_matches_the_nix_gc_signature() {
        // The exact dangling-store signature (single-quoted /nix/store path + does not exist).
        let stderr = "building...\n\
             error: path '/nix/store/0ccnxa25whszw7mgbgyzdm4nqc0zwnm8-source/flake.nix' does not exist\n\
             error: build of '/nix/store/abc.drv' failed\n";
        let line = dangling_store_path_line(stderr).expect("should match");
        assert!(line.contains("0ccnxa25whszw7mgbgyzdm4nqc0zwnm8-source"));
        // Double-quoted nix path form also matches.
        assert!(
            dangling_store_path_line("error: path \"/nix/store/xyz-source\" does not exist")
                .is_some()
        );
    }

    #[test]
    fn dangling_store_line_ignores_unrelated_does_not_exist() {
        // A workload's own missing source file must NOT trip the degraded-store
        // recovery hint — no /nix/store path on the line.
        assert!(dangling_store_path_line("error: file 'src/main.rs' does not exist").is_none());
        // A /nix/store mention without "does not exist" is also not it.
        assert!(
            dangling_store_path_line("copying '/nix/store/abc-foo' to the binary cache").is_none()
        );
        assert!(dangling_store_path_line("").is_none());
    }

    #[test]
    fn degraded_store_error_names_the_recovery_dir_and_command() {
        let e = BuilderVmError::DegradedBuilderStore {
            cache_dir: "/home/u/mvm-home/cache/builder-vm".into(),
            log_path: "/tmp/job/nix-stderr.log".into(),
            detail: "error: path '/nix/store/x-source/flake.nix' does not exist".into(),
        };
        let msg = e.to_string();
        assert!(msg.contains("mvmctl cache repair")); // the first-class recovery
        assert!(msg.contains("rm -rf /home/u/mvm-home/cache/builder-vm")); // manual fallback
        assert!(msg.contains("mvmctl bootstrap"));
        assert!(msg.contains("dangling")); // distinct from a generic build failure
    }

    #[test]
    fn builder_vm_cache_dir_honors_mvm_cache_dir() {
        // Reuse-first: the gated libkrun helper delegates here. Just assert the
        // path ends in builder-vm (env-isolated check would need a lock).
        assert!(builder_vm_cache_dir().ends_with("builder-vm"));
    }

    #[test]
    fn clear_builder_store_removes_the_dir_and_reports_bytes() {
        let tmp = tempfile::tempdir().unwrap();
        let store = tmp.path().join("builder-vm");
        std::fs::create_dir_all(store.join("vms/x")).unwrap();
        std::fs::write(store.join("nix-store.img"), vec![0u8; 4096]).unwrap();
        std::fs::write(store.join("vms/x/console.log"), vec![0u8; 100]).unwrap();

        // dry-run: reports freed bytes, removes nothing. The figure is the
        // disk a delete returns — allocated blocks, not the 4196 bytes the
        // two files hold.
        let dry = clear_builder_store_at(&store, true).unwrap();
        assert!(dry.existed && dry.dry_run);
        assert!(dry.bytes_freed >= 4196, "{}", dry.bytes_freed);
        assert!(store.exists(), "dry-run must not delete");

        // real: removes the dir, reports the same bytes.
        let done = clear_builder_store_at(&store, false).unwrap();
        assert!(done.existed && !done.dry_run);
        assert_eq!(done.bytes_freed, dry.bytes_freed);
        assert!(!store.exists(), "repair must remove the store dir");
    }

    #[test]
    fn clearing_only_the_store_image_keeps_the_expensive_builder_artifacts() {
        // The whole point: a damaged store image must not cost the intact
        // stage0 seed and builder images alongside it.
        let tmp = tempfile::tempdir().unwrap();
        let store = tmp.path().join("builder-vm");
        std::fs::create_dir_all(store.join("hvf")).unwrap();
        std::fs::write(store.join("nix-store-aarch64.img"), vec![0u8; 4096]).unwrap();
        std::fs::write(store.join("nix-store-stage0-aarch64.img"), vec![0u8; 512]).unwrap();
        std::fs::write(store.join("hvf/rootfs.ext4"), vec![0u8; 256]).unwrap();

        let dry = clear_builder_store_image_at(&store, "aarch64", true).unwrap();
        assert!(dry.existed && dry.dry_run);
        assert_eq!(dry.bytes_freed, 4096);
        assert!(
            store.join("nix-store-aarch64.img").exists(),
            "dry-run must not delete"
        );

        let done = clear_builder_store_image_at(&store, "aarch64", false).unwrap();
        assert!(done.existed && !done.dry_run);
        assert_eq!(done.bytes_freed, 4096);
        assert!(
            !store.join("nix-store-aarch64.img").exists(),
            "the damaged image goes"
        );
        assert!(
            store.join("nix-store-stage0-aarch64.img").exists(),
            "the stage0 seed must survive"
        );
        assert!(
            store.join("hvf/rootfs.ext4").exists(),
            "builder images must survive"
        );
    }

    #[test]
    fn clearing_a_store_image_that_is_absent_is_a_noop() {
        let tmp = tempfile::tempdir().unwrap();
        let store = tmp.path().join("builder-vm");
        std::fs::create_dir_all(&store).unwrap();
        let r = clear_builder_store_image_at(&store, "aarch64", false).unwrap();
        assert!(!r.existed && r.bytes_freed == 0);
    }

    #[test]
    fn clear_builder_store_is_a_noop_when_absent() {
        let tmp = tempfile::tempdir().unwrap();
        let store = tmp.path().join("builder-vm"); // never created
        let r = clear_builder_store_at(&store, false).unwrap();
        assert!(!r.existed && r.bytes_freed == 0);
    }

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
            staged_user_flake: None,
        };
        let err = stub.run_build(&job, &mounts).expect_err("stub returns err");
        assert!(matches!(err, BuilderVmError::NotYetImplemented));
    }

    #[test]
    fn stub_returns_not_yet_implemented_for_install_job() {
        // The Install variant is reserved plumbing; until its behavior
        // is wired, every backend (including the stub) must surface
        // NotYetImplemented for it.
        let stub = StubBuilderVm;
        let job = BuilderJob::Install {
            spec_path: PathBuf::from("/tmp/spec.json"),
        };
        let mounts = BuilderMounts {
            flake_src: PathBuf::from("/tmp/flake"),
            host_nix_store: None,
            artifact_out: PathBuf::from("/tmp/out"),
            host_bin_dir: PathBuf::from("/tmp/host-bins"),
            staged_user_flake: None,
        };
        let err = stub.run_build(&job, &mounts).expect_err("stub returns err");
        assert!(matches!(err, BuilderVmError::NotYetImplemented));
    }

    /// The declared capability has to match what the backend actually does.
    ///
    /// A matrix nothing checks is a decoration: `doctor` would report a
    /// backend as able to bootstrap while `run_stage0` refused, which is worse
    /// than not reporting at all because a user would trust it.
    #[test]
    fn a_backend_declaring_no_stage0_actually_refuses_it() {
        let stub = StubBuilderVm;
        assert!(!stub.capabilities().stage0_bootstrap);
        assert!(
            stub.run_stage0(
                Path::new("/tmp/root"),
                "/init",
                Path::new("/tmp/work"),
                Path::new("/tmp/out"),
                Path::new("/tmp/mvm-bins"),
            )
            .is_err(),
            "declared stage0_bootstrap=false but run_stage0 did not refuse"
        );
    }

    #[test]
    fn cleanup_default_is_ok() {
        // Stateless implementations get a free no-op cleanup.
        assert!(StubBuilderVm.cleanup().is_ok());
    }

    /// A backend that cannot Stage 0 refuses in its own impl and names itself.
    ///
    /// This replaces a test of the trait default, which asserted the refusal
    /// "names the supported backend" by looking for the word `libkrun`. That
    /// assertion passed for years after it stopped being true — qemu had
    /// implemented Stage 0 and the shared sentence still said libkrun was the
    /// only one. A refusal written by the backend that is refusing cannot
    /// drift that way, because there is no shared sentence to go stale.
    #[test]
    fn a_backend_without_stage0_refuses_and_names_itself() {
        let stub = StubBuilderVm;
        let err = stub
            .run_stage0(
                Path::new("/tmp/root"),
                "/init",
                Path::new("/tmp/work"),
                Path::new("/tmp/out"),
                Path::new("/tmp/mvm-bins"),
            )
            .expect_err("a backend without Stage 0 must fail closed");
        match err {
            BuilderVmError::VmmUnavailable { requested, reason } => {
                assert_eq!(requested, "stage0-bootstrap");
                assert!(
                    reason.contains("stub"),
                    "the refusal names the backend refusing: {reason}"
                );
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
            entrypoint_argv: Vec::new(),
            init_system: "busybox".to_string(),
            expected_boot_ms: 300,
            agent_binary: "stub".to_string(),
            rootless_entrypoint: false,
            hypervisor: "libkrun".to_string(),
            overlay_aware: true,
            runtime_lean: false,
            image_tag: String::new(),
            source: String::new(),
            built_at: String::new(),
            protocol_version: 0,
            generator_rev: String::new(),
            libc: GuestLibc::Glibc,
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

    /// A sidecar written before the provenance fields existed must keep
    /// deserializing. Asserted against a literal blob rather than a round-trip
    /// of the current struct: a round-trip serializes the new fields, so it
    /// would still pass with `#[serde(default)]` missing and prove nothing.
    #[test]
    fn an_old_sidecar_without_provenance_fields_still_deserializes() {
        let old = r#"{
            "name": "mvm-default-microvm",
            "accessible": false,
            "sealed": true,
            "entrypointKind": "command",
            "initSystem": "busybox",
            "expectedBootMs": 300,
            "agentBinary": "real",
            "rootlessEntrypoint": true,
            "hypervisor": "libkrun",
            "overlayAware": true
        }"#;

        let sidecar: GuestSidecar = serde_json::from_str(old).expect(
            "a sidecar predating the provenance fields must still deserialize; \
             every new field carries #[serde(default)]",
        );

        assert_eq!(sidecar.name, "mvm-default-microvm");
        assert_eq!(sidecar.image_tag, "");
        assert_eq!(sidecar.source, "");
        assert_eq!(sidecar.built_at, "");
        assert_eq!(sidecar.protocol_version, 0);
        assert_eq!(sidecar.generator_rev, "");
    }

    #[test]
    fn sidecar_read_missing_returns_none() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let result = GuestSidecar::read_from_dir(tmp.path()).expect("ok");
        assert!(result.is_none());
    }

    #[test]
    fn oci_run_sidecar_passes_overlay_aware_gate() {
        // The whole point of injecting the mvm runtime into an OCI
        // rootfs is that the resulting image admits honestly. Writing
        // the `for_oci_run` sidecar next to the rootfs must satisfy
        // `admit_runtime_overlay_contract` — without it, `run --image` never boots.
        let tmp = tempfile::tempdir().expect("tempdir");
        // `run_image` always writes the sidecar runtime-lean now: the overlay
        // is the single source of the guest binaries, so an injected rootfs
        // never carries a copy of them.
        let sidecar = GuestSidecar::for_oci_run("oci:sha256-deadbeef", false, true);
        assert!(sidecar.is_overlay_aware());
        assert!(sidecar.is_runtime_lean());
        assert_eq!(sidecar.agent_binary, "real");
        sidecar.write_to_dir(tmp.path()).expect("write");
        admit_runtime_overlay_contract(tmp.path()).expect("OCI-run rootfs must admit");
    }

    #[test]
    fn runtime_lean_oci_run_sidecar_admits_required_overlay() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let sidecar = GuestSidecar::for_oci_run("oci:sha256-deadbeef", true, true);
        assert!(sidecar.is_runtime_lean());
        sidecar.write_to_dir(tmp.path()).expect("write");
        admit_runtime_overlay_contract(tmp.path())
            .expect("runtime-lean OCI rootfs must admit required-overlay boots");
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
        assert!(body.contains("\"runtimeLean\""), "got: {body}");
        let read = GuestSidecar::read_from_dir(tmp.path())
            .expect("read")
            .expect("present");
        assert!(read.is_overlay_aware());
        assert!(!read.is_runtime_lean());
    }

    #[test]
    fn sidecar_missing_overlay_fields_deserialize_as_false() {
        // Older sidecars on disk don't carry `overlayAware` or `runtimeLean`.
        // `#[serde(default)]` must read them as `false` so the admission gate
        // refuses them rather than silently boot-attempting a non-overlay-aware
        // or non-runtime-lean rootfs.
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
        assert!(
            !read.is_runtime_lean(),
            "missing runtimeLean field must default to false"
        );
    }

    #[test]
    fn required_overlay_admission_refuses_non_runtime_lean_sidecar() {
        let tmp = tempfile::tempdir().expect("tempdir");
        fixture_sidecar().write_to_dir(tmp.path()).expect("write");
        let err = admit_runtime_overlay_contract(tmp.path())
            .expect_err("required-overlay rootfs must be runtime-lean");
        let msg = err.to_string();
        assert!(msg.contains("runtimeLean: true"), "got: {msg}");
    }

    #[test]
    fn required_overlay_admission_accepts_runtime_lean_sidecar() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let mut sidecar = fixture_sidecar();
        sidecar.runtime_lean = true;
        sidecar.write_to_dir(tmp.path()).expect("write");
        admit_runtime_overlay_contract(tmp.path()).expect("runtime-lean sidecar must admit");
    }

    #[test]
    fn admit_runtime_overlay_contract_refuses_missing_sidecar() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let err =
            admit_runtime_overlay_contract(tmp.path()).expect_err("missing sidecar must refuse");
        let msg = err.to_string();
        assert!(msg.contains("no `mvm-meta.json` sidecar"), "got: {msg}");
        assert!(msg.contains("predates W1.4b"), "got: {msg}");
    }

    #[test]
    fn admit_runtime_overlay_contract_refuses_pre_w14b_sidecar() {
        let tmp = tempfile::tempdir().expect("tempdir");
        // Write a sidecar with overlay_aware=false (mirrors an older
        // cached template or a sidecar that lost the field).
        let mut stale = fixture_sidecar();
        stale.overlay_aware = false;
        stale.write_to_dir(tmp.path()).expect("write stale");
        let err = admit_runtime_overlay_contract(tmp.path())
            .expect_err("overlay_aware: false must refuse");
        let msg = err.to_string();
        assert!(msg.contains("overlay_aware: false"), "got: {msg}");
        assert!(msg.contains("Rebuild the image"), "got: {msg}");
    }

    #[test]
    fn admit_runtime_overlay_contract_propagates_malformed_sidecar() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(tmp.path().join(SIDECAR_FILENAME), "{not valid json")
            .expect("write malformed");
        let err =
            admit_runtime_overlay_contract(tmp.path()).expect_err("malformed sidecar must error");
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
        // The accessible field is the console-gate wire — check it's present.
        assert!(body.contains("\"accessible\""), "got: {body}");
    }
}
