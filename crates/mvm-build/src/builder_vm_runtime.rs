//! Hypervisor-agnostic builder-VM orchestration helper.
//!
//! `BuilderVmRuntime` is the shared orchestration body that both
//! the libkrun and HVF builder paths route through. It owns the
//! pieces that aren't tied to a specific VMM:
//!
//! - `cmd.sh` emission (Flake jobs) and `install_spec.json` staging
//!   (Install jobs)
//! - Filtered staging for disk-transport `/work` inputs
//! - `/job/result` JSON parsing
//! - Per-variant artifact finalisation (rootfs path resolution,
//!   revision hash extraction, install-volume sidecar discovery)
//! - Nix store image lock acquisition (libkrun-only concern in
//!   today's runtime; abstracted here for future HVF reuse)
//! - stderr-tail capture for build-failure diagnostics
//! - Wall-clock timeout handling
//!
//! It does **not** own:
//!
//! - Supervisor process lifecycle (lives in the
//!   `VmBackendForBuilder` impl — libkrun's
//!   `spawn_supervisor_in_background` / HVF's `run_attached`)
//! - Console-log watching for kernel-panic detection (also lives
//!   in the impl; surfaces through `BuilderVmExitInfo.panic_line`)
//! - Hypervisor-specific config translation (KrunContext vs.
//!   HVF's `SupervisorConfig`)

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use serde::Deserialize;

use crate::builder_vm::{BuilderArtifacts, BuilderJob, BuilderVmError, VmBackendForBuilder};
pub use crate::volume_image::{VolumeImageLock, ensure_persistent_volume_image};

/// Sparse allocation + cross-process locking for the persistent block
/// images a builder VM attaches. Re-exported below so callers keep
/// naming `builder_vm_runtime::acquire_nix_store_image_lock`.
mod image_lock;

pub use image_lock::{
    DEFAULT_LOCK_WAIT, LOCK_WAIT_ENV, LockWait, NixStoreImageLock, UnlockedStoreImage,
    acquire_nix_store_image_lock, acquire_nix_store_image_lock_named,
    ensure_nix_store_image_unlocked, hold_image_lock, nix_store_image_is_contended,
};
pub(crate) use image_lock::{
    acquire_sidecar_lock_within, pid_alive, sidecar_lock_path, sparse_create_image,
};

/// Wall-clock timeout for a builder VM run when the operator hasn't
/// overridden it. 30 minutes covers a cold-cache `nix build` of the
/// project's heaviest derivations on a fresh CI runner without
/// punishing fast machines.
pub const DEFAULT_BUILDER_VM_TIMEOUT: Duration = Duration::from_secs(30 * 60);

/// Filename of the marker the host stages under `<job_dir>/` to tell
/// `mvm-host-vm-init` to enter its dispatch loop instead of running the
/// single-shot `cmd.sh` / `install_spec` flow.
///
/// The guest hardcodes the same literal — it is a separate binary that cannot
/// depend on this crate — so the string is pinned on both sides. Backend-
/// agnostic: the marker is part of the guest contract, not of any one VMM.
pub const DISPATCH_SOCK_MARKER: &str = "dispatch.sock.marker";

/// Filename the guest creates after binding its dispatch listener. The host
/// waits for it before publishing a usable session record.
pub const DISPATCH_READY_MARKER: &str = "dispatch.ready";

/// How long a host waits for a persistent builder's dispatch loop to come up.
/// A first boot formats and seeds the persistent Nix disk before exposing the
/// listener, and that seed is a large closure copy, so the window has to cover
/// a cold disk as well as a warm boot.
pub const PERSISTENT_BUILDER_READY_TIMEOUT: Duration = Duration::from_secs(180);

/// Stage `<job_dir>/<DISPATCH_SOCK_MARKER>` so the in-guest
/// `mvm-host-vm-init` enters its dispatch loop, and clear any stale ready
/// marker from a previous session so the caller's readiness wait cannot
/// observe the last boot's.
///
/// The marker body is intentionally empty — its existence is the signal.
pub fn stage_persistent_job_dir(job_dir: &Path) -> Result<(), BuilderVmError> {
    std::fs::create_dir_all(job_dir).map_err(|e| {
        BuilderVmError::ExtractionFailed(format!(
            "creating persistent job dir {}: {e}",
            job_dir.display()
        ))
    })?;
    let marker_path = job_dir.join(DISPATCH_SOCK_MARKER);
    let ready_path = job_dir.join(DISPATCH_READY_MARKER);
    let _ = std::fs::remove_file(&ready_path);
    std::fs::write(&marker_path, b"").map_err(|e| {
        BuilderVmError::ExtractionFailed(format!(
            "staging dispatch marker {}: {e}",
            marker_path.display()
        ))
    })?;
    Ok(())
}

/// libkrun exposes attached sparse block images 64 KiB shorter than their
/// host-side file length. Reserve that tail when creating a new image so an
/// ext4 filesystem formatted to the file's capacity never trips the guest's
/// stale-geometry guard on the next boot.
pub(crate) const LIBKRUN_BLOCK_DEVICE_TAIL_RESERVE_BYTES: u64 = 64 * 1024;

/// Env var the operator sets to override [`DEFAULT_BUILDER_VM_TIMEOUT`].
/// Plain integer seconds; zero is rejected so a typo doesn't silently
/// disable the safety net.
pub const MVM_BUILDER_VM_TIMEOUT_SECS_ENV: &str = "MVM_BUILDER_VM_TIMEOUT_SECS";

/// Builder persistent `/nix` store auto-GC threshold (GiB of *used*
/// space). When the in-guest store exceeds this after a build, the
/// build script runs `nix-collect-garbage --delete-older-than 14d`.
/// Default 24 GiB (above doctor's 20 GiB warning, below the 64 GiB
/// sparse cap [`DEFAULT_NIX_STORE_MIB`](crate::libkrun_builder::DEFAULT_NIX_STORE_MIB)).
/// Override: [`MVM_BUILDER_STORE_GC_GIB_ENV`].
///
/// Lives here (always compiled) rather than in `libkrun_builder`
/// (feature-gated `builder-vm`) because `render_flake_cmd_sh` reads it
/// at render time and that path compiles unconditionally;
/// `libkrun_builder` re-exports it near `DEFAULT_NIX_STORE_MIB` for
/// discoverability.
pub const DEFAULT_BUILDER_STORE_GC_GIB: u32 = 24;

/// Env var that overrides [`DEFAULT_BUILDER_STORE_GC_GIB`]. Plain
/// integer GiB; a missing/garbage/zero value falls back to the
/// default (this is a best-effort space cap, not a correctness gate —
/// a typo must not disable the just-built-closure-preserving GC).
pub const MVM_BUILDER_STORE_GC_GIB_ENV: &str = "MVM_BUILDER_STORE_GC_GIB";

/// Resolve the builder-store GC cap, in KiB, for substitution into the
/// in-guest build script's `du -k` comparison. Reads
/// [`MVM_BUILDER_STORE_GC_GIB_ENV`]; an unset, non-integer, or zero
/// value falls back to [`DEFAULT_BUILDER_STORE_GC_GIB`].
pub fn builder_store_gc_cap_kib() -> u64 {
    let gib = std::env::var(MVM_BUILDER_STORE_GC_GIB_ENV)
        .ok()
        .and_then(|v| v.trim().parse::<u32>().ok())
        .filter(|g| *g > 0)
        .unwrap_or(DEFAULT_BUILDER_STORE_GC_GIB);
    u64::from(gib) * 1024 * 1024
}

/// Per-job dir filename mvm-host-vm-init detects to dispatch
/// through the application-dependency install pipeline. Migrated
/// from `libkrun_builder.rs` because the install spec staging is a
/// hypervisor-agnostic concern that both the libkrun and HVF builder
/// paths need.
pub const INSTALL_SPEC_FILENAME: &str = "install_spec.json";

/// virtio-fs tag the libkrun and QEMU builders attach an optional seeded Nix
/// store closure NAR under. `mvm-host-vm-init`'s fixed-share mount table
/// mounts this tag read-only at `/closure-seed`, matching the disk-transport
/// `closure-seed/` tar entry the hvf VMM uses for the same NAR — the guest
/// import logic (`import_seeded_closure`) doesn't care which transport
/// populated the mount point.
pub const CLOSURE_SEED_TAG: &str = "closure-seed";

/// Stage `closure_nar` into its own share directory under `parent_dir` so it
/// can be attached as a read-only virtio-fs share without exposing
/// `parent_dir`'s other contents. This matters because the source lives in
/// the resolved builder image's per-arch cache dir alongside `vmlinux` /
/// `rootfs.ext4` — sharing that whole directory would leak the kernel/rootfs
/// into the guest through an unrelated mount. Returns the staged directory
/// (containing exactly one file, named after `closure_nar`'s own file name)
/// for the caller to pass to `add_virtio_fs(CLOSURE_SEED_TAG, ...)`.
pub fn stage_closure_seed_dir(
    closure_nar: &Path,
    parent_dir: &Path,
) -> Result<PathBuf, BuilderVmError> {
    let share_dir = parent_dir.join(CLOSURE_SEED_TAG);
    std::fs::create_dir_all(&share_dir).map_err(|e| {
        BuilderVmError::ExtractionFailed(format!(
            "creating closure-seed share dir {}: {e}",
            share_dir.display()
        ))
    })?;
    // The guest mounts this share at `/closure-seed` and imports a fixed file
    // name (`CLOSURE_FILE`), so stage the NAR under that name regardless of what
    // the source path is called — a mismatched name would make the guest import
    // a silent no-op.
    let dest = share_dir.join(crate::builder_pack::CLOSURE_FILE);
    std::fs::copy(closure_nar, &dest).map_err(|e| {
        BuilderVmError::ExtractionFailed(format!(
            "staging closure NAR {} -> {}: {e}",
            closure_nar.display(),
            dest.display()
        ))
    })?;
    Ok(share_dir)
}

/// Hypervisor-agnostic orchestration helper. Holds a reference to
/// a [`VmBackendForBuilder`] so the actual supervisor spawn /
/// console-log path / per-VM state directory are routed through
/// the appropriate VMM without the helper knowing which one.
///
/// Lifetime-bound — the helper doesn't own the backend; callers
/// keep a long-lived backend instance (e.g. `LibkrunBuilderBackend`
/// constructed once at `LibkrunBuilderVm::run_build` entry) and
/// hand a borrow to the helper for the duration of one run.
pub struct BuilderVmRuntime<'a> {
    backend: &'a dyn VmBackendForBuilder,
}

impl<'a> BuilderVmRuntime<'a> {
    /// Construct over an existing backend reference.
    pub fn new(backend: &'a dyn VmBackendForBuilder) -> Self {
        Self { backend }
    }

    /// Borrow the underlying backend. Subsequent migration commits
    /// expose more targeted methods; this exists today so the
    /// helper has a way to thread the backend through its yet-to-be-
    /// migrated methods without re-routing every call site through
    /// a builder.
    pub fn backend(&self) -> &dyn VmBackendForBuilder {
        self.backend
    }
}

/// Stage the per-job dir inside `~/.mvm/cache/builder-vm/jobs/<id>/`
/// so the in-guest `mvm-host-vm-init` finds the right artifact
/// for dispatch:
///
/// - [`BuilderJob::Flake`] → writes `cmd.sh` (the in-guest nix-build
///   script). mvm-host-vm-init runs it after `/work` `/out` `/job`
///   virtio-fs shares are mounted.
/// - [`BuilderJob::Install`] → copies the caller's install-spec JSON
///   to `<job_dir>/install_spec.json`. mvm-host-vm-init detects the
///   filename and dispatches the application-dep install pipeline
///   instead of `cmd.sh`.
///
/// Hypervisor-agnostic — the staging produces files in a virtio-fs
/// share; libkrun and HVF both bind-mount the same host dir, so the
/// helper doesn't need to know which VMM is on the other end.
/// Migrated from `libkrun_builder.rs`.
pub fn stage_job_dir(
    job_dir: &Path,
    job: &BuilderJob,
    mvm_local_override: Option<&Path>,
    workspace_src: Option<&Path>,
) -> Result<(), BuilderVmError> {
    std::fs::create_dir_all(job_dir).map_err(|e| {
        BuilderVmError::ExtractionFailed(format!("creating job dir {}: {e}", job_dir.display()))
    })?;

    let (flake_ref, attr_path) = match job {
        BuilderJob::Flake {
            flake_ref,
            attr_path,
        } => (flake_ref.as_str(), attr_path.as_str()),
        BuilderJob::Install { spec_path } => {
            // Copy the caller's spec into the per-job dir so the
            // virtio-fs share carries it into the guest at
            // `/job/install_spec.json`. `mvm-host-vm-init` detects
            // that filename and dispatches through the install
            // pipeline instead of running cmd.sh.
            let dst = job_dir.join(INSTALL_SPEC_FILENAME);
            std::fs::copy(spec_path, &dst).map_err(|e| {
                BuilderVmError::ExtractionFailed(format!(
                    "copying install spec {} -> {}: {e}",
                    spec_path.display(),
                    dst.display()
                ))
            })?;
            return Ok(());
        }
    };

    // Source-checkout invariant: when the caller stages a local user
    // flake (`mvm_local_override = Some`), the
    // workspace — not the user flake — is mounted at `/work`, and we
    // copy the user flake into the job dir so it rides the existing
    // `/job` virtio-fs share. The build then resolves `mvm` from the
    // mounted local checkout (`path:/work/nix`) instead of GitHub, so a
    // contributor's nix changes are exercised without a release
    // round-trip. No new guest mount: `/work` + `/job` already exist.
    let override_mvm = match mvm_local_override {
        Some(user_flake) => {
            let dst = job_dir.join(STAGED_WORKLOAD_SUBDIR);
            copy_dir_recursive(user_flake, &dst).map_err(|e| {
                BuilderVmError::ExtractionFailed(format!(
                    "staging user flake {} -> {}: {e}",
                    user_flake.display(),
                    dst.display()
                ))
            })?;
            // Stage a filtered cargo-tree snapshot of the workspace so the
            // build can pin `mvm/mvm-workspace` to it (path:.../mvm-src):
            // mvm's default `mvm-workspace = path:..` resolves to
            // `/nix/store` once mvm is store-copied as a subdir, and the
            // raw /work mount carries `target/` + multi-GB Swift `.build`.
            if let Some(workspace) = workspace_src {
                let mvm_src = job_dir.join(STAGED_MVM_SRC_SUBDIR);
                stage_filtered_workspace(workspace, &mvm_src).map_err(|e| {
                    BuilderVmError::ExtractionFailed(format!(
                        "staging mvm workspace {} -> {}: {e}",
                        workspace.display(),
                        mvm_src.display()
                    ))
                })?;
            }
            true
        }
        None => false,
    };

    let body = render_flake_cmd_sh(flake_ref, attr_path, override_mvm);

    let cmd_path = job_dir.join("cmd.sh");
    std::fs::write(&cmd_path, body).map_err(|e| {
        BuilderVmError::ExtractionFailed(format!("writing {}: {e}", cmd_path.display()))
    })?;
    Ok(())
}

/// Job-dir subdirectory the user flake is staged into under
/// source-checkout override mode; reachable in-guest at
/// `/job/<relpath>/workload` (the job dir is the `/job` virtio-fs share).
const STAGED_WORKLOAD_SUBDIR: &str = "workload";

/// Copy a directory tree (used to stage the user flake into the job dir).
/// Shallow recursion is fine — compiled flakes are `flake.nix` +
/// `launch.json` + a small `src/` tree.
fn copy_dir_recursive(src: &Path, dst: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir_recursive(&from, &to)?;
        } else {
            std::fs::copy(&from, &to)?;
        }
    }
    Ok(())
}

/// Job-dir subdirectory the filtered mvm-workspace snapshot is staged into
/// under source-checkout override mode; the build pins `mvm/mvm-workspace`
/// to it (reachable beside cmd.sh in the `/job` virtio-fs share).
const STAGED_MVM_SRC_SUBDIR: &str = "mvm-src";

/// Basenames pruned when staging the mvm-workspace snapshot — build
/// artifacts + VCS/tooling scratch that must never enter the agent's `src`
/// closure (they bloat it and break the source hash / caching; the Swift
/// `.build` dirs alone are multi-GB). Kept aligned with
/// `nix/lib/workspace-filter.nix`.
const WORKSPACE_SNAPSHOT_SKIP: &[&str] = &[
    "target",
    ".build",
    "node_modules",
    ".direnv",
    ".cargo",
    "dist",
    ".astro",
    "dev-prebuilt",
    ".mvm-test",
    "graphify-out",
    ".ur-seed-result",
    "nixos.qcow2",
    ".git",
    ".claude",
    ".worktrees",
    ".playwright-mcp",
    "keys",
    "result",
];

/// Stage an allowlisted, filtered copy of the mvm workspace into `mvm_src`:
/// only the cargo tree — root `Cargo.{toml,lock}` + `src` + `crates` +
/// `third_party` local dependencies + `xtask` (the `[workspace] members`) —
/// with `WORKSPACE_SNAPSHOT_SKIP`
/// basenames pruned at any depth. This is what `mvm/mvm-workspace`
/// resolves to, so `mvm-guest-agent` / `mvm-addon-dns` compile from a clean
/// source tree. Allowlist (not blocklist): a missing member fails the build
/// loudly rather than silently leaking host files into the rootfs.
fn stage_filtered_workspace(workspace: &Path, mvm_src: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(mvm_src)?;
    for item in [
        "Cargo.toml",
        "Cargo.lock",
        "src",
        "crates",
        "third_party",
        "xtask",
    ] {
        let from = workspace.join(item);
        if !from.exists() {
            continue;
        }
        let to = mvm_src.join(item);
        if from.is_dir() {
            copy_dir_filtered(&from, &to)?;
        } else {
            std::fs::copy(&from, &to)?;
        }
    }
    Ok(())
}

/// Recursive copy that prunes `WORKSPACE_SNAPSHOT_SKIP` basenames (and
/// `result-*` symlinks) at any depth. `pub(crate)` so the disk-transport
/// `work` input staging (`libkrun_builder`) can reuse this exclusion
/// instead of forking a second skip list.
pub(crate) fn copy_dir_filtered(src: &Path, dst: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let raw = entry.file_name();
        let name = raw.to_string_lossy();
        if WORKSPACE_SNAPSHOT_SKIP.contains(&name.as_ref()) || name.starts_with("result-") {
            continue;
        }
        let from = entry.path();
        let to = dst.join(&raw);
        if entry.file_type()?.is_dir() {
            copy_dir_filtered(&from, &to)?;
        } else {
            std::fs::copy(&from, &to)?;
        }
    }
    Ok(())
}

/// Render the `cmd.sh` body the in-guest `mvm-host-vm-init` runs
/// for a [`BuilderJob::Flake`]. Inlined as a separate function so
/// tests can assert the rendered output without touching the
/// filesystem.
fn render_flake_cmd_sh(flake_ref: &str, attr_path: &str, override_mvm: bool) -> String {
    // Source-checkout override mode: `/work` is the workspace and the
    // user flake was staged into this job dir (reachable beside cmd.sh).
    // Resolve it relative to the script so we don't need the job dir's
    // guest relpath, and pin `mvm` to the mounted local checkout.
    let (flake_ref_assign, override_flag) = if override_mvm {
        (
            // Resolve the staged user flake and the filtered mvm-workspace
            // snapshot relative to this script (both live in the job dir).
            format!(
                "FLAKE_REF=\"$(cd \"$(dirname \"$0\")\" && pwd)/{STAGED_WORKLOAD_SUBDIR}\"\nMVM_SRC=\"$(cd \"$(dirname \"$0\")\" && pwd)/{STAGED_MVM_SRC_SUBDIR}\""
            ),
            // Pin `mvm` to the mounted local checkout, and its
            // `mvm-workspace` to the filtered snapshot. The second override
            // is load-bearing: mvm's default `mvm-workspace = path:..`
            // resolves to `/nix/store` once mvm is store-copied as a subdir.
            " --override-input mvm path:/work/nix --override-input mvm/mvm-workspace \"path:$MVM_SRC\"".to_string(),
        )
    } else {
        (
            format!("FLAKE_REF='{}'", shell_single_quote_escape(flake_ref)),
            String::new(),
        )
    };
    // Resolved on the host, baked as a literal into the script so
    // the in-guest `du` comparison needs no env plumbing through the VM.
    let gc_cap_kib = builder_store_gc_cap_kib();
    format!(
        r#"#!/bin/sh
# mvm-builder-vm cmd.sh — emitted by BuilderVmRuntime.
# Runs inside the builder VM under `/bin/sh -eu`. The host wires
# /work (workspace), /out (artifact dir), /job (this dir) as
# virtio-fs shares; /nix is a persistent virtio-blk overlay
# handled by mvm-host-vm-init.
set -eu

{flake_ref_assign}
ATTR_PATH='{attr_path}'

# Point HOME at writable tmpfs (`/tmp`) to satisfy code paths that
# write to `~/...` (the rootfs is mounted `ro`; nix would otherwise
# bail with "creating directory '//.cache/nix': Read-only file
# system"). XDG_CACHE_HOME lives on the persistent `/nix-store`
# disk so Nix's eval-cache-v5, tarball-cache, and binary-cache-v6
# survive across builds — cold flake eval is the long pole on
# warm-store rebuilds, and these caches reclaim it. `/nix-store`
# is the ext4 root for the persistent virtio-blk device; it sits
# alongside the overlay upperdir (`/nix-store/upper`) at the
# disk's top level, so writes here don't pollute the Nix store
# namespace. XDG_STATE_HOME stays on tmpfs: it only holds profile
# generations, which one-shot build VMs don't use.
export HOME=/tmp
export XDG_CACHE_HOME=/nix-store/.cache
export XDG_STATE_HOME=/tmp/.local/state
mkdir -p /nix-store/.cache /tmp/.local/state
# Do not rely on PID 1's inherited PATH here. The build script may run
# under shells / wrappers that sanitize env, but mkGuest guarantees the
# builder tools are symlinked into these prefixes.
export PATH=/usr/local/sbin:/usr/local/bin:/sbin:/usr/sbin:/bin:/usr/bin
NIX_BIN=/sbin/nix
NIX_STORE_BIN=/sbin/nix-store
if [ ! -x "$NIX_BIN" ]; then
    echo "builder VM missing executable $NIX_BIN" >&2
    ls -l /usr/local/bin/nix /sbin/nix 2>/dev/null >&2 || true
    exit 127
fi
if [ ! -x "$NIX_STORE_BIN" ]; then
    echo "builder VM missing executable $NIX_STORE_BIN" >&2
    ls -l /usr/local/bin/nix-store /sbin/nix-store 2>/dev/null >&2 || true
    exit 127
fi

# CA certs for TLS to cache.nixos.org / api.github.com.
export CURL_CA_BUNDLE=/etc/ssl/certs/ca-bundle.crt
export NIX_SSL_CERT_FILE=/etc/ssl/certs/ca-bundle.crt
export SSL_CERT_FILE=/etc/ssl/certs/ca-bundle.crt

cd /work
# `experimental-features` enables nix-command + flakes. `sandbox =
# false` + `build-users-group =` is mandatory inside the builder
# VM: there are no `nixbld*` accounts in the rootfs and no kernel
# user-ns isolation for build sandboxes, so every derivation would
# otherwise fail with "the group 'nixbld' specified in
# 'build-users-group' does not exist". The builder VM IS the
# isolation boundary, so an in-guest sandbox is redundant.
export NIX_CONFIG="experimental-features = nix-command flakes
sandbox = false
build-users-group =
max-jobs = auto
cores = 0
auto-optimise-store = true
substituters = https://cache.nixos.org/
trusted-public-keys = cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY=
# Resilience to a flaky builder-egress link: retry each substitute download a
# few times, cap concurrent connections so large NARs don't starve/drop mid
# transfer, and fall back to building a derivation from source when its binary
# cache download keeps failing (a smaller, different fetch than the large
# prebuilt NAR). Without this a single dropped NAR aborts the whole build.
fallback = true
download-attempts = 5
http-connections = 8
connect-timeout = 15
stalled-download-timeout = 90"
# Flake convention: workspace-path env var so flakes that reference
# the workspace root don't depend on relative-path resolution
# against the store-copied flake dir.
export MVM_WORKSPACE_PATH=/work
# Host-vm binaries extracted from the mvmctl embedded payload and
# mounted read-only at /mvm-bins. The builder-vm
# flake reads this to install the correct cross-compiled binaries into
# the rootfs without a separate nix build.
export MVM_HOST_BIN_DIR=/mvm-bins

echo "mvm-builder-vm: filesystem space before nix build:" >&2
df -h /nix /tmp >&2 || true

# `--impure` is what unblocks builds inside the VM when the
# flake has path inputs; `--no-write-lock-file` keeps the
# read-only `/work` mount from tripping EROFS.
# `--print-build-logs --keep-going` dumps every failing build's
# stderr inline (default nix only prints the last 10 lines and
# cascades up). We tee stderr to /job/nix-build.log so the host
# can read the actual root cause when a deep dependency fails.
set +e
"$NIX_BIN" build "${{FLAKE_REF}}#${{ATTR_PATH}}"{override_flag} \
    --no-link --print-out-paths --no-write-lock-file --impure \
    --print-build-logs --keep-going \
    > /job/nix-stdout.log 2> /job/nix-stderr.log
NIX_RC=$?
set -e
NIX_OUT=$(cat /job/nix-stdout.log)
if [ "$NIX_RC" -ne 0 ]; then
    echo "mvm-builder-vm: filesystem space after failed nix build:" >&2
    df -h /nix /tmp >&2 || true
    echo "nix build exited $NIX_RC; tail of stderr:" >&2
    tail -200 /job/nix-stderr.log >&2
    exit $NIX_RC
fi

if [ -z "$NIX_OUT" ]; then
    echo "nix build emitted no /nix/store output path" >&2
    exit 1
fi
printf '%s\n' "$NIX_OUT" > /job/store-path

# Pin the just-built closure as a warm GC root so the cap-triggered GC
# below spares the kernel + runtime base it carries. That GC deletes every
# unrooted path regardless of age, and a fresh build's kernel/base are
# reachable only through the transient build root — so without this the next
# build recompiles the kernel and re-pulls the base closure.
#
# Key the root by build kind so alternating builder-vm-image (bootstrap / stage0)
# and workload (machine run) builds don't evict each other's closure. Two
# bounded fixed names keep the store bounded — the cap GC still frees a
# superseded closure within a kind, and an unchanged derivation is a store hit
# next build. The builder-vm image derivation name (mvm-builder-vm-image-* /
# mvm-builder-vm-dev-*) is set in nix/images/builder-vm/flake.nix; everything
# else (workload rootfs/images) is the workload kind. Best-effort; never fails
# the build.
case "$(basename "$NIX_OUT")" in
  *-mvm-builder-vm-*) warm=builder ;;
  *)                  warm=workload ;;
esac
mkdir -p /nix/var/nix/gcroots 2>/dev/null || true
"$NIX_STORE_BIN" --add-root "/nix/var/nix/gcroots/mvm-warm-$warm" --indirect -r "$NIX_OUT" >/dev/null 2>&1 \
  || ln -sfn "$NIX_OUT" "/nix/var/nix/gcroots/mvm-warm-$warm" 2>/dev/null || true
# Retire the pre-fix single root so it stops protecting a stale closure.
rm -f /nix/var/nix/gcroots/mvm-warm-latest 2>/dev/null || true

# Resolve the rootfs source path and any kernel source path. A plain
# mkGuest workload image is a bare ext4 file ($NIX_OUT is the rootfs
# itself); builder / interactive images are a directory carrying
# `vmlinux` + `rootfs.ext4`. Accept either `vmlinux` / `Image` /
# `bzImage` for the kernel across flake conventions.
ROOTFS_SRC=
KERNEL_SRC=
if [ -f "$NIX_OUT" ]; then
    ROOTFS_SRC="$NIX_OUT"
elif [ -d "$NIX_OUT" ]; then
    if   [ -f "$NIX_OUT/vmlinux" ]; then KERNEL_SRC="$NIX_OUT/vmlinux"
    elif [ -f "$NIX_OUT/Image"   ]; then KERNEL_SRC="$NIX_OUT/Image"
    elif [ -f "$NIX_OUT/bzImage" ]; then KERNEL_SRC="$NIX_OUT/bzImage"
    fi
    if [ -f "$NIX_OUT/rootfs.ext4" ]; then
        ROOTFS_SRC="$NIX_OUT/rootfs.ext4"
    fi
fi

if [ -z "$ROOTFS_SRC" ] || [ ! -f "$ROOTFS_SRC" ]; then
    echo "no rootfs.ext4 in nix build output at $NIX_OUT" >&2
    exit 1
fi

# Run the before_build lifecycle hook inside a writable copy of the
# rootfs before the artifact is copied to /out. The hook is baked
# into the rootfs at /etc/mvm/hooks/before_build.sh by
# mkFunctionService; mvm-host-vm-init provides the builder-VM
# consumer.
BUILD_HOOK_ROOTFS="/tmp/mvm-rootfs-before-build.ext4"
cp -L "$ROOTFS_SRC" "$BUILD_HOOK_ROOTFS"
echo "mvm-builder-vm: running before_build hook" >&2
set +e
/sbin/mvm-host-vm-init run-before-build-hook "$BUILD_HOOK_ROOTFS"
hook_rc=$?
set -e
if [ "$hook_rc" -ne 0 ]; then
    echo "mvm-builder-vm: before_build hook failed (exit $hook_rc)" >&2
    rm -f "$BUILD_HOOK_ROOTFS"
    exit $hook_rc
fi
cp -L "$BUILD_HOOK_ROOTFS" /out/rootfs.ext4
rm -f "$BUILD_HOOK_ROOTFS"

if [ -n "$KERNEL_SRC" ]; then
    cp -L "$KERNEL_SRC" /out/vmlinux
fi

# Permissions for the host-side reader. Ignore failures —
# virtio-fs may map the uid such that chmod is a no-op.
chmod 0644 /out/rootfs.ext4 2>/dev/null || true
[ -f /out/vmlinux ] && chmod 0644 /out/vmlinux 2>/dev/null || true

# Emit the mvm-meta.json sidecar next to the rootfs. The runtime
# admission path refuses to boot a rootfs without it (it certifies the
# overlay-aware contract), and the host has no nix, so we eval the
# flake's `passthru.mvm` (the GuestSidecar) here in the guest.
# mkGuest puts it on the rootfs derivation; an image that wraps the
# rootfs (the builder-vm `dev`/`default` attrs are a runCommand around
# it) surfaces it one level down under `passthru.rootfs`. Try the direct
# attr first, then the wrapped one.
#
# An image that published a sidecar of its own wins over both. A wrapping
# derivation knows things the inner mkGuest attrs cannot — which release line
# the bytes belong to, which revision generated them — and re-deriving the
# sidecar from `passthru` here would silently drop exactly those fields.
if [ -f "$NIX_OUT/mvm-meta.json" ]; then
    cp -L "$NIX_OUT/mvm-meta.json" /out/mvm-meta.json
    echo "mvm-builder-vm: wrote /out/mvm-meta.json (image-published sidecar)" >&2
elif nix eval --json "${{FLAKE_REF}}#${{ATTR_PATH}}.passthru.mvm" --impure{override_flag} \
      > /out/mvm-meta.json 2> /job/sidecar-direct.log; then
    echo "mvm-builder-vm: wrote /out/mvm-meta.json (passthru.mvm)" >&2
elif nix eval --json "${{FLAKE_REF}}#${{ATTR_PATH}}.passthru.rootfs.passthru.mvm" --impure{override_flag} \
      > /out/mvm-meta.json 2> /job/sidecar-rootfs.log; then
    echo "mvm-builder-vm: wrote /out/mvm-meta.json (passthru.rootfs.passthru.mvm)" >&2
else
    echo "mvm-builder-vm: WARNING could not emit mvm-meta.json; the runtime will refuse to boot this rootfs:" >&2
    cat /job/sidecar-direct.log /job/sidecar-rootfs.log >&2 || true
    rm -f /out/mvm-meta.json
fi

# Pin the builder VM's own materialize toolchain under fixed GC roots so the
# cap GC below can't reap it. The OCI rootfs materialize job runs
# /sbin/mkfs.ext4 (and `mount`) inside this VM but registers no root of its
# own, and a workload build's $NIX_OUT closure never carries e2fsprogs — so
# without these roots a cap GC after a workload build leaves /sbin/mkfs.ext4
# a dangling symlink and every later image run dies with "mkfs.ext4: not
# found". Best-effort; skips a tool already missing (recovery rebuilds it).
for tool in /sbin/mkfs.ext4 mount; do
  tool_path=$(command -v "$tool" 2>/dev/null) || continue
  tool_store=$(readlink -f "$tool_path" 2>/dev/null) || continue
  [ -n "$tool_store" ] || continue
  tool_root="/nix/var/nix/gcroots/mvm-builder-tools-$(basename "$tool")"
  nix-store --add-root "$tool_root" --indirect -r "$tool_store" >/dev/null 2>&1 \
    || ln -sfn "$tool_store" "$tool_root" 2>/dev/null || true
done

# Bound the persistent /nix store: GC stale closures once it grows
# past the cap. `--delete-older-than 14d` keeps the just-built closure
# (recent) so rebuilds stay warm; only old-revision garbage is freed.
# Best-effort and POST-build so it can never fail the build or lose output.
store_kib=$(du -s -k /nix 2>/dev/null | cut -f1 || echo 0)
if [ "$store_kib" -gt {gc_cap_kib} ]; then
  echo "mvm-builder: /nix store ${{store_kib}} KiB > cap {gc_cap_kib} KiB — nix-collect-garbage --delete-older-than 14d" >&2
  nix-collect-garbage --delete-older-than 14d >&2 2>&1 || echo "mvm-builder: nix-collect-garbage failed (continuing)" >&2
fi
"#,
        flake_ref_assign = flake_ref_assign,
        override_flag = override_flag,
        attr_path = shell_single_quote_escape(attr_path),
        gc_cap_kib = gc_cap_kib,
    )
}

/// Escape a string for inclusion inside `'…'` single quotes in
/// POSIX shell. The only character that can't appear inside single
/// quotes is `'` itself; we close the quote, emit `\'`, then
/// reopen. Standard sh-escape pattern.
///
/// Public so external callers that build their own per-job shell
/// scripts (e.g. `LibkrunBuilderVm::run_shell_script`'s validator)
/// can reuse the same escape rules.
pub fn shell_single_quote_escape(s: &str) -> String {
    s.replace('\'', "'\\''")
}

/// Parsed `<job_dir>/result` written by `mvm-host-vm-init`. Shape
/// matches the JSON `mvm-host-vm-init::linux::write_result` emits.
/// The guest PID 1 writes this on every code path that reaches
/// `power_off`; the host-side helper reads it to learn the guest's
/// exit code and the cmd.sh stderr-tail ringbuffer for diagnostics.
///
/// Hypervisor-agnostic: the file lives in the `/job` virtio-fs share,
/// which both libkrun and HVF attach identically. Migrated from
/// `libkrun_builder.rs`.
#[derive(Debug, Deserialize)]
pub struct JobResult {
    pub exit_code: i32,
    #[serde(default)]
    pub stderr_tail: String,
}

/// Read and parse `<job_dir>/result`. The guest's PID 1 writes this
/// on every code path that reaches `power_off`; absence here means
/// the VM crashed before `mvm-host-vm-init` could finalize.
///
/// Error mapping mirrors the original libkrun-side implementation:
/// missing file → [`BuilderVmError::NixBuildFailed`] (it's almost
/// always a guest crash mid-build); malformed JSON →
/// [`BuilderVmError::ExtractionFailed`] (host couldn't extract the
/// result, regardless of whether the build succeeded).
pub fn read_job_result(job_dir: &Path) -> Result<JobResult, BuilderVmError> {
    let path = job_dir.join("result");
    let body = std::fs::read_to_string(&path).map_err(|e| {
        BuilderVmError::NixBuildFailed(format!(
            "guest did not write {}: {e} \
             (the VM may have crashed before mvm-host-vm-init could finalize)",
            path.display()
        ))
    })?;
    serde_json::from_str::<JobResult>(&body).map_err(|e| {
        BuilderVmError::ExtractionFailed(format!(
            "parsing {} as JSON: {e}\nbody:\n{body}",
            path.display()
        ))
    })
}

/// Read and parse `<job_dir>/result`, enriching the missing-result failure with
/// the builder VM's host-side log paths and short tails.
///
/// The libkrun/HVF/qemu live proof lanes all fail the same way when PID 1
/// exits before finalization: `cmd.sh` exists, but `/job/result` never lands.
/// Surfacing the VM state dir plus whatever `console.log` /
/// `supervisor.{stdout,stderr}.log` captured keeps the next operator run from
/// starting at a bare ENOENT.
pub fn read_job_result_with_diagnostics(
    job_dir: &Path,
    vm_state_dir: &Path,
) -> Result<JobResult, BuilderVmError> {
    match read_job_result(job_dir) {
        Ok(result) => Ok(result),
        Err(BuilderVmError::NixBuildFailed(message)) => {
            Err(BuilderVmError::NixBuildFailed(format!(
                "{message}\n{}",
                missing_job_result_diagnostics(job_dir, vm_state_dir)
            )))
        }
        Err(err) => Err(err),
    }
}

/// Stage a one-shot builder shell job.
///
/// Shell jobs are not Nix builds, but they use the same `/job/cmd.sh`
/// contract as the builder VM's flake path. Keeping this helper in the
/// backend-neutral runtime module avoids each VMM driver drifting on the
/// job-dir shape.
pub fn stage_shell_job_dir(job_dir: &Path, script: &str) -> Result<(), BuilderVmError> {
    std::fs::create_dir_all(job_dir).map_err(|e| {
        BuilderVmError::ExtractionFailed(format!("creating job dir {}: {e}", job_dir.display()))
    })?;
    let cmd_path = job_dir.join("cmd.sh");
    std::fs::write(&cmd_path, script).map_err(|e| {
        BuilderVmError::ExtractionFailed(format!("writing {}: {e}", cmd_path.display()))
    })?;
    Ok(())
}

/// Stage a filtered copy of `src` for a disk-transport `/work` input.
///
/// A source checkout can carry `target/`, `.worktrees/`, `.git/`, and other
/// build or VCS scratch measured in tens of GiB. Raw-disk builder transports
/// must not archive that host-local state into the guest. Reuse the same
/// exclusion contract as the staged mvm-workspace snapshot so all disk-backed
/// builders pack only source inputs.
///
/// The returned temporary directory owns the staged tree and must remain alive
/// until the caller finishes packing its transport disk.
pub fn stage_filtered_work_input(src: &Path) -> Result<tempfile::TempDir, BuilderVmError> {
    let staged = tempfile::TempDir::new().map_err(|e| {
        BuilderVmError::ExtractionFailed(format!("creating filtered work staging dir: {e}"))
    })?;
    copy_dir_filtered(src, staged.path()).map_err(|e| {
        BuilderVmError::ExtractionFailed(format!(
            "staging filtered work input {} -> {}: {e}",
            src.display(),
            staged.path().display()
        ))
    })?;
    Ok(staged)
}

/// Filename of the install report `mvm-host-vm-init` writes into
/// `artifact_out/` after the install pipeline finishes. The host
/// reads + parses this to decide whether the install succeeded.
pub const INSTALL_RESULT_FILENAME: &str = "result.json";

/// Read the last `max_bytes` of `path` into a `String`, replacing any
/// invalid UTF-8 lossily. Returns `Err` if the file is missing or
/// unreadable. Used by [`finalize_flake_job`] to surface the tail of
/// `<job_dir>/nix-stderr.log` (the cmd.sh's nix-build stderr capture)
/// in the failure path without loading a multi-hundred-KB log into
/// memory.
pub fn read_last_bytes_of(path: &Path, max_bytes: u64) -> std::io::Result<String> {
    use std::io::{Read, Seek, SeekFrom};
    let mut file = std::fs::File::open(path)?;
    let len = file.metadata()?.len();
    let take = max_bytes.min(len);
    // SeekFrom::End wants i64; max_bytes is bounded to a small constant
    // at every call site (4 KiB today) so the cast is safe.
    let offset = i64::try_from(take).unwrap_or(i64::MAX).saturating_neg();
    file.seek(SeekFrom::End(offset))?;
    let mut buf = Vec::with_capacity(take as usize);
    file.read_to_end(&mut buf)?;
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

fn missing_job_result_diagnostics(job_dir: &Path, vm_state_dir: &Path) -> String {
    let console_log = vm_state_dir.join("console.log");
    let supervisor_stdout = vm_state_dir.join("supervisor.stdout.log");
    let supervisor_stderr = vm_state_dir.join("supervisor.stderr.log");
    let supervisor_lifecycle = vm_state_dir.join("supervisor.lifecycle.log");
    let supervisor_config = vm_state_dir.join("supervisor-config.json");
    let init_lifecycle = job_dir.join("mvm-host-vm-init.lifecycle.log");
    let persistent_store_init_lifecycle =
        diagnose_persistent_store_init_lifecycle(vm_state_dir, &supervisor_config);
    format!(
        "builder VM state dir: {}\nbuilder job dir: {}\n{}\n{}\n{}\n{}\n{}\n{}\n{}",
        vm_state_dir.display(),
        job_dir.display(),
        diagnose_log_path("console.log", &console_log),
        diagnose_log_path("supervisor.stdout.log", &supervisor_stdout),
        diagnose_log_path("supervisor.stderr.log", &supervisor_stderr),
        diagnose_log_path("supervisor.lifecycle.log", &supervisor_lifecycle),
        diagnose_log_path("supervisor-config.json", &supervisor_config),
        diagnose_log_path("mvm-host-vm-init.lifecycle.log", &init_lifecycle),
        persistent_store_init_lifecycle,
    )
}

#[derive(Deserialize)]
struct SupervisorConfigDiskView {
    krun: SupervisorConfigKrunView,
}

#[derive(Deserialize)]
struct SupervisorConfigKrunView {
    extra_disks: Vec<SupervisorConfigExtraDiskView>,
}

#[derive(Deserialize)]
struct SupervisorConfigExtraDiskView {
    id: String,
    path: String,
}

fn diagnose_persistent_store_init_lifecycle(
    vm_state_dir: &Path,
    supervisor_config: &Path,
) -> String {
    let Some(image_path) = persistent_nix_store_image_from_supervisor_config(supervisor_config)
    else {
        return format!(
            "persistent nix-store init lifecycle: unavailable (no nix-store disk in {})",
            supervisor_config.display()
        );
    };
    let Some(debugfs) = locate_debugfs() else {
        return format!(
            "persistent nix-store init lifecycle: unavailable (debugfs not installed; image {})",
            image_path.display()
        );
    };
    for guest_path in [
        "/out/mvm-host-vm-init.lifecycle.log",
        "/mvm-host-vm-init.lifecycle.log",
    ] {
        match debugfs_cat(&debugfs, &image_path, guest_path) {
            Ok(Some(body)) => {
                return format!(
                    "persistent nix-store init lifecycle ({} via {}):\n{}",
                    guest_path,
                    image_path.display(),
                    body.trim_end()
                );
            }
            Ok(None) => continue,
            Err(err) => {
                return format!(
                    "persistent nix-store init lifecycle: debugfs read failed for {} in {}: {}",
                    guest_path,
                    image_path.display(),
                    err
                );
            }
        }
    }
    format!(
        "persistent nix-store init lifecycle: missing in {} (/out/... and /... checked; vm state dir {})",
        image_path.display(),
        vm_state_dir.display()
    )
}

fn persistent_nix_store_image_from_supervisor_config(supervisor_config: &Path) -> Option<PathBuf> {
    let body = std::fs::read_to_string(supervisor_config).ok()?;
    let cfg: SupervisorConfigDiskView = serde_json::from_str(&body).ok()?;
    cfg.krun
        .extra_disks
        .into_iter()
        .find(|disk| disk.id == "nix-store")
        .map(|disk| PathBuf::from(disk.path))
}

fn locate_debugfs() -> Option<PathBuf> {
    for candidate in [
        "/usr/sbin/debugfs",
        "/sbin/debugfs",
        "/usr/bin/debugfs",
        "/bin/debugfs",
    ] {
        let path = Path::new(candidate);
        if path.is_file() {
            return Some(path.to_path_buf());
        }
    }
    which::which("debugfs").ok()
}

fn debugfs_cat(debugfs: &Path, image: &Path, guest_path: &str) -> Result<Option<String>, String> {
    let output = Command::new(debugfs)
        .args(["-R", &format!("cat {guest_path}")])
        .arg(image)
        .output()
        .map_err(|e| format!("spawn {}: {e}", debugfs.display()))?;
    if output.status.success() {
        return Ok(Some(String::from_utf8_lossy(&output.stdout).into_owned()));
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    if stderr.contains("File not found") || stderr.contains("not found") {
        return Ok(None);
    }
    Err(format!(
        "status {:?}; stderr: {}",
        output.status.code(),
        stderr.trim()
    ))
}

fn diagnose_log_path(label: &str, path: &Path) -> String {
    if !path.exists() {
        return format!("{label}: missing ({})", path.display());
    }
    match std::fs::metadata(path) {
        Ok(metadata) if metadata.len() == 0 => {
            format!("{label}: present but empty ({})", path.display())
        }
        Ok(_) => match read_last_bytes_of(path, 4096) {
            Ok(tail) => format!("{label}: {}\n{}", path.display(), tail.trim_end()),
            Err(err) => format!(
                "{label}: present but unreadable ({}): {err}",
                path.display()
            ),
        },
        Err(err) => format!(
            "{label}: present but unreadable ({}): {err}",
            path.display()
        ),
    }
}

/// Forward bytes newly appended to `file` to `sink`; returns true if any were
/// written. `read_to_end` resumes from the file's current offset, so repeated
/// calls stream only the freshly-appended tail. Extracted so the tail behaviour
/// is unit-testable without a thread or a VM. Write errors are swallowed — the
/// echo must never fail a build.
#[cfg(any(feature = "builder-vm", test))]
fn drain_appended(file: &mut std::fs::File, sink: &mut impl std::io::Write) -> bool {
    use std::io::Read;
    let mut chunk = Vec::new();
    if file.read_to_end(&mut chunk).is_ok() && !chunk.is_empty() {
        let _ = sink.write_all(&chunk);
        let _ = sink.flush();
        return true;
    }
    false
}

/// Verbose iff `RUST_LOG` is set. `mvm-build` sits *below* `mvm-backend`, so it
/// can't call `ui::is_verbose()`; the CLI defines verbose as `-v` OR a user-set
/// `RUST_LOG` and exports `RUST_LOG` on `-v`, so `RUST_LOG`'s presence is the
/// equivalent signal at this layer. Crate-visible: both the nix-stream
/// streamer here and the host-side supervisor rebuild in `libkrun_builder`
/// read the same signal.
#[cfg(feature = "builder-vm")]
pub(crate) fn verbose_from_env() -> bool {
    std::env::var_os("RUST_LOG").is_some()
}

/// Streams the in-builder-VM nix build log to the terminal as the build runs.
///
/// `mvmctl build image` / `template build` run `nix … --print-build-logs`
/// inside the builder VM, redirecting stderr to `<job_dir>/nix-stderr.log` on
/// the `/job` virtio-fs share — host-readable and appended live. Until now the
/// host only read it *after* a failure; this tails it to stderr while the build
/// runs, but only when verbose (`-v`/`RUST_LOG`). Quiet builds spawn no thread
/// and pay nothing. Stops + drains on drop, so the closing lines aren't lost.
#[cfg(feature = "builder-vm")]
pub(crate) struct JobLogStreamer {
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

#[cfg(feature = "builder-vm")]
impl JobLogStreamer {
    /// Start streaming `nix_stderr_log` to stderr if verbose; otherwise a no-op
    /// guard (no thread).
    pub(crate) fn start(nix_stderr_log: std::path::PathBuf) -> Self {
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        if !verbose_from_env() {
            return Self { stop, handle: None };
        }
        let thread_stop = std::sync::Arc::clone(&stop);
        let handle = std::thread::spawn(move || {
            tail_forward(
                &nix_stderr_log,
                &thread_stop,
                std::time::Duration::from_millis(200),
            );
        });
        Self {
            stop,
            handle: Some(handle),
        }
    }
}

#[cfg(feature = "builder-vm")]
impl Drop for JobLogStreamer {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

/// Tail loop: open `log_path` (retrying each poll until the in-guest build
/// creates it on first write), forward freshly-appended bytes until `stop`,
/// then one final drain to capture the tail written after the last poll.
#[cfg(feature = "builder-vm")]
fn tail_forward(
    log_path: &std::path::Path,
    stop: &std::sync::atomic::AtomicBool,
    poll: std::time::Duration,
) {
    use std::sync::atomic::Ordering;
    let mut file: Option<std::fs::File> = None;
    let mut stderr = std::io::stderr();
    while !stop.load(Ordering::SeqCst) {
        if file.is_none() && log_path.exists() {
            file = std::fs::File::open(log_path).ok();
        }
        if let Some(ref mut f) = file {
            let _ = drain_appended(f, &mut stderr);
        }
        std::thread::sleep(poll);
    }
    if let Some(ref mut f) = file {
        let _ = drain_appended(f, &mut stderr);
    }
}

/// Finalize a flake build: read the guest result from `<job_dir>/result` or its
/// host-visible mirror in `artifact_out`, validate the `rootfs.ext4` (and
/// optional `vmlinux`) landed in `artifact_out`,
/// return a [`BuilderArtifacts::Image`]. Hypervisor-agnostic — the
/// inputs are all host paths into virtio-fs shares libkrun and HVF
/// both attach identically.
pub fn finalize_flake_job(
    job_dir: &Path,
    artifact_out: &Path,
    job_id: &str,
) -> Result<BuilderArtifacts, BuilderVmError> {
    let result = read_flake_job_result(job_dir, artifact_out)?;
    if result.exit_code != 0 {
        // The 20-line `stderr_tail` in `result` is from the OUTER
        // cmd.sh (run_job captures cmd.sh's stderr into a 20-line
        // ringbuffer). That ringbuffer typically only carries the
        // "nix build exited N; tail of stderr:" preamble — not the
        // real per-derivation failure. The actual nix-build stderr
        // is at `<job_dir>/nix-stderr.log` (cmd.sh redirects there
        // via `2> /job/nix-stderr.log`). Surface its tail so the
        // operator doesn't have to know the convention.
        let stderr_log = job_dir.join("nix-stderr.log");
        let derivation_tail = read_last_bytes_of(&stderr_log, 4 * 1024)
            .unwrap_or_else(|_| String::from("<nix-stderr.log not present on host>"));

        // A dangling/GC'd store path makes every build fail identically
        // (the user re-runs and "loops"). Detect that exact nix signature and
        // return the one-line recovery instead of the opaque build error.
        if let Some(line) = crate::builder_vm::dangling_store_path_line(&derivation_tail)
            .or_else(|| crate::builder_vm::dangling_store_path_line(&result.stderr_tail))
        {
            return Err(BuilderVmError::DegradedBuilderStore {
                cache_dir: crate::builder_vm::builder_vm_cache_dir()
                    .display()
                    .to_string(),
                log_path: stderr_log.display().to_string(),
                detail: line.trim().to_string(),
            });
        }

        return Err(BuilderVmError::NixBuildFailed(format!(
            "guest cmd.sh exited {} — full log: {}\n\
             outer stderr tail (cmd.sh ringbuffer):\n{}\n\
             derivation stderr tail (last 4 KiB of {}):\n{}",
            result.exit_code,
            stderr_log.display(),
            result.stderr_tail,
            stderr_log.display(),
            derivation_tail,
        )));
    }

    let rootfs_path = artifact_out.join("rootfs.ext4");
    if !rootfs_path.is_file() {
        return Err(BuilderVmError::ExtractionFailed(format!(
            "builder VM exited cleanly but {} was not written",
            rootfs_path.display()
        )));
    }
    let kernel_path_out = artifact_out.join("vmlinux");
    let kernel_path = if kernel_path_out.is_file() {
        Some(kernel_path_out)
    } else {
        None
    };

    Ok(BuilderArtifacts::Image {
        rootfs_path,
        kernel_path,
        revision_hash: read_revision_hash(job_dir).unwrap_or_else(|| job_id.to_string()),
        lock_hash: None,
        accessible: None,
    })
}

fn read_flake_job_result(job_dir: &Path, artifact_out: &Path) -> Result<JobResult, BuilderVmError> {
    // Guest init writes the same result to both writable shares. Some VMM/FUSE
    // combinations can lose one share's final write during power-off, so accept
    // the mirror only when the primary file is absent. A malformed primary
    // remains a hard failure and cannot be hidden by the mirror.
    match read_job_result(job_dir) {
        Ok(result) => Ok(result),
        Err(BuilderVmError::NixBuildFailed(primary)) => match read_job_result(artifact_out) {
            Ok(result) => Ok(result),
            Err(BuilderVmError::NixBuildFailed(_)) => Err(BuilderVmError::NixBuildFailed(format!(
                "{primary}; mirrored result was also absent at {}",
                artifact_out.join("result").display()
            ))),
            Err(err) => Err(err),
        },
        Err(err) => Err(err),
    }
}

/// Read `<job_dir>/store-path` and extract the leading Nix store hash
/// from `/nix/store/<hash>-<name>`. Older guest images may not write
/// the sidecar; those callers fall back to the unique job id.
pub fn read_revision_hash(job_dir: &Path) -> Option<String> {
    let body = std::fs::read_to_string(job_dir.join("store-path")).ok()?;
    extract_nix_store_hash(body.trim()).map(str::to_string)
}

fn extract_nix_store_hash(store_path: &str) -> Option<&str> {
    let name = store_path.strip_prefix("/nix/store/")?;
    let (hash, _rest) = name.split_once('-')?;
    if hash.is_empty() { None } else { Some(hash) }
}

/// Parsed shape of `<artifact_out>/result.json` — the install report
/// `mvm-host-vm-init::install::InstallReport::to_json` emits. Field
/// set kept in sync with the writer; an additive change to the writer
/// (egress allowlist diagnostics, for example) needs a matching
/// `#[serde(default)]` field here.
#[derive(Debug, Deserialize)]
pub struct InstallResultReport {
    pub installer_exit_code: i32,
    /// Set when `mvm-host-vm-init` synthesizes a failure report (e.g.
    /// installer binary missing on PATH). Surfaced in the host-side
    /// error message.
    #[serde(default)]
    pub failure_reason: Option<String>,
}

/// Finalize an install job: validate the install report
/// `mvm-host-vm-init` wrote to
/// `<artifact_out>/result.json`, fail closed on
/// `installer_exit_code != 0`, and return
/// [`BuilderArtifacts::InstallVolume`] pointing at the directory.
/// Sealing the volume (via `mvm_sdk::compile::deps_audit::seal_volume`)
/// and renaming into the deps cache is the orchestrator's job
/// (`mvm_build::app_deps::install_app_deps`) — keeping it out of the
/// builder VM means the same code path covers fresh installs and
/// cache rehydrations.
pub fn finalize_install_job(artifact_out: &Path) -> Result<BuilderArtifacts, BuilderVmError> {
    let result_path = artifact_out.join(INSTALL_RESULT_FILENAME);
    if !result_path.is_file() {
        return Err(BuilderVmError::ExtractionFailed(format!(
            "install job VM exited cleanly but {} was not written",
            result_path.display()
        )));
    }
    let body = std::fs::read_to_string(&result_path).map_err(|e| {
        BuilderVmError::ExtractionFailed(format!("reading {}: {e}", result_path.display()))
    })?;
    let report: InstallResultReport = serde_json::from_str(&body).map_err(|e| {
        BuilderVmError::ExtractionFailed(format!(
            "parsing {} as JSON: {e}\nbody:\n{body}",
            result_path.display()
        ))
    })?;

    if report.installer_exit_code != 0 {
        let reason = report
            .failure_reason
            .clone()
            .unwrap_or_else(|| format!("installer exited {}", report.installer_exit_code));
        return Err(BuilderVmError::NixBuildFailed(format!(
            "install pipeline failed inside builder VM: {reason}"
        )));
    }

    // The four sealed-volume artifacts must all be present —
    // mvm-host-vm-init emits stubs on missing optional tooling
    // (SBOM / CVE) so absence here means the guest crashed mid-
    // pipeline. seal_volume would catch this too, but failing
    // closed at the builder layer pins the error to the right
    // diagnostic message.
    for name in ["content", "sbom.cdx.json", "fetch.log", "cve.json"] {
        let p = artifact_out.join(name);
        if !p.exists() {
            return Err(BuilderVmError::ExtractionFailed(format!(
                "install job VM exited cleanly but sealed-volume artifact {} is missing",
                p.display()
            )));
        }
    }

    Ok(BuilderArtifacts::InstallVolume {
        volume_dir: artifact_out.to_path_buf(),
        result_json_path: result_path,
    })
}

/// Format the [`BuilderVmError`] returned when the supervisor exited
/// non-zero before the guest had a chance to write `/job/result`.
/// Names `vm_state_dir` so the operator can grep the console log
/// (`<vm_state_dir>/console.log`) for the guest's pre-shutdown stderr.
///
/// Hypervisor-agnostic: the message references the per-VM state
/// directory, which both libkrun and HVF expose under the same name.
/// Migrated from `libkrun_builder.rs`. The libkrun path produced this
/// exact error from two call sites; lifting it removes the drift risk
/// if one site changes wording but not the other.
pub fn supervisor_exit_error(exit_code: i32, vm_state_dir: &Path) -> BuilderVmError {
    BuilderVmError::SupervisorExited {
        exit_code,
        vm_state_dir: vm_state_dir.display().to_string(),
    }
}

/// Format the [`BuilderVmError`] returned when the guest's cmd.sh
/// exited non-zero. `stderr_tail` is the 20-line ringbuffer
/// `mvm-host-vm-init` captured from cmd.sh's stderr —
/// surfaced as-is so the operator sees the last few lines without
/// having to read the `/job/result` JSON or chase the full log.
///
/// For full flake builds, prefer [`finalize_flake_job`] — it pairs
/// the outer ringbuffer with the tail of `<job_dir>/nix-stderr.log`
/// so the real per-derivation failure isn't hidden behind cmd.sh's
/// "nix build exited N" preamble. This helper covers the shell-job
/// path (e.g. `run_shell_script`), where there's no separate
/// nix-stderr.log to surface.
pub fn shell_job_exit_error(exit_code: i32, stderr_tail: &str) -> BuilderVmError {
    BuilderVmError::NixBuildFailed(format!(
        "guest shell job exited {exit_code} — stderr tail:\n{stderr_tail}"
    ))
}

/// Resolve the wall-clock timeout for a single builder-VM run.
/// Reads [`MVM_BUILDER_VM_TIMEOUT_SECS_ENV`] from the host env;
/// returns [`DEFAULT_BUILDER_VM_TIMEOUT`] when unset.
///
/// Both backends (libkrun + HVF) thread the returned [`Duration`] into
/// their per-VM-run timer so a stuck guest doesn't pin a Cargo job
/// indefinitely. Migrated from `libkrun_builder.rs`. The env var name
/// is intentionally hypervisor-agnostic; the policy is the same on
/// both paths.
///
/// Rejects zero so a typo (`MVM_BUILDER_VM_TIMEOUT_SECS=0`) doesn't
/// silently disable the timeout. Operators that want "no limit" should
/// pass a very large value.
pub fn builder_vm_timeout() -> Result<Duration, BuilderVmError> {
    let Some(raw) = std::env::var_os(MVM_BUILDER_VM_TIMEOUT_SECS_ENV) else {
        return Ok(DEFAULT_BUILDER_VM_TIMEOUT);
    };
    let raw = raw.to_string_lossy();
    let secs = raw.parse::<u64>().map_err(|e| {
        BuilderVmError::ExtractionFailed(format!(
            "{MVM_BUILDER_VM_TIMEOUT_SECS_ENV} must be an integer number of seconds, got {raw:?}: {e}"
        ))
    })?;
    if secs == 0 {
        return Err(BuilderVmError::ExtractionFailed(format!(
            "{MVM_BUILDER_VM_TIMEOUT_SECS_ENV} must be greater than zero"
        )));
    }
    Ok(Duration::from_secs(secs))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder_vm::{BuilderVmDisk, BuilderVmExitInfo, BuilderVmMount, BuilderVmRunConfig};
    use mvm_core::util::test_env::TestEnv;
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    #[test]
    fn drain_appended_forwards_only_freshly_written_bytes() {
        use std::io::Write;
        let dir = tempfile::TempDir::new().unwrap();
        let log = dir.path().join("nix-stderr.log");
        std::fs::write(&log, b"building '/nix/store/aaa.drv'...\n").unwrap();

        let mut reader = std::fs::File::open(&log).unwrap();
        let mut sink: Vec<u8> = Vec::new();

        // First drain forwards the whole current contents.
        assert!(drain_appended(&mut reader, &mut sink));
        assert_eq!(sink, b"building '/nix/store/aaa.drv'...\n");

        // Append more; the next drain resumes from the file offset and forwards
        // only the new tail — not the bytes already streamed.
        let mut appender = std::fs::OpenOptions::new().append(true).open(&log).unwrap();
        appender
            .write_all(b"building '/nix/store/bbb.drv'...\n")
            .unwrap();
        assert!(drain_appended(&mut reader, &mut sink));
        assert_eq!(
            sink,
            b"building '/nix/store/aaa.drv'...\nbuilding '/nix/store/bbb.drv'...\n"
        );

        // Nothing new → no write, no duplication.
        assert!(!drain_appended(&mut reader, &mut sink));
        assert_eq!(
            sink,
            b"building '/nix/store/aaa.drv'...\nbuilding '/nix/store/bbb.drv'...\n"
        );
    }

    /// Minimal backend that records every call. Same shape as the
    /// mock in `builder_vm::vm_backend_for_builder_tests`, but
    /// re-defined here because that mock lives inside `#[cfg(test)]`
    /// in the sibling module and isn't visible across the module
    /// boundary. As the helper grows, this fixture grows with it.
    #[derive(Default)]
    struct CountingBackend {
        run_calls: std::sync::atomic::AtomicUsize,
        console_calls: std::sync::atomic::AtomicUsize,
    }

    impl VmBackendForBuilder for CountingBackend {
        fn run_attached_with_mounts(
            &self,
            _config: &BuilderVmRunConfig,
            _mounts: &[BuilderVmMount],
            _extra_disks: &[BuilderVmDisk],
            _timeout: Duration,
        ) -> Result<BuilderVmExitInfo, crate::builder_vm::BuilderVmError> {
            self.run_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(BuilderVmExitInfo {
                exit_code: Some(0),
                panic_line: None,
            })
        }

        fn console_log_path(&self, vm_state_dir: &Path) -> PathBuf {
            self.console_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            vm_state_dir.join("console.log")
        }
    }

    #[test]
    fn runtime_borrows_backend_for_lifetime_of_run() {
        let backend = CountingBackend::default();
        let runtime = BuilderVmRuntime::new(&backend);
        // Backend accessor returns the same trait object we passed
        // in; future helper methods will use it to dispatch.
        let log = runtime
            .backend()
            .console_log_path(Path::new("/tmp/state/foo"));
        assert_eq!(log, PathBuf::from("/tmp/state/foo/console.log"));
        assert_eq!(
            backend
                .console_calls
                .load(std::sync::atomic::Ordering::SeqCst),
            1
        );
    }

    #[test]
    fn runtime_is_zero_cost_to_construct() {
        // Construction is a single pointer + vtable; no fs / VM /
        // network ops fire. This test pins that contract — a
        // subsequent commit that adds expensive setup to
        // `BuilderVmRuntime::new` would break it.
        let backend = CountingBackend::default();
        let _runtime = BuilderVmRuntime::new(&backend);
        assert_eq!(
            backend.run_calls.load(std::sync::atomic::Ordering::SeqCst),
            0
        );
        assert_eq!(
            backend
                .console_calls
                .load(std::sync::atomic::Ordering::SeqCst),
            0
        );
    }

    #[test]
    fn read_job_result_parses_well_formed_json() {
        let scratch = tempfile::TempDir::new().unwrap();
        let job_dir = scratch.path().to_path_buf();
        std::fs::write(
            job_dir.join("result"),
            r#"{"exit_code":0,"stderr_tail":"hello"}"#,
        )
        .unwrap();
        let r = read_job_result(&job_dir).unwrap();
        assert_eq!(r.exit_code, 0);
        assert_eq!(r.stderr_tail, "hello");
    }

    #[test]
    fn read_job_result_defaults_stderr_tail_when_absent() {
        // `#[serde(default)]` on stderr_tail. A guest that
        // exited before writing stderr_tail (rare, but possible
        // under panic) still parses cleanly.
        let scratch = tempfile::TempDir::new().unwrap();
        let job_dir = scratch.path().to_path_buf();
        std::fs::write(job_dir.join("result"), r#"{"exit_code":2}"#).unwrap();
        let r = read_job_result(&job_dir).unwrap();
        assert_eq!(r.exit_code, 2);
        assert_eq!(r.stderr_tail, "");
    }

    #[test]
    fn read_job_result_errors_when_missing() {
        let scratch = tempfile::TempDir::new().unwrap();
        let err = read_job_result(scratch.path()).unwrap_err();
        assert!(matches!(err, BuilderVmError::NixBuildFailed(_)));
    }

    #[test]
    fn read_job_result_with_diagnostics_includes_vm_logs_on_missing_result() {
        let scratch = tempfile::TempDir::new().unwrap();
        let vm_state_dir = scratch.path().join("vm-state");
        let persistent_store_image = scratch.path().join("nix-store.img");
        std::fs::create_dir_all(&vm_state_dir).unwrap();
        std::fs::write(vm_state_dir.join("console.log"), b"console line\n").unwrap();
        std::fs::write(vm_state_dir.join("supervisor.stderr.log"), b"stderr line\n").unwrap();
        std::fs::write(vm_state_dir.join("supervisor.stdout.log"), b"").unwrap();
        std::fs::write(
            vm_state_dir.join("supervisor.lifecycle.log"),
            b"dispatch_route: direct\n",
        )
        .unwrap();
        std::fs::write(
            vm_state_dir.join("supervisor-config.json"),
            format!(
                r#"{{"krun":{{"extra_disks":[{{"id":"nix-store","path":"{}"}},{{"id":"input","path":"{}"}}]}}}}"#,
                persistent_store_image.display(),
                scratch.path().join("input.img").display(),
            ),
        )
        .unwrap();
        std::fs::write(
            scratch.path().join("mvm-host-vm-init.lifecycle.log"),
            b"virtiofs_mount_ok: job->/job\n",
        )
        .unwrap();

        let err = read_job_result_with_diagnostics(scratch.path(), &vm_state_dir).unwrap_err();
        let msg = match err {
            BuilderVmError::NixBuildFailed(msg) => msg,
            other => panic!("expected NixBuildFailed, got {other:?}"),
        };
        assert!(msg.contains("guest did not write"));
        assert!(msg.contains(&format!("builder VM state dir: {}", vm_state_dir.display())));
        assert!(msg.contains(&format!("builder job dir: {}", scratch.path().display())));
        assert!(msg.contains("console.log:"));
        assert!(msg.contains("console line"));
        assert!(msg.contains("supervisor.stdout.log: present but empty"));
        assert!(msg.contains("supervisor.stderr.log:"));
        assert!(msg.contains("stderr line"));
        assert!(msg.contains("supervisor.lifecycle.log:"));
        assert!(msg.contains("dispatch_route: direct"));
        assert!(msg.contains("supervisor-config.json:"));
        assert!(msg.contains("mvm-host-vm-init.lifecycle.log:"));
        assert!(msg.contains("virtiofs_mount_ok: job->/job"));
        assert!(msg.contains("persistent nix-store init lifecycle"));
    }

    #[test]
    fn persistent_nix_store_image_is_resolved_from_supervisor_config() {
        let scratch = tempfile::TempDir::new().unwrap();
        let config = scratch.path().join("supervisor-config.json");
        std::fs::write(
            &config,
            r#"{"krun":{"extra_disks":[{"id":"input","path":"/tmp/input.img"},{"id":"nix-store","path":"/var/cache/mvm/nix-store-x86_64.img"}]}}"#,
        )
        .unwrap();
        assert_eq!(
            persistent_nix_store_image_from_supervisor_config(&config),
            Some(PathBuf::from("/var/cache/mvm/nix-store-x86_64.img"))
        );
    }

    #[test]
    fn read_job_result_errors_on_malformed_json() {
        // New coverage relative to the libkrun-side tests: the
        // ExtractionFailed arm wasn't exercised before. Pinning it
        // here means a future change to the error mapping (e.g.
        // collapsing both arms) breaks visibly.
        let scratch = tempfile::TempDir::new().unwrap();
        std::fs::write(scratch.path().join("result"), "{not valid json").unwrap();
        let err = read_job_result(scratch.path()).unwrap_err();
        assert!(matches!(err, BuilderVmError::ExtractionFailed(_)));
    }

    // -----------------------------------------------------------------
    // Tests migrated from libkrun_builder.rs alongside finalize_*.
    // -----------------------------------------------------------------

    #[test]
    fn extract_nix_store_hash_parses_output_path() {
        assert_eq!(
            extract_nix_store_hash("/nix/store/abc123def4567890-tenant-rootfs"),
            Some("abc123def4567890")
        );
        assert_eq!(extract_nix_store_hash("/tmp/not-store"), None);
        assert_eq!(extract_nix_store_hash("/nix/store/-missing-hash"), None);
    }

    #[test]
    fn finalize_flake_job_uses_store_path_hash_when_present() {
        let scratch = tempfile::TempDir::new().unwrap();
        let job_dir = scratch.path().join("job");
        let artifact_out = scratch.path().join("out");
        std::fs::create_dir_all(&job_dir).unwrap();
        std::fs::create_dir_all(&artifact_out).unwrap();
        std::fs::write(
            job_dir.join("result"),
            r#"{"exit_code":0,"stderr_tail":""}"#,
        )
        .unwrap();
        std::fs::write(
            job_dir.join("store-path"),
            "/nix/store/deadbeefcafebabe-builder-vm\n",
        )
        .unwrap();
        std::fs::write(artifact_out.join("rootfs.ext4"), b"rootfs").unwrap();

        let artifacts = finalize_flake_job(&job_dir, &artifact_out, "fallback-job-id").unwrap();
        match artifacts {
            BuilderArtifacts::Image { revision_hash, .. } => {
                assert_eq!(revision_hash, "deadbeefcafebabe");
            }
            other => panic!("wrong artifact variant: {other:?}"),
        }
    }

    #[test]
    fn finalize_flake_job_falls_back_to_job_id_without_store_path() {
        let scratch = tempfile::TempDir::new().unwrap();
        let job_dir = scratch.path().join("job");
        let artifact_out = scratch.path().join("out");
        std::fs::create_dir_all(&job_dir).unwrap();
        std::fs::create_dir_all(&artifact_out).unwrap();
        std::fs::write(
            job_dir.join("result"),
            r#"{"exit_code":0,"stderr_tail":""}"#,
        )
        .unwrap();
        std::fs::write(artifact_out.join("rootfs.ext4"), b"rootfs").unwrap();

        let artifacts = finalize_flake_job(&job_dir, &artifact_out, "fallback-job-id").unwrap();
        match artifacts {
            BuilderArtifacts::Image { revision_hash, .. } => {
                assert_eq!(revision_hash, "fallback-job-id");
            }
            other => panic!("wrong artifact variant: {other:?}"),
        }
    }

    #[test]
    fn finalize_flake_job_reads_mirrored_result_from_artifact_out() {
        let scratch = tempfile::TempDir::new().unwrap();
        let job_dir = scratch.path().join("job");
        let artifact_out = scratch.path().join("out");
        std::fs::create_dir_all(&job_dir).unwrap();
        std::fs::create_dir_all(&artifact_out).unwrap();
        std::fs::write(
            artifact_out.join("result"),
            r#"{"exit_code":0,"stderr_tail":""}"#,
        )
        .unwrap();
        std::fs::write(artifact_out.join("rootfs.ext4"), b"rootfs").unwrap();

        let artifacts = finalize_flake_job(&job_dir, &artifact_out, "fallback-job-id").unwrap();
        assert!(matches!(artifacts, BuilderArtifacts::Image { .. }));
    }

    /// `read_last_bytes_of` returns the trailing `max_bytes` of a
    /// file. When the file is larger than the cap, we get the *end*,
    /// not the head — the use case is tailing nix-build stderr where
    /// the cause-of-death is at the bottom.
    #[test]
    fn read_last_bytes_of_returns_trailing_window_when_file_exceeds_cap() {
        let scratch = tempfile::TempDir::new().unwrap();
        let path = scratch.path().join("log");
        let mut body = String::new();
        for i in 0..2_000 {
            body.push_str(&format!("line {i}\n"));
        }
        std::fs::write(&path, &body).unwrap();
        let tail = read_last_bytes_of(&path, 200).unwrap();
        assert!(tail.len() <= 200);
        assert!(tail.contains("line 1999"), "tail contains the last line");
        assert!(
            !tail.contains("line 0\n"),
            "tail does not include the head: {tail}"
        );
    }

    /// Small file: the helper returns the whole file (capped at its
    /// real length, not the requested max).
    #[test]
    fn read_last_bytes_of_returns_entire_file_when_smaller_than_cap() {
        let scratch = tempfile::TempDir::new().unwrap();
        let path = scratch.path().join("log");
        std::fs::write(&path, b"hello world").unwrap();
        let tail = read_last_bytes_of(&path, 4096).unwrap();
        assert_eq!(tail, "hello world");
    }

    /// Missing file surfaces as an `io::Error`; the caller in
    /// `finalize_flake_job` swallows it into a `<not present>`
    /// sentinel rather than failing the whole error format.
    #[test]
    fn read_last_bytes_of_errors_on_missing_file() {
        let scratch = tempfile::TempDir::new().unwrap();
        let err = read_last_bytes_of(&scratch.path().join("missing"), 1024).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    }

    /// The failure-path error message names the nix-stderr.log path
    /// AND inlines its tail. Diagnostic-surface fix — before the
    /// change, callers got the outer cmd.sh ringbuffer only, with no
    /// hint where the real log lived.
    #[test]
    fn finalize_flake_job_failure_includes_nix_stderr_log_path_and_tail() {
        let scratch = tempfile::TempDir::new().unwrap();
        let job_dir = scratch.path().join("job");
        let artifact_out = scratch.path().join("out");
        std::fs::create_dir_all(&job_dir).unwrap();
        std::fs::create_dir_all(&artifact_out).unwrap();
        std::fs::write(
            job_dir.join("result"),
            r#"{"exit_code":1,"stderr_tail":"outer-tail"}"#,
        )
        .unwrap();
        // Sentinel string the helper must surface — proves we're
        // reading from THIS file and not from the outer ringbuffer.
        std::fs::write(
            job_dir.join("nix-stderr.log"),
            "/nix/store/.../cargo-install-hook.sh: line 27: /dev/fd/63: No such file or directory\n",
        )
        .unwrap();

        let err = finalize_flake_job(&job_dir, &artifact_out, "job-id").unwrap_err();
        let msg = match err {
            BuilderVmError::NixBuildFailed(s) => s,
            other => panic!("expected NixBuildFailed, got {other:?}"),
        };
        assert!(msg.contains("exited 1"), "names exit code: {msg}");
        let log_path = job_dir.join("nix-stderr.log");
        assert!(
            msg.contains(&*log_path.to_string_lossy()),
            "names the full log path: {msg}"
        );
        assert!(
            msg.contains("/dev/fd/63: No such file or directory"),
            "inlines the real derivation stderr tail: {msg}"
        );
        assert!(
            msg.contains("outer-tail"),
            "still includes the outer ringbuffer for context: {msg}"
        );
    }

    /// Missing `nix-stderr.log` doesn't crash the formatter — we get
    /// a clean sentinel instead of an `Err(...)` cascade. Matters for
    /// very-early failures (e.g. cmd.sh exit before the
    /// `2> /job/nix-stderr.log` redirect runs).
    #[test]
    fn finalize_flake_job_failure_handles_missing_nix_stderr_log_cleanly() {
        let scratch = tempfile::TempDir::new().unwrap();
        let job_dir = scratch.path().join("job");
        let artifact_out = scratch.path().join("out");
        std::fs::create_dir_all(&job_dir).unwrap();
        std::fs::create_dir_all(&artifact_out).unwrap();
        std::fs::write(
            job_dir.join("result"),
            r#"{"exit_code":2,"stderr_tail":"no cmd.sh"}"#,
        )
        .unwrap();

        let err = finalize_flake_job(&job_dir, &artifact_out, "job-id").unwrap_err();
        let msg = match err {
            BuilderVmError::NixBuildFailed(s) => s,
            other => panic!("expected NixBuildFailed, got {other:?}"),
        };
        assert!(
            msg.contains("<nix-stderr.log not present on host>"),
            "sentinel surfaces in place of missing log: {msg}"
        );
        assert!(
            msg.contains("no cmd.sh"),
            "outer tail still surfaces: {msg}"
        );
    }

    #[test]
    fn finalize_install_job_requires_result_json() {
        // Empty artifact dir → ExtractionFailed pointing at the
        // missing result.json. Surfaces guest crashes that prevented
        // mvm-host-vm-init from finalizing the report.
        let scratch = tempfile::TempDir::new().unwrap();
        let err = finalize_install_job(scratch.path()).unwrap_err();
        assert!(matches!(err, BuilderVmError::ExtractionFailed(_)));
        assert!(err.to_string().contains("result.json"), "got {err}");
    }

    #[test]
    fn finalize_install_job_rejects_nonzero_installer_exit() {
        let scratch = tempfile::TempDir::new().unwrap();
        // Populate enough of the layout that the missing-artifacts
        // check doesn't trip first.
        std::fs::create_dir_all(scratch.path().join("content")).unwrap();
        std::fs::write(scratch.path().join("sbom.cdx.json"), b"{}").unwrap();
        std::fs::write(scratch.path().join("fetch.log"), b"").unwrap();
        std::fs::write(scratch.path().join("cve.json"), b"{}").unwrap();
        std::fs::write(
            scratch.path().join(INSTALL_RESULT_FILENAME),
            br#"{"installer_exit_code":1,"sbom_emitted":false,"cve_emitted":false,"language":"python","gate":"dev","content_path":"/out/content","sbom_path":"/out/sbom.cdx.json","fetch_log_path":"/out/fetch.log","cve_path":"/out/cve.json","failure_reason":"lockfile not found"}"#,
        )
        .unwrap();
        let err = finalize_install_job(scratch.path()).unwrap_err();
        match err {
            BuilderVmError::NixBuildFailed(msg) => {
                assert!(msg.contains("lockfile not found"), "got {msg}");
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn finalize_install_job_returns_install_volume_on_happy_path() {
        let scratch = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(scratch.path().join("content")).unwrap();
        std::fs::write(scratch.path().join("sbom.cdx.json"), b"{}").unwrap();
        std::fs::write(scratch.path().join("fetch.log"), b"").unwrap();
        std::fs::write(scratch.path().join("cve.json"), b"{}").unwrap();
        std::fs::write(
            scratch.path().join(INSTALL_RESULT_FILENAME),
            br#"{"installer_exit_code":0,"sbom_emitted":true,"cve_emitted":true,"language":"python","gate":"prod","content_path":"/out/content","sbom_path":"/out/sbom.cdx.json","fetch_log_path":"/out/fetch.log","cve_path":"/out/cve.json"}"#,
        )
        .unwrap();
        let art = finalize_install_job(scratch.path()).unwrap();
        match art {
            BuilderArtifacts::InstallVolume {
                volume_dir,
                result_json_path,
            } => {
                assert_eq!(volume_dir, scratch.path());
                assert_eq!(
                    result_json_path,
                    scratch.path().join(INSTALL_RESULT_FILENAME)
                );
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn finalize_install_job_rejects_missing_sealed_artifact() {
        let scratch = tempfile::TempDir::new().unwrap();
        // result.json says success, but the sealed-volume sidecars
        // are missing. Fail closed so seal_volume doesn't later
        // chase a half-populated dir.
        std::fs::write(
            scratch.path().join(INSTALL_RESULT_FILENAME),
            br#"{"installer_exit_code":0,"sbom_emitted":true,"cve_emitted":true,"language":"python","gate":"dev","content_path":"/out/content","sbom_path":"/out/sbom.cdx.json","fetch_log_path":"/out/fetch.log","cve_path":"/out/cve.json"}"#,
        )
        .unwrap();
        let err = finalize_install_job(scratch.path()).unwrap_err();
        assert!(
            matches!(err, BuilderVmError::ExtractionFailed(_)),
            "got {err:?}"
        );
    }

    #[test]
    fn finalize_install_job_rejects_malformed_result_json() {
        let scratch = tempfile::TempDir::new().unwrap();
        std::fs::write(scratch.path().join(INSTALL_RESULT_FILENAME), b"{not valid").unwrap();
        let err = finalize_install_job(scratch.path()).unwrap_err();
        match err {
            BuilderVmError::ExtractionFailed(msg) => assert!(msg.contains("parsing"), "got {msg}"),
            other => panic!("wrong variant: {other:?}"),
        }
    }

    // -----------------------------------------------------------------
    // supervisor_exit_error + shell_job_exit_error — stderr-tail
    // capture / build failure formatting.
    // -----------------------------------------------------------------

    #[test]
    fn supervisor_exit_error_names_exit_code_and_state_dir() {
        let err = supervisor_exit_error(42, Path::new("/tmp/vmstate/foo"));
        // Distinct `SupervisorExited` variant (VMM-level failure) so the
        // builder dispatch can fall back without masking a real build error.
        let (exit_code, vm_state_dir) = match err {
            BuilderVmError::SupervisorExited {
                exit_code,
                vm_state_dir,
            } => (exit_code, vm_state_dir),
            other => panic!("wrong variant: {other:?}"),
        };
        assert_eq!(exit_code, 42);
        assert_eq!(vm_state_dir, "/tmp/vmstate/foo");
        // The Display string keeps the operator-facing wording.
        let msg = format!(
            "{}",
            supervisor_exit_error(42, Path::new("/tmp/vmstate/foo"))
        );
        assert!(msg.contains("non-zero status (42)"), "got: {msg}");
        assert!(msg.contains("/tmp/vmstate/foo"), "got: {msg}");
        assert!(msg.contains("guest stderr at"), "got: {msg}");
    }

    #[test]
    fn shell_job_exit_error_inlines_stderr_tail() {
        let err =
            shell_job_exit_error(7, "warning: implicit declaration\nerror: missing semicolon");
        let msg = match err {
            BuilderVmError::NixBuildFailed(s) => s,
            other => panic!("wrong variant: {other:?}"),
        };
        assert!(msg.contains("exited 7"), "got: {msg}");
        assert!(msg.contains("warning: implicit declaration"), "got: {msg}");
        assert!(msg.contains("missing semicolon"), "got: {msg}");
        // The tail appears on its own line — a newline between the
        // header and the tail is the contract callers rely on when
        // grepping logs.
        assert!(msg.contains("stderr tail:\n"), "got: {msg}");
    }

    #[test]
    fn shell_job_exit_error_handles_empty_tail() {
        // mvm-host-vm-init writes an empty `stderr_tail` when cmd.sh
        // failed before producing any stderr (e.g. SIGKILL via OOM).
        // The error message should still be coherent — no trailing
        // garbage, no panic on the format!.
        let err = shell_job_exit_error(137, "");
        let msg = match err {
            BuilderVmError::NixBuildFailed(s) => s,
            other => panic!("wrong variant: {other:?}"),
        };
        assert!(msg.contains("exited 137"), "got: {msg}");
        assert!(msg.ends_with("stderr tail:\n"), "got: {msg}");
    }

    // -----------------------------------------------------------------
    // builder_vm_timeout — reads MVM_BUILDER_VM_TIMEOUT_SECS from the process
    // env; `TestEnv` serializes env mutation across tests and restores it.
    // -----------------------------------------------------------------

    #[test]
    fn builder_vm_timeout_defaults_when_unset() {
        let mut env = TestEnv::new();
        env.remove(MVM_BUILDER_VM_TIMEOUT_SECS_ENV);
        assert_eq!(builder_vm_timeout().unwrap(), DEFAULT_BUILDER_VM_TIMEOUT);
    }

    #[test]
    fn builder_vm_timeout_parses_positive_seconds() {
        let mut env = TestEnv::new();
        env.set(MVM_BUILDER_VM_TIMEOUT_SECS_ENV, "120");
        assert_eq!(
            builder_vm_timeout().unwrap(),
            std::time::Duration::from_secs(120)
        );
    }

    #[test]
    fn builder_vm_timeout_rejects_zero() {
        let mut env = TestEnv::new();
        env.set(MVM_BUILDER_VM_TIMEOUT_SECS_ENV, "0");
        let err = builder_vm_timeout().unwrap_err();
        assert!(format!("{err}").contains("greater than zero"), "got {err}");
    }

    #[test]
    fn builder_vm_timeout_rejects_non_integer() {
        let mut env = TestEnv::new();
        env.set(MVM_BUILDER_VM_TIMEOUT_SECS_ENV, "not-an-integer");
        let err = builder_vm_timeout().unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("must be an integer"), "got: {msg}");
        // The bad value surfaces in the message so the operator
        // doesn't have to re-check their env to find the typo.
        assert!(msg.contains("not-an-integer"), "got: {msg}");
    }

    // -----------------------------------------------------------------
    // Builder persistent /nix store auto-GC. The cap is resolved on the host
    // and baked into the rendered cmd.sh; `TestEnv` serializes env mutation.
    // -----------------------------------------------------------------

    #[test]
    fn render_flake_cmd_sh_embeds_gc_tail_with_default_cap() {
        let mut env = TestEnv::new();
        env.remove(MVM_BUILDER_STORE_GC_GIB_ENV);
        let body = render_flake_cmd_sh(".", "default", false);
        // Age-based GC is required (keeps the just-built closure warm).
        assert!(
            body.contains("nix-collect-garbage --delete-older-than 14d"),
            "missing GC command in:\n{body}"
        );
        // 24 GiB default → 24 * 1024 * 1024 = 25165824 KiB, baked literal.
        assert!(
            body.contains("-gt 25165824 ]"),
            "missing default cap literal in:\n{body}"
        );
        // GC must be POST-build — after the mvm-meta.json emission block.
        let meta_idx = body.find("mvm-meta.json").expect("meta block present");
        let gc_idx = body.find("nix-collect-garbage").expect("gc present");
        assert!(gc_idx > meta_idx, "GC tail must follow output emission");

        // The warm gcroot must be keyed by build kind so alternating
        // builder-vm-image (bootstrap / stage0) and workload (machine run) builds
        // don't evict each other's closure. Two bounded roots
        // (mvm-warm-builder / mvm-warm-workload), classified from $NIX_OUT's
        // derivation name, registered BEFORE the GC; the pre-fix single
        // mvm-warm-latest root is retired.
        let warm_idx = body
            .find("case \"$(basename \"$NIX_OUT\")\" in")
            .expect("per-kind warm gcroot classifier present");
        assert!(
            body.contains("*-mvm-builder-vm-*) warm=builder"),
            "builder-vm image name must classify as the builder warm root in:\n{body}"
        );
        assert!(
            body.contains("warm=workload"),
            "non-builder builds must classify as the workload warm root in:\n{body}"
        );
        assert!(
            body.contains("--add-root \"/nix/var/nix/gcroots/mvm-warm-$warm\""),
            "warm gcroot must add-root the per-kind name in:\n{body}"
        );
        assert!(
            body.contains("ln -sfn \"$NIX_OUT\" \"/nix/var/nix/gcroots/mvm-warm-$warm\""),
            "warm gcroot must fall back to an ln symlink of $NIX_OUT in:\n{body}"
        );
        assert!(
            body.contains("rm -f /nix/var/nix/gcroots/mvm-warm-latest"),
            "the pre-fix single mvm-warm-latest root must be retired in:\n{body}"
        );
        // The pin itself must no longer target the single overwritten root.
        assert!(
            !body.contains("--add-root /nix/var/nix/gcroots/mvm-warm-latest")
                && !body.contains("--add-root \"/nix/var/nix/gcroots/mvm-warm-latest\""),
            "must not pin the single fixed-name mvm-warm-latest root in:\n{body}"
        );
        assert!(
            warm_idx < gc_idx,
            "warm gcroot must be registered before the GC tail"
        );
    }

    #[test]
    fn render_flake_cmd_sh_runs_before_build_hook_before_copying_artifact() {
        let body = render_flake_cmd_sh(".", "default", false);
        // The hook runner is invoked on a writable temp copy so the Nix
        // store output is never modified in place.
        assert!(
            body.contains("/sbin/mvm-host-vm-init run-before-build-hook"),
            "missing before_build hook runner invocation in:\n{body}"
        );
        assert!(
            body.contains("/tmp/mvm-rootfs-before-build.ext4"),
            "missing writable temp rootfs path in:\n{body}"
        );
        // The hook must run before the final rootfs is copied to /out.
        let hook_idx = body
            .find("/sbin/mvm-host-vm-init run-before-build-hook")
            .expect("hook runner present");
        let out_copy_idx = body
            .find(r#"cp -L "$BUILD_HOOK_ROOTFS" /out/rootfs.ext4"#)
            .expect("final rootfs copy present");
        assert!(
            hook_idx < out_copy_idx,
            "before_build hook must run before /out/rootfs.ext4 is copied"
        );
        // A failed hook must fail the build, leaving no partial artifact.
        assert!(
            body.contains("mvm-builder-vm: before_build hook failed"),
            "missing hook failure message in:\n{body}"
        );
        assert!(
            body.contains(r#"rm -f "$BUILD_HOOK_ROOTFS""#),
            "temp rootfs must be cleaned up on hook failure in:\n{body}"
        );
        assert!(
            body.contains(
                "set +e\n/sbin/mvm-host-vm-init run-before-build-hook \"$BUILD_HOOK_ROOTFS\"\nhook_rc=$?\nset -e"
            ),
            "the hook's real exit status must be captured before testing it in:\n{body}"
        );
        assert!(
            !body.contains("if ! /sbin/mvm-host-vm-init run-before-build-hook"),
            "negating the hook command makes `$?` report the `!` result instead of the hook failure"
        );
    }

    #[test]
    fn render_flake_cmd_sh_pins_builder_toolchain_before_gc() {
        let body = render_flake_cmd_sh(".", "default", false);
        // The OCI rootfs materialize job runs /sbin/mkfs.ext4 inside the
        // builder VM but registers no GC root, and a workload build's
        // $NIX_OUT closure never carries e2fsprogs. Without a dedicated root
        // the cap GC reaps the builder's own toolchain, leaving
        // /sbin/mkfs.ext4 a dangling symlink and breaking every later image
        // run. Pin the materialize toolchain under fixed roots, before the GC.
        let pin_idx = body
            .find("/nix/var/nix/gcroots/mvm-builder-tools-")
            .expect("builder-toolchain gcroot present");
        assert!(
            body.contains("tool_root=\"/nix/var/nix/gcroots/mvm-builder-tools-"),
            "toolchain pin must build the gcroot path in:\n{body}"
        );
        assert!(
            body.contains("nix-store --add-root \"$tool_root\" --indirect -r \"$tool_store\""),
            "toolchain pin must register an indirect --add-root in:\n{body}"
        );
        assert!(
            body.contains("/sbin/mkfs.ext4"),
            "toolchain pin must cover mkfs.ext4 in:\n{body}"
        );
        let gc_idx = body.find("nix-collect-garbage").expect("gc present");
        assert!(
            pin_idx < gc_idx,
            "builder-toolchain gcroot must be registered before the GC tail"
        );
    }

    #[test]
    fn builder_store_gc_cap_kib_default_override_and_garbage() {
        let mut env = TestEnv::new();

        // Unset → default 24 GiB in KiB.
        env.remove(MVM_BUILDER_STORE_GC_GIB_ENV);
        assert_eq!(
            builder_store_gc_cap_kib(),
            u64::from(DEFAULT_BUILDER_STORE_GC_GIB) * 1024 * 1024
        );
        assert_eq!(builder_store_gc_cap_kib(), 25_165_824);

        // Valid override → that many GiB in KiB.
        env.set(MVM_BUILDER_STORE_GC_GIB_ENV, "8");
        assert_eq!(builder_store_gc_cap_kib(), 8 * 1024 * 1024);

        // Garbage → fall back to default (best-effort cap, never disabled).
        env.set(MVM_BUILDER_STORE_GC_GIB_ENV, "not-a-number");
        assert_eq!(builder_store_gc_cap_kib(), 25_165_824);

        // Zero → also falls back (zero would GC the just-built closure).
        env.set(MVM_BUILDER_STORE_GC_GIB_ENV, "0");
        assert_eq!(builder_store_gc_cap_kib(), 25_165_824);
    }

    #[test]
    fn stage_closure_seed_dir_copies_only_the_nar_under_its_own_share_dir() {
        let arch_dir = tempfile::TempDir::new().unwrap();
        // The source lives alongside sibling image files the share must never
        // expose — the real arch cache dir holds vmlinux/rootfs.ext4 too.
        std::fs::write(arch_dir.path().join("vmlinux"), b"kernel-bytes").unwrap();
        let nar = arch_dir.path().join("nix-closure.nar");
        std::fs::write(&nar, b"nar-bytes").unwrap();

        let vm_state_dir = tempfile::TempDir::new().unwrap();
        let share_dir = stage_closure_seed_dir(&nar, vm_state_dir.path()).expect("stage");

        assert_eq!(share_dir, vm_state_dir.path().join(CLOSURE_SEED_TAG));
        let entries: Vec<_> = std::fs::read_dir(&share_dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(entries, vec![std::ffi::OsString::from("nix-closure.nar")]);
        assert_eq!(
            std::fs::read(share_dir.join("nix-closure.nar")).unwrap(),
            b"nar-bytes"
        );
    }

    #[test]
    fn stage_closure_seed_dir_uses_the_fixed_closure_file_name() {
        // A source named something other than CLOSURE_FILE must still stage
        // under CLOSURE_FILE — the guest imports that fixed name.
        let src = tempfile::TempDir::new().unwrap();
        let nar = src.path().join("some-other-name.nar");
        std::fs::write(&nar, b"nar-bytes").unwrap();

        let vm_state_dir = tempfile::TempDir::new().unwrap();
        let share_dir = stage_closure_seed_dir(&nar, vm_state_dir.path()).expect("stage");

        let entries: Vec<_> = std::fs::read_dir(&share_dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(
            entries,
            vec![std::ffi::OsString::from(crate::builder_pack::CLOSURE_FILE)]
        );
    }
}
