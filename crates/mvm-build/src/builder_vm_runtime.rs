//! Plan 97 §"Phase C seam design" — hypervisor-agnostic builder-VM
//! orchestration helper.
//!
//! [`BuilderVmRuntime`] is the shared orchestration body that both
//! the libkrun and Vz builder paths route through. It owns the
//! pieces that aren't tied to a specific VMM:
//!
//! - `cmd.sh` emission (Flake jobs) and `install_spec.json` staging
//!   (Install jobs)
//! - `/job/result` JSON parsing
//! - Per-variant artifact finalisation (rootfs path resolution,
//!   revision hash extraction, install-volume sidecar discovery)
//! - Nix store image lock acquisition (libkrun-only concern in
//!   today's runtime; abstracted here for future Vz reuse)
//! - stderr-tail capture for build-failure diagnostics
//! - Wall-clock timeout handling
//!
//! It does **not** own:
//!
//! - Supervisor process lifecycle (lives in the
//!   [`VmBackendForBuilder`] impl — libkrun's
//!   `spawn_supervisor_in_background` / Vz's `run_attached`)
//! - Console-log watching for kernel-panic detection (also lives
//!   in the impl; surfaces through `BuilderVmExitInfo.panic_line`)
//! - Hypervisor-specific config translation (KrunContext vs.
//!   Vz's `SupervisorConfig`)
//!
//! Today the helper is a skeleton. Subsequent commits migrate the
//! concerns above out of `LibkrunBuilderVm.run_build` into here,
//! one at a time. Each migration commit is independently
//! verifiable: build + existing tests stay green, and the new
//! helper methods get their own unit tests.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;

use crate::builder_vm::{BuilderArtifacts, BuilderJob, BuilderVmError, VmBackendForBuilder};

/// Wall-clock timeout for a builder VM run when the operator hasn't
/// overridden it. 30 minutes covers a cold-cache `nix build` of the
/// project's heaviest derivations on a fresh CI runner without
/// punishing fast machines.
pub const DEFAULT_BUILDER_VM_TIMEOUT: Duration = Duration::from_secs(30 * 60);

/// Env var the operator sets to override [`DEFAULT_BUILDER_VM_TIMEOUT`].
/// Plain integer seconds; zero is rejected so a typo doesn't silently
/// disable the safety net.
pub const MVM_BUILDER_VM_TIMEOUT_SECS_ENV: &str = "MVM_BUILDER_VM_TIMEOUT_SECS";

/// Per-job dir filename mvm-host-vm-init detects to dispatch
/// through the application-dependency install pipeline (Plan 73
/// Followup B.2). Migrated from `libkrun_builder.rs` because the
/// install spec staging is a hypervisor-agnostic concern that
/// both the libkrun and Vz builder paths need.
pub const INSTALL_SPEC_FILENAME: &str = "install_spec.json";

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

/// Stage the per-job dir inside `~/.cache/mvm/builder-vm/jobs/<id>/`
/// so the in-guest `mvm-host-vm-init` finds the right artifact
/// for dispatch:
///
/// - [`BuilderJob::Flake`] → writes `cmd.sh` (the in-guest nix-build
///   script). mvm-host-vm-init runs it after `/work` `/out` `/job`
///   virtio-fs shares are mounted.
/// - [`BuilderJob::Install`] → copies the caller's install-spec JSON
///   to `<job_dir>/install_spec.json`. mvm-host-vm-init detects the
///   filename and dispatches the application-dep install pipeline
///   (Plan 73 Followup B.2) instead of `cmd.sh`.
///
/// Hypervisor-agnostic — the staging produces files in a virtio-fs
/// share; libkrun and Vz both bind-mount the same host dir, so the
/// helper doesn't need to know which VMM is on the other end.
/// Migrated from `libkrun_builder.rs` in Plan 97 Phase C PR-B-migrate.
pub fn stage_job_dir(
    job_dir: &Path,
    job: &BuilderJob,
    mvm_local_override: Option<&Path>,
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
            // `/job/install_spec.json`. `mvm-host-vm-init`
            // (Plan 73 Followup B.2) detects that filename and
            // dispatches through the install pipeline instead of
            // running cmd.sh.
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

    // Plan 120 / ADR-046 source-checkout invariant: when the caller
    // stages a local user flake (`mvm_local_override = Some`), the
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
            format!("FLAKE_REF=\"$(cd \"$(dirname \"$0\")\" && pwd)/{STAGED_WORKLOAD_SUBDIR}\""),
            " --override-input mvm path:/work/nix".to_string(),
        )
    } else {
        (
            format!("FLAKE_REF='{}'", shell_single_quote_escape(flake_ref)),
            String::new(),
        )
    };
    format!(
        r#"#!/bin/sh
# mvm-builder-vm cmd.sh — emitted by BuilderVmRuntime (Plan 97
# Phase C migration; was Plan 72 W4's stage_job_dir).
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
trusted-public-keys = cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY="
# Plan 72 W0's flake convention: workspace-path env var so
# flakes that reference the workspace root don't depend on
# relative-path resolution against the store-copied flake dir.
export MVM_WORKSPACE_PATH=/work
# Plan 115 / ADR-065: host-vm binaries extracted from the mvmctl
# embedded payload and mounted read-only at /mvm-bins. The builder-vm
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
nix build "${{FLAKE_REF}}#${{ATTR_PATH}}"{override_flag} \
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

# Copy the artifacts the host expects into /out. We accept
# either `vmlinux` (the canonical name our flakes use) or
# `Image` / `bzImage` (raw kernel format names) for
# robustness across flake conventions.
if   [ -f "$NIX_OUT/vmlinux" ]; then cp -L "$NIX_OUT/vmlinux" /out/vmlinux
elif [ -f "$NIX_OUT/Image"   ]; then cp -L "$NIX_OUT/Image"   /out/vmlinux
elif [ -f "$NIX_OUT/bzImage" ]; then cp -L "$NIX_OUT/bzImage" /out/vmlinux
fi
if [ -f "$NIX_OUT/rootfs.ext4" ]; then
    cp -L "$NIX_OUT/rootfs.ext4" /out/rootfs.ext4
else
    echo "no rootfs.ext4 in nix build output at $NIX_OUT" >&2
    exit 1
fi

# Permissions for the host-side reader. Ignore failures —
# virtio-fs may map the uid such that chmod is a no-op.
chmod 0644 /out/rootfs.ext4 2>/dev/null || true
[ -f /out/vmlinux ] && chmod 0644 /out/vmlinux 2>/dev/null || true

# W6.2 — emit the mvm-meta.json sidecar next to the rootfs. The runtime
# admission path refuses to boot a rootfs without it (it certifies the
# overlay-aware contract), and the host has no nix, so we eval the
# flake's `passthru.mvm` (the ArtifactManifest) here in the guest.
# mkGuest puts it on the rootfs derivation; an image that wraps the
# rootfs (the builder-vm `dev`/`default` attrs are a runCommand around
# it) surfaces it one level down under `passthru.rootfs`. Try the direct
# attr first, then the wrapped one.
if nix eval --json "${{FLAKE_REF}}#${{ATTR_PATH}}.passthru.mvm" --impure{override_flag} \
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
"#,
        flake_ref_assign = flake_ref_assign,
        override_flag = override_flag,
        attr_path = shell_single_quote_escape(attr_path),
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

/// Parsed `<job_dir>/result` written by `mvm-host-vm-init` (Plan 72
/// W3). Shape matches the JSON `mvm-host-vm-init::linux::write_result`
/// emits. The guest PID 1 writes this on every code path that reaches
/// `power_off`; the host-side helper reads it to learn the guest's
/// exit code and the cmd.sh stderr-tail ringbuffer for diagnostics.
///
/// Hypervisor-agnostic: the file lives in the `/job` virtio-fs share,
/// which both libkrun and Vz attach identically. Migrated from
/// `libkrun_builder.rs` in Plan 97 Phase C (second migration after
/// `stage_job_dir`).
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

/// Finalize a flake build: read `<job_dir>/result`, validate the
/// `rootfs.ext4` (and optional `vmlinux`) landed in `artifact_out`,
/// return a [`BuilderArtifacts::Image`]. Hypervisor-agnostic — the
/// inputs are all host paths into virtio-fs shares libkrun and Vz
/// both attach identically.
pub fn finalize_flake_job(
    job_dir: &Path,
    artifact_out: &Path,
    job_id: &str,
) -> Result<BuilderArtifacts, BuilderVmError> {
    let result = read_job_result(job_dir)?;
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
/// (B.2.x egress allowlist diagnostics, for example) needs a matching
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

/// Finalize an install job (Plan 73 Followup B.2): validate the
/// install report `mvm-host-vm-init` wrote to
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

/// Host-side exclusive lock on the persistent `/nix-store` sparse image.
///
/// The builder VM attaches this file as a writable virtio-blk device;
/// the guest's `mvm-host-vm-init` mounts it as ext4 at `/nix-store`.
/// Two independent guests mounting the same ext4 image read-write can
/// corrupt the filesystem, so the host holds an exclusive `flock` for
/// the full VM lifetime.
///
/// `_file: std::fs::File` is **load-bearing** — dropping the guard
/// releases the lock. Callers must keep the guard alive until the
/// supervisor exits and all artifact reads are done. The seam design
/// in Plan 97 §"Phase C seam design" calls this out explicitly because
/// an underscore-prefixed field reads as inert; it isn't.
///
/// Hypervisor-agnostic: both libkrun and Vz attach the same image
/// path as a virtio-blk device. Migrated from `libkrun_builder.rs` in
/// Plan 97 Phase C PR-B-migrate (fourth migration after
/// `finalize_flake_job` / `finalize_install_job`).
#[derive(Debug)]
pub struct NixStoreImageLock {
    path: PathBuf,
    _file: std::fs::File,
}

impl NixStoreImageLock {
    /// Path to the locked image file. Callers pass this into the
    /// hypervisor as the `virtio-blk` device backing.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Find or create the persistent `<builder_cache_dir>/nix-store-<arch>.img`
/// sparse image and hold an exclusive host-side lock on it.
///
/// `builder_cache_dir` is the host-side root the builder VM uses for
/// shared state — callers compute this themselves (typically
/// `~/.cache/mvm/builder-vm/`) so the helper stays free of
/// `mvm_core::config` lookups. The directory is created if missing.
///
/// `arch` only appears in the filename (`nix-store-<arch>.img`) so
/// multi-arch hosts can keep one image per arch in the same cache.
///
/// `size_mib` is the sparse cap — the file consumes only the bytes
/// the in-VM ext4 actually writes. Caller-controlled because dev
/// hosts may want a smaller cap than CI runners.
///
/// Returns a [`NixStoreImageLock`] guard. Dropping it releases the
/// lock — see the type docs.
pub fn acquire_nix_store_image_lock(
    builder_cache_dir: &Path,
    arch: &str,
    size_mib: u64,
) -> Result<NixStoreImageLock, BuilderVmError> {
    use fs2::FileExt;

    std::fs::create_dir_all(builder_cache_dir).map_err(|e| {
        BuilderVmError::ExtractionFailed(format!(
            "creating builder cache dir {}: {e}",
            builder_cache_dir.display()
        ))
    })?;
    let path = builder_cache_dir.join(format!("nix-store-{arch}.img"));
    let existed_before_open = path.exists();

    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .map_err(|e| BuilderVmError::ExtractionFailed(format!("open {}: {e}", path.display())))?;

    file.try_lock_exclusive().map_err(|e| {
        BuilderVmError::ExtractionFailed(format!(
            "nix-store image {} is already attached by another builder VM process; \
             wait for the running `mvmctl build` / `mvmctl deps install` to finish and retry: {e}",
            path.display()
        ))
    })?;

    // Allocate a sparse file: open with O_CREAT, seek to size-1,
    // write a zero byte. The filesystem records the size but
    // doesn't allocate the blocks until something writes them
    // (true on APFS + ext4). Avoids paying multi-GiB at provision
    // time for a store that may never fill up.
    let size_bytes = size_mib.checked_mul(1024 * 1024).ok_or_else(|| {
        BuilderVmError::ExtractionFailed(format!(
            "nix-store size_mib overflowed multiplying to bytes: {size_mib}"
        ))
    })?;

    let current_len = file.metadata().map_err(|e| {
        BuilderVmError::ExtractionFailed(format!("metadata {}: {e}", path.display()))
    })?;
    if current_len.len() == 0 {
        file.set_len(size_bytes).map_err(|e| {
            if !existed_before_open {
                let _ = std::fs::remove_file(&path);
            }
            BuilderVmError::ExtractionFailed(format!(
                "set_len({size_bytes}) on {}: {e}",
                path.display()
            ))
        })?;
    }

    let current_len = file.metadata().map_err(|e| {
        BuilderVmError::ExtractionFailed(format!("metadata {}: {e}", path.display()))
    })?;
    if current_len.len() == 0 {
        if !existed_before_open {
            let _ = std::fs::remove_file(&path);
        }
        return Err(BuilderVmError::ExtractionFailed(format!(
            "nix-store image {} stayed empty after sparse allocation",
            path.display()
        )));
    }

    Ok(NixStoreImageLock { path, _file: file })
}

/// Format the [`BuilderVmError`] returned when the supervisor exited
/// non-zero before the guest had a chance to write `/job/result`.
/// Names `vm_state_dir` so the operator can grep the console log
/// (`<vm_state_dir>/console.log`) for the guest's pre-shutdown stderr.
///
/// Hypervisor-agnostic: the message references the per-VM state
/// directory, which both libkrun and Vz expose under the same name.
/// Migrated from `libkrun_builder.rs` in Plan 97 Phase C PR-B-migrate
/// (fifth migration after `NixStoreImageLock`). The libkrun path
/// produced this exact error from two call sites; lifting it removes
/// the drift risk if one site changes wording but not the other.
pub fn supervisor_exit_error(exit_code: i32, vm_state_dir: &Path) -> BuilderVmError {
    BuilderVmError::NixBuildFailed(format!(
        "supervisor exited with non-zero status ({exit_code}); \
         guest stderr at {}",
        vm_state_dir.display()
    ))
}

/// Format the [`BuilderVmError`] returned when the guest's cmd.sh
/// exited non-zero. `stderr_tail` is the 20-line ringbuffer
/// `mvm-host-vm-init` captured from cmd.sh's stderr (Plan 72 W3) —
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
/// Both backends (libkrun + Vz) thread the returned [`Duration`] into
/// their per-VM-run timer so a stuck guest doesn't pin a Cargo job
/// indefinitely. Migrated from `libkrun_builder.rs` in Plan 97 Phase C
/// PR-B-migrate (sixth migration). The env var name is intentionally
/// hypervisor-agnostic; the policy is the same on both paths.
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
    use std::path::{Path, PathBuf};
    use std::time::Duration;

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
    // Tests migrated from libkrun_builder.rs alongside finalize_*
    // (Plan 97 Phase C PR-B-migrate commit 4).
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
    // Tests migrated from libkrun_builder.rs alongside NixStoreImageLock
    // and acquire_nix_store_image_lock (Plan 97 Phase C PR-B-migrate
    // commit 5). The new signature takes the cache dir as a &Path arg,
    // so the XDG_CACHE_HOME env hack from the old tests is gone — each
    // test passes a fresh TempDir path directly and runs without
    // process-wide env mutation.
    // -----------------------------------------------------------------

    #[test]
    fn acquire_nix_store_image_lock_creates_sparse_file_once() {
        // Sparse file allocates the logical size but consumes ~no disk
        // blocks. `set_len` is what asks the FS to record the size. A
        // later acquisition finds the existing file and returns its
        // path without retouching.
        let scratch = tempfile::TempDir::new().unwrap();
        let cache_dir = scratch.path().join("builder-vm");
        let guard = acquire_nix_store_image_lock(&cache_dir, "x86_64", 256).unwrap();
        let path = guard.path().to_path_buf();
        assert!(path.is_file());
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 256 * 1024 * 1024);
        drop(guard);
        // Second acquisition is idempotent.
        let guard2 = acquire_nix_store_image_lock(&cache_dir, "x86_64", 256).unwrap();
        let path2 = guard2.path().to_path_buf();
        assert_eq!(path, path2);
        drop(guard2);
    }

    #[test]
    fn acquire_nix_store_image_lock_refuses_concurrent_writer() {
        let scratch = tempfile::TempDir::new().unwrap();
        let cache_dir = scratch.path().join("builder-vm");

        let first = acquire_nix_store_image_lock(&cache_dir, "x86_64", 256).unwrap();
        let err = acquire_nix_store_image_lock(&cache_dir, "x86_64", 256).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("already attached by another builder VM process"),
            "unexpected error: {msg}"
        );
        drop(first);

        acquire_nix_store_image_lock(&cache_dir, "x86_64", 256)
            .expect("lock should be available after first guard drops");
    }

    #[test]
    fn acquire_nix_store_image_lock_filename_carries_arch() {
        // Multi-arch hosts can keep one image per arch in the same
        // cache. Pin the filename convention so a future refactor that
        // collapses the arch out of the path doesn't silently break it.
        let scratch = tempfile::TempDir::new().unwrap();
        let cache_dir = scratch.path().join("builder-vm");
        let guard = acquire_nix_store_image_lock(&cache_dir, "aarch64", 64).unwrap();
        assert_eq!(
            guard.path().file_name().and_then(|s| s.to_str()),
            Some("nix-store-aarch64.img")
        );
    }

    #[test]
    fn acquire_nix_store_image_lock_creates_missing_cache_dir() {
        // `create_dir_all` is part of the contract — callers pass the
        // computed `~/.cache/mvm/builder-vm/` path and expect it to be
        // created on demand.
        let scratch = tempfile::TempDir::new().unwrap();
        let cache_dir = scratch.path().join("not").join("yet").join("created");
        let guard = acquire_nix_store_image_lock(&cache_dir, "x86_64", 16).unwrap();
        assert!(guard.path().is_file());
        assert!(cache_dir.is_dir());
    }

    // -----------------------------------------------------------------
    // supervisor_exit_error + shell_job_exit_error — Plan 97 Phase C
    // PR-B-migrate (fifth migration: stderr-tail capture / build failure
    // formatting).
    // -----------------------------------------------------------------

    #[test]
    fn supervisor_exit_error_names_exit_code_and_state_dir() {
        let err = supervisor_exit_error(42, Path::new("/tmp/vmstate/foo"));
        let msg = match err {
            BuilderVmError::NixBuildFailed(s) => s,
            other => panic!("wrong variant: {other:?}"),
        };
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
    // builder_vm_timeout — Plan 97 Phase C PR-B-migrate (sixth and
    // final pre-VzBuilderVm migration). Reads
    // MVM_BUILDER_VM_TIMEOUT_SECS from the process env; mutation is
    // serialised through TIMEOUT_ENV_LOCK so concurrent test threads
    // don't observe each other's writes.
    // -----------------------------------------------------------------

    use std::sync::{LazyLock, Mutex};

    static TIMEOUT_ENV_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

    #[test]
    fn builder_vm_timeout_defaults_when_unset() {
        let _lock = TIMEOUT_ENV_LOCK.lock().unwrap();
        let old = std::env::var_os(MVM_BUILDER_VM_TIMEOUT_SECS_ENV);
        // SAFETY: tests serialise env mutation via TIMEOUT_ENV_LOCK.
        unsafe {
            std::env::remove_var(MVM_BUILDER_VM_TIMEOUT_SECS_ENV);
        }
        assert_eq!(builder_vm_timeout().unwrap(), DEFAULT_BUILDER_VM_TIMEOUT);
        unsafe {
            match old {
                Some(v) => std::env::set_var(MVM_BUILDER_VM_TIMEOUT_SECS_ENV, v),
                None => std::env::remove_var(MVM_BUILDER_VM_TIMEOUT_SECS_ENV),
            }
        }
    }

    #[test]
    fn builder_vm_timeout_parses_positive_seconds() {
        let _lock = TIMEOUT_ENV_LOCK.lock().unwrap();
        let old = std::env::var_os(MVM_BUILDER_VM_TIMEOUT_SECS_ENV);
        unsafe {
            std::env::set_var(MVM_BUILDER_VM_TIMEOUT_SECS_ENV, "120");
        }
        assert_eq!(
            builder_vm_timeout().unwrap(),
            std::time::Duration::from_secs(120)
        );
        unsafe {
            match old {
                Some(v) => std::env::set_var(MVM_BUILDER_VM_TIMEOUT_SECS_ENV, v),
                None => std::env::remove_var(MVM_BUILDER_VM_TIMEOUT_SECS_ENV),
            }
        }
    }

    #[test]
    fn builder_vm_timeout_rejects_zero() {
        let _lock = TIMEOUT_ENV_LOCK.lock().unwrap();
        let old = std::env::var_os(MVM_BUILDER_VM_TIMEOUT_SECS_ENV);
        unsafe {
            std::env::set_var(MVM_BUILDER_VM_TIMEOUT_SECS_ENV, "0");
        }
        let err = builder_vm_timeout().unwrap_err();
        assert!(format!("{err}").contains("greater than zero"), "got {err}");
        unsafe {
            match old {
                Some(v) => std::env::set_var(MVM_BUILDER_VM_TIMEOUT_SECS_ENV, v),
                None => std::env::remove_var(MVM_BUILDER_VM_TIMEOUT_SECS_ENV),
            }
        }
    }

    #[test]
    fn builder_vm_timeout_rejects_non_integer() {
        let _lock = TIMEOUT_ENV_LOCK.lock().unwrap();
        let old = std::env::var_os(MVM_BUILDER_VM_TIMEOUT_SECS_ENV);
        unsafe {
            std::env::set_var(MVM_BUILDER_VM_TIMEOUT_SECS_ENV, "not-an-integer");
        }
        let err = builder_vm_timeout().unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("must be an integer"), "got: {msg}");
        // The bad value surfaces in the message so the operator
        // doesn't have to re-check their env to find the typo.
        assert!(msg.contains("not-an-integer"), "got: {msg}");
        unsafe {
            match old {
                Some(v) => std::env::set_var(MVM_BUILDER_VM_TIMEOUT_SECS_ENV, v),
                None => std::env::remove_var(MVM_BUILDER_VM_TIMEOUT_SECS_ENV),
            }
        }
    }
}
