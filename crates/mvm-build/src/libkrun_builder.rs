//! Libkrun-backed builder VM.
//!
//! libkrun-direct (on macOS Apple Silicon / Intel) and Firecracker
//! (on Linux) replaced the older builder VM. This module is the
//! libkrun half.
//!
//! ## What `LibkrunBuilderVm` does
//!
//! Given a populated builder VM image cache and a current
//! `mvm-libkrun-supervisor`, `run_build` runs a one-shot `nix build` against the
//! caller's `BuilderJob` and returns `BuilderArtifacts`. The
//! pipeline (in `BuilderVm::run_build`):
//!
//! 1. Validate mounts + job (`validate_mounts`, `validate_job`).
//! 2. Check `libkrun_sys::is_available()` — bail with install hint
//!    if libkrun isn't on the host.
//! 3. Locate or build `mvm-libkrun-supervisor` (env override / next-to-exe /
//!    source checkout build / PATH).
//! 4. Read the builder VM image from
//!    `~/.mvm/cache/builder-vm/<arch>/` — vmlinux + rootfs.ext4 +
//!    cmdline.txt + manifest.json, the shape the builder-vm flake
//!    emits. Populated by `bootstrap_builder_vm_image`
//!    (`mvm-cli::commands::env::builder_vm`).
//! 5. Allocate / reuse the persistent `/nix-store-<arch>.img`
//!    sparse virtio-blk image (64 GiB cap by default; idempotent
//!    across invocations so the warm Nix store survives).
//! 6. Stage `<job_dir>/cmd.sh` with the shell-escaped flake_ref +
//!    attr_path, plus the canonical `nix build` invocation.
//! 7. Build a `KrunContext`: kernel + rootfs + cmdline + per-VM
//!    vsock dir + virtio-blk (Nix store) + virtio-fs (work / out /
//!    job).
//! 8. Spawn `mvm-libkrun-supervisor`, pipe the `SupervisorConfig`
//!    JSON to stdin, **wait** for it to exit (unlike
//!    `LibkrunBackend::start` which returns after the PID file
//!    appears — the builder is a one-shot).
//! 9. Read `<job_dir>/result` (JSON: `{exit_code, stderr_tail}`)
//!    that `mvm-host-vm-init` wrote.
//! 10. Validate the artifact dir now contains `rootfs.ext4` (and
//!     optionally `vmlinux`); return `BuilderArtifacts`.
//!
//! ## Feature gate
//!
//! Gated behind `builder-vm`. Default-off until the cutover flips
//! `ensure_dev_image` to dispatch through `LibkrunBuilderVm`.
//! Library consumers that don't need the libkrun builder build with
//! `default-features = false`.
//!
//! ## Not the runtime backend
//!
//! `LibkrunBackend` (`crates/mvm-runtime/src/libkrun.rs`) is for
//! running user microVMs; this module is for building them. The
//! two share `mvm-libkrun`'s FFI but compose differently — the
//! builder mounts a workspace + persistent `/nix`-store disk and
//! runs a one-shot `nix build`, while the runtime mounts the
//! user's rootfs and runs the user's entrypoint.

use std::ffi::OsString;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use std::{fs, io};

use libkrun_sys::{KernelFormat, KrunContext, SupervisorConfig};
use mvm_vmm::host::network_endpoint_spawn::{
    HandshakeContext, handshake_timeout, read_handshake_line,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::builder_disk_transport::{
    InputTree, create_output_disk, pack_input_disk, read_output_disk,
};
use crate::builder_vm::{
    BuilderArtifacts, BuilderJob, BuilderMounts, BuilderVm, BuilderVmDisk, BuilderVmError,
    BuilderVmExitInfo, BuilderVmMount, BuilderVmRunConfig, VmBackendForBuilder,
};
// These items previously lived in this file; they migrated to
// `builder_vm_runtime` so the future VzBuilderVm path can reuse the
// same logic without duplicating it. `INSTALL_SPEC_FILENAME` and
// `shell_single_quote_escape` are imported only inside the test
// module below.
use crate::builder_vm_runtime::{
    CLOSURE_SEED_TAG, acquire_nix_store_image_lock, acquire_nix_store_image_lock_named,
    builder_vm_timeout, ensure_nix_store_image_unlocked, finalize_flake_job, finalize_install_job,
    read_job_result_with_diagnostics, shell_job_exit_error, stage_closure_seed_dir,
    stage_filtered_work_input, stage_job_dir, stage_persistent_job_dir, stage_shell_job_dir,
    supervisor_exit_error, verbose_from_env,
};
use crate::pipeline::build::BUILDER_OUTPUT_DISK_MIB;

/// Default vCPU count for the builder VM. Nix builds are
/// embarrassingly parallel at the derivation level; 4 cores is the
/// sweet spot on M-series Macs without saturating the host.
pub const DEFAULT_VCPUS: u8 = 4;

/// Default RAM in MiB. Originally 8 GiB (in-VM nix builds peak
/// ~5-6 GiB). Raised to 16 GiB for headroom
/// when several derivations' build working sets overlap. Before the
/// persistent-store cutover this also had to cover a 14 GiB in-RAM
/// `/nix` tmpfs; the Stage 0 store now lives on a virtio-blk ext4 disk
/// (`nix-store-stage0-<arch>.img`), so this RAM only has to cover the
/// compiles themselves, not the store.
pub const DEFAULT_MEMORY_MIB: u32 = 16384;

/// Default size of the persistent `/nix`-store virtio-blk image,
/// in MiB. 64 GiB sparse — the file only consumes the bytes the
/// in-VM ext4 actually writes, but capacity caps growth so a
/// runaway build can't fill the host disk.
pub const DEFAULT_NIX_STORE_MIB: u32 = 65536;

/// Builder persistent /nix store auto-GC threshold (GiB of *used* space).
/// When the in-guest store exceeds this after a build, the build script runs
/// `nix-collect-garbage --delete-older-than 14d`. Override: MVM_BUILDER_STORE_GC_GIB.
/// Default 24 GiB (above doctor's 20 GiB warning, below the 64 GiB sparse cap).
///
/// Canonical definition lives in `builder_vm_runtime` (always compiled;
/// `render_flake_cmd_sh` bakes the resolved cap into the in-guest script).
/// Re-exported here next to [`DEFAULT_NIX_STORE_MIB`] for discoverability.
pub use crate::builder_vm_runtime::{DEFAULT_BUILDER_STORE_GC_GIB, builder_store_gc_cap_kib};

/// Where the workspace gets mounted inside the builder VM
/// (read-only virtio-fs).
/// Explicit path URL prevents Nix from treating the mounted checkout as a
/// Git flake and reaching for host-side worktree metadata that is not mounted.
pub const GUEST_WORK_DIR: &str = "path:/work";

/// Where artifacts get extracted inside the builder VM (read-write
/// virtio-fs).
pub const GUEST_OUT_DIR: &str = "/out";

/// Where the persistent Nix store lives inside the builder VM. The
/// `mvm-host-vm-init` PID-1 bind-mounts the virtio-blk device at
/// this path before exec-ing the build script.
pub const GUEST_NIX_DIR: &str = "/nix";

/// Where the per-build job spec lives inside the builder VM. The
/// host stages `cmd.sh`, `env`, and the eventual `result` file
/// under this path (read-write virtio-fs).
pub const GUEST_JOB_DIR: &str = "/job";
const BUILDER_INPUT_DEVICE: &str = "/dev/vdc";
const BUILDER_OUTPUT_DEVICE: &str = "/dev/vdd";
const BUILDER_RUNTIME_DEVICE: &str = "/dev/vde";
const BUILDER_VIRTIOFS_RUNTIME_DEVICE: &str = "/dev/vdc";
const BUILDER_INPUT_DISK_MIN: u64 = 16 << 20;
const BUILDER_VSOCK_EGRESS_TOKEN: &str = "mvm.vsock_egress=1";
const BUILDER_SUBST_PID_FILE: &str = "substitution.pid";
const BUILDER_SUBST_STDERR_LOG_FILE: &str = "substitution.stderr.log";
const BUILDER_VM_BOOTSTRAP_BIN_ENV: &str = "MVM_BUILDER_VM_BOOTSTRAP_BIN";
const BUILDER_VM_AUTO_BOOTSTRAP_SKIP_ENV: &str = "MVM_SKIP_BUILDER_VM_AUTO_BOOTSTRAP";
/// Set on every process this crate spawns to bootstrap the builder VM image.
///
/// A bootstrap that finishes without populating the cache must fail, not
/// delegate: without this marker the child re-enters auto-bootstrap on the same
/// cold cache and forks another child, forever. One level is all the delegation
/// that can ever help, because the second level has nothing new to try.
const BUILDER_VM_BOOTSTRAP_ACTIVE_ENV: &str = "MVM_BUILDER_VM_BOOTSTRAP_ACTIVE";
const BUILDER_VM_CACHE_CONTRACT_VERSION: u32 = 4;

/// Whether the running executable carries the embedded Linux host binaries.
///
/// The whole point of the bootstrap helper is to obtain a binary that has
/// them, so when the running one already does it *is* the helper and there is
/// nothing to build. This crate sits below the one that owns the embed table
/// and cannot read it, so the binary that owns it says so once at startup.
/// Default `false`: an undeclared caller (a test binary, a library embedder)
/// gets the conservative build-a-helper path it had before.
static CURRENT_EXE_CARRIES_HOST_BINARIES: AtomicBool = AtomicBool::new(false);

/// Declare whether this process's executable carries the embedded Linux host
/// binaries a builder-VM bootstrap needs. Called once by `mvmctl` at startup.
pub fn declare_current_exe_carries_host_binaries(carries: bool) {
    CURRENT_EXE_CARRIES_HOST_BINARIES.store(carries, Ordering::Relaxed);
}

/// The running executable, when it has declared a host-binary payload and the
/// OS will name it. Both halves must hold: a declared payload we cannot point
/// a `Command` at is no use as a helper.
fn current_exe_as_bootstrap_helper() -> Option<PathBuf> {
    CURRENT_EXE_CARRIES_HOST_BINARIES
        .load(Ordering::Relaxed)
        .then(|| std::env::current_exe().ok())
        .flatten()
}

/// Resolve (or locally build) the runtime overlay ext4 the builder VM sources
/// its guest binaries from, failing closed when it cannot be produced.
///
/// A lean builder image bakes no guest binaries — every one is sourced from
/// this overlay mounted at `/mvm/runtime` — so booting without it silently
/// strands the guest agent. Callers that boot a lean `Rootfs` builder MUST
/// treat a resolution failure as fatal; see [`builder_runtime_overlay_or_bail`]
/// for the image-gated wrapper the boot paths use.
pub fn require_runtime_overlay_ext4() -> anyhow::Result<PathBuf> {
    use anyhow::Context as _;
    let cache_root = PathBuf::from(mvm_core::config::mvm_cache_dir());
    let version = env!("CARGO_PKG_VERSION");
    let arch = mvm_core::arch::GuestArch::host();
    let artifact =
        crate::runtime_overlay::resolve_or_build_local_runtime_overlay(&cache_root, version, arch)
            .with_context(|| {
                format!(
                    "builder VM requires the runtime overlay but it could not be resolved or \
                     built (cache_root={}, version={version}, arch={arch})",
                    cache_root.display()
                )
            })?;
    Ok(artifact.overlay_ext4)
}

/// Resolve the runtime overlay for a builder boot, gating on the image shape.
///
/// A lean [`BuilderVmImage::Rootfs`] builder requires the overlay and fails
/// closed when it is unavailable. A [`BuilderVmImage::RootDir`] (Stage 0
/// bootstrap) image boots from libkrun's bundled kernel and sources no guest
/// binaries from the overlay, so it legitimately returns `None`.
pub(crate) fn builder_runtime_overlay_or_bail(
    image: &BuilderVmImage,
) -> Result<Option<PathBuf>, BuilderVmError> {
    builder_runtime_overlay_or_bail_with(image, require_runtime_overlay_ext4)
}

/// Injectable core of [`builder_runtime_overlay_or_bail`] — takes the resolver
/// as a closure so the image-gating and fail-closed mapping are unit-testable
/// without touching the on-disk cache or triggering a source-checkout rebuild.
fn builder_runtime_overlay_or_bail_with(
    image: &BuilderVmImage,
    resolve: impl FnOnce() -> anyhow::Result<PathBuf>,
) -> Result<Option<PathBuf>, BuilderVmError> {
    match image {
        BuilderVmImage::Rootfs { .. } => resolve()
            .map(Some)
            .map_err(|e| BuilderVmError::RuntimeOverlayUnavailable(format!("{e:#}"))),
        BuilderVmImage::RootDir { .. } => Ok(None),
    }
}

fn append_cmdline_token(base_cmdline: &str, token: &str) -> String {
    if base_cmdline
        .split_whitespace()
        .any(|existing| existing == token)
    {
        return base_cmdline.to_string();
    }
    if base_cmdline.trim().is_empty() {
        return token.to_string();
    }
    format!("{base_cmdline} {token}")
}

fn builder_vsock_egress_cmdline(base_cmdline: &str) -> String {
    append_cmdline_token(base_cmdline, BUILDER_VSOCK_EGRESS_TOKEN)
}

fn apply_builder_vsock_egress(krun: KrunContext) -> KrunContext {
    krun.with_cmdline(BUILDER_VSOCK_EGRESS_TOKEN)
        .with_vsock_direct()
        .add_host_listen_port(mvm_agentd::vsock::EGRESS_PORT)
}

fn builder_boot_contract_cmdline(base_cmdline: &str) -> String {
    let cmdline = append_cmdline_token(base_cmdline, "rootwait");
    let cmdline = append_cmdline_token(&cmdline, "panic=-1");
    append_cmdline_token(&cmdline, "loglevel=8")
}

fn builder_disk_transport_cmdline(base_cmdline: &str) -> String {
    let cmdline = builder_boot_contract_cmdline(base_cmdline);
    let cmdline = append_cmdline_token(&cmdline, "mvm.builder_transport=disk");
    let cmdline = append_cmdline_token(
        &cmdline,
        &format!("mvm.builder_input={BUILDER_INPUT_DEVICE}"),
    );
    let cmdline = append_cmdline_token(
        &cmdline,
        &format!("mvm.builder_output={BUILDER_OUTPUT_DEVICE}"),
    );
    builder_vsock_egress_cmdline(&cmdline)
}

fn builder_runtime_overlay_cmdline(base_cmdline: &str, runtime_device: &str) -> String {
    let cmdline = builder_disk_transport_cmdline(base_cmdline);
    append_cmdline_token(&cmdline, &format!("mvm.runtime_data={runtime_device}"))
}

fn builder_virtiofs_runtime_overlay_cmdline(base_cmdline: &str, runtime_device: &str) -> String {
    let cmdline = builder_boot_contract_cmdline(base_cmdline);
    let cmdline = builder_vsock_egress_cmdline(&cmdline);
    append_cmdline_token(&cmdline, &format!("mvm.runtime_data={runtime_device}"))
}

pub(crate) struct BuilderRuntimeOverlayAttachment<'a> {
    pub(crate) cmdline: String,
    pub(crate) disk_path: &'a Path,
    pub(crate) read_only: bool,
}

fn builder_runtime_overlay_guest_agent_enabled(
    image: &BuilderVmImage,
    runtime_overlay: Option<&Path>,
) -> bool {
    matches!(
        (image, runtime_overlay),
        (BuilderVmImage::Rootfs { .. }, Some(_))
    )
}

fn builder_uses_vsock_egress(image: &BuilderVmImage) -> bool {
    matches!(image, BuilderVmImage::Rootfs { .. })
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum BuilderEndpointTransport {
    Uds { path: PathBuf },
    Vsock { port: u32 },
}

#[derive(Debug)]
pub(crate) struct BuilderVsockEgressEndpoint {
    state_dir: PathBuf,
}

/// Mint this builder boot's FlowMux identity and write the drive its guest
/// reads the keys off. Returned so the caller can attach the drive to the VM.
///
/// The session id is the per-VM state dir's own name, which is unique per boot
/// and in scope at every builder spawn site — the alternative was threading a
/// name through call sites that variously have one, have a differently-named
/// one, or have none.
pub(crate) fn stage_builder_flowmux_identity(
    state_dir: &Path,
) -> Result<
    (
        mvm_vmm::host::flowmux_identity::FlowMuxIdentityMaterial,
        PathBuf,
    ),
    BuilderVmError,
> {
    let vm_name = state_dir
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("builder");
    let material =
        mvm_vmm::host::flowmux_identity::FlowMuxIdentityMaterial::mint_from_host_signer(vm_name)
            .map_err(|e| {
                BuilderVmError::ExtractionFailed(format!("mint the builder FlowMux identity: {e}"))
            })?;
    let drive = state_dir.join(mvm_vmm::host::flowmux_identity::IDENTITY_DRIVE_FILE);
    material.write_drive(&drive).map_err(|e| {
        BuilderVmError::ExtractionFailed(format!("write the builder FlowMux identity drive: {e}"))
    })?;
    Ok((material, drive))
}

impl BuilderVsockEgressEndpoint {
    fn spawn(
        state_dir: &Path,
        identity: &mvm_vmm::host::network_endpoint_spawn::FlowMuxIdentitySpawnConfig,
    ) -> Result<Self, BuilderVmError> {
        let socket_dir = builder_vsock_socket_dir(state_dir)?;
        let transport_path = socket_dir.join(mvm_core::config::vsock_socket_filename(
            mvm_agentd::vsock::EGRESS_PORT,
        ));
        Self::spawn_with_transport(
            state_dir,
            BuilderEndpointTransport::Uds {
                path: transport_path,
            },
            identity,
        )
    }

    pub(crate) fn spawn_with_transport(
        state_dir: &Path,
        transport: BuilderEndpointTransport,
        identity: &mvm_vmm::host::network_endpoint_spawn::FlowMuxIdentitySpawnConfig,
    ) -> Result<Self, BuilderVmError> {
        let endpoint_path = resolve_network_endpoint_path()?;
        let config = serde_json::json!({
            "tenant_id": "builder",
            "secrets": [],
            "transport": transport,
            "redaction": mvm_core::policy::RedactionPolicy::default(),
            "network_policy": mvm_core::policy::network_policy::NetworkPolicy::trusted_build_egress(),
            // One authenticated session, same as every other tier. The guest's
            // egress client speaks nothing else.
            "egress_mode": "flow_mux",
            "flowmux_identity": {
                "session_id": identity.session_id,
                "host_signing_key_base64": identity.host_signing_key_base64,
                "guest_verifying_key_base64": identity.guest_verifying_key_base64,
            },
        });

        let mvmctl_path = std::env::current_exe().map_err(|e| {
            BuilderVmError::ExtractionFailed(format!(
                "resolve mvmctl for persistent builder egress supervisor: {e}"
            ))
        })?;
        let stderr_log_path = state_dir.join(BUILDER_SUBST_STDERR_LOG_FILE);
        let stderr_log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&stderr_log_path)
            .map_err(|e| {
                BuilderVmError::ExtractionFailed(format!(
                    "open persistent builder egress log {}: {e}",
                    stderr_log_path.display()
                ))
            })?;
        let mut endpoint_command = builder_egress_supervisor_command(&mvmctl_path, &endpoint_path);
        let mut child = endpoint_command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::from(stderr_log))
            .spawn()
            .map_err(|e| {
                BuilderVmError::ExtractionFailed(format!(
                    "spawn persistent builder egress supervisor for {}: {e}",
                    endpoint_path.display()
                ))
            })?;

        child
            .stdin
            .take()
            .ok_or_else(|| {
                BuilderVmError::ExtractionFailed(
                    "builder egress endpoint stdin was not piped".to_string(),
                )
            })?
            .write_all(config.to_string().as_bytes())
            .map_err(|e| {
                BuilderVmError::ExtractionFailed(format!(
                    "pipe builder egress endpoint config: {e}"
                ))
            })?;

        let stdout = child.stdout.take().ok_or_else(|| {
            BuilderVmError::ExtractionFailed(
                "builder egress endpoint stdout was not piped".to_string(),
            )
        })?;
        // The shared reader, not a local copy: the builder's own version
        // accepted any non-empty line as a handshake and reported a bare
        // duration on timeout, which is not enough to tell a slow endpoint from
        // a dead one.
        read_handshake_line(
            stdout,
            child.id(),
            handshake_timeout(),
            &HandshakeContext {
                endpoint: &endpoint_path,
                stderr_log: Some(&stderr_log_path),
            },
        )
        .map_err(|e| BuilderVmError::ExtractionFailed(format!("{e:#}")))?;

        let pid_file = state_dir.join(BUILDER_SUBST_PID_FILE);
        std::fs::write(&pid_file, child.id().to_string()).map_err(|e| {
            BuilderVmError::ExtractionFailed(format!("write {}: {e}", pid_file.display()))
        })?;

        let child_pid = child.id();
        std::thread::spawn(move || match child.wait() {
            Ok(status) => eprintln!(
                "builder egress endpoint pid={} exited with status {}",
                child_pid, status
            ),
            Err(e) => eprintln!("builder egress endpoint pid={} wait failed: {e}", child_pid),
        });

        Ok(Self {
            state_dir: state_dir.to_path_buf(),
        })
    }

    fn reap(&self) {
        reap_builder_vsock_egress_endpoint(&self.state_dir);
    }
}

fn builder_egress_supervisor_command(mvmctl_path: &Path, endpoint_path: &Path) -> Command {
    let mut command = Command::new(mvmctl_path);
    command
        .arg("__builder-egress-supervisor")
        .arg("--endpoint")
        .arg(endpoint_path)
        // This child's stdout is a typed JSON handshake channel. The parent
        // CLI's verbose RUST_LOG value must not turn tracing records into
        // protocol bytes before the wrapper execs the endpoint.
        .env("RUST_LOG", "off")
        .env_remove(mvm_core::observability::span_timing::ENV_ENABLE)
        .env_remove(mvm_core::observability::span_timing::ENV_OUT)
        .env_remove(mvm_core::observability::span_timing::ENV_FILTER);
    command
}

fn builder_vsock_socket_dir(state_dir: &Path) -> Result<PathBuf, BuilderVmError> {
    let socket_dir = mvm_core::config::vm_socket_dir_at(state_dir);
    std::fs::create_dir_all(&socket_dir).map_err(|e| {
        BuilderVmError::ExtractionFailed(format!(
            "creating builder vsock socket dir {}: {e}",
            socket_dir.display()
        ))
    })?;
    Ok(socket_dir)
}

impl Drop for BuilderVsockEgressEndpoint {
    fn drop(&mut self) {
        self.reap();
    }
}

/// Whether `candidate` predates the running executable.
///
/// The endpoint is a separate binary that `machine run` does not build, so a
/// copy left by an older checkout sits on disk and is picked up in preference
/// to building a current one. A guest and a host from different builds then
/// speak different protocols, and the only symptom is a framing error whose
/// length field decodes to ASCII from the wrong wire format.
///
/// Modification time is the cheap comparison that catches it: both binaries
/// come out of the same workspace, so an endpoint older than the `mvmctl`
/// running it cannot have been built from this source. Unknowable times mean
/// no opinion — rebuild rather than refuse, since a false stale reading costs
/// a build and a false fresh one costs a mystery.
fn endpoint_predates_running_exe(candidate: &std::path::Path) -> bool {
    let modified = |p: &std::path::Path| p.metadata().and_then(|m| m.modified()).ok();
    let Some(exe) = std::env::current_exe().ok().as_deref().and_then(modified) else {
        return false;
    };
    let Some(cand) = modified(candidate) else {
        return true;
    };
    cand < exe
}

fn resolve_network_endpoint_path() -> Result<PathBuf, BuilderVmError> {
    if let Some(path) = std::env::var_os("MVM_SUBSTITUTION_ENDPOINT_PATH").map(PathBuf::from) {
        if path.is_file() {
            return Ok(path);
        }
        return Err(BuilderVmError::ExtractionFailed(format!(
            "MVM_SUBSTITUTION_ENDPOINT_PATH points at {} which is not a file",
            path.display()
        )));
    }

    if let Ok(current_exe) = std::env::current_exe()
        && let Some(dir) = current_exe.parent()
    {
        let candidate = dir.join("mvm-network-endpoint");
        if candidate.is_file() && !endpoint_predates_running_exe(&candidate) {
            return Ok(candidate);
        }
    }

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let Some(workspace_root) = manifest_dir.parent().and_then(|p| p.parent()) else {
        return Err(BuilderVmError::ExtractionFailed(
            "resolve workspace root for mvm-network-endpoint".to_string(),
        ));
    };

    let mut target_roots = vec![workspace_root.join("target")];
    if let Some(target_dir) = std::env::var_os("CARGO_TARGET_DIR")
        && !target_dir.is_empty()
    {
        let candidate = PathBuf::from(target_dir);
        let normalized = if candidate.is_absolute() {
            candidate
        } else {
            workspace_root.join(candidate)
        };
        if !target_roots.iter().any(|root| root == &normalized) {
            target_roots.push(normalized);
        }
    }

    for root in &target_roots {
        for variant in ["release", "debug"] {
            let candidate = root.join(variant).join("mvm-network-endpoint");
            if candidate.is_file() && !endpoint_predates_running_exe(&candidate) {
                return Ok(candidate);
            }
        }
    }

    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let mut build = Command::new(cargo);
    build.current_dir(workspace_root).args([
        "build",
        "-p",
        "mvm-hostd",
        "--bin",
        "mvm-network-endpoint",
    ]);
    if !build
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
    {
        return Err(BuilderVmError::ExtractionFailed(
            "build mvm-network-endpoint".to_string(),
        ));
    }

    for root in &target_roots {
        let built = root.join("debug").join("mvm-network-endpoint");
        if built.is_file() {
            // Deliberately no mtime re-check here. The comparison above is a
            // cheap trigger for "might be stale, try a rebuild"; it is not a
            // verdict, because it compares two artifacts' mtimes rather than
            // the sources they came from.
            //
            // `cargo build` has just confirmed this binary is current with its
            // sources in this workspace. When it was already current, cargo
            // does not relink and the mtime does not move — so re-testing it
            // against the running `mvmctl` failed forever with "even after
            // rebuilding it". `cargo build --workspace --bins` links `mvmctl`
            // last, so a normal build leaves the endpoint older every time and
            // no amount of rebuilding could satisfy the check.
            return Ok(built);
        }
    }
    Err(BuilderVmError::ExtractionFailed(format!(
        "mvm-network-endpoint not found after build (searched: {})",
        target_roots
            .iter()
            .map(|root| root.join("debug").join("mvm-network-endpoint"))
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    )))
}

fn reap_builder_vsock_egress_endpoint(state_dir: &Path) {
    let pid_file = state_dir.join(BUILDER_SUBST_PID_FILE);
    if let Some(pid) = read_pid(&pid_file)
        && pid_alive(pid)
    {
        kill_pid(pid, libc::SIGTERM);
    }
    let _ = std::fs::remove_file(pid_file);
}

fn read_pid(path: &Path) -> Option<libc::pid_t> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

fn pid_alive(pid: libc::pid_t) -> bool {
    unsafe { libc::kill(pid, 0) == 0 }
}

fn kill_pid(pid: libc::pid_t, sig: libc::c_int) {
    unsafe {
        libc::kill(pid, sig);
    }
}

/// Pack the inbound trees onto an input disk and create the output disk the
/// guest writes its artifact tar onto — the host half of the disk transport,
/// shared by every one-shot builder VMM.
///
/// `closure_nar` is the resolved builder image's optional seeded Nix store
/// closure: a single file that rides the same input disk at
/// `closure-seed/<CLOSURE_FILE>`. The guest imports that fixed path and does
/// not care which transport populated it, so a caller still attaching the
/// closure as a virtio-fs share passes `None` here instead.
pub(crate) fn prepare_builder_transport_disks(
    vm_state_dir: &Path,
    input_trees: &[InputTree<'_>],
    closure_nar: Option<&Path>,
    output_size: u64,
) -> Result<(PathBuf, PathBuf), BuilderVmError> {
    let input_disk = vm_state_dir.join("input.img");
    let output_disk = vm_state_dir.join("output.img");
    pack_input_disk(
        input_trees,
        closure_nar,
        &input_disk,
        BUILDER_INPUT_DISK_MIN,
    )
    .map_err(|e| {
        BuilderVmError::ExtractionFailed(format!(
            "pack builder input disk {}: {e}",
            input_disk.display()
        ))
    })?;
    create_output_disk(&output_disk, output_size).map_err(|e| {
        BuilderVmError::ExtractionFailed(format!(
            "create builder output disk {}: {e}",
            output_disk.display()
        ))
    })?;
    Ok((input_disk, output_disk))
}

pub(crate) fn extract_builder_transport_output(
    output_disk: &Path,
    artifact_out: &Path,
    job_dir: &Path,
) -> Result<(), BuilderVmError> {
    read_output_disk(output_disk, artifact_out).map_err(|e| {
        BuilderVmError::ExtractionFailed(format!(
            "extract builder output disk {} into {}: {e}",
            output_disk.display(),
            artifact_out.display()
        ))
    })?;
    for name in [
        "result",
        "nix-stderr.log",
        "nix-stdout.log",
        "boot-timings.json",
    ] {
        let src = artifact_out.join(name);
        if src.is_file() {
            let dst = job_dir.join(name);
            std::fs::copy(&src, &dst).map_err(|e| {
                BuilderVmError::ExtractionFailed(format!(
                    "copy extracted builder artifact {} -> {}: {e}",
                    src.display(),
                    dst.display()
                ))
            })?;
        }
    }
    Ok(())
}

pub(crate) fn builder_runtime_overlay_attachment<'a>(
    image: &'a BuilderVmImage,
    runtime_overlay: Option<&'a Path>,
) -> Option<BuilderRuntimeOverlayAttachment<'a>> {
    match (image, runtime_overlay) {
        (BuilderVmImage::Rootfs { cmdline, .. }, Some(runtime_overlay)) => {
            Some(BuilderRuntimeOverlayAttachment {
                cmdline: builder_runtime_overlay_cmdline(cmdline, BUILDER_RUNTIME_DEVICE),
                disk_path: runtime_overlay,
                read_only: true,
            })
        }
        _ => None,
    }
}

pub(crate) fn builder_virtiofs_runtime_overlay_attachment<'a>(
    image: &'a BuilderVmImage,
    runtime_overlay: Option<&'a Path>,
) -> Option<BuilderRuntimeOverlayAttachment<'a>> {
    match (image, runtime_overlay) {
        (BuilderVmImage::Rootfs { cmdline, .. }, Some(runtime_overlay)) => {
            Some(BuilderRuntimeOverlayAttachment {
                cmdline: builder_virtiofs_runtime_overlay_cmdline(
                    cmdline,
                    BUILDER_VIRTIOFS_RUNTIME_DEVICE,
                ),
                disk_path: runtime_overlay,
                read_only: true,
            })
        }
        _ => None,
    }
}

/// Libkrun-backed builder VM driver.
///
/// Configuration only — `run_build` consumes it to spin a per-job
/// VM, runs `nix build` inside, extracts the artifacts via the
/// `/out` virtio-fs mount, and tears the VM down. No persistent
/// state on the struct; the `/nix`-store image lives on the host
/// filesystem and survives across invocations.
#[derive(Debug, Clone)]
pub struct LibkrunBuilderVm {
    /// Guest vCPU count. See [`DEFAULT_VCPUS`].
    pub vcpus: u8,
    /// Guest RAM in MiB. See [`DEFAULT_MEMORY_MIB`].
    pub memory_mib: u32,
    /// Persistent `/nix`-store image size in MiB (sparse cap).
    /// See [`DEFAULT_NIX_STORE_MIB`].
    pub nix_store_mib: u32,
    /// Optional caller-supplied bootstrap image. When set, `run_build`
    /// boots from this kernel/rootfs/cmdline instead of looking up the
    /// builder VM image in `~/.mvm/cache/builder-vm/<arch>/`.
    ///
    /// This is the Stage 0 escape from the chicken-and-egg on source
    /// checkouts: a local dev image that contains `/sbin/mvm-host-vm-init`
    /// can build the real builder VM image without downloading a
    /// published builder-VM artifact.
    pub image_override: Option<BuilderVmImage>,
    /// Optional seeded Nix store closure NAR, resolved alongside the
    /// builder image when it carries one. `None` (the common case today)
    /// attaches no closure-seed share, so every boot behaves exactly as
    /// before this field existed. See [`LibkrunBuilderVm::with_closure_nar`].
    pub closure_nar: Option<PathBuf>,
    /// Stream the guest `console.log` to stderr as the build runs.
    /// Set by the CLI from `--verbose`. Default false (heartbeat only).
    pub verbose: bool,
}

/// Additional virtio-blk device passed to a one-shot builder shell
/// job. Devices appear after the builder VM's persistent Nix-store
/// disk; the first extra disk here is `/dev/vdc` in the guest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuilderExtraDisk {
    pub id: String,
    pub path: PathBuf,
    pub read_only: bool,
}

/// Generic builder-VM shell job.
///
/// This is intentionally narrower than [`BuilderJob`]: it is for
/// in-tree infrastructure commands that need the Linux builder
/// boundary but do not produce Nix build artifacts. The OCI image
/// runner uses it to run `mkfs.ext4` and copy an OCI-unpacked rootfs
/// into a writable virtio-blk image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuilderShellJob {
    pub work_dir: PathBuf,
    pub artifact_out: PathBuf,
    pub script: String,
    pub extra_disks: Vec<BuilderExtraDisk>,
}

/// Result metadata from a one-shot builder shell job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuilderShellResult {
    pub job_dir: PathBuf,
    pub vm_state_dir: PathBuf,
}

impl Default for LibkrunBuilderVm {
    fn default() -> Self {
        Self {
            vcpus: DEFAULT_VCPUS,
            memory_mib: DEFAULT_MEMORY_MIB,
            nix_store_mib: DEFAULT_NIX_STORE_MIB,
            image_override: None,
            closure_nar: None,
            verbose: false,
        }
    }
}

impl LibkrunBuilderVm {
    /// Override the default vCPU / RAM pair. Useful for CI runners
    /// or low-memory hosts that can't afford the 4 GiB default.
    pub fn with_resources(mut self, vcpus: u8, memory_mib: u32) -> Self {
        self.vcpus = vcpus;
        self.memory_mib = memory_mib;
        self
    }

    /// Override the default `/nix`-store image cap. Smaller for
    /// CI runners that build a known-small closure; larger for
    /// developer hosts that want to keep many tenants' artifacts
    /// in one warm store.
    pub fn with_nix_store_mib(mut self, mib: u32) -> Self {
        self.nix_store_mib = mib;
        self
    }

    /// Boot from a caller-supplied kernel/rootfs/cmdline instead of
    /// resolving the builder VM image from `~/.mvm/cache/builder-vm/`.
    pub fn with_image_override(mut self, image: BuilderVmImage) -> Self {
        self.image_override = Some(image);
        self
    }

    /// Attach a seeded Nix store closure NAR resolved from the builder
    /// image cache, mirroring `HvfBuilderVm::with_closure_nar`. Every boot
    /// after this call (Stage 0, a shell job, or a flake build) stages the
    /// NAR into a dedicated share dir under the VM's state dir and attaches
    /// it read-only at the `closure-seed` virtio-fs tag; omitting this call
    /// (the default) attaches nothing, so a builder image without a
    /// closure boots exactly as before this seam existed.
    pub fn with_closure_nar(mut self, closure_nar: Option<PathBuf>) -> Self {
        self.closure_nar = closure_nar;
        self
    }

    /// Stage `self.closure_nar` under `vm_state_dir` and return the tag +
    /// staged share dir for the caller to `add_virtio_fs` with, or `None`
    /// when no closure was attached — the shared no-op path every
    /// `run_build`-shaped method takes.
    fn closure_seed_share(&self, vm_state_dir: &Path) -> Result<Option<PathBuf>, BuilderVmError> {
        self.closure_nar
            .as_deref()
            .map(|nar| stage_closure_seed_dir(nar, vm_state_dir))
            .transpose()
    }

    /// Stream guest console output to stderr during the build (`--verbose`).
    pub fn with_verbose(mut self, verbose: bool) -> Self {
        self.verbose = verbose;
        self
    }

    /// libkrun-side Stage 0 boot. Drives a self-contained `RootDir`
    /// guest — no `/job/cmd.sh` staging, no `/job/result` parsing. The
    /// guest's `/init` reads `/work` and writes the steady-state builder
    /// VM artifacts to `/out`, then powers off cleanly.
    ///
    /// Attaches a dedicated persistent `nix-store-stage0-<arch>.img` as
    /// the guest's first virtio-blk device (`/dev/vda` — Stage 0 has no
    /// block rootfs, its root is virtio-fs via `krun_set_root`). The
    /// guest mounts it at `/nix` (formatting on first boot), so the slim
    /// kernel + Rust host binaries are built once and reused across
    /// bootstrap runs instead of recompiled into a throwaway tmpfs every
    /// time. ext4 is case-sensitive, which is also why the old in-RAM
    /// tmpfs existed (APFS case-insensitivity breaks Nix substitution) —
    /// the disk keeps that property and adds persistence.
    ///
    /// The workspace source travels as a second virtio-blk device rather
    /// than a virtio-fs share (see [`pack_stage0_work_disk`]): `nix build`
    /// reading a large workspace tree through virtio-fs-over-FUSE exhausts
    /// libkrun's virtio-fs handle pool (`nix build` fails with "Too many
    /// open files"). `stage0-init` identifies the disk by its ext4 volume
    /// label rather than by enumeration order, and falls back to the old
    /// `"work"` virtio-fs tag when no such disk is attached.
    ///
    /// On success the caller still validates that the expected artifacts
    /// (`vmlinux`, `rootfs.ext4`) landed in `artifact_out`; this only
    /// asserts the supervisor exited 0.
    ///
    /// Private impl behind `<Self as BuilderVm>::run_stage0`, which
    /// adapts the backend-agnostic `(root_dir, entry)` trait signature
    /// to libkrun's `BuilderVmImage`.
    fn run_stage0_impl(
        &self,
        image: BuilderVmImage,
        workspace_dir: &std::path::Path,
        artifact_out: &std::path::Path,
        host_bin_dir: &std::path::Path,
    ) -> Result<(), BuilderVmError> {
        ensure_utf8_path(workspace_dir, "workspace_dir")?;
        ensure_utf8_path(artifact_out, "artifact_out")?;
        ensure_utf8_path(host_bin_dir, "host_bin_dir")?;
        if !workspace_dir.is_dir() {
            return Err(BuilderVmError::ExtractionFailed(format!(
                "Stage 0 workspace_dir must be an existing directory: {}",
                workspace_dir.display()
            )));
        }
        // The builder-vm flake installs the pre-cross-compiled host-vm
        // binaries from this dir rather than building them with the guest's
        // nix; the Stage 0 nix build aborts without it.
        if !host_bin_dir.is_dir() {
            return Err(BuilderVmError::ExtractionFailed(format!(
                "Stage 0 host_bin_dir must be an existing directory: {}",
                host_bin_dir.display()
            )));
        }
        std::fs::create_dir_all(artifact_out).map_err(|e| {
            BuilderVmError::ExtractionFailed(format!(
                "creating Stage 0 artifact_out {}: {e}",
                artifact_out.display()
            ))
        })?;

        if !libkrun_sys::is_available() {
            return Err(BuilderVmError::LibkrunUnavailable(format!(
                "libkrun shared library not found on host. {}",
                libkrun_sys::install_hint()
            )));
        }

        let supervisor_path = resolve_supervisor_path()?;

        // Persistent, host-locked Nix store for the image build. Sparse
        // image, formatted in-guest on first boot; survives across
        // bootstrap runs so the slim kernel + Rust toolchain closure are
        // built once. Dedicated filename (not the builder's
        // `nix-store-<arch>.img`) so the flock never contends with a
        // concurrent `mvmctl build`. The guard must outlive the
        // supervisor — bound here, dropped at function end.
        let nix_store_lock = acquire_nix_store_image_lock_named(
            &builder_vm_cache_dir(),
            &stage0_nix_store_image_name(),
            u64::from(self.nix_store_mib),
        )?;
        prepopulate_stage0_nix_store_image(&image, nix_store_lock.path())?;

        let job_id = unique_job_id();
        let vm_name = format!("mvm-stage0-{job_id}");
        let vm_state_dir = builder_vm_cache_dir().join("vms").join(&vm_name);
        std::fs::create_dir_all(&vm_state_dir).map_err(|e| {
            BuilderVmError::ExtractionFailed(format!(
                "creating Stage 0 VM state dir {}: {e}",
                vm_state_dir.display()
            ))
        })?;
        let console_log = vm_state_dir.join("console.log");
        let socket_dir = builder_vsock_socket_dir(&vm_state_dir)?;
        // The in-guest nix build streams its `--print-build-logs` to this
        // console as it runs (stage0-init echoes each line live). In verbose
        // mode the host forwards that console to stderr, so the build log is
        // already on screen — pointing at the file would be redundant. In quiet
        // mode the build is silent for minutes, so point the operator at the
        // file. `[mvm]` eprintln matches the existing Stage 0 hint channel.
        if !self.verbose {
            eprintln!(
                "[mvm] Stage 0 build log streams to {} — `tail -f` it to watch progress \
                 (or re-run with `-v` to stream it here)",
                console_log.display()
            );
        }

        // Pack the workspace onto an ext4 disk instead of exporting it over
        // virtio-fs: `nix build` opening every file in a large workspace tree
        // through virtio-fs-over-FUSE exhausts libkrun's virtio-fs handle
        // pool (EMFILE, "Too many open files"), which reliably fails the
        // Stage 0 build. `stage0-init` mounts it by ext4 volume label.
        let work_disk = pack_stage0_work_disk(workspace_dir, &vm_state_dir)?;

        let mut krun = krun_context_for_image(&vm_name, &image)?
            .with_resources(self.vcpus, self.memory_mib)
            .with_console_output(path_to_str(&console_log, "console_log")?)
            .with_vsock_socket_dir(path_to_str(&socket_dir, "vm_socket_dir")?)
            // Persistent /nix store disk — the first block device attached
            // to a RootDir guest, so it enumerates as /dev/vda. `stage0-init`
            // mounts and reuses it when it is ext4, formats it when the seed
            // carries mkfs.ext4, and otherwise falls back to the tmpfs seed
            // copy.
            .add_disk(
                "nix-store",
                path_to_str(nix_store_lock.path(), "nix_store_img")?,
                false,
            )
            // Read-only: `stage0-init` invokes `nix build --no-write-lock-file`
            // against a flake that already carries a committed lock, so
            // nothing ever writes back into the workspace tree.
            .add_disk("work", path_to_str(&work_disk, "work_disk")?, true)
            .add_virtio_fs("out", path_to_str(artifact_out, "artifact_out")?)
            // /mvm-bins inside the guest — stage0-init sets MVM_HOST_BIN_DIR
            // to it so the flake picks up the pre-built host-vm binaries.
            .add_virtio_fs("mvm-bins", path_to_str(host_bin_dir, "host_bin_dir")?);
        if let Some(share_dir) = self.closure_seed_share(&vm_state_dir)? {
            krun = krun.add_virtio_fs(
                CLOSURE_SEED_TAG,
                path_to_str(&share_dir, "closure_seed_dir")?,
            );
        }
        let (identity_material, identity_drive) = stage_builder_flowmux_identity(&vm_state_dir)?;
        krun = krun.add_disk(
            "mvm-identity",
            path_to_str(&identity_drive, "identity_drive")?,
            true,
        );
        krun = apply_builder_vsock_egress(krun);
        let _egress_endpoint =
            BuilderVsockEgressEndpoint::spawn(&vm_state_dir, identity_material.spawn_config())?;

        let cfg = SupervisorConfig {
            krun,
            vm_state_dir: path_to_str(&vm_state_dir, "vm_state_dir")?.to_string(),
            pid_file_name: Some("stage0.pid".to_string()),
            tenant_id: None,
            audit_dir: None,
            gateway_audit_socket: None,
            gateway_events_socket: None,
            signing_key_path: None,
            plan: None,
            bundle: None,
            // Builder VMs take the legacy non-bridge path (tenant_id None), so
            // this is inert today (set explicitly to None — no bare-policy
            // override). Step 3 flips builder/dev to trusted_build_egress when
            // they move onto the bridge.
            network_policy: None,
            transparent_terminator_port: None,
            egress_relay_socket: None,
            exclusive_image_lock: None,
            // Builder VMs are always hard-fail; they don't model
            // long-running user workloads where a restart policy would
            // apply.
            bridge_restart_policy: libkrun_sys::BridgeRestartPolicy::HardFail,
        };

        let exit_code =
            match spawn_supervisor_and_wait(&supervisor_path, &cfg, &vm_state_dir, self.verbose) {
                Ok(code) => code,
                Err(BuilderVmError::GuestHalted { .. })
                    if stage0_guest_halt_completed_successfully(&console_log, artifact_out) =>
                {
                    0
                }
                Err(error) => {
                    invalidate_stage0_store_after_ext4_error(&console_log, nix_store_lock.path())?;
                    return Err(error);
                }
            };
        if exit_code != 0 {
            invalidate_stage0_store_after_ext4_error(&console_log, nix_store_lock.path())?;
            return Err(BuilderVmError::NixBuildFailed(format!(
                "Stage 0 supervisor exited with status {exit_code}; \
                 console log at {}",
                console_log.display()
            )));
        }
        // A clean supervisor exit only means the guest powered off; stage0-init
        // powers off on a failed build too. Read the guest's terminal marker
        // from the console so a nix failure surfaces here with its own log
        // instead of as a downstream "rootfs.ext4 missing" error.
        let console = std::fs::read_to_string(&console_log).unwrap_or_default();
        invalidate_stage0_store_after_ext4_error(&console_log, nix_store_lock.path())?;
        let console_log_path = console_log.to_string_lossy();
        stage0_run_result(&console, &console_log_path)
    }

    /// Run an in-tree shell script inside the existing builder VM
    /// boundary. The script is staged as `/job/cmd.sh`; `/work`
    /// points at [`BuilderShellJob::work_dir`], `/out` points at
    /// [`BuilderShellJob::artifact_out`], and callers may attach
    /// additional writable or read-only virtio-blk disks.
    pub fn run_shell_script(
        &self,
        job: &BuilderShellJob,
    ) -> Result<BuilderShellResult, BuilderVmError> {
        self.validate_shell_job(job)?;

        if !libkrun_sys::is_available() {
            return Err(BuilderVmError::LibkrunUnavailable(format!(
                "libkrun shared library not found on host. {}",
                libkrun_sys::install_hint()
            )));
        }

        let supervisor_path = resolve_supervisor_path()?;
        let image = match &self.image_override {
            Some(image) => image.clone(),
            None => ensure_builder_vm_image()?,
        };
        let nix_store_lock = acquire_nix_store_image_lock(
            &builder_vm_cache_dir(),
            host_arch_tag(),
            u64::from(self.nix_store_mib),
        )?;

        let job_id = unique_job_id();
        let job_dir = builder_vm_cache_dir().join("jobs").join(&job_id);
        stage_shell_job_dir(&job_dir, &job.script)?;
        // Tell the operator up-front where the build's stderr will
        // land. `/job` is a virtio-fs share into the VM; the guest's
        // cmd.sh redirects `nix build` stderr into <job_dir>/nix-
        // stderr.log, which is this exact path on the host. A
        // contributor watching a long build can `tail -f` it without
        // waiting for the failure-path formatter (finalize_flake_job)
        // to surface the same path.
        tracing::info!(
            job_dir = %job_dir.display(),
            "builder VM job dir staged (nix-stderr.log streams here as the build runs)"
        );

        let vm_name = format!("mvm-builder-vm-{job_id}");
        let vm_state_dir = builder_vm_cache_dir().join("vms").join(&vm_name);
        std::fs::create_dir_all(&vm_state_dir).map_err(|e| {
            BuilderVmError::ExtractionFailed(format!(
                "creating builder VM state dir {}: {e}",
                vm_state_dir.display()
            ))
        })?;
        let console_log = vm_state_dir.join("console.log");
        let socket_dir = builder_vsock_socket_dir(&vm_state_dir)?;
        let runtime_overlay = builder_runtime_overlay_or_bail(&image)?;
        let guest_agent_vsock =
            builder_runtime_overlay_guest_agent_enabled(&image, runtime_overlay.as_deref());
        // `job.work_dir` can be the repo root on a source checkout; stage a
        // filtered copy so `target/`/`.worktrees/`/`.git/` never ride the
        // input tar. `work_staging` must outlive this call.
        let work_staging = stage_filtered_work_input(&job.work_dir)?;
        let (input_disk, output_disk) = prepare_builder_transport_disks(
            &vm_state_dir,
            &[
                InputTree {
                    name: "job",
                    src: &job_dir,
                },
                InputTree {
                    name: "work",
                    src: work_staging.path(),
                },
            ],
            // The closure seed is still attached below as a virtio-fs share on
            // this path, so it must not also ride the input disk.
            None,
            u64::from(BUILDER_OUTPUT_DISK_MIB) << 20,
        )?;

        let mut krun = krun_context_for_image(&vm_name, &image)?
            .with_resources(self.vcpus, self.memory_mib)
            .with_console_output(path_to_str(&console_log, "console_log")?)
            .with_vsock_socket_dir(path_to_str(&socket_dir, "vm_socket_dir")?)
            .add_disk(
                "nix-store",
                path_to_str(nix_store_lock.path(), "nix_store_img")?,
                false,
            )
            .add_disk("input", path_to_str(&input_disk, "input_disk")?, true)
            .add_disk("output", path_to_str(&output_disk, "output_disk")?, false)
            .add_vsock_port(mvm_agentd::builder_agent::BUILDER_DISPATCH_PORT);
        if guest_agent_vsock {
            krun = krun.add_vsock_port(mvm_agentd::vsock::GUEST_AGENT_PORT);
        }
        if let Some(attachment) =
            builder_runtime_overlay_attachment(&image, runtime_overlay.as_deref())
        {
            krun = krun.with_cmdline(attachment.cmdline).add_disk(
                "runtime-overlay",
                path_to_str(attachment.disk_path, "runtime_overlay_ext4")?,
                attachment.read_only,
            );
        }
        if let Some(share_dir) = self.closure_seed_share(&vm_state_dir)? {
            krun = krun.add_virtio_fs(
                CLOSURE_SEED_TAG,
                path_to_str(&share_dir, "closure_seed_dir")?,
            );
        }

        for disk in &job.extra_disks {
            krun = krun.add_disk(
                disk.id.as_str(),
                path_to_str(&disk.path, "extra_disk")?,
                disk.read_only,
            );
        }
        // Builder VMs are NIC-less: egress goes over the vsock relay below, so
        // the libkrun networking mode must be the disconnected sink — the
        // supervisor rejects anything else. Matches the Stage 0 path.
        krun = krun.with_vsock_direct();

        // A lean Rootfs builder always carries the runtime overlay here
        // (resolution failed closed above), so the disk-transport cmdline is
        // set by `builder_runtime_overlay_attachment` — there is no
        // overlay-absent degraded boot.
        let egress_endpoint = if builder_uses_vsock_egress(&image) {
            let (identity_material, identity_drive) =
                stage_builder_flowmux_identity(&vm_state_dir)?;
            krun = krun
                .with_vsock_direct()
                .add_host_listen_port(mvm_agentd::vsock::EGRESS_PORT)
                .add_disk(
                    "mvm-identity",
                    path_to_str(&identity_drive, "identity_drive")?,
                    true,
                );
            BuilderVsockEgressEndpoint::spawn(&vm_state_dir, identity_material.spawn_config())
                .map(Some)?
        } else {
            krun = krun.with_vsock_direct();
            None
        };

        let cfg = SupervisorConfig {
            krun,
            vm_state_dir: path_to_str(&vm_state_dir, "vm_state_dir")?.to_string(),
            pid_file_name: Some("builder.pid".to_string()),
            tenant_id: None,
            audit_dir: None,
            gateway_audit_socket: None,
            gateway_events_socket: None,
            signing_key_path: None,
            plan: None,
            bundle: None,
            // Builder VMs take the legacy non-bridge path (tenant_id None), so
            // this is inert today (set explicitly to None — no bare-policy
            // override). Step 3 flips builder/dev to trusted_build_egress when
            // they move onto the bridge.
            network_policy: None,
            transparent_terminator_port: None,
            egress_relay_socket: None,
            exclusive_image_lock: None,
            // Builder VMs are always hard-fail; they don't model
            // long-running user workloads where a restart policy would
            // apply.
            bridge_restart_policy: libkrun_sys::BridgeRestartPolicy::HardFail,
        };
        // Spawn the vsock response listener BEFORE the supervisor so
        // it can connect as soon as libkrun creates the dispatch
        // socket. Drained after the supervisor exits — see
        // `log_vsock_response_outcome` for the cross-validation
        // contract.
        let vsock_rx = spawn_vsock_response_listener(&vm_state_dir);
        let guest_agent_rx = if guest_agent_vsock {
            Some(spawn_vsock_socket_observer(
                &vm_state_dir,
                mvm_agentd::vsock::GUEST_AGENT_PORT,
                Duration::from_secs(60),
            ))
        } else {
            None
        };
        let wait_result =
            spawn_supervisor_and_wait(&supervisor_path, &cfg, &vm_state_dir, self.verbose);
        // A clean exit and the poweroff-fallback halt both fall through to the
        // authoritative on-disk job result read below; only a non-zero
        // supervisor exit or a VMM-level failure short-circuits. The
        // fall-through path drains the observation threads alongside its own
        // result cross-validation, so only the short-circuit arms drain here.
        match post_wait_action(wait_result) {
            PostWaitAction::FinalizeFromDisk { halted } => {
                if halted {
                    tracing::debug!(
                        "builder guest halted at job end; deferring to the on-disk job result"
                    );
                }
            }
            PostWaitAction::FailSupervisorExit(code) => {
                drain_builder_observations(guest_agent_rx, vsock_rx);
                if let Some(endpoint) = &egress_endpoint {
                    endpoint.reap();
                }
                return Err(supervisor_exit_error(code, &vm_state_dir));
            }
            PostWaitAction::Propagate(error) => {
                drain_builder_observations(guest_agent_rx, vsock_rx);
                if let Some(endpoint) = &egress_endpoint {
                    endpoint.reap();
                }
                return Err(error);
            }
        }

        extract_builder_transport_output(&output_disk, &job.artifact_out, &job_dir)?;

        let result = match read_job_result_with_diagnostics(&job_dir, &vm_state_dir) {
            Ok(result) => {
                if let Some(rx) = guest_agent_rx {
                    tracing::info!(
                        summary = %describe_vsock_socket_observation(rx, mvm_agentd::vsock::GUEST_AGENT_PORT),
                        "builder guest-agent socket observation"
                    );
                }
                log_vsock_response_outcome(vsock_rx, Some(result.exit_code));
                result
            }
            Err(BuilderVmError::NixBuildFailed(message)) => {
                let guest_agent_summary = guest_agent_rx.map(|rx| {
                    describe_vsock_socket_observation(rx, mvm_agentd::vsock::GUEST_AGENT_PORT)
                });
                return Err(BuilderVmError::NixBuildFailed(format!(
                    "{message}\n{}\n{}",
                    guest_agent_summary.unwrap_or_else(|| {
                        "builder guest-agent socket observation was not enabled".to_string()
                    }),
                    describe_vsock_response_outcome(vsock_rx, None)
                )));
            }
            Err(err) => return Err(err),
        };
        if result.exit_code != 0 {
            if let Some(endpoint) = &egress_endpoint {
                endpoint.reap();
            }
            return Err(shell_job_exit_error(result.exit_code, &result.stderr_tail));
        }

        if let Some(endpoint) = &egress_endpoint {
            endpoint.reap();
        }

        let result = BuilderShellResult {
            job_dir,
            vm_state_dir,
        };
        drop(nix_store_lock);
        Ok(result)
    }

    /// Validate caller-supplied mount paths early. Catches issues
    /// that would otherwise surface as opaque libkrun C-API
    /// failures: missing directories, non-UTF-8 paths (libkrun's
    /// FFI takes `*const c_char` and we'd hit `CString::new`
    /// failures inside `libkrun_sys::sys` otherwise), and
    /// uncreatable artifact dirs.
    ///
    /// Public-in-crate so unit tests can exercise it directly.
    pub(crate) fn validate_mounts(&self, mounts: &BuilderMounts) -> Result<(), BuilderVmError> {
        // Reject non-UTF-8 paths first — libkrun's C API takes
        // `*const c_char` and we want the error message pinned to
        // the offending field rather than at a CString conversion
        // deep inside the FFI. Cheap predicate; runs before any
        // I/O so a test can exercise it on a synthetic path
        // without filesystem support for non-UTF-8 names (APFS).
        ensure_utf8_path(&mounts.flake_src, "flake_src")?;
        ensure_utf8_path(&mounts.artifact_out, "artifact_out")?;
        ensure_utf8_path(&mounts.host_bin_dir, "host_bin_dir")?;
        if let Some(store) = &mounts.host_nix_store {
            ensure_utf8_path(store, "host_nix_store")?;
        }
        if !mounts.flake_src.exists() {
            return Err(BuilderVmError::ExtractionFailed(format!(
                "flake source path does not exist: {}",
                mounts.flake_src.display()
            )));
        }
        if !mounts.flake_src.is_dir() {
            return Err(BuilderVmError::ExtractionFailed(format!(
                "flake source must be a directory: {}",
                mounts.flake_src.display()
            )));
        }
        if !mounts.host_bin_dir.is_dir() {
            return Err(BuilderVmError::ExtractionFailed(format!(
                "host_bin_dir must be an existing directory: {}",
                mounts.host_bin_dir.display()
            )));
        }
        std::fs::create_dir_all(&mounts.artifact_out).map_err(|e| {
            BuilderVmError::ExtractionFailed(format!(
                "creating artifact_out {}: {e}",
                mounts.artifact_out.display()
            ))
        })?;
        Ok(())
    }

    /// Validate the job description. For [`BuilderJob::Flake`] both
    /// fields must be non-empty strings (`flake_ref` may include a
    /// `path:` or `git+` prefix but the prefix-less form is also
    /// accepted — libkrun runs the command verbatim inside the
    /// builder VM). For [`BuilderJob::Install`] the spec path must
    /// exist on the host; B.2 will fill in the rest of the
    /// install-pipeline validation against the parsed spec.
    pub(crate) fn validate_job(&self, job: &BuilderJob) -> Result<(), BuilderVmError> {
        match job {
            BuilderJob::Flake {
                flake_ref,
                attr_path,
            } => {
                if flake_ref.trim().is_empty() {
                    return Err(BuilderVmError::NixBuildFailed(
                        "BuilderJob.flake_ref is empty".to_string(),
                    ));
                }
                if attr_path.trim().is_empty() {
                    return Err(BuilderVmError::NixBuildFailed(
                        "BuilderJob.attr_path is empty".to_string(),
                    ));
                }
            }
            BuilderJob::Install { spec_path } => {
                // Validate the file exists so a caller's typo
                // surfaces here rather than as an opaque
                // NotYetImplemented mid-pipeline.
                if !spec_path.is_file() {
                    return Err(BuilderVmError::ExtractionFailed(format!(
                        "BuilderJob::Install spec_path does not exist or is not a file: {}",
                        spec_path.display()
                    )));
                }
            }
        }
        Ok(())
    }

    fn validate_shell_job(&self, job: &BuilderShellJob) -> Result<(), BuilderVmError> {
        ensure_utf8_path(&job.work_dir, "work_dir")?;
        ensure_utf8_path(&job.artifact_out, "artifact_out")?;
        for disk in &job.extra_disks {
            ensure_utf8_path(&disk.path, "extra_disk")?;
            if disk.id.trim().is_empty() {
                return Err(BuilderVmError::ExtractionFailed(
                    "extra disk id is empty".to_string(),
                ));
            }
            if !disk.path.is_file() {
                return Err(BuilderVmError::ExtractionFailed(format!(
                    "extra disk path does not exist or is not a file: {}",
                    disk.path.display()
                )));
            }
        }
        if !job.work_dir.is_dir() {
            return Err(BuilderVmError::ExtractionFailed(format!(
                "shell job work_dir must be a directory: {}",
                job.work_dir.display()
            )));
        }
        std::fs::create_dir_all(&job.artifact_out).map_err(|e| {
            BuilderVmError::ExtractionFailed(format!(
                "creating artifact_out {}: {e}",
                job.artifact_out.display()
            ))
        })?;
        if job.script.trim().is_empty() {
            return Err(BuilderVmError::NixBuildFailed(
                "builder shell script is empty".to_string(),
            ));
        }
        Ok(())
    }
}

/// Pack `workspace_dir` into a read-only ext4 disk for the Stage 0 `/work`
/// mount, carrying [`crate::rootfs::STAGE0_WORK_EXT4_LABEL`] so
/// `stage0-init` can find it by content instead of by device-enumeration
/// order. Stages a filtered copy first (dropping `target/`, `.git/`, …
/// — [`crate::qemu_builder::WORK_TREE_EXCLUDE_DIRS`], the same list the
/// QEMU Stage 0 path drops) so the pure writer never packs a multi-gigabyte
/// `target/` for nothing, then discards the filtered copy once it's on
/// disk. The image itself is left under `vm_state_dir` for the same
/// existing reaper that already prunes stale Stage 0 VM state (console
/// logs, sockets, …).
fn pack_stage0_work_disk(
    workspace_dir: &std::path::Path,
    vm_state_dir: &std::path::Path,
) -> Result<PathBuf, BuilderVmError> {
    let staged = vm_state_dir.join("work-src");
    crate::qemu_builder::copy_tree_filtered(
        workspace_dir,
        &staged,
        crate::qemu_builder::WORK_TREE_EXCLUDE_DIRS,
    )?;
    let image_path = vm_state_dir.join("work.ext4");
    let input = crate::rootfs::MaterializeExt4Input::new(staged.clone(), image_path.clone(), 0)
        .with_volume_label(crate::rootfs::STAGE0_WORK_EXT4_LABEL);
    let result = crate::rootfs::materialize_ext4_pure(&input)
        .map_err(|e| BuilderVmError::ExtractionFailed(format!("packing /work ext4 disk: {e}")));
    let _ = std::fs::remove_dir_all(&staged);
    result?;
    Ok(image_path)
}

#[cfg(test)]
struct BuilderShellKrunContextParams<'a> {
    vm_name: &'a str,
    image: &'a BuilderVmImage,
    vcpus: u8,
    memory_mib: u32,
    console_log: &'a Path,
    vm_state_dir: &'a Path,
    nix_store_img: &'a Path,
    work_dir: &'a Path,
    artifact_out: &'a Path,
    job_dir: &'a Path,
    extra_disks: &'a [BuilderExtraDisk],
}

#[cfg(test)]
fn builder_shell_krun_context(
    params: &BuilderShellKrunContextParams<'_>,
) -> Result<KrunContext, BuilderVmError> {
    let socket_dir = mvm_core::config::vm_socket_dir_at(params.vm_state_dir);
    let mut krun = krun_context_for_image(params.vm_name, params.image)?
        .with_resources(params.vcpus, params.memory_mib)
        .with_console_output(path_to_str(params.console_log, "console_log")?)
        .with_vsock_socket_dir(path_to_str(&socket_dir, "vm_socket_dir")?)
        .add_disk(
            "nix-store",
            path_to_str(params.nix_store_img, "nix_store_img")?,
            false,
        )
        .add_virtio_fs("work", path_to_str(params.work_dir, "work_dir")?)
        .add_virtio_fs("out", path_to_str(params.artifact_out, "artifact_out")?)
        .add_virtio_fs("job", path_to_str(params.job_dir, "job_dir")?)
        .add_vsock_port(mvm_agentd::builder_agent::BUILDER_DISPATCH_PORT);

    for disk in params.extra_disks {
        krun = krun.add_disk(
            disk.id.as_str(),
            path_to_str(&disk.path, "extra_disk")?,
            disk.read_only,
        );
    }

    Ok(krun.with_vsock_direct())
}

/// Reject a path that isn't UTF-8 representable. Internal helper —
/// the libkrun FFI requires CString-convertible paths and we want
/// the failure pinned to the offending field with a useful name.
pub(crate) fn ensure_utf8_path(p: &std::path::Path, field: &str) -> Result<(), BuilderVmError> {
    p.to_str().ok_or_else(|| {
        BuilderVmError::ExtractionFailed(format!("{field} has non-UTF-8 bytes: {p:?}"))
    })?;
    Ok(())
}

impl BuilderVm for LibkrunBuilderVm {
    /// Adapt the backend-agnostic `(root_dir, entry)` Stage 0
    /// contract to libkrun's `BuilderVmImage::RootDir` and run it.
    fn run_stage0(
        &self,
        guest_root_dir: &std::path::Path,
        entry_path: &str,
        workspace_dir: &std::path::Path,
        artifact_out: &std::path::Path,
        host_bin_dir: &std::path::Path,
    ) -> Result<(), BuilderVmError> {
        let image = BuilderVmImage::new_root_dir(guest_root_dir.to_path_buf(), entry_path);
        self.run_stage0_impl(image, workspace_dir, artifact_out, host_bin_dir)
    }

    fn run_build(
        &self,
        job: &BuilderJob,
        mounts: &BuilderMounts,
    ) -> Result<BuilderArtifacts, BuilderVmError> {
        // 1. Validate caller-supplied inputs early; clearer
        //    errors than failing inside the libkrun FFI.
        self.validate_mounts(mounts)?;
        self.validate_job(job)?;

        // 2. Refuse to proceed on a host without libkrun. The
        //    `builder-vm` feature being compiled
        //    in doesn't imply the runtime library is installed.
        if !libkrun_sys::is_available() {
            return Err(BuilderVmError::LibkrunUnavailable(format!(
                "libkrun shared library not found on host. {}",
                libkrun_sys::install_hint()
            )));
        }

        // 3. Find the supervisor binary up front. Failing now is
        //    a much better UX than spawning the supervisor with a
        //    stale PATH and discovering at child-exit time.
        let supervisor_path = resolve_supervisor_path()?;

        // 4. Find or initialise the builder VM image (kernel +
        //    rootfs.ext4 + canonical cmdline) the builder-vm flake
        //    produces. Stage 0 callers can provide a bootstrap
        //    image so a fresh source checkout can build the builder
        //    image cache without first downloading it.
        let image = match &self.image_override {
            Some(image) => image.clone(),
            None => ensure_builder_vm_image()?,
        };

        // 5. Allocate / locate the persistent `/nix-store`
        //    virtio-blk image. First build on a host pays the
        //    sparse-allocate cost; subsequent builds reuse the
        //    warm Nix store.
        let nix_store_lock = acquire_nix_store_image_lock(
            &builder_vm_cache_dir(),
            host_arch_tag(),
            u64::from(self.nix_store_mib),
        )?;

        // 6. Stage the per-build job dir. Flake jobs get
        //    `cmd.sh`; install jobs get `install_spec.json`.
        //    `mvm-host-vm-init` dispatches based on which file it
        //    sees.
        let job_id = unique_job_id();
        let job_dir = builder_vm_cache_dir().join("jobs").join(&job_id);
        stage_job_dir(
            &job_dir,
            job,
            mounts.staged_user_flake.as_deref(),
            // Override mode (staged_user_flake = Some) mounts the workspace
            // at /work as `flake_src`; stage its filtered cargo tree so the
            // build can pin `mvm/mvm-workspace` to it.
            mounts
                .staged_user_flake
                .as_ref()
                .map(|_| mounts.flake_src.as_path()),
        )?;
        // Same announcement as the single-shot path — see the
        // identical block in `LibkrunBuilderVm::run_build`.
        tracing::info!(
            job_dir = %job_dir.display(),
            "builder VM job dir staged (nix-stderr.log streams here as the build runs)"
        );

        // 7. Build the `KrunContext` libkrun consumes. Three
        //    virtio-fs shares (work / out / job), one virtio-blk
        //    (Nix store), and the canonical cmdline pinned at the
        //    flake output. The mount layout is identical for
        //    flake + install jobs — the guest decides what to do
        //    with each share based on the staged job files.
        let vm_name = format!("mvm-builder-vm-{job_id}");
        let vm_state_dir = builder_vm_cache_dir().join("vms").join(&vm_name);
        std::fs::create_dir_all(&vm_state_dir).map_err(|e| {
            BuilderVmError::ExtractionFailed(format!(
                "creating builder VM state dir {}: {e}",
                vm_state_dir.display()
            ))
        })?;

        // Route the guest's serial console to a per-VM log file so
        // failures of the in-VM cmd.sh / mvm-host-vm-init produce a
        // readable transcript. Without this, libkrun discards the
        // hvc0 output silently and "supervisor running, then exits 1"
        // is the only observable signal.
        let console_log = vm_state_dir.join("console.log");
        let socket_dir = builder_vsock_socket_dir(&vm_state_dir)?;
        let runtime_overlay = builder_runtime_overlay_or_bail(&image)?;
        let guest_agent_vsock =
            builder_runtime_overlay_guest_agent_enabled(&image, runtime_overlay.as_deref());
        // `mounts.flake_src` is the repo root itself on a source checkout
        // (the "local-mvm override" invariant): stage a filtered copy so
        // `target/`/`.worktrees/`/`.git/` never ride the input tar into the
        // guest's RAM-capped extraction tmpfs. `work_staging` must outlive
        // this call.
        let work_staging = stage_filtered_work_input(&mounts.flake_src)?;
        let (input_disk, output_disk) = prepare_builder_transport_disks(
            &vm_state_dir,
            &[
                InputTree {
                    name: "job",
                    src: &job_dir,
                },
                InputTree {
                    name: "work",
                    src: work_staging.path(),
                },
                InputTree {
                    name: "mvm-bins",
                    src: &mounts.host_bin_dir,
                },
            ],
            // The closure seed is still attached below as a virtio-fs share on
            // this path, so it must not also ride the input disk.
            None,
            u64::from(BUILDER_OUTPUT_DISK_MIB) << 20,
        )?;
        let mut krun = krun_context_for_image(&vm_name, &image)?
            .with_resources(self.vcpus, self.memory_mib)
            .with_console_output(path_to_str(&console_log, "console_log")?)
            .with_vsock_socket_dir(path_to_str(&socket_dir, "vm_socket_dir")?)
            .add_disk(
                "nix-store",
                path_to_str(nix_store_lock.path(), "nix_store_img")?,
                false,
            )
            .add_disk("input", path_to_str(&input_disk, "input_disk")?, true)
            .add_disk("output", path_to_str(&output_disk, "output_disk")?, false)
            .add_vsock_port(mvm_agentd::builder_agent::BUILDER_DISPATCH_PORT);
        if guest_agent_vsock {
            krun = krun.add_vsock_port(mvm_agentd::vsock::GUEST_AGENT_PORT);
        }
        if let Some(attachment) =
            builder_runtime_overlay_attachment(&image, runtime_overlay.as_deref())
        {
            krun = krun.with_cmdline(attachment.cmdline).add_disk(
                "runtime-overlay",
                path_to_str(attachment.disk_path, "runtime_overlay_ext4")?,
                attachment.read_only,
            );
        }
        if let Some(share_dir) = self.closure_seed_share(&vm_state_dir)? {
            krun = krun.add_virtio_fs(
                CLOSURE_SEED_TAG,
                path_to_str(&share_dir, "closure_seed_dir")?,
            );
        }
        // Builder VMs are NIC-less: egress goes over the vsock relay below, so
        // the libkrun networking mode must be the disconnected sink — the
        // supervisor rejects anything else. Matches the Stage 0 path.
        krun = krun.with_vsock_direct();

        // A lean Rootfs builder always carries the runtime overlay here
        // (resolution failed closed above), so the disk-transport cmdline is
        // set by `builder_runtime_overlay_attachment` — there is no
        // overlay-absent degraded boot.
        let egress_endpoint = if builder_uses_vsock_egress(&image) {
            let (identity_material, identity_drive) =
                stage_builder_flowmux_identity(&vm_state_dir)?;
            krun = krun
                .with_vsock_direct()
                .add_host_listen_port(mvm_agentd::vsock::EGRESS_PORT)
                .add_disk(
                    "mvm-identity",
                    path_to_str(&identity_drive, "identity_drive")?,
                    true,
                );
            BuilderVsockEgressEndpoint::spawn(&vm_state_dir, identity_material.spawn_config())
                .map(Some)?
        } else {
            krun = krun.with_vsock_direct();
            None
        };

        // 8. Drive the supervisor: pipe `SupervisorConfig` to
        //    stdin and **wait** for the child to exit. Unlike
        //    `LibkrunBackend::start` (returns immediately after
        //    the PID file appears), the builder is a one-shot —
        //    we want the supervisor to live until the guest
        //    powers off, then collect the result.
        let cfg = SupervisorConfig {
            krun,
            vm_state_dir: path_to_str(&vm_state_dir, "vm_state_dir")?.to_string(),
            pid_file_name: Some("builder.pid".to_string()),
            tenant_id: None,
            audit_dir: None,
            gateway_audit_socket: None,
            gateway_events_socket: None,
            signing_key_path: None,
            plan: None,
            bundle: None,
            // Builder VMs take the legacy non-bridge path (tenant_id None), so
            // this is inert today (set explicitly to None — no bare-policy
            // override). Step 3 flips builder/dev to trusted_build_egress when
            // they move onto the bridge.
            network_policy: None,
            transparent_terminator_port: None,
            egress_relay_socket: None,
            exclusive_image_lock: None,
            // Builder VMs are always hard-fail; they don't model
            // long-running user workloads where a restart policy would
            // apply.
            bridge_restart_policy: libkrun_sys::BridgeRestartPolicy::HardFail,
        };
        // Same dispatch-listener wiring as `run_shell_script`.
        // Drained after the supervisor exits (or right before bailing
        // on supervisor failure) so the background thread always gets
        // a chance to log.
        let vsock_rx = spawn_vsock_response_listener(&vm_state_dir);
        let guest_agent_rx = if guest_agent_vsock {
            Some(spawn_vsock_socket_observer(
                &vm_state_dir,
                mvm_agentd::vsock::GUEST_AGENT_PORT,
                Duration::from_secs(60),
            ))
        } else {
            None
        };
        // Stream the in-guest `nix --print-build-logs` output to the terminal as
        // the build runs (under `-v`/`RUST_LOG`); no-op otherwise. The console
        // echo carries init/kernel lines; this carries the nix build log, which
        // cmd.sh redirects to the host-readable `<job_dir>/nix-stderr.log`.
        let _job_log =
            crate::builder_vm_runtime::JobLogStreamer::start(job_dir.join("nix-stderr.log"));
        let wait_result =
            spawn_supervisor_and_wait(&supervisor_path, &cfg, &vm_state_dir, self.verbose);
        // The observation threads must be drained on every exit path (each
        // consumes its receiver). The per-variant finalize below is the
        // authoritative success/failure gate, so a clean exit and the
        // poweroff-fallback halt both fall through to it; only a non-zero
        // supervisor exit or a VMM-level failure short-circuits. `None` to the
        // drain skips file/vsock cross-validation (not wired per-variant here).
        match post_wait_action(wait_result) {
            PostWaitAction::FinalizeFromDisk { halted } => {
                if halted {
                    tracing::debug!(
                        "builder guest halted at job end; deferring to the on-disk build result"
                    );
                }
                drain_builder_observations(guest_agent_rx, vsock_rx);
            }
            PostWaitAction::FailSupervisorExit(code) => {
                drain_builder_observations(guest_agent_rx, vsock_rx);
                if let Some(endpoint) = &egress_endpoint {
                    endpoint.reap();
                }
                return Err(supervisor_exit_error(code, &vm_state_dir));
            }
            PostWaitAction::Propagate(error) => {
                drain_builder_observations(guest_agent_rx, vsock_rx);
                if let Some(endpoint) = &egress_endpoint {
                    endpoint.reap();
                }
                return Err(error);
            }
        }
        extract_builder_transport_output(&output_disk, &mounts.artifact_out, &job_dir)?;

        // 9. Per-variant result parsing + artifact validation.
        //    Flake jobs read `<job_dir>/result` (legacy shape);
        //    install jobs read `<artifact_out>/result.json` and
        //    return a different artifact variant.
        let artifacts = match job {
            BuilderJob::Flake { .. } => finalize_flake_job(&job_dir, &mounts.artifact_out, &job_id),
            BuilderJob::Install { .. } => finalize_install_job(&mounts.artifact_out),
        }?;
        if let Some(endpoint) = &egress_endpoint {
            endpoint.reap();
        }
        drop(nix_store_lock);
        Ok(artifacts)
    }

    fn cleanup(&self) -> Result<(), BuilderVmError> {
        // Hygiene: prune old job dirs under
        // `~/.mvm/cache/builder-vm/jobs/` past N days. No-op until a
        // retention policy is picked.
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────
// LibkrunBuilderBackend
//
// This is the hypervisor-agnostic seam's libkrun-flavored impl.
// Wraps `spawn_supervisor_in_background` + `wait_with_panic_detector_until`
// + the KrunContext-building pattern from `LibkrunBuilderVm::run_build`.
// Today nothing in production uses it — `LibkrunBuilderVm::run_build`
// stays as-is. The follow-up slice introduces a `BuilderVmRuntime`
// helper that takes `&dyn VmBackendForBuilder` and migrates
// `run_build` to use it; this struct is what plugs into that helper
// for the libkrun backend.
//
// Lives in the same file as the private helpers it calls
// (`resolve_supervisor_path`, `ensure_builder_vm_image`,
// `krun_context_for_image`, `path_to_str`,
// `spawn_supervisor_in_background`, `wait_with_panic_detector_until`,
// `WaitOutcome`, `DEFAULT_PANIC_POLL_INTERVAL`). Putting it here
// avoids widening those helpers' visibility for a single new caller.
// ─────────────────────────────────────────────────────────────────

/// libkrun-flavored impl of the hypervisor-agnostic
/// [`VmBackendForBuilder`] primitive trait.
///
/// Holds the resolved supervisor binary path and the cached
/// builder VM image (kernel + rootfs + cmdline). Construction
/// eagerly resolves both so a missing prerequisite surfaces at
/// `new()`-time rather than mid-build.
///
/// `LibkrunBuilderVm::run_build` does not yet use this — a
/// follow-up slice introduces `BuilderVmRuntime` and flips the
/// migration. Today it exists so the `VzBuilderVm` work has a
/// worked example of how to wrap a hypervisor-specific supervisor
/// behind the seam.
pub struct LibkrunBuilderBackend {
    supervisor_path: PathBuf,
    image: BuilderVmImage,
}

impl LibkrunBuilderBackend {
    /// Resolve the supervisor binary + builder VM image eagerly.
    /// Surfaces "supervisor binary missing" / "builder image not
    /// installed" at the call site rather than at first run.
    pub fn new() -> Result<Self, BuilderVmError> {
        let supervisor_path = resolve_supervisor_path()?;
        let image = ensure_builder_vm_image()?;
        Ok(Self {
            supervisor_path,
            image,
        })
    }

    /// Test seam — caller supplies the supervisor path + image
    /// directly so unit tests can construct a backend without
    /// touching the host's libkrun install or the image cache.
    /// Used by the construction test below; the future
    /// `BuilderVmRuntime` test suite will reuse this pattern.
    pub fn with_supervisor_and_image(supervisor_path: PathBuf, image: BuilderVmImage) -> Self {
        Self {
            supervisor_path,
            image,
        }
    }
}

impl VmBackendForBuilder for LibkrunBuilderBackend {
    fn run_attached_with_mounts(
        &self,
        config: &BuilderVmRunConfig,
        mounts: &[BuilderVmMount],
        extra_disks: &[BuilderVmDisk],
        timeout: Duration,
    ) -> Result<BuilderVmExitInfo, BuilderVmError> {
        // Same refusal posture as run_build's step 2: a missing
        // shared library is the most-common failure mode and an
        // early surface keeps the supervisor spawn from producing
        // a confusing rc -2.
        if !libkrun_sys::is_available() {
            return Err(BuilderVmError::LibkrunUnavailable(format!(
                "libkrun shared library not found on host. {}",
                libkrun_sys::install_hint()
            )));
        }

        std::fs::create_dir_all(&config.vm_state_dir).map_err(|e| {
            BuilderVmError::ExtractionFailed(format!(
                "creating builder VM state dir {}: {e}",
                config.vm_state_dir.display()
            ))
        })?;

        let console_log = self.console_log_path(&config.vm_state_dir);
        let socket_dir = builder_vsock_socket_dir(&config.vm_state_dir)?;

        // KrunContext construction — same shape as run_build's
        // step 7, but parameterised on the trait's hypervisor-
        // agnostic config. Builds top-down (resources first, then
        // disks, then mounts, then vsock ports, then networking)
        // because libkrun's builder methods consume `self` by value.
        let mut krun = krun_context_for_image(&config.name, &self.image)?
            .with_resources(config.vcpus, config.memory_mib)
            .with_console_output(path_to_str(&console_log, "console_log")?)
            .with_vsock_socket_dir(path_to_str(&socket_dir, "vm_socket_dir")?);
        for disk in extra_disks {
            krun = krun.add_disk(
                disk.id.clone(),
                path_to_str(&disk.host_path, "extra_disk_path")?,
                disk.read_only,
            );
        }
        for mount in mounts {
            // libkrun's add_virtio_fs takes only (tag, host_path) —
            // every share is RW from the guest's perspective. The
            // `BuilderVmMount::read_only` flag is currently ignored
            // on this backend; a hypervisor with native virtio-fs
            // read-only support can honour it instead.
            krun = krun.add_virtio_fs(
                mount.tag.clone(),
                path_to_str(&mount.host_path, "mount_host_path")?,
            );
        }
        for port in &config.vsock_ports {
            krun = krun.add_vsock_port(*port);
        }
        if builder_uses_vsock_egress(&self.image)
            && let BuilderVmImage::Rootfs { cmdline, .. } = &self.image
        {
            krun = krun
                .with_cmdline(
                    crate::builder_cmdline::checked_builder_cmdline(builder_vsock_egress_cmdline(
                        cmdline,
                    ))
                    .map_err(BuilderVmError::NixBuildFailed)?,
                )
                .with_vsock_direct()
                .add_host_listen_port(mvm_agentd::vsock::EGRESS_PORT);
        }
        let egress_endpoint = if builder_uses_vsock_egress(&self.image) {
            let (identity_material, identity_drive) =
                stage_builder_flowmux_identity(&config.vm_state_dir)?;
            krun = krun.add_disk(
                "mvm-identity",
                path_to_str(&identity_drive, "identity_drive")?,
                true,
            );
            BuilderVsockEgressEndpoint::spawn(
                &config.vm_state_dir,
                identity_material.spawn_config(),
            )
            .map(Some)?
        } else {
            krun = krun.with_vsock_direct();
            None
        };

        let cfg = SupervisorConfig {
            krun,
            vm_state_dir: path_to_str(&config.vm_state_dir, "vm_state_dir")?.to_string(),
            pid_file_name: Some("builder.pid".to_string()),
            tenant_id: None,
            audit_dir: None,
            gateway_audit_socket: None,
            gateway_events_socket: None,
            signing_key_path: None,
            plan: None,
            bundle: None,
            // Builder VMs take the legacy non-bridge path (tenant_id None), so
            // this is inert today (set explicitly to None — no bare-policy
            // override). Step 3 flips builder/dev to trusted_build_egress when
            // they move onto the bridge.
            network_policy: None,
            transparent_terminator_port: None,
            egress_relay_socket: None,
            exclusive_image_lock: None,
            // Builder VMs are always hard-fail; they don't model
            // long-running user workloads where a restart policy would
            // apply.
            bridge_restart_policy: libkrun_sys::BridgeRestartPolicy::HardFail,
        };

        let mut child =
            spawn_supervisor_in_background(&self.supervisor_path, &cfg, &config.vm_state_dir)?;
        // Same wait + panic-detection shape `spawn_supervisor_and_wait`
        // uses, but we surface the panic line via the seam's exit
        // info instead of an Err so the future BuilderVmRuntime
        // helper can decide whether the job's expectations were
        // met.
        let outcome = match wait_with_panic_detector_until(
            &mut child,
            Some(&console_log),
            DEFAULT_PANIC_POLL_INTERVAL,
            Some(timeout),
            false,
        ) {
            Ok(WaitOutcome::Clean(code)) => Ok(BuilderVmExitInfo {
                exit_code: Some(code),
                panic_line: None,
            }),
            Ok(WaitOutcome::KernelPanic { panic_line, .. }) => Ok(BuilderVmExitInfo {
                exit_code: None,
                panic_line: Some(panic_line),
            }),
            Ok(WaitOutcome::GuestHalted { halt_line, .. }) => {
                // A halt is a build failure, not a clean exit — surface it as a
                // non-zero exit with the halt reason so the runtime treats the
                // job as failed instead of waiting to the wall-clock timeout.
                Ok(BuilderVmExitInfo {
                    exit_code: Some(1),
                    panic_line: Some(halt_line),
                })
            }
            Ok(WaitOutcome::Timeout) => Err(BuilderVmError::NixBuildFailed(format!(
                "builder VM exceeded {} seconds wall-clock; killed. Console log at {}.",
                timeout.as_secs(),
                console_log.display(),
            ))),
            Err(e) => Err(BuilderVmError::ExtractionFailed(format!(
                "wait on supervisor child: {e}"
            ))),
        };
        if let Some(endpoint) = &egress_endpoint {
            endpoint.reap();
        }
        outcome
    }

    fn console_log_path(&self, vm_state_dir: &Path) -> PathBuf {
        vm_state_dir.join("console.log")
    }
}

// ─────────────────────────────────────────────────────────────────
// Helpers — kept in one place at the bottom of the file rather
// than scattered through `impl` blocks so the run_build pipeline
// reads top-down.
// ─────────────────────────────────────────────────────────────────

/// Resolved builder VM image. One of two boot shapes:
///
/// - **Rootfs**: kernel + rootfs.ext4 + cmdline. The steady-state
///   builder VM path produced by the builder-vm flake.
/// - **RootDir**: host directory + guest entrypoint. The Stage 0
///   bootstrap path. libkrun's bundled kernel boots transparently;
///   no host-built kernel involved.
#[derive(Debug, Clone)]
pub enum BuilderVmImage {
    /// Steady-state builder VM image.
    Rootfs {
        kernel_path: PathBuf,
        rootfs_path: PathBuf,
        cmdline: String,
    },
    /// Host directory libkrun mounts as the guest root via virtiofs.
    /// `entry_path` is the guest PID 1 (relative to `root_dir`).
    RootDir {
        root_dir: PathBuf,
        entry_path: String,
    },
}

impl BuilderVmImage {
    /// Image that boots from a rootfs ext4 disk + the supervisor's
    /// canonical `init=` cmdline.
    pub fn new(kernel_path: PathBuf, rootfs_path: PathBuf, cmdline: String) -> Self {
        Self::Rootfs {
            kernel_path,
            rootfs_path,
            cmdline,
        }
    }

    /// Image that hands a host directory to libkrun as the guest
    /// root via `krun_set_root`. libkrun's bundled kernel boots
    /// transparently. `entry_path` is the guest PID 1, relative to
    /// `root_dir`.
    pub fn new_root_dir(root_dir: PathBuf, entry_path: impl Into<String>) -> Self {
        Self::RootDir {
            root_dir,
            entry_path: entry_path.into(),
        }
    }
}

/// Build the right `KrunContext` flavor for a [`BuilderVmImage`],
/// pre-populated with the variant's kernel cmdline (where applicable).
/// `RootDir` images carry no cmdline — libkrun handles `set_root`
/// mode without one.
/// The alignment KVM's `KVM_SET_USER_MEMORY_REGION` enforces: the **host** page
/// size. 4 KiB on x86_64 and 4K-page aarch64, but 16 KiB / 64 KiB aarch64 hosts
/// exist (RHEL/CentOS 64K-page kernels), where a kernel aligned only to 4 KiB
/// still trips `EINVAL`. Query `sysconf(_SC_PAGESIZE)` so the padding is correct
/// on every host instead of assuming 4 KiB; fall back to 4 KiB only if the query
/// is unavailable.
fn host_page_size() -> u64 {
    #[cfg(unix)]
    {
        // SAFETY: `sysconf` is a side-effect-free query with no preconditions.
        let v = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if v > 0 {
            return v as u64;
        }
    }
    4096
}

/// Round `n` up to the next multiple of `align`.
fn align_up(n: u64, align: u64) -> u64 {
    n.div_ceil(align) * align
}

/// libkrun maps the external kernel into guest memory with the kernel file's
/// exact size. Linux KVM rejects a `KVM_SET_USER_MEMORY_REGION` whose size is
/// not a multiple of the host page size, so an unaligned `vmlinux` makes VM
/// creation fail with `EINVAL` (`rc -22`) — distinct from a `nix build` error,
/// and previously masked by the libkrun→QEMU builder fallback. macOS HVF has no
/// such requirement, so this is a no-op off Linux.
///
/// Return a kernel path whose file size is page-aligned: the original when it
/// already is, otherwise a zero-padded sibling (`vmlinux` →
/// `vmlinux.page-aligned`) created next to it and reused across builds. Trailing
/// zeros are safe — libkrun loads the kernel from its own headers; the padded
/// tail is unused guest RAM.
///
/// Scope: only the external-`vmlinux` (`Rootfs`) path runs this. `RootDir` /
/// Stage 0 boots use libkrun's bundled libkrunfw kernel via `set_kernel`, which
/// libkrun maps itself — they never reach here and need no padding.
fn page_aligned_kernel(kernel_path: &Path) -> Result<PathBuf, BuilderVmError> {
    if !cfg!(target_os = "linux") {
        return Ok(kernel_path.to_path_buf());
    }
    let size = std::fs::metadata(kernel_path)
        .map_err(|e| {
            BuilderVmError::ExtractionFailed(format!(
                "stat builder kernel {}: {e}",
                kernel_path.display()
            ))
        })?
        .len();
    let align = host_page_size();
    if size.is_multiple_of(align) {
        return Ok(kernel_path.to_path_buf());
    }
    let aligned_size = align_up(size, align);
    let aligned_path = kernel_path.with_extension("page-aligned");
    if !aligned_copy_is_current(&aligned_path, aligned_size, kernel_path) {
        write_zero_padded_copy(kernel_path, &aligned_path, aligned_size)?;
    }
    Ok(aligned_path)
}

fn builder_kernel_for_host(kernel_path: &Path) -> Result<(PathBuf, KernelFormat), BuilderVmError> {
    let normalized = if cfg!(target_arch = "x86_64") && kernel_path.exists() {
        mvm_vmm::host::fc_kernel::ensure_fc_loadable_kernel(kernel_path).map_err(|e| {
            BuilderVmError::ExtractionFailed(format!(
                "prepare x86_64 libkrun-builder kernel from {}: {e}",
                kernel_path.display()
            ))
        })?
    } else {
        kernel_path.to_path_buf()
    };
    let aligned = page_aligned_kernel(&normalized)?;
    let format = if cfg!(target_arch = "x86_64") {
        KernelFormat::Elf
    } else {
        KernelFormat::Raw
    };
    Ok((aligned, format))
}

/// True when `aligned_path` is a reusable cached copy: it exists, has the
/// expected padded size, and is no older than the source (a rebuilt `vmlinux`
/// regenerates it).
fn aligned_copy_is_current(aligned_path: &Path, aligned_size: u64, source: &Path) -> bool {
    let (Ok(a), Ok(s)) = (std::fs::metadata(aligned_path), std::fs::metadata(source)) else {
        return false;
    };
    if a.len() != aligned_size {
        return false;
    }
    matches!((a.modified(), s.modified()), (Ok(am), Ok(sm)) if am >= sm)
}

/// Copy `source` to `dest` and zero-extend it to `padded_size` (`set_len`
/// zero-fills the tail). Written to a process-unique temp sibling then renamed
/// onto `dest`, so a concurrent reader never sees a half-written kernel and two
/// builders sharing a cache dir don't interleave each other's copy/extend on a
/// shared `.tmp` path — each writes its own `.tmp.<pid>` and the final rename is
/// atomic (last-writer-wins; both produce byte-identical padded copies).
fn write_zero_padded_copy(
    source: &Path,
    dest: &Path,
    padded_size: u64,
) -> Result<(), BuilderVmError> {
    let mut tmp = dest.as_os_str().to_owned();
    tmp.push(format!(".tmp.{}", std::process::id()));
    let tmp = PathBuf::from(tmp);
    std::fs::copy(source, &tmp).map_err(|e| {
        BuilderVmError::ExtractionFailed(format!(
            "copy kernel {} -> {}: {e}",
            source.display(),
            tmp.display()
        ))
    })?;
    // `fs::copy` preserves the source's mode; the cached `vmlinux` comes from a
    // read-only Nix store path, so make the working copy writable before we
    // extend it (else `set_len` fails EACCES for a non-root builder).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644)).map_err(|e| {
            BuilderVmError::ExtractionFailed(format!("chmod {}: {e}", tmp.display()))
        })?;
    }
    let f = std::fs::OpenOptions::new()
        .write(true)
        .open(&tmp)
        .map_err(|e| BuilderVmError::ExtractionFailed(format!("open {}: {e}", tmp.display())))?;
    f.set_len(padded_size)
        .map_err(|e| BuilderVmError::ExtractionFailed(format!("pad {}: {e}", tmp.display())))?;
    drop(f);
    std::fs::rename(&tmp, dest).map_err(|e| {
        BuilderVmError::ExtractionFailed(format!(
            "rename {} -> {}: {e}",
            tmp.display(),
            dest.display()
        ))
    })
}

fn krun_context_for_image(
    vm_name: &str,
    image: &BuilderVmImage,
) -> Result<KrunContext, BuilderVmError> {
    match image {
        BuilderVmImage::Rootfs {
            kernel_path,
            rootfs_path,
            cmdline,
        } => {
            let (kernel, kernel_format) = builder_kernel_for_host(kernel_path)?;
            Ok(KrunContext::new(
                vm_name,
                path_to_str(&kernel, "kernel_path")?,
                path_to_str(rootfs_path, "rootfs_path")?,
            )
            .with_cmdline(
                crate::builder_cmdline::checked_builder_cmdline(cmdline.clone())
                    .map_err(BuilderVmError::NixBuildFailed)?,
            )
            .with_kernel_format(kernel_format))
        }
        BuilderVmImage::RootDir {
            root_dir,
            entry_path,
        } => Ok(KrunContext::new_root_dir(
            vm_name,
            path_to_str(root_dir, "root_dir")?,
            entry_path.as_str(),
        )),
    }
}

/// Host architecture tag used as a cache-key segment for
/// per-arch builder VM images. `aarch64` on Apple Silicon /
/// ARM Linux, `x86_64` everywhere else. The builder-vm flake
/// emits both per release.
pub(crate) fn host_arch_tag() -> &'static str {
    crate::builder_vm::host_arch_tag()
}

/// `~/.mvm/cache/builder-vm/`. Wrapper around
/// `mvm_core::config::mvm_cache_dir()` to keep the per-arch
/// subdirs in one place. Created lazily by callers — this
/// function does not touch the filesystem.
pub(crate) fn builder_vm_cache_dir() -> PathBuf {
    crate::builder_vm::builder_vm_cache_dir()
}

#[derive(Debug, Deserialize)]
struct BuilderVmCacheManifest {
    #[serde(default)]
    cache_contract_version: u32,
    #[serde(default)]
    runtime_overlay_ready: bool,
    #[serde(default)]
    vsock_egress_ready: bool,
}

fn read_builder_vm_cache_manifest(
    manifest_path: &Path,
    arch_dir: &Path,
) -> Result<BuilderVmCacheManifest, BuilderVmError> {
    let body = std::fs::read_to_string(manifest_path).map_err(|e| {
        BuilderVmError::ExtractionFailed(format!(
            "{} missing or unreadable ({e}). The builder VM cache is poisoned; delete {} and re-run `mvmctl bootstrap` to re-bootstrap.",
            manifest_path.display(),
            arch_dir.display(),
        ))
    })?;
    serde_json::from_str(&body).map_err(|e| {
        BuilderVmError::ExtractionFailed(format!(
            "{} is malformed ({e}). The builder VM cache is poisoned; delete {} and re-run `mvmctl bootstrap` to re-bootstrap.",
            manifest_path.display(),
            arch_dir.display(),
        ))
    })
}

fn builder_vm_source_checkout_root() -> Option<PathBuf> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir.parent()?.parent()?.to_path_buf();
    workspace_root
        .join("nix")
        .join("images")
        .join("builder-vm")
        .join("flake.nix")
        .is_file()
        .then_some(workspace_root)
}

fn default_builder_vm_cache_dir() -> PathBuf {
    crate::cache_install::default_cache_root().join("builder-vm")
}

fn seed_builder_vm_image_from_default_cache(arch_dir: &Path) -> Result<bool, BuilderVmError> {
    crate::cache_install::seed_on_miss(
        &builder_vm_cache_dir().join(host_arch_tag()),
        &default_builder_vm_cache_dir().join(host_arch_tag()),
        |source_arch_dir| {
            // Seeding from the default cache is opportunistic. If the host's
            // shared cache is stale or malformed, skip it and let
            // source-checkout auto-bootstrap build a fresh image into the
            // isolated target cache. A missing dir fails validation too.
            validate_builder_vm_image_cache(source_arch_dir).ok()?;
            // Same policy for a shared cache whose recorded digests no longer
            // describe its bytes: decline the seed rather than propagate it.
            // Declining (not erroring) matters — an error here would abort the
            // build instead of falling through to a fresh local build.
            if !shared_cache_digests_are_trustworthy(source_arch_dir) {
                return None;
            }
            Some(source_arch_dir.to_path_buf())
        },
        |source_arch_dir| copy_builder_vm_image_files(&source_arch_dir, arch_dir),
    )
}

/// Does the host's shared cache still match the digests it recorded?
///
/// This is the admission boundary — the one moment bytes cross from the shared
/// cache into an isolated root — so it is where the check belongs. It is
/// deliberately not in `validate_builder_vm_image_cache`, which runs on every
/// builder VM start: re-hashing a multi-hundred-megabyte rootfs per start is
/// not a trade worth making on a host the threat model already trusts.
///
/// A cache carrying no manifest at all predates the sidecar or came from
/// another populator. Absence is not evidence of tampering, so it passes.
fn shared_cache_digests_are_trustworthy(source_arch_dir: &Path) -> bool {
    let check = crate::cache_install::verify_digest_manifest(
        source_arch_dir,
        crate::cache_install::BUILDER_VM_ARTIFACT_DIGEST_FILE,
        crate::cache_install::BUILDER_VM_CACHE_ARTIFACTS,
    );
    match check {
        crate::cache_install::DigestManifestCheck::Match
        | crate::cache_install::DigestManifestCheck::ManifestAbsent => true,
        rejected => {
            // A silently declined seed is invisible otherwise, and this one
            // means someone's shared cache is damaged.
            tracing::debug!(
                source = %source_arch_dir.display(),
                verdict = ?rejected,
                "declining to seed builder image from shared cache: recorded digests do not match"
            );
            false
        }
    }
}

fn copy_builder_vm_image_files(
    source_arch_dir: &Path,
    arch_dir: &Path,
) -> Result<(), BuilderVmError> {
    std::fs::create_dir_all(arch_dir).map_err(|e| {
        BuilderVmError::ExtractionFailed(format!("create {}: {e}", arch_dir.display()))
    })?;

    for name in crate::cache_install::BUILDER_VM_CACHE_ARTIFACTS {
        let src = source_arch_dir.join(name);
        let dst = arch_dir.join(name);
        std::fs::copy(&src, &dst).map_err(|e| {
            BuilderVmError::ExtractionFailed(format!(
                "seed builder image cache {} -> {}: {e}",
                src.display(),
                dst.display(),
            ))
        })?;
    }
    // Sidecars are best-effort: a source lacking them still yields a bootable
    // image, and failing the seed over an absent provenance file would be
    // worse than seeding without it.
    for name in crate::cache_install::BUILDER_VM_CACHE_SIDECARS {
        let src = source_arch_dir.join(name);
        if src.is_file() {
            let _ = std::fs::copy(&src, arch_dir.join(name));
        }
    }
    Ok(())
}

fn auto_bootstrap_builder_vm_image(arch_dir: &Path) -> Result<bool, BuilderVmError> {
    if std::env::var_os(BUILDER_VM_AUTO_BOOTSTRAP_SKIP_ENV).is_some() {
        return Ok(false);
    }

    // This process *is* a bootstrap. Reporting the cold cache is the whole
    // signal; spawning a third one would only lose it.
    if std::env::var_os(BUILDER_VM_BOOTSTRAP_ACTIVE_ENV).is_some() {
        return Ok(false);
    }

    #[cfg(test)]
    if std::env::var_os(BUILDER_VM_BOOTSTRAP_BIN_ENV).is_none() {
        return Ok(false);
    }

    let Some(workspace_root) = builder_vm_source_checkout_root() else {
        return Ok(false);
    };

    let bootstrap_bin = resolve_builder_vm_bootstrap_bin(&workspace_root)?;
    let mut cmd = Command::new(&bootstrap_bin);
    cmd.current_dir(&workspace_root)
        .arg("__builder-vm-bootstrap")
        .env(BUILDER_VM_BOOTSTRAP_ACTIVE_ENV, "1");
    #[cfg(target_os = "linux")]
    if std::env::var_os(crate::builder_backend_select::MVM_BUILDER_BACKEND_ENV).is_none() {
        // Source-checkout auto-bootstrap on Linux should follow the Linux
        // builder path, not the libkrun-default host path. The runtime-overlay
        // source-build flow already uses QEMU shell jobs on Linux; keep Stage 0
        // aligned so a cold builder-image cache does not fall into a libkrun
        // networking prerequisite that the Linux builder path itself does not
        // require.
        cmd.env(
            crate::builder_backend_select::MVM_BUILDER_BACKEND_ENV,
            "qemu",
        );
    }
    let status = cmd.status().map_err(|e| {
        BuilderVmError::ExtractionFailed(format!(
            "spawn builder VM bootstrap helper {}: {e}",
            bootstrap_bin.display()
        ))
    })?;
    if !status.success() {
        return Err(BuilderVmError::ExtractionFailed(format!(
            "builder VM bootstrap helper {} exited with {} while refreshing {}",
            bootstrap_bin.display(),
            status.code().unwrap_or(-1),
            arch_dir.display(),
        )));
    }
    Ok(true)
}

pub fn maybe_reexec_builder_vm_bootstrap_helper() -> Result<bool, BuilderVmError> {
    maybe_reexec_builder_vm_helper(BuilderVmHelperCommand::Bootstrap)
}

pub fn maybe_reexec_builder_vm_sdk_sidecar_helper(force: bool) -> Result<bool, BuilderVmError> {
    maybe_reexec_builder_vm_helper(BuilderVmHelperCommand::SdkSidecarBuild { force })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BuilderVmHelperCommand {
    Bootstrap,
    SdkSidecarBuild { force: bool },
}

impl BuilderVmHelperCommand {
    fn args(self) -> Vec<&'static str> {
        match self {
            Self::Bootstrap => vec!["__builder-vm-bootstrap"],
            Self::SdkSidecarBuild { force: false } => {
                vec!["build", "sdk-sidecar", "build"]
            }
            Self::SdkSidecarBuild { force: true } => {
                vec!["build", "sdk-sidecar", "build", "--force"]
            }
        }
    }
}

fn maybe_reexec_builder_vm_helper(command: BuilderVmHelperCommand) -> Result<bool, BuilderVmError> {
    let Some(workspace_root) = builder_vm_source_checkout_root() else {
        return Ok(false);
    };

    let bootstrap_bin = resolve_builder_vm_bootstrap_bin(&workspace_root)?;
    if current_exe_matches(&bootstrap_bin) {
        return Ok(false);
    }

    let mut cmd = Command::new(&bootstrap_bin);
    cmd.current_dir(&workspace_root).args(command.args());
    if command == BuilderVmHelperCommand::Bootstrap {
        cmd.env(BUILDER_VM_BOOTSTRAP_ACTIVE_ENV, "1");
    }
    #[cfg(target_os = "linux")]
    if std::env::var_os(crate::builder_backend_select::MVM_BUILDER_BACKEND_ENV).is_none() {
        cmd.env(
            crate::builder_backend_select::MVM_BUILDER_BACKEND_ENV,
            "qemu",
        );
    }
    let status = cmd.status().map_err(|e| {
        BuilderVmError::ExtractionFailed(format!(
            "spawn embedded builder VM helper {}: {e}",
            bootstrap_bin.display()
        ))
    })?;
    if !status.success() {
        return Err(BuilderVmError::ExtractionFailed(format!(
            "embedded builder VM helper {} exited with {}",
            bootstrap_bin.display(),
            status.code().unwrap_or(-1),
        )));
    }
    Ok(true)
}

fn current_exe_matches(path: &Path) -> bool {
    let Ok(current_exe) = std::env::current_exe() else {
        return false;
    };
    let current = current_exe.canonicalize().unwrap_or(current_exe);
    let expected = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    current == expected
}

fn resolve_builder_vm_bootstrap_bin(workspace_root: &Path) -> Result<PathBuf, BuilderVmError> {
    if let Some(path) = std::env::var_os(BUILDER_VM_BOOTSTRAP_BIN_ENV).map(PathBuf::from) {
        if path.is_file() {
            return Ok(path);
        }
        return Err(BuilderVmError::ExtractionFailed(format!(
            "{} points at {} which is not a file",
            BUILDER_VM_BOOTSTRAP_BIN_ENV,
            path.display(),
        )));
    }

    if let Some(current_exe) = current_exe_as_bootstrap_helper() {
        return Ok(current_exe);
    }

    let helper_target_dir = builder_vm_bootstrap_helper_target_dir(workspace_root);
    let helper_bin = helper_target_dir.join("debug").join("mvmctl");
    if helper_bin.is_file() && !bootstrap_helper_needs_rebuild(&helper_bin, workspace_root) {
        return Ok(helper_bin);
    }
    // The helper is built `--features embed-host-bins`, which cross-compiles
    // the host binaries with the pinned zig + musl Rust. Ask for that toolchain
    // before spending minutes on a compile whose build script would only panic
    // about it at the very end.
    if let Err(reason) = embed_toolchain_ready(workspace_root) {
        return Err(BuilderVmError::ExtractionFailed(
            bootstrap_helper_toolchain_refusal(&reason),
        ));
    }
    std::fs::create_dir_all(&helper_target_dir).map_err(|e| {
        BuilderVmError::ExtractionFailed(format!(
            "create builder VM bootstrap helper target dir {}: {e}",
            helper_target_dir.display()
        ))
    })?;

    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let mut cmd =
        builder_vm_bootstrap_helper_build_command(&cargo, workspace_root, &helper_target_dir);
    let status = cmd.status().map_err(|e| {
        BuilderVmError::ExtractionFailed(format!(
            "spawn cargo to build mvmctl bootstrap helper: {e}"
        ))
    })?;
    if !status.success() {
        return Err(BuilderVmError::ExtractionFailed(format!(
            "cargo build --bin mvmctl --features embed-host-bins exited with {} while \
             preparing the builder VM bootstrap helper. {}",
            status.code().unwrap_or(-1),
            BOOTSTRAP_HELPER_WAYS_OUT,
        )));
    }

    if helper_bin.is_file() {
        return Ok(helper_bin);
    }

    Err(BuilderVmError::ExtractionFailed(format!(
        "mvmctl bootstrap helper not found after build at {}",
        helper_bin.display()
    )))
}

/// The two supported ways past a helper this host cannot build.
///
/// `just embed` is the better one: it gives *this* binary the payload, after
/// which the helper is not needed at all. The env var is the escape hatch for
/// a helper someone else built.
const BOOTSTRAP_HELPER_WAYS_OUT: &str = "Either run `just embed` so this mvmctl \
     carries the embedded Linux host binaries itself (no helper needed), or set \
     MVM_BUILDER_VM_BOOTSTRAP_BIN to an mvmctl that already carries them.";

/// Whether this host can cross-compile the embedded Linux host binaries.
///
/// Runs the same two resolutions `mvm-cli`'s build script does and nothing
/// else — it compiles no code. Asking first turns "wait five minutes, then read
/// a build-script panic" into an immediate, actionable refusal.
fn embed_toolchain_ready(workspace_root: &Path) -> Result<(), String> {
    use crate::embed_toolchain;

    let pin = embed_toolchain::try_read_pinned_toolchain(workspace_root, std::env::consts::ARCH)?;
    embed_toolchain::resolve_pinned_zig(&pin.zig)?;
    embed_toolchain::try_rustup_cargo_and_rustc(
        embed_toolchain::strip_glibc(&pin.target),
        &pin.rust,
    )?;
    Ok(())
}

fn bootstrap_helper_toolchain_refusal(reason: &str) -> String {
    format!(
        "this mvmctl carries no embedded Linux host binaries, and the pinned \
         cross-compile toolchain needed to build a bootstrap helper that does is \
         unavailable: {reason} Install it with `just toolchain-embed`. {}",
        BOOTSTRAP_HELPER_WAYS_OUT,
    )
}

fn builder_vm_bootstrap_helper_build_command(
    cargo: &std::ffi::OsStr,
    workspace_root: &Path,
    helper_target_dir: &Path,
) -> Command {
    let mut cmd = Command::new(cargo);
    cmd.current_dir(workspace_root)
        .env("CARGO_TARGET_DIR", helper_target_dir)
        .args([
            "build",
            "-q",
            "--bin",
            "mvmctl",
            "--features",
            "embed-host-bins",
        ]);
    cmd
}

fn bootstrap_helper_needs_rebuild(helper_bin: &Path, workspace_root: &Path) -> bool {
    let Ok(helper_metadata) = fs::metadata(helper_bin) else {
        return true;
    };
    let Ok(helper_modified) = helper_metadata.modified() else {
        return true;
    };

    bootstrap_helper_inputs(workspace_root)
        .into_iter()
        .any(|path| {
            newest_path_mtime(&path)
                .map(|mtime| mtime > helper_modified)
                .unwrap_or(true)
        })
}

fn bootstrap_helper_inputs(workspace_root: &Path) -> Vec<PathBuf> {
    [
        workspace_root.join("Cargo.toml"),
        workspace_root.join("Cargo.lock"),
        workspace_root.join("crates/mvm-build/Cargo.toml"),
        workspace_root.join("crates/mvm-cli/Cargo.toml"),
        workspace_root.join("crates/mvm-build/src"),
        workspace_root.join("crates/mvm-cli/src"),
    ]
    .into_iter()
    .collect()
}

fn newest_path_mtime(path: &Path) -> io::Result<std::time::SystemTime> {
    let metadata = fs::metadata(path)?;
    if metadata.is_file() {
        return metadata.modified();
    }
    if !metadata.is_dir() {
        return Err(io::Error::other(format!(
            "{} is neither a file nor a directory",
            path.display()
        )));
    }

    let mut newest = None;
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let child_mtime = newest_path_mtime(&entry.path())?;
        match newest {
            Some(current) if child_mtime <= current => {}
            _ => newest = Some(child_mtime),
        }
    }
    newest.or_else(|| metadata.modified().ok()).ok_or_else(|| {
        io::Error::other(format!(
            "failed to read modified time for {}",
            path.display()
        ))
    })
}

fn builder_vm_bootstrap_helper_target_dir(workspace_root: &Path) -> PathBuf {
    if let Some(target_dir) = std::env::var_os("CARGO_TARGET_DIR").filter(|dir| !dir.is_empty()) {
        let target_dir = PathBuf::from(target_dir);
        let base = if target_dir.is_absolute() {
            target_dir
        } else {
            workspace_root.join(target_dir)
        };
        return base.join("mvm-builder-vm-bootstrap");
    }

    workspace_root
        .join("target")
        .join("mvm-builder-vm-bootstrap")
}

fn validate_builder_vm_image_cache(arch_dir: &Path) -> Result<String, BuilderVmError> {
    let kernel_path = arch_dir.join("vmlinux");
    let rootfs_path = arch_dir.join("rootfs.ext4");
    let cmdline_path = arch_dir.join("cmdline.txt");
    let manifest_path = arch_dir.join("manifest.json");

    if !kernel_path.is_file() || !rootfs_path.is_file() {
        return Err(BuilderVmError::ExtractionFailed(format!(
            "builder VM image not found at {}. \
             Populate the cache by running `nix build ./nix/images/builder-vm#packages.{}-linux.default` \
             on a host with Nix and copying `result/{{vmlinux,rootfs.ext4,cmdline.txt}}` to {}/.",
            arch_dir.display(),
            host_arch_tag(),
            arch_dir.display(),
        )));
    }

    let cmdline = std::fs::read_to_string(&cmdline_path)
        .map_err(|e| {
            BuilderVmError::ExtractionFailed(format!(
                "{} missing or unreadable ({e}). The builder VM cache is poisoned; delete {} and re-run `mvmctl bootstrap` to re-bootstrap.",
                cmdline_path.display(),
                arch_dir.display(),
            ))
        })?
        .trim()
        .to_string();
    // Ride the host wall clock onto the base cmdline for every backend that boots
    // this image (libkrun + hvf are RTC-less): PID 1 seeds the guest clock from it
    // so a cold Nix store's HTTPS fetch doesn't fail cert validation. Fresh per
    // run, and preserved through the later per-boot token appends.
    let cmdline = append_cmdline_token(
        &cmdline,
        &crate::builder_vm::builder_hostepoch_cmdline_token(),
    );

    let manifest = read_builder_vm_cache_manifest(&manifest_path, arch_dir)?;
    if manifest.cache_contract_version != BUILDER_VM_CACHE_CONTRACT_VERSION
        || !manifest.runtime_overlay_ready
        || !manifest.vsock_egress_ready
    {
        return Err(BuilderVmError::ExtractionFailed(format!(
            "builder VM cache at {} is stale: manifest.json must declare `cache_contract_version={}`, `runtime_overlay_ready=true`, and `vsock_egress_ready=true`. Delete {} and re-run `mvmctl bootstrap` to re-bootstrap a current vsock-only builder image.",
            arch_dir.display(),
            BUILDER_VM_CACHE_CONTRACT_VERSION,
            arch_dir.display(),
        )));
    }

    Ok(cmdline)
}

fn load_builder_vm_image_from_cache(arch_dir: &Path) -> Result<BuilderVmImage, BuilderVmError> {
    let kernel_path = arch_dir.join("vmlinux");
    let rootfs_path = arch_dir.join("rootfs.ext4");
    let cmdline = validate_builder_vm_image_cache(arch_dir)?;

    Ok(BuilderVmImage::new(kernel_path, rootfs_path, cmdline))
}

/// Filename of Stage 0's dedicated persistent Nix-store image,
/// `nix-store-stage0-<arch>.img`. Distinct from the steady-state
/// builder's `nix-store-<arch>.img` so a builder VM bootstrap and a
/// concurrent `mvmctl build` never contend on the same flock — see
/// [`acquire_nix_store_image_lock_named`]. Lives in
/// [`builder_vm_cache_dir`] and matches `cache info`'s
/// `nix-store-*.img` sparse-footprint report.
pub(crate) fn stage0_nix_store_image_name() -> String {
    format!("nix-store-stage0-{}.img", host_arch_tag())
}

pub(crate) fn prepopulate_stage0_nix_store_image(
    image: &BuilderVmImage,
    store_image: &Path,
) -> Result<(), BuilderVmError> {
    let host_mkfs = find_host_mkfs_ext4();
    prepopulate_stage0_nix_store_image_with_mkfs(image, store_image, host_mkfs.as_deref())
}

fn prepopulate_stage0_nix_store_image_with_mkfs(
    image: &BuilderVmImage,
    store_image: &Path,
    host_mkfs: Option<&Path>,
) -> Result<(), BuilderVmError> {
    let BuilderVmImage::RootDir { root_dir, .. } = image else {
        return Ok(());
    };
    let seed_nix = root_dir.join("nix");
    let seed_store = seed_nix.join("store");
    if !seed_store.is_dir() {
        return Ok(());
    }

    let marker = stage0_nix_store_host_marker(&seed_store)?;
    let marker_path = stage0_nix_store_host_marker_path(store_image);
    if std::fs::read_to_string(&marker_path).is_ok_and(|existing| existing == marker)
        && stage0_store_superblock_is_recoverable(store_image)?
    {
        return Ok(());
    }

    // The marker binds the image to the seed closure, but it is deliberately
    // outside the filesystem and therefore cannot attest filesystem health.
    // Drop it before rebuilding so an interrupted format can never make a
    // damaged image look reusable on the next invocation.
    if marker_path.exists() {
        std::fs::remove_file(&marker_path).map_err(|e| {
            BuilderVmError::ExtractionFailed(format!("remove {}: {e}", marker_path.display()))
        })?;
    }

    let Some(mkfs) = host_mkfs else {
        // macOS has no host mkfs.ext4, and the minimal verified Stage 0 seed
        // intentionally does not carry e2fsprogs. Format a valid labeled ext4
        // image in-process when that capability is compiled in; otherwise
        // leave a blank device and let a richer Linux seed format it.
        format_stage0_store_without_host_mkfs(store_image)?;
        std::fs::write(&marker_path, marker).map_err(|e| {
            BuilderVmError::ExtractionFailed(format!("write {}: {e}", marker_path.display()))
        })?;
        return Ok(());
    };

    let blocks_4k = host_file_4k_blocks_for_ext4(store_image)?;
    tracing::info!(
        image = %store_image.display(),
        seed = %seed_nix.display(),
        blocks_4k,
        "prepopulating Stage 0 Nix store image with host mkfs.ext4"
    );
    let status = Command::new(mkfs)
        // `-L` so the guest can find this disk by label instead of by device
        // letter, which shifts whenever a backend attaches another drive.
        .args(["-F", "-q", "-b", "4096", "-L"])
        .arg(crate::rootfs::STAGE0_NIX_STORE_EXT4_LABEL)
        .args(["-d"])
        .arg(&seed_nix)
        .arg(store_image)
        .arg(blocks_4k.to_string())
        .status()
        .map_err(|e| BuilderVmError::ExtractionFailed(format!("spawn {}: {e}", mkfs.display())))?;
    if !status.success() {
        return Err(BuilderVmError::ExtractionFailed(format!(
            "{} -d {} -> {} exited {}",
            mkfs.display(),
            seed_nix.display(),
            store_image.display(),
            status.code().unwrap_or(-1)
        )));
    }
    std::fs::write(&marker_path, marker).map_err(|e| {
        BuilderVmError::ExtractionFailed(format!("write {}: {e}", marker_path.display()))
    })?;
    Ok(())
}

/// Reset a failed or seed-mismatched Stage 0 store to a blank sparse device.
/// The Linux Stage 0 guest formats it with e2fsprogs before copying the verified
/// seed closure. Truncating before restoring the device size discards every
/// block from a previously damaged filesystem without materializing 64 GiB of
/// zeros on the host.
#[cfg(not(feature = "pure-mkfs"))]
fn reset_stage0_store_for_guest_format(store_image: &Path) -> Result<(), BuilderVmError> {
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(store_image)
        .map_err(|e| {
            BuilderVmError::ExtractionFailed(format!("open {}: {e}", store_image.display()))
        })?;
    let device_size = file
        .metadata()
        .map_err(|e| {
            BuilderVmError::ExtractionFailed(format!("stat {}: {e}", store_image.display()))
        })?
        .len();
    file.set_len(0).map_err(|e| {
        BuilderVmError::ExtractionFailed(format!("truncate {}: {e}", store_image.display()))
    })?;
    file.set_len(device_size).map_err(|e| {
        BuilderVmError::ExtractionFailed(format!("resize {}: {e}", store_image.display()))
    })?;
    tracing::info!(
        image = %store_image.display(),
        device_size,
        "reset Stage 0 Nix store for in-guest e2fsprogs format"
    );
    Ok(())
}

#[cfg(feature = "pure-mkfs")]
fn format_stage0_store_without_host_mkfs(store_image: &Path) -> Result<(), BuilderVmError> {
    let blocks_4k = host_file_4k_blocks_for_ext4(store_image)?;
    let size_bytes = blocks_4k * mvm_fs::ext4::BLOCK_SIZE as u64;
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(store_image)
        .map_err(|e| {
            BuilderVmError::ExtractionFailed(format!("open {}: {e}", store_image.display()))
        })?;
    let device_size = file
        .metadata()
        .map_err(|e| {
            BuilderVmError::ExtractionFailed(format!("stat {}: {e}", store_image.display()))
        })?
        .len();
    file.set_len(0).map_err(|e| {
        BuilderVmError::ExtractionFailed(format!("truncate {}: {e}", store_image.display()))
    })?;
    file.set_len(device_size).map_err(|e| {
        BuilderVmError::ExtractionFailed(format!("resize {}: {e}", store_image.display()))
    })?;
    let summary = mvm_fs::ext4::mkfs::format_empty_ext4_labeled(
        &mut file,
        size_bytes,
        crate::rootfs::STAGE0_NIX_STORE_EXT4_LABEL.as_bytes(),
    )
    .map_err(|e| {
        BuilderVmError::ExtractionFailed(format!(
            "pure-Rust ext4 format of {}: {e}",
            store_image.display()
        ))
    })?;
    tracing::info!(
        image = %store_image.display(),
        free_blocks = summary.free_blocks,
        groups = summary.groups,
        "formatted Stage 0 Nix store image in-process"
    );
    Ok(())
}

#[cfg(not(feature = "pure-mkfs"))]
fn format_stage0_store_without_host_mkfs(store_image: &Path) -> Result<(), BuilderVmError> {
    reset_stage0_store_for_guest_format(store_image)
}

fn find_host_mkfs_ext4() -> Option<PathBuf> {
    [
        "/sbin/mkfs.ext4",
        "/usr/sbin/mkfs.ext4",
        "/bin/mkfs.ext4",
        "/usr/bin/mkfs.ext4",
    ]
    .into_iter()
    .map(PathBuf::from)
    .find(|p| p.is_file())
    .or_else(|| which::which("mkfs.ext4").ok())
}

fn host_file_4k_blocks_for_ext4(store_image: &Path) -> Result<u64, BuilderVmError> {
    let len = std::fs::metadata(store_image)
        .map_err(|e| {
            BuilderVmError::ExtractionFailed(format!("stat {}: {e}", store_image.display()))
        })?
        .len();
    let blocks = len / 4096;
    if blocks <= 16 {
        return Err(BuilderVmError::ExtractionFailed(format!(
            "Stage 0 store image {} is too small for ext4 prepopulation ({len} bytes)",
            store_image.display()
        )));
    }
    // Leave the same 64 KiB safety margin used by the in-guest formatter path;
    // it avoids libkrun virtio-blk geometry rounding at mount time.
    Ok(blocks - 16)
}

fn stage0_nix_store_host_marker_path(store_image: &Path) -> PathBuf {
    store_image.with_extension("stage0-seed")
}

fn invalidate_stage0_store_after_ext4_error(
    console_log: &Path,
    store_image: &Path,
) -> Result<(), BuilderVmError> {
    const EXT4_ERROR_REPORT: &str = "persistent Stage 0 ext4 store reported";
    let console = std::fs::read_to_string(console_log).unwrap_or_default();
    if !console.contains(EXT4_ERROR_REPORT) {
        return Ok(());
    }

    let marker_path = stage0_nix_store_host_marker_path(store_image);
    match std::fs::remove_file(&marker_path) {
        Ok(()) => {
            tracing::warn!(
                image = %store_image.display(),
                console = %console_log.display(),
                "invalidated Stage 0 Nix store after guest ext4 error report"
            );
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(BuilderVmError::ExtractionFailed(format!(
            "remove invalid Stage 0 store marker {}: {error}",
            marker_path.display()
        ))),
    }
}

const EXT4_SUPERBLOCK_MAGIC_OFFSET: u64 = 1024 + 0x38;
const EXT4_SUPERBLOCK_MAGIC: u16 = 0xEF53;
#[cfg(test)]
const EXT4_VALID_FS: u16 = 0x0001;
const EXT4_ERROR_FS: u16 = 0x0002;

/// The external seed marker remains reusable after an interrupted mount when
/// ext4 has a valid superblock and has not recorded filesystem errors. A dirty
/// journal is recoverable: the next guest mount replays it before Nix reads the
/// store. Only an invalid superblock or the explicit error bit forces a reset.
fn stage0_store_superblock_is_recoverable(store_image: &Path) -> Result<bool, BuilderVmError> {
    use std::io::{Read, Seek, SeekFrom};

    let mut file = std::fs::File::open(store_image).map_err(|e| {
        BuilderVmError::ExtractionFailed(format!("open {}: {e}", store_image.display()))
    })?;
    file.seek(SeekFrom::Start(EXT4_SUPERBLOCK_MAGIC_OFFSET))
        .map_err(|e| {
            BuilderVmError::ExtractionFailed(format!("seek {}: {e}", store_image.display()))
        })?;
    let mut fields = [0u8; 4];
    file.read_exact(&mut fields).map_err(|e| {
        BuilderVmError::ExtractionFailed(format!(
            "read ext4 state from {}: {e}",
            store_image.display()
        ))
    })?;
    let magic = u16::from_le_bytes([fields[0], fields[1]]);
    let state = u16::from_le_bytes([fields[2], fields[3]]);
    Ok(magic == EXT4_SUPERBLOCK_MAGIC && state & EXT4_ERROR_FS == 0)
}

fn stage0_nix_store_host_marker(seed_store: &Path) -> Result<String, BuilderVmError> {
    Ok(format!(
        "schema_version=2\nseed_store_entries_sha256={}\n",
        seed_store_entries_hash(seed_store)?
    ))
}

fn seed_store_entries_hash(seed_store: &Path) -> Result<String, BuilderVmError> {
    let mut entries = std::fs::read_dir(seed_store)
        .map_err(|e| {
            BuilderVmError::ExtractionFailed(format!("read {}: {e}", seed_store.display()))
        })?
        .map(|entry| {
            entry
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
                .map_err(|e| {
                    BuilderVmError::ExtractionFailed(format!(
                        "read entry under {}: {e}",
                        seed_store.display()
                    ))
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    entries.sort_unstable();

    let mut hasher = Sha256::new();
    for entry in entries {
        hasher.update(entry.as_bytes());
        hasher.update(b"\n");
    }
    Ok(hex::encode(hasher.finalize()))
}

/// Find the builder VM image (kernel + rootfs + cmdline) in
/// the host cache. The builder-vm flake's `packages.<system>.default`
/// produces exactly the `vmlinux` / `rootfs.ext4` / `cmdline.txt`
/// files this loads. The build-or-download step populates this
/// cache; today it errors when missing with an actionable hint.
pub fn ensure_builder_vm_image() -> Result<BuilderVmImage, BuilderVmError> {
    let arch_dir = builder_vm_cache_dir().join(host_arch_tag());
    match load_builder_vm_image_from_cache(&arch_dir) {
        Ok(image) => Ok(image),
        Err(initial_error) => {
            if seed_builder_vm_image_from_default_cache(&arch_dir)? {
                return load_builder_vm_image_from_cache(&arch_dir);
            }
            if !auto_bootstrap_builder_vm_image(&arch_dir)? {
                return Err(initial_error);
            }
            load_builder_vm_image_from_cache(&arch_dir)
        }
    }
}

/// Monotonic per-process job ID. Combines a UNIX timestamp
/// with the current PID so two concurrent invocations on one
/// host don't clobber each other's job dirs even if they hit
/// the same second.
///
/// `pub(crate)` so a parallel builder driver could reuse the same
/// per-job ID shape; backends share a cache root, so collisions on it
/// would corrupt each
/// other's job dirs.
pub(crate) fn unique_job_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let pid = std::process::id();
    format!("{now:013}-{pid}")
}

// `INSTALL_SPEC_FILENAME` moved to `crate::builder_vm_runtime`; the
// `use` at the top of this file pulls it back in for the existing
// callers.

// `stage_job_dir`, `stage_shell_job_dir`, `shell_single_quote_escape`, `read_job_result`,
// `JobResult`, `INSTALL_RESULT_FILENAME`, `read_last_bytes_of`,
// `finalize_flake_job`, `read_revision_hash`, `extract_nix_store_hash`,
// `finalize_install_job`, and `InstallResultReport` all live in
// `crate::builder_vm_runtime` so the future VzBuilderVm path can reuse
// them.

const LIBKRUN_SUPERVISOR_BIN: &str = "mvm-libkrun-supervisor";
const LIBKRUN_SUPERVISOR_PACKAGE: &str = "mvm-hostd";
const LIBKRUN_SUPERVISOR_INPUT_ROOTS: &[&str] = &[
    "Cargo.toml",
    "Cargo.lock",
    "crates/deps/libkrun-sys/Cargo.toml",
    "crates/deps/libkrun-sys/src",
    "crates/mvm-runtime/Cargo.toml",
    "crates/mvm-runtime/src",
    "crates/mvm-build/Cargo.toml",
    "crates/mvm-build/src",
    "crates/mvm-core/Cargo.toml",
    "crates/mvm-core/src",
    "crates/mvm-agentd/Cargo.toml",
    "crates/mvm-agentd/src",
    "crates/mvm-hostd/Cargo.toml",
    "crates/mvm-hostd/src",
];

/// File name for the captured rebuild log, written under `target_dir`
/// alongside the compiled binaries so it can't outlive the build it
/// describes.
const SUPERVISOR_BUILD_LOG_FILENAME: &str = "mvm-supervisor-build.log";

/// Locate the `mvm-libkrun-supervisor` binary. Mirrors the resolver in
/// `mvm-runtime::libkrun::resolve_supervisor_path` (kept local rather than
/// re-exported to keep the dep graph flat). Order: env override → next to
/// current_exe → current source checkout build → PATH.
/// Where [`resolve_supervisor_path`] found the supervisor binary. The source
/// matters because a PATH hit is an installed copy (`cargo install`) that a
/// source-checkout `cargo build` never refreshes — so it can silently lag the
/// driver and reintroduce stale-supervisor failures (orphan teardown
/// noise, `deny_unknown_fields` rejects of newer `SupervisorConfig` fields).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SupervisorSource {
    EnvOverride,
    NextToExe,
    LocalBuild,
    Path,
}

/// Pure precedence over the four already-probed candidates: explicit env
/// override > a binary next to the running exe (the version-matched local
/// build) > a fresh build in a sibling cargo profile dir > whatever is on
/// `$PATH`. Each arg is `Some` only when that candidate exists (and, for
/// `local_build`, only when the caller judged it fresher than `$PATH`). Returns
/// the chosen path and where it came from, or `None` when nothing resolved.
/// Split out from [`resolve_supervisor_path`] so the precedence — and the
/// "fell back to PATH" signal that drives the staleness warning — is unit
/// testable without touching the process environment.
fn choose_supervisor(
    env_override: Option<PathBuf>,
    next_to_exe: Option<PathBuf>,
    local_build: Option<PathBuf>,
    on_path: Option<PathBuf>,
) -> Option<(PathBuf, SupervisorSource)> {
    if let Some(p) = env_override {
        return Some((p, SupervisorSource::EnvOverride));
    }
    if let Some(p) = next_to_exe {
        return Some((p, SupervisorSource::NextToExe));
    }
    if let Some(p) = local_build {
        return Some((p, SupervisorSource::LocalBuild));
    }
    on_path.map(|p| (p, SupervisorSource::Path))
}

/// A freshly-built `mvm-libkrun-supervisor` in a sibling cargo profile dir —
/// e.g. running `target/release/mvmctl` while the supervisor was last built
/// into `target/debug/`. Source checkouts routinely split the driver and this
/// per-VM binary across profiles because the supervisor is a separate bin that
/// mvmctl's own build never refreshes; without this probe the resolver skips
/// the fresh local build and falls through to a stale `$PATH` copy.
///
/// Only activates for a cargo `target/<profile>/` layout — an installed mvmctl
/// (`~/.cargo/bin/mvmctl`, a release download) has no sibling profiles, so
/// `$PATH` stays the right source there. Returns the newest match by mtime.
fn sibling_profile_supervisor(exe_dir: &Path) -> Option<PathBuf> {
    let target_dir = exe_dir.parent()?;
    if target_dir.file_name()?.to_str()? != "target" {
        return None;
    }
    let mut candidates: Vec<(std::time::SystemTime, PathBuf)> = std::fs::read_dir(target_dir)
        .ok()?
        .flatten()
        .map(|entry| entry.path())
        .filter(|profile_dir| profile_dir.is_dir() && profile_dir != exe_dir)
        .map(|profile_dir| profile_dir.join(LIBKRUN_SUPERVISOR_BIN))
        .filter(|bin| bin.is_file())
        .filter_map(|bin| Some((std::fs::metadata(&bin).ok()?.modified().ok()?, bin)))
        .collect();
    candidates.sort_by_key(|(mtime, _)| *mtime);
    candidates.pop().map(|(_, bin)| bin)
}

/// Whether a sibling-profile `candidate` should win over the `$PATH` copy: no
/// `$PATH` copy, an unreadable mtime on either side (source-checkout intent —
/// prefer the fresh local build), or `candidate` at least as new. Guards against
/// a stale leftover build shadowing a freshly *installed* supervisor.
fn supervisor_build_outranks_path(candidate: &Path, on_path: Option<&Path>) -> bool {
    let Some(on_path) = on_path else {
        return true;
    };
    let mtime = |p: &Path| std::fs::metadata(p).and_then(|m| m.modified()).ok();
    match (mtime(candidate), mtime(on_path)) {
        (Some(cand), Some(path)) => cand >= path,
        _ => true,
    }
}

fn workspace_root_from_manifest_dir() -> Option<PathBuf> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir.parent()?.parent().map(Path::to_path_buf)
}

fn source_checkout_supervisor(exe_dir: Option<&Path>) -> Option<Result<PathBuf, BuilderVmError>> {
    let exe_dir = exe_dir?;
    let workspace_root = workspace_root_from_manifest_dir()?;
    if !workspace_root.join("Cargo.toml").is_file() {
        return None;
    }
    let (target_dir, profile) = source_checkout_exe_target_dir(exe_dir, &workspace_root)?;

    let candidate = target_dir.join(profile).join(LIBKRUN_SUPERVISOR_BIN);
    let input_roots = supervisor_input_roots(&workspace_root);
    match supervisor_needs_rebuild(&candidate, &input_roots) {
        Ok(false) => Some(Ok(candidate)),
        Ok(true) => Some(build_supervisor_in_workspace(
            &workspace_root,
            target_dir,
            profile,
        )),
        Err(e) => Some(Err(BuilderVmError::LibkrunUnavailable(format!(
            "checking {} freshness: {e}",
            candidate.display()
        )))),
    }
}

fn source_checkout_exe_target_dir<'a>(
    exe_dir: &'a Path,
    workspace_root: &Path,
) -> Option<(&'a Path, &'a str)> {
    source_checkout_exe_target_dir_with_effective(
        exe_dir,
        workspace_root,
        &effective_cargo_target_dir(workspace_root),
    )
}

fn source_checkout_exe_target_dir_with_effective<'a>(
    exe_dir: &'a Path,
    workspace_root: &Path,
    effective_target_dir: &Path,
) -> Option<(&'a Path, &'a str)> {
    let profile = exe_dir.file_name()?.to_str()?;
    let target_dir = exe_dir.parent()?;
    let default_target_dir = workspace_root.join("target");
    if target_dir == default_target_dir
        || target_dir == effective_target_dir
        || matches!(profile, "debug" | "release")
    {
        Some((target_dir, profile))
    } else {
        None
    }
}

fn effective_cargo_target_dir(workspace_root: &Path) -> PathBuf {
    cargo_target_dir_from_env(workspace_root, std::env::var_os("CARGO_TARGET_DIR"))
}

fn cargo_target_dir_from_env(workspace_root: &Path, target_dir: Option<OsString>) -> PathBuf {
    let Some(target_dir) = target_dir else {
        return workspace_root.join("target");
    };
    if target_dir.is_empty() {
        return workspace_root.join("target");
    }
    let target_dir = PathBuf::from(target_dir);
    if target_dir.is_absolute() {
        target_dir
    } else {
        workspace_root.join(target_dir)
    }
}

fn supervisor_input_roots(workspace_root: &Path) -> Vec<PathBuf> {
    LIBKRUN_SUPERVISOR_INPUT_ROOTS
        .iter()
        .map(|root| workspace_root.join(root))
        .collect()
}

fn supervisor_needs_rebuild(helper: &Path, input_roots: &[PathBuf]) -> std::io::Result<bool> {
    let Ok(helper_meta) = std::fs::metadata(helper) else {
        return Ok(true);
    };
    let helper_modified = helper_meta.modified()?;
    let newest_input = newest_modified_input(input_roots)?;
    Ok(newest_input.is_some_and(|modified| modified > helper_modified))
}

fn newest_modified_input(
    input_roots: &[PathBuf],
) -> std::io::Result<Option<std::time::SystemTime>> {
    let mut newest = None;
    for root in input_roots {
        newest = max_system_time(newest, newest_modified_under(root)?);
    }
    Ok(newest)
}

fn newest_modified_under(path: &Path) -> std::io::Result<Option<std::time::SystemTime>> {
    let Ok(meta) = std::fs::metadata(path) else {
        return Ok(None);
    };
    let mut newest = Some(meta.modified()?);
    if meta.is_dir() {
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            newest = max_system_time(newest, newest_modified_under(&entry.path())?);
        }
    }
    Ok(newest)
}

fn max_system_time(
    a: Option<std::time::SystemTime>,
    b: Option<std::time::SystemTime>,
) -> Option<std::time::SystemTime> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.max(b)),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    }
}

fn build_supervisor_in_workspace(
    workspace_root: &Path,
    target_dir: &Path,
    profile: &str,
) -> Result<PathBuf, BuilderVmError> {
    let log_path = target_dir.join(SUPERVISOR_BUILD_LOG_FILENAME);
    let verbose = verbose_from_env();
    if verbose {
        eprintln!(
            "[mvm] building {LIBKRUN_SUPERVISOR_BIN} for this source checkout so the supervisor matches mvmctl"
        );
    } else {
        eprintln!(
            "[mvm] building {LIBKRUN_SUPERVISOR_BIN} for this source checkout so the supervisor matches mvmctl — logs: {}",
            log_path.display()
        );
    }
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let mut cmd = Command::new(cargo);
    cmd.current_dir(workspace_root)
        .env("CARGO_TARGET_DIR", target_dir)
        .args([
            "build",
            "-p",
            LIBKRUN_SUPERVISOR_PACKAGE,
            "--bin",
            LIBKRUN_SUPERVISOR_BIN,
            "--features",
            "libkrun-sys",
        ]);
    match profile {
        "debug" => {}
        "release" => {
            cmd.arg("--release");
        }
        other => {
            cmd.args(["--profile", other]);
        }
    }
    run_logged(cmd, &log_path, verbose)?;
    let built = supervisor_path_in_target_dir(target_dir, profile);
    if built.is_file() {
        Ok(built)
    } else {
        Err(BuilderVmError::LibkrunUnavailable(format!(
            "cargo build completed but {} was not produced",
            built.display()
        )))
    }
}

/// Run `cmd` to completion, keeping its raw output out of the terminal
/// unless `verbose`. The host cargo rebuild this backs streams a
/// `Compiling …` / `Building [===]` wall of text that otherwise
/// interleaves with the CLI's own progress output — quiet mode redirects
/// both stdout and stderr to `log_path` instead, and a failing command
/// surfaces the log's tail inline so the operator isn't left guessing
/// which file to open. `verbose` opts back into live streaming, matching
/// the previous terminal-inheriting behavior.
fn run_logged(mut cmd: Command, log_path: &Path, verbose: bool) -> Result<(), BuilderVmError> {
    if verbose {
        cmd.stdout(Stdio::inherit()).stderr(Stdio::inherit());
    } else {
        if let Some(parent) = log_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                BuilderVmError::LibkrunUnavailable(format!(
                    "create log directory {}: {e}",
                    parent.display()
                ))
            })?;
        }
        let stdout_file = std::fs::File::create(log_path).map_err(|e| {
            BuilderVmError::LibkrunUnavailable(format!(
                "create log file {}: {e}",
                log_path.display()
            ))
        })?;
        let stderr_file = stdout_file.try_clone().map_err(|e| {
            BuilderVmError::LibkrunUnavailable(format!(
                "clone log file handle for {}: {e}",
                log_path.display()
            ))
        })?;
        cmd.stdout(Stdio::from(stdout_file))
            .stderr(Stdio::from(stderr_file));
    }

    let status = cmd
        .status()
        .map_err(|e| BuilderVmError::LibkrunUnavailable(format!("spawn {cmd:?}: {e}")))?;
    if status.success() {
        return Ok(());
    }
    if verbose {
        return Err(BuilderVmError::LibkrunUnavailable(format!(
            "{cmd:?} failed with status {status}"
        )));
    }
    let log_path_str = log_path.to_string_lossy();
    Err(BuilderVmError::LibkrunUnavailable(format!(
        "{cmd:?} failed with status {status}; full log at {log_path_str}\n{}",
        read_console_tail(&log_path_str, 20)
    )))
}

fn supervisor_path_in_target_dir(target_dir: &Path, profile: &str) -> PathBuf {
    target_dir.join(profile).join(LIBKRUN_SUPERVISOR_BIN)
}

fn supervisor_target_roots(workspace_root: &Path) -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if let Some(target_dir) = std::env::var_os("CARGO_TARGET_DIR").map(PathBuf::from) {
        roots.push(if target_dir.is_absolute() {
            target_dir
        } else {
            workspace_root.join(target_dir)
        });
    }
    roots.push(workspace_root.join("target"));
    if let Ok(exe) = std::env::current_exe()
        && let Some(exe_dir) = exe.parent()
        && let Some(target_dir) = exe_dir.parent()
        && target_dir.file_name().is_some_and(|name| name == "target")
    {
        roots.push(target_dir.to_path_buf());
    }
    let mut deduped = Vec::new();
    for root in roots {
        let normalized = root.canonicalize().unwrap_or(root);
        if !deduped.iter().any(|existing| existing == &normalized) {
            deduped.push(normalized);
        }
    }
    deduped
}

fn locate_supervisor_in_target_roots(target_roots: &[PathBuf]) -> Option<PathBuf> {
    let mut candidates: Vec<(std::time::SystemTime, PathBuf)> = Vec::new();
    for root in target_roots {
        for profile in ["debug", "release"] {
            let candidate = root.join(profile).join("mvm-libkrun-supervisor");
            if !candidate.is_file() {
                continue;
            }
            let mtime = std::fs::metadata(&candidate)
                .and_then(|metadata| metadata.modified())
                .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
            candidates.push((mtime, candidate));
        }
    }
    candidates.sort_by_key(|(mtime, _)| *mtime);
    candidates.pop().map(|(_, path)| path)
}

fn source_checkout_supervisor_build(on_path: Option<&Path>) -> Option<PathBuf> {
    let workspace_root = builder_vm_source_checkout_root()?;
    let target_roots = supervisor_target_roots(&workspace_root);
    locate_supervisor_in_target_roots(&target_roots)
        .filter(|candidate| supervisor_build_outranks_path(candidate, on_path))
}

fn auto_build_supervisor_from_source_checkout() -> Result<Option<PathBuf>, BuilderVmError> {
    let Some(workspace_root) = builder_vm_source_checkout_root() else {
        return Ok(None);
    };
    let target_roots = supervisor_target_roots(&workspace_root);
    if let Some(candidate) = locate_supervisor_in_target_roots(&target_roots) {
        return Ok(Some(candidate));
    }

    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let status = Command::new(cargo)
        .current_dir(&workspace_root)
        .args([
            "build",
            "-q",
            "-p",
            "mvm-hostd",
            "--bin",
            "mvm-libkrun-supervisor",
            "--features",
            "libkrun-sys",
        ])
        .status()
        .map_err(|e| {
            BuilderVmError::ExtractionFailed(format!(
                "spawn cargo to build mvm-libkrun-supervisor: {e}"
            ))
        })?;
    if !status.success() {
        return Err(BuilderVmError::ExtractionFailed(format!(
            "cargo build -p mvm-hostd --bin mvm-libkrun-supervisor --features libkrun-sys exited with {} while preparing the libkrun builder supervisor",
            status.code().unwrap_or(-1),
        )));
    }
    Ok(locate_supervisor_in_target_roots(&target_roots))
}

fn resolve_supervisor_path() -> Result<PathBuf, BuilderVmError> {
    // An explicit override that points at a non-file is a hard error, not a
    // silent fall-through to a different binary — surface the operator's typo.
    let env_override = match std::env::var_os("MVM_LIBKRUN_SUPERVISOR_PATH") {
        Some(p) => {
            let path = PathBuf::from(p);
            if !path.is_file() {
                return Err(BuilderVmError::LibkrunUnavailable(format!(
                    "MVM_LIBKRUN_SUPERVISOR_PATH points at {} which is not a file",
                    path.display()
                )));
            }
            Some(path)
        }
        None => None,
    };
    if let Some(path) = env_override {
        return Ok(path);
    }
    let exe = std::env::current_exe().ok();
    let exe_dir = exe.as_deref().and_then(Path::parent);
    let on_path = which::which(LIBKRUN_SUPERVISOR_BIN).ok();
    let source_checkout_build = match source_checkout_supervisor(exe_dir) {
        Some(Ok(path)) => Some(path),
        Some(Err(err)) => return Err(err),
        None => None,
    };
    let next_to_exe = exe_dir
        .map(|dir| dir.join(LIBKRUN_SUPERVISOR_BIN))
        .filter(|candidate| candidate.is_file());
    // A sibling-profile build (fresh local `cargo build`) closes the stale-PATH
    // trap — but only when it's at least as fresh as the `$PATH` copy, so a
    // stale leftover build can't shadow a freshly installed supervisor.
    let local_build = source_checkout_build.or_else(|| {
        exe_dir
            .and_then(sibling_profile_supervisor)
            .filter(|candidate| supervisor_build_outranks_path(candidate, on_path.as_deref()))
    });
    let local_build = local_build.or_else(|| source_checkout_supervisor_build(on_path.as_deref()));

    match choose_supervisor(None, next_to_exe, local_build, on_path) {
        Some((path, SupervisorSource::Path)) => {
            if let Some(path) = auto_build_supervisor_from_source_checkout()? {
                return Ok(path);
            }
            // The stale-install trap: a `cargo install`ed copy on $PATH is used
            // because no fresh binary sits next to the exe. Source checkouts
            // never rebuild it, so it drifts from the driver. Warn loudly with
            // the one-line fix rather than booting a mismatched supervisor.
            tracing::warn!(
                supervisor = %path.display(),
                "using mvm-libkrun-supervisor from $PATH — a source checkout's `cargo build` \
                 does not refresh this installed copy, so it can lag the driver and reintroduce \
                 stale-supervisor failures. Rebuild a fresh one next to the exe with \
                 `cargo build -p mvm-hostd --bin mvm-libkrun-supervisor --features libkrun-sys`."
            );
            Ok(path)
        }
        Some((path, _)) => Ok(path),
        None => {
            if let Some(path) = auto_build_supervisor_from_source_checkout()? {
                return Ok(path);
            }
            Err(BuilderVmError::LibkrunUnavailable(
                "mvm-libkrun-supervisor binary not found. \
                 Looked for: $MVM_LIBKRUN_SUPERVISOR_PATH, alongside the current exe, and on $PATH. \
                 Build it with `cargo build -p mvm-hostd --bin mvm-libkrun-supervisor --features libkrun-sys` \
                 or set MVM_LIBKRUN_SUPERVISOR_PATH=/abs/path/to/the/binary."
                    .to_string(),
            ))
        }
    }
}

/// Spawn `mvm-libkrun-supervisor`, pipe a `SupervisorConfig`
/// JSON document to its stdin, then **wait** for it to exit.
/// Returns the child's exit code (0 on clean guest power-off
/// per libkrun's `start_enter` semantics; non-zero if the
/// supervisor errored before or during the guest run).
///
/// Spawn the supervisor with the given `cfg` piped to its stdin,
/// return the live `Child` *without* waiting on it. Persistent-VM
/// callers
/// ([`LibkrunPersistentHostVm::start`]) consume the child via
/// [`PersistentVmHandle`]; the single-shot
/// [`spawn_supervisor_and_wait`] calls this then runs the wait
/// loop on top.
fn spawn_supervisor_in_background(
    supervisor_path: &Path,
    cfg: &SupervisorConfig,
    vm_state_dir: &Path,
) -> Result<std::process::Child, BuilderVmError> {
    let json = serde_json::to_string(cfg).map_err(|e| {
        BuilderVmError::ExtractionFailed(format!("serialize SupervisorConfig: {e}"))
    })?;
    persist_supervisor_config_dump(vm_state_dir, &json)?;
    let stdout_log_path = supervisor_stdout_log_path(vm_state_dir);
    let stderr_log_path = supervisor_stderr_log_path(vm_state_dir);
    let stdout_log = std::fs::File::create(&stdout_log_path).map_err(|e| {
        BuilderVmError::ExtractionFailed(format!(
            "creating supervisor stdout log {}: {e}",
            stdout_log_path.display()
        ))
    })?;
    let stderr_log = std::fs::File::create(&stderr_log_path).map_err(|e| {
        BuilderVmError::ExtractionFailed(format!(
            "creating supervisor stderr log {}: {e}",
            stderr_log_path.display()
        ))
    })?;

    let mut command = Command::new(supervisor_path);
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::from(stdout_log))
        .stderr(Stdio::from(stderr_log));
    // libkrun dlopens `libkrunfw.5.dylib` by short name when its
    // bundled-kernel path runs (e.g. `krun_set_root` mode without
    // an explicit `set_kernel`). macOS dyld's default search list
    // does not include /opt/homebrew/lib where Homebrew installs
    // libkrunfw, so the dlopen fails with "Couldn't find or load"
    // and the supervisor exits rc -2. Adding the Homebrew prefix
    // to DYLD_FALLBACK_LIBRARY_PATH unblocks the lookup without
    // overriding dyld's normal search order.
    #[cfg(target_os = "macos")]
    {
        let mut fallback = std::env::var("DYLD_FALLBACK_LIBRARY_PATH").unwrap_or_default();
        for path in ["/opt/homebrew/lib", "/usr/local/lib"] {
            if !fallback.split(':').any(|p| p == path) {
                if !fallback.is_empty() {
                    fallback.push(':');
                }
                fallback.push_str(path);
            }
        }
        command.env("DYLD_FALLBACK_LIBRARY_PATH", fallback);
    }
    let mut child = command.spawn().map_err(|e| {
        BuilderVmError::LibkrunUnavailable(format!("spawn {}: {e}", supervisor_path.display()))
    })?;
    child
        .stdin
        .take()
        .ok_or_else(|| {
            BuilderVmError::ExtractionFailed(
                "supervisor stdin was not piped (unreachable — Stdio::piped() requested)"
                    .to_string(),
            )
        })?
        .write_all(json.as_bytes())
        .map_err(|e| {
            BuilderVmError::ExtractionFailed(format!(
                "writing SupervisorConfig to supervisor stdin: {e}"
            ))
        })?;
    Ok(child)
}

fn wait_for_vsock_socket(
    child: &mut Child,
    vm_state_dir: &Path,
    port: u32,
    timeout: Duration,
    label: &str,
) -> Result<(), BuilderVmError> {
    let socket_path = mvm_core::config::vm_vsock_port_socket_at(vm_state_dir, port);
    wait_for_path(child, &socket_path, timeout, label)
}

fn wait_for_path(
    child: &mut Child,
    path: &Path,
    timeout: Duration,
    label: &str,
) -> Result<(), BuilderVmError> {
    let deadline = Instant::now() + timeout;
    while !path.exists() {
        if let Some(status) = child
            .try_wait()
            .map_err(|e| BuilderVmError::ExtractionFailed(format!("poll supervisor child: {e}")))?
        {
            return Err(BuilderVmError::NixBuildFailed(format!(
                "supervisor exited before {label} became ready at {} (status: {status})",
                path.display()
            )));
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            return Err(BuilderVmError::NixBuildFailed(format!(
                "supervisor did not make {label} ready at {} within {:?}; killed",
                path.display(),
                timeout
            )));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Ok(())
}

/// Distinct from `mvm-runtime::LibkrunBackend::start` which
/// only waits for the PID file to appear and then returns —
/// that consumer wants a long-lived background VM. The
/// builder VM is a one-shot; the caller can't make progress
/// until the build finishes.
fn spawn_supervisor_and_wait(
    supervisor_path: &Path,
    cfg: &SupervisorConfig,
    vm_state_dir: &Path,
    verbose: bool,
) -> Result<i32, BuilderVmError> {
    let mut child = spawn_supervisor_in_background(supervisor_path, cfg, vm_state_dir)?;

    let timeout = builder_vm_timeout()?;
    // Concurrent kernel-panic detector. The libkrun supervisor
    // blocks in `krun_start_enter` until the VM cleanly
    // exits; a kernel panic at PID 1 doesn't trigger a clean exit, so
    // a plain `child.wait()` would hang indefinitely. We tail the VM's
    // console log for the kernel's stable panic banner and kill the
    // supervisor on detection. When `console_output_path` is None
    // (callers that opted out of console capture), behavior is
    // unchanged — plain wait, plain exit code.
    let console_log = cfg.krun.console_output_path.as_deref().map(PathBuf::from);
    let outcome = wait_with_panic_detector_until(
        &mut child,
        console_log.as_deref(),
        DEFAULT_PANIC_POLL_INTERVAL,
        Some(timeout),
        verbose,
    );

    // The supervisor has now exited on every arm below — clean guest
    // poweroff (libkrun's internal `exit()`), or panic/timeout where we
    // SIGKILL'd it above. None of those run `GvproxyHandle::Drop` (no
    // unwind) or the supervisor's SIGTERM handler (SIGKILL is uncatchable,
    // exit() skips it), so the per-VM helper is left "waiting for clients"
    // and reparented to the init process. Reap it here: we (the spawning
    // host) have observed the supervisor exit, so this is the one place
    // teardown is guaranteed regardless of how libkrun terminated.
    //
    match outcome {
        Ok(WaitOutcome::Clean(code)) => Ok(code),
        Ok(WaitOutcome::KernelPanic {
            panic_line,
            console_log_path,
        }) => Err(BuilderVmError::SeedKernelPanic {
            panic_line,
            console_log_path,
        }),
        Ok(WaitOutcome::GuestHalted {
            halt_line,
            console_log_path,
        }) => Err(BuilderVmError::GuestHalted {
            halt_line,
            console_log_path,
        }),
        Ok(WaitOutcome::Timeout) => Err(BuilderVmError::NixBuildFailed(format!(
            "builder VM exceeded {} seconds wall-clock; killed. Console log at {}/console.log.",
            timeout.as_secs(),
            vm_state_dir.display(),
        ))),
        Err(e) => Err(BuilderVmError::ExtractionFailed(format!(
            "wait on supervisor child: {e}"
        ))),
    }
}

/// The follow-up a single-shot build path takes once
/// [`spawn_supervisor_and_wait`] returns. The authoritative build result is
/// written to the output disk, so both a clean power-off and the
/// poweroff-fallback halt defer to the caller's fail-closed finalize; only a
/// non-zero supervisor exit or a VMM-level failure short-circuits.
#[derive(Debug)]
enum PostWaitAction {
    /// Read the output disk and let the caller's fail-closed finalize decide
    /// success or failure. `halted` records whether the guest reached this via
    /// the poweroff-fallback halt (worth a diagnostic log) rather than a clean
    /// power-off.
    FinalizeFromDisk { halted: bool },
    /// The supervisor process itself exited non-zero — surface its exit code.
    FailSupervisorExit(i32),
    /// A VMM-level failure (kernel panic, timeout, spawn/wait error). There is
    /// no build result to read, so propagate it unchanged.
    Propagate(BuilderVmError),
}

/// Decide what a single-shot build path does with a `spawn_supervisor_and_wait`
/// outcome. Pure so the branch decision is unit-testable without spawning a VM.
/// A guest halt is deferred to the on-disk result exactly like a clean exit:
/// the rootfs-backed builder kernel has no power-off method, so the guest's
/// end-of-job power-off falls back to a halt that is not itself a build failure.
fn post_wait_action(outcome: Result<i32, BuilderVmError>) -> PostWaitAction {
    match outcome {
        Ok(0) => PostWaitAction::FinalizeFromDisk { halted: false },
        Ok(code) => PostWaitAction::FailSupervisorExit(code),
        Err(BuilderVmError::GuestHalted { .. }) => {
            PostWaitAction::FinalizeFromDisk { halted: true }
        }
        Err(other) => PostWaitAction::Propagate(other),
    }
}

/// Drain the two background observation threads started before the supervisor
/// (the guest-agent socket observer and the vsock response listener). Each
/// consumes its receiver, so this runs once per build on whichever exit path
/// the supervisor took. Passing `None` for the file exit code skips the
/// file/vsock cross-validation — callers holding an authoritative exit code
/// cross-validate at their own call site instead.
fn drain_builder_observations(
    guest_agent_rx: Option<std::sync::mpsc::Receiver<VsockSocketObservation>>,
    vsock_rx: std::sync::mpsc::Receiver<crate::builder_protocol::HostVmResponseRead>,
) {
    if let Some(rx) = guest_agent_rx {
        tracing::info!(
            summary = %describe_vsock_socket_observation(rx, mvm_agentd::vsock::GUEST_AGENT_PORT),
            "builder guest-agent socket observation"
        );
    }
    log_vsock_response_outcome(vsock_rx, None);
}

/// Spawn a background thread that reads the
/// `HostVmResponse::Result` frame `mvm-host-vm-init` sends over
/// AF_VSOCK port [`mvm_agentd::builder_agent::BUILDER_DISPATCH_PORT`]
/// right before reboot. Returns a `Receiver` the caller drains
/// after the supervisor exits via [`log_vsock_response_outcome`].
///
/// The thread starts BEFORE the supervisor so it can connect as
/// soon as libkrun creates `<vm_state_dir>/vsock-21471.sock` —
/// before the guest's listener exists, `UnixStream::connect` would
/// return `ENOENT`/`ECONNREFUSED`, hence the retry loop with a 60-second
/// outer deadline. Once connected, the thread reads with a 10-second
/// read deadline so an unresponsive guest doesn't leak the thread
/// indefinitely.
///
/// Older cached dev images won't send a response at all; the legacy
/// `<job_dir>/result` file path remains authoritative for the
/// build's exit code. This helper's job is purely
/// observational: log what arrives, warn on mismatch against the
/// file, never gate the build on the vsock outcome.
#[cfg(feature = "builder-vm")]
pub fn spawn_vsock_response_listener(
    vm_state_dir: &Path,
) -> std::sync::mpsc::Receiver<crate::builder_protocol::HostVmResponseRead> {
    use std::os::unix::net::UnixStream;
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    use crate::builder_protocol::{HostVmResponseRead, read_host_vm_response};

    let (tx, rx) = mpsc::channel();
    let socket_path = mvm_core::config::vm_vsock_port_socket_at(
        vm_state_dir,
        mvm_agentd::builder_agent::BUILDER_DISPATCH_PORT,
    );

    std::thread::Builder::new()
        .name("vsock-builder-response".to_string())
        .spawn(move || {
            let connect_deadline = Duration::from_secs(60);
            let poll_interval = Duration::from_millis(100);
            let read_timeout = Duration::from_secs(10);
            let start = Instant::now();
            let result = loop {
                if start.elapsed() > connect_deadline {
                    break HostVmResponseRead::Timeout;
                }
                match UnixStream::connect(&socket_path) {
                    Ok(mut stream) => {
                        let _ = stream.set_read_timeout(Some(read_timeout));
                        break read_host_vm_response(&mut stream);
                    }
                    Err(_) => std::thread::sleep(poll_interval),
                }
            };
            // The receiver may have been dropped already (caller hit
            // its recv_timeout before the thread finished). That's
            // fine — the response was observational anyway.
            let _ = tx.send(result);
        })
        .expect("std::thread::Builder::spawn never fails on unix");

    rx
}

#[cfg(feature = "builder-vm")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VsockSocketObservation {
    Seen,
    Timeout,
}

#[cfg(feature = "builder-vm")]
fn spawn_vsock_socket_observer(
    vm_state_dir: &Path,
    port: u32,
    timeout: Duration,
) -> std::sync::mpsc::Receiver<VsockSocketObservation> {
    use std::sync::mpsc;

    let (tx, rx) = mpsc::channel();
    let socket_path = mvm_core::config::vm_vsock_port_socket_at(vm_state_dir, port);
    std::thread::Builder::new()
        .name(format!("vsock-socket-observer-{port}"))
        .spawn(move || {
            let poll_interval = Duration::from_millis(100);
            let start = Instant::now();
            let result = loop {
                if socket_path.exists() {
                    break VsockSocketObservation::Seen;
                }
                if start.elapsed() > timeout {
                    break VsockSocketObservation::Timeout;
                }
                std::thread::sleep(poll_interval);
            };
            let _ = tx.send(result);
        })
        .expect("std::thread::Builder::spawn never fails on unix");

    rx
}

#[cfg(feature = "builder-vm")]
fn describe_vsock_socket_observation(
    rx: std::sync::mpsc::Receiver<VsockSocketObservation>,
    port: u32,
) -> String {
    match rx.recv_timeout(Duration::from_secs(5)) {
        Ok(VsockSocketObservation::Seen) => {
            format!("vsock socket {} became visible on the host", port)
        }
        Ok(VsockSocketObservation::Timeout) => {
            format!("vsock socket {} never became visible on the host", port)
        }
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            format!(
                "vsock socket {} observation thread did not report in time",
                port
            )
        }
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            format!("vsock socket {} observation thread disconnected", port)
        }
    }
}

/// Drain the listener from [`spawn_vsock_response_listener`] with a
/// bounded wait and log the outcome. If `file_exit_code` is `Some`,
/// cross-validate against the vsock-reported exit code and warn on
/// mismatch (but never propagate as an error — the file is the
/// authoritative source for now).
///
/// The 5-second `recv_timeout` past supervisor exit is enough for
/// the read-deadline-bounded thread to deliver any in-flight
/// response; longer waits would hurt UX without buying meaningful
/// signal.
#[cfg(feature = "builder-vm")]
pub fn log_vsock_response_outcome(
    rx: std::sync::mpsc::Receiver<crate::builder_protocol::HostVmResponseRead>,
    file_exit_code: Option<i32>,
) {
    let summary = describe_vsock_response_outcome(rx, file_exit_code);
    tracing::info!(summary = %summary, "vsock dispatch outcome");
}

#[cfg(feature = "builder-vm")]
pub fn describe_vsock_response_outcome(
    rx: std::sync::mpsc::Receiver<crate::builder_protocol::HostVmResponseRead>,
    file_exit_code: Option<i32>,
) -> String {
    use crate::builder_protocol::{HostVmResponse, HostVmResponseRead};

    match rx.recv_timeout(std::time::Duration::from_secs(5)) {
        Ok(HostVmResponseRead::Frame(HostVmResponse::Result {
            exit_code,
            job_timings,
            boot_timings,
            ..
        })) => match file_exit_code {
            Some(file_code) if file_code != exit_code => format!(
                "received HostVmResponse::Result via vsock dispatch channel \
                 (vsock_exit_code={exit_code}, file_exit_code={file_code}, \
                 build_ms={}, boot_timings_present={})",
                job_timings.build_ms,
                boot_timings.is_some()
            ),
            _ => format!(
                "received HostVmResponse::Result via vsock dispatch channel \
                 (vsock_exit_code={exit_code}, build_ms={}, boot_timings_present={})",
                job_timings.build_ms,
                boot_timings.is_some()
            ),
        },
        Ok(HostVmResponseRead::Frame(other)) => {
            format!("vsock dispatch: non-Result frame ignored in single-shot: {other:?}")
        }
        Ok(HostVmResponseRead::EmptyEof) => {
            "vsock dispatch: guest closed without sending (pre-W2-part-3 image, expected)"
                .to_string()
        }
        Ok(HostVmResponseRead::Timeout) => "vsock dispatch: receive thread timed out".to_string(),
        Err(_) => "vsock dispatch: no response within 5s of supervisor exit \
             (thread will self-terminate via read deadline)"
            .to_string(),
    }
}

/// Outcome of [`wait_with_panic_detector`]. `KernelPanic`
/// short-circuits the normal exit-code path with the captured banner
/// line so the caller can map it to [`BuilderVmError::SeedKernelPanic`]
/// without a separate side channel.
#[derive(Debug)]
enum WaitOutcome {
    Clean(i32),
    KernelPanic {
        panic_line: String,
        console_log_path: String,
    },
    /// The guest reached a halt without a clean power-off — emitted when a
    /// Stage 0 / builder build fails and the kernel can't power off (`reboot:
    /// Power off not available: System halted instead`). The supervisor's
    /// blocking `start_enter` never returns on a halt, so detecting this is what
    /// lets the host fail fast with the guest's error instead of waiting to the
    /// wall-clock timeout.
    GuestHalted {
        halt_line: String,
        console_log_path: String,
    },
    Timeout,
}

/// Terminal guest states the console watcher detects: either a kernel panic or
/// a halt (the latter is the failure mode a build error reaches when the guest
/// can't power off).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Terminal {
    Panic,
    Halt,
}

/// Poll interval for the panic-detector watcher in production. Keeping
/// this short (100 ms) is what makes a panic surface in well under a
/// second — the kernel's panic banner is written via printk well
/// before the supervisor's blocking `start_enter` would have otherwise
/// noticed anything wrong.
const DEFAULT_PANIC_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Block on `child` while concurrently tailing `console_log` (if any)
/// for the kernel's stable panic banner `Kernel panic - not syncing`.
/// On detection, kill the child and return [`WaitOutcome::KernelPanic`]
/// with the captured line. When `console_log` is `None`, falls back to
/// a plain `child.wait`.
///
/// `poll_interval` is the watcher's sleep between log-tail polls;
/// production calls pass [`DEFAULT_PANIC_POLL_INTERVAL`]. Tests pass a
/// shorter interval (e.g. 10 ms) to keep wall-clock under control.
///
/// The watcher runs on its own thread. The main thread loops
/// `Child::try_wait` so it can break out either on child exit or on
/// the watcher signaling a panic. When the watcher signals a panic,
/// the main thread calls `Child::kill` to unblock the libkrun
/// supervisor (libkrun's `krun_start_enter` runs on the supervisor's
/// main thread inside `exit()` — SIGKILL is the only reliable
/// signal, which matches the gotcha documented in
/// `reference_libkrun_gotchas.md`).
#[cfg(test)]
fn wait_with_panic_detector(
    child: &mut Child,
    console_log: Option<&Path>,
    poll_interval: Duration,
    verbose: bool,
) -> std::io::Result<WaitOutcome> {
    wait_with_panic_detector_until(child, console_log, poll_interval, None, verbose)
}

fn wait_with_panic_detector_until(
    child: &mut Child,
    console_log: Option<&Path>,
    poll_interval: Duration,
    timeout: Option<Duration>,
    verbose: bool,
) -> std::io::Result<WaitOutcome> {
    let deadline = timeout.map(|duration| Instant::now() + duration);

    let terminal: Arc<Mutex<Option<(Terminal, String)>>> = Arc::new(Mutex::new(None));
    let stop = Arc::new(AtomicBool::new(false));
    let watcher = console_log.map(|console_log| {
        let watcher_terminal = Arc::clone(&terminal);
        let watcher_stop = Arc::clone(&stop);
        let watcher_path = console_log.to_path_buf();
        std::thread::spawn(move || {
            panic_watcher(
                &watcher_path,
                &watcher_terminal,
                &watcher_stop,
                poll_interval,
                verbose,
            );
        })
    });

    let wait_result = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Ok(status),
            Ok(None) => {}
            Err(e) => break Err(e),
        }
        if terminal
            .lock()
            .expect("terminal detector state lock poisoned")
            .is_some()
        {
            // Best-effort kill; the supervisor is wedged inside
            // libkrun's `start_enter` so SIGKILL is the only reliable
            // signal. If the kill itself fails (already exited, etc.),
            // fall through to `wait` so we still reap the zombie.
            let _ = child.kill();
            match child.wait() {
                Ok(status) => break Ok(status),
                Err(e) => break Err(e),
            }
        }
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            let _ = child.kill();
            let _ = child.wait();
            stop.store(true, Ordering::SeqCst);
            if let Some(watcher) = watcher {
                let _ = watcher.join();
            }
            return Ok(WaitOutcome::Timeout);
        }
        let sleep = deadline
            .map(|deadline| deadline.saturating_duration_since(Instant::now()))
            .map(|remaining| remaining.min(poll_interval))
            .unwrap_or(poll_interval);
        std::thread::sleep(sleep);
    };

    // Signal the watcher to exit and join it. Even on `Err` paths we
    // need the join — without it the spawned thread could outlive the
    // function with a live `&Path` to a tempdir the caller is about
    // to drop.
    stop.store(true, Ordering::SeqCst);
    if let Some(watcher) = watcher {
        let _ = watcher.join();
    }

    let status = wait_result?;
    let captured = terminal
        .lock()
        .expect("terminal detector state lock poisoned")
        .take();
    match captured {
        Some((kind, line)) => {
            let console_log_path = console_log
                .expect("a terminal line can only be captured when console log exists")
                .display()
                .to_string();
            Ok(match kind {
                Terminal::Panic => WaitOutcome::KernelPanic {
                    panic_line: line,
                    console_log_path,
                },
                Terminal::Halt => WaitOutcome::GuestHalted {
                    halt_line: line,
                    console_log_path,
                },
            })
        }
        None => Ok(WaitOutcome::Clean(status.code().unwrap_or(-1))),
    }
}

/// The kernel's panic banner. Stable in upstream `kernel/panic.c` for
/// the last ~decade; substring match keeps us robust to colour codes,
/// log-level prefixes, and trailing detail.
const KERNEL_PANIC_BANNER: &str = "Kernel panic - not syncing";

/// Maximum bytes of unmatched tail we keep buffered between polls.
/// A panic line is short (~150 bytes) so 4 KiB is plenty of slack to
/// handle a partial last line spanning multiple reads.
const PANIC_WATCHER_BUFFER_CAP: usize = 4096;

/// Under `--verbose`, forward freshly-read console bytes to `sink`
/// (stderr in production). Extracted so the verbose-gating is unit
/// testable without capturing process stderr. Write errors are
/// silently dropped — the echo must never fail the build.
fn echo_console_chunk(sink: &mut impl Write, verbose: bool, chunk: &[u8]) {
    if verbose && !chunk.is_empty() {
        let _ = sink.write_all(chunk);
        let _ = sink.flush();
    }
}

/// Tail `console_log` for a terminal guest banner (kernel panic or halt). On
/// match, stores the `(kind, line)` into `terminal` and returns. Polls every
/// `poll_interval` until either a match is found or `stop` is set.
///
/// Two robustness details that matter:
///
/// 1. **The console log doesn't exist when we start.** libkrun creates
///    the file on the first hvc0 byte the guest writes, ~100 ms after
///    `start_enter`. The watcher retries the `File::open` on every
///    poll until it succeeds — `console_log.exists()` is the cheap
///    pre-check.
///
/// 2. **Reads can split a line across polls.** A panic banner that
///    arrives at the same instant as the poll could be partially read
///    on one tick and completed on the next. We buffer unmatched tail
///    bytes (capped at [`PANIC_WATCHER_BUFFER_CAP`]) so the substring
///    match across reads still succeeds.
fn panic_watcher(
    console_log: &Path,
    terminal: &Arc<Mutex<Option<(Terminal, String)>>>,
    stop: &Arc<AtomicBool>,
    poll_interval: Duration,
    verbose: bool,
) {
    let mut file: Option<std::fs::File> = None;
    let mut buf: Vec<u8> = Vec::new();

    while !stop.load(Ordering::SeqCst) {
        if file.is_none() && console_log.exists() {
            file = std::fs::File::open(console_log).ok();
        }
        if let Some(ref mut f) = file {
            let mut chunk = Vec::new();
            // Best-effort; an IO error here just defers detection to
            // the next poll. The supervisor's eventual exit still
            // unblocks the main thread.
            if f.read_to_end(&mut chunk).is_ok() && !chunk.is_empty() {
                echo_console_chunk(&mut std::io::stderr(), verbose, &chunk);
                buf.extend_from_slice(&chunk);
                if let Some(found) = find_terminal_line_in(&buf) {
                    *terminal.lock().unwrap() = Some(found);
                    return;
                }
                // Trim buf to the last PANIC_WATCHER_BUFFER_CAP bytes
                // so a multi-minute build's console output doesn't
                // grow the watcher's memory without bound. The banner
                // is much shorter than the cap so a truncated buffer
                // never severs a pending match.
                if buf.len() > PANIC_WATCHER_BUFFER_CAP {
                    let start = buf.len() - PANIC_WATCHER_BUFFER_CAP;
                    buf.drain(0..start);
                }
            }
        }
        std::thread::sleep(poll_interval);
    }
}

/// The kernel's halt banner. Emitted when the guest can't power off and halts
/// instead — the terminal state a Stage 0 / builder build failure reaches
/// (`reboot: Power off not available: System halted instead`). The supervisor's
/// blocking `start_enter` never returns on a halt, so detecting this is what
/// distinguishes "build failed, give up" from "still building."
const GUEST_HALT_BANNER: &str = "System halted";

/// Scan `buf` for a terminal guest banner — a kernel panic or a halt — and
/// return its kind plus the containing line (lossy UTF-8; kernel log output is
/// ASCII in practice but a stray non-UTF-8 byte must not silently drop
/// detection). Panic takes precedence: it's the more specific kernel state.
fn find_terminal_line_in(buf: &[u8]) -> Option<(Terminal, String)> {
    if let Some(idx) = find_subslice(buf, KERNEL_PANIC_BANNER.as_bytes()) {
        return Some((Terminal::Panic, extract_line(buf, idx)));
    }
    if let Some(idx) = find_subslice(buf, GUEST_HALT_BANNER.as_bytes()) {
        return Some((Terminal::Halt, extract_line(buf, idx)));
    }
    None
}

fn find_subslice(buf: &[u8], needle: &[u8]) -> Option<usize> {
    buf.windows(needle.len()).position(|w| w == needle)
}

/// Extract the full line containing byte index `idx`: walk back to the previous
/// newline (or start) and forward to the next (or end), so the banner's detail
/// is included (e.g. `Kernel panic - not syncing: Requested init ... (error N)`).
fn extract_line(buf: &[u8], idx: usize) -> String {
    let line_start = buf[..idx]
        .iter()
        .rposition(|&b| b == b'\n')
        .map(|i| i + 1)
        .unwrap_or(0);
    let line_end = buf[idx..]
        .iter()
        .position(|&b| b == b'\n')
        .map(|i| idx + i)
        .unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[line_start..line_end])
        .trim_end_matches('\r')
        .to_string()
}

/// Last `max_lines` non-empty lines of a console log, for surfacing the guest's
/// actual error in a halt failure (the build error sits just above the halt
/// banner). Best-effort: an unreadable/missing log yields an empty string.
fn read_console_tail(console_log_path: &str, max_lines: usize) -> String {
    let Ok(contents) = std::fs::read_to_string(console_log_path) else {
        return String::new();
    };
    let lines: Vec<&str> = contents.lines().filter(|l| !l.trim().is_empty()).collect();
    let start = lines.len().saturating_sub(max_lines);
    lines[start..].join("\n")
}

fn stage0_guest_halt_completed_successfully(console_log: &Path, artifact_out: &Path) -> bool {
    let outputs_present =
        artifact_out.join("vmlinux").is_file() || artifact_out.join("rootfs.ext4").is_file();
    if !outputs_present {
        return false;
    }
    std::fs::read_to_string(console_log)
        .map(|log| log.contains("stage0-init: done; halting"))
        .unwrap_or(false)
}

fn supervisor_stdout_log_path(vm_state_dir: &Path) -> PathBuf {
    vm_state_dir.join("supervisor.stdout.log")
}

fn supervisor_stderr_log_path(vm_state_dir: &Path) -> PathBuf {
    vm_state_dir.join("supervisor.stderr.log")
}

fn supervisor_config_dump_path(vm_state_dir: &Path) -> PathBuf {
    vm_state_dir.join("supervisor-config.json")
}

fn persist_supervisor_config_dump(vm_state_dir: &Path, json: &str) -> Result<(), BuilderVmError> {
    let config_path = supervisor_config_dump_path(vm_state_dir);
    let pretty = serde_json::from_str::<serde_json::Value>(json)
        .and_then(|value| serde_json::to_vec_pretty(&value))
        .unwrap_or_else(|_| json.as_bytes().to_vec());
    std::fs::write(&config_path, pretty).map_err(|e| {
        BuilderVmError::ExtractionFailed(format!(
            "writing supervisor config dump {}: {e}",
            config_path.display()
        ))
    })
}

/// What the Stage 0 guest's console says about how it terminated.
#[derive(Debug, PartialEq, Eq)]
enum Stage0HaltOutcome {
    /// `stage0-init` finished the build and copied artifacts to `/out`.
    CleanHalt,
    /// `nix build` (or a copy step) failed; the guest powered off anyway.
    BuildFailed,
    /// The guest refused before starting the build — no egress proxy, no
    /// clock, a share that would not mount. Carries the refusal, because it
    /// names a cause the nix output never will.
    SetupFailed(String),
    /// No terminal marker at all — a panic, kill, or truncated console.
    NoCleanHalt,
}

/// Decide Stage 0 success from the guest console, not the VMM exit code. A
/// libkrun supervisor that exits 0 only means the guest powered off — and
/// `stage0-init` powers off cleanly on build failure too (its own error is
/// printed, then `reboot`). Absent this check the caller would trip on a
/// downstream "rootfs.ext4 missing" error that hides the real nix failure.
/// `stage0-init` prints one stable terminal line, so match on it (the QEMU
/// Stage 0 path keys on the same markers).
fn stage0_console_halt_outcome(log: &str) -> Stage0HaltOutcome {
    // Setup refusals are checked first and win over everything else: the
    // guest stops before `nix build` runs, so any later marker would be
    // describing a build that never started.
    if let Some(why) = log
        .lines()
        .find_map(|line| line.trim().strip_prefix("stage0-init: FATAL: "))
    {
        return Stage0HaltOutcome::SetupFailed(why.trim().to_string());
    }
    if log.contains("stage0-init: build failed") {
        Stage0HaltOutcome::BuildFailed
    } else if log.contains("stage0-init: done; halting") {
        Stage0HaltOutcome::CleanHalt
    } else {
        Stage0HaltOutcome::NoCleanHalt
    }
}

/// Turn a Stage 0 console's terminal state into the caller's result,
/// naming the console log path in both failure messages so an operator
/// always knows where to look instead of hitting a downstream error that
/// hides the real cause. Split out of the supervisor-wait call site so
/// this message construction is unit-testable without spawning a VM.
fn stage0_run_result(console: &str, console_log_path: &str) -> Result<(), BuilderVmError> {
    match stage0_console_halt_outcome(console) {
        Stage0HaltOutcome::CleanHalt => Ok(()),
        Stage0HaltOutcome::BuildFailed => Err(BuilderVmError::NixBuildFailed(format!(
            "nix build failed inside the Stage 0 guest; console log at {console_log_path}\n{}",
            read_console_tail(console_log_path, 20)
        ))),
        Stage0HaltOutcome::SetupFailed(why) => Err(BuilderVmError::NixBuildFailed(format!(
            "Stage 0 guest refused to start the build: {why}; console log at {console_log_path}"
        ))),
        Stage0HaltOutcome::NoCleanHalt => Err(BuilderVmError::ExtractionFailed(format!(
            "Stage 0 guest did not reach a clean halt; console log at {console_log_path}\n{}",
            read_console_tail(console_log_path, 20)
        ))),
    }
}

/// Render a Path as a `&str` or surface a clear error if it
/// contains non-UTF-8 bytes. libkrun's C API takes
/// `*const c_char`; rejecting non-UTF-8 here pins the failure
/// to the offending field rather than a CString conversion
/// deep inside the FFI.
fn path_to_str<'a>(p: &'a Path, field: &str) -> Result<&'a str, BuilderVmError> {
    p.to_str().ok_or_else(|| {
        BuilderVmError::ExtractionFailed(format!("{field} has non-UTF-8 bytes: {p:?}"))
    })
}

// ============================================================
// LibkrunPersistentHostVm
// ============================================================

/// The dispatch markers and readiness window are the guest contract, shared
/// with every backend that can host a session; they live in
/// [`crate::builder_vm_runtime`]. Re-exported here because
/// `mvmctl persistent-builder` already names this path.
pub use crate::builder_vm_runtime::{
    DISPATCH_READY_MARKER, DISPATCH_SOCK_MARKER, PERSISTENT_BUILDER_READY_TIMEOUT,
};

/// Spawn the long-lived builder VM that `mvm-host-vm-init`'s
/// dispatch loop runs inside.
///
/// Mirrors the config surface of [`LibkrunBuilderVm`] but
/// produces a different shape of dispatch: instead of running a
/// single cmd.sh / install_spec and powering off, the guest
/// detects `<job_dir>/<DISPATCH_SOCK_MARKER>` and enters the
/// dispatch loop that reads `HostVmRequest` frames over
/// AF_VSOCK port [`mvm_agentd::builder_agent::BUILDER_DISPATCH_PORT`].
///
/// The caller pairs this with a `PersistentBuilderSupervisor`
/// constructed against [`PersistentVmHandle::dispatch_socket_path`].
///
/// ## Not yet wired
///
/// - The builder VM bootstrap integration is what actually constructs one of
///   these against the dev session's lifecycle.
/// - Per-job namespace isolation inside the dispatch loop.
#[cfg(feature = "builder-vm")]
#[derive(Debug, Clone)]
pub struct LibkrunPersistentHostVm {
    vcpus: u8,
    memory_mib: u32,
    nix_store_mib: u32,
    image_override: Option<BuilderVmImage>,
    /// Host directory bound at `/work` in the guest. Bound at VM
    /// start, not per-dispatch.
    workspace_root: PathBuf,
    /// Extracted host binaries bound at `/mvm-bins` so a builder-image
    /// rebuild can bake the current init and resident daemons into its
    /// rootfs.
    host_bin_dir: Option<PathBuf>,
}

#[cfg(feature = "builder-vm")]
impl LibkrunPersistentHostVm {
    /// Construct a persistent builder VM rooted at `workspace_root`.
    /// Defaults match [`LibkrunBuilderVm::default`] for vCPUs / RAM /
    /// nix-store image size.
    pub fn new(workspace_root: impl Into<PathBuf>) -> Self {
        Self {
            vcpus: DEFAULT_VCPUS,
            memory_mib: DEFAULT_MEMORY_MIB,
            nix_store_mib: DEFAULT_NIX_STORE_MIB,
            image_override: None,
            workspace_root: workspace_root.into(),
            host_bin_dir: None,
        }
    }

    pub fn with_vcpus(mut self, vcpus: u8) -> Self {
        self.vcpus = vcpus;
        self
    }

    pub fn with_memory_mib(mut self, memory_mib: u32) -> Self {
        self.memory_mib = memory_mib;
        self
    }

    pub fn with_nix_store_mib(mut self, nix_store_mib: u32) -> Self {
        self.nix_store_mib = nix_store_mib;
        self
    }

    pub fn with_image_override(mut self, image: BuilderVmImage) -> Self {
        self.image_override = Some(image);
        self
    }

    /// Bind the extracted host-vm binaries at `/mvm-bins`.
    pub fn with_host_bin_dir(mut self, host_bin_dir: impl Into<PathBuf>) -> Self {
        self.host_bin_dir = Some(host_bin_dir.into());
        self
    }

    pub fn workspace_root(&self) -> &Path {
        &self.workspace_root
    }

    /// Spawn the supervisor + libkrun VM in the background and
    /// return a handle whose `dispatch_socket_path` the supervisor
    /// connects to. The returned `Child` is alive
    /// until either the guest dispatch loop processes a
    /// `HostVmRequest::Shutdown` (clean exit) or the caller
    /// invokes [`PersistentVmHandle::kill`].
    pub fn start(&self) -> Result<PersistentVmHandle, BuilderVmError> {
        if !libkrun_sys::is_available() {
            return Err(BuilderVmError::LibkrunUnavailable(format!(
                "libkrun shared library not found on host. {}",
                libkrun_sys::install_hint()
            )));
        }

        if !self.workspace_root.is_dir() {
            return Err(BuilderVmError::ExtractionFailed(format!(
                "workspace_root {} is not a directory",
                self.workspace_root.display()
            )));
        }

        let supervisor_path = resolve_supervisor_path()?;
        let image = match &self.image_override {
            Some(image) => image.clone(),
            None => ensure_builder_vm_image()?,
        };
        // Materialize the store image but do NOT lock it here. The supervisor
        // takes the lock (`exclusive_image_lock` below) and holds it for its
        // whole life, which is the VM's life. Locking here instead would tie
        // the flock to this process, and the caller that starts a session
        // exits immediately afterwards — releasing the lock out from under a
        // VM that is still writing the image.
        let nix_store = ensure_nix_store_image_unlocked(
            &builder_vm_cache_dir(),
            host_arch_tag(),
            u64::from(self.nix_store_mib),
        )?;

        let session_id = unique_job_id();
        let job_dir = builder_vm_cache_dir().join("jobs").join(&session_id);
        stage_persistent_job_dir(&job_dir)?;

        let vm_name = mvm_core::naming::persistent_builder_vm_name(
            mvm_core::naming::BuilderVmSlot::Libkrun,
            &session_id,
        );
        let vm_state_dir = builder_vm_cache_dir().join("vms").join(&vm_name);
        std::fs::create_dir_all(&vm_state_dir).map_err(|e| {
            BuilderVmError::ExtractionFailed(format!(
                "creating persistent builder VM state dir {}: {e}",
                vm_state_dir.display()
            ))
        })?;
        let console_log = vm_state_dir.join("console.log");
        let socket_dir = builder_vsock_socket_dir(&vm_state_dir)?;
        let runtime_overlay = builder_runtime_overlay_or_bail(&image)?;
        let guest_agent_vsock =
            builder_runtime_overlay_guest_agent_enabled(&image, runtime_overlay.as_deref());
        let host_bin_dir = self.host_bin_dir.as_ref().ok_or_else(|| {
            BuilderVmError::ExtractionFailed(
                "persistent builder requires an extracted host binary directory".into(),
            )
        })?;
        if !host_bin_dir.is_dir() {
            return Err(BuilderVmError::ExtractionFailed(format!(
                "persistent builder host binary directory does not exist: {}",
                host_bin_dir.display()
            )));
        }

        let mut krun = krun_context_for_image(&vm_name, &image)?
            .with_resources(self.vcpus, self.memory_mib)
            .with_console_output(path_to_str(&console_log, "console_log")?)
            .with_vsock_socket_dir(path_to_str(&socket_dir, "vm_socket_dir")?)
            .add_disk(
                "nix-store",
                path_to_str(nix_store.path(), "nix_store_img")?,
                false,
            )
            // Left on virtio-fs deliberately, unlike Stage 0's `/work`
            // (`pack_stage0_work_disk`): this is the long-lived persistent
            // VM, so `/work` has to keep reflecting live host edits across
            // the session — a packed ext4 snapshot would need repacking on
            // every change. Revisit if a large workspace ever hits the same
            // virtio-fs handle exhaustion here.
            .add_virtio_fs("work", path_to_str(&self.workspace_root, "workspace_root")?)
            .add_virtio_fs("out", path_to_str(&job_dir, "job_dir")?)
            .add_virtio_fs("job", path_to_str(&job_dir, "job_dir")?)
            .add_virtio_fs("mvm-bins", path_to_str(host_bin_dir, "host_bin_dir")?)
            .add_vsock_port(mvm_agentd::builder_agent::BUILDER_DISPATCH_PORT)
            // The workload-vsock nesting hop. The in-host-VM forwarder
            // listens here; the outer host reaches a workload's
            // Firecracker vsock via `<vm_state_dir>/vsock-21472.sock`.
            // libkrun registers vsock ports at launch, so this must be
            // added up front even though workloads start later.
            .add_vsock_port(mvm_agentd::builder_agent::WORKLOAD_FORWARD_PORT)
            // The resident builder control daemon's typed control plane
            // mvm-host-vm-init launches `mvm-builderd` at boot;
            // the host reaches it via `<vm_state_dir>/vsock-21473.sock`.
            .add_vsock_port(mvm_agentd::builder_agent::BUILDERD_CONTROL_PORT);
        if guest_agent_vsock {
            krun = krun.add_vsock_port(mvm_agentd::vsock::GUEST_AGENT_PORT);
        }
        if let Some(attachment) =
            builder_virtiofs_runtime_overlay_attachment(&image, runtime_overlay.as_deref())
        {
            krun = krun.with_cmdline(attachment.cmdline).add_disk(
                "runtime-overlay",
                path_to_str(attachment.disk_path, "runtime_overlay_ext4")?,
                attachment.read_only,
            );
        }

        // A lean Rootfs builder always carries the runtime overlay here
        // (resolution failed closed above), so its cmdline is set by
        // `builder_runtime_overlay_attachment` — there is no overlay-absent
        // degraded boot.
        let egress_endpoint = if builder_uses_vsock_egress(&image) {
            let (identity_material, identity_drive) =
                stage_builder_flowmux_identity(&vm_state_dir)?;
            krun = krun
                .with_vsock_direct()
                .add_host_listen_port(mvm_agentd::vsock::EGRESS_PORT)
                .add_disk(
                    "mvm-identity",
                    path_to_str(&identity_drive, "identity_drive")?,
                    true,
                );
            BuilderVsockEgressEndpoint::spawn(&vm_state_dir, identity_material.spawn_config())
                .map(Some)?
        } else {
            krun = krun.with_vsock_direct();
            None
        };

        let cfg = SupervisorConfig {
            krun,
            vm_state_dir: path_to_str(&vm_state_dir, "vm_state_dir")?.to_string(),
            pid_file_name: Some("builder.pid".to_string()),
            tenant_id: None,
            audit_dir: None,
            gateway_audit_socket: None,
            gateway_events_socket: None,
            signing_key_path: None,
            plan: None,
            bundle: None,
            // Builder VMs take the legacy non-bridge path (tenant_id None), so
            // this is inert today (set explicitly to None — no bare-policy
            // override). Step 3 flips builder/dev to trusted_build_egress when
            // they move onto the bridge.
            network_policy: None,
            transparent_terminator_port: None,
            egress_relay_socket: None,
            // The supervisor holds this for its whole life. This process starts
            // the session and exits, so a lock taken here would not survive to
            // protect the running VM.
            exclusive_image_lock: Some(nix_store.lock_path().to_path_buf()),
            // Builder VMs are always hard-fail; they don't model
            // long-running user workloads where a restart policy would
            // apply.
            bridge_restart_policy: libkrun_sys::BridgeRestartPolicy::HardFail,
        };

        let mut child = spawn_supervisor_in_background(&supervisor_path, &cfg, &vm_state_dir)?;
        if guest_agent_vsock {
            wait_for_vsock_socket(
                &mut child,
                &vm_state_dir,
                mvm_agentd::vsock::GUEST_AGENT_PORT,
                PERSISTENT_BUILDER_READY_TIMEOUT,
                "builder guest agent",
            )?;
        }
        wait_for_path(
            &mut child,
            &job_dir.join(DISPATCH_READY_MARKER),
            PERSISTENT_BUILDER_READY_TIMEOUT,
            "persistent builder dispatch loop",
        )?;

        Ok(PersistentVmHandle {
            vm_state_dir,
            job_dir,
            session_id,
            supervisor: Some(child),
            egress_endpoint,
        })
    }
}

/// Handle to a live persistent builder VM. Owns the supervisor
/// `Child` for its lifetime; dropping without calling
/// [`Self::wait_for_shutdown`] or [`Self::kill`] leaks the
/// supervisor process (and the VM behind it) — callers should
/// always one of the two before dropping.
#[cfg(feature = "builder-vm")]
#[derive(Debug)]
pub struct PersistentVmHandle {
    vm_state_dir: PathBuf,
    job_dir: PathBuf,
    session_id: String,
    /// `None` after [`Self::wait_for_shutdown`] consumes it.
    supervisor: Option<std::process::Child>,
    egress_endpoint: Option<BuilderVsockEgressEndpoint>,
}

#[cfg(feature = "builder-vm")]
impl PersistentVmHandle {
    /// Path libkrun uses for the per-VM state (vsock sockets,
    /// console log, PID file). Pass this to
    /// `dispatch_socket_path` when constructing the
    /// `PersistentBuilderSupervisor`.
    pub fn vm_state_dir(&self) -> &Path {
        &self.vm_state_dir
    }

    /// Host-side path of the libkrun-managed Unix socket that
    /// proxies to AF_VSOCK [`mvm_agentd::builder_agent::BUILDER_DISPATCH_PORT`]
    /// inside the guest. `PersistentBuilderSupervisor::new` takes
    /// this directly.
    pub fn dispatch_socket_path(&self) -> PathBuf {
        mvm_core::config::vm_vsock_port_socket_at(
            &self.vm_state_dir,
            mvm_agentd::builder_agent::BUILDER_DISPATCH_PORT,
        )
    }

    /// Per-VM job directory bound at `/job` inside the guest.
    /// Hosts stage per-dispatch artifacts (`<job_dir_relpath>/cmd.sh`,
    /// per-dispatch install specs, etc.) here before sending the
    /// matching `HostVmRequest::Run`.
    pub fn job_dir(&self) -> &Path {
        &self.job_dir
    }

    /// Opaque session identifier — useful for logging /
    /// observability. Stable for the VM's lifetime.
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Block until the supervisor child exits. Normal way to
    /// reach this is the supervisor sending `HostVmRequest::Shutdown`,
    /// the guest dispatch loop processing it + replying `Bye`,
    /// then `mvm-host-vm-init` calling `reboot(RB_POWER_OFF)`,
    /// then libkrun's `krun_start_enter` returning, then the
    /// supervisor exiting `main`. Consumes the child; subsequent
    /// calls return [`BuilderVmError::ExtractionFailed`].
    pub fn wait_for_shutdown(mut self) -> Result<i32, BuilderVmError> {
        let mut child = self.supervisor.take().ok_or_else(|| {
            BuilderVmError::ExtractionFailed(
                "PersistentVmHandle::wait_for_shutdown called twice".to_string(),
            )
        })?;
        let status = child.wait().map_err(|e| {
            BuilderVmError::ExtractionFailed(format!("waiting on persistent supervisor: {e}"))
        })?;
        if let Some(endpoint) = &self.egress_endpoint {
            endpoint.reap();
        }
        Ok(status.code().unwrap_or(-1))
    }

    /// Forcibly terminate the supervisor child (SIGKILL via
    /// `Child::kill`). The VM goes down hard; in-flight builds
    /// are abandoned. Use only as a fallback after
    /// [`Self::wait_for_shutdown`] hangs.
    pub fn kill(&mut self) -> std::io::Result<()> {
        if let Some(child) = self.supervisor.as_mut() {
            child.kill()?;
            let _ = child.wait();
            self.supervisor = None;
        }
        if let Some(endpoint) = &self.egress_endpoint {
            endpoint.reap();
        }
        self.egress_endpoint = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_egress_supervisor_keeps_protocol_stdout_free_of_tracing() {
        let command = builder_egress_supervisor_command(
            Path::new("/opt/mvmctl"),
            Path::new("/opt/mvm-network-endpoint"),
        );
        assert_eq!(command.get_program(), "/opt/mvmctl");
        assert_eq!(
            command.get_args().collect::<Vec<_>>(),
            [
                "__builder-egress-supervisor",
                "--endpoint",
                "/opt/mvm-network-endpoint"
            ]
        );
        let env = command.get_envs().collect::<Vec<_>>();
        assert!(env.iter().any(|(key, value)| {
            *key == "RUST_LOG" && value.is_some_and(|value| value == "off")
        }));
        for key in [
            mvm_core::observability::span_timing::ENV_ENABLE,
            mvm_core::observability::span_timing::ENV_OUT,
            mvm_core::observability::span_timing::ENV_FILTER,
        ] {
            assert!(
                env.iter()
                    .any(|(candidate, value)| *candidate == key && value.is_none()),
                "{key} must be removed from the protocol child"
            );
        }
    }
    use crate::builder_vm_runtime::{INSTALL_SPEC_FILENAME, shell_single_quote_escape};
    use mvm_core::util::test_env::TestEnv;
    use tempfile::TempDir;

    static ENV_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Drop the per-run `mvm.hostepoch=<secs>` clock token the image cmdline
    /// carries (its value is wall-clock-dependent), so exact-cmdline assertions
    /// stay deterministic.
    fn strip_hostepoch_token(cmdline: &str) -> String {
        cmdline
            .split_whitespace()
            .filter(|t| !t.starts_with("mvm.hostepoch="))
            .collect::<Vec<_>>()
            .join(" ")
    }

    #[test]
    fn align_up_rounds_to_next_multiple() {
        assert_eq!(align_up(0, 4096), 0);
        assert_eq!(align_up(1, 4096), 4096);
        assert_eq!(align_up(4096, 4096), 4096);
        assert_eq!(align_up(4097, 4096), 8192);
        // The real builder-kernel case: 8_963_072 (mod 4096 == 1024) → 8_966_144.
        assert_eq!(align_up(8_963_072, 4096), 8_966_144);
    }

    #[test]
    fn write_zero_padded_copy_pads_and_preserves_prefix() {
        let dir = TempDir::new().unwrap();
        let src = dir.path().join("vmlinux");
        let body = vec![0xABu8; 5000]; // not a multiple of 4096
        std::fs::write(&src, &body).unwrap();
        let dest = dir.path().join("vmlinux.page-aligned");
        write_zero_padded_copy(&src, &dest, 8192).unwrap();

        let padded = std::fs::read(&dest).unwrap();
        assert_eq!(padded.len(), 8192, "padded to the page boundary");
        assert_eq!(&padded[..5000], &body[..], "original bytes preserved");
        assert!(padded[5000..].iter().all(|&b| b == 0), "tail zero-filled");
        // The process-unique temp sibling is renamed away, not left behind.
        let leftover_tmp = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .any(|e| {
                e.file_name()
                    .to_string_lossy()
                    .contains(".page-aligned.tmp")
            });
        assert!(!leftover_tmp, "no .tmp.<pid> sibling left behind");
    }

    #[test]
    fn host_page_size_is_a_sane_page() {
        let p = host_page_size();
        assert!(p >= 4096, "page size {p} unexpectedly small");
        assert!(p.is_power_of_two(), "page size {p} not a power of two");
    }

    #[cfg(unix)]
    #[test]
    fn write_zero_padded_copy_handles_read_only_source() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        let src = dir.path().join("vmlinux");
        std::fs::write(&src, vec![0x5Au8; 5000]).unwrap();
        // Mirror the cached kernel: a read-only Nix-store-style source.
        std::fs::set_permissions(&src, std::fs::Permissions::from_mode(0o444)).unwrap();
        let dest = dir.path().join("vmlinux.page-aligned");
        // Must not fail EACCES extending the copied (read-only) file.
        write_zero_padded_copy(&src, &dest, 8192).unwrap();
        assert_eq!(std::fs::metadata(&dest).unwrap().len(), 8192);
    }

    #[test]
    fn aligned_copy_is_current_only_when_sized_and_fresh() {
        let dir = TempDir::new().unwrap();
        let src = dir.path().join("vmlinux");
        std::fs::write(&src, vec![1u8; 5000]).unwrap();
        let aligned = dir.path().join("vmlinux.page-aligned");

        // Absent → not current.
        assert!(!aligned_copy_is_current(&aligned, 8192, &src));
        // Wrong size → not current.
        std::fs::write(&aligned, vec![0u8; 4096]).unwrap();
        assert!(!aligned_copy_is_current(&aligned, 8192, &src));
        // Correct size and at least as new as the source → current.
        std::fs::write(&aligned, vec![0u8; 8192]).unwrap();
        assert!(aligned_copy_is_current(&aligned, 8192, &src));
    }

    #[test]
    fn page_aligned_kernel_passes_through_when_already_aligned() {
        let dir = TempDir::new().unwrap();
        let k = dir.path().join("vmlinux");
        // A whole number of host pages is aligned by construction on any host.
        let aligned_len = (host_page_size() * 2) as usize;
        std::fs::write(&k, vec![0u8; aligned_len]).unwrap();
        // Already aligned → original path, no sibling created.
        assert_eq!(page_aligned_kernel(&k).unwrap(), k);
        assert!(!dir.path().join("vmlinux.page-aligned").exists());
    }

    // The padding path is Linux-only (KVM's alignment requirement; macOS HVF
    // tolerates an unaligned kernel and `page_aligned_kernel` short-circuits).
    #[cfg(target_os = "linux")]
    #[test]
    fn page_aligned_kernel_pads_unaligned_on_linux() {
        let dir = TempDir::new().unwrap();
        let k = dir.path().join("vmlinux");
        // 5000 is not a whole number of pages on any real page size (4K/16K/64K).
        let raw = 5000u64;
        std::fs::write(&k, vec![7u8; raw as usize]).unwrap();
        let aligned = page_aligned_kernel(&k).unwrap();
        assert_eq!(aligned, dir.path().join("vmlinux.page-aligned"));
        let expected = align_up(raw, host_page_size());
        assert_eq!(std::fs::metadata(&aligned).unwrap().len(), expected);
    }

    #[test]
    fn krun_context_for_rootfs_image_sets_cmdline_and_kernel_format() {
        let dir = TempDir::new().unwrap();
        let kernel = dir.path().join("vmlinux");
        let rootfs = dir.path().join("rootfs.ext4");
        let mut kernel_bytes = vec![0u8; host_page_size() as usize];
        if cfg!(target_arch = "x86_64") {
            kernel_bytes[..4].copy_from_slice(b"\x7fELF");
        }
        std::fs::write(&kernel, kernel_bytes).unwrap();
        std::fs::write(&rootfs, b"rootfs").unwrap();

        let image = BuilderVmImage::new(
            kernel.clone(),
            rootfs.clone(),
            "console=hvc0 root=/dev/vda ro rootfstype=ext4 rootwait panic=-1 loglevel=8 init=/init mvm.chain_init=/sbin/mvm-host-vm-init".to_string(),
        );

        let ctx = krun_context_for_image("builder-test", &image).unwrap();
        assert_eq!(ctx.rootfs_path.as_deref(), Some(rootfs.to_str().unwrap()));
        assert_eq!(
            ctx.kernel_cmdline.as_deref(),
            Some(
                "console=hvc0 root=/dev/vda ro rootfstype=ext4 rootwait panic=-1 loglevel=8 init=/init mvm.chain_init=/sbin/mvm-host-vm-init"
            )
        );
        let expected = if cfg!(target_arch = "x86_64") {
            KernelFormat::Elf
        } else {
            KernelFormat::Raw
        };
        assert_eq!(ctx.kernel_format, expected);
    }

    #[test]
    fn builder_vsock_egress_switches_stage0_launches_to_vsock_direct() {
        let ctx = apply_builder_vsock_egress(KrunContext::new(
            "stage0-test",
            "/k/vmlinux",
            "/r/rootfs.ext4",
        ));
        assert_eq!(
            ctx.kernel_cmdline.as_deref(),
            Some(BUILDER_VSOCK_EGRESS_TOKEN)
        );
        assert!(
            matches!(ctx.networking, libkrun_sys::NetworkingMode::VsockDirect),
            "Stage 0 builder boots must use the explicit vsock device, not TSI"
        );
        assert_eq!(ctx.host_listen_ports, vec![mvm_agentd::vsock::EGRESS_PORT]);
    }

    #[test]
    fn builder_vsock_socket_dir_handles_deep_worktree_paths() {
        let root = TempDir::new().unwrap();
        let state_dir = root.path().join("x".repeat(120));
        std::fs::create_dir_all(&state_dir).unwrap();

        let socket_dir = builder_vsock_socket_dir(&state_dir).unwrap();
        assert_ne!(socket_dir, state_dir);
        assert_eq!(socket_dir, mvm_core::config::vm_socket_dir_at(&state_dir));
        assert!(socket_dir.exists());
        let socket_path =
            mvm_core::config::vm_vsock_port_socket_at(&state_dir, mvm_agentd::vsock::EGRESS_PORT);
        assert!(socket_path.to_string_lossy().len() <= 103);

        std::fs::remove_dir_all(socket_dir).unwrap();
    }

    fn ok_mounts(scratch: &TempDir) -> BuilderMounts {
        let flake = scratch.path().join("flake");
        std::fs::create_dir_all(&flake).unwrap();
        let out = scratch.path().join("out");
        let host_bins = scratch.path().join("host-bins");
        std::fs::create_dir_all(&host_bins).unwrap();
        BuilderMounts {
            flake_src: flake,
            host_nix_store: None,
            artifact_out: out,
            host_bin_dir: host_bins,
            staged_user_flake: None,
        }
    }

    fn ok_job() -> BuilderJob {
        BuilderJob::Flake {
            flake_ref: "path:/work".to_string(),
            attr_path: "packages.x86_64-linux.default".to_string(),
        }
    }

    #[test]
    fn defaults_match_plan_72_w1() {
        let vm = LibkrunBuilderVm::default();
        assert_eq!(vm.vcpus, 4);
        // 4 → 8 GiB (in-VM nix builds peak ~5-6 GiB; OOM at lower
        // default). Later raised to 16 GiB for overlapping build
        // working sets. Hardcoded so a regression on either side
        // fails fast.
        assert_eq!(vm.memory_mib, 16384);
        assert_eq!(vm.nix_store_mib, 65536);
    }

    #[test]
    fn validate_mounts_rejects_missing_flake_src() {
        let scratch = TempDir::new().unwrap();
        let host_bins = scratch.path().join("host-bins");
        std::fs::create_dir_all(&host_bins).unwrap();
        let mounts = BuilderMounts {
            flake_src: scratch.path().join("does-not-exist"),
            host_nix_store: None,
            artifact_out: scratch.path().join("out"),
            host_bin_dir: host_bins,
            staged_user_flake: None,
        };
        let err = LibkrunBuilderVm::default()
            .validate_mounts(&mounts)
            .unwrap_err();
        assert!(matches!(err, BuilderVmError::ExtractionFailed(_)));
        assert!(format!("{err}").contains("does not exist"));
    }

    #[test]
    fn validate_mounts_rejects_flake_src_that_is_a_file() {
        let scratch = TempDir::new().unwrap();
        let file = scratch.path().join("not-a-dir");
        std::fs::write(&file, b"").unwrap();
        let host_bins = scratch.path().join("host-bins");
        std::fs::create_dir_all(&host_bins).unwrap();
        let mounts = BuilderMounts {
            flake_src: file,
            host_nix_store: None,
            artifact_out: scratch.path().join("out"),
            host_bin_dir: host_bins,
            staged_user_flake: None,
        };
        let err = LibkrunBuilderVm::default()
            .validate_mounts(&mounts)
            .unwrap_err();
        assert!(format!("{err}").contains("must be a directory"));
    }

    #[test]
    fn validate_mounts_creates_artifact_out_if_missing() {
        let scratch = TempDir::new().unwrap();
        let mounts = ok_mounts(&scratch);
        assert!(!mounts.artifact_out.exists());
        LibkrunBuilderVm::default()
            .validate_mounts(&mounts)
            .unwrap();
        assert!(mounts.artifact_out.is_dir());
    }

    #[cfg(unix)]
    #[test]
    fn validate_mounts_rejects_non_utf8_paths() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;
        use std::path::PathBuf;

        // Synthesize a PathBuf with non-UTF-8 bytes in memory.
        // 0xFF is invalid UTF-8 (RFC 3629 says the byte cannot
        // appear in a valid UTF-8 sequence). We don't touch the
        // filesystem because APFS refuses to create files with
        // non-UTF-8 names; the validator's UTF-8 check runs
        // before any I/O so this still exercises the right path.
        let raw = OsStr::from_bytes(b"/tmp/non-utf8-\xff");
        let bad_path = PathBuf::from(raw);
        let scratch = TempDir::new().unwrap();
        let host_bins = scratch.path().join("host-bins");
        std::fs::create_dir_all(&host_bins).unwrap();
        let mounts = BuilderMounts {
            flake_src: bad_path,
            host_nix_store: None,
            artifact_out: std::env::temp_dir().join("mvm-plan72-w1-utf8-test-out"),
            host_bin_dir: host_bins,
            staged_user_flake: None,
        };
        let err = LibkrunBuilderVm::default()
            .validate_mounts(&mounts)
            .unwrap_err();
        assert!(
            format!("{err}").contains("non-UTF-8 bytes"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn validate_job_rejects_empty_flake_ref() {
        let job = BuilderJob::Flake {
            flake_ref: "".to_string(),
            attr_path: "packages.x86_64-linux.default".to_string(),
        };
        let err = LibkrunBuilderVm::default().validate_job(&job).unwrap_err();
        assert!(format!("{err}").contains("flake_ref"));
    }

    #[test]
    fn validate_job_rejects_whitespace_only_attr_path() {
        let job = BuilderJob::Flake {
            flake_ref: "path:/work".to_string(),
            attr_path: "   ".to_string(),
        };
        let err = LibkrunBuilderVm::default().validate_job(&job).unwrap_err();
        assert!(format!("{err}").contains("attr_path"));
    }

    #[test]
    fn validate_job_rejects_install_with_missing_spec() {
        // The Install variant validates that spec_path actually
        // exists — the spec is read inside the VM, so the host needs
        // the file present before dispatch.
        let job = BuilderJob::Install {
            spec_path: PathBuf::from("/definitely/does/not/exist.json"),
        };
        let err = LibkrunBuilderVm::default().validate_job(&job).unwrap_err();
        assert!(
            matches!(err, BuilderVmError::ExtractionFailed(_)),
            "got {err:?}"
        );
        assert!(
            format!("{err}").contains("spec_path"),
            "expected spec_path in error: {err}"
        );
    }

    #[test]
    fn validate_job_accepts_install_with_existing_spec() {
        // Smoke-test the happy path of Install validation. We
        // don't construct a real spec — the parsing happens later.
        // We only check that a real file passes.
        let scratch = TempDir::new().unwrap();
        let spec_path = scratch.path().join("spec.json");
        std::fs::write(&spec_path, b"{}").unwrap();
        let job = BuilderJob::Install { spec_path };
        LibkrunBuilderVm::default().validate_job(&job).unwrap();
    }

    #[test]
    fn run_build_surfaces_environment_gaps_for_install_variant() {
        // The Install variant is wired — passing input validation no
        // longer trips NotYetImplemented. Two host shapes can hit
        // this code path:
        //
        // - CI runner without libkrun: `run_build` short-circuits at
        //   the supervisor-binary lookup with `LibkrunUnavailable`
        //   (or `ExtractionFailed` if an earlier I/O step fails).
        // - Contributor host with libkrun installed via Homebrew (per
        //   `CLAUDE.md` host-deps): the supervisor actually spawns
        //   against the stub `{}` install spec, which the in-VM
        //   pipeline rejects because the spec is missing required
        //   fields (`language`, …) — surfacing as `NixBuildFailed`.
        // - Contributor host with a current lean builder image but no
        //   resolvable runtime overlay → `RuntimeOverlayUnavailable`.
        //
        // Both outcomes prove the wiring proceeds past validation
        // rather than short-circuiting on `NotYetImplemented`, which
        // is what this test exists to guarantee. The test must NOT
        // require a specific host environment.
        let scratch = TempDir::new().unwrap();
        let spec_path = scratch.path().join("spec.json");
        std::fs::write(&spec_path, b"{}").unwrap();
        let mounts = ok_mounts(&scratch);
        let err = LibkrunBuilderVm::default()
            .run_build(&BuilderJob::Install { spec_path }, &mounts)
            .unwrap_err();
        assert!(
            !matches!(err, BuilderVmError::NotYetImplemented),
            "Install variant must not short-circuit on NotYetImplemented: {err:?}"
        );
        assert!(
            matches!(
                err,
                BuilderVmError::LibkrunUnavailable(_)
                    | BuilderVmError::ExtractionFailed(_)
                    | BuilderVmError::NixBuildFailed(_)
                    | BuilderVmError::DegradedBuilderStore { .. }
                    | BuilderVmError::SupervisorExited { .. }
                    | BuilderVmError::RuntimeOverlayUnavailable(_)
            ),
            "unexpected error variant: {err:?}"
        );
    }

    #[test]
    fn stage_job_dir_install_copies_spec_into_job_dir() {
        // Install jobs stage `<job_dir>/install_spec.json` rather
        // than `cmd.sh`. The
        // guest's `mvm-host-vm-init` probes for that filename and
        // dispatches through the install pipeline.
        let scratch = TempDir::new().unwrap();
        let job_dir = scratch.path().join("job-1");
        let spec_path = scratch.path().join("spec.json");
        let spec_body = br#"{"language":"python","lockfile_relative_path":"uv.lock","source_mount":"/work","gate":"dev"}"#;
        std::fs::write(&spec_path, spec_body).unwrap();
        stage_job_dir(&job_dir, &BuilderJob::Install { spec_path }, None, None).expect("stage ok");
        let dst = job_dir.join(INSTALL_SPEC_FILENAME);
        assert!(dst.is_file(), "install_spec.json must be staged at {dst:?}");
        let on_disk = std::fs::read(&dst).unwrap();
        assert_eq!(on_disk, spec_body, "spec bytes must round-trip verbatim");
        // No cmd.sh is emitted for install jobs.
        assert!(
            !job_dir.join("cmd.sh").exists(),
            "install jobs must not stage cmd.sh"
        );
    }

    // `finalize_install_job_*` test coverage migrated to
    // `builder_vm_runtime` alongside the function itself.

    #[test]
    fn run_build_fails_validation_before_reaching_libkrun() {
        // Bad input → validation error from `validate_mounts` /
        // `validate_job`, before run_build reaches the libkrun
        // availability check or the image cache.
        let scratch = TempDir::new().unwrap();
        let host_bins = scratch.path().join("host-bins");
        std::fs::create_dir_all(&host_bins).unwrap();
        let mounts = BuilderMounts {
            flake_src: scratch.path().join("missing"),
            host_nix_store: None,
            artifact_out: scratch.path().join("out"),
            host_bin_dir: host_bins,
            staged_user_flake: None,
        };
        let err = LibkrunBuilderVm::default()
            .run_build(&ok_job(), &mounts)
            .unwrap_err();
        assert!(matches!(err, BuilderVmError::ExtractionFailed(_)));
    }

    #[test]
    fn run_build_surfaces_environment_gaps_on_clean_input() {
        // Input passes `validate_mounts` + `validate_job` (the dir
        // exists, the flake_ref/attr_path are well-shaped) but the
        // *environment* is missing one of the things `run_build`
        // needs to succeed. Which thing depends on host state, and
        // each yields a typed error variant — this test pins the
        // union so a regression that swaps in `Internal`/`Unknown`
        // or panics outright fails fast:
        //   - libkrun shared library missing → LibkrunUnavailable
        //   - builder VM image cache empty   → ExtractionFailed
        //   - mvm-libkrun-supervisor missing → LibkrunUnavailable
        //   - flake.nix missing inside the (empty) stub mount, on
        //     a host where libkrun + cache + supervisor are all
        //     present (fully-bootstrapped contributor host) →
        //     NixBuildFailed
        //   - builder store degraded (dangling GC root in the nix
        //     store) on a host with a populated but corrupted cache →
        //     DegradedBuilderStore
        //   - a partially bootable cached image on a host where the
        //     supervisor starts but exits before the requested job runs →
        //     SupervisorExited
        //   - a lean builder image without a resolvable runtime sidecar →
        //     RuntimeOverlayUnavailable
        // All six are legitimate "environment gap" surfaces. The
        // Nix-build failure is what `mvmctl bootstrap` reports to operators with
        // a populated cache; the first three are what `mvmctl bootstrap`
        // reports before the Stage 0 bootstrap completes.
        let scratch = TempDir::new().unwrap();
        let mounts = ok_mounts(&scratch);
        let err = LibkrunBuilderVm::default()
            .run_build(&ok_job(), &mounts)
            .unwrap_err();
        assert!(
            matches!(
                err,
                BuilderVmError::LibkrunUnavailable(_)
                    | BuilderVmError::ExtractionFailed(_)
                    | BuilderVmError::NixBuildFailed(_)
                    | BuilderVmError::DegradedBuilderStore { .. }
                    | BuilderVmError::SupervisorExited { .. }
                    | BuilderVmError::RuntimeOverlayUnavailable(_)
            ),
            "unexpected error variant: {err:?}"
        );
    }

    #[test]
    fn shell_single_quote_escape_handles_apostrophes() {
        // `cmd.sh` embeds flake_ref + attr_path inside `'…'`
        // quoted shell variables. The only character that can't
        // appear verbatim is `'`. Standard escape: close-quote,
        // escape-via-backslash, reopen-quote.
        assert_eq!(shell_single_quote_escape("plain"), "plain");
        assert_eq!(shell_single_quote_escape("it's"), r"it'\''s");
        assert_eq!(shell_single_quote_escape("a'b'c"), r"a'\''b'\''c");
    }

    #[test]
    fn stage_job_dir_writes_cmd_sh_with_escaped_inputs() {
        let scratch = TempDir::new().unwrap();
        let job_dir = scratch.path().join("job-1");
        let job = BuilderJob::Flake {
            flake_ref: "path:/work/nix/images/foo".to_string(),
            attr_path: "packages.x86_64-linux.default".to_string(),
        };
        stage_job_dir(&job_dir, &job, None, None).unwrap();
        let cmd = std::fs::read_to_string(job_dir.join("cmd.sh")).unwrap();
        assert!(cmd.contains("FLAKE_REF='path:/work/nix/images/foo'"));
        assert!(cmd.contains("ATTR_PATH='packages.x86_64-linux.default'"));
        assert!(cmd.starts_with("#!/bin/sh"));
        assert!(cmd.contains("set -eu"));
        assert!(cmd.contains("cd /work"));
        assert!(cmd.contains("max-jobs = auto"));
        assert!(cmd.contains("cores = 0"));
        assert!(cmd.contains("auto-optimise-store = true"));
        assert!(cmd.contains("XDG_CACHE_HOME=/nix-store/.cache"));
        assert!(
            cmd.contains(
                "export PATH=/usr/local/sbin:/usr/local/bin:/sbin:/usr/sbin:/bin:/usr/bin"
            )
        );
        assert!(cmd.contains("NIX_BIN=/sbin/nix"));
        assert!(cmd.contains("NIX_STORE_BIN=/sbin/nix-store"));
        assert!(cmd.contains("\"$NIX_BIN\" build"));
        assert!(cmd.contains("\"$NIX_STORE_BIN\" --add-root"));
        assert!(cmd.contains("printf '%s\\n' \"$NIX_OUT\" > /job/store-path"));
        // Legacy (no-override) mode never injects an mvm override.
        assert!(!cmd.contains("--override-input mvm"));
    }

    #[test]
    fn stage_job_dir_override_stages_user_flake_and_overrides_mvm() {
        // Source-checkout override mode stages the user flake into
        // the job dir and pins `mvm` to the local checkout
        // mounted at /work, so the workload builds against in-repo nix
        // rather than GitHub.
        let scratch = TempDir::new().unwrap();
        let job_dir = scratch.path().join("job-ovr");
        let user_flake = scratch.path().join("hello-app");
        std::fs::create_dir_all(user_flake.join("src")).unwrap();
        std::fs::write(user_flake.join("flake.nix"), "{ inputs.mvm.url = \"x\"; }").unwrap();
        std::fs::write(user_flake.join("launch.json"), "{}").unwrap();
        std::fs::write(user_flake.join("src/app.py"), "x").unwrap();

        // A stand-in mvm workspace: members + a build artifact and a
        // non-allowlisted top-level dir that must be pruned from the
        // staged snapshot.
        let workspace = scratch.path().join("mvm-ws");
        std::fs::create_dir_all(workspace.join("crates/mvm-agentd/src")).unwrap();
        std::fs::create_dir_all(workspace.join("crates/mvm-agentd/target/debug")).unwrap();
        std::fs::create_dir_all(workspace.join("third_party/local-path-crate/src")).unwrap();
        std::fs::create_dir_all(workspace.join("public")).unwrap();
        std::fs::write(workspace.join("Cargo.toml"), "[workspace]").unwrap();
        std::fs::write(workspace.join("Cargo.lock"), "").unwrap();
        std::fs::write(workspace.join("crates/mvm-agentd/Cargo.toml"), "x").unwrap();
        std::fs::write(workspace.join("crates/mvm-agentd/src/lib.rs"), "x").unwrap();
        std::fs::write(workspace.join("crates/mvm-agentd/target/debug/junk"), "x").unwrap();
        std::fs::write(
            workspace.join("third_party/local-path-crate/Cargo.toml"),
            "[package]\nname = \"local-path-crate\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        std::fs::write(
            workspace.join("third_party/local-path-crate/src/lib.rs"),
            "pub fn linked() {}",
        )
        .unwrap();
        std::fs::write(workspace.join("public/index.html"), "x").unwrap();

        let job = BuilderJob::Flake {
            flake_ref: "/work".to_string(), // ignored in override mode
            attr_path: "packages.aarch64-linux.default".to_string(),
        };
        stage_job_dir(
            &job_dir,
            &job,
            Some(user_flake.as_path()),
            Some(workspace.as_path()),
        )
        .unwrap();

        // User flake copied beside cmd.sh, including the src tree.
        assert!(job_dir.join("workload/flake.nix").exists());
        assert!(job_dir.join("workload/src/app.py").exists());

        // Filtered mvm-workspace snapshot: members copied, build artifacts
        // and non-allowlisted top-level dirs pruned.
        assert!(job_dir.join("mvm-src/Cargo.lock").exists());
        assert!(
            job_dir
                .join("mvm-src/crates/mvm-agentd/src/lib.rs")
                .exists()
        );
        assert!(
            job_dir
                .join("mvm-src/third_party/local-path-crate/src/lib.rs")
                .exists(),
            "workspace-local path dependencies must be staged"
        );
        assert!(
            !job_dir.join("mvm-src/crates/mvm-agentd/target").exists(),
            "target/ must be pruned from the staged snapshot"
        );
        assert!(
            !job_dir.join("mvm-src/public").exists(),
            "non-allowlisted top-level dirs must not be staged"
        );

        let cmd = std::fs::read_to_string(job_dir.join("cmd.sh")).unwrap();
        // Builds the staged workload resolved relative to the script dir.
        assert!(cmd.contains(r#"FLAKE_REF="$(cd "$(dirname "$0")" && pwd)/workload""#));
        // Resolves the filtered workspace snapshot beside the script too.
        assert!(cmd.contains(r#"MVM_SRC="$(cd "$(dirname "$0")" && pwd)/mvm-src""#));
        // Pins mvm to the local checkout and mvm-workspace to the snapshot.
        assert!(cmd.contains("--override-input mvm path:/work/nix"));
        assert!(cmd.contains(r#"--override-input mvm/mvm-workspace "path:$MVM_SRC""#));
        assert!(cmd.contains("ATTR_PATH='packages.aarch64-linux.default'"));
        // The overrides ride both the build and the metadata eval.
        assert_eq!(
            cmd.matches("--override-input mvm path:/work/nix").count(),
            3
        );
        assert_eq!(
            cmd.matches(r#"--override-input mvm/mvm-workspace "path:$MVM_SRC""#)
                .count(),
            3
        );
    }

    #[test]
    fn stage_filtered_work_input_excludes_scratch_dirs_and_keeps_source() {
        // A source checkout's `work` input (`BuilderMounts::flake_src` /
        // `BuilderShellJob::work_dir`) can be the repo root itself, which
        // carries `target/` (Rust build output), `.worktrees/` (sibling
        // checkouts), and `.git/` (full history) — tens of GB unfiltered.
        // Staging through the same exclusion the mvm-workspace snapshot
        // uses must prune all three while keeping real source files, or
        // the packed input overflows the guest's RAM-capped extraction
        // tmpfs ("No space left on device").
        let scratch = TempDir::new().unwrap();
        let src = scratch.path().join("repo");
        std::fs::create_dir_all(src.join("target/debug")).unwrap();
        std::fs::write(src.join("target/debug/junk"), "x").unwrap();
        std::fs::create_dir_all(src.join(".worktrees/other-branch")).unwrap();
        std::fs::write(src.join(".worktrees/other-branch/junk"), "x").unwrap();
        std::fs::create_dir_all(src.join(".git")).unwrap();
        std::fs::write(src.join(".git/HEAD"), "ref: refs/heads/main").unwrap();
        std::fs::create_dir_all(src.join("crates/mvm-build/src")).unwrap();
        std::fs::write(src.join("crates/mvm-build/src/lib.rs"), "// real source").unwrap();

        let staged = stage_filtered_work_input(&src).expect("stage ok");

        assert!(
            !staged.path().join("target").exists(),
            "target/ must be pruned from the work input"
        );
        assert!(
            !staged.path().join(".worktrees").exists(),
            ".worktrees/ must be pruned from the work input"
        );
        assert!(
            !staged.path().join(".git").exists(),
            ".git/ must be pruned from the work input"
        );
        assert_eq!(
            std::fs::read_to_string(staged.path().join("crates/mvm-build/src/lib.rs")).unwrap(),
            "// real source"
        );

        // Prove the exclusion survives the actual disk-transport pack —
        // this tar is what rides into the guest.
        let image = scratch.path().join("input.img");
        pack_input_disk(
            &[InputTree {
                name: "work",
                src: staged.path(),
            }],
            None,
            &image,
            512,
        )
        .unwrap();
        let dest = scratch.path().join("unpacked");
        read_output_disk(&image, &dest).unwrap();
        assert!(!dest.join("work/target").exists());
        assert!(!dest.join("work/.worktrees").exists());
        assert!(!dest.join("work/.git").exists());
        assert_eq!(
            std::fs::read_to_string(dest.join("work/crates/mvm-build/src/lib.rs")).unwrap(),
            "// real source"
        );
    }

    #[test]
    fn host_arch_tag_is_one_of_two_known_values() {
        // The builder-vm flake outputs aarch64-linux and
        // x86_64-linux only; the cache-key segment must match
        // one of those.
        let tag = host_arch_tag();
        assert!(
            tag == "aarch64" || tag == "x86_64",
            "unexpected arch tag: {tag}"
        );
    }

    #[test]
    fn stage0_nix_store_image_name_is_arch_keyed_and_distinct_from_builder() {
        let name = stage0_nix_store_image_name();
        // `cache info` globs `nix-store-*.img` for its sparse report;
        // stay inside that glob so the Stage 0 store is surfaced too.
        assert!(name.starts_with("nix-store-stage0-"), "got {name}");
        assert!(name.ends_with(".img"), "got {name}");
        assert!(name.contains(host_arch_tag()), "got {name}");
        // Must NOT collide with the steady-state builder store filename,
        // or the two flocks would serialize against each other.
        assert_ne!(name, format!("nix-store-{}.img", host_arch_tag()));
    }

    #[test]
    fn stage0_nix_store_host_marker_is_order_independent_and_schema_bound() {
        let scratch = TempDir::new().unwrap();
        let store = scratch.path().join("store");
        std::fs::create_dir_all(store.join("bbb-seed-b")).unwrap();
        std::fs::create_dir_all(store.join("aaa-seed-a")).unwrap();

        let marker = stage0_nix_store_host_marker(&store).unwrap();
        assert!(marker.starts_with("schema_version=2\n"));
        assert!(marker.contains("seed_store_entries_sha256="));

        std::fs::remove_dir_all(&store).unwrap();
        std::fs::create_dir_all(store.join("aaa-seed-a")).unwrap();
        std::fs::create_dir_all(store.join("bbb-seed-b")).unwrap();
        assert_eq!(marker, stage0_nix_store_host_marker(&store).unwrap());
    }

    #[test]
    fn stage0_host_ext4_block_count_leaves_geometry_margin() {
        let scratch = TempDir::new().unwrap();
        let image = scratch.path().join("nix-store-stage0-test.img");
        std::fs::File::create(&image)
            .unwrap()
            .set_len(128 * 1024)
            .unwrap();

        assert_eq!(host_file_4k_blocks_for_ext4(&image).unwrap(), 16);
    }

    /// The no-host-mkfs path leaves a blank sparse device so the Linux guest's
    /// established e2fsprogs formatter owns the long-lived filesystem.
    #[cfg(not(feature = "pure-mkfs"))]
    #[test]
    fn stage0_store_reset_leaves_blank_sparse_device_for_guest_format() {
        let scratch = TempDir::new().unwrap();
        let image = scratch.path().join("nix-store-stage0-test.img");
        std::fs::File::create(&image)
            .unwrap()
            .set_len(64 * 1024 * 1024)
            .unwrap();
        std::fs::OpenOptions::new()
            .write(true)
            .open(&image)
            .unwrap()
            .write_all(b"stale-filesystem")
            .unwrap();

        reset_stage0_store_for_guest_format(&image).unwrap();

        assert_eq!(std::fs::metadata(&image).unwrap().len(), 64 * 1024 * 1024);
        let mut prefix = [0u8; 16];
        std::fs::File::open(&image)
            .unwrap()
            .read_exact(&mut prefix)
            .unwrap();
        assert_eq!(prefix, [0; 16]);
    }

    #[cfg(feature = "pure-mkfs")]
    #[test]
    fn stage0_store_without_host_mkfs_writes_labeled_ext4() {
        use std::io::{Read, Seek, SeekFrom};

        let scratch = TempDir::new().unwrap();
        let image = scratch.path().join("nix-store-stage0-test.img");
        std::fs::File::create(&image)
            .unwrap()
            .set_len(64 * 1024 * 1024)
            .unwrap();

        format_stage0_store_without_host_mkfs(&image).unwrap();

        let mut file = std::fs::File::open(&image).unwrap();
        file.seek(SeekFrom::Start(1024 + 0x38)).unwrap();
        let mut magic = [0u8; 2];
        file.read_exact(&mut magic).unwrap();
        assert_eq!(u16::from_le_bytes(magic), EXT4_SUPERBLOCK_MAGIC);

        file.seek(SeekFrom::Start(1024 + 0x78)).unwrap();
        let mut label = [0u8; 16];
        file.read_exact(&mut label).unwrap();
        assert!(label.starts_with(crate::rootfs::STAGE0_NIX_STORE_EXT4_LABEL.as_bytes()));
    }

    /// A matching external marker must not hide filesystem corruption. The
    /// second prepopulation pass reformats an image whose ext4 error-state bit
    /// is set, restoring a usable sparse store instead of handing it back to
    /// Stage 0.
    #[test]
    fn stage0_store_prepopulate_repairs_corrupt_marked_store() {
        use std::io::{Read, Seek, SeekFrom, Write};

        let scratch = TempDir::new().unwrap();
        let root_dir = scratch.path().join("root");
        let seed_store = root_dir.join("nix").join("store");
        std::fs::create_dir_all(&seed_store).unwrap();
        std::fs::write(seed_store.join("aaa-seed-pkg"), b"x").unwrap();
        let image = BuilderVmImage::RootDir {
            root_dir: root_dir.clone(),
            entry_path: "init".into(),
        };
        let store_image = scratch.path().join("nix-store-stage0-test.img");
        std::fs::File::create(&store_image)
            .unwrap()
            .set_len(64 * 1024 * 1024)
            .unwrap();

        // Pass 1: create the best available clean store and record the seed marker.
        prepopulate_stage0_nix_store_image_with_mkfs(&image, &store_image, None).unwrap();
        assert!(
            stage0_nix_store_host_marker_path(&store_image).exists(),
            "first prepopulate records the host marker"
        );
        let magic_off = 1024 + 0x38;
        let read_magic = |p: &Path| {
            let mut f = std::fs::File::open(p).unwrap();
            f.seek(SeekFrom::Start(magic_off)).unwrap();
            let mut b = [0u8; 2];
            f.read_exact(&mut b).unwrap();
            u16::from_le_bytes(b)
        };
        let read_state = |p: &Path| {
            let mut f = std::fs::File::open(p).unwrap();
            f.seek(SeekFrom::Start(magic_off + 2)).unwrap();
            let mut b = [0u8; 2];
            f.read_exact(&mut b).unwrap();
            u16::from_le_bytes(b)
        };
        #[cfg(feature = "pure-mkfs")]
        assert_eq!(read_magic(&store_image), EXT4_SUPERBLOCK_MAGIC);
        #[cfg(not(feature = "pure-mkfs"))]
        assert_eq!(
            read_magic(&store_image),
            0,
            "guest must receive a blank disk"
        );

        // Model the guest's e2fsprogs format and clean unmount by writing the
        // superblock fields the host-side health check consumes.
        {
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .open(&store_image)
                .unwrap();
            f.seek(SeekFrom::Start(magic_off)).unwrap();
            f.write_all(&EXT4_SUPERBLOCK_MAGIC.to_le_bytes()).unwrap();
            f.write_all(&EXT4_VALID_FS.to_le_bytes()).unwrap();
        }

        // Set EXT4_ERROR_FS in the superblock state; only a reformat restores
        // the valid-filesystem state.
        {
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .open(&store_image)
                .unwrap();
            f.seek(SeekFrom::Start(magic_off + 2)).unwrap();
            f.write_all(&EXT4_ERROR_FS.to_le_bytes()).unwrap();
        }

        // Pass 2: marker matches, but filesystem health does not, so the
        // damaged state must be replaced rather than mounted again.
        prepopulate_stage0_nix_store_image_with_mkfs(&image, &store_image, None).unwrap();
        #[cfg(feature = "pure-mkfs")]
        assert_eq!(read_state(&store_image), EXT4_VALID_FS);
        #[cfg(not(feature = "pure-mkfs"))]
        assert_eq!(read_state(&store_image), 0);
    }

    #[test]
    fn stage0_store_prepopulate_preserves_recoverable_dirty_marked_store() {
        use std::io::{Read, Seek, SeekFrom, Write};

        let scratch = TempDir::new().unwrap();
        let root_dir = scratch.path().join("root");
        let seed_store = root_dir.join("nix").join("store");
        std::fs::create_dir_all(&seed_store).unwrap();
        std::fs::write(seed_store.join("aaa-seed-pkg"), b"x").unwrap();
        let image = BuilderVmImage::RootDir {
            root_dir,
            entry_path: "init".into(),
        };
        let store_image = scratch.path().join("nix-store-stage0-test.img");
        std::fs::File::create(&store_image)
            .unwrap()
            .set_len(64 * 1024 * 1024)
            .unwrap();

        prepopulate_stage0_nix_store_image_with_mkfs(&image, &store_image, None).unwrap();
        // Model a successful guest format followed by a forced host-side
        // timeout while the filesystem is mounted. The valid bit is clear,
        // but ext4 has not recorded an error and can replay its journal.
        {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .open(&store_image)
                .unwrap();
            file.seek(SeekFrom::Start(EXT4_SUPERBLOCK_MAGIC_OFFSET))
                .unwrap();
            file.write_all(&EXT4_SUPERBLOCK_MAGIC.to_le_bytes())
                .unwrap();
            file.write_all(&0_u16.to_le_bytes()).unwrap();
        }
        let sentinel_offset = 8 * 1024 * 1024;
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&store_image)
            .unwrap();
        file.seek(SeekFrom::Start(sentinel_offset)).unwrap();
        file.write_all(b"warm-cache").unwrap();
        drop(file);

        prepopulate_stage0_nix_store_image_with_mkfs(&image, &store_image, None).unwrap();
        let mut file = std::fs::File::open(&store_image).unwrap();
        file.seek(SeekFrom::Start(sentinel_offset)).unwrap();
        let mut sentinel = [0u8; 10];
        file.read_exact(&mut sentinel).unwrap();
        assert_eq!(&sentinel, b"warm-cache");
    }

    #[test]
    fn stage0_ext4_error_report_invalidates_only_the_external_store_marker() {
        let scratch = TempDir::new().unwrap();
        let store_image = scratch.path().join("nix-store-stage0-test.img");
        let marker = stage0_nix_store_host_marker_path(&store_image);
        let console = scratch.path().join("console.log");
        std::fs::write(&marker, b"seed").unwrap();
        std::fs::write(&console, b"stage0-init: build failed: nix build exit 1\n").unwrap();

        invalidate_stage0_store_after_ext4_error(&console, &store_image).unwrap();
        assert!(
            marker.exists(),
            "ordinary build failures preserve the warm store"
        );

        std::fs::write(
            &console,
            b"stage0-init: build failed: persistent Stage 0 ext4 store reported 7 filesystem error(s)\n",
        )
        .unwrap();
        invalidate_stage0_store_after_ext4_error(&console, &store_image).unwrap();
        assert!(
            !marker.exists(),
            "filesystem errors force a fresh guest format"
        );
    }

    // `read_job_result_*`, `extract_nix_store_hash_*`,
    // `finalize_flake_job_*`, `read_last_bytes_of_*`,
    // `acquire_nix_store_image_lock_*` test coverage migrated to
    // `builder_vm_runtime` alongside the functions themselves.

    #[test]
    fn ensure_builder_vm_image_requires_cmdline_txt() {
        let _env_lock = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut env = TestEnv::new();
        let scratch = TempDir::new().unwrap();
        env.set("HOME", scratch.path());
        env.set("MVM_HOME", scratch.path());
        // `ensure_builder_vm_image` falls back to seeding from the *default*
        // cache, which is `$HOME/.mvm/cache` and deliberately ignores MVM_HOME.
        // Without isolating HOME too, a developer with a real builder image on
        // disk gets it copied in - cmdline.txt and all - so the refusal under
        // test never happens and this passes only on a machine that has never
        // built one. CI is such a machine; a contributor's laptop is not.
        env.set("HOME", scratch.path());

        let arch_dir = scratch
            .path()
            .join("cache")
            .join("builder-vm")
            .join(host_arch_tag());
        std::fs::create_dir_all(&arch_dir).unwrap();
        std::fs::write(arch_dir.join("vmlinux"), b"kernel").unwrap();
        std::fs::write(arch_dir.join("rootfs.ext4"), b"rootfs").unwrap();

        let err = ensure_builder_vm_image().unwrap_err();
        assert!(
            format!("{err}").contains("cmdline.txt missing or unreadable"),
            "got {err}"
        );
    }

    #[test]
    fn ensure_builder_vm_image_refuses_stale_manifest_capabilities() {
        let _env_lock = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut env = TestEnv::new();
        let scratch = TempDir::new().unwrap();
        env.set("HOME", scratch.path());
        env.set("MVM_HOME", scratch.path());
        // `ensure_builder_vm_image` falls back to seeding from the *default*
        // cache, which is `$HOME/.mvm/cache` and deliberately ignores MVM_HOME.
        // Without isolating HOME too, a developer with a real builder image on
        // disk gets it copied in - cmdline.txt and all - so the refusal under
        // test never happens and this passes only on a machine that has never
        // built one. CI is such a machine; a contributor's laptop is not.
        env.set("HOME", scratch.path());

        let arch_dir = scratch
            .path()
            .join("cache")
            .join("builder-vm")
            .join(host_arch_tag());
        std::fs::create_dir_all(&arch_dir).unwrap();
        std::fs::write(arch_dir.join("vmlinux"), b"kernel").unwrap();
        std::fs::write(arch_dir.join("rootfs.ext4"), b"rootfs").unwrap();
        std::fs::write(
            arch_dir.join("cmdline.txt"),
            "console=hvc0 root=/dev/vda ro rootfstype=ext4 rootwait panic=-1 loglevel=8 init=/init mvm.chain_init=/sbin/mvm-host-vm-init\n",
        )
        .unwrap();
        std::fs::write(
            arch_dir.join("manifest.json"),
            r#"{"cache_contract_version":4,"runtime_overlay_ready":false,"vsock_egress_ready":true}"#,
        )
        .unwrap();

        let err = ensure_builder_vm_image().unwrap_err();
        assert!(
            format!("{err}").contains("cache_contract_version=4"),
            "got {err}"
        );
    }

    #[test]
    fn ensure_builder_vm_image_refuses_old_manifest_contract_version() {
        let _env_lock = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut env = TestEnv::new();
        let scratch = TempDir::new().unwrap();
        env.set("HOME", scratch.path());
        env.set("MVM_HOME", scratch.path());
        // `ensure_builder_vm_image` falls back to seeding from the *default*
        // cache, which is `$HOME/.mvm/cache` and deliberately ignores MVM_HOME.
        // Without isolating HOME too, a developer with a real builder image on
        // disk gets it copied in - cmdline.txt and all - so the refusal under
        // test never happens and this passes only on a machine that has never
        // built one. CI is such a machine; a contributor's laptop is not.
        env.set("HOME", scratch.path());

        let arch_dir = scratch
            .path()
            .join("cache")
            .join("builder-vm")
            .join(host_arch_tag());
        std::fs::create_dir_all(&arch_dir).unwrap();
        std::fs::write(arch_dir.join("vmlinux"), b"kernel").unwrap();
        std::fs::write(arch_dir.join("rootfs.ext4"), b"rootfs").unwrap();
        std::fs::write(
            arch_dir.join("cmdline.txt"),
            "console=hvc0 root=/dev/vda ro rootfstype=ext4 rootwait panic=-1 loglevel=8 init=/init mvm.chain_init=/sbin/mvm-host-vm-init\n",
        )
        .unwrap();
        std::fs::write(
            arch_dir.join("manifest.json"),
            r#"{"runtime_overlay_ready":true,"vsock_egress_ready":true}"#,
        )
        .unwrap();

        let err = ensure_builder_vm_image().unwrap_err();
        assert!(
            format!("{err}").contains("cache_contract_version=4"),
            "got {err}"
        );
    }

    #[test]
    #[cfg(not(target_os = "linux"))]
    fn ensure_builder_vm_image_accepts_current_manifest_capabilities() {
        let _env_lock = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut env = TestEnv::new();
        let scratch = TempDir::new().unwrap();
        env.set("MVM_HOME", scratch.path());
        // `ensure_builder_vm_image` falls back to seeding from the *default*
        // cache, which is `$HOME/.mvm/cache` and deliberately ignores MVM_HOME.
        // Without isolating HOME too, a developer with a real builder image on
        // disk gets it copied in - cmdline.txt and all - so the refusal under
        // test never happens and this passes only on a machine that has never
        // built one. CI is such a machine; a contributor's laptop is not.
        env.set("HOME", scratch.path());

        let arch_dir = scratch
            .path()
            .join("cache")
            .join("builder-vm")
            .join(host_arch_tag());
        std::fs::create_dir_all(&arch_dir).unwrap();
        let kernel = arch_dir.join("vmlinux");
        let rootfs = arch_dir.join("rootfs.ext4");
        std::fs::write(&kernel, b"kernel").unwrap();
        std::fs::write(&rootfs, b"rootfs").unwrap();
        std::fs::write(
            arch_dir.join("cmdline.txt"),
            "console=hvc0 root=/dev/vda ro rootfstype=ext4 rootwait panic=-1 loglevel=8 init=/init mvm.chain_init=/sbin/mvm-host-vm-init\n",
        )
        .unwrap();
        std::fs::write(
            arch_dir.join("manifest.json"),
            r#"{"cache_contract_version":4,"runtime_overlay_ready":true,"vsock_egress_ready":true}"#,
        )
        .unwrap();

        let image = ensure_builder_vm_image().unwrap();
        match image {
            BuilderVmImage::Rootfs {
                kernel_path,
                rootfs_path,
                cmdline,
            } => {
                assert_eq!(kernel_path, kernel);
                assert_eq!(rootfs_path, rootfs);
                assert_eq!(
                    strip_hostepoch_token(&cmdline),
                    "console=hvc0 root=/dev/vda ro rootfstype=ext4 rootwait panic=-1 loglevel=8 init=/init mvm.chain_init=/sbin/mvm-host-vm-init"
                );
            }
            BuilderVmImage::RootDir { .. } => panic!("expected rootfs builder image"),
        }
    }

    #[test]
    fn ensure_builder_vm_image_auto_bootstraps_missing_cache_via_helper() {
        use std::os::unix::fs::PermissionsExt;

        let _env_lock = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut env = TestEnv::new();
        let scratch = TempDir::new().unwrap();
        env.set("MVM_HOME", scratch.path());
        // `ensure_builder_vm_image` falls back to seeding from the *default*
        // cache, which is `$HOME/.mvm/cache` and deliberately ignores MVM_HOME.
        // Without isolating HOME too, a developer with a real builder image on
        // disk gets it copied in - cmdline.txt and all - so the refusal under
        // test never happens and this passes only on a machine that has never
        // built one. CI is such a machine; a contributor's laptop is not.
        env.set("HOME", scratch.path());

        let arch = host_arch_tag().to_string();
        let cache_root = scratch.path().join("cache");
        let script = scratch.path().join("bootstrap-builder-vm.sh");
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\nset -eu\narch_dir=\"$MVM_HOME/cache/builder-vm/{arch}\"\nmkdir -p \"$arch_dir\"\nprintf 'kernel' > \"$arch_dir/vmlinux\"\nprintf 'rootfs' > \"$arch_dir/rootfs.ext4\"\nprintf '%s\\n' 'console=hvc0 root=/dev/vda ro rootfstype=ext4 rootwait panic=-1 loglevel=8 init=/init mvm.chain_init=/sbin/mvm-host-vm-init' > \"$arch_dir/cmdline.txt\"\nmanifest_tmp=\"$arch_dir/manifest.$$.json.tmp\"\ncat > \"$manifest_tmp\" <<'EOF'\n{{\"cache_contract_version\":4,\"runtime_overlay_ready\":true,\"vsock_egress_ready\":true}}\nEOF\nmv \"$manifest_tmp\" \"$arch_dir/manifest.json\"\n"
            ),
        )
        .unwrap();
        let mut perms = std::fs::metadata(&script).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&script, perms).unwrap();
        env.set(BUILDER_VM_BOOTSTRAP_BIN_ENV, &script);

        let arch_dir = cache_root.join("builder-vm").join(&arch);
        let expected_cmdline = "console=hvc0 root=/dev/vda ro rootfstype=ext4 rootwait panic=-1 loglevel=8 init=/init mvm.chain_init=/sbin/mvm-host-vm-init";

        // Backend-agnostic loader: the auto-bootstrap helper populates the
        // cache and the shared image load succeeds on every host, including
        // Linux/KVM (qemu/hvf boot the same image). The libkrun steady-state
        // guard is exercised separately on the libkrun boot path.
        let image = ensure_builder_vm_image().expect("auto-bootstrap should populate cache");
        match image {
            BuilderVmImage::Rootfs {
                kernel_path,
                rootfs_path,
                cmdline,
            } => {
                assert_eq!(kernel_path, arch_dir.join("vmlinux"));
                assert_eq!(rootfs_path, arch_dir.join("rootfs.ext4"));
                assert_eq!(strip_hostepoch_token(&cmdline), expected_cmdline);
            }
            BuilderVmImage::RootDir { .. } => panic!("expected rootfs builder image"),
        }
    }

    #[test]
    fn ensure_builder_vm_image_seeds_missing_cache_from_default_cache() {
        let _env_lock = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut env = TestEnv::new();
        let scratch = TempDir::new().unwrap();
        env.set("HOME", scratch.path());
        env.set("MVM_HOME", scratch.path().join("isolated-cache"));

        let arch = host_arch_tag().to_string();
        let source_arch_dir = crate::cache_install::default_cache_root()
            .join("builder-vm")
            .join(&arch);
        std::fs::create_dir_all(&source_arch_dir).unwrap();
        let kernel = source_arch_dir.join("vmlinux");
        let rootfs = source_arch_dir.join("rootfs.ext4");
        std::fs::write(&kernel, b"kernel").unwrap();
        std::fs::write(&rootfs, b"rootfs").unwrap();
        std::fs::write(
            source_arch_dir.join("cmdline.txt"),
            "console=hvc0 root=/dev/vda ro rootfstype=ext4 rootwait panic=-1 loglevel=8 init=/init mvm.chain_init=/sbin/mvm-host-vm-init\n",
        )
        .unwrap();
        std::fs::write(
            source_arch_dir.join("manifest.json"),
            r#"{"cache_contract_version":4,"runtime_overlay_ready":true,"vsock_egress_ready":true}"#,
        )
        .unwrap();

        let target_arch_dir = scratch
            .path()
            .join("isolated-cache")
            .join("cache")
            .join("builder-vm")
            .join(&arch);

        // Seeding from the default cache populates the isolated cache and the
        // shared loader returns the image on every host, Linux/KVM included.
        let image = ensure_builder_vm_image().expect("seed from default cache");
        assert_eq!(
            std::fs::read(target_arch_dir.join("manifest.json")).unwrap(),
            std::fs::read(source_arch_dir.join("manifest.json")).unwrap()
        );
        match image {
            BuilderVmImage::Rootfs {
                kernel_path,
                rootfs_path,
                ..
            } => {
                assert_eq!(kernel_path, target_arch_dir.join("vmlinux"));
                assert_eq!(rootfs_path, target_arch_dir.join("rootfs.ext4"));
            }
            BuilderVmImage::RootDir { .. } => panic!("expected rootfs builder image"),
        }
    }

    /// A shared-cache source dir as the real populators write it: the four
    /// artifacts plus the digest and provenance sidecars.
    fn write_shared_cache_source(source_arch_dir: &Path) {
        std::fs::create_dir_all(source_arch_dir).unwrap();
        std::fs::write(source_arch_dir.join("vmlinux"), b"kernel").unwrap();
        std::fs::write(source_arch_dir.join("rootfs.ext4"), b"rootfs").unwrap();
        std::fs::write(
            source_arch_dir.join("cmdline.txt"),
            "console=hvc0 root=/dev/vda ro rootfstype=ext4 rootwait panic=-1 loglevel=8 init=/init mvm.chain_init=/sbin/mvm-host-vm-init\n",
        )
        .unwrap();
        std::fs::write(
            source_arch_dir.join("manifest.json"),
            r#"{"cache_contract_version":4,"runtime_overlay_ready":true,"vsock_egress_ready":true}"#,
        )
        .unwrap();
        let sums = crate::cache_install::digest_manifest(
            source_arch_dir,
            crate::cache_install::BUILDER_VM_CACHE_ARTIFACTS,
        )
        .unwrap();
        std::fs::write(
            source_arch_dir.join(crate::cache_install::BUILDER_VM_ARTIFACT_DIGEST_FILE),
            sums,
        )
        .unwrap();
        std::fs::write(source_arch_dir.join(".mvm-provenance.json"), b"{}").unwrap();
        std::fs::write(source_arch_dir.join(".mvm-source.sha256"), b"fingerprint\n").unwrap();
    }

    #[test]
    fn seeding_carries_the_integrity_sidecars_into_the_isolated_cache() {
        let _env_lock = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut env = TestEnv::new();
        let scratch = TempDir::new().unwrap();
        env.set("HOME", scratch.path());
        env.set("MVM_HOME", scratch.path().join("isolated-cache"));

        let arch = host_arch_tag().to_string();
        write_shared_cache_source(
            &crate::cache_install::default_cache_root()
                .join("builder-vm")
                .join(&arch),
        );

        ensure_builder_vm_image().expect("seed from default cache");

        // Without these the seeded copy cannot be verified afterwards, and the
        // bootstrap readiness check reads it as incomplete and rebuilds over
        // the image the seed just copied.
        let target_arch_dir = scratch
            .path()
            .join("isolated-cache")
            .join("cache")
            .join("builder-vm")
            .join(&arch);
        for name in crate::cache_install::BUILDER_VM_CACHE_SIDECARS {
            assert!(
                target_arch_dir.join(name).is_file(),
                "seeded cache is missing {name}"
            );
        }
        assert!(matches!(
            crate::cache_install::verify_digest_manifest(
                &target_arch_dir,
                crate::cache_install::BUILDER_VM_ARTIFACT_DIGEST_FILE,
                crate::cache_install::BUILDER_VM_CACHE_ARTIFACTS,
            ),
            crate::cache_install::DigestManifestCheck::Match
        ));
    }

    #[test]
    fn seeding_declines_a_shared_cache_whose_digests_no_longer_match() {
        let _env_lock = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut env = TestEnv::new();
        let scratch = TempDir::new().unwrap();
        env.set("HOME", scratch.path());
        env.set("MVM_HOME", scratch.path().join("isolated-cache"));

        let arch = host_arch_tag().to_string();
        let source_arch_dir = crate::cache_install::default_cache_root()
            .join("builder-vm")
            .join(&arch);
        write_shared_cache_source(&source_arch_dir);
        // Same length, so only the digest can catch it.
        std::fs::write(source_arch_dir.join("rootfs.ext4"), b"r00tfs").unwrap();

        let err = ensure_builder_vm_image().expect_err("drifted shared cache must not seed");

        // Declined, not propagated: the caller falls through to a fresh local
        // build, so the surfaced error is the original cache miss rather than
        // a digest complaint.
        let target_arch_dir = scratch
            .path()
            .join("isolated-cache")
            .join("cache")
            .join("builder-vm")
            .join(&arch);
        assert!(
            !target_arch_dir.join("rootfs.ext4").exists(),
            "drifted bytes must not reach the isolated cache: {err}"
        );
    }

    #[test]
    fn ensure_builder_vm_image_skips_stale_default_cache_and_auto_bootstraps() {
        use std::os::unix::fs::PermissionsExt;

        let _env_lock = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut env = TestEnv::new();
        let scratch = TempDir::new().unwrap();
        env.set("HOME", scratch.path());
        env.set("MVM_HOME", scratch.path().join("isolated-cache"));

        let arch = host_arch_tag().to_string();
        let source_arch_dir = crate::cache_install::default_cache_root()
            .join("builder-vm")
            .join(&arch);
        std::fs::create_dir_all(&source_arch_dir).unwrap();
        std::fs::write(source_arch_dir.join("vmlinux"), b"kernel").unwrap();
        std::fs::write(source_arch_dir.join("rootfs.ext4"), b"rootfs").unwrap();
        std::fs::write(
            source_arch_dir.join("cmdline.txt"),
            "console=hvc0 root=/dev/vda ro rootfstype=ext4 init=/sbin/mvm-host-vm-init\n",
        )
        .unwrap();
        std::fs::write(
            source_arch_dir.join("manifest.json"),
            r#"{"cache_contract_version":2,"runtime_overlay_ready":true,"vsock_egress_ready":true}"#,
        )
        .unwrap();

        let script = scratch.path().join("bootstrap-builder-vm.sh");
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\nset -eu\narch_dir=\"$MVM_HOME/cache/builder-vm/{arch}\"\nmkdir -p \"$arch_dir\"\nprintf 'kernel-new' > \"$arch_dir/vmlinux\"\nprintf 'rootfs-new' > \"$arch_dir/rootfs.ext4\"\nprintf '%s\\n' 'console=hvc0 root=/dev/vda ro rootfstype=ext4 rootwait panic=-1 loglevel=8 init=/init mvm.chain_init=/sbin/mvm-host-vm-init' > \"$arch_dir/cmdline.txt\"\nmanifest_tmp=\"$arch_dir/manifest.$$.json.tmp\"\ncat > \"$manifest_tmp\" <<'EOF'\n{{\"cache_contract_version\":4,\"runtime_overlay_ready\":true,\"vsock_egress_ready\":true}}\nEOF\nmv \"$manifest_tmp\" \"$arch_dir/manifest.json\"\n"
            ),
        )
        .unwrap();
        let mut perms = std::fs::metadata(&script).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&script, perms).unwrap();
        env.set(BUILDER_VM_BOOTSTRAP_BIN_ENV, &script);

        let target_arch_dir = scratch
            .path()
            .join("isolated-cache")
            .join("cache")
            .join("builder-vm")
            .join(&arch);

        // Backend-agnostic loader: the stale default cache is skipped, the
        // helper repopulates the isolated cache, and the shared image load
        // succeeds on every host, Linux/KVM included — the libkrun steady-state
        // guard is enforced on the libkrun boot path, not here.
        let image = ensure_builder_vm_image().expect("stale default cache should fall through");
        assert_eq!(
            std::fs::read_to_string(target_arch_dir.join("manifest.json"))
                .unwrap()
                .trim(),
            "{\"cache_contract_version\":4,\"runtime_overlay_ready\":true,\"vsock_egress_ready\":true}"
        );
        match image {
            BuilderVmImage::Rootfs {
                kernel_path,
                rootfs_path,
                cmdline,
            } => {
                assert_eq!(kernel_path, target_arch_dir.join("vmlinux"));
                assert_eq!(rootfs_path, target_arch_dir.join("rootfs.ext4"));
                assert_eq!(
                    strip_hostepoch_token(&cmdline),
                    "console=hvc0 root=/dev/vda ro rootfstype=ext4 rootwait panic=-1 loglevel=8 init=/init mvm.chain_init=/sbin/mvm-host-vm-init"
                );
            }
            BuilderVmImage::RootDir { .. } => panic!("expected rootfs builder image"),
        }
    }

    #[test]
    fn builder_vm_bootstrap_helper_target_dir_is_dedicated() {
        let _env_lock = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut env = TestEnv::new();
        env.remove("CARGO_TARGET_DIR");

        let dir = builder_vm_bootstrap_helper_target_dir(Path::new("/workspace"));
        assert_eq!(
            dir,
            PathBuf::from("/workspace/target/mvm-builder-vm-bootstrap")
        );
    }

    #[test]
    fn builder_vm_bootstrap_helper_target_dir_honors_cargo_target_dir() {
        let _env_lock = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut env = TestEnv::new();
        env.set("CARGO_TARGET_DIR", "shared-target");

        let dir = builder_vm_bootstrap_helper_target_dir(Path::new("/workspace"));
        assert_eq!(
            dir,
            PathBuf::from("/workspace/shared-target/mvm-builder-vm-bootstrap")
        );
    }

    /// Restore the process-wide payload declaration on drop.
    ///
    /// It is a static, so a test that leaves it set makes the next test in the
    /// same process resolve *its* executable as a bootstrap helper.
    struct DeclaredPayload(bool);

    impl DeclaredPayload {
        fn set(carries: bool) -> Self {
            let previous = CURRENT_EXE_CARRIES_HOST_BINARIES.load(Ordering::Relaxed);
            declare_current_exe_carries_host_binaries(carries);
            Self(previous)
        }
    }

    impl Drop for DeclaredPayload {
        fn drop(&mut self) {
            declare_current_exe_carries_host_binaries(self.0);
        }
    }

    /// The point of the helper is to obtain a binary carrying the embedded
    /// Linux host binaries. When the running one already carries them, building
    /// a second `mvmctl` reproduces what is already loaded — minutes of
    /// compile, plus a silent dependency on the pinned cross-compile toolchain,
    /// for nothing.
    #[test]
    fn a_declared_payload_makes_this_binary_the_bootstrap_helper() {
        let _env_lock = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut env = TestEnv::new();
        env.remove(BUILDER_VM_BOOTSTRAP_BIN_ENV);
        let _declared = DeclaredPayload::set(true);

        let workspace_root =
            builder_vm_source_checkout_root().expect("tests run from a source checkout");
        let resolved =
            resolve_builder_vm_bootstrap_bin(&workspace_root).expect("current exe resolves");

        assert_eq!(resolved, std::env::current_exe().unwrap());
        // `maybe_reexec_builder_vm_helper` reads this to decide it is already
        // the helper and bootstraps in-process instead of forking.
        assert!(current_exe_matches(&resolved));
    }

    /// The default has to be the conservative one: a library embedder or a test
    /// binary that never declares anything must not be handed to `Command` as
    /// an `mvmctl`.
    #[test]
    fn an_undeclared_binary_is_not_offered_as_the_helper() {
        let _env_lock = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _declared = DeclaredPayload::set(false);

        assert!(current_exe_as_bootstrap_helper().is_none());
    }

    /// The explicit override outranks the running binary: someone who names a
    /// helper is telling us theirs is the one to use.
    #[test]
    fn an_explicit_helper_outranks_a_declared_payload() {
        let _env_lock = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut env = TestEnv::new();
        let scratch = TempDir::new().unwrap();
        let explicit = scratch.path().join("mvmctl");
        std::fs::write(&explicit, b"helper").unwrap();
        env.set(BUILDER_VM_BOOTSTRAP_BIN_ENV, &explicit);
        let _declared = DeclaredPayload::set(true);

        let workspace_root =
            builder_vm_source_checkout_root().expect("tests run from a source checkout");
        assert_eq!(
            resolve_builder_vm_bootstrap_bin(&workspace_root).unwrap(),
            explicit
        );
    }

    /// Every exit is named, because the one the reader reaches for depends on
    /// what they have: the toolchain, a rebuild of this binary, or someone
    /// else's helper.
    #[test]
    fn the_toolchain_refusal_names_every_way_past_it() {
        let message = bootstrap_helper_toolchain_refusal("zig 0.13.0 was not found.");

        assert!(message.contains("zig 0.13.0 was not found."), "{message}");
        assert!(message.contains("just toolchain-embed"), "{message}");
        assert!(message.contains("just embed"), "{message}");
        assert!(message.contains(BUILDER_VM_BOOTSTRAP_BIN_ENV), "{message}");
    }

    /// A bootstrap child that still finds a cold cache has to report it. The
    /// alternative is a fork bomb: each level spawns another child with nothing
    /// new to try.
    #[test]
    fn a_running_bootstrap_does_not_spawn_another_one() {
        let _env_lock = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut env = TestEnv::new();
        let scratch = TempDir::new().unwrap();
        env.isolate_mvm_home(scratch.path());
        env.set(BUILDER_VM_BOOTSTRAP_BIN_ENV, "/nonexistent/mvmctl");
        env.set(BUILDER_VM_BOOTSTRAP_ACTIVE_ENV, "1");

        let arch_dir = scratch
            .path()
            .join("cache")
            .join("builder-vm")
            .join(host_arch_tag());

        assert!(
            !auto_bootstrap_builder_vm_image(&arch_dir).expect("guard declines, it does not error")
        );
    }

    /// The child has to be *told* it is a bootstrap; the guard above is dead
    /// weight if the spawn site forgets to set the marker.
    #[test]
    fn the_spawned_bootstrap_is_marked_as_one() {
        use std::os::unix::fs::PermissionsExt;

        let _env_lock = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut env = TestEnv::new();
        let scratch = TempDir::new().unwrap();
        env.isolate_mvm_home(scratch.path());

        let observed = scratch.path().join("marker");
        let script = scratch.path().join("bootstrap-builder-vm.sh");
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\nprintf '%s' \"${{{}:-unset}}\" > {}\nexit 1\n",
                BUILDER_VM_BOOTSTRAP_ACTIVE_ENV,
                observed.display()
            ),
        )
        .unwrap();
        let mut perms = std::fs::metadata(&script).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&script, perms).unwrap();
        env.set(BUILDER_VM_BOOTSTRAP_BIN_ENV, &script);

        let arch_dir = scratch
            .path()
            .join("cache")
            .join("builder-vm")
            .join(host_arch_tag());
        // The helper exits nonzero on purpose — this test is about what it was
        // handed, not about it succeeding.
        assert!(auto_bootstrap_builder_vm_image(&arch_dir).is_err());
        assert_eq!(std::fs::read_to_string(&observed).unwrap(), "1");
    }

    #[test]
    fn bootstrap_helper_build_command_uses_isolated_target_dir() {
        let cmd = builder_vm_bootstrap_helper_build_command(
            std::ffi::OsStr::new("cargo"),
            Path::new("/workspace"),
            Path::new("/tmp/helper-target"),
        );

        let args = cmd
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert_eq!(
            args,
            vec![
                "build",
                "-q",
                "--bin",
                "mvmctl",
                "--features",
                "embed-host-bins"
            ]
        );

        let envs = cmd
            .get_envs()
            .map(|(key, value)| {
                (
                    key.to_string_lossy().into_owned(),
                    value.map(|v| v.to_string_lossy().into_owned()),
                )
            })
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(
            envs.get("CARGO_TARGET_DIR"),
            Some(&Some("/tmp/helper-target".to_string()))
        );
    }

    #[test]
    fn builder_vm_helper_commands_are_closed_and_preserve_force() {
        assert_eq!(
            BuilderVmHelperCommand::Bootstrap.args(),
            ["__builder-vm-bootstrap"]
        );
        assert_eq!(
            BuilderVmHelperCommand::SdkSidecarBuild { force: false }.args(),
            ["build", "sdk-sidecar", "build"]
        );
        assert_eq!(
            BuilderVmHelperCommand::SdkSidecarBuild { force: true }.args(),
            ["build", "sdk-sidecar", "build", "--force"]
        );
    }

    #[test]
    fn builder_vm_source_checkout_root_detects_workspace() {
        let root = builder_vm_source_checkout_root().expect("source checkout root");
        assert!(
            root.join("nix/images/builder-vm/flake.nix").is_file(),
            "workspace root must contain the builder-vm flake"
        );
    }

    #[test]
    fn resolve_builder_vm_bootstrap_bin_prefers_env_override() {
        let dir = TempDir::new().unwrap();
        let helper = dir.path().join("mvmctl-helper");
        std::fs::write(&helper, b"#!/bin/sh\n").unwrap();

        let _env_lock = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut env = TestEnv::new();
        env.set(
            BUILDER_VM_BOOTSTRAP_BIN_ENV,
            helper.display().to_string().as_str(),
        );

        let got = resolve_builder_vm_bootstrap_bin(dir.path()).expect("helper path");
        assert_eq!(got, helper);
    }

    #[test]
    fn resolve_builder_vm_bootstrap_bin_rejects_missing_env_override() {
        let dir = TempDir::new().unwrap();
        let missing = dir.path().join("missing-helper");

        let _env_lock = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut env = TestEnv::new();
        env.set(
            BUILDER_VM_BOOTSTRAP_BIN_ENV,
            missing.display().to_string().as_str(),
        );

        let err =
            resolve_builder_vm_bootstrap_bin(dir.path()).expect_err("missing helper must fail");
        assert!(err.to_string().contains("not a file"), "{err}");
        assert!(
            err.to_string().contains(BUILDER_VM_BOOTSTRAP_BIN_ENV),
            "{err}"
        );
    }

    #[test]
    fn bootstrap_helper_needs_rebuild_when_tracked_source_is_newer() {
        let workspace = TempDir::new().unwrap();
        let helper = workspace
            .path()
            .join("target/mvm-builder-vm-bootstrap/debug/mvmctl");
        let helper_parent = helper.parent().expect("helper parent");
        std::fs::create_dir_all(helper_parent).unwrap();
        std::fs::write(&helper, b"helper").unwrap();

        let cargo_toml = workspace.path().join("Cargo.toml");
        std::fs::write(&cargo_toml, "[workspace]\n").unwrap();
        let cargo_lock = workspace.path().join("Cargo.lock");
        std::fs::write(&cargo_lock, "# lock\n").unwrap();
        let build_toml = workspace.path().join("crates/mvm-build/Cargo.toml");
        std::fs::create_dir_all(build_toml.parent().expect("mvm-build manifest parent")).unwrap();
        std::fs::write(&build_toml, "[package]\nname = \"mvm-build\"\n").unwrap();
        let cli_toml = workspace.path().join("crates/mvm-cli/Cargo.toml");
        std::fs::create_dir_all(cli_toml.parent().expect("mvm-cli manifest parent")).unwrap();
        std::fs::write(&cli_toml, "[package]\nname = \"mvm-cli\"\n").unwrap();
        let build_src = workspace.path().join("crates/mvm-build/src/lib.rs");
        std::fs::create_dir_all(build_src.parent().expect("mvm-build src parent")).unwrap();
        std::fs::write(&build_src, "pub fn build() {}\n").unwrap();
        let cli_src = workspace.path().join("crates/mvm-cli/src/main.rs");
        std::fs::create_dir_all(cli_src.parent().expect("mvm-cli src parent")).unwrap();
        std::fs::write(&cli_src, "fn main() {}\n").unwrap();

        let older = std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(10);
        let newer = std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(20);
        set_mtime(&helper, older);
        set_mtime(&cargo_toml, older);
        set_mtime(&cargo_lock, older);
        set_mtime(&build_toml, older);
        set_mtime(&cli_toml, older);
        set_mtime(&build_src, older);
        set_mtime(&cli_src, newer);

        assert!(bootstrap_helper_needs_rebuild(&helper, workspace.path()));
    }

    #[test]
    fn bootstrap_helper_needs_rebuild_skips_fresh_helper() {
        let workspace = TempDir::new().unwrap();
        let helper = workspace
            .path()
            .join("target/mvm-builder-vm-bootstrap/debug/mvmctl");
        let helper_parent = helper.parent().expect("helper parent");
        std::fs::create_dir_all(helper_parent).unwrap();
        std::fs::write(&helper, b"helper").unwrap();

        let cargo_toml = workspace.path().join("Cargo.toml");
        std::fs::write(&cargo_toml, "[workspace]\n").unwrap();
        let cargo_lock = workspace.path().join("Cargo.lock");
        std::fs::write(&cargo_lock, "# lock\n").unwrap();
        let build_toml = workspace.path().join("crates/mvm-build/Cargo.toml");
        std::fs::create_dir_all(build_toml.parent().expect("mvm-build manifest parent")).unwrap();
        std::fs::write(&build_toml, "[package]\nname = \"mvm-build\"\n").unwrap();
        let cli_toml = workspace.path().join("crates/mvm-cli/Cargo.toml");
        std::fs::create_dir_all(cli_toml.parent().expect("mvm-cli manifest parent")).unwrap();
        std::fs::write(&cli_toml, "[package]\nname = \"mvm-cli\"\n").unwrap();
        let build_src = workspace.path().join("crates/mvm-build/src/lib.rs");
        std::fs::create_dir_all(build_src.parent().expect("mvm-build src parent")).unwrap();
        std::fs::write(&build_src, "pub fn build() {}\n").unwrap();
        let cli_src = workspace.path().join("crates/mvm-cli/src/main.rs");
        std::fs::create_dir_all(cli_src.parent().expect("mvm-cli src parent")).unwrap();
        std::fs::write(&cli_src, "fn main() {}\n").unwrap();

        let older = std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(10);
        let newer = std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(20);
        set_mtime(&cargo_toml, older);
        set_mtime(&cargo_lock, older);
        set_mtime(&build_toml, older);
        set_mtime(&cli_toml, older);
        set_mtime(&build_src, older);
        set_mtime(&cli_src, older);
        set_mtime(&helper, newer);

        assert!(!bootstrap_helper_needs_rebuild(&helper, workspace.path()));
    }

    #[test]
    fn current_exe_matches_current_binary() {
        let current = std::env::current_exe().expect("current exe");
        assert!(
            current_exe_matches(&current),
            "current executable should match itself"
        );
    }

    // `builder_vm_timeout_*` tests migrated to `builder_vm_runtime`
    // alongside the function.

    #[test]
    fn unique_job_id_includes_pid_and_timestamp() {
        let id = unique_job_id();
        let pid = std::process::id().to_string();
        assert!(id.ends_with(&pid), "id missing pid suffix: {id}");
        assert!(id.contains('-'), "id missing separator: {id}");
    }

    #[test]
    fn with_resources_overrides() {
        let vm = LibkrunBuilderVm::default().with_resources(2, 2048);
        assert_eq!(vm.vcpus, 2);
        assert_eq!(vm.memory_mib, 2048);
        assert_eq!(vm.nix_store_mib, 65536); // unchanged
    }

    #[test]
    fn with_nix_store_mib_overrides() {
        let vm = LibkrunBuilderVm::default().with_nix_store_mib(8192);
        assert_eq!(vm.nix_store_mib, 8192);
    }

    #[test]
    fn closure_nar_defaults_to_none_and_is_settable() {
        let vm = LibkrunBuilderVm::default();
        assert_eq!(vm.closure_nar, None);
        let vm = LibkrunBuilderVm::default().with_closure_nar(Some(PathBuf::from("/nar")));
        assert_eq!(vm.closure_nar, Some(PathBuf::from("/nar")));
    }

    #[test]
    fn closure_seed_share_is_none_when_no_closure_attached() {
        let vm_state_dir = tempfile::TempDir::new().unwrap();
        let vm = LibkrunBuilderVm::default();
        assert_eq!(
            vm.closure_seed_share(vm_state_dir.path()).unwrap(),
            None,
            "no closure_nar attached means no share directory is staged"
        );
        // No stray closure-seed dir left behind either.
        assert!(!vm_state_dir.path().join("closure-seed").exists());
    }

    #[test]
    fn closure_seed_share_stages_the_nar_when_attached() {
        let arch_dir = tempfile::TempDir::new().unwrap();
        let nar = arch_dir.path().join("nix-closure.nar");
        std::fs::write(&nar, b"closure-bytes").unwrap();
        let vm_state_dir = tempfile::TempDir::new().unwrap();

        let vm = LibkrunBuilderVm::default().with_closure_nar(Some(nar));
        let share_dir = vm
            .closure_seed_share(vm_state_dir.path())
            .unwrap()
            .expect("closure attached must stage a share dir");
        assert_eq!(share_dir, vm_state_dir.path().join(CLOSURE_SEED_TAG));
        assert_eq!(
            std::fs::read(share_dir.join("nix-closure.nar")).unwrap(),
            b"closure-bytes"
        );
    }

    // ---------------------------------------------------------------
    // kernel-panic detector.
    //
    // `find_panic_line_in` is a pure scanner — tested directly. The
    // `wait_with_panic_detector` integration tests spawn `sleep` as a
    // stand-in for the libkrun supervisor (writes nothing on its own
    // to the console log, exits cleanly when killed or after its
    // configured duration). Tests run on Unix only because `sleep`
    // and `Child::kill` semantics are POSIX-specific.
    // ---------------------------------------------------------------

    #[test]
    fn find_terminal_line_in_returns_none_when_no_banner() {
        let buf = b"some boot log\nanother line\nfinal line\n";
        assert_eq!(find_terminal_line_in(buf), None);
    }

    #[test]
    fn find_terminal_line_in_extracts_full_panic_line() {
        let buf = b"[ 0.05 ] EXT4-fs: mounted\n\
                    [ 0.08 ] Kernel panic - not syncing: Requested init /sbin/foo failed (error -2).\n\
                    [ 0.09 ] more output\n";
        let (kind, line) = find_terminal_line_in(buf).expect("must match");
        assert_eq!(kind, Terminal::Panic);
        assert!(line.contains("Kernel panic - not syncing"));
        assert!(line.contains("Requested init /sbin/foo failed"));
        assert!(!line.contains('\n'));
    }

    #[test]
    fn find_terminal_line_in_handles_buffer_with_no_trailing_newline() {
        // Watcher may read partial output where the line is at the end with no
        // `\n` yet; the scanner returns the buffered line so it fires immediately.
        let buf = b"[ 0.05 ] booting\n[ 0.08 ] Kernel panic - not syncing: detail";
        let (_, line) = find_terminal_line_in(buf).expect("must match");
        assert!(line.contains("Kernel panic - not syncing: detail"));
    }

    #[test]
    fn find_terminal_line_in_trims_trailing_carriage_return() {
        let buf = b"[ 0.08 ] Kernel panic - not syncing: oops\r\nnext line\n";
        let (_, line) = find_terminal_line_in(buf).expect("must match");
        assert!(!line.ends_with('\r'), "got {line:?}");
        assert!(line.ends_with(": oops"));
    }

    #[test]
    fn find_terminal_line_in_returns_match_at_start_of_buffer() {
        let buf = b"Kernel panic - not syncing: first thing\nsubsequent\n";
        let (kind, line) = find_terminal_line_in(buf).expect("must match");
        assert_eq!(kind, Terminal::Panic);
        assert_eq!(line, "Kernel panic - not syncing: first thing");
    }

    #[test]
    fn find_terminal_line_in_detects_guest_halt() {
        // The exact shape a Stage 0 build failure reaches: build fails, the
        // kernel can't power off, the guest halts. This must be detected so the
        // host fails fast instead of waiting to the wall-clock timeout.
        let buf = b"stage0-init: build failed: nix build exit 1\n\
                    [ 1.009 ] reboot: Power off not available: System halted instead\n";
        let (kind, line) = find_terminal_line_in(buf).expect("must match");
        assert_eq!(kind, Terminal::Halt);
        assert!(line.contains("System halted"));
    }

    #[test]
    fn find_terminal_line_in_prefers_panic_over_halt() {
        // A panic is the more specific kernel state; if both appear, report panic.
        let buf = b"Kernel panic - not syncing: oops\nSystem halted\n";
        let (kind, _) = find_terminal_line_in(buf).expect("must match");
        assert_eq!(kind, Terminal::Panic);
    }

    #[test]
    fn read_console_tail_returns_last_nonempty_lines() {
        let tmp = tempfile::tempdir().unwrap();
        let log = tmp.path().join("console.log");
        std::fs::write(&log, "a\n\nb\nc\n\nd\n").unwrap();
        let tail = read_console_tail(log.to_str().unwrap(), 2);
        assert_eq!(tail, "c\nd");
        // Missing file → empty, never panics.
        assert_eq!(read_console_tail("/nonexistent/console.log", 5), "");
    }

    /// `sh -c <script>` as an owned `Command`. `Command::args` returns
    /// `&mut Command` for chaining, but `run_logged` takes ownership, so
    /// callers build it in two steps.
    fn sh_command(script: &str) -> Command {
        let mut cmd = Command::new("sh");
        cmd.args(["-c", script]);
        cmd
    }

    #[test]
    fn run_logged_quiet_captures_combined_output_to_file_on_success() {
        let tmp = tempfile::tempdir().unwrap();
        // A nested path exercises parent-dir creation rather than an
        // already-existing tempdir.
        let log = tmp.path().join("nested").join("build.log");
        let cmd = sh_command("echo out-line; echo err-line 1>&2");
        run_logged(cmd, &log, false).unwrap();
        let body = std::fs::read_to_string(&log).unwrap();
        assert!(body.contains("out-line"), "stdout captured: {body}");
        assert!(body.contains("err-line"), "stderr captured: {body}");
    }

    #[test]
    fn run_logged_quiet_failure_returns_err_carrying_log_tail() {
        let tmp = tempfile::tempdir().unwrap();
        let log = tmp.path().join("build.log");
        let cmd = sh_command("echo boom-marker; exit 7");
        let err = run_logged(cmd, &log, false).unwrap_err();
        assert!(
            err.to_string().contains("boom-marker"),
            "error carries the log tail: {err}"
        );
    }

    #[test]
    fn run_logged_verbose_success_never_touches_the_log_file() {
        let tmp = tempfile::tempdir().unwrap();
        let log = tmp.path().join("build.log");
        let cmd = sh_command("exit 0");
        run_logged(cmd, &log, true).unwrap();
        assert!(
            !log.exists(),
            "verbose mode streams live and captures nothing"
        );
    }

    #[test]
    fn run_logged_spawn_failure_returns_libkrun_unavailable() {
        let tmp = tempfile::tempdir().unwrap();
        let log = tmp.path().join("build.log");
        let cmd = Command::new("/nonexistent/definitely-not-a-binary");
        let err = run_logged(cmd, &log, false).unwrap_err();
        assert!(
            matches!(err, BuilderVmError::LibkrunUnavailable(_)),
            "expected LibkrunUnavailable, got {err:?}"
        );
    }

    #[test]
    fn run_logged_quiet_empty_output_produces_empty_log_file() {
        let tmp = tempfile::tempdir().unwrap();
        let log = tmp.path().join("build.log");
        let cmd = sh_command("exit 0");
        run_logged(cmd, &log, false).unwrap();
        let body = std::fs::read_to_string(&log).unwrap();
        assert!(body.is_empty(), "log file should be empty: {body:?}");
    }

    #[test]
    fn stage0_guest_halt_completed_successfully_requires_done_marker_and_artifact() {
        let tmp = tempfile::tempdir().unwrap();
        let console = tmp.path().join("console.log");
        let out = tmp.path().join("out");
        std::fs::create_dir_all(&out).unwrap();

        std::fs::write(
            &console,
            "linux> buildPhase completed\nstage0-init: done; halting\n",
        )
        .unwrap();
        assert!(
            !stage0_guest_halt_completed_successfully(&console, &out),
            "without emitted artifacts a halt must still count as failure"
        );

        std::fs::write(out.join("vmlinux"), b"kernel").unwrap();
        assert!(
            stage0_guest_halt_completed_successfully(&console, &out),
            "the success marker plus a copied artifact proves the halt was intentional"
        );
    }

    #[test]
    fn stage0_console_halt_outcome_distinguishes_success_failure_and_silence() {
        // Clean build: the terminal success marker is present.
        assert_eq!(
            stage0_console_halt_outcome("nix log…\nstage0-init: done; halting\n"),
            Stage0HaltOutcome::CleanHalt
        );
        // Failed build: the guest powers off cleanly but reports the failure —
        // this must NOT read as success just because the VMM exited 0.
        assert_eq!(
            stage0_console_halt_outcome(
                "error: home directory \"/homeless-shelter\" exists\n\
                 stage0-init: build failed: nix build exit 1\n"
            ),
            Stage0HaltOutcome::BuildFailed
        );
        // Failure marker wins even if a stray success-looking line precedes it.
        assert_eq!(
            stage0_console_halt_outcome(
                "stage0-init: done; halting\nstage0-init: build failed: x\n"
            ),
            Stage0HaltOutcome::BuildFailed
        );
        // Panic / kill / truncation: no terminal marker at all.
        assert_eq!(
            stage0_console_halt_outcome("kernel panic - not syncing\n"),
            Stage0HaltOutcome::NoCleanHalt
        );
    }

    #[test]
    fn a_setup_refusal_is_reported_as_a_refusal_not_as_an_unclean_halt() {
        // This is the console shape of the guest-egress regression: the client
        // dies, stage0-init refuses before nix runs, and the guest powers off.
        // Read as NoCleanHalt it would say "did not reach a clean halt"; read
        // as BuildFailed it would blame a build that never started.
        let console = "stage0-init: forked mvm-egress-client pid=227\n\
             mvm-egress-client: failed to load guest signing key\n\
             stage0-init: FATAL: mvm-egress-client exited before binding the \
             local egress proxy at 127.0.0.1:1080 (exit code 1)\n\
             [    9.3] reboot: Power down\n";
        assert_eq!(
            stage0_console_halt_outcome(console),
            Stage0HaltOutcome::SetupFailed(
                "mvm-egress-client exited before binding the local egress proxy at \
                 127.0.0.1:1080 (exit code 1)"
                    .to_string()
            )
        );
    }

    #[test]
    fn a_setup_refusal_outranks_a_later_build_marker() {
        // The guest stops before the build, so a build marker in the same
        // console can only be stale output from an earlier run.
        assert_eq!(
            stage0_console_halt_outcome(
                "stage0-init: FATAL: no egress\nstage0-init: build failed: x\n"
            ),
            Stage0HaltOutcome::SetupFailed("no egress".to_string())
        );
    }

    #[test]
    fn stage0_run_result_surfaces_the_refusal_rather_than_the_nix_noise() {
        let err = stage0_run_result(
            "warning: unable to download 'https://github.com/NixOS/nixpkgs'\n\
             stage0-init: FATAL: mvm-egress-client exited before binding the local \
             egress proxy at 127.0.0.1:1080 (exit code 1)\n",
            "/tmp/mvm-stage0-test/console.log",
        )
        .expect_err("a setup refusal must fail the run");
        let msg = err.to_string();
        assert!(msg.contains("refused to start the build"), "{msg}");
        assert!(msg.contains("mvm-egress-client"), "{msg}");
        assert!(
            msg.contains("console log at /tmp/mvm-stage0-test/console.log"),
            "{msg}"
        );
    }

    #[test]
    fn stage0_run_result_build_failure_names_the_console_log_path() {
        // Drive the same path a real Stage 0 build failure takes: the guest
        // powered off cleanly but printed the build-failed marker, so the
        // caller must not read the clean exit as success — and the resulting
        // error must tell the operator exactly which console log to read.
        let err = stage0_run_result(
            "stage0-init: build failed: nix build exit 1\n",
            "/tmp/mvm-stage0-test/console.log",
        )
        .unwrap_err();
        assert!(
            matches!(err, BuilderVmError::NixBuildFailed(_)),
            "expected NixBuildFailed, got {err:?}"
        );
        assert!(
            err.to_string()
                .contains("console log at /tmp/mvm-stage0-test/console.log"),
            "error should name the console log path: {err}"
        );
    }

    #[test]
    fn stage0_run_result_no_clean_halt_names_the_console_log_path() {
        // No terminal marker at all (panic, kill, or truncated console) —
        // the caller still needs to be pointed at the right console log.
        let err = stage0_run_result(
            "kernel panic - not syncing\n",
            "/tmp/mvm-stage0-test/console.log",
        )
        .unwrap_err();
        assert!(
            matches!(err, BuilderVmError::ExtractionFailed(_)),
            "expected ExtractionFailed, got {err:?}"
        );
        assert!(
            err.to_string()
                .contains("console log at /tmp/mvm-stage0-test/console.log"),
            "error should name the console log path: {err}"
        );
    }

    #[test]
    fn stage0_guest_halt_completed_successfully_rejects_halts_without_done_marker() {
        let tmp = tempfile::tempdir().unwrap();
        let console = tmp.path().join("console.log");
        let out = tmp.path().join("out");
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(&console, "stage0-init: build failed: nix build exit 1\n").unwrap();
        std::fs::write(out.join("rootfs.ext4"), b"rootfs").unwrap();

        assert!(
            !stage0_guest_halt_completed_successfully(&console, &out),
            "artifact leftovers must not mask a real build failure"
        );
    }

    #[test]
    fn guest_halted_display_names_halt_line_and_console_path() {
        let err = BuilderVmError::GuestHalted {
            halt_line: "reboot: Power off not available: System halted instead".to_string(),
            console_log_path: "/tmp/mvm-builder/console.log".to_string(),
        };
        let rendered = err.to_string();
        assert!(
            rendered.contains("reboot: Power off not available: System halted instead"),
            "display should surface the halt line: {rendered}"
        );
        assert!(
            rendered.contains("/tmp/mvm-builder/console.log"),
            "display should name the console log path: {rendered}"
        );
    }

    #[test]
    fn post_wait_action_defers_clean_exit_to_the_on_disk_result() {
        assert!(matches!(
            post_wait_action(Ok(0)),
            PostWaitAction::FinalizeFromDisk { halted: false }
        ));
    }

    #[test]
    fn post_wait_action_defers_guest_halt_to_the_on_disk_result() {
        // The rootfs-backed builder kernel halts instead of powering off at job
        // end; that halt is the normal shutdown, so the on-disk result decides.
        let outcome = Err(BuilderVmError::GuestHalted {
            halt_line: "System halted instead".to_string(),
            console_log_path: "/tmp/console.log".to_string(),
        });
        assert!(matches!(
            post_wait_action(outcome),
            PostWaitAction::FinalizeFromDisk { halted: true }
        ));
    }

    #[test]
    fn post_wait_action_fails_on_nonzero_supervisor_exit() {
        assert!(matches!(
            post_wait_action(Ok(7)),
            PostWaitAction::FailSupervisorExit(7)
        ));
    }

    #[test]
    fn post_wait_action_propagates_vmm_level_errors() {
        // A kernel panic (or timeout) is not a clean shutdown — there is no
        // build result on disk, so it must propagate rather than defer.
        let outcome = Err(BuilderVmError::SeedKernelPanic {
            panic_line: "Kernel panic - not syncing: attempted to kill init".to_string(),
            console_log_path: "/tmp/console.log".to_string(),
        });
        assert!(matches!(
            post_wait_action(outcome),
            PostWaitAction::Propagate(BuilderVmError::SeedKernelPanic { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn wait_with_panic_detector_returns_clean_when_no_console_log() {
        // No console log → falls back to plain wait; clean exit code
        // is propagated as-is.
        let mut child = Command::new("sh")
            .args(["-c", "exit 7"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn sh");
        let outcome = wait_with_panic_detector(&mut child, None, Duration::from_millis(10), false)
            .expect("ok");
        match outcome {
            WaitOutcome::Clean(7) => {}
            other => panic!("expected Clean(7), got {other:?}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn wait_with_panic_detector_returns_clean_when_log_never_contains_banner() {
        let scratch = TempDir::new().unwrap();
        let console = scratch.path().join("console.log");
        // Write a few benign lines — the watcher sees them, finds no
        // banner, the child exits cleanly, outcome is Clean.
        std::fs::write(&console, b"[ 0.01 ] boot\n[ 0.02 ] hello\n").unwrap();
        let mut child = Command::new("sh")
            .args(["-c", "exit 0"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn sh");
        let outcome =
            wait_with_panic_detector(&mut child, Some(&console), Duration::from_millis(10), false)
                .expect("ok");
        match outcome {
            WaitOutcome::Clean(0) => {}
            other => panic!("expected Clean(0), got {other:?}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn wait_with_panic_detector_kills_child_when_banner_appears() {
        let scratch = TempDir::new().unwrap();
        let console = scratch.path().join("console.log");

        // Long-running child standing in for the wedged libkrun
        // supervisor. Without panic detection this would block the
        // wait for the full 30s; with detection we expect it to be
        // killed within ~poll_interval of the banner write.
        let mut child = Command::new("sh")
            .args(["-c", "sleep 30"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn sh");

        // Writer thread: after a short delay, drop the banner into
        // the console log. The watcher should pick it up on the next
        // poll and signal the main thread to kill the sleep.
        let console_writer = console.clone();
        let writer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            std::fs::write(
                &console_writer,
                b"[ 0.01 ] booting\n[ 0.08 ] Kernel panic - not syncing: test banner\n",
            )
            .expect("write console log fixture");
        });

        let start = std::time::Instant::now();
        let outcome =
            wait_with_panic_detector(&mut child, Some(&console), Duration::from_millis(10), false)
                .expect("ok");
        let elapsed = start.elapsed();
        writer.join().expect("writer thread join");

        match outcome {
            WaitOutcome::KernelPanic {
                panic_line,
                console_log_path,
            } => {
                assert!(
                    panic_line.contains("Kernel panic - not syncing: test banner"),
                    "panic_line: {panic_line:?}"
                );
                assert_eq!(console_log_path, console.display().to_string());
            }
            other => panic!("expected KernelPanic, got {other:?}"),
        }

        // The full sleep is 30s; detection-and-kill must complete in
        // a small fraction of that. 5s is generous slack for the
        // slowest plausible CI runner. A regression that loses the
        // kill (i.e. falls back to the wait blocking for 30s) blows
        // this assertion well before it would hang the suite.
        assert!(
            elapsed < Duration::from_secs(5),
            "panic detector did not kill the child promptly: {elapsed:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn wait_with_panic_detector_fails_fast_on_guest_halt() {
        // Regression for the host-hangs-on-build-failure bug: a Stage 0 build
        // failure halts the guest (no clean power-off), the supervisor's
        // start_enter never returns, and without halt detection the host would
        // block to the wall-clock timeout. We must kill + return GuestHalted.
        let scratch = TempDir::new().unwrap();
        let console = scratch.path().join("console.log");
        let mut child = Command::new("sh")
            .args(["-c", "sleep 30"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn sh");

        let console_writer = console.clone();
        let writer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            std::fs::write(
                &console_writer,
                b"stage0-init: build failed: nix build exit 1\n\
                  [ 1.009 ] reboot: Power off not available: System halted instead\n",
            )
            .expect("write console log fixture");
        });

        let start = std::time::Instant::now();
        let outcome =
            wait_with_panic_detector(&mut child, Some(&console), Duration::from_millis(10), false)
                .expect("ok");
        let elapsed = start.elapsed();
        writer.join().expect("writer thread join");

        match outcome {
            WaitOutcome::GuestHalted { halt_line, .. } => {
                assert!(
                    halt_line.contains("System halted"),
                    "halt_line: {halt_line:?}"
                );
            }
            other => panic!("expected GuestHalted, got {other:?}"),
        }
        assert!(
            elapsed < Duration::from_secs(5),
            "halt detector did not kill the child promptly: {elapsed:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn wait_with_panic_detector_handles_late_console_log_creation() {
        let scratch = TempDir::new().unwrap();
        let console = scratch.path().join("console.log");
        // No console.log on disk yet — the watcher must poll for it.
        let mut child = Command::new("sh")
            .args(["-c", "sleep 30"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn sh");

        let console_writer = console.clone();
        let writer = std::thread::spawn(move || {
            // Sleep past several poll cycles so the watcher exercises
            // its "file doesn't exist yet, retry" branch before the
            // write lands.
            std::thread::sleep(Duration::from_millis(200));
            std::fs::write(
                &console_writer,
                b"Kernel panic - not syncing: delayed banner\n",
            )
            .expect("write console log fixture");
        });

        let outcome =
            wait_with_panic_detector(&mut child, Some(&console), Duration::from_millis(10), false)
                .expect("ok");
        writer.join().unwrap();

        match outcome {
            WaitOutcome::KernelPanic { panic_line, .. } => {
                assert!(panic_line.contains("delayed banner"));
            }
            other => panic!("expected KernelPanic, got {other:?}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn seed_kernel_panic_error_display_mentions_panic_line_and_log_path() {
        // Pin the error's Display output so callers (Stage 0 audit
        // emit, user-facing UI) get a stable, parseable message
        // shape.
        let err = BuilderVmError::SeedKernelPanic {
            panic_line: "Kernel panic - not syncing: example".to_string(),
            console_log_path: "/tmp/example/console.log".to_string(),
        };
        let msg = format!("{err}");
        assert!(msg.contains("Stage 0 seed VM kernel-panicked"), "{msg}");
        assert!(msg.contains("Kernel panic - not syncing: example"), "{msg}");
        assert!(msg.contains("/tmp/example/console.log"), "{msg}");
    }

    // -----------------------------------------------------------
    // LibkrunPersistentHostVm
    // -----------------------------------------------------------

    #[test]
    fn dispatch_sock_marker_constant_is_filename_only() {
        // Must not contain `/`. The host joins it under <job_dir>;
        // a slash would break the path concatenation contract the
        // in-guest builder-init's marker probe assumes.
        assert!(!DISPATCH_SOCK_MARKER.contains('/'));
        assert!(!DISPATCH_SOCK_MARKER.is_empty());
        assert_eq!(DISPATCH_SOCK_MARKER, "dispatch.sock.marker");
    }

    #[test]
    fn persistent_builder_egress_log_is_scoped_to_vm_state() {
        let state_dir = Path::new("/tmp/mvm-builder-state");
        assert_eq!(
            state_dir.join(BUILDER_SUBST_STDERR_LOG_FILE),
            PathBuf::from("/tmp/mvm-builder-state/substitution.stderr.log")
        );
    }

    #[test]
    fn stage_persistent_job_dir_creates_marker_in_fresh_dir() {
        // Hermetic — no libkrun, no VM. Validates the host's
        // side of the marker-file convention.
        let scratch = TempDir::new().expect("tempdir");
        let job_dir = scratch.path().join("job-dir");
        stage_persistent_job_dir(&job_dir).expect("stage");
        let marker = job_dir.join(DISPATCH_SOCK_MARKER);
        assert!(
            marker.is_file(),
            "marker should exist at {}",
            marker.display()
        );
        assert!(
            !job_dir.join(DISPATCH_READY_MARKER).exists(),
            "ready marker is guest-owned and must not be staged by the host"
        );
        // Marker body is intentionally empty — its existence is
        // the signal. If the body grows non-empty in the future
        // the dispatch contract changes.
        let body = std::fs::read(&marker).expect("read marker");
        assert_eq!(body, b"");
    }

    #[test]
    fn stage_persistent_job_dir_is_idempotent() {
        // Re-staging into the same job dir must succeed (caller
        // may retry after a transient supervisor failure).
        let scratch = TempDir::new().expect("tempdir");
        let job_dir = scratch.path().join("job-dir");
        stage_persistent_job_dir(&job_dir).expect("stage 1");
        stage_persistent_job_dir(&job_dir).expect("stage 2");
        assert!(job_dir.join(DISPATCH_SOCK_MARKER).is_file());
    }

    #[test]
    fn persistent_vm_config_defaults_track_libkrun_builder_vm() {
        // Same vcpus / memory / nix-store defaults so users moving
        // from single-shot to persistent don't see surprise
        // resource shifts.
        let vm = LibkrunPersistentHostVm::new(std::env::temp_dir());
        assert_eq!(vm.vcpus, DEFAULT_VCPUS);
        assert_eq!(vm.memory_mib, DEFAULT_MEMORY_MIB);
        assert_eq!(vm.nix_store_mib, DEFAULT_NIX_STORE_MIB);
    }

    #[test]
    fn persistent_vm_with_setters_override_defaults() {
        let vm = LibkrunPersistentHostVm::new(std::env::temp_dir())
            .with_vcpus(2)
            .with_memory_mib(2048)
            .with_nix_store_mib(8192);
        assert_eq!(vm.vcpus, 2);
        assert_eq!(vm.memory_mib, 2048);
        assert_eq!(vm.nix_store_mib, 8192);
    }

    #[test]
    fn builder_runtime_overlay_cmdline_appends_overlay_tokens() {
        let cmdline =
            builder_runtime_overlay_cmdline("console=hvc0 root=/dev/vda", BUILDER_RUNTIME_DEVICE);
        assert!(cmdline.contains("rootwait"));
        assert!(cmdline.contains("panic=-1"));
        assert!(cmdline.contains("loglevel=8"));
        assert!(cmdline.contains("mvm.builder_transport=disk"));
        assert!(cmdline.contains("mvm.builder_input=/dev/vdc"));
        assert!(cmdline.contains("mvm.builder_output=/dev/vdd"));
        assert!(cmdline.contains("mvm.runtime_data=/dev/vde"));
        assert!(cmdline.contains(BUILDER_VSOCK_EGRESS_TOKEN));
        assert!(cmdline.starts_with("console=hvc0 root=/dev/vda"));
    }

    #[test]
    fn builder_runtime_overlay_attachment_uses_read_only_disk_for_rootfs_images() {
        let image = BuilderVmImage::new(
            PathBuf::from("/img/Image"),
            PathBuf::from("/img/rootfs.ext4"),
            "console=hvc0 root=/dev/vda".to_string(),
        );
        let overlay = Path::new("/cache/runtime-overlay.ext4");
        let attachment = builder_runtime_overlay_attachment(&image, Some(overlay))
            .expect("rootfs builder images attach the runtime overlay");
        assert_eq!(attachment.disk_path, overlay);
        assert!(attachment.read_only);
        assert!(attachment.cmdline.contains("rootwait"));
        assert!(attachment.cmdline.contains("panic=-1"));
        assert!(attachment.cmdline.contains("loglevel=8"));
        assert!(attachment.cmdline.contains("mvm.builder_transport=disk"));
        assert!(attachment.cmdline.contains("mvm.builder_input=/dev/vdc"));
        assert!(attachment.cmdline.contains("mvm.builder_output=/dev/vdd"));
        assert!(attachment.cmdline.contains("mvm.runtime_data=/dev/vde"));
    }

    #[test]
    fn builder_runtime_overlay_attachment_skips_rootdir_images() {
        let image = BuilderVmImage::new_root_dir(PathBuf::from("/rootdir"), "/init");
        assert!(
            builder_runtime_overlay_attachment(
                &image,
                Some(Path::new("/cache/runtime-overlay.ext4"))
            )
            .is_none()
        );
    }

    #[test]
    fn builder_virtiofs_runtime_overlay_uses_virtiofs_disk_layout() {
        let image = BuilderVmImage::new(
            PathBuf::from("/img/Image"),
            PathBuf::from("/img/rootfs.ext4"),
            "console=hvc0 root=/dev/vda".to_string(),
        );
        let overlay = Path::new("/cache/runtime-overlay.ext4");
        let attachment = builder_virtiofs_runtime_overlay_attachment(&image, Some(overlay))
            .expect("virtio-fs rootfs builders attach the runtime overlay");

        assert_eq!(attachment.disk_path, overlay);
        assert!(attachment.read_only);
        assert!(attachment.cmdline.contains("mvm.runtime_data=/dev/vdc"));
        assert!(!attachment.cmdline.contains("mvm.builder_transport=disk"));
        assert!(!attachment.cmdline.contains("mvm.builder_input="));
        assert!(!attachment.cmdline.contains("mvm.builder_output="));
    }

    #[test]
    fn builder_runtime_overlay_or_bail_fails_closed_for_lean_rootfs_when_unavailable() {
        let image = BuilderVmImage::new(
            PathBuf::from("/img/Image"),
            PathBuf::from("/img/rootfs.ext4"),
            "console=hvc0 root=/dev/vda".to_string(),
        );
        let err = builder_runtime_overlay_or_bail_with(&image, || {
            Err(anyhow::anyhow!("cache miss and no source checkout"))
        })
        .expect_err("a lean Rootfs builder must fail closed when the overlay is unavailable");
        match err {
            BuilderVmError::RuntimeOverlayUnavailable(msg) => {
                assert!(msg.contains("cache miss and no source checkout"), "{msg}");
            }
            other => panic!("expected RuntimeOverlayUnavailable, got {other:?}"),
        }
    }

    #[test]
    fn builder_runtime_overlay_or_bail_threads_resolved_overlay_for_rootfs() {
        let image = BuilderVmImage::new(
            PathBuf::from("/img/Image"),
            PathBuf::from("/img/rootfs.ext4"),
            "console=hvc0 root=/dev/vda".to_string(),
        );
        let resolved = PathBuf::from("/cache/runtime-overlay.ext4");
        let out = builder_runtime_overlay_or_bail_with(&image, || Ok(resolved.clone()))
            .expect("resolved overlay threads through");
        assert_eq!(out.as_deref(), Some(resolved.as_path()));
    }

    #[test]
    fn builder_runtime_overlay_or_bail_skips_resolver_for_rootdir_stage0() {
        // Stage 0 (RootDir) boots libkrun's bundled kernel and bakes its own
        // entrypoint, so it must never even attempt overlay resolution.
        let image = BuilderVmImage::new_root_dir(PathBuf::from("/rootdir"), "/init");
        let out = builder_runtime_overlay_or_bail_with(&image, || {
            panic!("RootDir images must not resolve the runtime overlay")
        })
        .expect("RootDir images resolve to no overlay");
        assert!(out.is_none());
    }

    #[test]
    fn builder_runtime_overlay_guest_agent_only_enables_for_rootfs_overlay_path() {
        let rootfs = BuilderVmImage::new(
            PathBuf::from("/img/Image"),
            PathBuf::from("/img/rootfs.ext4"),
            "console=hvc0 root=/dev/vda".to_string(),
        );
        let rootdir = BuilderVmImage::new_root_dir(PathBuf::from("/rootdir"), "/init");
        let overlay = Some(Path::new("/cache/runtime-overlay.ext4"));

        assert!(builder_runtime_overlay_guest_agent_enabled(
            &rootfs, overlay,
        ));
        assert!(!builder_runtime_overlay_guest_agent_enabled(&rootfs, None));
        assert!(!builder_runtime_overlay_guest_agent_enabled(
            &rootdir, overlay,
        ));
    }

    #[test]
    fn persistent_vm_start_rejects_missing_workspace() {
        // ExtractionFailed is the typed error variant for "host
        // input doesn't satisfy the precondition". Caller will
        // surface it directly.
        let nonexistent = std::env::temp_dir().join(format!(
            "no-such-workspace-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let vm = LibkrunPersistentHostVm::new(&nonexistent);
        match vm.start() {
            Err(BuilderVmError::ExtractionFailed(msg)) => {
                assert!(msg.contains("workspace_root"), "msg: {msg}");
                assert!(msg.contains("not a directory"), "msg: {msg}");
            }
            // libkrun may not be installed in CI; that's a
            // different error variant and also acceptable.
            Err(BuilderVmError::LibkrunUnavailable(_)) => {}
            other => panic!("expected ExtractionFailed or LibkrunUnavailable, got {other:?}"),
        }
    }

    // ---------------------------------------------------------------
    // vsock response listener
    // ---------------------------------------------------------------
    //
    // Live in `crates/mvm-build/tests/vsock_response_listener.rs`
    // (not here) so the server-binding pattern they need to simulate
    // libkrun's host-side proxy doesn't trip the `architecture.yml`
    // invariant grep against `crates/` source. The grep excludes
    // `**/tests/**` by design — that's where mock-server patterns
    // for test scaffolding belong.

    // ---------------------------------------------------------------
    // LibkrunBuilderBackend impl
    //
    // Construction-shape tests only. Exercising `run_attached_with_mounts`
    // requires libkrun + the builder image + an actual supervisor
    // child, which is the integration-test surface; unit-level
    // assertions cover the trait wiring + the `console_log_path`
    // contract.
    // ---------------------------------------------------------------

    #[test]
    fn libkrun_builder_backend_with_supervisor_and_image_stores_paths() {
        let supervisor = PathBuf::from("/tmp/mvm-test-supervisor");
        let image = BuilderVmImage::Rootfs {
            kernel_path: PathBuf::from("/tmp/vmlinux"),
            rootfs_path: PathBuf::from("/tmp/rootfs.ext4"),
            cmdline: "console=hvc0".to_string(),
        };
        let backend = LibkrunBuilderBackend::with_supervisor_and_image(supervisor.clone(), image);
        assert_eq!(backend.supervisor_path, supervisor);
        match &backend.image {
            BuilderVmImage::Rootfs { kernel_path, .. } => {
                assert_eq!(kernel_path, &PathBuf::from("/tmp/vmlinux"));
            }
            other => panic!("expected Rootfs variant, got {other:?}"),
        }
    }

    #[test]
    fn libkrun_builder_backend_console_log_lives_under_vm_state_dir() {
        let backend = LibkrunBuilderBackend::with_supervisor_and_image(
            PathBuf::from("/tmp/supervisor"),
            BuilderVmImage::Rootfs {
                kernel_path: PathBuf::from("/tmp/k"),
                rootfs_path: PathBuf::from("/tmp/r"),
                cmdline: String::new(),
            },
        );
        let dir = PathBuf::from("/tmp/state/builder-foo");
        let log = backend.console_log_path(&dir);
        assert_eq!(log, dir.join("console.log"));
        // Trait-object safety: confirm the impl satisfies `&dyn ...`.
        let _erased: &dyn VmBackendForBuilder = &backend;
    }

    #[test]
    fn supervisor_logs_live_under_vm_state_dir() {
        let dir = PathBuf::from("/tmp/state/builder-foo");
        assert_eq!(
            supervisor_stdout_log_path(&dir),
            dir.join("supervisor.stdout.log")
        );
        assert_eq!(
            supervisor_stderr_log_path(&dir),
            dir.join("supervisor.stderr.log")
        );
    }

    #[test]
    fn supervisor_config_dump_is_persisted_under_vm_state_dir() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let config_path = supervisor_config_dump_path(tmp.path());
        persist_supervisor_config_dump(
            tmp.path(),
            r#"{"vm_state_dir":"/tmp/vm","krun":{"host_listen_ports":[5253]}}"#,
        )
        .expect("persist supervisor config");
        let contents =
            std::fs::read_to_string(&config_path).expect("read persisted supervisor config");
        assert_eq!(config_path, tmp.path().join("supervisor-config.json"));
        let value: serde_json::Value =
            serde_json::from_str(&contents).expect("persisted config stays valid json");
        assert_eq!(value["vm_state_dir"], "/tmp/vm");
        assert_eq!(value["krun"]["host_listen_ports"][0], 5253);
        assert!(
            contents.contains('\n'),
            "config dump should be pretty-printed for witness readability"
        );
    }

    #[test]
    fn echo_console_chunk_writes_only_when_verbose() {
        let mut sink: Vec<u8> = Vec::new();
        echo_console_chunk(&mut sink, false, b"hello");
        assert!(sink.is_empty(), "quiet mode must not echo");
        echo_console_chunk(&mut sink, true, b"hello");
        assert_eq!(sink, b"hello", "verbose mode echoes the chunk verbatim");
        echo_console_chunk(&mut sink, true, b"");
        assert_eq!(sink, b"hello", "empty chunk is a no-op");
    }

    #[test]
    fn libkrun_builder_vm_with_verbose_sets_flag() {
        let vm = LibkrunBuilderVm::default();
        assert!(!vm.verbose, "default is quiet");
        let vm = LibkrunBuilderVm::default().with_verbose(true);
        assert!(vm.verbose, "with_verbose(true) flips the flag");
    }

    #[test]
    fn builder_shell_krun_context_keeps_shell_jobs_nicless() {
        let temp = tempfile::tempdir().expect("tempdir");
        // The x86_64 builder path normalizes kernels through the Firecracker
        // loadability helper first, so the fixture must look like an ELF.
        let kernel_path = temp.path().join("vmlinux");
        let mut kernel_bytes = Vec::from(&b"\x7fELF"[..]);
        kernel_bytes.resize(host_page_size() as usize, 0);
        std::fs::write(&kernel_path, kernel_bytes).expect("write builder kernel");
        let image = BuilderVmImage::Rootfs {
            kernel_path,
            rootfs_path: temp.path().join("rootfs.ext4"),
            cmdline: String::new(),
        };
        let extra_disk = temp.path().join("extra.img");
        let krun = builder_shell_krun_context(&BuilderShellKrunContextParams {
            vm_name: "builder-shell",
            image: &image,
            vcpus: DEFAULT_VCPUS,
            memory_mib: DEFAULT_MEMORY_MIB,
            console_log: &temp.path().join("console.log"),
            vm_state_dir: temp.path(),
            nix_store_img: &temp.path().join("nix-store.img"),
            work_dir: temp.path(),
            artifact_out: temp.path(),
            job_dir: temp.path(),
            extra_disks: &[BuilderExtraDisk {
                id: "extra".to_string(),
                path: extra_disk,
                read_only: true,
            }],
        })
        .expect("shell context");

        assert!(
            matches!(krun.networking, libkrun_sys::NetworkingMode::VsockDirect),
            "shell jobs must stay on the direct-vsock-only path"
        );
    }

    #[test]
    fn choose_supervisor_prefers_env_then_next_to_exe_then_local_build_then_path() {
        let env = PathBuf::from("/env/mvm-libkrun-supervisor");
        let exe = PathBuf::from("/exe/mvm-libkrun-supervisor");
        let build = PathBuf::from("/ws/target/debug/mvm-libkrun-supervisor");
        let path = PathBuf::from("/usr/bin/mvm-libkrun-supervisor");

        // Env override wins over everything.
        assert_eq!(
            choose_supervisor(
                Some(env.clone()),
                Some(exe.clone()),
                Some(build.clone()),
                Some(path.clone())
            ),
            Some((env, SupervisorSource::EnvOverride))
        );
        // Next-to-exe (version-matched) wins over a sibling build and PATH.
        assert_eq!(
            choose_supervisor(
                None,
                Some(exe.clone()),
                Some(build.clone()),
                Some(path.clone())
            ),
            Some((exe, SupervisorSource::NextToExe))
        );
        // A fresh sibling-profile build beats a (stale) PATH copy — the trap fix.
        assert_eq!(
            choose_supervisor(None, None, Some(build.clone()), Some(path.clone())),
            Some((build, SupervisorSource::LocalBuild))
        );
        // PATH is the last resort — and is flagged as such so the caller can warn.
        assert_eq!(
            choose_supervisor(None, None, None, Some(path.clone())),
            Some((path, SupervisorSource::Path))
        );
        // Nothing found.
        assert_eq!(choose_supervisor(None, None, None, None), None);
    }

    /// A supervisor in a sibling cargo profile dir is discovered (newest wins),
    /// but only under a `target/<profile>/` layout — an installed-exe layout
    /// returns `None` so `$PATH` stays authoritative there.
    #[test]
    fn sibling_profile_supervisor_finds_newest_under_target_layout() {
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("target");
        let release = target.join("release");
        let debug = target.join("debug");
        std::fs::create_dir_all(&release).unwrap();
        std::fs::create_dir_all(&debug).unwrap();
        // The co-located (release) build is excluded; the sibling (debug) is found.
        std::fs::write(release.join("mvm-libkrun-supervisor"), b"co-located").unwrap();
        std::fs::write(debug.join("mvm-libkrun-supervisor"), b"sibling").unwrap();

        assert_eq!(
            sibling_profile_supervisor(&release),
            Some(debug.join("mvm-libkrun-supervisor")),
            "must find the sibling-profile build, not the co-located one"
        );

        // Not a `target/<profile>/` layout → no sibling probing.
        let installed = tmp.path().join("home/.cargo/bin");
        std::fs::create_dir_all(&installed).unwrap();
        assert_eq!(sibling_profile_supervisor(&installed), None);
    }

    #[test]
    fn supervisor_path_uses_supplied_target_dir() {
        let target = Path::new("/tmp/mvm-target");
        assert_eq!(
            supervisor_path_in_target_dir(target, "release"),
            Path::new("/tmp/mvm-target/release/mvm-libkrun-supervisor")
        );
    }

    #[test]
    fn cargo_target_dir_from_env_honors_absolute_and_relative_overrides() {
        let root = Path::new("/repo/mvm");

        assert_eq!(cargo_target_dir_from_env(root, None), root.join("target"));
        assert_eq!(
            cargo_target_dir_from_env(root, Some(OsString::from("/tmp/mvm-target"))),
            Path::new("/tmp/mvm-target")
        );
        assert_eq!(
            cargo_target_dir_from_env(root, Some(OsString::from("build/target"))),
            root.join("build/target")
        );
    }

    #[test]
    fn source_checkout_exe_target_dir_accepts_effective_cargo_target_dir() {
        let root = Path::new("/repo/mvm");
        let effective = Path::new("/tmp/mvm-target");
        let exe_dir = effective.join("release");
        let (target_dir, profile) =
            source_checkout_exe_target_dir_with_effective(&exe_dir, root, effective)
                .expect("effective target dir should be accepted");

        assert_eq!(target_dir, effective);
        assert_eq!(profile, "release");
        assert!(
            source_checkout_exe_target_dir_with_effective(
                Path::new("/usr/local/bin"),
                root,
                effective
            )
            .is_none(),
            "installed layouts must not be treated as source-checkout cargo target dirs"
        );
    }

    #[test]
    fn source_checkout_exe_target_dir_accepts_standalone_debug_release_layouts() {
        let root = Path::new("/repo/mvm");
        let effective = root.join("target");
        let exe_dir = Path::new("/tmp/mvm236-proof-target").join("debug");
        let (target_dir, profile) =
            source_checkout_exe_target_dir_with_effective(&exe_dir, root, &effective)
                .expect("standalone debug target dir should still be treated as cargo output");

        assert_eq!(target_dir, Path::new("/tmp/mvm236-proof-target"));
        assert_eq!(profile, "debug");
    }

    /// A sibling build outranks `$PATH` when it is missing/newer/equal, but a
    /// stale build must not shadow a freshly installed `$PATH` copy.
    #[test]
    fn supervisor_build_outranks_path_respects_freshness() {
        let tmp = tempfile::tempdir().unwrap();
        let build = tmp.path().join("build-supervisor");
        let path = tmp.path().join("path-supervisor");
        std::fs::write(&build, b"b").unwrap();

        // No `$PATH` copy → the local build always wins.
        assert!(supervisor_build_outranks_path(&build, None));

        // `$PATH` copy present but older than the build → build wins.
        std::fs::write(&path, b"p").unwrap();
        let older = std::time::SystemTime::UNIX_EPOCH;
        let newer = older + std::time::Duration::from_secs(100);
        set_mtime(&path, older);
        set_mtime(&build, newer);
        assert!(supervisor_build_outranks_path(&build, Some(&path)));

        // `$PATH` copy newer (fresh install) → build must not shadow it.
        set_mtime(&path, newer);
        set_mtime(&build, older);
        assert!(!supervisor_build_outranks_path(&build, Some(&path)));
    }

    #[test]
    fn supervisor_needs_rebuild_when_source_input_is_newer() {
        let tmp = tempfile::tempdir().unwrap();
        let helper = tmp.path().join("mvm-libkrun-supervisor");
        let input_dir = tmp.path().join("crates").join("deps").join("libkrun-sys");
        std::fs::create_dir_all(&input_dir).unwrap();
        let input = input_dir.join("lib.rs");
        std::fs::write(&helper, b"old-helper").unwrap();
        std::fs::write(&input, b"enum NetworkingMode {}").unwrap();

        let older = std::time::SystemTime::UNIX_EPOCH;
        let newer = older + std::time::Duration::from_secs(100);
        set_mtime(&helper, older);
        set_mtime(&input, newer);
        assert!(
            supervisor_needs_rebuild(&helper, std::slice::from_ref(&input)).unwrap(),
            "newer libkrun-sys input must force a supervisor rebuild"
        );

        set_mtime(&helper, newer);
        set_mtime(&input, older);
        assert!(
            !supervisor_needs_rebuild(&helper, &[input]).unwrap(),
            "fresh helper should be reused"
        );
    }

    #[test]
    fn source_checkout_supervisor_build_uses_target_root_before_path() {
        let _env_lock = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut env = TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        let target_root = tmp.path().join("target-root");
        let debug_dir = target_root.join("debug");
        std::fs::create_dir_all(&debug_dir).unwrap();
        let local = debug_dir.join("mvm-libkrun-supervisor");
        std::fs::write(&local, b"local").unwrap();

        let path_dir = tmp.path().join("path");
        std::fs::create_dir_all(&path_dir).unwrap();
        let installed = path_dir.join("mvm-libkrun-supervisor");
        std::fs::write(&installed, b"installed").unwrap();

        let older = std::time::SystemTime::UNIX_EPOCH;
        let newer = std::time::SystemTime::now() + std::time::Duration::from_secs(3600);
        set_mtime(&installed, older);
        set_mtime(&local, newer);

        env.set("CARGO_TARGET_DIR", &target_root);

        let chosen = source_checkout_supervisor_build(Some(installed.as_path()));
        let chosen = chosen
            .expect("fresh target-root supervisor must outrank installed PATH copy")
            .canonicalize()
            .unwrap();
        let expected = local.canonicalize().unwrap();
        assert_eq!(chosen, expected);
    }

    #[test]
    #[ignore = "live: needs a working libkrun builder VM image and host libkrun runtime"]
    fn live_libkrun_builder_runtime_overlay_is_read_only() {
        assert!(
            libkrun_sys::is_available(),
            "libkrun runtime must be installed on the host"
        );
        let _env_lock = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut env = TestEnv::new();
        let bootstrap_cache = if std::env::var_os("MVM_HOME").is_some() {
            None
        } else {
            Some(tempfile::tempdir().expect("bootstrap cache tempdir"))
        };
        if let Some(cache) = &bootstrap_cache {
            env.isolate_mvm_home(cache.path());
        }

        let workspace_root =
            builder_vm_source_checkout_root().expect("source checkout must contain workspace root");
        let bootstrap_helper = resolve_builder_vm_bootstrap_bin(&workspace_root)
            .expect("builder VM bootstrap helper must build from source checkout");
        env.set(BUILDER_VM_BOOTSTRAP_BIN_ENV, &bootstrap_helper);

        let image = ensure_builder_vm_image()
            .expect("builder VM image must resolve from the configured cache");
        assert!(
            matches!(image, BuilderVmImage::Rootfs { .. }),
            "live proof needs the steady-state rootfs-backed builder image"
        );

        let tmp = tempfile::tempdir().expect("tempdir");
        let work_dir = tmp.path().join("work");
        let artifact_out = tmp.path().join("out");
        std::fs::create_dir_all(&work_dir).expect("create work_dir");

        let job = BuilderShellJob {
            work_dir,
            artifact_out: artifact_out.clone(),
            script: r#"
set -eu
awk '$2=="/mvm/runtime"{print; found=1} END{exit(found?0:1)}' /proc/mounts > /out/runtime-mount.txt
cat /proc/cmdline > /out/proc-cmdline.txt
if ! grep -q ' /mvm/runtime .* ro[, ]' /out/runtime-mount.txt; then
  echo "runtime overlay mount is not read-only" >&2
  echo "/proc/cmdline: $(cat /proc/cmdline)" >&2
  cat /out/runtime-mount.txt >&2
  exit 1
fi
if touch /mvm/runtime/probe-write 2>/out/runtime-touch.err; then
  echo "runtime overlay unexpectedly writable" >&2
  echo "/proc/cmdline: $(cat /proc/cmdline)" >&2
  exit 1
fi
"#
            .to_string(),
            extra_disks: Vec::new(),
        };

        let result = LibkrunBuilderVm::default()
            .run_shell_script(&job)
            .expect("builder shell job must succeed");
        let mount_line = std::fs::read_to_string(artifact_out.join("runtime-mount.txt"))
            .expect("read runtime-mount.txt");
        let touch_err = std::fs::read_to_string(artifact_out.join("runtime-touch.err"))
            .expect("read runtime-touch.err");
        assert!(
            mount_line.contains("/mvm/runtime"),
            "proof artifact must contain the runtime mount line: {mount_line}"
        );
        assert!(
            mount_line.contains(" ro,") || mount_line.ends_with(" ro"),
            "runtime overlay mount must be read-only: {mount_line}"
        );
        assert!(
            touch_err.contains("Read-only file system"),
            "write attempt must fail with EROFS: {touch_err}"
        );
        assert!(
            result.vm_state_dir.join("console.log").exists(),
            "live proof must leave a console log for diagnosis"
        );
    }

    fn set_mtime(path: &Path, when: std::time::SystemTime) {
        let f = std::fs::File::options().write(true).open(path).unwrap();
        f.set_modified(when).unwrap();
    }

    #[test]
    fn describe_vsock_response_outcome_reports_missing_response() {
        let (tx, rx) = std::sync::mpsc::channel();
        drop(tx);
        let summary = describe_vsock_response_outcome(rx, None);
        assert!(summary.contains("no response within 5s of supervisor exit"));
    }

    #[test]
    fn describe_vsock_response_outcome_reports_result_frame() {
        let (tx, rx) = std::sync::mpsc::channel();
        tx.send(crate::builder_protocol::HostVmResponseRead::Frame(
            crate::builder_protocol::HostVmResponse::Result {
                job_id: crate::builder_protocol::JobId::default(),
                exit_code: 7,
                stderr_tail: String::new(),
                boot_timings: None,
                job_timings: crate::builder_protocol::JobTimings {
                    dispatch_ms: 1,
                    build_ms: 2,
                    teardown_ms: 3,
                },
            },
        ))
        .unwrap();
        let summary = describe_vsock_response_outcome(rx, Some(9));
        assert!(summary.contains("vsock_exit_code=7"));
        assert!(summary.contains("file_exit_code=9"));
        assert!(summary.contains("build_ms=2"));
    }

    /// The regression this exists for. `machine run` does not build the
    /// endpoint, so a copy from an older checkout is found first and used
    /// silently; the guest and host then speak different protocols and the
    /// only symptom is a frame-length field that decodes to ASCII.
    #[test]
    fn an_endpoint_older_than_the_running_exe_is_stale() {
        let dir = tempfile::tempdir().expect("tempdir");
        let old = dir.path().join("mvm-network-endpoint");
        std::fs::write(&old, b"pre-cutover").expect("write");
        // Backdate well past any plausible clock skew between the two files.
        let long_ago = std::time::SystemTime::now() - std::time::Duration::from_secs(7 * 86_400);
        std::fs::File::options()
            .write(true)
            .open(&old)
            .expect("open")
            .set_modified(long_ago)
            .expect("backdate");

        assert!(
            endpoint_predates_running_exe(&old),
            "an endpoint a week older than the running binary must read as stale"
        );
    }

    /// The companion, so the check cannot pass by calling everything stale:
    /// a binary newer than the running one is used as-is.
    #[test]
    fn an_endpoint_newer_than_the_running_exe_is_not_stale() {
        let dir = tempfile::tempdir().expect("tempdir");
        let fresh = dir.path().join("mvm-network-endpoint");
        std::fs::write(&fresh, b"current").expect("write");
        let soon = std::time::SystemTime::now() + std::time::Duration::from_secs(600);
        std::fs::File::options()
            .write(true)
            .open(&fresh)
            .expect("open")
            .set_modified(soon)
            .expect("postdate");

        assert!(
            !endpoint_predates_running_exe(&fresh),
            "an endpoint newer than the running binary must be used as-is"
        );
    }

    /// A path that cannot be stat'd has no usable time. Reading that as stale
    /// costs a rebuild; reading it as fresh costs a protocol mismatch nobody
    /// can diagnose, so it fails towards the rebuild.
    #[test]
    fn an_unstattable_endpoint_reads_as_stale() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert!(endpoint_predates_running_exe(&dir.path().join("absent")));
    }
}
