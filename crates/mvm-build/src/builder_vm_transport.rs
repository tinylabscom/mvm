//! VMM-neutral disk transport, runtime-overlay, and builder egress helpers.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use mvm_vmm::host::aux_bin::{CliSpawn, HostProcess};
use mvm_vmm::host::network_endpoint_spawn::{
    HandshakeContext, handshake_timeout, read_handshake_line,
};
use serde::Serialize;

use crate::builder_disk_transport::{
    INPUT_DISK_MIN_BYTES, InputTree, create_output_disk, pack_input_disk, read_output_disk,
};
use crate::builder_vm::{BuilderVmError, BuilderVmImage};

use crate::builder_egress_process::{
    builder_egress_endpoint_was_terminated, builder_egress_supervisor_command_for,
};
use crate::builder_host_binaries::{endpoint_in_host_binary_dir, endpoint_predates_running_exe};

fn terminate_and_reap(child: &mut Child) {
    if matches!(child.try_wait(), Ok(Some(_))) {
        return;
    }
    let _ = child.kill();
    let _ = child.wait();
}

struct PendingChild(Option<Child>);

impl PendingChild {
    fn new(child: Child) -> Self {
        Self(Some(child))
    }
    fn child_mut(&mut self) -> &mut Child {
        self.0
            .as_mut()
            .expect("a pending child remains owned until setup succeeds")
    }
    fn into_child(mut self) -> Child {
        self.0
            .take()
            .expect("a pending child can only be transferred once")
    }
}

impl Drop for PendingChild {
    fn drop(&mut self) {
        if let Some(child) = &mut self.0 {
            terminate_and_reap(child);
        }
    }
}

pub(crate) const BUILDER_INPUT_DEVICE: &str = "/dev/vdc";
pub(crate) const BUILDER_OUTPUT_DEVICE: &str = "/dev/vdd";
pub(crate) const BUILDER_RUNTIME_DEVICE: &str = "/dev/vde";
pub(crate) const BUILDER_VSOCK_EGRESS_TOKEN: &str = "mvm.vsock_egress=1";
const BUILDER_SUBST_PID_FILE: &str = "substitution.pid";
pub(crate) const BUILDER_SUBST_STDERR_LOG_FILE: &str = "substitution.stderr.log";
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
/// closed when it is unavailable. A [`BuilderVmImage::RootDir`] Stage 0 seed
/// sources no guest binaries from the overlay, so it legitimately returns
/// `None`.
pub fn builder_runtime_overlay_or_bail(
    image: &BuilderVmImage,
) -> Result<Option<PathBuf>, BuilderVmError> {
    builder_runtime_overlay_or_bail_with(image, require_runtime_overlay_ext4)
}

/// Injectable core of [`builder_runtime_overlay_or_bail`] — takes the resolver
/// as a closure so the image-gating and fail-closed mapping are unit-testable
/// without touching the on-disk cache or triggering a source-checkout rebuild.
pub fn builder_runtime_overlay_or_bail_with(
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

pub(crate) fn append_cmdline_token(base_cmdline: &str, token: &str) -> String {
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

pub(crate) fn builder_vsock_egress_cmdline(base_cmdline: &str) -> String {
    append_cmdline_token(base_cmdline, BUILDER_VSOCK_EGRESS_TOKEN)
}

pub(crate) fn builder_boot_contract_cmdline(base_cmdline: &str) -> String {
    let cmdline = append_cmdline_token(base_cmdline, "rootwait");
    let cmdline = append_cmdline_token(&cmdline, "panic=-1");
    append_cmdline_token(&cmdline, "loglevel=8")
}

pub(crate) fn builder_disk_transport_cmdline(base_cmdline: &str) -> String {
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

pub(crate) fn builder_runtime_overlay_cmdline(base_cmdline: &str, runtime_device: &str) -> String {
    let cmdline = builder_disk_transport_cmdline(base_cmdline);
    append_cmdline_token(&cmdline, &format!("mvm.runtime_data={runtime_device}"))
}

pub struct BuilderRuntimeOverlayAttachment<'a> {
    pub cmdline: String,
    pub disk_path: &'a Path,
    pub read_only: bool,
}

pub fn builder_runtime_overlay_guest_agent_enabled(
    image: &BuilderVmImage,
    runtime_overlay: Option<&Path>,
) -> bool {
    matches!(
        (image, runtime_overlay),
        (BuilderVmImage::Rootfs { .. }, Some(_))
    )
}

pub fn builder_uses_vsock_egress(image: &BuilderVmImage) -> bool {
    matches!(image, BuilderVmImage::Rootfs { .. })
}

/// The egress policy the builder's endpoint decides every builder job under:
/// flake fetches and dependency installs alike. Builder infrastructure only;
/// no workload launch path may use it.
pub fn builder_egress_policy() -> mvm_core::policy::network_policy::NetworkPolicy {
    mvm_core::policy::network_policy::NetworkPolicy::trusted_build_egress()
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BuilderEndpointTransport {
    Uds { path: PathBuf },
    Vsock { port: u32 },
}

#[derive(Debug)]
pub struct BuilderVsockEgressEndpoint {
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
    pub fn spawn(
        state_dir: &Path,
        identity: &mvm_vmm::host::network_endpoint_spawn::FlowMuxIdentitySpawnConfig,
    ) -> Result<Self, BuilderVmError> {
        let socket_dir = builder_vsock_socket_dir(state_dir)?;
        let transport_path = socket_dir.join(mvm_core::config::vsock_socket_filename(
            mvm_agentd::vsock::EGRESS_PORT,
        ));
        Self::spawn_on_transport(
            state_dir,
            BuilderEndpointTransport::Uds {
                path: transport_path,
            },
            identity,
        )
    }

    pub fn spawn_on_transport(
        state_dir: &Path,
        transport: BuilderEndpointTransport,
        identity: &mvm_vmm::host::network_endpoint_spawn::FlowMuxIdentitySpawnConfig,
    ) -> Result<Self, BuilderVmError> {
        // Refused before the endpoint is resolved, which may build it.
        let host = HostProcess::current();
        host.refuse_cli_spawn(CliSpawn::BuilderEgressSupervisor)?;
        let endpoint_path = resolve_network_endpoint_path()?;
        let config = serde_json::json!({
            "tenant_id": "builder",
            "secrets": [],
            "transport": transport,
            "redaction": mvm_core::policy::RedactionPolicy::default(),
            "network_policy": builder_egress_policy(),
            // One authenticated session, same as every other tier. The guest's
            // egress client speaks nothing else.
            "egress_mode": "flow_mux",
            "flowmux_identity": {
                "session_id": identity.session_id,
                "host_signing_key_base64": identity.host_signing_key_base64,
                "guest_verifying_key_base64": identity.guest_verifying_key_base64,
            },
        });

        let mut endpoint_command = builder_egress_supervisor_command_for(&host, &endpoint_path)?;
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
        let child = endpoint_command
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
        let mut child = PendingChild::new(child);

        child
            .child_mut()
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

        let stdout = child.child_mut().stdout.take().ok_or_else(|| {
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
            child.child_mut().id(),
            handshake_timeout(),
            &HandshakeContext {
                endpoint: &endpoint_path,
                stderr_log: Some(&stderr_log_path),
            },
        )
        .map_err(|e| BuilderVmError::ExtractionFailed(format!("{e:#}")))?;

        let pid_file = state_dir.join(BUILDER_SUBST_PID_FILE);
        std::fs::write(&pid_file, child.child_mut().id().to_string()).map_err(|e| {
            BuilderVmError::ExtractionFailed(format!("write {}: {e}", pid_file.display()))
        })?;

        let mut child = child.into_child();
        let child_pid = child.id();
        std::thread::spawn(move || match child.wait() {
            Ok(status) if builder_egress_endpoint_was_terminated(&status) => {
                tracing::debug!(
                    pid = child_pid,
                    %status,
                    "builder egress endpoint stopped during teardown"
                );
            }
            Ok(status) => eprintln!(
                "builder egress endpoint pid={} exited unexpectedly with status {}",
                child_pid, status
            ),
            Err(e) => eprintln!("builder egress endpoint pid={} wait failed: {e}", child_pid),
        });

        Ok(Self {
            state_dir: state_dir.to_path_buf(),
        })
    }

    pub(crate) fn reap(&self) {
        reap_builder_vsock_egress_endpoint(&self.state_dir);
    }
}

pub fn builder_vsock_socket_dir(state_dir: &Path) -> Result<PathBuf, BuilderVmError> {
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

    if let Some(candidate) = endpoint_in_host_binary_dir(&HostProcess::current()) {
        return Ok(candidate);
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
/// not care which builder backend populated it.
pub(crate) fn prepare_builder_transport_disks(
    vm_state_dir: &Path,
    input_trees: &[InputTree<'_>],
    closure_nar: Option<&Path>,
    output_size: u64,
) -> Result<(PathBuf, PathBuf), BuilderVmError> {
    let input_disk = vm_state_dir.join("input.img");
    let output_disk = vm_state_dir.join("output.img");
    pack_input_disk(input_trees, closure_nar, &input_disk, INPUT_DISK_MIN_BYTES).map_err(|e| {
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
