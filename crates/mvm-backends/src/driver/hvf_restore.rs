//! Booting a fresh HVF VMM out of a saved machine state.
//!
//! The capture side already exists: a paused supervisor serializes guest RAM
//! plus its vCPU and deterministic device state into `snapshot.ram` /
//! `snapshot.frame`, and `HvfVmFullControl::save_memory` copies both out. This
//! module is the inverse — it takes a checkpoint that has already been
//! materialized into a state directory and starts a supervisor that maps that
//! RAM privately and restores the frame instead of loading a kernel.
//!
//! The saved RAM and frame are never handed over by path. Each is cloned into a
//! private, unlinked file, verified against the digest the checkpoint's signed
//! record carries, and passed to the supervisor as an inherited descriptor —
//! see [`mvm_vmm::host::restore_image`]. The RAM is then mapped copy-on-write
//! rather than read, so a restore costs one digest pass over the saved RAM and
//! no copy of it.
//!
//! Two properties make the rewrite load-bearing rather than cosmetic:
//!
//! * **Every per-VM host path is re-derived from the child's own state dir.**
//!   A config that kept the parent's pid file, console log or agent socket
//!   would make two live VMMs fight over one identity.
//! * **No authority-bearing relay survives the rewrite.** The substitution
//!   endpoint, the host-services broker and the dev console sockets are
//!   dropped, so a restored guest comes up with no path off the box until a
//!   claim binds one. That is the same deny-all posture a workload boot gets
//!   when its plan admits no egress.

use std::io::Write;
use std::os::fd::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Instant;

use anyhow::{Context, Result, anyhow, bail};
use mvm_core::checkpoint::{
    ContentBlob, DEVICE_ANCHORS_BLOB, DeviceAnchors, HVF_FRAME_BLOB, MEMORY_BLOB, ROOTFS_BLOB,
    ROOTFS_VERITY_BLOB, SUPERVISOR_CONFIG_BLOB,
};
use mvm_vmm::host::hvf_supervisor::{HvfDisk, HvfRestoreFds, HvfSupervisorConfig};
use mvm_vmm::host::restore_image::{PrivateCopy, VerifiedRestoreFile, inherit_descriptors};

use crate::driver::hvf_process::{PID_FILE_NAME, read_pid, resolve_supervisor_path_verified};

/// A materialized HVF checkpoint about to be booted under a fresh identity.
///
/// `state_dir` must already hold the checkpoint's cloned content — the saved
/// memory image, the HVF frame, the launch config, the device anchors and the
/// child's own copies of every remappable device file.
pub struct HvfRestoreRequest<'a> {
    /// Fresh, registry-unique name the restored guest runs under.
    pub vm_name: &'a str,
    /// The child's state directory, already holding the materialized content.
    pub state_dir: &'a Path,
    /// The CPU share this restore was admitted under, applied to the supervisor
    /// the restored machine runs inside. `None` means the admitted plan granted
    /// none, which is unbounded — the same answer a cold boot gives.
    pub cpu_grant: Option<mvm_contract::grants::CpuGrant>,
    /// The checkpoint's content manifest, already bound to the signed audit
    /// chain. The saved RAM and frame are verified against it on the exact
    /// bytes the supervisor loads, which is why the checkpoint layer does not
    /// hash those two blobs itself.
    pub content: &'a [ContentBlob],
}

/// The blobs [`restore_hvf_vm`] verifies itself, on the bytes it loads.
pub const VERIFIED_ON_LOAD: &[&str] = &[MEMORY_BLOB, HVF_FRAME_BLOB];

/// The saved state a restore boots from, verified and private.
struct VerifiedSavedState {
    ram: VerifiedRestoreFile,
    frame: VerifiedRestoreFile,
}

impl VerifiedSavedState {
    fn prepare(cfg: &HvfSupervisorConfig, req: &HvfRestoreRequest<'_>) -> Result<Self> {
        let prepare = |path: &Option<PathBuf>, blob: &str| -> Result<VerifiedRestoreFile> {
            let path = path
                .as_deref()
                .ok_or_else(|| anyhow!("HVF restore config names no {blob}"))?;
            let expected = recorded_digest(req.content, blob)?;
            let verified = VerifiedRestoreFile::prepare(path, req.state_dir, expected)
                .with_context(|| format!("verifying saved machine state {blob}"))?;
            if verified.copy() == PrivateCopy::Copied {
                tracing::warn!(
                    vm = req.vm_name,
                    blob,
                    bytes = verified.len(),
                    "the state directory's filesystem cannot clone; the saved {blob} was copied \
                     byte for byte, which costs a full write of it on every restore"
                );
            }
            Ok(verified)
        };
        Ok(Self {
            ram: prepare(&cfg.restore_ram, MEMORY_BLOB)?,
            frame: prepare(&cfg.restore_frame, HVF_FRAME_BLOB)?,
        })
    }

    fn fds(&self) -> HvfRestoreFds {
        HvfRestoreFds {
            ram: self.ram.file().as_raw_fd(),
            frame: self.frame.file().as_raw_fd(),
        }
    }
}

/// The digest the checkpoint recorded for `blob`.
fn recorded_digest<'a>(content: &'a [ContentBlob], blob: &str) -> Result<&'a str> {
    content
        .iter()
        .find(|entry| entry.name == blob)
        .map(|entry| entry.sha256.as_str())
        .ok_or_else(|| anyhow!("checkpoint records no digest for {blob}; refusing to load it"))
}

/// The live supervisor a restore produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoredHvfVm {
    /// The supervisor process now owning the restored machine.
    pub pid: u32,
    /// Host→guest agent RPC socket the supervisor bound for this VM.
    pub agent_socket: PathBuf,
}

/// Read the parent launch config a vm_full checkpoint carried.
fn read_parent_config(state_dir: &Path) -> Result<HvfSupervisorConfig> {
    let path = state_dir.join(SUPERVISOR_CONFIG_BLOB);
    let raw = std::fs::read(&path)
        .with_context(|| format!("reading the captured HVF launch config {}", path.display()))?;
    serde_json::from_slice(&raw)
        .with_context(|| format!("parsing the captured HVF launch config {}", path.display()))
}

/// Read the absolute device paths the saved state embeds.
fn read_anchors(state_dir: &Path) -> Result<DeviceAnchors> {
    let path = state_dir.join(DEVICE_ANCHORS_BLOB);
    let raw = std::fs::read(&path)
        .with_context(|| format!("reading HVF restore device anchors {}", path.display()))?;
    serde_json::from_slice(&raw)
        .with_context(|| format!("parsing HVF restore device anchors {}", path.display()))
}

/// Point one captured disk at the child's own copy.
///
/// A restored guest resumes with its page cache and in-flight virtio descriptors
/// intact, so the bytes behind each device must be the ones the capture froze.
/// The two device files a checkpoint clones (rootfs and its verity sidecar) are
/// remapped to the child's copies; anything else is an immutable shared artifact
/// (the runtime overlay, its verity tree) that both parent and child read from
/// the same path. A disk the child can write is refused outright: the capture
/// never froze its backing bytes, so restoring against it would resume a guest
/// whose page cache disagrees with its disk.
fn remap_disk(disk: &HvfDisk, anchors: &DeviceAnchors, state_dir: &Path) -> Result<HvfDisk> {
    if !disk.read_only {
        bail!(
            "cannot restore an HVF checkpoint whose disk {} was writable: its \
             backing bytes are not part of the saved machine state",
            disk.path.display()
        );
    }
    let remapped = if disk.path == anchors.rootfs {
        state_dir.join(ROOTFS_BLOB)
    } else if anchors.rootfs_verity.as_deref() == Some(disk.path.as_path()) {
        state_dir.join(ROOTFS_VERITY_BLOB)
    } else {
        disk.path.clone()
    };
    if !remapped.is_file() {
        bail!(
            "HVF restore needs disk image {}, which is not on disk",
            remapped.display()
        );
    }
    Ok(HvfDisk {
        path: remapped,
        read_only: true,
        ephemeral: false,
    })
}

/// Rewrite a captured parent's launch config into one that boots `req.vm_name`
/// from its own materialized copies. See the module docs for the two invariants
/// this rewrite carries.
///
/// Public because the rewrite *is* the security boundary of an HVF restore: the
/// path re-homing and the relay drop are what keep a restored guest from
/// sharing its parent's identity or inheriting its egress. Conformance asserts
/// on this value directly rather than on a booted VM.
pub fn hvf_child_restore_config(
    parent: &HvfSupervisorConfig,
    anchors: &DeviceAnchors,
    req: &HvfRestoreRequest<'_>,
) -> Result<HvfSupervisorConfig> {
    if !parent.kernel.is_file() {
        bail!(
            "HVF restore needs the captured kernel {}, which is not on disk",
            parent.kernel.display()
        );
    }
    let restore_ram = req.state_dir.join(MEMORY_BLOB);
    let restore_frame = req.state_dir.join(HVF_FRAME_BLOB);
    for required in [&restore_ram, &restore_frame] {
        if !required.is_file() {
            bail!(
                "HVF restore needs saved machine state at {}, which is not on disk",
                required.display()
            );
        }
    }
    let disks = parent
        .disks
        .iter()
        .map(|disk| remap_disk(disk, anchors, req.state_dir))
        .collect::<Result<Vec<_>>>()?;

    Ok(HvfSupervisorConfig {
        // Same tier as the parent it forked from.
        trusted_builder_egress: parent.trusted_builder_egress,
        // Never inherited. The request names the *parent's* VM, state dir and
        // identity drive; a child adopting it would spawn a second endpoint
        // over the parent's socket and overwrite the identity drive of a VM
        // that is still running off it. A restored child is not a builder.
        builder_egress_endpoint: None,
        kernel: parent.kernel.clone(),
        cmdline: parent.cmdline.clone(),
        memory_mib: parent.memory_mib,
        // A restored child resumes the parent's saved vCPU state, so it must
        // come up with the parent's CPU topology. Booting a different count
        // against a snapshot taken under another one is not a smaller machine —
        // it is a mismatched one.
        vcpus: parent.vcpus,
        initramfs: parent.initramfs.clone(),
        disks,
        vsock: parent.vsock,
        console_log: req.state_dir.join("console.log"),
        pid_file: req.state_dir.join(PID_FILE_NAME),
        workload_exit: req.state_dir.join("workload.exit"),
        pause_state: Some(req.state_dir.join("pause.state")),
        snapshot_request: Some(req.state_dir.join("snapshot.request")),
        snapshot_ram: Some(req.state_dir.join("snapshot.ram")),
        snapshot_frame: Some(req.state_dir.join("snapshot.frame")),
        restore_ram: Some(restore_ram),
        restore_frame: Some(restore_frame),
        restore_fds: None,
        timeout_secs: parent.timeout_secs,
        // A restored child does not re-arm the wall-clock timer. Inheriting the
        // parent's plan would audit the child's kill against the parent's
        // identity — a wrong entry in the chain is worse than a missing one.
        // The child is still admission-bounded; this mirrors the host-side CPU
        // control, which a restore does not re-arm either.
        plan: None,
        audit_dir: None,
        signing_key_path: None,
        agent_socket: Some(mvm_core::config::vm_hvf_agent_socket_at(req.state_dir)),
        // Authority-bearing relays never survive a restore: the child reaches
        // the network, the broker and an interactive console only through
        // channels a claim binds for its own admitted plan.
        substitution_socket: None,
        egress_relay_socket: None,
        broker_socket: None,
        display_socket: None,
        // Observations use a fresh child-local endpoint, never the parent's
        // inherited listener and never an interactive console grant.
        console_data_sockets: vec![mvm_vmm::host::hvf_supervisor::HostDialSocket {
            guest_port: mvm_core::protocol::telemetry::TELEMETRY_PORT,
            host_socket: mvm_core::config::vm_hvf_vsock_port_socket_at(
                req.state_dir,
                mvm_core::protocol::telemetry::TELEMETRY_PORT,
            ),
        }],
        // A restored child is a workload fork, never the build engine.
        builder_control_sockets: Vec::new(),
        // A restored child is a workload fork; it owns no store image.
        exclusive_image_lock: None,
        // The live-handoff control socket is a privileged path onto a resident
        // parent. A restored child is not a standby factory and must never
        // serve it.
        handoff_socket: None,
        handoff_root: None,
        handoff_verify_key: None,
        cpu_millicores: parent.cpu_millicores,
        quota_record: parent.quota_record.clone(),
    })
}

/// The restore's supervisor launch, bounded by the restored guest's memory and
/// task ceilings and by the CPU share the child's plan was admitted under.
///
/// The same seam a cold HVF boot goes through, for the same reason: the HVF VMM
/// runs inside this supervisor process, so the supervisor is what has to be born
/// inside the scope. A restore that spawned unwrapped would come up perfectly
/// well and simply be unbounded, so nothing but reading the argv back catches a
/// regression — hence a function to read.
///
/// The guest's memory is the parent's: a restore maps the saved RAM back at the
/// size it was captured with.
///
/// `inherited` are the verified saved-state descriptors the supervisor maps.
/// They are marked for inheritance on the supervisor command itself, so a
/// scope launcher, which runs as its own command, would not pass them on. HVF
/// hosts have no scope mechanism, so this never wraps in practice; if it ever
/// did, the restore is refused here by name rather than left to fail inside
/// the supervisor on a descriptor that never arrived.
fn bounded_restore_command(
    supervisor: &Path,
    req: &HvfRestoreRequest<'_>,
    guest_memory_mib: u32,
    inherited: &[RawFd],
) -> Result<mvm_core::spawn_scope::BoundCommand> {
    let mut command = Command::new(supervisor);
    inherit_descriptors(&mut command, inherited.to_vec());
    let bound = mvm_core::spawn_scope::bind_spawn(
        command,
        req.vm_name,
        req.state_dir,
        &mvm_core::spawn_scope::SpawnBounds::for_guest_memory(guest_memory_mib)
            .with_cpu_grant(req.cpu_grant),
    );
    if !inherited.is_empty()
        && let Some(unit) = bound.unit()
    {
        bail!(
            "HVF restore of '{}': the spawn scope {unit} would not pass the verified saved \
             state to the supervisor; refusing to restore",
            req.vm_name
        );
    }
    Ok(bound)
}

/// Persist the child's own launch config, and clear the state the run this
/// directory last held left behind.
///
/// The config is written before spawning because a later capture of this VM
/// reads it back through `supervisor_config_path`, so a restored child is
/// itself checkpointable.
///
/// The sidecar clear matters here for a reason the fork paths do not have: a
/// same-identity restore lands back in the state directory the pre-checkpoint
/// run wrote into, so that run's captured exit code and usage record are
/// already sitting there. A restored run that is killed rather than reaching
/// its own teardown writes neither, and the exit report would read the
/// pre-checkpoint run's numbers and sign them as this run's measurement.
fn prepare_child_state_dir(req: &HvfRestoreRequest<'_>, cfg: &HvfSupervisorConfig) -> Result<()> {
    let config_path = req.state_dir.join("supervisor.json");
    std::fs::write(
        &config_path,
        serde_json::to_vec(cfg).context("serializing the restored HVF launch config")?,
    )
    .with_context(|| format!("writing {}", config_path.display()))?;
    mvm_core::run_sidecars::clear_prior_run(req.state_dir);
    let _ = std::fs::remove_file(req.state_dir.join("pause.state"));
    let _ = std::fs::remove_file(mvm_vmm::host::hvf_supervisor::restore_ready_path(
        req.state_dir,
    ));
    Ok(())
}

/// How long a restoring supervisor has, from spawn, to adopt, map, validate
/// and apply the saved state and release its vCPUs.
///
/// Longer than a cold boot's pid-file wait because more happens before the
/// signal: the frame is read and checked and every device and CPU is restored.
/// None of it scales with guest RAM — the RAM is mapped, not read.
pub const RESTORE_READY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// How a restore starts its supervisor.
///
/// A seam so the verify-before-spawn order and the readiness handshake are
/// testable without the real, codesigned supervisor binary.
pub(crate) trait SpawnSupervisor {
    /// Start the supervisor for `req`, inheriting `inherited`, with stdin
    /// piped for the config and stderr captured in the state directory.
    fn spawn(
        &self,
        req: &HvfRestoreRequest<'_>,
        cfg: &HvfSupervisorConfig,
        inherited: &[RawFd],
    ) -> Result<std::process::Child>;
}

/// The installed `mvm-hvf-supervisor`, resolved and contract-checked.
struct InstalledSupervisor;

impl SpawnSupervisor for InstalledSupervisor {
    fn spawn(
        &self,
        req: &HvfRestoreRequest<'_>,
        cfg: &HvfSupervisorConfig,
        inherited: &[RawFd],
    ) -> Result<std::process::Child> {
        let supervisor = resolve_supervisor_path_verified()?;
        bounded_restore_command(&supervisor, req, cfg.memory_mib, inherited)?
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(mvm_vmm::host::console_capture::supervisor_stderr(
                req.state_dir,
            ))
            .spawn()
            .with_context(|| format!("spawning {}", supervisor.display()))
    }
}

/// Start a supervisor that loads `req`'s materialized saved state instead of
/// booting a kernel, and wait until it reports the machine running.
#[tracing::instrument(name = "hvf.restore", skip_all, fields(vm = %req.vm_name))]
pub fn restore_hvf_vm(req: &HvfRestoreRequest<'_>) -> Result<RestoredHvfVm> {
    restore_hvf_vm_with(req, &InstalledSupervisor, RESTORE_READY_TIMEOUT)
}

fn restore_hvf_vm_with(
    req: &HvfRestoreRequest<'_>,
    spawner: &dyn SpawnSupervisor,
    ready_timeout: std::time::Duration,
) -> Result<RestoredHvfVm> {
    if !req.state_dir.is_dir() {
        bail!(
            "HVF restore of '{}': state dir {} is missing",
            req.vm_name,
            req.state_dir.display()
        );
    }
    let parent = read_parent_config(req.state_dir)?;
    let anchors = read_anchors(req.state_dir)?;
    let mut cfg = hvf_child_restore_config(&parent, &anchors, req)?;

    prepare_child_state_dir(req, &cfg)?;
    // Verification comes before anything that could map: the supervisor is
    // handed only descriptors of private copies that already matched the
    // checkpoint's recorded digests, and it refuses a restore named by path.
    let saved = VerifiedSavedState::prepare(&cfg, req)?;
    let fds = saved.fds();
    cfg.restore_fds = Some(fds);

    let json = serde_json::to_string(&cfg).context("serializing HvfSupervisorConfig")?;
    let mut child = spawner.spawn(req, &cfg, &[fds.ram, fds.frame])?;
    // The supervisor holds its own copies now; ours close here.
    drop(saved);
    let piped = child
        .stdin
        .take()
        .ok_or_else(|| anyhow!("supervisor stdin was not piped"))
        .and_then(|mut stdin| {
            stdin
                .write_all(json.as_bytes())
                .context("piping HvfSupervisorConfig to the supervisor")
        });
    if let Err(error) = piped {
        // A supervisor that died before reading its config says why on stderr.
        let _ = child.kill();
        let _ = child.wait();
        return Err(error.context(restore_failure(req, &cfg, "could not be configured")));
    }
    await_restored(&mut child, req, &cfg, ready_timeout)
}

/// Wait for the supervisor to announce the restored machine running.
///
/// The pid file alone is not enough: the supervisor publishes it before it
/// adopts, maps or validates anything, so a refusal of the saved state would
/// otherwise be reported as a successful restore of a VM that is already gone.
/// Readiness is the marker the supervisor writes only once the state is
/// applied; its exit before then is a failed restore, reported with its
/// stderr.
fn await_restored(
    child: &mut std::process::Child,
    req: &HvfRestoreRequest<'_>,
    cfg: &HvfSupervisorConfig,
    timeout: std::time::Duration,
) -> Result<RestoredHvfVm> {
    let marker = mvm_vmm::host::hvf_supervisor::restore_ready_path(req.state_dir);
    let deadline = Instant::now() + timeout;
    loop {
        if marker.is_file()
            && let Some(pid) = read_pid(&cfg.pid_file)
        {
            let pid = u32::try_from(pid).map_err(|_| {
                anyhow!("restored HVF VM '{}' published a negative pid", req.vm_name)
            })?;
            let agent_socket = cfg
                .agent_socket
                .clone()
                .ok_or_else(|| anyhow!("restored HVF VM '{}' has no agent socket", req.vm_name))?;
            return Ok(RestoredHvfVm { pid, agent_socket });
        }
        if let Some(status) = child.try_wait().context("polling the HVF supervisor")? {
            bail!(restore_failure(
                req,
                cfg,
                &format!("exited before the restored machine was running ({status})")
            ));
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            bail!(restore_failure(
                req,
                cfg,
                &format!("did not report the restored machine running within {timeout:?}")
            ));
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

/// A failed restore, with the supervisor's own account of why.
fn restore_failure(req: &HvfRestoreRequest<'_>, cfg: &HvfSupervisorConfig, what: &str) -> String {
    format!(
        "HVF restore of '{}': the supervisor {what}; see {}{}",
        req.vm_name,
        cfg.console_log.display(),
        mvm_vmm::host::console_capture::supervisor_stderr_detail(req.state_dir)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parent_config(state: &Path, disks: Vec<HvfDisk>) -> HvfSupervisorConfig {
        HvfSupervisorConfig {
            trusted_builder_egress: false,
            builder_egress_endpoint: None,
            kernel: state.join("Image"),
            cmdline: Some("console=ttyAMA0 root=/dev/vda ro".into()),
            memory_mib: 512,
            vcpus: 1,
            initramfs: None,
            disks,
            vsock: true,
            console_log: PathBuf::from("/parent/console.log"),
            pid_file: PathBuf::from("/parent/hvf.pid"),
            workload_exit: PathBuf::from("/parent/workload.exit"),
            pause_state: Some(PathBuf::from("/parent/pause.state")),
            snapshot_request: Some(PathBuf::from("/parent/snapshot.request")),
            snapshot_ram: Some(PathBuf::from("/parent/snapshot.ram")),
            snapshot_frame: Some(PathBuf::from("/parent/snapshot.frame")),
            restore_ram: None,
            restore_frame: None,
            restore_fds: None,
            display_socket: None,
            timeout_secs: 0,
            plan: None,
            audit_dir: None,
            signing_key_path: None,
            agent_socket: Some(PathBuf::from("/parent/hvf-agent.sock")),
            substitution_socket: Some(PathBuf::from("/parent/substitution.sock")),
            egress_relay_socket: Some(PathBuf::from("/parent/egress.sock")),
            broker_socket: Some(PathBuf::from("/parent/broker.sock")),
            builder_control_sockets: vec![],
            exclusive_image_lock: None,
            console_data_sockets: vec![mvm_vmm::host::hvf_supervisor::HostDialSocket {
                guest_port: 20001,
                host_socket: PathBuf::from("/parent/vsock/vsock-20001.sock"),
            }],
            handoff_socket: Some(PathBuf::from("/parent/hvf-handoff.sock")),
            handoff_root: Some(PathBuf::from("/parent/vms")),
            handoff_verify_key: Some("aa".repeat(32)),
            cpu_millicores: None,
            quota_record: None,
        }
    }

    /// Lay down everything a restore needs: kernel, saved state, and the child's
    /// own rootfs copy.
    fn materialized(dir: &Path) -> DeviceAnchors {
        std::fs::write(dir.join("Image"), b"kernel").unwrap();
        std::fs::write(dir.join(MEMORY_BLOB), b"ram").unwrap();
        std::fs::write(dir.join(HVF_FRAME_BLOB), b"frame").unwrap();
        std::fs::write(dir.join(ROOTFS_BLOB), b"child-rootfs").unwrap();
        DeviceAnchors {
            rootfs: PathBuf::from("/parent/rootfs.ext4"),
            rootfs_verity: None,
            config: None,
            secrets: None,
            vsock: PathBuf::from("/parent/hvf-agent.sock"),
        }
    }

    fn request<'a>(vm_name: &'a str, dir: &'a Path) -> HvfRestoreRequest<'a> {
        HvfRestoreRequest {
            vm_name,
            state_dir: dir,
            cpu_grant: None,
            content: &[],
        }
    }

    #[test]
    fn preparing_the_child_state_dir_drops_the_pre_checkpoint_runs_exit_and_usage() {
        // A same-identity restore lands back in the directory the
        // pre-checkpoint run wrote into, unlike a fork, which gets a child dir
        // of its own. Leaving that run's usage record here would let a restored
        // run that is killed before its own teardown sign the pre-checkpoint
        // run's CPU into its receipt as a measurement.
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        let anchors = materialized(dir);
        let parent = parent_config(
            dir,
            vec![HvfDisk {
                path: PathBuf::from("/parent/rootfs.ext4"),
                read_only: true,
                ephemeral: false,
            }],
        );
        let req = request("restored", dir);
        let cfg = hvf_child_restore_config(&parent, &anchors, &req).unwrap();

        std::fs::write(mvm_core::exit_capture::exit_file_path(dir), b"0\n").unwrap();
        mvm_core::usage_capture::write_captured(
            dir,
            &mvm_core::usage_capture::UsageCapture {
                cpu_ms: mvm_core::usage_capture::Metric::measured(
                    4210,
                    mvm_core::usage_capture::Mechanism::HvfSummedVcpuClock,
                ),
                ..mvm_core::usage_capture::UsageCapture::default()
            },
        )
        .unwrap();
        std::fs::write(dir.join("pause.state"), b"paused").unwrap();

        prepare_child_state_dir(&req, &cfg).unwrap();

        assert_eq!(
            mvm_core::usage_capture::read_captured(dir),
            mvm_core::usage_capture::UsageCapture::default(),
            "the pre-checkpoint run's usage must not survive the restore"
        );
        assert_eq!(mvm_core::exit_capture::read_captured(dir), None);
        assert!(!dir.join("pause.state").exists());
        // The half this function exists for is still done: a restored child is
        // itself checkpointable only if its own launch config is on disk.
        assert!(dir.join("supervisor.json").is_file());
    }

    #[test]
    fn a_restored_child_never_inherits_the_parents_egress_endpoint_request() {
        // The request names the *parent's* vm, state dir, socket and identity
        // drive. A child that inherited it would spawn a second endpoint over
        // the running parent's socket and rewrite the identity drive that
        // parent's guest is still authenticating against — so this is the same
        // family as the relay drop the module docs describe, not an
        // optimisation.
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        let anchors = materialized(dir);
        let mut parent = parent_config(dir, vec![]);
        parent.builder_egress_endpoint =
            Some(mvm_vmm::host::hvf_supervisor::BuilderEgressEndpoint {
                vm_name: "the-parent".into(),
                state_dir: dir.join("parent-state"),
                socket: dir.join("parent.sock"),
                identity_drive: dir.join("parent-identity.ext4"),
            });

        let cfg = hvf_child_restore_config(&parent, &anchors, &request("child", dir)).unwrap();

        assert!(
            cfg.builder_egress_endpoint.is_none(),
            "a restored child must not adopt its parent's endpoint request"
        );
    }

    #[test]
    fn child_config_rehomes_every_per_vm_path_onto_the_child_state_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        let anchors = materialized(dir);
        let parent = parent_config(
            dir,
            vec![HvfDisk {
                path: PathBuf::from("/parent/rootfs.ext4"),
                read_only: true,
                ephemeral: false,
            }],
        );

        let cfg = hvf_child_restore_config(&parent, &anchors, &request("child", dir)).unwrap();

        assert_eq!(cfg.pid_file, dir.join(PID_FILE_NAME));
        assert_eq!(cfg.console_log, dir.join("console.log"));
        assert_eq!(cfg.workload_exit, dir.join("workload.exit"));
        assert_eq!(cfg.pause_state, Some(dir.join("pause.state")));
        assert_eq!(cfg.snapshot_ram, Some(dir.join("snapshot.ram")));
        assert_eq!(
            cfg.agent_socket,
            Some(mvm_core::config::vm_hvf_agent_socket_at(dir))
        );
        // The parent's rootfs anchor resolves to the child's own clone.
        assert_eq!(cfg.disks[0].path, dir.join(ROOTFS_BLOB));
    }

    #[test]
    fn child_config_loads_saved_state_instead_of_booting_a_kernel() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        let anchors = materialized(dir);
        let parent = parent_config(dir, Vec::new());

        let cfg = hvf_child_restore_config(&parent, &anchors, &request("child", dir)).unwrap();

        assert_eq!(cfg.restore_ram, Some(dir.join(MEMORY_BLOB)));
        assert_eq!(cfg.restore_frame, Some(dir.join(HVF_FRAME_BLOB)));
        // The saved shape is authoritative: memory size and cmdline are inherited
        // verbatim, because the restored guest is already running against them.
        assert_eq!(cfg.memory_mib, 512);
        assert_eq!(cfg.cmdline, parent.cmdline);
    }

    #[test]
    fn child_config_drops_every_authority_bearing_relay() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        let anchors = materialized(dir);
        let parent = parent_config(dir, Vec::new());
        assert!(parent.egress_relay_socket.is_some(), "parent has egress");

        let cfg = hvf_child_restore_config(&parent, &anchors, &request("child", dir)).unwrap();

        assert_eq!(cfg.egress_relay_socket, None);
        assert_eq!(cfg.substitution_socket, None);
        assert_eq!(cfg.broker_socket, None);
        assert_eq!(
            cfg.console_data_sockets,
            vec![mvm_vmm::host::hvf_supervisor::HostDialSocket {
                guest_port: mvm_core::protocol::telemetry::TELEMETRY_PORT,
                host_socket: mvm_core::config::vm_hvf_vsock_port_socket_at(
                    dir,
                    mvm_core::protocol::telemetry::TELEMETRY_PORT,
                ),
            }]
        );
        assert_ne!(cfg.console_data_sockets, parent.console_data_sockets);
        assert_eq!(cfg.handoff_socket, None);
        assert_eq!(cfg.handoff_root, None);
        assert_eq!(cfg.handoff_verify_key, None);
    }

    #[test]
    fn child_config_remaps_a_verity_sidecar_to_the_child_copy() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        let mut anchors = materialized(dir);
        anchors.rootfs_verity = Some(PathBuf::from("/parent/rootfs.verity"));
        std::fs::write(dir.join(ROOTFS_VERITY_BLOB), b"verity").unwrap();
        let parent = parent_config(
            dir,
            vec![
                HvfDisk {
                    path: PathBuf::from("/parent/rootfs.ext4"),
                    read_only: true,
                    ephemeral: false,
                },
                HvfDisk {
                    path: PathBuf::from("/parent/rootfs.verity"),
                    read_only: true,
                    ephemeral: false,
                },
            ],
        );

        let cfg = hvf_child_restore_config(&parent, &anchors, &request("child", dir)).unwrap();

        assert_eq!(cfg.disks[0].path, dir.join(ROOTFS_BLOB));
        assert_eq!(cfg.disks[1].path, dir.join(ROOTFS_VERITY_BLOB));
    }

    #[test]
    fn child_config_refuses_a_writable_disk() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        let anchors = materialized(dir);
        let parent = parent_config(
            dir,
            vec![HvfDisk {
                path: PathBuf::from("/parent/rootfs.ext4"),
                read_only: false,
                ephemeral: true,
            }],
        );

        let error =
            hvf_child_restore_config(&parent, &anchors, &request("child", dir)).unwrap_err();
        assert!(
            error.to_string().contains("writable"),
            "expected the writable-disk refusal, got: {error}"
        );
    }

    #[test]
    fn child_config_refuses_missing_saved_state() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        let anchors = materialized(dir);
        std::fs::remove_file(dir.join(HVF_FRAME_BLOB)).unwrap();
        let parent = parent_config(dir, Vec::new());

        let error =
            hvf_child_restore_config(&parent, &anchors, &request("child", dir)).unwrap_err();
        assert!(
            error.to_string().contains(HVF_FRAME_BLOB),
            "the refusal must name the missing frame, got: {error}"
        );
    }

    #[test]
    fn child_config_refuses_a_missing_kernel() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        let anchors = materialized(dir);
        std::fs::remove_file(dir.join("Image")).unwrap();
        let parent = parent_config(dir, Vec::new());

        let error =
            hvf_child_restore_config(&parent, &anchors, &request("child", dir)).unwrap_err();
        assert!(
            error.to_string().contains("kernel"),
            "the refusal must name the kernel, got: {error}"
        );
    }

    /// A fake `systemctl --user show <unit> -p ControlGroup` plus the cgroup it
    /// names, so the read-back can be exercised off a Linux session.
    fn probe_over_a_scope_with_quota(
        scratch: &Path,
        quota: &str,
    ) -> mvm_core::spawn_scope::ScopeProbe {
        let cgroup_root = scratch.join("cgroup");
        std::fs::create_dir_all(cgroup_root.join("mvm-restored.scope")).unwrap();
        std::fs::write(
            cgroup_root.join("mvm-restored.scope").join("cpu.max"),
            quota,
        )
        .unwrap();
        let systemctl = scratch.join("systemctl");
        std::fs::write(
            &systemctl,
            "#!/bin/sh\necho ControlGroup=/mvm-restored.scope\n",
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&systemctl, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        mvm_core::spawn_scope::ScopeProbe::with_root_and_systemctl(cgroup_root, systemctl)
    }

    /// The whole point of the restore-side grant thread: the supervisor that
    /// runs the restored machine is born inside the scope. An unwrapped spawn
    /// restores the child perfectly well and is simply unbounded, so the argv is
    /// the only thing that distinguishes the two.
    #[test]
    fn an_hvf_restored_child_is_cpu_bounded_by_its_admitted_grant() {
        let scratch = tempfile::tempdir().expect("scratch");
        let mut env = mvm_core::util::test_env::TestEnv::new();
        mvm_core::spawn_scope::pretend_mechanism_present(&mut env, scratch.path())
            .expect("fake mechanism");
        let state = scratch.path().join("child-state");
        std::fs::create_dir_all(&state).unwrap();

        let cmd = bounded_restore_command(
            Path::new("/usr/bin/mvm-hvf-supervisor"),
            &HvfRestoreRequest {
                vm_name: "restored-child",
                state_dir: &state,
                cpu_grant: Some(mvm_contract::grants::CpuGrant::Share { millicores: 1500 }),
                content: &[],
            },
            1024,
            &[],
        )
        .expect("no descriptors to inherit");

        let argv = mvm_core::spawn_scope::rendered_argv(cmd.as_command());
        assert_eq!(
            Path::new(&argv[0])
                .file_name()
                .and_then(|name| name.to_str()),
            Some("systemd-run")
        );
        assert!(argv.contains(&"CPUQuota=150%".to_string()), "{argv:?}");
        assert!(
            argv.contains(&format!(
                "MemoryMax={}M",
                1024 + mvm_core::spawn_scope::VMM_MEMORY_OVERHEAD_MIB
            )),
            "the restored guest's saved RAM sizes its ceiling: {argv:?}"
        );
        assert_eq!(argv.last().expect("payload"), "/usr/bin/mvm-hvf-supervisor");
    }

    /// A bound that cannot be read back afterwards is a bound a receipt has to
    /// call `Declared`. The spawn records the unit it was born into, which is
    /// what turns the quota into a reportable tier.
    #[test]
    fn a_restored_child_reports_its_enforced_tier() {
        let scratch = tempfile::tempdir().expect("scratch");
        let mut env = mvm_core::util::test_env::TestEnv::new();
        mvm_core::spawn_scope::pretend_mechanism_present(&mut env, scratch.path())
            .expect("fake mechanism");
        let state = scratch.path().join("child-state");
        std::fs::create_dir_all(&state).unwrap();

        let _ = bounded_restore_command(
            Path::new("/usr/bin/mvm-hvf-supervisor"),
            &HvfRestoreRequest {
                vm_name: "restored-child",
                state_dir: &state,
                cpu_grant: Some(mvm_contract::grants::CpuGrant::Share { millicores: 1500 }),
                content: &[],
            },
            1024,
            &[],
        )
        .expect("no descriptors to inherit");

        // Rewrite the recorded name to the one the fake systemctl answers for:
        // the real name carries a per-boot suffix that cannot be reconstructed.
        let recorded = mvm_core::spawn_scope::read_scope_unit(&state)
            .expect("a bound restore records the scope it was born into");
        assert!(recorded.ends_with(".scope"), "{recorded}");
        std::fs::write(state.join("spawn-scope"), "mvm-restored.scope").unwrap();

        assert_eq!(
            probe_over_a_scope_with_quota(scratch.path(), "150000 100000\n")
                .readback_for_vm(&state)
                .cpu,
            mvm_contract::protocol::resource_controls::EnforcedTier::Cgroup2CpuMax
        );
    }

    /// The honest other half. A plan granting no share leaves the restore with
    /// no CPU quota, and on a host without the mechanism the read-back says
    /// `Declared` rather than claiming a bound nothing applied.
    #[test]
    fn a_restored_child_without_the_mechanism_runs_unbounded_and_says_so() {
        let scratch = tempfile::tempdir().expect("scratch");
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let empty_path = scratch.path().join("empty-path");
        std::fs::create_dir_all(&empty_path).unwrap();
        env.set("PATH", &empty_path);
        env.remove("XDG_RUNTIME_DIR");
        env.remove("DBUS_SESSION_BUS_ADDRESS");
        let state = scratch.path().join("child-state");
        std::fs::create_dir_all(&state).unwrap();

        let cmd = bounded_restore_command(
            Path::new("/usr/bin/mvm-hvf-supervisor"),
            &HvfRestoreRequest {
                vm_name: "restored-child",
                state_dir: &state,
                cpu_grant: None,
                content: &[],
            },
            1024,
            &[],
        )
        .expect("no descriptors to inherit");

        assert_eq!(
            mvm_core::spawn_scope::rendered_argv(cmd.as_command()),
            vec!["/usr/bin/mvm-hvf-supervisor".to_string()]
        );
        assert!(mvm_core::spawn_scope::read_scope_unit(&state).is_none());
        assert_eq!(
            mvm_core::spawn_scope::enforced_grants_for_vm(&state),
            mvm_contract::protocol::resource_controls::EnforcedGrants::all_declared()
        );
    }

    /// Verified saved state is inherited by the supervisor command itself, so
    /// a scope launcher wrapping it would drop the descriptors. That is
    /// refused by name before anything is spawned, and an unscoped launch runs
    /// the supervisor directly.
    #[test]
    fn inherited_saved_state_is_never_routed_through_a_scope_launcher() {
        let scratch = tempfile::tempdir().expect("scratch");
        let state = scratch.path().join("child-state");
        std::fs::create_dir_all(&state).unwrap();
        let req = HvfRestoreRequest {
            vm_name: "restored-child",
            state_dir: &state,
            cpu_grant: None,
            content: &[],
        };
        let supervisor = Path::new("/usr/bin/mvm-hvf-supervisor");

        {
            let mut env = mvm_core::util::test_env::TestEnv::new();
            mvm_core::spawn_scope::pretend_mechanism_present(&mut env, scratch.path())
                .expect("fake mechanism");
            let refused = bounded_restore_command(supervisor, &req, 1024, &[7, 8])
                .err()
                .expect("a scoped launch cannot carry the descriptors");
            assert!(
                refused
                    .to_string()
                    .contains("would not pass the verified saved state"),
                "{refused:#}"
            );
        }

        let mut env = mvm_core::util::test_env::TestEnv::new();
        let empty_path = scratch.path().join("empty-path");
        std::fs::create_dir_all(&empty_path).unwrap();
        env.set("PATH", &empty_path);
        env.remove("XDG_RUNTIME_DIR");
        env.remove("DBUS_SESSION_BUS_ADDRESS");
        let direct = bounded_restore_command(supervisor, &req, 1024, &[7, 8])
            .expect("an unscoped launch inherits the descriptors directly");
        assert_eq!(
            mvm_core::spawn_scope::rendered_argv(direct.as_command()),
            vec!["/usr/bin/mvm-hvf-supervisor".to_string()]
        );
    }

    /// A state dir a restore can reach verification in: the parent's launch
    /// config and anchors on disk beside the saved state `materialized` lays
    /// down.
    fn restorable(dir: &Path) {
        let anchors = materialized(dir);
        let parent = parent_config(
            dir,
            vec![HvfDisk {
                path: anchors.rootfs.clone(),
                read_only: true,
                ephemeral: false,
            }],
        );
        std::fs::write(
            dir.join(SUPERVISOR_CONFIG_BLOB),
            serde_json::to_vec(&parent).unwrap(),
        )
        .unwrap();
        std::fs::write(
            dir.join(DEVICE_ANCHORS_BLOB),
            serde_json::to_vec(&anchors).unwrap(),
        )
        .unwrap();
    }

    fn blob(name: &str, bytes: &[u8]) -> ContentBlob {
        ContentBlob {
            name: name.into(),
            sha256: mvm_core::crypto::image_verify::sha256_reader(bytes).unwrap(),
        }
    }

    /// A spawner that records every launch and starts `/bin/sh -c script` in
    /// place of the supervisor, with `PID_FILE` and `READY` naming the files
    /// the real one publishes.
    struct ScriptedSupervisor {
        script: &'static str,
        spawned: std::cell::Cell<usize>,
    }

    impl ScriptedSupervisor {
        fn new(script: &'static str) -> Self {
            Self {
                script,
                spawned: std::cell::Cell::new(0),
            }
        }
    }

    impl SpawnSupervisor for ScriptedSupervisor {
        fn spawn(
            &self,
            req: &HvfRestoreRequest<'_>,
            cfg: &HvfSupervisorConfig,
            inherited: &[RawFd],
        ) -> Result<std::process::Child> {
            self.spawned.set(self.spawned.get() + 1);
            assert_eq!(inherited.len(), 2, "RAM and frame are both handed over");
            let mut command = Command::new("/bin/sh");
            command
                .args(["-c", self.script])
                .env("PID_FILE", &cfg.pid_file)
                .env(
                    "READY",
                    mvm_vmm::host::hvf_supervisor::restore_ready_path(req.state_dir),
                )
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(mvm_vmm::host::console_capture::supervisor_stderr(
                    req.state_dir,
                ));
            Ok(command.spawn()?)
        }
    }

    /// The digests of the saved state `materialized` lays down.
    fn matching_content() -> Vec<ContentBlob> {
        vec![blob(MEMORY_BLOB, b"ram"), blob(HVF_FRAME_BLOB, b"frame")]
    }

    fn restore_request<'a>(dir: &'a Path, content: &'a [ContentBlob]) -> HvfRestoreRequest<'a> {
        HvfRestoreRequest {
            vm_name: "restored",
            state_dir: dir,
            cpu_grant: None,
            content,
        }
    }

    /// Saved state that does not match the digest the checkpoint recorded is
    /// refused before a supervisor is spawned, so there is never a moment in
    /// which unverified bytes are mapped as guest memory. The matching case is
    /// the control: the same fixture does reach the spawner.
    #[test]
    fn saved_state_is_verified_before_any_supervisor_is_spawned() {
        let cases: [(&str, Vec<ContentBlob>, &str); 3] = [
            (
                "ram",
                vec![blob(MEMORY_BLOB, b"other"), blob(HVF_FRAME_BLOB, b"frame")],
                "failed integrity",
            ),
            (
                "frame",
                vec![blob(MEMORY_BLOB, b"ram"), blob(HVF_FRAME_BLOB, b"other")],
                "failed integrity",
            ),
            (
                "unrecorded",
                vec![blob(HVF_FRAME_BLOB, b"frame")],
                "records no digest",
            ),
        ];
        for (case, content, expected) in cases {
            let tmp = tempfile::tempdir().unwrap();
            let dir = tmp.path();
            restorable(dir);
            let spawner = ScriptedSupervisor::new("exit 99");

            let error = restore_hvf_vm_with(
                &restore_request(dir, &content),
                &spawner,
                std::time::Duration::from_secs(5),
            )
            .expect_err("mismatched saved state must be refused");

            assert!(format!("{error:#}").contains(expected), "{case}: {error:#}");
            assert_eq!(
                spawner.spawned.get(),
                0,
                "{case}: no supervisor was spawned"
            );
            let leftovers: Vec<_> = std::fs::read_dir(dir)
                .unwrap()
                .filter_map(|entry| entry.ok())
                .filter(|entry| entry.file_name().to_string_lossy().starts_with(".restore-"))
                .collect();
            assert!(
                leftovers.is_empty(),
                "{case}: no private copy is left named"
            );
        }

        let tmp = tempfile::tempdir().unwrap();
        restorable(tmp.path());
        let spawner = ScriptedSupervisor::new("cat >/dev/null; exit 99");
        let content = matching_content();
        let _ = restore_hvf_vm_with(
            &restore_request(tmp.path(), &content),
            &spawner,
            std::time::Duration::from_secs(5),
        );
        assert_eq!(
            spawner.spawned.get(),
            1,
            "verified state reaches the spawner"
        );
    }

    /// The supervisor publishes its pid before it adopts, maps or validates
    /// the saved state, so a refusal after that point must still fail the
    /// restore — with the supervisor's own reason — instead of reporting a
    /// VM that is already gone.
    #[test]
    fn a_supervisor_refusal_after_its_pid_is_published_fails_the_restore() {
        let tmp = tempfile::tempdir().unwrap();
        restorable(tmp.path());
        let spawner = ScriptedSupervisor::new(
            "cat >/dev/null; echo $$ > \"$PID_FILE\"; \
             echo 'Error: inherited restore descriptor 7 is not an unlinked, read-only regular file' >&2; \
             exit 1",
        );
        let content = matching_content();

        let error = restore_hvf_vm_with(
            &restore_request(tmp.path(), &content),
            &spawner,
            std::time::Duration::from_secs(20),
        )
        .expect_err("a refused restore is not a running VM");

        let rendered = format!("{error:#}");
        assert!(
            rendered.contains("exited before the restored machine was running"),
            "{rendered}"
        );
        assert!(
            rendered.contains("not an unlinked, read-only regular file"),
            "the supervisor's reason is carried: {rendered}"
        );
    }

    /// A supervisor that never reports the machine running is killed at the
    /// deadline and the restore fails; a live pid is not enough.
    #[test]
    fn a_restore_that_never_reports_ready_times_out_and_is_killed() {
        let tmp = tempfile::tempdir().unwrap();
        restorable(tmp.path());
        let spawner =
            ScriptedSupervisor::new("cat >/dev/null; echo $$ > \"$PID_FILE\"; exec sleep 60");
        let content = matching_content();

        let error = restore_hvf_vm_with(
            &restore_request(tmp.path(), &content),
            &spawner,
            std::time::Duration::from_millis(500),
        )
        .expect_err("no readiness, no restore");
        assert!(
            format!("{error:#}").contains("did not report the restored machine running"),
            "{error:#}"
        );
        let pid = read_pid(&tmp.path().join(PID_FILE_NAME)).expect("the fake published a pid");
        // SAFETY: signal 0 only probes whether the pid exists.
        let alive = unsafe { libc::kill(pid, 0) } == 0;
        assert!(!alive, "the unresponsive supervisor was killed and reaped");
    }

    /// Readiness is the marker, published after the state is applied.
    #[test]
    fn a_restore_is_reported_once_the_supervisor_marks_it_running() {
        let tmp = tempfile::tempdir().unwrap();
        restorable(tmp.path());
        let spawner = ScriptedSupervisor::new(
            "cat >/dev/null; echo $$ > \"$PID_FILE\"; sleep 0.2; echo ready > \"$READY\"; exec sleep 60",
        );
        let content = matching_content();

        let restored = restore_hvf_vm_with(
            &restore_request(tmp.path(), &content),
            &spawner,
            std::time::Duration::from_secs(20),
        )
        .expect("a supervisor that reports ready is a restored VM");
        // SAFETY: terminating the fake supervisor this test started.
        unsafe { libc::kill(restored.pid as libc::pid_t, libc::SIGKILL) };
        assert!(restored.pid > 0);
    }

    #[test]
    fn restore_refuses_a_state_dir_that_was_never_materialized() {
        let tmp = tempfile::tempdir().unwrap();
        let missing = tmp.path().join("never-created");
        let error = restore_hvf_vm(&request("child", &missing)).unwrap_err();
        assert!(error.to_string().contains("state dir"), "got: {error}");
    }
}
