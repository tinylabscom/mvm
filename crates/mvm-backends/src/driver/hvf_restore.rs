//! Booting a fresh HVF VMM out of a saved machine state.
//!
//! The capture side already exists: a paused supervisor serializes guest RAM
//! plus its vCPU and deterministic device state into `snapshot.ram` /
//! `snapshot.frame`, and `HvfVmFullControl::save_memory` copies both out. This
//! module is the inverse — it takes a checkpoint that has already been
//! materialized into a state directory and starts a supervisor that maps that
//! RAM privately and restores the frame instead of loading a kernel.
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
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Instant;

use anyhow::{Context, Result, anyhow, bail};
use mvm_core::checkpoint::{
    DEVICE_ANCHORS_BLOB, DeviceAnchors, HVF_FRAME_BLOB, MEMORY_BLOB, ROOTFS_BLOB,
    ROOTFS_VERITY_BLOB, SUPERVISOR_CONFIG_BLOB,
};
use mvm_vmm::host::hvf_supervisor::{HvfDisk, HvfSupervisorConfig};

use crate::driver::hvf_process::{
    PID_FILE_NAME, PID_FILE_TIMEOUT, read_pid, resolve_supervisor_path_verified,
};

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
        console_data_sockets: Vec::new(),
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

/// The restore's supervisor launch, bounded by the CPU share the restored
/// child's plan was admitted under.
///
/// The same seam a cold HVF boot goes through, for the same reason: the HVF VMM
/// runs inside this supervisor process, so the supervisor is what has to be born
/// inside the scope. A restore that spawned unwrapped would come up perfectly
/// well and simply be unbounded, so nothing but reading the argv back catches a
/// regression — hence a function to read.
fn bounded_restore_command(supervisor: &Path, req: &HvfRestoreRequest<'_>) -> Command {
    mvm_core::cpu_scope::bind_cpu_grant(
        Command::new(supervisor),
        req.vm_name,
        req.state_dir,
        req.cpu_grant.as_ref(),
    )
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
    Ok(())
}

/// Start a supervisor that loads `req`'s materialized saved state instead of
/// booting a kernel, and wait for it to confirm the VM is live.
#[tracing::instrument(name = "hvf.restore", skip_all, fields(vm = %req.vm_name))]
pub fn restore_hvf_vm(req: &HvfRestoreRequest<'_>) -> Result<RestoredHvfVm> {
    if !req.state_dir.is_dir() {
        bail!(
            "HVF restore of '{}': state dir {} is missing",
            req.vm_name,
            req.state_dir.display()
        );
    }
    let parent = read_parent_config(req.state_dir)?;
    let anchors = read_anchors(req.state_dir)?;
    let cfg = hvf_child_restore_config(&parent, &anchors, req)?;

    prepare_child_state_dir(req, &cfg)?;

    let supervisor = resolve_supervisor_path_verified()?;
    let json = serde_json::to_string(&cfg).context("serializing HvfSupervisorConfig")?;
    let mut child = bounded_restore_command(&supervisor, req)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(mvm_vmm::host::console_capture::supervisor_stderr(
            req.state_dir,
        ))
        .spawn()
        .with_context(|| format!("spawning {}", supervisor.display()))?;
    child
        .stdin
        .take()
        .ok_or_else(|| anyhow!("supervisor stdin was not piped"))?
        .write_all(json.as_bytes())
        .context("piping HvfSupervisorConfig to the supervisor")?;

    let deadline = Instant::now() + PID_FILE_TIMEOUT;
    loop {
        if let Some(pid) = read_pid(&cfg.pid_file) {
            let pid = u32::try_from(pid).map_err(|_| {
                anyhow!("restored HVF VM '{}' published a negative pid", req.vm_name)
            })?;
            return Ok(RestoredHvfVm {
                pid,
                agent_socket: cfg
                    .agent_socket
                    .clone()
                    .expect("the restored config always binds an agent socket"),
            });
        }
        if let Some(status) = child.try_wait().context("polling the HVF supervisor")? {
            bail!(
                "HVF restore of '{}' exited before publishing its pid (status: {status}); see {}{}",
                req.vm_name,
                cfg.console_log.display(),
                mvm_vmm::host::console_capture::supervisor_stderr_detail(req.state_dir)
            );
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            bail!(
                "HVF restore of '{}' did not confirm within {PID_FILE_TIMEOUT:?}; see {}{}",
                req.vm_name,
                cfg.console_log.display(),
                mvm_vmm::host::console_capture::supervisor_stderr_detail(req.state_dir)
            );
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
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
        assert!(cfg.console_data_sockets.is_empty());
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

    /// A fake `systemctl --user show <unit> -p ControlGroup --value` plus the
    /// cgroup it names, so the read-back can be exercised off a Linux session.
    fn probe_over_a_scope_with_quota(
        scratch: &Path,
        quota: &str,
    ) -> mvm_core::cpu_scope::ScopeProbe {
        let cgroup_root = scratch.join("cgroup");
        std::fs::create_dir_all(cgroup_root.join("mvm-restored.scope")).unwrap();
        std::fs::write(
            cgroup_root.join("mvm-restored.scope").join("cpu.max"),
            quota,
        )
        .unwrap();
        let systemctl = scratch.join("systemctl");
        std::fs::write(&systemctl, "#!/bin/sh\necho /mvm-restored.scope\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&systemctl, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        mvm_core::cpu_scope::ScopeProbe::with_root_and_systemctl(cgroup_root, systemctl)
    }

    /// The whole point of the restore-side grant thread: the supervisor that
    /// runs the restored machine is born inside the scope. An unwrapped spawn
    /// restores the child perfectly well and is simply unbounded, so the argv is
    /// the only thing that distinguishes the two.
    #[test]
    fn a_restored_child_is_cpu_bounded_by_its_admitted_grant() {
        let scratch = tempfile::tempdir().expect("scratch");
        let mut env = mvm_core::util::test_env::TestEnv::new();
        mvm_core::cpu_scope::pretend_mechanism_present(&mut env, scratch.path())
            .expect("fake mechanism");
        let state = scratch.path().join("child-state");
        std::fs::create_dir_all(&state).unwrap();

        let cmd = bounded_restore_command(
            Path::new("/usr/bin/mvm-hvf-supervisor"),
            &HvfRestoreRequest {
                vm_name: "restored-child",
                state_dir: &state,
                cpu_grant: Some(mvm_contract::grants::CpuGrant::Share { millicores: 1500 }),
            },
        );

        let argv = mvm_core::cpu_scope::rendered_argv(&cmd);
        assert_eq!(argv[0], "systemd-run");
        assert!(argv.contains(&"CPUQuota=150%".to_string()), "{argv:?}");
        assert_eq!(argv.last().expect("payload"), "/usr/bin/mvm-hvf-supervisor");
    }

    /// A bound that cannot be read back afterwards is a bound a receipt has to
    /// call `Declared`. The spawn records the unit it was born into, which is
    /// what turns the quota into a reportable tier.
    #[test]
    fn a_restored_child_reports_its_enforced_tier() {
        let scratch = tempfile::tempdir().expect("scratch");
        let mut env = mvm_core::util::test_env::TestEnv::new();
        mvm_core::cpu_scope::pretend_mechanism_present(&mut env, scratch.path())
            .expect("fake mechanism");
        let state = scratch.path().join("child-state");
        std::fs::create_dir_all(&state).unwrap();

        let _ = bounded_restore_command(
            Path::new("/usr/bin/mvm-hvf-supervisor"),
            &HvfRestoreRequest {
                vm_name: "restored-child",
                state_dir: &state,
                cpu_grant: Some(mvm_contract::grants::CpuGrant::Share { millicores: 1500 }),
            },
        );

        // Rewrite the recorded name to the one the fake systemctl answers for:
        // the real name carries a per-boot suffix that cannot be reconstructed.
        let recorded = mvm_core::cpu_scope::read_scope_unit(&state)
            .expect("a bound restore records the scope it was born into");
        assert!(recorded.ends_with(".scope"), "{recorded}");
        std::fs::write(state.join("cpu-scope"), "mvm-restored.scope").unwrap();

        assert_eq!(
            probe_over_a_scope_with_quota(scratch.path(), "150000 100000\n").tier_for_vm(&state),
            mvm_contract::protocol::resource_controls::EnforcedTier::Cgroup2CpuMax
        );
    }

    /// The honest other half. A plan granting no share leaves the restore
    /// unwrapped, and the read-back says `Declared` rather than claiming a bound
    /// nobody asked for.
    #[test]
    fn a_restored_child_without_a_grant_runs_unbounded_and_says_so() {
        let scratch = tempfile::tempdir().expect("scratch");
        let mut env = mvm_core::util::test_env::TestEnv::new();
        mvm_core::cpu_scope::pretend_mechanism_present(&mut env, scratch.path())
            .expect("fake mechanism");
        let state = scratch.path().join("child-state");
        std::fs::create_dir_all(&state).unwrap();

        let cmd = bounded_restore_command(
            Path::new("/usr/bin/mvm-hvf-supervisor"),
            &HvfRestoreRequest {
                vm_name: "restored-child",
                state_dir: &state,
                cpu_grant: None,
            },
        );

        assert_eq!(
            mvm_core::cpu_scope::rendered_argv(&cmd),
            vec!["/usr/bin/mvm-hvf-supervisor".to_string()]
        );
        assert!(mvm_core::cpu_scope::read_scope_unit(&state).is_none());
        assert_eq!(
            mvm_core::cpu_scope::enforced_grants_for_vm(&state).cpu,
            mvm_contract::protocol::resource_controls::EnforcedTier::Declared
        );
    }

    #[test]
    fn restore_refuses_a_state_dir_that_was_never_materialized() {
        let tmp = tempfile::tempdir().unwrap();
        let missing = tmp.path().join("never-created");
        let error = restore_hvf_vm(&request("child", &missing)).unwrap_err();
        assert!(error.to_string().contains("state dir"), "got: {error}");
    }
}
