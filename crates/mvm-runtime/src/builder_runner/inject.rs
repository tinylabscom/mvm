//! Self-hosting rootfs bootstrap primitive: inject mvm host binaries into a
//! builder rootfs using ONLY the hvf VMM (no legacy builder).
//!
//! Boots `kernel + an inject initramfs + a writable copy of the base rootfs`; the
//! `mvm-rootfs-patcher` init (carried in the initramfs) mounts the rootfs
//! read-write, copies each payload binary to its manifest path, and powers off.
//! Reusable by both the CLI's builder-image resolver and the `hvf-rootfs-inject`
//! example.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};

use mvm_build::rootfs_inject::{InjectBinary, build_inject_initramfs};
use mvm_vmm::host::hvf_supervisor::{HvfDisk, HvfSupervisorConfig};

use mvm_backends::driver::hvf_process::resolve_supervisor_path;

/// A rootfs-injection request.
pub struct InjectRequest<'a> {
    /// arm64 boot `Image` (HVF-bootable) to run the patcher on.
    pub kernel: &'a Path,
    /// Read-only source rootfs (never modified).
    pub base_rootfs: &'a Path,
    /// Where the patched rootfs copy is written.
    pub out_rootfs: &'a Path,
    /// Scratch dir for the initramfs + console log (created if absent).
    pub work_dir: &'a Path,
    /// The `mvm-rootfs-patcher` static binary (the initramfs `/init`).
    pub patcher: &'a [u8],
    /// Binaries to inject at their rootfs install paths.
    pub binaries: &'a [InjectBinary<'a>],
}

/// Inject `req.binaries` into a copy of `req.base_rootfs`, producing
/// `req.out_rootfs`. Blocks until the patcher VM powers off.
pub fn inject_host_binaries(req: &InjectRequest<'_>) -> Result<()> {
    std::fs::create_dir_all(req.work_dir)
        .with_context(|| format!("create inject work dir {}", req.work_dir.display()))?;

    // A writable copy the patcher edits; the source is never touched.
    std::fs::copy(req.base_rootfs, req.out_rootfs).with_context(|| {
        format!(
            "copy base rootfs {} -> {}",
            req.base_rootfs.display(),
            req.out_rootfs.display()
        )
    })?;

    let initramfs = build_inject_initramfs(req.patcher, req.binaries);
    let initramfs_path = req.work_dir.join("inject-initramfs.cpio");
    std::fs::write(&initramfs_path, &initramfs)
        .with_context(|| format!("write initramfs {}", initramfs_path.display()))?;

    let console_log = req.work_dir.join("inject-console.log");
    let cfg = HvfSupervisorConfig {
        // Irrelevant here: this helper VM carries no egress relay at all.
        trusted_builder_egress: false,
        kernel: req.kernel.to_path_buf(),
        // Default cmdline runs the initramfs /init (the patcher); the default RAM
        // is plenty for a mount + copy.
        cmdline: None,
        memory_mib: 0,
        initramfs: Some(initramfs_path),
        disks: vec![HvfDisk {
            path: req.out_rootfs.to_path_buf(),
            read_only: false,
            ephemeral: false,
        }],
        virtiofs_root: None,
        virtiofs_shares: vec![],
        vsock: false,
        console_log: console_log.clone(),
        pid_file: req.work_dir.join("inject.pid"),
        workload_exit: req.work_dir.join("inject.exit"),
        pause_state: None,
        snapshot_request: None,
        snapshot_ram: None,
        snapshot_frame: None,
        restore_ram: None,
        restore_frame: None,
        timeout_secs: 120,
        // The builder VM boots from no admitted plan: no bound to enforce.
        plan: None,
        audit_dir: None,
        signing_key_path: None,
        agent_socket: None,
        substitution_socket: None,
        egress_relay_socket: None,
        // The rootfs-inject helper VM runs no workload, so no host-services broker.
        broker_socket: None,
        // The rootfs-inject helper VM has no egress tunnel.
        console_data_sockets: vec![],
        // The rootfs patcher runs an initramfs to completion; it serves no
        // dispatch loop.
        builder_control_sockets: vec![],
        // The patcher runs an initramfs to completion against a work dir, not
        // the shared store.
        exclusive_image_lock: None,
        handoff_socket: None,
        handoff_root: None,
        handoff_verify_key: None,
        cpu_millicores: None,
        quota_record: None,
    };
    let json = serde_json::to_string(&cfg).context("serialize inject supervisor config")?;

    let supervisor = resolve_supervisor_path()?;
    let mut child = Command::new(&supervisor)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| format!("spawn supervisor {}", supervisor.display()))?;
    child
        .stdin
        .take()
        .context("supervisor stdin")?
        .write_all(json.as_bytes())
        .context("pipe inject config to supervisor")?;
    let status = child.wait().context("wait for inject VM")?;
    if !status.success() {
        bail!(
            "inject VM exited with {status}; see {}",
            console_log.display()
        );
    }

    // The patcher logs one line per injected binary; require at least one.
    let console = std::fs::read_to_string(&console_log).unwrap_or_default();
    if !console.contains("mvm-rootfs-patcher: injected") {
        bail!(
            "inject VM produced no injection; see {}",
            console_log.display()
        );
    }
    Ok(())
}

/// Convenience: the standard scratch path for an injection keyed by `name`.
pub fn default_inject_work_dir(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("mvm-inject-{name}"))
}
