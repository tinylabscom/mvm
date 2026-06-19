//! `mvmctl pause <vm>` / `mvmctl resume <vm>` — instance snapshot
//! lifecycle.
//!
//! `pause` quiesces the running VM, asks Firecracker to write
//! `vmstate.bin` + `mem.bin` to `~/.mvm/instances/<vm>/snapshot/`,
//! seals the epoch-bound HMAC envelope, and flips
//! `paused = true` in the persistent VM-name registry.
//!
//! `resume` verifies the envelope (refusing replayed older
//! snapshots), asks Firecracker to load the bytes back, resumes
//! vCPUs, and clears the `paused` flag.
//!
//! Both verbs hit the live Firecracker socket — calls against a
//! VM that's already gone fail cleanly at the socket-existence
//! check rather than mid-API.

use anyhow::{Context, Result, bail};
use clap::Args as ClapArgs;
use std::path::PathBuf;

use mvm::vm::instance_snapshot::{
    CannedIO, FirecrackerIO, SnapshotIO, VsockPostRestoreSignal, pause_and_seal,
    signal_post_restore, verify_and_resume,
};
use mvm_backend::backend::AnyBackend;
use mvm_core::config::vm_state_dir;
use mvm_core::naming::validate_vm_name;
use mvm_core::user_config::MvmConfig;
use mvm_core::vm_backend::VmId;

use super::Cli;
use super::shared::clap_vm_name;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct PauseArgs {
    /// Name of the VM to pause
    #[arg(value_parser = clap_vm_name)]
    pub name: String,
    /// Hypervisor to drive the snapshot through. Defaults to
    /// `firecracker`. `--hypervisor mock` swaps the FirecrackerIO
    /// snapshot transport for `CannedIO` (writes deterministic
    /// stub bytes to vmstate.bin + mem.bin), letting the live tests
    /// exercise `WorkloadSleep` without a real Firecracker socket.
    #[arg(long, default_value = "firecracker")]
    pub hypervisor: String,
}

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct ResumeArgs {
    /// Name of the VM to resume
    #[arg(value_parser = clap_vm_name)]
    pub name: String,
    /// Hypervisor to drive the restore through. Defaults to
    /// `firecracker`. See `pause --help` for the `mock` variant.
    #[arg(long, default_value = "firecracker")]
    pub hypervisor: String,
}

/// A running VM whose state dir carries a `vz.pid` marker is a Vz VM — it gets
/// native vCPU pause/resume rather than the Firecracker snapshot-seal path.
fn is_vz_vm(name: &str) -> bool {
    matches!(AnyBackend::for_started_vm(name), Some(AnyBackend::Vz(_)))
}

/// Pick the `SnapshotIO` impl matching the hypervisor selector.
/// `mock` swaps in `CannedIO` for hermetic
/// `WorkloadSleep` / `WorkloadWake` audit-emit coverage; every
/// other selector uses `FirecrackerIO` against the running VM's
/// UDS socket.
fn snapshot_io_for(hypervisor: &str, vm_name: &str) -> Result<Box<dyn SnapshotIO>> {
    if hypervisor == "mock" {
        // The mock VM's per-VM directory lives at
        // `<mvm_data_dir>/mock-vms/<name>/` and is created by
        // `MockBackend::start_with_mode`. Nothing to validate here
        // beyond its existence — `pause_and_seal` writes the
        // snapshot files into a sibling `snapshot/` directory.
        let dir = mvm_backend::MockBackend::vm_dir(vm_name);
        if !dir.exists() {
            bail!(
                "mock VM {vm_name:?} is not running (no directory at {})",
                dir.display()
            );
        }
        return Ok(Box::new(CannedIO {
            vmstate_bytes: b"mock-vmstate".to_vec(),
            mem_bytes: b"mock-mem".to_vec(),
        }));
    }
    let vm_dir = mvm_backend::microvm::resolve_running_vm_dir(vm_name)
        .with_context(|| format!("VM {vm_name:?} is not running"))?;
    let socket = firecracker_socket(&vm_dir);
    Ok(Box::new(FirecrackerIO::new(socket)))
}

pub(in crate::commands) fn run_pause(_cli: &Cli, args: PauseArgs, _cfg: &MvmConfig) -> Result<()> {
    validate_vm_name(&args.name).with_context(|| format!("Invalid VM name: {:?}", args.name))?;
    if is_vz_vm(&args.name) {
        AnyBackend::Vz(mvm_backend::vz::VzBackend)
            .pause(&VmId::from(args.name.as_str()))
            .with_context(|| format!("pausing Vz VM {:?}", args.name))?;
        // Stamp the live supervisor pid into a marker so the fs_quick gate
        // can confirm the VM is quiesced without depending on the name
        // registry (which `up`-created VMs may never have populated).
        // The marker is only valid while the same pid is alive; a re-launched
        // or crashed VM will have a different or absent pid, so the marker
        // self-invalidates without any explicit cleanup on those paths.
        let state_dir = vm_state_dir(&args.name);
        match std::fs::read_to_string(state_dir.join("vz.pid")) {
            Ok(pid) => {
                if let Err(e) = std::fs::write(state_dir.join("vz.paused"), pid.trim()) {
                    tracing::warn!(error = %e, vm = %args.name, "could not write vz.paused marker (pause succeeded)");
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, vm = %args.name, "vz.pid unreadable; vz.paused marker not written (pause succeeded)");
            }
        }
        let registry_path = mvm::vm::name_registry::registry_path();
        if let Ok(mut registry) = mvm::vm::name_registry::VmNameRegistry::load(&registry_path) {
            let _ = registry.set_paused(&args.name, true);
            let _ = registry.save(&registry_path);
        }
        println!("{}: paused (vz, vCPUs quiesced)", args.name);
        mvm_core::audit_emit!(WorkloadSleep, vm: &args.name, "backend=vz");
        return Ok(());
    }
    let io = snapshot_io_for(&args.hypervisor, &args.name)?;

    let sidecar =
        pause_and_seal(&args.name, &*io).with_context(|| format!("pausing VM {:?}", args.name))?;

    let registry_path = mvm::vm::name_registry::registry_path();
    if let Ok(mut registry) = mvm::vm::name_registry::VmNameRegistry::load(&registry_path) {
        let _ = registry.set_paused(&args.name, true);
        let _ = registry.save(&registry_path);
    }
    println!(
        "{}: paused (epoch {}, vmstate {} B, mem {} B)",
        args.name, sidecar.epoch, sidecar.vmstate_len, sidecar.mem_len
    );
    mvm_core::audit_emit!(WorkloadSleep, vm: &args.name, "epoch={} vmstate={} mem={}" ,
        sidecar.epoch, sidecar.vmstate_len, sidecar.mem_len
    );
    Ok(())
}

pub(in crate::commands) fn run_resume(
    _cli: &Cli,
    args: ResumeArgs,
    _cfg: &MvmConfig,
) -> Result<()> {
    validate_vm_name(&args.name).with_context(|| format!("Invalid VM name: {:?}", args.name))?;
    if is_vz_vm(&args.name) {
        AnyBackend::Vz(mvm_backend::vz::VzBackend)
            .resume(&VmId::from(args.name.as_str()))
            .with_context(|| format!("resuming Vz VM {:?}", args.name))?;
        // Remove the pause marker now that vCPUs are running again.
        // Tolerate a missing file — it may have already been cleaned up or
        // was never written (best-effort on the pause side).
        let marker = vm_state_dir(&args.name).join("vz.paused");
        let _ = std::fs::remove_file(&marker);
        let registry_path = mvm::vm::name_registry::registry_path();
        if let Ok(mut registry) = mvm::vm::name_registry::VmNameRegistry::load(&registry_path) {
            let _ = registry.set_paused(&args.name, false);
            let _ = registry.touch_last_active(&args.name, mvm_core::time::utc_now());
            let _ = registry.save(&registry_path);
        }
        println!("{}: resumed (vz, vCPUs running)", args.name);
        mvm_core::audit_emit!(WorkloadWake, vm: &args.name, "backend=vz");
        return Ok(());
    }
    // For resume the VM may not yet be running — the snapshot
    // restore path is what brings it back. We still need a
    // Firecracker socket the orchestrator can talk to. v1
    // requires the user to have already started a fresh VM
    // shell that's waiting for the snapshot load (Firecracker's
    // restore-into-empty-VMM workflow). The substrate is
    // ready; the launcher integration is a follow-up.
    // `--hypervisor mock` swaps in `CannedIO` so the
    // verify-resume path can land its `WorkloadWake` audit emit
    // without a live Firecracker socket.
    let io = snapshot_io_for(&args.hypervisor, &args.name)?;

    let sidecar = verify_and_resume(&args.name, &*io)
        .with_context(|| format!("resuming VM {:?}", args.name))?;

    // The VM is now running at the hypervisor level — mark it resumed before
    // signaling the guest, so a post-restore failure below leaves the registry
    // consistent (the VM *is* up) and the operator can simply re-run resume.
    let registry_path = mvm::vm::name_registry::registry_path();
    if let Ok(mut registry) = mvm::vm::name_registry::VmNameRegistry::load(&registry_path) {
        let _ = registry.set_paused(&args.name, false);
        // A resume is activity — refresh idle tracking so the freshly woken
        // VM isn't immediately re-slept by the idle reaper.
        let _ = registry.touch_last_active(&args.name, mvm_core::time::utc_now());
        let _ = registry.save(&registry_path);
    }

    // The host-side PostRestore sender. Resuming vCPUs is
    // not enough: the guest agent must remount the config/secrets drives and
    // restart services (it maps PostRestore → SIGUSR1 → PID 1). The `mock`
    // hypervisor has no guest agent, so skip it there.
    if args.hypervisor != "mock" {
        crate::commands::shared::emit_vsock_rpc_audit(
            &args.name,
            &mvm_guest::vsock::GuestRequest::PostRestore,
        );
        signal_post_restore(&args.name, &VsockPostRestoreSignal)
            .with_context(|| format!("post-restore signal for {:?}", args.name))?;
    }

    println!(
        "{}: resumed (epoch {}, vmstate {} B, mem {} B)",
        args.name, sidecar.epoch, sidecar.vmstate_len, sidecar.mem_len
    );
    mvm_core::audit_emit!(WorkloadWake, vm: &args.name, "epoch={} vmstate={} mem={}" ,
        sidecar.epoch, sidecar.vmstate_len, sidecar.mem_len
    );
    Ok(())
}

fn firecracker_socket(vm_dir: &str) -> PathBuf {
    PathBuf::from(format!("{vm_dir}/runtime/firecracker.socket"))
}

// `mvmctl snapshot ls / rm` lives next to pause/resume because
// they share `instance_snapshot` plumbing — keeping them in one
// file avoids a third tiny module.
#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct SnapshotArgs {
    #[command(subcommand)]
    pub command: SnapshotCmd,
}

#[derive(clap::Subcommand, Debug, Clone)]
pub(in crate::commands) enum SnapshotCmd {
    /// List sealed instance snapshots under ~/.mvm/instances/*/snapshot/
    Ls {
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Remove a sealed instance snapshot
    Rm {
        /// VM name whose snapshot to remove
        #[arg(value_parser = clap_vm_name)]
        name: String,
        /// Output the removal result as JSON
        #[arg(long)]
        json: bool,
    },
}

pub(in crate::commands) fn run_snapshot(
    _cli: &Cli,
    args: SnapshotArgs,
    _cfg: &MvmConfig,
) -> Result<()> {
    match args.command {
        SnapshotCmd::Ls { json } => snap_ls(json),
        SnapshotCmd::Rm { name, json } => snap_rm(&name, json),
    }
}

fn snap_ls(json: bool) -> Result<()> {
    let entries = mvm::vm::instance_snapshot::list_instance_snapshots()?;
    if json {
        #[derive(serde::Serialize)]
        struct Row<'a> {
            vm_name: &'a str,
            vmstate_size_bytes: u64,
            mem_size_bytes: u64,
            epoch: Option<u64>,
            sealed: bool,
        }
        let rows: Vec<Row<'_>> = entries
            .iter()
            .map(|e| Row {
                vm_name: &e.vm_name,
                vmstate_size_bytes: e.vmstate_size_bytes,
                mem_size_bytes: e.mem_size_bytes,
                epoch: e.sidecar.as_ref().map(|s| s.epoch),
                sealed: e.sidecar.is_some(),
            })
            .collect();
        crate::json_out::emit_json(&rows)?;
        return Ok(());
    }
    if entries.is_empty() {
        println!("(no instance snapshots)");
        return Ok(());
    }
    println!(
        "{:<24} {:<7} {:<14} {:<14} STATUS",
        "VM", "EPOCH", "VMSTATE", "MEM"
    );
    for e in &entries {
        let (epoch, status) = match &e.sidecar {
            Some(s) => (s.epoch.to_string(), "sealed"),
            None => ("-".to_string(), "unsealed"),
        };
        println!(
            "{:<24} {:<7} {:<14} {:<14} {}",
            e.vm_name, epoch, e.vmstate_size_bytes, e.mem_size_bytes, status
        );
    }
    Ok(())
}

#[derive(serde::Serialize)]
struct SnapshotRemoveJson<'a> {
    schema_version: u8,
    action: &'static str,
    vm_name: &'a str,
    removed: bool,
}

fn snap_rm(name: &str, json: bool) -> Result<()> {
    validate_vm_name(name).with_context(|| format!("Invalid VM name: {:?}", name))?;
    let removed = mvm::vm::instance_snapshot::delete_instance_snapshot(name)?;
    if !removed {
        bail!("no snapshot found for VM {:?}", name);
    }
    let registry_path = mvm::vm::name_registry::registry_path();
    if let Ok(mut registry) = mvm::vm::name_registry::VmNameRegistry::load(&registry_path) {
        let _ = registry.set_paused(name, false);
        let _ = registry.save(&registry_path);
    }
    if json {
        crate::json_out::emit_json(&SnapshotRemoveJson {
            schema_version: 1,
            action: "rm",
            vm_name: name,
            removed: true,
        })?;
    } else {
        println!("{}: snapshot removed", name);
    }
    mvm_core::audit_emit!(SnapshotDelete, vm: name);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_vz_vm_true_for_vz_marker() {
        let tmp = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.set("MVM_DATA_DIR", tmp.path());
        let dir = mvm_core::config::vm_state_dir("vzvm");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("vz.pid"), "1").unwrap();
        assert!(is_vz_vm("vzvm"));
        assert!(!is_vz_vm("nope"));
    }
}
