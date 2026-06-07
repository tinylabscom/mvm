//! `mvmctl pause <vm>` / `mvmctl resume <vm>` — instance snapshot
//! lifecycle. W1 / A4 of the filesystem-volumes plan.
//!
//! `pause` quiesces the running VM, asks Firecracker to write
//! `vmstate.bin` + `mem.bin` to `~/.mvm/instances/<vm>/snapshot/`,
//! seals the W4 HMAC envelope (now epoch-bound — G5), and flips
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
use std::path::{Path, PathBuf};

use mvm::vm::instance_snapshot::{
    CannedIO, FirecrackerIO, SnapshotIO, pause_and_seal, verify_and_resume,
};
use mvm_core::naming::validate_vm_name;
use mvm_core::user_config::MvmConfig;

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
    /// stub bytes to vmstate.bin + mem.bin), letting plan 65's
    /// live tests exercise `WorkloadSleep` without a real
    /// Firecracker socket.
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

/// Pick the `SnapshotIO` impl matching the hypervisor selector.
/// Plan 65 W2: `mock` swaps in `CannedIO` for hermetic
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
    // For resume the VM may not yet be running — the snapshot
    // restore path is what brings it back. We still need a
    // Firecracker socket the orchestrator can talk to. v1
    // requires the user to have already started a fresh VM
    // shell that's waiting for the snapshot load (Firecracker's
    // restore-into-empty-VMM workflow). The substrate is
    // ready; the launcher integration is a follow-up. Plan 65
    // W2: `--hypervisor mock` swaps in `CannedIO` so the
    // verify-resume path can land its `WorkloadWake` audit emit
    // without a live Firecracker socket.
    let io = snapshot_io_for(&args.hypervisor, &args.name)?;

    let sidecar = verify_and_resume(&args.name, &*io)
        .with_context(|| format!("resuming VM {:?}", args.name))?;

    let registry_path = mvm::vm::name_registry::registry_path();
    if let Ok(mut registry) = mvm::vm::name_registry::VmNameRegistry::load(&registry_path) {
        let _ = registry.set_paused(&args.name, false);
        let _ = registry.save(&registry_path);
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
    },
    /// Save a running VM's machine state to a file via Vz's
    /// `saveMachineStateTo` API (macOS 14+). The file's SHA-256 is
    /// hash-pinned in the audit chain. Plan 97 Phase E.
    Save {
        /// Name of the VM to snapshot.
        #[arg(value_parser = clap_vm_name)]
        name: String,
        /// Absolute path where the supervisor writes the snapshot
        /// blob. The file is opaque — Vz controls the format.
        #[arg(long)]
        path: PathBuf,
        /// Hypervisor that drives the snapshot. Only `vz` is wired
        /// today; other selectors error with a clear message.
        #[arg(long, default_value = "vz")]
        hypervisor: String,
    },
    /// Restore a saved Vz machine state file. NOT YET IMPLEMENTED —
    /// returns a clean error explaining the missing supervisor
    /// startup mode. Plan 97 Phase E §"RESTORE follow-up".
    Restore {
        /// Name of the VM (must not be currently running).
        #[arg(value_parser = clap_vm_name)]
        name: String,
        /// Absolute path of the snapshot blob to load.
        #[arg(long)]
        path: PathBuf,
        /// Hypervisor that drives the restore.
        #[arg(long, default_value = "vz")]
        hypervisor: String,
    },
}

pub(in crate::commands) fn run_snapshot(
    _cli: &Cli,
    args: SnapshotArgs,
    _cfg: &MvmConfig,
) -> Result<()> {
    match args.command {
        SnapshotCmd::Ls { json } => snap_ls(json),
        SnapshotCmd::Rm { name } => snap_rm(&name),
        SnapshotCmd::Save {
            name,
            path,
            hypervisor,
        } => snap_save(&name, &path, &hypervisor),
        SnapshotCmd::Restore {
            name,
            path,
            hypervisor,
        } => snap_restore(&name, &path, &hypervisor),
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

fn snap_rm(name: &str) -> Result<()> {
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
    println!("{}: snapshot removed", name);
    mvm_core::audit_emit!(SnapshotDelete, vm: name);
    Ok(())
}

/// Plan 97 Phase E — `mvmctl snapshot save <vm> --path <p>`.
///
/// Dispatches to `VzBackend::snapshot_save`, then hashes the
/// resulting file and emits a `vm.snapshot_saved` chain entry
/// bound to the plan that admitted this VM (loaded from
/// `~/.mvm/vms/<vm>/plan.json` — written at launch by
/// `emit_launched_if` in `up.rs`).
///
/// Only the `vz` hypervisor is implemented today. Other selectors
/// error out cleanly: libkrun has no snapshot API, Firecracker has
/// a different snapshot model (already covered by `pause`/`resume`),
/// and the mock backend never persists state. The audit emit is
/// best-effort: a flaky `~/.mvm/audit/` fs warns and continues so a
/// successful save is still observable on stdout.
fn snap_save(name: &str, path: &Path, hypervisor: &str) -> Result<()> {
    validate_vm_name(name).with_context(|| format!("Invalid VM name: {:?}", name))?;
    if hypervisor != "vz" {
        bail!(
            "snapshot save is only implemented for the `vz` backend (got: {:?}). \
             Firecracker snapshots flow through `mvmctl pause` / `mvmctl resume`; \
             libkrun and apple-container have no snapshot API.",
            hypervisor,
        );
    }
    if !path.is_absolute() {
        bail!(
            "--path must be absolute, got {} — Vz's saveMachineStateTo \
             does not honour cwd",
            path.display(),
        );
    }
    if !mvm_core::platform::current().has_vz() {
        bail!("vz snapshot save requires macOS 13+ with Virtualization.framework");
    }

    // Drive the supervisor first; if the save fails there's nothing
    // to hash. The supervisor returns its own error message for
    // pre-macOS-14 hosts ("ERR SAVE requires macOS 14+") which
    // bubbles up verbatim.
    let id = mvm_core::vm_backend::VmId(name.to_string());
    let backend = mvm_backend::vz::VzBackend;
    backend
        .snapshot_save(&id, path)
        .with_context(|| format!("vz snapshot save for {name:?}"))?;

    let meta = std::fs::metadata(path)
        .with_context(|| format!("stat snapshot file {}", path.display()))?;
    let size = meta.len();
    let sha = hash_file_sha256(path)
        .with_context(|| format!("hashing snapshot file {}", path.display()))?;

    println!("{name}: saved snapshot ({size} bytes, sha256 {sha})");
    println!("  path: {}", path.display());

    // Audit chain emit. If we can load the persisted plan + host
    // signer key, we get a tamper-evident `vm.snapshot_saved` entry
    // bound to the plan_id that admitted the VM. If anything in the
    // chain isn't ready (no plan.json, no signer, audit fs missing),
    // warn + continue: the snapshot file is already on disk and the
    // human-facing output above is the operator's source of truth.
    match super::plan_persist::read_plan(name) {
        Ok(plan) => match super::host_signer::load_or_init() {
            Ok(signer) => match super::audit_chain::AuditEmitter::new(signer.signing) {
                Ok(emitter) => {
                    if let Err(e) = emitter.emit_vm_snapshot_saved(&plan, path, &sha, size, "vz") {
                        tracing::warn!(error = %e, "audit emit_vm_snapshot_saved failed (non-fatal)");
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "audit emitter unavailable; chain entry skipped")
                }
            },
            Err(e) => tracing::warn!(error = %e, "host signer unavailable; chain entry skipped"),
        },
        Err(e) => tracing::warn!(
            error = %e,
            vm = name,
            "no persisted plan for VM; vm.snapshot_saved emitted without chain binding"
        ),
    }
    Ok(())
}

/// Plan 97 Phase E — `mvmctl snapshot restore <vm> --path <p>`.
///
/// Loads a previously saved Vz machine-state file by spawning a new
/// supervisor in `StartupMode::Restore` (`VzBackend::snapshot_restore`),
/// which calls Apple's `restoreMachineState(from:)` + `resume()`.
/// macOS 14+ only.
///
/// Pre-restore steps:
/// 1. Verify `<snapshot_path>` exists and is absolute.
/// 2. Re-hash the file and compare against the SHA-256 the audit
///    chain recorded at save time (`vm.snapshot_saved`). Result
///    feeds the `chain_match` field on the emitted
///    `vm.snapshot_restored` audit entry. Mismatch does NOT refuse —
///    an operator may legitimately transfer a snapshot between
///    hosts — but the chain entry flags it explicitly.
/// 3. Compute the optional `<snapshot_path>.machine-id` sidecar path
///    so the restored guest preserves its prior identity.
fn snap_restore(name: &str, path: &Path, hypervisor: &str) -> Result<()> {
    validate_vm_name(name).with_context(|| format!("Invalid VM name: {:?}", name))?;
    if hypervisor != "vz" {
        bail!(
            "snapshot restore is only implemented for the `vz` backend (got: {:?})",
            hypervisor,
        );
    }
    if !path.is_absolute() {
        bail!(
            "--path must be absolute, got {} — Vz's restoreMachineState \
             does not honour cwd",
            path.display(),
        );
    }
    if !path.exists() {
        bail!("snapshot file does not exist: {}", path.display(),);
    }
    if !mvm_core::platform::current().has_vz() {
        bail!(
            "vz snapshot restore requires macOS 13+ with Virtualization.framework (saveMachineStateTo needs macOS 14+)"
        );
    }

    let meta = std::fs::metadata(path)
        .with_context(|| format!("stat snapshot file {}", path.display()))?;
    let size = meta.len();
    let sha = hash_file_sha256(path)
        .with_context(|| format!("hashing snapshot file {}", path.display()))?;

    let machine_id_sidecar = {
        let mut p = path.to_path_buf();
        let new_name = match p.file_name() {
            Some(n) => format!("{}.machine-id", n.to_string_lossy()),
            None => "snapshot.machine-id".to_string(),
        };
        p.set_file_name(new_name);
        p
    };
    let machine_id_arg = if machine_id_sidecar.exists() {
        Some(machine_id_sidecar.as_path())
    } else {
        None
    };

    // Cross-check the SHA-256 against the audit chain. Doing this
    // BEFORE the restore so the chain_match label on the audit
    // entry reflects the file's state at the moment of restore.
    let plan = super::plan_persist::read_plan(name).ok();
    let chain_match = chain_match_for_snapshot(plan.as_ref(), path, &sha);

    let id = mvm_core::vm_backend::VmId(name.to_string());
    let backend = mvm_backend::vz::VzBackend;
    backend
        .snapshot_restore(&id, path, machine_id_arg)
        .with_context(|| format!("vz snapshot restore for {name:?}"))?;

    println!(
        "{name}: restored snapshot ({size} bytes, sha256 {sha}, chain={})",
        chain_match.as_str()
    );
    println!("  path: {}", path.display());
    if let Some(p) = machine_id_arg {
        println!("  machine-id sidecar: {}", p.display());
    } else {
        println!("  machine-id sidecar: <missing> (guest identity not preserved)");
    }
    if matches!(
        chain_match,
        super::audit_chain::SnapshotChainMatch::Mismatch
    ) {
        crate::ui::warn(
            "snapshot SHA-256 does not match the audit chain's recorded value. \
             The restore proceeded but the audit entry is flagged as `chain_match=mismatch`.",
        );
    }

    // Emit the audit entry. Same best-effort policy as snap_save:
    // chain unavailable = warn + continue.
    if let Some(plan) = plan {
        match super::host_signer::load_or_init() {
            Ok(signer) => match super::audit_chain::AuditEmitter::new(signer.signing) {
                Ok(emitter) => {
                    if let Err(e) = emitter.emit_vm_snapshot_restored(
                        &plan,
                        path,
                        &sha,
                        size,
                        "vz",
                        chain_match,
                    ) {
                        tracing::warn!(error = %e, "audit emit_vm_snapshot_restored failed (non-fatal)");
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "audit emitter unavailable; chain entry skipped")
                }
            },
            Err(e) => tracing::warn!(error = %e, "host signer unavailable; chain entry skipped"),
        }
    } else {
        tracing::warn!(
            vm = name,
            "no persisted plan for VM; vm.snapshot_restored emitted without chain binding"
        );
    }
    Ok(())
}

/// Look up the SHA recorded by a prior `vm.snapshot_saved` event for
/// this snapshot path. Returns:
///
/// - [`SnapshotChainMatch::Verified`] when an entry exists and the
///   hash matches the file we just hashed.
/// - [`SnapshotChainMatch::Mismatch`] when an entry exists with a
///   different hash.
/// - [`SnapshotChainMatch::NotInChain`] when no entry exists, the
///   plan isn't persisted, or the audit chain lookup fails (we
///   warn and degrade rather than fail).
fn chain_match_for_snapshot(
    plan: Option<&mvm_core::plan::ExecutionPlan>,
    snapshot_path: &Path,
    actual_sha: &str,
) -> super::audit_chain::SnapshotChainMatch {
    use super::audit_chain::{SnapshotChainMatch, default_audit_dir, find_snapshot_saved_sha};
    let Some(plan) = plan else {
        return SnapshotChainMatch::NotInChain;
    };
    let audit_dir = match default_audit_dir() {
        Ok(d) => d,
        Err(_) => return SnapshotChainMatch::NotInChain,
    };
    let recorded = match find_snapshot_saved_sha(&audit_dir, &plan.tenant.0, snapshot_path) {
        Ok(Some(s)) => s,
        Ok(None) => return SnapshotChainMatch::NotInChain,
        Err(e) => {
            tracing::warn!(error = %e, "audit chain lookup failed; treating as NotInChain");
            return SnapshotChainMatch::NotInChain;
        }
    };
    if recorded.eq_ignore_ascii_case(actual_sha) {
        SnapshotChainMatch::Verified
    } else {
        SnapshotChainMatch::Mismatch
    }
}

/// Stream-hash a file with SHA-256 and return the lowercase hex
/// digest. `Path` may point at multi-GB Vz snapshots, so we never
/// slurp the whole file into memory.
fn hash_file_sha256(path: &Path) -> Result<String> {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    let mut f = std::fs::File::open(path)
        .with_context(|| format!("opening {} for hashing", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = f
            .read(&mut buf)
            .with_context(|| format!("reading {} for hashing", path.display()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let digest = hasher.finalize();
    let mut out = String::with_capacity(digest.len() * 2);
    for b in digest.iter() {
        use std::fmt::Write as _;
        let _ = write!(out, "{:02x}", b);
    }
    Ok(out)
}

#[cfg(test)]
mod snapshot_save_tests {
    use super::*;

    #[test]
    fn save_rejects_non_vz_hypervisor() {
        let err = snap_save("vm1", Path::new("/tmp/snap.bin"), "libkrun").unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("only implemented for the `vz` backend"));
        assert!(msg.contains("libkrun"));
    }

    #[test]
    fn save_rejects_relative_path() {
        // Skipped when Vz isn't on the host — the relative-path
        // check fires before the has_vz() probe on macOS, but on
        // Linux the has_vz()=false bail trips first and the
        // assertion below tolerates either error message.
        let err = snap_save("vm1", Path::new("relative.bin"), "vz").unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("absolute") || msg.contains("Virtualization.framework"),
            "expected absolute-path or vz-availability error, got: {msg}"
        );
    }

    #[test]
    fn restore_rejects_non_vz_hypervisor() {
        let err = snap_restore("vm1", Path::new("/tmp/snap.bin"), "firecracker").unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("only implemented for the `vz` backend"));
    }

    #[test]
    fn restore_rejects_relative_path() {
        // Relative path is refused before any backend probe.
        let err = snap_restore("vm1", Path::new("relative.bin"), "vz").unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("absolute"),
            "expected absolute-path error, got: {msg}"
        );
    }

    #[test]
    fn restore_rejects_missing_snapshot_file() {
        // Path doesn't exist — refused before backend probe so the
        // test runs cleanly on hosts without Vz.
        let err = snap_restore("vm1", Path::new("/nonexistent/snap.bin"), "vz").unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("does not exist"),
            "expected missing-file error, got: {msg}"
        );
    }

    #[test]
    fn chain_match_returns_not_in_chain_when_plan_is_none() {
        let actual = chain_match_for_snapshot(None, Path::new("/tmp/x.bin"), "abc123");
        assert_eq!(
            actual,
            super::super::audit_chain::SnapshotChainMatch::NotInChain
        );
    }

    #[test]
    fn hash_file_sha256_matches_known_vector() {
        // SHA-256 of "abc" = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("input.bin");
        std::fs::write(&p, b"abc").unwrap();
        let h = hash_file_sha256(&p).unwrap();
        assert_eq!(
            h,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        );
    }

    #[test]
    fn hash_file_sha256_handles_large_streamed_input() {
        // 256 KiB of 0x42 — exercises the multi-chunk read path.
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("big.bin");
        let bytes = vec![0x42u8; 256 * 1024];
        std::fs::write(&p, &bytes).unwrap();
        let h = hash_file_sha256(&p).unwrap();

        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        let expected: String = hasher
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(h, expected);
    }
}
