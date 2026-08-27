//! VM state and backend-capability probes for the checkpoint verbs.
//!
//! One question each: is this VM quiesced enough to checkpoint, where is its
//! rootfs, and can the backend that owns it actually save and restore. They
//! were inline in `checkpoint.rs` until that file crossed the production-line
//! ceiling; grouping them here keeps the answer to "what state is this VM in"
//! in one place rather than interleaved with the verbs that ask it.

use super::*;

/// Resolve the host-side bootable rootfs image for a quiesced VM, or a clean
/// error explaining why a checkpoint can't be taken.
///
/// "Quiesced" means the VM is not running, OR the pause verb has written a
/// pause marker that matches the live supervisor pid (vCPUs and virtio queues
/// quiesced). A live, unpaused VM is refused: an fs_quick checkpoint has no
/// memory, so the rootfs must be in a clean, deterministic state.
///
/// Resolution order (first match wins):
/// 1. Per-instance `rootfs.ext4` CoW clone in `vm_state_dir(name)`.
/// 2. `mode.json` `rootfs_path` field (backend-neutral; written by every
///    backend that calls `record_from_rootfs` at start time).
pub(super) fn resolve_quiesced_vm_rootfs(name: &str) -> Result<PathBuf> {
    if !vm_is_quiesced(name) {
        bail!("stop or pause VM '{name}' before checkpointing");
    }
    let state_dir = vm_state_dir(name);

    // Per-instance CoW clone — deterministic, present on disk.
    let instance_rootfs = state_dir.join("rootfs.ext4");
    if instance_rootfs.is_file() {
        return Ok(instance_rootfs);
    }

    // Backend-neutral: every backend that calls `record_from_rootfs` at start
    // time writes the rootfs path into mode.json.
    if let Some(path) = rootfs_from_mode_json(&state_dir)? {
        if !path.exists() {
            bail!(
                "fs_quick checkpoint needs the VM's rootfs ({}), which is no longer \
                 on disk. Pause instead of stopping: `mvmctl machine pause {name}`, \
                 checkpoint, then `mvmctl machine resume {name}` — or use \
                 `--class vm-full` on a running VM.",
                path.display()
            );
        }
        return Ok(path);
    }

    bail!("fs_quick checkpoint is not supported for this VM's backend");
}

/// Read `mode.json` and return the recorded `rootfs_path` field, if present.
/// Absent file or absent field → `Ok(None)`. Malformed JSON propagates.
pub(super) fn rootfs_from_mode_json(state_dir: &std::path::Path) -> Result<Option<PathBuf>> {
    let path = state_dir.join("mode.json");
    let body = match std::fs::read_to_string(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    };
    let meta: mvm_runtime::base::runtime_meta::VmRuntimeMeta =
        serde_json::from_str(&body).with_context(|| format!("parsing {}", path.display()))?;
    Ok(meta.rootfs_path.map(PathBuf::from))
}

/// Best-effort liveness: a VM is "running" iff one of its per-backend PID
/// files names a live process. Delegates to the runtime's probe so this side
/// cannot keep its own marker list — every registered backend's marker
/// (`fc.pid`, `libkrun.pid`, `hvf.pid`, `qemu.pid`) is covered by one pass over
/// the shared list, which is also where the `EPERM`-means-alive rule lives. A
/// hand-kept list here is how a live HVF VM used to read as stopped, and a
/// root-owned Firecracker with it.
pub(super) fn vm_is_running(name: &str) -> bool {
    mvm_runtime::checkpoint::vm_is_running(name)
}

/// fs_quick clones the instance rootfs, so the guest must not be writing:
/// either the VM is stopped, or it is paused (vCPUs and virtio queues quiesced
/// — the FC pause verb stamps the fc pid into `fc.paused`; resume and any path
/// that replaces the process removes or invalidates the marker). A
/// running-but-paused VM keeps its pid alive, so `vm_is_running` alone would
/// incorrectly refuse the checkpoint without these marker checks.
pub(super) fn vm_is_quiesced(name: &str) -> bool {
    if !vm_is_running(name) {
        return true;
    }
    fc_pause_marker_matches_live_pid(name) || hvf_pause_marker_present(name)
}

/// The HVF supervisor writes `pause.state` only after its vCPU has entered the
/// pause hold, and removes it on resume. Unlike Firecracker's marker this one is
/// written by the process that owns the vCPU, so its presence beside a live
/// `hvf.pid` is itself the acknowledgement — there is no pid to cross-check
/// against a marker some other verb stamped.
pub(super) fn hvf_pause_marker_present(name: &str) -> bool {
    let dir = vm_state_dir(name);
    dir.join("hvf.pid").is_file() && dir.join("pause.state").is_file()
}

/// `machine pause` snapshot-seals FC but leaves the fc process running, so a
/// live pid cannot
/// distinguish paused from running. The pause verb stamps the fc pid into
/// `fc.paused` (under `vm_state_dir`); resume removes it. Quiesced iff the
/// marker matches the live fc pid at `<mvm_home>/vms/<name>/fc.pid`.
pub(super) fn fc_pause_marker_matches_live_pid(name: &str) -> bool {
    let marker = std::fs::read_to_string(vm_state_dir(name).join("fc.paused")).ok();
    let live =
        mvm_runtime::microvm::fc_pid_path(name).and_then(|p| std::fs::read_to_string(p).ok());
    matches!((marker, live), (Some(m), Some(l)) if !m.trim().is_empty() && m.trim() == l.trim())
}

/// Hash the VM's persisted supervisor config so the checkpoint pins the launch
/// shape it was captured from. No config on disk → empty digest (the field is
/// advisory for fs_quick; integrity rests on `content_sha256`).
pub(super) fn supervisor_config_digest(state_dir: &std::path::Path) -> String {
    let cfg_path = state_dir.join("supervisor-config.json");
    mvm_core::crypto::image_verify::sha256_file(&cfg_path).unwrap_or_default()
}

pub(super) fn runtime_contract_for_checkpoint(name: &str) -> Result<Option<String>> {
    Ok(mvm_runtime::base::runtime_meta::read(name)?.and_then(|meta| meta.runtime_overlay_version))
}

/// The backend that actually owns `name`, falling back to the host default for
/// a VM with no live marker (a restore target that has not been started yet).
pub(super) fn backend_for_vm(name: &str) -> AnyBackend {
    AnyBackend::for_started_vm(name).unwrap_or_else(AnyBackend::auto_select)
}

/// Refuse a memory-snapshot verb on a backend that cannot save and reload
/// machine state. The check is against the backend that owns *this* VM, not the
/// host default: on a host where several VMMs can run, the capability of the
/// one holding the VM is the only one that matters.
pub(super) fn ensure_save_restore_supported(action: &str, backend: &AnyBackend) -> Result<()> {
    let available = backend.snapshot_capability();
    if !available.satisfies(SnapshotCapability::SaveRestore) {
        bail!(
            "vm {action} requires memory-snapshot support, but backend '{}' reports \
             snapshot tier '{}' on this host",
            backend.name(),
            available.label()
        );
    }
    Ok(())
}
