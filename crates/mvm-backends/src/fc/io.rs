//! The Firecracker `SnapshotIO`: pause/create/load/resume over the VMM's
//! API socket, plus the pid-file plumbing the socket lifecycle needs.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use mvm_core::crypto::snapshot_hmac::{MEM_FILENAME, VMSTATE_FILENAME};

use mvm_vmm::snapshot::SnapshotIO;

/// `SnapshotIO` impl that talks to a live Firecracker over its
/// Unix socket, speaking HTTP/1.1 to the API directly rather than
/// spawning a process per call. Pause issues `PATCH /vm` (state =
/// Paused) followed by `PUT /snapshot/create`; resume runs `PUT
/// /snapshot/load` then `PATCH /vm` (state = Resumed).
///
/// The socket path is taken from the running-VM lookup at call
/// time so a stale `mvmctl pause` against a vanished VM fails
/// cleanly with `socket does not exist` rather than mid-API.
pub struct FirecrackerIO {
    /// Absolute path to the live Firecracker control socket.
    pub socket_path: PathBuf,
    /// Who the *fresh* VMM a snapshot load starts is scoped as, and the CPU
    /// share it is born under. `None` on a handle that only talks to an
    /// already-running Firecracker, and on a same-identity restore, which
    /// scopes the VMM by its directory instead.
    restore_bound: Option<RestoreBound>,
}

/// The admitted child a restore-launched Firecracker is scoped as, and the CPU
/// share its plan granted.
///
/// The machine id names the scope whether or not a share was granted: the
/// memory and task ceilings apply to every snapshot load, so a restored child
/// is scoped under its own name even when its plan grants no CPU.
#[derive(Clone, Debug)]
pub struct RestoreBound {
    pub machine_id: String,
    pub cpu_grant: Option<mvm_contract::grants::CpuGrant>,
}

impl FirecrackerIO {
    pub fn new(socket_path: PathBuf) -> Self {
        Self {
            socket_path,
            restore_bound: None,
        }
    }

    /// Carry the identity and CPU bound the restored child's plan was admitted
    /// under.
    #[must_use]
    pub fn bounded_by(mut self, bound: RestoreBound) -> Self {
        self.restore_bound = Some(bound);
        self
    }

    /// The scope prefix the fresh VMM's launch line carries, or empty when
    /// this host cannot scope it. The launch uses this exact value, so reading
    /// it back is reading what the restored guest actually runs inside.
    pub(crate) fn restore_scope_prefix(&self, state_dir: &Path, guest_memory_mib: u32) -> String {
        let bounds = mvm_core::spawn_scope::SpawnBounds::for_guest_memory(guest_memory_mib);
        match &self.restore_bound {
            Some(bound) => super::spawn_scope_prefix(
                &bound.machine_id,
                state_dir,
                &bounds.with_cpu_grant(bound.cpu_grant),
            ),
            None => {
                let machine_id = state_dir
                    .file_name()
                    .map(|name| name.to_string_lossy().into_owned())
                    .unwrap_or_default();
                super::spawn_scope_prefix(&machine_id, state_dir, &bounds)
            }
        }
    }

    /// Stop the Firecracker recorded in `vm_dir/fc.pid`, if it is the one
    /// serving this handle's API socket, and wait until it is gone.
    fn stop_own_vmm(&self, vm_dir: &Path) -> Result<()> {
        let name = vm_dir
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| vm_dir.display().to_string());
        stop_restored_vmm(
            &name,
            &vm_dir.join("fc.pid"),
            |pid| super::is_firecracker_for_socket(pid, &self.socket_path),
            crate::driver::fc::terminate_firecracker_pid,
        )
    }

    fn ensure_socket(&self) -> Result<()> {
        if !self.socket_path.exists() {
            bail!(
                "Firecracker socket {} does not exist — VM is not running",
                self.socket_path.display()
            );
        }
        Ok(())
    }

    /// Load a sealed snapshot into a fresh VMM, leaving vCPUs paused.
    ///
    /// `clean_vsock` selects the launcher: a plain instance restore starts a
    /// VMM that re-creates the host vsock socket, while a fork restore keeps
    /// the paths its private mount namespace already remapped.
    fn load_snapshot_inner(&self, dir: &Path, clean_vsock: bool) -> Result<()> {
        let vm_dir = self
            .socket_path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("Firecracker socket path has no parent directory"))?;
        let socket_str = self.socket_path.to_string_lossy();

        // Firecracker refuses `/snapshot/load` on a VMM that has already
        // started a microVM. If a previous pause left the process alive, stop
        // it; if it already exited, just start a fresh blank VMM. Either way
        // resume from the sealed snapshot rather than assuming a live API. Only
        // this VM's own Firecracker is ever signalled: a pid left from before
        // a reboot may name another process now.
        self.stop_own_vmm(vm_dir)
            .with_context(|| "stopping paused Firecracker before snapshot restore")?;
        super::start_vm_firecracker_scoped(
            &vm_dir.to_string_lossy(),
            &socket_str,
            clean_vsock,
            &self.restore_scope_prefix(vm_dir, snapshot_guest_memory_mib(dir)),
        )
        .with_context(|| "starting fresh Firecracker for snapshot restore")?;

        // `resume_vm: false` — vCPUs stay paused so the device-model guard in
        // `verify_and_resume_from_dir` can inspect `GET /vm/config` before
        // anything executes.
        let body = serde_json::json!({
            "snapshot_path": format!("{}/{}", dir.display(), VMSTATE_FILENAME),
            "mem_backend": {
                "backend_type": "File",
                "backend_path": format!("{}/{}", dir.display(), MEM_FILENAME),
            },
            "resume_vm": false,
        })
        .to_string();
        if let Err(e) = super::api_put_socket(&socket_str, "/snapshot/load", &body) {
            let state_file = dir.join(VMSTATE_FILENAME);
            // Firecracker has already refused before any guest code ran; this
            // only names the refusal when the state itself could not be decoded.
            if let Some(undecodable) =
                super::snapshot_decode::explain_load_failure(&e, &self.socket_path, &state_file)
            {
                return Err(e.context(undecodable));
            }
            return Err(e).context("PUT /snapshot/load");
        }
        Ok(())
    }
}

/// The guest RAM a snapshot restores, in MiB, read off the size of its memory
/// file.
///
/// The memory file is the guest's RAM byte for byte, so its length is the
/// guest size the restored VMM will map — whatever any record says. Zero when
/// it cannot be read, which leaves the VMM without a memory ceiling rather than
/// with one sized from nothing.
pub(crate) fn snapshot_guest_memory_mib(dir: &Path) -> u32 {
    const BYTES_PER_MIB: u64 = 1024 * 1024;
    std::fs::metadata(dir.join(MEM_FILENAME))
        .ok()
        .and_then(|meta| u32::try_from(meta.len().div_ceil(BYTES_PER_MIB)).ok())
        .unwrap_or(0)
}

impl SnapshotIO for FirecrackerIO {
    fn create_snapshot(&self, dir: &Path) -> Result<()> {
        self.ensure_socket()?;
        // Pause vCPUs first (Firecracker requires a paused VM
        // before /snapshot/create). PATCH /vm.
        super::call(
            &self.socket_path,
            "PATCH",
            "/vm",
            Some(r#"{"state":"Paused"}"#),
        )
        .with_context(|| "PATCH /vm Paused")?;

        let payload = format!(
            r#"{{"snapshot_type":"Full","snapshot_path":"{}/{}","mem_file_path":"{}/{}"}}"#,
            dir.display(),
            VMSTATE_FILENAME,
            dir.display(),
            MEM_FILENAME,
        );
        super::call(&self.socket_path, "PUT", "/snapshot/create", Some(&payload))
            .with_context(|| "PUT /snapshot/create")?;
        Ok(())
    }

    fn load_snapshot_paused(&self, dir: &Path) -> Result<()> {
        self.load_snapshot_inner(dir, true)
    }

    fn load_snapshot_for_fork_paused(&self, dir: &Path) -> Result<()> {
        self.load_snapshot_inner(dir, false)
    }

    fn restored_network_interface_count(&self) -> Result<usize> {
        self.ensure_socket()?;
        let body = super::call(&self.socket_path, "GET", "/vm/config", None)
            .with_context(|| "GET /vm/config")?;
        let model: super::RestoredDeviceModel =
            serde_json::from_str(&body).with_context(|| "parsing GET /vm/config response")?;
        Ok(model.network_interfaces.len())
    }

    fn resume(&self) -> Result<()> {
        self.ensure_socket()?;
        super::call(
            &self.socket_path,
            "PATCH",
            "/vm",
            Some(r#"{"state":"Resumed"}"#),
        )
        .with_context(|| "PATCH /vm Resumed")?;
        Ok(())
    }

    fn teardown_paused(&self) -> Result<()> {
        // This restore attempt's fresh Firecracker must not outlive a refusal:
        // a NIC-carrying VMM sitting paused is exactly the state the
        // device-model guard exists to prevent from ever resuming, and a
        // resumed guest that did not reseed must not keep running on its
        // snapshot's random state. The result is the stop's own, so a caller
        // that reports "stopped" has a stopped process behind it.
        let vm_dir = self
            .socket_path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("Firecracker socket path has no parent directory"))?;
        self.stop_own_vmm(vm_dir)?;
        // The API socket is dead with its process; the next restore starts a
        // fresh VMM that binds a new one.
        let _ = std::fs::remove_file(&self.socket_path);
        Ok(())
    }
}

/// Stop the Firecracker a snapshot restore started, recorded in `pid_file`.
///
/// No marker means no VMM was started, so there is nothing to stop. A marker
/// that cannot be read is an error rather than a guess. A recorded pid that
/// `is_ours` does not confirm as this VM's Firecracker is never signalled: the
/// VMM is already gone and the pid may since have been reused, by an unrelated
/// process or by another VM's Firecracker, so only the stale marker is
/// removed. Otherwise `terminate` is the verified stop: it
/// succeeds only once that pid is gone, and removes the marker then.
fn stop_restored_vmm(
    name: &str,
    pid_file: &Path,
    is_ours: impl FnOnce(u32) -> Result<bool>,
    terminate: impl FnOnce(&str, u32, &Path) -> Result<()>,
) -> Result<()> {
    let recorded = match std::fs::read_to_string(pid_file) {
        Ok(recorded) => recorded,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error).with_context(|| format!("reading {}", pid_file.display()));
        }
    };
    let pid = recorded
        .trim()
        .parse::<u32>()
        .with_context(|| format!("parsing the Firecracker pid in {}", pid_file.display()))?;
    if !is_ours(pid)
        .with_context(|| format!("checking whether pid {pid} is still this VM's Firecracker"))?
    {
        let _ = std::fs::remove_file(pid_file);
        return Ok(());
    }
    terminate(name, pid, pid_file)
        .with_context(|| format!("stopping the restored Firecracker for VM '{name}'"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_restore_that_started_no_vmm_has_nothing_to_stop() {
        let dir = tempfile::tempdir().expect("tempdir");
        stop_restored_vmm(
            "vm-a",
            &dir.path().join("fc.pid"),
            |_| panic!("no marker, nothing to probe"),
            |_, _, _| panic!("no marker, no process to stop"),
        )
        .expect("nothing to stop");
    }

    #[test]
    fn the_recorded_pid_is_the_one_stopped() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pid_file = dir.path().join("fc.pid");
        std::fs::write(&pid_file, "4242\n").unwrap();
        let mut stopped = None;
        stop_restored_vmm(
            "vm-a",
            &pid_file,
            |_| Ok(true),
            |name, pid, _| {
                stopped = Some((name.to_string(), pid));
                Ok(())
            },
        )
        .expect("stopped");
        assert_eq!(stopped, Some(("vm-a".to_string(), 4242)));
    }

    #[test]
    fn a_stop_that_fails_is_reported_not_swallowed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pid_file = dir.path().join("fc.pid");
        std::fs::write(&pid_file, "4242").unwrap();
        let error = stop_restored_vmm(
            "vm-a",
            &pid_file,
            |_| Ok(true),
            |_, _, _| bail!("still running after SIGTERM and SIGKILL"),
        )
        .expect_err("a surviving process is an error");
        let message = format!("{error:#}");
        assert!(message.contains("still running"), "{message}");
        assert!(message.contains("vm-a"), "{message}");
    }

    #[test]
    fn an_unreadable_marker_is_an_error_not_a_guess() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pid_file = dir.path().join("fc.pid");
        std::fs::write(&pid_file, "not-a-pid").unwrap();
        stop_restored_vmm(
            "vm-a",
            &pid_file,
            |_| panic!("an unparsable pid is never probed"),
            |_, _, _| panic!("an unparsable pid is never signalled"),
        )
        .expect_err("refused");
    }

    /// A recorded pid that no longer names a Firecracker process may have
    /// been reused by an unrelated process, so it is never signalled; the
    /// stale marker is removed and the VMM counts as already stopped.
    #[test]
    fn a_recycled_pid_is_never_signalled() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pid_file = dir.path().join("fc.pid");
        std::fs::write(&pid_file, "4242").unwrap();
        let mut probed = None;
        stop_restored_vmm(
            "vm-a",
            &pid_file,
            |pid| {
                probed = Some(pid);
                Ok(false)
            },
            |_, _, _| panic!("a pid that is not Firecracker must not be signalled"),
        )
        .expect("already stopped");
        assert_eq!(probed, Some(4242));
        assert!(!pid_file.exists(), "the stale marker is removed");
    }

    #[test]
    fn a_liveness_probe_that_fails_is_an_error_not_a_kill() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pid_file = dir.path().join("fc.pid");
        std::fs::write(&pid_file, "4242").unwrap();
        stop_restored_vmm(
            "vm-a",
            &pid_file,
            |_| bail!("cannot read /proc"),
            |_, _, _| panic!("an unknown pid is never signalled"),
        )
        .expect_err("refused");
        assert!(pid_file.exists(), "the marker is kept for a retry");
    }
}
