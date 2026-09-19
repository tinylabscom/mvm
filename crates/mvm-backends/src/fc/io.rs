//! The Firecracker `SnapshotIO`: pause/create/load/resume over the VMM's
//! API socket, plus the pid-file plumbing the socket lifecycle needs.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use mvm_core::crypto::snapshot_hmac::{MEM_FILENAME, VMSTATE_FILENAME};

use mvm_vmm::host::shell::{run_in_vm, shell_quote};
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
        let pid_file = vm_dir.join("fc.pid");
        let pid_file_str = pid_file.to_string_lossy();

        // Firecracker refuses `/snapshot/load` on a VMM that has already
        // started a microVM. If a previous pause left the process alive, stop
        // it; if it already exited, just start a fresh blank VMM. Either way
        // resume from the sealed snapshot rather than assuming a live API.
        if super::host::is_vm_running(&pid_file_str)? {
            let q_pid = shell_quote(&pid_file_str);
            run_in_vm(&format!(
                "sudo kill -9 \"$(cat {q_pid})\" 2>/dev/null; sleep 1"
            ))
            .with_context(|| "stopping paused Firecracker before snapshot restore")?;
        }
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
        // Best-effort: this restore attempt's fresh FC process must not
        // linger paused once the guard has refused it — a NIC-carrying VMM
        // sitting paused is exactly the state this guard exists to prevent
        // from ever resuming. Never surfaced to the caller (`verify_and_resume_from_dir`
        // discards this `Result`), so any failure here is logged, not propagated.
        let Some(vm_dir) = self.socket_path.parent() else {
            return Ok(());
        };
        let pid_file = vm_dir.join("fc.pid");
        if !pid_file.exists() {
            return Ok(());
        }
        let pid_file_str = pid_file.to_string_lossy();
        let q_pid = shell_quote(&pid_file_str);
        let _ = run_in_vm(&format!("sudo kill -9 \"$(cat {q_pid})\" 2>/dev/null"));
        Ok(())
    }
}
