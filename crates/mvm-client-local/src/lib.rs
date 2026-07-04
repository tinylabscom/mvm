//! `LocalBackend` — the `MvmClient` over this host's microVMs, in-process.
//!
//! Split out of `mvm-client` so that crate's manifest carries no `mvm-*`
//! dependency (see this crate's `Cargo.toml` for the cycle it avoids).
//!
//! `list`/`stop`/`logs` go straight to the backend dispatch (they act on VMs
//! that already exist, so they carry no admission concern). `run` boots through
//! the signed-plan admission gate in-process — no subprocess, no CLI — by
//! resolving the spec's image to a host-materialized rootfs and handing it to
//! `mvm_hostd::run::admit_and_boot_local`. Image refs that still need a registry
//! pull or an unpacked-dir materialize step fail honestly (that resolution is
//! not wired into this backend yet); a workload never boots on a path that
//! skipped admission.

use std::path::Path;

use async_trait::async_trait;
use mvm_backend::AnyBackend;
use mvm_core::protocol::vm_backend::{VmId, VmInfo, VmStatus};
use mvm_hostd::plan_admission::{InMemoryNonceLedger, SystemClock};
use mvm_hostd::run::{LocalRunContext, LocalRunRequest, admit_and_boot_local};

use mvm_client::dto::{
    ExecResult, LogOpts, MachineFilter, MachineId, MachineSpec, MachineState, MachineStatus,
};
use mvm_client::{MvmClient, MvmError, Result};

/// Drives the host's VM backend directly. Construct with [`LocalBackend::new`]
/// (auto-selected backend) or [`LocalBackend::with_hypervisor`].
pub struct LocalBackend {
    backend: AnyBackend,
}

impl LocalBackend {
    pub fn new() -> Self {
        Self {
            backend: AnyBackend::auto_select(),
        }
    }

    pub fn with_hypervisor(name: &str) -> Self {
        Self {
            backend: AnyBackend::from_hypervisor(name),
        }
    }
}

impl Default for LocalBackend {
    fn default() -> Self {
        Self::new()
    }
}

fn map_status(s: &VmStatus) -> MachineStatus {
    match s {
        VmStatus::Running => MachineStatus::Running,
        VmStatus::Starting => MachineStatus::Starting,
        // A paused VM isn't accepting work; surface it as stopped rather than
        // inventing a facade state that callers don't model.
        VmStatus::Stopped | VmStatus::Paused => MachineStatus::Stopped,
        VmStatus::Failed { .. } => MachineStatus::Failed,
    }
}

fn to_state(v: VmInfo) -> MachineState {
    MachineState {
        id: MachineId(v.id.0),
        name: v.name,
        status: map_status(&v.status),
    }
}

fn backend_err(e: impl std::fmt::Display) -> MvmError {
    MvmError::Backend {
        reason: e.to_string(),
    }
}

/// Resolve `image` to a host path pointing at an already-materialized ext4
/// rootfs. Only a direct path to a materialized image boots in-process today;
/// an unpacked-dir materialize step and registry pulls are deferred to a later
/// slice and fail with a clear message rather than a partial boot.
fn resolve_local_rootfs(image: &str) -> Result<std::path::PathBuf> {
    let path = Path::new(image);
    if path.is_file() {
        return Ok(path.to_path_buf());
    }
    if path.is_dir() {
        return Err(backend_err(format!(
            "'{image}' is an unpacked rootfs directory; in-process materialization \
             is not wired into the local backend yet — pre-materialize a rootfs.ext4 \
             or use `mvmctl machine run`"
        )));
    }
    Err(backend_err(format!(
        "in-process local run expects a path to a materialized rootfs.ext4; '{image}' \
         is neither a file nor a directory (registry pulls are not wired into the local \
         backend — use `mvmctl machine run`)"
    )))
}

/// Probe the dm-verity sidecars the pure materializer writes beside the image
/// (`rootfs.verity` + `rootfs.roothash`), reading them from the host filesystem
/// directly. Returns `(verity_path, roothash)` when both are present and the
/// hash is well-formed (64-hex); `(None, None)` for an unverified image.
///
/// Distinct from `mvm_backend::probe_verity_sidecar`, which reads the sidecars
/// from inside a builder VM — wrong for a host-materialized rootfs.
fn host_verity_sidecars(rootfs: &Path) -> (Option<String>, Option<String>) {
    let Some(parent) = rootfs.parent() else {
        return (None, None);
    };
    let verity = parent.join("rootfs.verity");
    let roothash_file = parent.join("rootfs.roothash");
    if !verity.is_file() {
        return (None, None);
    }
    let Ok(raw) = std::fs::read_to_string(&roothash_file) else {
        return (None, None);
    };
    let hash = raw.trim().to_string();
    if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return (None, None);
    }
    (Some(verity.to_string_lossy().into_owned()), Some(hash))
}

#[async_trait]
impl MvmClient for LocalBackend {
    async fn list_machines(&self, filter: MachineFilter) -> Result<Vec<MachineState>> {
        let infos = self.backend.list().map_err(backend_err)?;
        Ok(infos
            .into_iter()
            .map(to_state)
            .filter(|m| filter.matches(m))
            .collect())
    }

    async fn run_machine(&self, spec: MachineSpec) -> Result<MachineState> {
        let rootfs = resolve_local_rootfs(&spec.image)?;
        let (verity_path, roothash) = host_verity_sidecars(&rootfs);

        let req = LocalRunRequest {
            name: spec.name.clone(),
            rootfs_path: rootfs,
            // libkrun/Vz/mock carry their own kernel; a Firecracker local run
            // that needs an explicit kernel path is a later slice.
            kernel_path: None,
            verity_path: verity_path.map(std::path::PathBuf::from),
            roothash,
            cpus: spec.cpus,
            mem_mib: spec.memory_mib,
            backend_name: self.backend.name().to_string(),
        };

        // A fresh per-run ledger: local runs are one-shot from this process, so
        // replay protection spans this admission (the CLI uses the same
        // per-invocation shape). Keys dir `None` → the host signer at
        // `~/.mvm/keys/`.
        let ledger = InMemoryNonceLedger::new();
        let clock = SystemClock;
        let started = admit_and_boot_local(
            &self.backend,
            &req,
            LocalRunContext {
                clock: &clock,
                ledger: &ledger,
                host_signer_keys_dir: None,
            },
        )
        .map_err(backend_err)?;

        Ok(MachineState {
            id: MachineId(started.vm_id.0),
            name: spec.name,
            status: MachineStatus::Running,
        })
    }

    async fn stop_machine(&self, id: &MachineId) -> Result<()> {
        self.backend.stop(&VmId(id.0.clone())).map_err(backend_err)
    }

    async fn machine_logs(&self, id: &MachineId, opts: LogOpts) -> Result<Vec<u8>> {
        let lines = opts.tail_lines.unwrap_or(200);
        let text = self
            .backend
            .logs(&VmId(id.0.clone()), lines, false)
            .map_err(backend_err)?;
        Ok(text.into_bytes())
    }

    async fn exec_machine(&self, _id: &MachineId, _command: Vec<String>) -> Result<ExecResult> {
        // The backend dispatch (`AnyBackend`) exposes no exec seam; in-guest exec
        // goes through the agent RPC path, which is not wired here.
        Err(MvmError::Backend {
            reason: "local exec requires the guest-agent exec seam (not wired)".into(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_maps_all_variants() {
        assert_eq!(map_status(&VmStatus::Running), MachineStatus::Running);
        assert_eq!(map_status(&VmStatus::Starting), MachineStatus::Starting);
        assert_eq!(map_status(&VmStatus::Stopped), MachineStatus::Stopped);
        assert_eq!(map_status(&VmStatus::Paused), MachineStatus::Stopped);
        assert_eq!(
            map_status(&VmStatus::Failed {
                reason: "boom".into()
            }),
            MachineStatus::Failed
        );
    }

    #[tokio::test]
    async fn list_over_mock_backend_succeeds() {
        let be = LocalBackend::with_hypervisor("mock");
        let machines = be.list_machines(MachineFilter::all()).await.unwrap();
        let none = be
            .list_machines(MachineFilter {
                name: Some("definitely-not-present-xyz".into()),
                status: None,
            })
            .await
            .unwrap();
        assert!(none.len() <= machines.len());
    }

    #[tokio::test]
    async fn run_refuses_unresolvable_image_ref() {
        // A registry ref (neither a file nor a dir on this host) fails honestly
        // — the local backend doesn't pull, and never boots without admission.
        let be = LocalBackend::with_hypervisor("mock");
        let spec = MachineSpec {
            name: "w".into(),
            image: "registry.example.com/app:latest".into(),
            cpus: 1,
            memory_mib: 64,
            env: vec![],
        };
        let err = be.run_machine(spec).await.unwrap_err();
        assert!(matches!(err, MvmError::Backend { .. }));
    }

    #[tokio::test]
    async fn run_boots_admitted_plan_from_materialized_rootfs() {
        // Isolate the host signer + mock VM dirs under a tempdir.
        let data = tempfile::tempdir().unwrap();
        // SAFETY: single-threaded test; no other thread reads these vars.
        unsafe {
            std::env::set_var("MVM_DATA_DIR", data.path());
        }
        let rootfs = data.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"hashable-rootfs-bytes\n").unwrap();

        let be = LocalBackend::with_hypervisor("mock");
        let spec = MachineSpec {
            name: "local-boot-from-image-path".into(),
            image: rootfs.to_string_lossy().into_owned(),
            cpus: 1,
            memory_mib: 128,
            env: vec![],
        };
        let state = be
            .run_machine(spec)
            .await
            .expect("in-process admitted boot");
        assert_eq!(state.name, "local-boot-from-image-path");
        assert_eq!(state.status, MachineStatus::Running);
        // The boot really landed a VM: it shows up in the backend listing.
        let listed = be.list_machines(MachineFilter::all()).await.unwrap();
        assert!(
            listed
                .iter()
                .any(|m| m.name == "local-boot-from-image-path")
        );
    }

    #[test]
    fn host_verity_sidecars_reads_well_formed_pair() {
        let dir = tempfile::tempdir().unwrap();
        let rootfs = dir.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"x").unwrap();
        // No sidecars yet → unverified.
        assert_eq!(host_verity_sidecars(&rootfs), (None, None));

        std::fs::write(dir.path().join("rootfs.verity"), b"tree").unwrap();
        let hex = "a".repeat(64);
        std::fs::write(dir.path().join("rootfs.roothash"), format!("{hex}\n")).unwrap();
        let (v, h) = host_verity_sidecars(&rootfs);
        assert!(v.unwrap().ends_with("rootfs.verity"));
        assert_eq!(h.unwrap(), hex);

        // A malformed (non-hex / wrong-length) roothash is rejected.
        std::fs::write(dir.path().join("rootfs.roothash"), "nothex\n").unwrap();
        assert_eq!(host_verity_sidecars(&rootfs), (None, None));
    }
}
