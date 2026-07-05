//! `LocalBackend` — the `MvmClient` over this host's microVMs, in-process.
//!
//! Split out of `mvm-client` so that crate's manifest carries no `mvm-*`
//! dependency (see this crate's `Cargo.toml` for the cycle it avoids).
//!
//! `list`/`stop`/`logs` go straight to the backend dispatch (they act on VMs
//! that already exist, so they carry no admission concern). `run` boots through
//! the signed-plan admission gate in-process — no subprocess, no CLI. It
//! resolves the spec's image to a host-materialized rootfs — a ready
//! `rootfs.ext4`, an unpacked OCI directory (inject runtime + pure-materialize),
//! or a registry ref (pull + unpack + inject + materialize) — reusing the exact
//! `mvm_build::run_image` orchestration the CLI's `run --image` uses, then hands
//! it to `mvm_hostd::run::admit_and_boot_local`. A workload never boots on a
//! path that skipped admission.

use std::io::Cursor;
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use flate2::read::GzDecoder;
use mvm_backend::AnyBackend;
use mvm_core::protocol::vm_backend::{VmId, VmInfo, VmStatus};
use mvm_hostd::plan_admission::{InMemoryNonceLedger, SystemClock};
use mvm_hostd::run::{LocalRunContext, LocalRunRequest, admit_and_boot_local};
use mvm_oci::{
    ImageReference, LayerDescriptor, LayerFetchOptions, LinuxPlatform, OciLayerFetcher,
    OciManifestFetcher, UnpackOptions, unpack_layer,
};

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

/// How a `spec.image` string is interpreted.
#[derive(Debug, PartialEq, Eq)]
enum ImageSource {
    /// A path to an already-materialized `rootfs.ext4` — boot it directly.
    Materialized(PathBuf),
    /// A path to an unpacked OCI rootfs directory — inject runtime + materialize.
    UnpackedDir(PathBuf),
    /// Anything else is treated as an OCI registry reference — pull + unpack +
    /// inject + materialize.
    Registry(String),
}

/// Classify a `spec.image`: an existing file is a materialized rootfs, an
/// existing directory is an unpacked tree, everything else is a registry ref.
fn classify_image(image: &str) -> ImageSource {
    let path = Path::new(image);
    if path.is_file() {
        ImageSource::Materialized(path.to_path_buf())
    } else if path.is_dir() {
        ImageSource::UnpackedDir(path.to_path_buf())
    } else {
        ImageSource::Registry(image.to_string())
    }
}

/// Resolve `spec.image` to a host `rootfs.ext4` path, materializing in-process
/// as needed (no subprocess, no CLI). Registry pulls are async; the dir +
/// pre-materialized cases are synchronous.
async fn resolve_local_rootfs(image: &str, name: &str) -> Result<PathBuf> {
    match classify_image(image) {
        ImageSource::Materialized(path) => Ok(path),
        ImageSource::UnpackedDir(dir) => materialize_from_dir(&dir, name),
        ImageSource::Registry(reference) => {
            let staging = tempfile::tempdir().map_err(backend_err)?;
            pull_image_to_dir(&reference, staging.path()).await?;
            materialize_from_dir(staging.path(), name)
        }
    }
}

/// Cache location for a locally-materialized run rootfs, keyed by machine name.
fn run_rootfs_output(name: &str) -> PathBuf {
    let key: String = name
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    PathBuf::from(mvm_core::config::mvm_cache_dir())
        .join("local-run")
        .join(key)
        .join("rootfs.ext4")
}

/// Inject the mvm runtime into an unpacked tree and materialize it into the
/// run-rootfs cache, reusing the CLI's shared `run_image` orchestration.
fn materialize_from_dir(dir: &Path, name: &str) -> Result<PathBuf> {
    let output = run_rootfs_output(name);
    let cache_root = PathBuf::from(mvm_core::config::mvm_cache_dir());
    // `None`: this library carries no embedded guest binaries (only the mvmctl
    // binary does), so it resolves them from the cache or a source checkout.
    mvm_build::run_image::inject_and_materialize(&cache_root, dir, &output, name, None)
        .map_err(backend_err)?;
    Ok(output)
}

/// Pull a public OCI registry reference and unpack every layer into `dest`,
/// reusing mvm-oci's fetch + hardened unpacker (gzip is decoded here, at the
/// crate boundary, keeping mvm-oci decompressor-free by design).
async fn pull_image_to_dir(reference: &str, dest: &Path) -> Result<()> {
    let image_ref: ImageReference = reference
        .parse()
        .map_err(|e| backend_err(format!("parse image reference {reference:?}: {e}")))?;
    let manifest_fetcher = OciManifestFetcher::new();
    let manifest = manifest_fetcher
        .fetch_linux_platform_manifest(&image_ref, &LinuxPlatform::for_current_arch())
        .await
        .map_err(|e| backend_err(format!("fetch manifest for {reference}: {e}")))?;
    let layers = manifest
        .layers()
        .map_err(|e| backend_err(format!("parse layers for {reference}: {e}")))?;
    if layers.is_empty() {
        return Err(backend_err(format!("OCI image {reference} has no layers")));
    }
    let layer_fetcher =
        OciLayerFetcher::from_manifest_fetcher(&manifest_fetcher, LayerFetchOptions::default());
    for layer in &layers {
        let mut bytes = Vec::new();
        layer_fetcher
            .fetch_layer(&image_ref, layer, &mut bytes)
            .await
            .map_err(|e| backend_err(format!("fetch layer {}: {e}", layer.digest)))?;
        unpack_one_layer(layer, &bytes, dest)?;
    }
    Ok(())
}

/// Unpack one layer's bytes into `dest`, decompressing gzip layers first.
fn unpack_one_layer(layer: &LayerDescriptor, bytes: &[u8], dest: &Path) -> Result<()> {
    let mt = &layer.media_type;
    let report = if mt.ends_with("+gzip") || mt.ends_with(".gzip") || mt.contains("tar.gzip") {
        unpack_layer(
            GzDecoder::new(Cursor::new(bytes)),
            dest,
            &UnpackOptions::default(),
        )
    } else {
        unpack_layer(Cursor::new(bytes), dest, &UnpackOptions::default())
    }
    .map_err(|e| backend_err(format!("unpack layer {}: {e}", layer.digest)))?;
    if !report.refused.is_empty() {
        return Err(backend_err(format!(
            "layer {} unpack refused entries: {:?}",
            layer.digest, report.refused
        )));
    }
    Ok(())
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
        let rootfs = resolve_local_rootfs(&spec.image, &spec.name).await?;
        let (verity_path, roothash) = host_verity_sidecars(&rootfs);

        let req = LocalRunRequest {
            name: spec.name.clone(),
            rootfs_path: rootfs,
            // libkrun/Vz/mock carry their own kernel; a Firecracker local run
            // that needs an explicit kernel path is a later slice.
            kernel_path: None,
            verity_path: verity_path.map(PathBuf::from),
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

    #[test]
    fn classify_image_routes_file_dir_and_registry() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("rootfs.ext4");
        std::fs::write(&file, b"x").unwrap();

        // An existing file → a materialized rootfs.
        assert_eq!(
            classify_image(&file.to_string_lossy()),
            ImageSource::Materialized(file.clone())
        );
        // An existing directory → an unpacked tree.
        assert_eq!(
            classify_image(&dir.path().to_string_lossy()),
            ImageSource::UnpackedDir(dir.path().to_path_buf())
        );
        // Anything else → a registry reference (no network touched here).
        assert_eq!(
            classify_image("docker.io/library/alpine:3.20"),
            ImageSource::Registry("docker.io/library/alpine:3.20".into())
        );
    }

    #[test]
    fn run_rootfs_output_is_name_sanitized_and_under_cache() {
        let out = run_rootfs_output("my/app:1.2");
        assert!(out.ends_with("rootfs.ext4"));
        let s = out.to_string_lossy();
        assert!(s.contains("local-run"));
        // Path-hostile characters in the name are replaced.
        assert!(s.contains("my_app_1_2"));
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
