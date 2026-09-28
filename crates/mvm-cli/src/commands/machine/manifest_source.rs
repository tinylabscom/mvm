//! Where a persistent machine's defaults come from when it is sourced from
//! an image-backed `mvm.toml`: the machine workflow, the directory relative
//! volume paths resolve against, and the manifest's contribution to the
//! machine's policy.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use mvm_core::manifest::{Manifest, ManifestMachineWorkflow, resolve_manifest_config_path};

#[derive(Debug)]
pub(super) struct MachineManifestSource {
    pub(super) workflow: ManifestMachineWorkflow,
    pub(super) base_dir: PathBuf,
    /// The manifest's `[policy]` and `[network] allow_hosts`.
    pub(super) project: mvm_client::policy_profiles::ProjectPolicy,
}

pub(super) fn load_machine_manifest_source(arg: &Path) -> Result<MachineManifestSource> {
    let manifest_path = resolve_manifest_config_path(arg)
        .with_context(|| format!("resolving machine manifest {}", arg.display()))?;
    let manifest = Manifest::read_file(&manifest_path)
        .with_context(|| format!("reading machine manifest {}", manifest_path.display()))?;
    if !manifest.network.routes.is_empty() {
        bail!(
            "{} declares [[network.routes]], which a persistent machine does not record yet; \
             a restart would drop them. Run it transiently, or remove the routes",
            manifest_path.display()
        );
    }
    let workflow = manifest.machine_workflow().ok_or_else(|| {
        anyhow!(
            "machine create --manifest requires an image-backed manifest; flake-backed manifests belong to `mvmctl machine run --flake`"
        )
    })?;
    let base_dir = manifest_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();
    let project =
        mvm_client::policy_profiles::ProjectPolicy::from_manifest(&manifest_path, &manifest);
    Ok(MachineManifestSource {
        workflow,
        base_dir,
        project,
    })
}

pub(super) fn absolutize_manifest_volume_spec(spec: &str, base_dir: &Path) -> Result<String> {
    fn simplify_path(path: PathBuf) -> PathBuf {
        let mut simplified = PathBuf::new();
        for component in path.components() {
            match component {
                std::path::Component::CurDir => {}
                std::path::Component::ParentDir => {
                    simplified.pop();
                }
                other => simplified.push(other.as_os_str()),
            }
        }
        simplified
    }

    let absolute_host = |host: &str| -> String {
        let path = Path::new(host);
        if path.is_absolute() {
            host.to_string()
        } else {
            simplify_path(base_dir.join(path))
                .to_string_lossy()
                .into_owned()
        }
    };

    match crate::commands::shared::parse_volume_spec(spec)? {
        crate::commands::shared::VolumeSpec::DirShare {
            host_dir,
            guest_mount,
            read_only,
        } => Ok(format!(
            "{}:{guest_mount}:{}",
            absolute_host(&host_dir),
            if read_only { "ro" } else { "rw" }
        )),
        crate::commands::shared::VolumeSpec::Disk {
            host,
            guest,
            size,
            read_only,
            encrypted,
        } => {
            let mut rendered = format!(
                "{}:{guest}:{size}:{}",
                absolute_host(&host),
                if read_only { "ro" } else { "rw" }
            );
            if encrypted {
                rendered.push_str(":enc");
            }
            Ok(rendered)
        }
    }
}
