//! Artifact sources and the eligibility boundary shared by explicit warming.

use anyhow::Result;

use super::{MvmConfig, VmStartConfig, warm_eligible_launch};
use crate::commands::{build, bundle, shared, vm};

/// The boot source a warm request names, matching its eventual launch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::commands) enum WarmSource {
    Image(Option<String>),
    Manifest(String),
    Flake {
        flake_ref: String,
        profile: Option<String>,
    },
}

impl WarmSource {
    pub(super) fn from_flags(
        image: Option<String>,
        manifest: Option<String>,
        flake: Option<String>,
        flake_profile: Option<String>,
    ) -> Result<Self> {
        anyhow::ensure!(
            flake_profile.is_none() || flake.is_some(),
            "--flake-profile requires --flake"
        );
        match (image, manifest, flake) {
            (image, None, None) => Ok(Self::Image(image)),
            (None, Some(manifest), None) => Ok(Self::Manifest(manifest)),
            (None, None, Some(flake_ref)) => Ok(Self::Flake {
                flake_ref,
                profile: flake_profile,
            }),
            _ => anyhow::bail!("pool warm takes one of --image, --manifest or --flake"),
        }
    }

    /// Use the launch resolvers, including archive verification and installation.
    pub(super) fn resolve(&self) -> Result<crate::exec::ImageSource> {
        match self {
            Self::Image(reference) => {
                vm::exec::resolve_launch_image_source(reference.as_deref(), false, None)
            }
            Self::Manifest(arg) => {
                let mut manifest = Some(arg.clone());
                bundle::settle_manifest_archive(&mut manifest, false, false)?;
                let settled = manifest.unwrap_or_else(|| arg.clone());
                manifest_template_source(&settled)
            }
            Self::Flake { flake_ref, profile } => {
                let slot = build::build::build_flake_to_slot(flake_ref, profile.as_deref())?;
                Ok(crate::exec::ImageSource::Template(slot))
            }
        }
    }
}

pub(super) fn manifest_template_source(arg: &str) -> Result<crate::exec::ImageSource> {
    match shared::resolve_manifest_arg(arg)? {
        shared::ManifestArgRef::Slot { slot_hash } => {
            Ok(crate::exec::ImageSource::Template(slot_hash))
        }
        shared::ManifestArgRef::WasmModule { .. } => {
            anyhow::bail!("{arg} names a wasm module; the wasm backend has no standby pool to warm")
        }
    }
}

/// What explicit warming and automatic refill prepare.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::commands) struct WarmRequest {
    pub(in crate::commands) source: WarmSource,
    pub(in crate::commands) cpus: u32,
    pub(in crate::commands) memory_mib: u32,
    pub(in crate::commands) target: u32,
    pub(in crate::commands) egress: bool,
}

impl WarmRequest {
    pub(in crate::commands) fn one_at_default_sizing(image: Option<&str>, cfg: &MvmConfig) -> Self {
        Self {
            source: WarmSource::Image(image.map(str::to_string)),
            cpus: cfg.default_cpus,
            memory_mib: cfg.default_memory_mib,
            target: 1,
            egress: false,
        }
    }

    pub(super) fn label(&self) -> String {
        match &self.source {
            WarmSource::Image(Some(image)) => image.clone(),
            WarmSource::Image(None) => "the default image".to_string(),
            WarmSource::Manifest(path) => format!("manifest {path}"),
            WarmSource::Flake { flake_ref, .. } => format!("flake {flake_ref}"),
        }
    }
}

/// Refuse before provisioning keys, taking the spawn lock, or creating capacity
/// that the launch path cannot claim.
pub(super) fn warm_if_eligible<T>(
    config: &VmStartConfig,
    late_volume_slots: u8,
    warm: impl FnOnce() -> Result<T>,
) -> Result<T> {
    anyhow::ensure!(
        warm_eligible_launch(config, late_volume_slots),
        "pool warm: this launch cannot claim a standby; bundles with pinned boot assets \
         must use their verified cold launch path"
    );
    warm()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_flake_profile_requires_a_flake_even_without_cli_parsing() {
        for source in [None, Some("alpine".into())] {
            assert!(WarmSource::from_flags(source, None, None, Some("slim".into())).is_err());
        }
    }
}
