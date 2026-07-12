use anyhow::{Context, Result};
use mvm_build::runtime_overlay::RuntimeOverlayArtifact;
use mvm_core::arch::GuestArch;
use std::path::{Path, PathBuf};

pub(crate) struct RuntimeOverlayAcquireParams<'a> {
    pub(crate) cache_root: &'a Path,
    pub(crate) expected_version: &'a str,
    pub(crate) arch: GuestArch,
    pub(crate) source_checkout_root: Option<&'a Path>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RuntimeOverlayAcquireMode {
    BuildFromSourceCheckout,
    DownloadPublishedArtifact,
}

pub(crate) const RUNTIME_OVERLAY_ACQUIRE_MODE_ENV: &str = "MVM_RUNTIME_OVERLAY_ACQUIRE_MODE";

pub(crate) fn runtime_overlay_source_checkout_root() -> Option<PathBuf> {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir.parent()?.parent()?;
    workspace_root
        .join("nix")
        .join("images")
        .join("runtime-overlay")
        .join("flake.nix")
        .is_file()
        .then(|| workspace_root.to_path_buf())
}

pub(crate) fn runtime_overlay_acquire_mode() -> RuntimeOverlayAcquireMode {
    if let Ok(value) = std::env::var(RUNTIME_OVERLAY_ACQUIRE_MODE_ENV) {
        match value.trim() {
            "build" => return RuntimeOverlayAcquireMode::BuildFromSourceCheckout,
            "download" => return RuntimeOverlayAcquireMode::DownloadPublishedArtifact,
            _ => {}
        }
    }
    if runtime_overlay_source_checkout_root().is_some() {
        RuntimeOverlayAcquireMode::BuildFromSourceCheckout
    } else {
        RuntimeOverlayAcquireMode::DownloadPublishedArtifact
    }
}

pub(crate) fn acquire_runtime_overlay(
    params: &RuntimeOverlayAcquireParams<'_>,
) -> Result<RuntimeOverlayArtifact> {
    if let Some(workspace_root) = params.source_checkout_root {
        return build_runtime_overlay_from_source_checkout(
            workspace_root,
            params.cache_root,
            params.expected_version,
            params.arch,
        )
        .with_context(|| {
            format!(
                "build runtime overlay {} for {} from source checkout {}",
                params.expected_version,
                params.arch,
                workspace_root.display()
            )
        });
    }
    mvm_build::runtime_overlay::download_runtime_overlay(
        params.expected_version,
        params.arch,
        params.cache_root,
    )
    .with_context(|| {
        format!(
            "download runtime overlay {} for {} into {}",
            params.expected_version,
            params.arch,
            params.cache_root.display()
        )
    })
}

fn build_runtime_overlay_from_source_checkout(
    workspace_root: &Path,
    cache_root: &Path,
    expected_version: &str,
    arch: GuestArch,
) -> Result<RuntimeOverlayArtifact> {
    let bins = mvm_build::guest_agent_build::resolve_or_build_runtime_overlay_guest_binaries(
        cache_root,
        expected_version,
        arch,
        workspace_root,
    )
    .context("build guest binaries for the direct runtime-overlay path")?;
    mvm_build::runtime_overlay::build_runtime_overlay_from_guest_binaries(
        cache_root,
        expected_version,
        arch,
        &bins,
    )
    .context("assemble direct runtime-overlay artifact from source-built guest binaries")
}
