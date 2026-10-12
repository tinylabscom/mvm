//! Source and template builds. Acquisition is explicit here, never a launch fallback.
use std::path::Path;

use anyhow::{Context, Result};
use mvm_build::pipeline::BuildMode;
use mvm_core::manifest::{
    MANIFEST_SCHEMA_VERSION, Manifest, PersistedManifest, Provenance, key_for_manifest_identity,
};
use mvm_core::template::TemplateRevision;
use mvm_runtime::vm::template::lifecycle;

pub struct ManifestBuildReport {
    pub manifest: PersistedManifest,
    pub revision: TemplateRevision,
}

/// Resolve relative sources against the manifest, not the caller's cwd.
pub fn prepare_manifest(manifest: &Manifest, path: &Path) -> Result<PersistedManifest> {
    let canonical = path
        .canonicalize()
        .with_context(|| format!("Failed to canonicalize manifest path {}", path.display()))?;
    let backend = mvm_runtime::backend::AnyBackend::auto_select()
        .name()
        .to_string();
    let mut persisted =
        PersistedManifest::from_manifest(manifest, &canonical, &backend, Provenance::current())?;
    if manifest.image.is_some() {
        return Ok(persisted);
    }
    let flake = manifest.flake_ref();
    persisted.flake_ref = if flake == "." {
        canonical
            .parent()
            .context("manifest has no parent")?
            .display()
            .to_string()
    } else if !flake.contains(':') && !Path::new(flake).is_absolute() {
        canonical
            .parent()
            .context("manifest has no parent")?
            .join(flake)
            .display()
            .to_string()
    } else {
        flake.to_owned()
    };
    Ok(persisted)
}

pub fn build_manifest(
    path: &Path,
    force: bool,
    update_hash: bool,
    mode: BuildMode,
) -> Result<ManifestBuildReport> {
    let manifest = Manifest::read_file(path)?;
    let persisted = prepare_manifest(&manifest, path)?;
    let revision = match manifest.image.as_deref() {
        Some(reference) => build_image_manifest(&persisted, reference, mode)?,
        None => build_flake_manifest(&persisted, force, update_hash, mode)?,
    };
    Ok(ManifestBuildReport {
        manifest: persisted,
        revision,
    })
}

pub fn build_flake_manifest(
    persisted: &PersistedManifest,
    force: bool,
    update_hash: bool,
    mode: BuildMode,
) -> Result<TemplateRevision> {
    prepare_builder()?;
    crate::builder_images::local_pair::seed_pair_workload_kernel_cache()?;
    let revision = lifecycle::template_build_from_manifest(persisted, force, update_hash, mode)
        .inspect_err(|error| audit_build_error("manifest", &persisted.manifest_path, error))?;
    audit_build_ok(
        "manifest",
        &persisted.manifest_path,
        &persisted.manifest_hash,
        &revision.revision_hash,
    );
    super::record_flake_build_node(persisted, &revision)?;
    Ok(revision)
}

pub fn build_image_manifest(
    persisted: &PersistedManifest,
    reference: &str,
    mode: BuildMode,
) -> Result<TemplateRevision> {
    // The image administration service alone owns materialization and trust receipts.
    let image = crate::image_admin::prepare_image(
        &crate::image_admin::PrepareImageRequest {
            cache_root: crate::image_admin::oci_cache_root(),
            reference: reference.to_owned(),
            prod: matches!(mode, BuildMode::Prod),
        },
        None,
        &crate::image_admin::TransferProgress::default(),
    )?;
    let kernel = crate::builder_images::default_microvm::prepare_workload_kernel()
        .context("preparing the workload kernel for an image-backed build")?;
    let revision = lifecycle::template_build_from_image(
        persisted,
        &lifecycle::ImageBuildSources {
            rootfs: image.rootfs_path,
            kernel: kernel.into(),
            image_ref: reference.to_owned(),
        },
        mode,
    )
    .inspect_err(|error| audit_build_error("manifest", &persisted.manifest_path, error))?;
    audit_build_ok(
        "manifest",
        &persisted.manifest_path,
        &persisted.manifest_hash,
        &revision.revision_hash,
    );
    Ok(revision)
}

fn prepare_builder() -> Result<()> {
    crate::host_runtime::initialize();
    if std::env::var("MVM_BUILD_STUB_OUTDIR")
        .map(|value| value.trim().is_empty())
        .unwrap_or(true)
    {
        crate::builder_images::bootstrap::bootstrap_builder_vm_image()
            .context("ensuring the builder VM image before flake build")?;
    }
    Ok(())
}

pub fn resolve_flake_ref(reference: &str) -> Result<String> {
    mvm_core::naming::validate_flake_ref(reference)
        .with_context(|| format!("Invalid flake reference: {reference:?}"))?;
    if reference.contains(':') {
        Ok(reference.to_owned())
    } else {
        Ok(Path::new(reference)
            .canonicalize()
            .with_context(|| format!("Flake path '{reference}' does not exist"))?
            .to_string_lossy()
            .into_owned())
    }
}

pub fn build_flake(
    reference: &str,
    profile: Option<&str>,
    mode: BuildMode,
) -> Result<mvm_build::dev_build::DevBuildResult> {
    let resolved = resolve_flake_ref(reference)?;
    prepare_builder()?;
    let env = mvm_runtime::build_env::default_build_env();
    mvm_core::launch_trace::record_image_build();
    let result = mvm_build::dev_build::dev_build(env.as_ref(), &resolved, profile, mode)
        .inspect_err(|error| audit_build_error("flake", &resolved, error))?;
    audit_build_ok("flake", &resolved, "", &result.revision_hash);
    Ok(result)
}

pub fn build_mvmfile(path: &str, output: Option<&str>) -> Result<String> {
    crate::host_runtime::initialize();
    let result = mvm_runtime::image::build(path, output)
        .inspect_err(|error| audit_build_error("mvmfile", path, error))?;
    audit_build_ok("mvmfile", path, "", &result);
    Ok(result)
}

pub fn build_flake_to_slot(reference: &str, profile: Option<&str>) -> Result<String> {
    let resolved = resolve_flake_ref(reference)?;
    prepare_builder()?;
    if std::env::var("MVM_BUILD_STUB_OUTDIR")
        .map(|value| value.trim().is_empty())
        .unwrap_or(true)
    {
        crate::builder_images::default_microvm::prepare_workload_kernel()
            .context("preparing the dm-verity-capable workload kernel for flake slot")?;
    }
    let backend = mvm_runtime::backend::AnyBackend::auto_select()
        .name()
        .to_string();
    let persisted = flake_slot_manifest(&resolved, profile, &backend);
    let revision =
        lifecycle::template_build_from_manifest(&persisted, false, false, BuildMode::Dev)
            .with_context(|| {
                format!(
                    "building flake {resolved:?} into slot {}",
                    persisted.manifest_hash
                )
            })?;
    audit_build_ok(
        "flake-slot",
        &resolved,
        &persisted.manifest_hash,
        &revision.revision_hash,
    );
    super::record_flake_build_node(&persisted, &revision)?;
    Ok(persisted.manifest_hash)
}

pub fn flake_slot_manifest(
    reference: &str,
    profile: Option<&str>,
    backend: &str,
) -> PersistedManifest {
    let synthetic_path = format!("<flake-slot>/{reference}");
    PersistedManifest {
        schema_version: MANIFEST_SCHEMA_VERSION,
        manifest_path: synthetic_path.clone(),
        manifest_hash: key_for_manifest_identity(&synthetic_path),
        flake_ref: reference.to_owned(),
        profile: profile.unwrap_or("default").to_owned(),
        vcpus: 2,
        mem_mib: 512,
        mem_initial_mib: None,
        data_disk_mib: 0,
        name: None,
        backend: backend.to_owned(),
        provenance: Provenance::current(),
        created_at: mvm_core::time::utc_now(),
        updated_at: mvm_core::time::utc_now(),
    }
}

fn audit_build_ok(mode: &str, source: &str, slot_hash: &str, artifact: &str) {
    let detail = if slot_hash.is_empty() {
        format!("mode={mode} source={source} artifact={artifact}")
    } else {
        format!("mode={mode} source={source} slot_hash={slot_hash} artifact={artifact}")
    };
    mvm_core::audit_emit!(TemplateBuild, "{detail}");
}

fn audit_build_error(mode: &str, source: &str, error: &anyhow::Error) {
    let message = error.to_string();
    let head = message.lines().next().unwrap_or("").trim();
    mvm_core::audit_emit!(
        TemplateBuildError,
        "mode={mode} source={source} error={head}"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slot_synthesis_never_canonicalizes_the_synthetic_identity() {
        let persisted = flake_slot_manifest("/missing/flake", Some("minimal"), "mock");
        assert_eq!(persisted.manifest_path, "<flake-slot>//missing/flake");
        assert_eq!(
            persisted.manifest_hash,
            key_for_manifest_identity(&persisted.manifest_path)
        );
        assert_eq!(persisted.profile, "minimal");
        assert_eq!(persisted.flake_ref, "/missing/flake");
    }

    #[test]
    fn invalid_source_is_refused_before_acquisition() {
        assert!(resolve_flake_ref("").is_err());
        assert!(resolve_flake_ref("/missing/mvm-source-fixture").is_err());
    }

    #[test]
    fn image_manifest_refusal_does_not_prepare_a_kernel_or_slot() {
        let home = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());
        let persisted = flake_slot_manifest("fixture", None, "mock");
        let error =
            build_image_manifest(&persisted, "rootfs-dir:/missing", BuildMode::Prod).unwrap_err();
        assert!(error.to_string().contains("local sources are dev-only"));
        assert!(!home.path().join("cache").exists());
    }

    #[test]
    fn manifest_source_is_resolved_against_its_own_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("mvm.toml");
        std::fs::write(&path, "flake = \"./app\"\n").unwrap();
        let manifest = Manifest::read_file(&path).unwrap();
        let persisted = prepare_manifest(&manifest, &path).unwrap();
        let canonical = path.canonicalize().unwrap();
        assert_eq!(
            persisted.flake_ref,
            canonical
                .parent()
                .unwrap()
                .join("./app")
                .display()
                .to_string()
        );
        assert_eq!(
            persisted.manifest_hash,
            key_for_manifest_identity(&canonical.display().to_string())
        );
    }
}
