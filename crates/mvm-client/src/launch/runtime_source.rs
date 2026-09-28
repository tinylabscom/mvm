//! Runtime-overlay attachment + status resolution for `mvmctl up` boots —
//! the verity-sealed guest-binary overlay every workload backend consumes,
//! and the audit label describing which source strategy actually landed.
//!
//! The optional glibc SDK sidecar rides the same seam: it is resolved from the
//! same version-keyed cache discipline and attached through the same
//! plan-admitted read-only disk mechanism, so there is one attachment path, not
//! two. Where the runtime overlay is attached to every workload, the sidecar is
//! attached only to workloads whose signed plan binds an SDK-served host
//! service.

use anyhow::{Context, Result};

pub use mvm_runtime::sdk_sidecar::SdkSidecarAttachment;
pub use mvm_runtime::universal_initramfs::attach_universal_initramfs_if_cached;

use crate::launch::runtime_overlay::{
    RuntimeOverlayAcquireMode, RuntimeOverlayAcquireParams, acquire_runtime_overlay,
    runtime_overlay_acquire_mode, runtime_overlay_source_checkout_root,
};
use mvm_runtime::ui;

/// Report where this launch's guest binaries come from.
///
/// There is one answer now — the runtime overlay — so this reports whether the
/// overlay was actually attached rather than which of several postures applied.
pub fn emit_runtime_source_status(start_config: &mvm_core::vm_backend::VmStartConfig) {
    let attached = start_config.runtime_overlay_path.is_some();
    tracing::info!(overlay_attached = attached, "resolved guest runtime source");
    ui::info(if attached {
        "Runtime source: overlay attached"
    } else {
        "Runtime source: overlay not attached"
    });
}

fn apply_runtime_overlay_artifact(
    start_config: &mut mvm_core::vm_backend::VmStartConfig,
    artifact: mvm_fs::overlay::RuntimeOverlayArtifact,
) {
    start_config.runtime_overlay_path = Some(artifact.overlay_ext4.display().to_string());
    start_config.runtime_overlay_verity_path = Some(artifact.sidecar.display().to_string());
    start_config.runtime_overlay_version = Some(artifact.version);
    start_config.runtime_overlay_roothash = Some(artifact.roothash);
}

/// Attach the verity-sealed runtime overlay by
/// populating `VmStartConfig`'s overlay fields from the resolver's cache
/// probe. Backends that can consume the sealed overlay attach it as extra
/// read-only block devices and thread the matching roothash through the
/// guest cmdline; unsupported backends ignore the fields.
/// **Fatal on a real backend**: the overlay is the only source of the guest
/// binaries, so a cold cache returns `Err` rather than leaving the fields
/// `None` and booting a guest that cannot reach an agent. The caller's
/// acquisition ladder catches that and builds or downloads. The seeded
/// resolve is a pure cache read — no build, no download, no `nix` — so this
/// is safe on every host.
#[tracing::instrument(skip_all, fields(hypervisor, arch = ?arch))]
pub fn attach_runtime_overlay(
    start_config: &mut mvm_core::vm_backend::VmStartConfig,
    hypervisor: &str,
    resolver: &mvm_fs::overlay::RuntimeOverlayResolver,
    arch: mvm_core::arch::GuestArch,
) -> Result<()> {
    if !matches!(hypervisor, "firecracker" | "hvf" | "qemu" | "libkrun") {
        return Ok(());
    }
    match mvm_build::runtime_overlay::resolve_or_seed_from_default_cache(resolver, arch) {
        Ok(a) => {
            apply_runtime_overlay_artifact(start_config, a);
            Ok(())
        }
        Err(e) => {
            anyhow::bail!("runtime overlay required for {hypervisor} boot but unavailable: {e}")
        }
    }
}

/// Production wrapper: build the resolver from the mvm cache dir + the
/// running mvmctl version, then attach for `hypervisor`. Called at each
/// workload-boot `VmStartConfig` construction in [`run`].
///
/// A selected local image checkout plus the one way this process builds a
/// pair target. The build closure is injected by the CLI, which owns the VM
/// backends; this crate orchestrates caches and refuses stale installs, and
/// never boots anything itself.
pub struct PairArtifactSource<'a> {
    pub checkout: &'a mvm_build::image_source::LocalImageCheckout,
    /// Build (or cache-hit) one image-set target of the pair. Returns the
    /// verified cache entry holding the target's files.
    pub build: &'a mut dyn FnMut(
        &mvm_build::image_source::LocalImageCheckout,
        mvm_build::image_source::ImageBuildTarget,
    ) -> anyhow::Result<mvm_build::image_source::CachedImageSet>,
}

impl PairArtifactSource<'_> {
    fn target(
        role: mvm_build::image_source::ImageBuildRole,
        attr: &str,
    ) -> mvm_build::image_source::ImageBuildTarget {
        mvm_build::image_source::ImageBuildTarget {
            role,
            attr: mvm_build::image_source::FlakeAttr::new(attr)
                .expect("a literal attribute is valid"),
        }
    }

    /// The pair's identity for `target` as it is now: the digest of the pair
    /// cache key. Recorded beside an install; a later boot compares before
    /// trusting the install, so a change in either checkout, the toolchain
    /// pins or a flake lock reinstalls rather than boots stale bytes.
    fn fingerprint(&self, target: &mvm_build::image_source::ImageBuildTarget) -> Result<String> {
        use mvm_build::image_source::KeyInputs;
        let mvm_root = mvm_build::image_source::mvm_source_checkout(
            mvm_build::artifact_acquisition::compiled_channel(),
        )
        .context("a pair build needs the mvm checkout this binary was compiled from")?;
        let key = mvm_build::image_source::LocalImageCacheKey::derive(&KeyInputs {
            images: self.checkout,
            mvm_checkout: &mvm_root,
            target,
            arch: mvm_core::arch::GuestArch::host(),
        })
        .context("reading the pair's cache key inputs")?;
        Ok(key.digest().as_str().to_string())
    }
}

/// Where the pair fingerprint for one overlay install is recorded: a sibling
/// of the installed `<arch>` directory, outside the artifact set the resolver
/// reads.
fn overlay_pair_stamp(
    cache_root: &std::path::Path,
    version: &str,
    arch: &str,
) -> std::path::PathBuf {
    cache_root
        .join("runtime-overlay")
        .join(version)
        .join(format!("{arch}.pair"))
}

fn installed_overlay_pair_fingerprint(
    cache_root: &std::path::Path,
    version: &str,
    arch: &str,
) -> Option<String> {
    std::fs::read_to_string(overlay_pair_stamp(cache_root, version, arch))
        .ok()
        .map(|text| text.trim().to_string())
        .filter(|text| !text.is_empty())
}

/// Record the pair fingerprint for the overlay installed at
/// (`cache_root`, `version`, `arch`), so a later launch under the same pair
/// trusts the install without rebuilding. `mvmctl build runtime-overlay
/// build` calls this after a pair install; the launch path records its own.
pub fn record_overlay_install_pair_fingerprint(
    cache_root: &std::path::Path,
    version: &str,
    arch: &str,
    fingerprint: &str,
) -> Result<()> {
    record_overlay_pair_fingerprint(cache_root, version, arch, fingerprint)
}

fn record_overlay_pair_fingerprint(
    cache_root: &std::path::Path,
    version: &str,
    arch: &str,
    fingerprint: &str,
) -> Result<()> {
    let stamp = overlay_pair_stamp(cache_root, version, arch);
    if let Some(parent) = stamp.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&stamp, format!("{fingerprint}\n"))?;
    Ok(())
}

/// The recorded pair fingerprint of an installed sidecar, if it was installed
/// from a pair. Anything else — published, in-tree source build — is not a
/// pair answer.
fn installed_sidecar_pair_fingerprint(
    cache_root: &std::path::Path,
    version: &str,
    arch: mvm_core::arch::GuestArch,
    libc: mvm_contract::guest_libc::GuestLibc,
) -> Option<String> {
    let layout =
        mvm_fs::sdk_sidecar::SdkSidecarLayout::under(cache_root, version, &arch.to_string(), libc);
    std::fs::read_to_string(
        layout
            .artifact_dir
            .join(mvm_build::sdk_sidecar::LOCAL_SOURCE_FINGERPRINT_FILE),
    )
    .ok()
    .map(|text| text.trim().to_string())
    .filter(|text| !text.is_empty())
}

/// Ordinary starts always re-resolve the overlay for the current host build.
/// Callers that need same-version continuity across lifecycle state must use
/// [`attach_runtime_overlay_if_cached_version`] with an explicit pin.
pub fn attach_runtime_overlay_if_cached(
    start_config: &mut mvm_core::vm_backend::VmStartConfig,
    hypervisor: &str,
) -> Result<()> {
    attach_runtime_overlay_if_cached_version(start_config, hypervisor, None, None)
}

/// The pair-aware form takes a selected checkout through
/// [`attach_runtime_overlay_if_cached_version`]; this convenience is for
/// callers with no selection to offer (tests, non-CLI consumers).
pub fn attach_runtime_overlay_if_cached_version_unpaired(
    start_config: &mut mvm_core::vm_backend::VmStartConfig,
    hypervisor: &str,
    expected_version: Option<&str>,
) -> Result<()> {
    attach_runtime_overlay_if_cached_version(start_config, hypervisor, expected_version, None)
}

pub fn attach_runtime_overlay_if_cached_version(
    start_config: &mut mvm_core::vm_backend::VmStartConfig,
    hypervisor: &str,
    expected_version: Option<&str>,
    pair: Option<&mut PairArtifactSource<'_>>,
) -> Result<()> {
    // The wasm backend runs a WASI module directly; it has no guest agent
    // runtime overlay to attach.
    if hypervisor == "wasm" {
        return Ok(());
    }
    let version = expected_version.unwrap_or(env!("CARGO_PKG_VERSION"));
    let cache_root = std::path::PathBuf::from(mvm_core::config::mvm_cache_dir());
    let arch = mvm_core::arch::GuestArch::host();
    // A selected checkout is the overlay's source: an unchanged pair answers
    // from the install recorded at the last pair build; a changed pair builds
    // once and reinstalls under the same stamp. Neither the in-tree build nor
    // the published download runs while a checkout is selected.
    if let Some(pair) = pair {
        let target = PairArtifactSource::target(
            mvm_build::image_source::ImageBuildRole::RuntimeOverlay,
            "default",
        );
        let fingerprint = pair.fingerprint(&target)?;
        if installed_overlay_pair_fingerprint(&cache_root, version, &arch.to_string()).as_deref()
            != Some(fingerprint.as_str())
        {
            ui::info("Runtime overlay: building from the selected image checkout...");
            let entry = (pair.build)(pair.checkout, target)?;
            let (_staged, artifact) =
                crate::launch::pair_stage::staged_overlay_artifact(&entry, arch)?;
            if artifact.version != version {
                anyhow::bail!(
                    "the selected checkout's runtime overlay is version {}, but this mvmctl requires {version}; check out matching versions or unset MVM_IMAGES_DIR",
                    artifact.version,
                );
            }
            mvm_build::runtime_overlay::install_overlay_into_cache(
                &artifact,
                &cache_root,
                &mvm_build::runtime_overlay::InstallOptions { overwrite: true },
            )?;
            record_overlay_pair_fingerprint(&cache_root, version, &arch.to_string(), &fingerprint)?;
        }
        // The pair's install is the only source under a selected checkout:
        // resolve it from the cache and return. Falling through would run
        // the in-tree build arm (for a contributor build it rebuilds from
        // the mvm checkout on every boot, overwriting the pair's bytes) or
        // the published-download ladder, and neither may run here.
        let resolver =
            mvm_fs::overlay::RuntimeOverlayResolver::new(cache_root.clone(), version.to_string());
        return attach_runtime_overlay(start_config, hypervisor, &resolver, arch).with_context(
            || {
                format!(
                    "the pair's runtime overlay {version} for {arch} installed but did not resolve from the cache"
                )
            },
        );
    }
    if expected_version.is_none()
        && matches!(hypervisor, "firecracker" | "hvf" | "qemu" | "libkrun")
        && runtime_overlay_acquire_mode() == RuntimeOverlayAcquireMode::BuildFromSourceCheckout
        && runtime_overlay_source_checkout_root().is_some()
    {
        let artifact = mvm_build::runtime_overlay::resolve_or_build_local_runtime_overlay(
            &cache_root,
            version,
            arch,
        )?;
        apply_runtime_overlay_artifact(start_config, artifact);
        return Ok(());
    }
    let resolver =
        mvm_fs::overlay::RuntimeOverlayResolver::new(cache_root.clone(), version.to_string());
    if attach_runtime_overlay(start_config, hypervisor, &resolver, arch).is_ok() {
        return Ok(());
    }
    // The published overlay is a member of the image set this build pins, and
    // is filed under that set's root rather than this CLI's version.
    let pinned_set = mvm_build::published_image_set::SetMemberCache::locked();
    if let Some(pinned) = expected_version {
        // A machine that booted from the pinned set recorded that member's own
        // version, which is what continuity asks for here.
        return match mvm_build::runtime_overlay::resolve_image_set_runtime_overlay(
            &cache_root,
            &pinned_set,
            arch,
        ) {
            Ok(artifact) if artifact.version == pinned => {
                apply_runtime_overlay_artifact(start_config, artifact);
                Ok(())
            }
            _ => Err(anyhow::anyhow!(
                "runtime overlay version {version} is required for this boot and was not found in the local cache"
            )),
        };
    }
    let source_checkout_root = match runtime_overlay_acquire_mode() {
        RuntimeOverlayAcquireMode::BuildFromSourceCheckout => {
            runtime_overlay_source_checkout_root()
        }
        RuntimeOverlayAcquireMode::DownloadPublishedArtifact => None,
    };
    if source_checkout_root.is_some() {
        ui::info("Runtime overlay missing from cache; building it from the source checkout...");
    } else {
        if let Ok(artifact) = mvm_build::runtime_overlay::resolve_image_set_runtime_overlay(
            &cache_root,
            &pinned_set,
            arch,
        ) {
            apply_runtime_overlay_artifact(start_config, artifact);
            return Ok(());
        }
        ui::info(
            "Runtime overlay missing from cache; downloading it from the pinned image set now...",
        );
    }
    let artifact = acquire_runtime_overlay(&RuntimeOverlayAcquireParams {
        cache_root: &cache_root,
        expected_version: version,
        arch,
        source_checkout_root: source_checkout_root.as_deref(),
    })?;
    tracing::info!(
        runtime_overlay_version = %artifact.version,
        backend = hypervisor,
        "runtime overlay cache populated for required-overlay boot"
    );
    apply_runtime_overlay_artifact(start_config, artifact);
    Ok(())
}

// ── SDK sidecar ──────────────────────────────────────────────────────────────

/// Production wrapper: build the sidecar resolver from the mvm cache dir + the
/// running mvmctl version, then resolve for `services`.
///
/// The decision, the resolution, and the attachment shape live in
/// `mvm_runtime::sdk_sidecar` so every driver — not just the CLI — reaches one
/// contract; this supplies the host's cache root and version, and owns the
/// cold-cache acquisition ladder the same way
/// [`attach_runtime_overlay_if_cached_version`] does for the overlay:
///
/// 1. Resolve from cache. A warm cache never touches the network.
/// 2. On a miss, seed from the default cache — a worktree-isolated `MVM_HOME`
///    inherits the host's artifact rather than re-acquiring it. Still offline.
/// 3. Still missing: consult the *same* build-vs-download decision the overlay
///    makes on this host, so a contributor whose overlay is source-built never
///    silently downloads a sidecar.
pub fn resolve_sdk_sidecar_attachment_for_host(
    services: &[mvm_contract::protocol::broker::ServiceId],
    libc: mvm_contract::guest_libc::GuestLibc,
    pair: Option<&mut PairArtifactSource<'_>>,
) -> Result<Option<SdkSidecarAttachment>> {
    let cache_root = std::path::PathBuf::from(mvm_core::config::mvm_cache_dir());
    let version = env!("CARGO_PKG_VERSION");
    let arch = mvm_core::arch::GuestArch::host();
    let resolver =
        mvm_fs::sdk_sidecar::SdkSidecarResolver::new(cache_root.clone(), version.to_string());

    // A selected checkout owns the sidecar's freshness: a cached sidecar
    // installed from a pair answers only while its recorded pair identity is
    // the pair on disk now, so a change in either checkout reinstalls rather
    // than boots a stale cdylib.
    let mut pair_plan: Option<(mvm_build::image_source::ImageBuildTarget, String)> = None;
    if let Some(pair) = pair.as_deref() {
        // `Unknown` selects no sidecar at all: the resolver answers `None`
        // for it below, and there is nothing for the pair to build. Probing
        // a sidecar for an undetected libc would only guess.
        let attr = match libc {
            mvm_contract::guest_libc::GuestLibc::Glibc => Some("sdk-sidecar-image"),
            mvm_contract::guest_libc::GuestLibc::Musl => Some("sdk-sidecar-image-musl"),
            mvm_contract::guest_libc::GuestLibc::Unknown => None,
        };
        if let Some(attr) = attr {
            let target = PairArtifactSource::target(
                mvm_build::image_source::ImageBuildRole::RuntimeOverlay,
                attr,
            );
            let fingerprint = pair.fingerprint(&target)?;
            pair_plan = Some((target, fingerprint));
        }
    }
    let pair_selected = pair_plan.is_some();
    if let (Some(pair), Some((target, fingerprint))) = (pair, pair_plan)
        && installed_sidecar_pair_fingerprint(&cache_root, version, arch, libc).as_deref()
            != Some(fingerprint.as_str())
    {
        ui::info("SDK sidecar: building from the selected image checkout...");
        let entry = (pair.build)(pair.checkout, target)?;
        crate::launch::pair_stage::install_pair_sidecar(
            &entry,
            &fingerprint,
            &cache_root,
            version,
            arch,
            libc,
        )?;
    }

    let cache_miss = match mvm_runtime::sdk_sidecar::resolve_sdk_sidecar_attachment(
        services, &resolver, arch, libc,
    ) {
        Ok(Some(resolved)) => {
            warn_if_sidecar_predates_the_working_tree(&cache_root, version, arch, libc);
            return Ok(Some(resolved));
        }
        // No SDK-served binding means no sidecar was selected. In particular,
        // an image whose libc has not been detected yet must not probe the
        // synthetic `unknown/` cache path and mislabel its absence as a
        // published artifact.
        Ok(None) => return Ok(None),
        Err(e) => e,
    };

    if mvm_build::sdk_sidecar::resolve_or_seed_from_default_cache(&resolver, arch, libc).is_ok() {
        return mvm_runtime::sdk_sidecar::resolve_sdk_sidecar_attachment(
            services, &resolver, arch, libc,
        );
    }

    match runtime_overlay_acquire_mode() {
        // Building the sidecar needs the builder VM, which must not be spawned
        // implicitly inside a launch. Keep the fail-closed refusal, which
        // names the binding and the explicit source-build command.
        RuntimeOverlayAcquireMode::BuildFromSourceCheckout => Err(cache_miss),
        RuntimeOverlayAcquireMode::DownloadPublishedArtifact => {
            if pair_selected {
                anyhow::bail!(
                    "the SDK sidecar for {libc} is not in the selected checkout's set and no pair install is usable; build it with `mvmctl build sdk-sidecar build` from the paired checkout"
                );
            }
            // The published sidecar is a member of the image set this build
            // pins, filed under that set's root rather than this CLI's
            // version, so a warm one resolves without the network.
            let pinned_set = mvm_build::published_image_set::SetMemberCache::locked();
            if let Some(attached) =
                resolve_image_set_sidecar_attachment(services, &cache_root, &pinned_set, arch, libc)
            {
                return Ok(Some(attached));
            }
            ui::info(
                "SDK sidecar missing from cache; downloading it from the pinned image set now...",
            );
            mvm_build::sdk_sidecar::download_sdk_sidecar(arch, libc, &cache_root)
                .with_context(|| sdk_sidecar_download_failure_context(services, arch, libc))?;
            let member_resolver = mvm_build::sdk_sidecar::image_set_sidecar_resolver(
                &cache_root,
                &pinned_set,
                arch,
                libc,
            )?;
            mvm_runtime::sdk_sidecar::resolve_sdk_sidecar_attachment(
                services,
                &member_resolver,
                arch,
                libc,
            )
        }
    }
}

/// The attachment for the `libc` sidecar installed from `set`, when one is
/// installed and still sound. A pure cache read.
fn resolve_image_set_sidecar_attachment(
    services: &[mvm_contract::protocol::broker::ServiceId],
    cache_root: &std::path::Path,
    set: &mvm_build::published_image_set::SetMemberCache,
    arch: mvm_core::arch::GuestArch,
    libc: mvm_contract::guest_libc::GuestLibc,
) -> Option<SdkSidecarAttachment> {
    let resolver =
        mvm_build::sdk_sidecar::image_set_sidecar_resolver(cache_root, set, arch, libc).ok()?;
    let attached =
        mvm_runtime::sdk_sidecar::resolve_sdk_sidecar_attachment(services, &resolver, arch, libc)
            .ok()??;
    warn_if_sidecar_predates_the_working_tree(
        resolver.cache_root(),
        resolver.expected_version(),
        arch,
        libc,
    );
    Some(attached)
}

/// Say so when the cached sidecar cannot carry this checkout's cdylib changes.
///
/// The sidecar cache key is version + architecture, so an older downloaded or
/// source-built image can remain structurally valid after `crates/mvm-sdk`
/// changes. A contributor who adds a host-service verb would otherwise learn
/// about the drift only from inside the guest, as `unknown method
/// \`host.kv.get\`` — an error that points at the broker rather than at the
/// stale image.
///
/// A warning, not an implicit rebuild: source construction boots Stage 0 and
/// therefore remains an explicit operator action outside a workload launch.
///
/// Silent for a release binary, which has no checkout and for which the
/// published artifact is exactly right.
/// Said once per process. A launch resolves the sidecar from more than one call
/// site, and the condition is process-global — same cache, same checkout — so
/// repeating it is noise that trains people to skip the line.
fn warn_if_sidecar_predates_the_working_tree(
    cache_root: &std::path::Path,
    version: &str,
    arch: mvm_core::arch::GuestArch,
    libc: mvm_contract::guest_libc::GuestLibc,
) {
    static SAID: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

    let Some(workspace_root) =
        crate::launch::runtime_overlay::runtime_overlay_source_checkout_root()
    else {
        return;
    };
    match mvm_build::sdk_sidecar::cached_sidecar_provenance(
        cache_root,
        version,
        arch,
        libc,
        &workspace_root,
    ) {
        Ok(mvm_build::sdk_sidecar::SidecarProvenance::MatchesSource) => {}
        Ok(_) if SAID.swap(true, std::sync::atomic::Ordering::Relaxed) => {}
        Ok(provenance) => {
            let origin = match provenance {
                mvm_build::sdk_sidecar::SidecarProvenance::Published => "is the published artifact",
                _ => "was built from a different revision of this tree",
            };
            let marker = mvm_fs::sdk_sidecar::SdkSidecarLayout::under(
                cache_root,
                version,
                &arch.to_string(),
                libc,
            )
            .artifact_dir
            .join(mvm_build::sdk_sidecar::LOCAL_SOURCE_FINGERPRINT_FILE);
            ui::warn(&sidecar_provenance_warning(origin, &marker));
        }
        // Provenance is a diagnostic. Failing to compute it must not fail a
        // launch that would otherwise proceed.
        Err(error) => {
            tracing::debug!(%error, "could not determine SDK sidecar provenance");
        }
    }
}

fn sidecar_provenance_warning(origin: &str, marker: &std::path::Path) -> String {
    format!(
        "SDK sidecar {origin}, so `libmvm_host_services.so` does not carry changes to \
         crates/mvm-host-services in this checkout. Host-service calls from the guest use \
         the verbs it shipped with; one added here answers `unknown method`. Run \
         `mvmctl build sdk-sidecar build` and wait for both libc variants to report cached \
         successfully. Provenance marker: {}.",
        marker.display()
    )
}

/// A failed download must read like the cache-miss refusal it replaces: name
/// the bindings that demanded the sidecar and where it was going to be mounted,
/// not just the URL that 404'd.
fn sdk_sidecar_download_failure_context(
    services: &[mvm_contract::protocol::broker::ServiceId],
    arch: mvm_core::arch::GuestArch,
    libc: mvm_contract::guest_libc::GuestLibc,
) -> String {
    let bound: Vec<&str> = mvm_core::plan::sdk_host_services_in(services)
        .iter()
        .map(|s| s.as_str())
        .collect();
    format!(
        "this workload binds SDK host service(s) [{}], which need the SDK sidecar mounted \
         read-only at {}; acquiring the pinned image set's {libc} sidecar for {arch} failed",
        bound.join(", "),
        mvm_core::plan::SDK_SIDECAR_GUEST_PATH,
    )
}

#[cfg(test)]
mod sdk_sidecar_host_resolution_tests {
    use super::*;
    use mvm_contract::protocol::broker::ServiceId;
    use mvm_core::arch::GuestArch;
    use mvm_fs::sdk_sidecar::{
        SDK_SIDECAR_IMAGE_FILE, SDK_SIDECAR_VERSION_FILE, SdkSidecarLayout, SdkSidecarResolver,
    };
    use sha2::{Digest, Sha256};

    fn svc(raw: &str) -> ServiceId {
        ServiceId::parse(raw).expect("fixture service id")
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        hex::encode(Sha256::digest(bytes))
    }

    #[test]
    fn stale_sidecar_guidance_names_the_current_owner_and_completion_signal() {
        let marker = std::path::Path::new("/cache/glibc/SOURCE_FINGERPRINT");
        let warning = sidecar_provenance_warning("is the published artifact", marker);

        assert!(warning.contains("crates/mvm-host-services"), "{warning}");
        assert!(!warning.contains("changes to crates/mvm-sdk"), "{warning}");
        assert!(warning.contains("both libc variants"), "{warning}");
        assert!(warning.contains(&marker.display().to_string()), "{warning}");
    }

    /// `libc` is explicit at every call site: the resolver proves an
    /// artifact's libc from its own `DT_NEEDED` and refuses one that disagrees
    /// with the slot it was filed under, so a defaulted fixture could disagree
    /// with its own slot silently.
    fn sidecar_ext4_bytes(libc: mvm_contract::guest_libc::GuestLibc) -> Vec<u8> {
        use mvm_fs::ext4::{Node, Owner};
        let nodes = vec![
            Node::Dir {
                path: "/lib".into(),
                mode: 0o555,
                xattrs: Vec::new(),
                owner: Owner::ROOT,
            },
            Node::File {
                path: "/lib/libmvm_host_services.so".into(),
                mode: 0o555,
                data: mvm_fs::elf::test_fixture::shared_object(&[
                    "libgcc_s.so.1",
                    libc.libc_soname().expect("a fixture names a real libc"),
                ]),
                xattrs: Vec::new(),
                owner: Owner::ROOT,
            },
        ];
        mvm_fs::ext4::build_image(nodes, &Default::default()).expect("build sidecar ext4 fixture")
    }

    fn seed_sidecar_cache(cache: &std::path::Path, version: &str, arch: GuestArch) {
        seed_sidecar_variant(
            cache,
            version,
            arch,
            mvm_contract::guest_libc::GuestLibc::Musl,
        );
    }

    fn seed_sidecar_variant(
        cache: &std::path::Path,
        version: &str,
        arch: GuestArch,
        libc: mvm_contract::guest_libc::GuestLibc,
    ) {
        let layout = SdkSidecarLayout::under(cache, version, &arch.to_string(), libc);
        std::fs::create_dir_all(&layout.artifact_dir).unwrap();
        let image = sidecar_ext4_bytes(libc);
        let version_text = format!("{version}\n");
        std::fs::write(&layout.image, &image).unwrap();
        std::fs::write(&layout.version_file, &version_text).unwrap();
        std::fs::write(
            &layout.checksum_manifest_file,
            format!(
                "{}  {SDK_SIDECAR_IMAGE_FILE}\n{}  {SDK_SIDECAR_VERSION_FILE}\n",
                sha256_hex(&image),
                sha256_hex(version_text.as_bytes()),
            ),
        )
        .unwrap();
    }

    /// The grant + volume pair the attachment produces is exactly what the
    /// shared admission gate admits — proven against the real gate, not a
    /// restatement of its rules.
    #[test]
    fn the_attachment_satisfies_the_shared_admission_gate() {
        let dir = tempfile::tempdir().unwrap();
        let arch = GuestArch::host();
        seed_sidecar_cache(dir.path(), "1.2.3", arch);
        let resolver = SdkSidecarResolver::new(dir.path().to_path_buf(), "1.2.3".into());
        let attached = mvm_runtime::sdk_sidecar::resolve_sdk_sidecar_attachment(
            &[svc("host.audit.v1")],
            &resolver,
            arch,
            mvm_contract::guest_libc::GuestLibc::Musl,
        )
        .unwrap()
        .unwrap();

        let plan = mvm_core::plan::test_support::PlanFixture::new()
            .services(vec![svc("host.audit.v1")])
            .build();
        mvm_hostd::plan_admission::enforce_sdk_sidecar_attachment(
            std::slice::from_ref(&attached.volume),
            &plan,
            mvm_contract::guest_libc::GuestLibc::Musl,
        )
        .expect("the resolved attachment must satisfy the admission gate");

        // And the same volume is refused for a plan that binds no SDK service.
        let unbound = mvm_core::plan::test_support::PlanFixture::new().build();
        assert!(
            mvm_hostd::plan_admission::enforce_sdk_sidecar_attachment(
                std::slice::from_ref(&attached.volume),
                &unbound,
                mvm_contract::guest_libc::GuestLibc::Musl,
            )
            .is_err()
        );
    }

    /// The host wrapper reads the mvm cache dir, so an isolated `MVM_HOME` is
    /// what makes this assertion about the wrapper rather than about whatever
    /// the developer happens to have cached.
    #[test]
    fn the_host_wrapper_resolves_nothing_when_no_sdk_service_is_bound() {
        let dir = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(dir.path());
        assert_eq!(
            resolve_sdk_sidecar_attachment_for_host(
                &[],
                mvm_contract::guest_libc::GuestLibc::Unknown,
                None,
            )
            .unwrap(),
            None,
            "no binding must short-circuit before probing an unknown-libc cache path"
        );
        assert_eq!(
            resolve_sdk_sidecar_attachment_for_host(
                &[],
                mvm_contract::guest_libc::GuestLibc::Musl,
                None,
            )
            .unwrap(),
            None
        );
        assert_eq!(
            resolve_sdk_sidecar_attachment_for_host(
                &[svc("broker.v1")],
                mvm_contract::guest_libc::GuestLibc::Musl,
                None,
            )
            .unwrap(),
            None
        );
    }

    #[test]
    fn the_host_wrapper_fails_closed_on_a_cold_cache() {
        let dir = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(dir.path());
        env.set(
            crate::launch::runtime_overlay::RUNTIME_OVERLAY_ACQUIRE_MODE_ENV,
            "build",
        );
        assert!(
            resolve_sdk_sidecar_attachment_for_host(
                &[svc("host.audit.v1")],
                mvm_contract::guest_libc::GuestLibc::Musl,
                None,
            )
            .is_err(),
            "a bound SDK service with no cached sidecar must refuse the launch"
        );
    }

    /// A base URL no transport can reach. Any test asserting "the network was
    /// not touched" points here: if the acquire path ran, the call fails.
    const UNREACHABLE_BASE_URL: &str = "file:///nonexistent/mvm-sdk-sidecar-release-fixture";

    /// A download-mode host with a cold cache acquires the sidecar from the
    /// image set this build pins — nothing else. The mirror serves nothing, so
    /// the refusal names the locked root it went for, and the cache stays
    /// cold. Installing a served member is `mvm_build::sdk_sidecar`'s to prove
    /// against a fixture set; the root here is pinned, so no fixture matches.
    #[test]
    fn a_download_mode_host_acquires_the_sidecar_from_the_locked_image_set() {
        let dir = tempfile::tempdir().unwrap();
        let mirror = tempfile::tempdir().unwrap();
        let version = env!("CARGO_PKG_VERSION");
        let arch = GuestArch::host();

        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(dir.path());
        env.set(
            crate::launch::runtime_overlay::RUNTIME_OVERLAY_ACQUIRE_MODE_ENV,
            "download",
        );
        env.set(
            "MVM_UPDATE_DOWNLOAD_URL",
            format!("file://{}", mirror.path().display()),
        );

        let err = resolve_sdk_sidecar_attachment_for_host(
            &[svc("host.audit.v1")],
            mvm_contract::guest_libc::GuestLibc::Glibc,
            None,
        )
        .expect_err("a mirror serving no image set cannot satisfy the binding");
        let msg = format!("{err:#}");

        let train = mvm_core::image_set::image_train_lock();
        assert!(msg.contains("locked image-set manifest"), "{msg}");
        assert!(
            msg.contains(train.image_set.release_tag.as_str()),
            "the refusal must name the pinned set: {msg}"
        );
        let layout = SdkSidecarLayout::under(
            &dir.path().join("cache"),
            version,
            &arch.to_string(),
            mvm_contract::guest_libc::GuestLibc::Glibc,
        );
        assert!(!layout.artifact_dir.exists(), "nothing may be cached");
    }

    /// Building the sidecar needs the builder VM, which a launch must never
    /// spawn implicitly — so a source checkout keeps the fail-closed refusal
    /// and never falls through to the network.
    #[test]
    fn a_source_checkout_host_refuses_instead_of_downloading() {
        let dir = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(dir.path());
        env.set(
            crate::launch::runtime_overlay::RUNTIME_OVERLAY_ACQUIRE_MODE_ENV,
            "build",
        );
        env.set("MVM_UPDATE_DOWNLOAD_URL", UNREACHABLE_BASE_URL);

        let err = resolve_sdk_sidecar_attachment_for_host(
            &[svc("host.kv.v1")],
            mvm_contract::guest_libc::GuestLibc::Musl,
            None,
        )
        .expect_err("a source-checkout host must refuse rather than download");
        let msg = format!("{err:#}");

        assert!(msg.contains("host.kv.v1"), "{msg}");
        assert!(
            msg.contains(mvm_core::plan::SDK_SIDECAR_GUEST_PATH),
            "{msg}"
        );
        assert!(
            msg.contains("mvmctl build sdk-sidecar build"),
            "the refusal must still name the build that satisfies it: {msg}"
        );
    }

    /// The download-mode refusal has to read like the cache-miss one it
    /// replaces: an operator needs the binding that demanded the sidecar, not
    /// just a failed URL.
    #[test]
    fn a_failed_download_still_names_the_binding_that_required_the_sidecar() {
        let dir = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(dir.path());
        env.set(
            crate::launch::runtime_overlay::RUNTIME_OVERLAY_ACQUIRE_MODE_ENV,
            "download",
        );
        env.set("MVM_UPDATE_DOWNLOAD_URL", UNREACHABLE_BASE_URL);

        let err = resolve_sdk_sidecar_attachment_for_host(
            &[svc("host.time.v1")],
            mvm_contract::guest_libc::GuestLibc::Musl,
            None,
        )
        .expect_err("an unreachable release must refuse the launch");
        let msg = format!("{err:#}");

        assert!(msg.contains("host.time.v1"), "{msg}");
        assert!(
            msg.contains(mvm_core::plan::SDK_SIDECAR_GUEST_PATH),
            "{msg}"
        );
    }

    /// A warm cache is a pure local read. Pointing the transport at an
    /// unreachable base URL is what proves it: if the acquire path ran at all,
    /// this call would fail.
    #[test]
    fn a_warm_cache_never_touches_the_network() {
        let dir = tempfile::tempdir().unwrap();
        let version = env!("CARGO_PKG_VERSION");
        let arch = GuestArch::host();
        seed_sidecar_cache(&dir.path().join("cache"), version, arch);

        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(dir.path());
        env.set(
            crate::launch::runtime_overlay::RUNTIME_OVERLAY_ACQUIRE_MODE_ENV,
            "download",
        );
        env.set("MVM_UPDATE_DOWNLOAD_URL", UNREACHABLE_BASE_URL);

        let attached = resolve_sdk_sidecar_attachment_for_host(
            &[svc("host.audit.v1")],
            mvm_contract::guest_libc::GuestLibc::Musl,
            None,
        )
        .expect("a warm cache resolves without any transport")
        .expect("a bound SDK service must attach the sidecar");
        assert_eq!(attached.version, version);
    }

    /// The published sidecar is identified by the root this build pins: a
    /// member at another version than this CLI's, for either libc, attaches
    /// from the cache without the transport being touched.
    #[test]
    fn a_pinned_set_sidecar_at_another_version_attaches_without_the_network() {
        let member_version = "0.0.1-member";
        assert_ne!(member_version, env!("CARGO_PKG_VERSION"));
        for libc in [
            mvm_contract::guest_libc::GuestLibc::Glibc,
            mvm_contract::guest_libc::GuestLibc::Musl,
        ] {
            let dir = tempfile::tempdir().unwrap();
            let arch = GuestArch::host();
            let cache = dir.path().join("cache");
            let set = mvm_build::published_image_set::SetMemberCache::locked();
            seed_sidecar_variant(&set.cache_root(&cache), member_version, arch, libc);
            set.record(
                &cache,
                mvm_core::image_set::ImageSetRole::SdkSidecar(libc),
                mvm_core::image_set::MemberTarget::Arch(arch),
                &mvm_build::published_image_set::MemberVersion::parse(member_version).unwrap(),
            )
            .unwrap();

            let mut env = mvm_core::util::test_env::TestEnv::new();
            env.isolate_mvm_home(dir.path());
            env.set(
                crate::launch::runtime_overlay::RUNTIME_OVERLAY_ACQUIRE_MODE_ENV,
                "download",
            );
            env.set("MVM_UPDATE_DOWNLOAD_URL", UNREACHABLE_BASE_URL);

            let attached =
                resolve_sdk_sidecar_attachment_for_host(&[svc("host.audit.v1")], libc, None)
                    .unwrap_or_else(|e| panic!("the pinned {libc} member must attach: {e:#}"))
                    .expect("a bound SDK service must attach the sidecar");
            assert_eq!(attached.version, member_version);
        }
    }
}

#[cfg(test)]
mod runtime_overlay_attach_tests {
    use super::*;
    use crate::launch::runtime_overlay::RUNTIME_OVERLAY_ACQUIRE_MODE_ENV;
    use mvm_core::arch::GuestArch;
    use mvm_core::util::test_env::TestEnv;
    use mvm_core::vm_backend::VmStartConfig;
    use mvm_fs::ext4::{Node, Owner};
    use mvm_fs::overlay::RuntimeOverlayResolver;
    use sha2::{Digest, Sha256};

    static ENV_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// A payload carrying every path the resolver requires, optionally minus
    /// the egress client — the one omission these tests actually exercise.
    ///
    /// Derived from `REQUIRED_OVERLAY_GUEST_PATHS` rather than restated: a
    /// hand-written copy is one an added required path silently invalidates,
    /// and it then fails as an unrelated integrity error rather than as a stale
    /// fixture.
    fn valid_overlay_ext4_bytes(version: &str, include_egress_client: bool) -> Vec<u8> {
        let nodes: Vec<Node> = mvm_fs::overlay::REQUIRED_OVERLAY_GUEST_PATHS
            .iter()
            .filter(|path| include_egress_client || **path != "/egress-client")
            .map(|path| Node::File {
                path: (*path).into(),
                // `VERSION` is data the resolver reads back, not a binary.
                mode: if *path == "/VERSION" { 0o444 } else { 0o555 },
                data: if *path == "/VERSION" {
                    format!("{version}\n").into_bytes()
                } else {
                    path.trim_start_matches('/').as_bytes().to_vec()
                },
                xattrs: Vec::new(),
                owner: Owner::ROOT,
            })
            .collect();
        mvm_fs::ext4::build_image(nodes, &Default::default())
            .expect("build valid overlay ext4 fixture")
    }

    /// Stage a complete overlay cache entry (the four files the resolver
    /// validates) in the layout `resolve` expects.
    fn seed_cache(cache: &std::path::Path, version: &str, arch: GuestArch) {
        let layout = RuntimeOverlayResolver::new(cache.to_path_buf(), version.to_string())
            .layout(&arch.to_string());
        std::fs::create_dir_all(&layout.artifact_dir).unwrap();
        let overlay_ext4 = valid_overlay_ext4_bytes(version, true);
        let sidecar = b"verity-bytes";
        let roothash = format!("{}\n", "a".repeat(64));
        let version_text = format!("{version}\n");
        std::fs::write(&layout.overlay_ext4, &overlay_ext4).unwrap();
        std::fs::write(&layout.sidecar, sidecar).unwrap();
        std::fs::write(&layout.roothash_file, &roothash).unwrap();
        std::fs::write(&layout.version_file, &version_text).unwrap();
        std::fs::write(
            &layout.checksum_manifest_file,
            format!(
                "{}  overlay.ext4\n{}  overlay.verity\n{}  overlay.roothash\n{}  VERSION\n",
                sha256_hex(&overlay_ext4),
                sha256_hex(sidecar),
                sha256_hex(roothash.as_bytes()),
                sha256_hex(version_text.as_bytes()),
            ),
        )
        .unwrap();
        if let Some(workspace_root) =
            crate::launch::runtime_overlay::runtime_overlay_source_checkout_root()
        {
            let fingerprint =
                mvm_build::guest_agent_build::runtime_overlay_source_checkout_fingerprint(
                    &workspace_root,
                )
                .expect("compute runtime-overlay source fingerprint");
            std::fs::write(
                &layout.local_source_fingerprint_file,
                format!("{fingerprint}\n"),
            )
            .unwrap();
        }
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        let digest = Sha256::digest(bytes);
        hex::encode(digest)
    }

    #[test]
    fn firecracker_with_cached_overlay_populates_all_three_fields() {
        let dir = tempfile::tempdir().unwrap();
        // `attach_runtime_overlay` seeds a miss from `$HOME/.mvm/cache`, so
        // without this the assertion holds partly on the developer's own
        // artifacts — and a broken `seed_cache` below would still pass.
        let mut env = TestEnv::new();
        env.isolate_mvm_home(dir.path());
        let ver = env!("CARGO_PKG_VERSION");
        let arch = GuestArch::host();
        seed_cache(dir.path(), ver, arch);
        let resolver = RuntimeOverlayResolver::new(dir.path().to_path_buf(), ver.to_string());
        let mut sc = VmStartConfig {
            ..VmStartConfig::default()
        };
        attach_runtime_overlay(&mut sc, "firecracker", &resolver, arch).unwrap();
        assert!(sc.runtime_overlay_path.is_some(), "ext4 path set");
        assert!(sc.runtime_overlay_verity_path.is_some(), "verity path set");
        assert_eq!(
            sc.runtime_overlay_roothash.as_deref(),
            Some("a".repeat(64).as_str())
        );
        assert_eq!(sc.runtime_overlay_version.as_deref(), Some(ver));
    }

    #[test]
    fn hvf_with_cached_overlay_populates_all_three_fields() {
        let dir = tempfile::tempdir().unwrap();
        // `attach_runtime_overlay` seeds a miss from `$HOME/.mvm/cache`, so
        // without this the assertion holds partly on the developer's own
        // artifacts — and a broken `seed_cache` below would still pass.
        let mut env = TestEnv::new();
        env.isolate_mvm_home(dir.path());
        let ver = env!("CARGO_PKG_VERSION");
        let arch = GuestArch::host();
        seed_cache(dir.path(), ver, arch);
        let resolver = RuntimeOverlayResolver::new(dir.path().to_path_buf(), ver.to_string());
        let mut sc = VmStartConfig {
            ..VmStartConfig::default()
        };
        attach_runtime_overlay(&mut sc, "hvf", &resolver, arch).unwrap();
        assert!(sc.runtime_overlay_path.is_some());
        assert!(sc.runtime_overlay_verity_path.is_some());
        assert!(sc.runtime_overlay_roothash.is_some());
        assert_eq!(sc.runtime_overlay_version.as_deref(), Some(ver));
    }

    #[test]
    fn libkrun_with_cached_overlay_populates_all_three_fields() {
        let dir = tempfile::tempdir().unwrap();
        // `attach_runtime_overlay` seeds a miss from `$HOME/.mvm/cache`, so
        // without this the assertion holds partly on the developer's own
        // artifacts — and a broken `seed_cache` below would still pass.
        let mut env = TestEnv::new();
        env.isolate_mvm_home(dir.path());
        let ver = env!("CARGO_PKG_VERSION");
        let arch = GuestArch::host();
        seed_cache(dir.path(), ver, arch);
        let resolver = RuntimeOverlayResolver::new(dir.path().to_path_buf(), ver.to_string());
        let mut sc = VmStartConfig {
            ..VmStartConfig::default()
        };
        attach_runtime_overlay(&mut sc, "libkrun", &resolver, arch).unwrap();
        assert!(sc.runtime_overlay_path.is_some());
        assert!(sc.runtime_overlay_verity_path.is_some());
        assert!(sc.runtime_overlay_roothash.is_some());
        assert_eq!(sc.runtime_overlay_version.as_deref(), Some(ver));
    }

    #[test]
    fn unsupported_backend_never_attaches() {
        let dir = tempfile::tempdir().unwrap();
        // `attach_runtime_overlay` seeds a miss from `$HOME/.mvm/cache`, so
        // without this the assertion holds partly on the developer's own
        // artifacts — and a broken `seed_cache` below would still pass.
        let mut env = TestEnv::new();
        env.isolate_mvm_home(dir.path());
        let ver = env!("CARGO_PKG_VERSION");
        let arch = GuestArch::host();
        seed_cache(dir.path(), ver, arch);
        let resolver = RuntimeOverlayResolver::new(dir.path().to_path_buf(), ver.to_string());
        let mut sc = VmStartConfig {
            ..VmStartConfig::default()
        };
        attach_runtime_overlay(&mut sc, "mock", &resolver, arch).unwrap();
        assert!(sc.runtime_overlay_path.is_none());
        assert!(sc.runtime_overlay_roothash.is_none());
    }

    #[test]
    fn firecracker_cold_cache_refuses_rather_than_booting_without_the_overlay() {
        let _env_lock = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut env = TestEnv::new();
        let dir = tempfile::tempdir().unwrap(); // empty cache
        let home = tempfile::tempdir().unwrap();
        env.set("HOME", home.path());
        let ver = env!("CARGO_PKG_VERSION");
        let arch = GuestArch::host();
        let resolver = RuntimeOverlayResolver::new(dir.path().to_path_buf(), ver.to_string());
        let mut sc = VmStartConfig {
            ..VmStartConfig::default()
        };
        // The overlay is the single source of the guest binaries, so a cold
        // cache is fatal here rather than something the boot can shrug off.
        // The caller's acquisition ladder catches this Err and builds or
        // downloads; what must never happen is a silent overlay-free boot.
        let err = attach_runtime_overlay(&mut sc, "firecracker", &resolver, arch)
            .expect_err("a cold cache must refuse, not attach nothing");
        assert!(
            err.to_string().contains("runtime overlay required"),
            "unexpected refusal: {err}"
        );
        assert!(sc.runtime_overlay_path.is_none());
    }

    #[test]
    fn firecracker_cold_cache_errors_when_overlay_is_required() {
        let _env_lock = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut env = TestEnv::new();
        let dir = tempfile::tempdir().unwrap(); // empty cache
        let home = tempfile::tempdir().unwrap();
        env.set("HOME", home.path());
        let ver = env!("CARGO_PKG_VERSION");
        let arch = GuestArch::host();
        let resolver = RuntimeOverlayResolver::new(dir.path().to_path_buf(), ver.to_string());
        let mut sc = VmStartConfig {
            ..VmStartConfig::default()
        };
        let err = attach_runtime_overlay(&mut sc, "firecracker", &resolver, arch).unwrap_err();
        assert!(err.to_string().contains("runtime overlay required"));
    }

    #[test]
    fn hvf_cold_cache_errors_when_overlay_is_required() {
        let _env_lock = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut env = TestEnv::new();
        let dir = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        env.set("HOME", home.path());
        let ver = env!("CARGO_PKG_VERSION");
        let arch = GuestArch::host();
        let resolver = RuntimeOverlayResolver::new(dir.path().to_path_buf(), ver.to_string());
        let mut sc = VmStartConfig {
            ..VmStartConfig::default()
        };
        let err = attach_runtime_overlay(&mut sc, "hvf", &resolver, arch).unwrap_err();
        assert!(err.to_string().contains("runtime overlay required"));
        assert!(err.to_string().contains("hvf"));
    }

    #[test]
    fn libkrun_cold_cache_errors_when_overlay_is_required() {
        let _env_lock = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut env = TestEnv::new();
        let dir = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        env.set("HOME", home.path());
        let ver = env!("CARGO_PKG_VERSION");
        let arch = GuestArch::host();
        let resolver = RuntimeOverlayResolver::new(dir.path().to_path_buf(), ver.to_string());
        let mut sc = VmStartConfig {
            ..VmStartConfig::default()
        };
        let err = attach_runtime_overlay(&mut sc, "libkrun", &resolver, arch).unwrap_err();
        assert!(err.to_string().contains("runtime overlay required"));
        assert!(err.to_string().contains("libkrun"));
    }

    #[test]
    fn qemu_with_cached_overlay_populates_all_three_fields() {
        let dir = tempfile::tempdir().unwrap();
        // `attach_runtime_overlay` seeds a miss from `$HOME/.mvm/cache`, so
        // without this the assertion holds partly on the developer's own
        // artifacts — and a broken `seed_cache` below would still pass.
        let mut env = TestEnv::new();
        env.isolate_mvm_home(dir.path());
        let ver = env!("CARGO_PKG_VERSION");
        let arch = GuestArch::host();
        seed_cache(dir.path(), ver, arch);
        let resolver = RuntimeOverlayResolver::new(dir.path().to_path_buf(), ver.to_string());
        let mut sc = VmStartConfig {
            ..VmStartConfig::default()
        };
        attach_runtime_overlay(&mut sc, "qemu", &resolver, arch).unwrap();
        assert!(sc.runtime_overlay_path.is_some());
        assert!(sc.runtime_overlay_verity_path.is_some());
        assert!(sc.runtime_overlay_roothash.is_some());
    }

    #[test]
    fn qemu_cold_cache_errors_when_overlay_is_required() {
        let _env_lock = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut env = TestEnv::new();
        let dir = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        env.set("HOME", home.path());
        let ver = env!("CARGO_PKG_VERSION");
        let arch = GuestArch::host();
        let resolver = RuntimeOverlayResolver::new(dir.path().to_path_buf(), ver.to_string());
        let mut sc = VmStartConfig {
            ..VmStartConfig::default()
        };
        let err = attach_runtime_overlay(&mut sc, "qemu", &resolver, arch).unwrap_err();
        assert!(err.to_string().contains("runtime overlay required"));
        assert!(err.to_string().contains("qemu"));
    }

    /// A required overlay missing from the cache is acquired from the image
    /// set this build pins. The mirror serves nothing, so the refusal names
    /// the locked root and nothing is attached or cached. Installing a served
    /// member is `mvm_build::runtime_overlay`'s to prove against a fixture set.
    #[test]
    fn required_overlay_cache_miss_acquires_from_the_locked_image_set() {
        let _env_lock = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut env = TestEnv::new();
        let cache = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        let mirror = tempfile::tempdir().unwrap();
        env.set("HOME", home.path());
        env.set("MVM_HOME", cache.path());
        env.set(RUNTIME_OVERLAY_ACQUIRE_MODE_ENV, "download");
        env.set(
            "MVM_UPDATE_DOWNLOAD_URL",
            format!("file://{}", mirror.path().display()),
        );

        let mut sc = VmStartConfig {
            ..VmStartConfig::default()
        };
        let err = attach_runtime_overlay_if_cached_version(&mut sc, "firecracker", None, None)
            .expect_err("a mirror serving no image set cannot supply the overlay");
        let msg = format!("{err:#}");

        let train = mvm_core::image_set::image_train_lock();
        assert!(msg.contains("locked image-set manifest"), "{msg}");
        assert!(
            msg.contains(train.image_set.release_tag.as_str()),
            "the refusal must name the pinned set: {msg}"
        );
        assert!(sc.runtime_overlay_path.is_none());
        let layout = RuntimeOverlayResolver::new(
            cache.path().join("cache"),
            env!("CARGO_PKG_VERSION").to_string(),
        )
        .layout(&GuestArch::host().to_string());
        assert!(!layout.overlay_ext4.exists(), "nothing may be cached");
    }

    #[test]
    fn runtime_overlay_acquire_mode_honors_explicit_download_override() {
        let _env_lock = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut env = TestEnv::new();
        env.set(RUNTIME_OVERLAY_ACQUIRE_MODE_ENV, "download");
        assert_eq!(
            runtime_overlay_acquire_mode(),
            RuntimeOverlayAcquireMode::DownloadPublishedArtifact
        );
    }

    #[test]
    fn runtime_overlay_acquire_mode_honors_explicit_build_override() {
        let _env_lock = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut env = TestEnv::new();
        env.set(RUNTIME_OVERLAY_ACQUIRE_MODE_ENV, "build");
        assert_eq!(
            runtime_overlay_acquire_mode(),
            RuntimeOverlayAcquireMode::BuildFromSourceCheckout
        );
    }

    #[cfg(feature = "release-channel")]
    #[test]
    fn release_channel_defaults_to_published_runtime_overlay() {
        let _env_lock = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut env = TestEnv::new();
        env.remove(RUNTIME_OVERLAY_ACQUIRE_MODE_ENV);
        assert_eq!(
            runtime_overlay_acquire_mode(),
            RuntimeOverlayAcquireMode::DownloadPublishedArtifact
        );
    }

    #[test]
    fn attach_runtime_overlay_if_cached_version_uses_requested_cached_version() {
        let _env_lock = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut env = TestEnv::new();
        let dir = tempfile::tempdir().unwrap();
        env.isolate_mvm_home(dir.path());

        let current = env!("CARGO_PKG_VERSION");
        let pinned = if current == "0.17.0" {
            "0.17.1"
        } else {
            "0.17.0"
        };
        let arch = GuestArch::host();
        seed_cache(&dir.path().join("cache"), current, arch);
        seed_cache(&dir.path().join("cache"), pinned, arch);

        let mut sc = VmStartConfig {
            ..VmStartConfig::default()
        };
        attach_runtime_overlay_if_cached_version(&mut sc, "firecracker", Some(pinned), None)
            .unwrap();

        let expected_layout =
            RuntimeOverlayResolver::new(dir.path().join("cache"), pinned.to_string())
                .layout(&arch.to_string());
        assert_eq!(sc.runtime_overlay_version.as_deref(), Some(pinned));
        assert_eq!(
            sc.runtime_overlay_path.as_deref(),
            Some(
                expected_layout
                    .overlay_ext4
                    .to_str()
                    .expect("utf-8 overlay path")
            )
        );
        assert_eq!(
            sc.runtime_overlay_verity_path.as_deref(),
            Some(expected_layout.sidecar.to_str().expect("utf-8 verity path"))
        );
    }

    #[test]
    fn attach_runtime_overlay_if_cached_version_refuses_drift_to_other_cached_version() {
        let _env_lock = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut env = TestEnv::new();
        let dir = tempfile::tempdir().unwrap();
        // Asserting an *absence*, so HOME has to move with MVM_HOME: the
        // overlay resolver seeds a cold cache from `$HOME/.mvm/cache`, which
        // would supply the very version this test requires to be missing.
        env.isolate_mvm_home(dir.path());

        let current = env!("CARGO_PKG_VERSION");
        let missing = if current == "0.17.0" {
            "0.17.1"
        } else {
            "0.17.0"
        };
        let arch = GuestArch::host();
        seed_cache(&dir.path().join("cache"), current, arch);

        let mut sc = VmStartConfig {
            ..VmStartConfig::default()
        };
        let err =
            attach_runtime_overlay_if_cached_version(&mut sc, "firecracker", Some(missing), None)
                .unwrap_err();

        let msg = err.to_string();
        assert!(msg.contains("required for this boot"), "{msg}");
        assert!(msg.contains(missing), "{msg}");
        assert!(
            sc.runtime_overlay_path.is_none(),
            "missing pinned version must not attach"
        );
        assert!(
            sc.runtime_overlay_version.is_none(),
            "missing pinned version must not silently drift to a different cache entry"
        );
    }

    #[test]
    fn attach_runtime_overlay_if_cached_prefers_current_host_version_for_plain_boot() {
        let _env_lock = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut env = TestEnv::new();
        let dir = tempfile::tempdir().unwrap();
        env.isolate_mvm_home(dir.path());
        env.set(RUNTIME_OVERLAY_ACQUIRE_MODE_ENV, "download");

        let current = env!("CARGO_PKG_VERSION");
        let older = if current == "0.17.0" {
            "0.16.9"
        } else {
            "0.17.0"
        };
        let arch = GuestArch::host();
        seed_cache(&dir.path().join("cache"), current, arch);
        seed_cache(&dir.path().join("cache"), older, arch);

        let mut sc = VmStartConfig {
            ..VmStartConfig::default()
        };
        attach_runtime_overlay_if_cached(&mut sc, "firecracker").unwrap();

        let expected_layout =
            RuntimeOverlayResolver::new(dir.path().join("cache"), current.to_string())
                .layout(&arch.to_string());
        assert_eq!(sc.runtime_overlay_version.as_deref(), Some(current));
        assert_eq!(
            sc.runtime_overlay_path.as_deref(),
            Some(
                expected_layout
                    .overlay_ext4
                    .to_str()
                    .expect("utf-8 overlay path")
            )
        );
    }

    #[test]
    fn attach_runtime_overlay_if_cached_ignores_stale_recorded_version_on_plain_boot() {
        let _env_lock = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut env = TestEnv::new();
        let dir = tempfile::tempdir().unwrap();
        env.isolate_mvm_home(dir.path());
        env.set(RUNTIME_OVERLAY_ACQUIRE_MODE_ENV, "download");

        let current = env!("CARGO_PKG_VERSION");
        let stale = if current == "0.17.0" {
            "0.16.9"
        } else {
            "0.17.0"
        };
        let arch = GuestArch::host();
        seed_cache(&dir.path().join("cache"), current, arch);
        seed_cache(&dir.path().join("cache"), stale, arch);

        let mut sc = VmStartConfig {
            runtime_overlay_version: Some(stale.to_string()),
            ..VmStartConfig::default()
        };
        attach_runtime_overlay_if_cached(&mut sc, "firecracker").unwrap();

        let expected_layout =
            RuntimeOverlayResolver::new(dir.path().join("cache"), current.to_string())
                .layout(&arch.to_string());
        assert_eq!(sc.runtime_overlay_version.as_deref(), Some(current));
        assert_eq!(
            sc.runtime_overlay_path.as_deref(),
            Some(
                expected_layout
                    .overlay_ext4
                    .to_str()
                    .expect("utf-8 overlay path")
            )
        );
    }

    /// A member cut from a workspace at another version than this CLI's.
    const MEMBER_VERSION: &str = "0.0.1-member";

    /// Install `MEMBER_VERSION` of the overlay as a member of `set`, laid out
    /// exactly as the image-set download installs one.
    fn seed_set_member(
        cache: &std::path::Path,
        set: &mvm_build::published_image_set::SetMemberCache,
        arch: GuestArch,
    ) {
        seed_cache(&set.cache_root(cache), MEMBER_VERSION, arch);
        set.record(
            cache,
            mvm_core::image_set::ImageSetRole::RuntimeOverlay,
            mvm_core::image_set::MemberTarget::Arch(arch),
            &mvm_build::published_image_set::MemberVersion::parse(MEMBER_VERSION).unwrap(),
        )
        .unwrap();
    }

    /// The published overlay is identified by the root this build pins, so a
    /// member at another version than this CLI's attaches from the cache. The
    /// transport points nowhere: reaching for the network would fail the boot.
    #[test]
    fn a_pinned_set_member_at_another_version_attaches_without_the_network() {
        let _env_lock = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        assert_ne!(MEMBER_VERSION, env!("CARGO_PKG_VERSION"));
        let mut env = TestEnv::new();
        let dir = tempfile::tempdir().unwrap();
        env.isolate_mvm_home(dir.path());
        env.set(RUNTIME_OVERLAY_ACQUIRE_MODE_ENV, "download");
        env.set(
            "MVM_UPDATE_DOWNLOAD_URL",
            "file:///nonexistent/mvm-runtime-overlay-release-fixture",
        );
        let arch = GuestArch::host();
        let cache = dir.path().join("cache");
        let set = mvm_build::published_image_set::SetMemberCache::locked();
        seed_set_member(&cache, &set, arch);

        let mut sc = VmStartConfig::default();
        attach_runtime_overlay_if_cached(&mut sc, "firecracker")
            .expect("the pinned set's member must attach from the cache");

        let expected = RuntimeOverlayResolver::new(set.cache_root(&cache), MEMBER_VERSION.into())
            .layout(&arch.to_string());
        assert_eq!(sc.runtime_overlay_version.as_deref(), Some(MEMBER_VERSION));
        assert_eq!(
            sc.runtime_overlay_path.as_deref(),
            expected.overlay_ext4.to_str()
        );
    }

    /// A member installed from a root this build no longer pins is not used:
    /// the boot goes to the pinned set for its member instead.
    #[test]
    fn a_member_of_another_root_is_not_reused_for_a_boot() {
        let _env_lock = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut env = TestEnv::new();
        let dir = tempfile::tempdir().unwrap();
        let mirror = tempfile::tempdir().unwrap();
        env.isolate_mvm_home(dir.path());
        env.set(RUNTIME_OVERLAY_ACQUIRE_MODE_ENV, "download");
        env.set(
            "MVM_UPDATE_DOWNLOAD_URL",
            format!("file://{}", mirror.path().display()),
        );
        let arch = GuestArch::host();
        let cache = dir.path().join("cache");
        let previous = mvm_build::published_image_set::SetMemberCache::for_root(
            mvm_core::packs::Sha256Hex::from_bytes(b"a previously pinned root"),
        );
        seed_set_member(&cache, &previous, arch);

        let mut sc = VmStartConfig::default();
        let err = attach_runtime_overlay_if_cached(&mut sc, "firecracker")
            .expect_err("another root's member must not satisfy the boot");

        let msg = format!("{err:#}");
        assert!(msg.contains("locked image-set manifest"), "{msg}");
        assert!(sc.runtime_overlay_path.is_none());
    }
}
