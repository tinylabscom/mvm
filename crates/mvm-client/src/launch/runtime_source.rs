//! Runtime-overlay attachment + status resolution for workload boots —
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
    AcquiredRuntimeOverlay, RuntimeOverlayAcquireMode, RuntimeOverlayAcquireParams,
    acquire_runtime_overlay, acquire_runtime_overlay_for_launch, runtime_overlay_acquire_mode,
    runtime_overlay_source_checkout_root,
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
    // A layout-only cache hit does not authenticate the archive that produced
    // it. Never retain a previous selection's proof across replacement.
    start_config.runtime_release_proof = None;
    start_config.unsigned_runtime_development = false;
    start_config.source_runtime_archive_sha256 = None;
    start_config.legacy_portable_runtime = None;
    start_config.legacy_bundle_runtime = None;
    start_config.bundle_boot_assets = None;
    start_config.runtime_overlay_path = Some(artifact.overlay_ext4.display().to_string());
    start_config.runtime_overlay_verity_path = Some(artifact.sidecar.display().to_string());
    start_config.runtime_overlay_version = Some(artifact.version);
    start_config.runtime_overlay_roothash = Some(artifact.roothash);
}

fn apply_acquired_runtime_overlay(
    start_config: &mut mvm_core::vm_backend::VmStartConfig,
    acquired: AcquiredRuntimeOverlay,
) {
    apply_runtime_overlay_artifact(start_config, acquired.artifact);
    start_config.runtime_release_proof = acquired.release_proof;
    // A request for development admission, never authority to bypass it.
    start_config.unsigned_runtime_development = acquired.unsigned_source;
    start_config.source_runtime_archive_sha256 = acquired.source_archive_sha256;
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
    // Every backend that boots a kernel boots the universal initramfs, and
    // that initramfs mounts the overlay. `apple-container` is the HVF runner
    // with another kernel image, so it needs the overlay exactly as HVF does.
    if !mvm_runtime::universal_initramfs::KERNEL_BOOTING_HYPERVISORS.contains(&hypervisor) {
        return Ok(());
    }
    match acquire_runtime_overlay_for_launch(resolver, arch) {
        Ok(a) => {
            apply_acquired_runtime_overlay(start_config, a);
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
/// A selected local image checkout plus the build closure used for Linux-layer
/// image targets. Guest runtime artifacts are assembled from this repository
/// on the host and never invoke the pair closure.
pub struct PairArtifactSource<'a> {
    pub checkout: &'a mvm_build::image_source::LocalImageCheckout,
    /// Build (or cache-hit) one image-set target of the pair. Returns the
    /// verified cache entry holding the target's files.
    pub build: &'a mut dyn FnMut(
        &mvm_build::image_source::LocalImageCheckout,
        mvm_build::image_source::ImageBuildTarget,
    ) -> anyhow::Result<mvm_build::image_source::CachedImageSet>,
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

/// The selected-checkout form takes a local image checkout through
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
    let mut selected = start_config.clone();
    attach_runtime_overlay_selection(&mut selected, hypervisor, expected_version, pair)?;
    *start_config = selected;
    Ok(())
}

fn attach_runtime_overlay_selection(
    start_config: &mut mvm_core::vm_backend::VmStartConfig,
    hypervisor: &str,
    expected_version: Option<&str>,
    pair: Option<&mut PairArtifactSource<'_>>,
) -> Result<()> {
    if super::bundle_runtime::attach_if_installed_bundle(start_config, hypervisor)? {
        return Ok(());
    }
    anyhow::ensure!(
        start_config.bundle_boot_assets.is_none(),
        "bundle boot-assets pin has no verified installed bundle; refusing runtime fallback"
    );
    if start_config.legacy_portable_runtime.is_some()
        || start_config.legacy_bundle_runtime.is_some()
        || start_config.runtime_release_proof.is_some()
        || start_config.source_runtime_archive_sha256.is_some()
        || start_config.unsigned_runtime_development
    {
        mvm_runtime::runtime_evidence::verify_runtime_for_launch(
            start_config,
            mvm_runtime::runtime_evidence::MIN_GUEST_RPC_PROTOCOL_VERSION,
        )?;
        return Ok(());
    }
    // The wasm backend runs a WASI module directly; it has no guest agent
    // runtime overlay to attach.
    if hypervisor == "wasm" {
        return Ok(());
    }
    let version = expected_version.unwrap_or(env!("CARGO_PKG_VERSION"));
    let cache_root = std::path::PathBuf::from(mvm_core::config::mvm_cache_dir());
    let arch = mvm_core::arch::GuestArch::host();
    // Selecting a local image checkout changes only Linux-layer image targets.
    // It does not grant a launch permission to compile the guest runtime.
    if pair.is_some() && expected_version.is_some_and(|pinned| pinned != env!("CARGO_PKG_VERSION"))
    {
        anyhow::bail!(
            "runtime overlay version {version} is pinned for this boot, but the selected source-built mvmctl provides only {}; do not replace the pinned guest runtime",
            env!("CARGO_PKG_VERSION")
        );
    }
    let resolver =
        mvm_fs::overlay::RuntimeOverlayResolver::new(cache_root.clone(), version.to_string());
    // The overlay is assembled from this CLI's own guest runtime and lives
    // only in its version-keyed slot. A miss is preparation work for
    // `mvmctl bootstrap`; no other copy is attached in its place.
    attach_runtime_overlay(start_config, hypervisor, &resolver, arch).with_context(|| {
        match expected_version {
            // Continuity asked for the overlay a machine booted with; this CLI
            // cannot assemble another version's, so name what is missing.
            Some(pinned) if pinned != env!("CARGO_PKG_VERSION") => format!(
                "runtime overlay version {pinned} is required for this boot and was not found \
                 in the local cache"
            ),
            _ => prepare_hint(version, arch),
        }
    })
}

/// The command that prepares this CLI's guest runtime pieces, for a launch
/// that found one missing.
fn prepare_hint(version: &str, arch: mvm_core::arch::GuestArch) -> String {
    let command = match runtime_overlay_acquire_mode() {
        RuntimeOverlayAcquireMode::BuildFromSourceCheckout => {
            "MVM_RUNTIME_OVERLAY_ACQUIRE_MODE=build mvmctl bootstrap"
        }
        RuntimeOverlayAcquireMode::DownloadPublishedArtifact => "mvmctl bootstrap",
    };
    format!("the guest runtime {version} for {arch} is not prepared; run `{command}` first")
}

// ── SDK sidecar ──────────────────────────────────────────────────────────────

/// Production wrapper: build the sidecar resolver from the mvm cache dir + the
/// running mvmctl version, then resolve for `services`.
///
/// The decision, the resolution, and the attachment shape live in
/// `mvm_runtime::sdk_sidecar` so every driver — not just the CLI — reaches one
/// contract; this supplies the host's cache root and version and remains a
/// cache-only launch resolver, like
/// [`attach_runtime_overlay_if_cached_version`] is for the overlay:
///
/// 1. Return immediately when no bound SDK service needs a sidecar; reject an
///    unknown guest libc before selecting a host artifact.
/// 2. Resolve the prepared version-keyed sidecar.
/// 3. Refuse a miss with the explicit bootstrap command; never assemble or
///    download from the launch path.
pub fn resolve_sdk_sidecar_attachment_for_host(
    services: &[mvm_contract::protocol::broker::ServiceId],
    libc: mvm_contract::guest_libc::GuestLibc,
    _pair: Option<&mut PairArtifactSource<'_>>,
) -> Result<Option<SdkSidecarAttachment>> {
    // This decision precedes even the pair target and fingerprint. Most
    // workloads bind no SDK host service and must do no sidecar work at all.
    if !mvm_core::plan::sdk_sidecar_required_for(services, true) {
        return Ok(None);
    }
    let cache_root = std::path::PathBuf::from(mvm_core::config::mvm_cache_dir());
    let version = env!("CARGO_PKG_VERSION");
    let arch = mvm_core::arch::GuestArch::host();
    let resolver =
        mvm_fs::sdk_sidecar::SdkSidecarResolver::new(cache_root.clone(), version.to_string());

    // A bound SDK service with an undetected libc is a hard error. Resolve
    // before touching the source cache so no host artifact is built on a
    // guessed ABI.
    if libc == mvm_contract::guest_libc::GuestLibc::Unknown {
        return mvm_runtime::sdk_sidecar::resolve_sdk_sidecar_attachment(
            services, &resolver, arch, libc,
        );
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

    Err(cache_miss).with_context(|| {
        format!("SDK sidecar for {arch}/{libc} is not prepared; run `mvmctl bootstrap` first")
    })
}

/// Prewarm the host-assembled runtime overlay for a launch that selected a
/// local Linux image checkout. SDK sidecars are assembled only when the
/// workload actually binds an SDK host service.
pub fn prepare_pair_launch_artifacts(_pair: &mut PairArtifactSource<'_>) -> Result<()> {
    if runtime_overlay_acquire_mode() != RuntimeOverlayAcquireMode::BuildFromSourceCheckout {
        return Ok(());
    }
    let cache_root = std::path::PathBuf::from(mvm_core::config::mvm_cache_dir());
    let version = env!("CARGO_PKG_VERSION");
    let arch = mvm_core::arch::GuestArch::host();
    let workspace_root = runtime_overlay_source_checkout_root().ok_or_else(|| {
        anyhow::anyhow!("a selected image checkout needs a source-built mvmctl guest runtime")
    })?;
    acquire_runtime_overlay(&RuntimeOverlayAcquireParams {
        cache_root: &cache_root,
        expected_version: version,
        arch,
        source_checkout_root: &workspace_root,
    })?;
    Ok(())
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
/// A warning, not an implicit rebuild: a launch resolves prepared artifacts
/// only, and repacking stays the explicit bootstrap step.
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
         `mvmctl dev sdk-sidecar build`, which repacks both libc variants on the host from \
         this checkout's guest runtime. Provenance marker: {}.",
        marker.display()
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

    /// Record that this version adopted a release guest runtime for `arch`,
    /// as a release bootstrap does once it has assembled every piece.
    pub(super) fn record_adopted_release(cache: &std::path::Path, arch: GuestArch) {
        let record = mvm_build::runtime_pieces::release_adoption_record(
            cache,
            env!("CARGO_PKG_VERSION"),
            arch,
        );
        std::fs::create_dir_all(record.parent().unwrap()).unwrap();
        std::fs::write(record, format!("{}\n", "e".repeat(64))).unwrap();
    }

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
        // The remedy packs on the host from the guest runtime, so it needs
        // neither an image checkout nor the builder VM.
        assert!(
            warning.contains("`mvmctl dev sdk-sidecar build`"),
            "{warning}"
        );
        assert!(!warning.contains("MVM_IMAGES_DIR"), "{warning}");
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
    fn source_mode_without_sdk_bindings_does_no_sidecar_work() {
        let dir = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(dir.path());
        env.set(
            crate::launch::runtime_overlay::RUNTIME_OVERLAY_ACQUIRE_MODE_ENV,
            "build",
        );
        assert_eq!(
            resolve_sdk_sidecar_attachment_for_host(
                &[svc("broker.v1")],
                mvm_contract::guest_libc::GuestLibc::Musl,
                None,
            )
            .unwrap(),
            None,
        );
        assert!(!dir.path().join("cache/guest-runtime").exists());
        assert!(!dir.path().join("cache/sdk-sidecar").exists());
    }

    /// A base URL no transport can reach. Any test asserting "the network was
    /// not touched" points here: if the acquire path ran, the call fails.
    const UNREACHABLE_BASE_URL: &str = "file:///nonexistent/mvm-sdk-sidecar-release-fixture";

    /// A download-mode launch with a cold cache refuses and names bootstrap;
    /// it never contacts the configured mirror.
    #[test]
    fn a_download_mode_host_refuses_an_unprepared_sidecar() {
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
        .expect_err("launch must not acquire a missing sidecar");
        let msg = format!("{err:#}");

        assert!(msg.contains("mvmctl bootstrap"), "{msg}");
        let layout = SdkSidecarLayout::under(
            &dir.path().join("cache"),
            version,
            &arch.to_string(),
            mvm_contract::guest_libc::GuestLibc::Glibc,
        );
        assert!(!layout.artifact_dir.exists(), "nothing may be cached");
    }

    /// An unknown guest libc cannot select one of the two host-packed
    /// sidecars. This fails before trying to build the shared source archive.
    #[test]
    fn an_unknown_libc_with_a_required_service_fails_before_source_build() {
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
            mvm_contract::guest_libc::GuestLibc::Unknown,
            None,
        )
        .expect_err("an unknown libc must fail closed without building a guessed sidecar");
        let msg = format!("{err:#}");

        assert!(msg.contains("host.kv.v1"), "{msg}");
        assert!(msg.contains("libc is unknown"), "{msg}");
        assert!(!dir.path().join("cache/guest-runtime").exists());
    }

    /// Seed the `libc` sidecar the way an older CLI installed it from the
    /// pinned image set: under the set's root, at the member's own version.
    fn seed_pinned_set_sidecar(
        cache: &std::path::Path,
        member_version: &str,
        arch: GuestArch,
        libc: mvm_contract::guest_libc::GuestLibc,
    ) {
        let set = mvm_build::published_image_set::SetMemberCache::locked();
        seed_sidecar_variant(&set.cache_root(cache), member_version, arch, libc);
        set.record(
            cache,
            mvm_core::image_set::ImageSetRole::RetiredGuestRuntime(
                mvm_core::image_set::RetiredGuestRuntimeRole::SdkSidecar(libc),
            ),
            mvm_core::image_set::MemberTarget::Arch(arch),
            &mvm_build::published_image_set::MemberVersion::parse(member_version).unwrap(),
        )
        .unwrap();
    }

    /// A sidecar an older CLI installed from the pinned image set is still
    /// on disk after an upgrade. A launch never attaches it, for either libc,
    /// whether or not this version adopted a release guest runtime: the
    /// sidecar comes from this CLI's own guest runtime, and a miss names the
    /// bootstrap that assembles it.
    #[test]
    fn a_launch_never_attaches_the_image_sets_sidecar() {
        for adopted in [false, true] {
            for libc in [
                mvm_contract::guest_libc::GuestLibc::Glibc,
                mvm_contract::guest_libc::GuestLibc::Musl,
            ] {
                let dir = tempfile::tempdir().unwrap();
                let arch = GuestArch::host();
                let cache = dir.path().join("cache");
                seed_pinned_set_sidecar(&cache, env!("CARGO_PKG_VERSION"), arch, libc);
                if adopted {
                    record_adopted_release(&cache, arch);
                }

                let mut env = mvm_core::util::test_env::TestEnv::new();
                env.isolate_mvm_home(dir.path());
                env.set(
                    crate::launch::runtime_overlay::RUNTIME_OVERLAY_ACQUIRE_MODE_ENV,
                    "download",
                );
                env.set("MVM_UPDATE_DOWNLOAD_URL", UNREACHABLE_BASE_URL);

                let error =
                    resolve_sdk_sidecar_attachment_for_host(&[svc("host.kv.v1")], libc, None)
                        .expect_err("the image set's sidecar is not this CLI's");
                let rendered = format!("{error:#}");
                assert!(rendered.contains("mvmctl bootstrap"), "{rendered}");
            }
        }
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
}

#[cfg(test)]
mod runtime_overlay_attach_tests {
    use super::*;

    fn mock_proof() -> mvm_core::protocol::runtime_release::RuntimeReleaseProof {
        mvm_core::protocol::runtime_release::RuntimeReleaseProof {
            archive: "/mock/archive".into(),
            checksum: "/mock/checksum".into(),
            signature_bundle: "/mock/signature".into(),
            archive_sha256: "a".repeat(64),
            version: "selected-release".into(),
            arch: mvm_core::arch::GuestArch::host(),
        }
    }

    fn mock_artifact() -> mvm_fs::overlay::RuntimeOverlayArtifact {
        mvm_fs::overlay::RuntimeOverlayArtifact {
            overlay_ext4: "/mock/overlay".into(),
            sidecar: "/mock/verity".into(),
            roothash_file: "/mock/roothash".into(),
            roothash: "b".repeat(64),
            arch: mvm_core::arch::GuestArch::host().to_string(),
            version: "selected-release".into(),
        }
    }

    #[test]
    fn selected_runtime_proof_handoff_is_not_cryptographic_verification() {
        let mut config = VmStartConfig::default();
        apply_acquired_runtime_overlay(
            &mut config,
            AcquiredRuntimeOverlay {
                artifact: mock_artifact(),
                release_proof: Some(mock_proof()),
                unsigned_source: false,
                source_archive_sha256: None,
            },
        );
        let proof = config.runtime_release_proof.as_ref().unwrap();
        assert_eq!(proof.archive, std::path::Path::new("/mock/archive"));
        assert_eq!(
            config.runtime_overlay_version.as_deref(),
            Some("selected-release")
        );
        assert!(!config.unsigned_runtime_development);
        // Synthetic locator fixture only: forwarding never makes it verified.
        assert!(
            mvm_build::guest_runtime::evidence::verify_runtime_release_proof(
                proof,
                "selected-release",
                GuestArch::host(),
            )
            .is_err()
        );
    }

    #[test]
    fn replacing_selected_runtime_clears_stale_proof_and_development_request() {
        let mut config = VmStartConfig {
            runtime_release_proof: Some(mock_proof()),
            unsigned_runtime_development: true,
            source_runtime_archive_sha256: Some("c".repeat(64)),
            ..Default::default()
        };
        apply_runtime_overlay_artifact(&mut config, mock_artifact());
        assert!(config.runtime_release_proof.is_none());
        assert!(!config.unsigned_runtime_development);
        assert!(config.source_runtime_archive_sha256.is_none());
    }

    #[test]
    fn source_runtime_handoff_requests_development_without_inventing_proof() {
        let mut config = VmStartConfig {
            runtime_release_proof: Some(mock_proof()),
            ..Default::default()
        };
        apply_acquired_runtime_overlay(
            &mut config,
            AcquiredRuntimeOverlay {
                artifact: mock_artifact(),
                release_proof: None,
                unsigned_source: true,
                source_archive_sha256: Some("c".repeat(64)),
            },
        );
        assert!(config.runtime_release_proof.is_none());
        assert!(config.unsigned_runtime_development);
        assert_eq!(config.source_runtime_archive_sha256, Some("c".repeat(64)));
    }

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
    /// validates), backed by the ordinary checked source archive.
    fn seed_cache(cache: &std::path::Path, version: &str, arch: GuestArch) {
        let Some(workspace) = runtime_overlay_source_checkout_root() else {
            seed_layout_only_cache(cache, version, arch);
            return;
        };
        let runtime = mvm_build::guest_runtime::test_support::write_source_cache_fixture(
            cache, &workspace, version, arch,
        )
        .unwrap();
        mvm_build::runtime_overlay::build_runtime_overlay_from_guest_runtime(
            cache, version, arch, &runtime,
        )
        .unwrap();
    }

    fn seed_layout_only_cache(cache: &std::path::Path, version: &str, arch: GuestArch) {
        let layout = RuntimeOverlayResolver::new(cache.to_path_buf(), version.to_string())
            .layout(&arch.to_string());
        std::fs::create_dir_all(&layout.artifact_dir).unwrap();
        let overlay = valid_overlay_ext4_bytes(version, true);
        let sidecar = b"verity-bytes";
        let roothash = format!("{}\n", "a".repeat(64));
        let version_text = format!("{version}\n");
        std::fs::write(&layout.overlay_ext4, &overlay).unwrap();
        std::fs::write(&layout.sidecar, sidecar).unwrap();
        std::fs::write(&layout.roothash_file, &roothash).unwrap();
        std::fs::write(&layout.version_file, &version_text).unwrap();
        std::fs::write(
            &layout.checksum_manifest_file,
            format!(
                "{}  overlay.ext4\n{}  overlay.verity\n{}  overlay.roothash\n{}  VERSION\n",
                sha256_hex(&overlay),
                sha256_hex(sidecar),
                sha256_hex(roothash.as_bytes()),
                sha256_hex(version_text.as_bytes()),
            ),
        )
        .unwrap();
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        let digest = Sha256::digest(bytes);
        hex::encode(digest)
    }

    #[test]
    fn layout_only_cache_does_not_supply_runtime_authority() {
        let dir = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(dir.path());
        let version = env!("CARGO_PKG_VERSION");
        let arch = GuestArch::host();
        seed_layout_only_cache(dir.path(), version, arch);
        let resolver = RuntimeOverlayResolver::new(dir.path().to_path_buf(), version.into());
        assert!(resolver.resolve(&arch.to_string()).is_ok());
        let mut config = VmStartConfig::default();
        assert!(attach_runtime_overlay(&mut config, "firecracker", &resolver, arch).is_err());
        assert!(config.runtime_overlay_path.is_none());
        assert!(config.runtime_release_proof.is_none());
        assert!(!config.unsigned_runtime_development);
    }

    #[cfg(not(feature = "release-channel"))]
    #[test]
    fn rejected_release_does_not_fall_back_to_a_checked_source_cache() {
        let dir = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(dir.path());
        let version = env!("CARGO_PKG_VERSION");
        let arch = GuestArch::host();
        seed_cache(dir.path(), version, arch);
        let release = dir.path().join("guest-runtime/releases").join(version);
        std::fs::create_dir_all(&release).unwrap();
        std::fs::write(
            release.join(format!("mvm-guest-bins-v{version}.tar.gz")),
            b"unauthenticated release",
        )
        .unwrap();
        let resolver = RuntimeOverlayResolver::new(dir.path().to_path_buf(), version.into());
        let mut config = VmStartConfig::default();
        assert!(attach_runtime_overlay(&mut config, "firecracker", &resolver, arch).is_err());
        assert!(config.runtime_overlay_path.is_none());
        assert!(!config.unsigned_runtime_development);
    }

    #[test]
    fn an_unverified_bundle_pin_is_rejected_before_ambient_resolution() {
        let dir = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(dir.path());
        let mut config = VmStartConfig {
            bundle_boot_assets: Some(mvm_core::vm_backend::BundleBootAssetsPin {
                manifest_sha256: mvm_core::packs::Sha256Hex::from_bytes(b"set"),
                arch: GuestArch::host(),
                initrd_sha256: mvm_core::packs::Sha256Hex::from_bytes(b"initrd"),
            }),
            runtime_overlay_path: Some("/selected/bundle/overlay".into()),
            ..Default::default()
        };
        let error = attach_runtime_overlay_if_cached(&mut config, "firecracker").unwrap_err();
        assert!(error.to_string().contains("no verified installed bundle"));
        assert_eq!(
            config.runtime_overlay_path.as_deref(),
            Some("/selected/bundle/overlay")
        );
        assert!(!dir.path().join("cache").exists());
    }

    #[cfg(feature = "release-channel")]
    #[test]
    fn source_build_override_cannot_authorize_an_unsigned_release_channel_boot() {
        let dir = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(dir.path());
        env.set(RUNTIME_OVERLAY_ACQUIRE_MODE_ENV, "build");
        let version = env!("CARGO_PKG_VERSION");
        let arch = GuestArch::host();
        seed_layout_only_cache(dir.path(), version, arch);
        let resolver = RuntimeOverlayResolver::new(dir.path().to_path_buf(), version.into());
        let mut config = VmStartConfig::default();
        let error =
            attach_runtime_overlay(&mut config, "firecracker", &resolver, arch).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("compiled release channel refuses")
        );
        assert!(!config.unsigned_runtime_development);
    }

    #[cfg(not(feature = "release-channel"))]
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
            Some(
                resolver
                    .resolve(&arch.to_string())
                    .unwrap()
                    .roothash
                    .as_str()
            )
        );
        assert!(sc.unsigned_runtime_development);
        assert!(sc.runtime_release_proof.is_none());
        assert_eq!(sc.runtime_overlay_version.as_deref(), Some(ver));
    }

    #[cfg(not(feature = "release-channel"))]
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

    #[cfg(not(feature = "release-channel"))]
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

    /// `apple-container` is the HVF runner with Apple's kernel: the same
    /// initramfs, the same activation, and the same overlay-contract gate. A
    /// launch that attached no overlay reached that gate with no egress client
    /// and failed activation on any boot that admitted egress.
    #[cfg(not(feature = "release-channel"))]
    #[test]
    fn apple_container_with_cached_overlay_populates_all_three_fields() {
        let dir = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(dir.path());
        let ver = env!("CARGO_PKG_VERSION");
        let arch = GuestArch::host();
        seed_cache(dir.path(), ver, arch);
        let resolver = RuntimeOverlayResolver::new(dir.path().to_path_buf(), ver.to_string());
        let mut sc = VmStartConfig::default();
        attach_runtime_overlay(&mut sc, "apple-container", &resolver, arch).unwrap();
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

    #[cfg(not(feature = "release-channel"))]
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

    /// A required overlay missing from the cache is launch preparation, never
    /// an implicit network operation.
    #[test]
    fn required_overlay_cache_miss_names_explicit_bootstrap() {
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
            .expect_err("a launch must not acquire its missing overlay");
        let msg = format!("{err:#}");

        assert!(msg.contains("mvmctl bootstrap"), "{msg}");
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

    #[cfg(not(feature = "release-channel"))]
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

    #[cfg(not(feature = "release-channel"))]
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

    #[cfg(not(feature = "release-channel"))]
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
    /// exactly as an older CLI installed one from the image set.
    fn seed_set_member(
        cache: &std::path::Path,
        set: &mvm_build::published_image_set::SetMemberCache,
        arch: GuestArch,
    ) {
        seed_cache(&set.cache_root(cache), MEMBER_VERSION, arch);
        set.record(
            cache,
            mvm_core::plan::bundle::BOOT_ASSET_OVERLAY_ROLE,
            mvm_core::image_set::MemberTarget::Arch(arch),
            &mvm_build::published_image_set::MemberVersion::parse(MEMBER_VERSION).unwrap(),
        )
        .unwrap();
    }

    /// An overlay an older CLI installed from the pinned image set is still on
    /// disk after an upgrade. A launch never attaches it, whether or not this
    /// version adopted a release guest runtime: the overlay comes from this
    /// CLI's own guest runtime, and the miss names the bootstrap.
    #[test]
    fn a_launch_never_attaches_the_image_sets_overlay() {
        let _env_lock = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        for adopted in [false, true] {
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
            if adopted {
                super::sdk_sidecar_host_resolution_tests::record_adopted_release(&cache, arch);
            }

            let mut sc = VmStartConfig::default();
            let error = attach_runtime_overlay_if_cached(&mut sc, "firecracker")
                .expect_err("the image set's overlay is not this CLI's");
            let rendered = format!("{error:#}");
            assert!(rendered.contains("mvmctl bootstrap"), "{rendered}");
            assert!(sc.runtime_overlay_path.is_none());
            assert!(sc.runtime_overlay_roothash.is_none());
        }
    }

    /// A member installed from a root this build no longer pins is not used,
    /// and launch does not contact the pinned set to repair the miss.
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
        assert!(msg.contains("mvmctl bootstrap"), "{msg}");
        assert!(sc.runtime_overlay_path.is_none());
    }
}
