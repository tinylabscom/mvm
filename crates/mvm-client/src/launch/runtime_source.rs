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
    // The wasm backend runs a WASI module directly; it has no guest agent
    // runtime overlay to attach.
    if hypervisor == "wasm" {
        return Ok(());
    }
    let version = expected_version.unwrap_or(env!("CARGO_PKG_VERSION"));
    let cache_root = std::path::PathBuf::from(mvm_core::config::mvm_cache_dir());
    let arch = mvm_core::arch::GuestArch::host();
    // Selecting a local image checkout changes only Linux-layer image
    // targets. The guest runtime still comes from this mvm source checkout.
    if pair.is_some() {
        if expected_version.is_some_and(|pinned| pinned != env!("CARGO_PKG_VERSION")) {
            anyhow::bail!(
                "runtime overlay version {version} is pinned for this boot, but the selected source-built mvmctl provides only {}; do not replace the pinned guest runtime",
                env!("CARGO_PKG_VERSION")
            );
        }
        let workspace_root = runtime_overlay_source_checkout_root().ok_or_else(|| {
            anyhow::anyhow!(
                "a selected image checkout cannot provide the guest runtime; run a source-built mvmctl or use the published runtime"
            )
        })?;
        let artifact = acquire_runtime_overlay(&RuntimeOverlayAcquireParams {
            cache_root: &cache_root,
            expected_version: version,
            arch,
            source_checkout_root: Some(&workspace_root),
        })?;
        apply_runtime_overlay_artifact(start_config, artifact);
        return Ok(());
    }
    if expected_version.is_none()
        && matches!(hypervisor, "firecracker" | "hvf" | "qemu" | "libkrun")
        && runtime_overlay_acquire_mode() == RuntimeOverlayAcquireMode::BuildFromSourceCheckout
        && runtime_overlay_source_checkout_root().is_some()
    {
        let workspace_root = runtime_overlay_source_checkout_root()
            .expect("source build mode already verified a source checkout");
        let artifact = acquire_runtime_overlay(&RuntimeOverlayAcquireParams {
            cache_root: &cache_root,
            expected_version: version,
            arch,
            source_checkout_root: Some(&workspace_root),
        })?;
        apply_runtime_overlay_artifact(start_config, artifact);
        return Ok(());
    }
    if !matches!(hypervisor, "firecracker" | "hvf" | "qemu" | "libkrun") {
        return Ok(());
    }
    // Verify the archive before consulting any assembled artifact. A warm
    // legacy overlay must not mask a missing or invalid release signature.
    let source_checkout_root = match runtime_overlay_acquire_mode() {
        RuntimeOverlayAcquireMode::BuildFromSourceCheckout => (version
            == env!("CARGO_PKG_VERSION"))
        .then(runtime_overlay_source_checkout_root)
        .flatten(),
        RuntimeOverlayAcquireMode::DownloadPublishedArtifact => None,
    };
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
/// 1. Return immediately when no bound SDK service needs a sidecar; reject an
///    unknown guest libc before selecting a host artifact.
/// 2. For a source checkout, assemble from the shared guest-runtime archive.
/// 3. For a published runtime, verify the exact CLI release archive and
///    assemble the sidecar from it. Never substitute an image-set runtime.
pub fn resolve_sdk_sidecar_attachment_for_host(
    services: &[mvm_contract::protocol::broker::ServiceId],
    libc: mvm_contract::guest_libc::GuestLibc,
    pair: Option<&mut PairArtifactSource<'_>>,
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

    if pair.is_some()
        || runtime_overlay_acquire_mode() == RuntimeOverlayAcquireMode::BuildFromSourceCheckout
    {
        if let Some(workspace_root) = runtime_overlay_source_checkout_root() {
            let runtime = mvm_build::guest_runtime::resolve_or_build_source_guest_runtime(
                &cache_root,
                version,
                arch,
                &workspace_root,
            )
            .context("resolve the shared guest runtime for the SDK sidecar")?;
            mvm_build::sdk_sidecar::build_sdk_sidecar_from_guest_runtime(
                &cache_root,
                version,
                arch,
                libc,
                &runtime,
            )
            .context("assemble the SDK sidecar from the shared guest runtime")?;
            return mvm_runtime::sdk_sidecar::resolve_sdk_sidecar_attachment(
                services, &resolver, arch, libc,
            );
        }
        if pair.is_some() {
            anyhow::bail!(
                "a selected image checkout cannot provide the SDK guest runtime; run a source-built mvmctl or use the published runtime"
            );
        }
    }

    let runtime =
        mvm_build::guest_runtime::resolve_or_download_guest_runtime(&cache_root, version, arch)
            .with_context(|| sdk_sidecar_download_failure_context(services, arch, libc))?;
    mvm_build::sdk_sidecar::build_sdk_sidecar_from_guest_runtime(
        &cache_root,
        version,
        arch,
        libc,
        &runtime,
    )
    .context("assemble the SDK sidecar from the signed released guest runtime")?;
    mvm_runtime::sdk_sidecar::resolve_sdk_sidecar_attachment(services, &resolver, arch, libc)
}

/// Prewarm the host-assembled runtime overlay for a launch that selected a
/// local Linux image checkout. SDK sidecars are assembled only when the
/// workload actually binds an SDK host service.
pub fn prepare_pair_launch_artifacts(_pair: &mut PairArtifactSource<'_>) -> Result<()> {
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
        source_checkout_root: Some(&workspace_root),
    })?;
    Ok(())
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
         read-only at {}; acquiring the signed CLI release guest runtime for the {libc} sidecar on {arch} failed",
        bound.join(", "),
        mvm_core::plan::SDK_SIDECAR_GUEST_PATH,
    )
}

/// A deliberately invalid release cache entry prevents any test from reaching
/// the network, while exercising the real acquisition boundary.
#[cfg(test)]
fn seed_invalid_release(cache: &std::path::Path, version: &str, failure: &str) {
    use sha2::Digest;
    let dir = cache.join("guest-runtime/releases").join(version);
    std::fs::create_dir_all(&dir).unwrap();
    let asset_version = if failure == "wrong-version" {
        "0.0.0-wrong"
    } else {
        version
    };
    let asset = format!("mvm-guest-bins-v{asset_version}.tar.gz");
    let bytes = b"unsigned guest runtime";
    std::fs::write(dir.join(&asset), bytes).unwrap();
    let digest = if failure == "corrupt" {
        "0".repeat(64)
    } else {
        hex::encode(sha2::Sha256::digest(bytes))
    };
    std::fs::write(
        dir.join(format!("{asset}.sha256")),
        format!("{digest}  {asset}\n"),
    )
    .unwrap();
    if failure != "unsigned" {
        std::fs::write(dir.join(format!("{asset}.bundle")), b"invalid bundle").unwrap();
    }
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

    /// An incomplete released archive must fail before sidecar assembly.
    #[test]
    fn a_download_mode_host_refuses_an_incomplete_guest_runtime() {
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

        seed_invalid_release(&dir.path().join("cache"), version, "unsigned");
        let err = resolve_sdk_sidecar_attachment_for_host(
            &[svc("host.audit.v1")],
            mvm_contract::guest_libc::GuestLibc::Glibc,
            None,
        )
        .expect_err("an unsigned archive cannot satisfy the binding");
        let msg = format!("{err:#}");

        assert!(msg.contains("host.audit.v1"), "{msg}");
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

    /// An image-set sidecar cannot hide a rejected released guest runtime.
    #[test]
    fn a_download_mode_host_refuses_a_sidecar_adopted_from_the_pinned_set() {
        let member_version = "0.0.1-member";
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

            seed_invalid_release(&cache, env!("CARGO_PKG_VERSION"), "corrupt");
            resolve_sdk_sidecar_attachment_for_host(&[svc("host.kv.v1")], libc, None)
                .expect_err("an image-set sidecar must not bypass archive verification");
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

        seed_invalid_release(
            &dir.path().join("cache"),
            env!("CARGO_PKG_VERSION"),
            "unsigned",
        );
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

    /// Even an assembled sidecar at the requested version requires provenance.
    #[test]
    fn a_warm_sidecar_does_not_bypass_unsigned_archive_rejection() {
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

        seed_invalid_release(&dir.path().join("cache"), version, "unsigned");
        let attached = resolve_sdk_sidecar_attachment_for_host(
            &[svc("host.audit.v1")],
            mvm_contract::guest_libc::GuestLibc::Musl,
            None,
        )
        .expect_err("a warm sidecar cannot bypass archive verification");
        assert!(format!("{attached:#}").contains("host.audit.v1"));
    }

    /// A wrong-version released asset cannot select an old image-set sidecar.
    #[test]
    fn a_pinned_set_sidecar_does_not_mask_a_wrong_version_release() {
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

            seed_invalid_release(&cache, env!("CARGO_PKG_VERSION"), "wrong-version");
            resolve_sdk_sidecar_attachment_for_host(&[svc("host.audit.v1")], libc, None)
                .expect_err("a wrong-version release must not fall back to an image-set sidecar");
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

    /// A rejected release cannot populate the assembled overlay cache.
    #[test]
    fn required_overlay_cache_miss_refuses_an_unsigned_release() {
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
        seed_invalid_release(
            &cache.path().join("cache"),
            env!("CARGO_PKG_VERSION"),
            "unsigned",
        );
        let err = attach_runtime_overlay_if_cached_version(&mut sc, "firecracker", None, None)
            .expect_err("an unsigned release cannot supply the overlay");
        let msg = format!("{err:#}");

        assert!(msg.contains("signed released guest runtime"), "{msg}");
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
    fn a_requested_cached_overlay_does_not_bypass_release_verification() {
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
        seed_invalid_release(&dir.path().join("cache"), pinned, "unsigned");
        attach_runtime_overlay_if_cached_version(&mut sc, "firecracker", Some(pinned), None)
            .expect_err("a pinned assembled overlay is not release provenance");
        assert!(sc.runtime_overlay_path.is_none());
        assert!(sc.runtime_overlay_version.is_none());
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
        seed_invalid_release(&dir.path().join("cache"), missing, "wrong-version");
        let err =
            attach_runtime_overlay_if_cached_version(&mut sc, "firecracker", Some(missing), None)
                .unwrap_err();

        let msg = format!("{err:#}");
        assert!(msg.contains("signed released guest runtime"), "{msg}");
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
    fn current_host_overlay_does_not_mask_a_corrupt_release() {
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
        seed_invalid_release(&dir.path().join("cache"), current, "corrupt");
        attach_runtime_overlay_if_cached(&mut sc, "firecracker")
            .expect_err("current and older assembled overlays cannot mask a corrupt release");
        assert!(sc.runtime_overlay_path.is_none());
        assert!(sc.runtime_overlay_version.is_none());
    }

    #[test]
    fn stale_recorded_version_cannot_mask_an_unsigned_current_release() {
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
        seed_invalid_release(&dir.path().join("cache"), current, "unsigned");
        attach_runtime_overlay_if_cached(&mut sc, "firecracker")
            .expect_err("a plain boot must verify the current release");
        assert!(sc.runtime_overlay_path.is_none());
        assert_eq!(sc.runtime_overlay_version.as_deref(), Some(stale));
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

    /// The pinned Linux image set cannot substitute its guest runtime.
    #[test]
    fn a_pinned_set_member_does_not_mask_a_corrupt_release() {
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

        seed_invalid_release(&cache, env!("CARGO_PKG_VERSION"), "corrupt");
        let mut sc = VmStartConfig::default();
        attach_runtime_overlay_if_cached(&mut sc, "firecracker")
            .expect_err("the pinned set's member cannot replace a rejected runtime");
        assert!(sc.runtime_overlay_path.is_none());
        assert!(sc.runtime_overlay_version.is_none());
    }

    /// An old image-set root is not a fallback for a rejected CLI release.
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

        seed_invalid_release(&cache, env!("CARGO_PKG_VERSION"), "wrong-version");
        let mut sc = VmStartConfig::default();
        let err = attach_runtime_overlay_if_cached(&mut sc, "firecracker")
            .expect_err("another root's member must not satisfy the boot");

        let msg = format!("{err:#}");
        assert!(msg.contains("signed released guest runtime"), "{msg}");
        assert!(sc.runtime_overlay_path.is_none());
    }
}
