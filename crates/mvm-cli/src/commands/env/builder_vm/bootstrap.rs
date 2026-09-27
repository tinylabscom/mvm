use super::stage0_cache::validate_builder_vm_stage0_artifacts;
#[cfg(any(
    all(feature = "release-artifact-bootstrap", feature = "builder-vm"),
    test
))]
use super::stage0_cache::{
    promote_builder_vm_stage0_cache, unique_builder_vm_stage0_staging_dir,
    write_builder_vm_cache_sidecars,
};
use super::*;

#[cfg(test)]
pub(super) fn first_nameserver_from_resolv_conf(body: &str) -> Option<String> {
    mvm_agentd::guest_net::first_nameserver_from_resolv_conf(body)
}

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Stage0InputOverride {
    pub input_path: String,
    pub guest_path: String,
}

#[cfg(test)]
pub(super) fn stage0_build_conf_contents(
    build_attr: &str,
    output_mode: &str,
    resolver: Option<&str>,
    workspace_archive: Option<&str>,
    offline: bool,
    input_overrides: &[Stage0InputOverride],
) -> String {
    let mut out =
        format!("MVM_STAGE0_BUILD_ATTR={build_attr}\nMVM_STAGE0_OUTPUT_MODE={output_mode}\n");
    if let Some(resolver) = resolver {
        out.push_str(&format!("MVM_STAGE0_RESOLVER={resolver}\n"));
    }
    if let Some(workspace_archive) = workspace_archive {
        out.push_str(&format!(
            "MVM_STAGE0_WORKSPACE_ARCHIVE={workspace_archive}\n"
        ));
    }
    if offline {
        out.push_str("MVM_STAGE0_OFFLINE=1\n");
    }
    for (idx, override_) in input_overrides.iter().enumerate() {
        out.push_str(&format!(
            "MVM_STAGE0_OVERRIDE_INPUT_{idx}={}={}\n",
            override_.input_path, override_.guest_path
        ));
    }
    out
}

/// Prepare the builder VM image for the images the caller selected.
///
/// With a local image checkout selected, the builder VM is the checkout
/// pair's `builder-vm` target, built once through the shared local-image-set
/// build and installed from the local image cache. With the selector unset,
/// it is the builder image the image lock pins, fetched and verified. A local
/// build asked for without a checkout is refused rather than answered with
/// the fetched image, which is exactly what the caller asked not to have.
pub(in crate::commands) fn bootstrap_builder_vm_image() -> Result<()> {
    #[cfg(feature = "builder-vm")]
    if let Some(checkout) = selected_local_checkout()? {
        return bootstrap_builder_vm_image_from_local_pair(&checkout);
    }
    refuse_a_local_builder_build(mvm_build::boot_image_select::resolve_env_override())?;
    bootstrap_tool_builder_vm_image()
}

/// Without a checkout there is nothing to build the builder image from, so a
/// caller that forces a local build is refused rather than handed the fetched
/// image it asked not to have.
fn refuse_a_local_builder_build(
    acquisition: Option<mvm_build::boot_image_select::BootImageAcquisition>,
) -> Result<()> {
    if acquisition == Some(mvm_build::boot_image_select::BootImageAcquisition::Build) {
        return Err(
            mvm_build::image_source::ImageConstructionRefused::new("the builder VM image").into(),
        );
    }
    Ok(())
}

/// The local image checkout the selector names, if that is the selected
/// source. A configured path that does not resolve is an error here, never a
/// quiet fall-through to the released set.
pub(crate) fn selected_local_checkout()
-> Result<Option<mvm_build::image_source::LocalImageCheckout>> {
    use mvm_build::image_source::{ImageSource, resolve_current_source};
    Ok(match resolve_current_source()? {
        ImageSource::LocalCheckout(checkout) => Some(checkout),
        ImageSource::Released => None,
    })
}

/// Prepare the builder-VM image the local image-set build itself runs in:
/// the published builder image the image lock pins.
///
/// Exempt from the image source selector: an image-set build runs inside
/// this builder, so routing it through the pair's `builder-vm` target would
/// recurse — building the builder image would need the builder image.
pub(in crate::commands) fn bootstrap_tool_builder_vm_image() -> Result<()> {
    #[cfg(feature = "builder-vm")]
    return bootstrap_builder_vm_image_with(
        || {
            mvm_build::builder_vm_bootstrap::maybe_reexec_builder_vm_bootstrap_helper()
                .map_err(anyhow::Error::from)
        },
        bootstrap_tool_builder_vm_image_in_process,
    );

    #[cfg(not(feature = "builder-vm"))]
    bootstrap_tool_builder_vm_image_in_process()
}

/// Serve the builder-VM cache from the pair's `builder-vm` target: build it
/// through the shared local-image-set path when the pair changed, install the
/// verified entry under a fingerprint naming both checkouts, and answer an
/// unchanged pair from the installed cache.
#[cfg(feature = "builder-vm")]
fn bootstrap_builder_vm_image_from_local_pair(
    checkout: &mvm_build::image_source::LocalImageCheckout,
) -> Result<()> {
    use mvm_build::image_source::{FlakeAttr, ImageBuildRole, ImageBuildTarget};
    let target = ImageBuildTarget {
        role: ImageBuildRole::BuilderVm,
        attr: FlakeAttr::new("default").expect("default is a valid flake attribute"),
    };
    let build = super::local_pair::ensure_pair_built(checkout, target)?;
    let fingerprint = super::local_pair::pair_fingerprint(&build.key);
    let arch = builder_vm_host_arch();
    let out_dir = std::path::Path::new(&mvm_core::config::mvm_cache_dir())
        .join("builder-vm")
        .join(arch);
    if super::stage0_cache::local_pair_cache_ready(&out_dir, &fingerprint) {
        crate::ui::info(&format!(
            "Builder VM image already cached at {}.",
            out_dir.display()
        ));
        return Ok(());
    }
    super::local_pair::install_pair_builder_vm(&build.entry, arch, &fingerprint)
}

#[cfg(feature = "builder-vm")]
fn bootstrap_builder_vm_image_with(
    maybe_reexec: impl FnOnce() -> Result<bool>,
    bootstrap_in_process: impl FnOnce() -> Result<()>,
) -> Result<()> {
    if maybe_reexec()? {
        return Ok(());
    }
    bootstrap_in_process()
}

fn bootstrap_tool_builder_vm_image_in_process() -> Result<()> {
    let arch = builder_vm_host_arch();
    let out_dir = format!("{}/builder-vm/{arch}", mvm_core::config::mvm_cache_dir());
    if validate_builder_vm_stage0_artifacts(std::path::Path::new(&out_dir)).is_ok() {
        ui::info(&format!("Builder VM image already cached at {out_dir}."));
        return Ok(());
    }
    perform_builder_vm_download_published(arch, &out_dir)
}

#[cfg(all(test, feature = "builder-vm"))]
mod bootstrap_helper_routing_tests {
    use super::bootstrap_builder_vm_image_with;
    use std::cell::Cell;

    #[test]
    fn completed_source_helper_skips_in_process_bootstrap() {
        let called = Cell::new(false);

        bootstrap_builder_vm_image_with(
            || Ok(true),
            || {
                called.set(true);
                Ok(())
            },
        )
        .expect("completed helper should satisfy bootstrap");

        assert!(!called.get(), "bootstrap must not run twice");
    }

    #[test]
    fn matching_source_helper_bootstraps_in_process() {
        let called = Cell::new(false);

        bootstrap_builder_vm_image_with(
            || Ok(false),
            || {
                called.set(true);
                Ok(())
            },
        )
        .expect("matching helper should bootstrap in process");

        assert!(called.get(), "matching helper must perform bootstrap");
    }

    #[test]
    fn helper_resolution_error_prevents_bootstrap() {
        let called = Cell::new(false);

        let error = bootstrap_builder_vm_image_with(
            || anyhow::bail!("helper build failed"),
            || {
                called.set(true);
                Ok(())
            },
        )
        .expect_err("helper errors must fail closed");

        assert!(error.to_string().contains("helper build failed"));
        assert!(!called.get(), "bootstrap must not bypass a helper error");
    }
}

pub(super) fn builder_vm_host_arch() -> &'static str {
    if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else {
        "x86_64"
    }
}

/// Fetch the builder image the image lock pins into `out_dir`.
///
/// A release binary built with `release-artifact-bootstrap` first tries a
/// signed builder pack from its own release; the pack is an accelerator, so
/// having none (or failing to place one) falls through to the signed image
/// set, which every build can reach.
fn perform_builder_vm_download_published(arch: &str, out_dir: &str) -> Result<()> {
    #[cfg(all(feature = "release-artifact-bootstrap", feature = "builder-vm"))]
    if attested_builder_pack::attested_builder_pack_selected() {
        match attested_builder_pack::attempt_attested_builder_pack(arch, out_dir, true) {
            Ok(true) => return Ok(()),
            Ok(false) => {}
            Err(error) => ui::warn(&format!(
                "Attested builder pack unavailable ({error:#}); falling back to download."
            )),
        }
    }
    ui::info("Builder VM image not in cache; downloading the builder image the image lock pins...");
    std::fs::create_dir_all(out_dir)
        .with_context(|| format!("creating builder-vm cache dir {out_dir}"))?;
    download_builder_vm_image(arch, out_dir).context("downloading the builder VM image")
}

/// Attested builder-image pack materializer: given a locally-verified builder
/// pack, place its `vmlinux` + `rootfs.ext4` (+ `cmdline.txt`) into the cache
/// dir the `DownloadPublished` path writes and stamp the readiness sidecars so
/// the next resolve takes `UseCached` with no Stage 0 and no network. The plain
/// checksum download pins bytes but carries no signature; this closes that gap
/// while staying a pure accelerator — anything short of a fully verified,
/// compatible pack falls through to the download untouched.
///
/// Placement reuses the Stage 0 promotion machinery verbatim: stage the files in
/// a same-filesystem sibling dir, write the identical sidecar set the readiness
/// check reads back, then let [`promote_builder_vm_stage0_cache`] do the atomic
/// rename + final readiness assertion — so the markers can never drift from the
/// predicate that gates them.
///
/// Gated on `all(release-artifact-bootstrap, builder-vm)` (plus `test`): the only
/// caller is the published-download arm, and it also needs the `builder-vm`
/// sidecar writers. A contributor build running from its source checkout never
/// reaches here.
#[cfg(any(
    all(feature = "release-artifact-bootstrap", feature = "builder-vm"),
    test
))]
pub(in crate::commands) mod attested_builder_pack {
    use std::collections::BTreeSet;
    use std::path::Path;

    use anyhow::{Context, Result};

    use mvm_core::arch::GuestArch;
    use mvm_core::config::mvm_keys_dir;
    #[cfg(feature = "manifest-verify")]
    use mvm_core::pack_cache::{PackProvenanceInput, promote_and_record};
    use mvm_core::pack_cache::{PackVerifyCtx, VerifiedPackDir, resolve_pack};
    use mvm_core::pack_trust::{PackTrustConfig, load_pack_trust_config};
    #[cfg(feature = "manifest-verify")]
    use mvm_core::packs::{COSIGN_BUNDLE_FILE_NAME, PackManifest};
    use mvm_core::packs::{
        HostCapability, LocalPackPolicy, PackBackend, PackKind, host_pack_policy_hash,
    };

    #[cfg(any(
        feature = "manifest-verify",
        feature = "release-artifact-bootstrap",
        test
    ))]
    use super::SYNTHESIZED_BUILDER_VM_CMDLINE;
    #[cfg(feature = "manifest-verify")]
    use super::builder_vm_boot_assets;
    use super::{
        promote_builder_vm_stage0_cache, unique_builder_vm_stage0_staging_dir,
        write_builder_vm_cache_sidecars,
    };
    #[cfg(feature = "manifest-verify")]
    use crate::commands::env::artifact_verify::download_file;
    use crate::ui;

    const SYNTHESIZED_BUILDER_VM_CACHE_MANIFEST: &str =
        r#"{"cache_contract_version":3,"runtime_overlay_ready":true,"vsock_egress_ready":true}"#;

    /// Truthy-parse for [`MVM_BUILDER_PACK`](super::MVM_BUILDER_PACK_ENV): `1`,
    /// `true`, `yes`, `on` (case-insensitive, trimmed). Everything else —
    /// including `0`, `false`, the empty string, and a missing value — is `false`.
    /// Lifted out so both arms are unit-testable without touching process env.
    pub(in crate::commands) fn builder_pack_requested_for(raw: Option<&str>) -> bool {
        matches!(
            raw.map(|s| s.trim().to_ascii_lowercase()).as_deref(),
            Some("1" | "true" | "yes" | "on"),
        )
    }

    fn builder_pack_requested() -> bool {
        builder_pack_requested_for(std::env::var(super::MVM_BUILDER_PACK_ENV).ok().as_deref())
    }

    /// Whether the attested-pack path should be attempted ahead of the plain
    /// download. Requires the opt-in flag AND an installed binary: a
    /// contributor build running from its source checkout takes the signed
    /// image set, never a published-pack shortcut.
    pub(in crate::commands) fn attested_builder_pack_selected() -> bool {
        builder_pack_requested() && !super::is_mvm_source_checkout()
    }

    /// Local verification context for host builder packs. `trust` is the
    /// operator's on-disk [`PackTrustConfig`] (loaded from `pack-trust.json` in
    /// the keys dir); it answers both "is this signer trusted?" and "is it
    /// revoked?". An empty config (no publishers) trusts no key and allows no
    /// channel, so every promoted pack fails verification and the caller falls
    /// back to the download — fail-open on availability, never on trust.
    pub(in crate::commands) struct HostPackVerifyInputs {
        pub(in crate::commands) policy: LocalPackPolicy,
        pub(in crate::commands) trust: PackTrustConfig,
    }

    /// Load the on-disk trust config, folding both the absent and the malformed
    /// case into the inert empty config. A missing file is the expected default;
    /// a broken file must never brick the builder VM bootstrap, so we warn and stay inert — the
    /// pack path then trusts nothing and falls through to the plain download. It
    /// can never trust an unverified pack, so failing open here is safe.
    fn load_host_pack_trust() -> PackTrustConfig {
        match load_pack_trust_config(&mvm_keys_dir().join("pack-trust.json")) {
            Ok(Some(config)) => config,
            Ok(None) => PackTrustConfig::default(),
            Err(error) => {
                ui::warn(&format!(
                    "Ignoring malformed pack trust config ({error}); attested builder \
                     packs stay inert and the builder VM bootstrap falls back to the download."
                ));
                PackTrustConfig::default()
            }
        }
    }

    pub(in crate::commands) fn host_pack_verify_inputs(arch: GuestArch) -> HostPackVerifyInputs {
        let trust = load_host_pack_trust();
        HostPackVerifyInputs {
            policy: LocalPackPolicy {
                host_arch: arch,
                backend: PackBackend::Hvf,
                host_capabilities: BTreeSet::from([HostCapability("vsock".to_string())]),
                policy_hash: host_pack_policy_hash(arch),
                allowed_channels: trust.allowed_channels(),
                now: chrono::Utc::now(),
            },
            trust,
        }
    }

    /// The local policy a keyless-signed release pack must satisfy: identical
    /// to the operator's on-disk policy, but with the compiled-in release
    /// channels unioned into the allowed set. A release pack always declares
    /// one of [`mvm_core::release_trust::release_channels`], and that trust is
    /// carried by the embedded identity template, not by anything the operator
    /// configures — so it must be allowed independent of `pack-trust.json`.
    #[cfg(feature = "manifest-verify")]
    pub(in crate::commands) fn keyless_release_policy(base: &LocalPackPolicy) -> LocalPackPolicy {
        let mut policy = base.clone();
        policy
            .allowed_channels
            .extend(mvm_core::release_trust::release_channels());
        policy
    }

    /// Parse a staged release pack's manifest and verify+promote it into the
    /// local pack cache. `Ok(Some(_))` means the pack now exists in the cache
    /// (freshly promoted, or already there) and the caller's next resolve will
    /// find it. A verification failure is `Ok(None)` — fail-open on
    /// availability, so the caller falls through to the plain checksum
    /// download — but the rejection is logged so an operator can see why the
    /// acceleration path was skipped. A missing or unparsable staged manifest
    /// is a genuine error: the fetch step is expected to have already placed
    /// valid bytes there, so this signals a caller bug rather than an
    /// untrusted-publisher condition.
    #[cfg(feature = "manifest-verify")]
    pub(in crate::commands) fn promote_staged_builder_pack(
        staging: &Path,
        ctx: &PackVerifyCtx<'_>,
    ) -> Result<Option<VerifiedPackDir>> {
        let manifest_path = staging.join("pack-manifest.json");
        let manifest_bytes = std::fs::read(&manifest_path).with_context(|| {
            format!(
                "reading staged builder pack manifest at {}",
                manifest_path.display()
            )
        })?;
        let manifest: PackManifest =
            serde_json::from_slice(&manifest_bytes).with_context(|| {
                format!(
                    "parsing staged builder pack manifest at {}",
                    manifest_path.display()
                )
            })?;
        // `v{version}` matches the release tag `fetch_release_builder_pack_staging`
        // builds its download base URL from, so the recorded version always
        // names the exact release this pack came from.
        let release_version = format!("v{}", env!("CARGO_PKG_VERSION"));
        let prov = PackProvenanceInput {
            channel: manifest.trust.channel_identity.clone(),
            release_version,
            promoted_at_unix: chrono::Utc::now().timestamp() as u64,
        };
        match promote_and_record(staging, &manifest, &prov, ctx) {
            Ok(dir) => Ok(Some(dir)),
            Err(error) => {
                ui::warn(&format!(
                    "Published builder pack failed verification ({error}); \
                     falling back to the checksum download."
                ));
                Ok(None)
            }
        }
    }

    /// Download the release channel's published builder pack — manifest,
    /// detached cosign bundle, and artifacts — into a fresh staging dir laid
    /// out exactly as [`promote_staged_builder_pack`] expects:
    /// `pack-manifest.json`, [`COSIGN_BUNDLE_FILE_NAME`], `vmlinux`,
    /// `rootfs.ext4`, and a best-effort `cmdline.txt`. Asset basenames mirror
    /// [`super::download_builder_vm_image`]'s naming exactly, so the two
    /// download paths can never drift apart. The staging dir is a
    /// process-local tempdir; `promote` only ever copies out of it (never
    /// renames it), so it need not share a filesystem with the pack cache,
    /// and its `Drop` cleans it up on any early return here.
    #[cfg(feature = "manifest-verify")]
    pub(in crate::commands) fn fetch_release_builder_pack_staging(
        arch: &str,
    ) -> Result<tempfile::TempDir> {
        let staging = tempfile::Builder::new()
            .prefix("mvm-builder-pack-")
            .tempdir()
            .context("creating builder pack staging dir")?;
        let [kernel_asset, rootfs_asset, cmdline_asset] = builder_vm_boot_assets(arch);
        let manifest_name = format!("builder-vm-{arch}.pack-manifest.json");
        let bundle_name = format!("{manifest_name}.bundle");
        let version = env!("CARGO_PKG_VERSION");
        let base_url = format!("https://github.com/tinylabscom/mvm/releases/download/v{version}");

        let manifest_dest = staging
            .path()
            .join("pack-manifest.json")
            .to_string_lossy()
            .into_owned();
        download_file(&format!("{base_url}/{manifest_name}"), &manifest_dest)
            .with_context(|| format!("downloading builder pack manifest {manifest_name}"))?;

        let bundle_dest = staging
            .path()
            .join(COSIGN_BUNDLE_FILE_NAME)
            .to_string_lossy()
            .into_owned();
        download_file(&format!("{base_url}/{bundle_name}"), &bundle_dest)
            .with_context(|| format!("downloading builder pack cosign bundle {bundle_name}"))?;

        let kernel_dest = staging
            .path()
            .join("vmlinux")
            .to_string_lossy()
            .into_owned();
        download_file(&format!("{base_url}/{kernel_asset}"), &kernel_dest)
            .context("downloading builder pack vmlinux artifact")?;

        let rootfs_dest = staging
            .path()
            .join("rootfs.ext4")
            .to_string_lossy()
            .into_owned();
        download_file(&format!("{base_url}/{rootfs_asset}"), &rootfs_dest)
            .context("downloading builder pack rootfs artifact")?;

        // Best-effort: a missing cmdline.txt sidecar has a documented
        // fallback at the materializer, so a 404 here is not fatal.
        let cmdline_dest = staging
            .path()
            .join("cmdline.txt")
            .to_string_lossy()
            .into_owned();
        let _ = download_file(&format!("{base_url}/{cmdline_asset}"), &cmdline_dest);

        Ok(staging)
    }

    /// Fetch the release channel's published builder pack and promote it into
    /// the local cache when it verifies. Both the fetch and the promote step
    /// are fail-open: any error is logged and swallowed here, never
    /// propagated, so [`attempt_attested_builder_pack`] always falls
    /// back to the plain checksum download rather than hard-failing the
    /// builder VM bootstrap on a network hiccup or a broken publish.
    #[cfg(feature = "manifest-verify")]
    fn fetch_and_promote_release_builder_pack(arch: &str, ctx: &PackVerifyCtx<'_>) {
        let staging = match fetch_release_builder_pack_staging(arch) {
            Ok(staging) => staging,
            Err(error) => {
                ui::warn(&format!(
                    "Fetching the published builder pack failed ({error:#}); \
                     falling back to the checksum download."
                ));
                return;
            }
        };
        if let Err(error) = promote_staged_builder_pack(staging.path(), ctx) {
            ui::warn(&format!(
                "Published builder pack was malformed ({error:#}); falling back \
                 to the checksum download."
            ));
        }
    }

    /// Entry point for the download arm: build the host verification context,
    /// resolve a compatible verified builder pack, and place it. `Ok(true)` when
    /// a pack was materialized (caller skips the download); `Ok(false)` when none
    /// is available. Errors are placement failures the caller logs before falling
    /// back — resolution finding nothing is `Ok(false)`, never an error.
    ///
    /// Two authorities are tried in order: the embedded keyless root (a stock
    /// binary's own release packs, no operator config needed) first, then the
    /// operator's ed25519 `pack-trust.json` (fleet/self-built packs). Both
    /// resolve against the same on-disk cache and fail open to the caller's
    /// plain download when neither yields a pack.
    ///
    /// `fetch_on_miss` gates the release-channel network fetch that runs when
    /// the embedded keyless root finds nothing locally cached: the production
    /// call site always passes `true`; a test passes `false` to exercise the
    /// local-cache-only resolve/materialize behavior without touching the
    /// network.
    pub(in crate::commands) fn attempt_attested_builder_pack(
        arch: &str,
        out_dir: &str,
        fetch_on_miss: bool,
    ) -> Result<bool> {
        let target_arch: GuestArch = arch
            .parse()
            .with_context(|| format!("unsupported builder pack arch {arch}"))?;
        let inputs = host_pack_verify_inputs(target_arch);
        let out_dir = Path::new(out_dir);
        let _ = fetch_on_miss;

        #[cfg(feature = "manifest-verify")]
        {
            let keyless = mvm_core::release_trust::release_keyless_trust(env!("CARGO_PKG_VERSION"));
            let policy = keyless_release_policy(&inputs.policy);
            let ctx = PackVerifyCtx::keyless(&policy, &keyless, &inputs.trust);
            if resolve_and_materialize_builder_pack(target_arch, out_dir, &ctx)? {
                return Ok(true);
            }
            if fetch_on_miss {
                fetch_and_promote_release_builder_pack(arch, &ctx);
                if resolve_and_materialize_builder_pack(target_arch, out_dir, &ctx)? {
                    return Ok(true);
                }
            }
        }

        // The config answers both trust and revocation queries, so it is passed
        // as the trust store and the revocation checker.
        let ctx = PackVerifyCtx::ed25519(&inputs.policy, &inputs.trust, &inputs.trust);
        resolve_and_materialize_builder_pack(target_arch, out_dir, &ctx)
    }

    /// Resolve a compatible verified builder pack against `ctx` and materialize
    /// it into `out_dir`. Split from [`attempt_attested_builder_pack`] so a test
    /// can inject a context whose trust store actually accepts a locally-minted
    /// pack (the production context trusts no keys yet).
    fn resolve_and_materialize_builder_pack(
        arch: GuestArch,
        out_dir: &Path,
        ctx: &PackVerifyCtx<'_>,
    ) -> Result<bool> {
        match resolve_pack(PackKind::Builder, arch, PackBackend::Hvf, ctx)
            .context("resolving attested builder pack from the local cache")?
        {
            Some(verified) => {
                let fingerprint = materialize_builder_pack(&verified, out_dir)?;
                ui::success(&format!(
                    "Placed attested builder VM image from verified pack {}.",
                    short_hash(&fingerprint)
                ));
                Ok(true)
            }
            None => Ok(false),
        }
    }

    fn short_hash(hash: &str) -> &str {
        &hash[..hash.len().min(12)]
    }

    /// Place the verified pack's builder-image files into `out_dir` atomically and
    /// stamp the readiness sidecars, returning the fingerprint the sidecars were
    /// keyed on (the pack's content-addressed hash). On any failure the staging
    /// dir is removed and `out_dir` is left untouched — a partial placement never
    /// publishes a dir that falsely reads ready.
    pub(in crate::commands) fn materialize_builder_pack(
        verified: &VerifiedPackDir,
        out_dir: &Path,
    ) -> Result<String> {
        // The pack's content-addressed hash is a stable, attested fingerprint: it
        // re-derives identically on every resolve, so the readiness sidecars pin
        // this exact pack's identity into the cache dir.
        let fingerprint = verified.verified.pack_hash.as_str().to_string();
        let staging = unique_builder_vm_stage0_staging_dir(out_dir)?;
        // A recycled pid could leave a prior crashed run's dir at this path; start
        // clean so no un-attested extra files ride the rename into the cache.
        let _ = std::fs::remove_dir_all(&staging);
        let outcome =
            place_and_promote_builder_pack(&verified.root, &staging, out_dir, &fingerprint);
        if outcome.is_err() {
            let _ = std::fs::remove_dir_all(&staging);
        }
        outcome.map(|()| fingerprint)
    }

    fn place_and_promote_builder_pack(
        pack_root: &Path,
        staging: &Path,
        out_dir: &Path,
        fingerprint: &str,
    ) -> Result<()> {
        std::fs::create_dir_all(staging)
            .with_context(|| format!("creating builder pack staging dir {}", staging.display()))?;
        copy_builder_pack_artifacts(pack_root, staging)?;
        // Reuses the shared sidecar writer so the markers can never drift from the
        // readiness predicate that reads them. That writer stamps a provenance
        // "kind" describing the local-build origin; here the origin is instead a
        // verified download, so the recorded kind is imprecise. Correcting it means
        // threading a distinct kind through the shared readiness predicate that the
        // local-build path also depends on, so it is left for a focused follow-up.
        write_builder_vm_cache_sidecars(staging, fingerprint)?;
        // The atomic rename + final readiness assertion; also the idempotency and
        // poisoned-final replacement the reuse path already handles.
        promote_builder_vm_stage0_cache(staging, out_dir, fingerprint)
            .context("promoting the materialized builder pack into the cache")
    }

    /// Copy the readiness-relevant builder-image files out of the verified pack.
    /// `vmlinux` + `rootfs.ext4` are required (a builder pack that omits them is
    /// malformed). `cmdline.txt` and the seeded closure NAR
    /// (`mvm_build::builder_pack::CLOSURE_FILE`) are optional and copied when
    /// present. When the pack omits `cmdline.txt`, this synthesizes the current
    /// canonical builder-vm cmdline. The closure NAR sits alongside the
    /// readiness-gated files here so the HVF/libkrun boot paths — which resolve
    /// it from this exact cache dir — pick it up without a separate lookup; it
    /// plays no part in the readiness check itself. The cache's `manifest.json`
    /// is always synthesized here because the pack envelope manifest
    /// (`pack-manifest.json`) is a different contract from the runtime cache
    /// manifest the builder loader validates. The copies are owner-writable
    /// whatever mode the pack's files carry: this is the same builder-VM cache
    /// the local-pair installer fills through `copy_contract_file`, and its
    /// consumers write into it.
    fn copy_builder_pack_artifacts(pack_root: &Path, dest: &Path) -> Result<()> {
        for name in ["vmlinux", "rootfs.ext4"] {
            let src = pack_root.join(name);
            if !src.exists() {
                anyhow::bail!(
                    "attested builder pack at {} is missing required artifact {name}",
                    pack_root.display()
                );
            }
            mvm_core::util::atomic_io::copy_writable(&src, &dest.join(name))
                .with_context(|| format!("copying builder pack artifact {name}"))?;
        }
        let cmdline = pack_root.join("cmdline.txt");
        if cmdline.exists() {
            mvm_core::util::atomic_io::copy_writable(&cmdline, &dest.join("cmdline.txt"))
                .context("copying builder pack cmdline.txt")?;
        } else {
            std::fs::write(dest.join("cmdline.txt"), SYNTHESIZED_BUILDER_VM_CMDLINE)
                .context("writing synthesized builder pack cmdline.txt")?;
        }
        let name = mvm_build::builder_pack::CLOSURE_FILE;
        let src = pack_root.join(name);
        if src.exists() {
            mvm_core::util::atomic_io::copy_writable(&src, &dest.join(name))
                .with_context(|| format!("copying builder pack artifact {name}"))?;
        }
        std::fs::write(
            dest.join("manifest.json"),
            SYNTHESIZED_BUILDER_VM_CACHE_MANIFEST,
        )
        .context("writing synthesized builder pack manifest.json")?;
        Ok(())
    }
}

#[cfg(test)]
mod forced_build_tests {
    use super::refuse_a_local_builder_build;
    use mvm_build::boot_image_select::BootImageAcquisition;

    #[test]
    fn a_forced_builder_build_without_a_checkout_is_refused() {
        let rendered = format!(
            "{:#}",
            refuse_a_local_builder_build(Some(BootImageAcquisition::Build))
                .expect_err("there is no source to build the builder image from")
        );

        assert!(rendered.contains("the builder VM image"), "{rendered}");
        assert!(
            rendered.contains("image construction lives in mvm-images"),
            "{rendered}"
        );
    }

    #[test]
    fn fetching_or_an_unset_override_goes_on_to_the_published_builder() {
        refuse_a_local_builder_build(Some(BootImageAcquisition::Fetch)).unwrap();
        refuse_a_local_builder_build(None).unwrap();
    }
}
