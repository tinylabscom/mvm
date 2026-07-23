//! Rootfs materialization: inject the mvm guest runtime into an unpacked OCI
//! layer tree and seal it into a bootable, verity-sidecar-backed ext4 image.
//! Also owns the runtime-identity tag that gates whether a cached rootfs can
//! be reused as-is or must be re-materialized against the running mvmctl.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use mvm_build::oci_runtime_inject::OciEntrypointConfig;
use mvm_build::rootfs::MaterializeExt4Input;

use super::cache::safe_cache_path;
use super::oci_types::OciImageConfig;

/// Bump when the injected OCI runtime (guest agent, netinit, or `/init`
/// script) changes such that already-materialized rootfs images must be
/// re-sealed. Folded with the crate version into [`oci_runtime_tag`]; a
/// stale rootfs then re-materializes instead of booting an outdated agent.
/// Epoch 1 introduces the interactive exec handler in the OCI agent. Epoch 2 adds
/// the detached-workload handler — a rootfs sealed with an older agent would
/// reject the run-detached request, so it must re-materialize. Epoch 3 moves
/// `mvm-egress-client` onto the runtime overlay contract: cached injected
/// rootfs images that still bake the old helper path must be re-materialized so
/// block-backed boots pick up the overlay-first layout. Epoch 4 rolls the
/// required-overlay `/init` contract fix that initializes the vsock-egress
/// flag safely under `set -u`; stale cached rootfs images otherwise keep
/// booting the pre-fix PID-1 script and panic before the agent binds. Epoch 5
/// teaches that same `/init` to skip re-mounting `/mvm/runtime` when
/// `mvm-verity-init` already mounted the verity-protected overlay there; stale
/// cached runtime-lean rootfs entries otherwise panic after the verity handoff.
const OCI_RUNTIME_EPOCH: u32 = 6;

/// Identity of the guest runtime the running mvmctl bakes into an OCI rootfs.
/// Cheap and build-free (no agent cross-compile) so it can gate the cache-hit
/// path without forcing a rebuild on hosts that only have a warm rootfs cache.
///
/// When this mvmctl ships no embedded guest binaries, the injected runtime is
/// cross-compiled from `crates/mvm-agentd/src` instead — the embedded SHAs are
/// then all-`missing` and can't track that source, so the guest source
/// fingerprint is folded in. That makes a guest-source edit re-materialize the
/// rootfs rather than reuse one carrying a stale injected `/init` / agent.
pub(super) fn oci_runtime_tag() -> String {
    oci_runtime_tag_with(source_runtime_fingerprint().as_deref())
}

/// The guest source fingerprint to fold into the runtime tag, or `None` when it
/// contributes nothing: this mvmctl ships embedded guest binaries (their SHAs
/// already pin the injected identity) or no source checkout is in reach.
fn source_runtime_fingerprint() -> Option<String> {
    runtime_source_fingerprint_for(embedded_guest_binaries().is_some())
}

/// The source fingerprint to fold in given whether embedded guest binaries are
/// present. Split from [`source_runtime_fingerprint`] so the embedded-vs-source
/// decision is unit-testable without build-time embedding state. Mirrors
/// [`mvm_build::run_image::resolve_guest_binaries`], which cross-compiles the
/// injected runtime from source only when no embedded binaries are present, and
/// keys that build on the same [`guest_source_fingerprint`] used here — so the
/// OCI cache tag and the guest-binary build cache miss and hit together.
///
/// [`guest_source_fingerprint`]: mvm_build::guest_agent_build::guest_source_fingerprint
fn runtime_source_fingerprint_for(has_embedded_binaries: bool) -> Option<String> {
    if has_embedded_binaries {
        return None;
    }
    let workspace = mvm_build::guest_agent_build::detect_source_workspace()?;
    match mvm_build::guest_agent_build::guest_source_fingerprint(&workspace) {
        Ok(fingerprint) => Some(fingerprint),
        Err(err) => {
            // Degrade to the embedded-only tag rather than fail the run, but
            // leave a breadcrumb: a silent drop here can reuse a stale injected
            // rootfs for this one invocation with no trace for a contributor
            // debugging "my guest-source edit didn't take".
            tracing::warn!(
                error = %err,
                "could not fingerprint guest source for the OCI runtime tag; \
                 a cached rootfs may reuse a stale injected runtime"
            );
            None
        }
    }
}

/// Pure runtime-tag computation over the embedded-binary SHAs plus an optional
/// guest source fingerprint. Split out from [`oci_runtime_tag`] so the
/// source-checkout invalidation is unit-testable without a real workspace or a
/// particular embedded-binary set.
fn oci_runtime_tag_with(source_fp: Option<&str>) -> String {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(b"epoch=");
    hasher.update(OCI_RUNTIME_EPOCH.to_string().as_bytes());
    hasher.update(b"\n");
    for name in [
        "mvm-oci-init",
        "mvm-oci-entrypoint",
        "mvm-guest-agent",
        "mvm-guest-netinit",
        "mvm-guest-netd",
        "mvm-egress-client",
        "mvm-verity-init",
    ] {
        hasher.update(name.as_bytes());
        hasher.update(b"=");
        let sha = crate::host_binaries::embedded::EMBEDDED
            .iter()
            .find(|bin| bin.name == name)
            .map(|bin| bin.sha256_hex)
            .unwrap_or("missing");
        hasher.update(sha.as_bytes());
        hasher.update(b"\n");
    }
    if let Some(fp) = source_fp {
        hasher.update(b"guest-source=");
        hasher.update(fp.as_bytes());
        hasher.update(b"\n");
    }
    let digest = hex::encode(hasher.finalize());
    format!("{}-guest-{}", env!("CARGO_PKG_VERSION"), &digest[..16])
}

fn oci_tree_key(identity: &str) -> String {
    super::cache::sha256_hex(identity).unwrap_or_else(|_| identity.replace(['/', ':'], "-"))
}

pub(super) fn prepared_virtiofs_root(
    cache_root: &Path,
    identity: &str,
    runtime_tag: &str,
) -> PathBuf {
    cache_root
        .join("prepared-roots")
        .join(format!("{}-{runtime_tag}", oci_tree_key(identity)))
        .join("rootfs-only")
}

pub(super) fn oci_entrypoint_from_config_bytes(
    bytes: &[u8],
) -> Result<Option<OciEntrypointConfig>> {
    let config: OciImageConfig = serde_json::from_slice(bytes).context("parse OCI image config")?;
    let mut argv = config.config.entrypoint.unwrap_or_default();
    argv.extend(config.config.cmd.unwrap_or_default());
    if argv.is_empty() {
        return Ok(None);
    }
    let env = config.config.env;
    let working_dir = config.config.working_dir.filter(|dir| !dir.is_empty());
    Ok(Some(OciEntrypointConfig {
        argv,
        env,
        working_dir,
    }))
}

pub(super) fn oci_entrypoint_from_cache_path(
    cache_root: &Path,
    config_path: Option<&str>,
) -> Result<Option<OciEntrypointConfig>> {
    let Some(config_path) = config_path else {
        return Ok(None);
    };
    let path = safe_cache_path(cache_root, config_path)?;
    let bytes = fs::read(&path).with_context(|| format!("read OCI config {}", path.display()))?;
    oci_entrypoint_from_config_bytes(&bytes)
}

/// Whether a cached image's materialized rootfs can be booted as-is: it must
/// exist and carry the current runtime tag. A `None` tag (pre-tag entry) or a
/// mismatch means the baked agent may be outdated, so the rootfs is stale.
pub(super) fn cached_rootfs_is_current(
    cached: &super::oci_types::CachedOciImage,
    runtime_tag: &str,
) -> bool {
    cached.rootfs_path.is_some() && cached.runtime_tag.as_deref() == Some(runtime_tag)
}

pub(super) fn rootfs_verity_sidecars_present(rootfs_path: &Path) -> bool {
    let Some(parent) = rootfs_path.parent() else {
        return false;
    };
    parent.join("rootfs.verity").is_file() && parent.join("rootfs.roothash").is_file()
}

pub(super) fn ensure_rootfs_verity_sidecars(
    rootfs_path: &Path,
    image_reference: &str,
    unpacked_root: Option<&Path>,
) -> Result<()> {
    if rootfs_verity_sidecars_present(rootfs_path) {
        return Ok(());
    }
    let unpacked_note = unpacked_root
        .map(|path| format!("cached unpacked tree: {}", path.display()))
        .unwrap_or_else(|| "cached unpacked tree: unavailable".to_string());
    bail!(
        "cached OCI image {} is missing sealed block-root sidecars beside {} \
         after materialization; required files rootfs.verity and rootfs.roothash were not produced ({})",
        image_reference,
        rootfs_path.display(),
        unpacked_note
    );
}

/// Callback signature used to inject the mvm guest runtime and seal a rootfs.
/// A type alias rather than a bare fn pointer everywhere it's threaded, and
/// swappable in tests for a fake that skips the real Nix/ext4 machinery.
pub(super) type RuntimeMaterializer =
    fn(&Path, &Path, &Path, &str, Option<&OciEntrypointConfig>, bool) -> Result<()>;

pub(super) fn rematerialize_cached_image(
    cache_root: &Path,
    mut image: super::oci_types::CachedOciImage,
    runtime_tag: &str,
    materialize: RuntimeMaterializer,
    prod: bool,
) -> Result<Option<super::oci_types::CachedOciImage>> {
    let Some(unpacked_root) =
        super::cache::unpacked_dir_if_present(cache_root, &image.resolved_digest)
    else {
        return Ok(None);
    };
    let rootfs_path = match (
        image.rootfs_path.as_deref(),
        image.runtime_tag.as_deref() == Some(runtime_tag),
    ) {
        (Some(path), true) => path.to_string(),
        _ => format!(
            "rootfs/{}-{runtime_tag}/rootfs.ext4",
            super::cache::sha256_hex(&image.resolved_digest)?
        ),
    };
    let rootfs_abs = safe_cache_path(cache_root, &rootfs_path)?;
    if !rootfs_abs.is_file() {
        materialize(
            cache_root,
            &unpacked_root,
            &rootfs_abs,
            &image.reference,
            oci_entrypoint_from_cache_path(cache_root, image.config_path.as_deref())?.as_ref(),
            prod,
        )
        .with_context(|| {
            format!(
                "re-materializing cached OCI image {} from {}",
                image.reference,
                unpacked_root.display()
            )
        })?;
    }
    image.rootfs_path = Some(rootfs_path);
    image.runtime_tag = Some(runtime_tag.to_string());
    let mut index = super::cache::load_index(cache_root)?;
    super::cache::upsert_image(&mut index, image.clone());
    super::cache::save_index(cache_root, &index)?;
    Ok(Some(image))
}

/// Materialize the run-path rootfs image from an unpacked tree.
///
/// Default: the pure in-process `mvm-ext4` writer — no builder VM, no `mkfs`,
/// no subprocess. `MVM_MATERIALIZE_BUILDER_VM` (any value) routes back through
/// the builder-VM `mkfs` path for parity / debugging. Both paths emit
/// `rootfs.verity` / `rootfs.roothash`, so OCI block roots boot sealed no
/// matter which materializer produced them.
pub(super) fn materialize_run_rootfs(input: &MaterializeExt4Input) -> Result<()> {
    mvm_build::run_image::materialize_run_rootfs(input)
}

/// Inject the mvm guest runtime into `unpacked_root`, seal it into
/// `rootfs_abs` as ext4, and drop the overlay-aware sidecar beside it.
///
/// Every OCI run source funnels through here. An arbitrary OCI image has
/// no mvm agent, so without the injection `run --image` boots a guest
/// with no vsock control plane and times out at `wait_for_agent`. The
/// injected `/init` + baked agent + `/mvm/runtime` mount point make the
/// rootfs genuinely overlay-aware, so the `for_oci_run` sidecar admits
/// honestly through `admit_overlay_aware` without weakening the gate.
pub(super) fn inject_runtime_and_materialize(
    cache_root: &Path,
    unpacked_root: &Path,
    rootfs_abs: &Path,
    image_label: &str,
    entrypoint: Option<&OciEntrypointConfig>,
    sealed: bool,
) -> Result<()> {
    mvm_build::run_image::inject_and_materialize(
        mvm_build::run_image::InjectAndMaterializeRequest::builder(
            cache_root,
            unpacked_root,
            rootfs_abs,
            image_label,
        )
        .profile(mvm_build::oci_runtime_inject::RuntimeInjectionProfile::RuntimeLean)
        .entrypoint(entrypoint)
        .prebuilt(embedded_guest_binaries())
        .sealed(sealed)
        .build(),
    )
}

pub(super) fn prepare_rootfs_only_tree(
    cache_root: &Path,
    raw_unpacked_root: &Path,
    identity: &str,
) -> Result<PathBuf> {
    let prepared_root = prepared_virtiofs_root(cache_root, identity, &oci_runtime_tag());
    if prepared_root.exists() {
        return Ok(prepared_root);
    }
    if let Some(parent) = prepared_root.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    copy_tree(raw_unpacked_root, &prepared_root).with_context(|| {
        format!(
            "copy raw OCI tree {} -> {}",
            raw_unpacked_root.display(),
            prepared_root.display()
        )
    })?;
    let bins = mvm_build::run_image::resolve_guest_binaries(cache_root, embedded_guest_binaries())
        .context("resolve guest binaries for rootfs-only OCI tree")?;
    mvm_build::oci_runtime_inject::inject_mvm_runtime(
        &prepared_root,
        &bins,
        None,
        false,
        mvm_build::oci_runtime_inject::RuntimeInjectionProfile::RootfsOnly,
    )
    .with_context(|| {
        format!(
            "inject rootfs-only runtime into {}",
            prepared_root.display()
        )
    })?;
    Ok(prepared_root)
}

pub(super) fn materialize_overlay_lean_rootfs(
    cache_root: &Path,
    raw_unpacked_root: &Path,
    rootfs_abs: &Path,
    image_label: &str,
) -> Result<()> {
    let staging_root = rootfs_abs.with_extension("staging");
    if staging_root.exists() {
        fs::remove_dir_all(&staging_root)
            .with_context(|| format!("remove stale staging dir {}", staging_root.display()))?;
    }
    copy_tree(raw_unpacked_root, &staging_root).with_context(|| {
        format!(
            "copy raw OCI tree {} -> {}",
            raw_unpacked_root.display(),
            staging_root.display()
        )
    })?;
    let result = inject_runtime_and_materialize(
        cache_root,
        &staging_root,
        rootfs_abs,
        image_label,
        None,
        false,
    );
    let cleanup = fs::remove_dir_all(&staging_root);
    if let Err(err) = cleanup
        && staging_root.exists()
    {
        tracing::warn!(
            error = %err,
            staging = %staging_root.display(),
            "failed to remove OCI runtime-lean staging tree"
        );
    }
    result
}

#[cfg(unix)]
pub(super) fn copy_tree(src: &Path, dst: &Path) -> std::io::Result<()> {
    let mut stack = vec![(src.to_path_buf(), dst.to_path_buf())];
    while let Some((from_dir, to_dir)) = stack.pop() {
        fs::create_dir_all(&to_dir)?;
        for entry in fs::read_dir(&from_dir)? {
            let entry = entry?;
            let ft = entry.file_type()?;
            let from = entry.path();
            let to = to_dir.join(entry.file_name());
            if ft.is_symlink() {
                let target = fs::read_link(&from)?;
                let _ = fs::remove_file(&to);
                std::os::unix::fs::symlink(&target, &to)?;
            } else if ft.is_dir() {
                stack.push((from, to));
            } else {
                fs::copy(&from, &to)?;
            }
        }
    }
    Ok(())
}

/// Whether booting an `--image` OCI run will cross-compile the mvm guest
/// runtime from source first: this build carries no embedded guest binaries
/// and the source-checkout guest cache is cold. Announcing this before the
/// pull keeps the slow, output-silent `cargo zigbuild` from looking like a hang.
pub(in crate::commands) fn oci_guest_runtime_compile_pending(cache_root: &Path) -> bool {
    embedded_guest_binaries().is_none()
        && mvm_build::guest_agent_build::source_build_pending(
            cache_root,
            mvm_core::arch::GuestArch::host(),
        )
}

/// The guest-agent binaries embedded in this mvmctl at build time (build.rs).
/// `None` only if a required embedded binary is unexpectedly missing.
pub(super) fn embedded_guest_binaries()
-> Option<mvm_build::run_image::PrebuiltGuestBinaries<'static>> {
    let find = |name: &str| {
        crate::host_binaries::embedded::EMBEDDED
            .iter()
            .find(|b| b.name == name)
            .map(|b| b.bytes)
            .filter(|b| !b.is_empty())
    };
    Some(mvm_build::run_image::PrebuiltGuestBinaries {
        oci_init: find("mvm-oci-init")?,
        agent: find("mvm-guest-agent")?,
        netinit: find("mvm-guest-netinit")?,
        netd: find("mvm-guest-netd")?,
        egress_client: find("mvm-egress-client")?,
        entrypoint_runner: find("mvm-oci-entrypoint")?,
        verity_init: find("mvm-verity-init")?,
    })
}

#[cfg(test)]
mod tests {
    use super::super::oci_types::{CachedOciImage, CachedOciLayer};
    use super::*;

    fn sample_image(reference: &str, digest: &str, layer_path: &str) -> CachedOciImage {
        CachedOciImage {
            reference: reference.to_string(),
            registry: "docker.io".to_string(),
            repository: "library/alpine".to_string(),
            tag: Some("3.20".to_string()),
            resolved_digest: digest.to_string(),
            fetched_at: "2026-05-18T00:00:00Z".to_string(),
            manifest_path: "manifests/alpine.json".to_string(),
            config_path: Some("configs/alpine.json".to_string()),
            rootfs_path: None,
            runtime_tag: None,
            claims_path: Some("claims/alpine.json".to_string()),
            layers: vec![CachedOciLayer {
                digest: "sha256:layer".to_string(),
                size_bytes: 4,
                path: Some(layer_path.to_string()),
            }],
        }
    }

    // The default run-path materialize is the pure in-process writer, and it
    // must emit dm-verity sidecars so OCI block roots boot sealed even before
    // the builder-VM fallback is exercised.
    #[cfg(feature = "pure-mkfs")]
    #[test]
    fn materialize_run_rootfs_default_is_pure_and_verity_backed() {
        // The builder-VM escape hatch must be unset for the default (pure) path.
        assert!(
            std::env::var_os("MVM_MATERIALIZE_BUILDER_VM").is_none(),
            "test env must not force the builder-VM materializer"
        );
        let src = tempfile::tempdir().unwrap();
        std::fs::create_dir(src.path().join("etc")).unwrap();
        std::fs::write(src.path().join("etc/hostname"), b"box\n").unwrap();
        let out = tempfile::tempdir().unwrap();
        let rootfs = out.path().join("rootfs.ext4");

        materialize_run_rootfs(&MaterializeExt4Input::new(
            src.path().to_path_buf(),
            rootfs.clone(),
            0,
        ))
        .expect("pure materialize");

        // A real ext4 image was written in-process (superblock magic present)…
        let img = std::fs::read(&rootfs).unwrap();
        assert_eq!(&img[1024 + 0x38..1024 + 0x3A], &[0x53, 0xEF]);
        // …and the sealed-boot sidecars sit beside it.
        assert!(out.path().join("rootfs.verity").exists());
        let roothash = std::fs::read_to_string(out.path().join("rootfs.roothash")).unwrap();
        assert_eq!(roothash.trim().len(), 64);
    }

    #[test]
    fn runtime_tag_includes_guest_runtime_hash() {
        let tag = oci_runtime_tag();
        assert!(
            tag.starts_with(concat!(env!("CARGO_PKG_VERSION"), "-guest-")),
            "unexpected runtime tag: {tag}"
        );
        assert_eq!(
            tag.rsplit_once("-guest-").unwrap().1.len(),
            16,
            "runtime tag should carry a short guest-runtime digest"
        );
    }

    #[test]
    fn source_fingerprint_folds_only_without_embedded_binaries() {
        // Shipped mvmctl (embedded binaries present): never fold a source
        // fingerprint, so the tag stays pinned to the embedded SHAs and warm
        // end-user rootfs caches are byte-stable. Guards the is_some/is_none
        // polarity that gates the whole source-checkout invalidation — an
        // inversion here would silently disrupt end-user caches or reopen the
        // stale-injected-runtime bug, and every other test would still pass.
        assert!(runtime_source_fingerprint_for(true).is_none());
        // In a source checkout (this test runs inside the mvm workspace) with
        // no embedded binaries, the workspace is detected and its fingerprint
        // folded in — the branch that closes the cache-invalidation bug.
        assert!(
            runtime_source_fingerprint_for(false).is_some(),
            "a detected source workspace must contribute a guest source fingerprint"
        );
    }

    #[test]
    fn guest_source_fingerprint_feeds_the_runtime_tag() {
        // The source-checkout invalidation: when this mvmctl ships no embedded
        // guest binaries and injects a runtime cross-compiled from
        // `crates/mvm-agentd/src`, a guest-source edit (a changed source
        // fingerprint) must change the runtime tag so the stale injected
        // rootfs/prepared-roots caches miss. A tag that ignored the fingerprint
        // (the old behaviour) is exactly the cache-correctness bug.
        let no_source = oci_runtime_tag_with(None);
        let fp_a = oci_runtime_tag_with(Some("aaaa1111"));
        let fp_b = oci_runtime_tag_with(Some("bbbb2222"));

        assert_ne!(
            fp_a, fp_b,
            "a changed guest source fingerprint must change the runtime tag"
        );
        assert_ne!(
            no_source, fp_a,
            "folding a source fingerprint in must diverge from the embedded-only tag"
        );
        // Still a well-formed tag regardless of the fingerprint input.
        for tag in [&no_source, &fp_a, &fp_b] {
            assert!(tag.starts_with(concat!(env!("CARGO_PKG_VERSION"), "-guest-")));
            assert_eq!(tag.rsplit_once("-guest-").unwrap().1.len(), 16);
        }
    }

    #[test]
    fn guest_source_edit_invalidates_cached_oci_rootfs() {
        // End-to-end regression: editing a guest source file must
        // change the OCI prepared-roots/rootfs cache key so a previously
        // materialized rootfs is treated as stale, rather than reusing an
        // injected runtime that no longer matches the source tree.
        let tmp = tempfile::tempdir().unwrap();
        let crate_dir = tmp.path().join("crates").join("mvm-agentd");
        let bin_dir = crate_dir.join("src").join("bin");
        std::fs::create_dir_all(&bin_dir).unwrap();
        std::fs::write(tmp.path().join("Cargo.toml"), "[workspace]\n").unwrap();
        std::fs::write(
            crate_dir.join("Cargo.toml"),
            "[package]\nname = 'mvm-agentd'\n",
        )
        .unwrap();
        let init_src = bin_dir.join("mvm-oci-init.rs");
        std::fs::write(&init_src, "fn main() { let _x = 1; }\n").unwrap();

        let fp_v1 = mvm_build::guest_agent_build::guest_source_fingerprint(tmp.path()).unwrap();
        let tag_v1 = oci_runtime_tag_with(Some(&fp_v1));

        std::fs::write(&init_src, "fn main() { let _x = 2; }\n").unwrap();

        let fp_v2 = mvm_build::guest_agent_build::guest_source_fingerprint(tmp.path()).unwrap();
        let tag_v2 = oci_runtime_tag_with(Some(&fp_v2));

        assert_ne!(
            fp_v1, fp_v2,
            "guest source edit must change source fingerprint"
        );
        assert_ne!(
            tag_v1, tag_v2,
            "changed fingerprint must change OCI runtime tag"
        );

        // A cached image carrying the old tag must be considered stale.
        let mut cached = sample_image("docker.io/library/alpine:3.20", "sha256:dead", "blobs/a");
        cached.rootfs_path = Some(format!("rootfs/{tag_v1}/rootfs.ext4"));
        cached.runtime_tag = Some(tag_v1.clone());
        assert!(
            !cached_rootfs_is_current(&cached, &tag_v2),
            "cached rootfs with old guest-source tag must be rematerialized"
        );

        // Sanity: identical source reproduces the same tag (cache hits remain
        // possible when the source is unchanged).
        assert_eq!(
            oci_runtime_tag_with(Some(&fp_v1)),
            tag_v1,
            "fingerprint-to-tag mapping must be stable"
        );
    }

    #[test]
    fn stale_runtime_tag_marks_rootfs_not_current() {
        let mut image = sample_image("docker.io/library/alpine:3.20", "sha256:dead", "blobs/a");
        image.rootfs_path = Some("rootfs/alpine/rootfs.ext4".to_string());
        let current = oci_runtime_tag();

        // Pre-tag entry (None): the baked agent predates the tag, so stale.
        assert!(!cached_rootfs_is_current(&image, &current));

        // A different epoch/version means a different injected runtime — stale.
        image.runtime_tag = Some("0.0.0.0".to_string());
        assert!(!cached_rootfs_is_current(&image, &current));

        // Matching tag is the only current case.
        image.runtime_tag = Some(current.clone());
        assert!(cached_rootfs_is_current(&image, &current));

        // A current tag with no materialized rootfs is still not bootable.
        image.rootfs_path = None;
        assert!(!cached_rootfs_is_current(&image, &current));
    }

    #[test]
    fn rootfs_verity_sidecars_present_requires_both_files() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let rootfs = tmp.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"rootfs").expect("write rootfs");
        assert!(!rootfs_verity_sidecars_present(&rootfs));

        std::fs::write(tmp.path().join("rootfs.verity"), b"verity").expect("write verity");
        assert!(!rootfs_verity_sidecars_present(&rootfs));

        std::fs::write(tmp.path().join("rootfs.roothash"), b"abc\n").expect("write roothash");
        assert!(rootfs_verity_sidecars_present(&rootfs));
    }
}
