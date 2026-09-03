//! Rootfs materialization: inject the mvm guest runtime into an unpacked OCI
//! layer tree and seal it into a bootable, verity-sidecar-backed ext4 image.
//! Also owns the runtime-identity tag that gates whether a cached rootfs can
//! be reused as-is or must be re-materialized against the running mvmctl.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use mvm_build::oci_runtime_inject::ImageRuntimeConfig;
use mvm_build::rootfs::MaterializeExt4Input;

use super::cache::safe_cache_path;
use super::oci_types::OciImageConfig;

/// How much of a runtime identity goes into the cache tag. Long enough that
/// two distinct guest runtimes cannot collide in practice, short enough to keep
/// the on-disk directory name readable.
const RUNTIME_TAG_PREFIX_LEN: usize = 16;

/// Identity of the guest runtime injected into a rootfs, for cache keying.
///
/// Derived from the bytes of the artifacts that actually get injected, so a
/// rebuilt `/init`, egress shim or verity initramfs invalidates every cached
/// rootfs on its own. This replaced a hand-bumped epoch constant paired with a
/// fingerprint over `mvm-agentd`'s sources — which could not see three of the
/// six injected artifacts, and needed a human to notice each time.
///
/// Still cheap enough for the cache-hit gate: `resolve_guest_runtime_identity`
/// reads a sidecar rather than the artifacts, and never triggers a build.
pub(super) fn oci_runtime_tag(cache_root: &Path) -> String {
    match mvm_build::run_image::resolve_guest_runtime_identity(cache_root) {
        Ok(identity) => oci_runtime_tag_from_identity(&identity),
        Err(err) => {
            // Degrade to a version-only tag rather than fail the run, but leave
            // a breadcrumb: a silent drop here can reuse a stale injected
            // rootfs for this one invocation with no trace for a contributor
            // debugging "my guest edit didn't take".
            tracing::warn!(
                error = %err,
                "could not identify the injected guest runtime; \
                 a cached rootfs may reuse a stale injected runtime"
            );
            oci_runtime_tag_from_identity("unidentified")
        }
    }
}

fn oci_runtime_tag_from_identity(identity: &str) -> String {
    format!(
        "{}-inject-{}-guest-{}",
        env!("CARGO_PKG_VERSION"),
        mvm_build::oci_runtime_inject::INJECT_SEMANTICS_VERSION,
        runtime_tag_prefix(identity)
    )
}

/// The identity prefix used in a cache tag.
///
/// `resolve_guest_runtime_identity` does not always return a hash: when the
/// guest-agent layout is not built yet it succeeds with a short
/// `pending-<cache_key>` sentinel. Slicing that blindly panicked on any fresh
/// `MVM_HOME` — the first `machine run --image` on a new host, before a guest
/// build had ever run. Take at most the prefix, on a char boundary, so a
/// shorter identity degrades to itself rather than aborting the run.
fn runtime_tag_prefix(identity: &str) -> &str {
    match identity.char_indices().nth(RUNTIME_TAG_PREFIX_LEN) {
        Some((byte_idx, _)) => &identity[..byte_idx],
        None => identity,
    }
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

/// The image's declared runtime config, or `None` when it declares nothing.
///
/// An empty argv does not make the result empty: an image is free to declare
/// `Env` and no command, and discarding the environment along with the absent
/// command is what left `rust:latest` without `/usr/local/cargo/bin` on
/// `PATH`.
pub(super) fn oci_entrypoint_from_config_bytes(bytes: &[u8]) -> Result<Option<ImageRuntimeConfig>> {
    let config: OciImageConfig = serde_json::from_slice(bytes).context("parse OCI image config")?;
    let mut argv = config.config.entrypoint.unwrap_or_default();
    argv.extend(config.config.cmd.unwrap_or_default());
    let resolved = ImageRuntimeConfig {
        argv,
        env: config.config.env,
        working_dir: config.config.working_dir,
    };
    Ok((!resolved.is_empty()).then_some(resolved))
}

pub(super) fn oci_entrypoint_from_cache_path(
    cache_root: &Path,
    config_path: Option<&str>,
) -> Result<Option<ImageRuntimeConfig>> {
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

/// One rootfs materialize invocation, grouped so the materializer callback
/// stays a single-argument signature no matter how many inputs a seal needs.
pub(super) struct MaterializeCall<'a> {
    pub(super) cache_root: &'a Path,
    pub(super) unpacked_root: &'a Path,
    pub(super) rootfs_abs: &'a Path,
    pub(super) image_label: &'a str,
    pub(super) entrypoint: Option<&'a ImageRuntimeConfig>,
    pub(super) sealed: bool,
    pub(super) deferred_nodes: Vec<mvm_fs::ext4::Node>,
    pub(super) evidence: Option<mvm_build::provenance_mark::SealEvidence<'a>>,
}

/// Callback signature used to inject the mvm guest runtime and seal a rootfs.
/// A type alias rather than a bare fn pointer everywhere it's threaded, and
/// swappable in tests for a fake that skips the real Nix/ext4 machinery.
pub(super) type RuntimeMaterializer = for<'a> fn(MaterializeCall<'a>) -> Result<()>;

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
        let signer;
        let evidence = if prod {
            signer = crate::commands::vm::host_signer::load_or_init()
                .context("load host signing key for the provenance mark")?;
            Some(
                mvm_build::provenance_mark::SealEvidence::builder(&signer.signing)
                    .with_image_ref(&image.reference)
                    .with_image_digest(&image.resolved_digest)
                    .build(),
            )
        } else {
            None
        };
        materialize(MaterializeCall {
            cache_root,
            unpacked_root: &unpacked_root,
            rootfs_abs: &rootfs_abs,
            image_label: &image.reference,
            entrypoint: oci_entrypoint_from_cache_path(cache_root, image.config_path.as_deref())?
                .as_ref(),
            sealed: prod,
            deferred_nodes: super::cache::read_deferred_nodes(cache_root, &image.resolved_digest)?,
            evidence,
        })
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
/// honestly through `admit_runtime_overlay_contract` without weakening the gate.
pub(super) fn inject_runtime_and_materialize(call: MaterializeCall<'_>) -> Result<()> {
    let MaterializeCall {
        cache_root,
        unpacked_root,
        rootfs_abs,
        image_label,
        entrypoint,
        sealed,
        deferred_nodes,
        evidence,
    } = call;
    mvm_build::run_image::inject_and_materialize(
        mvm_build::run_image::InjectAndMaterializeRequest::builder(
            cache_root,
            unpacked_root,
            rootfs_abs,
            image_label,
        )
        .entrypoint(entrypoint)
        .sealed(sealed)
        .deferred_nodes(deferred_nodes)
        .evidence(evidence)
        .build(),
    )
}

pub(super) fn prepare_rootfs_only_tree(
    cache_root: &Path,
    raw_unpacked_root: &Path,
    identity: &str,
) -> Result<PathBuf> {
    let prepared_root = prepared_virtiofs_root(cache_root, identity, &oci_runtime_tag(cache_root));
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
    let bins = mvm_build::run_image::resolve_guest_binaries(cache_root)
        .context("resolve guest binaries for rootfs-only OCI tree")?;
    mvm_build::oci_runtime_inject::inject_mvm_runtime(&prepared_root, &bins, None, false)
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
    deferred_nodes: Vec<mvm_fs::ext4::Node>,
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
    let result = inject_runtime_and_materialize(MaterializeCall {
        cache_root,
        unpacked_root: &staging_root,
        rootfs_abs,
        image_label,
        entrypoint: None,
        sealed: false,
        deferred_nodes,
        evidence: None,
    });
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

#[cfg(test)]
mod tests {
    use super::super::oci_types::{CachedOciImage, CachedOciLayer};
    use super::*;

    /// The exact shape that panicked on a fresh `MVM_HOME`: before any guest
    /// build has run, `resolve_guest_runtime_identity` succeeds with a short
    /// `pending-<cache_key>` sentinel rather than a hash, and the tag builder
    /// used to slice it at a fixed 16 bytes.
    #[test]
    fn a_pending_identity_shorter_than_the_prefix_does_not_panic() {
        let identity = "pending-abc123";
        assert!(identity.len() < RUNTIME_TAG_PREFIX_LEN);
        assert_eq!(runtime_tag_prefix(identity), "pending-abc123");
    }

    #[test]
    fn a_full_hash_identity_is_truncated_to_the_prefix() {
        let identity = "0123456789abcdef0123456789abcdef";
        assert_eq!(runtime_tag_prefix(identity), "0123456789abcdef");
        assert_eq!(runtime_tag_prefix(identity).len(), RUNTIME_TAG_PREFIX_LEN);
    }

    #[test]
    fn an_identity_exactly_the_prefix_length_is_returned_whole() {
        let identity = "0123456789abcdef";
        assert_eq!(runtime_tag_prefix(identity), identity);
    }

    #[test]
    fn an_empty_identity_does_not_panic() {
        assert_eq!(runtime_tag_prefix(""), "");
    }

    /// Truncation is on a char boundary. A byte-indexed slice would panic here
    /// even for an identity that is long enough in bytes.
    #[test]
    fn a_multibyte_identity_truncates_on_a_char_boundary() {
        let identity = "ééééééééééééééééééé";
        let got = runtime_tag_prefix(identity);
        assert_eq!(got.chars().count(), RUNTIME_TAG_PREFIX_LEN);
        assert!(identity.starts_with(got));
    }

    #[test]
    fn runtime_tag_carries_host_injection_semantics_outside_the_binary_sidecar() {
        let tag = oci_runtime_tag_from_identity("0123456789abcdef-rest");
        assert_eq!(
            tag,
            format!(
                "{}-inject-{}-guest-0123456789abcdef",
                env!("CARGO_PKG_VERSION"),
                mvm_build::oci_runtime_inject::INJECT_SEMANTICS_VERSION
            )
        );
        assert_ne!(
            tag,
            format!("{}-guest-0123456789abcdef", env!("CARGO_PKG_VERSION")),
            "the pre-semantics cache tag must become stale"
        );
    }

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

    /// Seed a cache root with a complete, distinguishable guest-artifact set.
    fn seed_guest_artifacts(cache_root: &std::path::Path, flavour: &[u8]) -> std::path::PathBuf {
        let source = mvm_build::guest_agent_build::guest_binary_source()
            .expect("resolve the guest-binary cache key");
        let layout = mvm_build::guest_agent_build::GuestAgentLayout::under(
            cache_root,
            source.cache_key(),
            mvm_core::arch::GuestArch::host(),
        );
        std::fs::create_dir_all(&layout.dir).unwrap();
        for (name, path) in layout.binaries().artifacts() {
            let mut bytes = name.as_bytes().to_vec();
            bytes.extend_from_slice(flavour);
            std::fs::write(path, &bytes).unwrap();
        }
        layout.dir.clone()
    }

    #[test]
    fn runtime_tag_is_well_formed() {
        let tmp = tempfile::tempdir().unwrap();
        seed_guest_artifacts(tmp.path(), b"v1");
        let tag = oci_runtime_tag(tmp.path());
        assert!(
            tag.starts_with(&format!(
                "{}-inject-{}-guest-",
                env!("CARGO_PKG_VERSION"),
                mvm_build::oci_runtime_inject::INJECT_SEMANTICS_VERSION
            )),
            "unexpected runtime tag: {tag}"
        );
        assert_eq!(
            tag.rsplit_once("-guest-").unwrap().1.len(),
            16,
            "runtime tag should carry a short guest-runtime digest"
        );
    }

    /// The behaviour the hand-bumped epoch constant used to stand in for: a
    /// rebuilt injected artifact must change the tag on its own. `/init` is the
    /// case the old source fingerprint structurally could not see, and which
    /// needed epochs 4, 5 and 8 bumped by hand.
    #[test]
    fn a_rebuilt_injected_artifact_changes_the_runtime_tag() {
        let tmp = tempfile::tempdir().unwrap();
        seed_guest_artifacts(tmp.path(), b"v1");
        let before = oci_runtime_tag(tmp.path());

        seed_guest_artifacts(tmp.path(), b"v2");
        let after = oci_runtime_tag(tmp.path());

        assert_ne!(
            before, after,
            "a rebuilt guest artifact must invalidate the cached rootfs"
        );

        let mut cached = sample_image("docker.io/library/alpine:3.20", "sha256:dead", "blobs/a");
        cached.rootfs_path = Some(format!("rootfs/{before}/rootfs.ext4"));
        cached.runtime_tag = Some(before);
        assert!(
            !cached_rootfs_is_current(&cached, &after),
            "a rootfs carrying the old runtime tag must be re-materialized"
        );
    }

    #[test]
    fn an_unchanged_runtime_keeps_the_tag_so_the_cache_hits() {
        let tmp = tempfile::tempdir().unwrap();
        seed_guest_artifacts(tmp.path(), b"v1");
        assert_eq!(
            oci_runtime_tag(tmp.path()),
            oci_runtime_tag(tmp.path()),
            "an unchanged runtime must keep hitting the cache"
        );
    }

    /// The tag gate runs before anything decides a materialization is needed,
    /// so a cold guest cache must not be answered by cross-compiling. It gets a
    /// marked placeholder that cannot collide with a real digest.
    #[test]
    fn a_cold_guest_cache_yields_a_marked_tag_without_building() {
        let tmp = tempfile::tempdir().unwrap();
        let identity = mvm_build::run_image::resolve_guest_runtime_identity(tmp.path()).unwrap();
        assert!(
            identity.starts_with("pending-"),
            "a cold cache must report a pending identity, not build: {identity}"
        );

        seed_guest_artifacts(tmp.path(), b"v1");
        let resolved = mvm_build::run_image::resolve_guest_runtime_identity(tmp.path()).unwrap();
        assert!(
            !resolved.starts_with("pending-"),
            "a warm cache must report the artifact digest"
        );
        assert_ne!(identity, resolved);
    }

    // The tag gate runs on every invocation, so its steady-state cost matters —
    // but there is deliberately no wall-clock assertion for it here.
    // `.config/nextest.toml` records that fixed time budgets are missed at full
    // workspace parallelism while passing alone, and that retries are off
    // because a test which passes on the second attempt carries no
    // information. A 20ms ceiling across a 77s local run and a 26m CI lane is a
    // flake generator, not a gate.
    //
    // The property that makes the cost small is asserted structurally instead,
    // by the test below: the gate resolves without reading the artifacts at
    // all. The measured figure is recorded in
    // `specs/sprint/delivery/artifact-derived-runtime-identity.md`.

    /// The steady-state gate must not read the artifacts either.
    ///
    /// Proven by swapping each artifact's content while holding its length and
    /// mtime fixed: the sidecar's stamps still match, so a path that trusts it
    /// returns the original tag, while anything that re-read the bytes would
    /// digest different content and return a different one.
    ///
    /// Deliberately not done by making the files unreadable — root ignores
    /// mode bits, and CI containers routinely run as root, so a permissions
    /// trick would pass there for the wrong reason.
    #[test]
    fn the_runtime_tag_reads_the_sidecar_not_the_artifact_bytes() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = seed_guest_artifacts(tmp.path(), b"v1");
        let expected = oci_runtime_tag(tmp.path());

        let mut swapped = 0;
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.file_name().and_then(|n| n.to_str()) == Some("runtime-id") {
                continue;
            }
            let original = std::fs::read(&path).unwrap();
            let mtime = std::fs::metadata(&path).unwrap().modified().unwrap();
            let flipped: Vec<u8> = original.iter().map(|b| b ^ 0xFF).collect();
            std::fs::write(&path, &flipped).unwrap();
            let f = std::fs::File::options().write(true).open(&path).unwrap();
            f.set_times(std::fs::FileTimes::new().set_modified(mtime))
                .unwrap();
            drop(f);
            swapped += 1;
        }
        assert_eq!(swapped, 4, "expected the full artifact set");

        assert_eq!(
            oci_runtime_tag(tmp.path()),
            expected,
            "the tag gate must be answerable from the sidecar alone"
        );
    }

    #[test]
    fn stale_runtime_tag_marks_rootfs_not_current() {
        let mut image = sample_image("docker.io/library/alpine:3.20", "sha256:dead", "blobs/a");
        image.rootfs_path = Some("rootfs/alpine/rootfs.ext4".to_string());
        let current = oci_runtime_tag(tempfile::tempdir().unwrap().path());

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

    /// A fn-pointer materializer cannot capture, so the evidence the
    /// rematerializer handed it is recorded on disk for the caller to
    /// assert on — same pattern as the deferred-nodes recording in the
    /// pull-path tests.
    fn evidence_recording_materialize(call: MaterializeCall<'_>) -> Result<()> {
        assert!(call.unpacked_root.is_dir(), "unpacked root must exist");
        let parent = call.rootfs_abs.parent().expect("rootfs has parent");
        fs::create_dir_all(parent)?;
        let seen = serde_json::json!({
            "sealed": call.sealed,
            "label": call.image_label,
            "evidence": call.evidence.map(|e| serde_json::json!({
                "image_ref": e.image_ref(),
                "image_digest": e.image_digest(),
            })),
        });
        fs::write(
            parent.join("evidence-seen.json"),
            serde_json::to_vec(&seen)?,
        )?;
        fs::write(
            call.rootfs_abs,
            format!("materialized:{}", call.image_label),
        )?;
        Ok(())
    }

    fn seed_index_and_unpacked(cache_root: &Path, image: &CachedOciImage) {
        let index = super::super::oci_types::OciCacheIndex {
            schema_version: 1,
            images: vec![image.clone()],
        };
        fs::create_dir_all(cache_root).expect("create cache root");
        fs::write(
            cache_root.join(super::super::oci_types::INDEX_FILE),
            serde_json::to_vec_pretty(&index).expect("serialize index"),
        )
        .expect("write index");
        let unpacked = cache_root
            .join("unpacked")
            .join(super::super::cache::sha256_hex(&image.resolved_digest).expect("digest hex"));
        fs::create_dir_all(&unpacked).expect("create unpacked tree");
    }

    #[test]
    fn prod_rematerialize_hands_seal_evidence_to_the_materializer() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let keys_home = tempfile::tempdir().expect("keys tempdir");
        // The evidence builder loads (and may create) the host signing key;
        // point the whole mvm world at a scratch home so the test never
        // touches the developer's real keyring.
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(keys_home.path());
        let digest = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
        let mut image = sample_image("docker.io/library/alpine:3.20", digest, "blobs/a");
        // No OCI config blob: the entrypoint lookup must not touch the network
        // of config files a pull would have written.
        image.config_path = None;
        seed_index_and_unpacked(tmp.path(), &image);
        let runtime_tag = oci_runtime_tag(tmp.path());

        let repaired = rematerialize_cached_image(
            tmp.path(),
            image,
            &runtime_tag,
            evidence_recording_materialize,
            true,
        )
        .expect("prod rematerialize succeeds")
        .expect("unpacked tree present");

        let rootfs_abs =
            safe_cache_path(tmp.path(), repaired.rootfs_path.as_deref().expect("rootfs"))
                .expect("resolve recorded rootfs");
        let seen: serde_json::Value = serde_json::from_slice(
            &fs::read(
                rootfs_abs
                    .parent()
                    .expect("rootfs has parent")
                    .join("evidence-seen.json"),
            )
            .expect("materializer recorded the evidence it was handed"),
        )
        .expect("parse recorded evidence");
        assert_eq!(seen["sealed"], true, "prod request seals the rootfs");
        assert_eq!(
            seen["evidence"]["image_ref"], "docker.io/library/alpine:3.20",
            "mark names the canonical image reference"
        );
        assert_eq!(seen["evidence"]["image_digest"], digest);
    }

    #[test]
    fn dev_rematerialize_passes_no_seal_evidence() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let digest = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
        let mut image = sample_image("docker.io/library/alpine:3.20", digest, "blobs/a");
        image.config_path = None;
        seed_index_and_unpacked(tmp.path(), &image);
        let runtime_tag = oci_runtime_tag(tmp.path());

        let repaired = rematerialize_cached_image(
            tmp.path(),
            image,
            &runtime_tag,
            evidence_recording_materialize,
            false,
        )
        .expect("dev rematerialize succeeds")
        .expect("unpacked tree present");

        let rootfs_abs =
            safe_cache_path(tmp.path(), repaired.rootfs_path.as_deref().expect("rootfs"))
                .expect("resolve recorded rootfs");
        let seen: serde_json::Value = serde_json::from_slice(
            &fs::read(
                rootfs_abs
                    .parent()
                    .expect("rootfs has parent")
                    .join("evidence-seen.json"),
            )
            .expect("materializer recorded the evidence it was handed"),
        )
        .expect("parse recorded evidence");
        assert_eq!(seen["sealed"], false);
        assert!(
            seen["evidence"].is_null(),
            "unsealed requests must not carry provenance evidence"
        );
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
