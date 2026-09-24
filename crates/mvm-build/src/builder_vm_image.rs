//! VMM-neutral builder image discovery and Stage 0 persistent-store setup.

use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Deserialize;

use crate::builder_vm::{
    BUILDER_VM_CACHE_CONTRACT_VERSION, BuilderVmError, BuilderVmImage, builder_vm_cache_dir,
    host_arch_tag, stage0_store_image_name_for,
};

type SourceFingerprintResolver = fn(&Path) -> Result<Option<String>, String>;

static SOURCE_FINGERPRINT_RESOLVER: OnceLock<SourceFingerprintResolver> = OnceLock::new();

/// Register the CLI-owned resolver for the source fingerprint embedded into
/// the builder image.
///
/// `mvm-build` owns cache loading but cannot see `mvmctl`'s embedded host
/// binary table. The CLI owns that table and the Stage 0 fingerprint function,
/// so it supplies the exact same answer here rather than letting the loader
/// grow a second, drifting fingerprint implementation.
pub fn register_source_fingerprint_resolver(resolver: SourceFingerprintResolver) {
    let _ = SOURCE_FINGERPRINT_RESOLVER.set(resolver);
}

enum SourceCheckoutFreshness {
    NotApplicable,
    Fingerprint(String),
    BootstrapPreflight,
}

#[derive(Debug, Deserialize)]
struct BuilderVmCacheManifest {
    #[serde(default)]
    cache_contract_version: u32,
    #[serde(default)]
    runtime_overlay_ready: bool,
    #[serde(default)]
    vsock_egress_ready: bool,
}

fn append_cmdline_token(base: &str, token: &str) -> String {
    if base.split_whitespace().any(|existing| existing == token) {
        base.to_string()
    } else if base.trim().is_empty() {
        token.to_string()
    } else {
        format!("{base} {token}")
    }
}

/// The source checkout this package was compiled from, when its builder image
/// flake is still present.
pub fn builder_vm_source_checkout_root() -> Option<PathBuf> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir.parent()?.parent()?.to_path_buf();
    workspace_root
        .join("nix/images/builder-vm/flake.nix")
        .is_file()
        .then_some(workspace_root)
}

fn read_manifest(path: &Path, arch_dir: &Path) -> Result<BuilderVmCacheManifest, BuilderVmError> {
    let body = std::fs::read_to_string(path).map_err(|error| {
        BuilderVmError::ExtractionFailed(format!(
            "{} missing or unreadable ({error}). The builder VM cache is poisoned; delete {} and re-run `mvmctl bootstrap` to re-bootstrap.",
            path.display(),
            arch_dir.display(),
        ))
    })?;
    serde_json::from_str(&body).map_err(|error| {
        BuilderVmError::ExtractionFailed(format!(
            "{} is malformed ({error}). The builder VM cache is poisoned; delete {} and re-run `mvmctl bootstrap` to re-bootstrap.",
            path.display(),
            arch_dir.display(),
        ))
    })
}

fn validate_cache(arch_dir: &Path) -> Result<String, BuilderVmError> {
    let kernel = arch_dir.join("vmlinux");
    let rootfs = arch_dir.join("rootfs.ext4");
    let cmdline_path = arch_dir.join("cmdline.txt");
    if !kernel.is_file() || !rootfs.is_file() {
        return Err(BuilderVmError::ExtractionFailed(format!(
            "builder VM image not found at {}. Populate the cache by running `nix build ./nix/images/builder-vm#packages.{}-linux.default` on a host with Nix and copying `result/{{vmlinux,rootfs.ext4,cmdline.txt}}` to {}/.",
            arch_dir.display(),
            host_arch_tag(),
            arch_dir.display(),
        )));
    }
    let cmdline = std::fs::read_to_string(&cmdline_path)
        .map_err(|error| {
            BuilderVmError::ExtractionFailed(format!(
                "{} missing or unreadable ({error}). The builder VM cache is poisoned; delete {} and re-run `mvmctl bootstrap` to re-bootstrap.",
                cmdline_path.display(),
                arch_dir.display(),
            ))
        })?
        .trim()
        .to_string();
    let cmdline = append_cmdline_token(
        &cmdline,
        &crate::builder_vm::builder_hostepoch_cmdline_token(),
    );
    let manifest = read_manifest(&arch_dir.join("manifest.json"), arch_dir)?;
    if manifest.cache_contract_version != BUILDER_VM_CACHE_CONTRACT_VERSION
        || !manifest.runtime_overlay_ready
        || !manifest.vsock_egress_ready
    {
        return Err(BuilderVmError::ExtractionFailed(format!(
            "builder VM cache at {} is stale: manifest.json must declare `cache_contract_version={BUILDER_VM_CACHE_CONTRACT_VERSION}`, `runtime_overlay_ready=true`, and `vsock_egress_ready=true`. Delete {} and re-run `mvmctl bootstrap` to re-bootstrap a current vsock-only builder image.",
            arch_dir.display(),
            arch_dir.display(),
        )));
    }
    Ok(cmdline)
}

fn load_from_cache(arch_dir: &Path) -> Result<BuilderVmImage, BuilderVmError> {
    Ok(BuilderVmImage::new(
        arch_dir.join("vmlinux"),
        arch_dir.join("rootfs.ext4"),
        validate_cache(arch_dir)?,
    ))
}

fn validate_source_fingerprint(
    arch_dir: &Path,
    expected_fingerprint: Option<&str>,
) -> Result<(), BuilderVmError> {
    let Some(expected) = expected_fingerprint else {
        return Ok(());
    };
    let path = arch_dir.join(crate::cache_install::BUILDER_VM_SOURCE_FINGERPRINT_FILE);
    let actual = std::fs::read_to_string(&path).map_err(|error| {
        BuilderVmError::ExtractionFailed(format!(
            "builder VM cache at {} is stale: source fingerprint {} is missing or unreadable ({error})",
            arch_dir.display(),
            path.display(),
        ))
    })?;
    if actual.trim() != expected {
        return Err(BuilderVmError::ExtractionFailed(format!(
            "builder VM cache at {} is stale: source fingerprint does not match this source checkout and its embedded host binaries",
            arch_dir.display(),
        )));
    }
    Ok(())
}

fn load_from_cache_for_source(
    arch_dir: &Path,
    expected_fingerprint: Option<&str>,
) -> Result<BuilderVmImage, BuilderVmError> {
    validate_source_fingerprint(arch_dir, expected_fingerprint)?;
    load_from_cache(arch_dir)
}

fn default_cache_dir() -> PathBuf {
    crate::cache_install::default_cache_root().join("builder-vm")
}

fn shared_cache_is_trustworthy(source: &Path) -> bool {
    use crate::cache_install::DigestManifestCheck;
    match crate::cache_install::verify_digest_manifest(
        source,
        crate::cache_install::BUILDER_VM_ARTIFACT_DIGEST_FILE,
        crate::cache_install::BUILDER_VM_CACHE_ARTIFACTS,
    ) {
        DigestManifestCheck::Match | DigestManifestCheck::ManifestAbsent => true,
        rejected => {
            tracing::debug!(source = %source.display(), verdict = ?rejected,
                "declining to seed builder image from shared cache: recorded digests do not match");
            false
        }
    }
}

fn shared_cache_source(source: &Path, expected_fingerprint: Option<&str>) -> Option<PathBuf> {
    validate_cache(source).ok()?;
    validate_source_fingerprint(source, expected_fingerprint).ok()?;
    shared_cache_is_trustworthy(source).then(|| source.to_path_buf())
}

fn copy_cache(source: &Path, target: &Path) -> Result<(), BuilderVmError> {
    std::fs::create_dir_all(target).map_err(|error| {
        BuilderVmError::ExtractionFailed(format!("create {}: {error}", target.display()))
    })?;
    for name in crate::cache_install::BUILDER_VM_CACHE_ARTIFACTS {
        let from = source.join(name);
        let to = target.join(name);
        std::fs::copy(&from, &to).map_err(|error| {
            BuilderVmError::ExtractionFailed(format!(
                "seed builder image cache {} -> {}: {error}",
                from.display(),
                to.display(),
            ))
        })?;
    }
    for name in crate::cache_install::BUILDER_VM_CACHE_SIDECARS {
        let from = source.join(name);
        if from.is_file() {
            let _ = std::fs::copy(&from, target.join(name));
        }
    }
    Ok(())
}

fn seed_from_default_cache(
    target: &Path,
    expected_fingerprint: Option<&str>,
) -> Result<bool, BuilderVmError> {
    crate::cache_install::seed_on_miss(
        &builder_vm_cache_dir().join(host_arch_tag()),
        &default_cache_dir().join(host_arch_tag()),
        |source| shared_cache_source(source, expected_fingerprint),
        |source| copy_cache(&source, target),
    )
}

fn source_checkout_freshness() -> Result<SourceCheckoutFreshness, BuilderVmError> {
    let Some(workspace_root) = builder_vm_source_checkout_root() else {
        return Ok(SourceCheckoutFreshness::NotApplicable);
    };
    let Some(resolver) = SOURCE_FINGERPRINT_RESOLVER.get() else {
        // Library embedders do not own mvmctl's embedded host-binary table and
        // keep the pre-existing cache contract. The CLI always registers.
        return Ok(SourceCheckoutFreshness::NotApplicable);
    };
    resolver(&workspace_root)
        .map(|fingerprint| match fingerprint {
            Some(fingerprint) => SourceCheckoutFreshness::Fingerprint(fingerprint),
            // An ordinary contributor binary has no embedded payload from
            // which to derive the authoritative identity. Its bootstrap helper
            // does, so let that helper run the canonical readiness decision.
            None => SourceCheckoutFreshness::BootstrapPreflight,
        })
        .map_err(|error| {
            BuilderVmError::ExtractionFailed(format!(
                "compute current builder VM source fingerprint: {error}"
            ))
        })
}

fn ensure_builder_vm_image_for_source(
    expected_fingerprint: Option<&str>,
) -> Result<BuilderVmImage, BuilderVmError> {
    let arch_dir = builder_vm_cache_dir().join(host_arch_tag());
    match load_from_cache_for_source(&arch_dir, expected_fingerprint) {
        Ok(image) => Ok(image),
        Err(initial_error) => {
            if seed_from_default_cache(&arch_dir, expected_fingerprint)? {
                return load_from_cache_for_source(&arch_dir, expected_fingerprint);
            }
            if !crate::builder_vm_bootstrap::auto_bootstrap_builder_vm_image(&arch_dir)? {
                return Err(initial_error);
            }
            load_from_cache_for_source(&arch_dir, expected_fingerprint)
        }
    }
}

fn load_after_source_preflight(
    arch_dir: &Path,
    bootstrap: impl FnOnce(&Path) -> Result<bool, BuilderVmError>,
) -> Result<BuilderVmImage, BuilderVmError> {
    if !bootstrap(arch_dir)? {
        return Err(BuilderVmError::ExtractionFailed(format!(
            "builder VM source-checkout freshness preflight was declined for {}; refusing to load a cache whose source and embedded host-binary identity was not verified",
            arch_dir.display(),
        )));
    }
    load_from_cache(arch_dir)
}

/// Find the current builder image in the configured cache, seeding or
/// bootstrapping it on a cache miss.
pub fn ensure_builder_vm_image() -> Result<BuilderVmImage, BuilderVmError> {
    let arch_dir = builder_vm_cache_dir().join(host_arch_tag());
    match source_checkout_freshness()? {
        SourceCheckoutFreshness::NotApplicable => ensure_builder_vm_image_for_source(None),
        SourceCheckoutFreshness::Fingerprint(fingerprint) => {
            ensure_builder_vm_image_for_source(Some(&fingerprint))
        }
        SourceCheckoutFreshness::BootstrapPreflight => load_after_source_preflight(
            &arch_dir,
            crate::builder_vm_bootstrap::auto_bootstrap_builder_vm_image,
        ),
    }
}

/// Filename of Stage 0's dedicated persistent Nix-store image.
pub fn stage0_nix_store_image_name() -> String {
    stage0_store_image_name_for(host_arch_tag())
}

/// Populate the Stage 0 store image from a materialized seed, when present.
///
/// Must run under the store's image lock: it judges the filesystem by the
/// state its last mount left behind, which only holds while nothing has it
/// mounted.
pub fn prepopulate_stage0_nix_store_image(
    image: &BuilderVmImage,
    store_image: &Path,
) -> Result<(), BuilderVmError> {
    let host_mkfs = find_host_mkfs_ext4();
    if let StorePreparation::Discarded(state) =
        prepopulate_with_mkfs(image, store_image, host_mkfs.as_deref())?
    {
        eprintln!("{}", stage0_store_discard_notice(store_image, state));
    }
    Ok(())
}

/// What preparing the Stage 0 store did to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StorePreparation {
    /// The image is not a seed root, so there was nothing to prepare from.
    NoSeed,
    /// Bound to this seed and cleanly unmounted: handed to the guest as-is.
    Reused,
    /// New, or bound to a different seed: formatted from the seed.
    Formatted,
    /// Bound to this seed but not safe to mount: discarded and formatted.
    Discarded(StoreSuperblock),
}

pub(crate) fn prepopulate_with_mkfs(
    image: &BuilderVmImage,
    store_image: &Path,
    host_mkfs: Option<&Path>,
) -> Result<StorePreparation, BuilderVmError> {
    let BuilderVmImage::RootDir { root_dir, .. } = image else {
        return Ok(StorePreparation::NoSeed);
    };
    let seed_nix = root_dir.join("nix");
    let seed_store = seed_nix.join("store");
    if !seed_store.is_dir() {
        return Ok(StorePreparation::NoSeed);
    }
    let marker = stage0_marker(&seed_store)?;
    let marker_path = marker_path(store_image);
    let mut preparation = StorePreparation::Formatted;
    if std::fs::read_to_string(&marker_path).is_ok_and(|existing| existing == marker) {
        let state = StoreSuperblock::read(store_image)?;
        if state.is_reusable() {
            return Ok(StorePreparation::Reused);
        }
        preparation = StorePreparation::Discarded(state);
    }
    if marker_path.exists() {
        std::fs::remove_file(&marker_path).map_err(|error| {
            BuilderVmError::ExtractionFailed(format!("remove {}: {error}", marker_path.display()))
        })?;
    }
    if let Some(mkfs) = host_mkfs {
        let blocks = host_file_4k_blocks(store_image)?;
        let status = Command::new(mkfs)
            .args(["-F", "-q", "-b", "4096", "-L"])
            .arg(crate::rootfs::STAGE0_NIX_STORE_EXT4_LABEL)
            .arg("-d")
            .arg(&seed_nix)
            .arg(store_image)
            .arg(blocks.to_string())
            .status()
            .map_err(|error| {
                BuilderVmError::ExtractionFailed(format!("spawn {}: {error}", mkfs.display()))
            })?;
        if !status.success() {
            return Err(BuilderVmError::ExtractionFailed(format!(
                "{} -d {} -> {} exited {}",
                mkfs.display(),
                seed_nix.display(),
                store_image.display(),
                status.code().unwrap_or(-1),
            )));
        }
    } else {
        format_empty_stage0_store(store_image)?;
    }
    std::fs::write(&marker_path, marker).map_err(|error| {
        BuilderVmError::ExtractionFailed(format!("write {}: {error}", marker_path.display()))
    })?;
    Ok(preparation)
}

pub(crate) fn format_empty_stage0_store(path: &Path) -> Result<(), BuilderVmError> {
    let blocks = host_file_4k_blocks(path)?;
    let size = blocks * mvm_fs::ext4::BLOCK_SIZE as u64;
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|error| {
            BuilderVmError::ExtractionFailed(format!("open {}: {error}", path.display()))
        })?;
    let device_size = file
        .metadata()
        .map_err(|error| {
            BuilderVmError::ExtractionFailed(format!("stat {}: {error}", path.display()))
        })?
        .len();
    file.set_len(0)
        .and_then(|()| file.set_len(device_size))
        .map_err(|error| {
            BuilderVmError::ExtractionFailed(format!("resize {}: {error}", path.display()))
        })?;
    mvm_fs::ext4::mkfs::format_empty_ext4_labeled(
        &mut file,
        size,
        crate::rootfs::STAGE0_NIX_STORE_EXT4_LABEL.as_bytes(),
    )
    .map_err(|error| {
        BuilderVmError::ExtractionFailed(format!(
            "pure-Rust ext4 format of {}: {error}",
            path.display()
        ))
    })?;
    Ok(())
}

fn find_host_mkfs_ext4() -> Option<PathBuf> {
    [
        "/sbin/mkfs.ext4",
        "/usr/sbin/mkfs.ext4",
        "/bin/mkfs.ext4",
        "/usr/bin/mkfs.ext4",
    ]
    .into_iter()
    .map(PathBuf::from)
    .find(|path| path.is_file())
    .or_else(|| which::which("mkfs.ext4").ok())
}

pub(crate) fn host_file_4k_blocks(path: &Path) -> Result<u64, BuilderVmError> {
    let len = std::fs::metadata(path)
        .map_err(|error| {
            BuilderVmError::ExtractionFailed(format!("stat {}: {error}", path.display()))
        })?
        .len();
    let blocks = len / 4096;
    if blocks <= 16 {
        return Err(BuilderVmError::ExtractionFailed(format!(
            "Stage 0 store image {} is too small for ext4 prepopulation ({len} bytes)",
            path.display()
        )));
    }
    Ok(blocks - 16)
}

pub(crate) fn marker_path(store_image: &Path) -> PathBuf {
    store_image.with_extension("stage0-seed")
}

pub fn invalidate_stage0_store_after_ext4_error(
    console_log: &Path,
    store_image: &Path,
) -> Result<(), BuilderVmError> {
    let console = std::fs::read_to_string(console_log).unwrap_or_default();
    if !console.contains("persistent Stage 0 ext4 store reported") {
        return Ok(());
    }
    match std::fs::remove_file(marker_path(store_image)) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(BuilderVmError::ExtractionFailed(format!(
            "remove invalid Stage 0 store marker for {}: {error}",
            store_image.display()
        ))),
    }
}

/// What a store image's ext4 superblock records about how its last mount
/// ended.
///
/// The seed marker beside the image binds it to a seed but lives outside the
/// filesystem, so it cannot say whether the filesystem is intact. The
/// superblock can. A read-write mount of an ext4 without a journal clears
/// `EXT4_VALID_FS` and only an unmount sets it again, so a guest that died
/// mid-build leaves the bit clear, and with no journal there is nothing to
/// replay: the next mount reads half-written allocation bitmaps as truth. The
/// pure-Rust formatter writes exactly that journal-less filesystem. A
/// journaled one never clears the bit (it marks the journal for recovery
/// instead), so requiring it costs a journaled store nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StoreSuperblock {
    /// Unmounted cleanly, no errors recorded.
    Clean,
    /// Mounted read-write and never unmounted.
    NotCleanlyUnmounted,
    /// The kernel recorded filesystem errors on it.
    ErrorsRecorded,
    /// No ext4 superblock at all.
    NotExt4,
}

impl StoreSuperblock {
    /// Classify the four bytes at `s_magic`: the magic, then `s_state`.
    fn parse(fields: [u8; 4]) -> Self {
        let magic = u16::from_le_bytes([fields[0], fields[1]]);
        let state = u16::from_le_bytes([fields[2], fields[3]]);
        if magic != EXT4_SUPERBLOCK_MAGIC {
            Self::NotExt4
        } else if state & EXT4_ERROR_FS != 0 {
            Self::ErrorsRecorded
        } else if state & EXT4_VALID_FS == 0 {
            Self::NotCleanlyUnmounted
        } else {
            Self::Clean
        }
    }

    pub(crate) fn read(path: &Path) -> Result<Self, BuilderVmError> {
        let mut file = std::fs::File::open(path).map_err(|error| {
            BuilderVmError::ExtractionFailed(format!("open {}: {error}", path.display()))
        })?;
        file.seek(SeekFrom::Start(EXT4_SUPERBLOCK_MAGIC_OFFSET))
            .map_err(|error| {
                BuilderVmError::ExtractionFailed(format!("seek {}: {error}", path.display()))
            })?;
        let mut fields = [0_u8; 4];
        file.read_exact(&mut fields).map_err(|error| {
            BuilderVmError::ExtractionFailed(format!(
                "read ext4 state from {}: {error}",
                path.display()
            ))
        })?;
        Ok(Self::parse(fields))
    }

    pub(crate) fn is_reusable(self) -> bool {
        self == Self::Clean
    }

    fn discard_reason(self) -> &'static str {
        match self {
            Self::Clean => "is clean",
            Self::NotCleanlyUnmounted => {
                "was left mounted by a Stage 0 run that did not shut down cleanly \
                 (it was interrupted or its VM was killed)"
            }
            Self::ErrorsRecorded => "has ext4 errors recorded by the guest kernel",
            Self::NotExt4 => "has no ext4 filesystem",
        }
    }
}

/// The one line a user sees when a warm Stage 0 store is thrown away, so a
/// slower bootstrap is explained rather than mysterious.
pub(crate) fn stage0_store_discard_notice(store_image: &Path, state: StoreSuperblock) -> String {
    format!(
        "[mvm] the Stage 0 Nix store {} {}; discarding it and rebuilding it from the seed",
        store_image.display(),
        state.discard_reason()
    )
}

pub(crate) fn stage0_marker(seed_store: &Path) -> Result<String, BuilderVmError> {
    Ok(format!(
        "schema_version=2\nseed_store_entries_sha256={}\n",
        crate::seed_store_entries::seed_store_entries_hash(seed_store)
            .map_err(BuilderVmError::ExtractionFailed)?
    ))
}

pub(crate) const EXT4_VALID_FS: u16 = 0x0001;
pub(crate) const EXT4_SUPERBLOCK_MAGIC_OFFSET: u64 = 1024 + 0x38;
pub(crate) const EXT4_SUPERBLOCK_MAGIC: u16 = 0xEF53;
pub(crate) const EXT4_ERROR_FS: u16 = 0x0002;

/// A collision-resistant per-process job identifier shared by all VMMs.
pub fn unique_job_id() -> String {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0);
    format!("{millis:013}-{}", std::process::id())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_test_cache(dir: &Path, source_fingerprint: Option<&str>) {
        std::fs::create_dir_all(dir).expect("create cache");
        std::fs::write(dir.join("vmlinux"), b"kernel").expect("write kernel");
        std::fs::write(dir.join("rootfs.ext4"), b"rootfs").expect("write rootfs");
        std::fs::write(
            dir.join("cmdline.txt"),
            b"console=hvc0 init=/sbin/mvm-host-vm-init\n",
        )
        .expect("write cmdline");
        std::fs::write(
            dir.join("manifest.json"),
            format!(
                "{{\"cache_contract_version\":{BUILDER_VM_CACHE_CONTRACT_VERSION},\"runtime_overlay_ready\":true,\"vsock_egress_ready\":true}}"
            ),
        )
        .expect("write manifest");
        if let Some(fingerprint) = source_fingerprint {
            std::fs::write(
                dir.join(crate::cache_install::BUILDER_VM_SOURCE_FINGERPRINT_FILE),
                format!("{fingerprint}\n"),
            )
            .expect("write source fingerprint");
        }
    }

    #[test]
    fn source_checkout_cache_requires_its_current_fingerprint() {
        let cache = tempfile::tempdir().expect("tempdir");
        write_test_cache(cache.path(), Some("old-source-and-host-binaries"));

        let error =
            load_from_cache_for_source(cache.path(), Some("current-source-and-host-binaries"))
                .expect_err("a source checkout must not boot an old builder image");

        assert!(format!("{error}").contains("source fingerprint"), "{error}");
    }

    #[test]
    fn source_checkout_cache_requires_a_fingerprint_marker() {
        let cache = tempfile::tempdir().expect("tempdir");
        write_test_cache(cache.path(), None);

        let error =
            load_from_cache_for_source(cache.path(), Some("current-source-and-host-binaries"))
                .expect_err("a source checkout must not boot an unversioned builder image");

        assert!(
            format!("{error}").contains("missing or unreadable"),
            "{error}"
        );
    }

    #[test]
    fn shared_cache_seed_requires_the_current_source_fingerprint() {
        let cache = tempfile::tempdir().expect("tempdir");
        write_test_cache(cache.path(), Some("old-source-and-host-binaries"));

        assert!(
            shared_cache_source(cache.path(), Some("current-source-and-host-binaries")).is_none(),
            "an isolated source checkout must not seed an old shared image"
        );
    }

    #[test]
    fn release_cache_does_not_require_a_source_fingerprint() {
        let cache = tempfile::tempdir().expect("tempdir");
        write_test_cache(cache.path(), None);

        load_from_cache_for_source(cache.path(), None)
            .expect("a release binary has no source checkout to compare");
        assert!(shared_cache_source(cache.path(), None).is_some());
    }

    #[test]
    fn declined_source_checkout_preflight_cannot_load_an_unverified_cache() {
        let cache = tempfile::tempdir().expect("tempdir");
        write_test_cache(cache.path(), Some("old-source-and-host-binaries"));

        let error = load_after_source_preflight(cache.path(), |_| Ok(false))
            .expect_err("a declined helper preflight must fail closed");

        assert!(format!("{error}").contains("preflight"), "{error}");
    }

    #[test]
    fn job_id_uses_one_shared_timestamp_pid_shape() {
        let id = unique_job_id();
        let (millis, pid) = id.split_once('-').expect("timestamp-pid shape");
        assert!(millis.parse::<u128>().is_ok());
        assert_eq!(pid, std::process::id().to_string());
    }

    /// A seed root with one store entry, and a sparse store image beside it.
    fn seeded_stage0_store(scratch: &Path) -> (BuilderVmImage, PathBuf) {
        let root_dir = scratch.join("root");
        let seed_store = root_dir.join("nix").join("store");
        std::fs::create_dir_all(&seed_store).expect("create seed store");
        std::fs::write(seed_store.join("aaa-seed-pkg"), b"x").expect("write seed entry");
        let store_image = scratch.join("nix-store-stage0-test.img");
        std::fs::File::create(&store_image)
            .and_then(|file| file.set_len(64 * 1024 * 1024))
            .expect("create sparse store image");
        (BuilderVmImage::new_root_dir(root_dir, "init"), store_image)
    }

    /// Stands in for everything a Stage 0 guest writes to its store: a reformat
    /// zeroes the image, so a surviving sentinel is a surviving store.
    const WARM_SENTINEL_OFFSET: u64 = 8 * 1024 * 1024;

    fn write_warm_sentinel(store_image: &Path) {
        use std::io::Write as _;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .open(store_image)
            .expect("open store image");
        file.seek(SeekFrom::Start(WARM_SENTINEL_OFFSET))
            .and_then(|_| file.write_all(b"warm-cache"))
            .expect("write sentinel");
    }

    fn warm_sentinel_survived(store_image: &Path) -> bool {
        let mut file = std::fs::File::open(store_image).expect("open store image");
        let mut sentinel = [0_u8; 10];
        file.seek(SeekFrom::Start(WARM_SENTINEL_OFFSET))
            .and_then(|_| file.read_exact(&mut sentinel))
            .expect("read sentinel");
        &sentinel == b"warm-cache"
    }

    /// Writes `s_state` the way the guest kernel leaves it: cleared at a
    /// read-write mount of an unjournaled filesystem, set again at unmount.
    fn write_superblock_state(store_image: &Path, state: u16) {
        use std::io::Write as _;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .open(store_image)
            .expect("open store image");
        file.seek(SeekFrom::Start(EXT4_SUPERBLOCK_MAGIC_OFFSET + 2))
            .and_then(|_| file.write_all(&state.to_le_bytes()))
            .expect("write s_state");
    }

    fn superblock_fields(magic: u16, state: u16) -> [u8; 4] {
        let [m0, m1] = magic.to_le_bytes();
        let [s0, s1] = state.to_le_bytes();
        [m0, m1, s0, s1]
    }

    #[test]
    fn superblock_state_classifies_the_last_mount() {
        let magic = EXT4_SUPERBLOCK_MAGIC;
        assert_eq!(
            StoreSuperblock::parse(superblock_fields(magic, EXT4_VALID_FS)),
            StoreSuperblock::Clean
        );
        assert_eq!(
            StoreSuperblock::parse(superblock_fields(magic, 0)),
            StoreSuperblock::NotCleanlyUnmounted
        );
        // Errors are the more specific diagnosis, so they win over a dirty bit.
        assert_eq!(
            StoreSuperblock::parse(superblock_fields(magic, EXT4_ERROR_FS)),
            StoreSuperblock::ErrorsRecorded
        );
        assert_eq!(
            StoreSuperblock::parse(superblock_fields(magic, EXT4_VALID_FS | EXT4_ERROR_FS)),
            StoreSuperblock::ErrorsRecorded
        );
        assert_eq!(
            StoreSuperblock::parse(superblock_fields(0, EXT4_VALID_FS)),
            StoreSuperblock::NotExt4
        );
    }

    #[test]
    fn only_a_clean_superblock_is_reusable() {
        assert!(StoreSuperblock::Clean.is_reusable());
        for state in [
            StoreSuperblock::NotCleanlyUnmounted,
            StoreSuperblock::ErrorsRecorded,
            StoreSuperblock::NotExt4,
        ] {
            assert!(!state.is_reusable(), "{state:?}");
        }
    }

    /// The pure-Rust formatter must hand the guest a store that reads as
    /// cleanly unmounted, or every first reuse would be a discard.
    #[test]
    fn a_freshly_formatted_store_reads_as_clean() {
        let scratch = tempfile::tempdir().expect("tempdir");
        let (image, store_image) = seeded_stage0_store(scratch.path());

        let prepared = prepopulate_with_mkfs(&image, &store_image, None).expect("format");

        assert_eq!(prepared, StorePreparation::Formatted);
        assert_eq!(
            StoreSuperblock::read(&store_image).expect("read superblock"),
            StoreSuperblock::Clean
        );
    }

    #[test]
    fn a_cleanly_unmounted_store_is_reused() {
        let scratch = tempfile::tempdir().expect("tempdir");
        let (image, store_image) = seeded_stage0_store(scratch.path());
        prepopulate_with_mkfs(&image, &store_image, None).expect("format");
        write_warm_sentinel(&store_image);

        let prepared = prepopulate_with_mkfs(&image, &store_image, None).expect("reuse");

        assert_eq!(prepared, StorePreparation::Reused);
        assert!(warm_sentinel_survived(&store_image));
    }

    /// The reported failure: a Stage 0 VM killed mid-build leaves its
    /// unjournaled store with the valid bit clear. Mounting that again is what
    /// produced `freeing already freed block` and a zero-filled `flake.nix`.
    #[test]
    fn a_store_an_interrupted_run_left_mounted_is_discarded() {
        let scratch = tempfile::tempdir().expect("tempdir");
        let (image, store_image) = seeded_stage0_store(scratch.path());
        prepopulate_with_mkfs(&image, &store_image, None).expect("format");
        write_warm_sentinel(&store_image);
        write_superblock_state(&store_image, 0);

        let prepared = prepopulate_with_mkfs(&image, &store_image, None).expect("discard");

        assert_eq!(
            prepared,
            StorePreparation::Discarded(StoreSuperblock::NotCleanlyUnmounted)
        );
        assert!(!warm_sentinel_survived(&store_image));
        assert_eq!(
            StoreSuperblock::read(&store_image).expect("read superblock"),
            StoreSuperblock::Clean,
            "the replacement store must itself be reusable"
        );
        assert!(
            marker_path(&store_image).exists(),
            "the replacement store is bound to the seed again"
        );
    }

    #[test]
    fn a_store_with_recorded_errors_is_discarded() {
        let scratch = tempfile::tempdir().expect("tempdir");
        let (image, store_image) = seeded_stage0_store(scratch.path());
        prepopulate_with_mkfs(&image, &store_image, None).expect("format");
        write_warm_sentinel(&store_image);
        write_superblock_state(&store_image, EXT4_VALID_FS | EXT4_ERROR_FS);

        let prepared = prepopulate_with_mkfs(&image, &store_image, None).expect("discard");

        assert_eq!(
            prepared,
            StorePreparation::Discarded(StoreSuperblock::ErrorsRecorded)
        );
        assert!(!warm_sentinel_survived(&store_image));
    }

    /// A build failure is not corruption. The guest unmounts the store on the
    /// failure path too, so the superblock reads clean and the console carries
    /// no ext4 report: the warm store has to survive.
    #[test]
    fn a_failed_build_that_shut_down_cleanly_keeps_its_store() {
        let scratch = tempfile::tempdir().expect("tempdir");
        let (image, store_image) = seeded_stage0_store(scratch.path());
        prepopulate_with_mkfs(&image, &store_image, None).expect("format");
        write_warm_sentinel(&store_image);
        // Mounted read-write, then unmounted by the guest's failure path.
        write_superblock_state(&store_image, 0);
        write_superblock_state(&store_image, EXT4_VALID_FS);
        let console = scratch.path().join("console.log");
        std::fs::write(&console, b"stage0-init: build failed: nix build exit 1\n")
            .expect("write console");

        invalidate_stage0_store_after_ext4_error(&console, &store_image).expect("inspect console");
        let prepared = prepopulate_with_mkfs(&image, &store_image, None).expect("reuse");

        assert_eq!(prepared, StorePreparation::Reused);
        assert!(warm_sentinel_survived(&store_image));
    }

    /// A seed change is a routine rebuild, not a fault, so it reformats without
    /// announcing a discard.
    #[test]
    fn a_store_formatted_for_a_different_seed_is_replaced_without_a_discard() {
        let scratch = tempfile::tempdir().expect("tempdir");
        let (image, store_image) = seeded_stage0_store(scratch.path());
        prepopulate_with_mkfs(&image, &store_image, None).expect("format");
        write_superblock_state(&store_image, 0);
        std::fs::write(marker_path(&store_image), b"schema_version=2\nold-seed\n")
            .expect("write stale marker");

        let prepared = prepopulate_with_mkfs(&image, &store_image, None).expect("reformat");

        assert_eq!(prepared, StorePreparation::Formatted);
    }

    #[test]
    fn the_discard_notice_names_the_store_and_the_cause() {
        let store = Path::new("/cache/nix-store-stage0-aarch64.img");

        let notice = stage0_store_discard_notice(store, StoreSuperblock::NotCleanlyUnmounted);

        assert!(notice.starts_with("[mvm] "), "{notice}");
        assert!(notice.contains(&store.display().to_string()), "{notice}");
        assert!(notice.contains("did not shut down cleanly"), "{notice}");
        assert!(notice.contains("rebuilding it from the seed"), "{notice}");
        assert!(
            stage0_store_discard_notice(store, StoreSuperblock::ErrorsRecorded)
                .contains("ext4 errors"),
        );
    }

    #[test]
    fn stage0_store_name_is_arch_keyed() {
        assert_eq!(
            stage0_nix_store_image_name(),
            format!("nix-store-stage0-{}.img", host_arch_tag())
        );
    }
}
