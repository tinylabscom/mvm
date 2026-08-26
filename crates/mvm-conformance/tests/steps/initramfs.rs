//! Steps for the deterministic cargo initramfs: the cpio build is
//! byte-deterministic and the assembled artifact carries the
//! content-address sidecar contract the resolver verifies. These drive the
//! real assembly code from fixed agent bytes and never invoke a toolchain,
//! so they run in the normal hermetic BDD gate.

use cucumber::{given, then, when};
use mvm_core::arch::GuestArch;
use mvm_core::vm_backend::RuntimeSourcePolicy;
use mvm_fs::initramfs::InitramfsResolver;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use crate::world::{CliWorld, ScenarioEnvGuard};

/// Parse the entry names of a newc archive, stopping at the trailer — the
/// layout assertion needs the exact entry sequence.
fn newc_names(cpio: &[u8]) -> Vec<String> {
    fn hex8(cpio: &[u8], off: usize) -> usize {
        usize::from_str_radix(std::str::from_utf8(&cpio[off..off + 8]).unwrap(), 16).unwrap()
    }
    let mut names = Vec::new();
    let mut off = 0;
    loop {
        assert_eq!(&cpio[off..off + 6], b"070701", "bad newc magic at {off}");
        let filesize = hex8(cpio, off + 54);
        let namesize = hex8(cpio, off + 94);
        let name = String::from_utf8(cpio[off + 110..off + 110 + namesize - 1].to_vec()).unwrap();
        let done = name == "TRAILER!!!";
        names.push(name);
        off = (off + 110 + namesize).div_ceil(4) * 4;
        off = (off + filesize).div_ceil(4) * 4;
        if done {
            return names;
        }
    }
}

fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(data))
}

/// Env selector pinning the overlay/initrd acquisition ladder to the
/// published-artifact mode, so a scenario running inside a source checkout
/// never takes the cross-compile branch. Kept in sync with the CLI's
/// `MVM_RUNTIME_OVERLAY_ACQUIRE_MODE`.
const ACQUIRE_MODE_ENV: &str = "MVM_RUNTIME_OVERLAY_ACQUIRE_MODE";

/// Isolate the whole mvm world for an in-process boot-policy scenario:
/// `MVM_HOME` *and* `HOME` move to `home` (a cold-cache scenario must not be
/// warmed by the developer's real default cache), and the acquisition mode
/// is pinned so no branch reaches for a toolchain.
fn isolated_boot_env(home: &Path) -> ScenarioEnvGuard {
    ScenarioEnvGuard::new(&[
        ("MVM_HOME", home.as_os_str()),
        ("HOME", home.as_os_str()),
        (ACQUIRE_MODE_ENV, OsStr::new("download")),
    ])
}

/// The workspace root the boot path's source-fingerprint freshness check
/// sees from this checkout, keyed on the same marker file it uses.
fn source_checkout_root() -> Option<PathBuf> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent()?.parent()?;
    root.join("nix")
        .join("images")
        .join("runtime-overlay")
        .join("flake.nix")
        .is_file()
        .then(|| root.to_path_buf())
}

/// Install a universal initramfs into `<mvm_home>/cache/initramfs` exactly
/// the way the real build/install path lays it out, including the source
/// fingerprint a source checkout records — without it the freshness check
/// would treat the artifact as stale and discard it.
fn seed_warm_universal_initramfs(mvm_home: &Path) {
    let version = env!("CARGO_PKG_VERSION");
    let arch = GuestArch::host();
    let source = mvm_home.join("universal-initramfs-source");
    let cache_root = mvm_home.join("cache").join("initramfs");
    mvm_build::initramfs::assemble_initramfs_artifact(b"bdd-static-guest-agent", version, &source)
        .expect("assemble the initramfs artifact");
    mvm_build::initramfs::install_initramfs_into_cache(&source, &cache_root, version, arch)
        .expect("install the initramfs into the cache");
    if let Some(root) = source_checkout_root() {
        let fingerprint =
            mvm_build::guest_agent_build::runtime_overlay_source_checkout_fingerprint(&root)
                .expect("fingerprint the source checkout");
        mvm_build::initramfs::record_source_fingerprint(&cache_root, version, arch, &fingerprint)
            .expect("record the initramfs source fingerprint");
    }
}

/// The scenario's sealed rootfs lives at a fixed spot inside its isolated
/// home so the Given that writes it and the When that boots it agree.
fn scenario_rootfs(mvm_home: &Path) -> PathBuf {
    mvm_home.join("vm").join("rootfs.ext4")
}

#[given("an isolated mvm home with a warm universal initramfs cache")]
fn isolated_home_warm_universal_initramfs(world: &mut CliWorld) {
    let tmp = tempfile::tempdir().expect("scenario mvm home");
    world.initramfs_boot_env = Some(isolated_boot_env(tmp.path()));
    seed_warm_universal_initramfs(tmp.path());
    world.isolated_home = Some(tmp);
}

#[given("an isolated mvm home with a cold universal initramfs cache")]
fn isolated_home_cold_universal_initramfs(world: &mut CliWorld) {
    let tmp = tempfile::tempdir().expect("scenario mvm home");
    world.initramfs_boot_env = Some(isolated_boot_env(tmp.path()));
    // Do not seed the cache: the resolver must not fall back to a legacy
    // per-rootfs initrd just because the universal initramfs is absent.
    world.isolated_home = Some(tmp);
}

#[given("a sealed OCI rootfs with no sibling initrd")]
fn sealed_oci_rootfs_without_sibling_initrd(world: &mut CliWorld) {
    let home = world
        .isolated_home
        .as_ref()
        .expect("a prior step must isolate the mvm home");
    let rootfs = scenario_rootfs(home.path());
    std::fs::create_dir_all(rootfs.parent().expect("the rootfs has a parent dir"))
        .expect("create the rootfs dir");
    std::fs::write(&rootfs, b"rootfs").expect("write the rootfs");
}

#[given("a sealed OCI rootfs with a sibling legacy initrd")]
fn sealed_oci_rootfs_with_sibling_legacy_initrd(world: &mut CliWorld) {
    let home = world
        .isolated_home
        .as_ref()
        .expect("a prior step must isolate the mvm home");
    let rootfs = scenario_rootfs(home.path());
    std::fs::create_dir_all(rootfs.parent().expect("the rootfs has a parent dir"))
        .expect("create the rootfs dir");
    std::fs::write(&rootfs, b"rootfs").expect("write the rootfs");
    let legacy_initrd = rootfs.with_extension("initrd");
    std::fs::write(&legacy_initrd, b"legacy initrd").expect("write the legacy sibling initrd");
}

#[when("the persistent OCI effective initrd is resolved for a required-overlay boot")]
fn resolve_persistent_oci_effective_initrd(world: &mut CliWorld) {
    let home = world
        .isolated_home
        .as_ref()
        .expect("a prior step must isolate the mvm home");
    let outcome = mvm_cli::boot_policy::persistent_oci_effective_initrd(
        &scenario_rootfs(home.path()),
        RuntimeSourcePolicy::RequiredOverlay,
    )
    .map_err(|e| format!("{e:#}"));
    world.initramfs_boot_initrd = Some(outcome);
}

#[then("the effective initrd is empty")]
fn effective_initrd_is_empty(world: &mut CliWorld) {
    let outcome = world
        .initramfs_boot_initrd
        .as_ref()
        .expect("a prior step must resolve the effective initrd");
    assert_eq!(
        outcome.as_ref().map(Option::as_deref),
        Ok(None),
        "a warm universal initramfs must skip the legacy initrd entirely: {outcome:?}"
    );
}

#[given("fixed guest-agent bytes for the initramfs build")]
fn fixed_agent_bytes(world: &mut CliWorld) {
    world.initramfs_agent_bytes = Some(b"bdd-static-guest-agent".to_vec());
}

#[when("I assemble the initramfs cpio twice from those bytes")]
fn assemble_twice(world: &mut CliWorld) {
    let bytes = world
        .initramfs_agent_bytes
        .as_ref()
        .expect("a prior step must fix the agent bytes");
    world.initramfs_cpio_a = Some(mvm_build::initramfs::initramfs_cpio(bytes));
    world.initramfs_cpio_b = Some(mvm_build::initramfs::initramfs_cpio(bytes));
}

#[then("the two cpios are byte-identical")]
fn cpios_identical(world: &mut CliWorld) {
    let (a, b) = (
        world.initramfs_cpio_a.as_ref().expect("first cpio"),
        world.initramfs_cpio_b.as_ref().expect("second cpio"),
    );
    assert_eq!(a, b, "the same agent bytes must produce the same cpio");
}

#[then("their content hashes match")]
fn hashes_match(world: &mut CliWorld) {
    let (a, b) = (
        world.initramfs_cpio_a.as_ref().expect("first cpio"),
        world.initramfs_cpio_b.as_ref().expect("second cpio"),
    );
    assert_eq!(sha256_hex(a), sha256_hex(b));
}

#[then(expr = "the cpio layout is exactly {string} and {string}")]
fn cpio_layout(world: &mut CliWorld, dir: String, init: String) {
    let a = world.initramfs_cpio_a.as_ref().expect("first cpio");
    assert_eq!(newc_names(a), vec![dir, init, "TRAILER!!!".to_string()]);
}

#[when("I assemble and install the initramfs artifact into a fresh cache")]
fn assemble_and_install(world: &mut CliWorld) {
    let bytes = world
        .initramfs_agent_bytes
        .as_ref()
        .expect("a prior step must fix the agent bytes");
    let tmp = tempfile::tempdir().expect("scenario cache root");
    let source = tmp.path().join("source");
    let cache_root = tmp.path().join("cache");
    let version = env!("CARGO_PKG_VERSION");
    mvm_build::initramfs::assemble_initramfs_artifact(bytes, version, &source)
        .expect("assemble the artifact");
    let artifact = mvm_build::initramfs::install_initramfs_into_cache(
        &source,
        &cache_root,
        version,
        GuestArch::Aarch64,
    )
    .expect("install into the cache");

    let dir = artifact
        .image_path
        .parent()
        .expect("the artifact dir has a parent")
        .to_path_buf();
    let read = |name: &str| {
        std::fs::read_to_string(dir.join(name))
            .expect("read sidecar")
            .trim()
            .to_string()
    };
    world.initramfs_sidecars = Some((
        read(mvm_fs::initramfs::INITRAMFS_HASH_FILE),
        read(mvm_fs::initramfs::INITRAMFS_SIZE_FILE),
        read(mvm_fs::initramfs::VERSION_FILE),
    ));

    // The resolver must accept the just-installed artifact — the install
    // path's own verification is the contract the boot path relies on.
    let resolved = InitramfsResolver::new(&cache_root, version)
        .resolve(&GuestArch::Aarch64.to_string())
        .expect("the artifact must resolve through the resolver");
    world.initramfs_resolved_image = Some(resolved.image_path);
    world.isolated_home = Some(tmp);
}

#[then("the artifact's hash sidecar is the SHA-256 of the uncompressed cpio")]
fn hash_sidecar_matches(world: &mut CliWorld) {
    let (hash, _, _) = world.initramfs_sidecars.as_ref().expect("sidecars");
    let image = world
        .initramfs_resolved_image
        .as_ref()
        .expect("resolved image");
    let compressed = std::fs::read(image).expect("read image");
    let mut uncompressed = Vec::new();
    std::io::Read::read_to_end(
        &mut flate2::read::GzDecoder::new(compressed.as_slice()),
        &mut uncompressed,
    )
    .expect("gunzip the image");
    assert_eq!(
        *hash,
        sha256_hex(&uncompressed),
        "the hash sidecar must cover the uncompressed cpio"
    );
}

#[then("the size sidecar is the compressed byte length")]
fn size_sidecar_matches(world: &mut CliWorld) {
    let (_, size, _) = world.initramfs_sidecars.as_ref().expect("sidecars");
    let image = world
        .initramfs_resolved_image
        .as_ref()
        .expect("resolved image");
    let compressed = std::fs::read(image).expect("read image");
    assert_eq!(
        size.parse::<usize>().expect("size sidecar is a number"),
        compressed.len(),
        "the size sidecar must cover the compressed file"
    );
}

#[then("the VERSION sidecar is the workspace version")]
fn version_sidecar_matches(world: &mut CliWorld) {
    let (_, _, version) = world.initramfs_sidecars.as_ref().expect("sidecars");
    assert_eq!(version, env!("CARGO_PKG_VERSION"));
}

#[then("the artifact resolves through the initramfs resolver")]
fn artifact_resolves(world: &mut CliWorld) {
    let image = world
        .initramfs_resolved_image
        .as_ref()
        .expect("resolved image");
    assert!(image.is_file(), "the resolved image must exist: {image:?}");
    assert!(
        image.ends_with(mvm_fs::initramfs::INITRAMFS_IMAGE_FILE),
        "the resolver must name the canonical image file: {image:?}"
    );
}
