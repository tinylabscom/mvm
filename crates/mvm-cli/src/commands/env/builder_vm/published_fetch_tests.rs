//! The published builder VM image fetch, run offline against a release served
//! from memory.
//!
//! The real source verifies the checksum manifest's signature before it hands
//! back a single pin; the fake models only the two outcomes that verification
//! can have — a pin map, or a refusal — so these tests pin down everything the
//! fetch does with them.

use super::stage0_cache::{
    BuilderVmArtifactNames, BuilderVmImageRelease, BuilderVmReleaseSource, fetch_builder_vm_image,
    fetched_builder_vm_image_line, validate_builder_vm_stage0_artifacts,
};
use super::*;
use mvm_core::util::test_env::TestEnv;
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::path::PathBuf;

const TAG: &str = "boot-image/v0.1.5";
const VERSION: &str = "0.1.5";
const BASE_URL: &str = "https://releases.invalid/download/boot-image/v0.1.5";

fn release() -> BuilderVmImageRelease<'static> {
    BuilderVmImageRelease {
        tag: TAG,
        version: VERSION,
        base_url: BASE_URL,
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn other_arch(arch: &str) -> &'static str {
    if arch == "aarch64" {
        "x86_64"
    } else {
        "aarch64"
    }
}

/// A release as the boot image workflow publishes it: four assets, and a
/// checksum manifest whose signature verification either yielded pins or
/// refused.
struct FakeRelease {
    arch: String,
    assets: HashMap<String, Vec<u8>>,
    checksums: Result<HashMap<String, String>, String>,
    checksum_requests: Cell<usize>,
    fetched: RefCell<Vec<String>>,
}

impl FakeRelease {
    /// A complete, self-consistent release for `arch`.
    fn published(arch: &str) -> Self {
        const EXT4_MAGIC_OFFSET: usize = 1024 + 56;
        let names = builder_vm_artifact_names(arch);
        let kernel = vec![0x7f; 1024 * 1024 + 1];
        let mut rootfs = vec![0u8; 4 * 1024 * 1024 + 1];
        rootfs[EXT4_MAGIC_OFFSET] = 0x53;
        rootfs[EXT4_MAGIC_OFFSET + 1] = 0xEF;
        let cmdline = b"console=hvc0 root=/dev/vda ro init=/sbin/mvm-host-vm-init\n".to_vec();

        let mut release = Self {
            arch: arch.to_string(),
            assets: HashMap::new(),
            checksums: Ok(HashMap::new()),
            checksum_requests: Cell::new(0),
            fetched: RefCell::new(Vec::new()),
        };
        release.publish(&names.kernel, kernel);
        release.publish(&names.rootfs, rootfs);
        release.publish(&names.cmdline, cmdline);
        let manifest = release.manifest_json();
        release.publish_manifest(manifest);
        release
    }

    fn names(&self) -> BuilderVmArtifactNames {
        builder_vm_artifact_names(&self.arch)
    }

    /// Publish `bytes` under `asset` with a matching signed pin.
    fn publish(&mut self, asset: &str, bytes: Vec<u8>) {
        if let Ok(pins) = &mut self.checksums {
            pins.insert(asset.to_string(), sha256_hex(&bytes));
        }
        self.assets.insert(asset.to_string(), bytes);
    }

    /// The manifest the producer writes, describing the published kernel and rootfs.
    fn manifest_json(&self) -> serde_json::Value {
        let names = self.names();
        let pin = |asset: &str| {
            let bytes = &self.assets[asset];
            serde_json::json!({ "sha256": sha256_hex(bytes), "size": bytes.len() })
        };
        serde_json::json!({
            "name": "mvm-builder-vm",
            "system": format!("{}-linux", self.arch),
            "vmlinux": pin(&names.kernel),
            "rootfs_ext4": pin(&names.rootfs),
            "cmdline": "console=hvc0",
            "cache_contract_version": 4,
            "runtime_overlay_ready": true,
            "vsock_egress_ready": true,
        })
    }

    /// Publish a manifest whose own signed pin matches, whatever it says.
    fn publish_manifest(&mut self, manifest: serde_json::Value) {
        let asset = self.names().manifest;
        self.publish(&asset, serde_json::to_vec(&manifest).unwrap());
    }

    /// Serve different bytes under `asset` while the signed pin stays put.
    fn tamper(mut self, asset: &str) -> Self {
        self.assets
            .get_mut(asset)
            .expect("tampering a published asset")[0] ^= 0xff;
        self
    }

    fn without(mut self, asset: &str) -> Self {
        self.assets.remove(asset);
        self
    }

    fn with_manifest(mut self, edit: impl FnOnce(&mut serde_json::Value)) -> Self {
        let mut manifest = self.manifest_json();
        edit(&mut manifest);
        self.publish_manifest(manifest);
        self
    }

    fn refusing_checksums(mut self, reason: &str) -> Self {
        self.checksums = Err(reason.to_string());
        self
    }

    fn requests(&self) -> usize {
        self.checksum_requests.get() + self.fetched.borrow().len()
    }
}

impl BuilderVmReleaseSource for FakeRelease {
    fn verified_checksums(
        &self,
        manifest: &ChecksumManifest<'_>,
        wanted: &[&str],
    ) -> Result<HashMap<String, String>> {
        self.checksum_requests.set(self.checksum_requests.get() + 1);
        assert_eq!(manifest.asset, self.names().checksums);
        assert_eq!(manifest.base_url, BASE_URL);
        assert_eq!(manifest.version, VERSION);
        assert_eq!(
            manifest.train,
            mvm_build::release_signature::ReleaseTrain::BootImage,
            "builder VM images are signed on the boot image train"
        );
        let names = self.names();
        for asset in [
            &names.kernel,
            &names.rootfs,
            &names.cmdline,
            &names.manifest,
        ] {
            assert!(wanted.contains(&asset.as_str()), "{asset} must be pinned");
        }
        self.checksums.clone().map_err(anyhow::Error::msg)
    }

    fn fetch(&self, url: &str, dest: &str) -> Result<()> {
        let asset = url
            .strip_prefix(&format!("{BASE_URL}/"))
            .unwrap_or_else(|| panic!("fetched outside the release: {url}"));
        self.fetched.borrow_mut().push(asset.to_string());
        let bytes = self
            .assets
            .get(asset)
            .ok_or_else(|| anyhow::anyhow!("HTTP 404 for {url}"))?;
        std::fs::write(dest, bytes)?;
        Ok(())
    }
}

/// An isolated `MVM_HOME` (the refusal paths write audit lines) and a cache
/// dir that does not exist yet.
struct Host {
    _env: TestEnv,
    _root: tempfile::TempDir,
    cache: PathBuf,
}

impl Host {
    fn new() -> Self {
        let mut env = TestEnv::new();
        env.remove("MVM_SKIP_HASH_VERIFY");
        env.remove("MVM_SKIP_COSIGN_VERIFY");
        let root = tempfile::tempdir().unwrap();
        env.isolate_mvm_home(root.path().join("home"));
        let cache = root.path().join("builder-vm").join(builder_vm_host_arch());
        Self {
            _env: env,
            _root: root,
            cache,
        }
    }

    /// A host whose cache already holds a previous image.
    fn with_existing_cache() -> Self {
        let host = Self::new();
        std::fs::create_dir_all(&host.cache).unwrap();
        std::fs::write(host.cache.join("vmlinux"), b"previous kernel").unwrap();
        std::fs::write(host.cache.join("previous-marker"), b"kept").unwrap();
        host
    }

    fn fetch(&self, source: &FakeRelease) -> Result<()> {
        fetch_builder_vm_image(source, &release(), &source.arch, &self.cache)
    }

    fn staging_dirs(&self) -> Vec<PathBuf> {
        let prefix = format!(".{}.stage0-", builder_vm_host_arch());
        std::fs::read_dir(self.cache.parent().unwrap())
            .map(|entries| {
                entries
                    .flatten()
                    .filter(|e| e.file_name().to_string_lossy().starts_with(&prefix))
                    .map(|e| e.path())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Nothing was promoted and nothing was left behind: a fresh host still
    /// has no cache, and a host with one still has exactly the old one.
    fn assert_unchanged(&self, existed: bool) {
        assert!(
            self.staging_dirs().is_empty(),
            "a refused fetch must remove its staging dir: {:?}",
            self.staging_dirs()
        );
        if existed {
            assert_eq!(
                std::fs::read(self.cache.join("vmlinux")).unwrap(),
                b"previous kernel"
            );
            assert!(self.cache.join("previous-marker").exists());
            assert!(!self.cache.join("rootfs.ext4").exists());
        } else {
            assert!(
                !self.cache.exists(),
                "a refused fetch must not create the cache dir"
            );
        }
    }
}

/// Run `source` against a fresh host and a host with a cache, expecting both
/// to refuse with a message containing `needle` and change nothing.
fn assert_refused_without_promotion(source: impl Fn() -> FakeRelease, needle: &str) {
    for existed in [false, true] {
        let host = if existed {
            Host::with_existing_cache()
        } else {
            Host::new()
        };
        let err = host.fetch(&source()).expect_err("the fetch must refuse");
        let chain = format!("{err:#}");
        assert!(
            chain.contains(needle),
            "the refusal must mention `{needle}`: {chain}"
        );
        host.assert_unchanged(existed);
    }
}

fn host_release() -> FakeRelease {
    FakeRelease::published(builder_vm_host_arch())
}

#[test]
fn a_verified_fetch_promotes_every_artifact_with_provenance_and_removes_staging() {
    let host = Host::new();
    let source = host_release();

    host.fetch(&source)
        .expect("a consistent signed release installs");

    let names = source.names();
    for (asset, file) in [
        (&names.kernel, "vmlinux"),
        (&names.rootfs, "rootfs.ext4"),
        (&names.cmdline, "cmdline.txt"),
        (&names.manifest, "manifest.json"),
    ] {
        assert_eq!(
            std::fs::read(host.cache.join(file)).unwrap(),
            source.assets[asset.as_str()],
            "{file} must hold the published {asset}"
        );
    }
    let provenance: serde_json::Value = serde_json::from_slice(
        &std::fs::read(host.cache.join(BUILDER_VM_PROVENANCE_FILE)).unwrap(),
    )
    .unwrap();
    assert_eq!(provenance["source_kind"], "fetched");
    assert_eq!(provenance["image_tag"], TAG);
    assert!(
        provenance.get("source_fingerprint").is_none(),
        "a fetched image has no source to fingerprint: {provenance}"
    );
    assert!(host.staging_dirs().is_empty(), "staging must be gone");
    validate_builder_vm_stage0_artifacts(&host.cache)
        .expect("the promoted cache must satisfy the bootstrap readiness check");
}

#[test]
fn a_verified_fetch_replaces_a_previous_cache_whole() {
    let host = Host::with_existing_cache();

    host.fetch(&host_release())
        .expect("a consistent signed release installs");

    assert!(
        !host.cache.join("previous-marker").exists(),
        "nothing from the previous cache may survive the swap"
    );
    assert!(host.staging_dirs().is_empty());
}

#[test]
fn a_kernel_digest_mismatch_refuses_and_promotes_nothing() {
    let kernel = host_release().names().kernel;
    assert_refused_without_promotion(|| host_release().tamper(&kernel), &kernel);
}

#[test]
fn a_rootfs_digest_mismatch_refuses_and_promotes_nothing() {
    let rootfs = host_release().names().rootfs;
    assert_refused_without_promotion(|| host_release().tamper(&rootfs), &rootfs);
}

#[test]
fn a_missing_asset_refuses_names_it_and_promotes_nothing() {
    let names = host_release().names();
    for asset in [names.kernel, names.rootfs, names.cmdline, names.manifest] {
        assert_refused_without_promotion(|| host_release().without(&asset), &asset);
    }
}

#[test]
fn a_checksum_manifest_refusal_stops_before_any_artifact_is_fetched() {
    for reason in [
        "no signature bundle beside the checksum manifest",
        "signed by an identity outside the boot image release set",
    ] {
        let host = Host::new();
        let source = host_release().refusing_checksums(reason);

        let err = host
            .fetch(&source)
            .expect_err("an unverified manifest refuses");

        assert!(format!("{err:#}").contains(reason), "{err:#}");
        assert!(
            source.fetched.borrow().is_empty(),
            "no artifact may be fetched under an unverified manifest: {:?}",
            source.fetched.borrow()
        );
        host.assert_unchanged(false);
    }
}

#[test]
fn a_manifest_built_for_another_architecture_is_refused() {
    let arch = builder_vm_host_arch();
    let foreign = format!("{}-linux", other_arch(arch));
    let build = || {
        host_release().with_manifest(|m| {
            m["system"] = serde_json::json!(format!("{}-linux", other_arch(arch)))
        })
    };

    assert_refused_without_promotion(build, &foreign);
    let err = Host::new().fetch(&build()).unwrap_err();
    assert!(
        format!("{err:#}").contains(&format!("{arch}-linux")),
        "the refusal must name the expected system too: {err:#}"
    );
}

#[test]
fn a_manifest_whose_pins_disagree_with_the_signed_checksums_is_refused() {
    let forged = "f".repeat(64);
    for field in ["vmlinux", "rootfs_ext4"] {
        let signed = host_release().manifest_json()[field]["sha256"]
            .as_str()
            .unwrap()
            .to_string();
        let build =
            || host_release().with_manifest(|m| m[field]["sha256"] = serde_json::json!(forged));
        assert_refused_without_promotion(build, &forged);
        let err = format!("{:#}", Host::new().fetch(&build()).unwrap_err());
        assert!(
            err.contains(&signed) && err.contains(field),
            "the refusal must name the field and the signed digest: {err}"
        );

        let build = || host_release().with_manifest(|m| m[field]["size"] = serde_json::json!(7));
        assert_refused_without_promotion(build, &format!("{field}.size"));
    }
}

#[test]
fn a_non_host_architecture_is_refused_before_any_network_request() {
    let host = Host::new();
    let foreign = other_arch(builder_vm_host_arch());
    let source = FakeRelease::published(foreign);

    let err = fetch_builder_vm_image(&source, &release(), foreign, &host.cache)
        .expect_err("a foreign-arch builder image refuses");

    let err = format!("{err:#}");
    assert!(
        err.contains(foreign) && err.contains(builder_vm_host_arch()),
        "{err}"
    );
    assert_eq!(
        source.requests(),
        0,
        "no request may precede the arch check"
    );
    host.assert_unchanged(false);
}

#[test]
fn the_provenance_line_is_stable_and_admits_a_waived_check() {
    assert_eq!(
        fetched_builder_vm_image_line(TAG, &[]),
        "Builder VM image source: fetched (boot-image/v0.1.5), signature and digests verified"
    );
    let waived = fetched_builder_vm_image_line(TAG, &["MVM_SKIP_COSIGN_VERIFY"]);
    assert!(
        waived.starts_with("Builder VM image source: fetched (boot-image/v0.1.5)")
            && waived.contains("MVM_SKIP_COSIGN_VERIFY")
            && !waived.contains("signature and digests verified"),
        "a waived check must not be reported as verified: {waived}"
    );
}
