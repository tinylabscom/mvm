//! Release-time gate for the boot image assets a CLI release republishes.
//!
//! Images are built and signed in `mvm-images`. A CLI release still carries
//! them under their historical names, because an installed `mvmctl` fetches
//! the runtime overlay and SDK sidecar from its own `v{version}` release and
//! verifies them under this repository's release identity. The release job
//! therefore re-signs bytes it did not build, and this gate is what makes that
//! safe: nothing is republished unless it is byte-for-byte what the signed
//! image-set root pinned by the compiled lock declares, or is anchored by a
//! checksum manifest that itself agrees with that root.
//!
//! The root's signature is checked by the CLI being released
//! (`mvmctl image boot verify`), which carries the sigstore stack this crate
//! deliberately does not. This gate starts from the root's pinned digest, so
//! the manifest it parses is the manifest that verification accepted.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};
use mvm_core::image_set::{ImageLock, ImageSetManifest};
use mvm_core::packs::Sha256Hex;

const ARCHITECTURES: [&str; 2] = ["aarch64", "x86_64"];
const SDK_LIBCS: [&str; 2] = ["glibc", "musl"];

pub(crate) fn run(args: &[String]) -> Result<()> {
    let lock = &mvm_core::image_set::image_train_lock().image_set;
    match args.first().map(String::as_str) {
        Some("tag") if args.len() == 1 => {
            println!("{}", mvm_core::config::default_boot_image_tag());
            Ok(())
        }
        Some("mirror-assets") if args.len() == 1 => {
            for asset in mirror_assets() {
                println!("{asset}");
            }
            Ok(())
        }
        Some("validate") if args.len() == 3 => {
            validate_release(lock, &args[1], Path::new(&args[2]))
        }
        _ => bail!(
            "usage: release-boot-image tag | release-boot-image mirror-assets | release-boot-image validate <tag> <mirror-dir>"
        ),
    }
}

/// Refuse the mirror unless every file in `dir` is accounted for by the signed
/// root `lock` pins.
fn validate_release(lock: &ImageLock, tag: &str, dir: &Path) -> Result<()> {
    let expected = lock.release_tag.as_str();
    if tag != expected {
        bail!(
            "release selected boot image tag {tag:?}, but the CLI embeds {expected:?}; refusing to validate different bytes"
        );
    }
    require_complete(tag, dir)?;
    let root = read_pinned_root(lock, dir)?;
    MirrorGate::new(&root, lock.manifest_asset.as_str(), dir).check()
}

fn require_complete(tag: &str, dir: &Path) -> Result<()> {
    let missing = required_assets()
        .into_iter()
        .filter(|name| !is_nonempty_file(&dir.join(name)))
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        bail!(
            "{tag} is incomplete; refusing to ship a CLI release whose boot image would fail on first boot. Missing: {}",
            missing.join(" ")
        );
    }
    Ok(())
}

/// The root manifest, parsed only after its bytes hash to the lock's pin.
fn read_pinned_root(lock: &ImageLock, dir: &Path) -> Result<ImageSetManifest> {
    let name = lock.manifest_asset.as_str();
    let bytes = fs::read(dir.join(name))
        .with_context(|| format!("cannot read the image-set root {name} from the mirror"))?;
    let actual = Sha256Hex::from_bytes(&bytes);
    if actual != lock.manifest_sha256 {
        bail!(
            "image-set root {name} hashes to {}, not the locked {}; refusing to mirror a set the CLI would not accept",
            actual.as_str(),
            lock.manifest_sha256.as_str()
        );
    }
    serde_json::from_slice(&bytes).with_context(|| format!("{name} is not an image-set manifest"))
}

fn is_nonempty_file(path: &Path) -> bool {
    fs::metadata(path).is_ok_and(|metadata| metadata.is_file() && metadata.len() > 0)
}

/// What an installed CLI resolves off a release and cannot boot without.
fn required_assets() -> Vec<String> {
    let mut assets = Vec::new();
    for arch in ARCHITECTURES {
        assets.extend([
            format!("default-microvm-vmlinux-{arch}"),
            format!("default-microvm-rootfs-{arch}.ext4"),
            format!("default-microvm-meta-{arch}.json"),
            format!("default-microvm-{arch}-checksums-sha256.txt"),
            format!("builder-vm-vmlinux-{arch}"),
            format!("builder-vm-rootfs-{arch}.ext4"),
            format!("builder-vm-{arch}-checksums-sha256.txt"),
            format!("runtime-overlay-{arch}.tar.gz"),
        ]);
        for libc in SDK_LIBCS {
            assets.extend([
                format!("sdk-sidecar-{arch}-{libc}.tar.gz"),
                format!("sdk-sidecar-{arch}-{libc}.tar.gz.sha256"),
            ]);
        }
    }
    assets
}

/// Every asset the release republishes, under the name it has always had.
///
/// The required set plus the files that complete it: verity sidecars, the
/// builder's boot metadata, and each archive's checksum. Only files the gate
/// can anchor are listed; the default image's free-text SBOM is anchored by
/// nothing the root signs, so it is not republished under this repository's
/// signature.
fn mirror_assets() -> Vec<String> {
    let mut assets = required_assets();
    for arch in ARCHITECTURES {
        assets.extend([
            format!("default-microvm-rootfs-{arch}.verity"),
            format!("default-microvm-rootfs-{arch}.roothash"),
            format!("builder-vm-{arch}.cmdline.txt"),
            format!("builder-vm-{arch}.manifest.json"),
            format!("builder-vm-{arch}.sbom.txt"),
            format!("runtime-overlay-{arch}.tar.gz.sha256"),
        ]);
    }
    assets.extend([
        "qemu-wasm-smoke-pack.tar.gz".to_string(),
        "qemu-wasm-smoke-pack.tar.gz.sha256".to_string(),
    ]);
    assets.sort();
    assets
}

/// Names that must be member artifacts of the root, not merely files beside
/// it: these are the bytes a CLI boots or executes, so their digest has to come
/// from the signed root and from nowhere weaker.
fn legacy_member_assets() -> Vec<String> {
    let mut assets = Vec::new();
    for arch in ARCHITECTURES {
        assets.extend([
            format!("default-microvm-vmlinux-{arch}"),
            format!("default-microvm-rootfs-{arch}.ext4"),
            format!("builder-vm-vmlinux-{arch}"),
            format!("builder-vm-rootfs-{arch}.ext4"),
            format!("runtime-overlay-{arch}.tar.gz"),
        ]);
        for libc in SDK_LIBCS {
            assets.push(format!("sdk-sidecar-{arch}-{libc}.tar.gz"));
        }
    }
    assets
}

/// One member artifact as the signed root declares it.
struct Declared {
    sha256: String,
    size: u64,
}

struct MirrorGate<'a> {
    dir: &'a Path,
    manifest_asset: &'a str,
    members: BTreeMap<String, Declared>,
}

impl<'a> MirrorGate<'a> {
    fn new(root: &ImageSetManifest, manifest_asset: &'a str, dir: &'a Path) -> Self {
        let members = root
            .members
            .iter()
            .flat_map(|member| &member.artifacts)
            .map(|artifact| {
                let declared = Declared {
                    sha256: artifact.sha256.as_str().to_string(),
                    size: artifact.size,
                };
                (artifact.name.as_str().to_string(), declared)
            })
            .collect();
        Self {
            dir,
            manifest_asset,
            members,
        }
    }

    fn check(&self) -> Result<()> {
        self.require_coverage()?;
        let files = self.files()?;
        let mut anchored = BTreeSet::new();
        for name in &files {
            if let Some(declared) = self.members.get(name) {
                self.check_member(name, declared)?;
                anchored.insert(name.clone());
            }
        }
        for name in files.iter().filter(|name| is_checksum_manifest(name)) {
            anchored.extend(self.check_checksum_manifest(name)?);
            anchored.insert(name.clone());
        }
        for name in files.iter().filter(|name| name.ends_with(".sha256")) {
            self.check_sidecar(name)?;
            anchored.insert(name.clone());
        }
        let unanchored = files
            .iter()
            .filter(|name| !anchored.contains(*name) && !self.is_root_file(name))
            .cloned()
            .collect::<Vec<_>>();
        if !unanchored.is_empty() {
            bail!(
                "refusing to republish files no signed root or checksum manifest accounts for: {}",
                unanchored.join(" ")
            );
        }
        Ok(())
    }

    fn require_coverage(&self) -> Result<()> {
        let uncovered = legacy_member_assets()
            .into_iter()
            .filter(|name| !self.members.contains_key(name))
            .collect::<Vec<_>>();
        if !uncovered.is_empty() {
            bail!(
                "the signed root does not declare {} as member artifacts; the legacy release names cannot be mirrored from it",
                uncovered.join(" ")
            );
        }
        Ok(())
    }

    fn files(&self) -> Result<BTreeSet<String>> {
        let mut names = BTreeSet::new();
        let entries = fs::read_dir(self.dir)
            .with_context(|| format!("cannot list mirror directory {}", self.dir.display()))?;
        for entry in entries {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                bail!(
                    "mirror directory holds {}, which is not a regular file",
                    entry.path().display()
                );
            }
            names.insert(entry.file_name().to_string_lossy().into_owned());
        }
        Ok(names)
    }

    /// The root and its signature bundle are inputs to the gate, not mirrored
    /// assets; the workflow removes them before anything is attached.
    fn is_root_file(&self, name: &str) -> bool {
        name == self.manifest_asset
            || name
                .strip_suffix(".bundle")
                .is_some_and(|stem| stem == self.manifest_asset)
    }

    fn check_member(&self, name: &str, declared: &Declared) -> Result<()> {
        let size = fs::metadata(self.dir.join(name))?.len();
        if size != declared.size {
            bail!(
                "{name} is {size} bytes, but the signed root declares {}",
                declared.size
            );
        }
        let actual = self.digest(name)?;
        if actual != declared.sha256 {
            bail!(
                "{name} hashes to {actual}, but the signed root declares {}",
                declared.sha256
            );
        }
        Ok(())
    }

    /// Every line names a present file with that digest, and a line naming a
    /// member agrees with the root. Returns the names the manifest anchors.
    fn check_checksum_manifest(&self, manifest: &str) -> Result<Vec<String>> {
        let body = fs::read_to_string(self.dir.join(manifest))
            .with_context(|| format!("{manifest} is not UTF-8 text"))?;
        let entries = mvm_fs::overlay::parse_checksums_manifest(&body);
        let lines = body.lines().filter(|line| !line.trim().is_empty()).count();
        if entries.is_empty() || entries.len() != lines {
            bail!("{manifest} carries lines that are not `<sha256>  <name>` entries");
        }
        let mut anchored = Vec::with_capacity(entries.len());
        for (name, listed) in entries {
            if let Some(declared) = self.members.get(&name)
                && listed != declared.sha256
            {
                bail!(
                    "{manifest} lists {name} as {listed}, but the signed root declares {}",
                    declared.sha256
                );
            }
            if !self.dir.join(&name).is_file() {
                bail!("{manifest} lists {name}, which the mirror does not carry");
            }
            let actual = self.digest(&name)?;
            if actual != listed {
                bail!("{name} hashes to {actual}, but {manifest} lists {listed}");
            }
            anchored.push(name);
        }
        Ok(anchored)
    }

    /// A `<archive>.sha256` must name exactly its archive and agree with the
    /// root's digest for it.
    fn check_sidecar(&self, sidecar: &str) -> Result<()> {
        let archive = sidecar.trim_end_matches(".sha256");
        let body = fs::read_to_string(self.dir.join(sidecar))
            .with_context(|| format!("{sidecar} is not UTF-8 text"))?;
        let entries = mvm_fs::overlay::parse_checksums_manifest(&body);
        let Some(listed) = entries.get(archive).filter(|_| entries.len() == 1) else {
            bail!("{sidecar} must hold exactly one entry, for {archive}");
        };
        let Some(declared) = self.members.get(archive) else {
            bail!("{sidecar} checks {archive}, which the signed root does not declare");
        };
        if listed != &declared.sha256 {
            bail!(
                "{sidecar} lists {listed}, but the signed root declares {} for {archive}",
                declared.sha256
            );
        }
        Ok(())
    }

    fn digest(&self, name: &str) -> Result<String> {
        mvm_core::crypto::image_verify::sha256_file(&self.dir.join(name))
            .with_context(|| format!("cannot hash {name}"))
    }
}

fn is_checksum_manifest(name: &str) -> bool {
    name.ends_with("-checksums-sha256.txt")
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::image_set::image_train_lock;
    use serde_json::json;

    /// A mirror directory built the way the release job builds one: every
    /// mirrored asset, a root declaring the member bytes, and a lock pinning
    /// that root.
    struct Mirror {
        dir: tempfile::TempDir,
        lock: ImageLock,
    }

    fn contents(name: &str) -> Vec<u8> {
        format!("bytes of {name}").into_bytes()
    }

    fn sha(bytes: &[u8]) -> String {
        Sha256Hex::from_bytes(bytes).as_str().to_string()
    }

    fn checksum_line(name: &str, bytes: &[u8]) -> String {
        format!("{}  {name}\n", sha(bytes))
    }

    impl Mirror {
        fn complete() -> Self {
            let members = legacy_member_assets()
                .into_iter()
                .chain([
                    "qemu-wasm-smoke-pack.tar.gz".to_string(),
                    "default-microvm-rootfs-x86_64.verity".to_string(),
                    "default-microvm-rootfs-x86_64.roothash".to_string(),
                    "default-microvm-rootfs-aarch64.verity".to_string(),
                    "default-microvm-rootfs-aarch64.roothash".to_string(),
                ])
                .collect::<Vec<_>>();
            Self::with_members(&members)
        }

        fn with_members(members: &[String]) -> Self {
            let dir = tempfile::tempdir().expect("create mirror fixture");
            for asset in mirror_assets() {
                if is_checksum_manifest(&asset) || asset.ends_with(".sha256") {
                    continue;
                }
                fs::write(dir.path().join(&asset), contents(&asset)).expect("write asset");
            }
            for asset in mirror_assets().iter().filter(|a| a.ends_with(".sha256")) {
                let archive = asset.trim_end_matches(".sha256");
                fs::write(
                    dir.path().join(asset),
                    checksum_line(archive, &contents(archive)),
                )
                .expect("write sidecar");
            }
            for arch in ARCHITECTURES {
                let builder = [
                    format!("builder-vm-vmlinux-{arch}"),
                    format!("builder-vm-rootfs-{arch}.ext4"),
                    format!("builder-vm-{arch}.cmdline.txt"),
                    format!("builder-vm-{arch}.manifest.json"),
                    format!("builder-vm-{arch}.sbom.txt"),
                ];
                let default = [
                    format!("default-microvm-vmlinux-{arch}"),
                    format!("default-microvm-rootfs-{arch}.ext4"),
                    format!("default-microvm-rootfs-{arch}.verity"),
                    format!("default-microvm-rootfs-{arch}.roothash"),
                    format!("default-microvm-meta-{arch}.json"),
                ];
                for (manifest, names) in [
                    (format!("builder-vm-{arch}-checksums-sha256.txt"), &builder),
                    (
                        format!("default-microvm-{arch}-checksums-sha256.txt"),
                        &default,
                    ),
                ] {
                    let body: String = names
                        .iter()
                        .map(|name| checksum_line(name, &contents(name)))
                        .collect();
                    fs::write(dir.path().join(manifest), body).expect("write checksums");
                }
            }
            let root = root_declaring(members);
            let root_bytes = serde_json::to_vec_pretty(&root).expect("serialize root");
            let mut lock = image_train_lock().image_set.clone();
            lock.manifest_sha256 = Sha256Hex::from_bytes(&root_bytes);
            fs::write(dir.path().join(lock.manifest_asset.as_str()), &root_bytes)
                .expect("write root");
            fs::write(
                dir.path().join(format!("{}.bundle", lock.manifest_asset)),
                b"bundle",
            )
            .expect("write bundle");
            Self { dir, lock }
        }

        fn path(&self, name: &str) -> std::path::PathBuf {
            self.dir.path().join(name)
        }

        fn validate(&self) -> Result<()> {
            validate_release(&self.lock, self.lock.release_tag.as_str(), self.dir.path())
        }

        fn refused(&self) -> String {
            format!(
                "{:#}",
                self.validate().expect_err("the mirror must be refused")
            )
        }
    }

    /// A release root in the published shape, one member per artifact.
    fn root_declaring(names: &[String]) -> serde_json::Value {
        let members = names
            .iter()
            .map(|name| {
                let bytes = contents(name);
                json!({
                    "role": "runtime_overlay",
                    "target": {"arch": "x86_64"},
                    "artifacts": [{
                        "name": name,
                        "format": "ext4",
                        "sha256": sha(&bytes),
                        "size": bytes.len(),
                    }],
                    "required_capabilities": [],
                    "pack_hash": sha(&bytes),
                })
            })
            .collect::<Vec<_>>();
        let tag = image_train_lock().image_set.release_tag.as_str();
        json!({
            "schema_version": 2,
            "set_version": tag.trim_start_matches("image-set/v"),
            "issued_at": "2026-09-23T00:01:56Z",
            "producer": {
                "repository": "tinylabscom/mvm-images",
                "workflow": ".github/workflows/release.yml",
                "release_tag": tag,
                "source_commit": "1b08fbc104d0a3e0ac9dd9d74ec5db3c38ff3f38"
            },
            "mvm_source_commit": "fa6d5c1b271382684f9387eed61850c299e1ade5",
            "compatibility": {"guest_agent_protocol": {"min": 2, "max": 2}, "builder_cache_contract": 4},
            "nix_inputs": {"flake_locks": [], "source_revisions": []},
            "members": members,
        })
    }

    #[test]
    fn a_mirror_equal_to_the_signed_root_is_accepted() {
        Mirror::complete()
            .validate()
            .expect("a mirror whose bytes match the root must validate");
    }

    #[test]
    fn a_tampered_member_is_refused() {
        let mirror = Mirror::complete();
        let name = "builder-vm-rootfs-x86_64.ext4";
        // Same length, different bytes: only the digest can catch it.
        let mut bytes = contents(name);
        bytes[0] ^= 0xff;
        fs::write(mirror.path(name), bytes).unwrap();

        let error = mirror.refused();

        assert!(
            error.contains(name) && error.contains("signed root declares"),
            "the refusal must name the tampered member: {error}"
        );
    }

    #[test]
    fn a_member_of_the_wrong_size_is_refused() {
        let mirror = Mirror::complete();
        let name = "default-microvm-vmlinux-aarch64";
        let mut bytes = contents(name);
        bytes.push(b'!');
        fs::write(mirror.path(name), bytes).unwrap();

        let error = mirror.refused();

        assert!(
            error.contains(name) && error.contains("bytes, but the signed root declares"),
            "the refusal must name the size mismatch: {error}"
        );
    }

    #[test]
    fn a_missing_required_asset_is_refused() {
        let mirror = Mirror::complete();
        let missing = "sdk-sidecar-x86_64-musl.tar.gz.sha256";
        fs::remove_file(mirror.path(missing)).unwrap();

        let error = mirror.refused();

        assert!(
            error.contains("Missing:") && error.contains(missing),
            "the refusal must name the missing asset: {error}"
        );
    }

    #[test]
    fn an_empty_required_asset_is_refused_as_missing() {
        let mirror = Mirror::complete();
        let empty = "runtime-overlay-aarch64.tar.gz";
        fs::write(mirror.path(empty), b"").unwrap();

        let error = mirror.refused();

        assert!(error.contains(empty), "got: {error}");
    }

    #[test]
    fn a_root_that_does_not_cover_the_legacy_names_is_refused() {
        let members = legacy_member_assets()
            .into_iter()
            .filter(|name| name != "default-microvm-rootfs-x86_64.ext4")
            .collect::<Vec<_>>();
        let mirror = Mirror::with_members(&members);

        let error = mirror.refused();

        assert!(
            error.contains("does not declare default-microvm-rootfs-x86_64.ext4"),
            "the refusal must name the uncovered legacy asset: {error}"
        );
    }

    #[test]
    fn a_root_the_lock_does_not_pin_is_refused_before_it_is_parsed() {
        let mirror = Mirror::complete();
        fs::write(mirror.path(mirror.lock.manifest_asset.as_str()), b"{}").unwrap();

        let error = mirror.refused();

        assert!(error.contains("not the locked"), "got: {error}");
    }

    #[test]
    fn a_checksum_manifest_disagreeing_with_the_root_is_refused() {
        let mirror = Mirror::complete();
        let manifest = "builder-vm-aarch64-checksums-sha256.txt";
        let member = "builder-vm-vmlinux-aarch64";
        // The file and the manifest agree with each other and not with the
        // root — the case a self-consistent substitution produces.
        fs::write(mirror.path(member), b"substituted").unwrap();
        let body = fs::read_to_string(mirror.path(manifest))
            .unwrap()
            .replace(&sha(&contents(member)), &sha(b"substituted"));
        fs::write(mirror.path(manifest), body).unwrap();

        let error = mirror.refused();

        assert!(error.contains(member), "got: {error}");
    }

    #[test]
    fn an_auxiliary_file_that_drifts_from_its_checksum_manifest_is_refused() {
        let mirror = Mirror::complete();
        let name = "default-microvm-meta-x86_64.json";
        fs::write(mirror.path(name), b"{\"edited\":true}").unwrap();

        let error = mirror.refused();

        assert!(
            error.contains(name) && error.contains("default-microvm-x86_64-checksums-sha256.txt"),
            "got: {error}"
        );
    }

    #[test]
    fn a_sidecar_disagreeing_with_the_root_is_refused() {
        let mirror = Mirror::complete();
        let sidecar = "runtime-overlay-x86_64.tar.gz.sha256";
        fs::write(
            mirror.path(sidecar),
            checksum_line("runtime-overlay-x86_64.tar.gz", b"other"),
        )
        .unwrap();

        let error = mirror.refused();

        assert!(error.contains(sidecar), "got: {error}");
    }

    #[test]
    fn an_unanchored_file_is_not_republished() {
        let mirror = Mirror::complete();
        fs::write(mirror.path("default-microvm-x86_64.sbom.txt"), b"sbom").unwrap();

        let error = mirror.refused();

        assert!(
            error.contains("default-microvm-x86_64.sbom.txt"),
            "got: {error}"
        );
    }

    #[test]
    fn a_tag_that_diverges_from_the_compiled_pin_is_refused() {
        let mirror = Mirror::complete();

        let error = validate_release(&mirror.lock, "boot-image/v999.0.0", mirror.dir.path())
            .expect_err("a different tag must fail closed");

        assert!(
            format!("{error:#}").contains("refusing to validate different bytes"),
            "unexpected error: {error:#}"
        );
    }

    #[test]
    fn the_mirror_list_covers_both_architectures_and_every_required_asset() {
        let assets = mirror_assets();
        for required in required_assets() {
            assert!(assets.contains(&required), "{required} must be mirrored");
        }
        for arch in ARCHITECTURES {
            for libc in SDK_LIBCS {
                let needle = format!("sdk-sidecar-{arch}-{libc}.tar.gz");
                assert!(assets.contains(&needle), "the list must include {needle}");
            }
        }
        assert_eq!(
            required_assets().len(),
            24,
            "the required matrix must stay exhaustive"
        );
    }
}
