//! The builder boot payload: a deterministic newc initramfs carrying mvm's own
//! builder binaries, assembled on the host and verified again in the guest.
//!
//! The host builds it from the extracted payload directory, checking each
//! member against the SHA-256 `mvmctl` was compiled with. The guest's stage 1
//! recomputes the digest of the unpacked `MANIFEST`, compares it with the one
//! on the kernel command line, and checks every member against the manifest
//! before it copies anything out of the initramfs. Both halves live here so
//! the format has one reader and one writer.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use thiserror::Error;

use super::{PAYLOAD_DIR_IN_INITRAMFS, PAYLOAD_MANIFEST_NAME, STAGE1_MEMBER};
use crate::host_payload_manifest::host_binary_names;
use crate::rootfs_inject::{CpioEntry, build_newc_cpio};

/// Mode of every payload binary, in the initramfs and in the guest's tmpfs
/// copy. Nothing in the guest has a reason to modify them.
const MEMBER_MODE: u32 = 0o555;
const MANIFEST_MODE: u32 = 0o444;

/// Why a payload could not be assembled, verified or installed.
#[derive(Debug, Error)]
pub enum BootPayloadError {
    #[error("builder boot payload: no host binary directory was given")]
    NoHostBinDir,
    #[error("builder boot payload: {name} is missing from {}", .dir.display())]
    MissingMember { name: String, dir: PathBuf },
    #[error(
        "builder boot payload: {name} does not match the digest this mvmctl was built with \
         (expected {expected}, found {actual})"
    )]
    MemberDigestMismatch {
        name: String,
        expected: String,
        actual: String,
    },
    #[error(
        "builder boot payload: its MANIFEST digest is {actual}, but the kernel command line \
         names {expected}"
    )]
    ManifestDigestMismatch { expected: String, actual: String },
    #[error("builder boot payload: malformed MANIFEST line {line:?}")]
    MalformedManifest { line: String },
    #[error("builder boot payload: MANIFEST does not list {STAGE1_MEMBER}")]
    NoStage1Member,
    #[error("builder boot payload: {0:?} is not a 64-character lowercase SHA-256")]
    InvalidDigest(String),
    #[error("builder boot payload: {op} {}: {source}", .path.display())]
    Io {
        op: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

fn io_error(op: &'static str, path: &Path) -> impl FnOnce(std::io::Error) -> BootPayloadError {
    let path = path.to_path_buf();
    move |source| BootPayloadError::Io { op, path, source }
}

fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// The payload's identity: the SHA-256 of its `MANIFEST`.
///
/// The manifest names every member with its SHA-256, so this pins every byte
/// the guest will execute, and the guest can recompute it from the unpacked
/// files — which a digest over the archive bytes would not allow once the
/// kernel has unpacked and discarded the archive.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PayloadDigest(String);

impl PayloadDigest {
    /// Parse a digest from its lowercase hex form.
    pub fn parse(hex: &str) -> Result<Self, BootPayloadError> {
        if is_sha256_hex(hex) {
            Ok(Self(hex.to_string()))
        } else {
            Err(BootPayloadError::InvalidDigest(hex.to_string()))
        }
    }

    fn of(bytes: &[u8]) -> Self {
        Self(sha256_hex(bytes))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PayloadDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The `MANIFEST` file: `"<name> <sha256>\n"` per member, sorted by name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayloadManifest {
    members: BTreeMap<String, String>,
}

impl PayloadManifest {
    /// Parse a manifest, refusing anything [`render`](Self::render) would not
    /// have produced byte for byte. The digest is taken over the bytes, so a
    /// lenient parse would let two texts with one meaning carry two digests.
    pub fn parse(text: &str) -> Result<Self, BootPayloadError> {
        let mut members = BTreeMap::new();
        for line in text.lines() {
            let malformed = || BootPayloadError::MalformedManifest {
                line: line.to_string(),
            };
            let (name, sha) = line.split_once(' ').ok_or_else(malformed)?;
            if !is_member_name(name) || !is_sha256_hex(sha) {
                return Err(malformed());
            }
            members.insert(name.to_string(), sha.to_string());
        }
        let manifest = Self { members };
        if manifest.render() != text {
            return Err(BootPayloadError::MalformedManifest {
                line: text.to_string(),
            });
        }
        if !manifest.members.contains_key(STAGE1_MEMBER) {
            return Err(BootPayloadError::NoStage1Member);
        }
        Ok(manifest)
    }

    pub fn render(&self) -> String {
        self.members
            .iter()
            .map(|(name, sha)| format!("{name} {sha}\n"))
            .collect()
    }

    pub fn digest(&self) -> PayloadDigest {
        PayloadDigest::of(self.render().as_bytes())
    }

    /// `(name, sha256)` per member, sorted by name.
    pub fn members(&self) -> impl Iterator<Item = (&str, &str)> {
        self.members.iter().map(|(n, s)| (n.as_str(), s.as_str()))
    }
}

/// A plain file name: what the manifest may name, so a hostile or corrupted
/// manifest cannot direct a copy outside the payload directory.
fn is_member_name(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && name != PAYLOAD_MANIFEST_NAME
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
}

/// An assembled payload: the initramfs bytes and their digest.
#[derive(Debug, Clone)]
pub struct BuilderBootPayload {
    cpio: Vec<u8>,
    manifest: PayloadManifest,
}

impl BuilderBootPayload {
    pub fn builder() -> BuilderBootPayloadBuilder {
        BuilderBootPayloadBuilder::default()
    }

    /// The newc archive the VMM loads as the guest's initramfs.
    pub fn cpio(&self) -> &[u8] {
        &self.cpio
    }

    pub fn manifest(&self) -> &PayloadManifest {
        &self.manifest
    }

    /// The digest that travels on the kernel command line.
    pub fn digest(&self) -> PayloadDigest {
        self.manifest.digest()
    }

    /// Write the archive to `path`, readable by its owner only. The payload
    /// goes into the booting VM's own state directory, never a shared cache.
    pub fn write_to(&self, path: &Path) -> Result<(), BootPayloadError> {
        use std::io::Write;
        #[cfg(unix)]
        use std::os::unix::fs::OpenOptionsExt;

        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options
            .open(path)
            .map_err(io_error("creating the payload file", path))?;
        file.write_all(&self.cpio)
            .and_then(|()| file.sync_all())
            .map_err(io_error("writing the payload file", path))
    }
}

/// Assembles a [`BuilderBootPayload`] from an extracted payload directory.
#[derive(Debug, Default)]
pub struct BuilderBootPayloadBuilder {
    host_bin_dir: Option<PathBuf>,
    expected: BTreeMap<String, String>,
}

impl BuilderBootPayloadBuilder {
    /// The directory the embedded payload was extracted to. Only the builder
    /// binaries are read from it; the seed and support binaries beside them
    /// never reach a builder guest.
    pub fn host_bin_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.host_bin_dir = Some(dir.into());
        self
    }

    /// The SHA-256 `name` must have. A member whose bytes differ is refused
    /// rather than shipped; names that are not payload members are ignored.
    pub fn expected_sha256(
        mut self,
        name: impl Into<String>,
        sha256_hex: impl Into<String>,
    ) -> Self {
        self.expected.insert(name.into(), sha256_hex.into());
        self
    }

    pub fn build(self) -> Result<BuilderBootPayload, BootPayloadError> {
        let dir = self.host_bin_dir.ok_or(BootPayloadError::NoHostBinDir)?;
        let mut members = BTreeMap::new();
        for name in host_binary_names() {
            let path = dir.join(name);
            if !path.is_file() {
                return Err(BootPayloadError::MissingMember {
                    name: name.to_string(),
                    dir: dir.clone(),
                });
            }
            let bytes = std::fs::read(&path).map_err(io_error("reading", &path))?;
            let actual = sha256_hex(&bytes);
            if let Some(expected) = self.expected.get(name)
                && *expected != actual
            {
                return Err(BootPayloadError::MemberDigestMismatch {
                    name: name.to_string(),
                    expected: expected.clone(),
                    actual,
                });
            }
            members.insert(name.to_string(), (actual, bytes));
        }
        let manifest = PayloadManifest {
            members: members
                .iter()
                .map(|(name, (sha, _))| (name.clone(), sha.clone()))
                .collect(),
        };
        let stage1 = members
            .get(STAGE1_MEMBER)
            .map(|(_, bytes)| bytes.clone())
            .ok_or(BootPayloadError::NoStage1Member)?;
        let cpio = build_newc_cpio(&initramfs_entries(stage1, &members, &manifest));
        Ok(BuilderBootPayload { cpio, manifest })
    }
}

/// The archive's entries, in a fixed order: parents before children, members
/// sorted by name. `build_newc_cpio` writes mtime 0 and uid/gid 0, so the
/// archive is a function of the member bytes alone.
fn initramfs_entries(
    stage1: Vec<u8>,
    members: &BTreeMap<String, (String, Vec<u8>)>,
    manifest: &PayloadManifest,
) -> Vec<CpioEntry> {
    let dir = PAYLOAD_DIR_IN_INITRAMFS;
    let mut entries = vec![
        // The console node init needs for stdio. Kernels unpack their built-in
        // initramfs first and that normally carries one, but a kernel built
        // with another built-in source would leave stage 1 without a console
        // to report a refusal on.
        CpioEntry::dir("dev"),
        CpioEntry::char_dev("dev/console", 0o600, 5, 1),
        CpioEntry::file("init", MEMBER_MODE, stage1),
        CpioEntry::dir("mvm"),
        CpioEntry::dir(dir),
    ];
    for (name, (_, bytes)) in members {
        entries.push(CpioEntry::file(
            &format!("{dir}/{name}"),
            MEMBER_MODE,
            bytes.clone(),
        ));
    }
    entries.push(CpioEntry::file(
        &format!("{dir}/{PAYLOAD_MANIFEST_NAME}"),
        MANIFEST_MODE,
        manifest.render().into_bytes(),
    ));
    entries
}

/// Check an unpacked payload in `dir` against the digest the host put on the
/// kernel command line: the manifest's own digest first, then every member
/// against the manifest. Returns the manifest for the copy that follows.
pub fn verify_unpacked_payload(
    dir: &Path,
    expected: &PayloadDigest,
) -> Result<PayloadManifest, BootPayloadError> {
    let manifest_path = dir.join(PAYLOAD_MANIFEST_NAME);
    let text = std::fs::read(&manifest_path).map_err(io_error("reading", &manifest_path))?;
    let actual = PayloadDigest::of(&text);
    if actual != *expected {
        return Err(BootPayloadError::ManifestDigestMismatch {
            expected: expected.to_string(),
            actual: actual.to_string(),
        });
    }
    let text = String::from_utf8(text).map_err(|_| BootPayloadError::MalformedManifest {
        line: "<not UTF-8>".to_string(),
    })?;
    let manifest = PayloadManifest::parse(&text)?;
    for (name, sha) in manifest.members() {
        let path = dir.join(name);
        let bytes = std::fs::read(&path).map_err(io_error("reading", &path))?;
        let actual = sha256_hex(&bytes);
        if actual != sha {
            return Err(BootPayloadError::MemberDigestMismatch {
                name: name.to_string(),
                expected: sha.to_string(),
                actual,
            });
        }
    }
    Ok(manifest)
}

/// Copy a verified payload from `from` into `to`, members read-only and
/// executable, the manifest beside them. Stage 1 copies into the tmpfs that
/// becomes the builder's `/run`, which is how the binaries outlive the pivot
/// away from the initramfs.
pub fn install_payload(
    from: &Path,
    manifest: &PayloadManifest,
    to: &Path,
) -> Result<(), BootPayloadError> {
    std::fs::create_dir_all(to).map_err(io_error("creating", to))?;
    for (name, _) in manifest.members() {
        copy_with_mode(&from.join(name), &to.join(name), MEMBER_MODE)?;
    }
    copy_with_mode(
        &from.join(PAYLOAD_MANIFEST_NAME),
        &to.join(PAYLOAD_MANIFEST_NAME),
        MANIFEST_MODE,
    )
}

fn copy_with_mode(from: &Path, to: &Path, mode: u32) -> Result<(), BootPayloadError> {
    // A previous copy is read-only; replace it rather than write through it.
    let _ = std::fs::remove_file(to);
    std::fs::copy(from, to).map_err(io_error("copying", from))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(to, std::fs::Permissions::from_mode(mode))
            .map_err(io_error("setting the mode of", to))?;
    }
    #[cfg(not(unix))]
    let _ = mode;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stage_bins(dir: &Path) {
        std::fs::write(dir.join("mvm-host-vm-init"), b"INIT-ELF").unwrap();
        std::fs::write(dir.join("mvm-builderd"), b"BUILDERD-ELF").unwrap();
        // Embedded alongside, never part of the payload.
        std::fs::write(dir.join("stage0-init"), b"SEED").unwrap();
    }

    fn payload_from(dir: &Path) -> BuilderBootPayload {
        BuilderBootPayload::builder()
            .host_bin_dir(dir)
            .build()
            .unwrap()
    }

    /// `(name, mode, data)` for every entry up to the trailer.
    fn parse_newc(buf: &[u8]) -> Vec<(String, u32, Vec<u8>)> {
        let hex = |s: &[u8]| u32::from_str_radix(std::str::from_utf8(s).unwrap(), 16).unwrap();
        let align = |n: usize| n.div_ceil(4) * 4;
        let mut out = Vec::new();
        let mut off = 0;
        loop {
            let field = |i: usize| hex(&buf[off + 6 + i * 8..off + 14 + i * 8]);
            let (mode, size, namesize) = (field(1), field(6) as usize, field(11) as usize);
            let name =
                String::from_utf8(buf[off + 110..off + 110 + namesize - 1].to_vec()).unwrap();
            let data_start = align(off + 110 + namesize);
            if name == "TRAILER!!!" {
                return out;
            }
            out.push((name, mode, buf[data_start..data_start + size].to_vec()));
            off = align(data_start + size);
        }
    }

    #[test]
    fn the_payload_is_byte_identical_across_runs() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        stage_bins(a.path());
        // A different directory, written in a different order.
        std::fs::write(b.path().join("mvm-builderd"), b"BUILDERD-ELF").unwrap();
        std::fs::write(b.path().join("mvm-host-vm-init"), b"INIT-ELF").unwrap();

        let first = payload_from(a.path());
        assert_eq!(first.cpio(), payload_from(a.path()).cpio());
        assert_eq!(first.cpio(), payload_from(b.path()).cpio());
        assert_eq!(first.digest(), payload_from(b.path()).digest());
    }

    #[test]
    fn the_archive_carries_stage1_the_members_and_the_manifest() {
        let dir = tempfile::tempdir().unwrap();
        stage_bins(dir.path());
        let payload = payload_from(dir.path());
        let entries = parse_newc(payload.cpio());
        let names: Vec<&str> = entries.iter().map(|(n, _, _)| n.as_str()).collect();
        assert_eq!(
            names,
            [
                "dev",
                "dev/console",
                "init",
                "mvm",
                "mvm/host-bins",
                "mvm/host-bins/mvm-builderd",
                "mvm/host-bins/mvm-host-vm-init",
                "mvm/host-bins/MANIFEST",
            ]
        );
        let data = |want: &str| {
            entries
                .iter()
                .find(|(n, _, _)| n == want)
                .map(|(_, _, d)| d.clone())
                .unwrap()
        };
        assert_eq!(data("init"), b"INIT-ELF");
        assert_eq!(data("mvm/host-bins/mvm-host-vm-init"), b"INIT-ELF");
        assert!(!names.iter().any(|n| n.contains("stage0-init")));
    }

    #[test]
    fn the_manifest_matches_the_member_bytes() {
        let dir = tempfile::tempdir().unwrap();
        stage_bins(dir.path());
        let payload = payload_from(dir.path());
        let expected = format!(
            "mvm-builderd {}\nmvm-host-vm-init {}\n",
            sha256_hex(b"BUILDERD-ELF"),
            sha256_hex(b"INIT-ELF")
        );
        assert_eq!(payload.manifest().render(), expected);
        assert_eq!(payload.digest().as_str(), sha256_hex(expected.as_bytes()));
    }

    /// Pins the format. If this moves, every host and guest must move with it:
    /// the digest is what the two compare.
    #[test]
    fn the_digest_of_a_known_payload_is_stable() {
        let dir = tempfile::tempdir().unwrap();
        stage_bins(dir.path());
        let payload = payload_from(dir.path());
        assert_eq!(
            payload.digest().as_str(),
            "15ed68a00c9fed2e2cdb9c479b20cd770271b6a9df721e1ebf065e8e42b77ba0"
        );
        assert_eq!(sha256_hex(payload.cpio()), GOLDEN_CPIO_SHA256);
    }

    /// The archive bytes for [`stage_bins`]. Two hosts running the same
    /// `mvmctl` must hand their guests the same archive.
    const GOLDEN_CPIO_SHA256: &str =
        "8fcc05ccd8c0baeae948212cd5dd4cd92f974657c89ae3b855bda3d6351a0bd9";

    #[test]
    fn a_member_that_does_not_match_its_compiled_digest_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        stage_bins(dir.path());
        let err = BuilderBootPayload::builder()
            .host_bin_dir(dir.path())
            .expected_sha256("mvm-host-vm-init", sha256_hex(b"the real init"))
            .build()
            .unwrap_err();
        assert!(
            matches!(err, BootPayloadError::MemberDigestMismatch { ref name, .. } if name == "mvm-host-vm-init"),
            "{err}"
        );
    }

    #[test]
    fn matching_expectations_and_non_member_names_are_accepted() {
        let dir = tempfile::tempdir().unwrap();
        stage_bins(dir.path());
        BuilderBootPayload::builder()
            .host_bin_dir(dir.path())
            .expected_sha256("mvm-host-vm-init", sha256_hex(b"INIT-ELF"))
            .expected_sha256("stage0-init", sha256_hex(b"something else"))
            .build()
            .unwrap();
    }

    #[test]
    fn a_missing_member_or_directory_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("mvm-host-vm-init"), b"INIT").unwrap();
        let err = payload_err(dir.path());
        assert!(
            matches!(err, BootPayloadError::MissingMember { ref name, .. } if name == "mvm-builderd"),
            "{err}"
        );
        assert!(matches!(
            BuilderBootPayload::builder().build().unwrap_err(),
            BootPayloadError::NoHostBinDir
        ));
    }

    fn payload_err(dir: &Path) -> BootPayloadError {
        BuilderBootPayload::builder()
            .host_bin_dir(dir)
            .build()
            .unwrap_err()
    }

    /// Lay the archive's payload directory out on disk the way the kernel
    /// would unpack it.
    fn unpack(payload: &BuilderBootPayload, root: &Path) -> PathBuf {
        for (name, _, data) in parse_newc(payload.cpio()) {
            let path = root.join(&name);
            if name.starts_with("mvm/host-bins/") {
                std::fs::create_dir_all(path.parent().unwrap()).unwrap();
                std::fs::write(path, data).unwrap();
            }
        }
        root.join(PAYLOAD_DIR_IN_INITRAMFS)
    }

    #[test]
    fn an_unpacked_payload_verifies_and_installs_read_only() {
        let bins = tempfile::tempdir().unwrap();
        stage_bins(bins.path());
        let payload = payload_from(bins.path());
        let root = tempfile::tempdir().unwrap();
        let unpacked = unpack(&payload, root.path());

        let manifest = verify_unpacked_payload(&unpacked, &payload.digest()).unwrap();
        let run = root.path().join("run/mvm/host-bins");
        install_payload(&unpacked, &manifest, &run).unwrap();
        // Installing twice replaces the read-only copies.
        install_payload(&unpacked, &manifest, &run).unwrap();

        assert_eq!(
            std::fs::read(run.join("mvm-builderd")).unwrap(),
            b"BUILDERD-ELF"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&run.join("mvm-host-vm-init")), 0o555);
            assert_eq!(mode(&run.join(PAYLOAD_MANIFEST_NAME)), 0o444);
        }
    }

    #[test]
    fn a_digest_the_manifest_does_not_hash_to_is_refused() {
        let bins = tempfile::tempdir().unwrap();
        stage_bins(bins.path());
        let payload = payload_from(bins.path());
        let root = tempfile::tempdir().unwrap();
        let unpacked = unpack(&payload, root.path());
        let other = PayloadDigest::parse(&"0".repeat(64)).unwrap();
        assert!(matches!(
            verify_unpacked_payload(&unpacked, &other).unwrap_err(),
            BootPayloadError::ManifestDigestMismatch { .. }
        ));
    }

    #[test]
    fn a_member_changed_after_packing_is_refused_in_the_guest() {
        let bins = tempfile::tempdir().unwrap();
        stage_bins(bins.path());
        let payload = payload_from(bins.path());
        let root = tempfile::tempdir().unwrap();
        let unpacked = unpack(&payload, root.path());
        std::fs::write(unpacked.join("mvm-builderd"), b"swapped").unwrap();
        assert!(matches!(
            verify_unpacked_payload(&unpacked, &payload.digest()).unwrap_err(),
            BootPayloadError::MemberDigestMismatch { .. }
        ));
    }

    #[test]
    fn a_manifest_is_parsed_only_in_its_rendered_form() {
        let sha = sha256_hex(b"x");
        let good = format!("mvm-host-vm-init {sha}\n");
        assert!(PayloadManifest::parse(&good).is_ok());
        for bad in [
            format!("mvm-host-vm-init  {sha}\n"),
            format!("mvm-host-vm-init {sha}"),
            format!("../etc/passwd {sha}\nmvm-host-vm-init {sha}\n"),
            format!("mvm-host-vm-init {}\n", sha.to_uppercase()),
            format!("b {sha}\na {sha}\nmvm-host-vm-init {sha}\n"),
        ] {
            assert!(PayloadManifest::parse(&bad).is_err(), "{bad:?}");
        }
        assert!(matches!(
            PayloadManifest::parse(&format!("mvm-builderd {sha}\n")).unwrap_err(),
            BootPayloadError::NoStage1Member
        ));
    }

    #[test]
    fn a_digest_must_be_lowercase_sha256_hex() {
        assert!(PayloadDigest::parse(&"a".repeat(64)).is_ok());
        for bad in ["", "abc", &"A".repeat(64), &"g".repeat(64)] {
            assert!(PayloadDigest::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn the_payload_file_is_private_to_its_owner() {
        let bins = tempfile::tempdir().unwrap();
        stage_bins(bins.path());
        let out = tempfile::tempdir().unwrap();
        let path = out.path().join("boot-payload.cpio");
        payload_from(bins.path()).write_to(&path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }
}
