//! The `mvm-guest-bins` artifact: the guest binaries an image build consumes,
//! packaged with a manifest that pins their bytes.
//!
//! Image construction lives in `mvm-images`; the binaries that run inside the
//! guest are compiled from this workspace, against the one `Cargo.lock` the
//! host links too. This artifact is how they cross the repository boundary as
//! bytes rather than as a source dependency: `mvm-images` pins the archive's
//! sha256 and unpacks it.
//!
//! The archive is a gzip tarball:
//!
//! ```text
//!   manifest.json
//!   aarch64/mvm-guest-agent
//!   aarch64/…
//!   x86_64/mvm-guest-agent
//!   x86_64/…
//! ```
//!
//! The manifest records each member's sha256, the workspace version, and two
//! source fingerprints of the producing tree — the guest-binary inputs and the
//! host-services cdylib inputs — so a consumer can verify the bytes and
//! recognise an unchanged tree without rebuilding.
//!
//! The archive is deterministic: members are written in sorted order with
//! zeroed timestamps and ownership, and the gzip header carries no time or
//! name. The same binaries always produce the same archive sha256.
//!
//! Every binary is produced by the existing host-side guest builds in
//! [`crate::guest_agent_build`] (the runtime-overlay set and the OCI runtime
//! set); this module adds no compile path of its own.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use flate2::Compression;
use flate2::read::GzDecoder;
use mvm_core::arch::GuestArch;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tar::{EntryType, Header};

use crate::guest_agent_build::{self, GuestAgentBuildError};

/// Name of the manifest member inside the archive.
pub const GUEST_BINS_MANIFEST_FILE: &str = "manifest.json";

/// The manifest format this build writes and accepts.
pub const GUEST_BINS_MANIFEST_SCHEMA: u32 = 1;

/// Largest single member a verifier will hash. Guest binaries are a few MiB;
/// the cap exists so a hostile archive cannot stream without bound.
const MAX_MEMBER_BYTES: u64 = 256 * 1024 * 1024;

/// Largest manifest a verifier will parse.
const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;

/// The release file name for `version`'s artifact.
pub fn guest_bins_archive_name(version: &str) -> String {
    format!("mvm-guest-bins-v{version}.tar.gz")
}

/// What the archive's `manifest.json` records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuestBinsManifest {
    pub schema_version: u32,
    /// The mvm workspace version that built the binaries.
    pub version: String,
    /// [`guest_agent_build::guest_source_fingerprint`] of the producing tree.
    pub guest_source_fingerprint: String,
    /// [`guest_agent_build::sdk_cdylib_source_fingerprint`] of the producing
    /// tree — the value the SDK sidecar's fetch-when-unchanged check compares.
    pub sdk_cdylib_source_fingerprint: String,
    /// Archive-relative member path (`<arch>/<binary>`) → lowercase hex sha256.
    pub files: BTreeMap<String, String>,
}

/// The two source fingerprints a manifest records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestBinsFingerprints {
    pub guest_source: String,
    pub sdk_cdylib: String,
}

impl GuestBinsFingerprints {
    /// Fingerprint the workspace at `workspace_root`.
    pub fn of_tree(workspace_root: &Path) -> Result<Self, GuestAgentBuildError> {
        Ok(Self {
            guest_source: guest_agent_build::guest_source_fingerprint(workspace_root)?,
            sdk_cdylib: guest_agent_build::sdk_cdylib_source_fingerprint(workspace_root)?,
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum GuestBinsError {
    #[error("refusing to assemble a guest-bins artifact with no binaries")]
    Empty,
    #[error("guest binary name {0:?} is not a plain file name")]
    InvalidName(String),
    #[error("guest binary {0} appears twice")]
    DuplicateMember(String),
    #[error("guest binary {member} is not a static guest executable: {reason}")]
    InvalidBinary { member: String, reason: String },
    #[error("build the guest binaries: {0}")]
    Build(#[from] GuestAgentBuildError),
    #[error("archive has no {GUEST_BINS_MANIFEST_FILE}")]
    MissingManifest,
    #[error(
        "archive manifest schema {found} is not the supported schema {GUEST_BINS_MANIFEST_SCHEMA}"
    )]
    UnsupportedSchema { found: u32 },
    #[error("archive manifest lists no binaries")]
    EmptyManifest,
    #[error("archive is missing {0}, which its manifest lists")]
    MissingMember(String),
    #[error("archive carries {0}, which its manifest does not list")]
    UnlistedMember(String),
    #[error("archive member {0} is not a regular file")]
    NonRegularMember(String),
    #[error("archive member {0} exceeds the size cap")]
    MemberTooLarge(String),
    #[error("{member}: sha256 {actual} does not match the manifest's {expected}")]
    DigestMismatch {
        member: String,
        expected: String,
        actual: String,
    },
    #[error("archive manifest: {0}")]
    Manifest(#[from] serde_json::Error),
    #[error("guest-bins io: {0}")]
    Io(#[from] std::io::Error),
}

/// Archive-relative member path for one binary.
fn member_path(arch: GuestArch, name: &str) -> String {
    format!("{arch}/{name}")
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// A plain file name: non-empty, no separator, not a dot entry.
fn is_plain_name(name: &str) -> bool {
    !name.is_empty() && name != "." && name != ".." && !name.contains(['/', '\\'])
}

/// Builder for one artifact. Collect binaries with [`Self::add`], then
/// [`Self::write`] the archive.
#[derive(Debug)]
pub struct GuestBinsArtifact {
    version: String,
    fingerprints: GuestBinsFingerprints,
    members: BTreeMap<String, Vec<u8>>,
}

impl GuestBinsArtifact {
    pub fn new(version: impl Into<String>, fingerprints: GuestBinsFingerprints) -> Self {
        Self {
            version: version.into(),
            fingerprints,
            members: BTreeMap::new(),
        }
    }

    /// Add the binary at `path` as `<arch>/<name>`.
    ///
    /// The bytes must be a static ELF for `arch`: a wrong-architecture or
    /// dynamically linked binary would reach a guest with no loader and fail
    /// there, far from the build that produced it.
    pub fn add(&mut self, arch: GuestArch, name: &str, path: &Path) -> Result<(), GuestBinsError> {
        if !is_plain_name(name) {
            return Err(GuestBinsError::InvalidName(name.to_string()));
        }
        let member = member_path(arch, name);
        if self.members.contains_key(&member) {
            return Err(GuestBinsError::DuplicateMember(member));
        }
        let bytes = std::fs::read(path)?;
        crate::guest_elf::validate_static_guest_elf(&bytes, path, arch).map_err(|e| {
            GuestBinsError::InvalidBinary {
                member: member.clone(),
                reason: e.to_string(),
            }
        })?;
        self.members.insert(member, bytes);
        Ok(())
    }

    /// The manifest the archive will carry.
    pub fn manifest(&self) -> GuestBinsManifest {
        GuestBinsManifest {
            schema_version: GUEST_BINS_MANIFEST_SCHEMA,
            version: self.version.clone(),
            guest_source_fingerprint: self.fingerprints.guest_source.clone(),
            sdk_cdylib_source_fingerprint: self.fingerprints.sdk_cdylib.clone(),
            files: self
                .members
                .iter()
                .map(|(member, bytes)| (member.clone(), sha256_hex(bytes)))
                .collect(),
        }
    }

    /// Serialize the archive to bytes: the manifest first, then every member
    /// in sorted order.
    pub fn to_bytes(&self) -> Result<Vec<u8>, GuestBinsError> {
        if self.members.is_empty() {
            return Err(GuestBinsError::Empty);
        }
        let manifest = serde_json::to_vec_pretty(&self.manifest())?;
        // A fixed header: no mtime, no file name, and the "unknown" OS byte,
        // so the compressed bytes do not depend on when or where they were made.
        let gz = flate2::GzBuilder::new()
            .mtime(0)
            .operating_system(255)
            .write(Vec::new(), Compression::best());
        let mut tar = tar::Builder::new(gz);
        append_member(&mut tar, GUEST_BINS_MANIFEST_FILE, 0o644, &manifest)?;
        for (member, bytes) in &self.members {
            append_member(&mut tar, member, 0o755, bytes)?;
        }
        Ok(tar.into_inner()?.finish()?)
    }

    /// Write `<out_dir>/mvm-guest-bins-v<version>.tar.gz` and its
    /// `sha256sum`-format sidecar, then re-verify what landed on disk.
    pub fn write(&self, out_dir: &Path) -> Result<WrittenGuestBins, GuestBinsError> {
        let bytes = self.to_bytes()?;
        let sha256 = sha256_hex(&bytes);
        std::fs::create_dir_all(out_dir)?;
        let name = guest_bins_archive_name(&self.version);
        let archive = out_dir.join(&name);
        write_atomically(&archive, &bytes)?;
        let checksum = out_dir.join(format!("{name}.sha256"));
        write_atomically(&checksum, format!("{sha256}  {name}\n").as_bytes())?;
        let manifest = verify_guest_bins_archive(&archive)?;
        Ok(WrittenGuestBins {
            archive,
            checksum,
            sha256,
            manifest,
        })
    }
}

/// What [`GuestBinsArtifact::write`] produced.
#[derive(Debug, Clone)]
pub struct WrittenGuestBins {
    pub archive: PathBuf,
    pub checksum: PathBuf,
    /// sha256 of the archive bytes — the value a consumer pins.
    pub sha256: String,
    pub manifest: GuestBinsManifest,
}

fn append_member<W: Write>(
    tar: &mut tar::Builder<W>,
    path: &str,
    mode: u32,
    bytes: &[u8],
) -> Result<(), GuestBinsError> {
    let mut header = Header::new_gnu();
    header.set_path(path)?;
    header.set_entry_type(EntryType::Regular);
    header.set_size(bytes.len() as u64);
    header.set_mode(mode);
    header.set_mtime(0);
    header.set_uid(0);
    header.set_gid(0);
    header.set_cksum();
    tar.append(&header, bytes)?;
    Ok(())
}

/// Atomically write a file meant for publication: world-readable, unlike the
/// owner-only temp file the atomic write stages through.
fn write_atomically(path: &Path, bytes: &[u8]) -> Result<(), GuestBinsError> {
    mvm_core::util::atomic_io::atomic_write(path, bytes).map_err(std::io::Error::other)?;
    set_readable(path)
}

#[cfg(unix)]
fn set_readable(path: &Path) -> Result<(), GuestBinsError> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_readable(_path: &Path) -> Result<(), GuestBinsError> {
    Ok(())
}

/// Verify an archive against the manifest it carries and return the manifest.
///
/// Refuses an archive with no manifest, an unsupported schema, an empty file
/// list, a listed member that is absent, a member the manifest does not list,
/// a non-regular or duplicated entry, or any member whose bytes do not hash to
/// the recorded digest.
pub fn verify_guest_bins_archive(path: &Path) -> Result<GuestBinsManifest, GuestBinsError> {
    let file = std::fs::File::open(path)?;
    let mut archive = tar::Archive::new(GzDecoder::new(file));
    let mut manifest_bytes: Option<Vec<u8>> = None;
    let mut digests: BTreeMap<String, String> = BTreeMap::new();
    for entry in archive.entries()? {
        let entry = entry?;
        let member = entry.path()?.to_string_lossy().into_owned();
        if entry.header().entry_type() != EntryType::Regular {
            return Err(GuestBinsError::NonRegularMember(member));
        }
        if member == GUEST_BINS_MANIFEST_FILE {
            if manifest_bytes.is_some() {
                return Err(GuestBinsError::DuplicateMember(member));
            }
            manifest_bytes = Some(read_capped(entry, MAX_MANIFEST_BYTES, &member)?);
        } else {
            if digests.contains_key(&member) {
                return Err(GuestBinsError::DuplicateMember(member));
            }
            let digest = hash_capped(entry, &member)?;
            digests.insert(member, digest);
        }
    }
    let manifest: GuestBinsManifest =
        serde_json::from_slice(&manifest_bytes.ok_or(GuestBinsError::MissingManifest)?)?;
    check_manifest_against(&manifest, &digests)?;
    Ok(manifest)
}

fn check_manifest_against(
    manifest: &GuestBinsManifest,
    digests: &BTreeMap<String, String>,
) -> Result<(), GuestBinsError> {
    if manifest.schema_version != GUEST_BINS_MANIFEST_SCHEMA {
        return Err(GuestBinsError::UnsupportedSchema {
            found: manifest.schema_version,
        });
    }
    if manifest.files.is_empty() {
        return Err(GuestBinsError::EmptyManifest);
    }
    if let Some(extra) = digests.keys().find(|m| !manifest.files.contains_key(*m)) {
        return Err(GuestBinsError::UnlistedMember(extra.clone()));
    }
    for (member, expected) in &manifest.files {
        let actual = digests
            .get(member)
            .ok_or_else(|| GuestBinsError::MissingMember(member.clone()))?;
        if actual != expected {
            return Err(GuestBinsError::DigestMismatch {
                member: member.clone(),
                expected: expected.clone(),
                actual: actual.clone(),
            });
        }
    }
    Ok(())
}

fn read_capped<R: Read>(entry: R, cap: u64, member: &str) -> Result<Vec<u8>, GuestBinsError> {
    let mut bytes = Vec::new();
    entry.take(cap + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > cap {
        return Err(GuestBinsError::MemberTooLarge(member.to_string()));
    }
    Ok(bytes)
}

fn hash_capped<R: Read>(entry: R, member: &str) -> Result<String, GuestBinsError> {
    let mut limited = entry.take(MAX_MEMBER_BYTES + 1);
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    let mut total: u64 = 0;
    loop {
        let n = limited.read(&mut buf)?;
        if n == 0 {
            break;
        }
        total += n as u64;
        hasher.update(&buf[..n]);
    }
    if total > MAX_MEMBER_BYTES {
        return Err(GuestBinsError::MemberTooLarge(member.to_string()));
    }
    Ok(hex::encode(hasher.finalize()))
}

/// Inputs to [`build_guest_bins`].
#[derive(Debug, Clone)]
pub struct GuestBinsBuild {
    /// The mvm source checkout the binaries are compiled from.
    pub workspace_root: PathBuf,
    /// The mvm cache root the existing guest builds cache under.
    pub cache_root: PathBuf,
    /// The workspace version recorded in the manifest and the file name.
    pub version: String,
    /// Architectures to include; each one is built if its cache is cold.
    pub arches: Vec<GuestArch>,
    /// Where the archive and its checksum land.
    pub out_dir: PathBuf,
}

/// Build (or reuse from cache) every guest binary for each requested
/// architecture, and write the artifact.
pub fn build_guest_bins(build: &GuestBinsBuild) -> Result<WrittenGuestBins, GuestBinsError> {
    let fingerprints = GuestBinsFingerprints::of_tree(&build.workspace_root)?;
    let mut artifact = GuestBinsArtifact::new(&build.version, fingerprints);
    let arches: BTreeSet<GuestArch> = build.arches.iter().copied().collect();
    for arch in arches {
        add_arch(&mut artifact, build, arch)?;
    }
    artifact.write(&build.out_dir)
}

/// Every guest binary for `arch`: the runtime-overlay set, plus the OCI entry
/// point that only the OCI runtime set carries.
fn add_arch(
    artifact: &mut GuestBinsArtifact,
    build: &GuestBinsBuild,
    arch: GuestArch,
) -> Result<(), GuestBinsError> {
    let overlay = guest_agent_build::resolve_or_build_runtime_overlay_guest_binaries(
        &build.cache_root,
        &build.version,
        arch,
        &build.workspace_root,
    )?;
    for (name, path) in overlay.artifacts() {
        artifact.add(arch, name, path)?;
    }
    let oci = guest_agent_build::resolve_or_build_guest_binaries(
        &build.cache_root,
        &guest_agent_build::source_cache_key(&build.workspace_root)?,
        arch,
        &build.workspace_root,
    )?;
    artifact.add(arch, "mvm-oci-entrypoint", &oci.entrypoint_runner)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guest_agent_build::fake_static_elf;

    fn fingerprints() -> GuestBinsFingerprints {
        GuestBinsFingerprints {
            guest_source: "g".repeat(64),
            sdk_cdylib: "c".repeat(64),
        }
    }

    fn write_bin(dir: &Path, name: &str, arch: GuestArch) -> PathBuf {
        std::fs::create_dir_all(dir).unwrap();
        let path = dir.join(format!("{arch}-{name}"));
        std::fs::write(&path, fake_static_elf(arch, name.as_bytes())).unwrap();
        path
    }

    fn two_arch_artifact(dir: &Path) -> GuestBinsArtifact {
        let mut artifact = GuestBinsArtifact::new("1.2.3", fingerprints());
        for arch in [GuestArch::Aarch64, GuestArch::X86_64] {
            for name in ["mvm-guest-agent", "mvm-guest-netinit"] {
                artifact
                    .add(arch, name, &write_bin(dir, name, arch))
                    .unwrap();
            }
        }
        artifact
    }

    /// Rebuild a written archive with `edit` applied to its members.
    fn rewrite(archive: &Path, edit: impl FnOnce(&mut BTreeMap<String, Vec<u8>>)) {
        let mut members = BTreeMap::new();
        let file = std::fs::File::open(archive).unwrap();
        let mut tar = tar::Archive::new(GzDecoder::new(file));
        for entry in tar.entries().unwrap() {
            let mut entry = entry.unwrap();
            let path = entry.path().unwrap().to_string_lossy().into_owned();
            let mut bytes = Vec::new();
            entry.read_to_end(&mut bytes).unwrap();
            members.insert(path, bytes);
        }
        edit(&mut members);
        let gz = flate2::write::GzEncoder::new(Vec::new(), Compression::default());
        let mut out = tar::Builder::new(gz);
        for (path, bytes) in &members {
            append_member(&mut out, path, 0o644, bytes).unwrap();
        }
        std::fs::write(archive, out.into_inner().unwrap().finish().unwrap()).unwrap();
    }

    #[test]
    fn manifest_digests_verify_against_the_archived_bytes() {
        let tmp = tempfile::tempdir().unwrap();
        let written = two_arch_artifact(tmp.path())
            .write(&tmp.path().join("out"))
            .unwrap();

        assert_eq!(
            written.archive.file_name().unwrap(),
            "mvm-guest-bins-v1.2.3.tar.gz"
        );
        assert_eq!(written.manifest.version, "1.2.3");
        assert_eq!(
            written.manifest.files.keys().collect::<Vec<_>>(),
            [
                "aarch64/mvm-guest-agent",
                "aarch64/mvm-guest-netinit",
                "x86_64/mvm-guest-agent",
                "x86_64/mvm-guest-netinit",
            ]
        );
        assert_eq!(
            written.manifest.files["x86_64/mvm-guest-agent"],
            sha256_hex(&fake_static_elf(GuestArch::X86_64, b"mvm-guest-agent")),
            "the recorded digest is the digest of the bytes that went in"
        );
        assert_eq!(
            verify_guest_bins_archive(&written.archive).unwrap(),
            written.manifest
        );
        assert_eq!(
            std::fs::read_to_string(&written.checksum).unwrap(),
            format!("{}  mvm-guest-bins-v1.2.3.tar.gz\n", written.sha256)
        );
        assert_eq!(
            written.sha256,
            sha256_hex(&std::fs::read(&written.archive).unwrap())
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for path in [&written.archive, &written.checksum] {
                let mode = std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
                assert_eq!(mode, 0o644, "{} is published readable", path.display());
            }
        }
    }

    #[test]
    fn the_same_binaries_produce_the_same_archive_bytes() {
        let tmp = tempfile::tempdir().unwrap();
        let first = two_arch_artifact(&tmp.path().join("a"));
        let second = two_arch_artifact(&tmp.path().join("b"));
        assert_eq!(first.to_bytes().unwrap(), second.to_bytes().unwrap());
    }

    #[test]
    fn archive_entries_are_sorted_and_carry_no_host_metadata() {
        let tmp = tempfile::tempdir().unwrap();
        let bytes = two_arch_artifact(tmp.path()).to_bytes().unwrap();
        let mut tar = tar::Archive::new(GzDecoder::new(bytes.as_slice()));
        let mut names = Vec::new();
        for entry in tar.entries().unwrap() {
            let entry = entry.unwrap();
            let header = entry.header();
            assert_eq!(header.mtime().unwrap(), 0);
            assert_eq!(header.uid().unwrap(), 0);
            assert_eq!(header.gid().unwrap(), 0);
            names.push(entry.path().unwrap().to_string_lossy().into_owned());
        }
        assert_eq!(names[0], GUEST_BINS_MANIFEST_FILE);
        let mut sorted = names[1..].to_vec();
        sorted.sort();
        assert_eq!(names[1..], sorted[..]);
    }

    #[test]
    fn a_tampered_member_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let written = two_arch_artifact(tmp.path()).write(tmp.path()).unwrap();
        rewrite(&written.archive, |members| {
            members
                .get_mut("aarch64/mvm-guest-agent")
                .unwrap()
                .push(0xff);
        });
        let err = verify_guest_bins_archive(&written.archive).unwrap_err();
        assert!(
            matches!(&err, GuestBinsError::DigestMismatch { member, .. } if member == "aarch64/mvm-guest-agent"),
            "{err}"
        );
    }

    #[test]
    fn a_missing_member_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let written = two_arch_artifact(tmp.path()).write(tmp.path()).unwrap();
        rewrite(&written.archive, |members| {
            members.remove("x86_64/mvm-guest-netinit");
        });
        let err = verify_guest_bins_archive(&written.archive).unwrap_err();
        assert!(
            matches!(&err, GuestBinsError::MissingMember(m) if m == "x86_64/mvm-guest-netinit"),
            "{err}"
        );
    }

    #[test]
    fn an_unlisted_member_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let written = two_arch_artifact(tmp.path()).write(tmp.path()).unwrap();
        rewrite(&written.archive, |members| {
            members.insert("x86_64/extra".into(), b"smuggled".to_vec());
        });
        let err = verify_guest_bins_archive(&written.archive).unwrap_err();
        assert!(
            matches!(&err, GuestBinsError::UnlistedMember(m) if m == "x86_64/extra"),
            "{err}"
        );
    }

    #[test]
    fn an_archive_without_a_manifest_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let written = two_arch_artifact(tmp.path()).write(tmp.path()).unwrap();
        rewrite(&written.archive, |members| {
            members.remove(GUEST_BINS_MANIFEST_FILE);
        });
        assert!(matches!(
            verify_guest_bins_archive(&written.archive),
            Err(GuestBinsError::MissingManifest)
        ));
    }

    #[test]
    fn an_unknown_schema_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let written = two_arch_artifact(tmp.path()).write(tmp.path()).unwrap();
        let mut manifest = written.manifest.clone();
        manifest.schema_version = GUEST_BINS_MANIFEST_SCHEMA + 1;
        rewrite(&written.archive, |members| {
            members.insert(
                GUEST_BINS_MANIFEST_FILE.into(),
                serde_json::to_vec(&manifest).unwrap(),
            );
        });
        assert!(matches!(
            verify_guest_bins_archive(&written.archive),
            Err(GuestBinsError::UnsupportedSchema { .. })
        ));
    }

    #[test]
    fn an_empty_artifact_is_refused() {
        let artifact = GuestBinsArtifact::new("1.2.3", fingerprints());
        assert!(matches!(artifact.to_bytes(), Err(GuestBinsError::Empty)));
    }

    #[test]
    fn a_wrong_architecture_binary_is_refused_at_add() {
        let tmp = tempfile::tempdir().unwrap();
        let x86 = write_bin(tmp.path(), "mvm-guest-agent", GuestArch::X86_64);
        let mut artifact = GuestBinsArtifact::new("1.2.3", fingerprints());
        let err = artifact
            .add(GuestArch::Aarch64, "mvm-guest-agent", &x86)
            .unwrap_err();
        assert!(matches!(err, GuestBinsError::InvalidBinary { .. }), "{err}");
    }

    #[test]
    fn a_duplicate_or_path_like_name_is_refused_at_add() {
        let tmp = tempfile::tempdir().unwrap();
        let bin = write_bin(tmp.path(), "mvm-guest-agent", GuestArch::X86_64);
        let mut artifact = GuestBinsArtifact::new("1.2.3", fingerprints());
        artifact
            .add(GuestArch::X86_64, "mvm-guest-agent", &bin)
            .unwrap();
        assert!(matches!(
            artifact.add(GuestArch::X86_64, "mvm-guest-agent", &bin),
            Err(GuestBinsError::DuplicateMember(_))
        ));
        assert!(matches!(
            artifact.add(GuestArch::X86_64, "../escape", &bin),
            Err(GuestBinsError::InvalidName(_))
        ));
    }

    fn write_fake_elves(arch: GuestArch, paths: &[&PathBuf]) {
        for path in paths {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(
                path,
                fake_static_elf(arch, path.to_string_lossy().as_bytes()),
            )
            .unwrap();
        }
    }

    /// Seed both guest-build caches the producer reads, so the test drives the
    /// real resolution path without a cross-compile.
    fn seed_guest_caches(cache_root: &Path, version: &str, arch: GuestArch, workspace: &Path) {
        let fingerprint =
            guest_agent_build::runtime_overlay_source_checkout_fingerprint(workspace).unwrap();
        let o = guest_agent_build::RuntimeOverlayGuestLayout::under(
            cache_root,
            version,
            arch,
            &fingerprint,
        );
        write_fake_elves(
            arch,
            &[
                &o.agent,
                &o.netinit,
                &o.seccomp_apply,
                &o.display_bridge,
                &o.runner,
                &o.egress_client,
                &o.addon_dns,
                &o.exit_report,
                &o.ping,
            ],
        );
        let key = guest_agent_build::source_cache_key(workspace).unwrap();
        let oci = guest_agent_build::GuestAgentLayout::under(cache_root, &key, arch);
        write_fake_elves(
            arch,
            &[
                &oci.agent,
                &oci.netinit,
                &oci.egress_client,
                &oci.entrypoint_runner,
            ],
        );
    }

    #[test]
    fn the_producer_records_the_producing_trees_fingerprints_and_every_binary() {
        let workspace = guest_agent_build::detect_source_workspace()
            .expect("the test runs inside the mvm workspace");
        let tmp = tempfile::tempdir().unwrap();
        let cache_root = tmp.path().join("cache");
        for arch in [GuestArch::Aarch64, GuestArch::X86_64] {
            seed_guest_caches(&cache_root, "9.9.9", arch, &workspace);
        }
        let written = build_guest_bins(&GuestBinsBuild {
            workspace_root: workspace.clone(),
            cache_root,
            version: "9.9.9".into(),
            arches: vec![GuestArch::X86_64, GuestArch::Aarch64, GuestArch::X86_64],
            out_dir: tmp.path().join("out"),
        })
        .unwrap();

        assert_eq!(
            written.manifest.sdk_cdylib_source_fingerprint,
            guest_agent_build::sdk_cdylib_source_fingerprint(&workspace).unwrap(),
            "consumers compare against the producing tree's own cdylib fingerprint"
        );
        assert_eq!(
            written.manifest.guest_source_fingerprint,
            guest_agent_build::guest_source_fingerprint(&workspace).unwrap(),
        );
        for arch in ["aarch64", "x86_64"] {
            for name in [
                "mvm-guest-agent",
                "mvm-guest-netinit",
                "mvm-seccomp-apply",
                "mvm-display-bridge",
                "mvm-runner",
                "mvm-egress-client",
                "mvm-addon-dns",
                "mvm-exit-report",
                "mvm-ping",
                "mvm-oci-entrypoint",
            ] {
                assert!(
                    written
                        .manifest
                        .files
                        .contains_key(&format!("{arch}/{name}")),
                    "{arch}/{name} missing from {:?}",
                    written.manifest.files.keys()
                );
            }
        }
        assert_eq!(
            written.manifest.files.len(),
            20,
            "a repeated --arch adds nothing"
        );
    }
}
