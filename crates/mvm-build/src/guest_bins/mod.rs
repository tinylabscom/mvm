//! The `mvm-guest-bins` artifact: every guest artifact mvm owns, packaged
//! with a manifest that pins its bytes.
//!
//! The programs and libraries that run inside a guest are compiled from this
//! workspace, against the one `Cargo.lock` the host links too. This archive is
//! the guest runtime as one versioned unit, and its consumer is `mvmctl`
//! itself: it is meant to ship as a signed asset of each CLI release, version
//! locked to the CLI, and `mvmctl` is to assemble the runtime overlay, the
//! initramfs and the SDK sidecar from it. Neither half is wired yet; today the
//! archive is produced by `mvmctl build guest-bins` and by the manually
//! dispatched guest-bins workflow, and nothing reads it. `mvm-images` does not
//! consume it: that repository builds only the Linux layer.
//!
//! The archive is a gzip tarball whose member paths spell each member's kind
//! (see [`member`]):
//!
//! ```text
//!   manifest.json
//!   <arch>/bin/<name>                 static executables: the runtime-overlay
//!                                     set, mvm-oci-entrypoint, mvm-setpriv
//!   <arch>/initramfs/mvm-guest-agent  the initramfs's static agent
//!   <arch>/lib/<glibc|musl>/<soname>  host-services cdylib and GPU shims
//!   sdk-py/mvm/…                      the in-guest Python SDK
//! ```
//!
//! The manifest records each member's sha256, the workspace version, the git
//! commit of the producing checkout and whether its files matched that commit,
//! and two source fingerprints — the guest-binary inputs and the host-services
//! cdylib inputs — so a consumer can verify the bytes, name their source, and
//! recognise an unchanged tree without rebuilding.
//!
//! The archive is deterministic: members are written in sorted order with
//! zeroed timestamps and ownership, and the gzip header carries no time or
//! name. The same inputs always produce the same archive sha256.
//!
//! Every compiled member comes from a host-side `cargo zigbuild` through
//! [`crate::guest_agent_build`]'s toolchain, target dir and locks: the
//! runtime-overlay and OCI runtime sets it already builds, plus the
//! [`extras`] it builds for this artifact.

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
use crate::image_source::RepoIdentity;

pub mod cdylib;
pub mod extras;
pub mod member;
pub mod python_sdk;

pub use cdylib::{GPU_SHIM_CDYLIBS, GuestCdylib, HOST_SERVICES_CDYLIB, guest_cdylibs};
pub use member::{GuestBinsMember, MemberError};

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
    /// The producing checkout: its commit, and whether its files matched it.
    /// A dirty tree carries a fingerprint of its changes, so its bytes are
    /// never attributed to the clean commit alone.
    pub source: RepoIdentity,
    /// Archive-relative member path → lowercase hex sha256.
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
    #[error(transparent)]
    Member(#[from] MemberError),
    #[error("guest-bins member {0} appears twice")]
    DuplicateMember(String),
    #[error("{member} is refused: {reason}")]
    InvalidMember { member: String, reason: String },
    #[error("build the guest binaries: {0}")]
    Build(#[from] GuestAgentBuildError),
    #[error("read the producing checkout's commit: {0}")]
    Source(String),
    #[error("{} holds no Python SDK files", .0.display())]
    EmptyPythonSdk(PathBuf),
    #[error("{} is not a regular file or directory", .0.display())]
    NonRegularSource(PathBuf),
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

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// One member's archived mode and bytes.
#[derive(Debug)]
struct MemberBytes {
    mode: u32,
    bytes: Vec<u8>,
}

/// Builder for one artifact. Collect members with [`Self::add`], then
/// [`Self::write`] the archive.
#[derive(Debug)]
pub struct GuestBinsArtifact {
    version: String,
    fingerprints: GuestBinsFingerprints,
    source: RepoIdentity,
    members: BTreeMap<String, MemberBytes>,
}

impl GuestBinsArtifact {
    pub fn new(
        version: impl Into<String>,
        fingerprints: GuestBinsFingerprints,
        source: RepoIdentity,
    ) -> Self {
        Self {
            version: version.into(),
            fingerprints,
            source,
            members: BTreeMap::new(),
        }
    }

    /// Add the file at `path` as `member`.
    ///
    /// The bytes must be what the member's kind requires — a static ELF for an
    /// executable, a shared object needing only its libc for a library. A
    /// wrong one would otherwise reach a guest and fail there, far from the
    /// build that produced it.
    pub fn add(&mut self, member: &GuestBinsMember, path: &Path) -> Result<(), GuestBinsError> {
        let member_path = member.path();
        if self.members.contains_key(&member_path) {
            return Err(GuestBinsError::DuplicateMember(member_path));
        }
        let bytes = std::fs::read(path)?;
        member
            .validate(&bytes, path)
            .map_err(|reason| GuestBinsError::InvalidMember {
                member: member_path.clone(),
                reason,
            })?;
        self.members.insert(
            member_path,
            MemberBytes {
                mode: member.mode(),
                bytes,
            },
        );
        Ok(())
    }

    /// The manifest the archive will carry.
    pub fn manifest(&self) -> GuestBinsManifest {
        GuestBinsManifest {
            schema_version: GUEST_BINS_MANIFEST_SCHEMA,
            version: self.version.clone(),
            guest_source_fingerprint: self.fingerprints.guest_source.clone(),
            sdk_cdylib_source_fingerprint: self.fingerprints.sdk_cdylib.clone(),
            source: self.source.clone(),
            files: self
                .members
                .iter()
                .map(|(member, entry)| (member.clone(), sha256_hex(&entry.bytes)))
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
        for (member, entry) in &self.members {
            append_member(&mut tar, member, entry.mode, &entry.bytes)?;
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
/// list, a member path outside the layout, a listed member that is absent, a
/// member the manifest does not list, a non-regular or duplicated entry, or
/// any member whose bytes do not hash to the recorded digest.
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
            GuestBinsMember::parse(&member)?;
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
    for member in manifest.files.keys() {
        GuestBinsMember::parse(member)?;
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

/// Build (or reuse from cache) every guest artifact for each requested
/// architecture, add the Python SDK, and write the artifact.
pub fn build_guest_bins(build: &GuestBinsBuild) -> Result<WrittenGuestBins, GuestBinsError> {
    let fingerprints = GuestBinsFingerprints::of_tree(&build.workspace_root)?;
    // Read before anything compiles, so the identity names the tree the
    // compiles read.
    let source = crate::image_source::probe_identity(&build.workspace_root)
        .map_err(GuestBinsError::Source)?;
    let mut artifact = GuestBinsArtifact::new(&build.version, fingerprints, source);
    let arches: BTreeSet<GuestArch> = build.arches.iter().copied().collect();
    for arch in arches {
        add_arch(&mut artifact, build, arch)?;
    }
    for (member, path) in python_sdk::python_sdk_members(&build.workspace_root)? {
        artifact.add(&member, &path)?;
    }
    artifact.write(&build.out_dir)
}

/// Every compiled member for `arch`: the runtime-overlay set, the OCI entry
/// point that only the OCI runtime set carries, and the [`extras`].
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
        artifact.add(&GuestBinsMember::executable(arch, name)?, path)?;
    }
    let oci = guest_agent_build::resolve_or_build_guest_binaries(
        &build.cache_root,
        &guest_agent_build::source_cache_key(&build.workspace_root)?,
        arch,
        &build.workspace_root,
    )?;
    artifact.add(
        &GuestBinsMember::executable(arch, "mvm-oci-entrypoint")?,
        &oci.entrypoint_runner,
    )?;
    let extras = extras::resolve_or_build_guest_extras(
        &build.cache_root,
        &build.version,
        arch,
        &build.workspace_root,
    )?;
    for (member, path) in extras {
        artifact.add(&member, &path)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guest_agent_build::fake_static_elf;
    use mvm_contract::guest_libc::GuestLibc;
    use mvm_core::image_set::{GitCommit, WorktreeState};

    fn fingerprints() -> GuestBinsFingerprints {
        GuestBinsFingerprints {
            guest_source: "g".repeat(64),
            sdk_cdylib: "c".repeat(64),
        }
    }

    fn source() -> RepoIdentity {
        RepoIdentity {
            commit: GitCommit::new("a".repeat(40)).unwrap(),
            worktree: WorktreeState::Clean,
        }
    }

    fn new_artifact() -> GuestBinsArtifact {
        GuestBinsArtifact::new("1.2.3", fingerprints(), source())
    }

    fn write_bin(dir: &Path, name: &str, arch: GuestArch) -> PathBuf {
        std::fs::create_dir_all(dir).unwrap();
        let path = dir.join(format!("{arch}-{name}"));
        std::fs::write(&path, fake_static_elf(arch, name.as_bytes())).unwrap();
        path
    }

    fn exe(arch: GuestArch, name: &str) -> GuestBinsMember {
        GuestBinsMember::executable(arch, name).unwrap()
    }

    fn lib(arch: GuestArch, libc: GuestLibc, soname: &str) -> GuestBinsMember {
        GuestBinsMember::shared_object(arch, libc, soname).unwrap()
    }

    /// A shared object for `arch` recording `needed`, as a guest library.
    fn shared_object(arch: GuestArch, needed: &[&str]) -> Vec<u8> {
        let mut bytes = mvm_fs::elf::test_fixture::shared_object(needed);
        let machine: u16 = match arch {
            GuestArch::X86_64 => 0x3E,
            GuestArch::Aarch64 => 0xB7,
        };
        bytes[18..20].copy_from_slice(&machine.to_le_bytes());
        bytes
    }

    fn write_file(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
        std::fs::create_dir_all(dir).unwrap();
        let path = dir.join(name);
        std::fs::write(&path, bytes).unwrap();
        path
    }

    /// One member of every kind, for both architectures.
    fn two_arch_artifact(dir: &Path) -> GuestBinsArtifact {
        let mut artifact = new_artifact();
        for arch in [GuestArch::Aarch64, GuestArch::X86_64] {
            for name in ["mvm-guest-agent", "mvm-guest-netinit"] {
                artifact
                    .add(&exe(arch, name), &write_bin(dir, name, arch))
                    .unwrap();
            }
            artifact
                .add(
                    &GuestBinsMember::InitramfsAgent { arch },
                    &write_bin(dir, "initramfs-agent", arch),
                )
                .unwrap();
            let so = write_file(
                dir,
                &format!("{arch}-libcuda-musl"),
                &shared_object(arch, &["libgcc_s.so.1", "libc.so"]),
            );
            artifact
                .add(&lib(arch, GuestLibc::Musl, "libcuda.so.1"), &so)
                .unwrap();
        }
        let py = write_file(dir, "host.py", b"def time(): pass\n");
        artifact
            .add(&GuestBinsMember::python_sdk("host.py").unwrap(), &py)
            .unwrap();
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
        assert_eq!(written.manifest.source, source());
        assert_eq!(
            written.manifest.files.keys().collect::<Vec<_>>(),
            [
                "aarch64/bin/mvm-guest-agent",
                "aarch64/bin/mvm-guest-netinit",
                "aarch64/initramfs/mvm-guest-agent",
                "aarch64/lib/musl/libcuda.so.1",
                "sdk-py/mvm/host.py",
                "x86_64/bin/mvm-guest-agent",
                "x86_64/bin/mvm-guest-netinit",
                "x86_64/initramfs/mvm-guest-agent",
                "x86_64/lib/musl/libcuda.so.1",
            ]
        );
        assert_eq!(
            written.manifest.files["x86_64/bin/mvm-guest-agent"],
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
    fn the_same_inputs_produce_the_same_archive_bytes() {
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
    fn executables_are_archived_executable_and_libraries_and_sources_are_not() {
        let tmp = tempfile::tempdir().unwrap();
        let bytes = two_arch_artifact(tmp.path()).to_bytes().unwrap();
        let mut tar = tar::Archive::new(GzDecoder::new(bytes.as_slice()));
        let modes: BTreeMap<String, u32> = tar
            .entries()
            .unwrap()
            .map(|entry| {
                let entry = entry.unwrap();
                (
                    entry.path().unwrap().to_string_lossy().into_owned(),
                    entry.header().mode().unwrap(),
                )
            })
            .collect();
        assert_eq!(modes["aarch64/bin/mvm-guest-agent"], 0o755);
        assert_eq!(modes["aarch64/initramfs/mvm-guest-agent"], 0o755);
        assert_eq!(modes["aarch64/lib/musl/libcuda.so.1"], 0o644);
        assert_eq!(modes["sdk-py/mvm/host.py"], 0o644);
    }

    #[test]
    fn a_tampered_member_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let written = two_arch_artifact(tmp.path()).write(tmp.path()).unwrap();
        rewrite(&written.archive, |members| {
            members
                .get_mut("aarch64/lib/musl/libcuda.so.1")
                .unwrap()
                .push(0xff);
        });
        let err = verify_guest_bins_archive(&written.archive).unwrap_err();
        assert!(
            matches!(&err, GuestBinsError::DigestMismatch { member, .. } if member == "aarch64/lib/musl/libcuda.so.1"),
            "{err}"
        );
    }

    #[test]
    fn a_missing_member_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let written = two_arch_artifact(tmp.path()).write(tmp.path()).unwrap();
        rewrite(&written.archive, |members| {
            members.remove("x86_64/bin/mvm-guest-netinit");
        });
        let err = verify_guest_bins_archive(&written.archive).unwrap_err();
        assert!(
            matches!(&err, GuestBinsError::MissingMember(m) if m == "x86_64/bin/mvm-guest-netinit"),
            "{err}"
        );
    }

    #[test]
    fn an_unlisted_member_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let written = two_arch_artifact(tmp.path()).write(tmp.path()).unwrap();
        rewrite(&written.archive, |members| {
            members.insert("x86_64/bin/extra".into(), b"smuggled".to_vec());
        });
        let err = verify_guest_bins_archive(&written.archive).unwrap_err();
        assert!(
            matches!(&err, GuestBinsError::UnlistedMember(m) if m == "x86_64/bin/extra"),
            "{err}"
        );
    }

    /// A member outside the layout is refused before its digest is compared,
    /// including one listed in the manifest — the path itself is the hazard.
    #[test]
    fn a_member_outside_the_layout_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let written = two_arch_artifact(tmp.path()).write(tmp.path()).unwrap();
        rewrite(&written.archive, |members| {
            members.insert("x86_64/etc/profile".into(), b"x".to_vec());
        });
        assert!(matches!(
            verify_guest_bins_archive(&written.archive),
            Err(GuestBinsError::Member(MemberError::UnknownLayout(_)))
        ));

        let written = two_arch_artifact(tmp.path()).write(tmp.path()).unwrap();
        let mut manifest = written.manifest.clone();
        let digest = manifest.files["x86_64/bin/mvm-guest-agent"].clone();
        manifest
            .files
            .insert("x86_64/mvm-guest-agent".into(), digest);
        rewrite(&written.archive, |members| {
            let agent = members["x86_64/bin/mvm-guest-agent"].clone();
            members.insert("x86_64/mvm-guest-agent".into(), agent);
            members.insert(
                GUEST_BINS_MANIFEST_FILE.into(),
                serde_json::to_vec(&manifest).unwrap(),
            );
        });
        assert!(matches!(
            verify_guest_bins_archive(&written.archive),
            Err(GuestBinsError::Member(MemberError::UnknownLayout(_)))
        ));
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
        assert!(matches!(
            new_artifact().to_bytes(),
            Err(GuestBinsError::Empty)
        ));
    }

    #[test]
    fn a_wrong_architecture_binary_is_refused_at_add() {
        let tmp = tempfile::tempdir().unwrap();
        let x86 = write_bin(tmp.path(), "mvm-guest-agent", GuestArch::X86_64);
        let err = new_artifact()
            .add(&exe(GuestArch::Aarch64, "mvm-guest-agent"), &x86)
            .unwrap_err();
        assert!(matches!(err, GuestBinsError::InvalidMember { .. }), "{err}");
    }

    #[test]
    fn a_duplicate_member_is_refused_at_add() {
        let tmp = tempfile::tempdir().unwrap();
        let bin = write_bin(tmp.path(), "mvm-guest-agent", GuestArch::X86_64);
        let mut artifact = new_artifact();
        let member = exe(GuestArch::X86_64, "mvm-guest-agent");
        artifact.add(&member, &bin).unwrap();
        assert!(matches!(
            artifact.add(&member, &bin),
            Err(GuestBinsError::DuplicateMember(_))
        ));
    }

    /// The library check, end to end through `add`: each refusal names the
    /// member, and only a libc-matched object with allowed needs is admitted.
    #[test]
    fn shared_objects_are_checked_against_their_libc_and_arch() {
        let tmp = tempfile::tempdir().unwrap();
        let add = |member: GuestBinsMember, bytes: Vec<u8>| {
            let path = write_file(tmp.path(), "candidate.so", &bytes);
            new_artifact().add(&member, &path)
        };
        let x86 = GuestArch::X86_64;
        let glibc = lib(x86, GuestLibc::Glibc, "libmvm_host_services.so");
        let musl = lib(x86, GuestLibc::Musl, "libmvm_host_services.so");

        // Admitted: what the zig and Nix builds each produce.
        add(
            glibc.clone(),
            shared_object(x86, &["libpthread.so.0", "libc.so.6"]),
        )
        .unwrap();
        add(
            glibc.clone(),
            shared_object(x86, &["libgcc_s.so.1", "libc.so.6", "ld-linux-x86-64.so.2"]),
        )
        .unwrap();
        add(musl.clone(), shared_object(x86, &["libc.so"])).unwrap();
        add(
            musl.clone(),
            shared_object(x86, &["libgcc_s.so.1", "libc.so"]),
        )
        .unwrap();

        let refusals = [
            // Wrong architecture.
            (
                glibc.clone(),
                shared_object(GuestArch::Aarch64, &["libc.so.6"]),
                "machine",
            ),
            // A static executable offered as a library.
            (
                musl.clone(),
                fake_static_elf(x86, b"exe"),
                "not a shared object",
            ),
            // A glibc object filed as musl, and the reverse.
            (musl.clone(), shared_object(x86, &["libc.so.6"]), "libc.so"),
            (glibc.clone(), shared_object(x86, &["libc.so"]), "libc.so.6"),
            // No libc at all.
            (musl.clone(), shared_object(x86, &[]), "libc.so"),
            // A need the guest may not carry.
            (
                glibc.clone(),
                shared_object(x86, &["libc.so.6", "libssl.so.3"]),
                "libssl.so.3",
            ),
            (
                musl.clone(),
                shared_object(x86, &["libc.so", "libpthread.so.0"]),
                "libpthread.so.0",
            ),
            // Another arch's loader.
            (
                glibc.clone(),
                shared_object(x86, &["libc.so.6", "ld-linux-aarch64.so.1"]),
                "ld-linux-aarch64.so.1",
            ),
        ];
        for (member, bytes, expected) in refusals {
            let err = add(member.clone(), bytes).unwrap_err();
            assert!(
                matches!(&err, GuestBinsError::InvalidMember { member: m, .. } if *m == member.path()),
                "{err}"
            );
            assert!(err.to_string().contains(expected), "{expected}: {err}");
        }
    }

    fn git(dir: &Path, args: &[&str]) {
        let status = std::process::Command::new("git")
            .args(args)
            .current_dir(dir)
            .env_remove("GIT_DIR")
            .env_remove("GIT_WORK_TREE")
            .env_remove("GIT_INDEX_FILE")
            .status()
            .unwrap();
        assert!(status.success(), "git {args:?}");
    }

    /// The manifest names the commit, and a tree that differs from it says so
    /// instead of passing as that commit.
    #[test]
    fn the_manifest_records_the_commit_and_a_dirty_tree_as_dirty() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        git(&repo, &["init", "-q"]);
        git(&repo, &["config", "user.email", "test@example.invalid"]);
        git(&repo, &["config", "user.name", "test"]);
        git(&repo, &["config", "commit.gpgsign", "false"]);
        git(&repo, &["config", "core.hooksPath", "/dev/null"]);
        std::fs::write(repo.join("a.txt"), "one\n").unwrap();
        git(&repo, &["add", "a.txt"]);
        git(&repo, &["commit", "-q", "-m", "one"]);

        let record = |dir: &Path| {
            let source = crate::image_source::probe_identity(&repo).unwrap();
            let mut artifact = GuestBinsArtifact::new("1.2.3", fingerprints(), source);
            artifact
                .add(
                    &exe(GuestArch::X86_64, "mvm-guest-agent"),
                    &write_bin(dir, "mvm-guest-agent", GuestArch::X86_64),
                )
                .unwrap();
            let written = artifact.write(dir).unwrap();
            verify_guest_bins_archive(&written.archive).unwrap()
        };

        let clean = record(&tmp.path().join("clean"));
        assert_eq!(clean.source.worktree, WorktreeState::Clean);
        assert_eq!(clean.source.commit.as_str().len(), 40);

        std::fs::write(repo.join("a.txt"), "two\n").unwrap();
        let dirty = record(&tmp.path().join("dirty"));
        assert_eq!(dirty.source.commit, clean.source.commit);
        assert!(dirty.source.worktree.is_dirty(), "{:?}", dirty.source);

        let json = serde_json::to_value(&dirty).unwrap();
        assert_eq!(json["source"]["worktree"]["state"], "dirty");
        assert_eq!(json["source"]["commit"], clean.source.commit.as_str());
    }

    /// Seed every guest-build cache the producer reads, so the test drives the
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
        let key = guest_agent_build::source_cache_key(workspace).unwrap();
        let oci = guest_agent_build::GuestAgentLayout::under(cache_root, &key, arch);
        for path in [
            &o.agent,
            &o.netinit,
            &o.seccomp_apply,
            &o.display_bridge,
            &o.runner,
            &o.egress_client,
            &o.addon_dns,
            &o.exit_report,
            &o.ping,
            &o.tool_shim,
            &o.tool_helper,
            &oci.agent,
            &oci.netinit,
            &oci.egress_client,
            &oci.entrypoint_runner,
        ] {
            write_file(
                path.parent().unwrap(),
                &path.file_name().unwrap().to_string_lossy(),
                &fake_static_elf(arch, path.to_string_lossy().as_bytes()),
            );
        }
        let extras = extras::GuestExtrasLayout::under(
            cache_root,
            version,
            arch,
            &extras::extras_source_fingerprint(workspace).unwrap(),
        );
        for build in extras::extra_builds(arch).unwrap() {
            let path = extras.path_of(&build.member);
            let bytes = match &build.member {
                GuestBinsMember::SharedObject { libc, .. } => {
                    shared_object(arch, &[libc.libc_soname().unwrap()])
                }
                _ => fake_static_elf(arch, path.to_string_lossy().as_bytes()),
            };
            write_file(
                path.parent().unwrap(),
                &path.file_name().unwrap().to_string_lossy(),
                &bytes,
            );
        }
    }

    #[test]
    fn the_producer_records_the_producing_tree_and_every_member() {
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
        assert_eq!(
            written.manifest.source.commit,
            crate::image_source::probe_identity(&workspace)
                .unwrap()
                .commit
        );
        let files = &written.manifest.files;
        for arch in ["aarch64", "x86_64"] {
            let mut expected: Vec<String> = [
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
                "mvm-setpriv",
                "mvm-tool-shim",
                "mvm-tool-helper",
            ]
            .iter()
            .map(|name| format!("{arch}/bin/{name}"))
            .collect();
            expected.push(format!("{arch}/initramfs/mvm-guest-agent"));
            for libc in ["glibc", "musl"] {
                for cdylib in guest_cdylibs() {
                    expected.push(format!("{arch}/lib/{libc}/{}", cdylib.soname));
                }
            }
            for member in &expected {
                assert!(
                    files.contains_key(member),
                    "{member} missing from {files:?}"
                );
            }
            assert_eq!(
                files.keys().filter(|k| k.starts_with(arch)).count(),
                expected.len(),
                "a repeated --arch adds nothing"
            );
        }
        let python = files
            .keys()
            .filter(|k| k.starts_with("sdk-py/mvm/"))
            .count();
        assert_eq!(
            python,
            python_sdk::python_sdk_members(&workspace).unwrap().len()
        );
        assert!(files.contains_key("sdk-py/mvm/__init__.py"));
    }
}
