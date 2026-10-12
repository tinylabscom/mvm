//! Synthetic unsigned source-cache bytes for downstream launch verifier tests.
//! This module never constructs checked evidence or bypasses channel policy.

use super::*;

/// Write a complete synthetic member archive and its ordinary source pointer.
/// The returned runtime is untrusted input, not permission to launch. Binaries
/// contain fixture bytes and must never be executed. Callers may assemble these
/// bytes with the ordinary public overlay/initramfs assemblers, then invoke the
/// real verifier (which still refuses source caches in a release-channel build).
pub fn write_source_cache_fixture(
    cache: &Path,
    workspace: &Path,
    version: &str,
    arch: GuestArch,
) -> Result<GuestRuntime, GuestRuntimeError> {
    let mut members = BTreeSet::new();
    for name in guest_agent_build::RUNTIME_OVERLAY_SEALED_BINS
        .into_iter()
        .chain(guest_agent_build::RUNTIME_OVERLAY_ADDON_BINS)
        .chain(["mvm-oci-entrypoint", "mvm-setpriv"])
    {
        members.insert(GuestBinsMember::executable(arch, name)?.path());
    }
    members.insert(GuestBinsMember::InitramfsAgent { arch }.path());
    for libc in [GuestLibc::Glibc, GuestLibc::Musl] {
        for library in [HOST_SERVICES_CDYLIB].into_iter().chain(GPU_SHIM_CDYLIBS) {
            members.insert(GuestBinsMember::shared_object(arch, libc, library.soname)?.path());
        }
    }
    for (member, _) in guest_bins::python_sdk::python_sdk_members(workspace)? {
        members.insert(member.path());
    }
    let manifest = GuestBinsManifest {
        schema_version: 1,
        version: version.to_owned(),
        guest_source_fingerprint: guest_agent_build::guest_source_fingerprint(workspace)?,
        sdk_cdylib_source_fingerprint: guest_agent_build::sdk_cdylib_source_fingerprint(workspace)?,
        source: crate::image_source::RepoIdentity {
            commit: mvm_core::image_set::GitCommit::new("c".repeat(40))
                .map_err(|error| GuestRuntimeError::Cache(error.to_string()))?,
            worktree: mvm_core::image_set::WorktreeState::Clean,
        },
        files: members
            .iter()
            .map(|member| (member.clone(), hex::encode(Sha256::digest(b"fixture"))))
            .collect(),
        assemblies: Default::default(),
    };
    let stage = tempfile::tempdir()?;
    let input = stage.path().join("fixture.tar.gz");
    let gz = flate2::GzBuilder::new()
        .mtime(0)
        .write(File::create(&input)?, flate2::Compression::fast());
    let mut tar = tar::Builder::new(gz);
    append(
        &mut tar,
        GUEST_BINS_MANIFEST_FILE,
        &serde_json::to_vec(&manifest).map_err(GuestBinsError::from)?,
    )?;
    for member in members {
        append(&mut tar, &member, b"fixture")?;
    }
    tar.into_inner()?.finish()?;
    let base = cache.join("guest-runtime/v1");
    let runtime = super::install_archive(&base, &input, version, arch)?;
    fs::create_dir_all(base.join("sources"))?;
    fs::write(
        base.join("sources")
            .join(super::source_fingerprint(version, arch, workspace)?),
        &runtime.digest,
    )?;
    Ok(runtime)
}

fn append(
    tar: &mut tar::Builder<flate2::write::GzEncoder<File>>,
    name: &str,
    bytes: &[u8],
) -> Result<(), std::io::Error> {
    let mut header = tar::Header::new_gnu();
    header.set_path(name)?;
    header.set_entry_type(EntryType::Regular);
    header.set_size(bytes.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    tar.append(&header, bytes)
}
