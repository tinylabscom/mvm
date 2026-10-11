//! What the host checks in a builder VM's output before it uses or signs it.
//!
//! The builder guest runs whatever a flake's derivations do, so everything it
//! leaves in the output directory is untrusted. Every transport hands that
//! output back as a tar the host extracts, and a tar can carry symbolic links.
//! A `rootfs.ext4` that is a link to a host file would, if the host followed
//! it, put that file into the template cache, or into a `.mvmpkg` signed under
//! the host's key. The host signing key is exactly such a file.
//!
//! So the host reads builder output only as regular files it finds by name in
//! the output directory, never through a link, and never a device, FIFO or
//! socket. [`require_regular_member`] is that rule for one file.
//!
//! [`verify_builder_output`] applies it to every member a bundle carries, then
//! checks what the runtime and the bundle format need of them: the sidecar
//! admits the runtime-overlay contract the runtime enforces at boot, and a
//! dm-verity pair is either whole and well formed or absent. Its result,
//! [`VerifiedBuilderOutput`], has no other constructor, so code that signs
//! builder output and takes one cannot be handed output nobody checked.
//!
//! None of this has to guard against the guest changing the files afterwards:
//! the host only reads output the guest wrote into a tar before it powered
//! off, extracted into a directory the guest never had a handle on.

use std::path::{Path, PathBuf};

use anyhow::Result;

use crate::builder_job_contract::FailureCategory;
use crate::builder_orchestrator::BuilderResult;
use crate::builder_vm::BuilderVmError;

/// The initrd a build may leave beside its rootfs.
pub const INITRD_FILENAME: &str = "initrd";
/// The dm-verity hash tree a sealed build leaves beside its rootfs.
pub const VERITY_TREE_FILENAME: &str = "rootfs.verity";
/// The dm-verity root hash a sealed build leaves beside its rootfs.
pub const VERITY_ROOTHASH_FILENAME: &str = "rootfs.roothash";
/// The store paths an image's rootfs closure was built from, when the image
/// records them.
pub const CLOSURE_PATHS_FILENAME: &str = "rootfs-closure-paths";
/// A flake-emitted image manifest, when the image carries one.
pub const MANIFEST_FILENAME: &str = "manifest.json";

/// What every build script copies verbatim out of a directory Nix output,
/// beside the rootfs, when the output has it.
///
/// The rootfs, kernel and guest sidecar are not on the list: each has its own
/// handling (the rootfs is rewritten by the `before_build` hook and the journal
/// seal, the kernel is accepted under three names, the sidecar can be derived
/// from `passthru`). Nor is the dm-verity pair: a pair the image built
/// covers the rootfs Nix produced, not the one the build ships, so no script
/// copies it; the host computes one over the shipped bytes instead
/// ([`seal_declared_rootfs`]).
pub const NIX_OUTPUT_MEMBERS: &[&str] =
    &[INITRD_FILENAME, CLOSURE_PATHS_FILENAME, MANIFEST_FILENAME];

/// The shell that copies [`NIX_OUTPUT_MEMBERS`] from the Nix output directory
/// `src` into `out_dir`. Both arguments are shell words, already quoted.
///
/// Every builder script splices this in, so one-shot and persistent builds
/// return the same member set.
pub fn copy_nix_output_members_sh(src: &str, out_dir: &str) -> String {
    format!(
        "if [ -d {src} ]; then\n\
         \x20   for member in {members}; do\n\
         \x20       if [ -f {src}/\"$member\" ]; then\n\
         \x20           cp -L {src}/\"$member\" {out_dir}/\"$member\"\n\
         \x20       fi\n\
         \x20   done\n\
         fi\n",
        members = NIX_OUTPUT_MEMBERS.join(" "),
    )
}

/// A builder output failure the guest caused: categorized as
/// [`FailureCategory::OutputContract`] so a caller can tell it from a build or
/// VMM failure without reading the text.
pub(crate) fn output_contract(detail: String) -> BuilderVmError {
    BuilderVmError::JobFailed {
        category: FailureCategory::OutputContract,
        detail,
    }
}

/// Refuse `path` unless it is a regular file, inspected without following a
/// link. A missing file is refused too; see [`regular_member_if_present`] for
/// members a build may leave out.
pub fn require_regular_member(path: &Path) -> Result<(), BuilderVmError> {
    regular_member_if_present(path)?.map(|_| ()).ok_or_else(|| {
        output_contract(format!(
            "the build did not write {}; the host needs it as a regular file",
            path.display()
        ))
    })
}

/// `Some(path)` when `path` is a regular file, `None` when nothing is there,
/// and a refusal for anything else: a symbolic link, a directory, a device, a
/// FIFO or a socket.
pub fn regular_member_if_present(path: &Path) -> Result<Option<PathBuf>, BuilderVmError> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(output_contract(format!(
                "inspecting builder output {}: {e}",
                path.display()
            )));
        }
    };
    let kind = metadata.file_type();
    if kind.is_file() {
        return Ok(Some(path.to_path_buf()));
    }
    let what = if kind.is_symlink() {
        "a symbolic link; the host reads builder output only as regular files, never \
         through a link the guest chose"
    } else if kind.is_dir() {
        "a directory, not a file"
    } else {
        "a special file, not a regular one"
    };
    Err(output_contract(format!(
        "builder output {} is {what}",
        path.display()
    )))
}

/// A dm-verity pair a build produced, both halves present and well formed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedVerity {
    hash_tree: PathBuf,
    roothash: String,
}

impl VerifiedVerity {
    /// The hash tree file.
    pub fn hash_tree(&self) -> &Path {
        &self.hash_tree
    }

    /// The root hash, 64 hex characters.
    pub fn roothash(&self) -> &str {
        &self.roothash
    }
}

/// Builder output the host has checked, member by member.
///
/// The only way to get one is [`verify_builder_output`], so a function that
/// takes one cannot be handed output that skipped the check:
///
/// ```compile_fail
/// use mvm_build::builder_output::VerifiedBuilderOutput;
///
/// fn forged(build: mvm_build::builder_orchestrator::BuilderResult) -> VerifiedBuilderOutput {
///     VerifiedBuilderOutput { build, initrd: None, verity: None }
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedBuilderOutput {
    build: BuilderResult,
    initrd: Option<PathBuf>,
    verity: Option<VerifiedVerity>,
}

impl VerifiedBuilderOutput {
    /// The build these members came from.
    pub fn build(&self) -> &BuilderResult {
        &self.build
    }

    /// The rootfs image, a regular file.
    pub fn rootfs(&self) -> &Path {
        &self.build.rootfs_path
    }

    /// The kernel, a regular file beside the rootfs, when the flake built one.
    pub fn kernel(&self) -> Option<&Path> {
        self.build.kernel_path.as_deref()
    }

    /// The guest sidecar, a regular file that admits the runtime-overlay
    /// contract.
    pub fn sidecar(&self) -> &Path {
        &self.build.sidecar_path
    }

    /// The initrd beside the rootfs, when the build left one.
    pub fn initrd(&self) -> Option<&Path> {
        self.initrd.as_deref()
    }

    /// The dm-verity pair beside the rootfs, when the build sealed it.
    pub fn verity(&self) -> Option<&VerifiedVerity> {
        self.verity.as_ref()
    }
}

/// Check every member of `build` the host would read, and return it as
/// [`VerifiedBuilderOutput`].
///
/// Each member must be a regular file in the rootfs's own directory. The
/// sidecar must admit the runtime-overlay contract, the same gate a boot
/// applies, so a bundle cannot be sealed around a rootfs the runtime would
/// refuse. A dm-verity pair must be complete and its root hash well formed:
/// the alternative is exporting a rootfs the build meant to seal as an
/// unsealed one, without saying so.
///
/// A failure is a [`BuilderVmError::JobFailed`] with
/// [`FailureCategory::OutputContract`].
pub fn verify_builder_output(build: &BuilderResult) -> Result<VerifiedBuilderOutput> {
    let dir = output_dir(&build.rootfs_path)?;
    require_regular_member(&build.rootfs_path)?;
    if let Some(kernel) = &build.kernel_path {
        require_member_of(dir, kernel)?;
        require_regular_member(kernel)?;
    }
    require_member_of(dir, &build.sidecar_path)?;
    require_regular_member(&build.sidecar_path)?;
    admit_sidecar(dir)?;
    let initrd = regular_member_if_present(&dir.join(INITRD_FILENAME))?;
    let verity = verity_pair(&build.rootfs_path, dir)?;
    Ok(VerifiedBuilderOutput {
        build: build.clone(),
        initrd,
        verity,
    })
}

fn output_dir(rootfs: &Path) -> Result<&Path, BuilderVmError> {
    rootfs
        .parent()
        .filter(|dir| !dir.as_os_str().is_empty())
        .ok_or_else(|| {
            output_contract(format!(
                "rootfs path {} has no parent directory",
                rootfs.display()
            ))
        })
}

/// The host finds members by name in one directory; a member reported
/// anywhere else is not output it looked for.
fn require_member_of(dir: &Path, member: &Path) -> Result<(), BuilderVmError> {
    if member.parent() == Some(dir) {
        return Ok(());
    }
    Err(output_contract(format!(
        "builder output {} is outside the output directory {}",
        member.display(),
        dir.display()
    )))
}

fn admit_sidecar(dir: &Path) -> Result<(), BuilderVmError> {
    crate::builder_vm::admit_runtime_overlay_contract(dir)
        .map_err(|e| output_contract(format!("the build's guest sidecar would not boot: {e:#}")))
}

/// Both halves or neither. The root hash is read with the same probe a boot
/// uses, so what passes here is what the runtime would attach.
fn verity_pair(rootfs: &Path, dir: &Path) -> Result<Option<VerifiedVerity>, BuilderVmError> {
    let tree = regular_member_if_present(&dir.join(VERITY_TREE_FILENAME))?;
    let roothash_file = regular_member_if_present(&dir.join(VERITY_ROOTHASH_FILENAME))?;
    match (tree, roothash_file) {
        (None, None) => Ok(None),
        (Some(_), Some(roothash_file)) => {
            let rootfs = rootfs.to_str().ok_or_else(|| {
                output_contract(format!("rootfs path {} is not UTF-8", rootfs.display()))
            })?;
            match mvm_vmm::host::boot_config::probe_verity_sidecar(rootfs) {
                (Some(hash_tree), Some(roothash)) => Ok(Some(VerifiedVerity {
                    hash_tree: PathBuf::from(hash_tree),
                    roothash,
                })),
                _ => Err(output_contract(format!(
                    "{} is not a 64-hex dm-verity root hash",
                    roothash_file.display()
                ))),
            }
        }
        (Some(present), None) | (None, Some(present)) => Err(output_contract(format!(
            "the build left {} without the other half of its dm-verity pair \
             ({VERITY_TREE_FILENAME} and {VERITY_ROOTHASH_FILENAME} travel together)",
            present.display()
        ))),
    }
}

/// Give the rootfs in `dir` the dm-verity pair its sidecar asks for.
///
/// When the guest sidecar beside it says `sealed: true`, the pair is computed
/// here, over the rootfs bytes the host received, with the same in-process
/// writer and pinned block sizes every other sealed image uses. Returns the
/// root hash it wrote, or `None` for an image that is not sealed.
///
/// Whatever the guest left at either verity name is removed first, sealed
/// image or not. The host is the only party that writes the pair: a pair the
/// guest supplied could describe any bytes, and one written through a link the
/// guest planted would land wherever the link points.
///
/// A sidecar that is missing is not an error here; [`verify_builder_output`]
/// refuses it. One that is a link or cannot be parsed is an
/// [`FailureCategory::OutputContract`] failure.
pub fn seal_declared_rootfs(dir: &Path) -> Result<Option<String>, BuilderVmError> {
    for name in [VERITY_TREE_FILENAME, VERITY_ROOTHASH_FILENAME] {
        discard_guest_member(&dir.join(name))?;
    }
    if !sidecar_declares_sealed(dir)? {
        return Ok(None);
    }
    let rootfs = dir.join("rootfs.ext4");
    require_regular_member(&rootfs)?;
    crate::rootfs::emit_verity_sidecars(&rootfs)
        .map(Some)
        .map_err(|e| {
            BuilderVmError::ExtractionFailed(format!(
                "computing the dm-verity pair for {}: {e}",
                rootfs.display()
            ))
        })
}

/// Remove `path` without following it. A directory there is refused: nothing
/// the host writes may be a directory, and removing a guest-built tree
/// recursively is not this function's business.
fn discard_guest_member(path: &Path) -> Result<(), BuilderVmError> {
    match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(output_contract(format!(
            "inspecting builder output {}: {e}",
            path.display()
        ))),
        Ok(metadata) if metadata.is_dir() => Err(output_contract(format!(
            "builder output {} is a directory, not a file",
            path.display()
        ))),
        Ok(_) => std::fs::remove_file(path).map_err(|e| {
            BuilderVmError::ExtractionFailed(format!("removing {}: {e}", path.display()))
        }),
    }
}

/// Only the one field is read, so a sidecar from any mkGuest generation that
/// carries it can be sealed; the full contract is checked by
/// [`verify_builder_output`] and at boot.
#[derive(serde::Deserialize)]
struct SealedSidecar {
    #[serde(default)]
    sealed: bool,
}

fn sidecar_declares_sealed(dir: &Path) -> Result<bool, BuilderVmError> {
    let path = dir.join(crate::builder_vm::SIDECAR_FILENAME);
    let Some(path) = regular_member_if_present(&path)? else {
        return Ok(false);
    };
    let body = std::fs::read(&path)
        .map_err(|e| output_contract(format!("reading {}: {e}", path.display())))?;
    serde_json::from_slice::<SealedSidecar>(&body)
        .map(|sidecar| sidecar.sealed)
        .map_err(|e| output_contract(format!("parsing {}: {e}", path.display())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder_orchestrator::{BuildLogs, BuildTimings, failure_category};
    use crate::builder_vm::SIDECAR_FILENAME;

    const ROOTHASH: &str = "abababababababababababababababababababababababababababababababab";
    const ADMITTED_SIDECAR: &[u8] = br#"{"overlayAware":true,"runtimeLean":true}"#;

    fn build_in(dir: &Path, kernel: bool) -> BuilderResult {
        std::fs::write(dir.join("rootfs.ext4"), b"rootfs").unwrap();
        std::fs::write(dir.join(SIDECAR_FILENAME), ADMITTED_SIDECAR).unwrap();
        if kernel {
            std::fs::write(dir.join("vmlinux"), b"kernel").unwrap();
        }
        BuilderResult {
            rootfs_path: dir.join("rootfs.ext4"),
            kernel_path: kernel.then(|| dir.join("vmlinux")),
            sidecar_path: dir.join(SIDECAR_FILENAME),
            revision_hash: "abc".to_string(),
            lock_hash: None,
            accessible: None,
            timings: BuildTimings {
                total_ms: 1,
                build_ms: None,
                boot: None,
            },
            logs: BuildLogs {
                stderr: None,
                stdout: None,
                stderr_tail: String::new(),
            },
        }
    }

    fn refusal(build: &BuilderResult) -> String {
        let err = verify_builder_output(build).expect_err("refused");
        assert_eq!(failure_category(&err), FailureCategory::OutputContract);
        format!("{err:#}")
    }

    fn replace_with_link(path: &Path, target: &Path) {
        std::fs::remove_file(path).unwrap();
        std::os::unix::fs::symlink(target, path).unwrap();
    }

    #[test]
    fn a_complete_output_verifies_with_its_optional_members() {
        let dir = tempfile::tempdir().unwrap();
        let build = build_in(dir.path(), true);
        std::fs::write(dir.path().join(INITRD_FILENAME), b"initrd").unwrap();
        std::fs::write(dir.path().join(VERITY_TREE_FILENAME), b"tree").unwrap();
        std::fs::write(
            dir.path().join(VERITY_ROOTHASH_FILENAME),
            format!("{ROOTHASH}\n"),
        )
        .unwrap();

        let verified = verify_builder_output(&build).expect("verifies");

        assert_eq!(verified.rootfs(), build.rootfs_path);
        assert_eq!(verified.kernel(), build.kernel_path.as_deref());
        assert_eq!(verified.sidecar(), build.sidecar_path);
        assert_eq!(
            verified.initrd(),
            Some(dir.path().join(INITRD_FILENAME).as_path())
        );
        let verity = verified.verity().expect("verity pair");
        assert_eq!(verity.roothash(), ROOTHASH);
        assert_eq!(verity.hash_tree(), dir.path().join(VERITY_TREE_FILENAME));
    }

    #[test]
    fn an_output_without_optional_members_verifies_without_them() {
        let dir = tempfile::tempdir().unwrap();
        let verified = verify_builder_output(&build_in(dir.path(), false)).expect("verifies");
        assert_eq!(verified.kernel(), None);
        assert_eq!(verified.initrd(), None);
        assert_eq!(verified.verity(), None);
    }

    #[test]
    fn a_rootfs_that_links_to_a_host_file_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let host = tempfile::tempdir().unwrap();
        let key = host.path().join("host-signer.ed25519");
        std::fs::write(&key, [7u8; 32]).unwrap();
        let build = build_in(dir.path(), true);
        replace_with_link(&build.rootfs_path, &key);

        assert!(refusal(&build).contains("symbolic link"));
    }

    #[test]
    fn every_member_is_held_to_the_regular_file_rule() {
        for member in [
            "vmlinux",
            SIDECAR_FILENAME,
            INITRD_FILENAME,
            VERITY_TREE_FILENAME,
        ] {
            let dir = tempfile::tempdir().unwrap();
            let build = build_in(dir.path(), true);
            std::fs::write(dir.path().join(INITRD_FILENAME), b"initrd").unwrap();
            std::fs::write(dir.path().join(VERITY_TREE_FILENAME), b"tree").unwrap();
            std::fs::write(dir.path().join(VERITY_ROOTHASH_FILENAME), ROOTHASH).unwrap();
            let elsewhere = dir.path().join("elsewhere");
            std::fs::copy(dir.path().join(member), &elsewhere).unwrap();
            replace_with_link(&dir.path().join(member), &elsewhere);

            let message = refusal(&build);
            assert!(message.contains("symbolic link"), "{member}: {message}");
        }
    }

    #[test]
    fn a_directory_or_fifo_where_a_member_belongs_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let build = build_in(dir.path(), false);
        std::fs::create_dir(dir.path().join(INITRD_FILENAME)).unwrap();
        assert!(refusal(&build).contains("a directory"));

        let dir = tempfile::tempdir().unwrap();
        let build = build_in(dir.path(), false);
        let fifo = dir.path().join(INITRD_FILENAME);
        let status = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap();
        assert!(status.success());
        assert!(refusal(&build).contains("special file"));
    }

    #[test]
    fn a_kernel_outside_the_output_directory_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let other = tempfile::tempdir().unwrap();
        let mut build = build_in(dir.path(), false);
        std::fs::write(other.path().join("vmlinux"), b"kernel").unwrap();
        build.kernel_path = Some(other.path().join("vmlinux"));

        assert!(refusal(&build).contains("outside the output directory"));
    }

    #[test]
    fn a_sidecar_the_runtime_would_refuse_is_refused_here() {
        let dir = tempfile::tempdir().unwrap();
        let build = build_in(dir.path(), false);
        std::fs::write(&build.sidecar_path, br#"{"overlayAware":false}"#).unwrap();

        assert!(refusal(&build).contains("would not boot"));
    }

    #[test]
    fn half_a_verity_pair_is_refused() {
        for present in [VERITY_TREE_FILENAME, VERITY_ROOTHASH_FILENAME] {
            let dir = tempfile::tempdir().unwrap();
            let build = build_in(dir.path(), false);
            std::fs::write(dir.path().join(present), ROOTHASH).unwrap();

            let message = refusal(&build);
            assert!(message.contains("other half"), "{present}: {message}");
        }
    }

    #[test]
    fn a_malformed_root_hash_is_refused_rather_than_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let build = build_in(dir.path(), false);
        std::fs::write(dir.path().join(VERITY_TREE_FILENAME), b"tree").unwrap();
        std::fs::write(dir.path().join(VERITY_ROOTHASH_FILENAME), b"not-hex").unwrap();

        assert!(refusal(&build).contains("64-hex"));
    }

    #[test]
    fn a_missing_member_is_named() {
        let dir = tempfile::tempdir().unwrap();
        let err = require_regular_member(&dir.path().join("rootfs.ext4")).unwrap_err();
        assert_eq!(err.failure_category(), FailureCategory::OutputContract);
        assert!(err.to_string().contains("rootfs.ext4"), "{err}");
    }

    const SEALED_SIDECAR: &[u8] = br#"{"overlayAware":true,"runtimeLean":true,"sealed":true}"#;

    /// Sixteen 4 KiB blocks of distinct bytes: enough for a two-block tree.
    fn image_bytes() -> Vec<u8> {
        (0..16 * 4096).map(|i| (i % 251) as u8).collect()
    }

    /// The root hash dm-verity would compute over `image` at boot.
    fn boot_root_hash(image: &[u8]) -> String {
        mvm_fs::ext4::verity::to_hex(&mvm_fs::ext4::verity::root_hash(
            image,
            &[0u8; 32],
            mvm_fs::oci_to_rootfs::MVM_VERITY_DATA_BLOCK_SIZE as usize,
            mvm_fs::oci_to_rootfs::MVM_VERITY_HASH_BLOCK_SIZE as usize,
        ))
    }

    fn sealed_output_in(dir: &Path) -> BuilderResult {
        let build = build_in(dir, true);
        std::fs::write(&build.rootfs_path, image_bytes()).unwrap();
        std::fs::write(&build.sidecar_path, SEALED_SIDECAR).unwrap();
        build
    }

    #[test]
    fn a_sealed_image_gets_a_pair_computed_over_the_rootfs_it_ships() {
        let dir = tempfile::tempdir().unwrap();
        let build = sealed_output_in(dir.path());

        let written = seal_declared_rootfs(dir.path())
            .expect("seals")
            .expect("the sidecar asked for a seal");

        let image = std::fs::read(&build.rootfs_path).unwrap();
        assert_eq!(written, boot_root_hash(&image));
        let verified = verify_builder_output(&build).expect("verifies");
        let verity = verified.verity().expect("the pair is carried");
        assert_eq!(verity.roothash(), written);
        let expected_tree = mvm_fs::ext4::verity::format(&image, &[0u8; 32], 4096, 4096).hash_tree;
        assert_eq!(std::fs::read(verity.hash_tree()).unwrap(), expected_tree);
    }

    #[test]
    fn a_rootfs_changed_after_sealing_no_longer_matches_its_root_hash() {
        let dir = tempfile::tempdir().unwrap();
        let build = sealed_output_in(dir.path());
        let written = seal_declared_rootfs(dir.path()).unwrap().unwrap();

        let mut tampered = std::fs::read(&build.rootfs_path).unwrap();
        tampered[5 * 4096 + 17] ^= 0x01;

        assert_ne!(boot_root_hash(&tampered), written);
    }

    #[test]
    fn a_pair_the_guest_left_is_replaced_by_the_one_the_host_computes() {
        let dir = tempfile::tempdir().unwrap();
        let build = sealed_output_in(dir.path());
        std::fs::write(dir.path().join(VERITY_TREE_FILENAME), b"guest tree").unwrap();
        std::fs::write(dir.path().join(VERITY_ROOTHASH_FILENAME), ROOTHASH).unwrap();

        let written = seal_declared_rootfs(dir.path()).unwrap().unwrap();

        assert_ne!(written, ROOTHASH);
        let verified = verify_builder_output(&build).unwrap();
        assert_eq!(verified.verity().unwrap().roothash(), written);
    }

    #[test]
    fn an_unsealed_image_is_left_unsealed_and_keeps_no_guest_pair() {
        let dir = tempfile::tempdir().unwrap();
        let build = build_in(dir.path(), false);
        std::fs::write(dir.path().join(VERITY_TREE_FILENAME), b"guest tree").unwrap();
        std::fs::write(dir.path().join(VERITY_ROOTHASH_FILENAME), ROOTHASH).unwrap();

        assert_eq!(seal_declared_rootfs(dir.path()).unwrap(), None);
        assert_eq!(verify_builder_output(&build).unwrap().verity(), None);
    }

    #[test]
    fn a_verity_link_the_guest_planted_is_removed_not_written_through() {
        let dir = tempfile::tempdir().unwrap();
        let host = tempfile::tempdir().unwrap();
        let victim = host.path().join("host-file");
        std::fs::write(&victim, b"host bytes").unwrap();
        sealed_output_in(dir.path());
        std::os::unix::fs::symlink(&victim, dir.path().join(VERITY_TREE_FILENAME)).unwrap();

        seal_declared_rootfs(dir.path()).unwrap().unwrap();

        assert_eq!(std::fs::read(&victim).unwrap(), b"host bytes");
        assert!(
            std::fs::symlink_metadata(dir.path().join(VERITY_TREE_FILENAME))
                .unwrap()
                .is_file()
        );
    }

    #[test]
    fn a_sidecar_link_is_refused_before_it_is_read() {
        let dir = tempfile::tempdir().unwrap();
        let build = sealed_output_in(dir.path());
        let elsewhere = dir.path().join("elsewhere");
        std::fs::copy(&build.sidecar_path, &elsewhere).unwrap();
        replace_with_link(&build.sidecar_path, &elsewhere);

        let err = seal_declared_rootfs(dir.path()).unwrap_err();
        assert_eq!(err.failure_category(), FailureCategory::OutputContract);
        assert!(err.to_string().contains("symbolic link"), "{err}");
    }

    #[test]
    fn the_member_copy_names_every_member_and_no_verity_file() {
        let sh = copy_nix_output_members_sh("\"$NIX_OUT\"", "/out");
        for member in NIX_OUTPUT_MEMBERS {
            assert!(sh.contains(member), "{member} missing from:\n{sh}");
        }
        assert!(sh.contains(INITRD_FILENAME), "{sh}");
        assert!(!sh.contains(VERITY_TREE_FILENAME), "{sh}");
        assert!(!sh.contains(VERITY_ROOTHASH_FILENAME), "{sh}");
    }

    #[test]
    fn the_typed_builder_exports_the_same_members_plus_the_sidecar() {
        let mut expected: Vec<&str> = NIX_OUTPUT_MEMBERS.to_vec();
        expected.push(crate::builder_vm::SIDECAR_FILENAME);
        assert_eq!(crate::builderd::EXPORTED_MEMBERS, expected.as_slice());
    }

    #[test]
    fn the_member_copy_runs_and_skips_what_the_output_does_not_have() {
        let nix_out = tempfile::tempdir().unwrap();
        let out = tempfile::tempdir().unwrap();
        std::fs::write(nix_out.path().join(INITRD_FILENAME), b"initrd").unwrap();
        std::fs::write(nix_out.path().join(VERITY_TREE_FILENAME), b"nix tree").unwrap();
        let sh = copy_nix_output_members_sh(
            &format!("'{}'", nix_out.path().display()),
            &format!("'{}'", out.path().display()),
        );

        let status = std::process::Command::new("/bin/sh")
            .args(["-eu", "-c", &sh])
            .status()
            .unwrap();

        assert!(status.success());
        assert_eq!(
            std::fs::read(out.path().join(INITRD_FILENAME)).unwrap(),
            b"initrd"
        );
        assert!(!out.path().join(CLOSURE_PATHS_FILENAME).exists());
        assert!(!out.path().join(VERITY_TREE_FILENAME).exists());
    }
}
