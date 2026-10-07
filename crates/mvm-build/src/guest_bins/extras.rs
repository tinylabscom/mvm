//! Host-side builds of the guest artifacts the runtime-overlay and OCI sets do
//! not carry: `mvm-setpriv`, the initramfs agent, and the guest shared objects
//! for both libcs.
//!
//! Each is one `cargo zigbuild` through the same pinned toolchain, target dir
//! and locks as [`crate::guest_agent_build`], with the flags the image recipes
//! build it with. Every crate gets its own invocation, so no artifact inherits a
//! feature or profile another one asked for.
//!
//! Outputs are cached under `<cache>/guest-bins-extras/<version>/<arch>/<fp>/`
//! at their archive member paths, keyed on a fingerprint of every input that
//! can change them.

use std::path::{Path, PathBuf};

use mvm_contract::guest_libc::GuestLibc;
use mvm_core::arch::GuestArch;
use sha2::{Digest, Sha256};

use super::cdylib::{GPU_SHIM_CDYLIBS, GuestCdylib, guest_cdylibs};
use super::member::GuestBinsMember;
use crate::guest_agent_build::{
    self, GuestAgentBuildError, GuestAgentBuildSpec, gnu_target_triple, musl_target_triple,
    package_bin_args,
};

/// The glibc version the guest shared objects are linked against, passed to
/// cargo-zigbuild as the target suffix. The objects then use no symbol newer
/// than this, which is the floor the published Nix-built objects already set:
/// any guest whose glibc is at least this version loads them.
pub const GUEST_GLIBC_FLOOR: &str = "2.34";

/// The libcs every guest shared object is built for.
pub const SHARED_OBJECT_LIBCS: [GuestLibc; 2] = [GuestLibc::Glibc, GuestLibc::Musl];

/// Release-profile overrides the image recipes set for the size-sensitive
/// guest artifacts — the initramfs agent and the GPU shims: thin LTO, one
/// codegen unit, symbols stripped.
const SIZE_PROFILE: [(&str, &str); 3] = [
    ("CARGO_PROFILE_RELEASE_LTO", "thin"),
    ("CARGO_PROFILE_RELEASE_CODEGEN_UNITS", "1"),
    ("CARGO_PROFILE_RELEASE_STRIP", "symbols"),
];

/// One `cargo zigbuild` and the single archive member it produces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExtraBuild {
    /// The member the output becomes.
    pub member: GuestBinsMember,
    /// The value passed to `--target`; for glibc it carries the version suffix.
    pub target: String,
    /// The plain target triple, which names cargo's output directory.
    pub cargo_triple: &'static str,
    /// `-p`/`--bin`/`--lib` selection.
    pub selection: Vec<String>,
    /// Environment added on top of the pinned guest-build environment.
    pub env: Vec<(String, String)>,
    /// The file cargo writes under `target/<triple>/release/`.
    pub output: String,
}

impl ExtraBuild {
    pub fn args(&self) -> Vec<String> {
        let mut args = vec![
            "zigbuild".to_string(),
            "--release".to_string(),
            "--target".to_string(),
            self.target.clone(),
        ];
        args.extend(self.selection.iter().cloned());
        args
    }

    fn output_path(&self, target_dir: &Path) -> PathBuf {
        target_dir
            .join(self.cargo_triple)
            .join("release")
            .join(&self.output)
    }
}

/// `CARGO_TARGET_<TRIPLE>_RUSTFLAGS` for `triple`. Per-target rather than
/// `RUSTFLAGS` so the flags reach only the guest artifacts, never the build
/// scripts and proc macros compiled for the host; the guest build environment
/// clears `RUSTFLAGS` for the same reason.
fn target_rustflags_env(triple: &str) -> String {
    format!(
        "CARGO_TARGET_{}_RUSTFLAGS",
        triple.to_ascii_uppercase().replace(['-', '.'], "_")
    )
}

fn env_pairs(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    pairs
        .iter()
        .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
        .collect()
}

/// `mvm-setpriv`: static musl, its own leaf package, default release profile.
fn setpriv_build(arch: GuestArch) -> Result<ExtraBuild, GuestAgentBuildError> {
    let triple = musl_target_triple(arch);
    Ok(ExtraBuild {
        member: member(GuestBinsMember::executable(arch, "mvm-setpriv"))?,
        target: triple.to_string(),
        cargo_triple: triple,
        selection: package_bin_args("mvm-setpriv", &["mvm-setpriv"]),
        env: Vec::new(),
        output: "mvm-setpriv".to_string(),
    })
}

/// The initramfs agent: static musl, no addons, sized for an initramfs.
/// `panic=abort` drops the unwinding tables a PID 1 never uses.
fn initramfs_agent_build(arch: GuestArch) -> ExtraBuild {
    let triple = musl_target_triple(arch);
    let mut env = env_pairs(&SIZE_PROFILE);
    env.extend(env_pairs(&[("CARGO_PROFILE_RELEASE_PANIC", "abort")]));
    env.push((
        target_rustflags_env(triple),
        "-C target-feature=+crt-static".to_string(),
    ));
    ExtraBuild {
        member: GuestBinsMember::InitramfsAgent { arch },
        target: triple.to_string(),
        cargo_triple: triple,
        selection: package_bin_args("mvm-agentd", &[super::member::INITRAMFS_AGENT_NAME]),
        env,
        output: super::member::INITRAMFS_AGENT_NAME.to_string(),
    }
}

/// The profile overrides `cdylib`'s image recipe builds it with: the GPU shims
/// are size-tuned, and the host-services object takes the workspace release
/// profile unchanged.
fn cdylib_profile(cdylib: &GuestCdylib) -> Vec<(String, String)> {
    if GPU_SHIM_CDYLIBS.contains(cdylib) {
        env_pairs(&SIZE_PROFILE)
    } else {
        Vec::new()
    }
}

/// One guest shared object for one libc. musl's target links statically by
/// default, which a shared object cannot be: it must load against the guest's
/// own `libc.so`.
fn cdylib_build(
    arch: GuestArch,
    libc: GuestLibc,
    cdylib: GuestCdylib,
) -> Result<ExtraBuild, GuestAgentBuildError> {
    let mut env = cdylib_profile(&cdylib);
    let (target, cargo_triple) = match libc {
        GuestLibc::Glibc => {
            let triple = gnu_target_triple(arch);
            (format!("{triple}.{GUEST_GLIBC_FLOOR}"), triple)
        }
        GuestLibc::Musl => {
            let triple = musl_target_triple(arch);
            env.push((
                target_rustflags_env(triple),
                "-C target-feature=-crt-static".to_string(),
            ));
            (triple.to_string(), triple)
        }
        GuestLibc::Unknown => {
            return Err(GuestAgentBuildError::BuildFailed {
                reason: format!("{}: no libc to build a shared object for", cdylib.package),
            });
        }
    };
    Ok(ExtraBuild {
        member: member(GuestBinsMember::shared_object(arch, libc, cdylib.soname))?,
        target,
        cargo_triple,
        selection: vec![
            "-p".to_string(),
            cdylib.package.to_string(),
            "--lib".to_string(),
        ],
        env,
        output: cdylib.cargo_output_file(),
    })
}

fn member(
    result: Result<GuestBinsMember, super::member::MemberError>,
) -> Result<GuestBinsMember, GuestAgentBuildError> {
    result.map_err(|e| GuestAgentBuildError::BuildFailed {
        reason: e.to_string(),
    })
}

/// Every extra build for `arch`, in the order they run.
pub(crate) fn extra_builds(arch: GuestArch) -> Result<Vec<ExtraBuild>, GuestAgentBuildError> {
    let mut builds = vec![setpriv_build(arch)?, initramfs_agent_build(arch)];
    for cdylib in guest_cdylibs() {
        for libc in SHARED_OBJECT_LIBCS {
            builds.push(cdylib_build(arch, libc, cdylib)?);
        }
    }
    Ok(builds)
}

/// A content fingerprint over everything the extra builds read: the guest
/// and host-services sources (their own fingerprints), the GPU shim crates,
/// the cargo configuration that adds target flags, and this recipe.
pub fn extras_source_fingerprint(workspace_root: &Path) -> Result<String, GuestAgentBuildError> {
    let mut hasher = Sha256::new();
    hasher.update(b"mvm-guest-bins-extras-input-v1\0");
    hasher.update(guest_agent_build::guest_source_fingerprint(workspace_root)?.as_bytes());
    hasher.update(b"\0");
    hasher.update(guest_agent_build::sdk_cdylib_source_fingerprint(workspace_root)?.as_bytes());
    hasher.update(b"\0");
    guest_agent_build::hash_inputs(
        &mut hasher,
        workspace_root,
        &[
            ".cargo/config.toml",
            "crates/mvm-gpu-shim-core/Cargo.toml",
            "crates/mvm-gpu-shim-core/src",
            "crates/mvm-gpu-cuda-shim/Cargo.toml",
            "crates/mvm-gpu-cuda-shim/build.rs",
            "crates/mvm-gpu-cuda-shim/src",
            "crates/mvm-gpu-cudart-shim/Cargo.toml",
            "crates/mvm-gpu-cudart-shim/build.rs",
            "crates/mvm-gpu-cudart-shim/src",
            "crates/mvm-gpu-nvml-shim/Cargo.toml",
            "crates/mvm-gpu-nvml-shim/build.rs",
            "crates/mvm-gpu-nvml-shim/src",
            "crates/mvm-build/src/guest_bins/cdylib.rs",
            "crates/mvm-build/src/guest_bins/extras.rs",
        ],
    )?;
    Ok(hex::encode(hasher.finalize()))
}

/// Where one `(version, arch, fingerprint)` of the extra builds is cached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestExtrasLayout {
    pub dir: PathBuf,
}

impl GuestExtrasLayout {
    pub fn under(cache_root: &Path, version: &str, arch: GuestArch, fingerprint: &str) -> Self {
        Self {
            dir: cache_root
                .join("guest-bins-extras")
                .join(version)
                .join(arch.to_string())
                .join(fingerprint),
        }
    }

    /// The cached file for `member`, at its archive path.
    pub fn path_of(&self, member: &GuestBinsMember) -> PathBuf {
        self.dir.join(member.path())
    }

    fn cached(&self, builds: &[ExtraBuild]) -> Option<Vec<(GuestBinsMember, PathBuf)>> {
        builds
            .iter()
            .map(|build| {
                let path = self.path_of(&build.member);
                path.is_file().then(|| (build.member.clone(), path))
            })
            .collect()
    }
}

/// The extra guest artifacts for `(version, arch)`, building and caching them
/// from `workspace_root` on a miss.
pub fn resolve_or_build_guest_extras(
    cache_root: &Path,
    version: &str,
    arch: GuestArch,
    workspace_root: &Path,
) -> Result<Vec<(GuestBinsMember, PathBuf)>, GuestAgentBuildError> {
    let fingerprint = extras_source_fingerprint(workspace_root)?;
    let layout = GuestExtrasLayout::under(cache_root, version, arch, &fingerprint);
    let builds = extra_builds(arch)?;
    if let Some(cached) = layout.cached(&builds) {
        return Ok(cached);
    }
    std::fs::create_dir_all(&layout.dir)?;
    let _build_lock =
        guest_agent_build::acquire_guest_build_lock(&layout.dir, "the guest extras build")?;
    if let Some(cached) = layout.cached(&builds) {
        return Ok(cached);
    }
    let spec = GuestAgentBuildSpec::new(
        workspace_root.to_path_buf(),
        arch,
        guest_agent_build::guest_build_target_dir(cache_root, workspace_root),
    );
    let mut targets: Vec<&str> = builds.iter().map(|build| build.cargo_triple).collect();
    targets.sort_unstable();
    targets.dedup();
    guest_agent_build::ensure_rust_targets(&spec, &targets)?;
    // Several builds write the same output name (the agent) into one target
    // directory, so the lock is held from each build through its copy out.
    let zigbuild_lock = guest_agent_build::acquire_guest_zigbuild_lock(&spec.target_dir)?;
    for build in &builds {
        guest_agent_build::run_zigbuild(&zigbuild_lock, &spec, &build.args(), &build.env)?;
        install_checked(build, &spec.target_dir, &layout.path_of(&build.member))?;
    }
    layout
        .cached(&builds)
        .ok_or_else(|| GuestAgentBuildError::OutputMissing(layout.dir.clone()))
}

/// Copy one output into the cache and check it is what its member must be. A
/// refused artifact is removed, so a bad build is never served from the cache.
fn install_checked(
    build: &ExtraBuild,
    target_dir: &Path,
    dest: &Path,
) -> Result<(), GuestAgentBuildError> {
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }
    guest_agent_build::install_one(&build.output_path(target_dir), dest)?;
    let bytes = std::fs::read(dest)?;
    if let Err(reason) = build.member.validate(&bytes, dest) {
        let _ = std::fs::remove_file(dest);
        return Err(GuestAgentBuildError::BuildFailed {
            reason: format!("{}: {reason}", build.member.path()),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guest_bins::cdylib::HOST_SERVICES_CDYLIB;

    fn env_of<'a>(build: &'a ExtraBuild, key: &str) -> Option<&'a str> {
        build
            .env
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    fn by_path(arch: GuestArch, path: &str) -> ExtraBuild {
        extra_builds(arch)
            .unwrap()
            .into_iter()
            .find(|build| build.member.path() == path)
            .unwrap_or_else(|| panic!("no build produces {path}"))
    }

    #[test]
    fn every_extra_member_is_built_exactly_once_per_arch() {
        let builds = extra_builds(GuestArch::Aarch64).unwrap();
        let mut paths: Vec<String> = builds.iter().map(|b| b.member.path()).collect();
        paths.sort();
        assert_eq!(
            paths,
            [
                "aarch64/bin/mvm-setpriv",
                "aarch64/initramfs/mvm-guest-agent",
                "aarch64/lib/glibc/libcuda.so.1",
                "aarch64/lib/glibc/libcudart.so",
                "aarch64/lib/glibc/libmvm_host_services.so",
                "aarch64/lib/glibc/libnvidia-ml.so.1",
                "aarch64/lib/musl/libcuda.so.1",
                "aarch64/lib/musl/libcudart.so",
                "aarch64/lib/musl/libmvm_host_services.so",
                "aarch64/lib/musl/libnvidia-ml.so.1",
            ]
        );
    }

    /// One package per invocation: a second `-p` would unify features and
    /// profiles across crates the image recipes build separately.
    #[test]
    fn each_build_selects_one_package() {
        for build in extra_builds(GuestArch::X86_64).unwrap() {
            let packages = build.selection.iter().filter(|a| *a == "-p").count();
            assert_eq!(packages, 1, "{:?}", build.selection);
            assert!(
                !build.selection.iter().any(|a| a == "--features"),
                "no extra build enables a feature: {:?}",
                build.selection
            );
        }
    }

    #[test]
    fn glibc_objects_target_the_glibc_floor_and_musl_objects_link_dynamically() {
        let glibc = by_path(GuestArch::X86_64, "x86_64/lib/glibc/libcuda.so.1");
        assert_eq!(glibc.target, "x86_64-unknown-linux-gnu.2.34");
        assert_eq!(glibc.cargo_triple, "x86_64-unknown-linux-gnu");
        assert_eq!(
            glibc.args(),
            [
                "zigbuild",
                "--release",
                "--target",
                "x86_64-unknown-linux-gnu.2.34",
                "-p",
                "mvm-gpu-cuda-shim",
                "--lib"
            ]
        );
        assert_eq!(glibc.output, "libcuda.so");
        assert_eq!(
            env_of(&glibc, "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS"),
            None
        );

        let musl = by_path(
            GuestArch::Aarch64,
            "aarch64/lib/musl/libmvm_host_services.so",
        );
        assert_eq!(musl.target, "aarch64-unknown-linux-musl");
        assert_eq!(
            env_of(&musl, "CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_RUSTFLAGS"),
            Some("-C target-feature=-crt-static")
        );
    }

    /// Each object takes the profile its own recipe sets: `mvm-gpu-shims.nix`
    /// size-tunes the shims, and `mvm-sdk-cdylib.nix` overrides nothing.
    #[test]
    fn gpu_shims_are_size_tuned_and_host_services_keeps_the_release_profile() {
        for arch in [GuestArch::Aarch64, GuestArch::X86_64] {
            for libc in SHARED_OBJECT_LIBCS {
                for shim in GPU_SHIM_CDYLIBS {
                    let build = cdylib_build(arch, libc, shim).unwrap();
                    assert_eq!(env_of(&build, "CARGO_PROFILE_RELEASE_LTO"), Some("thin"));
                    assert_eq!(
                        env_of(&build, "CARGO_PROFILE_RELEASE_CODEGEN_UNITS"),
                        Some("1")
                    );
                    assert_eq!(
                        env_of(&build, "CARGO_PROFILE_RELEASE_STRIP"),
                        Some("symbols")
                    );
                    assert_eq!(env_of(&build, "CARGO_PROFILE_RELEASE_PANIC"), None);
                }
                let host = cdylib_build(arch, libc, HOST_SERVICES_CDYLIB).unwrap();
                assert!(
                    !host
                        .env
                        .iter()
                        .any(|(k, _)| k.starts_with("CARGO_PROFILE_")),
                    "{:?}",
                    host.env
                );
            }
        }
    }

    #[test]
    fn the_initramfs_agent_is_static_size_tuned_and_aborts_on_panic() {
        let agent = by_path(GuestArch::X86_64, "x86_64/initramfs/mvm-guest-agent");
        assert_eq!(agent.target, "x86_64-unknown-linux-musl");
        assert_eq!(
            agent.selection,
            ["-p", "mvm-agentd", "--bin", "mvm-guest-agent"]
        );
        assert_eq!(
            env_of(&agent, "CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_RUSTFLAGS"),
            Some("-C target-feature=+crt-static")
        );
        assert_eq!(env_of(&agent, "CARGO_PROFILE_RELEASE_PANIC"), Some("abort"));
        assert_eq!(env_of(&agent, "CARGO_PROFILE_RELEASE_LTO"), Some("thin"));
    }

    #[test]
    fn setpriv_is_its_own_static_package_build() {
        let setpriv = by_path(GuestArch::Aarch64, "aarch64/bin/mvm-setpriv");
        assert_eq!(setpriv.target, "aarch64-unknown-linux-musl");
        assert_eq!(
            setpriv.selection,
            ["-p", "mvm-setpriv", "--bin", "mvm-setpriv"]
        );
        assert!(setpriv.env.is_empty());
    }

    #[test]
    fn rustflags_env_names_the_target_cargo_reads() {
        assert_eq!(
            target_rustflags_env("aarch64-unknown-linux-musl"),
            "CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_RUSTFLAGS"
        );
    }

    #[test]
    fn a_complete_cache_resolves_without_building() {
        let workspace =
            crate::guest_agent_build::source_workspace_from(Path::new(env!("CARGO_MANIFEST_DIR")))
                .expect("the test runs inside the mvm workspace");
        let cache = tempfile::tempdir().unwrap();
        let arch = GuestArch::X86_64;
        let layout = GuestExtrasLayout::under(
            cache.path(),
            "9.9.9",
            arch,
            &extras_source_fingerprint(&workspace).unwrap(),
        );
        let builds = extra_builds(arch).unwrap();
        assert!(layout.cached(&builds).is_none());
        for build in &builds {
            let path = layout.path_of(&build.member);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, b"x").unwrap();
        }
        let resolved =
            resolve_or_build_guest_extras(cache.path(), "9.9.9", arch, &workspace).unwrap();
        assert_eq!(resolved.len(), builds.len());
        assert!(
            resolved
                .iter()
                .all(|(_, path)| path.starts_with(&layout.dir))
        );
    }

    #[test]
    fn a_refused_output_is_not_left_in_the_cache() {
        let tmp = tempfile::tempdir().unwrap();
        let build = by_path(GuestArch::X86_64, "x86_64/lib/musl/libcuda.so.1");
        let output = build.output_path(tmp.path());
        std::fs::create_dir_all(output.parent().unwrap()).unwrap();
        // A static executable where a musl shared object belongs.
        std::fs::write(
            &output,
            crate::guest_agent_build::fake_static_elf(GuestArch::X86_64, b"exe"),
        )
        .unwrap();
        let dest = tmp.path().join("cache/libcuda.so.1");
        let err = install_checked(&build, tmp.path(), &dest).unwrap_err();
        assert!(
            err.to_string().contains("x86_64/lib/musl/libcuda.so.1"),
            "{err}"
        );
        assert!(!dest.exists());
    }
}
