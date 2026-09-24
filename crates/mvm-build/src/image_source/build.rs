//! Building one target of the selected image checkout.
//!
//! The build itself runs inside the builder VM, never with host Nix: the
//! caller hands [`render_build_script`] to a builder shell job whose `/work`
//! is the tree [`stage_work_tree`] assembled — a filtered copy of each
//! checkout, and for the builder image the host binaries built from the paired
//! mvm checkout — and whose `/out` receives the target's output files.
//!
//! Two steps stay on the host because they are the image repository's own
//! contract, and running its scripts is how that contract is kept to one
//! implementation:
//!
//! - the builder image's static host binaries, built by the image
//!   checkout's `scripts/build-host-binaries.sh --mvm-checkout` exactly as its
//!   release does; the builder image has Nix and nothing else, so a
//!   cross-compile with the pinned zig cannot run inside it;
//! - the local manifest, written by the image checkout's
//!   `scripts/emit-local-manifest.py`. That emitter is the one producer of a
//!   local set; this crate is its reader, and every build therefore checks the
//!   two against each other.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

use mvm_core::arch::GuestArch;
use mvm_core::image_set::{ImageSetRole, WorkloadImageProfile};
use mvm_core::kernel_format::KernelFormat;
use thiserror::Error;

use super::LocalImageCheckout;
use super::cache::{
    CacheLookup, CachedImageSet, EntryContext, ImageBuildRole, ImageBuildTarget, KeyInputs,
    LocalImageCache, LocalImageCacheKey,
};
use crate::builder_vm_runtime::copy_dir_filtered;
use crate::guest_libc::GuestLibc;

/// The image checkout's host-binary build script, relative to its root.
pub const HOST_BINARIES_SCRIPT: &str = "scripts/build-host-binaries.sh";
/// The image checkout's local-manifest emitter, relative to its root.
pub const EMIT_MANIFEST_SCRIPT: &str = "scripts/emit-local-manifest.py";

/// The static binaries the builder image installs from `MVM_HOST_BIN_DIR`.
pub const BUILDER_HOST_BINARIES: [&str; 2] = ["mvm-host-vm-init", "mvm-builderd"];

/// Where each checkout sits inside the staged `/work` tree.
const WORK_IMAGES: &str = "images";
const WORK_MVM: &str = "mvm";
const WORK_HOST_BINS: &str = "host-bins";

/// Why a local image build refused.
#[derive(Debug, Error)]
pub enum LocalImageBuildError {
    #[error("{target}: {reason}")]
    Unsupported { target: String, reason: String },
    #[error("{what} failed: {detail}")]
    Tool { what: String, detail: String },
    #[error("{op} {}: {source}", .path.display())]
    Io {
        op: &'static str,
        path: PathBuf,
        source: std::io::Error,
    },
}

/// How an output file is described in the manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    /// A kernel image, whose format is read from its bytes.
    Kernel,
    /// A fixed format, spelled as the emitter takes it.
    Fixed(&'static str),
}

/// One file a target's output carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutputFile {
    /// The file's name inside the Nix output.
    pub name: &'static str,
    /// The manifest role it belongs to, as the emitter names it.
    pub role: &'static str,
    pub format: OutputFormat,
}

/// What building one target produces, and how it is described.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TargetContract {
    pub files: &'static [OutputFile],
    /// `(role, capability)` pairs, as the emitter takes them.
    pub capabilities: &'static [(&'static str, &'static str)],
    /// The manifest roles the set carries, which a reader requires.
    pub set_roles: &'static [ImageSetRole],
    pub needs_host_binaries: bool,
}

const fn file(name: &'static str, role: &'static str, format: &'static str) -> OutputFile {
    OutputFile {
        name,
        role,
        format: OutputFormat::Fixed(format),
    }
}

const fn kernel(name: &'static str, role: &'static str) -> OutputFile {
    OutputFile {
        name,
        role,
        format: OutputFormat::Kernel,
    }
}

const BUILDER_VM: TargetContract = TargetContract {
    files: &[
        kernel("vmlinux", "builder_vm"),
        file("rootfs.ext4", "builder_vm", "ext4"),
        file("cmdline.txt", "builder_vm", "text"),
        file("manifest.json", "builder_vm", "json"),
    ],
    capabilities: &[("builder_vm", "virtio_vsock"), ("builder_vm", "virtio_blk")],
    set_roles: &[ImageSetRole::BuilderVm],
    needs_host_binaries: true,
};

const RUNTIME_OVERLAY: TargetContract = TargetContract {
    files: &[
        file("overlay.ext4", "runtime_overlay", "ext4"),
        file("overlay.verity", "runtime_overlay", "verity_hash_tree"),
        file("overlay.roothash", "runtime_overlay", "verity_root_hash"),
        file("VERSION", "runtime_overlay", "text"),
    ],
    capabilities: &[
        ("runtime_overlay", "virtio_blk"),
        ("runtime_overlay", "dm_verity"),
    ],
    set_roles: &[ImageSetRole::RuntimeOverlay],
    needs_host_binaries: false,
};

const SDK_SIDECAR_GLIBC: TargetContract = TargetContract {
    files: &[
        file("sdk.ext4", "sdk_sidecar_glibc", "ext4"),
        file("VERSION", "sdk_sidecar_glibc", "text"),
        file("checksums-sha256.txt", "sdk_sidecar_glibc", "text"),
    ],
    capabilities: &[("sdk_sidecar_glibc", "virtio_blk")],
    set_roles: &[ImageSetRole::SdkSidecar(GuestLibc::Glibc)],
    needs_host_binaries: false,
};

const SDK_SIDECAR_MUSL: TargetContract = TargetContract {
    files: &[
        file("sdk.ext4", "sdk_sidecar_musl", "ext4"),
        file("VERSION", "sdk_sidecar_musl", "text"),
        file("checksums-sha256.txt", "sdk_sidecar_musl", "text"),
    ],
    capabilities: &[("sdk_sidecar_musl", "virtio_blk")],
    set_roles: &[ImageSetRole::SdkSidecar(GuestLibc::Musl)],
    needs_host_binaries: false,
};

const DEFAULT_TENANT: TargetContract = TargetContract {
    files: &[
        kernel("vmlinux", "default_tenant_workload_kernel"),
        file("rootfs.ext4", "default_tenant_workload_rootfs", "ext4"),
        file(
            "rootfs.verity",
            "default_tenant_workload_rootfs",
            "verity_hash_tree",
        ),
        file(
            "rootfs.roothash",
            "default_tenant_workload_rootfs",
            "verity_root_hash",
        ),
        file("mvm-meta.json", "default_tenant_workload_rootfs", "json"),
    ],
    capabilities: &[
        ("default_tenant_workload_kernel", "virtio_vsock"),
        ("default_tenant_workload_rootfs", "virtio_blk"),
        ("default_tenant_workload_rootfs", "dm_verity"),
    ],
    set_roles: &[
        ImageSetRole::WorkloadKernel(WorkloadImageProfile::DefaultTenant),
        ImageSetRole::WorkloadRootfs(WorkloadImageProfile::DefaultTenant),
    ],
    needs_host_binaries: false,
};

const ROOTLESS_TENANT: TargetContract = TargetContract {
    files: &[
        kernel("vmlinux", "rootless_tenant_workload_kernel"),
        file("rootfs.ext4", "rootless_tenant_workload_rootfs", "ext4"),
        file(
            "rootfs.verity",
            "rootless_tenant_workload_rootfs",
            "verity_hash_tree",
        ),
        file(
            "rootfs.roothash",
            "rootless_tenant_workload_rootfs",
            "verity_root_hash",
        ),
        file("mvm-meta.json", "rootless_tenant_workload_rootfs", "json"),
    ],
    capabilities: &[
        ("rootless_tenant_workload_kernel", "virtio_vsock"),
        ("rootless_tenant_workload_rootfs", "virtio_blk"),
        ("rootless_tenant_workload_rootfs", "dm_verity"),
    ],
    set_roles: &[
        ImageSetRole::WorkloadKernel(WorkloadImageProfile::RootlessTenant),
        ImageSetRole::WorkloadRootfs(WorkloadImageProfile::RootlessTenant),
    ],
    needs_host_binaries: false,
};

/// The contract for `target`, or why it cannot be built from a local
/// checkout yet.
pub fn contract_for(
    target: &ImageBuildTarget,
) -> Result<&'static TargetContract, LocalImageBuildError> {
    let unsupported = |reason: &str| LocalImageBuildError::Unsupported {
        target: target.to_string(),
        reason: reason.to_string(),
    };
    match (target.role, target.attr.as_str()) {
        (ImageBuildRole::BuilderVm, "default") => Ok(&BUILDER_VM),
        (ImageBuildRole::RuntimeOverlay, "default") => Ok(&RUNTIME_OVERLAY),
        (ImageBuildRole::RuntimeOverlay, "sdk-sidecar-image") => Ok(&SDK_SIDECAR_GLIBC),
        (ImageBuildRole::RuntimeOverlay, "sdk-sidecar-image-musl") => Ok(&SDK_SIDECAR_MUSL),
        (ImageBuildRole::DefaultTenant, "default") => Ok(&DEFAULT_TENANT),
        (ImageBuildRole::RootlessTenant, "default") => Ok(&ROOTLESS_TENANT),
        (ImageBuildRole::Initramfs, _) => Err(unsupported(
            "the image-set schema has no initramfs role, so a built initramfs has no manifest \
             to be published under",
        )),
        (ImageBuildRole::Kernel, _) => Err(unsupported(
            "the kernel flake is not built from a local checkout yet; `default-tenant` carries \
             the workload kernel",
        )),
        _ => Err(unsupported(
            "no output contract for this attribute; known: builder-vm.default, \
             runtime-overlay.default, runtime-overlay.sdk-sidecar-image, \
             runtime-overlay.sdk-sidecar-image-musl, default-tenant.default, \
             rootless-tenant.default",
        )),
    }
}

/// The `cmd.sh` the builder guest runs: build `target` from the staged image
/// checkout with the staged mvm checkout as its `mvm` input, and copy the
/// contract's files to `/out`.
///
/// The image checkout is evaluated as a `path:` flake, so the build sees the
/// working tree as staged, uncommitted edits included, which is what its
/// recorded identity describes. `MVM_WORKSPACE_PATH` is cleared because the
/// image flake refuses to evaluate with it set.
#[must_use]
pub fn render_build_script(
    target: &ImageBuildTarget,
    arch: GuestArch,
    contract: &TargetContract,
) -> String {
    let flake = format!(
        "path:/work/{WORK_IMAGES}#legacyPackages.{}.{}.{}",
        arch.nix_system(),
        target.role,
        target.attr
    );
    let host_bins = if contract.needs_host_binaries {
        format!("export MVM_HOST_BIN_DIR=/work/{WORK_HOST_BINS}\n")
    } else {
        String::new()
    };
    let names: Vec<String> = contract
        .files
        .iter()
        .map(|file| format!("'{}'", file.name))
        .collect();
    format!(
        r#"#!/bin/sh
set -eu
export HOME=/tmp
export XDG_CACHE_HOME=/nix-store/.cache
export XDG_STATE_HOME=/tmp/.local/state
export NIX_SSL_CERT_FILE=/etc/ssl/certs/ca-bundle.crt
export SSL_CERT_FILE=/etc/ssl/certs/ca-bundle.crt
export NIX_CONFIG='experimental-features = nix-command flakes
sandbox = false
build-users-group =
substituters = https://cache.nixos.org/
trusted-public-keys = cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY=
fallback = true
download-attempts = 5'
unset MVM_WORKSPACE_PATH
{host_bins}mkdir -p "$XDG_CACHE_HOME" "$XDG_STATE_HOME"
out=$(/sbin/nix build '{flake}' \
  --override-input mvm 'path:/work/{WORK_MVM}' \
  --no-link --print-out-paths --no-write-lock-file --impure --print-build-logs)
test -n "$out"
test -d "$out"
for name in {names}; do
  test -f "$out/$name"
  cp -L "$out/$name" "/out/$name"
  chmod 0644 "/out/$name"
done
sync
"#,
        names = names.join(" ")
    )
}

/// Assemble the builder's `/work` tree in `dest`: a filtered copy of each
/// checkout, and the host binaries when the target needs them.
///
/// The copies prune what the builder's own work-input filter prunes — build
/// output, VCS metadata and tool scratch — so they carry the sources the image
/// flakes read and nothing that would bloat the store copy.
pub fn stage_work_tree(
    images_root: &Path,
    mvm_root: &Path,
    host_bins: Option<&Path>,
    dest: &Path,
) -> Result<(), LocalImageBuildError> {
    let copy = |from: &Path, to: PathBuf| {
        copy_dir_filtered(from, &to).map_err(|source| LocalImageBuildError::Io {
            op: "staging",
            path: from.to_path_buf(),
            source,
        })
    };
    copy(images_root, dest.join(WORK_IMAGES))?;
    copy(mvm_root, dest.join(WORK_MVM))?;
    if let Some(bins) = host_bins {
        let to = dest.join(WORK_HOST_BINS);
        std::fs::create_dir_all(&to).map_err(|source| LocalImageBuildError::Io {
            op: "creating",
            path: to.clone(),
            source,
        })?;
        for name in BUILDER_HOST_BINARIES {
            let from = bins.join(name);
            std::fs::copy(&from, to.join(name)).map_err(|source| LocalImageBuildError::Io {
                op: "copying host binary",
                path: from.clone(),
                source,
            })?;
        }
    }
    Ok(())
}

/// Build the builder image's host binaries from `mvm_root` with the image
/// checkout's own script, and return the directory holding them.
pub fn build_host_binaries(
    images_root: &Path,
    mvm_root: &Path,
    arch: GuestArch,
) -> Result<PathBuf, LocalImageBuildError> {
    let mut cmd = Command::new("bash");
    cmd.arg(images_root.join(HOST_BINARIES_SCRIPT))
        .arg("--mvm-checkout")
        .arg(mvm_root)
        .arg(arch.to_string())
        .env_remove("MVM_WORKSPACE_PATH")
        .env_remove("GITHUB_ENV")
        .stderr(std::process::Stdio::inherit());
    let stdout = run_tool("building the builder's host binaries", &mut cmd)?;
    let dir = host_bin_dir_from(&stdout).ok_or_else(|| LocalImageBuildError::Tool {
        what: "building the builder's host binaries".to_string(),
        detail: "the script printed no MVM_HOST_BIN_DIR= line".to_string(),
    })?;
    for name in BUILDER_HOST_BINARIES {
        if !dir.join(name).is_file() {
            return Err(LocalImageBuildError::Tool {
                what: "building the builder's host binaries".to_string(),
                detail: format!("{} has no {name}", dir.display()),
            });
        }
    }
    Ok(dir)
}

/// The directory the host-binary script reports on its last
/// `MVM_HOST_BIN_DIR=` line.
fn host_bin_dir_from(stdout: &str) -> Option<PathBuf> {
    stdout
        .lines()
        .rev()
        .find_map(|line| line.strip_prefix("MVM_HOST_BIN_DIR="))
        .filter(|dir| !dir.is_empty())
        .map(PathBuf::from)
}

/// What the emitter is asked to describe.
#[derive(Debug, Clone, Copy)]
pub struct EmitRequest<'a> {
    pub images_root: &'a Path,
    pub mvm_root: &'a Path,
    pub arch: GuestArch,
    pub builder_cache_contract: u32,
    /// The directory the builder copied the target's files into.
    pub built: &'a Path,
    /// A new, empty directory for the set, outside both checkouts.
    pub out: &'a Path,
    pub contract: &'a TargetContract,
}

/// Write the local manifest for a built target into `request.out`, with the
/// image checkout's emitter.
pub fn emit_local_manifest(request: &EmitRequest<'_>) -> Result<(), LocalImageBuildError> {
    let argv = emit_argv(request)?;
    let mut cmd = Command::new("python3");
    cmd.args(argv).stderr(std::process::Stdio::inherit());
    run_tool("writing the local image-set manifest", &mut cmd).map(|_| ())
}

/// The emitter's argument vector. Kernel formats are read from the built
/// bytes, since the emitter takes the format as an argument rather than
/// guessing it.
pub fn emit_argv(request: &EmitRequest<'_>) -> Result<Vec<OsString>, LocalImageBuildError> {
    let mut argv: Vec<OsString> = vec![
        request.images_root.join(EMIT_MANIFEST_SCRIPT).into(),
        "--images-checkout".into(),
        request.images_root.into(),
        "--mvm-checkout".into(),
        request.mvm_root.into(),
        "--arch".into(),
        request.arch.to_string().into(),
        "--builder-cache-contract".into(),
        request.builder_cache_contract.to_string().into(),
        "--out".into(),
        request.out.into(),
    ];
    for file in request.contract.files {
        let path = request.built.join(file.name);
        let format = match file.format {
            OutputFormat::Fixed(format) => format.to_string(),
            OutputFormat::Kernel => format!("kernel:{}", read_kernel_format(&path)?.name()),
        };
        argv.extend([
            "--artifact".into(),
            file.role.into(),
            format.into(),
            path.into_os_string(),
        ]);
    }
    for (role, capability) in request.contract.capabilities {
        argv.extend(["--capability".into(), (*role).into(), (*capability).into()]);
    }
    Ok(argv)
}

fn read_kernel_format(path: &Path) -> Result<KernelFormat, LocalImageBuildError> {
    let bytes = read_head(path)?;
    KernelFormat::sniff_magic(&bytes).ok_or_else(|| LocalImageBuildError::Tool {
        what: "reading the built kernel".to_string(),
        detail: format!(
            "{} is neither an ELF vmlinux, an arm64 Image nor an x86 bzImage",
            path.display()
        ),
    })
}

fn read_head(path: &Path) -> Result<Vec<u8>, LocalImageBuildError> {
    use std::io::Read;
    let mut head = Vec::with_capacity(KernelFormat::SNIFF_LEN);
    std::fs::File::open(path)
        .and_then(|file| {
            file.take(KernelFormat::SNIFF_LEN as u64)
                .read_to_end(&mut head)
        })
        .map_err(|source| LocalImageBuildError::Io {
            op: "reading",
            path: path.to_path_buf(),
            source,
        })?;
    Ok(head)
}

fn run_tool(what: &str, cmd: &mut Command) -> Result<String, LocalImageBuildError> {
    let out = cmd.output().map_err(|e| LocalImageBuildError::Tool {
        what: what.to_string(),
        detail: format!("could not run {:?}: {e}", cmd.get_program()),
    })?;
    if !out.status.success() {
        return Err(LocalImageBuildError::Tool {
            what: what.to_string(),
            detail: format!("{:?} exited with {}", cmd.get_program(), out.status),
        });
    }
    String::from_utf8(out.stdout).map_err(|_| LocalImageBuildError::Tool {
        what: what.to_string(),
        detail: "printed non-UTF-8 output".to_string(),
    })
}

/// Hardlink `files` — each a (manifest role, contract file name) pair — from
/// `entry` into `dest` under their canonical contract names, for consumers
/// that read a fixed layout (the overlay reader, the sidecar installer).
/// Hardlinks, not copies: the bytes can be large, and `dest` is a sibling
/// staging directory on the same cache filesystem.
pub fn stage_contract_files(
    entry: &CachedImageSet,
    files: &[(&str, &str)],
    dest: &Path,
) -> Result<(), LocalImageBuildError> {
    std::fs::create_dir_all(dest).map_err(|source| LocalImageBuildError::Io {
        op: "creating",
        path: dest.to_path_buf(),
        source,
    })?;
    for (role, name) in files {
        let from = entry
            .contract_file(role, name)
            .ok_or_else(|| LocalImageBuildError::Tool {
                what: format!("reading the pair's {role} artifact {name}"),
                detail: "the verified set does not carry that contract file".to_string(),
            })?;
        std::fs::hard_link(from, dest.join(name)).map_err(|source| LocalImageBuildError::Io {
            op: "hardlinking",
            path: from.to_path_buf(),
            source,
        })?;
    }
    Ok(())
}

/// Hardlink the runtime-overlay contract files (`overlay.ext4`,
/// `overlay.verity`, `overlay.roothash`, `VERSION`) from a pair entry into
/// `dest` under their canonical names, for consumers that read the fixed
/// overlay layout. The entry files carry the producer's manifest names
/// (`<role>-<arch>-<name>`); the installer also derives the version file
/// from the artifact's directory, so the canonical staging must exist on
/// disk, not just in path arithmetic.
pub fn stage_overlay_contract_files(
    entry: &CachedImageSet,
    dest: &Path,
) -> Result<(), LocalImageBuildError> {
    stage_contract_files(
        entry,
        &[
            ("runtime_overlay", "overlay.ext4"),
            ("runtime_overlay", "overlay.verity"),
            ("runtime_overlay", "overlay.roothash"),
            ("runtime_overlay", "VERSION"),
        ],
        dest,
    )
}

/// One built (or cache-hit) target of a checkout pair.
#[derive(Debug)]
pub struct PairBuild {
    /// The key the entry answers; also the identity the install sidecars
    /// record.
    pub key: LocalImageCacheKey,
    /// The verified cache entry holding the target's files.
    pub entry: CachedImageSet,
    /// False when a cache hit answered without running the build.
    pub built: bool,
}

/// Build `target` from the checkout pair and publish it to `cache`, answering
/// an unchanged pair from the cache without booting anything.
///
/// This is the one implementation of a local image-set build; the `build
/// image-set` verb and the builder-VM bootstrap share it, so a target built
/// either way is the same bytes under the same key. The two closures are the
/// VM boundary, injected so this crate stays free of backend drivers and tests
/// can run a build without a VM: `prepare_builder` readies the builder image
/// the job runs in, and `run_job` boots it. Neither runs on a cache hit.
///
/// `prepare_builder` must not itself route through this function for the
/// builder-vm target: the image-set build runs *inside* a builder, so its
/// builder image comes from the in-tree or published bootstrap, never from
/// the pair being built.
pub fn build_target_for_pair(
    checkout: &LocalImageCheckout,
    mvm_root: &Path,
    target: ImageBuildTarget,
    arch: GuestArch,
    cache: &LocalImageCache,
    prepare_builder: &mut dyn FnMut() -> Result<(), String>,
    run_job: &mut dyn FnMut(&crate::builder_vm::BuilderShellJob) -> Result<(), String>,
) -> Result<PairBuild, LocalImageBuildError> {
    let contract = contract_for(&target)?;
    let ctx = EntryContext {
        images: checkout,
        mvm_checkout: mvm_root,
        roles: contract.set_roles,
    };
    let key_inputs = KeyInputs {
        images: checkout,
        mvm_checkout: mvm_root,
        target: &target,
        arch,
    };
    let key =
        LocalImageCacheKey::derive(&key_inputs).map_err(|error| LocalImageBuildError::Tool {
            what: "deriving the local image cache key".to_string(),
            detail: error.to_string(),
        })?;
    match cache
        .lookup(&key, &ctx)
        .map_err(|error| LocalImageBuildError::Tool {
            what: "looking up the local image cache".to_string(),
            detail: error.to_string(),
        })? {
        CacheLookup::Hit(entry) => {
            return Ok(PairBuild {
                key,
                entry: *entry,
                built: false,
            });
        }
        CacheLookup::Evicted { .. } | CacheLookup::Miss => {}
    }

    prepare_builder().map_err(|detail| LocalImageBuildError::Tool {
        what: "preparing the builder VM image".to_string(),
        detail,
    })?;
    let host_bins = if contract.needs_host_binaries {
        Some(build_host_binaries(checkout.root(), mvm_root, arch)?)
    } else {
        None
    };

    let scratch = scratch_dir()?;
    let work = scratch.path().join("work");
    let out = scratch.path().join("out");
    std::fs::create_dir_all(&out).map_err(|source| LocalImageBuildError::Io {
        op: "creating",
        path: out.clone(),
        source,
    })?;
    stage_work_tree(checkout.root(), mvm_root, host_bins.as_deref(), &work)?;
    // The staged copies must be of the trees the key names; an edit while
    // they were being copied would publish one tree's bytes under another's
    // identity.
    let staged_key =
        LocalImageCacheKey::derive(&key_inputs).map_err(|error| LocalImageBuildError::Tool {
            what: "re-verifying the staged checkouts".to_string(),
            detail: error.to_string(),
        })?;
    if staged_key != key {
        return Err(LocalImageBuildError::Unsupported {
            target: target.to_string(),
            reason: "a checkout changed while it was being staged for the build; run it again"
                .to_string(),
        });
    }

    let job = crate::builder_vm::BuilderShellJob {
        work_dir: work,
        artifact_out: out.clone(),
        script: render_build_script(&target, arch, contract),
        extra_disks: Vec::new(),
    };
    run_job(&job).map_err(|detail| LocalImageBuildError::Tool {
        what: format!("running the builder shell job for {target}"),
        detail,
    })?;

    let staged = cache
        .stage(&key)
        .map_err(|error| LocalImageBuildError::Tool {
            what: "staging the local image cache entry".to_string(),
            detail: error.to_string(),
        })?;
    emit_local_manifest(&EmitRequest {
        images_root: checkout.root(),
        mvm_root,
        arch,
        builder_cache_contract: crate::builder_vm::BUILDER_VM_CACHE_CONTRACT_VERSION,
        built: &out,
        out: staged.dir(),
        contract,
    })?;
    let outcome = cache
        .publish(staged, &ctx)
        .map_err(|error| LocalImageBuildError::Tool {
            what: "publishing the local image cache entry".to_string(),
            detail: error.to_string(),
        })?;
    Ok(PairBuild {
        key,
        entry: outcome.entry().clone(),
        built: true,
    })
}

/// Mutable scratch for one build, removed when the build returns. It sits in
/// the mvm cache rather than inside either checkout, whose identity it would
/// otherwise change.
fn scratch_dir() -> Result<tempfile::TempDir, LocalImageBuildError> {
    let parent = Path::new(&mvm_core::config::mvm_cache_dir()).join("local-image-builds");
    std::fs::create_dir_all(&parent).map_err(|source| LocalImageBuildError::Io {
        op: "creating",
        path: parent.clone(),
        source,
    })?;
    tempfile::Builder::new()
        .prefix("build-")
        .tempdir_in(&parent)
        .map_err(|source| LocalImageBuildError::Io {
            op: "creating a build directory in",
            path: parent,
            source,
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::image_source::FlakeAttr;

    fn target(role: ImageBuildRole, attr: &str) -> ImageBuildTarget {
        ImageBuildTarget {
            role,
            attr: FlakeAttr::new(attr).unwrap(),
        }
    }

    #[test]
    fn each_supported_target_names_the_roles_it_produces() {
        for (role, attr, roles, host_bins) in [
            (
                ImageBuildRole::BuilderVm,
                "default",
                &[ImageSetRole::BuilderVm][..],
                true,
            ),
            (
                ImageBuildRole::RuntimeOverlay,
                "default",
                &[ImageSetRole::RuntimeOverlay][..],
                false,
            ),
            (
                ImageBuildRole::RuntimeOverlay,
                "sdk-sidecar-image",
                &[ImageSetRole::SdkSidecar(GuestLibc::Glibc)][..],
                false,
            ),
            (
                ImageBuildRole::RuntimeOverlay,
                "sdk-sidecar-image-musl",
                &[ImageSetRole::SdkSidecar(GuestLibc::Musl)][..],
                false,
            ),
            (
                ImageBuildRole::DefaultTenant,
                "default",
                &[
                    ImageSetRole::WorkloadKernel(WorkloadImageProfile::DefaultTenant),
                    ImageSetRole::WorkloadRootfs(WorkloadImageProfile::DefaultTenant),
                ][..],
                false,
            ),
            (
                ImageBuildRole::RootlessTenant,
                "default",
                &[
                    ImageSetRole::WorkloadKernel(WorkloadImageProfile::RootlessTenant),
                    ImageSetRole::WorkloadRootfs(WorkloadImageProfile::RootlessTenant),
                ][..],
                false,
            ),
        ] {
            let contract = contract_for(&target(role, attr)).unwrap();
            assert_eq!(contract.set_roles, roles, "{role}.{attr}");
            assert_eq!(contract.needs_host_binaries, host_bins, "{role}.{attr}");
            for file in contract.files {
                let named = contract
                    .set_roles
                    .iter()
                    .any(|r| r.to_string() == file.role);
                assert!(named, "{role}.{attr}: {} has role {}", file.name, file.role);
            }
            for (cap_role, _) in contract.capabilities {
                assert!(
                    contract.files.iter().any(|f| f.role == *cap_role),
                    "{role}.{attr}: a capability for {cap_role}, which has no file"
                );
            }
        }
    }

    #[test]
    fn a_target_without_a_contract_is_refused_with_the_reason() {
        for (role, attr, needle) in [
            (ImageBuildRole::Initramfs, "default", "no initramfs role"),
            (ImageBuildRole::Kernel, "workload-vmlinux", "default-tenant"),
            (ImageBuildRole::BuilderVm, "dev", "no output contract"),
            (ImageBuildRole::DefaultTenant, "dev", "no output contract"),
        ] {
            let err = contract_for(&target(role, attr)).unwrap_err();
            assert!(err.to_string().contains(needle), "{role}.{attr}: {err}");
        }
    }

    #[test]
    fn default_and_rootless_targets_have_distinct_cache_identities() {
        let default = target(ImageBuildRole::DefaultTenant, "default");
        let rootless = target(ImageBuildRole::RootlessTenant, "default");

        assert_ne!(default, rootless);
        assert_eq!(default.to_string(), "default-tenant.default");
        assert_eq!(rootless.to_string(), "rootless-tenant.default");
    }

    #[test]
    fn the_script_builds_the_staged_images_against_the_staged_mvm() {
        let t = target(ImageBuildRole::RuntimeOverlay, "default");
        let contract = contract_for(&t).unwrap();
        let script = render_build_script(&t, GuestArch::Aarch64, contract);

        assert!(
            script.contains(
                "'path:/work/images#legacyPackages.aarch64-linux.runtime-overlay.default'"
            )
        );
        assert!(script.contains("--override-input mvm 'path:/work/mvm'"));
        assert!(script.contains("/sbin/nix build"));
        assert!(script.contains("unset MVM_WORKSPACE_PATH"));
        assert!(!script.contains("MVM_HOST_BIN_DIR"));
        for file in contract.files {
            assert!(
                script.contains(&format!("'{}'", file.name)),
                "{}",
                file.name
            );
        }
        assert!(script.contains("\"/out/$name\""));
    }

    #[test]
    fn only_the_builder_image_script_points_at_the_host_binaries() {
        let t = target(ImageBuildRole::BuilderVm, "default");
        let script = render_build_script(&t, GuestArch::X86_64, contract_for(&t).unwrap());

        assert!(script.contains("export MVM_HOST_BIN_DIR=/work/host-bins"));
        assert!(script.contains("legacyPackages.x86_64-linux.builder-vm.default"));
    }

    fn write(path: &Path, body: &[u8]) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, body).unwrap();
    }

    #[test]
    fn the_work_tree_holds_both_checkouts_without_their_scratch() {
        let tmp = tempfile::tempdir().unwrap();
        let images = tmp.path().join("images-src");
        let mvm = tmp.path().join("mvm-src");
        write(&images.join("flake.nix"), b"{}");
        write(&images.join(".git/HEAD"), b"ref");
        write(&mvm.join("crates/a/src/lib.rs"), b"// src");
        write(&mvm.join("target/debug/junk"), b"x");
        let bins = tmp.path().join("bins");
        for name in BUILDER_HOST_BINARIES {
            write(&bins.join(name), name.as_bytes());
        }
        let dest = tmp.path().join("work");

        stage_work_tree(&images, &mvm, Some(&bins), &dest).unwrap();

        assert!(dest.join("images/flake.nix").is_file());
        assert!(!dest.join("images/.git").exists());
        assert!(dest.join("mvm/crates/a/src/lib.rs").is_file());
        assert!(!dest.join("mvm/target").exists());
        for name in BUILDER_HOST_BINARIES {
            assert_eq!(
                std::fs::read(dest.join("host-bins").join(name)).unwrap(),
                name.as_bytes()
            );
        }
    }

    #[test]
    fn a_missing_host_binary_fails_the_staging() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        write(&src.join("f"), b"x");
        let bins = tmp.path().join("bins");
        write(&bins.join("mvm-host-vm-init"), b"x");

        let err = stage_work_tree(&src, &src, Some(&bins), &tmp.path().join("work")).unwrap_err();

        assert!(err.to_string().contains("host binary"), "{err}");
    }

    #[test]
    fn the_host_binary_directory_is_the_last_one_reported() {
        assert_eq!(
            host_bin_dir_from("building...\nMVM_HOST_BIN_DIR=/a\nMVM_HOST_BIN_DIR=/b\n"),
            Some(PathBuf::from("/b"))
        );
        assert_eq!(host_bin_dir_from("nothing\n"), None);
        assert_eq!(host_bin_dir_from("MVM_HOST_BIN_DIR=\n"), None);
    }

    fn elf_kernel() -> Vec<u8> {
        let mut bytes = vec![0u8; KernelFormat::SNIFF_LEN];
        bytes[..4].copy_from_slice(b"\x7fELF");
        bytes
    }

    #[test]
    fn the_emitter_is_told_every_file_its_format_and_capability() {
        let tmp = tempfile::tempdir().unwrap();
        let built = tmp.path().join("built");
        let t = target(ImageBuildRole::DefaultTenant, "default");
        let contract = contract_for(&t).unwrap();
        for file in contract.files {
            write(&built.join(file.name), b"bytes");
        }
        write(&built.join("vmlinux"), &elf_kernel());
        let request = EmitRequest {
            images_root: Path::new("/images"),
            mvm_root: Path::new("/mvm"),
            arch: GuestArch::X86_64,
            builder_cache_contract: 4,
            built: &built,
            out: Path::new("/cache/staged"),
            contract,
        };

        let argv: Vec<String> = emit_argv(&request)
            .unwrap()
            .into_iter()
            .map(|a| a.into_string().unwrap())
            .collect();
        let joined = argv.join(" ");

        assert_eq!(argv[0], "/images/scripts/emit-local-manifest.py");
        assert!(joined.contains("--images-checkout /images --mvm-checkout /mvm"));
        assert!(joined.contains("--arch x86_64 --builder-cache-contract 4 --out /cache/staged"));
        assert!(joined.contains(&format!(
            "--artifact default_tenant_workload_kernel kernel:elf {}",
            built.join("vmlinux").display()
        )));
        assert!(joined.contains(&format!(
            "--artifact default_tenant_workload_rootfs verity_root_hash {}",
            built.join("rootfs.roothash").display()
        )));
        assert!(joined.contains("--capability default_tenant_workload_rootfs dm_verity"));
        assert_eq!(
            argv.iter().filter(|a| *a == "--artifact").count(),
            contract.files.len()
        );
    }

    #[test]
    fn a_kernel_with_no_known_magic_is_not_described() {
        let tmp = tempfile::tempdir().unwrap();
        let built = tmp.path().join("built");
        let t = target(ImageBuildRole::BuilderVm, "default");
        let contract = contract_for(&t).unwrap();
        for file in contract.files {
            write(&built.join(file.name), b"not a kernel");
        }
        let request = EmitRequest {
            images_root: Path::new("/images"),
            mvm_root: Path::new("/mvm"),
            arch: GuestArch::Aarch64,
            builder_cache_contract: 4,
            built: &built,
            out: Path::new("/out"),
            contract,
        };

        let err = emit_argv(&request).unwrap_err();

        assert!(err.to_string().contains("neither an ELF"), "{err}");
    }
}
