//! Idempotent extraction of embedded host-vm binaries to a
//! content-hashed dir under the supplied cache root (typically
//! `~/.cache/mvm/host-bins`). Re-verifies each binary's SHA-256
//! against the embedded constant on every call — a corrupted or
//! tampered on-disk cache fails closed.

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use super::embedded::EMBEDDED;
use super::source_build::{has_source_checkout, resolve_or_build_host_binaries};

pub fn ensure_extracted(cache_root: &Path) -> std::io::Result<PathBuf> {
    let combined_hash = combined_hash_hex();
    let target = cache_root.join(&combined_hash);
    std::fs::create_dir_all(&target)?;
    // Lock the parent + restrict its perms.
    let perm = std::fs::Permissions::from_mode(0o700);
    let _ = std::fs::set_permissions(cache_root, perm.clone());
    let _ = std::fs::set_permissions(&target, perm);

    for bin in EMBEDDED.iter() {
        let final_path = target.join(bin.name);
        if final_path.exists() && verify_sha(&final_path, bin.sha256_hex)? {
            continue;
        }
        write_atomic(&final_path, bin.bytes, 0o755)?;
        if !verify_sha(&final_path, bin.sha256_hex)? {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("post-extract SHA mismatch for {}", bin.name),
            ));
        }
    }
    Ok(target)
}

/// Like [`ensure_extracted`], but refuses a stub build — the zero-byte
/// binaries baked into non-release builds unless `MVM_EMBED_BINARIES=1`
/// overrides the fast path. Call this from any path that actually boots a VM
/// from the embedded binaries so a stub build fails fast with a clear message
/// instead of an opaque builder-VM boot failure.
pub fn ensure_extracted_for_boot(cache_root: &Path) -> std::io::Result<PathBuf> {
    if EMBEDDED.iter().any(|bin| bin.bytes.is_empty()) {
        if has_source_checkout() {
            return resolve_or_build_host_binaries(cache_root)
                .map_err(|e| std::io::Error::other(e.to_string()));
        }
        let stub = EMBEDDED
            .iter()
            .find(|bin| bin.bytes.is_empty())
            .expect("stub binary present when any embedded payload is empty");
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "embedded host-vm binary `{}` is a zero-byte stub — this mvmctl was \
                 built without real embedded host binaries and has no source checkout to \
                 build them from",
                stub.name
            ),
        ));
    }
    ensure_extracted(cache_root)
}

pub struct BootHostBinaries {
    pub dir: PathBuf,
    pub stage0_init: Vec<u8>,
}

/// Resolve the Linux host binaries required to boot Stage 0 or any source-built
/// local builder path. Real embedded builds extract the payload as-is; source
/// checkouts that baked zero-byte stubs rebuild the same musl binaries and
/// cache them under `cache_root`.
pub fn ensure_boot_host_binaries(cache_root: &Path) -> anyhow::Result<BootHostBinaries> {
    if embedded_stub_build() {
        let workspace_root = source_checkout_workspace_root().ok_or_else(|| {
            anyhow::anyhow!(
                "embedded host-vm binaries are zero-byte stubs and no source checkout was found; \
                 rebuild with MVM_EMBED_BINARIES=1 or run from a source checkout with \
                 nix/images/builder-vm/flake.nix present"
            )
        })?;
        let dir = build_host_binaries_from_source(cache_root, &workspace_root)?;
        let stage0_init = std::fs::read(dir.join("stage0-init"))
            .map_err(|e| anyhow::anyhow!("read source-built stage0-init: {e}"))?;
        return Ok(BootHostBinaries { dir, stage0_init });
    }

    let dir = ensure_extracted_for_boot(cache_root)
        .map_err(|e| anyhow::anyhow!("extract embedded host-vm binaries: {e}"))?;
    let stage0_init = std::fs::read(dir.join("stage0-init"))
        .map_err(|e| anyhow::anyhow!("read embedded stage0-init: {e}"))?;
    Ok(BootHostBinaries { dir, stage0_init })
}

fn combined_hash_hex() -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    for bin in EMBEDDED.iter() {
        h.update(bin.name.as_bytes());
        h.update(bin.sha256_hex.as_bytes());
    }
    format!("{:x}", h.finalize())
}

fn verify_sha(path: &Path, expected_hex: &str) -> std::io::Result<bool> {
    use sha2::{Digest, Sha256};
    let bytes = std::fs::read(path)?;
    let mut h = Sha256::new();
    h.update(&bytes);
    Ok(format!("{:x}", h.finalize()) == expected_hex)
}

fn write_atomic(target: &Path, bytes: &[u8], mode: u32) -> std::io::Result<()> {
    let tmp = target.with_extension(format!("tmp.{}.{}", std::process::id(), rand_suffix()));
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        f.set_permissions(std::fs::Permissions::from_mode(mode))?;
    }
    std::fs::rename(&tmp, target)
}

fn rand_suffix() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{n:x}")
}

fn embedded_stub_build() -> bool {
    EMBEDDED.iter().any(|bin| bin.bytes.is_empty())
}

fn source_checkout_workspace_root() -> Option<PathBuf> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = super::toolchain::workspace_root_from_manifest_dir(&manifest_dir);
    workspace_root
        .join("nix/images/builder-vm/flake.nix")
        .exists()
        .then_some(workspace_root)
}

fn build_host_binaries_from_source(
    cache_root: &Path,
    workspace_root: &Path,
) -> anyhow::Result<PathBuf> {
    let pin = super::toolchain::read_pinned_toolchain(workspace_root, std::env::consts::ARCH);
    let source_dir = source_built_dir(cache_root, workspace_root, &pin.target);
    std::fs::create_dir_all(&source_dir).map_err(|e| {
        anyhow::anyhow!(
            "create source-built host-binary dir {}: {e}",
            source_dir.display()
        )
    })?;

    let target_dir = runtime_host_target_dir(workspace_root);
    std::fs::create_dir_all(&target_dir).map_err(|e| {
        anyhow::anyhow!(
            "create host-binary target dir {}: {e}",
            target_dir.display()
        )
    })?;

    for (package, bins) in host_binary_build_groups() {
        run_host_bin_zigbuild(workspace_root, &target_dir, &pin, package, &bins)?;
    }

    let built_root = target_dir
        .join(super::toolchain::strip_glibc(&pin.target))
        .join("release");
    for spec in host_binary_specs() {
        let built = built_root.join(spec.name);
        if !built.is_file() {
            return Err(anyhow::anyhow!(
                "source-built host binary missing after cargo zigbuild: {}",
                built.display()
            ));
        }
        let bytes = std::fs::read(&built).map_err(|e| {
            anyhow::anyhow!("read source-built host binary {}: {e}", built.display())
        })?;
        write_atomic(&source_dir.join(spec.name), &bytes, 0o755)
            .map_err(|e| anyhow::anyhow!("cache source-built host binary {}: {e}", spec.name))?;
    }

    Ok(source_dir)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct HostBinarySpec {
    package: &'static str,
    name: &'static str,
}

fn host_binary_specs() -> Vec<HostBinarySpec> {
    let mut specs = Vec::new();
    specs.extend(
        super::manifest::HOST_BINARIES
            .iter()
            .map(|bin| HostBinarySpec {
                package: "mvm-build",
                name: bin.name,
            }),
    );
    specs.extend(
        super::manifest::SEED_BINARIES
            .iter()
            .copied()
            .map(|name| HostBinarySpec {
                package: "mvm-build",
                name,
            }),
    );
    specs.extend(
        super::manifest::BOOTSTRAP_SUPPORT_BINARIES
            .iter()
            .map(|bin| HostBinarySpec {
                package: bin.package,
                name: bin.name,
            }),
    );
    specs
}

fn host_binary_build_groups() -> Vec<(&'static str, Vec<&'static str>)> {
    let mut groups = std::collections::BTreeMap::<&'static str, Vec<&'static str>>::new();
    for spec in host_binary_specs() {
        groups.entry(spec.package).or_default().push(spec.name);
    }
    groups.into_iter().collect()
}

fn source_built_dir(cache_root: &Path, workspace_root: &Path, target: &str) -> PathBuf {
    let workspace_key = {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(workspace_root.to_string_lossy().as_bytes());
        let hex = hex::encode(h.finalize());
        hex[..12].to_string()
    };
    cache_root.join(format!(
        "source-built-{}-{}",
        workspace_key,
        super::toolchain::strip_glibc(target)
    ))
}

fn runtime_host_target_dir(workspace_root: &Path) -> PathBuf {
    if let Ok(target_dir) = std::env::var("CARGO_TARGET_DIR")
        && !target_dir.trim().is_empty()
    {
        let base = PathBuf::from(target_dir.trim());
        return if base.is_absolute() {
            base.join("mvm-host-bins-source-build")
        } else {
            workspace_root.join(base).join("mvm-host-bins-source-build")
        };
    }
    workspace_root.join("target/mvm-host-bins-source-build")
}

fn run_host_bin_zigbuild(
    workspace_root: &Path,
    target_dir: &Path,
    pin: &super::toolchain::Pin,
    package: &str,
    bins: &[&str],
) -> anyhow::Result<()> {
    let (cargo, rustc) =
        super::toolchain::rustup_cargo_and_rustc(super::toolchain::strip_glibc(&pin.target));
    let mut cmd = std::process::Command::new(&cargo);
    cmd.args([
        "zigbuild",
        "--release",
        "--target",
        &pin.target,
        "-p",
        package,
    ])
    .env("RUSTC", &rustc)
    .env("CARGO_TARGET_DIR", target_dir)
    .env_remove("RUSTUP_TOOLCHAIN")
    .env_remove("RUSTC_WRAPPER")
    .env_remove("RUSTC_WORKSPACE_WRAPPER")
    .current_dir(workspace_root);
    if let Some(zig) = super::toolchain::pinned_zig_path_or_fail(&pin.zig) {
        cmd.env("CARGO_ZIGBUILD_ZIG_PATH", zig);
    }
    for name in bins {
        cmd.args(["--bin", name]);
    }
    let status = cmd.status().map_err(|e| {
        anyhow::anyhow!(
            "spawn cargo zigbuild for source-built host binaries in package {package}: {e}"
        )
    })?;
    if !status.success() {
        return Err(anyhow::anyhow!(
            "cargo zigbuild failed while source-building host binaries for Stage 0 (package {package})"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_host_target_dir_honors_cargo_target_dir() {
        unsafe {
            std::env::set_var("CARGO_TARGET_DIR", "/tmp/mvm-host-bins-target");
        }
        let got = runtime_host_target_dir(Path::new("/work/mvm"));
        unsafe {
            std::env::remove_var("CARGO_TARGET_DIR");
        }
        assert_eq!(
            got,
            PathBuf::from("/tmp/mvm-host-bins-target/mvm-host-bins-source-build")
        );
    }

    #[test]
    fn source_built_dir_is_workspace_scoped() {
        let a = source_built_dir(
            Path::new("/tmp/cache"),
            Path::new("/worktrees/a"),
            "aarch64-unknown-linux-musl",
        );
        let b = source_built_dir(
            Path::new("/tmp/cache"),
            Path::new("/worktrees/b"),
            "aarch64-unknown-linux-musl",
        );
        assert_ne!(a, b);
    }

    #[test]
    fn host_binary_names_include_bootstrap_support_binaries() {
        let names: Vec<_> = host_binary_specs()
            .into_iter()
            .map(|spec| spec.name)
            .collect();
        assert!(names.contains(&"mvm-egress-client"));
    }

    #[test]
    fn host_binary_build_groups_include_guest_helpers_support_binary() {
        let groups = host_binary_build_groups();
        assert!(groups.iter().any(|(package, bins)| {
            *package == "mvm-guest-helpers" && bins.contains(&"mvm-egress-client")
        }));
    }
}
