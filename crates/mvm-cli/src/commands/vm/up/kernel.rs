//! Workload-kernel resolution for `mvmctl up` boots — the kernel-less-image
//! fallback to the cached builder-VM kernel, and the `--kernel-pin` /
//! bundle-pin resolution paths against the mvm cache.

/// Kernel-less images (mkGuest ships no kernel) boot fine on libkrun,
/// which materializes its own bundled kernel and ignores this path. The
/// out-of-process backends (hvf and firecracker) need a real kernel file;
/// fall back to the cached builder-VM kernel — the same kernel the builder
/// and dev VMs boot — rather than handing them a missing path.
///
/// Firecracker's direct/manifest boot path already performs this same
/// fallback; without it here the flake path would refuse a kernel-less
/// mkGuest workload that the manifest path boots fine.
pub(in crate::commands::vm) fn resolve_workload_kernel(
    vmlinux_path: &str,
    hypervisor: &str,
) -> anyhow::Result<String> {
    if std::path::Path::new(vmlinux_path).exists() {
        return Ok(vmlinux_path.to_string());
    }
    // libkrun supplies its own bundled kernel, so it never needs the
    // fallback; every other out-of-process backend does.
    if !matches!(hypervisor, "hvf" | "firecracker") {
        return Ok(vmlinux_path.to_string());
    }
    let arch = if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else {
        "x86_64"
    };
    let fallback = format!(
        "{}/builder-vm/{arch}/kernels/workload/vmlinux",
        mvm_core::config::mvm_cache_dir()
    );
    if std::path::Path::new(&fallback).exists() {
        return Ok(fallback);
    }
    anyhow::bail!(
        "image has no kernel ({vmlinux_path} missing) and the {hypervisor} backend \
         needs one; the builder-VM kernel fallback at {fallback} is also absent — \
         run `mvmctl kernel build --which workload` once to populate it"
    )
}

/// Resolve the locally-built workload kernel from the mvm cache for a
/// `--kernel-pin` boot. Does not fall back to the image-supplied kernel or
/// the builder-VM fallback: the pin is explicit, so an absent cache entry
/// is always a hard error with a build hint.
///
/// Returns `Ok(path_string)` when the kernel is cached, `Err` otherwise with
/// a message that names the required build command.
pub(super) fn resolve_pinned_kernel(
    cache_dir: &std::path::Path,
    arch: &str,
    source_checkout: bool,
) -> anyhow::Result<String> {
    resolve_pinned_kernel_with(cache_dir, arch, source_checkout, download_published_kernel)
}

#[cfg(feature = "builder-vm")]
fn download_published_kernel(
    arch: &str,
    variant: &str,
    dest: &std::path::Path,
) -> anyhow::Result<()> {
    crate::update::download_kernel(arch, variant, dest)
}

#[cfg(not(feature = "builder-vm"))]
fn download_published_kernel(
    _arch: &str,
    _variant: &str,
    _dest: &std::path::Path,
) -> anyhow::Result<()> {
    anyhow::bail!(
        "kernel-pin: downloading published workload kernels requires mvm-cli's builder-vm feature"
    )
}

fn resolve_pinned_kernel_with<F>(
    cache_dir: &std::path::Path,
    arch: &str,
    source_checkout: bool,
    download_kernel: F,
) -> anyhow::Result<String>
where
    F: Fn(&str, &str, &std::path::Path) -> anyhow::Result<()>,
{
    use mvm_build::kernel_fetch::{KernelResolution, resolve_kernel};
    match resolve_kernel(cache_dir, arch, "workload", source_checkout) {
        KernelResolution::Cached(v) => Ok(v.path().display().to_string()),
        KernelResolution::NeedsBuild(p) => {
            anyhow::bail!(
                "kernel-pin: workload kernel not built yet (expected at {}); \
                 run `mvmctl kernel build --which workload` first",
                p.display()
            )
        }
        KernelResolution::NeedsFetch(p) => {
            download_kernel(arch, "workload", &p).map_err(|err| {
                anyhow::anyhow!(
                    "kernel-pin: downloading the published workload kernel for {arch} failed: {err:#}"
                )
            })?;
            Ok(p.display().to_string())
        }
    }
}

/// Resolve a `--kernel-pin` request to a concrete workload-kernel path, or
/// `None` when no pin was requested (the caller then falls back to the image's
/// own kernel / the default microVM image). The pin selects the locally-built
/// workload kernel from the mvm cache; presence is the signal — the value is a
/// human label only. Shared by the canonical `machine run` boot path.
pub(in crate::commands) fn resolve_kernel_pin_path(pinned: bool) -> anyhow::Result<Option<String>> {
    if !pinned {
        return Ok(None);
    }
    let cache_dir = std::path::PathBuf::from(mvm_core::config::mvm_cache_dir());
    let arch = if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else {
        "x86_64"
    };
    let source_checkout =
        crate::commands::env::builder_vm::find_builder_vm_flake_is_source_checkout();
    Ok(Some(resolve_pinned_kernel(
        &cache_dir,
        arch,
        source_checkout,
    )?))
}

pub(super) fn persistent_oci_uses_prod_kernel(
    profile: &str,
    runtime_source_policy: mvm_core::vm_backend::RuntimeSourcePolicy,
) -> bool {
    profile != "dev"
        || runtime_source_policy == mvm_core::vm_backend::RuntimeSourcePolicy::RequiredOverlay
}

#[cfg(test)]
mod resolve_workload_kernel_tests {
    use super::*;
    use mvm_core::util::test_env::TestEnv;

    #[test]
    fn existing_path_passes_through_unchanged() {
        let tmp = tempfile::tempdir().unwrap();
        let vmlinux = tmp.path().join("vmlinux");
        std::fs::write(&vmlinux, b"kernel").unwrap();
        let result = resolve_workload_kernel(vmlinux.to_str().unwrap(), "hvf").unwrap();
        assert_eq!(result, vmlinux.to_str().unwrap());
    }

    #[test]
    fn non_hvf_hypervisor_passes_through_even_when_missing() {
        let mut env = TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.set("MVM_HOME", tmp.path());
        let result = resolve_workload_kernel("/nonexistent/vmlinux", "libkrun").unwrap();
        assert_eq!(result, "/nonexistent/vmlinux");
    }

    #[test]
    fn hvf_missing_kernel_falls_back_to_builder_vm_cache() {
        let mut env = TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        let arch = if cfg!(target_arch = "aarch64") {
            "aarch64"
        } else {
            "x86_64"
        };
        let fallback_dir = tmp
            .path()
            .join("cache")
            .join("builder-vm")
            .join(arch)
            .join("kernels")
            .join("workload");
        std::fs::create_dir_all(&fallback_dir).unwrap();
        let fallback = fallback_dir.join("vmlinux");
        std::fs::write(&fallback, b"builder-kernel").unwrap();
        env.set("MVM_HOME", tmp.path());
        let result = resolve_workload_kernel("/nonexistent/vmlinux", "hvf").unwrap();
        assert_eq!(result, fallback.to_str().unwrap());
    }

    #[test]
    fn firecracker_missing_kernel_falls_back_to_builder_vm_cache() {
        // The firecracker flake path must reuse the cached builder-VM
        // kernel for a kernel-less mkGuest workload, exactly as the
        // firecracker manifest path does — otherwise a `sleeper`-style
        // image (no emitted vmlinux) can't boot under firecracker.
        let mut env = TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        let arch = if cfg!(target_arch = "aarch64") {
            "aarch64"
        } else {
            "x86_64"
        };
        let fallback_dir = tmp
            .path()
            .join("cache")
            .join("builder-vm")
            .join(arch)
            .join("kernels")
            .join("workload");
        std::fs::create_dir_all(&fallback_dir).unwrap();
        let fallback = fallback_dir.join("vmlinux");
        std::fs::write(&fallback, b"builder-kernel").unwrap();
        env.set("MVM_HOME", tmp.path());
        let result = resolve_workload_kernel("/nonexistent/vmlinux", "firecracker").unwrap();
        assert_eq!(result, fallback.to_str().unwrap());
    }

    #[test]
    fn hvf_both_missing_returns_error_mentioning_bootstrap() {
        let mut env = TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.set("MVM_HOME", tmp.path());
        let err = resolve_workload_kernel("/nonexistent/vmlinux", "hvf").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("mvmctl kernel build --which workload"),
            "expected 'mvmctl kernel build --which workload' in: {msg}"
        );
        assert!(msg.contains("hvf"), "expected hypervisor name in: {msg}");
    }
}

#[cfg(test)]
mod resolve_pinned_kernel_tests {
    use super::*;

    #[test]
    fn cached_kernel_returns_its_path_when_pinned() {
        // Staged with a recorded digest: a cache hit is now evidence about the
        // bytes, not about the filename. Without the pin this resolves to
        // "needs build" — see `an_unpinned_cached_kernel_is_not_served`.
        let _env = mvm_core::util::test_env::TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        let kernel_path =
            mvm_build::kernel_fetch::cached_kernel_path(tmp.path(), "aarch64", "workload");
        std::fs::create_dir_all(kernel_path.parent().unwrap()).unwrap();
        std::fs::write(&kernel_path, b"vmlinux").unwrap();
        mvm_build::kernel_fetch::record_kernel_digest(&kernel_path).unwrap();
        let result = resolve_pinned_kernel(tmp.path(), "aarch64", true).unwrap();
        assert_eq!(result, kernel_path.display().to_string());
    }

    #[test]
    fn an_unpinned_cached_kernel_is_not_served() {
        // The behaviour this replaces: a kernel was booted because a file sat
        // at the expected path. It now falls through to the build hint.
        let _env = mvm_core::util::test_env::TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        let kernel_path =
            mvm_build::kernel_fetch::cached_kernel_path(tmp.path(), "aarch64", "workload");
        std::fs::create_dir_all(kernel_path.parent().unwrap()).unwrap();
        std::fs::write(&kernel_path, b"vmlinux").unwrap();

        let err = resolve_pinned_kernel(tmp.path(), "aarch64", true).unwrap_err();
        assert!(
            err.to_string().contains("mvmctl kernel build"),
            "expected the build hint, got: {err}"
        );
    }

    #[test]
    fn source_checkout_without_cache_returns_err_with_build_hint() {
        let tmp = tempfile::tempdir().unwrap();
        let err = resolve_pinned_kernel(tmp.path(), "aarch64", true).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("mvmctl kernel build"),
            "expected build hint in: {msg}"
        );
    }

    #[test]
    fn installed_binary_without_cache_fetches_the_published_kernel() {
        let tmp = tempfile::tempdir().unwrap();
        let result =
            resolve_pinned_kernel_with(tmp.path(), "x86_64", false, |arch, variant, dest| {
                assert_eq!(arch, "x86_64");
                assert_eq!(variant, "workload");
                std::fs::create_dir_all(dest.parent().expect("cache parent")).unwrap();
                std::fs::write(dest, b"downloaded-vmlinux").unwrap();
                Ok(())
            })
            .unwrap();
        let expected =
            mvm_build::kernel_fetch::cached_kernel_path(tmp.path(), "x86_64", "workload");
        assert_eq!(result, expected.display().to_string());
        assert_eq!(std::fs::read(expected).unwrap(), b"downloaded-vmlinux");
    }

    #[test]
    fn installed_binary_without_cache_surfaces_download_failures() {
        let tmp = tempfile::tempdir().unwrap();
        let err = resolve_pinned_kernel_with(tmp.path(), "x86_64", false, |_, _, _| {
            anyhow::bail!("simulated download failure")
        })
        .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("kernel-pin:"),
            "expected kernel-pin context in: {msg}"
        );
        assert!(
            msg.contains("simulated download failure"),
            "expected download failure detail in: {msg}"
        );
    }
}
