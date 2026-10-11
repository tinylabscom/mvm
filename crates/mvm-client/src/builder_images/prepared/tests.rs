use super::*;
use mvm_core::image_set::{ImageSetRole, LOCAL_SET_MANIFEST_NAME};
use mvm_core::packs::Sha256Hex;
use std::path::Path;

fn write(path: &Path, bytes: &[u8]) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, bytes).unwrap();
}

fn commit(root: &Path) {
    for args in [
        &["init", "-q"][..],
        &["add", "-A"],
        &["commit", "-qm", "fixture"],
    ] {
        let output = mvm_core::env_hygiene::helper_command("git")
            .arg("-C")
            .arg(root)
            .args([
                "-c",
                "user.name=test",
                "-c",
                "user.email=test@example.invalid",
                "-c",
                "commit.gpgsign=false",
            ])
            .args(args)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env_remove("GIT_DIR")
            .env_remove("GIT_WORK_TREE")
            .env_remove("GIT_INDEX_FILE")
            .output()
            .unwrap_or_else(|error| {
                panic!(
                    "git {args:?} in {} failed: {error}; PATH={:?}",
                    root.display(),
                    std::env::var_os("PATH")
                )
            });
        assert!(output.status.success(), "{output:?}");
    }
}

struct Pair {
    tmp: tempfile::TempDir,
    images: LocalImageCheckout,
    mvm: std::path::PathBuf,
    cache: LocalImageCache,
    // Keep process env stable through key derivation, publication and resolution,
    // not just while creating the repositories. Drop after the fixture fields.
    env: mvm_core::util::test_env::TestEnv,
}

impl Pair {
    fn new() -> Self {
        let env = mvm_core::util::test_env::TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        let images = tmp.path().join("images");
        for marker in mvm_build::image_source::IMAGES_CHECKOUT_MARKERS {
            write(&images.join(marker), b"# fixture\n");
        }
        commit(&images);
        let images = LocalImageCheckout::open(&images).unwrap();
        let mvm = tmp.path().join("mvm");
        write(
            &mvm.join("Cargo.toml"),
            br#"[workspace]
[workspace.metadata.mvm.toolchain]
rust = "nightly-2026-08-25"
zig = "0.14.1"
cargo-zigbuild = "0.20.1"
[workspace.metadata.mvm.toolchain.targets]
aarch64 = "aarch64-unknown-linux-musl"
x86_64 = "x86_64-unknown-linux-musl"
"#,
        );
        write(
            &mvm.join("rust-toolchain.toml"),
            b"[toolchain]\nchannel = \"nightly-2026-08-25\"\n",
        );
        commit(&mvm);
        let cache = LocalImageCache::at(tmp.path().join("cache"));
        Self {
            tmp,
            images,
            mvm,
            cache,
            env,
        }
    }

    fn target(&self) -> ImageBuildTarget {
        workload_kernel_target(WorkloadImageProfile::DefaultTenant)
    }

    fn resolve(&self) -> Result<CachedImageSet> {
        resolve_pair_in(&self.images, &self.mvm, self.target(), &self.cache)
    }

    fn publish(&self) -> CachedImageSet {
        let target = self.target();
        let key = LocalImageCacheKey::derive(&KeyInputs {
            images: &self.images,
            mvm_checkout: &self.mvm,
            target: &target,
            arch: GuestArch::host(),
        })
        .unwrap();
        let staged = self.cache.stage(&key).unwrap();
        let checkouts = self.images.current_checkouts(&self.mvm).unwrap();
        let profile = WorkloadImageProfile::DefaultTenant;
        let mut members = Vec::new();
        for (role, names, boot) in [
            (
                ImageSetRole::WorkloadKernel(profile),
                vec!["vmlinux"],
                Some("linux_direct"),
            ),
            (
                ImageSetRole::WorkloadRootfs(profile),
                vec![
                    "rootfs.ext4",
                    "rootfs.verity",
                    "rootfs.roothash",
                    "mvm-meta.json",
                ],
                None,
            ),
        ] {
            let mut artifacts = Vec::new();
            for name in names {
                let bytes = format!("fixture {name}");
                let format = match name {
                    "vmlinux" => serde_json::json!({"kernel": "image"}),
                    "rootfs.ext4" => serde_json::json!("ext4"),
                    "rootfs.verity" => serde_json::json!("verity_hash_tree"),
                    "rootfs.roothash" => serde_json::json!("verity_root_hash"),
                    _ => serde_json::json!("json"),
                };
                write(&staged.dir().join(name), bytes.as_bytes());
                artifacts.push(serde_json::json!({
                    "name": name, "format": format,
                    "sha256": Sha256Hex::from_bytes(bytes.as_bytes()).as_str(), "size": bytes.len(),
                }));
            }
            members.push(serde_json::json!({
                "role": role, "target": {"arch": key.arch.to_string()},
                "boot_protocol": boot, "artifacts": artifacts, "required_capabilities": [],
            }));
        }
        let manifest = serde_json::json!({
            "schema_version": 2, "set_version": "0.0.0-local", "issued_at": "2026-01-01T00:00:00Z",
            "producer": {"local_checkouts": checkouts}, "mvm_source_commit": checkouts.mvm.commit,
            "compatibility": {
                "guest_agent_protocol": {"min": 2, "max": 2}, "builder_cache_contract": 1, "builder_boot_abi": 0
            },
            "nix_inputs": {
                "flake_locks": [{"reference": "mvm-images:flake.lock", "lock_hash": Sha256Hex::from_bytes(b"lock").as_str()}],
                "source_revisions": []
            },
            "members": members,
        });
        write(
            &staged.dir().join(LOCAL_SET_MANIFEST_NAME),
            &serde_json::to_vec(&manifest).unwrap(),
        );
        self.cache
            .publish(
                staged,
                &EntryContext {
                    images: &self.images,
                    mvm_checkout: &self.mvm,
                    roles: contract_for(&target).unwrap().set_roles,
                },
            )
            .unwrap()
            .entry()
            .clone()
    }
}

#[test]
fn prepared_pair_resolves_exact_key_without_acquisition() {
    let pair = Pair::new();
    let entry = pair.publish();
    let resolved = pair.resolve().unwrap();
    assert_eq!(resolved.key, entry.key);
    assert_eq!(resolved.dir, entry.dir);
}

#[test]
fn cold_pair_fails_with_executable_preparation_guidance() {
    let pair = Pair::new();
    let error = pair.resolve().unwrap_err().to_string();
    assert!(
        error.contains("mvmctl build image-set default-tenant --attr default"),
        "{error}"
    );
    assert!(
        !pair.cache.root().exists(),
        "resolution must not acquire artifacts"
    );
}

#[test]
fn tampered_pair_is_rejected_not_rebuilt() {
    let pair = Pair::new();
    let entry = pair.publish();
    let artifact = &entry.set.artifacts[0].path;
    std::fs::remove_file(artifact).unwrap();
    std::fs::write(artifact, b"tampered").unwrap();
    let error = pair.resolve().unwrap_err().to_string();
    assert!(error.contains("failed verification"), "{error}");
}

#[test]
fn changed_selected_source_cannot_reuse_a_prepared_pair() {
    let pair = Pair::new();
    let entry = pair.publish();
    write(
        &pair.images.root().join("flake.nix"),
        b"# changed after selection\n",
    );
    assert!(pair.resolve().is_err());
    assert!(
        entry.dir.exists(),
        "source mismatch must be rejected before cache eviction"
    );
}

#[test]
fn selected_pair_cannot_replace_a_different_pinned_runtime() {
    let mut pair = Pair::new();
    pair.env.isolate_mvm_home(pair.tmp.path());
    let mut resolve = resolve_pair;
    let mut source = crate::launch::runtime_source::PairArtifactSource {
        checkout: &pair.images,
        build: &mut resolve,
    };
    let mut config = mvm_core::vm_backend::VmStartConfig::default();
    let error = crate::launch::runtime_source::attach_runtime_overlay_if_cached_version(
        &mut config,
        "hvf",
        Some("0.0.0-missing"),
        Some(&mut source),
    )
    .unwrap_err()
    .to_string();
    assert!(
        error.contains("do not replace the pinned guest runtime"),
        "{error}"
    );
    assert!(config.runtime_overlay_path.is_none());
}

#[test]
fn selected_pair_cold_runtime_requires_explicit_bootstrap() {
    let mut pair = Pair::new();
    pair.env.isolate_mvm_home(pair.tmp.path());
    pair.env
        .set("MVM_UPDATE_DOWNLOAD_URL", "http://127.0.0.1:1");
    let mut resolve = resolve_pair;
    let mut source = crate::launch::runtime_source::PairArtifactSource {
        checkout: &pair.images,
        build: &mut resolve,
    };
    let mut config = mvm_core::vm_backend::VmStartConfig::default();
    let error = crate::launch::runtime_source::attach_runtime_overlay_if_cached_version(
        &mut config,
        "hvf",
        None,
        Some(&mut source),
    )
    .unwrap_err()
    .to_string();
    assert!(
        error.contains("MVM_RUNTIME_OVERLAY_ACQUIRE_MODE=build mvmctl bootstrap"),
        "{error}"
    );
    assert!(config.runtime_overlay_path.is_none());
}

#[test]
fn sibling_and_bundled_kernel_do_not_consult_pair_fallback() {
    let pair = Pair::new();
    let sibling = pair.tmp.path().join("vmlinux");
    write(&sibling, b"kernel");
    for (path, backend) in [
        (sibling.to_str().unwrap(), "hvf"),
        ("/missing/vmlinux", "libkrun"),
    ] {
        assert_eq!(
            resolve_workload_kernel_with(path, backend, || anyhow::bail!("must not select"))
                .unwrap(),
            path
        );
    }
}

// ── Kernel-less-image fallback matrix ────────────────────────────────────
//
// mkGuest images ship no kernel: libkrun materializes its bundled kernel and
// ignores the path, but hvf and firecracker need a real kernel file and fall
// back to the cached, verified workload kernel. These pin that matrix.

fn resolve_released_workload_kernel(
    vmlinux_path: &str,
    hypervisor: &str,
) -> anyhow::Result<String> {
    resolve_workload_kernel_with(vmlinux_path, hypervisor, || Ok(None))
}

#[test]
fn existing_path_passes_through_unchanged() {
    let tmp = tempfile::tempdir().unwrap();
    let vmlinux = tmp.path().join("vmlinux");
    std::fs::write(&vmlinux, b"kernel").unwrap();
    let result = resolve_released_workload_kernel(vmlinux.to_str().unwrap(), "hvf").unwrap();
    assert_eq!(result, vmlinux.to_str().unwrap());
}

#[test]
fn non_hvf_hypervisor_passes_through_even_when_missing() {
    let mut env = mvm_core::util::test_env::TestEnv::new();
    let tmp = tempfile::tempdir().unwrap();
    env.isolate_mvm_home(tmp.path());
    let result = resolve_released_workload_kernel("/nonexistent/vmlinux", "libkrun").unwrap();
    assert_eq!(result, "/nonexistent/vmlinux");
}

/// Stage a workload kernel in the cache under `MVM_HOME`, optionally
/// recording the digest sidecar a verified read requires.
fn stage_cached_workload_kernel(
    home: &std::path::Path,
    bytes: &[u8],
    pin: bool,
) -> std::path::PathBuf {
    let arch = mvm_core::arch::GuestArch::host().to_string();
    let kernel =
        mvm_build::kernel_fetch::cached_kernel_path(&home.join("cache"), &arch, "workload");
    std::fs::create_dir_all(kernel.parent().unwrap()).unwrap();
    std::fs::write(&kernel, bytes).unwrap();
    if pin {
        mvm_build::kernel_fetch::record_kernel_digest(&kernel).unwrap();
    }
    kernel
}

#[test]
fn hvf_missing_kernel_falls_back_to_cached_workload_kernel() {
    let mut env = mvm_core::util::test_env::TestEnv::new();
    let tmp = tempfile::tempdir().unwrap();
    env.isolate_mvm_home(tmp.path());
    let fallback = stage_cached_workload_kernel(tmp.path(), b"builder-kernel", true);
    let result = resolve_released_workload_kernel("/nonexistent/vmlinux", "hvf").unwrap();
    assert_eq!(result, fallback.to_str().unwrap());
}

#[test]
fn firecracker_missing_kernel_falls_back_to_cached_workload_kernel() {
    // The firecracker flake path must reuse the cached workload kernel
    // for a kernel-less mkGuest workload, exactly as the firecracker
    // manifest path does — otherwise a `sleeper`-style image (no emitted
    // vmlinux) can't boot under firecracker.
    let mut env = mvm_core::util::test_env::TestEnv::new();
    let tmp = tempfile::tempdir().unwrap();
    env.isolate_mvm_home(tmp.path());
    let fallback = stage_cached_workload_kernel(tmp.path(), b"builder-kernel", true);
    let result = resolve_released_workload_kernel("/nonexistent/vmlinux", "firecracker").unwrap();
    assert_eq!(result, fallback.to_str().unwrap());
}

#[test]
fn an_unpinned_fallback_kernel_is_refused() {
    // The behaviour this replaces: the kernel-less-image route formatted
    // the cache path itself and booted whatever sat there. Both tests
    // above passed without a digest before this change.
    let mut env = mvm_core::util::test_env::TestEnv::new();
    let tmp = tempfile::tempdir().unwrap();
    env.isolate_mvm_home(tmp.path());
    let kernel = stage_cached_workload_kernel(tmp.path(), b"builder-kernel", false);
    let err = resolve_released_workload_kernel("/nonexistent/vmlinux", "firecracker").unwrap_err();
    assert!(
        err.to_string().contains("no verified workload kernel"),
        "expected the verification refusal, got: {err}"
    );
    assert!(
        !kernel.exists(),
        "an unpinned kernel is evicted, not left to be re-adopted"
    );
}

#[test]
fn a_tampered_fallback_kernel_is_refused() {
    let mut env = mvm_core::util::test_env::TestEnv::new();
    let tmp = tempfile::tempdir().unwrap();
    env.isolate_mvm_home(tmp.path());
    let kernel = stage_cached_workload_kernel(tmp.path(), b"the real kernel", true);
    // Same length, so a size check would not notice.
    std::fs::write(&kernel, b"the fake kernel").unwrap();
    let err = resolve_released_workload_kernel("/nonexistent/vmlinux", "firecracker").unwrap_err();
    assert!(
        err.to_string().contains("no verified workload kernel"),
        "expected the verification refusal, got: {err}"
    );
    assert!(!kernel.exists(), "rejected kernel removed");
}

#[test]
fn hvf_both_missing_returns_error_mentioning_bootstrap() {
    let mut env = mvm_core::util::test_env::TestEnv::new();
    let tmp = tempfile::tempdir().unwrap();
    env.isolate_mvm_home(tmp.path());
    let err = resolve_released_workload_kernel("/nonexistent/vmlinux", "hvf").unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("mvmctl kernel build --which workload"),
        "expected 'mvmctl kernel build --which workload' in: {msg}"
    );
    assert!(msg.contains("hvf"), "expected hypervisor name in: {msg}");
}
