//! Runtime-overlay attachment + status resolution for `mvmctl up` boots —
//! the verity-sealed guest-binary overlay every workload backend consumes,
//! and the audit label describing which source strategy actually landed.
//!
//! The optional glibc SDK sidecar rides the same seam: it is resolved from the
//! same version-keyed cache discipline and attached through the same
//! plan-admitted read-only disk mechanism, so there is one attachment path, not
//! two. Where the runtime overlay is attached to every workload, the sidecar is
//! attached only to workloads whose signed plan binds an SDK-served host
//! service.

use anyhow::{Context, Result};

pub(crate) use mvm_runtime::sdk_sidecar::SdkSidecarAttachment;

use crate::commands::runtime_overlay::{
    RuntimeOverlayAcquireMode, RuntimeOverlayAcquireParams, acquire_runtime_overlay,
    runtime_overlay_acquire_mode, runtime_overlay_source_checkout_root,
};
use crate::ui;

/// Report where this launch's guest binaries come from.
///
/// There is one answer now — the runtime overlay — so this reports whether the
/// overlay was actually attached rather than which of several postures applied.
pub(crate) fn emit_runtime_source_status(start_config: &mvm_core::vm_backend::VmStartConfig) {
    let attached = start_config.runtime_overlay_path.is_some();
    tracing::info!(overlay_attached = attached, "resolved guest runtime source");
    ui::info(if attached {
        "Runtime source: overlay attached"
    } else {
        "Runtime source: overlay not attached"
    });
}

fn apply_runtime_overlay_artifact(
    start_config: &mut mvm_core::vm_backend::VmStartConfig,
    artifact: mvm_fs::overlay::RuntimeOverlayArtifact,
) {
    start_config.runtime_overlay_path = Some(artifact.overlay_ext4.display().to_string());
    start_config.runtime_overlay_verity_path = Some(artifact.sidecar.display().to_string());
    start_config.runtime_overlay_version = Some(artifact.version);
    start_config.runtime_overlay_roothash = Some(artifact.roothash);
}

/// Attach the verity-sealed runtime overlay by
/// populating `VmStartConfig`'s overlay fields from the resolver's cache
/// probe. Backends that can consume the sealed overlay attach it as extra
/// read-only block devices and thread the matching roothash through the
/// guest cmdline; unsupported backends ignore the fields.
/// **Fatal on a real backend**: the overlay is the only source of the guest
/// binaries, so a cold cache returns `Err` rather than leaving the fields
/// `None` and booting a guest that cannot reach an agent. The caller's
/// acquisition ladder catches that and builds or downloads. The seeded
/// resolve is a pure cache read — no build, no download, no `nix` — so this
/// is safe on every host.
#[tracing::instrument(skip_all, fields(hypervisor, arch = ?arch))]
pub(crate) fn attach_runtime_overlay(
    start_config: &mut mvm_core::vm_backend::VmStartConfig,
    hypervisor: &str,
    resolver: &mvm_fs::overlay::RuntimeOverlayResolver,
    arch: mvm_core::arch::GuestArch,
) -> Result<()> {
    if !matches!(hypervisor, "firecracker" | "hvf" | "qemu" | "libkrun") {
        return Ok(());
    }
    match mvm_build::runtime_overlay::resolve_or_seed_from_default_cache(resolver, arch) {
        Ok(a) => {
            apply_runtime_overlay_artifact(start_config, a);
            Ok(())
        }
        Err(e) => {
            anyhow::bail!("runtime overlay required for {hypervisor} boot but unavailable: {e}")
        }
    }
}

/// Production wrapper: build the resolver from the mvm cache dir + the
/// running mvmctl version, then attach for `hypervisor`. Called at each
/// workload-boot `VmStartConfig` construction in [`run`].
///
/// Ordinary starts always re-resolve the overlay for the current host build.
/// Callers that need same-version continuity across lifecycle state must use
/// [`attach_runtime_overlay_if_cached_version`] with an explicit pin.
pub(crate) fn attach_runtime_overlay_if_cached(
    start_config: &mut mvm_core::vm_backend::VmStartConfig,
    hypervisor: &str,
) -> Result<()> {
    attach_runtime_overlay_if_cached_version(start_config, hypervisor, None)
}

pub(crate) fn attach_runtime_overlay_if_cached_version(
    start_config: &mut mvm_core::vm_backend::VmStartConfig,
    hypervisor: &str,
    expected_version: Option<&str>,
) -> Result<()> {
    // The wasm backend runs a WASI module directly; it has no guest agent
    // runtime overlay to attach.
    if hypervisor == "wasm" {
        return Ok(());
    }
    let version = expected_version.unwrap_or(env!("CARGO_PKG_VERSION"));
    let cache_root = std::path::PathBuf::from(mvm_core::config::mvm_cache_dir());
    let arch = mvm_core::arch::GuestArch::host();
    if expected_version.is_none()
        && matches!(hypervisor, "firecracker" | "hvf" | "qemu" | "libkrun")
        && runtime_overlay_acquire_mode() == RuntimeOverlayAcquireMode::BuildFromSourceCheckout
        && runtime_overlay_source_checkout_root().is_some()
    {
        let artifact = mvm_build::runtime_overlay::resolve_or_build_local_runtime_overlay(
            &cache_root,
            version,
            arch,
        )?;
        apply_runtime_overlay_artifact(start_config, artifact);
        return Ok(());
    }
    let resolver =
        mvm_fs::overlay::RuntimeOverlayResolver::new(cache_root.clone(), version.to_string());
    match attach_runtime_overlay(start_config, hypervisor, &resolver, arch) {
        Ok(()) => Ok(()),
        Err(_err) => {
            if expected_version.is_some() {
                return Err(anyhow::anyhow!(
                    "runtime overlay version {version} is required for this boot and was not found in the local cache"
                ));
            }
            let acquire_mode = runtime_overlay_acquire_mode();
            let source_checkout_root = match acquire_mode {
                RuntimeOverlayAcquireMode::BuildFromSourceCheckout => {
                    runtime_overlay_source_checkout_root()
                }
                RuntimeOverlayAcquireMode::DownloadPublishedArtifact => None,
            };
            match acquire_mode {
                RuntimeOverlayAcquireMode::BuildFromSourceCheckout => {
                    ui::info(
                        "Runtime overlay missing from cache; building it from the source checkout...",
                    );
                }
                RuntimeOverlayAcquireMode::DownloadPublishedArtifact => {
                    ui::info(
                        "Runtime overlay missing from cache; downloading the published artifact now...",
                    );
                }
            }
            let artifact = acquire_runtime_overlay(&RuntimeOverlayAcquireParams {
                cache_root: &cache_root,
                expected_version: version,
                arch,
                source_checkout_root: source_checkout_root.as_deref(),
            })?;
            apply_runtime_overlay_artifact(start_config, artifact);
            tracing::info!(
                runtime_overlay_version = version,
                backend = hypervisor,
                "runtime overlay cache populated for required-overlay boot"
            );
            Ok(())
        }
    }
}

/// Local shell execution boundary for the initramfs build fallback.
///
/// On Linux this runs directly on the host (which *is* the builder VM
/// boundary). On macOS this path is never reached because the nix-build
/// fallback is `#[cfg(target_os = "linux")]`.
struct HostShellEnvironment;

impl mvm_core::build_env::ShellEnvironment for HostShellEnvironment {
    fn shell_exec(&self, script: &str) -> Result<()> {
        let output = std::process::Command::new("bash")
            .args(["-c", script])
            .output()
            .context("failed to run shell command")?;
        if output.status.success() {
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!(
                "shell command failed (exit {}): {stderr}",
                output.status.code().unwrap_or(-1)
            );
        }
    }

    fn shell_exec_stdout(&self, script: &str) -> Result<String> {
        let output = self.shell_exec_capture(script)?;
        Ok(output.0.trim().to_string())
    }

    fn shell_exec_visible(&self, script: &str) -> Result<()> {
        let status = std::process::Command::new("bash")
            .args(["-c", script])
            .stdin(std::process::Stdio::inherit())
            .stdout(std::process::Stdio::inherit())
            .stderr(std::process::Stdio::inherit())
            .status()
            .context("failed to run shell command")?;
        if status.success() {
            Ok(())
        } else {
            anyhow::bail!(
                "shell command failed (exit {})",
                status.code().unwrap_or(-1)
            );
        }
    }

    fn log_info(&self, msg: &str) {
        tracing::info!("{msg}");
    }

    fn log_success(&self, msg: &str) {
        tracing::info!("{msg}");
    }

    fn shell_exec_capture(&self, script: &str) -> Result<(String, String)> {
        let output = std::process::Command::new("bash")
            .args(["-c", script])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .output()
            .context("failed to run shell command")?;
        if output.status.success() {
            Ok((
                String::from_utf8_lossy(&output.stdout).into_owned(),
                String::from_utf8_lossy(&output.stderr).into_owned(),
            ))
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!(
                "shell command failed (exit {}): {stderr}",
                output.status.code().unwrap_or(-1)
            );
        }
    }
}

/// Attach the universal initramfs when it is present in the
/// cache. This is intentionally non-fatal: until the Nix-built initramfs is
/// seeded on every supported host, workloads that have a rootfs continue to
/// boot with their legacy `/init`. Once attached, `WorkloadRunner::start_workload`
/// will send `ActivateEnvironment` over vsock after boot.
/// Discard a cached universal initramfs whose recorded source fingerprint no
/// longer matches the checkout it would be attached from. Returns true when a
/// stale artifact was evicted.
///
/// A source checkout rebuilds its guest binaries when they change, but the
/// initramfs cache is keyed only on `(version, arch)` — so without this it
/// keeps serving the artifact built before the change, and a guest-side fix
/// appears not to have worked. Evicting on a fingerprint mismatch is what
/// makes the next resolve rebuild rather than re-find the stale bytes.
fn evict_stale_universal_initramfs(
    cache_root: &std::path::Path,
    version: &str,
    arch: mvm_core::arch::GuestArch,
) -> bool {
    let Some(workspace_root) = runtime_overlay_source_checkout_root() else {
        return false;
    };
    let Ok(fingerprint) =
        mvm_build::guest_agent_build::runtime_overlay_source_checkout_fingerprint(&workspace_root)
    else {
        return false;
    };
    matches!(
        mvm_build::initramfs::evict_if_source_changed(cache_root, version, arch, &fingerprint),
        Ok(true)
    )
}

/// Pure-read probe: would the universal initramfs attach from the cache
/// without building or downloading anything? Applies the same
/// source-fingerprint eviction as the attach path first, so a stale artifact
/// never counts as available.
#[cfg(test)]
pub(crate) fn universal_initramfs_available() -> bool {
    let version = env!("CARGO_PKG_VERSION");
    let cache_root = std::path::PathBuf::from(mvm_core::config::mvm_cache_dir()).join("initramfs");
    let arch = mvm_core::arch::GuestArch::host();
    evict_stale_universal_initramfs(&cache_root, version, arch);
    mvm_build::initramfs::resolve_or_seed_from_default_cache(&cache_root, version, arch).is_ok()
}

#[tracing::instrument(skip_all)]
pub(crate) fn attach_universal_initramfs_if_cached(
    start_config: &mut mvm_core::vm_backend::VmStartConfig,
) -> Result<()> {
    attach_universal_initramfs_with_resolver(start_config, |env, cache_root, version, arch| {
        mvm_build::initramfs::resolve_or_build_local_initramfs(env, cache_root, version, arch)
    })
}

fn attach_universal_initramfs_with_resolver(
    start_config: &mut mvm_core::vm_backend::VmStartConfig,
    resolve: impl FnOnce(
        &HostShellEnvironment,
        &std::path::Path,
        &str,
        mvm_core::arch::GuestArch,
    ) -> Result<
        mvm_fs::initramfs::InitramfsArtifact,
        mvm_build::initramfs::InitramfsBuildError,
    >,
) -> Result<()> {
    // No kernel means no initramfs leg (e.g. the wasm backend).
    if start_config.kernel_path.is_none() {
        return Ok(());
    }
    let version = env!("CARGO_PKG_VERSION");
    let cache_root = std::path::PathBuf::from(mvm_core::config::mvm_cache_dir()).join("initramfs");
    let arch = mvm_core::arch::GuestArch::host();
    let env = HostShellEnvironment;
    if evict_stale_universal_initramfs(&cache_root, version, arch) {
        tracing::info!(
            initramfs_version = version,
            "guest sources changed since the cached universal initramfs was built; discarded it"
        );
    }
    match resolve(&env, &cache_root, version, arch) {
        Ok(artifact) => {
            if let Some(workspace_root) =
                crate::commands::runtime_overlay::runtime_overlay_source_checkout_root()
                && let Ok(fingerprint) =
                    mvm_build::guest_agent_build::runtime_overlay_source_checkout_fingerprint(
                        &workspace_root,
                    )
            {
                let _ = mvm_build::initramfs::record_source_fingerprint(
                    &cache_root,
                    version,
                    arch,
                    &fingerprint,
                );
            }
            start_config.initrd_path = Some(artifact.image_path.display().to_string());
            tracing::info!(
                initramfs_version = version,
                path = %artifact.image_path.display(),
                "attached universal initramfs"
            );
        }
        Err(e) => {
            // Fail closed. Nothing else mounts the runtime overlay: the guest
            // `/init` baked into a workload rootfs has no code for it, and the
            // `ActivateEnvironment` that does mount it is only sent on the
            // universal-initramfs path. So a rootfs boot without an initramfs
            // reaches PID 1 with an empty `/mvm/runtime` — no agent, no egress
            // client — and dies as a kernel panic the host only sees as a
            // 30-second agent-readiness timeout naming nothing.
            //
            // Swallowing this at debug level is what turned a missing artifact
            // into that timeout. Refuse here, while the resolver's real error
            // is still in hand.
            if initramfs_is_required(start_config) {
                return Err(anyhow::Error::new(e).context(format!(
                    "the universal initramfs {version} for {arch} could not be resolved, and \
                     this workload cannot boot without it: it is what mounts the guest runtime \
                     overlay at /mvm/runtime, which carries the guest agent and the egress \
                     client. Run `mvmctl doctor` to see the artifact state"
                )));
            }
            tracing::debug!(error = %e, "universal initramfs not attached");
        }
    }
    Ok(())
}

/// Whether this launch cannot boot without the universal initramfs.
///
/// True for every boot that has a guest root to mount and expects its runtime
/// binaries from the overlay. A kernel-less shape (wasm) has no initramfs leg
/// at all, and is the only launch that can come up without one.
fn initramfs_is_required(config: &mvm_core::vm_backend::VmStartConfig) -> bool {
    config.kernel_path.is_some() && !config.rootfs_path.is_empty()
}

// ── SDK sidecar ──────────────────────────────────────────────────────────────

/// Production wrapper: build the sidecar resolver from the mvm cache dir + the
/// running mvmctl version, then resolve for `services`.
///
/// The decision, the resolution, and the attachment shape live in
/// `mvm_runtime::sdk_sidecar` so every driver — not just the CLI — reaches one
/// contract; this supplies the host's cache root and version, and owns the
/// cold-cache acquisition ladder the same way
/// [`attach_runtime_overlay_if_cached_version`] does for the overlay:
///
/// 1. Resolve from cache. A warm cache never touches the network.
/// 2. On a miss, seed from the default cache — a worktree-isolated `MVM_HOME`
///    inherits the host's artifact rather than re-acquiring it. Still offline.
/// 3. Still missing: consult the *same* build-vs-download decision the overlay
///    makes on this host, so a contributor whose overlay is source-built never
///    silently downloads a sidecar.
pub(crate) fn resolve_sdk_sidecar_attachment_for_host(
    services: &[mvm_contract::protocol::broker::ServiceId],
    libc: mvm_contract::guest_libc::GuestLibc,
) -> Result<Option<SdkSidecarAttachment>> {
    let cache_root = std::path::PathBuf::from(mvm_core::config::mvm_cache_dir());
    let version = env!("CARGO_PKG_VERSION");
    let arch = mvm_core::arch::GuestArch::host();
    let resolver =
        mvm_fs::sdk_sidecar::SdkSidecarResolver::new(cache_root.clone(), version.to_string());

    let cache_miss = match mvm_runtime::sdk_sidecar::resolve_sdk_sidecar_attachment(
        services, &resolver, arch, libc,
    ) {
        Ok(resolved) => {
            warn_if_sidecar_predates_the_working_tree(&cache_root, version, arch, libc);
            return Ok(resolved);
        }
        Err(e) => e,
    };

    if mvm_build::sdk_sidecar::resolve_or_seed_from_default_cache(&resolver, arch, libc).is_ok() {
        return mvm_runtime::sdk_sidecar::resolve_sdk_sidecar_attachment(
            services, &resolver, arch, libc,
        );
    }

    match runtime_overlay_acquire_mode() {
        // Building the sidecar needs the builder VM, which must not be spawned
        // implicitly inside a launch. Keep the fail-closed refusal, which
        // names the binding and the explicit source-build command.
        RuntimeOverlayAcquireMode::BuildFromSourceCheckout => Err(cache_miss),
        RuntimeOverlayAcquireMode::DownloadPublishedArtifact => {
            ui::info("SDK sidecar missing from cache; downloading the published artifact now...");
            mvm_build::sdk_sidecar::download_sdk_sidecar(version, arch, libc, &cache_root)
                .with_context(|| sdk_sidecar_download_failure_context(services, version, arch))?;
            mvm_runtime::sdk_sidecar::resolve_sdk_sidecar_attachment(
                services, &resolver, arch, libc,
            )
        }
    }
}

/// Say so when the cached sidecar cannot carry this checkout's cdylib changes.
///
/// The sidecar cache key is version + architecture, so an older downloaded or
/// source-built image can remain structurally valid after `crates/mvm-sdk`
/// changes. A contributor who adds a host-service verb would otherwise learn
/// about the drift only from inside the guest, as `unknown method
/// \`host.kv.get\`` — an error that points at the broker rather than at the
/// stale image.
///
/// A warning, not an implicit rebuild: source construction boots Stage 0 and
/// therefore remains an explicit operator action outside a workload launch.
///
/// Silent for a release binary, which has no checkout and for which the
/// published artifact is exactly right.
/// Said once per process. A launch resolves the sidecar from more than one call
/// site, and the condition is process-global — same cache, same checkout — so
/// repeating it is noise that trains people to skip the line.
fn warn_if_sidecar_predates_the_working_tree(
    cache_root: &std::path::Path,
    version: &str,
    arch: mvm_core::arch::GuestArch,
    libc: mvm_contract::guest_libc::GuestLibc,
) {
    static SAID: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

    let Some(workspace_root) =
        crate::commands::runtime_overlay::runtime_overlay_source_checkout_root()
    else {
        return;
    };
    match mvm_build::sdk_sidecar::cached_sidecar_provenance(
        cache_root,
        version,
        arch,
        libc,
        &workspace_root,
    ) {
        Ok(mvm_build::sdk_sidecar::SidecarProvenance::MatchesSource) => {}
        Ok(_) if SAID.swap(true, std::sync::atomic::Ordering::Relaxed) => {}
        Ok(provenance) => {
            let origin = match provenance {
                mvm_build::sdk_sidecar::SidecarProvenance::Published => "is the published artifact",
                _ => "was built from a different revision of this tree",
            };
            ui::warn(&format!(
                "SDK sidecar {origin}, so `libmvm_host_services.so` does not carry \
                 changes to crates/mvm-sdk in this checkout. Host-service calls from \
                 the guest use the verbs it shipped with; one added here answers \
                 `unknown method`. Refresh it with `mvmctl build sdk-sidecar build`."
            ));
        }
        // Provenance is a diagnostic. Failing to compute it must not fail a
        // launch that would otherwise proceed.
        Err(error) => {
            tracing::debug!(%error, "could not determine SDK sidecar provenance");
        }
    }
}

/// A failed download must read like the cache-miss refusal it replaces: name
/// the bindings that demanded the sidecar and where it was going to be mounted,
/// not just the URL that 404'd.
fn sdk_sidecar_download_failure_context(
    services: &[mvm_contract::protocol::broker::ServiceId],
    version: &str,
    arch: mvm_core::arch::GuestArch,
) -> String {
    let bound: Vec<&str> = mvm_core::plan::sdk_host_services_in(services)
        .iter()
        .map(|s| s.as_str())
        .collect();
    format!(
        "this workload binds SDK host service(s) [{}], which need the SDK sidecar mounted \
         read-only at {}; downloading the published sidecar {version} for {arch} failed",
        bound.join(", "),
        mvm_core::plan::SDK_SIDECAR_GUEST_PATH,
    )
}

#[cfg(test)]
mod sdk_sidecar_host_resolution_tests {
    use super::*;
    use mvm_contract::protocol::broker::ServiceId;
    use mvm_core::arch::GuestArch;
    use mvm_fs::sdk_sidecar::{
        SDK_SIDECAR_IMAGE_FILE, SDK_SIDECAR_VERSION_FILE, SdkSidecarLayout, SdkSidecarResolver,
    };
    use sha2::{Digest, Sha256};

    fn svc(raw: &str) -> ServiceId {
        ServiceId::parse(raw).expect("fixture service id")
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        hex::encode(Sha256::digest(bytes))
    }

    fn sidecar_ext4_bytes() -> Vec<u8> {
        use mvm_fs::ext4::Node;
        let nodes = vec![
            Node::Dir {
                path: "/lib".into(),
                mode: 0o555,
                xattrs: Vec::new(),
            },
            Node::File {
                path: "/lib/libmvm_host_services.so".into(),
                mode: 0o555,
                data: b"\x7fELF-stub".to_vec(),
                xattrs: Vec::new(),
            },
        ];
        mvm_fs::ext4::build_image(nodes).expect("build sidecar ext4 fixture")
    }

    fn seed_sidecar_cache(cache: &std::path::Path, version: &str, arch: GuestArch) {
        let layout = SdkSidecarLayout::under(
            cache,
            version,
            &arch.to_string(),
            mvm_contract::guest_libc::GuestLibc::Musl,
        );
        std::fs::create_dir_all(&layout.artifact_dir).unwrap();
        let image = sidecar_ext4_bytes();
        let version_text = format!("{version}\n");
        std::fs::write(&layout.image, &image).unwrap();
        std::fs::write(&layout.version_file, &version_text).unwrap();
        std::fs::write(
            &layout.checksum_manifest_file,
            format!(
                "{}  {SDK_SIDECAR_IMAGE_FILE}\n{}  {SDK_SIDECAR_VERSION_FILE}\n",
                sha256_hex(&image),
                sha256_hex(version_text.as_bytes()),
            ),
        )
        .unwrap();
    }

    /// The grant + volume pair the attachment produces is exactly what the
    /// shared admission gate admits — proven against the real gate, not a
    /// restatement of its rules.
    #[test]
    fn the_attachment_satisfies_the_shared_admission_gate() {
        let dir = tempfile::tempdir().unwrap();
        let arch = GuestArch::host();
        seed_sidecar_cache(dir.path(), "1.2.3", arch);
        let resolver = SdkSidecarResolver::new(dir.path().to_path_buf(), "1.2.3".into());
        let attached = mvm_runtime::sdk_sidecar::resolve_sdk_sidecar_attachment(
            &[svc("host.audit.v1")],
            &resolver,
            arch,
            mvm_contract::guest_libc::GuestLibc::Musl,
        )
        .unwrap()
        .unwrap();

        let plan = mvm_core::plan::test_support::PlanFixture::new()
            .services(vec![svc("host.audit.v1")])
            .build();
        mvm_hostd::plan_admission::enforce_sdk_sidecar_attachment(
            std::slice::from_ref(&attached.volume),
            &plan,
            mvm_build::guest_libc::SIDECAR_CDYLIB_LIBC,
        )
        .expect("the resolved attachment must satisfy the admission gate");

        // And the same volume is refused for a plan that binds no SDK service.
        let unbound = mvm_core::plan::test_support::PlanFixture::new().build();
        assert!(
            mvm_hostd::plan_admission::enforce_sdk_sidecar_attachment(
                std::slice::from_ref(&attached.volume),
                &unbound,
                mvm_build::guest_libc::SIDECAR_CDYLIB_LIBC,
            )
            .is_err()
        );
    }

    /// The host wrapper reads the mvm cache dir, so an isolated `MVM_HOME` is
    /// what makes this assertion about the wrapper rather than about whatever
    /// the developer happens to have cached.
    #[test]
    fn the_host_wrapper_resolves_nothing_when_no_sdk_service_is_bound() {
        let dir = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(dir.path());
        assert_eq!(
            resolve_sdk_sidecar_attachment_for_host(&[], mvm_contract::guest_libc::GuestLibc::Musl)
                .unwrap(),
            None
        );
        assert_eq!(
            resolve_sdk_sidecar_attachment_for_host(
                &[svc("broker.v1")],
                mvm_contract::guest_libc::GuestLibc::Musl
            )
            .unwrap(),
            None
        );
    }

    #[test]
    fn the_host_wrapper_fails_closed_on_a_cold_cache() {
        let dir = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(dir.path());
        env.set(
            crate::commands::runtime_overlay::RUNTIME_OVERLAY_ACQUIRE_MODE_ENV,
            "build",
        );
        assert!(
            resolve_sdk_sidecar_attachment_for_host(
                &[svc("host.audit.v1")],
                mvm_contract::guest_libc::GuestLibc::Musl
            )
            .is_err(),
            "a bound SDK service with no cached sidecar must refuse the launch"
        );
    }

    /// A base URL no transport can reach. Any test asserting "the network was
    /// not touched" points here: if the acquire path ran, the call fails.
    const UNREACHABLE_BASE_URL: &str = "file:///nonexistent/mvm-sdk-sidecar-release-fixture";

    fn sidecar_archive_bytes(version: &str) -> Vec<u8> {
        let image = sidecar_ext4_bytes();
        let version_text = format!("{version}\n").into_bytes();
        let manifest = format!(
            "{}  {SDK_SIDECAR_IMAGE_FILE}\n{}  {SDK_SIDECAR_VERSION_FILE}\n",
            sha256_hex(&image),
            sha256_hex(&version_text),
        )
        .into_bytes();
        let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        let mut tar = tar::Builder::new(encoder);
        for (name, bytes) in [
            (SDK_SIDECAR_IMAGE_FILE, image),
            (SDK_SIDECAR_VERSION_FILE, version_text),
            (mvm_fs::overlay::CHECKSUM_MANIFEST_FILE, manifest),
        ] {
            let mut header = tar::Header::new_gnu();
            header.set_mode(0o644);
            header.set_size(u64::try_from(bytes.len()).unwrap());
            header.set_cksum();
            tar.append_data(&mut header, name, bytes.as_slice())
                .unwrap();
        }
        tar.into_inner().unwrap().finish().unwrap()
    }

    /// Stage the two assets `release.yml` publishes for this arch, so the
    /// download path runs end to end against local bytes instead of the network.
    fn seed_sidecar_release_fixture(base: &std::path::Path, version: &str, arch: GuestArch) {
        let names = mvm_build::sdk_sidecar::SdkSidecarArtifactNames::for_target(
            &arch.to_string(),
            mvm_contract::guest_libc::GuestLibc::Glibc,
        );
        let release_dir = base.join(format!("v{version}"));
        std::fs::create_dir_all(&release_dir).unwrap();
        let archive = sidecar_archive_bytes(version);
        std::fs::write(release_dir.join(&names.archive), &archive).unwrap();
        std::fs::write(
            release_dir.join(&names.archive_checksum),
            format!("{}  {}\n", sha256_hex(&archive), names.archive),
        )
        .unwrap();
    }

    #[test]
    fn a_download_mode_host_acquires_the_sidecar_on_a_cold_cache() {
        let dir = tempfile::tempdir().unwrap();
        let release_root = tempfile::tempdir().unwrap();
        let version = env!("CARGO_PKG_VERSION");
        let arch = GuestArch::host();
        seed_sidecar_release_fixture(release_root.path(), version, arch);

        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(dir.path());
        env.set(
            crate::commands::runtime_overlay::RUNTIME_OVERLAY_ACQUIRE_MODE_ENV,
            "download",
        );
        env.set(
            "MVM_OVERLAY_BASE_URL",
            format!("file://{}", release_root.path().display()),
        );
        // See the overlay test above: the signature rung is witnessed in
        // `mvm_build::release_signature`, not here.
        env.set(mvm_build::release_signature::SKIP_COSIGN_VERIFY_ENV, "1");

        // The published variant, unlike the seeded-cache tests above: this is the
        // one path that fetches a real release asset, and the release carries only
        // the glibc archive. Asking for the other is refused before any transport.
        let attached = resolve_sdk_sidecar_attachment_for_host(
            &[svc("host.audit.v1")],
            mvm_contract::guest_libc::GuestLibc::Glibc,
        )
        .expect("a published sidecar must satisfy the binding")
        .expect("a bound SDK service must attach the sidecar");

        let layout = SdkSidecarLayout::under(
            &dir.path().join("cache"),
            version,
            &arch.to_string(),
            mvm_contract::guest_libc::GuestLibc::Glibc,
        );
        assert_eq!(attached.volume.host, layout.image.display().to_string());
        assert!(attached.volume.read_only);
        assert_eq!(attached.version, version);
        assert!(
            layout.image.is_file(),
            "the artifact must land in the cache"
        );
        assert!(layout.checksum_manifest_file.is_file());
    }

    /// Building the sidecar needs the builder VM, which a launch must never
    /// spawn implicitly — so a source checkout keeps the fail-closed refusal
    /// and never falls through to the network.
    #[test]
    fn a_source_checkout_host_refuses_instead_of_downloading() {
        let dir = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(dir.path());
        env.set(
            crate::commands::runtime_overlay::RUNTIME_OVERLAY_ACQUIRE_MODE_ENV,
            "build",
        );
        env.set("MVM_OVERLAY_BASE_URL", UNREACHABLE_BASE_URL);

        let err = resolve_sdk_sidecar_attachment_for_host(
            &[svc("host.secrets.v1")],
            mvm_contract::guest_libc::GuestLibc::Musl,
        )
        .expect_err("a source-checkout host must refuse rather than download");
        let msg = format!("{err:#}");

        assert!(msg.contains("host.secrets.v1"), "{msg}");
        assert!(
            msg.contains(mvm_core::plan::SDK_SIDECAR_GUEST_PATH),
            "{msg}"
        );
        assert!(
            msg.contains("mvmctl build sdk-sidecar build"),
            "the refusal must still name the build that satisfies it: {msg}"
        );
    }

    /// The download-mode refusal has to read like the cache-miss one it
    /// replaces: an operator needs the binding that demanded the sidecar, not
    /// just a failed URL.
    #[test]
    fn a_failed_download_still_names_the_binding_that_required_the_sidecar() {
        let dir = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(dir.path());
        env.set(
            crate::commands::runtime_overlay::RUNTIME_OVERLAY_ACQUIRE_MODE_ENV,
            "download",
        );
        env.set("MVM_OVERLAY_BASE_URL", UNREACHABLE_BASE_URL);

        let err = resolve_sdk_sidecar_attachment_for_host(
            &[svc("host.time.v1")],
            mvm_contract::guest_libc::GuestLibc::Musl,
        )
        .expect_err("an unreachable release must refuse the launch");
        let msg = format!("{err:#}");

        assert!(msg.contains("host.time.v1"), "{msg}");
        assert!(
            msg.contains(mvm_core::plan::SDK_SIDECAR_GUEST_PATH),
            "{msg}"
        );
    }

    /// A warm cache is a pure local read. Pointing the transport at an
    /// unreachable base URL is what proves it: if the acquire path ran at all,
    /// this call would fail.
    #[test]
    fn a_warm_cache_never_touches_the_network() {
        let dir = tempfile::tempdir().unwrap();
        let version = env!("CARGO_PKG_VERSION");
        let arch = GuestArch::host();
        seed_sidecar_cache(&dir.path().join("cache"), version, arch);

        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(dir.path());
        env.set(
            crate::commands::runtime_overlay::RUNTIME_OVERLAY_ACQUIRE_MODE_ENV,
            "download",
        );
        env.set("MVM_OVERLAY_BASE_URL", UNREACHABLE_BASE_URL);

        let attached = resolve_sdk_sidecar_attachment_for_host(
            &[svc("host.audit.v1")],
            mvm_contract::guest_libc::GuestLibc::Musl,
        )
        .expect("a warm cache resolves without any transport")
        .expect("a bound SDK service must attach the sidecar");
        assert_eq!(attached.version, version);
    }
}

#[cfg(test)]
mod runtime_overlay_attach_tests {
    use super::*;
    use crate::commands::runtime_overlay::RUNTIME_OVERLAY_ACQUIRE_MODE_ENV;
    use mvm_core::arch::GuestArch;
    use mvm_core::util::test_env::TestEnv;
    use mvm_core::vm_backend::VmStartConfig;
    use mvm_fs::ext4::Node;
    use mvm_fs::overlay::RuntimeOverlayResolver;
    use sha2::{Digest, Sha256};

    static ENV_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// A payload carrying every path the resolver requires, optionally minus
    /// the egress client — the one omission these tests actually exercise.
    ///
    /// Derived from `REQUIRED_OVERLAY_GUEST_PATHS` rather than restated: a
    /// hand-written copy is one an added required path silently invalidates,
    /// and it then fails as an unrelated integrity error rather than as a stale
    /// fixture.
    fn valid_overlay_ext4_bytes(version: &str, include_egress_client: bool) -> Vec<u8> {
        let nodes: Vec<Node> = mvm_fs::overlay::REQUIRED_OVERLAY_GUEST_PATHS
            .iter()
            .filter(|path| include_egress_client || **path != "/egress-client")
            .map(|path| Node::File {
                path: (*path).into(),
                // `VERSION` is data the resolver reads back, not a binary.
                mode: if *path == "/VERSION" { 0o444 } else { 0o555 },
                data: if *path == "/VERSION" {
                    format!("{version}\n").into_bytes()
                } else {
                    path.trim_start_matches('/').as_bytes().to_vec()
                },
                xattrs: Vec::new(),
            })
            .collect();
        mvm_fs::ext4::build_image(nodes).expect("build valid overlay ext4 fixture")
    }

    /// Stage a complete overlay cache entry (the four files the resolver
    /// validates) in the layout `resolve` expects.
    fn seed_cache(cache: &std::path::Path, version: &str, arch: GuestArch) {
        let layout = RuntimeOverlayResolver::new(cache.to_path_buf(), version.to_string())
            .layout(&arch.to_string());
        std::fs::create_dir_all(&layout.artifact_dir).unwrap();
        let overlay_ext4 = valid_overlay_ext4_bytes(version, true);
        let sidecar = b"verity-bytes";
        let roothash = format!("{}\n", "a".repeat(64));
        let version_text = format!("{version}\n");
        std::fs::write(&layout.overlay_ext4, &overlay_ext4).unwrap();
        std::fs::write(&layout.sidecar, sidecar).unwrap();
        std::fs::write(&layout.roothash_file, &roothash).unwrap();
        std::fs::write(&layout.version_file, &version_text).unwrap();
        std::fs::write(
            &layout.checksum_manifest_file,
            format!(
                "{}  overlay.ext4\n{}  overlay.verity\n{}  overlay.roothash\n{}  VERSION\n",
                sha256_hex(&overlay_ext4),
                sha256_hex(sidecar),
                sha256_hex(roothash.as_bytes()),
                sha256_hex(version_text.as_bytes()),
            ),
        )
        .unwrap();
        if let Some(workspace_root) =
            crate::commands::runtime_overlay::runtime_overlay_source_checkout_root()
        {
            let fingerprint =
                mvm_build::guest_agent_build::runtime_overlay_source_checkout_fingerprint(
                    &workspace_root,
                )
                .expect("compute runtime-overlay source fingerprint");
            std::fs::write(
                &layout.local_source_fingerprint_file,
                format!("{fingerprint}\n"),
            )
            .unwrap();
        }
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        let digest = Sha256::digest(bytes);
        hex::encode(digest)
    }

    fn write_fixture(dir: &std::path::Path, name: &str, bytes: &[u8]) {
        std::fs::write(dir.join(name), bytes).unwrap();
    }

    fn runtime_overlay_archive_bytes(
        ext4_bytes: &[u8],
        verity_bytes: &[u8],
        roothash_bytes: &[u8],
        version_bytes: &[u8],
        arch: GuestArch,
    ) -> Vec<u8> {
        let guest_files: Vec<(&str, Vec<u8>)> =
            mvm_build::guest_agent_build::OCI_GUEST_RUNTIME_BINARY_NAMES
                .iter()
                .map(|name| (*name, fake_static_elf(arch, name.as_bytes())))
                .collect();
        let mut checksums = format!(
            "{}  overlay.ext4\n{}  overlay.verity\n{}  overlay.roothash\n{}  VERSION\n",
            sha256_hex(ext4_bytes),
            sha256_hex(verity_bytes),
            sha256_hex(roothash_bytes),
            sha256_hex(version_bytes),
        );
        for (name, bytes) in &guest_files {
            checksums.push_str(&format!("{}  {name}\n", sha256_hex(bytes)));
        }
        let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        let mut tar = tar::Builder::new(encoder);
        append_archive_file(&mut tar, "overlay.ext4", ext4_bytes);
        append_archive_file(&mut tar, "overlay.verity", verity_bytes);
        append_archive_file(&mut tar, "overlay.roothash", roothash_bytes);
        append_archive_file(&mut tar, "VERSION", version_bytes);
        for (name, bytes) in &guest_files {
            append_archive_file(&mut tar, name, bytes);
        }
        append_archive_file(&mut tar, "checksums-sha256.txt", checksums.as_bytes());
        let encoder = tar.into_inner().unwrap();
        encoder.finish().unwrap()
    }

    fn fake_static_elf(arch: GuestArch, tag: &[u8]) -> Vec<u8> {
        let machine: u16 = match arch {
            GuestArch::X86_64 => 0x3E,
            GuestArch::Aarch64 => 0xB7,
        };
        let mut bytes = vec![0u8; 64];
        bytes[..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        bytes[4] = 2;
        bytes[5] = 1;
        bytes[18..20].copy_from_slice(&machine.to_le_bytes());
        bytes[54..56].copy_from_slice(&56u16.to_le_bytes());
        bytes.extend_from_slice(tag);
        bytes
    }

    fn append_archive_file<W: std::io::Write>(tar: &mut tar::Builder<W>, path: &str, bytes: &[u8]) {
        let mut header = tar::Header::new_gnu();
        header.set_mode(0o644);
        header.set_size(u64::try_from(bytes.len()).unwrap());
        header.set_cksum();
        tar.append_data(&mut header, path, bytes).unwrap();
    }

    fn seed_release_fixture(base: &std::path::Path, version: &str, arch: GuestArch) {
        let names = mvm_fs::overlay::RuntimeOverlayArtifactNames::for_arch(&arch.to_string());
        let release_dir = base.join(format!("v{version}"));
        std::fs::create_dir_all(&release_dir).unwrap();

        let ext4_bytes = b"downloaded-ext4";
        let verity_bytes = b"downloaded-verity";
        let roothash_text = b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n";
        let version_text = format!("{version}\n");
        let archive_bytes = runtime_overlay_archive_bytes(
            ext4_bytes,
            verity_bytes,
            roothash_text,
            version_text.as_bytes(),
            arch,
        );
        write_fixture(&release_dir, &names.archive, &archive_bytes);
        write_fixture(
            &release_dir,
            &names.archive_checksum,
            format!("{}  {}\n", sha256_hex(&archive_bytes), names.archive).as_bytes(),
        );
    }

    #[test]
    fn firecracker_with_cached_overlay_populates_all_three_fields() {
        let dir = tempfile::tempdir().unwrap();
        // `attach_runtime_overlay` seeds a miss from `$HOME/.mvm/cache`, so
        // without this the assertion holds partly on the developer's own
        // artifacts — and a broken `seed_cache` below would still pass.
        let mut env = TestEnv::new();
        env.isolate_mvm_home(dir.path());
        let ver = env!("CARGO_PKG_VERSION");
        let arch = GuestArch::host();
        seed_cache(dir.path(), ver, arch);
        let resolver = RuntimeOverlayResolver::new(dir.path().to_path_buf(), ver.to_string());
        let mut sc = VmStartConfig {
            ..VmStartConfig::default()
        };
        attach_runtime_overlay(&mut sc, "firecracker", &resolver, arch).unwrap();
        assert!(sc.runtime_overlay_path.is_some(), "ext4 path set");
        assert!(sc.runtime_overlay_verity_path.is_some(), "verity path set");
        assert_eq!(
            sc.runtime_overlay_roothash.as_deref(),
            Some("a".repeat(64).as_str())
        );
        assert_eq!(sc.runtime_overlay_version.as_deref(), Some(ver));
    }

    #[test]
    fn hvf_with_cached_overlay_populates_all_three_fields() {
        let dir = tempfile::tempdir().unwrap();
        // `attach_runtime_overlay` seeds a miss from `$HOME/.mvm/cache`, so
        // without this the assertion holds partly on the developer's own
        // artifacts — and a broken `seed_cache` below would still pass.
        let mut env = TestEnv::new();
        env.isolate_mvm_home(dir.path());
        let ver = env!("CARGO_PKG_VERSION");
        let arch = GuestArch::host();
        seed_cache(dir.path(), ver, arch);
        let resolver = RuntimeOverlayResolver::new(dir.path().to_path_buf(), ver.to_string());
        let mut sc = VmStartConfig {
            ..VmStartConfig::default()
        };
        attach_runtime_overlay(&mut sc, "hvf", &resolver, arch).unwrap();
        assert!(sc.runtime_overlay_path.is_some());
        assert!(sc.runtime_overlay_verity_path.is_some());
        assert!(sc.runtime_overlay_roothash.is_some());
        assert_eq!(sc.runtime_overlay_version.as_deref(), Some(ver));
    }

    #[test]
    fn libkrun_with_cached_overlay_populates_all_three_fields() {
        let dir = tempfile::tempdir().unwrap();
        // `attach_runtime_overlay` seeds a miss from `$HOME/.mvm/cache`, so
        // without this the assertion holds partly on the developer's own
        // artifacts — and a broken `seed_cache` below would still pass.
        let mut env = TestEnv::new();
        env.isolate_mvm_home(dir.path());
        let ver = env!("CARGO_PKG_VERSION");
        let arch = GuestArch::host();
        seed_cache(dir.path(), ver, arch);
        let resolver = RuntimeOverlayResolver::new(dir.path().to_path_buf(), ver.to_string());
        let mut sc = VmStartConfig {
            ..VmStartConfig::default()
        };
        attach_runtime_overlay(&mut sc, "libkrun", &resolver, arch).unwrap();
        assert!(sc.runtime_overlay_path.is_some());
        assert!(sc.runtime_overlay_verity_path.is_some());
        assert!(sc.runtime_overlay_roothash.is_some());
        assert_eq!(sc.runtime_overlay_version.as_deref(), Some(ver));
    }

    #[test]
    fn unsupported_backend_never_attaches() {
        let dir = tempfile::tempdir().unwrap();
        // `attach_runtime_overlay` seeds a miss from `$HOME/.mvm/cache`, so
        // without this the assertion holds partly on the developer's own
        // artifacts — and a broken `seed_cache` below would still pass.
        let mut env = TestEnv::new();
        env.isolate_mvm_home(dir.path());
        let ver = env!("CARGO_PKG_VERSION");
        let arch = GuestArch::host();
        seed_cache(dir.path(), ver, arch);
        let resolver = RuntimeOverlayResolver::new(dir.path().to_path_buf(), ver.to_string());
        let mut sc = VmStartConfig {
            ..VmStartConfig::default()
        };
        attach_runtime_overlay(&mut sc, "mock", &resolver, arch).unwrap();
        assert!(sc.runtime_overlay_path.is_none());
        assert!(sc.runtime_overlay_roothash.is_none());
    }

    #[test]
    fn firecracker_cold_cache_refuses_rather_than_booting_without_the_overlay() {
        let _env_lock = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut env = TestEnv::new();
        let dir = tempfile::tempdir().unwrap(); // empty cache
        let home = tempfile::tempdir().unwrap();
        env.set("HOME", home.path());
        let ver = env!("CARGO_PKG_VERSION");
        let arch = GuestArch::host();
        let resolver = RuntimeOverlayResolver::new(dir.path().to_path_buf(), ver.to_string());
        let mut sc = VmStartConfig {
            ..VmStartConfig::default()
        };
        // The overlay is the single source of the guest binaries, so a cold
        // cache is fatal here rather than something the boot can shrug off.
        // The caller's acquisition ladder catches this Err and builds or
        // downloads; what must never happen is a silent overlay-free boot.
        let err = attach_runtime_overlay(&mut sc, "firecracker", &resolver, arch)
            .expect_err("a cold cache must refuse, not attach nothing");
        assert!(
            err.to_string().contains("runtime overlay required"),
            "unexpected refusal: {err}"
        );
        assert!(sc.runtime_overlay_path.is_none());
    }

    #[test]
    fn firecracker_cold_cache_errors_when_overlay_is_required() {
        let _env_lock = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut env = TestEnv::new();
        let dir = tempfile::tempdir().unwrap(); // empty cache
        let home = tempfile::tempdir().unwrap();
        env.set("HOME", home.path());
        let ver = env!("CARGO_PKG_VERSION");
        let arch = GuestArch::host();
        let resolver = RuntimeOverlayResolver::new(dir.path().to_path_buf(), ver.to_string());
        let mut sc = VmStartConfig {
            ..VmStartConfig::default()
        };
        let err = attach_runtime_overlay(&mut sc, "firecracker", &resolver, arch).unwrap_err();
        assert!(err.to_string().contains("runtime overlay required"));
    }

    #[test]
    fn hvf_cold_cache_errors_when_overlay_is_required() {
        let _env_lock = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut env = TestEnv::new();
        let dir = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        env.set("HOME", home.path());
        let ver = env!("CARGO_PKG_VERSION");
        let arch = GuestArch::host();
        let resolver = RuntimeOverlayResolver::new(dir.path().to_path_buf(), ver.to_string());
        let mut sc = VmStartConfig {
            ..VmStartConfig::default()
        };
        let err = attach_runtime_overlay(&mut sc, "hvf", &resolver, arch).unwrap_err();
        assert!(err.to_string().contains("runtime overlay required"));
        assert!(err.to_string().contains("hvf"));
    }

    #[test]
    fn libkrun_cold_cache_errors_when_overlay_is_required() {
        let _env_lock = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut env = TestEnv::new();
        let dir = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        env.set("HOME", home.path());
        let ver = env!("CARGO_PKG_VERSION");
        let arch = GuestArch::host();
        let resolver = RuntimeOverlayResolver::new(dir.path().to_path_buf(), ver.to_string());
        let mut sc = VmStartConfig {
            ..VmStartConfig::default()
        };
        let err = attach_runtime_overlay(&mut sc, "libkrun", &resolver, arch).unwrap_err();
        assert!(err.to_string().contains("runtime overlay required"));
        assert!(err.to_string().contains("libkrun"));
    }

    #[test]
    fn qemu_with_cached_overlay_populates_all_three_fields() {
        let dir = tempfile::tempdir().unwrap();
        // `attach_runtime_overlay` seeds a miss from `$HOME/.mvm/cache`, so
        // without this the assertion holds partly on the developer's own
        // artifacts — and a broken `seed_cache` below would still pass.
        let mut env = TestEnv::new();
        env.isolate_mvm_home(dir.path());
        let ver = env!("CARGO_PKG_VERSION");
        let arch = GuestArch::host();
        seed_cache(dir.path(), ver, arch);
        let resolver = RuntimeOverlayResolver::new(dir.path().to_path_buf(), ver.to_string());
        let mut sc = VmStartConfig {
            ..VmStartConfig::default()
        };
        attach_runtime_overlay(&mut sc, "qemu", &resolver, arch).unwrap();
        assert!(sc.runtime_overlay_path.is_some());
        assert!(sc.runtime_overlay_verity_path.is_some());
        assert!(sc.runtime_overlay_roothash.is_some());
    }

    #[test]
    fn qemu_cold_cache_errors_when_overlay_is_required() {
        let _env_lock = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut env = TestEnv::new();
        let dir = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        env.set("HOME", home.path());
        let ver = env!("CARGO_PKG_VERSION");
        let arch = GuestArch::host();
        let resolver = RuntimeOverlayResolver::new(dir.path().to_path_buf(), ver.to_string());
        let mut sc = VmStartConfig {
            ..VmStartConfig::default()
        };
        let err = attach_runtime_overlay(&mut sc, "qemu", &resolver, arch).unwrap_err();
        assert!(err.to_string().contains("runtime overlay required"));
        assert!(err.to_string().contains("qemu"));
    }

    #[test]
    fn required_overlay_cache_miss_downloads_overlay_and_attaches_it() {
        let _env_lock = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut env = TestEnv::new();
        let cache = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        env.set("HOME", home.path());
        env.set("MVM_HOME", cache.path());
        env.set(RUNTIME_OVERLAY_ACQUIRE_MODE_ENV, "download");
        // A valid Sigstore signature cannot be minted offline; this test is
        // about the acquire ladder's cache/install rungs. The signature rung
        // has its own witnesses in `mvm_build::release_signature`.
        env.set(mvm_build::release_signature::SKIP_COSIGN_VERIFY_ENV, "1");

        let release_root = tempfile::tempdir().unwrap();
        let version = env!("CARGO_PKG_VERSION");
        let arch = GuestArch::host();
        seed_release_fixture(release_root.path(), version, arch);
        env.set(
            "MVM_OVERLAY_BASE_URL",
            format!("file://{}", release_root.path().display()),
        );

        let mut sc = VmStartConfig {
            ..VmStartConfig::default()
        };
        attach_runtime_overlay_if_cached_version(&mut sc, "firecracker", None).unwrap();

        let layout = RuntimeOverlayResolver::new(cache.path().join("cache"), version.to_string())
            .layout(&arch.to_string());
        assert_eq!(sc.runtime_overlay_version.as_deref(), Some(version));
        assert_eq!(
            sc.runtime_overlay_path.as_deref(),
            Some(layout.overlay_ext4.to_str().expect("utf-8 overlay path"))
        );
        assert_eq!(
            sc.runtime_overlay_verity_path.as_deref(),
            Some(layout.sidecar.to_str().expect("utf-8 verity path"))
        );
        assert_eq!(
            sc.runtime_overlay_roothash.as_deref(),
            Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
        );
        assert!(layout.overlay_ext4.is_file());
        assert!(layout.sidecar.is_file());
        assert!(layout.roothash_file.is_file());
        assert!(layout.version_file.is_file());
    }

    #[test]
    fn runtime_overlay_acquire_mode_honors_explicit_download_override() {
        let _env_lock = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut env = TestEnv::new();
        env.set(RUNTIME_OVERLAY_ACQUIRE_MODE_ENV, "download");
        assert_eq!(
            runtime_overlay_acquire_mode(),
            RuntimeOverlayAcquireMode::DownloadPublishedArtifact
        );
    }

    #[test]
    fn runtime_overlay_acquire_mode_honors_explicit_build_override() {
        let _env_lock = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut env = TestEnv::new();
        env.set(RUNTIME_OVERLAY_ACQUIRE_MODE_ENV, "build");
        assert_eq!(
            runtime_overlay_acquire_mode(),
            RuntimeOverlayAcquireMode::BuildFromSourceCheckout
        );
    }

    #[cfg(feature = "release-channel")]
    #[test]
    fn release_channel_defaults_to_published_runtime_overlay() {
        let _env_lock = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut env = TestEnv::new();
        env.remove(RUNTIME_OVERLAY_ACQUIRE_MODE_ENV);
        assert_eq!(
            runtime_overlay_acquire_mode(),
            RuntimeOverlayAcquireMode::DownloadPublishedArtifact
        );
    }

    #[test]
    fn attach_runtime_overlay_if_cached_version_uses_requested_cached_version() {
        let _env_lock = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut env = TestEnv::new();
        let dir = tempfile::tempdir().unwrap();
        env.isolate_mvm_home(dir.path());

        let current = env!("CARGO_PKG_VERSION");
        let pinned = if current == "0.17.0" {
            "0.17.1"
        } else {
            "0.17.0"
        };
        let arch = GuestArch::host();
        seed_cache(&dir.path().join("cache"), current, arch);
        seed_cache(&dir.path().join("cache"), pinned, arch);

        let mut sc = VmStartConfig {
            ..VmStartConfig::default()
        };
        attach_runtime_overlay_if_cached_version(&mut sc, "firecracker", Some(pinned)).unwrap();

        let expected_layout =
            RuntimeOverlayResolver::new(dir.path().join("cache"), pinned.to_string())
                .layout(&arch.to_string());
        assert_eq!(sc.runtime_overlay_version.as_deref(), Some(pinned));
        assert_eq!(
            sc.runtime_overlay_path.as_deref(),
            Some(
                expected_layout
                    .overlay_ext4
                    .to_str()
                    .expect("utf-8 overlay path")
            )
        );
        assert_eq!(
            sc.runtime_overlay_verity_path.as_deref(),
            Some(expected_layout.sidecar.to_str().expect("utf-8 verity path"))
        );
    }

    #[test]
    fn attach_runtime_overlay_if_cached_version_refuses_drift_to_other_cached_version() {
        let _env_lock = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut env = TestEnv::new();
        let dir = tempfile::tempdir().unwrap();
        // Asserting an *absence*, so HOME has to move with MVM_HOME: the
        // overlay resolver seeds a cold cache from `$HOME/.mvm/cache`, which
        // would supply the very version this test requires to be missing.
        env.isolate_mvm_home(dir.path());

        let current = env!("CARGO_PKG_VERSION");
        let missing = if current == "0.17.0" {
            "0.17.1"
        } else {
            "0.17.0"
        };
        let arch = GuestArch::host();
        seed_cache(&dir.path().join("cache"), current, arch);

        let mut sc = VmStartConfig {
            ..VmStartConfig::default()
        };
        let err = attach_runtime_overlay_if_cached_version(&mut sc, "firecracker", Some(missing))
            .unwrap_err();

        let msg = err.to_string();
        assert!(msg.contains("required for this boot"), "{msg}");
        assert!(msg.contains(missing), "{msg}");
        assert!(
            sc.runtime_overlay_path.is_none(),
            "missing pinned version must not attach"
        );
        assert!(
            sc.runtime_overlay_version.is_none(),
            "missing pinned version must not silently drift to a different cache entry"
        );
    }

    #[test]
    fn attach_runtime_overlay_if_cached_prefers_current_host_version_for_plain_boot() {
        let _env_lock = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut env = TestEnv::new();
        let dir = tempfile::tempdir().unwrap();
        env.isolate_mvm_home(dir.path());
        env.set(RUNTIME_OVERLAY_ACQUIRE_MODE_ENV, "download");

        let current = env!("CARGO_PKG_VERSION");
        let older = if current == "0.17.0" {
            "0.16.9"
        } else {
            "0.17.0"
        };
        let arch = GuestArch::host();
        seed_cache(&dir.path().join("cache"), current, arch);
        seed_cache(&dir.path().join("cache"), older, arch);

        let mut sc = VmStartConfig {
            ..VmStartConfig::default()
        };
        attach_runtime_overlay_if_cached(&mut sc, "firecracker").unwrap();

        let expected_layout =
            RuntimeOverlayResolver::new(dir.path().join("cache"), current.to_string())
                .layout(&arch.to_string());
        assert_eq!(sc.runtime_overlay_version.as_deref(), Some(current));
        assert_eq!(
            sc.runtime_overlay_path.as_deref(),
            Some(
                expected_layout
                    .overlay_ext4
                    .to_str()
                    .expect("utf-8 overlay path")
            )
        );
    }

    #[test]
    fn attach_runtime_overlay_if_cached_ignores_stale_recorded_version_on_plain_boot() {
        let _env_lock = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut env = TestEnv::new();
        let dir = tempfile::tempdir().unwrap();
        env.isolate_mvm_home(dir.path());
        env.set(RUNTIME_OVERLAY_ACQUIRE_MODE_ENV, "download");

        let current = env!("CARGO_PKG_VERSION");
        let stale = if current == "0.17.0" {
            "0.16.9"
        } else {
            "0.17.0"
        };
        let arch = GuestArch::host();
        seed_cache(&dir.path().join("cache"), current, arch);
        seed_cache(&dir.path().join("cache"), stale, arch);

        let mut sc = VmStartConfig {
            runtime_overlay_version: Some(stale.to_string()),
            ..VmStartConfig::default()
        };
        attach_runtime_overlay_if_cached(&mut sc, "firecracker").unwrap();

        let expected_layout =
            RuntimeOverlayResolver::new(dir.path().join("cache"), current.to_string())
                .layout(&arch.to_string());
        assert_eq!(sc.runtime_overlay_version.as_deref(), Some(current));
        assert_eq!(
            sc.runtime_overlay_path.as_deref(),
            Some(
                expected_layout
                    .overlay_ext4
                    .to_str()
                    .expect("utf-8 overlay path")
            )
        );
    }
}

#[cfg(test)]
mod universal_initramfs_attach_tests {
    use super::*;
    use mvm_core::arch::GuestArch;
    use mvm_core::util::test_env::TestEnv;
    use mvm_core::vm_backend::VmStartConfig;

    /// Install a fixture universal initramfs into `<mvm_home>/cache/initramfs`
    /// exactly the way the real build/install path lays it out.
    fn seed_warm_universal_initramfs(mvm_home: &std::path::Path) {
        let version = env!("CARGO_PKG_VERSION");
        let arch = GuestArch::host();
        let source = mvm_home.join("source");
        std::fs::create_dir_all(&source).unwrap();
        // The installer verifies the image against its hash sidecar, so the
        // fixture has to match what the build emits: a real gzip stream, the
        // SHA-256 of the uncompressed payload, and the compressed length.
        let payload = b"cpio-payload";
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        std::io::Write::write_all(&mut encoder, payload).unwrap();
        let image = encoder.finish().unwrap();
        std::fs::write(source.join("initramfs.cpio.gz"), &image).unwrap();
        std::fs::write(
            source.join("initramfs.hash"),
            format!(
                "{}\n",
                hex::encode(<sha2::Sha256 as sha2::Digest>::digest(payload))
            ),
        )
        .unwrap();
        std::fs::write(source.join("initramfs.size"), format!("{}\n", image.len())).unwrap();
        std::fs::write(source.join("VERSION"), version).unwrap();

        let cache_root = mvm_home.join("cache").join("initramfs");
        mvm_build::initramfs::install_initramfs_into_cache(&source, &cache_root, version, arch)
            .unwrap();
        // A warm cache in a source checkout has to say what built it. Without a
        // fingerprint the artifact is of unknown provenance and is discarded —
        // which is the whole point of the eviction, and would make this fixture
        // describe a cache the attach path is right to refuse.
        if let Some(workspace_root) = runtime_overlay_source_checkout_root()
            && let Ok(fingerprint) =
                mvm_build::guest_agent_build::runtime_overlay_source_checkout_fingerprint(
                    &workspace_root,
                )
        {
            mvm_build::initramfs::record_source_fingerprint(
                &cache_root,
                version,
                arch,
                &fingerprint,
            )
            .unwrap();
        }
    }

    /// The resolver failure a cold cache produces, as the real ladder now
    /// reports it (both acquisition arms having failed).
    fn cold_cache_failure() -> mvm_build::initramfs::InitramfsBuildError {
        mvm_build::initramfs::InitramfsBuildError::CargoBuildFailed {
            reason: "automatic warming is disabled in this test".to_string(),
        }
    }

    #[test]
    fn attach_universal_initramfs_if_cached_cold_cache_is_non_fatal_without_a_rootfs() {
        let mut env = TestEnv::new();
        let dir = tempfile::tempdir().unwrap();
        // HOME moves with MVM_HOME or the cache under test is not cold: the
        // initramfs resolver seeds a miss from `$HOME/.mvm/cache`.
        env.isolate_mvm_home(dir.path());

        // No rootfs and no virtiofs root: an initramfs-only guest boots
        // entirely from RAM, so there is no runtime overlay to strand.
        let mut sc = VmStartConfig {
            kernel_path: Some("/dummy/vmlinux".to_string()),
            ..Default::default()
        };
        let resolver_called = std::cell::Cell::new(false);
        attach_universal_initramfs_with_resolver(&mut sc, |_, _, _, _| {
            resolver_called.set(true);
            Err(cold_cache_failure())
        })
        .unwrap();

        assert!(
            resolver_called.get(),
            "the cold-cache resolver must be called"
        );
        assert!(
            sc.initrd_path.is_none(),
            "a cold-cache resolution failure leaves no initramfs attached"
        );
    }

    #[test]
    fn attach_universal_initramfs_refuses_a_rootfs_boot_that_cannot_resolve_one() {
        // The regression this exists for: the resolver failure used to be
        // swallowed at debug level, so the launch continued with no initramfs.
        // Nothing else mounts the runtime overlay, so PID 1 came up to an empty
        // /mvm/runtime, found neither the agent nor the egress client, exited,
        // and panicked the kernel. The host saw only "guest agent did not
        // become reachable within 30s" — a message naming nothing that was
        // actually wrong.
        let mut env = TestEnv::new();
        let dir = tempfile::tempdir().unwrap();
        env.isolate_mvm_home(dir.path());

        let mut sc = VmStartConfig {
            kernel_path: Some("/dummy/vmlinux".to_string()),
            rootfs_path: "/cache/oci/rootfs.ext4".to_string(),
            ..Default::default()
        };
        let error = attach_universal_initramfs_with_resolver(&mut sc, |_, _, _, _| {
            Err(cold_cache_failure())
        })
        .expect_err("a rootfs boot with no resolvable initramfs must refuse");

        let rendered = format!("{error:#}");
        assert!(
            rendered.contains("universal initramfs"),
            "the refusal must name the missing artifact: {rendered}"
        );
        assert!(
            rendered.contains("/mvm/runtime"),
            "the refusal must say what the artifact would have mounted: {rendered}"
        );
        assert!(
            sc.initrd_path.is_none(),
            "a refused launch attaches nothing"
        );
    }

    #[test]
    fn attach_universal_initramfs_still_refuses_a_prefer_overlay_rootfs_boot() {
        // PreferOverlay is the default policy, and it is the one every
        // `machine run --image` launch actually carries into this function on a
        // non-sealed image. It needs the initramfs for exactly the same reason
        // RequiredOverlay does — only RootfsOnly declares a baked-in agent.
        let mut env = TestEnv::new();
        let dir = tempfile::tempdir().unwrap();
        env.isolate_mvm_home(dir.path());

        let mut sc = VmStartConfig {
            kernel_path: Some("/dummy/vmlinux".to_string()),
            rootfs_path: "/cache/oci/rootfs.ext4".to_string(),
            ..Default::default()
        };
        attach_universal_initramfs_with_resolver(&mut sc, |_, _, _, _| Err(cold_cache_failure()))
            .expect_err("PreferOverlay with a rootfs must refuse too");
    }

    #[test]
    fn attach_universal_initramfs_lets_a_kernel_less_launch_through() {
        // A wasm launch has no kernel and therefore no initramfs leg at all.
        // It is the only shape left that can come up without one — every
        // guest that boots a kernel sources its binaries from the overlay,
        // and the initramfs is what mounts it.
        let mut env = TestEnv::new();
        let dir = tempfile::tempdir().unwrap();
        env.isolate_mvm_home(dir.path());

        let mut sc = VmStartConfig {
            kernel_path: None,
            ..Default::default()
        };
        attach_universal_initramfs_with_resolver(&mut sc, |_, _, _, _| Err(cold_cache_failure()))
            .expect("a kernel-less launch needs no initramfs");
        assert!(sc.initrd_path.is_none());
    }

    #[test]
    fn attach_universal_initramfs_if_cached_attaches_from_cache() {
        let mut env = TestEnv::new();
        let dir = tempfile::tempdir().unwrap();
        env.isolate_mvm_home(dir.path());
        seed_warm_universal_initramfs(dir.path());

        let mut sc = VmStartConfig {
            kernel_path: Some("/dummy/vmlinux".to_string()),
            ..Default::default()
        };
        attach_universal_initramfs_if_cached(&mut sc).unwrap();

        assert!(
            sc.initrd_path.is_some(),
            "initramfs path should be attached from a warm cache"
        );
        assert!(
            sc.initrd_path
                .as_deref()
                .unwrap()
                .contains("initramfs.cpio.gz"),
            "attached path should point at the cpio.gz image"
        );
    }

    #[test]
    fn universal_initramfs_available_true_on_warm_cache() {
        let mut env = TestEnv::new();
        let dir = tempfile::tempdir().unwrap();
        env.isolate_mvm_home(dir.path());
        seed_warm_universal_initramfs(dir.path());

        assert!(universal_initramfs_available());
    }

    #[test]
    fn universal_initramfs_available_false_on_cold_cache() {
        let mut env = TestEnv::new();
        let dir = tempfile::tempdir().unwrap();
        // HOME moves with MVM_HOME or the cache under test is not cold: the
        // initramfs resolver seeds a miss from `$HOME/.mvm/cache`.
        env.isolate_mvm_home(dir.path());

        assert!(!universal_initramfs_available());
    }

    #[test]
    fn universal_initramfs_available_false_when_source_fingerprint_is_stale() {
        let Some(_workspace_root) = runtime_overlay_source_checkout_root() else {
            // Fingerprint eviction only applies to a source checkout.
            return;
        };
        let mut env = TestEnv::new();
        let dir = tempfile::tempdir().unwrap();
        env.isolate_mvm_home(dir.path());
        seed_warm_universal_initramfs(dir.path());

        let version = env!("CARGO_PKG_VERSION");
        let arch = GuestArch::host();
        let cache_root = dir.path().join("cache").join("initramfs");
        mvm_build::initramfs::record_source_fingerprint(
            &cache_root,
            version,
            arch,
            "stale-fingerprint",
        )
        .unwrap();

        assert!(!universal_initramfs_available());
        // The probe evicts the stale artifact rather than merely ignoring it,
        // so the attach path never re-finds the same stale bytes.
        assert!(!cache_root.join(version).join(arch.to_string()).exists());
    }
}
