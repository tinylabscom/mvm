//! The Wasm tier's activation analog: environment delivery for a WASI run.
//!
//! Every other backend now delivers the same environment description after
//! boot — the universal initramfs receives `ActivateEnvironment` over
//! vsock; this tier has no guest agent and no vsock, so the handshake is
//! adapted to WASI's own capability model:
//!
//! - **Preopens instead of mounts.** The runtime overlay's guest binaries
//!   are preopened read-only at `/mvm/runtime` (the same guest path the
//!   dm-verity overlay occupies on microVM backends), and each declared
//!   `DirShare` volume is preopened at its guest mountpoint with its
//!   read-only flag honored. WASI has no block devices: a `Disk` volume
//!   fails closed before any of this, in
//!   [`crate::wasm_backend::WasmBackendError`].
//! - **An activation file instead of a vsock verb.** The run's environment
//!   summary — overlay guest path, volume mountpoints, the network
//!   policy's posture label, and whether a verb-grant sidecar was pinned —
//!   is written to `activation.json` inside a per-run directory preopened
//!   read-only at `/run/mvm`, and the instance gets
//!   `MVM_ACTIVATION_FILE=/run/mvm/activation.json` in its env.
//! - **The WASI capability model is the gate.** A module receives exactly
//!   the preopens, env entries, and host imports the run admits — nothing
//!   else exists for it to open. That is this tier's `NotActivated`
//!   analog: there is no second, broader environment to escalate into.
//!
//! Honesty boundaries, stated plainly: the activation file is host→module
//! environment *description*, not a security envelope — there is no
//! in-guest signature verification because the WASI host is the trust
//! boundary. The policy summary is informational; enforcement stays
//! host-side at the substitution endpoint and the `mvm:egress` import.
//! And this remains the claim-free demo/preview tier: real untrusted
//! workloads run engine-in-guest on the microVM runner backends, which is
//! the full-isolation path.
//!
//! Rootfs: WASI has no mountable root — the module's filesystem view IS
//! its root (the in-place analog of a container's image root), assembled
//! entirely from the preopens above.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use mvm_core::vm_backend::{VmStartConfig, VmVolumeKind};
use serde::{Deserialize, Serialize};

use crate::wasm_backend::WasmBackendError;

/// Guest path the per-run activation directory is preopened at (read-only).
pub const RUN_DIR_GUEST_PATH: &str = "/run/mvm";
/// Guest path of the activation file inside that directory.
pub const ACTIVATION_FILE_GUEST_PATH: &str = "/run/mvm/activation.json";
/// Guest path the runtime-overlay guest binaries are preopened at
/// (read-only) — the same location the dm-verity overlay occupies on
/// microVM backends.
pub const RUNTIME_OVERLAY_GUEST_PATH: &str = "/mvm/runtime";
/// Env var naming the activation file for the module.
pub const ACTIVATION_FILE_ENV: &str = "MVM_ACTIVATION_FILE";

/// The activation file's wire shape: host→module environment description
/// (see the module docs for what it is deliberately NOT — no signatures,
/// no secrets, enforcement stays host-side).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WasmActivation {
    /// Guest path of the preopened runtime overlay, when the launch
    /// declared one. `None` for an overlay-free (rootfs-only) run.
    pub runtime_overlay: Option<String>,
    /// Declared volume mountpoints the module can see as preopens.
    pub volumes: Vec<WasmVolume>,
    /// The launch network policy's posture label — informational only;
    /// egress enforcement lives at the host-side endpoint.
    pub network_policy_summary: String,
    /// Whether a verb-grant sidecar was pinned for this launch. The grant
    /// itself is a signed host artifact; a WASI module has no anchor to
    /// verify it against, so only its presence travels.
    pub grant_present: bool,
}

/// One declared volume in the activation file: its guest mountpoint and
/// whether the preopen is read-only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WasmVolume {
    pub guest_path: String,
    pub read_only: bool,
}

/// One WASI preopen: a host directory exposed to the module at a guest
/// path, read-only or read-write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WasmPreopen {
    pub host_dir: PathBuf,
    pub guest_path: String,
    pub read_only: bool,
}

/// The capability handshake for one WASI run, translated into engine
/// inputs: the preopens and env entries the instance is built with. Pure
/// data so the whole config→capabilities mapping is unit-testable with no
/// wasmtime dependency.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WasmPreopenPlan {
    pub preopens: Vec<WasmPreopen>,
    pub env: Vec<(String, String)>,
}

/// Translate a launch config into the preopen/env plan: the activation run
/// dir first (read-only, always present), then the runtime overlay
/// (read-only, when resolved), then every declared `DirShare` volume in
/// config order with its read-only flag honored. Pure — no I/O, no
/// wasmtime — so the exact tuples are assertable in a test.
pub fn build_wasm_preopen_plan(
    config: &VmStartConfig,
    run_dir: &Path,
    overlay_bins_dir: Option<&Path>,
) -> WasmPreopenPlan {
    let mut preopens = vec![WasmPreopen {
        host_dir: run_dir.to_path_buf(),
        guest_path: RUN_DIR_GUEST_PATH.to_string(),
        read_only: true,
    }];
    if let Some(dir) = overlay_bins_dir {
        preopens.push(WasmPreopen {
            host_dir: dir.to_path_buf(),
            guest_path: RUNTIME_OVERLAY_GUEST_PATH.to_string(),
            read_only: true,
        });
    }
    for volume in config
        .volumes
        .iter()
        .filter(|v| matches!(v.kind, VmVolumeKind::DirShare))
    {
        preopens.push(WasmPreopen {
            host_dir: PathBuf::from(&volume.host),
            guest_path: volume.guest.clone(),
            read_only: volume.read_only,
        });
    }
    WasmPreopenPlan {
        preopens,
        env: vec![(
            ACTIVATION_FILE_ENV.to_string(),
            ACTIVATION_FILE_GUEST_PATH.to_string(),
        )],
    }
}

/// Whether this launch declares the runtime overlay: the full artifact triple
/// is present (the all-three-or-none rule the block layout applies). An
/// overlay-free launch gets no preopen and no error.
pub fn overlay_declared(config: &VmStartConfig) -> bool {
    config.runtime_overlay_path.is_some()
        && config.runtime_overlay_verity_path.is_some()
        && config.runtime_overlay_roothash.is_some()
}

/// Resolve the runtime-overlay guest binaries as a host directory to
/// preopen read-only at `/mvm/runtime`, reusing the shared
/// resolve-or-build helper (never a forked copy). `None` when the launch
/// is overlay-free; a typed `RuntimeOverlayUnavailable` when the launch
/// declares the overlay but it can't resolve — booting without it would
/// silently hand the module a lesser environment than the launch contract
/// promises.
pub fn resolve_wasm_overlay_bins_dir(
    config: &VmStartConfig,
) -> std::result::Result<Option<PathBuf>, WasmBackendError> {
    if !overlay_declared(config) {
        return Ok(None);
    }
    let unavailable = |reason: String| WasmBackendError::RuntimeOverlayUnavailable { reason };
    let Some(workspace) = mvm_build::guest_agent_build::detect_source_workspace() else {
        return Err(unavailable(
            "no source checkout detected to build the guest binaries from".to_string(),
        ));
    };
    let cache_root = PathBuf::from(mvm_core::config::mvm_cache_dir());
    let arch = mvm_core::arch::GuestArch::host();
    let version = config
        .runtime_overlay_version
        .as_deref()
        .unwrap_or(env!("CARGO_PKG_VERSION"));
    let binaries = mvm_build::guest_agent_build::resolve_or_build_runtime_overlay_guest_binaries(
        &cache_root,
        version,
        arch,
        &workspace,
    )
    .map_err(|e| unavailable(e.to_string()))?;
    // Every binary in the set lives in the layout's own cache dir.
    let dir = binaries
        .agent
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| unavailable("resolved agent path has no parent directory".to_string()))?;
    Ok(Some(dir))
}

/// Validate a volume's guest mountpoint for preopening: the guest agent's
/// own mount-path policy (absolute, no reserved shadowing), plus this
/// tier's own reserved paths (`/run/mvm` carries the activation file,
/// `/mvm/runtime` carries the overlay) so a declared volume can never
/// shadow the handshake itself.
pub fn validate_wasm_volume_guest_path(
    guest_path: &str,
) -> std::result::Result<(), WasmBackendError> {
    mvm_agentd::guest_mount::validate_volume_mountpoint(guest_path).map_err(|e| {
        WasmBackendError::VolumePathDenied {
            guest_path: guest_path.to_string(),
            reason: e.to_string(),
        }
    })?;
    let normalized = guest_path.trim_end_matches('/');
    if normalized == RUN_DIR_GUEST_PATH
        || normalized.starts_with(&format!("{RUN_DIR_GUEST_PATH}/"))
        || normalized == RUNTIME_OVERLAY_GUEST_PATH
        || normalized.starts_with(&format!("{RUNTIME_OVERLAY_GUEST_PATH}/"))
    {
        return Err(WasmBackendError::VolumePathDenied {
            guest_path: guest_path.to_string(),
            reason: format!(
                "shadows reserved path {RUN_DIR_GUEST_PATH} or {RUNTIME_OVERLAY_GUEST_PATH}"
            ),
        });
    }
    Ok(())
}

/// Write the run's activation file into a fresh per-run directory and
/// return the preopen/env plan that delivers it. The run dir is created
/// owner-only: it is preopened read-only into the instance, so its
/// contents are the module's environment description and nothing more.
pub fn prepare_wasm_activation(
    config: &VmStartConfig,
    state_dir: &Path,
    overlay_bins_dir: Option<&Path>,
    grant_present: bool,
) -> Result<WasmPreopenPlan> {
    // Validate every volume mountpoint before touching the filesystem: a
    // relative or shadowing path fails closed, never a silently odd
    // preopen.
    for volume in &config.volumes {
        validate_wasm_volume_guest_path(&volume.guest)?;
    }
    let run_dir = state_dir.join("wasm-activation");
    std::fs::create_dir_all(&run_dir)
        .map_err(|e| anyhow!("create wasm activation dir {}: {e}", run_dir.display()))?;
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&run_dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| anyhow!("chmod 0700 {}: {e}", run_dir.display()))?;
    }

    let activation = WasmActivation {
        runtime_overlay: overlay_bins_dir.map(|_| RUNTIME_OVERLAY_GUEST_PATH.to_string()),
        volumes: config
            .volumes
            .iter()
            .filter(|v| matches!(v.kind, VmVolumeKind::DirShare))
            .map(|v| WasmVolume {
                guest_path: v.guest.clone(),
                read_only: v.read_only,
            })
            .collect(),
        network_policy_summary: config.network_policy.posture_label(),
        grant_present,
    };
    let json =
        serde_json::to_vec_pretty(&activation).context("serialize wasm activation config")?;
    std::fs::write(run_dir.join("activation.json"), json)
        .map_err(|e| anyhow!("write activation file in {}: {e}", run_dir.display()))?;

    Ok(build_wasm_preopen_plan(config, &run_dir, overlay_bins_dir))
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::vm_backend::VmVolume;

    fn cfg(name: &str) -> VmStartConfig {
        VmStartConfig {
            name: name.to_string(),
            rootfs_path: "/tmp/mod.wasm".to_string(),
            ..Default::default()
        }
    }

    fn dir_share(host: &str, guest: &str, read_only: bool) -> VmVolume {
        VmVolume {
            materialized_image: None,
            volume_label: None,
            host: host.into(),
            guest: guest.into(),
            size: String::new(),
            read_only,
            kind: VmVolumeKind::DirShare,
            encrypted: false,
        }
    }

    fn disk_volume(host: &str, guest: &str) -> VmVolume {
        VmVolume {
            materialized_image: None,
            volume_label: None,
            host: host.into(),
            guest: guest.into(),
            size: String::new(),
            read_only: false,
            kind: VmVolumeKind::Disk,
            encrypted: false,
        }
    }

    #[test]
    fn overlay_declared_only_for_a_full_triple_or_required_policy() {
        assert!(!overlay_declared(&cfg("x")));
        let mut c = cfg("x");
        c.runtime_overlay_path = Some("/img/runtime.ext4".into());
        assert!(
            !overlay_declared(&c),
            "a partial overlay set declares nothing"
        );
        c.runtime_overlay_verity_path = Some("/img/runtime.verity".into());
        c.runtime_overlay_roothash = Some("ab".repeat(32));
        assert!(overlay_declared(&c), "the full triple declares the overlay");
    }

    #[test]
    fn preopen_plan_maps_run_dir_overlay_and_volumes_in_order_with_ro_honored() {
        let mut c = cfg("x");
        c.volumes = vec![
            dir_share("/host/share", "/data/share", true),
            dir_share("/host/data", "/data/incoming", false),
            // A Disk volume in the config is not a preopen (it is refused
            // upstream by reject_unsupported_start_config); the plan must
            // never silently emit one either.
            disk_volume("/host/disk.img", "/data/disk"),
        ];
        let plan = build_wasm_preopen_plan(
            &c,
            Path::new("/state/x/wasm-activation"),
            Some(Path::new("/cache/runtime-overlay-bins")),
        );
        assert_eq!(
            plan.preopens,
            vec![
                WasmPreopen {
                    host_dir: PathBuf::from("/state/x/wasm-activation"),
                    guest_path: "/run/mvm".into(),
                    read_only: true,
                },
                WasmPreopen {
                    host_dir: PathBuf::from("/cache/runtime-overlay-bins"),
                    guest_path: "/mvm/runtime".into(),
                    read_only: true,
                },
                WasmPreopen {
                    host_dir: PathBuf::from("/host/share"),
                    guest_path: "/data/share".into(),
                    read_only: true,
                },
                WasmPreopen {
                    host_dir: PathBuf::from("/host/data"),
                    guest_path: "/data/incoming".into(),
                    read_only: false,
                },
            ]
        );
        assert_eq!(
            plan.env,
            vec![(
                "MVM_ACTIVATION_FILE".to_string(),
                "/run/mvm/activation.json".to_string()
            )]
        );
    }

    #[test]
    fn preopen_plan_without_overlay_carries_no_runtime_preopen() {
        let plan = build_wasm_preopen_plan(&cfg("x"), Path::new("/state/x/wasm-activation"), None);
        assert_eq!(plan.preopens.len(), 1);
        assert_eq!(plan.preopens[0].guest_path, "/run/mvm");
    }

    #[test]
    fn activation_file_carries_the_honest_environment_summary() {
        let dir = tempfile::tempdir().unwrap();
        let state_dir = dir.path();
        let mut c = cfg("act-vm");
        c.volumes = vec![dir_share("/host/share", "/data/share", true)];
        c.network_policy = mvm_core::network_policy::NetworkPolicy::preset(
            mvm_core::network_policy::NetworkPreset::None,
        );
        let overlay = dir.path().join("runtime-overlay-bins");
        let plan = prepare_wasm_activation(&c, state_dir, Some(&overlay), true).unwrap();

        let written: WasmActivation = serde_json::from_slice(
            &std::fs::read(state_dir.join("wasm-activation/activation.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(
            written,
            WasmActivation {
                runtime_overlay: Some("/mvm/runtime".to_string()),
                volumes: vec![WasmVolume {
                    guest_path: "/data/share".into(),
                    read_only: true,
                }],
                network_policy_summary: "deny-all".to_string(),
                grant_present: true,
            }
        );
        // The plan preopens the run dir that was just written.
        assert_eq!(plan.preopens[0].host_dir, state_dir.join("wasm-activation"));
        assert!(plan.preopens[0].read_only);
    }

    #[test]
    fn activation_file_uses_the_policy_posture_label() {
        let dir = tempfile::tempdir().unwrap();
        let c = cfg("policy-vm");
        prepare_wasm_activation(&c, dir.path(), None, false).unwrap();
        let written: WasmActivation = serde_json::from_slice(
            &std::fs::read(dir.path().join("wasm-activation/activation.json")).unwrap(),
        )
        .unwrap();
        // VmStartConfig::default() policy is the deny-all default.
        assert_eq!(written.network_policy_summary, "deny-all");
        assert_eq!(written.runtime_overlay, None);
        assert!(written.volumes.is_empty());
        assert!(!written.grant_present);
    }

    #[test]
    fn run_dir_is_created_owner_only() {
        let dir = tempfile::tempdir().unwrap();
        prepare_wasm_activation(&cfg("perm-vm"), dir.path(), None, false).unwrap();
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(dir.path().join("wasm-activation"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700);
    }

    #[test]
    fn volume_guest_path_validation_rejects_shadowing_and_relative_paths() {
        assert!(validate_wasm_volume_guest_path("/data/share").is_ok());
        for bad in [
            "mnt/relative",
            "/",
            "/run/mvm",
            "/run/mvm/activation.json",
            "/mvm/runtime",
            "/mvm/runtime/bins",
        ] {
            assert!(
                matches!(
                    validate_wasm_volume_guest_path(bad),
                    Err(WasmBackendError::VolumePathDenied { .. })
                ),
                "{bad} must be refused"
            );
        }
    }
}
