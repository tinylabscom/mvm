use super::stage0_cache::{
    builder_vm_source_cache_status, builder_vm_source_fingerprint,
    validate_builder_vm_stage0_artifacts,
};
use super::*;

#[derive(Debug, Serialize, PartialEq, Eq)]
pub(in crate::commands) struct DevImageCacheJson {
    state: &'static str,
    kernel: &'static str,
    rootfs: &'static str,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub(in crate::commands) struct BuilderVmCacheJson {
    kind: &'static str,
    state: &'static str,
    reason_code: &'static str,
}

#[derive(Debug, Serialize)]
struct DevCacheInspectJson {
    schema_version: u8,
    dev_image: DevImageCacheJson,
    builder_cache: BuilderVmCacheJson,
}

pub(super) fn resolve_dev_cache_inspect_summary() -> DevCacheInspectSummary {
    DevCacheInspectSummary {
        dev_image: dev_image_cache_summary(resolve_dev_status_image().as_ref()),
        builder_cache: resolve_builder_vm_cache_status_summary(),
    }
}

pub(super) fn dev_image_cache_summary(image: Option<&DevStatusImage>) -> DevImageCacheSummary {
    match image {
        Some(image) => DevImageCacheSummary {
            state: "cached",
            kernel: if image.kernel_path.is_some() {
                "present"
            } else {
                "missing"
            },
            rootfs: "present",
        },
        None => DevImageCacheSummary {
            state: "missing",
            kernel: "missing",
            rootfs: "missing",
        },
    }
}

pub(super) fn dev_cache_inspect_json(summary: &DevCacheInspectSummary) -> Result<String> {
    let output = DevCacheInspectJson {
        schema_version: 1,
        dev_image: dev_image_cache_json(&summary.dev_image),
        builder_cache: builder_vm_cache_json(&summary.builder_cache),
    };
    serde_json::to_string_pretty(&output).context("serializing dev cache inspection JSON")
}

fn dev_image_cache_json(summary: &DevImageCacheSummary) -> DevImageCacheJson {
    DevImageCacheJson {
        state: summary.state,
        kernel: summary.kernel,
        rootfs: summary.rootfs,
    }
}

fn builder_vm_cache_json(summary: &BuilderVmCacheStatusSummary) -> BuilderVmCacheJson {
    BuilderVmCacheJson {
        kind: summary.cache_kind,
        state: summary.state.label(),
        reason_code: summary.reason_code,
    }
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub(in crate::commands) struct DevStatusJson {
    pub schema_version: u8,
    pub backend: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vm_name: Option<&'static str>,
    pub state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guest_kernel: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dev_image: Option<DevImageCacheJson>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub builder_cache: Option<BuilderVmCacheJson>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base: Option<DevBaseStatusJson>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub linux_native: Option<LinuxNativeDevStatusJson>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub(in crate::commands) struct LinuxNativeDevStatusJson {
    pub kvm: LinuxNativeComponentJson,
    pub firecracker: LinuxNativeComponentJson,
    pub base_assets: LinuxNativeComponentJson,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub(in crate::commands) struct LinuxNativeComponentJson {
    pub state: &'static str,
}

pub(in crate::commands) fn build_dev_status_json(
    backend: &'static str,
    state: &'static str,
    guest_kernel: Option<String>,
) -> DevStatusJson {
    DevStatusJson {
        schema_version: 1,
        backend,
        vm_name: Some(DEV_VM_NAME),
        state,
        guest_kernel,
        dev_image: Some(dev_image_cache_json(&dev_image_cache_summary(
            resolve_dev_status_image().as_ref(),
        ))),
        builder_cache: Some(builder_vm_cache_json(
            &resolve_builder_vm_cache_status_summary(),
        )),
        base: resolve_dev_base_status_json(),
        linux_native: None,
    }
}

pub(in crate::commands) fn build_dev_status_json_vmless(
    backend: &'static str,
    state: &'static str,
) -> DevStatusJson {
    DevStatusJson {
        schema_version: 1,
        backend,
        vm_name: None,
        state,
        guest_kernel: None,
        dev_image: None,
        builder_cache: None,
        base: None,
        linux_native: None,
    }
}

pub(in crate::commands) fn build_dev_status_json_linux_native(
    has_kvm: bool,
    firecracker_installed: bool,
    base_assets_present: bool,
) -> DevStatusJson {
    let state = if !has_kvm {
        "no-kvm"
    } else if firecracker_installed && base_assets_present {
        "ready"
    } else {
        "not-ready"
    };
    DevStatusJson {
        schema_version: 1,
        backend: "linux-native",
        vm_name: None,
        state,
        guest_kernel: None,
        dev_image: None,
        builder_cache: None,
        base: None,
        linux_native: Some(LinuxNativeDevStatusJson {
            kvm: LinuxNativeComponentJson {
                state: if has_kvm { "present" } else { "missing" },
            },
            firecracker: LinuxNativeComponentJson {
                state: if firecracker_installed {
                    "present"
                } else {
                    "missing"
                },
            },
            base_assets: LinuxNativeComponentJson {
                state: if base_assets_present {
                    "present"
                } else {
                    "missing"
                },
            },
        }),
    }
}

fn resolve_dev_base_status_json() -> Option<DevBaseStatusJson> {
    let state_dir = {
        #[cfg(feature = "builder-vm")]
        {
            mvm_build::vz_builder::persistent_vz_state_dir(DEV_VM_SESSION_ID)
        }
        #[cfg(not(feature = "builder-vm"))]
        {
            std::path::PathBuf::new()
        }
    };
    read_dev_base_provenance(&state_dir).map(|provenance| DevBaseStatusJson {
        id: provenance.id,
        revision: provenance.revision,
        rootfs_fingerprint: provenance.rootfs_fingerprint,
    })
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub(in crate::commands) struct DevLifecycleJson {
    pub schema_version: u8,
    pub backend: &'static str,
    pub action: &'static str,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub reset: bool,
    pub outcome: &'static str,
}

pub(in crate::commands) fn build_dev_up_json(
    backend: &'static str,
    outcome: &'static str,
) -> DevLifecycleJson {
    DevLifecycleJson {
        schema_version: 1,
        backend,
        action: "up",
        outcome,
        reset: false,
    }
}

pub(in crate::commands) fn build_dev_down_json(
    backend: &'static str,
    was_running: bool,
    reset: bool,
) -> DevLifecycleJson {
    DevLifecycleJson {
        schema_version: 1,
        backend,
        action: "down",
        outcome: if was_running {
            "stopped"
        } else {
            "not-running"
        },
        reset,
    }
}

pub(in crate::commands) fn build_dev_park_json(
    backend: &'static str,
    parked: bool,
) -> DevLifecycleJson {
    DevLifecycleJson {
        schema_version: 1,
        backend,
        action: "park",
        outcome: if parked { "parked" } else { "not-running" },
        reset: false,
    }
}

pub(super) fn resolve_builder_vm_cache_status_summary() -> BuilderVmCacheStatusSummary {
    builder_vm_cache_status_summary(
        find_builder_vm_flake(),
        std::path::Path::new(&mvm_core::config::mvm_cache_dir()),
        builder_vm_host_arch(),
    )
}

pub(super) fn builder_vm_cache_status_summary(
    builder_flake: Result<String>,
    cache_root: &std::path::Path,
    arch: &str,
) -> BuilderVmCacheStatusSummary {
    let cache_dir = cache_root.join("builder-vm").join(arch);
    let Ok(flake_dir) = builder_flake else {
        return release_builder_vm_cache_status_summary(&cache_dir);
    };
    let Ok(fingerprint) = builder_vm_source_fingerprint(&flake_dir) else {
        return BuilderVmCacheStatusSummary {
            cache_kind: "source",
            state: BuilderVmCacheState::Stale,
            reason_code: "source_fingerprint_error",
        };
    };
    let status = builder_vm_source_cache_status(&cache_dir, &fingerprint);
    BuilderVmCacheStatusSummary {
        cache_kind: "source",
        state: if status.is_ready() {
            BuilderVmCacheState::Ready
        } else {
            BuilderVmCacheState::Stale
        },
        reason_code: status.reason_code(),
    }
}

fn release_builder_vm_cache_status_summary(
    cache_dir: &std::path::Path,
) -> BuilderVmCacheStatusSummary {
    if validate_builder_vm_stage0_artifacts(cache_dir).is_ok() {
        return BuilderVmCacheStatusSummary {
            cache_kind: "release",
            state: BuilderVmCacheState::Ready,
            reason_code: "hit",
        };
    }
    BuilderVmCacheStatusSummary {
        cache_kind: "release",
        state: BuilderVmCacheState::Stale,
        reason_code: "missing_or_invalid_artifacts",
    }
}
