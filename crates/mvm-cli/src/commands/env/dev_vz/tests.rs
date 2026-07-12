use super::*;

#[cfg(all(test, feature = "builder-vm"))]
mod builder_backend_attempt_order_tests {
    use super::builder_backend_attempt_order;
    use mvm_build::builder_backend_select::BuilderBackendChoice;

    #[test]
    fn explicit_qemu_stays_qemu() {
        assert_eq!(
            builder_backend_attempt_order(BuilderBackendChoice::Qemu, true),
            vec![BuilderBackendChoice::Qemu]
        );
    }

    #[test]
    fn explicit_hvf_stays_hvf() {
        assert_eq!(
            builder_backend_attempt_order(BuilderBackendChoice::Hvf, true),
            vec![BuilderBackendChoice::Hvf]
        );
    }

    #[test]
    fn delegates_to_shared_policy_for_live_platform() {
        use mvm_build::builder_backend_select::builder_attempt_order;
        let is_linux = matches!(
            mvm_core::platform::current(),
            mvm_core::platform::Platform::LinuxNative
        );
        assert_eq!(
            builder_backend_attempt_order(BuilderBackendChoice::Libkrun, false),
            builder_attempt_order(
                BuilderBackendChoice::Libkrun,
                false,
                is_linux,
                mvm_build::builder_health::libkrun_marked_unavailable(),
            )
        );
    }
}

#[cfg(test)]
mod default_microvm_tests {
    use super::{
        WorkloadKernelBootstrap, default_microvm_assets, find_cached_workload_kernel,
        resolve_workload_kernel_bootstrap,
    };

    #[test]
    fn default_microvm_assets_pins_the_five_asset_contract() {
        let a = default_microvm_assets("/cache/dm", "aarch64");
        let names: Vec<&str> = a.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(
            names,
            vec![
                "default-microvm-vmlinux-aarch64",
                "default-microvm-rootfs-aarch64.ext4",
                "default-microvm-rootfs-aarch64.verity",
                "default-microvm-rootfs-aarch64.roothash",
                "default-microvm-meta-aarch64.json",
            ],
            "release asset names must match the default-microvm release job",
        );
        let dests: Vec<&str> = a.iter().map(|(_, d)| d.as_str()).collect();
        assert_eq!(
            dests,
            vec![
                "/cache/dm/vmlinux",
                "/cache/dm/rootfs.ext4",
                "/cache/dm/rootfs.verity",
                "/cache/dm/rootfs.roothash",
                "/cache/dm/mvm-meta.json",
            ],
            "local dests must be the rootfs siblings the backend + admit gate expect",
        );
    }

    #[test]
    fn prod_workload_kernel_cache_never_reuses_dev_default_kernel() {
        let tmp = tempfile::tempdir().unwrap();
        let cache_dir = tmp.path().to_string_lossy().to_string();
        let dev_kernel = tmp.path().join("default-microvm/dev/vmlinux");
        std::fs::create_dir_all(dev_kernel.parent().unwrap()).unwrap();
        std::fs::write(&dev_kernel, b"dev-kernel").unwrap();

        assert_eq!(
            find_cached_workload_kernel(&cache_dir, "x86_64", true),
            None,
            "prod/workload boots must not silently reuse a dev-tier default kernel"
        );
    }

    #[test]
    fn dev_workload_kernel_cache_may_reuse_dev_default_kernel() {
        let tmp = tempfile::tempdir().unwrap();
        let cache_dir = tmp.path().to_string_lossy().to_string();
        let dev_kernel = tmp.path().join("default-microvm/dev/vmlinux");
        std::fs::create_dir_all(dev_kernel.parent().unwrap()).unwrap();
        std::fs::write(&dev_kernel, b"dev-kernel").unwrap();

        assert_eq!(
            find_cached_workload_kernel(&cache_dir, "x86_64", false),
            Some(dev_kernel.to_string_lossy().to_string())
        );
    }

    #[test]
    fn prod_workload_kernel_bootstrap_downloads_when_only_dev_default_kernel_exists() {
        let tmp = tempfile::tempdir().unwrap();
        let cache_dir = tmp.path().to_string_lossy().to_string();
        let dev_kernel = tmp.path().join("default-microvm/dev/vmlinux");
        std::fs::create_dir_all(dev_kernel.parent().unwrap()).unwrap();
        std::fs::write(&dev_kernel, b"dev-kernel").unwrap();

        let resolved = resolve_workload_kernel_bootstrap(&cache_dir, "x86_64", true, false);
        assert_eq!(
            resolved,
            WorkloadKernelBootstrap::Download(format!(
                "{cache_dir}/builder-vm/{}/kernels/workload/vmlinux",
                "x86_64"
            ))
        );
    }

    #[test]
    fn prod_workload_kernel_bootstrap_builds_locally_from_source_checkout() {
        let tmp = tempfile::tempdir().unwrap();
        let cache_dir = tmp.path().to_string_lossy().to_string();

        let resolved = resolve_workload_kernel_bootstrap(&cache_dir, "x86_64", true, true);
        assert_eq!(
            resolved,
            WorkloadKernelBootstrap::BuildLocal(format!(
                "{cache_dir}/builder-vm/{}/kernels/workload/vmlinux",
                "x86_64"
            ))
        );
    }
}

#[cfg(all(test, feature = "builder-vm"))]
mod default_microvm_variant_tests {
    use super::DefaultMicrovmVariant;

    #[test]
    fn prod_variant_targets_release_default_attr_with_verity_outputs() {
        assert_eq!(DefaultMicrovmVariant::Prod.attr(), "default");
        let prod = DefaultMicrovmVariant::Prod.required_outputs();
        for f in [
            "vmlinux",
            "rootfs.ext4",
            "mvm-meta.json",
            "rootfs.verity",
            "rootfs.roothash",
        ] {
            assert!(prod.contains(&f), "prod must emit {f}");
        }
    }

    #[test]
    fn dev_variant_targets_dev_attr_without_verity() {
        assert_eq!(DefaultMicrovmVariant::Dev.attr(), "dev");
        let dev = DefaultMicrovmVariant::Dev.required_outputs();
        assert!(dev.contains(&"mvm-meta.json"));
        assert!(
            !dev.contains(&"rootfs.verity") && !dev.contains(&"rootfs.roothash"),
            "dev is accessible/unsealed — no verity sidecars",
        );
    }
}

#[cfg(test)]
mod dev_status_image_tests {
    use super::*;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    struct EnvGuard {
        _env: mvm_core::util::test_env::TestEnv,
    }

    impl EnvGuard {
        fn set(
            home: &std::path::Path,
            data_dir: &std::path::Path,
            cache_dir: &std::path::Path,
        ) -> Self {
            let mut env = mvm_core::util::test_env::TestEnv::new();
            env.set("HOME", home);
            env.set("MVM_DATA_DIR", data_dir);
            env.set("MVM_CACHE_DIR", cache_dir);
            Self { _env: env }
        }
    }

    fn touch(path: &std::path::Path) {
        std::fs::create_dir_all(path.parent().expect("test path must have parent")).unwrap();
        std::fs::write(path, b"test").unwrap();
    }

    fn write_valid_builder_cache_artifacts(dir: &std::path::Path) {
        const EXT4_MAGIC_OFFSET: usize = 1024 + 56;
        std::fs::create_dir_all(dir).expect("mkdir artifact dir");
        std::fs::write(dir.join("vmlinux"), vec![0x7f; 1024 * 1024 + 1]).expect("write kernel");
        let mut rootfs = vec![0u8; 4 * 1024 * 1024 + 1];
        rootfs[EXT4_MAGIC_OFFSET] = 0x53;
        rootfs[EXT4_MAGIC_OFFSET + 1] = 0xEF;
        std::fs::write(dir.join("rootfs.ext4"), rootfs).expect("write rootfs");
        std::fs::write(
            dir.join("cmdline.txt"),
            b"console=hvc0 root=/dev/vda ro rootfstype=ext4 rootwait panic=-1 loglevel=8 init=/init mvm.chain_init=/sbin/mvm-host-vm-init\n",
        )
        .expect("write cmdline");
        std::fs::write(
            dir.join("manifest.json"),
            br#"{"cache_contract_version":3,"runtime_overlay_ready":true,"vsock_egress_ready":true}"#,
        )
        .expect("write manifest");
    }

    fn write_builder_vm_flake(dir: &std::path::Path) {
        std::fs::create_dir_all(dir).expect("mkdir flake dir");
        std::fs::write(dir.join("flake.nix"), "{ outputs = _: {}; }").expect("write flake");
        std::fs::write(dir.join("flake.lock"), "{\"nodes\":{}}").expect("write lock");
    }

    fn write_builder_vm_workspace_prereqs(workspace_root: &std::path::Path) {
        std::fs::write(workspace_root.join("Cargo.lock"), "# stub Cargo.lock\n")
            .expect("write Cargo.lock");
    }

    #[test]
    fn status_image_reports_current_data_dir_image() {
        let _lock = ENV_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let _env = EnvGuard::set(
            &tmp.path().join("home"),
            &tmp.path().join("data"),
            &tmp.path().join("cache"),
        );
        let kernel = tmp.path().join("data/dev/current/vmlinux");
        let rootfs = tmp.path().join("data/dev/current/rootfs.ext4");
        touch(&kernel);
        touch(&rootfs);

        assert_eq!(
            resolve_dev_status_image(),
            Some(DevStatusImage {
                kernel_path: Some(kernel.to_string_lossy().into_owned()),
                rootfs_path: rootfs.to_string_lossy().into_owned(),
            })
        );
    }

    #[test]
    fn status_image_reports_versioned_prebuilt_when_current_missing() {
        let _lock = ENV_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path().join("data");
        let _env = EnvGuard::set(
            &tmp.path().join("home"),
            &data_dir,
            &tmp.path().join("cache"),
        );
        let dir = data_dir
            .join("dev/prebuilt")
            .join(format!("v{}", env!("CARGO_PKG_VERSION")));
        let rootfs = dir.join("rootfs.ext4");
        touch(&rootfs);

        assert_eq!(
            resolve_dev_status_image(),
            Some(DevStatusImage {
                kernel_path: None,
                rootfs_path: rootfs.to_string_lossy().into_owned(),
            })
        );
    }

    #[test]
    fn status_image_falls_back_to_legacy_cache_dir() {
        let _lock = ENV_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let cache_dir = tmp.path().join("cache");
        let _env = EnvGuard::set(
            &tmp.path().join("home"),
            &tmp.path().join("data"),
            &cache_dir,
        );
        let rootfs = cache_dir.join("dev/rootfs.ext4");
        touch(&rootfs);

        assert_eq!(
            resolve_dev_status_image(),
            Some(DevStatusImage {
                kernel_path: None,
                rootfs_path: rootfs.to_string_lossy().into_owned(),
            })
        );
    }

    #[test]
    fn status_image_is_none_when_no_rootfs_exists() {
        let _lock = ENV_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let _env = EnvGuard::set(
            &tmp.path().join("home"),
            &tmp.path().join("data"),
            &tmp.path().join("cache"),
        );

        assert_eq!(resolve_dev_status_image(), None);
    }

    fn write_valid_dev_image(dir: &std::path::Path) {
        const EXT4_MAGIC_OFFSET: usize = 1024 + 56;
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join("vmlinux"), vec![0x7f; 1024 * 1024 + 1]).unwrap();
        let mut rootfs = vec![0u8; 4 * 1024 * 1024 + 1];
        rootfs[EXT4_MAGIC_OFFSET] = 0x53;
        rootfs[EXT4_MAGIC_OFFSET + 1] = 0xEF;
        std::fs::write(dir.join("rootfs.ext4"), rootfs).unwrap();
    }

    #[test]
    fn fallback_image_finds_dev_current() {
        let _lock = ENV_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path().join("data");
        let _env = EnvGuard::set(
            &tmp.path().join("home"),
            &data_dir,
            &tmp.path().join("cache"),
        );

        let current = data_dir.join("dev/current");
        write_valid_dev_image(&current);

        let (kernel, rootfs, label) =
            find_local_fallback_image().expect("dev/current/ pair must be discovered");
        assert_eq!(kernel, current.join("vmlinux"));
        assert_eq!(rootfs, current.join("rootfs.ext4"));
        assert_eq!(label, "current");
    }

    #[test]
    fn fallback_image_prefers_most_recent_candidate() {
        let _lock = ENV_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path().join("data");
        let _env = EnvGuard::set(
            &tmp.path().join("home"),
            &data_dir,
            &tmp.path().join("cache"),
        );

        let prebuilt = data_dir.join("dev/prebuilt/v0.0.1");
        let current = data_dir.join("dev/current");
        write_valid_dev_image(&prebuilt);
        write_valid_dev_image(&current);
        let later = std::time::SystemTime::now() + std::time::Duration::from_secs(2);
        std::fs::OpenOptions::new()
            .write(true)
            .open(current.join("rootfs.ext4"))
            .unwrap()
            .set_modified(later)
            .unwrap();

        let (_, _, label) = find_local_fallback_image().expect("a candidate must be discovered");
        assert_eq!(label, "current");
    }

    #[test]
    fn fallback_image_is_none_when_no_pair_exists() {
        let _lock = ENV_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let _env = EnvGuard::set(
            &tmp.path().join("home"),
            &tmp.path().join("data"),
            &tmp.path().join("cache"),
        );

        assert!(find_local_fallback_image().is_none());
    }

    #[test]
    fn builder_cache_status_reports_source_cache_hit_without_paths() {
        let tmp = tempfile::tempdir().unwrap();
        let flake = tmp.path().join("nix/images/builder-vm");
        let cache_root = tmp.path().join("cache");
        let cache = cache_root.join("builder-vm/testarch");
        write_builder_vm_flake(&flake);
        write_builder_vm_workspace_prereqs(tmp.path());
        write_valid_builder_cache_artifacts(&cache);
        let fingerprint = builder_vm_source_fingerprint(flake.to_str().unwrap()).unwrap();
        write_builder_vm_source_fingerprint(&cache, &fingerprint).unwrap();
        write_builder_vm_artifact_digest_manifest(&cache).unwrap();
        write_builder_vm_source_cache_provenance(&cache, &fingerprint).unwrap();

        assert_eq!(
            builder_vm_cache_status_summary(
                Ok(flake.to_string_lossy().into_owned()),
                &cache_root,
                "testarch"
            ),
            BuilderVmCacheStatusSummary {
                cache_kind: "source",
                state: BuilderVmCacheState::Ready,
                reason_code: "hit",
            }
        );
    }

    #[test]
    fn builder_cache_status_reports_source_provenance_drift() {
        let tmp = tempfile::tempdir().unwrap();
        let flake = tmp.path().join("nix/images/builder-vm");
        let cache_root = tmp.path().join("cache");
        let cache = cache_root.join("builder-vm/testarch");
        write_builder_vm_flake(&flake);
        write_builder_vm_workspace_prereqs(tmp.path());
        write_valid_builder_cache_artifacts(&cache);
        let fingerprint = builder_vm_source_fingerprint(flake.to_str().unwrap()).unwrap();
        write_builder_vm_source_fingerprint(&cache, &fingerprint).unwrap();
        write_builder_vm_artifact_digest_manifest(&cache).unwrap();

        assert_eq!(
            builder_vm_cache_status_summary(
                Ok(flake.to_string_lossy().into_owned()),
                &cache_root,
                "testarch"
            ),
            BuilderVmCacheStatusSummary {
                cache_kind: "source",
                state: BuilderVmCacheState::Stale,
                reason_code: "missing_provenance",
            }
        );
    }

    #[test]
    fn builder_cache_status_reports_release_cache_without_source_flake() {
        let tmp = tempfile::tempdir().unwrap();
        let cache_root = tmp.path().join("cache");

        assert_eq!(
            builder_vm_cache_status_summary(
                Err(anyhow::anyhow!("missing source flake")),
                &cache_root,
                "testarch",
            ),
            BuilderVmCacheStatusSummary {
                cache_kind: "release",
                state: BuilderVmCacheState::Stale,
                reason_code: "missing_or_invalid_artifacts",
            }
        );

        write_valid_builder_cache_artifacts(&cache_root.join("builder-vm/testarch"));
        assert_eq!(
            builder_vm_cache_status_summary(
                Err(anyhow::anyhow!("missing source flake")),
                &cache_root,
                "testarch",
            ),
            BuilderVmCacheStatusSummary {
                cache_kind: "release",
                state: BuilderVmCacheState::Ready,
                reason_code: "hit",
            }
        );
    }

    #[test]
    fn dev_image_cache_summary_never_includes_paths() {
        let image = DevStatusImage {
            kernel_path: Some("/private/tmp/mvm/vmlinux".to_string()),
            rootfs_path: "/private/tmp/mvm/rootfs.ext4".to_string(),
        };

        assert_eq!(
            dev_image_cache_summary(Some(&image)),
            DevImageCacheSummary {
                state: "cached",
                kernel: "present",
                rootfs: "present",
            }
        );
        assert_eq!(
            dev_image_cache_summary(None),
            DevImageCacheSummary {
                state: "missing",
                kernel: "missing",
                rootfs: "missing",
            }
        );
    }

    #[test]
    fn dev_cache_inspect_json_omits_paths_and_digests() {
        let summary = DevCacheInspectSummary {
            dev_image: DevImageCacheSummary {
                state: "cached",
                kernel: "present",
                rootfs: "present",
            },
            builder_cache: BuilderVmCacheStatusSummary {
                cache_kind: "source",
                state: BuilderVmCacheState::Ready,
                reason_code: "hit",
            },
        };

        let json = dev_cache_inspect_json(&summary).expect("serialize JSON");
        assert!(json.contains("\"schema_version\": 1"));
        assert!(json.contains("\"builder_cache\""));
        assert!(json.contains("\"reason_code\": \"hit\""));
        assert!(!json.contains("/private/tmp"));
        assert!(!json.contains("sha256"));
        assert!(!json.contains("rootfs.ext4"));
        assert!(!json.contains("vmlinux"));
    }

    #[test]
    fn dev_status_json_is_versioned_and_privacy_safe() {
        let _lock = ENV_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let _env = EnvGuard::set(
            tmp.path(),
            &tmp.path().join("data"),
            &tmp.path().join("cache"),
        );

        let report = build_dev_status_json("libkrun", "running", Some("6.1.0-mvm".to_string()));
        assert_eq!(report.schema_version, 1);
        assert_eq!(report.backend, "libkrun");
        assert_eq!(report.vm_name, Some(DEV_VM_NAME));
        assert_eq!(report.state, "running");
        assert_eq!(report.guest_kernel.as_deref(), Some("6.1.0-mvm"));
        assert!(report.dev_image.is_some());
        assert!(report.builder_cache.is_some());
        assert!(report.linux_native.is_none());

        let json = crate::json_out::to_json_string(&report).expect("serialize");
        assert!(json.contains("\"backend\": \"libkrun\""));
        assert!(json.contains("\"state\": \"running\""));
        assert!(json.contains("\"guest_kernel\": \"6.1.0-mvm\""));
        assert!(!json.contains("/Users"));
        assert!(!json.contains("/private/tmp"));
        assert!(!json.contains("rootfs.ext4"));
        assert!(!json.contains("vmlinux"));
    }

    #[test]
    fn dev_status_json_stopped_omits_kernel() {
        let report = build_dev_status_json("libkrun", "stopped", None);
        assert_eq!(report.state, "stopped");
        assert!(report.guest_kernel.is_none());
        let json = crate::json_out::to_json_string(&report).expect("serialize");
        assert!(!json.contains("\"guest_kernel\""));
    }

    #[test]
    fn dev_status_json_vmless_omits_vm_and_caches() {
        let report = build_dev_status_json_vmless("linux-native", "ready");
        assert_eq!(report.backend, "linux-native");
        assert_eq!(report.state, "ready");
        assert!(report.vm_name.is_none());
        assert!(report.dev_image.is_none());
        assert!(report.builder_cache.is_none());
        assert!(report.linux_native.is_none());
        let json = crate::json_out::to_json_string(&report).expect("serialize");
        assert!(json.contains("\"backend\": \"linux-native\""));
        assert!(!json.contains("\"vm_name\""));
        assert!(!json.contains("\"dev_image\""));
        assert!(!json.contains("\"builder_cache\""));
    }

    #[test]
    fn dev_status_json_linux_native_reports_typed_safe_detail() {
        let report = build_dev_status_json_linux_native(true, false, true);
        assert_eq!(report.backend, "linux-native");
        assert_eq!(report.state, "not-ready");
        assert!(report.vm_name.is_none());
        assert!(report.dev_image.is_none());
        assert!(report.builder_cache.is_none());
        let detail = report.linux_native.as_ref().expect("linux detail");
        assert_eq!(detail.kvm.state, "present");
        assert_eq!(detail.firecracker.state, "missing");
        assert_eq!(detail.base_assets.state, "present");

        let json = crate::json_out::to_json_string(&report).expect("serialize");
        assert!(json.contains("\"linux_native\""));
        assert!(json.contains("\"firecracker\""));
        assert!(json.contains("\"base_assets\""));
        assert!(!json.contains("/dev/kvm"));
        assert!(!json.contains("/Users"));
        assert!(!json.contains("/private/tmp"));
        assert!(!json.contains("rootfs.ext4"));
        assert!(!json.contains("vmlinux"));
        assert!(!json.contains("sha256"));
    }

    #[test]
    fn dev_status_json_linux_native_state_tracks_readiness() {
        assert_eq!(
            build_dev_status_json_linux_native(false, true, true).state,
            "no-kvm"
        );
        assert_eq!(
            build_dev_status_json_linux_native(true, true, false).state,
            "not-ready"
        );
        assert_eq!(
            build_dev_status_json_linux_native(true, true, true).state,
            "ready"
        );
    }

    #[test]
    fn dev_down_json_reports_stopped_and_omits_reset_when_false() {
        let report = build_dev_down_json("libkrun", true, false);
        assert_eq!(report.schema_version, 1);
        assert_eq!(report.backend, "libkrun");
        assert_eq!(report.action, "down");
        assert_eq!(report.outcome, "stopped");
        let json = crate::json_out::to_json_string(&report).expect("serialize");
        assert!(json.contains("\"action\": \"down\""));
        assert!(json.contains("\"outcome\": \"stopped\""));
        assert!(!json.contains("\"reset\""));
    }

    #[test]
    fn dev_down_json_reports_not_running_and_reset() {
        let report = build_dev_down_json("libkrun", false, true);
        assert_eq!(report.outcome, "not-running");
        assert!(report.reset);
        let json = crate::json_out::to_json_string(&report).expect("serialize");
        assert!(json.contains("\"outcome\": \"not-running\""));
        assert!(json.contains("\"reset\": true"));
    }

    #[test]
    fn dev_up_json_reports_outcome_and_omits_reset() {
        let started = build_dev_up_json("libkrun", "started");
        assert_eq!(started.action, "up");
        assert_eq!(started.outcome, "started");
        assert_eq!(started.backend, "libkrun");
        let json = crate::json_out::to_json_string(&started).expect("serialize");
        assert!(json.contains("\"action\": \"up\""));
        assert!(json.contains("\"outcome\": \"started\""));
        assert!(!json.contains("\"reset\""));

        let already = build_dev_up_json("libkrun", "already-running");
        assert_eq!(already.outcome, "already-running");
    }
}

#[cfg(test)]
mod reap_orphans_tests {
    use super::*;

    #[test]
    fn missing_vms_root_is_empty_outcome() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vms_root = dir.path().join("does-not-exist");
        let out = reap_orphaned_vm_helpers_at(&vms_root, BUILDER_SIDECARS, true, false, false)
            .expect("reap");
        assert_eq!(out.killed, 0);
        assert_eq!(out.removed_dirs, 0);
        assert_eq!(out.freed_bytes, 0);
    }

    #[test]
    fn dead_pids_get_their_dirs_swept() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vms_root = dir.path().join("vms");
        let vm = vms_root.join("mvm-stage0-99999-1234567890");
        std::fs::create_dir_all(&vm).expect("mkdir");
        std::fs::write(vm.join("builder.pid"), "2147483646\n").expect("write pid");
        std::fs::write(vm.join("payload"), vec![0u8; 1024]).expect("write payload");

        let out = reap_orphaned_vm_helpers_at(&vms_root, BUILDER_SIDECARS, true, false, false)
            .expect("reap");
        assert_eq!(out.killed, 0, "no live PID, so nothing to kill");
        assert_eq!(out.removed_dirs, 1, "dir should be removed");
        assert!(out.freed_bytes >= 1024, "payload size counted");
        assert!(!vm.exists(), "dir should be gone");
    }

    #[test]
    fn live_owner_preserves_dir_in_dry_run_and_real() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vms_root = dir.path().join("vms");
        let vm = vms_root.join("mvm-stage0-pid-of-self");
        std::fs::create_dir_all(&vm).expect("mkdir");
        let my_pid = std::process::id() as i32;
        std::fs::write(vm.join("builder.pid"), format!("{my_pid}\n")).expect("write pid");

        let out = reap_orphaned_vm_helpers_at(&vms_root, BUILDER_SIDECARS, true, false, false)
            .expect("reap");
        assert_eq!(out.killed, 0, "live owner should not be killed");
        assert_eq!(out.removed_dirs, 0, "dir preserved while owner alive");
        assert!(vm.exists(), "dir should still be on disk");
    }

    #[test]
    fn workload_root_preserves_dir_with_dead_pid() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vms_root = dir.path().join("vms");
        let vm = vms_root.join("mvm-workload-reaptest-7f3a9c-deadpid");
        std::fs::create_dir_all(&vm).expect("mkdir");
        std::fs::write(vm.join("libkrun.pid"), "2147483646\n").expect("write pid");
        std::fs::write(vm.join("config"), vec![0u8; 512]).expect("write state");

        let out = reap_orphaned_vm_helpers_at(&vms_root, WORKLOAD_SIDECARS, false, true, false)
            .expect("reap workload root");
        assert_eq!(out.killed, 0, "dead PID, nothing to kill");
        assert_eq!(out.removed_dirs, 0, "workload dir must never be removed");
        assert!(vm.exists(), "workload VM state dir must survive the sweep");
        assert!(vm.join("config").exists(), "persistent state untouched");
    }

    #[test]
    fn dry_run_does_not_mutate() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vms_root = dir.path().join("vms");
        let vm = vms_root.join("mvm-stage0-dryrun-test");
        std::fs::create_dir_all(&vm).expect("mkdir");
        std::fs::write(vm.join("builder.pid"), "2147483646\n").expect("write pid");
        std::fs::write(vm.join("payload"), vec![0u8; 256]).expect("write payload");

        let out = reap_orphaned_vm_helpers_at(&vms_root, BUILDER_SIDECARS, true, false, true)
            .expect("dry-run reap");
        assert_eq!(out.removed_dirs, 1);
        assert!(vm.exists(), "dry-run must not remove the dir");
        assert!(vm.join("builder.pid").exists(), "pid file untouched");
    }

    fn alive_child_under_launchd() -> (std::process::Child, i32, ProcSnapshot) {
        let child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn stand-in supervisor");
        let pid = child.id() as i32;
        let snapshot = ProcSnapshot::from_parts([(pid, 1)].into_iter().collect(), Vec::new());
        (child, pid, snapshot)
    }

    #[test]
    fn reap_spares_live_persistent_dev_vm_under_launchd() {
        let (mut child, pid, snapshot) = alive_child_under_launchd();

        let dir = tempfile::tempdir().expect("tempdir");
        let vms_root = dir.path().join("vms");
        let vm = vms_root.join("mvm-persistent-builder-vz-dev");
        std::fs::create_dir_all(&vm).expect("mkdir");
        std::fs::write(vm.join("builder.pid"), format!("{pid}\n")).expect("write pid");

        let out = reap_orphaned_vm_helpers_at_with_snapshot(
            &vms_root,
            BUILDER_SIDECARS,
            true,
            false,
            false,
            &snapshot,
        )
        .expect("reap");

        assert_eq!(
            out.killed, 0,
            "live dev VM supervisor must not be signalled"
        );
        assert_eq!(out.removed_dirs, 0, "live dev VM dir must be preserved");
        assert!(
            pid_is_alive(pid),
            "live dev VM supervisor was wrongly killed"
        );

        let _ = child.kill();
        let _ = child.wait();
    }

    #[test]
    fn reap_spares_live_named_workload_under_launchd() {
        let (mut child, pid, snapshot) = alive_child_under_launchd();

        let dir = tempfile::tempdir().expect("tempdir");
        let vms_root = dir.path().join("vms");
        let vm = vms_root.join("mvm-workload-livetest-3b1f-running");
        std::fs::create_dir_all(&vm).expect("mkdir");
        std::fs::write(vm.join("vz.pid"), format!("{pid}\n")).expect("write pid");

        let out = reap_orphaned_vm_helpers_at_with_snapshot(
            &vms_root,
            WORKLOAD_SIDECARS,
            false,
            true,
            false,
            &snapshot,
        )
        .expect("reap");

        assert_eq!(out.killed, 0, "live named workload must not be signalled");
        assert!(pid_is_alive(pid), "live named workload was wrongly killed");

        let _ = child.kill();
        let _ = child.wait();
    }

    #[test]
    fn reap_still_kills_orphaned_ephemeral_builder_under_launchd() {
        let (mut child, pid, snapshot) = alive_child_under_launchd();

        let dir = tempfile::tempdir().expect("tempdir");
        let vms_root = dir.path().join("vms");
        let vm = vms_root.join("mvm-builder-vz-abc12345");
        std::fs::create_dir_all(&vm).expect("mkdir");
        std::fs::write(vm.join("builder.pid"), format!("{pid}\n")).expect("write pid");

        let out = reap_orphaned_vm_helpers_at_with_snapshot(
            &vms_root,
            BUILDER_SIDECARS,
            true,
            false,
            false,
            &snapshot,
        )
        .expect("reap");

        assert_eq!(out.killed, 1, "orphaned ephemeral builder must be reaped");

        let _ = child.kill();
        let _ = child.wait();
    }

    #[test]
    fn reap_spares_live_helper_of_live_workload() {
        let mut sup = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn stand-in supervisor");
        let sup_pid = sup.id() as i32;
        let dir = tempfile::tempdir().expect("tempdir");
        let vms_root = dir.path().join("vms");
        let vm = vms_root.join("mvm-workload-livehelper-9c2a-running");
        std::fs::create_dir_all(&vm).expect("mkdir");
        let helper_cmd = format!("sleep 30 # {}", vm.file_name().unwrap().to_string_lossy());
        let mut helper = std::process::Command::new("sh")
            .arg("-c")
            .arg(&helper_cmd)
            .spawn()
            .expect("spawn stand-in helper");
        let helper_pid = helper.id() as i32;
        let snapshot = ProcSnapshot::from_parts(
            [(sup_pid, 1), (helper_pid, 1)].into_iter().collect(),
            vec![(helper_pid, helper_cmd)],
        );

        std::fs::write(vm.join("vz.pid"), format!("{sup_pid}\n")).expect("write sup pid");

        let out = reap_orphaned_vm_helpers_at_with_snapshot(
            &vms_root,
            WORKLOAD_SIDECARS,
            false,
            true,
            false,
            &snapshot,
        )
        .expect("reap");

        assert_eq!(out.killed, 0, "live VM's supervisor and helper both spared");
        assert!(
            pid_is_alive(helper_pid),
            "helper of a live VM was wrongly killed"
        );

        let _ = sup.kill();
        let _ = sup.wait();
        let _ = helper.kill();
        let _ = helper.wait();
    }

    #[test]
    fn reap_kills_leaked_helper_of_dead_workload() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vms_root = dir.path().join("vms");
        let vm = vms_root.join("mvm-workload-deadhelper-4e7b-stopped");
        std::fs::create_dir_all(&vm).expect("mkdir");
        let helper_cmd = format!("sleep 30 # {}", vm.file_name().unwrap().to_string_lossy());
        let mut helper = std::process::Command::new("sh")
            .arg("-c")
            .arg(&helper_cmd)
            .spawn()
            .expect("spawn stand-in helper");
        let helper_pid = helper.id() as i32;
        let dead_sup = i32::MAX;
        let snapshot = ProcSnapshot::from_parts(
            [(helper_pid, 1)].into_iter().collect(),
            vec![(helper_pid, helper_cmd)],
        );

        std::fs::write(vm.join("vz.pid"), format!("{dead_sup}\n")).expect("write dead sup pid");

        let out = reap_orphaned_vm_helpers_at_with_snapshot(
            &vms_root,
            WORKLOAD_SIDECARS,
            false,
            true,
            false,
            &snapshot,
        )
        .expect("reap");

        assert_eq!(
            out.killed, 1,
            "leaked helper of a stopped VM must be reaped"
        );

        let _ = helper.kill();
        let _ = helper.wait();
    }

    #[test]
    fn prune_spares_stopped_persistent_builder_store() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vms_root = dir.path().join("vms");
        let vm = vms_root.join("mvm-persistent-builder-vz-dev");
        std::fs::create_dir_all(&vm).expect("mkdir");
        std::fs::write(vm.join("builder.pid"), format!("{}\n", i32::MAX)).expect("write pid");
        std::fs::write(vm.join("store"), vec![0u8; 4096]).expect("write store payload");

        let out = reap_orphaned_vm_helpers_at_with_snapshot(
            &vms_root,
            BUILDER_SIDECARS,
            true,
            false,
            false,
            &ProcSnapshot::from_parts(std::collections::HashMap::new(), Vec::new()),
        )
        .expect("reap");

        assert_eq!(
            out.removed_dirs, 0,
            "persistent builder dir must not be pruned"
        );
        assert!(
            vm.exists(),
            "persistent builder store dir must survive prune"
        );
        assert!(vm.join("store").exists(), "warm store payload untouched");
    }

    #[test]
    fn prune_still_reclaims_dead_ephemeral_builder() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vms_root = dir.path().join("vms");
        let vm = vms_root.join("mvm-builder-vz-deadjob1");
        std::fs::create_dir_all(&vm).expect("mkdir");
        std::fs::write(vm.join("builder.pid"), format!("{}\n", i32::MAX)).expect("write pid");

        let out = reap_orphaned_vm_helpers_at_with_snapshot(
            &vms_root,
            BUILDER_SIDECARS,
            true,
            false,
            false,
            &ProcSnapshot::from_parts(std::collections::HashMap::new(), Vec::new()),
        )
        .expect("reap");

        assert_eq!(
            out.removed_dirs, 1,
            "dead ephemeral builder dir must be reclaimed"
        );
        assert!(!vm.exists(), "ephemeral builder dir should be gone");
    }
}

#[cfg(all(test, feature = "builder-vm"))]
mod heartbeat_tests {
    use super::format_compile_elapsed;
    use std::time::Duration;

    #[test]
    fn format_compile_elapsed_renders_minutes_and_seconds() {
        assert_eq!(
            format_compile_elapsed(Duration::from_secs(5)),
            "still compiling… (0m05s elapsed)"
        );
        assert_eq!(
            format_compile_elapsed(Duration::from_secs(130)),
            "still compiling… (2m10s elapsed)"
        );
    }
}
