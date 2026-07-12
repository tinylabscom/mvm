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
