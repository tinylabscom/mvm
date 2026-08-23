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
    fn auto_libkrun_never_silently_falls_back_to_qemu() {
        assert_eq!(
            builder_backend_attempt_order(BuilderBackendChoice::Libkrun, false),
            vec![BuilderBackendChoice::Libkrun]
        );
    }

    #[test]
    fn auto_hvf_keeps_only_the_shared_libkrun_handoff() {
        let order = builder_backend_attempt_order(BuilderBackendChoice::Hvf, false);
        assert!(
            order == vec![BuilderBackendChoice::Hvf, BuilderBackendChoice::Libkrun]
                || order == vec![BuilderBackendChoice::Hvf],
            "expected hvf auto path to stay on the shared hvf/libkrun policy, got {order:?}"
        );
        assert!(
            !order.contains(&BuilderBackendChoice::Qemu),
            "qemu must stay explicit-only, got {order:?}"
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
    use super::default_microvm::{
        default_workload_kernel_source, default_workload_kernel_source_for,
    };
    use super::{KernelSource, default_microvm_assets, missing_workload_kernel_message};

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

    /// One rule for every workload boot: no default-microvm kernel stands in,
    /// dev or prod. The previous split ("prod never reuses the dev default, dev
    /// may") meant a workload's kernel — and therefore whether it could enter a
    /// user namespace — depended on which images happened to be cached locally.
    #[test]
    fn no_default_microvm_kernel_is_ever_reused_as_the_workload_kernel() {
        for variant in ["dev", "prod"] {
            let tmp = tempfile::tempdir().unwrap();
            let kernel = tmp
                .path()
                .join(format!("default-microvm/{variant}/vmlinux"));
            std::fs::create_dir_all(kernel.parent().unwrap()).unwrap();
            std::fs::write(&kernel, b"default-kernel").unwrap();

            let resolved =
                mvm_build::kernel_fetch::resolve_kernel(tmp.path(), "x86_64", "workload", true);
            assert!(
                matches!(
                    resolved,
                    mvm_build::kernel_fetch::KernelResolution::NeedsBuild(_)
                ),
                "the {variant} default-microvm kernel must not stand in for the workload kernel"
            );
        }
    }

    #[test]
    fn source_checkout_defaults_to_local_build_and_installed_binary_to_download() {
        assert_eq!(default_workload_kernel_source(true), KernelSource::Compile);
        assert_eq!(
            default_workload_kernel_source(false),
            KernelSource::Download
        );
    }

    #[test]
    fn official_release_defaults_to_download_even_inside_a_checkout() {
        assert_eq!(
            default_workload_kernel_source_for(
                mvm_build::artifact_acquisition::DistributionChannel::Release,
                true,
            ),
            KernelSource::Download
        );
    }

    #[test]
    fn missing_workload_kernel_message_explains_automatic_and_manual_paths() {
        let msg =
            missing_workload_kernel_message("/cache/builder-vm/aarch64/kernels/workload/vmlinux");
        assert!(msg.contains("mvmctl kernel build --which workload"));
        assert!(msg.contains("just kernel-workload"));
        assert!(msg.contains("dm-verity-capable workload kernel"));
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
        std::fs::write(
            vm.join("builder-egress-runtime.json"),
            br#"{"state":"bound","socket_path":"/tmp/vsock-5253.sock"}"#,
        )
        .expect("write builder egress runtime sidecar");

        let out = reap_orphaned_vm_helpers_at(&vms_root, BUILDER_SIDECARS, true, false, false)
            .expect("reap");
        assert_eq!(out.killed, 0, "no live PID, so nothing to kill");
        assert_eq!(out.removed_dirs, 1, "dir should be removed");
        assert!(
            out.freed_bytes >= 1024,
            "payload and evidence sidecars should be counted"
        );
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

    /// The HVF builder stages each shell job under the *workload* root, so a
    /// finished build leaves a dir there. Blanket workload treatment kept it
    /// forever; now that the inventory no longer surfaces builder VMs, nothing
    /// else would have shown the accumulation either.
    #[test]
    fn a_finished_builder_job_under_the_workload_root_is_pruned() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vms_root = dir.path().join("vms");
        let vm = vms_root.join(mvm_core::naming::builder_shell_vm_name("4242-9999"));
        std::fs::create_dir_all(&vm).expect("mkdir");
        std::fs::write(vm.join("hvf.pid"), "2147483646\n").expect("write pid");
        std::fs::write(vm.join("payload"), vec![0u8; 2048]).expect("write payload");

        let out = reap_orphaned_vm_helpers_at(&vms_root, WORKLOAD_SIDECARS, true, true, false)
            .expect("reap workload root");
        assert_eq!(out.removed_dirs, 1, "a dead per-job builder dir is garbage");
        assert!(!vm.exists(), "the job dir should be gone");
        assert!(out.freed_bytes >= 2048);
    }

    /// The persistent builder's dir is its warm Nix store. Reaping it would
    /// throw away the cache the builder exists to hold, so it stays managed
    /// even though it is equally "builder-owned".
    #[test]
    fn the_persistent_builder_dir_is_never_pruned() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vms_root = dir.path().join("vms");
        let vm = vms_root.join(mvm_core::naming::persistent_builder_vm_name(
            mvm_core::naming::BuilderVmSlot::Hvf,
            "session",
        ));
        std::fs::create_dir_all(&vm).expect("mkdir");
        std::fs::write(vm.join("hvf.pid"), "2147483646\n").expect("write pid");

        let out = reap_orphaned_vm_helpers_at(&vms_root, WORKLOAD_SIDECARS, true, true, false)
            .expect("reap workload root");
        assert_eq!(out.removed_dirs, 0);
        assert!(vm.exists(), "the warm store must survive a prune");
    }

    /// The prune authority granted above must not spill onto real machines:
    /// a stopped machine's state dir is restartable state, not garbage.
    #[test]
    fn granting_builder_prune_does_not_reach_a_stopped_machine() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vms_root = dir.path().join("vms");
        let vm = vms_root.join("web");
        std::fs::create_dir_all(&vm).expect("mkdir");
        std::fs::write(vm.join("libkrun.pid"), "2147483646\n").expect("write pid");

        let out = reap_orphaned_vm_helpers_at(&vms_root, WORKLOAD_SIDECARS, true, true, false)
            .expect("reap workload root");
        assert_eq!(out.removed_dirs, 0);
        assert!(vm.exists(), "a stopped machine keeps its state dir");
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
        let vm = vms_root.join("mvm-persistent-builder-hvf-dev");
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
        std::fs::write(vm.join("libkrun.pid"), format!("{pid}\n")).expect("write pid");

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
    fn reap_spares_live_hvf_workload_under_launchd() {
        // Regression: WORKLOAD_SIDECARS previously omitted `hvf.pid`, so a
        // live HVF supervisor's marker was never read
        // in the supervisor phase — an argv-scanned helper match on the same
        // dir could then be misclassified as an unprotected orphan and
        // SIGTERM'd. `hvf.pid` must now be recognised the same as the other
        // backends' sidecars.
        let (mut child, pid, snapshot) = alive_child_under_launchd();

        let dir = tempfile::tempdir().expect("tempdir");
        let vms_root = dir.path().join("vms");
        let vm = vms_root.join("mvm-workload-livetest-hvf-running");
        std::fs::create_dir_all(&vm).expect("mkdir");
        std::fs::write(vm.join("hvf.pid"), format!("{pid}\n")).expect("write pid");

        let out = reap_orphaned_vm_helpers_at_with_snapshot(
            &vms_root,
            WORKLOAD_SIDECARS,
            false,
            true,
            false,
            &snapshot,
        )
        .expect("reap");

        assert_eq!(out.killed, 0, "live hvf workload must not be signalled");
        assert!(pid_is_alive(pid), "live hvf workload was wrongly killed");

        let _ = child.kill();
        let _ = child.wait();
    }

    /// A supervisor owned by another uid — Firecracker under the jailer runs as
    /// root — must read as alive. `kill(pid, 0)` returns `EPERM` for it, which
    /// a bare `== 0` check reads as dead, and the reaper would then treat the
    /// guest's dir as unowned. Skipped where the probe cannot be exercised:
    /// as root nothing returns `EPERM`, and a host with no other-uid process
    /// has nothing to point it at.
    #[test]
    fn liveness_reports_a_process_owned_by_another_uid_as_alive() {
        // SAFETY: `getuid` reads the calling process's real uid and cannot fail.
        if unsafe { libc::getuid() } == 0 {
            return;
        }
        let Some(pid) = first_process_owned_by_another_uid() else {
            return;
        };
        assert!(
            pid_is_alive(pid),
            "pid {pid} is running under another uid and must read as alive"
        );
    }

    /// A live PID this process may not signal, or `None` if the host has none.
    fn first_process_owned_by_another_uid() -> Option<i32> {
        // SAFETY: `getuid` reads the calling process's real uid and cannot fail.
        let me = unsafe { libc::getuid() };
        let out = std::process::Command::new("ps")
            .args(["-axo", "pid=,uid="])
            .output()
            .ok()?;
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .find_map(|line| {
                let mut fields = line.split_whitespace();
                let pid: i32 = fields.next()?.parse().ok()?;
                let uid: u32 = fields.next()?.parse().ok()?;
                (pid > 1 && uid != me).then_some(pid)
            })
    }

    #[test]
    fn reap_spares_live_qemu_workload_under_launchd() {
        // A workload dir's marker set has to be the same one every other
        // liveness probe reads. `qemu.pid` was missing from it, so a live QEMU
        // guest whose supervisor had been reparented to launchd read as having
        // no owner, and the argv-scanned helper on the same dir was reaped.
        let mut supervisor = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn stand-in QEMU supervisor");
        let supervisor_pid = supervisor.id() as i32;
        let dir = tempfile::tempdir().expect("tempdir");
        let vms_root = dir.path().join("vms");
        let vm = vms_root.join("mvm-workload-livetest-qemu-running");
        std::fs::create_dir_all(&vm).expect("mkdir");
        let helper_cmd = format!("sleep 30 # {}", vm.file_name().unwrap().to_string_lossy());
        let mut helper = std::process::Command::new("sh")
            .arg("-c")
            .arg(&helper_cmd)
            .spawn()
            .expect("spawn stand-in helper");
        let helper_pid = helper.id() as i32;
        let snapshot = ProcSnapshot::from_parts(
            [(supervisor_pid, 1), (helper_pid, 1)].into_iter().collect(),
            vec![(helper_pid, helper_cmd)],
        );
        std::fs::write(vm.join("qemu.pid"), format!("{supervisor_pid}\n")).expect("write pid");

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
            out.killed, 0,
            "a live QEMU supervisor must protect its helper"
        );
        assert!(
            pid_is_alive(helper_pid),
            "helper of live QEMU was wrongly killed"
        );

        let _ = supervisor.kill();
        let _ = supervisor.wait();
        let _ = helper.kill();
        let _ = helper.wait();
    }

    #[test]
    fn reap_spares_live_firecracker_workload_under_launchd() {
        let mut supervisor = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn stand-in Firecracker supervisor");
        let supervisor_pid = supervisor.id() as i32;
        let dir = tempfile::tempdir().expect("tempdir");
        let vms_root = dir.path().join("vms");
        let vm = vms_root.join("mvm-workload-livetest-fc-running");
        std::fs::create_dir_all(&vm).expect("mkdir");
        let helper_cmd = format!("sleep 30 # {}", vm.file_name().unwrap().to_string_lossy());
        let mut helper = std::process::Command::new("sh")
            .arg("-c")
            .arg(&helper_cmd)
            .spawn()
            .expect("spawn stand-in helper");
        let helper_pid = helper.id() as i32;
        let snapshot = ProcSnapshot::from_parts(
            [(supervisor_pid, 1), (helper_pid, 1)].into_iter().collect(),
            vec![(helper_pid, helper_cmd)],
        );
        std::fs::write(vm.join("fc.pid"), format!("{supervisor_pid}\n")).expect("write pid");

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
            out.killed, 0,
            "a live Firecracker supervisor must protect its helper"
        );
        assert!(
            pid_is_alive(helper_pid),
            "helper of live Firecracker was wrongly killed"
        );

        let _ = supervisor.kill();
        let _ = supervisor.wait();
        let _ = helper.kill();
        let _ = helper.wait();
    }

    #[test]
    fn reap_still_kills_orphaned_ephemeral_builder_under_launchd() {
        let (mut child, pid, snapshot) = alive_child_under_launchd();

        let dir = tempfile::tempdir().expect("tempdir");
        let vms_root = dir.path().join("vms");
        let vm = vms_root.join("mvm-builder-hvf-abc12345");
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

        std::fs::write(vm.join("libkrun.pid"), format!("{sup_pid}\n")).expect("write sup pid");

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

        std::fs::write(vm.join("libkrun.pid"), format!("{dead_sup}\n"))
            .expect("write dead sup pid");

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
        let vm = vms_root.join("mvm-persistent-builder-hvf-dev");
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
        let vm = vms_root.join("mvm-builder-hvf-deadjob1");
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

    #[test]
    fn startup_reaps_builder_egress_supervisor_from_another_worktree() {
        let pid = std::process::id() as i32;
        let command = concat!(
            "/tmp/other-worktree/target/debug/mvmctl ",
            "__builder-egress-supervisor --endpoint ",
            "/tmp/other-worktree/target/debug/mvm-network-endpoint"
        );
        let snapshot = ProcSnapshot::from_parts(
            [(pid, 1)].into_iter().collect(),
            vec![(pid, command.to_string())],
        );

        assert_eq!(
            reap_orphaned_builder_egress_supervisors(true, &snapshot),
            1,
            "a launchd-parented builder egress wrapper is orphaned regardless of worktree"
        );
    }

    #[test]
    fn startup_spares_owned_or_unrelated_mvmctl_processes() {
        let pid = std::process::id() as i32;
        let wrapper = concat!(
            "/tmp/worktree/target/debug/mvmctl ",
            "__builder-egress-supervisor --endpoint /tmp/endpoint"
        );
        let owned = ProcSnapshot::from_parts(
            [(pid, 42)].into_iter().collect(),
            vec![(pid, wrapper.to_string())],
        );
        let unrelated = ProcSnapshot::from_parts(
            [(pid, 1)].into_iter().collect(),
            vec![(
                pid,
                "/tmp/worktree/target/debug/mvmctl machine ls".to_string(),
            )],
        );
        let spoofed_executable = ProcSnapshot::from_parts(
            [(pid, 1)].into_iter().collect(),
            vec![(
                pid,
                "/tmp/worktree/target/debug/not-mvmctl __builder-egress-supervisor".to_string(),
            )],
        );
        let later_argument = ProcSnapshot::from_parts(
            [(pid, 1)].into_iter().collect(),
            vec![(
                pid,
                "/tmp/worktree/target/debug/mvmctl machine run __builder-egress-supervisor"
                    .to_string(),
            )],
        );

        assert_eq!(reap_orphaned_builder_egress_supervisors(true, &owned), 0);
        assert_eq!(
            reap_orphaned_builder_egress_supervisors(true, &unrelated),
            0
        );
        assert_eq!(
            reap_orphaned_builder_egress_supervisors(true, &spoofed_executable),
            0
        );
        assert_eq!(
            reap_orphaned_builder_egress_supervisors(true, &later_argument),
            0
        );
    }
}

#[cfg(all(test, feature = "builder-vm"))]
mod heartbeat_tests {
    use super::{format_compile_elapsed, format_compile_start};
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

    #[test]
    fn compile_start_message_avoids_a_false_fixed_duration_promise() {
        let message = format_compile_start("workload", "aarch64");
        assert!(message.contains("depending on the host"));
        assert!(message.contains("reuse the persistent Nix store"));
        assert!(!message.contains("3-10"));
    }
}
