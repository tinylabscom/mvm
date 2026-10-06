use super::stage0_cache::{validate_builder_vm_stage0_artifacts, write_builder_vm_cache_sidecars};
use super::*;
use std::io::Write;

#[test]
fn workload_config_is_the_capability_witness() {
    let supported = "CONFIG_MD=y\nCONFIG_BLK_DEV_DM=y\nCONFIG_DM_VERITY=y\n";
    assert_eq!(workload_config_carries_dm_verity(supported), Some(true));

    let builder = "# CONFIG_MD is not set\n# CONFIG_BLK_DEV_DM is not set\n";
    assert_eq!(workload_config_carries_dm_verity(builder), Some(false));

    assert_eq!(workload_config_carries_dm_verity(""), None);
    assert_eq!(
        workload_config_carries_dm_verity("not a kernel config"),
        None
    );
}

#[test]
fn assert_workload_kernel_supports_verity_rejects_an_explicit_non_verity_config() {
    let tmp = tempfile::tempdir().unwrap();
    let bad = tmp.path().join("vmlinux");
    std::fs::write(&bad, b"valid raw ARM64 Image without KALLSYMS strings").unwrap();
    std::fs::write(
        tmp.path().join("config"),
        "# CONFIG_BLK_DEV_DM is not set\n",
    )
    .unwrap();
    let err = assert_workload_kernel_supports_verity(bad.to_str().unwrap()).unwrap_err();
    assert!(
        err.to_string().contains("CONFIG_DM_VERITY=y"),
        "unexpected error: {err}"
    );
}

#[test]
fn assert_workload_kernel_supports_verity_accepts_kallsyms_free_image_with_valid_config() {
    let tmp = tempfile::tempdir().unwrap();
    let kernel = tmp.path().join("vmlinux");
    std::fs::write(&kernel, b"raw ARM64 Image with no searchable dm symbols").unwrap();
    std::fs::write(
        tmp.path().join("config"),
        "CONFIG_MD=y\nCONFIG_BLK_DEV_DM=y\nCONFIG_DM_VERITY=y\n",
    )
    .unwrap();

    assert_workload_kernel_supports_verity(kernel.to_str().unwrap()).unwrap();
}

#[test]
fn assert_workload_kernel_supports_verity_accepts_raw_image_without_optional_local_config() {
    let tmp = tempfile::tempdir().unwrap();
    let kernel = tmp.path().join("vmlinux");
    std::fs::write(
        &kernel,
        b"published raw ARM64 Image with no KALLSYMS strings",
    )
    .unwrap();

    assert_workload_kernel_supports_verity(kernel.to_str().unwrap()).unwrap();
}

#[test]
fn incompatible_cached_kernel_is_fully_evicted_for_automatic_recovery() {
    let tmp = tempfile::tempdir().unwrap();
    let kernel = mvm_build::kernel_fetch::cached_kernel_path(tmp.path(), "aarch64", "workload");
    std::fs::create_dir_all(kernel.parent().unwrap()).unwrap();
    std::fs::write(&kernel, b"builder kernel in workload slot").unwrap();
    std::fs::write(
        kernel.with_file_name("config"),
        "# CONFIG_BLK_DEV_DM is not set\n# CONFIG_DM_VERITY is not set\n",
    )
    .unwrap();
    mvm_build::kernel_fetch::record_kernel_digest(&kernel).unwrap();

    assert!(
        assert_workload_kernel_supports_verity(kernel.to_str().unwrap()).is_err(),
        "the explicit non-verity config must be rejected"
    );
    evict_incompatible_workload_kernel(&kernel).unwrap();

    assert!(!kernel.exists());
    assert!(!mvm_build::kernel_fetch::kernel_digest_sidecar(&kernel).exists());
    assert!(!kernel.with_file_name("config").exists());
    assert!(matches!(
        mvm_build::kernel_fetch::resolve_kernel(tmp.path(), "aarch64", "workload", true),
        mvm_build::kernel_fetch::KernelResolution::NeedsBuild(_)
    ));
}

/// Per-arch artifact filenames must match what the release
/// workflow's `builder-vm-image` job uploads. Pure function —
/// asserts the contract between `builder_vm_artifact_names()`
/// (the consumer side that constructs download URLs) and the
/// `cp "$STORE_PATH/..." "staging/builder-vm-..."` lines in
/// `.github/workflows/build.yml` (the producer side).
#[test]
fn builder_vm_artifact_names_match_release_workflow() {
    let n = builder_vm_artifact_names("aarch64");
    assert_eq!(n.kernel, "builder-vm-vmlinux-aarch64");
    assert_eq!(n.kernel_config, "builder-vm-aarch64.kernel.config");
    assert_eq!(n.rootfs, "builder-vm-rootfs-aarch64.ext4");
    assert_eq!(n.cmdline, "builder-vm-aarch64.cmdline.txt");
    assert_eq!(n.manifest, "builder-vm-aarch64.manifest.json");
    assert_eq!(n.checksums, "builder-vm-aarch64-checksums-sha256.txt");

    let n = builder_vm_artifact_names("x86_64");
    assert_eq!(n.kernel, "builder-vm-vmlinux-x86_64");
    assert_eq!(n.kernel_config, "builder-vm-x86_64.kernel.config");
    assert_eq!(n.rootfs, "builder-vm-rootfs-x86_64.ext4");
    assert_eq!(n.cmdline, "builder-vm-x86_64.cmdline.txt");
    assert_eq!(n.manifest, "builder-vm-x86_64.manifest.json");
    assert_eq!(n.checksums, "builder-vm-x86_64-checksums-sha256.txt");
}

#[test]
fn first_nameserver_from_resolv_conf_ignores_comments_and_invalid_lines() {
    let body = "\
# comment
search example.internal
nameserver invalid
nameserver 10.0.0.2
nameserver 10.0.0.3
";
    assert_eq!(
        bootstrap::first_nameserver_from_resolv_conf(body).as_deref(),
        Some("10.0.0.2")
    );
}

#[test]
fn first_nameserver_from_resolv_conf_none_when_absent() {
    let body = "search example.internal\noptions timeout:1\n";
    assert_eq!(bootstrap::first_nameserver_from_resolv_conf(body), None);
}

#[test]
fn stage0_build_conf_contents_emits_workspace_archive_offline_and_overrides() {
    let with_workspace = bootstrap::stage0_build_conf_contents(
        "default",
        "image",
        Some("1.1.1.1"),
        Some("/out/stage0-workspace.tar.gz"),
        true,
        &[bootstrap::Stage0InputOverride {
            input_path: "nixpkgs".to_string(),
            guest_path: "/out/stage0-inputs/nixpkgs.tar.gz".to_string(),
        }],
    );
    assert!(with_workspace.contains("MVM_STAGE0_BUILD_ATTR=default\n"));
    assert!(with_workspace.contains("MVM_STAGE0_OUTPUT_MODE=image\n"));
    assert!(with_workspace.contains("MVM_STAGE0_RESOLVER=1.1.1.1\n"));
    assert!(with_workspace.contains("MVM_STAGE0_WORKSPACE_ARCHIVE=/out/stage0-workspace.tar.gz\n"));
    assert!(with_workspace.contains("MVM_STAGE0_OFFLINE=1\n"));
    assert!(
        with_workspace
            .contains("MVM_STAGE0_OVERRIDE_INPUT_0=nixpkgs=/out/stage0-inputs/nixpkgs.tar.gz\n")
    );

    let minimal =
        bootstrap::stage0_build_conf_contents("stage0-rootfs", "rootfs", None, None, false, &[]);
    assert!(minimal.contains("MVM_STAGE0_BUILD_ATTR=stage0-rootfs\n"));
    assert!(minimal.contains("MVM_STAGE0_OUTPUT_MODE=rootfs\n"));
    assert!(!minimal.contains("MVM_STAGE0_RESOLVER="));
    assert!(!minimal.contains("MVM_STAGE0_WORKSPACE_ARCHIVE="));
    assert!(!minimal.contains("MVM_STAGE0_OFFLINE="));
}

fn write_valid_builder_vm_artifacts(dir: &std::path::Path) {
    const EXT4_MAGIC_OFFSET: usize = 1024 + 56;
    std::fs::create_dir_all(dir).expect("mkdir artifact dir");
    std::fs::write(dir.join("vmlinux"), vec![0x7f; 1024 * 1024 + 1]).expect("write kernel");
    std::fs::write(
        dir.join("kernel.config"),
        b"# CONFIG_NETDEVICES is not set\nCONFIG_VSOCKETS=y\nCONFIG_VIRTIO_VSOCKETS=y\n",
    )
    .expect("write kernel config");
    let mut rootfs = vec![0u8; 4 * 1024 * 1024 + 1];
    rootfs[EXT4_MAGIC_OFFSET] = 0x53;
    rootfs[EXT4_MAGIC_OFFSET + 1] = 0xEF;
    std::fs::write(dir.join("rootfs.ext4"), rootfs).expect("write rootfs");
    std::fs::write(
        dir.join("cmdline.txt"),
        b"console=hvc0 root=/dev/vda ro init=/sbin/mvm-host-vm-init\n",
    )
    .expect("write cmdline");
    std::fs::write(
        dir.join("manifest.json"),
        format!(
            "{{\"cache_contract_version\":{},\"runtime_overlay_ready\":true,\"vsock_egress_ready\":true,\"no_network_devices_ready\":true}}",
            mvm_build::builder_vm::BUILDER_VM_CACHE_CONTRACT_VERSION
        ),
    )
    .expect("write manifest");
}

fn write_builder_vm_source_cache_metadata(dir: &std::path::Path, fingerprint: &str) {
    write_builder_vm_source_fingerprint(dir, fingerprint).expect("write fingerprint");
    write_builder_vm_artifact_digest_manifest(dir).expect("write artifact digest manifest");
    write_builder_vm_source_cache_provenance(dir, fingerprint).expect("write provenance");
}

/// `acquire_stage0_lock` is an advisory `flock(2)`
/// guard at `<cache_parent>/stage0.lock`. The first acquisition
/// succeeds; a second attempt with no wait budget (the test default)
/// refuses with a message naming the subject, the live holder and the
/// lock file; once the first guard drops, the lock becomes available again.
#[test]
fn stage0_lock_refuses_concurrent_acquisition() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let out_dir = tmp.path().join("aarch64");
    let out_dir_str = out_dir.to_str().expect("utf-8 out_dir");

    let first = acquire_stage0_lock_uncontended(out_dir_str);
    // Lock file lives one directory above out_dir, named `stage0.lock`.
    assert!(
        tmp.path().join("stage0.lock").exists(),
        "stage0.lock should be created on first acquisition"
    );

    let err = match acquire_stage0_lock(out_dir_str, "the builder VM image") {
        Err(e) => e,
        Ok(_) => panic!("second acquisition must refuse while first is held"),
    };
    let msg = format!("{err:#}");
    assert!(
        msg.contains("the builder VM image (") && msg.contains("is still held by"),
        "unexpected error: {msg}"
    );
    assert!(
        msg.contains(&format!("pid {}", std::process::id())),
        "error should name the live holder: {msg}"
    );
    assert!(
        !msg.contains("delete the lock file"),
        "a dead holder releases its flock; nobody should be told to delete it: {msg}"
    );
    assert!(
        msg.contains("stage0.lock"),
        "error should name the lock file path: {msg}"
    );

    drop(first);

    // Now reachable again — guards must not leak past their scope.
    let _second = acquire_stage0_lock_uncontended(out_dir_str);
}

/// A second caller queues behind a live holder instead of failing, and picks
/// the lock up as soon as the holder is done with it.
#[test]
fn stage0_lock_waits_for_a_live_holder_then_proceeds() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let out_dir = tmp.path().join("aarch64");
    let out_dir_str = out_dir.to_str().expect("utf-8 out_dir").to_string();

    let first = acquire_stage0_lock_uncontended(&out_dir_str);
    let releaser = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(300));
        drop(first);
    });

    let started = std::time::Instant::now();
    let second = super::stage0_cache::acquire_stage0_lock_within(
        &out_dir_str,
        "the builder VM image",
        mvm_build::builder_vm_runtime::LockWait::of(std::time::Duration::from_secs(30)),
    )
    .expect("the waiter must get the lock once the holder releases it");
    assert!(
        started.elapsed() >= std::time::Duration::from_millis(250),
        "the waiter returned before the holder released"
    );
    releaser.join().expect("releaser thread");
    drop(second);
}

/// Lock setup must not fail when the parent cache directory does
/// not yet exist on disk (fresh contributor host). `acquire_stage0_lock`
/// is responsible for creating it.
#[test]
fn stage0_lock_creates_missing_cache_parent() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let nested = tmp.path().join("nested/builder-vm/aarch64");
    let nested_str = nested.to_str().expect("utf-8 nested");

    let _guard = acquire_stage0_lock_uncontended(nested_str);
    assert!(
        tmp.path().join("nested/builder-vm/stage0.lock").exists(),
        "lock file must be created at the constructed parent path"
    );
}

/// `stage0_bootstrap_in_flight_at` — the guard `cache repair` consults —
/// reports false on a missing/idle builder-vm dir and true only while the
/// shared Stage 0 lock is actually held.
#[test]
fn stage0_in_flight_tracks_the_lock() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let builder_vm = tmp.path().join("builder-vm");

    // Missing dir → nothing in flight (fresh host).
    assert!(!stage0_bootstrap_in_flight_at(&builder_vm));

    std::fs::create_dir_all(&builder_vm).expect("mkdir builder-vm");
    // Present but unlocked → idle.
    assert!(!stage0_bootstrap_in_flight_at(&builder_vm));

    // Hold the same lock a live bootstrap takes (anchor = `<root>/stage0`).
    let out_dir = builder_vm.join("aarch64");
    let guard = acquire_stage0_lock_uncontended(out_dir.to_str().expect("utf-8"));
    assert!(
        stage0_bootstrap_in_flight_at(&builder_vm),
        "a held Stage 0 lock must read as in-flight"
    );

    drop(guard);
    assert!(
        !stage0_bootstrap_in_flight_at(&builder_vm),
        "releasing the lock must clear the in-flight signal"
    );
}

#[test]
fn kernel_stage0_retry_sweeps_only_matching_orphan_staging_dirs() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let kernels = tmp.path().join("aarch64/kernels");
    let final_dir = kernels.join("workload");
    let old_a = kernels.join(".workload.stage0-123-456");
    let old_b = kernels.join(".workload.stage0-789-012");
    let unrelated = kernels.join(".builder.stage0-123-456");
    let live = kernels.join("workload");
    for dir in [&old_a, &old_b, &unrelated, &live] {
        std::fs::create_dir_all(dir).expect("create test directory");
        std::fs::write(dir.join("artifact"), b"bytes").expect("write test artifact");
    }

    let removed = sweep_stage0_staging_siblings(&final_dir).expect("sweep matching orphans");

    assert_eq!(removed, 2);
    assert!(!old_a.exists());
    assert!(!old_b.exists());
    assert!(
        unrelated.exists(),
        "another variant's staging belongs to its producer"
    );
    assert!(
        live.exists(),
        "the live cache directory must never be swept"
    );
}

/// Name predicate must match both the current hidden
/// `.<arch>.stage0-<pid>-<nonce>` form and the legacy
/// `<arch>-staging[-...]` form, and reject everything else that
/// lives alongside under `~/.mvm/cache/builder-vm/` (live cache
/// dirs `aarch64/` / `x86_64/`, the `nix-store-<arch>.img` blob,
/// `jobs/`, `vms/`, `stage0.lock`, sundry dotfiles).
#[test]
fn is_orphan_stage0_staging_dir_name_matches_known_shapes() {
    // Current hidden form (matches `unique_builder_vm_stage0_staging_dir`).
    assert!(is_orphan_stage0_staging_dir_name(
        ".aarch64.stage0-12345-1700000000000000000"
    ));
    assert!(is_orphan_stage0_staging_dir_name(
        ".x86_64.stage0-99999-1700000000000000000"
    ));
    // Legacy plain form.
    assert!(is_orphan_stage0_staging_dir_name("aarch64-staging"));
    assert!(is_orphan_stage0_staging_dir_name("x86_64-staging-foo"));

    // Negatives: everything that legitimately lives next to
    // staging dirs must be left alone.
    assert!(!is_orphan_stage0_staging_dir_name("aarch64"));
    assert!(!is_orphan_stage0_staging_dir_name("x86_64"));
    assert!(!is_orphan_stage0_staging_dir_name("jobs"));
    assert!(!is_orphan_stage0_staging_dir_name("vms"));
    assert!(!is_orphan_stage0_staging_dir_name("stage0.lock"));
    assert!(!is_orphan_stage0_staging_dir_name("nix-store-aarch64.img"));
    assert!(!is_orphan_stage0_staging_dir_name("nix-store-x86_64.img"));
    // Dotfile that isn't a staging dir.
    assert!(!is_orphan_stage0_staging_dir_name(".DS_Store"));
    // Unknown arch suffixes are conservative-deny.
    assert!(!is_orphan_stage0_staging_dir_name(".riscv64.stage0-1-2"));
    assert!(!is_orphan_stage0_staging_dir_name("riscv64-staging"));
}

/// `flock(2)` can spuriously report `EWOULDBLOCK` on a brand-new,
/// uncontended lock path when hundreds of test threads hammer the
/// syscall in parallel (seen as `acquire_stage0_lock` → `Err` /
/// `sweep` → `SkippedLockHeld` on paths no other test can possibly
/// hold). These helpers retry the *uncontended* acquisitions a bounded
/// number of times: the test owns the only would-be holder, so a
/// reported block here is always spurious. Tests that deliberately
/// contend the lock (`sweep_skips_when_stage0_lock_is_held`) do not use
/// these — they want the real "held" outcome.
fn acquire_stage0_lock_uncontended(out_dir: &str) -> super::stage0_cache::Stage0LockGuard {
    for attempt in 0..200u32 {
        match acquire_stage0_lock(out_dir, "the builder VM image") {
            Ok(guard) => return guard,
            Err(e) => {
                assert!(
                    attempt < 199,
                    "stage0 lock stayed spuriously blocked: {e:#}"
                );
                std::thread::sleep(std::time::Duration::from_millis(2));
            }
        }
    }
    unreachable!()
}

fn try_acquire_filelock_uncontended(anchor: &std::path::Path) -> mvm_core::atomic_io::FileLock {
    use mvm_core::atomic_io::FileLock;
    for attempt in 0..200u32 {
        match FileLock::try_acquire(anchor) {
            Ok(Some(guard)) => return guard,
            Ok(None) => {
                assert!(attempt < 199, "flock stayed spuriously blocked");
                std::thread::sleep(std::time::Duration::from_millis(2));
            }
            Err(e) => panic!("flock error: {e:#}"),
        }
    }
    unreachable!()
}

fn sweep_uncontended(root: &std::path::Path, dry_run: bool) -> Stage0SweepOutcome {
    for attempt in 0..200u32 {
        match sweep_orphaned_stage0_staging_dirs_at(root, dry_run).expect("sweep should succeed") {
            Stage0SweepOutcome::SkippedLockHeld => {
                assert!(attempt < 199, "sweep stayed spuriously lock-blocked");
                std::thread::sleep(std::time::Duration::from_millis(2));
            }
            swept => return swept,
        }
    }
    unreachable!()
}

/// Build the representative sweep layout under `root`: one orphan
/// staging dir (18 bytes across two files), a live cache dir, and an
/// unrelated nix-store image sibling. Returns the three paths.
fn stage_sweep_layout(
    root: &std::path::Path,
) -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
    let orphan = root.join(".aarch64.stage0-12345-1700000000000000000");
    std::fs::create_dir_all(orphan.join("nested")).unwrap();
    std::fs::write(orphan.join("a"), b"hello world").unwrap(); // 11 bytes
    std::fs::write(orphan.join("nested/b"), vec![0u8; 7]).unwrap();

    let live_cache = root.join("aarch64");
    std::fs::create_dir_all(&live_cache).unwrap();
    std::fs::write(live_cache.join("rootfs.ext4"), b"do-not-delete").unwrap();

    let nix_store = root.join("nix-store-aarch64.img");
    std::fs::write(&nix_store, b"sparse").unwrap();
    (orphan, live_cache, nix_store)
}

// NOTE: the dry-run and real-run sweeps are split into two tests on
// purpose. A single test that swept twice took the Stage 0 `flock`,
// released it, then re-took it on the *same* path microseconds later;
// under parallel test load the close()-release / flock()-reacquire
// window intermittently surfaced `EWOULDBLOCK` (a `SkippedLockHeld`
// false positive). One acquire per test removes the self-race; the
// unique tempdir per test keeps them independent.

/// The dry-run sweep is purely observational: it reports
/// the orphan + byte count but mutates nothing.
#[test]
fn sweep_dry_run_reports_orphan_without_removing() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path().to_path_buf();
    let (orphan, live_cache, _nix_store) = stage_sweep_layout(&root);

    match sweep_uncontended(&root, true) {
        Stage0SweepOutcome::Swept {
            removed,
            freed_bytes,
        } => {
            assert_eq!(removed, 1, "dry-run reports the orphan");
            // The reported figure is the disk a delete returns — allocated
            // blocks, not the 18 bytes the two fixture files hold.
            assert!(
                freed_bytes >= 18,
                "dry-run reports the orphan's footprint: {freed_bytes}"
            );
        }
        Stage0SweepOutcome::SkippedLockHeld => panic!("dry-run must not skip"),
    }
    assert!(orphan.is_dir(), "dry-run must not remove the orphan");
    assert!(live_cache.is_dir(), "dry-run must not touch the live cache");
}

/// The real sweep removes the orphan staging dir, reports
/// its byte count, and leaves the live cache and unrelated siblings
/// intact.
#[test]
fn sweep_real_run_removes_orphan_and_leaves_siblings() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path().to_path_buf();
    let (orphan, live_cache, nix_store) = stage_sweep_layout(&root);

    match sweep_uncontended(&root, false) {
        Stage0SweepOutcome::Swept {
            removed,
            freed_bytes,
        } => {
            assert_eq!(removed, 1);
            assert!(freed_bytes >= 18, "reports the orphan's footprint");
        }
        Stage0SweepOutcome::SkippedLockHeld => panic!("must not skip on uncontended lock"),
    }
    assert!(!orphan.exists(), "orphan must be removed");
    assert!(
        live_cache.join("rootfs.ext4").is_file(),
        "live cache must be untouched"
    );
    assert!(nix_store.is_file(), "nix-store image must be untouched");
}

/// When a live Stage 0 is in progress and holds the
/// advisory lock, the sweep must skip rather than race the
/// staging dir the live run is about to promote.
#[test]
fn sweep_skips_when_stage0_lock_is_held() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path().to_path_buf();
    std::fs::create_dir_all(&root).unwrap();

    // Hold the lock as a "live" Stage 0 would.
    let _live = try_acquire_filelock_uncontended(&root.join("stage0"));

    // Stage an orphan to confirm the sweep would have something to do.
    let orphan = root.join(".aarch64.stage0-12345-1700000000000000000");
    std::fs::create_dir_all(&orphan).unwrap();

    match sweep_orphaned_stage0_staging_dirs_at(&root, false)
        .expect("sweep should succeed even when skipping")
    {
        Stage0SweepOutcome::SkippedLockHeld => {}
        Stage0SweepOutcome::Swept { .. } => {
            panic!("sweep must skip while the Stage 0 lock is held")
        }
    }
    assert!(
        orphan.is_dir(),
        "skipped sweep must not touch the would-be orphan"
    );
}

/// Sweep on a non-existent root is a no-op. Exercises
/// the early-return for fresh hosts that have never bootstrapped.
#[test]
fn sweep_is_noop_when_root_missing() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let missing = tmp.path().join("never-existed");

    match sweep_orphaned_stage0_staging_dirs_at(&missing, false)
        .expect("sweep on missing root should succeed")
    {
        Stage0SweepOutcome::Swept {
            removed,
            freed_bytes,
        } => {
            assert_eq!(removed, 0);
            assert_eq!(freed_bytes, 0);
        }
        Stage0SweepOutcome::SkippedLockHeld => {
            panic!("missing root must not look like lock contention")
        }
    }
}

/// Pin that the orphan reaper covers a builder state dir whatever its
/// name prefix. The traversal in `reap_orphaned_vm_helpers_at` is
/// prefix-agnostic and every builder writes a `builder.pid` sidecar under
/// the shared `~/.mvm/cache/builder-vm/vms/` tree; this test guards
/// against a future refactor narrowing either invariant.
#[test]
fn reap_picks_up_orphaned_builder_state_dir_regardless_of_prefix() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let vms = tmp.path();
    let builder_dir = vms.join("mvm-builder-unrecognised-prefix-abc12345");
    std::fs::create_dir_all(&builder_dir).unwrap();
    // `i32::MAX` is guaranteed not to be a live process on any
    // supported host — classify_pid → Dead, so the dir has no
    // live owner and is eligible for removal.
    std::fs::write(builder_dir.join("builder.pid"), format!("{}\n", i32::MAX)).unwrap();

    let outcome = reap_orphaned_vm_helpers_at(
        vms,
        BUILDER_SIDECARS,
        true,
        /* all_dirs_managed = */ false,
        /* dry_run = */ false,
    )
    .expect("reap should succeed");

    assert_eq!(
        outcome.removed_dirs, 1,
        "builder state dir should be reaped whatever its prefix"
    );
    assert!(
        !builder_dir.exists(),
        "builder state dir should be gone on disk"
    );
}

#[test]
fn builder_vm_stage0_staging_dir_is_hidden_sibling() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let final_dir = tmp.path().join("builder-vm").join("aarch64");
    let staging = unique_builder_vm_stage0_staging_dir(&final_dir)
        .expect("valid final dir should produce staging dir");

    assert_eq!(staging.parent(), final_dir.parent());
    let name = staging
        .file_name()
        .and_then(|s| s.to_str())
        .expect("staging basename should be utf-8");
    assert!(
        name.starts_with(".aarch64.stage0-"),
        "unexpected staging dir name: {name}"
    );
}

#[test]
fn builder_vm_stage0_promotion_rejects_invalid_artifacts_without_live_cache() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let staging = tmp.path().join(".aarch64.stage0-test");
    std::fs::create_dir_all(&staging).expect("mkdir staging");
    std::fs::write(staging.join("vmlinux"), b"stub").expect("write stub kernel");
    std::fs::write(staging.join("kernel.config"), b"stub").expect("write stub config");
    std::fs::write(staging.join("rootfs.ext4"), b"stub").expect("write stub rootfs");
    std::fs::write(
        staging.join("cmdline.txt"),
        b"console=hvc0 root=/dev/vda ro init=/sbin/mvm-host-vm-init\n",
    )
    .expect("write cmdline");
    std::fs::write(
        staging.join("manifest.json"),
        br#"{"cache_contract_version":2,"runtime_overlay_ready":true,"vsock_egress_ready":true}"#,
    )
    .expect("write manifest");
    write_builder_vm_source_cache_metadata(&staging, "fingerprint");
    let final_dir = tmp.path().join("aarch64");

    let err = promote_builder_vm_stage0_cache(&staging, &final_dir, "fingerprint")
        .expect_err("stub artifacts must not be promoted");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("validating Stage 0 builder VM artifacts"),
        "{msg}"
    );
    assert!(!final_dir.exists(), "invalid cache must not go live");
}

#[test]
fn builder_vm_stage0_promotion_validates_then_promotes() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let staging = tmp.path().join(".aarch64.stage0-test");
    let final_dir = tmp.path().join("aarch64");
    write_valid_builder_vm_artifacts(&staging);
    write_builder_vm_source_cache_metadata(&staging, "fingerprint");

    promote_builder_vm_stage0_cache(&staging, &final_dir, "fingerprint")
        .expect("valid artifacts should promote");

    assert!(!staging.exists(), "staging dir should be moved away");
    validate_builder_vm_stage0_artifacts(&final_dir).expect("final cache should validate");
    assert!(builder_vm_source_cache_ready(&final_dir, "fingerprint"));
}

#[test]
fn builder_vm_stage0_promotion_keeps_existing_valid_cache() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let staging = tmp.path().join(".aarch64.stage0-test");
    let final_dir = tmp.path().join("aarch64");
    write_valid_builder_vm_artifacts(&staging);
    write_builder_vm_source_cache_metadata(&staging, "fingerprint");
    write_valid_builder_vm_artifacts(&final_dir);
    write_builder_vm_source_cache_metadata(&final_dir, "fingerprint");

    promote_builder_vm_stage0_cache(&staging, &final_dir, "fingerprint")
        .expect("existing valid cache should win the race");

    assert!(!staging.exists(), "redundant staging dir should be removed");
    validate_builder_vm_stage0_artifacts(&final_dir).expect("existing cache should remain valid");
}

#[test]
fn builder_vm_source_cache_requires_matching_fingerprint() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let cache = tmp.path().join("builder-vm").join("aarch64");
    write_valid_builder_vm_artifacts(&cache);

    assert!(
        !builder_vm_source_cache_ready(&cache, "fingerprint"),
        "valid artifacts without a source marker must not satisfy source checkout cache"
    );
    write_builder_vm_source_cache_metadata(&cache, "other");
    assert!(
        !builder_vm_source_cache_ready(&cache, "fingerprint"),
        "stale source marker must not satisfy source checkout cache"
    );
    write_builder_vm_source_cache_metadata(&cache, "fingerprint");
    assert!(builder_vm_source_cache_ready(&cache, "fingerprint"));
}

#[test]
fn builder_vm_source_cache_status_reports_safe_reason_codes() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let cache = tmp.path().join("builder-vm").join("aarch64");

    assert_eq!(
        builder_vm_source_cache_status(&cache, "fingerprint").reason_code(),
        "missing_artifact"
    );

    std::fs::create_dir_all(&cache).expect("mkdir cache");
    std::fs::write(cache.join("vmlinux"), b"stub").expect("write stub kernel");
    std::fs::write(cache.join("rootfs.ext4"), b"stub").expect("write stub rootfs");
    assert_eq!(
        builder_vm_source_cache_status(&cache, "fingerprint").reason_code(),
        "invalid_stage0_artifacts"
    );

    write_valid_builder_vm_artifacts(&cache);
    std::fs::write(cache.join("kernel.config"), b"CONFIG_TUN=y\n").expect("write unsafe config");
    assert_eq!(
        builder_vm_source_cache_status(&cache, "fingerprint").reason_code(),
        "invalid_stage0_artifacts"
    );
    write_valid_builder_vm_artifacts(&cache);
    assert_eq!(
        builder_vm_source_cache_status(&cache, "fingerprint").reason_code(),
        "missing_fingerprint"
    );

    write_builder_vm_source_fingerprint(&cache, "other").expect("write fingerprint");
    assert_eq!(
        builder_vm_source_cache_status(&cache, "fingerprint").reason_code(),
        "fingerprint_mismatch"
    );

    write_builder_vm_source_fingerprint(&cache, "fingerprint").expect("write fingerprint");
    assert_eq!(
        builder_vm_source_cache_status(&cache, "fingerprint").reason_code(),
        "missing_artifact_digest_manifest"
    );

    write_builder_vm_artifact_digest_manifest(&cache).expect("write digest manifest");
    assert_eq!(
        builder_vm_source_cache_status(&cache, "fingerprint").reason_code(),
        "missing_provenance"
    );

    write_builder_vm_source_cache_provenance(&cache, "other").expect("write provenance");
    assert_eq!(
        builder_vm_source_cache_status(&cache, "fingerprint").reason_code(),
        "provenance_mismatch"
    );

    write_builder_vm_source_cache_provenance(&cache, "fingerprint").expect("write provenance");
    assert_eq!(
        builder_vm_source_cache_status(&cache, "fingerprint").reason_code(),
        "hit"
    );

    write_builder_vm_artifact_digest_manifest(&cache).expect("rewrite digest manifest");
    std::fs::OpenOptions::new()
        .append(true)
        .open(cache.join("vmlinux"))
        .expect("open kernel")
        .write_all(b"tamper")
        .expect("tamper kernel");
    assert_eq!(
        builder_vm_source_cache_status(&cache, "fingerprint").reason_code(),
        "artifact_digest_mismatch"
    );

    write_valid_builder_vm_artifacts(&cache);
    write_builder_vm_source_cache_metadata(&cache, "fingerprint");
    assert_eq!(
        builder_vm_source_cache_status(&cache, "fingerprint").reason_code(),
        "hit"
    );
}

// Fix A — `build_image_via_libkrun` writes the same fingerprint +
// artifact-digest + provenance sidecars the Layer-1 cache uses, so the
// next build fast-paths past the builder VM. Round-trip: a sidecar
// write for a fingerprint reads back as a hit for that fingerprint and a
// miss for any other — which is exactly the gate `ensure_dev_image`
// consults before deciding to rebuild.
#[test]
fn dev_image_cache_sidecars_enable_hit_and_reject_changed_source() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let out = tmp.path().join("dev").join("current");
    write_valid_builder_vm_artifacts(&out);

    write_builder_vm_cache_sidecars(&out, "devfp").expect("write sidecars");
    assert!(
        builder_vm_source_cache_status(&out, "devfp").is_ready(),
        "matching fingerprint must be a cache hit"
    );
    assert_eq!(
        builder_vm_source_cache_status(&out, "changed").reason_code(),
        "fingerprint_mismatch",
        "a changed source fingerprint must miss so the dev image rebuilds"
    );
}

#[test]
fn builder_vm_source_cache_provenance_omits_local_paths_and_artifact_digests() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let cache = tmp.path().join("builder-vm").join("aarch64");
    write_valid_builder_vm_artifacts(&cache);
    write_builder_vm_source_cache_metadata(&cache, "fingerprint");

    let json =
        std::fs::read_to_string(cache.join(BUILDER_VM_PROVENANCE_FILE)).expect("read provenance");
    assert!(json.contains("\"source_kind\": \"source_checkout_stage0\""));
    assert!(json.contains("\"source_fingerprint\": \"fingerprint\""));
    assert!(json.contains("\"vmlinux\""));
    assert!(json.contains("\"rootfs.ext4\""));
    assert!(
        !json.contains(&cache.display().to_string()),
        "provenance must not store local cache paths: {json}"
    );
    assert!(
        !json.contains("sha256"),
        "artifact digests belong in the separate digest manifest, not provenance: {json}"
    );
}

#[test]
fn builder_vm_source_cache_rejects_tampered_provenance() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let cache = tmp.path().join("builder-vm").join("aarch64");
    write_valid_builder_vm_artifacts(&cache);
    write_builder_vm_source_cache_metadata(&cache, "fingerprint");

    let tampered = serde_json::json!({
        "schema_version": 1,
        "source_kind": "source_checkout_stage0",
        "source_fingerprint": "other",
        "artifacts": ["vmlinux", "rootfs.ext4"]
    });
    std::fs::write(
        cache.join(BUILDER_VM_PROVENANCE_FILE),
        serde_json::to_string_pretty(&tampered).expect("json"),
    )
    .expect("write tampered provenance");

    assert_eq!(
        builder_vm_source_cache_status(&cache, "fingerprint").reason_code(),
        "provenance_mismatch"
    );
    assert!(
        !builder_vm_source_cache_ready(&cache, "fingerprint"),
        "provenance drift must force a source-checkout rebuild"
    );
}

#[test]
fn builder_vm_source_cache_rejects_tampered_artifact_after_metadata() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let cache = tmp.path().join("builder-vm").join("aarch64");
    write_valid_builder_vm_artifacts(&cache);
    write_builder_vm_source_cache_metadata(&cache, "fingerprint");

    std::fs::OpenOptions::new()
        .append(true)
        .open(cache.join("vmlinux"))
        .expect("open kernel")
        .write_all(b"tamper")
        .expect("tamper kernel");

    assert!(
        !builder_vm_source_cache_ready(&cache, "fingerprint"),
        "artifact digest drift must force a source-checkout rebuild"
    );
}

#[test]
fn builder_vm_stage0_promotion_replaces_stale_valid_cache() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let staging = tmp.path().join(".aarch64.stage0-test");
    let final_dir = tmp.path().join("aarch64");
    write_valid_builder_vm_artifacts(&staging);
    write_builder_vm_source_cache_metadata(&staging, "new");
    write_valid_builder_vm_artifacts(&final_dir);
    write_builder_vm_source_cache_metadata(&final_dir, "old");

    promote_builder_vm_stage0_cache(&staging, &final_dir, "new")
        .expect("stale valid cache should be replaced");

    assert!(!staging.exists(), "staging dir should be moved away");
    assert!(builder_vm_source_cache_ready(&final_dir, "new"));
}

#[test]
fn stage0_promotion_leaves_the_cached_workload_kernel_alone() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let cache_dir = tmp.path().join("cache");
    let final_dir = cache_dir.join("builder-vm").join("aarch64");
    let staging = cache_dir.join("builder-vm").join(".aarch64.stage0-test");

    // A previously-built, verified workload kernel sits in the cache.
    let kernel = mvm_build::kernel_fetch::cached_kernel_path(&cache_dir, "aarch64", "workload");
    std::fs::create_dir_all(kernel.parent().expect("kernel parent")).expect("mkdir kernels");
    std::fs::write(&kernel, b"a real workload kernel").expect("write kernel");
    mvm_build::kernel_fetch::record_kernel_digest(&kernel).expect("record digest");
    assert!(
        matches!(
            mvm_build::kernel_fetch::resolve_kernel(&cache_dir, "aarch64", "workload", true),
            mvm_build::kernel_fetch::KernelResolution::Cached(_)
        ),
        "precondition: the planted kernel must resolve as a verified cache hit"
    );

    // The builder-VM source fingerprint changes, so Stage 0 rebuilds and promotes.
    write_valid_builder_vm_artifacts(&final_dir);
    write_builder_vm_source_cache_metadata(&final_dir, "old");
    write_valid_builder_vm_artifacts(&staging);
    write_builder_vm_source_cache_metadata(&staging, "new");
    promote_builder_vm_stage0_cache(&staging, &final_dir, "new").expect("promote");

    assert!(
        kernel.exists(),
        "promoting a new builder-VM image must not delete the cached workload kernel at {}",
        kernel.display()
    );
}
