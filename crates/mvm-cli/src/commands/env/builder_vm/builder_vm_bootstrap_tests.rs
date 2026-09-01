use super::stage0_cache::validate_builder_vm_stage0_artifacts;
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

#[test]
#[cfg(feature = "builder-vm")]
fn build_heartbeat_emits_while_alive_and_stops_on_drop() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let count = Arc::new(AtomicUsize::new(0));
    let sink = Arc::clone(&count);
    // Tight 10ms cadence into a counter (not stdout) so the test is fast and
    // deterministic-ish; a generous window then asserts it ticked.
    let hb = BuildHeartbeat::start_with(
        "Test build",
        std::time::Duration::from_millis(10),
        move |_line| {
            sink.fetch_add(1, Ordering::Relaxed);
        },
    );
    std::thread::sleep(std::time::Duration::from_millis(120));
    let while_alive = count.load(Ordering::Relaxed);
    assert!(while_alive >= 1, "heartbeat should tick while alive");

    drop(hb); // joins the thread — no further emits after this returns
    let after_drop = count.load(Ordering::Relaxed);
    std::thread::sleep(std::time::Duration::from_millis(60));
    assert_eq!(
        count.load(Ordering::Relaxed),
        after_drop,
        "no heartbeat ticks after drop joins the thread"
    );
}

#[test]
fn find_builder_vm_flake_resolves_to_in_repo_path() {
    // From a source checkout, the helper must find the
    // flake at <workspace>/nix/images/builder-vm/flake.nix.
    // `env!("CARGO_MANIFEST_DIR")` is baked at compile time
    // and points at the workspace's mvm-cli crate dir, so
    // this assertion is robust across `cargo test` and
    // `cargo nextest`.
    let path = find_builder_vm_flake().expect("expected builder-vm flake present in repo");
    assert!(
        path.ends_with("nix/images/builder-vm"),
        "unexpected flake path: {path}"
    );
    // The flake file itself must be readable.
    assert!(
        std::path::Path::new(&path).join("flake.nix").is_file(),
        "flake.nix missing under {path}"
    );
}

/// Per-arch artifact filenames must match what the release
/// workflow's `builder-vm-image` job uploads. Pure function —
/// asserts the contract between `builder_vm_artifact_names()`
/// (the consumer side that constructs download URLs) and the
/// `cp "$STORE_PATH/..." "staging/builder-vm-..."` lines in
/// `.github/workflows/release.yml` (the producer side).
#[test]
fn builder_vm_artifact_names_match_release_workflow() {
    let n = builder_vm_artifact_names("aarch64");
    assert_eq!(n.kernel, "builder-vm-vmlinux-aarch64");
    assert_eq!(n.rootfs, "builder-vm-rootfs-aarch64.ext4");
    assert_eq!(n.cmdline, "builder-vm-aarch64.cmdline.txt");
    assert_eq!(n.manifest, "builder-vm-aarch64.manifest.json");
    assert_eq!(n.checksums, "builder-vm-aarch64-checksums-sha256.txt");

    let n = builder_vm_artifact_names("x86_64");
    assert_eq!(n.kernel, "builder-vm-vmlinux-x86_64");
    assert_eq!(n.rootfs, "builder-vm-rootfs-x86_64.ext4");
    assert_eq!(n.cmdline, "builder-vm-x86_64.cmdline.txt");
    assert_eq!(n.manifest, "builder-vm-x86_64.manifest.json");
    assert_eq!(n.checksums, "builder-vm-x86_64-checksums-sha256.txt");
}

#[test]
fn builder_vm_bootstrap_uses_cache_even_in_source_checkout() {
    let action = resolve_builder_vm_bootstrap_action(
        Ok("/repo/nix/images/builder-vm".to_string()),
        true,
        mvm_build::boot_image_select::BootImageAcquisition::Build,
    )
    .expect("cache hit should be usable in a source checkout");

    assert_eq!(action, BuilderVmBootstrapAction::UseCached);
}

#[test]
fn builder_vm_bootstrap_source_checkout_builds_from_source_on_cache_miss() {
    let action = resolve_builder_vm_bootstrap_action(
        Ok("/repo/nix/images/builder-vm".to_string()),
        false,
        mvm_build::boot_image_select::BootImageAcquisition::Build,
    )
    .expect("source checkout cache miss should route to local source build");

    assert_eq!(
        action,
        BuilderVmBootstrapAction::BuildFromSource {
            flake_dir: "/repo/nix/images/builder-vm".to_string()
        }
    );
}

#[test]
fn builder_vm_bootstrap_installed_binary_may_download_on_cache_miss() {
    let action = resolve_builder_vm_bootstrap_action(
        Err(anyhow::anyhow!("no source flake")),
        false,
        mvm_build::boot_image_select::BootImageAcquisition::Fetch,
    )
    .expect("installed binaries may use published prebuilts");

    assert_eq!(action, BuilderVmBootstrapAction::DownloadPublished);
}

#[test]
fn builder_vm_bootstrap_fetch_override_bypasses_source_build() {
    let action = resolve_builder_vm_bootstrap_action(
        Ok("/repo/nix/images/builder-vm".to_string()),
        false,
        mvm_build::boot_image_select::BootImageAcquisition::Fetch,
    )
    .expect("an explicit fetch in a source checkout must use the published image");

    assert_eq!(action, BuilderVmBootstrapAction::DownloadPublished);
}

#[test]
fn builder_vm_bootstrap_build_override_needs_a_source_flake() {
    let error = resolve_builder_vm_bootstrap_action(
        Err(anyhow::anyhow!("no source flake")),
        false,
        mvm_build::boot_image_select::BootImageAcquisition::Build,
    )
    .expect_err("an installed binary cannot satisfy a forced local build");

    assert!(
        error
            .to_string()
            .contains("requires the in-repo builder VM flake")
    );
}

#[cfg(feature = "builder-vm")]
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

#[cfg(feature = "builder-vm")]
#[test]
fn first_nameserver_from_resolv_conf_none_when_absent() {
    let body = "search example.internal\noptions timeout:1\n";
    assert_eq!(bootstrap::first_nameserver_from_resolv_conf(body), None);
}

#[cfg(feature = "builder-vm")]
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

#[cfg(feature = "builder-vm")]
#[test]
fn stage0_locked_input_sources_read_builder_flake_lock() {
    let flake_dir = find_builder_vm_flake().expect("builder flake path");
    let inputs = bootstrap::stage0_locked_input_sources(&flake_dir).expect("parse flake.lock");
    assert_eq!(inputs.len(), 3);
    assert_eq!(inputs[0].0, "nixpkgs");
    assert_eq!(inputs[1].0, "microvm");
    assert_eq!(inputs[2].0, "microvm/spectrum");
}

/// Even when the resolver routes to `DownloadPublished`,
/// a contributor build (no `release-artifact-bootstrap` feature) must
/// refuse to invoke the download path and surface a clear structural
/// error. This locks the AGENTS.md / CLAUDE.md "no prebuilt builder
/// VM artifact" invariant into the type system rather than runtime
/// branch order. The companion sibling under
/// `#[cfg(feature = "release-artifact-bootstrap")]` would need a
/// network mock; we cover the structural-failure side here because
/// it's the one contributors hit.
#[cfg(not(feature = "release-artifact-bootstrap"))]
#[test]
fn perform_builder_vm_download_published_bails_without_feature() {
    let err = perform_builder_vm_download_published("aarch64", "/tmp/mvm-w4-test-out")
        .expect_err("download must refuse without release-artifact-bootstrap");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("release-artifact-bootstrap"),
        "error must name the feature flag: {msg}"
    );
    assert!(
        msg.contains("nix/images/builder-vm/flake.nix"),
        "error must point at the source-checkout remediation: {msg}"
    );
    // Critically: the bail must happen before any directory creation.
    // Otherwise a contributor running on a shared host could pollute
    // `/tmp/...` even when the gate is "closed".
    assert!(
        !std::path::Path::new("/tmp/mvm-w4-test-out").exists(),
        "structural failure must not touch the filesystem"
    );
}

fn write_valid_builder_vm_artifacts(dir: &std::path::Path) {
    const EXT4_MAGIC_OFFSET: usize = 1024 + 56;
    std::fs::create_dir_all(dir).expect("mkdir artifact dir");
    std::fs::write(dir.join("vmlinux"), vec![0x7f; 1024 * 1024 + 1]).expect("write kernel");
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
        br#"{"cache_contract_version":2,"runtime_overlay_ready":true,"vsock_egress_ready":true}"#,
    )
    .expect("write manifest");
}

fn write_builder_vm_flake(dir: &std::path::Path, flake: &str, lock: Option<&str>) {
    std::fs::create_dir_all(dir).expect("mkdir flake dir");
    std::fs::write(dir.join("flake.nix"), flake).expect("write flake");
    if let Some(lock) = lock {
        std::fs::write(dir.join("flake.lock"), lock).expect("write lock");
    }
}

fn write_builder_vm_source_cache_metadata(dir: &std::path::Path, fingerprint: &str) {
    write_builder_vm_source_fingerprint(dir, fingerprint).expect("write fingerprint");
    write_builder_vm_artifact_digest_manifest(dir).expect("write artifact digest manifest");
    write_builder_vm_source_cache_provenance(dir, fingerprint).expect("write provenance");
}

/// `acquire_stage0_lock` is an advisory `flock(2)`
/// guard at `<cache_parent>/stage0.lock`. The first acquisition
/// succeeds; a second concurrent attempt while the first guard is
/// still in scope fails fast with a recognizable message; once the
/// first guard drops, the lock becomes available again.
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

    let err = match acquire_stage0_lock(out_dir_str) {
        Err(e) => e,
        Ok(_) => panic!("second acquisition must refuse while first is held"),
    };
    let msg = format!("{err:#}");
    assert!(
        msg.contains("already bootstrapping the builder VM image"),
        "unexpected error: {msg}"
    );
    assert!(
        msg.contains("stage0.lock"),
        "error should name the lock file path: {msg}"
    );

    drop(first);

    // Now reachable again — guards must not leak past their scope.
    let _second = acquire_stage0_lock_uncontended(out_dir_str);
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
        match acquire_stage0_lock(out_dir) {
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

/// Lay out a synthetic mvm workspace under `tmp` that the
/// `builder_vm_source_fingerprint` will accept:
///
/// ```text
/// tmp/
///   Cargo.lock
///   nix/lib/mkguest.nix
///   nix/images/builder-vm/{flake.nix,flake.lock}
/// ```
///
/// In-VM binary identity now rides on the embedded host-binary
/// bytes (see `fold_embedded_binary_identity`), so the old per-crate
/// `crates/<name>/{Cargo.toml,src}` stubs are gone. `nix/lib` is
/// present because the flake imports it (Layer 3) and the dir-walker
/// skip tests exercise it.
///
/// Returns the path of the `nix/images/builder-vm/` dir — the
/// argument the fingerprint function expects.
fn write_builder_vm_workspace(tmp: &std::path::Path) -> std::path::PathBuf {
    std::fs::write(tmp.join("Cargo.lock"), "# stub Cargo.lock\n").expect("write Cargo.lock");

    let nix_lib = tmp.join("nix/lib");
    std::fs::create_dir_all(&nix_lib).expect("mkdir nix/lib");
    std::fs::write(nix_lib.join("mkguest.nix"), "{ }\n").expect("write nix/lib");

    let flake = tmp.join("nix/images/builder-vm");
    write_builder_vm_flake(&flake, "{ outputs = _: {}; }", Some("{\"nodes\":{}}"));
    flake
}

#[test]
fn builder_vm_source_fingerprint_changes_with_flake_inputs() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let flake = write_builder_vm_workspace(tmp.path());
    let first = builder_vm_source_fingerprint(flake.to_str().unwrap()).expect("fingerprint");

    write_builder_vm_flake(
        &flake,
        "{ outputs = _: { changed = true; }; }",
        Some("{\"nodes\":{}}"),
    );
    let second = builder_vm_source_fingerprint(flake.to_str().unwrap()).expect("fingerprint");

    assert_ne!(first, second);
}

#[test]
fn builder_vm_source_fingerprint_is_unaffected_by_cargo_lock() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let flake = write_builder_vm_workspace(tmp.path());
    let first = builder_vm_source_fingerprint(flake.to_str().unwrap()).expect("fingerprint");

    // The builder-VM flake forbids `buildRustPackage`; no flake artifact
    // consumes the workspace lockfile. The only baked Rust is the
    // embedded host binaries, whose identity rides on the byte-hash layer
    // (a rebuilt binary changes its sha256). A `cargo update` therefore
    // must NOT invalidate the builder-VM cache key.
    std::fs::write(
        tmp.path().join("Cargo.lock"),
        "# stub Cargo.lock — updated\n",
    )
    .expect("rewrite Cargo.lock");
    let second = builder_vm_source_fingerprint(flake.to_str().unwrap()).expect("fingerprint");

    assert_eq!(
        first, second,
        "a workspace Cargo.lock edit must not invalidate the builder-vm cache key"
    );
}

#[test]
fn fold_embedded_binary_identity_distinguishes_inputs() {
    // The new contract: in-VM binary identity rides on the embedded
    // bytes, not a per-crate source walk. A rebuilt binary (changed
    // name OR changed sha256) must fold to a different digest so the
    // Stage 0 cache key busts.
    let base = {
        let mut h = Sha256::new();
        fold_embedded_binary_identity(&mut h, "mvm-host-vm-init", "aa");
        hex::encode(h.finalize())
    };
    let changed_hash = {
        let mut h = Sha256::new();
        fold_embedded_binary_identity(&mut h, "mvm-host-vm-init", "bb");
        hex::encode(h.finalize())
    };
    let changed_name = {
        let mut h = Sha256::new();
        fold_embedded_binary_identity(&mut h, "mvm-egress-proxy", "aa");
        hex::encode(h.finalize())
    };

    assert_ne!(
        base, changed_hash,
        "a rebuilt binary (new sha256) must bust the cache key"
    );
    assert_ne!(
        base, changed_name,
        "a renamed embedded binary must bust the cache key"
    );
    // The `\0` separator prevents (name+hash) concatenation
    // collisions, e.g. ("ab","") vs ("a","b").
    let glued = {
        let mut h = Sha256::new();
        fold_embedded_binary_identity(&mut h, "mvm-host-vm-initaa", "");
        hex::encode(h.finalize())
    };
    assert_ne!(base, glued, "name/hash boundary must be unambiguous");
}

#[test]
fn builder_vm_source_fingerprint_is_deterministic_for_identical_workspace() {
    let tmp1 = tempfile::tempdir().expect("tempdir 1");
    let tmp2 = tempfile::tempdir().expect("tempdir 2");
    let flake1 = write_builder_vm_workspace(tmp1.path());
    let flake2 = write_builder_vm_workspace(tmp2.path());

    let a = builder_vm_source_fingerprint(flake1.to_str().unwrap()).expect("fingerprint 1");
    let b = builder_vm_source_fingerprint(flake2.to_str().unwrap()).expect("fingerprint 2");

    // Same inputs → same fingerprint regardless of where they
    // live on disk. (The hash discipline keys off relative
    // paths, never absolute, so this must hold.)
    assert_eq!(
        a, b,
        "identical workspace layouts must produce identical fingerprints"
    );
}

#[test]
fn builder_vm_source_fingerprint_ignores_target_dir() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let flake = write_builder_vm_workspace(tmp.path());
    let baseline =
        builder_vm_source_fingerprint(flake.to_str().unwrap()).expect("baseline fingerprint");

    // The `nix/lib` walk (Layer 3) skips `target/`. Drop junk in a
    // `target/` under the walked dir; the fingerprint must ignore it.
    let lib_target = tmp.path().join("nix/lib/target/debug");
    std::fs::create_dir_all(&lib_target).expect("mkdir nix/lib/target");
    std::fs::write(lib_target.join("junk.rlib"), vec![0u8; 4096]).expect("write target garbage");

    let after = builder_vm_source_fingerprint(flake.to_str().unwrap()).expect("after fingerprint");

    assert_eq!(
        baseline, after,
        "target/ contents must not affect the builder-vm cache key"
    );
}

#[test]
fn builder_vm_source_fingerprint_ignores_hidden_files() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let flake = write_builder_vm_workspace(tmp.path());
    let baseline =
        builder_vm_source_fingerprint(flake.to_str().unwrap()).expect("baseline fingerprint");

    // `.git/HEAD`, editor swap files (`.swp`, `foo.rs.swp`),
    // `.DS_Store`, etc. — none are flake inputs and editing them
    // shouldn't bust the cache. Drop each inside the walked `nix/lib`
    // dir, exercising the explicit skip in `walk_source_dir_sorted`.
    for path in [
        "nix/lib/.DS_Store",
        "nix/lib/.swp",
        "nix/lib/mkguest.nix.swp",
    ] {
        std::fs::write(tmp.path().join(path), b"junk").expect("write hidden");
    }

    let after = builder_vm_source_fingerprint(flake.to_str().unwrap()).expect("after fingerprint");

    assert_eq!(
        baseline, after,
        "hidden entries / swap files must not affect the cache key"
    );
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

// -------------------------------------------------------------------
// Stage 0 audit-emit helpers.
//
// Tests below pin the *details* of the audit emits (which strings
// the macro will write into `kind`, `detail`) so that the
// downstream log shippers don't break on a typo, plus a structural
// test for the failure-summary truncation rule.
// -------------------------------------------------------------------

#[test]
fn stage0_fingerprint_prefix_truncates_to_eight_chars() {
    let full = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let prefix = stage0_fingerprint_prefix(full);
    assert_eq!(prefix, "01234567");
    assert_eq!(prefix.len(), 8);
}

#[test]
fn stage0_fingerprint_prefix_handles_short_input() {
    // Defensive: source_fingerprint should always be 64 hex chars,
    // but if a future caller hands us a short string the helper
    // must not panic.
    let prefix = stage0_fingerprint_prefix("abc");
    assert_eq!(prefix, "abc");
}

#[test]
fn stage0_failure_reason_summary_strips_newlines_and_caps_length() {
    let err = anyhow::anyhow!("first line\nsecond line\twith tab");
    let summary = stage0_failure_reason_summary(&err);
    assert!(!summary.contains('\n'));
    assert!(!summary.contains('\r'));
    assert!(!summary.contains('\t'));

    // 200-char input → 160-char output.
    let long_err = anyhow::anyhow!("{}", "x".repeat(200));
    let summary = stage0_failure_reason_summary(&long_err);
    assert_eq!(summary.chars().count(), 160);
}

#[test]
fn stage0_failure_reason_summary_escapes_equals() {
    // The audit detail format is space-separated `key=value` pairs.
    // A bare `=` in the reason text would confuse downstream
    // parsers; the helper maps them to `~`.
    let err = anyhow::anyhow!("expected x=1 got y=2");
    let summary = stage0_failure_reason_summary(&err);
    assert!(!summary.contains('='), "got {summary}");
    assert!(summary.contains('~'));
}

#[test]
fn stage0_failure_stage_wire_format_is_stable() {
    // The `stage=` value lands in audit details that downstream
    // dashboards filter on. Pinning the casing here keeps a future
    // refactor from accidentally renaming the variant.
    assert_eq!(Stage0FailureStage::Build.as_str(), "build");
    assert_eq!(Stage0FailureStage::Validate.as_str(), "validate");
    assert_eq!(format!("{}", Stage0FailureStage::Build), "build");
}

#[test]
fn stage0_flavor_current_wire_format_is_stable() {
    // The `flavor=` value emitted on every
    // `Stage0Boot` / `Stage0CachePromoted` audit line. Today there
    // is one variant (`"current"` — the nix-tarball seed); a future
    // change may introduce additional variants. Pinning the current
    // literal here so a rename surfaces immediately.
    assert_eq!(STAGE0_FLAVOR_CURRENT, "current");
}

/// A non-ext4 blob (here: zeros, no valid superblock) must surface
/// as an `Err` from the load, not a silent "init present / absent".
/// Cross-platform — no `mke2fs` needed to produce a bad image.
#[cfg(feature = "builder-vm")]
#[test]
fn verify_stage0_rootfs_has_init_rejects_non_ext4() {
    let tmp = tempfile::tempdir().unwrap();
    let rootfs = tmp.path().join("rootfs.ext4");
    std::fs::write(&rootfs, vec![0u8; 1024 * 1024]).unwrap();
    let err = verify_stage0_rootfs_has_init(&rootfs)
        .expect_err("a zero-filled blob is not a loadable ext4");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("as ext4"),
        "error names the load failure: {msg}"
    );
}

/// Build a tiny real ext4 from `staged_dir` at `image`, returning
/// `false` if `mke2fs` isn't installed (so the test skips rather than
/// fails on a host without e2fsprogs). Mirrors the preallocate-then-
/// `mke2fs -d` shape `mvm_fs::oci_to_rootfs::ext4` uses.
#[cfg(all(feature = "builder-vm", target_os = "linux"))]
fn mke2fs_from_dir(staged_dir: &std::path::Path, image: &std::path::Path) -> bool {
    {
        let f = std::fs::File::create(image).expect("create image file");
        f.set_len(16 * 1024 * 1024).expect("preallocate image");
    }
    match std::process::Command::new("mke2fs")
        .args(["-q", "-F", "-t", "ext4", "-b", "4096", "-d"])
        .arg(staged_dir)
        .arg(image)
        .output()
    {
        Ok(out) if out.status.success() => true,
        Ok(out) => panic!("mke2fs failed: {}", String::from_utf8_lossy(&out.stderr)),
        Err(_) => false, // e2fsprogs absent on this host — skip.
    }
}

/// Real ext4 round-trip: an image carrying `/sbin/mvm-host-vm-init`
/// passes; an otherwise-identical image without it fails. Linux-only
/// because `mke2fs` is the only ext4 writer available (matches the
/// `oci_to_rootfs` ext4 tests' gating).
#[cfg(all(feature = "builder-vm", target_os = "linux"))]
#[test]
fn verify_stage0_rootfs_has_init_round_trips_real_ext4() {
    let tmp = tempfile::tempdir().unwrap();

    let with_dir = tmp.path().join("with/sbin");
    std::fs::create_dir_all(&with_dir).unwrap();
    std::fs::write(with_dir.join("mvm-host-vm-init"), b"#!/bin/true\n").unwrap();
    let with_img = tmp.path().join("with.ext4");
    if !mke2fs_from_dir(&tmp.path().join("with"), &with_img) {
        eprintln!("skipping: mke2fs not installed");
        return;
    }
    verify_stage0_rootfs_has_init(&with_img)
        .expect("rootfs carrying /sbin/mvm-host-vm-init must validate");

    let without_dir = tmp.path().join("without/sbin");
    std::fs::create_dir_all(&without_dir).unwrap();
    std::fs::write(without_dir.join("something-else"), b"x").unwrap();
    let without_img = tmp.path().join("without.ext4");
    assert!(mke2fs_from_dir(&tmp.path().join("without"), &without_img));
    let err = verify_stage0_rootfs_has_init(&without_img)
        .expect_err("rootfs missing the init binary must be rejected");
    assert!(
        format!("{err:#}").contains("missing /sbin/mvm-host-vm-init"),
        "error names the missing binary"
    );
}
