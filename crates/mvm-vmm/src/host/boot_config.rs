//! dm-verity/runtime-overlay helpers and Firecracker API body builders.
//!
//! These host-side boot helpers are backend-agnostic and live in `mvm-vmm`
//! so concrete VMM backends can build kernel cmdlines and Firecracker API
//! bodies without depending on `mvm-runtime`.

/// Probe the directory containing `rootfs_path` for the dm-verity sidecar
/// files emitted by mkGuest when `verifiedBoot = true`. The rootfs and its
/// sidecars are host files the VMM attaches as block devices, so the probe
/// reads the host filesystem directly — it must not shell into a builder/dev
/// VM, which both missed the real host sidecars and woke a heavyweight VM on
/// every run. Returns `(Some(verity_path), Some(roothash))` when both files
/// are present and the roothash decodes to a 64-char hex string; otherwise
/// `(None, None)` so callers fall back to the unverified-boot path.
/// The host's current wall clock as an `mvm.hostepoch=<unix_seconds>` cmdline
/// token. The libkrun + hvf builder VMMs expose no RTC, so the guest boots with a
/// ~1970 clock; PID 1 reads this token and seeds the wall clock from it.
pub fn builder_hostepoch_cmdline_token() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("mvm.hostepoch={secs}")
}

pub fn probe_verity_sidecar(rootfs_path: &str) -> (Option<String>, Option<String>) {
    use std::path::Path;

    let Some(parent) = Path::new(rootfs_path)
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
    else {
        return (None, None);
    };
    let verity = parent.join("rootfs.verity");
    let roothash_file = parent.join("rootfs.roothash");

    if !verity.is_file() {
        return (None, None);
    }
    let Ok(raw) = std::fs::read_to_string(&roothash_file) else {
        return (None, None);
    };
    let hash = raw.trim().to_string();
    if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return (None, None);
    }
    (Some(verity.to_string_lossy().into_owned()), Some(hash))
}

/// Build the cmdline fragment consumed by `mvm-verity-init`
/// (the PID 1 in the verity initramfs). Pure function for unit
/// testing — `None` is returned when verity is disabled (no
/// `roothash`). When the three runtime-overlay fields are also
/// present, the fragment includes the `mvm.runtime_*` knobs the
/// init binary reads to set up the second dm-verity target and
/// bind-mount it at `/sysroot/mvm/runtime`.
pub fn build_verity_cmdline_args(
    roothash: Option<&str>,
    overlay_roothash: Option<&str>,
) -> Option<String> {
    let h = roothash?;
    let base = format!("mvm.roothash={h} mvm.data=/dev/vda mvm.hash=/dev/vdb");
    match overlay_roothash {
        Some(oh) => Some(format!(
            "{base} mvm.runtime_roothash={oh} mvm.runtime_data=/dev/vdc mvm.runtime_hash=/dev/vdd"
        )),
        None => Some(base),
    }
}

/// Build the runtime-overlay cmdline fragment for Firecracker workload boots.
///
/// Verity-root boots use the fixed `/dev/vdc` + `/dev/vdd` runtime pair that
/// `mvm-verity-init` consumes. Injected OCI non-verity boots instead mount a
/// plain read-only overlay ext4 from `/dev/vdb` in their `/init`, so they only
/// need the data-device token.
pub fn build_runtime_overlay_cmdline_args(
    rootfs_roothash: Option<&str>,
    overlay_present: bool,
) -> Option<String> {
    if !overlay_present {
        return None;
    }
    match rootfs_roothash {
        Some(_) => Some("mvm.runtime_data=/dev/vdc mvm.runtime_hash=/dev/vdd".to_string()),
        None => Some("mvm.runtime_data=/dev/vdb".to_string()),
    }
}

/// Whether this boot attached the universal initramfs (as opposed to a
/// legacy per-rootfs verity initramfs or no initramfs at all).  The CLI
/// resolves the artifact out of the shared initramfs cache, so the path
/// itself is the discriminant — a cold-cache legacy boot keeps its
/// `rootfs.initrd` sibling and is never sent `ActivateEnvironment`.
pub fn booted_with_universal_initramfs(config: &mvm_core::vm_backend::VmStartConfig) -> bool {
    let Some(initrd) = &config.initrd_path else {
        return false;
    };
    let cache_root = std::path::PathBuf::from(mvm_core::config::mvm_cache_dir()).join("initramfs");
    std::path::Path::new(initrd).starts_with(&cache_root)
}

/// The runtime-overlay ext4 to attach as a plain read-only virtio-blk device
/// on a NON-verity workload boot, or `None` to attach nothing.
///
/// A sealed (verity) boot instead attaches the dm-verity overlay pair that the
/// universal initramfs sets up, so this is only consulted on the non-verity
/// branch of each backend. Attach whenever the resolved overlay triple is
/// present — including on the virtiofs-root shape, which reaches its guest
/// binaries the same way every other shape does now that the overlay is the
/// single runtime source. Returned to the backends that assign the overlay the
/// next free `/dev/vdN` after the rootfs — always `/dev/vdb` on the non-verity
/// branch, matching [`build_runtime_overlay_cmdline_args`]`(None, true)`.
pub fn non_verity_overlay_ext4(config: &mvm_core::vm_backend::VmStartConfig) -> Option<&str> {
    // The three overlay fields are populated together; require the full triple
    // so a half-populated config can't attach a device the guest can't
    // corroborate against the cmdline token.
    if config.runtime_overlay_verity_path.is_none() || config.runtime_overlay_roothash.is_none() {
        return None;
    }
    config.runtime_overlay_path.as_deref()
}

// ── Firecracker per-device API PUT body builders ─────────────────────────────
//
// One scalar-parameterized builder per device body, shared by the raw flake
// path (the `configure_*` functions below) and the converged NIC-less driver.
// A field change to any body now lands in exactly one place instead of drifting
// between two copies. The `api_put_socket` call stays per-caller; only the
// body-string construction is shared.

/// Firecracker `/logger` PUT body. `log_dir` is the per-VM directory whose
/// `firecracker.log` the VMM writes.
pub fn logger_body(log_dir: &str) -> String {
    format!(
        r#"{{"log_path": "{log_dir}/firecracker.log", "level": "Debug", "show_level": true, "show_log_origin": true}}"#,
    )
}

/// Firecracker `/machine-config` PUT body: vCPU count and memory size.
pub fn machine_config_body(vcpus: u32, mem_mib: u32) -> String {
    format!(r#"{{"vcpu_count": {vcpus}, "mem_size_mib": {mem_mib}}}"#)
}

/// Firecracker `/boot-source` PUT body. The `initrd_path` field is emitted only
/// when an initramfs is present, matching the two shapes the API accepts (an
/// initramfs boot owns root mounting; a plain boot lets the kernel mount vda).
pub fn boot_source_body(
    kernel_image_path: &str,
    boot_args: &str,
    initrd_path: Option<&str>,
) -> String {
    match initrd_path {
        Some(initrd) => format!(
            r#"{{"kernel_image_path": "{kernel_image_path}", "boot_args": "{boot_args}", "initrd_path": "{initrd}"}}"#,
        ),
        None => {
            format!(r#"{{"kernel_image_path": "{kernel_image_path}", "boot_args": "{boot_args}"}}"#,)
        }
    }
}

/// Firecracker `/drives/<id>` PUT body. Firecracker assigns guest device letters
/// in API-call order, so the caller owns the ordering; this only shapes one
/// drive's JSON.
pub fn drive_body(
    drive_id: &str,
    path_on_host: &str,
    is_root_device: bool,
    is_read_only: bool,
) -> String {
    format!(
        r#"{{"drive_id": "{drive_id}", "path_on_host": "{path_on_host}", "is_root_device": {is_root_device}, "is_read_only": {is_read_only}}}"#,
    )
}

/// Firecracker `/vsock` PUT body: the single vsock device (`vsock0`) with the
/// guest CID and the host-side UDS the mux binds.
pub fn vsock_body(guest_cid: u32, uds_path: &str) -> String {
    format!(r#"{{"vsock_id": "vsock0", "guest_cid": {guest_cid}, "uds_path": "{uds_path}"}}"#)
}

/// Firecracker `/balloon` PUT body. `deflate_on_oom` is always on so the device
/// yields pages back under guest memory pressure instead of letting the guest
/// OOM-kill the workload while the host still has memory to give.
pub fn balloon_body(amount_mib: u32) -> String {
    format!(
        r#"{{"amount_mib": {amount_mib}, "deflate_on_oom": true, "stats_polling_interval_s": 1}}"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------
    // Firecracker API body builders — byte-identical pins
    //
    // These lock each shared body builder to the exact JSON the raw flake path
    // emitted inline before the extraction, so the driver and the raw path can
    // never silently diverge and the raw (Linux production default) path stays
    // byte-for-byte unchanged.
    // ------------------------------------------------------------------

    #[test]
    fn logger_body_pins_the_exact_json() {
        let legacy = format!(
            r#"{{"log_path": "{dir}/firecracker.log", "level": "Debug", "show_level": true, "show_log_origin": true}}"#,
            dir = "/vms/w",
        );
        assert_eq!(logger_body("/vms/w"), legacy);
        assert_eq!(
            logger_body("/vms/w"),
            r#"{"log_path": "/vms/w/firecracker.log", "level": "Debug", "show_level": true, "show_log_origin": true}"#,
        );
    }

    #[test]
    fn machine_config_body_pins_the_exact_json() {
        let legacy = format!(
            r#"{{"vcpu_count": {cpus}, "mem_size_mib": {mem}}}"#,
            cpus = 2,
            mem = 1024,
        );
        assert_eq!(machine_config_body(2, 1024), legacy);
        assert_eq!(
            machine_config_body(2, 1024),
            r#"{"vcpu_count": 2, "mem_size_mib": 1024}"#,
        );
    }

    #[test]
    fn boot_source_body_pins_both_shapes() {
        // No initramfs: kernel + boot_args only.
        let legacy_plain = format!(
            r#"{{"kernel_image_path": "{kernel}", "boot_args": "{args}"}}"#,
            kernel = "/img/vmlinux",
            args = "console=ttyS0",
        );
        assert_eq!(
            boot_source_body("/img/vmlinux", "console=ttyS0", None),
            legacy_plain,
        );
        assert_eq!(
            boot_source_body("/img/vmlinux", "console=ttyS0", None),
            r#"{"kernel_image_path": "/img/vmlinux", "boot_args": "console=ttyS0"}"#,
        );

        // With initramfs: the initrd_path field is appended.
        let legacy_initrd = format!(
            r#"{{"kernel_image_path": "{kernel}", "boot_args": "{args}", "initrd_path": "{initrd}"}}"#,
            kernel = "/img/vmlinux",
            args = "console=ttyS0",
            initrd = "/img/initrd.cpio",
        );
        assert_eq!(
            boot_source_body("/img/vmlinux", "console=ttyS0", Some("/img/initrd.cpio")),
            legacy_initrd,
        );
        assert_eq!(
            boot_source_body("/img/vmlinux", "console=ttyS0", Some("/img/initrd.cpio")),
            r#"{"kernel_image_path": "/img/vmlinux", "boot_args": "console=ttyS0", "initrd_path": "/img/initrd.cpio"}"#,
        );
    }

    #[test]
    fn drive_body_pins_root_and_non_root_shapes() {
        // Root device, read-write (the plain-rootfs unverified boot).
        let legacy_root = format!(
            r#"{{"drive_id": "rootfs", "path_on_host": "{rootfs}", "is_root_device": true, "is_read_only": {ro}}}"#,
            rootfs = "/k/rootfs.ext4",
            ro = false,
        );
        assert_eq!(
            drive_body("rootfs", "/k/rootfs.ext4", true, false),
            legacy_root,
        );
        assert_eq!(
            drive_body("rootfs", "/k/rootfs.ext4", true, false),
            r#"{"drive_id": "rootfs", "path_on_host": "/k/rootfs.ext4", "is_root_device": true, "is_read_only": false}"#,
        );

        // Non-root read-only sidecar (verity/overlay/config/secrets shape).
        let legacy_sidecar = format!(
            r#"{{"drive_id": "verity", "path_on_host": "{path}", "is_root_device": false, "is_read_only": true}}"#,
            path = "/k/rootfs.verity",
        );
        assert_eq!(
            drive_body("verity", "/k/rootfs.verity", false, true),
            legacy_sidecar,
        );
    }

    #[test]
    fn vsock_body_pins_the_exact_json() {
        let legacy = format!(
            r#"{{"vsock_id": "vsock0", "guest_cid": {cid}, "uds_path": "{vsock}"}}"#,
            cid = mvm_agentd::vsock::GUEST_CID,
            vsock = "/vms/w/runtime/v.sock",
        );
        assert_eq!(
            vsock_body(mvm_agentd::vsock::GUEST_CID, "/vms/w/runtime/v.sock"),
            legacy,
        );
    }

    #[test]
    fn balloon_body_pins_the_exact_json() {
        let legacy = format!(
            r#"{{"amount_mib": {amount}, "deflate_on_oom": true, "stats_polling_interval_s": 1}}"#,
            amount = 384,
        );
        assert_eq!(balloon_body(384), legacy);
        assert_eq!(
            balloon_body(384),
            r#"{"amount_mib": 384, "deflate_on_oom": true, "stats_polling_interval_s": 1}"#,
        );
    }

    // ------------------------------------------------------------------
    // verity cmdline + runtime-overlay attachment
    // ------------------------------------------------------------------

    /// 64-char lowercase hex used wherever a roothash is needed.
    /// Two distinct values so cmdline tests can prove the rootfs
    /// hash and the overlay hash flow through the right knobs.
    const ROOTFS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000001";
    const OVERLAY_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000002";

    #[test]
    fn build_verity_cmdline_args_none_without_roothash() {
        assert_eq!(build_verity_cmdline_args(None, None), None);
        // Overlay hash alone without rootfs verity does not synthesize verity
        // knobs; non-verity OCI boots use the separate runtime-data token path.
        assert_eq!(
            build_verity_cmdline_args(None, Some(OVERLAY_HASH)),
            None,
            "overlay-only input should not produce verity cmdline knobs"
        );
    }

    #[test]
    fn build_verity_cmdline_args_rootfs_only_matches_legacy_shape() {
        let got =
            build_verity_cmdline_args(Some(ROOTFS_HASH), None).expect("rootfs verity → cmdline");
        assert_eq!(
            got,
            format!("mvm.roothash={ROOTFS_HASH} mvm.data=/dev/vda mvm.hash=/dev/vdb"),
        );
        assert!(!got.contains("runtime_"));
    }

    #[test]
    fn build_verity_cmdline_args_with_overlay_appends_runtime_knobs() {
        let got = build_verity_cmdline_args(Some(ROOTFS_HASH), Some(OVERLAY_HASH))
            .expect("rootfs + overlay verity → cmdline");
        // Rootfs knobs come first, overlay knobs append at the end —
        // mvm-verity-init parses tokens left-to-right and only the
        // last assignment wins for a duplicate key, so order is
        // load-bearing if rootfs/overlay were ever to share a key.
        // The runtime keys are distinct names today, but pinning
        // the order keeps the contract obvious.
        assert!(got.starts_with(&format!("mvm.roothash={ROOTFS_HASH} ")));
        assert!(got.contains(&format!("mvm.runtime_roothash={OVERLAY_HASH}")));
        assert!(got.contains("mvm.runtime_data=/dev/vdc"));
        assert!(got.contains("mvm.runtime_hash=/dev/vdd"));
    }

    #[test]
    fn build_runtime_overlay_cmdline_args_none_without_overlay() {
        assert_eq!(build_runtime_overlay_cmdline_args(None, false), None);
        assert_eq!(
            build_runtime_overlay_cmdline_args(Some(ROOTFS_HASH), false),
            None
        );
    }

    #[test]
    fn build_runtime_overlay_cmdline_args_uses_verity_shape_when_rootfs_is_verified() {
        assert_eq!(
            build_runtime_overlay_cmdline_args(Some(ROOTFS_HASH), true).as_deref(),
            Some("mvm.runtime_data=/dev/vdc mvm.runtime_hash=/dev/vdd")
        );
    }

    #[test]
    fn build_runtime_overlay_cmdline_args_uses_non_verity_oci_shape() {
        assert_eq!(
            build_runtime_overlay_cmdline_args(None, true).as_deref(),
            Some("mvm.runtime_data=/dev/vdb")
        );
    }

    #[test]
    fn non_verity_overlay_ext4_requires_the_full_triple() {
        use mvm_core::vm_backend::VmStartConfig;

        // Bare rootfs, no overlay resolved → nothing to attach.
        let bare = VmStartConfig::default();
        assert_eq!(non_verity_overlay_ext4(&bare), None);

        // Full triple → attach the ext4.
        let resolved = VmStartConfig {
            runtime_overlay_path: Some("/cache/runtime.ext4".into()),
            runtime_overlay_verity_path: Some("/cache/runtime.verity".into()),
            runtime_overlay_roothash: Some("b".repeat(64)),
            ..Default::default()
        };
        assert_eq!(
            non_verity_overlay_ext4(&resolved),
            Some("/cache/runtime.ext4")
        );

        // A half-populated triple must not attach a device the guest can't
        // corroborate against the cmdline token.
        let partial = VmStartConfig {
            runtime_overlay_path: Some("/cache/runtime.ext4".into()),
            ..Default::default()
        };
        assert_eq!(non_verity_overlay_ext4(&partial), None);
    }

    /// With the overlay as the single runtime source there is no baked copy of
    /// the guest binaries to fall back to, so a boot that declares no rootfs
    /// verity still has to carry the overlay device.
    #[test]
    fn a_non_verity_boot_still_attaches_the_runtime_overlay() {
        use mvm_core::vm_backend::VmStartConfig;

        let cfg = VmStartConfig {
            runtime_overlay_path: Some("/cache/runtime.ext4".into()),
            runtime_overlay_verity_path: Some("/cache/runtime.verity".into()),
            runtime_overlay_roothash: Some("b".repeat(64)),
            ..Default::default()
        };
        assert_eq!(
            non_verity_overlay_ext4(&cfg),
            Some("/cache/runtime.ext4"),
            "there are no baked guest binaries left to fall back to"
        );
    }

    #[test]
    fn probe_verity_sidecar_reads_host_sidecars() {
        // The rootfs and its dm-verity sidecars are host files the VMM
        // attaches as block devices, so the probe must read the host
        // filesystem — never shell into a builder/dev VM. Regression guard
        // for the stale nested-model probe that reached into the dev VM and
        // so (a) missed real host sidecars and (b) auto-started a heavyweight
        // dev VM on any interactive `machine run --image`.
        let dir = tempfile::tempdir().unwrap();
        let rootfs = dir.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"data").unwrap();
        std::fs::write(dir.path().join("rootfs.verity"), b"hash-tree").unwrap();
        std::fs::write(
            dir.path().join("rootfs.roothash"),
            format!("{ROOTFS_HASH}\n"),
        )
        .unwrap();

        let (verity, roothash) = probe_verity_sidecar(rootfs.to_str().unwrap());
        assert_eq!(
            verity.as_deref(),
            Some(dir.path().join("rootfs.verity").to_str().unwrap()),
        );
        assert_eq!(roothash.as_deref(), Some(ROOTFS_HASH));
    }

    #[test]
    fn probe_verity_sidecar_none_without_sidecars() {
        // A non-sealed rootfs (e.g. an unpacked OCI image) has no sidecars;
        // the probe falls back to unverified boot without touching any VM.
        let dir = tempfile::tempdir().unwrap();
        let rootfs = dir.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"data").unwrap();
        assert_eq!(probe_verity_sidecar(rootfs.to_str().unwrap()), (None, None));
    }

    #[test]
    fn probe_verity_sidecar_rejects_malformed_roothash() {
        // A present-but-garbage roothash must fail closed to unverified
        // boot rather than feed a bogus hash into the kernel cmdline.
        let dir = tempfile::tempdir().unwrap();
        let rootfs = dir.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"data").unwrap();
        std::fs::write(dir.path().join("rootfs.verity"), b"hash-tree").unwrap();
        std::fs::write(dir.path().join("rootfs.roothash"), b"not-a-hex-roothash").unwrap();
        assert_eq!(probe_verity_sidecar(rootfs.to_str().unwrap()), (None, None));
    }
}
