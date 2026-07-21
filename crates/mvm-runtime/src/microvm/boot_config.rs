//! dm-verity/runtime-overlay cmdline helpers and the Firecracker API
//! sequence that configures a flake-built microVM's boot source, machine
//! config, drives, network, vsock, and balloon.

use anyhow::{Context, Result};
use tracing::instrument;

use crate::base::config::BRIDGE_IP;
use crate::base::ui;

use super::daemon::{api_put_socket, prepare_vsock_runtime_dir};
use super::egress_bridge::{
    egress_ca_cmdline_token, require_grant_cmdline_token, secret_env_cmdline_token,
    verb_grant_cmdline_token,
};
use super::firecracker_vsock_uds_path;
use super::flake_run::{FlakeRunConfig, create_dev_config_drive, create_dev_secrets_drive};

/// Probe the directory containing `rootfs_path` for the dm-verity sidecar
/// files emitted by mkGuest when `verifiedBoot = true`. The rootfs and its
/// sidecars are host files the VMM attaches as block devices, so the probe
/// reads the host filesystem directly — it must not shell into a builder/dev
/// VM, which both missed the real host sidecars and woke a heavyweight VM on
/// every run. Returns `(Some(verity_path), Some(roothash))` when both files
/// are present and the roothash decodes to a 64-char hex string; otherwise
/// `(None, None)` so callers fall back to the unverified-boot path.
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

/// The runtime-overlay ext4 to attach as a plain read-only virtio-blk device
/// on a NON-verity workload boot, or `None` to attach nothing.
///
/// A sealed (verity) boot instead attaches the dm-verity overlay pair that the
/// verity initramfs sets up, so this is only consulted on the non-verity
/// branch of each backend. The gate mirrors the firecracker path: attach only
/// when the resolved overlay triple is present and the boot is not rootfs-only
/// (the virtiofs-root shape carries no block overlay). Returned to the
/// backends that assign the overlay the next free `/dev/vdN` after the rootfs
/// — always `/dev/vdb` on the non-verity branch, matching
/// [`build_runtime_overlay_cmdline_args`]`(None, true)`.
pub fn non_verity_overlay_ext4(config: &mvm_core::vm_backend::VmStartConfig) -> Option<&str> {
    if config.runtime_source_policy == mvm_core::vm_backend::RuntimeSourcePolicy::RootfsOnly {
        return None;
    }
    // The three overlay fields are populated together; require the full triple
    // so a half-populated config can't attach a device the guest can't
    // corroborate against the cmdline token.
    if config.runtime_overlay_verity_path.is_none() || config.runtime_overlay_roothash.is_none() {
        return None;
    }
    config.runtime_overlay_path.as_deref()
}

/// Resolve whether the runtime-overlay drives should be attached
/// alongside the rootfs verity sidecar. Returns the
/// `(overlay_ext4_path, overlay_verity_sidecar_path,
/// overlay_roothash)` triple only when all three are present —
/// any missing field disables the overlay attachment so a
/// half-configured workload boots through the legacy
/// rootfs-verity-only path instead of failing with a partial
/// drive map.
pub fn resolved_runtime_overlay(config: &FlakeRunConfig) -> Option<(&str, &str, &str)> {
    Some((
        config.runtime_overlay_path.as_deref()?,
        config.runtime_overlay_verity_path.as_deref()?,
        config.runtime_overlay_roothash.as_deref()?,
    ))
}

/// Resolve the initrd to attach for a flake boot, enforcing the dm-verity
/// fail-closed invariant.
///
/// A caller-supplied stage-1 initrd wins over the verity initramfs at
/// `<rootfs_dir>/rootfs.initrd` (the two never co-exist in practice). When
/// verity is requested — a `roothash` is set — but neither an initrd is
/// available, refuse to boot: without the verity initramfs the kernel would
/// silently mount `/dev/vda` directly, dropping dm-verity and booting an
/// unsealed root. That must fail closed, not fall through to an unverified
/// boot.
fn resolve_effective_initrd(config: &FlakeRunConfig) -> Result<Option<String>> {
    // Convention from the flake: the verity initrd lives at
    // `<rev_dir>/rootfs.initrd`, alongside `rootfs.{ext4,verity,roothash}`.
    // Only derived when both the verity sidecar and roothash are present.
    let verity_initrd_path = config
        .verity_path
        .as_deref()
        .zip(config.roothash.as_deref())
        .and_then(|_| {
            std::path::Path::new(&config.rootfs_path)
                .parent()
                .map(|p| format!("{}/rootfs.initrd", p.display()))
        })
        .filter(|p| std::path::Path::new(p).exists());

    let effective_initrd = config.initrd_path.clone().or(verity_initrd_path);

    if config.roothash.is_some() && effective_initrd.is_none() {
        anyhow::bail!("verity roothash present but no verity initramfs; refusing to boot unsealed");
    }
    Ok(effective_initrd)
}

/// Configure a flake-built microVM via the Firecracker API (multi-VM).
#[instrument(skip_all, fields(name = %config.name))]
pub fn configure_flake_microvm(config: &FlakeRunConfig, abs_dir: &str, socket: &str) -> Result<()> {
    configure_flake_microvm_with_drives_dir(config, abs_dir, socket, abs_dir)
}

/// Configure a flake-built microVM with custom config/secrets drive location.
/// This allows template snapshots to use template-relative drive paths.
/// The vsock socket is also placed in drives_dir for snapshot portability.
#[instrument(skip_all, fields(name = %config.name))]
pub fn configure_flake_microvm_with_drives_dir(
    config: &FlakeRunConfig,
    abs_dir: &str,
    socket: &str,
    drives_dir: &str,
) -> Result<()> {
    configure_logger(socket, abs_dir)?;
    // Verity-root workloads rely on `mvm-verity-init` to mount the runtime
    // overlay. Injected OCI `/init` is different: it can mount a plain
    // read-only overlay ext4 itself even when the rootfs is not verity-backed.
    // Resolve the overlay unconditionally so both boot shapes keep the same
    // attach contract. Shared by the boot-source cmdline tokens and the
    // drives block below — resolved once, since it's the same triple.
    let overlay = resolved_runtime_overlay(config);
    configure_boot_source(socket, config, overlay)?;
    configure_machine(socket, config)?;
    configure_drives(socket, config, drives_dir, overlay)?;
    configure_network(socket, config)?;
    configure_vsock(socket, drives_dir)?;
    configure_balloon(socket, config)?;
    Ok(())
}

/// Configure the Firecracker logger sink (`/logger`).
fn configure_logger(socket: &str, abs_dir: &str) -> Result<()> {
    ui::info("Configuring logger...");
    api_put_socket(
        socket,
        "/logger",
        &format!(
            r#"{{"log_path": "{dir}/firecracker.log", "level": "Debug", "show_level": true, "show_log_origin": true}}"#,
            dir = abs_dir,
        ),
    )
}

/// Configure the Firecracker boot source (`/boot-source`): kernel image
/// path, initrd, and the full kernel cmdline — guest IP/gateway, dm-verity
/// roothash, runtime-overlay tokens, egress CA, secret placeholders, and
/// verb-grant sidecars.
fn configure_boot_source(
    socket: &str,
    config: &FlakeRunConfig,
    overlay: Option<(&str, &str, &str)>,
) -> Result<()> {
    let slot = &config.slot;

    // Boot args: pass guest IP and gateway via kernel cmdline.
    // When initrd is present (NixOS guest or verity initrd), the initrd
    // handles root mounting. When absent (minimal guest, no verity),
    // the kernel mounts /dev/vda directly.
    let base_args = format!(
        "console=ttyS0 reboot=k panic=1 net.ifnames=0 mvm.ip={ip}/24 mvm.gw={gw}",
        ip = slot.guest_ip,
        gw = BRIDGE_IP,
    );

    // dm-verity boot path: when verity is on, the kernel
    // mounts the verity initramfs first, which is `mvm-verity-init`
    // (PID 1) — that binary reads `mvm.roothash=…` from the cmdline,
    // builds the verity device-mapper target via raw ioctls, mounts
    // /dev/mapper/root, and switch_root's to /sysroot/init.
    //
    // We deliberately do NOT add `root=/dev/dm-0` here: Firecracker on
    // aarch64 unconditionally appends `root=/dev/vda ro` after our
    // boot_args, and the kernel uses last-wins for `root=`. By owning
    // the pivot in userspace via the initramfs, the kernel's `root=`
    // setting becomes irrelevant — `mvm-verity-init` chooses the real
    // root explicitly via `mount` + `switch_root`.
    // Resolve the initrd, enforcing the fail-closed verity invariant: a
    // roothash-requested boot with no verity initramfs must error rather than
    // silently mount /dev/vda unsealed.
    let effective_initrd = resolve_effective_initrd(config)?;
    let verity_args: Option<String> =
        build_verity_cmdline_args(config.roothash.as_deref(), overlay.map(|(_, _, h)| h));
    let runtime_overlay_args =
        if config.runtime_source_policy != mvm_core::vm_backend::RuntimeSourcePolicy::RootfsOnly {
            build_runtime_overlay_cmdline_args(config.roothash.as_deref(), overlay.is_some())
        } else {
            None
        };

    let boot_args = if effective_initrd.is_some() {
        // initrd owns root mounting. Verity adds the cmdline knobs the
        // initramfs reads to construct /dev/mapper/root.
        match &verity_args {
            Some(extra) => format!("{base_args} {extra}"),
            None => base_args,
        }
    } else {
        format!("root=/dev/vda rw rootwait init=/init {base_args}")
    };

    // A fresh FC boot attaches no secrets drive, so the per-VM
    // egress intermediate cert reaches the sealed guest via the kernel cmdline.
    // `mvmctl up` staged it in `egress-intermediate.json`; `/init` decodes the
    // `mvm.egress_ca=` token into the guest trust bundle (cert only — the key
    // stays host-side in the terminator endpoint).
    let boot_args = match egress_ca_cmdline_token(&config.slot.name) {
        Some(token) => format!("{boot_args} {token}"),
        None => boot_args,
    };
    // The substitution endpoint spawned pre-boot minted the
    // workload's placeholders and wrote them to
    // `vm_substitution_env_path`. Carry them on the cmdline (`mvm.secret_env=`)
    // so `/init` exports `$VAR=placeholder` into a sealed entrypoint (placeholders
    // only, never values). Absent ⇒ no secrets / no endpoint.
    let boot_args = match secret_env_cmdline_token(&config.slot.name) {
        Some(token) => format!("{boot_args} {token}"),
        None => boot_args,
    };
    let boot_args = match verb_grant_cmdline_token(&config.slot.name) {
        Some(token) => format!("{boot_args} {token}"),
        None => boot_args,
    };
    let boot_args = match require_grant_cmdline_token(&config.slot.name) {
        Some(token) => format!("{boot_args} {token}"),
        None => boot_args,
    };
    let boot_args = match runtime_overlay_args {
        Some(token) => format!("{boot_args} {token}"),
        None => boot_args,
    };
    let boot_args = format!(
        "{boot_args} {}",
        mvm_core::vm_backend::encode_runtime_source_policy_cmdline(config.runtime_source_policy)
    );

    // FC's x86_64 loader needs an uncompressed ELF `vmlinux`, but the
    // published default-microvm x86_64 kernel is a bzImage (named `vmlinux`),
    // which FC rejects with "Invalid Elf magic number". Extract the embedded ELF
    // to a cached sibling once and boot from that. No-op for an already-ELF
    // kernel (aarch64 `Image`, or a fixed image).
    let kernel_for_boot =
        mvm_build::fc_kernel::ensure_fc_loadable_kernel(std::path::Path::new(&config.vmlinux_path))
            .with_context(|| {
                format!("preparing FC-loadable kernel from {}", config.vmlinux_path)
            })?;
    let kernel_for_boot = kernel_for_boot.display();

    ui::info(&format!("Setting boot source: {kernel_for_boot}"));
    let boot_source = match &effective_initrd {
        Some(initrd) => {
            ui::info(&format!("Using initrd: {}", initrd));
            format!(
                r#"{{"kernel_image_path": "{kernel}", "boot_args": "{args}", "initrd_path": "{initrd}"}}"#,
                kernel = kernel_for_boot,
                args = boot_args,
                initrd = initrd,
            )
        }
        None => {
            format!(
                r#"{{"kernel_image_path": "{kernel}", "boot_args": "{args}"}}"#,
                kernel = kernel_for_boot,
                args = boot_args,
            )
        }
    };
    api_put_socket(socket, "/boot-source", &boot_source)
}

/// Configure the Firecracker machine (`/machine-config`): vCPU count and
/// memory size.
fn configure_machine(socket: &str, config: &FlakeRunConfig) -> Result<()> {
    ui::info(&format!(
        "Setting machine config: {} vCPUs, {} MiB",
        config.cpus, config.memory
    ));
    api_put_socket(
        socket,
        "/machine-config",
        &format!(
            r#"{{"vcpu_count": {cpus}, "mem_size_mib": {mem}}}"#,
            cpus = config.cpus,
            mem = config.memory,
        ),
    )
}

/// Configure every Firecracker block device: rootfs, the dm-verity
/// sidecars, the runtime overlay pair, the config/secrets drives, and any
/// extra `--volume` mounts. Firecracker assigns drive letters in API-call
/// order, so this sequence — and each drive's conditional inclusion — is
/// load-bearing for dm-verity correctness and must not be reordered.
fn configure_drives(
    socket: &str,
    config: &FlakeRunConfig,
    drives_dir: &str,
    overlay: Option<(&str, &str, &str)>,
) -> Result<()> {
    // Verity-on means the rootfs is read-only and re-mounted via
    // /dev/dm-0; opening a writable handle would let any host process
    // mutate the bytes the Merkle tree was built against and silently
    // break the integrity check.
    let rootfs_read_only = config.verity_path.is_some();
    ui::info(&format!("Setting rootfs: {}", config.rootfs_path));
    api_put_socket(
        socket,
        "/drives/rootfs",
        &format!(
            r#"{{"drive_id": "rootfs", "path_on_host": "{rootfs}", "is_root_device": true, "is_read_only": {ro}}}"#,
            rootfs = config.rootfs_path,
            ro = rootfs_read_only,
        ),
    )?;

    // dm-verity Merkle tree → /dev/vdb. Firecracker assigns drive
    // letters in API-call order, so this PUT must precede the config /
    // secrets drives below. Always mounted read-only — modifying the
    // hash tree would break verity at the next read.
    if let Some(verity_path) = &config.verity_path {
        ui::info(&format!("Attaching dm-verity sidecar: {}", verity_path));
        api_put_socket(
            socket,
            "/drives/verity",
            &format!(
                r#"{{"drive_id": "verity", "path_on_host": "{path}", "is_root_device": false, "is_read_only": true}}"#,
                path = verity_path,
            ),
        )?;
    }

    // Runtime overlay:
    // - verity-root workloads attach ext4 + verity sidecar as `/dev/vdc` +
    //   `/dev/vdd` for `mvm-verity-init`.
    // - injected OCI non-verity boots attach only the ext4 as `/dev/vdb`; the
    //   injected `/init` mounts it read-only from `mvm.runtime_data=/dev/vdb`.
    // The data drive is always read-only.
    if let Some((overlay_path, overlay_verity_path, _)) = overlay {
        ui::info(&format!("Attaching runtime overlay ext4: {}", overlay_path));
        api_put_socket(
            socket,
            "/drives/runtime_overlay",
            &format!(
                r#"{{"drive_id": "runtime_overlay", "path_on_host": "{path}", "is_root_device": false, "is_read_only": true}}"#,
                path = overlay_path,
            ),
        )?;
        if config.roothash.is_some() {
            ui::info(&format!(
                "Attaching runtime overlay verity sidecar: {}",
                overlay_verity_path
            ));
            api_put_socket(
                socket,
                "/drives/runtime_verity",
                &format!(
                    r#"{{"drive_id": "runtime_verity", "path_on_host": "{path}", "is_root_device": false, "is_read_only": true}}"#,
                    path = overlay_verity_path,
                ),
            )?;
        }
    }

    // Create and attach mvm-config drive (config.json + role.toml)
    ui::info("Creating config drive...");
    let config_drive = create_dev_config_drive(drives_dir, config)?;
    api_put_socket(
        socket,
        "/drives/config",
        &format!(
            r#"{{"drive_id": "config", "path_on_host": "{path}", "is_root_device": false, "is_read_only": true}}"#,
            path = config_drive,
        ),
    )?;

    // Attach the mvm-secrets drive ONLY when there is something to put on it.
    // The workload guest never mounts this drive — `/init` reads the egress CA
    // cert and the secret PLACEHOLDERS from the kernel cmdline (`mvm.egress_ca=`
    // / `mvm.secret_env=`), and raw secrets never enter the guest (they are
    // substituted at egress, claim 13). So for the common no-secret-binding
    // workload the drive carries only a stub `{}` and is dead weight; skip the
    // `mkfs` + attach entirely. It is still built when `secret_files` is
    // non-empty (an explicit `--volume <host>:/mnt/secrets` share).
    if !config.secret_files.is_empty() {
        ui::info("Creating secrets drive...");
        let secrets_drive = create_dev_secrets_drive(drives_dir, &config.secret_files)?;
        api_put_socket(
            socket,
            "/drives/secrets",
            &format!(
                r#"{{"drive_id": "secrets", "path_on_host": "{path}", "is_root_device": false, "is_read_only": true}}"#,
                path = secrets_drive,
            ),
        )?;
    }

    for (idx, vol) in config.volumes.iter().enumerate() {
        let drive_id = format!("vol{}", idx);
        let mode = if vol.read_only { "ro" } else { "rw" };
        ui::info(&format!(
            "Attaching volume {} -> {} (size {}, {mode})",
            vol.host, vol.guest, vol.size
        ));
        api_put_socket(
            socket,
            &format!("/drives/{}", drive_id),
            &format!(
                r#"{{"drive_id": "{id}", "path_on_host": "{host}", "is_root_device": false, "is_read_only": {ro}}}"#,
                id = drive_id,
                host = vol.host,
                ro = vol.read_only,
            ),
        )?;
    }

    Ok(())
}

/// Configure the Firecracker network interface (`/network-interfaces/net1`).
fn configure_network(socket: &str, config: &FlakeRunConfig) -> Result<()> {
    let slot = &config.slot;
    ui::info(&format!(
        "Setting network interface: {} (MAC {})",
        slot.tap_dev, slot.mac
    ));
    api_put_socket(
        socket,
        "/network-interfaces/net1",
        &format!(
            r#"{{"iface_id": "net1", "guest_mac": "{mac}", "host_dev_name": "{tap}"}}"#,
            mac = slot.mac,
            tap = slot.tap_dev,
        ),
    )
}

/// Configure the Firecracker vsock device (`/vsock`).
fn configure_vsock(socket: &str, drives_dir: &str) -> Result<()> {
    ui::info("Setting vsock device...");
    prepare_vsock_runtime_dir(drives_dir);
    let vsock = firecracker_vsock_uds_path(drives_dir);
    api_put_socket(
        socket,
        "/vsock",
        &format!(
            r#"{{"vsock_id": "vsock0", "guest_cid": {cid}, "uds_path": "{vsock}"}}"#,
            cid = mvm_agentd::vsock::GUEST_CID,
            vsock = vsock,
        ),
    )
}

/// Configure the Firecracker virtio-balloon device (`/balloon`), only when
/// the workload opted in via `mem_initial`. The device boots pre-inflated to
/// `memory - mem_initial` MiB so the host commits only `mem_initial` MiB
/// until the reclaim controller deflates the balloon.
///
/// `deflate_on_oom = true` is mandatory: under guest memory pressure the
/// device must yield pages back, otherwise the guest OOM-kills the workload
/// while the host still has memory it could give back.
/// `stats_polling_interval_s = 1` lets the host controller poll real guest
/// commitment without driving the guest's stat refresh too aggressively.
fn configure_balloon(socket: &str, config: &FlakeRunConfig) -> Result<()> {
    if let Some(initial) = config.mem_initial {
        let amount_mib = config.memory.saturating_sub(initial);
        ui::info(&format!(
            "Attaching virtio-balloon (cap {} MiB, initial commit {} MiB, balloon {} MiB)",
            config.memory, initial, amount_mib
        ));
        api_put_socket(
            socket,
            "/balloon",
            &format!(
                r#"{{"amount_mib": {amount}, "deflate_on_oom": true, "stats_polling_interval_s": 1}}"#,
                amount = amount_mib,
            ),
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::config::VmSlot;

    fn baseline_run_config(mem_initial: Option<u32>) -> FlakeRunConfig {
        FlakeRunConfig {
            name: "v".to_string(),
            slot: VmSlot::new("v", 0),
            vmlinux_path: "/k/vmlinux".to_string(),
            initrd_path: None,
            rootfs_path: "/k/rootfs.ext4".to_string(),
            verity_path: None,
            roothash: None,
            runtime_overlay_path: None,
            runtime_overlay_verity_path: None,
            runtime_overlay_roothash: None,
            runtime_source_policy: mvm_core::vm_backend::RuntimeSourcePolicy::PreferOverlay,
            revision_hash: "abc".to_string(),
            flake_ref: "/p".to_string(),
            profile: None,
            cpus: 2,
            memory: 1024,
            mem_initial,
            volumes: Vec::new(),
            config_files: Vec::new(),
            secret_files: Vec::new(),
            ports: Vec::new(),
            network_policy: mvm_core::network_policy::NetworkPolicy::default(),
            network_tunnel: None,
        }
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
    fn non_verity_overlay_ext4_requires_full_triple_and_non_rootfs_only() {
        use mvm_core::vm_backend::{RuntimeSourcePolicy, VmStartConfig};

        // Bare rootfs, no overlay resolved → nothing to attach.
        let bare = VmStartConfig {
            runtime_source_policy: RuntimeSourcePolicy::PreferOverlay,
            ..Default::default()
        };
        assert_eq!(non_verity_overlay_ext4(&bare), None);

        // Full triple + a non-rootfs-only policy → attach the ext4.
        let resolved = VmStartConfig {
            runtime_overlay_path: Some("/cache/runtime.ext4".into()),
            runtime_overlay_verity_path: Some("/cache/runtime.verity".into()),
            runtime_overlay_roothash: Some("b".repeat(64)),
            runtime_source_policy: RuntimeSourcePolicy::PreferOverlay,
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
            runtime_source_policy: RuntimeSourcePolicy::PreferOverlay,
            ..Default::default()
        };
        assert_eq!(non_verity_overlay_ext4(&partial), None);

        // Rootfs-only (the virtiofs-root shape) never attaches a block overlay.
        let rootfs_only = VmStartConfig {
            runtime_source_policy: RuntimeSourcePolicy::RootfsOnly,
            ..resolved.clone()
        };
        assert_eq!(non_verity_overlay_ext4(&rootfs_only), None);
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

    #[test]
    fn resolve_effective_initrd_fails_closed_when_verity_requested_without_initramfs() {
        // A roothash means dm-verity was requested. With no verity
        // initramfs present (and no caller-supplied stage-1), booting would
        // silently mount /dev/vda unsealed — the claim-3 hole. Refuse.
        let dir = tempfile::tempdir().unwrap();
        let rootfs = dir.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"data").unwrap();
        std::fs::write(dir.path().join("rootfs.verity"), b"hash-tree").unwrap();
        // Deliberately do NOT write rootfs.initrd.

        let mut cfg = baseline_run_config(None);
        cfg.rootfs_path = rootfs.to_string_lossy().into_owned();
        cfg.verity_path = Some(
            dir.path()
                .join("rootfs.verity")
                .to_string_lossy()
                .into_owned(),
        );
        cfg.roothash = Some(ROOTFS_HASH.into());

        let err = resolve_effective_initrd(&cfg).expect_err("must fail closed");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("refusing to boot unsealed"),
            "unexpected error message: {msg}"
        );
    }

    #[test]
    fn resolve_effective_initrd_proceeds_when_verity_initramfs_present() {
        // Roothash + the sibling rootfs.initrd present ⇒ the verity boot
        // path is complete, so resolution yields that initrd.
        let dir = tempfile::tempdir().unwrap();
        let rootfs = dir.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"data").unwrap();
        std::fs::write(dir.path().join("rootfs.verity"), b"hash-tree").unwrap();
        let initrd = dir.path().join("rootfs.initrd");
        std::fs::write(&initrd, b"initramfs").unwrap();

        let mut cfg = baseline_run_config(None);
        cfg.rootfs_path = rootfs.to_string_lossy().into_owned();
        cfg.verity_path = Some(
            dir.path()
                .join("rootfs.verity")
                .to_string_lossy()
                .into_owned(),
        );
        cfg.roothash = Some(ROOTFS_HASH.into());

        let got = resolve_effective_initrd(&cfg).expect("verity boot path is complete");
        assert_eq!(got.as_deref(), Some(initrd.to_str().unwrap()));
    }

    #[test]
    fn resolve_effective_initrd_proceeds_with_caller_supplied_initrd() {
        // A caller-supplied stage-1 initrd satisfies the invariant even when
        // no sibling rootfs.initrd exists, and takes precedence.
        let dir = tempfile::tempdir().unwrap();
        let rootfs = dir.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"data").unwrap();

        let mut cfg = baseline_run_config(None);
        cfg.rootfs_path = rootfs.to_string_lossy().into_owned();
        cfg.roothash = Some(ROOTFS_HASH.into());
        cfg.initrd_path = Some("/k/stage1.initrd".into());

        let got = resolve_effective_initrd(&cfg).expect("caller initrd satisfies the guard");
        assert_eq!(got.as_deref(), Some("/k/stage1.initrd"));
    }

    #[test]
    fn resolve_effective_initrd_unsealed_boot_unaffected() {
        // No roothash ⇒ verity is not requested. The guard must not fire;
        // a plain unsealed rootfs boots with no initrd (kernel mounts vda).
        let cfg = baseline_run_config(None);
        assert!(cfg.roothash.is_none());
        let got = resolve_effective_initrd(&cfg).expect("plain unsealed boot proceeds");
        assert_eq!(got, None);
    }

    #[test]
    fn resolved_runtime_overlay_requires_all_three_fields() {
        let mut cfg = baseline_run_config(None);
        cfg.roothash = Some(ROOTFS_HASH.into());
        // All three None ⇒ no overlay.
        assert!(resolved_runtime_overlay(&cfg).is_none());

        // Only path set ⇒ no overlay.
        cfg.runtime_overlay_path = Some("/k/rootfs.runtime.ext4".into());
        assert!(resolved_runtime_overlay(&cfg).is_none());

        // Path + verity sidecar set, hash missing ⇒ no overlay.
        cfg.runtime_overlay_verity_path = Some("/k/rootfs.runtime.verity".into());
        assert!(resolved_runtime_overlay(&cfg).is_none());

        // All three present ⇒ Some.
        cfg.runtime_overlay_roothash = Some(OVERLAY_HASH.into());
        let (p, vp, h) = resolved_runtime_overlay(&cfg).expect("complete triple resolves");
        assert_eq!(p, "/k/rootfs.runtime.ext4");
        assert_eq!(vp, "/k/rootfs.runtime.verity");
        assert_eq!(h, OVERLAY_HASH);
    }

    #[test]
    fn resolved_runtime_overlay_can_feed_non_verity_oci_mount_path() {
        let mut cfg = baseline_run_config(None);
        cfg.roothash = None; // verity off
        cfg.runtime_overlay_path = Some("/k/rootfs.runtime.ext4".into());
        cfg.runtime_overlay_verity_path = Some("/k/rootfs.runtime.verity".into());
        cfg.runtime_overlay_roothash = Some(OVERLAY_HASH.into());
        assert!(resolved_runtime_overlay(&cfg).is_some());
        assert_eq!(build_verity_cmdline_args(None, Some(OVERLAY_HASH)), None);
        assert_eq!(
            build_runtime_overlay_cmdline_args(None, true).as_deref(),
            Some("mvm.runtime_data=/dev/vdb")
        );
    }

    // ──── Verity ──────────────────────────────────────────────────────
    //
    // The host-side cmdline shape and DM-table construction now live in
    // `mvm-verity-init` (initramfs PID 1). The unit tests below cover the
    // host-side helper still running on the cold-boot path: the sidecar probe.

    #[test]
    fn probe_verity_sidecar_returns_none_for_path_without_parent() {
        let (v, h) = probe_verity_sidecar("rootfs.ext4");
        assert!(v.is_none());
        assert!(h.is_none());
    }

    #[test]
    fn probe_verity_sidecar_reads_valid_host_sidecars() {
        let dir = tempfile::tempdir().expect("tempdir");
        let rootfs = dir.path().join("rootfs.ext4");
        let verity = dir.path().join("rootfs.verity");
        std::fs::write(&rootfs, b"rootfs").expect("write rootfs");
        std::fs::write(&verity, b"verity").expect("write verity");
        std::fs::write(
            dir.path().join("rootfs.roothash"),
            format!("{ROOTFS_HASH}\n"),
        )
        .expect("write roothash");

        let (v, h) = probe_verity_sidecar(&rootfs.to_string_lossy());

        assert_eq!(v.as_deref(), Some(verity.to_string_lossy().as_ref()));
        assert_eq!(h.as_deref(), Some(ROOTFS_HASH));
    }

    #[test]
    fn probe_verity_sidecar_returns_none_when_sidecar_missing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let rootfs = dir.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"rootfs").expect("write rootfs");
        std::fs::write(
            dir.path().join("rootfs.roothash"),
            format!("{ROOTFS_HASH}\n"),
        )
        .expect("write roothash");

        let (v, h) = probe_verity_sidecar(&rootfs.to_string_lossy());

        assert!(v.is_none());
        assert!(h.is_none());
    }

    #[test]
    fn probe_verity_sidecar_returns_none_for_malformed_roothash() {
        let dir = tempfile::tempdir().expect("tempdir");
        let rootfs = dir.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"rootfs").expect("write rootfs");
        std::fs::write(dir.path().join("rootfs.verity"), b"verity").expect("write verity");
        std::fs::write(dir.path().join("rootfs.roothash"), b"abc\n").expect("write roothash");

        let (v, h) = probe_verity_sidecar(&rootfs.to_string_lossy());

        assert!(v.is_none());
        assert!(h.is_none());
    }
}
