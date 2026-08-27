//! Workload kernel-cmdline assembly.
//!
//! Every guest kernel-cmdline security token — dm-verity roothash, plan-bound
//! verb grant + enforcement assertion + host-signer trust anchor, the in-guest
//! vsock egress client, and the runtime-source
//! policy / overlay knobs — is strung together here, once, so the raw HVF
//! backend and `WorkloadRunner::start` boot with the identical cmdline. Pure
//! string assembly (cfg-free) so it stays unit-testable with no hypervisor.
//!
//! One token is deliberately NOT in that shared list: `mvm.uvols=`, the
//! user-volume mount manifest. The raw HVF backend calls `workload_cmdline`
//! too, but its `hvf_workload_disks` never attaches `config.volumes` as block
//! devices — so a `mvm.uvols=` token emitted from inside `workload_cmdline`
//! would reach the guest describing disks that were never attached. Only the
//! runner attaches volume disks (`spec_map::workload_blocks`), so only the
//! runner appends the token, via `runner_cmdline` below.

use std::path::{Path, PathBuf};

use mvm_core::vm_backend::VmStartConfig;

#[cfg(test)]
use crate::host::boot_config::booted_with_universal_initramfs;
use crate::host::boot_config::non_verity_overlay_ext4;
use crate::host::egress_bridge::{
    host_signer_pub_cmdline_token, require_grant_cmdline_token, verb_grant_cmdline_token,
};

/// Bytes the guest kernel reserves for its command line (`COMMAND_LINE_SIZE`,
/// 2048 on both x86_64 and arm64), including the trailing NUL.
const KERNEL_CMDLINE_LIMIT: usize = 2048;

/// `Some(reason)` when `cmdline` would not reach the guest intact.
///
/// The kernel copies at most `COMMAND_LINE_SIZE` bytes and drops the rest
/// without a diagnostic. Truncation takes whatever was appended last, and the
/// tokens appended last here are the security-bearing ones — the verb grant,
/// its enforcement assertion, the host-signer trust anchor, the egress knob. A
/// guest can therefore come up silently missing its trust anchor or its egress
/// policy, and the only visible symptom is an unrelated-looking readiness
/// timeout. Callers refuse the boot instead.
pub fn cmdline_overflow(cmdline: &str) -> Option<String> {
    (cmdline.len() + 1 > KERNEL_CMDLINE_LIMIT).then(|| {
        format!(
            "assembled kernel cmdline is {} bytes, past the guest kernel's \
             {KERNEL_CMDLINE_LIMIT}-byte command line; the kernel would truncate it \
             and silently drop the trailing security tokens",
            cmdline.len()
        )
    })
}

/// Kernel cmdline token that turns on the authenticated in-guest vsock client.
pub fn vsock_egress_cmdline_token(config: &VmStartConfig, _state_dir: &Path) -> Option<String> {
    crate::host::egress_shared::effective_vsock_egress(config)
        .then(|| "mvm.vsock_egress=1".to_string())
}

/// Kernel cmdline token that gives the guest the workload's machine name.
///
/// The name crosses a whitespace-delimited boundary, so validate it again at
/// the encoding seam even though normal machine creation already validates it.
/// A malformed internal launch config must not be able to inject another
/// kernel argument.
pub fn hostname_cmdline_token(machine_name: &str) -> Option<String> {
    mvm_core::naming::validate_vm_name(machine_name)
        .is_ok()
        .then(|| format!("mvm.hostname={machine_name}"))
}

/// The initramfs this boot uses: the explicit `--initrd` override, or the
/// universal initramfs path attached by the runtime source resolver.
pub fn effective_initrd(config: &VmStartConfig) -> Option<PathBuf> {
    config.initrd_path.as_ref().map(PathBuf::from)
}

/// Whether this boot has everything dm-verity needs: a verity sidecar, a
/// roothash, and a resolvable initramfs to run the verification logic.
pub fn verity_enabled(config: &VmStartConfig) -> bool {
    config.verity_path.is_some() && config.roothash.is_some() && effective_initrd(config).is_some()
}

/// The resolved runtime-overlay artifact triple, when the launch config
/// carries all three parts.
pub fn runtime_overlay(config: &VmStartConfig) -> Option<(&str, &str, &str)> {
    Some((
        config.runtime_overlay_path.as_deref()?,
        config.runtime_overlay_verity_path.as_deref()?,
        config.runtime_overlay_roothash.as_deref()?,
    ))
}

/// The `mvm.runtime_data=` token for a non-verity boot, naming the device the
/// runtime overlay was *actually* attached to.
///
/// Derived from [`workload_blocks`] rather than assumed, because the two
/// disagreed: the layout appends the rootfs dm-verity sidecar whenever
/// `verity_path` is set, but this branch runs whenever verity is *disabled* —
/// and verity is disabled by a missing initramfs, not by a missing sidecar. An
/// OCI image built with verified boot but launched without an initramfs
/// therefore had its Merkle tree at `/dev/vdb` while the hardcoded token still
/// said the overlay was there. Reading the slot off the layout cannot drift.
///
/// [`workload_blocks`]: crate::host::spec_map::workload_blocks
fn build_runtime_overlay_cmdline_args_for_layout(config: &VmStartConfig) -> Option<String> {
    let overlay = non_verity_overlay_ext4(config)?;
    let overlay_path = Path::new(overlay);
    let device = crate::host::spec_map::workload_blocks(config)
        .iter()
        .find(|block| block.source == overlay_path)
        .map(crate::driver::spec::BlockDev::device_node)?;
    Some(format!("mvm.runtime_data={device}"))
}

/// Assemble the workload kernel cmdline for `config`, or `None` when no extra
/// tokens are needed (the driver then falls back to its own default base
/// cmdline).
///
/// `base_bootargs` supplies the VMM-specific console/earlycon/root base
/// (`VmmDriver::workload_base_bootargs` for a runner driver, or
/// `hvf_like_workload_bootargs` directly for the raw HVF
/// backend, which has no driver to call through) — every other token here is
/// shared across VMMs.
pub fn workload_cmdline(
    config: &VmStartConfig,
    state_dir: &Path,
    base_bootargs: impl Fn(bool, bool) -> String,
) -> Option<String> {
    workload_cmdline_for_hostname(config, state_dir, base_bootargs, Some(&config.name))
}

fn workload_cmdline_for_hostname(
    config: &VmStartConfig,
    state_dir: &Path,
    base_bootargs: impl Fn(bool, bool) -> String,
    guest_hostname: Option<&str>,
) -> Option<String> {
    let egress = vsock_egress_cmdline_token(config, state_dir);
    let hostname = guest_hostname.and_then(hostname_cmdline_token);
    let grants: Vec<String> = [
        verb_grant_cmdline_token(&config.name),
        require_grant_cmdline_token(&config.name),
        host_signer_pub_cmdline_token(&config.name),
    ]
    .into_iter()
    .flatten()
    .collect();
    let virtiofs_root = config.virtiofs_root.is_some();
    let has_disk = !virtiofs_root && !config.rootfs_path.is_empty();
    let verity_is_enabled = verity_enabled(config);
    if egress.is_none() && hostname.is_none() && grants.is_empty() && !verity_is_enabled {
        // Nothing mvm-specific to say and no initramfs boot: let the driver
        // fall back to its own default base cmdline. (This used to also require
        // a rootfs-only runtime-source policy; with the overlay as the single
        // source that conjunct was always true and said nothing.)
        return None;
    }
    let mut cmdline = if verity_is_enabled {
        // A verity/initramfs boot: the initramfs PID 1 owns root/init selection,
        // so the base carries only the VMM-specific console (has_disk=false).
        // Route through the driver seam — libkrun needs `console=hvc0`, HVF the
        // pl011 UART — instead of hardcoding one VMM's console onto every guest.
        base_bootargs(virtiofs_root, false)
    } else {
        base_bootargs(virtiofs_root, has_disk)
    };
    // The universal initramfs receives the rootfs and runtime-overlay
    // roothashes/device paths over vsock via `ActivateEnvironment` after boot, so
    // its cmdline carries none of them. The legacy per-rootfs verity initramfs
    // is no longer supported.
    // Non-verity boots carry the runtime overlay as a plain read-only block
    // device; emit the token naming the device it actually landed on.
    if !verity_is_enabled
        && has_disk
        && let Some(overlay_args) = build_runtime_overlay_cmdline_args_for_layout(config)
    {
        cmdline.push(' ');
        cmdline.push_str(&overlay_args);
    }
    for token in hostname.into_iter().chain(egress).chain(grants) {
        cmdline.push(' ');
        cmdline.push_str(&token);
    }
    Some(cmdline)
}

/// The runner's full cmdline: the shared `workload_cmdline` base plus, only
/// on this path, the `mvm.uvols=` user-volume token (see the module doc for
/// why it can't live inside `workload_cmdline` itself).
///
/// `workload_cmdline` returns `None` as a shortcut meaning "no extra tokens
/// needed — let the driver apply its own built-in default base cmdline". A
/// volume token can't ride on that shortcut (an empty `VmmSpec.cmdline` means
/// "ignore this string entirely"), so when a volume is present and the
/// shortcut would otherwise apply, this synthesizes the same base bootargs
/// `workload_cmdline`'s non-shortcut branch would have produced (via the same
/// `base_bootargs` closure) and appends the token to that instead of to
/// nothing.
pub fn runner_cmdline(
    config: &VmStartConfig,
    state_dir: &Path,
    base_bootargs: impl Fn(bool, bool) -> String,
) -> String {
    runner_cmdline_for_hostname(config, state_dir, base_bootargs, Some(&config.name))
}

/// Assemble a factory parent's cmdline without binding it to the parent's
/// temporary internal name. A restored child receives its own hostname over
/// the post-restore identity handshake.
pub fn runner_cmdline_without_hostname(
    config: &VmStartConfig,
    state_dir: &Path,
    base_bootargs: impl Fn(bool, bool) -> String,
) -> String {
    runner_cmdline_for_hostname(config, state_dir, base_bootargs, None)
}

fn runner_cmdline_for_hostname(
    config: &VmStartConfig,
    state_dir: &Path,
    base_bootargs: impl Fn(bool, bool) -> String,
    guest_hostname: Option<&str>,
) -> String {
    let base = workload_cmdline_for_hostname(config, state_dir, &base_bootargs, guest_hostname);
    let mut tokens: Vec<String> = Vec::new();
    if !config.rootfs_path.is_empty() || config.virtiofs_root.is_some() {
        // HVF/libkrun workload guests have no RTC. Seed their wall clock before
        // image processes perform TLS validation (for example, pip contacting
        // PyPI), using the same host epoch captured at boot time as the builder.
        tokens.push(crate::host::boot_config::builder_hostepoch_cmdline_token());
    }
    let user_volumes = config
        .volumes
        .iter()
        .filter(|volume| !super::spec_map::is_sdk_sidecar_volume(volume))
        .cloned()
        .collect::<Vec<_>>();
    if let Some(uvols) = mvm_core::vm_backend::encode_user_volumes_cmdline(&user_volumes) {
        tokens.push(uvols);
    }
    // Tell the guest which device the SDK sidecar landed on. The guest can't
    // derive the slot itself — it shifts with verity, the runtime overlay, and
    // any preceding user volumes — so the host names it, exactly as it already
    // does for the runtime overlay's `mvm.runtime_data=` device.
    if let Some(dev) = super::spec_map::sdk_sidecar_block_device(config) {
        tokens.push(format!("mvm.sdk_dev={dev}"));
    }
    if tokens.is_empty() {
        return base.unwrap_or_default();
    }
    let extra = tokens.join(" ");
    match base {
        Some(base) => format!("{base} {extra}"),
        None => {
            let virtiofs_root = config.virtiofs_root.is_some();
            let has_disk = !virtiofs_root && !config.rootfs_path.is_empty();
            format!("{} {extra}", base_bootargs(virtiofs_root, has_disk))
        }
    }
}

/// Materialize an initramfs inside the shared initramfs cache that
/// [`booted_with_universal_initramfs`] recognizes, and return its
/// path. `home` must already be the active `MVM_HOME`. Shared by the boot-shape
/// tests here and in [`crate::workload_runner::standby_boot`], which both need a
/// launch config that resolves as a universal-initramfs boot.
#[cfg(any(test, feature = "test-support"))]
pub fn seed_universal_initramfs(home: &Path) -> String {
    let dir = PathBuf::from(mvm_core::config::mvm_cache_dir()).join("initramfs");
    assert!(
        dir.starts_with(home),
        "test must isolate MVM_HOME before seeding the initramfs cache"
    );
    std::fs::create_dir_all(&dir).expect("create initramfs cache dir");
    let image = dir.join("initramfs.cpio.gz");
    std::fs::write(&image, b"initramfs").expect("write initramfs");
    image.display().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// HVF-like base bootargs for tests (pl011 UART console). Keeps the
    /// cmdline tests independent of the HVF backend module.
    fn hvf_like_workload_bootargs(virtiofs_root: bool, has_disk: bool) -> String {
        const UART_BASE: u64 = 0x9000000; // matches fdt::SERIAL_MMIO_BASE historically
        let mut args =
            format!("earlycon=pl011,0x{UART_BASE:x} console=ttyAMA0 panic=-1 nokaslr loglevel=8");
        if virtiofs_root {
            args.push_str(" rootfstype=virtiofs root=mvmroot rw init=/init");
        } else if has_disk {
            args.push_str(" root=/dev/vda rw init=/init");
        }
        args
    }

    /// A non-verity launch whose image *was* built with verified boot: the
    /// rootfs carries a dm-verity sidecar, but no initramfs resolved, so verity
    /// is disabled and the guest `/init` mounts the overlay from the
    /// `mvm.runtime_data=` token.
    fn sidecar_bearing_non_verity_config() -> VmStartConfig {
        VmStartConfig {
            name: "w".to_string(),
            kernel_path: Some("/cache/vmlinux".to_string()),
            rootfs_path: "/cache/oci/rootfs.ext4".to_string(),
            verity_path: Some("/cache/oci/rootfs.verity".to_string()),
            roothash: Some("a".repeat(64)),
            // No initrd: this is what makes verity *disabled* despite the
            // sidecar being present, and it is the exact shape a cold
            // initramfs cache produced.
            initrd_path: None,
            runtime_overlay_path: Some("/cache/runtime-overlay/overlay.ext4".to_string()),
            runtime_overlay_verity_path: Some("/cache/runtime-overlay/overlay.verity".to_string()),
            runtime_overlay_roothash: Some("b".repeat(64)),
            ..Default::default()
        }
    }

    #[test]
    fn runtime_data_token_names_the_device_the_overlay_actually_landed_on() {
        // The regression: the token was hardcoded to /dev/vdb on every
        // non-verity boot, but `workload_blocks` appends the rootfs dm-verity
        // sidecar whenever `verity_path` is set — which is independent of
        // whether verity is *enabled*. So on an image built with verified boot
        // but launched without an initramfs, /dev/vdb was the rootfs Merkle
        // tree and the overlay was one slot further along at /dev/vdc.
        let config = sidecar_bearing_non_verity_config();
        assert!(
            !verity_enabled(&config),
            "no initrd means verity is disabled, which is what selects this branch"
        );

        let token = build_runtime_overlay_cmdline_args_for_layout(&config)
            .expect("a resolved overlay triple yields a token");

        let blocks = crate::host::spec_map::workload_blocks(&config);
        let overlay_device = blocks
            .iter()
            .find(|b| b.source == Path::new("/cache/runtime-overlay/overlay.ext4"))
            .map(crate::driver::spec::BlockDev::device_node)
            .expect("the overlay is in the attached layout");

        assert_eq!(token, format!("mvm.runtime_data={overlay_device}"));
        assert_eq!(
            token, "mvm.runtime_data=/dev/vdc",
            "rootfs=vda, rootfs verity sidecar=vdb, overlay=vdc"
        );
        assert_ne!(
            token, "mvm.runtime_data=/dev/vdb",
            "vdb is the rootfs Merkle tree on this shape, not the overlay"
        );
    }

    #[test]
    fn runtime_data_token_is_vdb_when_no_verity_sidecar_is_attached() {
        // The plain OCI shape: no sidecar, so the overlay really is the second
        // disk. The layout-derived token must agree with the old hardcoded
        // answer here, or the fix would have moved a working case.
        let mut config = sidecar_bearing_non_verity_config();
        config.verity_path = None;
        config.roothash = None;

        assert_eq!(
            build_runtime_overlay_cmdline_args_for_layout(&config).as_deref(),
            Some("mvm.runtime_data=/dev/vdb"),
        );
    }

    #[test]
    fn assembled_cmdline_carries_the_layout_derived_runtime_device() {
        // End of the seam: the token the guest actually receives.
        let config = sidecar_bearing_non_verity_config();
        let state = std::path::PathBuf::from("/tmp/nonexistent-state");
        let cmdline = workload_cmdline(&config, &state, hvf_like_workload_bootargs)
            .expect("a required-overlay boot always emits tokens");

        assert!(
            cmdline.contains("mvm.runtime_data=/dev/vdc"),
            "assembled cmdline must point at the overlay's real slot: {cmdline}"
        );
        assert!(
            !cmdline.contains("mvm.runtime_data=/dev/vdb"),
            "must not point at the rootfs Merkle tree: {cmdline}"
        );
    }

    #[test]
    fn no_runtime_data_token_without_a_resolved_overlay() {
        let mut config = sidecar_bearing_non_verity_config();
        config.runtime_overlay_path = None;
        config.runtime_overlay_verity_path = None;
        config.runtime_overlay_roothash = None;
        assert_eq!(build_runtime_overlay_cmdline_args_for_layout(&config), None);
    }

    #[test]
    fn cmdline_within_the_kernel_limit_is_accepted() {
        assert_eq!(cmdline_overflow("console=ttyS0 root=/dev/vda"), None);
        // Exactly fills the buffer alongside its NUL.
        assert_eq!(
            cmdline_overflow(&"a".repeat(KERNEL_CMDLINE_LIMIT - 1)),
            None
        );
    }

    #[test]
    fn cmdline_past_the_kernel_limit_is_refused() {
        // One byte more than the buffer can hold with its NUL.
        let over = "a".repeat(KERNEL_CMDLINE_LIMIT);
        let reason = cmdline_overflow(&over).expect("oversized cmdline must be refused");
        assert!(
            reason.contains(&KERNEL_CMDLINE_LIMIT.to_string()),
            "{reason}"
        );
        assert!(reason.contains(&over.len().to_string()), "{reason}");
    }

    #[test]
    pub fn vsock_egress_cmdline_token_for_ingress_under_deny_all() {
        let dir = tempfile::tempdir().unwrap();
        let deny_all = VmStartConfig::default();
        assert_eq!(vsock_egress_cmdline_token(&deny_all, dir.path()), None);

        let mut plan = mvm_core::plan::test_support::PlanFixture::new().build();
        plan.ingress.push(
            mvm_core::plan::IngressMapping::builder()
                .mapping_id(1)
                .protocol(mvm_core::plan::IngressProtocol::Tcp)
                .host_addr("127.0.0.1")
                .host_port(8080)
                .guest_addr("127.0.0.1")
                .guest_port(8080)
                .transform(mvm_core::plan::IngressTransform::Opaque)
                .build()
                .expect("valid ingress fixture"),
        );
        let ingress = VmStartConfig {
            plan_json: Some(serde_json::to_string(&plan).expect("serialize ingress fixture")),
            ..Default::default()
        };
        assert_eq!(
            vsock_egress_cmdline_token(&ingress, dir.path()).as_deref(),
            Some("mvm.vsock_egress=1")
        );

        let allow_egress = VmStartConfig {
            network_policy: mvm_core::network_policy::NetworkPolicy::preset(
                mvm_core::network_policy::NetworkPreset::Dev,
            ),
            ..Default::default()
        };
        assert_eq!(
            vsock_egress_cmdline_token(&allow_egress, dir.path()).as_deref(),
            Some("mvm.vsock_egress=1")
        );
    }

    #[test]
    fn workload_cmdline_carries_the_machine_name_as_the_guest_hostname() {
        let dir = tempfile::tempdir().unwrap();
        let config = VmStartConfig {
            name: "build-worker-7".to_string(),
            ..Default::default()
        };

        let cmdline =
            workload_cmdline(&config, dir.path(), hvf_like_workload_bootargs).expect("cmdline");

        assert!(
            cmdline.contains("mvm.hostname=build-worker-7"),
            "all workload backends consume this shared cmdline: {cmdline}"
        );
    }

    #[test]
    fn an_invalid_machine_name_cannot_inject_a_kernel_cmdline_token() {
        assert_eq!(hostname_cmdline_token("worker mvm.vsock_egress=1"), None);
        assert_eq!(hostname_cmdline_token("UPPERCASE"), None);
        assert_eq!(hostname_cmdline_token("-leading"), None);
    }

    #[test]
    fn workload_cmdline_appends_vsock_egress_token_for_virtiofs_root() {
        let dir = tempfile::tempdir().unwrap();

        let config = VmStartConfig {
            virtiofs_root: Some("/tmp/root".to_string()),
            network_policy: mvm_core::network_policy::NetworkPolicy::allow_list(vec![
                mvm_core::network_policy::HostPort::new("example.com", 443),
            ]),
            ..Default::default()
        };
        let cmdline =
            workload_cmdline(&config, dir.path(), hvf_like_workload_bootargs).expect("cmdline");
        assert!(cmdline.contains("rootfstype=virtiofs root=mvmroot"));
        assert!(cmdline.contains("init=/init"));
        assert!(cmdline.contains("mvm.vsock_egress=1"));
    }

    /// A verity boot whose initramfs is the *universal* one (resolved out of the
    /// shared initramfs cache) gets its roothashes and device paths over vsock
    /// via `ActivateEnvironment`, so the kernel cmdline must not carry them.
    #[test]
    fn workload_cmdline_for_universal_initramfs_verity_boot_emits_console_only() {
        let _guard = crate::host::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.set("MVM_HOME", dir.path());
        let rootfs = dir.path().join("rootfs.ext4");
        let verity = dir.path().join("rootfs.verity");
        std::fs::write(&rootfs, b"rootfs").unwrap();
        std::fs::write(&verity, b"verity").unwrap();

        let config = VmStartConfig {
            rootfs_path: rootfs.display().to_string(),
            verity_path: Some(verity.display().to_string()),
            roothash: Some("a".repeat(64)),
            initrd_path: Some(seed_universal_initramfs(dir.path())),
            runtime_overlay_path: Some("/tmp/runtime.ext4".into()),
            runtime_overlay_verity_path: Some("/tmp/runtime.verity".into()),
            runtime_overlay_roothash: Some("b".repeat(64)),
            ..Default::default()
        };
        let cmdline =
            workload_cmdline(&config, dir.path(), hvf_like_workload_bootargs).expect("cmdline");
        assert!(
            booted_with_universal_initramfs(&config),
            "fixture must resolve as a universal-initramfs boot"
        );
        assert!(!cmdline.contains("root=/dev/vda"));
        assert!(!cmdline.contains("init=/init"));
        assert!(!cmdline.contains("mvm.roothash="));
        assert!(!cmdline.contains("mvm.data=/dev/vda"));
        assert!(!cmdline.contains("mvm.hash=/dev/vdb"));
        assert!(!cmdline.contains("mvm.runtime_roothash="));
        assert!(!cmdline.contains("mvm.runtime_data=/dev/vdc"));
        assert!(!cmdline.contains("mvm.runtime_hash=/dev/vdd"));
    }

    #[test]
    fn verity_cmdline_takes_the_console_from_the_driver_seam_not_a_hardcoded_uart() {
        // Isolate MVM_HOME: this seeds an initramfs cache, and it also keeps
        // the host signer out — an un-isolated home leaks a real
        // `mvm.host_signer_pub=` token in and makes the assertions below pass
        // for a reason that has nothing to do with the console.
        let _guard = crate::host::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.set("MVM_HOME", dir.path());
        let rootfs = dir.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"rootfs").unwrap();
        let config = VmStartConfig {
            rootfs_path: rootfs.display().to_string(),
            verity_path: Some(dir.path().join("rootfs.verity").display().to_string()),
            roothash: Some("a".repeat(64)),
            // `verity_enabled` needs an initramfs as well as the sidecar pair:
            // the initramfs is PID 1 on a sealed boot and is what sets the
            // dm-verity target up. Without it this is not a verity boot, the
            // cmdline carries no mvm tokens at all, and the driver's own base
            // is used instead — which is a different function's contract.
            initrd_path: Some(seed_universal_initramfs(dir.path())),
            ..Default::default()
        };
        // libkrun's base: a verity boot (has_disk=false) carries only the
        // console; a disk boot adds root/init.
        let libkrun_base = |_virtiofs: bool, has_disk: bool| {
            if has_disk {
                "console=hvc0 root=/dev/vda rw init=/init".to_string()
            } else {
                "console=hvc0".to_string()
            }
        };
        let cmdline = workload_cmdline(&config, dir.path(), libkrun_base).expect("cmdline");
        assert!(
            cmdline.contains("console=hvc0"),
            "verity cmdline must use the driver console base: {cmdline}"
        );
        assert!(
            !cmdline.contains("ttyAMA0") && !cmdline.contains("earlycon=pl011"),
            "verity cmdline must not hardcode the HVF UART: {cmdline}"
        );
    }

    fn disk_volume(host: &str, guest: &str) -> mvm_core::vm_backend::VmVolume {
        mvm_core::vm_backend::VmVolume {
            host: host.into(),
            guest: guest.into(),
            size: String::new(),
            read_only: true,
            kind: mvm_core::vm_backend::VmVolumeKind::Disk,
            encrypted: false,
        }
    }

    #[test]
    fn runner_cmdline_matches_workload_cmdline_when_no_volumes_are_present() {
        let _guard = crate::host::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.set("MVM_HOME", dir.path());
        let config = VmStartConfig::default();
        assert_eq!(
            runner_cmdline(&config, dir.path(), hvf_like_workload_bootargs),
            workload_cmdline(&config, dir.path(), hvf_like_workload_bootargs).unwrap_or_default()
        );
    }

    #[test]
    fn runner_cmdline_appends_uvols_to_a_non_trivial_base() {
        let _guard = crate::host::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.set("MVM_HOME", dir.path());
        let config = VmStartConfig {
            network_policy: mvm_core::network_policy::NetworkPolicy::preset(
                mvm_core::network_policy::NetworkPreset::Dev,
            ),
            volumes: vec![disk_volume("/vol/data.img", "/data")],
            ..Default::default()
        };
        // The egress token forces workload_cmdline's non-shortcut branch, so
        // this exercises the `Some(base)` arm of runner_cmdline's match.
        let base = workload_cmdline(&config, dir.path(), hvf_like_workload_bootargs)
            .expect("non-trivial base");
        let cmdline = runner_cmdline(&config, dir.path(), hvf_like_workload_bootargs);
        assert!(
            cmdline.starts_with(&base),
            "base: {base}\ncmdline: {cmdline}"
        );
        assert!(
            cmdline.contains("mvm.uvols=uvol0:"),
            "cmdline missing uvols token: {cmdline}"
        );
    }

    #[test]
    fn runner_cmdline_synthesizes_a_base_when_workload_cmdline_takes_the_shortcut() {
        let dir = tempfile::tempdir().unwrap();
        // Isolate MVM_HOME: the host-signer anchor is read from the keys dir, so
        // without this the assertions depend on whether the developer running the
        // suite happens to have a host key on disk.
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.set("MVM_HOME", dir.path());
        let config = VmStartConfig {
            rootfs_path: "/img/rootfs.ext4".into(),
            volumes: vec![disk_volume("/vol/data.img", "/data")],
            ..Default::default()
        };
        // Deny-all + RootfsOnly + no verity/grants: workload_cmdline
        // alone would return None here (the "let the driver default apply"
        // shortcut), so runner_cmdline must not silently drop the base
        // bootargs the volume token needs to ride on.
        assert_eq!(
            workload_cmdline(&config, dir.path(), hvf_like_workload_bootargs),
            None
        );
        let cmdline = runner_cmdline(&config, dir.path(), hvf_like_workload_bootargs);
        assert!(cmdline.contains("root=/dev/vda"), "cmdline: {cmdline}");
        assert!(cmdline.contains("init=/init"), "cmdline: {cmdline}");
        assert!(
            cmdline.contains("mvm.uvols=uvol0:"),
            "cmdline missing uvols token: {cmdline}"
        );
    }

    fn sdk_sidecar_volume(host: &str) -> mvm_core::vm_backend::VmVolume {
        let mut v = disk_volume(host, mvm_core::plan::SDK_SIDECAR_GUEST_PATH);
        v.read_only = true;
        v
    }

    #[test]
    fn runner_cmdline_emits_no_sidecar_token_without_a_sidecar_volume() {
        let dir = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.set("MVM_HOME", dir.path());
        let config = VmStartConfig {
            rootfs_path: "/img/rootfs.ext4".into(),
            volumes: vec![disk_volume("/vol/data.img", "/data")],
            ..Default::default()
        };
        let cmdline = runner_cmdline(&config, dir.path(), hvf_like_workload_bootargs);
        assert!(
            !cmdline.contains("mvm.sdk_dev="),
            "a workload with no SDK sidecar must carry no sidecar token: {cmdline}"
        );
    }

    #[test]
    fn runner_cmdline_names_the_sidecar_device_the_backend_attached() {
        let dir = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.set("MVM_HOME", dir.path());
        let config = VmStartConfig {
            rootfs_path: "/img/rootfs.ext4".into(),
            volumes: vec![
                disk_volume("/vol/data.img", "/data"),
                sdk_sidecar_volume("/cache/sdk.ext4"),
            ],
            ..Default::default()
        };
        let cmdline = runner_cmdline(&config, dir.path(), hvf_like_workload_bootargs);
        // Two disks after the rootfs on an unsealed boot: the user volume takes
        // /dev/vdb, so the sidecar is /dev/vdc. The token must match the block
        // list, not a baked constant.
        let attached = super::super::spec_map::sdk_sidecar_block_device(&config)
            .expect("the sidecar resolves a device");
        assert_eq!(attached, "/dev/vdc");
        assert!(
            cmdline.contains("mvm.sdk_dev=/dev/vdc"),
            "cmdline missing the sidecar device token: {cmdline}"
        );
        // The reserved sidecar is named only by mvm.sdk_dev. It must not also
        // enter the generic user-volume manifest, whose mountpoint policy
        // deliberately excludes /mvm/sdk.
        assert!(
            cmdline.contains("mvm.uvols=uvol0:2f64617461:ro:blk"),
            "cmdline missing the ordinary user volume: {cmdline}"
        );
        assert!(
            !cmdline.contains("2f6d766d2f73646b"),
            "cmdline encoded the SDK sidecar as a user volume: {cmdline}"
        );
        assert_eq!(cmdline_overflow(&cmdline), None);
    }

    #[test]
    fn runner_cmdline_is_empty_when_neither_base_nor_volumes_are_present() {
        let dir = tempfile::tempdir().unwrap();
        // See the note above: an un-isolated MVM_HOME leaks the real host key in
        // as a `mvm.host_signer_pub=` token and this is no longer empty.
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.set("MVM_HOME", dir.path());
        let config = VmStartConfig::default();
        assert_eq!(
            runner_cmdline(&config, dir.path(), hvf_like_workload_bootargs),
            String::new()
        );
    }

    #[test]
    fn runner_cmdline_seeds_the_clock_for_a_rootfs_workload() {
        let dir = tempfile::tempdir().unwrap();
        let config = VmStartConfig {
            rootfs_path: "/img/rootfs.ext4".into(),
            ..Default::default()
        };
        let cmdline = runner_cmdline(&config, dir.path(), hvf_like_workload_bootargs);
        let epoch = cmdline
            .split_whitespace()
            .find_map(|token| token.strip_prefix("mvm.hostepoch="))
            .and_then(|value| value.parse::<u64>().ok())
            .expect("rootfs workload must carry a positive host epoch");
        assert!(epoch > 0);
    }
}
