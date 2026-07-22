//! Workload kernel-cmdline assembly.
//!
//! Every guest kernel-cmdline security token — dm-verity roothash, plan-bound
//! verb grant + enforcement assertion + host-signer trust anchor, the in-guest
//! vsock egress client, the network-tunnel handoff, and the runtime-source
//! policy / overlay knobs — is strung together here, once, so the raw HVF
//! backend and `WorkloadRunner::start` boot with the identical cmdline. Pure
//! string assembly (cfg-free) so it stays unit-testable with no hypervisor.

use std::path::{Path, PathBuf};

use mvm_core::vm_backend::VmStartConfig;

/// Kernel cmdline token that turns on the in-guest vsock egress client.
/// Emitted only when the run actually allows outbound egress and the workload
/// carries no bound secrets, so the raw SOCKS path never contends with the
/// substitution endpoint for the shared egress port.
fn vsock_egress_cmdline_token(config: &VmStartConfig, state_dir: &Path) -> Option<String> {
    (config.network_policy.allows_egress()
        && !crate::egress_shared::state_has_bound_secrets(state_dir).unwrap_or(false))
    .then(|| "mvm.vsock_egress=1".to_string())
}

fn verity_initrd_path(config: &VmStartConfig) -> Option<PathBuf> {
    config
        .verity_path
        .as_deref()
        .zip(config.roothash.as_deref())
        .and_then(|_| {
            Path::new(&config.rootfs_path)
                .parent()
                .map(|p| p.join("rootfs.initrd"))
        })
        .filter(|p| p.exists())
}

/// The initramfs this boot uses: an explicit `--initrd` override, or (for a
/// verity-sealed boot) the sibling `rootfs.initrd` next to the rootfs image.
pub(crate) fn effective_initrd(config: &VmStartConfig) -> Option<PathBuf> {
    config
        .initrd_path
        .as_ref()
        .map(PathBuf::from)
        .or_else(|| verity_initrd_path(config))
}

/// Whether this boot has everything dm-verity needs: a verity sidecar, a
/// roothash, and a resolvable initramfs to run the verification logic.
pub(crate) fn verity_enabled(config: &VmStartConfig) -> bool {
    config.verity_path.is_some() && config.roothash.is_some() && effective_initrd(config).is_some()
}

/// The resolved runtime-overlay artifact triple, when the launch config
/// carries all three parts.
pub(crate) fn runtime_overlay(config: &VmStartConfig) -> Option<(&str, &str, &str)> {
    Some((
        config.runtime_overlay_path.as_deref()?,
        config.runtime_overlay_verity_path.as_deref()?,
        config.runtime_overlay_roothash.as_deref()?,
    ))
}

/// Assemble the workload kernel cmdline for `config`, or `None` when no extra
/// tokens are needed (the driver then falls back to its own default base
/// cmdline).
///
/// The `ttyAMA0` console base lives in `crate::hvf_bootargs` — today's only
/// runner driver. It moves behind a `VmmDriver` base-cmdline hook once a
/// second driver with a different console needs to join the runner.
pub(crate) fn workload_cmdline(config: &VmStartConfig, state_dir: &Path) -> Option<String> {
    let egress = vsock_egress_cmdline_token(config, state_dir);
    // The userspace L3 egress tunnel: tell the guest (via mvm-guest-netinit →
    // mvm-guest-netd) to stand up its TUN and pump packets to the host worker over
    // vsock. Present only for an admitted allow-list run.
    let tunnel = config
        .network_tunnel
        .as_ref()
        .and_then(mvm_core::vm_backend::encode_network_tunnel_cmdline);
    let grants = crate::hvf_bootargs::grant_tokens(&config.name);
    let virtiofs_root = config.virtiofs_root.is_some();
    let has_disk = !virtiofs_root && !config.rootfs_path.is_empty();
    let verity_is_enabled = verity_enabled(config);
    if egress.is_none()
        && tunnel.is_none()
        && grants.is_empty()
        && !verity_is_enabled
        && config.runtime_source_policy == mvm_core::vm_backend::RuntimeSourcePolicy::RootfsOnly
    {
        return None;
    }
    let mut cmdline = if verity_is_enabled {
        crate::hvf_bootargs::default_verity_bootargs()
    } else {
        crate::hvf_bootargs::workload_bootargs(virtiofs_root, has_disk)
    };
    if let Some(verity_args) = crate::microvm::build_verity_cmdline_args(
        config.roothash.as_deref(),
        if verity_is_enabled {
            runtime_overlay(config).map(|(_, _, roothash)| roothash)
        } else {
            None
        },
    ) {
        cmdline.push(' ');
        cmdline.push_str(&verity_args);
    }
    // Non-verity boots carry the runtime overlay as a plain read-only
    // `/dev/vdb` (attached by the backend's disk layout); emit the token its
    // `/init` mounts from. Verity boots already emitted the dm-verity variant
    // above.
    if !verity_is_enabled
        && has_disk
        && let Some(overlay_args) = crate::microvm::build_runtime_overlay_cmdline_args(
            None,
            crate::microvm::non_verity_overlay_ext4(config).is_some(),
        )
    {
        cmdline.push(' ');
        cmdline.push_str(&overlay_args);
    }
    cmdline.push(' ');
    cmdline.push_str(&mvm_core::vm_backend::encode_runtime_source_policy_cmdline(
        config.runtime_source_policy,
    ));
    for token in egress.into_iter().chain(tunnel).chain(grants) {
        cmdline.push(' ');
        cmdline.push_str(&token);
    }
    Some(cmdline)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vsock_egress_cmdline_token_only_when_policy_allows_egress() {
        let dir = tempfile::tempdir().unwrap();
        let deny_all = VmStartConfig::default();
        assert_eq!(vsock_egress_cmdline_token(&deny_all, dir.path()), None);

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
    fn workload_cmdline_appends_vsock_egress_token_for_virtiofs_root() {
        let dir = tempfile::tempdir().unwrap();

        let config = VmStartConfig {
            virtiofs_root: Some("/tmp/root".to_string()),
            network_policy: mvm_core::network_policy::NetworkPolicy::allow_list(vec![
                mvm_core::network_policy::HostPort::new("example.com", 443),
            ]),
            ..Default::default()
        };
        let cmdline = workload_cmdline(&config, dir.path()).expect("cmdline");
        assert!(cmdline.contains("rootfstype=virtiofs root=mvmroot"));
        assert!(cmdline.contains("init=/init"));
        assert!(cmdline.contains("mvm.runtime_source_policy=rootfs_only"));
        assert!(cmdline.contains("mvm.vsock_egress=1"));
    }

    #[test]
    fn workload_cmdline_appends_network_tunnel_token_for_admitted_allowlist() {
        let dir = tempfile::tempdir().unwrap();
        let policy = mvm_core::network_policy::NetworkPolicy::allow_list(vec![
            mvm_core::network_policy::HostPort::new("93.184.216.34", 443),
        ]);
        let tunnel = crate::network_tunnel_spawn::network_tunnel_for_launch(
            &policy,
            crate::network_tunnel_spawn::TunnelLaunchIdentity {
                tenant_id: "acme".to_string(),
                vm_id: "vm-1".to_string(),
                boot_id: "boot-1".to_string(),
                session_nonce: "nonce-1".to_string(),
            },
        )
        .expect("an allow-list launch carries a forwarding tunnel");
        let expected = mvm_core::vm_backend::encode_network_tunnel_cmdline(&tunnel)
            .expect("the tunnel encodes to a cmdline token");

        let config = VmStartConfig {
            virtiofs_root: Some("/tmp/root".to_string()),
            network_policy: policy,
            network_tunnel: Some(tunnel),
            ..Default::default()
        };
        let cmdline = workload_cmdline(&config, dir.path()).expect("cmdline");
        assert!(
            cmdline.contains(&expected),
            "cmdline missing the tunnel token: {cmdline}"
        );
        assert!(cmdline.contains("mvm.network_tunnel="));
        // An allow-list run carrying no bound secrets also turns on the raw vsock
        // egress client, so both tokens coexist on one cmdline (mirrors libkrun).
        assert!(cmdline.contains("mvm.vsock_egress=1"));
    }

    #[test]
    fn workload_cmdline_uses_verity_shape_and_runtime_overlay_tokens() {
        let dir = tempfile::tempdir().unwrap();
        let rootfs = dir.path().join("rootfs.ext4");
        let verity = dir.path().join("rootfs.verity");
        let initrd = dir.path().join("rootfs.initrd");
        std::fs::write(&rootfs, b"rootfs").unwrap();
        std::fs::write(&verity, b"verity").unwrap();
        std::fs::write(&initrd, b"initrd").unwrap();

        let config = VmStartConfig {
            rootfs_path: rootfs.display().to_string(),
            verity_path: Some(verity.display().to_string()),
            roothash: Some("a".repeat(64)),
            runtime_overlay_path: Some("/tmp/runtime.ext4".into()),
            runtime_overlay_verity_path: Some("/tmp/runtime.verity".into()),
            runtime_overlay_roothash: Some("b".repeat(64)),
            runtime_source_policy: mvm_core::vm_backend::RuntimeSourcePolicy::RequiredOverlay,
            ..Default::default()
        };
        let cmdline = workload_cmdline(&config, dir.path()).expect("cmdline");
        assert!(!cmdline.contains("root=/dev/vda"));
        assert!(!cmdline.contains("init=/init"));
        assert!(cmdline.contains("mvm.roothash="));
        assert!(cmdline.contains("mvm.data=/dev/vda"));
        assert!(cmdline.contains("mvm.hash=/dev/vdb"));
        assert!(cmdline.contains("mvm.runtime_roothash="));
        assert!(cmdline.contains("mvm.runtime_data=/dev/vdc"));
        assert!(cmdline.contains("mvm.runtime_hash=/dev/vdd"));
        assert!(cmdline.contains("mvm.runtime_source_policy=required_overlay"));
    }
}
