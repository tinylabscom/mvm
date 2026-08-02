//! PID 1 injected into arbitrary OCI rootfs trees.
//!
//! This binary must not depend on `/bin/sh`, busybox, coreutils, or a distro
//! init system. It is statically linked and baked at `/init` so scratch,
//! distroless, Alpine, Debian, and language-base images all get the same mvm
//! vsock control plane.

#[cfg(target_os = "linux")]
mod linux {
    use mvm_agentd::guest_bootstrap::{
        cmdline, cmdline_has_flag, cmdline_value, cstring_str, ensure_runtime_dirs, hex_decode,
        is_executable, provision_guest_environment, resolve_exec, runtime_source_policy, spawn_one,
    };
    use std::ffi::{CString, OsStr};
    use std::fs;
    use std::os::unix::ffi::OsStrExt;
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    const AGENT_FALLBACK: &str = "/usr/local/bin/mvm-guest-agent";
    const AGENT_OVERLAY: &str = "/mvm/runtime/agent";
    const AGENT_OVERLAY_INTERACTIVE: &str = "/mvm/runtime/agent-interactive";
    const NET_AGENT_FALLBACK: &str = "/usr/local/bin/mvm-net-agent";
    const NET_AGENT_OVERLAY: &str = "/mvm/runtime/net-agent";
    const L3_READY_TIMEOUT: Duration = Duration::from_secs(15);
    pub fn main() {
        mount_pseudofs();
        ensure_runtime_dirs();
        if let Err(error) = mount_user_volumes() {
            eprintln!("mvm-oci-init: user-volume activation failed: {error}");
            std::process::exit(1);
        }
        provision_host_signer_pub();
        if provision_guest_environment().is_err() {
            std::process::exit(1);
        }
        if cmdline_has_flag(mvm_protocol::l3::GUEST_CMDLINE_FLAG) {
            start_l3_tunnel();
        }
        // The guest agent is the mvm vsock control plane — the whole reason this
        // init exists (scratch/distroless/Alpine all get it from the overlay).
        // Fail closed if it can't be resolved: idling on agent-less would leave
        // the host waiting out its agent-readiness timeout on a silently dead VM.
        // PID 1 exiting panics the kernel (panic=-1 -> reboot), so the boot fails
        // loudly instead.
        let Some(agent) = resolve_guest_agent() else {
            eprintln!(
                "mvm-oci-init: no guest agent resolved from /mvm/runtime and no baked \
                 fallback — refusing to boot without the mvm control plane"
            );
            std::process::exit(1);
        };
        spawn_one(&agent, "guest-agent");
        idle_forever();
    }

    fn mount_pseudofs() {
        mount_fs("proc", "/proc", "proc", 0, None);
        mount_fs("sysfs", "/sys", "sysfs", 0, None);
        mount_fs("devtmpfs", "/dev", "devtmpfs", 0, None);
        mount_fs("devpts", "/dev/pts", "devpts", 0, None);
        mount_fs(
            "tmpfs",
            "/run",
            "tmpfs",
            libc::MS_NOSUID | libc::MS_NODEV,
            None,
        );
        mount_fs(
            "tmpfs",
            "/tmp",
            "tmpfs",
            libc::MS_NOSUID | libc::MS_NODEV,
            None,
        );
    }

    fn mount_user_volumes() -> Result<(), String> {
        let Some(encoded) = cmdline_value("mvm.uvols") else {
            return Ok(());
        };
        let mut volumes = parse_user_volumes(&encoded)?;
        let block_count = volumes
            .iter()
            .filter(|volume| volume.kind == mvm_agentd::vsock::VolumeConfigKind::Block)
            .count();
        let mut block_devices = user_block_devices(block_count)?.into_iter();

        for volume in &mut volumes {
            if volume.kind == mvm_agentd::vsock::VolumeConfigKind::Block {
                volume.device = block_devices
                    .next()
                    .map(|device| device.to_string_lossy().into_owned());
            }
        }

        mvm_agentd::guest_mount::mount_volumes(&volumes, Path::new("/"))
            .map_err(|error| error.to_string())
    }

    fn parse_user_volumes(encoded: &str) -> Result<Vec<mvm_agentd::vsock::VolumeConfig>, String> {
        let mut volumes = Vec::new();
        for item in encoded.split(';').filter(|s| !s.is_empty()) {
            let mut parts = item.splitn(4, ':');
            let (Some(tag), Some(path_hex), Some(mode), Some(kind)) =
                (parts.next(), parts.next(), parts.next(), parts.next())
            else {
                return Err("malformed user volume token".to_string());
            };
            let path_bytes = hex_decode(path_hex)
                .ok_or_else(|| "malformed user volume path encoding".to_string())?;
            let mountpoint = String::from_utf8(path_bytes)
                .map_err(|_| "user volume path is not valid UTF-8".to_string())?;
            let read_only = match mode {
                "ro" => true,
                "rw" => false,
                other => return Err(format!("unsupported user volume mode {other:?}")),
            };
            let kind = match kind {
                "fs" => mvm_agentd::vsock::VolumeConfigKind::VirtioFs,
                "blk" => mvm_agentd::vsock::VolumeConfigKind::Block,
                other => return Err(format!("unsupported user volume kind {other:?}")),
            };
            volumes.push(mvm_agentd::vsock::VolumeConfig {
                tag: tag.to_string(),
                mountpoint,
                read_only,
                kind,
                device: None,
            });
        }
        Ok(volumes)
    }

    fn user_block_devices(count: usize) -> Result<Vec<PathBuf>, String> {
        let entries = fs::read_dir("/sys/block")
            .map_err(|error| format!("read /sys/block for user volumes: {error}"))?;
        let mut names = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|error| format!("read /sys/block entry: {error}"))?;
            if let Some(name) = entry.file_name().to_str() {
                names.push(name.to_string());
            }
        }
        trailing_user_block_devices(names, count)
    }

    fn trailing_user_block_devices(
        names: Vec<String>,
        count: usize,
    ) -> Result<Vec<PathBuf>, String> {
        if count == 0 {
            return Ok(Vec::new());
        }
        let mut devices: Vec<String> = names
            .into_iter()
            .filter(|name| {
                let bytes = name.as_bytes();
                bytes.len() == 3 && bytes.starts_with(b"vd") && bytes[2].is_ascii_lowercase()
            })
            .collect();
        devices.sort_unstable();
        if devices.len() < count {
            return Err(format!(
                "expected {count} user block devices, found only {} virtio disks",
                devices.len()
            ));
        }
        Ok(devices
            .split_off(devices.len() - count)
            .into_iter()
            .map(|name| Path::new("/dev").join(name))
            .collect())
    }

    /// Provision the out-of-band host-signer trust anchor delivered on the kernel
    /// cmdline. Block backends copy this key off the config drive; a vsock-only
    /// guest has no config drive, so the launcher rides the 32-byte public key on
    /// `mvm.host_signer_pub=<hex>` and the agent verifies the grant against it.
    fn provision_host_signer_pub() {
        let cmdline = cmdline();
        let Some(hex) = mvm_agentd::vsock::host_signer_pub_token(&cmdline) else {
            return;
        };
        if let Err(e) = mvm_agentd::vsock::write_host_signer_anchor(Path::new("/"), hex) {
            eprintln!("mvm-oci-init: host-signer anchor not provisioned: {e}");
        }
    }

    fn mount_fs(
        source: impl AsRef<OsStr>,
        target: impl AsRef<Path>,
        fstype: &str,
        flags: libc::c_ulong,
        data: Option<&str>,
    ) {
        let source = match cstring_os(source.as_ref()) {
            Some(s) => s,
            None => return,
        };
        let target_path = target.as_ref();
        if let Err(e) = fs::create_dir_all(target_path) {
            eprintln!(
                "mvm-oci-init: mkdir mount target {}: {e}",
                target_path.display()
            );
            return;
        }
        let Some(target) = cstring_os(target_path.as_os_str()) else {
            return;
        };
        let Some(fstype) = cstring_str(fstype) else {
            return;
        };
        let data_c = data.and_then(cstring_str);
        let data_ptr = data_c
            .as_ref()
            .map_or(std::ptr::null(), |s| s.as_ptr().cast::<libc::c_void>());
        let rc = unsafe {
            libc::mount(
                source.as_ptr(),
                target.as_ptr(),
                fstype.as_ptr(),
                flags,
                data_ptr,
            )
        };
        if rc != 0 {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() != Some(libc::EBUSY) {
                eprintln!("mvm-oci-init: mount {}: {e}", target_path.display());
            }
        }
    }

    fn guest_security_profile() -> mvm_core::security::AgentProfile {
        mvm_agentd::builder_agent::load_security_policy()
            .ok()
            .flatten()
            .map(|policy| policy.profile)
            .unwrap_or_else(|| mvm_core::security::SecurityPolicy::dev_defaults().profile)
    }

    fn resolve_guest_agent() -> Option<PathBuf> {
        resolve_guest_agent_for(
            runtime_source_policy(),
            guest_security_profile(),
            is_executable,
        )
    }

    fn resolve_guest_agent_for(
        runtime_source_policy: mvm_core::vm_backend::RuntimeSourcePolicy,
        profile: mvm_core::security::AgentProfile,
        is_exec: impl Fn(&Path) -> bool,
    ) -> Option<PathBuf> {
        let candidates: &[&str] = match (runtime_source_policy, profile) {
            (
                mvm_core::vm_backend::RuntimeSourcePolicy::RequiredOverlay,
                mvm_core::security::AgentProfile::Dev,
            ) => &[AGENT_OVERLAY_INTERACTIVE],
            (
                mvm_core::vm_backend::RuntimeSourcePolicy::RequiredOverlay,
                mvm_core::security::AgentProfile::SealedProd
                | mvm_core::security::AgentProfile::Builder,
            ) => &[AGENT_OVERLAY],
            (
                mvm_core::vm_backend::RuntimeSourcePolicy::PreferOverlay,
                mvm_core::security::AgentProfile::Dev,
            ) => &[AGENT_OVERLAY_INTERACTIVE, AGENT_OVERLAY, AGENT_FALLBACK],
            (
                mvm_core::vm_backend::RuntimeSourcePolicy::PreferOverlay,
                mvm_core::security::AgentProfile::SealedProd
                | mvm_core::security::AgentProfile::Builder,
            ) => &[AGENT_OVERLAY, AGENT_FALLBACK],
            (
                mvm_core::vm_backend::RuntimeSourcePolicy::RootfsOnly,
                mvm_core::security::AgentProfile::Dev
                | mvm_core::security::AgentProfile::SealedProd
                | mvm_core::security::AgentProfile::Builder,
            ) => &[AGENT_FALLBACK],
        };
        candidates
            .iter()
            .map(Path::new)
            .find(|path| is_exec(path))
            .map(Path::to_path_buf)
    }

    fn start_l3_tunnel() {
        let ready = Path::new(mvm_protocol::l3::GUEST_READY_FILE);
        let _ = fs::remove_file(ready);
        let Some(agent) = resolve_exec([NET_AGENT_OVERLAY, NET_AGENT_FALLBACK]) else {
            eprintln!(
                "mvm-oci-init: {} was set but no l3 net agent resolved — refusing to boot",
                mvm_protocol::l3::GUEST_CMDLINE_FLAG
            );
            std::process::exit(1);
        };
        spawn_one(&agent, "net-agent");
        let deadline = std::time::Instant::now() + L3_READY_TIMEOUT;
        while std::time::Instant::now() < deadline {
            if ready.exists() {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        eprintln!(
            "mvm-oci-init: l3 tunnel did not become ready within {L3_READY_TIMEOUT:?} — refusing to boot"
        );
        std::process::exit(1);
    }

    fn idle_forever() -> ! {
        loop {
            std::thread::sleep(Duration::from_secs(2_147_483_647));
        }
    }

    fn cstring_os(s: &OsStr) -> Option<CString> {
        CString::new(s.as_bytes())
            .map_err(|_| eprintln!("mvm-oci-init: path contains NUL"))
            .ok()
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn user_block_devices_are_the_trailing_virtio_disks() {
            let devices = trailing_user_block_devices(
                vec![
                    "loop0".to_string(),
                    "vdc".to_string(),
                    "vda".to_string(),
                    "vdb".to_string(),
                    "nvme0n1".to_string(),
                ],
                2,
            )
            .unwrap();
            assert_eq!(
                devices,
                vec![PathBuf::from("/dev/vdb"), PathBuf::from("/dev/vdc")]
            );
        }

        #[test]
        fn user_block_devices_refuse_an_incomplete_vmm_disk_set() {
            let error = trailing_user_block_devices(vec!["vda".to_string()], 2).unwrap_err();
            assert!(error.contains("expected 2 user block devices"));
        }

        #[test]
        fn user_block_devices_are_empty_when_no_block_volume_was_requested() {
            assert!(
                trailing_user_block_devices(Vec::new(), 0)
                    .unwrap()
                    .is_empty()
            );
        }

        #[test]
        fn user_volume_manifest_decodes_block_and_virtiofs_entries() {
            let volumes =
                parse_user_volumes("uvol0:2f64617461:rw:blk;uvol1:2f726561646f6e6c79:ro:fs")
                    .unwrap();
            assert_eq!(volumes.len(), 2);
            assert_eq!(volumes[0].tag, "uvol0");
            assert_eq!(volumes[0].mountpoint, "/data");
            assert!(!volumes[0].read_only);
            assert_eq!(volumes[0].kind, mvm_agentd::vsock::VolumeConfigKind::Block);
            assert_eq!(volumes[1].mountpoint, "/readonly");
            assert!(volumes[1].read_only);
            assert_eq!(
                volumes[1].kind,
                mvm_agentd::vsock::VolumeConfigKind::VirtioFs
            );
        }

        #[test]
        fn user_volume_manifest_rejects_unknown_mode_and_kind() {
            assert!(parse_user_volumes("uvol0:2f64617461:maybe:blk").is_err());
            assert!(parse_user_volumes("uvol0:2f64617461:rw:mystery").is_err());
        }
        // The anchor writer moved to `mvm_agentd::vsock::write_host_signer_anchor`
        // so both inits share one implementation; its byte layout, 0644 mode and
        // malformed-token refusal are covered there rather than duplicated here.

        #[test]
        fn resolve_guest_agent_for_dev_required_overlay_prefers_interactive_overlay() {
            let got = resolve_guest_agent_for(
                mvm_core::vm_backend::RuntimeSourcePolicy::RequiredOverlay,
                mvm_core::security::AgentProfile::Dev,
                |path| path == Path::new(AGENT_OVERLAY_INTERACTIVE),
            );
            assert_eq!(got, Some(PathBuf::from(AGENT_OVERLAY_INTERACTIVE)));
        }

        #[test]
        fn resolve_guest_agent_for_prod_required_overlay_uses_plain_overlay_agent() {
            let got = resolve_guest_agent_for(
                mvm_core::vm_backend::RuntimeSourcePolicy::RequiredOverlay,
                mvm_core::security::AgentProfile::SealedProd,
                |path| path == Path::new(AGENT_OVERLAY),
            );
            assert_eq!(got, Some(PathBuf::from(AGENT_OVERLAY)));
        }

        #[test]
        fn resolve_guest_agent_for_rootfs_only_dev_falls_back_to_baked_agent() {
            let got = resolve_guest_agent_for(
                mvm_core::vm_backend::RuntimeSourcePolicy::RootfsOnly,
                mvm_core::security::AgentProfile::Dev,
                |path| path == Path::new(AGENT_FALLBACK),
            );
            assert_eq!(got, Some(PathBuf::from(AGENT_FALLBACK)));
        }

        #[test]
        fn resolve_guest_agent_for_required_overlay_returns_none_when_overlay_missing() {
            // No executable candidate -> None, which main() treats as fatal
            // (fail closed) rather than booting agent-less.
            let got = resolve_guest_agent_for(
                mvm_core::vm_backend::RuntimeSourcePolicy::RequiredOverlay,
                mvm_core::security::AgentProfile::SealedProd,
                |_path| false,
            );
            assert_eq!(got, None);
        }
    }
}

#[cfg(target_os = "linux")]
fn main() {
    linux::main();
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("mvm-oci-init is Linux-only");
}
