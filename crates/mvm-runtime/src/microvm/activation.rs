//! Host-side activation for the universal initramfs boot path.
//!
//! After the VMM boots, the guest PID-1 agent waits in a fail-closed state
//! that only accepts [`mvm_agentd::vsock::ActivateEnvironment`]. This module
//! builds that message from the admitted [`VmStartConfig`] and the actual
//! virtio-blk slot layout produced by [`mvm_vmm::host::spec_map::workload_blocks`],
//! then sends it over the agent vsock channel.

use std::path::Path;

use anyhow::{Context, Result, bail};
use mvm_agentd::vsock::{
    ActivateEnvironment, ExtensionConfig, GuestRequest, GuestResponse, RootfsConfig,
    RuntimeOverlayConfig, VolumeConfig, VolumeConfigKind,
};
use mvm_core::protocol::vm_backend::{VerbGrantEnvelope, VmStartConfig, VmVolumeKind};

use crate::driver::traits::RunningVm;

/// Fallback guest device nodes used when the block layout does not contain a
/// matching source. The real devices are derived from [`workload_blocks`] so
/// missing rootfs-verity slots do not shift the runtime overlay.
const ROOTFS_DATA_DEV: &str = "/dev/vda";
const ROOTFS_HASH_DEV: &str = "/dev/vdb";
const RUNTIME_DATA_DEV: &str = "/dev/vdc";
const RUNTIME_HASH_DEV: &str = "/dev/vdd";

/// virtio-fs tag the backend assigns the root share on a block-less
/// virtiofs-root dev boot.  Mirrors the driver's `root=<tag>` cmdline knob.
const VIRTIOFS_ROOT_TAG: &str = "mvmroot";

pub use mvm_vmm::host::boot_config::booted_with_universal_initramfs;

/// How long activation waits for the guest agent to come up before failing.
///
/// A generous ceiling on a wait that is normally short: measured on HVF, the
/// agent binds its control port ~50ms after the VM starts, and the activation
/// round-trip itself takes ~8ms. The 30s is headroom for a loaded host, not an
/// expectation — which matters, because a schedule sized for "a few seconds"
/// is a schedule that cannot see 50ms. See [`activation_retry_delay`].
const ACTIVATION_READY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Activate a workload that booted with the universal initramfs.
///
/// Sends [`ActivateEnvironment`] over the agent vsock port and waits for an
/// ACK. If the guest replies with an error or an unexpected response, the
/// boot fails closed. The agent is not listening the instant the VM process
/// starts, so the connect+handshake retries on transient "agent not listening
/// yet" failures until [`ACTIVATION_READY_TIMEOUT`] rather than failing the
/// first attempt; a genuine activation rejection (an
/// `ActivateEnvironmentError` or an unexpected response) is returned
/// immediately, never retried.
pub fn activate_workload(vm: &dyn RunningVm, config: &VmStartConfig) -> Result<()> {
    let env = build_activation_environment(config)?;
    let started = std::time::Instant::now();
    let deadline = started + ACTIVATION_READY_TIMEOUT;
    let mut attempt = 0u32;
    loop {
        attempt = attempt.saturating_add(1);
        let attempt_started = std::time::Instant::now();
        match activate_once(vm, &env) {
            Ok(()) => {
                // Attempt count and the split between waiting and working are
                // what distinguish "the guest was slow" from "the schedule
                // slept through the guest being ready". The coarse phase timer
                // reports one `activate_workload` span and cannot tell those
                // apart; that is how a 100ms first backoff hid inside a 160ms
                // span for as long as it did.
                tracing::debug!(
                    attempt,
                    waited_ms = (attempt_started - started).as_secs_f64() * 1000.0,
                    activation_ms = attempt_started.elapsed().as_secs_f64() * 1000.0,
                    total_ms = started.elapsed().as_secs_f64() * 1000.0,
                    "guest activation complete"
                );
                return Ok(());
            }
            Err(e) if is_retryable_activation_error(&e) && std::time::Instant::now() < deadline => {
                std::thread::sleep(activation_retry_delay(attempt));
            }
            Err(e) => return Err(e),
        }
    }
}

/// One connect + handshake + `ActivateEnvironment` round-trip.
fn activate_once(vm: &dyn RunningVm, env: &ActivateEnvironment) -> Result<()> {
    let mut stream = vm
        .vsock_connect(mvm_agentd::vsock::GUEST_AGENT_PORT)
        .context("connect to guest agent for activation")?;
    activate_over_stream(&mut stream, env)
}

/// Whether an activation failure is a transient "agent isn't listening yet"
/// transport error worth retrying (as opposed to a real rejection or bug).
fn is_retryable_activation_error(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        if let Some(session) = cause.downcast_ref::<mvm_core::net::session::SessionError>() {
            return session.is_peer_hangup();
        }
        cause.downcast_ref::<std::io::Error>().is_some_and(|io| {
            matches!(
                io.kind(),
                std::io::ErrorKind::WouldBlock
                    | std::io::ErrorKind::TimedOut
                    | std::io::ErrorKind::ConnectionRefused
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::NotFound
                    | std::io::ErrorKind::AddrNotAvailable
                    | std::io::ErrorKind::Interrupted
                    | std::io::ErrorKind::UnexpectedEof
                    | std::io::ErrorKind::BrokenPipe
            )
        })
    })
}

/// First gap between activation attempts.
///
/// Small on purpose. The thing being waited for — the guest agent binding its
/// control port — happens tens of milliseconds after the VM starts, so a first
/// backsleep measured in that same order of magnitude decides the launch's
/// latency rather than observing it.
const ACTIVATION_POLL_MIN: std::time::Duration = std::time::Duration::from_millis(2);

/// Ceiling on the gap between activation attempts.
///
/// The gap grows so a guest that is genuinely slow to come up is not polled
/// thousands of times, but it stays far below [`ACTIVATION_READY_TIMEOUT`]:
/// every millisecond of the final gap is latency added to a launch that was
/// otherwise ready, and the cap is what bounds that error.
const ACTIVATION_POLL_MAX: std::time::Duration = std::time::Duration::from_millis(25);

/// Backoff between activation attempts: doubles from
/// [`ACTIVATION_POLL_MIN`], capped at [`ACTIVATION_POLL_MAX`].
///
/// This was `50ms << attempt`, capped at 500ms — so the first gap was 100ms.
/// Measured against a real HVF launch, the agent became reachable ~50ms in and
/// activation itself took ~8ms, but the first attempt failed and the schedule
/// then slept 100ms before looking again: `activate_workload` cost ~160ms to
/// do ~8ms of work. A backoff coarser than the event it polls for does not
/// measure that event, it replaces it.
fn activation_retry_delay(attempt: u32) -> std::time::Duration {
    let doublings = attempt.saturating_sub(1).min(16);
    let scaled = ACTIVATION_POLL_MIN.saturating_mul(1u32 << doublings);
    scaled.min(ACTIVATION_POLL_MAX)
}

/// Send a pre-built [`ActivateEnvironment`] over an already-connected
/// stream and require the ACK. Shared by [`activate_workload`] (whose
/// stream comes from a `RunningVm` vsock connection) and by backends whose
/// agent channel is not a vsock at all — the shared-kernel container tier
/// reaches the agent over a host bind-mounted Unix socket, through the
/// identical authenticated framing.
pub fn activate_over_stream<S>(stream: &mut S, env: &ActivateEnvironment) -> Result<()>
where
    S: std::io::Read + std::io::Write + Send,
{
    let response = mvm_agentd::vsock::send_request_stream(
        stream,
        &GuestRequest::ActivateEnvironment(env.clone()),
    )
    .context("send ActivateEnvironment to guest")?;
    match response {
        GuestResponse::ActivateEnvironmentAck => Ok(()),
        GuestResponse::ActivateEnvironmentError { message } => {
            bail!("guest activation failed: {message}")
        }
        other => bail!("unexpected response to ActivateEnvironment: {other:?}"),
    }
}

/// Build an [`ActivateEnvironment`] from the admitted launch config.
///
/// The rootfs is verity-sealed when the launch carries a roothash (config or
/// sidecar), plain-block otherwise; a virtiofs-root launch mounts the root
/// share by tag instead.  The runtime overlay rides along only when the full
/// overlay triple is present — it is always verity-sealed.  Custom volumes
/// are translated to virtio-fs tags when the config carries directory shares.
///
/// Look up the guest device node for a host block source in the emitted layout.
fn find_block_device(blocks: &[mvm_vmm::driver::spec::BlockDev], source: &str) -> Option<String> {
    let source_path = std::path::Path::new(source);
    blocks
        .iter()
        .find(|b| b.source == source_path)
        .map(|b| b.device_node())
}

fn build_activation_environment(config: &VmStartConfig) -> Result<ActivateEnvironment> {
    // Verity is keyed off the hash device: `verity_path` set means the
    // backend attached the Merkle sidecar at the hash slot, so the root mounts
    // as dm-verity and must carry a roothash. No sidecar device means a plain
    // unverified mount, whatever the config's roothash field says.
    let blocks = mvm_vmm::host::spec_map::workload_blocks(config);
    let block_dev = |path: &str| {
        find_block_device(&blocks, path).unwrap_or_else(|| ROOTFS_DATA_DEV.to_string())
    };

    let rootfs = if config.virtiofs_root.is_some() {
        RootfsConfig {
            data_dev: String::new(),
            hash_dev: None,
            roothash: None,
            virtiofs_tag: Some(VIRTIOFS_ROOT_TAG.to_string()),
            in_place: false,
        }
    } else if config.verity_path.is_some() {
        let roothash = resolve_rootfs_roothash(config)
            .context("verity rootfs attached but no roothash in config or sidecar")?;
        RootfsConfig {
            data_dev: block_dev(&config.rootfs_path),
            hash_dev: config
                .verity_path
                .as_deref()
                .and_then(|p| find_block_device(&blocks, p))
                .or_else(|| Some(ROOTFS_HASH_DEV.to_string())),
            roothash: Some(roothash),
            virtiofs_tag: None,
            in_place: false,
        }
    } else {
        RootfsConfig {
            data_dev: block_dev(&config.rootfs_path),
            hash_dev: None,
            roothash: None,
            virtiofs_tag: None,
            in_place: false,
        }
    };

    // The overlay rides only as a complete triple — the same all-three-or-none
    // rule the block layout applies, so the guest never mounts a device the
    // backend did not attach. The device nodes follow the actual slot layout,
    // not the hard-coded verity-everywhere assignment.
    let runtime = match (
        &config.runtime_overlay_path,
        &config.runtime_overlay_verity_path,
        &config.runtime_overlay_roothash,
    ) {
        (Some(overlay), Some(verity), Some(roothash)) => Some(RuntimeOverlayConfig {
            data_dev: find_block_device(&blocks, overlay)
                .unwrap_or_else(|| RUNTIME_DATA_DEV.to_string()),
            hash_dev: find_block_device(&blocks, verity)
                .unwrap_or_else(|| RUNTIME_HASH_DEV.to_string()),
            roothash: roothash.clone(),
        }),
        _ => None,
    };

    let volumes = build_volume_configs(config)?;
    let extensions = build_extension_configs(config)?;
    let verb_grant_envelope = read_verb_grant_envelope(&config.name)?;

    Ok(ActivateEnvironment {
        rootfs,
        runtime,
        volumes,
        extensions,
        verb_grant_envelope,
    })
}

fn build_extension_configs(config: &VmStartConfig) -> Result<Vec<ExtensionConfig>> {
    let plan_id = config
        .extension_plan_id
        .as_deref()
        .map(|value| mvm_contract::assurance::AssuranceId::parse(value.replace(':', "-")))
        .transpose()
        .context("parsing extension plan id")?;
    let devices = mvm_vmm::host::spec_map::workload_volume_devices(config);
    config
        .extensions
        .iter()
        .map(|binding| {
            let digest = hex::encode(binding.pack_digest);
            let mountpoint = format!("/run/mvm/extensions/{digest}");
            let index = config
                .volumes
                .iter()
                .position(|volume| volume.guest == mountpoint)
                .ok_or_else(|| anyhow::anyhow!("extension {digest} has no admitted volume"))?;
            let device = devices
                .get(index)
                .and_then(Clone::clone)
                .ok_or_else(|| anyhow::anyhow!("extension {digest} has no block device"))?;
            Ok(ExtensionConfig {
                binding: binding.clone(),
                plan_id: plan_id.clone().ok_or_else(|| {
                    anyhow::anyhow!("extension {digest} has no admitted plan identity")
                })?,
                mountpoint,
                device,
            })
        })
        .collect()
}

/// Resolve the rootfs roothash from the config or the host sidecar file, if
/// either carries a well-formed one.  `None` means an unverified plain-block
/// root — the guest mounts the data device without dm-verity.
fn resolve_rootfs_roothash(config: &VmStartConfig) -> Option<String> {
    if let Some(hash) = &config.roothash
        && hash.len() == 64
        && hash
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    {
        return Some(hash.clone());
    }
    probe_roothash_sidecar(&config.rootfs_path)
}

/// Read `<parent>/rootfs.roothash` next to the rootfs image, if it exists and
/// contains a well-formed 64-char lowercase hex hash.
fn probe_roothash_sidecar(rootfs_path: &str) -> Option<String> {
    let parent = Path::new(rootfs_path).parent()?;
    let raw = std::fs::read_to_string(parent.join("rootfs.roothash")).ok()?;
    let hash = raw.trim();
    (hash.len() == 64
        && hash
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()))
    .then(|| hash.to_string())
}

/// Translate configured volumes into the exact devices the runner attached.
fn build_volume_configs(config: &VmStartConfig) -> Result<Vec<VolumeConfig>> {
    let block_devices = mvm_vmm::host::spec_map::workload_volume_devices(config);

    config
        .volumes
        .iter()
        .zip(block_devices)
        .filter(|(volume, _)| !mvm_vmm::host::spec_map::is_sdk_sidecar_volume(volume))
        .enumerate()
        .map(|(idx, (volume, device))| {
            let (kind, device) = match volume.kind {
                VmVolumeKind::DirShare => (VolumeConfigKind::VirtioFs, None),
                VmVolumeKind::Disk => (VolumeConfigKind::Block, device),
            };
            if matches!(volume.kind, VmVolumeKind::Disk) && device.is_none() {
                bail!("missing VMM block device for user volume uvol{idx}");
            }
            Ok(VolumeConfig {
                tag: format!("uvol{idx}"),
                mountpoint: volume.guest.clone(),
                read_only: volume.read_only,
                kind,
                device,
            })
        })
        .collect()
}

/// Load the signed verb-grant envelope written by the host signer, if present.
///
/// `pub(crate)` so the wasm tier's capability handshake reads the same
/// sidecar through the same parser instead of re-rolling it.
pub(crate) fn read_verb_grant_envelope(vm_name: &str) -> Result<Option<VerbGrantEnvelope>> {
    let path = mvm_core::config::vm_state_dir(vm_name).join("verb-grant.json");
    if !path.is_file() {
        return Ok(None);
    }
    let bytes = std::fs::read(&path)
        .with_context(|| format!("read verb-grant envelope from {}", path.display()))?;
    let envelope = serde_json::from_slice(&bytes)
        .with_context(|| format!("parse verb-grant envelope from {}", path.display()))?;
    Ok(Some(envelope))
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::net::session::SessionError;
    use mvm_core::util::test_env::TestEnv;

    /// The first retry must not dominate the wait it is polling for.
    ///
    /// This schedule used to start at 100ms and double to 500ms. The guest
    /// agent binds its port ~50ms after the VM starts, so the very first
    /// backoff overshot the entire thing: a launch spent 100ms asleep to
    /// discover a readiness that had already happened, and `activate_workload`
    /// measured ~160ms against ~8ms of actual activation work.
    #[test]
    fn the_first_activation_retry_is_shorter_than_the_readiness_it_waits_for() {
        assert!(
            activation_retry_delay(1) <= std::time::Duration::from_millis(2),
            "first retry {:?} must be a poll, not a sleep",
            activation_retry_delay(1)
        );
    }

    #[test]
    fn activation_retries_back_off_monotonically_to_a_bounded_cap() {
        let mut previous = std::time::Duration::ZERO;
        for attempt in 1..=64u32 {
            let delay = activation_retry_delay(attempt);
            assert!(
                delay >= previous,
                "attempt {attempt} backed off to {delay:?}, below the previous {previous:?}"
            );
            assert!(
                delay <= ACTIVATION_POLL_MAX,
                "attempt {attempt} delay {delay:?} exceeds the cap"
            );
            previous = delay;
        }
        assert_eq!(activation_retry_delay(64), ACTIVATION_POLL_MAX);
    }

    /// A capped poll must still be coarse enough that a guest which never
    /// comes up does not spin the full deadline away on handshake attempts.
    #[test]
    fn the_capped_poll_bounds_attempts_across_the_activation_deadline() {
        let attempts = ACTIVATION_READY_TIMEOUT.as_millis() / ACTIVATION_POLL_MAX.as_millis();
        assert!(
            attempts <= 2_000,
            "a never-ready guest would make {attempts} handshake attempts before the deadline"
        );
    }

    const VALID_HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn test_env() -> (TestEnv, tempfile::TempDir) {
        let mut env = TestEnv::new();
        let dir = tempfile::tempdir().unwrap();
        env.set("MVM_HOME", dir.path());
        (env, dir)
    }

    fn base_config() -> VmStartConfig {
        VmStartConfig {
            rootfs_path: "/img/rootfs.ext4".into(),
            ..Default::default()
        }
    }

    #[test]
    fn activation_retries_a_typed_session_peer_hangup() {
        let error = anyhow::Error::new(SessionError::Io(std::io::Error::from(
            std::io::ErrorKind::ConnectionReset,
        )))
        .context("host session handshake failed");

        assert!(is_retryable_activation_error(&error));
    }

    #[test]
    fn activation_does_not_retry_an_authenticated_session_rejection() {
        let error = anyhow::Error::new(SessionError::PeerIdentityMismatch(
            "unexpected guest identity".into(),
        ))
        .context("host session handshake failed");

        assert!(!is_retryable_activation_error(&error));
    }

    #[test]
    fn build_env_uses_config_roothash_and_sidecar_overlay() {
        let (_env, _dir) = test_env();
        let config = VmStartConfig {
            name: "test-vm".into(),
            rootfs_path: "/img/rootfs.ext4".into(),
            verity_path: Some("/img/rootfs.verity".into()),
            roothash: Some(VALID_HASH.into()),
            runtime_overlay_path: Some("/img/runtime.ext4".into()),
            runtime_overlay_verity_path: Some("/img/runtime.verity".into()),
            runtime_overlay_roothash: Some(VALID_HASH.into()),
            ..Default::default()
        };

        let env = build_activation_environment(&config).unwrap();
        assert_eq!(env.rootfs.data_dev, "/dev/vda");
        assert_eq!(env.rootfs.hash_dev.as_deref(), Some("/dev/vdb"));
        assert_eq!(env.rootfs.roothash.as_deref(), Some(VALID_HASH));
        let runtime = env.runtime.as_ref().expect("overlay triple ⇒ runtime");
        assert_eq!(runtime.data_dev, "/dev/vdc");
        assert_eq!(runtime.hash_dev, "/dev/vdd");
        assert_eq!(runtime.roothash, VALID_HASH);
        assert!(env.volumes.is_empty());
        assert!(env.verb_grant_envelope.is_none());
    }

    #[test]
    fn build_env_reads_roothash_sidecar_when_config_empty() {
        let (_env, dir) = test_env();
        let rootfs = dir.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"data").unwrap();
        std::fs::write(
            dir.path().join("rootfs.roothash"),
            format!("{VALID_HASH}\n"),
        )
        .unwrap();

        let config = VmStartConfig {
            name: "test-vm".into(),
            rootfs_path: rootfs.to_string_lossy().into_owned(),
            verity_path: Some(
                dir.path()
                    .join("rootfs.verity")
                    .to_string_lossy()
                    .into_owned(),
            ),
            ..Default::default()
        };

        let env = build_activation_environment(&config).unwrap();
        assert_eq!(env.rootfs.roothash.as_deref(), Some(VALID_HASH));
    }

    #[test]
    fn build_env_without_roothash_is_an_unverified_plain_block_root() {
        let (_env, _dir) = test_env();
        let config = VmStartConfig {
            name: "test-vm".into(),
            runtime_overlay_roothash: Some(VALID_HASH.into()),
            ..base_config()
        };

        let env = build_activation_environment(&config).unwrap();
        assert_eq!(env.rootfs.data_dev, "/dev/vda");
        assert_eq!(env.rootfs.roothash, None);
        assert_eq!(env.rootfs.hash_dev, None);
        assert_eq!(env.rootfs.virtiofs_tag, None);
        // An overlay roothash without its image/verity siblings is not a
        // complete triple, so no overlay is mounted.
        assert!(env.runtime.is_none());
    }

    #[test]
    fn build_env_maps_runtime_overlay_to_next_slot_when_rootfs_has_no_verity() {
        let (_env, _dir) = test_env();
        let config = VmStartConfig {
            name: "test-vm".into(),
            rootfs_path: "/img/rootfs.ext4".into(),
            runtime_overlay_path: Some("/img/runtime.ext4".into()),
            runtime_overlay_verity_path: Some("/img/runtime.verity".into()),
            runtime_overlay_roothash: Some(VALID_HASH.into()),
            ..Default::default()
        };

        let env = build_activation_environment(&config).unwrap();
        assert_eq!(env.rootfs.data_dev, "/dev/vda");
        assert_eq!(env.rootfs.hash_dev, None);
        assert_eq!(env.rootfs.roothash, None);
        let runtime = env.runtime.as_ref().expect("overlay triple ⇒ runtime");
        // No rootfs verity slot means the runtime overlay slides from
        // /dev/vdc to /dev/vdb and its hash sidecar from /dev/vdd to /dev/vdc.
        assert_eq!(runtime.data_dev, "/dev/vdb");
        assert_eq!(runtime.hash_dev, "/dev/vdc");
        assert_eq!(runtime.roothash, VALID_HASH);
    }

    #[test]
    fn build_env_for_virtiofs_root_mounts_the_root_tag() {
        let (_env, _dir) = test_env();
        let config = VmStartConfig {
            name: "test-vm".into(),
            rootfs_path: String::new(),
            virtiofs_root: Some("/host/unpacked-oci".into()),
            ..Default::default()
        };

        let env = build_activation_environment(&config).unwrap();
        assert_eq!(env.rootfs.virtiofs_tag.as_deref(), Some("mvmroot"));
        assert_eq!(env.rootfs.roothash, None);
        assert!(env.runtime.is_none());
    }

    #[test]
    fn universal_initramfs_gate_keys_on_the_cache_path() {
        let (_env, dir) = test_env();
        let cache_root =
            std::path::PathBuf::from(mvm_core::config::mvm_cache_dir()).join("initramfs");
        let universal = cache_root
            .join("0.18.0")
            .join("aarch64")
            .join("initramfs.cpio.gz");
        let legacy = dir.path().join("rootfs.initrd");

        let mut config = base_config();
        assert!(!booted_with_universal_initramfs(&config));

        config.initrd_path = Some(legacy.display().to_string());
        assert!(!booted_with_universal_initramfs(&config));

        config.initrd_path = Some(universal.display().to_string());
        assert!(booted_with_universal_initramfs(&config));
    }

    #[test]
    fn build_env_maps_directory_and_block_volumes() {
        let (_env, _dir) = test_env();
        let config = VmStartConfig {
            name: "test-vm".into(),
            roothash: Some(VALID_HASH.into()),
            runtime_overlay_roothash: Some(VALID_HASH.into()),
            volumes: vec![
                VmVolumeKind::DirShare.into_volume("/host/share", "/guest/share", false),
                VmVolumeKind::Disk.into_volume("/host/disk", "/guest/disk", true),
            ],
            ..base_config()
        };

        let env = build_activation_environment(&config).unwrap();
        assert_eq!(env.volumes.len(), 2);
        assert_eq!(env.volumes[0].tag, "uvol0");
        assert_eq!(env.volumes[0].mountpoint, "/guest/share");
        assert!(!env.volumes[0].read_only);
        assert!(matches!(
            env.volumes[0].kind,
            mvm_agentd::vsock::VolumeConfigKind::VirtioFs
        ));
        assert_eq!(env.volumes[0].device, None);
        assert_eq!(env.volumes[1].tag, "uvol1");
        assert_eq!(env.volumes[1].mountpoint, "/guest/disk");
        assert!(env.volumes[1].read_only);
        assert!(matches!(
            env.volumes[1].kind,
            mvm_agentd::vsock::VolumeConfigKind::Block
        ));
        assert_eq!(env.volumes[1].device.as_deref(), Some("/dev/vdb"));
    }

    #[test]
    fn build_env_excludes_the_reserved_sdk_sidecar_from_user_volumes() {
        let (_env, _dir) = test_env();
        let config = VmStartConfig {
            name: "test-vm".into(),
            roothash: Some(VALID_HASH.into()),
            runtime_overlay_roothash: Some(VALID_HASH.into()),
            volumes: vec![
                VmVolumeKind::Disk.into_volume("/host/data", "/data", false),
                VmVolumeKind::Disk.into_volume(
                    "/host/sdk.ext4",
                    mvm_core::plan::SDK_SIDECAR_GUEST_PATH,
                    true,
                ),
            ],
            ..base_config()
        };

        let env = build_activation_environment(&config).unwrap();
        assert_eq!(env.volumes.len(), 1);
        assert_eq!(env.volumes[0].tag, "uvol0");
        assert_eq!(env.volumes[0].mountpoint, "/data");
        assert_eq!(env.volumes[0].device.as_deref(), Some("/dev/vdb"));
    }

    #[test]
    fn build_env_loads_verb_grant_envelope() {
        let (_env, _dir) = test_env();
        let state = mvm_core::config::vm_state_dir("granted-vm");
        std::fs::create_dir_all(&state).unwrap();
        let grant = mvm_core::plan::VerbGrant {
            session_id: "session-1".into(),
            plan_nonce: mvm_core::plan::Nonce::from_hex("0123456789abcdef0123456789abcdef")
                .unwrap(),
            not_after: chrono::Utc::now(),
            verbs: vec![mvm_core::plan::VerbId::new("ping").unwrap()],
            sig: vec![0u8; 64],
        };
        let envelope = VerbGrantEnvelope {
            pubkey_hex: VALID_HASH.into(),
            plan_nonce_hex: VALID_HASH.into(),
            predecessor_session_id: None,
            predecessor_plan_nonce_hex: None,
            grant,
        };
        std::fs::write(
            state.join("verb-grant.json"),
            serde_json::to_vec(&envelope).unwrap(),
        )
        .unwrap();

        let config = VmStartConfig {
            name: "granted-vm".into(),
            roothash: Some(VALID_HASH.into()),
            runtime_overlay_roothash: Some(VALID_HASH.into()),
            ..base_config()
        };

        let env = build_activation_environment(&config).unwrap();
        assert!(env.verb_grant_envelope.is_some());
    }

    #[test]
    fn activate_over_stream_requires_the_ack_and_fails_closed_otherwise() {
        // Error response ⇒ the boot fails closed with the guest's message.
        let (mut host, mut guest) = std::os::unix::net::UnixStream::pair().unwrap();
        let server = std::thread::spawn(move || {
            let guest_key = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
            let host_key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]).verifying_key();
            let mut session =
                mvm_agentd::vsock::AuthenticatedSession::guest(&mut guest, guest_key, &host_key)
                    .unwrap();
            let req: GuestRequest = session.read(&mut guest).unwrap();
            assert!(matches!(req, GuestRequest::ActivateEnvironment(_)));
            session
                .write(
                    &mut guest,
                    &GuestResponse::ActivateEnvironmentError {
                        message: "mount failed".into(),
                    },
                )
                .unwrap();
        });

        let (_env, dir) = test_env();
        // The host side of the handshake reads its signer from the keys dir.
        let keys = mvm_core::config::mvm_keys_dir();
        std::fs::create_dir_all(&keys).unwrap();
        std::fs::write(keys.join("host-signer.ed25519"), [7u8; 32]).unwrap();
        let _ = dir;

        let env = build_activation_environment(&base_config()).unwrap();
        let err = activate_over_stream(&mut host, &env).unwrap_err();
        assert!(
            err.to_string().contains("mount failed"),
            "expected the guest's error to fail the boot: {err}"
        );
        server.join().unwrap();
    }

    trait VolumeExt {
        fn into_volume(
            self,
            host: &str,
            guest: &str,
            read_only: bool,
        ) -> mvm_core::protocol::vm_backend::VmVolume;
    }

    impl VolumeExt for VmVolumeKind {
        fn into_volume(
            self,
            host: &str,
            guest: &str,
            read_only: bool,
        ) -> mvm_core::protocol::vm_backend::VmVolume {
            mvm_core::protocol::vm_backend::VmVolume {
                host: host.into(),
                guest: guest.into(),
                size: String::new(),
                read_only,
                kind: self,
                encrypted: false,
            }
        }
    }
}
