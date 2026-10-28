//! Read-only volumes attached to a warm-claimed child after it is restored.
//!
//! A warm parent boots before any launch names a volume, so it cannot mount
//! one at activation the way a cold boot does. Instead it boots with a fixed
//! number of read-only block slots holding placeholders, and its kernel
//! cmdline says how many ([`SLOTS_TOKEN`]). The claim points those slots at the
//! launch's own materialized images before the child resumes, and its
//! `PostRestore` names the volumes to mount.
//!
//! Mounting needs `CAP_SYS_ADMIN`, which the agent gives up at activation. So
//! the PID-1 agent of a slotted guest starts one helper first, while it is
//! still root, and keeps the only end of a socket pair to it. The helper
//! serves exactly one request and exits:
//!
//! - it is started only in a guest whose cmdline carries [`SLOTS_TOKEN`], which
//!   only a warm parent's does, so a cold-booted workload never has one;
//! - the first `PostRestore` consumes it, with or without volumes, and that
//!   happens before the claim commits and before any workload process exists,
//!   so no workload ever runs beside it;
//! - it accepts only read-only ext4 block volumes that name their label, at
//!   most as many as the guest has slots, at mountpoints the mount-path policy
//!   admits, and mounts them read-only.

use crate::vsock::{VolumeConfig, VolumeConfigKind};

/// Kernel cmdline token carrying how many late-volume slots this guest booted.
pub const SLOTS_TOKEN: &str = "mvm.late_volume_slots";

/// The most slots a guest may declare. Each is one virtio-blk device, and the
/// guest device range is `/dev/vd[a-z]`.
pub const MAX_SLOTS: u8 = 4;

/// First argument that makes the agent binary run as the late-volume helper.
pub const HELPER_ARG: &str = "--late-volume-helper";

/// Descriptor the helper finds its end of the socket pair on.
pub const HELPER_FD: i32 = 3;

/// The largest request the helper reads. Four volume entries fit many times
/// over; anything longer is not a request this protocol produces.
pub const MAX_REQUEST_BYTES: usize = 16 * 1024;

/// Read the slot count off a kernel cmdline. Absent, malformed or above
/// [`MAX_SLOTS`] answers `0`: a guest that cannot say how many slots it has
/// starts no helper and mounts nothing late.
pub fn slots_from_cmdline(cmdline: &str) -> u8 {
    cmdline
        .split_whitespace()
        .find_map(|token| token.strip_prefix(SLOTS_TOKEN)?.strip_prefix('='))
        .and_then(|value| value.parse::<u8>().ok())
        .filter(|slots| *slots <= MAX_SLOTS)
        .unwrap_or(0)
}

/// The cmdline token declaring `slots` late-volume slots.
pub fn slots_token(slots: u8) -> String {
    format!("{SLOTS_TOKEN}={slots}")
}

/// Refuse a request the helper must not act on.
///
/// Every volume is a read-only block device that names both its slot's device
/// node and the ext4 label the host wrote, and there are no more of them than
/// the guest has slots. The mountpoint and device checks themselves are the
/// activation path's own, run again by the mount.
pub fn validate_request(volumes: &[VolumeConfig], slots: u8) -> Result<(), String> {
    if volumes.len() > usize::from(slots) {
        return Err(format!(
            "{} late volumes requested, but this guest booted {slots} slots",
            volumes.len()
        ));
    }
    for volume in volumes {
        if volume.kind != VolumeConfigKind::Block {
            return Err(format!(
                "late volume {:?} is not a block volume",
                volume.tag
            ));
        }
        if !volume.read_only {
            return Err(format!("late volume {:?} is not read-only", volume.tag));
        }
        if volume.device.is_none() || volume.label.is_none() {
            return Err(format!(
                "late volume {:?} must name its device and its label",
                volume.tag
            ));
        }
        crate::guest_mount::validate_volume_mountpoint(&volume.mountpoint)
            .map_err(|error| error.to_string())?;
    }
    Ok(())
}

/// The helper's answer: empty on success, the reason otherwise.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HelperReply {
    pub mounted: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Encode one request: a big-endian length and the JSON volume list.
pub fn encode_request(volumes: &[VolumeConfig]) -> Result<Vec<u8>, String> {
    let body = serde_json::to_vec(volumes).map_err(|error| error.to_string())?;
    if body.len() > MAX_REQUEST_BYTES {
        return Err("late-volume request is too large".into());
    }
    let mut frame = (body.len() as u32).to_be_bytes().to_vec();
    frame.extend_from_slice(&body);
    Ok(frame)
}

/// Read one request frame from `reader`.
pub fn read_request(reader: &mut impl std::io::Read) -> Result<Vec<VolumeConfig>, String> {
    let mut len = [0u8; 4];
    reader
        .read_exact(&mut len)
        .map_err(|error| format!("reading the request length: {error}"))?;
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_REQUEST_BYTES {
        return Err(format!("late-volume request of {len} bytes is too large"));
    }
    let mut body = vec![0u8; len];
    reader
        .read_exact(&mut body)
        .map_err(|error| format!("reading the request: {error}"))?;
    serde_json::from_slice(&body).map_err(|error| format!("decoding the request: {error}"))
}

/// Serve the one request on `stream`: validate it, mount it through `mount`,
/// and answer. Returns whether the mount succeeded.
pub fn serve_once<S: std::io::Read + std::io::Write>(
    stream: &mut S,
    slots: u8,
    mount: impl FnOnce(&[VolumeConfig]) -> Result<(), String>,
) -> bool {
    let outcome = read_request(stream).and_then(|volumes| {
        validate_request(&volumes, slots)?;
        mount(&volumes)?;
        Ok(volumes.len() as u32)
    });
    let reply = match &outcome {
        Ok(mounted) => HelperReply {
            mounted: *mounted,
            error: None,
        },
        Err(error) => HelperReply {
            mounted: 0,
            error: Some(error.clone()),
        },
    };
    let body = serde_json::to_vec(&reply).unwrap_or_default();
    let _ = stream.write_all(&(body.len() as u32).to_be_bytes());
    let _ = stream.write_all(&body);
    let _ = stream.flush();
    outcome.is_ok()
}

/// Send `volumes` to the helper on `stream` and wait for its reply.
pub fn request_mount<S: std::io::Read + std::io::Write>(
    stream: &mut S,
    volumes: &[VolumeConfig],
) -> Result<u32, String> {
    stream
        .write_all(&encode_request(volumes)?)
        .and_then(|()| stream.flush())
        .map_err(|error| format!("late-volume helper did not take the request: {error}"))?;
    let mut len = [0u8; 4];
    stream
        .read_exact(&mut len)
        .map_err(|error| format!("late-volume helper did not answer: {error}"))?;
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_REQUEST_BYTES {
        return Err("late-volume helper sent a malformed reply".into());
    }
    let mut body = vec![0u8; len];
    stream
        .read_exact(&mut body)
        .map_err(|error| format!("late-volume helper did not answer: {error}"))?;
    let reply: HelperReply = serde_json::from_slice(&body)
        .map_err(|_| "late-volume helper sent a malformed reply".to_string())?;
    match reply.error {
        Some(error) => Err(error),
        None => Ok(reply.mounted),
    }
}

static HELPER: std::sync::Mutex<Option<std::os::unix::net::UnixStream>> =
    std::sync::Mutex::new(None);

/// Hand the late-volume request of a `PostRestore` to this guest's helper.
///
/// Answers `Ok(None)` when the guest has no helper and nothing was asked of
/// it. A guest with a helper always consumes it here, so a restore that names
/// no volume still closes it before any workload runs.
pub fn attach_after_restore(volumes: &[VolumeConfig]) -> Result<Option<u32>, String> {
    let taken = HELPER
        .lock()
        .map_err(|_| "late-volume helper state is poisoned".to_string())?
        .take();
    match taken {
        Some(mut stream) => {
            let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(10)));
            let _ = stream.set_write_timeout(Some(std::time::Duration::from_secs(10)));
            request_mount(&mut stream, volumes).map(Some)
        }
        None if volumes.is_empty() => Ok(None),
        None => Err(format!(
            "{} late volumes requested, but this guest has no late-volume helper",
            volumes.len()
        )),
    }
}

/// Entry point for the agent binary run with [`HELPER_ARG`]. Returns the
/// process exit code.
pub fn run_helper() -> i32 {
    #[cfg(target_os = "linux")]
    {
        linux::run()
    }
    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("mvm-guest-agent: the late-volume helper runs inside Linux guests only");
        1
    }
}

/// Start this guest's helper when its cmdline declares late-volume slots.
/// Called by the PID-1 agent while it is still root, before it drops
/// privilege. A failure is logged: a claim that then names a volume is refused
/// by this guest, and the host fails it closed.
#[cfg(target_os = "linux")]
pub fn start_helper_if_slotted() {
    let slots = std::fs::read_to_string("/proc/cmdline")
        .map(|cmdline| slots_from_cmdline(&cmdline))
        .unwrap_or(0);
    if slots == 0 {
        return;
    }
    match linux::spawn() {
        Ok((stream, pid)) => {
            if let Ok(mut helper) = HELPER.lock() {
                *helper = Some(stream);
            }
            eprintln!("mvm-guest-agent: late-volume helper pid={pid} slots={slots}");
        }
        Err(error) => eprintln!("mvm-guest-agent: no late-volume helper ({error})"),
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::net::UnixStream;
    use std::process::{Command, Stdio};

    use super::{HELPER_ARG, HELPER_FD};

    pub(super) fn run() -> i32 {
        // SAFETY: plain prctl with integer arguments.
        if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
            eprintln!(
                "mvm-guest-agent: late-volume helper cannot disable dumping: {}",
                io::Error::last_os_error()
            );
            return 1;
        }
        if let Err(error) = crate::fd_hygiene::close_descriptors_from(HELPER_FD as u32 + 1, None) {
            eprintln!("mvm-guest-agent: late-volume helper: {error}");
            return 1;
        }
        let slots = std::fs::read_to_string("/proc/cmdline")
            .map(|cmdline| super::slots_from_cmdline(&cmdline))
            .unwrap_or(0);
        // SAFETY: PID 1 placed this process's end of the socket pair on
        // `HELPER_FD`, and nothing else in this process owns it.
        let mut stream = UnixStream::from(unsafe { OwnedFd::from_raw_fd(HELPER_FD) });
        let mounted = super::serve_once(&mut stream, slots, |volumes| {
            crate::guest_mount::mount_volumes(volumes, std::path::Path::new("/"))
                .map_err(|error| error.to_string())
        });
        if mounted { 0 } else { 1 }
    }

    pub(super) fn spawn() -> io::Result<(UnixStream, u32)> {
        use std::os::unix::process::CommandExt;

        let (agent_end, helper_end) = UnixStream::pair()?;
        let helper_fd = helper_end.as_raw_fd();
        let mut cmd = Command::new("/proc/self/exe");
        crate::trusted_env::configure_command(&mut cmd);
        cmd.arg(HELPER_ARG)
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
        // SAFETY: runs in the forked child before exec, and calls only
        // async-signal-safe syscalls without allocating.
        unsafe {
            cmd.pre_exec(move || {
                let rc = if helper_fd == HELPER_FD {
                    libc::fcntl(helper_fd, libc::F_SETFD, 0)
                } else {
                    libc::dup2(helper_fd, HELPER_FD)
                };
                if rc < 0 {
                    return Err(io::Error::last_os_error());
                }
                crate::fd_hygiene::mark_descriptors_close_on_exec_from(HELPER_FD as u32 + 1, None)
            });
        }
        let child = cmd.spawn()?;
        drop(helper_end);
        Ok((agent_end, child.id()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block(tag: &str, mountpoint: &str) -> VolumeConfig {
        VolumeConfig {
            tag: tag.into(),
            mountpoint: mountpoint.into(),
            read_only: true,
            kind: VolumeConfigKind::Block,
            device: Some("/dev/vde".into()),
            label: Some("mvmmnt0".into()),
        }
    }

    #[test]
    fn the_slot_count_is_read_only_from_a_well_formed_token() {
        assert_eq!(
            slots_from_cmdline("console=ttyS0 mvm.late_volume_slots=2 quiet"),
            2
        );
        assert_eq!(slots_from_cmdline(&slots_token(MAX_SLOTS)), MAX_SLOTS);
        for absent in [
            "console=ttyS0",
            "mvm.late_volume_slots=",
            "mvm.late_volume_slots=two",
            "mvm.late_volume_slots=9",
            "mvm.late_volume_slots_extra=2",
        ] {
            assert_eq!(slots_from_cmdline(absent), 0, "{absent}");
        }
    }

    #[test]
    fn only_labelled_read_only_block_volumes_within_the_slot_count_are_admitted() {
        assert!(validate_request(&[block("uvol0", "/data")], 1).is_ok());
        assert!(validate_request(&[], 0).is_ok());
        assert!(validate_request(&[block("uvol0", "/data")], 0).is_err());

        let mut writable = block("uvol0", "/data");
        writable.read_only = false;
        let mut virtiofs = block("uvol0", "/data");
        virtiofs.kind = VolumeConfigKind::VirtioFs;
        let mut unlabelled = block("uvol0", "/data");
        unlabelled.label = None;
        let mut no_device = block("uvol0", "/data");
        no_device.device = None;
        let outside_policy = block("uvol0", "/etc");
        for (why, volume) in [
            ("writable", writable),
            ("virtio-fs", virtiofs),
            ("unlabelled", unlabelled),
            ("no device", no_device),
            ("denied mountpoint", outside_policy),
        ] {
            assert!(validate_request(&[volume], 4).is_err(), "{why}");
        }
    }

    #[test]
    fn a_request_round_trips_and_the_helper_mounts_only_what_it_admits() {
        let volumes = vec![block("uvol0", "/data")];
        let (mut agent, mut helper) = std::os::unix::net::UnixStream::pair().unwrap();
        let served = std::thread::spawn(move || {
            let mut seen = Vec::new();
            let ok = serve_once(&mut helper, 1, |volumes| {
                seen = volumes.to_vec();
                Ok(())
            });
            (ok, seen)
        });
        assert_eq!(request_mount(&mut agent, &volumes).unwrap(), 1);
        let (ok, seen) = served.join().unwrap();
        assert!(ok);
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].mountpoint, "/data");
    }

    #[test]
    fn a_refused_request_mounts_nothing_and_says_why() {
        let (mut agent, mut helper) = std::os::unix::net::UnixStream::pair().unwrap();
        let served = std::thread::spawn(move || {
            let mut called = false;
            let ok = serve_once(&mut helper, 0, |_| {
                called = true;
                Ok(())
            });
            (ok, called)
        });
        let err = request_mount(&mut agent, &[block("uvol0", "/data")]).unwrap_err();
        assert!(err.contains("booted 0 slots"), "{err}");
        let (ok, called) = served.join().unwrap();
        assert!(!ok);
        assert!(!called, "a refused request must never reach the mount");
    }

    #[test]
    fn an_oversized_request_is_refused_before_it_is_read() {
        let mut frame = ((MAX_REQUEST_BYTES + 1) as u32).to_be_bytes().to_vec();
        frame.extend_from_slice(b"[]");
        assert!(read_request(&mut frame.as_slice()).is_err());
    }

    #[test]
    fn a_guest_without_a_helper_refuses_volumes_and_ignores_an_empty_request() {
        assert_eq!(attach_after_restore(&[]).unwrap(), None);
        assert!(attach_after_restore(&[block("uvol0", "/data")]).is_err());
    }
}
