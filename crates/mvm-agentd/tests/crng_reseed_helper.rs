//! The CRNG reseed helper as a real process: the agent binary started in helper
//! mode, confined by its own seccomp allowlist.
//!
//! The unprivileged tests run as any user. Without `CAP_SYS_ADMIN` the kernel refuses
//! the ioctls, which is the point: the helper must answer that refusal and keep
//! serving rather than be killed by its own filter. The privileged tests start
//! the helper exactly as the guest does and inspect the running process; they
//! mutate host state (a uid switch in the child, a directory under `/run/mvm`)
//! and so run only as root with `MVM_GUEST_PRIVILEGED_TESTS=1`.

#![cfg(target_os = "linux")]

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::process::Child;
use std::time::{Duration, Instant};

use mvm_agentd::crng_reseed::{HelperConnection, HelperSpawn, ReseedError, ReseedStep};
use mvm_agentd::guest_mount::{CRNG_RESEED_HELPER_GID, CRNG_RESEED_HELPER_UID};

const AGENT: &str = env!("CARGO_BIN_EXE_mvm-guest-agent");
const SETPRIV: &str = env!("CARGO_BIN_EXE_mvm-setpriv");
const TOKEN: [u8; 16] = [0x5a; 16];

/// Whether a privileged test asked for with `MVM_GUEST_PRIVILEGED_TESTS=1` may
/// run with effective uid `euid`. Asking without root is an error, not a skip:
/// CI sets the variable under `sudo`, and an escalation that silently failed
/// would otherwise report a pass that asserted nothing.
///
/// The library's own privilege witnesses carry the same gate; a `cfg(test)`
/// helper there is not visible to this integration test, so it is not shared.
fn privileged_run(requested: Option<&str>, euid: u32) -> Result<bool, String> {
    match (requested, euid) {
        (Some("1"), 0) => Ok(true),
        (Some("1"), euid) => Err(format!(
            "MVM_GUEST_PRIVILEGED_TESTS=1 is set but this test runs as euid {euid}; \
             run it as root or unset the variable"
        )),
        _ => Ok(false),
    }
}

fn privileged() -> bool {
    let requested = std::env::var("MVM_GUEST_PRIVILEGED_TESTS").ok();
    // SAFETY: geteuid has no preconditions.
    let euid = unsafe { libc::geteuid() };
    privileged_run(requested.as_deref(), euid).unwrap_or_else(|refusal| panic!("{refusal}"))
}

#[test]
fn a_privileged_run_without_root_fails_instead_of_skipping() {
    assert_eq!(privileged_run(None, 1000), Ok(false));
    assert_eq!(privileged_run(Some("0"), 1000), Ok(false));
    assert_eq!(privileged_run(Some("1"), 0), Ok(true));
    let refusal = privileged_run(Some("1"), 1000).unwrap_err();
    assert!(refusal.contains("euid 1000"), "{refusal}");
}

/// Put the agent binary behind world-traversable test-only path components.
///
/// Hosted runners may keep Cargo's target directory below a private home
/// directory. The production guest installs this binary under `/bin`, but a
/// test that drops identity before `exec` cannot traverse a private build
/// path even when the binary itself is executable.
fn agent_binary_for_dropped_identity() -> (tempfile::TempDir, std::path::PathBuf) {
    use std::os::unix::fs::PermissionsExt;

    // Under `/tmp` rather than `TMPDIR`: a runner can point `TMPDIR` below the
    // same private home, and `sudo -E` carries it through.
    let dir = tempfile::Builder::new()
        .prefix("mvm-reseed-helper-")
        .tempdir_in("/tmp")
        .expect("create accessible agent directory");
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755))
        .expect("make agent directory traversable");
    let agent = dir.path().join("mvm-guest-agent");
    std::fs::copy(AGENT, &agent).expect("copy agent binary");
    std::fs::set_permissions(&agent, std::fs::Permissions::from_mode(0o755))
        .expect("make agent binary executable");
    (dir, agent)
}

/// A descriptor with close-on-exec clear, standing in for anything the agent
/// holds open that missed the flag.
fn leaky_descriptor() -> OwnedFd {
    let file = std::fs::File::open("/dev/null").expect("open /dev/null");
    // SAFETY: duplicating an open descriptor; F_DUPFD leaves close-on-exec clear.
    let fd = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD, 20) };
    assert!(fd >= 0);
    // SAFETY: `fd` was just created and nothing else owns it.
    unsafe { OwnedFd::from_raw_fd(fd) }
}

fn wait_for_exit(child: &mut Child) -> std::process::ExitStatus {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = child.try_wait().expect("try_wait") {
            return status;
        }
        assert!(Instant::now() < deadline, "the helper did not exit");
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn status_field(pid: u32, field: &str) -> String {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).expect("read status");
    status
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{field}:")))
        .unwrap_or_else(|| panic!("no {field} in status:\n{status}"))
        .trim()
        .to_string()
}

/// The helper's descriptors above stdio, as what each refers to with socket
/// inode numbers reduced to `socket`.
fn descriptors_above_stdio(pid: u32) -> Vec<String> {
    let mut fds: Vec<u32> = std::fs::read_dir(format!("/proc/{pid}/fd"))
        .expect("read the helper's descriptor table")
        .filter_map(|entry| entry.ok()?.file_name().to_str()?.parse().ok())
        .collect();
    fds.sort_unstable();
    assert_eq!(&fds[..3], &[0, 1, 2], "stdio is open");
    fds[3..]
        .iter()
        .map(|fd| {
            let target = std::fs::read_link(format!("/proc/{pid}/fd/{fd}"))
                .expect("readlink")
                .display()
                .to_string();
            if target.starts_with("socket:") {
                "socket".to_string()
            } else {
                target
            }
        })
        .collect()
}

/// A request frame as the helper reads it: the id, then the token. Written by
/// hand here so the test can send what a well-behaved agent never would.
fn raw_request(id: u64) -> [u8; 24] {
    let mut frame = [0u8; 24];
    frame[..8].copy_from_slice(&id.to_le_bytes());
    frame[8..].copy_from_slice(&TOKEN);
    frame
}

/// Whether a reseed result is an answer from the helper: success, or the
/// kernel refusing an unprivileged caller. Anything else means the helper did
/// not answer.
fn assert_answered(result: Result<(), ReseedError>) {
    match result {
        Ok(()) => {}
        Err(ReseedError::Kernel {
            step: ReseedStep::AddEntropy,
            source,
        }) => assert_eq!(
            source.raw_os_error(),
            Some(libc::EPERM),
            "an unprivileged helper is refused by the kernel, not by its filter"
        ),
        Err(other) => panic!("the helper must answer: {other:?}"),
    }
}

/// The whole serve loop under the real seccomp filter, unprivileged, so every
/// CI lane — the aarch64 one included — runs the allowlist on its own
/// architecture. A filter installs with no-new-privileges alone, so nothing
/// here needs root.
///
/// The helper gets two frames carrying an id the agent has already moved past,
/// the second a duplicate of the first, then two ordinary requests. Every one of
/// them reaches the `random` ioctls, which refuse an unprivileged caller. The
/// agent discards the two stale answers, takes its own, and closes; the helper
/// must exit on its own with status 0. A syscall missing from the allowlist
/// shows up as the helper dying by `SIGSYS` rather than answering.
#[test]
fn the_confined_helper_answers_every_request_and_exits_cleanly() {
    use std::io::Write;
    use std::os::unix::process::ExitStatusExt;

    let _leaky = leaky_descriptor();
    let (stream, mut child) = HelperSpawn::new()
        .executable(AGENT)
        .spawn()
        .expect("spawn helper");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    (&stream).write_all(&raw_request(0)).expect("stale request");
    (&stream)
        .write_all(&raw_request(0))
        .expect("duplicate request");

    let mut connection = HelperConnection::new(stream);
    // The first real request is id 1: its answer arrives behind the two
    // answers for id 0, which must be read and discarded, not returned.
    assert_answered(connection.reseed(&TOKEN));
    assert_answered(connection.reseed(&TOKEN));
    drop(connection);

    let status = wait_for_exit(&mut child);
    assert_ne!(
        status.signal(),
        Some(libc::SIGSYS),
        "the helper was killed by its own seccomp filter: a syscall it makes on \
         this architecture is missing from the allowlist"
    );
    assert_eq!(
        status.code(),
        Some(0),
        "the helper must exit cleanly once the agent closes its end: {status:?}"
    );
}

/// The helper as PID 1 starts it: its own uid, only `CAP_SYS_ADMIN`, no
/// dumping, seccomp on, and nothing open but stdio, its socket and
/// `/dev/urandom`.
#[test]
fn the_helper_started_by_pid1_holds_only_what_it_needs() {
    if !privileged() {
        return;
    }
    let (_agent_dir, agent) = agent_binary_for_dropped_identity();
    let _leaky = leaky_descriptor();
    let (stream, mut child) = HelperSpawn::new()
        .executable(agent)
        .identity(CRNG_RESEED_HELPER_UID, CRNG_RESEED_HELPER_GID)
        .spawn()
        .expect("spawn helper");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut connection = HelperConnection::new(stream);
    connection
        .reseed(&TOKEN)
        .expect("a helper holding CAP_SYS_ADMIN reseeds");

    let pid = child.id();
    assert_eq!(status_field(pid, "CapEff"), "0000000000200000");
    assert_eq!(status_field(pid, "CapPrm"), "0000000000200000");
    assert_eq!(status_field(pid, "CapBnd"), "0000000000200000");
    assert_eq!(status_field(pid, "NoNewPrivs"), "1");
    assert_eq!(status_field(pid, "Seccomp"), "2");
    assert!(
        status_field(pid, "Uid").starts_with(&format!("{CRNG_RESEED_HELPER_UID}\t")),
        "the helper runs under its own uid"
    );
    assert_eq!(
        descriptors_above_stdio(pid),
        vec!["socket", "/dev/urandom"],
        "the helper holds its socket and the device it opened, and inherited nothing else"
    );

    drop(connection);
    assert!(wait_for_exit(&mut child).success());
}

/// The helper as a shell init starts it, through `mvm-setpriv` with the same
/// flags the image uses, listening on its fixed socket; the agent reaches it by
/// connecting and checking the peer.
#[test]
fn the_helper_started_by_a_shell_init_listens_and_is_trusted_by_uid() {
    if !privileged() {
        return;
    }
    let socket = std::path::Path::new(mvm_agentd::crng_reseed::HELPER_SOCKET);
    let dir = socket.parent().expect("socket directory");
    std::fs::create_dir_all(dir).expect("create socket directory");
    let agent_gid: u32 = 990;
    std::os::unix::fs::chown(dir, Some(CRNG_RESEED_HELPER_UID), Some(agent_gid)).unwrap();
    std::fs::set_permissions(dir, std::os::unix::fs::PermissionsExt::from_mode(0o750)).unwrap();

    let (_agent_dir, agent) = agent_binary_for_dropped_identity();
    let _leaky = leaky_descriptor();
    let mut child = std::process::Command::new(SETPRIV)
        .arg(format!("--reuid={CRNG_RESEED_HELPER_UID}"))
        .arg(format!("--regid={agent_gid}"))
        .args([
            "--clear-groups",
            "--securebits=keep-caps",
            "--inh-caps=+sys_admin",
            "--ambient-caps=+sys_admin",
            "--no-new-privs",
            "--",
        ])
        .arg(&agent)
        .args([
            mvm_agentd::crng_reseed::HELPER_ARG,
            mvm_agentd::crng_reseed::LISTEN_ARG,
        ])
        .spawn()
        .expect("spawn listening helper");
    let deadline = Instant::now() + Duration::from_secs(10);
    while !socket.exists() {
        assert!(
            Instant::now() < deadline,
            "the helper never bound its socket"
        );
        std::thread::sleep(Duration::from_millis(20));
    }

    // A connection that never sends must not hold the helper: it is dropped
    // at the helper's deadline and the agent's reseed behind it is served.
    let idle = std::os::unix::net::UnixStream::connect(socket).expect("idle connector");
    let result = mvm_agentd::crng_reseed::reseed_via_helper(&TOKEN);
    drop(idle);
    let pid = child.id();
    let mode = std::os::unix::fs::PermissionsExt::mode(
        &std::fs::metadata(socket)
            .expect("socket metadata")
            .permissions(),
    );
    let seccomp = status_field(pid, "Seccomp");
    let descriptors = descriptors_above_stdio(pid);
    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_file(socket);

    result.expect("the listening helper reseeds for a trusted connection");
    assert_eq!(mode & 0o777, 0o660, "only the owner and the agent's group");
    assert_eq!(seccomp, "2");
    assert_eq!(
        descriptors,
        vec!["/dev/urandom", "socket", "socket"],
        "the device, the listener and the agent's connection; nothing inherited from the init"
    );
}
