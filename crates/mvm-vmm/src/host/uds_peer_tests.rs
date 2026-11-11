//! Socket peer-identity witnesses, without a hypervisor or authorization service.

use super::connected_peer_pid;
use crate::host::process_exit::wait_for_test_child;
use mio::{Events, Interest, Poll, Token, unix::SourceFd};
use std::io::{Read, Write};
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::process::{Child, Stdio};
use std::time::{Duration, Instant};

const HELPER: &str = "host::uds_peer::process_tests::peer_process_helper";
const SOCKET_ENV: &str = "MVM_TEST_PEER_SOCKET";
const PARENT_ENV: &str = "MVM_TEST_PEER_PARENT";
const DEADLINE: Duration = Duration::from_secs(5);

struct PeerChild {
    child: Child,
    reaped: bool,
}

impl PeerChild {
    fn spawn(stdin: Stdio, socket: Option<&Path>) -> Self {
        let mut command = mvm_core::env_hygiene::helper_command(std::env::current_exe().unwrap());
        command
            .args(["--exact", HELPER, "--ignored", "--test-threads=1"])
            .env_remove(SOCKET_ENV)
            .env(PARENT_ENV, std::process::id().to_string())
            .stdin(stdin)
            .stdout(Stdio::null())
            .stderr(Stdio::inherit());
        if let Some(socket) = socket {
            command.env(SOCKET_ENV, socket);
        }
        Self {
            child: command.spawn().unwrap(),
            reaped: false,
        }
    }

    fn finish(&mut self) {
        let status = wait_for_test_child(&mut self.child, Instant::now() + DEADLINE)
            .unwrap()
            .expect("peer helper must exit before the deadline");
        self.reaped = true;
        assert!(status.success(), "peer helper failed: {status}");
    }
}

impl Drop for PeerChild {
    fn drop(&mut self) {
        if !self.reaped {
            let _ = self.child.kill();
            if !matches!(
                wait_for_test_child(&mut self.child, Instant::now() + DEADLINE),
                Ok(Some(_))
            ) {
                eprintln!("peer helper cleanup could not confirm its exit");
            }
        }
    }
}

fn read_child_id(stream: &mut UnixStream) -> u32 {
    stream.set_read_timeout(Some(DEADLINE)).unwrap();
    let mut bytes = [0; 4];
    stream.read_exact(&mut bytes).unwrap();
    u32::from_be_bytes(bytes)
}

#[test]
#[ignore = "subprocess entry point, not a standalone test"]
fn peer_process_helper() {
    let parent: i32 = std::env::var(PARENT_ENV).unwrap().parse().unwrap();
    // SAFETY: getppid reads this fixture process's kernel parent identity.
    assert_eq!(unsafe { libc::getppid() }, parent);
    let mut stream = match std::env::var_os(SOCKET_ENV) {
        Some(path) => {
            let stream = UnixStream::connect(path).unwrap();
            assert_eq!(connected_peer_pid(&stream).unwrap(), parent);
            stream
        }
        None => UnixStream::from(std::io::stdin().as_fd().try_clone_to_owned().unwrap()),
    };
    stream.set_write_timeout(Some(DEADLINE)).unwrap();
    stream.write_all(&std::process::id().to_be_bytes()).unwrap();
}

#[test]
fn a_fresh_connection_identifies_both_actual_processes() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("peer.sock");
    let listener = UnixListener::bind(&path).unwrap();
    listener.set_nonblocking(true).unwrap();
    let mut poll = Poll::new().unwrap();
    let fd = listener.as_raw_fd();
    poll.registry()
        .register(&mut SourceFd(&fd), Token(0), Interest::READABLE)
        .unwrap();
    let mut events = Events::with_capacity(1);
    let mut child = PeerChild::spawn(Stdio::null(), Some(&path));
    let deadline = Instant::now() + DEADLINE;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        assert!(!remaining.is_zero(), "peer connection deadline");
        match poll.poll(&mut events, Some(remaining)) {
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            result => result.unwrap(),
        }
        assert!(!events.is_empty(), "peer must connect before the deadline");
        break;
    }
    let (mut stream, _) = listener.accept().unwrap();
    stream.set_nonblocking(false).unwrap();
    let kernel_peer = connected_peer_pid(&stream).unwrap();
    let reported_child = read_child_id(&mut stream);
    child.finish();
    assert_eq!(reported_child, child.child.id());
    assert_eq!(kernel_peer, i32::try_from(reported_child).unwrap());
    assert_ne!(kernel_peer, i32::try_from(std::process::id()).unwrap());
    assert_eq!(stream.read(&mut [0]).unwrap(), 0);
    assert!(child.child.try_wait().unwrap().is_some());
    if let Ok(retained_peer) = connected_peer_pid(&stream) {
        assert_eq!(retained_peer, kernel_peer, "identity is not a live handle");
    }
}

#[test]
fn inherited_socketpair_peer_identity_depends_on_the_platform() {
    let (mut retained, inherited) = UnixStream::pair().unwrap();
    let inherited: OwnedFd = inherited.into();
    let mut child = PeerChild::spawn(Stdio::from(inherited), None);
    let reported_child = read_child_id(&mut retained);
    let kernel_peer = connected_peer_pid(&retained).unwrap();
    child.finish();
    assert_eq!(reported_child, child.child.id());
    #[cfg(target_os = "linux")]
    {
        assert_eq!(kernel_peer, i32::try_from(std::process::id()).unwrap());
        assert_ne!(kernel_peer, i32::try_from(reported_child).unwrap());
    }
    #[cfg(target_os = "macos")]
    assert_eq!(kernel_peer, i32::try_from(reported_child).unwrap());
}
