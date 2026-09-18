#![cfg(target_os = "linux")]

use std::collections::BTreeMap;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use mvm_agentd::process_rpc::{Caps, Registry, handle_proc_start, handle_proc_wait};
use mvm_agentd::vsock::{ProcResult, ProcWaitEvent};

const TEST_WRAPPER: &str = env!("CARGO_BIN_EXE_mvm-entrypoint-test-wrapper");

fn test_wrapper() -> String {
    std::env::var("MVM_ENTRYPOINT_TEST_WRAPPER").unwrap_or_else(|_| TEST_WRAPPER.to_string())
}

#[test]
fn process_rpc_child_inherits_only_its_standard_streams() {
    let listener_dir = tempfile::tempdir().expect("tempdir");
    let listener = std::os::unix::net::UnixListener::bind(listener_dir.path().join("agent.sock"))
        .expect("bind listener");
    // SAFETY: duplicating an open descriptor; the returned descriptor has no
    // close-on-exec flag and is owned by `_leaky` below.
    let leaky = unsafe { libc::fcntl(listener.as_raw_fd(), libc::F_DUPFD, 10) };
    assert!(
        leaky >= 10,
        "failed to create a deliberately inheritable fd"
    );
    // SAFETY: `leaky` was just returned by F_DUPFD and has no other owner.
    let _leaky = unsafe { OwnedFd::from_raw_fd(leaky) };

    let registry = Registry::new();
    let caps = Caps::default();
    let wrapper = test_wrapper();
    let started = handle_proc_start(
        &registry,
        &caps,
        &[wrapper, "--list-fds".to_string()],
        &BTreeMap::new(),
        None,
        b"",
    );
    let token = match started {
        ProcResult::Started { pid_token } => pid_token,
        other => panic!("expected process to start, got {other:?}"),
    };

    let mut events = Vec::new();
    let terminal = handle_proc_wait(&registry, &caps, &token, Some(5), |event| {
        events.push(event)
    });
    assert!(
        matches!(terminal, ProcWaitEvent::Exit { code: 0 }),
        "expected process to exit successfully, got {terminal:?}"
    );

    let listing: Vec<u8> = events
        .into_iter()
        .flat_map(|event| match event {
            ProcWaitEvent::Stdout { chunk } => chunk,
            _ => Vec::new(),
        })
        .collect();
    let listing = String::from_utf8(listing).expect("descriptor listing is UTF-8");
    for line in listing.lines() {
        let (fd, target) = line.split_once(' ').expect("`N TARGET`");
        let fd: u32 = fd.parse().expect("descriptor number");
        assert!(
            fd <= 2,
            "process RPC child inherited descriptor {fd} ({target}):\n{listing}"
        );
        assert!(
            !target.starts_with("socket:"),
            "process RPC child inherited a socket on {fd}:\n{listing}"
        );
    }
    for expected in 0..=2 {
        assert!(
            listing
                .lines()
                .any(|line| line.starts_with(&format!("{expected} "))),
            "descriptor {expected} must be present:\n{listing}"
        );
    }
}
