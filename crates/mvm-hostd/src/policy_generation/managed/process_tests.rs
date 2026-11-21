use super::*;
use std::io::{Read, Write};
use std::os::unix::net::UnixListener;
use std::time::{Duration, Instant};

#[test]
fn direct_observation_binds_live_detached_socket_and_rejects_false_claims() {
    let directory = tempfile::tempdir().unwrap();
    let home = directory.path().canonicalize().unwrap();
    let socket = super::super::coordinator::socket_path(&home);
    std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
    let valid = CoordinatorStatus::of_this_process(&home, Lifetime::Detached);
    for case in 0..7 {
        let listener = UnixListener::bind(&socket).unwrap();
        let mut status = valid.clone();
        match case {
            0 => {}
            1 => status.home = home.join("wrong"),
            2 => status.protocol += 1,
            3 => status.pid += 1,
            4 => status.uid += 1,
            5 => {
                status.lifetime = Lifetime::Managed {
                    unit: "unverified".into(),
                    invocation: "00".repeat(16),
                }
            }
            6 => status.pid = 0,
            _ => unreachable!(),
        }
        std::thread::scope(|scope| {
            let responder = scope.spawn(|| {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut length = [0; 4];
                stream.read_exact(&mut length).unwrap();
                let mut request = vec![0; u32::from_be_bytes(length) as usize];
                stream.read_exact(&mut request).unwrap();
                assert!(matches!(
                    serde_json::from_slice::<super::super::coordinator::Request>(&request).unwrap(),
                    super::super::coordinator::Request::Status
                ));
                // Replacing the pathname must not cause a second connection.
                let replacement = if case == 0 {
                    std::fs::remove_file(&socket).unwrap();
                    Some(UnixListener::bind(&socket).unwrap())
                } else {
                    None
                };
                let response =
                    serde_json::to_vec(&super::super::coordinator::Response::Status { status })
                        .unwrap();
                stream
                    .write_all(&u32::try_from(response.len()).unwrap().to_be_bytes())
                    .unwrap();
                stream.write_all(&response).unwrap();
                replacement
            });
            let result = process_status(&home);
            if case == 0 {
                let observed = result.unwrap();
                assert_eq!(observed.pid, valid.pid);
                assert_eq!(observed.uid, valid.uid);
                assert_eq!(observed.home, home);
            } else {
                assert!(result.is_err(), "accepted case {case}");
            }
            if let Some(replacement) = responder.join().unwrap() {
                replacement.set_nonblocking(true).unwrap();
                assert_eq!(
                    replacement.accept().unwrap_err().kind(),
                    std::io::ErrorKind::WouldBlock
                );
            }
        });
        std::fs::remove_file(&socket).unwrap();
    }
}

#[test]
fn direct_observation_never_creates_missing_state_or_starts_stopped_socket() {
    let directory = tempfile::tempdir().unwrap();
    let home = directory.path().canonicalize().unwrap();
    assert!(process_status(&home.join("missing")).is_err());
    assert!(process_status(&home).is_err());
    assert_eq!(std::fs::read_dir(&home).unwrap().count(), 0);
    let socket = super::super::coordinator::socket_path(&home);
    std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
    drop(UnixListener::bind(&socket).unwrap());
    assert!(process_status(&home).is_err());
    assert!(socket.exists());
}

#[test]
fn direct_observation_refuses_expired_budget_before_connecting() {
    let directory = tempfile::tempdir().unwrap();
    let home = directory.path().canonicalize().unwrap();
    let error = process_status_until(&home, Instant::now()).unwrap_err();
    assert!(error.to_string().contains("deadline"));
    assert_eq!(std::fs::read_dir(home).unwrap().count(), 0);
}

#[test]
fn direct_observation_requires_a_usable_same_user_kernel_peer() {
    let uid = rustix::process::geteuid().as_raw();
    assert!(require_observation_peer(PeerProcess { pid: 0, uid }).is_err());
    assert!(
        require_observation_peer(PeerProcess {
            pid: std::process::id(),
            uid: uid.wrapping_add(1),
        })
        .is_err()
    );
    assert!(
        require_observation_peer(PeerProcess {
            pid: std::process::id(),
            uid,
        })
        .is_ok()
    );
}

#[test]
fn direct_observation_refuses_noncanonical_or_nondirectory_home() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    let home = root.join("home");
    std::fs::create_dir(&home).unwrap();
    let alias = root.join("alias");
    std::os::unix::fs::symlink(&home, &alias).unwrap();
    assert!(process_status(&alias).is_err());
    let file = root.join("file");
    std::fs::write(&file, []).unwrap();
    assert!(process_status(&file).is_err());
    assert_eq!(std::fs::read_dir(home).unwrap().count(), 0);
}
