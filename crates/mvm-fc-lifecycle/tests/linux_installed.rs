#![cfg(target_os = "linux")]

use mvm_fc_lifecycle::protocol::{Operation, Request, Response};

fn explicitly_enabled() {
    assert_eq!(
        std::env::var("MVM_FC_LIFECYCLE_PRIVILEGED_TEST").as_deref(),
        Ok("1"),
        "requires a separately approved disposable Linux installation and running service"
    );
}

#[test]
#[ignore = "requires explicitly approved installed Linux service; never native host"]
fn installed_service_refuses_unknown_registration() {
    explicitly_enabled();
    // SAFETY: getuid only queries credentials. Root bypasses the prebody UID filter.
    assert_eq!(unsafe { libc::getuid() }, 0);
    let request: Request = serde_json::from_value(serde_json::json!({
        "version": 1, "operation": {
            "op": "query",
            "id": "0000000000000000000000000000000000000000000000000000000000000000"
        }
    }))
    .unwrap();
    assert!(matches!(
        mvm_fc_lifecycle::request(&request).unwrap(),
        Response::Refused
    ));
}

#[test]
#[ignore = "requires explicitly approved installed Linux service and non-root test peer"]
fn installed_service_refuses_invalid_non_root_payload_limited_witness() {
    explicitly_enabled();
    // SAFETY: a credential query with no side effects.
    assert_ne!(
        unsafe { libc::getuid() },
        0,
        "run this witness as an ordinary user"
    );
    let request = Request {
        version: 1,
        operation: Operation::Register {
            pid: i32::try_from(std::process::id()).unwrap(),
            owner_uid: 0,
            state_dir: "/nonexistent-mvm-fc-lifecycle".into(),
            api_socket: "/nonexistent-mvm-fc-lifecycle/api.sock".into(),
        },
    };
    // This is only an endpoint refusal witness, not proof that authorization
    // precedes identity checks. The positive-control test below supplies that.
    assert!(matches!(
        mvm_fc_lifecycle::request(&request),
        Err(_) | Ok(Response::Refused)
    ));
}

fn valid_candidate() -> Request {
    let value = |key| {
        std::env::var(key).expect("operator must supply an already-running trusted candidate")
    };
    Request {
        version: 1,
        operation: Operation::Register {
            pid: value("MVM_FC_TEST_PID").parse().unwrap(),
            owner_uid: value("MVM_FC_TEST_OWNER_UID").parse().unwrap(),
            state_dir: value("MVM_FC_TEST_STATE_DIR"),
            api_socket: value("MVM_FC_TEST_API_SOCKET"),
        },
    }
}

#[test]
#[ignore = "root-only positive control writes a real registration; requires separate approval"]
fn installed_valid_candidate_root_positive_then_non_root_refusal() {
    use std::os::unix::process::CommandExt;
    explicitly_enabled();
    // SAFETY: getuid only queries credentials.
    assert_eq!(unsafe { libc::getuid() }, 0);
    let request = valid_candidate();
    let Operation::Register { owner_uid, .. } = &request.operation else {
        panic!("register fixture");
    };
    assert_ne!(*owner_uid, 0);
    // Exactly this candidate must succeed before any non-root refusal counts.
    assert!(matches!(
        mvm_fc_lifecycle::request(&request).unwrap(),
        Response::Registered { .. }
    ));
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--ignored", "--exact", "non_root_valid_candidate_probe"])
        .env("MVM_FC_TEST_CHILD", "1")
        .uid(*owner_uid)
        .status()
        .unwrap();
    assert!(status.success());
}

#[test]
#[ignore = "invoked only as the dedicated non-root child of the positive-control witness"]
fn non_root_valid_candidate_probe() {
    explicitly_enabled();
    assert_eq!(std::env::var("MVM_FC_TEST_CHILD").as_deref(), Ok("1"));
    // SAFETY: getuid only queries credentials.
    assert_ne!(unsafe { libc::getuid() }, 0);
    assert!(matches!(
        mvm_fc_lifecycle::request(&valid_candidate()).unwrap(),
        Response::Refused
    ));
}
