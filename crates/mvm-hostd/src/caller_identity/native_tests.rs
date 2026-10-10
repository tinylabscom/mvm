//! Opt-in witness. Every OS operation addresses one fresh test-only namespace.
//! Use the real user's HOME only for this ignored native-store witness; keep
//! MVM_HOME and Cargo state isolated. A fake HOME can hide the user keychain.
//! Never run unrelated HOME-sensitive tests as part of this explicit exception.
use super::*;
use std::process::Command;
use std::sync::mpsc;
use std::time::{Duration, Instant};

const CHILD: &str = "caller_identity::native_tests::native_child";
struct TestStore(String);
impl Store for TestStore {
    fn read(&self, account: &str) -> Result<Zeroizing<Vec<u8>>> {
        macos::read_at(&self.0, &format!("test:{account}"))
    }
    fn create(&self, account: &str, seed: &[u8]) -> Result<()> {
        macos::create_at(&self.0, &format!("test:{account}"), seed)
    }
}
fn service(namespace: Uuid) -> String {
    format!("com.tinylabs.mvm.test.entrypoint-caller.v1.{namespace}")
}
fn invoke(
    namespace: Uuid,
    operation: &str,
    pin: Option<&EnrolledIdentity>,
) -> std::process::Output {
    let mut child = Command::new(std::env::current_exe().unwrap());
    child.args(["--exact", CHILD, "--ignored", "--nocapture"]);
    child.env("MVM_NATIVE_CALLER_TEST_NAMESPACE", namespace.to_string());
    child.env("MVM_NATIVE_CALLER_TEST_OPERATION", operation);
    if let Some(pin) = pin {
        // Exclusively the public enrollment record, never a secret.
        child.env(
            "MVM_NATIVE_CALLER_TEST_PIN",
            serde_json::to_string(pin).unwrap(),
        );
    } else {
        child.env_remove("MVM_NATIVE_CALLER_TEST_PIN");
    }
    child.output().expect("run native credential witness child")
}
struct Cleanup(Uuid);
impl Drop for Cleanup {
    fn drop(&mut self) {
        let deleted = invoke(self.0, "delete", None).status.success();
        let absent = invoke(self.0, "absent", None).status.success();
        if !deleted || !absent {
            eprintln!(
                "NATIVE TEST CLEANUP FAILED: service={} account=test:{}",
                service(self.0),
                account(self.0).unwrap()
            );
        }
        assert!(deleted && absent, "exact owned native test item may remain");
    }
}

#[test]
#[ignore = "requires explicit authorization for a fresh native test credential"]
fn native_cross_process_enroll_read_delete() {
    assert_eq!(std::env::var("MVM_NATIVE_CALLER_TEST").as_deref(), Ok("1"));
    let namespace = Uuid::new_v4();
    println!(
        "native test service={} account=test:{}",
        service(namespace),
        account(namespace).unwrap()
    );
    assert!(
        invoke(namespace, "absent", None).status.success(),
        "test namespace must start absent"
    );
    let cleanup = Cleanup(namespace);
    let created = invoke(namespace, "create", None);
    assert!(
        created.status.success(),
        "native enrollment failed; child diagnostics withheld"
    );
    let text = String::from_utf8(created.stdout).unwrap();
    let encoded = text
        .lines()
        .find_map(|line| line.split_once("PUBLIC_IDENTITY=").map(|(_, value)| value))
        .expect("native child returned public enrollment");
    let identity: EnrolledIdentity = serde_json::from_str(encoded).unwrap();
    assert!(
        invoke(namespace, "read", Some(&identity)).status.success(),
        "separate-process pinned load failed"
    );
    let mut wrong = identity.clone();
    wrong.public_key[0] ^= 1;
    assert!(
        invoke(namespace, "wrong-pin", Some(&wrong))
            .status
            .success(),
        "wrong pin was not refused"
    );
    assert!(
        invoke(namespace, "duplicate", None).status.success(),
        "enrollment replaced an existing key"
    );
    assert!(
        invoke(namespace, "read", Some(&identity)).status.success(),
        "original identity changed"
    );
    drop(cleanup);
    println!("native cross-process deletion verified");
}

#[test]
#[ignore = "internal subprocess of the authorized native witness"]
fn native_child() {
    let namespace =
        Uuid::parse_str(&std::env::var("MVM_NATIVE_CALLER_TEST_NAMESPACE").unwrap()).unwrap();
    assert!(!namespace.is_nil());
    let operation = std::env::var("MVM_NATIVE_CALLER_TEST_OPERATION").unwrap();
    let service = service(namespace);
    let account = format!("test:{}", account(namespace).unwrap());
    let deadline = Instant::now() + Duration::from_secs(5);
    match operation.as_str() {
        "delete" => {
            let (reply, result) = mpsc::sync_channel(1);
            std::thread::spawn(move || {
                let _ = reply.send(macos::delete_test_entry(&service, &account));
            });
            assert_eq!(result.recv_timeout(Duration::from_secs(5)).unwrap(), Ok(()));
        }
        "absent" => {
            let (reply, result) = mpsc::sync_channel(1);
            std::thread::spawn(move || {
                let outcome = match macos::read_at(&service, &account) {
                    Err(IdentityError::Missing) => Ok(()),
                    Err(error) => Err(error),
                    Ok(_) => Err(IdentityError::Conflict),
                };
                let _ = reply.send(outcome);
            });
            let outcome = result.recv_timeout(Duration::from_secs(5)).unwrap();
            println!("native absence category: {outcome:?}");
            assert_eq!(outcome, Ok(()));
        }
        "create" | "duplicate" => {
            let client = IdentityClient::start(Box::new(TestStore(service))).unwrap();
            let result = client.enroll(namespace, deadline).unwrap().wait();
            if operation == "duplicate" {
                assert!(matches!(result, Err(IdentityError::Conflict)));
            } else {
                let credential = result.expect("native enrollment refused");
                println!(
                    "PUBLIC_IDENTITY={}",
                    serde_json::to_string(&credential.identity()).unwrap()
                );
            }
        }
        "read" | "wrong-pin" => {
            let identity: EnrolledIdentity =
                serde_json::from_str(&std::env::var("MVM_NATIVE_CALLER_TEST_PIN").unwrap())
                    .unwrap();
            assert_eq!(identity.installation, namespace);
            let client = IdentityClient::start(Box::new(TestStore(service))).unwrap();
            let result = client.load(&identity, deadline).unwrap().wait();
            if operation == "wrong-pin" {
                assert!(matches!(result, Err(IdentityError::Conflict)));
            } else {
                assert_eq!(
                    result.expect("native load refused").identity(),
                    identity
                );
            }
        }
        _ => panic!("unknown native witness operation"),
    }
}
