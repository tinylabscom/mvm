//! Real process witness for the inherited actor authority socket and sealed guest channel.

use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::Child;
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use mvm_contract::protocol::workload_actor::{ActorRequest, ActorResponse};
use mvm_core::net::actor_session::{
    ActorDeadlineStream, ActorSession, ActorSessionBinding, read_actor_request,
    write_actor_response,
};
use mvm_hostd::actor_holder::{ActorHolderConfig, spawn};

struct OwnedChild(Child);

impl Drop for OwnedChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn actor_holder_contract_probe_needs_no_inherited_actor_sockets() {
    use mvm_core::helper_contract::{CONTRACT_PROBE_FLAG, HOST_HELPER_CONTRACT_VERSION};

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_mvm-actor-holder"))
        .arg(CONTRACT_PROBE_FLAG)
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "probe entered holder startup: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        format!("mvm-actor-holder contract-version={HOST_HELPER_CONTRACT_VERSION}\n")
    );
}

#[test]
fn actor_holder_process_authenticates_before_forwarding_to_private_authority() {
    let directory = tempfile::tempdir().unwrap();
    let guest_key = SigningKey::from_bytes(&[21; 32]);
    let host_key = SigningKey::from_bytes(&[22; 32]);
    let binding = ActorSessionBinding {
        protocol_version: 1,
        purpose: "host.actor.v1".into(),
        tenant: "tenant".into(),
        workflow: "workflow".into(),
        boot_id: "boot".into(),
        plan_digest: [23; 32],
        epoch: 1,
        controller_generation: 1,
        key_generation: 1,
        guest_public_key: guest_key.verifying_key().to_bytes(),
        host_public_key: host_key.verifying_key().to_bytes(),
    };
    let path = directory.path().join("holder.sock");
    let config = ActorHolderConfig {
        binding: binding.clone(),
        host_seed: host_key.to_bytes(),
        listen_socket: path.clone(),
    };
    let (authority, private) = UnixStream::pair().unwrap();
    let mut child = OwnedChild(
        spawn(
            Path::new(env!("CARGO_BIN_EXE_mvm-actor-holder")),
            config,
            private,
        )
        .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut authority = ActorDeadlineStream::new(authority, deadline).unwrap();
    let mut guest = ActorDeadlineStream::new(UnixStream::connect(path).unwrap(), deadline).unwrap();
    let mut session = ActorSession::guest(&mut guest, &binding, guest_key).unwrap();
    let request = ActorRequest::decode(
        br#"{"version":1,"operation":{"operation":"launch","grant_id":"g","template_id":"t","idempotency_key":"i"}}"#,
    ).unwrap();
    session.send_request(&mut guest, &request).unwrap();
    assert_eq!(read_actor_request(&mut authority).unwrap(), request);
    let response =
        ActorResponse::decode(br#"{"version":1,"outcome":{"status":"refused","code":"capacity"}}"#)
            .unwrap();
    write_actor_response(&mut authority, &response).unwrap();
    assert_eq!(session.receive_response(&mut guest).unwrap(), response);
    assert!(child.0.try_wait().unwrap().is_none());
}
