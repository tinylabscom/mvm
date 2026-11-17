//! Process-crash witness, not a production helper restart supervisor.

use ed25519_dalek::SigningKey;
use mvm_contract::protocol::mailbox::{
    ContentType, CorrelationId, DeliveryAckNonce, MailboxDeliveryAck, MessageId, ProtocolVersion,
    SignatureAlgorithm, SignedMailboxDeliveryLease,
};
use mvm_contract::protocol::workload_actor::{ParentIdentity, WorkflowRole};
use mvm_core::mailbox::conversation_wire::{
    self, ConversationBinding, ConversationInvocation, ConversationRequest, ConversationResponse,
};
use mvm_core::mailbox::reader::{sign_delivery_ack, sign_reader_possession};
use mvm_hostd::actor_lifecycle::ActorMailboxes as _;
use mvm_hostd::mailbox_process::MailboxProcessConfig;
use std::io::{Read as _, Write as _};
use std::os::fd::AsRawFd as _;
use std::os::unix::net::{UnixListener, UnixStream};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

const WAIT: Duration = Duration::from_secs(10);

/// Retain the original process handle through kill and reap, including on panic.
struct Helper(Option<Child>);

impl Helper {
    fn spawn(original_config: &[u8]) -> Self {
        let mut owner = Self(Some(
            Command::new(env!("CARGO_BIN_EXE_mvm-mailbox"))
                .env_clear()
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .unwrap(),
        ));
        let child = owner.0.as_mut().unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(original_config)
            .unwrap();
        let mut stdout = child.stdout.take().unwrap();
        let (send, receive) = std::sync::mpsc::sync_channel(1);
        let reader = std::thread::spawn(move || {
            let mut ready = [0; 6];
            let _ = send.send(stdout.read_exact(&mut ready).map(|()| ready));
        });
        let ready = receive.recv_timeout(WAIT);
        if ready.is_err() {
            owner.kill_and_reap();
        }
        reader.join().unwrap();
        assert_eq!(ready.unwrap().unwrap(), *b"READY\n");
        owner
    }

    fn kill_and_reap(&mut self) {
        if let Some(mut child) = self.0.take() {
            if child.try_wait().unwrap().is_none() {
                child.kill().unwrap();
            }
            child.wait().unwrap();
        }
    }

    fn crash(&mut self) {
        let child = self.0.as_mut().unwrap();
        assert!(
            child.try_wait().unwrap().is_none(),
            "helper must be live at the crash point"
        );
        child.kill().unwrap();
        assert!(!child.wait().unwrap().success());
        self.0 = None;
    }
}

impl Drop for Helper {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

struct Guest {
    listener: UnixListener,
    binding: ConversationBinding,
    ack: SigningKey,
}

impl Guest {
    fn new(config: &MailboxProcessConfig, ack_seed: u8) -> Self {
        let mvm_core::vm_backend::HostDialRoute::PortSocket(path) = &config.route else {
            panic!("fixture requires its own Unix listener")
        };
        let listener = UnixListener::bind(path).unwrap();
        listener.set_nonblocking(true).unwrap();
        let material = config.actor.as_ref().unwrap();
        Self {
            listener,
            binding: ConversationBinding {
                reader: config.reader_boot.clone().unwrap(),
                address: material.address,
                policy_epoch: material.template.capability.policy_epoch,
            },
            ack: SigningKey::from_bytes(&[ack_seed; 32]),
        }
    }

    fn connect(&self) -> UnixStream {
        let mut event = libc::pollfd {
            fd: self.listener.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: event points to one initialized pollfd for this live listener.
        assert_eq!(unsafe { libc::poll(&mut event, 1, 10_000) }, 1);
        let (stream, _) = self.listener.accept().unwrap();
        // Accepted sockets can inherit the listener's nonblocking flag on macOS.
        stream.set_nonblocking(false).unwrap();
        stream.set_read_timeout(Some(WAIT)).unwrap();
        stream.set_write_timeout(Some(WAIT)).unwrap();
        stream
    }

    fn request(&self, request: ConversationRequest) -> ConversationResponse {
        let operation = match &request {
            ConversationRequest::Call { .. } => "Call",
            ConversationRequest::Receive { .. } => "Receive",
            ConversationRequest::Reply { .. } => "Reply",
            ConversationRequest::ReceiveResult { .. } => "ReceiveResult",
            ConversationRequest::AckResult { .. } => "AckResult",
            ConversationRequest::AckRequest { .. } => "AckRequest",
            ConversationRequest::Possession { .. } => "Possession",
        };
        let invocation = ConversationInvocation::new(request, WAIT).unwrap();
        let encoded = serde_json::to_vec(&invocation).unwrap();
        serde_json::from_slice::<ConversationInvocation>(&encoded)
            .unwrap_or_else(|error| panic!("{operation} fixture wire shape: {error}"));
        let mut stream = self.connect();
        let mut session =
            conversation_wire::guest_session(&mut stream, &self.binding, self.ack.clone()).unwrap();
        conversation_wire::send_invocation(&mut stream, &mut session, &invocation).unwrap();
        let (enrollment, challenge) =
            match conversation_wire::receive_response(&mut stream, &mut session).unwrap() {
                ConversationResponse::Challenge {
                    enrollment,
                    challenge,
                    ..
                } => (enrollment, challenge),
                ConversationResponse::Refused { reason } => {
                    panic!("{operation}: refused before possession challenge: {reason:?}")
                }
                response => panic!(
                    "{operation}: expected possession challenge, got {:?}",
                    std::mem::discriminant(&response)
                ),
            };
        let signature = sign_reader_possession(&enrollment, &challenge, &self.ack).unwrap();
        conversation_wire::send_request(
            &mut stream,
            &mut session,
            &ConversationRequest::Possession {
                signature: signature.to_vec(),
            },
        )
        .unwrap();
        conversation_wire::receive_response(&mut stream, &mut session).unwrap()
    }

    fn acknowledge(
        &self,
        lease: &SignedMailboxDeliveryLease,
    ) -> Box<mvm_contract::protocol::mailbox::SignedMailboxDeliveryAck> {
        Box::new(
            sign_delivery_ack(
                MailboxDeliveryAck {
                    protocol_version: ProtocolVersion::V1,
                    signature_algorithm: SignatureAlgorithm::ED25519,
                    lease: lease.clone(),
                    ack_nonce: DeliveryAckNonce::from_bytes([70; 16]),
                    acknowledged_at_unix_ms: lease.lease.issued_at_unix_ms,
                },
                &self.ack,
            )
            .unwrap(),
        )
    }

    fn discard_dead_connections(&self) {
        // The killed helper can have queued its next connection before the crash.
        // Drain only already-accepted backlog; this is not a timed readiness poll.
        for _ in 0..4 {
            match self.listener.accept() {
                Ok((stream, _)) => drop(stream),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return,
                Err(error) => panic!("drain test listener: {error}"),
            }
        }
        panic!("unexpected helper connection backlog");
    }
}

#[test]
fn actor_response_survives_helper_process_crash_before_signed_ack() {
    const MARKER: &str = "MVM_TEST_ACTOR_CRASH_CHILD";
    if std::env::var_os(MARKER).is_none() {
        // Canonical peer paths read MVM_HOME. Scope it to this subprocess,
        // never change the environment of the parallel integration-test runner.
        let home = tempfile::tempdir_in("/tmp").unwrap();
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "actor_crash::actor_response_survives_helper_process_crash_before_signed_ack",
                "--nocapture",
            ])
            .env(MARKER, "1")
            .env("MVM_HOME", home.path());
        let output = mvm_core::bounded_run::run_bounded(
            command,
            mvm_core::bounded_run::RunBounds::new(Duration::from_secs(90), 32 * 1024),
        )
        .unwrap();
        assert!(
            output.status.success(),
            "isolated process witness failed:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }

    let fixture = super::actor_fixture(std::path::Path::new(&mvm_core::config::mvm_home()));
    let parent_config = super::actor_process_config(&fixture.home, &fixture.plan, 44);
    let mut child_plan = fixture.plan.clone();
    child_plan.workload.0 = "crash-child".into();
    child_plan.image.name = child_plan.workload.0.clone();
    let WorkflowRole::Controller { grant } = &fixture.plan.workflow.as_ref().unwrap().role else {
        panic!("controller fixture")
    };
    child_plan.workflow.as_mut().unwrap().role = WorkflowRole::Worker {
        parent: ParentIdentity {
            controller: grant.controller.clone(),
            plan_id: fixture.plan.plan_id.clone(),
        },
    };
    child_plan.mailbox = Some(
        fixture
            .owner
            .derive(&fixture.plan, &child_plan)
            .unwrap()
            .grant,
    );
    child_plan.plan_id = mvm_core::plan::compute_plan_id(&child_plan);
    let child_config = super::actor_process_config(&fixture.home, &child_plan, 46);
    let parent_guest = Guest::new(&parent_config, 44);
    let child_guest = Guest::new(&child_config, 46);
    // Serialize once: restart consumes these exact original keys and actor material.
    let parent_bytes = serde_json::to_vec(&parent_config).unwrap();
    let child_bytes = serde_json::to_vec(&child_config).unwrap();
    let _child = Helper::spawn(&child_bytes);
    let mut parent = Helper::spawn(&parent_bytes);
    let call = MessageId::from_bytes([40; 32]);
    let reply = MessageId::from_bytes([41; 32]);
    let correlation = CorrelationId::from_bytes([42; 32]);
    let content_type = ContentType::parse("application/vnd.mvm.actor-test", 1).unwrap();
    assert_eq!(
        parent_guest.request(ConversationRequest::Call {
            destination: child_guest.binding.address,
            message_id: call,
            correlation_id: correlation,
            deadline_unix_ms: fixture.plan.valid_until.timestamp_millis() - 1000,
            content_type: content_type.clone(),
            payload: b"durable-call".to_vec(),
        }),
        ConversationResponse::Queued {
            call_message_id: call
        }
    );
    let ConversationResponse::Delivery { lease, .. } =
        child_guest.request(ConversationRequest::Receive {})
    else {
        panic!("child did not receive the call")
    };
    assert_eq!(
        child_guest.request(ConversationRequest::AckRequest {
            request_message_id: call,
            signed: Some(child_guest.acknowledge(&lease)),
            lease,
        }),
        ConversationResponse::Acknowledged
    );
    assert_eq!(
        child_guest.request(ConversationRequest::Reply {
            request_message_id: call,
            message_id: reply,
            content_type,
            payload: b"durable-response".to_vec(),
        }),
        ConversationResponse::Queued {
            call_message_id: call
        }
    );
    let read = ConversationRequest::ReceiveResult {
        call_message_id: call,
    };
    let original = parent_guest.request(read.clone());
    let ConversationResponse::Delivery {
        header,
        lease,
        payload,
    } = &original
    else {
        panic!("parent did not durably accept the response")
    };
    assert_eq!(header.message_id, reply);
    assert_eq!(header.correlation_id, correlation);
    assert_eq!(payload, b"durable-response");
    assert_eq!(lease.lease.message_id, reply);

    // No parent ACK has been constructed or sent. Kill and reap the retained
    // original Child, then restart the actual binary without deriving anything.
    parent.crash();
    parent_guest.discard_dead_connections();
    let _restarted = Helper::spawn(&parent_bytes);
    assert!(serde_json::to_vec(&parent_config).unwrap() == parent_bytes);
    let replay = parent_guest.request(read.clone());
    assert_eq!(
        replay, original,
        "unexpired lease and ciphertext commitment must replay exactly"
    );
    let signed = parent_guest.acknowledge(lease);
    assert_eq!(
        parent_guest.request(ConversationRequest::AckResult {
            call_message_id: call,
            result_message_id: reply,
            lease: lease.clone(),
            signed: Some(signed),
        }),
        ConversationResponse::Acknowledged
    );
    assert_eq!(parent_guest.request(read), ConversationResponse::Settled);
}
