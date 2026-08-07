//! Serving one node-control connection.
//!
//! This is where the transport meets the decision, and the only thing it
//! contributes is the caller's identity — read from the kernel before a
//! single byte of the request is parsed, so no field of the message can
//! influence who the message is from.
//!
//! Binding a listener, its directory mode, and its lifetime belong to
//! whichever host process owns the node's state. There is no such process
//! yet: the node-control surface is per-node and the daemons that exist are
//! per-VM and per-tenant, so hosting it in one of those would put it at the
//! wrong granularity and have to be undone.

use std::os::unix::net::UnixStream;

use libkrun_sys::framing::{FrameError, read_json_frame_sync, write_json_frame_sync_capped};

use super::caller::peer_identity;
use super::limits::{MAX_REQUEST_FRAME_BYTES, MAX_RESPONSE_FRAME_BYTES};
use super::service::NodeControl;
use super::wire::{NodeControlEnvelope, NodeControlResponse, Refusal};

/// Read one request from `stream`, answer it, and write the answer back.
///
/// A request that does not parse is answered with a refusal rather than by
/// dropping the connection: a caller that gets silence cannot tell a
/// rejected message from a dead node.
pub fn serve_connection(
    node: &NodeControl,
    stream: &mut UnixStream,
) -> Result<NodeControlResponse, FrameError> {
    let caller = peer_identity(stream)?;
    let response =
        match read_json_frame_sync::<_, NodeControlEnvelope>(stream, MAX_REQUEST_FRAME_BYTES) {
            Ok(envelope) => node.handle(&caller, &envelope),
            Err(FrameError::Io(err)) => return Err(FrameError::Io(err)),
            Err(err) => NodeControlResponse::Refused(Refusal::malformed(err.to_string())),
        };
    write_json_frame_sync_capped(stream, &response, MAX_RESPONSE_FRAME_BYTES)?;
    Ok(response)
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::net::Ipv4Addr;

    use mvm_net::channel::VmInstanceIdentity;
    use mvm_net::lease::{LeaseRequest, LocalLeaseAuthority, NetworkLease};

    use crate::netd::ForwardingCapabilities;

    use super::super::registry::{MachineRecord, NodeRegistry};
    use super::super::wire::{
        DescribeMachine, NodeControlRequest, NodeControlResponse, RefusalReason,
    };
    use super::*;

    const NOW: u64 = 1_000_000;

    fn lease(instance: &VmInstanceIdentity) -> NetworkLease {
        LocalLeaseAuthority::new(&instance.node_id, [7u8; 32]).issue(&LeaseRequest {
            instance,
            tenant_id: "default",
            ipv4: Ipv4Addr::new(10, 201, 0, 6),
            gateway_ipv4: Ipv4Addr::new(10, 201, 0, 5),
            dns_name: None,
            routes: &[],
            ingress: &[],
            egress_policy_digest: "sha256:egress",
            policy_epoch: 1,
            now_millis: NOW,
        })
    }

    /// A node holding one machine owned by a uid that is not this process.
    /// The connection's credential is this process's, so the request below
    /// arrives from a caller that owns nothing here.
    fn node_owned_by_a_stranger() -> NodeControl {
        // SAFETY: `getuid` cannot fail and takes no arguments.
        let me = unsafe { libc::getuid() };
        let instance = VmInstanceIdentity::new("node-1", "vm-a", "boot-1", "sha256:plan");
        let lease = lease(&instance);
        let mut registry = NodeRegistry::new("node-1");
        registry
            .register(MachineRecord {
                instance,
                lease,
                owner_uid: me.wrapping_add(1),
                registered_at_millis: NOW,
            })
            .expect("register");
        NodeControl::new(registry, ForwardingCapabilities::USERSPACE_SOCKETS)
    }

    fn ask_over_a_socket(node: &NodeControl, request: NodeControlRequest) -> NodeControlResponse {
        let (mut host, mut client) = UnixStream::pair().expect("socket pair");
        let envelope = NodeControlEnvelope::current(request);
        std::thread::scope(|scope| {
            let sent = scope.spawn(move || {
                write_json_frame_sync_capped(&mut client, &envelope, MAX_REQUEST_FRAME_BYTES)
                    .expect("send");
                read_json_frame_sync::<_, NodeControlResponse>(
                    &mut client,
                    MAX_RESPONSE_FRAME_BYTES,
                )
                .expect("receive")
            });
            serve_connection(node, &mut host).expect("serve");
            sent.join().expect("client thread")
        })
    }

    /// The end-to-end form of the ownership witness: the identity comes off
    /// the connection, and the machine registered under a different uid is
    /// refused even though the caller named it exactly.
    #[test]
    fn a_request_over_a_socket_is_scoped_to_the_connections_own_credential() {
        let response = ask_over_a_socket(
            &node_owned_by_a_stranger(),
            NodeControlRequest::DescribeMachine(DescribeMachine {
                vm_id: "vm-a".to_string(),
            }),
        );
        assert_eq!(
            response,
            NodeControlResponse::Refused(Refusal::not_found()),
            "the caller's uid is not the registrant's, so the machine is not \
             the caller's to be told about"
        );
    }

    /// A body this node cannot parse gets an answer, not a hang-up.
    #[test]
    fn an_unparseable_request_is_refused_rather_than_dropped() {
        let (mut host, mut client) = UnixStream::pair().expect("socket pair");
        let body = br#"{"version":1,"request":{"kind":"describe_node"},"extra":1}"#;
        let len = u32::try_from(body.len()).expect("length");
        std::thread::scope(|scope| {
            let sent = scope.spawn(move || {
                client.write_all(&len.to_be_bytes()).expect("prefix");
                client.write_all(body).expect("body");
                read_json_frame_sync::<_, NodeControlResponse>(
                    &mut client,
                    MAX_RESPONSE_FRAME_BYTES,
                )
                .expect("receive")
            });
            serve_connection(&node_owned_by_a_stranger(), &mut host).expect("serve");
            let response = sent.join().expect("client thread");
            let NodeControlResponse::Refused(refusal) = response else {
                panic!("an unparseable request must be refused: {response:?}");
            };
            assert_eq!(refusal.reason, RefusalReason::Malformed);
        });
    }

    /// A hostile length prefix must be refused on the cap, before a body
    /// buffer is allocated for it.
    #[test]
    fn an_oversized_length_prefix_is_refused_before_the_body_is_allocated() {
        let (mut host, mut client) = UnixStream::pair().expect("socket pair");
        std::thread::scope(|scope| {
            let sent = scope.spawn(move || {
                client
                    .write_all(&u32::MAX.to_be_bytes())
                    .expect("hostile prefix");
                read_json_frame_sync::<_, NodeControlResponse>(
                    &mut client,
                    MAX_RESPONSE_FRAME_BYTES,
                )
                .expect("receive")
            });
            serve_connection(&node_owned_by_a_stranger(), &mut host).expect("serve");
            let response = sent.join().expect("client thread");
            let NodeControlResponse::Refused(refusal) = response else {
                panic!("an oversized frame must be refused: {response:?}");
            };
            assert_eq!(refusal.reason, RefusalReason::Malformed);
            assert!(
                refusal.detail.contains("exceeds cap"),
                "the refusal must name the cap it tripped: {}",
                refusal.detail
            );
        });
    }
}
