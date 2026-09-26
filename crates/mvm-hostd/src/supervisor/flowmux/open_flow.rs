//! The open-a-flow decision for one guest `OpenTcp`.
//!
//! A guest names a destination. This module decides first whether that
//! destination may be reached at all — the claim-10 gate, the single decision
//! point — and only then how the flow is served: terminated on the host so a
//! bound credential can be substituted into the request, relayed opaquely, or
//! refused. The order is the point. The shape of a flow is only ever chosen
//! against a destination admission has already allowed.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::os::unix::net::UnixStream;
use std::sync::Arc;

use mvm_vmm::vsock_egress_bridge::egress_gate::{EgressVerdict, Route};
use tracing::warn;

use super::socket::FlowSocket;
use super::tcp_relay::connect_first_admitted;
use super::wire::{lock_registry, parse_host_port};
use super::{FlowMuxError, FlowMuxSession, registry};
use crate::supervisor::audit_recorder::EventCategory;
use crate::supervisor::network_endpoint_proxy::TerminationMode;
use crate::supervisor::terminator;

/// One `OpenTcp` the claim-10 gate admitted: what the guest named, and what
/// the gate decided about it. Carried between admission and whichever way the
/// flow is then served, so neither half re-derives the other's facts.
struct AdmittedFlow {
    /// The `host:port` exactly as the guest wrote it, for the audit label.
    target: String,
    /// The host half of that target — what a secret binding is checked
    /// against, and the authority a terminated request must agree with.
    host: String,
    /// Which policy namespace decided the flow. Kept typed rather than as its
    /// label, because one of the two values decides whether the flow may be
    /// terminated at all.
    route: Route,
    /// Every address the gate admitted, in its order.
    ips: Vec<IpAddr>,
    /// The admitted port, which the gate may have chosen rather than taken
    /// from the target.
    port: u16,
}

impl AdmittedFlow {
    /// Render the admitted addresses as one audit label value.
    fn resolved_ips(&self) -> String {
        FlowMuxSession::format_ips(&self.ips)
    }

    /// The audit-label form of the route.
    fn route_label(&self) -> String {
        self.route.as_str().to_string()
    }

    /// Whether this flow may be served by terminating it on the host.
    ///
    /// Only an egress-routed flow may. A peer route's admitted address *is*
    /// the translation — the gate rewrites `<name>.mvm.peer:<port>` to the
    /// peer's local ingress mapping, and the name resolves nowhere — so a
    /// terminated peer flow would discard the one fact that made it
    /// reachable and re-originate by an unresolvable name. A peer flow
    /// therefore falls through to the opaque path, where a bound destination
    /// is refused at open.
    fn may_terminate(&self) -> bool {
        matches!(self.route, Route::Egress)
    }
}

/// How a terminated flow was terminated, as an audit label. Metadata about
/// which flow was decided and how, never anything from inside it.
fn termination_label(mode: TerminationMode) -> &'static str {
    match mode {
        TerminationMode::Tls => "tls",
        TerminationMode::Cleartext => "cleartext",
    }
}

impl FlowMuxSession {
    /// Serve one guest `OpenTcp`.
    ///
    /// Admission first — rate, then the claim-10 gate, which is the single
    /// decision point about whether this destination may be reached at all.
    /// Only then does the flow's *shape* get decided: a destination carrying a
    /// bound secret is terminated on the host so the credential can be
    /// substituted into the request, and everything else is relayed opaquely.
    /// A bound destination this endpoint cannot terminate stays refused rather
    /// than being relayed, because relaying it would put a placeholder on the
    /// wire to a real upstream. A peer-routed flow is never terminated at all —
    /// see [`AdmittedFlow::may_terminate`].
    pub(super) fn handle_open_tcp(
        &mut self,
        stream_id: u32,
        payload_len: u32,
    ) -> Result<(), FlowMuxError> {
        let Some(flow) = self.admit_open_tcp(stream_id, payload_len)? else {
            return Ok(());
        };

        let termination = if flow.may_terminate() {
            self.substitution
                .as_ref()
                .and_then(|service| service.terminable(&flow.host, flow.port))
        } else {
            None
        };
        let Some(mode) = termination else {
            if let Some(reason) = self
                .substitution
                .as_ref()
                .and_then(|service| service.route_refusal_reason(&flow.host, flow.port))
            {
                self.send_refused(
                    stream_id,
                    "destination has endpoint rules; the plan must grant interception to enforce them",
                )?;
                self.deny_flow(stream_id, &flow, reason);
                return Ok(());
            }
            if let Some(reason) = self
                .substitution
                .as_ref()
                .and_then(|service| service.opaque_refusal_reason(&flow.host))
            {
                self.send_refused(stream_id, reason)?;
                self.deny_flow(stream_id, &flow, "typed_transform_required");
                return Ok(());
            }
            return self.open_opaque_flow(stream_id, &flow);
        };
        self.open_terminated_flow(stream_id, &flow, mode)
    }

    /// Parse, rate-limit, and gate one `OpenTcp` target.
    ///
    /// `Ok(None)` means the guest has already been answered with a refusal and
    /// the audit entry for it emitted.
    fn admit_open_tcp(
        &mut self,
        stream_id: u32,
        payload_len: u32,
    ) -> Result<Option<AdmittedFlow>, FlowMuxError> {
        if payload_len == 0 || payload_len > 256 {
            self.send_refused(stream_id, "OpenTcp target missing or too long")?;
            return Ok(None);
        }

        let target = match std::str::from_utf8(self.frame_payload(payload_len)) {
            Ok(s) => s.to_string(),
            Err(_) => {
                self.send_refused(stream_id, "OpenTcp target is not UTF-8")?;
                return Ok(None);
            }
        };

        let (host, requested_port) = match parse_host_port(&target) {
            Ok((host, port)) => (host.to_string(), port),
            Err(e) => {
                self.send_refused(stream_id, &format!("invalid OpenTcp target: {e}"))?;
                return Ok(None);
            }
        };

        if !self.check_connection_rate(registry::FlowClass::Tcp) {
            self.send_refused(stream_id, "rate limited")?;
            self.deny_unrouted_flow(stream_id, registry::FlowClass::Tcp, &target, "rate_limited");
            return Ok(None);
        }

        let decision = self.gate.decide_target(&host, requested_port);
        // Recorded on every audit entry this connect emits, so the chain says
        // which namespace authorized (or refused) the flow rather than leaving
        // a reader to infer it from the target's shape.
        let mut flow = AdmittedFlow {
            target,
            host,
            route: decision.route,
            ips: Vec::new(),
            port: requested_port,
        };
        match decision.verdict {
            EgressVerdict::Allow { ips, port } => {
                flow.ips = ips;
                flow.port = port;
                Ok(Some(flow))
            }
            EgressVerdict::Deny(reason) => {
                self.send_refused(stream_id, &reason.to_string())?;
                self.deny_flow(stream_id, &flow, reason.audit_label());
                Ok(None)
            }
            EgressVerdict::Malformed => {
                self.send_refused(stream_id, "malformed destination")?;
                self.deny_flow(stream_id, &flow, "malformed");
                Ok(None)
            }
        }
    }

    /// Relay an admitted flow straight through to its destination.
    fn open_opaque_flow(
        &mut self,
        stream_id: u32,
        flow: &AdmittedFlow,
    ) -> Result<(), FlowMuxError> {
        if !self.reserve_stream(stream_id, flow)? {
            return Ok(());
        }

        let upstream = match connect_first_admitted(&flow.ips, flow.port, self.connect_timeout) {
            Some(stream) => stream,
            None => {
                warn!(stream_id, target = %flow.target, "FlowMux TCP connect failed");
                let _ = lock_registry(&self.registry).retire(stream_id);
                self.send_connect_failed(stream_id, "connection failed")?;
                self.deny_flow(stream_id, flow, "connect_failed");
                return Ok(());
            }
        };

        if !self.confirm_stream(stream_id)? {
            return Ok(());
        }

        self.send_opened(stream_id)?;
        self.spawn_tcp_relay(stream_id, FlowSocket::from(upstream))?;
        self.emit_audit(
            EventCategory::Host,
            "host.flow.allowed",
            BTreeMap::from([
                ("stream_id".to_string(), stream_id.to_string()),
                ("class".to_string(), "tcp".to_string()),
                ("route".to_string(), flow.route_label()),
                ("target".to_string(), flow.target.clone()),
                ("resolved_ips".to_string(), flow.resolved_ips()),
            ]),
        );
        Ok(())
    }

    /// Serve an admitted flow by terminating it on this host.
    ///
    /// The guest's half of the flow is one end of a local socket pair, so the
    /// relay and the credit accounting are exactly what they are for an opaque
    /// flow; the other end is driven by the terminator, which reads each
    /// request, puts it through the substitution pipeline, and writes the
    /// response back. Nothing dials the destination here — the forward leg
    /// inside that pipeline does.
    fn open_terminated_flow(
        &mut self,
        stream_id: u32,
        flow: &AdmittedFlow,
        mode: TerminationMode,
    ) -> Result<(), FlowMuxError> {
        let (Some(service), Some(runtime)) =
            (self.substitution.clone(), self.runtime_handle.clone())
        else {
            self.send_refused(stream_id, "termination unavailable on this endpoint")?;
            self.deny_flow(stream_id, flow, "termination_unavailable");
            return Ok(());
        };

        // Claimed before anything is built, and held by the flow's thread for
        // its whole life. A terminated flow is several times the cost of an
        // opaque one, so it gets its own ceiling rather than sharing the
        // registry's.
        let Some(slot) = terminator::flow::FlowSlot::claim(&self.terminated_flows) else {
            self.send_refused(stream_id, "too many terminated flows")?;
            self.deny_flow(stream_id, flow, "termination_exhausted");
            return Ok(());
        };

        let terminated = match terminator::flow::TerminatedFlow::builder()
            .service(service)
            .runtime(runtime)
            .leaves(Arc::clone(&self.leaves))
            .authority(&flow.host, flow.port)
            .mode(mode)
            .build()
        {
            Ok(terminated) => terminated,
            Err(reason) => {
                warn!(stream_id, %reason, "FlowMux terminated flow is incomplete");
                self.send_refused(stream_id, reason)?;
                self.deny_flow(stream_id, flow, "termination_unavailable");
                return Ok(());
            }
        };

        if !self.reserve_stream(stream_id, flow)? {
            return Ok(());
        }

        let (endpoint_side, terminator_side) = match UnixStream::pair() {
            Ok(pair) => pair,
            Err(error) => {
                warn!(stream_id, %error, "FlowMux terminated flow has no transport");
                let _ = lock_registry(&self.registry).retire(stream_id);
                self.send_connect_failed(stream_id, "termination setup failed")?;
                self.deny_flow(stream_id, flow, "termination_failed");
                return Ok(());
            }
        };

        if let Err(error) = terminator::flow::spawn(terminated, terminator_side, slot) {
            warn!(stream_id, %error, "FlowMux terminated flow could not start");
            let _ = lock_registry(&self.registry).retire(stream_id);
            self.send_connect_failed(stream_id, "termination setup failed")?;
            self.deny_flow(stream_id, flow, "termination_failed");
            return Ok(());
        }

        if !self.confirm_stream(stream_id)? {
            return Ok(());
        }

        self.send_opened(stream_id)?;
        self.spawn_tcp_relay(stream_id, FlowSocket::from(endpoint_side))?;
        self.emit_audit(
            EventCategory::Host,
            "host.flow.allowed",
            BTreeMap::from([
                ("stream_id".to_string(), stream_id.to_string()),
                ("class".to_string(), "tcp".to_string()),
                ("route".to_string(), flow.route_label()),
                ("target".to_string(), flow.target.clone()),
                ("resolved_ips".to_string(), flow.resolved_ips()),
                (
                    "termination".to_string(),
                    termination_label(mode).to_string(),
                ),
            ]),
        );
        Ok(())
    }

    /// Take a registry slot for an admitted flow. `Ok(false)` means the guest
    /// has been refused and the refusal audited.
    fn reserve_stream(
        &mut self,
        stream_id: u32,
        flow: &AdmittedFlow,
    ) -> Result<bool, FlowMuxError> {
        let open_err = lock_registry(&self.registry)
            .open_guest(stream_id, registry::FlowClass::Tcp)
            .err();
        if let Some(e) = open_err {
            self.send_refused(stream_id, &e.to_string())?;
            self.deny_flow(stream_id, flow, "resource_exhausted");
            return Ok(false);
        }
        Ok(true)
    }

    /// Move a reserved slot to live. `Ok(false)` means the guest has been
    /// refused and the slot released.
    fn confirm_stream(&mut self, stream_id: u32) -> Result<bool, FlowMuxError> {
        let confirm_err = lock_registry(&self.registry).confirm(stream_id).err();
        if let Some(e) = confirm_err {
            let _ = lock_registry(&self.registry).retire(stream_id);
            self.send_refused(stream_id, &e.to_string())?;
            return Ok(false);
        }
        Ok(true)
    }

    /// Audit a refusal of a flow the gate had already routed.
    fn deny_flow(&self, stream_id: u32, flow: &AdmittedFlow, reason: &str) {
        self.emit_audit(
            EventCategory::Host,
            "host.flow.denied",
            BTreeMap::from([
                ("stream_id".to_string(), stream_id.to_string()),
                ("class".to_string(), "tcp".to_string()),
                ("route".to_string(), flow.route_label()),
                ("target".to_string(), flow.target.clone()),
                ("reason".to_string(), reason.to_string()),
            ]),
        );
    }

    /// Audit a refusal of a flow to `target` that carries no route: taken
    /// before the gate chose one, or decided for a datagram, which the gate
    /// never routes.
    pub(super) fn deny_unrouted_flow(
        &self,
        stream_id: u32,
        class: registry::FlowClass,
        target: &str,
        reason: &str,
    ) {
        self.emit_audit(
            EventCategory::Host,
            "host.flow.denied",
            BTreeMap::from([
                ("stream_id".to_string(), stream_id.to_string()),
                ("class".to_string(), class.to_string()),
                ("target".to_string(), target.to_string()),
                ("reason".to_string(), reason.to_string()),
            ]),
        );
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::net::UnixStream;
    use std::sync::Arc;
    use std::thread;

    use mvm_contract::protocol::network_flow::Opcode;
    use mvm_contract::protocol::network_flow::hello::Handshake;
    use mvm_core::net::session::Session;
    use mvm_vmm::vsock_egress_bridge::egress_gate::EgressGate;

    use super::*;
    use crate::supervisor::flowmux::registry::RegistryLimits;
    use crate::supervisor::flowmux::tests::{
        fresh_keys, gate_allowing_addr, gate_pinning_name, local_test_ip, read_flowmux_frame,
        recorder_at, run_session, run_session_from, run_session_on_runtime, run_session_with,
        tcp_echo_server, write_frame,
    };
    use crate::supervisor::flowmux::{FlowMuxAccept, FlowMuxVmResources};

    #[test]
    fn open_tcp_to_unknown_host_is_refused_by_default_deny_gate() {
        let (host_key, host_verify) = fresh_keys();
        let (guest_key, guest_verify) = fresh_keys();

        let (host_stream, mut guest_stream) = UnixStream::pair().unwrap();

        let gate = EgressGate::default_deny();
        let host_handle = thread::spawn(move || {
            let mut session = FlowMuxSession::accept(
                host_stream,
                "test-session",
                host_key,
                &guest_verify,
                RegistryLimits::default(),
                gate,
            )
            .unwrap();
            session.serve()
        });

        let (mut guest_session, _session_id) =
            Session::guest(&mut guest_stream, guest_key, &host_verify).unwrap();

        write_frame(
            &mut guest_stream,
            &mut guest_session,
            Opcode::Hello,
            0,
            &Handshake::local("test-guest").encode(),
        );

        let (opcode, _stream_id, _payload) =
            read_flowmux_frame(&mut guest_stream, &mut guest_session);
        assert_eq!(opcode, Opcode::HelloAck);

        write_frame(
            &mut guest_stream,
            &mut guest_session,
            Opcode::OpenTcp,
            1,
            b"example.com:443",
        );

        let (opcode, _stream_id, payload) =
            read_flowmux_frame(&mut guest_stream, &mut guest_session);
        assert_eq!(opcode, Opcode::Refused);
        assert!(!payload.is_empty());

        // The session stays alive; an unknown-stream frame afterward still
        // receives a GoAway rather than dropping the connection.
        write_frame(&mut guest_stream, &mut guest_session, Opcode::Data, 3, b"?");

        let (opcode, _stream_id, _payload) =
            read_flowmux_frame(&mut guest_stream, &mut guest_session);
        assert_eq!(opcode, Opcode::GoAway);

        drop(guest_stream);
        host_handle.join().unwrap().unwrap();
    }

    #[test]
    fn parse_host_port_accepts_ipv4_and_names() {
        assert_eq!(
            parse_host_port("127.0.0.1:443").unwrap(),
            ("127.0.0.1", 443)
        );
        assert_eq!(
            parse_host_port("example.com:80").unwrap(),
            ("example.com", 80)
        );
    }

    #[test]
    fn parse_host_port_rejects_missing_port_and_empty_host() {
        assert!(parse_host_port("example.com").is_err());
        assert!(parse_host_port(":443").is_err());
        assert!(parse_host_port("example.com:99999").is_err());
    }

    #[test]
    fn open_tcp_to_allowed_local_addr_roundtrips_data() {
        let addr = tcp_echo_server();
        let (mut guest, mut guest_session, host) =
            run_session(gate_allowing_addr(addr.ip(), addr.port(), None));
        write_frame(
            &mut guest,
            &mut guest_session,
            Opcode::OpenTcp,
            1,
            format!("{}:{}", addr.ip(), addr.port()).as_bytes(),
        );
        let (opcode, _stream_id, _payload) = read_flowmux_frame(&mut guest, &mut guest_session);
        assert_eq!(opcode, Opcode::Opened);

        let payload = b"ping";
        write_frame(&mut guest, &mut guest_session, Opcode::Data, 1, payload);
        let data = loop {
            let (opcode, _stream_id, frame) = read_flowmux_frame(&mut guest, &mut guest_session);
            if opcode == Opcode::Data {
                break frame;
            }
            // WindowUpdate and other non-data frames are expected before the
            // upstream response reaches us.
        };
        assert_eq!(&data[..], payload);

        write_frame(&mut guest, &mut guest_session, Opcode::HalfClose, 1, b"");
        let opcode = loop {
            let (op, _stream_id, _payload) = read_flowmux_frame(&mut guest, &mut guest_session);
            if op == Opcode::HalfClose {
                break op;
            }
            // WindowUpdate may be in flight before the relay observes EOF.
            assert_eq!(op, Opcode::WindowUpdate);
        };
        assert_eq!(opcode, Opcode::HalfClose);

        drop(guest);
        host.join().unwrap().unwrap();
    }

    /// Every builder job — a flake build's fetches and a dependency install's
    /// alike — leaves the builder through its vsock egress client and is
    /// decided here, on the builder endpoint's gate. That gate is built by the
    /// endpoint's own `build_egress_gate` from the builder's egress policy,
    /// exactly as the builder spawns it. The policy is open, and open reaches
    /// only public addresses: a private range is refused as `private_range`
    /// and cloud metadata as `cloud_metadata`, each refusal audited, because a
    /// flake's fetcher is as able to aim at the host's LAN as any workload.
    #[test]
    fn builder_egress_refuses_private_ranges_and_metadata_and_audits_both() {
        const PRIVATE: &str = "10.255.0.1:80";
        const METADATA: &str = "169.254.169.254:80";
        let dir = tempfile::tempdir().expect("tempdir");
        let audit_path = dir.path().join("audit.jsonl");
        let (recorder, audit_key) = recorder_at(&audit_path);
        let gate = crate::supervisor::network_endpoint::build_egress_gate(
            &mvm_build::builder_vm_transport::builder_egress_policy(),
        );
        let (mut guest, mut guest_session, host) =
            run_session_on_runtime(move |id, key, anchor, limits| {
                FlowMuxAccept::new(id, key, anchor, limits, gate).with_recorder(Some(recorder))
            });

        for (stream, target) in [(1_u32, PRIVATE), (3, METADATA)] {
            write_frame(
                &mut guest,
                &mut guest_session,
                Opcode::OpenTcp,
                stream,
                target.as_bytes(),
            );
            let (opcode, stream_id) = loop {
                let (opcode, stream_id, _frame) =
                    read_flowmux_frame(&mut guest, &mut guest_session);
                if stream_id == stream {
                    break (opcode, stream_id);
                }
            };
            assert_eq!((opcode, stream_id), (Opcode::Refused, stream), "{target}");
        }

        drop(guest);
        host.join().unwrap().unwrap();

        crate::supervisor::audit_file::verify_audit_chain(&audit_path, &audit_key)
            .expect("audit chain verifies");
        let chain = std::fs::read_to_string(&audit_path).expect("read audit chain");
        let denied: Vec<&str> = chain
            .lines()
            .filter(|line| line.contains("host.flow.denied"))
            .collect();
        assert_eq!(denied.len(), 2, "{chain}");
        assert!(
            denied[0].contains(PRIVATE) && denied[0].contains("private_range"),
            "{chain}"
        );
        assert!(
            denied[1].contains(METADATA) && denied[1].contains("cloud_metadata"),
            "{chain}"
        );
        assert!(!chain.contains("host.flow.allowed"), "{chain}");
    }

    #[test]
    fn open_tcp_to_denied_local_addr_is_refused() {
        let addr = tcp_echo_server();
        let (mut guest, mut guest_session, host) =
            run_session(gate_allowing_addr(addr.ip(), addr.port(), None));
        let denied_port = addr.port().wrapping_add(1);
        write_frame(
            &mut guest,
            &mut guest_session,
            Opcode::OpenTcp,
            1,
            format!("{}:{}", addr.ip(), denied_port).as_bytes(),
        );
        let (opcode, _stream_id, payload) = read_flowmux_frame(&mut guest, &mut guest_session);
        assert_eq!(opcode, Opcode::Refused);
        assert!(!payload.is_empty());

        drop(guest);
        host.join().unwrap().unwrap();
    }

    /// Build a substitution service binding one secret to `bound_host`, with
    /// or without the per-VM egress intermediate a terminated flow needs.
    ///
    /// Real registry, real resolver over a real encrypted secret store; only
    /// the forward leg is a double, and no test here reaches it.
    fn substitution_binding(
        bound_host: &str,
        with_intermediate: bool,
    ) -> (
        Arc<crate::supervisor::network_endpoint_proxy::SubstitutionService>,
        tempfile::TempDir,
    ) {
        substitution_binding_routed(bound_host, with_intermediate, Vec::new())
    }

    /// [`substitution_binding`] whose service gate carries `routes`.
    fn substitution_binding_routed(
        bound_host: &str,
        with_intermediate: bool,
        routes: Vec<mvm_contract::policy::routes::EgressRoute>,
    ) -> (
        Arc<crate::supervisor::network_endpoint_proxy::SubstitutionService>,
        tempfile::TempDir,
    ) {
        use crate::keyholder::substitution::SubstitutionRegistry;
        use crate::keyholder::{LocalResolver, SecretResolver};
        use crate::supervisor::network_endpoint_proxy::{
            ForwardError, ForwardResponse, Forwarder, PreparedRequest, SubstitutionService,
        };
        use mvm_contract::ir::{AuthType, SecretMount, SecretRef};
        use mvm_core::crypto::secret_store::{FileSecretStore, SecretStore};
        use secrecy::SecretBox;

        /// Never reached by these tests: both of them refuse or relay before
        /// any forward leg exists.
        struct UnusedForwarder;

        #[async_trait::async_trait]
        impl Forwarder for UnusedForwarder {
            async fn forward(
                &self,
                _req: PreparedRequest,
            ) -> Result<ForwardResponse, ForwardError> {
                Err(ForwardError::Failed("no forward leg in this test".into()))
            }
        }

        let dir = tempfile::tempdir().expect("tempdir");
        let store = FileSecretStore::with_dir(dir.path().join("secrets"));
        store
            .put(
                "local",
                "model-api",
                &SecretBox::new(Box::new("sk-live-value".to_string())),
            )
            .expect("seed secret store");
        let resolver: Arc<dyn SecretResolver> = Arc::new(LocalResolver::new(
            "local",
            Arc::new(store) as Arc<dyn SecretStore>,
        ));
        let mut registry = SubstitutionRegistry::new();
        let _placeholder = registry.mint(SecretRef {
            name: "model-api".into(),
            mount: SecretMount::Env {
                var: "API_KEY".into(),
            },
            auth_type: AuthType::Bearer,
            allowed_hosts: vec![bound_host.to_string()],
            sigv4: None,
        });
        // Every flow in these tests is decided on the FlowMux connect path, by
        // the session's own gate, before any request reaches the service. Its
        // gate denies everything so a test that did reach it would fail rather
        // than forward.
        let mut service = SubstitutionService::new(
            Arc::new(registry),
            resolver,
            Arc::new(UnusedForwarder),
            Arc::new(EgressGate::default_deny().with_routes(
                mvm_contract::policy::routes::RouteSet::new(routes).expect("test routes validate"),
            )),
        );
        if with_intermediate {
            service = service.with_tls_intermediate(
                mvm_core::crypto::egress_ca::VmEgressCa::mint(&[bound_host])
                    .expect("mint the per-VM egress ca"),
            );
        }
        (Arc::new(service), dir)
    }

    /// A destination carrying a bound secret, on an endpoint with no egress
    /// intermediate, stays refused.
    ///
    /// The flow is admitted by the gate — this is not a policy denial. It is
    /// refused because the only honest way to serve it is to terminate it and
    /// substitute the credential, and this endpoint cannot. Relaying it
    /// instead would put a `mvm-secret-<hex>` placeholder on the wire to a real
    /// upstream, which is the failure the refusal exists to prevent.
    #[test]
    fn connect_to_bound_host_without_an_intermediate_is_refused() {
        let ip = local_test_ip();
        let (service, _dir) = substitution_binding(&ip.to_string(), false);
        let gate = gate_allowing_addr(ip, 443, None);
        let (mut guest, mut guest_session, host) =
            run_session_from(RegistryLimits::default(), move |id, key, anchor, limits| {
                FlowMuxAccept::new(id, key, anchor, limits, gate).with_substitution(Some(service))
            });

        write_frame(
            &mut guest,
            &mut guest_session,
            Opcode::OpenTcp,
            1,
            format!("{ip}:443").as_bytes(),
        );
        let (opcode, _stream_id, payload) = read_flowmux_frame(&mut guest, &mut guest_session);
        assert_eq!(opcode, Opcode::Refused);
        assert_eq!(
            String::from_utf8_lossy(&payload),
            "destination requires secret substitution over typed HTTP",
            "the refusal must name the reason, not a generic failure"
        );

        drop(guest);
        host.join().unwrap().unwrap();
    }

    /// Real ClientHello bytes for `name`, produced by rustls rather than
    /// hand-assembled, so the terminator is answering a handshake a client
    /// would actually send.
    fn client_hello_for(name: &str) -> Vec<u8> {
        let config = rustls::ClientConfig::builder_with_provider(
            rustls::crypto::ring::default_provider().into(),
        )
        .with_safe_default_protocol_versions()
        .expect("client protocol versions")
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
        let server_name = rustls::pki_types::ServerName::try_from(name)
            .expect("test name is a server name")
            .to_owned();
        let mut connection = rustls::ClientConnection::new(Arc::new(config), server_name)
            .expect("build a client connection");
        let mut hello = Vec::new();
        connection
            .write_tls(&mut hello)
            .expect("a fresh client connection has a ClientHello to write");
        hello
    }

    /// A flow to a destination carrying a bound secret is served by
    /// terminating it on the host, not by dialing the destination.
    ///
    /// The proof is the ServerHello: the pinned address has nothing listening
    /// on 443, so an opaque relay could only answer `ConnectFailed`, and
    /// nothing but a host-side terminator can answer a ClientHello with a TLS
    /// record. The audit entry then has to say so.
    #[test]
    fn a_bound_connect_is_terminated_on_the_host_rather_than_dialed() {
        const NAME: &str = "api.terminated.test";
        let dir = tempfile::tempdir().expect("tempdir");
        let audit_path = dir.path().join("audit.jsonl");
        let (recorder, audit_key) = recorder_at(&audit_path);
        let (service, _secrets) = substitution_binding(NAME, true);
        let gate = gate_pinning_name(NAME, local_test_ip(), 443);

        let (mut guest, mut guest_session, host) =
            run_session_on_runtime(move |id, key, anchor, limits| {
                FlowMuxAccept::new(id, key, anchor, limits, gate)
                    .with_substitution(Some(service))
                    .with_recorder(Some(recorder))
            });

        write_frame(
            &mut guest,
            &mut guest_session,
            Opcode::OpenTcp,
            1,
            format!("{NAME}:443").as_bytes(),
        );
        let (opcode, stream_id, payload) = read_flowmux_frame(&mut guest, &mut guest_session);
        assert_eq!(
            opcode,
            Opcode::Opened,
            "a terminated flow opens without dialing: {}",
            String::from_utf8_lossy(&payload)
        );
        assert_eq!(stream_id, 1);

        let hello = client_hello_for(NAME);
        write_frame(&mut guest, &mut guest_session, Opcode::Data, 1, &hello);
        let answer = loop {
            let (opcode, _stream_id, frame) = read_flowmux_frame(&mut guest, &mut guest_session);
            match opcode {
                Opcode::Data => break frame,
                Opcode::WindowUpdate => {}
                other => panic!("unexpected {other:?}: {}", String::from_utf8_lossy(&frame)),
            }
        };
        assert_eq!(
            answer.first(),
            Some(&0x16),
            "only a host-side terminator can answer a ClientHello with a TLS handshake record"
        );

        crate::supervisor::audit_file::verify_audit_chain(&audit_path, &audit_key)
            .expect("audit chain verifies");
        let chain = std::fs::read_to_string(&audit_path).expect("read audit chain");
        assert!(
            chain.contains("host.flow.allowed"),
            "the open must be audited: {chain}"
        );
        assert!(
            chain.contains("\"termination\":\"tls\""),
            "the chain must say the flow was terminated and how: {chain}"
        );
        assert!(
            chain.contains(&format!("{NAME}:443")),
            "the entry names the target: {chain}"
        );

        drop(guest);
        host.join().unwrap().unwrap();
    }

    /// The terminated-flow ceiling and the leaf cache belong to the VM, not to
    /// a session.
    ///
    /// A per-session budget is multiplied by `MAX_CONCURRENT_FLOWMUX_SESSIONS`:
    /// a guest that reconnects sixteen times would reach sixteen times the
    /// intended ceiling and keep sixteen independent caches, which is exactly
    /// what `FlowMuxVmResources` exists to prevent. Two sessions built from one
    /// resources value must therefore look at the same counter and the same
    /// cache.
    #[test]
    fn the_terminated_flow_budget_and_leaf_cache_are_shared_across_a_vms_sessions() {
        let resources = Arc::new(FlowMuxVmResources::from_registry_limits(
            RegistryLimits::default(),
        ));
        let build = |resources: Arc<FlowMuxVmResources>| {
            let (host_stream, mut guest_stream) = UnixStream::pair().unwrap();
            let (host_key, host_verify) = fresh_keys();
            let (guest_key, guest_verify) = fresh_keys();
            let accepted = thread::spawn(move || {
                FlowMuxSession::accept_with(
                    host_stream,
                    FlowMuxAccept::new(
                        "shared-session",
                        host_key,
                        guest_verify,
                        RegistryLimits::default(),
                        EgressGate::default_deny(),
                    )
                    .with_vm_resources(resources),
                )
                .unwrap()
            });
            let (guest_session, _id) =
                Session::guest(&mut guest_stream, guest_key, &host_verify).unwrap();
            let session = accepted.join().unwrap();
            (session, guest_stream, guest_session)
        };

        let (first, _first_guest, _first_session) = build(Arc::clone(&resources));
        let (second, _second_guest, _second_session) = build(Arc::clone(&resources));

        assert!(
            Arc::ptr_eq(&first.terminated_flows, &second.terminated_flows),
            "a second session must spend the same budget, not a fresh one"
        );
        assert!(
            Arc::ptr_eq(&first.leaves, &second.leaves),
            "a second session must reuse the VM's minted leaves"
        );
        assert!(
            Arc::ptr_eq(&first.terminated_flows, &resources.terminated_flows),
            "the budget is the VM's, not one the session invented"
        );

        // And it is the budget the open path actually spends.
        let held = terminator::flow::FlowSlot::claim(&first.terminated_flows)
            .expect("a slot below the ceiling");
        assert_eq!(
            second
                .terminated_flows
                .load(std::sync::atomic::Ordering::Acquire),
            1,
            "a flow opened on one session is visible to the other"
        );
        drop(held);
    }

    /// A peer route is never terminated, even when its name carries a bound
    /// secret.
    ///
    /// The gate rewrites `<name>.mvm.peer:<port>` to the peer's local ingress
    /// mapping, and that rewrite *is* what makes the peer reachable — the name
    /// resolves nowhere. A terminated peer flow would throw the mapping away
    /// and re-originate by the unresolvable name with the real credential
    /// attached. So it falls through to the opaque path, where a bound
    /// destination is refused at open.
    #[test]
    fn a_peer_route_is_never_terminated_even_when_the_peer_name_is_bound() {
        use mvm_contract::peer::{PeerBinding, PeerName};

        let peer_target = "db.mvm.peer";
        let (service, _secrets) = substitution_binding(peer_target, true);
        // The dialed port and the mapped port differ, which is the rewrite
        // this guard exists for. The *mapped* port is the terminable one, so
        // `terminable` would say yes and only the route can refuse: with the
        // route check removed this test opens a terminated peer flow.
        let gate = EgressGate::default_deny().with_peers(vec![PeerBinding {
            name: PeerName::parse(peer_target).expect("peer name parses"),
            port: 8443,
            host_addr: local_test_ip().to_string(),
            host_port: 443,
        }]);

        let (mut guest, mut guest_session, host) =
            run_session_on_runtime(move |id, key, anchor, limits| {
                FlowMuxAccept::new(id, key, anchor, limits, gate).with_substitution(Some(service))
            });

        write_frame(
            &mut guest,
            &mut guest_session,
            Opcode::OpenTcp,
            1,
            format!("{peer_target}:8443").as_bytes(),
        );
        let (opcode, _stream_id, payload) = read_flowmux_frame(&mut guest, &mut guest_session);
        assert_eq!(
            opcode,
            Opcode::Refused,
            "a peer route must not be opened as a terminated flow"
        );
        assert_eq!(
            String::from_utf8_lossy(&payload),
            "destination requires secret substitution over typed HTTP",
            "the peer flow falls through to the opaque refusal"
        );

        drop(guest);
        host.join().unwrap().unwrap();
    }

    /// A destination with no bound secret is relayed opaquely even on an
    /// endpoint that could terminate, and the bytes cross unchanged.
    ///
    /// Mediating every flow was rejected: the host gains nothing from
    /// decrypting a destination it holds no credential for, and loses the
    /// guest's end-to-end TLS by doing it.
    #[test]
    fn an_unbound_connect_is_spliced_without_termination() {
        let addr = tcp_echo_server();
        let (service, _dir) = substitution_binding("bound.example", true);
        // What decides this flow is the binding, not the port: asserted at the
        // terminable port, where the port arm cannot be what refuses. Without
        // this the test would pass with the binding check inverted, because an
        // ephemeral port is not terminable either way.
        assert_eq!(
            service.terminable(&addr.ip().to_string(), 443),
            None,
            "an unbound destination is not terminable even on a terminable port"
        );
        let gate = gate_allowing_addr(addr.ip(), addr.port(), None);
        let (mut guest, mut guest_session, host) =
            run_session_from(RegistryLimits::default(), move |id, key, anchor, limits| {
                FlowMuxAccept::new(id, key, anchor, limits, gate).with_substitution(Some(service))
            });

        write_frame(
            &mut guest,
            &mut guest_session,
            Opcode::OpenTcp,
            1,
            format!("{}:{}", addr.ip(), addr.port()).as_bytes(),
        );
        let (opcode, _stream_id, _payload) = read_flowmux_frame(&mut guest, &mut guest_session);
        assert_eq!(
            opcode,
            Opcode::Opened,
            "an unbound destination is opened, not refused"
        );

        // A TLS ClientHello prefix: an opaque relay must pass it through
        // verbatim, where a terminator would answer it with a ServerHello.
        let payload = b"\x16\x03\x01\x00\x05opaque";
        write_frame(&mut guest, &mut guest_session, Opcode::Data, 1, payload);
        let data = loop {
            let (opcode, _stream_id, frame) = read_flowmux_frame(&mut guest, &mut guest_session);
            if opcode == Opcode::Data {
                break frame;
            }
        };
        assert_eq!(
            &data[..],
            payload,
            "the echo server saw exactly what the guest sent"
        );

        drop(guest);
        host.join().unwrap().unwrap();
    }

    /// A destination whose route has endpoint rules, on a plan that does not
    /// grant interception, is refused at open rather than relayed opaquely:
    /// the rules could not be enforced on a flow the host never reads.
    #[test]
    fn an_opaque_flow_to_a_route_with_ungranted_rules_is_refused_and_audited() {
        let addr = tcp_echo_server();
        let route = mvm_contract::policy::routes::EgressRoute {
            id: "local".into(),
            host: addr.ip().to_string(),
            port: addr.port(),
            rules: vec![mvm_contract::policy::routes::EndpointRule {
                id: None,
                method: Some("GET".into()),
                path: "/**".into(),
                outcome: mvm_contract::policy::routes::RouteOutcome::Allow,
            }],
            otherwise: mvm_contract::policy::routes::RouteOutcome::Deny,
            intercept: false,
        };
        let (service, _dir) = substitution_binding_routed("bound.example", true, vec![route]);
        let dir = tempfile::tempdir().expect("tempdir");
        let audit_path = dir.path().join("audit.jsonl");
        let (recorder, audit_key) = recorder_at(&audit_path);
        let gate = gate_allowing_addr(addr.ip(), addr.port(), None);
        let (mut guest, mut guest_session, host) =
            run_session_on_runtime(move |id, key, anchor, limits| {
                FlowMuxAccept::new(id, key, anchor, limits, gate)
                    .with_substitution(Some(service))
                    .with_recorder(Some(recorder))
            });

        write_frame(
            &mut guest,
            &mut guest_session,
            Opcode::OpenTcp,
            1,
            format!("{}:{}", addr.ip(), addr.port()).as_bytes(),
        );
        let (opcode, _stream_id, _payload) = read_flowmux_frame(&mut guest, &mut guest_session);
        assert_eq!(opcode, Opcode::Refused);

        drop(guest);
        host.join().unwrap().unwrap();
        crate::supervisor::audit_file::verify_audit_chain(&audit_path, &audit_key)
            .expect("audit chain verifies");
        let chain = std::fs::read_to_string(&audit_path).expect("read audit chain");
        assert!(chain.contains("endpoint_rules_unenforceable"), "{chain}");
        assert!(!chain.contains("host.flow.allowed"), "{chain}");
    }

    #[test]
    fn open_tcp_to_allowed_but_unbound_addr_is_refused_truthfully() {
        let ip = local_test_ip();
        // Bind briefly to let the OS assign a free port, then drop the
        // listener so the attempted connect fails with ECONNREFUSED.
        let free_port = std::net::TcpListener::bind(std::net::SocketAddr::new(ip, 0))
            .unwrap()
            .local_addr()
            .unwrap()
            .port();

        let (mut guest, mut guest_session, host) =
            run_session(gate_allowing_addr(ip, free_port, None));
        write_frame(
            &mut guest,
            &mut guest_session,
            Opcode::OpenTcp,
            1,
            format!("{}:{}", ip, free_port).as_bytes(),
        );
        let (opcode, _stream_id, payload) = read_flowmux_frame(&mut guest, &mut guest_session);
        assert_eq!(opcode, Opcode::ConnectFailed);
        assert!(!payload.is_empty());

        drop(guest);
        host.join().unwrap().unwrap();
    }

    #[test]
    fn tcp_connection_rate_limit_refuses_overflow() {
        let addr = tcp_echo_server();
        let limits = RegistryLimits {
            tcp_connect_rate: 1,
            ..Default::default()
        };
        let (mut guest, mut guest_session, host) =
            run_session_with(gate_allowing_addr(addr.ip(), addr.port(), None), limits);

        write_frame(
            &mut guest,
            &mut guest_session,
            Opcode::OpenTcp,
            1,
            format!("{}:{}", addr.ip(), addr.port()).as_bytes(),
        );
        let (opcode, _, _) = read_flowmux_frame(&mut guest, &mut guest_session);
        assert_eq!(opcode, Opcode::Opened);

        write_frame(
            &mut guest,
            &mut guest_session,
            Opcode::OpenTcp,
            3,
            format!("{}:{}", addr.ip(), addr.port()).as_bytes(),
        );
        let (opcode, _, payload) = read_flowmux_frame(&mut guest, &mut guest_session);
        assert_eq!(opcode, Opcode::Refused);
        assert!(std::str::from_utf8(&payload).unwrap().contains("rate"));

        drop(guest);
        host.join().unwrap().unwrap();
    }
}
