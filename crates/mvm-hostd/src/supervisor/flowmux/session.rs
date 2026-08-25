use super::*;

impl FlowMuxSession {
    /// Return the session identifier for logging and correlation.
    pub fn session_id(&self) -> String {
        lock_session(&self.session).session_id().to_string()
    }

    /// Clone the host-initiated ingress half of this authenticated session.
    #[must_use]
    pub fn ingress_handle(&self) -> FlowMuxIngressHandle {
        FlowMuxIngressHandle {
            session: Arc::clone(&self.session),
            writer: Arc::clone(&self.writer),
            validator: Arc::clone(&self.validator),
            registry: Arc::clone(&self.registry),
            streams: Arc::clone(&self.streams),
            pending: Arc::clone(&self.pending_ingress),
            credit_wait: self.limits.credit_wait,
            recorder: self.recorder.as_ref().map(Arc::clone),
            runtime_handle: self.runtime_handle.clone(),
            udp_associations: Arc::clone(&self.udp_associations),
            udp_idle_timeout: self.limits.udp_idle_timeout,
            max_udp_peers: self.limits.max_udp_peers,
        }
    }

    /// Accept one authenticated FlowMux session on `stream`.
    ///
    /// `session_id` must be unique per VM boot. `host_key` signs the
    /// handshake; `guest_anchor` is the only guest identity this endpoint
    /// will accept. A mismatch fails closed.
    pub fn accept(
        stream: UnixStream,
        session_id: &str,
        host_key: SigningKey,
        guest_anchor: &VerifyingKey,
        limits: RegistryLimits,
        gate: EgressGate,
    ) -> Result<Self, FlowMuxError> {
        Self::accept_with(
            stream,
            FlowMuxAccept::new(session_id, host_key, guest_anchor.to_owned(), limits, gate),
        )
    }

    /// Accept one authenticated FlowMux session with an optional audit
    /// recorder attached.
    ///
    /// `session_id` must be unique per VM boot. `host_key` signs the
    /// handshake; `guest_anchor` is the only guest identity this endpoint
    /// will accept. A mismatch fails closed.
    pub fn accept_with(
        mut stream: UnixStream,
        params: FlowMuxAccept,
    ) -> Result<Self, FlowMuxError> {
        let FlowMuxAccept {
            session_id,
            host_key,
            guest_anchor,
            limits,
            gate,
            recorder,
            substitution,
            vm_resources,
            ingress_mappings,
        } = params;
        let session_id = session_id.as_str();
        // Split the socket into independent read/write descriptors so the
        // main thread can block on guest frames while relay threads emit
        // upstream data back to the guest.
        let writer = stream.try_clone()?;
        let (session, _peer_key) = Session::host(&mut stream, session_id, host_key)
            .map_err(|e| FlowMuxError::Handshake(e.to_string()))?;

        if session.peer_verifying_key() != &guest_anchor {
            return Err(FlowMuxError::Handshake(
                "guest identity does not match pinned anchor".to_string(),
            ));
        }

        info!(session_id, "FlowMux handshake complete");

        let resources = vm_resources
            .unwrap_or_else(|| Arc::new(FlowMuxVmResources::from_registry_limits(limits)));
        Ok(Self {
            reader: stream,
            writer: Arc::new(Mutex::new(writer)),
            session: Arc::new(Mutex::new(session)),
            validator: Arc::new(Mutex::new(SessionValidator::new_with_ingress(
                ingress_mappings,
            ))),
            registry: Arc::new(Mutex::new(StreamRegistry::with_budget(
                limits,
                Arc::clone(&resources.registry_budget),
            ))),
            streams: Arc::new(Mutex::new(BTreeMap::new())),
            pending_ingress: Arc::new(Mutex::new(BTreeMap::new())),
            icmp_rate: Arc::clone(&resources.icmp_rate),
            http_flows: BTreeMap::new(),
            http_cancellations: Arc::new(Mutex::new(BTreeMap::new())),
            substitution,
            udp_associations: Arc::new(Mutex::new(BTreeMap::new())),
            gate,
            read_buf: Vec::with_capacity(4096),
            limits,
            connect_timeout: Duration::from_secs(30),
            recorder,
            runtime_handle: tokio::runtime::Handle::try_current().ok(),
            rate_limiter: Arc::clone(&resources.rate_limiter),
        })
    }

    /// Emit a payload-free audit entry. The labels carry only metadata
    /// (stream id, class, target, verdict) — never payload bytes.
    ///
    /// Best effort: a missing recorder or absent Tokio runtime is ignored so
    /// audit plumbing never blocks the networking path.
    fn emit_audit(
        &self,
        category: EventCategory,
        event_name: &str,
        labels: BTreeMap<String, String>,
    ) {
        emit_unbound_audit(
            self.recorder.as_ref(),
            self.runtime_handle.as_ref(),
            category,
            event_name,
            labels,
        );
    }

    /// Check the per-class connection-rate limiter. Returns `true` when the
    /// attempt is admitted (or when limiting is disabled for this class).
    fn check_connection_rate(&self, class: registry::FlowClass) -> bool {
        self.rate_limiter.try_open(class)
    }

    /// Render a list of IP addresses as a compact, stable label value.
    fn format_ips(ips: &[IpAddr]) -> String {
        let mut out = String::with_capacity(ips.len() * 16);
        for (i, ip) in ips.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push_str(&ip.to_string());
        }
        out
    }

    /// Serve the session until it closes or errors.
    ///
    /// The implementation completes the FlowMux `Hello`/`HelloAck` exchange,
    /// then dispatches flow frames. `OpenTcp` flows that pass the shared
    /// [`EgressGate`] are connected on the host and relayed; everything else
    /// is refused or terminated with `GoAway`.
    pub fn serve(&mut self) -> Result<(), FlowMuxError> {
        // Wait for the guest's Hello, then acknowledge. The authenticated
        // session is already established; this is the FlowMux session opening.
        let guest_payload_len = match self.read_frame()? {
            Some((Opcode::Hello, 0, payload_len)) => payload_len,
            Some((opcode, _, _)) => {
                return Err(FlowMuxError::FrameRefused(format!(
                    "expected Hello as first FlowMux frame, got {opcode:?}"
                )));
            }
            None => {
                return Err(FlowMuxError::FrameRefused(
                    "peer closed before Hello".to_string(),
                ));
            }
        };

        // Refuse a guest built against a different revision before serving it
        // anything. A GoAway first, so the guest reports the same mismatch
        // rather than a bare disconnect it cannot explain.
        let local = Handshake::local(HOST_BUILD);
        let payload_start = LENGTH_PREFIX_LEN + HEADER_LEN;
        let guest = Handshake::decode(
            &self.read_buf[payload_start..payload_start + guest_payload_len as usize],
        )
        .map_err(|e| FlowMuxError::FrameRefused(e.to_string()))?;
        if let Err(e) = agree(&local, &guest) {
            self.send_goaway(&e.to_string())?;
            return Err(FlowMuxError::FrameRefused(e.to_string()));
        }

        lock_validator(&self.validator)
            .admit(&mvm_contract::protocol::network_flow::FrameFacts::new(
                Direction::GuestToHost,
                Opcode::Hello,
                0,
            ))
            .map_err(|e| FlowMuxError::FrameRefused(e.to_string()))?;

        self.send_hello_ack()?;
        lock_validator(&self.validator)
            .mark_hello_ack_sent()
            .map_err(|e| FlowMuxError::FrameRefused(e.to_string()))?;

        loop {
            let (opcode, stream_id, payload_len) = match self.read_frame()? {
                Some(facts) => facts,
                None => {
                    info!("FlowMux peer closed session");
                    return Ok(());
                }
            };

            if let Err(e) = lock_validator(&self.validator).admit(&Self::inbound_frame_facts(
                &self.read_buf,
                opcode,
                stream_id,
                payload_len,
            )) {
                warn!(error = %e, "FlowMux frame refused by session validator");
                self.send_goaway(&e.to_string())?;
                return Ok(());
            }

            match opcode {
                Opcode::Hello => {
                    // A second Hello is illegal after the session is established;
                    // the validator already refuses it.
                }
                Opcode::OpenTcp => {
                    if let Err(e) = self.handle_open_tcp(stream_id, payload_len) {
                        warn!(error = %e, stream_id, "FlowMux TCP open failed");
                        self.send_reset(stream_id, "host error")?;
                    }
                }
                Opcode::InboundReady => {
                    self.handle_inbound_ready(stream_id);
                }
                Opcode::InboundRefused => {
                    self.handle_inbound_refused(stream_id, payload_len);
                }
                Opcode::Data => {
                    if let Err(e) = self.handle_guest_data(stream_id, payload_len) {
                        warn!(error = %e, stream_id, "FlowMux data forwarding failed");
                        let _ = self.reset_stream(stream_id);
                    }
                }
                Opcode::HalfClose => {
                    if let Err(e) = self.handle_guest_half_close(stream_id) {
                        warn!(error = %e, stream_id, "FlowMux half-close failed");
                        let _ = self.reset_stream(stream_id);
                    }
                }
                Opcode::Reset => {
                    self.reset_stream(stream_id)?;
                }
                Opcode::WindowUpdate => {
                    if let Err(e) = self.handle_window_update(stream_id, payload_len) {
                        warn!(error = %e, stream_id, "FlowMux window update failed");
                        let _ = self.reset_stream(stream_id);
                    }
                }
                Opcode::OpenUdp => {
                    if let Err(e) = self.handle_open_udp(stream_id) {
                        warn!(error = %e, stream_id, "FlowMux UDP open failed");
                        self.send_refused(stream_id, "host error")?;
                    }
                }
                Opcode::UdpSend => {
                    if let Err(e) = self.handle_udp_send(stream_id, payload_len) {
                        warn!(error = %e, stream_id, "FlowMux UDP send failed");
                        self.remove_udp_association(stream_id);
                    }
                }
                Opcode::Resolve => {
                    let open_err = class_for_open(opcode).and_then(|class| {
                        lock_registry(&self.registry)
                            .open_guest(stream_id, class)
                            .err()
                    });
                    if let Some(e) = open_err {
                        warn!(error = %e, stream_id, "FlowMux refusing DNS resolve");
                        self.send_resolve_refused(stream_id, &e.to_string())?;
                    } else if let Err(e) = self.handle_resolve(stream_id, payload_len) {
                        warn!(error = %e, stream_id, "FlowMux DNS resolve failed");
                        self.send_resolve_refused(stream_id, "resolve failed")?;
                        self.remove_stream(stream_id);
                    }
                }
                Opcode::IcmpEcho => {
                    if let Err(e) = self.handle_icmp_echo(stream_id, payload_len) {
                        warn!(error = %e, stream_id, "FlowMux ICMP echo failed");
                        self.send_icmp_refused(stream_id, "icmp echo failed")?;
                        self.remove_stream(stream_id);
                    }
                }
                Opcode::OpenHttp => {
                    if let Err(e) = self.handle_open_http(stream_id) {
                        warn!(error = %e, stream_id, "FlowMux HTTP open failed");
                        self.send_refused(stream_id, "http open refused")?;
                        self.http_flows.remove(&stream_id);
                        self.remove_stream(stream_id);
                    }
                }
                Opcode::HttpRequestHead | Opcode::HttpRequestBody => {
                    if let Err(e) = self.handle_http_request_frame(opcode, stream_id, payload_len) {
                        warn!(error = %e, stream_id, "FlowMux HTTP request refused");
                        self.send_reset(stream_id, "http request refused")?;
                        self.http_flows.remove(&stream_id);
                        self.remove_stream(stream_id);
                    }
                }
                Opcode::CloseUdp => {
                    self.remove_udp_association(stream_id);
                }
                _ => {
                    if lock_registry(&self.registry).get(stream_id).is_some() {
                        warn!(?opcode, stream_id, "FlowMux skeleton rejects flow frame");
                        self.send_goaway("flow frames not yet implemented")?;
                    } else {
                        warn!(?opcode, stream_id, "FlowMux frame on unknown stream");
                        self.send_goaway("unknown stream")?;
                    }
                    return Ok(());
                }
            }
        }
    }

    fn handle_open_tcp(&mut self, stream_id: u32, payload_len: u32) -> Result<(), FlowMuxError> {
        if payload_len == 0 || payload_len > 256 {
            self.send_refused(stream_id, "OpenTcp target missing or too long")?;
            return Ok(());
        }

        let target = match std::str::from_utf8(self.frame_payload(payload_len)) {
            Ok(s) => s,
            Err(_) => {
                self.send_refused(stream_id, "OpenTcp target is not UTF-8")?;
                return Ok(());
            }
        };

        let (host, port) = match parse_host_port(target) {
            Ok(pair) => pair,
            Err(e) => {
                self.send_refused(stream_id, &format!("invalid OpenTcp target: {e}"))?;
                return Ok(());
            }
        };
        let target = target.to_string();

        if let Some(reason) = self
            .substitution
            .as_ref()
            .and_then(|service| service.opaque_refusal_reason(host))
        {
            self.send_refused(stream_id, reason)?;
            self.emit_audit(
                EventCategory::Host,
                "host.flow.denied",
                BTreeMap::from([
                    ("stream_id".to_string(), stream_id.to_string()),
                    ("class".to_string(), "tcp".to_string()),
                    ("target".to_string(), target),
                    ("reason".to_string(), "typed_transform_required".to_string()),
                ]),
            );
            return Ok(());
        }

        if !self.check_connection_rate(registry::FlowClass::Tcp) {
            self.send_refused(stream_id, "rate limited")?;
            self.emit_audit(
                EventCategory::Host,
                "host.flow.denied",
                BTreeMap::from([
                    ("stream_id".to_string(), stream_id.to_string()),
                    ("class".to_string(), "tcp".to_string()),
                    ("target".to_string(), target.to_string()),
                    ("reason".to_string(), "rate_limited".to_string()),
                ]),
            );
            return Ok(());
        }

        let (ips, port) = match self.gate.decide_target(host, port) {
            EgressVerdict::Allow { ips, port } => (ips, port),
            EgressVerdict::Deny(reason) => {
                self.send_refused(stream_id, &reason.to_string())?;
                self.emit_audit(
                    EventCategory::Host,
                    "host.flow.denied",
                    BTreeMap::from([
                        ("stream_id".to_string(), stream_id.to_string()),
                        ("class".to_string(), "tcp".to_string()),
                        ("target".to_string(), target.to_string()),
                        ("reason".to_string(), "policy_denied".to_string()),
                    ]),
                );
                return Ok(());
            }
            EgressVerdict::Malformed => {
                self.send_refused(stream_id, "malformed destination")?;
                self.emit_audit(
                    EventCategory::Host,
                    "host.flow.denied",
                    BTreeMap::from([
                        ("stream_id".to_string(), stream_id.to_string()),
                        ("class".to_string(), "tcp".to_string()),
                        ("target".to_string(), target.to_string()),
                        ("reason".to_string(), "malformed".to_string()),
                    ]),
                );
                return Ok(());
            }
        };

        let open_err = lock_registry(&self.registry)
            .open_guest(stream_id, registry::FlowClass::Tcp)
            .err();
        if let Some(e) = open_err {
            self.send_refused(stream_id, &e.to_string())?;
            self.emit_audit(
                EventCategory::Host,
                "host.flow.denied",
                BTreeMap::from([
                    ("stream_id".to_string(), stream_id.to_string()),
                    ("class".to_string(), "tcp".to_string()),
                    ("target".to_string(), target.to_string()),
                    ("reason".to_string(), "resource_exhausted".to_string()),
                ]),
            );
            return Ok(());
        }

        let upstream = match connect_first_admitted(&ips, port, self.connect_timeout) {
            Some(stream) => stream,
            None => {
                warn!(stream_id, %target, "FlowMux TCP connect failed");
                let _ = lock_registry(&self.registry).retire(stream_id);
                self.send_refused(stream_id, "connection failed")?;
                self.emit_audit(
                    EventCategory::Host,
                    "host.flow.denied",
                    BTreeMap::from([
                        ("stream_id".to_string(), stream_id.to_string()),
                        ("class".to_string(), "tcp".to_string()),
                        ("target".to_string(), target.to_string()),
                        ("reason".to_string(), "connect_failed".to_string()),
                    ]),
                );
                return Ok(());
            }
        };

        let confirm_err = lock_registry(&self.registry).confirm(stream_id).err();
        if let Some(e) = confirm_err {
            let _ = lock_registry(&self.registry).retire(stream_id);
            self.send_refused(stream_id, &e.to_string())?;
            return Ok(());
        }

        self.send_opened(stream_id)?;
        self.spawn_tcp_relay(stream_id, upstream)?;
        self.emit_audit(
            EventCategory::Host,
            "host.flow.allowed",
            BTreeMap::from([
                ("stream_id".to_string(), stream_id.to_string()),
                ("class".to_string(), "tcp".to_string()),
                ("target".to_string(), target.to_string()),
                ("resolved_ips".to_string(), Self::format_ips(&ips)),
            ]),
        );
        Ok(())
    }

    fn handle_resolve(&mut self, stream_id: u32, payload_len: u32) -> Result<(), FlowMuxError> {
        if payload_len == 0 || payload_len as usize > MAX_DNS_MESSAGE {
            self.send_resolve_refused(stream_id, "DNS query missing or oversized")?;
            self.remove_stream(stream_id);
            return Ok(());
        }

        let query = self.frame_payload(payload_len);

        let question = match decode_query(query) {
            Ok(q) => q,
            Err(e) => {
                self.send_resolve_refused(stream_id, &format!("malformed DNS query: {e:?}"))?;
                self.remove_stream(stream_id);
                return Ok(());
            }
        };

        if !self.check_connection_rate(registry::FlowClass::Dns) {
            self.send_resolve_refused(stream_id, "rate limited")?;
            self.emit_audit(
                EventCategory::Dns,
                "dns.refused",
                BTreeMap::from([
                    ("stream_id".to_string(), stream_id.to_string()),
                    ("qname".to_string(), question.name.clone()),
                    ("qtype".to_string(), question.qtype.to_string()),
                    ("reason".to_string(), "rate_limited".to_string()),
                ]),
            );
            self.remove_stream(stream_id);
            return Ok(());
        }

        let timeout = self.connect_timeout;
        let verdict = self
            .gate
            .dns_verdict(&question.name, question.qtype, |name| {
                resolve_hostname_ips(name, timeout)
            });

        let response = match verdict {
            DnsVerdict::Resolved(ips) => {
                self.emit_audit(
                    EventCategory::Dns,
                    "dns.resolved",
                    BTreeMap::from([
                        ("stream_id".to_string(), stream_id.to_string()),
                        ("qname".to_string(), question.name.clone()),
                        ("qtype".to_string(), question.qtype.to_string()),
                        ("resolved_ips".to_string(), Self::format_ips(&ips)),
                    ]),
                );
                encode_response(
                    &question,
                    mvm_contract::protocol::dns::DnsRcode::NoError,
                    &ips,
                )
            }
            DnsVerdict::Refused => {
                self.emit_audit(
                    EventCategory::Dns,
                    "dns.refused",
                    BTreeMap::from([
                        ("stream_id".to_string(), stream_id.to_string()),
                        ("qname".to_string(), question.name.clone()),
                        ("qtype".to_string(), question.qtype.to_string()),
                        ("reason".to_string(), "policy_denied".to_string()),
                    ]),
                );
                self.send_resolve_refused(stream_id, "policy refused")?;
                self.remove_stream(stream_id);
                return Ok(());
            }
        };

        self.send_resolved(stream_id, &response)?;
        self.remove_stream(stream_id);
        Ok(())
    }

    fn handle_open_udp(&mut self, stream_id: u32) -> Result<(), FlowMuxError> {
        if !self.check_connection_rate(registry::FlowClass::Udp) {
            self.send_refused(stream_id, "rate limited")?;
            self.emit_audit(
                EventCategory::Host,
                "host.flow.denied",
                BTreeMap::from([
                    ("stream_id".to_string(), stream_id.to_string()),
                    ("class".to_string(), "udp".to_string()),
                    ("reason".to_string(), "rate_limited".to_string()),
                ]),
            );
            return Ok(());
        }

        let open_err = lock_registry(&self.registry)
            .open_guest(stream_id, registry::FlowClass::Udp)
            .err();
        if let Some(e) = open_err {
            self.send_refused(stream_id, &e.to_string())?;
            self.emit_audit(
                EventCategory::Host,
                "host.flow.denied",
                BTreeMap::from([
                    ("stream_id".to_string(), stream_id.to_string()),
                    ("class".to_string(), "udp".to_string()),
                    ("reason".to_string(), "resource_exhausted".to_string()),
                ]),
            );
            return Ok(());
        }

        let socket = std::net::UdpSocket::bind("0.0.0.0:0").map_err(|e| {
            warn!(stream_id, error = %e, "FlowMux UDP bind failed");
            FlowMuxError::Transport(e)
        })?;
        let (poll, waker) = udp_event_sources(&socket).map_err(FlowMuxError::Transport)?;
        let idle_timeout = self.limits.udp_idle_timeout;
        let max_peers = self.limits.max_udp_peers;

        let (tx, rx) = std::sync::mpsc::channel();
        let session = Arc::clone(&self.session);
        let writer = Arc::clone(&self.writer);
        let registry_arc = Arc::clone(&self.registry);
        std::thread::Builder::new()
            .name(format!("flowmux-udp-{stream_id}"))
            .spawn(move || {
                run_udp_relay(UdpRelayParams {
                    stream_id,
                    socket,
                    poll,
                    session,
                    writer,
                    idle_timeout,
                    max_peers,
                    peer_admission: UdpPeerAdmission::GuestMayIntroduce,
                    rx,
                    registry: registry_arc,
                })
            })
            .map_err(FlowMuxError::Transport)?;

        lock_udp_associations(&self.udp_associations).insert(
            stream_id,
            UdpAssociationHandle {
                tx,
                waker,
                peer_admission: UdpPeerAdmission::GuestMayIntroduce,
            },
        );
        self.send_udp_opened(stream_id)?;
        self.emit_audit(
            EventCategory::Host,
            "host.flow.allowed",
            BTreeMap::from([
                ("stream_id".to_string(), stream_id.to_string()),
                ("class".to_string(), "udp".to_string()),
            ]),
        );
        Ok(())
    }

    fn handle_udp_send(&mut self, stream_id: u32, payload_len: u32) -> Result<(), FlowMuxError> {
        let relay = match lock_udp_associations(&self.udp_associations).get(&stream_id) {
            Some(handle) => (
                handle.tx.clone(),
                Arc::clone(&handle.waker),
                handle.peer_admission,
            ),
            None => {
                warn!(stream_id, "UdpSend on unknown association");
                self.send_goaway("unknown UDP association")?;
                return Ok(());
            }
        };

        let payload = self.frame_payload(payload_len);
        if payload.len() < UDP_ADDR_PREFIX_LEN {
            return Err(FlowMuxError::FrameRefused(
                "UdpSend payload too short".to_string(),
            ));
        }

        let (ip, port, datagram) = decode_udp_addr(payload)
            .map_err(|e| FlowMuxError::FrameRefused(format!("invalid UdpSend address: {e}")))?;
        let target = format!("{ip}:{port}");

        if relay.2 == UdpPeerAdmission::GuestMayIntroduce {
            if let Some(reason) = self
                .substitution
                .as_ref()
                .and_then(|service| service.opaque_refusal_reason(&ip.to_string()))
            {
                warn!(stream_id, %target, reason, "FlowMux opaque UDP transform refused");
                self.emit_audit(
                    EventCategory::Host,
                    "host.flow.denied",
                    BTreeMap::from([
                        ("stream_id".to_string(), stream_id.to_string()),
                        ("class".to_string(), "udp".to_string()),
                        ("target".to_string(), target),
                        ("reason".to_string(), "typed_transform_required".to_string()),
                    ]),
                );
                return Ok(());
            }

            match self.gate.decide_udp_request(&target) {
                EgressVerdict::Allow { .. } => {}
                EgressVerdict::Deny(reason) => {
                    warn!(stream_id, %target, %reason, "FlowMux UDP datagram denied");
                    return Ok(());
                }
                EgressVerdict::Malformed => {
                    return Err(FlowMuxError::FrameRefused(
                        "malformed UDP destination".to_string(),
                    ));
                }
            }
        }

        let msg = UdpSendMsg {
            destination: SocketAddr::new(ip, port),
            payload: datagram.to_vec(),
        };
        if relay.0.send(msg).is_err() {
            return Err(FlowMuxError::FrameRefused(
                "UDP relay thread has exited".to_string(),
            ));
        }
        relay.1.wake().map_err(FlowMuxError::Transport)?;
        Ok(())
    }

    fn remove_udp_association(&mut self, stream_id: u32) {
        if let Some(UdpAssociationHandle { tx, waker, .. }) =
            lock_udp_associations(&self.udp_associations).remove(&stream_id)
        {
            drop(tx);
            let _ = waker.wake();
        }
        let _ = lock_registry(&self.registry).retire(stream_id);
    }

    fn send_udp_opened(&mut self, stream_id: u32) -> Result<(), FlowMuxError> {
        info!(stream_id, "FlowMux sending UdpOpened");
        self.write_frame(Opcode::UdpOpened, stream_id, b"")?;
        self.mark_sent(Opcode::UdpOpened, stream_id);
        Ok(())
    }

    fn spawn_tcp_relay(&mut self, stream_id: u32, upstream: TcpStream) -> Result<(), FlowMuxError> {
        self.ingress_handle().spawn_tcp_relay(stream_id, upstream)
    }

    fn handle_guest_data(&mut self, stream_id: u32, payload_len: u32) -> Result<(), FlowMuxError> {
        let payload = self.frame_payload(payload_len).to_vec();

        let mut streams = lock_tcp_streams(&self.streams);
        let handle = match streams.get_mut(&stream_id) {
            Some(h) => h,
            None => {
                warn!(stream_id, "Data frame on unknown stream");
                self.send_goaway("unknown stream")?;
                return Ok(());
            }
        };

        if handle.host_half_closed.load(Ordering::Relaxed) {
            drop(streams);
            self.send_reset(stream_id, "data after host half-close")?;
            self.remove_stream(stream_id);
            return Ok(());
        }

        {
            let mut reg = lock_registry(&self.registry);
            if let Err(e) = reg.consume_guest_credit(stream_id, payload_len) {
                warn!(error = %e, stream_id, "guest credit exhausted");
                drop(reg);
                drop(streams);
                self.send_reset(stream_id, "credit exhausted")?;
                self.remove_stream(stream_id);
                return Ok(());
            }
        }

        if let Err(e) = handle
            .upstream
            .write_all(&payload)
            .and_then(|_| handle.upstream.flush())
        {
            warn!(error = %e, stream_id, "write to upstream failed");
            drop(streams);
            self.send_reset(stream_id, "upstream write failed")?;
            self.remove_stream(stream_id);
            return Ok(());
        }

        // Replenish at the low-water mark instead of emitting one authenticated
        // update for every small DATA frame. Zero-length frames never produce
        // an update, because the protocol rejects a zero credit delta.
        let credit_update = lock_registry(&self.registry)
            .replenish_guest_credit_if_low(stream_id)
            .unwrap_or(None);
        drop(streams);
        if let Some(delta) = credit_update {
            self.send_window_update(stream_id, delta)?;
        }
        Ok(())
    }

    fn handle_guest_half_close(&mut self, stream_id: u32) -> Result<(), FlowMuxError> {
        let mut streams = lock_tcp_streams(&self.streams);
        let handle = match streams.get_mut(&stream_id) {
            Some(h) => h,
            None => {
                warn!(stream_id, "HalfClose on unknown stream");
                self.send_goaway("unknown stream")?;
                return Ok(());
            }
        };

        let _ = handle.upstream.shutdown(std::net::Shutdown::Write);

        if handle.host_half_closed.load(Ordering::Relaxed) {
            // Both directions are now done.
            handle.retired.store(true, Ordering::Relaxed);
            drop(streams);
            self.send_reset(stream_id, "stream complete")?;
            self.remove_stream(stream_id);
        } else {
            let _ = lock_registry(&self.registry).half_close(stream_id);
        }
        Ok(())
    }

    /// Serve one host-mediated ICMP echo.
    ///
    /// A NIC-less guest has no raw socket, so the host echoes on its behalf.
    /// The decision — parse, bounds, admission, rate — is
    /// [`icmp_handler::serve_request`], shared with every other transport that
    /// has ever carried this verb, so they cannot drift on what is allowed.
    fn handle_icmp_echo(&mut self, stream_id: u32, payload_len: u32) -> Result<(), FlowMuxError> {
        use crate::supervisor::{icmp_audit, icmp_echo, icmp_handler};

        if !self.check_connection_rate(registry::FlowClass::Icmp) {
            return Err(FlowMuxError::FrameRefused("icmp rate limit".to_string()));
        }
        lock_registry(&self.registry)
            .open_guest(stream_id, registry::FlowClass::Icmp)
            .map_err(|e| FlowMuxError::FrameRefused(e.to_string()))?;

        let line = String::from_utf8_lossy(self.frame_payload(payload_len)).into_owned();
        let (replies, audit) = icmp_handler::serve_request(
            &line,
            &self.gate,
            &self.icmp_rate,
            &icmp_echo::PingSocketEcho,
        );
        if let Some(recorder) = self.recorder.as_deref() {
            icmp_audit::emit_icmp_echo_blocking(recorder, &audit);
        }

        // One echo per flow, so the last reply ends it. A refusal is an answer
        // too — the guest gets the reason rather than a closed stream.
        let last = replies.len().saturating_sub(1);
        for (index, reply) in replies.into_iter().enumerate() {
            let encoded = serde_json::to_vec(&reply)
                .map_err(|e| FlowMuxError::FrameRefused(e.to_string()))?;
            let opcode = match reply {
                mvm_core::icmp_wire::IcmpEchoReply::Refused { .. } => Opcode::IcmpRefused,
                _ => Opcode::IcmpReply,
            };
            self.write_frame(opcode, stream_id, &encoded)?;
            if index == last {
                self.mark_sent(opcode, stream_id);
            }
        }
        self.remove_stream(stream_id);
        Ok(())
    }

    fn send_icmp_refused(&mut self, stream_id: u32, reason: &str) -> Result<(), FlowMuxError> {
        let reply = mvm_core::icmp_wire::IcmpEchoReply::Refused {
            message: reason.to_string(),
        };
        let encoded =
            serde_json::to_vec(&reply).map_err(|e| FlowMuxError::FrameRefused(e.to_string()))?;
        self.write_frame(Opcode::IcmpRefused, stream_id, &encoded)?;
        self.mark_sent(Opcode::IcmpRefused, stream_id);
        Ok(())
    }

    /// Open a typed HTTP flow.
    ///
    /// Refused outright when this endpoint assembled no substitution service:
    /// the flow exists to carry a request that may name a placeholder, and
    /// there would be nothing here to resolve it. Failing the open is the
    /// difference between a workload that cannot reach the network and one
    /// that sends `mvm-secret-<hex>` to a real upstream.
    fn handle_open_http(&mut self, stream_id: u32) -> Result<(), FlowMuxError> {
        if self.substitution.is_none() {
            return Err(FlowMuxError::FrameRefused(
                "no substitution service on this endpoint".to_string(),
            ));
        }
        if !self.check_connection_rate(registry::FlowClass::Http) {
            return Err(FlowMuxError::FrameRefused(
                "http open rate limit".to_string(),
            ));
        }
        lock_registry(&self.registry)
            .open_guest(stream_id, registry::FlowClass::Http)
            .map_err(|e| FlowMuxError::FrameRefused(e.to_string()))?;
        self.http_flows
            .insert(stream_id, http_flow::HttpFlow::new());
        self.send_opened(stream_id)
    }

    /// Take one head or body frame, and forward as soon as the declared body
    /// has arrived in full.
    fn handle_http_request_frame(
        &mut self,
        opcode: Opcode,
        stream_id: u32,
        payload_len: u32,
    ) -> Result<(), FlowMuxError> {
        let payload = self.frame_payload(payload_len).to_vec();
        let flow = self.http_flows.get_mut(&stream_id).ok_or_else(|| {
            FlowMuxError::FrameRefused(format!("http frame on unopened flow {stream_id}"))
        })?;
        if opcode == Opcode::HttpRequestHead {
            let request = flow
                .accept_head(&payload)
                .map_err(|e| FlowMuxError::FrameRefused(e.to_string()))?;
            let (Some(service), Some(handle)) = (&self.substitution, &self.runtime_handle) else {
                return Err(FlowMuxError::FrameRefused(
                    "no runtime to forward the http flow on".to_string(),
                ));
            };
            let (cancel_sender, cancel_receiver) = tokio::sync::watch::channel(false);
            self.http_cancellations
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(stream_id, cancel_sender);
            let task = http_flow::ForwardTask::builder()
                .runtime(handle.clone())
                .service(Arc::clone(service))
                .session(Arc::clone(&self.session))
                .writer(Arc::clone(&self.writer))
                .stream_id(stream_id)
                .request(request)
                .cancellation(cancel_receiver)
                .cancellations(Arc::clone(&self.http_cancellations))
                .registry(Arc::clone(&self.registry))
                .build()
                .map_err(|error| FlowMuxError::FrameRefused(error.to_string()))?;
            http_flow::spawn_forward(task);
        } else {
            flow.accept_body(&payload)
                .map_err(|e| FlowMuxError::FrameRefused(e.to_string()))?;
        }
        if flow.is_complete() {
            http_flow::cancel(&mut self.http_flows, stream_id);
        }
        Ok(())
    }

    /// The payload of the frame currently in `read_buf`.
    ///
    /// The frame is decoded in place, so the payload is readable without a
    /// copy. One accessor rather than the same two-line slice at each call
    /// site: those indexed unchecked, so a frame shorter than its header
    /// claimed would have panicked the session thread rather than refusing a
    /// frame.
    fn frame_payload(&self, payload_len: u32) -> &[u8] {
        let start = LENGTH_PREFIX_LEN + HEADER_LEN;
        let end = start.saturating_add(payload_len as usize);
        self.read_buf.get(start..end).unwrap_or(&[])
    }

    fn handle_window_update(
        &mut self,
        stream_id: u32,
        payload_len: u32,
    ) -> Result<(), FlowMuxError> {
        if payload_len != 4 {
            return Err(FlowMuxError::FrameRefused(
                "WindowUpdate payload must be 4 bytes".to_string(),
            ));
        }
        let payload = self.frame_payload(payload_len);
        let delta = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
        lock_registry(&self.registry)
            .grant_host_credit(stream_id, delta)
            .map_err(|e| FlowMuxError::FrameRefused(e.to_string()))
    }

    fn handle_inbound_ready(&mut self, stream_id: u32) {
        let result = lock_registry(&self.registry)
            .confirm(stream_id)
            .map_err(|error| error.to_string());
        if let Some(sender) = lock_pending_ingress(&self.pending_ingress).remove(&stream_id) {
            let _ = sender.send(result);
        }
    }

    fn handle_inbound_refused(&mut self, stream_id: u32, payload_len: u32) {
        let reason = String::from_utf8_lossy(self.frame_payload(payload_len)).into_owned();
        let _ = lock_registry(&self.registry).retire(stream_id);
        if let Some(sender) = lock_pending_ingress(&self.pending_ingress).remove(&stream_id) {
            let _ = sender.send(Err(reason));
        }
    }

    fn reset_stream(&mut self, stream_id: u32) -> Result<(), FlowMuxError> {
        // Dropping an incomplete typed request wipes its zeroizing body buffer.
        // A guest reset is cancellation, not permission to retain the partial
        // cleartext until the authenticated session itself eventually exits.
        self.http_flows.remove(&stream_id);
        http_flow::cancel_forwarding(&self.http_cancellations, stream_id);
        let was_live = lock_tcp_streams(&self.streams).remove(&stream_id);
        let live = was_live.is_some();
        if let Some(handle) = was_live {
            handle.retired.store(true, Ordering::Relaxed);
            let _ = handle.upstream.shutdown(std::net::Shutdown::Both);
        }
        let _ = lock_registry(&self.registry).retire(stream_id);
        // Only announce a teardown we are actually performing. A relay thread
        // that already reset this stream has told the guest once; telling it
        // again names a stream the guest has retired, which is a protocol error
        // on its validator and kills the whole session — taking every other
        // live stream with it. The guest is right to refuse the second one, so
        // the fix belongs here.
        if live {
            self.send_reset(stream_id, "reset by peer")?;
        }
        Ok(())
    }

    fn remove_stream(&mut self, stream_id: u32) {
        if let Some(handle) = lock_tcp_streams(&self.streams).remove(&stream_id) {
            handle.retired.store(true, Ordering::Relaxed);
            let _ = handle.upstream.shutdown(std::net::Shutdown::Both);
        }
        let _ = lock_registry(&self.registry).retire(stream_id);
    }

    fn send_hello_ack(&self) -> Result<(), FlowMuxError> {
        self.write_frame(Opcode::HelloAck, 0, &Handshake::local(HOST_BUILD).encode())
    }

    fn send_goaway(&self, reason: &str) -> Result<(), FlowMuxError> {
        warn!(%reason, "FlowMux sending GoAway");
        self.write_frame(Opcode::GoAway, 0, reason.as_bytes())
    }

    /// Facts for a frame arriving from the guest.
    ///
    /// A `WindowUpdate`'s payload *is* its credit, and the validator refuses an
    /// update that carries none. Describing one by length alone therefore
    /// refuses every window update the guest sends, and the host answers a
    /// perfectly good frame with `GoAway` — killing the session on the first
    /// credit the guest returns. The guest-side reader has the same shape for
    /// the same reason.
    fn inbound_frame_facts(
        read_buf: &[u8],
        opcode: Opcode,
        stream_id: u32,
        payload_len: u32,
    ) -> mvm_contract::protocol::network_flow::FrameFacts {
        let facts = mvm_contract::protocol::network_flow::FrameFacts::new(
            Direction::GuestToHost,
            opcode,
            stream_id,
        )
        .with_payload(payload_len);
        if opcode != Opcode::WindowUpdate {
            return facts;
        }
        let start = LENGTH_PREFIX_LEN + HEADER_LEN;
        match read_buf.get(start..start + 4) {
            // A malformed or truncated update keeps no credit, so the
            // validator still refuses it — this reads the field, it does not
            // wave frames through.
            Some([a, b, c, d]) => facts.with_credit(u32::from_be_bytes([*a, *b, *c, *d])),
            _ => facts,
        }
    }

    /// Advance the local state machine for a frame the host is about to send.
    /// Each side validates the frames it reads, but a confirming or terminal
    /// frame sent by the host still moves the host-side view of the stream.
    fn mark_sent(&mut self, opcode: Opcode, stream_id: u32) {
        let _ = lock_validator(&self.validator).admit(
            &mvm_contract::protocol::network_flow::FrameFacts::new(
                Direction::HostToGuest,
                opcode,
                stream_id,
            ),
        );
    }

    fn send_opened(&mut self, stream_id: u32) -> Result<(), FlowMuxError> {
        info!(stream_id, "FlowMux sending Opened");
        self.write_frame(Opcode::Opened, stream_id, b"")?;
        self.mark_sent(Opcode::Opened, stream_id);
        Ok(())
    }

    fn send_refused(&mut self, stream_id: u32, reason: &str) -> Result<(), FlowMuxError> {
        warn!(stream_id, %reason, "FlowMux sending Refused");
        self.write_frame(Opcode::Refused, stream_id, reason.as_bytes())?;
        self.mark_sent(Opcode::Refused, stream_id);
        Ok(())
    }

    fn send_resolved(&mut self, stream_id: u32, response: &[u8]) -> Result<(), FlowMuxError> {
        info!(stream_id, len = response.len(), "FlowMux sending Resolved");
        self.write_frame(Opcode::Resolved, stream_id, response)?;
        self.mark_sent(Opcode::Resolved, stream_id);
        Ok(())
    }

    fn send_resolve_refused(&mut self, stream_id: u32, reason: &str) -> Result<(), FlowMuxError> {
        warn!(stream_id, %reason, "FlowMux sending ResolveRefused");
        self.write_frame(Opcode::ResolveRefused, stream_id, reason.as_bytes())?;
        self.mark_sent(Opcode::ResolveRefused, stream_id);
        Ok(())
    }

    fn send_reset(&self, stream_id: u32, reason: &str) -> Result<(), FlowMuxError> {
        warn!(stream_id, %reason, "FlowMux sending Reset");
        self.write_frame(Opcode::Reset, stream_id, reason.as_bytes())
    }

    fn send_window_update(&self, stream_id: u32, delta: u32) -> Result<(), FlowMuxError> {
        self.write_frame(Opcode::WindowUpdate, stream_id, &delta.to_be_bytes())
    }

    fn write_frame(
        &self,
        opcode: Opcode,
        stream_id: u32,
        payload: &[u8],
    ) -> Result<(), FlowMuxError> {
        write_frame_to(&self.session, &self.writer, opcode, stream_id, payload)
    }

    /// Read one decrypted FlowMux frame from the peer, returning the opcode,
    /// stream id, and payload length, or `None` on clean close.
    ///
    /// The session layer encrypts each frame; this helper reads the encrypted
    /// envelope, opens it, and decodes the inner FlowMux header.
    fn read_frame(&mut self) -> Result<Option<(Opcode, u32, u32)>, FlowMuxError> {
        let mut len_buf = [0u8; 4];
        match self.reader.read_exact(&mut len_buf) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) if is_peer_disconnect(&e) => return Ok(None),
            Err(e) => return Err(e.into()),
        }
        let sealed_len = u32::from_be_bytes(len_buf) as usize;
        if sealed_len == 0 {
            return Ok(None);
        }
        if sealed_len > 1 << 20 {
            return Err(FlowMuxError::FrameRefused(format!(
                "FlowMux sealed frame length {sealed_len} exceeds 1 MiB"
            )));
        }
        let mut sealed_buf = vec![0u8; sealed_len];
        if let Err(e) = self.reader.read_exact(&mut sealed_buf) {
            if is_peer_disconnect(&e) {
                return Ok(None);
            }
            return Err(e.into());
        }

        let sealed = mvm_core::net::session::SealedFrame::decode(&sealed_buf)
            .map_err(|e| FlowMuxError::FrameRefused(e.to_string()))?;
        self.read_buf = {
            let mut session = lock_session(&self.session);
            session
                .open(&sealed)
                .map_err(|e| FlowMuxError::FrameRefused(e.to_string()))?
        };

        let frame = match decode(&self.read_buf) {
            Ok(frame) => frame,
            Err(FrameError::Incomplete { have: 0, .. }) => return Ok(None),
            Err(e) => return Err(FlowMuxError::FrameRefused(e.to_string())),
        };

        Ok(Some((
            frame.header.opcode,
            frame.header.stream_id,
            frame.header.payload_len,
        )))
    }
}
