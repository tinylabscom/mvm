use super::*;

/// Background task that owns the FlowMux session.
pub(super) struct SessionPump<S> {
    pub(super) stream: Pin<Box<S>>,
    pub(super) session: mvm_core::net::session::Session,
    pub(super) validator: SessionValidator,
    pub(super) client_rx: mpsc::UnboundedReceiver<ClientRequest>,
    pub(super) client_tx: mpsc::UnboundedSender<ClientRequest>,
    pub(super) state_tx: watch::Sender<SessionState>,
    pub(super) ingress_targets: BTreeMap<u16, GuestIngressTarget>,
    pub(super) tcp_streams: BTreeMap<u32, TcpStreamState>,
    pub(super) udp_associations: BTreeMap<u32, UdpAssociationState>,
    pub(super) inbound_udp: BTreeMap<u32, mpsc::Sender<InboundUdpDatagram>>,
    pub(super) pending_opens: BTreeMap<u32, PendingOpen>,
    pub(super) pending_resolves: BTreeMap<u32, oneshot::Sender<Result<Vec<u8>, FlowMuxError>>>,
    /// Survives a `select!` cancellation so a half-read frame resumes.
    pub(super) frame_reader: FrameReader,
}

impl<S> SessionPump<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    pub(super) async fn run(mut self) -> Result<(), FlowMuxError> {
        let outcome = self.run_until_closed().await;
        self.fail_all("session closed");
        let reason: Arc<str> = match &outcome {
            Ok(()) => Arc::from("session closed"),
            Err(e) => Arc::from(e.to_string().as_str()),
        };
        let _ = self.state_tx.send(SessionState::Dead(reason));
        outcome
    }

    async fn run_until_closed(&mut self) -> Result<(), FlowMuxError> {
        self.send_hello().await?;
        self.read_hello_ack().await?;
        let _ = self.state_tx.send(SessionState::Ready);

        loop {
            tokio::select! {
                biased;
                req = self.client_rx.recv() => {
                    match req {
                        Some(req) => self.handle_request(req).await?,
                        None => {
                            info!("FlowMux client dropped; closing session");
                            break;
                        }
                    }
                }
                frame = self
                    .frame_reader
                    .read(&mut self.stream, &mut self.session) => {
                    match frame? {
                        Some((opcode, stream_id, _payload_len, payload)) => {
                            self.handle_frame(opcode, stream_id, payload).await?;
                        }
                        None => {
                            info!("FlowMux peer closed session");
                            break;
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn fail_all(&mut self, reason: &str) {
        let reason = reason.to_string();
        for (_id, state) in std::mem::take(&mut self.tcp_streams) {
            let _ = state.tx.send(StreamEvent::Reset(reason.clone()));
        }
        for (_id, state) in std::mem::take(&mut self.udp_associations) {
            let _ = state.tx.send(UdpEvent::Reset(reason.clone()));
        }
        for (_id, pending) in std::mem::take(&mut self.pending_opens) {
            complete_pending_open_error(pending, FlowMuxError::SessionClosed(reason.clone()));
        }
        for (_id, respond) in std::mem::take(&mut self.pending_resolves) {
            let _ = respond.send(Err(FlowMuxError::SessionClosed(reason.clone())));
        }
    }

    async fn send_hello(&mut self) -> Result<(), FlowMuxError> {
        let payload = Handshake::local(GUEST_BUILD).encode();
        self.validator
            .admit(&frame_facts(
                Direction::GuestToHost,
                Opcode::Hello,
                0,
                payload.len() as u32,
            ))
            .map_err(|e| FlowMuxError::Frame(e.to_string()))?;
        self.write_frame(Opcode::Hello, 0, &payload).await
    }

    async fn read_hello_ack(&mut self) -> Result<(), FlowMuxError> {
        let (opcode, stream_id, payload_len, payload) =
            self.read_frame().await?.ok_or_else(|| {
                // The host closing here is the shape of a host that is not
                // speaking FlowMux at all, so say so rather than reporting a
                // bare disconnect the operator has to guess at.
                FlowMuxError::SessionClosed(format!(
                    "host closed the connection before answering the FlowMux handshake; \
                     this guest is {GUEST_BUILD} — the host endpoint is either stale or \
                     serving a different egress protocol"
                ))
            })?;
        if opcode != Opcode::HelloAck || stream_id != 0 {
            return Err(FlowMuxError::Frame(format!(
                "expected HelloAck, got {opcode:?} on stream {stream_id}"
            )));
        }
        let host = Handshake::decode(&payload).map_err(|e| FlowMuxError::Frame(e.to_string()))?;
        agree(&Handshake::local(GUEST_BUILD), &host)
            .map_err(|e| FlowMuxError::Frame(e.to_string()))?;
        self.validator
            .admit(&frame_facts(
                Direction::HostToGuest,
                Opcode::HelloAck,
                stream_id,
                payload_len,
            ))
            .map_err(|e| FlowMuxError::Frame(e.to_string()))?;
        Ok(())
    }

    async fn handle_request(&mut self, req: ClientRequest) -> Result<(), FlowMuxError> {
        match req {
            ClientRequest::OpenTcp {
                target,
                stream_id,
                respond,
            } => {
                self.do_open_tcp(target, stream_id, respond).await;
            }
            ClientRequest::OpenUdp { stream_id, respond } => {
                self.do_open_udp(stream_id, respond).await;
            }
            ClientRequest::Resolve {
                stream_id,
                query,
                respond,
            } => {
                self.do_resolve(stream_id, query, respond).await;
            }
            ClientRequest::SendData { stream_id, bytes } => {
                self.send_data(stream_id, &bytes).await?;
            }
            ClientRequest::HalfClose { stream_id } => {
                self.send_half_close(stream_id).await?;
            }
            ClientRequest::Reset { stream_id, reason } => {
                self.send_reset(stream_id, &reason).await?;
            }
            ClientRequest::UdpSend {
                stream_id,
                destination,
                payload,
            } => {
                self.send_udp(stream_id, destination, &payload).await?;
            }
            ClientRequest::InboundUdpReply {
                stream_id,
                peer,
                payload,
            } => {
                self.send_udp(stream_id, peer, &payload).await?;
            }
            ClientRequest::CloseUdp { stream_id } => {
                self.send_close_udp(stream_id).await?;
            }
        }
        Ok(())
    }

    async fn do_open_tcp(
        &mut self,
        target: String,
        stream_id: u32,
        respond: oneshot::Sender<Result<FlowMuxStream, FlowMuxError>>,
    ) {
        if self
            .validator
            .admit(&frame_facts(
                Direction::GuestToHost,
                Opcode::OpenTcp,
                stream_id,
                target.len() as u32,
            ))
            .is_err()
        {
            let _ = respond.send(Err(FlowMuxError::SessionClosed("invalid open".into())));
            return;
        }

        let (stream_event_tx, stream_event_rx) = mpsc::unbounded_channel();
        self.pending_opens.insert(
            stream_id,
            PendingOpen::Tcp {
                respond,
                stream_event_tx,
                stream_event_rx,
            },
        );

        if let Err(e) = self
            .write_frame(Opcode::OpenTcp, stream_id, target.as_bytes())
            .await
            && let Some(PendingOpen::Tcp { respond, .. }) = self.pending_opens.remove(&stream_id)
        {
            let _ = respond.send(Err(e));
        }
    }

    async fn do_open_udp(
        &mut self,
        stream_id: u32,
        respond: oneshot::Sender<Result<FlowMuxUdpSocket, FlowMuxError>>,
    ) {
        if self
            .validator
            .admit(&frame_facts(
                Direction::GuestToHost,
                Opcode::OpenUdp,
                stream_id,
                0,
            ))
            .is_err()
        {
            let _ = respond.send(Err(FlowMuxError::SessionClosed("invalid open".into())));
            return;
        }

        let (udp_event_tx, udp_event_rx) = mpsc::unbounded_channel();
        self.pending_opens.insert(
            stream_id,
            PendingOpen::Udp {
                respond,
                udp_event_tx,
                udp_event_rx,
            },
        );

        if let Err(e) = self.write_frame(Opcode::OpenUdp, stream_id, &[]).await
            && let Some(PendingOpen::Udp { respond, .. }) = self.pending_opens.remove(&stream_id)
        {
            let _ = respond.send(Err(e));
        }
    }

    async fn do_resolve(
        &mut self,
        stream_id: u32,
        query: Vec<u8>,
        respond: oneshot::Sender<Result<Vec<u8>, FlowMuxError>>,
    ) {
        if self
            .validator
            .admit(&frame_facts(
                Direction::GuestToHost,
                Opcode::Resolve,
                stream_id,
                query.len() as u32,
            ))
            .is_err()
        {
            let _ = respond.send(Err(FlowMuxError::SessionClosed("invalid resolve".into())));
            return;
        }

        self.pending_resolves.insert(stream_id, respond);

        if let Err(e) = self.write_frame(Opcode::Resolve, stream_id, &query).await
            && let Some(respond) = self.pending_resolves.remove(&stream_id)
        {
            let _ = respond.send(Err(e));
        }
    }

    async fn handle_frame(
        &mut self,
        opcode: Opcode,
        stream_id: u32,
        payload: Vec<u8>,
    ) -> Result<(), FlowMuxError> {
        self.validator
            .admit(&inbound_frame_facts(opcode, stream_id, &payload))
            .map_err(|e| FlowMuxError::Frame(e.to_string()))?;

        match opcode {
            Opcode::InboundOpen => {
                self.handle_inbound_open(stream_id, &payload).await?;
            }
            Opcode::Opened => {
                if let Some(PendingOpen::Tcp {
                    respond,
                    stream_event_tx,
                    stream_event_rx,
                }) = self.pending_opens.remove(&stream_id)
                {
                    let handle = FlowMuxStream {
                        stream_id,
                        tx: self.client_tx.clone(),
                        rx: stream_event_rx,
                        read_buf: Vec::new(),
                    };
                    self.tcp_streams.insert(
                        stream_id,
                        TcpStreamState {
                            tx: stream_event_tx,
                            host_half_closed: false,
                        },
                    );
                    let _ = respond.send(Ok(handle));
                }
            }
            Opcode::UdpOpened => {
                if let Some(PendingOpen::Udp {
                    respond,
                    udp_event_tx,
                    udp_event_rx,
                }) = self.pending_opens.remove(&stream_id)
                {
                    let handle = FlowMuxUdpSocket {
                        stream_id,
                        tx: self.client_tx.clone(),
                        rx: udp_event_rx,
                    };
                    self.udp_associations
                        .insert(stream_id, UdpAssociationState { tx: udp_event_tx });
                    let _ = respond.send(Ok(handle));
                }
            }
            Opcode::Refused => {
                let reason = String::from_utf8_lossy(&payload).into_owned();
                if let Some(pending) = self.pending_opens.remove(&stream_id) {
                    complete_pending_open_error(pending, FlowMuxError::refused(reason));
                } else if let Some(respond) = self.pending_resolves.remove(&stream_id) {
                    let _ = respond.send(Err(FlowMuxError::refused(reason)));
                }
            }
            Opcode::Resolved => {
                if let Some(respond) = self.pending_resolves.remove(&stream_id) {
                    let _ = respond.send(Ok(payload));
                }
            }
            Opcode::ResolveRefused => {
                let reason = String::from_utf8_lossy(&payload).into_owned();
                if let Some(respond) = self.pending_resolves.remove(&stream_id) {
                    let _ = respond.send(Err(FlowMuxError::refused(reason)));
                }
            }
            Opcode::Data => {
                let consumed = u32::try_from(payload.len()).unwrap_or(u32::MAX);
                let delivered = match self.tcp_streams.get_mut(&stream_id) {
                    Some(state) => {
                        let _ = state.tx.send(StreamEvent::Data(payload));
                        true
                    }
                    None => false,
                };
                // Return the credit those bytes consumed.
                //
                // The host replenishes the guest's window on every DATA it
                // relays, but nothing replenished the host's — so the host→guest
                // window drained and the host reset the stream the moment it hit
                // zero. That caps every download at one window (~48 KiB here) and
                // surfaces as a truncated archive rather than as a flow-control
                // failure. Only for a stream we still hold: replenishing one we
                // have already retired would name a stream the host has closed.
                if delivered && consumed > 0 {
                    self.send_window_update(stream_id, consumed).await?;
                }
            }
            Opcode::HalfClose => {
                if let Some(state) = self.tcp_streams.get_mut(&stream_id) {
                    state.host_half_closed = true;
                    let _ = state.tx.send(StreamEvent::HalfClose);
                }
            }
            Opcode::Reset => {
                let reason = String::from_utf8_lossy(&payload).into_owned();
                if let Some(state) = self.tcp_streams.remove(&stream_id) {
                    let _ = state.tx.send(StreamEvent::Reset(reason.clone()));
                }
                if let Some(state) = self.udp_associations.remove(&stream_id) {
                    let _ = state.tx.send(UdpEvent::Reset(reason.clone()));
                }
                self.inbound_udp.remove(&stream_id);
                if let Some(pending) = self.pending_opens.remove(&stream_id) {
                    complete_pending_open_error(
                        pending,
                        FlowMuxError::SessionClosed(reason.clone()),
                    );
                }
                if let Some(respond) = self.pending_resolves.remove(&stream_id) {
                    let _ = respond.send(Err(FlowMuxError::SessionClosed(reason)));
                }
            }
            Opcode::UdpRecv => {
                if let Ok((addr, body)) = decode_udp_addr(&payload) {
                    if let Some(sender) = self.inbound_udp.get(&stream_id) {
                        let _ = sender.try_send(InboundUdpDatagram {
                            peer: addr,
                            payload: body.to_vec(),
                        });
                    } else if let Some(state) = self.udp_associations.get_mut(&stream_id) {
                        let _ = state.tx.send(UdpEvent::Recv(addr, body.to_vec()));
                    }
                }
            }
            Opcode::CloseUdp => {
                let reason = String::from_utf8_lossy(&payload).into_owned();
                if let Some(state) = self.udp_associations.remove(&stream_id) {
                    let _ = state.tx.send(UdpEvent::CloseUdp(reason));
                }
                self.inbound_udp.remove(&stream_id);
            }
            Opcode::WindowUpdate => {
                if payload.len() == 4 {
                    let delta =
                        u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
                    if let Some(state) = self.tcp_streams.get_mut(&stream_id) {
                        let _delta = delta;
                        let _ = state.tx.send(StreamEvent::WindowUpdate);
                    }
                }
            }
            Opcode::GoAway => {
                let reason = String::from_utf8_lossy(&payload).into_owned();
                return Err(FlowMuxError::SessionClosed(reason));
            }
            _ => {
                warn!(
                    ?opcode,
                    stream_id, "FlowMux client ignoring unexpected frame"
                );
            }
        }
        Ok(())
    }

    async fn handle_inbound_open(
        &mut self,
        stream_id: u32,
        payload: &[u8],
    ) -> Result<(), FlowMuxError> {
        let Some(mapping_id) = decode_ingress_mapping_id(payload) else {
            return self
                .send_inbound_refused(stream_id, "missing ingress mapping id")
                .await;
        };
        let Some(target) = self.ingress_targets.get(&mapping_id).cloned() else {
            return self
                .send_inbound_refused(stream_id, "undeclared ingress mapping")
                .await;
        };
        match target.protocol {
            mvm_contract::plan::IngressProtocol::Tcp => {
                self.open_inbound_tcp(stream_id, mapping_id, &target).await
            }
            mvm_contract::plan::IngressProtocol::Udp => {
                self.open_inbound_udp(stream_id, mapping_id, &target).await
            }
        }
    }

    async fn open_inbound_tcp(
        &mut self,
        stream_id: u32,
        mapping_id: u16,
        target: &GuestIngressTarget,
    ) -> Result<(), FlowMuxError> {
        let guest_ip = target.guest_addr.parse().map_err(|error| {
            FlowMuxError::Frame(format!("invalid guest ingress target: {error}"))
        })?;
        let address = SocketAddr::new(guest_ip, target.guest_port);
        let local = match tokio::net::TcpStream::connect(address).await {
            Ok(stream) => stream,
            Err(error) => {
                warn!(mapping_id, %address, %error, "guest ingress target refused connection");
                return self
                    .send_inbound_refused(stream_id, "guest loopback target unavailable")
                    .await;
            }
        };

        let (stream_event_tx, stream_event_rx) = mpsc::unbounded_channel();
        self.tcp_streams.insert(
            stream_id,
            TcpStreamState {
                tx: stream_event_tx,
                host_half_closed: false,
            },
        );
        self.send_inbound_ready(stream_id).await?;

        let mut flow = FlowMuxStream {
            stream_id,
            tx: self.client_tx.clone(),
            rx: stream_event_rx,
            read_buf: Vec::new(),
        };
        tokio::spawn(async move {
            let mut local = local;
            if let Err(error) = tokio::io::copy_bidirectional(&mut local, &mut flow).await {
                warn!(stream_id, %error, "guest ingress relay ended");
            }
        });
        Ok(())
    }

    async fn open_inbound_udp(
        &mut self,
        stream_id: u32,
        mapping_id: u16,
        target: &GuestIngressTarget,
    ) -> Result<(), FlowMuxError> {
        let guest_ip = target.guest_addr.parse().map_err(|error| {
            FlowMuxError::Frame(format!("invalid guest UDP ingress target: {error}"))
        })?;
        let target_addr = SocketAddr::new(guest_ip, target.guest_port);
        let bind_addr = SocketAddr::new(guest_ip, 0);
        let socket = match tokio::net::UdpSocket::bind(bind_addr).await {
            Ok(socket) => socket,
            Err(error) => {
                warn!(mapping_id, %bind_addr, %error, "guest UDP ingress bind failed");
                return self
                    .send_inbound_refused(stream_id, "guest UDP ingress unavailable")
                    .await;
            }
        };
        if let Err(error) = socket.connect(target_addr).await {
            warn!(mapping_id, %target_addr, %error, "guest UDP ingress target connect failed");
            return self
                .send_inbound_refused(stream_id, "guest UDP ingress target unavailable")
                .await;
        }

        let (datagram_tx, mut datagram_rx) = mpsc::channel::<InboundUdpDatagram>(64);
        self.inbound_udp.insert(stream_id, datagram_tx);
        self.send_inbound_ready(stream_id).await?;
        let client_tx = self.client_tx.clone();
        tokio::spawn(async move {
            let mut response = vec![0_u8; MAX_UDP_DATAGRAM_LEN];
            while let Some(datagram) = datagram_rx.recv().await {
                if let Err(error) = socket.send(&datagram.payload).await {
                    warn!(stream_id, %error, "guest UDP ingress delivery failed");
                    break;
                }
                let received =
                    match tokio::time::timeout(Duration::from_secs(5), socket.recv(&mut response))
                        .await
                    {
                        Ok(Ok(received)) => received,
                        Ok(Err(error)) => {
                            warn!(stream_id, %error, "guest UDP ingress reply failed");
                            break;
                        }
                        Err(_) => continue,
                    };
                if client_tx
                    .send(ClientRequest::InboundUdpReply {
                        stream_id,
                        peer: datagram.peer,
                        payload: response[..received].to_vec(),
                    })
                    .is_err()
                {
                    break;
                }
            }
        });
        Ok(())
    }

    async fn send_inbound_ready(&mut self, stream_id: u32) -> Result<(), FlowMuxError> {
        self.validator
            .admit(&frame_facts(
                Direction::GuestToHost,
                Opcode::InboundReady,
                stream_id,
                0,
            ))
            .map_err(|error| FlowMuxError::Frame(error.to_string()))?;
        self.write_frame(Opcode::InboundReady, stream_id, &[]).await
    }

    async fn send_inbound_refused(
        &mut self,
        stream_id: u32,
        reason: &str,
    ) -> Result<(), FlowMuxError> {
        self.validator
            .admit(&frame_facts(
                Direction::GuestToHost,
                Opcode::InboundRefused,
                stream_id,
                reason.len() as u32,
            ))
            .map_err(|error| FlowMuxError::Frame(error.to_string()))?;
        self.write_frame(Opcode::InboundRefused, stream_id, reason.as_bytes())
            .await
    }

    async fn send_data(&mut self, stream_id: u32, bytes: &[u8]) -> Result<(), FlowMuxError> {
        self.write_frame(Opcode::Data, stream_id, bytes).await
    }

    async fn send_half_close(&mut self, stream_id: u32) -> Result<(), FlowMuxError> {
        self.write_frame(Opcode::HalfClose, stream_id, &[]).await
    }

    /// Grant the host `delta` more bytes of room on this stream.
    ///
    /// The mirror of the host's replenish. A zero delta is a frame error by
    /// the protocol, so callers only reach here with bytes actually consumed.
    async fn send_window_update(&mut self, stream_id: u32, delta: u32) -> Result<(), FlowMuxError> {
        self.write_frame(Opcode::WindowUpdate, stream_id, &delta.to_be_bytes())
            .await?;
        // Advance our own view of the host's allowance to match what we just
        // told it. The validator only learns of credit it admits, so a grant
        // that goes out on the wire without this leaves the local window
        // shrinking while the host's grows — and the guest then refuses the
        // host's data as over-credit, on a window it granted itself.
        // The host keeps its own view in step the same way, via `mark_sent`.
        let _ = self.validator.admit(
            &mvm_contract::protocol::network_flow::FrameFacts::new(
                Direction::GuestToHost,
                Opcode::WindowUpdate,
                stream_id,
            )
            .with_payload(4)
            .with_credit(delta),
        );
        Ok(())
    }

    async fn send_reset(&mut self, stream_id: u32, reason: &str) -> Result<(), FlowMuxError> {
        self.write_frame(Opcode::Reset, stream_id, reason.as_bytes())
            .await
    }

    async fn send_udp(
        &mut self,
        stream_id: u32,
        destination: SocketAddr,
        payload: &[u8],
    ) -> Result<(), FlowMuxError> {
        let mut wire = encode_udp_addr(destination.ip(), destination.port());
        wire.extend_from_slice(payload);
        self.write_frame(Opcode::UdpSend, stream_id, &wire).await
    }

    async fn send_close_udp(&mut self, stream_id: u32) -> Result<(), FlowMuxError> {
        self.write_frame(Opcode::CloseUdp, stream_id, &[]).await
    }

    async fn write_frame(
        &mut self,
        opcode: Opcode,
        stream_id: u32,
        payload: &[u8],
    ) -> Result<(), FlowMuxError> {
        let mut frame = Vec::new();
        encode_into(&mut frame, opcode, stream_id, payload)
            .map_err(|e| FlowMuxError::Frame(e.to_string()))?;
        let sealed = self
            .session
            .seal(&frame)
            .map_err(|e| FlowMuxError::Frame(e.to_string()))?;
        let mut sealed_bytes = Vec::new();
        sealed
            .encode(&mut sealed_bytes)
            .map_err(|e| FlowMuxError::Frame(e.to_string()))?;
        let len = u32::try_from(sealed_bytes.len())
            .map_err(|_| FlowMuxError::Frame("sealed frame too large".into()))?;
        self.stream.write_all(&len.to_be_bytes()).await?;
        self.stream.write_all(&sealed_bytes).await?;
        self.stream.flush().await?;
        Ok(())
    }

    async fn read_frame(&mut self) -> Result<Option<(Opcode, u32, u32, Vec<u8>)>, FlowMuxError> {
        read_sealed_frame_from(&mut self.stream, &mut self.session).await
    }
}
