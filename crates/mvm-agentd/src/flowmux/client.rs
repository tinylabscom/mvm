use super::pump::SessionPump;
use super::*;

impl FlowMuxClient {
    /// Connect to the host NetworkFlow channel and complete the FlowMux
    /// handshake (`Hello` / `HelloAck`).
    ///
    /// The cryptographic session handshake is performed as the guest using
    /// `guest_signing_key` and the pinned host anchor. After the handshake the
    /// session task takes ownership of `stream` and runs until it closes.
    pub async fn connect<S>(
        stream: S,
        guest_signing_key: SigningKey,
        host_anchor: VerifyingKey,
    ) -> Result<Self, FlowMuxError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        Self::connect_with_ingress(stream, guest_signing_key, host_anchor, Vec::new()).await
    }

    /// Connect with the signed plan's guest-loopback ingress targets.
    pub async fn connect_with_ingress<S>(
        stream: S,
        guest_signing_key: SigningKey,
        host_anchor: VerifyingKey,
        ingress_targets: Vec<GuestIngressTarget>,
    ) -> Result<Self, FlowMuxError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let handle = tokio::runtime::Handle::try_current()
            .map_err(|e| FlowMuxError::Handshake(e.to_string()))?;

        let handshake = tokio::task::spawn_blocking(move || {
            let mut adapter = AsyncStreamSyncAdapter::new(stream, handle);
            Session::guest(&mut adapter, guest_signing_key, &host_anchor)
                .map_err(|e| FlowMuxError::Handshake(e.to_string()))
                .map(|(session, session_id)| {
                    let stream = adapter.into_inner();
                    (session, session_id, stream)
                })
        })
        .await
        .map_err(|e| FlowMuxError::Handshake(e.to_string()))?;

        let (session, _session_id, stream) = handshake?;

        let (client_tx, client_rx) = mpsc::unbounded_channel();
        let (state_tx, state_rx) = watch::channel(SessionState::Connecting);

        let mut targets = BTreeMap::new();
        for target in ingress_targets {
            if target.mapping_id == 0 || targets.insert(target.mapping_id, target).is_some() {
                return Err(FlowMuxError::Frame(
                    "ingress targets must have unique non-zero mapping ids".to_string(),
                ));
            }
        }

        let next_stream_id = Arc::new(AtomicU32::new(FIRST_GUEST_STREAM_ID));
        let pump = SessionPump {
            stream: Box::pin(stream),
            session,
            validator: SessionValidator::new_with_ingress(targets.iter().map(
                |(&mapping, target)| {
                    let kind = match target.protocol {
                        mvm_contract::plan::IngressProtocol::Tcp => {
                            mvm_contract::protocol::network_flow::IngressFlowKind::Tcp
                        }
                        mvm_contract::plan::IngressProtocol::Udp => {
                            mvm_contract::protocol::network_flow::IngressFlowKind::Udp
                        }
                    };
                    (mapping, kind)
                },
            )),
            client_rx,
            client_tx: client_tx.clone(),
            state_tx,
            ingress_targets: targets,
            tcp_streams: BTreeMap::new(),
            udp_associations: BTreeMap::new(),
            inbound_udp: BTreeMap::new(),
            pending_opens: BTreeMap::new(),
            pending_resolves: BTreeMap::new(),
            frame_reader: FrameReader::default(),
        };

        tokio::spawn(async move {
            if let Err(e) = pump.run().await {
                warn!(error = %e, "FlowMux session pump ended");
            }
        });

        Ok(Self {
            tx: client_tx,
            state: state_rx,
            next_stream_id,
        })
    }

    /// Wait until the session is ready, or fail if it becomes dead.
    async fn await_ready(&self) -> Result<(), FlowMuxError> {
        let mut state = self.state.clone();
        loop {
            let snapshot = state.borrow().clone();
            match snapshot {
                SessionState::Ready => return Ok(()),
                SessionState::Dead(reason) => {
                    return Err(FlowMuxError::SessionClosed(reason.to_string()));
                }
                SessionState::Connecting | SessionState::Reconnecting => {
                    if state.changed().await.is_err() {
                        return Err(FlowMuxError::SessionClosed("state watch closed".into()));
                    }
                }
            }
        }
    }

    /// Allocate a fresh odd guest stream ID.
    fn alloc_stream_id(&self) -> u32 {
        self.next_stream_id.fetch_add(2, Ordering::Relaxed)
    }

    /// A receiver that tracks the session lifecycle.
    pub fn state(&self) -> watch::Receiver<SessionState> {
        self.state.clone()
    }

    /// Open a TCP flow to `target` (`host:port`).
    ///
    /// This waits for the host to confirm the open with `Opened` before
    /// returning. A refused open surfaces as [`FlowMuxError::Refused`].
    pub async fn open_tcp(&self, target: &str) -> Result<FlowMuxStream, FlowMuxError> {
        self.await_ready().await?;
        let stream_id = self.alloc_stream_id();
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(ClientRequest::OpenTcp {
                target: target.to_string(),
                stream_id,
                respond: tx,
            })
            .map_err(|_| FlowMuxError::ChannelClosed)?;
        rx.await.map_err(|_| FlowMuxError::ChannelClosed)?
    }

    /// Open a UDP association.
    pub async fn open_udp(&self) -> Result<FlowMuxUdpSocket, FlowMuxError> {
        self.await_ready().await?;
        let stream_id = self.alloc_stream_id();
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(ClientRequest::OpenUdp {
                stream_id,
                respond: tx,
            })
            .map_err(|_| FlowMuxError::ChannelClosed)?;
        rx.await.map_err(|_| FlowMuxError::ChannelClosed)?
    }

    /// Resolve a DNS name. Returns the raw DNS response bytes.
    pub async fn resolve(&self, name: &str, qtype: u16) -> Result<Vec<u8>, FlowMuxError> {
        self.await_ready().await?;
        let stream_id = self.alloc_stream_id();
        let query = build_dns_query(name, qtype, stream_id as u16)?;
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(ClientRequest::Resolve {
                stream_id,
                query,
                respond: tx,
            })
            .map_err(|_| FlowMuxError::ChannelClosed)?;
        rx.await.map_err(|_| FlowMuxError::ChannelClosed)?
    }
}
