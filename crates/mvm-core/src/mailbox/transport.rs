//! Replaceable mailbox overlay and byte-transport interfaces.
//!
//! Logical mailbox authority stays above this module. A verified transport
//! binding proves where an identity may be reached; it does not grant mailbox
//! operations. The byte channel accepts only [`AuthorizedMailboxFrame`], which
//! is produced after capability verification. It deliberately has no packet,
//! datagram, TUN, or arbitrary raw-write API.

use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use mvm_contract::protocol::mailbox::{
    AuthorizationDomainRouteLabel, DestinationRouteToken, ED25519_SIGNATURE_BYTES, ExecutionEpoch,
    MAILBOX_PROTOCOL_VERSION, MAX_ENCODED_ENVELOPE_BYTES, MailboxAddress, MailboxEnvelope,
    MailboxEnvelopeHeader, MailboxOperation, PrincipalId, ProtocolVersion, SignatureAlgorithm,
    SignedMailboxCapability, TransportBindingId,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::crypto::aead::Key;

use super::{
    MailboxError, OpenContext, SealRequest, encode_envelope, seal_envelope,
    validate_inner_versions, validate_outer_versions, verify_capability_scope,
    verify_capability_signature, verify_identity_and_time,
};

const TRANSPORT_BINDING_SIGNATURE_DOMAIN: &[u8] = b"mvm.mailbox.transport-binding.v1\0";
const MAX_ROUTE_LOCATOR_BYTES: usize = 512;
const MAX_ROUTE_CANDIDATES: usize = 32;
const MAX_PENDING_TRANSPORT_BYTES: usize = 64 * 1024 * 1024;

macro_rules! transport_id {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(
            Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
        )]
        #[serde(transparent)]
        pub struct $name([u8; 32]);

        impl $name {
            #[must_use]
            pub const fn from_bytes(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }

            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }
    };
}

transport_id!(
    TransportIdentity,
    "Rotatable authenticated peer identity, distinct from mailbox principals."
);
transport_id!(
    RouteId,
    "Identity of one signed route candidate, distinct from route tokens."
);

/// Opaque bounded locator interpreted only by a concrete transport adapter.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct RouteLocator(String);

impl RouteLocator {
    /// Parse one non-secret, printable ASCII locator.
    pub fn parse(value: impl Into<String>) -> Result<Self, TransportBindingError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_ROUTE_LOCATOR_BYTES
            || !value.bytes().all(|byte| byte.is_ascii_graphic())
        {
            return Err(TransportBindingError::InvalidRouteLocator);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for RouteLocator {
    type Error = TransportBindingError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

impl From<RouteLocator> for String {
    fn from(value: RouteLocator) -> Self {
        value.0
    }
}

/// Observable path class. Public relays are never selected without opt-in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportPath {
    Direct,
    CustomerRelay,
    PublicRelay,
}

/// Which path classes a caller admits. The default refuses public relays, so
/// a public path is never a silent fallback.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum RelayPolicy {
    DirectOnly,
    #[default]
    CustomerRelays,
    PublicRelaysAllowed,
}

impl RelayPolicy {
    #[must_use]
    pub fn allows(self, path: TransportPath) -> bool {
        match path {
            TransportPath::Direct => true,
            TransportPath::CustomerRelay => self >= Self::CustomerRelays,
            TransportPath::PublicRelay => self == Self::PublicRelaysAllowed,
        }
    }
}

/// Confidentiality posture asserted by the signed transport binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportAssurance {
    Development,
    IsolatedProduction,
    HostBlind,
}

/// Authority-signed route and transport-identity binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransportBindingClaims {
    pub protocol_version: ProtocolVersion,
    pub signature_algorithm: SignatureAlgorithm,
    pub binding_id: TransportBindingId,
    pub issuer: PrincipalId,
    pub address: MailboxAddress,
    pub execution_epoch: ExecutionEpoch,
    pub transport_identity: TransportIdentity,
    pub route_id: RouteId,
    pub authorization_domain_route_label: AuthorizationDomainRouteLabel,
    pub destination_route_token: DestinationRouteToken,
    pub path: TransportPath,
    pub locator: RouteLocator,
    pub assurance: TransportAssurance,
    pub policy_epoch: u64,
    pub not_before_unix_ms: i64,
    pub expires_at_unix_ms: i64,
}

/// Signed transport binding. Its signature is not mailbox send authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedTransportBinding {
    pub claims: TransportBindingClaims,
    pub signature: Vec<u8>,
}

/// Current authority and lifecycle state used to verify a route binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportBindingContext {
    pub expected_issuer: PrincipalId,
    pub expected_address: MailboxAddress,
    pub current_execution_epoch: ExecutionEpoch,
    pub current_policy_epoch: u64,
    pub minimum_assurance: TransportAssurance,
    pub now_unix_ms: i64,
}

/// Transport-binding verification failures contain no locator or payload data.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TransportBindingError {
    #[error("transport binding could not be canonicalized")]
    Canonicalization,
    #[error("transport binding signature is invalid")]
    SignatureInvalid,
    #[error("unsupported transport binding protocol version")]
    UnsupportedProtocolVersion,
    #[error("unsupported transport binding signature algorithm")]
    UnsupportedSignatureAlgorithm,
    #[error("transport binding has an invalid route locator")]
    InvalidRouteLocator,
    #[error("transport binding has an invalid validity window")]
    InvalidValidityWindow,
    #[error("transport binding issuer does not match")]
    WrongIssuer,
    #[error("transport binding mailbox address does not match")]
    WrongAddress,
    #[error("transport binding execution epoch is stale")]
    StaleExecutionEpoch,
    #[error("transport binding policy epoch is stale")]
    StalePolicyEpoch,
    #[error("transport binding is not yet valid")]
    NotYetValid,
    #[error("transport binding has expired")]
    Expired,
    #[error("transport binding assurance is below the required tier")]
    InsufficientAssurance,
    #[error("transport binding signature has the wrong length")]
    InvalidSignatureLength,
}

fn binding_bytes(claims: &TransportBindingClaims) -> Result<Vec<u8>, TransportBindingError> {
    let encoded = serde_jcs::to_vec(claims).map_err(|_| TransportBindingError::Canonicalization)?;
    let mut bytes = Vec::with_capacity(
        TRANSPORT_BINDING_SIGNATURE_DOMAIN
            .len()
            .saturating_add(encoded.len()),
    );
    bytes.extend_from_slice(TRANSPORT_BINDING_SIGNATURE_DOMAIN);
    bytes.extend_from_slice(&encoded);
    Ok(bytes)
}

fn validate_binding_shape(claims: &TransportBindingClaims) -> Result<(), TransportBindingError> {
    if claims.protocol_version.0 != MAILBOX_PROTOCOL_VERSION {
        return Err(TransportBindingError::UnsupportedProtocolVersion);
    }
    if claims.signature_algorithm != SignatureAlgorithm::ED25519 {
        return Err(TransportBindingError::UnsupportedSignatureAlgorithm);
    }
    if claims.not_before_unix_ms >= claims.expires_at_unix_ms {
        return Err(TransportBindingError::InvalidValidityWindow);
    }
    RouteLocator::parse(claims.locator.as_str())?;
    Ok(())
}

/// Sign a rotatable transport binding under its own domain.
pub fn sign_transport_binding(
    claims: TransportBindingClaims,
    authority_key: &SigningKey,
) -> Result<SignedTransportBinding, TransportBindingError> {
    validate_binding_shape(&claims)?;
    let signature = authority_key.sign(&binding_bytes(&claims)?);
    Ok(SignedTransportBinding {
        claims,
        signature: signature.to_bytes().to_vec(),
    })
}

/// A route whose certificate, identity, epoch, policy, and validity all passed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedRoute {
    claims: TransportBindingClaims,
}

impl AuthorizedRoute {
    #[must_use]
    pub const fn route_id(&self) -> RouteId {
        self.claims.route_id
    }

    #[must_use]
    pub const fn path(&self) -> TransportPath {
        self.claims.path
    }

    #[must_use]
    pub const fn binding_id(&self) -> TransportBindingId {
        self.claims.binding_id
    }

    #[must_use]
    pub const fn address(&self) -> MailboxAddress {
        self.claims.address
    }

    #[must_use]
    pub const fn transport_identity(&self) -> TransportIdentity {
        self.claims.transport_identity
    }

    #[must_use]
    pub fn locator(&self) -> &RouteLocator {
        &self.claims.locator
    }
}

/// Verify and type-state one route candidate before overlay registration.
pub fn authorize_route(
    signed: &SignedTransportBinding,
    context: &TransportBindingContext,
    authority_key: &VerifyingKey,
) -> Result<AuthorizedRoute, TransportBindingError> {
    validate_binding_shape(&signed.claims)?;
    let signature: [u8; ED25519_SIGNATURE_BYTES] = signed
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| TransportBindingError::InvalidSignatureLength)?;
    authority_key
        .verify(
            &binding_bytes(&signed.claims)?,
            &Signature::from_bytes(&signature),
        )
        .map_err(|_| TransportBindingError::SignatureInvalid)?;
    let claims = &signed.claims;
    if claims.issuer != context.expected_issuer {
        return Err(TransportBindingError::WrongIssuer);
    }
    if claims.address != context.expected_address {
        return Err(TransportBindingError::WrongAddress);
    }
    if claims.execution_epoch != context.current_execution_epoch {
        return Err(TransportBindingError::StaleExecutionEpoch);
    }
    if claims.policy_epoch != context.current_policy_epoch {
        return Err(TransportBindingError::StalePolicyEpoch);
    }
    if context.now_unix_ms < claims.not_before_unix_ms {
        return Err(TransportBindingError::NotYetValid);
    }
    if context.now_unix_ms >= claims.expires_at_unix_ms {
        return Err(TransportBindingError::Expired);
    }
    if claims.assurance < context.minimum_assurance {
        return Err(TransportBindingError::InsufficientAssurance);
    }
    Ok(AuthorizedRoute {
        claims: claims.clone(),
    })
}

/// Stable logical lookup. A route result does not grant a mailbox operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverlayQuery {
    pub address: MailboxAddress,
    pub execution_epoch: ExecutionEpoch,
    pub policy_epoch: u64,
    pub now_unix_ms: i64,
    pub relay_policy: RelayPolicy,
}

/// Route resolution is synchronous and bounded; concrete overlays may refresh
/// their own state outside the mailbox hot path.
pub trait PeerOverlay {
    fn resolve(&self, query: &OverlayQuery) -> Result<Vec<AuthorizedRoute>, OverlayError>;
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum OverlayState {
    #[default]
    Available,
    Partitioned,
    ShuttingDown,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OverlayError {
    #[error("peer overlay is partitioned")]
    Partitioned,
    #[error("peer overlay is shutting down")]
    ShuttingDown,
    #[error("peer overlay has no authorized route")]
    NoAuthorizedRoute,
    #[error("peer overlay route candidate bound was exceeded")]
    CandidateBoundExceeded,
}

/// Deterministic overlay for local operation and conformance tests.
#[derive(Debug, Default)]
pub struct InMemoryPeerOverlay {
    state: OverlayState,
    routes: Vec<(u16, AuthorizedRoute)>,
}

impl InMemoryPeerOverlay {
    pub fn register(&mut self, priority: u16, route: AuthorizedRoute) -> Result<(), OverlayError> {
        if self.routes.len() >= MAX_ROUTE_CANDIDATES {
            return Err(OverlayError::CandidateBoundExceeded);
        }
        self.routes.push((priority, route));
        Ok(())
    }

    pub fn set_state(&mut self, state: OverlayState) {
        self.state = state;
    }
}

impl PeerOverlay for InMemoryPeerOverlay {
    fn resolve(&self, query: &OverlayQuery) -> Result<Vec<AuthorizedRoute>, OverlayError> {
        match self.state {
            OverlayState::Available => {}
            OverlayState::Partitioned => return Err(OverlayError::Partitioned),
            OverlayState::ShuttingDown => return Err(OverlayError::ShuttingDown),
        }
        let mut matches: Vec<_> = self
            .routes
            .iter()
            .filter(|(_, route)| {
                let claims = &route.claims;
                claims.address == query.address
                    && claims.execution_epoch == query.execution_epoch
                    && claims.policy_epoch == query.policy_epoch
                    && claims.not_before_unix_ms <= query.now_unix_ms
                    && query.now_unix_ms < claims.expires_at_unix_ms
                    && query.relay_policy.allows(claims.path)
            })
            .cloned()
            .collect();
        matches.sort_by_key(|(priority, route)| (*priority, route.path(), route.route_id()));
        if matches.is_empty() {
            return Err(OverlayError::NoAuthorizedRoute);
        }
        Ok(matches.into_iter().map(|(_, route)| route).collect())
    }
}

/// Optional fleet route metadata. The coordinator may prioritize a signed
/// binding but cannot alter its locator, identity, path, or canonical envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MvmdRouteHint {
    pub placement_generation: u64,
    pub priority: u16,
    pub binding: SignedTransportBinding,
}

/// Adapt coordinator metadata into an authorized route without touching the
/// encrypted envelope or importing coordinator types into MVM.
pub fn adapt_mvmd_route_hint(
    hint: &MvmdRouteHint,
    envelope: &MailboxEnvelope,
    context: &TransportBindingContext,
    authority_key: &VerifyingKey,
) -> Result<AuthorizedRoute, RouteAdapterError> {
    let route = authorize_route(&hint.binding, context, authority_key)?;
    let routing = &envelope.routing;
    if routing.authorization_domain_route_label != route.claims.authorization_domain_route_label
        || routing.destination_route_token != route.claims.destination_route_token
        || routing.transport_binding_id != route.claims.binding_id
    {
        return Err(RouteAdapterError::EnvelopeRouteMismatch);
    }
    Ok(route)
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RouteAdapterError {
    #[error(transparent)]
    Binding(#[from] TransportBindingError),
    #[error("fleet route hint does not match the canonical envelope routing frame")]
    EnvelopeRouteMismatch,
}

/// Fixed channel bounds. There is no unbounded queue mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelLimits {
    max_frame_bytes: usize,
    max_pending_bytes: usize,
}

impl ChannelLimits {
    pub fn new(max_frame_bytes: usize, max_pending_bytes: usize) -> Result<Self, TransportError> {
        if max_frame_bytes == 0
            || max_frame_bytes > MAX_ENCODED_ENVELOPE_BYTES
            || max_pending_bytes < max_frame_bytes
            || max_pending_bytes > MAX_PENDING_TRANSPORT_BYTES
        {
            return Err(TransportError::InvalidLimits);
        }
        Ok(Self {
            max_frame_bytes,
            max_pending_bytes,
        })
    }
}

/// Explicit cancellation shared by connect and send without an async runtime.
#[derive(Debug, Clone, Default)]
pub struct CancellationToken(Arc<AtomicBool>);

impl CancellationToken {
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }

    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

/// Inputs to the mailbox authority gate above the byte transport.
pub struct OutboundAuthorization<'a> {
    pub prepared: &'a PreparedMailboxEnvelope,
    pub capability: &'a SignedMailboxCapability,
    pub context: &'a OpenContext,
    pub capability_authority_key: &'a VerifyingKey,
    pub route: &'a AuthorizedRoute,
}

/// Canonical envelope paired with the exact header that was encrypted and
/// signed. Only [`prepare_mailbox_envelope`] can construct this type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedMailboxEnvelope {
    envelope: MailboxEnvelope,
    header: MailboxEnvelopeHeader,
}

impl PreparedMailboxEnvelope {
    #[must_use]
    pub fn envelope(&self) -> &MailboxEnvelope {
        &self.envelope
    }
}

/// Seal one outbound message while retaining an unforgeable header/envelope
/// pairing for the transport authorization gate.
pub fn prepare_mailbox_envelope(
    request: SealRequest<'_>,
    encryption_key: &Key,
    signing_key: &SigningKey,
) -> Result<PreparedMailboxEnvelope, MailboxError> {
    let header = request.header.clone();
    let envelope = seal_envelope(request, encryption_key, signing_key)?;
    Ok(PreparedMailboxEnvelope { envelope, header })
}

/// Canonically encoded ciphertext admitted by mailbox authority. Its bytes are
/// private so a transport cannot be used as an arbitrary packet-forwarding API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedMailboxFrame {
    bytes: Vec<u8>,
}

impl AuthorizedMailboxFrame {
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        self.bytes.len()
    }
}

/// Verify capability, lifecycle, and route binding before exposing a frame to
/// [`PeerChannel`]. Connection authentication alone never reaches this type.
pub fn authorize_outbound(
    request: OutboundAuthorization<'_>,
) -> Result<AuthorizedMailboxFrame, OutboundAuthorizationError> {
    if request.context.required_operation != MailboxOperation::Send {
        return Err(OutboundAuthorizationError::SendOperationRequired);
    }
    let envelope = &request.prepared.envelope;
    let header = &request.prepared.header;
    envelope.validate_bounds().map_err(MailboxError::from)?;
    validate_outer_versions(envelope)?;
    validate_inner_versions(header)?;
    let commitment: [u8; 32] = Sha256::digest(&envelope.ciphertext).into();
    if commitment != envelope.ciphertext_commitment {
        return Err(MailboxError::CiphertextCommitmentInvalid.into());
    }
    if header.encryption != envelope.encryption
        || header.expires_at_unix_ms != envelope.routing.expires_at_unix_ms
    {
        return Err(OutboundAuthorizationError::EnvelopeHeaderMismatch);
    }
    verify_identity_and_time(header, request.context)?;
    verify_capability_signature(request.capability, request.capability_authority_key)?;
    verify_capability_scope(header, request.capability, request.context)?;
    let claims = &request.route.claims;
    if claims.address.tenant != header.tenant
        || claims.address.authorization_domain != header.authorization_domain
        || claims.address.mailbox != header.mailbox
        || claims.address.recipient != header.recipient
        || claims.execution_epoch != header.execution_epoch
        || claims.binding_id != envelope.routing.transport_binding_id
        || claims.authorization_domain_route_label
            != envelope.routing.authorization_domain_route_label
        || claims.destination_route_token != envelope.routing.destination_route_token
    {
        return Err(OutboundAuthorizationError::RouteMismatch);
    }
    Ok(AuthorizedMailboxFrame {
        bytes: encode_envelope(envelope)?,
    })
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OutboundAuthorizationError {
    #[error(transparent)]
    Mailbox(#[from] MailboxError),
    #[error("outbound transport authorization requires the send operation")]
    SendOperationRequired,
    #[error("mailbox envelope and supplied signed header do not match")]
    EnvelopeHeaderMismatch,
    #[error("mailbox envelope does not match the authorized transport route")]
    RouteMismatch,
}

/// Authenticated bounded stream. Only capability-authorized mailbox frames can
/// cross it; there is intentionally no `write(&[u8])` method.
pub trait PeerChannel: Send {
    fn try_send(
        &mut self,
        frame: &AuthorizedMailboxFrame,
        cancellation: &CancellationToken,
    ) -> Result<(), TransportError>;
}

/// Replaceable authenticated byte transport.
pub trait PeerTransport {
    fn connect(
        &self,
        route: &AuthorizedRoute,
        limits: ChannelLimits,
        cancellation: &CancellationToken,
    ) -> Result<Box<dyn PeerChannel>, TransportError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectAction {
    Accept,
    Refuse,
    Partition,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TransportError {
    #[error("mailbox transport limits are invalid")]
    InvalidLimits,
    #[error("mailbox transport operation was cancelled")]
    Cancelled,
    #[error("mailbox transport route was refused")]
    Refused,
    #[error("mailbox transport route is partitioned")]
    Partitioned,
    #[error("mailbox transport is shutting down")]
    ShuttingDown,
    #[error("mailbox transport frame exceeds the channel bound")]
    FrameTooLarge,
    #[error("mailbox transport channel is backpressured")]
    Backpressured,
    #[error("mailbox transport route is unknown")]
    UnknownRoute,
    #[error("mailbox transport state is unavailable")]
    StateUnavailable,
    #[error("all authorized mailbox routes failed")]
    AllRoutesFailed,
}

#[derive(Debug, Default)]
struct MemoryRoute {
    connect_script: VecDeque<ConnectAction>,
    pending: VecDeque<Vec<u8>>,
    pending_bytes: usize,
}

#[derive(Debug, Default)]
struct MemoryTransportState {
    shutting_down: bool,
    routes: BTreeMap<RouteId, MemoryRoute>,
}

/// Deterministic authenticated byte transport for conformance tests and local
/// composition. Frames remain bounded and are copied on send.
#[derive(Debug, Clone, Default)]
pub struct InMemoryPeerTransport {
    state: Arc<Mutex<MemoryTransportState>>,
}

impl InMemoryPeerTransport {
    pub fn register_route(&self, route: RouteId) -> Result<(), TransportError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| TransportError::StateUnavailable)?;
        state.routes.entry(route).or_default();
        Ok(())
    }

    pub fn script_connect(
        &self,
        route: RouteId,
        actions: impl IntoIterator<Item = ConnectAction>,
    ) -> Result<(), TransportError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| TransportError::StateUnavailable)?;
        let entry = state
            .routes
            .get_mut(&route)
            .ok_or(TransportError::UnknownRoute)?;
        entry.connect_script = actions.into_iter().collect();
        Ok(())
    }

    pub fn drain(&self, route: RouteId) -> Result<Vec<Vec<u8>>, TransportError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| TransportError::StateUnavailable)?;
        let entry = state
            .routes
            .get_mut(&route)
            .ok_or(TransportError::UnknownRoute)?;
        entry.pending_bytes = 0;
        Ok(entry.pending.drain(..).collect())
    }

    pub fn shutdown(&self) -> Result<(), TransportError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| TransportError::StateUnavailable)?;
        state.shutting_down = true;
        Ok(())
    }
}

struct InMemoryPeerChannel {
    route: RouteId,
    limits: ChannelLimits,
    state: Arc<Mutex<MemoryTransportState>>,
}

impl PeerChannel for InMemoryPeerChannel {
    fn try_send(
        &mut self,
        frame: &AuthorizedMailboxFrame,
        cancellation: &CancellationToken,
    ) -> Result<(), TransportError> {
        if cancellation.is_cancelled() {
            return Err(TransportError::Cancelled);
        }
        if frame.bytes.len() > self.limits.max_frame_bytes {
            return Err(TransportError::FrameTooLarge);
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| TransportError::StateUnavailable)?;
        if state.shutting_down {
            return Err(TransportError::ShuttingDown);
        }
        let route = state
            .routes
            .get_mut(&self.route)
            .ok_or(TransportError::UnknownRoute)?;
        let new_pending = route.pending_bytes.saturating_add(frame.bytes.len());
        if new_pending > self.limits.max_pending_bytes {
            return Err(TransportError::Backpressured);
        }
        route.pending.push_back(frame.bytes.clone());
        route.pending_bytes = new_pending;
        Ok(())
    }
}

impl PeerTransport for InMemoryPeerTransport {
    fn connect(
        &self,
        route: &AuthorizedRoute,
        limits: ChannelLimits,
        cancellation: &CancellationToken,
    ) -> Result<Box<dyn PeerChannel>, TransportError> {
        if cancellation.is_cancelled() {
            return Err(TransportError::Cancelled);
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| TransportError::StateUnavailable)?;
        if state.shutting_down {
            return Err(TransportError::ShuttingDown);
        }
        let route_state = state
            .routes
            .get_mut(&route.route_id())
            .ok_or(TransportError::UnknownRoute)?;
        match route_state
            .connect_script
            .pop_front()
            .unwrap_or(ConnectAction::Accept)
        {
            ConnectAction::Accept => Ok(Box::new(InMemoryPeerChannel {
                route: route.route_id(),
                limits,
                state: Arc::clone(&self.state),
            })),
            ConnectAction::Refuse => Err(TransportError::Refused),
            ConnectAction::Partition => Err(TransportError::Partitioned),
        }
    }
}

/// Try authorized routes in deterministic overlay order. Retry work is bounded
/// by the route-candidate cap; no timer or polling loop is hidden here.
pub fn connect_with_fallback(
    transport: &impl PeerTransport,
    routes: &[AuthorizedRoute],
    limits: ChannelLimits,
    cancellation: &CancellationToken,
) -> Result<Box<dyn PeerChannel>, TransportError> {
    for route in routes.iter().take(MAX_ROUTE_CANDIDATES) {
        match transport.connect(route, limits, cancellation) {
            Ok(channel) => return Ok(channel),
            Err(TransportError::Cancelled) => return Err(TransportError::Cancelled),
            Err(TransportError::ShuttingDown) => return Err(TransportError::ShuttingDown),
            Err(
                TransportError::Refused
                | TransportError::Partitioned
                | TransportError::UnknownRoute,
            ) => {}
            Err(error) => return Err(error),
        }
    }
    Err(TransportError::AllRoutesFailed)
}

#[cfg(test)]
mod tests;
