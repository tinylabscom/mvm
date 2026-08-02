//! Host-owned session identity for an L3 tunnel.
//!
//! Machine identity is structural: a connection arriving on a machine's
//! own per-VM vsock listener is by construction from that machine. The
//! session id layered on top binds a *boot* — so a restart, restore, or
//! snapshot resume cannot reuse the previous session's address lease,
//! flow state, DNS bindings, or ingress mappings.
//!
//! Nothing here reads an identity the guest supplied. `HELLO` carries no
//! machine id, and the id in a data frame's header is only ever compared
//! against the live session, never used to look one up.

use std::collections::BTreeMap;

use super::alloc::AddressLease;

/// Opaque per-boot session identifier. Minted by the host; the guest only
/// ever echoes it back.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SessionId(pub u64);

impl core::fmt::Display for SessionId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:016x}", self.0)
    }
}

/// Where a session is in its lifecycle. The tunnel only carries packets in
/// [`SessionState::Ready`]; anything arriving in another state is dropped,
/// so a guest cannot skip the handshake by sending data early.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// Control connection accepted, `HELLO` not yet validated.
    Handshaking,
    /// `CONFIG` sent; waiting for the guest to report its interface up.
    Configured,
    /// `READY` received. Packets may flow.
    Ready,
    /// Torn down. Terminal — a session never re-opens.
    Closed,
}

/// One machine's live L3 session.
#[derive(Debug, Clone)]
pub struct L3Session {
    id: SessionId,
    machine_id: String,
    plan_digest: String,
    policy_epoch: u64,
    lease: AddressLease,
    state: SessionState,
    /// Peer CID where the backend exposes one. Recorded for audit
    /// corroboration only — never an authorization input.
    peer_cid: Option<u32>,
    opened_at_millis: u64,
}

impl L3Session {
    pub fn id(&self) -> SessionId {
        self.id
    }

    pub fn machine_id(&self) -> &str {
        &self.machine_id
    }

    pub fn plan_digest(&self) -> &str {
        &self.plan_digest
    }

    pub fn policy_epoch(&self) -> u64 {
        self.policy_epoch
    }

    pub fn lease(&self) -> &AddressLease {
        &self.lease
    }

    pub fn state(&self) -> SessionState {
        self.state
    }

    pub fn peer_cid(&self) -> Option<u32> {
        self.peer_cid
    }

    pub fn opened_at_millis(&self) -> u64 {
        self.opened_at_millis
    }

    /// Record the CID the backend reported for this connection.
    pub fn set_peer_cid(&mut self, cid: u32) {
        self.peer_cid = Some(cid);
    }

    /// Whether packets may flow right now.
    pub fn accepts_packets(&self) -> bool {
        self.state == SessionState::Ready
    }

    /// Advance the lifecycle. Illegal transitions are refused rather than
    /// silently applied, so a guest replaying `READY` on a closed session
    /// cannot resurrect it.
    pub fn transition(&mut self, to: SessionState) -> Result<(), SessionError> {
        let ok = matches!(
            (self.state, to),
            (SessionState::Handshaking, SessionState::Configured)
                | (SessionState::Configured, SessionState::Ready)
                | (SessionState::Handshaking, SessionState::Closed)
                | (SessionState::Configured, SessionState::Closed)
                | (SessionState::Ready, SessionState::Closed)
        );
        if !ok {
            return Err(SessionError::IllegalTransition {
                from: self.state,
                to,
            });
        }
        self.state = to;
        Ok(())
    }

    /// Whether a frame's header session id belongs to this session.
    pub fn owns(&self, id: SessionId) -> bool {
        self.state != SessionState::Closed && self.id == id
    }
}

/// Session-registry refusals.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SessionError {
    /// A machine already has a live session. The caller must invalidate
    /// the old one first; silently replacing it would leave the previous
    /// tunnel's flows and mappings alive under a new id.
    #[error("machine {machine_id:?} already has live session {existing}")]
    AlreadyOpen {
        machine_id: String,
        existing: SessionId,
    },
    /// No live session for that machine.
    #[error("no live session for machine {0:?}")]
    NoSession(String),
    /// The lifecycle does not permit this move.
    #[error("illegal session transition {from:?} -> {to:?}")]
    IllegalTransition {
        from: SessionState,
        to: SessionState,
    },
}

/// Every live session on this host, keyed by machine.
///
/// Session ids are derived from a caller-supplied entropy seed mixed with
/// a monotonic counter. The seed keeps ids unpredictable in production;
/// the counter guarantees that even a degenerate entropy source can never
/// hand out an id that collides with a live one.
#[derive(Debug, Default)]
pub struct SessionRegistry {
    live: BTreeMap<String, L3Session>,
    counter: u64,
}

impl SessionRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Open a session for `machine_id`. `entropy` should come from the
    /// host's random source; it is mixed, not used verbatim.
    pub fn open(
        &mut self,
        machine_id: impl Into<String>,
        plan_digest: impl Into<String>,
        policy_epoch: u64,
        lease: AddressLease,
        entropy: u64,
        now_millis: u64,
    ) -> Result<&L3Session, SessionError> {
        let machine_id = machine_id.into();
        if let Some(existing) = self.live.get(&machine_id) {
            return Err(SessionError::AlreadyOpen {
                machine_id,
                existing: existing.id,
            });
        }
        self.counter = self.counter.wrapping_add(1);
        let mut id = mix(entropy, self.counter);
        // A zero id is reserved on the wire for "no session yet" (HELLO).
        while id.0 == 0 || self.live.values().any(|s| s.id == id) {
            self.counter = self.counter.wrapping_add(1);
            id = mix(entropy, self.counter);
        }
        let session = L3Session {
            id,
            machine_id: machine_id.clone(),
            plan_digest: plan_digest.into(),
            policy_epoch,
            lease,
            state: SessionState::Handshaking,
            peer_cid: None,
            opened_at_millis: now_millis,
        };
        Ok(self.live.entry(machine_id).or_insert(session))
    }

    pub fn get(&self, machine_id: &str) -> Option<&L3Session> {
        self.live.get(machine_id)
    }

    pub fn get_mut(&mut self, machine_id: &str) -> Option<&mut L3Session> {
        self.live.get_mut(machine_id)
    }

    /// Whether `id` is the live session for `machine_id`. This is the only
    /// question a data frame's session field is ever allowed to ask: it is
    /// a check against a session the host already located structurally,
    /// never a lookup key.
    pub fn owns(&self, machine_id: &str, id: SessionId) -> bool {
        self.live.get(machine_id).is_some_and(|s| s.owns(id))
    }

    /// Invalidate a machine's session and return it. Called on stop,
    /// restart, restore, and resume — every path that could otherwise
    /// leave stale state addressable.
    pub fn invalidate(&mut self, machine_id: &str) -> Option<L3Session> {
        self.live.remove(machine_id).map(|mut s| {
            s.state = SessionState::Closed;
            s
        })
    }

    pub fn len(&self) -> usize {
        self.live.len()
    }

    pub fn is_empty(&self) -> bool {
        self.live.is_empty()
    }

    pub fn machines(&self) -> impl Iterator<Item = &str> {
        self.live.keys().map(String::as_str)
    }
}

/// SplitMix64 finalizer over the seed and counter. Cheap, and good enough
/// that two sessions opened in the same millisecond do not share high
/// bits — the property that matters, since the id is a binding check, not
/// a secret.
fn mix(seed: u64, counter: u64) -> SessionId {
    let mut z = seed.wrapping_add(counter.wrapping_mul(0x9E37_79B9_7F4A_7C15));
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    SessionId(z ^ (z >> 31))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::l3::alloc::AddressAllocator;

    fn lease() -> AddressLease {
        AddressAllocator::with_defaults()
            .allocate()
            .expect("pool has room")
    }

    fn registry_with_one() -> (SessionRegistry, SessionId) {
        let mut reg = SessionRegistry::new();
        let id = reg
            .open("vm-a", "sha256:abc", 1, lease(), 0x1234, 0)
            .unwrap()
            .id();
        (reg, id)
    }

    #[test]
    fn a_new_session_starts_handshaking_and_carries_no_packets() {
        let (reg, _) = registry_with_one();
        let session = reg.get("vm-a").unwrap();
        assert_eq!(session.state(), SessionState::Handshaking);
        assert!(!session.accepts_packets());
    }

    #[test]
    fn packets_only_flow_after_the_full_handshake() {
        let (mut reg, _) = registry_with_one();
        let session = reg.get_mut("vm-a").unwrap();
        session.transition(SessionState::Configured).unwrap();
        assert!(!session.accepts_packets(), "config alone is not readiness");
        session.transition(SessionState::Ready).unwrap();
        assert!(session.accepts_packets());
    }

    #[test]
    fn a_session_cannot_skip_straight_to_ready() {
        let (mut reg, _) = registry_with_one();
        let err = reg
            .get_mut("vm-a")
            .unwrap()
            .transition(SessionState::Ready)
            .unwrap_err();
        assert!(matches!(err, SessionError::IllegalTransition { .. }));
    }

    #[test]
    fn a_closed_session_never_reopens() {
        let (mut reg, _) = registry_with_one();
        let session = reg.get_mut("vm-a").unwrap();
        session.transition(SessionState::Closed).unwrap();
        assert!(session.transition(SessionState::Ready).is_err());
        assert!(session.transition(SessionState::Configured).is_err());
    }

    #[test]
    fn opening_twice_for_one_machine_is_refused() {
        let (mut reg, id) = registry_with_one();
        let err = reg
            .open("vm-a", "sha256:abc", 1, lease(), 0x5678, 1)
            .unwrap_err();
        assert!(matches!(err, SessionError::AlreadyOpen { existing, .. } if existing == id));
    }

    #[test]
    fn invalidation_clears_the_machine_and_marks_the_session_closed() {
        let (mut reg, id) = registry_with_one();
        let closed = reg.invalidate("vm-a").unwrap();
        assert_eq!(closed.id(), id);
        assert_eq!(closed.state(), SessionState::Closed);
        assert!(reg.get("vm-a").is_none());
        assert!(reg.is_empty());
    }

    #[test]
    fn a_restart_does_not_reuse_the_previous_session_id() {
        let (mut reg, first) = registry_with_one();
        reg.invalidate("vm-a");
        let second = reg
            .open("vm-a", "sha256:abc", 2, lease(), 0x1234, 10)
            .unwrap()
            .id();
        assert_ne!(
            first, second,
            "a restart must mint a fresh session even with identical entropy"
        );
    }

    #[test]
    fn a_stale_session_id_is_not_owned_after_invalidation() {
        let (mut reg, id) = registry_with_one();
        assert!(reg.owns("vm-a", id));
        reg.invalidate("vm-a");
        assert!(!reg.owns("vm-a", id));
    }

    #[test]
    fn one_machine_cannot_present_another_machines_session_id() {
        let mut reg = SessionRegistry::new();
        let a = reg
            .open("vm-a", "sha256:a", 1, lease(), 0x1111, 0)
            .unwrap()
            .id();
        let b = reg
            .open("vm-b", "sha256:b", 1, lease(), 0x2222, 0)
            .unwrap()
            .id();
        assert_ne!(a, b);
        assert!(!reg.owns("vm-a", b));
        assert!(!reg.owns("vm-b", a));
    }

    #[test]
    fn session_ids_are_never_zero_because_zero_means_no_session_on_the_wire() {
        let mut reg = SessionRegistry::new();
        for i in 0..64u64 {
            let id = reg
                .open(format!("vm-{i}"), "d", 1, lease(), 0, i)
                .unwrap()
                .id();
            assert_ne!(id.0, 0);
        }
    }

    #[test]
    fn ids_stay_distinct_even_with_a_degenerate_entropy_source() {
        let mut reg = SessionRegistry::new();
        let mut seen = std::collections::BTreeSet::new();
        for i in 0..256u64 {
            let id = reg
                .open(format!("vm-{i}"), "d", 1, lease(), 0, i)
                .unwrap()
                .id();
            assert!(seen.insert(id), "duplicate session id {id}");
        }
    }

    #[test]
    fn peer_cid_is_recorded_but_is_not_the_identity() {
        let (mut reg, id) = registry_with_one();
        let session = reg.get_mut("vm-a").unwrap();
        session.set_peer_cid(42);
        assert_eq!(session.peer_cid(), Some(42));
        // Ownership still answers on the session id alone.
        assert!(reg.owns("vm-a", id));
    }

    #[test]
    fn session_id_displays_as_fixed_width_hex_for_audit() {
        assert_eq!(SessionId(0x1f).to_string(), "000000000000001f");
    }
}
