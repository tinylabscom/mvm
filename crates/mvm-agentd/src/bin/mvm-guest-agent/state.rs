//! Shared in-process state: worker-busy status, boot readiness, and the
//! health caches the monitoring/health/probe threads populate and the
//! request handlers read.

use std::sync::Mutex;
use std::time::Instant;

use mvm_agentd::integrations::{IntegrationEntry, IntegrationHealthResult};
use mvm_agentd::probes::{ProbeEntry, ProbeResult};
use mvm_agentd::vsock::{BootTimingReport, ComponentState, ReadinessReport};
use mvm_core::security::AgentProfile;

// ============================================================================
// Agent state (shared between monitoring thread and request handlers)
// ============================================================================

pub(crate) struct AgentState {
    pub(crate) status: String,
    pub(crate) last_busy_at: Option<String>,
}

impl AgentState {
    pub(crate) fn new() -> Self {
        Self {
            status: "idle".to_string(),
            last_busy_at: None,
        }
    }
}

// ============================================================================
// Boot readiness state
// ============================================================================

/// Per-subsystem readiness, surfaced through `ReadinessStatus` and
/// also consulted by `RunEntrypoint` so a host that races
/// invocation ahead of warmup gets a typed `NotReady` rather than a
/// permanent failure.
///
/// **State design.** A single `Mutex<BootStateInner>` instead of
/// per-component atomics. Readers (`ReadinessStatus` handlers,
/// `entrypoint_ready()` checks) are rare; writers fire at boot
/// completion events. The lock holds for at most a few struct-field
/// reads so contention is a non-issue. Per-component atomics
/// (`AtomicU8` + side-channel for `Failed { message }`) would be
/// more complex and earn nothing measurable.
///
/// **Why background init is still safe.** Per-handler invariants
/// stay intact:
///   - `RunEntrypoint` consults this state AND the existing
///     `VALIDATED_ENTRYPOINT` `OnceLock` — `NotReady` while
///     `Starting`, `EntrypointInvalid` once `VALIDATED_ENTRYPOINT`
///     is set to `Err`.
///   - Warm-process dispatch in the worker pool keeps its own
///     ready flag (`WorkerPool::wait_for_ready`) — this state is
///     observability, not the gate.
pub(crate) struct AgentBootState {
    pub(crate) inner: Mutex<BootStateInner>,
    pub(crate) profile: AgentProfile,
    pub(crate) boot_at: Instant,
}

#[derive(Default)]
pub(crate) struct BootStateInner {
    pub(crate) control_plane: ComponentState,
    pub(crate) entrypoint: ComponentState,
    pub(crate) warm_pool: ComponentState,
    pub(crate) integrations: ComponentState,
    pub(crate) probes: ComponentState,
    pub(crate) volumes: ComponentState,
    pub(crate) timing: BootTimingReport,
    /// Pinned agent-verb grant from the admission handshake; `None` means
    /// no grant is pinned — the class gate (`allowed_in`) is the only
    /// verb filter. Mutable so `PostRestore` can re-pin after restore.
    pub(crate) verb_grant: Option<mvm_core::plan::VerbGrant>,
    /// `true` when the measured verb-trust policy required a grant but none
    /// was validly pinned; control RPCs are refused while this is set.
    /// Cleared when a valid grant is re-pinned via `PostRestore`.
    pub(crate) trust_denied: bool,
    /// Boot-pinned host-signer trust anchor (from `HOST_SIGNER_PUBKEY_PATH`).
    /// `None` on a grant-less boot with no provisioned key. `PostRestore`
    /// re-pin verifies incoming envelopes against THIS anchor, never against
    /// the self-attested key embedded in the envelope.
    pub(crate) host_signer_key: Option<ed25519_dalek::VerifyingKey>,
}

impl AgentBootState {
    pub(crate) fn new(profile: AgentProfile, boot_at: Instant) -> Self {
        Self {
            inner: Mutex::new(BootStateInner {
                // Two components start `Starting` rather than the
                // `Default` `Disabled`: `control_plane` flips to
                // `Ready` immediately after `bind+listen` in `main`
                // (we're not running until then), and `entrypoint`
                // is the boot dependency `RunEntrypoint` gates on.
                // The remaining components keep `Disabled` from
                // `Default` — the background init thread flips them
                // to `Starting` when it sees config that requires
                // them.
                control_plane: ComponentState::Starting,
                entrypoint: ComponentState::Starting,
                ..Default::default()
            }),
            profile,
            boot_at,
        }
    }

    /// Milliseconds elapsed since `boot_at`. Always fits in `u64`
    /// for any plausible agent lifetime; saturates on the absurd.
    pub(crate) fn elapsed_ms(&self) -> u64 {
        u64::try_from(self.boot_at.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    pub(crate) fn mark_vsock_bound(&self) {
        if let Ok(mut s) = self.inner.lock() {
            s.control_plane = ComponentState::Ready;
            let ms = self.elapsed_ms();
            s.timing.agent_started_ms.get_or_insert(ms);
            s.timing.vsock_bound_ms.get_or_insert(ms);
        }
    }

    /// Stamp the first-accept timing. Idempotent — only the first
    /// caller wins, subsequent accept loops are no-ops.
    pub(crate) fn mark_first_accept(&self) {
        if let Ok(mut s) = self.inner.lock()
            && s.timing.first_accept_ms.is_none()
        {
            s.timing.first_accept_ms = Some(self.elapsed_ms());
        }
    }

    pub(crate) fn set_entrypoint(&self, state: ComponentState) {
        if let Ok(mut s) = self.inner.lock() {
            // `Disabled` is terminal too — an image that offers no per-call
            // entrypoint resolves immediately (entrypoint starts as
            // `Starting`), same as `set_warm_pool` treats its Disabled.
            let became_terminal = matches!(
                state,
                ComponentState::Ready | ComponentState::Failed { .. } | ComponentState::Disabled
            );
            s.entrypoint = state;
            if became_terminal && s.timing.entrypoint_ready_ms.is_none() {
                s.timing.entrypoint_ready_ms = Some(self.elapsed_ms());
            }
        }
    }

    /// Set the warm-pool component and stamp `warm_pool_ready_ms`
    /// when the state first leaves `Starting` for a terminal value
    /// (`Ready` / `Failed` / `Disabled`). Initial `Disabled` (the
    /// `Default` value, set before any background thread runs) does
    /// not stamp — we only count time once init actually starts.
    pub(crate) fn set_warm_pool(&self, state: ComponentState) {
        if let Ok(mut s) = self.inner.lock() {
            let was_starting = matches!(s.warm_pool, ComponentState::Starting);
            s.warm_pool = state;
            if was_starting && s.timing.warm_pool_ready_ms.is_none() {
                s.timing.warm_pool_ready_ms = Some(self.elapsed_ms());
            }
        }
    }

    /// Set the integrations component. Stamps `integrations_ready_ms`
    /// on the first transition out of `Starting`. See `set_warm_pool`
    /// for the rationale on skipping initial-Disabled stamps.
    pub(crate) fn set_integrations(&self, state: ComponentState) {
        if let Ok(mut s) = self.inner.lock() {
            let was_starting = matches!(s.integrations, ComponentState::Starting);
            s.integrations = state;
            if was_starting && s.timing.integrations_ready_ms.is_none() {
                s.timing.integrations_ready_ms = Some(self.elapsed_ms());
            }
        }
    }

    /// Set the probes component. Stamps `probes_ready_ms` on the
    /// first transition out of `Starting`.
    pub(crate) fn set_probes(&self, state: ComponentState) {
        if let Ok(mut s) = self.inner.lock() {
            let was_starting = matches!(s.probes, ComponentState::Starting);
            s.probes = state;
            if was_starting && s.timing.probes_ready_ms.is_none() {
                s.timing.probes_ready_ms = Some(self.elapsed_ms());
            }
        }
    }

    pub(crate) fn snapshot(&self) -> ReadinessReport {
        let inner = self.inner.lock();
        let (control_plane, entrypoint, warm_pool, integrations, probes, volumes, timing) =
            match inner {
                Ok(s) => (
                    s.control_plane.clone(),
                    s.entrypoint.clone(),
                    s.warm_pool.clone(),
                    s.integrations.clone(),
                    s.probes.clone(),
                    s.volumes.clone(),
                    s.timing.clone(),
                ),
                // Poisoned lock means another thread panicked mid-update;
                // surface that as a generic Failed rather than swallowing.
                Err(_) => {
                    let msg = "boot-state lock poisoned".to_string();
                    (
                        ComponentState::Failed {
                            message: msg.clone(),
                        },
                        ComponentState::Failed {
                            message: msg.clone(),
                        },
                        ComponentState::Failed {
                            message: msg.clone(),
                        },
                        ComponentState::Failed {
                            message: msg.clone(),
                        },
                        ComponentState::Failed {
                            message: msg.clone(),
                        },
                        ComponentState::Failed { message: msg },
                        BootTimingReport::default(),
                    )
                }
            };
        ReadinessReport {
            control_plane,
            entrypoint,
            warm_pool,
            integrations,
            probes,
            volumes,
            profile: self.profile,
            boot_millis: timing,
        }
    }

    /// Read `(trust_denied, verb_grant)` atomically under the inner lock.
    /// Used by the enforcement gate in the request handler.
    pub(crate) fn grant_state(&self) -> (bool, Option<mvm_core::plan::VerbGrant>) {
        match self.inner.lock() {
            Ok(s) => (s.trust_denied, s.verb_grant.clone()),
            Err(_) => (true, None), // poisoned lock → fail closed
        }
    }

    /// Read the boot-pinned host-signer trust anchor. `PostRestore` re-pin
    /// verifies incoming envelopes against this; `None` means no anchor was
    /// provisioned at boot, so a re-pin has nothing to trust and must be
    /// refused (fail closed).
    pub(crate) fn host_signer_key(&self) -> Option<ed25519_dalek::VerifyingKey> {
        match self.inner.lock() {
            Ok(s) => s.host_signer_key,
            Err(_) => None, // poisoned lock → no anchor → refuse re-pin
        }
    }

    /// Re-pin a newly verified grant, clearing `trust_denied`. Called from
    /// the `PostRestore` handler after `re_pin_verb_grant` succeeds.
    pub(crate) fn set_verb_grant(&self, grant: mvm_core::plan::VerbGrant) {
        if let Ok(mut s) = self.inner.lock() {
            s.verb_grant = Some(grant);
            s.trust_denied = false;
        }
    }
}

// ============================================================================
// Integration health state (shared between health thread and request handlers)
// ============================================================================

pub(crate) struct IntegrationHealth {
    pub(crate) entry: IntegrationEntry,
    pub(crate) last_result: Option<IntegrationHealthResult>,
}

pub(crate) struct IntegrationState {
    pub(crate) integrations: Vec<IntegrationHealth>,
}

// ============================================================================
// Probe health state (shared between probe thread and request handlers)
// ============================================================================

pub(crate) struct ProbeHealth {
    pub(crate) entry: ProbeEntry,
    pub(crate) last_result: Option<ProbeResult>,
}

pub(crate) struct ProbeState {
    pub(crate) probes: Vec<ProbeHealth>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_agentd::vsock::{
        GuestRequest, GuestResponse, enforce_verb_grant, is_verb_trust_baseline,
    };

    // ─── AgentBootState transitions ────

    fn fresh_boot_state() -> AgentBootState {
        AgentBootState::new(AgentProfile::SealedProd, Instant::now())
    }

    #[test]
    fn boot_state_starts_with_starting_control_plane_and_entrypoint() {
        let s = fresh_boot_state().snapshot();
        assert_eq!(s.control_plane, ComponentState::Starting);
        assert_eq!(s.entrypoint, ComponentState::Starting);
        // Optional subsystems default to Disabled — they only flip
        // to Starting when their background init thread actually runs.
        assert_eq!(s.warm_pool, ComponentState::Disabled);
        assert_eq!(s.integrations, ComponentState::Disabled);
        assert_eq!(s.probes, ComponentState::Disabled);
        assert_eq!(s.volumes, ComponentState::Disabled);
    }

    #[test]
    fn mark_vsock_bound_flips_control_plane_to_ready_and_stamps_timing() {
        let bs = fresh_boot_state();
        bs.mark_vsock_bound();
        let s = bs.snapshot();
        assert_eq!(s.control_plane, ComponentState::Ready);
        assert!(s.boot_millis.vsock_bound_ms.is_some());
        assert!(s.boot_millis.agent_started_ms.is_some());
    }

    #[test]
    fn set_entrypoint_ready_stamps_entrypoint_ready_ms_once() {
        let bs = fresh_boot_state();
        bs.set_entrypoint(ComponentState::Ready);
        let t1 = bs.snapshot().boot_millis.entrypoint_ready_ms;
        assert!(t1.is_some());
        // A later transition (e.g. PostRestore reset) must not
        // overwrite the original timing — readers polling for
        // cold-path stats want the FIRST ready time, not the most
        // recent.
        std::thread::sleep(std::time::Duration::from_millis(2));
        bs.set_entrypoint(ComponentState::Failed {
            message: "synthetic".to_string(),
        });
        let t2 = bs.snapshot().boot_millis.entrypoint_ready_ms;
        assert_eq!(t1, t2);
    }

    #[test]
    fn set_integrations_starting_then_ready_stamps_timing() {
        let bs = fresh_boot_state();
        // The init helpers go through Starting first; only that path
        // should stamp the timing. A direct Disabled → Disabled
        // transition must NOT stamp.
        bs.set_integrations(ComponentState::Disabled);
        assert!(bs.snapshot().boot_millis.integrations_ready_ms.is_none());

        bs.set_integrations(ComponentState::Starting);
        assert!(bs.snapshot().boot_millis.integrations_ready_ms.is_none());

        bs.set_integrations(ComponentState::Ready);
        assert!(bs.snapshot().boot_millis.integrations_ready_ms.is_some());
    }

    #[test]
    fn set_integrations_starting_then_disabled_also_stamps() {
        // Empty drop-in dir: the background thread enters Starting,
        // scans, finds nothing, and flips to Disabled. That's still
        // a meaningful "scan completed" event — stamp the time so
        // a host can see cold-path latency includes the no-op scan.
        let bs = fresh_boot_state();
        bs.set_integrations(ComponentState::Starting);
        bs.set_integrations(ComponentState::Disabled);
        assert!(bs.snapshot().boot_millis.integrations_ready_ms.is_some());
    }

    #[test]
    fn set_warm_pool_only_stamps_after_first_starting_transition() {
        let bs = fresh_boot_state();
        // Initial Disabled (Default) → Disabled (cold-tier image,
        // no warm-pool config). No Starting in between → no stamp.
        bs.set_warm_pool(ComponentState::Disabled);
        assert!(bs.snapshot().boot_millis.warm_pool_ready_ms.is_none());

        bs.set_warm_pool(ComponentState::Starting);
        bs.set_warm_pool(ComponentState::Ready);
        assert!(bs.snapshot().boot_millis.warm_pool_ready_ms.is_some());
    }

    // ─── verb-grant / verb-trust enforcement at the request-handling seam ───
    //
    // The control-RPC gate is inline in the accept loop, which cannot be driven
    // without a live vsock. `gate_control_rpc` reproduces the handler's two
    // ordered steps verbatim — the trust-policy fail-closed check
    // (`trust_denied && !baseline`) followed by the verb-grant intersection
    // (`enforce_verb_grant`) — over a real `AgentBootState`, so the negative
    // paths exercise the same primitives (`grant_state`, `is_verb_trust_baseline`,
    // `enforce_verb_grant`) the handler composes.

    /// Mirror of the handler's control-RPC gate. `None` = the request would be
    /// dispatched; `Some(resp)` = the request is refused with `resp`.
    fn gate_control_rpc(boot_state: &AgentBootState, req: &GuestRequest) -> Option<GuestResponse> {
        let (trust_denied, verb_grant) = boot_state.grant_state();
        if trust_denied && !is_verb_trust_baseline(req.kind_name()) {
            return Some(GuestResponse::VerbNotAuthorized {
                verb: req.kind_name().to_string(),
            });
        }
        enforce_verb_grant(req, verb_grant.as_ref())
    }

    /// A host-signed grant listing exactly `verbs` (plus the always-answerable
    /// baseline). The signing key is irrelevant to enforcement — the pinned grant
    /// is trusted once seated — so any fixed key suffices here.
    fn signed_grant(verbs: &[&str]) -> mvm_core::plan::VerbGrant {
        use ed25519_dalek::Signer;
        use mvm_core::plan::{Nonce, VerbGrant, VerbId};
        let signer = ed25519_dalek::SigningKey::from_bytes(&[55u8; 32]);
        let mut g = VerbGrant {
            session_id: "sess-agent".into(),
            plan_nonce: Nonce::from_bytes([56u8; 16]),
            not_after: chrono::Utc::now() + chrono::Duration::minutes(10),
            verbs: verbs.iter().map(|v| VerbId::new(v).unwrap()).collect(),
            sig: vec![],
        };
        g.sig = signer.sign(&g.signing_bytes()).to_bytes().to_vec();
        g
    }

    /// Row: grant-less deny-all. When the measured policy required a grant and
    /// none pinned (the boot init `FailClosed` branch), every non-baseline
    /// control RPC is refused while baseline verbs still answer for liveness.
    #[test]
    fn grant_less_fail_closed_denies_non_baseline_serves_baseline() {
        let bs = fresh_boot_state();
        {
            let mut s = bs.inner.lock().unwrap();
            s.trust_denied = true;
            s.verb_grant = None;
        }
        // Baseline verbs remain answerable.
        assert!(is_verb_trust_baseline("protocol-hello"));
        assert!(
            gate_control_rpc(&bs, &GuestRequest::Ping).is_none(),
            "ping is baseline and must answer under fail-closed"
        );
        // Every non-baseline control RPC is refused with VerbNotAuthorized.
        for req in [
            GuestRequest::WorkerStatus,
            GuestRequest::IntegrationStatus,
            GuestRequest::UpdateIdleTimeout { secs: 0 },
        ] {
            let name = req.kind_name();
            match gate_control_rpc(&bs, &req) {
                Some(GuestResponse::VerbNotAuthorized { verb }) => assert_eq!(verb, name),
                other => panic!("{name} must be refused under fail-closed, got {other:?}"),
            }
        }
    }

    /// Row: verb regain via reconnect. Enforcement state is boot-scoped (the
    /// shared `AgentBootState`), not per-connection: the gate re-reads
    /// `grant_state()` on every request, so a dropped-and-reopened control
    /// connection cannot reset a fail-closed agent to a permissive posture.
    ///
    /// A true socket reconnect needs a live vsock accept loop and is not
    /// unit-testable here; this pins the invariant at the boot-state seam — the
    /// state the accept loop reads is unchanged across simulated connections.
    #[test]
    fn fail_closed_survives_simulated_reconnect() {
        let bs = fresh_boot_state();
        {
            let mut s = bs.inner.lock().unwrap();
            s.trust_denied = true;
        }
        for _connection in 0..3 {
            assert!(
                matches!(
                    gate_control_rpc(&bs, &GuestRequest::WorkerStatus),
                    Some(GuestResponse::VerbNotAuthorized { .. })
                ),
                "reconnect must not clear the fail-closed posture"
            );
            assert!(gate_control_rpc(&bs, &GuestRequest::Ping).is_none());
        }
    }

    /// Row: verb regain via reconnect (pinned-grant case). A pinned grant applies
    /// unchanged across a simulated reconnect, and replaying the pre-grant
    /// handshake cannot widen it — `ProtocolHello` is baseline and never mutates
    /// the pinned grant, so the served set is identical before and after.
    #[test]
    fn reconnect_and_replayed_hello_cannot_widen_pinned_grant() {
        let bs = fresh_boot_state();
        bs.set_verb_grant(signed_grant(&["update-idle-timeout"]));
        let before = bs.grant_state().1.expect("grant pinned");

        for _connection in 0..3 {
            // A replayed handshake conveys no authority (baseline, no grant edit).
            assert!(is_verb_trust_baseline("protocol-hello"));
            // Listed verb served; unlisted non-baseline verb still refused.
            assert!(
                gate_control_rpc(&bs, &GuestRequest::UpdateIdleTimeout { secs: 0 }).is_none(),
                "listed verb must stay served across reconnect"
            );
            assert!(
                matches!(
                    gate_control_rpc(&bs, &GuestRequest::WorkerStatus),
                    Some(GuestResponse::VerbNotAuthorized { .. })
                ),
                "unlisted verb must stay refused across reconnect"
            );
        }

        let after = bs.grant_state().1.expect("grant still pinned");
        assert_eq!(
            before.verbs, after.verbs,
            "handshake replay / reconnect must not widen the pinned grant"
        );
    }

    /// Row: two-layer enforcement (profile gate + grant gate) composes as
    /// defense-in-depth. A DevOnly verb is refused by the profile gate in
    /// SealedProd regardless of grant; an unlisted ProdSafe verb is refused by
    /// the grant gate; the listed ProdSafe verb is served.
    #[test]
    fn sealed_profile_and_grant_gates_compose() {
        let bs = fresh_boot_state(); // SealedProd
        assert_eq!(bs.profile, AgentProfile::SealedProd);
        bs.set_verb_grant(signed_grant(&["update-idle-timeout"]));

        // Layer 1 — profile gate: a DevOnly verb never runs in SealedProd, even
        // if a grant were to list it. (The handler emits UnsupportedInProfile
        // ahead of the grant gate.)
        let dev_only = GuestRequest::RunDetached {
            argv: vec!["/bin/true".into()],
            env: vec![],
        };
        assert!(matches!(
            dev_only.class(),
            mvm_agentd::vsock::RequestClass::DevOnly
        ));
        assert!(
            !dev_only.allowed_in(bs.profile),
            "DevOnly verb must be refused in SealedProd"
        );

        // Layer 2 — grant gate: unlisted ProdSafe verb refused, listed served.
        match gate_control_rpc(&bs, &GuestRequest::WorkerStatus) {
            Some(GuestResponse::VerbNotAuthorized { verb }) => assert_eq!(verb, "worker-status"),
            other => panic!("unlisted ProdSafe verb must be refused, got {other:?}"),
        }
        assert!(
            gate_control_rpc(&bs, &GuestRequest::UpdateIdleTimeout { secs: 0 }).is_none(),
            "listed ProdSafe verb must be served"
        );
    }

    // ─── PostRestore re-pin binds to the boot-pinned host-signer anchor ───

    /// Build a `VerbGrantEnvelope` self-signed by `signer` (carrying `signer`'s
    /// own pubkey), for use as a forged or a genuine restore envelope depending
    /// on whether `signer` is the boot anchor.
    fn envelope_signed_by(
        signer: &ed25519_dalek::SigningKey,
        session: &str,
        nonce: mvm_core::plan::Nonce,
        verbs: &[&str],
    ) -> mvm_core::protocol::vm_backend::VerbGrantEnvelope {
        use ed25519_dalek::Signer;
        use mvm_core::plan::{VerbGrant, VerbId};
        let mut g = VerbGrant {
            session_id: session.into(),
            plan_nonce: nonce.clone(),
            not_after: chrono::Utc::now() + chrono::Duration::minutes(10),
            verbs: verbs.iter().map(|v| VerbId::new(v).unwrap()).collect(),
            sig: vec![],
        };
        g.sig = signer.sign(&g.signing_bytes()).to_bytes().to_vec();
        let pubkey_hex: String = signer
            .verifying_key()
            .to_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        mvm_core::protocol::vm_backend::VerbGrantEnvelope {
            pubkey_hex,
            plan_nonce_hex: nonce.as_hex().to_string(),
            predecessor_session_id: None,
            predecessor_plan_nonce_hex: None,
            grant: g,
        }
    }

    /// Mirror of the `PostRestore` re-pin decision: verify the incoming envelope
    /// against the boot-pinned host anchor and replace the pinned grant only on
    /// success. `true` = re-pinned; `false` = refused (bad anchor / no anchor).
    /// The inline handler cannot be driven without a live vsock, so this
    /// reproduces its two steps verbatim over a real `AgentBootState`.
    fn apply_post_restore_repin(
        bs: &AgentBootState,
        env: &mvm_core::protocol::vm_backend::VerbGrantEnvelope,
        now: chrono::DateTime<chrono::Utc>,
    ) -> bool {
        match bs.host_signer_key() {
            Some(anchor) => match mvm_agentd::vsock::re_pin_verb_grant(
                env,
                bs.grant_state().1.as_ref(),
                &anchor,
                now,
            ) {
                Some(g) => {
                    bs.set_verb_grant(g);
                    true
                }
                None => false,
            },
            None => false,
        }
    }

    /// A forged `PostRestore` envelope self-signed by a NON-anchor key must not
    /// replace the pinned grant nor flip `trust_denied` — the served authority is
    /// unchanged.
    #[test]
    fn post_restore_forged_envelope_does_not_replace_grant() {
        let anchor = ed25519_dalek::SigningKey::from_bytes(&[60u8; 32]);
        let attacker = ed25519_dalek::SigningKey::from_bytes(&[61u8; 32]);
        let bs = fresh_boot_state();
        {
            let mut s = bs.inner.lock().unwrap();
            s.host_signer_key = Some(anchor.verifying_key());
        }
        bs.set_verb_grant(signed_grant(&["update-idle-timeout"]));

        let forged = envelope_signed_by(
            &attacker,
            "attacker",
            mvm_core::plan::Nonce::from_bytes([62u8; 16]),
            &["run-entrypoint", "update-idle-timeout"],
        );
        let repinned = apply_post_restore_repin(&bs, &forged, chrono::Utc::now());
        assert!(!repinned, "forged envelope must not re-pin");

        let (trust_denied, grant) = bs.grant_state();
        assert!(!trust_denied, "forged envelope must not touch trust_denied");
        let grant = grant.expect("original grant must remain pinned");
        assert!(
            !grant.permits("run-entrypoint"),
            "forged envelope must not widen the served verb set"
        );
    }

    /// A grant-less fail-closed boot (no host-signer anchor pinned) refuses every
    /// re-pin: with no anchor there is nothing to trust the envelope against.
    #[test]
    fn post_restore_no_boot_anchor_refuses_repin() {
        let some_key = ed25519_dalek::SigningKey::from_bytes(&[63u8; 32]);
        let bs = fresh_boot_state();
        {
            let mut s = bs.inner.lock().unwrap();
            s.trust_denied = true; // grant-less fail-closed boot
            s.host_signer_key = None;
        }
        let env = envelope_signed_by(
            &some_key,
            "sess",
            mvm_core::plan::Nonce::from_bytes([64u8; 16]),
            &["run-entrypoint"],
        );
        assert!(
            !apply_post_restore_repin(&bs, &env, chrono::Utc::now()),
            "re-pin must be refused with no boot anchor"
        );
        let (trust_denied, grant) = bs.grant_state();
        assert!(trust_denied, "fail-closed posture must survive the re-pin");
        assert!(grant.is_none(), "no grant may be pinned without an anchor");
    }

    /// A genuine host-signed restore envelope (signed by the boot anchor) re-pins
    /// and MAY legitimately widen the served set — a fork runs a newly admitted
    /// plan with a fresh session/nonce, so the boot session/nonce are NOT forced.
    #[test]
    fn post_restore_host_signed_envelope_repins_and_may_widen() {
        let anchor = ed25519_dalek::SigningKey::from_bytes(&[65u8; 32]);
        let bs = fresh_boot_state();
        {
            let mut s = bs.inner.lock().unwrap();
            s.host_signer_key = Some(anchor.verifying_key());
        }
        bs.set_verb_grant(signed_grant(&["update-idle-timeout"]));

        let current = bs.grant_state().1.expect("boot grant pinned");

        // Fresh child session/nonce, unequal to the current grant, widened
        // verbs, but explicitly linked back to the currently pinned grant.
        let mut fork_env = envelope_signed_by(
            &anchor,
            "child-session",
            mvm_core::plan::Nonce::from_bytes([66u8; 16]),
            &["run-entrypoint", "update-idle-timeout"],
        );
        fork_env.predecessor_session_id = Some(current.session_id.clone());
        fork_env.predecessor_plan_nonce_hex = Some(current.plan_nonce.as_hex().to_string());
        assert!(
            apply_post_restore_repin(&bs, &fork_env, chrono::Utc::now()),
            "host-signed fork envelope must re-pin"
        );
        let grant = bs.grant_state().1.expect("grant re-pinned");
        assert_eq!(grant.session_id, "child-session");
        assert!(
            grant.permits("run-entrypoint"),
            "a host-signed fork may widen the served verb set"
        );
    }
}
