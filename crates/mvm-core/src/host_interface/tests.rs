use ed25519_dalek::SigningKey;

use super::local::LocalHostInterface;
use super::*;

fn now() -> u64 {
    1_000
}
fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}
fn trusted(k: &SigningKey) -> Vec<(String, ed25519_dalek::VerifyingKey)> {
    vec![("issuer".into(), k.verifying_key())]
}
fn req(epoch: u64) -> LaunchRequest {
    LaunchRequest {
        workload_id: "w".into(),
        image_digest: "sha256:a".into(),
        epoch: ExecutionEpoch(epoch),
    }
}
fn local(p: HostPolicy, a: Assurance) -> LocalHostInterface {
    LocalHostInterface::new("n1", p, a, now)
}
fn ro(id: &str, src: &str) -> NamedVolumeGrant {
    NamedVolumeGrant {
        id: id.into(),
        source: src.into(),
        guest_target: "/data".into(),
        mode: VolumeMode::ReadOnly,
        read_write_authorized: false,
        quota_bytes: None,
    }
}
fn denied(r: Result<LaunchAuthorization, HostInterfaceError>) -> Denial {
    match r {
        Err(HostInterfaceError::Denied(d)) => d,
        o => panic!("expected denial, got {o:?}"),
    }
}

#[test]
fn local_default_launches_with_no_assurance_and_no_central_identity() {
    let a = local(HostPolicy::default(), Assurance::None)
        .authorize_workload(&req(1))
        .unwrap();
    assert_eq!(a.assurance, Assurance::None);
}

#[test]
fn default_policy_does_not_require_attestation() {
    assert!(!HostPolicy::default().attestation.required);
}

#[test]
fn hardware_required_blocks_software_evidence() {
    let p = HostPolicy {
        attestation: AssuranceRequirement {
            required: true,
            minimum: Assurance::Hardware,
        },
        ..Default::default()
    };
    let d = denied(local(p, Assurance::Software).authorize_workload(&req(1)));
    assert_eq!(d, Denial::AttestationRequired(Assurance::Software));
}

#[test]
fn signed_policy_round_trips() {
    let k = key(1);
    let s = SignedHostPolicy::sign(
        HostPolicy {
            version: 3,
            ..Default::default()
        },
        "issuer",
        &k,
    )
    .unwrap();
    assert_eq!(s.verify(&trusted(&k), now(), 1).unwrap().version, 3);
}

#[test]
fn tampered_policy_is_rejected() {
    let k = key(1);
    let mut s = SignedHostPolicy::sign(HostPolicy::default(), "issuer", &k).unwrap();
    s.policy.version = 99;
    assert_eq!(
        s.verify(&trusted(&k), now(), 0).unwrap_err(),
        Denial::PolicySignature
    );
}

#[test]
fn wrong_key_is_rejected() {
    let s = SignedHostPolicy::sign(HostPolicy::default(), "issuer", &key(1)).unwrap();
    assert_eq!(
        s.verify(&trusted(&key(2)), now(), 0).unwrap_err(),
        Denial::PolicySignature
    );
}

#[test]
fn unknown_issuer_expired_and_rolled_back_policy_are_rejected() {
    let k = key(1);
    let sign = |p| SignedHostPolicy::sign(p, "issuer", &k).unwrap();
    let mut other = sign(HostPolicy::default());
    other.issuer = "nobody".into();
    assert_eq!(
        other.verify(&trusted(&k), now(), 0).unwrap_err(),
        Denial::PolicyIssuer
    );
    let exp = sign(HostPolicy {
        not_after: Some(1_000),
        ..Default::default()
    });
    assert_eq!(
        exp.verify(&trusted(&k), now(), 0).unwrap_err(),
        Denial::PolicyExpired
    );
    let old = sign(HostPolicy {
        version: 1,
        ..Default::default()
    });
    assert_eq!(
        old.verify(&trusted(&k), now(), 5).unwrap_err(),
        Denial::PolicyRollback { got: 1, min: 5 }
    );
}

#[test]
fn expired_scope_and_image_policy_block_launch() {
    let expired = HostPolicy {
        not_after: Some(500),
        ..Default::default()
    };
    assert_eq!(
        denied(local(expired, Assurance::None).authorize_workload(&req(1))),
        Denial::PolicyExpired
    );
    let scoped = HostPolicy {
        scope: vec!["other".into()],
        ..Default::default()
    };
    assert_eq!(
        denied(local(scoped, Assurance::None).authorize_workload(&req(1))),
        Denial::PolicyScope
    );
    let pinned = HostPolicy {
        image_digests: vec!["sha256:b".into()],
        ..Default::default()
    };
    assert_eq!(
        denied(local(pinned, Assurance::None).authorize_workload(&req(1))),
        Denial::ImageDigest
    );
}

#[test]
fn unavailable_enforcement_blocks_launch() {
    let h = local(HostPolicy::default(), Assurance::None).with_enforcement_ready(false);
    assert_eq!(
        denied(h.authorize_workload(&req(1))),
        Denial::EnforcementUnavailable
    );
}

#[test]
fn revoked_and_quarantined_nodes_cannot_launch_and_revoked_is_terminal() {
    let h = local(HostPolicy::default(), Assurance::None);
    h.transition(NodeState::Quarantined).unwrap();
    assert_eq!(
        denied(h.authorize_workload(&req(1))),
        Denial::NodeNotActive("quarantined")
    );
    h.transition(NodeState::Revoked).unwrap();
    assert_eq!(
        denied(h.authorize_workload(&req(1))),
        Denial::NodeNotActive("revoked")
    );
    assert!(matches!(
        h.transition(NodeState::Active),
        Err(HostInterfaceError::InvalidTransition { .. })
    ));
}

#[test]
fn replacement_gets_a_fresh_epoch_and_the_stale_one_is_rejected() {
    let h = local(HostPolicy::default(), Assurance::None);
    let old = h.current_epoch();
    let new = h.advance_epoch();
    assert!(new > old);
    assert_eq!(
        denied(h.authorize_workload(&req(old.0))),
        Denial::StaleEpoch {
            got: old.0,
            current: new.0
        }
    );
    assert!(h.authorize_workload(&req(new.0)).is_ok());
}

#[test]
fn invalid_volume_grants_block_launch() {
    let mut rw = ro("rw", "/trusted");
    rw.mode = VolumeMode::ReadWrite;
    let cases = [
        ro("up", "/trusted/../etc"),
        ro("rel", "trusted"),
        ro("root", "/"),
        ro("", "/t"),
        rw,
    ];
    for v in cases {
        let p = HostPolicy {
            volumes: vec![v],
            ..Default::default()
        };
        assert!(matches!(
            denied(local(p, Assurance::None).authorize_workload(&req(1))),
            Denial::VolumeGrant(_)
        ));
    }
}

#[test]
fn authorized_read_write_and_read_only_volumes_are_accepted() {
    let mut rw = ro("rw", "/trusted/out");
    rw.mode = VolumeMode::ReadWrite;
    rw.read_write_authorized = true;
    let p = HostPolicy {
        volumes: vec![ro("in", "/trusted/in"), rw],
        ..Default::default()
    };
    assert!(
        local(p, Assurance::None)
            .authorize_workload(&req(1))
            .is_ok()
    );
}

struct Always(CheckKind, Option<Denial>);
impl PreflightCheck for Always {
    fn kind(&self) -> CheckKind {
        self.0
    }
    fn run(&self) -> Result<(), Denial> {
        self.1.clone().map_or(Ok(()), Err)
    }
}
struct Panics(CheckKind);
impl PreflightCheck for Panics {
    fn kind(&self) -> CheckKind {
        self.0
    }
    fn run(&self) -> Result<(), Denial> {
        panic!("boom")
    }
}
fn all_ok() -> Vec<Box<dyn PreflightCheck>> {
    CheckKind::REQUIRED
        .iter()
        .map(|k| Box::new(Always(*k, None)) as Box<dyn PreflightCheck>)
        .collect()
}

#[test]
fn preflight_passes_only_when_every_required_check_runs_and_passes() {
    assert!(run_preflight(&all_ok()).into_result().is_ok());
}

#[test]
fn preflight_missing_required_check_is_a_denial() {
    let mut c = all_ok();
    c.pop();
    assert_eq!(
        run_preflight(&c).into_result().unwrap_err(),
        Denial::CheckMissing("attestation")
    );
}

#[test]
fn preflight_panicking_check_fails_closed() {
    let mut c = all_ok();
    c[0] = Box::new(Panics(CheckKind::Policy));
    assert_eq!(
        run_preflight(&c).into_result().unwrap_err(),
        Denial::CheckMissing("policy")
    );
}

#[test]
fn preflight_runs_checks_concurrently() {
    use std::{sync::Arc, sync::Barrier};
    struct Rendezvous(CheckKind, Arc<Barrier>);
    impl PreflightCheck for Rendezvous {
        fn kind(&self) -> CheckKind {
            self.0
        }
        fn run(&self) -> Result<(), Denial> {
            self.1.wait();
            Ok(())
        }
    }
    // Sequential execution would deadlock on the barrier.
    let b = Arc::new(Barrier::new(CheckKind::REQUIRED.len()));
    let c: Vec<Box<dyn PreflightCheck>> = CheckKind::REQUIRED
        .iter()
        .map(|k| Box::new(Rendezvous(*k, b.clone())) as Box<dyn PreflightCheck>)
        .collect();
    assert!(run_preflight(&c).into_result().is_ok());
}

#[test]
fn lifecycle_transitions_are_small_and_closed() {
    use NodeState::*;
    assert!(Pending.can_transition_to(Active));
    assert!(!Pending.can_transition_to(Quarantined));
    assert!(!Revoked.can_transition_to(Pending));
}

#[test]
fn policy_serde_rejects_unknown_fields() {
    assert!(
        serde_json::from_str::<HostPolicy>(r#"{"version":1,"not_after":null,"bogus":1}"#).is_err()
    );
}
