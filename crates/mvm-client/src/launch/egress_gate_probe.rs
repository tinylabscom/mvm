//! The fail-closed runtime egress-gate probe.
//!
//! Admission proves the *signed* network policy verified; it says nothing
//! about the gate the per-VM endpoint process actually built from it. This
//! module closes that gap at the detached-launch acceptance seam: it dials
//! the running endpoint's socket, asks the live gate to decide a small set
//! of samples chosen from the admitted policy, and refuses the launch unless
//! every verdict matches what that policy provably admits. The probe
//! witnesses the gate — it sends no substitution request, opens no forward
//! leg, and writes no audit record on the endpoint side.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use mvm_core::substitution_wire::{
    GateProbeExpect, GateProbeRequest, GateProbeResponse, GateProbeSample, GateProbeVerdict,
    read_frame, write_frame,
};

/// Failure of the runtime egress-gate probe. Every variant fails closed: the
/// launch is rolled back, because a gate that cannot be witnessed cannot be
/// distinguished from a gate that silently never took effect.
#[derive(Debug, thiserror::Error)]
pub enum EgressGateProbeError {
    /// The endpoint socket never accepted a connection: missing, or refused
    /// on every bounded attempt.
    #[error("the egress endpoint socket {path} never answered ({attempts} attempts)")]
    Unreachable {
        /// The endpoint socket the probe dialed.
        path: PathBuf,
        /// How many connect attempts were made.
        attempts: u32,
    },
    /// The probe's deadline expired while the endpoint was answering.
    #[error("the egress gate probe against {path} timed out after {timeout:?}")]
    Timeout {
        /// The endpoint socket the probe dialed.
        path: PathBuf,
        /// The budget the probe was given.
        timeout: Duration,
    },
    /// The endpoint accepted the probe but did not answer it: the connection
    /// failed mid-exchange or the reply was not a gate-probe response.
    #[error("the egress endpoint refused the gate probe: {message}")]
    Refused {
        /// What the endpoint did instead of answering.
        message: String,
    },
    /// The running gate's verdict disagreed with the verdict the admitted
    /// policy provably gives for the sample — the gate in force is not the
    /// gate the plan admitted.
    #[error(
        "the running egress gate decided {host}:{port} as {actual:?}, but the admitted policy \
         expects {expected:?}{}",
        reason
            .as_deref()
            .map(|reason| format!(": {reason}"))
            .unwrap_or_default()
    )]
    VerdictMismatch {
        /// The sample's host.
        host: String,
        /// The sample's port.
        port: u16,
        /// The verdict the admitted policy provably gives.
        expected: GateProbeExpect,
        /// The verdict the running gate gave.
        actual: GateProbeVerdict,
        /// The gate's own explanation, when it denied.
        reason: Option<String>,
    },
    /// The endpoint answered, but the answer is structurally wrong: a
    /// different number of results than samples, results out of order, or a
    /// `malformed` verdict for a well-formed sample.
    #[error("the egress gate probe response is malformed: {message}")]
    ResponseMalformed {
        /// What is wrong with the response.
        message: String,
    },
}

/// How long the detached launch waits for the running gate to verify. The
/// endpoint already completed its ready handshake before the backend start
/// returned, so this bounds a wedged answer, not ordinary startup.
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// Bounded connect attempts against the endpoint socket. The socket is
/// externally owned (the endpoint process binds it), so a fresh launch can
/// race the bind; each refusal backs off before the next attempt rather than
/// polling a condition that has no event source here.
const MAX_CONNECT_ATTEMPTS: u32 = 5;
const CONNECT_BACKOFF: [Duration; 4] = [
    Duration::from_millis(50),
    Duration::from_millis(100),
    Duration::from_millis(200),
    Duration::from_millis(400),
];

/// Documentation-range destinations a signed policy can only admit by naming
/// them literally, so under any other policy the gate must refuse them. Port
/// 9 (discard) is in no preset and names no real service.
const DOC_DENY_CANDIDATES: [(&str, u16); 3] =
    [("192.0.2.1", 9), ("198.51.100.1", 9), ("203.0.113.1", 9)];

/// A mandatory-deny destination: cloud metadata is refused by every gate,
/// including an unrestricted one, so it is the one deny sample a permissive
/// policy still provably refuses.
const MANDATORY_DENY_SAMPLE: (&str, u16) = ("169.254.169.254", 80);

/// Choose the probe samples for an admitted policy. Selection is data access
/// over the policy's declared rules — the expansion every other consumer
/// uses (`NetworkPolicy::resolve_rules`) — never a second policy evaluation:
/// the running gate is the only evaluator.
fn select_samples(policy: &mvm_core::network_policy::NetworkPolicy) -> Vec<GateProbeSample> {
    let Some(rules) = policy.resolve_rules() else {
        // Unrestricted admits every non-restricted destination, so no
        // documentation-range candidate is provably refused; only the
        // mandatory-deny layer is. That is still the dangerous direction to
        // witness: a gate that silently never took effect would admit it.
        return vec![deny_sample(
            MANDATORY_DENY_SAMPLE.0,
            MANDATORY_DENY_SAMPLE.1,
        )];
    };
    let mut samples = Vec::new();
    for (host, port) in DOC_DENY_CANDIDATES {
        if !rules.iter().any(|rule| rule.host == host) {
            samples.push(deny_sample(host, port));
            break;
        }
    }
    // The first allow rule. Pinned hosts were resolved when the endpoint
    // built its gate, so the verdict is deterministic.
    if let Some(rule) = rules.first() {
        samples.push(GateProbeSample {
            host: rule.host.clone(),
            port: rule.port,
            expect: GateProbeExpect::Admit,
        });
    }
    samples
}

fn deny_sample(host: &str, port: u16) -> GateProbeSample {
    GateProbeSample {
        host: host.into(),
        port,
        expect: GateProbeExpect::Deny,
    }
}

/// Whether this launch carries the per-VM endpoint process that owns the
/// egress gate. A secret-free, ingress-free boot whose policy reaches nothing
/// is spawned with no endpoint at all — there is no gate to witness, and
/// nothing egress-shaped for a silently-missing gate to expose. The
/// predicate mirrors the runner's spawn decision exactly; any launch it
/// passes is one where an endpoint must be answering.
pub(crate) fn launch_carries_endpoint(
    plan: &mvm_core::plan::ExecutionPlan,
    policy: &mvm_core::network_policy::NetworkPolicy,
) -> bool {
    !(plan.secrets.is_empty() && plan.ingress.is_empty() && !policy.admits_outbound())
}

/// Probe the running egress gate of `name`'s endpoint and fail closed unless
/// every sample's verdict matches the admitted policy.
pub fn require_egress_gate(
    name: &str,
    policy: &mvm_core::network_policy::NetworkPolicy,
    timeout: Duration,
) -> Result<(), EgressGateProbeError> {
    require_egress_gate_at(
        &mvm_core::config::vm_network_gate_probe_socket_at(&mvm_core::config::vm_state_dir(name)),
        policy,
        timeout,
    )
}

fn require_egress_gate_at(
    path: &std::path::Path,
    policy: &mvm_core::network_policy::NetworkPolicy,
    timeout: Duration,
) -> Result<(), EgressGateProbeError> {
    let samples = select_samples(policy);
    let body = serde_json::to_vec(&GateProbeRequest {
        samples: samples.clone(),
    })
    .map_err(|error| EgressGateProbeError::Refused {
        message: format!("serializing the gate probe failed: {error}"),
    })?;
    let deadline = Instant::now() + timeout;
    let mut attempts = 0;
    loop {
        attempts += 1;
        match std::os::unix::net::UnixStream::connect(path) {
            Ok(stream) => return exchange(path, stream, &body, &samples, timeout, deadline),
            Err(_) if attempts < MAX_CONNECT_ATTEMPTS => {
                std::thread::sleep(CONNECT_BACKOFF[(attempts - 1) as usize]);
            }
            Err(_) => {
                return Err(EgressGateProbeError::Unreachable {
                    path: path.to_path_buf(),
                    attempts,
                });
            }
        }
    }
}

/// One probe exchange over a connected socket: one framed request, one framed
/// response, compared sample by sample.
fn exchange(
    path: &std::path::Path,
    stream: std::os::unix::net::UnixStream,
    body: &[u8],
    samples: &[GateProbeSample],
    timeout: Duration,
    deadline: Instant,
) -> Result<(), EgressGateProbeError> {
    fn io_error(
        path: &std::path::Path,
        timeout: Duration,
        error: std::io::Error,
    ) -> EgressGateProbeError {
        match error.kind() {
            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => {
                EgressGateProbeError::Timeout {
                    path: path.to_path_buf(),
                    timeout,
                }
            }
            _ => EgressGateProbeError::Refused {
                message: error.to_string(),
            },
        }
    }

    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(EgressGateProbeError::Timeout {
            path: path.to_path_buf(),
            timeout,
        });
    }
    stream
        .set_read_timeout(Some(remaining))
        .map_err(|error| io_error(path, timeout, error))?;
    stream
        .set_write_timeout(Some(remaining))
        .map_err(|error| io_error(path, timeout, error))?;
    let mut stream = stream;
    write_frame(&mut stream, body).map_err(|error| io_error(path, timeout, error))?;
    let framed = read_frame(&mut stream).map_err(|error| io_error(path, timeout, error))?;
    let response: GateProbeResponse =
        serde_json::from_slice(&framed).map_err(|error| EgressGateProbeError::Refused {
            message: format!("the endpoint reply is not a gate-probe response: {error}"),
        })?;
    compare(samples, response.results)
}

/// Compare the endpoint's outcomes against the samples, in order. The
/// response must carry exactly one outcome per sample, each echoing its
/// host and port.
fn compare(
    samples: &[GateProbeSample],
    results: Vec<mvm_core::substitution_wire::GateProbeOutcome>,
) -> Result<(), EgressGateProbeError> {
    if results.len() != samples.len() {
        return Err(EgressGateProbeError::ResponseMalformed {
            message: format!(
                "the endpoint returned {} results for {} samples",
                results.len(),
                samples.len()
            ),
        });
    }
    for (sample, outcome) in samples.iter().zip(results) {
        if outcome.host != sample.host || outcome.port != sample.port {
            return Err(EgressGateProbeError::ResponseMalformed {
                message: format!(
                    "a result is for {}:{}, not the sample's {}:{}",
                    outcome.host, outcome.port, sample.host, sample.port
                ),
            });
        }
        let expected = match sample.expect {
            GateProbeExpect::Admit => GateProbeVerdict::Admit,
            GateProbeExpect::Deny => GateProbeVerdict::Deny,
        };
        if outcome.verdict == GateProbeVerdict::Malformed {
            return Err(EgressGateProbeError::ResponseMalformed {
                message: format!(
                    "the endpoint reported a malformed verdict for {}:{}",
                    sample.host, sample.port
                ),
            });
        }
        if outcome.verdict != expected {
            return Err(EgressGateProbeError::VerdictMismatch {
                host: sample.host.clone(),
                port: sample.port,
                expected: sample.expect,
                actual: outcome.verdict,
                reason: outcome.reason,
            });
        }
    }
    Ok(())
}

/// The probe a detached persistent launch runs before accepting the start:
/// witness the running gate against the policy the plan admitted, and fail
/// closed on any answer but the expected one.
///
/// Skipped — returning `Ok` — where there is no gate to witness: the mock
/// backend is a lifecycle test double with no endpoint process, and a
/// secret-free, ingress-free boot whose policy reaches nothing is spawned
/// with no endpoint at all.
pub(crate) fn require_running_gate(
    name: &str,
    started: &crate::StartedVm,
    plan: &mvm_core::plan::ExecutionPlan,
    policy: &mvm_core::network_policy::NetworkPolicy,
) -> Result<(), EgressGateProbeError> {
    if started.backend().kind() == mvm_core::vm_backend::BackendKind::Mock
        || !launch_carries_endpoint(plan, policy)
    {
        return Ok(());
    }
    require_egress_gate(name, policy, PROBE_TIMEOUT)
}

#[cfg(test)]
mod tests {
    use mvm_core::network_policy::{HostPort, NetworkPolicy, NetworkPreset};
    use mvm_core::substitution_wire::{
        GateProbeExpect, GateProbeOutcome, GateProbeRequest, GateProbeResponse, GateProbeVerdict,
        read_frame, write_frame,
    };

    use super::*;

    fn allowlist_policy() -> NetworkPolicy {
        NetworkPolicy::allow_list(vec![
            HostPort::new("api.example.com", 443),
            HostPort::new("registry.example.com", 443),
        ])
    }

    // --- sample selection ---

    #[test]
    fn deny_all_selects_only_a_deny_sample() {
        let samples = select_samples(&NetworkPolicy::deny_all());
        assert_eq!(samples.len(), 1);
        assert_eq!(samples[0].expect, GateProbeExpect::Deny);
        assert_eq!(samples[0].host, "192.0.2.1");
        assert_eq!(samples[0].port, 9);
    }

    #[test]
    fn an_allowlist_selects_a_deny_and_an_admit_sample() {
        let samples = select_samples(&allowlist_policy());
        assert_eq!(samples.len(), 2);
        assert_eq!(samples[0].expect, GateProbeExpect::Deny);
        assert_eq!(samples[0].host, "192.0.2.1");
        // The admit sample is the policy's first allow rule, verbatim.
        assert_eq!(samples[1].expect, GateProbeExpect::Admit);
        assert_eq!(samples[1].host, "api.example.com");
        assert_eq!(samples[1].port, 443);
    }

    #[test]
    fn a_preset_selects_from_its_expanded_rules() {
        let samples = select_samples(&NetworkPolicy::preset(NetworkPreset::Agent));
        let rules = NetworkPolicy::preset(NetworkPreset::Agent)
            .resolve_rules()
            .expect("a named preset expands to rules");
        assert!(!rules.is_empty());
        assert_eq!(samples.len(), 2);
        assert_eq!(samples[0].expect, GateProbeExpect::Deny);
        assert_eq!(
            samples[1].expect,
            GateProbeExpect::Admit,
            "a preset still yields an admit sample from its first rule"
        );
        assert_eq!(samples[1].host, rules[0].host);
        assert_eq!(samples[1].port, rules[0].port);
    }

    #[test]
    fn a_rule_naming_a_documentation_ip_falls_back_to_the_next_candidate() {
        let policy = NetworkPolicy::allow_list(vec![HostPort::new("192.0.2.1", 443)]);
        let samples = select_samples(&policy);
        assert_eq!(samples.len(), 2);
        assert_eq!(samples[0].expect, GateProbeExpect::Deny);
        assert_ne!(
            samples[0].host, "192.0.2.1",
            "a documentation IP the policy names literally cannot witness the deny direction"
        );
        assert_eq!(samples[1].expect, GateProbeExpect::Admit);
        assert_eq!(samples[1].host, "192.0.2.1");
    }

    #[test]
    fn a_policy_naming_every_documentation_ip_still_selects_an_admit_sample() {
        let policy = NetworkPolicy::allow_list(vec![
            HostPort::new("192.0.2.1", 443),
            HostPort::new("198.51.100.1", 443),
            HostPort::new("203.0.113.1", 443),
        ]);
        let samples = select_samples(&policy);
        assert_eq!(samples.len(), 1);
        assert_eq!(samples[0].expect, GateProbeExpect::Admit);
    }

    #[test]
    fn an_unrestricted_policy_selects_the_mandatory_deny_sample() {
        let samples = select_samples(&NetworkPolicy::unrestricted());
        assert_eq!(samples.len(), 1);
        assert_eq!(samples[0].expect, GateProbeExpect::Deny);
        assert_eq!(samples[0].host, "169.254.169.254");
        assert_eq!(samples[0].port, 80);
    }

    #[test]
    fn a_peers_only_policy_selects_the_deny_sample_only() {
        let peer = mvm_contract::peer::PeerBinding {
            name: mvm_contract::peer::PeerName::parse("db.mvm.peer").expect("valid peer name"),
            port: 5432,
            host_addr: "127.0.0.1".parse().expect("loopback literal"),
            host_port: 34567,
        };
        let policy = NetworkPolicy::deny_all().with_peers(vec![peer]);
        let samples = select_samples(&policy);
        assert_eq!(samples.len(), 1);
        assert_eq!(samples[0].expect, GateProbeExpect::Deny);
    }

    // --- the launch-carries-endpoint predicate ---

    fn plan_fixture() -> mvm_core::plan::ExecutionPlan {
        mvm_core::plan::test_support::PlanFixture::new().build()
    }

    #[test]
    fn a_secret_free_ingress_free_deny_all_launch_carries_no_endpoint() {
        assert!(!launch_carries_endpoint(
            &plan_fixture(),
            &NetworkPolicy::deny_all()
        ));
    }

    #[test]
    fn any_route_off_box_or_any_secret_or_any_ingress_carries_an_endpoint() {
        let plan = plan_fixture();
        assert!(launch_carries_endpoint(&plan, &allowlist_policy()));
        assert!(launch_carries_endpoint(
            &plan,
            &NetworkPolicy::deny_all().with_peers(vec![mvm_contract::peer::PeerBinding {
                name: mvm_contract::peer::PeerName::parse("db.mvm.peer").expect("valid peer name"),
                port: 5432,
                host_addr: "127.0.0.1".parse().expect("loopback literal"),
                host_port: 34567,
            }])
        ));
        let with_secret = mvm_core::plan::test_support::PlanFixture::new()
            .secrets(vec![mvm_core::plan::SecretBinding {
                name: "openai".into(),
                source: mvm_core::plan::SecretSource::Keystore {
                    address: "local/openai".into(),
                },
                destinations: vec!["api.openai.com".into()],
                approval_required: false,
            }])
            .build();
        assert!(!with_secret.secrets.is_empty());
        assert!(launch_carries_endpoint(
            &with_secret,
            &NetworkPolicy::deny_all()
        ));
        let mut with_ingress = plan_fixture();
        with_ingress.ingress.push(
            mvm_core::plan::IngressMapping::builder()
                .mapping_id(1)
                .protocol(mvm_core::plan::IngressProtocol::Tcp)
                .host_addr("127.0.0.1")
                .host_port(8080)
                .guest_addr("127.0.0.1")
                .guest_port(80)
                .transform(mvm_core::plan::IngressTransform::Opaque)
                .build()
                .expect("valid ingress mapping"),
        );
        assert!(launch_carries_endpoint(
            &with_ingress,
            &NetworkPolicy::deny_all()
        ));
    }

    // --- the probe exchange over a stub endpoint ---

    /// A stub endpoint speaking the frame protocol over a real UnixListener.
    /// `answer` builds the response frame from the request's samples.
    struct StubEndpoint {
        path: PathBuf,
        join: Option<std::thread::JoinHandle<()>>,
    }

    impl StubEndpoint {
        /// Serve `answer` for the first connection, then hold no more.
        fn start(answer: impl Fn(&GateProbeRequest) -> GateProbeResponse + Send + 'static) -> Self {
            let dir = tempfile::tempdir().expect("stub endpoint dir");
            let path = dir.path().join("endpoint.sock");
            let listener = std::os::unix::net::UnixListener::bind(&path)
                .expect("bind the stub endpoint socket");
            let join = std::thread::spawn(move || {
                let _dir = dir;
                let (mut stream, _) = listener.accept().expect("stub endpoint accept");
                let framed = read_frame(&mut stream).expect("stub endpoint read");
                let request: GateProbeRequest =
                    serde_json::from_slice(&framed).expect("stub endpoint parse");
                let response = answer(&request);
                write_frame(&mut stream, &serde_json::to_vec(&response).unwrap())
                    .expect("stub endpoint write");
            });
            Self {
                path,
                join: Some(join),
            }
        }

        /// Accept the probe, then close the connection without answering.
        fn start_silent() -> Self {
            let dir = tempfile::tempdir().expect("stub endpoint dir");
            let path = dir.path().join("endpoint.sock");
            let listener = std::os::unix::net::UnixListener::bind(&path)
                .expect("bind the stub endpoint socket");
            let join = std::thread::spawn(move || {
                let _dir = dir;
                let (stream, _) = listener.accept().expect("stub endpoint accept");
                // Read the request, then drop the connection unanswered.
                let mut stream = stream;
                let _ = read_frame(&mut stream);
            });
            Self {
                path,
                join: Some(join),
            }
        }

        fn wait(self) {
            self.join
                .expect("join handle")
                .join()
                .expect("stub endpoint thread");
        }
    }

    fn verdict_of(expect: GateProbeExpect) -> GateProbeVerdict {
        match expect {
            GateProbeExpect::Admit => GateProbeVerdict::Admit,
            GateProbeExpect::Deny => GateProbeVerdict::Deny,
        }
    }

    /// A responder that answers every sample with its expected verdict.
    fn echo_expected(request: &GateProbeRequest) -> GateProbeResponse {
        GateProbeResponse {
            results: request
                .samples
                .iter()
                .map(|sample| GateProbeOutcome {
                    host: sample.host.clone(),
                    port: sample.port,
                    verdict: verdict_of(sample.expect),
                    reason: None,
                })
                .collect(),
        }
    }

    #[test]
    fn launch_probe_uses_control_socket_not_guest_data_socket() {
        let home = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());
        let state = mvm_core::config::vm_state_dir("gate-control");
        let control = mvm_core::config::vm_network_gate_probe_socket_at(&state);
        std::fs::create_dir_all(control.parent().unwrap()).unwrap();
        let listener = std::os::unix::net::UnixListener::bind(&control).unwrap();
        let data = std::os::unix::net::UnixListener::bind(
            mvm_core::config::vm_network_endpoint_socket("gate-control"),
        )
        .unwrap();
        data.set_nonblocking(true).unwrap();
        let worker = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let request = serde_json::from_slice(&read_frame(&mut stream).unwrap()).unwrap();
            write_frame(
                &mut stream,
                &serde_json::to_vec(&echo_expected(&request)).unwrap(),
            )
            .unwrap();
        });
        require_egress_gate("gate-control", &allowlist_policy(), Duration::from_secs(5)).unwrap();
        worker.join().unwrap();
        assert_eq!(
            data.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn matching_verdicts_accept_the_launch() {
        let stub = StubEndpoint::start(echo_expected);
        let path = stub.path.clone();
        require_egress_gate_at(&path, &allowlist_policy(), Duration::from_secs(5))
            .expect("a gate answering as the policy admits is accepted");
        stub.wait();
    }

    #[test]
    fn a_deny_sample_answered_with_admit_fails_closed_with_the_mismatch() {
        let stub = StubEndpoint::start(|request| GateProbeResponse {
            results: request
                .samples
                .iter()
                .map(|sample| GateProbeOutcome {
                    host: sample.host.clone(),
                    port: sample.port,
                    verdict: GateProbeVerdict::Admit,
                    reason: None,
                })
                .collect(),
        });
        let path = stub.path.clone();
        let err = require_egress_gate_at(&path, &allowlist_policy(), Duration::from_secs(5))
            .expect_err("a permissive gate is the dangerous direction");
        let EgressGateProbeError::VerdictMismatch {
            host,
            expected,
            actual,
            ..
        } = &err
        else {
            panic!("expected a verdict mismatch, got {err:?}");
        };
        assert_eq!(host, "192.0.2.1");
        assert_eq!(*expected, GateProbeExpect::Deny);
        assert_eq!(*actual, GateProbeVerdict::Admit);
        stub.wait();
    }

    #[test]
    fn a_gate_reason_rides_along_on_a_mismatch() {
        let stub = StubEndpoint::start(|request| GateProbeResponse {
            results: request
                .samples
                .iter()
                .map(|sample| GateProbeOutcome {
                    host: sample.host.clone(),
                    port: sample.port,
                    verdict: GateProbeVerdict::Deny,
                    reason: Some("api.example.com:443 is not admitted".into()),
                })
                .collect(),
        });
        let path = stub.path.clone();
        let err = require_egress_gate_at(&path, &allowlist_policy(), Duration::from_secs(5))
            .expect_err("an over-denying gate mismatches the admit sample");
        let EgressGateProbeError::VerdictMismatch { reason, .. } = &err else {
            panic!("expected a verdict mismatch, got {err:?}");
        };
        assert_eq!(
            reason.as_deref(),
            Some("api.example.com:443 is not admitted")
        );
        stub.wait();
    }

    #[test]
    fn a_closed_connection_is_a_typed_error_not_a_panic() {
        let stub = StubEndpoint::start_silent();
        let path = stub.path.clone();
        let err = require_egress_gate_at(&path, &allowlist_policy(), Duration::from_secs(5))
            .expect_err("an unanswered probe fails closed");
        assert!(
            matches!(err, EgressGateProbeError::Refused { .. }),
            "got {err:?}"
        );
        stub.wait();
    }

    #[test]
    fn a_malformed_verdict_on_a_wellformed_sample_is_a_response_error() {
        let stub = StubEndpoint::start(|request| GateProbeResponse {
            results: request
                .samples
                .iter()
                .map(|sample| GateProbeOutcome {
                    host: sample.host.clone(),
                    port: sample.port,
                    verdict: GateProbeVerdict::Malformed,
                    reason: None,
                })
                .collect(),
        });
        let path = stub.path.clone();
        let err = require_egress_gate_at(&path, &allowlist_policy(), Duration::from_secs(5))
            .expect_err("a malformed verdict fails closed");
        assert!(
            matches!(err, EgressGateProbeError::ResponseMalformed { .. }),
            "got {err:?}"
        );
        stub.wait();
    }

    #[test]
    fn a_result_count_that_differs_from_the_samples_is_a_response_error() {
        let stub = StubEndpoint::start(|_| GateProbeResponse {
            results: Vec::new(),
        });
        let path = stub.path.clone();
        let err = require_egress_gate_at(&path, &allowlist_policy(), Duration::from_secs(5))
            .expect_err("a short result list fails closed");
        assert!(
            matches!(err, EgressGateProbeError::ResponseMalformed { .. }),
            "got {err:?}"
        );
        stub.wait();
    }

    #[test]
    fn an_unreachable_socket_is_unreachable_after_bounded_attempts() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("no-such-endpoint.sock");
        let started = Instant::now();
        let err = require_egress_gate_at(&path, &allowlist_policy(), Duration::from_secs(5))
            .expect_err("a missing endpoint fails closed");
        let EgressGateProbeError::Unreachable {
            path: got,
            attempts,
        } = &err
        else {
            panic!("expected unreachability, got {err:?}");
        };
        assert_eq!(got, &path);
        assert_eq!(*attempts, MAX_CONNECT_ATTEMPTS);
        // The bounded backoff is 50+100+200+400ms; assert the shape without
        // flaking on scheduling: well under the 5s budget.
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the retry loop stays inside the probe budget"
        );
    }

    #[test]
    fn a_wedged_endpoint_times_out() {
        let dir = tempfile::tempdir().expect("stub endpoint dir");
        let path = dir.path().join("endpoint.sock");
        let listener =
            std::os::unix::net::UnixListener::bind(&path).expect("bind the stub endpoint socket");
        let join = std::thread::spawn(move || {
            let _dir = dir;
            let (stream, _) = listener.accept().expect("stub endpoint accept");
            // Hold the connection open without ever answering.
            let _hold = stream;
            std::thread::sleep(Duration::from_secs(10));
        });
        let err = require_egress_gate_at(&path, &allowlist_policy(), Duration::from_millis(200))
            .expect_err("a wedged endpoint times out");
        assert!(
            matches!(err, EgressGateProbeError::Timeout { .. }),
            "got {err:?}"
        );
        drop(err);
        join.join().expect("stub endpoint thread");
    }
}
