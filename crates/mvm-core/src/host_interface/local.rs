use std::sync::Mutex;

use super::{
    Assurance, ExecutionEpoch, HostInterface, HostInterfaceError, HostPolicy, LaunchAuthorization,
    LaunchRequest, NodeState,
    error::Denial,
    preflight::{CheckKind, PreflightCheck, run_preflight},
};

struct Fn1<F: Fn() -> Result<(), Denial> + Send + Sync>(CheckKind, F);
impl<F: Fn() -> Result<(), Denial> + Send + Sync> PreflightCheck for Fn1<F> {
    fn kind(&self) -> CheckKind {
        self.0
    }
    fn run(&self) -> Result<(), Denial> {
        (self.1)()
    }
}

/// Default adapter: local identity and policy, no central admission, no
/// required hardware attestation. A fresh local node is `Active`.
pub struct LocalHostInterface {
    node_id: String,
    policy: HostPolicy,
    assurance: Assurance,
    enforcement_ready: bool,
    now: fn() -> u64,
    state: Mutex<(NodeState, ExecutionEpoch)>,
}

impl LocalHostInterface {
    pub fn new(node_id: &str, policy: HostPolicy, assurance: Assurance, now: fn() -> u64) -> Self {
        Self {
            node_id: node_id.to_owned(),
            policy,
            assurance,
            enforcement_ready: true,
            now,
            state: Mutex::new((NodeState::Active, ExecutionEpoch(1))),
        }
    }

    /// Start from a persisted node record instead of the fresh-node default.
    pub fn with_record(self, state: NodeState, epoch: ExecutionEpoch) -> Self {
        *self.state.lock().unwrap_or_else(|e| e.into_inner()) = (state, epoch);
        self
    }

    pub fn with_enforcement_ready(mut self, ready: bool) -> Self {
        self.enforcement_ready = ready;
        self
    }

    /// Issue the epoch a replacement workload must carry.
    pub fn advance_epoch(&self) -> ExecutionEpoch {
        let mut g = self.state.lock().unwrap_or_else(|e| e.into_inner());
        g.1 = g.1.next();
        g.1
    }

    pub fn current_epoch(&self) -> ExecutionEpoch {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).1
    }
}

impl HostInterface for LocalHostInterface {
    fn node_state(&self) -> NodeState {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).0
    }

    fn policy(&self) -> Result<HostPolicy, HostInterfaceError> {
        Ok(self.policy.clone())
    }

    fn authorize_workload(
        &self,
        req: &LaunchRequest,
    ) -> Result<LaunchAuthorization, HostInterfaceError> {
        let (state, epoch) = *self.state.lock().unwrap_or_else(|e| e.into_inner());
        let (p, now) = (&self.policy, (self.now)());
        let ready = self.enforcement_ready;
        let checks: Vec<Box<dyn PreflightCheck + '_>> = vec![
            Box::new(Fn1(CheckKind::Policy, || {
                p.check_launch_scope(&self.node_id, now)
            })),
            Box::new(Fn1(CheckKind::Image, || p.check_image(&req.image_digest))),
            Box::new(Fn1(CheckKind::Enforcement, move || {
                ready.then_some(()).ok_or(Denial::EnforcementUnavailable)
            })),
            Box::new(Fn1(CheckKind::NodeAdmission, move || {
                if state != NodeState::Active {
                    return Err(Denial::NodeNotActive(state.label()));
                }
                if !req.epoch.is_current(epoch) {
                    return Err(Denial::StaleEpoch {
                        got: req.epoch.0,
                        current: epoch.0,
                    });
                }
                Ok(())
            })),
            Box::new(Fn1(CheckKind::Volumes, || {
                p.volumes.iter().try_for_each(|v| v.validate())
            })),
            Box::new(Fn1(CheckKind::Resources, || Ok(()))),
            Box::new(Fn1(CheckKind::Secrets, || Ok(()))),
            Box::new(Fn1(CheckKind::Attestation, || {
                p.check_assurance(self.assurance)
            })),
        ];
        run_preflight(&checks).into_result()?;
        Ok(LaunchAuthorization {
            workload_id: req.workload_id.clone(),
            epoch,
            policy_version: p.version,
            assurance: self.assurance,
        })
    }

    fn transition(&self, to: NodeState) -> Result<(), HostInterfaceError> {
        let mut g = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if !g.0.can_transition_to(to) {
            return Err(HostInterfaceError::InvalidTransition { from: g.0, to });
        }
        g.0 = to;
        Ok(())
    }
}
