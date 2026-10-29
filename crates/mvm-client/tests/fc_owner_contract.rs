//! Test-only sequencing model, not authentication, persistence or native custody.
//! No production owner, process host or positive execution factory is imported.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Binding {
    // Integer labels are synthetic identities, not a wire format or credential.
    // The fixture prepopulates plan/config/generation; phase acquisition is unmodeled.
    uid: u32,
    principal: u64,
    tenant: u64,
    operation: u64,
    request_digest: u64,
    plan: u64,
    configuration: u64,
    incarnation: u64,
    generation: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Registered,
    Active,
    Executing,
    Stopping,
    Terminal,
    Aborted,
    Quarantined,
}

#[derive(Debug, PartialEq, Eq)]
enum Refusal {
    Binding,
    Phase,
    Persistence,
    Incomplete,
    Revision,
    Output,
}

#[derive(Debug)]
struct Model {
    binding: Binding,
    phase: Phase,
    quarantine: bool,
    detached: bool,
    dispatched: bool,
    births: usize,
    output_bytes: usize,
    output_failed: bool,
    revision: Option<u64>,
    delivery_acked: bool,
}

impl Model {
    fn registered(binding: Binding) -> Self {
        Self {
            binding,
            phase: Phase::Registered,
            quarantine: false,
            detached: false,
            dispatched: false,
            births: 0,
            output_bytes: 0,
            output_failed: false,
            revision: None,
            delivery_acked: false,
        }
    }

    fn observe_start(&self, binding: Binding) -> Result<Phase, Refusal> {
        if binding != self.binding {
            return Err(Refusal::Binding);
        }
        if self.phase == Phase::Quarantined {
            return Err(Refusal::Phase);
        }
        Ok(self.phase)
    }

    fn activate(&mut self) -> Result<(), Refusal> {
        if self.phase != Phase::Registered {
            return Err(Refusal::Phase);
        }
        if !self.quarantine {
            return Err(Refusal::Persistence);
        }
        self.births += 1;
        self.phase = Phase::Active;
        Ok(())
    }

    fn dispatch(&mut self) -> Result<(), Refusal> {
        if self.phase != Phase::Active {
            return Err(Refusal::Phase);
        }
        self.dispatched = true;
        self.phase = Phase::Executing;
        Ok(())
    }

    fn detach(&mut self) -> Result<(), Refusal> {
        if !matches!(self.phase, Phase::Active | Phase::Executing) {
            return Err(Refusal::Phase);
        }
        self.detached = true;
        Ok(())
    }

    fn cancel(&mut self) -> Result<(), Refusal> {
        if matches!(
            self.phase,
            Phase::Terminal | Phase::Aborted | Phase::Quarantined
        ) {
            return Err(Refusal::Phase);
        }
        self.phase = Phase::Stopping;
        Ok(())
    }

    fn disconnect(&mut self) {
        if !self.detached {
            let _ = self.cancel();
        }
    }

    fn queue_output(&mut self, bytes: usize) -> Result<(), Refusal> {
        const MAX: usize = 16 * 1024 * 1024;
        let total = self
            .output_bytes
            .checked_add(bytes)
            .filter(|sum| *sum <= MAX);
        let Some(total) = total else {
            self.output_failed = true;
            self.cancel()?;
            return Err(Refusal::Output);
        };
        self.output_bytes = total;
        Ok(())
    }

    // Model facts only: actual implementation must consume original typed evidence.
    fn terminal(&mut self, facts: [bool; 5]) -> Result<(), Refusal> {
        if self.phase != Phase::Stopping || !self.dispatched {
            return Err(Refusal::Phase);
        }
        // Exec terminal, same-session Sync, original exit, cleanup, audit outcome.
        if self.output_failed || !facts.into_iter().all(|present| present) {
            return Err(Refusal::Incomplete);
        }
        self.phase = Phase::Terminal;
        self.revision = Some(1);
        Ok(())
    }

    fn abort_complete(&mut self, facts: [bool; 4]) -> Result<(), Refusal> {
        if self.phase != Phase::Stopping {
            return Err(Refusal::Phase);
        }
        // Child-free preparation OR original exit, then cleanup and abort audit.
        let absent = if self.births == 0 { facts[0] } else { facts[1] };
        if !absent || !facts[2] || !facts[3] {
            return Err(Refusal::Incomplete);
        }
        self.phase = Phase::Aborted;
        self.revision = Some(1);
        Ok(())
    }

    fn ack(&mut self, revision: u64) -> Result<(), Refusal> {
        if !matches!(self.phase, Phase::Terminal | Phase::Aborted)
            || self.revision != Some(revision)
        {
            return Err(Refusal::Revision);
        }
        self.delivery_acked = true;
        Ok(())
    }

    fn retire(&mut self, durable: bool) -> Result<(), Refusal> {
        if !matches!(self.phase, Phase::Terminal | Phase::Aborted) {
            return Err(Refusal::Phase);
        }
        if !durable {
            return Err(Refusal::Persistence);
        }
        self.quarantine = false;
        Ok(())
    }

    fn owner_lost(&mut self) {
        self.phase = Phase::Quarantined;
        self.quarantine = true;
    }
}

fn binding() -> Binding {
    Binding {
        uid: 1000,
        principal: 1,
        tenant: 2,
        operation: 3,
        request_digest: 4,
        plan: 5,
        configuration: 6,
        incarnation: 7,
        generation: 8,
    }
}

fn active() -> Model {
    let mut model = Model::registered(binding());
    model.quarantine = true; // Simulated successful durable write, not a proof.
    model.activate().unwrap();
    model
}

#[test]
fn every_binding_component_is_required_beyond_matching_uid() {
    let model = active();
    let original = binding();
    let mismatches = [
        Binding {
            uid: 2000,
            ..original
        },
        Binding {
            principal: 9,
            ..original
        },
        Binding {
            tenant: 9,
            ..original
        },
        Binding {
            operation: 9,
            ..original
        },
        Binding {
            request_digest: 9,
            ..original
        },
        Binding {
            plan: 9,
            ..original
        },
        Binding {
            configuration: 9,
            ..original
        },
        Binding {
            incarnation: 9,
            ..original
        },
        Binding {
            generation: 9,
            ..original
        },
    ];
    for changed in mismatches {
        assert_eq!(model.observe_start(changed), Err(Refusal::Binding));
    }
    assert_eq!(model.births, 1);
}

#[test]
fn lost_start_response_observes_without_a_second_birth() {
    let mut model = active();
    for _ in 0..3 {
        assert_eq!(model.observe_start(binding()), Ok(Phase::Active));
        assert_eq!(model.activate(), Err(Refusal::Phase));
    }
    assert_eq!(model.births, 1);
}

#[test]
fn missing_quarantine_refuses_before_native_effects() {
    let mut model = Model::registered(binding());
    assert_eq!(model.activate(), Err(Refusal::Persistence));
    assert_eq!(model.births, 0);
    assert_eq!(model.phase, Phase::Registered);
}

#[test]
fn detach_commit_survives_a_lost_reply_and_disconnect() {
    let mut model = active();
    model.dispatch().unwrap();
    model.detach().unwrap();
    model.disconnect();
    assert_eq!(model.observe_start(binding()), Ok(Phase::Executing));
    assert!(model.detached);
    assert_eq!(model.births, 1);
}

#[test]
fn disconnect_before_detach_cancels_and_cannot_dispatch_or_commit() {
    let mut model = active();
    model.disconnect();
    assert_eq!(model.phase, Phase::Stopping);
    assert_eq!(model.dispatch(), Err(Refusal::Phase));
    assert_eq!(model.detach(), Err(Refusal::Phase));
}

#[test]
fn executing_model_accepts_cancel_intent_with_a_full_output_counter() {
    let mut model = active();
    model.dispatch().unwrap();
    model.queue_output(16 * 1024 * 1024).unwrap();
    model.cancel().unwrap();
    assert_eq!(model.phase, Phase::Stopping);
    assert!(model.quarantine);
}

#[test]
fn output_overflow_cancels_and_cannot_become_successful_completion() {
    for extra in [1, usize::MAX] {
        let mut model = active();
        model.dispatch().unwrap();
        model.queue_output(16 * 1024 * 1024).unwrap();
        assert_eq!(model.queue_output(extra), Err(Refusal::Output));
        assert_eq!(model.phase, Phase::Stopping);
        assert_eq!(model.terminal([true; 5]), Err(Refusal::Incomplete));
        assert!(model.quarantine);
        model.abort_complete([false, true, true, true]).unwrap();
        assert_eq!(model.phase, Phase::Aborted);
        model.retire(true).unwrap();
        assert!(!model.quarantine);
    }
}

#[test]
fn cancellation_before_activation_never_births_a_child() {
    let mut model = Model::registered(binding());
    model.cancel().unwrap();
    model.quarantine = true;
    assert_eq!(model.activate(), Err(Refusal::Phase));
    assert_eq!(model.births, 0);
}

#[test]
fn every_missing_compound_terminal_fact_keeps_quarantine() {
    for present in 0..32 {
        let mut model = active();
        model.dispatch().unwrap();
        model.cancel().unwrap();
        let facts = std::array::from_fn(|bit| present & (1 << bit) != 0);
        if present == 31 {
            assert_eq!(model.terminal(facts), Ok(()));
        } else {
            assert_eq!(model.terminal(facts), Err(Refusal::Incomplete));
            assert_eq!(model.retire(true), Err(Refusal::Phase));
            assert_eq!(model.ack(1), Err(Refusal::Revision));
        }
        assert!(model.quarantine);
    }
}

#[test]
fn pre_execution_abort_cannot_become_success_from_claimed_terminal_facts() {
    let mut model = active();
    model.cancel().unwrap();
    assert_eq!(model.terminal([true; 5]), Err(Refusal::Phase));
    assert_eq!(model.retire(true), Err(Refusal::Phase));
    assert!(model.quarantine);
    model.abort_complete([false, true, true, true]).unwrap();
    assert_eq!(model.phase, Phase::Aborted);
    model.retire(true).unwrap();
    assert!(!model.quarantine);
}

#[test]
fn safe_abort_needs_the_applicable_absence_cleanup_and_audit_facts() {
    for born in [false, true] {
        for present in 0..16 {
            let mut model = if born {
                active()
            } else {
                Model::registered(binding())
            };
            model.quarantine = true;
            model.cancel().unwrap();
            let facts = std::array::from_fn(|bit| present & (1 << bit) != 0);
            let expected = facts[usize::from(born)] && facts[2] && facts[3];
            if expected {
                model.abort_complete(facts).unwrap();
                assert_eq!(model.phase, Phase::Aborted);
                assert_eq!(model.terminal([true; 5]), Err(Refusal::Phase));
                model.ack(1).unwrap();
                assert!(model.quarantine);
                model.retire(true).unwrap();
                assert!(!model.quarantine);
            } else {
                assert_eq!(model.abort_complete(facts), Err(Refusal::Incomplete));
                assert_eq!(model.retire(true), Err(Refusal::Phase));
                assert!(model.quarantine);
            }
        }
    }
}

#[test]
fn result_ack_is_revision_bound_delivery_only() {
    let mut model = active();
    assert_eq!(model.ack(1), Err(Refusal::Revision));
    model.dispatch().unwrap();
    model.cancel().unwrap();
    model.terminal([true; 5]).unwrap();
    assert_eq!(model.ack(2), Err(Refusal::Revision));
    model.ack(1).unwrap();
    model.ack(1).unwrap();
    assert!(model.delivery_acked);
    assert!(model.quarantine);
    assert_eq!(model.births, 1);
}

#[test]
fn failed_retirement_does_not_clear_quarantine() {
    let mut model = active();
    model.dispatch().unwrap();
    model.cancel().unwrap();
    model.terminal([true; 5]).unwrap();
    assert_eq!(model.retire(false), Err(Refusal::Persistence));
    assert!(model.quarantine);
    model.retire(true).unwrap();
    assert!(!model.quarantine);
}

#[test]
fn owner_loss_cannot_restore_custody_or_clear_uncertainty() {
    for phase in [
        Phase::Registered,
        Phase::Active,
        Phase::Executing,
        Phase::Stopping,
        Phase::Terminal,
        Phase::Aborted,
    ] {
        let mut model = active();
        model.phase = phase;
        model.owner_lost();
        assert!(model.quarantine);
        assert_eq!(model.observe_start(binding()), Err(Refusal::Phase));
        assert_eq!(model.activate(), Err(Refusal::Phase));
        assert_eq!(model.dispatch(), Err(Refusal::Phase));
        assert_eq!(model.detach(), Err(Refusal::Phase));
        assert_eq!(model.ack(1), Err(Refusal::Revision));
        assert_eq!(model.retire(true), Err(Refusal::Phase));
    }
}
