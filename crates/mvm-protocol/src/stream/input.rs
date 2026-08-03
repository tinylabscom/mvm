//! Wire DTOs for the workload input plane, and the plan grant that
//! authorizes it.
//!
//! Output capture ([`crate::stream::record`]) is always on and needs no
//! authorization; input is the mirror image. A running workload's stdin is
//! reachable only through a signed [`crate::plan::ExecutionPlan`] grant — see
//! [`grants_input`] — so "no grant" and "no path" look identical from the
//! guest's side. [`InputFrame`] carries one chunk of bytes toward the
//! entrypoint's stdin; [`CloseInput`] is the explicit end-of-input marker a
//! writer must send for a read-to-EOF program to ever terminate.

use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use crate::plan::execution_plan::ExecutionPlan;
use crate::protocol::broker::ServiceId;

/// The `ExecutionPlan.services` token that authorizes the input plane. A
/// plan's `services` list is otherwise the broker-dispatch binding set (see
/// [`crate::plan::sdk_sidecar`]); this token is checked directly rather than
/// folded into that set, because the input plane is a stream-plane grant, not
/// a broker RPC service the SDK cdylib dispatches to.
pub const INPUT_GRANT_SERVICE: &str = "host.stream.v1";

/// One host→guest byte chunk on the input plane.
///
/// `seq` numbers frames within one writer's session so the receiving gate can
/// detect a gap or a reorder; unlike [`crate::stream::StreamRecord`] there is
/// no `prev_hash` here — a single leased writer needs ordering, not a
/// tamper-evident chain, and the gate that admits these frames (a later
/// piece) owns replay/lease bookkeeping.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InputFrame {
    /// 0-based position of this frame in the writer's session.
    pub seq: u64,
    /// Raw bytes to deliver to the entrypoint's stdin, verbatim.
    pub payload: Vec<u8>,
}

/// Explicit end-of-input marker.
///
/// Continuous input has no natural end the way one-shot `stdin_data` does
/// (`entrypoint.rs` writes it once and closes the pipe immediately). Without
/// this frame, a read-to-EOF program — `cat`-shaped workloads chief among
/// them — hangs forever waiting on a stdin that never closes. Carries no
/// fields of its own: it is a pure signal, not a payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloseInput {}

/// Whether `services` authorizes the input plane, i.e. carries the
/// [`INPUT_GRANT_SERVICE`] token. A `services` list that says nothing about
/// it grants nothing: default-deny, not an oversight. Mirrors the shape of
/// [`crate::plan::sdk_sidecar::sdk_sidecar_required_for`] for the analogous
/// question on the output side.
#[must_use]
pub fn grants_input_for(services: &[ServiceId]) -> bool {
    services.iter().any(|s| s.as_str() == INPUT_GRANT_SERVICE)
}

/// Whether `plan` authorizes the input plane. Thin wrapper over
/// [`grants_input_for`] for the common case of asking about an already
/// synthesized plan.
#[must_use]
pub fn grants_input(plan: &ExecutionPlan) -> bool {
    grants_input_for(&plan.services)
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;
    use crate::plan::execution_plan::minimal_plan;

    fn svc(raw: &str) -> ServiceId {
        ServiceId::parse(raw).expect("fixture service id parses")
    }

    fn sample_frame() -> InputFrame {
        InputFrame {
            seq: 0,
            payload: vec![b'h', b'i'],
        }
    }

    #[test]
    fn input_frame_serde_round_trip() {
        let f = sample_frame();
        let json = serde_json::to_string(&f).unwrap();
        let back: InputFrame = serde_json::from_str(&json).unwrap();
        assert_eq!(f, back);
    }

    #[test]
    fn input_frame_rejects_unknown_field() {
        let mut value = serde_json::to_value(sample_frame()).unwrap();
        value["surprise"] = serde_json::Value::Bool(true);
        let json = serde_json::to_string(&value).unwrap();
        assert!(serde_json::from_str::<InputFrame>(&json).is_err());
    }

    #[test]
    fn close_input_serde_round_trip() {
        let c = CloseInput::default();
        let json = serde_json::to_string(&c).unwrap();
        let back: CloseInput = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
    }

    #[test]
    fn close_input_rejects_unknown_field() {
        let json = r#"{"surprise":true}"#;
        assert!(serde_json::from_str::<CloseInput>(json).is_err());
    }

    #[test]
    fn no_services_grants_no_input() {
        assert!(!grants_input_for(&[]));
    }

    #[test]
    fn the_stream_token_grants_input() {
        assert!(grants_input_for(&[svc(INPUT_GRANT_SERVICE)]));
    }

    #[test]
    fn an_unrelated_service_does_not_grant_input() {
        assert!(!grants_input_for(&[svc("host.audit.v1")]));
    }

    #[test]
    fn a_plan_without_the_grant_reports_false() {
        let plan = minimal_plan();
        assert!(plan.services.is_empty());
        assert!(!grants_input(&plan));
    }

    #[test]
    fn a_plan_carrying_the_grant_reports_true() {
        let mut plan = minimal_plan();
        plan.services = vec![svc(INPUT_GRANT_SERVICE)];
        assert!(grants_input(&plan));
    }

    #[test]
    fn a_plan_carrying_only_another_service_reports_false() {
        let mut plan = minimal_plan();
        plan.services = vec![svc("host.audit.v1")];
        assert!(!grants_input(&plan));
    }
}
