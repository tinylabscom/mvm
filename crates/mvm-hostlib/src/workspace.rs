//! Stateless reviewed workspace mutations with visible interrupted-work recovery.

use crate::{
    host_local::{error, parse},
    status::Outcome,
};
use mvm_client::workspace_apply::{
    RegisteredWorkspace, Workspace, WorkspaceRequest,
    wire::{
        AppliedReport, ApplyRequest, HistoryRequest, RecoveryReport, RelationReport, ReviewSummary,
    },
};
use serde::Serialize;

pub const REVIEW: &str = "workspace.review";
pub const APPLY: &str = "workspace.apply";
pub const UNDO: &str = "workspace.undo";
pub const REDO: &str = "workspace.redo";
pub const METHODS: &[&str] = &[REVIEW, APPLY, UNDO, REDO];

#[derive(Debug, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ReviewReply {
    pub workspace: Workspace,
    pub review: ReviewSummary,
    pub recoveries: Vec<RecoveryReport>,
}

#[derive(Debug, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ApplyReply {
    pub applied: AppliedReport,
    pub recoveries: Vec<RecoveryReport>,
}

#[derive(Debug, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct HistoryReply {
    pub relation: Option<RelationReport>,
    pub recoveries: Vec<RecoveryReport>,
}

pub(crate) fn dispatch(method: &str, request: &[u8]) -> Outcome {
    match answer(method, request) {
        Ok(outcome) | Err(outcome) => outcome,
    }
}

fn open(request: WorkspaceRequest) -> Result<(RegisteredWorkspace, Vec<RecoveryReport>), Outcome> {
    crate::declared()?;
    RegisteredWorkspace::open(request)
        .map(|(workspace, recovered)| (workspace, recovered.into_iter().map(Into::into).collect()))
        .map_err(error)
}

// Recovery may already have changed the host even if the subsequent operation
// fails. Include its safe report in the failure rather than claiming no work.
fn recovered_error(error_value: anyhow::Error, recoveries: &[RecoveryReport]) -> Outcome {
    if recoveries.is_empty() {
        return error(error_value);
    }
    match serde_json::to_string(recoveries) {
        Ok(report) => error(error_value.context(format!("workspace recovery completed: {report}"))),
        Err(serialization) => error(error_value.context(format!(
            "workspace recovery completed; report encoding failed: {serialization}"
        ))),
    }
}

fn answer(method: &str, request: &[u8]) -> Result<Outcome, Outcome> {
    match method {
        REVIEW => {
            let request: WorkspaceRequest = parse(request)?;
            let (workspace, recoveries) = open(request)?;
            let reviewed = workspace
                .review()
                .and_then(|review| ReviewSummary::try_from(&review))
                .map_err(|e| recovered_error(e, &recoveries))?;
            Ok(Outcome::ok(&ReviewReply {
                workspace: workspace.workspace().clone(),
                review: reviewed,
                recoveries,
            }))
        }
        APPLY => {
            let request: ApplyRequest = parse(request)?;
            if !request.approved {
                return Err(Outcome::invalid_input(
                    "workspace apply requires explicit approval",
                ));
            }
            let (workspace, recoveries) = open(request.workspace)?;
            let applied = workspace
                .apply_reviewed(&request.expected_fingerprint, request.approved)
                .map_err(|e| recovered_error(e, &recoveries))?;
            Ok(Outcome::ok(&ApplyReply {
                applied: applied.into(),
                recoveries,
            }))
        }
        UNDO | REDO => {
            let request: HistoryRequest = parse(request)?;
            if !request.approved {
                return Err(Outcome::invalid_input(
                    "workspace history mutation requires explicit approval",
                ));
            }
            let (workspace, recoveries) = open(request.workspace)?;
            let relation = if method == UNDO {
                workspace.undo()
            } else {
                workspace.redo()
            }
            .map_err(|e| recovered_error(e, &recoveries))?;
            Ok(Outcome::ok(&HistoryReply {
                relation: relation.map(Into::into),
                recoveries,
            }))
        }
        _ => Err(Outcome::invalid_input("unknown workspace method")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_caller_plan_no_implicit_mutation() {
        for method in METHODS {
            for body in [b"null".as_slice(), br#"{"vm":"x","plan":{}}"#] {
                assert_eq!(
                    dispatch(method, body).status,
                    crate::status::MVM_HOSTLIB_INVALID_INPUT
                );
            }
        }
        for method in [APPLY, UNDO, REDO] {
            assert_eq!(
                dispatch(method, br#"{"workspace":{"vm":"x"}}"#).status,
                crate::status::MVM_HOSTLIB_INVALID_INPUT
            );
        }
        assert_eq!(
            dispatch(
                APPLY,
                br#"{"workspace":{"vm":"x"},"expected_fingerprint":"digest","approved":false}"#
            )
            .status,
            crate::status::MVM_HOSTLIB_INVALID_INPUT
        );
        let recovery = vec![RecoveryReport::Interrupted("apply-1".into())];
        let outcome = recovered_error(anyhow::anyhow!("review failed"), &recovery);
        let body: serde_json::Value = serde_json::from_slice(&outcome.body).unwrap();
        let message = body["message"].as_str().unwrap();
        assert!(message.contains("apply-1"));
        assert!(message.contains("review failed"));
    }
}
