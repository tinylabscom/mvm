//! Safe stateless workspace reports. Opaque approval plans never cross this seam.

use super::{Applied, AppliedRelation, ApplyPlan, Recovered, Review};
use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ReviewSummary {
    Unchanged,
    Refused {
        plan: PlanSummary,
    },
    Ready {
        fingerprint: String,
        plan: PlanSummary,
    },
}

#[derive(Debug, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct PlanSummary {
    pub changes: Vec<ChangeSummary>,
    pub skipped_excluded: Vec<String>,
    pub refused_protected: Vec<(String, String)>,
    pub refused_unappliable: Vec<(String, String)>,
}

#[derive(Debug, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ChangeSummary {
    pub path: String,
    pub action: ChangeAction,
}

#[derive(Debug, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum ChangeAction {
    WriteFile,
    WriteSymlink,
    Remove,
}

impl From<&ApplyPlan> for PlanSummary {
    fn from(plan: &ApplyPlan) -> Self {
        Self {
            changes: plan
                .ops
                .iter()
                .map(|op| ChangeSummary {
                    path: op.path.clone(),
                    action: match &op.action {
                        super::OpAction::WriteFile => ChangeAction::WriteFile,
                        super::OpAction::WriteSymlink { .. } => ChangeAction::WriteSymlink,
                        super::OpAction::Remove => ChangeAction::Remove,
                    },
                })
                .collect(),
            skipped_excluded: plan.skipped_excluded.clone(),
            refused_protected: plan.refused_protected.clone(),
            refused_unappliable: plan.refused_unappliable.clone(),
        }
    }
}

impl TryFrom<&Review> for ReviewSummary {
    type Error = anyhow::Error;

    fn try_from(review: &Review) -> Result<Self> {
        Ok(match review {
            Review::Unchanged => Self::Unchanged,
            Review::Refused(plan) => Self::Refused { plan: plan.into() },
            Review::Ready(pending) => Self::Ready {
                fingerprint: pending.fingerprint()?,
                plan: pending.plan().into(),
            },
        })
    }
}

#[derive(Debug, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(tag = "kind", content = "apply_id", rename_all = "snake_case")]
pub enum RecoveryReport {
    Interrupted(String),
    Unaudited(String),
}

impl From<Recovered> for RecoveryReport {
    fn from(recovered: Recovered) -> Self {
        match recovered {
            Recovered::Interrupted(id) => Self::Interrupted(id),
            Recovered::Unaudited(id) => Self::Unaudited(id),
        }
    }
}

#[derive(Debug, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct AppliedReport {
    pub apply_id: String,
    pub changes: usize,
    pub snapshot_root: String,
    pub merkle_root: String,
}

impl From<Applied> for AppliedReport {
    fn from(applied: Applied) -> Self {
        Self {
            apply_id: applied.apply_id,
            changes: applied.changes,
            snapshot_root: applied.snapshot_root,
            merkle_root: applied.merkle_root,
        }
    }
}

#[derive(Debug, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct RelationReport {
    pub apply_id: String,
    pub target_id: String,
    pub merkle_root: String,
}

impl From<AppliedRelation> for RelationReport {
    fn from(relation: AppliedRelation) -> Self {
        Self {
            apply_id: relation.apply_id,
            target_id: relation.target_id,
            merkle_root: relation.merkle_root,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct ApplyRequest {
    pub workspace: super::WorkspaceRequest,
    pub expected_fingerprint: String,
    pub approved: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct HistoryRequest {
    pub workspace: super::WorkspaceRequest,
    pub approved: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refused_and_recovered_reports_are_safe_owned_data() {
        let plan = ApplyPlan {
            refused_protected: vec![(".ssh/key".into(), "credentials".into())],
            skipped_excluded: vec!["build/out".into()],
            ..Default::default()
        };
        let report = ReviewSummary::try_from(&Review::Refused(plan)).unwrap();
        let json = serde_json::to_value(report).unwrap();
        assert_eq!(json["status"], "refused");
        assert_eq!(json["plan"]["refused_protected"][0][0], ".ssh/key");
        assert!(json.get("fingerprint").is_none());
        let recovered = RecoveryReport::from(Recovered::Unaudited("prior".into()));
        assert_eq!(
            serde_json::to_value(recovered).unwrap(),
            serde_json::json!({"kind": "unaudited", "apply_id": "prior"})
        );
    }

    #[test]
    fn approval_inputs_cannot_carry_plans_or_disable_protection() {
        for input in [
            r#"{"workspace":{"vm":"worker"},"approved":true}"#,
            r#"{"workspace":{"vm":"worker","disable_protection":true},"expected_fingerprint":"x","approved":true}"#,
            r#"{"workspace":{"vm":"worker"},"expected_fingerprint":"x","approved":true,"plan":{}}"#,
        ] {
            assert!(serde_json::from_str::<ApplyRequest>(input).is_err());
        }
    }
}
