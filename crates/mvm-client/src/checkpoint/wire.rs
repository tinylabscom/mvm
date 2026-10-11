//! Stateless requests for local checkpoint and replay callers.

use serde::{Deserialize, Serialize};

/// Operations without a genuine preview require this explicit intent.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum MutationIntent {
    Execute,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct Mutation<T> {
    pub intent: MutationIntent,
    pub request: T,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct Empty {}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct IdRequest {
    pub id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct DiffRequest {
    pub a: String,
    pub b: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct TimelineRequest {
    pub target: String,
    pub kind: Option<super::LineageKind>,
}

/// Ordinary forks cannot replace secret bindings or opt out of attenuation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct ForkRequest {
    pub id: String,
    pub new_id: Option<String>,
    pub boot: bool,
    pub hypervisor: String,
    pub cpus: Option<u32>,
    pub memory: Option<String>,
    pub tenant: String,
}

impl ForkRequest {
    pub fn into_client(self) -> anyhow::Result<super::ForkRequest> {
        Ok(super::ForkRequest {
            id: super::validated_id(&self.id)?,
            new_id: self.new_id,
            boot: self.boot,
            hypervisor: self.hypervisor,
            cpus: self.cpus,
            memory: self.memory,
            tenant: self.tenant,
            declared_secrets: Vec::new(),
            allow_secret_drop: false,
            intent: super::ForkIntent::Ordinary,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct ReplayRequest {
    pub selection: crate::replay::SessionReplayRequest,
    #[serde(default = "preview")]
    pub dry_run: bool,
    pub timeout_secs: u64,
    pub tenant: String,
}

fn preview() -> bool {
    true
}

impl From<ReplayRequest> for crate::replay::SessionReplayRunRequest {
    fn from(request: ReplayRequest) -> Self {
        Self {
            selection: request.selection,
            dry_run: request.dry_run,
            timeout_secs: request.timeout_secs,
            tenant: request.tenant,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forks_keep_admission_controls_client_owned() {
        let body = serde_json::json!({
            "id": "base", "new_id": "child", "boot": true,
            "hypervisor": "", "tenant": "local"
        });
        let request: ForkRequest = serde_json::from_value(body.clone()).unwrap();
        let client = request.into_client().unwrap();
        assert_eq!(client.intent, crate::checkpoint::ForkIntent::Ordinary);
        assert!(!client.allow_secret_drop);
        assert!(client.declared_secrets.is_empty());
        for field in [
            "declared_secrets",
            "allow_secret_drop",
            "intent",
            "raw_backend",
            "root",
        ] {
            let mut forbidden = body.clone();
            forbidden[field] = serde_json::json!(true);
            assert!(
                serde_json::from_value::<ForkRequest>(forbidden).is_err(),
                "{field}"
            );
        }
    }

    #[test]
    fn mutations_roundtrip_without_acquiring_an_implicit_intent() {
        let input = serde_json::json!({"intent": "execute", "request": {"id": "base"}});
        let request: Mutation<IdRequest> = serde_json::from_value(input.clone()).unwrap();
        assert_eq!(serde_json::to_value(request).unwrap(), input);
        assert!(
            serde_json::from_value::<Mutation<IdRequest>>(
                serde_json::json!({"request": {"id": "base"}})
            )
            .is_err()
        );
        let replay: ReplayRequest = serde_json::from_value(serde_json::json!({
            "selection": {"session_id": "session"}, "tenant": "local", "timeout_secs": 30
        }))
        .unwrap();
        assert!(crate::replay::SessionReplayRunRequest::from(replay).dry_run);
    }
}
