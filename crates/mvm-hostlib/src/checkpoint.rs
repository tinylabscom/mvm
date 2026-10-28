//! Read-only checkpoint catalog access through the client-owned service.

use mvm_client::checkpoint::Checkpoints;

use crate::{host_local, status::Outcome};

pub const LIST: &str = "checkpoint.list";
pub const METHODS: &[&str] = &[LIST];

/// Listing has no filters; reject unknown fields rather than silently ignoring them.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ListRequest {}

pub fn is_known(method: &str) -> bool {
    METHODS.contains(&method)
}

pub(crate) fn dispatch(method: &str, request: &[u8]) -> Outcome {
    if !is_known(method) {
        return Outcome::invalid_input("unknown checkpoint method");
    }
    if let Err(outcome) = host_local::parse::<ListRequest>(request) {
        return outcome;
    }
    match Checkpoints::open().list() {
        Ok(records) => Outcome::ok(&records),
        Err(error) => host_local::error(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::status::{MVM_HOSTLIB_BACKEND, MVM_HOSTLIB_INVALID_INPUT, MVM_HOSTLIB_OK};

    #[test]
    fn checkpoint_list_requires_strict_empty_object() {
        for request in [
            b"".as_slice(),
            b"[]",
            b"[{}]",
            b"null",
            b"true",
            b"1",
            b"\"\"",
            b"{",
            br#"{"unexpected":true}"#,
            br#"{"unexpected":1,"unexpected":2}"#,
        ] {
            assert_eq!(dispatch(LIST, request).status, MVM_HOSTLIB_INVALID_INPUT);
        }
        assert_eq!(
            dispatch("checkpoint.remove", b"{}").status,
            MVM_HOSTLIB_INVALID_INPUT
        );
    }

    #[test]
    fn checkpoint_list_returns_exact_persisted_metadata_and_refuses_corruption() {
        let home = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());
        assert_eq!(dispatch(LIST, b"{}").body, b"[]");
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/checkpoint/catalog.json"
        ))
        .unwrap();
        for record in fixture.as_array().unwrap() {
            let dir = mvm_core::config::checkpoints_dir().join(record["id"].as_str().unwrap());
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("meta.json"), serde_json::to_vec(record).unwrap()).unwrap();
        }
        let outcome = dispatch(LIST, b" \n{} ");
        assert_eq!(outcome.status, MVM_HOSTLIB_OK);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&outcome.body).unwrap(),
            fixture
        );
        std::fs::write(
            mvm_core::config::checkpoints_dir().join("a/meta.json"),
            b"{}",
        )
        .unwrap();
        let failure = dispatch(LIST, b"{}");
        assert_eq!(failure.status, MVM_HOSTLIB_BACKEND);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&failure.body).unwrap()["retryable"],
            false
        );
    }
}
