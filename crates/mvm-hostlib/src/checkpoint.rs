//! Host-local checkpoint operations through the client-owned service.

use mvm_client::checkpoint::Checkpoints;
use mvm_core::checkpoint::CheckpointId;

use crate::{host_local, status::Outcome};

pub const LIST: &str = "checkpoint.list";
pub const REMOVE: &str = "checkpoint.remove";
pub const METHODS: &[&str] = &[LIST, REMOVE];

/// Listing has no filters; reject unknown fields rather than silently ignoring them.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ListRequest {}

/// A host-local checkpoint ID, with no force or storage-root override.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CheckpointRemoveRequest {
    id: String,
}

pub fn is_known(method: &str) -> bool {
    METHODS.contains(&method)
}

pub(crate) fn dispatch(method: &str, request: &[u8]) -> Outcome {
    match method {
        LIST => {
            if let Err(outcome) = host_local::parse::<ListRequest>(request) {
                return outcome;
            }
            match Checkpoints::open().list() {
                Ok(records) => Outcome::ok(&records),
                Err(error) => host_local::error(error),
            }
        }
        REMOVE => {
            let request = match host_local::parse::<CheckpointRemoveRequest>(request) {
                Ok(request) => request,
                Err(outcome) => return outcome,
            };
            match Checkpoints::open().remove(&CheckpointId::new(request.id)) {
                Ok(()) => Outcome::ok(&crate::dispatch::Empty {}),
                Err(error) => host_local::error(error),
            }
        }
        _ => Outcome::invalid_input("unknown checkpoint method"),
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
            dispatch("checkpoint.unknown", b"{}").status,
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

    fn seed_checkpoint(
        id: &str,
        parent: Option<&mvm_core::checkpoint::CheckpointMeta>,
    ) -> mvm_core::checkpoint::CheckpointMeta {
        let meta = mvm_core::checkpoint::CheckpointMeta::builder(
            mvm_core::checkpoint::CheckpointId::new(id),
            mvm_core::checkpoint::CheckpointClass::FsQuick,
            "vm",
        )
        .parent(parent.map(|record| record.meta_digest.clone()))
        .build();
        let directory = mvm_core::config::checkpoints_dir().join(id);
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(
            directory.join("meta.json"),
            serde_json::to_vec(&meta).unwrap(),
        )
        .unwrap();
        meta
    }

    #[test]
    fn checkpoint_remove_is_strict_and_preserves_error_mapping() {
        use crate::status::{MVM_HOSTLIB_CONFLICT, MVM_HOSTLIB_INVALID_SPEC};

        let home = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());
        for request in [
            b"{}".as_slice(),
            b"null",
            br#"{"id":"target","force":true}"#,
            br#"{"id":"target","root":"/outside"}"#,
            br#"{"id":"target","id":"other"}"#,
        ] {
            assert_eq!(
                dispatch("checkpoint.remove", request).status,
                MVM_HOSTLIB_INVALID_INPUT
            );
        }
        assert_eq!(
            dispatch("checkpoint.remove", br#"{"id":"../outside"}"#).status,
            MVM_HOSTLIB_INVALID_SPEC
        );
        let parent = seed_checkpoint("parent", None);
        seed_checkpoint("child", Some(&parent));
        let refusal = dispatch("checkpoint.remove", br#"{"id":"parent"}"#);
        assert_eq!(refusal.status, MVM_HOSTLIB_CONFLICT);
        let body: serde_json::Value = serde_json::from_slice(&refusal.body).unwrap();
        assert_eq!(body["code"], "CONFLICT");
        assert_eq!(body["retryable"], false);
        assert!(
            mvm_core::config::checkpoints_dir()
                .join("parent/meta.json")
                .is_file()
        );
        for id in ["child", "parent", "absent"] {
            let request = serde_json::to_vec(&serde_json::json!({"id": id})).unwrap();
            let outcome = dispatch("checkpoint.remove", &request);
            assert_eq!(outcome.status, MVM_HOSTLIB_OK);
            assert_eq!(outcome.body, b"{}");
        }
    }

    #[test]
    fn checkpoint_remove_refuses_metadata_and_pin_lookup_failures_without_leaking_payloads() {
        for id in ["corrupt", "incomplete", "pin-lookup"] {
            let home = tempfile::tempdir().unwrap();
            let mut env = mvm_core::util::test_env::TestEnv::new();
            env.isolate_mvm_home(home.path());
            let checkpoint = seed_checkpoint(id, None);
            let meta = mvm_core::config::checkpoints_dir()
                .join(id)
                .join("meta.json");
            match id {
                "corrupt" => {
                    let mut record = serde_json::to_value(checkpoint).unwrap();
                    record["class"] = serde_json::json!("private-checkpoint-payload");
                    let parse_error =
                        serde_json::from_value::<mvm_core::checkpoint::CheckpointMeta>(
                            record.clone(),
                        )
                        .unwrap_err();
                    assert!(
                        parse_error
                            .to_string()
                            .contains("private-checkpoint-payload")
                    );
                    std::fs::write(&meta, serde_json::to_vec(&record).unwrap()).unwrap();
                }
                "incomplete" => std::fs::remove_file(&meta).unwrap(),
                _ => std::fs::create_dir_all(
                    mvm_core::config::agent_sessions_dir().join("sess-incomplete"),
                )
                .unwrap(),
            }
            let request = serde_json::to_vec(&serde_json::json!({"id": id})).unwrap();
            let outcome = dispatch("checkpoint.remove", &request);
            assert_eq!(outcome.status, MVM_HOSTLIB_BACKEND);
            let body: serde_json::Value = serde_json::from_slice(&outcome.body).unwrap();
            assert_eq!(body["code"], "BACKEND_ERROR");
            assert_eq!(body["retryable"], false);
            assert!(
                !String::from_utf8(outcome.body)
                    .unwrap()
                    .contains("private-checkpoint-payload")
            );
            assert!(meta.parent().unwrap().is_dir());
        }
    }

    #[test]
    fn checkpoint_remove_keeps_session_pinned_content() {
        let home = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());
        let meta = seed_checkpoint("pinned", None);
        let session = mvm_core::config::agent_sessions_dir().join("sess-pinned");
        std::fs::create_dir_all(&session).unwrap();
        std::fs::write(
            session.join("session.json"),
            serde_json::to_vec(&serde_json::json!({
                "session_id": "sess-pinned", "generation": 1, "state": "hibernated",
                "members": ["vm"], "parent_checkpoint": meta.meta_digest,
                "created_unix": 0, "updated_unix": 0, "journal_cursor": 0,
                "approval_head": null, "storage_tier": null, "park_reason": null,
                "retain_until_unix": null, "last_transition": null
            }))
            .unwrap(),
        )
        .unwrap();
        let outcome = dispatch("checkpoint.remove", br#"{"id":"pinned"}"#);
        assert_eq!(outcome.status, crate::status::MVM_HOSTLIB_CONFLICT);
        assert!(
            mvm_core::config::checkpoints_dir()
                .join("pinned/meta.json")
                .is_file()
        );
    }

    #[test]
    fn checkpoint_remove_refuses_a_sibling_with_missing_metadata() {
        let home = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());
        let parent = seed_checkpoint("parent", None);
        seed_checkpoint("child", Some(&parent));
        let root = mvm_core::config::checkpoints_dir();
        std::fs::write(root.join("child/keep"), b"child content").unwrap();
        std::fs::remove_file(root.join("child/meta.json")).unwrap();
        let outcome = dispatch("checkpoint.remove", br#"{"id":"parent"}"#);
        assert_eq!(outcome.status, MVM_HOSTLIB_BACKEND);
        assert!(root.join("parent/meta.json").is_file());
        assert_eq!(
            std::fs::read(root.join("child/keep")).unwrap(),
            b"child content"
        );
    }
}
