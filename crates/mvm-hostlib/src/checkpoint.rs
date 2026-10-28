//! Read-only checkpoint catalog access through the client-owned operation.

use mvm_client::checkpoint::Checkpoints;
use mvm_core::client::MvmError;

use crate::status::Outcome;

pub const LIST: &str = "checkpoint.list";
pub const METHODS: &[&str] = &[LIST];

pub fn is_known(method: &str) -> bool {
    METHODS.contains(&method)
}

pub(crate) fn dispatch(method: &str, request: &[u8]) -> Outcome {
    if method != LIST {
        return Outcome::invalid_input(&format!("unknown method `{method}`"));
    }
    // A derived empty struct also accepts an empty sequence. A map requires
    // the object representation advertised by the wire schema.
    let object: serde_json::Map<String, serde_json::Value> = match serde_json::from_slice(request) {
        Ok(object) => object,
        Err(error) => {
            return Outcome::invalid_input(&format!("invalid request JSON: {error}"));
        }
    };
    if !object.is_empty() {
        return Outcome::invalid_input("checkpoint.list request must be an empty object");
    }
    match Checkpoints::open().list() {
        Ok(records) => Outcome::ok(&records),
        Err(error) => Outcome::from(MvmError::Backend {
            reason: format!("{error:#}"),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use crate::status::MVM_HOSTLIB_OK;
    use crate::status::{MVM_HOSTLIB_BACKEND, MVM_HOSTLIB_INVALID_INPUT};

    #[test]
    fn only_an_empty_json_object_is_a_list_request() {
        for request in [
            b"".as_slice(),
            b"[]",
            b"null",
            b"false",
            b"42",
            b"\"text\"",
            b"{",
            b"{} {}",
            b"{\"unknown\":0}",
            b"{\"unknown\":0,\"unknown\":1}",
        ] {
            assert_eq!(
                dispatch(LIST, request).status,
                MVM_HOSTLIB_INVALID_INPUT,
                "request: {:?}",
                String::from_utf8_lossy(request)
            );
        }
        assert_eq!(
            dispatch("checkpoint.remove", b"{}").status,
            MVM_HOSTLIB_INVALID_INPUT
        );
        assert!(is_known(LIST));
        assert!(!is_known("checkpoint.remove"));
    }

    #[cfg(unix)]
    #[test]
    fn full_and_legacy_catalog_json_matches_the_client_without_projection() {
        let home = tempfile::tempdir().expect("home");
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());
        let empty = dispatch(LIST, b" { \n } ");
        assert_eq!(empty.status, MVM_HOSTLIB_OK);
        assert_eq!(empty.body, b"[]");

        let fixture: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../mvm-core/tests/fixtures/checkpoint-list.json"
        )))
        .expect("shared metadata fixture");
        let root = mvm_core::config::checkpoints_dir();
        for record in fixture.as_array().expect("record array").iter().rev() {
            let directory = root.join(record["id"].as_str().expect("record id"));
            std::fs::create_dir_all(&directory).expect("checkpoint directory");
            std::fs::write(
                directory.join("meta.json"),
                serde_json::to_vec(record).expect("record JSON"),
            )
            .expect("write record");
        }
        let client = Checkpoints::open().list().expect("client listing");
        let reply = dispatch(LIST, b"{}");
        assert_eq!(reply.status, MVM_HOSTLIB_OK);
        assert_eq!(
            reply.body,
            serde_json::to_vec(&client).expect("client JSON")
        );
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&reply.body).expect("reply JSON"),
            fixture
        );
    }

    #[test]
    fn catalog_refusal_keeps_the_client_error_and_backend_status() {
        let home = tempfile::tempdir().expect("home");
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());
        let directory = mvm_core::config::checkpoints_dir().join("broken");
        std::fs::create_dir_all(&directory).expect("checkpoint directory");
        std::fs::write(directory.join("meta.json"), b"{").expect("malformed record");
        let error = Checkpoints::open().list().expect_err("invalid metadata");
        let reply = dispatch(LIST, b"{}");
        assert_eq!(reply.status, MVM_HOSTLIB_BACKEND);
        let body: serde_json::Value = serde_json::from_slice(&reply.body).expect("error JSON");
        assert!(
            body["message"]
                .as_str()
                .expect("message")
                .contains(&format!("{error:#}"))
        );
        assert_eq!(body["retryable"], false);
    }
}
