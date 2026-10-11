//! Built-manifest inspection and explicit operations over the shared client facade.
//!
//! These are host-local operations, not guest verbs. Requests and reports are
//! owned by the client, not re-modeled here.

use mvm_client::manifest::{
    self, ExportOciRequest, InfoRequest, ListRequest, PruneRequest, RemoveRequest, VerifyRequest,
};
use mvm_core::client::MvmError;

use crate::status::Outcome;

pub const LIST: &str = "manifest.list";
pub const INFO: &str = "manifest.info";
pub const VERIFY: &str = "manifest.verify";
pub const REMOVE: &str = "manifest.remove";
pub const PRUNE: &str = "manifest.prune";
pub const EXPORT_OCI: &str = "manifest.export_oci";
pub const METHODS: &[&str] = &[LIST, INFO, VERIFY, REMOVE, PRUNE, EXPORT_OCI];

pub fn is_known(method: &str) -> bool {
    METHODS.contains(&method)
}

pub(crate) fn dispatch(method: &str, request: &[u8]) -> Outcome {
    match answer(method, request) {
        Ok(outcome) | Err(outcome) => outcome,
    }
}

fn answer(method: &str, request: &[u8]) -> Result<Outcome, Outcome> {
    match method {
        LIST => {
            let request: ListRequest = parse(request)?;
            manifest::list(&request).map(|reply| Outcome::ok(&reply))
        }
        INFO => {
            let request: InfoRequest = parse(request)?;
            manifest::info(&request).map(|reply| Outcome::ok(&reply))
        }
        VERIFY => {
            let request: VerifyRequest = parse(request)?;
            manifest::verify(&request).map(|reply| Outcome::ok(&reply))
        }
        REMOVE => {
            let request: RemoveRequest = parse(request)?;
            crate::declared()?;
            manifest::remove(&request).map(|reply| Outcome::ok(&reply))
        }
        PRUNE => {
            let request: PruneRequest = parse(request)?;
            crate::declared()?;
            manifest::prune(&request).map(|reply| Outcome::ok(&reply))
        }
        EXPORT_OCI => {
            let request: ExportOciRequest = parse(request)?;
            crate::declared()?;
            manifest::export_oci(&request).map(|reply| Outcome::ok(&reply))
        }
        _ => {
            return Err(Outcome::invalid_input(&format!(
                "unknown method `{method}`"
            )));
        }
    }
    .map_err(|error| {
        Outcome::from(MvmError::Backend {
            reason: format!("{error:#}"),
        })
    })
}

fn parse<T: serde::de::DeserializeOwned>(request: &[u8]) -> Result<T, Outcome> {
    serde_json::from_slice(request)
        .map_err(|error| Outcome::invalid_input(&format!("invalid request JSON: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::status::{MVM_HOSTLIB_BACKEND, MVM_HOSTLIB_INVALID_INPUT};

    #[test]
    fn requests_reject_unknown_fields_and_wrong_types() {
        for method in METHODS {
            for request in [br#"{"unexpected":true}"#.as_slice(), b"null", b"not json"] {
                assert_eq!(
                    dispatch(method, request).status,
                    MVM_HOSTLIB_INVALID_INPUT,
                    "{method}"
                );
            }
        }
        assert_eq!(
            dispatch(LIST, br#"{"orphans":"yes"}"#).status,
            MVM_HOSTLIB_INVALID_INPUT
        );
    }

    #[test]
    fn signature_refusal_preserves_the_facade_error_chain() {
        let request = br#"{"check_signature":true}"#;
        let error = manifest::verify(&serde_json::from_slice(request).unwrap()).unwrap_err();
        let outcome = dispatch(VERIFY, request);
        assert_eq!(outcome.status, MVM_HOSTLIB_BACKEND);
        let body: serde_json::Value = serde_json::from_slice(&outcome.body).unwrap();
        assert!(
            body["message"]
                .as_str()
                .unwrap()
                .contains(&format!("{error:#}"))
        );
        assert_eq!(body["retryable"], false);
    }

    #[test]
    fn missing_manifest_preserves_the_facade_error_chain() {
        let dir = tempfile::tempdir().unwrap();
        let request = serde_json::json!({"path": dir.path().join("absent.toml")});
        let bytes = serde_json::to_vec(&request).unwrap();
        let error = manifest::info(&serde_json::from_slice(&bytes).unwrap()).unwrap_err();
        let outcome = dispatch(INFO, &bytes);
        assert_eq!(outcome.status, MVM_HOSTLIB_BACKEND);
        let body: serde_json::Value = serde_json::from_slice(&outcome.body).unwrap();
        assert!(
            body["message"]
                .as_str()
                .unwrap()
                .contains(&format!("{error:#}"))
        );
    }

    #[test]
    fn prune_defaults_to_preview_and_does_not_delete_candidates() {
        let home = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());
        let key = "a".repeat(64);
        let slot = mvm_core::manifest::slot_dir(&key);
        std::fs::create_dir_all(&slot).unwrap();
        std::fs::write(
            std::path::Path::new(&slot).join("manifest.json"),
            b"invalid",
        )
        .unwrap();
        let outcome = dispatch(PRUNE, br#"{"orphans":true}"#);
        assert_eq!(outcome.status, 0);
        let body: serde_json::Value = serde_json::from_slice(&outcome.body).unwrap();
        assert_eq!(body["dry_run"], true);
        assert_eq!(body["candidates"][0]["slot_hash"], key);
        assert_eq!(body["removed_count"], 0);
        assert!(std::path::Path::new(&slot).join("manifest.json").exists());
    }

    #[test]
    fn mutation_failures_preserve_client_error_chains() {
        let home = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());
        let missing = home.path().join("missing.toml");
        let remove = serde_json::json!({"path": missing});
        let export =
            serde_json::json!({"template": "missing", "out": home.path().join("image.tar.gz")});
        for (method, request, error) in [
            (
                REMOVE,
                remove.clone(),
                manifest::remove(&serde_json::from_value(remove).unwrap()).unwrap_err(),
            ),
            (
                PRUNE,
                serde_json::json!({}),
                manifest::prune(&PruneRequest::default()).unwrap_err(),
            ),
            (
                EXPORT_OCI,
                export.clone(),
                manifest::export_oci(&serde_json::from_value(export).unwrap()).unwrap_err(),
            ),
        ] {
            let outcome = dispatch(method, &serde_json::to_vec(&request).unwrap());
            assert_eq!(outcome.status, MVM_HOSTLIB_BACKEND);
            let body: serde_json::Value = serde_json::from_slice(&outcome.body).unwrap();
            assert!(
                body["message"]
                    .as_str()
                    .unwrap()
                    .contains(&format!("{error:#}"))
            );
        }
    }

    #[test]
    fn only_the_listed_methods_are_known() {
        for method in METHODS {
            assert!(is_known(method));
        }
        assert!(!is_known("manifest.unknown"));
        assert_eq!(
            dispatch("manifest.unknown", b"{}").status,
            MVM_HOSTLIB_INVALID_INPUT
        );
    }
}
