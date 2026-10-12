//! Built-manifest inspection over the shared client facade.
//!
//! These local registry operations need neither a running machine nor guest
//! helpers. Requests and reports are owned by the client, not re-modeled here.

use mvm_client::manifest::{self, InfoRequest, ListRequest, VerifyRequest};
use mvm_core::client::MvmError;

use crate::status::Outcome;

pub const LIST: &str = "manifest.list";
pub const INFO: &str = "manifest.info";
pub const VERIFY: &str = "manifest.verify";
pub const METHODS: &[&str] = &[LIST, INFO, VERIFY];

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
    fn only_the_listed_methods_are_known() {
        for method in METHODS {
            assert!(is_known(method));
        }
        assert!(!is_known("manifest.remove"));
        assert_eq!(
            dispatch("manifest.remove", b"{}").status,
            MVM_HOSTLIB_INVALID_INPUT
        );
    }
}
