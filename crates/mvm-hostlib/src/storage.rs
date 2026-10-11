//! Host-local thin-pool operations. No guest or runtime-driver inputs.

use crate::status::Outcome;
use mvm_client::storage::{self, GcRequest, InfoRequest};
use mvm_core::client::MvmError;

pub const INFO: &str = "storage.info";
pub const GC: &str = "storage.gc";
pub const METHODS: &[&str] = &[INFO, GC];

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
        INFO => {
            let request: InfoRequest = serde_json::from_slice(request).map_err(|error| {
                Outcome::invalid_input(&format!("invalid request JSON: {error}"))
            })?;
            crate::declared()?;
            storage::info(&request).map(|reply| Outcome::ok(&reply))
        }
        GC => {
            let request: GcRequest = serde_json::from_slice(request).map_err(|error| {
                Outcome::invalid_input(&format!("invalid request JSON: {error}"))
            })?;
            crate::declared()?;
            storage::gc(&request).map(|reply| Outcome::ok(&reply))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::status::MVM_HOSTLIB_INVALID_INPUT;

    #[test]
    fn strict_requests_and_mock_reports() {
        let home = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());
        for method in METHODS {
            for request in [
                b"null".as_slice(),
                br#"{"driver":"host"}"#,
                br#"{"mock":1}"#,
            ] {
                assert_eq!(dispatch(method, request).status, MVM_HOSTLIB_INVALID_INPUT);
            }
            let outcome = dispatch(method, br#"{"mock":true}"#);
            assert_eq!(outcome.status, 0);
            let body: serde_json::Value = serde_json::from_slice(&outcome.body).unwrap();
            if *method == GC {
                assert_eq!(body["applied"], false);
                assert_eq!(body["removed"], serde_json::json!([]));
            } else {
                assert_eq!(body["available"], false);
                assert!(body["reason"].is_string());
            }
        }
    }
}
