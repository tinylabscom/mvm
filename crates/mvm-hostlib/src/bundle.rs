//! Signed host-local exports; signing keys never cross the ABI.

use crate::status::Outcome;
use mvm_core::client::MvmError;

pub const EXPORT: &str = "bundle.export";
pub const METHODS: &[&str] = &[EXPORT];

pub fn is_known(method: &str) -> bool {
    METHODS.contains(&method)
}

pub(crate) fn dispatch(method: &str, request: &[u8]) -> Outcome {
    if !is_known(method) {
        return Outcome::invalid_input(&format!("unknown method `{method}`"));
    }
    let request: mvm_client::bundle::ExportRequest = match serde_json::from_slice(request) {
        Ok(request) => request,
        Err(error) => {
            return Outcome::invalid_input(&format!("invalid request JSON: {error}"));
        }
    };
    if let Err(outcome) = crate::declared() {
        return outcome;
    }
    match mvm_client::bundle::export(&request) {
        Ok(reply) => Outcome::ok(&reply),
        Err(error) => Outcome::from(MvmError::Backend {
            reason: format!("{error:#}"),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::status::{MVM_HOSTLIB_BACKEND, MVM_HOSTLIB_INVALID_INPUT};

    #[test]
    fn rejects_private_keys_and_unknown_posture_fields() {
        for extra in [
            serde_json::json!({"private_key": "not-a-key"}),
            serde_json::json!({"posture": {"profile": "dev", "driver": "host"}}),
        ] {
            let mut request = serde_json::json!({"template": "missing", "out": "out.mvmpkg"});
            request
                .as_object_mut()
                .unwrap()
                .extend(extra.as_object().unwrap().clone());
            assert_eq!(
                dispatch(EXPORT, &serde_json::to_vec(&request).unwrap()).status,
                MVM_HOSTLIB_INVALID_INPUT
            );
        }
    }

    #[test]
    fn missing_artifact_preserves_error_chain() {
        let home = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());
        let request =
            serde_json::json!({"template": "missing", "out": home.path().join("out.mvmpkg")});
        let error = mvm_client::bundle::export(&serde_json::from_value(request.clone()).unwrap())
            .unwrap_err();
        let outcome = dispatch(EXPORT, &serde_json::to_vec(&request).unwrap());
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
