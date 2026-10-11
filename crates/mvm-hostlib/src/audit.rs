//! Verified audit session queries and configured-host posture inspection.

use crate::{
    host_local::{error, parse},
    status::Outcome,
};
use mvm_client::audit::{posture, sessions};
use serde::{Deserialize, Serialize};

pub const LIST: &str = "audit.sessions.list";
pub const SHOW: &str = "audit.sessions.show";
pub const VERIFY: &str = "audit.sessions.verify";
pub const POSTURE: &str = "posture.inspect";
pub const METHODS: &[&str] = &[LIST, SHOW, VERIFY, POSTURE];

#[derive(Debug, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct PostureRequest {}

pub(crate) fn dispatch(method: &str, request: &[u8]) -> Outcome {
    match answer(method, request) {
        Ok(outcome) | Err(outcome) => outcome,
    }
}

fn answer(method: &str, request: &[u8]) -> Result<Outcome, Outcome> {
    match method {
        LIST => {
            let request: sessions::ListRequest = parse(request)?;
            sessions::list(&request)
                .map(|reply| Outcome::ok(&reply))
                .map_err(error)
        }
        SHOW => {
            let request: sessions::ShowRequest = parse(request)?;
            sessions::show(&request)
                .map(|reply| Outcome::ok(&reply))
                .map_err(error)
        }
        VERIFY => {
            let request: sessions::VerifyRequest = parse(request)?;
            sessions::verify(&request)
                .map(|reply| Outcome::ok(&reply))
                .map_err(error)
        }
        POSTURE => {
            let _: PostureRequest = parse(request)?;
            let home = mvm_core::config::mvm_home();
            Ok(Outcome::ok(&posture::build_report(Some(
                std::path::Path::new(&home),
            ))))
        }
        _ => Err(Outcome::invalid_input("unknown audit method")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_requests_absent_chain_and_configured_posture() {
        let home = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());
        for method in METHODS {
            for body in [
                b"null".as_slice(),
                br#"{"pubkey":"untrusted"}"#,
                br#"{"root":"/tmp"}"#,
            ] {
                assert_eq!(
                    dispatch(method, body).status,
                    crate::status::MVM_HOSTLIB_INVALID_INPUT
                );
            }
        }
        assert_eq!(
            dispatch(LIST, br#"{"range":{"unknown":1}}"#).status,
            crate::status::MVM_HOSTLIB_INVALID_INPUT
        );
        let outcome = dispatch(LIST, b"{}");
        assert_eq!(
            outcome.status,
            0,
            "{}",
            String::from_utf8_lossy(&outcome.body)
        );
        let body: serde_json::Value = serde_json::from_slice(&outcome.body).unwrap();
        assert_eq!(body["sessions"], serde_json::json!([]));
        assert!(body["ledger"].is_null());
        let outcome = dispatch(VERIFY, br#"{"selector":"sha256:abcdef01"}"#);
        assert_eq!(outcome.status, 0);
        let body: serde_json::Value = serde_json::from_slice(&outcome.body).unwrap();
        assert_eq!(body["verdict"], "NOT_FOUND");
        assert_eq!(dispatch(POSTURE, b"{}").status, 0);
        assert!(!home.path().join("keys/host-signer.ed25519").exists());
    }
}
