//! Verified, one-shot session replay without exporting prepared handles or inputs.

use crate::{
    host_local::{error, parse},
    status::Outcome,
};
use mvm_client::{checkpoint::wire, replay::ReplayService};

pub const METHODS: &[&str] = &["replay.run_session"];

pub(crate) fn dispatch(request: &[u8]) -> Outcome {
    match answer(request) {
        Ok(outcome) | Err(outcome) => outcome,
    }
}

fn answer(request: &[u8]) -> Result<Outcome, Outcome> {
    let request: wire::ReplayRequest = parse(request)?;
    crate::declared()?;
    ReplayService::open()
        .run_session(
            &request.into(),
            &mut mvm_client::entrypoint::CapturedOutput::default(),
        )
        .map(|reply| Outcome::ok(&reply))
        .map_err(error)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preview_default_and_nested_privilege_refusal() {
        let body =
            br#"{"selection":{"session_id":"Not A Session"},"timeout_secs":1,"tenant":"local"}"#;
        let request: wire::ReplayRequest = serde_json::from_slice(body).unwrap();
        assert!(request.dry_run);
        let home = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());
        let outcome = dispatch(body);
        assert_ne!(outcome.status, 0);
        assert!(String::from_utf8_lossy(&outcome.body).contains("session"));
        assert_eq!(
            dispatch(
                br#"{"selection":{"session_id":"valid","nonce":"chosen"},
            "timeout_secs":1,"tenant":"local"}"#
            )
            .status,
            crate::status::MVM_HOSTLIB_INVALID_INPUT
        );
    }
}
