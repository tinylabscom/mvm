//! Shared wire decoding and cause-preserving host-local failure translation.

use crate::status::Outcome;
use mvm_core::client::MvmError;

pub(crate) fn parse<T: serde::de::DeserializeOwned>(request: &[u8]) -> Result<T, Outcome> {
    serde_json::from_slice(request)
        .map_err(|error| Outcome::invalid_input(&format!("invalid request JSON: {error}")))
}

pub(crate) fn error(error: anyhow::Error) -> Outcome {
    if let Some(typed) = error.downcast_ref::<MvmError>() {
        Outcome::failure(
            crate::status::status_of(typed),
            typed.code(),
            &format!("{error:#}"),
            typed.retryable(),
        )
    } else {
        Outcome::from(MvmError::Backend {
            reason: format!("{error:#}"),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_does_not_erase_typed_status_or_retryability() {
        let cause = MvmError::Unavailable {
            reason: "inner cause".into(),
        };
        let outcome = error(anyhow::Error::new(cause).context("outer operation"));
        assert_eq!(outcome.status, crate::status::MVM_HOSTLIB_UNAVAILABLE);
        let body: serde_json::Value = serde_json::from_slice(&outcome.body).unwrap();
        assert_eq!(body["retryable"], true);
        let message = body["message"].as_str().unwrap();
        assert!(message.contains("outer operation"));
        assert!(message.contains("inner cause"));
    }
}
