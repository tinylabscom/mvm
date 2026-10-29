//! Shared bounded host-local request/error boundary, independent of machines.

use mvm_core::client::MvmError;

use crate::status::Outcome;

pub(crate) fn parse<T: serde::de::DeserializeOwned>(request: &[u8]) -> Result<T, Outcome> {
    if request
        .iter()
        .find(|byte| !matches!(**byte, b' ' | b'\n' | b'\r' | b'\t'))
        != Some(&b'{')
    {
        return Err(Outcome::invalid_input(
            "expected a host-local request object",
        ));
    }
    // Deserialize directly: a Value intermediary would discard duplicate fields.
    serde_json::from_slice(request)
        .map_err(|_| Outcome::invalid_input("invalid host-local request JSON"))
}

pub(crate) fn error(error: anyhow::Error) -> Outcome {
    // Context must not erase a typed client error or its recovery details.
    if let Some(typed) = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<MvmError>())
    {
        return Outcome::from(typed.clone());
    }
    // Unclassified errors can carry parser diagnostics from signed file inputs.
    // Do not turn those input bytes into a transport diagnostic.
    Outcome::from(MvmError::Backend {
        reason: "host-local operation failed".into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_preserves_typed_recovery_without_parsing_messages() {
        let failure = MvmError::RecoveryRequired {
            machine_id: "machine".into(),
            plan_id: "plan".into(),
            reason: "explicit recovery required".into(),
        };
        let direct = Outcome::from(failure.clone());
        let contextual = error(anyhow::Error::new(failure).context("outer context"));
        assert_eq!(contextual.status, 12);
        assert_eq!(contextual.body, direct.body);
    }

    #[test]
    fn parser_diagnostics_are_not_transport_payloads() {
        let marker = "private-request-must-not-be-logged";
        let bytes = serde_json::to_vec(marker).unwrap();
        let outcome = parse::<crate::attestation::AttestationEmpty>(&bytes).unwrap_err();
        assert!(!String::from_utf8(outcome.body).unwrap().contains(marker));
        let outcome = error(anyhow::anyhow!(marker));
        assert!(!String::from_utf8(outcome.body).unwrap().contains(marker));
    }
}
