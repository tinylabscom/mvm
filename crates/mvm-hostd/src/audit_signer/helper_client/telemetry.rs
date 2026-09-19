//! Deadline-bounded telemetry authentication through the resident signer.

use std::time::Duration;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use mvm_core::{
    net::telemetry::{TelemetryError, handshake_signing_bytes},
    protocol::{
        audit_signer::{SignerHelperRequest, SignerHelperResponse, SignerHelperSignHost},
        host_signer::{SignRequest, SignResponse, TelemetryHandshake},
    },
    security::{SIG_ALG_ED25519, SessionHello, SessionHelloAck},
};

use super::SignerHelperClient;

impl SignerHelperClient {
    /// Sign a validated telemetry handshake through the key-owning helper.
    /// One deadline covers connection, write and read. The timeout must be
    /// nonzero and at most 30 seconds. Refusals never include remote payloads.
    ///
    /// Cancellation drops the exclusively owned socket and leaves no task or
    /// thread behind. Call from the collector worker, never a trace producer.
    pub async fn sign_telemetry_handshake(
        &self,
        hello: &SessionHello,
        ack: &SessionHelloAck,
        host_key: &VerifyingKey,
        timeout: Duration,
    ) -> Result<Signature, TelemetryError> {
        if timeout.is_zero() || timeout > Duration::from_secs(30) {
            return Err(TelemetryError::Authentication);
        }
        tokio::time::timeout(timeout, async {
            let transcript = handshake_signing_bytes(hello, ack, host_key)?;
            let request_id = hello.session_id.clone();
            let request = SignerHelperRequest::SignHost(SignerHelperSignHost {
                request_id: request_id.clone(),
                request: SignRequest::SignTelemetryHandshake {
                    request_id: request_id.clone(),
                    handshake: Box::new(TelemetryHandshake {
                        hello: hello.clone(),
                        ack: ack.clone(),
                    }),
                },
            });
            let mut stream = tokio::net::UnixStream::connect(&self.uds_path)
                .await
                .map_err(|_| TelemetryError::Authentication)?;
            crate::framing::write_json_frame(&mut stream, &request)
                .await
                .map_err(|_| TelemetryError::Authentication)?;
            let response: SignerHelperResponse =
                crate::framing::read_json_frame(&mut stream, self.max_frame_bytes)
                    .await
                    .map_err(|_| TelemetryError::Authentication)?;
            verified_signature(response, &request_id, &transcript, host_key)
        })
        .await
        .map_err(|_| TelemetryError::Authentication)?
    }
}

fn verified_signature(
    response: SignerHelperResponse,
    request_id: &str,
    transcript: &[u8],
    host_key: &VerifyingKey,
) -> Result<Signature, TelemetryError> {
    let SignerHelperResponse::HostSigned {
        request_id: echoed,
        response,
    } = response
    else {
        return Err(TelemetryError::Authentication);
    };
    if echoed != request_id || response.request_id() != request_id {
        return Err(TelemetryError::Authentication);
    }
    let SignResponse::Ok {
        sig_alg,
        signature,
        signer_pubkey,
        ..
    } = response
    else {
        return Err(TelemetryError::Authentication);
    };
    if sig_alg != SIG_ALG_ED25519 || signer_pubkey != host_key.as_bytes() {
        return Err(TelemetryError::Authentication);
    }
    let signature =
        Signature::from_slice(&signature).map_err(|_| TelemetryError::Authentication)?;
    host_key
        .verify(transcript, &signature)
        .map_err(|_| TelemetryError::Authentication)?;
    Ok(signature)
}
