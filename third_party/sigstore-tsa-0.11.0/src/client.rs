//! TSA client for RFC 3161 Time-Stamp Protocol

use crate::asn1::{AlgorithmIdentifier, Asn1MessageImprint, TimeStampReq};
use crate::error::{Error, Result};
use sigstore_types::SignatureBytes;
use sigstore_types::TimestampToken;

/// A client for interacting with a Time-Stamp Authority
pub struct TimestampClient {
    /// Base URL of the TSA
    url: String,
    /// HTTP client
    client: reqwest::Client,
}

impl TimestampClient {
    /// Create a new TSA client
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            client: reqwest::Client::new(),
        }
    }

    /// Create a client for the Sigstore TSA
    pub fn sigstore() -> Self {
        Self::new("https://timestamp.sigstore.dev/api/v1/timestamp")
    }

    /// Create a client for the FreeTSA service
    pub fn freetsa() -> Self {
        Self::new("https://freetsa.org/tsr")
    }

    /// Request a timestamp for the given digest
    ///
    /// # Arguments
    /// * `digest` - The hash digest to timestamp
    /// * `algorithm` - The hash algorithm used
    ///
    /// # Returns
    /// The timestamp token (DER-encoded RFC 3161 response)
    async fn timestamp(
        &self,
        digest: &[u8],
        algorithm: AlgorithmIdentifier,
    ) -> Result<TimestampToken> {
        // Build the timestamp request
        let imprint = Asn1MessageImprint::new(algorithm, digest.to_vec());
        let request = TimeStampReq::new(imprint);

        // Encode to DER
        let request_der = request
            .to_der()
            .map_err(|e| Error::Asn1(format!("failed to encode request: {}", e)))?;

        // Send HTTP request
        let response = self
            .client
            .post(&self.url)
            .header("Content-Type", "application/timestamp-query")
            .body(request_der)
            .send()
            .await
            .map_err(|e| Error::Http(e.to_string()))?;

        if !response.status().is_success() {
            return Err(Error::Http(format!(
                "TSA returned status {}",
                response.status()
            )));
        }

        // Get response bytes
        let response_bytes = response
            .bytes()
            .await
            .map_err(|e| Error::Http(e.to_string()))?;

        // Parse the response and extract TstInfo
        let (tst_info, _) = crate::verify::parse_timestamp_token(&response_bytes)?;

        // Verify the nonce matches the request nonce
        if let Some(req_nonce) = &request.nonce {
            if tst_info.nonce.as_ref() != Some(req_nonce) {
                return Err(Error::InvalidResponse(format!(
                    "TSA response nonce mismatch: expected {:?}, got {:?}",
                    req_nonce, tst_info.nonce
                )));
            }
        }

        // Return the timestamp token
        Ok(TimestampToken::new(response_bytes.to_vec()))
    }

    /// Request a timestamp for a signature
    ///
    /// This is the most common use case - timestamps the SHA-256 hash of the signature bytes.
    pub async fn timestamp_signature(&self, signature: &SignatureBytes) -> Result<TimestampToken> {
        let digest = sigstore_crypto::sha256(signature.as_bytes());
        self.timestamp(digest.as_bytes(), AlgorithmIdentifier::sha256())
            .await
    }
}
