//! Hardware attestation providers.
//!
//! Each provider implements [`HwAttestationProvider`] and returns an opaque
//! [`HwMeasurement`] that the host can embed in an [`AttestationReport`].
//! The only hardware backend is TPM2, behind the `attestation-tpm2` feature.

use crate::crypto::attestation::error::AttestationError;
use serde::{Deserialize, Serialize};

/// Identifies a hardware attestation backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum HwProviderKind {
    /// Discrete or firmware TPM2.
    Tpm2,
}

impl HwProviderKind {
    /// Return the snake_case identifier for this provider.
    pub fn as_str(&self) -> &'static str {
        match self {
            HwProviderKind::Tpm2 => "tpm2",
        }
    }

    /// Return the cargo feature that enables this provider.
    pub fn cargo_feature(&self) -> &'static str {
        match self {
            HwProviderKind::Tpm2 => "mvm-core/attestation-tpm2",
        }
    }

    /// Return whether this provider is compiled into the current binary.
    pub fn compiled_in(&self) -> bool {
        match self {
            HwProviderKind::Tpm2 => cfg!(all(target_os = "linux", feature = "attestation-tpm2")),
        }
    }
}

impl std::fmt::Display for HwProviderKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Opaque measurement returned by a hardware provider.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HwMeasurement {
    /// Provider that produced this measurement.
    pub provider: HwProviderKind,
    /// Hex-encoded opaque measurement payload. Format is provider-specific
    /// and interpreted by the verifier.
    pub measurement_hex: String,
}

/// Trait implemented by every hardware attestation backend.
pub trait HwAttestationProvider {
    /// Provider discriminant.
    fn kind(&self) -> HwProviderKind;

    /// Generate a hardware measurement.
    ///
    /// Failures are reported as [`AttestationError::MeasurementFailed`]
    /// (environmental problems such as a missing TPM).
    fn measure(&self) -> Result<HwMeasurement, AttestationError>;
}

// ---------------------------------------------------------------------------
// TPM2
// ---------------------------------------------------------------------------

/// TPM2 attestation provider. On Linux with `attestation-tpm2` this delegates
/// to the real `tss-esapi` implementation; on other platforms it returns
/// [`AttestationError::MeasurementFailed`].
#[cfg(all(target_os = "linux", feature = "attestation-tpm2"))]
#[derive(Debug, Default)]
pub struct Tpm2Provider;

#[cfg(all(target_os = "linux", feature = "attestation-tpm2"))]
impl HwAttestationProvider for Tpm2Provider {
    fn kind(&self) -> HwProviderKind {
        HwProviderKind::Tpm2
    }
    fn measure(&self) -> Result<HwMeasurement, AttestationError> {
        super::tpm2::Tpm2Provider.measure()
    }
}

#[cfg(all(not(target_os = "linux"), feature = "attestation-tpm2"))]
#[derive(Debug, Default)]
pub struct Tpm2Provider;

#[cfg(all(not(target_os = "linux"), feature = "attestation-tpm2"))]
impl HwAttestationProvider for Tpm2Provider {
    fn kind(&self) -> HwProviderKind {
        HwProviderKind::Tpm2
    }
    fn measure(&self) -> Result<HwMeasurement, AttestationError> {
        Err(AttestationError::MeasurementFailed {
            provider: HwProviderKind::Tpm2,
            message: "TPM2 attestation is only available on Linux".to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_kind_as_str_is_snake_case() {
        assert_eq!(HwProviderKind::Tpm2.as_str(), "tpm2");
    }

    #[test]
    fn provider_kind_display_matches_as_str() {
        assert_eq!(
            HwProviderKind::Tpm2.to_string(),
            HwProviderKind::Tpm2.as_str()
        );
    }

    #[test]
    fn provider_kind_cargo_feature_names_workspace_feature() {
        assert_eq!(
            HwProviderKind::Tpm2.cargo_feature(),
            "mvm-core/attestation-tpm2"
        );
    }

    #[test]
    fn compiled_in_reflects_platform_and_features() {
        // TPM2 is only compiled on Linux with the attestation-tpm2 feature.
        #[cfg(all(target_os = "linux", feature = "attestation-tpm2"))]
        assert!(HwProviderKind::Tpm2.compiled_in());
        #[cfg(not(all(target_os = "linux", feature = "attestation-tpm2")))]
        assert!(!HwProviderKind::Tpm2.compiled_in());
    }

    #[cfg(all(not(target_os = "linux"), feature = "attestation-tpm2"))]
    #[test]
    fn tpm2_stub_returns_measurement_failed_on_non_linux() {
        let err = Tpm2Provider.measure().unwrap_err();
        match err {
            AttestationError::MeasurementFailed { provider, message } => {
                assert_eq!(provider, HwProviderKind::Tpm2);
                assert!(message.contains("only available on Linux"));
            }
            other => panic!("expected MeasurementFailed, got {other:?}"),
        }
    }

    #[test]
    fn hw_measurement_serde_roundtrip() {
        let original = HwMeasurement {
            provider: HwProviderKind::Tpm2,
            measurement_hex: "DEADBEEF".to_string(),
        };
        let json = serde_json::to_string(&original).expect("serialize");
        let roundtrip: HwMeasurement = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(original, roundtrip);
    }
}
