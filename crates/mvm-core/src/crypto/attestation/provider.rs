//! Plan 60 Phase 6 — hardware attestation provider stubs.
//!
//! Three feature-gated providers reserve the API surface for real
//! hardware integrations landing post-Phase-6:
//!
//! - `attestation-tpm2`     — TPM2 quote (Linux/Windows hosts with a
//!   TPM). Real impl pulls in `tss-esapi`.
//! - `attestation-sev-snp`  — AMD SEV-SNP attestation report.
//! - `attestation-tdx`      — Intel TDX attestation report.
//!
//! When a feature is disabled, the corresponding provider type is
//! not compiled in at all, so the supervisor can statically reason
//! about which hardware backends a given build supports: a tenant
//! policy that demands `AttestationMode::Tpm2` from a binary built
//! without `attestation-tpm2` is refused at admission rather than
//! silently downgraded.
//!
//! For v0, every wired provider's `measure()` returns
//! `AttestationError::NotYetImplemented`. The real bring-up work is
//! sequenced post-Phase-6 when the hosted mvmd cloud needs hardware
//! attestation for compliance (plan 60 §"Hardware attestation
//! everywhere", tier 5).

use crate::crypto::attestation::error::AttestationError;
use serde::{Deserialize, Serialize};

/// Discriminant for the three hardware attestation backends. Stable
/// across crate versions because it's part of the wire format and the
/// `mvmctl attest` CLI surface — adding a new variant is a
/// `#[non_exhaustive]` extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum HwProviderKind {
    Tpm2,
    SevSnp,
    Tdx,
}

impl HwProviderKind {
    pub fn as_str(self) -> &'static str {
        match self {
            HwProviderKind::Tpm2 => "tpm2",
            HwProviderKind::SevSnp => "sev_snp",
            HwProviderKind::Tdx => "tdx",
        }
    }

    /// Cargo feature flag that gates this provider. The supervisor
    /// uses this to render the operator-facing "this build was
    /// compiled without `feature = …`" refusal message when a
    /// tenant policy demands a mode the binary cannot satisfy.
    pub fn cargo_feature(self) -> &'static str {
        match self {
            HwProviderKind::Tpm2 => "attestation-tpm2",
            HwProviderKind::SevSnp => "attestation-sev-snp",
            HwProviderKind::Tdx => "attestation-tdx",
        }
    }

    /// Whether this build was compiled with the provider's feature
    /// enabled. Used at admission time so the supervisor can refuse
    /// a plan demanding a mode the binary cannot honor.
    pub fn compiled_in(self) -> bool {
        match self {
            HwProviderKind::Tpm2 => cfg!(feature = "attestation-tpm2"),
            HwProviderKind::SevSnp => cfg!(feature = "attestation-sev-snp"),
            HwProviderKind::Tdx => cfg!(feature = "attestation-tdx"),
        }
    }
}

/// A single hardware-measurement payload. Opaque bytes — providers
/// keep their native quote/report format so verifiers downstream
/// (mvmd, customer auditors) can apply provider-specific parsing
/// without forcing this crate to take a dep on every quote parser.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HwMeasurement {
    pub provider: HwProviderKind,
    /// Hex-encoded provider-native quote/report bytes.
    pub measurement_hex: String,
}

/// The trait every hardware backend implements.
///
/// `measure()` is fallible because real hardware can refuse to quote
/// (TPM in failure mode, SEV-SNP not initialised, etc.). For v0 each
/// stub returns `NotYetImplemented`.
pub trait HwAttestationProvider: Send + Sync {
    fn kind(&self) -> HwProviderKind;
    fn measure(&self) -> Result<HwMeasurement, AttestationError>;
}

// ---------------------------------------------------------------------------
// TPM2 stub
// ---------------------------------------------------------------------------

/// TPM2 attestation provider. Stub — real impl will wrap `tss-esapi`.
#[cfg(feature = "attestation-tpm2")]
#[derive(Debug, Default)]
pub struct Tpm2Provider;

#[cfg(feature = "attestation-tpm2")]
impl HwAttestationProvider for Tpm2Provider {
    fn kind(&self) -> HwProviderKind {
        HwProviderKind::Tpm2
    }
    fn measure(&self) -> Result<HwMeasurement, AttestationError> {
        Err(AttestationError::NotYetImplemented(HwProviderKind::Tpm2))
    }
}

// ---------------------------------------------------------------------------
// AMD SEV-SNP stub
// ---------------------------------------------------------------------------

#[cfg(feature = "attestation-sev-snp")]
#[derive(Debug, Default)]
pub struct SevSnpProvider;

#[cfg(feature = "attestation-sev-snp")]
impl HwAttestationProvider for SevSnpProvider {
    fn kind(&self) -> HwProviderKind {
        HwProviderKind::SevSnp
    }
    fn measure(&self) -> Result<HwMeasurement, AttestationError> {
        Err(AttestationError::NotYetImplemented(HwProviderKind::SevSnp))
    }
}

// ---------------------------------------------------------------------------
// Intel TDX stub
// ---------------------------------------------------------------------------

#[cfg(feature = "attestation-tdx")]
#[derive(Debug, Default)]
pub struct TdxProvider;

#[cfg(feature = "attestation-tdx")]
impl HwAttestationProvider for TdxProvider {
    fn kind(&self) -> HwProviderKind {
        HwProviderKind::Tdx
    }
    fn measure(&self) -> Result<HwMeasurement, AttestationError> {
        Err(AttestationError::NotYetImplemented(HwProviderKind::Tdx))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_strings_are_stable_wire_values() {
        assert_eq!(HwProviderKind::Tpm2.as_str(), "tpm2");
        assert_eq!(HwProviderKind::SevSnp.as_str(), "sev_snp");
        assert_eq!(HwProviderKind::Tdx.as_str(), "tdx");
    }

    #[test]
    fn cargo_feature_names_match_workspace_features() {
        assert_eq!(HwProviderKind::Tpm2.cargo_feature(), "attestation-tpm2");
        assert_eq!(
            HwProviderKind::SevSnp.cargo_feature(),
            "attestation-sev-snp"
        );
        assert_eq!(HwProviderKind::Tdx.cargo_feature(), "attestation-tdx");
    }

    #[test]
    fn compiled_in_reports_feature_cfg() {
        // Whatever cfg the test run was compiled under, compiled_in()
        // must match the corresponding cfg!(feature = ...). We assert
        // this against the same cfg!() so the test is consistent
        // across any feature combination CI exercises.
        assert_eq!(
            HwProviderKind::Tpm2.compiled_in(),
            cfg!(feature = "attestation-tpm2")
        );
        assert_eq!(
            HwProviderKind::SevSnp.compiled_in(),
            cfg!(feature = "attestation-sev-snp")
        );
        assert_eq!(
            HwProviderKind::Tdx.compiled_in(),
            cfg!(feature = "attestation-tdx")
        );
    }

    #[test]
    fn hw_measurement_round_trips_json() {
        let m = HwMeasurement {
            provider: HwProviderKind::Tpm2,
            measurement_hex: "deadbeef".to_string(),
        };
        let s = serde_json::to_string(&m).unwrap();
        let back: HwMeasurement = serde_json::from_str(&s).unwrap();
        assert_eq!(back, m);
    }

    #[cfg(feature = "attestation-tpm2")]
    #[test]
    fn tpm2_stub_returns_not_yet_implemented() {
        let p = Tpm2Provider;
        let err = p.measure().expect_err("stub must error");
        assert!(matches!(
            err,
            AttestationError::NotYetImplemented(HwProviderKind::Tpm2)
        ));
    }

    #[cfg(feature = "attestation-sev-snp")]
    #[test]
    fn sev_snp_stub_returns_not_yet_implemented() {
        let p = SevSnpProvider;
        let err = p.measure().expect_err("stub must error");
        assert!(matches!(
            err,
            AttestationError::NotYetImplemented(HwProviderKind::SevSnp)
        ));
    }

    #[cfg(feature = "attestation-tdx")]
    #[test]
    fn tdx_stub_returns_not_yet_implemented() {
        let p = TdxProvider;
        let err = p.measure().expect_err("stub must error");
        assert!(matches!(
            err,
            AttestationError::NotYetImplemented(HwProviderKind::Tdx)
        ));
    }
}
