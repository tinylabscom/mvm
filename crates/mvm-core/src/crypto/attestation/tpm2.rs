//! TPM2 hardware attestation provider.
//!
//! This module is compiled only on Linux with the `attestation-tpm2`
//! feature enabled. It uses `tss-esapi` to talk to the system TPM2
//! and produce a TPM2 quote over the SHA-256 PCR 0-7 bank.
//!
//! The quote is returned as a JSON object containing the base64-encoded
//! TPMS_ATTEST blob, the base64-encoded signature, and the hex-encoded
//! digest of the selected PCRs. A verifier needs the corresponding
//! Attestation Key public area to validate the signature; this first
//! implementation creates transient keys and returns the AK public area
//! alongside the quote so a verifier can reconstruct the trust chain.
//!
//! Key persistence is intentionally left for a follow-up. Transient keys
//! mean every `measure()` call regenerates the EK/AK pair, which is slow
//! but stateless and safe for a v1 implementation.

use crate::crypto::attestation::error::AttestationError;
use crate::crypto::attestation::provider::{HwMeasurement, HwProviderKind};
use base64::Engine;

use tss_esapi::Context;
use tss_esapi::abstraction::pcr::PcrData;
use tss_esapi::constants::StartupType;
use tss_esapi::interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm};
use tss_esapi::interface_types::ecc::EccCurve;
use tss_esapi::interface_types::key_bits::RsaKeyBits;
use tss_esapi::interface_types::resource_handles::Hierarchy;
use tss_esapi::structures::{
    Data, EccParameter, EccPoint, EccScheme, HashScheme, PcrSelectionList, PcrSelectionListBuilder,
    PcrSlot, Public, PublicBuilder, PublicEccParametersBuilder, Signature, SignatureScheme,
};
use tss_esapi::tcti_ldr::TctiNameConf;
use tss_esapi::traits::Marshall;
use tss_esapi::utils::create_restricted_decryption_rsa_public;

/// Provider that generates a TPM2 quote over boot-relevant PCRs.
#[derive(Debug, Default)]
pub struct Tpm2Provider;

impl Tpm2Provider {
    pub fn measure(&self) -> Result<HwMeasurement, AttestationError> {
        let measurement =
            generate_tpm2_quote().map_err(|message| AttestationError::MeasurementFailed {
                provider: HwProviderKind::Tpm2,
                message,
            })?;

        Ok(HwMeasurement {
            provider: HwProviderKind::Tpm2,
            measurement_hex: hex::encode_upper(measurement),
        })
    }
}

/// Build the PCR selection used for the quote: SHA-256 bank, PCRs 0-7.
fn pcr_selection_list() -> PcrSelectionList {
    PcrSelectionListBuilder::new()
        .with_selection(
            HashingAlgorithm::Sha256,
            &[
                PcrSlot::Slot0,
                PcrSlot::Slot1,
                PcrSlot::Slot2,
                PcrSlot::Slot3,
                PcrSlot::Slot4,
                PcrSlot::Slot5,
                PcrSlot::Slot6,
                PcrSlot::Slot7,
            ],
        )
        .build()
        .expect("static PCR selection is valid")
}

/// Generate a TPM2 quote and serialize the result.
fn generate_tpm2_quote() -> Result<Vec<u8>, String> {
    let tcti = TctiNameConf::from_environment_variable()
        .map_err(|e| format!("failed to resolve TPM TCTI: {e}"))?;

    let mut context = Context::new(tcti).map_err(|e| format!("failed to connect to TPM: {e}"))?;

    // Software TPM simulators (swtpm) need an explicit TPM2_Startup before
    // any object commands. Real firmware TPMs have already received this from
    // the platform, so calling it again is a harmless no-op.
    context
        .startup(StartupType::Clear)
        .map_err(|e| format!("failed to start up TPM: {e}"))?;

    // 1. Create a primary Endorsement Key (EK). The EK is a restricted
    //    decryption key in the endorsement hierarchy and acts as the parent
    //    for the Attestation Key (AK).
    let ek_public = create_restricted_decryption_rsa_public(
        tss_esapi::structures::SymmetricDefinitionObject::AES_256_CFB,
        RsaKeyBits::Rsa2048,
        tss_esapi::structures::RsaExponent::default(),
    )
    .map_err(|e| format!("failed to build EK public area: {e}"))?;

    let ek_handle = context
        .execute_with_nullauth_session(|ctx| {
            ctx.create_primary(Hierarchy::Endorsement, ek_public, None, None, None, None)
        })
        .map_err(|e| format!("failed to create TPM primary EK: {e}"))?
        .key_handle;

    // 2. Create an Attestation Key (AK) under the EK. The AK is a restricted
    //    signing key that can produce TPM2 quotes.
    let ak_public = build_ak_public()?;

    let create_result = context
        .execute_with_nullauth_session(|ctx| {
            ctx.create(ek_handle, ak_public, None, None, None, None)
        })
        .map_err(|e| format!("failed to create TPM AK: {e}"))?;

    // Clone before moving the public area into the load closure.
    let ak_public_area = create_result.out_public.clone();
    let ak_handle = context
        .execute_with_nullauth_session(|ctx| {
            ctx.load(
                ek_handle,
                create_result.out_private,
                create_result.out_public,
            )
        })
        .map_err(|e| format!("failed to load TPM AK: {e}"))?;

    // 3. Generate the quote over the selected PCRs. The extra data is empty
    //    for now; a future version can bind a nonce from the verifier here.
    let pcr_selection = pcr_selection_list();
    let (attest, signature) = context
        .execute_with_nullauth_session(|ctx| {
            ctx.quote(
                ak_handle,
                Data::default(),
                SignatureScheme::EcDsa {
                    hash_scheme: HashScheme::new(HashingAlgorithm::Sha256),
                },
                pcr_selection,
            )
        })
        .map_err(|e| format!("failed to generate TPM2 quote: {e}"))?;

    // 4. Serialize the quote, signature, and AK public area into a stable
    //    JSON payload so verifiers can parse it without needing tss-esapi.
    let quote_bytes = attest
        .marshall()
        .map_err(|e| format!("failed to marshal TPM2 attest: {e}"))?;
    let signature_bytes = marshall_signature(&signature)?;
    let ak_public_bytes = ak_public_area
        .marshall()
        .map_err(|e| format!("failed to marshal AK public area: {e}"))?;

    #[derive(serde::Serialize)]
    struct Tpm2QuoteEnvelope {
        version: u32,
        quote_b64: String,
        signature_b64: String,
        ak_public_b64: String,
        pcrs: Vec<(u8, String)>,
    }

    let pcr_values = read_pcr_values(&mut context)?;

    let envelope = Tpm2QuoteEnvelope {
        version: 1,
        quote_b64: base64::engine::general_purpose::STANDARD.encode(&quote_bytes),
        signature_b64: base64::engine::general_purpose::STANDARD.encode(&signature_bytes),
        ak_public_b64: base64::engine::general_purpose::STANDARD.encode(&ak_public_bytes),
        pcrs: pcr_values,
    };

    serde_json::to_vec(&envelope)
        .map_err(|e| format!("failed to serialize TPM2 quote envelope: {e}"))
}

/// Build a restricted signing ECC public area for the Attestation Key.
fn build_ak_public() -> Result<Public, String> {
    let parameters = PublicEccParametersBuilder::new()
        .with_symmetric(tss_esapi::structures::SymmetricDefinitionObject::Null)
        .with_ecc_scheme(EccScheme::EcDsa(HashScheme::new(HashingAlgorithm::Sha256)))
        .with_curve(EccCurve::NistP256)
        .with_key_derivation_function_scheme(
            tss_esapi::structures::KeyDerivationFunctionScheme::Null,
        )
        .with_is_signing_key(true)
        .with_is_decryption_key(false)
        .build()
        .map_err(|e| format!("failed to build AK ECC parameters: {e}"))?;

    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(
            tss_esapi::attributes::ObjectAttributesBuilder::new()
                .with_fixed_tpm(true)
                .with_st_clear(false)
                .with_fixed_parent(true)
                .with_sensitive_data_origin(true)
                .with_user_with_auth(true)
                .with_admin_with_policy(false)
                .with_no_da(false)
                .with_restricted(true)
                .with_decrypt(false)
                .with_sign_encrypt(true)
                .build()
                .map_err(|e| format!("failed to build AK object attributes: {e}"))?,
        )
        .with_ecc_parameters(parameters)
        .with_ecc_unique_identifier(EccPoint::new(
            EccParameter::default(),
            EccParameter::default(),
        ))
        .build()
        .map_err(|e| format!("failed to build AK public area: {e}"))
}

/// Read the selected PCR values and return (slot, hex_digest) pairs.
fn read_pcr_values(context: &mut Context) -> Result<Vec<(u8, String)>, String> {
    let pcr_selection = pcr_selection_list();
    let (_update_counter, read_pcr_selection_list, digest_list) = context
        .execute_with_session(None, |ctx| ctx.pcr_read(pcr_selection.clone()))
        .map_err(|e| format!("failed to read PCR values: {e}"))?;

    let pcr_data = PcrData::create(&read_pcr_selection_list, &digest_list)
        .map_err(|e| format!("failed to create PCR data: {e}"))?;

    let mut values = Vec::new();
    let sha256_bank = pcr_data
        .pcr_bank(HashingAlgorithm::Sha256)
        .ok_or("missing SHA-256 PCR bank")?;
    for (slot, digest) in sha256_bank {
        values.push((
            (*slot as u32).trailing_zeros() as u8,
            hex::encode_upper(digest.value()),
        ));
    }

    Ok(values)
}

/// Marshal a TPM2 signature into a flat byte vector.
fn marshall_signature(signature: &Signature) -> Result<Vec<u8>, String> {
    match signature {
        Signature::EcDsa(sig) => {
            let mut bytes = sig.signature_r().value().to_vec();
            bytes.extend_from_slice(sig.signature_s().value());
            Ok(bytes)
        }
        _ => Err("unsupported TPM2 signature algorithm".to_string()),
    }
}
