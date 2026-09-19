//! Persist the signed agent and drive authority consumed at guest boot.

use super::write_secret_file;
use anyhow::{Context, Result};
use mvm_core::plan::{ExecutionPlan, SignedExecutionPlan};
use mvm_core::protocol::vm_backend::VerbGrantEnvelope;
use std::path::Path;

/// Mint a signed `VerbGrantEnvelope` when the plan carries agent or drive
/// authority and write it to `<state_dir>/verb-grant.json` at mode 0600.
///
/// The sidecar is consumed by the backend's `verb_grant_cmdline_token` at
/// launch time and carried to the guest on the kernel command line.
pub(super) fn mint_verb_grant_sidecar(
    plan_json: &str,
    vm_name: &str,
    state_dir: &Path,
) -> Result<Option<VerbGrantEnvelope>> {
    let sidecar_path = state_dir.join("verb-grant.json");
    match std::fs::remove_file(&sidecar_path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(anyhow::Error::from(error)).with_context(|| {
                format!("remove stale verb-grant sidecar {}", sidecar_path.display())
            });
        }
    }

    let Ok(signed) = serde_json::from_str::<SignedExecutionPlan>(plan_json) else {
        return Ok(None);
    };
    let Ok(plan) = serde_json::from_slice::<ExecutionPlan>(&signed.0.payload) else {
        return Ok(None);
    };

    let verbs = plan.agent_verbs.unwrap_or_default();
    let drive = plan.grants.as_ref().and_then(|grants| grants.drive.clone());
    if verbs.is_empty() && drive.is_none() {
        return Ok(None);
    }

    let keys_dir = mvm_core::config::mvm_keys_dir();
    let signer = crate::audit::host_keypair::load_or_init_at(&keys_dir)
        .context("load host signer for verb-grant mint")?;
    let keystore = crate::host_signer::keystore::Keystore::load_from_file(&signer.secret_path)
        .context("load Keystore from host-signer key file")?;
    let grant = crate::host_signer::mint_verb_grant(
        &keystore,
        vm_name,
        &plan.nonce,
        plan.valid_until,
        verbs,
        drive,
    )
    .context("mint verb grant")?;

    let envelope = VerbGrantEnvelope {
        pubkey_hex: keystore
            .pub_key()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
        plan_nonce_hex: plan.nonce.as_hex().to_string(),
        predecessor_session_id: None,
        predecessor_plan_nonce_hex: None,
        grant,
    };
    let envelope_json = serde_json::to_vec(&envelope).context("serialize VerbGrantEnvelope")?;
    write_secret_file(&sidecar_path, &envelope_json)?;
    Ok(Some(envelope))
}
