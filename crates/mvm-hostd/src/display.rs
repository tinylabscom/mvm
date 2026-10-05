//! Host-side composition for attended display input on a running machine.
//!
//! A display input session is the display input gate, a route to the guest
//! agent, and the authority both are opened under. This module rebuilds that
//! authority from the host's own record of the run rather than from anything
//! a caller supplies: the admitted plan the launch persisted, the tier the
//! image was built at, and — where one was minted — the host-signed verb grant
//! that must name `display-input`.

use std::sync::Arc;

use mvm_contract::grants::DisplayTier;
use mvm_contract::stream::DISPLAY_INPUT_VERB;

use crate::audit::emitter::AuditEmitter;
use crate::stream::display_input_gate::{DisplayInputGate, DisplayInputRefusal};
use crate::stream::display_input_route::{DisplayInputRoute, VsockDisplayInput};

/// Failure to establish a running machine's display input authority.
#[derive(Debug, thiserror::Error)]
pub enum DisplayAuthorityError {
    #[error("loading the admitted display authority: {0:#}")]
    Authority(anyhow::Error),
    #[error("opening the host audit chain: {0:#}")]
    Audit(anyhow::Error),
}

/// A running machine's display input authority, reloaded and checked.
///
/// The fields are private so an out-of-process caller cannot turn a bare
/// deserialized plan into authority; [`load`](Self::load) is the only
/// constructor.
pub struct DisplayAuthority {
    vm: String,
    plan: mvm_contract::plan::ExecutionPlan,
    tier: DisplayTier,
    audit: Arc<AuditEmitter>,
}

impl DisplayAuthority {
    /// Reload `vm`'s display input authority.
    ///
    /// `Ok(None)` is the ordinary case of a plan that grants no display input.
    /// A sealed machine also needs a host-signed verb grant naming
    /// `display-input`, because a sealed image refuses every unlisted verb and
    /// the grant is the guest's only view of the plan.
    ///
    /// # Errors
    /// The machine name is invalid, its plan cannot be read, or its signed
    /// grant does not verify or does not name display input.
    pub fn load(vm: &str) -> Result<Option<Self>, DisplayAuthorityError> {
        mvm_core::naming::validate_vm_name(vm).map_err(|error| {
            DisplayAuthorityError::Authority(anyhow::anyhow!("invalid machine name: {error}"))
        })?;
        let plan =
            crate::audit::plan_persist::read_plan(vm).map_err(DisplayAuthorityError::Authority)?;
        if mvm_contract::grants::display::display_input_grant(plan.grants.as_ref()).is_none() {
            return Ok(None);
        }
        let tier = tier_from_meta(mvm_runtime::vm::runtime_meta::read(vm).ok().flatten());
        let signer =
            crate::audit::host_keypair::load_or_init().map_err(DisplayAuthorityError::Authority)?;
        let envelope = mvm_runtime::microvm::read_verb_grant_envelope(vm)
            .map_err(DisplayAuthorityError::Authority)?;
        match envelope {
            Some(envelope) => {
                if envelope.plan_nonce_hex != plan.nonce.as_hex() {
                    return Err(authority_error(
                        "the verb grant nonce does not match the admitted plan",
                    ));
                }
                envelope
                    .grant
                    .verify(&signer.verifying, vm, &plan.nonce, chrono::Utc::now())
                    .map_err(|error| {
                        DisplayAuthorityError::Authority(anyhow::anyhow!(
                            "host-signed verb grant verification failed: {error}"
                        ))
                    })?;
                if !names_display_input(&envelope.grant.verbs) {
                    return Err(authority_error(
                        "the admitted plan grants display input but the host-signed verb grant does not name display-input",
                    ));
                }
            }
            None if tier == DisplayTier::Sealed => {
                return Err(authority_error(
                    "a sealed machine accepts display input only under a host-signed verb grant, and this one has none",
                ));
            }
            None => {}
        }
        let audit =
            Arc::new(AuditEmitter::new(signer.signing).map_err(DisplayAuthorityError::Audit)?);
        Ok(Some(Self {
            vm: vm.to_string(),
            plan,
            tier,
            audit,
        }))
    }

    /// Open the single-writer display input route for this machine.
    ///
    /// # Errors
    /// The gate's refusal, already recorded.
    pub fn open_input(&self) -> Result<DisplayInputRoute, DisplayInputRefusal> {
        let session = DisplayInputGate::open_authority(self)?;
        Ok(DisplayInputRoute::new(
            session,
            Box::new(VsockDisplayInput::new(&self.vm)),
        ))
    }

    /// Whether the signed grant marks this run attended.
    #[must_use]
    pub fn attended(&self) -> bool {
        mvm_contract::grants::display::display_input_grant(self.plan.grants.as_ref())
            .is_some_and(|grant| grant.attended)
    }

    /// Whether the signed grant allows paste.
    #[must_use]
    pub fn clipboard(&self) -> bool {
        mvm_contract::grants::display::display_input_grant(self.plan.grants.as_ref())
            .is_some_and(|grant| grant.clipboard.is_some())
    }

    /// Whether the signed grant allows a credential entry.
    #[must_use]
    pub fn human_credential(&self) -> bool {
        mvm_contract::grants::display::display_input_grant(self.plan.grants.as_ref())
            .is_some_and(|grant| grant.human_credential.is_some())
    }

    pub(crate) fn plan(&self) -> &mvm_contract::plan::ExecutionPlan {
        &self.plan
    }

    pub(crate) fn vm(&self) -> &str {
        &self.vm
    }

    pub(crate) fn tier(&self) -> DisplayTier {
        self.tier
    }

    pub(crate) fn audit(&self) -> Arc<AuditEmitter> {
        Arc::clone(&self.audit)
    }
}

/// A machine whose image says it is accessible is the accessible tier; every
/// other answer — sealed, missing, unreadable — is the sealed tier, so a gap
/// in the host's record can only make display input harder to get.
fn tier_from_meta(meta: Option<mvm_runtime::vm::runtime_meta::VmRuntimeMeta>) -> DisplayTier {
    match meta {
        Some(meta) if meta.accessible => DisplayTier::Accessible,
        _ => DisplayTier::Sealed,
    }
}

fn names_display_input(verbs: &[mvm_contract::plan::VerbId]) -> bool {
    verbs.iter().any(|verb| verb.as_str() == DISPLAY_INPUT_VERB)
}

fn authority_error(message: &str) -> DisplayAuthorityError {
    DisplayAuthorityError::Authority(anyhow::anyhow!("{message}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unknown_tier_is_the_sealed_tier() {
        assert_eq!(tier_from_meta(None), DisplayTier::Sealed);
        let mut meta =
            mvm_runtime::vm::runtime_meta::dev_attached(mvm_core::vm_backend::StartMode::Attached);
        meta.accessible = false;
        assert_eq!(tier_from_meta(Some(meta.clone())), DisplayTier::Sealed);
        meta.accessible = true;
        assert_eq!(tier_from_meta(Some(meta)), DisplayTier::Accessible);
    }

    #[test]
    fn only_the_display_input_verb_counts() {
        let verb = |name: &str| mvm_contract::plan::VerbId::new(name).unwrap();
        assert!(!names_display_input(&[
            verb("display-view"),
            verb("stream-input")
        ]));
        assert!(names_display_input(&[
            verb("ping"),
            verb(DISPLAY_INPUT_VERB)
        ]));
    }
}
