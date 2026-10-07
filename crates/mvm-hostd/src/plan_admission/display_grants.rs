//! Admission rules for the display input grant.

use anyhow::Result;
use mvm_contract::grants::Grants;
use mvm_contract::grants::display::{
    DisplayTier, authorize_display_input, check_display_input_grant,
};
use mvm_core::plan::Variant;

/// Refuse a display input grant this run may not carry.
///
/// A sealed production run needs the grant marked attended: input into a
/// sealed workload is a human driving it, and the plan has to say so. A
/// human-credential grant confines egress to the destinations it names, and
/// the clipboard bound has a ceiling. Neither of those depends on posture.
pub(super) fn admit_display_input(grants: &Grants, variant: Variant) -> Result<()> {
    if grants.display_input.is_none() {
        return Ok(());
    }
    check_display_input_grant(grants)
        .map_err(|violation| anyhow::anyhow!("refusing the display input grant: {violation}"))?;
    if variant.is_prod() {
        authorize_display_input(Some(grants), DisplayTier::Sealed).map_err(|violation| {
            anyhow::anyhow!("refusing the display input grant on a production run: {violation}")
        })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_contract::grants::{DisplayInputGrant, EgressGrant, HumanCredentialGrant};
    use mvm_contract::policy::network_policy::HostPort;

    fn with_display(grant: DisplayInputGrant) -> Grants {
        Grants {
            display_input: Some(grant),
            ..Grants::default()
        }
    }

    #[test]
    fn a_production_run_refuses_unattended_display_input() {
        let unattended = with_display(DisplayInputGrant::default());
        let error = admit_display_input(&unattended, Variant::Prod)
            .expect_err("a sealed run must not admit input nobody attends");
        assert!(format!("{error:#}").contains("attended"), "{error:#}");
        assert!(admit_display_input(&unattended, Variant::Dev).is_ok());

        let attended = with_display(DisplayInputGrant {
            attended: true,
            ..DisplayInputGrant::default()
        });
        assert!(admit_display_input(&attended, Variant::Prod).is_ok());
        assert!(admit_display_input(&Grants::default(), Variant::Prod).is_ok());
    }

    #[test]
    fn a_human_credential_run_is_refused_egress_beyond_its_destinations() {
        let mut grants = with_display(DisplayInputGrant {
            attended: true,
            clipboard: None,
            human_credential: Some(HumanCredentialGrant {
                destinations: vec![HostPort::new("login.example", 443)],
            }),
        });
        grants.egress = Some(EgressGrant {
            allow: vec![
                HostPort::new("login.example", 443),
                HostPort::new("exfil.example", 443),
            ],
        });
        let error = admit_display_input(&grants, Variant::Dev)
            .expect_err("egress must stay inside the credential's destinations");
        assert!(format!("{error:#}").contains("exfil.example"), "{error:#}");
    }
}
