//! Host-to-guest display input authority.
//!
//! Viewing a workload's display is a guest-to-host stream and is granted by
//! the `host.display.view.v1` service token alone. Input is the opposite
//! direction — it changes what the workload does — so it is a separate,
//! structured grant here rather than a second token beside the first. A plan
//! that grants view and not input therefore carries no input authority at all:
//! there is nothing to disable, because nothing was granted.
//!
//! Three things ride on the input grant and nowhere else, because each is only
//! meaningful while a human is driving the display:
//!
//! - `attended`, the explicit statement that a human is present. A sealed
//!   workload refuses display input without it.
//! - `clipboard`, host-to-guest paste. Default off: a paste is an arbitrary
//!   byte payload rather than a keystroke, so it has its own bound.
//! - `human_credential`, the signed marker that a human will type a credential
//!   into the guest during this run. A run carrying it may reach only the
//!   destinations it names, and cannot be checkpointed or forked once the
//!   credential has been entered.

use alloc::vec::Vec;
use core::num::NonZeroU32;

use serde::{Deserialize, Deserializer, Serialize};

use crate::grants::Grants;
use crate::policy::network_policy::HostPort;

/// The largest single paste a clipboard grant may authorize.
///
/// A paste is delivered to the guest as one text insertion, so this also
/// bounds what one input event can carry.
pub const MAX_CLIPBOARD_PASTE_BYTES: u32 = 64 * 1024;

/// Authority to send display input events to a workload.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct DisplayInputGrant {
    /// A human attends this run. Required before a sealed workload accepts
    /// display input, and reported by `doctor` and `machine ls`.
    #[serde(default, skip_serializing_if = "core::ops::Not::not")]
    pub attended: bool,
    /// Host-to-guest paste. Absent means no paste event is accepted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clipboard: Option<DisplayClipboardGrant>,
    /// A human will enter a credential through the display during this run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub human_credential: Option<HumanCredentialGrant>,
}

/// Host-to-guest paste authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct DisplayClipboardGrant {
    /// Largest paste, in UTF-8 bytes. Admission refuses a value above
    /// [`MAX_CLIPBOARD_PASTE_BYTES`].
    pub max_paste_bytes: NonZeroU32,
}

/// The signed statement that a human credential will be typed into the guest.
///
/// The credential itself never appears anywhere in the plan or the audit
/// chain. What the plan records is where the resulting session may be used.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct HumanCredentialGrant {
    /// The only destinations this run may reach. Never empty: a credential
    /// with nowhere to be used needs no display input.
    #[serde(deserialize_with = "deserialize_destinations")]
    pub destinations: Vec<HostPort>,
}

fn deserialize_destinations<'de, D>(deserializer: D) -> Result<Vec<HostPort>, D::Error>
where
    D: Deserializer<'de>,
{
    let destinations = Vec::<HostPort>::deserialize(deserializer)?;
    if destinations.is_empty() {
        return Err(serde::de::Error::custom(
            "human_credential.destinations must name at least one destination",
        ));
    }
    Ok(destinations)
}

/// Whether the workload's image was built sealed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisplayTier {
    /// A sealed production image: display input needs an attended grant.
    Sealed,
    /// A development image that ships the accessible agent surface.
    Accessible,
}

/// Why a plan's display grants cannot be admitted or used.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DisplayGrantViolation {
    /// The plan carries no display input grant.
    #[error("the signed plan grants no display input")]
    NotGranted,
    /// A sealed workload was asked for input the plan did not mark attended.
    #[error("display input on a sealed workload requires an attended grant in the signed plan")]
    SealedWithoutAttendedGrant,
    /// The clipboard bound exceeds the contract ceiling.
    #[error(
        "clipboard paste bound {requested} bytes exceeds the {ceiling}-byte ceiling",
        ceiling = MAX_CLIPBOARD_PASTE_BYTES
    )]
    ClipboardBoundTooLarge { requested: u32 },
    /// A human-credential run may reach a destination its credential grant
    /// does not name.
    #[error(
        "egress destination {0} is outside the human-credential destinations; a run that carries a human credential may reach only those"
    )]
    EgressOutsideCredentialDestinations(HostPort),
}

impl DisplayGrantViolation {
    /// Wire-stable reason word for the audit chain.
    #[must_use]
    pub fn reason(&self) -> &'static str {
        match self {
            Self::NotGranted => "not-granted",
            Self::SealedWithoutAttendedGrant => "sealed-without-attended-grant",
            Self::ClipboardBoundTooLarge { .. } => "clipboard-bound-too-large",
            Self::EgressOutsideCredentialDestinations(_) => {
                "egress-outside-credential-destinations"
            }
        }
    }
}

/// The display input grant `grants` carries, if any.
#[must_use]
pub fn display_input_grant(grants: Option<&Grants>) -> Option<&DisplayInputGrant> {
    grants.and_then(|grants| grants.display_input.as_ref())
}

/// Authorize display input on a workload of `tier`.
///
/// # Errors
/// [`DisplayGrantViolation::NotGranted`] without a grant, and
/// [`DisplayGrantViolation::SealedWithoutAttendedGrant`] when a sealed
/// workload's grant is not marked attended.
pub fn authorize_display_input(
    grants: Option<&Grants>,
    tier: DisplayTier,
) -> Result<&DisplayInputGrant, DisplayGrantViolation> {
    let grant = display_input_grant(grants).ok_or(DisplayGrantViolation::NotGranted)?;
    if tier == DisplayTier::Sealed && !grant.attended {
        return Err(DisplayGrantViolation::SealedWithoutAttendedGrant);
    }
    Ok(grant)
}

/// Check the parts of a display input grant that do not depend on where the
/// workload runs: the clipboard ceiling, and that a human-credential run's
/// egress stays inside the destinations its credential grant names.
///
/// An absent egress grant is deny-all and therefore already inside any
/// destination set.
///
/// # Errors
/// The first violation found, clipboard before egress.
pub fn check_display_input_grant(grants: &Grants) -> Result<(), DisplayGrantViolation> {
    let Some(grant) = grants.display_input.as_ref() else {
        return Ok(());
    };
    if let Some(clipboard) = grant.clipboard
        && clipboard.max_paste_bytes.get() > MAX_CLIPBOARD_PASTE_BYTES
    {
        return Err(DisplayGrantViolation::ClipboardBoundTooLarge {
            requested: clipboard.max_paste_bytes.get(),
        });
    }
    if let Some(credential) = grant.human_credential.as_ref()
        && let Some(egress) = grants.egress.as_ref()
        && let Some(outside) = egress
            .allow
            .iter()
            .find(|destination| !credential.destinations.contains(destination))
    {
        return Err(DisplayGrantViolation::EgressOutsideCredentialDestinations(
            outside.clone(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;
    use crate::grants::EgressGrant;

    fn input(attended: bool) -> Grants {
        Grants {
            display_input: Some(DisplayInputGrant {
                attended,
                ..DisplayInputGrant::default()
            }),
            ..Grants::default()
        }
    }

    fn credential_grants(destinations: Vec<HostPort>, egress: Vec<HostPort>) -> Grants {
        Grants {
            egress: Some(EgressGrant { allow: egress }),
            display_input: Some(DisplayInputGrant {
                attended: true,
                clipboard: None,
                human_credential: Some(HumanCredentialGrant { destinations }),
            }),
            ..Grants::default()
        }
    }

    #[test]
    fn no_grant_authorizes_no_input_on_either_tier() {
        for tier in [DisplayTier::Accessible, DisplayTier::Sealed] {
            assert_eq!(
                authorize_display_input(None, tier),
                Err(DisplayGrantViolation::NotGranted)
            );
            assert_eq!(
                authorize_display_input(Some(&Grants::default()), tier),
                Err(DisplayGrantViolation::NotGranted)
            );
        }
    }

    #[test]
    fn a_sealed_workload_needs_the_attended_grant() {
        let unattended = input(false);
        assert_eq!(
            authorize_display_input(Some(&unattended), DisplayTier::Sealed),
            Err(DisplayGrantViolation::SealedWithoutAttendedGrant)
        );
        assert!(authorize_display_input(Some(&unattended), DisplayTier::Accessible).is_ok());
        assert!(authorize_display_input(Some(&input(true)), DisplayTier::Sealed).is_ok());
    }

    #[test]
    fn an_unattended_grant_serializes_without_the_attended_key() {
        let json = serde_json::to_string(&input(false)).unwrap();
        assert_eq!(json, r#"{"display_input":{}}"#);
        let attended = serde_json::to_string(&input(true)).unwrap();
        assert_eq!(attended, r#"{"display_input":{"attended":true}}"#);
    }

    #[test]
    fn a_human_credential_grant_needs_a_destination() {
        let empty = r#"{"display_input":{"human_credential":{"destinations":[]}}}"#;
        assert!(serde_json::from_str::<Grants>(empty).is_err());
        let named = r#"{"display_input":{"human_credential":{"destinations":[{"host":"login.example","port":443}]}}}"#;
        let grants: Grants = serde_json::from_str(named).unwrap();
        assert!(check_display_input_grant(&grants).is_ok());
    }

    #[test]
    fn unknown_display_grant_fields_are_refused() {
        let typo = r#"{"display_input":{"atended":true}}"#;
        assert!(serde_json::from_str::<Grants>(typo).is_err());
    }

    #[test]
    fn a_human_credential_run_cannot_reach_outside_its_destinations() {
        let login = HostPort::new("login.example", 443);
        let other = HostPort::new("other.example", 443);
        assert!(
            check_display_input_grant(&credential_grants(vec![login.clone()], vec![login.clone()]))
                .is_ok()
        );
        assert_eq!(
            check_display_input_grant(&credential_grants(
                vec![login.clone()],
                vec![login, other.clone()]
            )),
            Err(DisplayGrantViolation::EgressOutsideCredentialDestinations(
                other
            ))
        );
    }

    #[test]
    fn the_clipboard_bound_has_a_ceiling() {
        let mut grants = input(true);
        let grant = grants.display_input.as_mut().unwrap();
        grant.clipboard = Some(DisplayClipboardGrant {
            max_paste_bytes: NonZeroU32::new(MAX_CLIPBOARD_PASTE_BYTES + 1).unwrap(),
        });
        assert_eq!(
            check_display_input_grant(&grants),
            Err(DisplayGrantViolation::ClipboardBoundTooLarge {
                requested: MAX_CLIPBOARD_PASTE_BYTES + 1
            })
        );
    }
}
