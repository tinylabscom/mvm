//! Whether launching a dashboard is allowed here at all.
//!
//! The issue's framing is that this is a dev/demo surface that "must never
//! become an alternate production or fleet-control path". That is a property
//! of the *environment*, not of the artifact, so it is checked first and
//! separately: an unsafe posture refuses before anything is resolved, read, or
//! executed.
//!
//! The unknown case refuses. A launcher that treats "I could not tell" as "it
//! is probably fine" has a default that is wrong in exactly the situation the
//! rule exists for.

/// The environment a `dashboard` launch was requested in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Posture {
    /// An unambiguous local development environment.
    LocalDev,
    /// A production environment.
    Production,
    /// A fleet-managed host.
    Fleet,
    /// Could not be determined.
    Unknown,
}

/// Why a launch was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostureRefusal {
    pub posture: Posture,
}

impl std::fmt::Display for PostureRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let reason = match self.posture {
            Posture::Production => "this is a production environment",
            Posture::Fleet => "this host is fleet-managed",
            Posture::Unknown => {
                "the environment could not be determined, and an undetermined \
                 environment is refused rather than assumed safe"
            }
            Posture::LocalDev => unreachable!("LocalDev is not a refusal"),
        };
        write!(
            f,
            "refusing to start the dashboard: {reason}. \
             `mvmctl dashboard` is a local development surface and is not an \
             alternate production or fleet-control path."
        )
    }
}

impl std::error::Error for PostureRefusal {}

/// Refuse everything that is not unambiguously local dev.
pub fn admit(posture: Posture) -> Result<(), PostureRefusal> {
    match posture {
        Posture::LocalDev => Ok(()),
        other => Err(PostureRefusal { posture: other }),
    }
}

/// Classify from explicit signals only.
///
/// Takes the signals as arguments rather than reading the process environment
/// so the classification is testable and so a caller cannot be surprised by
/// which variables are consulted.
pub fn classify(prod_flag: bool, fleet_flag: bool, dev_flag: bool) -> Posture {
    // Production and fleet are checked before dev: a host asserting both is
    // ambiguous, and the safe reading of an ambiguous host is the restrictive
    // one, not the permissive one.
    if prod_flag {
        Posture::Production
    } else if fleet_flag {
        Posture::Fleet
    } else if dev_flag {
        Posture::LocalDev
    } else {
        Posture::Unknown
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_local_dev_is_admitted() {
        assert!(admit(Posture::LocalDev).is_ok());
        for refused in [Posture::Production, Posture::Fleet, Posture::Unknown] {
            assert!(
                admit(refused).is_err(),
                "{refused:?} must not admit a dashboard launch"
            );
        }
    }

    /// The default is the one that matters. "Could not tell" must refuse, or
    /// the rule fails open in exactly the situation it exists for.
    #[test]
    fn an_undetermined_environment_refuses() {
        assert_eq!(classify(false, false, false), Posture::Unknown);
        assert!(admit(classify(false, false, false)).is_err());
    }

    /// A host claiming both dev and production is ambiguous. The restrictive
    /// reading wins; a permissive one would let a production host opt itself
    /// back in by also setting the dev signal.
    #[test]
    fn production_and_fleet_outrank_a_dev_signal() {
        assert_eq!(classify(true, false, true), Posture::Production);
        assert_eq!(classify(false, true, true), Posture::Fleet);
    }

    #[test]
    fn a_plain_dev_host_is_local_dev() {
        assert_eq!(classify(false, false, true), Posture::LocalDev);
        assert!(admit(classify(false, false, true)).is_ok());
    }

    #[test]
    fn every_refusal_says_it_is_not_a_production_path() {
        for refused in [Posture::Production, Posture::Fleet, Posture::Unknown] {
            let rendered = PostureRefusal { posture: refused }.to_string();
            assert!(
                rendered.contains("not an alternate production or fleet-control path"),
                "{refused:?} refusal must state the boundary: {rendered}"
            );
        }
    }
}
