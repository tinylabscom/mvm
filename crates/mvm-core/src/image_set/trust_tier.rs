//! The trust tier an image set is classified into before anything consumes it.

use std::fmt;

use serde::{Deserialize, Serialize};

/// How much an image set is trusted, decided by where it came from.
///
/// There are exactly two tiers and no conversion between them. A set built in
/// a local image checkout is never promoted to [`Self::VerifiedRelease`] by
/// anything it carries: an unsigned manifest describes bytes, it does not vouch
/// for them. Only verification of a signed, lock-pinned release produces the
/// release tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ImageTrustTier {
    /// A published set whose manifest verified against the checked-in lock and
    /// its allow-listed signing identity.
    VerifiedRelease,
    /// A set built from an explicitly selected local image checkout. Usable by
    /// a contributor build in the development tier and nowhere else.
    LocalDev,
}

impl ImageTrustTier {
    /// The stable name, as reported by `mvmctl doctor` and recorded alongside
    /// an image set.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::VerifiedRelease => "verified-release",
            Self::LocalDev => "local-dev",
        }
    }

    /// Whether a production admission may boot a set of this tier.
    #[must_use]
    pub const fn permits_production(self) -> bool {
        matches!(self, Self::VerifiedRelease)
    }
}

impl fmt::Display for ImageTrustTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_local_set_is_never_the_release_tier() {
        assert_ne!(ImageTrustTier::LocalDev, ImageTrustTier::VerifiedRelease);
        assert_ne!(
            ImageTrustTier::LocalDev.name(),
            ImageTrustTier::VerifiedRelease.name()
        );
    }

    #[test]
    fn only_a_verified_release_may_boot_in_production() {
        assert!(ImageTrustTier::VerifiedRelease.permits_production());
        assert!(!ImageTrustTier::LocalDev.permits_production());
    }

    #[test]
    fn the_serialized_name_is_the_reported_name() {
        for tier in [ImageTrustTier::VerifiedRelease, ImageTrustTier::LocalDev] {
            let json = serde_json::to_string(&tier).unwrap();
            assert_eq!(json, format!("\"{}\"", tier.name()));
            assert_eq!(serde_json::from_str::<ImageTrustTier>(&json).unwrap(), tier);
            assert_eq!(tier.to_string(), tier.name());
        }
    }

    #[test]
    fn an_unknown_tier_name_does_not_deserialize() {
        for name in ["\"verified\"", "\"release\"", "\"local\"", "\"LocalDev\""] {
            assert!(
                serde_json::from_str::<ImageTrustTier>(name).is_err(),
                "{name}"
            );
        }
    }
}
