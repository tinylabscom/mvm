//! The base-image contract: what a workload base root filesystem promises the
//! guest runtime `mvmctl` boots it with.
//!
//! The guest agent, its helpers and the initramfs agent ship with `mvmctl`, so
//! the guest-agent protocol is a property of the CLI and its own guest runtime,
//! which always match. What can still drift is the base root filesystem the
//! image set publishes, and this version is how it says which interface it
//! offers. The base root filesystem declares one integer in
//! `/etc/mvm/base-image-contract`, and a set carries the same integer in its
//! signed `[compatibility]` section, where `mvmctl` checks it before any member
//! is fetched and so before anything boots. The meaning of each value is fixed
//! once released:
//!
//! - **0** — the legacy contract. The set declares nothing because it was
//!   published before the declaration existed: every image set up to and
//!   including `image-set/v0.2.4`. Its base root filesystems are composed with
//!   `mkGuest` and may still carry mvm's `/init` and mvm binaries. `mvmctl`
//!   boots them only through its own initramfs agent and runtime overlay. An
//!   absent declaration is read as this value by name, never skipped, and a
//!   host that stops booting it says so by narrowing its supported range.
//! - **1** — the Linux layer only. The root filesystem carries no binary
//!   compiled from mvm's source and no mvm-authored `/init`; it declares the
//!   marker above; and its read-only `/etc/passwd` and `/etc/group` name the
//!   fixed guest identities the runtime drops to: `root` 0, `mvm-worker` 901,
//!   `mvm-dns` 987, `mvm-crng` 988 and `mvm-egress` 989. The initramfs agent
//!   pivots into it in-process and stays PID 1, so nothing in it runs as
//!   init.
//!
//! A change to what the base root filesystem must provide is a new number,
//! never a reinterpretation. The builder image is not covered: it has its own
//! [`super::BuilderBootAbi`].

use std::fmt;

use serde::{Deserialize, Serialize};

/// The file a base root filesystem declares its contract version in.
pub const BASE_IMAGE_CONTRACT_MARKER: &str = "/etc/mvm/base-image-contract";

/// One base-image contract version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct BaseImageContract(u32);

impl BaseImageContract {
    /// A set published before the declaration existed.
    pub const LEGACY: Self = Self(0);
    /// The Linux layer only: no mvm binary and no mvm `/init`.
    pub const LINUX_LAYER: Self = Self(1);

    pub const fn new(version: u32) -> Self {
        Self(version)
    }

    pub const fn get(self) -> u32 {
        self.0
    }
}

impl fmt::Display for BaseImageContract {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// The inclusive range of base-image contracts one `mvmctl` boots.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BaseImageContractRange {
    min: BaseImageContract,
    max: BaseImageContract,
}

impl BaseImageContractRange {
    /// What this `mvmctl` boots. Every workload launch attaches the CLI's own
    /// initramfs agent and runtime overlay and fails closed without them, so a
    /// root filesystem that bakes mvm's programs and one that carries none boot
    /// the same way.
    pub const SUPPORTED: Self = Self {
        min: BaseImageContract::LEGACY,
        max: BaseImageContract::LINUX_LAYER,
    };

    /// `None` when `min` exceeds `max`: an empty range would refuse every set
    /// and say nothing about why.
    pub const fn new(min: BaseImageContract, max: BaseImageContract) -> Option<Self> {
        if min.0 <= max.0 {
            Some(Self { min, max })
        } else {
            None
        }
    }

    pub const fn min(self) -> BaseImageContract {
        self.min
    }

    pub const fn max(self) -> BaseImageContract {
        self.max
    }

    pub const fn contains(self, contract: BaseImageContract) -> bool {
        self.min.0 <= contract.0 && contract.0 <= self.max.0
    }
}

impl fmt::Display for BaseImageContractRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}..={}", self.min, self.max)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn this_mvmctl_boots_the_legacy_and_linux_layer_contracts_and_nothing_above() {
        let range = BaseImageContractRange::SUPPORTED;
        assert!(range.contains(BaseImageContract::LEGACY));
        assert!(range.contains(BaseImageContract::LINUX_LAYER));
        assert!(!range.contains(BaseImageContract::new(2)));
        assert_eq!(range.to_string(), "0..=1");
    }

    #[test]
    fn an_inverted_range_is_not_a_range() {
        assert!(
            BaseImageContractRange::new(BaseImageContract::LINUX_LAYER, BaseImageContract::LEGACY)
                .is_none()
        );
    }

    #[test]
    fn the_contract_serializes_as_a_bare_integer() {
        assert_eq!(
            serde_json::to_string(&BaseImageContract::LINUX_LAYER).unwrap(),
            "1"
        );
        let contract: BaseImageContract = serde_json::from_str("0").unwrap();
        assert_eq!(contract, BaseImageContract::LEGACY);
    }
}
