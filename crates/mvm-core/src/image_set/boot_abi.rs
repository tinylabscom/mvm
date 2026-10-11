//! The builder boot ABI: what a builder image promises the `mvmctl` that
//! boots it.
//!
//! A builder image declares one integer in `/etc/mvm/builder-boot-abi`, and a
//! published set carries the same integer in its signed `[compatibility]`
//! section. The meaning of each value is fixed once released:
//!
//! - **0** — the legacy image. It carries no marker, and it bakes `mvmctl`'s
//!   builder binaries and `mvm-setpriv` at `/sbin`. It boots either with those
//!   baked binaries or with the boot payload, whose binaries then win.
//! - **1** — the image carries none of the builder binaries the boot payload
//!   supplies (`mvm-host-vm-init`, `mvm-builderd`) and boots only with the
//!   payload. It still bakes `mvm-setpriv` at `/sbin`.
//! - **2** — the image carries no mvm binary at all. `mvm-setpriv` also
//!   arrives in the boot payload, so the image depends on nothing compiled
//!   from mvm's source.
//!
//! Every boot payload carries all three binaries whatever the image's ABI, and
//! the guest prefers the payload's copy to a baked one, so a host that boots 2
//! boots 0 and 1 the same way.
//!
//! All of them promise the rest of the builder's surface: `/run` is a mount point,
//! busybox, `nix`, `iptables` and `/usr/bin/firecracker` sit at their paths,
//! the builder uid 902 exists, and the persistent store lives on `/dev/vdb`.
//! A change to any of those is a new ABI number, never a reinterpretation.

use std::fmt;

use serde::{Deserialize, Serialize};

/// One builder boot ABI version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct BuilderBootAbi(u32);

impl BuilderBootAbi {
    /// Host binaries baked into the image, no marker.
    pub const LEGACY: Self = Self(0);
    /// No builder binaries in the image; they arrive in the boot payload. The
    /// image still bakes `mvm-setpriv`.
    pub const PAYLOAD: Self = Self(1);
    /// No mvm binary in the image: `mvm-setpriv` arrives in the boot payload
    /// beside the builder binaries.
    pub const NO_MVM_BINARY: Self = Self(2);

    pub const fn new(version: u32) -> Self {
        Self(version)
    }

    pub const fn get(self) -> u32 {
        self.0
    }
}

impl fmt::Display for BuilderBootAbi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// The inclusive range of builder boot ABIs one host can boot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BuilderBootAbiRange {
    min: BuilderBootAbi,
    max: BuilderBootAbi,
}

impl BuilderBootAbiRange {
    /// Only the legacy ABI: a host that hands builders no boot payload can
    /// boot only an image that bakes its own init.
    pub const LEGACY_ONLY: Self = Self {
        min: BuilderBootAbi::LEGACY,
        max: BuilderBootAbi::LEGACY,
    };

    /// Every ABI whose meaning is defined: a host with a boot payload boots
    /// them all.
    pub const WITH_PAYLOAD: Self = Self {
        min: BuilderBootAbi::LEGACY,
        max: BuilderBootAbi::NO_MVM_BINARY,
    };

    /// `None` when `min` exceeds `max`: an empty range would refuse every
    /// image and say nothing about why.
    pub const fn new(min: BuilderBootAbi, max: BuilderBootAbi) -> Option<Self> {
        if min.0 <= max.0 {
            Some(Self { min, max })
        } else {
            None
        }
    }

    pub const fn min(self) -> BuilderBootAbi {
        self.min
    }

    pub const fn max(self) -> BuilderBootAbi {
        self.max
    }

    pub const fn contains(self, abi: BuilderBootAbi) -> bool {
        self.min.0 <= abi.0 && abi.0 <= self.max.0
    }
}

impl fmt::Display for BuilderBootAbiRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}..={}", self.min, self.max)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_range_contains_its_ends_and_nothing_outside() {
        let range = BuilderBootAbiRange::new(BuilderBootAbi::LEGACY, BuilderBootAbi::PAYLOAD)
            .expect("0..=1 is a range");
        assert!(range.contains(BuilderBootAbi::LEGACY));
        assert!(range.contains(BuilderBootAbi::PAYLOAD));
        assert!(!range.contains(BuilderBootAbi::NO_MVM_BINARY));
        assert_eq!(range.to_string(), "0..=1");
    }

    #[test]
    fn the_named_ranges_are_what_they_say() {
        assert_eq!(BuilderBootAbiRange::LEGACY_ONLY.to_string(), "0..=0");
        assert_eq!(BuilderBootAbiRange::WITH_PAYLOAD.to_string(), "0..=2");
    }

    #[test]
    fn a_payload_boots_every_defined_abi_and_nothing_above() {
        let range = BuilderBootAbiRange::WITH_PAYLOAD;
        for abi in [
            BuilderBootAbi::LEGACY,
            BuilderBootAbi::PAYLOAD,
            BuilderBootAbi::NO_MVM_BINARY,
        ] {
            assert!(range.contains(abi), "{abi}");
        }
        assert!(!range.contains(BuilderBootAbi::new(3)));
    }

    #[test]
    fn an_inverted_range_is_not_a_range() {
        assert!(
            BuilderBootAbiRange::new(BuilderBootAbi::PAYLOAD, BuilderBootAbi::LEGACY).is_none()
        );
    }

    #[test]
    fn the_abi_serializes_as_a_bare_integer() {
        assert_eq!(
            serde_json::to_string(&BuilderBootAbi::PAYLOAD).unwrap(),
            "1"
        );
        let abi: BuilderBootAbi = serde_json::from_str("0").unwrap();
        assert_eq!(abi, BuilderBootAbi::LEGACY);
    }
}
