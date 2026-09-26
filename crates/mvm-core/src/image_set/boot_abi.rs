//! The builder boot ABI: what a builder image promises the `mvmctl` that
//! boots it.
//!
//! A builder image declares one integer in `/etc/mvm/builder-boot-abi`, and a
//! published set carries the same integer in its signed `[compatibility]`
//! section. The meaning of each value is fixed once released:
//!
//! - **0** — the legacy image. It carries no marker, and it bakes `mvmctl`'s
//!   builder binaries at `/sbin`. It boots either with those baked binaries or
//!   with the boot payload, whose binaries then win.
//! - **1** — the image carries no `mvmctl` binary at all. It boots only with
//!   the boot payload, which supplies `mvm-host-vm-init` and `mvm-builderd`.
//!
//! Both promise the rest of the builder's surface: `/run` is a mount point,
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
    /// No host binaries in the image; they arrive in the boot payload.
    pub const PAYLOAD: Self = Self(1);

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
        assert!(!range.contains(BuilderBootAbi::new(2)));
        assert_eq!(range.to_string(), "0..=1");
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
