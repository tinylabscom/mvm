//! Whether a builder guest may fall back to a tmpfs Nix store, or must stop.
//!
//! Stage 0 prefers a persistent ext4 store disk and falls back to copying the
//! seed into a tmpfs when there is none. That fallback is deliberate — it keeps
//! bootstrap working on a host with no `mkfs.ext4` and a blank disk — but it is
//! only correct when the store is genuinely *absent*.
//!
//! When a disk is present and unusable the fallback is actively harmful: the
//! tmpfs is sized by guest RAM, so a large build dies thousands of lines later
//! on `No space left on device`, naming neither the disk nor the fallback. That
//! is exactly how a re-lettered device — a 32 KiB identity image mounted as the
//! Nix store — cost an afternoon to diagnose.
//!
//! The decision is a pure function over [`StoreProbe`] so the part that has to
//! be right is testable without booting a guest, mirroring
//! [`crate::egress_readiness`].

/// A store disk smaller than this cannot hold a builder closure, so a device
/// this size is a misidentified disk rather than an empty store.
///
/// Deliberately far below any real store (they are gigabytes) and far above the
/// identity drive that was actually being mounted (32 KiB), so the check
/// catches a wrong device without second-guessing a legitimately small one.
pub const MIN_PLAUSIBLE_STORE_BYTES: u64 = 64 * 1024 * 1024;

/// How the search for a persistent store ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreProbe {
    /// A usable store disk was mounted.
    Mounted { device: String },
    /// No disk carries the store label and no fallback device exists. The
    /// tmpfs copy is the intended behaviour here.
    Absent,
    /// A device was identified as the store but is too small to be one.
    ImplausiblySmall { device: String, bytes: u64 },
    /// A store device was found but could not be mounted or prepared.
    Unusable { device: String, why: String },
}

/// Decide whether the guest may proceed, and on what.
///
/// `Ok(Some(dev))` mounts that store, `Ok(None)` takes the tmpfs fallback, and
/// `Err` stops the build while the cause is still on screen.
pub fn store_readiness_outcome(probe: StoreProbe) -> Result<Option<String>, String> {
    let cost = "the tmpfs fallback is sized by guest RAM and cannot hold a large build";
    match probe {
        StoreProbe::Mounted { device } => Ok(Some(device)),
        StoreProbe::Absent => Ok(None),
        StoreProbe::ImplausiblySmall { device, bytes } => Err(format!(
            "{device} was selected as the Stage 0 Nix store but is {bytes} bytes, \
             below the {MIN_PLAUSIBLE_STORE_BYTES}-byte floor for a store disk; \
             it is a different device, not an empty store, so refusing rather than \
             falling back — {cost}"
        )),
        StoreProbe::Unusable { device, why } => Err(format!(
            "the Stage 0 Nix store disk {device} is present but unusable ({why}); \
             refusing rather than falling back — {cost}"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_mounted_store_is_used() {
        assert_eq!(
            store_readiness_outcome(StoreProbe::Mounted {
                device: "/dev/vdg".into()
            }),
            Ok(Some("/dev/vdg".to_string()))
        );
    }

    /// The fallback exists for this case and must keep working: a host with no
    /// `mkfs.ext4` and no store disk still bootstraps.
    #[test]
    fn an_absent_store_falls_back_to_tmpfs() {
        assert_eq!(store_readiness_outcome(StoreProbe::Absent), Ok(None));
    }

    /// The regression this module exists for: a re-lettered device handed the
    /// guest a 32 KiB identity image, which it accepted as an empty store.
    #[test]
    fn an_identity_sized_device_is_refused_rather_than_treated_as_an_empty_store() {
        let err = store_readiness_outcome(StoreProbe::ImplausiblySmall {
            device: "/dev/vde".into(),
            bytes: 32 * 1024,
        })
        .expect_err("a 32 KiB disk is not a Nix store");
        assert!(err.contains("/dev/vde"), "{err}");
        assert!(err.contains("32768"), "{err}");
        assert!(err.contains("different device"), "{err}");
    }

    #[test]
    fn a_present_but_unmountable_store_refuses_instead_of_degrading() {
        let err = store_readiness_outcome(StoreProbe::Unusable {
            device: "/dev/vdg".into(),
            why: "EACCES: Permission denied".into(),
        })
        .expect_err("an unusable store must stop the build");
        assert!(err.contains("/dev/vdg"), "{err}");
        assert!(err.contains("EACCES"), "{err}");
    }

    /// Every refusal has to say why falling back would be worse, because the
    /// failure it prevents surfaces far from here.
    #[test]
    fn every_refusal_names_the_cost_of_the_fallback() {
        for probe in [
            StoreProbe::ImplausiblySmall {
                device: "/dev/vde".into(),
                bytes: 1,
            },
            StoreProbe::Unusable {
                device: "/dev/vdg".into(),
                why: "bad superblock".into(),
            },
        ] {
            let err = store_readiness_outcome(probe.clone()).expect_err("must refuse");
            assert!(
                err.contains("sized by guest RAM"),
                "{probe:?} must explain the fallback's limit: {err}"
            );
        }
    }

    /// The floor must sit between a real store and the identity drive that was
    /// being mistaken for one. Asserted through the decision rather than on the
    /// constant, so this stays a behavioural test rather than a tautology.
    #[test]
    fn the_floor_refuses_an_identity_drive_and_admits_a_real_store() {
        let verdict = |bytes: u64| {
            if bytes < MIN_PLAUSIBLE_STORE_BYTES {
                store_readiness_outcome(StoreProbe::ImplausiblySmall {
                    device: "/dev/vdx".into(),
                    bytes,
                })
            } else {
                store_readiness_outcome(StoreProbe::Mounted {
                    device: "/dev/vdx".into(),
                })
            }
        };
        // The drive that was actually being mounted as the store.
        assert!(verdict(32 * 1024).is_err(), "a 32 KiB disk must be refused");
        // A real store, orders of magnitude larger.
        assert!(
            verdict(64 * 1024 * 1024 * 1024).is_ok(),
            "a 64 GiB store must be admitted"
        );
    }
}
