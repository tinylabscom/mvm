//! Library surface for the dev-only cucumber-rs BDD conformance harness.
//!
//! `cucumber` is a dev-dependency of this crate, and Cargo never exposes a
//! package's dev-dependencies to its own `[lib]` target — only to the test
//! binary that links it — so the `World` type and the cucumber-attributed step
//! definitions live under `tests/` (see `tests/conformance.rs`). Step logic
//! that doesn't need cucumber's macros belongs here instead, so it can be
//! unit-tested independent of the cucumber runner. Not a dependency of any
//! shipped crate.

/// Cucumber tag for a scenario whose steps aren't implemented yet; always skipped.
pub const PENDING_TAG: &str = "wip";

/// Cucumber tag for a scenario that boots a real microVM and reaches the
/// network; opt in with `MVM_BDD_LIVE=1` (skipped in the default hermetic lane).
pub const LIVE_TAG: &str = "live";

/// Cucumber tag for a scenario that boots a real Firecracker microVM. Being a
/// real boot it also honors the `@live` opt-in (`MVM_BDD_LIVE`), and it runs
/// only where a usable `/dev/kvm` and a `firecracker` binary are both present —
/// skipped cleanly, never failed, elsewhere, so the suite stays green on hosts
/// without KVM (GitHub-hosted ARM runners, or any dev box lacking one).
pub const FIRECRACKER_TAG: &str = "firecracker";

/// Cucumber tag for a scenario that boots from a pre-built signed bundle.
/// Sealing a bundle means a full image build, far too slow to run inline, so
/// the operator supplies one with `MVM_BDD_BUNDLE=<path to .mvmpkg>` and the
/// scenario is skipped cleanly when that is absent.
pub const BUNDLE_TAG: &str = "bundle";

/// Host capabilities a scenario may require, probed once by the harness.
///
/// Plain data so [`scenario_should_run`] is a pure decision the harness can
/// unit-test without touching the environment.
#[derive(Debug, Clone, Copy)]
pub struct RuntimeCaps {
    /// `MVM_BDD_LIVE` is set — the operator opted into real-microVM scenarios.
    pub live_opted_in: bool,
    /// A usable `/dev/kvm` and a `firecracker` binary on `PATH` are both present,
    /// so a real Firecracker boot can run here.
    pub firecracker_bootable: bool,
    /// `MVM_BDD_BUNDLE` names a readable `.mvmpkg`, so a bundle-boot scenario
    /// has something to install.
    pub bundle_fixture: bool,
}

/// Decide whether a scenario with `tags` should run given the host `caps`.
///
/// A required capability that is absent yields a clean skip, never a failure.
/// Pure so it is unit-testable: the harness supplies real probed capabilities,
/// tests supply synthetic ones.
pub fn scenario_should_run(tags: &[String], caps: RuntimeCaps) -> bool {
    let tagged = |name: &str| tags.iter().any(|t| t == name);
    if tagged(PENDING_TAG) {
        return false;
    }
    if tagged(LIVE_TAG) && !caps.live_opted_in {
        return false;
    }
    // A firecracker scenario is a real boot, so it also requires the `@live`
    // opt-in and is additionally skipped where KVM or the binary is absent.
    if tagged(FIRECRACKER_TAG) && (!caps.live_opted_in || !caps.firecracker_bootable) {
        return false;
    }
    if tagged(BUNDLE_TAG) && !caps.bundle_fixture {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tags(names: &[&str]) -> Vec<String> {
        names.iter().map(|s| (*s).to_string()).collect()
    }

    const NONE: RuntimeCaps = RuntimeCaps {
        live_opted_in: false,
        firecracker_bootable: false,
        bundle_fixture: false,
    };
    const ALL: RuntimeCaps = RuntimeCaps {
        live_opted_in: true,
        firecracker_bootable: true,
        bundle_fixture: true,
    };

    #[test]
    fn bundle_scenario_skips_without_a_fixture() {
        // Everything else in place, but no `.mvmpkg` to install.
        assert!(!scenario_should_run(
            &tags(&["live", "firecracker", "bundle"]),
            RuntimeCaps {
                bundle_fixture: false,
                ..ALL
            },
        ));
        assert!(scenario_should_run(
            &tags(&["live", "firecracker", "bundle"]),
            ALL
        ));
    }

    #[test]
    fn untagged_scenario_always_runs() {
        assert!(scenario_should_run(&tags(&[]), NONE));
    }

    #[test]
    fn pending_scenario_never_runs_even_with_all_caps() {
        assert!(!scenario_should_run(&tags(&["wip"]), ALL));
    }

    #[test]
    fn live_scenario_skips_without_opt_in_but_runs_with_it() {
        assert!(!scenario_should_run(&tags(&["live"]), NONE));
        assert!(scenario_should_run(
            &tags(&["live"]),
            RuntimeCaps {
                live_opted_in: true,
                firecracker_bootable: false,
                bundle_fixture: false,
            },
        ));
    }

    #[test]
    fn firecracker_scenario_skips_cleanly_without_kvm_and_binary() {
        assert!(!scenario_should_run(
            &tags(&["live", "firecracker"]),
            RuntimeCaps {
                live_opted_in: true,
                firecracker_bootable: false,
                bundle_fixture: false,
            },
        ));
        assert!(scenario_should_run(&tags(&["live", "firecracker"]), ALL));
    }

    #[test]
    fn firecracker_scenario_also_requires_live_opt_in() {
        // KVM + firecracker present but no live opt-in → still skipped.
        assert!(!scenario_should_run(
            &tags(&["firecracker"]),
            RuntimeCaps {
                live_opted_in: false,
                firecracker_bootable: true,
                bundle_fixture: false,
            },
        ));
        // Live opt-in but missing capability → skipped.
        assert!(!scenario_should_run(
            &tags(&["firecracker"]),
            RuntimeCaps {
                live_opted_in: true,
                firecracker_bootable: false,
                bundle_fixture: false,
            },
        ));
        // Both present → runs.
        assert!(scenario_should_run(&tags(&["firecracker"]), ALL));
    }
}
