//! Library surface for the dev-only cucumber-rs BDD conformance harness.
//!
//! `cucumber` is a dev-dependency of this crate, and Cargo never exposes a
//! package's dev-dependencies to its own `[lib]` target — only to the test
//! binary that links it — so the `World` type and the cucumber-attributed step
//! definitions live under `tests/` (see `tests/conformance.rs`). Step logic
//! that doesn't need cucumber's macros belongs here instead, so it can be
//! unit-tested independent of the cucumber runner. Not a dependency of any
//! shipped crate.

pub mod claims;
pub mod doc_examples;
pub mod source_commands;

/// Cucumber tag for a scenario whose steps aren't implemented yet; always skipped.
pub const PENDING_TAG: &str = "wip";

/// Cucumber tag for a scenario that boots a real microVM and reaches the
/// network; opt in with `MVM_BDD_LIVE=1` (skipped in the default hermetic lane).
pub const LIVE_TAG: &str = "live";

/// Cucumber tag for the narrow real-microVM lifecycle selected by the merge
/// queue. Selection stays inside [`scenario_gate_for_ci`] so it cannot replace
/// or bypass the live and Firecracker capability checks.
pub const CI_LIVE_TAG: &str = "ci_live";

/// Cucumber tag for a scenario that boots a real Firecracker microVM. Being a
/// real boot it also honors the `@live` opt-in (`MVM_BDD_LIVE`), and it runs
/// only where a usable `/dev/kvm` and a `firecracker` binary are both present —
/// skipped cleanly, never failed, elsewhere, so the suite stays green on hosts
/// without KVM (GitHub-hosted ARM runners, or any dev box lacking one).
pub const FIRECRACKER_TAG: &str = "firecracker";

/// Cucumber tag for a scenario that shells out to Node — the TypeScript
/// example checkers. A host without Node is a real configuration (the KVM
/// witness box is one), and failing there would report a missing toolchain as
/// a documentation defect. Gated rather than skipped inside the step, so the
/// run's own skip tally counts it instead of the scenario passing on no work.
pub const NODE_TAG: &str = "node";

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
    /// A `node` binary is resolvable, so the TypeScript example checkers can
    /// run at all.
    pub node_available: bool,
}

/// Decide whether a scenario with `tags` should run given the host `caps`.
///
/// A required capability that is absent yields a clean skip, never a failure.
/// Pure so it is unit-testable: the harness supplies real probed capabilities,
/// tests supply synthetic ones.
pub fn scenario_should_run(tags: &[String], caps: RuntimeCaps) -> bool {
    matches!(scenario_gate(tags, caps), ScenarioGate::Run)
}

/// Why a scenario runs or does not.
///
/// `scenario_should_run` collapses this to a bool, which is all the cucumber
/// filter needs — but a bool cannot be counted by reason, and a suite that
/// reports nothing about what it declined to attempt reads as full coverage
/// when it is not. The harness tallies these and says so.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScenarioGate {
    /// The scenario runs.
    Run,
    /// Tagged `@wip`: unfinished by declaration, not by capability.
    Pending,
    /// Tagged `@live` on a host that did not opt in (`MVM_BDD_LIVE` unset).
    /// This is the one that matters: these are the scenarios that boot a real
    /// microVM, and skipping them is why a change can break every guest boot
    /// with a green suite.
    NeedsLiveOptIn,
    /// Opted into live, but this host cannot boot Firecracker — no `/dev/kvm`
    /// this process can open, or no `firecracker` on `PATH`.
    NeedsFirecracker,
    /// No `.mvmpkg` for a bundle-boot scenario to install.
    NeedsBundleFixture,
    /// No `node` on `PATH`, so the TypeScript example checkers cannot run.
    NeedsNode,
    /// The merge-queue lane selected only `@ci_live` scenarios, and this
    /// scenario is outside that deliberately narrow subset.
    OutsideCiLiveSubset,
}

/// The reason behind [`scenario_should_run`]. Same order of checks, so the two
/// cannot disagree about whether a scenario runs.
pub fn scenario_gate(tags: &[String], caps: RuntimeCaps) -> ScenarioGate {
    let tagged = |name: &str| tags.iter().any(|t| t == name);
    if tagged(PENDING_TAG) {
        return ScenarioGate::Pending;
    }
    if tagged(LIVE_TAG) && !caps.live_opted_in {
        return ScenarioGate::NeedsLiveOptIn;
    }
    // A firecracker scenario is a real boot, so it also requires the `@live`
    // opt-in and is additionally skipped where KVM or the binary is absent.
    if tagged(FIRECRACKER_TAG) && !caps.live_opted_in {
        return ScenarioGate::NeedsLiveOptIn;
    }
    if tagged(FIRECRACKER_TAG) && !caps.firecracker_bootable {
        return ScenarioGate::NeedsFirecracker;
    }
    if tagged(BUNDLE_TAG) && !caps.bundle_fixture {
        return ScenarioGate::NeedsBundleFixture;
    }
    if tagged(NODE_TAG) && !caps.node_available {
        return ScenarioGate::NeedsNode;
    }
    ScenarioGate::Run
}

/// Apply the merge-queue subset selection without replacing the capability
/// checks. Cucumber's command-line tag filter replaces the programmatic
/// filter; keeping the selection here makes a missing live opt-in or KVM
/// capability continue to fail closed.
pub fn scenario_gate_for_ci(
    tags: &[String],
    caps: RuntimeCaps,
    ci_live_only: bool,
) -> ScenarioGate {
    if ci_live_only && !tags.iter().any(|tag| tag == CI_LIVE_TAG) {
        return ScenarioGate::OutsideCiLiveSubset;
    }
    scenario_gate(tags, caps)
}

impl ScenarioGate {
    /// What to tell the operator, in the summary line.
    pub fn reason(self) -> Option<&'static str> {
        match self {
            Self::Run => None,
            Self::Pending => Some("@wip"),
            Self::NeedsLiveOptIn => Some("need MVM_BDD_LIVE (these boot a real microVM)"),
            Self::NeedsFirecracker => Some("need /dev/kvm + firecracker on PATH"),
            Self::NeedsBundleFixture => Some("need MVM_BDD_BUNDLE to name a readable .mvmpkg"),
            Self::NeedsNode => Some("need node on PATH (TypeScript example checkers)"),
            Self::OutsideCiLiveSubset => Some("outside the merge-queue @ci_live subset"),
        }
    }
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
        node_available: false,
    };
    const ALL: RuntimeCaps = RuntimeCaps {
        live_opted_in: true,
        firecracker_bootable: true,
        bundle_fixture: true,
        node_available: false,
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
                node_available: false,
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
                node_available: false,
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
                node_available: false,
            },
        ));
        // Live opt-in but missing capability → skipped.
        assert!(!scenario_should_run(
            &tags(&["firecracker"]),
            RuntimeCaps {
                live_opted_in: true,
                firecracker_bootable: false,
                bundle_fixture: false,
                node_available: false,
            },
        ));
        // Both present → runs.
        assert!(scenario_should_run(&tags(&["firecracker"]), ALL));
    }

    /// The gate and the bool must never disagree about whether a scenario runs
    /// — they are read by the same filter, and a divergence would make the
    /// summary describe a different run than the one that happened.
    #[test]
    fn the_gate_and_the_bool_agree_on_every_shape() {
        let caps = [
            RuntimeCaps {
                live_opted_in: false,
                firecracker_bootable: false,
                bundle_fixture: false,
                node_available: false,
            },
            RuntimeCaps {
                live_opted_in: true,
                firecracker_bootable: false,
                bundle_fixture: false,
                node_available: false,
            },
            RuntimeCaps {
                live_opted_in: true,
                firecracker_bootable: true,
                bundle_fixture: false,
                node_available: false,
            },
            RuntimeCaps {
                live_opted_in: true,
                firecracker_bootable: true,
                bundle_fixture: true,
                node_available: false,
            },
            RuntimeCaps {
                live_opted_in: false,
                firecracker_bootable: true,
                bundle_fixture: true,
                node_available: false,
            },
        ];
        let shapes = [
            tags(&[]),
            tags(&[PENDING_TAG]),
            tags(&[LIVE_TAG]),
            tags(&[FIRECRACKER_TAG]),
            tags(&[LIVE_TAG, FIRECRACKER_TAG]),
            tags(&[BUNDLE_TAG]),
            tags(&[LIVE_TAG, FIRECRACKER_TAG, BUNDLE_TAG]),
        ];
        for c in caps {
            for t in &shapes {
                assert_eq!(
                    scenario_should_run(t, c),
                    scenario_gate(t, c) == ScenarioGate::Run,
                    "tags {t:?} caps {c:?}"
                );
            }
        }
    }

    /// Each skip reason is distinguishable, because the whole point is to
    /// count them separately. `@live` without the opt-in is the one that
    /// matters most — those are the scenarios that boot a real microVM.
    #[test]
    fn each_skip_reason_is_reported_distinctly() {
        let none = RuntimeCaps {
            live_opted_in: false,
            firecracker_bootable: false,
            bundle_fixture: false,
            node_available: false,
        };
        let live_only = RuntimeCaps {
            live_opted_in: true,
            firecracker_bootable: false,
            bundle_fixture: false,
            node_available: false,
        };
        let bootable = RuntimeCaps {
            live_opted_in: true,
            firecracker_bootable: true,
            bundle_fixture: false,
            node_available: false,
        };

        assert_eq!(
            scenario_gate(&tags(&[PENDING_TAG]), bootable),
            ScenarioGate::Pending
        );
        assert_eq!(
            scenario_gate(&tags(&[LIVE_TAG]), none),
            ScenarioGate::NeedsLiveOptIn
        );
        // Opted in, but this host cannot boot: a different problem with a
        // different fix, and it must not be reported as "you forgot the flag".
        assert_eq!(
            scenario_gate(&tags(&[FIRECRACKER_TAG]), live_only),
            ScenarioGate::NeedsFirecracker
        );
        assert_eq!(
            scenario_gate(&tags(&[BUNDLE_TAG]), bootable),
            ScenarioGate::NeedsBundleFixture
        );
        assert_eq!(scenario_gate(&tags(&[]), none), ScenarioGate::Run);

        // Every non-Run gate explains itself; Run has nothing to explain.
        assert!(ScenarioGate::Run.reason().is_none());
        for g in [
            ScenarioGate::Pending,
            ScenarioGate::NeedsLiveOptIn,
            ScenarioGate::NeedsFirecracker,
            ScenarioGate::NeedsBundleFixture,
            ScenarioGate::OutsideCiLiveSubset,
        ] {
            assert!(g.reason().is_some(), "{g:?} must say why");
        }
    }

    #[test]
    fn ci_subset_selection_preserves_live_and_firecracker_gates() {
        let selected = tags(&[LIVE_TAG, FIRECRACKER_TAG, CI_LIVE_TAG]);
        assert_eq!(
            scenario_gate_for_ci(&selected, NONE, true),
            ScenarioGate::NeedsLiveOptIn
        );
        assert_eq!(
            scenario_gate_for_ci(
                &selected,
                RuntimeCaps {
                    live_opted_in: true,
                    firecracker_bootable: false,
                    bundle_fixture: false,
                    node_available: false,
                },
                true,
            ),
            ScenarioGate::NeedsFirecracker
        );
        assert_eq!(
            scenario_gate_for_ci(&selected, ALL, true),
            ScenarioGate::Run
        );
        assert_eq!(
            scenario_gate_for_ci(&tags(&[LIVE_TAG]), ALL, true),
            ScenarioGate::OutsideCiLiveSubset
        );
        assert_eq!(
            scenario_gate_for_ci(&tags(&[]), NONE, false),
            ScenarioGate::Run
        );
    }
}
