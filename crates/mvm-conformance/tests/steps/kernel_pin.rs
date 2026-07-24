//! Steps for the kernel-pin freshness watcher contract. These drive the pure
//! `mvm_core::kernel_advisory::assess` decision — no I/O, no network, no VM —
//! so they run in the normal hermetic BDD gate. The xtask shell that fetches
//! upstream releases and reads the local pins is exercised separately; here we
//! pin down the security-relevant verdict: a trailing pin recommends a bump,
//! matched pins do not, and missing knowledge never recommends action.

use cucumber::{given, then, when};
use mvm_core::kernel_advisory::{KernelPin, Staleness, UpstreamReleases, assess};

use crate::world::CliWorld;

#[given(expr = "a local kernel pin {string} at version {string}")]
fn local_pin(world: &mut CliWorld, name: String, version: String) {
    world.kernel_pins.push(KernelPin { name, version });
}

#[given(expr = "the latest upstream point release for series {string} is {string}")]
fn upstream_release(world: &mut CliWorld, series: String, latest: String) {
    world.kernel_upstream.insert(series, latest);
}

#[given("no upstream release data")]
fn no_upstream(world: &mut CliWorld) {
    world.kernel_upstream.clear();
}

#[when("the kernel pin freshness is assessed")]
fn assess_freshness(world: &mut CliWorld) {
    let upstream = UpstreamReleases {
        latest_by_series: world.kernel_upstream.clone(),
    };
    world.kernel_advisory = Some(assess(&world.kernel_pins, &upstream));
}

#[then("the advisory recommends action")]
fn recommends_action(world: &mut CliWorld) {
    assert!(
        world.advisory().action_recommended,
        "expected a bump to be recommended: {:?}",
        world.advisory()
    );
}

#[then("the advisory does not recommend action")]
fn no_action(world: &mut CliWorld) {
    assert!(
        !world.advisory().action_recommended,
        "expected no bump to be recommended: {:?}",
        world.advisory()
    );
}

#[then("every assessed pin is reported up to date")]
fn all_up_to_date(world: &mut CliWorld) {
    for (pin, staleness) in &world.advisory().pins {
        assert!(
            matches!(staleness, Staleness::UpToDate),
            "expected pin {:?} up to date, got {staleness:?}",
            pin.name
        );
    }
}

#[then(expr = "the worst pin is reported behind by {int} patch releases")]
fn worst_behind_by(world: &mut CliWorld, gap: u32) {
    match &world.advisory().worst {
        Staleness::Behind { patch_gap, .. } => assert_eq!(
            *patch_gap, gap,
            "expected worst pin behind by {gap}, got {patch_gap}"
        ),
        other => panic!("expected worst pin behind by {gap}, got {other:?}"),
    }
}

#[then("the worst pin status is unknown")]
fn worst_unknown(world: &mut CliWorld) {
    assert!(
        matches!(world.advisory().worst, Staleness::Unknown { .. }),
        "expected worst pin status unknown, got {:?}",
        world.advisory().worst
    );
}
