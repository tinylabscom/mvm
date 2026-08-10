//! The live CPU-bound witness: does a `CpuGrant::Share` actually bind?
//!
//! `#[ignore]` because it needs a Linux host with a systemd **user session** —
//! the delegation the mechanism rests on hangs off that session, so this is not
//! something a CI container or a Mac can answer. Run it explicitly on a host
//! that has one:
//!
//! ```sh
//! cargo test -p mvm-core --test cpu_scope_live -- --ignored --nocapture
//! ```
//!
//! It asserts the bound by *measurement*, not by reading back the file it just
//! wrote. A test that checks `cpu.max` contains what was asked for proves the
//! write reached the kernel and nothing at all about whether the kernel then
//! throttled anything — and the write succeeding while the limit fails to bind
//! is exactly the failure this whole seam exists to catch.

use std::process::Command;
use std::time::Instant;

use mvm_contract::grants::CpuGrant;
use mvm_contract::protocol::resource_controls::EnforcedTier;
use mvm_core::cpu_scope;

/// 1.5 cores, the share the mechanism spike measured against.
const MILLICORES: u32 = 1500;
const TARGET_CORES: f64 = 1.5;

/// More spinners than the quota allows, so an unbounded run is unmistakable:
/// four busy loops take ~4 cores where the grant permits 1.5.
const SPINNERS: usize = 4;
const SPIN_SECS: u64 = 10;
const SAMPLE_SECS: f64 = 5.0;

/// The measured share may sit slightly under the target (the kernel throttles at
/// period boundaries) but must never sit above it. 5% of a core each way is
/// generous enough not to flake and far tighter than the ~4 cores an unbounded
/// run would show.
const TOLERANCE_CORES: f64 = 0.05;

#[test]
#[ignore = "needs a Linux host with a systemd user session"]
fn a_granted_cpu_share_binds_a_real_spawn_to_its_quota() {
    if let Some(gap) = cpu_scope::mechanism_gap() {
        panic!(
            "this witness needs the mechanism present: {}",
            gap.describe()
        );
    }

    let machine_id = format!("mvm-live-witness-{}", std::process::id());
    let mut spinners = Command::new("/bin/sh");
    spinners.arg("-c").arg(format!(
        "for i in $(seq 1 {SPINNERS}); do ( end=$(($(date +%s)+{SPIN_SECS})); \
         while [ $(date +%s) -lt $end ]; do :; done ) & done; wait"
    ));

    // The shipped call path, not a hand-rolled systemd-run line.
    let mut child = cpu_scope::bind_cpu_grant(
        spinners,
        &machine_id,
        Some(&CpuGrant::Share {
            millicores: MILLICORES,
        }),
    )
    .spawn()
    .expect("spawning the bounded workload");

    // Let the scope register and the spinners get going before sampling.
    std::thread::sleep(std::time::Duration::from_millis(1500));

    let tier = cpu_scope::read_back_tier(&machine_id).expect("reading the tier back");
    assert_eq!(
        tier,
        EnforcedTier::Cgroup2CpuMax,
        "a bound spawn must read back as enforced, not as declared"
    );

    let measured = measure_cores(&machine_id);
    let _ = child.wait();

    println!("measured {measured:.4} cores against a {TARGET_CORES}-core target");
    assert!(
        measured <= TARGET_CORES + TOLERANCE_CORES,
        "the bound did not hold: {measured:.4} cores against a {TARGET_CORES}-core grant"
    );
    assert!(
        measured >= TARGET_CORES - TOLERANCE_CORES,
        "the workload never reached its grant ({measured:.4} cores); the sample is not \
         evidence the quota bound anything"
    );
}

/// Host CPU consumed by the scope over a sampling window, in cores.
///
/// Read from the cgroup's own `cpu.stat` rather than summed across
/// `/proc/<pid>/stat`: the cgroup accounts for every process in the scope,
/// including the ones that came and went during the window.
fn measure_cores(machine_id: &str) -> f64 {
    let before = usage_usec(machine_id);
    let start = Instant::now();
    std::thread::sleep(std::time::Duration::from_secs_f64(SAMPLE_SECS));
    let after = usage_usec(machine_id);
    let elapsed = start.elapsed().as_secs_f64();
    ((after - before) as f64 / 1_000_000.0) / elapsed
}

fn usage_usec(machine_id: &str) -> u64 {
    let cgroup = control_group(machine_id);
    let stat = std::fs::read_to_string(format!("/sys/fs/cgroup{cgroup}/cpu.stat"))
        .expect("reading the scope's cpu.stat");
    stat.lines()
        .find_map(|line| line.strip_prefix("usage_usec "))
        .and_then(|v| v.trim().parse().ok())
        .expect("cpu.stat carries usage_usec")
}

fn control_group(machine_id: &str) -> String {
    let out = Command::new("systemctl")
        .args([
            "--user",
            "show",
            &format!("{machine_id}.scope"),
            "-p",
            "ControlGroup",
            "--value",
        ])
        .output()
        .expect("querying the scope's cgroup");
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}
