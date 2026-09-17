//! The live spawn-scope witnesses: do the CPU quota and the memory ceiling a
//! VMM spawn is wrapped in actually bind, and does a wedged service manager
//! fail the launch instead of hanging it?
//!
//! `#[ignore]` because they need a Linux host with a systemd **user session** —
//! the delegation the mechanism rests on hangs off that session, so this is not
//! something a CI container or a Mac can answer. Run them explicitly on a host
//! that has one:
//!
//! ```sh
//! cargo test -p mvm-core --test spawn_scope_live -- --ignored --nocapture --test-threads 1
//! ```
//!
//! The stopped-manager witness freezes this user's own manager for the length
//! of its deadline, so run it on a host where nothing else of that user's is
//! starting units.
//!
//! Each bound is asserted by *measurement*, not by reading back the file just
//! written. A test that checks `cpu.max` contains what was asked for proves the
//! write reached the kernel and nothing at all about whether the kernel then
//! throttled anything — and the write succeeding while the limit fails to bind
//! is exactly the failure this whole seam exists to catch.

use std::process::Command;
use std::time::{Duration, Instant};

use mvm_contract::grants::CpuGrant;
use mvm_contract::protocol::resource_controls::{EnforcedCeiling, EnforcedTier};
use mvm_core::spawn_scope::{self, SpawnBounds};

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
    if let Some(gap) = spawn_scope::mechanism_gap() {
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

    // A real state dir, because the scope's unit name is minted per boot and
    // recorded there — reconstructing it from the machine id is exactly what
    // the per-boot suffix made impossible.
    let state = tempfile::tempdir().expect("state dir");

    // The shipped call path, not a hand-rolled systemd-run line.
    let mut child = spawn_scope::bind_spawn(
        spinners,
        &machine_id,
        state.path(),
        &SpawnBounds::for_guest_memory(64).with_cpu_grant(Some(CpuGrant::Share {
            millicores: MILLICORES,
        })),
    )
    .spawn()
    .expect("spawning the bounded workload");

    // Let the scope register and the spinners get going before sampling.
    std::thread::sleep(std::time::Duration::from_millis(1500));

    let unit = spawn_scope::read_scope_unit(state.path())
        .expect("the scope name is recorded, without which no read-back is possible");

    let tier = spawn_scope::ScopeProbe::default()
        .readback_for_vm(state.path())
        .cpu;
    assert_eq!(
        tier,
        EnforcedTier::Cgroup2CpuMax,
        "a bound spawn must read back as enforced, not as declared"
    );

    let measured = measure_cores(&unit);
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

/// Guest RAM for the memory witness. Small, so the ceiling is reached quickly.
const GUEST_MIB: u32 = 64;

/// What the payload tries to hold: well past guest RAM plus the overhead.
const ALLOCATE_BYTES: u64 = 2 * 1024 * 1024 * 1024;

#[test]
#[ignore = "needs a Linux host with a systemd user session"]
fn a_spawn_past_its_memory_ceiling_is_killed_and_the_kill_is_recorded() {
    if let Some(gap) = spawn_scope::mechanism_gap() {
        panic!(
            "this witness needs the mechanism present: {}",
            gap.describe()
        );
    }

    let machine_id = format!("mvm-live-memory-{}", std::process::id());
    // `tail -n 1` holds a newline-free stream in memory whole, so this grows
    // resident memory without bound until something stops it. The pause gives
    // the read-back a live scope to read.
    let mut hog = Command::new("/bin/sh");
    hog.arg("-c").arg(format!(
        "sleep 1; head -c {ALLOCATE_BYTES} /dev/zero | tail -n 1 >/dev/null"
    ));
    let state = tempfile::tempdir().expect("state dir");

    let mut child = spawn_scope::bind_spawn(
        hog,
        &machine_id,
        state.path(),
        &SpawnBounds::for_guest_memory(GUEST_MIB),
    )
    .spawn()
    .expect("spawning the bounded workload");

    std::thread::sleep(Duration::from_millis(300));
    let readback = spawn_scope::ScopeProbe::default().readback_for_vm(state.path());
    let expected_bytes = spawn_scope::memory_max_bytes_for_guest(GUEST_MIB);
    println!("read back {readback:?}; expected memory.max {expected_bytes}");
    assert_eq!(
        readback.memory,
        EnforcedCeiling::enforced(EnforcedTier::Cgroup2MemoryMax, expected_bytes),
        "memory.max must read back as guest RAM plus the overhead"
    );
    assert_eq!(
        readback.tasks,
        EnforcedCeiling::enforced(
            EnforcedTier::Cgroup2PidsMax,
            u64::from(spawn_scope::VMM_TASKS_MAX)
        ),
    );

    let started = Instant::now();
    let status = child.wait().expect("waiting for the workload");
    println!("workload ended with {status} after {:?}", started.elapsed());
    assert!(
        !status.success(),
        "a workload holding {ALLOCATE_BYTES} bytes under a {expected_bytes}-byte ceiling          must not complete"
    );

    // The unit's result lands a beat after its last process is gone.
    let deadline = Instant::now() + Duration::from_secs(5);
    let exceeded = loop {
        if let Some(exceeded) =
            spawn_scope::ScopeProbe::default().memory_limit_exceeded(state.path())
        {
            break exceeded;
        }
        assert!(
            Instant::now() < deadline,
            "the scope never reported an OOM kill"
        );
        std::thread::sleep(Duration::from_millis(50));
    };
    println!("unit reported {exceeded:?}");
    assert_eq!(exceeded.memory_max_bytes, Some(expected_bytes));

    if let Some(unit) = spawn_scope::read_scope_unit(state.path()) {
        let _ = Command::new("systemctl")
            .args(["--user", "reset-failed", &unit])
            .status();
    }
}

#[test]
#[ignore = "needs a Linux host with a systemd user session, and freezes its manager"]
fn a_stopped_service_manager_fails_the_launch_at_the_deadline() {
    if let Some(gap) = spawn_scope::mechanism_gap() {
        panic!(
            "this witness needs the mechanism present: {}",
            gap.describe()
        );
    }
    let manager = ManagerFrozen::freeze();

    let state = tempfile::tempdir().expect("state dir");
    let mut payload = Command::new("/bin/true");
    payload.arg("never-runs");
    let started = Instant::now();
    let result = spawn_scope::bind_spawn(
        payload,
        &format!("mvm-live-frozen-{}", std::process::id()),
        state.path(),
        &SpawnBounds::for_guest_memory(GUEST_MIB),
    )
    .spawn();
    let elapsed = started.elapsed();
    drop(manager);

    let err = result.expect_err("a manager that never answers must fail the launch");
    println!("launch failed after {elapsed:?}: {err:#}");
    assert!(
        format!("{err:#}").contains("did not create scope"),
        "{err:#}"
    );
    assert!(
        elapsed >= spawn_scope::SCOPE_CREATION_TIMEOUT
            && elapsed < spawn_scope::SCOPE_CREATION_TIMEOUT + Duration::from_secs(5),
        "the launch must fail at its deadline, not before and not long after: {elapsed:?}"
    );
}

/// This user's systemd manager, stopped with SIGSTOP until dropped.
struct ManagerFrozen(String);

impl ManagerFrozen {
    fn freeze() -> Self {
        let uid = String::from_utf8(Command::new("id").arg("-u").output().expect("id -u").stdout)
            .expect("utf8 uid");
        let out = Command::new("pgrep")
            .args(["-u", uid.trim(), "-x", "systemd"])
            .output()
            .expect("pgrep the user manager");
        let pid = String::from_utf8_lossy(&out.stdout)
            .lines()
            .next()
            .expect("this user runs a systemd manager")
            .trim()
            .to_string();
        let stopped = Command::new("kill")
            .args(["-STOP", &pid])
            .status()
            .expect("kill -STOP");
        assert!(stopped.success(), "could not stop manager {pid}");
        Self(pid)
    }
}

impl Drop for ManagerFrozen {
    fn drop(&mut self) {
        let _ = Command::new("kill").args(["-CONT", &self.0]).status();
    }
}

/// Host CPU consumed by the scope over a sampling window, in cores.
///
/// Read from the cgroup's own `cpu.stat` rather than summed across
/// `/proc/<pid>/stat`: the cgroup accounts for every process in the scope,
/// including the ones that came and went during the window.
fn measure_cores(unit: &str) -> f64 {
    let before = usage_usec(unit);
    let start = Instant::now();
    std::thread::sleep(std::time::Duration::from_secs_f64(SAMPLE_SECS));
    let after = usage_usec(unit);
    let elapsed = start.elapsed().as_secs_f64();
    ((after - before) as f64 / 1_000_000.0) / elapsed
}

fn usage_usec(unit: &str) -> u64 {
    let cgroup = control_group(unit);
    let stat = std::fs::read_to_string(format!("/sys/fs/cgroup{cgroup}/cpu.stat"))
        .expect("reading the scope's cpu.stat");
    stat.lines()
        .find_map(|line| line.strip_prefix("usage_usec "))
        .and_then(|v| v.trim().parse().ok())
        .expect("cpu.stat carries usage_usec")
}

/// The unit name is passed in whole rather than rebuilt from the machine id:
/// it carries a per-boot suffix, so `{machine_id}.scope` no longer names it.
fn control_group(unit: &str) -> String {
    let out = Command::new("systemctl")
        .args(["--user", "show", unit, "-p", "ControlGroup", "--value"])
        .output()
        .expect("querying the scope's cgroup");
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}
