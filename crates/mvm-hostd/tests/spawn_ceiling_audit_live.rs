//! Live witnesses for the spawn-time memory and task ceilings on a real VMM:
//! the ceiling a guest's scope carries reads back as guest RAM plus the
//! overhead margin, and a VMM pushed past it is killed and leaves a
//! chain-signed entry.
//!
//! `#[ignore]` because they need a Linux host with a systemd user session and a
//! VMM to run. The VMM command line is supplied, whitespace-separated, in
//! `MVM_LIVE_VMM_ARGV`; it should start a guest of `MVM_LIVE_GUEST_MIB` MiB
//! that holds all of its RAM (a preallocating VMM does), so the kill witness can
//! bound it as a smaller guest and watch it cross the ceiling:
//!
//! ```sh
//! MVM_LIVE_GUEST_MIB=512 \
//! MVM_LIVE_VMM_ARGV="qemu-system-x86_64 -machine microvm,accel=kvm -m 512 -mem-prealloc \
//!   -display none -serial null -nodefaults -kernel /path/to/kernel -append console=ttyS0" \
//! cargo test -p mvm-hostd --test spawn_ceiling_audit_live -- --ignored --nocapture --test-threads 1
//! ```

use std::process::Command;
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use mvm_contract::protocol::resource_controls::{EnforcedCeiling, EnforcedTier};
use mvm_core::spawn_scope::{self, ScopeProbe, SpawnBounds};
use mvm_hostd::audit::emitter::{AuditEmitter, grants_audit};

/// Guest RAM the kill witness bounds the VMM as. Far below what the VMM holds,
/// so the ceiling is crossed during boot.
const UNDERSIZED_GUEST_MIB: u32 = 64;

fn require_mechanism() {
    if let Some(gap) = spawn_scope::mechanism_gap() {
        panic!(
            "this witness needs the mechanism present: {}",
            gap.describe()
        );
    }
}

fn vmm_command() -> Command {
    let argv = std::env::var("MVM_LIVE_VMM_ARGV")
        .expect("MVM_LIVE_VMM_ARGV names the VMM command line to run");
    let mut words = argv.split_whitespace();
    let mut cmd = Command::new(words.next().expect("a VMM program"));
    cmd.args(words);
    cmd
}

fn guest_mib() -> u32 {
    std::env::var("MVM_LIVE_GUEST_MIB")
        .expect("MVM_LIVE_GUEST_MIB is the guest RAM the VMM command boots")
        .parse()
        .expect("MVM_LIVE_GUEST_MIB is a number")
}

fn emitter_in(dir: &std::path::Path) -> (AuditEmitter, ed25519_dalek::VerifyingKey) {
    let key = SigningKey::from_bytes(&[7; 32]);
    let verifying = key.verifying_key();
    (
        AuditEmitter::with_dir(key, dir).expect("emitter"),
        verifying,
    )
}

fn plan(plan_id: &str) -> mvm_core::plan::ExecutionPlan {
    mvm_core::plan::test_support::PlanFixture::new()
        .tenant("local")
        .plan_id(plan_id)
        .build()
}

#[test]
#[ignore = "needs a Linux host with a systemd user session and a VMM"]
fn a_scoped_vmm_reads_back_guest_ram_plus_the_overhead() {
    require_mechanism();
    let guest = guest_mib();
    let state = tempfile::tempdir().expect("state dir");
    let machine_id = format!("mvm-live-ceiling-{}", std::process::id());

    let mut child = spawn_scope::bind_spawn(
        vmm_command(),
        &machine_id,
        state.path(),
        &SpawnBounds::for_guest_memory(guest),
    )
    .spawn()
    .expect("spawning the scoped VMM");
    std::thread::sleep(Duration::from_secs(3));
    assert!(
        child.try_wait().expect("poll").is_none(),
        "a VMM within its ceiling must still be running"
    );

    let enforced = spawn_scope::enforced_grants_for_vm(state.path());
    println!("guest {guest} MiB read back {enforced:?}");
    assert_eq!(
        enforced.memory,
        EnforcedCeiling::enforced(
            EnforcedTier::Cgroup2MemoryMax,
            spawn_scope::memory_max_bytes_for_guest(guest)
        )
    );
    assert_eq!(
        enforced.tasks,
        EnforcedCeiling::enforced(
            EnforcedTier::Cgroup2PidsMax,
            u64::from(spawn_scope::VMM_TASKS_MAX)
        )
    );

    let audit = tempfile::tempdir().expect("audit dir");
    let (emitter, verifying) = emitter_in(audit.path());
    emitter
        .emit_grants_enforced(&plan("plan-LIVE-CEILING"), &enforced)
        .expect("audit the read-back");
    let chain = audit.path().join("local.jsonl");
    let content = std::fs::read_to_string(&chain).expect("chain written");
    println!("{content}");
    let expected_bytes = spawn_scope::memory_max_bytes_for_guest(guest).to_string();
    assert!(content.contains(grants_audit::LABEL_MEMORY_MAX_BYTES));
    assert!(content.contains(&expected_bytes), "{content}");
    mvm_hostd::supervisor::verify_audit_chain(&chain, &verifying).expect("chain verifies");

    let unit = spawn_scope::read_scope_unit(state.path()).expect("recorded unit");
    let _ = Command::new("systemctl")
        .args(["--user", "stop", &unit])
        .status();
    let _ = child.wait();
}

#[test]
#[ignore = "needs a Linux host with a systemd user session and a VMM"]
fn a_vmm_pushed_past_its_memory_ceiling_is_killed_and_audited() {
    require_mechanism();
    let state = tempfile::tempdir().expect("state dir");
    let machine_id = format!("mvm-live-overrun-{}", std::process::id());

    let started = Instant::now();
    let mut child = spawn_scope::bind_spawn(
        vmm_command(),
        &machine_id,
        state.path(),
        &SpawnBounds::for_guest_memory(UNDERSIZED_GUEST_MIB),
    )
    .spawn()
    .expect("spawning the scoped VMM");
    let status = child.wait().expect("waiting for the VMM");
    println!("VMM ended with {status} after {:?}", started.elapsed());
    assert!(!status.success(), "a VMM over its ceiling must not survive");

    let deadline = Instant::now() + Duration::from_secs(5);
    let exceeded = loop {
        if let Some(exceeded) = ScopeProbe::default().memory_limit_exceeded(state.path()) {
            break exceeded;
        }
        assert!(
            Instant::now() < deadline,
            "the scope never reported an OOM kill"
        );
        std::thread::sleep(Duration::from_millis(50));
    };
    println!("unit reported {exceeded:?}");
    assert_eq!(
        exceeded.memory_max_bytes,
        Some(spawn_scope::memory_max_bytes_for_guest(
            UNDERSIZED_GUEST_MIB
        ))
    );

    let audit = tempfile::tempdir().expect("audit dir");
    let (emitter, verifying) = emitter_in(audit.path());
    emitter
        .emit_memory_limit_exceeded(&plan("plan-LIVE-OVERRUN"), &exceeded)
        .expect("audit the kill");
    let chain = audit.path().join("local.jsonl");
    let content = std::fs::read_to_string(&chain).expect("chain written");
    println!("{content}");
    assert!(content.contains(grants_audit::MEMORY_LIMIT_EXCEEDED_EVENT));
    mvm_hostd::supervisor::verify_audit_chain(&chain, &verifying).expect("chain verifies");

    if let Some(unit) = spawn_scope::read_scope_unit(state.path()) {
        let _ = Command::new("systemctl")
            .args(["--user", "reset-failed", &unit])
            .status();
    }
}
