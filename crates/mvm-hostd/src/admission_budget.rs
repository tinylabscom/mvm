//! The host-wide side of admission: does the *sum* still fit.
//!
//! The per-workload ceiling bounds one VM. Nothing bounded the total, so a
//! host could be oversubscribed into thrashing by a sequence of individually
//! well-formed grants. This module measures what is already committed and
//! hands the decision to [`HostBudget`], which is pure arithmetic.
//!
//! # Two properties this module exists to get right
//!
//! **It counts only what is live.** A total summed from every VM record on
//! disk would refuse every subsequent boot forever the moment one VM crashed
//! without cleanup — the safety check becoming a permanent lockout, which is a
//! worse failure than the oversubscription it prevents. Liveness here is the
//! same pid-marker probe the fork path trusts
//! ([`state_dir_has_live_process`]), not a second notion of "running" that
//! could disagree with it.
//!
//! **It counts the configured maximum, not current usage.** The charge is
//! recorded once, at the boot admission granted it, and is never rewritten.
//! The balloon controller moves a running VM's host commitment down under
//! pressure and back up when the guest needs its pages; summing that figure
//! would re-admit memory the host has already promised and discover the
//! overcommit when both guests want their pages at once.
//!
//! # What it does not do
//!
//! Two admissions racing each other can both read the same total and both be
//! admitted, overshooting by one boot. Closing that needs a host-wide lock
//! held across measure-and-start, which is a larger change than the bound is
//! worth: the failure it prevents is a slow slide into thrash across many
//! boots, not a precise cliff at boot N.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use mvm_contract::grants::budget::{HostBudget, MachineCharge};
use mvm_contract::grants::{CpuGrant, Grants};
use mvm_vmm::host::process_liveness::state_dir_has_live_process;

/// File name of the per-VM charge record, written into the VM's state dir at
/// boot and read back by every later admission.
const CHARGE_FILE: &str = "admitted-charge.json";

/// Path of the charge record for a machine, beneath an explicit mvm home.
fn charge_path_at(mvm_home: &Path, vm_name: &str) -> PathBuf {
    mvm_core::config::vm_state_dir_at(mvm_home, vm_name).join(CHARGE_FILE)
}

/// What a boot commits, derived from the figures admission granted it.
///
/// `memory_mib` is the plan's configured guest RAM — the same number
/// `BalloonState::max_mib` mirrors at boot, and the one the balloon may not
/// exceed. `cpu_millicores` is the granted share, or zero for a workload that
/// declared none.
#[must_use]
pub fn charge_for(mem_mib: u64, grants: &Grants) -> MachineCharge {
    MachineCharge {
        memory_mib: mem_mib,
        cpu_millicores: match grants.cpu {
            Some(CpuGrant::Share { millicores }) => millicores,
            // Fuel is an instruction count, not a fraction of a host core.
            // Charging it against a millicore budget would be adding two
            // different units, so a fuel-bounded workload contributes nothing
            // to the CPU total — the same answer as an ungranted one.
            Some(CpuGrant::Fuel { .. }) | None => 0,
        },
    }
}

/// Persist what this boot was admitted with, so later admissions can count it.
///
/// Written after the backend has started the VM, into the state dir the
/// backend created. A failure here is returned rather than logged: a machine
/// running without a charge record is invisible to every later budget check,
/// which is the silent-undercount failure this whole module exists to avoid.
///
/// # Errors
///
/// If the state directory is absent or the record cannot be written.
pub fn record_charge(vm_name: &str, charge: MachineCharge) -> Result<()> {
    record_charge_at(Path::new(&mvm_core::config::mvm_home()), vm_name, charge)
}

/// [`record_charge`] beneath an explicit mvm home.
///
/// # Errors
///
/// If the record cannot be written.
pub fn record_charge_at(mvm_home: &Path, vm_name: &str, charge: MachineCharge) -> Result<()> {
    let path = charge_path_at(mvm_home, vm_name);
    let dir = path
        .parent()
        .context("a charge record path always has a parent state dir")?;
    std::fs::create_dir_all(dir)
        .with_context(|| format!("creating the VM state dir {}", dir.display()))?;
    let json = serde_json::to_vec(&charge).context("serializing the admitted charge")?;
    std::fs::write(&path, json)
        .with_context(|| format!("writing the admitted charge to {}", path.display()))
}

/// Sum what every live machine on this host was admitted with.
#[must_use]
pub fn committed() -> MachineCharge {
    committed_at(Path::new(&mvm_core::config::mvm_home()))
}

/// [`committed`] beneath an explicit mvm home.
///
/// A machine contributes only when its state dir carries a pid marker
/// pointing at a live process *and* a readable charge record. Both halves fail
/// open, in the undercount direction, and that is the deliberate choice: an
/// unreadable record makes one machine invisible to the budget, while treating
/// it as a fatal read would make one stale file refuse every boot on the host.
#[must_use]
pub fn committed_at(mvm_home: &Path) -> MachineCharge {
    let vms = mvm_core::config::vms_dir_at(mvm_home);
    let Ok(entries) = std::fs::read_dir(&vms) else {
        // No vms dir yet is an empty host, not an error.
        return MachineCharge::default();
    };
    entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|dir| state_dir_has_live_process(dir))
        .filter_map(|dir| read_charge(&dir.join(CHARGE_FILE)))
        .fold(MachineCharge::default(), MachineCharge::plus)
}

fn read_charge(path: &Path) -> Option<MachineCharge> {
    let bytes = std::fs::read(path).ok()?;
    match serde_json::from_slice(&bytes) {
        Ok(charge) => Some(charge),
        Err(e) => {
            tracing::warn!(
                path = %path.display(),
                "unreadable admitted-charge record; this machine is not counted \
                 against the host budget: {e}"
            );
            None
        }
    }
}

/// Refuse a boot whose charge, on top of what is already live, would exceed
/// the host's configured headroom.
///
/// # Errors
///
/// If the sum exceeds the budget in any dimension.
pub fn admits(budget: &HostBudget, committed: MachineCharge, request: MachineCharge) -> Result<()> {
    budget.admits(committed, request).map_err(|v| {
        anyhow::anyhow!(
            "boot would exceed this host's budget: {dimension} is already {committed} \
             across live machines and this boot asks for {requested}, but the host allows \
             at most {budget} in total",
            dimension = v.dimension,
            committed = v.committed,
            requested = v.requested,
            budget = v.budget,
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_contract::protocol::vm_backend::BalloonState;

    fn budget(memory_mib: u64) -> HostBudget {
        HostBudget {
            max_total_memory_mib: Some(memory_mib),
            max_total_cpu_millicores: None,
        }
    }

    fn charge(memory_mib: u64) -> MachineCharge {
        MachineCharge {
            memory_mib,
            cpu_millicores: 0,
        }
    }

    /// A machine on this host: a state dir, a charge record, and a pid marker
    /// naming either this test process (live) or a pid that cannot be running.
    fn machine(home: &Path, name: &str, charge: MachineCharge, live: bool) {
        record_charge_at(home, name, charge).expect("recording the charge");
        let dir = mvm_core::config::vm_state_dir_at(home, name);
        // The probe reads whichever of the backends' markers it finds; any one
        // of them exercises the same code path a real boot writes.
        let pid = if live {
            std::process::id()
        } else {
            // A pid that has already exited. Reserved-but-unused high pids can
            // be recycled, so use one the kernel will not hand out: pid 1 is
            // rejected by the probe's own floor, and this is the next-cheapest
            // reliably-absent value on both Linux and macOS.
            dead_pid()
        };
        std::fs::write(dir.join("libkrun.pid"), pid.to_string()).expect("writing the pid marker");
    }

    /// A pid guaranteed absent: fork a process that exits immediately and reap
    /// it, so the number is genuinely dead rather than merely improbable.
    fn dead_pid() -> u32 {
        let child = std::process::Command::new("true")
            .spawn()
            .expect("spawning a short-lived child");
        let pid = child.id();
        let mut child = child;
        child.wait().expect("reaping the short-lived child");
        pid
    }

    fn isolated_home() -> (mvm_core::util::test_env::TestEnv, tempfile::TempDir) {
        let home = tempfile::tempdir().expect("scratch mvm home");
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());
        (env, home)
    }

    #[test]
    fn an_empty_host_admits_a_boot_within_headroom() {
        let (_env, home) = isolated_home();
        let committed = committed_at(home.path());
        assert_eq!(committed, MachineCharge::default());
        assert!(admits(&budget(8192), committed, charge(4096)).is_ok());
    }

    #[test]
    fn a_boot_past_the_headroom_is_refused() {
        let (_env, home) = isolated_home();
        machine(home.path(), "neighbour-a", charge(4096), true);
        machine(home.path(), "neighbour-b", charge(3072), true);

        let committed = committed_at(home.path());
        assert_eq!(committed.memory_mib, 7168);

        let err = admits(&budget(8192), committed, charge(4096))
            .expect_err("7168 + 4096 does not fit in 8192");
        let msg = format!("{err}");
        assert!(
            msg.contains("host.total_memory_mib") && msg.contains("7168") && msg.contains("8192"),
            "the refusal must name the dimension, the live total and the budget: {msg}"
        );
    }

    /// The lockout regression. A crashed machine that was never reaped leaves
    /// its charge record behind; if the budget counted records rather than
    /// live processes, that one crash would refuse every later boot on the
    /// host, permanently, with no way out but manual cleanup.
    #[test]
    fn budget_ignores_dead_machines() {
        let (_env, home) = isolated_home();
        machine(home.path(), "crashed-and-never-reaped", charge(8192), false);
        machine(home.path(), "also-gone", charge(8192), false);
        machine(home.path(), "still-running", charge(1024), true);

        let committed = committed_at(home.path());
        assert_eq!(
            committed.memory_mib, 1024,
            "only the live machine may be charged; counting the two dead records \
             would be a permanent lockout"
        );
        assert!(
            admits(&budget(8192), committed, charge(4096)).is_ok(),
            "a boot that fits beside the one live machine must be admitted"
        );
    }

    /// The balloon controller moves a running VM's host commitment down under
    /// pressure. Charging that figure would re-admit memory the host has
    /// already promised — here, admitting a 4 GiB boot next to a 4 GiB machine
    /// on a 6 GiB host, because the neighbour happens to be deflated to 1 GiB
    /// at the moment the question is asked.
    #[test]
    fn budget_counts_the_configured_maximum_not_current_usage() {
        let (_env, home) = isolated_home();
        let ballooned = BalloonState {
            max_mib: 4096,
            inflated_mib: 3072,
            host_committed_mib: 1024,
        };
        machine(
            home.path(),
            "ballooned",
            charge(u64::from(ballooned.max_mib)),
            true,
        );

        let committed = committed_at(home.path());
        assert_eq!(
            committed.memory_mib,
            u64::from(ballooned.max_mib),
            "the charge is what admission granted, not what the balloon left committed"
        );
        assert_ne!(
            committed.memory_mib,
            u64::from(ballooned.host_committed_mib)
        );

        assert!(
            admits(&budget(6144), committed, charge(4096)).is_err(),
            "charging the deflated figure would have admitted this boot and \
             overcommitted the host by 2 GiB"
        );
    }

    #[test]
    fn a_fuel_grant_contributes_no_cpu_share() {
        let grants = Grants {
            cpu: Some(CpuGrant::Fuel {
                instructions: 1_000_000,
            }),
            ..Grants::default()
        };
        assert_eq!(charge_for(512, &grants).cpu_millicores, 0);

        let shared = Grants {
            cpu: Some(CpuGrant::Share { millicores: 1500 }),
            ..Grants::default()
        };
        assert_eq!(charge_for(512, &shared).cpu_millicores, 1500);
        assert_eq!(charge_for(512, &shared).memory_mib, 512);
    }

    #[test]
    fn an_unreadable_charge_record_is_skipped_rather_than_fatal() {
        let (_env, home) = isolated_home();
        machine(home.path(), "good", charge(1024), true);
        machine(home.path(), "corrupt", charge(2048), true);
        let corrupt = mvm_core::config::vm_state_dir_at(home.path(), "corrupt").join(CHARGE_FILE);
        std::fs::write(&corrupt, b"{ not json").expect("corrupting the record");

        assert_eq!(committed_at(home.path()).memory_mib, 1024);
    }

    #[test]
    fn a_live_machine_with_no_charge_record_is_not_counted() {
        let (_env, home) = isolated_home();
        let dir = mvm_core::config::vm_state_dir_at(home.path(), "no-record");
        std::fs::create_dir_all(&dir).expect("creating the state dir");
        std::fs::write(dir.join("libkrun.pid"), std::process::id().to_string())
            .expect("writing the pid marker");

        assert_eq!(committed_at(home.path()), MachineCharge::default());
    }
}
