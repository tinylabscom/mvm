//! Host-wide memory/CPU admission using durable, one-dispatch capacity holds.
//!
//! [`HostBudgetPermit`] atomically counts pending holds and legacy live
//! charges before reserving capacity. Its short ledger lock is released before
//! boot. Charges use configured maxima, never current balloon usage.
//!
//! Possibly dispatched holds survive launcher death. A failed `vm_full` fork is
//! settled by `HostBudgetPermit::settle_failed_launch`, which releases an
//! ordinary hold only when no PID marker leaves its machine possibly running,
//! the ledger's own liveness rule. Other launch kinds do not call it yet: a
//! cold transient that fails after spending its hold, and every fs_quick fork,
//! still leave a `Dispatching` hold that nothing retires. Ordinary running
//! holds can reconcile only against their persisted original process
//! identity; coordinated holds require explicit terminal reconciliation.
//! The older `committed` queries are diagnostic legacy-record projections,
//! not admission authority, and do not include pending holds.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use mvm_contract::grants::budget::{HostBudget, MachineCharge};
use mvm_contract::grants::{CpuGrant, Grants};
use mvm_vmm::host::process_liveness::state_dir_has_live_process;

mod permit;
pub use permit::{HostBudgetPermit, HostBudgetRelease};
pub(crate) use permit::{acquire_lock, read_private};

/// File name of the per-VM charge record, written into the VM's state dir at
/// boot and read back by every later admission.
const CHARGE_FILE: &str = "admitted-charge.json";

/// The admitted plan persisted beside it, from which the same charge follows.
const PLAN_FILE: &str = crate::audit::plan_persist::PLAN_FILENAME;

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
/// running without a charge record leans on its persisted plan alone, and is
/// invisible to every later budget check when that is missing too, which is
/// the silent-undercount failure this whole module exists to avoid.
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
    mvm_core::atomic_io::atomic_write_durable(&path, &json)
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
/// pointing at a live process, at the charge [`machine_charge`] finds for it.
/// Both halves fail open, in the undercount direction, and that is the
/// deliberate choice: a machine with no readable charge evidence is invisible
/// to the budget, while treating it as a fatal read would make one stale file
/// refuse every boot on the host.
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
        .filter_map(|dir| machine_charge(&dir, read_if_present))
        .fold(MachineCharge::default(), MachineCharge::plus)
}

fn read_if_present(path: &Path) -> Result<Option<Vec<u8>>> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

/// The charge a possibly live machine is counted at.
///
/// Its charge record when that reads; otherwise the charge its persisted
/// admitted plan implies, which is the figure admission charged it from.
/// `None` when neither yields one: that machine alone goes uncounted rather
/// than one bad file refusing every boot. Neither file existing is the normal
/// state of an idle standby, which admission does not charge, so only a file
/// that exists but will not read is warned about.
fn machine_charge(
    dir: &Path,
    read: impl Fn(&Path) -> Result<Option<Vec<u8>>>,
) -> Option<MachineCharge> {
    let machine = dir
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let record = read(&dir.join(CHARGE_FILE)).and_then(|bytes| {
        bytes
            .map(|bytes| serde_json::from_slice(&bytes).context("parsing the charge record"))
            .transpose()
    });
    let record_error = match record {
        Ok(Some(charge)) => return Some(charge),
        Ok(None) => None,
        Err(error) => Some(error),
    };
    let plan = read(&dir.join(PLAN_FILE)).and_then(|bytes| {
        bytes
            .map(|bytes| -> Result<MachineCharge> {
                let plan = mvm_core::plan::plan_from_admitted_json(std::str::from_utf8(&bytes)?)?;
                Ok(charge_for(
                    plan.resources.mem_mib,
                    plan.grants.as_ref().unwrap_or(&Grants::default()),
                ))
            })
            .transpose()
    });
    match (plan, record_error) {
        (Ok(Some(charge)), None) => Some(charge),
        (Ok(Some(charge)), Some(error)) => {
            warn_once(
                &machine,
                format!(
                    "unreadable admitted-charge record; counting this machine at the charge \
                     its admitted plan implies: {error:#}"
                ),
            );
            Some(charge)
        }
        (Ok(None), None) => {
            tracing::debug!(machine, "no admitted charge or plan; not counted");
            None
        }
        (plan, record_error) => {
            let record = record_error.map_or_else(|| "absent".to_owned(), |e| format!("{e:#}"));
            let plan = plan
                .err()
                .map_or_else(|| "absent".to_owned(), |e| format!("{e:#}"));
            warn_once(
                &machine,
                format!(
                    "no readable admitted-charge record (record: {record}; plan: {plan}); \
                     this possibly live machine is not counted against the host budget"
                ),
            );
            None
        }
    }
}

/// Warn about one machine's bad accounting evidence once per process.
///
/// Every admission re-reads every machine, so a persistent bad file would
/// otherwise repeat the same warning on each launch; later repeats go to debug.
fn warn_once(machine: &str, message: String) {
    static WARNED: std::sync::OnceLock<std::sync::Mutex<std::collections::BTreeSet<String>>> =
        std::sync::OnceLock::new();
    let first = WARNED
        .get_or_init(Default::default)
        .lock()
        .map_or(true, |mut warned| {
            warned.insert(format!("{machine}\n{message}"))
        });
    if first {
        tracing::warn!(machine, "{message}");
    } else {
        tracing::debug!(machine, "{message}");
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

    #[test]
    fn an_empty_host_admits_a_boot_within_headroom() {
        let (_env, home) = crate::test_fixtures::isolated_mvm_home();
        let committed = committed_at(home.path());
        assert_eq!(committed, MachineCharge::default());
        assert!(admits(&budget(8192), committed, charge(4096)).is_ok());
    }

    #[test]
    fn a_boot_past_the_headroom_is_refused() {
        let (_env, home) = crate::test_fixtures::isolated_mvm_home();
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
        let (_env, home) = crate::test_fixtures::isolated_mvm_home();
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
        let (_env, home) = crate::test_fixtures::isolated_mvm_home();
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
        let (_env, home) = crate::test_fixtures::isolated_mvm_home();
        machine(home.path(), "good", charge(1024), true);
        machine(home.path(), "corrupt", charge(2048), true);
        let corrupt = mvm_core::config::vm_state_dir_at(home.path(), "corrupt").join(CHARGE_FILE);
        std::fs::write(&corrupt, b"{ not json").expect("corrupting the record");

        assert_eq!(committed_at(home.path()).memory_mib, 1024);
    }

    #[test]
    fn a_marker_that_records_its_start_time_still_counts_the_live_machine() {
        let (_env, home) = crate::test_fixtures::isolated_mvm_home();
        machine(home.path(), "recorded", charge(1024), false);
        let marker = mvm_core::config::vm_state_dir_at(home.path(), "recorded").join("libkrun.pid");
        std::fs::write(
            &marker,
            mvm_vmm::host::network_endpoint_spawn::EndpointPid::of_child(std::process::id())
                .render(),
        )
        .expect("writing the pid marker");

        assert_eq!(committed_at(home.path()).memory_mib, 1024);
    }

    #[test]
    fn a_live_machine_with_no_charge_record_is_not_counted() {
        let (_env, home) = crate::test_fixtures::isolated_mvm_home();
        let dir = mvm_core::config::vm_state_dir_at(home.path(), "no-record");
        std::fs::create_dir_all(&dir).expect("creating the state dir");
        std::fs::write(dir.join("libkrun.pid"), std::process::id().to_string())
            .expect("writing the pid marker");

        assert_eq!(committed_at(home.path()), MachineCharge::default());
    }

    /// `plan.json` as the launch path stashes it: the signed envelope.
    fn persist_plan(home: &Path, name: &str, mem_mib: u64) {
        let mut plan = mvm_core::plan::test_support::PlanFixture::new().build();
        plan.resources.mem_mib = mem_mib;
        plan.grants = None;
        let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        let signed = mvm_core::plan::sign_plan(&plan, &key, "test-host");
        let dir = mvm_core::config::vm_state_dir_at(home, name);
        std::fs::write(dir.join(PLAN_FILE), serde_json::to_vec(&signed).unwrap())
            .expect("persisting the plan");
    }

    /// The claimed child's marker links to its standby parent's; the parent's
    /// dir has no charge evidence of its own.
    fn handed_off(home: &Path, live: bool) {
        machine(home, "standby-parent", charge(0), live);
        std::fs::remove_file(
            mvm_core::config::vm_state_dir_at(home, "standby-parent").join(CHARGE_FILE),
        )
        .expect("a standby carries no record");
        record_charge_at(home, "claimed-child", charge(1024)).expect("recording the charge");
        std::os::unix::fs::symlink(
            mvm_core::config::vm_state_dir_at(home, "standby-parent").join("libkrun.pid"),
            mvm_core::config::vm_state_dir_at(home, "claimed-child").join("libkrun.pid"),
        )
        .expect("linking the child's marker");
    }

    #[test]
    fn a_live_handoff_child_is_counted_once_through_its_linked_marker() {
        let (_env, home) = crate::test_fixtures::isolated_mvm_home();
        handed_off(home.path(), true);
        assert_eq!(committed_at(home.path()).memory_mib, 1024);
    }

    #[test]
    fn a_dead_handoff_child_is_not_counted() {
        let (_env, home) = crate::test_fixtures::isolated_mvm_home();
        handed_off(home.path(), false);
        assert_eq!(committed_at(home.path()), MachineCharge::default());
    }

    #[test]
    fn an_unreadable_charge_record_is_counted_from_the_machines_plan() {
        let (_env, home) = crate::test_fixtures::isolated_mvm_home();
        machine(home.path(), "torn", charge(2048), true);
        let record = mvm_core::config::vm_state_dir_at(home.path(), "torn").join(CHARGE_FILE);
        std::fs::write(&record, b"").expect("tearing the record");
        persist_plan(home.path(), "torn", 2048);

        assert_eq!(committed_at(home.path()).memory_mib, 2048);
    }

    #[test]
    fn a_live_machine_with_no_charge_record_is_counted_from_its_plan() {
        let (_env, home) = crate::test_fixtures::isolated_mvm_home();
        let dir = mvm_core::config::vm_state_dir_at(home.path(), "booting");
        std::fs::create_dir_all(&dir).expect("creating the state dir");
        std::fs::write(dir.join("libkrun.pid"), std::process::id().to_string())
            .expect("writing the pid marker");
        persist_plan(home.path(), "booting", 1024);

        assert_eq!(committed_at(home.path()).memory_mib, 1024);
    }
}
