//! Egress refusals, shown to the person who started the workload.
//!
//! When the per-VM network endpoint refuses a workload's connection, the guest
//! gets a refusal and the chain-signed audit log gets an entry naming the
//! destination and a fixed reason. This module reads those entries back for
//! one machine and turns each into a line that says what was blocked, why, and
//! the exact remedy for that reason — or that there is none.
//!
//! It is observation only. The endpoint remains the single place an egress
//! decision is made; nothing here is consulted by it or can change what it
//! decides.
//!
//! - live, while a foreground run or a followed machine's output is on
//!   screen: [`PendingWatch`] / [`watch_machine`];
//! - at exit: [`print_summary`], one block with counts and the flags to
//!   allow what can be allowed;
//! - after the fact: [`denials_in_window`], which `mvmctl explain` uses.

mod denial;
mod reason;
mod tally;
mod watch;

use std::cell::RefCell;
use std::path::PathBuf;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use mvm_hostd::supervisor::PlanAuditEntry;

pub(in crate::commands) use tally::{DenialTally, DeniedDestination};
pub(in crate::commands) use watch::{DenialWatch, Live, WatchTarget, print_summary};

use super::audit_chain::{audit_path_for_tenant, default_audit_dir};
use super::host_notices::{NoticeSink, Stderr};

/// The tenant a local run is admitted under, and so the chain its endpoint
/// records in.
fn local_chain() -> Option<PathBuf> {
    let dir = default_audit_dir().ok()?;
    Some(audit_path_for_tenant(&dir, mvm_core::plan::DEFAULT_TENANT))
}

/// Start watching `vm_name`'s refusals in the local tenant's chain. `None`
/// when there is no home to read a chain from; the command runs regardless.
pub(in crate::commands) fn watch_machine(vm_name: &str, live: Live) -> Option<DenialWatch> {
    Some(DenialWatch::start(WatchTarget {
        chain: local_chain()?,
        vm_name: vm_name.to_string(),
        live,
        sink: Arc::new(Stderr) as Arc<dyn NoticeSink>,
    }))
}

/// Finish a watch, if one was running, and print its exit summary. Returns
/// what it saw.
pub(in crate::commands) fn finish_and_summarize(watch: Option<DenialWatch>) -> DenialTally {
    let tally = watch.map(DenialWatch::finish).unwrap_or_default();
    print_summary(&tally, &Stderr);
    tally
}

/// A watch that starts once the machine's name exists.
///
/// A transient run names its machine inside the boot path, immediately before
/// the admission that precedes the endpoint's spawn. The watch is armed there,
/// so its starting point in the chain precedes anything the endpoint writes.
pub(in crate::commands) struct PendingWatch {
    live: Live,
    running: RefCell<Option<DenialWatch>>,
}

impl PendingWatch {
    pub(in crate::commands) fn new(live: Live) -> Self {
        Self {
            live,
            running: RefCell::new(None),
        }
    }

    /// Start watching `vm_name`. A second call — a retried boot under a new
    /// name — replaces the first watch.
    pub(in crate::commands) fn arm(&self, vm_name: &str) {
        let watch = watch_machine(vm_name, self.live);
        if let Some(previous) = self.running.replace(watch) {
            drop(previous.finish());
        }
    }

    /// Stop watching and return what was seen: empty when the run never got
    /// as far as naming a machine.
    pub(in crate::commands) fn finish(&self) -> DenialTally {
        self.running
            .borrow_mut()
            .take()
            .map(DenialWatch::finish)
            .unwrap_or_default()
    }
}

/// The refusals recorded for machine `vm_name` between `from` and `until`
/// (open-ended when `None`), counted as a run's exit summary counts them.
pub(in crate::commands) fn denials_in_window<'a>(
    entries: impl IntoIterator<Item = &'a PlanAuditEntry>,
    vm_name: &str,
    from: DateTime<Utc>,
    until: Option<DateTime<Utc>>,
) -> DenialTally {
    let mut tally = DenialTally::default();
    for entry in entries {
        if entry.timestamp < from || until.is_some_and(|end| entry.timestamp > end) {
            continue;
        }
        if let Some(denial) = denial::EgressDenial::from_entry(entry, vm_name) {
            tally.observe(denial);
        }
    }
    tally
}

#[cfg(test)]
mod tests {
    use super::denial::tests::entry;
    use super::*;

    fn at(entry: PlanAuditEntry, ts: &str) -> PlanAuditEntry {
        PlanAuditEntry {
            timestamp: ts.parse().unwrap(),
            ..entry
        }
    }

    fn refused(ts: &str, vm: &str, target: &str) -> PlanAuditEntry {
        at(
            entry(
                "host.flow.denied",
                &[
                    ("vm_name", vm),
                    ("target", target),
                    ("reason", "policy_denied"),
                ],
            ),
            ts,
        )
    }

    #[test]
    fn a_window_counts_only_its_machine_between_its_bounds() {
        let entries = [
            refused("2026-09-26T09:59:59Z", "vm-a", "before.example:443"),
            refused("2026-09-26T10:00:01Z", "vm-a", "inside.example:443"),
            refused("2026-09-26T10:00:02Z", "vm-b", "other.example:443"),
            refused("2026-09-26T10:00:03Z", "vm-a", "inside.example:443"),
            refused("2026-09-26T10:00:09Z", "vm-a", "after.example:443"),
        ];
        let tally = denials_in_window(
            &entries,
            "vm-a",
            "2026-09-26T10:00:00Z".parse().unwrap(),
            Some("2026-09-26T10:00:05Z".parse().unwrap()),
        );
        let rows = tally.destinations();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].destination, "inside.example:443");
        assert_eq!(rows[0].count, 2);

        let open = denials_in_window(
            &entries,
            "vm-a",
            "2026-09-26T10:00:00Z".parse().unwrap(),
            None,
        );
        assert_eq!(open.destinations().len(), 2);
    }

    #[test]
    fn an_unarmed_watch_finishes_empty() {
        assert!(PendingWatch::new(Live::Quiet).finish().is_empty());
    }
}
