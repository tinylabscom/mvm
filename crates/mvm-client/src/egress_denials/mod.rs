//! Egress refusals, read back for the person who started the workload.
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
//! - live, while a workload runs: [`DenialWatch`], which hands each distinct
//!   refusal to a [`NoticeSink`](crate::notices::NoticeSink) as it is recorded;
//! - at exit: [`print_summary`], one block with counts and the flags to
//!   allow what can be allowed;
//! - after the fact: [`denials_in_window`], which [`crate::explain`] uses.

pub mod denial;
pub mod reason;
mod tally;
mod watch;

use std::path::PathBuf;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use mvm_hostd::supervisor::PlanAuditEntry;

use crate::audit::follow::{ChainLine, parse_chain_line};

pub use tally::{DenialTally, DeniedDestination};
pub use watch::{DenialWatch, Live, WatchTarget, print_summary};

/// The chain a local run's endpoint records its refusals in: the default
/// tenant's, in this host's audit directory. `None` when there is no home to
/// read one from.
pub fn local_chain() -> Option<PathBuf> {
    let dir = mvm_hostd::audit::emitter::default_audit_dir().ok()?;
    Some(mvm_hostd::audit::emitter::audit_path_for_tenant(
        &dir,
        mvm_core::plan::DEFAULT_TENANT,
    ))
}

/// The plan id of the latest admission of machine `vm_name` in the local
/// chain: the run `mvmctl explain` should be pointed at. `None` when the chain
/// cannot be read or records no admission under that name.
pub fn latest_admission(vm_name: &str) -> Option<String> {
    let text = std::fs::read_to_string(local_chain()?).ok()?;
    let entries = text
        .lines()
        .filter_map(|line| match parse_chain_line(line) {
            ChainLine::Entry(entry) => Some(*entry),
            ChainLine::Foreign(_) => None,
        });
    latest_admission_in(entries, vm_name)
}

/// An admission records the machine's name as its `image_name`.
fn latest_admission_in(
    entries: impl IntoIterator<Item = PlanAuditEntry>,
    vm_name: &str,
) -> Option<String> {
    entries
        .into_iter()
        .filter(|entry| entry.event == "plan.admitted" && entry.image_name == vm_name)
        .max_by_key(|entry| entry.timestamp)
        .map(|entry| entry.plan_id.0)
}

/// Verify the local chain under this host's signing key. Watching is
/// best-effort display; anything that proposes a policy change from what it
/// saw needs this stronger, signed source first.
pub fn verify_local_chain() -> Result<()> {
    let path = local_chain().context("the local audit-chain path is unavailable")?;
    let signer = mvm_hostd::audit::host_keypair::load_or_init()
        .context("loading the host signer for denial review")?;
    mvm_hostd::supervisor::verify_audit_chain(&path, &signer.verifying)
        .with_context(|| format!("verifying audit chain {}", path.display()))?;
    Ok(())
}

/// The refusals recorded for machine `vm_name` between `from` and `until`
/// (open-ended when `None`), counted as a run's exit summary counts them.
pub fn denials_in_window<'a>(
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

    fn admitted(ts: &str, vm: &str, plan: &str) -> PlanAuditEntry {
        PlanAuditEntry {
            image_name: vm.into(),
            plan_id: mvm_core::plan::PlanId(plan.into()),
            ..at(entry("plan.admitted", &[]), ts)
        }
    }

    #[test]
    fn the_run_explain_is_pointed_at_is_the_machines_latest_admission() {
        let entries = [
            admitted("2026-09-26T10:00:00Z", "vm-a", "plan-old"),
            admitted("2026-09-26T10:00:05Z", "vm-b", "plan-other"),
            refused("2026-09-26T10:00:06Z", "vm-a", "api.example:443"),
            admitted("2026-09-26T10:00:07Z", "vm-a", "plan-new"),
        ];
        assert_eq!(
            latest_admission_in(entries.clone(), "vm-a").as_deref(),
            Some("plan-new")
        );
        assert_eq!(latest_admission_in(entries, "vm-c"), None);
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
}
