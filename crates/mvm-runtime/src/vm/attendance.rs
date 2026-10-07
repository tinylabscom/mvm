//! Whether a running machine is an attended run.
//!
//! A run is attended when its admitted plan grants display input marked
//! `attended`: a human may be driving the guest's display, and possibly typing
//! into it. That is a different security tier from an unattended run, so
//! `machine ls` and `doctor` say so. The answer comes from the plan the launch
//! persisted in the VM's state directory, which is the plan admission signed.

use std::path::Path;

/// Whether `vm`'s current run is attended. A machine with no readable plan is
/// reported as unattended: this is a report, and the gate that matters reads
/// the plan itself.
#[must_use]
pub fn attended(vm: &str) -> bool {
    attended_at(&mvm_core::config::vm_state_dir(vm))
}

/// Every running machine whose run is attended, by name, sorted.
#[must_use]
pub fn attended_running_machines() -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(mvm_core::config::vms_dir()) else {
        return Vec::new();
    };
    let mut names: Vec<String> = entries
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter(|name| crate::checkpoint::vm_is_running(name) && attended(name))
        .collect();
    names.sort();
    names
}

fn attended_at(state_dir: &Path) -> bool {
    let Ok(json) = std::fs::read_to_string(state_dir.join("plan.json")) else {
        return false;
    };
    mvm_core::plan::plan_from_admitted_json(&json).is_ok_and(|plan| {
        mvm_contract::grants::display::display_input_grant(plan.grants.as_ref())
            .is_some_and(|grant| grant.attended)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_contract::grants::{DisplayInputGrant, Grants};
    use mvm_core::plan::test_support::PlanFixture;

    fn write_plan(dir: &Path, display_input: Option<DisplayInputGrant>) {
        let plan = PlanFixture::new()
            .grants(Some(Grants {
                display_input,
                ..Grants::default()
            }))
            .build();
        std::fs::write(dir.join("plan.json"), serde_json::to_vec(&plan).unwrap()).unwrap();
    }

    #[test]
    fn only_an_attended_display_grant_makes_a_run_attended() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!attended_at(dir.path()), "no plan is not attended");

        write_plan(dir.path(), None);
        assert!(!attended_at(dir.path()));

        write_plan(dir.path(), Some(DisplayInputGrant::default()));
        assert!(!attended_at(dir.path()), "input without attendance");

        write_plan(
            dir.path(),
            Some(DisplayInputGrant {
                attended: true,
                ..DisplayInputGrant::default()
            }),
        );
        assert!(attended_at(dir.path()));
    }

    #[test]
    fn an_unreadable_plan_is_not_attended() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("plan.json"), b"{not json").unwrap();
        assert!(!attended_at(dir.path()));
    }
}
