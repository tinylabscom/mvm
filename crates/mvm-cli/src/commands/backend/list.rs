//! `mvmctl backend list` — every backend in the component table, with this
//! host's support, install state, and the default.

use anyhow::{Context, Result};
use clap::Args as ClapArgs;

use crate::host_binaries::backend_components::{
    component_dirs, component_files_present, component_table, detect_install_default_for,
    live_host, not_available_reason,
};
use crate::ui;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args;

pub(in crate::commands) fn run(_args: Args) -> Result<()> {
    let host = live_host().context("this build has no release archive target")?;
    let default = detect_install_default_for(&host);
    let dirs = component_dirs();
    for row in component_table() {
        let name = row.backend.as_str();
        let mut facts = Vec::new();
        match not_available_reason(row, &host) {
            None => {
                let state = if row.files.is_empty() {
                    "bundled (no host components)"
                } else if component_files_present(row, &dirs) {
                    "installed"
                } else {
                    "not installed — add with `mvmctl backend add`"
                };
                facts.push(state.to_string());
                if default == Some(row.backend) {
                    facts.push("default on this host".to_string());
                }
            }
            Some(reason) => facts.push(format!("not available: {reason}")),
        }
        facts.push(row.summary.to_string());
        ui::status_line(&format!("  {name}:"), &facts.join("; "));
    }
    Ok(())
}
