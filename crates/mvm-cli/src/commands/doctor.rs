//! `mvmctl doctor` — environment diagnostics.

use anyhow::Result;

pub(super) fn cmd_doctor(json: bool) -> Result<()> {
    crate::doctor::run(json)
}
