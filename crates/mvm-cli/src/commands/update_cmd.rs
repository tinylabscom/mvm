//! `mvmctl update` — self-update.

use anyhow::Result;

use crate::update;

pub(super) fn cmd_update(check: bool, force: bool, skip_verify: bool) -> Result<()> {
    let result = update::update(check, force, skip_verify);
    if result.is_ok() && !check {
        mvm_core::audit::emit(mvm_core::audit::LocalAuditKind::UpdateInstall, None, None);
    }
    result
}
