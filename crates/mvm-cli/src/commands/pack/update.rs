//! `mvmctl pack update` — fetch the latest pack version and activate it.
//! `download` + `set_active_version` composed into one step.

use anyhow::Result;

use mvm_core::packs::PackKind;

use super::PackKindArg;
use super::download::builder;

pub(in crate::commands) fn run(kind: PackKindArg) -> Result<()> {
    match kind.to_pack_kind() {
        PackKind::Builder => {
            let promoted = builder::fetch_and_promote(None)?;
            mvm_core::pack_cache::set_active_version(&promoted.key, &promoted.hash)?;
            crate::ui::success(&format!(
                "Updated builder pack to {} ({}) and activated it.",
                promoted.release_version,
                builder::short_hash(promoted.hash.as_str()),
            ));
            Ok(())
        }
        other => super::download::not_fetchable(other),
    }
}
