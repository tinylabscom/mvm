//! `mvmctl pack update` — fetch the latest pack version and activate it.
//! `download` + `set_active_version` composed into one step, so it refuses
//! exactly where `download` does.

use anyhow::Result;

use super::PackKindArg;

pub(in crate::commands) fn run(kind: PackKindArg) -> Result<()> {
    super::download::not_fetchable(kind.to_pack_kind())
}
