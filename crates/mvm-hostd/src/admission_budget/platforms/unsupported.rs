use anyhow::{Result, bail};
use std::path::Path;

pub(super) fn prepare_directory(_: &Path) -> Result<()> {
    bail!("host reservations require owner-only storage")
}
pub(crate) fn acquire_lock(_: &Path) -> Result<mvm_core::atomic_io::FileLock> {
    bail!("host reservations require owner-only storage")
}

pub(crate) fn acquire_existing_lock(_: &Path) -> Result<mvm_core::atomic_io::FileLock> {
    bail!("host reservations require owner-only storage")
}
pub(crate) fn read_private(_: &Path, _: usize) -> Result<Option<Vec<u8>>> {
    bail!("host reservations require owner-only storage")
}
pub(super) fn read_legacy(_: &Path, _: usize) -> Result<Option<Vec<u8>>> {
    bail!("host reservations require owner-only storage")
}
pub(super) fn current_owner() -> Result<String> {
    bail!("host reservations require process identity")
}
pub(super) fn validate_owner(_: &str) -> Result<()> {
    bail!("host reservations require process identity")
}
pub(super) fn owner_is_confirmed_dead(_: &str) -> bool {
    false
}
pub(super) fn machine_is_confirmed_dead(_: &Path) -> Result<bool> {
    bail!("host reservations require process identity")
}
pub(super) fn machine_identity(_: &Path) -> Result<Option<String>> {
    bail!("host reservations require process identity")
}
