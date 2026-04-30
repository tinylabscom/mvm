//! `mvmctl update` — self-update.

use anyhow::Result;
use clap::Args as ClapArgs;

use mvm_core::user_config::MvmConfig;

use crate::update;

use super::Cli;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// Only check, don't install
    #[arg(long)]
    pub check: bool,
    /// Force re-install even if already up to date
    #[arg(long)]
    pub force: bool,
    /// Skip checksum verification
    #[arg(long)]
    pub skip_verify: bool,
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    let result = update::update(args.check, args.force, args.skip_verify);
    if result.is_ok() && !args.check {
        mvm_core::audit::emit(mvm_core::audit::LocalAuditKind::UpdateInstall, None, None);
    }
    result
}
