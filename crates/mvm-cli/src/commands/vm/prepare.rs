//! `mvmctl prepare` — report whether the host default runtime pack is ready
//! for instant launch, and why not when it isn't.
//!
//! Scope is deliberately narrow and read-only: only the host default runtime
//! pack cache is diagnosed here (the same cache `machine run`'s default launch
//! path consults). Acquiring packs — resolve, download, verify, activate — is a
//! separate, side-effecting concern that lives in `mvmctl pack download`/`update`
//! (over the content-addressed pack cache) and the install-time `mvmctl bootstrap`
//! prefetch; this command only reports readiness and takes no positional input.

use anyhow::Result;
use clap::Args as ClapArgs;

use crate::ui;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// Report readiness without side effects. Currently a no-op: there is no
    /// download/build path yet for a missing runtime pack, so `--dry-run` and
    /// the default mode report identically.
    #[arg(long)]
    pub dry_run: bool,
}

pub(in crate::commands) fn run(args: Args) -> Result<()> {
    let diagnosis = super::runtime_pack::runtime_pack_diagnosis()?;

    match &diagnosis {
        mvm_core::pack_cache::PackDiagnosis::Ready {
            pack_hash,
            file_count,
        } => {
            ui::success(&format!(
                "Runtime pack {} verified — instant launch ready ({file_count} files).",
                pack_hash.as_str()
            ));
        }
        _ => {
            let reason = super::runtime_pack::not_instant_reason(&diagnosis)
                .unwrap_or_else(|| "no verified runtime pack is cached for this host".to_string());
            ui::info(&reason);
            ui::info("machine run will build the bundled default microVM in the builder VM.");
        }
    }

    if args.dry_run {
        ui::info(
            "--dry-run: downloading or building a missing runtime pack is not yet wired; \
             this report reflects the current cache only.",
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::Args;

    #[derive(Parser, Debug)]
    struct Harness {
        #[command(flatten)]
        args: Args,
    }

    #[test]
    fn dry_run_flag_parses() {
        let harness = Harness::try_parse_from(["prepare", "--dry-run"]).expect("parses");
        assert!(harness.args.dry_run);
    }

    #[test]
    fn no_flag_defaults_to_false() {
        let harness = Harness::try_parse_from(["prepare"]).expect("parses");
        assert!(!harness.args.dry_run);
    }
}
