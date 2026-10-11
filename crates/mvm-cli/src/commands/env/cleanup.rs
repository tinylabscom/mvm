//! Cleanup argument mapping, confirmation, and rendering.

use anyhow::{Context, Result};
use clap::{ArgGroup, Args as ClapArgs};
use std::io::IsTerminal;

use super::Cli;
use crate::ui;
pub(in crate::commands) use mvm_client::maintenance::cleanup::running_vms_at;
use mvm_client::maintenance::cleanup::{self, Event, Identity, Intent, Request, Retention, Tier};
use mvm_core::user_config::MvmConfig;

#[derive(ClapArgs, Debug, Clone)]
#[command(group(
    ArgGroup::new("tier")
        .args(["cache", "state", "nuclear"])
        .multiple(false),
))]
pub(in crate::commands) struct Args {
    /// Number of newest in-VM build revisions to keep
    #[arg(long)]
    pub keep: Option<usize>,
    /// Remove all in-VM cached build revisions
    #[arg(long)]
    pub all: bool,
    /// Also wipe `~/.mvm/cache` (Stage 0 staging, builder VM artifacts).
    /// All cache contents are regenerable; the next build rebuilds them.
    #[arg(long)]
    pub cache: bool,
    /// Wipe `~/.mvm/cache` PLUS regenerable subdirs of `~/.mvm`
    /// (`dev`, `vms`, `log`, `dev-cluster`, `mock-vms`, `tool-staging`).
    /// Preserves identity (`keys`, `audit`, `volumes`, `secrets`,
    /// `config.toml`) and `templates`.
    #[arg(long)]
    pub state: bool,
    /// Wipe every entry under `~/.mvm`, leaving the (0700) root dir
    /// itself in place. Past audit logs become unverifiable under the
    /// new signer. Requires an interactive text confirmation; `--yes`
    /// does NOT bypass it.
    #[arg(long)]
    pub nuclear: bool,
    /// With `--nuclear`, spare the host's cryptographic identity:
    /// `keys`, `audit`, `attestation`, `secrets`, `secret-bindings`,
    /// `egress-ca`, `.secret-store.key`, `snapshot.key` and
    /// `config.toml`. Everything else under `~/.mvm` still goes.
    #[arg(long, requires = "nuclear")]
    pub keep_identity: bool,
    /// Print what would be removed by the tier sweep without removing it.
    /// Has no effect on the in-VM cleanup step.
    #[arg(long)]
    pub dry_run: bool,
    /// Skip the y/N prompt for `--cache` / `--state`. `--nuclear` still
    /// requires its interactive text confirmation regardless of `--yes`.
    #[arg(long)]
    pub yes: bool,
    /// Allow the tier sweep to proceed even when a VM is running.
    /// Wiping live VM state corrupts the running guest — use only when
    /// the VM is already known-dead and the PID file is stale.
    #[arg(long)]
    pub force: bool,
}

fn pick_tier(args: &Args) -> Option<Tier> {
    if args.nuclear {
        Some(Tier::Nuclear)
    } else if args.state {
        Some(Tier::State)
    } else if args.cache {
        Some(Tier::Cache)
    } else {
        None
    }
}

fn request(args: &Args) -> Result<Request> {
    let retention = if args.all {
        Retention::All
    } else {
        Retention::Newest(
            std::num::NonZeroUsize::new(args.keep.unwrap_or(5))
                .context("--keep must be greater than 0 (or use --all)")?,
        )
    };
    Ok(Request {
        retention,
        tier: pick_tier(args),
        identity: Identity::from_flag(args.keep_identity),
        force: args.force,
        // The CLI historically always runs the in-VM step, even for --dry-run.
        intent: Intent::Apply,
    })
}

pub(in crate::commands) fn run(cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    let request = request(&args)?;
    let tier = request.tier;
    let identity = request.identity;
    let prepared = cleanup::prepare(request, |event| render(event, cli.verbose > 0))?;
    let Some(tier) = tier else {
        return Ok(());
    };
    ui::info(&format!(
        "Cleanup tier: {}{}",
        tier.name(),
        identity.suffix()
    ));
    if prepared.is_empty() {
        ui::info("Nothing to wipe — none of the tier's paths exist on disk.");
        return Ok(());
    }
    ui::info(&format!(
        "Will remove {} path(s):",
        prepared.paths().count()
    ));
    for (path, bytes) in prepared.paths() {
        println!(
            "  {} ({})",
            path.display(),
            super::super::shared::human_bytes(bytes)
        );
    }
    if args.dry_run {
        ui::info("(dry-run) No paths removed.");
        return Ok(());
    }
    if !confirm_tier(tier, identity, args.yes)? {
        ui::info("Cancelled.");
        return Ok(());
    }
    let intent = if tier == Tier::Nuclear {
        Intent::DeleteEverything
    } else {
        Intent::Apply
    };
    let spinner = ui::spinner("Cleaning mvm cache...");
    let result = cleanup::apply(prepared, intent);
    spinner.finish_and_clear();
    let report = result?;
    ui::success(&format!(
        "Cleanup tier {}: removed {} path(s), freed {}",
        tier.name(),
        report.paths_removed,
        super::super::shared::human_bytes(report.bytes_freed),
    ));
    Ok(())
}

fn render(event: Event, verbose: bool) {
    match event {
        Event::DiskBefore(pct) => ui::info(&format!("Dev VM disk usage: {pct}%")),
        Event::ClearingTemporaryFiles => ui::info("Clearing temporary files..."),
        Event::BuildsRemoved {
            paths,
            count,
            retention,
        } => {
            if verbose {
                if paths.is_empty() {
                    ui::info("No cached build paths removed.");
                } else {
                    ui::info("Removed cached build paths:");
                    for path in paths {
                        println!("  {path}");
                    }
                }
            }
            match retention {
                Retention::All => ui::success(&format!("Removed {count} cached build(s).")),
                Retention::Newest(keep) => ui::success(&format!(
                    "Removed {count} cached build(s), kept newest {keep}."
                )),
            }
        }
        Event::GarbageCollectionSkipped => {
            ui::info("Skipping nix-collect-garbage: dev VM is not running.")
        }
        Event::GarbageCollectionStarted => ui::info("Running nix-collect-garbage..."),
        Event::GarbageCollectionOutput(output) => {
            let trimmed = output.trim();
            if !trimmed.is_empty() {
                println!("{trimmed}");
            }
        }
        Event::GarbageCollectionFailed(error) => {
            ui::warn(&format!("nix-collect-garbage failed: {error}"))
        }
        Event::GarbageCollectionRetry => {
            ui::info("Retrying after clearing Nix profile generations...")
        }
        Event::GarbageCollectionRetryFailed(error) => {
            ui::warn(&format!("nix-collect-garbage retry failed: {error}"))
        }
        Event::DiskAfter { before, after } => {
            let freed = match before {
                Some(before) if before > after => format!(" (freed {}%)", before - after),
                _ => String::new(),
            };
            ui::success(&format!("Dev VM disk usage: {after}%{freed}"));
        }
    }
}

/// Nuclear always requires interactive text; --yes cannot bypass this.
fn confirm_tier(tier: Tier, identity: Identity, yes_flag: bool) -> Result<bool> {
    if tier == Tier::Nuclear {
        if !std::io::stdin().is_terminal() {
            anyhow::bail!(
                "--nuclear requires an interactive terminal for confirmation. \
                 Run from a TTY."
            );
        }
        match identity {
            Identity::Wipe => ui::warn(
                "NUCLEAR will delete every entry under the mvm root, \
                 including the host signer keypair, audit chain, \
                 attestation identity, secrets and config.toml. Past \
                 audit logs will become unverifiable. Pass --keep-identity \
                 to spare them.",
            ),
            Identity::Keep => ui::warn(
                "NUCLEAR will delete every entry under the mvm root except \
                 the host's cryptographic identity: templates, machines, \
                 images, checkpoints and snapshots all go.",
            ),
        }
        let entered = ui::prompt_text("Type DELETE-EVERYTHING to confirm:")
            .context("reading destructive confirmation from interactive prompt")?;
        Ok(entered.trim() == "DELETE-EVERYTHING")
    } else if yes_flag {
        Ok(true)
    } else {
        Ok(ui::confirm(&format!("Proceed with --{}?", tier.name())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args() -> Args {
        Args {
            keep: None,
            all: false,
            cache: false,
            state: false,
            nuclear: false,
            keep_identity: false,
            dry_run: false,
            yes: false,
            force: false,
        }
    }

    #[test]
    fn pick_tier_priority_nuclear_wins() {
        let args = Args {
            cache: true,
            state: true,
            nuclear: true,
            ..args()
        };
        assert_eq!(pick_tier(&args), Some(Tier::Nuclear));
    }

    #[test]
    fn pick_tier_returns_none_when_no_tier_flag_set() {
        assert_eq!(pick_tier(&args()), None);
    }

    #[test]
    fn request_preserves_defaults_all_force_identity_and_dry_run_mapping() {
        let default = request(&args()).unwrap();
        assert_eq!(default.retention.count(), 5);
        assert_eq!(default.intent, Intent::Apply);
        assert!(
            request(&Args {
                keep: Some(0),
                ..args()
            })
            .is_err()
        );
        let mapped = request(&Args {
            all: true,
            keep: Some(0),
            force: true,
            nuclear: true,
            keep_identity: true,
            dry_run: true,
            ..args()
        })
        .unwrap();
        assert_eq!(mapped.retention, Retention::All);
        assert_eq!(mapped.tier, Some(Tier::Nuclear));
        assert_eq!(mapped.identity, Identity::Keep);
        assert!(mapped.force);
        assert_eq!(mapped.intent, Intent::Apply);
        assert_eq!(
            request(&Args {
                cache: true,
                ..args()
            })
            .unwrap()
            .tier,
            Some(Tier::Cache)
        );
        assert_eq!(
            request(&Args {
                state: true,
                ..args()
            })
            .unwrap()
            .tier,
            Some(Tier::State)
        );
    }
}
