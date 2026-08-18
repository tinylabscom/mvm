//! `mvmctl plugin` — emit the files a coding agent needs to reach for mvm.
//!
//! The docs already tell agent authors to drive the CLI (see the agent tool
//! contract guide). What was missing is the step before that: an agent only
//! uses a tool it has been told about, and telling it means dropping a file in
//! the right place with the right shape.
//!
//! This writes that file. It does **not** stand up a server. The tool an agent
//! needs already exists and already audits every launch — `mvmctl run` — so a
//! protocol layer in front of it would be a second way to say the same thing.
//! That was tried: [ADR-002] shipped a local MCP server and withdrew it as "a
//! surface nobody drove … duplicated authority that the CLI's JSON output and
//! the SDKs already expose". The withdrawal reasoning still holds, so this
//! deliberately stays on the near side of it.
//!
//! Only targets whose file format can be verified are offered. Emitting a
//! config for an agent whose schema was guessed at would produce a file that
//! looks installed and does nothing.

use anyhow::{Context, Result};
use clap::{Args as ClapArgs, Subcommand};

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    #[command(subcommand)]
    pub action: PluginAction,
}

#[derive(Subcommand, Debug, Clone)]
pub(in crate::commands) enum PluginAction {
    /// List the agents mvm can emit an integration for.
    List,
    /// Write the integration files for one agent.
    Install {
        /// Which agent.
        #[arg(value_enum)]
        target: PluginTarget,
        /// Project root to install into. Defaults to the working directory.
        #[arg(long, value_name = "DIR")]
        dir: Option<std::path::PathBuf>,
        /// Overwrite an existing file.
        #[arg(long)]
        force: bool,
        /// Print what would be written without writing it.
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub(in crate::commands) enum PluginTarget {
    /// Claude Code — installs a skill under `.claude/skills/`.
    Claude,
}

impl PluginTarget {
    /// Every target, so `list` and any future walk read one declaration.
    const ALL: &'static [Self] = &[Self::Claude];

    fn label(self) -> &'static str {
        match self {
            Self::Claude => "claude",
        }
    }

    fn description(self) -> &'static str {
        match self {
            Self::Claude => "Claude Code — a skill telling it to sandbox untrusted commands",
        }
    }

    /// Files this target installs, relative to the project root.
    fn files(self) -> Vec<(&'static str, String)> {
        match self {
            Self::Claude => vec![(".claude/skills/mvm-sandbox/SKILL.md", claude_skill())],
        }
    }
}

pub(in crate::commands) fn run(args: Args) -> Result<()> {
    match args.action {
        PluginAction::List => {
            println!("Agents mvm can emit an integration for:\n");
            for target in PluginTarget::ALL {
                println!("  {:<8} {}", target.label(), target.description());
            }
            println!(
                "\nEach one drives `mvmctl run`, which admits through a signed plan and \
                 audits every launch. mvm runs no agent-facing server."
            );
            Ok(())
        }
        PluginAction::Install {
            target,
            dir,
            force,
            dry_run,
        } => install(target, dir, force, dry_run),
    }
}

fn install(
    target: PluginTarget,
    dir: Option<std::path::PathBuf>,
    force: bool,
    dry_run: bool,
) -> Result<()> {
    let root = match dir {
        Some(d) => d,
        None => std::env::current_dir().context("resolving the working directory")?,
    };

    for (rel, contents) in target.files() {
        let path = root.join(rel);

        // These land in a directory the user curates by hand. Silently
        // replacing something they wrote would be the worst way for this to
        // fail, so an existing file stops the install and names the flag.
        if path.exists() && !force {
            anyhow::bail!(
                "{} already exists; pass --force to overwrite it",
                path.display()
            );
        }

        if dry_run {
            println!("would write {} ({} bytes)", path.display(), contents.len());
            continue;
        }

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        std::fs::write(&path, &contents).with_context(|| format!("writing {}", path.display()))?;
        println!("wrote {}", path.display());
    }

    if !dry_run {
        println!(
            "\n{} can now reach mvm. Nothing was started — the skill shells to `mvmctl run`.",
            target.label()
        );
    }
    Ok(())
}

/// The Claude Code skill.
///
/// Written against the CLI as it is, not as the docs once described it: `run`
/// is the flagship one-shot, egress is deny-all unless admitted, and the
/// profile default is `standard`. A skill that names a flag that does not
/// exist is worse than no skill, because the agent will type it.
fn claude_skill() -> String {
    r#"---
name: mvm-sandbox
description: Use when running code you did not write, or a command whose blast radius you are unsure of - test suites from a fetched branch, generated scripts, install steps, anything untrusted. Runs it in a hardware-isolated microVM with no network instead of on the host.
---

# Running untrusted code in a microVM

`mvmctl run` boots a fresh microVM, runs one command, and tears it down.

```sh
mvmctl run -- <command>
```

The guest has **no network device at all**. Egress leaves only over a host-side
vsock endpoint, and only to destinations policy admitted, so the default is a
sandbox that cannot phone home.

## Picking the image

You usually should not. `run` infers one:

```sh
mvmctl run -- npm test        # node, from the command
mvmctl run -- pytest          # python, from the command
mvmctl run -- cargo test      # rust, from the command
```

Inference order: an `mvm.toml` in or above the working directory, then the
command, then a project file (`package.json`, `Cargo.toml`, `pyproject.toml`,
`go.mod`, `Gemfile`). It announces what it picked before booting.

Override when you need to:

```sh
mvmctl run --runtime python -- ./script.py   # name a catalog runtime
mvmctl run --image alpine:3.20 -- sh -c '...'  # name an image
mvmctl run --no-detect -- /bin/true          # bundled default, infer nothing
```

## Flags worth knowing

| Flag | Use |
| --- | --- |
| `--mount HOST:/GUEST:ro` | Give the guest a read-only view of a directory |
| `--allow-host HOST[:PORT]` | Admit one egress destination. Without it, none |
| `--timeout SECS` | Bound the run |
| `--profile restrictive` | No env, no mounts |
| `--json` | Machine-readable summary; exit code preserved |
| `--receipt PATH` | Signed record of what ran |

## Do not

- Do not pass secrets with `--env`. Use `mvmctl secret set` and let the host
  substitute them on the way out, so the value never enters the guest.
- Do not reach for `--profile permissive`. It needs an explicit
  acknowledgement env var, and if you want it you probably want `--mount` or
  `--allow-host` instead.
- Do not use this to run the user's own project commands they asked you to run
  directly. It is for code whose behaviour you cannot vouch for.

## Checking it works

```sh
mvmctl doctor      # host backend and posture
mvmctl run -- echo ok
```
"#
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_skill_frontmatter_is_well_formed() {
        let skill = claude_skill();
        assert!(skill.starts_with("---\n"), "needs YAML frontmatter");
        let body = skill.strip_prefix("---\n").expect("prefix");
        let (front, _) = body.split_once("\n---\n").expect("frontmatter must close");
        assert!(front.contains("name: mvm-sandbox"));
        assert!(
            front.contains("description: Use when"),
            "the description decides whether the skill is ever invoked"
        );
    }

    /// A skill that names a flag the CLI does not have is worse than no skill,
    /// because the agent will type it. Every `--flag` in the skill text is
    /// extracted and resolved — an earlier version of this test compared
    /// against a hardcoded list instead, which meant renaming a flag in the
    /// skill kept it green.
    #[test]
    fn every_flag_the_skill_names_exists_on_the_verb_it_names() {
        let cmd = crate::commands::cli_command();
        let run = cmd
            .get_subcommands()
            .find(|c| c.get_name() == "run")
            .expect("run must exist");
        let known: Vec<String> = run
            .get_arguments()
            .flat_map(|a| {
                a.get_long()
                    .into_iter()
                    .chain(a.get_all_aliases().into_iter().flatten())
                    .map(|l| format!("--{l}"))
                    .collect::<Vec<_>>()
            })
            .collect();

        let skill = claude_skill();
        let mut checked = 0;
        for token in skill.split_whitespace() {
            let token = token.trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '-');
            if !token.starts_with("--") || token.len() < 4 {
                continue;
            }
            // Env-var acknowledgements and prose dashes are not flags.
            if token.chars().any(|c| c.is_ascii_uppercase()) {
                continue;
            }
            assert!(
                known.iter().any(|f| f == token),
                "the skill names `{token}`, which `mvmctl run` does not have; \
                 known: {known:?}"
            );
            checked += 1;
        }
        assert!(
            checked >= 8,
            "expected to resolve several flags from the skill, saw {checked}"
        );
    }

    /// Every command the skill shows must resolve, for the same reason.
    #[test]
    fn every_command_the_skill_shows_resolves() {
        let cmd = crate::commands::cli_command();
        let skill = claude_skill();
        let mut checked = 0;
        for line in skill.lines() {
            let line = line
                .trim()
                .trim_start_matches("| `")
                .trim_start_matches('`');
            let Some(rest) = line.strip_prefix("mvmctl ") else {
                continue;
            };
            let Some(verb) = rest.split_whitespace().next() else {
                continue;
            };
            // Inline code (`` `mvmctl run` ``) and table cells leave trailing
            // punctuation on the token.
            let verb = verb.trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '-');
            if verb.is_empty() || verb.starts_with('-') {
                continue;
            }
            assert!(
                cmd.get_subcommands().any(|c| c.get_name() == verb),
                "the skill shows `mvmctl {verb}`, which is not a command"
            );
            checked += 1;
        }
        assert!(
            checked >= 5,
            "expected to check several commands, saw {checked}"
        );
    }

    /// Every listed target must actually emit something. A target that lists
    /// itself and writes nothing is an install that silently no-ops.
    #[test]
    fn every_listed_target_emits_at_least_one_file() {
        for target in PluginTarget::ALL {
            let files = target.files();
            assert!(!files.is_empty(), "{} emits nothing", target.label());
            for (rel, contents) in files {
                assert!(!rel.is_empty() && !contents.trim().is_empty());
            }
        }
    }

    #[test]
    fn install_refuses_to_clobber_and_dry_run_writes_nothing() {
        let dir = tempfile::tempdir().expect("tmp");
        let target = PluginTarget::Claude;
        let (rel, _) = target.files().into_iter().next().expect("one file");
        let path = dir.path().join(rel);

        install(target, Some(dir.path().to_path_buf()), false, true).expect("dry run");
        assert!(!path.exists(), "--dry-run must not write");

        install(target, Some(dir.path().to_path_buf()), false, false).expect("install");
        assert!(path.is_file(), "install must write the skill");

        std::fs::write(&path, b"hand-edited").expect("edit");
        let err = install(target, Some(dir.path().to_path_buf()), false, false)
            .expect_err("a second install must refuse");
        assert!(err.to_string().contains("--force"), "{err}");
        assert_eq!(
            std::fs::read_to_string(&path).expect("read"),
            "hand-edited",
            "the refusal must leave the user's file alone"
        );

        install(target, Some(dir.path().to_path_buf()), true, false).expect("forced");
        assert!(
            std::fs::read_to_string(&path)
                .expect("read")
                .contains("mvm-sandbox"),
            "--force must overwrite"
        );
    }
}
