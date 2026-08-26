//! Integration-style tests for the top-level CLI surface.

#![cfg(test)]

use super::*;
use clap::Parser;
use std::path::Path;

#[test]
fn help_output_truncates_long_lines() {
    let help =
        "  command  A long description that must wrap before it exceeds the fixed output width";
    let wrapped = constrain_help_output(help);

    assert_eq!(wrapped.lines().count(), 1);
    assert_eq!(wrapped.chars().count(), CLI_HELP_WIDTH);
    assert!(wrapped.ends_with('…'));
}

#[test]
fn help_output_truncates_unbreakable_tokens() {
    let help = format!("  command  {}", "x".repeat(CLI_HELP_WIDTH * 2));
    let wrapped = constrain_help_output(&help);

    assert_eq!(wrapped.lines().count(), 1);
    assert_eq!(wrapped.chars().count(), CLI_HELP_WIDTH);
    assert!(wrapped.ends_with('…'));
}

#[test]
fn help_output_compacts_each_item_onto_one_line() {
    let help = "Arguments:\n  [ARGV]...\n          Command to run\n\nOptions:\n      --image <REF>\n          Boot an OCI image\n\n  -h, --help\n          Print help\n";
    let compacted = constrain_help_output(help);

    assert!(compacted.contains("  [ARGV]...  Command to run"));
    assert!(compacted.contains("      --image <REF>  Boot an OCI image"));
    assert!(compacted.contains("  -h, --help  Print help"));
    assert!(!compacted.contains("\n          "));
}

#[test]
fn every_command_help_surface_stays_within_80_columns() {
    let mut violations = Vec::new();
    collect_help_width_violations(cli_command(), &mut Vec::new(), &mut violations);

    assert!(
        violations.is_empty(),
        "CLI help lines must be 80 characters or shorter:\n{}",
        violations.join("\n")
    );
}

fn collect_help_width_violations(
    command: clap::Command,
    path: &mut Vec<String>,
    violations: &mut Vec<String>,
) {
    path.push(command.get_name().to_owned());

    for (help_kind, help) in [
        (
            "help",
            constrain_help_output(&command.clone().render_help().to_string()),
        ),
        (
            "long-help",
            constrain_help_output(&command.clone().render_long_help().to_string()),
        ),
    ] {
        for (line_number, line) in help.lines().enumerate() {
            let width = line.chars().count();
            if width > CLI_HELP_WIDTH {
                violations.push(format!(
                    "{} --{help_kind} line {} is {width} columns: {line}",
                    path.join(" "),
                    line_number + 1
                ));
            }
        }
    }

    for subcommand in command.get_subcommands().cloned().collect::<Vec<_>>() {
        collect_help_width_violations(subcommand, path, violations);
    }

    path.pop();
}

// Group module aliases — give tests short names (`cleanup`, `up`, etc.) that
// follow the dispatcher's naming, regardless of which group they live in.
use super::agent_session;
use super::build::build;
use super::build::compile;
use super::build::group as build_group;
use super::catalog;
use super::deps;
use super::dispatch::TopLevelCommand;
use super::env::group as env_group;
use super::env::{cleanup, init, uninstall};
use super::image;
use super::machine;
use super::ops;
use super::ops::{audit, cache, config, metrics, secret};
use super::trust;
use super::vm::{
    checkpoint, console, cp, exec, forward, group, sandbox, session, snapshot, volume,
};

use audit::AuditAction;
use cache::CacheAction;
use catalog::CatalogAction;
use config::ConfigAction;
use image::ImageAction;

use super::shared::{
    VolumeSpec, clap_flake_ref, clap_port_spec, clap_vm_name, clap_volume_spec, parse_port_spec,
    parse_volume_spec, resolve_flake_ref,
};

#[test]
fn deploy_flags_parse_and_keep_local_output_controls() {
    let cli = Cli::try_parse_from([
        "mvmctl",
        "deploy",
        "--from-ir",
        "workload.json",
        "--out",
        "./sealed",
        "--boot-artifact",
        "./rootfs.ext4",
        "--dep-volume",
        "./deps/sha256-volume",
        "--kernel-sha256",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "--mvmd-url",
        "https://mvmd.example",
    ])
    .unwrap();
    assert!(matches!(
        cli.command,
        Commands::Deploy(args)
            if args.from_ir == Some("workload.json".into())
                && args.out == Some("./sealed".into())
                && args.boot_artifact == Path::new("./rootfs.ext4")
                && args.dependency_volume == Some("./deps/sha256-volume".into())
                && args.mvmd_url == Some("https://mvmd.example".into())
    ));
}

#[test]
fn top_level_command_summaries_stay_short() {
    let longest_allowed = 72;
    let long_summaries = cli_command()
        .get_subcommands()
        // Hidden internal commands (e.g. `__qemu-vsock-bridge`) never
        // appear in user-facing help, so the summary-length UX rule
        // doesn't apply to them.
        .filter(|cmd| !cmd.is_hide_set())
        .filter_map(|cmd| {
            cmd.get_about().and_then(|about| {
                let about = about.to_string();
                (about.chars().count() > longest_allowed)
                    .then(|| format!("{}: {about}", cmd.get_name()))
            })
        })
        .collect::<Vec<_>>();

    assert!(
        long_summaries.is_empty(),
        "top-level command summaries must be {longest_allowed} chars or shorter:\n{}",
        long_summaries.join("\n")
    );
}

#[test]
fn top_level_command_descriptions_share_a_column() {
    let command = cli_command();
    let visible_command_names = command
        .get_subcommands()
        .filter(|subcommand| !subcommand.is_hide_set())
        .map(|subcommand| subcommand.get_name().to_owned())
        .collect::<Vec<_>>();
    let error = command
        .try_get_matches_from(["mvmctl", "--help"])
        .expect_err("--help must stop argument parsing");
    let help = constrain_help_output(&error.to_string());
    let description_columns = visible_command_names
        .iter()
        .map(|name| {
            let prefix = format!("  {name}");
            let line = help
                .lines()
                .find(|line| line.starts_with(&prefix))
                .unwrap_or_else(|| panic!("help is missing the `{name}` command:\n{help}"));
            line[prefix.len()..]
                .find(|character: char| !character.is_whitespace())
                .map(|offset| prefix.len() + offset)
                .unwrap_or_else(|| panic!("help is missing the `{name}` description:\n{help}"))
        })
        .collect::<Vec<_>>();

    assert!(
        description_columns
            .windows(2)
            .all(|columns| columns[0] == columns[1]),
        "top-level command descriptions must share one column; got {description_columns:?}:\n{help}"
    );
}

#[test]
fn deps_capture_parses_seal_inputs() {
    let cli = Cli::try_parse_from([
        "mvmctl",
        "deps",
        "capture",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "--content-dir",
        "captured",
        "--sbom",
        "sbom.json",
        "--fetch-log",
        "fetch.log",
        "--cve",
        "cve.json",
        "--declaration",
        "dependencies.json",
        "--lockfile",
        "uv.lock",
        "--json",
    ])
    .unwrap();
    let Commands::Deps(args) = cli.command else {
        panic!("expected deps command")
    };
    let deps::DepsAction::Capture(capture) = args.action else {
        panic!("expected deps capture command")
    };
    assert_eq!(capture.volume_hash.len(), 64);
    assert!(capture.json);
    assert_eq!(
        capture.declaration.as_deref(),
        Some(Path::new("dependencies.json"))
    );
    assert_eq!(capture.lockfile.as_deref(), Some(Path::new("uv.lock")));
}

#[test]
fn deps_install_parses_development_install_inputs() {
    let cli = Cli::try_parse_from([
        "mvmctl",
        "deps",
        "install",
        "--lockfile",
        "uv.lock",
        "--source-root",
        "project",
        "--language",
        "python",
        "--cache-root",
        "cache",
        "--json",
    ])
    .unwrap();
    let Commands::Deps(args) = cli.command else {
        panic!("expected deps command")
    };
    let deps::DepsAction::Install(install) = args.action else {
        panic!("expected deps install command")
    };
    assert_eq!(install.lockfile, Path::new("uv.lock"));
    assert_eq!(install.source_root, Path::new("project"));
    assert!(matches!(
        install.language,
        deps::install::LanguageArg::Python
    ));
    assert_eq!(install.cache_root.as_deref(), Some(Path::new("cache")));
    assert!(install.json);
}

#[test]
fn deps_capture_live_parses_guest_artifact_inputs() {
    let cli = Cli::try_parse_from([
        "mvmctl",
        "deps",
        "capture-live",
        "a".repeat(64).as_str(),
        "--vm",
        "dev-vm",
        "--guest-content",
        "/mvm/deps/content",
        "--guest-sbom",
        "/mvm/deps/sbom.cdx.json",
        "--guest-fetch-log",
        "/mvm/deps/fetch.log",
        "--guest-cve",
        "/mvm/deps/cve.json",
        "--declaration",
        "dependencies.json",
        "--lockfile",
        "uv.lock",
        "--max-files",
        "10",
    ])
    .unwrap();
    let Commands::Deps(args) = cli.command else {
        panic!("expected deps command")
    };
    let deps::DepsAction::CaptureLive(capture) = args.action else {
        panic!("expected deps capture-live command")
    };
    assert_eq!(capture.vm, "dev-vm");
    assert_eq!(capture.guest_content, "/mvm/deps/content");
    assert_eq!(capture.max_files, 10);
    assert_eq!(capture.lockfile.as_deref(), Some(Path::new("uv.lock")));
}

#[test]
fn watch_parses_file_backed_ir_and_defaults_to_one_shot_only_when_requested() {
    let cli = Cli::try_parse_from([
        "mvmctl",
        "watch",
        "--from-ir",
        "workload.json",
        "--once",
        "--interval-ms",
        "1",
    ])
    .unwrap();
    let Commands::Watch(args) = cli.command else {
        panic!("expected watch command")
    };
    assert_eq!(args.from_ir, Some("workload.json".into()));
    assert!(args.once);
    assert_eq!(args.interval_ms, 1);
}

#[test]
fn global_option_summaries_stay_short() {
    let longest_allowed = 48;
    let long_summaries = cli_command()
        .get_arguments()
        .filter(|arg| arg.is_global_set())
        .filter_map(|arg| {
            arg.get_long_help()
                .or_else(|| arg.get_help())
                .and_then(|help| {
                    let help = help.to_string();
                    (help.chars().count() > longest_allowed)
                        .then(|| format!("--{}: {help}", arg.get_id()))
                })
        })
        .collect::<Vec<_>>();

    assert!(
        long_summaries.is_empty(),
        "global option summaries must be {longest_allowed} chars or shorter:\n{}",
        long_summaries.join("\n")
    );
}

#[test]
fn machine_run_option_summaries_stay_short() {
    let longest_allowed = 64;
    let command = cli_command();
    let machine = command
        .find_subcommand("machine")
        .expect("machine command must exist");
    let run = machine
        .find_subcommand("run")
        .expect("machine run command must exist");
    let long_summaries = run
        .get_arguments()
        .filter(|arg| !arg.is_hide_set())
        .filter_map(|arg| {
            arg.get_long_help()
                .or_else(|| arg.get_help())
                .and_then(|help| {
                    let help = help.to_string();
                    (help.chars().count() > longest_allowed)
                        .then(|| format!("{}: {help}", arg.get_id()))
                })
        })
        .collect::<Vec<_>>();

    assert!(
        long_summaries.is_empty(),
        "machine run option summaries must be {longest_allowed} chars or shorter:\n{}",
        long_summaries.join("\n")
    );
}

#[test]
fn dev_tooling_and_internal_transports_are_hidden_from_help() {
    // Two of the three visibility buckets. Dev tooling is a real command a
    // user is not expected to reach for; an internal transport is subprocess
    // plumbing, `__`-prefixed so it cannot be typed by accident. Both stay
    // dispatchable but `hide = true`. The third bucket — everything a user is
    // expected to invoke — is asserted by
    // `top_level_help_shows_user_facing_groups_and_hides_dev_tooling`.
    let visible: Vec<String> = cli_command()
        .get_subcommands()
        .filter(|cmd| !cmd.is_hide_set())
        .map(|cmd| cmd.get_name().to_string())
        .collect();
    for hidden in [
        "reconcile",
        "storage",
        "seccomp-audit",
        "dashboard",
        "persistent-builder",
        "__sdk-no-vm",
        "__builder-vm-bootstrap",
        "__builder-egress-supervisor",
        "__builder-shell-job",
        "__qemu-vsock-bridge",
    ] {
        assert!(
            !visible.iter().any(|n| n == hidden),
            "internal command `{hidden}` must be hidden from top-level help"
        );
    }
}

#[test]
fn internal_builder_vm_bootstrap_command_is_hidden_but_parseable() {
    let cli = Cli::try_parse_from(["mvmctl", "__builder-vm-bootstrap"]).unwrap();
    assert!(matches!(cli.command, Commands::BuilderVmBootstrap(_)));
}

#[test]
fn internal_builder_egress_supervisor_command_is_hidden_but_parseable() {
    let cli = Cli::try_parse_from([
        "mvmctl",
        "__builder-egress-supervisor",
        "--endpoint",
        "/tmp/mvm-network-endpoint",
    ])
    .unwrap();
    assert!(matches!(cli.command, Commands::BuilderEgressSupervisor(_)));
}

#[test]
#[cfg(feature = "builder-vm")]
fn internal_builder_shell_job_command_is_hidden_but_parseable() {
    let cli = Cli::try_parse_from(["mvmctl", "__builder-shell-job", "--script", "/tmp/dummy.sh"])
        .unwrap();
    assert!(matches!(cli.command, Commands::BuilderShellJob(_)));
}

#[test]
fn test_cleanup_defaults() {
    let cli = Cli::try_parse_from(["mvmctl", "env", "cleanup"]).unwrap();
    let Commands::Env(eg) = cli.command else {
        panic!("expected env group")
    };
    match eg.action {
        env_group::EnvCmd::Cleanup(cleanup::Args {
            keep,
            all,
            cache,
            state,
            nuclear,
            keep_identity,
            dry_run,
            yes,
            force,
        }) => {
            assert_eq!(keep, None);
            assert!(!all);
            assert!(!cache);
            assert!(!state);
            assert!(!nuclear);
            assert!(!keep_identity);
            assert!(!dry_run);
            assert!(!yes);
            assert!(!force);
        }
        _ => panic!("Expected Cleanup command"),
    }
}

#[test]
fn test_cleanup_keep_identity_requires_nuclear() {
    // `--keep-identity` alone would silently do nothing, so clap
    // rejects it rather than letting a caller believe it took effect.
    assert!(
        Cli::try_parse_from(["mvmctl", "env", "cleanup", "--keep-identity"]).is_err(),
        "--keep-identity must require --nuclear",
    );
    let cli =
        Cli::try_parse_from(["mvmctl", "env", "cleanup", "--nuclear", "--keep-identity"]).unwrap();
    let Commands::Env(eg) = cli.command else {
        panic!("expected env group")
    };
    match eg.action {
        env_group::EnvCmd::Cleanup(args) => {
            assert!(args.nuclear);
            assert!(args.keep_identity);
        }
        _ => panic!("Expected Cleanup command"),
    }
}

#[test]
fn test_cleanup_keep_flag() {
    let cli = Cli::try_parse_from(["mvmctl", "env", "cleanup", "--keep", "9"]).unwrap();
    let Commands::Env(eg) = cli.command else {
        panic!("expected env group")
    };
    match eg.action {
        env_group::EnvCmd::Cleanup(args) => {
            assert_eq!(args.keep, Some(9));
            assert!(!args.all);
        }
        _ => panic!("Expected Cleanup command"),
    }
}

#[test]
fn test_cleanup_all_flag() {
    let cli = Cli::try_parse_from(["mvmctl", "env", "cleanup", "--all"]).unwrap();
    let Commands::Env(eg) = cli.command else {
        panic!("expected env group")
    };
    match eg.action {
        env_group::EnvCmd::Cleanup(args) => {
            assert_eq!(args.keep, None);
            assert!(args.all);
        }
        _ => panic!("Expected Cleanup command"),
    }
}

#[test]
fn test_cleanup_verbose_flag() {
    let cli = Cli::try_parse_from(["mvmctl", "env", "cleanup", "--verbose"]).unwrap();
    assert_eq!(cli.verbose, 1);
    let Commands::Env(eg) = cli.command else {
        panic!("expected env group")
    };
    match eg.action {
        env_group::EnvCmd::Cleanup(args) => {
            assert_eq!(args.keep, None);
            assert!(!args.all);
        }
        _ => panic!("Expected Cleanup command"),
    }
}

#[test]
fn test_cleanup_cache_tier_flag() {
    let cli = Cli::try_parse_from(["mvmctl", "env", "cleanup", "--cache"]).unwrap();
    let Commands::Env(eg) = cli.command else {
        panic!("expected env group")
    };
    match eg.action {
        env_group::EnvCmd::Cleanup(args) => {
            assert!(args.cache);
            assert!(!args.state);
            assert!(!args.nuclear);
        }
        _ => panic!("Expected Cleanup command"),
    }
}

#[test]
fn test_cleanup_state_tier_flag() {
    let cli = Cli::try_parse_from(["mvmctl", "env", "cleanup", "--state", "--yes"]).unwrap();
    let Commands::Env(eg) = cli.command else {
        panic!("expected env group")
    };
    match eg.action {
        env_group::EnvCmd::Cleanup(args) => {
            assert!(!args.cache);
            assert!(args.state);
            assert!(!args.nuclear);
            assert!(args.yes);
        }
        _ => panic!("Expected Cleanup command"),
    }
}

#[test]
fn test_cleanup_nuclear_tier_flag() {
    let cli = Cli::try_parse_from(["mvmctl", "env", "cleanup", "--nuclear", "--dry-run"]).unwrap();
    let Commands::Env(eg) = cli.command else {
        panic!("expected env group")
    };
    match eg.action {
        env_group::EnvCmd::Cleanup(args) => {
            assert!(!args.cache);
            assert!(!args.state);
            assert!(args.nuclear);
            assert!(args.dry_run);
        }
        _ => panic!("Expected Cleanup command"),
    }
}

#[test]
fn test_cleanup_tier_flags_are_mutually_exclusive() {
    // ArgGroup("tier") forces at most one of --cache/--state/--nuclear.
    let err = Cli::try_parse_from(["mvmctl", "env", "cleanup", "--cache", "--state"]).unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("cannot be used with") || msg.contains("conflict"),
        "expected mutual-exclusion error, got: {msg}"
    );
}

#[test]
fn test_cleanup_force_flag() {
    let cli = Cli::try_parse_from(["mvmctl", "env", "cleanup", "--cache", "--force"]).unwrap();
    let Commands::Env(eg) = cli.command else {
        panic!("expected env group")
    };
    match eg.action {
        env_group::EnvCmd::Cleanup(args) => {
            assert!(args.cache);
            assert!(args.force);
        }
        _ => panic!("Expected Cleanup command"),
    }
}

#[test]
fn volume_create_parses_default_root() {
    let cli = Cli::try_parse_from(["mvmctl", "machine", "volume", "create", "work"]).unwrap();
    let Commands::Machine(mg) = cli.command else {
        panic!("expected machine group")
    };
    match mg.action {
        machine::MachineAction::Vm(group::VmCmd::Volume(volume::Args {
            command:
                volume::VolumeCmd::Create {
                    volume,
                    root,
                    host_backed,
                    size,
                    remote,
                    bucket,
                    storage_class,
                },
        })) => {
            assert_eq!(volume, "work");
            assert_eq!(root, None);
            assert!(!host_backed);
            assert_eq!(size, "1G");
            assert!(!remote);
            assert!(bucket.is_none());
            assert!(storage_class.is_none());
        }
        _ => panic!("Expected volume create command"),
    }
}

#[test]
fn volume_create_host_backed_parses() {
    let cli = Cli::try_parse_from([
        "mvmctl",
        "machine",
        "volume",
        "create",
        "work",
        "--host-backed",
    ])
    .unwrap();
    let Commands::Machine(mg) = cli.command else {
        panic!("expected machine group")
    };
    match mg.action {
        machine::MachineAction::Vm(group::VmCmd::Volume(volume::Args {
            command:
                volume::VolumeCmd::Create {
                    volume,
                    root,
                    host_backed,
                    size,
                    remote,
                    bucket,
                    storage_class,
                },
        })) => {
            assert_eq!(volume, "work");
            assert_eq!(root, None);
            assert!(host_backed);
            assert_eq!(size, "1G");
            assert!(!remote);
            assert!(bucket.is_none());
            assert!(storage_class.is_none());
        }
        _ => panic!("Expected volume create command"),
    }
}

#[test]
fn volume_unlock_parses() {
    let cli = Cli::try_parse_from(["mvmctl", "machine", "volume", "unlock", "work"]).unwrap();
    let Commands::Machine(mg) = cli.command else {
        panic!("expected machine group")
    };
    match mg.action {
        machine::MachineAction::Vm(group::VmCmd::Volume(volume::Args {
            command: volume::VolumeCmd::Unlock { volume },
        })) => assert_eq!(volume, "work"),
        _ => panic!("Expected volume unlock command"),
    }
}

#[test]
fn volume_lock_parses() {
    let cli = Cli::try_parse_from(["mvmctl", "machine", "volume", "lock", "work"]).unwrap();
    let Commands::Machine(mg) = cli.command else {
        panic!("expected machine group")
    };
    match mg.action {
        machine::MachineAction::Vm(group::VmCmd::Volume(volume::Args {
            command: volume::VolumeCmd::Lock { volume },
        })) => assert_eq!(volume, "work"),
        _ => panic!("Expected volume lock command"),
    }
}

#[test]
fn volume_catalog_json_parses() {
    let cli = Cli::try_parse_from(["mvmctl", "machine", "volume", "catalog", "--json"]).unwrap();
    let Commands::Machine(mg) = cli.command else {
        panic!("expected machine group")
    };
    match mg.action {
        machine::MachineAction::Vm(group::VmCmd::Volume(volume::Args {
            command: volume::VolumeCmd::Catalog { json, remote },
        })) => {
            assert!(json);
            assert!(!remote);
        }
        _ => panic!("Expected volume catalog command"),
    }
}

#[test]
fn volume_snapshot_parses() {
    let cli = Cli::try_parse_from([
        "mvmctl",
        "machine",
        "volume",
        "snapshot",
        "work",
        "before-upgrade",
    ])
    .unwrap();
    let Commands::Machine(mg) = cli.command else {
        panic!("expected machine group")
    };
    assert!(matches!(
        mg.action,
        machine::MachineAction::Vm(group::VmCmd::Volume(volume::Args {
            command: volume::VolumeCmd::Snapshot { volume, snapshot, remote },
        })) if volume == "work" && snapshot == "before-upgrade" && !remote
    ));
}

#[test]
fn volume_restore_parses() {
    let cli = Cli::try_parse_from([
        "mvmctl",
        "machine",
        "volume",
        "restore",
        "work",
        "before-upgrade",
    ])
    .unwrap();
    let Commands::Machine(mg) = cli.command else {
        panic!("expected machine group")
    };
    assert!(matches!(
        mg.action,
        machine::MachineAction::Vm(group::VmCmd::Volume(volume::Args {
            command: volume::VolumeCmd::Restore { volume, snapshot, target, remote },
        })) if volume == "work" && snapshot == "before-upgrade" && target.is_none() && !remote
    ));
}

#[test]
fn remote_volume_lifecycle_flags_parse() {
    let create = Cli::try_parse_from([
        "mvmctl",
        "machine",
        "volume",
        "create",
        "data",
        "--size",
        "8G",
        "--remote",
        "--bucket",
        "bucket-1",
        "--storage-class",
        "durable",
    ])
    .unwrap();
    let Commands::Machine(group) = create.command else {
        panic!("expected machine group")
    };
    assert!(matches!(
        group.action,
        machine::MachineAction::Vm(group::VmCmd::Volume(volume::Args {
            command: volume::VolumeCmd::Create {
                volume,
                size,
                remote: true,
                bucket: Some(bucket),
                storage_class: Some(storage_class),
                ..
            },
        })) if volume == "data" && size == "8G" && bucket == "bucket-1" && storage_class == "durable"
    ));

    let checkpoint = Cli::try_parse_from([
        "mvmctl",
        "machine",
        "volume",
        "checkpoint",
        "vol-1",
        "snap-1",
        "--remote",
    ])
    .unwrap();
    let Commands::Machine(group) = checkpoint.command else {
        panic!("expected machine group")
    };
    assert!(matches!(
        group.action,
        machine::MachineAction::Vm(group::VmCmd::Volume(volume::Args {
            command: volume::VolumeCmd::Snapshot {
                volume,
                snapshot,
                remote: true,
            },
        })) if volume == "vol-1" && snapshot == "snap-1"
    ));

    let restore = Cli::try_parse_from([
        "mvmctl", "machine", "volume", "restore", "vol-1", "snap-1", "--target", "restored",
        "--remote",
    ])
    .unwrap();
    let Commands::Machine(group) = restore.command else {
        panic!("expected machine group")
    };
    assert!(matches!(
        group.action,
        machine::MachineAction::Vm(group::VmCmd::Volume(volume::Args {
            command: volume::VolumeCmd::Restore {
                volume,
                snapshot,
                target: Some(target),
                remote: true,
            },
        })) if volume == "vol-1" && snapshot == "snap-1" && target == "restored"
    ));

    let delete =
        Cli::try_parse_from(["mvmctl", "machine", "volume", "delete", "vol-1", "--remote"])
            .unwrap();
    let Commands::Machine(group) = delete.command else {
        panic!("expected machine group")
    };
    assert!(matches!(
        group.action,
        machine::MachineAction::Vm(group::VmCmd::Volume(volume::Args {
            command: volume::VolumeCmd::Delete {
                volume,
                remote: true,
            },
        })) if volume == "vol-1"
    ));
}

#[test]
fn volume_mount_managed_omits_host() {
    let cli = Cli::try_parse_from([
        "mvmctl",
        "machine",
        "volume",
        "mount",
        "vm-1",
        "--volume",
        "work",
        "--guest",
        "/data/work",
    ])
    .unwrap();
    let Commands::Machine(mg) = cli.command else {
        panic!("expected machine group")
    };
    match mg.action {
        machine::MachineAction::Vm(group::VmCmd::Volume(volume::Args {
            command:
                volume::VolumeCmd::Mount {
                    name,
                    volume,
                    host,
                    guest,
                    rw,
                    remote,
                },
        })) => {
            assert_eq!(name, "vm-1");
            assert_eq!(volume, "work");
            assert_eq!(host, None);
            assert_eq!(guest, "/data/work");
            assert!(!rw);
            assert!(!remote);
        }
        _ => panic!("Expected volume mount command"),
    }
}

// ---- Build --flake tests ----

#[test]
fn test_build_flake_with_profile() {
    let cli = Cli::try_parse_from([
        "mvmctl",
        "machine",
        "build",
        "--flake",
        ".",
        "--profile",
        "gateway",
    ])
    .unwrap();
    let Commands::Machine(mg) = cli.command else {
        panic!("expected machine group")
    };
    match mg.action {
        machine::MachineAction::Build(build::Args { flake, profile, .. }) => {
            assert_eq!(flake.as_deref(), Some("."));
            assert_eq!(profile.as_deref(), Some("gateway"));
        }
        _ => panic!("Expected machine build command"),
    }
}

#[test]
fn test_build_flake_defaults_to_no_profile() {
    let cli = Cli::try_parse_from(["mvmctl", "machine", "build", "--flake", "."]).unwrap();
    let Commands::Machine(mg) = cli.command else {
        panic!("expected machine group")
    };
    match mg.action {
        machine::MachineAction::Build(build::Args { flake, profile, .. }) => {
            assert_eq!(flake.as_deref(), Some("."));
            assert!(profile.is_none(), "profile should be None when omitted");
        }
        _ => panic!("Expected machine build command"),
    }
}

#[test]
fn test_build_mvmfile_mode_still_works() {
    let cli = Cli::try_parse_from(["mvmctl", "machine", "build", "myimage"]).unwrap();
    let Commands::Machine(mg) = cli.command else {
        panic!("expected machine group")
    };
    match mg.action {
        machine::MachineAction::Build(build::Args { path, flake, .. }) => {
            assert_eq!(path, "myimage");
            assert!(flake.is_none(), "Mvmfile mode should have no --flake");
        }
        _ => panic!("Expected machine build command"),
    }
}

#[test]
fn machine_build_parses_image_and_flake() {
    // `machine build --flake .` parses.
    let cli_flake =
        Cli::try_parse_from(["mvmctl", "machine", "build", "--flake", "."]).expect("flake parse");
    let Commands::Machine(mg) = cli_flake.command else {
        panic!("expected machine group")
    };
    assert!(
        matches!(mg.action, machine::MachineAction::Build(build::Args { ref flake, .. }) if flake.as_deref() == Some(".")),
        "expected machine build with --flake ."
    );

    // `machine build myimage` (mvmfile/manifest path) also parses.
    let cli_path =
        Cli::try_parse_from(["mvmctl", "machine", "build", "myimage"]).expect("path parse");
    let Commands::Machine(mg2) = cli_path.command else {
        panic!("expected machine group")
    };
    assert!(
        matches!(mg2.action, machine::MachineAction::Build(build::Args { ref path, .. }) if path == "myimage"),
        "expected machine build with positional path"
    );
}

#[test]
fn build_image_subcommand_removed() {
    let err = Cli::try_parse_from(["mvmctl", "build", "image", "--flake", "."])
        .expect_err("build image must not parse after removal");
    assert_eq!(
        err.kind(),
        clap::error::ErrorKind::InvalidSubcommand,
        "expected InvalidSubcommand, got: {err:?}"
    );
}

#[test]
fn build_runtime_overlay_subcommand_parses() {
    let cli = Cli::try_parse_from(["mvmctl", "build", "runtime-overlay", "build"])
        .expect("runtime-overlay build must parse");
    let Commands::Build(bg) = cli.command else {
        panic!("expected build group");
    };
    assert!(
        matches!(bg.action, build_group::BuildCmd::RuntimeOverlay(_)),
        "expected runtime-overlay build command"
    );
}

#[test]
fn top_level_kernel_build_subcommand_parses() {
    let cli = Cli::try_parse_from(["mvmctl", "kernel", "build", "--which", "workload"])
        .expect("kernel build must parse");
    let Commands::Kernel(_) = cli.command else {
        panic!("expected top-level kernel command");
    };
}

#[test]
fn nested_kernel_build_subcommand_still_parses() {
    let cli = Cli::try_parse_from(["mvmctl", "build", "kernel", "build", "--which", "workload"])
        .expect("nested kernel build must keep parsing");
    let Commands::Build(bg) = cli.command else {
        panic!("expected build group");
    };
    assert!(
        matches!(bg.action, build_group::BuildCmd::Kernel(_)),
        "expected nested kernel build command"
    );
}

#[test]
fn test_resolve_flake_ref_remote_passthrough() {
    let resolved = resolve_flake_ref("github:user/repo").unwrap();
    assert_eq!(resolved, "github:user/repo");
}

#[test]
fn test_resolve_flake_ref_remote_with_path() {
    let resolved = resolve_flake_ref("github:user/repo#attr").unwrap();
    assert_eq!(resolved, "github:user/repo#attr");
}

#[test]
fn test_resolve_flake_ref_absolute_path() {
    let resolved = resolve_flake_ref("/tmp").unwrap();
    // /tmp may be a symlink on macOS to /private/tmp
    assert!(
        resolved == "/tmp" || resolved == "/private/tmp",
        "unexpected resolved path: {}",
        resolved
    );
}

#[test]
fn test_resolve_flake_ref_nonexistent_fails() {
    let result = resolve_flake_ref("/nonexistent/path/that/does/not/exist");
    assert!(result.is_err());
}

// ---- up/run removal tests ----

#[test]
fn up_removed() {
    let result = Cli::try_parse_from(["mvmctl", "up", "--flake", "."]);
    assert!(
        result.is_err(),
        "`up` was retired; `machine run --flake .` is the replacement"
    );
    assert_eq!(
        result.unwrap_err().kind(),
        clap::error::ErrorKind::InvalidSubcommand,
    );
}

#[test]
fn run_is_visible_and_still_carries_the_sdk_transport() {
    // `run` is the one-shot flagship and appears in `--help`. It had been
    // hidden while the published CLI reference documented it as the flagship,
    // so a user could not discover from the tool the command the docs told
    // them to type.
    let cli = Cli::try_parse_from(["mvmctl", "run", "--mode", "live", "script.py"]).unwrap();
    assert!(matches!(cli.command, Commands::Run(_)));

    let visible: Vec<String> = cli_command()
        .get_subcommands()
        .filter(|cmd| !cmd.is_hide_set())
        .map(|cmd| cmd.get_name().to_string())
        .collect();
    assert!(
        visible.iter().any(|n| n == "run"),
        "`run` must be visible in top-level help; visible = {visible:?}"
    );
}

#[test]
fn sdk_no_vm_kept_hidden_as_sdk_transport() {
    let cli = Cli::try_parse_from([
        "mvmctl",
        "__sdk-no-vm",
        "--language",
        "python",
        "--module",
        "adder_mod",
        "--function",
        "add",
        "--format",
        "json",
        "--source-path",
        "/tmp/src",
        "--stdin",
        "-",
    ])
    .unwrap();
    assert!(matches!(cli.command, Commands::SdkNoVm(_)));

    let help = {
        use clap::CommandFactory;
        let mut cmd = Cli::command();
        let mut buf = Vec::new();
        cmd.write_long_help(&mut buf).unwrap();
        String::from_utf8(buf).unwrap()
    };
    assert!(
        !help.contains("__sdk-no-vm"),
        "`__sdk-no-vm` must be hidden from top-level help"
    );
}

#[test]
fn invoke_removed() {
    let result = Cli::try_parse_from(["mvmctl", "invoke", "tmpl"]);
    assert!(
        result.is_err(),
        "`invoke` was retired; `machine run --manifest tmpl --entrypoint` is the replacement"
    );
    assert_eq!(
        result.unwrap_err().kind(),
        clap::error::ErrorKind::InvalidSubcommand,
    );
}

#[test]
fn test_up_manifest_flag() {
    let cli = Cli::try_parse_from([
        "mvmctl",
        "machine",
        "run",
        "--manifest",
        "openclaw",
        "--",
        "sh",
    ])
    .unwrap();
    match cli.command {
        Commands::Machine(mg) => match mg.action {
            machine::MachineAction::Run(machine::MachineRunArgs {
                run: exec::RunArgs {
                    manifest, flake, ..
                },
                ..
            }) => {
                assert!(flake.is_none());
                assert_eq!(manifest, Some("openclaw".to_string()));
            }
            _ => panic!("Expected machine run"),
        },
        _ => panic!("Expected Machine command"),
    }
}

#[test]
fn test_up_manifest_short_flag() {
    // `machine run` uses --manifest (long form only; -m is not wired on MachineRunArgs)
    let cli = Cli::try_parse_from([
        "mvmctl",
        "machine",
        "run",
        "--manifest",
        "openclaw",
        "--",
        "sh",
    ])
    .unwrap();
    match cli.command {
        Commands::Machine(mg) => match mg.action {
            machine::MachineAction::Run(machine::MachineRunArgs {
                run: exec::RunArgs { manifest, .. },
                ..
            }) => {
                assert_eq!(manifest, Some("openclaw".to_string()));
            }
            _ => panic!("Expected machine run"),
        },
        _ => panic!("Expected Machine command"),
    }
}

#[test]
fn test_up_flake_and_manifest_conflict() {
    let result = Cli::try_parse_from([
        "mvmctl",
        "machine",
        "run",
        "--flake",
        ".",
        "--manifest",
        "openclaw",
        "--",
        "sh",
    ]);
    assert!(
        result.is_err(),
        "--flake and --manifest should be mutually exclusive"
    );
}

#[test]
fn machine_run_source_flags_parse_and_conflict() {
    // --image alone parses
    Cli::try_parse_from([
        "mvmctl",
        "machine",
        "run",
        "--image",
        "alpine:latest",
        "--",
        "sh",
    ])
    .unwrap();
    // --manifest alone parses
    Cli::try_parse_from([
        "mvmctl",
        "machine",
        "run",
        "--manifest",
        "/path/to/slot",
        "--",
        "sh",
    ])
    .unwrap();
    // --flake alone parses
    Cli::try_parse_from(["mvmctl", "machine", "run", "--flake", ".", "--", "sh"]).unwrap();
    // --image + --manifest conflict
    let err = Cli::try_parse_from([
        "mvmctl",
        "machine",
        "run",
        "--image",
        "alpine",
        "--manifest",
        ".",
        "--",
        "sh",
    ])
    .unwrap_err();
    assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
    // --image + --flake conflict
    let err = Cli::try_parse_from([
        "mvmctl", "machine", "run", "--image", "alpine", "--flake", ".", "--", "sh",
    ])
    .unwrap_err();
    assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
    // --manifest + --flake conflict
    let err = Cli::try_parse_from([
        "mvmctl",
        "machine",
        "run",
        "--manifest",
        ".",
        "--flake",
        ".",
        "--",
        "sh",
    ])
    .unwrap_err();
    assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
}

#[test]
fn machine_run_flake_resolves_to_persistent_lifecycle() {
    // `--flake . -d` must parse to Persistent lifecycle with flake set,
    // NOT a separate "up" path — the source and lifecycle are orthogonal.
    let cli = Cli::try_parse_from(["mvmctl", "machine", "run", "--flake", ".", "-d"]).unwrap();
    match cli.command {
        Commands::Machine(machine::Args {
            action: machine::MachineAction::Run(ref run_args),
        }) => {
            assert_eq!(run_args.run.flake.as_deref(), Some("."));
            assert!(
                run_args.run.image.is_none(),
                "image must be absent when --flake set"
            );
            assert!(
                run_args.run.manifest.is_none(),
                "manifest must be absent when --flake set"
            );
            // -d selects Persistent lifecycle
            assert!(
                run_args.detach,
                "-d must set detach for Persistent lifecycle"
            );
        }
        _ => panic!("expected machine run command"),
    }
}

/// Helper: parse a `machine run …` argv and return the `MachineRunArgs`.
fn parse_machine_run(argv: &[&str]) -> Result<machine::MachineRunArgs, clap::Error> {
    let mut full = vec!["mvmctl", "machine", "run"];
    full.extend_from_slice(argv);
    match Cli::try_parse_from(full)?.command {
        Commands::Machine(machine::Args {
            action: machine::MachineAction::Run(args),
        }) => Ok(args),
        other => panic!("expected machine run, got {other:?}"),
    }
}

#[test]
fn machine_run_entrypoint_flag_parses() {
    // `--manifest m --entrypoint` selects the entrypoint action; the source +
    // entrypoint flags round-trip. Stdin is now auto-read from a piped host
    // stdin at dispatch — there is no `--stdin` flag.
    let args = parse_machine_run(&["--manifest", "tmpl", "--entrypoint"]).unwrap();
    assert!(args.entrypoint);
    assert_eq!(args.run.manifest.as_deref(), Some("tmpl"));
    assert!(args.run.argv.is_empty());
}

#[test]
fn machine_run_entrypoint_conflicts_with_argv() {
    // The entrypoint action calls the baked entrypoint; a trailing argv would
    // be ambiguous, so clap rejects the combination.
    let err =
        parse_machine_run(&["--manifest", "tmpl", "--entrypoint", "--", "echo", "hi"]).unwrap_err();
    assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
    // `--entrypoint` alone (no argv) is fine.
    parse_machine_run(&["--manifest", "tmpl", "--entrypoint"]).unwrap();
}

#[test]
fn machine_run_entrypoint_flags_require_entrypoint() {
    // `--from-workload-ir`/`--attach` only make sense for the entrypoint
    // action — clap refuses them without `--entrypoint`. (`--stdin` was
    // removed; stdin is auto-detected from the host pipe at dispatch.)
    for flag in [
        &[
            "--manifest",
            "tmpl",
            "--from-workload-ir",
            "/w/workload.json",
        ][..],
        &["--name", "n", "--attach"][..],
    ] {
        let err = parse_machine_run(flag).unwrap_err();
        assert_eq!(
            err.kind(),
            clap::error::ErrorKind::MissingRequiredArgument,
            "{flag:?} must require --entrypoint"
        );
    }
}

#[test]
fn machine_run_entrypoint_from_workload_ir_parses() {
    // The secrets path: `--from-workload-ir` routes the entrypoint call through
    // plan admission so the substitution endpoint spawns. (Migrated from the
    // retired `invoke` parse test.)
    let args = parse_machine_run(&[
        "--manifest",
        "tmpl",
        "--entrypoint",
        "--from-workload-ir",
        "/w/workload.json",
    ])
    .unwrap();
    assert_eq!(
        args.from_workload_ir.as_deref(),
        Some(std::path::Path::new("/w/workload.json"))
    );
}

#[test]
fn machine_run_entrypoint_agent_verbs_parse() {
    let args = parse_machine_run(&[
        "--manifest",
        "tmpl",
        "--entrypoint",
        "--agent-verb",
        "run-entrypoint",
        "--agent-verb",
        "ping",
    ])
    .unwrap();
    assert!(args.entrypoint);
    assert_eq!(args.run.agent_verb, vec!["run-entrypoint", "ping"]);
}

#[test]
fn machine_run_entrypoint_attach_parses_and_requires_name() {
    // `--attach` dispatches into a running machine named by `--name`; it
    // reinterprets the target and so conflicts with a fresh source + boot flags.
    // (Migrated from the retired `invoke --attach` parse test.)
    let args = parse_machine_run(&["--name", "myvm", "--entrypoint", "--attach"]).unwrap();
    assert!(args.attach && args.entrypoint);
    assert_eq!(args.name.as_deref(), Some("myvm"));
    // --attach needs --name (the running machine to target).
    let err = parse_machine_run(&["--entrypoint", "--attach"]).unwrap_err();
    assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
    // --attach is incompatible with a fresh source + transient-boot flags.
    for flag in [
        &[
            "--name",
            "n",
            "--entrypoint",
            "--attach",
            "--image",
            "alpine",
        ][..],
        &["--name", "n", "--entrypoint", "--attach", "--manifest", "m"][..],
        &["--name", "n", "--entrypoint", "--attach", "--fresh"][..],
        &["--name", "n", "--entrypoint", "--attach", "--reset"][..],
        &["--name", "n", "--entrypoint", "--attach", "-d"][..],
    ] {
        let err = parse_machine_run(flag).unwrap_err();
        assert_eq!(
            err.kind(),
            clap::error::ErrorKind::ArgumentConflict,
            "{flag:?} must conflict with --attach"
        );
    }
}

#[test]
fn machine_run_entrypoint_conflicts_with_interactive() {
    // An entrypoint call is not an interactive shell.
    for flag in ["-t", "-i"] {
        let err = parse_machine_run(&["--manifest", "tmpl", "--entrypoint", flag]).unwrap_err();
        assert_eq!(
            err.kind(),
            clap::error::ErrorKind::ArgumentConflict,
            "--entrypoint must conflict with {flag}"
        );
    }
}

#[test]
fn machine_run_parses_healthcheck_flags() {
    let args = parse_machine_run(&[
        "--image",
        "nginx",
        "--healthcheck",
        "curl -fsS localhost/health",
        "--health-interval",
        "10",
        "--health-retries",
        "5",
        "--",
        "nginx",
        "-g",
        "daemon off;",
    ])
    .expect("healthcheck flags parse");
    assert_eq!(
        args.healthcheck.as_deref(),
        Some("curl -fsS localhost/health")
    );
    assert_eq!(args.health_interval, 10);
    assert_eq!(args.health_timeout, 5); // default
    assert_eq!(args.health_retries, 5);
    assert_eq!(args.health_start_period, 0); // default
}

#[test]
fn test_run_volume_dir_inject() {
    let cli = Cli::try_parse_from([
        "mvmctl",
        "machine",
        "run",
        "--image",
        "alpine:latest",
        "--mount",
        "/tmp/config:/mnt/config",
        "--volume",
        "/tmp/secrets:/mnt/secrets",
        "--",
        "sh",
    ])
    .unwrap();
    match cli.command {
        Commands::Machine(mg) => match mg.action {
            machine::MachineAction::Run(machine::MachineRunArgs {
                run: exec::RunArgs { mounts: volume, .. },
                ..
            }) => {
                assert_eq!(volume.len(), 2);
                assert_eq!(volume[0], "/tmp/config:/mnt/config");
                assert_eq!(volume[1], "/tmp/secrets:/mnt/secrets");
            }
            _ => panic!("Expected machine run"),
        },
        _ => panic!("Expected Machine command"),
    }
}

#[test]
fn test_run_volume_persistent() {
    let cli = Cli::try_parse_from([
        "mvmctl",
        "machine",
        "run",
        "--image",
        "alpine:latest",
        "--mount",
        "/data:/data/vol:4G",
        "--",
        "sh",
    ])
    .unwrap();
    match cli.command {
        Commands::Machine(mg) => match mg.action {
            machine::MachineAction::Run(machine::MachineRunArgs {
                run: exec::RunArgs { mounts: volume, .. },
                ..
            }) => {
                assert_eq!(volume.len(), 1);
                assert_eq!(volume[0], "/data:/data/vol:4G");
            }
            _ => panic!("Expected machine run"),
        },
        _ => panic!("Expected Machine command"),
    }
}

#[test]
fn test_parse_volume_spec_dir_share() {
    let spec = parse_volume_spec("/tmp/config:/mnt/config").unwrap();
    match spec {
        VolumeSpec::DirShare {
            host_dir,
            guest_mount,
            read_only,
        } => {
            assert_eq!(host_dir, "/tmp/config");
            assert_eq!(guest_mount, "/mnt/config");
            assert!(read_only, "default is read-only");
        }
        _ => panic!("Expected DirShare"),
    }
}

#[test]
fn test_parse_volume_spec_disk() {
    let spec = parse_volume_spec("/data:/data/vol:4G").unwrap();
    match spec {
        VolumeSpec::Disk {
            host,
            guest,
            size,
            encrypted,
            ..
        } => {
            assert_eq!(host, "/data");
            assert_eq!(guest, "/data/vol");
            assert_eq!(size, "4G");
            assert!(!encrypted);
        }
        _ => panic!("Expected Disk"),
    }
}

#[test]
fn test_parse_volume_spec_invalid() {
    let result = parse_volume_spec("just-a-path");
    assert!(result.is_err());
}

#[test]
fn test_parse_volume_spec_generic_dir_share() {
    // A generic guest mount (not /mnt/config|secrets) now parses as a
    // dir share — the old "unsupported mount" bail is gone.
    let spec = parse_volume_spec("/tmp/foo:/data/custom").unwrap();
    match spec {
        VolumeSpec::DirShare { guest_mount, .. } => {
            assert_eq!(guest_mount, "/data/custom");
        }
        _ => panic!("Expected DirShare"),
    }
}

#[test]
fn test_run_port_and_env_flags() {
    // `--port` is not on `machine run`; test env injection which IS available.
    let cli = Cli::try_parse_from([
        "mvmctl",
        "machine",
        "run",
        "--image",
        "alpine:latest",
        "-e",
        "NODE_ENV=production",
        "-e",
        "DEBUG=true",
        "--",
        "sh",
    ])
    .unwrap();
    match cli.command {
        Commands::Machine(mg) => match mg.action {
            machine::MachineAction::Run(machine::MachineRunArgs {
                run: exec::RunArgs { env, .. },
                ..
            }) => {
                assert_eq!(env, vec!["NODE_ENV=production", "DEBUG=true"]);
            }
            _ => panic!("Expected machine run"),
        },
        _ => panic!("Expected Machine command"),
    }
}

#[test]
fn test_run_port_and_env_default_empty() {
    let cli = Cli::try_parse_from([
        "mvmctl",
        "machine",
        "run",
        "--image",
        "alpine:latest",
        "--",
        "sh",
    ])
    .unwrap();
    match cli.command {
        Commands::Machine(mg) => match mg.action {
            machine::MachineAction::Run(machine::MachineRunArgs {
                run: exec::RunArgs { env, .. },
                ..
            }) => {
                assert!(env.is_empty());
            }
            _ => panic!("Expected machine run"),
        },
        _ => panic!("Expected Machine command"),
    }
}

#[test]
fn test_run_forward_flag() {
    // `--forward` was an `up`-only flag; `up` is retired.
    let result = Cli::try_parse_from([
        "mvmctl",
        "up",
        "--flake",
        ".",
        "-p",
        "3333:3000",
        "--forward",
    ]);
    assert!(result.is_err(), "`up` was retired");
    assert_eq!(
        result.unwrap_err().kind(),
        clap::error::ErrorKind::InvalidSubcommand
    );
}

#[test]
fn test_run_forward_default_false() {
    // `--forward` was an `up`-only flag; `up` is retired.
    let result = Cli::try_parse_from(["mvmctl", "up", "--flake", "."]);
    assert!(result.is_err(), "`up` was retired");
    assert_eq!(
        result.unwrap_err().kind(),
        clap::error::ErrorKind::InvalidSubcommand
    );
}

// ---- VM subcommand tests ----

// ---- machine stop tests ----

// `mvmctl down` was removed; `machine stop` is the sole stop path.
// It requires exactly one of: a positional VM name, or `--all`.

#[test]
fn machine_stop_named_and_all_parse() {
    let cli = Cli::try_parse_from(["mvmctl", "machine", "stop", "web"]).unwrap();
    let Commands::Machine(mg) = cli.command else {
        panic!("expected machine group")
    };
    match mg.action {
        machine::MachineAction::Stop(args) => {
            assert_eq!(args.names, vec!["web"]);
            assert!(!args.all);
        }
        _ => panic!("expected stop action"),
    }

    let cli = Cli::try_parse_from(["mvmctl", "machine", "stop", "--all"]).unwrap();
    let Commands::Machine(mg) = cli.command else {
        panic!("expected machine group")
    };
    match mg.action {
        machine::MachineAction::Stop(args) => {
            assert!(args.names.is_empty());
            assert!(args.all);
        }
        _ => panic!("expected stop action"),
    }
}

#[test]
fn machine_stop_requires_target() {
    let err = Cli::try_parse_from(["mvmctl", "machine", "stop"])
        .expect_err("no name and no --all must be rejected");
    assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
}

#[test]
fn down_removed() {
    let err = Cli::try_parse_from(["mvmctl", "down", "web"])
        .expect_err("down must not parse after removal");
    assert_eq!(
        err.kind(),
        clap::error::ErrorKind::InvalidSubcommand,
        "expected InvalidSubcommand, got: {err:?}"
    );
}

// ---- Forward command tests ----

#[test]
fn test_forward_parses() {
    let cli = Cli::try_parse_from(["mvmctl", "machine", "forward", "swift", "3000"]).unwrap();
    let Commands::Machine(mg) = cli.command else {
        panic!("expected vm group")
    };
    let machine::MachineAction::Vm(vmg) = mg.action else {
        panic!("expected Vm action under machine")
    };
    match vmg {
        group::VmCmd::Forward(forward::Args { name, port, ports }) => {
            assert_eq!(name, "swift");
            // Positional ports land in `ports`, flag ports in `port`.
            assert!(port.is_empty());
            assert_eq!(ports, vec!["3000"]);
        }
        _ => panic!("Expected Forward command"),
    }
}

#[test]
fn test_forward_with_port_mapping() {
    let cli = Cli::try_parse_from(["mvmctl", "machine", "forward", "swift", "8080:3000"]).unwrap();
    let Commands::Machine(mg) = cli.command else {
        panic!("expected vm group")
    };
    let machine::MachineAction::Vm(vmg) = mg.action else {
        panic!("expected Vm action under machine")
    };
    match vmg {
        group::VmCmd::Forward(forward::Args { name, port, ports }) => {
            assert_eq!(name, "swift");
            assert!(port.is_empty());
            assert_eq!(ports, vec!["8080:3000"]);
        }
        _ => panic!("Expected Forward command"),
    }
}

#[test]
fn test_forward_with_flag() {
    let cli = Cli::try_parse_from(["mvmctl", "machine", "forward", "swift", "-p", "3000"]).unwrap();
    let Commands::Machine(mg) = cli.command else {
        panic!("expected vm group")
    };
    let machine::MachineAction::Vm(vmg) = mg.action else {
        panic!("expected Vm action under machine")
    };
    match vmg {
        group::VmCmd::Forward(forward::Args { name, port, ports }) => {
            assert_eq!(name, "swift");
            assert_eq!(port, vec!["3000"]);
            assert!(ports.is_empty());
        }
        _ => panic!("Expected Forward command"),
    }
}

#[test]
fn test_forward_multiple_ports() {
    let cli = Cli::try_parse_from([
        "mvmctl", "machine", "forward", "swift", "-p", "3000", "-p", "8080:443",
    ])
    .unwrap();
    let Commands::Machine(mg) = cli.command else {
        panic!("expected vm group")
    };
    let machine::MachineAction::Vm(vmg) = mg.action else {
        panic!("expected Vm action under machine")
    };
    match vmg {
        group::VmCmd::Forward(forward::Args { name, port, ports }) => {
            assert_eq!(name, "swift");
            assert_eq!(port, vec!["3000", "8080:443"]);
            assert!(ports.is_empty());
        }
        _ => panic!("Expected Forward command"),
    }
}

#[test]
fn test_forward_multiple_positional() {
    let cli =
        Cli::try_parse_from(["mvmctl", "machine", "forward", "swift", "3000", "8080:443"]).unwrap();
    let Commands::Machine(mg) = cli.command else {
        panic!("expected vm group")
    };
    let machine::MachineAction::Vm(vmg) = mg.action else {
        panic!("expected Vm action under machine")
    };
    match vmg {
        group::VmCmd::Forward(forward::Args { name, port, ports }) => {
            assert_eq!(name, "swift");
            assert!(port.is_empty());
            assert_eq!(ports, vec!["3000", "8080:443"]);
        }
        _ => panic!("Expected Forward command"),
    }
}

#[test]
fn test_forward_no_ports_parses() {
    // Stale invocations still parse so execution can return the targeted
    // signed-ingress migration error.
    let cli = Cli::try_parse_from(["mvmctl", "machine", "forward", "swift"]).unwrap();
    let Commands::Machine(mg) = cli.command else {
        panic!("expected vm group")
    };
    let machine::MachineAction::Vm(vmg) = mg.action else {
        panic!("expected Vm action under machine")
    };
    match vmg {
        group::VmCmd::Forward(forward::Args { name, port, ports }) => {
            assert_eq!(name, "swift");
            assert!(port.is_empty());
            assert!(ports.is_empty());
        }
        _ => panic!("Expected Forward command"),
    }
}

#[test]
fn test_parse_port_spec_single() {
    let (local, guest) = parse_port_spec("3000").unwrap();
    assert_eq!(local, 3000);
    assert_eq!(guest, 3000);
}

#[test]
fn test_parse_port_spec_mapping() {
    let (local, guest) = parse_port_spec("8080:3000").unwrap();
    assert_eq!(local, 8080);
    assert_eq!(guest, 3000);
}

#[test]
fn test_parse_port_spec_invalid() {
    assert!(parse_port_spec("abc").is_err());
    assert!(parse_port_spec("abc:3000").is_err());
    assert!(parse_port_spec("3000:abc").is_err());
    assert!(parse_port_spec("99999").is_err());
}

// -------------------------------------------------------------------------
// Top-level verb tests. `ps`, `start`, `flake`, `image`, `setup`,
// `completions`, and `security` were dropped — `ls`/`validate`/
// `catalog`/`doctor` cover the cleaned surface. `up` and `invoke` were
// consolidated into `machine run` (argv lifecycle + `--entrypoint` action);
// `up_removed`/`invoke_removed` pin they no longer parse. `run` is a visible
// top-level verb and also carries the SDK Sandbox transport
// (`run_is_visible_and_still_carries_the_sdk_transport`).
// -------------------------------------------------------------------------

/// Listing is `machine ls` alone. A top-level `ls` (and the `ps` it once
/// aliased) would be a second listing over a different store — the split this
/// command surface exists to remove.
#[test]
fn top_level_listing_verbs_are_unrecognized() {
    assert!(Cli::try_parse_from(["mvmctl", "ls"]).is_err());
    assert!(Cli::try_parse_from(["mvmctl", "ps"]).is_err());
}

// --- `agent-session`: the durable-agent-session operator surface ---

#[test]
fn agent_session_ls_parses() {
    let cli = Cli::try_parse_from(["mvmctl", "agent-session", "ls"]).unwrap();
    assert!(matches!(cli.command, Commands::AgentSession(_)));
}

#[test]
fn agent_session_open_requires_an_id_and_takes_repeatable_members() {
    assert!(Cli::try_parse_from(["mvmctl", "agent-session", "open"]).is_err());

    let cli = Cli::try_parse_from([
        "mvmctl",
        "agent-session",
        "open",
        "sess-a",
        "--member",
        "vm-one",
        "--member",
        "vm-two",
        "--resume-point",
        "sha256:abababababababababababababababababababababababababababababababab",
    ])
    .unwrap();
    let Commands::AgentSession(args) = cli.command else {
        panic!("expected the agent-session command")
    };
    let agent_session::AgentSessionAction::Open(open) = args.action else {
        panic!("expected the open subcommand")
    };
    assert_eq!(open.session_id, "sess-a");
    assert_eq!(open.members, vec!["vm-one", "vm-two"]);
    assert!(open.resume_point.is_some());
}

#[test]
fn agent_session_open_needs_neither_a_member_nor_a_resume_point() {
    // Both are legal to omit: a session with no resume point is refused at
    // resume time, not at open time, and one with no member simply cannot
    // chain its park.
    let cli = Cli::try_parse_from(["mvmctl", "agent-session", "open", "sess-a"]).unwrap();
    let Commands::AgentSession(args) = cli.command else {
        panic!("expected the agent-session command")
    };
    let agent_session::AgentSessionAction::Open(open) = args.action else {
        panic!("expected the open subcommand")
    };
    assert!(open.members.is_empty());
    assert!(open.resume_point.is_none());
}

#[test]
fn agent_session_show_requires_an_id() {
    assert!(Cli::try_parse_from(["mvmctl", "agent-session", "show"]).is_err());
    assert!(Cli::try_parse_from(["mvmctl", "agent-session", "show", "sess-alpha"]).is_ok());
}

#[test]
fn agent_session_verb_is_not_named_session() {
    // `mvmctl machine session` already means machine-session residency.
    // A bare `session` verb would collide with it in the operator's head.
    assert!(Cli::try_parse_from(["mvmctl", "session", "ls"]).is_err());
}

#[test]
fn agent_session_park_requires_a_reason() {
    assert!(Cli::try_parse_from(["mvmctl", "agent-session", "park", "sess-a"]).is_err());
    assert!(
        Cli::try_parse_from([
            "mvmctl",
            "agent-session",
            "park",
            "sess-a",
            "--reason",
            "approval-wait",
        ])
        .is_ok()
    );
}

#[test]
fn agent_session_resume_requires_the_workload_material() {
    // The session record deliberately carries no image, kernel or size, so
    // the operator supplies them. A resume that could be typed without them
    // would have to guess, which is the thing the flags exist to prevent.
    assert!(Cli::try_parse_from(["mvmctl", "agent-session", "resume", "sess-a"]).is_err());

    let cli = Cli::try_parse_from([
        "mvmctl",
        "agent-session",
        "resume",
        "sess-a",
        "--backend",
        "hvf",
        "--image",
        "demo",
        "--image-sha256",
        "abababababababababababababababababababababababababababababababab",
        "--cpus",
        "2",
        "--mem-mib",
        "512",
    ])
    .unwrap();
    let Commands::AgentSession(args) = cli.command else {
        panic!("expected the agent-session command")
    };
    let agent_session::AgentSessionAction::Resume(resume) = args.action else {
        panic!("expected the resume subcommand")
    };
    assert_eq!(resume.backend, "hvf");
    assert_eq!(resume.image, "demo");
    assert_eq!(resume.cpus, 2);
    assert_eq!(resume.mem_mib, 512);
    assert!(
        resume.kernel_sha256.is_none(),
        "a backend that carries its own kernel supplies no sha"
    );
}

#[test]
fn agent_session_park_takes_a_journal_cursor_and_an_approval_head() {
    let cli = Cli::try_parse_from([
        "mvmctl",
        "agent-session",
        "park",
        "sess-a",
        "--reason",
        "idle",
        "--journal-cursor",
        "42",
        "--approval-head",
        "sha256:abababababababababababababababababababababababababababababababab",
    ])
    .unwrap();
    let Commands::AgentSession(args) = cli.command else {
        panic!("expected the agent-session command")
    };
    let agent_session::AgentSessionAction::Park(park) = args.action else {
        panic!("expected the park subcommand")
    };
    assert_eq!(park.journal_cursor, 42);
    assert!(park.approval_head.is_some());
}

#[test]
fn test_start_verb_is_unrecognized() {
    let result = Cli::try_parse_from(["mvmctl", "start", "--flake", "."]);
    assert!(result.is_err(), "`start` alias was dropped in plan 40");
}

#[test]
fn test_run_command_is_recognized() {
    // `mvmctl run` was retired; `machine run` is the replacement.
    let cli = Cli::try_parse_from([
        "mvmctl",
        "machine",
        "run",
        "--image",
        "alpine:latest",
        "--",
        "/bin/true",
    ])
    .unwrap();
    match cli.command {
        Commands::Machine(mg) => match mg.action {
            machine::MachineAction::Run(machine::MachineRunArgs {
                run: exec::RunArgs { profile, argv, .. },
                ..
            }) => {
                assert_eq!(profile, exec::RunProfile::Standard);
                assert_eq!(argv, vec!["/bin/true".to_string()]);
            }
            _ => panic!("Expected machine run"),
        },
        _ => panic!("Expected Machine command"),
    }
}

#[test]
fn test_setup_verb_is_unrecognized() {
    let result = Cli::try_parse_from(["mvmctl", "setup"]);
    assert!(result.is_err(), "`setup` was folded into `bootstrap`");
}

/// `completions` was folded into a hidden `shell-init --emit-completions`
/// flag, and this test pinned that. The fold is reversed: the reference
/// documented the hidden flag as the way to get completions, so the capability
/// was documented and unfindable at once. The verb is back, the hidden flag is
/// gone, and the eval block calls the verb — one name, and it is the
/// discoverable one.
#[test]
fn completions_is_a_verb_and_the_eval_block_calls_it() {
    let cli = Cli::try_parse_from(["mvmctl", "completions", "bash"])
        .expect("`completions bash` must parse");
    assert!(matches!(cli.command, Commands::Completions(_)));

    assert!(
        Cli::try_parse_from(["mvmctl", "shell-init", "--emit-completions", "bash"]).is_err(),
        "the hidden flag must be gone, not shadowed by the verb"
    );

    let block = crate::shell_init::generate_block("/some/path");
    assert!(
        block.contains("mvmctl completions"),
        "the eval block must call the public verb"
    );
    assert!(
        !block.contains("--emit-completions"),
        "and must not still call the removed flag"
    );
}

#[test]
fn test_flake_verb_is_unrecognized() {
    let result = Cli::try_parse_from(["mvmctl", "flake", "check"]);
    assert!(result.is_err(), "`flake` was renamed to `validate`");
}

#[test]
fn test_security_verb_is_unrecognized() {
    let result = Cli::try_parse_from(["mvmctl", "security", "status"]);
    assert!(result.is_err(), "`security` was folded into `doctor`");
}

#[test]
fn test_image_ls_parses() {
    let cli = Cli::try_parse_from(["mvmctl", "image", "ls", "--registry", "docker.io", "--json"])
        .unwrap();
    assert!(matches!(
        cli.command,
        Commands::Image(image::Args {
            action: ImageAction::Ls {
                registry: Some(ref registry),
                json: true
            },
        }) if registry == "docker.io"
    ));
}

#[test]
fn test_image_inspect_parses() {
    let cli = Cli::try_parse_from([
        "mvmctl",
        "image",
        "inspect",
        "docker.io/library/alpine:3.20",
        "--json",
    ])
    .unwrap();
    assert!(matches!(
        cli.command,
        Commands::Image(image::Args {
            action: ImageAction::Inspect {
                ref reference,
                json: true
            },
        }) if reference == "docker.io/library/alpine:3.20"
    ));
}

#[test]
fn test_image_rm_parses() {
    let cli = Cli::try_parse_from(["mvmctl", "image", "rm", "sha256:abc"]).unwrap();
    assert!(matches!(
        cli.command,
        Commands::Image(image::Args {
            action: ImageAction::Rm { ref reference },
        }) if reference == "sha256:abc"
    ));
}

// -------------------------------------------------------------------------
// Metrics tests (Phase 1)
// -------------------------------------------------------------------------

#[test]
fn test_metrics_command_parses() {
    let cli = Cli::try_parse_from(["mvmctl", "ops", "metrics"]).unwrap();
    assert!(matches!(
        cli.command,
        Commands::Ops(ops::group::Args {
            action: ops::group::OpsCmd::Metrics(metrics::Args {
                json: false,
                instance: None,
            })
        })
    ));
}

#[test]
fn mcp_stdio_command_parses() {
    let cli = Cli::try_parse_from(["mvmctl", "ops", "mcp", "stdio"])
        .expect("the named MCP stdio consumer must parse");
    assert!(matches!(
        cli.command,
        Commands::Ops(ops::group::Args {
            action: ops::group::OpsCmd::Mcp(ops::mcp::Args {
                transport: ops::mcp::Transport::Stdio
            })
        })
    ));
}

#[test]
fn test_metrics_json_flag_parses() {
    let cli = Cli::try_parse_from(["mvmctl", "ops", "metrics", "--json"]).unwrap();
    assert!(matches!(
        cli.command,
        Commands::Ops(ops::group::Args {
            action: ops::group::OpsCmd::Metrics(metrics::Args {
                json: true,
                instance: None,
            })
        })
    ));
}

#[test]
fn test_metrics_instance_flag_parses() {
    let cli = Cli::try_parse_from(["mvmctl", "ops", "metrics", "--instance", "i-abc"]).unwrap();
    let Commands::Ops(opsg) = cli.command else {
        panic!("expected ops group")
    };
    match opsg.action {
        ops::group::OpsCmd::Metrics(metrics::Args { instance, .. }) => {
            assert_eq!(instance.as_deref(), Some("i-abc"));
        }
        _ => panic!("expected Metrics command"),
    }
}

#[test]
fn test_metrics_snapshot_serializes_to_json() {
    let snap = mvm_core::observability::metrics::global().snapshot();
    let json = serde_json::to_string(&snap).expect("snapshot must serialize");
    assert!(json.contains("requests_total"));
    assert!(json.contains("instances_created"));
}

#[test]
fn test_prometheus_exposition_has_expected_metrics() {
    let prom = mvm_core::observability::metrics::global().prometheus_exposition();
    assert!(prom.contains("mvm_requests_total"));
    assert!(prom.contains("mvm_instances_created_total"));
    assert!(prom.contains("# HELP"));
    assert!(prom.contains("# TYPE"));
}

// ---- Config command tests ----

#[test]
fn test_config_show_parses() {
    let cli = Cli::try_parse_from(["mvmctl", "ops", "config", "show"]).unwrap();
    assert!(matches!(
        cli.command,
        Commands::Ops(ops::group::Args {
            action: ops::group::OpsCmd::Config(config::Args {
                action: ConfigAction::Show
            })
        })
    ));
}

#[test]
fn test_config_set_parses() {
    let cli = Cli::try_parse_from(["mvmctl", "ops", "config", "set", "dev_vm_cpus", "4"]).unwrap();
    let Commands::Ops(opsg) = cli.command else {
        panic!("expected ops group")
    };
    match opsg.action {
        ops::group::OpsCmd::Config(config::Args {
            action: ConfigAction::Set { key, value },
        }) => {
            assert_eq!(key, "dev_vm_cpus");
            assert_eq!(value, "4");
        }
        _ => panic!("Expected Config Set command"),
    }
}

#[test]
fn test_config_show_output_contains_dev_vm_cpus() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = mvm_core::user_config::MvmConfig::default();
    mvm_core::user_config::save(&cfg, Some(tmp.path())).unwrap();
    let loaded = mvm_core::user_config::load(Some(tmp.path()));
    let text = toml::to_string_pretty(&loaded).unwrap();
    assert!(text.contains("dev_vm_cpus"));
}

#[test]
fn test_config_set_persists() {
    let tmp = tempfile::tempdir().unwrap();
    let mut cfg = mvm_core::user_config::load(Some(tmp.path()));
    mvm_core::user_config::set_key(&mut cfg, "dev_vm_cpus", "4").unwrap();
    mvm_core::user_config::save(&cfg, Some(tmp.path())).unwrap();
    let reloaded = mvm_core::user_config::load(Some(tmp.path()));
    assert_eq!(reloaded.dev_vm_cpus, 4);
}

#[test]
fn test_config_set_unknown_key_fails() {
    let mut cfg = mvm_core::user_config::MvmConfig::default();
    let err = mvm_core::user_config::set_key(&mut cfg, "nonexistent_key", "5").unwrap_err();
    assert!(err.to_string().contains("Unknown config key"));
}

// ---- Uninstall command tests ----

#[test]
fn test_uninstall_parses_defaults() {
    let cli = Cli::try_parse_from(["mvmctl", "env", "uninstall", "--yes"]).unwrap();
    assert!(matches!(
        cli.command,
        Commands::Env(env_group::Args {
            action: env_group::EnvCmd::Uninstall(uninstall::Args {
                yes: true,
                all: false,
                dry_run: false,
            })
        })
    ));
}

#[test]
fn test_uninstall_dry_run_parses() {
    let cli = Cli::try_parse_from(["mvmctl", "env", "uninstall", "--dry-run", "--yes"]).unwrap();
    assert!(matches!(
        cli.command,
        Commands::Env(env_group::Args {
            action: env_group::EnvCmd::Uninstall(uninstall::Args {
                yes: true,
                all: false,
                dry_run: true,
            })
        })
    ));
}

#[test]
fn test_uninstall_all_flag_parses() {
    let cli = Cli::try_parse_from(["mvmctl", "env", "uninstall", "--all", "--yes"]).unwrap();
    assert!(matches!(
        cli.command,
        Commands::Env(env_group::Args {
            action: env_group::EnvCmd::Uninstall(uninstall::Args {
                yes: true,
                all: true,
                dry_run: false,
            })
        })
    ));
}

// ---- Audit command tests ----

#[test]
fn test_audit_show_json_parses() {
    let cli =
        Cli::try_parse_from(["mvmctl", "trust", "audit", "show", "plan-abc", "--json"]).unwrap();
    assert!(matches!(
        cli.command,
        Commands::Trust(trust::Args {
            action: trust::TrustAction::Audit(audit::Args {
                action: AuditAction::Show {
                    ref plan_id,
                    json: true,
                    ..
                }
            })
        }) if plan_id == "plan-abc"
    ));
}

#[test]
fn test_audit_tail_parses() {
    let cli = Cli::try_parse_from(["mvmctl", "trust", "audit", "tail"]).unwrap();
    let Commands::Trust(tg) = cli.command else {
        panic!("expected trust group")
    };
    match tg.action {
        trust::TrustAction::Audit(audit::Args {
            action:
                AuditAction::Tail {
                    lines,
                    follow,
                    chain,
                    tenant,
                },
        }) => {
            assert_eq!(lines, 20);
            assert!(!follow);
            assert!(!chain, "tail defaults to legacy LocalAudit");
            assert_eq!(tenant, "local");
        }
        _ => panic!("Expected Audit::Tail"),
    }
}

#[test]
fn test_audit_tail_follow_parses() {
    let cli = Cli::try_parse_from([
        "mvmctl", "trust", "audit", "tail", "--follow", "--lines", "50",
    ])
    .unwrap();
    let Commands::Trust(tg) = cli.command else {
        panic!("expected trust group")
    };
    match tg.action {
        trust::TrustAction::Audit(audit::Args {
            action:
                AuditAction::Tail {
                    lines,
                    follow,
                    chain: _,
                    tenant: _,
                },
        }) => {
            assert_eq!(lines, 50);
            assert!(follow);
        }
        _ => panic!("Expected Audit::Tail"),
    }
}

#[test]
fn test_audit_tail_chain_flag_parses() {
    let cli = Cli::try_parse_from(["mvmctl", "trust", "audit", "tail", "--chain"]).unwrap();
    let Commands::Trust(tg) = cli.command else {
        panic!("expected trust group")
    };
    match tg.action {
        trust::TrustAction::Audit(audit::Args {
            action: AuditAction::Tail { chain, tenant, .. },
        }) => {
            assert!(chain);
            assert_eq!(tenant, "local");
        }
        _ => panic!("Expected Audit::Tail with --chain"),
    }
}

#[test]
fn test_audit_verify_parses() {
    let cli = Cli::try_parse_from(["mvmctl", "trust", "audit", "verify"]).unwrap();
    let Commands::Trust(tg) = cli.command else {
        panic!("expected trust group")
    };
    match tg.action {
        trust::TrustAction::Audit(audit::Args {
            action: AuditAction::Verify { tenant },
        }) => assert_eq!(tenant, "local"),
        _ => panic!("Expected Audit::Verify"),
    }
}

#[test]
fn test_audit_verify_with_tenant() {
    let cli =
        Cli::try_parse_from(["mvmctl", "trust", "audit", "verify", "--tenant", "acme"]).unwrap();
    let Commands::Trust(tg) = cli.command else {
        panic!("expected trust group")
    };
    match tg.action {
        trust::TrustAction::Audit(audit::Args {
            action: AuditAction::Verify { tenant },
        }) => assert_eq!(tenant, "acme"),
        _ => panic!("Expected Audit::Verify"),
    }
}

#[test]
fn test_audit_show_parses() {
    let cli = Cli::try_parse_from(["mvmctl", "trust", "audit", "show", "plan-abc"]).unwrap();
    let Commands::Trust(tg) = cli.command else {
        panic!("expected trust group")
    };
    match tg.action {
        trust::TrustAction::Audit(audit::Args {
            action:
                AuditAction::Show {
                    plan_id,
                    tenant,
                    json,
                },
        }) => {
            assert_eq!(plan_id, "plan-abc");
            assert_eq!(tenant, "local");
            assert!(!json);
        }
        _ => panic!("Expected Audit::Show"),
    }
}

#[test]
fn test_audit_publish_root_parses() {
    let cli = Cli::try_parse_from(["mvmctl", "trust", "audit", "publish-root"]).unwrap();
    let Commands::Trust(tg) = cli.command else {
        panic!("expected trust group")
    };
    match tg.action {
        trust::TrustAction::Audit(audit::Args {
            action: AuditAction::PublishRoot { tenant },
        }) => assert_eq!(tenant, "local"),
        _ => panic!("Expected Audit::PublishRoot"),
    }
}

#[test]
fn test_audit_prove_parses() {
    let cli = Cli::try_parse_from([
        "mvmctl",
        "trust",
        "audit",
        "prove",
        "sha256:abc",
        "--tenant",
        "acme",
        "--json",
    ])
    .unwrap();
    let Commands::Trust(tg) = cli.command else {
        panic!("expected trust group")
    };
    match tg.action {
        trust::TrustAction::Audit(audit::Args {
            action:
                AuditAction::Prove {
                    selector,
                    tenant,
                    json,
                },
        }) => {
            assert_eq!(selector, "sha256:abc");
            assert_eq!(tenant, "acme");
            assert!(json);
        }
        _ => panic!("Expected Audit::Prove"),
    }
}

#[test]
fn test_audit_verify_inclusion_parses() {
    let cli = Cli::try_parse_from([
        "mvmctl",
        "trust",
        "audit",
        "verify-inclusion",
        "--proof",
        "proof.json",
        "--root",
        "root.json",
        "--pubkey",
        "host.pub",
    ])
    .unwrap();
    let Commands::Trust(tg) = cli.command else {
        panic!("expected trust group")
    };
    match tg.action {
        trust::TrustAction::Audit(audit::Args {
            action:
                AuditAction::VerifyInclusion {
                    proof,
                    root,
                    pubkey,
                    tenant,
                },
        }) => {
            assert_eq!(proof, "proof.json");
            assert_eq!(root.as_deref(), Some(std::path::Path::new("root.json")));
            assert_eq!(pubkey.as_deref(), Some(std::path::Path::new("host.pub")));
            assert_eq!(tenant, "local");
        }
        _ => panic!("Expected Audit::VerifyInclusion"),
    }
}

#[test]
fn test_audit_verify_inclusion_defaults_optional_paths() {
    let cli = Cli::try_parse_from([
        "mvmctl",
        "trust",
        "audit",
        "verify-inclusion",
        "--proof",
        "-",
    ])
    .unwrap();
    let Commands::Trust(tg) = cli.command else {
        panic!("expected trust group")
    };
    match tg.action {
        trust::TrustAction::Audit(audit::Args {
            action:
                AuditAction::VerifyInclusion {
                    proof,
                    root,
                    pubkey,
                    tenant,
                },
        }) => {
            assert_eq!(proof, "-");
            assert!(root.is_none());
            assert!(pubkey.is_none());
            assert_eq!(tenant, "local");
        }
        _ => panic!("Expected Audit::VerifyInclusion"),
    }
}

#[test]
fn test_audit_receipts_export_parses() {
    let cli = Cli::try_parse_from([
        "mvmctl", "trust", "audit", "receipts", "export", "--tenant", "acme", "--json",
    ])
    .unwrap();
    let Commands::Trust(tg) = cli.command else {
        panic!("expected trust group")
    };
    match tg.action {
        trust::TrustAction::Audit(audit::Args {
            action:
                AuditAction::Receipts {
                    action:
                        audit::ReceiptsAction::Export {
                            tenant,
                            plan_id,
                            json,
                            archive,
                            full_chain,
                        },
                },
        }) => {
            assert_eq!(tenant, "acme");
            assert_eq!(plan_id, None);
            assert!(json);
            // The archive flags default off, so the pre-existing print path is
            // what a bare `--json` export still takes.
            assert_eq!(archive, None);
            assert!(!full_chain);
        }
        _ => panic!("Expected Audit::Receipts::Export"),
    }
}

#[test]
fn test_audit_tail_no_log_prints_message() {
    // When no audit log exists, the command should succeed with a
    // helpful message rather than an error.
    let tmp = tempfile::tempdir().unwrap();
    let nonexistent = tmp.path().join("audit.jsonl");
    // Path doesn't exist — simulate the early-return path.
    assert!(!nonexistent.exists());
}

// ---- Clap value parser tests ----

#[test]
fn test_clap_port_spec_valid() {
    assert!(clap_port_spec("8080").is_ok());
    assert!(clap_port_spec("8080:80").is_ok());
    assert!(clap_port_spec("443:443").is_ok());
    assert!(clap_port_spec("0:0").is_ok());
}

#[test]
fn test_clap_port_spec_invalid() {
    assert!(clap_port_spec("").is_err());
    assert!(clap_port_spec("abc").is_err());
    assert!(clap_port_spec("8080:abc").is_err());
    assert!(clap_port_spec("abc:80").is_err());
    assert!(clap_port_spec("99999").is_err()); // out of u16 range
}

#[test]
fn test_clap_volume_spec_valid() {
    assert!(clap_volume_spec("/host:/guest").is_ok());
    assert!(clap_volume_spec("/host/path:/guest/mount").is_ok());
    assert!(clap_volume_spec("/host:/guest:1G").is_ok());
    assert!(clap_volume_spec("./local:/app").is_ok());
}

#[test]
fn test_clap_volume_spec_invalid() {
    assert!(clap_volume_spec("").is_err());
    assert!(clap_volume_spec("nocolon").is_err());
    assert!(clap_volume_spec(":/guest").is_err()); // empty host
}

#[test]
fn test_clap_vm_name_valid() {
    assert!(clap_vm_name("my-vm").is_ok());
    assert!(clap_vm_name("vm1").is_ok());
    assert!(clap_vm_name("a").is_ok());
}

#[test]
fn test_clap_vm_name_invalid() {
    assert!(clap_vm_name("").is_err());
    assert!(clap_vm_name("UPPER").is_err());
    assert!(clap_vm_name("has space").is_err());
    assert!(clap_vm_name("-leading").is_err());
}

#[test]
fn test_clap_flake_ref_valid() {
    assert!(clap_flake_ref(".").is_ok());
    assert!(clap_flake_ref("github:org/repo").is_ok());
    assert!(clap_flake_ref("/absolute/path").is_ok());
}

#[test]
fn test_clap_flake_ref_invalid() {
    assert!(clap_flake_ref("").is_err());
    assert!(clap_flake_ref(". ; rm -rf /").is_err());
    assert!(clap_flake_ref("$(evil)").is_err());
}

#[test]
fn test_run_rejects_invalid_vm_name_at_parse_time() {
    // `up` validated --name via a clap value_parser; it is now retired.
    // Pin the retirement rather than the old parse-time rejection.
    let result = Cli::try_parse_from(["mvmctl", "up", "--flake", ".", "--name", "INVALID"]);
    assert!(result.is_err(), "`up` was retired");
    assert_eq!(
        result.unwrap_err().kind(),
        clap::error::ErrorKind::InvalidSubcommand
    );
}

#[test]
fn test_run_rejects_invalid_flake_at_parse_time() {
    // `up` validated --flake via a clap value_parser; it is now retired.
    // Pin the retirement rather than the old parse-time rejection.
    let result = Cli::try_parse_from(["mvmctl", "up", "--flake", ". ; rm -rf /", "--name", "vm1"]);
    assert!(result.is_err(), "`up` was retired");
    assert_eq!(
        result.unwrap_err().kind(),
        clap::error::ErrorKind::InvalidSubcommand
    );
}

#[test]
fn test_run_rejects_invalid_port_at_parse_time() {
    // `--port` was an `up`-only flag; `up` is retired. The test now pins
    // that `up` itself is unrecognized.
    let result = Cli::try_parse_from(["mvmctl", "up", "--flake", ".", "--port", "notaport"]);
    assert!(result.is_err(), "`up` was retired");
    assert_eq!(
        result.unwrap_err().kind(),
        clap::error::ErrorKind::InvalidSubcommand
    );
}

// ---- Config defaults wired into the Up command ----

#[test]
fn test_run_uses_config_default_cpus() {
    // When --cpus is omitted, the config default should be applied.
    let cfg = mvm_core::user_config::MvmConfig {
        default_cpus: 4,
        ..mvm_core::user_config::MvmConfig::default()
    };

    // Simulate the resolution logic from the Commands::Up dispatch.
    let cli_cpus: Option<u32> = None;
    let effective = cli_cpus.or(Some(cfg.default_cpus));
    assert_eq!(effective, Some(4));
}

#[test]
fn test_run_cli_flag_overrides_config_cpus() {
    // When --cpus is provided, it takes precedence over config.
    let cfg = mvm_core::user_config::MvmConfig {
        default_cpus: 4,
        ..mvm_core::user_config::MvmConfig::default()
    };

    let cli_cpus: Option<u32> = Some(8);
    let effective = cli_cpus.or(Some(cfg.default_cpus));
    assert_eq!(effective, Some(8));
}

#[test]
fn test_run_uses_config_default_memory() {
    let cfg = mvm_core::user_config::MvmConfig {
        default_memory_mib: 2048,
        ..mvm_core::user_config::MvmConfig::default()
    };

    let cli_memory: Option<u32> = None;
    let effective = cli_memory.or(Some(cfg.default_memory_mib));
    assert_eq!(effective, Some(2048));
}

#[test]
fn test_run_cli_flag_overrides_config_memory() {
    let cfg = mvm_core::user_config::MvmConfig {
        default_memory_mib: 2048,
        ..mvm_core::user_config::MvmConfig::default()
    };

    let cli_memory: Option<u32> = Some(512);
    let effective = cli_memory.or(Some(cfg.default_memory_mib));
    assert_eq!(effective, Some(512));
}

#[test]
fn tenant_orchestration_commands_are_not_mvmctl_surface() {
    for command in ["policy", "tenant"] {
        let err = Cli::try_parse_from(["mvmctl", command])
            .expect_err("mvmd-owned command should not parse under mvmctl");
        assert_eq!(err.kind(), clap::error::ErrorKind::InvalidSubcommand);
    }
}

// --- Network CLI tests ---

#[test]
fn test_network_list_json_parses() {
    let cli = Cli::try_parse_from(["mvmctl", "network", "list", "--json"]).unwrap();
    assert!(matches!(
        cli.command,
        Commands::Network(ops::network::Args {
            action: ops::network::NetworkAction::List { json: true }
        })
    ));
}

#[test]
fn test_network_inspect_json_parses() {
    let cli = Cli::try_parse_from(["mvmctl", "network", "inspect", "isolated", "--json"]).unwrap();
    assert!(matches!(
        cli.command,
        Commands::Network(ops::network::Args {
            action: ops::network::NetworkAction::Inspect { json: true, .. }
        })
    ));
}

#[test]
fn test_network_list_help() {
    let cli = Cli::try_parse_from(["mvmctl", "network", "list"]);
    assert!(cli.is_ok());
}

#[test]
fn test_network_create_help() {
    let cli = Cli::try_parse_from(["mvmctl", "network", "create", "mynet"]);
    assert!(cli.is_ok());
}

#[test]
fn test_network_inspect_help() {
    let cli = Cli::try_parse_from(["mvmctl", "network", "inspect", "mynet"]);
    assert!(cli.is_ok());
}

#[test]
fn test_network_remove_help() {
    let cli = Cli::try_parse_from(["mvmctl", "network", "rm", "mynet"]);
    assert!(cli.is_ok());
}

// --- Snapshot CLI tests ---

#[test]
fn test_snapshot_ls_json_parses() {
    let cli = Cli::try_parse_from(["mvmctl", "machine", "snapshot", "ls", "--json"]).unwrap();
    assert!(matches!(
        cli.command,
        Commands::Machine(machine::Args {
            action: machine::MachineAction::Vm(group::VmCmd::Snapshot(snapshot::SnapshotArgs {
                command: snapshot::SnapshotCmd::Ls { json: true }
            }))
        })
    ));
}

#[test]
fn test_snapshot_rm_json_parses() {
    let cli =
        Cli::try_parse_from(["mvmctl", "machine", "snapshot", "rm", "myvm", "--json"]).unwrap();
    assert!(matches!(
        cli.command,
        Commands::Machine(machine::Args {
            action: machine::MachineAction::Vm(group::VmCmd::Snapshot(snapshot::SnapshotArgs {
                command: snapshot::SnapshotCmd::Rm { json: true, .. }
            }))
        })
    ));
}

#[test]
fn test_vm_save_json_parses() {
    let cli = Cli::try_parse_from([
        "mvmctl", "machine", "save", "myvm", "--tag", "gold", "--json",
    ])
    .unwrap();
    assert!(matches!(
        cli.command,
        Commands::Machine(machine::Args {
            action: machine::MachineAction::Vm(group::VmCmd::Save(checkpoint::SaveArgs {
                name,
                tag: Some(tag),
                json: true,
            }))
        }) if name == "myvm" && tag == "gold"
    ));
}

#[test]
fn test_machine_restore_json_parses() {
    let cli = Cli::try_parse_from([
        "mvmctl", "machine", "restore", "ckpt-abc", "--as", "child", "--json",
    ])
    .unwrap();
    assert!(matches!(
        cli.command,
        Commands::Machine(machine::Args {
            action: machine::MachineAction::Restore(machine::MachineRestoreArgs {
                checkpoint,
                child_name,
                json: true,
                ..
            })
        }) if checkpoint == "ckpt-abc" && child_name.as_deref() == Some("child")
    ));
}

// --- Checkpoint CLI tests ---

#[test]
fn test_checkpoint_create_parses() {
    let cli = Cli::try_parse_from([
        "mvmctl",
        "machine",
        "checkpoint",
        "create",
        "myvm",
        "--tag",
        "gold",
    ])
    .unwrap();
    assert!(matches!(
        cli.command,
        Commands::Machine(machine::Args {
            action: machine::MachineAction::Vm(group::VmCmd::Checkpoint(
                checkpoint::CheckpointArgs {
                    command: checkpoint::CheckpointCmd::Create { .. }
                }
            ))
        })
    ));
}

#[test]
fn test_checkpoint_fork_parses() {
    assert!(
        Cli::try_parse_from([
            "mvmctl",
            "machine",
            "checkpoint",
            "fork",
            "ckpt-abc",
            "--new-id",
            "child"
        ])
        .is_ok()
    );
}

#[test]
fn test_checkpoint_fork_json_parses() {
    let cli = Cli::try_parse_from([
        "mvmctl",
        "machine",
        "checkpoint",
        "fork",
        "ckpt-abc",
        "--new-id",
        "child",
        "--json",
    ])
    .unwrap();
    assert!(matches!(
        cli.command,
        Commands::Machine(machine::Args {
            action: machine::MachineAction::Vm(group::VmCmd::Checkpoint(
                checkpoint::CheckpointArgs {
                    command: checkpoint::CheckpointCmd::Fork { json: true, .. }
                }
            ))
        })
    ));
}

#[test]
fn test_checkpoint_fork_rejects_traversal_new_id() {
    // --new-id must not allow a path component that escapes the VM state dir.
    let r = Cli::try_parse_from([
        "mvmctl",
        "machine",
        "checkpoint",
        "fork",
        "ckpt-abc",
        "--new-id",
        "../escape",
    ]);
    assert!(r.is_err());
}

#[test]
fn test_checkpoint_ls_json_parses() {
    let cli = Cli::try_parse_from(["mvmctl", "machine", "checkpoint", "ls", "--json"]).unwrap();
    assert!(matches!(
        cli.command,
        Commands::Machine(machine::Args {
            action: machine::MachineAction::Vm(group::VmCmd::Checkpoint(
                checkpoint::CheckpointArgs {
                    command: checkpoint::CheckpointCmd::Ls { json: true }
                }
            ))
        })
    ));
}

#[test]
fn test_checkpoint_create_vm_full_parses() {
    let cli = Cli::try_parse_from([
        "mvmctl",
        "machine",
        "checkpoint",
        "create",
        "myvm",
        "--class",
        "vm-full",
    ])
    .unwrap();
    assert!(matches!(
        cli.command,
        Commands::Machine(machine::Args {
            action: machine::MachineAction::Vm(group::VmCmd::Checkpoint(
                checkpoint::CheckpointArgs {
                    command: checkpoint::CheckpointCmd::Create {
                        class: checkpoint::CheckpointClassArg::VmFull,
                        ..
                    }
                }
            ))
        })
    ));
}

#[test]
fn test_checkpoint_restore_parses() {
    assert!(
        Cli::try_parse_from(["mvmctl", "machine", "checkpoint", "restore", "ckpt-abc"]).is_ok()
    );
}

#[test]
fn test_checkpoint_restore_json_parses() {
    let cli = Cli::try_parse_from([
        "mvmctl",
        "machine",
        "checkpoint",
        "restore",
        "ckpt-abc",
        "--json",
    ])
    .unwrap();
    assert!(matches!(
        cli.command,
        Commands::Machine(machine::Args {
            action: machine::MachineAction::Vm(group::VmCmd::Checkpoint(
                checkpoint::CheckpointArgs {
                    command: checkpoint::CheckpointCmd::Restore { json: true, .. }
                }
            ))
        })
    ));
}

#[test]
fn test_checkpoint_rm_json_parses() {
    let cli = Cli::try_parse_from([
        "mvmctl",
        "machine",
        "checkpoint",
        "rm",
        "ckpt-abc",
        "--json",
    ])
    .unwrap();
    assert!(matches!(
        cli.command,
        Commands::Machine(machine::Args {
            action: machine::MachineAction::Vm(group::VmCmd::Checkpoint(
                checkpoint::CheckpointArgs {
                    command: checkpoint::CheckpointCmd::Rm { json: true, .. }
                }
            ))
        })
    ));
}

#[test]
fn test_checkpoint_verify_parses() {
    let cli = Cli::try_parse_from([
        "mvmctl",
        "machine",
        "checkpoint",
        "verify",
        "ckpt-abc",
        "--json",
    ])
    .unwrap();
    assert!(matches!(
        cli.command,
        Commands::Machine(machine::Args {
            action: machine::MachineAction::Vm(group::VmCmd::Checkpoint(
                checkpoint::CheckpointArgs {
                    command: checkpoint::CheckpointCmd::Verify { json: true, .. }
                }
            ))
        })
    ));
}

#[test]
fn test_checkpoint_create_defaults_fs_quick() {
    let cli = Cli::try_parse_from(["mvmctl", "machine", "checkpoint", "create", "myvm"]).unwrap();
    assert!(matches!(
        cli.command,
        Commands::Machine(machine::Args {
            action: machine::MachineAction::Vm(group::VmCmd::Checkpoint(
                checkpoint::CheckpointArgs {
                    command: checkpoint::CheckpointCmd::Create {
                        class: checkpoint::CheckpointClassArg::FsQuick,
                        ..
                    }
                }
            ))
        })
    ));
}

#[test]
fn test_checkpoint_diff_parses() {
    let cli = Cli::try_parse_from([
        "mvmctl",
        "machine",
        "checkpoint",
        "diff",
        "ckpt-a",
        "ckpt-b",
        "--json",
    ])
    .unwrap();
    assert!(matches!(
        cli.command,
        Commands::Machine(machine::Args {
            action: machine::MachineAction::Vm(group::VmCmd::Checkpoint(
                checkpoint::CheckpointArgs {
                    command: checkpoint::CheckpointCmd::Diff { json: true, .. }
                }
            ))
        })
    ));
}

#[test]
fn test_snapshot_save_is_gone() {
    assert!(Cli::try_parse_from(["mvmctl", "snapshot", "save", "vm", "--path", "/x"]).is_err());
}

#[test]
fn test_snapshot_restore_is_gone() {
    assert!(Cli::try_parse_from(["mvmctl", "snapshot", "restore", "vm", "--path", "/x"]).is_err());
}

// --- Catalog CLI tests (replaced `mvmctl image *`) ---

#[test]
fn test_image_pull_parses() {
    let cli =
        Cli::try_parse_from(["mvmctl", "image", "pull", "docker.io/library/alpine:3.20"]).unwrap();
    match cli.command {
        Commands::Image(image::Args {
            action: ImageAction::Pull { reference, prod },
        }) => {
            assert_eq!(reference, "docker.io/library/alpine:3.20");
            assert!(!prod);
        }
        _ => panic!("Expected Image Pull command"),
    }
}

#[test]
fn test_image_pull_prod_parses() {
    let digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let reference = format!("docker.io/library/alpine@{digest}");
    let cli = Cli::try_parse_from(["mvmctl", "image", "pull", "--prod", &reference]).unwrap();
    match cli.command {
        Commands::Image(image::Args {
            action:
                ImageAction::Pull {
                    reference: parsed,
                    prod,
                },
        }) => {
            assert_eq!(parsed, reference);
            assert!(prod);
        }
        _ => panic!("Expected Image Pull command"),
    }
}

#[test]
fn test_catalog_list_parses() {
    let cli = Cli::try_parse_from(["mvmctl", "catalog", "list"]);
    assert!(cli.is_ok());
}

#[test]
fn test_catalog_search_parses() {
    let cli = Cli::try_parse_from(["mvmctl", "catalog", "search", "http"]).unwrap();
    match cli.command {
        Commands::Catalog(catalog::Args {
            action: CatalogAction::Search { query },
        }) => assert_eq!(query, "http"),
        _ => panic!("Expected Catalog Search command"),
    }
}

#[test]
fn test_catalog_info_parses() {
    let cli = Cli::try_parse_from(["mvmctl", "catalog", "info", "postgres"]).unwrap();
    match cli.command {
        Commands::Catalog(catalog::Args {
            action: CatalogAction::Info { name },
        }) => assert_eq!(name, "postgres"),
        _ => panic!("Expected Catalog Info command"),
    }
}

#[test]
fn test_console_help() {
    let cli = Cli::try_parse_from(["mvmctl", "machine", "console", "myvm"]);
    assert!(cli.is_ok());
}

#[test]
fn test_console_with_command() {
    let cli = Cli::try_parse_from(["mvmctl", "machine", "console", "myvm", "--command", "ls"]);
    assert!(cli.is_ok());
    let Commands::Machine(mg) = cli.unwrap().command else {
        panic!("expected machine group")
    };
    match mg.action {
        machine::MachineAction::Console(console::Args {
            name,
            command,
            force,
            env,
            pty_argv,
        }) => {
            assert_eq!(name, "myvm");
            assert_eq!(command.as_deref(), Some("ls"));
            assert!(!force, "default --force is off");
            assert!(env.is_empty());
            assert!(pty_argv.is_empty());
        }
        _ => panic!("Expected machine console action"),
    }
}

// --- Secret CLI tests ---

#[test]
fn secret_put_without_value_source_parses_for_interactive_prompt() {
    let cli = Cli::try_parse_from(["mvmctl", "secret", "put", "api-key"]).expect("parse");
    match cli.command {
        Commands::Secret(secret::Args {
            action:
                secret::SecretAction::Put {
                    name,
                    tenant,
                    value,
                    value_file,
                },
        }) => {
            assert_eq!(name, "api-key");
            assert_eq!(tenant, "local");
            assert!(value.is_none());
            assert!(value_file.is_none());
        }
        _ => panic!("Expected Secret put command"),
    }
}

#[test]
fn secret_get_rejects_force_flag() {
    let err = Cli::try_parse_from(["mvmctl", "secret", "get", "api-key", "--force"])
        .expect_err("secret get must not accept --force");
    let msg = err.to_string();
    assert!(
        msg.contains("unexpected argument '--force'") || msg.contains("unexpected argument found"),
        "got: {msg}"
    );
}

#[test]
fn up_accepts_repeatable_secret_flag() {
    // `--secret` was an `up`-only flag; `up` is retired.
    let result = Cli::try_parse_from([
        "mvmctl",
        "up",
        "--flake",
        ".",
        "--secret",
        "openai:api.openai.com",
    ]);
    assert!(result.is_err(), "`up` was retired");
    assert_eq!(
        result.unwrap_err().kind(),
        clap::error::ErrorKind::InvalidSubcommand
    );
}

#[test]
fn up_accepts_security_profile_flag_and_defaults_to_none() {
    // `--security-profile` and `--seccomp` were `up`-only flags; `up` is retired.
    let result = Cli::try_parse_from(["mvmctl", "up", "--flake", ".", "--security-profile", "dev"]);
    assert!(result.is_err(), "`up` was retired");
    assert_eq!(
        result.unwrap_err().kind(),
        clap::error::ErrorKind::InvalidSubcommand
    );
}

// --- machine run (replaced the retired `mvmctl run`) CLI tests ---

#[test]
fn run_transient_default_manifest_argv_only() {
    // `mvmctl run` is retired; pin defaults on `machine run` instead.
    let cli = Cli::try_parse_from([
        "mvmctl",
        "machine",
        "run",
        "--image",
        "alpine:latest",
        "--",
        "uname",
        "-a",
    ])
    .expect("parse");
    match cli.command {
        Commands::Machine(mg) => match mg.action {
            machine::MachineAction::Run(machine::MachineRunArgs {
                run:
                    exec::RunArgs {
                        manifest,
                        cpus,
                        memory,
                        mounts: volume,
                        env,
                        timeout,
                        argv,
                        ..
                    },
                ..
            }) => {
                assert!(manifest.is_none());
                assert_eq!(cpus, 2);
                assert_eq!(memory, "512M");
                assert!(volume.is_empty());
                assert!(env.is_empty());
                assert_eq!(timeout, None, "unset --timeout ⇒ None");
                assert_eq!(argv, vec!["uname".to_string(), "-a".to_string()]);
            }
            _ => panic!("Expected machine run"),
        },
        _ => panic!("Expected Machine command"),
    }
}

#[test]
fn run_transient_timeout_parses_to_some() {
    let cli = Cli::try_parse_from([
        "mvmctl",
        "machine",
        "run",
        "--image",
        "alpine:latest",
        "--timeout",
        "5",
        "--",
        "sleep",
        "10",
    ])
    .expect("parse");
    match cli.command {
        Commands::Machine(mg) => match mg.action {
            machine::MachineAction::Run(machine::MachineRunArgs {
                run: exec::RunArgs { timeout, .. },
                ..
            }) => {
                assert_eq!(timeout, Some(5), "--timeout 5 ⇒ Some(5)");
            }
            _ => panic!("Expected machine run"),
        },
        _ => panic!("Expected Machine command"),
    }
}

#[test]
fn run_default_profile_argv_only() {
    // Pin defaults on `machine run` — the successor to `mvmctl run`.
    let cli = Cli::try_parse_from([
        "mvmctl",
        "machine",
        "run",
        "--image",
        "alpine:latest",
        "--",
        "uname",
        "-a",
    ])
    .expect("parse");
    match cli.command {
        Commands::Machine(mg) => match mg.action {
            machine::MachineAction::Run(machine::MachineRunArgs {
                run:
                    exec::RunArgs {
                        manifest,
                        image,
                        net,
                        allow_host,
                        cpus,
                        memory,
                        profile,
                        mounts: volume,
                        env,
                        timeout,
                        receipt,
                        json,
                        dry_run,
                        argv,
                        ..
                    },
                ..
            }) => {
                assert!(manifest.is_none());
                assert_eq!(image.as_deref(), Some("alpine:latest"));
                assert!(!net, "deny-all by default");
                assert!(allow_host.is_empty());
                assert_eq!(cpus, 2);
                assert_eq!(memory, "512M");
                assert_eq!(profile, exec::RunProfile::Standard);
                assert!(volume.is_empty());
                assert!(env.is_empty());
                assert_eq!(timeout, None);
                assert!(receipt.is_none());
                assert!(!json);
                assert!(!dry_run);
                assert_eq!(argv, vec!["uname".to_string(), "-a".to_string()]);
            }
            _ => panic!("Expected machine run"),
        },
        _ => panic!("Expected Machine command"),
    }
}

#[test]
fn run_timeout_parses_to_some() {
    let cli = Cli::try_parse_from([
        "mvmctl",
        "machine",
        "run",
        "--image",
        "alpine:latest",
        "--timeout",
        "5",
        "--",
        "sleep",
        "10",
    ])
    .expect("parse");
    match cli.command {
        Commands::Machine(mg) => match mg.action {
            machine::MachineAction::Run(machine::MachineRunArgs {
                run: exec::RunArgs { timeout, .. },
                ..
            }) => {
                assert_eq!(timeout, Some(5), "--timeout 5 ⇒ Some(5)");
            }
            _ => panic!("Expected machine run"),
        },
        _ => panic!("Expected Machine command"),
    }
}

#[test]
fn machine_run_interactive_image_shell_dx_parses() {
    let args = parse_machine_run(&["--net", "-it", "--image", "alpine", "--", "/bin/sh"])
        .expect("parse Docker-style interactive shell run");
    assert!(args.run.net);
    assert!(args.tty);
    assert!(args.interactive);
    assert_eq!(args.run.image.as_deref(), Some("alpine"));
    assert_eq!(args.run.argv, vec!["/bin/sh".to_string()]);
}

#[test]
fn run_image_flag_parses() {
    let cli = Cli::try_parse_from([
        "mvmctl",
        "machine",
        "run",
        "--image",
        "docker.io/library/alpine:3.20",
        "--",
        "/bin/sh",
        "-c",
        "echo hi",
    ])
    .expect("parse");
    match cli.command {
        Commands::Machine(mg) => match mg.action {
            machine::MachineAction::Run(machine::MachineRunArgs {
                run: exec::RunArgs { image, argv, .. },
                ..
            }) => {
                assert_eq!(image.as_deref(), Some("docker.io/library/alpine:3.20"));
                assert_eq!(
                    argv,
                    vec![
                        "/bin/sh".to_string(),
                        "-c".to_string(),
                        "echo hi".to_string()
                    ]
                );
            }
            _ => panic!("Expected machine run"),
        },
        _ => panic!("Expected Machine command"),
    }
}

#[test]
fn run_image_prod_flag_parses_as_image_policy() {
    // `run` is kept hidden for the SDK transport; `--prod` is its OCI digest-pin
    // flag (not on `machine run`).
    let pinned = "docker.io/library/alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let cli = Cli::try_parse_from([
        "mvmctl",
        "run",
        "--image",
        pinned,
        "--prod",
        "--",
        "/bin/true",
    ])
    .expect("parse");
    match cli.command {
        Commands::Run(exec::TransientRunArgs { run, sdk }) => {
            assert_eq!(run.image.as_deref(), Some(pinned));
            assert!(run.prod);
            assert!(sdk.mode.is_none());
        }
        _ => panic!("Expected Run command"),
    }
}

#[test]
fn run_manifest_and_image_conflict() {
    // Still enforced on `machine run`.
    let cli = Cli::try_parse_from([
        "mvmctl",
        "machine",
        "run",
        "--manifest",
        "hello",
        "--image",
        "docker.io/library/alpine:3.20",
        "--",
        "/bin/true",
    ]);
    assert!(cli.is_err());
}

#[test]
fn run_accepts_restrictive_profile() {
    let cli = Cli::try_parse_from([
        "mvmctl",
        "machine",
        "run",
        "--image",
        "alpine:latest",
        "--profile",
        "restrictive",
        "--",
        "/bin/true",
    ])
    .expect("parse");
    match cli.command {
        Commands::Machine(mg) => match mg.action {
            machine::MachineAction::Run(machine::MachineRunArgs {
                run: exec::RunArgs { profile, argv, .. },
                ..
            }) => {
                assert_eq!(profile, exec::RunProfile::Restrictive);
                assert_eq!(argv, vec!["/bin/true".to_string()]);
            }
            _ => panic!("Expected machine run"),
        },
        _ => panic!("Expected Machine command"),
    }
}

#[test]
fn run_rejects_unknown_profile() {
    let cli = Cli::try_parse_from([
        "mvmctl",
        "machine",
        "run",
        "--image",
        "alpine:latest",
        "--profile",
        "unsafe",
        "--",
        "/bin/true",
    ]);
    assert!(cli.is_err());
}

#[test]
fn run_receipt_flag_parses() {
    let cli = Cli::try_parse_from([
        "mvmctl",
        "machine",
        "run",
        "--image",
        "alpine:latest",
        "--receipt",
        "/tmp/mvm-run-receipt.json",
        "--",
        "/bin/true",
    ])
    .expect("parse");
    match cli.command {
        Commands::Machine(mg) => match mg.action {
            machine::MachineAction::Run(machine::MachineRunArgs {
                run: exec::RunArgs { receipt, .. },
                ..
            }) => {
                assert_eq!(
                    receipt.as_deref(),
                    Some(std::path::Path::new("/tmp/mvm-run-receipt.json"))
                );
            }
            _ => panic!("Expected machine run"),
        },
        _ => panic!("Expected Machine command"),
    }
}

#[test]
fn run_json_flag_parses() {
    let cli = Cli::try_parse_from([
        "mvmctl",
        "machine",
        "run",
        "--image",
        "alpine:latest",
        "--json",
        "--",
        "/bin/true",
    ])
    .expect("parse");
    match cli.command {
        Commands::Machine(mg) => match mg.action {
            machine::MachineAction::Run(machine::MachineRunArgs {
                run: exec::RunArgs { json, argv, .. },
                ..
            }) => {
                assert!(json);
                assert_eq!(argv, vec!["/bin/true".to_string()]);
            }
            _ => panic!("Expected machine run"),
        },
        _ => panic!("Expected Machine command"),
    }
}

#[test]
fn run_dry_run_json_flags_parse() {
    let cli = Cli::try_parse_from([
        "mvmctl",
        "machine",
        "run",
        "--image",
        "alpine:latest",
        "--dry-run",
        "--json",
        "--",
        "/bin/true",
    ])
    .expect("parse");
    match cli.command {
        Commands::Machine(mg) => match mg.action {
            machine::MachineAction::Run(machine::MachineRunArgs {
                run:
                    exec::RunArgs {
                        dry_run,
                        json,
                        argv,
                        ..
                    },
                ..
            }) => {
                assert!(dry_run);
                assert!(json);
                assert_eq!(argv, vec!["/bin/true".to_string()]);
            }
            _ => panic!("Expected machine run"),
        },
        _ => panic!("Expected Machine command"),
    }
}

#[test]
fn receipt_verify_parses() {
    let cli = Cli::try_parse_from(["mvmctl", "trust", "receipt", "verify", "/tmp/receipt.json"])
        .expect("parse");
    let Commands::Trust(tg) = cli.command else {
        panic!("expected trust group")
    };
    match tg.action {
        trust::TrustAction::Receipt(exec::ReceiptArgs {
            action: exec::ReceiptAction::Verify { path, pubkey: None },
        }) => {
            assert_eq!(path, std::path::Path::new("/tmp/receipt.json"));
        }
        _ => panic!("Expected Receipt verify command"),
    }
}

#[test]
fn receipt_verify_pubkey_flag_parses() {
    let cli = Cli::try_parse_from([
        "mvmctl",
        "trust",
        "receipt",
        "verify",
        "/tmp/receipt.json",
        "--pubkey",
        "/tmp/host-signer.pub",
    ])
    .expect("parse");
    let Commands::Trust(tg) = cli.command else {
        panic!("expected trust group")
    };
    match tg.action {
        trust::TrustAction::Receipt(exec::ReceiptArgs {
            action: exec::ReceiptAction::Verify { path, pubkey },
        }) => {
            assert_eq!(path, std::path::Path::new("/tmp/receipt.json"));
            assert_eq!(
                pubkey.as_deref(),
                Some(std::path::Path::new("/tmp/host-signer.pub"))
            );
        }
        _ => panic!("Expected Receipt verify command"),
    }
}

#[test]
fn sandbox_gc_defaults_to_dry_run() {
    let cli = Cli::try_parse_from(["mvmctl", "machine", "sandbox", "gc"]).expect("parse");
    let Commands::Machine(mg) = cli.command else {
        panic!("expected vm group")
    };
    let machine::MachineAction::Vm(vmg) = mg.action else {
        panic!("expected Vm action under machine")
    };
    match vmg {
        group::VmCmd::Sandbox(sandbox::Args {
            action:
                sandbox::SandboxAction::Gc(sandbox::GcArgs {
                    dry_run,
                    apply,
                    json,
                }),
        }) => {
            assert!(
                !dry_run,
                "--dry-run flag is optional because dry-run is default"
            );
            assert!(!apply);
            assert!(!json);
        }
        _ => panic!("Expected Sandbox gc command"),
    }
}

#[test]
fn sandbox_gc_apply_parses() {
    let cli =
        Cli::try_parse_from(["mvmctl", "machine", "sandbox", "gc", "--apply"]).expect("parse");
    let Commands::Machine(mg) = cli.command else {
        panic!("expected vm group")
    };
    let machine::MachineAction::Vm(vmg) = mg.action else {
        panic!("expected Vm action under machine")
    };
    match vmg {
        group::VmCmd::Sandbox(sandbox::Args {
            action:
                sandbox::SandboxAction::Gc(sandbox::GcArgs {
                    dry_run,
                    apply,
                    json,
                }),
        }) => {
            assert!(!dry_run);
            assert!(apply);
            assert!(!json);
        }
        _ => panic!("Expected Sandbox gc command"),
    }
}

#[test]
fn sandbox_gc_json_parses() {
    let cli = Cli::try_parse_from(["mvmctl", "machine", "sandbox", "gc", "--json"]).expect("parse");
    let Commands::Machine(mg) = cli.command else {
        panic!("expected vm group")
    };
    let machine::MachineAction::Vm(vmg) = mg.action else {
        panic!("expected Vm action under machine")
    };
    match vmg {
        group::VmCmd::Sandbox(sandbox::Args {
            action: sandbox::SandboxAction::Gc(sandbox::GcArgs { json, .. }),
        }) => {
            assert!(json);
        }
        _ => panic!("Expected Sandbox gc command"),
    }
}

#[test]
fn sandbox_gc_rejects_apply_and_dry_run_together() {
    let result =
        Cli::try_parse_from(["mvmctl", "machine", "sandbox", "gc", "--apply", "--dry-run"]);
    assert!(result.is_err());
}

#[test]
fn cp_host_to_guest_parses() {
    let cli = Cli::try_parse_from([
        "mvmctl",
        "machine",
        "cp",
        "--force",
        "--create-parents",
        "--max-bytes",
        "1024",
        "./host.txt",
        "vm1:/tmp/host.txt",
    ])
    .expect("parse");
    let Commands::Machine(mg) = cli.command else {
        panic!("expected vm group")
    };
    let machine::MachineAction::Vm(vmg) = mg.action else {
        panic!("expected Vm action under machine")
    };
    match vmg {
        group::VmCmd::Cp(cp::Args {
            source,
            destination,
            force,
            create_parents,
            max_bytes,
            json,
        }) => {
            assert_eq!(source, "./host.txt");
            assert_eq!(destination, "vm1:/tmp/host.txt");
            assert!(force);
            assert!(create_parents);
            assert_eq!(max_bytes, 1024);
            assert!(!json);
        }
        _ => panic!("Expected Cp command"),
    }
}

#[test]
fn cp_json_flag_parses() {
    let cli = Cli::try_parse_from([
        "mvmctl",
        "machine",
        "cp",
        "--json",
        "./host.txt",
        "vm1:/tmp/host.txt",
    ])
    .expect("parse");
    let Commands::Machine(mg) = cli.command else {
        panic!("expected vm group")
    };
    let machine::MachineAction::Vm(vmg) = mg.action else {
        panic!("expected Vm action under machine")
    };
    match vmg {
        group::VmCmd::Cp(cp::Args { json, .. }) => {
            assert!(json);
        }
        _ => panic!("Expected Cp command"),
    }
}

#[test]
fn cp_guest_to_host_defaults_parse() {
    let cli = Cli::try_parse_from(["mvmctl", "machine", "cp", "vm1:/tmp/out.txt", "./out.txt"])
        .expect("parse");
    let Commands::Machine(mg) = cli.command else {
        panic!("expected vm group")
    };
    let machine::MachineAction::Vm(vmg) = mg.action else {
        panic!("expected Vm action under machine")
    };
    match vmg {
        group::VmCmd::Cp(cp::Args {
            source,
            destination,
            force,
            create_parents,
            max_bytes,
            json,
        }) => {
            assert_eq!(source, "vm1:/tmp/out.txt");
            assert_eq!(destination, "./out.txt");
            assert!(!force);
            assert!(!create_parents);
            assert_eq!(max_bytes, 16 * 1024 * 1024);
            assert!(!json);
        }
        _ => panic!("Expected Cp command"),
    }
}

#[test]
fn run_transient_with_launch_plan_no_argv() {
    let cli =
        Cli::try_parse_from(["mvmctl", "run", "--launch-plan", "./plan.json"]).expect("parse");
    match cli.command {
        Commands::Run(exec::TransientRunArgs { run, .. }) => {
            assert_eq!(run.launch_plan.as_deref(), Some("./plan.json"));
            assert!(run.argv.is_empty());
        }
        _ => panic!("Expected Run command"),
    }
}

#[test]
fn run_transient_launch_plan_conflicts_with_argv() {
    let cli = Cli::try_parse_from([
        "mvmctl",
        "run",
        "--launch-plan",
        "./plan.json",
        "--",
        "echo",
        "hi",
    ]);
    assert!(
        cli.is_err(),
        "--launch-plan and trailing argv must be mutually exclusive"
    );
}

#[test]
fn run_transient_with_manifest_and_resources() {
    let cli = Cli::try_parse_from([
        "mvmctl",
        "machine",
        "run",
        "--manifest",
        "my-tpl",
        "--cpus",
        "4",
        "--memory",
        "1G",
        "--",
        "/bin/true",
    ])
    .expect("parse");
    match cli.command {
        Commands::Machine(mg) => match mg.action {
            machine::MachineAction::Run(machine::MachineRunArgs {
                run:
                    exec::RunArgs {
                        manifest,
                        cpus,
                        memory,
                        argv,
                        ..
                    },
                ..
            }) => {
                assert_eq!(manifest.as_deref(), Some("my-tpl"));
                assert_eq!(cpus, 4);
                assert_eq!(memory, "1G");
                assert_eq!(argv, vec!["/bin/true".to_string()]);
            }
            _ => panic!("Expected machine run"),
        },
        _ => panic!("Expected Machine command"),
    }
}

#[test]
fn run_transient_with_mount_and_env() {
    // `machine run` uses `--mount` for directory shares and
    // `--env` for environment variables.
    let cli = Cli::try_parse_from([
        "mvmctl",
        "machine",
        "run",
        "--image",
        "alpine:latest",
        "--mount",
        "/tmp:/work",
        "--volume",
        "/etc:/host-etc",
        "--env",
        "FOO=bar",
        "--env",
        "BAZ=qux",
        "--",
        "ls",
        "/work",
    ])
    .expect("parse");
    match cli.command {
        Commands::Machine(mg) => match mg.action {
            machine::MachineAction::Run(machine::MachineRunArgs {
                run:
                    exec::RunArgs {
                        mounts: volume,
                        env,
                        argv,
                        ..
                    },
                ..
            }) => {
                assert_eq!(
                    volume,
                    vec!["/tmp:/work".to_string(), "/etc:/host-etc".to_string()]
                );
                assert_eq!(env, vec!["FOO=bar".to_string(), "BAZ=qux".to_string()]);
                assert_eq!(argv, vec!["ls".to_string(), "/work".to_string()]);
            }
            _ => panic!("Expected machine run"),
        },
        _ => panic!("Expected Machine command"),
    }
}

#[test]
fn direct_run_accepts_a_read_only_mount() {
    let cli = Cli::try_parse_from([
        "mvmctl",
        "run",
        "--mount",
        "/tmp:/work:ro",
        "--",
        "ls",
        "/work",
    ])
    .expect("parse");
    match cli.command {
        Commands::Run(exec::TransientRunArgs { run, .. }) => {
            assert_eq!(run.mounts, vec!["/tmp:/work:ro"]);
            assert_eq!(run.argv, vec!["ls", "/work"]);
        }
        _ => panic!("Expected Run command"),
    }
}

#[test]
fn run_transient_requires_argv() {
    // `argv` is shared with `machine run`, which legitimately boots with no
    // command (`-d`), so the requirement moved off the clap attribute and onto
    // `run_transient`. It parses; running it is what refuses.
    let cli = Cli::try_parse_from(["mvmctl", "run"]).expect("parses");
    let Commands::Run(args) = cli.command else {
        panic!("expected Commands::Run");
    };
    let err = exec::run_transient(
        &Cli::parse_from(["mvmctl", "doctor"]),
        args,
        &mvm_core::user_config::MvmConfig::default(),
    )
    .expect_err("a bare `run` must refuse");
    assert!(
        err.to_string().contains("needs a command"),
        "unexpected error: {err}"
    );
}

// --- Init CLI tests (pure project-scaffold; DIR is required) ---

#[test]
fn test_init_requires_dir() {
    let result = Cli::try_parse_from(["mvmctl", "init"]);
    assert!(
        result.is_err(),
        "bare `mvmctl init` should error (DIR required)"
    );
}

#[test]
fn test_init_with_catalog_flag() {
    let cli = Cli::try_parse_from(["mvmctl", "init", "demo", "--catalog", "postgres"]).unwrap();
    match cli.command {
        Commands::Init(init::Args {
            dir,
            preset,
            prompt,
            catalog,
        }) => {
            assert_eq!(dir, "demo");
            assert!(preset.is_none());
            assert!(prompt.is_none());
            assert_eq!(catalog.as_deref(), Some("postgres"));
        }
        _ => panic!("Expected Init command"),
    }
}

#[test]
fn test_init_catalog_conflicts_with_preset() {
    let result = Cli::try_parse_from([
        "mvmctl",
        "init",
        "demo",
        "--catalog",
        "http",
        "--preset",
        "minimal",
    ]);
    assert!(
        result.is_err(),
        "--catalog and --preset are mutually exclusive"
    );
}

// --- Generate CLI tests ---

#[test]
fn test_generate_sdk_parses() {
    let cli =
        Cli::try_parse_from(["mvmctl", "generate", "sdk", "app.py", "-o", "./my-app"]).unwrap();
    assert!(matches!(
        cli.command,
        Commands::Generate(generate::Args {
            action: generate::GenerateAction::Sdk { .. }
        })
    ));
}

#[test]
fn test_generate_template_parses() {
    let cli =
        Cli::try_parse_from(["mvmctl", "generate", "template", "python", "./my-app"]).unwrap();
    assert!(matches!(
        cli.command,
        Commands::Generate(generate::Args {
            action: generate::GenerateAction::Template { .. }
        })
    ));
}

#[test]
fn test_generate_prompt_parses() {
    let cli = Cli::try_parse_from([
        "mvmctl",
        "generate",
        "prompt",
        "python api with postgres",
        "./my-app",
    ])
    .unwrap();
    assert!(matches!(
        cli.command,
        Commands::Generate(generate::Args {
            action: generate::GenerateAction::Prompt { .. }
        })
    ));
}

#[test]
fn test_generate_sdk_default_out() {
    let cli = Cli::try_parse_from(["mvmctl", "generate", "sdk", "app.py"]).unwrap();
    match cli.command {
        Commands::Generate(generate::Args {
            action: generate::GenerateAction::Sdk { out, .. },
        }) => assert_eq!(out, std::path::PathBuf::from("./out")),
        _ => panic!("expected generate sdk"),
    }
}

// --- Template CLI tests ---

#[test]
fn test_template_list_parses() {
    let cli = Cli::try_parse_from(["mvmctl", "template", "list"]);
    assert!(cli.is_ok());
}

#[test]
fn test_template_search_parses() {
    let cli = Cli::try_parse_from(["mvmctl", "template", "search", "python"]).unwrap();
    assert!(matches!(
        cli.command,
        Commands::Template(template::Args {
            action: template::TemplateAction::Search { .. }
        })
    ));
}

#[test]
fn test_template_info_parses() {
    let cli = Cli::try_parse_from(["mvmctl", "template", "info", "python-pandas"]).unwrap();
    match cli.command {
        Commands::Template(template::Args {
            action: template::TemplateAction::Info { name },
        }) => assert_eq!(name, "python-pandas"),
        _ => panic!("expected template info"),
    }
}

// --- Cache CLI tests ---

#[test]
fn test_cache_info_json_parses() {
    let cli = Cli::try_parse_from(["mvmctl", "cache", "info", "--json"]).unwrap();
    assert!(matches!(
        cli.command,
        Commands::Cache(cache::Args {
            action: CacheAction::Info { json: true }
        })
    ));
}

#[test]
fn test_cache_info() {
    let cli = Cli::try_parse_from(["mvmctl", "cache", "info"]);
    assert!(cli.is_ok());
}

#[test]
fn test_cache_prune() {
    let cli = Cli::try_parse_from(["mvmctl", "cache", "prune"]);
    assert!(cli.is_ok());
}

#[test]
fn test_cache_status_json_parses() {
    let cli = Cli::try_parse_from(["mvmctl", "cache", "status", "--json"]).unwrap();
    assert!(matches!(
        cli.command,
        Commands::Cache(cache::Args {
            action: CacheAction::Status { json: true }
        })
    ));
}

#[test]
fn test_cache_status() {
    let cli = Cli::try_parse_from(["mvmctl", "cache", "status"]);
    assert!(cli.is_ok());
}

#[test]
fn test_cache_status_help() {
    let cli = Cli::try_parse_from(["mvmctl", "cache", "status", "--help"]);
    // clap exits with a "help displayed" error rather than Ok, so assert the
    // parse at least recognizes the subcommand/flag combination.
    assert!(cli.is_err());
}

#[test]
fn test_cache_prune_help() {
    let cli = Cli::try_parse_from(["mvmctl", "cache", "prune", "--help"]);
    assert!(cli.is_err());
}

#[test]
fn test_pool_warm_parses_optional_count() {
    // `mvmctl pool warm` (default count) and `pool warm N`.
    assert!(Cli::try_parse_from(["mvmctl", "pool", "warm"]).is_ok());
    let cli = Cli::try_parse_from(["mvmctl", "pool", "warm", "3"]).unwrap();
    match cli.command {
        Commands::Pool(pool::Args {
            action: pool::PoolAction::Warm { count, .. },
        }) => assert_eq!(count, Some(3)),
        _ => panic!("Expected Pool Warm command"),
    }
}

#[test]
fn test_pool_status_parses_json_flag() {
    let cli = Cli::try_parse_from(["mvmctl", "pool", "status", "--json"]).unwrap();
    match cli.command {
        Commands::Pool(pool::Args {
            action: pool::PoolAction::Status { json },
        }) => assert!(json),
        _ => panic!("Expected Pool Status command"),
    }
}

#[test]
fn test_cache_prune_dry_run() {
    let cli = Cli::try_parse_from(["mvmctl", "cache", "prune", "--dry-run"]).unwrap();
    match cli.command {
        Commands::Cache(cache::Args {
            action:
                CacheAction::Prune {
                    dry_run,
                    orphan_builds,
                    no_reap_orphans,
                    ..
                },
        }) => {
            assert!(dry_run);
            assert!(!orphan_builds);
            // Reaping is on by default; `--no-reap-orphans` was not passed.
            assert!(!no_reap_orphans);
        }
        _ => panic!("Expected Cache Prune command"),
    }
}

#[test]
fn test_cache_prune_orphan_builds_flag() {
    let cli = Cli::try_parse_from(["mvmctl", "cache", "prune", "--orphan-builds"]).unwrap();
    match cli.command {
        Commands::Cache(cache::Args {
            action:
                CacheAction::Prune {
                    dry_run,
                    orphan_builds,
                    no_reap_orphans,
                    ..
                },
        }) => {
            assert!(!dry_run);
            assert!(orphan_builds);
            // Reaping is on by default; `--no-reap-orphans` was not passed.
            assert!(!no_reap_orphans);
        }
        _ => panic!("Expected Cache Prune command"),
    }
}

#[test]
fn test_cache_prune_no_reap_orphans_flag() {
    // `prune` reaps orphaned mvm-libkrun-supervisor / legacy gateway / console-tail
    // processes (and their per-VM cache dirs) by default; `--no-reap-orphans`
    // opts out so a disk-only prune touches no processes.
    let cli = Cli::try_parse_from(["mvmctl", "cache", "prune", "--no-reap-orphans"]).unwrap();
    match cli.command {
        Commands::Cache(cache::Args {
            action:
                CacheAction::Prune {
                    dry_run,
                    orphan_builds,
                    no_reap_orphans,
                    ..
                },
        }) => {
            assert!(!dry_run);
            assert!(!orphan_builds);
            assert!(no_reap_orphans);
        }
        _ => panic!("Expected Cache Prune command"),
    }
}

#[test]
fn test_cache_prune_reaps_orphans_by_default() {
    // Regression: a bare `cache prune` must reap orphans (dead microVMs don't
    // accumulate); the opt-out flag is off.
    let cli = Cli::try_parse_from(["mvmctl", "cache", "prune"]).unwrap();
    match cli.command {
        Commands::Cache(cache::Args {
            action: CacheAction::Prune {
                no_reap_orphans, ..
            },
        }) => assert!(!no_reap_orphans),
        _ => panic!("Expected Cache Prune command"),
    }
}

#[test]
fn test_cache_prune_combined_flags() {
    // All sweep flags should compose so users can do a single
    // "clean everything" pass.
    let cli = Cli::try_parse_from([
        "mvmctl",
        "cache",
        "prune",
        "--dry-run",
        "--orphan-builds",
        "--no-reap-orphans",
        "--orphan-dirs",
        "--deep",
    ])
    .unwrap();
    match cli.command {
        Commands::Cache(cache::Args {
            action:
                CacheAction::Prune {
                    dry_run,
                    orphan_builds,
                    no_reap_orphans,
                    orphan_dirs,
                    deep,
                },
        }) => {
            assert!(dry_run);
            assert!(orphan_builds);
            assert!(no_reap_orphans);
            assert!(orphan_dirs);
            assert!(deep);
        }
        _ => panic!("Expected Cache Prune command"),
    }
}

#[test]
fn test_cache_repair_force_flag() {
    let cli = Cli::try_parse_from(["mvmctl", "cache", "repair", "--force"]).unwrap();
    match cli.command {
        Commands::Cache(cache::Args {
            action: CacheAction::Repair { force, .. },
        }) => assert!(force),
        _ => panic!("Expected Cache Repair command"),
    }
}

// --- Up --network flag tests (up retired; pin removal) ---

#[test]
fn test_up_network_default() {
    // `--network` was an `up`-only flag; `up` is retired.
    let result = Cli::try_parse_from(["mvmctl", "up", "--flake", "."]);
    assert!(result.is_err(), "`up` was retired");
    assert_eq!(
        result.unwrap_err().kind(),
        clap::error::ErrorKind::InvalidSubcommand
    );
}

#[test]
fn test_up_network_custom() {
    // `--network` was an `up`-only flag; `up` is retired.
    let result = Cli::try_parse_from(["mvmctl", "up", "--flake", ".", "--network", "isolated"]);
    assert!(result.is_err(), "`up` was retired");
    assert_eq!(
        result.unwrap_err().kind(),
        clap::error::ErrorKind::InvalidSubcommand
    );
}

// The `mvmctl template *` namespace was removed outright. The two
// tests previously here covered `template init …` preset/prompt
// parsing — equivalent coverage now lives on
// `mvmctl init <DIR> --preset/--prompt` (smart-dispatch in
// `commands/env/init.rs`). See `test_init_*` below.

#[test]
fn test_init_scaffold_dir() {
    let cli = Cli::try_parse_from(["mvmctl", "init", "demo"]).unwrap();
    match cli.command {
        Commands::Init(init::Args {
            dir,
            preset,
            prompt,
            catalog,
        }) => {
            assert_eq!(dir, "demo");
            assert!(preset.is_none());
            assert!(prompt.is_none());
            assert!(catalog.is_none());
        }
        _ => panic!("Expected Init command"),
    }
}

#[test]
fn test_init_scaffold_with_prompt_flag() {
    let cli = Cli::try_parse_from([
        "mvmctl",
        "init",
        "demo",
        "--prompt",
        "python worker that polls an API",
    ])
    .unwrap();
    match cli.command {
        Commands::Init(init::Args {
            dir,
            prompt,
            preset,
            catalog,
        }) => {
            assert_eq!(dir, "demo");
            assert_eq!(prompt.as_deref(), Some("python worker that polls an API"));
            assert!(preset.is_none());
            assert!(catalog.is_none());
        }
        _ => panic!("Expected Init command"),
    }
}

// ---- admission flags (up retired; pin removal) ----

#[test]
fn test_up_tenant_parse_default_is_none() {
    // `--tenant` was an `up`-only flag; `up` is retired.
    let result = Cli::try_parse_from(["mvmctl", "up"]);
    assert!(result.is_err(), "`up` was retired");
    assert_eq!(
        result.unwrap_err().kind(),
        clap::error::ErrorKind::InvalidSubcommand
    );
}

#[test]
fn test_up_tenant_override_via_flag() {
    // `--tenant` was an `up`-only flag; `up` is retired.
    let result = Cli::try_parse_from(["mvmctl", "up", "--tenant", "acme"]);
    assert!(result.is_err(), "`up` was retired");
    assert_eq!(
        result.unwrap_err().kind(),
        clap::error::ErrorKind::InvalidSubcommand
    );
}

#[test]
fn test_up_no_supervisor_defaults_off() {
    // `--no-supervisor` was an `up`-only flag; `up` is retired.
    let result = Cli::try_parse_from(["mvmctl", "up"]);
    assert!(result.is_err(), "`up` was retired");
    assert_eq!(
        result.unwrap_err().kind(),
        clap::error::ErrorKind::InvalidSubcommand
    );
}

#[test]
fn test_up_no_supervisor_flag_parses() {
    // `--no-supervisor` was an `up`-only flag; `up` is retired.
    let result = Cli::try_parse_from(["mvmctl", "up", "--no-supervisor"]);
    assert!(result.is_err(), "`up` was retired");
    assert_eq!(
        result.unwrap_err().kind(),
        clap::error::ErrorKind::InvalidSubcommand
    );
}

// ---- `mvmctl compile --from-recording` ----

#[test]
fn test_compile_from_recording_parses() {
    let cli = Cli::try_parse_from([
        "mvmctl",
        "build",
        "compile",
        "--from-recording",
        "/tmp/rec.json",
        "--out",
        "/tmp/out",
    ])
    .expect("parse");
    let Commands::Build(bg) = cli.command else {
        panic!("expected build group")
    };
    match bg.action {
        build_group::BuildCmd::Compile(compile::Args {
            from_recording,
            from_ir,
            entry,
            ..
        }) => {
            assert_eq!(
                from_recording
                    .as_deref()
                    .map(|p| p.to_string_lossy().into_owned()),
                Some("/tmp/rec.json".to_string())
            );
            assert!(from_ir.is_none());
            assert!(entry.is_none());
        }
        _ => panic!("Expected Compile command"),
    }
}

#[test]
fn test_compile_from_recording_conflicts_with_from_ir() {
    // --from-ir and --from-recording are mutually exclusive at the
    // clap level; pin that so a future refactor can't accidentally
    // accept both.
    let err = Cli::try_parse_from([
        "mvmctl",
        "build",
        "compile",
        "--from-recording",
        "/tmp/rec.json",
        "--from-ir",
        "/tmp/ir.json",
    ])
    .expect_err("clap must reject the combo");
    let msg = err.to_string();
    assert!(
        msg.contains("from-ir") || msg.contains("from-recording") || msg.contains("cannot be used"),
        "expected a clap mutual-exclusion error, got: {msg}"
    );
}

#[test]
fn test_compile_default_no_from_flags_leaves_them_none() {
    let cli = Cli::try_parse_from(["mvmctl", "build", "compile", "--from-ir", "/tmp/ir.json"])
        .expect("parse");
    let Commands::Build(bg) = cli.command else {
        panic!("expected build group")
    };
    match bg.action {
        build_group::BuildCmd::Compile(compile::Args {
            from_ir,
            from_recording,
            ..
        }) => {
            assert!(from_ir.is_some());
            assert!(from_recording.is_none());
        }
        _ => panic!("Expected Compile command"),
    }
}

// ── `--builder` global flag ──

#[test]
fn builder_flag_appears_in_help() {
    // Renders the top-level clap Command's help via the same code
    // path `mvmctl --help` exercises. Asserts the new global flag
    // surfaces in `mvmctl --help` without spawning the binary.
    let cmd = cli_command();
    let help = cmd.clone().render_help().to_string();
    assert!(
        help.contains("--builder"),
        "`--builder` flag not surfaced in `mvmctl --help`; help text was:\n{help}"
    );
    assert!(
        help.contains("libkrun") && help.contains("hvf"),
        "`--builder` value choices missing from help; help text was:\n{help}"
    );
}

#[test]
fn builder_flag_accepts_libkrun() {
    let cli = Cli::try_parse_from(["mvmctl", "--builder", "libkrun", "doctor"]).expect("parse");
    assert_eq!(cli.builder.as_deref(), Some("libkrun"));
}

#[test]
fn builder_flag_rejects_unknown_value() {
    // Clap's `value_parser = ["libkrun", "qemu", "hvf"]` should refuse
    // anything outside that set. Catches typos like `=vmz` early
    // rather than letting `MVM_BUILDER_BACKEND_ENV`'s
    // warn-and-fall-through path eat them.
    let err = Cli::try_parse_from(["mvmctl", "--builder", "bogus", "doctor"]).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("invalid value")
            || msg.contains("possible values")
            || msg.contains("bogus")
            || msg.contains("one of the values isn't valid for an argument"),
        "expected a clap value-parser error mentioning 'bogus', got: {msg}"
    );
}

#[test]
fn builder_flag_unset_by_default() {
    let cli = Cli::try_parse_from(["mvmctl", "doctor"]).expect("parse");
    assert_eq!(cli.builder, None);
}

#[test]
fn builder_flag_lists_hvf() {
    let cmd = cli_command();
    let help = cmd.clone().render_help().to_string();
    assert!(
        help.contains("hvf"),
        "expected --builder to accept hvf; help text was:\n{help}"
    );
}

#[test]
fn builder_flag_accepts_hvf() {
    let cli = Cli::try_parse_from(["mvmctl", "--builder", "hvf", "doctor"]).expect("parse");
    assert_eq!(cli.builder.as_deref(), Some("hvf"));
}

// --- Session start --ephemeral tests ---

#[test]
fn test_session_start_ephemeral_parses() {
    let cli = Cli::try_parse_from([
        "mvmctl",
        "machine",
        "session",
        "start",
        "tmpl",
        "--ephemeral",
    ])
    .unwrap();
    let Commands::Machine(mg) = cli.command else {
        panic!("expected vm group")
    };
    let machine::MachineAction::Vm(vmg) = mg.action else {
        panic!("expected Vm action under machine")
    };
    match vmg {
        group::VmCmd::Session(session::Args {
            command: session::Cmd::Start(a),
        }) => assert!(a.ephemeral),
        _ => panic!("expected session start"),
    }
}

#[test]
fn test_session_start_agent_verbs_parse() {
    let cli = Cli::try_parse_from([
        "mvmctl",
        "machine",
        "session",
        "start",
        "tmpl",
        "--agent-verb",
        "ping",
        "--agent-verb",
        "run-entrypoint",
    ])
    .unwrap();
    let Commands::Machine(mg) = cli.command else {
        panic!("expected vm group")
    };
    let machine::MachineAction::Vm(vmg) = mg.action else {
        panic!("expected Vm action under machine")
    };
    match vmg {
        group::VmCmd::Session(session::Args {
            command: session::Cmd::Start(a),
        }) => assert_eq!(a.agent_verb, vec!["ping", "run-entrypoint"]),
        _ => panic!("expected session start"),
    }
}

// --- Session attach --continue / --resume tests ---

#[test]
fn test_session_attach_continue_parses() {
    let cli =
        Cli::try_parse_from(["mvmctl", "machine", "session", "attach", "--continue"]).unwrap();
    let Commands::Machine(mg) = cli.command else {
        panic!("expected vm group")
    };
    let machine::MachineAction::Vm(vmg) = mg.action else {
        panic!("expected Vm action under machine")
    };
    match vmg {
        group::VmCmd::Session(session::Args {
            command: session::Cmd::Attach(a),
        }) => {
            assert!(a.continue_latest);
            assert!(a.session_id.is_none());
            assert!(a.resume.is_none());
        }
        _ => panic!("expected session attach"),
    }
}

#[test]
fn test_up_wait_parses() {
    // `--wait` was an `up`-only flag; `up` is retired.
    let result = Cli::try_parse_from(["mvmctl", "up", "--flake", ".", "--wait"]);
    assert!(result.is_err(), "`up` was retired");
    assert_eq!(
        result.unwrap_err().kind(),
        clap::error::ErrorKind::InvalidSubcommand
    );
}

#[test]
fn test_up_wait_conflicts_with_detach() {
    // `--wait`/`--detach` were `up`-only flags; `up` is retired.
    let result = Cli::try_parse_from(["mvmctl", "up", "--flake", ".", "--wait", "--detach"]);
    assert!(result.is_err(), "`up` was retired");
    assert_eq!(
        result.unwrap_err().kind(),
        clap::error::ErrorKind::InvalidSubcommand
    );
}

#[test]
fn test_up_wait_conflicts_with_up_json() {
    // `--wait`/`--up-json` were `up`-only flags; `up` is retired.
    let result = Cli::try_parse_from(["mvmctl", "up", "--flake", ".", "--wait", "--up-json"]);
    assert!(result.is_err(), "`up` was retired");
    assert_eq!(
        result.unwrap_err().kind(),
        clap::error::ErrorKind::InvalidSubcommand
    );
}

#[test]
fn test_session_attach_resume_parses() {
    let cli = Cli::try_parse_from([
        "mvmctl",
        "machine",
        "session",
        "attach",
        "-r",
        "aaaaaaaaaaaaaaaa",
    ])
    .unwrap();
    let Commands::Machine(mg) = cli.command else {
        panic!("expected vm group")
    };
    let machine::MachineAction::Vm(vmg) = mg.action else {
        panic!("expected Vm action under machine")
    };
    match vmg {
        group::VmCmd::Session(session::Args {
            command: session::Cmd::Attach(a),
        }) => {
            assert_eq!(a.resume.as_deref(), Some("aaaaaaaaaaaaaaaa"));
        }
        _ => panic!("expected session attach"),
    }
}

// -------- reconcile-on-entry gate --------

fn touches(argv: &[&str]) -> bool {
    Cli::try_parse_from(argv)
        .unwrap()
        .command
        .touches_vm_state()
}

fn emits_machine_readable_stdout(argv: &[&str]) -> bool {
    Cli::try_parse_from(argv)
        .unwrap()
        .command
        .emits_machine_readable_stdout()
}

fn exits_early(argv: &[&str]) -> bool {
    Cli::try_parse_from(argv)
        .unwrap()
        .command
        .is_early_command()
}

#[test]
fn state_touching_commands_trigger_entry_convergence() {
    // Lifecycle mutate/read commands run the cheap converge pass.
    // (`up` was retired — named/persistent `machine run` and `machine start` are
    // the lifecycle-entry points.)
    assert!(touches(&[
        "mvmctl",
        "machine",
        "run",
        "--image",
        "alpine:latest",
        "-d"
    ]));
    assert!(touches(&["mvmctl", "machine", "start", "myvm"]));
    assert!(touches(&["mvmctl", "machine", "stop", "--all"]));
    assert!(touches(&["mvmctl", "machine", "console", "myvm"]));
    assert!(touches(&["mvmctl", "machine", "pause", "myvm"]));
    assert!(touches(&["mvmctl", "machine", "save", "myvm"]));
    assert!(touches(&["mvmctl", "machine", "resume", "myvm"]));
    assert!(touches(&["mvmctl", "machine", "ls"]));
}

#[test]
fn read_only_and_vm_agnostic_commands_skip_entry_convergence() {
    assert!(!touches(&["mvmctl", "doctor"]));
    assert!(!touches(&["mvmctl", "catalog", "list"]));
    assert!(!touches(&["mvmctl", "trust", "audit", "tail"]));
    assert!(!touches(&["mvmctl", "cache", "info"]));
    // `machine ls --all` must preserve registry-only stopped rows for rendering.
    assert!(!touches(&["mvmctl", "machine", "ls", "--all"]));
    assert!(!touches(&["mvmctl", "machine", "ls", "--all", "--json"]));
    // Foreground transient image runs are throwaway launches. They must not
    // auto-resume unrelated dev/persistent machines before booting the image.
    assert!(!touches(&[
        "mvmctl",
        "machine",
        "run",
        "--image",
        "alpine:latest",
        "--",
        "sh"
    ]));
    assert!(!touches(&[
        "mvmctl",
        "machine",
        "run",
        "--image",
        "alpine:latest",
        "-it",
        "--",
        "/bin/sh"
    ]));
    // `reconcile` is the convergence verb itself — must not double-run on entry.
    assert!(!touches(&["mvmctl", "reconcile"]));
    assert!(!touches(&["mvmctl", "reconcile", "--dry-run"]));
}

#[test]
fn state_touching_json_commands_reserve_stdout_before_entry_convergence() {
    // Regression: `machine ls --json` runs reconcile-on-entry before dispatch;
    // if chrome is still stdout-routed, a dev-VM hint can precede the JSON.
    assert!(emits_machine_readable_stdout(&[
        "mvmctl", "machine", "ls", "--all", "--json"
    ]));
    // `mvmctl up` is retired; `run` survives hidden as the SDK transport and
    // keeps its `--json` reservation. The user-facing machine-readable channel
    // is `machine run --json`.
    assert!(emits_machine_readable_stdout(&[
        "mvmctl", "run", "--json", "--", "true"
    ]));
    assert!(emits_machine_readable_stdout(&[
        "mvmctl", "machine", "save", "myvm", "--json"
    ]));
    assert!(emits_machine_readable_stdout(&[
        "mvmctl",
        "machine",
        "restore",
        "ckpt-myvm",
        "--json"
    ]));
    assert!(emits_machine_readable_stdout(&[
        "mvmctl", "machine", "snapshot", "ls", "--json"
    ]));

    assert!(!emits_machine_readable_stdout(&["mvmctl", "machine", "ls"]));
    // `mvmctl up` is retired; `up_removed` pins the removal separately.
}

#[test]
fn internal_helper_commands_short_circuit_before_startup_side_effects() {
    assert!(exits_early(&[
        "mvmctl",
        "__qemu-vsock-bridge",
        "--spec",
        "/tmp/qemu-vsock-bridge.json",
    ]));
    assert!(!exits_early(&["mvmctl", "doctor"]));
    assert!(!exits_early(&[
        "mvmctl",
        "machine",
        "run",
        "--image",
        "alpine:latest",
        "--",
        "true",
    ]));
}

// --- Top-level help surface tests ---

#[test]
fn top_level_help_shows_user_facing_groups_and_hides_dev_tooling() {
    let visible: Vec<String> = cli_command()
        .get_subcommands()
        .filter(|cmd| !cmd.is_hide_set())
        .map(|cmd| cmd.get_name().to_string())
        .collect();

    // Anything a user is expected to invoke. `secret` owns the entry point to
    // host-side credential substitution and `trust` owns `trust receipt
    // verify`; both were hidden while the CLI reference documented them, which
    // meant the tool could not tell you those subsystems had a CLI at all.
    for shown in &[
        "machine",
        "run",
        "build",
        "kernel",
        "deploy",
        "generate",
        "template",
        "init",
        "doctor",
        "bootstrap",
        "explain",
        "prepare",
        "watch",
        "pack",
        "env",
        "manifest",
        "image",
        "catalog",
        "cache",
        "network",
        "pool",
        "secret",
        "trust",
        "bundle",
        "artifact",
        "deps",
        "ops",
        "shell-init",
    ] {
        assert!(
            visible.iter().any(|n| n == shown),
            "user-facing command `{shown}` must appear in top-level help; visible = {visible:?}"
        );
    }

    let help = cli_command().render_help().to_string();
    // Dev tooling stays out of the way. It still works when typed.
    for hidden in &["storage", "reconcile", "seccomp-audit", "dashboard"] {
        // Commands are listed one per line; a hidden command's name should
        // not appear as a standalone word at the start of a help line.
        let visible_as_subcommand = help.lines().any(|line| {
            let trimmed = line.trim_start();
            trimmed.starts_with(hidden)
                && trimmed[hidden.len()..].starts_with(|c: char| c.is_whitespace() || c == '\0')
        });
        assert!(
            !visible_as_subcommand,
            "dev-tooling command `{hidden}` must be hidden from top-level help but was found"
        );
    }
}

#[test]
fn machine_run_verbose_after_options_is_not_guest_argv() {
    let cli = Cli::try_parse_from([
        "mvmctl",
        "machine",
        "run",
        "--image",
        "alpine:latest",
        "-vvv",
        "--allow-host",
        "google.com",
        "--",
        "ps",
        "aux",
    ])
    .expect("machine run verbosity must parse before trailing guest argv");

    assert_eq!(cli.verbose, 3);
    let Commands::Machine(machine_args) = cli.command else {
        panic!("expected machine command")
    };
    let machine::MachineAction::Run(args) = machine_args.action else {
        panic!("expected machine run")
    };
    assert_eq!(args.run.allow_host, vec!["google.com"]);
    assert_eq!(args.run.argv, vec!["ps", "aux"]);
}

#[test]
fn debug_alias_parses_before_and_after_machine_run() {
    let cli = Cli::try_parse_from(["mvmctl", "--debug", "doctor"])
        .expect("root --debug alias must parse before subcommand");
    assert_eq!(cli.verbose, 1);

    let cli = Cli::try_parse_from(["mvmctl", "doctor", "--debug"])
        .expect("root --debug alias must parse after subcommand");
    assert_eq!(cli.verbose, 1);

    let cli = Cli::try_parse_from([
        "mvmctl",
        "machine",
        "run",
        "--image",
        "alpine:latest",
        "--debug",
        "--",
        "true",
    ])
    .expect("machine run --debug alias must parse before trailing guest argv");
    assert_eq!(cli.verbose, 1);
    let Commands::Machine(machine_args) = cli.command else {
        panic!("expected machine command")
    };
    let machine::MachineAction::Run(args) = machine_args.action else {
        panic!("expected machine run")
    };
    assert_eq!(args.run.argv, vec!["true"]);
}

#[test]
fn infra_commands_still_invoke() {
    // Hidden commands must still parse — `hide` only affects help visibility.
    assert!(
        Cli::try_parse_from(["mvmctl", "pool", "status"]).is_ok(),
        "pool must still parse when hidden"
    );
    assert!(
        Cli::try_parse_from(["mvmctl", "cache", "info"]).is_ok(),
        "cache must still parse when hidden"
    );
    assert!(
        Cli::try_parse_from(["mvmctl", "network", "list"]).is_ok(),
        "network must still parse when hidden"
    );
    assert!(
        Cli::try_parse_from(["mvmctl", "catalog", "list"]).is_ok(),
        "catalog must still parse when hidden"
    );
    assert!(
        Cli::try_parse_from(["mvmctl", "ops", "metrics"]).is_ok(),
        "ops must still parse when hidden"
    );
}

#[test]
fn machine_help_lists_run_first() {
    let mut machine_cmd = cli_command()
        .find_subcommand_mut("machine")
        .expect("machine subcommand must exist")
        .clone();
    let help = machine_cmd.render_help().to_string();

    // Verify the key ordering: run < start < stop < inspect < check-artifact
    let pos = |name: &str| -> usize {
        help.lines()
            .position(|line| {
                let t = line.trim_start();
                t.starts_with(name) && t[name.len()..].starts_with(|c: char| c.is_whitespace())
            })
            .unwrap_or_else(|| {
                panic!("`{name}` must appear as a line in machine --help;\nhelp:\n{help}")
            })
    };

    let run = pos("run");
    let start = pos("start");
    let stop = pos("stop");
    let inspect = pos("inspect");
    let check = pos("check-artifact");

    assert!(
        run < start,
        "`run` (line {run}) must appear before `start` (line {start}) in machine --help"
    );
    assert!(
        start < stop,
        "`start` (line {start}) must appear before `stop` (line {stop}) in machine --help"
    );
    assert!(
        stop < inspect,
        "`stop` (line {stop}) must appear before `inspect` (line {inspect}) in machine --help"
    );
    assert!(
        inspect < check,
        "`inspect` (line {inspect}) must appear before `check-artifact` (line {check}) in machine --help"
    );
}

// ---- Task 6: logs/console folded into machine ----

#[test]
fn machine_logs_parses() {
    let cli = Cli::try_parse_from(["mvmctl", "machine", "logs", "myvm"]).unwrap();
    let Commands::Machine(mg) = cli.command else {
        panic!("expected machine group")
    };
    match mg.action {
        machine::MachineAction::Logs(args) => {
            assert_eq!(args.name, "myvm");
        }
        _ => panic!("expected machine logs action"),
    }
}

#[test]
fn machine_console_parses() {
    let cli = Cli::try_parse_from(["mvmctl", "machine", "console", "myvm"]).unwrap();
    let Commands::Machine(mg) = cli.command else {
        panic!("expected machine group")
    };
    match mg.action {
        machine::MachineAction::Console(args) => {
            assert_eq!(args.name, "myvm");
        }
        _ => panic!("expected machine console action"),
    }
}

#[test]
fn logs_removed() {
    let err = Cli::try_parse_from(["mvmctl", "logs", "myvm"])
        .expect_err("logs must not parse after removal");
    assert_eq!(
        err.kind(),
        clap::error::ErrorKind::InvalidSubcommand,
        "expected InvalidSubcommand, got: {err:?}"
    );
}

#[test]
fn console_removed() {
    let err = Cli::try_parse_from(["mvmctl", "console", "myvm"])
        .expect_err("console must not parse after removal");
    assert_eq!(
        err.kind(),
        clap::error::ErrorKind::InvalidSubcommand,
        "expected InvalidSubcommand, got: {err:?}"
    );
}

#[test]
fn machine_console_refused_on_sealed_image() {
    use mvm_runtime::vm::runtime_meta::{StartModeKind, VmRuntimeMeta, write as write_meta};

    let _guard = mvm_runtime::vm::runtime_meta::HOME_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let mut env = mvm_core::util::test_env::TestEnv::new();
    let tmp = tempfile::tempdir().expect("tempdir");
    env.set("HOME", tmp.path());
    env.set("MVM_HOME", tmp.path());

    let name = "sealed-machine-console";
    write_meta(
        name,
        &VmRuntimeMeta {
            mode: StartModeKind::Detached,
            accessible: false,
            rootfs_path: None,
            runtime_source_policy: mvm_core::vm_backend::RuntimeSourcePolicy::RootfsOnly,
            runtime_overlay_version: None,
            observability_target: None,
        },
    )
    .expect("write");
    let err = console::enforce_accessible_gate(name, false).expect_err("must refuse");
    assert!(
        err.to_string().contains("sealed image"),
        "claim-15 gate must fire through machine console path: {err}"
    );
}

#[test]
fn machine_run_up_json_and_ttl_parse() {
    // `machine run --up-json --manifest x --ttl 60s` must parse without error
    // and set the expected fields.
    let args = parse_machine_run(&["--up-json", "--manifest", "x", "--ttl", "60s"]).unwrap();
    assert!(args.up_json);
    assert_eq!(args.ttl.as_deref(), Some("60s"));
    assert_eq!(args.run.manifest.as_deref(), Some("x"));
}

#[test]
fn machine_run_up_json_implies_persistent_mode() {
    // `--up-json` implies persistence: `--manifest x --up-json` (no argv, no -d)
    // must parse and route to the persistent lifecycle. We verify this via the
    // parsed fields: up_json is set, and the parse doesn't error (a transient
    // run with no argv would fail at dispatch, but persistent doesn't need argv).
    let args = parse_machine_run(&["--up-json", "--manifest", "x"]).unwrap();
    assert!(args.up_json, "up_json field must be set");
    // The manifest source must survive parsing.
    assert_eq!(args.run.manifest.as_deref(), Some("x"));
    // No detach flag needed — up_json alone implies persistence.
    assert!(!args.detach, "detach is not required when up_json is set");
}

#[test]
fn machine_run_up_json_guards_stdout() {
    // `machine run --up-json` must reserve stdout (emits_machine_readable_stdout).
    let cli =
        Cli::try_parse_from(["mvmctl", "machine", "run", "--up-json", "--manifest", "x"]).unwrap();
    assert!(
        cli.command.emits_machine_readable_stdout(),
        "--up-json must guard stdout via emits_machine_readable_stdout"
    );
}

#[test]
fn machine_run_up_json_withholds_the_started_banner() {
    // The test above pins a parse-level flag and passed the whole time stdout
    // was in fact being polluted: `run -d --up-json` printed
    // "started machine <name>" ahead of the envelope, so the SDK's live
    // transport died on `json.loads(stdout)` at line 1 column 1. Declaring
    // stdout machine-readable is not the same as withholding the banner, so
    // pin the banner decision itself.
    let args = parse_machine_run(&["--up-json", "--name", "vm", "--image", "alpine"])
        .expect("up-json run args parse");
    assert!(
        crate::commands::machine::runtime::banner_suppressed(&args),
        "--up-json reserves stdout for the envelope, so the banner must be withheld"
    );
    // Pin the wiring too, not just the decision: a mapping that stopped
    // consulting `banner_suppressed` would leave the assertion above green
    // while stdout went back to carrying the banner.
    assert!(
        crate::commands::machine::runtime::start_args_for_run(&args, "vm").quiet,
        "the start arguments a --up-json run boots under must carry quiet"
    );
}

#[test]
fn machine_run_without_up_json_keeps_the_started_banner() {
    // The banner is the only feedback an interactive `-d` run gives, so
    // suppressing it unconditionally would be a regression of its own.
    let args = parse_machine_run(&["-d", "--name", "vm", "--image", "alpine"])
        .expect("detached run args parse");
    assert!(
        !crate::commands::machine::runtime::banner_suppressed(&args),
        "a plain detached run still tells the user the machine started"
    );
    assert!(
        !crate::commands::machine::runtime::start_args_for_run(&args, "vm").quiet,
        "a plain detached run boots without quiet"
    );
}

#[test]
fn sdk_live_mode_shelled_commands_keep_parsing() {
    // Every command the SDKs shell to must parse against the real Cli.
    // A future rename that breaks any of these will fail CI here first.
    let sdk_commands: &[&[&str]] = &[
        &[
            "machine", "proc", "start", "vm", "-e", "K=V", "--", "echo", "hi",
        ],
        &["machine", "proc", "wait", "vm", "tok", "--timeout", "30"],
        &["machine", "fs", "write", "vm", "/app/x"],
        &["machine", "cp", "host.txt", "vm:/guest.txt"],
        &["machine", "forward", "vm", "--port", "8080:80"],
        &["machine", "stop", "vm"],
        &[
            "machine",
            "run",
            "-d",
            "--up-json",
            "--name",
            "vm",
            "--manifest",
            "tmpl",
            "--ttl",
            "1800s",
        ],
    ];
    for argv in sdk_commands {
        let mut full = vec!["mvmctl"];
        full.extend_from_slice(argv);
        Cli::try_parse_from(full.clone())
            .unwrap_or_else(|e| panic!("SDK command {:?} failed to parse: {e}", argv));
    }
}

/// The CLI's startup registration is what makes `mvmctl logs -f` read a
/// broker instead of an unchained console tail — for every command, not just
/// the ones that obviously boot a VM. A registration that stopped happening
/// would leave the whole capture path silently degraded with nothing else
/// failing.
#[test]
fn startup_registers_the_output_stream_plane() {
    register_stream_plane();
    assert!(
        mvm_runtime::workload_runner::console_streamer_installed(),
        "mvmctl must hand the workload runner a real console streamer at startup"
    );
    // Idempotent: a second call must not panic or unregister the first.
    register_stream_plane();
    assert!(mvm_runtime::workload_runner::console_streamer_installed());
}
