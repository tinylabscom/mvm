//! Installed application command contracts without acquisition or runtime side effects.

use mvm_cli::commands::cli_command;

#[test]
fn policy_activation_requires_an_explicit_project_and_is_listed() {
    cli_command()
        .try_get_matches_from(["mvmctl", "policy", "activate", "/project"])
        .expect("the activation command accepts a project path");
    assert!(
        cli_command()
            .try_get_matches_from(["mvmctl", "policy", "activate"])
            .is_err(),
        "activation cannot guess which project to commit"
    );
    let help = mvm_cli::commands::help_text_for(&["policy".into(), "--help".into()])
        .expect("policy --help renders");
    assert!(
        help.contains("activate"),
        "policy help must list the activation command"
    );
}

#[test]
fn policy_coordinator_takes_no_project_and_is_listed() {
    for arguments in [
        &["mvmctl", "policy", "coordinator"][..],
        &["mvmctl", "policy", "coordinator", "--json"],
    ] {
        cli_command()
            .try_get_matches_from(arguments)
            .expect("the coordinator report parses");
    }
    assert!(
        cli_command()
            .try_get_matches_from(["mvmctl", "policy", "coordinator", "--start"])
            .is_err(),
        "the report has no way to start or install a service"
    );
    let help = mvm_cli::commands::help_text_for(&["policy".into(), "--help".into()])
        .expect("policy --help renders");
    assert!(help.contains("coordinator"), "{help}");
}

#[test]
fn audit_consistency_requires_explicit_roots_and_exposes_help() {
    for verb in ["prove-consistency", "verify-consistency"] {
        let mut args = vec!["mvmctl", "trust", "audit", verb];
        if verb == "verify-consistency" {
            args.extend(["--proof", "proof.json"]);
        }
        assert!(cli_command().try_get_matches_from(&args).is_err());
        args.extend(["--old-root", "saved.json"]);
        assert!(cli_command().try_get_matches_from(&args).is_err());
        args.extend(["--new-root", "candidate.json", "--pubkey", "trusted.pub"]);
        assert!(cli_command().try_get_matches_from(&args).is_ok());
        let help = cli_command()
            .try_get_matches_from(["mvmctl", "trust", "audit", verb, "--help"])
            .unwrap_err();
        assert_eq!(help.kind(), clap::error::ErrorKind::DisplayHelp);
        for flag in ["--old-root", "--new-root", "--pubkey", "--tenant"] {
            assert!(help.to_string().contains(flag));
        }
    }
    assert!(
        cli_command()
            .try_get_matches_from([
                "mvmctl",
                "trust",
                "audit",
                "verify-consistency",
                "--old-root",
                "saved.json",
                "--new-root",
                "candidate.json",
            ])
            .is_err()
    );
}

#[test]
fn application_run_accepts_the_joke_workflow_without_launch_flags() {
    for command in [
        vec!["mvmctl", "run", "agent/claude"],
        vec!["mvmctl", "run", "--app", "agent/claude"],
    ] {
        let matches = cli_command().try_get_matches_from(command).unwrap();
        let run = matches.subcommand_matches("run").unwrap();
        assert!(
            !run.get_flag("entrypoint"),
            "dispatch selects the application action"
        );
        assert!(run.get_many::<String>("argv").is_none());
        assert!(run.get_many::<String>("allow_host").is_none());
        assert!(run.get_many::<String>("secret").is_none());
        assert!(
            run.get_one::<String>("stdin").is_none(),
            "implicit stdin stays one-shot"
        );
    }
    for command in [
        vec!["mvmctl", "search", "agent/claude"],
        vec!["mvmctl", "pull", "agent/claude"],
        vec!["mvmctl", "run", "agent/claude", "--", "echo", "hello"],
    ] {
        assert!(cli_command().try_get_matches_from(command).is_ok());
    }
}

#[test]
fn application_run_refuses_ambiguous_sources_and_entrypoint_commands() {
    for command in [
        vec![
            "mvmctl",
            "run",
            "--app",
            "agent/claude",
            "--image",
            "alpine",
        ],
        vec!["mvmctl", "run", "--app", "agent/claude", "alpine"],
        vec![
            "mvmctl",
            "run",
            "agent/claude",
            "--entrypoint",
            "--",
            "echo",
        ],
    ] {
        assert!(cli_command().try_get_matches_from(command).is_err());
    }
}

#[test]
fn backend_group_parses_its_verbs() {
    for command in [
        vec!["mvmctl", "backend", "list"],
        vec!["mvmctl", "backend", "add", "libkrun"],
        vec!["mvmctl", "backend", "remove", "libkrun"],
        vec!["mvmctl", "backend", "detect"],
        vec!["mvmctl", "backend", "detect", "--plain"],
    ] {
        let label = format!("{command:?}");
        cli_command()
            .try_get_matches_from(command)
            .unwrap_or_else(|error| panic!("{label} must parse: {error}"));
    }
}

#[test]
fn backend_add_and_remove_require_a_name() {
    for command in [
        vec!["mvmctl", "backend", "add"],
        vec!["mvmctl", "backend", "remove"],
    ] {
        let label = format!("{command:?}");
        assert!(
            cli_command().try_get_matches_from(command).is_err(),
            "{label} must fail without a backend name"
        );
    }
}

#[test]
fn backend_help_names_every_verb() {
    let help = mvm_cli::commands::help_text_for(&["backend".to_string(), "--help".to_string()])
        .expect("backend --help renders");
    for verb in ["list", "add", "remove", "detect"] {
        assert!(
            help.contains(verb),
            "backend help must name {verb}:\n{help}"
        );
    }
    let detect_help = mvm_cli::commands::help_text_for(&[
        "backend".to_string(),
        "detect".to_string(),
        "--help".to_string(),
    ])
    .expect("backend detect --help renders");
    assert!(detect_help.contains("--plain"), "{detect_help}");
}

#[test]
fn bench_report_takes_a_density_dir_and_the_lane_form_still_parses() {
    assert!(
        cli_command()
            .try_get_matches_from(["mvmctl", "bench", "report"])
            .is_err(),
        "the report needs a density directory"
    );
    cli_command()
        .try_get_matches_from([
            "mvmctl",
            "bench",
            "report",
            "--density-dir",
            "/run",
            "--launch-report",
            "a.json",
            "--launch-report",
            "b.json",
            "--state-cell-latency",
            "cells.json",
            "--json",
            "--out",
            "r.json",
        ])
        .expect("the report form parses");
    cli_command()
        .try_get_matches_from(["mvmctl", "bench", "--lane", "warm-claim", "--runs", "5"])
        .expect("the lane form still parses");
    cli_command()
        .try_get_matches_from([
            "mvmctl",
            "bench",
            "--",
            "run",
            "--no-detect",
            "--",
            "/bin/true",
        ])
        .expect("a launch after `--` still parses");
    let help =
        mvm_cli::commands::help_text_for(&["bench".into(), "report".into(), "--help".into()])
            .expect("bench report --help renders");
    assert!(
        help.contains("--density-dir")
            && help.contains("--launch-report")
            && help.contains("--state-cell-latency")
    );
    cli_command()
        .try_get_matches_from([
            "mvmctl",
            "bench",
            "fit",
            "--units",
            "4",
            "--vcpus",
            "2",
            "--memory-mib",
            "512",
            "--disk-mib",
            "1024",
            "--report",
            "r.json",
            "--backend",
            "hvf",
            "--architecture",
            "aarch64",
            "--inventory",
            "h.json",
            "--json",
        ])
        .expect("the fit form parses");
    assert!(
        cli_command()
            .try_get_matches_from(["mvmctl", "bench", "fit", "--units", "4"])
            .is_err(),
        "fit needs vcpus and memory"
    );
    cli_command()
        .try_get_matches_from([
            "mvmctl",
            "bench",
            "fit",
            "--topology",
            "t.json",
            "--backend",
            "firecracker",
            "--inventory",
            "h.json",
        ])
        .expect("the topology form parses without a size");
    assert!(
        cli_command()
            .try_get_matches_from([
                "mvmctl",
                "bench",
                "fit",
                "--topology",
                "t.json",
                "--units",
                "4",
            ])
            .is_err(),
        "a topology carries its own sizes"
    );
    let help = mvm_cli::commands::help_text_for(&["bench".into(), "--help".into()])
        .expect("bench --help renders");
    assert!(help.contains("fit"), "{help}");
}
