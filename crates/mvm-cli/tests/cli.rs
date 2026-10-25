//! Installed application command contracts without acquisition or runtime side effects.

use mvm_cli::commands::cli_command;

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
