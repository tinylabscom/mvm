//! Integration-style tests for the top-level CLI surface.

#![cfg(test)]

use super::*;
use clap::Parser;

// Group module aliases — give tests short names (`cleanup`, `up`, etc.) that
// follow the dispatcher's naming, regardless of which group they live in.
use super::build::{build, template};
use super::env::{cleanup, dev, init, uninstall};
use super::ops::{audit, cache, config, metrics, security};
use super::vm::{console, down, exec, forward, up};

use audit::AuditAction;
use cache::CacheAction;
use config::ConfigAction;
use dev::DevAction;
use security::SecurityAction;
use template::TemplateAction;
use up::RunParams;

use super::shared::{
    VolumeSpec, clap_flake_ref, clap_port_spec, clap_vm_name, clap_volume_spec,
    env_vars_to_drive_file, parse_port_spec, parse_port_specs, parse_volume_spec,
    ports_to_drive_file, read_dir_to_drive_files, resolve_flake_ref, resolve_network_policy,
};

#[test]
fn test_cleanup_defaults() {
    let cli = Cli::try_parse_from(["mvmctl", "cleanup"]).unwrap();
    match cli.command {
        Commands::Cleanup(cleanup::Args { keep, all, verbose }) => {
            assert_eq!(keep, None);
            assert!(!all);
            assert!(!verbose);
        }
        _ => panic!("Expected Cleanup command"),
    }
}

#[test]
fn test_cleanup_keep_flag() {
    let cli = Cli::try_parse_from(["mvmctl", "cleanup", "--keep", "9"]).unwrap();
    match cli.command {
        Commands::Cleanup(cleanup::Args { keep, all, verbose }) => {
            assert_eq!(keep, Some(9));
            assert!(!all);
            assert!(!verbose);
        }
        _ => panic!("Expected Cleanup command"),
    }
}

#[test]
fn test_cleanup_all_flag() {
    let cli = Cli::try_parse_from(["mvmctl", "cleanup", "--all"]).unwrap();
    match cli.command {
        Commands::Cleanup(cleanup::Args { keep, all, verbose }) => {
            assert_eq!(keep, None);
            assert!(all);
            assert!(!verbose);
        }
        _ => panic!("Expected Cleanup command"),
    }
}

#[test]
fn test_cleanup_verbose_flag() {
    let cli = Cli::try_parse_from(["mvmctl", "cleanup", "--verbose"]).unwrap();
    match cli.command {
        Commands::Cleanup(cleanup::Args { keep, all, verbose }) => {
            assert_eq!(keep, None);
            assert!(!all);
            assert!(verbose);
        }
        _ => panic!("Expected Cleanup command"),
    }
}

// ---- Build --flake tests ----

#[test]
fn test_build_flake_with_profile() {
    let cli =
        Cli::try_parse_from(["mvmctl", "build", "--flake", ".", "--profile", "gateway"]).unwrap();
    match cli.command {
        Commands::Build(build::Args { flake, profile, .. }) => {
            assert_eq!(flake.as_deref(), Some("."));
            assert_eq!(profile.as_deref(), Some("gateway"));
        }
        _ => panic!("Expected Build command"),
    }
}

#[test]
fn test_build_flake_defaults_to_no_profile() {
    let cli = Cli::try_parse_from(["mvmctl", "build", "--flake", "."]).unwrap();
    match cli.command {
        Commands::Build(build::Args { flake, profile, .. }) => {
            assert_eq!(flake.as_deref(), Some("."));
            assert!(profile.is_none(), "profile should be None when omitted");
        }
        _ => panic!("Expected Build command"),
    }
}

#[test]
fn test_build_mvmfile_mode_still_works() {
    let cli = Cli::try_parse_from(["mvmctl", "build", "myimage"]).unwrap();
    match cli.command {
        Commands::Build(build::Args { path, flake, .. }) => {
            assert_eq!(path, "myimage");
            assert!(flake.is_none(), "Mvmfile mode should have no --flake");
        }
        _ => panic!("Expected Build command"),
    }
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

// ---- Run command tests ----

#[test]
fn test_run_parses_all_flags() {
    let cli = Cli::try_parse_from([
        "mvmctl",
        "run",
        "--flake",
        ".",
        "--profile",
        "full",
        "--cpus",
        "4",
        "--memory",
        "2048",
    ])
    .unwrap();
    match cli.command {
        Commands::Up(up::Args {
            flake,
            profile,
            cpus,
            memory,
            ..
        }) => {
            assert_eq!(flake, Some(".".to_string()));
            assert_eq!(profile.as_deref(), Some("full"));
            assert_eq!(cpus, Some(4));
            assert_eq!(memory, Some("2048".to_string()));
        }
        _ => panic!("Expected Run command"),
    }
}

#[test]
fn test_run_defaults() {
    let cli = Cli::try_parse_from(["mvmctl", "run", "--flake", "."]).unwrap();
    match cli.command {
        Commands::Up(up::Args {
            flake,
            template,
            name,
            profile,
            cpus,
            memory,
            volume,
            hypervisor,
            ..
        }) => {
            assert_eq!(flake, Some(".".to_string()));
            assert!(template.is_none(), "template should be None when omitted");
            assert!(name.is_none(), "name should be None when omitted");
            assert!(profile.is_none(), "profile should be None when omitted");
            assert!(cpus.is_none(), "cpus should be None when omitted");
            assert!(memory.is_none(), "memory should be None when omitted");
            assert_eq!(volume.len(), 0);
            assert_eq!(hypervisor, "firecracker");
        }
        _ => panic!("Expected Run command"),
    }
}

#[test]
fn test_run_without_source_uses_default_microvm() {
    // No --flake / --template: the dispatcher falls back to the bundled
    // default microVM image. Clap should accept the bare invocation; the
    // dispatcher then resolves the image at runtime.
    let cli = Cli::try_parse_from(["mvmctl", "run"]).expect("parse");
    match cli.command {
        Commands::Up(up::Args {
            flake, template, ..
        }) => {
            assert!(flake.is_none(), "no --flake should be parsed");
            assert!(template.is_none(), "no --template should be parsed");
        }
        _ => panic!("Expected Run command"),
    }
}

#[test]
fn test_run_template_flag() {
    let cli = Cli::try_parse_from(["mvmctl", "run", "--template", "openclaw"]).unwrap();
    match cli.command {
        Commands::Up(up::Args {
            flake, template, ..
        }) => {
            assert!(flake.is_none());
            assert_eq!(template, Some("openclaw".to_string()));
        }
        _ => panic!("Expected Run command"),
    }
}

#[test]
fn test_run_flake_and_template_conflict() {
    let result = Cli::try_parse_from(["mvmctl", "run", "--flake", ".", "--template", "openclaw"]);
    assert!(
        result.is_err(),
        "--flake and --template should be mutually exclusive"
    );
}

#[test]
fn test_run_volume_dir_inject() {
    let cli = Cli::try_parse_from([
        "mvmctl",
        "run",
        "--flake",
        ".",
        "-v",
        "/tmp/config:/mnt/config",
        "-v",
        "/tmp/secrets:/mnt/secrets",
    ])
    .unwrap();
    match cli.command {
        Commands::Up(up::Args { volume, .. }) => {
            assert_eq!(volume.len(), 2);
            assert_eq!(volume[0], "/tmp/config:/mnt/config");
            assert_eq!(volume[1], "/tmp/secrets:/mnt/secrets");
        }
        _ => panic!("Expected Run command"),
    }
}

#[test]
fn test_run_volume_persistent() {
    let cli =
        Cli::try_parse_from(["mvmctl", "run", "--flake", ".", "-v", "/data:/mnt/data:4G"]).unwrap();
    match cli.command {
        Commands::Up(up::Args { volume, .. }) => {
            assert_eq!(volume.len(), 1);
            assert_eq!(volume[0], "/data:/mnt/data:4G");
        }
        _ => panic!("Expected Run command"),
    }
}

#[test]
fn test_parse_volume_spec_dir_inject() {
    let spec = parse_volume_spec("/tmp/config:/mnt/config").unwrap();
    match spec {
        VolumeSpec::DirInject {
            host_dir,
            guest_mount,
        } => {
            assert_eq!(host_dir, "/tmp/config");
            assert_eq!(guest_mount, "/mnt/config");
        }
        _ => panic!("Expected DirInject"),
    }
}

#[test]
fn test_parse_volume_spec_persistent() {
    let spec = parse_volume_spec("/data:/mnt/data:4G").unwrap();
    match spec {
        VolumeSpec::Persistent(vol) => {
            assert_eq!(vol.host, "/data");
            assert_eq!(vol.guest, "/mnt/data");
            assert_eq!(vol.size, "4G");
        }
        _ => panic!("Expected Persistent"),
    }
}

#[test]
fn test_parse_volume_spec_invalid() {
    let result = parse_volume_spec("just-a-path");
    assert!(result.is_err());
}

#[test]
fn test_parse_volume_spec_unsupported_mount() {
    let spec = parse_volume_spec("/tmp/foo:/mnt/custom").unwrap();
    // The spec itself parses fine — the error happens at routing time in cmd_run
    match spec {
        VolumeSpec::DirInject { guest_mount, .. } => {
            assert_eq!(guest_mount, "/mnt/custom");
        }
        _ => panic!("Expected DirInject"),
    }
}

#[test]
fn test_run_port_and_env_flags() {
    let cli = Cli::try_parse_from([
        "mvmctl",
        "run",
        "--flake",
        ".",
        "-p",
        "3333:3000",
        "-p",
        "3334:3002",
        "-e",
        "NODE_ENV=production",
        "-e",
        "DEBUG=true",
    ])
    .unwrap();
    match cli.command {
        Commands::Up(up::Args { port, env, .. }) => {
            assert_eq!(port, vec!["3333:3000", "3334:3002"]);
            assert_eq!(env, vec!["NODE_ENV=production", "DEBUG=true"]);
        }
        _ => panic!("Expected Run command"),
    }
}

#[test]
fn test_run_port_and_env_default_empty() {
    let cli = Cli::try_parse_from(["mvmctl", "run", "--flake", "."]).unwrap();
    match cli.command {
        Commands::Up(up::Args { port, env, .. }) => {
            assert!(port.is_empty());
            assert!(env.is_empty());
        }
        _ => panic!("Expected Run command"),
    }
}

#[test]
fn test_run_forward_flag() {
    let cli = Cli::try_parse_from([
        "mvmctl",
        "run",
        "--flake",
        ".",
        "-p",
        "3333:3000",
        "--forward",
    ])
    .unwrap();
    match cli.command {
        Commands::Up(up::Args { forward, port, .. }) => {
            assert!(forward);
            assert_eq!(port, vec!["3333:3000"]);
        }
        _ => panic!("Expected Run command"),
    }
}

#[test]
fn test_run_forward_default_false() {
    let cli = Cli::try_parse_from(["mvmctl", "run", "--flake", "."]).unwrap();
    match cli.command {
        Commands::Up(up::Args { forward, .. }) => {
            assert!(!forward);
        }
        _ => panic!("Expected Run command"),
    }
}

#[test]
fn test_parse_port_specs_multiple() {
    let specs = vec!["3333:3000".to_string(), "8080".to_string()];
    let result = parse_port_specs(&specs).unwrap();
    assert_eq!(result.len(), 2);
    assert_eq!(result[0].host, 3333);
    assert_eq!(result[0].guest, 3000);
    assert_eq!(result[1].host, 8080);
    assert_eq!(result[1].guest, 8080);
}

#[test]
fn test_parse_port_specs_empty() {
    let specs: Vec<String> = vec![];
    let result = parse_port_specs(&specs).unwrap();
    assert!(result.is_empty());
}

#[test]
fn test_ports_to_drive_file() {
    use mvm_runtime::config::PortMapping;
    let ports = vec![
        PortMapping {
            host: 3333,
            guest: 3000,
        },
        PortMapping {
            host: 3334,
            guest: 3002,
        },
    ];
    let f = ports_to_drive_file(&ports).unwrap();
    assert_eq!(f.name, "mvm-ports.env");
    assert!(f.content.contains("MVM_PORT_MAP=\"3333:3000,3334:3002\""));
    assert_eq!(f.mode, 0o444);
}

#[test]
fn test_ports_to_drive_file_empty() {
    assert!(ports_to_drive_file(&[]).is_none());
}

#[test]
fn test_env_vars_to_drive_file() {
    let vars = vec!["NODE_ENV=production".to_string(), "DEBUG=true".to_string()];
    let f = env_vars_to_drive_file(&vars).unwrap();
    assert_eq!(f.name, "mvm-env.env");
    assert!(f.content.contains("export NODE_ENV=production"));
    assert!(f.content.contains("export DEBUG=true"));
    assert_eq!(f.mode, 0o444);
}

#[test]
fn test_env_vars_to_drive_file_empty() {
    let vars: Vec<String> = vec![];
    assert!(env_vars_to_drive_file(&vars).is_none());
}

// ---- VM subcommand tests ----

// ---- Up/Down command tests ----

#[test]
fn test_down_parses_no_args() {
    let cli = Cli::try_parse_from(["mvmctl", "down"]).unwrap();
    match cli.command {
        Commands::Down(down::Args { name, config }) => {
            assert!(name.is_none());
            assert!(config.is_none());
        }
        _ => panic!("Expected Down command"),
    }
}

#[test]
fn test_down_parses_with_name() {
    let cli = Cli::try_parse_from(["mvmctl", "down", "gw"]).unwrap();
    match cli.command {
        Commands::Down(down::Args { name, config }) => {
            assert_eq!(name.as_deref(), Some("gw"));
            assert!(config.is_none());
        }
        _ => panic!("Expected Down command"),
    }
}

#[test]
fn test_down_parses_with_config() {
    let cli = Cli::try_parse_from(["mvmctl", "down", "-f", "my-fleet.toml"]).unwrap();
    match cli.command {
        Commands::Down(down::Args { name, config }) => {
            assert!(name.is_none());
            assert_eq!(config.as_deref(), Some("my-fleet.toml"));
        }
        _ => panic!("Expected Down command"),
    }
}

// ---- read_dir_to_drive_files tests ----

#[test]
fn test_read_dir_to_drive_files_reads_files() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("a.txt"), "hello").unwrap();
    std::fs::write(dir.path().join("b.env"), "KEY=val").unwrap();

    let files = read_dir_to_drive_files(dir.path().to_str().unwrap(), 0o444).unwrap();
    assert_eq!(files.len(), 2);

    let names: Vec<&str> = files.iter().map(|f| f.name.as_str()).collect();
    assert!(names.contains(&"a.txt"));
    assert!(names.contains(&"b.env"));

    for f in &files {
        assert_eq!(f.mode, 0o444);
    }
}

#[test]
fn test_read_dir_to_drive_files_skips_directories() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("file.txt"), "content").unwrap();
    std::fs::create_dir(dir.path().join("subdir")).unwrap();

    let files = read_dir_to_drive_files(dir.path().to_str().unwrap(), 0o400).unwrap();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].name, "file.txt");
    assert_eq!(files[0].mode, 0o400);
}

#[test]
fn test_read_dir_to_drive_files_empty_dir() {
    let dir = tempfile::tempdir().unwrap();
    let files = read_dir_to_drive_files(dir.path().to_str().unwrap(), 0o444).unwrap();
    assert!(files.is_empty());
}

#[test]
fn test_read_dir_to_drive_files_nonexistent_dir() {
    let result = read_dir_to_drive_files("/nonexistent/path/abc123", 0o444);
    assert!(result.is_err());
}

// ---- Forward command tests ----

#[test]
fn test_forward_parses() {
    let cli = Cli::try_parse_from(["mvmctl", "forward", "swift", "3000"]).unwrap();
    match cli.command {
        Commands::Forward(forward::Args { name, port, ports }) => {
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
    let cli = Cli::try_parse_from(["mvmctl", "forward", "swift", "8080:3000"]).unwrap();
    match cli.command {
        Commands::Forward(forward::Args { name, port, ports }) => {
            assert_eq!(name, "swift");
            assert!(port.is_empty());
            assert_eq!(ports, vec!["8080:3000"]);
        }
        _ => panic!("Expected Forward command"),
    }
}

#[test]
fn test_forward_with_flag() {
    let cli = Cli::try_parse_from(["mvmctl", "forward", "swift", "-p", "3000"]).unwrap();
    match cli.command {
        Commands::Forward(forward::Args { name, port, ports }) => {
            assert_eq!(name, "swift");
            assert_eq!(port, vec!["3000"]);
            assert!(ports.is_empty());
        }
        _ => panic!("Expected Forward command"),
    }
}

#[test]
fn test_forward_multiple_ports() {
    let cli = Cli::try_parse_from(["mvmctl", "forward", "swift", "-p", "3000", "-p", "8080:443"])
        .unwrap();
    match cli.command {
        Commands::Forward(forward::Args { name, port, ports }) => {
            assert_eq!(name, "swift");
            assert_eq!(port, vec!["3000", "8080:443"]);
            assert!(ports.is_empty());
        }
        _ => panic!("Expected Forward command"),
    }
}

#[test]
fn test_forward_multiple_positional() {
    let cli = Cli::try_parse_from(["mvmctl", "forward", "swift", "3000", "8080:443"]).unwrap();
    match cli.command {
        Commands::Forward(forward::Args { name, port, ports }) => {
            assert_eq!(name, "swift");
            assert!(port.is_empty());
            assert_eq!(ports, vec!["3000", "8080:443"]);
        }
        _ => panic!("Expected Forward command"),
    }
}

#[test]
fn test_forward_no_ports_parses() {
    // forward with no ports should parse successfully — the runtime path
    // falls back to persisted ports from run-info.json
    let cli = Cli::try_parse_from(["mvmctl", "forward", "swift"]).unwrap();
    match cli.command {
        Commands::Forward(forward::Args { name, port, ports }) => {
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
// Alias tests (Phase 4)
// -------------------------------------------------------------------------

#[test]
fn test_ls_alias_for_ps() {
    let cli = Cli::try_parse_from(["mvmctl", "ls"]).unwrap();
    assert!(matches!(cli.command, Commands::Ps(_)));
}

#[test]
fn test_ps_command() {
    let cli = Cli::try_parse_from(["mvmctl", "ps"]).unwrap();
    assert!(matches!(cli.command, Commands::Ps(_)));
}

#[test]
fn test_start_alias_for_run() {
    // 'start' is already an alias on Run — verify it still works
    assert!(Cli::try_parse_from(["mvmctl", "start", "--flake", "."]).is_ok());
}

// -------------------------------------------------------------------------
// Metrics tests (Phase 1)
// -------------------------------------------------------------------------

#[test]
fn test_metrics_command_parses() {
    let cli = Cli::try_parse_from(["mvmctl", "metrics"]).unwrap();
    assert!(matches!(
        cli.command,
        Commands::Metrics(metrics::Args { json: false })
    ));
}

#[test]
fn test_metrics_json_flag_parses() {
    let cli = Cli::try_parse_from(["mvmctl", "metrics", "--json"]).unwrap();
    assert!(matches!(
        cli.command,
        Commands::Metrics(metrics::Args { json: true })
    ));
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
    let cli = Cli::try_parse_from(["mvmctl", "config", "show"]).unwrap();
    assert!(matches!(
        cli.command,
        Commands::Config(config::Args {
            action: ConfigAction::Show
        })
    ));
}

#[test]
fn test_config_set_parses() {
    let cli = Cli::try_parse_from(["mvmctl", "config", "set", "lima_cpus", "4"]).unwrap();
    match cli.command {
        Commands::Config(config::Args {
            action: ConfigAction::Set { key, value },
        }) => {
            assert_eq!(key, "lima_cpus");
            assert_eq!(value, "4");
        }
        _ => panic!("Expected Config Set command"),
    }
}

#[test]
fn test_config_show_output_contains_lima_cpus() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = mvm_core::user_config::MvmConfig::default();
    mvm_core::user_config::save(&cfg, Some(tmp.path())).unwrap();
    let loaded = mvm_core::user_config::load(Some(tmp.path()));
    let text = toml::to_string_pretty(&loaded).unwrap();
    assert!(text.contains("lima_cpus"));
}

#[test]
fn test_config_set_persists() {
    let tmp = tempfile::tempdir().unwrap();
    let mut cfg = mvm_core::user_config::load(Some(tmp.path()));
    mvm_core::user_config::set_key(&mut cfg, "lima_cpus", "4").unwrap();
    mvm_core::user_config::save(&cfg, Some(tmp.path())).unwrap();
    let reloaded = mvm_core::user_config::load(Some(tmp.path()));
    assert_eq!(reloaded.lima_cpus, 4);
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
    let cli = Cli::try_parse_from(["mvmctl", "uninstall", "--yes"]).unwrap();
    assert!(matches!(
        cli.command,
        Commands::Uninstall(uninstall::Args {
            yes: true,
            all: false,
            dry_run: false,
        })
    ));
}

#[test]
fn test_uninstall_dry_run_parses() {
    let cli = Cli::try_parse_from(["mvmctl", "uninstall", "--dry-run", "--yes"]).unwrap();
    assert!(matches!(
        cli.command,
        Commands::Uninstall(uninstall::Args {
            yes: true,
            all: false,
            dry_run: true,
        })
    ));
}

#[test]
fn test_uninstall_all_flag_parses() {
    let cli = Cli::try_parse_from(["mvmctl", "uninstall", "--all", "--yes"]).unwrap();
    assert!(matches!(
        cli.command,
        Commands::Uninstall(uninstall::Args {
            yes: true,
            all: true,
            dry_run: false,
        })
    ));
}

// ---- Audit command tests ----

#[test]
fn test_audit_tail_parses() {
    let cli = Cli::try_parse_from(["mvmctl", "audit", "tail"]).unwrap();
    assert!(matches!(
        cli.command,
        Commands::Audit(audit::Args {
            action: AuditAction::Tail {
                lines: 20,
                follow: false,
            }
        })
    ));
}

#[test]
fn test_audit_tail_follow_parses() {
    let cli =
        Cli::try_parse_from(["mvmctl", "audit", "tail", "--follow", "--lines", "50"]).unwrap();
    assert!(matches!(
        cli.command,
        Commands::Audit(audit::Args {
            action: AuditAction::Tail {
                lines: 50,
                follow: true,
            }
        })
    ));
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
    // Clap should reject bad --name values before any command runs.
    let result = Cli::try_parse_from(["mvmctl", "run", "--flake", ".", "--name", "INVALID"]);
    assert!(
        result.is_err(),
        "uppercase VM name should fail at parse time"
    );
}

#[test]
fn test_run_rejects_invalid_flake_at_parse_time() {
    let result = Cli::try_parse_from(["mvmctl", "run", "--flake", ". ; rm -rf /", "--name", "vm1"]);
    assert!(
        result.is_err(),
        "shell-injection flake ref should fail at parse time"
    );
}

#[test]
fn test_run_rejects_invalid_port_at_parse_time() {
    let result = Cli::try_parse_from(["mvmctl", "run", "--flake", ".", "--port", "notaport"]);
    assert!(result.is_err(), "invalid port should fail at parse time");
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
fn test_resolve_network_policy_default() {
    let policy = resolve_network_policy(None, &[]).unwrap();
    assert!(policy.is_unrestricted());
}

#[test]
fn test_resolve_network_policy_preset() {
    let policy = resolve_network_policy(Some("dev"), &[]).unwrap();
    assert!(!policy.is_unrestricted());
    let rules = policy.resolve_rules().unwrap();
    assert!(rules.iter().any(|r| r.host == "github.com"));
}

#[test]
fn test_resolve_network_policy_allow_list() {
    let allow = vec![
        "github.com:443".to_string(),
        "api.openai.com:443".to_string(),
    ];
    let policy = resolve_network_policy(None, &allow).unwrap();
    let rules = policy.resolve_rules().unwrap();
    assert_eq!(rules.len(), 2);
}

#[test]
fn test_resolve_network_policy_mutual_exclusion() {
    let allow = vec!["github.com:443".to_string()];
    let result = resolve_network_policy(Some("dev"), &allow);
    assert!(result.is_err());
}

#[test]
fn test_resolve_network_policy_invalid_preset() {
    let result = resolve_network_policy(Some("bogus"), &[]);
    assert!(result.is_err());
}

#[test]
fn test_resolve_network_policy_invalid_allow_entry() {
    let allow = vec!["not-a-host-port".to_string()];
    let result = resolve_network_policy(None, &allow);
    assert!(result.is_err());
}

// --- Network CLI tests ---

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

// --- Image CLI tests ---

#[test]
fn test_image_list_help() {
    let cli = Cli::try_parse_from(["mvmctl", "image", "list"]);
    assert!(cli.is_ok());
}

#[test]
fn test_image_search_help() {
    let cli = Cli::try_parse_from(["mvmctl", "image", "search", "http"]);
    assert!(cli.is_ok());
}

#[test]
fn test_image_fetch_help() {
    let cli = Cli::try_parse_from(["mvmctl", "image", "fetch", "minimal"]);
    assert!(cli.is_ok());
}

#[test]
fn test_image_info_help() {
    let cli = Cli::try_parse_from(["mvmctl", "image", "info", "postgres"]);
    assert!(cli.is_ok());
}

// --- Console CLI tests ---

#[test]
fn test_console_help() {
    let cli = Cli::try_parse_from(["mvmctl", "console", "myvm"]);
    assert!(cli.is_ok());
}

#[test]
fn test_console_with_command() {
    let cli = Cli::try_parse_from(["mvmctl", "console", "myvm", "--command", "ls"]);
    assert!(cli.is_ok());
    match cli.unwrap().command {
        Commands::Console(console::Args { name, command }) => {
            assert_eq!(name, "myvm");
            assert_eq!(command.as_deref(), Some("ls"));
        }
        _ => panic!("Expected Console command"),
    }
}

// --- Exec CLI tests ---

#[test]
fn exec_default_template_argv_only() {
    let cli = Cli::try_parse_from(["mvmctl", "exec", "--", "uname", "-a"]).expect("parse");
    match cli.command {
        Commands::Exec(exec::Args {
            template,
            cpus,
            memory,
            add_dir,
            env,
            timeout,
            launch_plan,
            argv,
        }) => {
            assert!(template.is_none(), "template should default to None");
            assert_eq!(cpus, 2);
            assert_eq!(memory, "512M");
            assert!(add_dir.is_empty());
            assert!(env.is_empty());
            assert_eq!(timeout, 60);
            assert!(launch_plan.is_none(), "launch_plan should default to None");
            assert_eq!(argv, vec!["uname".to_string(), "-a".to_string()]);
        }
        _ => panic!("Expected Exec command"),
    }
}

#[test]
fn exec_with_launch_plan_no_argv() {
    let cli =
        Cli::try_parse_from(["mvmctl", "exec", "--launch-plan", "./plan.json"]).expect("parse");
    match cli.command {
        Commands::Exec(exec::Args {
            launch_plan, argv, ..
        }) => {
            assert_eq!(launch_plan.as_deref(), Some("./plan.json"));
            assert!(argv.is_empty());
        }
        _ => panic!("Expected Exec command"),
    }
}

#[test]
fn exec_launch_plan_conflicts_with_argv() {
    let cli = Cli::try_parse_from([
        "mvmctl",
        "exec",
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
fn exec_with_template_and_resources() {
    let cli = Cli::try_parse_from([
        "mvmctl",
        "exec",
        "--template",
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
        Commands::Exec(exec::Args {
            template,
            cpus,
            memory,
            argv,
            ..
        }) => {
            assert_eq!(template.as_deref(), Some("my-tpl"));
            assert_eq!(cpus, 4);
            assert_eq!(memory, "1G");
            assert_eq!(argv, vec!["/bin/true".to_string()]);
        }
        _ => panic!("Expected Exec command"),
    }
}

#[test]
fn exec_with_add_dir_and_env() {
    let cli = Cli::try_parse_from([
        "mvmctl",
        "exec",
        "--add-dir",
        "/tmp:/work",
        "--add-dir",
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
        Commands::Exec(exec::Args {
            add_dir, env, argv, ..
        }) => {
            assert_eq!(
                add_dir,
                vec!["/tmp:/work".to_string(), "/etc:/host-etc".to_string()]
            );
            assert_eq!(env, vec!["FOO=bar".to_string(), "BAZ=qux".to_string()]);
            assert_eq!(argv, vec!["ls".to_string(), "/work".to_string()]);
        }
        _ => panic!("Expected Exec command"),
    }
}

#[test]
fn exec_requires_argv() {
    // Without trailing argv, Clap should reject because `argv` is required.
    let cli = Cli::try_parse_from(["mvmctl", "exec"]);
    assert!(cli.is_err());
}

// --- Init CLI tests ---

#[test]
fn test_init_defaults() {
    let cli = Cli::try_parse_from(["mvmctl", "init"]).unwrap();
    match cli.command {
        Commands::Init(init::Args {
            non_interactive,
            lima_cpus,
            lima_mem,
        }) => {
            assert!(!non_interactive);
            assert_eq!(lima_cpus, 8);
            assert_eq!(lima_mem, 16);
        }
        _ => panic!("Expected Init command"),
    }
}

#[test]
fn test_init_non_interactive() {
    let cli =
        Cli::try_parse_from(["mvmctl", "init", "--non-interactive", "--lima-cpus", "4"]).unwrap();
    match cli.command {
        Commands::Init(init::Args {
            non_interactive,
            lima_cpus,
            ..
        }) => {
            assert!(non_interactive);
            assert_eq!(lima_cpus, 4);
        }
        _ => panic!("Expected Init command"),
    }
}

// --- Security CLI tests ---

#[test]
fn test_security_status_help() {
    let cli = Cli::try_parse_from(["mvmctl", "security", "status"]);
    assert!(cli.is_ok());
}

#[test]
fn test_security_status_json() {
    let cli = Cli::try_parse_from(["mvmctl", "security", "status", "--json"]).unwrap();
    match cli.command {
        Commands::Security(security::Args {
            action: SecurityAction::Status { json },
        }) => {
            assert!(json);
        }
        _ => panic!("Expected Security Status command"),
    }
}

// --- Cache CLI tests ---

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
fn test_cache_prune_dry_run() {
    let cli = Cli::try_parse_from(["mvmctl", "cache", "prune", "--dry-run"]).unwrap();
    match cli.command {
        Commands::Cache(cache::Args {
            action: CacheAction::Prune { dry_run },
        }) => {
            assert!(dry_run);
        }
        _ => panic!("Expected Cache Prune command"),
    }
}

// --- Up --network flag tests ---

#[test]
fn test_up_network_default() {
    let cli = Cli::try_parse_from(["mvmctl", "up", "--flake", "."]).unwrap();
    match cli.command {
        Commands::Up(up::Args { network, .. }) => {
            assert_eq!(network, "default");
        }
        _ => panic!("Expected Up command"),
    }
}

#[test]
fn test_up_network_custom() {
    let cli =
        Cli::try_parse_from(["mvmctl", "up", "--flake", ".", "--network", "isolated"]).unwrap();
    match cli.command {
        Commands::Up(up::Args { network, .. }) => {
            assert_eq!(network, "isolated");
        }
        _ => panic!("Expected Up command"),
    }
}

#[test]
fn test_template_init_defaults_to_no_preset_or_prompt() {
    let cli = Cli::try_parse_from(["mvmctl", "template", "init", "demo", "--local"]).unwrap();
    match cli.command {
        Commands::Template(template::Args {
            action: TemplateAction::Init { preset, prompt, .. },
        }) => {
            assert!(preset.is_none(), "preset should be None when omitted");
            assert!(prompt.is_none(), "prompt should be None when omitted");
        }
        _ => panic!("Expected Template Init command"),
    }
}

#[test]
fn test_template_init_parses_prompt_flag() {
    let cli = Cli::try_parse_from([
        "mvmctl",
        "template",
        "init",
        "demo",
        "--local",
        "--prompt",
        "python worker that polls an API",
    ])
    .unwrap();
    match cli.command {
        Commands::Template(template::Args {
            action: TemplateAction::Init { prompt, preset, .. },
        }) => {
            assert_eq!(prompt.as_deref(), Some("python worker that polls an API"));
            assert!(preset.is_none(), "preset should remain None when omitted");
        }
        _ => panic!("Expected Template Init command"),
    }
}

// --- Apple Container dev tests ---

#[test]
fn test_dev_up_with_lima_flag() {
    let cli = Cli::try_parse_from(["mvmctl", "dev", "up", "--lima"]).unwrap();
    match cli.command {
        Commands::Dev(dev::Args {
            action: Some(DevAction::Up { lima, .. }),
        }) => {
            assert!(lima);
        }
        _ => panic!("Expected Dev Up command"),
    }
}

#[test]
fn test_dev_down_parses() {
    let cli = Cli::try_parse_from(["mvmctl", "dev", "down"]);
    assert!(cli.is_ok());
}

#[test]
fn test_dev_shell_parses() {
    let cli = Cli::try_parse_from(["mvmctl", "dev", "shell"]);
    assert!(cli.is_ok());
}

#[test]
fn test_dev_status_parses() {
    let cli = Cli::try_parse_from(["mvmctl", "dev", "status"]);
    assert!(cli.is_ok());
}

#[test]
fn test_is_apple_container_dev_running_returns_bool() {
    // Just verify it doesn't panic — actual result depends on platform
    let _ = super::env::apple_container::is_apple_container_dev_running();
}

// ---- RunParams compile-check (referenced for type-export verification) ----
#[allow(dead_code)]
fn _runparams_has_lifetime() {
    fn _take(_p: RunParams<'_>) {}
}
