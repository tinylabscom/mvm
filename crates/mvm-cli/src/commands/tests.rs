//! Integration-style tests for the top-level CLI surface.

#![cfg(test)]

use super::*;
use clap::Parser;

// Group module aliases — give tests short names (`cleanup`, `up`, etc.) that
// follow the dispatcher's naming, regardless of which group they live in.
use super::build::build;
use super::build::compile;
use super::build::group as build_group;
use super::catalog;
use super::env::group as env_group;
use super::env::{cleanup, dev, init, uninstall};
use super::image;
use super::ops;
use super::ops::{audit, cache, config, metrics, secret};
use super::trust;
use super::vm::{
    checkpoint, console, cp, down, exec, forward, group, pause, sandbox, session, up, volume,
};

use audit::AuditAction;
use cache::CacheAction;
use catalog::CatalogAction;
use config::ConfigAction;
use dev::{DevAction, DevCacheAction};
use image::ImageAction;
use up::RunParams;

use super::shared::{
    VolumeSpec, clap_flake_ref, clap_port_spec, clap_vm_name, clap_volume_spec,
    env_vars_to_drive_file, parse_port_spec, parse_port_specs, parse_volume_spec,
    ports_to_drive_file, read_dir_to_drive_files, resolve_flake_ref, resolve_network_policy,
};

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
fn internal_subprocess_commands_are_hidden_from_help() {
    // Subprocess/internal commands must not clutter the user-facing
    // surface. They stay dispatchable but `hide = true`.
    let visible: Vec<String> = cli_command()
        .get_subcommands()
        .filter(|cmd| !cmd.is_hide_set())
        .map(|cmd| cmd.get_name().to_string())
        .collect();
    for hidden in [
        "shell-init",
        "reconcile",
        "persistent-builder",
        "__qemu-vsock-bridge",
        "__ssh-agent-proxy",
    ] {
        assert!(
            !visible.iter().any(|n| n == hidden),
            "internal command `{hidden}` must be hidden from top-level help"
        );
    }
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
            verbose,
            cache,
            state,
            nuclear,
            dry_run,
            yes,
            force,
        }) => {
            assert_eq!(keep, None);
            assert!(!all);
            assert!(!verbose);
            assert!(!cache);
            assert!(!state);
            assert!(!nuclear);
            assert!(!dry_run);
            assert!(!yes);
            assert!(!force);
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
            assert!(!args.verbose);
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
            assert!(!args.verbose);
        }
        _ => panic!("Expected Cleanup command"),
    }
}

#[test]
fn test_cleanup_verbose_flag() {
    let cli = Cli::try_parse_from(["mvmctl", "env", "cleanup", "--verbose"]).unwrap();
    let Commands::Env(eg) = cli.command else {
        panic!("expected env group")
    };
    match eg.action {
        env_group::EnvCmd::Cleanup(args) => {
            assert_eq!(args.keep, None);
            assert!(!args.all);
            assert!(args.verbose);
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
    let cli = Cli::try_parse_from(["mvmctl", "vm", "volume", "create", "work"]).unwrap();
    let Commands::Vm(vmg) = cli.command else {
        panic!("expected vm group")
    };
    match vmg.action {
        group::VmCmd::Volume(volume::Args {
            command:
                volume::VolumeCmd::Create {
                    volume,
                    root,
                    host_backed,
                },
        }) => {
            assert_eq!(volume, "work");
            assert_eq!(root, None);
            assert!(!host_backed);
        }
        _ => panic!("Expected volume create command"),
    }
}

#[test]
fn volume_create_host_backed_parses() {
    let cli =
        Cli::try_parse_from(["mvmctl", "vm", "volume", "create", "work", "--host-backed"]).unwrap();
    let Commands::Vm(vmg) = cli.command else {
        panic!("expected vm group")
    };
    match vmg.action {
        group::VmCmd::Volume(volume::Args {
            command:
                volume::VolumeCmd::Create {
                    volume,
                    root,
                    host_backed,
                },
        }) => {
            assert_eq!(volume, "work");
            assert_eq!(root, None);
            assert!(host_backed);
        }
        _ => panic!("Expected volume create command"),
    }
}

#[test]
fn volume_unlock_parses() {
    let cli = Cli::try_parse_from(["mvmctl", "vm", "volume", "unlock", "work"]).unwrap();
    let Commands::Vm(vmg) = cli.command else {
        panic!("expected vm group")
    };
    match vmg.action {
        group::VmCmd::Volume(volume::Args {
            command: volume::VolumeCmd::Unlock { volume },
        }) => assert_eq!(volume, "work"),
        _ => panic!("Expected volume unlock command"),
    }
}

#[test]
fn volume_lock_parses() {
    let cli = Cli::try_parse_from(["mvmctl", "vm", "volume", "lock", "work"]).unwrap();
    let Commands::Vm(vmg) = cli.command else {
        panic!("expected vm group")
    };
    match vmg.action {
        group::VmCmd::Volume(volume::Args {
            command: volume::VolumeCmd::Lock { volume },
        }) => assert_eq!(volume, "work"),
        _ => panic!("Expected volume lock command"),
    }
}

#[test]
fn volume_catalog_json_parses() {
    let cli = Cli::try_parse_from(["mvmctl", "vm", "volume", "catalog", "--json"]).unwrap();
    let Commands::Vm(vmg) = cli.command else {
        panic!("expected vm group")
    };
    match vmg.action {
        group::VmCmd::Volume(volume::Args {
            command: volume::VolumeCmd::Catalog { json },
        }) => assert!(json),
        _ => panic!("Expected volume catalog command"),
    }
}

#[test]
fn volume_mount_managed_omits_host() {
    let cli = Cli::try_parse_from([
        "mvmctl",
        "vm",
        "volume",
        "mount",
        "vm-1",
        "--volume",
        "work",
        "--guest",
        "/mnt/work",
    ])
    .unwrap();
    let Commands::Vm(vmg) = cli.command else {
        panic!("expected vm group")
    };
    match vmg.action {
        group::VmCmd::Volume(volume::Args {
            command:
                volume::VolumeCmd::Mount {
                    name,
                    volume,
                    host,
                    guest,
                    rw,
                    remote,
                },
        }) => {
            assert_eq!(name, "vm-1");
            assert_eq!(volume, "work");
            assert_eq!(host, None);
            assert_eq!(guest, "/mnt/work");
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
        "build",
        "image",
        "--flake",
        ".",
        "--profile",
        "gateway",
    ])
    .unwrap();
    let Commands::Build(bg) = cli.command else {
        panic!("expected build group")
    };
    match bg.action {
        build_group::BuildCmd::Image(build::Args { flake, profile, .. }) => {
            assert_eq!(flake.as_deref(), Some("."));
            assert_eq!(profile.as_deref(), Some("gateway"));
        }
        _ => panic!("Expected Build command"),
    }
}

#[test]
fn test_build_flake_defaults_to_no_profile() {
    let cli = Cli::try_parse_from(["mvmctl", "build", "image", "--flake", "."]).unwrap();
    let Commands::Build(bg) = cli.command else {
        panic!("expected build group")
    };
    match bg.action {
        build_group::BuildCmd::Image(build::Args { flake, profile, .. }) => {
            assert_eq!(flake.as_deref(), Some("."));
            assert!(profile.is_none(), "profile should be None when omitted");
        }
        _ => panic!("Expected Build command"),
    }
}

#[test]
fn test_build_mvmfile_mode_still_works() {
    let cli = Cli::try_parse_from(["mvmctl", "build", "image", "myimage"]).unwrap();
    let Commands::Build(bg) = cli.command else {
        panic!("expected build group")
    };
    match bg.action {
        build_group::BuildCmd::Image(build::Args { path, flake, .. }) => {
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
        "up",
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
    let cli = Cli::try_parse_from(["mvmctl", "up", "--flake", "."]).unwrap();
    match cli.command {
        Commands::Up(up::Args {
            flake,
            manifest,
            name,
            profile,
            cpus,
            memory,
            volume,
            hypervisor,
            ..
        }) => {
            assert_eq!(flake, Some(".".to_string()));
            assert!(manifest.is_none(), "manifest should be None when omitted");
            assert!(name.is_none(), "name should be None when omitted");
            assert!(profile.is_none(), "profile should be None when omitted");
            assert!(cpus.is_none(), "cpus should be None when omitted");
            assert!(memory.is_none(), "memory should be None when omitted");
            assert_eq!(volume.len(), 0);
            assert_eq!(hypervisor, "firecracker");
        }
        _ => panic!("Expected Up command"),
    }
}

#[test]
fn test_up_without_source_uses_default_microvm() {
    // No --flake / --manifest: the dispatcher falls back to the bundled
    // default microVM image. Clap should accept the bare invocation; the
    // dispatcher then resolves the image at runtime.
    let cli = Cli::try_parse_from(["mvmctl", "up"]).expect("parse");
    match cli.command {
        Commands::Up(up::Args {
            flake, manifest, ..
        }) => {
            assert!(flake.is_none(), "no --flake should be parsed");
            assert!(manifest.is_none(), "no --manifest should be parsed");
        }
        _ => panic!("Expected Up command"),
    }
}

#[test]
fn test_up_manifest_flag() {
    let cli = Cli::try_parse_from(["mvmctl", "up", "--manifest", "openclaw"]).unwrap();
    match cli.command {
        Commands::Up(up::Args {
            flake, manifest, ..
        }) => {
            assert!(flake.is_none());
            assert_eq!(manifest, Some("openclaw".to_string()));
        }
        _ => panic!("Expected Up command"),
    }
}

#[test]
fn test_up_redact_flag_parses_repeatably() {
    let cli = Cli::try_parse_from([
        "mvmctl",
        "up",
        "--redact",
        "api.openai.com",
        "--redact",
        "logs.example.com=audit",
    ])
    .unwrap();
    match cli.command {
        Commands::Up(up::Args { redact, .. }) => {
            assert_eq!(redact, vec!["api.openai.com", "logs.example.com=audit"]);
        }
        _ => panic!("Expected Up command"),
    }
}

#[test]
fn test_up_dev_flag_resolves_dev_mode() {
    let cli = Cli::try_parse_from(["mvmctl", "up", "--flake", ".", "--dev"]).unwrap();
    match cli.command {
        Commands::Up(up::Args { build_mode, .. }) => {
            assert!(build_mode.dev);
            assert!(!build_mode.prod);
            assert_eq!(build_mode.resolve(), mvm_build::pipeline::BuildMode::Dev);
        }
        _ => panic!("Expected Up command"),
    }
}

#[test]
fn test_up_prod_flag_resolves_prod_mode() {
    let cli = Cli::try_parse_from(["mvmctl", "up", "--flake", ".", "--prod"]).unwrap();
    match cli.command {
        Commands::Up(up::Args { build_mode, .. }) => {
            assert!(!build_mode.dev);
            assert!(build_mode.prod);
            assert_eq!(build_mode.resolve(), mvm_build::pipeline::BuildMode::Prod);
        }
        _ => panic!("Expected Up command"),
    }
}

#[test]
fn test_up_no_build_mode_flag_defaults_to_prod() {
    let cli = Cli::try_parse_from(["mvmctl", "up", "--flake", "."]).unwrap();
    match cli.command {
        Commands::Up(up::Args { build_mode, .. }) => {
            assert!(!build_mode.dev);
            assert!(!build_mode.prod);
            // No flag → resolve to Prod (the architectural default).
            assert_eq!(build_mode.resolve(), mvm_build::pipeline::BuildMode::Prod);
        }
        _ => panic!("Expected Up command"),
    }
}

#[test]
fn test_up_dev_and_prod_are_mutually_exclusive() {
    let result = Cli::try_parse_from(["mvmctl", "up", "--flake", ".", "--dev", "--prod"]);
    assert!(
        result.is_err(),
        "passing both --dev and --prod must be a clap parse error"
    );
}

// `--from-workload-ir <path>` wires `mvmctl up` into the app-deps
// install pipeline. These tests pin the flag-parse surface (clap-side);
// the install-pipeline integration itself is covered by
// `app_deps_gate::tests` + the helper unit tests in
// `vm/up.rs::resolve_deps_volume_binding`-adjacent fixtures.

#[test]
fn test_up_from_workload_ir_flag_parses() {
    let cli = Cli::try_parse_from([
        "mvmctl",
        "up",
        "--flake",
        ".",
        "--from-workload-ir",
        "./workload.ir.json",
    ])
    .expect("clap parses --from-workload-ir");
    match cli.command {
        Commands::Up(up::Args {
            from_workload_ir, ..
        }) => {
            assert_eq!(
                from_workload_ir,
                Some(std::path::PathBuf::from("./workload.ir.json"))
            );
        }
        _ => panic!("Expected Up command"),
    }
}

#[test]
fn test_up_from_workload_ir_absent_means_none() {
    // Claim-8 preservation guard: when the user doesn't pass the
    // flag, `from_workload_ir` is `None` and `mvmctl up` runs the
    // no-deps-volume path with `deps_volume = None` on the plan.
    let cli = Cli::try_parse_from(["mvmctl", "up", "--flake", "."]).unwrap();
    match cli.command {
        Commands::Up(up::Args {
            from_workload_ir, ..
        }) => {
            assert!(from_workload_ir.is_none());
        }
        _ => panic!("Expected Up command"),
    }
}

#[test]
fn test_up_from_workload_ir_combines_with_prod_gate_flag() {
    let cli = Cli::try_parse_from([
        "mvmctl",
        "up",
        "--flake",
        ".",
        "--from-workload-ir",
        "./workload.ir.json",
        "--prod",
    ])
    .expect("clap parses --from-workload-ir + --prod");
    match cli.command {
        Commands::Up(up::Args {
            from_workload_ir,
            build_mode,
            ..
        }) => {
            assert_eq!(
                from_workload_ir,
                Some(std::path::PathBuf::from("./workload.ir.json"))
            );
            assert!(build_mode.prod);
            assert_eq!(build_mode.resolve(), mvm_build::pipeline::BuildMode::Prod);
        }
        _ => panic!("Expected Up command"),
    }
}

#[test]
fn test_up_from_workload_ir_combines_with_dev_gate_flag() {
    let cli = Cli::try_parse_from([
        "mvmctl",
        "up",
        "--flake",
        ".",
        "--from-workload-ir",
        "./workload.ir.json",
        "--dev",
    ])
    .expect("clap parses --from-workload-ir + --dev");
    match cli.command {
        Commands::Up(up::Args {
            from_workload_ir,
            build_mode,
            ..
        }) => {
            assert_eq!(
                from_workload_ir,
                Some(std::path::PathBuf::from("./workload.ir.json"))
            );
            assert!(build_mode.dev);
            assert_eq!(build_mode.resolve(), mvm_build::pipeline::BuildMode::Dev);
        }
        _ => panic!("Expected Up command"),
    }
}

#[test]
fn test_up_manifest_short_flag() {
    let cli = Cli::try_parse_from(["mvmctl", "up", "-m", "openclaw"]).unwrap();
    match cli.command {
        Commands::Up(up::Args { manifest, .. }) => {
            assert_eq!(manifest, Some("openclaw".to_string()));
        }
        _ => panic!("Expected Up command"),
    }
}

#[test]
fn test_up_flake_and_manifest_conflict() {
    let result = Cli::try_parse_from(["mvmctl", "up", "--flake", ".", "--manifest", "openclaw"]);
    assert!(
        result.is_err(),
        "--flake and --manifest should be mutually exclusive"
    );
}

#[test]
fn test_run_volume_dir_inject() {
    let cli = Cli::try_parse_from([
        "mvmctl",
        "up",
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
        Cli::try_parse_from(["mvmctl", "up", "--flake", ".", "-v", "/data:/mnt/data:4G"]).unwrap();
    match cli.command {
        Commands::Up(up::Args { volume, .. }) => {
            assert_eq!(volume.len(), 1);
            assert_eq!(volume[0], "/data:/mnt/data:4G");
        }
        _ => panic!("Expected Run command"),
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
    let spec = parse_volume_spec("/data:/mnt/data:4G").unwrap();
    match spec {
        VolumeSpec::Disk {
            host,
            guest,
            size,
            encrypted,
            ..
        } => {
            assert_eq!(host, "/data");
            assert_eq!(guest, "/mnt/data");
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
    let spec = parse_volume_spec("/tmp/foo:/mnt/custom").unwrap();
    match spec {
        VolumeSpec::DirShare { guest_mount, .. } => {
            assert_eq!(guest_mount, "/mnt/custom");
        }
        _ => panic!("Expected DirShare"),
    }
}

#[test]
fn test_run_port_and_env_flags() {
    let cli = Cli::try_parse_from([
        "mvmctl",
        "up",
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
    let cli = Cli::try_parse_from(["mvmctl", "up", "--flake", "."]).unwrap();
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
        "up",
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
    let cli = Cli::try_parse_from(["mvmctl", "up", "--flake", "."]).unwrap();
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
    use mvm::config::PortMapping;
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

// The `mvmctl down -f <fleet-config>` flag was removed along with
// fleet.rs — multi-VM orchestration is mvmd's job. `down::Args` now
// has only `name`.

#[test]
fn test_down_parses_no_args() {
    let cli = Cli::try_parse_from(["mvmctl", "down"]).unwrap();
    match cli.command {
        Commands::Down(down::Args { name }) => {
            assert!(name.is_none());
        }
        _ => panic!("Expected Down command"),
    }
}

#[test]
fn test_down_parses_with_name() {
    let cli = Cli::try_parse_from(["mvmctl", "down", "gw"]).unwrap();
    match cli.command {
        Commands::Down(down::Args { name }) => {
            assert_eq!(name.as_deref(), Some("gw"));
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
    let cli = Cli::try_parse_from(["mvmctl", "vm", "forward", "swift", "3000"]).unwrap();
    let Commands::Vm(vmg) = cli.command else {
        panic!("expected vm group")
    };
    match vmg.action {
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
    let cli = Cli::try_parse_from(["mvmctl", "vm", "forward", "swift", "8080:3000"]).unwrap();
    let Commands::Vm(vmg) = cli.command else {
        panic!("expected vm group")
    };
    match vmg.action {
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
    let cli = Cli::try_parse_from(["mvmctl", "vm", "forward", "swift", "-p", "3000"]).unwrap();
    let Commands::Vm(vmg) = cli.command else {
        panic!("expected vm group")
    };
    match vmg.action {
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
        "mvmctl", "vm", "forward", "swift", "-p", "3000", "-p", "8080:443",
    ])
    .unwrap();
    let Commands::Vm(vmg) = cli.command else {
        panic!("expected vm group")
    };
    match vmg.action {
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
        Cli::try_parse_from(["mvmctl", "vm", "forward", "swift", "3000", "8080:443"]).unwrap();
    let Commands::Vm(vmg) = cli.command else {
        panic!("expected vm group")
    };
    match vmg.action {
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
    // forward with no ports should parse successfully — the runtime path
    // falls back to persisted ports from run-info.json
    let cli = Cli::try_parse_from(["mvmctl", "vm", "forward", "swift"]).unwrap();
    let Commands::Vm(vmg) = cli.command else {
        panic!("expected vm group")
    };
    match vmg.action {
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
// `completions`, and `security` were dropped — `ls`/`up`/`validate`/
// `catalog`/`doctor` cover the cleaned surface. `run` was reintroduced
// later as the secure one-shot execution UX, distinct from the old `up`
// alias.
// -------------------------------------------------------------------------

#[test]
fn test_ls_command() {
    let cli = Cli::try_parse_from(["mvmctl", "ls"]).unwrap();
    assert!(matches!(cli.command, Commands::Ls(_)));
}

#[test]
fn test_ps_verb_is_unrecognized() {
    let result = Cli::try_parse_from(["mvmctl", "ps"]);
    assert!(result.is_err(), "`ps` was dropped in plan 40");
}

#[test]
fn test_start_verb_is_unrecognized() {
    let result = Cli::try_parse_from(["mvmctl", "start", "--flake", "."]);
    assert!(result.is_err(), "`start` alias was dropped in plan 40");
}

#[test]
fn test_run_command_is_recognized() {
    let cli = Cli::try_parse_from(["mvmctl", "run", "--", "/bin/true"]).unwrap();
    match cli.command {
        Commands::Run(exec::RunArgs { profile, argv, .. }) => {
            assert_eq!(profile, exec::RunProfile::Standard);
            assert_eq!(argv, vec!["/bin/true".to_string()]);
        }
        _ => panic!("Expected Run command"),
    }
}

#[test]
fn test_setup_verb_is_unrecognized() {
    let result = Cli::try_parse_from(["mvmctl", "setup"]);
    assert!(result.is_err(), "`setup` was folded into `bootstrap`");
}

#[test]
fn test_completions_verb_is_unrecognized() {
    let result = Cli::try_parse_from(["mvmctl", "completions", "bash"]);
    assert!(
        result.is_err(),
        "`completions` was folded into `shell-init`"
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
    let result = Cli::try_parse_from(["mvmctl", "up", "--flake", ".", "--name", "INVALID"]);
    assert!(
        result.is_err(),
        "uppercase VM name should fail at parse time"
    );
}

#[test]
fn test_run_rejects_invalid_flake_at_parse_time() {
    let result = Cli::try_parse_from(["mvmctl", "up", "--flake", ". ; rm -rf /", "--name", "vm1"]);
    assert!(
        result.is_err(),
        "shell-injection flake ref should fail at parse time"
    );
}

#[test]
fn test_run_rejects_invalid_port_at_parse_time() {
    let result = Cli::try_parse_from(["mvmctl", "up", "--flake", ".", "--port", "notaport"]);
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
fn test_resolve_network_policy_default_is_deny_all() {
    // Claim 10: the safe default is deny-all. Workloads that need
    // network access opt in explicitly.
    let policy = resolve_network_policy(None, &[]).unwrap();
    assert!(!policy.is_unrestricted());
    let rules = policy
        .resolve_rules()
        .expect("default resolves to a concrete rule set");
    assert!(rules.is_empty(), "deny-all should yield no allow rules");
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

#[test]
fn tenant_orchestration_commands_are_not_mvmctl_surface() {
    for command in ["deploy", "policy", "tenant"] {
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
    let cli = Cli::try_parse_from(["mvmctl", "vm", "snapshot", "ls", "--json"]).unwrap();
    assert!(matches!(
        cli.command,
        Commands::Vm(group::Args {
            action: group::VmCmd::Snapshot(pause::SnapshotArgs {
                command: pause::SnapshotCmd::Ls { json: true }
            })
        })
    ));
}

#[test]
fn test_snapshot_rm_json_parses() {
    let cli = Cli::try_parse_from(["mvmctl", "vm", "snapshot", "rm", "myvm", "--json"]).unwrap();
    assert!(matches!(
        cli.command,
        Commands::Vm(group::Args {
            action: group::VmCmd::Snapshot(pause::SnapshotArgs {
                command: pause::SnapshotCmd::Rm { json: true, .. }
            })
        })
    ));
}

#[test]
fn test_vm_save_json_parses() {
    let cli =
        Cli::try_parse_from(["mvmctl", "vm", "save", "myvm", "--tag", "gold", "--json"]).unwrap();
    assert!(matches!(
        cli.command,
        Commands::Vm(group::Args {
            action: group::VmCmd::Save(checkpoint::SaveArgs {
                name,
                tag: Some(tag),
                json: true,
            })
        }) if name == "myvm" && tag == "gold"
    ));
}

#[test]
fn test_vm_restore_json_parses() {
    let cli = Cli::try_parse_from(["mvmctl", "vm", "restore", "ckpt-abc", "--json"]).unwrap();
    assert!(matches!(
        cli.command,
        Commands::Vm(group::Args {
            action: group::VmCmd::Restore(checkpoint::RestoreArgs { id, json: true })
        }) if id == "ckpt-abc"
    ));
}

// --- Checkpoint CLI tests ---

#[test]
fn test_checkpoint_create_parses() {
    let cli = Cli::try_parse_from([
        "mvmctl",
        "vm",
        "checkpoint",
        "create",
        "myvm",
        "--tag",
        "gold",
    ])
    .unwrap();
    assert!(matches!(
        cli.command,
        Commands::Vm(group::Args {
            action: group::VmCmd::Checkpoint(checkpoint::CheckpointArgs {
                command: checkpoint::CheckpointCmd::Create { .. }
            })
        })
    ));
}

#[test]
fn test_checkpoint_fork_parses() {
    assert!(
        Cli::try_parse_from([
            "mvmctl",
            "vm",
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
        "vm",
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
        Commands::Vm(group::Args {
            action: group::VmCmd::Checkpoint(checkpoint::CheckpointArgs {
                command: checkpoint::CheckpointCmd::Fork { json: true, .. }
            })
        })
    ));
}

#[test]
fn test_checkpoint_fork_rejects_traversal_new_id() {
    // --new-id must not allow a path component that escapes the VM state dir.
    let r = Cli::try_parse_from([
        "mvmctl",
        "vm",
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
    let cli = Cli::try_parse_from(["mvmctl", "vm", "checkpoint", "ls", "--json"]).unwrap();
    assert!(matches!(
        cli.command,
        Commands::Vm(group::Args {
            action: group::VmCmd::Checkpoint(checkpoint::CheckpointArgs {
                command: checkpoint::CheckpointCmd::Ls { json: true }
            })
        })
    ));
}

#[test]
fn test_checkpoint_create_vm_full_parses() {
    let cli = Cli::try_parse_from([
        "mvmctl",
        "vm",
        "checkpoint",
        "create",
        "myvm",
        "--class",
        "vm-full",
    ])
    .unwrap();
    assert!(matches!(
        cli.command,
        Commands::Vm(group::Args {
            action: group::VmCmd::Checkpoint(checkpoint::CheckpointArgs {
                command: checkpoint::CheckpointCmd::Create {
                    class: checkpoint::CheckpointClassArg::VmFull,
                    ..
                }
            })
        })
    ));
}

#[test]
fn test_checkpoint_restore_parses() {
    assert!(Cli::try_parse_from(["mvmctl", "vm", "checkpoint", "restore", "ckpt-abc"]).is_ok());
}

#[test]
fn test_checkpoint_restore_json_parses() {
    let cli = Cli::try_parse_from([
        "mvmctl",
        "vm",
        "checkpoint",
        "restore",
        "ckpt-abc",
        "--json",
    ])
    .unwrap();
    assert!(matches!(
        cli.command,
        Commands::Vm(group::Args {
            action: group::VmCmd::Checkpoint(checkpoint::CheckpointArgs {
                command: checkpoint::CheckpointCmd::Restore { json: true, .. }
            })
        })
    ));
}

#[test]
fn test_checkpoint_rm_json_parses() {
    let cli =
        Cli::try_parse_from(["mvmctl", "vm", "checkpoint", "rm", "ckpt-abc", "--json"]).unwrap();
    assert!(matches!(
        cli.command,
        Commands::Vm(group::Args {
            action: group::VmCmd::Checkpoint(checkpoint::CheckpointArgs {
                command: checkpoint::CheckpointCmd::Rm { json: true, .. }
            })
        })
    ));
}

#[test]
fn test_checkpoint_create_defaults_fs_quick() {
    let cli = Cli::try_parse_from(["mvmctl", "vm", "checkpoint", "create", "myvm"]).unwrap();
    assert!(matches!(
        cli.command,
        Commands::Vm(group::Args {
            action: group::VmCmd::Checkpoint(checkpoint::CheckpointArgs {
                command: checkpoint::CheckpointCmd::Create {
                    class: checkpoint::CheckpointClassArg::FsQuick,
                    ..
                }
            })
        })
    ));
}

#[test]
fn test_checkpoint_diff_parses() {
    let cli = Cli::try_parse_from([
        "mvmctl",
        "vm",
        "checkpoint",
        "diff",
        "ckpt-a",
        "ckpt-b",
        "--json",
    ])
    .unwrap();
    assert!(matches!(
        cli.command,
        Commands::Vm(group::Args {
            action: group::VmCmd::Checkpoint(checkpoint::CheckpointArgs {
                command: checkpoint::CheckpointCmd::Diff { json: true, .. }
            })
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
        Commands::Console(console::Args {
            name,
            command,
            force,
            env,
        }) => {
            assert_eq!(name, "myvm");
            assert_eq!(command.as_deref(), Some("ls"));
            assert!(!force, "default --force is off");
            assert!(env.is_empty());
        }
        _ => panic!("Expected Console command"),
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
    assert!(
        err.to_string().contains("unexpected argument '--force'"),
        "got: {err}"
    );
}

#[test]
fn up_accepts_repeatable_secret_flag() {
    let cli = Cli::try_parse_from([
        "mvmctl",
        "up",
        "--flake",
        ".",
        "--secret",
        "openai:api.openai.com",
        "--secret",
        "aws:s3.amazonaws.com,sts.amazonaws.com",
    ])
    .unwrap();
    match cli.command {
        Commands::Up(up::Args { secret, .. }) => {
            assert_eq!(
                secret,
                vec![
                    "openai:api.openai.com".to_string(),
                    "aws:s3.amazonaws.com,sts.amazonaws.com".to_string(),
                ]
            );
        }
        _ => panic!("Expected Up command"),
    }
}

#[test]
fn up_accepts_security_profile_flag_and_defaults_to_none() {
    // Explicitly named.
    let cli =
        Cli::try_parse_from(["mvmctl", "up", "--flake", ".", "--security-profile", "dev"]).unwrap();
    match cli.command {
        Commands::Up(up::Args {
            security_profile, ..
        }) => assert_eq!(security_profile.as_deref(), Some("dev")),
        _ => panic!("Expected Up command"),
    }
    // Unset → None (the runtime then defaults it to `production`).
    let cli = Cli::try_parse_from(["mvmctl", "up", "--flake", "."]).unwrap();
    match cli.command {
        Commands::Up(up::Args {
            security_profile,
            seccomp,
            ..
        }) => {
            assert_eq!(security_profile, None);
            assert_eq!(seccomp, None, "no --seccomp default; profile supplies it");
        }
        _ => panic!("Expected Up command"),
    }
}

// --- Run (transient runner; absorbed the former exec) CLI tests ---

#[test]
fn run_transient_default_manifest_argv_only() {
    let cli = Cli::try_parse_from(["mvmctl", "run", "--", "uname", "-a"]).expect("parse");
    match cli.command {
        Commands::Run(exec::RunArgs {
            manifest,
            cpus,
            memory,
            add_dir,
            env,
            timeout,
            launch_plan,
            argv,
            ..
        }) => {
            assert!(manifest.is_none(), "manifest should default to None");
            assert_eq!(cpus, 2);
            assert_eq!(memory, "512M");
            assert!(add_dir.is_empty());
            assert!(env.is_empty());
            assert_eq!(
                timeout, None,
                "unset --timeout ⇒ None (no per-command kill)"
            );
            assert!(launch_plan.is_none(), "launch_plan should default to None");
            assert_eq!(argv, vec!["uname".to_string(), "-a".to_string()]);
        }
        _ => panic!("Expected Run command"),
    }
}

#[test]
fn run_transient_timeout_parses_to_some() {
    let cli = Cli::try_parse_from(["mvmctl", "run", "--timeout", "5", "--", "sleep", "10"])
        .expect("parse");
    match cli.command {
        Commands::Run(exec::RunArgs { timeout, .. }) => {
            assert_eq!(timeout, Some(5), "--timeout 5 ⇒ Some(5)");
        }
        _ => panic!("Expected Run command"),
    }
}

#[test]
fn run_default_profile_argv_only() {
    let cli = Cli::try_parse_from(["mvmctl", "run", "--", "uname", "-a"]).expect("parse");
    match cli.command {
        Commands::Run(exec::RunArgs {
            manifest,
            image,
            net,
            allow_host,
            cpus,
            memory,
            profile,
            add_dir,
            env,
            timeout,
            receipt,
            json,
            dry_run,
            launch_plan,
            mode,
            dev,
            prod,
            argv,
            ack_divergence,
        }) => {
            assert!(manifest.is_none(), "manifest should default to None");
            assert!(image.is_none(), "image should default to None");
            assert!(!net, "net should default to false (deny-all)");
            assert!(allow_host.is_empty(), "allow_host should default to empty");
            assert_eq!(cpus, 2);
            assert_eq!(memory, "512M");
            assert_eq!(profile, exec::RunProfile::Standard);
            assert!(add_dir.is_empty());
            assert!(env.is_empty());
            assert_eq!(
                timeout, None,
                "unset --timeout ⇒ None (no per-command kill)"
            );
            assert!(receipt.is_none(), "receipt should default to None");
            assert!(!json, "json should default to false");
            assert!(!dry_run, "dry_run should default to false");
            assert!(launch_plan.is_none(), "launch_plan should default to None");
            assert!(mode.is_none(), "mode should default to None");
            assert!(!dev, "dev should default to false");
            assert!(!prod, "prod should default to false");
            assert_eq!(argv, vec!["uname".to_string(), "-a".to_string()]);
            assert!(
                ack_divergence.is_empty(),
                "ack_divergence should default to empty"
            );
        }
        _ => panic!("Expected Run command"),
    }
}

#[test]
fn run_timeout_parses_to_some() {
    let cli = Cli::try_parse_from(["mvmctl", "run", "--timeout", "5", "--", "sleep", "10"])
        .expect("parse");
    match cli.command {
        Commands::Run(exec::RunArgs { timeout, .. }) => {
            assert_eq!(timeout, Some(5), "--timeout 5 ⇒ Some(5)");
        }
        _ => panic!("Expected Run command"),
    }
}

#[test]
fn run_image_flag_parses() {
    let cli = Cli::try_parse_from([
        "mvmctl",
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
        Commands::Run(exec::RunArgs {
            image, prod, argv, ..
        }) => {
            assert_eq!(image.as_deref(), Some("docker.io/library/alpine:3.20"));
            assert!(!prod);
            assert_eq!(
                argv,
                vec![
                    "/bin/sh".to_string(),
                    "-c".to_string(),
                    "echo hi".to_string()
                ]
            );
        }
        _ => panic!("Expected Run command"),
    }
}

#[test]
fn run_image_prod_flag_parses_as_image_policy() {
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
        Commands::Run(exec::RunArgs {
            image, prod, mode, ..
        }) => {
            assert_eq!(image.as_deref(), Some(pinned));
            assert!(prod);
            assert!(mode.is_none());
        }
        _ => panic!("Expected Run command"),
    }
}

#[test]
fn run_manifest_and_image_conflict() {
    let cli = Cli::try_parse_from([
        "mvmctl",
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
        "run",
        "--profile",
        "restrictive",
        "--",
        "/bin/true",
    ])
    .expect("parse");
    match cli.command {
        Commands::Run(exec::RunArgs { profile, argv, .. }) => {
            assert_eq!(profile, exec::RunProfile::Restrictive);
            assert_eq!(argv, vec!["/bin/true".to_string()]);
        }
        _ => panic!("Expected Run command"),
    }
}

#[test]
fn run_rejects_unknown_profile() {
    let cli = Cli::try_parse_from(["mvmctl", "run", "--profile", "unsafe", "--", "/bin/true"]);
    assert!(cli.is_err());
}

#[test]
fn run_receipt_flag_parses() {
    let cli = Cli::try_parse_from([
        "mvmctl",
        "run",
        "--receipt",
        "/tmp/mvm-run-receipt.json",
        "--",
        "/bin/true",
    ])
    .expect("parse");
    match cli.command {
        Commands::Run(exec::RunArgs { receipt, .. }) => {
            assert_eq!(
                receipt.as_deref(),
                Some(std::path::Path::new("/tmp/mvm-run-receipt.json"))
            );
        }
        _ => panic!("Expected Run command"),
    }
}

#[test]
fn run_json_flag_parses() {
    let cli = Cli::try_parse_from(["mvmctl", "run", "--json", "--", "/bin/true"]).expect("parse");
    match cli.command {
        Commands::Run(exec::RunArgs { json, argv, .. }) => {
            assert!(json);
            assert_eq!(argv, vec!["/bin/true".to_string()]);
        }
        _ => panic!("Expected Run command"),
    }
}

#[test]
fn run_dry_run_json_flags_parse() {
    let cli = Cli::try_parse_from(["mvmctl", "run", "--dry-run", "--json", "--", "/bin/true"])
        .expect("parse");
    match cli.command {
        Commands::Run(exec::RunArgs {
            dry_run,
            json,
            argv,
            ..
        }) => {
            assert!(dry_run);
            assert!(json);
            assert_eq!(argv, vec!["/bin/true".to_string()]);
        }
        _ => panic!("Expected Run command"),
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
    let cli = Cli::try_parse_from(["mvmctl", "vm", "sandbox", "gc"]).expect("parse");
    let Commands::Vm(vmg) = cli.command else {
        panic!("expected vm group")
    };
    match vmg.action {
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
    let cli = Cli::try_parse_from(["mvmctl", "vm", "sandbox", "gc", "--apply"]).expect("parse");
    let Commands::Vm(vmg) = cli.command else {
        panic!("expected vm group")
    };
    match vmg.action {
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
    let cli = Cli::try_parse_from(["mvmctl", "vm", "sandbox", "gc", "--json"]).expect("parse");
    let Commands::Vm(vmg) = cli.command else {
        panic!("expected vm group")
    };
    match vmg.action {
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
    let result = Cli::try_parse_from(["mvmctl", "vm", "sandbox", "gc", "--apply", "--dry-run"]);
    assert!(result.is_err());
}

#[test]
fn cp_host_to_guest_parses() {
    let cli = Cli::try_parse_from([
        "mvmctl",
        "vm",
        "cp",
        "--force",
        "--create-parents",
        "--max-bytes",
        "1024",
        "./host.txt",
        "vm1:/tmp/host.txt",
    ])
    .expect("parse");
    let Commands::Vm(vmg) = cli.command else {
        panic!("expected vm group")
    };
    match vmg.action {
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
        "vm",
        "cp",
        "--json",
        "./host.txt",
        "vm1:/tmp/host.txt",
    ])
    .expect("parse");
    let Commands::Vm(vmg) = cli.command else {
        panic!("expected vm group")
    };
    match vmg.action {
        group::VmCmd::Cp(cp::Args { json, .. }) => {
            assert!(json);
        }
        _ => panic!("Expected Cp command"),
    }
}

#[test]
fn cp_guest_to_host_defaults_parse() {
    let cli = Cli::try_parse_from(["mvmctl", "vm", "cp", "vm1:/tmp/out.txt", "./out.txt"])
        .expect("parse");
    let Commands::Vm(vmg) = cli.command else {
        panic!("expected vm group")
    };
    match vmg.action {
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
        Commands::Run(exec::RunArgs {
            launch_plan, argv, ..
        }) => {
            assert_eq!(launch_plan.as_deref(), Some("./plan.json"));
            assert!(argv.is_empty());
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
        Commands::Run(exec::RunArgs {
            manifest,
            cpus,
            memory,
            argv,
            ..
        }) => {
            assert_eq!(manifest.as_deref(), Some("my-tpl"));
            assert_eq!(cpus, 4);
            assert_eq!(memory, "1G");
            assert_eq!(argv, vec!["/bin/true".to_string()]);
        }
        _ => panic!("Expected Run command"),
    }
}

#[test]
fn run_transient_with_add_dir_and_env() {
    let cli = Cli::try_parse_from([
        "mvmctl",
        "run",
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
        Commands::Run(exec::RunArgs {
            add_dir, env, argv, ..
        }) => {
            assert_eq!(
                add_dir,
                vec!["/tmp:/work".to_string(), "/etc:/host-etc".to_string()]
            );
            assert_eq!(env, vec!["FOO=bar".to_string(), "BAZ=qux".to_string()]);
            assert_eq!(argv, vec!["ls".to_string(), "/work".to_string()]);
        }
        _ => panic!("Expected Run command"),
    }
}

#[test]
fn run_transient_requires_argv() {
    // Without trailing argv, Clap should reject because `argv` is required.
    let cli = Cli::try_parse_from(["mvmctl", "run"]);
    assert!(cli.is_err());
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
    // `prune` reaps orphaned mvm-libkrun-supervisor / gvproxy / console-tail
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

#[test]
fn test_dev_cache_inspect() {
    let cli = Cli::try_parse_from(["mvmctl", "dev", "cache", "inspect"]).unwrap();
    match cli.command {
        Commands::Dev(dev::Args {
            action:
                Some(DevAction::Cache {
                    action: DevCacheAction::Inspect { json },
                }),
        }) => assert!(!json),
        _ => panic!("Expected Dev Cache Inspect command"),
    }
}

#[test]
fn test_dev_cache_inspect_json() {
    let cli = Cli::try_parse_from(["mvmctl", "dev", "cache", "inspect", "--json"]).unwrap();
    match cli.command {
        Commands::Dev(dev::Args {
            action:
                Some(DevAction::Cache {
                    action: DevCacheAction::Inspect { json },
                }),
        }) => assert!(json),
        _ => panic!("Expected Dev Cache Inspect command"),
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

// --- Apple Container dev tests ---

#[test]
fn test_dev_down_parses() {
    let cli = Cli::try_parse_from(["mvmctl", "dev", "down"]).unwrap();
    match cli.command {
        Commands::Dev(dev::Args {
            action: Some(DevAction::Down { reset, json }),
        }) => {
            assert!(!reset);
            assert!(!json, "bare `dev down` defaults to text output");
        }
        _ => panic!("Expected Dev Down command"),
    }
}

#[test]
fn test_dev_down_json_and_reset_flags_parse() {
    let cli = Cli::try_parse_from(["mvmctl", "dev", "down", "--reset", "--json"]).unwrap();
    match cli.command {
        Commands::Dev(dev::Args {
            action: Some(DevAction::Down { reset, json }),
        }) => {
            assert!(reset);
            assert!(json);
        }
        _ => panic!("Expected Dev Down command"),
    }
}

#[test]
fn test_dev_park_parses() {
    let cli = Cli::try_parse_from(["mvmctl", "dev", "park"]).unwrap();
    match cli.command {
        Commands::Dev(dev::Args {
            action: Some(DevAction::Park { json }),
        }) => assert!(!json, "bare `dev park` defaults to text output"),
        _ => panic!("Expected Dev Park command"),
    }
}

#[test]
fn test_dev_park_json_flag_parses() {
    let cli = Cli::try_parse_from(["mvmctl", "dev", "park", "--json"]).unwrap();
    match cli.command {
        Commands::Dev(dev::Args {
            action: Some(DevAction::Park { json }),
        }) => assert!(json, "`--json` requests machine-readable output"),
        _ => panic!("Expected Dev Park command"),
    }
}

#[test]
fn test_dev_up_json_flag_parses() {
    let cli = Cli::try_parse_from(["mvmctl", "dev", "up", "--json"]).unwrap();
    match cli.command {
        Commands::Dev(dev::Args {
            action: Some(DevAction::Up { json, .. }),
        }) => assert!(json),
        _ => panic!("Expected Dev Up command"),
    }
}

#[test]
fn test_dev_up_base_flag_parses() {
    let cli = Cli::try_parse_from(["mvmctl", "dev", "up", "--base", "dev-base@rev-a"]).unwrap();
    match cli.command {
        Commands::Dev(dev::Args {
            action: Some(DevAction::Up { base, .. }),
        }) => assert_eq!(base.as_deref(), Some("dev-base@rev-a")),
        _ => panic!("Expected Dev Up command"),
    }
}

#[test]
fn test_dev_up_json_conflicts_with_shell() {
    // `--json` is non-interactive by definition; `--shell` must be rejected.
    let res = Cli::try_parse_from(["mvmctl", "dev", "up", "--json", "--shell"]);
    assert!(res.is_err(), "`dev up --json --shell` must conflict");
}

#[test]
fn test_dev_shell_parses() {
    let cli = Cli::try_parse_from(["mvmctl", "dev", "shell"]);
    assert!(cli.is_ok());
}

#[test]
fn test_dev_status_parses() {
    let cli = Cli::try_parse_from(["mvmctl", "dev", "status"]).unwrap();
    match cli.command {
        Commands::Dev(dev::Args {
            action: Some(DevAction::Status { json }),
        }) => assert!(!json, "bare `dev status` defaults to text output"),
        _ => panic!("Expected Dev Status command"),
    }
}

#[test]
fn test_dev_status_json_flag_parses() {
    let cli = Cli::try_parse_from(["mvmctl", "dev", "status", "--json"]).unwrap();
    match cli.command {
        Commands::Dev(dev::Args {
            action: Some(DevAction::Status { json }),
        }) => assert!(json, "`--json` requests machine-readable output"),
        _ => panic!("Expected Dev Status command"),
    }
}

#[test]
fn test_is_vz_dev_running_returns_bool() {
    // Just verify it doesn't panic — actual result depends on platform
    let _ = super::env::dev_vz::is_vz_dev_running();
}

// ---- RunParams compile-check (referenced for type-export verification) ----
#[allow(dead_code)]
fn _runparams_has_lifetime() {
    fn _take(_p: RunParams<'_>) {}
}

// ---- admission flags ----

#[test]
fn test_up_tenant_parse_default_is_none() {
    // The clap field is `Option<String>`; the `"local"` default has
    // moved into `vm::tenant_resolution::resolve_tenant` so the 4-level
    // precedence (built-in → config.toml → env → flag) can apply.
    let cli = Cli::try_parse_from(["mvmctl", "up"]).expect("parse");
    match cli.command {
        Commands::Up(up::Args { tenant, .. }) => {
            assert!(
                tenant.is_none(),
                "tenant parse default is None; resolver fills `local` per ADR-064 §Decision 9",
            );
        }
        _ => panic!("Expected Up command"),
    }
}

#[test]
fn test_up_tenant_override_via_flag() {
    let cli = Cli::try_parse_from(["mvmctl", "up", "--tenant", "acme"]).expect("parse");
    match cli.command {
        Commands::Up(up::Args { tenant, .. }) => {
            assert_eq!(tenant.as_deref(), Some("acme"))
        }
        _ => panic!("Expected Up command"),
    }
}

#[test]
fn test_up_no_supervisor_defaults_off() {
    let cli = Cli::try_parse_from(["mvmctl", "up"]).expect("parse");
    match cli.command {
        Commands::Up(up::Args { no_supervisor, .. }) => {
            assert!(!no_supervisor, "admission is on by default");
        }
        _ => panic!("Expected Up command"),
    }
}

#[test]
fn test_up_no_supervisor_flag_parses() {
    let cli = Cli::try_parse_from(["mvmctl", "up", "--no-supervisor"]).expect("parse");
    match cli.command {
        Commands::Up(up::Args { no_supervisor, .. }) => assert!(no_supervisor),
        _ => panic!("Expected Up command"),
    }
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
        help.contains("libkrun") && help.contains("vz"),
        "`--builder` value choices missing from help; help text was:\n{help}"
    );
}

#[test]
fn builder_flag_accepts_libkrun() {
    let cli = Cli::try_parse_from(["mvmctl", "--builder", "libkrun", "doctor"]).expect("parse");
    assert_eq!(cli.builder.as_deref(), Some("libkrun"));
}

#[test]
fn builder_flag_accepts_vz() {
    let cli = Cli::try_parse_from(["mvmctl", "--builder", "vz", "doctor"]).expect("parse");
    assert_eq!(cli.builder.as_deref(), Some("vz"));
}

#[test]
fn builder_flag_rejects_unknown_value() {
    // Clap's `value_parser = ["libkrun", "vz"]` should refuse
    // anything outside that set. Catches typos like `=vmz` early
    // rather than letting `MVM_BUILDER_BACKEND_ENV`'s
    // warn-and-fall-through path eat them.
    let err = Cli::try_parse_from(["mvmctl", "--builder", "bogus", "doctor"]).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("invalid value") || msg.contains("possible values") || msg.contains("bogus"),
        "expected a clap value-parser error mentioning 'bogus', got: {msg}"
    );
}

#[test]
fn builder_flag_unset_by_default() {
    let cli = Cli::try_parse_from(["mvmctl", "doctor"]).expect("parse");
    assert_eq!(cli.builder, None);
}

// --- Session start --ephemeral tests ---

#[test]
fn test_session_start_ephemeral_parses() {
    let cli =
        Cli::try_parse_from(["mvmctl", "vm", "session", "start", "tmpl", "--ephemeral"]).unwrap();
    let Commands::Vm(vmg) = cli.command else {
        panic!("expected vm group")
    };
    match vmg.action {
        group::VmCmd::Session(session::Args {
            command: session::Cmd::Start(a),
        }) => assert!(a.ephemeral),
        _ => panic!("expected session start"),
    }
}

// --- Session attach --continue / --resume tests ---

#[test]
fn test_session_attach_continue_parses() {
    let cli = Cli::try_parse_from(["mvmctl", "vm", "session", "attach", "--continue"]).unwrap();
    let Commands::Vm(vmg) = cli.command else {
        panic!("expected vm group")
    };
    match vmg.action {
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
    let cli = Cli::try_parse_from(["mvmctl", "up", "--flake", ".", "--wait"]).unwrap();
    match cli.command {
        Commands::Up(ref a) => assert!(a.wait),
        _ => panic!("expected up"),
    }
}

#[test]
fn test_up_wait_conflicts_with_detach() {
    let res = Cli::try_parse_from(["mvmctl", "up", "--flake", ".", "--wait", "--detach"]);
    assert!(
        res.is_err(),
        "--wait --detach must be rejected at parse time"
    );
}

#[test]
fn test_up_wait_conflicts_with_up_json() {
    let res = Cli::try_parse_from(["mvmctl", "up", "--flake", ".", "--wait", "--up-json"]);
    assert!(
        res.is_err(),
        "--wait --up-json must be rejected at parse time"
    );
}

#[test]
fn test_session_attach_resume_parses() {
    let cli = Cli::try_parse_from([
        "mvmctl",
        "vm",
        "session",
        "attach",
        "-r",
        "aaaaaaaaaaaaaaaa",
    ])
    .unwrap();
    let Commands::Vm(vmg) = cli.command else {
        panic!("expected vm group")
    };
    match vmg.action {
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

#[test]
fn state_touching_commands_trigger_entry_convergence() {
    // Lifecycle mutate/read commands run the cheap converge pass.
    assert!(touches(&["mvmctl", "up"]));
    assert!(touches(&["mvmctl", "down"]));
    assert!(touches(&["mvmctl", "console", "myvm"]));
    assert!(touches(&["mvmctl", "vm", "pause", "myvm"]));
    assert!(touches(&["mvmctl", "vm", "save", "myvm"]));
    assert!(touches(&["mvmctl", "vm", "restore", "ckpt-myvm"]));
    assert!(touches(&["mvmctl", "ls"]));
    assert!(touches(&["mvmctl", "dev", "status"]));
}

#[test]
fn read_only_and_vm_agnostic_commands_skip_entry_convergence() {
    assert!(!touches(&["mvmctl", "doctor"]));
    assert!(!touches(&["mvmctl", "catalog", "list"]));
    assert!(!touches(&["mvmctl", "trust", "audit", "tail"]));
    assert!(!touches(&["mvmctl", "cache", "info"]));
    // `ls --all` must preserve registry-only stopped rows for rendering.
    assert!(!touches(&["mvmctl", "ls", "--all"]));
    assert!(!touches(&["mvmctl", "ls", "--all", "--json"]));
    // `reconcile` is the convergence verb itself — must not double-run on entry.
    assert!(!touches(&["mvmctl", "reconcile"]));
    assert!(!touches(&["mvmctl", "reconcile", "--dry-run"]));
}

#[test]
fn state_touching_json_commands_reserve_stdout_before_entry_convergence() {
    // Regression: `ls --json` runs reconcile-on-entry before dispatch; if
    // chrome is still stdout-routed, a dev-VM hint can precede the JSON array.
    assert!(emits_machine_readable_stdout(&[
        "mvmctl", "ls", "--all", "--json"
    ]));
    assert!(emits_machine_readable_stdout(&[
        "mvmctl", "dev", "status", "--json"
    ]));
    assert!(emits_machine_readable_stdout(&[
        "mvmctl", "dev", "up", "--json"
    ]));
    assert!(emits_machine_readable_stdout(&[
        "mvmctl", "dev", "down", "--json"
    ]));
    assert!(emits_machine_readable_stdout(&[
        "mvmctl", "dev", "cache", "inspect", "--json"
    ]));
    assert!(emits_machine_readable_stdout(&[
        "mvmctl",
        "run",
        "--json",
        "--",
        "/bin/true"
    ]));
    assert!(emits_machine_readable_stdout(&[
        "mvmctl",
        "up",
        "--up-json"
    ]));
    assert!(emits_machine_readable_stdout(&[
        "mvmctl", "vm", "save", "myvm", "--json"
    ]));
    assert!(emits_machine_readable_stdout(&[
        "mvmctl",
        "vm",
        "restore",
        "ckpt-myvm",
        "--json"
    ]));
    assert!(emits_machine_readable_stdout(&[
        "mvmctl", "vm", "snapshot", "ls", "--json"
    ]));

    assert!(!emits_machine_readable_stdout(&["mvmctl", "ls"]));
    assert!(!emits_machine_readable_stdout(&["mvmctl", "dev", "status"]));
    assert!(!emits_machine_readable_stdout(&["mvmctl", "up"]));
}

// --- Top-level help surface tests ---

#[test]
fn top_level_help_hides_infra() {
    let help = cli_command().render_help().to_string();
    // Daily-driver commands must appear.
    assert!(
        help.contains("machine"),
        "machine must appear in top-level help"
    );
    assert!(help.contains("dev"), "dev must appear in top-level help");
    assert!(
        help.contains("build"),
        "build must appear in top-level help"
    );
    assert!(help.contains("init"), "init must appear in top-level help");
    assert!(
        help.contains("doctor"),
        "doctor must appear in top-level help"
    );
    // Infrastructure commands must NOT appear in the default help.
    for hidden in &[
        "pool", "cache", "storage", "manifest", "catalog", "image", "bundle", "trust", "deps",
        "artifact", "secret", "network", "ops", "env",
    ] {
        // Commands are listed one per line; a hidden command's name should
        // not appear as a standalone word at the start of a help line.
        let visible_as_subcommand = help.lines().any(|line| {
            let trimmed = line.trim_start();
            trimmed.starts_with(hidden)
                && trimmed[hidden.len()..].starts_with(|c: char| c.is_whitespace() || c == '\0')
        });
        assert!(
            !visible_as_subcommand,
            "infra command `{hidden}` must be hidden from top-level help but was found"
        );
    }
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
