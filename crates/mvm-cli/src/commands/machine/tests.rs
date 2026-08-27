use super::receipt::MachineStartInitPolicy;
use super::runtime::{PostStart, post_start_action, resolve_persistent_spec};
use super::*;
use crate::commands::{Cli, Commands};
use clap::{CommandFactory, Parser};
use mvm_core::atomic_io::atomic_write;
use mvm_core::util::test_env::TestEnv;
/// dragging the whole top-level CLI in for unit-level assertions.
#[derive(Parser, Debug)]
struct TestCli {
    #[command(subcommand)]
    action: MachineAction,
}

struct IsolatedMachineState {
    _env: TestEnv,
    _tmp: tempfile::TempDir,
}

impl IsolatedMachineState {
    fn new() -> Self {
        let mut env = TestEnv::new();
        let tmp = tempfile::tempdir().expect("tempdir");
        env.set("MVM_HOME", tmp.path());
        Self {
            _env: env,
            _tmp: tmp,
        }
    }
}

fn parse(argv: &[&str]) -> Result<MachineAction, clap::Error> {
    let mut full = vec!["machine"];
    full.extend_from_slice(argv);
    TestCli::try_parse_from(full).map(|cli| cli.action)
}

fn parse_owned(argv: &[String]) -> Result<MachineAction, clap::Error> {
    let full = std::iter::once("machine".to_string())
        .chain(argv.iter().cloned())
        .collect::<Vec<_>>();
    TestCli::try_parse_from(full).map(|cli| cli.action)
}

fn parse_run(argv: &[&str]) -> Result<MachineRunArgs, clap::Error> {
    parse(argv).map(|action| match action {
        MachineAction::Run(r) => r,
        other => panic!("expected run action, got {other:?}"),
    })
}

fn parse_owned_run(argv: &[String]) -> Result<MachineRunArgs, clap::Error> {
    parse_owned(argv).map(|action| match action {
        MachineAction::Run(r) => r,
        other => panic!("expected run action, got {other:?}"),
    })
}

fn parse_fork(argv: &[&str]) -> Result<MachineForkArgs, clap::Error> {
    parse(argv).map(|action| match action {
        MachineAction::Fork(f) => f,
        other => panic!("expected fork action, got {other:?}"),
    })
}

fn parse_restore(argv: &[&str]) -> Result<MachineRestoreArgs, clap::Error> {
    parse(argv).map(|action| match action {
        MachineAction::Restore(r) => r,
        other => panic!("expected restore action, got {other:?}"),
    })
}

const SDK_RUN_EGRESS_BACKEND: &str = "libkrun";
const SDK_RUN_EGRESS_ENFORCEMENT: &str = "libkrun:l4-host-port";

fn sdk_machine_fixture(name: &str) -> Vec<String> {
    std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/machine-fixtures")
            .join(format!("{name}.argv")),
    )
    .expect("read shared SDK machine argv fixture")
    .lines()
    .map(std::string::ToString::to_string)
    .collect()
}

/// The `machine` subcommand token a parsed action was built from — used to
/// assert a shared SDK fixture parses to the verb its first line names.
fn machine_subcommand(action: &MachineAction) -> &'static str {
    match action {
        MachineAction::Run(_) => "run",
        MachineAction::Build(_) => "build",
        MachineAction::Create(_) => "create",
        MachineAction::Start(_) => "start",
        MachineAction::Restart(_) => "restart",
        MachineAction::Stop(_) => "stop",
        MachineAction::Reconfigure(_) => "reconfigure",
        MachineAction::Rm(_) => "rm",
        MachineAction::Ls(_) => "ls",
        MachineAction::Inspect(_) => "inspect",
        MachineAction::Shell(_) => "shell",
        MachineAction::Exec(_) => "exec",
        MachineAction::SetTimeout(_) => "set-timeout",
        MachineAction::Logs(_) => "logs",
        MachineAction::Console(_) => "console",
        MachineAction::CheckArtifact(_) => "check-artifact",
        MachineAction::Timeline(_) => "timeline",
        MachineAction::Revert(_) => "revert",
        MachineAction::Rewind(_) => "rewind",
        MachineAction::Advance(_) => "advance",
        MachineAction::WarmRestore(_) => "warm-restore",
        MachineAction::Fork(_) => "fork",
        MachineAction::Restore(_) => "restore",
        MachineAction::Vm(_) => "vm",
    }
}

/// Source-of-truth anchor for the cross-language conformance harness: every
/// `tests/machine-fixtures/*.argv` the SDKs assert against must be argv the
/// CLI parser actually accepts, and must map to the verb its first line
/// names. This is what catches an SDK emitting a flag the CLI rejects (e.g.
/// `stop --name X` when `stop` takes a positional name).
#[test]
fn fork_parses_with_as() {
    let args = parse_fork(&["fork", "parent", "--as", "child"]).unwrap();
    assert_eq!(args.parent, "parent");
    assert_eq!(args.child_name, Some("child".to_string()));
    assert!(args.branch.is_none());
}

#[test]
fn fork_parses_with_branch() {
    let args = parse_fork(&["fork", "parent", "--branch", "feature-x"]).unwrap();
    assert_eq!(args.parent, "parent");
    assert!(args.child_name.is_none());
    assert_eq!(args.branch, Some("feature-x".to_string()));
}

#[test]
fn fork_rejects_as_and_branch_together() {
    assert!(parse_fork(&["fork", "parent", "--as", "child", "--branch", "feature-x"]).is_err());
}

#[test]
fn fork_allows_no_name() {
    let args = parse_fork(&["fork", "parent"]).unwrap();
    assert_eq!(args.parent, "parent");
    assert!(args.child_name.is_none());
    assert!(args.branch.is_none());
}

#[test]
fn restore_auto_names_when_as_and_branch_are_omitted() {
    let args = parse_restore(&["restore", "ckpt-abc"]).unwrap();
    assert_eq!(args.checkpoint, "ckpt-abc");
    assert!(args.child_name.is_none());
    assert!(args.branch.is_none());
}

#[test]
fn restore_parses_with_as() {
    let args = parse_restore(&["restore", "ckpt-abc", "--as", "child"]).unwrap();
    assert_eq!(args.checkpoint, "ckpt-abc");
    assert_eq!(args.child_name, Some("child".to_string()));
    assert!(args.branch.is_none());
}

#[test]
fn restore_parses_with_branch() {
    let args = parse_restore(&["restore", "ckpt-abc", "--branch", "feature-x"]).unwrap();
    assert_eq!(args.checkpoint, "ckpt-abc");
    assert!(args.child_name.is_none());
    assert_eq!(args.branch, Some("feature-x".to_string()));
}

#[test]
fn every_shared_machine_fixture_parses_to_its_verb() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/machine-fixtures");
    let mut seen = 0;
    for entry in std::fs::read_dir(&dir).expect("read machine-fixtures dir") {
        let path = entry.expect("dir entry").path();
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("");
        if file_name.starts_with('.') {
            continue;
        }
        if path.extension().and_then(|e| e.to_str()) != Some("argv") {
            continue;
        }
        let argv: Vec<String> = std::fs::read_to_string(&path)
            .expect("read fixture")
            .lines()
            .map(std::string::ToString::to_string)
            .collect();
        let action = parse_owned(&argv).unwrap_or_else(|e| {
            panic!(
                "fixture {} must parse as a machine subcommand: {e}",
                path.display()
            )
        });
        let expected = argv.first().expect("non-empty fixture");
        assert_eq!(
            machine_subcommand(&action),
            expected,
            "fixture {} parsed to the wrong subcommand",
            path.display()
        );
        seen += 1;
    }
    assert!(
        seen >= 14,
        "expected the full machine fixture set, found {seen}"
    );
}

fn assert_sdk_run_admission_inputs(summary: super::super::vm::exec::RunSecuritySummary) {
    assert!(summary.dry_run);
    assert!(!summary.will_execute);
    assert_eq!(summary.image_kind, "oci");
    assert_eq!(summary.cpus, 4);
    assert_eq!(summary.memory, "1G");
    assert_eq!(summary.memory_mib, 1024);
    assert_eq!(summary.profile, "dev");
    assert!(summary.receipt_requested);
    assert_eq!(
        summary.preflight_network_posture,
        "allow-list:api.example.com:443"
    );
    assert_eq!(
        summary.receipt_network_posture,
        summary.preflight_network_posture
    );
    assert_eq!(
        summary.receipt_egress_enforcement,
        SDK_RUN_EGRESS_ENFORCEMENT
    );
    assert_eq!(summary.preflight_command, summary.receipt_command);
    assert!(summary.preflight_command.contains("argv_len=3"));
    assert!(!summary.preflight_command.contains("echo ok"));
    assert_eq!(
        sdk_fixture_env_keys(&summary.preflight_env_keys),
        ["MODE", "TOKEN"]
    );
    assert_eq!(
        sdk_fixture_env_keys(&summary.receipt_env_keys),
        ["MODE", "TOKEN"]
    );
    assert_eq!(summary.preflight_mounts, summary.receipt_mounts);
    assert_eq!(summary.preflight_mounts.len(), 1);
    let mount = &summary.preflight_mounts[0];
    assert_eq!(mount.guest_path, "/work");
    assert!(mount.read_only);
    assert!(!mount.host_path_sha256.contains("/tmp/mvm-sdk-src"));
    assert_eq!(summary.preflight_timeout_secs, 30);
    assert_eq!(summary.receipt_timeout_secs, 30);
}

fn sdk_fixture_env_keys(keys: &[String]) -> Vec<&str> {
    keys.iter()
        .map(String::as_str)
        .filter(|key| !is_oci_proxy_env_key(key))
        .collect()
}

fn is_oci_proxy_env_key(key: &str) -> bool {
    matches!(
        key,
        "ALL_PROXY"
            | "all_proxy"
            | "HTTP_PROXY"
            | "HTTPS_PROXY"
            | "NO_PROXY"
            | "http_proxy"
            | "https_proxy"
            | "no_proxy"
    )
}

fn assert_manifest_fixture_reaches_unknown_key_gate(mut sdk_args: Vec<String>) {
    let dir = tempfile::tempdir().expect("tempdir");
    let manifest = dir.path().join("mvm.toml");
    std::fs::write(
        &manifest,
        "image = \"alpine:latest\"\nnetwork_typo = true\n",
    )
    .expect("manifest");
    let manifest_slot = sdk_args
        .iter()
        .position(|arg| arg == "mvm.toml")
        .expect("fixture carries manifest path");
    sdk_args[manifest_slot] = manifest.display().to_string();

    let action = parse_owned(&sdk_args).expect("sdk args parse as CLI machine create");
    let MachineAction::Create(args) = action else {
        panic!("expected create action");
    };
    let err = args
        .into_spec()
        .expect_err("CLI manifest parser must reject unknown SDK-provided keys");
    let chain = err
        .chain()
        .map(std::string::ToString::to_string)
        .collect::<Vec<_>>()
        .join("\n");

    assert!(
        chain.contains("unknown field") || chain.contains("unknown key"),
        "unexpected error chain: {chain}"
    );
}

#[test]
fn run_parses_image_and_trailing_argv() {
    let args = parse_run(&["run", "--image", "alpine", "--", "echo", "hello"]).expect("parse");
    assert_eq!(args.run.image.as_deref(), Some("alpine"));
    assert_eq!(args.run.argv, vec!["echo", "hello"]);
}

#[test]
fn run_rejects_an_unknown_flag_before_the_argv_separator() {
    // Swallowing it into argv ships the typo to the guest shell, which answers
    // with something like `exec: illegal option --` instead of naming the flag.
    let err = parse_run(&[
        "run",
        "--image",
        "alpine",
        "--nonexistent",
        "8080:80",
        "--",
        "uname",
        "-a",
    ])
    .expect_err("unknown flag must not be swallowed into argv");
    assert_eq!(err.kind(), clap::error::ErrorKind::UnknownArgument);
}

#[test]
fn exec_rejects_an_unknown_flag_before_the_argv_separator() {
    let err = parse(&["exec", "web", "--nonexistent", "--", "uname", "-a"])
        .expect_err("unknown flag must not be swallowed into argv");
    assert_eq!(err.kind(), clap::error::ErrorKind::UnknownArgument);
}

#[test]
fn run_keeps_hyphenated_argv_after_the_separator() {
    let args = parse_run(&["run", "--image", "alpine", "--", "uname", "-a", "--all"])
        .expect("hyphenated argv after `--` stays argv");
    assert_eq!(args.run.argv, vec!["uname", "-a", "--all"]);
}

#[test]
fn run_parses_hypervisor_flag_and_forwards_to_run_args() {
    let args = parse_run(&[
        "run",
        "--image",
        "alpine",
        "--hypervisor",
        "libkrun",
        "--",
        "echo",
        "hello",
    ])
    .expect("parse");
    assert_eq!(args.run.hypervisor.as_deref(), Some("libkrun"));

    let run = args.into_run_args();
    assert_eq!(run.hypervisor.as_deref(), Some("libkrun"));
}

#[test]
fn run_without_hypervisor_flag_forwards_none() {
    let args = parse_run(&["run", "--image", "alpine", "--", "echo", "hello"]).expect("parse");
    assert!(args.run.hypervisor.is_none());

    let run = args.into_run_args();
    assert!(run.hypervisor.is_none());
}

#[test]
fn run_parses_runtime_pack_flag_and_forwards_to_run_args() {
    let args = parse_run(&["run", "--runtime-pack", "--", "true"]).expect("parse");
    assert!(args.run.runtime_pack);

    let run = args.into_run_args();
    assert!(run.runtime_pack);
    assert!(run.image.is_none());
    assert!(run.manifest.is_none());
}

#[test]
fn run_runtime_pack_conflicts_with_image_manifest_and_flake() {
    let err = parse_run(&["run", "--runtime-pack", "--image", "alpine", "--", "true"])
        .expect_err("--runtime-pack conflicts with --image");
    assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);

    let err = parse_run(&["run", "--runtime-pack", "--manifest", "base", "--", "true"])
        .expect_err("--runtime-pack conflicts with --manifest");
    assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);

    let err = parse_run(&["run", "--runtime-pack", "--flake", ".", "--", "true"])
        .expect_err("--runtime-pack conflicts with --flake");
    assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
}

#[test]
fn run_parses_deployment_source_and_conflicts_with_other_sources() {
    let args = parse_run(&["run", "--deployment", "/tmp/deployment", "--", "true"])
        .expect("deployment source parses");
    assert_eq!(args.run.deployment, Some(PathBuf::from("/tmp/deployment")));

    let err = parse_run(&[
        "run",
        "--deployment",
        "/tmp/deployment",
        "--image",
        "alpine",
        "--",
        "true",
    ])
    .expect_err("deployment and image must be mutually exclusive");
    assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
}

#[test]
fn run_parses_and_forwards_net_flags() {
    let args = parse_run(&[
        "run",
        "--image",
        "alpine",
        "--net",
        "--allow-host",
        "a.com",
        "--allow-host",
        "b.com:8443",
        "--",
        "true",
    ])
    .expect("parse");
    assert!(args.run.net);
    assert_eq!(args.run.allow_host, vec!["a.com", "b.com:8443"]);
    // The flags ride through into the canonical run args unchanged.
    let run = args.into_run_args();
    assert!(run.net);
    assert_eq!(run.allow_host, vec!["a.com", "b.com:8443"]);
}

#[test]
fn run_net_flags_default_off() {
    let args = parse_run(&["run", "--image", "alpine", "--", "true"]).expect("parse");
    assert!(!args.run.net);
    assert!(args.run.allow_host.is_empty());
}

#[test]
fn fresh_boot_without_image_is_rejected_at_dispatch() {
    // `--image` is no longer clap-required (a persistent run can reconnect
    // by name), so a fresh transient boot with no image parses and is
    // refused at mode resolution with a clear message.
    let args = parse_run(&["run", "--", "echo", "hi"]).expect("parse");
    let err = args.resolve_mode().expect_err("fresh boot needs an image");
    assert!(err.to_string().contains("image"), "unexpected error: {err}");
}

#[test]
fn transient_run_without_argv_is_rejected_at_dispatch() {
    // Argv is no longer clap-required (persistent/interactive modes boot
    // without a command), so a bare transient run parses and is refused at
    // mode resolution with a clear message — not a hang, not a silent exit.
    let args = parse_run(&["run", "--image", "alpine"]).expect("parse");
    let err = args
        .resolve_mode()
        .expect_err("transient run needs a command");
    assert!(
        err.to_string().contains("command"),
        "unexpected error: {err}"
    );
}

#[test]
fn run_defaults_match_the_lower_level_runner() {
    let args = parse_run(&["run", "--image", "alpine", "--", "true"]).expect("parse");
    assert_eq!(args.run.cpus, 2);
    assert_eq!(args.run.memory, "512M");
    assert_eq!(
        args.run.profile,
        RunProfile::Standard,
        "`machine run` and `mvmctl run` share one default"
    );
    assert!(!args.run.json);
    assert!(!args.run.dry_run);
    assert!(args.run.mounts.is_empty());
    assert!(args.run.env.is_empty());
    assert!(args.name.is_none());
    assert!(!args.detach);
    assert!(!args.tty);
    assert!(!args.interactive);
}

#[test]
fn run_accepts_passthrough_flags() {
    let args = parse_run(&[
        "run",
        "--image",
        "alpine",
        "--cpus",
        "4",
        "--memory",
        "1G",
        "--profile",
        "dev",
        "--volume",
        "/host:/work:rw",
        "-e",
        "FOO=bar",
        "--timeout",
        "30",
        "--json",
        "--dry-run",
        "--",
        "uname",
        "-a",
    ])
    .expect("parse");
    assert_eq!(args.run.cpus, 4);
    assert_eq!(args.run.memory, "1G");
    assert_eq!(args.run.profile, RunProfile::Dev);
    assert_eq!(args.run.mounts, vec!["/host:/work:rw"]);
    assert_eq!(args.run.env, vec!["FOO=bar"]);
    assert_eq!(args.run.timeout, Some(30));
    assert!(args.run.json);
    assert!(args.run.dry_run);
    assert_eq!(args.run.argv, vec!["uname", "-a"]);
}

#[test]
fn volume_flag_carries_live_mount_and_d_is_detach() {
    let args = parse_run(&[
        "run",
        "--image",
        "alpine",
        "--volume",
        "/host:/work:rw",
        "--",
        "true",
    ])
    .expect("parse");
    assert_eq!(args.run.mounts, vec!["/host:/work:rw"]);
    let forwarded = args.clone().into_run_args_for_test();
    assert_eq!(forwarded.mounts, vec!["/host:/work:rw"]);
    // `-d` now means --detach, so it must NOT consume the following value as
    // a dir share.
    let detached = parse_run(&["run", "--image", "alpine", "-d"]).expect("parse");
    assert!(detached.detach);
    assert!(detached.run.mounts.is_empty());
}

#[test]
fn run_port_is_repeatable_and_implies_persistence() {
    let args = parse_run(&[
        "run",
        "--image",
        "alpine",
        "--port",
        "8080:3000",
        "-p",
        "9090",
    ])
    .expect("parse port forwards");

    assert_eq!(args.port, vec!["8080:3000", "9090"]);
    assert!(args.persistent(), "a forward needs a live machine owner");
    assert_eq!(
        args.resolve_mode().expect("port forward resolves"),
        MachineRunMode::Persistent
    );
    assert_eq!(post_start_action(&args), PostStart::Attach);
}

#[test]
fn run_port_rejects_invalid_mappings_and_supports_detached_ownership() {
    let invalid = parse_run(&["run", "--image", "alpine", "--port", "abc:3000"])
        .expect_err("invalid ports must fail during CLI parsing");
    assert_eq!(invalid.kind(), clap::error::ErrorKind::ValueValidation);

    let detached = parse_run(&[
        "run",
        "--image",
        "alpine",
        "--port",
        "8080:3000",
        "--detach",
    ])
    .expect("declared ingress belongs to the persistent machine, not the foreground CLI");
    assert_eq!(detached.port, vec!["8080:3000"]);
    assert!(detached.detach);
    assert_eq!(
        detached.resolve_mode().expect("detached ingress resolves"),
        MachineRunMode::Persistent
    );
    assert_eq!(post_start_action(&detached), PostStart::PrintId);

    let with_command = parse_run(&[
        "run",
        "--image",
        "alpine",
        "--port",
        "8080:3000",
        "--",
        "python",
        "-m",
        "http.server",
    ])
    .expect("the trailing command is syntactically valid");
    assert_eq!(
        with_command
            .resolve_mode()
            .expect("declared FlowMux ingress and a foreground service share one owner"),
        MachineRunMode::Persistent
    );
}

#[test]
fn detach_short_and_long_imply_persistence() {
    for argv in [
        &["run", "--image", "alpine", "-d"][..],
        &["run", "--image", "alpine", "--detach"][..],
    ] {
        let args = parse_run(argv).expect("parse");
        assert!(args.detach, "argv {argv:?}");
        assert!(args.persistent(), "argv {argv:?}");
        assert!(!args.interactive());
    }
}

#[test]
fn name_is_identity_not_persistence() {
    let args =
        parse_run(&["run", "--image", "alpine", "--name", "web", "--", "true"]).expect("parse");
    assert_eq!(args.name.as_deref(), Some("web"));
    assert!(!args.persistent());
    assert!(!args.detach);
    assert!(!args.interactive());
}

#[test]
fn tty_long_short_alias_and_it_bundle_request_interactivity() {
    for argv in [
        &["run", "--image", "alpine", "--tty"][..],
        &["run", "--image", "alpine", "-t"][..],
        &["run", "--image", "alpine", "-i"][..],
        &["run", "--image", "alpine", "-it"][..],
    ] {
        let args = parse_run(argv).expect("parse");
        assert!(args.interactive(), "argv {argv:?}");
        // Interactivity alone never implies persistence.
        assert!(!args.persistent(), "argv {argv:?}");
    }
}

#[test]
fn resolve_mode_covers_the_behavior_matrix() {
    let cases: &[(&[&str], MachineRunMode)] = &[
        (
            &["run", "--image", "X", "--", "cmd"],
            MachineRunMode::Transient,
        ),
        (
            &["run", "-it", "--image", "X", "--", "/bin/sh"],
            MachineRunMode::InteractiveTransient,
        ),
        (
            &["run", "--name", "web", "--image", "X", "--", "cmd"],
            MachineRunMode::Transient,
        ),
        (&["run", "-d", "--image", "X"], MachineRunMode::Persistent),
        (
            &["run", "-d", "--name", "web", "--image", "X"],
            MachineRunMode::Persistent,
        ),
        // `--up-json` implies Persistent (SDK boot-and-return path).
        (
            &["run", "--up-json", "--manifest", "tmpl"],
            MachineRunMode::Persistent,
        ),
        (
            &[
                "run", "-it", "--name", "web", "--image", "X", "--", "/bin/sh",
            ],
            MachineRunMode::InteractiveTransient,
        ),
    ];
    for (argv, expected) in cases {
        let args = parse_run(argv).expect("parse");
        let mode = args.resolve_mode().expect("resolve");
        assert_eq!(mode, *expected, "argv {argv:?}");
    }
}

#[test]
fn resolve_mode_wasm_allows_empty_argv() {
    // The wasm backend runs the module itself; no guest-agent command is
    // required, so a transient run with an empty argv is valid.
    let args = parse_run(&[
        "run",
        "--hypervisor",
        "wasm",
        "--manifest",
        "fixture/mvm.toml",
    ])
    .expect("parse");
    assert_eq!(
        args.resolve_mode().expect("resolve"),
        MachineRunMode::Transient
    );
}

#[test]
fn resolve_mode_accepts_materialized_flake_slot_after_build() {
    let mut args = parse_run(&["run", "--flake", ".", "--", "cmd"]).expect("parse");
    let flake = args.run.flake.take().expect("flake source present");
    assert_eq!(flake, ".");
    args.run.manifest = Some("materialized-slot".to_string());

    let mode = args.resolve_mode().expect("materialized flake is a source");

    assert_eq!(mode, MachineRunMode::Transient);
}

#[test]
fn interactive_run_requires_foreground_argv() {
    let args = parse_run(&["run", "-t", "--image", "X"]).expect("parse");
    let err = args.resolve_mode().expect_err("interactive run needs argv");
    assert!(err.to_string().contains("command after `--`"));
}

#[test]
fn warm_pool_size_is_claim_eligible_only_for_throwaway_runs() {
    // Unnamed transient + interactive-transient are cattle → eligible:
    // an explicit override is honoured verbatim (the residency-policy default
    // for `None` is env-dependent, so the override path is the deterministic
    // assertion).
    assert_eq!(MachineRunMode::Transient.warm_pool_size(Some(3), false), 3);
    assert_eq!(
        MachineRunMode::InteractiveTransient.warm_pool_size(Some(2), false),
        2
    );
    // A user-named foreground run has an observable identity, so it never
    // reuses pool cattle.
    assert_eq!(MachineRunMode::Transient.warm_pool_size(Some(3), true), 0);
    assert_eq!(
        MachineRunMode::InteractiveTransient.warm_pool_size(Some(2), true),
        0
    );
    // A persistent machine is long-lived, never pooled — size 0 regardless
    // of any override.
    assert_eq!(MachineRunMode::Persistent.warm_pool_size(Some(5), false), 0);
    assert_eq!(MachineRunMode::Persistent.warm_pool_size(None, true), 0);
}

#[test]
fn auto_generated_machine_name_is_a_valid_vm_name() {
    let name = auto_machine_name();
    mvm_core::naming::validate_vm_name(&name)
        .unwrap_or_else(|e| panic!("auto name {name:?} invalid: {e}"));
}

#[test]
fn detach_resolves_to_an_auto_name_and_named_uses_the_given_name() {
    let named = parse_run(&["run", "--image", "x", "--name", "web"]).expect("parse");
    assert_eq!(resolve_machine_run_name(&named).expect("name"), "web");

    let detached = parse_run(&["run", "--image", "x", "-d"]).expect("parse");
    let auto = resolve_machine_run_name(&detached).expect("name");
    mvm_core::naming::validate_vm_name(&auto).expect("auto name valid");
    assert_ne!(auto, "web");
}

fn spec_fixture(name: &str) -> MachineSpec {
    MachineSpec {
        schema_version: MACHINE_SPEC_SCHEMA_VERSION,
        name: name.to_string(),
        image: Some("alpine:latest".to_string()),
        manifest: None,
        deployment: None,
        resolved_digest: None,
        runtime_pack: false,
        net: false,
        allow_host: vec![],
        peer: Vec::new(),
        ai: None,
        ports: vec![],
        cpus: 2,
        memory: "512M".to_string(),
        mem_initial: None,
        profile: "standard".to_string(),
        volumes: vec![],
        init: vec![],
        agent_verb: vec![],
        created_at: None,
        last_started_at: None,
        health_check: None,
        grants: None,
    }
}

#[test]
fn run_spec_maps_run_args_into_a_machine_spec() {
    let args = parse_run(&[
        "run",
        "--image",
        "alpine:3.20",
        "--name",
        "web",
        "--cpus",
        "4",
        "--memory",
        "1G",
        "--profile",
        "dev",
        "--net",
        "--allow-host",
        "api.example.com:443",
    ])
    .expect("parse");
    let spec = machine_run_spec(&args, "web".to_string(), None).expect("spec");
    assert_eq!(spec.name, "web");
    assert_eq!(spec.image.as_deref(), Some("alpine:3.20"));
    assert_eq!(spec.cpus, 4);
    assert_eq!(spec.memory, "1G");
    assert_eq!(spec.profile, "dev");
    assert!(spec.net);
    assert_eq!(spec.allow_host, vec!["api.example.com:443"]);
    // Disk volumes / init are not part of the `run` surface.
    assert!(spec.volumes.is_empty());
    assert!(spec.init.is_empty());
    // No --agent-verb: spec stores an empty list (computed default applies at start).
    assert!(spec.agent_verb.is_empty());
}

#[test]
fn deployment_source_is_verified_and_persisted_as_canonical_directory() {
    let dir = tempfile::tempdir().expect("deployment dir");
    let rootfs = dir.path().join("rootfs.ext4");
    std::fs::write(&rootfs, b"rootfs bytes").expect("rootfs");
    let boot_artifact = mvm_sdk::deploy::digest_boot_artifact(&rootfs).expect("digest");
    let record = mvm_sdk::deploy::DeployRecord {
        schema_version: mvm_sdk::deploy::DEPLOY_RECORD_SCHEMA_VERSION,
        workload_id: "demo".to_string(),
        ir_hash: "ir".to_string(),
        image: mvm_sdk::deploy::ArtifactDigests {
            blake3: "0".repeat(64),
            sha256: "0".repeat(64),
            size_bytes: 0,
        },
        boot_artifact,
        environment: None,
        dependency_volume: None,
    };
    mvm_sdk::deploy::write_deploy_record(&record, &dir.path().join("deploy.json")).expect("record");

    let args = parse_run(&[
        "run",
        "--deployment",
        dir.path().to_str().expect("utf8 path"),
        "--name",
        "web",
        "-d",
    ])
    .expect("parse");
    let spec = machine_run_spec(&args, "web".to_string(), None).expect("spec");
    assert_eq!(
        spec.deployment.as_deref(),
        Some(
            dir.path()
                .canonicalize()
                .expect("canonical")
                .to_str()
                .expect("utf8")
        )
    );
    assert!(spec.image.is_none());
    assert!(spec.manifest.is_none());

    std::fs::write(&rootfs, b"tampered").expect("tamper");
    let err = resolve_local_deployment(dir.path()).expect_err("tampered rootfs refused");
    assert!(
        err.to_string()
            .contains("verifying deployment boot artifact")
    );
}

#[test]
fn agent_verb_flag_persisted_in_spec_and_survives_roundtrip() {
    let _state = IsolatedMachineState::new();
    let args = parse_run(&[
        "run",
        "--image",
        "alpine:3.20",
        "--name",
        "web",
        "--agent-verb",
        "run-entrypoint",
        "--agent-verb",
        "resolve-secret",
    ])
    .expect("parse");
    let spec = machine_run_spec(&args, "web".to_string(), None).expect("spec");
    assert_eq!(
        spec.agent_verb,
        vec!["run-entrypoint".to_string(), "resolve-secret".to_string()]
    );
    // Round-trip: save → load preserves the verb list.
    save_machine_spec(&spec, false).expect("save");
    let loaded = load_machine_spec("web").expect("load");
    assert_eq!(loaded.agent_verb, spec.agent_verb);
    // When the field is absent from the JSON (old spec), deserializes as empty.
    let path = config::machine_spec_path("other");
    atomic_write(
        &path,
        br#"{
              "schema_version": 1,
              "name": "other",
              "image": "alpine:latest",
              "net": false,
              "allow_host": [],
              "cpus": 2,
              "memory": "512M",
              "profile": "standard"
            }"#,
    )
    .expect("write");
    let old = load_machine_spec("other").expect("load old spec without agent_verb");
    assert!(
        old.agent_verb.is_empty(),
        "missing field must default to empty"
    );
}

#[test]
fn run_volume_is_threaded_into_managed_spec_with_absolute_host() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let host = dir.path().to_string_lossy().into_owned();
    let args = parse_run(&[
        "run",
        "--image",
        "x",
        "--name",
        "web",
        "--volume",
        &format!("{host}:/work:ro"),
    ])
    .expect("parse");
    let spec = machine_run_spec(&args, "web".to_string(), None).expect("spec");
    assert_eq!(spec.volumes.len(), 1);
    let stored = &spec.volumes[0];
    // Host pinned to an absolute (canonicalized) path so a reconnect from a
    // different cwd still resolves; the guest+mode tail is preserved verbatim.
    let host_part = stored.split(':').next().unwrap();
    assert!(
        std::path::Path::new(host_part).is_absolute(),
        "host not absolute: {stored}"
    );
    assert!(stored.ends_with(":/work:ro"), "stored: {stored}");
}

#[test]
fn run_rw_volume_requires_dev_profile() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let host = dir.path().to_string_lossy().into_owned();
    // The default is `standard`, so a writable share is refused unless the user
    // asks for `dev` explicitly. It refuses at spec time with the flag to pass,
    // rather than quietly handing the guest a read-only mount it will fail to
    // write to later.
    let default_args = parse_run(&[
        "run",
        "--image",
        "x",
        "--name",
        "web",
        "--volume",
        &format!("{host}:/work:rw"),
    ])
    .expect("parse");
    let default_err = machine_run_spec(&default_args, "web".to_string(), None)
        .expect_err(":rw is not in the default profile");
    assert!(
        default_err.to_string().contains("profile dev"),
        "the refusal must name the flag that grants it: {default_err}"
    );

    // An explicitly stricter profile still refuses the writable share.
    let std_args = parse_run(&[
        "run",
        "--image",
        "x",
        "--name",
        "web",
        "--profile",
        "standard",
        "--volume",
        &format!("{host}:/work:rw"),
    ])
    .expect("parse");
    let err = machine_run_spec(&std_args, "web".to_string(), None)
        .expect_err(":rw needs a dev-capable profile");
    assert!(err.to_string().contains("profile dev"), "msg: {err}");

    // With --profile dev the writable share is accepted.
    let dev_args = parse_run(&[
        "run",
        "--image",
        "x",
        "--name",
        "web",
        "--profile",
        "dev",
        "--volume",
        &format!("{host}:/work:rw"),
    ])
    .expect("parse");
    let spec =
        machine_run_spec(&dev_args, "web".to_string(), None).expect("dev profile allows :rw");
    assert!(
        spec.volumes[0].ends_with(":/work:rw"),
        "stored: {}",
        spec.volumes[0]
    );
}

#[test]
fn persistent_spec_reconnects_without_image_and_errors_when_absent() {
    // No `--image`: reconnect to the existing spec verbatim.
    let reconnect = parse_run(&["run", "--name", "web"]).expect("parse");
    let existing = spec_fixture("web");
    let (spec, action) = resolve_persistent_spec(&reconnect, "web", Some(existing.clone()), None)
        .expect("reconnect");
    assert_eq!(action, SpecReconcile::Reuse);
    assert_eq!(spec, existing);

    // No `--image` and no on-disk spec: a clear "does not exist" error.
    let err = resolve_persistent_spec(&reconnect, "web", None, None)
        .expect_err("reconnect to a missing machine errors");
    assert!(err.to_string().contains("does not exist"), "msg: {err}");
}

#[test]
fn interactive_requires_a_host_tty() {
    require_tty(true).expect("a host TTY is allowed");
    let err = require_tty(false).expect_err("no TTY must be refused, not left to hang");
    let msg = err.to_string().to_lowercase();
    assert!(
        msg.contains("tty") || msg.contains("terminal") || msg.contains("interactive"),
        "msg: {msg}"
    );
}

#[test]
fn interactive_refuses_a_sealed_machine_via_the_claim15_gate() {
    let _guard = mvm_runtime::vm::runtime_meta::HOME_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let mut env = TestEnv::new();
    let tmp = tempfile::tempdir().expect("tempdir");
    env.set("HOME", tmp.path());
    env.set("MVM_HOME", tmp.path());
    let name = "sealed-machine";
    mvm_runtime::vm::runtime_meta::write(
        name,
        &mvm_runtime::vm::runtime_meta::VmRuntimeMeta {
            mode: mvm_runtime::vm::runtime_meta::StartModeKind::Detached,
            accessible: false,
            rootfs_path: None,
            runtime_overlay_version: None,
            observability_target: None,
        },
    )
    .expect("write sealed runtime meta");
    // The interactive path reuses console's claim-15 gate before attaching.
    let err = super::super::vm::console::enforce_accessible_gate(name, false)
        .expect_err("a sealed machine must be refused");
    assert!(err.to_string().contains("sealed image"), "msg: {err}");
}

#[test]
fn resolve_machine_build_mode_is_fail_closed_and_reads_accessible() {
    let _guard = mvm_runtime::vm::runtime_meta::HOME_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let mut env = TestEnv::new();
    let tmp = tempfile::tempdir().expect("tempdir");
    env.set("HOME", tmp.path());
    env.set("MVM_HOME", tmp.path());

    // No manifest, no runtime meta → fail-closed to prod. This is the value
    // `Sandbox.connect(id)` inherits its dev-only exec guard from, so a machine
    // the CLI cannot positively classify must never resolve to dev.
    assert_eq!(
        super::runtime::resolve_machine_build_mode(None, "ghost"),
        "prod"
    );

    let write_meta = |name: &str, accessible: bool| {
        mvm_runtime::vm::runtime_meta::write(
            name,
            &mvm_runtime::vm::runtime_meta::VmRuntimeMeta {
                mode: mvm_runtime::vm::runtime_meta::StartModeKind::Detached,
                accessible,
                rootfs_path: None,
                runtime_overlay_version: None,
                observability_target: None,
            },
        )
        .expect("write runtime meta");
    };
    write_meta("dev-machine", true);
    write_meta("sealed-machine", false);
    assert_eq!(
        super::runtime::resolve_machine_build_mode(None, "dev-machine"),
        "dev"
    );
    assert_eq!(
        super::runtime::resolve_machine_build_mode(None, "sealed-machine"),
        "prod"
    );
}

#[test]
fn translation_is_an_image_backed_transient_run() {
    let args = parse_run(&[
        "run",
        "--image",
        "alpine",
        "--json",
        "--dry-run",
        "--",
        "echo",
        "hi",
    ])
    .expect("parse");
    let run = args.into_run_args();
    // Image-backed: never a manifest, never a launch plan.
    assert_eq!(run.image.as_deref(), Some("alpine"));
    assert!(run.manifest.is_none());
    assert!(run.launch_plan.is_none());
    // OCI prod-pin stays off — `machine run` doesn't expose it.
    assert!(!run.prod);
    // User-facing flags flow through untouched.
    assert!(run.json);
    assert!(run.dry_run);
    assert_eq!(run.argv, vec!["echo", "hi"]);
}

#[test]
fn agent_verb_forwarded_to_run_args_on_transient_path() {
    // `--agent-verb` on a transient run (no --name/-d) must flow into
    // RunArgs.agent_verb so the transient admit site uses it instead of
    // falling back to the computed default.
    let args = parse_run(&[
        "run",
        "--image",
        "alpine",
        "--agent-verb",
        "run-entrypoint",
        "--agent-verb",
        "ping",
        "--",
        "true",
    ])
    .expect("parse");
    let run = args.into_run_args();
    assert_eq!(run.agent_verb, vec!["run-entrypoint", "ping"]);
}

#[test]
fn agent_verb_empty_on_transient_path_when_not_specified() {
    let args = parse_run(&["run", "--image", "alpine", "--", "true"]).expect("parse");
    let run = args.into_run_args();
    assert!(run.agent_verb.is_empty());
}

#[test]
fn rust_sdk_machine_run_uses_cli_default_deny_preflight() {
    let sdk_args = mvm_sdk::MachineRun::builder()
        .image("alpine:latest")
        .command(["true"])
        .dry_run(true)
        .json(true)
        .machine_args()
        .expect("sdk machine run args");

    let run = parse_owned_run(&sdk_args)
        .expect("sdk args parse as CLI machine run")
        .into_run_args();
    let summary = super::super::vm::exec::test_run_security_summary(&run, "firecracker")
        .expect("CLI preflight accepts SDK args");

    assert!(summary.dry_run);
    assert!(!summary.will_execute);
    assert_eq!(summary.image_kind, "oci");
    assert_eq!(summary.preflight_network_posture, "deny-all");
    assert_eq!(summary.preflight_egress_enforcement, "flow-drop");
    assert_eq!(summary.receipt_network_posture, "deny-all");
    assert_eq!(summary.receipt_egress_enforcement, "flow-drop");
}

#[test]
fn rust_sdk_machine_run_allow_host_matches_cli_receipt_posture() {
    let sdk_args = mvm_sdk::MachineRun::builder()
        .image("alpine:latest")
        .allow_host("api.example.com")
        .receipt("/tmp/mvm-sdk-machine.receipt.json")
        .dry_run(true)
        .json(true)
        .command(["true"])
        .machine_args()
        .expect("sdk machine run args");

    let run = parse_owned_run(&sdk_args)
        .expect("sdk args parse as CLI machine run")
        .into_run_args();
    let summary = super::super::vm::exec::test_run_security_summary_with_preflight_backend(
        &run,
        SDK_RUN_EGRESS_BACKEND,
        SDK_RUN_EGRESS_BACKEND,
    )
    .expect("CLI receipt input accepts SDK args");

    assert_eq!(
        summary.preflight_network_posture,
        "allow-list:api.example.com:443"
    );
    assert!(summary.receipt_requested);
    assert_eq!(
        summary.receipt_network_posture,
        summary.preflight_network_posture
    );
    assert_eq!(
        summary.receipt_egress_enforcement,
        SDK_RUN_EGRESS_ENFORCEMENT
    );
}

#[test]
fn rust_sdk_machine_run_matches_cli_admission_and_receipt_inputs() {
    let sdk_args = mvm_sdk::MachineRun::builder()
        .image("alpine:latest")
        .allow_host("api.example.com")
        .cpus(4)
        .memory("1G")
        .profile("dev")
        .volume("/tmp/mvm-sdk-src:/work:ro")
        .env("TOKEN=secret")
        .env("MODE=test")
        .timeout(30)
        .receipt("/tmp/mvm-sdk-machine.receipt.json")
        .json(true)
        .dry_run(true)
        .command(["sh", "-lc", "echo ok"])
        .machine_args()
        .expect("sdk machine run args");
    assert_eq!(sdk_args, sdk_machine_fixture("run-admission"));

    let run = parse_owned_run(&sdk_args)
        .expect("sdk args parse as CLI machine run")
        .into_run_args();
    let summary = super::super::vm::exec::test_run_security_summary_with_preflight_backend(
        &run,
        SDK_RUN_EGRESS_BACKEND,
        SDK_RUN_EGRESS_BACKEND,
    )
    .expect("CLI receipt input accepts SDK args");

    assert_sdk_run_admission_inputs(summary);
}

#[test]
fn python_typescript_machine_run_default_fixture_uses_cli_default_deny_preflight() {
    let sdk_args = sdk_machine_fixture("run-default");
    let run = parse_owned_run(&sdk_args)
        .expect("Python/TypeScript SDK fixture parses as CLI machine run")
        .into_run_args();
    let summary = super::super::vm::exec::test_run_security_summary(&run, "firecracker")
        .expect("CLI preflight accepts Python/TypeScript SDK fixture");

    assert!(summary.dry_run);
    assert!(!summary.will_execute);
    assert_eq!(summary.image_kind, "oci");
    assert_eq!(summary.preflight_network_posture, "deny-all");
    assert_eq!(summary.preflight_egress_enforcement, "flow-drop");
    assert_eq!(summary.receipt_network_posture, "deny-all");
    assert_eq!(summary.receipt_egress_enforcement, "flow-drop");
}

#[test]
fn python_typescript_machine_run_allow_host_fixture_matches_cli_receipt_posture() {
    let sdk_args = sdk_machine_fixture("run-allow-host-receipt");
    let run = parse_owned_run(&sdk_args)
        .expect("Python/TypeScript SDK fixture parses as CLI machine run")
        .into_run_args();
    let summary = super::super::vm::exec::test_run_security_summary_with_preflight_backend(
        &run,
        SDK_RUN_EGRESS_BACKEND,
        SDK_RUN_EGRESS_BACKEND,
    )
    .expect("CLI receipt input accepts Python/TypeScript SDK fixture");

    assert_eq!(
        summary.preflight_network_posture,
        "allow-list:api.example.com:443"
    );
    assert!(summary.receipt_requested);
    assert_eq!(
        summary.receipt_network_posture,
        summary.preflight_network_posture
    );
    assert_eq!(
        summary.receipt_egress_enforcement,
        SDK_RUN_EGRESS_ENFORCEMENT
    );
}

#[test]
fn python_typescript_machine_run_fixture_matches_cli_admission_and_receipt_inputs() {
    let sdk_args = sdk_machine_fixture("run-admission");
    let run = parse_owned_run(&sdk_args)
        .expect("Python/TypeScript SDK fixture parses as CLI machine run")
        .into_run_args();
    let summary = super::super::vm::exec::test_run_security_summary_with_preflight_backend(
        &run,
        SDK_RUN_EGRESS_BACKEND,
        SDK_RUN_EGRESS_BACKEND,
    )
    .expect("CLI receipt input accepts Python/TypeScript SDK fixture");

    assert_sdk_run_admission_inputs(summary);
}

#[test]
fn rust_sdk_machine_create_manifest_reaches_cli_unknown_key_gate() {
    let sdk_args = mvm_sdk::MachineCreate::builder("web")
        .manifest("mvm.toml")
        .profile("dev")
        .force(true)
        .json(true)
        .machine_args()
        .expect("sdk machine create args");
    assert_eq!(sdk_args, sdk_machine_fixture("create-manifest"));

    assert_manifest_fixture_reaches_unknown_key_gate(sdk_args);
}

#[test]
fn python_typescript_machine_create_manifest_fixture_reaches_cli_unknown_key_gate() {
    assert_manifest_fixture_reaches_unknown_key_gate(sdk_machine_fixture("create-manifest"));
}

#[test]
fn create_parses_persistent_spec_flags() {
    let action = parse(&[
        "create",
        "web",
        "--image",
        "ghcr.io/acme/web:latest",
        "--net",
        "--allow-host",
        "api.example.com:443",
        "--cpus",
        "4",
        "--memory",
        "1G",
        "--profile",
        "dev",
        "--json",
        "--force",
    ])
    .expect("parse");
    match action {
        MachineAction::Create(args) => {
            assert_eq!(args.name.as_deref(), Some("web"));
            assert_eq!(args.image.as_deref(), Some("ghcr.io/acme/web:latest"));
            assert!(args.net);
            assert_eq!(args.allow_host, vec!["api.example.com:443"]);
            assert_eq!(args.cpus, Some(4));
            assert_eq!(args.memory.as_deref(), Some("1G"));
            assert_eq!(args.profile, Some(RunProfile::Dev));
            assert!(args.json);
            assert!(args.force);
        }
        other => panic!("expected create action, got {other:?}"),
    }
}

#[test]
fn readme_persistent_machine_workflow_parses() {
    let create = parse(&[
        "create", "web", "--image", "nginx", "--cpus", "2", "--memory", "512M",
    ])
    .expect("README machine create command parses");
    let MachineAction::Create(create) = create else {
        panic!("expected create action");
    };
    assert_eq!(create.name.as_deref(), Some("web"));

    assert!(matches!(
        parse(&["start", "web"]).expect("README machine start command parses"),
        MachineAction::Start(_)
    ));
    assert!(matches!(
        parse(&["exec", "web", "--", "nginx", "-v"]).expect("README machine exec command parses"),
        MachineAction::Exec(_)
    ));
    assert!(matches!(
        parse(&["logs", "web"]).expect("README machine logs command parses"),
        MachineAction::Logs(_)
    ));
    assert!(matches!(
        parse(&["reconfigure", "web", "--memory", "1G"])
            .expect("README machine reconfigure command parses"),
        MachineAction::Reconfigure(_)
    ));
    assert!(matches!(
        parse(&["stop", "web"]).expect("README machine stop command parses"),
        MachineAction::Stop(_)
    ));
    assert!(matches!(
        parse(&["rm", "web"]).expect("README machine rm command parses"),
        MachineAction::Rm(_)
    ));
    assert!(matches!(
        parse(&["ls"]).expect("README machine ls command parses"),
        MachineAction::Ls(_)
    ));
    assert!(matches!(
        parse(&["inspect", "web"]).expect("README machine inspect command parses"),
        MachineAction::Inspect(_)
    ));
}

#[test]
fn list_inspect_and_remove_parse() {
    match parse(&["ls", "--json"]).expect("parse") {
        MachineAction::Ls(args) => assert!(args.json),
        other => panic!("expected ls action, got {other:?}"),
    }
    // `ps` is a docker-style visible alias for `ls`.
    match parse(&["ps", "--json"]).expect("parse ps alias") {
        MachineAction::Ls(args) => assert!(args.json),
        other => panic!("expected ls action from `ps`, got {other:?}"),
    }
    match parse(&[
        "start",
        "web",
        "--receipt",
        "/tmp/web.receipt.json",
        "--json",
        "--dry-run",
    ])
    .expect("parse")
    {
        MachineAction::Start(args) => {
            assert_eq!(args.names, vec!["web"]);
            assert_eq!(
                args.receipt.as_deref(),
                Some(Path::new("/tmp/web.receipt.json"))
            );
            assert!(args.json);
            assert!(args.dry_run);
        }
        other => panic!("expected start action, got {other:?}"),
    }
    match parse(&["inspect", "web", "--json"]).expect("parse") {
        MachineAction::Inspect(args) => {
            assert_eq!(args.name, "web");
            assert!(args.json);
        }
        other => panic!("expected inspect action, got {other:?}"),
    }
    match parse(&["rm", "web", "--yes", "--json"]).expect("parse") {
        MachineAction::Rm(args) => {
            assert_eq!(args.names, vec!["web"]);
            assert!(!args.all);
            assert!(args.yes);
            assert!(args.json);
        }
        other => panic!("expected rm action, got {other:?}"),
    }
}

#[test]
fn rm_parses_multiple_names_and_all() {
    match parse(&["rm", "web", "db", "cache", "--yes"]).expect("parse") {
        MachineAction::Rm(args) => {
            assert_eq!(args.names, vec!["web", "db", "cache"]);
            assert!(!args.all);
            assert!(args.yes);
        }
        other => panic!("expected rm action, got {other:?}"),
    }
    match parse(&["rm", "--all", "--yes"]).expect("parse") {
        MachineAction::Rm(args) => {
            assert!(args.names.is_empty());
            assert!(args.all);
            assert!(args.yes);
            assert!(!args.force, "force defaults off");
        }
        other => panic!("expected rm action, got {other:?}"),
    }
    match parse(&["rm", "web", "--yes", "--force"]).expect("parse") {
        MachineAction::Rm(args) => {
            assert_eq!(args.names, vec!["web"]);
            assert!(args.force);
        }
        other => panic!("expected rm action, got {other:?}"),
    }
}

#[test]
fn rm_requires_a_target_and_rejects_names_with_all() {
    // Bare `rm` names no machine and doesn't pass --all.
    let err = parse(&["rm", "--yes"]).expect_err("a target is required");
    assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
    // --all is mutually exclusive with explicit names.
    let err = parse(&["rm", "web", "--all", "--yes"]).expect_err("names conflict with --all");
    assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
}

#[test]
fn start_quiet_is_internal_only_and_defaults_off() {
    // `quiet` is an internal `MachineStartArgs` field, never a CLI flag —
    // the standalone `machine start` path keeps printing the boot banner.
    match parse(&["start", "web"]).expect("parse") {
        MachineAction::Start(args) => assert_eq!(args.names, vec!["web"]),
        other => panic!("expected start action, got {other:?}"),
    }
    assert!(
        parse(&["start", "web", "--quiet"]).is_err(),
        "--quiet must not be exposed as a CLI flag"
    );
}

#[test]
fn start_parses_multiple_names_and_refuses_single_machine_flags_in_batch() {
    match parse(&["start", "web", "db", "cache"]).expect("parse batch") {
        MachineAction::Start(cmd) => assert_eq!(cmd.names, vec!["web", "db", "cache"]),
        other => panic!("expected start action, got {other:?}"),
    }
    // `--receipt`/`--json`/`--dry-run` report on one machine; a batch is
    // refused before any boot is attempted.
    let MachineAction::Start(cmd) =
        parse(&["start", "web", "db", "--receipt", "/tmp/r.json"]).expect("parse")
    else {
        panic!("expected start action");
    };
    let err = run_start(cmd).expect_err("receipt + batch is refused");
    assert!(err.to_string().contains("single machine"), "msg: {err}");
}

#[test]
fn start_requires_at_least_one_name() {
    let err = parse(&["start"]).expect_err("a machine name is required");
    assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
}

#[test]
fn restart_parses_names_and_flags() {
    match parse(&["restart", "web", "db"]).expect("parse restart batch") {
        MachineAction::Restart(cmd) => assert_eq!(cmd.names, vec!["web", "db"]),
        other => panic!("expected restart action, got {other:?}"),
    }
    match parse(&["restart", "web", "--hypervisor", "mock"]).expect("parse restart") {
        MachineAction::Restart(cmd) => {
            assert_eq!(cmd.names, vec!["web"]);
            assert_eq!(cmd.hypervisor.as_deref(), Some("mock"));
        }
        other => panic!("expected restart action, got {other:?}"),
    }
    let err = parse(&["restart"]).expect_err("a machine name is required");
    assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
}

#[test]
fn already_running_notice_wording() {
    assert_eq!(
        already_running_notice("web", false),
        "machine web is already running"
    );
    let json: serde_json::Value =
        serde_json::from_str(&already_running_notice("web", true)).expect("valid json");
    assert_eq!(json["machine"], "web");
    assert_eq!(json["already_running"], true);
}

#[test]
fn humanize_age_buckets() {
    let now = chrono::DateTime::parse_from_rfc3339("2026-01-02T00:00:00Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    let ago = |s: &str| humanize_age(Some(s), now);
    assert_eq!(ago("2026-01-01T23:59:30Z"), "just now");
    assert_eq!(ago("2026-01-01T23:30:00Z"), "30m");
    assert_eq!(ago("2026-01-01T20:00:00Z"), "4h");
    assert_eq!(ago("2025-12-30T00:00:00Z"), "3d");
    assert_eq!(humanize_age(None, now), "-");
    assert_eq!(humanize_age(Some("not-a-date"), now), "-");
    // A future timestamp (clock skew) degrades to "-" rather than a negative.
    assert_eq!(ago("2026-01-02T01:00:00Z"), "-");
}

#[test]
fn health_cell_maps_readiness() {
    use mvm_core::domain::instance::InstanceReadiness::{
        Degraded, ServicesReady, ServicesStarting,
    };

    assert_eq!(health_cell(Some(&ServicesReady)), "healthy");
    assert_eq!(
        health_cell(Some(&Degraded { unhealthy: vec![] })),
        "unhealthy"
    );
    assert_eq!(
        health_cell(Some(&ServicesStarting { pending: vec![] })),
        "starting"
    );
    assert_eq!(health_cell(None), "-");
}

#[test]
fn exec_shell_and_stop_parse() {
    match parse(&["exec", "web", "--", "echo", "hello world"]).expect("parse") {
        MachineAction::Exec(args) => {
            assert_eq!(args.name, "web");
            assert_eq!(args.argv, vec!["echo", "hello world"]);
            assert!(!args.force);
            assert!(!args.tty);
            assert!(!args.interactive);
        }
        other => panic!("expected exec action, got {other:?}"),
    }
    match parse(&["shell", "web", "--force"]).expect("parse") {
        MachineAction::Shell(args) => {
            assert_eq!(args.name, "web");
            assert!(args.force);
        }
        other => panic!("expected shell action, got {other:?}"),
    }
    match parse(&["set-timeout", "web", "60"]).expect("parse") {
        MachineAction::SetTimeout(args) => {
            assert_eq!(args.name, "web");
            assert_eq!(args.seconds, 60);
        }
        other => panic!("expected set-timeout action, got {other:?}"),
    }
    match parse(&["stop", "web"]).expect("parse") {
        MachineAction::Stop(args) => {
            assert_eq!(args.names, vec!["web"]);
            assert!(!args.all);
        }
        other => panic!("expected stop action, got {other:?}"),
    }
}

#[test]
fn exec_argv_is_optional_for_interactive_shell() {
    // `machine exec <name>` with no argv parses and yields an empty argv,
    // which the handler turns into an interactive shell (like `machine shell`).
    match parse(&["exec", "web"]).expect("parse") {
        MachineAction::Exec(args) => {
            assert_eq!(args.name, "web");
            assert!(args.argv.is_empty());
        }
        other => panic!("expected exec action, got {other:?}"),
    }
}

#[test]
fn exec_accepts_it_for_pty_command() {
    match parse(&["exec", "web", "-it", "--", "/bin/sh"]).expect("parse") {
        MachineAction::Exec(args) => {
            assert_eq!(args.name, "web");
            assert!(args.tty);
            assert!(args.interactive);
            assert_eq!(args.argv, vec!["/bin/sh"]);
        }
        other => panic!("expected exec action, got {other:?}"),
    }
}

#[test]
fn machine_exec_command_quotes_argv_for_guest_exec() {
    let argv = vec![
        "printf".to_string(),
        "hello %s\n".to_string(),
        "it's ok".to_string(),
    ];
    assert_eq!(
        machine_exec_command(&argv),
        "exec 'printf' 'hello %s\n' 'it'\\''s ok'"
    );
}

#[test]
fn mark_machine_started_sets_digest_and_timestamp() {
    let mut spec = MachineSpec {
        schema_version: MACHINE_SPEC_SCHEMA_VERSION,
        name: "web".to_string(),
        image: Some("alpine:latest".to_string()),
        manifest: None,
        deployment: None,
        resolved_digest: None,
        runtime_pack: false,
        net: false,
        allow_host: Vec::new(),
        peer: Vec::new(),
        ai: None,
        ports: vec![],
        cpus: 2,
        memory: "512M".to_string(),
        mem_initial: None,
        profile: "standard".to_string(),
        volumes: Vec::new(),
        init: Vec::new(),
        agent_verb: Vec::new(),
        created_at: Some("2026-06-18T00:00:00Z".to_string()),
        last_started_at: None,
        health_check: None,
        grants: None,
    };
    mark_machine_started(&mut spec, "sha256:abc".to_string());
    assert_eq!(spec.resolved_digest.as_deref(), Some("sha256:abc"));
    assert!(spec.last_started_at.is_some());
}

#[test]
fn create_persists_machine_spec_under_data_dir() {
    let _state = IsolatedMachineState::new();
    let args = MachineCreateArgs {
        name: Some("web".to_string()),
        manifest: None,
        image: Some("alpine:latest".to_string()),
        net: true,
        allow_host: vec!["api.example.com".to_string()],
        peer: Vec::new(),
        cpus: Some(4),
        cpu_limit: None,
        timeout: None,
        grants_file: None,
        memory: Some("1G".to_string()),
        mem_initial: None,
        profile: Some(RunProfile::Dev),
        force: false,
        json: false,
    };
    let spec = args.into_spec().expect("spec");
    save_machine_spec(&spec, false).expect("save");

    let path = config::machine_spec_path("web");
    assert!(path.exists(), "spec path should exist: {}", path.display());
    let loaded = load_machine_spec("web").expect("load");
    assert_eq!(loaded, spec);
    assert_eq!(loaded.schema_version, MACHINE_SPEC_SCHEMA_VERSION);
    assert!(loaded.created_at.is_some());
    assert!(loaded.last_started_at.is_none());
}

#[test]
fn create_auto_generates_a_name_when_omitted() {
    let _state = IsolatedMachineState::new();
    let spec = MachineCreateArgs {
        name: None,
        manifest: None,
        image: Some("alpine:latest".to_string()),
        net: false,
        allow_host: Vec::new(),
        peer: Vec::new(),
        cpus: None,
        cpu_limit: None,
        timeout: None,
        grants_file: None,
        memory: None,
        mem_initial: None,
        profile: None,
        force: false,
        json: false,
    }
    .into_spec()
    .expect("auto-named spec");
    // A generated name is present and passes the same validation as an
    // explicit one, so a subsequent `start`/`ls`/`rm` can reference it.
    assert!(!spec.name.is_empty());
    validate_machine_name(&spec.name).expect("generated name is valid");
    assert_eq!(spec.profile, "dev");
}

#[test]
fn create_sources_machine_defaults_from_manifest() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(dir.path().join("src")).expect("src dir");
    std::fs::write(
        dir.path().join("mvm.toml"),
        r#"
image = "python:3.12-alpine"
net = true
cpus = 4
mem = "2G"
mem_initial = "512M"

[network]
allow_hosts = ["api.example.com"]

[dev]
init = ["pip install -r requirements.txt"]
volumes = ["./src:/work:rw"]
"#,
    )
    .expect("manifest");

    let spec = MachineCreateArgs {
        name: Some("web".to_string()),
        manifest: Some(dir.path().join("mvm.toml").display().to_string()),
        image: None,
        net: false,
        allow_host: Vec::new(),
        peer: Vec::new(),
        cpus: None,
        cpu_limit: None,
        timeout: None,
        grants_file: None,
        memory: None,
        mem_initial: None,
        profile: Some(RunProfile::Dev),
        force: false,
        json: false,
    }
    .into_spec()
    .expect("manifest-backed spec");

    assert_eq!(spec.image.as_deref(), Some("python:3.12-alpine"));
    assert!(spec.net);
    assert_eq!(spec.allow_host, vec!["api.example.com"]);
    assert_eq!(spec.cpus, 4);
    assert_eq!(spec.memory, "2G");
    assert_eq!(spec.mem_initial.as_deref(), Some("512M"));
    assert_eq!(spec.profile, "dev");
    assert_eq!(spec.init, vec!["pip install -r requirements.txt"]);
    assert_eq!(
        spec.volumes,
        vec![format!("{}:/work:rw", dir.path().join("src").display())]
    );
}

#[test]
fn create_rejects_flake_backed_manifest_for_machine_specs() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("mvm.toml"), "flake = \".\"\n").expect("manifest");
    let err = MachineCreateArgs {
        name: Some("web".to_string()),
        manifest: Some(dir.path().join("mvm.toml").display().to_string()),
        image: None,
        net: false,
        allow_host: Vec::new(),
        peer: Vec::new(),
        cpus: None,
        cpu_limit: None,
        timeout: None,
        grants_file: None,
        memory: None,
        mem_initial: None,
        profile: None,
        force: false,
        json: false,
    }
    .into_spec()
    .expect_err("flake manifest rejected");
    assert!(
        err.to_string()
            .contains("requires an image-backed manifest")
    );
}

#[test]
fn create_defaults_to_dev_profile_when_manifest_declares_dev_init() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        dir.path().join("mvm.toml"),
        "image = \"alpine:latest\"\n[dev]\ninit = [\"echo hi\"]\n",
    )
    .expect("manifest");
    let spec = MachineCreateArgs {
        name: Some("web".to_string()),
        manifest: Some(dir.path().join("mvm.toml").display().to_string()),
        image: None,
        net: false,
        allow_host: Vec::new(),
        peer: Vec::new(),
        cpus: None,
        cpu_limit: None,
        timeout: None,
        grants_file: None,
        memory: None,
        mem_initial: None,
        profile: None,
        force: false,
        json: false,
    }
    .into_spec()
    .expect("CLI-created machines default to dev");
    assert_eq!(spec.profile, "dev");

    let err = MachineCreateArgs {
        name: Some("web".to_string()),
        manifest: Some(dir.path().join("mvm.toml").display().to_string()),
        image: None,
        net: false,
        allow_host: Vec::new(),
        peer: Vec::new(),
        cpus: None,
        cpu_limit: None,
        timeout: None,
        grants_file: None,
        memory: None,
        mem_initial: None,
        profile: Some(RunProfile::Standard),
        force: false,
        json: false,
    }
    .into_spec()
    .expect_err("explicit standard profile should refuse dev.init");
    assert!(
        err.to_string()
            .contains("dev.init requires a dev-capable profile")
    );
}

#[test]
fn machine_start_receipt_input_redacts_host_paths_and_surfaces_policy() {
    let spec = MachineSpec {
        schema_version: MACHINE_SPEC_SCHEMA_VERSION,
        name: "web".to_string(),
        image: Some("ghcr.io/acme/web:latest".to_string()),
        manifest: None,
        deployment: None,
        resolved_digest: Some("sha256:abc".to_string()),
        runtime_pack: false,
        net: false,
        allow_host: vec!["api.example.com".to_string()],
        peer: Vec::new(),
        ai: None,
        ports: vec![],
        cpus: 4,
        memory: "2G".to_string(),
        mem_initial: Some("512M".to_string()),
        profile: "dev".to_string(),
        volumes: vec!["/Users/example/src:/work:rw".to_string()],
        init: vec!["pip install -r requirements.txt".to_string()],
        agent_verb: Vec::new(),
        created_at: Some("2026-06-18T00:00:00Z".to_string()),
        last_started_at: None,
        health_check: None,
        grants: None,
    };

    let summary = machine_start_preflight_summary(
        &spec,
        Some("libkrun"),
        Some(Path::new("/tmp/web.receipt.json")),
    )
    .expect("preflight summary");
    assert_eq!(
        summary.invocation.network_posture,
        "allow-list:api.example.com:443"
    );
    assert_eq!(summary.invocation.volumes.len(), 1);
    assert_eq!(summary.invocation.volumes[0].kind, "dir_share");
    assert!(!summary.invocation.volumes[0].host_path_sha256.is_empty());
    assert_eq!(summary.invocation.volumes[0].guest_path, "/work");
    assert!(!summary.invocation.volumes[0].read_only);
    assert_eq!(summary.invocation.init.command_count, 1);
    let json = serde_json::to_string(&summary).expect("summary json");
    assert!(!json.contains("/Users/example/src"));
    assert!(json.contains("allow-list:api.example.com:443"));
}

#[test]
fn machine_start_receipt_is_signed_and_verifiable() {
    let _state = IsolatedMachineState::new();
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("machine-start.receipt.json");
    let invocation = MachineStartReceiptInput {
        machine_name: "web".to_string(),
        image: Some("ghcr.io/acme/web:latest".to_string()),
        manifest: None,
        deployment: None,
        resolved_digest: Some("sha256:abc".to_string()),
        cpus: 2,
        memory: "512M".to_string(),
        mem_initial: None,
        profile: "standard".to_string(),
        network_posture: "deny-all".to_string(),
        egress_enforcement: "flow-drop".to_string(),
        volumes: Vec::new(),
        init: MachineStartInitPolicy {
            command_count: 0,
            script_sha256: None,
        },
    };
    let outcome = MachineStartReceiptOutcome {
        resolved_digest: "sha256:abc".to_string(),
        started_at: "2026-06-18T00:00:00Z".to_string(),
        init_commands_executed: 0,
    };

    write_machine_start_receipt(&path, invocation.clone(), outcome.clone()).expect("receipt");
    let verified = verify_machine_start_receipt(&path, None).expect("verified receipt");
    assert_eq!(
        verified.payload.invocation.machine_name,
        invocation.machine_name
    );
    assert_eq!(
        verified.payload.outcome.resolved_digest,
        outcome.resolved_digest
    );
    assert_eq!(verified.signature.signer_id, host_signer_id());
}

#[test]
fn machine_start_preflight_reports_uniform_l4_enforcement_for_oci_allow_host() {
    let spec = MachineSpec {
        schema_version: MACHINE_SPEC_SCHEMA_VERSION,
        name: "web".to_string(),
        image: Some("ghcr.io/acme/web:latest".to_string()),
        manifest: None,
        deployment: None,
        resolved_digest: None,
        runtime_pack: false,
        net: false,
        allow_host: vec!["api.example.com".to_string()],
        peer: Vec::new(),
        ai: None,
        ports: vec![],
        cpus: 2,
        memory: "512M".to_string(),
        mem_initial: None,
        profile: "dev".to_string(),
        volumes: Vec::new(),
        init: Vec::new(),
        agent_verb: Vec::new(),
        created_at: Some("2026-06-18T00:00:00Z".to_string()),
        last_started_at: None,
        health_check: None,
        grants: None,
    };

    let summary = machine_start_preflight_summary(&spec, Some("libkrun"), None)
        .expect("libkrun OCI allow-host preflight should summarize the active vsock/L4 contract");
    assert_eq!(
        summary.invocation.network_posture,
        "allow-list:api.example.com:443"
    );
    assert_eq!(
        summary.invocation.egress_enforcement,
        "libkrun:l4-host-port"
    );
}

#[test]
fn create_rejects_unsafe_machine_name() {
    let args = MachineCreateArgs {
        name: Some("../web".to_string()),
        manifest: None,
        image: Some("alpine:latest".to_string()),
        net: false,
        allow_host: Vec::new(),
        peer: Vec::new(),
        cpus: Some(2),
        cpu_limit: None,
        timeout: None,
        grants_file: None,
        memory: Some("512M".to_string()),
        mem_initial: None,
        profile: Some(RunProfile::Standard),
        force: false,
        json: false,
    };
    let err = args.into_spec().expect_err("unsafe name rejected");
    assert!(err.to_string().contains("machine name ID"));
}

#[test]
fn create_refuses_overwrite_without_force() {
    let _state = IsolatedMachineState::new();
    let spec = MachineSpec {
        schema_version: MACHINE_SPEC_SCHEMA_VERSION,
        name: "web".to_string(),
        image: Some("alpine:latest".to_string()),
        manifest: None,
        deployment: None,
        resolved_digest: None,
        runtime_pack: false,
        net: false,
        allow_host: Vec::new(),
        peer: Vec::new(),
        ai: None,
        ports: vec![],
        cpus: 2,
        memory: "512M".to_string(),
        mem_initial: None,
        profile: "standard".to_string(),
        volumes: Vec::new(),
        init: Vec::new(),
        agent_verb: Vec::new(),
        created_at: Some(mvm_core::time::utc_now()),
        last_started_at: None,
        health_check: None,
        grants: None,
    };
    save_machine_spec(&spec, false).expect("first save");
    let err = save_machine_spec(&spec, false).expect_err("overwrite rejected");
    assert!(err.to_string().contains("already exists"));
    save_machine_spec(&spec, true).expect("force overwrites");
}

#[test]
fn remove_machine_spec_requires_confirmation_and_deletes_dir() {
    let _state = IsolatedMachineState::new();
    let spec = MachineSpec {
        schema_version: MACHINE_SPEC_SCHEMA_VERSION,
        name: "web".to_string(),
        image: Some("alpine:latest".to_string()),
        manifest: None,
        deployment: None,
        resolved_digest: None,
        runtime_pack: false,
        net: false,
        allow_host: Vec::new(),
        peer: Vec::new(),
        ai: None,
        ports: vec![],
        cpus: 2,
        memory: "512M".to_string(),
        mem_initial: None,
        profile: "standard".to_string(),
        volumes: Vec::new(),
        init: Vec::new(),
        agent_verb: Vec::new(),
        created_at: Some(mvm_core::time::utc_now()),
        last_started_at: None,
        health_check: None,
        grants: None,
    };
    save_machine_spec(&spec, false).expect("save");
    let err = remove_machine_spec("web", false).expect_err("confirmation required");
    assert!(err.to_string().contains("without --yes"));

    let summary = remove_machine_spec("web", true).expect("remove");
    assert_eq!(summary.name, "web");
    assert!(summary.removed);
    assert!(!config::machine_state_dir("web").exists());
}

fn seed_machine_spec(name: &str) {
    let spec = MachineSpec {
        schema_version: MACHINE_SPEC_SCHEMA_VERSION,
        name: name.to_string(),
        image: Some(format!("example/{name}:latest")),
        manifest: None,
        deployment: None,
        resolved_digest: None,
        runtime_pack: false,
        net: false,
        allow_host: Vec::new(),
        peer: Vec::new(),
        ai: None,
        ports: vec![],
        cpus: 2,
        memory: "512M".to_string(),
        mem_initial: None,
        profile: "standard".to_string(),
        volumes: Vec::new(),
        init: Vec::new(),
        agent_verb: Vec::new(),
        created_at: Some(mvm_core::time::utc_now()),
        last_started_at: None,
        health_check: None,
        grants: None,
    };
    save_machine_spec(&spec, false).expect("save");
}

fn rm_args(names: &[&str], all: bool, yes: bool) -> MachineRemoveArgs {
    MachineRemoveArgs {
        names: names.iter().map(|n| n.to_string()).collect(),
        all,
        yes,
        force: false,
        json: false,
    }
}

/// Seed the runtime state directory a booted machine leaves under `vms/`,
/// which is a different namespace from the `machines/` spec.
fn seed_runtime_state(name: &str) -> std::path::PathBuf {
    let dir = config::vm_state_dir(name);
    std::fs::create_dir_all(&dir).expect("state dir");
    std::fs::write(dir.join("console.log"), b"boot log").expect("console log");
    dir
}

#[test]
fn removing_a_machine_removes_its_runtime_state_not_only_its_spec() {
    // `machine rm` deletes `machines/<name>/`. It used to stop there, so a
    // removed machine kept its console log, sockets and pid file under
    // `vms/<name>/` forever — and `machine ls`, which reads that directory,
    // kept listing it.
    let _state = IsolatedMachineState::new();
    seed_machine_spec("web");
    let runtime = seed_runtime_state("web");
    assert!(runtime.exists());

    remove_machine(rm_args(&["web"], false, true)).expect("remove");

    assert!(
        !config::machine_state_dir("web").exists(),
        "the spec must still be removed",
    );
    assert!(
        !runtime.exists(),
        "the runtime state directory outlived the machine it belonged to",
    );
}

#[test]
fn removing_a_machine_with_no_runtime_state_is_not_an_error() {
    // A machine created but never booted has a spec and no `vms/` entry.
    let _state = IsolatedMachineState::new();
    seed_machine_spec("web");
    assert!(!config::vm_state_dir("web").exists());
    remove_machine(rm_args(&["web"], false, true)).expect("remove");
    assert!(!config::machine_state_dir("web").exists());
}

#[test]
fn runtime_state_owned_by_a_live_process_is_left_alone() {
    // The case that makes this more than a cleanup: `--force` asks the machine
    // to stop but only warns if the stop failed, so "we asked" is not "nothing
    // is using this". Deleting a live supervisor's pid file and sockets would
    // strand it, so a directory the liveness probe still claims is kept.
    let _state = IsolatedMachineState::new();
    let dir = config::vm_state_dir("web");
    std::fs::create_dir_all(&dir).expect("state dir");
    // Our own pid: the probe's definition of a live owner.
    std::fs::write(dir.join("libkrun.pid"), std::process::id().to_string()).expect("pid file");
    assert!(
        mvm_vmm::host::process_liveness::state_dir_has_live_process(&dir),
        "the probe must see this as live, or the test proves nothing",
    );

    assert!(!remove_machine_runtime_state("web").expect("probe"));
    assert!(dir.exists(), "state owned by a live process must survive");
}

#[test]
fn rm_running_refusal_wording() {
    assert!(rm_running_refusal(&[]).is_none());
    let msg = rm_running_refusal(&["web".to_string(), "db".to_string()])
        .expect("running machines refuse");
    assert!(msg.contains("web, db"), "lists the running names: {msg}");
    assert!(msg.contains("machine stop web db"), "hints stop: {msg}");
    assert!(msg.contains("--force"), "mentions --force: {msg}");
}

#[test]
fn remove_machine_deletes_multiple_named_specs() {
    let _state = IsolatedMachineState::new();
    for name in ["web", "db", "cache"] {
        seed_machine_spec(name);
    }
    remove_machine(rm_args(&["web", "cache"], false, true)).expect("remove batch");
    assert!(!config::machine_state_dir("web").exists());
    assert!(!config::machine_state_dir("cache").exists());
    // Untargeted machine is untouched.
    assert!(config::machine_state_dir("db").exists());
}

#[test]
fn remove_machine_all_deletes_every_spec() {
    let _state = IsolatedMachineState::new();
    for name in ["web", "db", "cache"] {
        seed_machine_spec(name);
    }
    remove_machine(rm_args(&[], true, true)).expect("remove all");
    assert!(list_machine_specs().expect("list").is_empty());
}

#[test]
fn remove_machine_all_on_empty_store_is_a_noop() {
    let _state = IsolatedMachineState::new();
    remove_machine(rm_args(&[], true, true)).expect("remove all on empty store");
}

#[test]
fn remove_machine_batch_declines_without_confirmation_and_keeps_all_specs() {
    let _state = IsolatedMachineState::new();
    for name in ["web", "db"] {
        seed_machine_spec(name);
    }
    // No `--yes` on a non-interactive stdin: the prompt is declined, nothing
    // is removed, and it is not an error (mirrors `machine stop`).
    remove_machine(rm_args(&["web", "db"], false, false)).expect("declined without error");
    assert!(config::machine_state_dir("web").exists());
    assert!(config::machine_state_dir("db").exists());
}

#[test]
fn remove_machine_batch_is_all_or_nothing_on_a_missing_spec() {
    let _state = IsolatedMachineState::new();
    seed_machine_spec("web");
    let err = remove_machine(rm_args(&["web", "ghost"], false, true))
        .expect_err("missing spec aborts the batch");
    assert!(err.to_string().contains("does not exist"));
    // The valid target survives because validation precedes deletion.
    assert!(config::machine_state_dir("web").exists());
}

#[test]
fn resolve_remove_targets_dedupes_named_and_enumerates_all() {
    let _state = IsolatedMachineState::new();
    for name in ["alpha", "zeta"] {
        seed_machine_spec(name);
    }
    let named = resolve_remove_targets(
        false,
        &["web".to_string(), "db".to_string(), "web".to_string()],
    )
    .expect("resolve named");
    assert_eq!(named, vec!["web", "db"]);
    let all = resolve_remove_targets(true, &[]).expect("resolve all");
    assert_eq!(all, vec!["alpha", "zeta"]);
}

/// Named for what it drives: `load_machine_spec` itself. The `shell`/`exec`
/// wrappers no longer go through it — they gate on `require_console_target`,
/// which admits a transient with no spec.
#[test]
fn loading_a_missing_machine_spec_names_the_recovery_verbs() {
    let _state = IsolatedMachineState::new();
    let err = load_machine_spec("web").expect_err("missing spec rejected");
    let msg = format!("{err:#}");
    // Actionable not-found: names the machine and points at the recovery verbs.
    assert!(msg.contains("machine \"web\" does not exist"), "msg: {msg}");
    assert!(msg.contains("machine ls"), "msg: {msg}");
    assert!(msg.contains("machine create"), "msg: {msg}");
}

/// `machine shell`/`exec` used to gate on a persisted spec, which a
/// transient VM from `machine run` never has — so the console was refused for
/// a machine `machine ls` was listing as running. The gate is existence now,
/// and a transient's existence is its runtime state dir.
#[test]
fn console_target_accepts_a_transient_vm_with_no_spec() {
    let _state = IsolatedMachineState::new();
    std::fs::create_dir_all(config::vm_state_dir("adhoc")).expect("seed runtime state");
    lifecycle::require_console_target("adhoc").expect("a live transient is a console target");
}

#[test]
fn console_target_accepts_a_created_machine_that_has_never_booted() {
    let _state = IsolatedMachineState::new();
    seed_machine_spec("web");
    lifecycle::require_console_target("web").expect("a created machine is a console target");
}

#[test]
fn console_target_rejects_a_name_with_neither_spec_nor_state() {
    let _state = IsolatedMachineState::new();
    let msg = format!(
        "{:#}",
        lifecycle::require_console_target("ghost").expect_err("unknown name rejected")
    );
    assert!(
        msg.contains("machine \"ghost\" does not exist"),
        "msg: {msg}"
    );
    assert!(msg.contains("machine ls"), "msg: {msg}");
}

/// Relaxing the gate to "has a runtime state dir" must not open the builder
/// VM, which stages its state in the same directory and is headless: it
/// serves no agent and no PTY, so admitting it would swap a wrong error for a
/// hang.
#[test]
fn console_target_rejects_an_internal_builder_vm_by_name() {
    let _state = IsolatedMachineState::new();
    let job = mvm_core::naming::builder_shell_vm_name("92326-1787337475138993000");
    std::fs::create_dir_all(config::vm_state_dir(&job)).expect("seed builder state");
    let msg = format!(
        "{:#}",
        lifecycle::require_console_target(&job).expect_err("builder VM is not a console target")
    );
    assert!(msg.contains("internal builder VM"), "msg: {msg}");
    assert!(msg.contains("headless"), "msg: {msg}");
}

#[test]
fn top_level_cli_routes_machine_run() {
    let cli = Cli::try_parse_from([
        "mvmctl", "machine", "run", "--image", "alpine", "--", "echo", "hi",
    ])
    .expect("top-level parse");
    match cli.command {
        Commands::Machine(args) => match args.action {
            MachineAction::Run(run) => {
                assert_eq!(run.run.image.as_deref(), Some("alpine"));
                assert_eq!(run.run.argv, vec!["echo", "hi"]);
            }
            other => panic!("expected run action, got {other:?}"),
        },
        other => panic!("expected Commands::Machine, got {other:?}"),
    }
}

#[test]
fn top_level_cli_routes_machine_create() {
    let cli = Cli::try_parse_from(["mvmctl", "machine", "create", "web", "--image", "alpine"])
        .expect("top-level parse");
    match cli.command {
        Commands::Machine(args) => match args.action {
            MachineAction::Create(create) => {
                assert_eq!(create.name.as_deref(), Some("web"));
                assert_eq!(create.image.as_deref(), Some("alpine"));
            }
            other => panic!("expected create action, got {other:?}"),
        },
        other => panic!("expected Commands::Machine, got {other:?}"),
    }
}

#[test]
fn top_level_cli_routes_machine_start() {
    let cli = Cli::try_parse_from([
        "mvmctl",
        "machine",
        "start",
        "web",
        "--receipt",
        "/tmp/web.receipt.json",
        "--json",
        "--dry-run",
    ])
    .expect("top-level parse");
    match cli.command {
        Commands::Machine(args) => match args.action {
            MachineAction::Start(start) => {
                assert_eq!(start.names, vec!["web"]);
                assert_eq!(
                    start.receipt.as_deref(),
                    Some(Path::new("/tmp/web.receipt.json"))
                );
                assert!(start.json);
                assert!(start.dry_run);
            }
            other => panic!("expected start action, got {other:?}"),
        },
        other => panic!("expected Commands::Machine, got {other:?}"),
    }
}

#[test]
fn top_level_cli_routes_machine_exec() {
    let cli = Cli::try_parse_from(["mvmctl", "machine", "exec", "web", "--", "echo", "hi"])
        .expect("top-level parse");
    match cli.command {
        Commands::Machine(args) => match args.action {
            MachineAction::Exec(exec) => {
                assert_eq!(exec.name, "web");
                assert_eq!(exec.argv, vec!["echo", "hi"]);
            }
            other => panic!("expected exec action, got {other:?}"),
        },
        other => panic!("expected Commands::Machine, got {other:?}"),
    }
}

#[test]
fn top_level_cli_routes_machine_set_timeout() {
    let cli = Cli::try_parse_from(["mvmctl", "machine", "set-timeout", "web", "60"])
        .expect("top-level parse");
    match cli.command {
        Commands::Machine(args) => match args.action {
            MachineAction::SetTimeout(timeout) => {
                assert_eq!(timeout.name, "web");
                assert_eq!(timeout.seconds, 60);
            }
            other => panic!("expected set-timeout action, got {other:?}"),
        },
        other => panic!("expected Commands::Machine, got {other:?}"),
    }
}

#[test]
fn machine_stop_named_and_all_parse() {
    match parse(&["stop", "web"]).expect("parse named") {
        MachineAction::Stop(args) => {
            assert_eq!(args.names, vec!["web"]);
            assert!(!args.all);
            assert!(!args.yes, "confirmation is required by default");
        }
        other => panic!("expected stop action, got {other:?}"),
    }
    // Multiple names stop as a batch.
    match parse(&["stop", "web", "db", "cache"]).expect("parse batch") {
        MachineAction::Stop(args) => {
            assert_eq!(args.names, vec!["web", "db", "cache"]);
            assert!(!args.all);
        }
        other => panic!("expected stop action, got {other:?}"),
    }
    match parse(&["stop", "--all"]).expect("parse --all") {
        MachineAction::Stop(args) => {
            assert!(args.names.is_empty());
            assert!(args.all);
            assert!(!args.yes);
        }
        other => panic!("expected stop action, got {other:?}"),
    }
}

#[test]
fn machine_stop_yes_skips_confirmation() {
    match parse(&["stop", "web", "--yes"]).expect("parse named --yes") {
        MachineAction::Stop(args) => {
            assert_eq!(args.names, vec!["web"]);
            assert!(args.yes);
        }
        other => panic!("expected stop action, got {other:?}"),
    }
    match parse(&["stop", "--all", "--yes"]).expect("parse --all --yes") {
        MachineAction::Stop(args) => {
            assert!(args.all);
            assert!(args.yes);
        }
        other => panic!("expected stop action, got {other:?}"),
    }
}

#[test]
fn machine_stop_without_tty_refuses_with_an_error() {
    let err = super::lifecycle::confirm_stop(false, false, || {
        panic!("a non-interactive stop must not try to prompt")
    })
    .expect_err("non-interactive stop without --yes must fail");

    assert!(
        err.to_string().contains("pass --yes"),
        "error must tell automation how to proceed: {err:#}"
    );
}

#[test]
fn machine_stop_yes_bypasses_confirmation_without_a_tty() {
    super::lifecycle::confirm_stop(true, false, || {
        panic!("--yes must bypass the confirmation prompt")
    })
    .expect("--yes must permit a non-interactive stop");
}

#[test]
fn machine_stop_declined_at_tty_refuses_with_an_error() {
    let err = super::lifecycle::confirm_stop(false, true, || false)
        .expect_err("declining a stop must not report success");

    assert!(
        err.to_string().contains("aborted"),
        "unexpected error: {err:#}"
    );
}

#[test]
fn machine_stop_requires_target() {
    let err = parse(&["stop"]).expect_err("no name and no --all must be rejected");
    assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
}

#[test]
fn machine_stop_name_and_all_conflict() {
    let err = parse(&["stop", "web", "--all"]).expect_err("name + --all must be a parse error");
    assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
}

#[test]
fn machine_advanced_verbs_parse() {
    use super::super::vm::group::VmCmd;

    // pause
    let r = parse(&["pause", "myvm", "--hypervisor", "mock"]);
    assert!(
        matches!(r, Ok(MachineAction::Vm(VmCmd::Pause(_)))),
        "pause: {r:?}"
    );

    // snapshot (subcommand with sub-subcommand)
    let r = parse(&["snapshot", "ls"]);
    assert!(
        matches!(r, Ok(MachineAction::Vm(VmCmd::Snapshot(_)))),
        "snapshot ls: {r:?}"
    );

    // cp
    let r = parse(&["cp", "myvm", "host.txt:/guest.txt"]);
    assert!(
        matches!(r, Ok(MachineAction::Vm(VmCmd::Cp(_)))),
        "cp: {r:?}"
    );

    // fs
    let r = parse(&["fs", "ls", "myvm", "/"]);
    assert!(
        matches!(r, Ok(MachineAction::Vm(VmCmd::Fs(_)))),
        "fs: {r:?}"
    );

    // proc
    let r = parse(&["proc", "ls", "myvm"]);
    assert!(
        matches!(r, Ok(MachineAction::Vm(VmCmd::Proc(_)))),
        "proc: {r:?}"
    );

    // session
    let r = parse(&["session", "ls"]);
    assert!(
        matches!(r, Ok(MachineAction::Vm(VmCmd::Session(_)))),
        "session: {r:?}"
    );

    // volume
    let r = parse(&["volume", "ls", "myvm"]);
    assert!(
        matches!(r, Ok(MachineAction::Vm(VmCmd::Volume(_)))),
        "volume: {r:?}"
    );

    // sandbox
    let r = parse(&["sandbox", "gc"]);
    assert!(
        matches!(r, Ok(MachineAction::Vm(VmCmd::Sandbox(_)))),
        "sandbox: {r:?}"
    );
}

#[test]
fn machine_vm_op_uses_per_op_audit_verb() {
    // Folded advanced ops keep their own `cmd.<verb>.*` audit verb (no
    // regression from the vm→machine move); the dash-renamed `set-ttl`
    // is the edge case that proves the clap name, not the enum variant.
    let action = parse(&["pause", "myvm", "--hypervisor", "mock"]).unwrap();
    assert_eq!(action.verb_name(), "pause");
    let action = parse(&["snapshot", "ls"]).unwrap();
    assert_eq!(action.verb_name(), "snapshot");
    let action = parse(&["set-ttl", "myvm", "5m"]).unwrap();
    assert_eq!(action.verb_name(), "set-ttl");
}

#[test]
fn machine_native_verb_audit_stays_machine() {
    // Native lifecycle verbs report `machine`, as they always have.
    assert_eq!(parse(&["stop", "web"]).unwrap().verb_name(), "machine");
    assert_eq!(parse(&["ls"]).unwrap().verb_name(), "machine");
}

#[test]
fn machine_run_json_reserves_stdout() {
    // `machine run --json` streams structured JSON, so the stdout guard
    // must fire (preserved from the retired `run --json`); without it, off.
    let on =
        Cli::try_parse_from(["mvmctl", "machine", "run", "--image", "alpine", "--json"]).unwrap();
    assert!(on.command.emits_machine_readable_stdout());
    let off = Cli::try_parse_from(["mvmctl", "machine", "run", "--image", "alpine"]).unwrap();
    assert!(!off.command.emits_machine_readable_stdout());
}

#[test]
fn vm_noun_removed() {
    use clap::error::ErrorKind;
    // After Task 7, `mvmctl vm <verb>` must not parse.
    let err = Cli::try_parse_from(["mvmctl", "vm", "pause", "myvm"])
        .expect_err("vm noun must be removed");
    assert_eq!(
        err.kind(),
        ErrorKind::InvalidSubcommand,
        "expected InvalidSubcommand, got: {err:?}"
    );
}

#[test]
fn machine_help_hides_advanced() {
    // `machine --help` must NOT list `snapshot`, but `machine snapshot <name>` must parse.
    let help = {
        let mut cmd = Cli::command();
        let machine_sub = cmd.find_subcommand_mut("machine").unwrap();
        format!("{}", machine_sub.render_help())
    };
    assert!(
        !help.contains("snapshot"),
        "`snapshot` must be hidden from `machine --help` output. Help text:\n{help}"
    );
    // But it still parses.
    let r = parse(&["snapshot", "ls"]);
    assert!(
        r.is_ok(),
        "`machine snapshot ls` must parse even when hidden from help: {r:?}"
    );
}

fn reconfigure_spec_fixture() -> MachineSpec {
    MachineSpec {
        schema_version: MACHINE_SPEC_SCHEMA_VERSION,
        name: "web".into(),
        image: Some("img:1".into()),
        manifest: None,
        deployment: None,
        resolved_digest: None,
        runtime_pack: false,
        net: false,
        allow_host: vec![],
        peer: Vec::new(),
        ai: None,
        ports: vec![],
        cpus: 2,
        memory: "512M".into(),
        mem_initial: None,
        profile: "standard".into(),
        volumes: vec!["/data:/data:ro".into()],
        init: vec![],
        agent_verb: vec![],
        created_at: None,
        last_started_at: None,
        health_check: None,
        grants: None,
    }
}

fn reconfigure_args_fixture(name: &str) -> MachineReconfigureArgs {
    MachineReconfigureArgs {
        name: name.into(),
        net: false,
        no_net: false,
        allow_host: vec![],
        clear_allow_host: false,
        cpus: None,
        memory: None,
        mem_initial: None,
        hypervisor: None,
    }
}

#[test]
fn apply_patch_overrides_only_set_fields_and_preserves_rest() {
    let mut args = reconfigure_args_fixture("web");
    args.cpus = Some(8);
    let patch = patch_from_args(&args).unwrap();
    let out = apply_patch(reconfigure_spec_fixture(), &patch);
    assert_eq!(out.cpus, 8);
    // Everything else preserved.
    assert_eq!(out.memory, "512M");
    assert_eq!(out.volumes, vec!["/data:/data:ro".to_string()]);
    assert!(!out.net);
}

#[test]
fn apply_patch_no_flags_is_noop() {
    let patch = patch_from_args(&reconfigure_args_fixture("web")).unwrap();
    assert_eq!(
        apply_patch(reconfigure_spec_fixture(), &patch),
        reconfigure_spec_fixture()
    );
}

#[test]
fn patch_net_is_tri_state() {
    let mut on = reconfigure_args_fixture("web");
    on.net = true;
    assert_eq!(patch_from_args(&on).unwrap().net, Some(true));
    let mut off = reconfigure_args_fixture("web");
    off.no_net = true;
    assert_eq!(patch_from_args(&off).unwrap().net, Some(false));
    assert_eq!(
        patch_from_args(&reconfigure_args_fixture("web"))
            .unwrap()
            .net,
        None
    );
}

#[test]
fn patch_allow_host_replace_and_clear() {
    let mut replace = reconfigure_args_fixture("web");
    replace.allow_host = vec!["a:443".into()];
    let out = apply_patch(
        reconfigure_spec_fixture(),
        &patch_from_args(&replace).unwrap(),
    );
    assert_eq!(out.allow_host, vec!["a:443".to_string()]);

    let base = MachineSpec {
        allow_host: vec!["old:443".into()],
        peer: Vec::new(),
        ai: None,
        ports: vec![],
        ..reconfigure_spec_fixture()
    };
    let mut clear = reconfigure_args_fixture("web");
    clear.clear_allow_host = true;
    let out = apply_patch(base, &patch_from_args(&clear).unwrap());
    assert!(out.allow_host.is_empty());
}

#[test]
fn patch_rejects_invalid_memory() {
    let mut args = reconfigure_args_fixture("web");
    args.memory = Some("notasize".into());
    assert!(patch_from_args(&args).is_err());
}

#[test]
fn reconfigure_unknown_machine_errors_clearly() {
    let _state = IsolatedMachineState::new();
    let mut args = reconfigure_args_fixture("does-not-exist");
    args.cpus = Some(4);
    let err = run_reconfigure(args).unwrap_err();
    assert!(
        err.to_string().contains("does not exist"),
        "unexpected error: {err}"
    );
}

#[test]
fn reconfigure_mem_initial_inconsistency_rejected() {
    // Validate that run_reconfigure rejects an inconsistent mem_initial
    // even when only --mem-initial is passed (no --memory). This tests the
    // post-apply re-validation added in Task 5 (Addition 2).
    let _state = IsolatedMachineState::new();
    // Persist a valid machine spec directly so the machine "exists".
    let spec = reconfigure_spec_fixture();
    save_machine_spec(&spec, false).expect("save fixture spec");
    // Now try to reconfigure with a mem_initial that exceeds the existing
    // memory (512M), which must be caught by the post-apply validator.
    let mut args = reconfigure_args_fixture("web");
    args.mem_initial = Some("1G".into()); // 1G > 512M → invalid
    let err = run_reconfigure(args).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("invalid machine memory after reconfigure")
            || msg.contains("mem_initial")
            || msg.contains("must be strictly less than"),
        "unexpected error: {err}"
    );
}

// ── revert / rewind / advance verb surface ────────────────────────────────

#[test]
fn revert_parses_target_and_kind() {
    let action = parse(&["revert", "sha256:abc", "--kind", "image"]).expect("parse revert");
    match action {
        MachineAction::Revert(a) => {
            assert_eq!(a.target, "sha256:abc");
            // `--kind image` is accepted and captured (the variant internals stay
            // private to the checkpoint module; parse acceptance is the contract).
            assert!(a.kind.is_some());
        }
        other => panic!("expected revert, got {other:?}"),
    }
    // An unknown --kind is rejected by clap's value-enum.
    assert!(parse(&["revert", "sha256:abc", "--kind", "bogus"]).is_err());
}

#[test]
fn rewind_parses_as_its_own_verb() {
    let action = parse(&["rewind", "ckpt-x"]).expect("parse rewind");
    assert!(matches!(action, MachineAction::Rewind(_)));
    assert_eq!(machine_subcommand(&action), "rewind");
}

/// The lineage forward-step is `advance`, deliberately NOT `forward` — the
/// latter remains a parsing-compatible migration boundary. Both must parse to
/// distinct, non-colliding actions.
#[test]
fn advance_does_not_collide_with_the_port_forward_verb() {
    let advance = parse(&["advance", "ckpt-x", "--to", "sha256:child"]).expect("parse advance");
    match advance {
        MachineAction::Advance(a) => {
            assert_eq!(a.target, "ckpt-x");
            assert_eq!(a.to.as_deref(), Some("sha256:child"));
        }
        other => panic!("expected advance, got {other:?}"),
    }
    // `forward` still routes to the folded migration boundary.
    let forward = parse(&["forward", "myvm", "8080:80"]).expect("parse forward");
    assert!(matches!(forward, MachineAction::Vm(VmCmd::Forward(_))));
}

// ── post-start behaviour: attach unless told otherwise ────────────────────

/// `machine run` used to end by printing "attach with `machine shell`" — the
/// dev-only interactive path a sealed production machine bars outright, so the
/// advice was unusable exactly where seeing output matters most. The default is
/// now a real attach to the output stream; the machine-readable and detached
/// forms keep their contracts.
#[test]
fn a_persistent_run_attaches_to_output_by_default() {
    let args = parse_run(&["run", "--name", "m", "--ttl", "1h"]).expect("parse run");
    assert!(!args.detach, "--ttl alone must not imply detach");
    assert_eq!(post_start_action(&args), PostStart::Attach);
}

#[test]
fn detach_prints_the_machine_id_instead_of_attaching() {
    let args = parse_run(&["run", "-d", "--name", "m"]).expect("parse run");
    assert_eq!(post_start_action(&args), PostStart::PrintId);
}

#[test]
fn the_machine_readable_forms_never_attach() {
    // Attaching would interleave workload bytes with the envelope a caller is
    // parsing off stdout.
    let envelope = parse_run(&["run", "--name", "m", "--up-json"]).expect("parse run");
    assert_eq!(post_start_action(&envelope), PostStart::Envelope);

    let json = parse_run(&["run", "--name", "m", "--json", "--ttl", "1h"]).expect("parse run");
    assert_eq!(post_start_action(&json), PostStart::Quiet);
}

/// `--up-json` wins over `--detach`: the SDK boot envelope is the whole point
/// of that flag, and a bare machine id would not parse as one.
#[test]
fn the_boot_envelope_outranks_the_detached_id() {
    let args = parse_run(&["run", "-d", "--name", "m", "--up-json"]).expect("parse run");
    assert_eq!(post_start_action(&args), PostStart::Envelope);
}

// ---- networking -----------------------------------------------------

/// There is one networking configuration and no way to ask for another.
/// A transport selector could only ever let someone choose a weaker posture
/// than the one they would otherwise have had.
#[test]
fn machine_run_exposes_no_network_mode_selector() {
    let command = TestCli::command();
    let run = command
        .find_subcommand("run")
        .expect("machine run must exist");
    for arg in run.get_arguments() {
        let id = arg.get_id().as_str();
        assert!(
            !id.contains("network_mode") && !id.contains("network-mode"),
            "machine run must not expose a networking transport selector, found {id:?}"
        );
    }
    // A stray `--network-mode` configures nothing: it is not an mvm flag, and
    // it is refused rather than smuggled into the workload's argv.
    let err = parse_run(&["run", "--image", "alpine", "--network-mode", "l3-vsock"])
        .expect_err("a transport selector must not parse");
    assert_eq!(err.kind(), clap::error::ErrorKind::UnknownArgument);
}

#[test]
fn every_networked_workload_uses_the_flowmux_endpoint() {
    assert_eq!(
        super::preflight_network(),
        mvm_contract::plan::NetworkMode::HostVsockProxy
    );
}

/// An egress rule says *where* traffic may go, not *how* it travels, and
/// there is no longer any way for it to influence the transport at all.
#[test]
fn an_allow_host_rule_does_not_influence_the_transport() {
    let args = parse_run(&[
        "run",
        "--image",
        "alpine",
        "--allow-host",
        "api.example.com:443",
    ])
    .unwrap();
    assert_eq!(args.run.allow_host, vec!["api.example.com:443"]);
    assert_eq!(
        super::preflight_network(),
        mvm_contract::plan::NetworkMode::HostVsockProxy
    );
}

// ── the grant flags ───────────────────────────────────────

#[test]
fn cpus_and_cpu_limit_are_independent_controls() {
    // Different questions: how many vCPUs the guest sees, and what share of
    // host CPU time it may consume. Conflating them is the mistake every
    // container runtime made once, so they must be separately settable and
    // neither may move the other.
    let args = parse_run(&[
        "run",
        "--image",
        "alpine",
        "--cpus",
        "4",
        "--cpu-limit",
        "500",
    ])
    .expect("both flags parse together");
    assert_eq!(args.run.cpus, 4);
    assert_eq!(args.run.cpu_limit, Some(500));

    let only_cpus = parse_run(&["run", "--image", "alpine", "--cpus", "4"]).expect("parses");
    assert_eq!(only_cpus.run.cpus, 4);
    assert_eq!(
        only_cpus.run.cpu_limit, None,
        "--cpus must not imply a share"
    );

    let only_limit =
        parse_run(&["run", "--image", "alpine", "--cpu-limit", "500"]).expect("parses");
    assert_eq!(only_limit.run.cpu_limit, Some(500));
    assert_eq!(
        only_limit.run.cpus, 2,
        "--cpu-limit must not move the vCPU count off its default"
    );
}

#[test]
fn the_cpu_flags_help_text_tells_them_apart() {
    // A user who cannot tell which flag caps what will reach for the wrong
    // one, and the wrong one silently does nothing they wanted.
    let help = {
        let mut cmd = Cli::command();
        cmd.find_subcommand_mut("machine")
            .expect("machine noun")
            .find_subcommand_mut("run")
            .expect("run verb")
            .render_long_help()
            .to_string()
    };
    assert!(help.contains("--cpu-limit"), "help must list --cpu-limit");
    assert!(
        help.contains("millicores"),
        "the share flag must name its unit: {help}"
    );
    assert!(
        help.contains("vCPUs the guest sees"),
        "the vCPU flag must say what it sets: {help}"
    );
}

#[test]
fn a_grants_file_is_accepted_on_run_and_create() {
    let run = parse_run(&["run", "--image", "alpine", "--grants-file", "/tmp/g.json"])
        .expect("run accepts --grants-file");
    assert_eq!(
        run.run.grants_file.as_deref(),
        Some(Path::new("/tmp/g.json"))
    );

    let create = match parse(&[
        "create",
        "--image",
        "alpine",
        "--grants-file",
        "/tmp/g.json",
    ])
    .expect("create accepts --grants-file")
    {
        MachineAction::Create(c) => c,
        other => panic!("expected create action, got {other:?}"),
    };
    assert_eq!(
        create.grants_file.as_deref(),
        Some(Path::new("/tmp/g.json"))
    );
}

#[test]
fn a_manifest_grant_lands_on_the_created_machine_spec() {
    // `machine create` is the verb that reads a project manifest, so it is
    // where a `[grants]` table becomes a persisted permission set — the one a
    // later `machine start` re-admits under.
    let home = tempfile::tempdir().expect("scratch mvm home");
    let mut env = mvm_core::util::test_env::TestEnv::new();
    env.isolate_mvm_home(home.path());

    let project = tempfile::tempdir().expect("project dir");
    std::fs::write(
        project.path().join("mvm.toml"),
        r#"
image = "alpine:3.20"

[grants]
cpu_millicores = 1500
allow_hosts = ["api.example.com:443"]
"#,
    )
    .expect("write manifest");

    let args = match parse_owned(&[
        "create".to_string(),
        "granted".to_string(),
        "--manifest".to_string(),
        project.path().display().to_string(),
    ])
    .expect("create parses")
    {
        MachineAction::Create(c) => c,
        other => panic!("expected create action, got {other:?}"),
    };
    let spec = args.into_spec().expect("spec");
    let grants = spec.grants.expect("the manifest's grants were persisted");
    assert_eq!(
        grants.cpu,
        Some(mvm_contract::grants::CpuGrant::Share { millicores: 1500 })
    );
    assert_eq!(
        grants.egress.expect("egress granted").allow,
        vec![mvm_core::network_policy::HostPort::new(
            "api.example.com",
            443
        )]
    );
}

#[test]
fn a_cli_cpu_limit_does_not_discard_the_manifests_egress_grant() {
    // Per-dimension precedence, at the surface a user actually types. Whole
    // object precedence would drop the allow-list silently.
    let home = tempfile::tempdir().expect("scratch mvm home");
    let mut env = mvm_core::util::test_env::TestEnv::new();
    env.isolate_mvm_home(home.path());

    let project = tempfile::tempdir().expect("project dir");
    std::fs::write(
        project.path().join("mvm.toml"),
        r#"
image = "alpine:3.20"

[grants]
cpu_millicores = 4000
allow_hosts = ["api.example.com:443"]
"#,
    )
    .expect("write manifest");

    let args = match parse_owned(&[
        "create".to_string(),
        "narrowed".to_string(),
        "--manifest".to_string(),
        project.path().display().to_string(),
        "--cpu-limit".to_string(),
        "500".to_string(),
    ])
    .expect("create parses")
    {
        MachineAction::Create(c) => c,
        other => panic!("expected create action, got {other:?}"),
    };
    let grants = args
        .into_spec()
        .expect("spec")
        .grants
        .expect("something was granted");
    assert_eq!(
        grants.cpu,
        Some(mvm_contract::grants::CpuGrant::Share { millicores: 500 }),
        "the CLI wins the CPU dimension"
    );
    assert_eq!(
        grants.egress.expect("egress survived").allow,
        vec![mvm_core::network_policy::HostPort::new(
            "api.example.com",
            443
        )],
        "the manifest keeps the egress dimension the CLI said nothing about"
    );
}

#[test]
fn the_argv_the_sdk_facade_emits_parses_back_into_the_grant_it_encoded() {
    // The receiving half of the SDK's encoding contract. `mvm-sdk`'s
    // `grant_argv` emits exactly these flags for a CPU share, a bounded wall
    // clock, and an egress allow-list; this asserts the CLI turns them back
    // into the grant that produced them. A flag that did not exist, or meant
    // something else here, would be a silently dropped grant — the SDK would
    // emit it, the CLI would ignore it, and nothing on either side would
    // notice.
    let args = parse_run(&[
        "run",
        "--image",
        "alpine:latest",
        "--cpu-limit",
        "1500",
        "--timeout",
        "600",
        "--allow-host",
        "api.example.com:443",
        "--allow-host",
        "db.internal:5432",
    ])
    .expect("the facade's argv parses");

    let config = mvm_core::user_config::MvmConfig::default();
    let resolved =
        crate::commands::shared::resolve_run_grants(crate::commands::shared::GrantInputs {
            cpu_limit_millicores: args.run.cpu_limit,
            timeout_secs: args.run.timeout,
            allow_host: &args.run.allow_host,
            peer: &[],
            net: args.run.net,
            grants_file: args.run.grants_file.as_deref(),
            manifest: None,
            config: &config,
            ai: None,
        })
        .expect("resolves");

    assert_eq!(
        resolved.plan_grants,
        Some(mvm_contract::grants::Grants {
            cpu: Some(mvm_contract::grants::CpuGrant::Share { millicores: 1500 }),
            wall_clock: Some(mvm_contract::grants::WallClockGrant::Secs {
                secs: std::num::NonZeroU32::new(600).expect("nonzero"),
            }),
            egress: Some(mvm_contract::grants::EgressGrant {
                allow: vec![
                    mvm_core::network_policy::HostPort::new("api.example.com", 443),
                    mvm_core::network_policy::HostPort::new("db.internal", 5432),
                ],
            }),
        })
    );
}

// ── machine inspect: request vs achieved ─────────────────────────
//
// A live measurement found `machine inspect` reporting only the requested
// grant on a boot whose CPU was genuinely bounded. A request and an
// enforcement are indistinguishable in a spec file and only one of them is a
// security property, so showing the request alone is the exact confusion the
// read-back exists to prevent.

#[test]
fn machine_inspect_shows_the_enforced_tier_not_only_the_request() {
    let _state = IsolatedMachineState::new();
    let mut spec = spec_fixture("vm-inspect-tier");
    spec.grants = Some(mvm_contract::grants::Grants {
        cpu: Some(mvm_contract::grants::CpuGrant::Share { millicores: 1500 }),
        ..Default::default()
    });
    mvm_client::record_enforced_grants(
        &spec.name,
        &mvm_contract::protocol::resource_controls::EnforcedGrants {
            cpu: mvm_contract::protocol::resource_controls::EnforcedTier::Cgroup2CpuMax,
            wall_clock: mvm_contract::protocol::resource_controls::EnforcedTier::Declared,
        },
    );

    let enforced = mvm_client::enforced_grants_of(&spec.name);
    let json = serde_json::to_string_pretty(&super::spec_ops::MachineInspectView {
        spec: &spec,
        enforced_grants: enforced.clone(),
    })
    .expect("view serializes");
    assert!(
        json.contains("\"enforced_grants\""),
        "inspect --json must carry the achieved tier: {json}"
    );
    assert!(
        json.contains("cgroup2_cpu_max"),
        "the achieved tier must be the one recorded at boot: {json}"
    );
    assert!(
        json.contains("1500"),
        "the request must survive alongside it — an operator needs both: {json}"
    );

    let line = super::spec_ops::enforced_cpu_line(enforced.as_ref()).expect("a recorded tier");
    assert!(line.contains("cgroup2:cpu.max"), "{line}");
    assert!(line.contains("bounded"), "{line}");
}

/// A machine whose boot degraded must read as degraded, not as silent.
#[test]
fn machine_inspect_marks_an_unenforced_tier_as_not_bounded() {
    let enforced = mvm_contract::protocol::resource_controls::EnforcedGrants::all_declared();
    let line = super::spec_ops::enforced_cpu_line(Some(&enforced)).expect("a recorded tier");
    assert!(line.contains("not bounded"), "{line}");
}

/// No boot, no claim. An absent record is "unknown", which is a different
/// answer from "measured and found unenforced"; inventing the latter would
/// assert something about a run that never happened.
#[test]
fn machine_inspect_says_nothing_when_no_boot_recorded_a_tier() {
    assert_eq!(super::spec_ops::enforced_cpu_line(None), None);
}

// ---------------------------------------------------------------------------
// `machine start` auto-create / reconcile tests
// ---------------------------------------------------------------------------

fn start_args_with_create_flags(
    name: &str,
    create_flags: MachineStartCreateFlags,
) -> MachineStartArgs {
    MachineStartArgs {
        name: name.to_string(),
        create_flags,
        receipt: None,
        json: false,
        dry_run: false,
        quiet: false,
        hypervisor: None,
        no_supervisor: false,
        kernel_pin: None,
        has_ad_hoc_argv: false,
    }
}

#[test]
fn start_parser_accepts_source_and_config_flags() {
    let action = parse(&[
        "start", "web", "--image", "nginx", "--cpus", "2", "--memory", "512M",
    ])
    .expect("parse start with flags");
    let MachineAction::Start(cmd) = action else {
        panic!("expected start action");
    };
    assert_eq!(cmd.names, vec!["web"]);
    assert_eq!(cmd.create_flags.image.as_deref(), Some("nginx"));
    assert_eq!(cmd.create_flags.cpus, Some(2));
    assert_eq!(cmd.create_flags.memory.as_deref(), Some("512M"));
}

#[test]
fn start_parser_rejects_image_and_manifest_together() {
    let err = parse(&["start", "web", "--image", "nginx", "--manifest", "mvm.toml"])
        .expect_err("image and manifest must conflict");
    assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
}

#[test]
fn start_resolver_creates_missing_machine_when_source_given() {
    let _state = IsolatedMachineState::new();
    let args = start_args_with_create_flags(
        "web",
        MachineStartCreateFlags {
            image: Some("nginx".to_string()),
            cpus: Some(2),
            memory: Some("512M".to_string()),
            ..MachineStartCreateFlags::default()
        },
    );
    let (spec, action) = super::lifecycle::resolve_start_spec(&args).expect("create on start");
    assert_eq!(action, super::SpecReconcile::Create);
    assert_eq!(spec.name, "web");
    assert_eq!(spec.image.as_deref(), Some("nginx"));
    assert_eq!(spec.cpus, 2);
    assert_eq!(spec.memory, "512M");
}

#[test]
fn start_resolver_reuses_existing_machine_without_source_flags() {
    let _state = IsolatedMachineState::new();
    let existing = spec_fixture("web");
    save_machine_spec(&existing, false).expect("save existing");
    let args = start_args_with_create_flags("web", MachineStartCreateFlags::default());
    let (spec, action) = super::lifecycle::resolve_start_spec(&args).expect("reuse existing");
    assert_eq!(action, super::SpecReconcile::Reuse);
    assert_eq!(spec, existing);
}

#[test]
fn start_resolver_errors_when_missing_and_no_source() {
    let _state = IsolatedMachineState::new();
    let args = start_args_with_create_flags("web", MachineStartCreateFlags::default());
    let err = super::lifecycle::resolve_start_spec(&args).expect_err("missing machine errors");
    let msg = err.to_string();
    assert!(msg.contains("does not exist"), "msg: {msg}");
    assert!(msg.contains("--image"), "msg: {msg}");
}

#[test]
fn start_resolver_errors_on_changed_config_without_force() {
    let _state = IsolatedMachineState::new();
    let existing = spec_fixture("web");
    save_machine_spec(&existing, false).expect("save existing");
    let args = start_args_with_create_flags(
        "web",
        MachineStartCreateFlags {
            image: Some("ubuntu:24.04".to_string()),
            ..MachineStartCreateFlags::default()
        },
    );
    let err = super::lifecycle::resolve_start_spec(&args)
        .expect_err("changed config without force errors");
    assert!(err.to_string().contains("different config"), "msg: {err}");
}

#[test]
fn start_resolver_recreates_with_force() {
    let _state = IsolatedMachineState::new();
    let existing = spec_fixture("web");
    save_machine_spec(&existing, false).expect("save existing");
    let args = start_args_with_create_flags(
        "web",
        MachineStartCreateFlags {
            image: Some("ubuntu:24.04".to_string()),
            force: true,
            ..MachineStartCreateFlags::default()
        },
    );
    let (spec, action) = super::lifecycle::resolve_start_spec(&args).expect("force recreate");
    match action {
        super::SpecReconcile::Recreate { changed } => {
            assert!(changed.contains("source"), "changed: {changed}");
        }
        other => panic!("expected Recreate, got {other:?}"),
    }
    assert_eq!(spec.image.as_deref(), Some("ubuntu:24.04"));
}
