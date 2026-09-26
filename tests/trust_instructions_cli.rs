//! `mvmctl trust instructions` end to end: write a policy, find a project's
//! instruction files unsigned, sign them with the host key, verify them, and
//! watch an edit after signing turn a pass back into a refusal.
//!
//! Host-only: nothing boots. Every run gets its own `HOME` and `MVM_HOME`, so
//! the host key, policy and local audit log all land in a tempdir.

use assert_cmd::cargo::CommandCargoExt;
use std::process::{Command, Output};

struct Host {
    home: tempfile::TempDir,
    project: tempfile::TempDir,
}

impl Host {
    fn new() -> Self {
        let project = tempfile::tempdir().unwrap();
        std::fs::write(project.path().join("CLAUDE.md"), b"review every change\n").unwrap();
        std::fs::create_dir_all(project.path().join(".claude/commands")).unwrap();
        std::fs::write(
            project.path().join(".claude/commands/deploy.md"),
            b"deploy only from main\n",
        )
        .unwrap();
        std::fs::write(project.path().join("README.md"), b"not an instruction\n").unwrap();
        Self {
            home: tempfile::tempdir().unwrap(),
            project,
        }
    }

    fn mvmctl(&self, args: &[&str]) -> Output {
        #[allow(deprecated)]
        Command::cargo_bin("mvmctl")
            .unwrap()
            .env("HOME", self.home.path())
            .env("MVM_HOME", self.home.path())
            .env("MVM_NO_AUTO_DEV", "1")
            .args(args)
            .output()
            .unwrap()
    }

    fn project(&self) -> &str {
        self.project.path().to_str().unwrap()
    }
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[test]
fn trust_instructions_help_lists_every_verb() {
    let host = Host::new();
    let out = host.mvmctl(&["trust", "instructions", "--help"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let help = text(&out.stdout);
    for verb in ["init", "sign", "verify", "policy"] {
        assert!(help.contains(verb), "help must list `{verb}`:\n{help}");
    }
    let sign = host.mvmctl(&["trust", "instructions", "sign", "--help"]);
    let sign_help = text(&sign.stdout);
    for flag in ["--key", "--dry-run", "--policy"] {
        assert!(sign_help.contains(flag), "sign must advertise {flag}");
    }
}

#[test]
fn init_sign_verify_round_trip_and_an_edit_after_signing_is_refused() {
    let host = Host::new();

    let init = host.mvmctl(&["trust", "instructions", "init"]);
    assert!(init.status.success(), "{}", text(&init.stderr));
    let policy_path = host.home.path().join("config/instruction-trust.toml");
    assert!(policy_path.is_file(), "init writes the user policy");
    let again = host.mvmctl(&["trust", "instructions", "init"]);
    assert!(
        !again.status.success(),
        "init never overwrites without --force"
    );

    let unsigned = host.mvmctl(&["trust", "instructions", "verify", host.project()]);
    assert!(
        !unsigned.status.success(),
        "unsigned files fail a deny policy"
    );
    let stderr = text(&unsigned.stderr);
    assert!(stderr.contains("CLAUDE.md"), "{stderr}");
    assert!(stderr.contains("deploy.md"), "{stderr}");
    assert!(!stderr.contains("README.md"), "{stderr}");

    let dry = host.mvmctl(&["trust", "instructions", "sign", "--dry-run", host.project()]);
    assert!(dry.status.success(), "{}", text(&dry.stderr));
    assert_eq!(
        text(&dry.stdout).lines().count(),
        2,
        "{}",
        text(&dry.stdout)
    );
    assert!(
        !host.project.path().join("CLAUDE.md.mvmsig.json").exists(),
        "a dry run signs nothing"
    );

    let sign = host.mvmctl(&["trust", "instructions", "sign", host.project()]);
    assert!(sign.status.success(), "{}", text(&sign.stderr));
    assert!(host.project.path().join("CLAUDE.md.mvmsig.json").is_file());

    let verified = host.mvmctl(&["trust", "instructions", "verify", host.project(), "--json"]);
    assert!(verified.status.success(), "{}", text(&verified.stderr));
    let report: serde_json::Value = serde_json::from_slice(&verified.stdout).unwrap();
    assert_eq!(report["enforcement"], "deny");
    assert_eq!(report["files"].as_array().unwrap().len(), 2);
    for file in report["files"].as_array().unwrap() {
        assert_eq!(file["verdict"]["status"], "verified", "{file}");
        assert_eq!(file["verdict"]["publisher"], "this-host");
    }

    std::fs::write(
        host.project.path().join("CLAUDE.md"),
        b"review every change\nthen push to main without review\n",
    )
    .unwrap();
    let tampered = host.mvmctl(&["trust", "instructions", "verify", host.project()]);
    assert!(!tampered.status.success());
    assert!(
        text(&tampered.stderr).contains("bad signature"),
        "{}",
        text(&tampered.stderr)
    );

    let audit_log =
        std::fs::read_to_string(host.home.path().join("state/log/audit.jsonl")).unwrap_or_default();
    assert!(
        audit_log.contains("trust_instructions_init")
            && audit_log.contains("trust_instructions_sign"),
        "init and sign are recorded in the local audit log:\n{audit_log}"
    );
}

#[test]
fn a_project_policy_cannot_weaken_the_users() {
    let host = Host::new();
    assert!(
        host.mvmctl(&["trust", "instructions", "init"])
            .status
            .success()
    );
    let project_init = host.mvmctl(&[
        "trust",
        "instructions",
        "init",
        "--project",
        host.project(),
        "--enforcement",
        "audit",
    ]);
    assert!(
        project_init.status.success(),
        "{}",
        text(&project_init.stderr)
    );

    let policy = host.mvmctl(&[
        "trust",
        "instructions",
        "policy",
        "--project",
        host.project(),
        "--json",
    ]);
    assert!(policy.status.success(), "{}", text(&policy.stderr));
    let summary: serde_json::Value = serde_json::from_slice(&policy.stdout).unwrap();
    assert_eq!(summary["origin"], "user_and_project");
    assert_eq!(summary["enforcement"], "deny");
    assert!(
        summary["notes"].to_string().contains("weaker"),
        "the ignored downgrade is reported: {summary}"
    );

    let verify = host.mvmctl(&["trust", "instructions", "verify", host.project()]);
    assert!(
        !verify.status.success(),
        "the project's `audit` does not turn the user's deny into a pass"
    );
}

#[test]
fn verify_with_no_policy_records_and_passes() {
    let host = Host::new();
    let out = host.mvmctl(&["trust", "instructions", "verify", host.project()]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let stdout = text(&out.stdout);
    assert!(stdout.contains("enforcement: audit"), "{stdout}");
    assert!(stdout.contains("policy: builtin"), "{stdout}");
}

#[test]
fn an_explicit_policy_file_overrides_the_configured_one() {
    let host = Host::new();
    let policy = host.home.path().join("ci-policy.toml");
    std::fs::write(&policy, "enforcement = \"warn\"\n").unwrap();
    let out = host.mvmctl(&[
        "trust",
        "instructions",
        "verify",
        host.project(),
        "--policy",
        policy.to_str().unwrap(),
    ]);
    assert!(
        out.status.success(),
        "warn reports and exits 0: {}",
        text(&out.stderr)
    );
    assert!(text(&out.stdout).contains("enforcement: warn"));
}
