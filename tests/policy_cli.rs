//! `mvmctl policy` and `run --policy/--plan` end to end, host-only: nothing
//! boots. Every refusal asserted here happens before image resolution, so a
//! run that got further than the policy would fail these tests loudly.

use assert_cmd::cargo::CommandCargoExt;
use std::process::{Command, Output};

struct Host {
    home: tempfile::TempDir,
}

impl Host {
    fn new() -> Self {
        Self {
            home: tempfile::tempdir().unwrap(),
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

    fn user_profile(&self, name: &str, text: &str) {
        let dir = self.home.path().join("config/policy/profiles");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(format!("{name}.toml")), text).unwrap();
    }
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[test]
fn policy_help_lists_every_verb() {
    let out = Host::new().mvmctl(&["policy", "--help"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let help = text(&out.stdout);
    for verb in ["resolve", "show", "validate", "diff", "groups"] {
        assert!(help.contains(verb), "help must list `{verb}`:\n{help}");
    }
}

#[test]
fn groups_lists_the_built_ins_and_user_files() {
    let host = Host::new();
    host.user_profile("mine", "description = \"my profile\"\n");
    let out = host.mvmctl(&["policy", "groups", "--json"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let listed: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let names: Vec<&str> = listed
        .as_array()
        .unwrap()
        .iter()
        .map(|l| l["name"].as_str().unwrap())
        .collect();
    for name in [
        "registries",
        "github",
        "llm-apis",
        "offline",
        "default",
        "agent-apis",
        "mine",
    ] {
        assert!(names.contains(&name), "{names:?}");
    }
}

#[test]
fn show_prints_toml_json_and_the_plan_it_yields() {
    let host = Host::new();
    let toml_out = host.mvmctl(&["policy", "show", "agent-apis"]);
    assert!(toml_out.status.success(), "{}", text(&toml_out.stderr));
    let shown = text(&toml_out.stdout);
    assert!(
        shown.contains("# layer: group `llm-apis` (built-in)"),
        "{shown}"
    );
    assert!(shown.contains("api.anthropic.com:443"), "{shown}");

    let json_out = host.mvmctl(&["policy", "show", "agent-apis", "--format", "json"]);
    let json: serde_json::Value = serde_json::from_slice(&json_out.stdout).unwrap();
    assert!(
        json["provenance"]["network.allow.github.com:443"]
            .as_str()
            .unwrap()
            .contains("github")
    );

    let plan_out = host.mvmctl(&["policy", "show", "offline", "--format", "plan"]);
    assert!(plan_out.status.success(), "{}", text(&plan_out.stderr));
    let plan: serde_json::Value = serde_json::from_slice(&plan_out.stdout).unwrap();
    assert_eq!(plan["egress_allow"], serde_json::json!([]));
}

#[test]
fn resolve_writes_a_manifest_that_validate_accepts() {
    let host = Host::new();
    let manifest = host.home.path().join("resolved.json");
    let out = host.mvmctl(&[
        "policy",
        "resolve",
        "dev-network",
        "-o",
        manifest.to_str().unwrap(),
    ]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let written: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&manifest).unwrap()).unwrap();
    assert!(
        written["policy"]["network"]["allow"]
            .as_array()
            .unwrap()
            .iter()
            .any(|h| h == "pypi.org:443")
    );
}

#[test]
fn validate_names_the_file_layer_and_key_and_strict_refuses_warnings() {
    let host = Host::new();
    let bad = host.home.path().join("bad.toml");
    std::fs::write(&bad, "[overrides.network]\nallow = [\"x.test:22\"]\n").unwrap();
    let out = host.mvmctl(&["policy", "validate", bad.to_str().unwrap()]);
    assert!(!out.status.success());
    let stderr = text(&out.stderr);
    assert!(
        stderr.contains("bad.toml") && stderr.contains("`network.allow`"),
        "{stderr}"
    );

    let tools = host.home.path().join("tools.toml");
    std::fs::write(&tools, "[overrides.tools]\nallow = [\"git\"]\n").unwrap();
    let lenient = host.mvmctl(&["policy", "validate", tools.to_str().unwrap()]);
    assert!(lenient.status.success(), "{}", text(&lenient.stderr));
    let strict = host.mvmctl(&["policy", "validate", tools.to_str().unwrap(), "--strict"]);
    assert!(
        !strict.status.success(),
        "--strict refuses the unenforced tools section"
    );
}

#[test]
fn diff_shows_what_one_profile_adds_over_another() {
    let out = Host::new().mvmctl(&["policy", "diff", "default", "agent-apis"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let diff = text(&out.stdout);
    assert!(
        diff.contains("+ network.allow api.openai.com:443"),
        "{diff}"
    );
    assert!(!diff.contains("- "), "{diff}");
}

#[test]
fn a_cycle_and_a_pack_reference_are_refused() {
    let host = Host::new();
    host.user_profile("a", "extends = \"b\"\n");
    host.user_profile("b", "extends = \"a\"\n");
    let out = host.mvmctl(&["policy", "show", "a"]);
    assert!(text(&out.stderr).contains("cycle"), "{}", text(&out.stderr));

    let out = host.mvmctl(&["policy", "show", "acme/agent"]);
    assert!(
        text(&out.stderr).contains("packs are not yet supported"),
        "{}",
        text(&out.stderr)
    );
}

#[test]
fn run_refuses_a_flag_the_policy_blocks_before_booting_anything() {
    let out = Host::new().mvmctl(&[
        "run",
        "--policy",
        "offline",
        "--allow-host",
        "example.com",
        "--image",
        "alpine:3.20",
        "--",
        "true",
    ]);
    assert!(!out.status.success());
    assert!(
        text(&out.stderr).contains("blocks the network"),
        "{}",
        text(&out.stderr)
    );
}

#[test]
fn run_refuses_a_signed_plan_given_as_a_resolved_manifest() {
    let host = Host::new();
    let plan = host.home.path().join("plan.json");
    std::fs::write(
        &plan,
        r#"{"plan":{},"signature":"AAAA","signer_id":"host:x"}"#,
    )
    .unwrap();
    let out = host.mvmctl(&[
        "run",
        "--plan",
        plan.to_str().unwrap(),
        "--image",
        "alpine:3.20",
        "--",
        "true",
    ]);
    assert!(!out.status.success());
    assert!(
        text(&out.stderr).contains("never trusted"),
        "{}",
        text(&out.stderr)
    );
}

#[test]
fn run_refuses_plan_with_any_policy_flag() {
    let out = Host::new().mvmctl(&[
        "run",
        "--plan",
        "/tmp/none.json",
        "--allow-host",
        "a.test",
        "--",
        "true",
    ]);
    assert!(!out.status.success());
    assert!(
        text(&out.stderr).contains("cannot be used with"),
        "{}",
        text(&out.stderr)
    );
}
