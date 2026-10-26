use std::fs;
use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn example_file(name: &str) -> PathBuf {
    workspace_root().join("examples/agent-workload").join(name)
}

fn read(path: &Path) -> String {
    fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()))
}

#[test]
fn agent_workload_declares_a_placeholder_secret_and_tight_egress() {
    let workload_text = read(&example_file("workload.json"));
    let typed: mvm_contract::ir::Workload = serde_json::from_str(&workload_text)
        .expect("agent workload IR must match the typed schema");
    mvm_contract::ir::validate(&typed).expect("agent workload IR must pass validation");
    let smoke: mvm_contract::ir::Workload =
        serde_json::from_str(&read(&example_file("workload-smoke.json")))
            .expect("agent smoke workload IR must match the typed schema");
    mvm_contract::ir::validate(&smoke).expect("agent smoke workload IR must pass validation");

    let workload: serde_json::Value =
        serde_json::from_str(&workload_text).expect("agent workload IR must be valid JSON");
    let secret = &workload["apps"][0]["env"]["ANTHROPIC_API_KEY"];

    assert_eq!(secret["kind"], "secret_ref");
    assert_eq!(secret["ref"]["name"], "anthropic");
    assert_eq!(secret["ref"]["mount"]["kind"], "env");
    assert_eq!(secret["ref"]["mount"]["var"], "ANTHROPIC_API_KEY");
    assert_eq!(secret["ref"]["allowed_hosts"][0], "api.anthropic.com");

    let manifest = read(&example_file("mvm.toml"));
    let typed_manifest = mvm_core::domain::manifest::Manifest::from_toml_str(&manifest)
        .expect("agent workload manifest must match the typed schema");
    assert_eq!(
        typed_manifest.network.allow_hosts,
        ["api.anthropic.com:443"]
    );
    assert_eq!(
        typed_manifest
            .network
            .ai
            .as_ref()
            .map(|policy| policy.metering),
        Some(true)
    );
    assert!(!manifest.contains("net = true"));
    assert!(!manifest.contains("/data/secrets"));
}

#[test]
fn agent_workload_uses_the_same_initial_resources_for_smoke_and_real_requests() {
    for name in ["workload.json", "workload-smoke.json"] {
        let workload: serde_json::Value =
            serde_json::from_str(&read(&example_file(name))).expect("valid workload JSON");
        assert_eq!(workload["apps"][0]["resources"]["cpu_cores"], 2, "{name}");
        assert_eq!(
            workload["apps"][0]["resources"]["memory_mb"], 4096,
            "{name}"
        );
    }

    let manifest = read(&example_file("mvm.toml"));
    assert!(manifest.lines().any(|line| line == "cpus = 2"));
    assert!(manifest.lines().any(|line| line == "mem = \"4G\""));
    let flake = read(&example_file("flake.nix"));
    assert!(flake.contains("vcpus = 2;"));
    assert!(flake.contains("memory_mib = 4096;"));
}

#[test]
fn agent_workload_is_a_guest_image_with_a_per_call_entrypoint() {
    let flake = read(&example_file("flake.nix"));

    assert!(flake.contains("mkGuest"));
    assert!(flake.contains("entrypoint.command = [ \"/etc/mvm/entrypoint\" ];"));
    assert!(flake.contains("extraFiles.\"/etc/mvm/entrypoint\""));
    assert!(flake.contains("tools = [ \"WebFetch\" ];"));
    assert!(flake.contains("--allowedTools WebFetch --max-turns 3 --max-budget-usd 0.50"));
    assert!(flake.contains("exec ${agent}/bin/mvm-agent"));
    assert!(!flake.contains("bootCommand"));
    assert!(flake.contains("ANTHROPIC_API_KEY"));
    assert!(!flake.contains("cat /data/secrets"));
}

#[test]
fn agent_workload_documents_and_live_tests_the_secure_run() {
    let readme = read(&example_file("README.md"));
    assert!(readme.contains("secret set anthropic"));
    assert!(readme.contains("--from-workload-ir examples/agent-workload/workload.json"));
    assert!(readme.contains("secret.substituted"));
    assert!(readme.contains("trust audit verify"));
    assert!(readme.contains("trust audit verify \"$SESSION_ID\" --json"));
    assert!(
        !readme
            .lines()
            .any(|line| line.contains("--mount") && line.contains(":/data/secrets:ro"))
    );

    let feature = read(
        &workspace_root().join("features/suites/s32_documented_surface/agent_workload.feature"),
    );
    assert!(feature.contains("@live"));
    assert!(feature.contains("examples/agent-workload"));
}

#[test]
fn agent_workload_smoke_uses_the_per_call_input_path() {
    let smoke = read(&example_file("workload-smoke.json"));
    assert!(!smoke.contains("MVM_AGENT_SMOKE"));

    let marker = "mvm-agent-smoke";
    let recipe = read(&workspace_root().join("nix/examples/llm-agent/default.nix"));
    let steps =
        read(&workspace_root().join("crates/mvm-conformance/tests/steps/agent_workload.rs"));
    let readme = read(&example_file("README.md"));
    assert!(recipe.contains(marker));
    assert!(recipe.contains("${pkgs.coreutils}/bin/cat"));
    assert!(steps.contains(marker));
    assert!(readme.contains(marker));
}

#[test]
fn the_network_preset_citation_resolves_to_a_real_recipe() {
    let recipe = workspace_root().join("nix/examples/llm-agent/default.nix");
    assert!(recipe.is_file(), "{} must exist", recipe.display());

    let policy = read(&workspace_root().join("crates/mvm-contract/src/policy/network_policy.rs"));
    assert!(policy.contains("nix/examples/llm-agent/"));
}

#[test]
fn both_agent_examples_reuse_the_one_pinned_binary_recipe() {
    let legacy = read(&workspace_root().join("examples/claude-code/flake.nix"));
    assert!(legacy.contains("${mvm}/examples/llm-agent"));
    assert!(!legacy.contains("linux-x64-musl"));
    assert!(!legacy.contains("linux-arm64-musl"));
}
