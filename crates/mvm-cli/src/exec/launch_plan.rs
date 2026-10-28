//! Parser for the two JSON documents mvmforge produces.
//!
//! Unknown metadata is tolerated within supported format versions. Entrypoint
//! kinds, environment values, and orchestration requirements are validated
//! before a command wrapper can be constructed.

use super::*;

/// Permissive deserialization shapes for the two JSON documents mvmforge
/// produces:
///
/// 1. **LaunchPlan artifact** (`<artifact-dir>/launch.json` from
///    `mvmforge compile`): top-level `entrypoint` + `env`, plus
///    `flake_attribute` / `workload_id` / `artifact_format_version`
///    metadata. This is the canonical handoff to mvm.
/// 2. **Workload IR manifest** (`mvmforge emit` stdout, also accepted by
///    `mvmforge compile` as input): top-level `apps[]` with
///    `apps[].entrypoints[]` (or legacy `apps[].entrypoint`). Useful for
///    callers that wire the emitter to `mvmctl run` without compiling.
///
/// `deny_unknown_fields` is intentionally NOT set so newer mvmforge
/// releases that add optional metadata don't break parsing. Unsupported
/// versions and known execution requirements are rejected explicitly.
#[derive(Debug, Deserialize)]
struct RawLaunchPlan {
    #[serde(default)]
    artifact_format_version: Option<String>,
    #[serde(default, alias = "ir_schema_version")]
    schema_version: Option<String>,
    #[serde(default)]
    addons: Vec<serde_json::Value>,
    #[serde(default)]
    mesh: Option<RawMesh>,
    /// Present only on the LaunchPlan artifact shape.
    #[serde(default)]
    entrypoint: Option<RawLaunchEntrypoint>,
    /// Present only on the LaunchPlan artifact shape (top-level env merged
    /// under `entrypoint.env`).
    #[serde(default)]
    env: BTreeMap<String, serde_json::Value>,
    /// Present only on the Workload IR shape.
    #[serde(default)]
    apps: Vec<RawLaunchApp>,
}

#[derive(Debug, Deserialize)]
struct RawLaunchApp {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    addons: Vec<serde_json::Value>,
    #[serde(default)]
    entrypoint: Option<RawLaunchEntrypoint>,
    #[serde(default)]
    entrypoints: Option<Vec<RawLaunchEntrypoint>>,
    #[serde(default)]
    env: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct RawLaunchEntrypoint {
    #[serde(default)]
    kind: Option<String>,
    #[serde(default)]
    command: Vec<String>,
    #[serde(default)]
    working_dir: Option<String>,
    #[serde(default)]
    env: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct RawMesh {
    enabled: bool,
    #[serde(default)]
    expected_peers: Vec<String>,
}

/// Read and parse an mvmforge document from disk.
///
/// Accepts either the LaunchPlan artifact (`mvmforge compile`'s `launch.json`)
/// or the Workload IR manifest (`mvmforge emit` stdout). The shape is
/// auto-detected. v1 supports single-app workloads only — IR with multiple
/// `apps[]` entries is rejected.
pub fn load_launch_plan(path: &Path) -> Result<LaunchEntrypoint> {
    let bytes =
        std::fs::read(path).with_context(|| format!("reading launch plan '{}'", path.display()))?;
    let raw: RawLaunchPlan = serde_json::from_slice(&bytes).map_err(|error| {
        anyhow::anyhow!(
            "launch plan '{}': schema mismatch at line {}, column {}; expected a command launch artifact or single-app Workload IR",
            path.display(),
            error.line(),
            error.column()
        )
    })?;
    parse_launch_plan(raw, &path.display().to_string())
}

fn parse_launch_plan(raw: RawLaunchPlan, source: &str) -> Result<LaunchEntrypoint> {
    let RawLaunchPlan {
        artifact_format_version,
        schema_version,
        addons,
        mesh,
        entrypoint: top_entrypoint,
        env: top_env,
        apps,
    } = raw;
    if let Some(version) = artifact_format_version {
        anyhow::ensure!(
            matches!(version.as_str(), "1.0" | "1.1"),
            "launch plan '{source}': unsupported artifact_format_version; expected 1.0 or 1.1"
        );
    }
    if let Some(version) = schema_version {
        anyhow::ensure!(
            mvm_contract::ir::validate_schema_version(&version).is_ok(),
            "launch plan '{source}': schema mismatch; unsupported IR schema_version"
        );
    }
    anyhow::ensure!(
        addons.is_empty()
            && mesh.is_none_or(|mesh| !mesh.enabled && mesh.expected_peers.is_empty()),
        "launch plan '{source}': addon/mesh orchestration is not supported by command wrappers"
    );
    match (top_entrypoint, apps.is_empty()) {
        (Some(entrypoint), true) => parse_launch_artifact(entrypoint, top_env, source),
        (None, false) => parse_workload_ir(apps, source),
        (Some(_), false) => anyhow::bail!(
            "launch plan '{source}': both top-level `entrypoint` and `apps[]` present — pick one shape (mvmforge launch.json artifact or Workload IR manifest)",
        ),
        (None, true) => anyhow::bail!(
            "launch plan '{source}': missing both top-level `entrypoint` (mvmforge launch.json artifact) and `apps[]` (Workload IR manifest)",
        ),
    }
}

/// Parse the LaunchPlan artifact shape emitted by `mvmforge compile`.
fn parse_launch_artifact(
    entrypoint: RawLaunchEntrypoint,
    top_env: BTreeMap<String, serde_json::Value>,
    source: &str,
) -> Result<LaunchEntrypoint> {
    anyhow::ensure!(
        entrypoint
            .kind
            .as_deref()
            .is_none_or(|kind| kind == "command"),
        "launch plan '{source}': only kind=command entrypoints are supported; function dispatch requires invoke"
    );
    if entrypoint.command.first().is_none_or(String::is_empty) {
        anyhow::bail!("launch plan '{source}': entrypoint.command must be non-empty");
    }
    let working_dir = entrypoint
        .working_dir
        .or_else(|| entrypoint.kind.as_ref().map(|_| "/app".to_owned()));
    // mvmforge: top-level env is merged under (overridden by) entrypoint.env.
    let mut merged = top_env;
    for (k, v) in entrypoint.env {
        merged.insert(k, v);
    }
    let env = resolve_literal_env(merged, source)?;
    validate_env_keys(&env, source)?;
    Ok(LaunchEntrypoint {
        command: entrypoint.command,
        working_dir,
        env,
    })
}

/// Parse the Workload IR manifest shape (top-level `apps[]`).
fn parse_workload_ir(apps: Vec<RawLaunchApp>, source: &str) -> Result<LaunchEntrypoint> {
    if apps.len() > 1 {
        let names: Vec<&str> = apps
            .iter()
            .map(|a| a.name.as_deref().unwrap_or("<unnamed>"))
            .collect();
        anyhow::bail!(
            "launch plan '{source}' has {} apps ({}); `mvmctl run` supports single-app workloads only",
            apps.len(),
            names.join(", "),
        );
    }
    let RawLaunchApp {
        name: _,
        addons,
        entrypoint,
        entrypoints,
        env: app_env,
    } = apps.into_iter().next().expect("apps non-empty");
    anyhow::ensure!(
        addons.is_empty(),
        "launch plan '{source}': addon orchestration is not supported by command wrappers"
    );
    let entrypoint = match (entrypoint, entrypoints) {
        (Some(entrypoint), None) => entrypoint,
        (None, Some(mut entries)) if entries.len() == 1 => entries.remove(0),
        _ => anyhow::bail!(
            "launch plan '{source}': schema mismatch; expected exactly one apps[].entrypoints[] entry or a legacy entrypoint, not both"
        ),
    };
    parse_launch_artifact(entrypoint, app_env, source)
}

/// Reuse the canonical IR literal type, retaining bare strings for legacy plans.
/// Secret references require the secret-delivery path, not shell exports.
fn resolve_literal_env(
    env: BTreeMap<String, serde_json::Value>,
    source: &str,
) -> Result<BTreeMap<String, String>> {
    env.into_iter()
        .map(|(key, value)| {
            if let serde_json::Value::String(value) = value {
                return Ok((key, value));
            }
            anyhow::ensure!(
                value.get("kind").and_then(serde_json::Value::as_str) != Some("secret_ref"),
                "launch plan '{source}': secret_ref environment values are not supported by command wrappers"
            );
            match serde_json::from_value::<mvm_contract::ir::EnvValue>(value) {
                Ok(mvm_contract::ir::EnvValue::Literal { value }) => Ok((key, value)),
                Ok(mvm_contract::ir::EnvValue::SecretRef { .. }) => anyhow::bail!(
                    "launch plan '{source}': secret_ref environment values are not supported by command wrappers"
                ),
                Err(_) => anyhow::bail!(
                    "launch plan '{source}': schema mismatch; env values must be strings or kind=literal objects"
                ),
            }
        })
        .collect()
}

/// Refuse an env key that cannot be a single shell assignment. The guest
/// wrapper exports each key unquoted, so a key such as `A;cmd` would run `cmd`.
fn validate_env_keys(env: &BTreeMap<String, String>, source: &str) -> Result<()> {
    if let Some(key) = env
        .keys()
        .find(|key| !mvm_core::vm_backend::is_secret_env_name(key))
    {
        anyhow::bail!("launch plan '{source}': env key {key:?} must match [A-Za-z_][A-Za-z0-9_]*");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_str(json: &str) -> Result<LaunchEntrypoint> {
        let raw: RawLaunchPlan = serde_json::from_str(json)?;
        parse_launch_plan(raw, "test")
    }

    #[test]
    fn canonical_workload_fixture_uses_literal_env_and_default_directory() {
        let fixture = include_str!("../../../../tests/fixtures/launch-plan/workload.json");
        let canonical: mvm_contract::ir::Workload = serde_json::from_str(fixture).unwrap();
        let plan = parse_str(fixture).unwrap();
        let roundtrip = serde_json::to_string(&canonical).unwrap();
        assert_eq!(plan, parse_str(&roundtrip).unwrap());
        assert_eq!(plan.command, ["python", "main.py"]);
        assert_eq!(plan.working_dir.as_deref(), Some("/app"));
        assert_eq!(plan.env["PORT"], "8080");
        assert_eq!(plan.env["LOG"], "info");
    }

    #[test]
    fn rejects_ambiguous_or_multiple_entrypoints() {
        for app in [
            r#"{"entrypoint":{"command":["true"]},"entrypoints":[{"kind":"command","command":["true"]}]}"#,
            r#"{"entrypoints":[]}"#,
            r#"{"entrypoints":[{"command":["true"]},{"command":["false"]}]}"#,
        ] {
            let err = parse_str(&format!(r#"{{"apps":[{app}]}}"#)).unwrap_err();
            assert!(err.to_string().contains("exactly one"), "{err}");
        }
    }

    #[test]
    fn rejects_unsupported_kinds_secrets_and_versions_without_echoing_values() {
        for (plan, expected) in [
            (
                r#"{"entrypoint":{"kind":"function","command":["true"]}}"#,
                "kind=command",
            ),
            (
                r#"{"entrypoint":{"kind":"future","command":["true"]}}"#,
                "kind=command",
            ),
            (r#"{"entrypoint":{"command":[""]}}"#, "non-empty"),
            (
                r#"{"schema_version":"99","entrypoint":{"command":["true"]}}"#,
                "schema mismatch",
            ),
            (
                r#"{"artifact_format_version":"99","entrypoint":{"command":["true"]}}"#,
                "artifact_format_version",
            ),
            (
                r#"{"entrypoint":{"command":["true"],"env":{"TOKEN":{"kind":"secret_ref","ref":{"name":"sensitive-marker"}}}}}"#,
                "secret_ref",
            ),
            (
                r#"{"entrypoint":{"command":["true"],"env":{"TOKEN":{"kind":"literal","value":42}}}}"#,
                "schema mismatch",
            ),
            (
                r#"{"entrypoint":{"command":["true"]},"addons":[{}]}"#,
                "orchestration",
            ),
            (
                r#"{"entrypoint":{"command":["true"]},"mesh":{"enabled":true}}"#,
                "orchestration",
            ),
        ] {
            let err = parse_str(plan).unwrap_err().to_string();
            assert!(err.contains(expected), "{err}");
            assert!(!err.contains("sensitive-marker"));
        }
    }

    #[test]
    fn accepts_current_artifact_without_addon_or_mesh_requirements() {
        let plan = parse_str(
            r#"{
            "artifact_format_version":"1.1",
            "ir_schema_version":"0.1",
            "entrypoint":{"kind":"command","command":["true"]},
            "env":{"X":{"kind":"literal","value":"app"}},
            "addons":[],
            "mesh":{"enabled":false,"expected_peers":[]}
        }"#,
        )
        .unwrap();
        assert_eq!(plan.env["X"], "app");
        assert_eq!(plan.working_dir.as_deref(), Some("/app"));
    }

    #[test]
    fn accepts_the_canonical_compiler_command_artifact() {
        let mut workload: mvm_contract::ir::Workload = serde_json::from_str(include_str!(
            "../../../../tests/fixtures/launch-plan/workload.json"
        ))
        .unwrap();
        workload.schema_version = format!(
            "{}.{}",
            mvm_contract::ir::IR_MAJOR,
            mvm_contract::ir::IR_MINOR
        );
        let source = mvm_compiler::SourcePlan {
            kind: "local_path",
            subdir: "src",
            file_count: 0,
            tree_hash: "0".repeat(64),
        };
        let artifact = mvm_compiler::build_launch_json(&workload, &source).unwrap();
        let plan = parse_str(&artifact).unwrap();
        assert_eq!(plan.command, ["python", "main.py"]);
        assert_eq!(plan.working_dir.as_deref(), Some("/app"));
        assert_eq!(plan.env["PORT"], "8080");
        assert_eq!(plan.env["LOG"], "info");
    }

    #[test]
    fn file_schema_errors_do_not_echo_environment_values() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("launch.json");
        std::fs::write(&path, r#"{"entrypoint":{"command":"sensitive-marker"}}"#).unwrap();
        let error = format!("{:#}", load_launch_plan(&path).unwrap_err());
        assert!(error.contains("schema mismatch"));
        assert!(!error.contains("sensitive-marker"));
    }

    #[test]
    fn launch_plan_minimal_app() {
        let plan = r#"{
            "apps": [
                { "entrypoint": { "command": ["python", "-m", "hello"] } }
            ]
        }"#;
        let ep = parse_str(plan).unwrap();
        assert_eq!(ep.command, vec!["python", "-m", "hello"]);
        assert!(ep.working_dir.is_none());
        assert!(ep.env.is_empty());
    }

    #[test]
    fn launch_plan_with_working_dir_and_env() {
        let plan = r#"{
            "apps": [
                {
                    "name": "hello",
                    "entrypoint": {
                        "command": ["python", "main.py"],
                        "working_dir": "/app",
                        "env": { "PORT": "8080" }
                    },
                    "env": { "LOG_LEVEL": "info" }
                }
            ]
        }"#;
        let ep = parse_str(plan).unwrap();
        assert_eq!(ep.command, vec!["python", "main.py"]);
        assert_eq!(ep.working_dir.as_deref(), Some("/app"));
        assert_eq!(ep.env.get("PORT").map(String::as_str), Some("8080"));
        // app.env merged in (under entrypoint.env precedence, but no conflict here).
        assert_eq!(ep.env.get("LOG_LEVEL").map(String::as_str), Some("info"));
    }

    #[test]
    fn launch_plan_rejects_no_apps() {
        let err = parse_str(r#"{ "apps": [] }"#).unwrap_err();
        assert!(err.to_string().contains("missing both"));
    }

    #[test]
    fn launch_plan_rejects_multi_app() {
        let plan = r#"{
            "apps": [
                { "name": "a", "entrypoint": { "command": ["x"] } },
                { "name": "b", "entrypoint": { "command": ["y"] } }
            ]
        }"#;
        let err = parse_str(plan).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("single-app"), "got: {msg}");
        assert!(msg.contains("a, b"), "names should appear: {msg}");
    }

    #[test]
    fn launch_plan_rejects_empty_command() {
        let plan = r#"{
            "apps": [ { "entrypoint": { "command": [] } } ]
        }"#;
        let err = parse_str(plan).unwrap_err();
        assert!(err.to_string().contains("non-empty"));
    }

    #[test]
    fn launch_plan_entrypoint_env_overrides_app_env() {
        let plan = r#"{
            "apps": [
                {
                    "entrypoint": {
                        "command": ["true"],
                        "env": { "X": "from-entrypoint" }
                    },
                    "env": { "X": "from-app", "Y": "y" }
                }
            ]
        }"#;
        let ep = parse_str(plan).unwrap();
        assert_eq!(ep.env.get("X").map(String::as_str), Some("from-entrypoint"));
        assert_eq!(ep.env.get("Y").map(String::as_str), Some("y"));
    }

    #[test]
    fn launch_plan_accepts_mvmforge_artifact_shape() {
        // The JSON `mvmforge compile` actually writes to launch.json: top-level
        // `entrypoint`, plus toolchain metadata fields we ignore.
        let plan = r#"{
            "artifact_format_version": "1.0",
            "flake_attribute": "mvmforge.workload",
            "flake_path": ".",
            "ir_hash": "deadbeef",
            "ir_schema_version": "0.1",
            "toolchain_version": "0.1.0",
            "workload_id": "hello",
            "image": { "kind": "nix_packages", "packages": ["python312"] },
            "entrypoint": {
                "command": ["python", "-m", "hello"],
                "working_dir": "/app",
                "env": { "PORT": "8080" }
            },
            "env": {},
            "mounts": [],
            "network": null,
            "source": { "kind": "local_path", "subdir": "src", "file_count": 0, "tree_hash": "0" }
        }"#;
        let ep = parse_str(plan).unwrap();
        assert_eq!(ep.command, vec!["python", "-m", "hello"]);
        assert_eq!(ep.working_dir.as_deref(), Some("/app"));
        assert_eq!(ep.env.get("PORT").map(String::as_str), Some("8080"));
    }

    #[test]
    fn launch_plan_artifact_rejects_empty_command() {
        let plan = r#"{ "entrypoint": { "command": [] } }"#;
        let err = parse_str(plan).unwrap_err();
        assert!(err.to_string().contains("non-empty"));
    }

    #[test]
    fn launch_plan_refuses_an_env_key_that_is_not_one_shell_assignment() {
        let artifact = r#"{ "entrypoint": { "command": ["true"], "env": { "A;touch /x": "1" } } }"#;
        let err = parse_str(artifact).unwrap_err();
        assert!(err.to_string().contains("env key"), "{err}");
        let ir =
            r#"{ "apps": [{ "entrypoint": { "command": ["true"] }, "env": { "A B": "1" } }] }"#;
        let err = parse_str(ir).unwrap_err();
        assert!(err.to_string().contains("env key"), "{err}");
    }

    #[test]
    fn launch_plan_artifact_top_env_merged_under_entrypoint_env() {
        let plan = r#"{
            "entrypoint": {
                "command": ["true"],
                "env": { "X": "from-entrypoint" }
            },
            "env": { "X": "from-top", "Y": "y" }
        }"#;
        let ep = parse_str(plan).unwrap();
        assert_eq!(ep.env.get("X").map(String::as_str), Some("from-entrypoint"));
        assert_eq!(ep.env.get("Y").map(String::as_str), Some("y"));
    }

    #[test]
    fn launch_plan_ignores_unknown_top_level_fields() {
        // mvmforge ships `version`, `workload.id`, etc. — we don't care about them.
        let plan = r#"{
            "version": "v0",
            "workload": { "id": "hello" },
            "apps": [ { "entrypoint": { "command": ["true"] } } ],
            "future_field": 42
        }"#;
        assert!(parse_str(plan).is_ok());
    }

    #[test]
    fn launch_plan_rejects_both_shapes_present() {
        // Defensive: a JSON that simultaneously declares `apps[]` and a
        // top-level `entrypoint` is ambiguous — refuse rather than silently
        // pick one.
        let plan = r#"{
            "apps": [ { "entrypoint": { "command": ["x"] } } ],
            "entrypoint": { "command": ["y"] }
        }"#;
        let err = parse_str(plan).unwrap_err();
        assert!(err.to_string().contains("both"));
    }

    #[test]
    fn launch_plan_rejects_completely_empty_document() {
        let err = parse_str(r#"{}"#).unwrap_err();
        assert!(err.to_string().contains("missing both"));
    }

    #[test]
    fn load_launch_plan_reads_file() {
        let dir = std::env::temp_dir().join(format!("mvm-launch-plan-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("launch.json");
        std::fs::write(
            &path,
            r#"{ "apps": [ { "entrypoint": { "command": ["echo", "hi"] } } ] }"#,
        )
        .unwrap();
        let ep = load_launch_plan(&path).unwrap();
        assert_eq!(ep.command, vec!["echo", "hi"]);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn load_launch_plan_reports_missing_file() {
        let err = load_launch_plan(Path::new("/nonexistent/launch.json")).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("reading launch plan"));
    }
}
