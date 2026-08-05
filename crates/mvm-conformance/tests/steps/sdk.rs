//! Cross-language SDK contract witnesses.
//!
//! These scenarios run the actual Python and TypeScript packages against
//! hermetic fixtures. They cover the two public authoring modes — the
//! decorator/IR surface and the imperative runtime recording surface — while
//! keeping the guest and host VM out of the test.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use cucumber::{then, when};
use serde_json::Value;

use crate::world::CliWorld;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

fn fixture_path(language: &str, surface: &str) -> PathBuf {
    let language = match language.to_ascii_lowercase().as_str() {
        "python" => "python",
        "typescript" => "typescript",
        other => panic!("unsupported SDK fixture language {other:?}"),
    };
    let surface = match surface.to_ascii_lowercase().as_str() {
        "decorator" => "decorator",
        "runtime" => "runtime",
        other => panic!("unsupported SDK fixture surface {other:?}"),
    };
    repo_root()
        .join("features")
        .join("suites")
        .join("s27_sdk")
        .join("fixtures")
        .join(format!(
            "{language}_{surface}.{}",
            if language == "python" { "py" } else { "mjs" }
        ))
}

fn run_fixture(language: &str, surface: &str) -> Output {
    let repo = repo_root();
    let fixture = fixture_path(language, surface);
    let mut command = if language.eq_ignore_ascii_case("python") {
        let mut command = Command::new("python3");
        let sdk_root = repo.join("crates/mvm-sdk/sdks/python");
        let pythonpath = std::env::var_os("PYTHONPATH").map_or_else(
            || sdk_root.clone().into_os_string(),
            |existing| {
                let mut paths = vec![sdk_root.clone()];
                paths.extend(std::env::split_paths(&existing));
                std::env::join_paths(paths).expect("join Python SDK import paths")
            },
        );
        command.env("PYTHONPATH", pythonpath);
        command
    } else {
        Command::new("node")
    };
    command
        .current_dir(&repo)
        .arg(fixture)
        .output()
        .expect("spawn SDK fixture interpreter")
}

fn sdk_json(world: &CliWorld) -> Value {
    let output = world
        .sdk_output
        .as_ref()
        .expect("no SDK fixture output recorded");
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "SDK fixture did not emit JSON: {error}; stdout={:?}; stderr={:?}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

#[when(expr = "I run the {string} SDK {string} fixture")]
fn run_sdk_fixture(world: &mut CliWorld, language: String, surface: String) {
    world.sdk_surface = Some(surface.clone());
    world.sdk_output = Some(run_fixture(&language, &surface));
}

#[then("the SDK fixture exits successfully")]
fn sdk_fixture_exits_successfully(world: &mut CliWorld) {
    let output = world
        .sdk_output
        .as_ref()
        .expect("no SDK fixture output recorded");
    assert!(
        output.status.success(),
        "SDK fixture failed: stdout={:?}; stderr={:?}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[then("the SDK fixture emits the canonical decorator document")]
fn decorator_document_is_canonical(world: &mut CliWorld) {
    let payload = sdk_json(world);
    assert_eq!(payload["id"], "bdd-decorator");
    let app = payload["apps"]
        .as_array()
        .and_then(|apps| apps.first())
        .expect("decorator fixture must emit one app");
    assert_eq!(app["name"], "bdd-decorator");
    assert_eq!(app["entrypoints"][0]["kind"], "command");
    assert_eq!(
        app["entrypoints"][0]["command"],
        serde_json::json!(["python", "-c", "print('ok')"])
    );
}

#[then("the SDK fixture records command and file operations")]
fn runtime_recording_has_command_and_file_operations(world: &mut CliWorld) {
    let payload = sdk_json(world);
    assert_eq!(payload["workload_id"], "bdd-runtime");
    assert_eq!(payload["create"]["template"], "python-3.12");
    let ops = payload["ops"]
        .as_array()
        .expect("runtime fixture must emit ops");
    assert_eq!(ops.len(), 2);
    assert_eq!(ops[0]["kind"], "command_start");
    assert_eq!(
        ops[0]["argv"],
        serde_json::json!(["python", "-c", "print('ok')"])
    );
    assert_eq!(ops[1]["kind"], "files_write");
    assert_eq!(ops[1]["path"], "/app/hello.txt");
}

#[when("I run the SDK codegen drift check")]
fn run_sdk_codegen_drift_check(world: &mut CliWorld) {
    let target_dir = std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| repo_root().join("target"));
    let xtask = target_dir.join("debug/xtask");
    let codegen_target =
        std::env::temp_dir().join(format!("mvm-sdk-codegen-{}", std::process::id()));
    let uv_cache = std::env::temp_dir().join(format!("mvm-sdk-uv-cache-{}", std::process::id()));
    world.sdk_output = Some(
        Command::new(xtask)
            .arg("check-stubs")
            .current_dir(repo_root())
            .env("CARGO_MANIFEST_DIR", repo_root().join("xtask"))
            .env("CARGO_TARGET_DIR", codegen_target)
            .env("UV_CACHE_DIR", uv_cache)
            .output()
            .expect("spawn SDK codegen drift check"),
    );
}

#[then("the SDK codegen drift check passes")]
fn sdk_codegen_drift_check_passes(world: &mut CliWorld) {
    let output = world
        .sdk_output
        .as_ref()
        .expect("no SDK codegen output recorded");
    assert!(
        output.status.success(),
        "SDK codegen drift check failed: stdout={:?}; stderr={:?}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
