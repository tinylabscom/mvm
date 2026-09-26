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
    let tool_home = tempfile::tempdir().expect("create isolated SDK codegen home");
    let tool_home_path = tool_home.path().to_path_buf();
    // All three are `TempDir` so the run cleans up after itself.
    //
    // The target dir and the uv cache used to be hand-built `temp_dir()` paths
    // keyed by pid. Nothing removed them, and a pid is not stable across runs,
    // so each run both rebuilt from scratch *and* left its ~5 GB behind — 117
    // of them, 347 GB, before anyone noticed. A `TempDir` keeps the isolation
    // and the rebuild cost identical and gives back the disk on drop.
    let codegen_target = tempfile::tempdir().expect("create isolated SDK codegen target dir");
    let uv_cache = tempfile::tempdir().expect("create isolated SDK codegen uv cache");
    world.sdk_output = Some(
        Command::new(xtask)
            .arg("check-stubs")
            .current_dir(repo_root())
            .env("CARGO_MANIFEST_DIR", repo_root().join("xtask"))
            .env("CARGO_TARGET_DIR", codegen_target.path())
            .env("UV_TOOL_DIR", tool_home_path.join("uv/tools"))
            .env("UV_TOOL_BIN_DIR", tool_home_path.join("uv/bin"))
            .env("UV_CACHE_DIR", uv_cache.path())
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

// ────────────────────────────────────────────────────────────────────
// Live-transport witnesses.
//
// The decorator and record-mode scenarios above never leave the SDK's own
// address space. These drive the *live* surface, where every Sandbox call
// is one host-library call, recorded in-process — so the call contract
// between each language SDK and `libmvm_hostlib` is asserted directly, and
// the two languages are asserted against each other.
// ────────────────────────────────────────────────────────────────────

/// Directory holding the shared fixtures both languages run.
fn sdk_fixture_dir() -> PathBuf {
    repo_root()
        .join("features")
        .join("suites")
        .join("s27_sdk")
        .join("fixtures")
}

/// Run a named fixture in live mode, returning its output. The fixture
/// replaces the SDK's one C call with a recorder (`_recording_hostlib`), so
/// the scenario sees exactly which host-library methods the SDK called, with
/// no library, no process and no microVM.
fn run_live_fixture(
    world: &mut CliWorld,
    language: &str,
    fixture_stem: &str,
    build_mode: &str,
) -> Output {
    let fixtures = sdk_fixture_dir();
    let log_dir = world
        .sdk_argv_log_dir
        .get_or_insert_with(|| tempfile::tempdir().expect("create SDK call log dir"));
    let log = log_dir
        .path()
        .join(format!("{language}-{fixture_stem}.jsonl"));

    let (program, script) = match language.to_ascii_lowercase().as_str() {
        "python" => (
            "python3",
            fixtures.join(format!("python_{fixture_stem}.py")),
        ),
        "typescript" => (
            "node",
            fixtures.join(format!("typescript_{fixture_stem}.mjs")),
        ),
        other => panic!("unsupported SDK fixture language {other:?}"),
    };

    let mut command = Command::new(program);
    if language.eq_ignore_ascii_case("python") {
        command.env("PYTHONPATH", repo_root().join("crates/mvm-sdk/sdks/python"));
    }
    if build_mode == "dev" {
        command.env(mvm_sdk::env::MVM_SDK_RUN_PROFILE_ENV, "dev");
    }
    let output = command
        .current_dir(repo_root())
        .arg(&script)
        .env("MVM_SDK_MODE", "live")
        .env_remove(mvm_sdk::env::MVM_HOSTLIB_PATH_ENV)
        .env("MVM_BDD_CALL_LOG", &log)
        .env("MVM_BDD_BUILD_MODE", build_mode)
        .output()
        .unwrap_or_else(|error| panic!("spawn {program} for {}: {error}", script.display()));

    let recorded = std::fs::read_to_string(&log).unwrap_or_default();
    let calls: Vec<Value> = recorded
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("the recorder wrote a non-JSON call"))
        .collect();
    world
        .sdk_recorded_calls
        .insert(language.to_ascii_lowercase(), calls);
    output
}

/// The one field that legitimately varies between runs: the machine name a
/// `Sandbox` generates carries a random suffix so concurrent sandboxes don't
/// collide.
fn normalize_vm_name(calls: &[Value]) -> Vec<Value> {
    calls
        .iter()
        .map(|call| {
            let mut out = call.clone();
            if out[0] == "machine.run"
                && let Some(name) = out[1].get_mut("name")
                && name.as_str().is_some_and(|n| n.starts_with("sdk-"))
            {
                *name = Value::String("<vm-name>".into());
            }
            out
        })
        .collect()
}

/// A public-surface name list a surface fixture emitted.
fn recorded(world: &CliWorld, key: &str) -> Vec<Vec<String>> {
    world
        .sdk_recorded_argv
        .get(key)
        .unwrap_or_else(|| panic!("no recorded surface for {key}"))
        .clone()
}

fn recorded_calls(world: &CliWorld, language: &str) -> Vec<Value> {
    world
        .sdk_recorded_calls
        .get(language)
        .unwrap_or_else(|| panic!("no recorded host-library calls for {language}"))
        .clone()
}

/// The language whose live fixture ran last.
fn last_live_language(world: &CliWorld) -> String {
    world
        .sdk_recorded_calls
        .keys()
        .next_back()
        .expect("no live fixture has run")
        .clone()
}

fn method_of(call: &Value) -> &str {
    call[0].as_str().expect("a recorded call names its method")
}

#[when(expr = "I run the {string} SDK live-transport fixture")]
fn run_live_transport_fixture(world: &mut CliWorld, language: String) {
    world.sdk_output = Some(run_live_fixture(world, &language, "live", "dev"));
}

#[when(expr = "I run the {string} SDK refusal fixture against a sealed machine")]
fn run_refusal_fixture(world: &mut CliWorld, language: String) {
    world.sdk_output = Some(run_live_fixture(world, &language, "refusals", "prod"));
}

#[then("the recorded host-library calls match the golden live session")]
fn recorded_calls_match_golden(world: &mut CliWorld) {
    let golden_path = sdk_fixture_dir().join("live_session.jsonl");
    let golden: Vec<Value> = std::fs::read_to_string(&golden_path)
        .unwrap_or_else(|error| panic!("read {}: {error}", golden_path.display()))
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("golden live session is not JSON"))
        .collect();

    let language = last_live_language(world);
    let actual = normalize_vm_name(&recorded_calls(world, &language));
    assert_eq!(
        actual,
        golden,
        "{language} live-mode host-library calls drifted from {}",
        golden_path.display()
    );
}

#[then("the two recorded call traces are identical")]
fn recorded_call_traces_agree(world: &mut CliWorld) {
    let python = normalize_vm_name(&recorded_calls(world, "python"));
    let typescript = normalize_vm_name(&recorded_calls(world, "typescript"));
    assert_eq!(
        python, typescript,
        "Python and TypeScript drove the host library differently in live mode"
    );
}

#[then("every recorded call names a method the host library defines")]
fn recorded_calls_name_real_methods(world: &mut CliWorld) {
    let path = repo_root().join("schema").join("host-abi-methods-v0.json");
    let manifest: Value = serde_json::from_str(
        &std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("read {}: {error}", path.display())),
    )
    .expect("the host-ABI method table is not JSON");
    let defined: Vec<&str> = manifest["methods"]
        .as_array()
        .expect("the method table has no `methods` array")
        .iter()
        .map(|m| m["name"].as_str().expect("a method name"))
        .collect();
    let language = last_live_language(world);
    let calls = recorded_calls(world, &language);
    assert!(!calls.is_empty(), "the live fixture made no calls");
    for call in &calls {
        assert!(
            defined.contains(&method_of(call)),
            "the live SDK called `{}`, which the host library does not define: {call}",
            method_of(call)
        );
    }
}

#[then("the SDK refused every dev-only and invalid-mode operation")]
fn sdk_refused_every_guarded_operation(world: &mut CliWorld) {
    let verdicts = sdk_json(world);
    for (key, expected) in [
        ("sealed_commands_start", "SandboxDevOnly"),
        ("sealed_files_write", "SandboxDevOnly"),
        ("plan_mode", "SandboxModeError"),
        ("unknown_mode", "SandboxModeError"),
    ] {
        assert_eq!(
            verdicts[key], expected,
            "{key} was not refused; got {:?}",
            verdicts[key]
        );
    }
}

#[then("no guest method reached the host library")]
fn no_guest_method_reached_the_library(world: &mut CliWorld) {
    let language = last_live_language(world);
    for call in recorded_calls(world, &language) {
        assert!(
            !method_of(&call).starts_with("guest."),
            "a sealed machine let `{}` through to the host library — the refusal must \
             land before the call: {call}",
            method_of(&call)
        );
    }
}

// ────────────────────────────────────────────────────────────────────
// Cross-language surface parity.
//
// The two SDKs drifted far apart once already — TypeScript exporting seven
// internals while missing surface Python had — and nothing noticed, because
// nothing compared them. This pins the comparison: the shared surface must
// agree, and every difference must appear in a reviewed list.
// ────────────────────────────────────────────────────────────────────

/// Normalize a public name to a language-neutral key, so `emitRecordingJson`
/// and `emit_recording_json` compare equal.
///
/// Case is folded only for callables, and the category is part of the key.
/// Folding everything collapses the class `Session` onto the function
/// `session` — both SDKs export both — which hides one of the pair and would
/// report parity when only half of it had been added.
///
/// The categories follow the convention both SDKs already keep: types are
/// PascalCase in either language and so compare verbatim, constants are
/// SCREAMING_SNAKE in either language and likewise, and only callables differ
/// (`camelCase` against `snake_case`).
fn neutral_name(name: &str) -> String {
    let has_lowercase = name.chars().any(char::is_lowercase);
    let starts_upper = name.starts_with(char::is_uppercase);
    if starts_upper && has_lowercase {
        return format!("type:{name}");
    }
    if !has_lowercase {
        return format!("const:{name}");
    }
    let mut out = String::with_capacity(name.len() + 4);
    for (index, ch) in name.chars().enumerate() {
        if ch.is_uppercase() && index != 0 {
            out.push('_');
        }
        out.extend(ch.to_lowercase());
    }
    format!("fn:{out}")
}

/// Run a surface-dump fixture and parse its sorted name list.
fn surface_names(language: &str) -> Vec<String> {
    let fixtures = sdk_fixture_dir();
    let (program, script) = match language {
        "python" => ("python3", fixtures.join("python_surface.py")),
        _ => ("node", fixtures.join("typescript_surface.mjs")),
    };
    let mut command = Command::new(program);
    if language == "python" {
        command.env("PYTHONPATH", repo_root().join("crates/mvm-sdk/sdks/python"));
    }
    let output = command
        .current_dir(repo_root())
        .arg(&script)
        .output()
        .unwrap_or_else(|error| panic!("spawn {program} for {}: {error}", script.display()));
    assert!(
        output.status.success(),
        "{language} surface fixture failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("surface fixture did not emit a JSON array")
}

#[when("I collect the Python and TypeScript public surfaces")]
fn collect_sdk_surfaces(world: &mut CliWorld) {
    world
        .sdk_recorded_argv
        .insert("python-surface".into(), vec![surface_names("python")]);
    world.sdk_recorded_argv.insert(
        "typescript-surface".into(),
        vec![surface_names("typescript")],
    );
}

/// The two surfaces, split into what they share and what only one has.
fn partition_surfaces(world: &CliWorld) -> (Vec<String>, Vec<String>, usize) {
    let python = &recorded(world, "python-surface")[0];
    let typescript = &recorded(world, "typescript-surface")[0];
    let py_neutral: std::collections::BTreeMap<String, String> = python
        .iter()
        .map(|name| (neutral_name(name), name.clone()))
        .collect();
    let ts_neutral: std::collections::BTreeMap<String, String> = typescript
        .iter()
        .map(|name| (neutral_name(name), name.clone()))
        .collect();
    let mut python_only: Vec<String> = py_neutral
        .iter()
        .filter(|(key, _)| !ts_neutral.contains_key(*key))
        .map(|(_, name)| name.clone())
        .collect();
    let mut typescript_only: Vec<String> = ts_neutral
        .iter()
        .filter(|(key, _)| !py_neutral.contains_key(*key))
        .map(|(_, name)| name.clone())
        .collect();
    python_only.sort();
    typescript_only.sort();
    let shared = py_neutral
        .keys()
        .filter(|key| ts_neutral.contains_key(*key))
        .count();
    (python_only, typescript_only, shared)
}

#[then("every Rust-owned env-var name reaches the surfaces it claims")]
fn env_registry_reaches_its_declared_surfaces(world: &mut CliWorld) {
    // `schema/sdk-env-v0.json` is generated from crates/mvm-sdk/src/env.rs,
    // and each row names the surfaces that export it. Checking both
    // directions is the point: "declared and present" catches a binding that
    // never got generated, and "undeclared and absent" catches the tempting
    // failure where a name is emitted into a language that has no code
    // reading it, clearing the divergence list without closing the gap.
    let path = repo_root().join("schema").join("sdk-env-v0.json");
    let manifest: Value = serde_json::from_str(
        &std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("read {}: {error}", path.display())),
    )
    .expect("sdk-env manifest is not JSON");

    let python = &recorded(world, "python-surface")[0];
    let typescript = &recorded(world, "typescript-surface")[0];
    let rows = manifest["vars"]
        .as_array()
        .expect("sdk-env manifest has no `vars` array");
    assert!(!rows.is_empty(), "sdk-env manifest is empty");

    for row in rows {
        let ident = row["ident"].as_str().expect("row ident is not a string");
        let surfaces: Vec<&str> = row["surfaces"]
            .as_array()
            .expect("row surfaces is not an array")
            .iter()
            .map(|value| value.as_str().expect("surface is not a string"))
            .collect();

        for (surface, names) in [("python", python), ("typescript", typescript)] {
            let declared = surfaces.contains(&surface);
            let present = names.iter().any(|name| name == ident);
            assert_eq!(
                declared, present,
                "{ident}: the registry says exported-to-{surface}={declared}, but the \
                 built {surface} surface says {present} — regenerate with \
                 `cargo xtask gen-stubs`, or correct the `surfaces` list in \
                 crates/mvm-sdk/src/env.rs"
            );
        }
    }
}

#[when(regex = r#"^I run the "(Python|TypeScript)" Tier A constructor fixture$"#)]
fn run_ctor_fixture(world: &mut CliWorld, language: String) {
    let fixture = sdk_fixture_dir().join(match language.as_str() {
        "Python" => "python_ctors.py",
        _ => "typescript_ctors.mjs",
    });
    let mut command = match language.as_str() {
        "Python" => {
            let mut c = Command::new("python3");
            c.env("PYTHONPATH", repo_root().join("crates/mvm-sdk/sdks/python"));
            c
        }
        _ => Command::new("node"),
    };
    let output = command
        .arg(&fixture)
        .current_dir(repo_root())
        .output()
        .unwrap_or_else(|error| panic!("spawn {}: {error}", fixture.display()));
    assert!(
        output.status.success(),
        "{} exited {}: {}",
        fixture.display(),
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    world.sdk_ctor_docs.insert(
        format!("{}-ctors", language.to_ascii_lowercase()),
        String::from_utf8_lossy(&output.stdout).to_string(),
    );
}

#[then("both Tier A constructor surfaces match the golden IR document")]
fn ctor_surfaces_match_golden(world: &mut CliWorld) {
    // The golden document is the behavioural gate the constructor registry
    // needs and a name-level comparison cannot provide: it pins the built
    // values *and* the refusal messages, in both languages, against one
    // file. A generator that drifted in either language — or between them —
    // fails here rather than shipping.
    let path = sdk_fixture_dir().join("ctor_golden.json");
    let golden: Value = serde_json::from_str(
        &std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("read {}: {error}", path.display())),
    )
    .expect("ctor golden document is not JSON");

    for language in ["python", "typescript"] {
        let raw = world
            .sdk_ctor_docs
            .get(&format!("{language}-ctors"))
            .unwrap_or_else(|| panic!("{language} constructor fixture did not run"));
        let actual: Value =
            serde_json::from_str(raw).expect("constructor fixture did not emit JSON");
        assert_eq!(
            actual,
            golden,
            "{language} Tier A constructors diverged from {}",
            path.display()
        );
    }
}

#[then("the shared surface agrees between the two languages")]
fn shared_surface_agrees(world: &mut CliWorld) {
    let (_, _, shared) = partition_surfaces(world);
    assert!(
        shared > 30,
        "only {shared} names are shared between the SDKs — the surfaces have \
         diverged far enough that the reviewed list is no longer meaningful"
    );
}

#[then("any divergence matches the reviewed divergence list")]
fn divergence_matches_reviewed_list(world: &mut CliWorld) {
    let path = sdk_fixture_dir().join("surface_divergence.json");
    let reviewed: Value = serde_json::from_str(
        &std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("read {}: {error}", path.display())),
    )
    .expect("reviewed divergence list is not JSON");

    let names = |key: &str| -> Vec<String> {
        reviewed[key]
            .as_array()
            .unwrap_or_else(|| panic!("{key} missing from the reviewed divergence list"))
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .expect("divergence entry is not a string")
                    .to_string()
            })
            .collect()
    };
    let mut expected_python_only = names("python_only_type_erased_in_typescript");
    // Permanent-by-design names are Python-only forever — `derive_schema`
    // needs runtime type information TypeScript has already erased — so they
    // are tracked apart from the backlog rather than mixed into it.
    expected_python_only.extend(names("python_only_permanent_by_design"));
    expected_python_only.extend(names("python_only_absent_from_typescript"));
    expected_python_only.sort();
    let expected_typescript_only = names("typescript_only_absent_from_python");

    let (python_only, typescript_only, _) = partition_surfaces(world);
    assert_eq!(
        python_only,
        expected_python_only,
        "Python-only surface changed; update {} deliberately if that was intended",
        path.display()
    );
    assert_eq!(
        typescript_only,
        expected_typescript_only,
        "TypeScript-only surface changed; update {} deliberately if that was intended",
        path.display()
    );
}

// ────────────────────────────────────────────────────────────────────
// Cross-language constructor verdicts.
//
// The surface comparison above reads names. It cannot see that two surfaces
// exporting the same name disagree about which arguments that name accepts —
// which is how `host_port` came to admit port 0 in one language and refuse it
// in the other for as long as it did. This reads the shared verdict corpus and
// checks the Python surface against it; the Rust surface is checked against the
// same file by `crates/mvm-sdk/tests/validate.rs`.
// ────────────────────────────────────────────────────────────────────

/// One golden case: constructor, its two arguments, and the verdict every
/// surface must reach.
#[derive(Debug, serde::Deserialize)]
struct ConstraintCase {
    id: String,
    verdict: String,
}

/// What one language surface did with a case.
#[derive(Debug, serde::Deserialize)]
struct ConstraintOutcome {
    /// The constructor rejected the arguments outright.
    refused: bool,
    /// The document it emitted when it did not.
    #[serde(default)]
    document: Option<Value>,
}

fn constraint_corpus() -> Vec<ConstraintCase> {
    let path = sdk_fixture_dir().join("network_constraints.json");
    let corpus: Value = serde_json::from_str(
        &std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("read {}: {error}", path.display())),
    )
    .expect("the verdict corpus is not JSON");
    serde_json::from_value(corpus["cases"].clone()).expect("the verdict corpus has no `cases`")
}

#[when("I run the Python SDK network-constraint fixture")]
fn run_constraint_fixture(world: &mut CliWorld) {
    let fixture = sdk_fixture_dir().join("python_constraints.py");
    world.sdk_output = Some(
        Command::new("python3")
            .current_dir(repo_root())
            .env("PYTHONPATH", repo_root().join("crates/mvm-sdk/sdks/python"))
            .arg(&fixture)
            .output()
            .unwrap_or_else(|error| panic!("spawn python3 for {}: {error}", fixture.display())),
    );
}

#[then("every constructor case reaches the verdict the shared corpus states")]
fn constructor_cases_match_the_corpus(world: &mut CliWorld) {
    let reported: std::collections::BTreeMap<String, ConstraintOutcome> =
        serde_json::from_value(sdk_json(world))
            .expect("constraint fixture emitted an unknown shape");

    let mut disagreements = Vec::new();
    for case in constraint_corpus() {
        let outcome = reported
            .get(&case.id)
            .unwrap_or_else(|| panic!("the Python fixture skipped corpus case {}", case.id));
        // Refusing at the constructor and emitting a document validation then
        // rejects are the same verdict: the value never reaches a workload.
        // Which seam catches it is a language-idiom detail; that both catch it
        // is the contract.
        let (actual, detail) = if outcome.refused {
            (
                "invalid".to_string(),
                "refused by the constructor".to_string(),
            )
        } else {
            let document = outcome
                .document
                .as_ref()
                .unwrap_or_else(|| panic!("case {} neither refused nor emitted", case.id));
            let workload: mvm_contract::ir::Workload = serde_json::from_value(document.clone())
                .unwrap_or_else(|error| {
                    panic!(
                        "case {} emitted a document the IR rejects: {error}",
                        case.id
                    )
                });
            match mvm_contract::ir::validate(&workload) {
                Ok(()) => ("valid".to_string(), "accepted by validate".to_string()),
                Err(errors) => ("invalid".to_string(), format!("{errors:?}")),
            }
        };
        if actual != case.verdict {
            disagreements.push(format!(
                "{}: corpus says {}, Python reached {} ({detail})",
                case.id, case.verdict, actual
            ));
        }
    }
    assert!(
        disagreements.is_empty(),
        "the Python surface disagrees with the shared verdict corpus on {} case(s) — \
         a constructor that admits what another language refuses is the drift \
         network_constraints.json exists to catch:\n  {}",
        disagreements.len(),
        disagreements.join("\n  ")
    );
}
