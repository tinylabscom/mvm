//! Every method of the host ABI, answered with the `mvmctl` CLI unavailable,
//! constructs no host process outside an explicit allowlist.
//!
//! The table below is checked against three independent lists of the ABI's
//! methods: each module's own `METHODS` constant and the checked-in method
//! schema. A method added to any of them without a case here fails
//! `the_table_names_every_method_the_abi_answers`.
//!
//! What this proves, and what it does not:
//!
//! - It records *construction* at `mvm_core::env_hygiene::helper_command_with`,
//!   the one constructor the `check-helper-env-hygiene` inventory sanctions
//!   for host helpers. A program named there may never have been run, and a
//!   process created any other way is not seen.
//! - The raw process sites that inventory classifies as guest or builder code
//!   are outside it.
//! - The client is the in-memory mock and the launcher the mock hypervisor, so
//!   the VMM launch chain a real backend would run is never reached. Guest,
//!   log and entrypoint methods run their real local operations against a
//!   machine that does not exist, so they prove the refusal path, not an
//!   operation on a live guest.
//! - The recorder is per thread. These calls run on the test's own thread; a
//!   process built on a thread the code under test started would not be seen.
//!
//! `PATH` is empty and every helper-location override is unset, so a spawn
//! that did happen would fail as well as be recorded. The negative control
//! that proves the recorder would catch a shell lives with the exported-entry
//! tests in `tests/abi_without_cli.rs`, because the `check-no-cli-shellout`
//! gate scans this crate's source for any process constructor.

use mvm_core::client::mock::MockBackend;
use mvm_core::env_hygiene::spawn_recorder::SpawnScope;
use mvm_core::util::test_env::TestEnv;
use serde_json::Value;

use crate::status::{MVM_HOSTLIB_INTERNAL, MVM_HOSTLIB_OK, Outcome};
use crate::{Services, entrypoint, guest, handle, stream};

/// Programs the ABI may construct with no CLI: none.
const ALLOWED: &[&str] = &[];

/// The mock client and mock launcher, with the real local guest, log and
/// entrypoint operations.
struct Offline;

impl Services for Offline {
    fn client(&self) -> Result<Box<dyn mvm_core::client::MvmClient>, Outcome> {
        Ok(Box::new(MockBackend::default()))
    }
    fn launcher(&self) -> Result<mvm_client::LocalBackend, Outcome> {
        Ok(mvm_client::LocalBackend::with_hypervisor("mock"))
    }
    fn guest(&self) -> Result<std::sync::Arc<dyn guest::GuestOps>, Outcome> {
        Ok(std::sync::Arc::new(guest::LocalGuest))
    }
    fn logs(&self) -> Result<std::sync::Arc<dyn stream::LogSource>, Outcome> {
        Ok(std::sync::Arc::new(stream::LocalLogs))
    }
    fn entrypoint(&self) -> Result<std::sync::Arc<dyn entrypoint::EntrypointOps>, Outcome> {
        Ok(std::sync::Arc::new(entrypoint::LocalEntrypoint))
    }
}

/// One request per method, each naming a machine, session or stream that does
/// not exist.
const TABLE: &[(&str, &str)] = &[
    ("attestation.export", "{}"),
    ("attestation.status", "{}"),
    (
        "attestation.verify",
        r#"{"report_path":"/nonexistent/report.json","trust":{"kind":"self_identity"}}"#,
    ),
    ("backend.capabilities", "{}"),
    ("checkpoint.list", "{}"),
    ("checkpoint.remove", r#"{"id":"ghost"}"#),
    ("checkpoint.verify_lineage", r#"{"id":"ghost"}"#),
    (
        "entrypoint.call",
        r#"{"workload":"ghost","payload_b64":""}"#,
    ),
    (
        "guest.cp",
        r#"{"id":"ghost","direction":"guest_to_host","guest_path":"/x","host_path":"/nonexistent/out"}"#,
    ),
    ("guest.fs.list", r#"{"id":"ghost","path":"/"}"#),
    ("guest.fs.mkdir", r#"{"id":"ghost","path":"/x"}"#),
    ("guest.fs.read", r#"{"id":"ghost","path":"/x","length":1}"#),
    ("guest.fs.remove", r#"{"id":"ghost","path":"/x"}"#),
    ("guest.fs.rename", r#"{"id":"ghost","from":"/a","to":"/b"}"#),
    ("guest.fs.stat", r#"{"id":"ghost","path":"/x"}"#),
    (
        "guest.fs.write",
        r#"{"id":"ghost","path":"/x","data_b64":""}"#,
    ),
    ("guest.proc.kill", r#"{"id":"ghost","token":"t"}"#),
    ("guest.proc.list", r#"{"id":"ghost"}"#),
    (
        "guest.proc.signal",
        r#"{"id":"ghost","token":"t","signum":15}"#,
    ),
    ("guest.proc.start", r#"{"id":"ghost","argv":["true"]}"#),
    (
        "guest.proc.stdin",
        r#"{"id":"ghost","token":"t","data_b64":""}"#,
    ),
    ("guest.proc.stream.close", r#"{"stream":1}"#),
    ("guest.proc.stream.next", r#"{"stream":1}"#),
    ("guest.proc.stream.open", r#"{"id":"ghost","token":"t"}"#),
    ("guest.proc.wait", r#"{"id":"ghost","token":"t"}"#),
    ("image_revocations.status", "{}"),
    (
        "image_revocations.update",
        r#"{"bundle_path":"/nonexistent/b","document_path":"/nonexistent/d"}"#,
    ),
    (
        "machine.create",
        r#"{"name":"made","image":"docker.io/library/alpine:3.20"}"#,
    ),
    ("machine.exec", r#"{"id":"ghost","command":["true"]}"#),
    ("machine.inspect", r#"{"id":"ghost"}"#),
    ("machine.inventory", "{}"),
    ("machine.list", "{}"),
    ("machine.logs", r#"{"id":"ghost"}"#),
    ("machine.logs.stream.close", r#"{"stream":1}"#),
    ("machine.logs.stream.next", r#"{"stream":1}"#),
    ("machine.logs.stream.open", r#"{"id":"ghost"}"#),
    ("machine.pause", r#"{"id":"ghost"}"#),
    ("machine.prompt", r#"{"id":"ghost","prompt_b64":"aGk="}"#),
    ("machine.reconfigure", r#"{"id":"ghost"}"#),
    ("machine.resume", r#"{"id":"ghost"}"#),
    ("machine.rm", r#"{"id":"ghost"}"#),
    (
        "machine.run",
        r#"{"image":"docker.io/library/alpine:3.20"}"#,
    ),
    ("machine.set_ttl", r#"{"id":"ghost"}"#),
    ("machine.start", r#"{"id":"ghost"}"#),
    ("machine.stop", r#"{"id":"ghost"}"#),
    ("manifest.info", "{}"),
    ("manifest.list", "{}"),
    ("manifest.prune", r#"{"orphans":true}"#),
    ("manifest.remove", "{}"),
    ("manifest.verify", "{}"),
    ("secret.get", r#"{"tenant":"t","name":"n"}"#),
    (
        "session.call",
        r#"{"session_id":"aaaaaaaaaaaaaaaa","payload_b64":""}"#,
    ),
    ("session.info", r#"{"session_id":"aaaaaaaaaaaaaaaa"}"#),
    ("session.start", r#"{"workload":"ghost"}"#),
    ("session.stop", r#"{"session_id":"aaaaaaaaaaaaaaaa"}"#),
    ("telemetry.records", r#"{"id":"ghost"}"#),
    ("telemetry.status", r#"{"id":"ghost"}"#),
];

/// Every method the library answers, from each module's own list.
fn answered_methods() -> std::collections::BTreeSet<&'static str> {
    [
        crate::attestation::METHODS,
        crate::checkpoint::METHODS,
        crate::dispatch::METHODS.as_slice(),
        crate::entrypoint::METHODS.as_slice(),
        crate::guest::METHODS.as_slice(),
        crate::image_admin::METHODS,
        crate::launch::METHODS.as_slice(),
        crate::manifest::METHODS,
        crate::secret::METHODS,
        crate::stream::LOG_METHODS.as_slice(),
        crate::stream::METHODS.as_slice(),
    ]
    .into_iter()
    .flatten()
    .copied()
    .collect()
}

/// A process with nothing runnable anywhere: empty `PATH`, helper overrides
/// unset, and a home of its own.
fn offline_process(env: &mut TestEnv, home: &std::path::Path) {
    env.isolate_mvm_home(home);
    let empty = home.join("empty-path");
    std::fs::create_dir_all(&empty).expect("an empty directory for PATH");
    env.set("PATH", &empty);
    for (name, _) in std::env::vars_os().filter(|(name, _)| {
        let name = name.to_string_lossy();
        name.starts_with("MVM_") && name.ends_with("_PATH")
    }) {
        env.remove(name);
    }
}

fn call(method: &str, request: &str) -> Outcome {
    handle(true, method.as_bytes(), request.as_bytes(), &Offline)
}

fn error_code(outcome: &Outcome) -> Option<String> {
    serde_json::from_slice::<Value>(&outcome.body)
        .ok()?
        .get("code")?
        .as_str()
        .map(str::to_owned)
}

#[test]
fn the_table_names_every_method_the_abi_answers() {
    let in_table: std::collections::BTreeSet<&str> = TABLE.iter().map(|(m, _)| *m).collect();
    assert_eq!(
        in_table.len(),
        TABLE.len(),
        "a method appears twice in the table"
    );
    assert_eq!(in_table, answered_methods());

    let schema: Value =
        serde_json::from_str(include_str!("../../../schema/host-abi-methods-v0.json"))
            .expect("the checked-in method schema parses");
    let in_schema: std::collections::BTreeSet<&str> = schema["methods"]
        .as_array()
        .expect("a methods array")
        .iter()
        .map(|row| row["name"].as_str().expect("a method name"))
        .collect();
    assert_eq!(in_table, in_schema);
}

#[test]
fn every_abi_method_constructs_only_allowlisted_programs_with_no_cli() {
    let home = tempfile::tempdir().expect("a home");
    let mut env = TestEnv::new();
    offline_process(&mut env, home.path());
    let scope = SpawnScope::begin();

    let mut report = Vec::new();
    for (method, request) in TABLE {
        let before = scope.programs().len();
        let outcome = call(method, request);
        let programs = scope.programs();
        report.push(format!(
            "{method}: status {} code {:?} built {:?} {}",
            outcome.status,
            error_code(&outcome),
            &programs[before..],
            String::from_utf8_lossy(&outcome.body)
                .chars()
                .take(160)
                .collect::<String>()
        ));
        assert_ne!(
            outcome.status,
            MVM_HOSTLIB_INTERNAL,
            "{method} panicked: {}",
            String::from_utf8_lossy(&outcome.body)
        );
        assert!(
            outcome.status == MVM_HOSTLIB_OK || error_code(&outcome).is_some(),
            "{method} failed without a typed error body: {}",
            String::from_utf8_lossy(&outcome.body)
        );
    }
    eprintln!("{}", report.join("\n"));
    scope.assert_only(ALLOWED);
}

#[test]
fn an_unknown_machine_is_a_typed_error_and_builds_nothing() {
    let home = tempfile::tempdir().expect("a home");
    let mut env = TestEnv::new();
    offline_process(&mut env, home.path());
    let scope = SpawnScope::begin();

    for method in ["machine.inspect", "machine.start", "telemetry.status"] {
        let outcome = call(method, r#"{"id":"ghost"}"#);
        assert_eq!(
            outcome.status,
            crate::status::MVM_HOSTLIB_NOT_FOUND,
            "{method}: {}",
            String::from_utf8_lossy(&outcome.body)
        );
        assert!(error_code(&outcome).is_some(), "{method}");
    }
    assert!(scope.programs().is_empty(), "{:?}", scope.programs());
}

#[test]
fn a_corrupt_checkpoint_registry_is_a_typed_error_and_builds_nothing() {
    let home = tempfile::tempdir().expect("a home");
    let mut env = TestEnv::new();
    offline_process(&mut env, home.path());
    let dir = mvm_core::config::checkpoints_dir().join("broken");
    std::fs::create_dir_all(&dir).expect("a checkpoint directory");
    std::fs::write(dir.join("meta.json"), b"{").expect("a corrupt record");
    let scope = SpawnScope::begin();

    let outcome = call("checkpoint.list", "{}");
    assert_eq!(outcome.status, crate::status::MVM_HOSTLIB_BACKEND);
    assert!(error_code(&outcome).is_some());
    assert!(scope.programs().is_empty(), "{:?}", scope.programs());
}
