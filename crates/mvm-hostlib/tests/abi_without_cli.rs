//! The exported C entry point, called as a binding would, constructs no host
//! process with the `mvmctl` CLI unavailable.
//!
//! This covers the host-local methods (attestation, checkpoint, image
//! revocation, manifest, secret), which answer without a machine backend, plus
//! the read-only machine methods through the real local client. The full
//! method table, on the mock client, is in the crate's `spawn_free` unit
//! tests, because the real entry point cannot be handed a mock backend.
//!
//! The recorder sees construction at `helper_command_with`, not execution,
//! does not see the guest and builder raw sites, and is per thread: every call
//! here runs on the test's own thread. `PATH` is empty and every helper
//! override is unset, so a spawn that did happen would also fail.

use mvm_core::env_hygiene::spawn_recorder::SpawnScope;
use mvm_core::util::test_env::TestEnv;
use mvm_hostlib::{
    MvmHostlibBuf, attestation, checkpoint, image_admin, manifest, mvm_hostlib_abi_is_compatible,
    mvm_hostlib_call, mvm_hostlib_free, secret,
};
use serde_json::Value;

/// The one program the real local client may build here: macOS reports its
/// version through `sw_vers` when the host tier is probed to pick a backend.
/// It is a fixed system tool, never the CLI, and absent on Linux.
const ALLOWED: &[&str] = &["sw_vers"];

const OK: i32 = 0;
const INTERNAL: i32 = 11;

/// One request per host-local method.
const HOST_LOCAL: &[(&str, &str)] = &[
    ("attestation.export", "{}"),
    ("attestation.status", "{}"),
    (
        "attestation.verify",
        r#"{"report_path":"/nonexistent/report.json","trust":{"kind":"self_identity"}}"#,
    ),
    ("checkpoint.list", "{}"),
    ("checkpoint.remove", r#"{"id":"ghost"}"#),
    ("checkpoint.verify_lineage", r#"{"id":"ghost"}"#),
    ("image_revocations.status", "{}"),
    (
        "image_revocations.update",
        r#"{"bundle_path":"/nonexistent/b","document_path":"/nonexistent/d"}"#,
    ),
    ("manifest.info", "{}"),
    ("manifest.list", "{}"),
    ("manifest.prune", r#"{"orphans":true}"#),
    ("manifest.remove", "{}"),
    ("manifest.verify", "{}"),
    ("secret.get", r#"{"tenant":"t","name":"n"}"#),
];

/// The read-only machine methods, which reach the real local client.
const MACHINE_READS: &[(&str, &str)] = &[
    ("backend.capabilities", "{}"),
    ("machine.inventory", "{}"),
    ("machine.list", "{}"),
    ("machine.inspect", r#"{"id":"ghost"}"#),
    ("machine.logs", r#"{"id":"ghost"}"#),
    ("telemetry.status", r#"{"id":"ghost"}"#),
];

fn host_local_methods() -> std::collections::BTreeSet<&'static str> {
    [
        attestation::METHODS,
        checkpoint::METHODS,
        image_admin::METHODS,
        manifest::METHODS,
        secret::METHODS,
    ]
    .into_iter()
    .flatten()
    .copied()
    .collect()
}

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

/// Call the exported entry point and return its status and decoded body.
fn call(method: &str, request: &str) -> (i32, Value) {
    let mut out = MvmHostlibBuf {
        data: std::ptr::null_mut(),
        len: 0,
    };
    // SAFETY: both pointers cover their stated lengths for the call, and `out`
    // is a valid, writable buffer that is released below.
    let status = unsafe {
        mvm_hostlib_call(
            method.as_ptr(),
            method.len(),
            request.as_ptr(),
            request.len(),
            &mut out,
        )
    };
    let body = if out.len == 0 {
        Value::Null
    } else {
        // SAFETY: a non-empty buffer from the call holds `len` readable bytes
        // until it is freed.
        let bytes = unsafe { std::slice::from_raw_parts(out.data, out.len) };
        serde_json::from_slice(bytes).expect("the body is JSON")
    };
    // SAFETY: `out` came from `mvm_hostlib_call` and is freed exactly once.
    unsafe { mvm_hostlib_free(out) };
    (status, body)
}

fn negotiate() {
    assert_eq!(mvm_hostlib_abi_is_compatible(1, 0), 1);
}

fn run_table(table: &[(&str, &str)]) {
    let home = tempfile::tempdir().expect("a home");
    let mut env = TestEnv::new();
    offline_process(&mut env, home.path());
    negotiate();
    let scope = SpawnScope::begin();
    for (method, request) in table {
        let (status, body) = call(method, request);
        assert_ne!(status, INTERNAL, "{method} panicked: {body}");
        assert!(
            status == OK || body["code"].is_string(),
            "{method} failed without a typed error: {body}"
        );
    }
    scope.assert_only(ALLOWED);
}

#[test]
fn the_host_local_table_names_every_host_local_method() {
    let in_table: std::collections::BTreeSet<&str> = HOST_LOCAL.iter().map(|(m, _)| *m).collect();
    assert_eq!(in_table.len(), HOST_LOCAL.len());
    assert_eq!(in_table, host_local_methods());
}

#[test]
fn host_local_methods_construct_no_process_with_no_cli() {
    run_table(HOST_LOCAL);
}

#[test]
fn read_only_machine_methods_construct_no_process_with_no_cli() {
    run_table(MACHINE_READS);
}

#[test]
fn an_unknown_machine_is_a_typed_not_found_without_a_process() {
    let home = tempfile::tempdir().expect("a home");
    let mut env = TestEnv::new();
    offline_process(&mut env, home.path());
    negotiate();
    let scope = SpawnScope::begin();
    let (status, body) = call("machine.inspect", r#"{"id":"ghost"}"#);
    assert_eq!(status, 1, "{body}");
    assert_eq!(body["code"], "NOT_FOUND");
    scope.assert_only(ALLOWED);
}

#[test]
fn a_corrupt_checkpoint_registry_is_a_typed_error_without_a_process() {
    let home = tempfile::tempdir().expect("a home");
    let mut env = TestEnv::new();
    offline_process(&mut env, home.path());
    negotiate();
    let dir = mvm_core::config::checkpoints_dir().join("broken");
    std::fs::create_dir_all(&dir).expect("a checkpoint directory");
    std::fs::write(dir.join("meta.json"), b"{").expect("a corrupt record");
    let scope = SpawnScope::begin();
    let (status, body) = call("checkpoint.list", "{}");
    assert_eq!(status, 3, "{body}");
    assert_eq!(body["code"], "BACKEND_ERROR");
    scope.assert_only(&[]);
}

/// Negative control: the same assertion `run_table` makes must fail when a
/// shell is built through the sanctioned constructor during a measured call.
#[test]
#[should_panic(expected = "\"sh\"")]
fn a_shell_built_during_a_measured_call_fails_the_assertion() {
    let home = tempfile::tempdir().expect("a home");
    let mut env = TestEnv::new();
    offline_process(&mut env, home.path());
    negotiate();
    let scope = SpawnScope::begin();
    let _ = call("manifest.list", "{}");
    let _ = mvm_core::env_hygiene::helper_command("sh");
    scope.assert_only(ALLOWED);
}
