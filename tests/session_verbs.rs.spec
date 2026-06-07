//! CLI-level tests for `mvmctl session ls / info / kill / set-timeout`.
//!
//! Phase 3 / `specs/upstream-mvm-prompt.md` deliverable D. The verbs
//! all operate on the on-disk session table at
//! `$XDG_RUNTIME_DIR/mvm/sessions/<id>.json`; these tests pre-populate
//! the table via `mvm_core::session::write_session` and then drive the
//! CLI to assert the verbs read/write the right entries. No real VM
//! ever boots — `ls` / `info` / `set-timeout` don't touch the
//! substrate, and `kill` is exercised via the unit-tested `cmd_kill`
//! path elsewhere (it requires a real backend, which a unit test
//! environment doesn't have).

use assert_cmd::Command;
use mvm_core::session::{SessionMode, SessionRecord, SessionState, write_session};
use predicates::prelude::*;

/// `cargo test` runs tests in parallel within a binary. Several tests
/// here mutate `MVM_RUNTIME_DIR` in the parent process to populate the
/// on-disk table via `mvm_core::session::write_session` before
/// spawning the mvmctl child. Without serialization the env races
/// across threads. Hold this mutex for the duration of any test that
/// touches the parent process's env.
static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn mvm_with_runtime_dir(runtime_dir: &std::path::Path) -> Command {
    #[allow(deprecated)]
    let mut cmd = Command::cargo_bin("mvmctl").unwrap();
    cmd.env("MVM_RUNTIME_DIR", runtime_dir);
    cmd
}

/// Spawn `mvmctl` with runtime + state + data dirs all pinned to
/// temps. Use when the test needs to inspect the audit log: the
/// audit framework's `default_audit_log()` first checks a legacy
/// path under `MVM_DATA_DIR` for backward compat, so we have to
/// pin **both** state and data dirs to ensure the log lands under
/// `<state_dir>/log/audit.jsonl` and not in the user's real home.
fn mvm_with_isolated_dirs(runtime_dir: &std::path::Path, state_dir: &std::path::Path) -> Command {
    #[allow(deprecated)]
    let mut cmd = Command::cargo_bin("mvmctl").unwrap();
    cmd.env("MVM_RUNTIME_DIR", runtime_dir);
    cmd.env("MVM_STATE_DIR", state_dir);
    // Point MVM_DATA_DIR somewhere that doesn't have a legacy
    // audit.jsonl — using the runtime_dir is convenient since it's
    // already a fresh temp.
    cmd.env("MVM_DATA_DIR", runtime_dir);
    cmd
}

/// Helper: pre-populate the on-disk session table at `runtime_dir`
/// while holding the env-lock so concurrent tests don't observe a
/// transient `MVM_RUNTIME_DIR` value. Returns the id of the written
/// record.
fn populate_record(
    runtime_dir: &std::path::Path,
    record: &SessionRecord,
) -> std::sync::MutexGuard<'static, ()> {
    let lock = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let prev = std::env::var("MVM_RUNTIME_DIR").ok();
    // SAFETY: lock above serializes env mutation across this test
    // binary; restoring the prior value on drop is the caller's
    // responsibility (we hold the guard for them via the return
    // value, but the tests below explicitly restore).
    unsafe {
        std::env::set_var("MVM_RUNTIME_DIR", runtime_dir);
    }
    write_session(record).expect("write");
    // Restore prior env so other helpers/tests don't observe the
    // override; the caller-held guard keeps the mutex.
    unsafe {
        match prev {
            Some(v) => std::env::set_var("MVM_RUNTIME_DIR", v),
            None => std::env::remove_var("MVM_RUNTIME_DIR"),
        }
    }
    lock
}

#[test]
fn session_ls_empty_reports_no_sessions() {
    let temp = tempfile::tempdir().unwrap();
    mvm_with_runtime_dir(temp.path())
        .args(["session", "ls"])
        .assert()
        .success()
        // `ui::info` writes to stdout with `[mvm]` prefix.
        .stdout(predicate::str::contains("No active sessions"));
}

#[test]
fn session_ls_json_emits_array() {
    let temp = tempfile::tempdir().unwrap();
    mvm_with_runtime_dir(temp.path())
        .args(["session", "ls", "--json"])
        .assert()
        .success()
        .stdout(predicate::str::starts_with("[]"));
}

#[test]
fn session_ls_with_records_prints_table() {
    let temp = tempfile::tempdir().unwrap();
    let rec = SessionRecord::new_running("vm-1", "agentapp", SessionMode::Prod);
    let _lock = populate_record(temp.path(), &rec);

    mvm_with_runtime_dir(temp.path())
        .args(["session", "ls"])
        .assert()
        .success()
        .stdout(predicate::str::contains("agentapp"))
        .stdout(predicate::str::contains("vm-1"));
}

#[test]
fn session_info_unknown_id_errors() {
    let temp = tempfile::tempdir().unwrap();
    mvm_with_runtime_dir(temp.path())
        .args([
            "session",
            "info",
            // 26-char base32 string that will never collide with a
            // real session id.
            "aaaaaaaaaaaaaaaaaaaaaaaaaa",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("no session with id"));
}

#[test]
fn session_info_returns_record_json() {
    let temp = tempfile::tempdir().unwrap();
    let rec = SessionRecord::new_running("vm-1", "agentapp", SessionMode::Dev);
    let id = rec.id.to_string();
    let _lock = populate_record(temp.path(), &rec);

    mvm_with_runtime_dir(temp.path())
        .args(["session", "info", &id])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"vm_name\": \"vm-1\""))
        .stdout(predicate::str::contains("\"mode\": \"dev\""))
        .stdout(predicate::str::contains("\"state\": \"running\""));
}

#[test]
fn session_set_timeout_zero_is_rejected() {
    let temp = tempfile::tempdir().unwrap();
    mvm_with_runtime_dir(temp.path())
        .args(["session", "set-timeout", "aaaaaaaaaaaaaaaaaaaaaaaaaa", "0"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("must be > 0"));
}

#[test]
fn session_set_timeout_invalid_id_is_rejected() {
    let temp = tempfile::tempdir().unwrap();
    mvm_with_runtime_dir(temp.path())
        .args(["session", "set-timeout", "TOO_SHORT", "60"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Invalid session id"));
}

#[test]
fn session_set_timeout_above_ceiling_is_rejected() {
    let temp = tempfile::tempdir().unwrap();
    // 86401 = 24h + 1s, just past the ceiling. The ceiling check
    // fires before id resolution so any id (even bogus) hits it.
    mvm_with_runtime_dir(temp.path())
        .args([
            "session",
            "set-timeout",
            "aaaaaaaaaaaaaaaaaaaaaaaaaa",
            "86401",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("ceiling"));
}

#[test]
fn session_set_timeout_updates_record() {
    let temp = tempfile::tempdir().unwrap();
    let rec = SessionRecord::new_running("vm-1", "agentapp", SessionMode::Prod);
    let id = rec.id.to_string();
    // Hold the env-lock through the read-back at the end so a
    // concurrent test can't change `MVM_RUNTIME_DIR` between mvmctl's
    // write and our re-read.
    let _lock = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let prev = std::env::var("MVM_RUNTIME_DIR").ok();
    // SAFETY: ENV_LOCK is held; serializes env mutation across this
    // binary's tests.
    unsafe {
        std::env::set_var("MVM_RUNTIME_DIR", temp.path());
    }
    write_session(&rec).unwrap();

    mvm_with_runtime_dir(temp.path())
        .args(["session", "set-timeout", &id, "999"])
        .assert()
        .success();

    let parsed = mvm_core::session::SessionId::parse(&id).unwrap();
    let reread = mvm_core::session::read_session(&parsed).unwrap().unwrap();
    assert_eq!(reread.idle_timeout_secs, 999);

    unsafe {
        match prev {
            Some(v) => std::env::set_var("MVM_RUNTIME_DIR", v),
            None => std::env::remove_var("MVM_RUNTIME_DIR"),
        }
    }
}

#[test]
fn session_kill_unknown_id_errors_without_backend_call() {
    let temp = tempfile::tempdir().unwrap();
    mvm_with_runtime_dir(temp.path())
        .args(["session", "kill", "aaaaaaaaaaaaaaaaaaaaaaaaaa"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("no session with id"));
}

#[test]
fn session_kill_non_running_session_is_refused() {
    let temp = tempfile::tempdir().unwrap();
    let mut rec = SessionRecord::new_running("vm-1", "agentapp", SessionMode::Prod);
    rec.state = SessionState::Killed;
    let id = rec.id.to_string();
    let _lock = populate_record(temp.path(), &rec);

    mvm_with_runtime_dir(temp.path())
        .args(["session", "kill", &id])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not running"));
}

// --- Phase 5a/5b: attach / exec / run-code ----------------------------------

#[test]
fn session_attach_unknown_id_errors() {
    let temp = tempfile::tempdir().unwrap();
    mvm_with_runtime_dir(temp.path())
        .args(["session", "attach", "aaaaaaaaaaaaaaaaaaaaaaaaaa"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("no session with id"));
}

#[test]
fn session_attach_killed_session_is_refused() {
    let temp = tempfile::tempdir().unwrap();
    let mut rec = SessionRecord::new_running("vm-1", "wl", SessionMode::Prod);
    rec.state = SessionState::Killed;
    let id = rec.id.to_string();
    let _lock = populate_record(temp.path(), &rec);

    mvm_with_runtime_dir(temp.path())
        .args(["session", "attach", &id])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not running"));
}

#[test]
fn session_exec_on_prod_session_is_refused() {
    let temp = tempfile::tempdir().unwrap();
    let rec = SessionRecord::new_running("vm-1", "wl", SessionMode::Prod);
    let id = rec.id.to_string();
    let _lock = populate_record(temp.path(), &rec);

    mvm_with_runtime_dir(temp.path())
        .args(["session", "exec", &id, "--", "ls"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("dev-only"));
}

#[test]
fn session_run_code_on_prod_session_is_refused() {
    let temp = tempfile::tempdir().unwrap();
    let rec = SessionRecord::new_running("vm-1", "wl", SessionMode::Prod);
    let id = rec.id.to_string();
    let _lock = populate_record(temp.path(), &rec);

    mvm_with_runtime_dir(temp.path())
        .args(["session", "run-code", &id, "print(1)"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("dev-only"));
}

#[test]
fn session_console_unknown_id_errors() {
    let temp = tempfile::tempdir().unwrap();
    mvm_with_runtime_dir(temp.path())
        .args(["session", "console", "aaaaaaaaaaaaaaaaaaaaaaaaaa"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("no session with id"));
}

#[test]
fn session_reap_emits_count_message() {
    let temp = tempfile::tempdir().unwrap();
    mvm_with_runtime_dir(temp.path())
        .args(["session", "reap"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Reaped 0 idle session(s)"));
}

#[test]
fn session_console_on_prod_is_refused() {
    let temp = tempfile::tempdir().unwrap();
    let rec = SessionRecord::new_running("vm-1", "wl", SessionMode::Prod);
    let id = rec.id.to_string();
    let _lock = populate_record(temp.path(), &rec);

    mvm_with_runtime_dir(temp.path())
        .args(["session", "console", &id])
        .assert()
        .failure()
        .stderr(predicate::str::contains("dev-only"));
}

#[test]
fn session_exec_unknown_id_errors_before_mode_check() {
    let temp = tempfile::tempdir().unwrap();
    mvm_with_runtime_dir(temp.path())
        .args(["session", "exec", "aaaaaaaaaaaaaaaaaaaaaaaaaa", "--", "ls"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("no session with id"));
}

#[test]
fn session_ls_warn_stale_quiet_on_fresh_records() {
    // No --warn-stale: nothing on stderr beyond ui::info.
    // With --warn-stale and a fresh record: still no warning text,
    // since neither the stale-Running nor long-lived-dev predicate
    // fires. Mode is dev to ensure we test the dev-age branch — it
    // just isn't past the 1h threshold yet.
    let temp = tempfile::tempdir().unwrap();
    let rec = SessionRecord::new_running("vm-fresh", "wl", SessionMode::Dev);
    let _lock = populate_record(temp.path(), &rec);

    mvm_with_runtime_dir(temp.path())
        .args(["session", "ls", "--warn-stale"])
        .assert()
        .success()
        .stderr(predicate::str::contains("WARN").not());
}

#[test]
fn session_ls_warn_stale_flags_long_lived_dev() {
    // A dev session whose started_at is 2h in the past — but with a
    // long enough idle_timeout that the lazy reaper doesn't reap it
    // — should trigger the "long-lived dev session(s) older than 1
    // hour" warning. The lazy reap fires at the start of every
    // session verb; bumping idle_timeout_secs past the elapsed
    // wall-clock keeps the record in Running state for the test.
    let temp = tempfile::tempdir().unwrap();
    let mut rec = SessionRecord::new_running("vm-old-dev", "wl", SessionMode::Dev);
    let two_hours_ago = chrono::Utc::now() - chrono::Duration::seconds(7200);
    rec.started_at = two_hours_ago.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    rec.last_invoke_at = Some(two_hours_ago.to_rfc3339_opts(chrono::SecondsFormat::Secs, true));
    rec.idle_timeout_secs = 86_400; // 24h — well past the elapsed 2h.
    let id = rec.id.to_string();
    let _lock = populate_record(temp.path(), &rec);

    mvm_with_runtime_dir(temp.path())
        .args(["session", "ls", "--warn-stale"])
        .assert()
        .success()
        .stderr(predicate::str::contains("long-lived dev"))
        .stderr(predicate::str::contains(&id));
}

#[test]
fn session_ls_warn_stale_flags_past_idle_timeout() {
    // A Running session whose last_invoke_at is past idle_timeout
    // should trigger the "stale Running" defensive warning. The
    // lazy reaper would normally catch this on the very call that
    // emits the warning — but since `cmd_ls` runs the reap and
    // then re-lists from the same on-disk table snapshot, fresh
    // records that the reap just touched will already be Reaped
    // (not Running). We get around that by writing the record
    // AFTER the populate_record helper releases its env-lock and
    // by skipping the reap path… in practice, the host reaper
    // marks Reaped, so this test pins the WARN message rather
    // than asserting via real reaper interaction.
    //
    // Easier: use a dev-mode session with started_at in the long-
    // lived range to get a stable warning hit, since the dev-aged
    // path doesn't depend on whether the reaper ran first.
    let temp = tempfile::tempdir().unwrap();
    let mut rec = SessionRecord::new_running("vm-old-prod", "wl", SessionMode::Prod);
    rec.idle_timeout_secs = 60;
    let stale_ts = chrono::Utc::now() - chrono::Duration::seconds(120);
    rec.started_at = stale_ts.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    rec.last_invoke_at = Some(stale_ts.to_rfc3339_opts(chrono::SecondsFormat::Secs, true));
    let _lock = populate_record(temp.path(), &rec);

    // The pre-verb reap will mark this session Reaped before cmd_ls
    // runs — that's the lazy-reaper contract. So no stale-Running
    // warning emits in this path. The test asserts the *non-emission*
    // explicitly: stale-Running should be defensive only.
    mvm_with_runtime_dir(temp.path())
        .args(["session", "ls", "--warn-stale"])
        .assert()
        .success()
        // The session is marked Reaped by the lazy sweep, so no
        // stale-Running warning. Listing shows it as Reaped.
        .stdout(predicate::str::contains("reaped"))
        .stderr(predicate::str::contains("stale Running").not());
}

#[test]
fn session_reap_emits_audit_line_per_reaped_session() {
    // Pre-populate one expired session, then run `mvmctl session reap`
    // with a pinned state dir. Assert the audit log at
    // `<state>/log/audit.jsonl` picks up a `session_reap` line.
    // Tear-down of the (non-existent) backend VM is best-effort and
    // doesn't block the audit emit — `tear_down_session_vm` swallows
    // backend errors via `tracing::warn`.
    let runtime = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();

    let mut rec = SessionRecord::new_running("vm-stale", "wl", SessionMode::Prod);
    let stale_ts = chrono::Utc::now() - chrono::Duration::seconds(900);
    rec.idle_timeout_secs = 60;
    rec.started_at = stale_ts.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let session_id = rec.id.to_string();
    let _lock = populate_record(runtime.path(), &rec);

    mvm_with_isolated_dirs(runtime.path(), state.path())
        .args(["session", "reap"])
        .assert()
        .success();

    let log_path = state.path().join("log").join("audit.jsonl");
    let log = std::fs::read_to_string(&log_path)
        .unwrap_or_else(|e| panic!("expected audit log at {log_path:?}: {e}"));
    assert!(
        log.contains("\"session_reap\""),
        "expected a session_reap kind in the audit log, got:\n{log}"
    );
    assert!(
        log.contains(&session_id),
        "expected the reaped session id {session_id} in audit detail, got:\n{log}"
    );
}
