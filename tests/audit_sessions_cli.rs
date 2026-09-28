//! `mvmctl trust audit sessions | show <session> | verify <session>` against a
//! real chain written under the host key in an isolated `MVM_HOME`.

use std::process::Command;

use std::collections::BTreeMap;

use mvm_core::plan::{PlanId, TenantId};
use mvm_hostd::audit::session::{SESSION_SEALED_EVENT, SealReason, SealRequest, compute_seal};
use mvm_hostd::supervisor::audit::PlanAuditEntry;
use mvm_hostd::supervisor::{AuditSigner, FileAuditSigner};

const SEALED: &str = "sha256:aaaa1111bbbb2222cccc3333";
const OPEN: &str = "sha256:dddd4444eeee5555ffff6666";

fn entry(plan_id: &str, event: &str, labels: Vec<(String, String)>) -> PlanAuditEntry {
    PlanAuditEntry {
        timestamp: chrono::Utc::now(),
        tenant: TenantId("local".into()),
        plan_id: PlanId(plan_id.into()),
        plan_version: 1,
        bundle_id: None,
        bundle_version: None,
        image_name: "test-image".into(),
        image_sha256: "00".repeat(32),
        caller_commitment: None,
        event: event.into(),
        labels: labels.into_iter().collect::<BTreeMap<_, _>>(),
    }
}

struct Home {
    dir: tempfile::TempDir,
}

impl Home {
    /// An `MVM_HOME` holding a host key and a chain with one sealed session
    /// and one still open, written under that key exactly as the host writes
    /// them.
    fn with_sessions() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let signer = mvm_hostd::audit::host_keypair::load_or_init_at(&dir.path().join("keys"))
            .expect("host key");
        let audit_dir = dir.path().join("audit");
        let file_signer = FileAuditSigner::open(signer.signing, &audit_dir).expect("signer");
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let emit = |e: PlanAuditEntry| rt.block_on(file_signer.sign_and_emit(&e)).unwrap();
        emit(entry(SEALED, "plan.admitted", vec![]));
        emit(entry(SEALED, "plan.launched", vec![]));
        emit(entry(
            SEALED,
            "plan.exited",
            vec![("exit_code".into(), "0".into())],
        ));
        let lines: Vec<String> = std::fs::read_to_string(audit_dir.join("local.jsonl"))
            .unwrap()
            .lines()
            .map(str::to_string)
            .collect();
        let seal = compute_seal(
            &lines,
            &SealRequest {
                plan_id: SEALED,
                reason: SealReason::Exited,
                compute_environment: None,
                snapshot_root: None,
            },
        )
        .unwrap();
        emit(entry(SEALED, SESSION_SEALED_EVENT, seal.to_labels()));
        emit(entry(OPEN, "plan.admitted", vec![]));
        Self { dir }
    }

    fn empty() -> Self {
        Self {
            dir: tempfile::tempdir().expect("tempdir"),
        }
    }

    fn mvmctl(&self, args: &[&str]) -> std::process::Output {
        Command::new(env!("CARGO_BIN_EXE_mvmctl"))
            .env("MVM_HOME", self.dir.path())
            .env("HOME", self.dir.path())
            .env("MVM_NO_AUTO_DEV", "1")
            .args(args)
            .output()
            .expect("run mvmctl")
    }

    fn chain_path(&self) -> std::path::PathBuf {
        self.dir.path().join("audit").join("local.jsonl")
    }
}

fn stdout(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn json(out: &std::process::Output) -> serde_json::Value {
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "not JSON ({e}): {}\nstderr: {}",
            stdout(out),
            String::from_utf8_lossy(&out.stderr)
        )
    })
}

#[test]
fn sessions_lists_each_admitted_run_with_its_seal_and_the_ledger() {
    let home = Home::with_sessions();
    let out = home.mvmctl(&["trust", "audit", "sessions", "--json"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let listing = json(&out);
    assert_eq!(listing["tenant"], "local");
    assert_eq!(listing["ledger"]["intact"], true);
    assert_eq!(listing["ledger"]["seals"], 1);
    let sessions = listing["sessions"].as_array().unwrap();
    assert_eq!(sessions.len(), 2);
    assert_eq!(sessions[0]["plan_id"], SEALED);
    assert_eq!(sessions[0]["sealed"], true);
    assert_eq!(sessions[0]["seal"]["exit_code"], "0");
    assert_eq!(sessions[1]["plan_id"], OPEN);
    assert_eq!(sessions[1]["sealed"], false);

    let human = stdout(&home.mvmctl(&["trust", "audit", "sessions"]));
    assert!(human.contains("aaaa1111bbbb"), "{human}");
    assert!(human.contains("sealed (exit 0)"), "{human}");
    assert!(human.contains("unsealed"), "{human}");
}

#[test]
fn sessions_time_filters_exclude_what_is_out_of_range() {
    let home = Home::with_sessions();
    let out = home.mvmctl(&[
        "trust",
        "audit",
        "sessions",
        "--until",
        "2000-01-01",
        "--json",
    ]);
    assert!(out.status.success());
    assert_eq!(json(&out)["sessions"].as_array().unwrap().len(), 0);
}

#[test]
fn verify_reports_each_verdict_with_its_exit_status() {
    let home = Home::with_sessions();

    let out = home.mvmctl(&["trust", "audit", "verify", "aaaa1111"]);
    assert_eq!(out.status.code(), Some(0));
    assert!(stdout(&out).starts_with("VERIFIED"), "{}", stdout(&out));

    let out = home.mvmctl(&["trust", "audit", "verify", OPEN, "--json"]);
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(json(&out)["verdict"], "UNSEALED");

    let out = home.mvmctl(&["trust", "audit", "verify", "99998888", "--json"]);
    assert_eq!(out.status.code(), Some(3));
    assert_eq!(json(&out)["verdict"], "NOT_FOUND");

    // Remove the sealed session's launch entry: the chain breaks, and the
    // session says why.
    let body = std::fs::read_to_string(home.chain_path()).unwrap();
    let kept: Vec<&str> = body
        .lines()
        .filter(|l| !(l.contains("\"plan.launched\"") && l.contains(SEALED)))
        .collect();
    std::fs::write(home.chain_path(), kept.join("\n") + "\n").unwrap();
    let out = home.mvmctl(&["trust", "audit", "verify", SEALED, "--json"]);
    assert_eq!(out.status.code(), Some(1));
    let report = json(&out);
    assert_eq!(report["verdict"], "MISMATCH");
    assert_eq!(report["reason"], "chain_break");
    let human = stdout(&home.mvmctl(&["trust", "audit", "verify", SEALED]));
    assert!(human.starts_with("MISMATCH"), "{human}");
    assert!(human.contains("chain break"), "{human}");
}

#[test]
fn show_filters_a_sessions_entries_by_kind() {
    let home = Home::with_sessions();
    let out = home.mvmctl(&[
        "trust", "audit", "show", "aaaa1111", "--kind", "*.sealed", "--json",
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let events = json(&out);
    let events = events.as_array().unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["envelope"]["entry"]["event"], "session.sealed");
    assert!(events[0]["seq"].is_u64());

    let all = json(&home.mvmctl(&["trust", "audit", "show", "aaaa1111", "--json"]));
    assert_eq!(
        all.as_array().unwrap().len(),
        4,
        "admitted, launched, exited, sealed"
    );
}

#[test]
fn a_pristine_home_has_no_sessions() {
    let home = Home::empty();
    let out = home.mvmctl(&["trust", "audit", "sessions", "--json"]);
    assert!(out.status.success());
    assert_eq!(json(&out)["sessions"].as_array().unwrap().len(), 0);
    let out = home.mvmctl(&["trust", "audit", "verify", "aaaa1111", "--json"]);
    assert_eq!(out.status.code(), Some(3));
}

#[test]
fn audit_help_names_the_session_verbs() {
    let out = Home::empty().mvmctl(&["trust", "audit", "--help"]);
    let help = stdout(&out);
    assert!(help.contains("sessions"), "{help}");
    let verify = stdout(&Home::empty().mvmctl(&["trust", "audit", "verify", "--help"]));
    for needle in ["[SESSION]", "--json", "--tenant"] {
        assert!(verify.contains(needle), "missing {needle:?}:\n{verify}");
    }
    let show = stdout(&Home::empty().mvmctl(&["trust", "audit", "show", "--help"]));
    for needle in ["--kind", "--since", "--until"] {
        assert!(show.contains(needle), "missing {needle:?}:\n{show}");
    }
}
