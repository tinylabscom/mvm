//! The per-tenant audit chain under concurrent writers.
//!
//! `FileAuditSigner` serializes the whole read-cursor / sign / append window
//! under an exclusive `flock` because the guarantee it owes a verifier is not
//! "each line is well-formed" but "each line names the line before it". Two
//! writers that both observe the same tail produce two entries claiming one
//! parent, and a fork is indistinguishable, to anyone holding only the log,
//! from a deleted or reordered entry. The chain would accuse an operator of
//! tampering that never happened.
//!
//! The interesting case is **separate processes**. Every per-VM supervisor is
//! its own process that opens the tenant chain, restores the cursor from disk,
//! and appends; nothing but the kernel lock stands between two of them. A
//! same-process test cannot substitute, because the two would contend on
//! in-process state that a second supervisor does not share.
//!
//! So the parent re-execs this test binary N times, each child emitting into
//! one shared chain, and then verifies the result. `verify_audit_chain` is the
//! whole assertion: it rejects a duplicated parent and equally rejects a line
//! that two interleaved writes tore in half.

use rand::Rng;
use std::path::{Path, PathBuf};

use ed25519_dalek::SigningKey;
use mvm_hostd::supervisor::{
    AuditSigner, FileAuditSigner, PlanAuditEntry, VerifyError, verify_audit_chain,
};

/// Set on a re-exec'd child: `<audit_dir>|<key_path>|<worker_index>`.
const WORKER_ENV: &str = "MVM_AUDIT_CONCURRENT_WORKER";

const WORKERS: usize = 6;
const ENTRIES_PER_WORKER: usize = 20;
const TENANT: &str = "local";

#[test]
fn concurrent_writer_processes_extend_one_chain_without_forking() {
    if let Ok(spec) = std::env::var(WORKER_ENV) {
        run_worker(&spec);
        return;
    }

    let dir = tempfile::tempdir().expect("tempdir");
    let audit_dir = dir.path().join("audit");
    std::fs::create_dir_all(&audit_dir).expect("audit dir");

    // One key, shared by every writer — a fork has to be provably ours, the
    // way it would be in production, or the test proves nothing about forks.
    let key_path = dir.path().join("chain.key");
    let mut seed = [0u8; 32];
    rand::rng().fill_bytes(&mut seed);
    std::fs::write(&key_path, seed).expect("write key seed");
    let verifying = SigningKey::from_bytes(&seed).verifying_key();

    let exe = std::env::current_exe().expect("test binary path");
    let children: Vec<_> = (0..WORKERS)
        .map(|idx| {
            std::process::Command::new(&exe)
                .args([
                    "--exact",
                    "concurrent_writer_processes_extend_one_chain_without_forking",
                    "--nocapture",
                ])
                .env(
                    WORKER_ENV,
                    format!("{}|{}|{idx}", audit_dir.display(), key_path.display()),
                )
                // A child is a writer, not a test run: its harness chatter
                // would interleave with this one's and make the real result
                // unreadable. Keep stderr so a panicking writer still explains
                // itself.
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .expect("spawn writer process")
        })
        .collect();

    for (idx, child) in children.into_iter().enumerate() {
        let out = child.wait_with_output().expect("wait for writer process");
        assert!(
            out.status.success(),
            "writer {idx} failed: {}\n{}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
    }

    let path = audit_dir.join(format!("{TENANT}.jsonl"));
    let expected = WORKERS * ENTRIES_PER_WORKER;

    // Every line landed. A torn line would have swallowed one; a lost append
    // would have too.
    let lines = std::fs::read_to_string(&path).expect("read chain");
    assert_eq!(
        lines.lines().filter(|l| !l.is_empty()).count(),
        expected,
        "every writer's entries must be on disk"
    );

    // And the chain is linear: no duplicate parent, no torn line, every
    // signature ours.
    match verify_audit_chain(&path, &verifying) {
        Ok(count) => assert_eq!(count, expected, "verified entry count"),
        Err(e) => panic!("{}", explain(&e, &path)),
    }

    // Each writer's entries all survived — a fork that happened to verify by
    // luck would still show up as a missing writer.
    for idx in 0..WORKERS {
        let marker = format!("\"writer\":\"{idx}\"");
        assert_eq!(
            lines.matches(&marker).count(),
            ENTRIES_PER_WORKER,
            "writer {idx} lost entries"
        );
    }
}

/// One re-exec'd writer: open the shared chain and append its entries.
fn run_worker(spec: &str) {
    let mut parts = spec.split('|');
    let audit_dir = PathBuf::from(parts.next().expect("audit dir in worker spec"));
    let key_path = PathBuf::from(parts.next().expect("key path in worker spec"));
    let idx: usize = parts
        .next()
        .expect("worker index in worker spec")
        .parse()
        .expect("worker index parses");

    let seed: [u8; 32] = std::fs::read(&key_path)
        .expect("read key seed")
        .try_into()
        .expect("key seed is 32 bytes");
    let signer = FileAuditSigner::open(SigningKey::from_bytes(&seed), &audit_dir).expect("signer");

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("worker runtime");
    for i in 0..ENTRIES_PER_WORKER {
        rt.block_on(signer.sign_and_emit(&entry(idx, i)))
            .expect("sign and emit");
    }
}

/// An entry big enough that its line exceeds a single atomic write. A short
/// entry can slip past an unlocked appender by accident; the torn-line half of
/// this test needs a line the kernel will not write in one piece.
fn entry(worker: usize, seq: usize) -> PlanAuditEntry {
    use mvm_core::plan::{PlanId, TenantId};

    let mut labels = std::collections::BTreeMap::new();
    labels.insert("writer".to_string(), worker.to_string());
    labels.insert("seq".to_string(), seq.to_string());
    // ~8 KiB of payload, past the page-sized write the append path would
    // otherwise get away with.
    for chunk in 0..16 {
        labels.insert(
            format!("filler_{chunk:02}"),
            format!("{worker:02}{seq:03}").repeat(64),
        );
    }

    PlanAuditEntry {
        timestamp: chrono::Utc::now(),
        tenant: TenantId(TENANT.to_string()),
        plan_id: PlanId(format!("plan-{worker}-{seq}")),
        plan_version: 1,
        bundle_id: None,
        bundle_version: None,
        image_name: "concurrency-fixture".to_string(),
        image_sha256: "00".repeat(32),
        event: "plan.admitted".to_string(),
        caller_commitment: None,
        labels,
    }
}

/// Render a verify failure with the offending line, so a regression reads as
/// "line 37 claims the parent line 36 already claimed" rather than a bare
/// error string.
fn explain(err: &VerifyError, path: &Path) -> String {
    let line_no = match err {
        VerifyError::PrevHashMismatch { line }
        | VerifyError::SignatureInvalid { line }
        | VerifyError::EntryCanonicalMismatch { line }
        | VerifyError::Malformed { line, .. } => Some(*line),
        VerifyError::TruncatedTail { line } => Some(*line),
        VerifyError::Io(_) => None,
    };
    let context = line_no
        .and_then(|n| {
            std::fs::read_to_string(path)
                .ok()?
                .lines()
                .nth(n)
                .map(|l| l.chars().take(200).collect::<String>())
        })
        .unwrap_or_default();
    format!("chain verification failed: {err}\n  offending line: {context}")
}
