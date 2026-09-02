//! `mvm explain <run-id>` — render a run's attestation from the
//! chain-signed audit log.
//!
//! Reads the same tamper-evident `~/.mvm/audit/<tenant>.jsonl` stream
//! `mvmctl trust audit tail --chain` / `mvmctl audit verify` already read,
//! selects the entries bound to one run, and renders its lifecycle,
//! outcome, backend, and source provenance — with a loud footer when
//! the chain fails verification. No new storage or signing surface;
//! this is a read-only render over data other commands already emit.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use clap::Args as ClapArgs;
use ed25519_dalek::VerifyingKey;
use serde::Serialize;

use mvm_hostd::supervisor::{PlanAuditEntry, SignedEnvelope, verify_audit_chain};

use super::audit_chain::{audit_path_for_tenant, default_audit_dir};
use super::host_signer;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// Run identity to explain: the plan id (or a unique prefix), or the
    /// workload/VM image name recorded in the audit log.
    pub run_id: String,
    /// Tenant whose audit chain to read (default: the local single-host tenant).
    #[arg(long, default_value = "local")]
    pub tenant: String,
    /// Emit a machine-readable JSON object instead of the human summary.
    #[arg(long)]
    pub json: bool,
}

pub(in crate::commands) fn run(args: Args) -> Result<()> {
    let dir = default_audit_dir()?;
    let path = audit_path_for_tenant(&dir, &args.tenant);
    let signer =
        host_signer::load_or_init().context("loading host signer to verify audit chain")?;
    let explanation = collect_run(&path, &signer.verifying, &args.tenant, &args.run_id)?;
    if args.json {
        crate::json_out::emit_json(&explanation)
    } else {
        explanation.render();
        Ok(())
    }
}

/// One audit-chain event rendered for a single run, stripped of the
/// chain-signing envelope (prev_hash / signature) — those are a
/// tamper-evidence detail, not part of the run's story.
#[derive(Debug, Clone, Serialize)]
pub(in crate::commands) struct EventRecord {
    pub timestamp: DateTime<Utc>,
    pub event: String,
    pub labels: BTreeMap<String, String>,
}

/// The rendered attestation for one run: its identity, its full
/// lifecycle of chain-signed events, and whether the chain that
/// carries them still verifies clean.
#[derive(Debug, Clone, Serialize)]
pub(in crate::commands) struct RunExplanation {
    pub run_id: String,
    pub tenant: String,
    pub plan_id: String,
    pub image_name: String,
    pub image_sha256: String,
    pub events: Vec<EventRecord>,
    pub chain_verified: bool,
    /// Total verified entry count across the whole chain file (not just
    /// this run's events). Rendering-only; not part of the JSON contract.
    #[serde(skip)]
    pub chain_entry_count: usize,
    pub verify_error: Option<String>,
}

impl RunExplanation {
    pub(in crate::commands) fn render(&self) {
        println!(
            "Run {}  image {} (sha256:{})  tenant {}",
            self.plan_id,
            self.image_name,
            short_sha256(&self.image_sha256),
            self.tenant
        );
        println!();
        for ev in &self.events {
            let labels = label_join(&ev.labels);
            if labels.is_empty() {
                println!("{}  {}", ev.timestamp, ev.event);
            } else {
                println!("{}  {}  [{}]", ev.timestamp, ev.event, labels);
            }
        }
        println!();
        println!("outcome: {}", self.outcome());
        if let Some(backend) = self.backend() {
            println!("backend: {backend}");
        }
        if let Some(provenance) = self.provenance_summary() {
            println!("source provenance: {provenance}");
        }
        println!();
        match (self.chain_verified, &self.verify_error) {
            (true, _) => println!(
                "\u{2713} audit chain verifies clean ({} entries)",
                self.chain_entry_count
            ),
            (false, Some(e)) => println!(
                "\u{26a0} audit chain FAILED verification: {e} — this run's record may be tampered"
            ),
            (false, None) => println!("\u{26a0} audit chain verification could not be confirmed"),
        }
    }

    /// The terminal-event-derived outcome: exit code, failure class +
    /// message, or "still open" when no terminal event was recorded.
    fn outcome(&self) -> String {
        if let Some(ev) = self.events.iter().rev().find(|e| e.event == "plan.exited") {
            let code = ev
                .labels
                .get("exit_code")
                .cloned()
                .unwrap_or_else(|| "?".to_string());
            return format!("exited with code {code}");
        }
        if let Some(ev) = self.events.iter().rev().find(|e| e.event == "plan.failed") {
            let class = ev
                .labels
                .get("error_class")
                .map(String::as_str)
                .unwrap_or("unknown");
            let message = ev
                .labels
                .get("error_message")
                .map(String::as_str)
                .unwrap_or("");
            return format!("failed ({class}): {message}");
        }
        "launched, no terminal event recorded".to_string()
    }

    /// The most recent `backend` label across this run's events.
    fn backend(&self) -> Option<String> {
        self.events
            .iter()
            .rev()
            .find_map(|e| e.labels.get("backend").cloned())
    }

    /// Renders the `plan.oci_provenance` event's labels, if the run
    /// admitted an OCI-sourced image.
    fn provenance_summary(&self) -> Option<String> {
        let ev = self
            .events
            .iter()
            .find(|e| e.event == "plan.oci_provenance")?;
        Some(label_join(&ev.labels))
    }
}

/// Read the chain-signed audit log at `path`, select the entries bound
/// to `run_id` (by exact plan id, plan id prefix, or workload image
/// name), and render the run's attestation. Pure aside from the
/// filesystem read at `path` — no global `~/.mvm` state — so tests can
/// point it at a tempdir.
pub(in crate::commands) fn collect_run(
    path: &Path,
    verifying_key: &VerifyingKey,
    tenant: &str,
    run_id: &str,
) -> Result<RunExplanation> {
    if !path.exists() {
        bail!(
            "no audit chain for tenant '{tenant}' at {}; runs appear after the next launch",
            path.display()
        );
    }

    let content = std::fs::read_to_string(path)
        .with_context(|| format!("reading audit chain {}", path.display()))?;

    let mut all_entries: Vec<PlanAuditEntry> = Vec::new();
    for line in content.lines() {
        if line.trim().is_empty() {
            continue;
        }
        // Unparsable lines are skipped, matching the tolerant read in
        // `ops/audit.rs::print_chain_line` — a foreign line shouldn't
        // sink the whole explain.
        if let Ok(envelope) = serde_json::from_str::<SignedEnvelope>(line) {
            all_entries.push(envelope.entry);
        }
    }

    let matches: Vec<&PlanAuditEntry> = all_entries
        .iter()
        .filter(|e| {
            e.plan_id.0 == run_id || e.plan_id.0.starts_with(run_id) || e.image_name == run_id
        })
        .collect();

    if matches.is_empty() {
        bail!(
            "no run {run_id:?} found in the audit chain for tenant {tenant:?}; \
             try `mvmctl trust audit tail` to list recent runs"
        );
    }

    let distinct_plan_ids: BTreeSet<&str> = matches.iter().map(|e| e.plan_id.0.as_str()).collect();
    if distinct_plan_ids.len() > 1 {
        let candidates: Vec<&str> = distinct_plan_ids.into_iter().collect();
        bail!(
            "run id {run_id:?} matches multiple runs: {}; pass a more specific plan id",
            candidates.join(", ")
        );
    }
    let plan_id = (*distinct_plan_ids
        .into_iter()
        .next()
        .expect("matches is non-empty, so distinct_plan_ids is non-empty"))
    .to_string();

    let final_events: Vec<&PlanAuditEntry> = all_entries
        .iter()
        .filter(|e| e.plan_id.0 == plan_id)
        .collect();
    let first = *final_events
        .first()
        .expect("plan_id was derived from at least one match");
    let image_name = first.image_name.clone();
    let image_sha256 = first.image_sha256.clone();

    let events: Vec<EventRecord> = final_events
        .into_iter()
        .map(|e| EventRecord {
            timestamp: e.timestamp,
            event: e.event.clone(),
            labels: e.labels.clone(),
        })
        .collect();

    let (chain_verified, chain_entry_count, verify_error) =
        match verify_audit_chain(path, verifying_key) {
            Ok(count) => (true, count, None),
            Err(e) => (false, 0, Some(e.to_string())),
        };

    Ok(RunExplanation {
        run_id: run_id.to_string(),
        tenant: tenant.to_string(),
        plan_id,
        image_name,
        image_sha256,
        events,
        chain_verified,
        chain_entry_count,
        verify_error,
    })
}

/// First 12 hex chars of an image sha256 — enough to disambiguate at a
/// glance without cluttering the header line with the full 64.
fn short_sha256(sha256: &str) -> &str {
    let end = sha256.len().min(12);
    &sha256[..end]
}

/// `key=value key=value` label join, matching the style
/// `ops/audit.rs::print_chain_line` uses for the tail/verify output.
fn label_join(labels: &BTreeMap<String, String>) -> String {
    labels
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use mvm_core::plan::ExecutionPlan;
    use mvm_hostd::audit::emitter::AuditEmitter;
    use rand::Rng;

    fn fixture_plan(tenant: &str, plan_id: &str) -> ExecutionPlan {
        mvm_core::plan::test_support::PlanFixture::new()
            .tenant(tenant)
            .plan_id(plan_id)
            .build()
    }

    #[test]
    fn collect_run_gathers_admitted_launched_exited_and_verifies_clean() {
        let dir = tempfile::tempdir().unwrap();
        let key = {
            let mut __ed_seed = [0u8; 32];
            rand::rng().fill_bytes(&mut __ed_seed);
            SigningKey::from_bytes(&__ed_seed)
        };
        let vk = key.verifying_key();
        let emitter = AuditEmitter::with_dir(key, dir.path()).unwrap();
        let plan = fixture_plan("local", "plan-explain-1");

        emitter.emit_admitted(&plan, "host:test").unwrap();
        emitter.emit_launched(&plan, "firecracker").unwrap();
        emitter.emit_exited(&plan, 0, "firecracker").unwrap();

        let path = dir.path().join("local.jsonl");
        let explanation = collect_run(&path, &vk, "local", "plan-explain-1").unwrap();

        assert_eq!(explanation.plan_id, "plan-explain-1");
        assert_eq!(explanation.tenant, "local");
        assert_eq!(explanation.events.len(), 3);
        assert_eq!(explanation.events[0].event, "plan.admitted");
        assert_eq!(explanation.events[1].event, "plan.launched");
        assert_eq!(explanation.events[2].event, "plan.exited");
        assert!(explanation.chain_verified);
        assert_eq!(explanation.chain_entry_count, 3);
        assert!(explanation.verify_error.is_none());
        assert_eq!(explanation.outcome(), "exited with code 0");
        assert_eq!(explanation.backend().as_deref(), Some("firecracker"));
    }

    #[test]
    fn collect_run_matches_by_plan_id_prefix() {
        let dir = tempfile::tempdir().unwrap();
        let key = {
            let mut __ed_seed = [0u8; 32];
            rand::rng().fill_bytes(&mut __ed_seed);
            SigningKey::from_bytes(&__ed_seed)
        };
        let vk = key.verifying_key();
        let emitter = AuditEmitter::with_dir(key, dir.path()).unwrap();
        let plan = fixture_plan("local", "plan-abcdef123456");
        emitter.emit_admitted(&plan, "host:test").unwrap();

        let path = dir.path().join("local.jsonl");
        let explanation = collect_run(&path, &vk, "local", "plan-abcdef").unwrap();
        assert_eq!(explanation.plan_id, "plan-abcdef123456");
    }

    #[test]
    fn collect_run_matches_by_image_name() {
        let dir = tempfile::tempdir().unwrap();
        let key = {
            let mut __ed_seed = [0u8; 32];
            rand::rng().fill_bytes(&mut __ed_seed);
            SigningKey::from_bytes(&__ed_seed)
        };
        let vk = key.verifying_key();
        let emitter = AuditEmitter::with_dir(key, dir.path()).unwrap();
        let plan = fixture_plan("local", "plan-img-match");
        emitter.emit_admitted(&plan, "host:test").unwrap();

        let path = dir.path().join("local.jsonl");
        // PlanFixture's image name is fixed at "vm-test".
        let explanation = collect_run(&path, &vk, "local", "vm-test").unwrap();
        assert_eq!(explanation.plan_id, "plan-img-match");
    }

    #[test]
    fn collect_run_errors_on_ambiguous_prefix() {
        let dir = tempfile::tempdir().unwrap();
        let key = {
            let mut __ed_seed = [0u8; 32];
            rand::rng().fill_bytes(&mut __ed_seed);
            SigningKey::from_bytes(&__ed_seed)
        };
        let vk = key.verifying_key();
        let emitter = AuditEmitter::with_dir(key, dir.path()).unwrap();
        emitter
            .emit_admitted(&fixture_plan("local", "plan-dup-aaa"), "host:test")
            .unwrap();
        emitter
            .emit_admitted(&fixture_plan("local", "plan-dup-bbb"), "host:test")
            .unwrap();

        let path = dir.path().join("local.jsonl");
        let err = collect_run(&path, &vk, "local", "plan-dup").unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("multiple runs"), "{msg}");
        assert!(msg.contains("plan-dup-aaa"), "{msg}");
        assert!(msg.contains("plan-dup-bbb"), "{msg}");
    }

    #[test]
    fn collect_run_errors_when_no_match() {
        let dir = tempfile::tempdir().unwrap();
        let key = {
            let mut __ed_seed = [0u8; 32];
            rand::rng().fill_bytes(&mut __ed_seed);
            SigningKey::from_bytes(&__ed_seed)
        };
        let vk = key.verifying_key();
        let emitter = AuditEmitter::with_dir(key, dir.path()).unwrap();
        emitter
            .emit_admitted(&fixture_plan("local", "plan-real"), "host:test")
            .unwrap();

        let path = dir.path().join("local.jsonl");
        let err = collect_run(&path, &vk, "local", "no-such-run").unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("no run"), "{msg}");
        assert!(msg.contains("no-such-run"), "{msg}");
    }

    #[test]
    fn collect_run_errors_when_chain_file_missing() {
        let dir = tempfile::tempdir().unwrap();
        let key = {
            let mut __ed_seed = [0u8; 32];
            rand::rng().fill_bytes(&mut __ed_seed);
            SigningKey::from_bytes(&__ed_seed)
        };
        let vk = key.verifying_key();
        let path = dir.path().join("local.jsonl");
        let err = collect_run(&path, &vk, "local", "anything").unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("no audit chain"), "{msg}");
    }

    #[test]
    fn collect_run_reports_tampered_chain_loudly_but_still_returns_the_run() {
        let dir = tempfile::tempdir().unwrap();
        let key = {
            let mut __ed_seed = [0u8; 32];
            rand::rng().fill_bytes(&mut __ed_seed);
            SigningKey::from_bytes(&__ed_seed)
        };
        let vk = key.verifying_key();
        let emitter = AuditEmitter::with_dir(key, dir.path()).unwrap();
        let plan = fixture_plan("local", "plan-tamper");
        emitter.emit_admitted(&plan, "host:test").unwrap();
        emitter.emit_launched(&plan, "firecracker").unwrap();

        let path = dir.path().join("local.jsonl");
        let content = std::fs::read_to_string(&path).unwrap();
        // Flip a byte inside the event name — signature no longer matches.
        let tampered = content.replacen("plan.launched", "plan.fakeville", 1);
        std::fs::write(&path, tampered).unwrap();

        let explanation = collect_run(&path, &vk, "local", "plan-tamper").unwrap();
        assert!(!explanation.chain_verified);
        assert!(explanation.verify_error.is_some());
        // The run's own events are still surfaced — a drift must be loud,
        // not hidden by refusing to render anything.
        assert!(!explanation.events.is_empty());
    }

    #[test]
    fn short_sha256_truncates_to_twelve_chars() {
        assert_eq!(short_sha256(&"a".repeat(64)), "aaaaaaaaaaaa");
        assert_eq!(short_sha256("short"), "short");
    }

    #[test]
    fn label_join_renders_key_value_pairs_sorted() {
        let mut labels = BTreeMap::new();
        labels.insert("b".to_string(), "2".to_string());
        labels.insert("a".to_string(), "1".to_string());
        assert_eq!(label_join(&labels), "a=1 b=2");
    }
}
