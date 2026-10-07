//! A run's attestation, read back from the chain-signed audit log.
//!
//! Reads the same tamper-evident `<audit_dir>/<tenant>.jsonl` chain the audit
//! verifier reads, selects the entries bound to one run, and assembles its
//! lifecycle, outcome, backend, source provenance and egress refusals —
//! recording whether the chain still verifies rather than refusing to answer
//! when it does not. Read-only: nothing here writes or signs.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use ed25519_dalek::VerifyingKey;
use serde::Serialize;

use mvm_hostd::supervisor::PlanAuditEntry;

use crate::audit::follow::{ChainLine, parse_chain_line};
use crate::egress_denials::{DeniedDestination, denials_in_window};

/// Explain run `run_id` from tenant `tenant`'s chain in this host's audit
/// directory, verified under this host's signing key.
pub fn explain_local_run(tenant: &str, run_id: &str) -> Result<RunExplanation> {
    let dir = mvm_hostd::audit::emitter::default_audit_dir()?;
    let path = mvm_hostd::audit::emitter::audit_path_for_tenant(&dir, tenant);
    let signer = mvm_hostd::audit::host_keypair::load_or_init()
        .context("loading host signer to verify audit chain")?;
    collect_run(&path, &signer.verifying, tenant, run_id)
}

/// One audit-chain event rendered for a single run, stripped of the
/// chain-signing envelope (prev_hash / signature) — those are a
/// tamper-evidence detail, not part of the run's story.
#[derive(Debug, Clone, Serialize)]
pub struct EventRecord {
    pub timestamp: DateTime<Utc>,
    pub event: String,
    pub labels: BTreeMap<String, String>,
}

/// The rendered attestation for one run: its identity, its full
/// lifecycle of chain-signed events, and whether the chain that
/// carries them still verifies clean.
#[derive(Debug, Clone, Serialize)]
pub struct RunExplanation {
    pub run_id: String,
    pub tenant: String,
    pub plan_id: String,
    pub image_name: String,
    pub image_sha256: String,
    pub events: Vec<EventRecord>,
    /// The machine's egress refusals while this run held its name, counted by
    /// destination and reason, each with its remedy.
    pub egress_denials: Vec<DeniedDestination>,
    pub chain_verified: bool,
    /// Total verified entry count across the whole chain file (not just
    /// this run's events). Rendering-only; not part of the JSON contract.
    #[serde(skip)]
    pub chain_entry_count: usize,
    pub verify_error: Option<String>,
}

impl RunExplanation {
    /// The terminal-event-derived outcome: exit code, failure class +
    /// message, or "still open" when no terminal event was recorded.
    pub fn outcome(&self) -> String {
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
    pub fn backend(&self) -> Option<String> {
        self.events
            .iter()
            .rev()
            .find_map(|e| e.labels.get("backend").cloned())
    }

    /// Renders the `plan.oci_provenance` event's labels, if the run
    /// admitted an OCI-sourced image.
    pub fn provenance_summary(&self) -> Option<String> {
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
pub fn collect_run(
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

    let audit_dir = path
        .parent()
        .with_context(|| format!("audit chain path {} has no parent", path.display()))?;
    let base = path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .with_context(|| format!("audit chain path {} has no file stem", path.display()))?;
    let (all_entries, verification) = match mvm_hostd::supervisor::audit_set::verify_segment_entries(
        audit_dir,
        base,
        verifying_key,
    ) {
        Ok(entries) => {
            let count = entries.len();
            (entries, Ok(count))
        }
        Err(error) => {
            let content = std::fs::read_to_string(path)
                .with_context(|| format!("reading audit chain {}", path.display()))?;
            let entries = content
                .lines()
                .filter_map(|line| match parse_chain_line(line) {
                    ChainLine::Entry(entry) => Some(*entry),
                    ChainLine::Foreign(_) => None,
                })
                .collect();
            (entries, Err(error))
        }
    };

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

    let egress_denials = run_denials(&all_entries, &plan_id, &image_name);

    let (chain_verified, chain_entry_count, verify_error) = match verification {
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
        egress_denials,
        chain_verified,
        chain_entry_count,
        verify_error,
    })
}

/// The refusals the per-VM endpoint recorded for this run's machine.
///
/// The endpoint holds no plan, so its entries are joined to the run by the
/// machine name they carry — the run's image name — and bounded in time: from
/// the run's first entry to its terminal one, or, for a run with no terminal
/// entry, to the next admission under the same name. A name reused by a later
/// run therefore never lends this one its refusals.
fn run_denials(entries: &[PlanAuditEntry], plan_id: &str, vm_name: &str) -> Vec<DeniedDestination> {
    let own = || entries.iter().filter(|e| e.plan_id.0 == plan_id);
    let Some(from) = own().map(|e| e.timestamp).min() else {
        return Vec::new();
    };
    let terminal = own()
        .filter(|e| e.event == "plan.exited" || e.event == "plan.failed")
        .map(|e| e.timestamp)
        .max();
    let next_admission = entries
        .iter()
        .filter(|e| {
            e.event == "plan.admitted"
                && e.image_name == vm_name
                && e.plan_id.0 != plan_id
                && e.timestamp > from
        })
        .map(|e| e.timestamp)
        .min();
    denials_in_window(entries, vm_name, from, terminal.or(next_admission)).destinations()
}

/// `key=value key=value`, sorted by key: the form the audit tail prints labels in.
pub fn label_join(labels: &BTreeMap<String, String>) -> String {
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

    /// Record a refusal the way the per-VM endpoint does: unbound, attributed
    /// to the machine by name, into the same tenant chain.
    fn endpoint_refusal(dir: &Path, key: &SigningKey, vm: &str, target: &str, reason: &str) {
        use mvm_hostd::supervisor::audit_recorder::{EventCategory, Recorder};
        let signer = mvm_hostd::supervisor::audit_file::FileAuditSigner::open(
            key.clone(),
            dir.to_path_buf(),
        )
        .unwrap();
        let recorder = Recorder::new(
            std::sync::Arc::new(signer),
            mvm_core::plan::TenantId("local".into()),
        )
        .with_vm_name(vm);
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(recorder.record_unbound(
                EventCategory::Host,
                "host.flow.denied",
                [
                    ("class".to_string(), "tcp".to_string()),
                    ("target".to_string(), target.to_string()),
                    ("reason".to_string(), reason.to_string()),
                ],
            ))
            .unwrap();
    }

    /// `explain` shows the machine's refusals from its own run and no other:
    /// not a different machine's, and not a later run's under the same name.
    #[test]
    fn collect_run_reports_the_runs_egress_denials_and_no_one_elses() {
        let dir = tempfile::tempdir().unwrap();
        let key = SigningKey::from_bytes(&[11; 32]);
        let vk = key.verifying_key();
        let emitter = AuditEmitter::with_dir(key.clone(), dir.path()).unwrap();
        let plan = fixture_plan("local", "plan-denied-1");
        emitter.emit_admitted(&plan, "host:test").unwrap();
        emitter.emit_launched(&plan, "firecracker").unwrap();
        endpoint_refusal(
            dir.path(),
            &key,
            "vm-test",
            "api.example.com:443",
            "policy_denied",
        );
        endpoint_refusal(
            dir.path(),
            &key,
            "vm-test",
            "api.example.com:443",
            "policy_denied",
        );
        endpoint_refusal(
            dir.path(),
            &key,
            "vm-test",
            "169.254.169.254:80",
            "cloud_metadata",
        );
        endpoint_refusal(
            dir.path(),
            &key,
            "vm-other",
            "other.example:443",
            "policy_denied",
        );
        emitter.emit_exited(&plan, 7, "firecracker").unwrap();
        let later = fixture_plan("local", "plan-denied-2");
        emitter.emit_admitted(&later, "host:test").unwrap();
        endpoint_refusal(
            dir.path(),
            &key,
            "vm-test",
            "later.example:443",
            "policy_denied",
        );

        let path = dir.path().join("local.jsonl");
        let explanation = collect_run(&path, &vk, "local", "plan-denied-1").unwrap();
        assert!(explanation.chain_verified, "{:?}", explanation.verify_error);
        let denied = &explanation.egress_denials;
        assert_eq!(denied.len(), 2, "{denied:?}");
        assert_eq!(denied[0].destination, "api.example.com:443");
        assert_eq!(denied[0].count, 2);
        assert_eq!(
            denied[0].hint,
            "allow with --allow-host api.example.com:443"
        );
        assert_eq!(denied[1].reason, "cloud_metadata");
        assert!(
            !denied[1].hint.contains("--allow-host"),
            "{}",
            denied[1].hint
        );

        let json = serde_json::to_value(&explanation).unwrap();
        assert_eq!(json["egress_denials"][0]["count"], 2);
        assert_eq!(json["egress_denials"][1]["remedy"]["kind"], "never");

        // The later run under the same name sees only its own.
        let later = collect_run(&path, &vk, "local", "plan-denied-2").unwrap();
        assert_eq!(later.egress_denials.len(), 1);
        assert_eq!(later.egress_denials[0].destination, "later.example:443");
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
    fn label_join_renders_key_value_pairs_sorted() {
        let mut labels = BTreeMap::new();
        labels.insert("b".to_string(), "2".to_string());
        labels.insert("a".to_string(), "1".to_string());
        assert_eq!(label_join(&labels), "a=1 b=2");
    }
}
